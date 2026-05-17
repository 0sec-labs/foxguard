//! foxguard-github-app — webhook receiver for the foxguard GitHub App.
//!
//! See `src/github_app/README.md` and the tracking issue at
//! <https://github.com/0sec-labs/foxguard/issues/246> for the design
//! discussion.
//!
//! This binary is intentionally scoped to the *Phase-1 foundation*
//! described in #246: receive webhook deliveries, verify the
//! signature, route by event type, acknowledge with 202. The actual
//! `pull_request` → clone → scan → comment pipeline is wired as a
//! TODO and lands in a follow-up so the architecture can be reviewed
//! in isolation first.
//!
//! Build:    `cargo build --release --features github-app --bin foxguard-github-app`
//! Run:      `FOXGUARD_WEBHOOK_SECRET=xxx FOXGUARD_BIND=0.0.0.0:8080 foxguard-github-app`
//! Docker:   `docker build -f Dockerfile.github-app -t ghcr.io/0sec-labs/foxguard-github-app .`

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use foxguard::github_app::auth::{
    AppCredentials, AuthError, GitHubAppAuthClient, InstallationTokenCache,
};
use foxguard::github_app::webhook::{verify_signature, EventKind, SignatureError};
use serde::Deserialize;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Hard cap on incoming webhook body size. GitHub's largest legitimate
/// `pull_request` payload sits around 200 KB; 1 MiB leaves comfortable
/// headroom while making it cheap to reject anything weaponised.
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

#[derive(Clone)]
struct AppState {
    webhook_secret: Vec<u8>,
    auth: GitHubAppAuthClient,
    installation_tokens: Arc<Mutex<InstallationTokenCache>>,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookPayload {
    action: Option<String>,
    installation: Option<GitHubInstallation>,
}

#[derive(Debug, Deserialize)]
struct GitHubInstallation {
    id: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,foxguard=debug")),
        )
        .init();

    let secret = std::env::var("FOXGUARD_WEBHOOK_SECRET").map_err(|_| {
        "FOXGUARD_WEBHOOK_SECRET is required — set it to the same secret you \
         configured on the GitHub App"
    })?;
    if secret.is_empty() {
        return Err("FOXGUARD_WEBHOOK_SECRET must be non-empty".into());
    }

    let bind: SocketAddr = std::env::var("FOXGUARD_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;

    let state = AppState {
        webhook_secret: secret.into_bytes(),
        auth: GitHubAppAuthClient::new(AppCredentials::from_env()?)?,
        installation_tokens: Arc::new(Mutex::new(InstallationTokenCache::new())),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/webhook", post(webhook))
        // Cap incoming bodies before they hit the handler so a hostile
        // multi-GB delivery cannot exhaust memory.
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!(%bind, "foxguard-github-app starting");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    info!("shutdown signal received");
                }
                Err(error) => {
                    warn!(%error, "failed to install Ctrl-C handler");
                    std::future::pending::<()>().await;
                }
            }
        })
        .await?;

    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

/// Webhook handler. Verifies the GitHub HMAC, parses the event type
/// from the `X-GitHub-Event` header, and dispatches to a per-kind
/// stub. All paths return 202 except for verification failures
/// (401) and oversized / unparseable inputs (400) — keeping retry
/// semantics correct on GitHub's end.
async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> StatusCode {
    let signature = match headers
        .get("X-Hub-Signature-256")
        .and_then(|h| h.to_str().ok())
    {
        Some(v) => v,
        None => {
            warn!("webhook delivery missing X-Hub-Signature-256");
            return StatusCode::UNAUTHORIZED;
        }
    };

    if let Err(e) = verify_signature(&state.webhook_secret, signature, &body) {
        // Log internally with detail; respond externally with the
        // same status either way so we don't leak the failure mode.
        match e {
            SignatureError::MalformedHeader => {
                warn!("webhook signature header malformed");
            }
            SignatureError::Mismatch => {
                warn!("webhook signature mismatch — possible forgery attempt");
            }
        }
        return StatusCode::UNAUTHORIZED;
    }

    let event = headers
        .get("X-GitHub-Event")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let kind = EventKind::from_header(event);
    let delivery = headers
        .get("X-GitHub-Delivery")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("?");

    match kind {
        EventKind::Ping => {
            info!(delivery, "ping received");
        }
        EventKind::Installation => match parse_webhook_payload(&body) {
            Ok(payload) => {
                if let Some(installation) = payload.installation {
                    if payload.action.as_deref() == Some("deleted") {
                        remove_cached_installation_token(&state, installation.id);
                    }
                    info!(
                        delivery,
                        installation_id = installation.id,
                        action = payload.action.as_deref().unwrap_or("?"),
                        "installation event — TODO: persist install metadata"
                    );
                } else {
                    warn!(delivery, "installation event missing installation.id");
                }
            }
            Err(error) => {
                warn!(delivery, %error, "installation payload was not valid JSON");
            }
        },
        EventKind::PullRequest => match parse_webhook_payload(&body) {
            Ok(payload) => {
                if let Some(installation) = payload.installation {
                    let state_for_task = state.clone();
                    let delivery = delivery.to_string();
                    let action = payload.action.unwrap_or_else(|| "?".to_string());
                    let installation_id = installation.id;
                    std::mem::drop(tokio::spawn(async move {
                        match installation_token_for(&state_for_task, installation_id).await {
                            Ok(_) => {
                                info!(
                                    delivery,
                                    installation_id,
                                    action,
                                    "pull_request auth ready — TODO: clone, run foxguard, post --github-pr comment"
                                );
                            }
                            Err(error) => {
                                warn!(
                                    delivery,
                                    installation_id,
                                    %error,
                                    "failed to prepare pull_request auth"
                                );
                            }
                        }
                    }));
                } else {
                    warn!(delivery, "pull_request event missing installation.id");
                }
            }
            Err(error) => {
                warn!(delivery, %error, "pull_request payload was not valid JSON");
            }
        },
        EventKind::Other => {
            // Acknowledge so GitHub doesn't retry. We log at debug
            // because a noisy install can subscribe us to events we
            // don't care about and we don't want to flood info-level.
            tracing::debug!(delivery, event, "unhandled event acknowledged");
        }
    }

    StatusCode::ACCEPTED
}

fn parse_webhook_payload(body: &[u8]) -> Result<GitHubWebhookPayload, serde_json::Error> {
    serde_json::from_slice(body)
}

async fn installation_token_for(
    state: &AppState,
    installation_id: u64,
) -> Result<String, AuthError> {
    if let Some(token) = cached_installation_token(state, installation_id) {
        return Ok(token);
    }

    let token = state
        .auth
        .create_installation_token(installation_id)
        .await?;
    let value = token.token.clone();
    match state.installation_tokens.lock() {
        Ok(mut cache) => cache.remember(installation_id, token, std::time::SystemTime::now()),
        Err(error) => {
            warn!(%error, installation_id, "installation token cache lock poisoned");
        }
    }
    Ok(value)
}

fn cached_installation_token(state: &AppState, installation_id: u64) -> Option<String> {
    match state.installation_tokens.lock() {
        Ok(cache) => cache
            .lookup(installation_id, std::time::SystemTime::now())
            .map(str::to_owned),
        Err(error) => {
            warn!(%error, installation_id, "installation token cache lock poisoned");
            None
        }
    }
}

fn remove_cached_installation_token(state: &AppState, installation_id: u64) {
    match state.installation_tokens.lock() {
        Ok(mut cache) => cache.remove(installation_id),
        Err(error) => {
            warn!(%error, installation_id, "installation token cache lock poisoned");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_installation_id_from_pull_request_payload() {
        let payload =
            match parse_webhook_payload(br#"{"action":"opened","installation":{"id":12345}}"#) {
                Ok(payload) => payload,
                Err(error) => panic!("payload should parse: {error}"),
            };

        assert_eq!(payload.action.as_deref(), Some("opened"));
        assert_eq!(
            payload.installation.map(|installation| installation.id),
            Some(12345)
        );
    }

    #[test]
    fn parses_payload_without_installation_id() {
        let payload = match parse_webhook_payload(br#"{"action":"synchronize"}"#) {
            Ok(payload) => payload,
            Err(error) => panic!("payload should parse: {error}"),
        };

        assert_eq!(payload.action.as_deref(), Some("synchronize"));
        assert!(payload.installation.is_none());
    }
}
