//! foxguard-github-app — webhook receiver for the foxguard GitHub App.
//!
//! See `src/github_app/README.md` and the tracking issue at
//! <https://github.com/PwnKit-Labs/foxguard/issues/246> for the design
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
//! Docker:   `docker build -f Dockerfile.github-app -t foxguard/github-app .`

use std::net::SocketAddr;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use foxguard::github_app::webhook::{verify_signature, EventKind, SignatureError};
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
            tokio::signal::ctrl_c()
                .await
                .expect("install Ctrl-C handler");
            info!("shutdown signal received");
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
        EventKind::Installation => {
            info!(
                delivery,
                "installation event — TODO: persist install metadata"
            );
        }
        EventKind::PullRequest => {
            info!(
                delivery,
                "pull_request event — TODO: clone, run foxguard, post --github-pr comment"
            );
        }
        EventKind::Other => {
            // Acknowledge so GitHub doesn't retry. We log at debug
            // because a noisy install can subscribe us to events we
            // don't care about and we don't want to flood info-level.
            tracing::debug!(delivery, event, "unhandled event acknowledged");
        }
    }

    StatusCode::ACCEPTED
}

#[cfg(test)]
mod tests {
    // The signature verification logic itself is exhaustively tested
    // in `src/github_app/webhook.rs`. Routing is exercised by the
    // axum runtime in production; pulling it into unit tests would
    // require spinning up a tokio runtime per test for low marginal
    // value. When the pull_request handler lands it should ship with
    // its own integration tests against a mocked GitHub API.
}
