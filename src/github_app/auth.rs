//! GitHub App JWT and installation-token authentication.
//!
//! GitHub App requests use a short-lived RS256 JWT signed with the
//! App private key. Installation-scoped requests then exchange that
//! JWT for a one-hour installation access token.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::{Component, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_API_BASE_URL: &str = "https://api.github.com";
const DEFAULT_API_HOST: &str = "api.github.com";
const GITHUB_API_VERSION: &str = "2026-03-10";
const JWT_BACKDATE_SECONDS: i64 = 60;
const JWT_TTL_SECONDS: i64 = 9 * 60;
const INSTALLATION_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
const INSTALLATION_TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(5 * 60);

#[derive(Debug)]
pub enum AuthError {
    MissingEnv(&'static str),
    InvalidAppId(std::num::ParseIntError),
    InvalidApiBaseUrl(String),
    InvalidPrivateKeyPath(String),
    Io(std::io::Error),
    Jwt(jsonwebtoken::errors::Error),
    Http(reqwest::Error),
    Time(std::time::SystemTimeError),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnv(name) => write!(f, "{name} is required"),
            Self::InvalidAppId(error) => write!(f, "invalid GitHub App ID: {error}"),
            Self::InvalidApiBaseUrl(error) => write!(f, "invalid GitHub API base URL: {error}"),
            Self::InvalidPrivateKeyPath(error) => {
                write!(f, "invalid GitHub App private key path: {error}")
            }
            Self::Io(error) => write!(f, "failed to read GitHub App private key: {error}"),
            Self::Jwt(error) => write!(f, "failed to sign GitHub App JWT: {error}"),
            Self::Http(error) => write!(f, "GitHub App auth request failed: {error}"),
            Self::Time(error) => write!(f, "system time is before Unix epoch: {error}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<std::io::Error> for AuthError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        Self::Jwt(error)
    }
}

impl From<reqwest::Error> for AuthError {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}

impl From<std::time::SystemTimeError> for AuthError {
    fn from(error: std::time::SystemTimeError) -> Self {
        Self::Time(error)
    }
}

#[derive(Clone)]
pub struct AppCredentials {
    app_id: u64,
    private_key_pem: Vec<u8>,
    api_base_url: String,
}

impl AppCredentials {
    pub fn new(app_id: u64, private_key_pem: Vec<u8>) -> Self {
        Self {
            app_id,
            private_key_pem,
            api_base_url: DEFAULT_API_BASE_URL.to_string(),
        }
    }

    pub fn from_env() -> Result<Self, AuthError> {
        let app_id = std::env::var("FOXGUARD_GITHUB_APP_ID")
            .map_err(|_| AuthError::MissingEnv("FOXGUARD_GITHUB_APP_ID"))?
            .parse()
            .map_err(AuthError::InvalidAppId)?;

        let private_key_pem = match std::env::var("FOXGUARD_GITHUB_PRIVATE_KEY") {
            Ok(value) => value.replace("\\n", "\n").into_bytes(),
            Err(_) => {
                let path = std::env::var("FOXGUARD_GITHUB_PRIVATE_KEY_PATH")
                    .map_err(|_| AuthError::MissingEnv("FOXGUARD_GITHUB_PRIVATE_KEY_PATH"))?;
                read_private_key_path(&path)?
            }
        };

        let api_base_url = std::env::var("FOXGUARD_GITHUB_API_BASE_URL")
            .unwrap_or_else(|_| DEFAULT_API_BASE_URL.to_string());
        validate_api_base_url(&api_base_url)?;

        Ok(Self {
            app_id,
            private_key_pem,
            api_base_url,
        })
    }

    pub fn app_id(&self) -> u64 {
        self.app_id
    }

    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }

    pub fn jwt(&self) -> Result<String, AuthError> {
        let now = unix_now()?;
        generate_app_jwt(self.app_id, &self.private_key_pem, now)
    }
}

fn read_private_key_path(path: &str) -> Result<Vec<u8>, AuthError> {
    let path = PathBuf::from(path); // foxguard: ignore[rs/no-path-traversal]
    if !path.is_absolute() {
        return Err(AuthError::InvalidPrivateKeyPath(
            "path must be absolute".to_string(),
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(AuthError::InvalidPrivateKeyPath(
            "path must not contain traversal components".to_string(),
        ));
    }

    // The path is operator-provided process configuration, validated above,
    // and used only to load the GitHub App signing key at startup.
    std::fs::read(&path).map_err(AuthError::Io) // foxguard: ignore[rs/no-path-traversal]
}

fn validate_api_base_url(api_base_url: &str) -> Result<(), AuthError> {
    let url = reqwest::Url::parse(api_base_url)
        .map_err(|error| AuthError::InvalidApiBaseUrl(error.to_string()))?;
    if url.scheme() != "https" {
        return Err(AuthError::InvalidApiBaseUrl(
            "scheme must be https".to_string(),
        ));
    }
    if url.username() != "" || url.password().is_some() {
        return Err(AuthError::InvalidApiBaseUrl(
            "credentials are not allowed".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(AuthError::InvalidApiBaseUrl(
            "query and fragment are not allowed".to_string(),
        ));
    }
    if url
        .path_segments()
        .into_iter()
        .flatten()
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(AuthError::InvalidApiBaseUrl(
            "path traversal segments are not allowed".to_string(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| AuthError::InvalidApiBaseUrl("host is required".to_string()))?;
    let allowed_hosts = std::env::var("FOXGUARD_GITHUB_ALLOWED_API_HOSTS").unwrap_or_default();
    let host_is_allowed = host == DEFAULT_API_HOST
        || allowed_hosts
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .any(|allowed| allowed.eq_ignore_ascii_case(host));
    if !host_is_allowed {
        return Err(AuthError::InvalidApiBaseUrl(format!(
            "host {host} is not allowlisted"
        )));
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct AppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

fn claims_for_app(app_id: u64, now: i64) -> AppJwtClaims {
    AppJwtClaims {
        iat: now - JWT_BACKDATE_SECONDS,
        exp: now + JWT_TTL_SECONDS,
        iss: app_id.to_string(),
    }
}

pub fn generate_app_jwt(
    app_id: u64,
    private_key_pem: &[u8],
    now: i64,
) -> Result<String, AuthError> {
    let claims = claims_for_app(app_id, now);
    // GitHub App JWTs are required by GitHub to use RS256, so this RSA
    // use is protocol-bound rather than an application crypto choice.
    let key = EncodingKey::from_rsa_pem(private_key_pem)?; // foxguard: ignore[rs/pq-vulnerable-crypto]
    Ok(encode(&Header::new(Algorithm::RS256), &claims, &key)?)
}

fn unix_now() -> Result<i64, AuthError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64)
}

#[derive(Debug, Deserialize)]
pub struct InstallationToken {
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Clone)]
struct CachedInstallationToken {
    token: String,
    refresh_at: SystemTime,
}

impl CachedInstallationToken {
    fn new(token: InstallationToken, received_at: SystemTime) -> Self {
        Self {
            token: token.token,
            refresh_at: received_at + INSTALLATION_TOKEN_TTL - INSTALLATION_TOKEN_REFRESH_SKEW,
        }
    }

    fn is_fresh(&self, now: SystemTime) -> bool {
        now < self.refresh_at
    }
}

#[derive(Debug, Default)]
pub struct InstallationTokenCache {
    tokens: HashMap<u64, CachedInstallationToken>,
}

impl InstallationTokenCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup(&self, installation_id: u64, now: SystemTime) -> Option<&str> {
        let token = self
            .tokens
            .iter()
            .find(|(cached_id, _)| **cached_id == installation_id)?
            .1;
        token.is_fresh(now).then_some(token.token.as_str())
    }

    pub fn remember(
        &mut self,
        installation_id: u64,
        token: InstallationToken,
        received_at: SystemTime,
    ) {
        self.tokens.insert(
            installation_id,
            CachedInstallationToken::new(token, received_at),
        );
    }

    pub fn remove(&mut self, installation_id: u64) {
        self.tokens.remove(&installation_id);
    }
}

#[derive(Clone)]
pub struct GitHubAppAuthClient {
    http: reqwest::Client,
    credentials: AppCredentials,
}

impl GitHubAppAuthClient {
    pub fn new(credentials: AppCredentials) -> Result<Self, AuthError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("foxguard-github-app")
            .build()?;
        Ok(Self { http, credentials })
    }

    pub async fn create_installation_token(
        &self,
        installation_id: u64,
    ) -> Result<InstallationToken, AuthError> {
        let jwt = self.credentials.jwt()?;
        let url = installation_token_url(self.credentials.api_base_url(), installation_id);
        // URL construction is restricted by `validate_api_base_url`; non-GitHub
        // Enterprise hosts must be explicitly allowlisted by the operator.
        let request = self.http.post(url); // foxguard: ignore[rs/no-ssrf]
        let response = request
            .bearer_auth(jwt)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        eprintln!("token-exchange: status={status} len={}", body.len());
        if !status.is_success() {
            eprintln!("token-exchange-error: {body}");
            return Err(AuthError::Jwt(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            )));
        }
        let token: InstallationToken = serde_json::from_str(&body).map_err(|e| {
            eprintln!("token-exchange-parse: {e}");
            AuthError::Jwt(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ))
        })?;
        eprintln!("token-exchange: ok token_prefix={}", &token.token[..token.token.len().min(10)]);
        Ok(token)
    }

    pub async fn installation_token(
        &self,
        cache: &mut InstallationTokenCache,
        installation_id: u64,
    ) -> Result<String, AuthError> {
        let now = SystemTime::now();
        if let Some(token) = cache.lookup(installation_id, now) {
            return Ok(token.to_string());
        }

        let token = self.create_installation_token(installation_id).await?;
        let value = token.token.clone();
        cache.remember(installation_id, token, now);
        Ok(value)
    }
}

fn installation_token_url(api_base_url: &str, installation_id: u64) -> String {
    format!(
        "{}/app/installations/{installation_id}/access_tokens",
        api_base_url.trim_end_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_jwt_claims_follow_github_clock_skew_guidance() {
        let claims = claims_for_app(12345, 1_700_000_000);
        assert_eq!(claims.iss, "12345");
        assert_eq!(claims.iat, 1_699_999_940);
        assert_eq!(claims.exp, 1_700_000_540);
        assert!(claims.exp - claims.iat <= 10 * 60);
    }

    #[test]
    fn installation_token_url_trims_base_url_slash() {
        assert_eq!(
            installation_token_url("https://api.github.com/", 42),
            "https://api.github.com/app/installations/42/access_tokens"
        );
    }

    #[test]
    fn validates_default_api_host() {
        assert!(validate_api_base_url(DEFAULT_API_BASE_URL).is_ok());
    }

    #[test]
    fn rejects_non_https_api_base_url() {
        let error = validate_api_base_url("http://api.github.com").unwrap_err();
        assert!(matches!(error, AuthError::InvalidApiBaseUrl(_)));
    }

    #[test]
    fn rejects_unallowlisted_api_host() {
        let error = validate_api_base_url("https://169.254.169.254").unwrap_err();
        assert!(matches!(error, AuthError::InvalidApiBaseUrl(_)));
    }

    #[test]
    fn invalid_private_key_is_reported_as_jwt_error() {
        let error = generate_app_jwt(12345, b"not a pem", 1_700_000_000).unwrap_err();
        assert!(matches!(error, AuthError::Jwt(_)));
    }

    #[test]
    fn token_cache_reuses_fresh_installation_token() {
        let mut cache = InstallationTokenCache::new();
        let received_at = UNIX_EPOCH + Duration::from_secs(1_000);
        cache.remember(
            42,
            InstallationToken {
                token: "ghs_token".to_string(),
                expires_at: "2026-05-17T15:00:00Z".to_string(),
            },
            received_at,
        );

        assert_eq!(
            cache.lookup(42, received_at + Duration::from_secs(30 * 60)),
            Some("ghs_token")
        );
    }

    #[test]
    fn token_cache_refreshes_before_github_expiry() {
        let mut cache = InstallationTokenCache::new();
        let received_at = UNIX_EPOCH + Duration::from_secs(1_000);
        cache.remember(
            42,
            InstallationToken {
                token: "ghs_token".to_string(),
                expires_at: "2026-05-17T15:00:00Z".to_string(),
            },
            received_at,
        );

        assert_eq!(
            cache.lookup(42, received_at + Duration::from_secs(56 * 60)),
            None
        );
    }

    #[test]
    fn token_cache_can_remove_installation() {
        let mut cache = InstallationTokenCache::new();
        let received_at = UNIX_EPOCH + Duration::from_secs(1_000);
        cache.remember(
            42,
            InstallationToken {
                token: "ghs_token".to_string(),
                expires_at: "2026-05-17T15:00:00Z".to_string(),
            },
            received_at,
        );
        cache.remove(42);

        assert_eq!(cache.lookup(42, received_at), None);
    }
}
