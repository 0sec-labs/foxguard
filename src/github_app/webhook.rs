//! GitHub webhook signature verification.
//!
//! GitHub signs every webhook delivery with HMAC-SHA256 over the raw
//! request body, using the secret configured at App-creation time, and
//! sends the digest in the `X-Hub-Signature-256` header in the form
//! `sha256=<hex>`. Receivers MUST verify this before doing anything
//! with the payload — otherwise an attacker can forge events to the
//! public webhook URL and trigger scans on arbitrary repositories.
//!
//! Documentation: <https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Errors returned by [`verify_signature`]. Variants are deliberately
/// coarse — a verification failure should never tell an attacker
/// *why* the check failed (it could leak something about the secret
/// shape or header parsing).
#[derive(Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// Header was missing or did not start with `sha256=`.
    MalformedHeader,
    /// Signature decoded successfully but did not match the expected
    /// HMAC of the body. Always treated as a forgery.
    Mismatch,
}

/// Verify the `X-Hub-Signature-256` header against the raw request
/// body. Returns `Ok(())` on success.
///
/// `secret` is the webhook secret configured for the GitHub App.
/// `header` is the full header value as received (`sha256=…`).
/// `body` is the raw request body bytes — exactly as received over
/// the wire, including any whitespace. Re-serializing parsed JSON
/// will not match.
///
/// The comparison runs in constant time relative to the secret and
/// signature length, so this function is safe to call on every
/// request.
pub fn verify_signature(secret: &[u8], header: &str, body: &[u8]) -> Result<(), SignatureError> {
    let prefix = "sha256=";
    let hex_digest = match header.strip_prefix(prefix) {
        Some(rest) => rest.trim(),
        None => return Err(SignatureError::MalformedHeader),
    };

    if hex_digest.is_empty() {
        return Err(SignatureError::MalformedHeader);
    }

    let received = match hex::decode(hex_digest) {
        Ok(bytes) => bytes,
        Err(_) => return Err(SignatureError::MalformedHeader),
    };

    // SHA-256 always emits 32 bytes. A wrong-length input cannot
    // match a real signature, but we explicitly reject it here so
    // verify().is_err() doesn't accept short inputs as "no signature
    // at all" through whatever upstream comparator GitHub picks.
    if received.len() != 32 {
        return Err(SignatureError::MalformedHeader);
    }

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| SignatureError::Mismatch)?;
    mac.update(body);

    // `hmac::Mac::verify_slice` does the constant-time comparison
    // for us, so we don't have to roll our own subtle-time loop.
    mac.verify_slice(&received)
        .map_err(|_| SignatureError::Mismatch)
}

/// Subset of the GitHub event types this receiver currently routes.
/// Any other event maps to [`EventKind::Other`] and is acknowledged
/// with a 202 so GitHub's delivery dashboard stays clean instead of
/// retrying.
///
/// Variants are added as the matching handlers come online; today
/// none of these events do anything beyond log + 202 from the
/// binary, but having the enum landed early means follow-up PRs can
/// wire handlers without re-touching this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// `installation` / `installation_repositories` — App was added
    /// or removed from one or more repos.
    Installation,
    /// `pull_request` — PR opened / synchronised / reopened. The
    /// scan handler runs against the head ref.
    PullRequest,
    /// `ping` — initial delivery sent at App-creation / re-delivery.
    Ping,
    /// Anything else GitHub may legitimately deliver. Acknowledged
    /// without action.
    Other,
}

impl EventKind {
    /// Map the value of the `X-GitHub-Event` header to the routed
    /// kind. Unknown values map to [`EventKind::Other`] rather than
    /// erroring so the receiver remains forward-compatible with
    /// GitHub adding new event types.
    pub fn from_header(value: &str) -> Self {
        match value {
            "installation" | "installation_repositories" => Self::Installation,
            "pull_request" => Self::PullRequest,
            "ping" => Self::Ping,
            _ => Self::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vector: a known body + secret produces a known HMAC.
    // Computed once with `python -c "import hmac, hashlib; print(hmac.new(b'sekret', b'hello', hashlib.sha256).hexdigest())"`.
    const SECRET: &[u8] = b"sekret";
    const BODY: &[u8] = b"hello";
    const KNOWN_DIGEST: &str = "24de3247aa41906931f59dd849ce2bf66043c21955d9f4726c198ee3006c5f47";

    fn ok_header() -> String {
        format!("sha256={KNOWN_DIGEST}")
    }

    #[test]
    fn verify_accepts_known_signature() {
        assert_eq!(verify_signature(SECRET, &ok_header(), BODY), Ok(()));
    }

    #[test]
    fn verify_rejects_modified_body() {
        assert_eq!(
            verify_signature(SECRET, &ok_header(), b"hellO"),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        assert_eq!(
            verify_signature(b"wrong", &ok_header(), BODY),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn verify_rejects_missing_prefix() {
        assert_eq!(
            verify_signature(SECRET, KNOWN_DIGEST, BODY),
            Err(SignatureError::MalformedHeader)
        );
    }

    #[test]
    fn verify_rejects_empty_digest() {
        assert_eq!(
            verify_signature(SECRET, "sha256=", BODY),
            Err(SignatureError::MalformedHeader)
        );
    }

    #[test]
    fn verify_rejects_non_hex() {
        assert_eq!(
            verify_signature(SECRET, "sha256=zzzz", BODY),
            Err(SignatureError::MalformedHeader)
        );
    }

    #[test]
    fn verify_rejects_short_digest() {
        // 16 bytes worth of hex (32 chars) is wrong length for SHA-256
        // and must be rejected even though it's structurally hex.
        assert_eq!(
            verify_signature(SECRET, "sha256=00112233445566778899aabbccddeeff", BODY),
            Err(SignatureError::MalformedHeader)
        );
    }

    #[test]
    fn verify_handles_trimming() {
        // Trailing whitespace on the header value (CRLF artefacts
        // from a misbehaving proxy) shouldn't break verification.
        let with_ws = format!("sha256={KNOWN_DIGEST}  ");
        assert_eq!(verify_signature(SECRET, &with_ws, BODY), Ok(()));
    }

    #[test]
    fn event_kind_maps_known_headers() {
        assert_eq!(
            EventKind::from_header("pull_request"),
            EventKind::PullRequest
        );
        assert_eq!(
            EventKind::from_header("installation"),
            EventKind::Installation
        );
        assert_eq!(
            EventKind::from_header("installation_repositories"),
            EventKind::Installation
        );
        assert_eq!(EventKind::from_header("ping"), EventKind::Ping);
    }

    #[test]
    fn event_kind_unknown_falls_back_to_other() {
        // New GitHub events shouldn't break the receiver.
        assert_eq!(EventKind::from_header("workflow_run"), EventKind::Other);
        assert_eq!(EventKind::from_header(""), EventKind::Other);
    }
}
