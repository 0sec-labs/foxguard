//! GitHub App webhook receiver foundation.
//!
//! This module hosts the pieces needed to receive `pull_request` and
//! `installation` events from GitHub and route them into a foxguard
//! scan. Right now it ships only the foundation:
//!
//! * [`webhook::verify_signature`] — constant-time HMAC-SHA256 check
//!   over the raw request body using the configured webhook secret.
//! * [`webhook::EventKind`] — minimal enum mapping the
//!   `X-GitHub-Event` header to the events the receiver actually
//!   handles.
//!
//! The HTTP server, JWT-based installation auth, and the
//! `pull_request` → scan → comment pipeline live in the
//! `foxguard-github-app` binary at `src/bin/foxguard_github_app.rs`
//! and are intentionally kept thin so the architecture can be
//! reviewed in isolation before the full `pull_request` handler
//! lands.
//!
//! Tracking issue: <https://github.com/PwnKit-Labs/foxguard/issues/246>.

pub mod webhook;
