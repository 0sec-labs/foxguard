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
//! The HTTP server lives in the `foxguard-github-app` binary at
//! `src/bin/foxguard_github_app.rs`. The full `pull_request` → scan
//! → comment pipeline is intentionally staged as follow-up work.
//!
//! Tracking issue: <https://github.com/0sec-labs/foxguard/issues/246>.

pub mod auth;
pub mod webhook;
