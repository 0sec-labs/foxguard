# foxguard GitHub App — Phase 1 foundation

Tracking issue: [0sec-labs/foxguard#246](https://github.com/0sec-labs/foxguard/issues/246).

This directory hosts the in-tree pieces of the GitHub App webhook receiver. The receiver is built behind the `github-app` feature flag so the core scanner build stays lean for users who only want the CLI:

```sh
# Build the App receiver binary
cargo build --release --features github-app --bin foxguard-github-app
```

## What's here today (Phase 1)

- `webhook.rs` — HMAC-SHA256 signature verification (`verify_signature`) and the `EventKind` router enum. 10 unit tests pin the verification contract: known-good vector, modified body, wrong secret, missing/empty/non-hex/short-length digest, trailing-whitespace tolerance, and the kind-routing map.
- `auth.rs` — GitHub App JWT generation plus installation-token exchange. It reads app credentials from `FOXGUARD_GITHUB_APP_ID` and either `FOXGUARD_GITHUB_PRIVATE_KEY` or an absolute `FOXGUARD_GITHUB_PRIVATE_KEY_PATH`, and keeps the outbound GitHub API base URL configurable for tests and allowlisted GitHub Enterprise hosts.
- `src/bin/foxguard_github_app.rs` — axum-based HTTP server with `/healthz` and `/webhook` endpoints. Verifies the signature, routes by `X-GitHub-Event`, and returns `202 Accepted` for all known kinds with the actual handler bodies stubbed and clearly marked TODO.

## What's NOT here yet (Phase 2)

The intentional gap. Each of these is a follow-up PR so the architecture above can land cleanly first:

- **Auth wiring and token cache.** The auth client exists; the event handlers still need to call it and cache installation tokens until expiry.
- **`pull_request` handler.** Clone the head ref into a sandboxed temp dir, run `foxguard scan` with a 60s timeout and a 1 GB repo cap, post the existing `--github-pr` output as a PR comment.
- **`installation` handler.** Persist install metadata so we know which orgs we're serving. SQLite is fine for Phase 1; the data is small and operationally easy to back up.
- **Check Runs API.** Inline annotations on the diff once the comment path is solid.

## Running locally

```sh
export FOXGUARD_WEBHOOK_SECRET=$(openssl rand -hex 32)
export FOXGUARD_GITHUB_APP_ID=12345
export FOXGUARD_GITHUB_PRIVATE_KEY_PATH=/path/to/private-key.pem
# Optional for GitHub Enterprise:
# export FOXGUARD_GITHUB_API_BASE_URL=https://github.example.com/api/v3
# export FOXGUARD_GITHUB_ALLOWED_API_HOSTS=github.example.com
export FOXGUARD_BIND=127.0.0.1:8080
foxguard-github-app
```

For testing without GitHub:

```sh
BODY='{"zen":"hello"}'
SECRET="$FOXGUARD_WEBHOOK_SECRET"
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | cut -d' ' -f2)"
curl -sS -X POST http://127.0.0.1:8080/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: ping" \
  -H "X-GitHub-Delivery: test-1" \
  -H "X-Hub-Signature-256: $SIG" \
  --data "$BODY"
# → 202
```

## Self-hosting

A reference Dockerfile lives at the repo root: [`Dockerfile.github-app`](../../Dockerfile.github-app). It builds the binary with the `github-app` feature, drops to a non-root user, and exposes `:8080`. Operators can deploy it to anything that runs containers (Fly.io, Railway, ECS, a tiny VM); the only persistent state once the install handler lands will be the install metadata, which is fine on a single small SQLite volume.

## Status

This PR is **Phase 1 only** — webhook foundation, no scan execution, no GitHub API calls outbound. The bones are here; everything else hangs off them. Ready for review on the architecture before the rest follows.
