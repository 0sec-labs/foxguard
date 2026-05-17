# foxguard GitHub App — Phase 1 foundation

Tracking issue: [0sec-labs/foxguard#246](https://github.com/0sec-labs/foxguard/issues/246).

This directory hosts the in-tree pieces of the GitHub App webhook receiver. The receiver is built behind the `github-app` feature flag so the core scanner build stays lean for users who only want the CLI:

```sh
# Build the App receiver binary
cargo build --release --features github-app --bin foxguard-github-app
```

## What's here today (Phase 1)

- `webhook.rs` — HMAC-SHA256 signature verification (`verify_signature`) and the `EventKind` router enum. 10 unit tests pin the verification contract: known-good vector, modified body, wrong secret, missing/empty/non-hex/short-length digest, trailing-whitespace tolerance, and the kind-routing map.
- `auth.rs` — GitHub App JWT generation, installation-token exchange, and conservative in-memory token caching. It reads app credentials from `FOXGUARD_GITHUB_APP_ID` and either `FOXGUARD_GITHUB_PRIVATE_KEY` or an absolute `FOXGUARD_GITHUB_PRIVATE_KEY_PATH`, and keeps the outbound GitHub API base URL configurable for tests and allowlisted GitHub Enterprise hosts.
- `installation_store.rs` — small JSON-backed installation registry. It records account metadata and selected repositories from `installation` / `installation_repositories` webhooks so self-hosted operators can recover install state across restarts without a database dependency.
- `src/bin/foxguard_github_app.rs` — axum-based HTTP server with `/healthz` and `/webhook` endpoints. Verifies the signature, routes by `X-GitHub-Event`, extracts installation IDs from JSON payloads, persists installation metadata, prepares installation auth for `pull_request` deliveries, clones and scans pull-request heads in a bounded temp workspace, posts foxguard PR review comments and a check run through the installation token, clears cached tokens when installations are deleted, and returns `202 Accepted` for all known kinds.
- `review.rs` — installation-token GitHub REST client for PR review comments and check runs. It deletes prior foxguard review comments, lists changed PR files, filters findings to commentable diff lines, posts inline comments using the shared CLI comment formatter, and creates a `foxguard` check run with up to 50 annotations.

## What's NOT here yet (Phase 2)

The intentional gap. Each of these is a follow-up PR so the architecture above can land cleanly first:

- **App registration.** Create the production GitHub App, wire the real install URL into the landing page, and verify the requested permissions include pull request review comments plus check runs.

## Running locally

```sh
export FOXGUARD_WEBHOOK_SECRET=$(openssl rand -hex 32)
export FOXGUARD_GITHUB_APP_ID=12345
export FOXGUARD_GITHUB_PRIVATE_KEY_PATH=/path/to/private-key.pem
# Optional for GitHub Enterprise:
# export FOXGUARD_GITHUB_API_BASE_URL=https://github.example.com/api/v3
# export FOXGUARD_GITHUB_ALLOWED_API_HOSTS=github.example.com
# Optional install metadata location (defaults to ./.foxguard-github-app/installations.json):
# export FOXGUARD_INSTALLATIONS_PATH=/var/lib/foxguard-github-app/installations.json
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

A reference Dockerfile lives at the repo root: [`Dockerfile.github-app`](../../Dockerfile.github-app). It builds the binary with the `github-app` feature, drops to a non-root user, and exposes `:8080`. Operators can deploy it to anything that runs containers (Fly.io, Railway, ECS, a tiny VM); the only persistent state is the install metadata JSON file, which is fine on a single small mounted volume.

## Status

The receiver now covers the first useful App loop: verified webhook intake, installation metadata persistence, installation-token auth, bounded PR checkout + scan, PR review comment posting, and check-run annotations.
