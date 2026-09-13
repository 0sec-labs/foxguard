# foxguard GitHub App

Tracking issue: [0sec-labs/foxguard#246](https://github.com/0sec-labs/foxguard/issues/246).

**Status: live in production.** The App is registered under `0sec-labs`, receives webhooks at `https://foxguard.0sec.ai`, and runs as a container on the 0cloud k3s cluster, scanning pull requests across its installations.

This directory hosts the in-tree pieces of the GitHub App webhook receiver. The receiver is built behind the `github-app` feature flag so the core scanner build stays lean for users who only want the CLI:

```sh
# Build the App receiver binary
cargo build --release --features github-app --bin foxguard-github-app
```

## What's here today (Phase 1)

- `webhook.rs` — HMAC-SHA256 signature verification (`verify_signature`) and the `EventKind` router enum. 10 unit tests pin the verification contract: known-good vector, modified body, wrong secret, missing/empty/non-hex/short-length digest, trailing-whitespace tolerance, and the kind-routing map.
- `auth.rs` — GitHub App JWT generation, installation-token exchange, and conservative in-memory token caching. It reads app credentials from `FOXGUARD_GITHUB_APP_ID` and either `FOXGUARD_GITHUB_PRIVATE_KEY` or an absolute `FOXGUARD_GITHUB_PRIVATE_KEY_PATH`, and keeps the outbound GitHub API base URL configurable for tests and allowlisted GitHub Enterprise hosts.
- `installation_store.rs` — small JSON-backed installation registry. It records account metadata and selected repositories from `installation` / `installation_repositories` webhooks so self-hosted operators can recover install state across restarts without a database dependency.
- `src/bin/foxguard_github_app.rs` — axum-based HTTP server with `/healthz` and `/webhook` endpoints. Verifies signatures, routes events, persists installation metadata and pull-request jobs, and schedules eligible work fairly across installations. Defaults are 4 workers and a 128-slot wake buffer; the durable backlog is not bounded by that buffer. Replayed delivery IDs are deduplicated, and updates to the same repository/PR coalesce behind its active scan. Workers prepare installation auth, clone and scan PR heads in a bounded temporary workspace, update one marker-tagged summary comment, delete legacy inline comments, post check-run annotations, and clean up.
- `review.rs` — installation-token GitHub REST client for PR summary comments and check runs. It lists existing marker-tagged bot issue comments and legacy comments, lists changed PR files, filters findings to changed lines, creates or updates exactly one Markdown summary without inline comment payloads, and pins each finding link to the scanned PR-head SHA (with file-only findings linked without a line anchor). It deletes legacy inline foxguard comments and creates a `foxguard` check run with up to 50 annotations.

Signed installation and pull-request payloads that cannot be decoded return
`400 Bad Request`. Installation persistence failures return `503 Service Unavailable`
rather than acknowledging an update that was not saved. After repairing the store,
redeliver the failed event from GitHub's delivery dashboard or API.

## App configuration (registered & live)

The production App is registered under `0sec-labs` and installed at `https://foxguard.0sec.ai`. It requests **exactly** the permissions and webhook events the receiver consumes — anything less fails at runtime, anything more is over-scoped:

  **Repository permissions**
  - `contents: read` — used by `git clone --filter=blob:none` of the PR head (`src/bin/foxguard_github_app.rs`).
  - `pull_requests: read` — used to list PR files, marker-tagged bot summary comments, and legacy comments (`src/github_app/review.rs`, `GET /repos/{owner}/{repo}/pulls/{n}/files`, `/issues/{n}/comments`, and `/pulls/{n}/comments`).
  - `pull_requests: write` — used to create or update the foxguard PR summary and delete legacy inline comments (`POST /repos/{owner}/{repo}/issues/{n}/comments`, `PATCH /repos/{owner}/{repo}/issues/comments/{id}`, `DELETE /repos/{owner}/{repo}/pulls/comments/{id}`).
  - `checks: write` — used to create the `foxguard` check run with annotations (`POST /repos/{owner}/{repo}/check-runs`).

  **Subscribed events**
  - `pull_request` — triggers the clone + scan + review-summary + check-run loop.
  - `installation` — keeps `installation_store.rs` in sync when the App is installed, suspended, or uninstalled (also clears the cached installation token on deletion).
  - `installation_repositories` — keeps the registry in sync when a user adds or removes repos from an existing installation.

  `ping` is delivered automatically by GitHub at webhook setup; the receiver handles it but it is not a subscribable event.

## Fair scheduling

Workers choose jobs **when they are ready to claim work**, not when a webhook
fills the wake channel. Jobs remain in the durable store until eligible.

- Each claim advances a round-robin installation-ID cursor. The next waiting
  installation after that cursor gets a turn, wrapping at the end; removing the
  previous installation does not reset the cursor and starve other tenants.
- Within an installation, the oldest eligible durable queue sequence wins.
  A claimed/running repository/PR key is excluded, but it does not block other
  PRs from that installation. Superseded heads and replayed deliveries retain
  the existing deduplication and coalescing behavior.
- Wake tokens carry no preselected job or tenant. A newly waiting installation
  joins the next available round-robin turn rather than sitting behind another
  installation's buffered jobs.
- Claiming a job immediately replenishes available wake capacity. Even a
  one-slot buffer can keep multiple workers busy; replenishment does not wait
  for the claimed scan to finish.
- Recovery and lifecycle changes use the same durable queue and eligibility
  checks. If every remaining job is blocked by an active PR, completion wakes
  the scheduler to consider them again.

This is non-preemptive fairness at dispatch, not a per-installation concurrency
limit: running scans finish normally, and one tenant can use every idle worker
when no other tenant is waiting. A late tenant waits for a free worker and its
round-robin turn; it is not guaranteed the immediately next slot if other tenants
are also waiting.

`FOXGUARD_PR_WORKERS` bounds active workers (default 4).
`FOXGUARD_PR_QUEUE_CAPACITY` bounds only buffered wake signals (default 128), not
the durable backlog or disk usage. No new configuration is required.


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
# Optional admission controls (positive integers):
# export FOXGUARD_PR_QUEUE_CAPACITY=128
# export FOXGUARD_PR_WORKERS=4
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

A reference Dockerfile lives at the repo root: [`Dockerfile.github-app`](../../Dockerfile.github-app). It builds the binary with the `github-app` feature, drops to a non-root user, and exposes `:8080`. Operators can deploy it on a container host such as Fly.io, Railway, ECS, or a VM. Persist both the installation registry and pull-request job store on the mounted volume; the durable queue is not a disk quota.

## Status

Live in production. The receiver covers the full App loop: verified webhook intake, installation metadata persistence (durable via a mounted volume), installation-token auth, bounded PR checkout + scan (full-tree with diff-scoped fallback on timeout, configurable via `FOXGUARD_SCAN_TIMEOUT_SECS`, noise-path exclusions), one updateable PR summary comment containing every eligible finding, legacy inline-comment cleanup, and check-run annotations.
