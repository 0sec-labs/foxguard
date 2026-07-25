#!/usr/bin/env bash
set -euo pipefail

# Prepare a tag-driven release for foxguard.
# Usage: ./scripts/release.sh 0.3.3

VERSION="${1:?Usage: ./scripts/release.sh <version>}"
TAG="v${VERSION}"
RELEASE_NOTES="docs/releases/${TAG}.md"
BRANCH="$(git branch --show-current)"

echo "=== Preparing foxguard ${TAG} ==="

if ! [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must look like 0.3.3"
  exit 1
fi

if [ ! -f "${RELEASE_NOTES}" ]; then
  echo "Write release notes at ${RELEASE_NOTES} before preparing ${TAG}"
  exit 1
fi

# The versioned release note may be newly authored and untracked; the release
# metadata commit below stages it. Every other local or staged change is a
# release blocker so the tag always points at a deliberate, reviewable tree.
DIRTY_PATHS="$(
  {
    git diff --name-only
    git diff --cached --name-only
    git ls-files --others --exclude-standard
  } | sort -u
)"
UNEXPECTED_PATHS="$(printf '%s' "${DIRTY_PATHS}" | grep -Fvx "${RELEASE_NOTES}" || true)"
if [ -n "${UNEXPECTED_PATHS}" ]; then
  echo "Working tree may only contain ${RELEASE_NOTES} before preparing a release"
  echo "Unexpected changes:"
  printf '%s\n' "${UNEXPECTED_PATHS}"
  exit 1
fi

if [ "${BRANCH}" != "main" ]; then
  echo "Run releases from main (current branch: ${BRANCH})"
  exit 1
fi

if git rev-parse "${TAG}" >/dev/null 2>&1; then
  echo "Tag ${TAG} already exists locally"
  exit 1
fi

if git ls-remote --tags origin "refs/tags/${TAG}" | grep -q .; then
  echo "Tag ${TAG} already exists on origin"
  exit 1
fi

echo "Bumping versions..."
perl -0pi -e 's/^version = ".*"/version = "'"${VERSION}"'"/m' Cargo.toml

for pkg in packages/npm/package.json vscode-extension/package.json; do
  node -e "
    const fs = require('fs');
    const path = '${pkg}';
    const data = JSON.parse(fs.readFileSync(path, 'utf8'));
    data.version = '${VERSION}';
    fs.writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
  "
done

# Rewrite README install-ref examples so copy-pasteable snippets stay pinned
# to the version users are about to receive.
perl -i -pe 's{(0sec-labs/foxguard/action)\@v[0-9]+\.[0-9]+\.[0-9]+}{$1\@v'"${VERSION}"'}g' README.md
perl -i -pe 's{(\s+rev:\s+)v[0-9]+\.[0-9]+\.[0-9]+}{${1}v'"${VERSION}"'}g' README.md

(
  cd vscode-extension
  npm install --package-lock-only
)

echo "Verifying release candidate..."
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
(
  cd www
  npm ci
  npm run build
)
(
  cd vscode-extension
  npm ci
  npm run compile
)
(
  cd packages/npm
  npm pack --dry-run
)

echo "Committing release metadata..."
git add Cargo.toml Cargo.lock packages/npm/package.json vscode-extension/package.json vscode-extension/package-lock.json README.md "${RELEASE_NOTES}"
git commit -m "Prepare ${TAG} release metadata" -m "Bump crate, npm, and VS Code extension versions to ${VERSION} so the
tag-driven release workflow can publish a coherent release.

Constraint: Release automation now validates tag-to-version alignment before publishing
Rejected: Keep manual publish steps in the local script | duplicates the release workflow and increases drift risk
Confidence: high
Scope-risk: narrow
Reversibility: clean
Directive: Use this script to prepare release metadata, then let the tag-triggered GitHub workflow publish artifacts
Tested: cargo fmt --check; cargo clippy --locked --all-targets --all-features -- -D warnings; cargo test --locked --all-features; npm ci && npm run build (www); npm ci && npm run compile (vscode-extension); npm pack --dry-run (packages/npm)
Not-tested: Live publish against GitHub Releases, npm, crates.io, and VS Code Marketplace"

echo "Pushing branch and tag..."
git push origin main
git tag "${TAG}"
git push origin "${TAG}"

echo ""
echo "=== ${TAG} queued ==="
echo "GitHub Actions release workflow will build binaries, publish artifact attestations, and publish GitHub, crates.io, npm, and VS Code if the required secrets are configured."
