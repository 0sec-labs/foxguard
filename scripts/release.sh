#!/usr/bin/env bash
set -euo pipefail

# Prepare a tag-driven release for foxguard.
# Usage: ./scripts/release.sh 0.3.3

VERSION="${1:?Usage: ./scripts/release.sh <version>}"
TAG="v${VERSION}"
BRANCH="$(git branch --show-current)"

echo "=== Preparing foxguard ${TAG} ==="

if ! [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must look like 0.3.3"
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Working tree must be clean before preparing a release"
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

(
  cd vscode-extension
  npm install --package-lock-only
)

echo "Verifying release candidate..."
cargo fmt --check
cargo clippy -- -D warnings
cargo test
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
git add Cargo.toml Cargo.lock packages/npm/package.json vscode-extension/package.json vscode-extension/package-lock.json
git commit -m "Prepare ${TAG} release metadata" -m "Bump crate, npm, and VS Code extension versions to ${VERSION} so the
tag-driven release workflow can publish a coherent release.

Constraint: Release automation now validates tag-to-version alignment before publishing
Rejected: Keep manual publish steps in the local script | duplicates the release workflow and increases drift risk
Confidence: high
Scope-risk: narrow
Reversibility: clean
Directive: Use this script to prepare release metadata, then let the tag-triggered GitHub workflow publish artifacts
Tested: cargo fmt --check; cargo clippy -- -D warnings; cargo test; npm ci && npm run build (www); npm ci && npm run compile (vscode-extension); npm pack --dry-run (packages/npm)
Not-tested: Live publish against GitHub Releases, npm, crates.io, and VS Code Marketplace"

echo "Pushing branch and tag..."
git push origin main
git tag "${TAG}"
git push origin "${TAG}"

echo ""
echo "=== ${TAG} queued ==="
echo "GitHub Actions release workflow will build binaries and publish GitHub, crates.io, npm, and VS Code if the required secrets are configured."
