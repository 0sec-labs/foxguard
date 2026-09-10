#!/usr/bin/env bash
set -euo pipefail

# Prepare a tag-driven release for foxguard.
# Usage: ./scripts/release.sh 0.3.3
#
# This script prepares release metadata and runs local verification.  It
# NEVER pushes branches, creates tags, or publishes.  Use it on a release
# branch, then open a PR.  After the PR merges to main, tag the verified
# merge commit to trigger the existing Release workflow.

VERSION="${1:?Usage: ./scripts/release.sh <version>}"
TAG="v${VERSION}"
RELEASE_NOTES="docs/releases/${TAG}.md"
BRANCH="$(git branch --show-current)"

echo "=== Preparing foxguard ${TAG} ==="

if ! [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must look like 0.3.3"
  exit 1
fi

if [ -z "${BRANCH}" ] || [ "${BRANCH}" = "main" ]; then
  echo "Prepare releases on a dedicated release branch"
  exit 1
fi

if [ ! -f "${RELEASE_NOTES}" ]; then
  echo "Write release notes at ${RELEASE_NOTES} before preparing ${TAG}"
  exit 1
fi

# The new release note may be untracked. Every other local or staged change
# blocks preparation so the release metadata can be reviewed independently.
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

if git rev-parse "${TAG}" >/dev/null 2>&1; then
  echo "Tag ${TAG} already exists locally"
  exit 1
fi

REMOTE_TAG="$(git ls-remote --tags origin "refs/tags/${TAG}")"
if [ -n "${REMOTE_TAG}" ]; then
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

# Refresh Cargo.lock root-package version so that subsequent --locked checks
# pass without fetching registry data or upgrading unrelated dependencies.
cargo update --workspace --offline

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

echo ""
echo "=== ${TAG} metadata prepared ==="
echo ""
echo "The working tree now contains version bumps, updated lock files,"
echo "README action-ref updates, and ${RELEASE_NOTES}."
echo ""
echo "To finish this release:"
echo ""
echo "  1. Review every changed file:"
echo ""
echo "       git diff"
echo ""
echo "  2. Commit the release metadata on this branch:"
echo ""
echo "       git add Cargo.toml Cargo.lock"
echo "       git add packages/npm/package.json"
echo "       git add vscode-extension/package.json vscode-extension/package-lock.json"
echo "       git add README.md ${RELEASE_NOTES}"
echo "       git commit -m \"Prepare ${TAG} release metadata\""
echo ""
echo "  3. Push the branch and open a pull request against main:"
echo ""
echo "       git push origin ${BRANCH}"
echo ""
echo "  4. After the PR passes required checks and is merged to main,"
echo "     check out the merge commit and tag it:"
echo ""
echo "       git checkout main"
echo "       git pull --ff-only"
echo "       git tag ${TAG}"
echo "       git push origin ${TAG}"
echo ""
echo "  5. The tag push triggers the Release workflow at"
echo "     https://github.com/0sec-labs/foxguard/actions/workflows/release.yml"
echo "     to build binaries, create a GitHub Release, and publish"
echo "     to crates.io, npm, VS Code Marketplace, and GHCR."