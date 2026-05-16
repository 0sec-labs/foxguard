#!/usr/bin/env bash
set -euo pipefail

# ─── Resolve version ────────────────────────────────────────────────────────

VERSION="${INPUT_VERSION:-latest}"
REPO="0sec-labs/foxguard"

if [ "$VERSION" = "latest" ]; then
    echo "::group::Fetching latest foxguard release"
    VERSION=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "Latest version: ${VERSION}"
    echo "::endgroup::"
fi

# ─── Detect platform ────────────────────────────────────────────────────────

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}" in
    linux)  PLATFORM="linux" ;;
    darwin) PLATFORM="macos" ;;
    mingw*|msys*|cygwin*) PLATFORM="windows" ;;
    *)      echo "::error::Unsupported OS: ${OS}"; exit 1 ;;
esac

case "${ARCH}" in
    x86_64|amd64) ARCH_SUFFIX="x86_64" ;;
    aarch64|arm64) ARCH_SUFFIX="aarch64" ;;
    *)             echo "::error::Unsupported architecture: ${ARCH}"; exit 1 ;;
esac

if [ "${PLATFORM}" = "windows" ]; then
    BINARY_NAME="foxguard-${PLATFORM}-${ARCH_SUFFIX}.exe"
    EXECUTABLE_NAME="foxguard.exe"
else
    BINARY_NAME="foxguard-${PLATFORM}-${ARCH_SUFFIX}"
    EXECUTABLE_NAME="foxguard"
fi

# ─── Download binary ────────────────────────────────────────────────────────

echo "::group::Downloading foxguard ${VERSION} for ${PLATFORM}-${ARCH_SUFFIX}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"
echo "URL: ${DOWNLOAD_URL}"

INSTALL_DIR="${RUNNER_TEMP:-/tmp}/foxguard"
mkdir -p "${INSTALL_DIR}"

curl -sL "${DOWNLOAD_URL}" -o "${INSTALL_DIR}/${EXECUTABLE_NAME}"
if [ "${PLATFORM}" != "windows" ]; then
    chmod +x "${INSTALL_DIR}/${EXECUTABLE_NAME}"
fi
echo "::endgroup::"

# ─── Build arguments ────────────────────────────────────────────────────────

SCAN_PATH="${INPUT_PATH:-.}"
SEVERITY="${INPUT_SEVERITY:-low}"
FORMAT="${INPUT_FORMAT:-sarif}"
FAIL_ON_FINDINGS="${INPUT_FAIL_ON_FINDINGS:-true}"
UPLOAD_SARIF="${INPUT_UPLOAD_SARIF:-true}"

ARGS=("${SCAN_PATH}" "-f" "${FORMAT}")

if [ "${SEVERITY}" != "low" ]; then
    ARGS+=("-s" "${SEVERITY}")
fi

# ─── Run scan ────────────────────────────────────────────────────────────────

echo "::group::Running foxguard"
echo "foxguard ${ARGS[*]}"

SARIF_FILE="${RUNNER_TEMP:-/tmp}/foxguard-results.sarif"
EXIT_CODE=0
EXECUTABLE_PATH="${INSTALL_DIR}/${EXECUTABLE_NAME}"

if [ "${FORMAT}" = "sarif" ]; then
    "${EXECUTABLE_PATH}" "${ARGS[@]}" > "${SARIF_FILE}" || EXIT_CODE=$?
    FINDINGS_COUNT=$(python3 -c "
import json, sys
try:
    data = json.load(open('${SARIF_FILE}'))
    results = data.get('runs', [{}])[0].get('results', [])
    print(len(results))
except:
    print(0)
" 2>/dev/null || echo "0")
else
    OUTPUT=$("${EXECUTABLE_PATH}" "${ARGS[@]}" 2>&1) || EXIT_CODE=$?
    echo "${OUTPUT}"
    if [ "${FORMAT}" = "json" ]; then
        FINDINGS_COUNT=$(echo "${OUTPUT}" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    else
        FINDINGS_COUNT="${EXIT_CODE}"
    fi
fi

echo "::endgroup::"

# ─── Set outputs ─────────────────────────────────────────────────────────────

echo "findings-count=${FINDINGS_COUNT}" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "sarif-file=${SARIF_FILE}" >> "${GITHUB_OUTPUT:-/dev/null}"

echo "Findings: ${FINDINGS_COUNT}"

# ─── Generate badge JSON (shields.io endpoint format) ────────────────────────

BADGE_LABEL="${INPUT_BADGE_LABEL:-foxguard}"
BADGE_FILE="${RUNNER_TEMP:-/tmp}/foxguard-badge.json"

if [ "${FINDINGS_COUNT}" = "0" ]; then
    BADGE_MESSAGE="clean"
    BADGE_COLOR="2dd4bf"
else
    BADGE_MESSAGE="${FINDINGS_COUNT} issue(s)"
    BADGE_COLOR="f59e0b"
fi

cat > "${BADGE_FILE}" <<BADGE_EOF
{
  "schemaVersion": 1,
  "label": "${BADGE_LABEL}",
  "message": "${BADGE_MESSAGE}",
  "color": "${BADGE_COLOR}",
  "namedLogo": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSI+PHBhdGggZD0iTTggOEwyMCAyOEwzMiAyMEw0NCAyOEw1NiA4TDUyIDMyTDQ0IDQ0TDM2IDUySDI4TDIwIDQ0TDEyIDMyTDggOFoiIGZpbGw9IiNGNTlFMEIiIGZpbGwtb3BhY2l0eT0iMC4yNSIgc3Ryb2tlPSIjRjU5RTBCIiBzdHJva2Utd2lkdGg9IjMiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz48Y2lyY2xlIGN4PSIyNCIgY3k9IjMyIiByPSIyLjUiIGZpbGw9IiNGNTlFMEIiLz48Y2lyY2xlIGN4PSI0MCIgY3k9IjMyIiByPSIyLjUiIGZpbGw9IiNGNTlFMEIiLz48L3N2Zz4="
}
BADGE_EOF

echo "badge-json=${BADGE_FILE}" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "Badge JSON written to: ${BADGE_FILE}"

# ─── Upload SARIF ────────────────────────────────────────────────────────────

if [ "${FORMAT}" = "sarif" ] && [ "${UPLOAD_SARIF}" = "true" ] && [ -f "${SARIF_FILE}" ] && [ -s "${SARIF_FILE}" ]; then
    echo "::group::Uploading SARIF to GitHub Code Scanning"
    # Use the github/codeql-action/upload-sarif action via the workflow
    # Set the sarif file path for subsequent steps
    echo "SARIF results written to: ${SARIF_FILE}"
    echo "::endgroup::"

    # Upload SARIF using the API directly
    if command -v gzip &>/dev/null; then
        SARIF_BASE64=$(gzip -c "${SARIF_FILE}" | base64 | tr -d '\n')
        COMMIT_SHA="${GITHUB_SHA:-$(git rev-parse HEAD)}"
        REF="${GITHUB_REF:-$(git symbolic-ref HEAD)}"

        curl -sL -X POST \
            -H "Authorization: token ${INPUT_GITHUB_TOKEN}" \
            -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/${GITHUB_REPOSITORY}/code-scanning/sarifs" \
            -d "{\"commit_sha\":\"${COMMIT_SHA}\",\"ref\":\"${REF}\",\"sarif\":\"${SARIF_BASE64}\"}" \
            > /dev/null 2>&1 || echo "::warning::Failed to upload SARIF results (Code Scanning may not be enabled)"
    fi
fi

# ─── Fail check if configured ───────────────────────────────────────────────

if [ "${FAIL_ON_FINDINGS}" = "true" ] && [ "${EXIT_CODE}" -ne 0 ]; then
    echo "::error::Foxguard found ${FINDINGS_COUNT} security issue(s) at severity '${SEVERITY}' or above"
    exit 1
fi
