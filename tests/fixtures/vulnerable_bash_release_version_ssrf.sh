#!/usr/bin/env bash
# Without the strict, fail-closed release-version allowlist, VERSION can alter
# the release-download URL passed to curl.

VERSION="$1"
REPO="0sec-labs/foxguard"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
DOWNLOAD_URL="${BASE_URL}/foxguard"
curl --fail --silent --show-error --location "$DOWNLOAD_URL"
