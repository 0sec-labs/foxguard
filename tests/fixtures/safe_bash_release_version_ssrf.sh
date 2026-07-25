#!/usr/bin/env bash
# A strict, fail-closed release-version allowlist makes the interpolated
# GitHub release URL safe even though VERSION originates from script input.

VERSION="$1"
if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    echo "::error::Invalid release version: ${VERSION}"
    exit 1
fi

REPO="0sec-labs/foxguard"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
DOWNLOAD_URL="${BASE_URL}/foxguard"
curl --fail --silent --show-error --location "$DOWNLOAD_URL"
