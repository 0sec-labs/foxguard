#!/bin/sh
# foxguard installer
#
# Installs the latest foxguard release from github.com/0sec-labs/foxguard.
# Usage:
#   curl -fsSL https://foxguard.dev/install.sh | sh
#
# Environment variables:
#   FOXGUARD_INSTALL_DIR  where to put the binary (default: $HOME/.local/bin)
#   FOXGUARD_VERSION      specific version tag to install (default: latest)

set -eu

REPO="0sec-labs/foxguard"
INSTALL_DIR="${FOXGUARD_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${FOXGUARD_VERSION:-latest}"

err() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || err "curl is required"

os="$(uname -s)"
case "$os" in
  Linux)  os_name="linux" ;;
  Darwin) os_name="macos" ;;
  *) err "unsupported OS: $os. On Windows, use: npx foxguard ." ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)   arch_name="x86_64" ;;
  aarch64|arm64)  arch_name="aarch64" ;;
  *) err "unsupported architecture: $arch" ;;
esac

binary_name="foxguard-${os_name}-${arch_name}"

if [ "$VERSION" = "latest" ]; then
  printf 'fetching latest foxguard release...\n'
  tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' | head -1 \
    | sed 's/.*"\([^"]*\)"$/\1/')"
  [ -n "$tag" ] || err "could not fetch latest release tag"
else
  tag="$VERSION"
fi

printf 'installing foxguard %s for %s-%s...\n' "$tag" "$os_name" "$arch_name"

mkdir -p "$INSTALL_DIR"

base_url="https://github.com/${REPO}/releases/download/${tag}"
download_url="${base_url}/${binary_name}"
checksums_url="${base_url}/checksums.txt"

tmp="$(mktemp)"
checksums_tmp="$(mktemp)"
trap 'rm -f "$tmp" "$checksums_tmp"' EXIT

if ! curl -fsSL -o "$checksums_tmp" "$checksums_url"; then
  err "failed to download checksums.txt from $checksums_url"
fi

if ! curl -fsSL -o "$tmp" "$download_url"; then
  err "failed to download $download_url"
fi

# Verify SHA-256 checksum
expected_hash="$(grep "  ${binary_name}\$" "$checksums_tmp" | cut -d ' ' -f 1)"
if [ -z "$expected_hash" ]; then
  # Also try single-space separator
  expected_hash="$(grep " ${binary_name}\$" "$checksums_tmp" | cut -d ' ' -f 1)"
fi
[ -n "$expected_hash" ] || err "no checksum found for ${binary_name} in checksums.txt"

if command -v sha256sum >/dev/null 2>&1; then
  actual_hash="$(sha256sum "$tmp" | cut -d ' ' -f 1)"
elif command -v shasum >/dev/null 2>&1; then
  actual_hash="$(shasum -a 256 "$tmp" | cut -d ' ' -f 1)"
else
  err "neither sha256sum nor shasum found — cannot verify binary integrity"
fi

if [ "$actual_hash" != "$expected_hash" ]; then
  err "SHA-256 mismatch for ${binary_name}
  expected: ${expected_hash}
  actual:   ${actual_hash}"
fi

printf 'checksum verified: %s\n' "$expected_hash"

chmod +x "$tmp"
mv "$tmp" "$INSTALL_DIR/foxguard"
trap 'rm -f "$checksums_tmp"' EXIT

printf '\ninstalled foxguard %s to %s/foxguard\n' "$tag" "$INSTALL_DIR"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    printf '\nnote: %s is not in your PATH.\n' "$INSTALL_DIR"
    printf 'add this to your shell profile:\n'
    printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
    ;;
esac

printf '\ntry:  foxguard --help\n'
