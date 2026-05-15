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

download_url="https://github.com/${REPO}/releases/download/${tag}/${binary_name}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

if ! curl -fsSL -o "$tmp" "$download_url"; then
  err "failed to download $download_url"
fi

chmod +x "$tmp"
mv "$tmp" "$INSTALL_DIR/foxguard"
trap - EXIT

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
