#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: $0 <version> <macos-arm-sha> <macos-x64-sha> <linux-arm-sha> <linux-x64-sha>}"
MACOS_ARM_SHA="${2:?Missing macOS arm64 SHA}"
MACOS_X64_SHA="${3:?Missing macOS x86_64 SHA}"
LINUX_ARM_SHA="${4:?Missing Linux arm64 SHA}"
LINUX_X64_SHA="${5:?Missing Linux x86_64 SHA}"

cat <<EOF
class Foxguard < Formula
  desc "Security scanner as fast as a linter. 174 built-in rules, 10 languages, taint tracking."
  homepage "https://foxguard.dev"
  version "${VERSION}"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/PwnKit-Labs/foxguard/releases/download/v${VERSION}/foxguard-macos-aarch64"
      sha256 "${MACOS_ARM_SHA}"
    else
      url "https://github.com/PwnKit-Labs/foxguard/releases/download/v${VERSION}/foxguard-macos-x86_64"
      sha256 "${MACOS_X64_SHA}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/PwnKit-Labs/foxguard/releases/download/v${VERSION}/foxguard-linux-aarch64"
      sha256 "${LINUX_ARM_SHA}"
    else
      url "https://github.com/PwnKit-Labs/foxguard/releases/download/v${VERSION}/foxguard-linux-x86_64"
      sha256 "${LINUX_X64_SHA}"
    end
  end

  def install
    bin.install Dir["foxguard*"].first => "foxguard"
  end

  test do
    assert_match "foxguard", shell_output("#{bin}/foxguard --version")
  end
end
EOF
