#!/bin/bash
# SessionStart hook for Claude Code cloud sessions.
# Installs PowerShell 7 (pwsh) so the test kit can run:
#   pwsh -NoProfile -File tests/run_all.ps1
# (The tool itself targets Windows PowerShell 5.1; pwsh is only for the Linux test kit.)
set -euo pipefail

# Only run in Claude Code cloud sessions.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

PWSH_VERSION=7.4.6
# SHA-256 of powershell-7.4.6-linux-x64.tar.gz, from the release's hashes.sha256
PWSH_SHA256=6f6015203c47806c5cc444c19d8ed019695e610fbd948154264bf9ca8e157561
PWSH_DIR=/opt/microsoft/powershell/7

# Skip if this exact version is already installed.
if command -v pwsh >/dev/null 2>&1 \
   && [ "$(pwsh -NoProfile -NoLogo -c '$PSVersionTable.PSVersion.ToString()' 2>/dev/null)" = "$PWSH_VERSION" ]; then
  exit 0
fi

case "$(uname -m)" in
  x86_64) arch=x64 ;;
  aarch64) arch=arm64; PWSH_SHA256= ;;  # hash above is for x64 only
  *) echo "session-start: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
tgz="$tmp/pwsh.tar.gz"
curl -fsSL --retry 4 -o "$tgz" \
  "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-linux-${arch}.tar.gz"
if [ -n "$PWSH_SHA256" ]; then
  echo "$PWSH_SHA256  $tgz" | sha256sum --check --status
fi

rm -rf "$PWSH_DIR"
mkdir -p "$PWSH_DIR"
tar xzf "$tgz" -C "$PWSH_DIR"
chmod +x "$PWSH_DIR/pwsh"
ln -sf "$PWSH_DIR/pwsh" /usr/local/bin/pwsh

pwsh -NoProfile -NoLogo -c '$PSVersionTable.PSVersion.ToString()' >&2
