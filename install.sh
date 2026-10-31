#!/bin/sh
# dumpscrub installer — detects OS/arch, downloads the latest tagged release
# binary, verifies its SHA-256, and installs it to /usr/local/bin.
#
# Usage:
#   sh install.sh
#   DUMPSCRUB_VERSION=v1.0.0 sh install.sh
#   DUMPSCRUB_REPO=your-org/dumpscrub sh install.sh
#
# Environment:
#   DUMPSCRUB_REPO         GitHub repo slug            (default: dumpscrub/dumpscrub)
#   DUMPSCRUB_VERSION      tag, or "latest"            (default: latest)
#   DUMPSCRUB_INSTALL_DIR  install destination         (default: /usr/local/bin)
set -eu

REPO="${DUMPSCRUB_REPO:-dumpscrub/dumpscrub}"
VERSION="${DUMPSCRUB_VERSION:-latest}"
INSTALL_DIR="${DUMPSCRUB_INSTALL_DIR:-/usr/local/bin}"
BIN="dumpscrub"

say() { printf '%s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

[ -n "$REPO" ] || \
  die "set DUMPSCRUB_REPO to the repo slug, e.g. DUMPSCRUB_REPO=dumpscrub/dumpscrub sh install.sh"

# --- detect downloader -------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
  fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
  fetch_stdout() { wget -qO- "$1"; }
else
  die "need curl or wget installed"
fi

# --- detect checksum tool ----------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  sha256_check() { sha256sum -c -; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_check() { shasum -a 256 -c -; }
else
  die "need sha256sum or shasum installed"
fi

# --- detect OS / arch --------------------------------------------------------
os=$(uname -s)
case "$os" in
  Linux)  os="Linux" ;;
  Darwin) os="Darwin" ;;
  *) die "unsupported OS: $os (only Linux and macOS have prebuilt binaries)" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64)       arch="x86_64" ;;
  arm64|aarch64)      arch="arm64" ;;
  *) die "unsupported architecture: $arch" ;;
esac

asset="${BIN}_${os}_${arch}.tar.gz"
say "detected: $os/$arch -> $asset"

# --- resolve version ---------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  say "resolving latest release of $REPO ..."
  VERSION=$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | head -n 1 \
    | sed 's/.*"\([^"]*\)"$/\1/') || true
  [ -n "${VERSION:-}" ] || die "could not resolve latest version (rate-limited? set DUMPSCRUB_VERSION)"
fi
say "installing $BIN $VERSION"

base="https://github.com/${REPO}/releases/download/${VERSION}"

# --- download + verify + extract --------------------------------------------
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t dumpscrub)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $asset ..."
fetch "${base}/${asset}" "${tmp}/${asset}" || die "download failed: ${base}/${asset}"

if fetch "${base}/SHA256SUMS" "${tmp}/SHA256SUMS" 2>/dev/null; then
  say "verifying checksum ..."
  ( cd "$tmp" && grep " ${asset}\$" SHA256SUMS | sha256_check ) \
    || die "checksum verification failed"
else
  say "warning: SHA256SUMS not found — skipping checksum verification"
fi

tar -xzf "${tmp}/${asset}" -C "$tmp" || die "failed to extract ${asset}"
[ -f "${tmp}/${BIN}" ] || die "archive did not contain a '$BIN' binary"
chmod 0755 "${tmp}/${BIN}"

# --- install -----------------------------------------------------------------
if [ -w "$INSTALL_DIR" ]; then
  mv "${tmp}/${BIN}" "${INSTALL_DIR}/${BIN}"
elif command -v sudo >/dev/null 2>&1; then
  say "writing to $INSTALL_DIR requires sudo"
  sudo mv "${tmp}/${BIN}" "${INSTALL_DIR}/${BIN}"
else
  mkdir -p "$HOME/.local/bin"
  mv "${tmp}/${BIN}" "$HOME/.local/bin/${BIN}"
  INSTALL_DIR="$HOME/.local/bin"
  say "no write access to /usr/local/bin and no sudo; installed to $INSTALL_DIR"
  say "add it to PATH:  export PATH=\"$HOME/.local/bin:\$PATH\""
fi

say ""
say "  ✓ $BIN $VERSION installed to ${INSTALL_DIR}/${BIN}"
say "  run:  $BIN --help"
