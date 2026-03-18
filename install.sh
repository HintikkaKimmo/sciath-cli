#!/usr/bin/env sh
# Sciath CLI installer
# Usage: curl -fsSL https://get.sciath.io/install.sh | sh
#
# Downloads the right pre-built binary from GitHub Releases,
# extracts it, and installs to /usr/local/bin (or ~/bin if no sudo).

set -eu

REPO="sciath-io/sciath"
INSTALL_DIR="/usr/local/bin"
BIN_NAME="sciath"

# ── Detect OS and architecture ────────────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
  Linux)  os="linux" ;;
  Darwin) os="macos" ;;
  *)
    echo "Unsupported OS: ${OS}" >&2
    echo "Install manually from https://github.com/${REPO}/releases" >&2
    exit 1
    ;;
esac

case "${ARCH}" in
  x86_64)         arch="x86_64" ;;
  aarch64|arm64)  arch="arm64" ;;
  *)
    echo "Unsupported architecture: ${ARCH}" >&2
    echo "Install manually from https://github.com/${REPO}/releases" >&2
    exit 1
    ;;
esac

# Normalise: macOS arm64 uses "arm64", macOS x86_64 uses "x86_64"
TARGET="${os}-${arch}"

# ── Resolve latest release tag ────────────────────────────────────────────────

LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "${LATEST}" ]; then
  echo "Could not determine latest release. Check https://github.com/${REPO}/releases" >&2
  exit 1
fi

ARCHIVE="sciath-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${ARCHIVE}"

# ── Download and extract ──────────────────────────────────────────────────────

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

echo "Downloading sciath ${LATEST} (${TARGET})..."
curl -fsSL "${URL}" -o "${TMPDIR}/${ARCHIVE}"

echo "Extracting..."
tar -xzf "${TMPDIR}/${ARCHIVE}" -C "${TMPDIR}"

# ── Install ───────────────────────────────────────────────────────────────────

# Use ~/bin if /usr/local/bin requires sudo
if [ -w "${INSTALL_DIR}" ]; then
  cp -r "${TMPDIR}/sciath" "${INSTALL_DIR}/${BIN_NAME}_dir" 2>/dev/null || true
  install -m 755 "${TMPDIR}/sciath/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
else
  # Fallback: ~/bin
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "${INSTALL_DIR}"
  cp -r "${TMPDIR}/sciath" "${INSTALL_DIR}/${BIN_NAME}_dir" 2>/dev/null || true
  install -m 755 "${TMPDIR}/sciath/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  echo ""
  echo "Installed to ${INSTALL_DIR}/${BIN_NAME}"
  echo "Make sure ${INSTALL_DIR} is in your PATH:"
  echo "  export PATH=\"\$PATH:${INSTALL_DIR}\""
fi

echo ""
echo "sciath ${LATEST} installed successfully."
echo "Run 'sciath --version' to verify, then 'sciath login' to authenticate."
