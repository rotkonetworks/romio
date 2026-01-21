#!/bin/bash
# install-jamt.sh - download jamt cli tool
#
# usage: ./scripts/install-jamt.sh

set -e

JAMT_VERSION="${JAMT_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-./bin}"
JAMT_REPO="parity-asia/jamt"

mkdir -p "$INSTALL_DIR"

# detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH="x86_64" ;;
    aarch64) ARCH="aarch64" ;;
    arm64)   ARCH="aarch64" ;;
    *)       echo "error: unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux)  TARGET="${ARCH}-unknown-linux-gnu" ;;
    darwin) TARGET="${ARCH}-apple-darwin" ;;
    *)      echo "error: unsupported os: $OS"; exit 1 ;;
esac

echo "detecting platform: $OS/$ARCH -> $TARGET"

# get download url
if [ "$JAMT_VERSION" = "latest" ]; then
    RELEASE_URL="https://api.github.com/repos/${JAMT_REPO}/releases/latest"
    echo "fetching latest release from $RELEASE_URL"
    DOWNLOAD_URL=$(curl -sL "$RELEASE_URL" | grep "browser_download_url.*${TARGET}" | head -1 | cut -d '"' -f 4)
else
    DOWNLOAD_URL="https://github.com/${JAMT_REPO}/releases/download/${JAMT_VERSION}/jamt-${TARGET}.tar.gz"
fi

if [ -z "$DOWNLOAD_URL" ]; then
    echo "error: could not find jamt release for $TARGET"
    echo ""
    echo "manual download:"
    echo "  https://github.com/${JAMT_REPO}/releases"
    echo ""
    echo "or build from source:"
    echo "  git clone https://github.com/${JAMT_REPO}"
    echo "  cd jamt && cargo build --release"
    echo "  cp target/release/jamt $INSTALL_DIR/"
    exit 1
fi

echo "downloading: $DOWNLOAD_URL"

# download and extract
TMPFILE=$(mktemp)
curl -sL "$DOWNLOAD_URL" -o "$TMPFILE"

if file "$TMPFILE" | grep -q "gzip"; then
    tar -xzf "$TMPFILE" -C "$INSTALL_DIR"
elif file "$TMPFILE" | grep -q "Zip"; then
    unzip -q "$TMPFILE" -d "$INSTALL_DIR"
else
    # assume raw binary
    mv "$TMPFILE" "$INSTALL_DIR/jamt"
fi

rm -f "$TMPFILE" 2>/dev/null || true

chmod +x "$INSTALL_DIR/jamt"

echo ""
echo "jamt installed to $INSTALL_DIR/jamt"
"$INSTALL_DIR/jamt" --version 2>/dev/null || echo "(version check failed, binary may still work)"
