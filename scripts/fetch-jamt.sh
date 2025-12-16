#!/bin/bash
# Fetch the latest jamt CLI tool from polkajam nightly releases
# This enables using jamt tooling with romio (JAM client)
#
# Requirements: gh (GitHub CLI), jq

set -e

# Configuration
GITHUB_REPO="paritytech/polkajam-releases"
INSTALL_DIR="${INSTALL_DIR:-/tmp}"

# Check dependencies
for cmd in gh jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is required but not installed"
        exit 1
    fi
done

# Detect platform
case "$(uname -s)" in
    Linux*)  PLATFORM="linux" ;;
    Darwin*) PLATFORM="macos" ;;
    *)       echo "Unsupported platform: $(uname -s)"; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64)  ARCH="x86_64" ;;
    aarch64) ARCH="aarch64" ;;
    arm64)   ARCH="aarch64" ;;
    *)       echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

echo "Fetching latest polkajam nightly release info..."

# Get the latest nightly release tag using gh api
RELEASE_INFO=$(gh api repos/${GITHUB_REPO}/releases --jq '[.[] | select(.tag_name | startswith("nightly-"))] | first')

if [ -z "$RELEASE_INFO" ] || [ "$RELEASE_INFO" = "null" ]; then
    echo "Error: Could not find any nightly releases"
    exit 1
fi

TAG_NAME=$(echo "$RELEASE_INFO" | jq -r '.tag_name')
PUBLISHED_AT=$(echo "$RELEASE_INFO" | jq -r '.published_at')

echo "  Latest release: ${TAG_NAME} (${PUBLISHED_AT})"

# Find the matching asset for our platform (format: polkajam-nightly-YYYY-MM-DD-PLATFORM-ARCH.tgz)
TARBALL_PATTERN="${PLATFORM}-${ARCH}.tgz"
DOWNLOAD_URL=$(echo "$RELEASE_INFO" | jq -r --arg pattern "$TARBALL_PATTERN" '.assets[] | select(.name | endswith($pattern)) | .browser_download_url')

if [ -z "$DOWNLOAD_URL" ] || [ "$DOWNLOAD_URL" = "null" ]; then
    echo "Error: Could not find asset matching pattern: ${TARBALL_PATTERN}"
    echo "Available assets:"
    echo "$RELEASE_INFO" | jq -r '.assets[].name'
    exit 1
fi

TARBALL_NAME=$(basename "$DOWNLOAD_URL")

echo "  Platform: ${PLATFORM}-${ARCH}"
echo "  Asset: ${TARBALL_NAME}"
echo "  Install dir: ${INSTALL_DIR}"
echo

# Download and extract
cd "${INSTALL_DIR}"

echo "Downloading ${TARBALL_NAME}..."
curl -L --progress-bar "${DOWNLOAD_URL}" -o "${TARBALL_NAME}"

echo "Extracting..."
tar xzf "${TARBALL_NAME}"
rm "${TARBALL_NAME}"

# Find the extracted directory
EXTRACTED_DIR=$(ls -dt polkajam-*-${PLATFORM}-${ARCH} 2>/dev/null | head -1)

if [ -z "${EXTRACTED_DIR}" ]; then
    echo "Error: Could not find extracted directory"
    exit 1
fi

echo
echo "Installed to: ${INSTALL_DIR}/${EXTRACTED_DIR}"
echo
echo "Available tools:"
ls -1 "${INSTALL_DIR}/${EXTRACTED_DIR}/" | while read f; do
    echo "  ${INSTALL_DIR}/${EXTRACTED_DIR}/$f"
done
echo
echo "Usage example:"
echo "  ${INSTALL_DIR}/${EXTRACTED_DIR}/jamt --help"
echo "  ${INSTALL_DIR}/${EXTRACTED_DIR}/jamt vm new <corevm-file> <gas>"
