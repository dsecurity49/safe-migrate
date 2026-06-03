#!/usr/bin/env bash
set -e

REPO="dsecurity49/safe-migrate"
BIN_NAME="safe-migrate"

echo "Detecting operating system and architecture..."

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     OS_TARGET="unknown-linux-gnu";;
    Darwin*)    OS_TARGET="apple-darwin";;
    *)          echo "Unsupported OS: ${OS}. Please compile from source."; exit 1;;
esac

# Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)   ARCH_TARGET="x86_64";;
    aarch64|arm64)  ARCH_TARGET="aarch64";;
    *)              echo "Unsupported architecture: ${ARCH}. Please compile from source."; exit 1;;
esac

TARGET="${ARCH_TARGET}-${OS_TARGET}"

echo "Target detected: ${TARGET}"
echo "Fetching latest release version..."

# Get latest release tag from GitHub API
VERSION=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$VERSION" ]; then
    echo "Error: Failed to fetch the latest version. Check your internet connection or GitHub API limits."
    exit 1
fi

DOWNLOAD_URL="https://github.com/dsecurity49/safe-migrate/releases/download/${VERSION}/${BIN_NAME}-${TARGET}.tar.gz"
TMP_DIR=$(mktemp -d)
TAR_FILE="${TMP_DIR}/${BIN_NAME}.tar.gz"

echo "Downloading ${BIN_NAME} ${VERSION}..."
curl -sL "$DOWNLOAD_URL" -o "$TAR_FILE"

if ! grep -q "gzip compressed data" <(file "$TAR_FILE"); then
    echo "Error: Downloaded file is not a valid archive. The release might still be building on GitHub Actions. Try again in a few minutes."
    exit 1
fi

echo "Extracting archive..."
tar -xzf "$TAR_FILE" -C "$TMP_DIR"

INSTALL_DIR="/usr/local/bin"
echo "Moving binary to ${INSTALL_DIR} (This might require sudo password)..."
sudo mv "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
sudo chmod +x "${INSTALL_DIR}/${BIN_NAME}"

# Cleanup
rm -rf "$TMP_DIR"

echo "----------------------------------------"
echo "✅ ${BIN_NAME} ${VERSION} installed successfully!"
echo "Run 'safe-migrate --help' to get started."
echo "----------------------------------------"
