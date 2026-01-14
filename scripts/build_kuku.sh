#!/bin/bash
# ============================================================================
# Build Kuku 2.1 for kctsb
# Kuku is a simple library for Cuckoo hashing
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
THIRDPARTY_DIR="$PROJECT_DIR/thirdparty"
DEPS_DIR="$PROJECT_DIR/deps"

KUKU_VERSION="2.1.0"
KUKU_URL="https://github.com/microsoft/Kuku/archive/refs/tags/v${KUKU_VERSION}.tar.gz"

echo "============================================"
echo "  Building Kuku ${KUKU_VERSION}"
echo "============================================"

# Create directories
mkdir -p "$DEPS_DIR"
mkdir -p "$THIRDPARTY_DIR/include"
mkdir -p "$THIRDPARTY_DIR/lib"

cd "$DEPS_DIR"

# Download if not exists
if [ ! -d "Kuku-${KUKU_VERSION}" ]; then
    echo "Downloading Kuku ${KUKU_VERSION}..."
    curl -L -o "kuku-${KUKU_VERSION}.tar.gz" "$KUKU_URL"
    tar -xzf "kuku-${KUKU_VERSION}.tar.gz"
    rm "kuku-${KUKU_VERSION}.tar.gz"
fi

cd "Kuku-${KUKU_VERSION}"

# Build
echo "Configuring Kuku..."
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$THIRDPARTY_DIR" \
    -DKUKU_BUILD_EXAMPLES=OFF \
    -DKUKU_BUILD_TESTS=OFF

echo "Building Kuku..."
cmake --build build --parallel

echo "Installing Kuku..."
cmake --install build

echo "✓ Kuku ${KUKU_VERSION} installed to $THIRDPARTY_DIR"
