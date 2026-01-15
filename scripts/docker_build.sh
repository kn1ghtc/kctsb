#!/bin/bash
# ============================================================================
# kctsb Docker Build Script for Linux x64
# Version: 3.4.0
#
# Features:
# - Platform-specific thirdparty: thirdparty/linux-x64/
# - GCC 12+ (required for NTL C++17 template support)
# - LTO enabled
# - Single-file distribution (like OpenSSL)
# - Unified public API header (kctsb_api.h)
#
# Usage:
#   ./scripts/docker_build.sh                    # Build Linux x64 release
#   ./scripts/docker_build.sh --test             # Build and run tests
#   ./scripts/docker_build.sh --clean            # Rebuild Docker image
#   ./scripts/docker_build.sh --shell            # Enter container shell
#   ./scripts/docker_build.sh --build-deps       # Build thirdparty first
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$PROJECT_DIR/docker"
RELEASE_DIR="$PROJECT_DIR/release"
THIRDPARTY_DIR="$PROJECT_DIR/thirdparty"

# Version and naming
VERSION="3.4.0"
DOCKER_IMAGE="kctsb-builder:almalinux9"
PLATFORM_SUFFIX="linux-x64"
THIRDPARTY_PLATFORM_DIR="$THIRDPARTY_DIR/$PLATFORM_SUFFIX"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Options
CLEAN_BUILD=false
RUN_TESTS=false
ENTER_SHELL=false
BUILD_DEPS=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        --test)
            RUN_TESTS=true
            shift
            ;;
        --shell)
            ENTER_SHELL=true
            shift
            ;;
        --build-deps)
            BUILD_DEPS=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --clean       Rebuild Docker image from scratch"
            echo "  --test        Run tests after build"
            echo "  --shell       Enter container shell for debugging"
            echo "  --build-deps  Build thirdparty dependencies first"
            echo "  --help        Show this help"
            echo ""
            echo "Thirdparty search order:"
            echo "  1. thirdparty/$PLATFORM_SUFFIX/"
            echo "  2. thirdparty/"
            echo "  3. System paths (Docker container)"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     kctsb Docker Build (Linux x64 - GCC 12+)              ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Version:    ${GREEN}$VERSION${NC}"
echo -e "Platform:   ${GREEN}$PLATFORM_SUFFIX${NC}"
echo -e "Image:      $DOCKER_IMAGE"
echo ""
echo -e "Thirdparty: $THIRDPARTY_PLATFORM_DIR"
if [ -d "$THIRDPARTY_PLATFORM_DIR/lib" ] && [ -f "$THIRDPARTY_PLATFORM_DIR/lib/libntl.a" ]; then
    echo -e "            ${GREEN}(platform-specific found with NTL)${NC}"
else
    echo -e "            ${YELLOW}(WARNING: thirdparty/linux-x64 not found!)${NC}"
    echo -e "            ${YELLOW}Run: ./scripts/build_thirdparty_linux.sh${NC}"
fi
echo ""

# Check Docker availability
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    exit 1
fi

# Check for platform-specific thirdparty
if [ ! -d "$THIRDPARTY_PLATFORM_DIR/lib" ] || [ ! -f "$THIRDPARTY_PLATFORM_DIR/lib/libntl.a" ]; then
    echo -e "${YELLOW}WARNING: Linux thirdparty not found${NC}"
    echo -e "${YELLOW}Building thirdparty dependencies first...${NC}"
    if [ -x "$SCRIPT_DIR/build_thirdparty_linux.sh" ]; then
        "$SCRIPT_DIR/build_thirdparty_linux.sh"
    else
        echo -e "${RED}Error: Run ./scripts/build_thirdparty_linux.sh first${NC}"
        exit 1
    fi
fi

# Build thirdparty if requested
if [ "$BUILD_DEPS" = true ]; then
    echo -e "${YELLOW}Building thirdparty dependencies...${NC}"
    "$SCRIPT_DIR/build_thirdparty_linux.sh"
fi

# Build Docker image if needed (AlmaLinux 9 with GCC 12+)
if [ "$CLEAN_BUILD" = true ] || ! docker image inspect "$DOCKER_IMAGE" &> /dev/null; then
    echo -e "${YELLOW}[1/4] Building Docker image (AlmaLinux 9 + GCC 12)...${NC}"
    docker build \
        -t "$DOCKER_IMAGE" \
        -f "$DOCKER_DIR/Dockerfile.almalinux9" \
        "$DOCKER_DIR"
    echo -e "${GREEN}  ✓ Docker image built${NC}"
else
    echo -e "${YELLOW}[1/4] Docker image exists, skipping build${NC}"
fi

# Enter shell mode if requested
if [ "$ENTER_SHELL" = true ]; then
    echo -e "${YELLOW}Entering container shell...${NC}"
    docker run -it --rm \
        -v "$PROJECT_DIR:/workspace" \
        -w /workspace \
        "$DOCKER_IMAGE" \
        bash
    exit 0
fi

# Build command - Full feature build with platform-specific thirdparty
BUILD_CMD="source /opt/rh/gcc-toolset-12/enable && cd /workspace && \
    rm -rf build-linux && \
    mkdir -p build-linux && \
    cd build-linux && \
    cmake .. -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DKCTSB_BUILD_STATIC=ON \
        -DKCTSB_BUILD_SHARED=OFF \
        -DKCTSB_BUILD_TESTS=ON \
        -DKCTSB_BUILD_EXAMPLES=OFF \
        -DKCTSB_BUILD_BENCHMARKS=OFF \
        -DKCTSB_ENABLE_LTO=ON \
        -DKCTSB_ENABLE_NTL=ON \
        -DKCTSB_ENABLE_GMP=ON \
        -DKCTSB_ENABLE_SEAL=OFF \
        -DKCTSB_ENABLE_HELIB=OFF \
        -DKCTSB_ENABLE_OPENSSL=OFF \
        -DCMAKE_PREFIX_PATH='/workspace/thirdparty/linux-x64' \
        -DGMP_ROOT='/workspace/thirdparty/linux-x64' \
        -DNTL_ROOT='/workspace/thirdparty/linux-x64' && \
    cmake --build . --parallel 4"

# Add test command if requested
if [ "$RUN_TESTS" = true ]; then
    BUILD_CMD="$BUILD_CMD && ctest --output-on-failure --parallel 4"
fi

# Run build
echo -e "${YELLOW}[2/4] Building kctsb in container...${NC}"
docker run --rm \
    -v "$PROJECT_DIR:/workspace" \
    -w /workspace \
    "$DOCKER_IMAGE" \
    bash -c "$BUILD_CMD"

echo -e "${GREEN}  ✓ Build completed${NC}"

# Copy release artifacts
echo -e "${YELLOW}[3/4] Copying release artifacts...${NC}"

RELEASE_PLATFORM_DIR="$RELEASE_DIR/$PLATFORM_SUFFIX"

# Clean old release for this platform
if [ -d "$RELEASE_PLATFORM_DIR" ]; then
    rm -rf "$RELEASE_PLATFORM_DIR"
fi

mkdir -p "$RELEASE_PLATFORM_DIR/bin"
mkdir -p "$RELEASE_PLATFORM_DIR/lib"
mkdir -p "$RELEASE_PLATFORM_DIR/include"

# Copy binaries
if [ -f "$PROJECT_DIR/build-linux/bin/kctsb" ]; then
    cp "$PROJECT_DIR/build-linux/bin/kctsb" "$RELEASE_PLATFORM_DIR/bin/kctsb"
    chmod +x "$RELEASE_PLATFORM_DIR/bin/kctsb"
    echo "  ✓ Copied kctsb executable"
fi

# Copy static library
if [ -f "$PROJECT_DIR/build-linux/lib/libkctsb.a" ]; then
    cp "$PROJECT_DIR/build-linux/lib/libkctsb.a" "$RELEASE_PLATFORM_DIR/lib/libkctsb.a"
    echo "  ✓ Copied libkctsb.a"
fi

# Copy shared library (if exists)
for so_file in "$PROJECT_DIR/build-linux/lib/libkctsb.so"*; do
    if [ -f "$so_file" ]; then
        filename=$(basename "$so_file")
        cp "$so_file" "$RELEASE_PLATFORM_DIR/lib/"
        echo "  ✓ Copied $filename"
    fi
done

# Copy ONLY the unified public API header
if [ -f "$PROJECT_DIR/include/kctsb/kctsb_api.h" ]; then
    cp "$PROJECT_DIR/include/kctsb/kctsb_api.h" "$RELEASE_PLATFORM_DIR/include/"
    echo "  ✓ Copied kctsb_api.h (unified public API)"
fi

# Generate release info
echo -e "${YELLOW}[4/4] Generating release info...${NC}"

GCC_VERSION=$(docker run --rm "$DOCKER_IMAGE" bash -c "source /opt/rh/gcc-toolset-12/enable && gcc --version" | head -1)
GLIBC_VERSION="2.34 (AlmaLinux 9)"

cat > "$RELEASE_PLATFORM_DIR/RELEASE_INFO.txt" << EOF
kctsb Release Information
==========================
Version: $VERSION
Platform: Linux x64 ($PLATFORM_SUFFIX)
Build Type: Release
Build Date: $(date '+%Y-%m-%d %H:%M:%S %Z')
Compiler: $GCC_VERSION
glibc: $GLIBC_VERSION (minimum requirement)

Features:
- NTL: Enabled (Number Theory Library)
- GMP: Enabled (GNU Multiple Precision)
- LTO: Enabled (Link-Time Optimization)

Contents:
- bin/kctsb              : Command-line tool
- lib/libkctsb.a         : Static library
- include/kctsb_api.h    : Unified public API header

Integration (like OpenSSL):
  #include <kctsb_api.h>
  // Link: -lkctsb -lntl -lgmp -lgf2x -lstdc++ -lm

Compatibility:
- AlmaLinux 9+ / RHEL 9+ / Rocky Linux 9+
- Ubuntu 22.04+ / Debian 12+
- Fedora 36+
- Most Linux distributions with glibc >= 2.34

License: Apache License 2.0
Repository: https://github.com/kn1ghtc/kctsb
EOF

echo -e "${GREEN}  ✓ Release info generated${NC}"

# Summary
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Linux build completed successfully!             ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Release dir:  $RELEASE_PLATFORM_DIR"
echo ""
echo -e "${CYAN}Distribution (like OpenSSL):${NC}"
echo "  Header:  kctsb_api.h"
echo "  Library: libkctsb.a"
echo "  Link:    -lkctsb -lstdc++"
echo ""
echo -e "${CYAN}Release contents:${NC}"
ls -la "$RELEASE_PLATFORM_DIR/bin/" 2>/dev/null || true
ls -la "$RELEASE_PLATFORM_DIR/lib/" 2>/dev/null || true
ls -la "$RELEASE_PLATFORM_DIR/include/" 2>/dev/null || true
echo ""
echo -e "${CYAN}Quick verification:${NC}"
echo "  file $RELEASE_PLATFORM_DIR/bin/kctsb"
echo "  ldd $RELEASE_PLATFORM_DIR/bin/kctsb"
