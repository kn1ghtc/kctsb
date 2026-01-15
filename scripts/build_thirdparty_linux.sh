#!/bin/bash
# ============================================================================
# Build thirdparty dependencies for Linux x64
# Version: 3.4.0
#
# This script builds GMP, gf2x, NTL in Docker and copies them to
# thirdparty/linux-x64/ for cross-platform development.
#
# Usage:
#   ./scripts/build_thirdparty_linux.sh
#   ./scripts/build_thirdparty_linux.sh --rebuild   # Rebuild Docker image
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$PROJECT_DIR/docker"
THIRDPARTY_DIR="$PROJECT_DIR/thirdparty/linux-x64"

# Docker image name
DOCKER_IMAGE="kctsb-thirdparty-builder:almalinux9"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REBUILD=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --rebuild)
            REBUILD=true
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     Build Linux x64 Thirdparty Dependencies               ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Docker Image: $DOCKER_IMAGE"
echo -e "Output Dir:   $THIRDPARTY_DIR"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    exit 1
fi

# Build Docker image if needed
if [ "$REBUILD" = true ] || ! docker image inspect "$DOCKER_IMAGE" &> /dev/null; then
    echo -e "${YELLOW}[1/3] Building Docker image (GCC 12 + thirdparty)...${NC}"
    docker build \
        -t "$DOCKER_IMAGE" \
        -f "$DOCKER_DIR/Dockerfile.almalinux9" \
        "$DOCKER_DIR"
    echo -e "${GREEN}  ✓ Docker image built${NC}"
else
    echo -e "${YELLOW}[1/3] Docker image exists, skipping build${NC}"
fi

# Create output directory
echo -e "${YELLOW}[2/3] Preparing output directory...${NC}"
mkdir -p "$THIRDPARTY_DIR/lib"
mkdir -p "$THIRDPARTY_DIR/include"

# Extract thirdparty files from Docker
echo -e "${YELLOW}[3/3] Extracting thirdparty libraries...${NC}"

# Create a temporary container to copy files
CONTAINER_ID=$(docker create "$DOCKER_IMAGE")

# Copy libraries
docker cp "$CONTAINER_ID:/usr/local/lib/libgmp.a" "$THIRDPARTY_DIR/lib/"
docker cp "$CONTAINER_ID:/usr/local/lib/libgmpxx.a" "$THIRDPARTY_DIR/lib/"
docker cp "$CONTAINER_ID:/usr/local/lib/libgf2x.a" "$THIRDPARTY_DIR/lib/" 2>/dev/null || true
docker cp "$CONTAINER_ID:/usr/local/lib/libntl.a" "$THIRDPARTY_DIR/lib/"

# Copy headers
docker cp "$CONTAINER_ID:/usr/local/include/gmp.h" "$THIRDPARTY_DIR/include/"
docker cp "$CONTAINER_ID:/usr/local/include/gmpxx.h" "$THIRDPARTY_DIR/include/"
docker cp "$CONTAINER_ID:/usr/local/include/NTL" "$THIRDPARTY_DIR/include/"
docker cp "$CONTAINER_ID:/usr/local/include/gf2x.h" "$THIRDPARTY_DIR/include/" 2>/dev/null || true
docker cp "$CONTAINER_ID:/usr/local/include/gf2x" "$THIRDPARTY_DIR/include/" 2>/dev/null || true

# Remove temporary container
docker rm "$CONTAINER_ID" > /dev/null

echo -e "${GREEN}  ✓ Libraries extracted${NC}"

# Create version info
GCC_VERSION=$(docker run --rm "$DOCKER_IMAGE" bash -c "source /opt/rh/gcc-toolset-12/enable && gcc --version" | head -1)
cat > "$THIRDPARTY_DIR/BUILD_INFO.txt" << EOF
Linux x64 Thirdparty Dependencies
==================================
Build Date: $(date '+%Y-%m-%d %H:%M:%S %Z')
Compiler: $GCC_VERSION
Base Image: AlmaLinux 9 + gcc-toolset-12

Dependencies:
- GMP 6.3.0 (static, PIC)
- gf2x 1.3.0 (static, PIC)
- NTL 11.6.0 (static, PIC, C++17 via CXXFLAGS)

Build Flags:
- CFLAGS: -O3 -fPIC
- CXXFLAGS: -O3 -fPIC -std=c++17
- NTL_GMP_LIP=on
- NTL_GF2X_LIB=on
EOF

# Summary
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Thirdparty build completed successfully!              ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Output directory: $THIRDPARTY_DIR${NC}"
echo ""
echo "Libraries:"
ls -lh "$THIRDPARTY_DIR/lib/"
echo ""
echo "Headers:"
ls -la "$THIRDPARTY_DIR/include/" | head -20
