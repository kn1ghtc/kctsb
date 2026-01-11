#!/bin/bash
# ============================================================================
# kctsb Build Script for Linux/macOS
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"

BUILD_TYPE="Release"
CLEAN=false
RUN_TEST=false
INSTALL=false
INSTALL_DIR="$PROJECT_DIR/install"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --test)
            RUN_TEST=true
            shift
            ;;
        --install)
            INSTALL=true
            shift
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "============================================"
echo "   kctsb Build Script"
echo "============================================"
echo ""
echo "Build Type: $BUILD_TYPE"
echo "Build Directory: $BUILD_DIR"
echo ""

# Clean build
if [ "$CLEAN" = true ]; then
    echo "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

# Create build directory
mkdir -p "$BUILD_DIR"

# Configure
echo "Configuring with CMake..."
cd "$BUILD_DIR"

CMAKE_ARGS=(
    ".."
    "-DCMAKE_BUILD_TYPE=$BUILD_TYPE"
    "-DKCTSB_BUILD_TESTS=ON"
    "-DKCTSB_BUILD_EXAMPLES=ON"
)

if [ "$INSTALL" = true ]; then
    CMAKE_ARGS+=("-DCMAKE_INSTALL_PREFIX=$INSTALL_DIR")
fi

cmake "${CMAKE_ARGS[@]}"

# Build
echo "Building..."
cmake --build . --parallel "$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

# Test
if [ "$RUN_TEST" = true ]; then
    echo "Running tests..."
    ctest --output-on-failure
fi

# Install
if [ "$INSTALL" = true ]; then
    echo "Installing to $INSTALL_DIR..."
    cmake --install .
fi

echo ""
echo "============================================"
echo "   Build completed successfully!"
echo "============================================"
echo ""
echo "Build outputs are in: $BUILD_DIR"
echo "  Libraries: $BUILD_DIR/lib"
echo "  Binaries: $BUILD_DIR/bin"
