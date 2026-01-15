#!/bin/bash
# ============================================================================
# kctsb Build Script for Linux/macOS
# Version: 3.3.0
#
# Usage:
#   ./scripts/build.sh                    # Quick release build
#   ./scripts/build.sh --debug --test     # Debug build with tests
#   ./scripts/build.sh --release          # Build and create release package
#   ./scripts/build.sh --clean --all      # Full clean build with all steps
#   ./scripts/build.sh --benchmark        # Build and run benchmarks
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
RELEASE_DIR="$PROJECT_DIR/release"

# Version info
VERSION="3.4.0"

BUILD_TYPE="Release"
CLEAN=false
RUN_TEST=false
INSTALL=false
BENCHMARK=false
VERBOSE=false
RELEASE=false
JOBS=""
INSTALL_DIR="$PROJECT_DIR/install"

# Detect OS
OS_NAME=""
OS_SUFFIX=""
case "$(uname -s)" in
    Darwin*)
        OS_NAME="macOS"
        OS_SUFFIX="macos"
        ;;
    Linux*)
        OS_NAME="Linux"
        OS_SUFFIX="linux"
        ;;
    CYGWIN*|MINGW*|MSYS*)
        OS_NAME="Windows"
        OS_SUFFIX="win"
        ;;
    *)
        OS_NAME="Unknown"
        OS_SUFFIX="unknown"
        ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ARCH_SUFFIX="x64"
        ;;
    arm64|aarch64)
        ARCH_SUFFIX="arm64"
        ;;
    *)
        ARCH_SUFFIX="$ARCH"
        ;;
esac

PLATFORM_SUFFIX="${OS_SUFFIX}-${ARCH_SUFFIX}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --debug           Build debug version (default: Release)"
    echo "  --clean           Clean build directory before building"
    echo "  --test            Run tests after build"
    echo "  --benchmark       Build and run benchmarks"
    echo "  --install         Install to prefix directory"
    echo "  --install-dir DIR Set install prefix (default: ./install)"
    echo "  --release         Create release package in ./release"
    echo "  --verbose         Show verbose build output"
    echo "  --jobs N          Use N parallel jobs (default: auto)"
    echo "  --all             Clean + Build + Test + Benchmark"
    echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                       # Quick release build"
    echo "  $0 --debug --test        # Debug build with tests"
    echo "  $0 --clean --all         # Full clean build with all steps"
    echo "  $0 --release             # Build and create release package"
    echo "  $0 --benchmark           # Build and run benchmarks"
    echo ""
    echo "Platform: ${OS_NAME} (${PLATFORM_SUFFIX})"
}

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
        --benchmark)
            BENCHMARK=true
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
        --release)
            RELEASE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        --all)
            CLEAN=true
            RUN_TEST=true
            BENCHMARK=true
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Calculate parallel jobs
if [ -z "$JOBS" ]; then
    JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
fi

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          kctsb Build Script v${VERSION}                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Platform:       ${GREEN}${OS_NAME} (${PLATFORM_SUFFIX})${NC}"
echo -e "Build Type:     ${GREEN}$BUILD_TYPE${NC}"
echo -e "Build Dir:      $BUILD_DIR"
echo -e "Parallel Jobs:  $JOBS"
echo -e "Options:        Clean=$CLEAN Test=$RUN_TEST Benchmark=$BENCHMARK Release=$RELEASE"
echo ""

# Record start time
START_TIME=$(date +%s)

# Step counter
STEP=1
TOTAL_STEPS=5
if [ "$RELEASE" = true ]; then
    TOTAL_STEPS=6
fi

# Clean build
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}[$STEP/$TOTAL_STEPS] Cleaning build directory...${NC}"
    rm -rf "$BUILD_DIR"
else
    echo -e "${YELLOW}[$STEP/$TOTAL_STEPS] Skipping clean (use --clean to force)${NC}"
fi
STEP=$((STEP + 1))

# Create build directory
mkdir -p "$BUILD_DIR"

# Configure
echo -e "${YELLOW}[$STEP/$TOTAL_STEPS] Configuring with CMake...${NC}"
cd "$BUILD_DIR"

CMAKE_ARGS=(
    ".."
    "-DCMAKE_BUILD_TYPE=$BUILD_TYPE"
    "-DKCTSB_BUILD_TESTS=ON"
    "-DKCTSB_BUILD_EXAMPLES=ON"
    "-DKCTSB_ENABLE_HELIB=ON"
    "-DKCTSB_ENABLE_OPENSSL=ON"
    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
)

# v3.4.0: Apply maximum optimization flags directly
if [ "$BUILD_TYPE" = "Release" ]; then
    # Extreme optimization flags (Principle #2)
    CMAKE_ARGS+=(
        "-DCMAKE_CXX_FLAGS=-O3 -march=native -mtune=native -ffast-math -funroll-loops -fomit-frame-pointer -flto -fno-rtti -fno-exceptions -fPIC"
    )
fi

if [ "$BENCHMARK" = true ] || [ "$RELEASE" = true ]; then
    CMAKE_ARGS+=("-DKCTSB_BUILD_BENCHMARKS=ON")
fi

if [ "$INSTALL" = true ]; then
    CMAKE_ARGS+=("-DCMAKE_INSTALL_PREFIX=$INSTALL_DIR")
fi

# Detect and use Ninja if available
if command -v ninja &> /dev/null; then
    CMAKE_ARGS+=("-G" "Ninja")
    echo "  Using Ninja generator"
fi

cmake "${CMAKE_ARGS[@]}"
STEP=$((STEP + 1))

# Build
echo -e "${YELLOW}[$STEP/$TOTAL_STEPS] Building with $JOBS parallel jobs...${NC}"

BUILD_CMD="cmake --build . --parallel $JOBS"
if [ "$VERBOSE" = true ]; then
    BUILD_CMD="$BUILD_CMD --verbose"
fi

eval $BUILD_CMD

# Check for build warnings
if [ -f build.log ]; then
    WARNING_COUNT=$(grep -c "warning:" build.log 2>/dev/null || echo 0)
    if [ "$WARNING_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}  Build completed with $WARNING_COUNT warnings${NC}"
    fi
fi
STEP=$((STEP + 1))

# Test
if [ "$RUN_TEST" = true ]; then
    echo -e "${YELLOW}[$STEP/$TOTAL_STEPS] Running tests...${NC}"
    ctest --output-on-failure --parallel "$JOBS"

    # Summary
    TEST_RESULT=$?
    if [ $TEST_RESULT -eq 0 ]; then
        echo -e "${GREEN}  ✓ All tests passed!${NC}"
    else
        echo -e "${RED}  ✗ Some tests failed!${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}[$STEP/$TOTAL_STEPS] Skipping tests (use --test to run)${NC}"
fi
STEP=$((STEP + 1))

# Benchmark
if [ "$BENCHMARK" = true ]; then
    echo -e "${YELLOW}[$STEP/$TOTAL_STEPS] Running benchmarks...${NC}"

    BENCH_BIN="$BUILD_DIR/bin/kctsb_benchmark"
    if [ -f "$BENCH_BIN" ]; then
        "$BENCH_BIN"
        echo -e "${GREEN}  ✓ Benchmark completed!${NC}"
    else
        echo -e "${RED}  ✗ Benchmark binary not found${NC}"
    fi
else
    echo -e "${YELLOW}[$STEP/$TOTAL_STEPS] Skipping benchmarks (use --benchmark to run)${NC}"
fi
STEP=$((STEP + 1))

# Release packaging
if [ "$RELEASE" = true ]; then
    echo -e "${YELLOW}[$STEP/$TOTAL_STEPS] Creating release package...${NC}"

    # v3.4.0: Platform-specific release directory
    RELEASE_PLATFORM_DIR="$RELEASE_DIR/$PLATFORM_SUFFIX"
    
    # Create release directory structure
    mkdir -p "$RELEASE_PLATFORM_DIR"
    mkdir -p "$RELEASE_PLATFORM_DIR/bin"
    mkdir -p "$RELEASE_PLATFORM_DIR/lib"
    mkdir -p "$RELEASE_PLATFORM_DIR/include"

    # Copy executables
    if [ -f "$BUILD_DIR/bin/kctsb" ]; then
        cp "$BUILD_DIR/bin/kctsb" "$RELEASE_PLATFORM_DIR/bin/kctsb-${PLATFORM_SUFFIX}"
        cp "$BUILD_DIR/bin/kctsb" "$RELEASE_PLATFORM_DIR/bin/kctsb"
        echo "  ✓ Copied kctsb executable"
    fi

    if [ -f "$BUILD_DIR/bin/kctsb_benchmark" ]; then
        cp "$BUILD_DIR/bin/kctsb_benchmark" "$RELEASE_PLATFORM_DIR/bin/kctsb_benchmark-${PLATFORM_SUFFIX}"
        cp "$BUILD_DIR/bin/kctsb_benchmark" "$RELEASE_PLATFORM_DIR/bin/kctsb_benchmark"
        echo "  ✓ Copied kctsb_benchmark executable"
    fi

    # Copy libraries (macOS/Linux)
    if [ "$OS_NAME" = "macOS" ]; then
        # Static library
        if [ -f "$BUILD_DIR/lib/libkctsb.a" ]; then
            cp "$BUILD_DIR/lib/libkctsb.a" "$RELEASE_PLATFORM_DIR/lib/libkctsb-${PLATFORM_SUFFIX}.a"
            cp "$BUILD_DIR/lib/libkctsb.a" "$RELEASE_PLATFORM_DIR/lib/libkctsb.a"
            echo "  ✓ Copied static library"
        fi
        # Dynamic library
        if [ -f "$BUILD_DIR/lib/libkctsb.dylib" ]; then
            cp "$BUILD_DIR/lib/libkctsb.dylib" "$RELEASE_PLATFORM_DIR/lib/libkctsb-${PLATFORM_SUFFIX}.dylib"
            cp "$BUILD_DIR/lib/libkctsb.dylib" "$RELEASE_PLATFORM_DIR/lib/libkctsb.dylib"
            echo "  ✓ Copied dynamic library"
        fi
    elif [ "$OS_NAME" = "Linux" ]; then
        # Static library
        if [ -f "$BUILD_DIR/lib/libkctsb.a" ]; then
            cp "$BUILD_DIR/lib/libkctsb.a" "$RELEASE_PLATFORM_DIR/lib/libkctsb-${PLATFORM_SUFFIX}.a"
            cp "$BUILD_DIR/lib/libkctsb.a" "$RELEASE_PLATFORM_DIR/lib/libkctsb.a"
            echo "  ✓ Copied static library"
        fi
        # Dynamic library
        for so_file in "$BUILD_DIR/lib/libkctsb.so"*; do
            if [ -f "$so_file" ]; then
                filename=$(basename "$so_file")
                cp "$so_file" "$RELEASE_PLATFORM_DIR/lib/"
                echo "  ✓ Copied $filename"
            fi
        done
    fi

    # Copy headers
    if [ -d "$PROJECT_DIR/include" ]; then
        cp -r "$PROJECT_DIR/include/kctsb" "$RELEASE_PLATFORM_DIR/include/"
        echo "  ✓ Copied headers"
    fi

    # Generate release info
    cat > "$RELEASE_PLATFORM_DIR/RELEASE_INFO.txt" << EOF
kctsb Release Information
==========================
Version: ${VERSION}
Platform: ${OS_NAME} (${PLATFORM_SUFFIX})
Build Type: ${BUILD_TYPE}
Build Date: $(date '+%Y-%m-%d %H:%M:%S %Z')
Compiler: $(cc --version 2>/dev/null | head -1 || echo "Unknown")

Contents:
- bin/kctsb              : Command-line tool
- bin/kctsb_benchmark    : Performance benchmark
- lib/libkctsb.a         : Static library
- lib/libkctsb.dylib     : Dynamic library (macOS)
- lib/libkctsb.so*       : Dynamic library (Linux)
- include/kctsb/         : Header files

Platform-specific binaries (with suffix):
- *-${PLATFORM_SUFFIX}.*

License: Apache License 2.0
Repository: https://github.com/kn1ghtc/kctsb
EOF

    echo -e "${GREEN}  ✓ Release package created in $RELEASE_PLATFORM_DIR${NC}"
    echo ""
    echo -e "${CYAN}Release contents:${NC}"
    ls -la "$RELEASE_PLATFORM_DIR/bin/" 2>/dev/null || true
    ls -la "$RELEASE_PLATFORM_DIR/lib/" 2>/dev/null || true
fi

# Install
if [ "$INSTALL" = true ]; then
    echo -e "${YELLOW}Installing to $INSTALL_DIR...${NC}"
    cmake --install .
fi

# Calculate elapsed time
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
MINUTES=$((ELAPSED / 60))
SECONDS=$((ELAPSED % 60))

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Build completed successfully!                    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Time elapsed:   ${MINUTES}m ${SECONDS}s"
echo -e "Build outputs:  $BUILD_DIR"
echo -e "  Libraries:    $BUILD_DIR/lib"
echo -e "  Binaries:     $BUILD_DIR/bin"
if [ "$RELEASE" = true ]; then
    echo -e "  Release:      $RELEASE_PLATFORM_DIR"
fi
echo ""

# Show quick commands
echo -e "${BLUE}Quick commands:${NC}"
echo "  Run tests:       cd $BUILD_DIR && ctest"
echo "  Run CLI tool:    $BUILD_DIR/bin/kctsb --help"
if [ -f "$BUILD_DIR/bin/kctsb_benchmark" ]; then
    echo "  Run benchmark:   $BUILD_DIR/bin/kctsb_benchmark"
fi
echo ""
echo -e "${CYAN}Development workflow:${NC}"
echo "  1. Quick build:  $0"
echo "  2. With tests:   $0 --test"
echo "  3. Full rebuild: $0 --clean --all"
echo "  4. Release:      $0 --release"
