#!/bin/bash
# ============================================================================
# kctsb Build Script for Linux/macOS
# Version: 3.2.0
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"

BUILD_TYPE="Release"
CLEAN=false
RUN_TEST=false
INSTALL=false
BENCHMARK=false
VERBOSE=false
JOBS=""
INSTALL_DIR="$PROJECT_DIR/install"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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
    echo "  --verbose         Show verbose build output"
    echo "  --jobs N          Use N parallel jobs (default: auto)"
    echo "  --all             Clean + Build + Test + Benchmark"
    echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                       # Quick release build"
    echo "  $0 --debug --test        # Debug build with tests"
    echo "  $0 --clean --all         # Full clean build with all steps"
    echo "  $0 --benchmark           # Build and run benchmarks"
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

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   kctsb Build Script v3.2.0${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "Build Type:     ${GREEN}$BUILD_TYPE${NC}"
echo -e "Build Dir:      $BUILD_DIR"
echo -e "Parallel Jobs:  $JOBS"
echo -e "Options:        Clean=$CLEAN Test=$RUN_TEST Benchmark=$BENCHMARK"
echo ""

# Record start time
START_TIME=$(date +%s)

# Clean build
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}[1/5] Cleaning build directory...${NC}"
    rm -rf "$BUILD_DIR"
else
    echo -e "${YELLOW}[1/5] Skipping clean (use --clean to force)${NC}"
fi

# Create build directory
mkdir -p "$BUILD_DIR"

# Configure
echo -e "${YELLOW}[2/5] Configuring with CMake...${NC}"
cd "$BUILD_DIR"

CMAKE_ARGS=(
    ".."
    "-DCMAKE_BUILD_TYPE=$BUILD_TYPE"
    "-DKCTSB_BUILD_TESTS=ON"
    "-DKCTSB_BUILD_EXAMPLES=ON"
)

if [ "$BENCHMARK" = true ]; then
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

# Build
echo -e "${YELLOW}[3/5] Building with $JOBS parallel jobs...${NC}"

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

# Test
if [ "$RUN_TEST" = true ]; then
    echo -e "${YELLOW}[4/5] Running tests...${NC}"
    ctest --output-on-failure --parallel "$JOBS"
    
    # Summary
    TEST_RESULT=$?
    if [ $TEST_RESULT -eq 0 ]; then
        echo -e "${GREEN}  All tests passed!${NC}"
    else
        echo -e "${RED}  Some tests failed!${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}[4/5] Skipping tests (use --test to run)${NC}"
fi

# Benchmark
if [ "$BENCHMARK" = true ]; then
    echo -e "${YELLOW}[5/5] Running benchmarks...${NC}"
    
    BENCH_BIN="$BUILD_DIR/bin/kctsb_benchmark"
    if [ -f "$BENCH_BIN" ]; then
        $BENCH_BIN --benchmark_out="$PROJECT_DIR/benchmark_results.json" \
                   --benchmark_out_format=json
        echo -e "${GREEN}  Benchmark results saved to benchmark_results.json${NC}"
    else
        echo -e "${RED}  Benchmark binary not found. Ensure KCTSB_BUILD_BENCHMARKS=ON${NC}"
    fi
else
    echo -e "${YELLOW}[5/5] Skipping benchmarks (use --benchmark to run)${NC}"
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
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}   Build completed successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "Time elapsed:   ${MINUTES}m ${SECONDS}s"
echo -e "Build outputs:  $BUILD_DIR"
echo -e "  Libraries:    $BUILD_DIR/lib"
echo -e "  Binaries:     $BUILD_DIR/bin"
echo ""

# Show quick commands
echo -e "${BLUE}Quick commands:${NC}"
echo "  Run tests:     cd $BUILD_DIR && ctest"
echo "  Run example:   $BUILD_DIR/bin/kctsb_example"
if [ "$BENCHMARK" = true ] && [ -f "$BUILD_DIR/bin/kctsb_benchmark" ]; then
    echo "  Run benchmark: $BUILD_DIR/bin/kctsb_benchmark"
fi
