#!/bin/bash
# ============================================================================
# kctsb Build Script for Linux/macOS
# Version: 3.4.2
#
# Features:
# - Platform-specific thirdparty: thirdparty/{linux-x64,macos-x64,macos-arm64}/
# - LTO enabled (GCC 11+/Clang)
# - Single-file distribution (libkctsb_bundled.a - includes all dependencies)
# - Unified public API header (kctsb_api.h)
# - Bundled library created on every build (default behavior)
#
# Usage:
#   ./scripts/build.sh                    # Quick release build
#   ./scripts/build.sh --debug --test     # Debug build with tests
#   ./scripts/build.sh --release          # Build and create release package
#   ./scripts/build.sh --clean --all      # Full clean build with all steps
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
RELEASE_DIR="$PROJECT_DIR/release"
THIRDPARTY_DIR="$PROJECT_DIR/thirdparty"

# Version info
VERSION="3.4.2"

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
THIRDPARTY_PLATFORM_DIR="$THIRDPARTY_DIR/$PLATFORM_SUFFIX"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

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
    echo "  --release         Create release package"
    echo "  --verbose         Show verbose build output"
    echo "  --jobs N          Use N parallel jobs (default: auto)"
    echo "  --all             Clean + Build + Test + Benchmark"
    echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                       # Quick release build"
    echo "  $0 --debug --test        # Debug build with tests"
    echo "  $0 --clean --all         # Full clean build"
    echo "  $0 --release             # Build and create release"
    echo ""
    echo "Thirdparty search order:"
    echo "  1. thirdparty/$PLATFORM_SUFFIX/"
    echo "  2. thirdparty/"
    echo "  3. System paths"
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
echo -e "Thirdparty:     $THIRDPARTY_PLATFORM_DIR"
if [ -d "$THIRDPARTY_PLATFORM_DIR" ]; then
    echo -e "                ${GREEN}(platform-specific found)${NC}"
else
    echo -e "                ${YELLOW}(using common thirdparty/ or system)${NC}"
fi
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
    "-DKCTSB_ENABLE_LTO=ON"
    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
)

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

# ====================================================================
# Create bundled static library (default for all builds)
# ====================================================================
echo -e "   ${YELLOW}Creating bundled static library...${NC}"

STATIC_LIB="$BUILD_DIR/lib/libkctsb.a"
if [ -f "$STATIC_LIB" ] && command -v ar &> /dev/null; then
    # Collect all static libraries to bundle
    LIBS_TO_BUNDLE=()
    LIBS_TO_BUNDLE+=("$STATIC_LIB")
    
    # Check both platform-specific and common thirdparty directories
    THIRDPARTY_LIB_DIRS=(
        "$THIRDPARTY_PLATFORM_DIR/lib"
        "$THIRDPARTY_DIR/lib"
    )
    
    DEP_LIBS=("libntl.a" "libgmp.a" "libgf2x.a" "libseal-4.1.a" "libhelib.a")
    
    for lib_dir in "${THIRDPARTY_LIB_DIRS[@]}"; do
        if [ -d "$lib_dir" ]; then
            for dep_lib in "${DEP_LIBS[@]}"; do
                dep_path="$lib_dir/$dep_lib"
                if [ -f "$dep_path" ]; then
                    # Check if already added
                    already_added=false
                    for existing in "${LIBS_TO_BUNDLE[@]}"; do
                        if [ "$existing" = "$dep_path" ]; then
                            already_added=true
                            break
                        fi
                    done
                    if [ "$already_added" = false ]; then
                        LIBS_TO_BUNDLE+=("$dep_path")
                    fi
                fi
            done
        fi
    done
    
    if [ ${#LIBS_TO_BUNDLE[@]} -gt 1 ]; then
        # Create temp directory for extraction
        BUNDLE_TMP_DIR="$BUILD_DIR/bundle_tmp"
        rm -rf "$BUNDLE_TMP_DIR"
        mkdir -p "$BUNDLE_TMP_DIR"
        
        cd "$BUNDLE_TMP_DIR"
        
        # Extract each library with prefixed object files
        lib_index=0
        for lib in "${LIBS_TO_BUNDLE[@]}"; do
            lib_name=$(basename "$lib" .a)
            prefix="lib${lib_index}_"
            
            ar x "$lib" 2>/dev/null || true
            
            # Rename extracted .o files with prefix to avoid conflicts
            for obj in *.o; do
                if [ -f "$obj" ] && [[ ! "$obj" =~ ^lib[0-9]+_ ]]; then
                    mv "$obj" "${prefix}${obj}"
                fi
            done
            lib_index=$((lib_index + 1))
        done
        
        # Count total objects
        obj_count=$(ls -1 *.o 2>/dev/null | wc -l)
        
        if [ "$obj_count" -gt 0 ]; then
            BUNDLED_LIB="$BUILD_DIR/lib/libkctsb_bundled.a"
            ar rcs "$BUNDLED_LIB" *.o 2>/dev/null
            
            if [ -f "$BUNDLED_LIB" ]; then
                bundled_size=$(du -h "$BUNDLED_LIB" | cut -f1)
                echo -e "   ${GREEN}✓ Created libkctsb_bundled.a ($bundled_size, $obj_count objects)${NC}"
            else
                echo -e "   ${RED}✗ Failed to create bundled library${NC}"
            fi
        fi
        
        # Cleanup
        cd "$BUILD_DIR"
        rm -rf "$BUNDLE_TMP_DIR"
    else
        echo -e "   (No dependencies to bundle, using kctsb only)"
    fi
else
    echo -e "   (ar not found or static lib missing, skipping bundled library)"
fi

STEP=$((STEP + 1))

# Test
if [ "$RUN_TEST" = true ]; then
    echo -e "${YELLOW}[$STEP/$TOTAL_STEPS] Running tests...${NC}"
    ctest --output-on-failure --parallel "$JOBS"

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

    RELEASE_PLATFORM_DIR="$RELEASE_DIR/$PLATFORM_SUFFIX"
    
    # Clean old release for this platform
    if [ -d "$RELEASE_PLATFORM_DIR" ]; then
        rm -rf "$RELEASE_PLATFORM_DIR"
    fi
    
    mkdir -p "$RELEASE_PLATFORM_DIR/bin"
    mkdir -p "$RELEASE_PLATFORM_DIR/lib"
    mkdir -p "$RELEASE_PLATFORM_DIR/include"

    # Copy executables
    if [ -f "$BUILD_DIR/bin/kctsb" ]; then
        cp "$BUILD_DIR/bin/kctsb" "$RELEASE_PLATFORM_DIR/bin/kctsb"
        chmod +x "$RELEASE_PLATFORM_DIR/bin/kctsb"
        echo "  ✓ Copied kctsb executable"
    fi

    if [ -f "$BUILD_DIR/bin/kctsb_benchmark" ]; then
        cp "$BUILD_DIR/bin/kctsb_benchmark" "$RELEASE_PLATFORM_DIR/bin/kctsb_benchmark"
        chmod +x "$RELEASE_PLATFORM_DIR/bin/kctsb_benchmark"
        echo "  ✓ Copied kctsb_benchmark"
    fi

    # Copy libraries
    if [ "$OS_NAME" = "macOS" ]; then
        # Static library
        if [ -f "$BUILD_DIR/lib/libkctsb.a" ]; then
            cp "$BUILD_DIR/lib/libkctsb.a" "$RELEASE_PLATFORM_DIR/lib/libkctsb.a"
            echo "  ✓ Copied libkctsb.a"
        fi
        # Dynamic library
        if [ -f "$BUILD_DIR/lib/libkctsb.dylib" ]; then
            cp "$BUILD_DIR/lib/libkctsb.dylib" "$RELEASE_PLATFORM_DIR/lib/libkctsb.dylib"
            echo "  ✓ Copied libkctsb.dylib"
        fi
    elif [ "$OS_NAME" = "Linux" ]; then
        # Static library
        if [ -f "$BUILD_DIR/lib/libkctsb.a" ]; then
            cp "$BUILD_DIR/lib/libkctsb.a" "$RELEASE_PLATFORM_DIR/lib/libkctsb.a"
            echo "  ✓ Copied libkctsb.a"
        fi
        # Shared library
        for so_file in "$BUILD_DIR/lib/libkctsb.so"*; do
            if [ -f "$so_file" ]; then
                filename=$(basename "$so_file")
                cp "$so_file" "$RELEASE_PLATFORM_DIR/lib/"
                echo "  ✓ Copied $filename"
            fi
        done
    fi

    # Copy ONLY the unified public API header
    if [ -f "$PROJECT_DIR/include/kctsb/kctsb_api.h" ]; then
        cp "$PROJECT_DIR/include/kctsb/kctsb_api.h" "$RELEASE_PLATFORM_DIR/include/"
        echo "  ✓ Copied kctsb_api.h (unified public API)"
    fi

    # ====================================================================
    # Create bundled static library (single-file with all dependencies)
    # ====================================================================
    echo "  Creating bundled static library..."
    
    STATIC_LIB="$BUILD_DIR/lib/libkctsb.a"
    if [ -f "$STATIC_LIB" ] && command -v ar &> /dev/null; then
        # Collect all static libraries to bundle
        LIBS_TO_BUNDLE=()
        LIBS_TO_BUNDLE+=("$STATIC_LIB")
        
        # Check both platform-specific and common thirdparty directories
        THIRDPARTY_LIB_DIRS=(
            "$THIRDPARTY_PLATFORM_DIR/lib"
            "$THIRDPARTY_DIR/lib"
        )
        
        DEP_LIBS=("libntl.a" "libgmp.a" "libgf2x.a" "libseal-4.1.a" "libhelib.a")
        
        for lib_dir in "${THIRDPARTY_LIB_DIRS[@]}"; do
            if [ -d "$lib_dir" ]; then
                for dep_lib in "${DEP_LIBS[@]}"; do
                    dep_path="$lib_dir/$dep_lib"
                    if [ -f "$dep_path" ]; then
                        # Check if already added
                        already_added=false
                        for existing in "${LIBS_TO_BUNDLE[@]}"; do
                            if [ "$existing" = "$dep_path" ]; then
                                already_added=true
                                break
                            fi
                        done
                        if [ "$already_added" = false ]; then
                            LIBS_TO_BUNDLE+=("$dep_path")
                        fi
                    fi
                done
            fi
        done
        
        if [ ${#LIBS_TO_BUNDLE[@]} -gt 1 ]; then
            # Create temp directory for extraction
            BUNDLE_TMP_DIR="$BUILD_DIR/bundle_tmp"
            rm -rf "$BUNDLE_TMP_DIR"
            mkdir -p "$BUNDLE_TMP_DIR"
            
            cd "$BUNDLE_TMP_DIR"
            
            # Extract each library with prefixed object files
            lib_index=0
            for lib in "${LIBS_TO_BUNDLE[@]}"; do
                lib_name=$(basename "$lib" .a)
                prefix="lib${lib_index}_"
                
                echo "     Extracting $lib_name..."
                ar x "$lib" 2>/dev/null || true
                
                # Rename extracted .o files with prefix to avoid conflicts
                for obj in *.o; do
                    if [ -f "$obj" ] && [[ ! "$obj" =~ ^lib[0-9]+_ ]]; then
                        mv "$obj" "${prefix}${obj}"
                    fi
                done
                lib_index=$((lib_index + 1))
            done
            
            # Count total objects
            obj_count=$(ls -1 *.o 2>/dev/null | wc -l)
            
            if [ "$obj_count" -gt 0 ]; then
                echo "     Creating libkctsb_bundled.a ($obj_count objects)..."
                BUNDLED_LIB="$RELEASE_PLATFORM_DIR/lib/libkctsb_bundled.a"
                ar rcs "$BUNDLED_LIB" *.o 2>/dev/null
                
                if [ -f "$BUNDLED_LIB" ]; then
                    bundled_size=$(ls -lh "$BUNDLED_LIB" | awk '{print $5}')
                    echo -e "  ${GREEN}✓ Created libkctsb_bundled.a ($bundled_size)${NC}"
                else
                    echo -e "  ${RED}✗ Failed to create bundled library${NC}"
                fi
            fi
            
            # Cleanup
            cd "$PROJECT_DIR"
            rm -rf "$BUNDLE_TMP_DIR"
        else
            echo "  (No dependencies to bundle)"
        fi
    else
        echo "  (ar not found or static lib missing, skipping bundled library)"
    fi

    # Generate release info
    COMPILER_INFO=$(cc --version 2>/dev/null | head -1 || echo "Unknown")
    
    # Check for bundled library
    BUNDLED_LIB_PATH="$RELEASE_PLATFORM_DIR/lib/libkctsb_bundled.a"
    BUNDLED_INFO=""
    if [ -f "$BUNDLED_LIB_PATH" ]; then
        bundled_size=$(ls -lh "$BUNDLED_LIB_PATH" | awk '{print $5}')
        BUNDLED_INFO="- lib/libkctsb_bundled.a    : Bundled static library ($bundled_size, includes NTL/GMP/SEAL)"
    fi
    
    # Platform-specific link instructions
    if [ "$OS_NAME" = "macOS" ]; then
        LINK_INSTRUCTION="// Link: -lkctsb -lc++ -framework Security"
        BUNDLED_LINK="// Link: -lkctsb_bundled -lc++ -framework Security"
    else
        LINK_INSTRUCTION="// Link: -lkctsb -lntl -lgmp -lstdc++"
        BUNDLED_LINK="// Link: -lkctsb_bundled -lstdc++"
    fi
    
    cat > "$RELEASE_PLATFORM_DIR/RELEASE_INFO.txt" << EOF
kctsb Release Information
==========================
Version: ${VERSION}
Platform: ${OS_NAME} (${PLATFORM_SUFFIX})
Build Type: ${BUILD_TYPE}
Build Date: $(date '+%Y-%m-%d %H:%M:%S %Z')
Compiler: ${COMPILER_INFO}

Contents:
- bin/kctsb              : Command-line tool
- bin/kctsb_benchmark    : Performance benchmark (if built)
- lib/libkctsb.a         : Static library (requires NTL/GMP)
${BUNDLED_INFO}
- lib/libkctsb.dylib     : Dynamic library (macOS)
- lib/libkctsb.so*       : Shared library (Linux)
- include/kctsb_api.h    : Unified public API header

Integration (like OpenSSL):
  #include <kctsb_api.h>
  
  // Option 1: Use bundled library (single file, no external deps)
  ${BUNDLED_LINK}
  
  // Option 2: Use separate libraries  
  ${LINK_INSTRUCTION}

License: Apache License 2.0
Repository: https://github.com/kn1ghtc/kctsb
EOF

    echo -e "${GREEN}  ✓ Release package created in $RELEASE_PLATFORM_DIR${NC}"
    echo ""
    echo -e "${CYAN}Release contents:${NC}"
    ls -la "$RELEASE_PLATFORM_DIR/bin/" 2>/dev/null || true
    ls -la "$RELEASE_PLATFORM_DIR/lib/" 2>/dev/null || true
    ls -la "$RELEASE_PLATFORM_DIR/include/" 2>/dev/null || true
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
if [ "$RELEASE" = true ]; then
    echo -e "Release:        $RELEASE_PLATFORM_DIR"
fi
echo ""
echo -e "${CYAN}Distribution (like OpenSSL):${NC}"
echo "  Header:  kctsb_api.h"
echo "  Library: libkctsb.a"
if [ "$OS_NAME" = "macOS" ]; then
    echo "  Link:    -lkctsb -lc++ -framework Security"
else
    echo "  Link:    -lkctsb -lstdc++"
fi
echo ""
echo -e "${BLUE}Quick commands:${NC}"
echo "  $0                  # Quick build"
echo "  $0 --test           # Build + test"
echo "  $0 --clean --all    # Full rebuild"
echo "  $0 --release        # Create release"
