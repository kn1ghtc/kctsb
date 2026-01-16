#!/bin/bash
# =============================================================================
# NTL 11.6.0 Bundled Build Script for Linux/macOS
#
# Creates a single libntl_bundled.a that includes:
# - NTL 11.6.0 (all core modules)
# - GMP 6.3.0 (embedded, no external dependency)
# - gf2x (for fast GF(2)[x] arithmetic)
#
# Output: thirdparty/{linux-x64,macos-x64,macos-arm64}/lib/libntl_bundled.a
#
# Usage:
#   ./scripts/build_ntl_bundled.sh              # Build bundled NTL
#   ./scripts/build_ntl_bundled.sh --clean      # Clean and rebuild
#   ./scripts/build_ntl_bundled.sh --skip-gmp   # Skip GMP if already built
#
# Author: knightc
# Date: 2026-01-13
# =============================================================================

set -e

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPS_DIR="$PROJECT_ROOT/deps"
THIRDPARTY_DIR="$PROJECT_ROOT/thirdparty"

# Version info
NTL_VERSION="11.6.0"
GMP_VERSION="6.3.0"
GF2X_VERSION="1.3.0"

# Detect platform
OS_NAME=""
ARCH_SUFFIX=""
case "$(uname -s)" in
    Darwin*)
        OS_NAME="macOS"
        case "$(uname -m)" in
            arm64)  ARCH_SUFFIX="macos-arm64" ;;
            x86_64) ARCH_SUFFIX="macos-x64" ;;
            *)      ARCH_SUFFIX="macos-$(uname -m)" ;;
        esac
        ;;
    Linux*)
        OS_NAME="Linux"
        case "$(uname -m)" in
            x86_64|amd64) ARCH_SUFFIX="linux-x64" ;;
            aarch64|arm64) ARCH_SUFFIX="linux-arm64" ;;
            *)      ARCH_SUFFIX="linux-$(uname -m)" ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $(uname -s)"
        exit 1
        ;;
esac

THIRDPARTY_PLATFORM_DIR="$THIRDPARTY_DIR/$ARCH_SUFFIX"

# Source directories
NTL_SRC_DIR="$DEPS_DIR/ntl-$NTL_VERSION/src"
GMP_SRC_DIR="$DEPS_DIR/gmp-$GMP_VERSION"
GF2X_SRC_DIR="$DEPS_DIR/gf2x-$GF2X_VERSION"

# Build directories
BUILD_ROOT="$DEPS_DIR/bundle-build"
NTL_BUILD_DIR="$BUILD_ROOT/ntl"
GMP_BUILD_DIR="$BUILD_ROOT/gmp"
GF2X_BUILD_DIR="$BUILD_ROOT/gf2x"
MERGE_BUILD_DIR="$BUILD_ROOT/merge"

# Output
OUTPUT_LIB="$THIRDPARTY_PLATFORM_DIR/lib/libntl_bundled.a"
OUTPUT_INCLUDE_DIR="$THIRDPARTY_PLATFORM_DIR/include"

# Compiler configuration
CXX="${CXX:-g++}"
CC="${CC:-gcc}"
AR="${AR:-ar}"
RANLIB="${RANLIB:-ranlib}"

# Compiler flags
COMMON_CFLAGS="-O2 -fPIC -DNDEBUG"
NTL_CXXFLAGS="$COMMON_CFLAGS -std=c++17 -w"
GMP_CFLAGS="$COMMON_CFLAGS"
GF2X_CFLAGS="$COMMON_CFLAGS"

# Parse arguments
CLEAN=false
SKIP_GMP=false
SKIP_GF2X=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=true
            shift
            ;;
        --skip-gmp)
            SKIP_GMP=true
            shift
            ;;
        --skip-gf2x)
            SKIP_GF2X=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --clean       Clean build directories"
            echo "  --skip-gmp    Skip GMP (use existing library)"
            echo "  --skip-gf2x   Skip gf2x (use existing library)"
            echo "  --verbose     Verbose output"
            echo "  --help        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Helper Functions
# =============================================================================

print_header() {
    echo ""
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo ""
}

print_step() {
    echo -e "  ${YELLOW}→${NC} $1"
}

print_success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_failure() {
    echo -e "  ${RED}✗${NC} $1"
}

# =============================================================================
# Main Script
# =============================================================================

print_header "NTL $NTL_VERSION Bundled Build ($OS_NAME)"
echo "  Platform:    $ARCH_SUFFIX"
echo "  Compiler:    $CXX"
echo "  Output:      $OUTPUT_LIB"
echo "  Components:  NTL $NTL_VERSION + GMP $GMP_VERSION + gf2x $GF2X_VERSION"
echo ""

# Check source directories
MISSING_DEPS=""
if [ ! -d "$NTL_SRC_DIR" ]; then
    MISSING_DEPS="$MISSING_DEPS\n  - NTL ($NTL_SRC_DIR)"
fi

if [ "$SKIP_GMP" != true ] && [ ! -d "$GMP_SRC_DIR" ]; then
    # Check if GMP library exists
    if [ ! -f "$THIRDPARTY_DIR/lib/libgmp.a" ] && [ ! -f "$THIRDPARTY_PLATFORM_DIR/lib/libgmp.a" ]; then
        MISSING_DEPS="$MISSING_DEPS\n  - GMP ($GMP_SRC_DIR or pre-built library)"
    fi
fi

if [ -n "$MISSING_DEPS" ]; then
    echo -e "${RED}Missing dependencies:${NC}$MISSING_DEPS"
    echo ""
    echo -e "${YELLOW}Please download and extract:${NC}"
    echo "  - NTL: https://libntl.org/ntl-$NTL_VERSION.tar.gz → $DEPS_DIR/ntl-$NTL_VERSION"
    echo "  - GMP: https://gmplib.org/download/gmp/gmp-$GMP_VERSION.tar.xz → $DEPS_DIR/gmp-$GMP_VERSION"
    exit 1
fi

# Clean if requested
if [ "$CLEAN" = true ]; then
    print_step "Cleaning build directories..."
    rm -rf "$BUILD_ROOT"
    print_success "Cleaned"
fi

# Create directories
mkdir -p "$NTL_BUILD_DIR" "$GMP_BUILD_DIR" "$GF2X_BUILD_DIR" "$MERGE_BUILD_DIR"
mkdir -p "$THIRDPARTY_PLATFORM_DIR/lib" "$OUTPUT_INCLUDE_DIR"

ALL_OBJ_FILES=()

# =============================================================================
# Build/Extract GMP
# =============================================================================

if [ "$SKIP_GMP" != true ]; then
    print_header "Processing GMP $GMP_VERSION"
    
    # Look for existing GMP library
    GMP_LIB=""
    for lib_path in "$THIRDPARTY_PLATFORM_DIR/lib/libgmp.a" "$THIRDPARTY_DIR/lib/libgmp.a"; do
        if [ -f "$lib_path" ]; then
            GMP_LIB="$lib_path"
            break
        fi
    done
    
    if [ -n "$GMP_LIB" ]; then
        print_step "Using existing GMP library: $GMP_LIB"
        cd "$GMP_BUILD_DIR"
        $AR x "$GMP_LIB" 2>/dev/null || true
        
        # Rename with prefix
        for obj in *.o; do
            if [ -f "$obj" ]; then
                mv "$obj" "gmp_$obj"
            fi
        done
        
        gmp_count=$(ls -1 gmp_*.o 2>/dev/null | wc -l)
        for obj in gmp_*.o; do
            if [ -f "$obj" ]; then
                ALL_OBJ_FILES+=("$GMP_BUILD_DIR/$obj")
            fi
        done
        print_success "Extracted $gmp_count GMP objects"
        cd "$PROJECT_ROOT"
    else
        print_failure "GMP library not found. Please build GMP first or use --skip-gmp"
        echo "  Run: ./scripts/build_thirdparty_linux.sh"
    fi
fi

# =============================================================================
# Build/Extract gf2x
# =============================================================================

if [ "$SKIP_GF2X" != true ]; then
    print_header "Processing gf2x $GF2X_VERSION"
    
    GF2X_LIB=""
    for lib_path in "$THIRDPARTY_PLATFORM_DIR/lib/libgf2x.a" "$THIRDPARTY_DIR/lib/libgf2x.a"; do
        if [ -f "$lib_path" ]; then
            GF2X_LIB="$lib_path"
            break
        fi
    done
    
    if [ -n "$GF2X_LIB" ]; then
        print_step "Using existing gf2x library: $GF2X_LIB"
        cd "$GF2X_BUILD_DIR"
        $AR x "$GF2X_LIB" 2>/dev/null || true
        
        for obj in *.o; do
            if [ -f "$obj" ]; then
                mv "$obj" "gf2x_$obj"
            fi
        done
        
        gf2x_count=$(ls -1 gf2x_*.o 2>/dev/null | wc -l)
        for obj in gf2x_*.o; do
            if [ -f "$obj" ]; then
                ALL_OBJ_FILES+=("$GF2X_BUILD_DIR/$obj")
            fi
        done
        print_success "Extracted $gf2x_count gf2x objects"
        cd "$PROJECT_ROOT"
    else
        print_step "gf2x library not found, NTL will use internal GF(2)[x] implementation"
    fi
fi

# =============================================================================
# Build NTL
# =============================================================================

print_header "Building NTL $NTL_VERSION"

# NTL core modules
NTL_CORE_MODULES=(
    "BasicThreadPool" "ctools" "FacVec" "FFT" "fileio"
    "G_LLL_FP" "G_LLL_QP" "G_LLL_RR" "G_LLL_XD"
    "GF2" "GF2E" "GF2EX" "GF2EXFactoring" "GF2X" "GF2X1" "GF2XFactoring" "GF2XVec"
    "HNF" "InitSettings" "lip" "LLL" "LLL_FP" "LLL_QP" "LLL_RR" "LLL_XD"
    "lzz_p" "lzz_pE" "lzz_pEX" "lzz_pEXFactoring" "lzz_pX" "lzz_pX1" "lzz_pXCharPoly" "lzz_pXFactoring"
    "mat_GF2" "mat_GF2E" "mat_lzz_p" "mat_lzz_pE" "mat_poly_lzz_p" "mat_poly_ZZ" "mat_poly_ZZ_p"
    "mat_RR" "mat_ZZ" "mat_ZZ_p" "mat_ZZ_pE" "MatPrime"
    "newnames" "pd_FFT" "quad_float" "quad_float1" "RR"
    "subset" "thread" "tools"
    "vec_GF2" "vec_GF2E" "vec_lzz_p" "vec_lzz_pE" "vec_RR" "vec_ZZ" "vec_ZZ_p" "vec_ZZ_pE"
    "WordVector" "xdouble"
    "ZZ" "ZZ_p" "ZZ_pE" "ZZ_pEX" "ZZ_pEXFactoring" "ZZ_pX" "ZZ_pX1" "ZZ_pXCharPoly" "ZZ_pXFactoring"
    "ZZVec" "ZZX" "ZZX1" "ZZXCharPoly" "ZZXFactoring"
)

NTL_INCLUDES="-I$THIRDPARTY_DIR/include -I$THIRDPARTY_PLATFORM_DIR/include"

ntl_total=${#NTL_CORE_MODULES[@]}
ntl_compiled=0
ntl_failed=0

print_step "Compiling $ntl_total NTL modules..."

for module in "${NTL_CORE_MODULES[@]}"; do
    src_file="$NTL_SRC_DIR/$module.cpp"
    obj_file="$NTL_BUILD_DIR/ntl_$module.o"
    
    if [ ! -f "$src_file" ]; then
        if [ "$VERBOSE" = true ]; then
            echo "    [SKIP] $module (not found)"
        fi
        continue
    fi
    
    progress=$((100 * (ntl_compiled + ntl_failed + 1) / ntl_total))
    printf "    [%3d%%] %s... " "$progress" "$module"
    
    if $CXX -c $NTL_CXXFLAGS $NTL_INCLUDES "$src_file" -o "$obj_file" 2>/dev/null; then
        size=$(ls -lh "$obj_file" | awk '{print $5}')
        echo -e "${GREEN}OK${NC} ($size)"
        ALL_OBJ_FILES+=("$obj_file")
        ntl_compiled=$((ntl_compiled + 1))
    else
        echo -e "${RED}FAILED${NC}"
        ntl_failed=$((ntl_failed + 1))
    fi
done

echo ""
print_success "NTL: $ntl_compiled compiled, $ntl_failed failed"

# =============================================================================
# Merge into single library
# =============================================================================

print_header "Creating Bundled Library"

if [ ${#ALL_OBJ_FILES[@]} -eq 0 ]; then
    print_failure "No object files to merge!"
    exit 1
fi

print_step "Merging ${#ALL_OBJ_FILES[@]} object files..."

# Remove old library
rm -f "$OUTPUT_LIB"

# Copy all object files to merge directory
cd "$MERGE_BUILD_DIR"
for obj in "${ALL_OBJ_FILES[@]}"; do
    cp "$obj" . 2>/dev/null || true
done

# Create archive
$AR rcs "$OUTPUT_LIB" *.o 2>/dev/null
$RANLIB "$OUTPUT_LIB" 2>/dev/null || true

cd "$PROJECT_ROOT"

if [ -f "$OUTPUT_LIB" ]; then
    lib_size=$(ls -lh "$OUTPUT_LIB" | awk '{print $5}')
    print_success "Created: $OUTPUT_LIB ($lib_size)"
else
    print_failure "Failed to create bundled library!"
    exit 1
fi

# =============================================================================
# Summary
# =============================================================================

print_header "Build Complete"
echo "  Output Library: $OUTPUT_LIB"
echo "  Size:           $lib_size"
echo "  Objects:        ${#ALL_OBJ_FILES[@]}"
echo ""
echo -e "  ${CYAN}Usage:${NC}"
echo "    #include <NTL/ZZ.h>"
if [ "$OS_NAME" = "macOS" ]; then
    echo "    // Link: -lntl_bundled -lc++"
else
    echo "    // Link: -lntl_bundled -lstdc++ -lpthread"
fi
echo ""
echo -e "  ${CYAN}CMake:${NC}"
echo "    target_link_libraries(myapp PRIVATE ntl_bundled)"
echo ""

# Cleanup
rm -rf "$MERGE_BUILD_DIR"
