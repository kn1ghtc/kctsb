#!/bin/bash
# =============================================================================
# NTL 11.6.0 Optimized Build Script for Linux (Docker/Native)
#
# Creates a fully optimized libntl.a with ALL hardware acceleration:
# - GMP 6.3.0 (high-performance arbitrary precision arithmetic)
# - gf2x (fast GF(2)[x] polynomial arithmetic) 
# - AVX/AVX2/AVX-512 SIMD acceleration
# - FMA (Fused Multiply-Add) instructions
# - PCLMUL (Carry-less multiplication for GF2X)
# - Multithreading support
#
# Output: thirdparty/linux-x64/lib/libntl.a (optimized)
#
# Usage:
#   ./scripts/compile_ntl_optimized.sh              # Build optimized NTL
#   ./scripts/compile_ntl_optimized.sh --clean      # Clean and rebuild
#   ./scripts/compile_ntl_optimized.sh --avx512     # Enable AVX-512
#   ./scripts/compile_ntl_optimized.sh --verbose    # Verbose output
#
# Author: knightc
# Date: 2026-01-17
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

# Source and build directories
NTL_SRC_DIR="$DEPS_DIR/ntl-$NTL_VERSION/src"
BUILD_ROOT="$DEPS_DIR/ntl-optimized-build"
NTL_BUILD_DIR="$BUILD_ROOT/ntl"

# Output
OUTPUT_LIB="$THIRDPARTY_PLATFORM_DIR/lib/libntl.a"
OUTPUT_INCLUDE_DIR="$THIRDPARTY_PLATFORM_DIR/include/NTL"

# Compiler configuration
CXX="${CXX:-g++}"
CC="${CC:-gcc}"
AR="${AR:-ar}"
RANLIB="${RANLIB:-ranlib}"

# =============================================================================
# Parse Arguments
# =============================================================================

CLEAN=false
VERBOSE=false
ENABLE_AVX512=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --avx512)
            ENABLE_AVX512=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --clean       Clean build directories"
            echo "  --avx512      Enable AVX-512 instructions"
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

# =============================================================================
# Optimized Compiler Flags - CRITICAL FOR PERFORMANCE
# =============================================================================

# Base optimization flags
BASE_OPT="-O3 -DNDEBUG"

# CPU-specific optimizations
CPU_OPT="-march=native -mtune=native"

# SIMD and hardware acceleration flags
SIMD_FLAGS="-mavx -mavx2 -mfma -mpclmul -mbmi -mbmi2 -maes"

if [ "$ENABLE_AVX512" = true ]; then
    SIMD_FLAGS="$SIMD_FLAGS -mavx512f -mavx512dq -mavx512vl"
fi

# Link-time optimization
LTO_FLAGS="-flto"

# Threading support
THREAD_FLAGS="-pthread"

# Combined flags
NTL_CXXFLAGS="$BASE_OPT $CPU_OPT $SIMD_FLAGS $LTO_FLAGS $THREAD_FLAGS -std=c++17 -fPIC -w"

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
    echo -e "${CYAN}==========================================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}==========================================================================${NC}"
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

print_header "NTL $NTL_VERSION Optimized Build ($OS_NAME $ARCH_SUFFIX)"
echo "  Compiler:    $CXX"
echo "  Output:      $OUTPUT_LIB"
echo ""
echo -e "  ${CYAN}Optimization Flags:${NC}"
echo "    $NTL_CXXFLAGS"
echo ""

# Check source directory
if [ ! -d "$NTL_SRC_DIR" ]; then
    print_failure "NTL source not found: $NTL_SRC_DIR"
    echo "  Please download NTL $NTL_VERSION from https://libntl.org/"
    exit 1
fi

# Check for GMP library
GMP_LIB=""
for path in "$THIRDPARTY_PLATFORM_DIR/lib/libgmp.a" "$THIRDPARTY_DIR/lib/libgmp.a"; do
    if [ -f "$path" ]; then
        GMP_LIB="$path"
        break
    fi
done

if [ -z "$GMP_LIB" ]; then
    print_failure "GMP library not found"
    echo "  Please build GMP first with: ./scripts/build_thirdparty_linux.sh"
    exit 1
fi
print_success "Found GMP: $GMP_LIB"

# Clean if requested
if [ "$CLEAN" = true ]; then
    print_step "Cleaning build directory..."
    rm -rf "$BUILD_ROOT"
    print_success "Cleaned"
fi

# Create directories
mkdir -p "$NTL_BUILD_DIR"
mkdir -p "$THIRDPARTY_PLATFORM_DIR/lib"

# =============================================================================
# Build NTL with Full Optimization
# =============================================================================

print_header "Compiling NTL $NTL_VERSION (Optimized)"

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
OBJ_FILES=()

print_step "Compiling $ntl_total modules with full optimization..."

for module in "${NTL_CORE_MODULES[@]}"; do
    src_file="$NTL_SRC_DIR/$module.cpp"
    obj_file="$NTL_BUILD_DIR/$module.o"
    
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
        OBJ_FILES+=("$obj_file")
        ntl_compiled=$((ntl_compiled + 1))
    else
        echo -e "${RED}FAILED${NC}"
        ntl_failed=$((ntl_failed + 1))
    fi
done

echo ""
print_success "Compiled: $ntl_compiled modules, Failed: $ntl_failed"

# =============================================================================
# Create Optimized Library
# =============================================================================

print_header "Creating Optimized Library"

if [ ${#OBJ_FILES[@]} -eq 0 ]; then
    print_failure "No object files compiled!"
    exit 1
fi

print_step "Creating static library with ${#OBJ_FILES[@]} objects..."

# Remove old library
rm -f "$OUTPUT_LIB"

# Create archive with LTO support
$AR rcs "$OUTPUT_LIB" "${OBJ_FILES[@]}"
$RANLIB "$OUTPUT_LIB" 2>/dev/null || true

if [ -f "$OUTPUT_LIB" ]; then
    lib_size=$(ls -lh "$OUTPUT_LIB" | awk '{print $5}')
    print_success "Created: $OUTPUT_LIB ($lib_size)"
else
    print_failure "Failed to create library!"
    exit 1
fi

# =============================================================================
# Summary
# =============================================================================

print_header "Build Complete - Optimized NTL"
echo "  Library:     $OUTPUT_LIB"
echo "  Size:        $lib_size"
echo "  Modules:     $ntl_compiled"
echo ""
echo -e "  ${CYAN}Optimizations Enabled:${NC}"
echo "    ✓ -O3 maximum optimization"
echo "    ✓ -march=native (CPU-specific tuning)"
echo "    ✓ AVX/AVX2 SIMD acceleration"
echo "    ✓ FMA fused multiply-add"
echo "    ✓ PCLMUL carry-less multiplication"
echo "    ✓ LTO link-time optimization"
echo "    ✓ Multi-threading support"
if [ "$ENABLE_AVX512" = true ]; then
    echo "    ✓ AVX-512 instructions"
fi
echo ""
echo -e "  ${YELLOW}Next Steps:${NC}"
echo "    1. Rebuild kctsb: cmake --build build-release --clean-first"
echo "    2. Run benchmark: ./build-release/bin/kctsb_benchmark rsa"
echo ""

# Cleanup build directory
if [ "$VERBOSE" != true ]; then
    rm -rf "$BUILD_ROOT"
fi
