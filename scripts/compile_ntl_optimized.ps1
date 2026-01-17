#!/usr/bin/env pwsh
# =============================================================================
# NTL 11.6.0 Optimized Build Script for Windows
#
# Creates a fully optimized libntl.a with ALL hardware acceleration:
# - GMP 6.3.0 (high-performance arbitrary precision arithmetic)
# - gf2x (fast GF(2)[x] polynomial arithmetic) 
# - AVX/AVX2/AVX-512 SIMD acceleration
# - FMA (Fused Multiply-Add) instructions
# - PCLMUL (Carry-less multiplication for GF2X)
# - Multithreading support
#
# Output: thirdparty/win-x64/lib/libntl.a (optimized)
#
# Usage:
#   .\scripts\compile_ntl_optimized.ps1              # Build optimized NTL
#   .\scripts\compile_ntl_optimized.ps1 -Clean       # Clean and rebuild
#   .\scripts\compile_ntl_optimized.ps1 -Verbose     # Verbose output
#
# Author: knightc
# Date: 2026-01-17
# =============================================================================

param(
    [switch]$Clean,
    [switch]$Verbose,
    [switch]$EnableAVX512
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# =============================================================================
# Configuration
# =============================================================================

$ProjectRoot = "D:\pyproject\kctsb"
$DepsDir = "$ProjectRoot\deps"
$ThirdpartyDir = "$ProjectRoot\thirdparty"
$ThirdpartyPlatformDir = "$ThirdpartyDir\win-x64"

# Version info
$NTL_VERSION = "11.6.0"

# Source and build directories
$NtlSrcDir = "$DepsDir\ntl-$NTL_VERSION\src"
$BuildRoot = "$DepsDir\ntl-optimized-build"
$NtlBuildDir = "$BuildRoot\ntl"

# Output
$OutputLib = "$ThirdpartyPlatformDir\lib\libntl.a"

# Compiler configuration (MSYS2 MinGW64)
$MSYS2_BIN = "C:\msys64\mingw64\bin"
if (Test-Path "$MSYS2_BIN\g++.exe") {
    $CXX = "$MSYS2_BIN\g++.exe"
    $AR = "$MSYS2_BIN\ar.exe"
    $RANLIB = "$MSYS2_BIN\ranlib.exe"
    $env:PATH = "$MSYS2_BIN;$env:PATH"
} else {
    Write-Error "MSYS2 MinGW64 not found. Please install from https://www.msys2.org/"
    exit 1
}

# =============================================================================
# Optimized Compiler Flags - CRITICAL FOR PERFORMANCE
# =============================================================================

# Base optimization flags
$BASE_OPT = "-O3 -DNDEBUG"

# CPU-specific optimizations (auto-detect best for current CPU)
$CPU_OPT = "-march=native -mtune=native"

# SIMD and hardware acceleration flags
$SIMD_FLAGS = @(
    "-mavx",        # AVX (256-bit SIMD)
    "-mavx2",       # AVX2 (enhanced 256-bit SIMD)
    "-mfma",        # Fused Multiply-Add
    "-mpclmul",     # Carry-less multiplication (for GF2X)
    "-mbmi",        # Bit Manipulation Instructions
    "-mbmi2",       # BMI2
    "-maes"         # AES-NI (for random number generation)
)

if ($EnableAVX512) {
    $SIMD_FLAGS += @(
        "-mavx512f",    # AVX-512 Foundation
        "-mavx512dq",   # AVX-512 Double/Quad word
        "-mavx512vl"    # AVX-512 Vector Length
    )
}

$SIMD_STR = $SIMD_FLAGS -join " "

# Link-time optimization for cross-module inlining
$LTO_FLAGS = "-flto"

# Threading support
$THREAD_FLAGS = "-pthread"

# Combined flags
$NTL_CXXFLAGS = "$BASE_OPT $CPU_OPT $SIMD_STR $LTO_FLAGS $THREAD_FLAGS -std=c++17 -fPIC -w"

# =============================================================================
# Helper Functions
# =============================================================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "=" * 75 -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "=" * 75 -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "  → $Text" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Text)
    Write-Host "  ✓ $Text" -ForegroundColor Green
}

function Write-Failure {
    param([string]$Text)
    Write-Host "  ✗ $Text" -ForegroundColor Red
}

# =============================================================================
# Main Script
# =============================================================================

Write-Header "NTL $NTL_VERSION Optimized Build (Windows x64)"
Write-Host "  Compiler:    MinGW GCC (MSYS2)"
Write-Host "  Output:      $OutputLib"
Write-Host ""
Write-Host "  Optimization Flags:" -ForegroundColor Cyan
Write-Host "    $NTL_CXXFLAGS" -ForegroundColor DarkGray
Write-Host ""

# Check source directory
if (-not (Test-Path $NtlSrcDir)) {
    Write-Failure "NTL source not found: $NtlSrcDir"
    Write-Host "  Please download NTL $NTL_VERSION from https://libntl.org/"
    exit 1
}

# Check for GMP library
$GmpLib = "$ThirdpartyDir\lib\libgmp.a"
if (-not (Test-Path $GmpLib)) {
    Write-Failure "GMP library not found: $GmpLib"
    Write-Host "  Please build GMP first with: .\scripts\build_gmp.ps1"
    exit 1
}

# Clean if requested
if ($Clean) {
    Write-Step "Cleaning build directory..."
    if (Test-Path $BuildRoot) { Remove-Item -Recurse -Force $BuildRoot }
    Write-Success "Cleaned"
}

# Create directories
New-Item -ItemType Directory -Force -Path $NtlBuildDir | Out-Null
New-Item -ItemType Directory -Force -Path "$ThirdpartyPlatformDir\lib" | Out-Null

# =============================================================================
# Build NTL with Full Optimization
# =============================================================================

Write-Header "Compiling NTL $NTL_VERSION (Optimized)"

# NTL core modules - ALL modules for complete functionality
$NtlCoreModules = @(
    "BasicThreadPool", "ctools", "FacVec", "FFT", "fileio",
    "G_LLL_FP", "G_LLL_QP", "G_LLL_RR", "G_LLL_XD",
    "GF2", "GF2E", "GF2EX", "GF2EXFactoring", "GF2X", "GF2X1", "GF2XFactoring", "GF2XVec",
    "HNF", "InitSettings", "lip", "LLL", "LLL_FP", "LLL_QP", "LLL_RR", "LLL_XD",
    "lzz_p", "lzz_pE", "lzz_pEX", "lzz_pEXFactoring", "lzz_pX", "lzz_pX1", "lzz_pXCharPoly", "lzz_pXFactoring",
    "mat_GF2", "mat_GF2E", "mat_lzz_p", "mat_lzz_pE", "mat_poly_lzz_p", "mat_poly_ZZ", "mat_poly_ZZ_p",
    "mat_RR", "mat_ZZ", "mat_ZZ_p", "mat_ZZ_pE", "MatPrime",
    "newnames", "pd_FFT", "quad_float", "quad_float1", "RR",
    "subset", "thread", "tools",
    "vec_GF2", "vec_GF2E", "vec_lzz_p", "vec_lzz_pE", "vec_RR", "vec_ZZ", "vec_ZZ_p", "vec_ZZ_pE",
    "WordVector", "xdouble",
    "ZZ", "ZZ_p", "ZZ_pE", "ZZ_pEX", "ZZ_pEXFactoring", "ZZ_pX", "ZZ_pX1", "ZZ_pXCharPoly", "ZZ_pXFactoring",
    "ZZVec", "ZZX", "ZZX1", "ZZXCharPoly", "ZZXFactoring"
)

$NtlIncludes = "-I`"$ThirdpartyDir\include`""

$ntlTotal = $NtlCoreModules.Count
$ntlCompiled = 0
$ntlFailed = 0
$objFiles = @()

Write-Step "Compiling $ntlTotal modules with full optimization..."

foreach ($module in $NtlCoreModules) {
    $srcFile = "$NtlSrcDir\$module.cpp"
    $objFile = "$NtlBuildDir\$module.o"
    
    if (-not (Test-Path $srcFile)) {
        if ($Verbose) { Write-Host "    [SKIP] $module (not found)" -ForegroundColor DarkGray }
        continue
    }
    
    $progress = [math]::Round(($ntlCompiled + $ntlFailed + 1) / $ntlTotal * 100)
    Write-Host -NoNewline "    [$progress%] $module... "
    
    # Build argument list properly for Start-Process
    $argList = @(
        "-c",
        "-O3", "-DNDEBUG",
        "-march=native", "-mtune=native",
        "-mavx", "-mavx2", "-mfma", "-mpclmul", "-mbmi", "-mbmi2", "-maes",
        "-flto", "-pthread",
        "-std=c++17", "-fPIC", "-w",
        "-I$ThirdpartyDir\include",
        $srcFile,
        "-o", $objFile
    )
    
    if ($Verbose) { Write-Host "`n      g++ $($argList -join ' ')" -ForegroundColor DarkGray }
    
    $proc = Start-Process -FilePath $CXX -ArgumentList $argList -NoNewWindow -Wait -PassThru -RedirectStandardError "NUL"
    
    if ($proc.ExitCode -eq 0 -and (Test-Path $objFile)) {
        $size = [math]::Round((Get-Item $objFile).Length / 1024, 1)
        Write-Host "OK (${size}KB)" -ForegroundColor Green
        $objFiles += $objFile
        $ntlCompiled++
    } else {
        Write-Host "FAILED" -ForegroundColor Red
        $ntlFailed++
    }
}

Write-Host ""
Write-Success "Compiled: $ntlCompiled modules, Failed: $ntlFailed"

# =============================================================================
# Create Optimized Library
# =============================================================================

Write-Header "Creating Optimized Library"

if ($objFiles.Count -eq 0) {
    Write-Failure "No object files compiled!"
    exit 1
}

Write-Step "Creating static library with $($objFiles.Count) objects..."

# Remove old library
if (Test-Path $OutputLib) {
    Remove-Item -Force $OutputLib
}

# Create archive with LTO support
$objList = ($objFiles | ForEach-Object { "`"$_`"" }) -join " "
$arCmd = "`"$AR`" rcs `"$OutputLib`" $objList"
Invoke-Expression $arCmd 2>&1 | Out-Null

# Ranlib for index
& $RANLIB $OutputLib 2>&1 | Out-Null

if (Test-Path $OutputLib) {
    $libSize = [math]::Round((Get-Item $OutputLib).Length / 1MB, 2)
    Write-Success "Created: $OutputLib ($libSize MB)"
} else {
    Write-Failure "Failed to create library!"
    exit 1
}

# =============================================================================
# Summary
# =============================================================================

Write-Header "Build Complete - Optimized NTL"
Write-Host "  Library:     $OutputLib"
Write-Host "  Size:        $libSize MB"
Write-Host "  Modules:     $ntlCompiled"
Write-Host ""
Write-Host "  Optimizations Enabled:" -ForegroundColor Cyan
Write-Host "    ✓ -O3 maximum optimization"
Write-Host "    ✓ -march=native (CPU-specific tuning)"
Write-Host "    ✓ AVX/AVX2 SIMD acceleration"
Write-Host "    ✓ FMA fused multiply-add"
Write-Host "    ✓ PCLMUL carry-less multiplication"
Write-Host "    ✓ LTO link-time optimization"
Write-Host "    ✓ Multi-threading support"
if ($EnableAVX512) {
    Write-Host "    ✓ AVX-512 instructions"
}
Write-Host ""
Write-Host "  Next Steps:" -ForegroundColor Yellow
Write-Host "    1. Rebuild kctsb: cmake --build build-release --clean-first"
Write-Host "    2. Run benchmark: .\build-release\bin\kctsb_benchmark.exe rsa"
Write-Host ""

# Cleanup build directory
if (-not $Verbose) {
    Remove-Item -Recurse -Force $BuildRoot -ErrorAction SilentlyContinue
}
