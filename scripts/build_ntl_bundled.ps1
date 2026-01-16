#!/usr/bin/env pwsh
# =============================================================================
# NTL 11.6.0 Bundled Build Script for Windows
#
# Creates a single libntl_bundled.a that includes:
# - NTL 11.6.0 (all core modules)
# - GMP 6.3.0 (embedded, no external dependency)
# - gf2x (for fast GF(2)[x] arithmetic)
#
# Output: thirdparty/win-x64/lib/libntl_bundled.a
#
# Usage:
#   .\scripts\build_ntl_bundled.ps1              # Build bundled NTL
#   .\scripts\build_ntl_bundled.ps1 -Clean       # Clean and rebuild
#   .\scripts\build_ntl_bundled.ps1 -SkipGmp     # Skip GMP if already built
#
# Author: knightc
# Date: 2026-01-13
# =============================================================================

param(
    [switch]$Clean,
    [switch]$SkipGmp,
    [switch]$SkipGf2x,
    [switch]$Verbose
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
$GMP_VERSION = "6.3.0"
$GF2X_VERSION = "1.3.0"

# Source directories (download or extract to these locations)
$NtlSrcDir = "$DepsDir\ntl-$NTL_VERSION\src"
$GmpSrcDir = "$DepsDir\gmp-$GMP_VERSION"
$Gf2xSrcDir = "$DepsDir\gf2x-$GF2X_VERSION"

# Build directories
$BuildRoot = "$DepsDir\bundle-build"
$NtlBuildDir = "$BuildRoot\ntl"
$GmpBuildDir = "$BuildRoot\gmp"
$Gf2xBuildDir = "$BuildRoot\gf2x"
$MergeBuildDir = "$BuildRoot\merge"

# Output
$OutputLib = "$ThirdpartyPlatformDir\lib\libntl_bundled.a"
$OutputIncludeDir = "$ThirdpartyPlatformDir\include"

# Compiler configuration (prefer MSYS2 MinGW64)
$MSYS2_BIN = "C:\msys64\mingw64\bin"
if (Test-Path "$MSYS2_BIN\g++.exe") {
    $CXX = "$MSYS2_BIN\g++.exe"
    $CC = "$MSYS2_BIN\gcc.exe"
    $AR = "$MSYS2_BIN\ar.exe"
    $RANLIB = "$MSYS2_BIN\ranlib.exe"
    $env:PATH = "$MSYS2_BIN;$env:PATH"
    $ToolchainName = "MSYS2 MinGW64"
} elseif (Test-Path "C:\Strawberry\c\bin\g++.exe") {
    $CXX = "C:\Strawberry\c\bin\g++.exe"
    $CC = "C:\Strawberry\c\bin\gcc.exe"
    $AR = "C:\Strawberry\c\bin\ar.exe"
    $RANLIB = "C:\Strawberry\c\bin\ranlib.exe"
    $ToolchainName = "Strawberry Perl"
} else {
    Write-Error "No suitable C/C++ compiler found. Install MSYS2 or Strawberry Perl."
    exit 1
}

# Compiler flags
$COMMON_CFLAGS = "-O2 -fPIC -DNDEBUG"
$NTL_CXXFLAGS = "$COMMON_CFLAGS -std=c++17 -w"  # -w to suppress NTL warnings
$GMP_CFLAGS = "$COMMON_CFLAGS"
$GF2X_CFLAGS = "$COMMON_CFLAGS"

# =============================================================================
# Helper Functions
# =============================================================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
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

function Compile-CFile {
    param(
        [string]$SrcFile,
        [string]$ObjFile,
        [string]$IncludeDirs,
        [string]$Flags = $GMP_CFLAGS
    )
    
    $includes = $IncludeDirs -split ";" | ForEach-Object { "-I`"$_`"" }
    $includeStr = $includes -join " "
    
    $cmd = "`"$CC`" -c $Flags $includeStr `"$SrcFile`" -o `"$ObjFile`""
    if ($Verbose) { Write-Host "    $cmd" -ForegroundColor DarkGray }
    
    $result = Invoke-Expression $cmd 2>&1
    return $LASTEXITCODE -eq 0
}

function Compile-CppFile {
    param(
        [string]$SrcFile,
        [string]$ObjFile,
        [string]$IncludeDirs,
        [string]$Flags = $NTL_CXXFLAGS
    )
    
    $includes = $IncludeDirs -split ";" | ForEach-Object { "-I`"$_`"" }
    $includeStr = $includes -join " "
    
    $cmd = "`"$CXX`" -c $Flags $includeStr `"$SrcFile`" -o `"$ObjFile`""
    if ($Verbose) { Write-Host "    $cmd" -ForegroundColor DarkGray }
    
    $result = Invoke-Expression $cmd 2>&1
    return $LASTEXITCODE -eq 0
}

# =============================================================================
# Main Script
# =============================================================================

Write-Header "NTL $NTL_VERSION Bundled Build (Windows)"
Write-Host "  Toolchain:   $ToolchainName"
Write-Host "  Output:      $OutputLib"
Write-Host "  Components:  NTL $NTL_VERSION + GMP $GMP_VERSION + gf2x $GF2X_VERSION"
Write-Host ""

# Check source directories
$missingDeps = @()
if (-not (Test-Path $NtlSrcDir)) { $missingDeps += "NTL ($NtlSrcDir)" }
if ((-not $SkipGmp) -and (-not (Test-Path $GmpSrcDir))) { $missingDeps += "GMP ($GmpSrcDir)" }
if ((-not $SkipGf2x) -and (-not (Test-Path $Gf2xSrcDir))) { $missingDeps += "gf2x ($Gf2xSrcDir)" }

if ($missingDeps.Count -gt 0) {
    Write-Host "Missing source directories:" -ForegroundColor Red
    foreach ($dep in $missingDeps) {
        Write-Host "  - $dep" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Please download and extract:" -ForegroundColor Yellow
    Write-Host "  - NTL: https://libntl.org/ntl-$NTL_VERSION.tar.gz → $DepsDir\ntl-$NTL_VERSION"
    Write-Host "  - GMP: https://gmplib.org/download/gmp/gmp-$GMP_VERSION.tar.xz → $DepsDir\gmp-$GMP_VERSION"
    Write-Host "  - gf2x: https://gitlab.inria.fr/gf2x/gf2x/-/archive/gf2x-$GF2X_VERSION → $DepsDir\gf2x-$GF2X_VERSION"
    exit 1
}

# Clean if requested
if ($Clean) {
    Write-Step "Cleaning build directories..."
    if (Test-Path $BuildRoot) { Remove-Item -Recurse -Force $BuildRoot }
    Write-Success "Cleaned"
}

# Create directories
New-Item -ItemType Directory -Force -Path $NtlBuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $GmpBuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $Gf2xBuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $MergeBuildDir | Out-Null
New-Item -ItemType Directory -Force -Path "$ThirdpartyPlatformDir\lib" | Out-Null
New-Item -ItemType Directory -Force -Path $OutputIncludeDir | Out-Null

$allObjFiles = @()

# =============================================================================
# Build GMP (if not skipped)
# =============================================================================

if (-not $SkipGmp) {
    Write-Header "Building GMP $GMP_VERSION"
    
    # GMP core source files (mini-gmp is simpler, or use full mpn/mpz)
    # For simplicity, we use pre-built GMP from thirdparty if available
    $existingGmpLib = "$ThirdpartyDir\lib\libgmp.a"
    if (Test-Path $existingGmpLib) {
        Write-Step "Using existing GMP library: $existingGmpLib"
        Push-Location $GmpBuildDir
        & $AR x $existingGmpLib 2>$null
        Get-ChildItem -Filter "*.o" | ForEach-Object {
            $newName = "gmp_$($_.Name)"
            Rename-Item $_.FullName $newName -Force
        }
        $gmpObjs = Get-ChildItem -Filter "gmp_*.o" | ForEach-Object { $_.FullName }
        $allObjFiles += $gmpObjs
        Pop-Location
        Write-Success "Extracted $(($gmpObjs).Count) GMP objects"
    } else {
        Write-Failure "GMP library not found. Please build GMP first or use -SkipGmp"
        Write-Host "  Run: .\scripts\build_gmp.ps1" -ForegroundColor Yellow
    }
}

# =============================================================================
# Build gf2x (if not skipped)
# =============================================================================

if (-not $SkipGf2x) {
    Write-Header "Building gf2x $GF2X_VERSION"
    
    $existingGf2xLib = "$ThirdpartyDir\lib\libgf2x.a"
    if (-not (Test-Path $existingGf2xLib)) {
        $existingGf2xLib = "$ThirdpartyDir\include\gf2x\libgf2x.a"
    }
    
    if (Test-Path $existingGf2xLib) {
        Write-Step "Using existing gf2x library: $existingGf2xLib"
        Push-Location $Gf2xBuildDir
        & $AR x $existingGf2xLib 2>$null
        Get-ChildItem -Filter "*.o" | ForEach-Object {
            $newName = "gf2x_$($_.Name)"
            Rename-Item $_.FullName $newName -Force
        }
        $gf2xObjs = Get-ChildItem -Filter "gf2x_*.o" | ForEach-Object { $_.FullName }
        $allObjFiles += $gf2xObjs
        Pop-Location
        Write-Success "Extracted $(($gf2xObjs).Count) gf2x objects"
    } else {
        Write-Step "gf2x library not found, NTL will use internal GF(2)[x] implementation"
    }
}

# =============================================================================
# Build NTL
# =============================================================================

Write-Header "Building NTL $NTL_VERSION"

# NTL core modules (excluding tests, checks, timing files)
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

# Include paths for NTL
$NtlIncludes = "$ThirdpartyDir\include;$ThirdpartyDir\lib"

$ntlTotal = $NtlCoreModules.Count
$ntlCompiled = 0
$ntlFailed = 0

Write-Step "Compiling $ntlTotal NTL modules..."

foreach ($module in $NtlCoreModules) {
    $srcFile = "$NtlSrcDir\$module.cpp"
    $objFile = "$NtlBuildDir\ntl_$module.o"
    
    if (-not (Test-Path $srcFile)) {
        Write-Host "    [SKIP] $module (not found)" -ForegroundColor DarkGray
        continue
    }
    
    $progress = [math]::Round(($ntlCompiled + $ntlFailed + 1) / $ntlTotal * 100)
    Write-Host -NoNewline "    [$progress%] $module... "
    
    if (Compile-CppFile -SrcFile $srcFile -ObjFile $objFile -IncludeDirs $NtlIncludes) {
        $size = [math]::Round((Get-Item $objFile).Length / 1024, 1)
        Write-Host "OK (${size}KB)" -ForegroundColor Green
        $allObjFiles += $objFile
        $ntlCompiled++
    } else {
        Write-Host "FAILED" -ForegroundColor Red
        $ntlFailed++
    }
}

Write-Host ""
Write-Success "NTL: $ntlCompiled compiled, $ntlFailed failed"

# =============================================================================
# Merge into single library
# =============================================================================

Write-Header "Creating Bundled Library"

if ($allObjFiles.Count -eq 0) {
    Write-Failure "No object files to merge!"
    exit 1
}

Write-Step "Merging $($allObjFiles.Count) object files..."

# Remove old library
if (Test-Path $OutputLib) {
    Remove-Item -Force $OutputLib
}

# Create bundled library
Push-Location $MergeBuildDir

# Copy all object files to merge directory with unique names
$copyIndex = 0
foreach ($objFile in $allObjFiles) {
    $baseName = Split-Path $objFile -Leaf
    Copy-Item $objFile "$MergeBuildDir\$baseName" -Force
    $copyIndex++
}

# Create archive
$objPattern = Get-ChildItem -Filter "*.o" | ForEach-Object { $_.Name }
& $AR rcs $OutputLib $objPattern 2>$null
& $RANLIB $OutputLib 2>$null

Pop-Location

if (Test-Path $OutputLib) {
    $libSize = [math]::Round((Get-Item $OutputLib).Length / 1MB, 2)
    Write-Success "Created: $OutputLib ($libSize MB)"
} else {
    Write-Failure "Failed to create bundled library!"
    exit 1
}

# =============================================================================
# Summary
# =============================================================================

Write-Header "Build Complete"
Write-Host "  Output Library: $OutputLib"
Write-Host "  Size:           $libSize MB"
Write-Host "  Objects:        $($allObjFiles.Count)"
Write-Host ""
Write-Host "  Usage:" -ForegroundColor Cyan
Write-Host "    #include <NTL/ZZ.h>"
Write-Host "    // Link: -lntl_bundled -lstdc++"
Write-Host ""
Write-Host "  CMake:" -ForegroundColor Cyan
Write-Host "    target_link_libraries(myapp PRIVATE ntl_bundled)"
Write-Host ""

# Cleanup merge directory
if (Test-Path $MergeBuildDir) {
    Remove-Item -Recurse -Force $MergeBuildDir
}
