#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build GMP (GNU Multiple Precision Arithmetic Library) with C++ support for Windows
    
.DESCRIPTION
    Downloads and compiles GMP from source using MSYS2/MinGW environment.
    Outputs both C (libgmp.a) and C++ (libgmpxx.a) libraries with headers.
    
    This script is required for HElib compilation which needs gmpxx.h.
    
.PARAMETER Version
    GMP version to download (default: 6.3.0)
    
.PARAMETER InstallDir
    Installation directory (default: D:\libs\gmp)
    
.PARAMETER BuildDir
    Temporary build directory (default: D:\libs\gmp_build)
    
.PARAMETER MSYS2Root
    MSYS2 installation root (default: C:\msys64)
    
.PARAMETER Clean
    Clean build and source directories before starting
    
.EXAMPLE
    .\build_gmp.ps1
    
.EXAMPLE
    .\build_gmp.ps1 -Version 6.3.0 -InstallDir D:\custom\gmp -Clean
    
.NOTES
    Author: knightc
    Date: 2026-01-12
    Requires: MSYS2 with mingw-w64-x86_64-gcc installed
    
    MSYS2 Installation:
    1. Download from https://www.msys2.org/
    2. Install to C:\msys64
    3. Run: pacman -Syu
    4. Run: pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make
#>

param(
    [string]$Version = "6.3.0",
    [string]$InstallDir = "D:\libs\gmp",
    [string]$BuildDir = "D:\libs\gmp_build",
    [string]$MSYS2Root = "C:\msys64",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# ANSI colors for output
$ColorReset = "`e[0m"
$ColorGreen = "`e[32m"
$ColorYellow = "`e[33m"
$ColorRed = "`e[31m"
$ColorCyan = "`e[36m"

function Write-Step {
    param([string]$Message)
    Write-Host "${ColorCyan}==>${ColorReset} ${Message}"
}

function Write-Success {
    param([string]$Message)
    Write-Host "${ColorGreen}✓${ColorReset} ${Message}"
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "${ColorRed}✗${ColorReset} ${Message}"
}

function Write-Warning-Custom {
    param([string]$Message)
    Write-Host "${ColorYellow}!${ColorReset} ${Message}"
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

Write-Host ""
Write-Host "${ColorGreen}========================================${ColorReset}"
Write-Host "${ColorGreen}  GMP Build Script for Windows (MinGW) ${ColorReset}"
Write-Host "${ColorGreen}========================================${ColorReset}"
Write-Host ""

Write-Step "Checking prerequisites..."

# Check MSYS2 installation
if (-not (Test-Path "$MSYS2Root\msys2_shell.cmd")) {
    Write-Error-Custom "MSYS2 not found at: $MSYS2Root"
    Write-Host ""
    Write-Host "Please install MSYS2:"
    Write-Host "  1. Download from: https://www.msys2.org/"
    Write-Host "  2. Install to: C:\msys64"
    Write-Host "  3. Run MSYS2 and execute:"
    Write-Host "       pacman -Syu"
    Write-Host "       pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make"
    exit 1
}
Write-Success "MSYS2 found at: $MSYS2Root"

# Check MinGW GCC
$mingwBin = "$MSYS2Root\mingw64\bin"
if (-not (Test-Path "$mingwBin\gcc.exe")) {
    Write-Error-Custom "MinGW GCC not found"
    Write-Host ""
    Write-Host "Install MinGW toolchain in MSYS2:"
    Write-Host "  pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make"
    exit 1
}
Write-Success "MinGW GCC found"

# ============================================================================
# Directory Setup
# ============================================================================

Write-Step "Setting up directories..."

if ($Clean) {
    if (Test-Path $BuildDir) {
        Remove-Item -Recurse -Force $BuildDir
        Write-Success "Cleaned build directory"
    }
}

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$SourceDir = Join-Path $BuildDir "gmp-$Version"
$TarballName = "gmp-${Version}.tar.xz"
$TarballPath = Join-Path $BuildDir $TarballName

# ============================================================================
# Download GMP Source
# ============================================================================

if (-not (Test-Path $TarballPath)) {
    Write-Step "Downloading GMP $Version..."
    
    $DownloadUrl = "https://gmplib.org/download/gmp/$TarballName"
    
    try {
        # Use alternative mirror if main site is slow
        $MirrorUrl = "https://ftp.gnu.org/gnu/gmp/$TarballName"
        
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TarballPath -UseBasicParsing
        Write-Success "Downloaded from gmplib.org"
    } catch {
        Write-Warning-Custom "Primary mirror failed, trying GNU mirror..."
        Invoke-WebRequest -Uri $MirrorUrl -OutFile $TarballPath -UseBasicParsing
        Write-Success "Downloaded from GNU mirror"
    }
} else {
    Write-Success "Tarball already exists: $TarballName"
}

# ============================================================================
# Extract Source
# ============================================================================

if (-not (Test-Path $SourceDir)) {
    Write-Step "Extracting GMP source..."
    
    # Use MSYS2 tar to extract
    $msysBash = "$MSYS2Root\usr\bin\bash.exe"
    
    $extractCmd = @"
cd '$($BuildDir -replace '\\', '/')' && tar -xf '$TarballName'
"@
    
    & $msysBash -lc $extractCmd
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Custom "Failed to extract tarball"
        exit 1
    }
    
    Write-Success "Extracted to: $SourceDir"
} else {
    Write-Success "Source directory exists"
}

# ============================================================================
# Configure and Build
# ============================================================================

Write-Step "Configuring GMP..."

# Convert Windows paths to MSYS2 paths
$msysSourceDir = $SourceDir -replace '\\', '/' -replace '^([A-Z]):', '/$1'
$msysInstallDir = $InstallDir -replace '\\', '/' -replace '^([A-Z]):', '/$1'

# GMP configure with C++ support
$configureCmd = @"
export PATH=/mingw64/bin:`$PATH
cd '$msysSourceDir'
./configure \
    --prefix='$msysInstallDir' \
    --enable-cxx \
    --enable-static \
    --disable-shared \
    --build=x86_64-w64-mingw32 \
    --host=x86_64-w64-mingw32
"@

Write-Host "Configuration command:"
Write-Host $configureCmd
Write-Host ""

$msysBash = "$MSYS2Root\usr\bin\bash.exe"
& $msysBash -lc $configureCmd

if ($LASTEXITCODE -ne 0) {
    Write-Error-Custom "Configure failed"
    exit 1
}

Write-Success "Configuration complete"

# Build
Write-Step "Building GMP (this may take 10-15 minutes)..."

$buildCmd = @"
export PATH=/mingw64/bin:`$PATH
cd '$msysSourceDir'
make -j`$(nproc)
"@

& $msysBash -lc $buildCmd

if ($LASTEXITCODE -ne 0) {
    Write-Error-Custom "Build failed"
    exit 1
}

Write-Success "Build complete"

# ============================================================================
# Install
# ============================================================================

Write-Step "Installing GMP to $InstallDir..."

$installCmd = @"
export PATH=/mingw64/bin:`$PATH
cd '$msysSourceDir'
make install
"@

& $msysBash -lc $installCmd

if ($LASTEXITCODE -ne 0) {
    Write-Error-Custom "Installation failed"
    exit 1
}

Write-Success "Installation complete"

# ============================================================================
# Verify Installation
# ============================================================================

Write-Step "Verifying installation..."

$libDir = Join-Path $InstallDir "lib"
$includeDir = Join-Path $InstallDir "include"

$requiredFiles = @(
    (Join-Path $libDir "libgmp.a"),
    (Join-Path $libDir "libgmpxx.a"),
    (Join-Path $includeDir "gmp.h"),
    (Join-Path $includeDir "gmpxx.h")
)

$allExist = $true
foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        $size = (Get-Item $file).Length
        Write-Success "Found: $(Split-Path -Leaf $file) ($([Math]::Round($size / 1KB, 2)) KB)"
    } else {
        Write-Error-Custom "Missing: $file"
        $allExist = $false
    }
}

if (-not $allExist) {
    Write-Error-Custom "Installation verification failed"
    exit 1
}

# ============================================================================
# Summary
# ============================================================================

Write-Host ""
Write-Host "${ColorGreen}========================================${ColorReset}"
Write-Host "${ColorGreen}  GMP Build Complete!${ColorReset}"
Write-Host "${ColorGreen}========================================${ColorReset}"
Write-Host ""
Write-Host "Installation directory: $InstallDir"
Write-Host ""
Write-Host "Libraries:"
Write-Host "  - libgmp.a   (C API)"
Write-Host "  - libgmpxx.a (C++ API)"
Write-Host ""
Write-Host "Headers:"
Write-Host "  - gmp.h      (C header)"
Write-Host "  - gmpxx.h    (C++ header)"
Write-Host ""
Write-Host "CMake usage:"
Write-Host "  cmake -DGMP_ROOT=$InstallDir ..."
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Build Microsoft SEAL: .\scripts\build_seal_mingw.ps1"
Write-Host "  2. Build HElib: .\scripts\build_helib.ps1"
Write-Host ""
