<#
.SYNOPSIS
    Build HElib for kctsb with MinGW/MSYS2
.DESCRIPTION
    This script compiles HElib from source using MinGW toolchain.
    HElib requires GMP (with C++ support) and NTL.
    
    Prerequisites:
    - MSYS2 installed at C:\msys64
    - GMP with C++ support (gmpxx.h, libgmpxx.a)
    - NTL library compiled (libntl.a)
    
.PARAMETER InstallDir
    Installation directory (default: D:\libs\helib)
.PARAMETER HElibVersion
    HElib version/tag to build (default: v2.3.0)
    
.EXAMPLE
    .\build_helib.ps1
    .\build_helib.ps1 -InstallDir "C:\libs\helib"
    
.NOTES
    Author: knightc
    Date: 2026-01-12 (Beijing Time, UTC+8)
    Version: 1.0.0
    
    HElib GitHub: https://github.com/homenc/HElib
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "D:\libs\helib",
    [string]$HElibVersion = "v2.3.0",
    [string]$MSYS2Root = "C:\msys64",
    [string]$NTLRoot = "D:\pyproject\kctsb\deps\ntl",
    [string]$GMPRoot = "D:\libs\gmp"
)

$ErrorActionPreference = "Stop"

Write-Host "=== HElib $HElibVersion Build Script (MinGW) ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check prerequisites
Write-Host "[1/7] Checking prerequisites..." -ForegroundColor Yellow

if (-not (Test-Path $MSYS2Root)) {
    Write-Error "MSYS2 not found at $MSYS2Root. Please install MSYS2 first."
    exit 1
}

if (-not (Test-Path "$NTLRoot\lib\libntl.a")) {
    Write-Error "NTL library not found at $NTLRoot\lib\libntl.a. Build NTL first."
    exit 1
}

if (-not (Test-Path "$GMPRoot\lib\libgmp.a")) {
    Write-Error "GMP library not found at $GMPRoot\lib\libgmp.a"
    exit 1
}

$msysBash = "$MSYS2Root\usr\bin\bash.exe"
Write-Host "  ✓ MSYS2 found" -ForegroundColor Green
Write-Host "  ✓ NTL found: $NTLRoot" -ForegroundColor Green
Write-Host "  ✓ GMP found: $GMPRoot" -ForegroundColor Green

# Step 2: Create build directories
Write-Host "[2/7] Setting up build directories..." -ForegroundColor Yellow

$buildRoot = "$PSScriptRoot\..\build\helib"
$sourceDir = "$buildRoot\HElib"
$buildDir = "$buildRoot\build"

if (-not (Test-Path $buildRoot)) {
    New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
}

# Step 3: Clone HElib repository
Write-Host "[3/7] Cloning HElib repository..." -ForegroundColor Yellow

if (-not (Test-Path $sourceDir)) {
    git clone --depth 1 --branch $HElibVersion https://github.com/homenc/HElib.git $sourceDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to clone HElib repository"
        exit 1
    }
    Write-Host "  ✓ Cloned HElib $HElibVersion" -ForegroundColor Green
} else {
    Write-Host "  ✓ HElib source exists: $sourceDir" -ForegroundColor Green
}

# Step 4: Check GMP C++ support
Write-Host "[4/7] Checking GMP C++ support..." -ForegroundColor Yellow

if (-not (Test-Path "$GMPRoot\include\gmpxx.h")) {
    Write-Warning "GMP C++ header (gmpxx.h) not found!"
    Write-Host "  You may need to build full GMP with C++ support." -ForegroundColor Yellow
    Write-Host "  Run: .\scripts\build_gmp.ps1" -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "Continue anyway? (y/N)"
    if ($response -ne "y") {
        exit 1
    }
} else {
    Write-Host "  ✓ GMP C++ support found" -ForegroundColor Green
}

# Step 5: Configure with CMake
Write-Host "[5/7] Configuring HElib with MinGW CMake..." -ForegroundColor Yellow

$sourcePathMsys = $sourceDir -replace '\\', '/' -replace '^([A-Z]):', '/$1'
$buildPathMsys = $buildDir -replace '\\', '/' -replace '^([A-Z]):', '/$1'
$installPathMsys = $InstallDir -replace '\\', '/' -replace '^([A-Z]):', '/$1'
$ntlPathMsys = $NTLRoot -replace '\\', '/' -replace '^([A-Z]):', '/$1'
$gmpPathMsys = $GMPRoot -replace '\\', '/' -replace '^([A-Z]):', '/$1'

$cmakeCmd = @"
export PATH=/mingw64/bin:`$PATH
mkdir -p '$buildPathMsys'
cd '$buildPathMsys'
cmake -G "MinGW Makefiles" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX='$installPathMsys' \
    -DCMAKE_C_COMPILER=gcc \
    -DCMAKE_CXX_COMPILER=g++ \
    -DNTL_DIR='$ntlPathMsys' \
    -DGMP_DIR='$gmpPathMsys' \
    -DENABLE_THREADS=ON \
    -DENABLE_TEST=OFF \
    '$sourcePathMsys'
"@

Write-Host "  CMake command:" -ForegroundColor Gray
Write-Host $cmakeCmd -ForegroundColor DarkGray

& $msysBash -lc $cmakeCmd

if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake configuration failed"
    exit 1
}

Write-Host "  ✓ Configuration complete" -ForegroundColor Green

# Step 6: Build HElib
Write-Host "[6/7] Building HElib (may take 10-30 minutes)..." -ForegroundColor Yellow

$buildCmd = @"
export PATH=/mingw64/bin:`$PATH
cd '$buildPathMsys'
mingw32-make -j`$(nproc)
"@

& $msysBash -lc $buildCmd

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}

Write-Host "  ✓ Build complete" -ForegroundColor Green

# Step 7: Install HElib
Write-Host "[7/7] Installing HElib to $InstallDir..." -ForegroundColor Yellow

$installCmd = @"
export PATH=/mingw64/bin:`$PATH
cd '$buildPathMsys'
mingw32-make install
"@

& $msysBash -lc $installCmd

if ($LASTEXITCODE -ne 0) {
    Write-Error "Installation failed"
    exit 1
}

Write-Host "  ✓ Installation complete" -ForegroundColor Green

# Verify installation
Write-Host ""
Write-Host "=== Installation Summary ===" -ForegroundColor Cyan
Write-Host "  HElib version: $HElibVersion" -ForegroundColor White
Write-Host "  Install dir:   $InstallDir" -ForegroundColor White

if (Test-Path "$InstallDir\lib\libhelib.a") {
    $libSize = (Get-Item "$InstallDir\lib\libhelib.a").Length / 1MB
    Write-Host "  Library:       libhelib.a ($([math]::Round($libSize, 2)) MB)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Update kctsb CMakeLists.txt:" -ForegroundColor White
Write-Host "     set(HELIB_ROOT `"$InstallDir`")" -ForegroundColor Gray
Write-Host "  2. Reconfigure with -DKCTSB_ENABLE_HELIB=ON" -ForegroundColor White
Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Green
