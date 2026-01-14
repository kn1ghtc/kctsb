<#
.SYNOPSIS
    Build Microsoft SEAL 4.1.2 with MinGW/MSYS2 for kctsb
.DESCRIPTION
    This script compiles Microsoft SEAL from source using MinGW toolchain
    to avoid MSVC/MinGW mixed linking issues (__security_cookie symbols).
    
    Prerequisites:
    - MSYS2 installed at C:\msys64 (or adjust $MSYS2_ROOT)
    - MinGW-w64 GCC toolchain in MSYS2
    - CMake available in MSYS2
    
.PARAMETER InstallDir
    Installation directory (default: D:\libs\seal)
.PARAMETER SealVersion
    SEAL version to build (default: 4.1.2)
    
.EXAMPLE
    .\build_seal_mingw.ps1
    .\build_seal_mingw.ps1 -InstallDir "C:\libs\seal" -SealVersion "4.1.1"
    
.NOTES
    Author: knightc
    Date: 2026-01-12 (Beijing Time, UTC+8)
    Version: 1.0.0
    
    SEAL GitHub: https://github.com/microsoft/SEAL
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "D:\libs\seal",
    [string]$SealVersion = "4.1.2",
    [string]$MSYS2Root = "C:\msys64"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Microsoft SEAL $SealVersion Build Script (MinGW) ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check prerequisites
Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Yellow

if (-not (Test-Path $MSYS2Root)) {
    Write-Error "MSYS2 not found at $MSYS2Root. Please install MSYS2 first."
    exit 1
}

$msysBash = "$MSYS2Root\usr\bin\bash.exe"
if (-not (Test-Path $msysBash)) {
    Write-Error "MSYS2 bash not found at $msysBash"
    exit 1
}

Write-Host "  ✓ MSYS2 found at: $MSYS2Root" -ForegroundColor Green

# Step 2: Create build directories
Write-Host "[2/6] Setting up build directories..." -ForegroundColor Yellow

$buildRoot = "$PSScriptRoot\..\build\seal"
$sourceDir = "$buildRoot\SEAL-$SealVersion"
$buildDir = "$buildRoot\build"

if (-not (Test-Path $buildRoot)) {
    New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
}

Write-Host "  Build root: $buildRoot" -ForegroundColor Gray

# Step 3: Download SEAL source
Write-Host "[3/6] Downloading SEAL $SealVersion source..." -ForegroundColor Yellow

$sealUrl = "https://github.com/microsoft/SEAL/archive/refs/tags/v$SealVersion.tar.gz"
$tarFile = "$buildRoot\SEAL-$SealVersion.tar.gz"

if (-not (Test-Path $sourceDir)) {
    if (-not (Test-Path $tarFile)) {
        Write-Host "  Downloading from $sealUrl..." -ForegroundColor Gray
        try {
            Invoke-WebRequest -Uri $sealUrl -OutFile $tarFile -UseBasicParsing
            Write-Host "  ✓ Downloaded: $tarFile" -ForegroundColor Green
        } catch {
            Write-Error "Failed to download SEAL: $_"
            exit 1
        }
    }
    
    Write-Host "  Extracting source..." -ForegroundColor Gray
    tar -xzf $tarFile -C $buildRoot
    Write-Host "  ✓ Extracted to: $sourceDir" -ForegroundColor Green
} else {
    Write-Host "  ✓ Source already exists: $sourceDir" -ForegroundColor Green
}

# Step 4: Configure with CMake (using MSYS2 MinGW)
Write-Host "[4/6] Configuring SEAL with MinGW CMake..." -ForegroundColor Yellow

# Convert Windows paths to MSYS2 paths
$sourcePathMsys = $sourceDir -replace '\\', '/' -replace '^([A-Z]):', '/$1'
$buildPathMsys = $buildDir -replace '\\', '/' -replace '^([A-Z]):', '/$1'
$installPathMsys = $InstallDir -replace '\\', '/' -replace '^([A-Z]):', '/$1'

$cmakeCmd = @"
export PATH=/mingw64/bin:`$PATH
mkdir -p '$buildPathMsys'
cd '$buildPathMsys'
/mingw64/bin/cmake -G 'Unix Makefiles' \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX='$installPathMsys' \
    -DCMAKE_C_COMPILER=/mingw64/bin/gcc \
    -DCMAKE_CXX_COMPILER=/mingw64/bin/g++ \
    -DSEAL_USE_INTEL_HEXL=OFF \
    -DSEAL_USE_MSGSL=OFF \
    -DSEAL_USE_ZLIB=OFF \
    -DSEAL_USE_ZSTD=OFF \
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

# Step 5: Build SEAL
Write-Host "[5/6] Building SEAL (this may take several minutes)..." -ForegroundColor Yellow

$buildCmd = @"
export PATH=/mingw64/bin:`$PATH
cd '$buildPathMsys'
make -j`$(nproc)
"@

& $msysBash -lc $buildCmd

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}

Write-Host "  ✓ Build complete" -ForegroundColor Green

# Step 6: Install SEAL
Write-Host "[6/6] Installing SEAL to $InstallDir..." -ForegroundColor Yellow

$installCmd = @"
export PATH=/mingw64/bin:`$PATH
cd '$buildPathMsys'
make install
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
Write-Host "  SEAL version: $SealVersion" -ForegroundColor White
Write-Host "  Install dir:  $InstallDir" -ForegroundColor White

if (Test-Path "$InstallDir\lib\libseal-4.1.a") {
    $libSize = (Get-Item "$InstallDir\lib\libseal-4.1.a").Length / 1MB
    Write-Host "  Library:      libseal-4.1.a ($([math]::Round($libSize, 2)) MB)" -ForegroundColor Green
} elseif (Test-Path "$InstallDir\lib\libseal.a") {
    $libSize = (Get-Item "$InstallDir\lib\libseal.a").Length / 1MB
    Write-Host "  Library:      libseal.a ($([math]::Round($libSize, 2)) MB)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Update kctsb CMakeLists.txt to find SEAL:" -ForegroundColor White
Write-Host "     set(SEAL_ROOT `"$InstallDir`")" -ForegroundColor Gray
Write-Host "  2. Reconfigure kctsb with -DKCTSB_ENABLE_SEAL=ON" -ForegroundColor White
Write-Host "  3. Build kctsb with SEAL support" -ForegroundColor White
Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Green
