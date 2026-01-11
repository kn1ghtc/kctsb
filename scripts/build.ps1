# ============================================================================
# kctsb Build Script for Windows (PowerShell)
# ============================================================================

param(
    [string]$BuildType = "Release",
    [switch]$Clean,
    [switch]$Test,
    [switch]$Install,
    [string]$InstallDir = "$PSScriptRoot\install"
)

$ErrorActionPreference = "Stop"
$BuildDir = "$PSScriptRoot\build"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   kctsb Build Script" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Build Type: $BuildType"
Write-Host "Build Directory: $BuildDir"
Write-Host ""

# Clean build
if ($Clean) {
    Write-Host "Cleaning build directory..." -ForegroundColor Yellow
    if (Test-Path $BuildDir) {
        Remove-Item -Recurse -Force $BuildDir
    }
}

# Create build directory
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

# Configure
Write-Host "Configuring with CMake..." -ForegroundColor Green
Push-Location $BuildDir

$CMakeArgs = @(
    "..",
    "-G", "MinGW Makefiles",
    "-DCMAKE_BUILD_TYPE=$BuildType",
    "-DKCTSB_BUILD_TESTS=ON",
    "-DKCTSB_BUILD_EXAMPLES=ON"
)

if ($Install) {
    $CMakeArgs += "-DCMAKE_INSTALL_PREFIX=$InstallDir"
}

cmake @CMakeArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "CMake configuration failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}

# Build
Write-Host "Building..." -ForegroundColor Green
cmake --build . --parallel

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}

# Test
if ($Test) {
    Write-Host "Running tests..." -ForegroundColor Green
    ctest --output-on-failure
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Some tests failed!" -ForegroundColor Yellow
    }
}

# Install
if ($Install) {
    Write-Host "Installing to $InstallDir..." -ForegroundColor Green
    cmake --install .
}

Pop-Location

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   Build completed successfully!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Build outputs are in: $BuildDir"
Write-Host "  Libraries: $BuildDir\lib"
Write-Host "  Binaries: $BuildDir\bin"
