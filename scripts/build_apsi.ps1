# ============================================================================
# Build Microsoft APSI for kctsb (Windows PowerShell)
# APSI - Asymmetric Private Set Intersection
# ============================================================================

param(
    [switch]$Clean,
    [string]$Generator
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$ProjectDir = Split-Path $ScriptDir -Parent
$ThirdpartyDir = Join-Path $ProjectDir "thirdparty"
$DepsDir = Join-Path $ProjectDir "deps"

$APSIVersion = "0.11.0"
$APSIUrl = "https://github.com/microsoft/APSI/archive/refs/tags/v${APSIVersion}.tar.gz"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Building Microsoft APSI ${APSIVersion}" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "NOTE: APSI has complex dependencies (SEAL, Kuku, FlatBuffers, etc.)" -ForegroundColor Yellow
Write-Host "Ensure the following are available in thirdparty/:" -ForegroundColor Yellow
Write-Host "  - Microsoft SEAL 4.1.2" -ForegroundColor Yellow
Write-Host "  - Kuku 2.1.0" -ForegroundColor Yellow
Write-Host "  - FlatBuffers" -ForegroundColor Yellow
Write-Host ""

# Create directories
New-Item -ItemType Directory -Force -Path $DepsDir | Out-Null
New-Item -ItemType Directory -Force -Path "$ThirdpartyDir\include" | Out-Null
New-Item -ItemType Directory -Force -Path "$ThirdpartyDir\lib" | Out-Null

Push-Location $DepsDir

try {
    $APSIDir = "APSI-${APSIVersion}"
    
    # Clean if requested
    if ($Clean -and (Test-Path $APSIDir)) {
        Write-Host "Cleaning previous build..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $APSIDir
    }
    
    # Download if not exists
    if (-not (Test-Path $APSIDir)) {
        Write-Host "Downloading APSI ${APSIVersion}..." -ForegroundColor Yellow
        $TarFile = "apsi-${APSIVersion}.tar.gz"
        Invoke-WebRequest -Uri $APSIUrl -OutFile $TarFile
        
        # Extract using tar
        tar -xzf $TarFile
        Remove-Item $TarFile
    }
    
    Push-Location $APSIDir
    
    # Determine generator
    $selectedGenerator = $null
    if ($Generator) {
        $selectedGenerator = $Generator
    } elseif (Get-Command ninja -ErrorAction SilentlyContinue) {
        $selectedGenerator = "Ninja"
    } else {
        $selectedGenerator = "MinGW Makefiles"
    }
    
    Write-Host "Using generator: $selectedGenerator" -ForegroundColor Green
    
    # Configure
    Write-Host "Configuring APSI..." -ForegroundColor Yellow
    
    $CMakeArgs = @(
        "-B", "build",
        "-G", $selectedGenerator,
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_INSTALL_PREFIX=$ThirdpartyDir",
        "-DCMAKE_PREFIX_PATH=$ThirdpartyDir",
        "-DAPSI_BUILD_TESTS=OFF",
        "-DAPSI_BUILD_CLI=OFF"
    )
    
    # Try to find SEAL
    $SEALDir = "$ThirdpartyDir\lib\cmake\SEAL-4.1"
    if (Test-Path $SEALDir) {
        $CMakeArgs += "-DSEAL_DIR=$SEALDir"
    }
    
    cmake @CMakeArgs
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed" }
    
    # Build
    Write-Host "Building APSI..." -ForegroundColor Yellow
    cmake --build build --parallel
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    
    # Install
    Write-Host "Installing APSI..." -ForegroundColor Yellow
    cmake --install build
    if ($LASTEXITCODE -ne 0) { throw "Install failed" }
    
    Write-Host "✓ APSI ${APSIVersion} installed to $ThirdpartyDir" -ForegroundColor Green
    
} finally {
    Pop-Location
    Pop-Location
}
