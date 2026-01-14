# ============================================================================
# Build Kuku 2.1 for kctsb (Windows PowerShell)
# Kuku is a simple library for Cuckoo hashing
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

$KukuVersion = "2.1.0"
$KukuUrl = "https://github.com/microsoft/Kuku/archive/refs/tags/v${KukuVersion}.tar.gz"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Building Kuku ${KukuVersion}" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Create directories
New-Item -ItemType Directory -Force -Path $DepsDir | Out-Null
New-Item -ItemType Directory -Force -Path "$ThirdpartyDir\include" | Out-Null
New-Item -ItemType Directory -Force -Path "$ThirdpartyDir\lib" | Out-Null

Push-Location $DepsDir

try {
    $KukuDir = "Kuku-${KukuVersion}"
    
    # Clean if requested
    if ($Clean -and (Test-Path $KukuDir)) {
        Write-Host "Cleaning previous build..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $KukuDir
    }
    
    # Download if not exists
    if (-not (Test-Path $KukuDir)) {
        Write-Host "Downloading Kuku ${KukuVersion}..." -ForegroundColor Yellow
        $TarFile = "kuku-${KukuVersion}.tar.gz"
        Invoke-WebRequest -Uri $KukuUrl -OutFile $TarFile
        
        # Extract using tar (available in Windows 10+)
        tar -xzf $TarFile
        Remove-Item $TarFile
    }
    
    Push-Location $KukuDir
    
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
    Write-Host "Configuring Kuku..." -ForegroundColor Yellow
    $CMakeArgs = @(
        "-B", "build",
        "-G", $selectedGenerator,
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_INSTALL_PREFIX=$ThirdpartyDir",
        "-DKUKU_BUILD_EXAMPLES=OFF",
        "-DKUKU_BUILD_TESTS=OFF"
    )
    
    cmake @CMakeArgs
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed" }
    
    # Build
    Write-Host "Building Kuku..." -ForegroundColor Yellow
    cmake --build build --parallel
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    
    # Install
    Write-Host "Installing Kuku..." -ForegroundColor Yellow
    cmake --install build
    if ($LASTEXITCODE -ne 0) { throw "Install failed" }
    
    Write-Host "✓ Kuku ${KukuVersion} installed to $ThirdpartyDir" -ForegroundColor Green
    
} finally {
    Pop-Location
    Pop-Location
}
