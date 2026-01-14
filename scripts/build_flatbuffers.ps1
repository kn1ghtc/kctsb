# ============================================================================
# Build FlatBuffers for kctsb (Windows PowerShell)
# FlatBuffers is an efficient cross-platform serialization library
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

$FlatbuffersVersion = "24.3.25"
$FlatbuffersUrl = "https://github.com/google/flatbuffers/archive/refs/tags/v${FlatbuffersVersion}.tar.gz"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Building FlatBuffers ${FlatbuffersVersion}" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Create directories
New-Item -ItemType Directory -Force -Path $DepsDir | Out-Null
New-Item -ItemType Directory -Force -Path "$ThirdpartyDir\include" | Out-Null
New-Item -ItemType Directory -Force -Path "$ThirdpartyDir\lib" | Out-Null

Push-Location $DepsDir

try {
    $FlatbuffersDir = "flatbuffers-${FlatbuffersVersion}"
    
    # Clean if requested
    if ($Clean -and (Test-Path $FlatbuffersDir)) {
        Write-Host "Cleaning previous build..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $FlatbuffersDir
    }
    
    # Download if not exists
    if (-not (Test-Path $FlatbuffersDir)) {
        Write-Host "Downloading FlatBuffers ${FlatbuffersVersion}..." -ForegroundColor Yellow
        $TarFile = "flatbuffers-${FlatbuffersVersion}.tar.gz"
        Invoke-WebRequest -Uri $FlatbuffersUrl -OutFile $TarFile
        
        # Extract using tar
        tar -xzf $TarFile
        Remove-Item $TarFile
    }
    
    Push-Location $FlatbuffersDir
    
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
    Write-Host "Configuring FlatBuffers..." -ForegroundColor Yellow
    $CMakeArgs = @(
        "-B", "build",
        "-G", $selectedGenerator,
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_INSTALL_PREFIX=$ThirdpartyDir",
        "-DFLATBUFFERS_BUILD_TESTS=OFF",
        "-DFLATBUFFERS_BUILD_FLATC=ON",
        "-DFLATBUFFERS_BUILD_FLATHASH=OFF",
        "-DFLATBUFFERS_STRICT_MODE=OFF"
    )
    
    cmake @CMakeArgs
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed" }
    
    # Build
    Write-Host "Building FlatBuffers..." -ForegroundColor Yellow
    cmake --build build --parallel
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    
    # Install
    Write-Host "Installing FlatBuffers..." -ForegroundColor Yellow
    cmake --install build
    if ($LASTEXITCODE -ne 0) { throw "Install failed" }
    
    Write-Host "✓ FlatBuffers ${FlatbuffersVersion} installed to $ThirdpartyDir" -ForegroundColor Green
    
} finally {
    Pop-Location
    Pop-Location
}
