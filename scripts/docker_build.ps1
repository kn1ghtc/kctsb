# ============================================================================
# kctsb Docker Build Script for Windows (PowerShell)
# Version: 3.4.0
#
# Usage:
#   .\scripts\docker_build.ps1                    # Build Linux x64 release
#   .\scripts\docker_build.ps1 -Test              # Build and run tests
#   .\scripts\docker_build.ps1 -Clean             # Rebuild Docker image
#   .\scripts\docker_build.ps1 -Shell             # Enter container shell
#
# Prerequisites:
#   - Docker Desktop with WSL2 backend OR
#   - WSL2 with Docker Engine installed
# ============================================================================

param(
    [switch]$Clean,
    [switch]$Test,
    [switch]$Shell,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$ProjectDir = Split-Path $ScriptDir -Parent
$DockerDir = Join-Path $ProjectDir "docker"
$ReleaseDir = Join-Path $ProjectDir "release"

# Version and naming
$VERSION = "3.4.0"
$DOCKER_IMAGE = "kctsb-builder:centos7"
$PLATFORM_SUFFIX = "linux-x64"

# Convert Windows path to Linux path for Docker mount
function ConvertTo-LinuxPath {
    param([string]$WinPath)
    # Convert D:\pyproject\kctsb to /mnt/d/pyproject/kctsb
    $WinPath = $WinPath.Replace('\', '/')
    if ($WinPath -match '^([A-Za-z]):(.*)$') {
        return "/mnt/$($Matches[1].ToLower())$($Matches[2])"
    }
    return $WinPath
}

if ($Help) {
    Write-Host "Usage: .\scripts\docker_build.ps1 [options]" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Clean     Rebuild Docker image from scratch"
    Write-Host "  -Test      Run tests after build"
    Write-Host "  -Shell     Enter container shell for debugging"
    Write-Host "  -Help      Show this help"
    Write-Host ""
    Write-Host "Prerequisites:"
    Write-Host "  - Docker Desktop with WSL2 backend OR"
    Write-Host "  - WSL2 with Docker Engine installed"
    exit 0
}

Write-Host ""
Write-Host "          kctsb Docker Build (Linux x64)                   " -ForegroundColor Cyan
Write-Host ""
Write-Host "Version:    " -NoNewline; Write-Host $VERSION -ForegroundColor Green
Write-Host "Platform:   " -NoNewline; Write-Host $PLATFORM_SUFFIX -ForegroundColor Green
Write-Host "Image:      $DOCKER_IMAGE"
Write-Host ""

# Check Docker availability
$dockerCmd = $null
$useWsl = $false

# Try Docker Desktop first
if (Get-Command docker -ErrorAction SilentlyContinue) {
    try {
        $null = docker info 2>$null
        $dockerCmd = "docker"
        Write-Host "  Docker: Docker Desktop" -ForegroundColor Green
    } catch {
        Write-Host "  Docker Desktop not running, trying WSL..." -ForegroundColor Yellow
    }
}

# Try WSL2 Docker if Docker Desktop not available
if (-not $dockerCmd) {
    if (Get-Command wsl -ErrorAction SilentlyContinue) {
        $wslDocker = wsl docker info 2>$null
        if ($LASTEXITCODE -eq 0) {
            $dockerCmd = "wsl docker"
            $useWsl = $true
            Write-Host "  Docker: WSL2 Docker Engine" -ForegroundColor Green
        }
    }
}

if (-not $dockerCmd) {
    Write-Host "Error: Docker is not available. Please install Docker Desktop or Docker in WSL2." -ForegroundColor Red
    exit 1
}

# Convert paths for WSL
$LinuxProjectDir = if ($useWsl) { ConvertTo-LinuxPath $ProjectDir } else { $ProjectDir }
$LinuxDockerDir = if ($useWsl) { ConvertTo-LinuxPath $DockerDir } else { $DockerDir }

# Build Docker image if needed
$imageExists = $false
if ($useWsl) {
    $result = wsl docker image inspect $DOCKER_IMAGE 2>$null
    $imageExists = ($LASTEXITCODE -eq 0)
} else {
    try {
        $null = docker image inspect $DOCKER_IMAGE 2>$null
        $imageExists = $true
    } catch {
        $imageExists = $false
    }
}

if ($Clean -or (-not $imageExists)) {
    Write-Host "[1/4] Building Docker image..." -ForegroundColor Yellow
    
    if ($useWsl) {
        wsl docker build -t $DOCKER_IMAGE -f "$LinuxDockerDir/Dockerfile.centos7" $LinuxDockerDir
    } else {
        docker build -t $DOCKER_IMAGE -f "$DockerDir\Dockerfile.centos7" $DockerDir
    }
    
    if ($LASTEXITCODE -ne 0) { throw "Docker build failed" }
    Write-Host "  Docker image built" -ForegroundColor Green
} else {
    Write-Host "[1/4] Docker image exists, skipping build" -ForegroundColor Yellow
}

# Enter shell mode if requested
if ($Shell) {
    Write-Host "Entering container shell..." -ForegroundColor Yellow
    if ($useWsl) {
        wsl docker run -it --rm -v "${LinuxProjectDir}:/workspace" -w /workspace $DOCKER_IMAGE bash
    } else {
        docker run -it --rm -v "${ProjectDir}:/workspace" -w /workspace $DOCKER_IMAGE bash
    }
    exit 0
}

# Build command
$BuildCmd = @"
cd /workspace && \
rm -rf build-linux && \
mkdir -p build-linux && \
cd build-linux && \
cmake .. -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DKCTSB_BUILD_TESTS=ON \
    -DKCTSB_BUILD_EXAMPLES=ON \
    -DKCTSB_BUILD_BENCHMARKS=OFF \
    -DCMAKE_CXX_FLAGS='-O3 -march=x86-64 -mtune=generic -ffast-math -funroll-loops -fomit-frame-pointer -flto -fno-rtti -fPIC' && \
cmake --build . --parallel 4
"@

if ($Test) {
    $BuildCmd += " && ctest --output-on-failure --parallel 4"
}

# Run build
Write-Host "[2/4] Building kctsb in container..." -ForegroundColor Yellow

if ($useWsl) {
    wsl docker run --rm -v "${LinuxProjectDir}:/workspace" -w /workspace $DOCKER_IMAGE bash -c $BuildCmd
} else {
    docker run --rm -v "${ProjectDir}:/workspace" -w /workspace $DOCKER_IMAGE bash -c $BuildCmd
}

if ($LASTEXITCODE -ne 0) { throw "Build failed" }
Write-Host "  Build completed" -ForegroundColor Green

# Copy release artifacts
Write-Host "[3/4] Copying release artifacts..." -ForegroundColor Yellow

$ReleasePlatformDir = Join-Path $ReleaseDir $PLATFORM_SUFFIX
$releaseBin = Join-Path $ReleasePlatformDir "bin"
$releaseLib = Join-Path $ReleasePlatformDir "lib"
$releaseInclude = Join-Path $ReleasePlatformDir "include"

@($releaseBin, $releaseLib, $releaseInclude) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ | Out-Null
    }
}

# Copy binaries
$kctsb = Join-Path $ProjectDir "build-linux\bin\kctsb"
if (Test-Path $kctsb) {
    Copy-Item $kctsb (Join-Path $releaseBin "kctsb")
    Copy-Item $kctsb (Join-Path $releaseBin "kctsb-$PLATFORM_SUFFIX")
    Write-Host "  Copied kctsb executable" -ForegroundColor Green
}

# Copy static library
$staticLib = Join-Path $ProjectDir "build-linux\lib\libkctsb.a"
if (Test-Path $staticLib) {
    Copy-Item $staticLib (Join-Path $releaseLib "libkctsb.a")
    Copy-Item $staticLib (Join-Path $releaseLib "libkctsb-$PLATFORM_SUFFIX.a")
    Write-Host "  Copied static library" -ForegroundColor Green
}

# Copy shared libraries
Get-ChildItem (Join-Path $ProjectDir "build-linux\lib\libkctsb.so*") -ErrorAction SilentlyContinue | ForEach-Object {
    Copy-Item $_.FullName $releaseLib
    Write-Host "  Copied $($_.Name)" -ForegroundColor Green
}

# Copy headers
$includeDir = Join-Path $ProjectDir "include"
if (Test-Path $includeDir) {
    Copy-Item (Join-Path $includeDir "kctsb") $releaseInclude -Recurse -Force
    Write-Host "  Copied headers" -ForegroundColor Green
}

# Generate release info
Write-Host "[4/4] Generating release info..." -ForegroundColor Yellow

$releaseInfo = @"
kctsb Release Information
==========================
Version: $VERSION
Platform: Linux x64 ($PLATFORM_SUFFIX)
Build Type: Release
Build Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
Compiler: GCC 11 (devtoolset-11)
glibc: 2.17 (CentOS 7 - minimum requirement)

Contents:
- bin/kctsb              : Command-line tool
- lib/libkctsb.a         : Static library
- lib/libkctsb.so*       : Shared library
- include/kctsb/         : Header files

Platform-specific binaries (with suffix):
- *-$PLATFORM_SUFFIX.*

Compatibility:
- CentOS 7+ / RHEL 7+
- Ubuntu 18.04+ / Debian 9+
- Most Linux distributions with glibc >= 2.17

License: Apache License 2.0
Repository: https://github.com/kn1ghtc/kctsb
"@

Set-Content -Path (Join-Path $ReleasePlatformDir "RELEASE_INFO.txt") -Value $releaseInfo
Write-Host "  Release info generated" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "           Linux build completed successfully!             " -ForegroundColor Green
Write-Host ""
Write-Host "Release dir:  $ReleasePlatformDir"
Write-Host ""
Write-Host "Release contents:" -ForegroundColor Cyan
Get-ChildItem $releaseBin -ErrorAction SilentlyContinue | Format-Table Name, Length
Get-ChildItem $releaseLib -ErrorAction SilentlyContinue | Format-Table Name, Length
Write-Host ""
Write-Host "Quick verification (run in WSL or Linux):" -ForegroundColor Cyan
Write-Host "  file $ReleasePlatformDir/bin/kctsb"
Write-Host "  ldd $ReleasePlatformDir/bin/kctsb"
