<#
.SYNOPSIS
    Automatic MSYS2 installation script for Windows (silent mode)
    
.DESCRIPTION
    Downloads MSYS2 installer and performs unattended installation to C:\msys64
    Configures MinGW-w64 toolchain, CMake, and development packages
    
.NOTES
    Author: kctsb Development Team
    Date: 2026-01-12
    Version: 1.0.0
#>

param(
    [string]$InstallPath = "C:\msys64",
    [string]$DownloadPath = "$env:TEMP\msys2-installer.exe",
    [switch]$UseMirror = $false
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "MSYS2 Automatic Installation Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if already installed
if (Test-Path "$InstallPath\msys2_shell.cmd") {
    Write-Host "[INFO] MSYS2 already installed at $InstallPath" -ForegroundColor Yellow
    Write-Host "[INFO] Skipping installation, will update packages..." -ForegroundColor Yellow
    $SkipInstall = $true
} else {
    $SkipInstall = $false
}

if (-not $SkipInstall) {
    # Step 1: Download MSYS2 installer
    Write-Host "[1/5] Downloading MSYS2 installer..." -ForegroundColor Green
    
    # Get latest version from official site (using known stable version)
    $MSYS2_VERSION = "20231026"  # Latest stable as of 2026-01
    $MSYS2_URL = "https://github.com/msys2/msys2-installer/releases/download/$MSYS2_VERSION/msys2-x86_64-$MSYS2_VERSION.exe"
    
    if ($UseMirror) {
        # Use Tsinghua mirror (faster in China)
        $MSYS2_URL = "https://mirrors.tuna.tsinghua.edu.cn/msys2/distrib/x86_64/msys2-x86_64-$MSYS2_VERSION.exe"
    }
    
    try {
        Write-Host "   Downloading from: $MSYS2_URL" -ForegroundColor Gray
        Invoke-WebRequest -Uri $MSYS2_URL -OutFile $DownloadPath -UseBasicParsing
        Write-Host "   [OK] Downloaded to: $DownloadPath" -ForegroundColor Green
    } catch {
        Write-Host "   [ERROR] Download failed: $_" -ForegroundColor Red
        Write-Host "   Trying alternative mirror..." -ForegroundColor Yellow
        
        # Fallback to GitHub
        $MSYS2_URL = "https://github.com/msys2/msys2-installer/releases/download/$MSYS2_VERSION/msys2-x86_64-$MSYS2_VERSION.exe"
        Invoke-WebRequest -Uri $MSYS2_URL -OutFile $DownloadPath -UseBasicParsing
        Write-Host "   [OK] Downloaded from GitHub" -ForegroundColor Green
    }
    
    # Step 2: Silent installation
    Write-Host ""
    Write-Host "[2/5] Installing MSYS2 to $InstallPath..." -ForegroundColor Green
    Write-Host "   This may take 2-5 minutes..." -ForegroundColor Gray
    
    # MSYS2 installer supports NSIS silent mode
    $InstallArgs = @(
        "/S",                          # Silent mode
        "/D=$InstallPath"              # Install directory (must be last)
    )
    
    $Process = Start-Process -FilePath $DownloadPath -ArgumentList $InstallArgs -Wait -PassThru
    
    if ($Process.ExitCode -eq 0) {
        Write-Host "   [OK] MSYS2 installed successfully" -ForegroundColor Green
    } else {
        Write-Host "   [ERROR] Installation failed with exit code: $($Process.ExitCode)" -ForegroundColor Red
        exit 1
    }
    
    # Cleanup installer
    Remove-Item $DownloadPath -Force
}

# Step 3: Update package database
Write-Host ""
Write-Host "[3/5] Updating MSYS2 package database..." -ForegroundColor Green

# Use MSYS2 bash to run pacman commands
$MSYS2_BASH = "$InstallPath\usr\bin\bash.exe"
$MSYS2_SHELL = "$InstallPath\msys2_shell.cmd"

if (-not (Test-Path $MSYS2_BASH)) {
    Write-Host "   [ERROR] MSYS2 bash not found at $MSYS2_BASH" -ForegroundColor Red
    exit 1
}

# First update (may require restart)
Write-Host "   Running pacman -Syu (first update)..." -ForegroundColor Gray
& $MSYS2_BASH -lc "pacman -Syu --noconfirm" 2>&1 | Out-Null

# Second update (complete the update)
Write-Host "   Running pacman -Su (second update)..." -ForegroundColor Gray
& $MSYS2_BASH -lc "pacman -Su --noconfirm" 2>&1 | Out-Null

Write-Host "   [OK] Package database updated" -ForegroundColor Green

# Step 4: Install development toolchain
Write-Host ""
Write-Host "[4/5] Installing MinGW-w64 toolchain and CMake..." -ForegroundColor Green

$PACKAGES = @(
    "mingw-w64-x86_64-gcc",          # GCC compiler
    "mingw-w64-x86_64-g++",          # C++ compiler
    "mingw-w64-x86_64-make",         # Make build tool
    "mingw-w64-x86_64-cmake",        # CMake
    "mingw-w64-x86_64-ninja",        # Ninja build system
    "base-devel",                     # Basic development tools
    "git",                            # Git version control
    "tar",                            # Archive tool
    "wget",                           # Download tool
    "unzip"                           # Unzip tool
)

foreach ($pkg in $PACKAGES) {
    Write-Host "   Installing $pkg..." -ForegroundColor Gray
    & $MSYS2_BASH -lc "pacman -S --noconfirm --needed $pkg" 2>&1 | Out-Null
}

Write-Host "   [OK] All packages installed" -ForegroundColor Green

# Step 5: Configure environment variables
Write-Host ""
Write-Host "[5/5] Configuring environment variables..." -ForegroundColor Green

# Add MSYS2 to PATH (user environment)
$MinGWPath = "$InstallPath\mingw64\bin"
$MSYS2Path = "$InstallPath\usr\bin"

$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")

if ($CurrentPath -notlike "*$MinGWPath*") {
    Write-Host "   Adding MinGW64 to PATH: $MinGWPath" -ForegroundColor Gray
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$MinGWPath;$CurrentPath",
        "User"
    )
}

if ($CurrentPath -notlike "*$MSYS2Path*") {
    Write-Host "   Adding MSYS2 to PATH: $MSYS2Path" -ForegroundColor Gray
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$MSYS2Path;$CurrentPath",
        "User"
    )
}

# Set MSYS2_ROOT environment variable
[Environment]::SetEnvironmentVariable("MSYS2_ROOT", $InstallPath, "User")
Write-Host "   Set MSYS2_ROOT=$InstallPath" -ForegroundColor Gray

# Refresh environment in current session
$env:Path = "$MinGWPath;$MSYS2Path;$env:Path"
$env:MSYS2_ROOT = $InstallPath

Write-Host "   [OK] Environment configured" -ForegroundColor Green

# Verification
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installation Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check GCC
try {
    $GccVersion = & "$MinGWPath\gcc.exe" --version 2>&1 | Select-Object -First 1
    Write-Host "[OK] GCC: $GccVersion" -ForegroundColor Green
} catch {
    Write-Host "[WARN] GCC not found in PATH (restart terminal)" -ForegroundColor Yellow
}

# Check CMake
try {
    $CmakeVersion = & "$MinGWPath\cmake.exe" --version 2>&1 | Select-Object -First 1
    Write-Host "[OK] CMake: $CmakeVersion" -ForegroundColor Green
} catch {
    Write-Host "[WARN] CMake not found in PATH (restart terminal)" -ForegroundColor Yellow
}

# Check Make
try {
    $MakeVersion = & "$MinGWPath\mingw32-make.exe" --version 2>&1 | Select-Object -First 1
    Write-Host "[OK] Make: $MakeVersion" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Make not found in PATH (restart terminal)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "MSYS2 Installation Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Installation Path: $InstallPath" -ForegroundColor White
Write-Host "MinGW64 Toolchain: $MinGWPath" -ForegroundColor White
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Restart PowerShell terminal to load new PATH" -ForegroundColor White
Write-Host "  2. Run: .\scripts\build_gmp.ps1" -ForegroundColor White
Write-Host "  3. Run: .\scripts\build_seal_mingw.ps1" -ForegroundColor White
Write-Host "  4. Run: .\scripts\build_helib.ps1" -ForegroundColor White
Write-Host ""
Write-Host "Verify installation:" -ForegroundColor Yellow
Write-Host "  gcc --version" -ForegroundColor White
Write-Host "  cmake --version" -ForegroundColor White
Write-Host "  mingw32-make --version" -ForegroundColor White
Write-Host ""
