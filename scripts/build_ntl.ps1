#!/usr/bin/env pwsh
# =============================================================================
# NTL (Number Theory Library) Windows Build Script
# 
# Compiles NTL 11.6.0 static library using MinGW-w64 GCC
# Only compiles core library files, excludes tests and check programs
#
# Usage: .\scripts\build_ntl.ps1 [-Clean] [-Verbose]
#
# Author: knightc
# Date: 2026-01-12
# =============================================================================

param(
    [switch]$Clean,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Path configuration
$ProjectRoot = "D:\pyproject\kctsb"
$NtlSrcDir = "$ProjectRoot\deps\ntl-11.6.0\src"
$NtlIncDir = "$ProjectRoot\thirdparty\include"
$BuildDir = "$ProjectRoot\deps\ntl-build"
$InstallDir = "$ProjectRoot\deps\ntl"
$GmpInclude = "C:\Strawberry\c\include"
$GmpLib = "C:\Strawberry\c\lib"

# Compiler configuration
$CXX = "g++"
$AR = "ar"
# Note: NTL_THREADS is defined in config.h, do not re-define here
$CXXFLAGS = "-O2 -std=c++17 -Wall -fPIC -I`"$NtlIncDir`" -I`"$GmpInclude`""

# Core modules list (excluding tests, checks, timing files)
$CoreModules = @(
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

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NTL 11.6.0 Build Script for Windows (MinGW-w64)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  NTL Source: $NtlSrcDir"
Write-Host "  Headers:    $NtlIncDir"
Write-Host "  Build Dir:  $BuildDir"
Write-Host "  Install:    $InstallDir"
Write-Host "  GMP:        $GmpInclude"
Write-Host ""

# Verify directories
if (-not (Test-Path $NtlSrcDir)) {
    Write-Error "NTL source directory not found: $NtlSrcDir"
    exit 1
}
if (-not (Test-Path "$NtlIncDir\NTL\config.h")) {
    Write-Error "NTL config.h not found: $NtlIncDir\NTL\config.h"
    exit 1
}
if (-not (Test-Path "$GmpInclude\gmp.h")) {
    Write-Error "GMP header not found: $GmpInclude\gmp.h"
    exit 1
}

# Clean
if ($Clean) {
    Write-Host "Cleaning build directories..." -ForegroundColor Yellow
    if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
    if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
}

# Create directories
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\lib" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\include" | Out-Null

$TotalFiles = $CoreModules.Count
Write-Host "Compiling $TotalFiles core modules..." -ForegroundColor Green
Write-Host ""

# Compile source files
$ObjFiles = @()
$CompileErrors = 0
$Counter = 0

foreach ($Module in $CoreModules) {
    $Counter++
    $SrcFile = "$NtlSrcDir\$Module.cpp"
    $ObjFile = "$BuildDir\$Module.o"
    
    if (-not (Test-Path $SrcFile)) {
        Write-Host "[$Counter/$TotalFiles] Skip: $Module (not found)" -ForegroundColor DarkGray
        continue
    }
    
    $ObjFiles += $ObjFile
    
    # Check if recompile needed
    if ((Test-Path $ObjFile) -and (-not $Clean)) {
        Write-Host "[$Counter/$TotalFiles] Skip: $Module (cached)" -ForegroundColor DarkGray
        continue
    }
    
    Write-Host "[$Counter/$TotalFiles] Compile: $Module" -ForegroundColor White
    
    # Use Start-Process to avoid PowerShell treating stderr as exception
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $CXX
    $pinfo.Arguments = "$CXXFLAGS -c `"$SrcFile`" -o `"$ObjFile`""
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $pinfo
    $process.Start() | Out-Null
    $stderr = $process.StandardError.ReadToEnd()
    $stdout = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()
    
    if ($process.ExitCode -ne 0) {
        Write-Host "  Failed: $Module" -ForegroundColor Red
        if ($Verbose -and $stderr) { 
            $stderr -split "`n" | Select-Object -First 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkRed }
        }
        $CompileErrors++
    } elseif ($stderr -match "warning:") {
        Write-Host "  OK (warnings): $Module" -ForegroundColor Yellow
    }
}

if ($CompileErrors -gt 0) {
    Write-Host ""
    Write-Host "$CompileErrors files failed to compile!" -ForegroundColor Red
    Write-Host "Continuing with available modules..." -ForegroundColor Yellow
}

# Get actual compiled .o files
$ActualObjFiles = Get-ChildItem -Path $BuildDir -Filter "*.o" | ForEach-Object { $_.FullName }
$ObjCount = $ActualObjFiles.Count

if ($ObjCount -eq 0) {
    Write-Error "No object files created!"
    exit 1
}

Write-Host ""
Write-Host "$ObjCount modules compiled successfully!" -ForegroundColor Green

# Create static library
Write-Host ""
Write-Host "Creating static library libntl.a..." -ForegroundColor Yellow

$LibFile = "$InstallDir\lib\libntl.a"

try {
    Push-Location $BuildDir
    $ObjNames = Get-ChildItem -Filter "*.o" | ForEach-Object { $_.Name }
    & $AR rcs $LibFile $ObjNames 2>&1 | Out-Null
    Pop-Location
    
    if (Test-Path $LibFile) {
        $LibSize = [math]::Round((Get-Item $LibFile).Length / 1MB, 2)
        Write-Host "Library created: $LibFile ($LibSize MB)" -ForegroundColor Green
    }
    else {
        Write-Error "Failed to create library"
        exit 1
    }
}
catch {
    Write-Host "Archive error: $_" -ForegroundColor Red
    exit 1
}

# Copy headers
Write-Host ""
Write-Host "Copying headers..." -ForegroundColor Yellow
Copy-Item -Path "$NtlIncDir\NTL" -Destination "$InstallDir\include\" -Recurse -Force
$HeaderCount = (Get-ChildItem "$InstallDir\include\NTL\*.h").Count
Write-Host "$HeaderCount headers copied" -ForegroundColor Green

# Done
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  NTL Build Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Installation:" -ForegroundColor Yellow
Write-Host "  Headers: $InstallDir\include\NTL\"
Write-Host "  Library: $LibFile"
Write-Host ""
Write-Host "CMake usage:" -ForegroundColor Yellow
Write-Host "  cmake -DNTL_ROOT=`"$InstallDir`" ..."
Write-Host ""
