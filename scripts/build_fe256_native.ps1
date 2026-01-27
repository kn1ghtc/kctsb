# Build and test fe256 native ECC module
# Run from kctsb directory

$ErrorActionPreference = "Stop"

Write-Host "=== Building Fe256 Native ECC Test ===" -ForegroundColor Cyan

# Set up paths
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$kctsb = Split-Path -Parent $scriptDir
Set-Location $kctsb

# Compiler settings
$CXX = "C:/msys64/mingw64/bin/g++.exe"
$CXXFLAGS = @(
    "-std=c++17",
    "-O3",
    "-march=native",
    "-Wall",
    "-Wextra",
    "-I$kctsb/src/crypto/ecc"
)

$srcDir = "$kctsb/src/crypto/ecc"
$outDir = "$kctsb/build/bin"

# Create output directory
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

# Compile
Write-Host "Compiling fe256_native.cpp..." -ForegroundColor Yellow
$cmd = @(
    $CXX
) + $CXXFLAGS + @(
    "-c",
    "$srcDir/fe256_native.cpp",
    "-o", "$outDir/fe256_native.o"
)
& $cmd[0] $cmd[1..($cmd.Length-1)]
if ($LASTEXITCODE -ne 0) {
    Write-Host "Compilation of fe256_native.cpp failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Compiling test_fe256_native.cpp..." -ForegroundColor Yellow
$cmd = @(
    $CXX
) + $CXXFLAGS + @(
    "-c",
    "$srcDir/test_fe256_native.cpp",
    "-o", "$outDir/test_fe256_native.o"
)
& $cmd[0] $cmd[1..($cmd.Length-1)]
if ($LASTEXITCODE -ne 0) {
    Write-Host "Compilation of test_fe256_native.cpp failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Linking..." -ForegroundColor Yellow
$cmd = @(
    $CXX,
    "$outDir/fe256_native.o",
    "$outDir/test_fe256_native.o",
    "-o", "$outDir/test_fe256_native.exe"
)
& $cmd[0] $cmd[1..($cmd.Length-1)]
if ($LASTEXITCODE -ne 0) {
    Write-Host "Linking failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Build Successful ===" -ForegroundColor Green
Write-Host "Running test..." -ForegroundColor Cyan
Write-Host ""

# Run test
& "$outDir/test_fe256_native.exe"

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Green
