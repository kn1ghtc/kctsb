# NTL 11.6.0 Full Build Script for Windows (MinGW GCC)
# This script compiles all NTL source files with proper flags for Windows LLP64 model

$ErrorActionPreference = "Continue"

# Configuration
$GCC = "C:\Strawberry\c\bin\g++.exe"
$AR = "C:\Strawberry\c\bin\ar.exe"
$NTL_SRC = "D:\pyproject\kctsb\deps\ntl-11.6.0\src"
$NTL_BUILD = "D:\pyproject\kctsb\deps\ntl-build"
$NTL_INCLUDE = "D:\pyproject\kctsb\thirdparty\include"
$GMP_INCLUDE = "C:\Strawberry\c\include"
$OUTPUT_LIB = "D:\pyproject\kctsb\deps\ntl\lib\libntl.a"

# Compiler flags:
# -O2: Optimization level 2
# -std=c++14: Use C++14 standard
# -w: Suppress warnings (NTL has many)
# -fPIC: Position Independent Code
# -mssse3: Enable SSSE3 instructions (required for ChaCha20 PRNG in ZZ.cpp)
$CFLAGS = "-c -O2 -std=c++14 -w -fPIC -mssse3"

# Create build directory
if (-not (Test-Path $NTL_BUILD)) {
    New-Item -ItemType Directory -Force -Path $NTL_BUILD | Out-Null
}

# Get all source files
$srcFiles = Get-ChildItem -Path $NTL_SRC -Filter "*.cpp" | Sort-Object Name
$totalFiles = $srcFiles.Count
$compiled = 0
$failed = 0

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NTL 11.6.0 Build for Windows (MinGW)" -ForegroundColor Cyan
Write-Host "Total source files: $totalFiles" -ForegroundColor Cyan
Write-Host "Compiler flags: $CFLAGS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$failedFiles = @()

foreach ($srcFile in $srcFiles) {
    $baseName = $srcFile.BaseName
    $srcPath = $srcFile.FullName
    $objPath = Join-Path $NTL_BUILD "$baseName.o"
    
    Write-Host -NoNewline "[$($compiled + $failed + 1)/$totalFiles] Compiling $baseName... "
    
    $proc = Start-Process -FilePath $GCC -ArgumentList "$CFLAGS -I$NTL_INCLUDE -I$GMP_INCLUDE $srcPath -o $objPath" -NoNewWindow -Wait -PassThru -RedirectStandardError "NUL"
    
    if ($proc.ExitCode -eq 0 -and (Test-Path $objPath)) {
        $size = (Get-Item $objPath).Length
        Write-Host "OK ($([math]::Round($size/1024,1)) KB)" -ForegroundColor Green
        $compiled++
    } else {
        Write-Host "FAILED" -ForegroundColor Red
        $failed++
        $failedFiles += $baseName
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Compilation Summary:" -ForegroundColor Cyan
Write-Host "  Compiled: $compiled / $totalFiles" -ForegroundColor $(if ($compiled -eq $totalFiles) { "Green" } else { "Yellow" })
Write-Host "  Failed:   $failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })

if ($failed -gt 0) {
    Write-Host "Failed files:" -ForegroundColor Red
    foreach ($f in $failedFiles) {
        Write-Host "  - $f" -ForegroundColor Red
    }
}

# Create static library
if ($compiled -gt 0) {
    Write-Host ""
    Write-Host "Creating static library..." -ForegroundColor Cyan
    
    # Ensure lib directory exists
    $libDir = Split-Path $OUTPUT_LIB
    if (-not (Test-Path $libDir)) {
        New-Item -ItemType Directory -Force -Path $libDir | Out-Null
    }
    
    # Delete old library if exists
    if (Test-Path $OUTPUT_LIB) {
        Remove-Item $OUTPUT_LIB -Force
    }
    
    # Create library with all object files
    $objFiles = Get-ChildItem -Path $NTL_BUILD -Filter "*.o" | ForEach-Object { $_.FullName }
    $objList = $objFiles -join " "
    
    Push-Location $NTL_BUILD
    $arProc = Start-Process -FilePath $AR -ArgumentList "rcs $OUTPUT_LIB *.o" -NoNewWindow -Wait -PassThru
    Pop-Location
    
    if ($arProc.ExitCode -eq 0 -and (Test-Path $OUTPUT_LIB)) {
        $libSize = (Get-Item $OUTPUT_LIB).Length
        Write-Host "Library created: $OUTPUT_LIB ($([math]::Round($libSize/1024/1024,2)) MB)" -ForegroundColor Green
    } else {
        Write-Host "Failed to create library!" -ForegroundColor Red
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build completed." -ForegroundColor Cyan
