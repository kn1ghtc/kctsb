# Build GMP 6.3.0 with C++ support for kctsb
# This script compiles GMP from source using MinGW-w64/GCC

$ErrorActionPreference = "Stop"

$GMP_VERSION = "6.3.0"
$GMP_SRC_DIR = "D:\pyproject\kctsb\deps\gmp-$GMP_VERSION"
$GMP_BUILD_DIR = "D:\pyproject\kctsb\deps\gmp-build"
$GMP_INSTALL_DIR = "D:\pyproject\kctsb\deps\gmp"
$GCC = "C:\Strawberry\c\bin\gcc.exe"
$GPP = "C:\Strawberry\c\bin\g++.exe"
$AR = "C:\Strawberry\c\bin\ar.exe"

Write-Host "=== Building GMP $GMP_VERSION with C++ support ===" -ForegroundColor Cyan

# Check GMP source
if (-not (Test-Path $GMP_SRC_DIR)) {
    Write-Error "GMP source not found at $GMP_SRC_DIR"
    exit 1
}

# Create build directories
New-Item -ItemType Directory -Path $GMP_BUILD_DIR -Force | Out-Null
New-Item -ItemType Directory -Path "$GMP_INSTALL_DIR\include" -Force | Out-Null
New-Item -ItemType Directory -Path "$GMP_INSTALL_DIR\lib" -Force | Out-Null

# Copy header files
Write-Host "Copying GMP header files..." -ForegroundColor Green
Copy-Item "$GMP_SRC_DIR\gmp-h.in" "$GMP_INSTALL_DIR\include\gmp.h" -Force
Copy-Item "$GMP_SRC_DIR\gmpxx.h" "$GMP_INSTALL_DIR\include\gmpxx.h" -Force

# Manual configuration for Windows
# We need to create config.h manually since configure requires MSYS2/Cygwin
$config_h = @"
/* config.h - Manual configuration for Windows MinGW-w64 */
#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
#define SIZEOF_UNSIGNED 4
#define SIZEOF_UNSIGNED_LONG 4
#define SIZEOF_UNSIGNED_LONG_LONG 8
#define SIZEOF_MP_LIMB_T 8
#define GMP_LIMB_BITS 64
#define GMP_NAIL_BITS 0
#define BITS_PER_MP_LIMB 64
#define BYTES_PER_MP_LIMB 8
#define HAVE_NATIVE_mpn_add_n 1
#define HAVE_NATIVE_mpn_sub_n 1
"@

Set-Content -Path "$GMP_BUILD_DIR\config.h" -Value $config_h

# Update gmp.h with proper defines
(Get-Content "$GMP_INSTALL_DIR\include\gmp.h") `
    -replace '@VERSION@', $GMP_VERSION `
    -replace '@GMP_LIMB_BITS@', '64' `
    -replace '@GMP_NAIL_BITS@', '0' `
    -replace '@DEFN_LONG_LONG_LIMB@', '#define _LONG_LONG_LIMB 1' `
    | Set-Content "$GMP_INSTALL_DIR\include\gmp.h"

Write-Host "Building GMP C library..." -ForegroundColor Green

# Compile essential GMP C sources
$gmp_c_sources = @(
    "assert.c", "compat.c", "errno.c", "extract-dbl.c", "invalid.c",
    "memory.c", "mp_bpl.c", "mp_clz_tab.c", "mp_dv_tab.c", 
    "mp_get_fns.c", "mp_minv_tab.c", "mp_set_fns.c", "nextprime.c",
    "primesieve.c", "tal-reent.c", "version.c"
)

# Compile mpz sources
$mpz_sources = Get-ChildItem "$GMP_SRC_DIR\mpz" -Filter "*.c" | Select-Object -ExpandProperty Name

# Compile mpq sources
$mpq_sources = Get-ChildItem "$GMP_SRC_DIR\mpq" -Filter "*.c" | Select-Object -ExpandProperty Name

# Compile mpf sources
$mpf_sources = Get-ChildItem "$GMP_SRC_DIR\mpf" -Filter "*.c" | Select-Object -ExpandProperty Name

# Compile all C sources
$all_c_files = @()
foreach ($src in $gmp_c_sources) {
    $all_c_files += "$GMP_SRC_DIR\$src"
}
foreach ($src in $mpz_sources) {
    $all_c_files += "$GMP_SRC_DIR\mpz\$src"
}
foreach ($src in $mpq_sources) {
    $all_c_files += "$GMP_SRC_DIR\mpq\$src"
}
foreach ($src in $mpf_sources) {
    $all_c_files += "$GMP_SRC_DIR\mpf\$src"
}

$compiled = 0
$total = $all_c_files.Count
foreach ($src_file in $all_c_files) {
    $compiled++
    $obj_name = [System.IO.Path]::GetFileNameWithoutExtension($src_file) + ".o"
    $obj_path = Join-Path $GMP_BUILD_DIR $obj_name
    
    Write-Progress -Activity "Compiling GMP C library" -Status "$compiled/$total" -PercentComplete (($compiled/$total)*100)
    
    & $GCC -c -O2 -fPIC -I"$GMP_SRC_DIR" -I"$GMP_BUILD_DIR" -I"$GMP_INSTALL_DIR\include" `
        -DHAVE_CONFIG_H -D__GMP_WITHIN_GMP `
        "$src_file" -o "$obj_path" 2>&1 | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to compile $src_file"
    }
}

Write-Host "Building GMP C++ library..." -ForegroundColor Green

# Compile GMP C++ sources
$cxx_sources = Get-ChildItem "$GMP_SRC_DIR\cxx" -Filter "*.cc" | Select-Object -ExpandProperty Name

$cxx_compiled = 0
$cxx_total = $cxx_sources.Count
foreach ($src in $cxx_sources) {
    $cxx_compiled++
    $obj_name = [System.IO.Path]::GetFileNameWithoutExtension($src) + ".o"
    $obj_path = Join-Path $GMP_BUILD_DIR $obj_name
    
    Write-Progress -Activity "Compiling GMP C++ library" -Status "$cxx_compiled/$cxx_total" -PercentComplete (($cxx_compiled/$cxx_total)*100)
    
    & $GPP -c -O2 -std=c++17 -fPIC -I"$GMP_SRC_DIR" -I"$GMP_BUILD_DIR" -I"$GMP_INSTALL_DIR\include" `
        -DHAVE_CONFIG_H -D__GMP_WITHIN_GMP -D__GMP_WITHIN_GMPXX `
        "$GMP_SRC_DIR\cxx\$src" -o "$obj_path" 2>&1 | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to compile cxx/$src"
    }
}

Write-Host "Creating static libraries..." -ForegroundColor Green

# Create libgmp.a (C library)
$c_objects = Get-ChildItem $GMP_BUILD_DIR -Filter "*.o" -Exclude "*osfuns.o", "*osinfmt.o", "*osfdiv.o" | Where-Object { $_.Name -notmatch "^(isfuns|infmt|fdiv)" } | Select-Object -ExpandProperty FullName
& $AR rcs "$GMP_INSTALL_DIR\lib\libgmp.a" $c_objects

# Create libgmpxx.a (C++ library)
$cxx_objects = Get-ChildItem $GMP_BUILD_DIR -Filter "*.o" | Where-Object { $_.Name -match "osfuns|osinfmt|osfdiv|isfuns|infmt|fdiv" } | Select-Object -ExpandProperty FullName
if ($cxx_objects.Count -gt 0) {
    & $AR rcs "$GMP_INSTALL_DIR\lib\libgmpxx.a" $cxx_objects
}

Write-Host ""
Write-Host "=== GMP Build Complete ===" -ForegroundColor Green
Write-Host "Install directory: $GMP_INSTALL_DIR"
Write-Host "Include path: $GMP_INSTALL_DIR\include"
Write-Host "Library path: $GMP_INSTALL_DIR\lib"

if (Test-Path "$GMP_INSTALL_DIR\lib\libgmp.a") {
    $size = (Get-Item "$GMP_INSTALL_DIR\lib\libgmp.a").Length
    Write-Host "libgmp.a: $([math]::Round($size/1MB, 2)) MB"
}

if (Test-Path "$GMP_INSTALL_DIR\lib\libgmpxx.a") {
    $size = (Get-Item "$GMP_INSTALL_DIR\lib\libgmpxx.a").Length
    Write-Host "libgmpxx.a: $([math]::Round($size/1MB, 2)) MB"
}
