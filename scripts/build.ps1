# ============================================================================
# kctsb Build Script for Windows (PowerShell)
# Version: 3.4.2
#
# Features:
# - Platform-specific thirdparty: thirdparty/win-x64/
# - LTO enabled (GCC 11+/Clang/MSVC)
# - Single-file distribution (libkctsb_bundled.a - default)
# - Unified public API header (kctsb_api.h)
# - Bundled library created automatically on every build
# ============================================================================

param(
    [switch]$Debug,
    [switch]$Clean,
    [switch]$Test,
    [switch]$Benchmark,
    [switch]$Install,
    [string]$InstallDir = "$PSScriptRoot\..\install",
    [switch]$Verbose,
    [int]$Jobs = 0,
    [switch]$All,
    [switch]$Release,
    [switch]$Help
)

$ErrorActionPreference = "Continue"
$ProjectDir = Split-Path $PSScriptRoot -Parent
$BuildType = if ($Debug) { "Debug" } else { "Release" }
# Standardized build directories: Debug→build, Release→build-release
$BuildDir = if ($Debug) { Join-Path $ProjectDir "build" } else { Join-Path $ProjectDir "build-release" }
$ReleaseDir = Join-Path $ProjectDir "release"
$ThirdpartyDir = Join-Path $ProjectDir "thirdparty"
$VERSION = "3.4.2"
$ARCH = $env:PROCESSOR_ARCHITECTURE
$ARCH_SUFFIX = if ($ARCH -eq "AMD64") { "x64" } else { "arm64" }
$PLATFORM_SUFFIX = "win-$ARCH_SUFFIX"
$ThirdpartyPlatformDir = Join-Path $ThirdpartyDir $PLATFORM_SUFFIX

# Auto-detect parallel jobs
if ($Jobs -eq 0) {
    $Jobs = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    if (-not $Jobs) { $Jobs = 4 }
}

if ($Help) {
    Write-Host "Usage: .\scripts\build.ps1 [options]" -ForegroundColor Cyan
    Write-Host "Options:"
    Write-Host "  -Debug          Debug build (default: Release)"
    Write-Host "  -Clean          Clean before building"
    Write-Host "  -Test           Run tests after build"
    Write-Host "  -Benchmark      Run benchmarks"
    Write-Host "  -Install        Install to prefix"
    Write-Host "  -InstallDir DIR Install prefix (default: ./install)"
    Write-Host "  -Release        Create release package"
    Write-Host "  -Verbose        Verbose output"
    Write-Host "  -Jobs N         Parallel jobs (default: auto=$Jobs)"
    Write-Host "  -All            Clean + Build + Test + Benchmark"
    Write-Host "  -Help           Show help"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\scripts\build.ps1                 # Quick release build"
    Write-Host "  .\scripts\build.ps1 -Debug -Test    # Debug + tests"
    Write-Host "  .\scripts\build.ps1 -Clean -All     # Full rebuild"
    Write-Host "  .\scripts\build.ps1 -Release        # Create release"
    Write-Host ""
    Write-Host "Thirdparty search order:"
    Write-Host "  1. thirdparty/$PLATFORM_SUFFIX/"
    Write-Host "  2. thirdparty/"
    Write-Host "  3. System paths"
    exit 0
}

if ($All) {
    $Clean = $true; $Test = $true; $Benchmark = $true
}

Write-Host "" -ForegroundColor Blue
Write-Host "          kctsb Build Script v$VERSION                       " -ForegroundColor Blue
Write-Host "" -ForegroundColor Blue
Write-Host "Platform:     " -NoNewline; Write-Host "Windows ($PLATFORM_SUFFIX)" -ForegroundColor Green
Write-Host "Build Type:   " -NoNewline; Write-Host "$BuildType" -ForegroundColor Green
Write-Host "Jobs:         $Jobs"
Write-Host "Options:      Clean=$Clean Test=$Test Benchmark=$Benchmark Release=$Release"
Write-Host ""
Write-Host "Thirdparty:   $ThirdpartyPlatformDir"
if (Test-Path $ThirdpartyPlatformDir) {
    Write-Host "              (platform-specific found)" -ForegroundColor Green
} else {
    Write-Host "              (using common thirdparty/)" -ForegroundColor Yellow
}
Write-Host ""

$startTime = Get-Date
$STEP = 1; $TOTAL_STEPS = 5
if ($Release) { $TOTAL_STEPS = 6 }

try {
    if ($Clean -and (Test-Path $BuildDir)) {
        Write-Host "[$STEP/$TOTAL_STEPS] Cleaning..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $BuildDir
    } else {
        Write-Host "[$STEP/$TOTAL_STEPS] Skip clean (-Clean to force)" -ForegroundColor Yellow
    }
    $STEP++

    if (-not (Test-Path $BuildDir)) { New-Item -ItemType Directory -Path $BuildDir | Out-Null }

    Write-Host "[$STEP/$TOTAL_STEPS] Configuring..." -ForegroundColor Yellow
    Push-Location $BuildDir

    $CMakeArgs = @(
        "..",
        "-DCMAKE_BUILD_TYPE=$BuildType",
        "-DKCTSB_BUILD_TESTS=ON",
        "-DKCTSB_BUILD_EXAMPLES=ON",
        "-DKCTSB_ENABLE_LTO=ON",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
    )

    if ($Benchmark -or $Release) { $CMakeArgs += "-DKCTSB_BUILD_BENCHMARKS=ON" }
    if ($Install) { $CMakeArgs += "-DCMAKE_INSTALL_PREFIX=$InstallDir" }

    # Detect and use Ninja if available
    if (Get-Command ninja -ErrorAction SilentlyContinue) {
        $CMakeArgs += @("-G", "Ninja")
        Write-Host "  Generator: Ninja" -ForegroundColor Green
    } else {
        Write-Host "  Generator: MinGW Makefiles (install Ninja for speed)" -ForegroundColor Yellow
        $CMakeArgs += @("-G", "MinGW Makefiles")
    }

    # MSYS2 MinGW64 toolchain
    $msysGcc = "C:\msys64\mingw64\bin\gcc.exe"
    $msysGxx = "C:\msys64\mingw64\bin\g++.exe"
    if ((Test-Path $msysGcc) -and (Test-Path $msysGxx)) {
        $CMakeArgs += "-DCMAKE_C_COMPILER=$msysGcc", "-DCMAKE_CXX_COMPILER=$msysGxx"
        $env:CC = $msysGcc; $env:CXX = $msysGxx
        if (-not ($env:PATH -like "*C:\msys64\mingw64\bin*")) {
            $env:PATH = "C:\msys64\mingw64\bin;C:\msys64\usr\bin;" + $env:PATH
        }
        Write-Host "  Toolchain: MSYS2 MinGW64" -ForegroundColor Green
    } else {
        Write-Warning "MSYS2 not found, using system compiler"
    }

    cmake @CMakeArgs
    if ($LASTEXITCODE -ne 0) { throw "CMake failed" }
    $STEP++

    Write-Host "[$STEP/$TOTAL_STEPS] Building..." -ForegroundColor Yellow
    $buildCmd = @("--build", ".", "--parallel", $Jobs)
    if ($Verbose) { $buildCmd += "--verbose" }
    cmake @buildCmd
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    
    # ====================================================================
    # Create bundled static library (always, single-file delivery)
    # ====================================================================
    Write-Host "   Creating bundled static library..." -ForegroundColor Yellow
    
    $staticLib = Join-Path $BuildDir "lib\libkctsb.a"
    $bundledLib = Join-Path $BuildDir "lib\libkctsb_bundled.a"
    
    # Find ar tool
    $AR = $null
    $arPaths = @(
        "C:\msys64\mingw64\bin\ar.exe",
        "C:\msys64\usr\bin\ar.exe",
        "C:\Strawberry\c\bin\ar.exe"
    )
    foreach ($arPath in $arPaths) {
        if (Test-Path $arPath) { $AR = $arPath; break }
    }
    
    if ($AR -and (Test-Path $staticLib)) {
        # Collect all static libraries to bundle
        $libsToBundle = @($staticLib)
        
        # Thirdparty libraries
        $thirdpartyLibDirs = @(
            (Join-Path $ThirdpartyPlatformDir "lib"),
            (Join-Path $ThirdpartyDir "lib")
        )
        
        $depLibs = @("libntl.a", "libgmp.a", "libgf2x.a", "libseal-4.1.a", "libhelib.a")
        foreach ($libDir in $thirdpartyLibDirs) {
            if (Test-Path $libDir) {
                foreach ($depLib in $depLibs) {
                    $depPath = Join-Path $libDir $depLib
                    if ((Test-Path $depPath) -and ($libsToBundle -notcontains $depPath)) {
                        $libsToBundle += $depPath
                    }
                }
            }
        }
        
        if ($libsToBundle.Count -gt 1) {
            # Create temp directory for extraction
            $bundleTmpDir = Join-Path $BuildDir "bundle_tmp"
            if (Test-Path $bundleTmpDir) {
                Remove-Item -Recurse -Force $bundleTmpDir
            }
            New-Item -ItemType Directory -Path $bundleTmpDir | Out-Null
            
            Push-Location $bundleTmpDir
            try {
                $libIndex = 0
                foreach ($lib in $libsToBundle) {
                    $libName = [System.IO.Path]::GetFileNameWithoutExtension($lib)
                    $prefix = "lib${libIndex}_"
                    
                    & $AR x $lib 2>$null
                    
                    # Rename extracted .o files with prefix
                    Get-ChildItem -Filter "*.o" | Where-Object { $_.Name -notmatch "^lib\d+_" } | ForEach-Object {
                        $newName = "${prefix}$($_.Name)"
                        Rename-Item $_.FullName $newName
                    }
                    $libIndex++
                }
                
                # Create bundled library
                $objFiles = Get-ChildItem -Filter "*.o" | ForEach-Object { $_.Name }
                
                if ($objFiles.Count -gt 0) {
                    & $AR rcs $bundledLib @objFiles 2>$null
                    
                    if (Test-Path $bundledLib) {
                        $bundledSize = (Get-Item $bundledLib).Length
                        $bundledSizeMB = [math]::Round($bundledSize / 1MB, 2)
                        Write-Host "   ✓ Created libkctsb_bundled.a ($bundledSizeMB MB, $($objFiles.Count) objects)" -ForegroundColor Green
                    }
                }
            }
            finally {
                Pop-Location
                if (Test-Path $bundleTmpDir) {
                    Remove-Item -Recurse -Force $bundleTmpDir
                }
            }
        } else {
            # No dependencies, just copy as bundled
            Copy-Item $staticLib $bundledLib -Force
            Write-Host "   ✓ Created libkctsb_bundled.a (no deps to bundle)" -ForegroundColor Green
        }
    } else {
        Write-Host "   (ar not found or static lib missing)" -ForegroundColor Yellow
    }
    
    $STEP++

    if ($Test) {
        Write-Host "[$STEP/$TOTAL_STEPS] Testing..." -ForegroundColor Yellow
        ctest --output-on-failure --parallel $Jobs
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   All tests passed!" -ForegroundColor Green
        } else {
            Write-Host "   Tests failed!" -ForegroundColor Red; throw "Tests failed"
        }
    } else {
        Write-Host "[$STEP/$TOTAL_STEPS] Skip tests (-Test to run)" -ForegroundColor Yellow
    }
    $STEP++

    if ($Benchmark) {
        Write-Host "[$STEP/$TOTAL_STEPS] Benchmarking..." -ForegroundColor Yellow
        $benchBin = Join-Path $BuildDir "bin\kctsb_benchmark.exe"
        if (Test-Path $benchBin) {
            & $benchBin
            if ($LASTEXITCODE -eq 0) { Write-Host "   Benchmark done!" -ForegroundColor Green }
            else { throw "Benchmark failed" }
        } else {
            Write-Host "   Benchmark binary not found" -ForegroundColor Red
        }
    } else {
        Write-Host "[$STEP/$TOTAL_STEPS] Skip benchmark (-Benchmark to run)" -ForegroundColor Yellow
    }
    $STEP++

    if ($Release) {
        Write-Host "[$STEP/$TOTAL_STEPS] Creating release..." -ForegroundColor Yellow
        
        # Platform-specific release directory
        $ReleasePlatformDir = Join-Path $ReleaseDir $PLATFORM_SUFFIX
        if (Test-Path $ReleasePlatformDir) {
            Remove-Item -Recurse -Force $ReleasePlatformDir
        }
        
        $releaseBin = Join-Path $ReleasePlatformDir "bin"
        $releaseLib = Join-Path $ReleasePlatformDir "lib"
        $releaseInclude = Join-Path $ReleasePlatformDir "include"
        @($releaseBin, $releaseLib, $releaseInclude) | ForEach-Object {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }

        # Copy CLI tool
        $kctsb = Join-Path $BuildDir "bin\kctsb.exe"
        if (Test-Path $kctsb) {
            Copy-Item $kctsb (Join-Path $releaseBin "kctsb.exe")
            Write-Host "   Copied kctsb.exe" -ForegroundColor Green
        }

        # Copy benchmark
        $benchBin = Join-Path $BuildDir "bin\kctsb_benchmark.exe"
        if (Test-Path $benchBin) {
            Copy-Item $benchBin (Join-Path $releaseBin "kctsb_benchmark.exe")
            Write-Host "   Copied kctsb_benchmark.exe" -ForegroundColor Green
        }

        # Copy static library
        $staticLib = Join-Path $BuildDir "lib\libkctsb.a"
        if (Test-Path $staticLib) {
            Copy-Item $staticLib (Join-Path $releaseLib "libkctsb.a")
            Write-Host "   Copied libkctsb.a" -ForegroundColor Green
        }

        # Copy DLL if exists
        $dll = Join-Path $BuildDir "lib\libkctsb.dll"
        if (Test-Path $dll) {
            Copy-Item $dll (Join-Path $releaseLib "libkctsb.dll")
            Write-Host "   Copied libkctsb.dll" -ForegroundColor Green
        }

        # ====================================================================
        # Create bundled static library (single-file with all dependencies)
        # ====================================================================
        Write-Host "   Creating bundled static library..." -ForegroundColor Yellow
        
        # Find ar tool (prefer MSYS2, fallback to Strawberry Perl)
        $AR = $null
        $arPaths = @(
            "C:\msys64\mingw64\bin\ar.exe",
            "C:\msys64\usr\bin\ar.exe",
            "C:\Strawberry\c\bin\ar.exe"
        )
        foreach ($arPath in $arPaths) {
            if (Test-Path $arPath) { $AR = $arPath; break }
        }
        
        if ($AR) {
            # Collect all static libraries to bundle
            $libsToBundle = @()
            
            # kctsb library (required)
            if (Test-Path $staticLib) {
                $libsToBundle += $staticLib
            }
            
            # Thirdparty libraries (check both platform-specific and common)
            $thirdpartyLibDirs = @(
                (Join-Path $ThirdpartyPlatformDir "lib"),
                (Join-Path $ThirdpartyDir "lib")
            )
            
            $depLibs = @("libntl.a", "libgmp.a", "libgf2x.a", "libseal-4.1.a", "libhelib.a")
            foreach ($libDir in $thirdpartyLibDirs) {
                if (Test-Path $libDir) {
                    foreach ($depLib in $depLibs) {
                        $depPath = Join-Path $libDir $depLib
                        if ((Test-Path $depPath) -and ($libsToBundle -notcontains $depPath)) {
                            $libsToBundle += $depPath
                        }
                    }
                }
            }
            
            if ($libsToBundle.Count -gt 1) {
                # Create temp directory for extraction
                $bundleTmpDir = Join-Path $BuildDir "bundle_tmp"
                if (Test-Path $bundleTmpDir) {
                    Remove-Item -Recurse -Force $bundleTmpDir
                }
                New-Item -ItemType Directory -Path $bundleTmpDir | Out-Null
                
                Push-Location $bundleTmpDir
                try {
                    # Extract each library and prefix object files to avoid name conflicts
                    $libIndex = 0
                    foreach ($lib in $libsToBundle) {
                        $libName = [System.IO.Path]::GetFileNameWithoutExtension($lib)
                        $prefix = "lib${libIndex}_"
                        
                        Write-Host "     Extracting $libName..." -ForegroundColor DarkGray
                        & $AR x $lib 2>$null
                        
                        # Rename extracted .o files with prefix
                        Get-ChildItem -Filter "*.o" | Where-Object { $_.Name -notmatch "^lib\d+_" } | ForEach-Object {
                            $newName = "${prefix}$($_.Name)"
                            Rename-Item $_.FullName $newName
                        }
                        $libIndex++
                    }
                    
                    # Create bundled library
                    $bundledLib = Join-Path $releaseLib "libkctsb_bundled.a"
                    $objFiles = Get-ChildItem -Filter "*.o" | ForEach-Object { $_.Name }
                    
                    if ($objFiles.Count -gt 0) {
                        Write-Host "     Creating libkctsb_bundled.a ($($objFiles.Count) objects)..." -ForegroundColor DarkGray
                        & $AR rcs $bundledLib @objFiles 2>$null
                        
                        if (Test-Path $bundledLib) {
                            $bundledSize = (Get-Item $bundledLib).Length
                            $bundledSizeMB = [math]::Round($bundledSize / 1MB, 2)
                            Write-Host "   Created libkctsb_bundled.a ($bundledSizeMB MB)" -ForegroundColor Green
                        } else {
                            Write-Host "   Failed to create bundled library" -ForegroundColor Red
                        }
                    }
                }
                finally {
                    Pop-Location
                    # Cleanup temp directory
                    if (Test-Path $bundleTmpDir) {
                        Remove-Item -Recurse -Force $bundleTmpDir
                    }
                }
            } else {
                Write-Host "   No dependencies to bundle (only kctsb)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "   ar not found, skipping bundled library" -ForegroundColor Yellow
        }

        # Copy ONLY the unified public API header
        $apiHeader = Join-Path $ProjectDir "include\kctsb\kctsb_api.h"
        if (Test-Path $apiHeader) {
            Copy-Item $apiHeader (Join-Path $releaseInclude "kctsb_api.h")
            Write-Host "   Copied kctsb_api.h (unified public API)" -ForegroundColor Green
        }

        # Generate release info
        $compilerVer = (& gcc --version 2>$null | Select-Object -First 1)
        if (-not $compilerVer) { $compilerVer = "Unknown" }
        
        # Check bundled library
        $bundledLibPath = Join-Path $releaseLib "libkctsb_bundled.a"
        $hasBundled = Test-Path $bundledLibPath
        $bundledInfo = if ($hasBundled) { 
            $sz = [math]::Round((Get-Item $bundledLibPath).Length / 1MB, 2)
            "- lib/libkctsb_bundled.a    : Bundled static library ($sz MB, includes NTL/GMP/SEAL)"
        } else { "" }
        
        $info = @"
kctsb Release Information
==========================
Version: $VERSION
Platform: Windows ($PLATFORM_SUFFIX)
Build Type: $BuildType
Build Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
Compiler: $compilerVer

Contents:
- bin/kctsb.exe              : Command-line tool
- bin/kctsb_benchmark.exe    : Performance benchmark (if built)
- lib/libkctsb.a             : Static library (requires NTL/GMP)
$bundledInfo
- lib/libkctsb.dll           : Dynamic library (if built)
- include/kctsb_api.h        : Unified public API header

Integration (like OpenSSL):
  #include <kctsb_api.h>
  
  // Option 1: Use bundled library (single file, no external deps)
  // Link: -lkctsb_bundled -lstdc++ -lbcrypt
  
  // Option 2: Use separate libraries  
  // Link: -lkctsb -lntl -lgmp -lstdc++ -lbcrypt

License: Apache License 2.0
Repository: https://github.com/kn1ghtc/kctsb
"@
        Set-Content -Path (Join-Path $ReleasePlatformDir "RELEASE_INFO.txt") -Value $info
        
        Write-Host "   Release created in $ReleasePlatformDir" -ForegroundColor Green
    }

    if ($Install) {
        Write-Host "Installing to $InstallDir..." -ForegroundColor Yellow
        cmake --install .
        if ($LASTEXITCODE -ne 0) { throw "Install failed" }
    }
}
catch { Write-Host "Build failed: $_" -ForegroundColor Red; throw }
finally { Pop-Location }

$duration = New-TimeSpan -Start $startTime -End (Get-Date)

Write-Host ""
Write-Host "" -ForegroundColor Green
Write-Host "           Build completed successfully!                    " -ForegroundColor Green
Write-Host "" -ForegroundColor Green
Write-Host "Time: $($duration.Minutes)m $($duration.Seconds)s"
Write-Host "Build dir: $BuildDir"
if ($Release) { Write-Host "Release:   $ReleaseDir\$PLATFORM_SUFFIX" }
Write-Host ""
Write-Host "Distribution (like OpenSSL):" -ForegroundColor Cyan
Write-Host "  Header:  kctsb_api.h"
Write-Host "  Library: libkctsb.a"
Write-Host "  Link:    -lkctsb -lstdc++ -lbcrypt"
Write-Host ""
Write-Host "Quick commands:" -ForegroundColor Cyan
Write-Host "  .\scripts\build.ps1          # Quick build"
Write-Host "  .\scripts\build.ps1 -Test    # Build + test"
Write-Host "  .\scripts\build.ps1 -All     # Full rebuild"
Write-Host "  .\scripts\build.ps1 -Release # Create release"
