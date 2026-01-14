# ============================================================================
# kctsb Build Script for Windows (PowerShell)
# Version: 3.2.1 - Optimized build with test separation
# ============================================================================

param(
    [switch]$Debug,
    [switch]$Clean,
    [switch]$Test,              # Run unit + integration tests (fast, default for -All)
    [switch]$TestAll,           # Run ALL tests including performance
    [switch]$Benchmark,         # Build and run OpenSSL comparison benchmarks
    [switch]$Install,
    [string]$InstallDir = "$PSScriptRoot\install",
    [switch]$Verbose,
    [int]$Jobs = 0,
    [switch]$All,               # Clean + Build + Test (unit+integration only)
    [switch]$Full,              # Clean + Build + TestAll + Benchmark (complete)
    [switch]$NoVcpkg,
    [switch]$UseVcpkg,
    [string]$Generator
)

$ErrorActionPreference = "Continue"

$ProjectDir = Split-Path $PSScriptRoot -Parent
$BuildDir = Join-Path $ProjectDir "build"
$BuildType = if ($Debug) { "Debug" } else { "Release" }

# Handle -All and -Full flags
if ($Full) {
    $Clean = $true
    $TestAll = $true
    $Benchmark = $true
}
if ($All) {
    $Clean = $true
    $Test = $true
}

# Parallel jobs
if ($Jobs -le 0) {
    $Jobs = [Environment]::ProcessorCount
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   kctsb Build Script (Windows)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Build Type:    $BuildType"
Write-Host "Build Dir:     $BuildDir"
Write-Host "Parallel Jobs: $Jobs"
Write-Host "Options:       Clean=$Clean Test=$Test TestAll=$TestAll Benchmark=$Benchmark"
Write-Host ""

$startTime = Get-Date

try {
    # [1/5] Clean
    if ($Clean -and (Test-Path $BuildDir)) {
        Write-Host "[1/5] Cleaning build directory..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $BuildDir
    } else {
        Write-Host "[1/5] Skipping clean (use -Clean, -All, or -Full)" -ForegroundColor Yellow
    }

    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir | Out-Null
    }

    # [2/5] Configure
    Write-Host "[2/5] Configuring with CMake..." -ForegroundColor Yellow
    Push-Location $BuildDir

    $CMakeArgs = @(
        "..",
        "-DCMAKE_BUILD_TYPE=$BuildType",
        "-DKCTSB_BUILD_TESTS=ON",
        "-DKCTSB_BUILD_EXAMPLES=ON",
        "-DKCTSB_ENABLE_HELIB=ON"
    )

    if ($Benchmark) {
        $CMakeArgs += "-DKCTSB_BUILD_BENCHMARKS=ON"
    }

    if ($Install) {
        $CMakeArgs += "-DCMAKE_INSTALL_PREFIX=$InstallDir"
    }

    # Generator selection
    $selectedGenerator = $null
    if ($Generator) {
        $selectedGenerator = $Generator
    } elseif (Get-Command ninja -ErrorAction SilentlyContinue) {
        $selectedGenerator = "Ninja"
    } else {
        $selectedGenerator = "MinGW Makefiles"
    }

    if ($selectedGenerator) {
        $CMakeArgs += @("-G", $selectedGenerator)
        Write-Host "  Using generator: $selectedGenerator" -ForegroundColor Green
    }

    # MSYS2 MinGW toolchain preference
    $msysGcc = "C:\\msys64\\mingw64\\bin\\gcc.exe"
    $msysGxx = "C:\\msys64\\mingw64\\bin\\g++.exe"
    if ((Test-Path $msysGcc) -and (Test-Path $msysGxx)) {
        $CMakeArgs += "-DCMAKE_C_COMPILER=$msysGcc"
        $CMakeArgs += "-DCMAKE_CXX_COMPILER=$msysGxx"
        $env:CC = $msysGcc
        $env:CXX = $msysGxx
        if (-not ($env:PATH -like "C:\\msys64\\mingw64\\bin*")) {
            $env:PATH = "C:\\msys64\\mingw64\\bin;C:\\msys64\\usr\\bin;" + $env:PATH
        }
        Write-Host "  Using MSYS2 MinGW64 toolchain: $msysGcc" -ForegroundColor Green
    } else {
        Write-Warning "MSYS2 MinGW64 toolchain not found; falling back to environment compilers"
    }

    # VCPKG only when explicitly requested
    $enableVcpkg = $Benchmark -and (-not $NoVcpkg) -and $UseVcpkg -and $env:VCPKG_ROOT
    if ($enableVcpkg) {
        $toolchain = Join-Path $env:VCPKG_ROOT "scripts\buildsystems\vcpkg.cmake"
        if (Test-Path $toolchain) {
            $CMakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$toolchain"
            Write-Host "  Using VCPKG toolchain: $toolchain" -ForegroundColor Green
        }
    }

    cmake @CMakeArgs
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed" }

    # [3/5] Build
    Write-Host "[3/5] Building with $Jobs parallel jobs..." -ForegroundColor Yellow
    $buildCmd = @("--build", ".", "--parallel", $Jobs)
    if ($Verbose) { $buildCmd += "--verbose" }
    cmake @buildCmd
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }

    # [4/5] Tests
    if ($Test -or $TestAll) {
        if ($TestAll) {
            Write-Host "[4/5] Running ALL tests..." -ForegroundColor Yellow
            ctest --output-on-failure --parallel $Jobs
        } else {
            Write-Host "[4/5] Running unit + integration tests (fast)..." -ForegroundColor Yellow
            # Run only unit and integration tests, skip performance
            ctest -L "unit|integration" --output-on-failure --parallel $Jobs
        }
        if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
    } else {
        Write-Host "[4/5] Skipping tests (use -Test, -TestAll, -All, or -Full)" -ForegroundColor Yellow
    }

    # [5/5] Benchmark
    if ($Benchmark) {
        Write-Host "[5/5] Running OpenSSL comparison benchmarks..." -ForegroundColor Yellow
        $benchBin = Join-Path $BuildDir "bin\kctsb_benchmark.exe"
        if (Test-Path $benchBin) {
            $benchLog = Join-Path $BuildDir "kctsb_benchmark.log"
            & $benchBin | Tee-Object -FilePath $benchLog
            if ($LASTEXITCODE -ne 0) { throw "Benchmarks failed" }
            Write-Host "  Benchmark log: $benchLog" -ForegroundColor Green
        } else {
            Write-Host "  Benchmark binary not found. Enable KCTSB_BUILD_BENCHMARKS." -ForegroundColor Red
        }
    } else {
        Write-Host "[5/5] Skipping benchmarks (use -Benchmark or -Full)" -ForegroundColor Yellow
    }

    # Install
    if ($Install) {
        Write-Host "Installing to $InstallDir..." -ForegroundColor Yellow
        cmake --install .
        if ($LASTEXITCODE -ne 0) { throw "Install failed" }
    }
}
catch {
    Write-Host "Build script failed: $_" -ForegroundColor Red
    throw
}
finally {
    Pop-Location
}

$duration = New-TimeSpan -Start $startTime -End (Get-Date)

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   Build completed successfully!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host ("Elapsed:      {0:00}m {1:00}s" -f $duration.Minutes, $duration.Seconds)
Write-Host "Build outputs: $BuildDir"
Write-Host "  Libraries:   $BuildDir\lib"
Write-Host "  Binaries:    $BuildDir\bin"
Write-Host ""
Write-Host "Quick commands:" -ForegroundColor Cyan
Write-Host "  Fast build + test:     .\scripts\build.ps1 -All"
Write-Host "  Full build + bench:    .\scripts\build.ps1 -Full -UseVcpkg"
Write-Host "  Unit tests only:       ctest -L unit --test-dir build"
Write-Host "  Integration only:      ctest -L integration --test-dir build"
