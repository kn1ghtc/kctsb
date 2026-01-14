# ============================================================================
# kctsb Build Script for Windows (PowerShell)
# Version: 3.2.0 (parity with scripts/build.sh)
# ============================================================================

param(
    [switch]$Debug,
    [switch]$Clean,
    [switch]$Test,
    [switch]$Benchmark,
    [switch]$Install,
    [string]$InstallDir = "$PSScriptRoot\install",
    [switch]$Verbose,
    [int]$Jobs = 0,
    [switch]$All,
    [switch]$NoVcpkg,
    [switch]$UseVcpkg,
    [string]$Generator
)

# Allow tools to emit warnings without stopping the script; we enforce failure via exit codes
$ErrorActionPreference = "Continue"

# Resolve project/build directories
$ProjectDir = Split-Path $PSScriptRoot -Parent
$BuildDir = Join-Path $ProjectDir "build"

# Derive build type
$BuildType = if ($Debug) { "Debug" } else { "Release" }
if ($All) {
    $Clean = $true
    $Test = $true
    $Benchmark = $true
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
Write-Host "Options:       Clean=$Clean Test=$Test Benchmark=$Benchmark Install=$Install" 
Write-Host ""

$startTime = Get-Date

try {
    # Clean build directory
    if ($Clean -and (Test-Path $BuildDir)) {
        Write-Host "[1/5] Cleaning build directory..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $BuildDir
    } else {
        Write-Host "[1/5] Skipping clean (use -Clean or -All to force)" -ForegroundColor Yellow
    }

    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir | Out-Null
    }

    # Configure
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

    # Prefer Ninja if available
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

    # Prefer MSYS2 MinGW toolchain over Strawberry Perl toolchain
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
        Write-Warning "MSYS2 MinGW64 toolchain not found at C:\\msys64\\mingw64\\bin; falling back to environment compilers"
        if ($env:PATH -match "Strawberry") {
            Write-Warning "Strawberry toolchain detected in PATH; prefer MSYS2 for consistency."
        }
    }

    # Auto-add VCPKG toolchain only when explicitly requested and benchmarking
    $enableVcpkg = $Benchmark -and (-not $NoVcpkg) -and $UseVcpkg -and $env:VCPKG_ROOT
    if ($enableVcpkg) {
        $toolchain = Join-Path $env:VCPKG_ROOT "scripts\buildsystems\vcpkg.cmake"
        if (Test-Path $toolchain) {
            $CMakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$toolchain"
            Write-Host "  Using VCPKG toolchain (explicitly enabled): $toolchain" -ForegroundColor Green
        } else {
            Write-Warning "VCPKG toolchain requested but not found; proceeding without it."
        }
    } else {
        Write-Host "  Skipping VCPKG toolchain (Use -UseVcpkg with -Benchmark after MSYS2/thirdparty attempts)." -ForegroundColor Yellow
    }

    cmake @CMakeArgs

    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }

    # Build
    Write-Host "[3/5] Building with $Jobs parallel jobs..." -ForegroundColor Yellow
    $buildCmd = @("--build", ".", "--parallel", $Jobs)
    if ($Verbose) { $buildCmd += "--verbose" }
    cmake @buildCmd
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }

    # Test
    if ($Test) {
        Write-Host "[4/5] Running tests..." -ForegroundColor Yellow
        ctest --output-on-failure --parallel $Jobs
        if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
    } else {
        Write-Host "[4/5] Skipping tests (use -Test or -All)" -ForegroundColor Yellow
    }

    # Benchmark
    if ($Benchmark) {
        Write-Host "[5/5] Running benchmarks..." -ForegroundColor Yellow
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
        Write-Host "[5/5] Skipping benchmarks (use -Benchmark or -All)" -ForegroundColor Yellow
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

$elapsed = Get-Date -Date $startTime
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
