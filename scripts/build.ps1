# ============================================================================
# kctsb Build Script for Windows (PowerShell)
# Version: 3.4.0
# ============================================================================

param(
    [switch]$Debug,
    [switch]$Clean,
    [switch]$Test,
    [switch]$Benchmark,
    [switch]$Install,
    [string]$InstallDir = "$PSScriptRoot\..\install",
    [switch]$Verbose,
    [int]$Jobs = 4,
    [switch]$All,
    [switch]$Release,
    [switch]$Help
)

$ErrorActionPreference = "Continue"
$ProjectDir = Split-Path $PSScriptRoot -Parent
$BuildDir = Join-Path $ProjectDir "build"
$ReleaseDir = Join-Path $ProjectDir "release"
$BuildType = if ($Debug) { "Debug" } else { "Release" }
$VERSION = "3.4.0"
$ARCH = $env:PROCESSOR_ARCHITECTURE
$ARCH_SUFFIX = if ($ARCH -eq "AMD64") { "x64" } else { "arm64" }
$PLATFORM_SUFFIX = "win-$ARCH_SUFFIX"

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
    Write-Host "  -Jobs N         Parallel jobs (default: 4)"
    Write-Host "  -All            Clean + Build + Test + Benchmark"
    Write-Host "  -Help           Show help"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\scripts\build.ps1                 # Quick release build"
    Write-Host "  .\scripts\build.ps1 -Debug -Test    # Debug + tests"
    Write-Host "  .\scripts\build.ps1 -Clean -All     # Full rebuild"
    Write-Host "  .\scripts\build.ps1 -Release        # Create release"
    exit 0
}

if ($All) {
    $Clean = $true; $Test = $true; $Benchmark = $true
}

Write-Host "" -ForegroundColor Blue
Write-Host "          kctsb Build Script v$VERSION                       " -ForegroundColor Blue
Write-Host "" -ForegroundColor Blue
Write-Host "Platform:  " -NoNewline; Write-Host "Windows ($PLATFORM_SUFFIX)" -ForegroundColor Green
Write-Host "Build Type:" -NoNewline; Write-Host " $BuildType" -ForegroundColor Green
Write-Host "Jobs:       $Jobs"
Write-Host "Options:    Clean=$Clean Test=$Test Benchmark=$Benchmark Release=$Release"
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

    $CMakeArgs = @("..", "-DCMAKE_BUILD_TYPE=$BuildType", "-DKCTSB_BUILD_TESTS=ON",
        "-DKCTSB_BUILD_EXAMPLES=ON", "-DKCTSB_ENABLE_HELIB=ON", "-DKCTSB_ENABLE_OPENSSL=ON",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON")

    if ($BuildType -eq "Release") {
        $CMakeArgs += "-DCMAKE_CXX_FLAGS=-O3 -march=native -mtune=native -ffast-math -funroll-loops -fomit-frame-pointer -flto -fno-rtti -fno-exceptions -fPIC"
    }

    if ($Benchmark -or $Release) { $CMakeArgs += "-DKCTSB_BUILD_BENCHMARKS=ON" }
    if ($Install) { $CMakeArgs += "-DCMAKE_INSTALL_PREFIX=$InstallDir" }

    if (Get-Command ninja -ErrorAction SilentlyContinue) {
        $CMakeArgs += @("-G", "Ninja")
        Write-Host "  Generator: Ninja" -ForegroundColor Green
    } else {
        Write-Host "  Generator: MinGW Makefiles (install Ninja for speed)" -ForegroundColor Yellow
        $CMakeArgs += @("-G", "MinGW Makefiles")
    }

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
        if (-not (Test-Path $ReleaseDir)) { New-Item -ItemType Directory -Path $ReleaseDir | Out-Null }
        $releaseBin = Join-Path $ReleaseDir "bin"
        $releaseLib = Join-Path $ReleaseDir "lib"
        $releaseInclude = Join-Path $ReleaseDir "include"
        @($releaseBin, $releaseLib, $releaseInclude) | ForEach-Object {
            if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ | Out-Null }
        }

        $kctsb = Join-Path $BuildDir "bin\kctsb.exe"
        if (Test-Path $kctsb) {
            Copy-Item $kctsb (Join-Path $releaseBin "kctsb-$PLATFORM_SUFFIX.exe")
            Copy-Item $kctsb (Join-Path $releaseBin "kctsb.exe")
            Write-Host "   Copied kctsb" -ForegroundColor Green
        }

        $benchBin = Join-Path $BuildDir "bin\kctsb_benchmark.exe"
        if (Test-Path $benchBin) {
            Copy-Item $benchBin (Join-Path $releaseBin "kctsb_benchmark-$PLATFORM_SUFFIX.exe")
            Copy-Item $benchBin (Join-Path $releaseBin "kctsb_benchmark.exe")
            Write-Host "   Copied benchmark" -ForegroundColor Green
        }

        $staticLib = Join-Path $BuildDir "lib\libkctsb.a"
        if (Test-Path $staticLib) {
            Copy-Item $staticLib (Join-Path $releaseLib "libkctsb-$PLATFORM_SUFFIX.a")
            Copy-Item $staticLib (Join-Path $releaseLib "libkctsb.a")
            Write-Host "   Copied static lib" -ForegroundColor Green
        }

        $dll = Join-Path $BuildDir "lib\libkctsb.dll"
        if (Test-Path $dll) {
            Copy-Item $dll (Join-Path $releaseLib "libkctsb-$PLATFORM_SUFFIX.dll")
            Copy-Item $dll (Join-Path $releaseLib "libkctsb.dll")
            Write-Host "   Copied DLL" -ForegroundColor Green
        }

        $includeDir = Join-Path $ProjectDir "include"
        if (Test-Path $includeDir) {
            Copy-Item (Join-Path $includeDir "kctsb") $releaseInclude -Recurse -Force
            Write-Host "   Copied headers" -ForegroundColor Green
        }

        $compilerVer = (& gcc --version 2>$null | Select-Object -First 1)
        if (-not $compilerVer) { $compilerVer = "Unknown" }
        
        $info = "kctsb Release v$VERSION`n"
        $info += "Platform: Windows ($PLATFORM_SUFFIX)`n"
        $info += "Build: $BuildType`n"
        $info += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n"
        $info += "Compiler: $compilerVer`n"
        Set-Content -Path (Join-Path $ReleaseDir "RELEASE_INFO.txt") -Value $info
        
        Write-Host "   Release created in $ReleaseDir" -ForegroundColor Green
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
if ($Release) { Write-Host "Release:   $ReleaseDir" }
Write-Host ""
Write-Host "Quick commands:" -ForegroundColor Cyan
Write-Host "  .\scripts\build.ps1          # Quick build"
Write-Host "  .\scripts\build.ps1 -Test    # Build + test"
Write-Host "  .\scripts\build.ps1 -All     # Full rebuild"
Write-Host "  .\scripts\build.ps1 -Release # Create release"