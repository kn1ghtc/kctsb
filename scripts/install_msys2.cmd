@echo off
REM MSYS2 Automatic Installation Script (Batch Version)
REM Author: kctsb Development Team
REM Date: 2026-01-12

echo ========================================
echo MSYS2 Automatic Installation Script
echo ========================================
echo.

set "INSTALL_PATH=C:\msys64"
set "DOWNLOAD_PATH=%TEMP%\msys2-installer.exe"
set "MSYS2_VERSION=20231026"
set "MSYS2_URL=https://repo.msys2.org/distrib/x86_64/msys2-x86_64-%MSYS2_VERSION%.exe"

REM Check if already installed
if exist "%INSTALL_PATH%\msys2_shell.cmd" (
    echo [INFO] MSYS2 already installed at %INSTALL_PATH%
    echo [INFO] Skipping download and installation...
    goto :UpdatePackages
)

REM Step 1: Download MSYS2 installer
echo [1/5] Downloading MSYS2 installer...
echo    URL: %MSYS2_URL%
echo    Destination: %DOWNLOAD_PATH%
echo.

powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri '%MSYS2_URL%' -OutFile '%DOWNLOAD_PATH%' -UseBasicParsing -Verbose; Write-Host '[OK] Download completed' -ForegroundColor Green } catch { Write-Host '[ERROR] Download failed: ' + $_.Exception.Message -ForegroundColor Red; $FALLBACK_URL='https://github.com/msys2/msys2-installer/releases/download/%MSYS2_VERSION%/msys2-x86_64-%MSYS2_VERSION%.exe'; Write-Host 'Trying GitHub mirror: ' + $FALLBACK_URL -ForegroundColor Yellow; Invoke-WebRequest -Uri $FALLBACK_URL -OutFile '%DOWNLOAD_PATH%' -UseBasicParsing -Verbose; Write-Host '[OK] Downloaded from GitHub' -ForegroundColor Green } }"

if errorlevel 1 (
    echo [ERROR] Download failed
    exit /b 1
)

if not exist "%DOWNLOAD_PATH%" (
    echo [ERROR] Installer file not found after download
    exit /b 1
)

echo.
echo [2/5] Installing MSYS2 to %INSTALL_PATH%...
echo    This may take 2-5 minutes...
echo    Running silent installation...
echo.

REM Silent installation using NSIS /S switch
"%DOWNLOAD_PATH%" /S /D=%INSTALL_PATH%

REM Wait for installation to complete
timeout /t 10 /nobreak >nul

REM Verify installation
if not exist "%INSTALL_PATH%\msys2_shell.cmd" (
    echo [ERROR] Installation failed - msys2_shell.cmd not found
    exit /b 1
)

echo [OK] MSYS2 installed successfully
echo.

REM Cleanup installer
del /f /q "%DOWNLOAD_PATH%" 2>nul

:UpdatePackages
REM Step 3: Update package database
echo [3/5] Updating MSYS2 package database...
echo.

REM Initialize MSYS2 first run
if not exist "%INSTALL_PATH%\var\lib\pacman\sync" (
    echo    Initializing MSYS2 first run...
    "%INSTALL_PATH%\usr\bin\bash.exe" --login -c "exit"
    timeout /t 3 /nobreak >nul
)

REM Update core packages (without confirmation)
echo    Running: pacman -Syu --noconfirm
"%INSTALL_PATH%\usr\bin\bash.exe" --login -c "pacman -Syu --noconfirm"

if errorlevel 1 (
    echo [WARNING] Package database update encountered issues
    echo [INFO] This is usually safe to ignore on first run
)

echo.
echo [4/5] Installing MinGW-w64 toolchain and development tools...
echo.

REM Install development packages
echo    Installing: mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja
"%INSTALL_PATH%\usr\bin\bash.exe" --login -c "pacman -S --needed --noconfirm mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja mingw-w64-x86_64-make base-devel git tar"

if errorlevel 1 (
    echo [ERROR] Toolchain installation failed
    exit /b 1
)

echo [OK] Toolchain installed successfully
echo.

REM Step 5: Configure environment
echo [5/5] Configuring system environment...
echo.

REM Add to PATH (session only)
set "PATH=%INSTALL_PATH%\mingw64\bin;%INSTALL_PATH%\usr\bin;%PATH%"

echo [OK] MSYS2 installation and configuration completed!
echo.
echo ========================================
echo Installation Summary
echo ========================================
echo Install Path: %INSTALL_PATH%
echo MinGW-w64 GCC: %INSTALL_PATH%\mingw64\bin\gcc.exe
echo CMake: %INSTALL_PATH%\mingw64\bin\cmake.exe
echo Bash: %INSTALL_PATH%\usr\bin\bash.exe
echo.
echo To use MSYS2 in this terminal:
echo    set PATH=%INSTALL_PATH%\mingw64\bin;%INSTALL_PATH%\usr\bin;%%PATH%%
echo.
echo To open MSYS2 shell:
echo    %INSTALL_PATH%\msys2_shell.cmd
echo.

REM Verify installation
echo Verifying installation...
"%INSTALL_PATH%\mingw64\bin\gcc.exe" --version 2>nul | findstr "gcc"
if errorlevel 1 (
    echo [WARNING] GCC verification failed
) else (
    echo [OK] GCC verified successfully
)

echo.
echo ========================================
echo Installation completed successfully!
echo ========================================
pause
