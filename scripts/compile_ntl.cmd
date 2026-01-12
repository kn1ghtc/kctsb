@echo off
REM NTL Batch Compilation Script for Windows (MinGW-w64)
REM Compiles all NTL core modules into a static library

setlocal enabledelayedexpansion
cd /d D:\pyproject\kctsb

set CXX=C:\Strawberry\c\bin\g++.exe
set AR=C:\Strawberry\c\bin\ar.exe
set CXXFLAGS=-c -O2 -std=c++14 -w -fPIC -Ithirdparty\include -IC:\Strawberry\c\include
set SRC=deps\ntl-11.6.0\src
set BUILD=deps\ntl-build
set INSTALL=deps\ntl

echo ============================================================
echo   NTL 11.6.0 Compilation (Windows MinGW-w64)
echo ============================================================
echo.

REM Create directories
if not exist "%BUILD%" mkdir "%BUILD%"
if not exist "%INSTALL%\lib" mkdir "%INSTALL%\lib"
if not exist "%INSTALL%\include" mkdir "%INSTALL%\include"

REM Core modules list
set MODULES=BasicThreadPool ctools FacVec FFT fileio G_LLL_FP G_LLL_QP G_LLL_RR G_LLL_XD
set MODULES=%MODULES% GF2 GF2E GF2EX GF2EXFactoring GF2X GF2X1 GF2XFactoring GF2XVec
set MODULES=%MODULES% HNF InitSettings lip LLL LLL_FP LLL_QP LLL_RR LLL_XD
set MODULES=%MODULES% lzz_p lzz_pE lzz_pEX lzz_pEXFactoring lzz_pX lzz_pX1 lzz_pXCharPoly lzz_pXFactoring
set MODULES=%MODULES% mat_GF2 mat_GF2E mat_lzz_p mat_lzz_pE mat_poly_lzz_p mat_poly_ZZ mat_poly_ZZ_p
set MODULES=%MODULES% mat_RR mat_ZZ mat_ZZ_p mat_ZZ_pE MatPrime
set MODULES=%MODULES% newnames pd_FFT quad_float quad_float1 RR
set MODULES=%MODULES% subset thread tools
set MODULES=%MODULES% vec_GF2 vec_GF2E vec_lzz_p vec_lzz_pE vec_RR vec_ZZ vec_ZZ_p vec_ZZ_pE
set MODULES=%MODULES% WordVector xdouble
set MODULES=%MODULES% ZZ ZZ_p ZZ_pE ZZ_pEX ZZ_pEXFactoring ZZ_pX ZZ_pX1 ZZ_pXCharPoly ZZ_pXFactoring
set MODULES=%MODULES% ZZVec ZZX ZZX1 ZZXCharPoly ZZXFactoring

set /a COUNT=0
set /a SUCCESS=0
set /a FAIL=0

echo Compiling modules...
for %%M in (%MODULES%) do (
    set /a COUNT+=1
    if exist "%SRC%\%%M.cpp" (
        echo [!COUNT!] %%M
        %CXX% %CXXFLAGS% "%SRC%\%%M.cpp" -o "%BUILD%\%%M.o" 2>nul
        if !errorlevel! equ 0 (
            set /a SUCCESS+=1
        ) else (
            echo     FAILED
            set /a FAIL+=1
        )
    )
)

echo.
echo Compiled: %SUCCESS% / %COUNT% modules
if %FAIL% gtr 0 echo Failed: %FAIL% modules

echo.
echo Creating static library...
cd "%BUILD%"
%AR% rcs "%INSTALL%\lib\libntl.a" *.o
if %errorlevel% equ 0 (
    echo Library: %INSTALL%\lib\libntl.a
) else (
    echo Failed to create library!
    exit /b 1
)

echo.
echo Copying headers...
xcopy /E /I /Y "..\thirdparty\include\NTL" "%INSTALL%\include\NTL" >nul
echo Headers: %INSTALL%\include\NTL\

echo.
echo ============================================================
echo   NTL Build Complete!
echo ============================================================
echo.
echo Library: %INSTALL%\lib\libntl.a
echo Headers: %INSTALL%\include\NTL\
echo.
