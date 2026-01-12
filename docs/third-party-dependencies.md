# kctsb Third-Party Dependencies Installation Guide

> **Version**: 3.1.0  
> **Last Updated**: 2026-01-12 (Beijing Time, UTC+8)  
> **Target**: All dependencies installed to `thirdparty/` directory

## Overview

kctsb requires the following dependencies, all installed to the unified `thirdparty/` directory:

| Dependency | Version | Required | Purpose |
|------------|---------|----------|---------|
| **GMP** | 6.3.0+ | ✅ Yes | High-precision arithmetic |
| **gf2x** | 1.3.0+ | ✅ Yes | Polynomial arithmetic over GF(2) (NTL dependency) |
| **NTL** | 11.6.0+ | ✅ Yes | Number theory, ECC, RSA |
| **SEAL** | 4.1.2 | ⚠️ Optional | Homomorphic encryption |
| **HElib** | 2.3.0 | ⚠️ Optional | Functional encryption |
| **OpenSSL** | 3.x | ⚠️ Benchmark only | Performance comparison |

**Important**: OpenSSL is ONLY used for benchmarks, NOT in the core library.

---

## Directory Structure

```
kctsb/
├── thirdparty/           # ★ All dependencies go here ★
│   ├── include/          # Header files
│   │   ├── NTL/          # NTL headers
│   │   ├── gf2x/         # gf2x headers
│   │   ├── gmp.h         # GMP headers
│   │   ├── gmpxx.h       # GMP C++ headers
│   │   ├── SEAL-4.1/     # SEAL headers
│   │   └── helib/        # HElib headers
│   └── lib/              # Library files
│       ├── libntl.a      # NTL static library
│       ├── libgf2x.a     # gf2x static library
│       ├── libgmp.a      # GMP static library
│       ├── libgmpxx.a    # GMP C++ library
│       ├── libseal-4.1.a # SEAL library
│       └── libhelib.a    # HElib library
└── deps/                 # Source compilation workspace (temporary)
```

---

## Windows Installation (MSYS2 + Ninja)

### Prerequisites

1. **Install MSYS2** from https://www.msys2.org/
2. **Open MSYS2 UCRT64 terminal** and install build tools:

```bash
pacman -Syu
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake \
          mingw-w64-ucrt-x86_64-ninja mingw-w64-ucrt-x86_64-make \
          git autoconf automake libtool
```

### Step 1: Install GMP (6.3.0)

```bash
cd /d/pyproject/kctsb/deps
wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz
tar xf gmp-6.3.0.tar.xz
cd gmp-6.3.0

# Configure with C++ support
./configure --prefix=/d/pyproject/kctsb/thirdparty \
    --enable-cxx \
    --enable-static \
    --disable-shared \
    CFLAGS="-O3 -march=native" \
    CXXFLAGS="-O3 -march=native"

make -j$(nproc)
make install
```

**Verify**: `ls /d/pyproject/kctsb/thirdparty/lib/libgmp.a`

### Step 2: Install gf2x (1.3.0)

```bash
cd /d/pyproject/kctsb/deps
git clone https://gitlab.inria.fr/gf2x/gf2x.git
cd gf2x

autoreconf -i
./configure --prefix=/d/pyproject/kctsb/thirdparty \
    --enable-static \
    --disable-shared \
    CFLAGS="-O3 -march=native"

make -j$(nproc)
make install
```

**Verify**: `ls /d/pyproject/kctsb/thirdparty/lib/libgf2x.a`

### Step 3: Install NTL (11.6.0)

```bash
cd /d/pyproject/kctsb/deps
wget https://libntl.org/ntl-11.6.0.tar.gz
tar xf ntl-11.6.0.tar.gz
cd ntl-11.6.0/src

# Configure with GMP and gf2x support
./configure PREFIX=/d/pyproject/kctsb/thirdparty \
    GMP_PREFIX=/d/pyproject/kctsb/thirdparty \
    GF2X_PREFIX=/d/pyproject/kctsb/thirdparty \
    NTL_GMP_LIP=on \
    NTL_GF2X_LIB=on \
    NTL_STD_CXX14=on \
    NTL_SAFE_VECTORS=off \
    TUNE=native \
    CXXFLAGS="-O3 -march=native"

make -j$(nproc)
make install
```

**Verify**: `ls /d/pyproject/kctsb/thirdparty/lib/libntl.a`

### Step 4: Install SEAL (Optional - 4.1.2)

```bash
cd /d/pyproject/kctsb/deps
git clone -b v4.1.2 https://github.com/microsoft/SEAL.git
cd SEAL

cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/d/pyproject/kctsb/thirdparty \
    -DSEAL_BUILD_DEPS=ON \
    -DSEAL_BUILD_EXAMPLES=OFF \
    -DSEAL_BUILD_TESTS=OFF \
    -DSEAL_BUILD_SEAL_C=OFF \
    -DBUILD_SHARED_LIBS=OFF

cmake --build build --parallel
cmake --install build
```

### Step 5: Install HElib (Optional - 2.3.0)

```bash
cd /d/pyproject/kctsb/deps
git clone -b v2.3.0 https://github.com/homenc/HElib.git
cd HElib

cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/d/pyproject/kctsb/thirdparty \
    -DGMP_DIR=/d/pyproject/kctsb/thirdparty \
    -DNTL_DIR=/d/pyproject/kctsb/thirdparty \
    -DBUILD_SHARED=OFF \
    -DENABLE_TEST=OFF \
    -DENABLE_THREADS=ON

cmake --build build --parallel
cmake --install build
```

---

## macOS Installation (Homebrew + Ninja)

### Prerequisites

```bash
xcode-select --install
brew install cmake ninja autoconf automake libtool wget
```

### Install Dependencies (Source Build)

```bash
export KCTSB_ROOT=~/projects/kctsb
export PREFIX=$KCTSB_ROOT/thirdparty
mkdir -p $KCTSB_ROOT/deps && cd $KCTSB_ROOT/deps

# GMP
wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz
tar xf gmp-6.3.0.tar.xz && cd gmp-6.3.0
./configure --prefix=$PREFIX --enable-cxx --enable-static --disable-shared
make -j$(sysctl -n hw.ncpu) && make install
cd ..

# gf2x
git clone https://gitlab.inria.fr/gf2x/gf2x.git && cd gf2x
autoreconf -i
./configure --prefix=$PREFIX --enable-static --disable-shared
make -j$(sysctl -n hw.ncpu) && make install
cd ..

# NTL
wget https://libntl.org/ntl-11.6.0.tar.gz
tar xf ntl-11.6.0.tar.gz && cd ntl-11.6.0/src
./configure PREFIX=$PREFIX GMP_PREFIX=$PREFIX GF2X_PREFIX=$PREFIX \
    NTL_GMP_LIP=on NTL_GF2X_LIB=on NTL_STD_CXX14=on TUNE=native
make -j$(sysctl -n hw.ncpu) && make install
```

---

## Linux Installation (Ubuntu/Debian)

### Prerequisites

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build git wget \
    autoconf automake libtool
```

### Install Dependencies (Source Build)

```bash
export KCTSB_ROOT=/path/to/kctsb
export PREFIX=$KCTSB_ROOT/thirdparty
mkdir -p $KCTSB_ROOT/deps && cd $KCTSB_ROOT/deps

# Same commands as macOS (use $(nproc) instead of sysctl)
```

---

## CMake Configuration

After installing all dependencies, configure kctsb:

```powershell
# Windows (PowerShell)
cd D:\pyproject\kctsb
cmake -B build -G Ninja `
    -DCMAKE_BUILD_TYPE=Release `
    -DKCTSB_BUILD_CLI=ON `
    -DKCTSB_BUILD_TESTS=ON `
    -DKCTSB_BUILD_BENCHMARKS=ON

cmake --build build --parallel
```

```bash
# Linux/macOS
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DKCTSB_BUILD_CLI=ON \
    -DKCTSB_BUILD_TESTS=ON

cmake --build build --parallel $(nproc)
```

---

## Verification

Run tests to verify the installation:

```bash
cd build
ctest --output-on-failure
./bin/kctsb version
```

Expected output:
```
╔════════════════════════════════════════════════════════════════╗
║  kctsb - Knight's Cryptographic Trusted Security Base         ║
╚════════════════════════════════════════════════════════════════╝

Version:      3.1.0
Build Date:   2026-01-12 (Beijing Time, UTC+8)
License:      Apache License 2.0
...
```

---

## Troubleshooting

### NTL Compilation Fails

**Error**: `cannot find -lgf2x`  
**Solution**: Ensure gf2x is installed to thirdparty/ before compiling NTL.

### SEAL Build Fails on Windows

**Error**: CMake cannot find ZLIB  
**Solution**: Install zlib via MSYS2: `pacman -S mingw-w64-ucrt-x86_64-zlib`

### Missing `gmpxx.h`

**Error**: `fatal error: gmpxx.h: No such file`  
**Solution**: Recompile GMP with `--enable-cxx` flag.

---

## Performance Optimization Flags

For maximum performance, all dependencies should be compiled with:

```bash
CFLAGS="-O3 -march=native -mtune=native -fomit-frame-pointer"
CXXFLAGS="-O3 -march=native -mtune=native -fomit-frame-pointer"
```

---

## Version Compatibility Matrix

| kctsb | GMP | gf2x | NTL | SEAL | HElib |
|-------|-----|------|-----|------|-------|
| 3.1.0 | 6.3.0 | 1.3.0 | 11.6.0 | 4.1.2 | 2.3.0 |
| 3.0.0 | 6.3.0 | 1.3.0 | 11.6.0 | 4.1.2 | 2.3.0 |

---

**Note**: All third-party libraries are compiled as static libraries to create a self-contained kctsb distribution without runtime dependencies.
