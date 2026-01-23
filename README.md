# kctsb - Knight's Cryptographic Trusted Security Base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](.)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](.)
[![CMake](https://img.shields.io/badge/CMake-3.20+-green.svg)](.)
[![Version](https://img.shields.io/badge/Version-4.9.0-brightgreen.svg)](.)

**kctsb** 是一个跨平台的 C/C++ 密码学和安全算法库，专为生产环境和安全研究设计。目标是成为 **OpenSSL 的现代替代品**。


## ✨ 特性

### 对称加密算法
- **AES** - AES-128/192/256，支持 **CTR/GCM** 模式（移除 ECB/CBC的不安全模式）
- **ChaCha20-Poly1305** - RFC 8439 AEAD 流密码 
- **SM4-GCM** - 国密 SM4 分组密码，仅支持 GCM 认证加密模式

### AEAD 认证加密
- **AES-GCM** - Galois/Counter Mode，128-bit 认证标签
- **ChaCha20-Poly1305** - 256-bit 密钥，128-bit 标签

### 非对称加密算法
- **RSA** - RSA-2048/3072/4096 OAEP加密/PSS签名 (PKCS#1 v2.2)
- **ECC** - 完整椭圆曲线密码（secp256k1, P-256）**原生实现**
- **ECDSA** - RFC 6979 确定性签名
- **ECDH** - RFC 5869 HKDF 密钥派生
- **ECIES** - 混合加密 (ECDH + AES-GCM)
- **SM2** - 国密 SM2 椭圆曲线
- **DH** - Diffie-Hellman 密钥交换 (RFC 3526)
- **DSA** - FIPS 186-4 数字签名

### 后量子密码
- **Kyber** - ML-KEM (FIPS 203), 512/768/1024
- **Dilithium** - ML-DSA (FIPS 204), Level 2/3/5

### 零知识证明
- **zk-SNARKs** - Groth16 协议 (BN254 曲线)
- **电路构建器** - 乘法门、加法门、布尔约束、范围证明

### SIMD 硬件加速 (v3.3.2 完整实现)
- **AES-NI** - 硬件 AES-128/256 加速 (Intel Westmere+) ✅ **42x 提速**
- **PCLMUL** - GHASH 硬件加速 (GF(2^128) 乘法) ✅ **GCM 模式优化**
- **SHA-NI** - 硬件 SHA-256 加速 (Intel Goldmont+)
- **AVX2** - Keccak/SHA3-256 向量化优化
- **AVX-512** - 512-bit 向量化运算
- **常量时间操作** - 防止侧信道攻击

### 哈希算法
- **SHA** - SHA-1/256/384/512 (SHA-NI 加速)
- **SHA3** - SHA3-256 (AVX2 优化)
- **SM3** - 国密 SM3 哈希
- **BLAKE2b** - RFC 7693 高性能哈希

### 安全原语
- **常量时间操作** - 防止时序攻击
- **安全内存** - 自动安全清零
- **CSPRNG** - 跨平台安全随机数

### 高级密码学原语
- **白盒密码** - Chow 白盒 AES/SM4 实现
- **秘密共享** - Shamir (t,n) 门限方案
- **同态加密 (v4.9.0)** ✅ **三大方案完整实现 + NTT Barrett优化**
  - **BGV 方案** - 原生实现，精确整数同态加密 ✅
    - 密钥生成、加密/解密、加法/乘法/重线性化
    - 噪声预算管理、批量编码 (SIMD slots)
    - 43/43 单元测试 100% 通过 (NTT+Barrett加速)
  - **BFV 方案 (v4.7.0)** - Scale-invariant 编码，复用 BGV 基础设施 ✅
    - 完整加密/解密/运算支持
    - 26/26 单元测试通过
  - **CKKS 方案 (v4.8.0)** - 近似实数/复数同态加密 ✅
    - FFT 正则嵌入编码，支持复数向量
    - Rescale 机制控制精度和噪声
    - 多层乘法深度支持 (3-5 层)
    - 33/33 单元测试 100% 通过
  - **性能优化 (v4.9.0)** - NTT Barrett 模运算加速 ✅ **NEW**
    - mul_mod_barrett 替换慢速 128-bit 除法
    - CRT 预计算常量优化
    - 50-bit 大素数混合处理
    - **2-3x 整体性能提升**

## 🏗️ 项目结构

```shell
kctsb/
├── CMakeLists.txt              # 主构建配置 (CMake 3.20+, Ninja推荐)
├── README.md                   # 项目文档
├── AGENTS.md                   # AI开发指南
├── LICENSE                     # Apache 2.0 许可证
│
├── include/                    # ★所有头文件在这里★
│   └── kctsb/
│       ├── kctsb.h             # 主入口头文件
│       ├── core/               # 核心定义
│       ├── crypto/             # 标准密码算法公共头 (v3.4.0 简化)
│       │   ├── aes.h           # AES-GCM
│       │   ├── chacha20_poly1305.h  # ChaCha20-Poly1305
│       │   ├── sha256.h        # SHA-256 (FIPS 180-4)
│       │   ├── sha512.h        # SHA-512/384 (FIPS 180-4)
│       │   ├── sha3.h          # SHA3/SHAKE (FIPS 202)
│       │   ├── blake2.h        # BLAKE2b (RFC 7693)
│       │   ├── sm3.h           # SM3 (GB/T 32905-2016)
│       │   ├── sm4.h           # SM4-GCM (GB/T 32907-2016)
│       │   ├── ecc/, rsa/      # 非对称算法头
│       │   └── sm/             # 国密算法头 (ZUC)
│       ├── advanced/           # 高级密码学
│       │   ├── pqc/            # 后量子密码 (Kyber, Dilithium)
│       │   ├── zk/             # 零知识证明 (Groth16)
│       │   ├── fe/             # 功能加密
│       │   ├── sss/            # 秘密共享
│       │   └── whitebox/       # 白盒密码
│       ├── simd/               # SIMD 硬件加速
│       │   └── simd.h          # AVX2/AVX-512/AES-NI
│       ├── math/               # 数学工具
│       └── utils/              # 实用工具
│
├── src/                        # ★源代码实现 (v3.4.0 扁平化)★
│   ├── core/                   # 核心功能
│   ├── crypto/                 # 密码算法实现 (单文件单算法)
│   │   ├── sha256.cpp          # SHA-256 C++ 实现 + C ABI
│   │   ├── sha512.cpp          # SHA-512/384 C++ 实现 + C ABI
│   │   ├── sha3.cpp            # SHA3/SHAKE C++ 实现 + C ABI
│   │   ├── blake2.cpp          # BLAKE2b C++ 实现 + C ABI
│   │   ├── sm3.cpp             # SM3 C++ 实现 + C ABI
│   │   ├── sm4.cpp             # SM4-GCM C++ 实现 + C ABI
│   │   ├── aes/                # AES-GCM 实现
│   │   ├── chacha20/           # ChaCha20-Poly1305
│   │   ├── ecc/                # 椭圆曲线 (NTL实现)
│   │   └── rsa/                # RSA (NTL实现)
│   ├── advanced/               # 高级算法实现
│   │   ├── pqc/                # 后量子密码实现
│   │   └── zk/                 # 零知识证明实现
│   ├── simd/                   # SIMD 加速实现
│   ├── cli/                    # 命令行工具
│   └── math/                   # 数学库
│
├── tests/                      # GoogleTest测试代码
├── benchmarks/                 # 性能对比测试 (vs OpenSSL)
├── thirdparty/                 # ★第三方库统一目录★
│   ├── win-x64/                # Windows x64 平台特定库 (可选)
│   ├── linux-x64/              # Linux x64 平台特定库 (可选)
│   ├── macos-x64/              # macOS x64 平台特定库 (可选)
│   ├── include/                # NTL/, gf2x/, gmp.h, SEAL-4.1/, helib/
│   └── lib/                    # libntl.a, libgf2x.a, libgmp.a, etc.
├── release/                    # ★跨平台发布目录★
│   ├── win-x64/                # Windows x64 构建产物
│   │   ├── bin/kctsb.exe       # CLI 工具 (全静态链接)
│   │   ├── lib/
│   │   │   ├── libkctsb.a      # 静态库
│   │   │   └── libkctsb_bundled.a  # ★ 打包库（含所有依赖）★
│   │   └── include/kctsb_api.h # 唯一公共头文件
│   └── linux-x64/              # Linux x64 构建产物
│       ├── bin/kctsb           # CLI 工具 (全静态链接)
│       ├── lib/
│       │   ├── libkctsb.a      # 静态库
│       │   └── libkctsb_bundled.a  # ★ 打包库（含所有依赖）★
│       └── include/kctsb_api.h # 唯一公共头文件
├── docs/                       # 文档
│   ├── releases/               # 版本发布说明
│   └── third-party-dependencies.md  # 源码安装指南
├── scripts/                    # 构建脚本
└── cmake/                      # CMake 模块
```

**核心依赖** (thirdparty/):
- ✅ GMP 6.3.0+ (必需)
- ✅ gf2x 1.3.0+ (必需)
- ⚠️ SEAL 4.1.2 (可选)
- ⚠️ HElib v2.3.0 (可选)

**测试状态**: 263 个测试 100% 通过（MinGW GCC 15 + Windows）

## 🚀 快速开始

### 系统要求

- **CMake**: 3.20 或更高版本
- **构建工具**: Ninja (推荐) 
- **编译器**:
  - Windows: MinGW-w64 GCC 13+ 
  - Linux: GCC 12+ 
  - macOS:  GCC 12+
- **C++ 标准**: C++17
- **C 标准**: C11

### Windows 构建 (推荐 Ninja)

```powershell
# 进入项目目录
cd D:\pyproject\kctsb

# 配置 (使用Ninja构建)
cmake -B build -G Ninja `
    -DCMAKE_BUILD_TYPE=Release `
    -DKCTSB_BUILD_CLI=ON `
    -DKCTSB_BUILD_TESTS=ON

# 构建
cmake --build build-release --parallel
#或者
ninja.exe -C build-release -j8 2>&1

#或直接一句话：
$env:PATH="C:\msys64\mingw64\bin;$env:PATH"; cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DKCTSB_BUILD_BENCHMARKS=ON
$env:PATH="C:\msys64\mingw64\bin;$env:PATH"; cmake --build build-release --parallel; .\build-release\bin\kctsb_benchmark.exe aes
```

# 运行测试
$env:PATH="C:\msys64\mingw64\bin;$env:PATH"; ctest --test-dir build --output-on-failure
$env:PATH="C:\msys64\mingw64\bin;$env:PATH"; ctest --test-dir build-release --output-on-failure

# 使用CLI工具
```shell
.\build-release\bin\kctsb.exe version
.\build-release\bin\kctsb.exe hash --sha3-256 "Hello, World!"
```

**Windows 环境变量统一（MSYS2）**

为避免多套编译器/`cmake` 冲突，建议在系统环境中固定以下变量，并重启终端生效：

- `MSYS2_ROOT = C:\msys64`
- `MSYS2_MINGW64_BIN = C:\msys64\mingw64\bin`
- `CC = C:\msys64\mingw64\bin\gcc.exe`
- `CXX = C:\msys64\mingw64\bin\g++.exe`
- `CMAKE_MAKE_PROGRAM = C:\msys64\mingw64\bin\ninja.exe`
- `VCPKG_ROOT = D:\vcpkg`

确保 `PATH` 以 `C:\msys64\mingw64\bin;C:\msys64\usr\bin` 开头。

### 构建脚本选项

```powershell
# 快速构建 + 单元/集成测试（推荐日常使用，约1分钟）
.\scripts\build.ps1 -All

# 完整构建 + 所有测试 + OpenSSL对比基准测试
.\scripts\build.ps1 -Full 

# 仅构建，不运行测试
.\scripts\build.ps1 -Clean

# 按标签运行测试
ctest -L unit --test-dir build           # 仅单元测试
ctest -L integration --test-dir build    # 仅集成测试
ctest -L performance --test-dir build    # 仅性能测试
```

### Linux Docker 构建 (CentOS 7, glibc 2.17)

使用 Docker 在 CentOS 7 环境下构建，确保最大的 Linux 兼容性：

```bash
# 在 WSL2 或原生 Linux 下执行
cd /path/to/kctsb
./scripts/docker_build.sh

# 构建产物位于 release/linux-x64/
ls -la release/linux-x64/bin/     # CLI 工具: kctsb
ls -la release/linux-x64/lib/     # 静态库: libkctsb.a (1.4 MB)
ls -la release/linux-x64/include/ # 头文件
```

**Docker 构建特性**:
- 基于 CentOS 7 + devtoolset-11 (GCC 11.2.1)
- glibc 2.17 兼容性（支持 RHEL 7+, Ubuntu 18.04+, Debian 9+）
- CMake 3.28.3, NTL 11.6.0, GMP 6.3.0 内置
- 自动生成平台特定命名: `kctsb-linux-x64`, `libkctsb-linux-x64.a`

### Linux/macOS 原生构建

```bash
# 1. 克隆项目
cd /path/to/kctsb

# 2. 使用构建脚本
./scripts/build.sh --test

# 或手动构建
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)

# 3. 运行测试
cd build && ctest --output-on-failure

# 4. 运行示例
./build/bin/kctsb_demo
```

### VS Code 集成

1. 打开 `kctsb` 目录作为工作区
2. 安装推荐扩展：C/C++, CMake Tools
3. 使用 `Ctrl+Shift+B` 构建
4. 使用 `F5` 调试

## 📖 使用示例

### Secure Computation Demo (Headless)

`docs/examples/psi/SecureComputationDemo.py` 仅生成 HTML 报告与日志输出，不会弹出图形窗口或生成图像文件。

### 统一公共 API 头文件 

从 v3.4.0 开始，kctsb 采用类似 OpenSSL EVP 的设计，**外部用户只需包含单个头文件**：

```c
// 外部用户只需要这一个头文件
#include <kctsb_api.h>

// 所有公共 API 都在这个头文件中定义：
// - 哈希: kctsb_sha256(), kctsb_sha3_256(), kctsb_blake2b(), kctsb_sm3()
// - AEAD: kctsb_aes_gcm_encrypt/decrypt(), kctsb_chacha20_poly1305_*(), kctsb_sm4_gcm_*()
// - MAC: kctsb_hmac_sha256(), kctsb_cmac_aes()
// - 安全: kctsb_secure_compare(), kctsb_secure_zero(), kctsb_random_bytes()
```

**Release 包内容** 
```
release/
├── linux-x64/
│   ├── bin/kctsb                    # CLI 工具 (1.5 MB, 全静态链接)
│   ├── lib/
│   │   ├── libkctsb.a               # 静态库 (4.7 MB, 需链接 NTL/GMP 等)
│   │   └── libkctsb_bundled.a       # ★ 打包库 (13 MB, 包含所有依赖) ★
│   └── include/kctsb_api.h          # 唯一公共头文件
│
└── win-x64/
    ├── bin/kctsb.exe                # CLI 工具 (3.3 MB, 仅需Windows系统DLL)
    ├── lib/
    │   ├── libkctsb.a               # 静态库 (4.7 MB)
    │   └── libkctsb_bundled.a       # ★ 打包库 (6.2 MB) ★
    └── include/kctsb_api.h          # 唯一公共头文件
```

### 库文件选择指南

| 库文件 | 大小 | 依赖 | 适用场景 |
|--------|------|------|----------|
| `libkctsb.a` | ~5 MB | 需额外链接 GMP/SEAL/HElib | 已有这些库的项目 |
| `libkctsb.dll/.so` | ~3 MB | 运行时加载 | 多进程共享、热更新 |

### 集成示例 (推荐: Bundled 库)

**Linux (GCC)**:
```bash
# 方法1: 使用 bundled 库（推荐，单文件链接）
g++ -O3 myapp.cpp -I./include -L./lib -lkctsb_bundled -lz -lpthread -ldl -o myapp

# 方法2: 使用标准库（需要链接所有依赖）
g++ -O3 myapp.cpp -I./include -L./lib \
    -lkctsb -lntl -lgmp -lgf2x -lseal-4.1 -lhelib \
    -lz -lpthread -o myapp
```

**Windows (MinGW-w64)**:
```powershell
# 方法1: 使用 bundled 库（推荐）
g++ -O3 myapp.cpp -I.\include -L.\lib -lkctsb_bundled -lbcrypt -lws2_32 -o myapp.exe

# 方法2: 标准库
g++ -O3 myapp.cpp -I.\include -L.\lib `
    -lkctsb -lntl -lgmp -lgf2x -lseal-4.1 -lhelib `
    -lbcrypt -lws2_32 -o myapp.exe
```

**CMake 项目集成**:
```cmake
# 使用 bundled 库（推荐）
add_executable(myapp main.cpp)
target_include_directories(myapp PRIVATE ${KCTSB_DIR}/include)
target_link_libraries(myapp PRIVATE
    ${KCTSB_DIR}/lib/libkctsb_bundled.a
    ZLIB::ZLIB
    Threads::Threads
    ${CMAKE_DL_LIBS}
)
if(WIN32)
    target_link_libraries(myapp PRIVATE bcrypt ws2_32)
endif()
```

## CMake 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `KCTSB_BUILD_SHARED` | ON | 构建共享库 |
| `KCTSB_BUILD_STATIC` | ON | 构建静态库 |
| `KCTSB_BUILD_TESTS` | ON | 构建测试 |
| `KCTSB_BUILD_EXAMPLES` | ON | 构建示例 |
| `KCTSB_BUILD_BENCHMARKS` | ON | 构建性能对比测试 |
| `KCTSB_ENABLE_NTL` | **ON** | 使用NTL库 (ECC/RSA/格密码) |
| `KCTSB_ENABLE_GMP` | **ON** | 使用GMP库 (高精度运算) |
| `KCTSB_ENABLE_OPENSSL` | **ON** | 使用OpenSSL (性能对比) |
| `KCTSB_ENABLE_SEAL` | **ON** | 使用Microsoft SEAL (同态加密) |
| `KCTSB_ENABLE_HELIB` | **ON** | 使用HElib (函数加密) |

```powershell
ninja.exe -C build -j8 2>&1 
```


## 📚 API 文档

### 统一公共 API

从 v3.4.0 开始，所有公共 API 都集中在单个头文件中：

- **[kctsb_api.h](include/kctsb/kctsb_api.h)** - 唯一公共头文件 (推荐)
  - 包含所有算法的公共 API
  - 平台检测和导出宏
  - 错误码定义
  - 可选的 C++ 命名空间

### 内部头文件 (仅供库内部使用)

以下头文件供库开发维护使用，外部用户无需关心：

- [core/common.h](include/kctsb/core/common.h) - 错误码和通用定义
- [crypto/aes.h](include/kctsb/crypto/aes.h) - AES 加密实现
- [crypto/sha256.h](include/kctsb/crypto/sha256.h) - SHA-256 实现
- [crypto/sha3.h](include/kctsb/crypto/sha3.h) - SHA3 实现
- [crypto/blake2.h](include/kctsb/crypto/blake2.h) - BLAKE2 实现
- [crypto/chacha20_poly1305.h](include/kctsb/crypto/chacha20_poly1305.h) - ChaCha20-Poly1305 实现
- [gm/sm3.h](include/kctsb/gm/sm3.h) - SM3 国密哈希
- [gm/sm4.h](include/kctsb/gm/sm4.h) - SM4 国密对称加密



## 🔒 变更策略

本项目仅允许核心维护者进行代码变更，外部或非授权修改不予接受。

### 开源协议

本项目采用 **Apache License 2.0**，允许商业使用、修改和分发。

## 📄 许可证

本项目采用 Apache License 2.0 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 👤 作者

**knightc** (owner: tsb)

Copyright © 2019-2026 knightc. All rights reserved.

## 🔗 参考资料

### 标准文档
- [FIPS 180-4 (SHA-256/384/512)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [FIPS 197 (AES)](https://csrc.nist.gov/publications/detail/fips/197/final)
- [FIPS 202 (SHA-3)](https://csrc.nist.gov/publications/detail/fips/202/final)
- [RFC 7539 (ChaCha20-Poly1305)](https://tools.ietf.org/html/rfc7539)
- [RFC 7693 (BLAKE2b)](https://tools.ietf.org/html/rfc7693)
- GM/T 0002-2012 (SM4), GM/T 0003-2012 (SM2), GM/T 0004-2012 (SM3)

### 依赖库
- [GMP: The GNU Multiple Precision Arithmetic Library](https://gmplib.org/)
- [Microsoft SEAL](https://github.com/microsoft/SEAL) (v4.1.2)
- [HElib](https://github.com/homenc/HElib) (v2.3.0)
