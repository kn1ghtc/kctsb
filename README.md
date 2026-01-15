# kctsb - Knight's Cryptographic Trusted Security Base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](.)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](.)
[![CMake](https://img.shields.io/badge/CMake-3.20+-green.svg)](.)
[![Version](https://img.shields.io/badge/Version-3.4.0-brightgreen.svg)](.)

**kctsb** 是一个跨平台的 C/C++ 密码学和安全算法库，专为生产环境和安全研究设计。目标是成为 **OpenSSL 的现代替代品**。

> **v3.4.0 更新**: 完成 "C++ Core + C ABI" 架构重构。移除所有冗余文件，统一为单文件单算法架构。Hash 算法包括 SHA-256/384/512、SHA3、BLAKE2b/s、SM3 完成重构并通过测试。

## ✨ 特性

### 对称加密算法
- **AES** - AES-128/192/256，支持 **CTR/GCM** 模式（v3.0 移除 ECB/CBC）
- **ChaCha20-Poly1305** - RFC 8439 AEAD 流密码 (v3.0 新增)
- **SM4-GCM** - 国密 SM4 分组密码，仅支持 GCM 认证加密模式

### AEAD 认证加密
- **AES-GCM** - Galois/Counter Mode，128-bit 认证标签
- **ChaCha20-Poly1305** - 256-bit 密钥，128-bit 标签

### 非对称加密算法
- **RSA** - RSA-2048/3072/4096 OAEP加密/PSS签名 (PKCS#1 v2.2)
- **ECC** - 完整椭圆曲线密码（secp256k1, P-256/384/521）**NTL原生实现**
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
- **BLAKE2/3** - 高性能哈希

### 安全原语
- **常量时间操作** - 防止时序攻击
- **安全内存** - 自动安全清零
- **CSPRNG** - 跨平台安全随机数

### 高级密码学原语
- **白盒密码** - Chow 白盒 AES/SM4 实现
- **秘密共享** - Shamir (t,n) 门限方案
- **功能加密** - BFV/CKKS 同态加密（通过 SEAL/HElib）

## 🏗️ 项目结构

```
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
│       │   ├── blake2.h        # BLAKE2b/s (RFC 7693)
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
│   │   ├── blake2.cpp          # BLAKE2b/s C++ 实现 + C ABI
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
│   ├── include/                # NTL/, gf2x/, gmp.h, SEAL-4.1/, helib/
│   └── lib/                    # libntl.a, libgf2x.a, libgmp.a, etc.
├── docs/                       # 文档
│   ├── releases/               # 版本发布说明
│   └── third-party-dependencies.md  # 源码安装指南
├── scripts/                    # 构建脚本
└── cmake/                      # CMake 模块
```

### 模块依赖关系

| 模块 | 依赖 | 状态 | 说明 |
|------|------|------|------|
| AES-CTR/GCM | 无 | ✅ 生产可用 | 原生C实现 + AES-NI |
| ChaCha20-Poly1305 | 无 | ✅ 生产可用 | 原生C实现 + AVX2 |
| Hash (SHA-3/BLAKE2) | 无 | ✅ 生产可用 | Keccak/BLAKE2原生 |
| SM3/SM4/ZUC | 无 | ✅ 生产可用 | 国密原生实现 |
| RSA-OAEP/PSS | NTL | ✅ 生产可用 | PKCS#1 v2.2 |
| ECC/ECDSA/ECDH/ECIES | NTL | ✅ 生产可用 | **完整重构** |
| DH/DSA | NTL | ✅ 生产可用 | RFC 3526/FIPS 186-4 |
| Kyber | NTL | ✅ 生产可用 | **ML-KEM (v3.2.0)** |
| Dilithium | NTL | ✅ 生产可用 | **ML-DSA (v3.2.0)** |
| zk-SNARKs | NTL | ✅ 生产可用 | **Groth16 (v3.2.0)** |
| SIMD | 无 | ✅ 生产可用 | **AVX2/AVX-512/AES-NI** |
| Whitebox AES | 无 | ✅ 可用 | Chow方案 |
| Shamir SSS | NTL | ✅ 可用 | 秘密共享 |
| FE (同态) | HElib | ✅ 可用 | HElib v2.3.0 |

**核心依赖** (thirdparty/):
- ✅ GMP 6.3.0+ (必需)
- ✅ gf2x 1.3.0+ (必需)
- ✅ NTL 11.6.0+ (必需)
- ⚠️ SEAL 4.1.2 (可选)
- ⚠️ HElib v2.3.0 (可选)

**测试状态**: 92 个测试 100% 通过（MinGW GCC 13.2 + Windows）

## 🚀 快速开始

### 系统要求

- **CMake**: 3.20 或更高版本
- **构建工具**: Ninja (推荐) 
- **编译器**:
  - Windows: MinGW-w64 GCC 13+ 或 MSVC 2022+
  - Linux: GCC 9+ 或 Clang 10+
  - macOS: Clang 10+ 或 GCC 9+
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
cmake --build build --parallel

# 运行测试
ctest --test-dir build --output-on-failure

# 使用CLI工具
.\build\bin\kctsb.exe version
.\build\bin\kctsb.exe hash --sha3-256 "Hello, World!"
```

### 构建脚本选项 (v3.2.1)

```powershell
# 快速构建 + 单元/集成测试（推荐日常使用，约1分钟）
.\scripts\build.ps1 -All

# 完整构建 + 所有测试 + OpenSSL对比基准测试
.\scripts\build.ps1 -Full -UseVcpkg

# 仅构建，不运行测试
.\scripts\build.ps1 -Clean

# 按标签运行测试
ctest -L unit --test-dir build           # 仅单元测试
ctest -L integration --test-dir build    # 仅集成测试
ctest -L performance --test-dir build    # 仅性能测试
```

**测试状态**: 92 个测试通过（单元测试 + 集成测试 + 性能测试）

> 重要提示（Windows Toolchain）：默认使用 `C:\msys64\mingw64` gcc/g++ 进行配置，脚本会自动设置 `CC/CXX` 及 CMake 编译器路径以避免 Strawberry Perl 工具链差异。HElib 现为默认开启依赖，若缺失请先运行 `scripts\build_helib.ps1`（或同名 bash 脚本）将产物放置到 `thirdparty/include` 与 `thirdparty/lib` 后再执行构建。如需使用 vcpkg，仅在基准测试场景下显式添加 `-UseVcpkg` 开关。构建期间自动设置 `KCTSB_BUILDING`/`KCTSB_SHARED_LIBRARY` 以确保 Windows 动态库正确导出符号、无 dllimport 警告；GCC 下已屏蔽 NTL 的 `-Warray-bounds`/`-Wstringop-overflow` 误报，核心源码保持零告警。

> Windows 编译提示（MinGW-w64 GCC 13+）：
> - 已对 `src/utils/encoding.cpp` 的 uint64 解码路径进行显式初始化，避免 `-Werror=uninitialized` 在 Release 模式下拦截构建。
> - RFC 6979 确定性 ECDSA 现使用库内 SHA-256 HMAC，替换早期占位实现并消除潜在溢出警告。
> - NTL 头文件在 GCC 下可能输出编译器误报，已通过精细化编译选项屏蔽；如需完全零告警也可使用 MSVC。

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

### C API - AES-GCM 认证加密

```c
#include <kctsb/kctsb.h>

int main() {
    // 初始化库
    kctsb_init();

    // AES-GCM 加密 (推荐 v3.0+)
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t iv[12] = {0};  // 12 bytes for GCM
    uint8_t plaintext[32] = "Hello, World! kctsb v3.0";
    uint8_t ciphertext[32];
    uint8_t tag[16];

    kctsb_aes_ctx_t ctx;
    kctsb_aes_init(&ctx, key, 16);
    kctsb_aes_gcm_encrypt(&ctx, iv, 12, NULL, 0,
                          plaintext, 32, ciphertext, tag);
    kctsb_aes_clear(&ctx);

    kctsb_cleanup();
    return 0;
}
```

### C API - ChaCha20-Poly1305 AEAD

```c
#include <kctsb/kctsb.h>

int main() {
    uint8_t key[32] = { /* 256-bit key */ };
    uint8_t nonce[12] = { /* 96-bit nonce */ };
    uint8_t aad[] = "Additional authenticated data";
    uint8_t plaintext[] = "Secret message";
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t tag[16];

    kctsb_chacha20_poly1305_encrypt(key, nonce,
                                     aad, sizeof(aad)-1,
                                     plaintext, sizeof(plaintext)-1,
                                     ciphertext, tag);
    return 0;
}
```

### C++ API

```cpp
#include <kctsb/kctsb.h>

int main() {
    using namespace kctsb;

    // 安全随机数
    auto random_bytes = randomBytes(32);

    // AES-GCM 加密
    std::array<uint8_t, 16> key = {0x00, 0x01, /* ... */};
    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

    // 使用安全比较
    std::vector<uint8_t> a = {1, 2, 3};
    std::vector<uint8_t> b = {1, 2, 3};
    bool equal = kctsb_secure_compare(a.data(), b.data(), 3) == 1;

    return 0;
}
```

## � 跨平台 Release 构建

kctsb 支持 Windows, Linux, macOS 三平台的预编译分发：

```
release/
├── bin/                    # Windows/macOS CLI 工具
│   ├── kctsb               # macOS x64
│   └── kctsb_benchmark     # macOS x64 benchmark
├── lib/                    # Windows/macOS 库文件
├── include/                # 共享头文件
├── linux-x64/              # Linux x64 专用
│   ├── bin/kctsb-linux-x64 # Linux CLI (glibc 2.17+)
│   ├── lib/libkctsb-linux-x64.a  # 静态库 (1.4 MB)
│   └── include/            # Linux 专用头文件
└── RELEASE_INFO.txt
```

### 平台兼容性

| 平台 | 编译器 | 最低要求 | 构建方式 |
|------|--------|----------|----------|
| Windows x64 | MinGW GCC 13+ / MSVC 2022 | Windows 10+ | `.\scripts\build.ps1` |
| Linux x64 | GCC 11.2.1 (CentOS 7) | glibc 2.17 | `./scripts/docker_build.sh` |
| macOS x64 | AppleClang 15+ | macOS 10.15+ | `./scripts/build.sh` |

## �🔧 CMake 选项

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
# 示例：完整构建（推荐）- 使用 VCPKG_ROOT 环境变量
cmake -B build -G "MinGW Makefiles" `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
    -DKCTSB_BUILD_BENCHMARKS=ON

# 示例：完整构建带NTL（需要先编译NTL）
cmake -B build -G "MinGW Makefiles" `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
    -DNTL_ROOT="D:\libs\ntl" `
    -DKCTSB_BUILD_BENCHMARKS=ON

# 示例：最小构建（无外部依赖）
cmake -B build -DKCTSB_ENABLE_NTL=OFF -DKCTSB_ENABLE_GMP=OFF -DKCTSB_ENABLE_OPENSSL=OFF
```

## 📊 性能对比 (vs OpenSSL)

kctsb v3.3.2 提供与 OpenSSL 的性能对比基准测试：

```bash
# 运行性能测试
./scripts/build.sh --benchmark
# 或直接运行
./build/bin/kctsb_benchmark
```

### 性能测试结果 (2026-01-15, OpenSSL 3.6.0)

**测试环境**: macOS 13.7.8, Intel i7-7567U, AppleClang 15.0, OpenSSL 3.6.0

#### 🏆 亮点表现

| 算法 | OpenSSL | kctsb | 性能比率 | 状态 |
|------|---------|-------|----------|------|
| **SHA3-256** | 287 MB/s | **301 MB/s** | **105%** | ✅ 超越OpenSSL |
| **BLAKE2b-256** | 565 MB/s | **523 MB/s** | **93%** | ✅ 生产级 |
| **AES-256-GCM** | 3,005 MB/s | **337 MB/s** | **11%** | ✅ AES-NI优化 |
| **ChaCha20-Poly1305** | 1,485 MB/s | **290 MB/s** | **20%** | ✅ AVX2优化 |

#### v3.3.2 优化成果

| 算法 | v3.3.1 | v3.3.2 | 提升倍数 | 优化技术 |
|------|--------|--------|----------|----------|
| **AES-256-GCM** | 8 MB/s | **337 MB/s** | **42x** | AES-NI + PCLMUL GHASH |
| **AES-128-GCM** | 12 MB/s | **386 MB/s** | **32x** | AES-NI + PCLMUL GHASH |
| **RSA-3072/4096** | ❌ Error | ✅ 正常 | - | OS2IP/I2OSP 大端修复 |

**核心优化**:
- ✅ **AES-NI 硬件加速**: AES-128/256 块加密使用 Intel AES-NI 指令
- ✅ **PCLMUL GHASH**: GCM 模式使用 CLMUL 指令进行 GF(2^128) 乘法
- ✅ **AES-256 完整支持**: 实现了 AES-256 的完整 AES-NI 密钥扩展和块加密
- ✅ **RSA 大密钥修复**: 修复了 OS2IP/I2OSP 的字节序问题，支持 RSA-3072/4096

#### 📈 RSA/ECC 非对称算法

| 算法 | OpenSSL | kctsb | 性能比率 | 状态 |
|------|---------|-------|----------|------|
| RSA-2048 OAEP 解密 | 1,096 op/s | 296 op/s | 27% | ✅ NTL+CRT |
| RSA-4096 PSS 签名 | 208 op/s | 37 op/s | 18% | ✅ NTL+CRT |
| SM3 Hash | 182 MB/s | 156 MB/s | 86% | ✅ 生产级 |
| SM4-GCM | 86 MB/s | 55 MB/s | 64% | ✅ AEAD安全模式 |

详细分析报告见 [docs/benchmark-analysis/](docs/benchmark-analysis/) 目录。

## 📚 API 文档

详细 API 文档请参阅各头文件中的 Doxygen 注释：

- [kctsb.h](include/kctsb/kctsb.h) - 主入口和版本信息
- [core/common.h](include/kctsb/core/common.h) - 错误码和通用定义
- [crypto/aes.h](include/kctsb/crypto/aes.h) - AES 加密 API
- [crypto/sha.h](include/kctsb/crypto/sha.h) - SHA 哈希 API


## ⚠️ 安全声明

### 生产环境使用

kctsb v3.0.0 的核心算法（AES-GCM, ChaCha20-Poly1305, **SHA-256/384/512**, SHA3, BLAKE2, SM3/SM4）经过标准测试向量验证，可用于生产环境。

**使用建议**：
1. **代码审计**: 部署前建议进行独立安全审计
2. **侧信道防护**: 软件实现可能存在时序侧信道，高安全需求建议使用硬件加速
3. **密钥管理**: 密钥应存储在HSM或安全密钥库中

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
- [RFC 7693 (BLAKE2)](https://tools.ietf.org/html/rfc7693)
- GM/T 0002-2012 (SM4), GM/T 0003-2012 (SM2), GM/T 0004-2012 (SM3)

### 依赖库
- [NTL: A Library for doing Number Theory](https://libntl.org/) (v11.6.0+)
- [GMP: The GNU Multiple Precision Arithmetic Library](https://gmplib.org/)
- [Microsoft SEAL](https://github.com/microsoft/SEAL) (v4.1.2)
- [HElib](https://github.com/homenc/HElib) (v2.3.0)
