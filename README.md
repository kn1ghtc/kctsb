# kctsb - Knight's Cryptographic Trusted Security Base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](.)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](.)
[![CMake](https://img.shields.io/badge/CMake-3.20+-green.svg)](.)
[![Version](https://img.shields.io/badge/Version-3.1.0-brightgreen.svg)](.)

**kctsb** 是一个跨平台的 C/C++ 密码学和安全算法库，专为生产环境和安全研究设计。目标是成为 **OpenSSL 的现代替代品**。

> **v3.1.0 新特性**: 移除MIRACL依赖，椭圆曲线算法使用NTL原生实现；源码中完全移除OpenSSL依赖；所有头文件统一到include/目录。

## ✨ 特性

### 对称加密算法
- **AES** - AES-128/192/256，支持 **CTR/GCM** 模式（v3.0 移除 ECB/CBC）
- **ChaCha20-Poly1305** - RFC 8439 AEAD 流密码 (v3.0 新增)
- **SM4** - 国密 SM4 分组密码

### AEAD 认证加密 (v3.0 强化)
- **AES-GCM** - Galois/Counter Mode，128-bit 认证标签
- **ChaCha20-Poly1305** - 256-bit 密钥，128-bit 标签

### 非对称加密算法
- **RSA** - RSA-2048/4096 加密签名 (NTL实现)
- **ECC** - 椭圆曲线密码（secp256k1, P-256, SM2曲线）**NTL原生实现**
- **SM2** - 国密 SM2 椭圆曲线

### 哈希算法
- **SHA** - SHA-1/256/384/512
- **SM3** - 国密 SM3 哈希
- **BLAKE2/3** - 高性能哈希

### 安全原语 (v3.0 新增)
- **常量时间操作** - 防止时序攻击
- **安全内存** - 自动安全清零
- **CSPRNG** - 跨平台安全随机数

### 高级密码学原语
- **白盒密码** - Chow 白盒 AES/SM4 实现
- **秘密共享** - Shamir (t,n) 门限方案
- **零知识证明** - Schnorr 协议、Sigma 协议
- **格密码** - 后量子密码原语
- **同态加密** - BFV/CKKS 方案（通过 SEAL/HElib）

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
│       ├── crypto/             # 标准密码算法公共头
│       │   ├── aes.h, blake.h, chacha.h, etc.
│       │   ├── hash/           # 哈希算法实现头
│       │   ├── ecc/, rsa/      # 非对称算法头
│       │   └── sm/             # 国密算法头
│       ├── advanced/           # 高级密码学
│       ├── internal/           # 内部实现头文件
│       │   ├── blake2_impl.h
│       │   ├── keccak_impl.h
│       │   └── ecc_impl.h      # NTL ECC实现
│       ├── math/               # 数学工具
│       └── utils/              # 实用工具
│
├── src/                        # ★源代码实现 (禁止放头文件)★
│   ├── core/                   # 核心功能
│   ├── crypto/                 # 密码算法实现
│   │   ├── aes/                # AES 实现
│   │   ├── chacha20/           # ChaCha20-Poly1305
│   │   ├── hash/               # 哈希算法 (原生实现)
│   │   ├── ecc/                # 椭圆曲线 (NTL实现)
│   │   ├── rsa/                # RSA (NTL实现)
│   │   └── sm/                 # 国密算法 (原生实现)
│   ├── advanced/               # 高级算法实现
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
| AES-CTR/GCM | 无 | ✅ 生产可用 | 原生C实现 |
| ChaCha20-Poly1305 | 无 | ✅ 生产可用 | 原生C实现 |
| Hash (SHA-3/BLAKE2) | 无 | ✅ 生产可用 | Keccak/BLAKE2原生 |
| SM3/SM4/ZUC | 无 | ✅ 生产可用 | 国密原生实现 |
| RSA | NTL | ✅ 生产可用 | NTL大数运算 |
| ECC/ECDSA | NTL | ✅ 生产可用 | **NTL原生实现** |
| Whitebox AES | 无 | ✅ 可用 | Chow方案 |
| Shamir SSS | NTL | ✅ 可用 | 秘密共享 |
| ZK (FFS) | NTL | ✅ 可用 | 零知识证明 |
| Lattice | NTL | ✅ 可用 | 格密码 |
| FE (同态) | HElib | ⚠️ 可选 | HElib v2.3.0 |

**核心依赖** (thirdparty/):
- ✅ GMP 6.3.0+ (必需)
- ✅ gf2x 1.3.0+ (必需)
- ✅ NTL 11.6.0+ (必需)
- ⚠️ SEAL 4.1.2 (可选)
- ⚠️ HElib v2.3.0 (可选)

**测试状态**: 72/72 通过 (100%)

## 🚀 快速开始

### 系统要求

- **CMake**: 3.20 或更高版本
- **构建工具**: Ninja (推荐) 或 Make
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

### Linux/macOS 构建

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

## 🔧 CMake 选项

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
| `KCTSB_ENABLE_HELIB` | OFF | 使用HElib (函数加密) |

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

kctsb v3.0.0 提供与 OpenSSL 的性能对比基准测试：

```powershell
# 运行性能测试
.\build\bin\kctsb_benchmark.exe
```

### 性能测试结果 (2026-01-12, OpenSSL 3.6.0)

| 算法 | 数据大小 | 吞吐量 | 平均延迟 |
|------|----------|--------|----------|
| AES-256-GCM (加密) | 10 MB | 6356 MB/s | 1.57 ms |
| AES-256-GCM (解密) | 10 MB | 6541 MB/s | 1.53 ms |
| ChaCha20-Poly1305 (加密) | 10 MB | 2387 MB/s | 4.19 ms |
| ChaCha20-Poly1305 (解密) | 10 MB | 2216 MB/s | 4.51 ms |
| SHA-256 | 10 MB | 2095 MB/s | 4.77 ms |
| SHA3-256 | 10 MB | 579 MB/s | 17.26 ms |
| BLAKE2b-256 | 10 MB | 1077 MB/s | 9.28 ms |

**测试环境**: Windows 11, MinGW GCC 13.2.0, vcpkg OpenSSL 3.6.0

详细基准测试代码见 [benchmarks/](benchmarks/) 目录。

## 📚 API 文档

详细 API 文档请参阅各头文件中的 Doxygen 注释：

- [kctsb.h](include/kctsb/kctsb.h) - 主入口和版本信息
- [core/common.h](include/kctsb/core/common.h) - 错误码和通用定义
- [crypto/aes.h](include/kctsb/crypto/aes.h) - AES 加密 API
- [crypto/sha.h](include/kctsb/crypto/sha.h) - SHA 哈希 API

### 第三方依赖安装

详细的依赖安装指南请参阅 [docs/third-party-dependencies.md](docs/third-party-dependencies.md)：

- **vcpkg**: 统一安装目录 `D:\vcpkg` (环境变量: `VCPKG_ROOT`)
- **NTL**: 从源码编译 (Windows需要MinGW/MSYS2)
  - 头文件已存在: `thirdparty/include/NTL/` (115个文件)
- **GMP**: Strawberry Perl自带 (`C:\Strawberry\c\lib\libgmp.a`)
- **OpenSSL**: vcpkg 安装 (已安装: 3.6.0)
- **SEAL**: vcpkg 安装 (已安装: 4.1.2)
- **SEAL**: vcpkg 安装 (已安装: 4.1.2)

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


