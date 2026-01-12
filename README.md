# kctsb - C/C++ 可信安全算法库

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](.)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](.)
[![CMake](https://img.shields.io/badge/CMake-3.20+-green.svg)](.)
[![Version](https://img.shields.io/badge/Version-3.0.0-brightgreen.svg)](.)

**kctsb** (Knight's Cryptographic Trusted Security Base) 是一个跨平台的 C/C++ 密码学和安全算法库，专为生产环境和安全研究设计。提供纯 C 和 C++ 两套 API 接口。

> **v3.0.0 新特性**: 完整的 AES-GCM 和 ChaCha20-Poly1305 AEAD 支持，侧信道防护，移除不安全模式。

## ✨ 特性

### 对称加密算法
- **AES** - AES-128/192/256，支持 **CTR/GCM** 模式（v3.0 移除 ECB/CBC）
- **ChaCha20-Poly1305** - RFC 8439 AEAD 流密码 (v3.0 新增)
- **SM4** - 国密 SM4 分组密码

### AEAD 认证加密 (v3.0 强化)
- **AES-GCM** - Galois/Counter Mode，128-bit 认证标签
- **ChaCha20-Poly1305** - 256-bit 密钥，128-bit 标签

### 非对称加密算法
- **RSA** - RSA-2048/4096 加密签名
- **ECC** - 椭圆曲线密码（P-256, P-384, P-521）
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
├── CMakeLists.txt              # 主构建配置
├── README.md                   # 项目文档
├── AGENTS.md                   # AI开发指南
├── LICENSE                     # Apache 2.0 许可证
│
├── include/
│   ├── kctsb/                  # 公共头文件
│   │   ├── kctsb.h             # 主入口头文件 (v3.0.0)
│   │   ├── core/               # 核心定义
│   │   │   ├── common.h        # 通用类型和错误码
│   │   │   ├── security.h      # 安全原语 (v3.0 新增)
│   │   │   └── types.h         # 类型定义
│   │   ├── crypto/             # 标准密码算法
│   │   │   ├── aes.h           # AES-CTR/GCM (v3.0 移除ECB/CBC)
│   │   │   ├── chacha20_poly1305.h  # ChaCha20-Poly1305 AEAD
│   │   │   └── ...
│   │   ├── advanced/           # 高级密码学
│   │   └── utils/              # 实用工具
│   └── opentsb/                # 旧版头文件（兼容）
│
├── src/                        # 源代码实现
│   ├── core/                   # 核心功能
│   │   ├── export.cpp          # 库导出函数
│   │   └── security.c          # 安全原语实现 (v3.0 新增)
│   ├── crypto/                 # 密码算法实现
│   │   ├── aes/                # AES 实现 (GCM完整支持)
│   │   ├── chacha20/           # ChaCha20-Poly1305 (v3.0 新增)
│   │   ├── sm/                 # SM2/SM3/SM4/ZUC (国密)
│   │   ├── rsa/                # RSA/DH/DSA/ElGamal
│   │   ├── ecc/                # ECC/ECDH/ECDSA
│   │   └── hash/               # Keccak/Blake/ChaCha/MAC
│   ├── advanced/               # 高级算法实现
│   └── math/                   # 数学库
│
├── tests/                      # 测试代码
├── examples/                   # 示例代码
├── docs/                       # 文档
│   └── releases/               # 版本发布说明
│       └── v3.0.0-release.md   # v3.0.0 发布说明
├── scripts/                    # 构建脚本
└── cmake/                      # CMake 模块
```

### 模块依赖关系

| 模块 | 依赖 | 状态 |
|------|------|------|
| AES-CTR/GCM | 无 | ✅ 生产可用 |
| ChaCha20-Poly1305 | 无 | ✅ 生产可用 (v3.0) |
| Security Core | 无 | ✅ 生产可用 (v3.0) |
| Hash (Keccak) | 无 | ✅ 可用 |
| SM (SM2/3/4/ZUC) | 无* | ⚠️ 需头文件修复 |
| RSA/DH/DSA | GMP | ⚠️ 可选启用 |
| ECC/ECDSA | NTL | ❌ 需安装NTL |
| Math | NTL | ❌ 需安装NTL |
| ZK/Lattice | NTL | ❌ 需安装NTL |
| Whitebox | 旧框架 | ❌ 需重构 |
| FE (同态) | HElib | ❌ 可选启用 |

## 🚀 快速开始

### 系统要求

- **CMake**: 3.20 或更高版本
- **编译器**: 
  - Windows: MinGW-w64 GCC 9+ 或 MSVC 2019+
  - Linux: GCC 9+ 或 Clang 10+
  - macOS: Clang 10+ 或 GCC 9+
- **C++ 标准**: C++17

### Windows 构建 (推荐 VS Code)

```powershell
# 1. 克隆项目
cd d:\pyproject\kctsb

# 2. 使用构建脚本
.\scripts\build.ps1 -BuildType Release -Test

# 或手动构建
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

# 3. 运行测试
cd build; ctest --output-on-failure

# 4. 运行示例
.\build\bin\kctsb_demo.exe
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
| `KCTSB_BUILD_TESTS` | OFF | 构建测试 |
| `KCTSB_BUILD_EXAMPLES` | OFF | 构建示例 |
| `KCTSB_USE_NTL` | OFF | 使用NTL库 |
| `KCTSB_USE_GMP` | OFF | 使用GMP库 |
| `KCTSB_USE_OPENSSL` | OFF | 使用OpenSSL |
| `KCTSB_USE_SEAL` | OFF | 使用Microsoft SEAL |
| `KCTSB_USE_HELIB` | OFF | 使用HElib |

```powershell
# 示例：启用所有可选依赖
cmake -B build -G "MinGW Makefiles" \
    -DKCTSB_BUILD_TESTS=ON \
    -DKCTSB_USE_NTL=ON \
    -DKCTSB_USE_GMP=ON
```

## 📚 API 文档

详细 API 文档请参阅各头文件中的 Doxygen 注释：

- [kctsb.h](include/kctsb/kctsb.h) - 主入口和版本信息
- [core/common.h](include/kctsb/core/common.h) - 错误码和通用定义
- [crypto/aes.h](include/kctsb/crypto/aes.h) - AES 加密 API
- [crypto/sha.h](include/kctsb/crypto/sha.h) - SHA 哈希 API

## ⚠️ 安全注意事项

1. **教育用途**: 本库主要用于教育和研究，不建议直接用于生产环境
2. **侧信道防护**: 当前实现未考虑时间侧信道攻击防护
3. **内存安全**: 使用 `kctsb_secure_memzero()` 清理敏感数据
4. **随机数**: 使用平台原生 CSPRNG（Windows BCrypt, Unix /dev/urandom）

## 📄 许可证

本项目采用 Apache License 2.0 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 👤 作者

**knightc** (owner: tsb)

Copyright © 2019-2025 knightc. All rights reserved.

## 🔗 参考资料

- [FIPS 197 (AES)](https://csrc.nist.gov/publications/detail/fips/197/final)
- [FIPS 180-4 (SHA)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [NTL: A Library for doing Number Theory](https://libntl.org/)
- [GMP: The GNU Multiple Precision Arithmetic Library](https://gmplib.org/)
- [Microsoft SEAL](https://github.com/microsoft/SEAL)
