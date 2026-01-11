# kctsb - C/C++ 可信安全算法库

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](.)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](.)
[![CMake](https://img.shields.io/badge/CMake-3.20+-green.svg)](.)

**kctsb** (Knight's Cryptographic Trusted Security Base) 是一个跨平台的 C/C++ 密码学和安全算法库，专为安全研究和教育用途设计。提供纯 C 和 C++ 两套 API 接口。

## ✨ 特性

### 对称加密算法
- **AES** - AES-128/192/256，支持 ECB/CBC/CTR/GCM 模式
- **SM4** - 国密 SM4 分组密码
- **ChaCha20** - 流密码

### 非对称加密算法
- **RSA** - RSA-2048/4096 加密签名
- **ECC** - 椭圆曲线密码（P-256, P-384, P-521）
- **SM2** - 国密 SM2 椭圆曲线

### 哈希算法
- **SHA** - SHA-1/256/384/512
- **SM3** - 国密 SM3 哈希
- **BLAKE2/3** - 高性能哈希

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
├── include/kctsb/              # 公共头文件
│   ├── kctsb.h                 # 主入口头文件
│   ├── core/                   # 核心定义
│   │   ├── common.h            # 通用定义、错误码
│   │   └── types.h             # 类型定义
│   ├── crypto/                 # 标准密码算法
│   │   ├── aes.h               # AES 加密
│   │   ├── sha.h               # SHA 哈希
│   │   ├── sm2.h               # 国密 SM2
│   │   ├── sm3.h               # 国密 SM3
│   │   └── sm4.h               # 国密 SM4
│   ├── advanced/               # 高级密码学
│   │   ├── whitebox.h          # 白盒密码
│   │   ├── sss.h               # 秘密共享
│   │   ├── zk.h                # 零知识证明
│   │   └── lattice.h           # 格密码
│   ├── math/                   # 数学工具
│   │   └── bigint.h            # 大整数运算
│   └── utils/                  # 实用工具
│       ├── encoding.h          # 编码转换
│       └── random.h            # 随机数生成
│
├── src/                        # 源代码实现
│   ├── core/                   # 核心功能
│   ├── crypto/                 # 密码算法实现
│   ├── advanced/               # 高级算法实现
│   ├── math/                   # 数学库实现
│   └── utils/                  # 工具函数实现
│
├── tests/                      # 测试代码
│   ├── CMakeLists.txt          # 测试构建配置
│   └── unit/                   # 单元测试
│       └── crypto/             # 密码算法测试
│
├── examples/                   # 示例代码
│   ├── basic/                  # 基础示例
│   ├── advanced/               # 高级示例
│   └── demo/                   # 演示程序
│
├── scripts/                    # 构建脚本
│   ├── build.ps1               # Windows 构建脚本
│   └── build.sh                # Unix 构建脚本
│
├── cmake/                      # CMake 模块
│   ├── FindNTL.cmake
│   ├── FindGMP.cmake
│   └── kctsbConfig.cmake.in
│
├── .vscode/                    # VS Code 配置
│   ├── tasks.json              # 构建任务
│   ├── launch.json             # 调试配置
│   ├── settings.json           # 编辑器设置
│   └── c_cpp_properties.json   # C/C++ 配置
│
└── kcalg/                      # 旧版代码（待迁移）
    └── ...
```

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

### C API

```c
#include <kctsb/kctsb.h>

int main() {
    // 初始化库
    kctsb_init();
    
    // AES 加密
    uint8_t key[16] = {0x00, 0x01, ...};
    uint8_t plaintext[16] = "Hello, World!!!";
    uint8_t ciphertext[16];
    
    kctsb_aes_ctx_t ctx;
    kctsb_aes_init(&ctx, key, KCTSB_AES_128);
    kctsb_aes_encrypt_ecb(&ctx, plaintext, ciphertext, 16);
    kctsb_aes_cleanup(&ctx);
    
    // 清理
    kctsb_cleanup();
    return 0;
}
```

### C++ API

```cpp
#include <kctsb/kctsb.h>

int main() {
    using namespace kctsb;
    
    // AES 加密
    std::array<uint8_t, 16> key = {0x00, 0x01, ...};
    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    
    AES aes(key);
    auto ciphertext = aes.encrypt(plaintext);
    auto decrypted = aes.decrypt(ciphertext);
    
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
