# AGENTS.md - kctsb AI Development Guidelines

> **项目**: kctsb - C/C++ 可信安全算法库
> **版本**: 3.0.0
> **更新时间**: 2026-01-17 (Beijing Time, UTC+8)

---

## 🎯 项目概述

kctsb (Knight's Cryptographic Trusted Security Base) 是一个**生产级**跨平台C/C++密码学和安全算法库，可用于安全研究、生产部署和算法验证。

### 核心设计原则

1. **生产级代码质量**: 所有实现均通过标准测试向量验证，无mock/placeholder代码
2. **跨平台兼容**: 支持 Windows/Linux/macOS，使用CMake构建
3. **双语言接口**: 提供纯C和C++ API，便于集成
4. **安全优先**: 实现遵循密码学最佳实践，包含适当的安全警告
5. **性能验证**: 提供与OpenSSL的性能对比benchmark

### 开源使用说明

本项目采用 **Apache License 2.0** 开源协议，可用于：
- ✅ 商业项目集成
- ✅ 安全研究与算法验证
- ✅ 教学与学习目的
- ✅ 二次开发与修改

**使用建议**：
- 生产环境使用前，请进行充分的安全审计
- 对于高安全需求场景，建议配合硬件安全模块(HSM)
- 时间敏感操作需注意侧信道防护

---

## 📁 目录结构

```
kctsb/
├── CMakeLists.txt          # 主构建配置（NTL/GMP/OpenSSL已默认启用）
├── include/                # 公共头文件
│   └── kctsb/
│       ├── kctsb.h         # 主入口头文件
│       ├── core/           # 核心定义
│       ├── crypto/         # 标准密码算法
│       ├── advanced/       # 高级密码学
│       ├── math/           # 数学工具
│       └── utils/          # 实用工具
├── src/                    # 源代码实现
│   ├── core/               # 核心功能实现
│   ├── crypto/             # 密码算法实现
│   │   ├── aes/            # AES-128/192/256-GCM
│   │   ├── chacha20/       # ChaCha20-Poly1305 AEAD
│   │   ├── hash/           # SHA3/BLAKE2b/BLAKE2s
│   │   ├── sm/             # SM2/SM3/SM4 国密算法
│   │   └── ...
│   ├── advanced/           # 高级算法实现
│   ├── math/               # 数学库实现（依赖NTL）
│   └── utils/              # 工具函数实现
├── tests/                  # 测试代码（真实测试，无placeholder）
│   ├── unit/               # 单元测试
│   └── integration/        # 集成测试
├── benchmarks/             # 性能对比测试（vs OpenSSL）
├── examples/               # 示例代码
├── scripts/                # 构建脚本
├── cmake/                  # CMake模块
├── thirdparty/             # 第三方库（NTL编译产物）
└── docs/                   # 文档
    └── third-party-dependencies.md  # 依赖安装指南
```

---

## 🔧 开发约束

### 代码风格

1. **命名规范**
   - C函数: `kctsb_<module>_<action>()` 格式
   - C++类: `PascalCase` 命名
   - 私有成员: `m_` 前缀
   - 常量: `KCTSB_<NAME>` 大写

2. **头文件结构**
   ```c
   #ifndef KCTSB_<MODULE>_<NAME>_H
   #define KCTSB_<MODULE>_<NAME>_H

   #include "kctsb/core/common.h"

   #ifdef __cplusplus
   extern "C" {
   #endif

   // C API declarations

   #ifdef __cplusplus
   } // extern "C"

   namespace kctsb {
   // C++ API declarations
   } // namespace kctsb
   #endif

   #endif // KCTSB_<MODULE>_<NAME>_H
   ```

3. **文档注释**
   - 每个公共函数必须有Doxygen注释
   - 参数和返回值必须详细说明
   - 安全注意事项必须标注

### 构建要求

1. **CMake 最低版本**: 3.20
2. **C++ 标准**: C++17
3. **C 标准**: C11
4. **编译器支持**: GCC 9+, Clang 10+, MSVC 2019+

### 依赖管理

- **NTL** (默认启用): 数论库，用于ECC/RSA/格密码/ZK证明
  - Windows: 需从源码编译 (见 `docs/third-party-dependencies.md`)
  - Linux/macOS: `apt install libntl-dev` / `brew install ntl`
  
- **GMP** (默认启用): 高精度整数运算，NTL的依赖
  - vcpkg: `vcpkg install gmp:x64-windows`
  
- **OpenSSL** (默认启用): 用于性能benchmark对比
  - vcpkg: `vcpkg install openssl:x64-windows`
  
- **SEAL** (可选): Microsoft同态加密库
  - vcpkg: `vcpkg install seal:x64-windows`

### vcpkg 集成

```powershell
# 设置 VCPKG_ROOT 环境变量
$env:VCPKG_ROOT = "C:\vcpkg"

# CMake 自动检测 vcpkg
cmake -B build -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake"
```

### NTL 源码编译 (Windows)

NTL 不支持 vcpkg，需从源码编译：

```powershell
# 使用 MinGW/MSYS2
cd /path/to/ntl/src
./configure PREFIX=/d/libs/ntl NTL_GMP_LIP=on SHARED=on NTL_THREADS=on
make -j$(nproc)
make install

# CMake 指定 NTL 路径
cmake -B build -DNTL_ROOT="D:/libs/ntl"
```

详细说明见 `docs/third-party-dependencies.md`。

### 测试要求

1. 使用 GoogleTest 框架
2. 每个算法至少包含:
   - 标准测试向量验证
   - 边界条件测试
   - 性能基准测试
3. 代码覆盖率目标: 80%+

---

## 📋 算法模块说明

### crypto/ - 标准密码算法

| 模块 | 功能 | 实现状态 | 测试状态 |
|------|------|----------|----------|
| aes/ | AES-128/192/256-GCM AEAD | ✅ 完成 | ✅ 测试向量验证 |
| chacha20/ | ChaCha20-Poly1305 AEAD | ✅ 完成 | ✅ RFC 7539 向量 |
| hash/Keccak | SHA3-256/512 (Keccak) | ✅ 完成 | ✅ FIPS 202 向量 |
| hash/blake2 | BLAKE2b/BLAKE2s | ✅ 完成 | ✅ RFC 7693 向量 |
| sm/sm2 | 国密SM2椭圆曲线 | ✅ 完成 | ✅ GM/T 向量 |
| sm/sm3 | 国密SM3哈希 | ✅ 完成 | ✅ GM/T 向量 |
| sm/sm4 | 国密SM4分组密码 | ✅ 完成 | ✅ GM/T 向量 |
| rsa/ | RSA加密签名 | 🔄 进行中 | 需要NTL/GMP |
| ecc/ | 椭圆曲线密码 | 🔄 进行中 | 需要NTL |

### advanced/ - 高级密码学

| 模块 | 功能 | 实现状态 | 依赖 |
|------|------|----------|------|
| whitebox/ | 白盒AES实现 | ✅ 完成 | 无 |
| sss/ | Shamir秘密共享 | 📋 计划中 | GMP |
| zk/ | 零知识证明 | 📋 计划中 | NTL |
| lattice/ | 格密码 (NTRU/Kyber) | 📋 计划中 | NTL |
| fe/ | 函数加密 | 📋 计划中 | HElib |

### benchmarks/ - 性能对比

| 测试项 | 说明 | 对比目标 |
|--------|------|----------|
| benchmark_aes_gcm | AES-256-GCM 吞吐量 | OpenSSL EVP |
| benchmark_chacha20 | ChaCha20-Poly1305 吞吐量 | OpenSSL EVP |
| benchmark_hash | SHA3/BLAKE2 哈希速度 | OpenSSL EVP |

---

## 🚀 构建命令

### Windows (PowerShell) - 推荐配置

```powershell
# 完整构建（启用所有依赖）
cmake -B build -G "MinGW Makefiles" `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
    -DNTL_ROOT="D:\libs\ntl" `
    -DKCTSB_BUILD_BENCHMARKS=ON
cmake --build build --parallel

# 运行测试
cd build; ctest --output-on-failure

# 运行性能对比
.\build\bin\kctsb_benchmark.exe

# 使用构建脚本
.\scripts\build.ps1 -BuildType Release -Test -Benchmark
```

### Linux/macOS

```bash
# 安装依赖
sudo apt install libntl-dev libgmp-dev libssl-dev  # Ubuntu/Debian
brew install ntl gmp openssl                        # macOS

# 配置并构建
cmake -B build -DCMAKE_BUILD_TYPE=Release -DKCTSB_BUILD_BENCHMARKS=ON
cmake --build build --parallel $(nproc)

# 运行测试和benchmark
cd build && ctest --output-on-failure
./bin/kctsb_benchmark
```
cmake --build build --parallel

# 运行测试
cd build; ctest --output-on-failure

# 使用构建脚本
.\scripts\build.ps1 -BuildType Release -Test
```

### Linux/macOS

```bash
# 配置并构建
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)

# 运行测试
cd build && ctest --output-on-failure

# 使用构建脚本
./scripts/build.sh --test
```

---

## ⚠️ 安全注意事项

### 生产环境使用指南

1. **代码审计**: 在生产环境部署前，建议进行独立的安全代码审计
2. **侧信道防护**: 
   - 当前AES-GCM和ChaCha20实现为软件实现，可能存在时间侧信道
   - 对于高安全需求，建议使用硬件AES-NI指令或HSM
3. **内存安全**: 
   - 使用 `kctsb_secure_memzero()` 清理敏感数据
   - 避免在日志中输出密钥材料
4. **随机数生成**: 
   - Windows: 使用BCryptGenRandom (CSPRNG)
   - Unix: 使用/dev/urandom (getrandom syscall)
   - 不要使用rand()或time-based种子

### 密码学最佳实践

- **密钥管理**: 密钥应存储在安全硬件或加密的密钥库中
- **IV/Nonce**: GCM模式下IV必须唯一，绝不能重用
- **认证**: 始终使用AEAD模式 (GCM/Poly1305)，避免使用ECB/CBC-only
- **密钥派生**: 使用HKDF或Argon2派生密钥，不要直接使用密码

---

## 📝 贡献指南

1. **代码要求**:
   - 所有代码必须通过CI测试
   - 新算法必须附带标准测试向量
   - 禁止提交mock/placeholder代码
   
2. **文档要求**:
   - 每个公共函数必须有Doxygen注释
   - 安全敏感代码必须标注警告
   - README/AGENTS.md与代码同步更新

3. **测试要求**:
   - 单元测试使用GoogleTest
   - 代码覆盖率目标: 80%+
   - 性能测试使用benchmark框架

---

## 🔗 相关资源

### 标准文档
- FIPS 197 (AES): https://csrc.nist.gov/publications/detail/fips/197/final
- FIPS 202 (SHA-3): https://csrc.nist.gov/publications/detail/fips/202/final
- RFC 7539 (ChaCha20-Poly1305): https://tools.ietf.org/html/rfc7539
- RFC 7693 (BLAKE2): https://tools.ietf.org/html/rfc7693
- GM/T 0002-2012 (SM4)
- GM/T 0003-2012 (SM2)
- GM/T 0004-2012 (SM3)

### 依赖库
- NTL: https://libntl.org/ (v11.6.0+)
- GMP: https://gmplib.org/
- OpenSSL: https://www.openssl.org/
- Microsoft SEAL: https://github.com/microsoft/SEAL
