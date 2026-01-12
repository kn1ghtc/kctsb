# AGENTS.md - kctsb AI Development Guidelines

> **项目**: kctsb - C/C++ 可信安全算法库
> **版本**: 3.0.0
> **更新时间**: 2026-01-19 (Beijing Time, UTC+8)

---

## 🎯 项目概述

kctsb (Knight's Cryptographic Trusted Security Base) 是一个**生产级**跨平台C/C++密码学和安全算法库，可用于安全研究、生产部署和算法验证。

### 核心设计原则

1. **生产级代码质量**: 所有实现均通过标准测试向量验证，无mock/placeholder代码
2. **跨平台兼容**: 支持 Windows/Linux/macOS，使用CMake构建
3. **双语言接口**: 提供纯C和C++ API，便于集成
4. **C API优先**: 所有C库优先使用C API接入，不强制要求C++封装（如GMP使用mpz_t而非mpz_class）
5. **安全优先**: 实现遵循密码学最佳实践，包含适当的安全警告
6. **性能验证**: 提供与OpenSSL的性能对比benchmark
7. **原生实现**: 核心算法必须原生实现，仅benchmark可引用OpenSSL进行对比

### 设计目标

本项目的目标是**替代OpenSSL**成为更现代、更安全的密码学库：
- ⚠️ **src/目录禁止引用OpenSSL**: 所有核心算法必须原生C/C++实现
- ✅ **benchmark/目录可以引用OpenSSL**: 仅用于性能对比测试
- ✅ **参考实现允许**: 可参考OpenSSL/MIRACL等开源实现，但必须重写为原生代码
- ✅ **性能目标**: 追求超越OpenSSL的性能表现

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
├── CMakeLists.txt          # 主构建配置
├── include/                # 公共头文件
│   └── kctsb/
│       ├── kctsb.h         # 主入口头文件
│       ├── core/           # 核心定义
│       ├── crypto/         # 标准密码算法
│       ├── advanced/       # 高级密码学
│       ├── math/           # 数学工具 (NTL封装)
│       └── utils/          # 实用工具
├── src/                    # 源代码实现
│   ├── core/               # 核心功能实现
│   ├── crypto/             # 密码算法实现
│   │   ├── aes/            # AES-128/192/256-GCM
│   │   ├── chacha20/       # ChaCha20-Poly1305 AEAD
│   │   ├── hash/           # SHA3/BLAKE2b/BLAKE2s
│   │   ├── sm/             # SM2/SM3/SM4 国密算法
│   │   ├── rsa/            # RSA (NTL实现)
│   │   └── ecc/            # 椭圆曲线 (待移除MIRACL)
│   ├── advanced/           # 高级算法实现
│   │   ├── whitebox/       # 白盒AES
│   │   ├── sss/            # Shamir秘密共享
│   │   ├── zk/             # 零知识证明
│   │   └── lattice/        # 格密码
│   ├── math/               # 数学库实现（NTL封装）
│   └── utils/              # 工具函数实现
├── tests/                  # GoogleTest测试代码
│   ├── unit/               # 单元测试
│   └── integration/        # 集成测试
├── benchmarks/             # 性能对比测试（vs OpenSSL）
├── examples/               # 示例代码
├── scripts/                # 构建脚本
├── cmake/                  # CMake模块 (Find*.cmake)
├── thirdparty/             # 第三方库 ★统一目录★
│   ├── include/            # 头文件
│   │   ├── NTL/            # NTL 11.6.0
│   │   ├── gmp.h, gmpxx.h  # GMP 6.3.0
│   │   ├── SEAL-4.1/       # SEAL 4.1.2
│   │   └── helib/          # HElib v2.3.0
│   └── lib/                # 库文件
│       ├── libntl.a        # NTL静态库 (5.09MB)
│       ├── libgmp.a        # GMP静态库
│       ├── libseal-4.1.a   # SEAL静态库
│       └── libhelib.a      # HElib静态库 (8.7MB)
├── deps/                   # 第三方源码 (构建临时目录)
│   └── ntl/                # NTL源码编译目录
└── docs/                   # 文档
    ├── releases/           # 版本发布说明
    └── third-party-dependencies.md  # 依赖安装指南
```

### 目录规范

1. **thirdparty/**: 所有第三方库的**编译产物**统一放置于此
   - `thirdparty/include/`: 头文件
   - `thirdparty/lib/`: 静态库 (.a) 和动态库 (.dll)
   - CMake优先从此目录搜索依赖

2. **deps/**: 第三方库**源码和编译中间产物**
   - 用于需要从源码编译的库 (如NTL)
   - 编译完成后将产物复制到thirdparty/

3. **build/**: CMake构建目录
   - 不提交到Git仓库
   - 包含编译产物和CMake缓存

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

4. **代码语言**
   - **src/目录**: 所有注释和变量名必须使用**英文**
   - **docs/目录**: 文档可使用中文
   - 禁止在代码中使用中文注释或变量名

### 构建要求

1. **CMake 最低版本**: 3.20
2. **C++ 标准**: C++17
3. **C 标准**: C11
4. **编译器支持**: MinGW GCC 13+, Clang 10+, MSVC 2022+

### 依赖管理

**thirdparty 统一目录** (优先):
- **位置**: `kctsb/thirdparty/`
- **结构**: `include/` 放头文件，`lib/` 放库文件
- **CMake**: 优先从thirdparty搜索，其次vcpkg/系统路径

**已安装依赖** (2026-01-19):
| 依赖 | 版本 | 位置 | 状态 |
|------|------|------|------|
| NTL | 11.6.0 | thirdparty + deps/ntl | ✅ 可用 |
| GMP | 6.3.0 | thirdparty | ✅ 可用 |
| SEAL | 4.1.2 | thirdparty | ✅ 可用 |
| HElib | v2.3.0 | thirdparty | ✅ 可用 |

**vcpkg 辅助** (可选):
- **安装目录**: `D:\vcpkg` (环境变量: `$env:VCPKG_ROOT`)
- **已安装包**: OpenSSL 3.6.0 (仅benchmark使用), zlib 1.3.1, zstd 1.5.7
- **用途**: 用于benchmark中与OpenSSL性能对比

### 依赖约束 ⚠️

1. **核心依赖** (src/目录可用):
   - NTL 11.6.0+: 数论运算
   - GMP 6.3.0+: 高精度整数
   - SEAL 4.1.2 (可选): 同态加密
   - HElib v2.3.0 (可选): 同态加密

2. **禁止依赖** (src/目录禁用):
   - ❌ OpenSSL: 目标是替代它，不能依赖
   - ❌ MIRACL: 计划移除，使用NTL原生实现ECC
   - ❌ 其他外部库: 使用纯C/C++原生实现

3. **benchmark依赖** (仅benchmarks/目录可用):
   - ✅ OpenSSL: 用于性能对比测试

### 测试要求

1. 使用 GoogleTest 框架
2. 每个算法至少包含:
   - 标准测试向量验证
   - 边界条件测试
   - 性能基准测试
3. 代码覆盖率目标: 80%+
4. 测试集成: ctest + GoogleTest

### 当前测试状态 (2026-01-19)

| 类别 | 测试数 | 通过 | 失败 | 状态 |
|------|--------|------|------|------|
| AES | 8 | 8 | 0 | ✅ |
| ChaCha20 | 4 | 4 | 0 | ✅ |
| Hash (SHA3/BLAKE2) | 12 | 12 | 0 | ✅ |
| SM2/SM3/SM4 | 10 | 10 | 0 | ✅ |
| RSA | 6 | 6 | 0 | ✅ |
| Whitebox | 4 | 4 | 0 | ✅ |
| ZK (FFS) | 8 | 8 | 0 | ✅ |
| SSS | 4 | 4 | 0 | ✅ |
| Lattice | 8 | 8 | 0 | ✅ |
| Math | 4 | 4 | 0 | ✅ |
| ECC | 4 | 0 | 4 | ⏸️ 禁用 (待移除MIRACL) |
| **总计** | **72** | **68** | **4** | **94.4%** |

---

## 📋 算法模块说明

### crypto/ - 标准密码算法

| 模块 | 功能 | 实现状态 | 测试状态 | 备注 |
|------|------|----------|----------|------|
| aes/ | AES-128/192/256-GCM AEAD | ✅ 完成 | ✅ 测试向量验证 | 生产就绪 |
| chacha20/ | ChaCha20-Poly1305 AEAD | ✅ 完成 | ✅ RFC 7539 向量 | 生产就绪 |
| hash/Keccak | SHA3-256/512 (Keccak) | ✅ 完成 | ✅ FIPS 202 向量 | 生产就绪 |
| hash/blake2 | BLAKE2b/BLAKE2s | ✅ 完成 | ✅ RFC 7693 向量 | 生产就绪 |
| sm/sm2 | 国密SM2椭圆曲线 | ✅ 完成 | ✅ GM/T 向量 | 完整实现 (sm2_enc.c) |
| sm/sm3 | 国密SM3哈希 | ✅ 完成 | ✅ GM/T 向量 | 完整实现 |
| sm/sm4 | 国密SM4分组密码 | ✅ 完成 | ✅ GM/T 向量 | 完整实现 |
| rsa/ | RSA加密签名 | ✅ 完成 | ✅ NTL实现 | kc_rsa.cpp |
| ecc/ | 椭圆曲线密码 | ⏸️ 待重构 | ❌ 禁用 | 依赖MIRACL，计划移除 |

### advanced/ - 高级密码学

| 模块 | 功能 | 实现状态 | 依赖 | 代码状态 |
|------|------|----------|------|----------|
| whitebox/ | 白盒AES实现 (Chow方案) | ✅ 完成 | 无 | 完整实现 (whitebox_aes.c) |
| sss/ | Shamir秘密共享 | ✅ 完成 | NTL | 测试通过 (kc_sss.cpp) |
| zk/ffs/ | Feige-Fiat-Shamir证明 | ✅ 完成 | NTL | 测试通过 (kc_ffs.cpp) |
| zk/snarks/ | zk-SNARKs | 📋 计划中 | - | 待实现 |
| lattice/ | 格密码 (LLL约简) | ✅ 完成 | NTL | 测试通过 (kc_latt.cpp) |
| fe/ | 函数加密 (BGV方案) | 📋 框架存在 | HElib | 设计草稿 |

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
# 进入项目目录
cd D:\pyproject\kctsb

# 完整构建（使用thirdparty目录依赖）
cmake -B build -G "MinGW Makefiles" `
    -DCMAKE_BUILD_TYPE=Release `
    -DKCTSB_BUILD_BENCHMARKS=ON `
    -DKCTSB_BUILD_TESTS=ON
cmake --build build --parallel

# 运行测试
cd build; ctest --output-on-failure

# 运行性能对比（需要OpenSSL）
cmake -B build -G "MinGW Makefiles" `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
    -DKCTSB_BUILD_BENCHMARKS=ON
.\build\bin\kctsb_benchmark.exe
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

### 构建产物

```
build/
├── lib/
│   ├── libkctsb.a          # 静态库
│   └── libkctsb.dll        # 动态库 (Windows)
├── bin/
│   ├── kctsb_tests         # GoogleTest测试可执行文件
│   ├── kctsb_benchmark     # 性能测试可执行文件
│   └── kctsb_demo          # 示例程序
└── ...
```

---

## 📝 待办事项 (TODO)

### 高优先级

1. **移除MIRACL依赖**
   - 文件: `src/crypto/ecc/eccEnc.cpp`, `src/crypto/sm/sm2_enc.c`, `src/crypto/sm/sm_util.c`
   - 目标: 使用NTL原生实现椭圆曲线
   - 参考: MIRACL GitHub实现，但需完全重写

2. **移除src/中的OpenSSL引用**
   - 文件: `src/crypto/hash/chacha.cpp`
   - 目标: 原生实现ChaCha20，不依赖OpenSSL

3. **修复中文注释**
   - 范围: src/目录下所有源文件
   - 目标: 所有注释和变量名使用英文

### 中优先级

4. **完成CLI工具**
   - 目标: 实现kctsb.exe命令行工具
   - 参考: OpenSSL CLI设计
   - 约束: 必须使用原生实现，不调用OpenSSL

5. **启用ECC测试**
   - 前提: 完成MIRACL移除
   - 目标: 4个ECC测试全部通过

### 低优先级

6. **性能优化**
   - 目标: 核心算法性能超越OpenSSL
   - 方法: SIMD优化、内存布局优化

7. **文档完善**
   - 更新API文档 (Doxygen)
   - 完善安全使用指南

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
   - src/目录禁止引用OpenSSL
   
2. **文档要求**:
   - 每个公共函数必须有Doxygen注释
   - 安全敏感代码必须标注警告
   - README/AGENTS.md与代码同步更新

3. **测试要求**:
   - 单元测试使用GoogleTest
   - 代码覆盖率目标: 80%+
   - 性能测试使用benchmark框架

### 新增算法开发规范

1. **文件组织**
   ```
   src/crypto/<algorithm>/
   ├── <algorithm>.c      # C实现
   ├── <algorithm>.cpp    # C++封装 (可选)
   include/kctsb/crypto/
   └── <algorithm>.h      # 公共头文件
   tests/
   └── test_<algorithm>.cpp  # GoogleTest测试
   ```

2. **API设计**
   - C函数: `kctsb_<algorithm>_<operation>()`
   - 必须提供初始化/更新/完成三段式API (适用时)
   - 返回错误码而非抛出异常

3. **测试要求**
   - 使用官方测试向量 (NIST/RFC/GM/T)
   - 边界条件测试
   - 性能benchmark与OpenSSL对比

4. **安全要求**
   - 时间常量操作 (防侧信道)
   - 敏感数据清零 (使用kctsb_secure_memzero)
   - 输入验证

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
- GMP: https://gmplib.org/ (v6.3.0+)
- Microsoft SEAL: https://github.com/microsoft/SEAL (v4.1.2)
- HElib: https://github.com/homenc/HElib (v2.3.0)
