# AGENTS.md - kctsb AI Development Guidelines

> **项目**: kctsb - Knight's Cryptographic Trusted Security Base  
> **版本**: 3.2.0  
> **更新时间**: 2026-01-14 (Beijing Time, UTC+8)

---

## 🎯 项目概述

kctsb (Knight's Cryptographic Trusted Security Base) 是一个**生产级**跨平台C/C++密码学和安全算法库，可用于安全研究、生产部署和算法验证。

### 核心设计原则

1. **生产级代码质量**: 所有实现均通过标准测试向量验证，无mock/placeholder代码
2. **跨平台兼容**: 支持 Windows/Linux/macOS，使用CMake + Ninja构建
3. **双语言接口**: 提供纯C和C++ API，便于集成
4. **C API优先**: 所有C库优先使用C API接入，不强制要求C++封装（如GMP使用mpz_t而非mpz_class）
5. **安全优先**: 实现遵循密码学最佳实践，包含适当的安全警告
6. **性能验证**: 提供与OpenSSL的性能对比benchmark（仅benchmark可用OpenSSL）
7. **原生实现**: 核心算法必须原生实现，仅benchmark可引用OpenSSL进行对比
8. **NTL-based ECC**: 椭圆曲线算法使用NTL原生实现，已移除MIRACL依赖

### 设计目标

本项目的目标是**替代OpenSSL**成为更现代、更安全的密码学库：
- ⚠️ **src/目录禁止引用OpenSSL**: 所有核心算法必须原生C/C++实现
- ⚠️ **已移除MIRACL**: ECC使用NTL实现（Montgomery ladder常量时间标量乘法）
- ✅ **benchmark/目录可以引用OpenSSL**: 仅用于性能对比测试
- ✅ **参考实现允许**: 可参考OpenSSL/MIRACL等开源实现，但必须重写为原生代码
- ✅ **性能目标**: 追求超越OpenSSL的性能表现（-O3, -march=native, -flto）

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
├── CMakeLists.txt          # 主构建配置 (CMake 3.20+, Ninja推荐)
├── include/                # 公共头文件 ★所有.h/.hpp放这里★
│   └── kctsb/
│       ├── kctsb.h         # 主入口头文件
│       ├── core/           # 核心定义
│       ├── crypto/         # 标准密码算法公共头
│       │   ├── hash/       # 哈希算法实现头
│       │   ├── ecc/, rsa/  # 非对称算法头
│       │   └── sm/         # 国密算法头
│       ├── advanced/       # 高级密码学
│       │   ├── pqc/        # 后量子密码 (Kyber, Dilithium)
│       │   ├── zk/         # 零知识证明 (Groth16)
│       │   └── fe/, sss/, whitebox/
│       ├── simd/           # SIMD 硬件加速
│       ├── internal/       # 内部实现头文件
│       ├── math/           # 数学工具
│       └── utils/          # 实用工具
│
├── src/                    # 源代码实现 ★禁止放.h/.hpp★
│   ├── core/               # 核心功能实现
│   ├── crypto/             # 密码算法实现
│   │   ├── aes/            # AES实现
│   │   ├── chacha20/       # ChaCha20-Poly1305
│   │   ├── hash/           # 哈希算法 (原生实现)
│   │   ├── ecc/            # 椭圆曲线 (NTL实现)
│   │   ├── rsa/            # RSA (NTL实现)
│   │   └── sm/             # 国密算法 (原生实现)
│   ├── advanced/           # 高级算法实现
│   ├── simd/               # SIMD 加速实现
│   ├── cli/                # 命令行工具
│   └── math/               # 数学库
│
├── tests/                  # GoogleTest测试代码
├── benchmarks/             # 性能对比测试 (vs OpenSSL)
├── thirdparty/             # ★第三方库统一目录★
│   ├── include/            # NTL/, gf2x/, gmp.h, SEAL-4.1/, helib/
│   └── lib/                # libntl.a, libgf2x.a, libgmp.a, etc.
├── docs/                   # 文档
│   ├── releases/           # 版本发布说明
│   └── third-party-dependencies.md
├── scripts/                # 构建脚本
└── cmake/                  # CMake 模块
```

### 目录规范

1. **include/**: 所有头文件 (.h, .hpp) 必须放在此目录
   - src/ 目录禁止放置头文件
   - 公共API: `include/kctsb/crypto/*.h`
   - 内部实现: `include/kctsb/internal/*.h`

2. **thirdparty/**: 所有第三方库的**编译产物**统一放置于此
   - `thirdparty/include/`: 第三方头文件
   - `thirdparty/lib/`: 静态库 (.a)
   - CMake优先从此目录搜索依赖

3. **deps/**: 第三方库**源码和编译中间产物** (临时目录)

4. **build/**: CMake构建目录 (不提交Git)

---

## 🔧 kctsb 特定开发约束

### 依赖管理

**thirdparty 统一目录** (优先):
- **位置**: `kctsb/thirdparty/`
- **结构**: `include/` 放头文件，`lib/` 放静态库
- **CMake**: 优先从thirdparty搜索，不再使用vcpkg（除benchmark）

**核心依赖** (2026-01-14):
| 依赖 | 版本 | 位置 | 状态 | 用途 |
|------|------|------|------|------|
| GMP | 6.3.0+ | thirdparty | ✅ 必需 | 高精度整数 |
| gf2x | 1.3.0+ | thirdparty | ✅ 必需 | NTL依赖 |
| NTL | 11.6.0+ | thirdparty | ✅ 必需 | 数论、ECC |
| SEAL | 4.1.2 | thirdparty | ⚠️ 可选 | 同态加密 |
| HElib | v2.3.0 | thirdparty | ⚠️ 可选 | 函数加密 |

**Benchmark专用依赖** (仅benchmarks/可用):
| 依赖 | 版本 | 来源 | 用途 |
|------|------|------|------|
| OpenSSL | 3.x | vcpkg | 性能对比 |
| zlib | 1.3.1 | vcpkg | 压缩支持 |
| zstd | 1.5.7 | vcpkg | 压缩支持 |

### 依赖约束 ⚠️

1. **核心依赖** (src/目录可用):
   - ✅ NTL 11.6.0+: 数论运算、椭圆曲线
   - ✅ GMP 6.3.0+: 高精度整数
   - ✅ gf2x 1.3.0+: NTL的GF(2)多项式运算
   - ⚠️ SEAL 4.1.2 (可选): 同态加密
   - ⚠️ HElib v2.3.0 (可选): 函数加密

2. **禁止依赖** (src/目录禁用):
   - ❌ OpenSSL: 目标是替代它
   - ❌ MIRACL: 已移除，使用NTL实现ECC
   - ❌ 其他外部库: 使用纯C/C++原生实现

3. **benchmark依赖** (仅benchmarks/目录可用):
   - ✅ OpenSSL: 性能对比测试
   - ✅ zlib/zstd: 压缩benchmark

### Windows 工具链与构建策略 (2026-01-14)
- **首选工具链**: `C:\msys64\mingw64` 下的 gcc/g++；`scripts/build.ps1` 已默认设置 `CC/CXX` 和 `-DCMAKE_C_COMPILER/-DCMAKE_CXX_COMPILER` 指向该路径。
- **禁止优先使用 Strawberry Perl 工具链**: 若 PATH 中存在 `C:\Strawberry\c\bin`，需主动切换至 MSYS2；仅在 MSYS2 缺失且确认风险时才退回。
- **VCPKG 使用原则**: 默认不启用；仅在 `-Benchmark` 且显式传入 `-UseVcpkg` 后才加载 `$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake`。优先从 thirdparty/ 及源码构建。
- **三方库独立脚本**: 每个依赖使用 scripts/ 下独立 build 脚本（例如 `build_helib.ps1`、`build_ntl.ps1`），保持 build/ 和 thirdparty/ 的分离与可复现。
- **HElib 为默认开启的必选项**: `KCTSB_ENABLE_HELIB=ON` 并在缺失时终止配置，按脚本编译后放置于 thirdparty/include|lib。

### 算法文件布局与共享工具
- 单一算法尽量使用单个 C/C++ 翻译单元实现；共用逻辑抽取到 `src/utils/`，并在 `include/kctsb/utils/` 暴露对应头文件。
- 统一使用 `kctsb::utils::enable_utf8_console()` / `kctsb_enable_utf8_console()` 处理 CLI、benchmark 等可执行程序的 UTF-8 输出，避免中文/框线字符乱码及重定向问题。

### 代码语言政策

- **src/目录**: 所有注释和变量名必须使用**英文**
- **docs/目录**: 文档可使用中文
- 禁止在代码中使用中文注释或变量名

---

## 📋 算法模块说明

### crypto/ - 标准密码算法

| 模块 | 功能 | 实现状态 | 测试状态 | 备注 |
|------|------|----------|----------|------|
| aes/ | AES-128/192/256-GCM AEAD | ✅ 完成 | ✅ 测试向量验证 | 生产就绪 |
| chacha20/ | ChaCha20-Poly1305 AEAD | ✅ 完成 | ✅ RFC 7539 向量 | 生产就绪 |
| hash/Keccak | SHA3-256/512 (Keccak) | ✅ 完成 | ✅ FIPS 202 向量 | 生产就绪 |
| hash/blake2 | BLAKE2b/BLAKE2s | ✅ 完成 | ✅ RFC 7693 向量 | 生产就绪 |
| sm/sm2 | 国密SM2椭圆曲线 | ✅ 完成 | ✅ GM/T 向量 | 完整实现 |
| sm/sm3 | 国密SM3哈希 | ✅ 完成 | ✅ GM/T 向量 | 完整实现 |
| sm/sm4 | 国密SM4分组密码 | ✅ 完成 | ✅ GM/T 向量 | 完整实现 |
| rsa/ | RSA加密签名 | ✅ 完成 | ✅ NTL实现 | kc_rsa.cpp |
| ecc/ | 椭圆曲线密码 | ✅ 完成 | ✅ NTL实现 | ecc_ntl.cpp |

### advanced/ - 高级密码学

| 模块 | 功能 | 实现状态 | 依赖 | 代码状态 |
|------|------|----------|------|----------|
| whitebox/ | 白盒AES (Chow方案) | ✅ 完成 | 无 | 完整实现 |
| sss/ | Shamir秘密共享 | ✅ 完成 | NTL | 测试通过 |
| zk/ffs/ | Feige-Fiat-Shamir证明 | ✅ 完成 | NTL | 测试通过 |
| zk/snarks/ | zk-SNARKs | 📋 计划中 | - | 待实现 |
| lattice/ | 格密码 (LLL约简) | ✅ 完成 | NTL | 测试通过 |
| fe/ | 函数加密 (BGV方案) | 📋 框架存在 | HElib | 设计草稿 |

### 当前测试状态 (2026-01-14)

| 类别 | 测试数 | 通过 | 失败 | 状态 |
|------|--------|------|------|------|
| AES | 8 | 8 | 0 | ✅ |
| ChaCha20 | 4 | 4 | 0 | ✅ |
| Hash | 12 | 12 | 0 | ✅ |
| SM2/SM3/SM4 | 10 | 10 | 0 | ✅ |
| RSA | 6 | 6 | 0 | ✅ |
| Whitebox | 4 | 4 | 0 | ✅ |
| ZK (FFS) | 8 | 8 | 0 | ✅ |
| **总计** | **72** | **72** | **0** | **100%** |

---

## 🚀 kctsb 构建命令

### Windows (PowerShell) - 推荐配置

```powershell
# 进入项目目录
cd D:\pyproject\kctsb

# 完整构建（使用thirdparty目录依赖, Ninja推荐）
cmake -B build -G Ninja `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_C_FLAGS="-O3 -march=native -mtune=native -fomit-frame-pointer" `
    -DCMAKE_CXX_FLAGS="-O3 -march=native -mtune=native -fomit-frame-pointer" `
    -DKCTSB_BUILD_CLI=ON `
    -DKCTSB_BUILD_TESTS=ON `
    -DKCTSB_BUILD_BENCHMARKS=ON

cmake --build build --parallel

# 运行测试
ctest --test-dir build --output-on-failure

# 运行CLI工具
.\build\bin\kctsb.exe version
.\build\bin\kctsb.exe hash --sha3-256 "Hello, World!"
```

### Linux/macOS

```bash
# 配置并构建（Ninja推荐）
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="-O3 -march=native" \
    -DCMAKE_CXX_FLAGS="-O3 -march=native" \
    -DKCTSB_BUILD_CLI=ON \
    -DKCTSB_BUILD_TESTS=ON
cmake --build build --parallel $(nproc)

# 运行测试和benchmark
ctest --test-dir build --output-on-failure
./build/bin/kctsb version
```

---

## 🎯 新增算法开发规范

### 文件组织

```
src/crypto/<algorithm>/
├── <algorithm>.c      # C实现
├── <algorithm>.cpp    # C++封装 (可选)
include/kctsb/crypto/
└── <algorithm>.h      # 公共头文件
tests/
└── test_<algorithm>.cpp  # GoogleTest测试
```

### API设计

- C函数: `kctsb_<algorithm>_<operation>()`
- 必须提供初始化/更新/完成三段式API (适用时)
- 返回错误码而非抛出异常

### 测试要求

- 使用官方测试向量 (NIST/RFC/GM/T)
- 边界条件测试
- 性能benchmark与OpenSSL对比

### 安全要求

- 时间常量操作 (防侧信道)
- 敏感数据清零 (使用kctsb_secure_memzero)
- 输入验证

---

## 📝 待办事项 (TODO)

### 高优先级

1. **修复编译警告和错误**
   - 目标: 修复所有warning、error、note
   - 编译器: GCC/Clang/MSVC
   - 文件: 所有src/目录代码

2. **中文乱码问题**
   - 目标: .\build\bin\kctsb_benchmark.exe 正常输出中文
   - 方法: UTF-8 BOM 或控制台编码设置
   - 平台: Windows

3. **完善CLI工具**
   - 目标: kctsb.exe支持所有加密操作
   - 参考: OpenSSL CLI设计
   - 子命令: hash, enc, dec, sign, verify, keygen, bench

### 中优先级

4. **性能优化**
   - 目标: 核心算法性能超越OpenSSL
   - 方法: SIMD优化 (AVX2/AVX-512)
   - 文件: `src/crypto/aes/*.c`, `src/crypto/hash/*.c`

5. **zk-SNARKs实现**
   - 目标: 完成零知识证明的SNARK实现
   - 依赖: NTL多项式运算
   - 位置: `src/advanced/zk/snarks/`

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

## 🔗 相关资源

### 标准文档
- FIPS 197 (AES): https://csrc.nist.gov/publications/detail/fips/197/final
- FIPS 202 (SHA-3): https://csrc.nist.gov/publications/detail/fips/202/final
- RFC 7539 (ChaCha20-Poly1305): https://tools.ietf.org/html/rfc7539
- RFC 7693 (BLAKE2): https://tools.ietf.org/html/rfc7693
- GM/T 0002-2012 (SM4), GM/T 0003-2012 (SM2), GM/T 0004-2012 (SM3)

### 依赖库
- NTL: https://libntl.org/ (v11.6.0+)
- GMP: https://gmplib.org/ (v6.3.0+)
- Microsoft SEAL: https://github.com/microsoft/SEAL (v4.1.2)
- HElib: https://github.com/homenc/HElib (v2.3.0)
