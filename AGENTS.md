# AGENTS.md - kctsb AI Development Guidelines

> **项目**: kctsb - Knight's Cryptographic Trusted Security Base  
> **版本**: 4.1.0  
> **更新时间**: 2026-01-19 (Beijing Time, UTC+8)  
> **重大变更**: NTL源码完全集成、动态库编译模式、编译优化

---

## 🎯 项目概述

kctsb (Knight's Cryptographic Trusted Security Base) 是一个**生产级**跨平台C++密码学和安全算法库，可用于安全研究、生产部署和算法验证。

---

## 🚀 v4.1.0 架构变更 (2026-01-19)

### 1. NTL 源码完全集成

- 原 NTL 库源码已完全集成到 `src/math/bignum/` 目录
- 所有 `NTL_*` 宏逐步迁移为 `KCTSB_*` 前缀（保持兼容层）
- 删除浮点精度模块（RR、xdouble、quad_float）- kctsb 只使用整数运算
- 头文件从 117 个精简到 ~90 个

### 2. 动态库编译模式

**v4.1.0 不再使用单文件静态库，改为动态库链接：**

```
build/lib/
├── kctsb.dll / libkctsb.so   # kctsb 共享库
├── libgmp-10.dll             # GMP 共享库 (从 thirdparty 复制)
└── libgf2x-1.dll             # gf2x 共享库 (从 thirdparty 复制)
```

**使用方式：**

```bash
# 编译链接
g++ -o myapp myapp.cpp -L./lib -lkctsb -lstdc++

# 运行时确保 DLL 在同一目录或 PATH 中
# Windows: kctsb.dll, libgmp-10.dll, libgf2x-1.dll
# Linux: libkctsb.so, libgmp.so, libgf2x.so
```

**thirdparty 动态库搜索顺序：**
1. `${CMAKE_BINARY_DIR}/lib` (构建输出目录)
2. `thirdparty/${PLATFORM}/lib` (预编译库)
3. 系统 PATH

### 3. 编译优化

| 特性 | 配置 | 说明 |
|------|------|------|
| 构建系统 | Ninja (推荐) | `cmake -G Ninja` |
| 并行构建 | 8 路 | `CMAKE_BUILD_PARALLEL_LEVEL=8` |
| 增量编译 | 启用 | 仅重编译修改的文件 |
| 默认测试 | 关闭 | 使用 `-DKCTSB_BUILD_TESTS=ON` 启用 |
| 默认 benchmark | 关闭 | 使用 `-DKCTSB_BUILD_BENCHMARKS=ON` 启用 |

**快速构建命令：**

```powershell
# Windows (PowerShell) - 推荐使用 Ninja
cd D:\pyproject\kctsb
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 8

# 构建并测试
cmake -B build -G Ninja -DKCTSB_BUILD_TESTS=ON
cmake --build build --parallel 8
ctest --test-dir build --output-on-failure
```

### 4. SEAL/HElib 仅用于 Benchmark

- SEAL 和 HElib 不再默认编译到 kctsb
- 仅在 benchmark 模式下作为性能对比参考
- 预编译库放在 `thirdparty/${PLATFORM}/lib/`

---

## 🔐 AES 安全加固 (保留自 v3.4.2)

**移除 T-table 查找表，防止缓存时序攻击：**

| 组件 | 状态 | 说明 |
|------|------|------|
| `Te0-Te3` 查找表 | ❌ 已移除 | 原用于 AES 加密的 4KB T-table |
| `Te4` (S-Box table) | ❌ 已移除 | 原用于最后一轮的 S-Box 查找 |

**新增 constexpr S-Box 编译期生成：**

```cpp
// 编译期 S-Box 生成 (GF(2^8) 有限域计算)
static constexpr std::array<uint8_t, 256> generate_aes_sbox() noexcept {
    // 使用 GF(2^8) 乘法逆元 + 仿射变换
    // 完全在编译期计算，运行时零开销
}

static constexpr std::array<uint8_t, 256> AES_SBOX = generate_aes_sbox();
static constexpr std::array<uint8_t, 256> AES_SBOX_INV = generate_aes_inv_sbox();
```

**AES 实现路径：**

| 路径 | 硬件要求 | 安全特性 | 性能 |
|------|----------|----------|------|
| AES-NI | x86_64 + AES-NI | 常量时间 (硬件保证) | ~1.6-1.8 GB/s |
| 软件后备 | 任意 CPU | 常量时间 (无 T-table) | ~300-500 MB/s |

---

## ⚡ 三大开发原则 (v4.1.0+)

### 🥇 第一原则：C++ Core + C ABI 封装

**所有算法必须采用「C++ 实现功能 + C 的 ABI 封装」架构。**

#### 为什么需要 C ABI 封装？

即使完全使用 C++ 实现，引入 C 语言封装（extern "C"）的目的不是为了兼容 C，而是为了**消除 C++ 的运行时不确定性**：

| 优势 | 说明 |
|------|------|
| **ABI 稳定性** | C++ 调用约定在不同编译器（GCC/Clang/MSVC）或版本间可能不一致。C 封装确保名字修饰（Name Mangling）稳定，跨模块调用不会崩溃 |
| **内存边界控制** | C 接口强制显式处理内存（传入 `uint8_t*` 缓冲区），避免 `std::vector` 隐式内存拷贝或扩容，严格控制内存消耗 |
| **防止异常逃逸** | 加密算法集成在底层，C++ 异常传播到非 C++ 环境会导致崩溃。C 接口通过返回错误码（`kctsb_error_t`）处理异常，更安全高效 |

#### 标准实现模式

```cpp
// ============================================================================
// Internal C++ Implementation (namespace kctsb::internal)
// ============================================================================
namespace kctsb::internal {

class AES256 {
public:
    // Template metaprogramming: compile-time constant computation
    template<size_t Rounds>
    static constexpr auto generate_round_keys() noexcept;

    // Force inline for hot path
    __attribute__((always_inline))
    void encrypt_block(const uint8_t* in, uint8_t* out) noexcept;

    // Zero-copy in-place operation
    void transform_inplace(uint8_t* buffer, size_t len) noexcept;

private:
    // SIMD-aligned memory
    alignas(32) std::array<uint32_t, 60> round_keys_;
};

} // namespace kctsb::internal

// ============================================================================
// C ABI Export (extern "C")
// ============================================================================
extern "C" {

KCTSB_API kctsb_error_t kctsb_aes256_init(kctsb_aes_ctx_t* ctx,
                                           const uint8_t* key) {
    if (!ctx || !key) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    try {
        // Internal C++ logic, catch all exceptions
        auto& impl = *reinterpret_cast<kctsb::internal::AES256*>(ctx->opaque);
        impl.set_key(key);
        return KCTSB_SUCCESS;
    } catch (...) {
        return KCTSB_ERROR_INTERNAL;
    }
}

KCTSB_API void kctsb_aes256_clear(kctsb_aes_ctx_t* ctx) {
    if (ctx) {
        // Secure memory zeroing
        kctsb_secure_memzero(ctx, sizeof(*ctx));
    }
}

} // extern "C"
```

---

### 🥈 第二原则：C++17 统一标准 + 极限性能优化

**全项目统一使用 C++17 标准，启用最优编译参数，追求极致速度和最小内存占用。**

#### 强制编译标准

```cmake
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)  # 禁用 GNU 扩展，保证跨平台一致性
```

#### C++17 性能特性利用

| 特性 | 用途 | 示例 |
|------|------|------|
| `constexpr if` | 编译期分支消除 | `if constexpr (KeyBits == 256) { ... }` |
| `std::array` | 定长零开销容器 | 替代 C 数组，带边界检查（Debug） |
| `std::string_view` | 零拷贝字符串视图 | 参数传递避免拷贝 |
| `[[nodiscard]]` | 强制检查返回值 | 错误码必须处理 |
| `[[likely]]`/`[[unlikely]]` | 分支预测提示 | 热路径优化 |
| Fold expressions | 模板元编程简化 | 批量初始化 |

#### 极限优化编译参数

**GCC/Clang (Release 模式)**:
```bash
-O3                    # 最高优化级别
-march=native          # 针对当前 CPU 架构优化
-mtune=native          # 针对当前 CPU 调度优化
-ffast-math            # 快速浮点运算（仅适用非精确场景）
-funroll-loops         # 循环展开
-fomit-frame-pointer   # 省略栈帧指针
-flto                  # 链接时优化
-fPIC                  # 位置无关代码

# 内存优化
-fno-rtti              # 禁用 RTTI，减少内存占用
-fno-exceptions        # 禁用异常（C ABI 层处理错误）

# 硬件加速
-maes -mpclmul         # AES-NI + PCLMUL
-msse4.1 -msse4.2      # SSE4
-mavx2                 # AVX2
-mavx512f              # AVX-512 (可选)

# 安全加固
-fstack-protector-strong
-D_FORTIFY_SOURCE=2
```

**MSVC (Release 模式)**:
```
/O2 /Oi /Ot /GL /fp:fast /arch:AVX2
/LTCG (链接时代码生成)
```

#### 内存优化策略

| 策略 | 实现 |
|------|------|
| **预分配内存** | 加密上下文在初始化时一次性分配，或由调用者传入预分配缓冲区 |
| **零拷贝设计** | 直接在原始字节数组上原地（In-place）加密，避免数据搬运 |
| **内存对齐** | 使用 `alignas(16/32)` 确保 SIMD 加载最优 |
| **禁用 RTTI** | `-fno-rtti` 去掉虚函数表指针，减少对象大小 |
| **禁用异常** | `-fno-exceptions`，通过 C ABI 返回错误码 |

#### 64位架构与SIMD优化规范

> **核心原则：本库仅支持64位操作系统和硬件，所有优化默认使用64位操作和8-block并行处理。**

| 规范项 | 要求 | 说明 |
|--------|------|------|
| **目标架构** | 仅支持 x86_64/ARM64 | 不支持32位系统，无需32位兼容代码 |
| **整数类型** | 优先使用 `uint64_t` | 64位操作在64位CPU上性能最优 |
| **SIMD并行度** | 默认 8-block 并行 | CTR模式、ECB模式等使用8块并行处理 |
| **寄存器利用** | 充分利用64位寄存器 | AVX2: 16个256位寄存器 |
| **内存操作** | 64位对齐加载/存储 | `alignas(32)` 或 `alignas(64)` |

**SIMD并行处理标准**：

```cpp
// ✅ 正确: 8-block 并行 (默认标准)
static constexpr size_t PARALLEL_BLOCKS = 8;
for (size_t i = 0; i + PARALLEL_BLOCKS * BLOCK_SIZE <= len; i += PARALLEL_BLOCKS * BLOCK_SIZE) {
    // 8块并行处理 - 最大化流水线利用率
    process_8_blocks(data + i, out + i);
}

// ❌ 禁止: 4-block 并行 (低于标准)
// static constexpr size_t PARALLEL_BLOCKS = 4;  // 不符合规范
```

**64位整数优化**：

```cpp
// ✅ 正确: 使用64位操作
uint64_t counter = static_cast<uint64_t>(nonce_low) | 
                   (static_cast<uint64_t>(nonce_high) << 32);
counter += 8;  // 8-block增量

// ❌ 避免: 32位操作 (在64位系统上浪费性能)
// uint32_t counter_lo, counter_hi;  // 不推荐
```

---

### 🥉 第三原则：单文件单算法 + 禁止额外封装层

**每个算法使用一个独立的 .cpp 文件实现，C ABI 封装直接在该文件内导出，每个算法对应一个独立的 .h 头文件。**

#### ✅ 正确做法

```
src/crypto/
├── sha256.cpp       # SHA-256 C++ 实现 + C ABI 导出
├── sha512.cpp       # SHA-512 C++ 实现 + C ABI 导出
├── sha3.cpp         # SHA3 C++ 实现 + C ABI 导出
├── blake2.cpp       # BLAKE2 C++ 实现 + C ABI 导出
├── sm2.cpp          # SM2 C++ 实现 + C ABI 导出
├── sm3.cpp          # SM3 C++ 实现 + C ABI 导出
├── sm4.cpp          # SM4 C++ 实现 + C ABI 导出
└── ...

include/kctsb/crypto/
├── sha256.h         # SHA-256 公共头文件
├── sha512.h         # SHA-512 公共头文件
├── sha3.h           # SHA3 公共头文件
├── blake2.h         # BLAKE2 公共头文件
├── sm2.h            # SM2 公共头文件
├── sm3.h            # SM3 公共头文件
├── sm4.h            # SM4 公共头文件
└── ...
```

#### ❌ 禁止做法

```
# 禁止: 额外的 API 封装文件
src/crypto/sm/sm_api.cpp       # ❌ 不合理的额外封装

# 禁止: 同一算法多个头文件
include/kctsb/crypto/sm/
├── sm3.h            # 公共头
├── sm3_core.h       # ❌ 冗余
├── sm3_impl.h       # ❌ 冗余

# 禁止: 分散的实现文件
src/crypto/sm/
├── sm3.c            # ❌
├── sm_api.cpp       # ❌
├── sm_util.c        # ❌
```

#### 头文件模板

```c
/**
 * @file algorithm.h
 * @brief Algorithm - Public C API
 */
#ifndef KCTSB_CRYPTO_ALGORITHM_H
#define KCTSB_CRYPTO_ALGORITHM_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================
#define KCTSB_ALGORITHM_DIGEST_SIZE 32
#define KCTSB_ALGORITHM_BLOCK_SIZE 64

// ============================================================================
// Types
// ============================================================================
typedef struct kctsb_algorithm_ctx_s {
    uint8_t opaque[256];  // Opaque storage for C++ implementation
} kctsb_algorithm_ctx_t;

// ============================================================================
// C API Functions
// ============================================================================
KCTSB_API kctsb_error_t kctsb_algorithm_init(kctsb_algorithm_ctx_t* ctx);
KCTSB_API kctsb_error_t kctsb_algorithm_update(kctsb_algorithm_ctx_t* ctx,
                                                const uint8_t* data, size_t len);
KCTSB_API kctsb_error_t kctsb_algorithm_final(kctsb_algorithm_ctx_t* ctx,
                                               uint8_t* digest);
KCTSB_API kctsb_error_t kctsb_algorithm(const uint8_t* data, size_t len,
                                         uint8_t* digest);
KCTSB_API void kctsb_algorithm_clear(kctsb_algorithm_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_ALGORITHM_H
```

---

## 字节序规范 (Byte Order Convention)

### 核心原则

**内部存储使用小端序 (Little-Endian)，外部接口使用大端序 (Big-Endian)。**

| 组件 | 字节序 | 说明 |
|------|--------|------|
| NTL `BytesFromZZ`/`ZZFromBytes` | 小端序 | NTL 原生格式 |
| 外部字节数组输入 | 大端序 | 密码学标准格式 (PKCS#1, SEC 1, GM/T) |
| 外部字节数组输出 | 大端序 | 密码学标准格式 |
| 内部计算 | 小端序 | 利用 x86/ARM 原生优势 |

### 标准转换函数

使用 `kctsb/utils/byte_order.h` 提供的统一转换工具：

```cpp
#include "kctsb/utils/byte_order.h"

// C++ NTL 集成（需要定义 KCTSB_USE_NTL）
#define KCTSB_USE_NTL
#include "kctsb/utils/byte_order.h"

namespace kctsb::byte_order {
    // 大端字节数组 → NTL ZZ
    ZZ be_bytes_to_zz(const uint8_t* data, size_t len);
    
    // NTL ZZ → 大端字节数组
    void zz_to_be_bytes(const ZZ& z, uint8_t* out, size_t len);
    
    // PKCS#1 I2OSP/OS2IP
    int i2osp(const ZZ& x, size_t x_len, uint8_t* out);
    ZZ os2ip(const uint8_t* data, size_t len);
}
```

### 实现规范

#### ✅ 正确做法

```cpp
// 输入：大端序字节数组
void process_input(const uint8_t* be_input, size_t len) {
    // 转换为 NTL ZZ
    NTL::ZZ value = kctsb::byte_order::be_bytes_to_zz(be_input, len);
    
    // 内部计算...
    NTL::ZZ result = compute(value);
    
    // 输出：转换回大端序
    kctsb::byte_order::zz_to_be_bytes(result, output, len);
}
```

#### ❌ 禁止做法

```cpp
// 禁止：直接使用 NTL 原生函数（输出为小端序）
NTL::BytesFromZZ(output, zz_value, len);  // ❌ 输出小端序，不符合标准

// 禁止：手动反转没有统一接口
std::reverse(output, output + len);  // ❌ 分散实现，难以维护
```

### ECC/RSA/SM2 字节序要求

| 算法 | 公钥格式 | 签名格式 | 密文格式 |
|------|----------|----------|----------|
| RSA | I2OSP (大端) | I2OSP (大端) | I2OSP (大端) |
| ECDSA | SEC 1 (大端) | DER/固定 (大端) | - |
| SM2 | GB/T 32918 (大端) | (r,s) 固定64字节 (大端) | C1‖C3‖C2 (大端) |
| ECDH | SEC 1 (大端) | - | - |

---

## 开发约束


### 编译器要求

**Linux Docker 构建要求 GCC 12+ (2026-01-15)**:
- **原因**: NTL 11.6.0 的模板代码在 GCC 11 下会产生编译错误
- **Docker 镜像**: AlmaLinux 9 + gcc-toolset-12 (GCC 12.2.1)
- **C++ 标准**: C++17 (`-std=c++17`)

| 平台 | 编译器 | 版本要求 | 镜像/工具链 |
|------|--------|----------|------------|
| Windows | MinGW-w64 GCC | 13.0+ | Strawberry C |
| Windows | MSVC | 2022+ | Visual Studio 2022 |
| Linux Docker | GCC | **12.0+** | AlmaLinux 9 + gcc-toolset-12 |
| Linux Native | GCC/Clang | 12.0+ | 系统自带 |

### 依赖管理

**跨平台 thirdparty 目录结构** (v3.4.0+):
```
thirdparty/
├── win-x64/          # Windows x64 预编译库
│   ├── lib/          # libntl.a, libgmp.a, libgf2x.a, etc.
│   └── include/      # 头文件
├── linux-x64/        # Linux x64 预编译库 (Docker 构建)
│   ├── lib/          # libntl.a, libgmp.a, libgf2x.a
│   └── include/      # NTL/, gmp.h, gf2x.h
├── lib/              # 通用库 (Windows 兼容)
└── include/          # 通用头文件
```

**CMake 搜索顺序**:
1. `thirdparty/${PLATFORM_SUFFIX}/` (平台特定)
2. `thirdparty/` (通用)
3. 系统路径

**Linux thirdparty 构建命令**:
```bash
# 构建 Linux 平台依赖并提取到 thirdparty/linux-x64/
./scripts/build_thirdparty_linux.sh

# Docker 构建并测试
./scripts/docker_build.sh --test
```

**核心依赖** (2026-01-15):
| 依赖 | 版本 | 位置 | 状态 | 用途 |
|------|------|------|------|------|
| GMP | 6.3.0+ | thirdparty | ✅ 必需 | 高精度整数 |
| gf2x | 1.3.0+ | thirdparty | ✅ 必需 | NTL 依赖 |
| NTL | 11.6.0+ | thirdparty | ✅ 必需 | 数论、ECC、大数运算加速 |
| SEAL | 4.1.2 | thirdparty | ⚠️ 可选 | 同态加密 |
| HElib | v2.3.0 | thirdparty | ⚠️ 可选 | 函数加密 |

**Benchmark 专用依赖** (仅 benchmarks/ 可用):
| 依赖 | 版本 | 来源 | 用途 |
|------|------|------|------|
| OpenSSL | 3.6.0+ | vcpkg (`D:/vcpkg`) | 性能对比 |
| zlib | 1.3.1 | vcpkg | 压缩支持 |
| zstd | 1.5.7 | vcpkg | 压缩支持 |

### 依赖约束 ⚠️

1. **核心依赖** (src/ 目录可用):
   - ✅ NTL 11.6.0+: 数论运算、椭圆曲线、大数加速
   - ✅ GMP 6.3.0+: 高精度整数
   - ✅ gf2x 1.3.0+: NTL 的 GF(2) 多项式运算
   - ⚠️ SEAL 4.1.2 (可选): 同态加密
   - ⚠️ HElib v2.3.0 (可选): 函数加密

2. **禁止依赖** (src/ 目录禁用):
   - ❌ OpenSSL: 目标是替代它
   - ❌ MIRACL: 已移除，使用 NTL 实现 ECC
   - ❌ 其他外部库: 使用纯 C++ 原生实现

3. **benchmark 依赖** (仅 benchmarks/ 目录可用):
   - ✅ OpenSSL: 性能对比测试
   - ✅ zlib/zstd: 压缩 benchmark

### 目录规范

1. **include/**: 所有头文件 (.h) 必须放在此目录
   - src/ 目录禁止放置头文件
   - 公共 API: `include/kctsb/crypto/*.h`
   - 内部实现: `include/kctsb/internal/*.h` (极少使用)

2. **src/crypto/**: 算法实现源文件
   - 每个算法一个 .cpp 文件
   - C ABI 封装在同一文件内导出

3. **thirdparty/**: 第三方库编译产物
   - `thirdparty/include/`: 第三方头文件
   - `thirdparty/lib/`: 静态库 (.a)

4. **build/**: CMake 构建目录 (不提交 Git)

### 代码语言政策

- **src/ 目录**: 所有注释和变量名必须使用**英文**
- **docs/ 目录**: 文档可使用中文
- 禁止在代码中使用中文注释或变量名

### Hash 算法统一调用规范

**所有使用 hash 算法的模块，必须统一调用 `src/crypto/` 下的 hash 实现：**

- `kctsb_sha256()` - SHA-256
- `kctsb_sha512()` - SHA-512  
- `kctsb_sha3_256()` / `kctsb_sha3_512()` - SHA3
- `kctsb_blake2b()` / `kctsb_blake2s()` - BLAKE2
- `kctsb_sm3()` - SM3

**禁止**在其他模块中重复实现 hash 算法。

---

## 📋 算法模块说明

### crypto/ - 标准密码算法

| 模块 | 功能 | 文件 | 实现状态 |
|------|------|------|----------|
| sha256 | SHA-256 | sha256.cpp + sha256.h | ✅ 生产就绪 |
| sha512 | SHA-512 | sha512.cpp + sha512.h | ✅ 生产就绪 |
| sha3 | SHA3-256/512 (Keccak) | sha3.cpp + sha3.h | ✅ 生产就绪 |
| blake2 | BLAKE2b/BLAKE2s | blake2.cpp + blake2.h | ✅ 生产就绪 |
| blake3 | BLAKE3 | blake3.cpp + blake3.h | ✅ 生产就绪 |
| aes | AES-128/192/256-GCM | aes.cpp + aes.h | ✅ 生产就绪 |
| chacha20 | ChaCha20-Poly1305 | chacha20.cpp + chacha20.h | ✅ 生产就绪 |
| sm2 | 国密 SM2 椭圆曲线 | sm2.cpp + sm2.h | ✅ 生产就绪 |
| sm3 | 国密 SM3 哈希 | sm3.cpp + sm3.h | ✅ 生产就绪 |
| sm4 | 国密 SM4-GCM | sm4.cpp + sm4.h | ✅ 生产就绪 |
| rsa | RSA-OAEP/PSS | rsa.cpp + rsa.h | ✅ 生产就绪 |
| ecc | ECC/ECDSA/ECDH/ECIES | ecc.cpp + ecc.h | ✅ 生产就绪 |

### advanced/ - 高级密码学

| 模块 | 功能 | 实现状态 | 依赖 |
|------|------|----------|------|
| whitebox | 白盒 AES (Chow 方案) | ✅ 完成 | 无 |
| sss | Shamir 秘密共享 | ✅ 完成 | NTL |
| zk/ffs | Feige-Fiat-Shamir | ✅ 完成 | NTL |
| zk/snarks | Groth16 zk-SNARKs | ✅ 完成 | NTL |
| pqc | 后量子密码 (Kyber/Dilithium) | ✅ 完成 | NTL |
| lattice | 格密码 (LLL 约简) | ✅ 完成 | NTL |
| fe | 函数加密 (BGV) | ⚠️ 可选 | HElib |

---

## 🚀 构建命令

### Linux/macOS (推荐)

```bash
# 一键构建 + 测试
./scripts/build.sh --all

# 仅构建
./scripts/build.sh

# 构建 + benchmark
./scripts/build.sh --benchmark
```

### Windows (PowerShell)

```powershell
# 一键构建 + 测试
.\scripts\build.ps1 -All

# 构建 + 创建 release (含 bundled 库)
.\scripts\build.ps1 -Release

# 构建 NTL bundled 库 (NTL + GMP + gf2x)
.\scripts\build_ntl_bundled.ps1
```

### Linux/macOS

```bash
# 一键构建 + 测试
./scripts/build.sh --all

# 构建 + 创建 release (含 bundled 库)
./scripts/build.sh --release

# 构建 NTL bundled 库
./scripts/build_ntl_bundled.sh
```

### 手动构建

```bash
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DKCTSB_BUILD_TESTS=ON \
    -DKCTSB_BUILD_BENCHMARKS=ON

cmake --build build --parallel $(nproc)
ctest --test-dir build --output-on-failure
```

---

## 🎯 API 设计规范

### C 函数命名

```c
kctsb_<algorithm>_<operation>()

// 示例
kctsb_sha256_init()
kctsb_sha256_update()
kctsb_sha256_final()
kctsb_sha256()          // 一次性调用
kctsb_sha256_clear()
```

### 三段式 API (流式处理)

```c
// 初始化
kctsb_error_t kctsb_sha256_init(kctsb_sha256_ctx_t* ctx);

// 更新 (可多次调用)
kctsb_error_t kctsb_sha256_update(kctsb_sha256_ctx_t* ctx,
                                   const uint8_t* data, size_t len);

// 完成
kctsb_error_t kctsb_sha256_final(kctsb_sha256_ctx_t* ctx,
                                  uint8_t digest[32]);

// 清理
void kctsb_sha256_clear(kctsb_sha256_ctx_t* ctx);
```

### 一次性 API

```c
// 小数据一次性处理
kctsb_error_t kctsb_sha256(const uint8_t* data, size_t len,
                           uint8_t digest[32]);
```

### 测试要求

- 使用官方测试向量 (NIST/RFC/GM/T)
- 边界条件测试
- 性能 benchmark 与 OpenSSL 对比

### 安全要求

- 时间常量操作 (防侧信道)
- 敏感数据清零 (使用 `kctsb_secure_memzero`)
- 输入验证

---

## ⚠️ 安全注意事项

### 生产环境使用指南

1. **代码审计**: 生产环境部署前，建议进行独立的安全代码审计
2. **侧信道防护**: 
   - 当前 AES-GCM 和 ChaCha20 实现为软件实现，可能存在时间侧信道
   - 高安全需求建议使用硬件 AES-NI 指令或 HSM
3. **内存安全**: 
   - 使用 `kctsb_secure_memzero()` 清理敏感数据
   - 避免在日志中输出密钥材料
4. **随机数生成**: 
   - Windows: BCryptGenRandom (CSPRNG)
   - Unix: /dev/urandom (getrandom syscall)
   - 不要使用 rand() 或 time-based 种子

### 密码学最佳实践

- **密钥管理**: 密钥应存储在安全硬件或加密的密钥库中
- **IV/Nonce**: GCM 模式下 IV 必须唯一，绝不能重用
- **认证**: 始终使用 AEAD 模式 (GCM/Poly1305)，避免使用 ECB/CBC-only
- **密钥派生**: 使用 HKDF 或 Argon2 派生密钥，不要直接使用密码

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
