# AGENTS.md - kctsb AI Development Guidelines

> **项目**: kctsb - Knight's Cryptographic Trusted Security Base  
> **版本**: 5.0.0  
> **更新时间**: 2026-01-24 (Beijing Time, UTC+8)  

---

## 🎯 项目概述

kctsb (Knight's Cryptographic Trusted Security Base) 是一个**生产级**跨平台C++密码学和安全算法库，可用于安全研究、生产部署和算法验证。
参考项目（源码在deps目录）：
- NTL 11.6.0: 高性能数论库
- GMP 6.3.0: 多精度整数运算
- gf2x 1.3.0: 二进制多项式运算
- SEAL 4.1.2: 微软同态加密库
- HElib v2.3.0: IBM 同态加密库
- OpenSSL 3.6.0: 主流加密库
bug跟踪与经验总结在 docs/troubleshooting/ 目录。
禁止使用类似“Select-Object -Last 20”的方式截断日志，必须提供完整日志以便准确诊断问题。
---

## 🚀 架构变更 (2026-01-21)

### 1. ECC模块精简
**删除fe256加速层，简化架构：**
移除了之前的 fe256* 系列文件（6个）临时保存在temp_restore目录，回归单文件原则的实现：
**当前ECC模块结构（精简后）：**
```
src/crypto/ecc/
├── ecc_curve.cpp      # ECC核心：曲线参数+点运算+标量乘法
├── ecdsa.cpp          # ECDSA签名
├── ecdh.cpp           # ECDH密钥交换
├── ecies.cpp          # ECIES加密
└── asm/
    └── fe256_x86_64.S # x86_64汇编优化（可选）
```

### 2. 测试目录规范

**所有单元测试统一放在 `tests/unit/` 目录下：**

```
tests/
├── unit/
│   ├── crypto/        # 加密算法测试
│   │   ├── test_aes.cpp
│   │   ├── test_hash.cpp
│   │   └── test_ecc.cpp
│   ├── fhe/           # 同态加密测试 (v4.7.0 新增目录)
│   │   └── test_bgv.cpp
│   ├── math/
│   │   └── test_math.cpp
│   └── security/
│       └── test_security_boundaries.cpp
├── integration/       # 集成测试
└── performance/       # 性能测试
```

### 3. 增量编译优化

**默认关闭测试和基准测试构建，加速日常开发迭代：**

```cmake
# 默认配置 - 仅构建核心库和CLI
option(KCTSB_BUILD_TESTS "Build unit tests (default OFF)" OFF)
option(KCTSB_BUILD_BENCHMARKS "Build benchmarks (default OFF)" OFF)
option(KCTSB_BUILD_CLI "Build kctsb.exe CLI tool" ON)
```

**构建命令：**
```powershell
# 快速增量构建 (< 30秒)
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 8

# 需要测试时显式启用
cmake -B build -G Ninja -DKCTSB_BUILD_TESTS=ON
cmake --build build --parallel 8
ctest --test-dir build --output-on-failure
```

---

## 🚀 v4.1.0 架构变更

### 1. NTL 源码完全集成

- 原 NTL 库源码已完全集成到 `src/math/bignum/` 目录
- 所有 `NTL_*` 宏逐步迁移为 `KCTSB_*` 前缀
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

#### 单文件原则细则

| 规则 | 说明 | 示例 |
|------|------|------|
| **核心算法单文件** | 一个核心算法的所有实现放在一个 .cpp 文件 | `fe256.cpp` 包含 secp256k1/P-256/SM2 全部场运算 |
| **禁止按曲线拆分** | 不同曲线的同类算法不单独成文件 | ❌ `fe256_p256.cpp`, `fe256_sm2.cpp` |
| **辅助代码允许分离** | 点运算、签名等可独立成文件 | ✅ `fe256.cpp` (场运算) + `fe256_point.cpp` (点运算) |
| **汇编代码独立** | 平台相关汇编放在 `asm/` 子目录 | ✅ `asm/fe256_x86_64.S` |
| **测试合并原则** | 相关测试合并到统一测试文件 | ✅ `test_ecc.cpp` 包含所有 ECC 测试 |

#### 文件合并指导

**何时应该合并：**
- 同一算法的多个变体 (AES-128/192/256 → `aes.cpp`)
- 同类曲线的场运算 (secp256k1/P-256/SM2 → `fe256.cpp`)
- 相关的测试用例 (test_fe256 + test_fe256_point → `test_ecc.cpp`)

**何时应该分离：**
- 不同层次的抽象 (场运算 vs 点运算 vs 签名)
- 平台相关代码 (C++ 实现 vs 汇编优化)
- 可选功能模块 (核心库 vs benchmark)

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

---

### 🥇 第四原则：三层头文件架构

**头文件分为三层，各司其职，严格遵循包含关系。**

#### 头文件层次定义

| 层级 | 头文件 | 用途 | 包含者 |
|------|--------|------|--------|
| **外部公共层** | `kctsb_api.h` | 外部程序/独立二进制调用的唯一公共头 | 外部用户 |
| **内部公共层** | `kctsb.h` + 各模块 `.h` | 内部模块间调用 | 内部 cpp 文件 |
| **内部私有层** | 各模块 `.hpp` | 单个 cpp 文件内部闭环 | 仅对应的 cpp |

#### 外部公共层: `kctsb_api.h`

**设计原则**:
- 类似 OpenSSL 的 evp.h，是外部用户唯一需要的头文件
- **完全自包含**：不依赖任何内部头文件
- 仅包含 C ABI 函数声明和必要的类型定义
- 使用类型守卫宏防止重复定义

```c
// kctsb_api.h - 外部公共 API
#ifndef KCTSB_API_H
#define KCTSB_API_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// 自包含的类型定义（带类型守卫）
#ifndef KCTSB_ERROR_T_DEFINED
#define KCTSB_ERROR_T_DEFINED
typedef enum { KCTSB_SUCCESS = 0, ... } kctsb_error_t;
#endif

#ifndef KCTSB_SHA256_CTX_DEFINED
#define KCTSB_SHA256_CTX_DEFINED
typedef struct { uint8_t opaque[128]; } kctsb_sha256_ctx_t;
#endif

// C ABI 函数声明
KCTSB_API kctsb_error_t kctsb_sha256(const uint8_t* data, size_t len, uint8_t* digest);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_API_H
```

#### 内部公共层: `kctsb.h` + 模块 `.h`

**设计原则**:
- `kctsb.h` 作为内部统一入口，包含所有模块头文件
- 各模块 `.h` 供内部模块间调用
- 可以包含 C++ 类定义和 namespace

```cpp
// kctsb.h - 内部统一入口
#include "kctsb/core/common.h"      // 内部通用定义
#include "kctsb/crypto/sha256.h"    // SHA-256 模块
#include "kctsb/crypto/aes.h"       // AES 模块
// ...

// sha256.h - SHA-256 模块头文件（内部公共）
namespace kctsb {
class SHA256 {
public:
    void update(const uint8_t* data, size_t len);
    void final(uint8_t digest[32]);
};
}

// 同时暴露 C ABI（供 kctsb_api.h 转发）
extern "C" {
    kctsb_error_t kctsb_sha256_init(kctsb_sha256_ctx_t* ctx);
    // ...
}
```

#### 内部私有层: 模块 `.hpp`

**设计原则**:
- 仅供对应的 `.cpp` 文件包含
- 包含实现细节：模板实现、内联函数、私有辅助类
- 文件名与 `.cpp` 对应

```cpp
// sha256_impl.hpp - SHA-256 内部实现细节
#ifndef KCTSB_SHA256_IMPL_HPP
#define KCTSB_SHA256_IMPL_HPP

namespace kctsb::internal {

// 编译期 S-Box 生成
static constexpr std::array<uint32_t, 64> generate_k_constants() noexcept {
    // ...
}

// 内联辅助函数
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept {
    return (x & y) ^ (~x & z);
}

} // namespace kctsb::internal

#endif // KCTSB_SHA256_IMPL_HPP
```

#### 头文件包含规则

| 文件类型 | 可以包含 | 禁止包含 |
|----------|----------|----------|
| `kctsb_api.h` | 仅 `<stdint.h>` 等标准库 | 任何内部头文件 |
| `kctsb.h` | 所有模块 `.h` | 模块 `.hpp` |
| 模块 `.h` | `core/common.h`, 其他模块 `.h` | 具体模块 `.hpp` |
| 模块 `.cpp` | 对应 `.h`, 对应 `.hpp`, 其他模块 `.h` | 其他模块 `.hpp` |
| 模块 `.hpp` | 对应 `.h` | 其他模块文件 |

#### 类型守卫命名规范

```c
// 格式: KCTSB_<TYPE_NAME>_DEFINED
#ifndef KCTSB_SHA256_CTX_DEFINED
#define KCTSB_SHA256_CTX_DEFINED
typedef struct { ... } kctsb_sha256_ctx_t;
#endif
```

#### ✅ 正确的包含示例

```cpp
// 外部用户
#include <kctsb_api.h>  // 唯一需要的头文件

// 内部模块 (sha256.cpp)
#include "kctsb/crypto/sha256.h"      // 对应的模块头文件
#include "kctsb/crypto/sha256_impl.hpp"  // 内部实现细节

// 内部模块间调用 (sm2.cpp 需要使用 SHA-256)
#include "kctsb/crypto/sm/sm2.h"      // 自身模块
#include "kctsb/crypto/sha256.h"      // 调用其他模块
```

#### ❌ 禁止的包含方式

```cpp
// 禁止: kctsb_api.h 包含内部头文件
#include "kctsb/core/common.h"  // ❌

// 禁止: 模块 A 包含模块 B 的 .hpp
#include "kctsb/crypto/sha256_impl.hpp"  // ❌ (仅 sha256.cpp 可包含)

// 禁止: 测试文件同时包含 kctsb_api.h 和内部 .hpp
#include "kctsb_api.h"
#include "kctsb/crypto/sha256_impl.hpp"  // ❌ 混乱的层级
```

---

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

### 📁 文件版本管理规范 (v4.11.0+)

**核心原则**: 不使用 V1/V2/V3 等版本后缀作为文件名，最新版本直接使用主文件名。

| 规则 | 说明 | 示例 |
|------|------|------|
| **主文件名** | 最新/生产版本使用无版本后缀的文件名 | `bgv_evaluator.cpp` (不是 `bgv_evaluator_v2.cpp`) |
| **历史备份** | 需要保留旧版本时使用 `.bak` 后缀 | `bgv_evaluator.cpp.bak_v1` |
| **中间状态清理** | 开发完成后删除中间版本文件 | 删除 `bgv_evaluator_v1.cpp`, `bgv_evaluator_v2.cpp` |
| **版本迁移** | 新版本完成后，旧版本归档到 `.bak` | `mv old.cpp old.cpp.bak_vX` |

**实施流程**:
```bash
# 1. 开发新版本时，可以临时使用 _v2 后缀
bgv_evaluator.cpp       # 当前生产版本
bgv_evaluator_v2.cpp    # 开发中的新版本

# 2. 新版本完成并测试通过后
mv bgv_evaluator.cpp bgv_evaluator.cpp.bak_v1   # 备份旧版本
mv bgv_evaluator_v2.cpp bgv_evaluator.cpp       # 新版本成为主文件

# 3. 清理中间文件
rm *_v2.cpp *_v2.hpp    # 删除已迁移的中间版本
```

**禁止**:
- ❌ 同时维护 `xxx.cpp` 和 `xxx_v2.cpp` 作为生产代码
- ❌ 使用 `xxx_new.cpp`, `xxx_final.cpp` 等命名
- ❌ 在 include/ 目录保留多个版本的头文件

**允许**:
- ✅ 开发期间临时使用 `_v2` 后缀
- ✅ 使用 `.bak_vX` 保留历史版本供参考
- ✅ 在 `docs/archive/` 存放历史设计文档

### 跨平台数据类型安全 ⚠️

**关键规则 (2026-01-20 SM2 Bug 教训)**:

| 数据类型 | Windows x64 | Linux x64 | 规则 |
|----------|-------------|-----------|------|
| `long` | ❌ **32-bit** | 64-bit | **禁止使用** |
| `unsigned long` | ❌ **32-bit** | 64-bit | **禁止使用** |
| `int64_t` | ✅ 64-bit | ✅ 64-bit | **必须使用** |
| `uint64_t` | ✅ 64-bit | ✅ 64-bit | **必须使用** |
| `int32_t` | ✅ 32-bit | ✅ 32-bit | 明确需要32位时 |
| `size_t` | 64-bit | 64-bit | 用于数组索引 |

**开发准则**:
1. **禁止使用 `long`/`unsigned long`** - Windows 与 Linux 位宽不同
2. **必须使用 `<cstdint>` 精确类型** - `int64_t`, `uint64_t`, `int32_t`
3. **累加器使用 `int64_t`** - 允许负数进位处理 (如 Solinas reduction)
4. **乘法结果使用 `uint128_t`** 或手动拆分为高/低 64 位

**错误示例**:
```cpp
// ❌ WRONG - Windows 上 long 只有 32 位
long carry = a + b;  // 溢出!

// ✅ CORRECT
int64_t carry = (int64_t)a + (int64_t)b;
```

参见 `docs/troubleshooting/fe256_data_type_issues.md` 获取完整分析。

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
| gf2x | 1.3.0+ | thirdparty | ✅ 必需 | 有限域运算 依赖 |


**Benchmark 专用依赖** (仅 benchmarks/ 可用):
| 依赖 | 版本 | 来源 | 用途 |
|------|------|------|------|
| OpenSSL | 3.6.0+ | vcpkg (`D:/vcpkg`) | 性能对比 |
| SEAL | 4.1.2 | thirdparty | ⚠️ 可选 | 同态加密 |
| HElib | v2.3.0 | thirdparty | ⚠️ 可选 | 函数加密 |
| zlib | 1.3.1 | vcpkg | 压缩支持 |
| zstd | 1.5.7 | vcpkg | 压缩支持 |


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
| sss | Shamir 秘密共享 | ✅ 完成 |无 |
| zk/ffs | Feige-Fiat-Shamir | ✅ 完成 | 无 |
| zk/snarks | Groth16 zk-SNARKs | ✅ 完成 | 无 |
| pqc | 后量子密码 (Kyber/Dilithium) | ✅ 完成 | 无 |
| lattice | 格密码 (LLL 约简) | ✅ 完成 | 无 |
| fe | 函数加密 (BGV) | ⚠️ 可选 | 无 |

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

```

### 手动构建

```bash
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

### 🔒 ECC 安全开发规则 

**重要：以下规则为强制性安全约束，违反会导致代码审查失败。**

#### ❌ 禁止使用的算法和实现

| 禁止项 | 原因 | 替代方案 |
|--------|------|----------|
| **wNAF 标量乘法** | 存在侧信道泄露（非常量时间执行） | 使用 Montgomery ladder |
| **滑动窗口方法** | 查表操作泄露标量位信息 | 使用 Montgomery ladder |
| **二进制展开法** | 条件分支泄露标量位 | 使用 Montgomery ladder |
| **预计算表 (wNAF 用途)** | 表访问模式泄露敏感信息 | 移除预计算表依赖 |

#### ✅ 强制要求的实现

| 操作 | 强制实现 | 说明 |
|------|----------|------|
| **标量乘法 (k * P)** | Montgomery ladder | 常量时间，每位执行相同操作 |
| **基点乘法 (k * G)** | Montgomery ladder | 同上，不允许例外 |
| **双标量乘法** | Shamir's trick | k1*P + k2*Q 同时计算 |

#### Montgomery Ladder 实现规范

```cpp
/**
 * @brief Montgomery ladder scalar multiplication (constant-time)
 * 
 * CRITICAL SECURITY REQUIREMENT:
 * - Every bit of scalar k must perform EXACTLY one double and one add
 * - No early termination allowed
 * - No conditional branches based on scalar bits
 */
JacobianPoint montgomery_ladder(const ZZ& k, const JacobianPoint& P) const {
    JacobianPoint R0;  // Infinity
    JacobianPoint R1 = P;
    
    long num_bits = NumBits(k);
    
    for (long i = num_bits - 1; i >= 0; --i) {
        if (bit(k, i)) {
            R0 = add(R0, R1);
            R1 = double_point(R1);
        } else {
            R1 = add(R0, R1);
            R0 = double_point(R0);
        }
    }
    
    return R0;
}
```

---

## � SM2 Montgomery 加速优化 (v5.0.0)

> **更新日期**: 2026-01-24 (Beijing Time, UTC+8)

### 优化概述

SM2 现已集成 Montgomery 域加速，对基点标量乘法 (k*G) 实现了显著性能提升：

| 操作 | 优化前 | 优化后 | 改进倍数 | vs OpenSSL |
|------|--------|--------|----------|------------|
| **KeyGen** | 0.25 ms | 0.24 ms | 1.04x | **117.83%** (比 OpenSSL 快！) |
| **Sign** | 134.5 ms | 2.0 ms | **67x** | 15.04% |
| **Verify** | 271 ms | 135.4 ms | **2x** | 0.22% |
| **Encrypt** | 265.5 ms | 136.4 ms | **1.9x** | 0.46% |
| **Decrypt** | 133 ms | 133.5 ms | ~1x | 0.22% |

### Montgomery 域实现文件

```
src/crypto/sm/
├── sm2_keygen.cpp        # 密钥生成 (d*G 使用 Montgomery)
├── sm2_sign.cpp          # 签名/验证 (k*G, s*G 使用 Montgomery)
├── sm2_encrypt.cpp       # 加密/解密 (k*G 使用 Montgomery)
├── sm2_mont.h            # Montgomery 域常量
├── sm2_mont.cpp          # Montgomery 域低级场运算
├── sm2_mont_curve.h      # Montgomery 域曲线点运算 API
└── sm2_asm.h             # x86_64 汇编优化 (可选, 当前禁用)
```

### 关键实现细节

**Montgomery 常量** (SM2 Prime: p = 2^256 - 2^224 - 2^96 + 2^64 - 1):

| 常量 | 描述 | 值 (小端 limb 顺序) |
|------|------|---------------------|
| `SM2_RR` | R² mod p | 用于转换到 Montgomery 域 |
| `SM2_MONT_ONE` | R mod p | Montgomery 域中的 1 |
| `SM2_P_PRIME` | -p⁻¹ mod 2^64 | Montgomery 约简参数 |

**wNAF 预计算优化**:
- 窗口宽度: w=5
- 预计算点: 16个 [G, 3G, 5G, ..., 31G]
- 所有预计算点存储在 Montgomery 域

**重要 Bug 修复** (2026-01-24):
```cpp
// 标量字节到 limb 转换 - 必须使用正确的字节偏移
// SM2 标量为大端字节序 (32 bytes), 需转换为小端 limbs (4 x uint64_t)

// ❌ 错误实现 (导致签名/验证失败):
for (int i = 0; i < 4; i++) {
    uint64_t limb = 0;
    for (int j = 0; j < 8; j++) {
        limb = (limb << 8) | k[i * 8 + j];
    }
    k_limbs[3 - i] = limb;  // 错误: limb 顺序颠倒
}

// ✅ 正确实现:
for (int i = 0; i < 4; i++) {
    uint64_t limb = 0;
    int offset = (3 - i) * 8;  // 正确: 24, 16, 8, 0
    for (int j = 0; j < 8; j++) {
        limb = (limb << 8) | k[offset + j];
    }
    k_limbs[i] = limb;  // limbs[0]=LSB, limbs[3]=MSB
}
```

### 当前限制

| 操作 | Montgomery 加速 | 备注 |
|------|-----------------|------|
| d*G (KeyGen) | ✅ 已启用 | 使用 `scalar_mult_base_mont` |
| k*G (Sign) | ✅ 已启用 | 使用 `scalar_mult_base_mont` |
| s*G (Verify) | ✅ 已启用 | 使用 `scalar_mult_base_mont` |
| k*G (Encrypt) | ✅ 已启用 | 使用 `scalar_mult_base_mont` |
| t*P (Verify) | ❌ 待实现 | 需要任意点标量乘法 |
| d*C1 (Decrypt) | ❌ 待实现 | 需要任意点标量乘法 |
| k*P (Encrypt) | ❌ 待实现 | 需要任意点标量乘法 |

### 汇编优化状态

x86_64 汇编实现 (`sm2_asm.h`) 当前**禁用**:

```cpp
// 在 sm2_asm.h 中
#if 0  // 临时禁用汇编，使用 C++ 实现
#if defined(__x86_64__) || defined(_M_X64)
    #define KCTSB_SM2_USE_ASM 1
#endif
#endif
```

汇编问题待调试：
- `fe256_mul_512` 进位链可能存在问题
- Montgomery 约简函数需要验证

---

## �🔗 相关资源

### 标准文档
- FIPS 202 (SHA-3): https://csrc.nist.gov/publications/detail/fips/202/final
- RFC 7539 (ChaCha20-Poly1305): https://tools.ietf.org/html/rfc7539
- RFC 7693 (BLAKE2): https://tools.ietf.org/html/rfc7693
- GM/T 0002-2012 (SM4), GM/T 0003-2012 (SM2), GM/T 0004-2012 (SM3)

### 依赖库
- NTL: https://libntl.org/ (v11.6.0+)
- GMP: https://gmplib.org/ (v6.3.0+)
- Microsoft SEAL: https://github.com/microsoft/SEAL (v4.1.2)
- HElib: https://github.com/homenc/HElib (v2.3.0)
---

## 🎯 FHE 模块工业级性能规范 (v4.11.0+)

> **核心目标**: 替代SEAL和HElib成为工业级开源FHE库

### 性能基准要求 (n=8192)

| 操作 | 参数 | 目标时间 | SEAL参考 | 状态 |
|------|------|---------|----------|------|
| **KeyGen (SK+PK)** | n=8192, L=3 | < 5 ms | ~50 ms | ✅ 10x faster |
| **Encrypt** | n=8192 | < 3 ms | ~5 ms | ✅ 达标 |
| **Decrypt** | n=8192 | < 1 ms | ~2 ms | ✅ 达标 |
| **Multiply+Relin** | n=8192, L=3 | < 15 ms | ~18 ms | ✅ 目标 |
| **Add** | n=8192 | < 0.1 ms | ~0.1 ms | ✅ 达标 |
| **Rotation** | n=8192 | < 10 ms | ~12 ms | 📋 Phase 4d |

**禁止**: 使用教育性的慢速实现（如CRT重构后大整数乘法）

### BFV 乘法必须使用 BEHZ 方法

**BEHZ Base Extension** (Bajard-Eynard-Hasan-Zucca 2016):

```
核心思想: 使用辅助模数基 B = {b_0, b_1, ..., b_k} 来处理 RNS 下的除法和舍入

BFV Multiply 步骤:
1. 张量积计算 (NTT domain): c' = c1 ⊗ c2
2. Base Extension Q → B: 将结果从模数基 Q 扩展到辅助基 B  
3. 在辅助基 B 上计算 round(c' * t / Q)
4. Base Extension B → Q: 将结果转换回原模数基
```

**参考实现**:
- SEAL 4.1: `seal/util/rns.cpp` - `base_converter` 类
- HElib: `helib/NumbTh.cpp` - `CRT` 和 `base conversion`

### SIMD 硬件加速路径

**必须支持的加速路径**:

| 硬件特性 | 检测方法 | 加速倍率 | 优先级 |
|----------|----------|----------|--------|
| **AVX-512** | `__AVX512F__` | 4-8x NTT | 🥇 最高 |
| **AVX2** | `__AVX2__` | 2-4x NTT | 🥈 次高 |
| **AES-NI** | `__AES__` | 10x 对称加密 | ✅ 已启用 |
| **CUDA** | 运行时检测 | 10-100x FHE ops | 📋 可选 |

**AVX-512 NTT 优化**:
```cpp
// 检测 AVX-512 支持
#if defined(__AVX512F__) && defined(__AVX512VL__)
    #define KCTSB_HAS_AVX512 1
#endif

// Harvey NTT with AVX-512 (8 modular reductions per instruction)
void ntt_forward_avx512(uint64_t* data, size_t n, const NTTTable& table);
void ntt_inverse_avx512(uint64_t* data, size_t n, const NTTTable& table);
```

### CUDA 加速 (可选)

**适用场景**: 批量FHE操作 (PIR/PSI)

```cpp
// GPU 加速配置
struct CudaFHEConfig {
    bool enabled = false;           // 运行时检测
    size_t min_batch_size = 16;     // 小于此批量不启用 GPU
    size_t gpu_memory_limit = 4ULL << 30; // 4GB 显存限制
};

// GPU 批量乘法
void bfv_multiply_batch_cuda(
    const std::vector<BFVCiphertext>& cts1,
    const std::vector<BFVCiphertext>& cts2,
    std::vector<BFVCiphertext>& results,
    const CudaFHEConfig& config);
```

### 测试超时配置

**单元测试必须在合理时间内完成**:

| 测试类型 | 参数 | 最大时间 | 说明 |
|----------|------|---------|------|
| n=256 快速测试 | L=2 | 100 ms | 功能验证 |
| n=8192 标准测试 | L=3 | 500 ms | 正确性验证 |
| n=8192 性能测试 | L=3, 10次重复 | 5 sec | 性能基准 |

**禁止**: 测试超时导致CI失败