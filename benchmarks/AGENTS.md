# AGENTS.md - benchmarks

## 目录说明

本目录用于 kctsb 与第三方密码学库的**库级别性能对比**基准测试。

## 架构设计 (v5.1.0)

### 独立编译

本目录完全独立于主编译系统：
- 拥有独立的 CMakeLists.txt
- 仅依赖主编译产物的静态库 (`../build/lib/libkctsb.a`)
- 仅使用公共 API 头文件 (`kctsb_api.h`)
- 不依赖内部实现细节

### 文件结构

```
benchmarks/
├── CMakeLists.txt          # 独立 CMake 构建配置
├── AGENTS.md               # 本文档
├── benchmark_common.hpp    # 通用工具函数
├── benchmark_main.cpp      # 主程序入口
├── benchmark_openssl.cpp   # vs OpenSSL 3.6.0
├── benchmark_seal.cpp      # vs SEAL 4.1.2
├── benchmark_gmssl.cpp     # vs GmSSL
└── benchmark_cuda.cpp      # CPU vs CUDA GPU
```

### 对比目标

| 目标 | 库 | 对比算法 |
|------|-----|----------|
| openssl | OpenSSL 3.6.0 | AES-GCM, ChaCha20-Poly1305, SHA3, RSA, ECC |
| seal | SEAL 4.1.2 | BFV, BGV, CKKS 同态加密 |
| gmssl | GmSSL | SM2, SM3, SM4 国密算法 |
| cuda | CUDA GPU | NTT, INTT, PolyMul |

## 构建方式

```bash
# 1. 首先确保主项目已编译
cd D:\pyproject\kctsb
cmake -B build -G Ninja -DKCTSB_BUILD_STATIC=ON
cmake --build build --parallel

# 2. 进入 benchmarks 目录独立编译
cd benchmarks
cmake -B build -G Ninja
cmake --build build --parallel

# 3. 运行基准测试
./build/bin/benchmark_suite all      # 运行所有对比
./build/bin/benchmark_suite openssl  # 仅 OpenSSL 对比
./build/bin/benchmark_suite seal     # 仅 SEAL 对比
./build/bin/benchmark_suite gmssl    # 仅 GmSSL 对比
./build/bin/benchmark_suite cuda     # 仅 CUDA 对比
```

## 依赖要求

### 静态库位置

- **kctsb**: `../build/lib/libkctsb.a` 或 `../release/{platform}/lib/libkctsb.a`
- **OpenSSL**: `../thirdparty/{platform}/lib/libcrypto.a`, `libssl.a`
- **SEAL**: `../thirdparty/{platform}/lib/libseal-4.1.a`
- **GmSSL**: `../thirdparty/{platform}/lib/libgmssl.a`
- **CUDA**: `../build-cuda/kctsb_cuda.lib`

### 头文件位置

- **kctsb**: `../include/kctsb/kctsb_api.h`
- **OpenSSL**: `../deps/openssl-3.6.0/include/`
- **SEAL**: `../deps/SEAL/native/src/`
- **GmSSL**: `../deps/gmssl/include/`

## 约束

1. **仅库级别对比**: 不依赖内部头文件，仅使用公共 API
2. **实测数据**: 不硬编码性能基线，完全运行时测量
3. **RSA 安全策略**: 仅允许 3072/4096 位，仅 OAEP/PSS + SHA-256
4. **禁止 Raw RSA 和 PKCS1-v1.5**
5. **统一测试方法**: 预热 10 次，正式测试 100 次，取平均值

## 测试数据规格

| 数据大小 | 用途 |
|----------|------|
| 1 KB | 短数据性能 |
| 1 MB | 中等数据性能 |
| 10 MB | 大数据吞吐量 |

## 输出格式

```
=== OpenSSL 3.6.0 Comparison ===

--- AES-256-GCM ---
Algorithm                     Impl        Time (ms)    Throughput
----------------------------------------------------------------------
AES-256-GCM Encrypt 1MB      kctsb           0.154    6503.81 MB/s
AES-256-GCM Encrypt 1MB      OpenSSL         0.160    6250.00 MB/s
  Ratio: 0.96x (GOOD)
```

## 性能基线来源

本目录的测试结果可作为 `tests/benchmark/` 目录中单算法优化时的性能基线数据参考。
