# AGENTS.md - tests/benchmark

## 目录说明

本目录用于**单算法性能优化**的基准测试，使用**硬编码基线数据**进行快速反馈。

## 与 benchmarks/ 目录的区别

| 特性 | benchmarks/ | tests/benchmark/ |
|------|-------------|------------------|
| **目的** | 库级别对比测试 | 单算法性能优化 |
| **基线** | 实测对比（调用第三方库API） | 硬编码基线值 |
| **依赖** | OpenSSL, SEAL, GmSSL 静态库 | 仅 kctsb 静态库 |
| **构建** | 完全独立编译 | 独立编译 |
| **使用场景** | 发布前验证 | 开发过程中的优化迭代 |

## 架构设计 (v5.1.0)

### 独立编译

本目录拥有独立的 CMakeLists.txt：
- 不被主编译包含
- 需要先编译主项目生成 `libkctsb.a`
- 使用 GoogleTest 框架

### 文件结构

```
tests/benchmark/
├── CMakeLists.txt              # 独立 CMake 配置
├── AGENTS.md                   # 本文档
├── test_bfv_benchmark.cpp      # BFV 性能测试
├── test_bgv_benchmark.cpp      # BGV 性能测试
└── test_ckks_benchmark.cpp     # CKKS 性能测试
```

## 构建方式

```bash
# 1. 首先确保主项目已编译
cd D:\pyproject\kctsb
cmake -B build -G Ninja -DKCTSB_BUILD_STATIC=ON
cmake --build build --parallel

# 2. 进入 tests/benchmark 目录独立编译
cd tests/benchmark
cmake -B build -G Ninja
cmake --build build --parallel

# 3. 运行单个基准测试
./build/bin/test_bfv_benchmark
./build/bin/test_bgv_benchmark
./build/bin/test_ckks_benchmark
```

## 硬编码基线数据来源

基线值来自 SEAL 4.1.2 的性能测量（不使用 Intel HEXL 加速），用于公平对比：

### SEAL 4.1.2 BFV 基线 (n=8192, 128-bit security)

| 操作 | 基线时间 | 说明 |
|------|----------|------|
| KeyGen (Secret) | 0.5 ms | NTT 密集 |
| KeyGen (Public) | 2.0 ms | NTT 密集 |
| KeyGen (Relin) | 15.0 ms | 采样密集 |
| Encode | 0.15 ms | NTT 单次 |
| Encrypt | 4.0 ms | 采样 + NTT |
| Decrypt | 1.5 ms | INTT + 取模 |
| Add | 0.03 ms | 无 NTT |
| Multiply | 10.0 ms | 多次 NTT |
| Relin | 10.0 ms | 分解 + NTT |

### SEAL 4.1.2 CKKS 基线 (n=8192, 128-bit security)

| 操作 | 基线时间 | 说明 |
|------|----------|------|
| KeyGen (Secret) | 0.8 ms | NTT 密集 |
| KeyGen (Public) | 3.5 ms | NTT 密集 |
| KeyGen (Relin) | 26.0 ms | 采样密集 |
| Encode | 0.35 ms | FFT |
| Decode | 0.30 ms | IFFT |
| Encrypt | 5.0 ms | 采样 + NTT |
| Decrypt | 2.0 ms | INTT + FFT |
| Add | 0.031 ms | 无 NTT |
| Multiply | 12.0 ms | 多次 NTT |
| Relin | 10.0 ms | 分解 + NTT |
| Rescale | 0.50 ms | 取模缩放 |

## 性能目标

- **EXCELLENT**: ratio ≤ 1.02x (比 SEAL 快或相当)
- **GOOD**: ratio ≤ 1.10x (可接受)
- **OK**: ratio ≤ 1.50x (需要优化)
- **SLOW**: ratio > 1.50x (不可接受)

## 约束

1. **仅使用内部 API**: 可以包含内部头文件用于详细测试
2. **硬编码基线**: 不调用第三方库，使用预设基线值
3. **快速反馈**: 用于开发过程中的性能回归检测
4. **GoogleTest 集成**: 使用 gtest 框架的 TEST_F 宏
