# kctsb vs OpenSSL 性能基线分析报告

**Version**: 3.3.0  
**Date**: 2026-01-14 (Beijing Time, UTC+8)  
**Platform**: macOS 13.7.8 (Darwin x86_64)  
**CPU**: Intel Core i7-7567U @ 3.50GHz  
**Compiler**: AppleClang 15.0.0.15000100  
**OpenSSL Version**: 3.6.0 (1 Oct 2025)  

---

## 📋 Executive Summary

本报告基于 kctsb v3.3.0 与 OpenSSL 3.6.0 的完整性能对比测试。关键发现：

### 🏆 亮点表现
| 算法 | kctsb | OpenSSL | 性能比率 | 评价 |
|------|-------|---------|----------|------|
| **BLAKE2b-256** | 567 MB/s | 575 MB/s | **98.7%** | ✅ 达到生产级 |
| **SHA3-256 (Keccak)** | 310 MB/s | 292 MB/s | **106%** | ✅ **超越OpenSSL** |
| **ChaCha20-Poly1305** | 302 MB/s | 1,558 MB/s | **19.4%** | ⚠️ 需优化 |

### ⚠️ 需重点优化
| 算法 | kctsb | OpenSSL | 性能比率 | 瓶颈 |
|------|-------|---------|----------|------|
| **AES-256-GCM** | 9.2 MB/s | 2,930 MB/s | **0.3%** | 🔴 **严重** - 需AES-NI |
| **SHA-256** | 166 MB/s | 349 MB/s | **47.6%** | 🟡 需SHA-NI |
| **ChaCha20** | 302 MB/s | 1,558 MB/s | **19.4%** | 🟡 需SIMD优化 |

---

## 🔬 详细测试结果

### 1. 对称加密 - AES-256-GCM

#### 测试数据

| 数据大小 | 实现 | 加密 (MB/s) | 解密 (MB/s) |
|----------|------|-------------|-------------|
| **1 KB** | OpenSSL | 626.81 | 565.59 |
| | kctsb | 6.99 | 7.41 |
| **1 MB** | OpenSSL | 3,018.50 | 2,769.28 |
| | kctsb | 8.58 | 9.59 |
| **10 MB** | OpenSSL | 2,929.84 | 2,746.64 |
| | kctsb | 9.23 | 8.93 |

#### 性能差距分析

```
OpenSSL 10MB 加密: 2,930 MB/s
kctsb   10MB 加密:     9 MB/s
差距: ~320x (0.3%)
```

**根因分析**:
1. **OpenSSL 使用 AES-NI 硬件加速** - Intel/AMD CPU 提供硬件AES指令，单核可达 3+ GB/s
2. **kctsb 当前为纯软件实现** - T-table 查表法虽经典但远不及硬件
3. **GCM 模式的 GHASH 计算** - OpenSSL 使用 PCLMULQDQ 指令加速多项式乘法

**优化建议**:

| 优先级 | 优化项 | 预期提升 | 难度 |
|--------|--------|----------|------|
| 🔴 P0 | AES-NI 内联汇编 | 50-100x | 高 |
| 🔴 P0 | PCLMULQDQ GHASH | 10-20x | 高 |
| 🟡 P1 | T-table 并行化 | 2-3x | 中 |

**参考实现**:
```c
// AES-NI single block encryption
__m128i aes_encrypt_block(__m128i block, __m128i *round_keys, int rounds) {
    block = _mm_xor_si128(block, round_keys[0]);
    for (int i = 1; i < rounds; i++) {
        block = _mm_aesenc_si128(block, round_keys[i]);
    }
    return _mm_aesenclast_si128(block, round_keys[rounds]);
}
```

---

### 2. 流密码 - ChaCha20-Poly1305

#### 测试数据

| 数据大小 | 实现 | 加密 (MB/s) | 解密 (MB/s) |
|----------|------|-------------|-------------|
| **1 KB** | OpenSSL | 432.96 | 547.66 |
| | kctsb | 149.31 | 0.67 |
| **1 MB** | OpenSSL | 1,200.86 | 1,486.77 |
| | kctsb | 266.85 | 296.19 |
| **10 MB** | OpenSSL | 1,558.42 | 1,364.18 |
| | kctsb | 302.86 | 301.11 |

#### 性能差距分析

```
10MB 数据:
OpenSSL 加密: 1,558 MB/s
kctsb   加密:   303 MB/s
性能比率: 19.4%

⚠️ 1KB 解密异常慢 (0.67 MB/s) - 存在初始化开销
```

**根因分析**:
1. **OpenSSL 使用 AVX2/AVX-512 向量化** - 一次处理 4-8 个 ChaCha20 块
2. **kctsb 为标量实现** - 每次处理单个 64 字节块
3. **Poly1305 MAC 计算** - OpenSSL 使用多项式乘法硬件加速
4. **1KB 解密异常** - 可能存在不必要的密钥重新生成

**优化建议**:

| 优先级 | 优化项 | 预期提升 | 难度 |
|--------|--------|----------|------|
| 🔴 P0 | AVX2 4路并行 ChaCha20 | 3-4x | 中 |
| 🟡 P1 | Poly1305 AVX2 实现 | 2x | 中 |
| 🟡 P1 | 修复 1KB 解密开销 | 10x+ | 低 |

**AVX2 参考架构**:
```c
// 4-way parallel ChaCha20 quarter round
void chacha20_avx2_block(__m256i *state) {
    // Process 4 blocks simultaneously using 256-bit registers
    // Each __m256i holds 4 x 32-bit integers from 4 different blocks
}
```

---

### 3. 哈希函数

#### 测试数据 (10 MB)

| 算法 | OpenSSL (MB/s) | kctsb (MB/s) | 比率 | 评价 |
|------|----------------|--------------|------|------|
| **SHA-256** | 348.52 | 165.96 | 47.6% | 🟡 需SHA-NI |
| **SHA3-256** | 291.96 | **309.51** | **106%** | ✅ **超越** |
| **BLAKE2b-256** | 575.03 | **567.56** | 98.7% | ✅ 达标 |

#### 亮点: SHA3-256 超越 OpenSSL

```
SHA3-256 (10MB):
OpenSSL: 292 MB/s
kctsb:   310 MB/s (+6%)
```

**原因分析**:
- kctsb 的 Keccak 实现针对 64-bit 架构优化
- 状态数组对齐和循环展开有效
- OpenSSL 的 Keccak 实现相对保守

#### BLAKE2b-256 接近 OpenSSL

```
BLAKE2b-256 (10MB):
OpenSSL: 575 MB/s
kctsb:   568 MB/s (98.7%)
```

**原因分析**:
- BLAKE2b 本身为软件友好设计
- kctsb 实现已充分优化
- 进一步提升需 AVX2 向量化

#### SHA-256 性能差距

```
SHA-256 (10MB):
OpenSSL: 349 MB/s
kctsb:   166 MB/s (47.6%)
```

**根因分析**:
1. OpenSSL 在支持的 CPU 上使用 **SHA-NI 硬件指令**
2. kctsb 当前为纯 C 实现
3. SHA-NI 可提供 ~3x 加速

**优化建议**:

| 优先级 | 优化项 | 预期提升 | 难度 |
|--------|--------|----------|------|
| 🟡 P1 | SHA-NI 内联汇编 | 2-3x | 中 |
| 🟢 P2 | 循环展开优化 | 10-20% | 低 |

---

### 4. 椭圆曲线密码 (ECC)

#### OpenSSL 基线数据

| 曲线 | 操作 | 吞吐量 (op/s) |
|------|------|---------------|
| **secp256k1** | Key Gen | 1,285 |
| | Sign | 1,092 |
| | Verify | 1,507 |
| | ECDH | 1,675 |
| **P-256 (secp256r1)** | Key Gen | 20,697 |
| | Sign | 16,641 |
| | Verify | 7,702 |
| | ECDH | 8,557 |
| **P-384 (secp384r1)** | Key Gen | 2,422 |
| | Sign | 2,283 |
| | Verify | 1,247 |
| | ECDH | 1,871 |

**关键发现**:
- P-256 比 secp256k1 快 **10-16x** (OpenSSL 对 NIST 曲线有专门优化)
- kctsb 使用 NTL 后端，预期达到 OpenSSL 70-80%

**优化建议**:
- 实现 P-256 专用场算术 (Montgomery 乘法)
- 使用 wNAF 标量乘法
- 预计算基点表

---

### 5. RSA 密码

#### OpenSSL 基线数据

| 密钥长度 | 操作 | 吞吐量 (op/s) |
|----------|------|---------------|
| **RSA-2048** | Key Gen | 24.72 |
| | OAEP Encrypt | 31,406 |
| | OAEP Decrypt | 985 |
| | PSS Sign | 991 |
| | PSS Verify | 23,060 |
| **RSA-4096** | Key Gen | 1.48 |
| | OAEP Encrypt | 10,877 |
| | OAEP Decrypt | 201 |
| | PSS Sign | 206 |
| | PSS Verify | 10,642 |

**关键发现**:
- 公钥操作 (加密/验签) 比私钥操作快 30-50x
- kctsb 使用 NTL + CRT 优化，预期达到 OpenSSL 75-85%

---

## 📊 综合性能评估

### 当前状态 vs v3.2.0

| 算法 | v3.2.0 状态 | v3.3.0 实测 | 变化 |
|------|-------------|-------------|------|
| AES-GCM | 基准待测 | **0.3%** | 🔴 已量化差距 |
| ChaCha20 | 基准待测 | **19.4%** | 🟡 已量化差距 |
| SHA-256 | ~357 MB/s (OpenSSL) | **47.6%** | 🟡 已量化 |
| SHA3-256 | 基准待测 | **106%** | ✅ **超越** |
| BLAKE2b | 基准待测 | **98.7%** | ✅ 达标 |

### 性能等级评定

| 等级 | 标准 | 算法 |
|------|------|------|
| ⭐⭐⭐ 生产级 | ≥95% OpenSSL | SHA3-256, BLAKE2b |
| ⭐⭐ 可用级 | 50-95% OpenSSL | SHA-256 |
| ⭐ 开发级 | 10-50% OpenSSL | ChaCha20-Poly1305 |
| ❌ 需重构 | <10% OpenSSL | **AES-GCM** |

---

## 🎯 优化路线图

### Phase 1: 紧急修复 (2周)

**目标**: AES-GCM 达到 50% OpenSSL 性能

| 任务 | 预期提升 | 工作量 |
|------|----------|--------|
| AES-NI 硬件加速 (CTR 模式) | 50x | 3天 |
| PCLMULQDQ GHASH | 10x | 3天 |
| 运行时 CPUID 检测 | - | 1天 |

### Phase 2: SIMD 优化 (1月)

**目标**: ChaCha20 达到 60%, SHA-256 达到 80%

| 任务 | 预期提升 | 工作量 |
|------|----------|--------|
| ChaCha20 AVX2 4路并行 | 3-4x | 5天 |
| Poly1305 AVX2 | 2x | 3天 |
| SHA-256 SHA-NI | 2-3x | 3天 |
| 修复 ChaCha20 1KB 解密开销 | 10x | 1天 |

### Phase 3: 高级优化 (Q1 2026)

**目标**: 全部算法达到 90%+ OpenSSL

| 任务 | 目标性能 |
|------|----------|
| AES-GCM AVX-512 | ≥90% |
| ARM NEON 支持 | Apple Silicon 原生 |
| P-256 专用场算术 | ≥80% OpenSSL |

---

## 📝 测试方法说明

### 测试配置
- **预热**: 10 次迭代 (丢弃结果)
- **测量**: 100 次迭代
- **数据大小**: 1KB, 1MB, 10MB
- **随机数据**: OpenSSL `RAND_bytes()` 生成

### 计时精度
- 使用 `std::chrono::high_resolution_clock`
- 纳秒级精度
- 最小化冷缓存影响

### 吞吐量计算
```
Throughput (MB/s) = (DataSize / 1024 / 1024) / (AvgTime / 1000)
```

---

## 🔗 参考资料

1. [Intel AES-NI White Paper](https://www.intel.com/content/www/us/en/developer/articles/tool/intel-advanced-encryption-standard-instructions-aes-ni.html)
2. [Intel SHA Extensions](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html)
3. [RFC 7539 - ChaCha20 and Poly1305](https://tools.ietf.org/html/rfc7539)
4. [BLAKE2 Specification](https://www.blake2.net/blake2.pdf)
5. [OpenSSL Performance Tuning](https://wiki.openssl.org/index.php/Performance)

---

**Report Prepared By**: kctsb Security Research Team  
**License**: Apache License 2.0  

*Last Updated: 2026-01-14 UTC+8*
