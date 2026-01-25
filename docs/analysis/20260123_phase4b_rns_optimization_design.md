# Phase 4b: 纯RNS uint64_t架构优化设计

> **版本**: v4.9.1 Phase 4b  
> **日期**: 2026-01-23 (Beijing Time, UTC+8)  
> **状态**: 📋 设计中

---

## 1. 问题分析

### 1.1 Phase 4a完成后的性能现状

| 操作 (n=8192) | kctsb (ms) | SEAL 4.1 (ms) | 差距 | 根因 |
|--------------|-----------|---------------|------|------|
| Multiply | 1353 | 10 | **135x** | ZZ_pX类型转换 |
| Multiply+Relin | 9650 | 18 | **536x** | 密钥切换开销 |
| Encrypt | 3494 | 5 | 699x | ZZ到uint64转换 |

### 1.2 性能瓶颈根因分析

通过代码分析确认主要耗时在：

1. **`reduce_to_prime()`** (~40%): 
   - 当前: 每个系数执行 `ZZ % q_zz` 大整数除法
   - SEAL: 直接存储 uint64_t，无需转换

2. **`crt_reconstruct_fast()`** (~35%):
   - 当前: 每个系数执行 ZZ 大整数乘法重建
   - SEAL: 保持RNS形式到最后，极少CRT重建

3. **`zz_px_to_uint64()` / `uint64_to_zz_px()`** (~15%):
   - 当前: 每次NTT前后转换 O(n) 个系数
   - SEAL: 原生RNS多项式，零转换开销

4. **`ZZ_p::init()`** (~10%):
   - 当前: 频繁切换模数上下文
   - SEAL: 无全局模数上下文

### 1.3 SEAL架构分析

SEAL的核心设计原则：

```
┌─────────────────────────────────────────────────────────────┐
│                     SEAL RNS Polynomial                      │
├─────────────────────────────────────────────────────────────┤
│  std::vector<uint64_t*> rns_components;  // k个RNS层         │
│  bool is_ntt_form;                        // NTT状态         │
│  size_t coeff_count;                      // n = 2^k         │
│  const RNSBase* base;                     // 模数信息         │
└─────────────────────────────────────────────────────────────┘

关键优化：
1. 多项式始终保持RNS形式（每个分量独立mod q_i）
2. 乘法在NTT域进行（逐点乘法O(n)）
3. 加法/减法直接操作无需NTT转换
4. CRT重建仅在必要时进行（解密、模切换）
```

---

## 2. 优化方案设计

### 2.1 新增RNSPoly类

```cpp
namespace kctsb::fhe {

/**
 * @brief 纯uint64_t RNS多项式类
 * 
 * 设计目标：
 * - 零NTL依赖的高性能多项式运算
 * - 原生RNS表示避免类型转换
 * - AVX2向量化加速
 */
class RNSPoly {
public:
    // ======== 构造和初始化 ========
    RNSPoly(size_t n, const std::vector<uint64_t>& primes);
    RNSPoly(const RNSPoly& other);
    RNSPoly(RNSPoly&& other) noexcept;
    
    // ======== 数据访问 ========
    uint64_t* component(size_t level);              // 获取第level层RNS分量
    const uint64_t* component(size_t level) const;
    size_t degree() const { return n_; }
    size_t num_levels() const { return k_; }
    bool is_ntt() const { return is_ntt_form_; }
    
    // ======== NTT转换 ========
    void to_ntt(const std::vector<NTTTable>& tables);
    void from_ntt(const std::vector<NTTTable>& tables);
    
    // ======== 算术运算 (NTT域) ========
    RNSPoly& operator+=(const RNSPoly& other);      // 逐元素加法
    RNSPoly& operator-=(const RNSPoly& other);      // 逐元素减法
    RNSPoly& operator*=(const RNSPoly& other);      // 逐点乘法 (NTT域)
    
    // ======== 标量运算 ========
    RNSPoly& operator*=(uint64_t scalar);
    
    // ======== 与ZZ_pX互转 (仅在必要时) ========
    static RNSPoly from_zz_px(const NTL::ZZ_pX& poly, size_t n,
                               const std::vector<uint64_t>& primes);
    NTL::ZZ_pX to_zz_px(const NTL::ZZ& Q) const;

private:
    size_t n_;                                       // 多项式度数
    size_t k_;                                       // RNS层数
    std::vector<uint64_t> primes_;                   // RNS模数
    std::vector<std::vector<uint64_t>> data_;        // [k][n] RNS数据
    bool is_ntt_form_;                               // 是否在NTT域
};

} // namespace kctsb::fhe
```

### 2.2 高效NTT实现 (Harvey算法)

参考SEAL的`ntt_negacyclic_harvey_lazy`：

```cpp
/**
 * @brief Harvey NTT (lazy reduction)
 * 
 * 特点：
 * - 结果在[0, 2q)范围，减少归约次数
 * - 使用预计算的twiddle quotient加速
 */
class NTTTable {
public:
    struct TwiddleFactor {
        uint64_t operand;   // w^i mod q
        uint64_t quotient;  // floor((w^i << 64) / q)
    };
    
    NTTTable(size_t n, uint64_t prime);
    
    // Harvey NTT (lazy reduction)
    void forward_lazy(uint64_t* data) const;
    void inverse_lazy(uint64_t* data) const;
    
    // 完全归约版本
    void forward(uint64_t* data) const;
    void inverse(uint64_t* data) const;
    
private:
    size_t n_;
    size_t log_n_;
    uint64_t q_;
    uint64_t two_q_;                          // 2 * q for lazy reduction
    std::vector<TwiddleFactor> root_powers_;  // 预计算twiddle因子
    std::vector<TwiddleFactor> inv_root_powers_;
    TwiddleFactor inv_n_;                     // n^{-1} mod q
};
```

### 2.3 AVX2向量化NTT

```cpp
#ifdef __AVX2__
/**
 * @brief AVX2加速的蝶形运算
 * 
 * 一次处理4个uint64_t系数
 */
inline void butterfly_avx2(
    uint64_t* x, uint64_t* y,
    const TwiddleFactor& w,
    uint64_t q, uint64_t two_q)
{
    // 加载4个系数
    __m256i vx = _mm256_loadu_si256((__m256i*)x);
    __m256i vy = _mm256_loadu_si256((__m256i*)y);
    __m256i vq = _mm256_set1_epi64x(q);
    __m256i v2q = _mm256_set1_epi64x(two_q);
    
    // t = y * w.operand (低64位)
    __m256i vw = _mm256_set1_epi64x(w.operand);
    __m256i vwq = _mm256_set1_epi64x(w.quotient);
    
    // 使用_mm256_mul_epu32获取低32位乘积，需要多次操作处理64位乘法
    // 实际实现使用内联汇编或分段乘法
    
    // x' = x + t
    // y' = x - t + 2q (保证非负)
    // 如果x' >= 2q，则x' -= 2q
    
    // ... (完整AVX2实现)
    
    _mm256_storeu_si256((__m256i*)x, vx_new);
    _mm256_storeu_si256((__m256i*)y, vy_new);
}
#endif
```

### 2.4 BGV Evaluator重构

```cpp
class BGVEvaluatorV2 {
public:
    // 使用RNSPoly替代ZZ_pX
    using RNSCiphertext = std::vector<RNSPoly>;
    
    // 密钥生成 (预转换为NTT域)
    BGVSecretKey generate_secret_key();
    BGVPublicKey generate_public_key(const BGVSecretKey& sk);
    BGVRelinKey generate_relin_key(const BGVSecretKey& sk);
    
    // 加密 (输出NTT域密文)
    RNSCiphertext encrypt(const BGVPlaintext& pt, const BGVPublicKey& pk);
    
    // 解密 (需要CRT重建)
    BGVPlaintext decrypt(const RNSCiphertext& ct, const BGVSecretKey& sk);
    
    // 同态运算 (NTT域操作)
    RNSCiphertext add(const RNSCiphertext& ct1, const RNSCiphertext& ct2);
    RNSCiphertext multiply(const RNSCiphertext& ct1, const RNSCiphertext& ct2);
    void relinearize(RNSCiphertext& ct, const BGVRelinKey& rk);
    
private:
    BGVContext context_;
    std::vector<NTTTable> ntt_tables_;  // 每个RNS模数一个表
};
```

---

## 3. 实现计划

### 3.1 文件结构

```
src/advanced/fe/
├── common/
│   ├── ntt.cpp              # 现有NTT (保留兼容)
│   ├── ntt_harvey.cpp       # 新增: Harvey NTT实现
│   ├── ntt_avx2.cpp         # 新增: AVX2加速NTT
│   ├── rns_poly.cpp         # 新增: RNSPoly类实现
│   └── modular_ops.cpp      # 新增: 高效模运算
├── bgv/
│   ├── bgv_evaluator.cpp    # 现有 (保留)
│   ├── bgv_evaluator_v2.cpp # 新增: RNSPoly版本
│   └── bgv_keygen.cpp       # 密钥生成优化
└── ...

include/kctsb/advanced/fe/
├── common/
│   ├── ntt_harvey.hpp       # Harvey NTT头文件
│   ├── rns_poly.hpp         # RNSPoly头文件
│   └── modular_ops.hpp      # 模运算头文件
└── ...
```

### 3.2 阶段划分

| 阶段 | 内容 | 预估工作量 | 依赖 |
|------|------|------------|------|
| P4b.1 | 模运算优化 (MultiplyUIntModOperand) | 2小时 | 无 |
| P4b.2 | Harvey NTT实现 | 3小时 | P4b.1 |
| P4b.3 | NTTTable预计算优化 | 2小时 | P4b.2 |
| P4b.4 | RNSPoly类实现 | 4小时 | P4b.3 |
| P4b.5 | AVX2 NTT加速 | 4小时 | P4b.2 |
| P4b.6 | BGVEvaluatorV2实现 | 6小时 | P4b.4 |
| P4b.7 | BFV/CKKS适配 | 4小时 | P4b.6 |
| P4b.8 | 测试和调试 | 4小时 | P4b.7 |
| P4b.9 | 性能调优 | 2小时 | P4b.8 |

**总计**: ~30小时

### 3.3 验收标准

| 操作 (n=8192) | Phase 4a (ms) | Phase 4b目标 (ms) | SEAL (ms) | 目标比值 |
|--------------|---------------|-------------------|-----------|----------|
| Add | 0.65 | < 0.2 | 0.1 | < 2x |
| Multiply | 1353 | < 100 | 10 | < 10x |
| Multiply+Relin | 9650 | < 300 | 18 | < 20x |
| Encrypt | 3494 | < 50 | 5 | < 10x |
| Decrypt | 1719 | < 20 | 2 | < 10x |

---

## 4. 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| Harvey NTT精度问题 | 中 | 高 | 参考SEAL实现，添加边界检查 |
| AVX2内存对齐问题 | 中 | 中 | 使用alignas(32)和对齐分配器 |
| ZZ_pX兼容性破坏 | 低 | 高 | 保留原有接口，新增V2接口 |
| 测试覆盖不足 | 低 | 中 | 复用现有测试向量 |

---

## 5. 参考资源

- **SEAL 4.1源码**: `deps/SEAL/native/src/seal/util/`
  - `ntt.cpp/h` - NTT实现
  - `uintarithsmallmod.h` - 高效模运算
  - `rns.cpp/h` - RNS基转换
  - `polyarithsmallmod.cpp/h` - 多项式运算

- **HElib源码**: `deps/HElib/src/`
  - `NumbTh.cpp` - 数论工具
  - `norms.cpp` - 多项式范数
  
- **论文参考**:
  - Harvey, "Faster arithmetic for number-theoretic transforms" (2014)
  - Seiler, "Faster AVX2 optimized NTT multiplication" (TCHES 2018)

---

*Phase 4b 设计文档 - 2026-01-23*
