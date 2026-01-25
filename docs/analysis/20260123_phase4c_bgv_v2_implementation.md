# Phase 4c: BGV EvaluatorV2 纯RNS实现设计

> **版本**: v4.10.0 Phase 4c  
> **日期**: 2026-01-23 (Beijing Time, UTC+8)  
> **状态**: 🚧 实施中

---

## 1. 项目背景与目标

### 1.1 Phase 4b 完成状态

v4.9.1 已完成 Harvey NTT 和 RNSPoly 基础设施：
- ✅ Harvey NTT 算法（lazy reduction）
- ✅ RNSPoly 类（独立 RNS 多项式）
- ✅ 正确的 Gentleman-Sande 逆 NTT
- ✅ ntt_poly_ops 迁移到 Harvey NTT
- ⏸️ AVX2 Forward NTT（临时禁用）

### 1.2 当前性能瓶颈

| 操作 (n=8192) | 当前耗时 | SEAL 4.1 | 性能差距 | 根因 |
|--------------|---------|----------|---------|------|
| Multiply | 1335 ms | ~10 ms | **133x** | ZZ_pX ↔ uint64_t 转换 |
| Multiply+Relin | 9650 ms | ~18 ms | **536x** | 密钥切换 + CRT 重建 |
| Encrypt | 3494 ms | ~5 ms | **699x** | reduce_to_prime() 开销 |

**关键性能杀手**:
```cpp
// bgv_evaluator.cpp 当前实现
BGVCiphertext multiply(...) {
    // 1. ZZ_pX → uint64_t 转换 (~35% 耗时)
    for (size_t i = 0; i < size; i++) {
        uint64_poly_i = zz_px_to_uint64(ct[i].poly(), primes);
    }
    
    // 2. NTT 多项式乘法 (~25% 耗时)
    multiply_poly_ntt(...);
    
    // 3. uint64_t → ZZ_pX 转换 + CRT (~40% 耗时)
    result_zz_px = crt_reconstruct_fast(...);
}
```

### 1.3 Phase 4c 目标

| 目标项 | 指标 | 验收标准 |
|--------|------|---------|
| **AVX2 NTT 修复** | 100% 测试通过 | DISABLED 测试启用 |
| **BGV Multiply** | < 20 ms | 接近 SEAL 10 ms |
| **Encrypt** | < 50 ms | 10x 加速 |
| **Decrypt** | < 20 ms | 10x 加速 |
| **整体加速比** | > 50x | vs Phase 4a |
| **测试覆盖** | 100% pass | 无回归 |

---

## 2. AVX2 NTT Bug 分析与修复

### 2.1 问题根因

当前 `ntt_negacyclic_harvey_avx2()` 产生错误结果（已禁用测试）。根因分析：

**问题代码** (ntt_harvey.cpp:367-430)：
```cpp
for (size_t i = 0; i < m; ++i) {
    const MultiplyUIntModOperand& w = root_powers[root_index];
    root_index++;
    
    size_t j1 = 2 * i * t;
    size_t j2 = j1 + t;
    
    // BUG: AVX2 向量化时未正确处理 butterfly 索引
    for (; j + 4 <= j2; j += 4) {
        __m256i vx = _mm256_loadu_si256((__m256i*)(operand + j));
        __m256i vy = _mm256_loadu_si256((__m256i*)(operand + j + t));  // 错误！
        // ...
    }
}
```

**根本问题**:
- 标量版本: `operand[j]` 和 `operand[j + t]` 配对
- AVX2 版本: 加载 4 个连续系数，但 `j + t` 的计算错误
- **解决方案**: 使用 `j1 + j` 和 `j2 + j` 索引，而不是 `j + t`

### 2.2 修复方案

```cpp
// 修复后的 AVX2 NTT
for (size_t i = 0; i < m; ++i) {
    const MultiplyUIntModOperand& w = root_powers[root_index++];
    
    __m256i vw = _mm256_set1_epi64x(w.operand);
    __m256i vwq = _mm256_set1_epi64x(w.quotient);
    
    size_t j1 = 2 * i * t;
    size_t j2 = j1 + t;
    
    // 修复索引计算
    size_t j = 0;
    for (; j + 4 <= t; j += 4) {  // 遍历蝶形对内部
        __m256i vx = _mm256_loadu_si256((__m256i*)(operand + j1 + j));
        __m256i vy = _mm256_loadu_si256((__m256i*)(operand + j2 + j));
        
        // ... butterfly 操作 ...
        
        _mm256_storeu_si256((__m256i*)(operand + j1 + j), vx_new);
        _mm256_storeu_si256((__m256i*)(operand + j2 + j), vy_new);
    }
    
    // 处理剩余标量
    for (; j < t; ++j) {
        // ...
    }
}
```

### 2.3 验证计划

- 启用 `test_ntt_harvey.cpp` 中的 `DISABLED_NTTForwardAVX2` 测试
- 与标量版本对比结果一致性
- 性能基准测试确认加速

---

## 3. BGV EvaluatorV2 架构设计

### 3.1 核心设计原则

**SEAL-Compatible RNS Flow**:
```
加密流程:
ZZ plaintext → RNSPoly (coefficient) → NTT → RNSPoly (NTT domain)
                 ↑                                    ↓
          coefficient domain                    密钥也在 NTT domain
                                                      ↓
                                              密文在 NTT domain 存储

同态运算:
RNSPoly (NTT) + RNSPoly (NTT) → 直接逐点加法 (O(n))
RNSPoly (NTT) * RNSPoly (NTT) → 直接逐点乘法 (O(n))

解密流程:
RNSPoly (NTT) → INTT → RNSPoly (coefficient) → CRT → ZZ plaintext
```

**关键优化点**:
1. **密钥预转换**: 密钥生成时直接转为 NTT domain
2. **密文 NTT 存储**: 加密输出已在 NTT domain
3. **零 ZZ_pX 依赖**: 全程使用 RNSPoly，仅解密时 CRT
4. **延迟 CRT**: 仅在绝对必要时（解密、模切换）才重建

### 3.2 类层次结构

```cpp
namespace kctsb::fhe::bgv {

// ============================================================================
// V2 Key Types (RNSPoly-based)
// ============================================================================

struct BGVSecretKeyV2 {
    RNSPoly s;              // 密钥多项式 (NTT domain)
    bool is_ntt_form;       // 始终为 true
};

struct BGVPublicKeyV2 {
    RNSPoly pk0;            // pk = (pk0, pk1) = (-(a*s + e), a)
    RNSPoly pk1;            // 均在 NTT domain
};

struct BGVRelinKeyV2 {
    // KSK: (ksk0_i, ksk1_i) = (-(a_i * s + e_i) + P * s^2 * b_i, a_i)
    std::vector<RNSPoly> ksk0;  // L 个密钥切换密钥
    std::vector<RNSPoly> ksk1;
    uint64_t decomp_base;       // 分解基 P
};

struct BGVCiphertextV2 {
    std::vector<RNSPoly> data;  // (c0, c1) 或 (c0, c1, c2) after multiply
    bool is_ntt_form;           // 始终为 true
    int level;                  // 当前模数级别
    int noise_budget;           // 噪声预算
    
    size_t size() const { return data.size(); }
    RNSPoly& operator[](size_t i) { return data[i]; }
    const RNSPoly& operator[](size_t i) const { return data[i]; }
};

// ============================================================================
// BGV Evaluator V2 (Pure RNS Implementation)
// ============================================================================

class BGVEvaluatorV2 {
public:
    explicit BGVEvaluatorV2(const RNSContext* ctx);
    
    // ========== Key Generation ==========
    BGVSecretKeyV2 generate_secret_key(std::mt19937_64& rng);
    BGVPublicKeyV2 generate_public_key(const BGVSecretKeyV2& sk, 
                                        std::mt19937_64& rng);
    BGVRelinKeyV2 generate_relin_key(const BGVSecretKeyV2& sk,
                                      std::mt19937_64& rng);
    
    // ========== Encryption/Decryption ==========
    BGVCiphertextV2 encrypt(const std::vector<uint64_t>& plaintext,
                             const BGVPublicKeyV2& pk,
                             std::mt19937_64& rng);
    
    std::vector<uint64_t> decrypt(const BGVCiphertextV2& ct,
                                   const BGVSecretKeyV2& sk);
    
    // ========== Homomorphic Operations (All in NTT Domain) ==========
    void add_inplace(BGVCiphertextV2& ct1, const BGVCiphertextV2& ct2);
    void sub_inplace(BGVCiphertextV2& ct1, const BGVCiphertextV2& ct2);
    void multiply_inplace(BGVCiphertextV2& ct1, const BGVCiphertextV2& ct2);
    void relinearize_inplace(BGVCiphertextV2& ct, const BGVRelinKeyV2& rk);
    
    BGVCiphertextV2 add(const BGVCiphertextV2& ct1, 
                         const BGVCiphertextV2& ct2);
    BGVCiphertextV2 multiply(const BGVCiphertextV2& ct1,
                              const BGVCiphertextV2& ct2);
    BGVCiphertextV2 relinearize(const BGVCiphertextV2& ct,
                                 const BGVRelinKeyV2& rk);
    
private:
    const RNSContext* context_;
    
    // Helper: RNS decomposition for key switching
    std::vector<RNSPoly> decompose_rns(const RNSPoly& poly, 
                                        uint64_t base);
};

} // namespace kctsb::fhe::bgv
```

### 3.3 关键算法实现

#### 3.3.1 密钥生成

```cpp
BGVSecretKeyV2 BGVEvaluatorV2::generate_secret_key(std::mt19937_64& rng) {
    // 1. 从 {-1, 0, 1} 分布采样
    std::uniform_int_distribution<int> dist(-1, 1);
    std::vector<uint64_t> coeffs(context_->n());
    
    for (size_t i = 0; i < context_->n(); ++i) {
        int val = dist(rng);
        coeffs[i] = (val < 0) ? (-val) : val;  // 先存正值，稍后处理符号
    }
    
    // 2. 转为 RNSPoly
    RNSPoly s(context_, coeffs);
    
    // 3. 转到 NTT domain
    s.ntt_transform(context_->all_ntt_tables());
    
    return BGVSecretKeyV2{std::move(s), true};
}

BGVPublicKeyV2 BGVEvaluatorV2::generate_public_key(
    const BGVSecretKeyV2& sk,
    std::mt19937_64& rng)
{
    // pk = (-(a*s + e), a)
    // 1. 采样随机 a (uniform mod q)
    RNSPoly a(context_);
    sample_uniform_rns(&a, rng);
    a.ntt_transform(context_->all_ntt_tables());  // a in NTT
    
    // 2. 采样小噪声 e (Gaussian)
    RNSPoly e(context_);
    sample_gaussian_rns(&e, rng, 3.2);  // σ = 3.2
    e.ntt_transform(context_->all_ntt_tables());  // e in NTT
    
    // 3. 计算 pk0 = -(a*s + e) (NTT domain 逐点乘法)
    RNSPoly as = poly_multiply(a, sk.s);  // 已在 NTT domain
    RNSPoly pk0 = poly_add(as, e);
    poly_negate_inplace(pk0);
    
    return BGVPublicKeyV2{std::move(pk0), std::move(a)};
}
```

#### 3.3.2 加密

```cpp
BGVCiphertextV2 BGVEvaluatorV2::encrypt(
    const std::vector<uint64_t>& plaintext,
    const BGVPublicKeyV2& pk,
    std::mt19937_64& rng)
{
    // ct = pk * u + (m, e1)
    // 其中 u, e0, e1 为小噪声
    
    // 1. 明文转 RNSPoly
    RNSPoly m(context_, plaintext);
    m.ntt_transform(context_->all_ntt_tables());  // m in NTT
    
    // 2. 采样 u ∈ {-1, 0, 1}
    RNSPoly u(context_);
    sample_ternary_rns(&u, rng);
    u.ntt_transform(context_->all_ntt_tables());
    
    // 3. 采样噪声 e0, e1 ~ Gaussian(σ)
    RNSPoly e0(context_), e1(context_);
    sample_gaussian_rns(&e0, rng, 3.2);
    sample_gaussian_rns(&e1, rng, 3.2);
    e0.ntt_transform(context_->all_ntt_tables());
    e1.ntt_transform(context_->all_ntt_tables());
    
    // 4. 计算密文 (NTT domain 操作)
    // c0 = pk0 * u + e0 + m
    RNSPoly c0 = poly_multiply(pk.pk0, u);  // pk0 * u
    poly_add_inplace(c0, e0);               // + e0
    poly_add_inplace(c0, m);                // + m
    
    // c1 = pk1 * u + e1
    RNSPoly c1 = poly_multiply(pk.pk1, u);
    poly_add_inplace(c1, e1);
    
    BGVCiphertextV2 ct;
    ct.data = {std::move(c0), std::move(c1)};
    ct.is_ntt_form = true;
    ct.level = 0;
    ct.noise_budget = initial_noise_budget();
    
    return ct;
}
```

#### 3.3.3 解密（含 CRT 重建）

```cpp
std::vector<uint64_t> BGVEvaluatorV2::decrypt(
    const BGVCiphertextV2& ct,
    const BGVSecretKeyV2& sk)
{
    // m ≈ c0 + c1 * s (mod q)
    
    // 1. 计算 c1 * s (NTT domain)
    RNSPoly c1s = poly_multiply(ct[1], sk.s);
    
    // 2. 加到 c0
    RNSPoly m_rns = poly_add(ct[0], c1s);
    
    // 3. 转回 coefficient domain
    m_rns.intt_transform(context_->all_ntt_tables());
    
    // 4. CRT 重建得到 ZZ 系数
    std::vector<uint64_t> plaintext(context_->n());
    crt_reconstruct_rns(m_rns, plaintext);
    
    // 5. 模 plaintext modulus 归约
    uint64_t t = plaintext_modulus();
    for (auto& coeff : plaintext) {
        coeff = balance_mod(coeff, t);  // 居中余数
    }
    
    return plaintext;
}
```

#### 3.3.4 同态乘法

```cpp
void BGVEvaluatorV2::multiply_inplace(
    BGVCiphertextV2& ct1,
    const BGVCiphertextV2& ct2)
{
    // (c0, c1) * (d0, d1) = (c0*d0, c0*d1 + c1*d0, c1*d1)
    
    size_t n1 = ct1.size();
    size_t n2 = ct2.size();
    
    std::vector<RNSPoly> result(n1 + n2 - 1, RNSPoly(context_));
    
    // 张量积展开（NTT domain 逐点乘法）
    for (size_t i = 0; i < n1; ++i) {
        for (size_t j = 0; j < n2; ++j) {
            RNSPoly prod = poly_multiply(ct1[i], ct2[j]);
            poly_add_inplace(result[i + j], prod);
        }
    }
    
    ct1.data = std::move(result);
    ct1.noise_budget -= noise_budget_after_multiply();
}
```

#### 3.3.5 重线性化（RNS 分解）

```cpp
void BGVEvaluatorV2::relinearize_inplace(
    BGVCiphertextV2& ct,
    const BGVRelinKeyV2& rk)
{
    if (ct.size() <= 2) return;  // 已经是 size 2
    
    // 将 c2 重线性化为 (c0', c1')
    // c2 分解为 c2 = sum_i c2_i * P^i
    auto decomposed = decompose_rns(ct[2], rk.decomp_base);
    
    RNSPoly c0_relin(context_);
    RNSPoly c1_relin(context_);
    
    for (size_t i = 0; i < decomposed.size(); ++i) {
        // c0' += c2_i * ksk0_i
        RNSPoly term0 = poly_multiply(decomposed[i], rk.ksk0[i]);
        poly_add_inplace(c0_relin, term0);
        
        // c1' += c2_i * ksk1_i
        RNSPoly term1 = poly_multiply(decomposed[i], rk.ksk1[i]);
        poly_add_inplace(c1_relin, term1);
    }
    
    // 更新密文
    poly_add_inplace(ct[0], c0_relin);
    poly_add_inplace(ct[1], c1_relin);
    ct.data.resize(2);  // 移除 c2
}

std::vector<RNSPoly> BGVEvaluatorV2::decompose_rns(
    const RNSPoly& poly,
    uint64_t base)
{
    // RNS digit decomposition: poly mod q = sum_i d_i * base^i
    size_t L = context_->level_count();
    size_t num_digits = (L * 60 + log2(base) - 1) / log2(base);  // 估计
    
    std::vector<RNSPoly> digits;
    digits.reserve(num_digits);
    
    // 执行分解（需要转回 coefficient domain）
    RNSPoly temp = poly;
    temp.intt_transform(context_->all_ntt_tables());
    
    for (size_t d = 0; d < num_digits; ++d) {
        RNSPoly digit(context_);
        
        for (size_t level = 0; level < L; ++level) {
            for (size_t i = 0; i < context_->n(); ++i) {
                uint64_t coeff = temp.component(level)[i];
                digit.component(level)[i] = coeff % base;
                temp.component(level)[i] = coeff / base;
            }
        }
        
        digit.ntt_transform(context_->all_ntt_tables());
        digits.push_back(std::move(digit));
    }
    
    return digits;
}
```

---

## 4. RNSPoly 辅助函数扩展

### 4.1 需要新增的操作

```cpp
// rns_poly.cpp 需要新增

// Component-wise 运算
RNSPoly poly_add(const RNSPoly& a, const RNSPoly& b);
void poly_add_inplace(RNSPoly& a, const RNSPoly& b);
void poly_sub_inplace(RNSPoly& a, const RNSPoly& b);
void poly_negate_inplace(RNSPoly& poly);
void poly_multiply_scalar_inplace(RNSPoly& poly, uint64_t scalar);

// NTT domain 乘法（已有，但需确认）
RNSPoly poly_multiply(const RNSPoly& a, const RNSPoly& b);

// 采样函数
void sample_uniform_rns(RNSPoly* out, std::mt19937_64& rng);
void sample_ternary_rns(RNSPoly* out, std::mt19937_64& rng);
void sample_gaussian_rns(RNSPoly* out, std::mt19937_64& rng, double sigma);

// CRT 重建
void crt_reconstruct_rns(const RNSPoly& poly, std::vector<uint64_t>& out);
uint64_t balance_mod(uint64_t x, uint64_t modulus);
```

---

## 5. 实施计划

### 5.1 文件结构

```
src/advanced/fe/bgv/
├── bgv_evaluator.cpp           # V1 保留
├── bgv_evaluator_v2.cpp        # ★ 新增: RNSPoly 版本
└── bgv_keygen_v2.cpp           # ★ 新增: 密钥生成 V2

include/kctsb/advanced/fe/bgv/
├── bgv_evaluator.hpp           # V1 保留
├── bgv_evaluator_v2.hpp        # ★ 新增
└── bgv_types_v2.hpp            # ★ 新增: V2 类型定义

src/advanced/fe/common/
├── ntt_harvey.cpp              # ★ 修改: 修复 AVX2
└── rns_poly.cpp                # ★ 扩展: 新增辅助函数

tests/
├── test_bgv_evaluator_v2.cpp   # ★ 新增: V2 单元测试
└── test_ntt_harvey.cpp         # ★ 修改: 启用 AVX2 测试

benchmarks/
└── benchmark_bgv.cpp           # ★ 修改: 添加 V2 性能对比
```

### 5.2 实施步骤

| 步骤 | 任务 | 预计工作量 | 依赖 |
|------|------|-----------|------|
| 1 | 修复 AVX2 Forward NTT 索引 bug | 1 小时 | 无 |
| 2 | 启用并验证 AVX2 测试 | 0.5 小时 | 步骤 1 |
| 3 | 扩展 RNSPoly 辅助函数 | 2 小时 | 无 |
| 4 | 实现 BGVEvaluatorV2 类框架 | 1 小时 | 无 |
| 5 | 实现密钥生成 V2 | 2 小时 | 步骤 3,4 |
| 6 | 实现加密/解密 V2 | 3 小时 | 步骤 5 |
| 7 | 实现加法/减法 V2 | 1 小时 | 步骤 4 |
| 8 | 实现乘法 V2 | 2 小时 | 步骤 4 |
| 9 | 实现重线性化 V2 | 3 小时 | 步骤 8 |
| 10 | 编写单元测试 | 3 小时 | 步骤 6-9 |
| 11 | 性能基准测试 | 2 小时 | 步骤 10 |
| 12 | 调优和验证 | 2 小时 | 步骤 11 |

**总计**: ~22.5 小时

### 5.3 验收标准

| 测试项 | 目标 | 验收标准 |
|--------|------|---------|
| **正确性测试** | 100% pass | test_bgv_evaluator_v2.cpp 全通过 |
| **AVX2 NTT** | 启用 | DISABLED 测试移除 |
| **加密性能** | < 50 ms | n=8192, 10x 加速 |
| **乘法性能** | < 20 ms | 接近 SEAL 10 ms |
| **重线性化** | < 10 ms | 密钥切换优化 |
| **完整流程** | < 100 ms | Encrypt+Mult+Relin+Decrypt |
| **回归测试** | 0 failures | ctest 全套通过 |

---

## 6. 风险与缓解

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|---------|
| AVX2 bug 修复失败 | 低 | 中 | 仅影响加速，标量版本可用 |
| RNS 分解精度问题 | 中 | 高 | 参考 SEAL decompose_single 实现 |
| CRT 重建溢出 | 低 | 高 | 使用 arbitrary precision 临时缓冲 |
| 性能未达标 | 中 | 中 | 逐步调优，先保证正确性 |
| 测试覆盖不足 | 低 | 中 | 复用 V1 测试向量，增加边界用例 |

---

## 7. 成功标准与退出条件

### 7.1 必须完成项（P0）

- ✅ AVX2 Forward NTT 修复并通过测试
- ✅ BGVEvaluatorV2 完整实现（加密/解密/加法/乘法/重线性化）
- ✅ 单元测试 100% 通过
- ✅ Multiply 性能 < 20ms (n=8192)

### 7.2 可选优化项（P1）

- 逆 NTT AVX2 优化（如果 Forward 修复顺利）
- 模切换 V2 实现
- Galois automorphism（旋转）支持

### 7.3 下一阶段计划（Phase 4d）

- BFV/CKKS 迁移到 EvaluatorV2
- 完整 SIMD 批量编码
- 多线程加速

---

**设计文档版本**: v1.0  
**审核状态**: 待实施  
**预计完成时间**: 2026-01-24

---

*Phase 4c Design Document - Knight's Cryptographic Trusted Security Base*
