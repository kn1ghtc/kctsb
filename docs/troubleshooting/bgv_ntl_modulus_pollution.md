# BGV 同态加密 NTL 全局模数污染问题

> **日期**: 2026-01-22 (UTC+8)  
> **版本**: kctsb v3.2.1  
> **严重性**: 高 (导致非确定性测试失败)  
> **状态**: 已解决

---

## 1. 问题描述

### 症状

BGV Power 测试 (`3³ = 27`) 产生**非确定性结果**：
- 有时返回正确值 27
- 有时返回随机垃圾值（如 -69, 107, 42 等）
- 问题在多次测试运行时随机出现

### 受影响组件

- `BGVTest.Power` (主要)
- `BGVTest.ManualVerifyMultiply` (偶发)
- `BGVTest.NoiseBudgetDecreasesAfterMultiply` (测试干扰)

### 复现条件

1. 连续运行多个 BGV 测试
2. 测试 fixture 的 `SetUp()` 调用 `ZZ_p::init()` 设置不同模数
3. 测试间共享 `BGVSecretKey` 对象

---

## 2. 根本原因分析

### 2.1 NTL 全局模数设计

NTL 库的 `ZZ_p` 类使用**全局模数上下文**：

```cpp
// 设置全局模数 - 影响所有 ZZ_p/ZZ_pX 操作!
ZZ_p::init(modulus);

// 此后所有 ZZ_pX 系数都在 mod modulus 下解释
ZZ_pX poly;  // 系数自动取模
```

**问题**：当测试 fixture 更改全局模数时，之前创建的 `ZZ_pX` 对象的系数会在**新模数**下被重新解释！

### 2.2 Secret Key 缓存污染

原始 `BGVSecretKey` 实现缓存了 secret key 的幂次：

```cpp
class BGVSecretKey {
private:
    RingElement s_;                        // 原始 secret key
    mutable std::vector<RingElement> powers_;  // 缓存的 s^k
    
public:
    const RingElement& power(size_t k) const {
        // 使用缓存的 powers_[k-1]
        return powers_[k - 1];  // BUG: 在错误模数下解释!
    }
};
```

**时序问题**：
```
Test 1: ZZ_p::init(q1) → generate sk → encrypt → decrypt ✓
Test 2: ZZ_p::init(q2) → sk.power(2) 返回在 q2 下的错误解释!
```

### 2.3 Decrypt 组件数量不匹配

原始 `decrypt()` 只处理 2-component 密文：

```cpp
// 错误实现:
result = c0 + c1 * s;  // 忽略了 c2*s² 项!
```

乘法后密文有 3 个组件，需要：
```cpp
result = c0 + c1*s + c2*s²;
```

### 2.4 Relinearization Base 不一致

两个函数使用不同的 base 计算：

| 函数 | Base 值 |
|------|---------|
| `generate_relin_key()` | 硬编码 `2^60` |
| `decompose()` | 动态计算 `2^22` |

这导致 relinearization keys 与实际 digit decomposition 不兼容。

---

## 3. 解决方案

### 3.1 模数无关的密钥存储

**修改**: `include/kctsb/advanced/fe/bgv/bgv_context.hpp`

```cpp
class BGVSecretKey {
private:
    RingElement s_;                    // 保留兼容性
    std::vector<ZZ> coeffs_;           // 新增: 模数无关的系数存储
    mutable std::vector<RingElement> powers_;
    
public:
    // 新增: 返回原始整数系数
    const std::vector<ZZ>& coefficients() const { return coeffs_; }
    long degree() const;
};
```

### 3.2 密钥生成时填充 coeffs_

**修改**: `src/advanced/fe/bgv/bgv_context.cpp`

```cpp
BGVSecretKey BGVContext::generate_secret_key() {
    BGVSecretKey sk;
    // ... 现有代码 ...
    
    // 新增: 存储模数无关的系数
    sk.coeffs_.resize(params_.n);
    for (size_t i = 0; i < params_.n; i++) {
        // 从 ZZ_pX 提取系数并转换为中心表示
        ZZ coef = rep(kctsb::coeff(sk.s_.poly(), i));
        // 中心化: [0, q) → (-q/2, q/2]
        if (coef > params_.q / 2) {
            coef -= params_.q;
        }
        sk.coeffs_[i] = coef;  // {-1, 0, 1}
    }
    return sk;
}
```

### 3.3 使用 coefficients() 重建密钥

在需要使用 secret key 的函数中：

```cpp
// 在正确模数下重建 secret key
ZZ_p::init(params_.q);  // 确保正确模数
ZZ_pX sk_q;
const auto& coeffs = sk.coefficients();
sk_q.SetLength(sk.degree() + 1);
for (long i = 0; i <= sk.degree(); i++) {
    ZZ coef = coeffs[i];
    if (coef < 0) coef += params_.q;  // 负数转正
    sk_q[i] = conv<ZZ_p>(coef);
}
```

### 3.4 Horner's Method Decrypt

**修改**: 支持任意数量的密文组件

```cpp
// Horner's method: result = c[n-1], then result = result*s + c[i]
result = ct[ct.size() - 1].poly();
for (long i = static_cast<long>(ct.size()) - 2; i >= 0; i--) {
    result = MulMod(result, sk_q, cyclotomic_);
    result = result + ct[i].poly();
}
```

### 3.5 统一 Digit Decomposition Base

```cpp
// 两个函数现在使用相同的计算:
long num_digits = 3;
long base_bits = (NumBits(params_.q) + num_digits - 1) / num_digits;
ZZ base = power2_ZZ(base_bits);  // ≈ 2^22 for TOY_PARAMS
```

---

## 4. 测试验证

### 验证命令

```powershell
cd D:\pyproject\kctsb

# 10 次 Power 测试
for ($i=1; $i -le 10; $i++) { 
    .\build\bin\test_bgv.exe --gtest_filter=*Power 2>&1 | 
    Select-String "PASSED|FAILED" 
}

# 应该输出 10 个 PASSED
```

### 预期结果

```
✅ Power test: 10/10 PASSED
✅ Core tests: 30/33 stable
⚠️  NoiseBudget: Occasionally flaky (test interference - separate issue)
```

---

## 5. NoiseBudget 测试修复

### 问题描述

`NoiseBudgetDecreasesAfterMultiply` 测试在完整套件中运行时约 50-60% 失败率。

### 根本原因

1. **噪声计算错误**: 原实现使用 `raw[i] mod t` 作为噪声度量，但这实际上是解密后的明文系数，对于正确的密文应该接近 0

2. **NTL FFT 限制**: 对于大模数 (q ≈ 2^64.5)，NTL 的 FFT 初始化会抛出 "modulus too big" 错误

3. **全局模数污染**: `noise_budget()` 调用 `ct[j].coeff(i)` 返回 `ZZ_p`，其值依赖当前 NTL 全局模数

### 解决方案

**3.6 正确的噪声估计算法**

```cpp
// BGV 中，解密值 = m + t*E (mod q)
// 其中 m 是消息，E 是噪声
// 噪声 E = floor(Dec / t)

for (size_t i = 0; i < n; i++) {
    ZZ centered = raw[i];
    if (centered > q_half) centered -= q;
    
    // 噪声 = |系数| / t
    ZZ noise_e = abs(centered) / t_modulus;
    if (noise_e > max_noise) max_noise = noise_e;
}

// 噪声预算 = log2(q/2) - log2(max_noise * t)
double budget = log_q - 1 - log(max_noise * t);
```

**3.7 使用 ZZ_pBak/ZZ_pContext 保护模数上下文**

```cpp
double BGVContext::noise_budget(...) {
    // 保存当前 NTL 模数
    ZZ_pBak modulus_backup;
    modulus_backup.save();
    
    // 设置正确的模数用于系数提取
    ZZ_pContext ctx(params_.q);
    ctx.restore();
    
    // ... 纯 ZZ 算术计算 ...
    
    // 恢复原模数
    modulus_backup.restore();
    return budget;
}
```

### 验证结果

```powershell
# 20 次完整测试 - 100% 通过
cd D:\pyproject\kctsb
for ($i=1; $i -le 20; $i++) { 
    .\build\bin\test_bgv.exe 2>&1 | Select-String "PASSED.*33"
}
# 输出: 20/20 "[  PASSED  ] 33 tests."
```

---

## 6. 教训总结

### 6.1 全局状态是危险的

NTL 的全局模数设计简化了单一上下文使用，但在多测试/多上下文场景下引入隐蔽 bug。

**建议**: 
- 显式文档化所有依赖全局状态的函数
- 在测试中使用独立的模数上下文
- 考虑使用 thread-local 或 context 对象管理模数

### 6.2 测试覆盖要深入

简单的单次乘法测试没有暴露问题，是 Power 测试（需要 2 次乘法 + 2 次 relin）才触发了 bug。

**建议**: 设计深度链式操作测试用例

### 6.3 缓存需要考虑上下文变化

缓存 `sk.power(i)` 提高了性能，但假设上下文不变。

**建议**: 
- 缓存时记录上下文版本
- 上下文变化时使缓存失效
- 或使用模数无关的存储

---

## 7. 相关文件

- [v3.2.1-bgv-fix.md](../releases/v3.2.1-bgv-fix.md) - Release Notes
- [homomorphic-encryption-roadmap.md](../homomorphic-encryption-roadmap.md) - 设计文档
- `src/advanced/fe/bgv/bgv_context.cpp` - 主要修改
- `include/kctsb/advanced/fe/bgv/bgv_context.hpp` - 接口变更
