# ECC 性能优化方案

> **目标**: 将 kctsb ECC 性能从当前的 2-30% 提升到 OpenSSL 的 80%+  
> **日期**: 2026-01-19  
> **作者**: knightc (密码学性能优化)

---

## 📊 当前性能分析

| 曲线 | 当前性能 (vs OpenSSL) | 目标性能 | 性能差距原因 |
|------|----------------------|---------|-------------|
| P-256 | 2.6-8.0% | 80%+ | OpenSSL使用`ecp_nistz256.c`专用Montgomery汇编 |
| secp256k1 | 31-67% | 80%+ | 无专用优化,NTL通用后端 |
| SM2 | 8-18% | 80%+ | 与P-256类似的曲线特性 |
| P-384 | 53-98% | 90%+ | 较大曲线NTL效率更优 |

---

## 🔴 问题1: ct_select/ct_negate 非常量时间实现

### 当前问题代码 (ecc_optimized.cpp:267-301)

```cpp
// ❌ 问题: 使用 if 分支，存在时序泄漏
JacobianPoint ct_select(uint8_t selector, 
                        const JacobianPoint& a, 
                        const JacobianPoint& b) {
    if (selector) {   // ← 分支泄漏!
        return a;
    } else {
        return b;
    }
}

JacobianPoint ct_negate(const ECCurve& curve, 
                        const JacobianPoint& P, 
                        uint8_t negate) {
    if (negate) {    // ← 分支泄漏!
        return curve.negate(P);
    }
    return P;
}
```

### ✅ 解决方案: 真正的常量时间实现

#### 方案A: 标量级常量时间操作 (适用于64位字)

```cpp
/**
 * @brief 常量时间64位选择 - 无分支实现
 * @param condition 条件: 非0选择a, 0选择b
 * @param a 条件为真时返回值
 * @param b 条件为假时返回值
 * @return 选择的值，执行时间不依赖condition
 */
KCTSB_FORCE_INLINE uint64_t ct_select_u64(uint64_t condition, 
                                           uint64_t a, 
                                           uint64_t b) {
    // 将condition规范化为0或1
    // 通过双重否定: 非0 -> 1, 0 -> 0
    condition = (condition | (~condition + 1)) >> 63;  // MSB提取
    
    // 创建掩码: condition=1 -> mask=0xFFFFFFFFFFFFFFFF
    //           condition=0 -> mask=0x0000000000000000
    uint64_t mask = ~(condition - 1);
    
    // 返回 (a & mask) | (b & ~mask)
    return (a & mask) | (b & (~mask));
}

/**
 * @brief 常量时间条件否定 - 无分支实现
 * @param condition 条件: 非0返回-x, 0返回x
 * @param x 输入值
 * @return 条件否定结果
 */
KCTSB_FORCE_INLINE uint64_t ct_negate_u64(uint64_t condition, uint64_t x) {
    condition = (condition | (~condition + 1)) >> 63;
    uint64_t mask = ~(condition - 1);
    // -x = ~x + 1 = x ^ 0xFFFF... + (condition != 0 ? 1 : 0)
    return (x ^ mask) + condition;
}
```

#### 方案B: 大整数级常量时间操作 (适用于ZZ_p/256-bit字段)

```cpp
/**
 * @brief 常量时间256位字段元素选择
 * 
 * 实现: 对每个64位limb应用掩码操作
 * 
 * @param condition 条件 (0或非0)
 * @param a 条件为真时的选择
 * @param b 条件为假时的选择
 * @param result 输出缓冲区 (4个uint64_t)
 */
void ct_select_fe256(uint64_t condition,
                     const uint64_t a[4],
                     const uint64_t b[4],
                     uint64_t result[4]) {
    // 规范化condition为0或全1
    uint64_t mask = ~((condition | (~condition + 1)) >> 63) + 1;
    
    // 常量时间选择 - 无分支
    result[0] = (a[0] & mask) | (b[0] & ~mask);
    result[1] = (a[1] & mask) | (b[1] & ~mask);
    result[2] = (a[2] & mask) | (b[2] & ~mask);
    result[3] = (a[3] & mask) | (b[3] & ~mask);
}

/**
 * @brief 常量时间Jacobian点选择
 * 
 * @param condition 选择条件
 * @param a 条件为真时返回
 * @param b 条件为假时返回
 * @return 选择的点 (执行时间恒定)
 */
JacobianPoint ct_select_point(uint64_t condition,
                               const JacobianPoint& a,
                               const JacobianPoint& b) {
    JacobianPoint result;
    
    // 将ZZ_p转换为limb数组进行操作
    // 假设已有 zz_p_to_limbs() 和 limbs_to_zz_p() 函数
    uint64_t a_X[4], a_Y[4], a_Z[4];
    uint64_t b_X[4], b_Y[4], b_Z[4];
    uint64_t r_X[4], r_Y[4], r_Z[4];
    
    zz_p_to_limbs(a.X, a_X);
    zz_p_to_limbs(a.Y, a_Y);
    zz_p_to_limbs(a.Z, a_Z);
    zz_p_to_limbs(b.X, b_X);
    zz_p_to_limbs(b.Y, b_Y);
    zz_p_to_limbs(b.Z, b_Z);
    
    ct_select_fe256(condition, a_X, b_X, r_X);
    ct_select_fe256(condition, a_Y, b_Y, r_Y);
    ct_select_fe256(condition, a_Z, b_Z, r_Z);
    
    limbs_to_zz_p(r_X, result.X);
    limbs_to_zz_p(r_Y, result.Y);
    limbs_to_zz_p(r_Z, result.Z);
    
    return result;
}

/**
 * @brief 常量时间点否定
 * 
 * P-256/SM2曲线上: -P = (X, p - Y, Z)
 * 常量时间实现: 始终计算neg_Y = p - Y, 然后条件选择
 * 
 * @param P 输入点
 * @param negate 否定条件 (0或非0)
 * @param prime 曲线模数p的limb表示
 * @return 条件否定结果
 */
JacobianPoint ct_negate_point(const JacobianPoint& P,
                               uint64_t negate,
                               const uint64_t prime[4]) {
    JacobianPoint result;
    
    uint64_t Y[4], neg_Y[4], result_Y[4];
    zz_p_to_limbs(P.Y, Y);
    
    // 始终计算 neg_Y = p - Y (常量时间减法)
    ct_sub_mod256(prime, Y, neg_Y, prime);  // neg_Y = p - Y mod p
    
    // 条件选择: negate ? neg_Y : Y
    ct_select_fe256(negate, neg_Y, Y, result_Y);
    
    // X和Z保持不变
    result.X = P.X;
    limbs_to_zz_p(result_Y, result.Y);
    result.Z = P.Z;
    
    return result;
}
```

#### 方案C: AVX2加速的常量时间选择 (256位一次性处理)

```cpp
#ifdef KCTSB_HAS_AVX2

/**
 * @brief AVX2加速的256位常量时间选择
 * 
 * 使用单条_mm256_blendv_epi8指令实现无分支选择
 */
void ct_select_fe256_avx2(uint64_t condition,
                           const uint64_t a[4],
                           const uint64_t b[4],
                           uint64_t result[4]) {
    // 广播condition到256位掩码
    __m256i cond_vec = _mm256_set1_epi64x(
        -static_cast<int64_t>((condition | (~condition + 1)) >> 63)
    );
    
    __m256i va = _mm256_loadu_si256((const __m256i*)a);
    __m256i vb = _mm256_loadu_si256((const __m256i*)b);
    
    // blendv: mask为0选b, mask为全1选a
    __m256i vr = _mm256_blendv_epi8(vb, va, cond_vec);
    
    _mm256_storeu_si256((__m256i*)result, vr);
}

/**
 * @brief AVX2加速的Jacobian点选择 (3个256位坐标)
 */
void ct_select_jacobian_avx2(uint64_t condition,
                              const uint64_t a[12],  // X,Y,Z各4个limb
                              const uint64_t b[12],
                              uint64_t result[12]) {
    __m256i cond_vec = _mm256_set1_epi64x(
        -static_cast<int64_t>((condition | (~condition + 1)) >> 63)
    );
    
    // 处理X (4 limbs = 256 bits)
    __m256i va_X = _mm256_loadu_si256((const __m256i*)(a));
    __m256i vb_X = _mm256_loadu_si256((const __m256i*)(b));
    _mm256_storeu_si256((__m256i*)(result), 
                        _mm256_blendv_epi8(vb_X, va_X, cond_vec));
    
    // 处理Y
    __m256i va_Y = _mm256_loadu_si256((const __m256i*)(a + 4));
    __m256i vb_Y = _mm256_loadu_si256((const __m256i*)(b + 4));
    _mm256_storeu_si256((__m256i*)(result + 4), 
                        _mm256_blendv_epi8(vb_Y, va_Y, cond_vec));
    
    // 处理Z
    __m256i va_Z = _mm256_loadu_si256((const __m256i*)(a + 8));
    __m256i vb_Z = _mm256_loadu_si256((const __m256i*)(b + 8));
    _mm256_storeu_si256((__m256i*)(result + 8), 
                        _mm256_blendv_epi8(vb_Z, va_Z, cond_vec));
}

#endif // KCTSB_HAS_AVX2
```

---

## 🔴 问题2: P-256/SM2 缺少专用Montgomery域实现

### 为什么OpenSSL P-256那么快?

OpenSSL的`ecp_nistz256.c`使用:
1. **P-256专用Montgomery常数**: 预计算的 R = 2^256 mod p, R^2 mod p, p'
2. **内联汇编**: 利用ADC指令链实现进位传播
3. **SIMD加速**: AVX2并行计算多个limb

### ✅ 解决方案: P-256/SM2 Montgomery域特化

#### 256位Montgomery乘法优化实现

```cpp
/**
 * @file fe_p256.h
 * @brief P-256/SM2曲线专用字段运算 - Montgomery域实现
 * 
 * Montgomery表示: x̄ = x * R mod p, 其中 R = 2^256
 * 乘法: x̄ * ȳ * R^(-1) mod p = (x*y)*R mod p
 */

namespace kctsb {
namespace ecc {
namespace p256 {

// P-256 曲线模数 (NIST)
// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
constexpr uint64_t P256_PRIME[4] = {
    0xFFFFFFFFFFFFFFFFULL,  // limb 0 (lowest)
    0x00000000FFFFFFFFULL,
    0x0000000000000000ULL,
    0xFFFFFFFF00000001ULL   // limb 3 (highest)
};

// Montgomery常数: R = 2^256 mod p
constexpr uint64_t P256_R[4] = {
    0x0000000000000001ULL,
    0xFFFFFFFF00000000ULL,
    0xFFFFFFFFFFFFFFFFULL,
    0x00000000FFFFFFFEULL
};

// R^2 mod p (用于转换到Montgomery域)
constexpr uint64_t P256_R_SQUARED[4] = {
    0x0000000000000003ULL,
    0xFFFFFFFBFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFEULL,
    0x00000004FFFFFFFDULL
};

// p' = -p^(-1) mod 2^64 (用于Montgomery约减)
constexpr uint64_t P256_P_PRIME = 0x0000000000000001ULL;

/**
 * @brief 256位加法 with carry
 * @return carry out (0或1)
 */
KCTSB_FORCE_INLINE uint64_t add256(const uint64_t a[4], 
                                    const uint64_t b[4],
                                    uint64_t result[4]) {
    uint64_t carry = 0;
    
#if defined(__GNUC__) && defined(__x86_64__)
    // 使用GCC内建的带进位加法
    carry = __builtin_addcll(a[0], b[0], 0, &result[0]);
    carry = __builtin_addcll(a[1], b[1], carry, &result[1]);
    carry = __builtin_addcll(a[2], b[2], carry, &result[2]);
    carry = __builtin_addcll(a[3], b[3], carry, &result[3]);
#else
    // 可移植实现
    result[0] = a[0] + b[0];
    carry = (result[0] < a[0]) ? 1 : 0;
    
    result[1] = a[1] + b[1] + carry;
    carry = (result[1] < a[1] || (carry && result[1] == a[1])) ? 1 : 0;
    
    result[2] = a[2] + b[2] + carry;
    carry = (result[2] < a[2] || (carry && result[2] == a[2])) ? 1 : 0;
    
    result[3] = a[3] + b[3] + carry;
    carry = (result[3] < a[3] || (carry && result[3] == a[3])) ? 1 : 0;
#endif
    
    return carry;
}

/**
 * @brief 256位减法 with borrow
 * @return borrow out (0或1)
 */
KCTSB_FORCE_INLINE uint64_t sub256(const uint64_t a[4], 
                                    const uint64_t b[4],
                                    uint64_t result[4]) {
    uint64_t borrow = 0;
    
    for (int i = 0; i < 4; i++) {
        uint64_t temp = a[i] - borrow;
        borrow = (temp > a[i]) ? 1 : 0;
        result[i] = temp - b[i];
        borrow |= (result[i] > temp) ? 1 : 0;
    }
    
    return borrow;
}

/**
 * @brief P-256 模加法
 * result = (a + b) mod p
 */
void fe_add_p256(const uint64_t a[4], 
                  const uint64_t b[4],
                  uint64_t result[4]) {
    uint64_t temp[4];
    uint64_t carry = add256(a, b, temp);
    
    // 如果 carry 或 temp >= p, 则减p
    uint64_t mask;
    if (carry) {
        mask = 0xFFFFFFFFFFFFFFFFULL;  // 肯定需要减p
    } else {
        // 比较 temp >= P256_PRIME
        // 常量时间比较
        int64_t ge = 0;
        ge |= (temp[3] > P256_PRIME[3]);
        ge |= (temp[3] == P256_PRIME[3]) && (temp[2] > P256_PRIME[2]);
        ge |= (temp[3] == P256_PRIME[3]) && (temp[2] == P256_PRIME[2]) && 
              (temp[1] > P256_PRIME[1]);
        ge |= (temp[3] == P256_PRIME[3]) && (temp[2] == P256_PRIME[2]) && 
              (temp[1] == P256_PRIME[1]) && (temp[0] >= P256_PRIME[0]);
        mask = ~(ge - 1);  // ge ? 全1 : 全0
    }
    
    // 条件减法: result = temp - (p & mask)
    uint64_t sub_val[4] = {
        P256_PRIME[0] & mask,
        P256_PRIME[1] & mask,
        P256_PRIME[2] & mask,
        P256_PRIME[3] & mask
    };
    sub256(temp, sub_val, result);
}

/**
 * @brief P-256 Montgomery乘法
 * 
 * 使用CIOS (Coarsely Integrated Operand Scanning)算法
 * result = (a * b * R^(-1)) mod p
 * 
 * 性能关键: 此函数在标量乘法中被调用约10,000次
 */
void fe_mul_mont_p256(const uint64_t a[4], 
                       const uint64_t b[4],
                       uint64_t result[4]) {
    // 累加器: 8个limbs + 1个进位
    uint64_t t[9] = {0};
    
    // CIOS算法: 逐limb乘加并约减
    for (int i = 0; i < 4; i++) {
        // 第1步: t += a[i] * b (乘法-累加)
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            // 128位乘法
            unsigned __int128 prod = 
                (unsigned __int128)a[i] * b[j] + t[j] + carry;
            t[j] = (uint64_t)prod;
            carry = (uint64_t)(prod >> 64);
        }
        t[4] += carry;
        carry = (t[4] < carry) ? 1 : 0;
        t[5] += carry;
        
        // 第2步: Montgomery约减
        // m = t[0] * p' mod 2^64
        uint64_t m = t[0] * P256_P_PRIME;
        
        // t += m * p
        carry = 0;
        unsigned __int128 prod;
        
        prod = (unsigned __int128)m * P256_PRIME[0] + t[0];
        // t[0]变为0 (by design)
        carry = (uint64_t)(prod >> 64);
        
        prod = (unsigned __int128)m * P256_PRIME[1] + t[1] + carry;
        t[0] = (uint64_t)prod;  // 右移一个limb
        carry = (uint64_t)(prod >> 64);
        
        prod = (unsigned __int128)m * P256_PRIME[2] + t[2] + carry;
        t[1] = (uint64_t)prod;
        carry = (uint64_t)(prod >> 64);
        
        prod = (unsigned __int128)m * P256_PRIME[3] + t[3] + carry;
        t[2] = (uint64_t)prod;
        carry = (uint64_t)(prod >> 64);
        
        t[3] = t[4] + carry;
        carry = (t[3] < t[4]) ? 1 : 0;
        t[4] = t[5] + carry;
        t[5] = 0;
    }
    
    // 最终约减: 如果 t >= p, 则减p
    uint64_t temp[4] = {t[0], t[1], t[2], t[3]};
    uint64_t borrow = sub256(temp, P256_PRIME, result);
    
    // 常量时间选择: borrow ? temp : result
    uint64_t mask = ~(borrow - 1);  // borrow=1 -> mask=全0
    result[0] = (result[0] & ~mask) | (temp[0] & mask);
    result[1] = (result[1] & ~mask) | (temp[1] & mask);
    result[2] = (result[2] & ~mask) | (temp[2] & mask);
    result[3] = (result[3] & ~mask) | (temp[3] & mask);
}

/**
 * @brief P-256 Montgomery平方
 * 
 * 专用平方比通用乘法快约30%（利用对称性减少乘法次数）
 * result = (a * a * R^(-1)) mod p
 */
void fe_sqr_mont_p256(const uint64_t a[4], uint64_t result[4]) {
    // 优化: 利用 a[i]*a[j] = a[j]*a[i] 的对称性
    // 只计算上三角，然后加倍
    
    uint64_t t[9] = {0};
    
    // 计算交叉项 2 * sum(a[i] * a[j] for i < j)
    // ... (实现类似fe_mul_mont_p256但利用对称性)
    
    // 简化实现: 调用通用乘法
    fe_mul_mont_p256(a, a, result);
}

/**
 * @brief 转换到Montgomery域
 * result = a * R mod p
 */
void fe_to_mont_p256(const uint64_t a[4], uint64_t result[4]) {
    fe_mul_mont_p256(a, P256_R_SQUARED, result);
}

/**
 * @brief 从Montgomery域转换回标准域
 * result = a * R^(-1) mod p
 */
void fe_from_mont_p256(const uint64_t a[4], uint64_t result[4]) {
    uint64_t one[4] = {1, 0, 0, 0};
    fe_mul_mont_p256(a, one, result);
}

} // namespace p256
} // namespace ecc
} // namespace kctsb
```

#### SM2曲线专用常数

```cpp
namespace sm2 {

// SM2 曲线模数
// p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
constexpr uint64_t SM2_PRIME[4] = {
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFF00000000ULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFEFFFFFFFFULL
};

// SM2 p' = -p^(-1) mod 2^64
constexpr uint64_t SM2_P_PRIME = 0x0000000000000001ULL;

// 其他Montgomery常数...
// R, R^2 等需要预计算

} // namespace sm2
```

---

## 🔴 问题3: 缺少AVX2加速的字段运算

### ✅ AVX2加速256位字段运算

```cpp
#ifdef KCTSB_HAS_AVX2

namespace avx2 {

/**
 * @brief AVX2加速的256位加法 (4个并行64位加法)
 * 
 * 注意: AVX2没有直接的64位带进位加法
 * 使用进位链模拟或使用BMI2的MULX/ADCX/ADOX
 */
void fe256_add_avx2(const uint64_t a[4], 
                     const uint64_t b[4],
                     uint64_t result[4]) {
    __m256i va = _mm256_loadu_si256((const __m256i*)a);
    __m256i vb = _mm256_loadu_si256((const __m256i*)b);
    
    // 64位加法 (无进位传播)
    __m256i sum = _mm256_add_epi64(va, vb);
    
    // 检测溢出: 如果 sum < a, 则发生溢出
    __m256i overflow = _mm256_cmpgt_epi64(va, sum);
    
    // 进位传播需要串行处理 (AVX2限制)
    // 提取到标量进行进位链
    alignas(32) uint64_t temp[4];
    alignas(32) uint64_t ovf[4];
    _mm256_store_si256((__m256i*)temp, sum);
    _mm256_store_si256((__m256i*)ovf, overflow);
    
    // 进位传播
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        temp[i] += carry;
        carry = (ovf[i] != 0) | (temp[i] < carry);
    }
    
    // 存储结果
    std::memcpy(result, temp, 32);
}

/**
 * @brief AVX2加速的256x64位乘法 (用于Montgomery约减内循环)
 * 
 * 使用MULX指令 (需要BMI2支持)
 */
#ifdef __BMI2__
KCTSB_FORCE_INLINE void mulx_u64(uint64_t a, uint64_t b,
                                  uint64_t* lo, uint64_t* hi) {
    unsigned long long hi_out;
    *lo = _mulx_u64(a, b, &hi_out);
    *hi = hi_out;
}
#endif

/**
 * @brief 使用ADCX/ADOX的并行乘加链 (需要ADX支持)
 * 
 * ADX允许两条独立的进位链并行执行
 */
#ifdef __ADX__
void fe256_mul_adx(const uint64_t a[4], 
                    const uint64_t b[4],
                    uint64_t result[8]) {
    // 使用MULX产生128位积
    // 使用ADCX/ADOX并行累加
    // 这是OpenSSL ecp_nistz256使用的核心技术
    
    uint64_t t0, t1, t2, t3, t4, t5, t6, t7;
    uint64_t hi, lo;
    unsigned char cf, of;
    
    // 第一列
    mulx_u64(a[0], b[0], &t0, &t1);
    mulx_u64(a[0], b[1], &lo, &hi);
    cf = _addcarryx_u64(0, t1, lo, &t1);
    of = _addcarryx_u64(0, 0, hi, &t2);
    
    // ... 完整的乘法链实现
    // (实际实现需要完整的4x4 = 16次乘法)
}
#endif

/**
 * @brief AVX2并行处理多个点操作
 * 
 * 同时处理2-4个独立的点乘法
 * 适用于批量签名验证场景
 */
struct Point256x4 {
    __m256i X[4];  // 4个点的X坐标 (每个256位)
    __m256i Y[4];  // 4个点的Y坐标
    __m256i Z[4];  // 4个点的Z坐标
};

void point_double_4way(Point256x4& P, const uint64_t prime[4]) {
    // 使用SIMD同时对4个点进行倍点运算
    // 利用Jacobian倍点公式并行化
    
    // 这需要重新设计数据布局 (SoA: Structure of Arrays)
    // 而不是当前的AoS (Array of Structures)
}

} // namespace avx2

#endif // KCTSB_HAS_AVX2
```

---

## 📊 预计性能提升

### 优化后预期性能对比

| 曲线 | 当前 | 优化后预期 | 提升倍数 |
|------|------|-----------|---------|
| P-256 KeyGen | 2.6% | 60-80% | **23-30x** |
| P-256 Sign | 2.6% | 60-80% | **23-30x** |
| P-256 Verify | 5.2% | 70-85% | **13-16x** |
| secp256k1 | 31-67% | 80-95% | **1.5-3x** |
| SM2 | 8-18% | 60-80% | **4-10x** |

### 各优化项贡献

| 优化项 | 预期贡献 | 实现复杂度 |
|--------|---------|-----------|
| 真正的常量时间ct_select/ct_negate | +10-15% | 低 (1周) |
| P-256专用Montgomery乘法 | +200-400% | 高 (3-4周) |
| AVX2加速字段运算 | +30-50% | 中 (2周) |
| MULX/ADCX/ADOX优化 | +20-30% | 高 (2周) |
| 预计算表优化 | +20-30% | 低 (1周) |

---

## 🛠️ 实现路线图

### Phase 1: 常量时间修复 (高优先级, 1周)
1. 实现真正的`ct_select_u64`, `ct_negate_u64`
2. 实现`ct_select_fe256` (256位字段元素版本)
3. 替换`ecc_optimized.cpp`中的条件分支
4. 添加时序攻击测试

### Phase 2: P-256 Montgomery特化 (高优先级, 3-4周)
1. 创建`src/crypto/ecc/fe_p256.cpp`
2. 实现CIOS Montgomery乘法
3. 实现专用加法、减法、平方
4. 与现有JacobianPoint集成

### Phase 3: SM2 Montgomery特化 (中优先级, 2周)
1. 复制P-256实现框架
2. 替换曲线常数
3. 验证SM2测试向量

### Phase 4: AVX2/SIMD加速 (中优先级, 2周)
1. 检测并启用BMI2/ADX指令
2. 实现AVX2版本的字段运算
3. 运行时特性检测和分发

### Phase 5: 高级优化 (低优先级, 可选)
1. 内联汇编版本 (x86-64)
2. ARM NEON版本 (移动设备)
3. 批量验证优化

---

## 📁 建议的文件结构

```
src/crypto/ecc/
├── ecc_curve.cpp           # 通用曲线实现 (现有)
├── ecc_optimized.cpp       # wNAF优化 (现有)
├── fe_generic.h            # 通用字段运算接口
├── fe_p256.cpp             # P-256专用Montgomery实现 (新增)
├── fe_p256_avx2.cpp        # P-256 AVX2加速版本 (新增)
├── fe_sm2.cpp              # SM2专用Montgomery实现 (新增)
├── ct_ops.h                # 常量时间操作 (新增)
└── simd_dispatch.h         # SIMD运行时分发 (新增)
```

---

## 🔗 参考资源

1. **OpenSSL ecp_nistz256.c**: https://github.com/openssl/openssl/blob/master/crypto/ec/ecp_nistz256.c
2. **NIST P-256 Curve**: FIPS 186-4 Appendix D.1.2.3
3. **Montgomery乘法**: Peter L. Montgomery, "Modular Multiplication Without Trial Division"
4. **wNAF算法**: Möller, "Improved Techniques for Fast Exponentiation"
5. **侧信道防护**: Bernstein, "Curve25519: new Diffie-Hellman speed records"

---

> **注意**: 本文档中的代码为优化方案示例，实际实现需要：
> 1. 完整的测试向量验证
> 2. 时序攻击抵抗性测试
> 3. 跨平台兼容性验证
> 4. 与现有NTL后端的无缝集成
