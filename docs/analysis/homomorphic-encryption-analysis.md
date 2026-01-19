# 同态加密库对比分析: Microsoft SEAL vs HElib

> **文档版本**: v1.0  
> **更新时间**: 2026-01-19 (Beijing Time, UTC+8)  
> **适用项目**: kctsb - Knight's Cryptographic Trusted Security Base

---

## 1. 概述

本文档详细分析两个主流同态加密库的设计、功能和实现，为kctsb自实现同态加密提供参考。

### 1.1 同态加密基础

**全同态加密 (Fully Homomorphic Encryption, FHE)** 允许在加密数据上进行任意计算，计算结果解密后与明文计算结果一致。

**核心数学基础**:
- 格基密码学 (Lattice-based Cryptography)
- Ring Learning With Errors (RLWE) 问题
- 多项式环运算 $R_q = \mathbb{Z}_q[X]/(X^n + 1)$

---

## 2. Microsoft SEAL 深度分析

### 2.1 项目信息

| 属性 | 描述 |
|------|------|
| **GitHub** | https://github.com/microsoft/SEAL |
| **许可证** | MIT License |
| **语言** | C++ (C++17标准) |
| **版本** | 4.1 (当前稳定版) |
| **依赖** | 无强制外部依赖 (可选: Intel HEXL) |

### 2.2 支持的加密方案

#### 2.2.1 BFV (Brakerski-Fan-Vercauteren)

**用途**: 精确整数运算

**数学原理**:
- 明文空间: $\mathbb{Z}_t$ (模 $t$ 整数)
- 密文空间: $R_q^2$ (多项式对)
- 加密: $ct = (c_0, c_1)$ where $c_0 = \Delta \cdot m + e_0 + a \cdot s$, $c_1 = a + e_1$
- 其中 $\Delta = \lfloor q/t \rfloor$ 是缩放因子

**关键操作**:
```
Encrypt(m): ct = (Δ·m + e₀ + a·s, a + e₁)
Add(ct₁, ct₂): (ct₁.c₀ + ct₂.c₀, ct₁.c₁ + ct₂.c₁)
Multiply(ct₁, ct₂): 张量积后重线性化
Decrypt(ct): m = round(t/q · (c₀ - c₁·s)) mod t
```

**参数选择**:
- `poly_modulus_degree`: 多项式模数度 (2^n, 通常 4096-32768)
- `coeff_modulus`: 系数模数链 (RNS 表示)
- `plain_modulus`: 明文模数 t

#### 2.2.2 BGV (Brakerski-Gentry-Vaikuntanathan)

**用途**: 精确整数运算 (模数切换优化)

**与BFV差异**:
- 采用 modulus switching 而非 scale invariant 技术
- 噪声增长模式不同
- 适合深层电路

**核心公式**:
```
Encrypt(m): ct = (m + e₀ + a·s, a + e₁)  // 注意：无Δ缩放
ModSwitch(ct, q→q'): 模数切换降噪
```

#### 2.2.3 CKKS (Cheon-Kim-Kim-Song)

**用途**: 近似实数/复数运算

**数学原理**:
- 明文空间: $\mathbb{C}^{n/2}$ (复数向量)
- 编码: 将复数向量编码为多项式
- 采用缩放因子 scale 管理精度

**关键操作**:
```
Encode(v, scale): p(X) ← 将复数向量编码为多项式
Encrypt(p): ct = (scale·p + e₀ + a·s, a + e₁)
Rescale(ct): 乘法后缩放因子减半
```

**优势**: 支持机器学习等需要浮点运算的场景

### 2.3 核心架构

```
SEAL/
├── native/src/seal/
│   ├── context.cpp          # 加密上下文管理
│   ├── evaluator.cpp         # 同态运算评估器
│   ├── encryptor.cpp         # 加密器
│   ├── decryptor.cpp         # 解密器
│   ├── keygenerator.cpp      # 密钥生成
│   ├── batchencoder.cpp      # BFV/BGV 批量编码
│   ├── ckks_encoder.cpp      # CKKS 编码器
│   ├── modulus.cpp           # 模数管理
│   ├── util/
│   │   ├── ntt.cpp           # 数论变换 (NTT)
│   │   ├── rns.cpp           # 残差数系统
│   │   ├── polyarithsmallmod.cpp  # 多项式运算
│   │   └── numth.cpp         # 数论工具
│   └── ...
```

### 2.4 关键技术

| 技术 | 描述 | 性能影响 |
|------|------|----------|
| **NTT** | 快速多项式乘法 O(n log n) | 核心加速 |
| **RNS** | 残差数系统分解大模数 | 避免大整数运算 |
| **Relinearization** | 密文重线性化 | 控制密文尺寸 |
| **Galois Rotation** | 密文槽位旋转 | SIMD 操作 |
| **Intel HEXL** | AVX512-IFMA 硬件加速 | 2-4x 提速 |

### 2.5 API 使用示例

```cpp
#include "seal/seal.h"

using namespace seal;

// 1. 参数设置
EncryptionParameters parms(scheme_type::bfv);
parms.set_poly_modulus_degree(4096);
parms.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
parms.set_plain_modulus(1024);

// 2. 创建上下文
SEALContext context(parms);

// 3. 密钥生成
KeyGenerator keygen(context);
SecretKey secret_key = keygen.secret_key();
PublicKey public_key;
keygen.create_public_key(public_key);
RelinKeys relin_keys;
keygen.create_relin_keys(relin_keys);

// 4. 加密器/解密器/评估器
Encryptor encryptor(context, public_key);
Decryptor decryptor(context, secret_key);
Evaluator evaluator(context);

// 5. 编码和加密
Plaintext plain("6");
Ciphertext encrypted;
encryptor.encrypt(plain, encrypted);

// 6. 同态计算
Ciphertext squared;
evaluator.square(encrypted, squared);
evaluator.relinearize_inplace(squared, relin_keys);

// 7. 解密
Plaintext result;
decryptor.decrypt(squared, result);
// result = "24" (6² mod 1024 = 36, 但受噪声影响需要更大参数)
```

---

## 3. HElib 深度分析

### 3.1 项目信息

| 属性 | 描述 |
|------|------|
| **GitHub** | https://github.com/homenc/HElib |
| **许可证** | Apache 2.0 |
| **语言** | C++ (C++17标准) |
| **版本** | 2.3.0 (当前稳定版) |
| **依赖** | NTL, GMP (必需) |

### 3.2 支持的加密方案

#### 3.2.1 BGV (原生支持)

HElib 以 BGV 为核心设计，提供深度优化的实现。

**特色功能**:
- Smart 模数链管理
- 自动噪声估计
- 自举 (Bootstrapping) 支持

#### 3.2.2 CKKS (近似运算)

从 v2.0 开始支持 CKKS 方案。

### 3.3 核心架构

```
HElib/
├── src/
│   ├── Context.cpp           # 方案上下文
│   ├── Ctxt.cpp              # 密文类
│   ├── PubKey.cpp            # 公钥管理
│   ├── SecKey.cpp            # 私钥管理
│   ├── EncryptedArray.cpp    # 加密数组 (SIMD)
│   ├── EvalMap.cpp           # 同态评估映射
│   ├── bootstrapping/        # 自举实现
│   ├── ntt/                  # NTT 实现
│   └── ...
```

### 3.4 关键技术

| 技术 | 描述 | 与 SEAL 对比 |
|------|------|-------------|
| **Bootstrapping** | 全同态自举 | HElib 更成熟 |
| **Packed Ciphertexts** | SIMD 批量加密 | 类似 BatchEncoder |
| **Modulus Switching** | 模数切换降噪 | BGV 核心技术 |
| **NTL 集成** | 高精度数学运算 | SEAL 无 NTL 依赖 |

### 3.5 API 使用示例

```cpp
#include <helib/helib.h>

using namespace helib;

// 1. 上下文参数
unsigned long p = 2;        // 明文模数基
unsigned long m = 4095;     // 环的阶
unsigned long r = 1;        // Hensel lifting
unsigned long bits = 500;   // 安全参数
unsigned long c = 2;        // 密钥切换列数

// 2. 创建上下文
Context context = ContextBuilder<BGV>()
    .m(m)
    .p(p)
    .r(r)
    .bits(bits)
    .c(c)
    .build();

// 3. 密钥生成
SecKey secret_key(context);
secret_key.GenSecKey();
addSome1DMatrices(secret_key);  // 旋转密钥

const PubKey& public_key = secret_key;

// 4. 加密数组 (SIMD)
const EncryptedArray& ea = context.getEA();
long nslots = ea.size();

std::vector<long> ptxt1(nslots, 3);
std::vector<long> ptxt2(nslots, 2);

Ctxt ctxt1(public_key);
Ctxt ctxt2(public_key);

ea.encrypt(ctxt1, public_key, ptxt1);
ea.encrypt(ctxt2, public_key, ptxt2);

// 5. 同态计算
ctxt1 += ctxt2;  // 加法
ctxt1 *= ctxt2;  // 乘法

// 6. 解密
std::vector<long> result;
ea.decrypt(ctxt1, secret_key, result);
```

---

## 4. SEAL vs HElib 对比

### 4.1 功能对比

| 特性 | Microsoft SEAL | HElib |
|------|---------------|-------|
| **BFV 方案** | ✅ 完整支持 | ❌ 不支持 |
| **BGV 方案** | ✅ v4.0+ | ✅ 核心方案 |
| **CKKS 方案** | ✅ 完整支持 | ✅ v2.0+ |
| **Bootstrapping** | ❌ 不支持 | ✅ 完整支持 |
| **SIMD/Batching** | ✅ BatchEncoder | ✅ EncryptedArray |
| **密钥切换** | ✅ | ✅ |
| **Galois 旋转** | ✅ | ✅ |

### 4.2 性能对比 (参考基准)

| 操作 | SEAL 4.1 | HElib 2.3 | 备注 |
|------|----------|-----------|------|
| **KeyGen (BGV)** | ~50 ms | ~80 ms | n=8192 |
| **Encrypt** | ~5 ms | ~8 ms | 单密文 |
| **Add** | ~0.1 ms | ~0.15 ms | |
| **Multiply** | ~10 ms | ~15 ms | 含 relin |
| **Rotate** | ~8 ms | ~10 ms | |

*注: 基准测试依赖硬件配置，仅供参考*

### 4.3 使用场景推荐

| 场景 | 推荐库 | 原因 |
|------|--------|------|
| 机器学习推理 | SEAL (CKKS) | 近似计算足够，API 友好 |
| 精确整数计算 | SEAL (BFV) | 无自举需求时性能更优 |
| 深层电路 | HElib (BGV) | Bootstrapping 支持 |
| 隐私集合运算 | SEAL/HElib | 取决于具体算法 |
| 学术研究 | HElib | NTL 集成便于原型开发 |

---

## 5. kctsb 自实现规划

### 5.1 设计目标

1. **不依赖外部 FHE 库**: 使用 kctsb 内置的 bignum (NTL 集成) 实现核心算法
2. **模块化设计**: BGV/BFV/CKKS 分离实现
3. **性能优化**: NTT 加速、RNS 分解、SIMD 批量处理
4. **安全性**: 常量时间操作、安全参数选择

### 5.2 实现路线图

#### Phase 1: BGV 基础实现 (v4.2.0)

```
src/advanced/fe/
├── bgv/
│   ├── bgv_context.cpp       # 上下文和参数管理
│   ├── bgv_keygen.cpp        # 密钥生成
│   ├── bgv_encrypt.cpp       # 加密/解密
│   ├── bgv_eval.cpp          # 同态评估 (Add/Mult)
│   └── bgv_ntt.cpp           # NTT 加速
```

**核心数据结构**:
```cpp
namespace kctsb::fe::bgv {

// BGV 参数
struct BGVParams {
    size_t poly_modulus_degree;   // n (通常 2^k)
    std::vector<uint64_t> q_primes;  // 模数链 (RNS)
    uint64_t plain_modulus;       // 明文模数 t
    
    // 计算 Δ = floor(Q/t)
    ZZ compute_delta() const;
};

// BGV 密文
class BGVCiphertext {
    std::vector<ZZ_pX> components;  // (c0, c1, ...)
    size_t level;                   // 当前模数层级
    
public:
    void add(const BGVCiphertext& other);
    void multiply(const BGVCiphertext& other, const EvalKey& ek);
    void mod_switch();             // 模数切换
};

}  // namespace kctsb::fe::bgv
```

#### Phase 2: BFV 实现 (v4.3.0)

继承 BGV 框架，修改缩放因子处理逻辑。

#### Phase 3: CKKS 实现 (v4.4.0)

添加复数编码和 rescale 操作。

### 5.3 性能目标

| 指标 | SEAL 4.1 | kctsb 目标 | 备注 |
|------|----------|-----------|------|
| KeyGen | 50 ms | < 100 ms | 初期 2x 差距可接受 |
| Add | 0.1 ms | < 0.2 ms | |
| Multiply | 10 ms | < 20 ms | |
| NTT | 基准 | < 1.5x | 使用 bignum FFT |

---

## 6. 参考资料

### 6.1 论文

1. **BFV**: Fan & Vercauteren, "Somewhat Practical Fully Homomorphic Encryption", IACR ePrint 2012/144
2. **BGV**: Brakerski, Gentry & Vaikuntanathan, "Fully Homomorphic Encryption without Bootstrapping", ITCS 2012
3. **CKKS**: Cheon, Kim, Kim & Song, "Homomorphic Encryption for Arithmetic of Approximate Numbers", ASIACRYPT 2017
4. **SEAL Design**: Microsoft Research, "Simple Encrypted Arithmetic Library (SEAL) Manual"

### 6.2 在线资源

- [Microsoft SEAL GitHub](https://github.com/microsoft/SEAL)
- [HElib GitHub](https://github.com/homenc/HElib)
- [OpenFHE](https://github.com/openfheorg/openfhe-development) - 另一个参考实现
- [TFHE](https://github.com/tfhe/tfhe) - 快速自举实现

---

*文档结束*
