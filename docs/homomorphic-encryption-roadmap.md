# kctsb 同态加密与隐私计算设计文档

> **文档版本**: v1.0  
> **更新时间**: 2026-01-19 (Beijing Time, UTC+8)  
> **项目版本**: kctsb v4.2.0+

---

## 1. 愿景与目标

### 1.1 核心愿景

将 kctsb 打造为**不依赖外部同态加密库**的完整隐私计算解决方案，提供:

- **自实现的同态加密方案** (BGV/BFV/CKKS)
- **高性能隐私集合运算** (PSI/PIR)  
- **安全多方计算基础组件** (Secret Sharing, OT)

### 1.2 设计原则

| 原则 | 描述 |
|------|------|
| **零外部 FHE 依赖** | 不依赖 SEAL/HElib，使用 kctsb bignum 自实现 |
| **安全优先** | 常量时间操作，抗侧信道攻击 |
| **极致性能** | NTT/AVX2 加速，逼近 SEAL 性能 |
| **模块化架构** | 方案独立，便于扩展 |
| **生产可用** | 完整测试，标准兼容 |

---

## 2. 架构设计

### 2.1 模块结构

```
src/advanced/
├── fe/                        # 功能加密 (Functional Encryption)
│   ├── common/                # 共享组件
│   │   ├── ntt.cpp            # 数论变换
│   │   ├── rns.cpp            # 残差数系统
│   │   ├── poly_ring.cpp      # 多项式环运算
│   │   └── param_selector.cpp # 参数选择器
│   │
│   ├── bgv/                   # BGV 方案 (精确整数)
│   │   ├── bgv_context.cpp
│   │   ├── bgv_keygen.cpp
│   │   ├── bgv_encrypt.cpp
│   │   ├── bgv_eval.cpp
│   │   └── bgv_modswitch.cpp
│   │
│   ├── bfv/                   # BFV 方案 (精确整数)
│   │   ├── bfv_context.cpp
│   │   ├── bfv_keygen.cpp
│   │   ├── bfv_encrypt.cpp
│   │   └── bfv_eval.cpp
│   │
│   ├── ckks/                  # CKKS 方案 (近似实数)
│   │   ├── ckks_context.cpp
│   │   ├── ckks_encoder.cpp
│   │   ├── ckks_encrypt.cpp
│   │   └── ckks_rescale.cpp
│   │
│   └── benchmark/             # 性能基准测试
│       ├── bench_bgv.cpp
│       └── bench_vs_seal.cpp
│
├── psi/                       # 隐私集合运算 (自实现)
│   ├── piano_psi.cpp          # 现有 Piano-PSI
│   ├── ot_psi.cpp             # 基于 OT 的 PSI (新增)
│   ├── pir_native.cpp         # 原生 PIR (替代 SEAL-PIR)
│   └── psi_benchmark.cpp
│
├── sss/                       # 秘密共享
│   └── shamir.cpp
│
├── otp/                       # 不经意传输
│   ├── ot_base.cpp
│   └── ot_extension.cpp
│
└── mpc/                       # 安全多方计算 (未来)
    ├── garbled_circuit.cpp
    └── gmw_protocol.cpp
```

### 2.2 头文件设计

```
include/kctsb/advanced/fe/
├── fe_common.h               # 共享类型定义
├── ntt.h                     # NTT 接口
├── rns.h                     # RNS 接口
├── bgv.h                     # BGV 公共 API
├── bfv.h                     # BFV 公共 API
├── ckks.h                    # CKKS 公共 API
└── he_params.h               # 参数选择
```

---

## 3. BGV 方案实现 (Phase 1)

### 3.1 数学基础

**多项式环**: $R_q = \mathbb{Z}_q[X]/(X^n + 1)$

**密文结构**:
$$ct = (c_0, c_1) \in R_q^2$$

**加密**:
$$\text{Encrypt}(m, pk) = (m + e_0 + a \cdot s, a + e_1)$$

**解密**:
$$\text{Decrypt}(ct, sk) = c_0 - c_1 \cdot s \mod t$$

### 3.2 核心数据结构

```cpp
namespace kctsb::fe::bgv {

/**
 * @brief BGV 加密参数
 */
struct BGVParams {
    // 多项式模数度 n (必须是 2 的幂)
    size_t poly_modulus_degree;
    
    // 模数链 (RNS 表示): q = q_0 * q_1 * ... * q_L
    std::vector<uint64_t> coeff_modulus;
    
    // 明文模数 t
    uint64_t plain_modulus;
    
    // 噪声标准差
    double noise_standard_deviation = 3.2;
    
    // 安全级别 (bits)
    size_t security_level = 128;
    
    /**
     * @brief 创建默认 128-bit 安全参数
     */
    static BGVParams Default128(size_t poly_degree);
    
    /**
     * @brief 验证参数有效性
     */
    bool validate() const;
};

/**
 * @brief BGV 密文
 */
class BGVCiphertext {
public:
    // 密文多项式分量 (通常 2 个)
    std::vector<Polynomial> data;
    
    // 当前模数层级 (0 = 最高层)
    size_t level;
    
    // 缩放因子 (BGV 为 1)
    double scale = 1.0;
    
    // 噪声估计 (用于自动参数管理)
    double noise_budget;
    
    /**
     * @brief 获取参数上下文
     */
    const BGVContext& context() const;
    
    /**
     * @brief 检查密文是否可解密
     */
    bool is_valid() const;
};

/**
 * @brief BGV 上下文 (管理参数和预计算表)
 */
class BGVContext {
public:
    explicit BGVContext(const BGVParams& params);
    
    // NTT 预计算表
    const NTTTable& ntt_table() const;
    
    // 参数访问
    const BGVParams& params() const;
    
private:
    BGVParams params_;
    std::unique_ptr<NTTTable> ntt_table_;
    // RNS 基转换表
    std::unique_ptr<RNSBase> rns_base_;
};

/**
 * @brief BGV 密钥生成器
 */
class BGVKeyGenerator {
public:
    explicit BGVKeyGenerator(const BGVContext& context);
    
    // 生成密钥对
    void generate_keys(SecretKey& sk, PublicKey& pk);
    
    // 生成重线性化密钥
    void generate_relin_keys(const SecretKey& sk, RelinKeys& rlk);
    
    // 生成 Galois 旋转密钥
    void generate_galois_keys(const SecretKey& sk, 
                              const std::vector<int>& steps,
                              GaloisKeys& gk);
};

/**
 * @brief BGV 加密器
 */
class BGVEncryptor {
public:
    BGVEncryptor(const BGVContext& context, const PublicKey& pk);
    
    void encrypt(const Plaintext& plain, BGVCiphertext& cipher);
    void encrypt_symmetric(const Plaintext& plain, 
                          const SecretKey& sk,
                          BGVCiphertext& cipher);
};

/**
 * @brief BGV 解密器
 */
class BGVDecryptor {
public:
    BGVDecryptor(const BGVContext& context, const SecretKey& sk);
    
    void decrypt(const BGVCiphertext& cipher, Plaintext& plain);
    
    // 计算剩余噪声预算
    int invariant_noise_budget(const BGVCiphertext& cipher);
};

/**
 * @brief BGV 同态评估器
 */
class BGVEvaluator {
public:
    explicit BGVEvaluator(const BGVContext& context);
    
    // 加法
    void add(const BGVCiphertext& a, const BGVCiphertext& b, 
             BGVCiphertext& result);
    void add_inplace(BGVCiphertext& a, const BGVCiphertext& b);
    void add_plain(const BGVCiphertext& a, const Plaintext& p,
                   BGVCiphertext& result);
    
    // 减法
    void sub(const BGVCiphertext& a, const BGVCiphertext& b,
             BGVCiphertext& result);
    
    // 乘法
    void multiply(const BGVCiphertext& a, const BGVCiphertext& b,
                  BGVCiphertext& result);
    void multiply_inplace(BGVCiphertext& a, const BGVCiphertext& b);
    void multiply_plain(const BGVCiphertext& a, const Plaintext& p,
                        BGVCiphertext& result);
    
    // 重线性化 (乘法后)
    void relinearize(const BGVCiphertext& in, const RelinKeys& rlk,
                     BGVCiphertext& out);
    
    // 模数切换 (降噪)
    void mod_switch_to_next(const BGVCiphertext& in, BGVCiphertext& out);
    void mod_switch_to_inplace(BGVCiphertext& cipher, size_t level);
    
    // Galois 旋转
    void rotate_rows(const BGVCiphertext& in, int steps,
                     const GaloisKeys& gk, BGVCiphertext& out);
    void rotate_columns(const BGVCiphertext& in, 
                        const GaloisKeys& gk, BGVCiphertext& out);
};

}  // namespace kctsb::fe::bgv
```

### 3.3 NTT 优化实现

```cpp
/**
 * @file ntt.h
 * @brief Number Theoretic Transform for polynomial multiplication
 */

namespace kctsb::fe {

/**
 * @brief NTT 预计算表
 */
class NTTTable {
public:
    /**
     * @brief 创建 NTT 表
     * @param n 多项式度 (2 的幂)
     * @param q 模数 (NTT-friendly 素数)
     */
    NTTTable(size_t n, uint64_t q);
    
    // 正向 NTT: 系数形式 → NTT 形式
    void forward(uint64_t* data) const;
    
    // 逆向 NTT: NTT 形式 → 系数形式
    void inverse(uint64_t* data) const;
    
private:
    size_t n_;
    uint64_t q_;
    std::vector<uint64_t> roots_;      // 单位根
    std::vector<uint64_t> inv_roots_;  // 逆单位根
    uint64_t n_inv_;                   // n 的模逆
    
    // AVX2 加速版本
    void forward_avx2(uint64_t* data) const;
    void inverse_avx2(uint64_t* data) const;
};

/**
 * @brief 多项式乘法 (NTT 加速)
 */
void poly_multiply_ntt(const uint64_t* a, const uint64_t* b,
                       uint64_t* result, const NTTTable& ntt);

}  // namespace kctsb::fe
```

---

## 4. PSI/PIR 自实现计划

### 4.1 当前状态

| 组件 | 状态 | 依赖 |
|------|------|------|
| Piano-PSI | ✅ 已实现 | 无外部依赖 |
| SEAL-PIR | ⚠️ 依赖 SEAL | 需替换 |
| OT-PSI | ❌ 未实现 | - |

### 4.2 替换 SEAL-PIR

**目标**: 使用 kctsb BGV 实现原生 PIR

```cpp
namespace kctsb::psi {

/**
 * @brief 原生 PIR 实现 (替代 SEAL-PIR)
 * 
 * 基于 SealPIR 论文: "PIR with Compression" (S&P 2019)
 */
class NativePIR {
public:
    struct Params {
        size_t database_size;    // 数据库条目数
        size_t entry_size;       // 每条目字节数
        size_t dimension;        // 查询维度 (通常 2)
        fe::bgv::BGVParams he_params;  // 同态加密参数
    };
    
    NativePIR(const Params& params);
    
    // 服务器端
    void set_database(const std::vector<std::vector<uint8_t>>& db);
    std::vector<fe::bgv::BGVCiphertext> answer(
        const std::vector<fe::bgv::BGVCiphertext>& query);
    
    // 客户端
    std::vector<fe::bgv::BGVCiphertext> generate_query(
        size_t index, 
        const fe::bgv::PublicKey& pk);
    std::vector<uint8_t> decode_response(
        const std::vector<fe::bgv::BGVCiphertext>& response,
        const fe::bgv::SecretKey& sk);
};

}  // namespace kctsb::psi
```

### 4.3 OT-based PSI

```cpp
namespace kctsb::psi {

/**
 * @brief 基于不经意传输的 PSI
 * 
 * 协议: KKRT16 (CCS 2016)
 */
class OT_PSI {
public:
    struct Result {
        std::vector<size_t> intersection_indices;
        size_t intersection_size;
    };
    
    // 发送方 (拥有集合 X)
    void sender_init(const std::vector<std::vector<uint8_t>>& set_x);
    std::vector<uint8_t> sender_round1();
    void sender_round2(const std::vector<uint8_t>& receiver_msg);
    
    // 接收方 (拥有集合 Y，获取交集)
    void receiver_init(const std::vector<std::vector<uint8_t>>& set_y);
    std::vector<uint8_t> receiver_round1(const std::vector<uint8_t>& sender_msg);
    Result receiver_finalize();
};

}  // namespace kctsb::psi
```

---

## 5. 演进路线图

### Phase 1: BGV 基础 (v4.2.0, 2026 Q1)

- [ ] NTT 核心实现 + AVX2 加速
- [ ] RNS 基转换
- [ ] BGV 加密/解密
- [ ] BGV 加法/乘法
- [ ] 重线性化
- [ ] 单元测试 (NIST 测试向量)
- [ ] Benchmark vs SEAL BGV

### Phase 2: BFV + PIR (v4.3.0, 2026 Q2)

- [ ] BFV 方案实现
- [ ] Native PIR (替代 SEAL-PIR)
- [ ] BatchEncoder (SIMD 批量处理)
- [ ] 性能优化 (目标: SEAL 80%)

### Phase 3: CKKS + PSI (v4.4.0, 2026 Q3)

- [ ] CKKS 编码器
- [ ] CKKS rescale
- [ ] OT-based PSI
- [ ] 完整 PSI/PIR 测试套件

### Phase 4: 生产加固 (v5.0.0, 2026 Q4)

- [ ] 安全审计
- [ ] API 稳定化
- [ ] 文档完善
- [ ] Python 绑定

---

## 6. 性能目标

### 6.1 同态加密性能

| 操作 | SEAL 4.1 | kctsb 目标 | n=8192 |
|------|----------|-----------|--------|
| KeyGen | 50 ms | < 80 ms | 1.6x 差距可接受 |
| Encrypt | 5 ms | < 8 ms | |
| Add | 0.1 ms | < 0.15 ms | |
| Multiply | 10 ms | < 15 ms | |
| Relin | 8 ms | < 12 ms | |

### 6.2 PSI/PIR 性能

| 操作 | SEAL-PIR | kctsb Native | 目标 |
|------|----------|--------------|------|
| Query Gen | 10 ms | < 15 ms | 1.5x |
| Answer | 100 ms | < 150 ms | 1.5x |
| Decode | 5 ms | < 8 ms | |

---

## 7. 示例代码

### 7.1 BGV 基础使用

```cpp
#include "kctsb/advanced/fe/bgv.h"

using namespace kctsb::fe::bgv;

void bgv_example() {
    // 1. 参数设置
    BGVParams params = BGVParams::Default128(8192);
    BGVContext context(params);
    
    // 2. 密钥生成
    BGVKeyGenerator keygen(context);
    SecretKey sk;
    PublicKey pk;
    keygen.generate_keys(sk, pk);
    
    RelinKeys rlk;
    keygen.generate_relin_keys(sk, rlk);
    
    // 3. 加密
    BGVEncryptor encryptor(context, pk);
    BGVDecryptor decryptor(context, sk);
    BGVEvaluator evaluator(context);
    
    Plaintext plain1, plain2;
    // ... 编码数据 ...
    
    BGVCiphertext ct1, ct2;
    encryptor.encrypt(plain1, ct1);
    encryptor.encrypt(plain2, ct2);
    
    // 4. 同态计算: (a + b) * a
    BGVCiphertext sum, product;
    evaluator.add(ct1, ct2, sum);
    evaluator.multiply(sum, ct1, product);
    evaluator.relinearize(product, rlk, product);
    
    // 5. 解密
    Plaintext result;
    decryptor.decrypt(product, result);
}
```

### 7.2 Native PIR 使用

```cpp
#include "kctsb/advanced/psi/pir_native.h"

using namespace kctsb::psi;

void pir_example() {
    // 服务器端设置
    std::vector<std::vector<uint8_t>> database = load_database();
    
    NativePIR::Params params;
    params.database_size = database.size();
    params.entry_size = database[0].size();
    params.dimension = 2;
    params.he_params = fe::bgv::BGVParams::Default128(4096);
    
    NativePIR server(params);
    server.set_database(database);
    
    // 客户端查询
    fe::bgv::BGVContext ctx(params.he_params);
    fe::bgv::BGVKeyGenerator keygen(ctx);
    fe::bgv::SecretKey sk;
    fe::bgv::PublicKey pk;
    keygen.generate_keys(sk, pk);
    
    size_t query_index = 42;
    auto query = server.generate_query(query_index, pk);
    
    // 服务器处理
    auto response = server.answer(query);
    
    // 客户端解码
    auto result = server.decode_response(response, sk);
    // result == database[42]
}
```

---

## 8. 参考实现

### 8.1 Python 示例迁移目标

当前 `docs/examples/` 中的 Python 示例需要迁移为使用 kctsb 原生实现:

| 示例文件 | 当前依赖 | 迁移目标 |
|----------|----------|----------|
| `SecureComputationDemo.py` | HElib | kctsb BGV |
| PSI 目录下的 SEAL 调用 | SEAL | kctsb Native PIR |

### 8.2 测试向量来源

- SEAL 官方测试用例
- HElib 测试向量
- OpenFHE 参考实现

---

*文档结束*
