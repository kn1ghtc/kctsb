# FHE 实现问题总结与经验

> **项目**: kctsb - Fully Homomorphic Encryption Module  
> **版本**: v4.13.0  
> **更新时间**: 2026-01-25 (Beijing Time, UTC+8)  
> **分类**: troubleshooting/fhe

---

## 1. BGV/BFV 实现问题总结

### 1.1 __int128 溢出问题 (已解决)

**问题描述**:
- 当 FHE 参数较大时 (n=8192, L=3, 50-bit primes)，Q = ∏qi ≈ 150 bits 超过 `__int128` 最大值 (127 bits)
- 导致 `scale_plaintext()` 中 delta = floor(Q/t) 计算溢出
- 所有使用大参数集的测试失败

**根本原因**:
```cpp
// 错误代码
__int128 Q = 1;
for (auto qi : moduli) {
    Q *= qi;  // 溢出！Q > 2^127
}
__int128 delta = Q / plaintext_modulus;
```

**解决方案** (v4.13.0):
```cpp
// 使用多精度算术
std::vector<uint64_t> Q_multiprecision;
// 实现多精度乘法、除法
// 使用 Horner 方法进行模约简
```

**经验教训**:
- ✅ 密码学实现必须考虑大数运算边界
- ✅ 使用 `__int128` 前需验证数值范围
- ✅ 对于 Q > 2^127 场景，必须使用多精度库（GMP 或自实现）
- ⚠️ 生产环境推荐直接使用 GMP/NTL 大数类型

**影响范围**:
- BGV Evaluator V2
- BFV Evaluator
- CKKS Rescale 操作

**测试验证**:
```bash
# 验证修复
ctest -R "BGV.*N8192" --output-on-failure
ctest -R "BFV.*N8192" --output-on-failure
```

---

### 1.2 CRT 重建精度问题

**问题描述**:
- 使用 `__int128` 进行 CRT 重建时，中间结果可能溢出
- 导致解密结果错误或噪声预算计算不准确

**解决方案**:
```cpp
// 正确的 CRT 重建
__int128 reconstruct_crt(const std::vector<uint64_t>& residues, 
                         const std::vector<uint64_t>& moduli) {
    __int128 result = 0;
    __int128 Q = compute_Q_multiprecision(moduli);
    
    for (size_t i = 0; i < moduli.size(); i++) {
        __int128 qi_inv = Q / moduli[i];
        __int128 qi_inv_mod = modinv(qi_inv % moduli[i], moduli[i]);
        result += residues[i] * qi_inv * qi_inv_mod;
        result %= Q;
    }
    return result;
}
```

**经验教训**:
- ✅ CRT 重建需要 Q 的精确计算
- ✅ 模逆运算必须在正确的模下进行
- ⚠️ 中间结果需要及时取模避免溢出

---

### 1.3 NTT Transform Domain 一致性

**问题描述**:
- 密钥和密文必须在同一 domain（NTT 或 Coefficient）
- 不一致会导致解密失败或运算错误

**正确实践**:
```cpp
// BGV/BFV 实现约定
// 1. 密钥生成后立即转换到 NTT domain
// 2. 密文加密后保持在 Coefficient domain
// 3. 运算前统一转换到 NTT domain
// 4. 解密前统一转换回 Coefficient domain

class BGVEvaluatorV2 {
    // 所有密钥存储在 NTT domain
    RNSPoly secret_key_ntt_;
    RNSPoly public_key_ntt_;
    
    // 运算时自动处理转换
    void multiply(Ciphertext& c1, const Ciphertext& c2) {
        c1.transform_to_ntt();
        c2.transform_to_ntt();
        // ... 运算 ...
    }
};
```

**经验教训**:
- ✅ 明确定义每个数据结构的 domain
- ✅ 在函数文档中标注 domain 要求
- ✅ 添加运行时 domain 检查（Debug 模式）

---

## 2. CKKS 实现问题总结

### 2.1 Rescale 精度控制

**问题描述**:
- CKKS 使用近似计算，rescale 操作会损失精度
- 多层乘法后精度累积误差导致结果不可用

**解决方案**:
```cpp
// 正确的 rescale 实现
void rescale(Ciphertext& ct) {
    // 1. 除以最后一个模数
    RNSPoly::drop_last_modulus(ct.c0);
    RNSPoly::drop_last_modulus(ct.c1);
    
    // 2. 更新 scale
    ct.scale = ct.scale / last_modulus;
    
    // 3. 检查精度
    if (ct.scale < min_scale_threshold) {
        throw std::runtime_error("Precision too low");
    }
}
```

**经验教训**:
- ✅ 控制初始 scale (建议 2^40)
- ✅ 限制乘法深度（3-5 层）
- ✅ 使用足够大的模数链（L ≥ depth + 2）

---

### 2.2 FFT 编码复数支持

**问题描述**:
- CKKS 需要复数向量编码
- FFT 实现需要处理复数槽位

**解决方案**:
```cpp
// 复数编码实现
void encode_complex(const std::vector<std::complex<double>>& values,
                   RNSPoly& poly, double scale) {
    size_t n = poly.degree();
    std::vector<std::complex<double>> fft_input(n);
    
    // 正则嵌入
    for (size_t i = 0; i < values.size(); i++) {
        fft_input[i] = values[i];
    }
    
    // 逆 FFT
    inverse_fft(fft_input);
    
    // 缩放和舍入到整数多项式
    for (size_t i = 0; i < n; i++) {
        poly.coeffs[i] = round(fft_input[i].real() * scale);
    }
}
```

**经验教训**:
- ✅ 使用高精度 FFT 库
- ✅ 控制舍入误差
- ✅ 验证编码/解码往返精度

---

## 3. 性能优化问题总结

### 3.1 NTT 优化

**Harvey NTT 实现要点**:
```cpp
// 正确的 Gentleman-Sande 逆 NTT
void inverse_ntt_harvey(uint64_t* a, size_t n, uint64_t q) {
    size_t t = 1;
    for (size_t m = n; m > 1; m >>= 1) {
        size_t j1 = 0;
        size_t h = m >> 1;
        for (size_t i = 0; i < h; i++) {
            uint64_t W = psi_inv_table[h + i];
            for (size_t j = j1; j < j1 + t; j++) {
                uint64_t U = a[j];
                uint64_t V = a[j + t];
                a[j] = U + V;
                a[j + t] = multiply_uint_mod((U + 2*q - V), W, q);
            }
            j1 += (t << 1);
        }
        t <<= 1;
    }
    
    // 最后乘以 n_inv
    uint64_t n_inv = modinv(n, q);
    for (size_t i = 0; i < n; i++) {
        a[i] = multiply_uint_mod(a[i], n_inv, q);
    }
}
```

**经验教训**:
- ✅ 使用 Lazy Reduction（减少取模次数）
- ✅ 预计算 twiddle factors
- ✅ AVX-512 IFMA 加速（Ice Lake+）

---

### 3.2 内存优化

**问题**: RNS 多项式内存占用大

**解决方案**:
```cpp
// 使用对齐内存
alignas(64) uint64_t coeffs[n * L];

// 批量操作减少内存分配
void batch_multiply(std::vector<Ciphertext>& cts) {
    // 预分配临时内存
    RNSPoly temp1, temp2;
    for (auto& ct : cts) {
        // 复用 temp1, temp2
    }
}
```

---

## 4. 已知限制与未来工作

### 4.1 当前限制

| 限制项 | 描述 | 影响 |
|--------|------|------|
| 模数链长度 | L ≤ 12 (n=32768) | 限制乘法深度 |
| 多精度运算 | 依赖 GMP/NTL | 无法完全移除外部依赖 |
| SIMD 加速 | 仅支持 x86_64 | ARM 性能未优化 |

### 4.2 未来优化方向

- [ ] GPU 加速（CUDA NTT）
- [ ] ARM NEON 优化
- [ ] Intel HEXL 集成
- [ ] Bootstrap 实现（BFV/CKKS）

---

## 5. 调试技巧

### 5.1 噪声预算追踪

```cpp
// 添加调试输出
void decrypt_and_check_noise(const Ciphertext& ct) {
    auto pt = decrypt(ct);
    int noise = estimate_noise_budget(ct);
    std::cout << "Noise budget: " << noise << " bits" << std::endl;
    if (noise < 20) {
        std::cerr << "Warning: Low noise budget!" << std::endl;
    }
}
```

### 5.2 参数验证

```cpp
// 参数合法性检查
bool validate_params(size_t n, size_t L, const std::vector<int>& qi_bits) {
    // 检查 n 是否是 2 的幂
    if ((n & (n - 1)) != 0) return false;
    
    // 检查模数链长度
    if (L > 12) return false;
    
    // 检查每个模数位数
    for (auto bits : qi_bits) {
        if (bits < 30 || bits > 60) return false;
    }
    
    return true;
}
```

---

## 6. 参考资料

- [SEAL Documentation](https://github.com/microsoft/SEAL)
- [HElib Wiki](https://github.com/homenc/HElib/wiki)
- [BEHZ Paper: A Full RNS Variant of FV](https://eprint.iacr.org/2016/510)
- [Harvey NTT: Fast Fourier Transform in Rings](https://arxiv.org/abs/1404.3160)

---

*最后更新: 2026-01-25 | kctsb v4.13.0*
