# CKKS NTT 素数验证问题

## 问题描述

CKKS 公钥加密在大参数 (n=1024) 时产生巨大误差 (~5e11)，但小参数 (n=16, BFV) 工作正常。

## 症状

1. `DebugPublicKeyEncryptStep` 测试中 `(-e) * u` 产生 5.49e+11 的误差（预期 ~100）
2. `DebugNTTMultiplicationSemantics` 测试显示 1023/1024 个系数不匹配
3. Fermat 测试失败：`2^{q-1} mod q = 844098482301` 而不是 1

## 诊断过程

### 1. 验证 Barrett Reduction

创建独立测试验证 Barrett reduction 正确性：
```cpp
// 测试结果：Barrett reduction 本身工作正常
// 5*5 mod q = 25 ✓
// 10^12 * 10^12 mod q = 正确 ✓
```

### 2. 验证模幂运算

```cpp
// pow_mod 对小指数工作正常
// 2^10 mod q = 1024 ✓
// 2^40 mod q = 65535 ✓
```

### 3. 验证 NTT 友好性

```cpp
// (q-1) % 2n = 0 对所有"素数"都成立
// 表明它们满足 NTT 友好条件
```

### 4. Miller-Rabin 素数测试 ⚠️ 关键发现

```cpp
// 测试结果：
// Prime 0: q = 1099511562241 - NOT PRIME!
// Prime 1: q = 1099511480321 - IS PRIME ✓
// Prime 2: q = 1099511218177 - NOT PRIME!
```

### 5. 因数分解确认

```
1099511562241 = 31 × 163 × 217595797
1099511218177 = 17 × 19 × 3404059499
```

## 根本原因

测试代码中硬编码的"素数"实际上是合数（composite numbers）！

由于 Fermat 小定理只对素数成立（`a^{p-1} ≡ 1 mod p`），使用合数作为模数会导致：
1. NTT 原根计算错误（`root^{2n} ≠ 1`）
2. NTT 变换结果错误
3. 多项式乘法结果错误
4. 所有依赖 NTT 的加密操作失败

## 解决方案

### 生成正确的 NTT 友好素数

使用 Miller-Rabin 测试验证素数，确保 `q = k×2n + 1` 形式：

```cpp
// 生成的正确 40-bit 素数 (n=1024):
std::vector<uint64_t> primes = {
    549755860993ULL,  // k=268435479
    549755873281ULL,  // k=268435485
    549755904001ULL   // k=268435500
};
```

### 验证方法

1. **Miller-Rabin 测试** - 使用多个见证值 (2,3,5,7,11,13,17,19,23,29,31,37)
2. **Fermat 测试** - `2^{q-1} mod q = 1`
3. **原根验证** - `root^n = q-1 = -1 mod q`

## 修复的文件

- `tests/advanced/fe/ckks/test_ckks_evaluator.cpp` - 更新 `SetUp()` 中的素数
- `src/advanced/fe/common/ntt_harvey.cpp` - 删除调试 fprintf 语句

## 预防措施

1. **始终验证素数** - 使用 Miller-Rabin 或类似的素数测试
2. **添加素数验证** - 在 `Modulus` 类构造函数中添加可选的素数验证
3. **使用 SEAL 的素数生成器** - 参考 `CoeffModulus::Create()` 实现

## 相关测试

修复后所有 364 个测试通过：
- `CKKSEvaluatorTest.DebugNTTRootOrder` - 验证 root^{2n}=1, root^n=-1
- `CKKSEvaluatorTest.DebugNTTMultiplicationSemantics` - 0/1024 不匹配
- `CKKSEvaluatorTest.DebugPublicKeyEncryptStep` - max_error ~11

## 参考

- SEAL 源码: `deps/SEAL/native/src/seal/modulus.cpp` - `is_prime()` 实现
- SEAL 源码: `deps/SEAL/native/src/seal/util/ntt.cpp` - 素数选择
- Miller-Rabin 测试: 使用 12 个见证值提供高可靠性

## 日期

2025-01-08 (UTC+8)
