# CKKS/PSI/PIR 优化计划

> **版本**: v4.14.0 开发计划  
> **日期**: 2026-01-25  
> **状态**: 进行中

## 📋 任务概述

基于用户需求，本次优化包含以下核心任务：

1. **CKKS算法实现与优化** - 迁移到统一RNS实现
2. **PSI/PIR算法实现与优化** - Native PIR, OT-based PSI
3. **性能基准测试** - 与SEAL对比真实数据
4. **路线图检查与后续规划**

---

## 🎯 任务1: CKKS RNS迁移

### 目标
将现有NTL依赖的CKKS实现迁移到纯RNS架构，参考BFV/BGV单文件实现模式。

### 当前状态
- ✅ 创建 `include/kctsb/advanced/fe/ckks/ckks_evaluator.hpp`
- ✅ 创建 `src/advanced/fe/ckks/ckks_evaluator.cpp`
- ✅ 创建 `tests/advanced/fe/ckks/test_ckks_evaluator.cpp`
- 🔄 调试公钥加密逻辑

### 架构设计

```
CKKS RNS Architecture
├── CKKSParams          - 参数配置
├── CKKSPlaintext       - RNS多项式明文
├── CKKSCiphertext      - (c0, c1) 密文对
├── CKKSSecretKey       - 三元分布密钥
├── CKKSPublicKey       - (b, a) 公钥对
├── CKKSRelinKey        - 重线性化密钥
├── CKKSEncoder         - FFT编码/解码
└── CKKSEvaluator       - 同态运算
```

### 关键API
- `encode_real()` / `decode_real()` - 实数向量编码
- `encrypt()` / `decrypt()` - 公钥/对称加密
- `add()` / `sub()` / `multiply()` - 同态运算
- `rescale()` - 缩放因子管理

---

## 🎯 任务2: Native PIR实现

### 目标
替代SEAL-PIR，使用kctsb原生BFV/CKKS实现PIR。

### 设计
- 基于BFV的索引PIR
- 支持批量查询
- 优化通信复杂度

### 文件规划
- `include/kctsb/advanced/psi/native_pir.hpp`
- `src/advanced/psi/native_pir.cpp`
- `tests/advanced/psi/test_native_pir.cpp`

---

## 🎯 任务3: OT-based PSI

### 目标
实现基于Oblivious Transfer的PSI协议。

### 设计
- 1-out-of-2 OT基础构建
- OT扩展优化
- PSI协议集成

### 文件规划
- `include/kctsb/advanced/psi/ot_psi.hpp`
- `src/advanced/psi/ot_psi.cpp`
- `tests/advanced/psi/test_ot_psi.cpp`

---

## 🎯 任务4: 性能基准测试

### 目标
对比kctsb与SEAL的FHE性能。

### 测试项目
| 测试项 | BFV | BGV | CKKS |
|--------|-----|-----|------|
| 加密   | ✅  | ✅  | 🔄   |
| 解密   | ✅  | ✅  | 🔄   |
| 加法   | ✅  | ✅  | 🔄   |
| 乘法   | ✅  | ✅  | 🔄   |

---

## 📊 进度跟踪

| 任务 | 状态 | 完成度 |
|------|------|--------|
| CKKS头文件 | ✅ | 100% |
| CKKS实现 | 🔄 | 80% |
| CKKS测试 | 🔄 | 70% |
| Native PIR | ⏳ | 0% |
| OT-based PSI | ⏳ | 0% |
| Benchmark | ⏳ | 0% |

---

## 🐛 当前问题

### 问题1: 公钥加密解密结果错误
- **现象**: 对称加密通过，公钥加密失败
- **期望值**: 3.14，实际值: ~10000
- **分析中**: 可能是NTT状态或运算顺序问题

### 调试记录
```
对称加密: c0 = -a*s + e + m, c1 = a  ✓
公钥加密: c0 = b*u + e0 + m, c1 = a*u + e1  ✗
其中 b = -a*s + e
```

---

## 📅 后续计划

1. 修复CKKS公钥加密问题
2. 完成CKKS乘法和rescale
3. 实现Native PIR
4. 实现OT-based PSI
5. 运行完整benchmark
6. 更新性能文档
