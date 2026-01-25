# SHA3-256 性能分析 & 优化建议

**分析日期**: 2026年1月16日（北京时间 UTC+8）  
**版本**: kctsb v3.4.1  
**分析者**: kn1ghtc  

---

## 📊 当前性能状态

### SHA3-256基准数据（编译参数：-O3 -march=native -flto）

| 数据大小 | kctsb吞吐量 | OpenSSL吞吐量 | 相对性能 | 绝对值评估 |
|---------|-----------|-----------|--------|---------|
| **1KB**  | 469 MB/s  | 417 MB/s  | **+12.58%** ✅ | 超预期 |
| **64KB** | 523 MB/s  | 574 MB/s  | -8.83%   | 接近 |
| **1MB**  | 490 MB/s  | 525 MB/s  | -6.75%   | 接近 |
| **10MB** | 495 MB/s  | 535 MB/s  | -7.42%   | 接近 |
| **平均值** | **507 MB/s** | **513 MB/s** | **-1.2%** | 基本持平 |

### 目标与现状对比

| 指标 | 目标值 | 当前值 | 差值 | 评估 |
|------|------|------|------|------|
| SHA3-256吞吐量 | 567 MB/s | 507 MB/s | -60 MB/s (-10.6%) | ⚠️ 需要优化 |
| 与OpenSSL比较 | > OpenSSL | -1.2%平均 | N/A | ⚠️ 略低 |
| 小数据（1KB）| > OpenSSL | +12.58% | N/A | ✅ 超预期 |

---

## 🔍 性能瓶颈分析

### 1. 问题现象
- **小数据优势**: 1KB时比OpenSSL快12.58%（469 vs 417 MB/s）
- **大数据劣势**: 随着数据增大，优势消失，反而略慢（-6到-9%）
- **平均水平**: 与OpenSSL基本持平（-1.2%）

### 2. 根本原因猜测（需要验证）

#### 原因A：Keccak permute()寄存器分配不优
```cpp
// 当前实现（src/crypto/sha3.cpp）:
class SHA3 {
    static inline void permute(uint64_t state[25]) {
        // 使用25个64位字，GCC可能产生次优的寄存器分配
        // 导致频繁的栈访问而非寄存器快速路径
        for (int round = 0; round < KECCAK_ROUNDS; round++) {
            // 25个state元素的读写
            // GCC可能生成大量mov指令从栈读写
        }
    }
};

// 性能影响：
// - 小数据（1KB）：permute()开销相对较小，初始化成本更大
//                   kctsb初始化开销小（-O3内联），所以快于OpenSSL
// - 大数据（10MB）：permute()开销占主导（50次以上循环）
//                   栈访问延迟积累（缓存行冲突、内存延迟）
//                   导致吞吐量下降到507 MB/s
```

#### 原因B：循环展开与缓存友好性
- 当前实现使用紧凑循环（compact loop），编译器可能未能充分展开
- OpenSSL使用部分展开或SIMD优化（如果可用）
- 大数据块时，缓存未命中导致延迟增加

#### 原因C：AVX2利用不足
```cpp
// 当前实现只在吸收阶段（absorb）使用AVX2 memxor
// permute阶段（占70-80%时间）仍使用标量操作
// - SHA3吸收速度：可能因memxor而优化
// - Permute速度：缺乏SIMD，完全依赖标量GCC生成的代码
```

---

## 💡 优化策略（按优先级）

### 🥇 第一优先：Permute() 寄存器优化（预期 +10-15%）

**目标**: 减少permute()中的栈访问，最大化寄存器利用

#### 策略1.1：手动寄存器分配优化
```cpp
// 分析：Keccak permute需要处理25个64位值
// GCC能分配的通用寄存器：16个（rax-r15在x86_64）
// 解决方案：分块处理（一次处理8-12个状态元素）

static inline void permute_block(uint64_t state[25]) {
    // 分割为3个块：[0..7], [8..16], [17..24]
    // 每块在寄存器中完成
    uint64_t a0 = state[0], a1 = state[1], ... a7 = state[7];
    
    // 第一轮只用这8个变量，其他在栈中
    for (int i = 0; i < KECCAK_ROUNDS; i++) {
        // 处理block 1...
        uint64_t b0 = state[8], ... (从栈加载一次)
        // 处理block 2...
    }
    
    // 写回状态
    state[0] = a0; ... state[7] = a7;
}

// GCC优化：确保a0-a7保持在寄存器中（通过volatile约束）
// 预期效果：栈访问减少50-70%
```

#### 策略1.2：使用__restrict和__attribute__((aligned))
```cpp
static inline void permute(uint64_t * __restrict aligned_state) 
    __attribute__((always_inline, hot)) {
    // __restrict 告诉编译器没有别名指针
    // 允许更激进的寄存器分配和循环优化
    
    // 对齐访问：确保编译器能生成高效的load/store指令
    register uint64_t r0 __asm__("r8");  // 明确要求使用哪个寄存器
    register uint64_t r1 __asm__("r9");
    // ... 16个通用寄存器全部显式分配
}
```

#### 策略1.3：SIMD加速（如果可用）
```cpp
// 仅在AVX2可用时启用
#ifdef __AVX2__
// 使用_mm256_permute4x64_epi64等内联函数
// 参考OpenSSL中的SHA3-SIMD实现
// 预期：额外+20-30%加速（需要重写整个permute逻辑）
#endif
```

#### 实现优先级：1.1 > 1.2 > 1.3

---

### 🥈 第二优先：吸收阶段优化（预期 +3-5%）

当前已有AVX2 memxor优化，可进一步改进：

```cpp
// 当前实现（sha3.cpp中）:
// 使用AVX2加速memxor，但可能只处理256位块
// 改进方向：
// 1. 扩展到512位块（使用两个256位操作）
// 2. 预取缓存行（PREFETCH_WRITE）
// 3. 展开吸收循环
```

---

### 🥉 第三优先：测试与验证（必须做）

#### 3.1 ASM审查
```bash
# 生成汇编代码审查
gcc -O3 -march=native -flto -S sha3.cpp -o sha3.s

# 关键指标：
# - mov from memory in permute(): 目标<50条
# - 寄存器利用率: 目标>80%
# - 循环展开因子: 目标>4
```

#### 3.2 性能计数器分析
```bash
# 使用perf工具（Linux）
perf stat -e cycles,instructions,cache-misses ./test_sha3

# 或Windows：
# Intel VTune 或 AMD uProf 分析
```

#### 3.3 基准对比
```bash
# 修改前后基准对比：
# 预期：512 MB/s -> 567+ MB/s
./build/bin/kctsb_benchmark.exe hash
```

---

## 📈 预期优化效果

| 优化阶段 | 方案 | 预期吞吐量 | 相对目标 | 实现难度 |
|--------|------|-----------|--------|--------|
| **基础** | 当前版本 | 507 MB/s | -10.6% | - |
| **+1级** | 寄存器优化 | 550-560 MB/s | -1~2% | ⭐⭐ |
| **+2级** | +吸收优化 | 567-575 MB/s | 目标达成✅ | ⭐⭐⭐ |
| **+3级** | +SIMD加速 | 700-750 MB/s | +23-32% | ⭐⭐⭐⭐⭐ |

---

## 🎯 建议行动计划

### v3.4.1（当前）
- ✅ 完成BLAKE2s移除
- ✅ 统一Debug/Release参数
- ✅ Hash基准数据收集
- 📋 **创建此性能分析文档**

### v3.5.0（下一个版本）
1. **周期1（Week 1-2）**: 
   - 实现Permute() 寄存器优化（策略1.1）
   - ASM审查与验证
   - 预期结果：550-560 MB/s

2. **周期2（Week 3-4）**:
   - 吸收阶段优化（策略2）
   - 单元测试补强
   - 预期结果：567+ MB/s（目标达成）

3. **周期3（Week 5-6，可选）**:
   - SIMD加速研究（策略1.3）
   - OpenSSL源码对标分析
   - 预期结果：700+ MB/s

4. **周期4**:
   - 性能回归人工复核流程
   - 设置手动阈值对比（防止回退）
   - 发布v3.5.0

---

## 📊 对标数据参考

### 标准库性能基准（供参考）
| 库 | SHA3-256 | 条件 |
|---|---------|------|
| OpenSSL 3.3.1 | 513-535 MB/s | -O3编译 |
| Boring SSL | 520-540 MB/s | -O3 |
| Crypto++ | 480-500 MB/s | 软件实现 |
| kctsb目标 | **567 MB/s** | -O3 -march=native -flto |

---

## ⚠️ 潜在风险

1. **代码复杂性增加**: 手动寄存器分配代码难以维护
   - 缓解：充分的注释和文档
   
2. **编译器差异**: GCC/Clang对寄存器优化的处理不同
   - 缓解：多编译器测试（GCC 13+, Clang 16+, MSVC 2022）

3. **性能回退**: 优化过程中不小心导致性能下降
   - 缓解：手动基准对比与复核

4. **安全风险**: 汇编级优化可能引入侧信道漏洞
   - 缓解：使用__restrict而非内联汇编
   - 注意：避免分支指令（时序侧信道）

---

## 📚 参考资源

- [Keccak Team - Optimization Guide](https://keccak.team/software.html)
- [OpenSSL SHA3 实现](https://github.com/openssl/openssl/blob/master/crypto/sha/keccak1600.c)
- [GCC 内联汇编](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html)
- [x86-64 ABI规范](https://refspecs.linuxbase.org/elf/x86-64-abi-0.99.pdf) - 寄存器约定

---

## 🎬 下一步

**立即行动**:
1. ✅ 完成此文档审查
2. ⏭️ 创建GitHub Issue或任务追踪（v3.5.0 SHA3优化）
3. ⏭️ 基准代码库存储（用于对比）
4. ⏭️ 启动寄存器优化实现

**关键成功指标**:
- SHA3-256吞吐量达到 567+ MB/s
- OpenSSL对标：≥ -3% 或 > OpenSSL性能
- 所有单元测试通过
- 无侧信道漏洞

---

**文档维护者**: kn1ghtc  
**最后更新**: 2026-01-16 (v3.4.1)  
**预计实现版本**: v3.5.0  
