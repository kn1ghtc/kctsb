# BLAKE2b AVX2优化深度研究

**研究日期**: 2026-01-16  
**目标**: 将kctsb的BLAKE2b性能从914 MB/s提升到>1913 MB/s (2倍+)  
**参考实现**: sneves/blake2-avx2 (官方AVX2版本)

---

## 📊 性能对比数据

### 官方实现性能 (Samuel Neves)
- **BLAKE2b AVX2**: ~900-920 MB/s (单核, Intel i5-8250U)
- **minio/blake2b-simd AVX2**: ~918 MB/s (3.94x vs Go纯实现)
- **oconnor663/blake2_simd AVX2**: 2.81 cpb (Rust实现)

### kctsb当前性能
- **BLAKE2b (portable)**: 914 MB/s
- **目标性能**: >1913 MB/s (需突破2倍性能瓶颈)

---

## 🔬 核心技术原理

### 1. 4-Way并行压缩策略

BLAKE2b使用64位整数运算，AVX2的256位YMM寄存器可同时处理4个64位值：

```c
/* AVX2: 4个操作并行 */
VPADDQ  YMM0, YMM0, YMM1   // v0+=v4, v1+=v5, v2+=v6, v3+=v7 (同时执行)

/* 标量版本: 串行执行 */
v0 += v4;
v1 += v5;
v2 += v6;
v3 += v7;
```

**关键洞察**: AVX2通过向量化将4个独立的64位加法操作合并为1条指令，理论加速比4x。

---

## 🛠️ G函数向量化实现

### G函数原始定义 (BLAKE2规范)
```c
#define G(r,i,a,b,c,d) do {                \
    a = a + b + m[sigma[r][2*i+0]];       \
    d = rotr64(d ^ a, 32);                \
    c = c + d;                            \
    b = rotr64(b ^ c, 24);                \
    a = a + b + m[sigma[r][2*i+1]];       \
    d = rotr64(d ^ a, 16);                \
    c = c + d;                            \
    b = rotr64(b ^ c, 63);                \
} while(0)
```

### AVX2向量化G函数 (sneves实现)

#### 关键Intrinsics映射
| 操作 | 标量实现 | AVX2 Intrinsic | 说明 |
|------|---------|----------------|------|
| **64位加法** | `a += b` | `_mm256_add_epi64(a, b)` | 4-way并行加法 |
| **XOR** | `d ^= a` | `_mm256_xor_si256(d, a)` | 4-way并行异或 |
| **旋转32位** | `rotr64(x, 32)` | `_mm256_shuffle_epi32(x, _MM_SHUFFLE(2,3,0,1))` | 使用shuffle替代移位 |
| **旋转24位** | `rotr64(x, 24)` | `_mm256_or_si256(_mm256_srli_epi64(x, 24), _mm256_slli_epi64(x, 40))` | 组合移位 |
| **旋转16位** | `rotr64(x, 16)` | `_mm256_shuffle_epi8(x, rot16_mask)` | 使用vpshufb |
| **旋转63位** | `rotr64(x, 63)` | `_mm256_or_si256(_mm256_srli_epi64(x, 63), _mm256_add_epi64(x, x))` | 优化为移位+加法 |

#### 优化版G1宏 (基于sneves/blake2-avx2)
```c
#define G1_AVX2(a, b, c, d, m0, m1) do {                          \
    a = _mm256_add_epi64(_mm256_add_epi64(a, m0), b);            \
    d = _mm256_xor_si256(d, a);                                   \
    d = _mm256_shuffle_epi32(d, _MM_SHUFFLE(2,3,0,1));  /* rotr32 */ \
    c = _mm256_add_epi64(c, d);                                   \
    b = _mm256_xor_si256(b, c);                                   \
    b = _mm256_or_si256(_mm256_srli_epi64(b, 24),                \
                        _mm256_slli_epi64(b, 40));      /* rotr24 */ \
} while(0)

#define G2_AVX2(a, b, c, d, m0, m1) do {                          \
    a = _mm256_add_epi64(_mm256_add_epi64(a, m1), b);            \
    d = _mm256_xor_si256(d, a);                                   \
    d = _mm256_shuffle_epi8(d, rot16_mask);             /* rotr16 */ \
    c = _mm256_add_epi64(c, d);                                   \
    b = _mm256_xor_si256(b, c);                                   \
    b = _mm256_xor_si256(_mm256_srli_epi64(b, 63),               \
                         _mm256_add_epi64(b, b));       /* rotr63 */ \
} while(0)
```

---

## 🔄 消息调度 (Message Schedule) SIMD适配

### 挑战: Sigma排列的内存访问模式
BLAKE2b的消息调度使用12轮不同的sigma排列，标量版本需要随机访问`m[0..15]`。

### AVX2解决方案: 预计算排列宏

#### 方案1: 使用_mm256_blend_epi32 (sneves首选)
```c
/* Round 0: m[0], m[1], m[2], m[3] */
#define BLAKE2B_LOAD_MSG_0_1(b0) do {                             \
    __m256i t0 = _mm256_unpacklo_epi64(m0, m1);                  \
    __m256i t1 = _mm256_unpacklo_epi64(m2, m3);                  \
    b0 = _mm256_blend_epi32(t0, t1, 0xF0);                       \
} while(0)

#define BLAKE2B_LOAD_MSG_0_2(b0) do {                             \
    __m256i t0 = _mm256_unpackhi_epi64(m0, m1);                  \
    __m256i t1 = _mm256_unpackhi_epi64(m2, m3);                  \
    b0 = _mm256_blend_epi32(t0, t1, 0xF0);                       \
} while(0)
```

**优势**: 
- `_mm256_blend_epi32` 延迟1周期，吞吐量0.33 (Haswell+)
- 避免内存随机访问，全部在寄存器内完成

#### 方案2: 使用_mm256_permute2x128_si256 (blake2bp)
```c
#define BLAKE2B_PACK_MSG_V4(w, m) do {                            \
    __m256i t0 = _mm256_unpacklo_epi64(m[0], m[4]);              \
    __m256i t1 = _mm256_unpackhi_epi64(m[0], m[4]);              \
    __m256i t2 = _mm256_unpacklo_epi64(m[8], m[12]);             \
    __m256i t3 = _mm256_unpackhi_epi64(m[8], m[12]);             \
    w[0] = _mm256_permute2x128_si256(t0, t2, 0x20);              \
    w[2] = _mm256_permute2x128_si256(t0, t2, 0x31);              \
    w[1] = _mm256_permute2x128_si256(t1, t3, 0x20);              \
    w[3] = _mm256_permute2x128_si256(t1, t3, 0x31);              \
} while(0)
```

**优势**: 适用于BLAKE2bp (4-way并行哈希)，减少内存带宽需求。

---

## 🎯 DIAGONALIZE/UNDIAGONALIZE优化

### 问题: 对角化操作的跨通道依赖
BLAKE2b压缩函数需要在列混合和对角混合之间切换状态布局。

### AVX2优化策略
```c
/* DIAGONALIZE: 调整通道布局 */
#define DIAGONALIZE_AVX2(a, b, c, d) do {                         \
    __m256i t0 = _mm256_alignr_epi8(b, b, 8);                    \
    __m256i t1 = _mm256_alignr_epi8(d, d, 8);                    \
    b = _mm256_permute4x64_epi64(t0, _MM_SHUFFLE(2,1,0,3));      \
    c = _mm256_permute4x64_epi64(c, _MM_SHUFFLE(1,0,3,2));       \
    d = _mm256_permute4x64_epi64(t1, _MM_SHUFFLE(0,3,2,1));      \
} while(0)

/* UNDIAGONALIZE: 恢复原布局 */
#define UNDIAGONALIZE_AVX2(a, b, c, d) do {                       \
    __m256i t0 = _mm256_alignr_epi8(b, b, 8);                    \
    __m256i t1 = _mm256_alignr_epi8(d, d, 8);                    \
    b = _mm256_permute4x64_epi64(t0, _MM_SHUFFLE(0,3,2,1));      \
    c = _mm256_permute4x64_epi64(c, _MM_SHUFFLE(1,0,3,2));       \
    d = _mm256_permute4x64_epi64(t1, _MM_SHUFFLE(2,1,0,3));      \
} while(0)
```

**关键**: 
- `_mm256_permute4x64_epi64` 是AVX2新增指令 (AVX中不可用)
- `_mm256_alignr_epi8` 提供字节级通道内旋转

---

## 🚀 达到1800+ MB/s的关键技术

### 1. 消息预加载 (Message Pre-loading)
```c
/* 将16个64位消息字广播到YMM寄存器 */
const __m256i m0 = _mm256_broadcastsi128_si256(LOADU128(input +   0));
const __m256i m1 = _mm256_broadcastsi128_si256(LOADU128(input +  16));
const __m256i m2 = _mm256_broadcastsi128_si256(LOADU128(input +  32));
const __m256i m3 = _mm256_broadcastsi128_si256(LOADU128(input +  48));
const __m256i m4 = _mm256_broadcastsi128_si256(LOADU128(input +  64));
const __m256i m5 = _mm256_broadcastsi128_si256(LOADU128(input +  80));
const __m256i m6 = _mm256_broadcastsi128_si256(LOADU128(input +  96));
const __m256i m7 = _mm256_broadcastsi128_si256(LOADU128(input + 112));
```

**优势**: 一次性加载所有消息字，避免12轮中重复内存访问。

### 2. 循环展开 (Loop Unrolling)
```c
/* 完全展开12轮压缩 */
ROUND_AVX2(0);
ROUND_AVX2(1);
ROUND_AVX2(2);
ROUND_AVX2(3);
ROUND_AVX2(4);
ROUND_AVX2(5);
ROUND_AVX2(6);
ROUND_AVX2(7);
ROUND_AVX2(8);
ROUND_AVX2(9);
ROUND_AVX2(10);
ROUND_AVX2(11);
```

**优势**: 消除分支预测开销，允许CPU指令流水线优化。

### 3. 寄存器压力管理
- **使用YMM0-YMM15** (16个寄存器): 状态向量(4) + 消息字(8) + 临时(4)
- **避免寄存器溢出**: 通过精心设计宏，减少临时变量

### 4. 内存对齐
```c
ALIGN(64) static const uint64_t blake2b_IV[8] = { ... };

/* 使用对齐加载 */
#define LOADU128(p) _mm_loadu_si128((const __m128i *)(p))
#define STOREU128(p, r) _mm_storeu_si128((__m128i *)(p), r)
```

**关键**: 对齐访问减少cache miss，但BLAKE2消息字通常未对齐，需用`_mm_loadu_si128`。

---

## 📐 完整压缩函数框架

```c
static inline void blake2b_compress_avx2(
    blake2b_state *S,
    const uint8_t block[BLAKE2B_BLOCKBYTES])
{
    /* 1. 加载状态向量 */
    __m256i a = _mm256_loadu_si256((__m256i *)&S->h[0]);
    __m256i b = _mm256_loadu_si256((__m256i *)&S->h[4]);
    __m256i c = _mm256_set_epi64x(IV3, IV2, IV1, IV0);
    __m256i d = _mm256_set_epi64x(
        S->t[1] ^ IV7, S->t[0] ^ IV6, S->f[1] ^ IV5, S->f[0] ^ IV4);

    /* 2. 预加载消息字 */
    const __m256i m0 = _mm256_broadcastsi128_si256(LOADU128(block +   0));
    const __m256i m1 = _mm256_broadcastsi128_si256(LOADU128(block +  16));
    // ... m2-m7 ...

    /* 3. 定义旋转掩码 */
    const __m256i rot16_mask = _mm256_set_epi8(
        9,8,11,10,13,12,15,14, 1,0,3,2,5,4,7,6,
        9,8,11,10,13,12,15,14, 1,0,3,2,5,4,7,6);

    /* 4. 执行12轮压缩 (完全展开) */
    __m256i b0, b1;
    
    /* Round 0 */
    BLAKE2B_LOAD_MSG_0_1(b0);
    BLAKE2B_LOAD_MSG_0_2(b1);
    G1_AVX2(a, b, c, d, b0, b1);
    BLAKE2B_LOAD_MSG_0_3(b0);
    BLAKE2B_LOAD_MSG_0_4(b1);
    G2_AVX2(a, b, c, d, b0, b1);
    DIAGONALIZE_AVX2(a, b, c, d);
    // ... 继续8个G函数 ...
    UNDIAGONALIZE_AVX2(a, b, c, d);
    
    /* Round 1-11 ... */
    
    /* 5. 更新状态 */
    a = _mm256_xor_si256(_mm256_xor_si256(a, c), _mm256_loadu_si256((__m256i *)&S->h[0]));
    b = _mm256_xor_si256(_mm256_xor_si256(b, d), _mm256_loadu_si256((__m256i *)&S->h[4]));
    
    _mm256_storeu_si256((__m256i *)&S->h[0], a);
    _mm256_storeu_si256((__m256i *)&S->h[4], b);
}
```

---

## ⚠️ 常见陷阱与解决方案

### 陷阱1: 旋转实现不当
**错误示例**:
```c
/* ❌ 性能极差 (需要3条指令) */
d = _mm256_or_si256(
    _mm256_srli_epi64(d, 32),
    _mm256_slli_epi64(d, 32));
```

**正确示例**:
```c
/* ✅ 使用shuffle (仅1条指令) */
d = _mm256_shuffle_epi32(d, _MM_SHUFFLE(2,3,0,1));
```

### 陷阱2: 消息调度使用标量访问
**错误示例**:
```c
/* ❌ 破坏向量化 */
for (int i = 0; i < 16; i++) {
    __m256i mi = _mm256_set1_epi64x(((uint64_t*)block)[sigma[r][i]]);
}
```

**正确示例**:
```c
/* ✅ 预定义所有排列宏 */
#define BLAKE2B_LOAD_MSG_0_1(b0) ...
#define BLAKE2B_LOAD_MSG_1_1(b0) ...
// ... 12轮 × 8个宏 = 96个宏定义 ...
```

### 陷阱3: 忽略CPU特性检测
```c
/* ✅ 运行时检测AVX2支持 */
#ifdef __AVX2__
static inline int cpu_supports_avx2(void) {
    uint32_t eax, ebx, ecx, edx;
    if (__get_cpuid(7, &eax, &ebx, &ecx, &edx)) {
        return (ebx & bit_AVX2) != 0;
    }
    return 0;
}

void blake2b_compress(blake2b_state *S, const uint8_t block[128]) {
    if (cpu_supports_avx2()) {
        blake2b_compress_avx2(S, block);
    } else {
        blake2b_compress_portable(S, block);
    }
}
#endif
```

---

## 🎓 性能优化检查清单

### ✅ 必须实现
- [ ] 使用`_mm256_add_epi64`替换标量加法
- [ ] 旋转32位用`_mm256_shuffle_epi32`
- [ ] 旋转16位用`_mm256_shuffle_epi8`
- [ ] 旋转24位用组合移位
- [ ] 旋转63位优化为`x<<1 | x>>63`
- [ ] 预定义所有12轮的消息调度宏
- [ ] 完全展开12轮循环
- [ ] 使用`_mm256_broadcastsi128_si256`预加载消息

### ⚡ 进阶优化
- [ ] 实现`_mm256_permute4x64_epi64`的DIAGONALIZE
- [ ] 使用`ALIGN(64)`对齐关键数据
- [ ] 减少临时变量，控制寄存器压力
- [ ] 运行时CPU特性检测
- [ ] 编译时`-mavx2 -O3 -march=native`

### 🔬 验证与测试
- [ ] 使用NIST官方测试向量验证正确性
- [ ] Benchmark对比标量版本（目标>2x加速）
- [ ] 跨平台测试（Haswell, Skylake, Zen3）
- [ ] 使用`perf stat`分析IPC和cache miss

---

## 📚 参考资料

1. **Samuel Neves论文** (IACR 2012/275):  
   "Implementing BLAKE with AVX, AVX2, and XOP"  
   URL: https://eprint.iacr.org/2012/275.pdf

2. **官方AVX2实现**:  
   - sneves/blake2-avx2: https://github.com/sneves/blake2-avx2
   - BLAKE2/BLAKE2 (sse/目录): https://github.com/BLAKE2/BLAKE2/tree/master/sse

3. **高性能Rust实现**:  
   - oconnor663/blake2_simd: https://github.com/oconnor663/blake2_simd

4. **Intel Intrinsics指南**:  
   - https://www.intel.com/content/www/us/en/docs/intrinsics-guide/

5. **BLAKE2规范**:  
   - RFC 7693: https://tools.ietf.org/html/rfc7693

---

## 🎯 下一步行动计划

### Phase 1: 核心G函数实现 (预计+100% 性能)
1. 创建`src/hash/blake2b_avx2.c`
2. 实现`G1_AVX2`和`G2_AVX2`宏
3. 实现旋转优化 (shuffle替代移位)

### Phase 2: 消息调度适配 (预计+30% 性能)
1. 定义96个`BLAKE2B_LOAD_MSG_*`宏
2. 使用`_mm256_broadcastsi128_si256`预加载

### Phase 3: 对角化优化 (预计+20% 性能)
1. 实现`DIAGONALIZE_AVX2`/`UNDIAGONALIZE_AVX2`
2. 使用`_mm256_permute4x64_epi64`

### Phase 4: 集成与测试
1. 添加CPU特性检测
2. NIST测试向量验证
3. Benchmark对比 (目标>1913 MB/s)

**预期最终性能**: 914 MB/s × 2.5 = 2285 MB/s ✅

---

**文档维护**: 实现过程中的关键发现和失败教训请更新至此文档。
