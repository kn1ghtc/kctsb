/**
 * @file blake2b_avx2_reference.c
 * @brief BLAKE2b AVX2优化参考实现 (基于sneves/blake2-avx2)
 * 
 * 本文件提供可直接集成到kctsb的核心代码片段和宏定义。
 * 所有代码均来自以下开源项目 (CC0/Apache 2.0协议):
 * - https://github.com/sneves/blake2-avx2
 * - https://github.com/BLAKE2/BLAKE2/tree/master/sse
 * 
 * 性能目标: 从914 MB/s提升到>1913 MB/s
 */

#ifndef BLAKE2B_AVX2_REFERENCE_H
#define BLAKE2B_AVX2_REFERENCE_H

#ifdef __AVX2__

#include <immintrin.h>
#include <stdint.h>

/* ============================================================================
 * 1. 基础宏定义
 * ============================================================================ */

/* 内存对齐 */
#if defined(_MSC_VER)
    #define ALIGN(n) __declspec(align(n))
#else
    #define ALIGN(n) __attribute__((aligned(n)))
#endif

/* 内存加载/存储 (BLAKE2消息字通常未对齐) */
#define LOADU128(p)   _mm_loadu_si128((const __m128i *)(p))
#define STOREU128(p, r) _mm_storeu_si128((__m128i *)(p), r)

/* 广播128位到256位 (AVX2) */
#define BROADCAST128(p) _mm256_broadcastsi128_si256(LOADU128(p))

/* ============================================================================
 * 2. 旋转优化宏 (核心性能关键)
 * ============================================================================ */

/**
 * @brief 旋转32位 - 使用shuffle替代移位 (性能提升~3x)
 * 
 * 原理: rotr64(x, 32) = swap_32bit_halves(x)
 * 指令: vpshufb (1周期延迟, 0.5 CPI)
 */
#define ROTR32_AVX2(x) \
    _mm256_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))

/**
 * @brief 旋转24位 - 组合移位
 * 
 * 指令: vpsrlq + vpsllq + vpor (3条指令, 可流水线)
 */
#define ROTR24_AVX2(x) \
    _mm256_or_si256(_mm256_srli_epi64((x), 24), \
                    _mm256_slli_epi64((x), 40))

/**
 * @brief 旋转16位 - 使用shuffle字节掩码
 * 
 * 原理: 交换每个64位字内的字节顺序
 * 指令: vpshufb (1周期延迟)
 */
static inline __m256i rotr16_avx2(__m256i x)
{
    const __m256i rot16_mask = _mm256_set_epi8(
        9,8,11,10, 13,12,15,14,  1,0,3,2,  5,4,7,6,   /* lane 1 */
        9,8,11,10, 13,12,15,14,  1,0,3,2,  5,4,7,6);  /* lane 0 */
    return _mm256_shuffle_epi8(x, rot16_mask);
}

#define ROTR16_AVX2(x) rotr16_avx2(x)

/**
 * @brief 旋转63位 - 优化为加法+移位
 * 
 * 原理: rotr64(x, 63) = (x >> 63) | (x << 1)
 *                      = (x >> 63) ^ (x + x)  [因为x<<1 = x+x]
 * 
 * 优势: _mm256_add_epi64延迟更低 (0.5周期 vs 1周期)
 */
#define ROTR63_AVX2(x) \
    _mm256_xor_si256(_mm256_srli_epi64((x), 63), \
                     _mm256_add_epi64((x), (x)))

/* ============================================================================
 * 3. G函数向量化实现 (4-way并行)
 * ============================================================================ */

/**
 * @brief G1宏 - BLAKE2b压缩函数的前半部分
 * 
 * 执行操作:
 *   a = a + b + m0
 *   d = rotr32(d ^ a)
 *   c = c + d
 *   b = rotr24(b ^ c)
 * 
 * @param a, b, c, d  状态向量 (YMM寄存器)
 * @param m0          消息字0 (从sigma排列获取)
 * @param m1          消息字1 (G2使用)
 */
#define G1_AVX2(a, b, c, d, m0, m1) do {                          \
    a = _mm256_add_epi64(_mm256_add_epi64(a, m0), b);            \
    d = _mm256_xor_si256(d, a);                                   \
    d = ROTR32_AVX2(d);                                           \
    c = _mm256_add_epi64(c, d);                                   \
    b = _mm256_xor_si256(b, c);                                   \
    b = ROTR24_AVX2(b);                                           \
} while(0)

/**
 * @brief G2宏 - BLAKE2b压缩函数的后半部分
 * 
 * 执行操作:
 *   a = a + b + m1
 *   d = rotr16(d ^ a)
 *   c = c + d
 *   b = rotr63(b ^ c)
 */
#define G2_AVX2(a, b, c, d, m0, m1) do {                          \
    a = _mm256_add_epi64(_mm256_add_epi64(a, m1), b);            \
    d = _mm256_xor_si256(d, a);                                   \
    d = ROTR16_AVX2(d);                                           \
    c = _mm256_add_epi64(c, d);                                   \
    b = _mm256_xor_si256(b, c);                                   \
    b = ROTR63_AVX2(b);                                           \
} while(0)

/* ============================================================================
 * 4. DIAGONALIZE/UNDIAGONALIZE (对角化操作)
 * ============================================================================ */

/**
 * @brief 对角化 - 调整向量通道布局以支持对角混合
 * 
 * 布局转换:
 *   原始: [a0 a1 a2 a3] [b0 b1 b2 b3] [c0 c1 c2 c3] [d0 d1 d2 d3]
 *   对角: [a0 a1 a2 a3] [b1 b2 b3 b0] [c2 c3 c0 c1] [d3 d0 d1 d2]
 * 
 * 使用指令:
 *   - _mm256_permute4x64_epi64 (AVX2独有, 3周期延迟)
 *   - _mm256_alignr_epi8 (字节级通道内旋转)
 */
#define DIAGONALIZE_AVX2(a, b, c, d) do {                         \
    __m256i t0 = _mm256_alignr_epi8(b, b, 8);                    \
    __m256i t1 = _mm256_alignr_epi8(d, d, 8);                    \
    b = _mm256_permute4x64_epi64(t0, _MM_SHUFFLE(2,1,0,3));      \
    c = _mm256_permute4x64_epi64(c, _MM_SHUFFLE(1,0,3,2));       \
    d = _mm256_permute4x64_epi64(t1, _MM_SHUFFLE(0,3,2,1));      \
} while(0)

/**
 * @brief 反对角化 - 恢复原始布局
 */
#define UNDIAGONALIZE_AVX2(a, b, c, d) do {                       \
    __m256i t0 = _mm256_alignr_epi8(b, b, 8);                    \
    __m256i t1 = _mm256_alignr_epi8(d, d, 8);                    \
    b = _mm256_permute4x64_epi64(t0, _MM_SHUFFLE(0,3,2,1));      \
    c = _mm256_permute4x64_epi64(c, _MM_SHUFFLE(1,0,3,2));       \
    d = _mm256_permute4x64_epi64(t1, _MM_SHUFFLE(2,1,0,3));      \
} while(0)

/* ============================================================================
 * 5. 消息调度宏 (Sigma Permutation)
 * ============================================================================ */

/**
 * @brief 消息调度 - Round 0的宏定义示例
 * 
 * Sigma[0] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
 * 
 * 使用_mm256_blend_epi32和_mm256_unpack*来构造所需的消息字组合。
 * 完整实现需要定义12轮 × 8个宏 = 96个宏。
 */

/* Round 0, 消息字对 (0, 1) */
#define BLAKE2B_LOAD_MSG_0_1(b0) do {                             \
    __m256i t0 = _mm256_unpacklo_epi64(m0, m1);                  \
    __m256i t1 = _mm256_unpacklo_epi64(m2, m3);                  \
    b0 = _mm256_blend_epi32(t0, t1, 0xF0);                       \
} while(0)

/* Round 0, 消息字对 (2, 3) */
#define BLAKE2B_LOAD_MSG_0_2(b0) do {                             \
    __m256i t0 = _mm256_unpackhi_epi64(m0, m1);                  \
    __m256i t1 = _mm256_unpackhi_epi64(m2, m3);                  \
    b0 = _mm256_blend_epi32(t0, t1, 0xF0);                       \
} while(0)

/* Round 0, 消息字对 (4, 5) */
#define BLAKE2B_LOAD_MSG_0_3(b0) do {                             \
    __m256i t0 = _mm256_unpacklo_epi64(m4, m5);                  \
    __m256i t1 = _mm256_unpacklo_epi64(m6, m7);                  \
    b0 = _mm256_blend_epi32(t0, t1, 0xF0);                       \
} while(0)

/* Round 0, 消息字对 (6, 7) */
#define BLAKE2B_LOAD_MSG_0_4(b0) do {                             \
    __m256i t0 = _mm256_unpackhi_epi64(m4, m5);                  \
    __m256i t1 = _mm256_unpackhi_epi64(m6, m7);                  \
    b0 = _mm256_blend_epi32(t0, t1, 0xF0);                       \
} while(0)

/*
 * 注意: Round 1-11的宏定义类似，但需根据Sigma排列调整。
 * 完整代码参考: https://github.com/sneves/blake2-avx2/blob/master/blake2b-load-avx2.h
 */

/* ============================================================================
 * 6. 完整压缩函数框架
 * ============================================================================ */

/**
 * @brief BLAKE2b AVX2压缩函数
 * 
 * 性能目标: ~2000 MB/s (Intel Haswell)
 * 
 * @param S      BLAKE2b状态 (h[8], t[2], f[2])
 * @param block  128字节输入消息块
 */
static inline void blake2b_compress_avx2(
    uint64_t h[8],
    uint64_t t[2],
    uint64_t f[2],
    const uint8_t block[128])
{
    /* 1. BLAKE2b IV常量 */
    ALIGN(32) static const uint64_t blake2b_IV[8] = {
        0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
        0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
        0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
        0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
    };

    /* 2. 加载状态向量 */
    __m256i a = _mm256_loadu_si256((__m256i *)&h[0]);  /* h[0..3] */
    __m256i b = _mm256_loadu_si256((__m256i *)&h[4]);  /* h[4..7] */
    __m256i c = _mm256_loadu_si256((__m256i *)&blake2b_IV[0]);
    __m256i d = _mm256_xor_si256(
        _mm256_loadu_si256((__m256i *)&blake2b_IV[4]),
        _mm256_set_epi64x(t[1], t[0], f[1], f[0]));

    /* 3. 预加载消息字 (关键优化) */
    const __m256i m0 = BROADCAST128(block +   0);
    const __m256i m1 = BROADCAST128(block +  16);
    const __m256i m2 = BROADCAST128(block +  32);
    const __m256i m3 = BROADCAST128(block +  48);
    const __m256i m4 = BROADCAST128(block +  64);
    const __m256i m5 = BROADCAST128(block +  80);
    const __m256i m6 = BROADCAST128(block +  96);
    const __m256i m7 = BROADCAST128(block + 112);

    /* 4. 执行12轮压缩 (完全展开) */
    __m256i b0, b1;

    /* ===== Round 0 ===== */
    BLAKE2B_LOAD_MSG_0_1(b0);
    BLAKE2B_LOAD_MSG_0_2(b1);
    G1_AVX2(a, b, c, d, b0, b1);
    BLAKE2B_LOAD_MSG_0_3(b0);
    BLAKE2B_LOAD_MSG_0_4(b1);
    G2_AVX2(a, b, c, d, b0, b1);
    DIAGONALIZE_AVX2(a, b, c, d);
    
    /* ... 继续8个G函数 (对角混合) ... */
    
    UNDIAGONALIZE_AVX2(a, b, c, d);

    /* ===== Round 1-11 (省略,实际需全部展开) ===== */
    // ROUND_AVX2(1);
    // ...
    // ROUND_AVX2(11);

    /* 5. 更新状态 */
    a = _mm256_xor_si256(_mm256_xor_si256(a, c),
                         _mm256_loadu_si256((__m256i *)&h[0]));
    b = _mm256_xor_si256(_mm256_xor_si256(b, d),
                         _mm256_loadu_si256((__m256i *)&h[4]));

    _mm256_storeu_si256((__m256i *)&h[0], a);
    _mm256_storeu_si256((__m256i *)&h[4], b);
}

/* ============================================================================
 * 7. CPU特性检测
 * ============================================================================ */

#if defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>

static inline int cpu_supports_avx2(void)
{
    uint32_t eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }
    /* 检查OSXSAVE和AVX */
    if (!(ecx & (1 << 27)) || !(ecx & (1 << 28))) {
        return 0;
    }
    /* 检查AVX2 */
    if (__get_cpuid_max(0, NULL) < 7) {
        return 0;
    }
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1 << 5)) != 0;  /* bit 5 = AVX2 */
}

#elif defined(_MSC_VER)
#include <intrin.h>

static inline int cpu_supports_avx2(void)
{
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 27)) || !(cpuInfo[2] & (1 << 28))) {
        return 0;
    }
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[1] & (1 << 5)) != 0;
}

#else
static inline int cpu_supports_avx2(void) { return 0; }
#endif

/* ============================================================================
 * 8. 使用示例
 * ============================================================================ */

/*
void blake2b_hash(uint8_t *out, const uint8_t *in, size_t inlen)
{
    blake2b_state S;
    blake2b_init(&S, 64);

    while (inlen >= 128) {
        S.t[0] += 128;
        if (S.t[0] < 128) S.t[1]++;
        
        if (cpu_supports_avx2()) {
            blake2b_compress_avx2(S.h, S.t, S.f, in);
        } else {
            blake2b_compress_portable(S.h, S.t, S.f, in);
        }
        
        in += 128;
        inlen -= 128;
    }

    // ... 处理剩余字节和finalize ...
    memcpy(out, S.h, 64);
}
*/

#endif /* __AVX2__ */
#endif /* BLAKE2B_AVX2_REFERENCE_H */

/* ============================================================================
 * 参考文献
 * ============================================================================
 * 
 * 1. Samuel Neves. "Implementing BLAKE with AVX, AVX2, and XOP"
 *    IACR ePrint 2012/275. https://eprint.iacr.org/2012/275
 * 
 * 2. sneves/blake2-avx2 (GitHub, CC0协议)
 *    https://github.com/sneves/blake2-avx2
 * 
 * 3. BLAKE2 官方实现 (CC0/OpenSSL/Apache 2.0三协议)
 *    https://github.com/BLAKE2/BLAKE2/tree/master/sse
 * 
 * 4. Intel Intrinsics Guide
 *    https://www.intel.com/content/www/us/en/docs/intrinsics-guide/
 * 
 * 5. RFC 7693 - The BLAKE2 Cryptographic Hash and MAC
 *    https://tools.ietf.org/html/rfc7693
 */
