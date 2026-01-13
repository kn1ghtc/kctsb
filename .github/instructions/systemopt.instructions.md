# kctsb System Optimization Guidelines

> **Agent**: System Optimization Specialist  
> **Project**: kctsb - Knight's Cryptographic Trusted Security Base  
> **Version**: 3.1.0  
> **Last Updated**: 2026-01-13

---

## 🎯 Optimization Philosophy

The kctsb library aims to **match or exceed OpenSSL performance** while maintaining:
- **Security**: No performance optimizations that compromise security
- **Portability**: Optimizations must work across Windows/Linux/macOS
- **Maintainability**: Code must remain readable and testable

### Performance Targets

| Algorithm | Target vs OpenSSL | Priority |
|-----------|------------------|----------|
| AES-256-GCM | ≥ 0.8x (80%) | High |
| ChaCha20-Poly1305 | ≥ 1.0x (100%) | High |
| SHA3-256 | ≥ 0.7x (70%) | Medium |
| BLAKE2b | ≥ 1.2x (120%) | Medium |
| RSA-2048 | ≥ 0.8x (80%) | Medium |
| ECC (secp256k1) | ≥ 0.8x (80%) | High |

---

## 🔧 Compiler Optimization Flags

### GCC/Clang (Linux/macOS/MinGW)

```cmake
# Release build - maximum optimization
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        # Optimization level
        -O3                        # Maximum optimization (enables most optimizations)
        
        # CPU-specific optimizations
        -march=native              # Use all instructions available on build CPU
        -mtune=native              # Optimize scheduling for build CPU
        
        # Link-time optimization
        -flto                      # Enable link-time optimization
        
        # Math optimizations
        -ffast-math                # Fast floating-point (OK for non-crypto math)
        
        # Loop optimizations
        -funroll-loops             # Unroll loops for better performance
        -ftree-vectorize           # Auto-vectorization (enabled by -O3)
        
        # Function inlining
        -finline-functions         # Inline suitable functions
        -fomit-frame-pointer       # Omit frame pointer for extra register
        
        # Code generation
        -fPIC                      # Position-independent code
    )
    
    # Linker flags
    add_link_options(
        -flto                      # Match compiler LTO setting
        -Wl,--strip-all            # Strip symbols in release (optional)
    )
endif()

# Debug build - disable optimizations, enable debug info
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(
        -O0                        # No optimization
        -g3                        # Maximum debug info
        -fno-omit-frame-pointer    # Keep frame pointer for debugging
    )
endif()
```

### MSVC (Visual Studio)

```cmake
# Release build
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        /O2                        # Maximize speed
        /Oi                        # Enable intrinsic functions
        /Ot                        # Favor fast code
        /GL                        # Whole program optimization
        /fp:fast                   # Fast floating-point mode
        /GS-                       # Disable security checks (only if safe)
    )
    
    # AVX2 support (x64 only)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        add_compile_options(/arch:AVX2)
    endif()
    
    # Linker flags
    add_link_options(
        /LTCG                      # Link-time code generation
        /OPT:REF                   # Remove unreferenced functions
        /OPT:ICF                   # Identical COMDAT folding
    )
endif()
```

---

## 🚀 SIMD Optimization Guidelines

### Detecting SIMD Support

```c
/* Feature detection at compile time */
#if defined(__AES__) && defined(__x86_64__)
    #define KCTSB_HAS_AESNI 1
    #include <wmmintrin.h>
#endif

#if defined(__AVX2__)
    #define KCTSB_HAS_AVX2 1
    #include <immintrin.h>
#endif

#if defined(__AVX512F__)
    #define KCTSB_HAS_AVX512 1
    #include <immintrin.h>
#endif

#if defined(__ARM_NEON)
    #define KCTSB_HAS_NEON 1
    #include <arm_neon.h>
#endif
```

### AES-NI Acceleration (x86_64)

```c
/**
 * @brief AES encryption using AES-NI instructions
 * @param in Input block (16 bytes)
 * @param out Output block (16 bytes)
 * @param round_keys Expanded round keys
 * @param rounds Number of rounds (10/12/14 for AES-128/192/256)
 */
#ifdef KCTSB_HAS_AESNI
static inline void aes_encrypt_block_aesni(
    const uint8_t *in,
    uint8_t *out,
    const __m128i *round_keys,
    int rounds)
{
    __m128i state = _mm_loadu_si128((const __m128i *)in);
    
    /* Initial round */
    state = _mm_xor_si128(state, round_keys[0]);
    
    /* Main rounds */
    for (int i = 1; i < rounds; i++) {
        state = _mm_aesenc_si128(state, round_keys[i]);
    }
    
    /* Final round */
    state = _mm_aesenclast_si128(state, round_keys[rounds]);
    
    _mm_storeu_si128((__m128i *)out, state);
}
#endif
```

### AVX2 Parallel Processing

```c
/**
 * @brief Process 8 blocks in parallel using AVX2
 * @note Requires AVX2 support (__AVX2__ defined)
 */
#ifdef KCTSB_HAS_AVX2
static inline void process_8_blocks_avx2(
    const uint8_t *in,
    uint8_t *out,
    const __m256i *keys)
{
    /* Load 8 blocks (256 bits each) */
    __m256i block0 = _mm256_loadu_si256((const __m256i *)(in + 0));
    __m256i block1 = _mm256_loadu_si256((const __m256i *)(in + 32));
    
    /* Process in parallel */
    block0 = _mm256_xor_si256(block0, keys[0]);
    block1 = _mm256_xor_si256(block1, keys[0]);
    
    /* Store results */
    _mm256_storeu_si256((__m256i *)(out + 0), block0);
    _mm256_storeu_si256((__m256i *)(out + 32), block1);
}
#endif
```

### ARM NEON Optimization

```c
/**
 * @brief ARM NEON optimized XOR operation
 */
#ifdef KCTSB_HAS_NEON
static inline void xor_blocks_neon(
    const uint8_t *a,
    const uint8_t *b,
    uint8_t *out,
    size_t len)
{
    size_t i;
    for (i = 0; i + 16 <= len; i += 16) {
        uint8x16_t va = vld1q_u8(a + i);
        uint8x16_t vb = vld1q_u8(b + i);
        uint8x16_t vout = veorq_u8(va, vb);
        vst1q_u8(out + i, vout);
    }
    
    /* Handle remaining bytes */
    for (; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}
#endif
```

---

## 🧠 Memory Optimization

### Alignment Requirements

```c
/* Ensure 16-byte alignment for SIMD operations */
#ifdef _MSC_VER
    #define KCTSB_ALIGN(n) __declspec(align(n))
#else
    #define KCTSB_ALIGN(n) __attribute__((aligned(n)))
#endif

/* Example usage */
KCTSB_ALIGN(16) uint8_t aes_state[16];
KCTSB_ALIGN(32) uint8_t avx_buffer[64];

/* Aligned allocation */
void* kctsb_aligned_alloc(size_t alignment, size_t size) {
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#else
    void *ptr;
    if (posix_memalign(&ptr, alignment, size) == 0) {
        return ptr;
    }
    return NULL;
#endif
}

void kctsb_aligned_free(void *ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}
```

### Cache Optimization

```c
/* Cache line size (typical: 64 bytes) */
#define KCTSB_CACHE_LINE_SIZE 64

/* Prefetch data for better cache utilization */
#ifdef __GNUC__
    #define KCTSB_PREFETCH(addr) __builtin_prefetch(addr)
#else
    #define KCTSB_PREFETCH(addr) ((void)0)
#endif

/* Example: Prefetch next block during processing */
void process_blocks_with_prefetch(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        /* Prefetch next block */
        if (i + 64 < len) {
            KCTSB_PREFETCH(data + i + 64);
        }
        
        /* Process current block */
        process_block(data + i);
    }
}
```

### Memory Layout for Performance

```c
/**
 * @brief Structure layout optimized for cache
 * 
 * Hot fields (frequently accessed) at the beginning
 * Cold fields (rarely accessed) at the end
 */
struct AesContext {
    /* Hot: Frequently accessed during encryption */
    uint8_t round_keys[240];    /* Expanded keys */
    uint8_t state[16];          /* Current state */
    uint32_t rounds;            /* Number of rounds */
    
    /* Cold: Used only during initialization */
    uint8_t original_key[32];
    uint32_t key_schedule_version;
    bool is_encryption;
};
```

---

## ⚡ Algorithm-Specific Optimizations

### AES-GCM Performance Tips

```c
/**
 * @brief Optimized GCM multiplication using precomputed tables
 * 
 * Trade memory for speed: Precompute H^i for i=1..8
 * This enables 8-block parallel processing
 */
struct GcmContext {
    __m128i H[8];           /* Precomputed H^1, H^2, ..., H^8 */
    __m128i counter;        /* Current counter value */
    uint8_t ghash_state[16]; /* GHASH accumulator */
};

/* Initialize precomputed tables */
void gcm_init_tables(struct GcmContext *ctx, const uint8_t *h) {
    ctx->H[0] = _mm_loadu_si128((const __m128i *)h);
    
    /* Compute H^2, H^3, ..., H^8 using GF(2^128) multiplication */
    for (int i = 1; i < 8; i++) {
        ctx->H[i] = gf128_mul(ctx->H[i-1], ctx->H[0]);
    }
}
```

### ChaCha20 Optimization

```c
/**
 * @brief SIMD-optimized ChaCha20 quarter-round
 * 
 * Process 4 states in parallel using SSE/AVX
 */
#ifdef KCTSB_HAS_AVX2
static inline void chacha20_block_avx2(__m256i *state) {
    /* 20 rounds (10 double-rounds) */
    for (int i = 0; i < 10; i++) {
        /* Column round */
        quarter_round_avx2(&state[0], &state[1], &state[2], &state[3]);
        
        /* Diagonal round */
        quarter_round_avx2(&state[0], &state[1], &state[2], &state[3]);
    }
}
#endif
```

### BLAKE2 Optimization

```c
/**
 * @brief Optimized BLAKE2b compression function
 * 
 * Use 64-bit operations on 64-bit platforms
 * Minimize memory access with register-heavy code
 */
static inline void blake2b_compress(
    uint64_t h[8],
    const uint64_t m[16],
    uint64_t t,
    bool final)
{
    uint64_t v[16];
    
    /* Initialize working variables (in registers if possible) */
    memcpy(v, h, 64);
    memcpy(v + 8, blake2b_iv, 64);
    
    v[12] ^= t;
    if (final) v[14] ^= ~0ULL;
    
    /* 12 rounds of mixing */
    for (int i = 0; i < 12; i++) {
        /* Mix function optimized for throughput */
        BLAKE2B_ROUND(v, m, i);
    }
    
    /* XOR back into state */
    for (int i = 0; i < 8; i++) {
        h[i] ^= v[i] ^ v[i + 8];
    }
}
```

---

## 🔄 Loop Optimization Patterns

### Loop Unrolling

```c
/* Manual loop unrolling for critical paths */
void process_blocks_unrolled(uint8_t *data, size_t blocks) {
    size_t i;
    
    /* Process 4 blocks per iteration */
    for (i = 0; i + 4 <= blocks; i += 4) {
        process_block(data + i * 16 + 0);
        process_block(data + i * 16 + 16);
        process_block(data + i * 16 + 32);
        process_block(data + i * 16 + 48);
    }
    
    /* Handle remaining blocks */
    for (; i < blocks; i++) {
        process_block(data + i * 16);
    }
}
```

### Data Parallelism

```c
/**
 * @brief Process independent blocks in parallel
 * 
 * Use CTR mode for parallelizable encryption
 */
void aes_ctr_encrypt_parallel(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t len)
{
    #pragma omp parallel for  /* OpenMP parallelization */
    for (size_t i = 0; i < len / 16; i++) {
        uint8_t counter_block[16];
        
        /* Generate counter block */
        memcpy(counter_block, nonce, 12);
        counter_block[12] = (i >> 24) & 0xFF;
        counter_block[13] = (i >> 16) & 0xFF;
        counter_block[14] = (i >> 8) & 0xFF;
        counter_block[15] = i & 0xFF;
        
        /* Encrypt counter and XOR with plaintext */
        uint8_t keystream[16];
        aes_encrypt_block(counter_block, keystream, key);
        
        for (int j = 0; j < 16; j++) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ keystream[j];
        }
    }
}
```

---

## 🎯 Profiling and Benchmarking

### Performance Measurement

```cpp
/**
 * @brief High-resolution timer for benchmarking
 */
class BenchmarkTimer {
public:
    void start() {
        start_ = std::chrono::high_resolution_clock::now();
    }
    
    double elapsed_ms() {
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = end - start_;
        return elapsed.count();
    }
    
    double throughput_mbps(size_t bytes) {
        double elapsed_sec = elapsed_ms() / 1000.0;
        double mb = bytes / (1024.0 * 1024.0);
        return mb / elapsed_sec;
    }
    
private:
    std::chrono::time_point<std::chrono::high_resolution_clock> start_;
};

/* Usage */
BenchmarkTimer timer;
timer.start();
aes_encrypt(data, len, key);
double throughput = timer.throughput_mbps(len);
std::cout << "AES-256-GCM: " << throughput << " MB/s" << std::endl;
```

### Benchmark Against OpenSSL

```cpp
void benchmark_comparison() {
    const size_t data_size = 1024 * 1024;  /* 1 MB */
    std::vector<uint8_t> data(data_size);
    
    /* kctsb implementation */
    BenchmarkTimer timer_kctsb;
    timer_kctsb.start();
    for (int i = 0; i < 100; i++) {
        kctsb_aes_gcm_encrypt(data.data(), data.size());
    }
    double kctsb_mbps = timer_kctsb.throughput_mbps(data_size * 100);
    
    /* OpenSSL implementation */
    BenchmarkTimer timer_openssl;
    timer_openssl.start();
    for (int i = 0; i < 100; i++) {
        openssl_aes_gcm_encrypt(data.data(), data.size());
    }
    double openssl_mbps = timer_openssl.throughput_mbps(data_size * 100);
    
    /* Report */
    double ratio = kctsb_mbps / openssl_mbps;
    std::cout << "kctsb:   " << kctsb_mbps << " MB/s\n";
    std::cout << "OpenSSL: " << openssl_mbps << " MB/s\n";
    std::cout << "Ratio:   " << ratio << "x\n";
}
```

---

## 🛡️ Security vs Performance Trade-offs

### Constant-Time Operations (NEVER Compromise)

```c
/**
 * @brief Constant-time comparison - NO OPTIMIZATION ALLOWED
 * 
 * This MUST remain constant-time even with -O3
 * Use 'volatile' to prevent compiler optimization
 */
int kctsb_secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (diff == 0) ? 1 : 0;
}

/**
 * @brief Constant-time conditional select
 * 
 * Select 'a' if condition is true, 'b' otherwise
 * No branches - constant time
 */
uint32_t ct_select(uint32_t condition, uint32_t a, uint32_t b) {
    uint32_t mask = -(uint32_t)(condition != 0);
    return (a & mask) | (b & ~mask);
}
```

### Safe Optimizations

```c
/* SAFE: Optimize non-secret data processing */
void hash_blocks_fast(const uint8_t *data, size_t len) {
    /* OK to use SIMD and aggressive optimizations */
    #ifdef KCTSB_HAS_AVX2
        hash_blocks_avx2(data, len);
    #else
        hash_blocks_scalar(data, len);
    #endif
}

/* UNSAFE: DON'T optimize secret-dependent operations */
void process_key_schedule(const uint8_t *key) {
    /* NO SIMD, NO early exit, NO data-dependent branches */
    for (int i = 0; i < key_length; i++) {
        /* Constant-time operations only */
    }
}
```

---

## 📊 Optimization Checklist

Before optimizing, verify:

- [ ] Algorithm is correct and passes all test vectors
- [ ] Baseline performance measured
- [ ] Target performance defined (vs OpenSSL)
- [ ] Profiling shows bottleneck (don't guess!)
- [ ] Security analysis done (constant-time where needed)

During optimization:

- [ ] Use compiler intrinsics for SIMD where appropriate
- [ ] Align data to cache line boundaries (64 bytes)
- [ ] Minimize memory allocations in hot paths
- [ ] Unroll critical loops (4-8 iterations)
- [ ] Use lookup tables for non-secret data
- [ ] Prefetch next data block during processing
- [ ] Enable LTO (-flto) for cross-module inlining

After optimization:

- [ ] Verify correctness with all test vectors
- [ ] Benchmark shows improvement (>10%)
- [ ] Security review confirms no timing leaks
- [ ] Code remains readable and maintainable
- [ ] Cross-platform compatibility verified
- [ ] Document optimization techniques used

---

## 🌐 Cross-Platform Compatibility

### Platform-Specific Code Organization

```c
/* crypto/aes/aes_encrypt.c */
void aes_encrypt_block(const uint8_t *in, uint8_t *out, const void *ctx) {
#if defined(KCTSB_HAS_AESNI)
    /* x86_64 with AES-NI */
    aes_encrypt_block_aesni(in, out, ctx);
#elif defined(KCTSB_HAS_NEON)
    /* ARM with NEON */
    aes_encrypt_block_neon(in, out, ctx);
#else
    /* Portable C implementation */
    aes_encrypt_block_portable(in, out, ctx);
#endif
}
```

### Feature Detection at Runtime

```c
/**
 * @brief Detect CPU features at runtime
 */
struct CpuFeatures {
    bool has_aesni;
    bool has_avx2;
    bool has_avx512;
    bool has_neon;
};

#ifdef __x86_64__
#include <cpuid.h>

struct CpuFeatures detect_cpu_features(void) {
    struct CpuFeatures features = {0};
    unsigned int eax, ebx, ecx, edx;
    
    /* Check for AES-NI */
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        features.has_aesni = (ecx & bit_AES) != 0;
    }
    
    /* Check for AVX2 */
    if (__get_cpuid(7, &eax, &ebx, &ecx, &edx)) {
        features.has_avx2 = (ebx & bit_AVX2) != 0;
    }
    
    return features;
}
#endif
```

---

## 📚 References

- **Intel Intrinsics Guide**: https://www.intel.com/content/www/us/en/docs/intrinsics-guide/
- **Agner Fog's Optimization Manuals**: https://www.agner.org/optimize/
- **GCC Optimization Options**: https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html
- **ARM NEON Programming**: https://developer.arm.com/architectures/instruction-sets/simd-isas/neon
- **Crypto Implementation Best Practices**: NIST SP 800-175B

---

**Remember**: Measure before optimizing. Profile to find bottlenecks. Verify security after changes.
