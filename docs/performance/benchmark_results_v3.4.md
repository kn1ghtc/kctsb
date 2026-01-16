# kctsb v3.4.0 Performance Benchmark Results

**Date**: 2025-01-07 (Beijing Time)  
**Compiler**: MinGW-w64 GCC 15.2.0  
**Optimization Flags**: `-O3 -march=native -mtune=native -flto -mavx2 -maes -mpclmul -msha`  
**Hardware**: x86_64 with AES-NI, AVX2, PCLMUL, SSE4.2, BMI2, SHA-NI  
**Build Directory**: `build-release/` (standardized Release builds)

---

## Executive Summary

| Category | kctsb Status | vs OpenSSL |
|----------|--------------|------------|
| **SHA-256** | ✅ Production-Ready | +31% faster (1KB), -3% (1MB+) |
| **SHA3-256** | ✅ Competitive | -5% (consistent across sizes) |
| **BLAKE2b-512** | ⭐ **Outstanding** | +45% faster (cross-platform optimized) |
| **SM3 (Chinese)** | ⭐ **Outstanding** | +65% faster (国密优化) |
| **AES-GCM** | ✅ Good (small data) | +12-93% (1KB), -72% (1MB+) |
| **ChaCha20-Poly1305** | ⚠️ Needs Work | -55-83% slower |

---

## Hash Functions Performance (v3.4.0)

### 1KB Data (Optimal for kctsb)

| Algorithm | OpenSSL | kctsb | Ratio | Notes |
|-----------|---------|-------|-------|-------|
| **SHA-256** | 1210 MB/s | **1590 MB/s** | +31.4% ⭐ | SHA-NI + AVX2 优化 |
| **SHA-512** | 652 MB/s | 645 MB/s | -1.1% ✅ | 64-bit优化良好 |
| **SHA3-256** | 462 MB/s | 438 MB/s | -5.2% ✅ | Keccak实现符合预期 |
| **SHA3-512** | 239 MB/s | **313 MB/s** | +30.8% ⭐ | 宽度优化 |
| **BLAKE2b-512** | 624 MB/s | **905 MB/s** | +45.1% 🏆 | 最佳性能 |
| **SM3** | 219 MB/s | **360 MB/s** | +64.8% 🏆 | 国密标准GB/T 32905 |

### 64KB Data

| Algorithm | OpenSSL | kctsb | Ratio | Notes |
|-----------|---------|-------|-------|-------|
| **SHA-256** | 1944 MB/s | 1813 MB/s | -6.8% ✅ | L1 cache友好 |
| **SHA3-256** | 528 MB/s | 527 MB/s | -0.3% ✅ | 几乎一致 |
| **BLAKE2b-512** | 707 MB/s | **901 MB/s** | +27.4% ⭐ | 持续领先 |
| **SM3** | 243 MB/s | **321 MB/s** | +32.0% ⭐ | 稳定优势 |

### 1MB+ Data (OpenSSL Assembly优势)

| Algorithm | OpenSSL | kctsb | Ratio | Notes |
|-----------|---------|-------|-------|-------|
| **SHA-256** | 2016 MB/s | 1879 MB/s | -6.8% ✅ | 预期范围内 |
| **SHA-512** | 856 MB/s | 729 MB/s | -14.9% ✅ | 可接受 |
| **SHA3-256** | 578 MB/s | 530 MB/s | -8.3% ✅ | 稳定表现 |
| **BLAKE2b-512** | 680 MB/s | **891 MB/s** | +31.0% 🏆 | 大数据仍领先 |

---

## AEAD Ciphers Performance

### AES-256-GCM (1KB)

| Operation | OpenSSL | kctsb | Ratio | Notes |
|-----------|---------|-------|-------|-------|
| **Encrypt** | 1112 MB/s | **1246 MB/s** | +12.0% ⭐ | AES-NI优化 |
| **Decrypt** | 687 MB/s | **1325 MB/s** | +92.8% 🏆 | PCLMUL加速 |

### AES-256-GCM (1MB - OpenSSL汇编优势)

| Operation | OpenSSL | kctsb | Ratio | Notes |
|-----------|---------|-------|-------|-------|
| **Encrypt** | 6257 MB/s | 1734 MB/s | -72.3% ⚠️ | 预期（OpenSSL汇编） |
| **Decrypt** | 5750 MB/s | 1669 MB/s | -71.0% ⚠️ | 同上 |

### ChaCha20-Poly1305 (需要改进)

| Data Size | OpenSSL | kctsb | Ratio | Status |
|-----------|---------|-------|-------|--------|
| **1KB** | 901 MB/s | 403 MB/s | -55.3% ⚠️ | SIMD优化待加强 |
| **1MB** | 2388 MB/s | 402 MB/s | -83.2% ⚠️ | 需要重写 |

---

## Asymmetric Cryptography (RSA/ECC)

### RSA-2048

| Operation | OpenSSL | kctsb | Ratio | Notes |
|-----------|---------|-------|-------|-------|
| **Key Generation** | 34 ms | 94 ms | -64.4% ⚠️ | NTL后端限制 |
| **OAEP Encrypt** | 0.02 ms | 0.02 ms | -16.7% ✅ | 小数据良好 |
| **OAEP Decrypt** | 0.46 ms | 0.64 ms | -27.9% ✅ | CRT优化 |
| **PSS Sign** | 0.53 ms | 0.64 ms | -17.1% ✅ | 可接受 |
| **PSS Verify** | 0.02 ms | 0.02 ms | -6.0% ✅ | 公钥操作快 |

### ECC secp256r1 (P-256)

| Operation | OpenSSL | kctsb | Ratio | Notes |
|-----------|---------|-------|-------|-------|
| **Key Generation** | 0.04 ms | 1.00 ms | -96.0% ⚠️ | NTL限制 |
| **ECDSA Sign** | 0.02 ms | 1.00 ms | -98.0% ⚠️ | 同上 |
| **ECDH** | 0.08 ms | 1.00 ms | -92.0% ⚠️ | 教育用途可 |

---

## Build System Changes (v3.4)

### Directory Structure (Standardized)

```
kctsb/
├── build/              ✅ Debug builds only
├── build-release/      ✅ Release builds (NEW standard)
└── build-release-hash/ ❌ DELETED (incorrect)
```

### Compilation Flags

**Release Mode** (all optimizations enabled):
```cmake
-O3                      # Maximum optimization
-march=native            # CPU-specific instructions
-mtune=native            # CPU-specific tuning
-flto                    # Link-time optimization
-ffast-math              # Fast floating-point
-funroll-loops           # Loop unrolling
-fomit-frame-pointer     # Extra register
-mavx2 -maes -mpclmul    # SIMD instructions
-msha -mbmi2 -mssse3     # More SIMD
```

**Build Script** (`scripts/build.ps1`):
- Auto-detects Ninja for faster parallel builds
- Debug → `build/`, Release → `build-release/`
- Parallel jobs: Auto-detect CPU cores
- LTO enabled by default

---

## Known Issues & Roadmap

### ⚠️ Performance Gaps

1. **ChaCha20-Poly1305**: -55-83% vs OpenSSL
   - **Root Cause**: Portable C implementation, no SIMD
   - **Solution**: AVX2/NEON vectorization (v3.5 target)

2. **Large Data AES-GCM**: -72% vs OpenSSL (1MB+)
   - **Root Cause**: OpenSSL uses assembly, kctsb uses intrinsics
   - **Status**: Expected, acceptable for education/testing

3. **ECC Operations**: -92-98% vs OpenSSL
   - **Root Cause**: NTL backend (arbitrary precision) vs OpenSSL (fixed-width assembly)
   - **Status**: Trade-off for correctness and portability

### ✅ Performance Wins

1. **BLAKE2b**: +31-45% faster (all data sizes)
2. **SM3 (国密)**: +32-65% faster (国产优化)
3. **SHA-256 (small data)**: +31% faster (SHA-NI)
4. **AES-GCM (small data)**: +12-93% faster

---

## Baseline Comparison (Historical)

| Metric | v3.3.0 | v3.4.0 (Current) | Change |
|--------|--------|------------------|--------|
| **SHA3-256 (1KB)** | ~467 MB/s | 438 MB/s | -6.2% (regression from old measure) |
| **BLAKE2b (1KB)** | ~620 MB/s | **905 MB/s** | +45.9% 🏆 |
| **Build Time** | ~3m 20s | 2m 4s | -38% (Ninja) |
| **Unit Tests** | 152/152 | 152/152 | ✅ |

**Note**: v3.4.0 used incorrect Debug build for initial measurements, causing false regression reports. This document reflects correct Release build results.

---

## Recommendations

### ✅ Production-Ready Algorithms

- **SHA-256** (FIPS 180-4): Use for general hashing
- **SHA3-256** (FIPS 202): Use for Keccak-based systems
- **BLAKE2b-512**: **Best choice** for high-speed hashing
- **SM3** (GB/T 32905): Use for 国密 compliance

### ⚠️ Use with Caution

- **AES-GCM**: Good for <1MB payloads, use OpenSSL for bulk encryption
- **ChaCha20-Poly1305**: Prefer OpenSSL until v3.5 SIMD rewrite

### ❌ Educational Only

- **ECC/RSA**: Use for learning, not production (OpenSSL 10-100x faster)

---

## Testing Environment

**Hardware**:
- CPU: x86_64 with AVX2, AES-NI, PCLMUL, SHA-NI
- Compiler: MinGW-w64 GCC 15.2.0 (MSYS2)
- OS: Windows 11

**Test Methodology**:
- Iterations: 100 (10 warmup)
- Data sizes: 1KB, 64KB, 1MB, 10MB
- Comparison: OpenSSL 3.3.1 (same machine)
- Build: Release mode with all optimizations

---

## Conclusion

kctsb v3.4.0 delivers **production-quality performance** for:
- ✅ Hash functions (SHA, SHA3, BLAKE2, SM3)
- ✅ Small-data AEAD (AES-GCM <1MB)
- ✅ Educational cryptography (RSA/ECC)

Performance gaps in ChaCha20 and ECC are **known trade-offs** prioritizing code clarity and cross-platform portability over raw speed. For production systems requiring maximum throughput, OpenSSL remains the recommended choice for AEAD and asymmetric operations.

**Next Steps (v3.5)**:
1. ChaCha20-Poly1305 AVX2/NEON vectorization
2. PSI/PIR performance optimization
3. Automated CI/CD benchmark regression detection
