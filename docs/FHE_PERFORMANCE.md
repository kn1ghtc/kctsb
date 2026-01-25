# FHE Performance Baseline

> kctsb Fully Homomorphic Encryption Module - Performance Benchmarks
> Version: v4.15.0 | Date: 2026-01-25

## 1. Overview

This document establishes performance baselines for kctsb's FHE implementation, comparing:
- **CPU**: Harvey NTT with Shoup precomputation (SIMD optional)
- **GPU**: CUDA kernels with coalesced memory access and lazy reduction
- **Reference**: Microsoft SEAL 4.1.x

### 1.1 Recent Updates (v4.15.0)

**CUDA GPU Acceleration for FHE Operations**

- **New**: Unified CUDA directory `src/advanced/cuda/` with independent CMake build
- **New**: Harvey NTT with tree-order root tables for CT-NTT/GS-INTT
- **New**: FHE GPU kernels: ct_add, ct_mul_tensor, relin, poly_multiply
- **Fix**: MSVC 128-bit precision via bit-by-bit long division for Shoup precomputation
- **Fix**: 50-bit NTT-friendly primes supporting n=32768 (p = k × 32768 + 1)
- **New**: Runtime accelerator detection and automatic backend selection

**Performance Highlights (RTX 4060 Laptop GPU):**
| Operation | n | L | GPU Speedup |
|-----------|---|---|-------------|
| NTT Inverse | 32768 | 12 | **7.77x** |
| CT Tensor Mul | 32768 | 12 | **5.40x** |
| CT Tensor Mul | 16384 | 12 | **4.95x** |
| CT Tensor Mul | 8192 | 3 | **3.27x** |

### 1.2 Previous Updates (v4.13.0)

**Multi-Precision Arithmetic for Large Parameters**

- **Issue**: `__int128` overflow when Q > 2^127 (e.g., n=8192, L=3 with 50-bit primes)
- **Solution**: Multi-precision arithmetic in `scale_plaintext()` using `std::vector<uint64_t>`
- **Impact**: All 119 FHE tests pass including n=8192 L=3 parameter sets

**Performance Ratio Convention**: Values > 1.0x mean **kctsb is faster**.

## 2. Test Environment

- **CPU**: Intel Core i7-12700H (14 cores, AVX2)
- **GPU**: NVIDIA RTX 4060 Laptop GPU (SM 8.9, 24 SMs, 8GB VRAM)
- **CUDA**: 12.5.82 + MSVC 19.44
- **Memory**: 32GB DDR5-4800
- **Compiler**: MSVC 2022 / GCC 13.x
- **Optimization**: `/O2` (MSVC) or `-O3 -march=native -flto` (GCC)

## 3. GPU vs CPU Performance (v4.15.0 Benchmark)

### 3.1 NTT Operations (50-bit primes)

| Operation | n | L | CPU (ms) | GPU (ms) | GPU Speedup | Verified |
|-----------|---|---|----------|----------|-------------|----------|
| NTT Forward | 8192 | 3 | 0.298 | 0.365 | 0.82x | ✓ |
| NTT Inverse | 8192 | 3 | 1.220 | 0.366 | **3.34x** | ✓ |
| NTT Forward | 16384 | 12 | 2.314 | 1.679 | 1.38x | ✓ |
| NTT Inverse | 16384 | 12 | 8.297 | 1.548 | **5.36x** | ✓ |
| NTT Forward | 32768 | 12 | 5.592 | 1.806 | **3.10x** | ✓ |
| NTT Inverse | 32768 | 12 | 16.424 | 2.113 | **7.77x** | ✓ |

### 3.2 FHE Polynomial Operations

| Operation | n | L | CPU (ms) | GPU (ms) | GPU Speedup | Verified |
|-----------|---|---|----------|----------|-------------|----------|
| Poly Multiply | 8192 | 3 | 0.148 | 0.103 | 1.44x | ✓ |
| CT Addition | 8192 | 3 | 0.050 | 0.259 | 0.19x | ✓ |
| CT Tensor Mul | 8192 | 3 | 0.586 | 0.179 | **3.27x** | ✓ |
| Poly Multiply | 16384 | 12 | 1.256 | 0.420 | **2.99x** | ✓ |
| CT Addition | 16384 | 12 | 0.309 | 0.860 | 0.36x | ✓ |
| CT Tensor Mul | 16384 | 12 | 4.366 | 0.882 | **4.95x** | ✓ |
| Poly Multiply | 32768 | 12 | 2.644 | 0.802 | **3.30x** | ✓ |
| CT Addition | 32768 | 12 | 1.675 | 1.570 | 1.07x | ✓ |
| CT Tensor Mul | 32768 | 12 | 9.509 | 1.761 | **5.40x** | ✓ |

### 3.3 GPU Acceleration Analysis

**When GPU is Beneficial:**
- NTT Inverse: Always faster for n ≥ 8192, L ≥ 3 (3.34x - 7.77x speedup)
- CT Tensor Multiply: Always faster (3.27x - 5.40x speedup)
- NTT Forward: Faster for n ≥ 16384 (1.38x - 3.10x speedup)
- Polynomial Multiply: Faster for n ≥ 8192 (1.44x - 3.30x speedup)

**When CPU is Faster:**
- CT Addition (small): Memory transfer overhead dominates for simple operations
- NTT Forward (small n): GPU kernel launch overhead

**Recommendation:**
- Use GPU for n ≥ 8192, L ≥ 3 for compute-intensive operations
- Keep CT Addition on CPU unless batching multiple operations

## 4. BFV Performance (n=8192, L=3, 50-bit primes)

### 4.1 Key Generation (CPU)

| Operation          | kctsb (ms) | SEAL (ms) | Speedup (SEAL/kctsb) |
|--------------------|------------|-----------|----------------------|
| Secret Key Gen     | 0.4        | 0.4       | 1.0x                 |
| Public Key Gen     | 2.5        | 2.8       | 1.12x                |
| Relin Key Gen      | 12.5       | 15.0      | 1.20x                |
| Galois Key Gen     | 150.0      | 180.0     | 1.20x ✓              |

### 4.2 Homomorphic Operations (GPU-Accelerated)

| Operation          | CPU (ms) | GPU (ms) | GPU Speedup |
|--------------------|----------|----------|-------------|
| Add                | 0.050    | 0.259    | 0.19x (use CPU) |
| Multiply (tensor)  | 0.586    | 0.179    | **3.27x** ✓ |
| Square             | ~0.5     | ~0.15    | ~3.3x ✓ |

## 5. Industrial Parameters (v4.15.0 Validated)

### 5.1 Parameter Set: n=16384, L=12 (Medium Depth)

| Operation          | CPU (ms) | GPU (ms) | Status |
|--------------------|----------|----------|--------|
| NTT Forward        | 2.31     | 1.68     | **GPU 1.38x** ✓ |
| NTT Inverse        | 8.30     | 1.55     | **GPU 5.36x** ✓ |
| CT Tensor Multiply | 4.37     | 0.88     | **GPU 4.95x** ✓ |
| Poly Multiply      | 1.26     | 0.42     | **GPU 2.99x** ✓ |

### 5.2 Parameter Set: n=32768, L=12 (Deep Circuits/Bootstrapping)

| Operation          | CPU (ms) | GPU (ms) | Status |
|--------------------|----------|----------|--------|
| NTT Forward        | 5.59     | 1.81     | **GPU 3.10x** ✓ |
| NTT Inverse        | 16.42    | 2.11     | **GPU 7.77x** ✓ |
| CT Tensor Multiply | 9.51     | 1.76     | **GPU 5.40x** ✓ |
| Poly Multiply      | 2.64     | 0.80     | **GPU 3.30x** ✓ |

### 5.3 Memory Usage

| Parameter Set      | Ciphertext (MB) | GPU VRAM (MB) | Notes |
|--------------------|-----------------|---------------|-------|
| n=8192, L=3        | 0.4             | ~10           | Light workloads |
| n=16384, L=12      | 3.0             | ~100          | Medium depth |
| n=32768, L=12      | 6.0             | ~200          | Deep circuits |

## 6. NTT-Friendly Primes (50-bit, n=32768)

Primes of form p = k × 32768 + 1 (50-bit, supports n up to 32768):

```
562949954142209   562949954961409   562949955125249   562949955551233
562949957287937   562949957386241   562949957779457   562949959581697
562949960335361   562949960564737   562949960728577   562949961842689
562949962203137   562949962530817   562949962825729
```

All primes verified with primitive n-th root of unity test: r^(n/2) ≡ -1 (mod p).

## 7. Optimization Roadmap

### 7.1 Phase 1: Core Implementation (v4.12.0) ✅
- [x] Pure RNS implementation (no NTL dependency)
- [x] BEHZ base extension for multiplication
- [x] NTL removal complete (native bignum module)
- [x] AVX2 NTT butterfly operations (conditional compile)
- [x] Rotation operations (Galois automorphisms)
- [x] GPU/CUDA detection (runtime)

### 7.2 Phase 2: SIMD Acceleration (v4.13.0) ✅
- [x] AVX2 NTT butterfly operations (enabled)
- [x] AVX-512 parallel coefficient processing
- [x] PCLMUL for GHASH/polynomial multiplication
- [x] Multi-precision arithmetic for large Q
- [ ] Intel HEXL integration (optional, future)

### 7.3 Phase 3: GPU Acceleration (v4.15.0) ✅
- [x] CUDA driver detection at runtime
- [x] **CUDA NTT implementation** (Harvey algorithm with Shoup)
- [x] **CUDA FHE kernels** (ct_add, ct_mul_tensor, relin)
- [x] **Unified CUDA directory** with independent CMake
- [x] **50-bit primes for n=32768**
- [x] **Runtime accelerator selection** (accelerator.h)
- [ ] Multi-GPU support (future)
- [ ] cuBLAS integration for batched operations (future)

### 7.4 Phase 4: Production Optimization (v4.16.0+) 🔄
- [ ] Async GPU pipeline (overlap H2D/kernel/D2H)
- [ ] Batched FHE operations (multiple ciphertexts)
- [ ] Memory pool for reduced allocation overhead
- [ ] CKKS GPU kernels (rescale, bootstrap)

## 8. Runtime Accelerator Selection

kctsb v4.15.0 includes automatic acceleration backend selection:

```c
#include <kctsb/advanced/accelerator.h>

// Detect available acceleration
uint32_t caps = kctsb_accel_detect();

// Check specific capabilities
if (kctsb_accel_has_cap(KCTSB_CAP_CUDA)) {
    printf("CUDA GPU available!\n");
}

// Get recommended backend for NTT
kctsb_accel_backend_t backend = kctsb_accel_select_ntt(32768, 12);
// Returns KCTSB_ACCEL_CUDA for n=32768, L=12

// Print full status
kctsb_accel_print_status();
```

Selection Logic:
- **n ≥ 8192, L ≥ 3 with CUDA**: Use GPU
- **AVX-512 available**: Use AVX-512
- **AVX2 available**: Use AVX2
- **Fallback**: Scalar CPU

## 9. Test Commands

```powershell
# Build CUDA benchmark (Windows + MSVC)
$env:CUDA_PATH = "D:\cuda125"
cmake -B build-cuda -S src/advanced/cuda -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-cuda --parallel

# Run NTT correctness test
.\build-cuda\bin\test_cuda_ntt.exe

# Run FHE benchmark
.\build-cuda\bin\benchmark_cuda_fhe.exe

# Run CPU-only benchmark
.\build\bin\kctsb_benchmark.exe --filter="FHE*"
```

## 10. References

1. Microsoft SEAL 4.1: https://github.com/microsoft/SEAL
2. BEHZ Paper: "A Full RNS Variant of FV-like Somewhat Homomorphic Encryption Schemes" (2016)
3. Harvey Butterfly: "Faster arithmetic for number-theoretic transforms" (2014)
4. Intel HEXL: https://github.com/intel/hexl
5. kctsb CUDA Implementation: `src/advanced/cuda/`

---
*Generated: 2026-01-25 | kctsb v4.15.0*
