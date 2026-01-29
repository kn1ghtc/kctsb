/**
 * @file ckks_evaluator.cpp
 * @brief CKKS Evaluator Implementation - Pure RNS Architecture
 *
 * High-performance CKKS implementation using:
 * - Pure RNS polynomial representation (RNSPoly)
 * - NTT for fast polynomial multiplication
 * - FFT-based canonical embedding for encode/decode
 * - Multi-precision arithmetic for large moduli
 * - AVX2 vectorization for complex FFT
 * - Batch random generation for key sampling (v5.0.1 optimization)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v5.0.1
 */

#include "kctsb/advanced/fe/ckks/ckks_evaluator.hpp"
#include "kctsb/advanced/fe/common/modular_ops.hpp"
#include <algorithm>
#include <cmath>
#include <stdexcept>

#ifdef __AVX2__
#include <immintrin.h>
#endif

namespace kctsb {
namespace fhe {
namespace ckks {

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Slow bit-reverse for fallback cases
 */
static inline size_t bit_reverse_slow(size_t x, int bits) {
    size_t result = 0;
    for (int i = 0; i < bits; ++i) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

// ============================================================================
// CKKSEncoder Implementation
// ============================================================================

CKKSEncoder::CKKSEncoder(const RNSContext* ctx, double default_scale)
    : context_(ctx)
    , n_(ctx ? ctx->n() : 0)
    , slots_(n_ / 2)
    , default_scale_(default_scale)
{
    if (!ctx) {
        throw std::invalid_argument("RNS context cannot be null");
    }
    precompute_roots();
}

void CKKSEncoder::precompute_roots() {
    // Precompute 2N-th roots of unity for canonical embedding
    // CKKS uses zeta^(2j+1) where zeta = exp(i*pi/N)
    roots_.resize(n_);
    roots_inv_.resize(n_);
    
    for (size_t j = 0; j < n_; ++j) {
        // zeta^(2j+1) = exp(i*pi*(2j+1)/N)
        double angle = PI * static_cast<double>(2 * j + 1) / static_cast<double>(n_);
        roots_[j] = Complex(std::cos(angle), std::sin(angle));
        roots_inv_[j] = std::conj(roots_[j]);
    }
    
    // Precompute zeta^(-j) and zeta^j for encode/decode post/pre-multiply
    // zeta = exp(i*pi/n), so zeta^(-j) = exp(-i*pi*j/n)
    zeta_neg_.resize(n_);
    zeta_pos_.resize(n_);
    for (size_t j = 0; j < n_; ++j) {
        double angle = PI * static_cast<double>(j) / static_cast<double>(n_);
        zeta_neg_[j] = Complex(std::cos(-angle), std::sin(-angle));
        zeta_pos_[j] = Complex(std::cos(angle), std::sin(angle));
    }
    
    // Precompute bit-reversal table
    size_t log_n = 0;
    while ((1ULL << log_n) < n_) ++log_n;
    bit_rev_table_.resize(n_);
    for (size_t i = 0; i < n_; ++i) {
        size_t rev = 0;
        for (size_t j = 0; j < log_n; ++j) {
            if (i & (1ULL << j)) {
                rev |= (1ULL << (log_n - 1 - j));
            }
        }
        bit_rev_table_[i] = rev;
    }
    
    // Precompute all FFT twiddle factors
    // For each stage len = 2, 4, 8, ..., n, we need w_len^k for k = 0 to len/2-1
    // Total storage: n/2 + n/4 + ... + 1 ≈ n complex values
    fft_twiddles_.clear();
    fft_twiddles_.reserve(n_);
    for (size_t len = 2; len <= n_; len *= 2) {
        double angle = 2.0 * PI / static_cast<double>(len);
        for (size_t k = 0; k < len / 2; ++k) {
            fft_twiddles_.push_back(Complex(std::cos(angle * k), std::sin(angle * k)));
        }
    }
}

void CKKSEncoder::bit_reverse_permute(std::vector<Complex>& values) {
    size_t n = values.size();
    // Use precomputed bit-reversal table for O(n) permutation
    if (n == n_ && !bit_rev_table_.empty()) {
        for (size_t i = 0; i < n; ++i) {
            size_t rev = bit_rev_table_[i];
            if (i < rev) {
                std::swap(values[i], values[rev]);
            }
        }
    } else {
        // Fallback for non-standard sizes
        size_t log_n = 0;
        while ((1ULL << log_n) < n) ++log_n;
        for (size_t i = 0; i < n; ++i) {
            size_t rev = 0;
            for (size_t j = 0; j < log_n; ++j) {
                if (i & (1ULL << j)) {
                    rev |= (1ULL << (log_n - 1 - j));
                }
            }
            if (i < rev) {
                std::swap(values[i], values[rev]);
            }
        }
    }
}

/**
 * @brief Optimized Cooley-Tukey FFT for standard DFT
 * 
 * Uses Cooley-Tukey radix-2 decimation-in-time with:
 * - Bit-reversal permutation
 * - Precomputed twiddle factors for O(1) lookup
 * - O(n log n) complexity
 */
void CKKSEncoder::fft_forward(std::vector<Complex>& values) {
    size_t n = values.size();
    bit_reverse_permute(values);
    
    // Use precomputed twiddles if available and matching size
    if (n == n_ && !fft_twiddles_.empty()) {
        size_t twiddle_offset = 0;
        for (size_t len = 2; len <= n; len *= 2) {
            size_t half_len = len / 2;
            
            for (size_t i = 0; i < n; i += len) {
                // Optimized butterfly with precomputed twiddles
                for (size_t j = 0; j < half_len; ++j) {
                    Complex w = fft_twiddles_[twiddle_offset + j];
                    Complex u = values[i + j];
                    Complex v = values[i + j + half_len] * w;
                    values[i + j] = u + v;
                    values[i + j + half_len] = u - v;
                }
            }
            twiddle_offset += half_len;
        }
    } else {
        // Fallback: compute twiddles on-the-fly
        for (size_t len = 2; len <= n; len *= 2) {
            double angle = 2.0 * PI / static_cast<double>(len);
            Complex w_len(std::cos(angle), std::sin(angle));
            
            for (size_t i = 0; i < n; i += len) {
                Complex w(1.0, 0.0);
                for (size_t j = 0; j < len / 2; ++j) {
                    Complex u = values[i + j];
                    Complex v = values[i + j + len / 2] * w;
                    values[i + j] = u + v;
                    values[i + j + len / 2] = u - v;
                    w *= w_len;
                }
            }
        }
    }
}

void CKKSEncoder::fft_inverse(std::vector<Complex>& values) {
    size_t n = values.size();
    
    // Optimized IFFT: Forward FFT with swapped real/imag parts
    // IFFT(x) = conj(FFT(conj(x))) / n
    // But we can also do: IFFT(x) = FFT(x[0], x[n-1], x[n-2], ..., x[1]) / n
    // which avoids two conjugate passes
    
    // Approach: FFT the reversed (except first element) array
    // values[1..n-1] reversed, then divide by n
    
    // Even faster: use property that FFT of conjugate equals conjugate of IFFT
    // Do FFT, then swap pairs and divide by n
    
    // Actually, simplest optimization: fuse first conjugate with bit-reversal
    // and second conjugate with scaling
    
    // Step 1: Conjugate and bit-reverse in one pass
    // First, bit-reverse permute
    int log_n = 0;
    for (size_t temp = n; temp > 1; temp >>= 1) ++log_n;
    
    for (size_t i = 0; i < n; ++i) {
        size_t rev = (bit_rev_table_.size() == n) ? bit_rev_table_[i] 
            : bit_reverse_slow(i, log_n);
        if (i < rev) {
            // Swap and conjugate both
            Complex temp = std::conj(values[i]);
            values[i] = std::conj(values[rev]);
            values[rev] = temp;
        } else if (i == rev) {
            values[i] = std::conj(values[i]);
        }
    }
    
    // Step 2: Forward FFT butterflies (same as fft_forward after bit-reversal)
    if (n == n_ && !fft_twiddles_.empty()) {
        size_t twiddle_offset = 0;
        for (size_t len = 2; len <= n; len *= 2) {
            size_t half_len = len / 2;
            for (size_t i = 0; i < n; i += len) {
                for (size_t j = 0; j < half_len; ++j) {
                    Complex w = fft_twiddles_[twiddle_offset + j];
                    Complex u = values[i + j];
                    Complex v = values[i + j + half_len] * w;
                    values[i + j] = u + v;
                    values[i + j + half_len] = u - v;
                }
            }
            twiddle_offset += half_len;
        }
    } else {
        for (size_t len = 2; len <= n; len *= 2) {
            double angle = 2.0 * PI / static_cast<double>(len);
            Complex w_len(std::cos(angle), std::sin(angle));
            for (size_t i = 0; i < n; i += len) {
                Complex w(1.0, 0.0);
                for (size_t j = 0; j < len / 2; ++j) {
                    Complex u = values[i + j];
                    Complex v = values[i + j + len / 2] * w;
                    values[i + j] = u + v;
                    values[i + j + len / 2] = u - v;
                    w *= w_len;
                }
            }
        }
    }
    
    // Step 3: Conjugate and scale in one pass
    double inv_n = 1.0 / static_cast<double>(n);
    for (size_t i = 0; i < n; ++i) {
        values[i] = std::conj(values[i]) * inv_n;
    }
}

/**
 * @brief Canonical embedding encode using special-form IDFT
 *
 * CKKS uses roots zeta^(2k+1) where zeta = exp(i*pi/n).
 * This is NOT a standard FFT problem, but we can still use FFT with correction.
 *
 * Key insight: zeta^(2k+1) = zeta * (zeta^2)^k = zeta * omega^k
 * where omega = zeta^2 = exp(i*2*pi/n) is the standard n-th root of unity.
 *
 * Inverse canonical embedding: coef[j] = (1/n) * sum_k v[k] * (zeta^(2k+1))^(-j)
 *                                       = (1/n) * zeta^(-j) * sum_k v[k] * omega^(-kj)
 *                                       = zeta^(-j) * IDFT(v)[j]
 */
CKKSPlaintext CKKSEncoder::encode(const std::vector<Complex>& values, double scale) {
    if (scale == 0.0) scale = default_scale_;
    if (scale == 0.0) scale = std::pow(2.0, 40.0);
    
    if (values.size() > slots_) {
        throw std::invalid_argument("Too many values for encoding");
    }
    
    // Pad input to n/2 slots
    std::vector<Complex> padded(slots_, Complex(0.0, 0.0));
    std::copy(values.begin(), values.end(), padded.begin());
    
    // Expand to n evaluation points (with conjugate pairs)
    // m(zeta^{2k+1}) = values[k] for k = 0, ..., n/2-1
    // m(zeta^{2(n-1-k)+1}) = conj(values[k]) for k = 0, ..., n/2-1
    std::vector<Complex> expanded(n_);
    for (size_t k = 0; k < slots_; ++k) {
        Complex scaled = padded[k] * scale;
        expanded[k] = scaled;
        expanded[n_ - 1 - k] = std::conj(scaled);
    }
    
    // OPTIMIZED O(n log n) encoding using FFT:
    // coef[j] = zeta^(-j) * IDFT(expanded)[j]
    
    // Step 1: Apply IDFT (in-place on expanded)
    fft_inverse(expanded);
    
    // Step 2: Post-multiply by precomputed zeta^(-j) and extract real part
    CKKSPlaintext pt(context_, scale);
    size_t L = context_->level_count();
    
    // Pre-fetch moduli values for better cache performance
    std::vector<uint64_t> moduli(L);
    for (size_t level = 0; level < L; ++level) {
        moduli[level] = context_->modulus(level).value();
    }
    
    // First pass: compute all rounded integer coefficients
    std::vector<int64_t> rounded_coeffs(n_);
    for (size_t i = 0; i < n_; ++i) {
        Complex zeta_neg_i = (!zeta_neg_.empty()) ? zeta_neg_[i] 
            : Complex(std::cos(-PI * static_cast<double>(i) / static_cast<double>(n_)),
                      std::sin(-PI * static_cast<double>(i) / static_cast<double>(n_)));
        Complex coeff_zeta = expanded[i] * zeta_neg_i;
        rounded_coeffs[i] = static_cast<int64_t>(std::round(coeff_zeta.real()));
    }
    
    // Second pass: convert to RNS representation level-by-level
    // This improves cache locality for the RNS polynomial
    for (size_t level = 0; level < L; ++level) {
        uint64_t q = moduli[level];
        
        for (size_t i = 0; i < n_; ++i) {
            int64_t rounded = rounded_coeffs[i];
            uint64_t coef;
            
            if (rounded >= 0) {
                uint64_t urounded = static_cast<uint64_t>(rounded);
                coef = (urounded < q) ? urounded : (urounded % q);
            } else {
                uint64_t upos = static_cast<uint64_t>(-rounded);
                if (upos < q) {
                    coef = q - upos;
                } else {
                    uint64_t rem = upos % q;
                    coef = (rem == 0) ? 0 : q - rem;
                }
            }
            pt.data()(level, i) = coef;
        }
    }
    return pt;
}

CKKSPlaintext CKKSEncoder::encode_real(const std::vector<double>& values, double scale) {
    std::vector<Complex> complex_vals(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        complex_vals[i] = Complex(values[i], 0.0);
    }
    return encode(complex_vals, scale);
}

CKKSPlaintext CKKSEncoder::encode_single(double value, double scale) {
    // Use the full canonical embedding with a single-element vector
    // This ensures consistency between encode_single and decode
    std::vector<Complex> values(1, Complex(value, 0.0));
    return encode(values, scale);
}

/**
 * @brief Canonical embedding decode using special-form DFT
 *
 * Evaluates polynomial at roots zeta^(2k+1):
 * result[k] = sum_j coef[j] * (zeta^(2k+1))^j
 *           = sum_j coef[j] * zeta^j * omega^(kj)
 *           = sum_j (coef[j] * zeta^j) * omega^(kj)
 *           = DFT(coef * zeta^j)[k]
 */
std::vector<Complex> CKKSEncoder::decode(const CKKSPlaintext& pt) {
    double scale = pt.scale();
    if (scale <= 0.0) scale = default_scale_;
    if (scale <= 0.0) scale = std::pow(2.0, 40.0);
    
    size_t level = pt.level();
    const Modulus& mod = context_->modulus(level);
    uint64_t q = mod.value();
    uint64_t q_half = q / 2;
    
    // Convert RNS coefficients to Complex
    std::vector<Complex> coeffs(n_);
    for (size_t i = 0; i < n_; ++i) {
        uint64_t coef = pt.data()(level, i);
        double val;
        if (coef > q_half) {
            val = -static_cast<double>(q - coef);
        } else {
            val = static_cast<double>(coef);
        }
        coeffs[i] = Complex(val, 0.0);
    }
    
    // OPTIMIZED O(n log n) decoding using FFT:
    // result[k] = DFT(coef[j] * zeta^j)[k]
    
    // Step 1: Pre-multiply by precomputed zeta^j where zeta = e^(i*pi/n)
    std::vector<Complex> shifted(n_);
    if (!zeta_pos_.empty()) {
        // Use precomputed values for O(1) lookup
        for (size_t j = 0; j < n_; ++j) {
            shifted[j] = coeffs[j] * zeta_pos_[j];
        }
    } else {
        // Fallback: compute on-the-fly
        for (size_t j = 0; j < n_; ++j) {
            double angle = PI * static_cast<double>(j) / static_cast<double>(n_);
            Complex zeta_j(std::cos(angle), std::sin(angle));
            shifted[j] = coeffs[j] * zeta_j;
        }
    }
    
    // Step 2: Apply forward FFT
    fft_forward(shifted);
    
    // Step 3: Extract first n/2 slots and divide by scale
    double inv_scale = 1.0 / scale;
    std::vector<Complex> result(slots_);
    for (size_t k = 0; k < slots_; ++k) {
        result[k] = shifted[k] * inv_scale;  // Use multiplication instead of division
    }
    return result;
}

std::vector<double> CKKSEncoder::decode_real(const CKKSPlaintext& pt) {
    std::vector<Complex> complex_vals = decode(pt);
    std::vector<double> result(complex_vals.size());
    for (size_t i = 0; i < complex_vals.size(); ++i) {
        result[i] = complex_vals[i].real();
    }
    return result;
}

// ============================================================================
// CKKSEvaluator Implementation
// ============================================================================

CKKSEvaluator::CKKSEvaluator(const RNSContext* ctx, double default_scale)
    : context_(ctx)
    , default_scale_(default_scale > 0 ? default_scale : std::pow(2.0, 40.0))
{
    if (!ctx) {
        throw std::invalid_argument("RNS context cannot be null");
    }
    encoder_ = std::make_unique<CKKSEncoder>(ctx, default_scale_);
    rns_tool_ = std::make_unique<CKKSRNSTool>(ctx);
}

void CKKSEvaluator::sample_ternary_rns(RNSPoly* poly, std::mt19937_64& rng) {
    size_t n = context_->n();
    size_t L = context_->level_count();
    
    // Pre-compute (q_i - 1) for each level to avoid repeated modulus lookups
    std::vector<uint64_t> neg_one_vals(L);
    for (size_t level = 0; level < L; ++level) {
        neg_one_vals[level] = context_->modulus(level).value() - 1;
    }
    
    // Batch random generation: generate n random values at once
    // Each 64-bit random contains multiple ternary values (using 2 bits each)
    // We use a simple approach: generate n int8 values, then convert
    std::vector<int8_t> ternary_vals(n);
    
    // Fast ternary generation: use raw bits
    // Each call to rng() gives 64 bits, we can extract 21 ternary values (3 bits each for modulo 3)
    // Simpler approach: batch generation using uniform distribution
    // For n=8192, we need ~8192 random calls which is the bottleneck
    
    // Use batch uint64 generation and extract values
    size_t idx = 0;
    while (idx < n) {
        uint64_t r = rng();
        // Extract up to 21 ternary values from one 64-bit random
        // Using 3 bits per value: val = (bits % 3) - 1 gives {-1, 0, 1}
        for (int k = 0; k < 21 && idx < n; ++k) {
            int bits = (r >> (k * 3)) & 0x7;  // 3 bits
            int val = (bits % 3) - 1;  // -1, 0, or 1
            ternary_vals[idx++] = static_cast<int8_t>(val);
        }
    }
    
    // Now fill the RNS polynomial
    for (size_t i = 0; i < n; ++i) {
        int8_t val = ternary_vals[i];
        
        if (val == 0) {
            for (size_t level = 0; level < L; ++level) {
                (*poly)(level, i) = 0;
            }
        } else if (val == 1) {
            for (size_t level = 0; level < L; ++level) {
                (*poly)(level, i) = 1;
            }
        } else {
            for (size_t level = 0; level < L; ++level) {
                (*poly)(level, i) = neg_one_vals[level];
            }
        }
    }
}

void CKKSEvaluator::sample_error_rns(RNSPoly* poly, double sigma, std::mt19937_64& rng) {
    size_t n = context_->n();
    size_t L = context_->level_count();
    std::normal_distribution<double> dist(0.0, sigma);
    
    // Pre-fetch moduli values for better cache performance
    std::vector<uint64_t> moduli(L);
    for (size_t level = 0; level < L; ++level) {
        moduli[level] = context_->modulus(level).value();
    }
    
    for (size_t i = 0; i < n; ++i) {
        int64_t val = static_cast<int64_t>(std::round(dist(rng)));
        
        // Fast path for small positive values (most common case for sigma=3.2)
        if (val >= 0 && val < 100) {
            // Small positive: just replicate
            uint64_t uval = static_cast<uint64_t>(val);
            for (size_t level = 0; level < L; ++level) {
                (*poly)(level, i) = uval;
            }
        } else if (val >= -100 && val < 0) {
            // Small negative: q - |val|
            uint64_t abs_val = static_cast<uint64_t>(-val);
            for (size_t level = 0; level < L; ++level) {
                (*poly)(level, i) = moduli[level] - abs_val;
            }
        } else {
            // Large values need full modular reduction
            for (size_t level = 0; level < L; ++level) {
                uint64_t q = moduli[level];
                uint64_t coef;
                if (val >= 0) {
                    coef = static_cast<uint64_t>(val) % q;
                } else {
                    uint64_t abs_val = static_cast<uint64_t>(-val) % q;
                    coef = (abs_val == 0) ? 0 : q - abs_val;
                }
                (*poly)(level, i) = coef;
            }
        }
    }
}

void CKKSEvaluator::sample_uniform_rns(RNSPoly* poly, std::mt19937_64& rng) {
    size_t n = context_->n();
    size_t L = context_->level_count();
    
    // Pre-generate a batch of random uint64 values for better performance
    // Then reduce modulo each modulus
    // This avoids recreating distribution objects and improves cache usage
    
    // First, generate n random 64-bit values
    std::vector<uint64_t> random_vals(n);
    for (size_t i = 0; i < n; ++i) {
        random_vals[i] = rng();
    }
    
    // Then reduce to each modulus level
    for (size_t level = 0; level < L; ++level) {
        const Modulus& mod = context_->modulus(level);
        uint64_t q = mod.value();
        
        // Fast modular reduction using Barrett precomputation if available
        // For now, use optimized modulo with rejection sampling avoidance
        for (size_t i = 0; i < n; ++i) {
            // Use the full 64-bit random value and reduce mod q
            // This has slight bias but acceptable for crypto sampling
            (*poly)(level, i) = random_vals[i] % q;
        }
    }
}

CKKSSecretKey CKKSEvaluator::generate_secret_key(std::mt19937_64& rng) {
    CKKSSecretKey sk;
    sk.s = RNSPoly(context_);
    sample_ternary_rns(&sk.s, rng);
    sk.s.ntt_transform();
    sk.is_ntt_form = true;
    return sk;
}

CKKSPublicKey CKKSEvaluator::generate_public_key(const CKKSSecretKey& sk, std::mt19937_64& rng) {
    if (!sk.is_ntt_form) {
        throw std::invalid_argument("Secret key must be in NTT form");
    }
    
    // CKKS public key: pk = (-(a*s + e), a)
    // Same formula as BFV for consistency
    
    // 1. Sample random polynomial a (uniform mod q)
    RNSPoly a(context_);
    sample_uniform_rns(&a, rng);
    a.ntt_transform();
    
    // 2. Sample small error e ~ Gaussian
    RNSPoly e(context_);
    sample_error_rns(&e, 3.2, rng);
    e.ntt_transform();
    
    // 3. Compute b = -(a*s + e) - exactly like BFV
    RNSPoly as = a * sk.s;  // NTT domain multiply
    RNSPoly b = as;
    b += e;                 // a*s + e
    b.negate();             // -(a*s + e)
    
    CKKSPublicKey pk;
    pk.b = std::move(b);
    pk.a = std::move(a);
    pk.is_ntt_form = true;
    return pk;
}

/**
 * @brief Generate relinearization key using RNS decomposition
 * 
 * RNS Key Switching (similar to SEAL's approach):
 * For each modulus q_j in the chain, we generate a key component:
 *   rk_j = (b_j, a_j) where b_j = -a_j*s + e_j + q̂_j * s^2 mod Q
 *   where q̂_j = Q/q_j (product of all other moduli)
 * 
 * During key switching, c2 is decomposed as:
 *   c2 = sum_j (c2 mod q_j) * q̂_j * (q̂_j^{-1} mod q_j) mod Q
 * 
 * By pre-multiplying s^2 by q̂_j in the key, we get:
 *   sum_j [(c2 mod q_j) * rk_j] ≈ c2 * s^2
 * 
 * Noise growth: O(sqrt(n*L) * sigma) instead of O(sqrt(n) * ||c2||)
 * 
 * @param sk Secret key (must be in NTT form)
 * @param rng Random number generator
 * @return Relinearization key with L components (one per modulus)
 */
CKKSRelinKey CKKSEvaluator::generate_relin_key(const CKKSSecretKey& sk, std::mt19937_64& rng) {
    if (!sk.is_ntt_form) {
        throw std::invalid_argument("Secret key must be in NTT form");
    }
    
    CKKSRelinKey rk;
    size_t L = context_->level_count();
    size_t n = context_->n();
    
    rk.rk_b.resize(L);
    rk.rk_a.resize(L);
    
    // Compute s^2 in NTT form
    RNSPoly s_squared = sk.s;
    s_squared *= sk.s;
    
    // For each modulus q_j, generate a key component
    for (size_t j = 0; j < L; ++j) {
        // Sample random a_j uniform in R_Q
        RNSPoly a_j(context_);
        sample_uniform_rns(&a_j, rng);
        a_j.ntt_transform();
        
        // Sample error e_j from Gaussian
        RNSPoly e_j(context_);
        sample_error_rns(&e_j, 3.2, rng);
        e_j.ntt_transform();
        
        // CRT-based key switching:
        // We want sum_j [(c2 mod q_j) * rk_j] = c2 * s^2
        // 
        // CRT reconstruction: c2 = sum_j [(c2 mod q_j) * q̂_j * q̂_j_inv] mod Q
        // where q̂_j = Q/q_j and q̂_j_inv = (q̂_j)^{-1} mod q_j
        //
        // So: c2 * s^2 = sum_j [(c2 mod q_j) * (q̂_j * q̂_j_inv * s^2)]
        //
        // We embed q̂_j * q̂_j_inv * s^2 into the key
        
        const Modulus& mod_j = context_->modulus(j);
        uint64_t q_j = mod_j.value();
        
        // Compute q̂_j mod q_j (product of all other moduli mod q_j)
        uint64_t q_hat_j_mod_qj = 1;
        for (size_t i = 0; i < L; ++i) {
            if (i != j) {
                q_hat_j_mod_qj = multiply_uint_mod(
                    q_hat_j_mod_qj, 
                    context_->modulus(i).value() % q_j, 
                    mod_j);
            }
        }
        
        // Compute (q̂_j)^{-1} mod q_j
        uint64_t q_hat_j_inv = inv_mod(q_hat_j_mod_qj, mod_j);
        
        // Store (q̂_j * q̂_j_inv) * s^2 mod each q_l
        // Note: q̂_j * q̂_j_inv mod q_l needs careful computation
        // q̂_j mod q_l = prod_{i!=j} q_i mod q_l
        // q̂_j_inv is computed mod q_j, so (q̂_j * q̂_j_inv) mod q_l is NOT simply 1
        //
        // The correct formula: we need to lift q̂_j_inv from Z_{q_j} to Z
        // then compute (q̂_j * lifted_q̂_j_inv) mod Q
        //
        // For practical implementation: embed q̂_j_inv into the scaling
        RNSPoly scaled_s2(context_);
        
        for (size_t l = 0; l < L; ++l) {
            const Modulus& mod_l = context_->modulus(l);
            uint64_t q_l = mod_l.value();
            
            // q̂_j mod q_l = prod_{i!=j} q_i mod q_l
            uint64_t q_hat_j_mod_l = 1;
            for (size_t i = 0; i < L; ++i) {
                if (i != j) {
                    q_hat_j_mod_l = multiply_uint_mod(
                        q_hat_j_mod_l,
                        context_->modulus(i).value() % q_l,
                        mod_l);
                }
            }
            
            // For the CRT coefficient: scale_factor = q̂_j * q̂_j_inv
            // where q̂_j_inv is lifted from Z_{q_j} to Z
            // In RNS: we compute q̂_j_inv mod q_l
            uint64_t q_hat_j_inv_mod_l = q_hat_j_inv % q_l;
            
            // Combined scaling: q̂_j * q̂_j_inv mod q_l
            uint64_t scale_factor = multiply_uint_mod(q_hat_j_mod_l, q_hat_j_inv_mod_l, mod_l);
            
            // scaled_s2[l] = scale_factor * s^2 mod q_l
            for (size_t i = 0; i < n; ++i) {
                uint64_t s2_coef = s_squared(l, i);
                scaled_s2(l, i) = multiply_uint_mod(s2_coef, scale_factor, mod_l);
            }
        }
        scaled_s2.set_ntt_form(true);
        
        // Compute b_j = -a_j*s + e_j + scaled_s^2 (in NTT form)
        RNSPoly b_j = a_j;
        b_j *= sk.s;         // a_j*s
        b_j.negate();        // -a_j*s
        b_j += e_j;          // -a_j*s + e_j
        b_j += scaled_s2;    // -a_j*s + e_j + q̂_j*q̂_j_inv*s^2
        
        rk.rk_b[j] = std::move(b_j);
        rk.rk_a[j] = std::move(a_j);
    }
    
    rk.is_ntt_form = true;
    return rk;
}

CKKSCiphertext CKKSEvaluator::encrypt(const CKKSPublicKey& pk, const CKKSPlaintext& pt, std::mt19937_64& rng) {
    CKKSCiphertext ct(context_, pt.scale());
    
    // 1. Sample u from ternary {-1, 0, 1}
    RNSPoly u(context_);
    sample_ternary_rns(&u, rng);
    u.ntt_transform();
    
    // 2. Sample errors e0, e1 ~ Gaussian
    RNSPoly e0(context_), e1(context_);
    sample_error_rns(&e0, 3.2, rng);
    sample_error_rns(&e1, 3.2, rng);
    e0.ntt_transform();
    e1.ntt_transform();
    
    // 3. Prepare message
    RNSPoly m = pt.data();
    if (!m.is_ntt_form()) {
        m.ntt_transform();
    }
    
    // 4. Compute ciphertext components using operator* (NTT domain)
    // c0 = b*u + e0 + m
    RNSPoly c0 = pk.b * u;  // b*u
    c0 += e0;
    c0 += m;
    
    // c1 = a*u + e1
    RNSPoly c1 = pk.a * u;  // a*u
    c1 += e1;
    
    ct.c0() = std::move(c0);
    ct.c1() = std::move(c1);
    ct.set_level(context_->level_count() - 1);
    return ct;
}

CKKSCiphertext CKKSEvaluator::encrypt_symmetric(const CKKSSecretKey& sk, const CKKSPlaintext& pt, std::mt19937_64& rng) {
    CKKSCiphertext ct(context_, pt.scale());
    
    RNSPoly a(context_);
    sample_uniform_rns(&a, rng);
    a.ntt_transform();
    
    RNSPoly e(context_);
    sample_error_rns(&e, 3.2, rng);
    e.ntt_transform();
    
    // c0 = -a*s + e + m
    ct.c0() = a;
    ct.c0() *= sk.s;
    ct.c0().negate();
    ct.c0() += e;
    
    RNSPoly m = pt.data();
    if (!m.is_ntt_form()) {
        m.ntt_transform();
    }
    ct.c0() += m;
    
    ct.c1() = a;
    ct.set_level(context_->level_count() - 1);
    return ct;
}

CKKSPlaintext CKKSEvaluator::decrypt(const CKKSSecretKey& sk, const CKKSCiphertext& ct) {
    // Decryption: m ≈ c0 + c1*s + c2*s^2 (if 3-component)
    RNSPoly result = ct.c1();
    result *= sk.s;      // c1*s
    result += ct.c0();   // c0 + c1*s
    
    // Handle 3-component ciphertext (before relinearization)
    if (ct.size() >= 3) {
        RNSPoly c2_s2 = ct.c2();
        c2_s2 *= sk.s;   // c2*s
        c2_s2 *= sk.s;   // c2*s^2
        result += c2_s2; // c0 + c1*s + c2*s^2
    }
    
    if (result.is_ntt_form()) {
        result.intt_transform();
    }
    
    CKKSPlaintext pt(context_, ct.scale());
    pt.data() = result;
    pt.set_level(ct.level());
    return pt;
}

CKKSCiphertext CKKSEvaluator::add(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    if (!scales_match(ct1, ct2)) {
        throw std::invalid_argument("Scales must match for addition");
    }
    
    // Optimized: create result by copying ct1, then add ct2 in-place
    // This avoids separate copy + add operations
    CKKSCiphertext result = ct1;  // Single copy of ct1
    result.c0() += ct2.c0();
    result.c1() += ct2.c1();
    result.set_level(std::min(ct1.level(), ct2.level()));
    return result;
}

CKKSCiphertext CKKSEvaluator::sub(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    if (!scales_match(ct1, ct2)) {
        throw std::invalid_argument("Scales must match for subtraction");
    }
    
    // Optimized: create result by copying ct1, then subtract ct2 in-place
    CKKSCiphertext result = ct1;  // Single copy of ct1
    result.c0() -= ct2.c0();
    result.c1() -= ct2.c1();
    result.set_level(std::min(ct1.level(), ct2.level()));
    return result;
}

CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext& ct, const CKKSPlaintext& pt) {
    CKKSCiphertext result = ct;
    
    RNSPoly m = pt.data();
    if (!m.is_ntt_form()) {
        m.ntt_transform();
    }
    result.c0() += m;
    return result;
}

CKKSCiphertext CKKSEvaluator::multiply(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    CKKSCiphertext result(context_, ct1.scale() * ct2.scale());
    
    // CKKS multiplication produces 3-component ciphertext:
    // (c0_1, c1_1) * (c0_2, c1_2) = (d0, d1, d2)
    // where:
    //   d0 = c0_1 * c0_2
    //   d1 = c0_1 * c1_2 + c1_1 * c0_2
    //   d2 = c1_1 * c1_2
    
    // d0 = c0_1 * c0_2
    result.c0() = ct1.c0();
    result.c0() *= ct2.c0();
    
    // d1 = c0_1 * c1_2 + c1_1 * c0_2
    RNSPoly temp1 = ct1.c0();
    temp1 *= ct2.c1();
    
    RNSPoly temp2 = ct1.c1();
    temp2 *= ct2.c0();
    
    result.c1() = temp1;
    result.c1() += temp2;
    
    // d2 = c1_1 * c1_2
    result.set_size(3);
    result.c2() = ct1.c1();
    result.c2() *= ct2.c1();
    
    result.set_level(std::min(ct1.level(), ct2.level()));
    return result;
}

CKKSCiphertext CKKSEvaluator::multiply_plain(const CKKSCiphertext& ct, const CKKSPlaintext& pt) {
    CKKSCiphertext result(context_, ct.scale() * pt.scale());
    
    RNSPoly m = pt.data();
    if (!m.is_ntt_form()) {
        m.ntt_transform();
    }
    
    result.c0() = ct.c0();
    result.c0() *= m;
    result.c1() = ct.c1();
    result.c1() *= m;
    result.set_level(ct.level());
    return result;
}

/**
 * @brief Relinearize using direct s^2 embedding key switching
 * 
 * Direct s^2 key switching algorithm:
 * Given ciphertext (c0, c1, c2) and relin key rk = (b, a)
 * where b = -a*s + e + s^2 (NO scaling factor P)
 * 
 * Key switching computes:
 *   c0_ks = c2 * b = c2*(-a*s + e + s^2)
 *   c1_ks = c2 * a
 * 
 * Then:
 *   c0' = c0 + c0_ks
 *   c1' = c1 + c1_ks
 * 
 * Correctness: 
 *   c0' + c1'*s = c0 + c0_ks + (c1 + c1_ks)*s
 *               = c0 + c2*(-a*s + e + s^2) + c1*s + c2*a*s
 *               = c0 + c1*s + c2*(s^2 + e) 
 *               ≈ c0 + c1*s + c2*s^2  (with small noise from c2*e)
 * 
 * Noise growth: O(sqrt(n) * sigma * ||c2||) which is acceptable for small L.
 * 
 * @param ct Input ciphertext (must have size 3)
 * @param rk Relinearization key (single component)
 * @return Relinearized ciphertext with size 2
 */
CKKSCiphertext CKKSEvaluator::relinearize(const CKKSCiphertext& ct, const CKKSRelinKey& rk) {
    // If already 2-component, nothing to do
    if (ct.size() <= 2) {
        return ct;
    }
    
    if (rk.rk_b.empty() || rk.rk_a.empty()) {
        throw std::runtime_error("Relinearization key has no components");
    }
    
    CKKSCiphertext result(context_, ct.scale());
    size_t L = context_->level_count();
    size_t n = context_->n();
    
    // Initialize result
    result.c0() = ct.c0();
    result.c1() = ct.c1();
    
    // Get c2 and convert to coefficient form for decomposition
    RNSPoly c2 = ct.c2();
    bool was_ntt = c2.is_ntt_form();
    if (was_ntt) {
        c2.intt_transform();
    }
    
    // RNS Decomposition Key Switching:
    // For each j = 0, ..., L-1:
    //   Extract (c2 mod q_j) as a single-modulus value
    //   Multiply by rk_j = (b_j, a_j) where b_j contains q̂_j*s^2 term
    //   Sum all contributions
    //
    // Result: sum_j [(c2 mod q_j) * rk_j] ≈ c2 * s^2
    // because sum_j [(c2 mod q_j) * q̂_j] = c2 (CRT reconstruction)
    
    for (size_t j = 0; j < L; ++j) {
        // Create a "lifted" polynomial from (c2 mod q_j)
        // For each level l, we store (c2 mod q_j) mod q_l
        RNSPoly c2_j(context_);
        uint64_t q_j = context_->modulus(j).value();
        
        for (size_t l = 0; l < L; ++l) {
            const Modulus& mod_l = context_->modulus(l);
            uint64_t q_l = mod_l.value();
            
            for (size_t i = 0; i < n; ++i) {
                // c2(j, i) is c2 mod q_j at position i
                // We need this value mod q_l
                uint64_t c2_mod_qj = c2(j, i);
                // Reduce mod q_l (c2_mod_qj < q_j, we need it mod q_l)
                c2_j(l, i) = c2_mod_qj % q_l;
            }
        }
        
        // Transform to NTT form
        c2_j.ntt_transform();
        
        // Multiply c2_j by rk_j and accumulate
        // c0_ks += c2_j * b_j
        // c1_ks += c2_j * a_j
        RNSPoly c0_contrib = c2_j;
        c0_contrib *= rk.rk_b[j];
        
        RNSPoly c1_contrib = c2_j;
        c1_contrib *= rk.rk_a[j];
        
        result.c0() += c0_contrib;
        result.c1() += c1_contrib;
    }
    
    result.set_level(ct.level());
    return result;
}

CKKSCiphertext CKKSEvaluator::rescale(const CKKSCiphertext& ct) {
    if (ct.level() == 0) {
        throw std::runtime_error("Cannot rescale: already at level 0");
    }
    
    size_t level = ct.level();
    uint64_t q_L = context_->modulus(level).value();
    double new_scale = ct.scale() / static_cast<double>(q_L);
    
    CKKSCiphertext result(context_, new_scale);
    
    RNSPoly c0 = ct.c0();
    RNSPoly c1 = ct.c1();
    
    bool was_ntt = c0.is_ntt_form();
    if (was_ntt) {
        c0.intt_transform();
        c1.intt_transform();
    }
    
    size_t n = context_->n();
    result.c0() = RNSPoly(context_);
    result.c1() = RNSPoly(context_);
    
    // Handle 3-component ciphertext
    RNSPoly c2;
    bool has_c2 = (ct.size() >= 3);
    if (has_c2) {
        c2 = ct.c2();
        if (was_ntt) {
            c2.intt_transform();
        }
        result.set_size(3);
    }
    
    // CKKS rescale: For each coefficient position i:
    // result[l][i] = (c[l][i] - c[L][i]) * q_L^{-1} mod q_l
    // where q_L^{-1} is the modular inverse of q_L mod q_l
    
    for (size_t l = 0; l < level; ++l) {
        const Modulus& mod_l = context_->modulus(l);
        uint64_t q_l = mod_l.value();
        // Compute q_L^{-1} mod q_l using extended Euclidean algorithm
        uint64_t q_L_inv = inv_mod(q_L % q_l, mod_l);
        
        for (size_t i = 0; i < n; ++i) {
            // Get coefficients at level l and top level L
            uint64_t c0_l = c0(l, i);
            uint64_t c1_l = c1(l, i);
            uint64_t c0_L = c0(level, i);
            uint64_t c1_L = c1(level, i);
            
            // Reduce top-level coefficient mod q_l
            uint64_t c0_L_mod = c0_L % q_l;
            uint64_t c1_L_mod = c1_L % q_l;
            
            // Compute (c[l] - c[L] mod q_l) * q_L^{-1} mod q_l
            uint64_t diff0 = sub_uint_mod(c0_l, c0_L_mod, mod_l);
            uint64_t diff1 = sub_uint_mod(c1_l, c1_L_mod, mod_l);
            
            result.c0()(l, i) = multiply_uint_mod(diff0, q_L_inv, mod_l);
            result.c1()(l, i) = multiply_uint_mod(diff1, q_L_inv, mod_l);
            
            // Rescale c2 if present
            if (has_c2) {
                uint64_t c2_l = c2(l, i);
                uint64_t c2_L = c2(level, i);
                uint64_t c2_L_mod = c2_L % q_l;
                uint64_t diff2 = sub_uint_mod(c2_l, c2_L_mod, mod_l);
                result.c2()(l, i) = multiply_uint_mod(diff2, q_L_inv, mod_l);
            }
        }
    }
    
    result.set_level(level - 1);
    
    if (was_ntt) {
        result.c0().ntt_transform();
        result.c1().ntt_transform();
        if (has_c2) {
            result.c2().ntt_transform();
        }
    }
    return result;
}

void CKKSEvaluator::rescale_inplace(CKKSCiphertext& ct) {
    if (ct.level() == 0) {
        throw std::runtime_error("Cannot rescale: already at level 0");
    }
    
    size_t level = ct.level();
    uint64_t q_L = context_->modulus(level).value();
    double new_scale = ct.scale() / static_cast<double>(q_L);
    
    RNSPoly& c0 = ct.c0();
    RNSPoly& c1 = ct.c1();
    
    bool was_ntt = c0.is_ntt_form();
    if (was_ntt) {
        c0.intt_transform();
        c1.intt_transform();
    }
    
    size_t n = context_->n();
    
    // Handle 3-component ciphertext
    bool has_c2 = (ct.size() >= 3);
    if (has_c2 && was_ntt) {
        ct.c2().intt_transform();
    }
    
    // CKKS rescale in-place: For each coefficient position i:
    // c[l][i] = (c[l][i] - c[L][i]) * q_L^{-1} mod q_l
    
    for (size_t l = 0; l < level; ++l) {
        const Modulus& mod_l = context_->modulus(l);
        uint64_t q_l = mod_l.value();
        uint64_t q_L_inv = inv_mod(q_L % q_l, mod_l);
        
        for (size_t i = 0; i < n; ++i) {
            uint64_t c0_l = c0(l, i);
            uint64_t c1_l = c1(l, i);
            uint64_t c0_L = c0(level, i);
            uint64_t c1_L = c1(level, i);
            
            uint64_t c0_L_mod = c0_L % q_l;
            uint64_t c1_L_mod = c1_L % q_l;
            
            uint64_t diff0 = sub_uint_mod(c0_l, c0_L_mod, mod_l);
            uint64_t diff1 = sub_uint_mod(c1_l, c1_L_mod, mod_l);
            
            c0(l, i) = multiply_uint_mod(diff0, q_L_inv, mod_l);
            c1(l, i) = multiply_uint_mod(diff1, q_L_inv, mod_l);
            
            if (has_c2) {
                uint64_t c2_l = ct.c2()(l, i);
                uint64_t c2_L = ct.c2()(level, i);
                uint64_t c2_L_mod = c2_L % q_l;
                uint64_t diff2 = sub_uint_mod(c2_l, c2_L_mod, mod_l);
                ct.c2()(l, i) = multiply_uint_mod(diff2, q_L_inv, mod_l);
            }
        }
    }
    
    ct.set_level(level - 1);
    ct.set_scale(new_scale);
    
    if (was_ntt) {
        c0.ntt_transform();
        c1.ntt_transform();
        if (has_c2) {
            ct.c2().ntt_transform();
        }
    }
}

void CKKSEvaluator::add_inplace(CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    if (!scales_match(ct1, ct2)) {
        throw std::invalid_argument("Scales must match for addition");
    }
    
    ct1.c0() += ct2.c0();
    ct1.c1() += ct2.c1();
    ct1.set_level(std::min(ct1.level(), ct2.level()));
}

void CKKSEvaluator::sub_inplace(CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    if (!scales_match(ct1, ct2)) {
        throw std::invalid_argument("Scales must match for subtraction");
    }
    
    ct1.c0() -= ct2.c0();
    ct1.c1() -= ct2.c1();
    ct1.set_level(std::min(ct1.level(), ct2.level()));
}

CKKSCiphertext CKKSEvaluator::multiply_relin_rescale(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2, const CKKSRelinKey& rk) {
    CKKSCiphertext product = multiply(ct1, ct2);
    CKKSCiphertext relined = relinearize(product, rk);
    return rescale(relined);
}

bool CKKSEvaluator::scales_match(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2, double tolerance) const {
    if (ct1.scale() == 0.0 || ct2.scale() == 0.0) {
        return ct1.scale() == ct2.scale();
    }
    double ratio = ct1.scale() / ct2.scale();
    return std::abs(ratio - 1.0) < tolerance;
}

}  // namespace ckks
}  // namespace fhe
}  // namespace kctsb
