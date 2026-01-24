/**
 * @file ntt_harvey.cpp
 * @brief Harvey NTT Implementation with Lazy Reduction
 * 
 * Implements SEAL-compatible Harvey NTT algorithm for negacyclic convolution.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.9.1
 * @since Phase 4b optimization
 */

#include "kctsb/advanced/fe/common/ntt_harvey.hpp"
#include <stdexcept>
#include <cmath>
#include <algorithm>

namespace kctsb {
namespace fhe {

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Count trailing zeros (log2 for power of 2)
 */
static int count_trailing_zeros(size_t n) {
    int count = 0;
    while ((n & 1) == 0 && n > 0) {
        n >>= 1;
        ++count;
    }
    return count;
}

/**
 * @brief Simple primality test
 */
static bool is_prime_simple(uint64_t n) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    for (uint64_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

/**
 * @brief Find prime factors of n
 */
static std::vector<uint64_t> prime_factors(uint64_t n) {
    std::vector<uint64_t> factors;
    
    while (n % 2 == 0) {
        if (factors.empty() || factors.back() != 2) factors.push_back(2);
        n /= 2;
    }
    
    for (uint64_t i = 3; i * i <= n; i += 2) {
        while (n % i == 0) {
            if (factors.empty() || factors.back() != i) factors.push_back(i);
            n /= i;
        }
    }
    
    if (n > 1) factors.push_back(n);
    return factors;
}

// ============================================================================
// NTTTables Implementation
// ============================================================================

size_t NTTTables::bit_reverse(size_t x, int bits) {
    size_t result = 0;
    for (int i = 0; i < bits; ++i) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

uint64_t NTTTables::find_minimal_primitive_root() const {
    // Find primitive 2n-th root of unity
    // We need g such that g^{2n} = 1 and g^k != 1 for k < 2n
    
    uint64_t q = modulus_.value();
    uint64_t order = q - 1;  // |Z_q^*| = q - 1
    uint64_t two_n = 2 * coeff_count_;
    
    if (order % two_n != 0) {
        throw std::invalid_argument("Modulus does not support NTT for this n");
    }
    
    // Find a generator of Z_q^*
    auto factors = prime_factors(order);
    
    // For small primes, limit search to first 10000 candidates
    // For most NTT-friendly primes, a generator is found quickly
    uint64_t max_search = std::min(q - 1, static_cast<uint64_t>(10000));
    
    for (uint64_t g = 2; g <= max_search; ++g) {
        bool is_generator = true;
        
        for (uint64_t p : factors) {
            if (pow_mod(g, order / p, modulus_) == 1) {
                is_generator = false;
                break;
            }
        }
        
        if (is_generator) {
            // g is a generator of Z_q^*
            // The 2n-th primitive root is g^{(q-1)/(2n)}
            return pow_mod(g, order / two_n, modulus_);
        }
    }
    
    throw std::runtime_error("Failed to find primitive root");
}

NTTTables::NTTTables(int log_n, const Modulus& modulus)
    : coeff_count_power_(log_n)
    , coeff_count_(1ULL << log_n)
    , modulus_(modulus)
    , two_times_modulus_(2 * modulus.value())
{
    initialize();
}

NTTTables::NTTTables(const NTTTables& other)
    : coeff_count_power_(other.coeff_count_power_)
    , coeff_count_(other.coeff_count_)
    , modulus_(other.modulus_)
    , root_(other.root_)
    , inv_root_(other.inv_root_)
    , two_times_modulus_(other.two_times_modulus_)
    , root_powers_(other.root_powers_)
    , inv_root_powers_(other.inv_root_powers_)
    , inv_degree_modulo_(other.inv_degree_modulo_)
{
}

void NTTTables::initialize() {
    size_t n = coeff_count_;
    uint64_t q = modulus_.value();
    
    // Find primitive 2n-th root of unity
    root_ = find_minimal_primitive_root();
    inv_root_ = inv_mod(root_, modulus_);
    
    // Allocate storage
    root_powers_.resize(n);
    inv_root_powers_.resize(n);
    
    // SEAL-compatible twiddle factor storage:
    // - root_powers_[i] = root^{bit_reverse(i)} for forward NTT (DIT)
    // - inv_root_powers_ uses "scrambled order": inv_root_powers_[reverse_bits(i-1)+1] = inv_root^i
    //   This ordering is optimized for the inverse NTT (DIF) access pattern
    
    // Initialize root_powers for forward NTT
    root_powers_[0].set(1, modulus_);
    uint64_t power = root_;
    for (size_t i = 1; i < n; ++i) {
        size_t br = bit_reverse(i, coeff_count_power_);
        root_powers_[br].set(power, modulus_);
        power = multiply_uint_mod(power, root_, modulus_);
    }
    
    // Initialize inv_root_powers for inverse NTT (SEAL scrambled order)
    inv_root_powers_[0].set(1, modulus_);
    power = inv_root_;
    for (size_t i = 1; i < n; ++i) {
        size_t idx = bit_reverse(i - 1, coeff_count_power_) + 1;
        inv_root_powers_[idx].set(power, modulus_);
        power = multiply_uint_mod(power, inv_root_, modulus_);
    }
    
    // Compute n^{-1} mod q
    uint64_t inv_n = inv_mod(static_cast<uint64_t>(n), modulus_);
    inv_degree_modulo_.set(inv_n, modulus_);
}

// ============================================================================
// Forward NTT (Cooley-Tukey, Decimation-in-Time)
// ============================================================================

void ntt_negacyclic_harvey_lazy(uint64_t* operand, const NTTTables& tables) {
    size_t n = tables.coeff_count();
    uint64_t q = tables.modulus().value();
    uint64_t two_q = tables.two_times_modulus();
    const MultiplyUIntModOperand* root_powers = tables.root_powers();
    
    // Cooley-Tukey butterfly NTT
    // Process from small butterflies to large
    
    size_t t = n;  // Butterfly width
    size_t root_index = 1;
    
    for (size_t m = 1; m < n; m <<= 1) {
        t >>= 1;  // t = n / (2 * m)
        
        for (size_t i = 0; i < m; ++i) {
            // Get twiddle factor for this butterfly group
            const MultiplyUIntModOperand& w = root_powers[root_index];
            root_index++;
            
            size_t j1 = 2 * i * t;
            size_t j2 = j1 + t;
            
            for (size_t j = j1; j < j2; ++j) {
                // Butterfly operation
                // x' = x + w * y
                // y' = x - w * y
                
                uint64_t x = operand[j];
                uint64_t y = operand[j + t];
                
                // Guard x to [0, 2q) if needed
                x = guard(x, two_q);
                
                // t = w * y (lazy, result in [0, 2q))
                uint64_t wt = multiply_uint_mod_lazy(y, w, tables.modulus());
                
                // x' = x + t (result in [0, 4q), guard later)
                operand[j] = x + wt;
                
                // y' = x - t + 2q (ensure non-negative, result in [0, 4q))
                operand[j + t] = x + two_q - wt;
            }
        }
    }
    
    // Final guard to ensure all values in [0, 2q)
    for (size_t i = 0; i < n; ++i) {
        operand[i] = guard(operand[i], two_q);
    }
}

void ntt_negacyclic_harvey(uint64_t* operand, const NTTTables& tables) {
#ifdef __AVX2__
    // Prefer AVX2 implementation for better performance
    ntt_negacyclic_harvey_avx2(operand, tables);
#else
    // First do lazy NTT
    ntt_negacyclic_harvey_lazy(operand, tables);
    
    // Then reduce all values to [0, q)
    size_t n = tables.coeff_count();
    uint64_t q = tables.modulus().value();
    
    for (size_t i = 0; i < n; ++i) {
        if (operand[i] >= q) {
            operand[i] -= q;
        }
    }
#endif
}

// ============================================================================
// Inverse NTT (Gentleman-Sande, Decimation-in-Frequency)
// ============================================================================

void inverse_ntt_negacyclic_harvey_lazy(uint64_t* operand, const NTTTables& tables) {
    size_t n = tables.coeff_count();
    uint64_t q = tables.modulus().value();
    uint64_t two_q = tables.two_times_modulus();
    const MultiplyUIntModOperand* inv_root_powers = tables.inv_root_powers();
    
    // Gentleman-Sande butterfly inverse NTT (DIF - Decimation in Frequency)
    // SEAL-compatible implementation: process from large to small butterflies
    // gap starts at 1, m starts at n/2
    
    size_t gap = 1;
    size_t m = n >> 1;
    size_t root_index = 1;
    
    for (; m > 1; m >>= 1) {
        size_t offset = 0;
        
        for (size_t i = 0; i < m; ++i) {
            const MultiplyUIntModOperand& w = inv_root_powers[root_index++];
            
            uint64_t* x = operand + offset;
            uint64_t* y = x + gap;
            
            for (size_t j = 0; j < gap; ++j) {
                // Inverse butterfly: x' = x + y, y' = (x - y) * w
                uint64_t u = *x;
                uint64_t v = *y;
                
                // Guard and add
                *x++ = guard(u + v, two_q);
                
                // Subtract with wrap-around prevention
                *y++ = multiply_uint_mod_lazy(u + two_q - v, w, tables.modulus());
            }
            
            offset += gap << 1;  // Move to next pair of butterflies
        }
        
        gap <<= 1;
    }
    
    // Final iteration with m = 1 (single butterfly at full width)
    // Also incorporate scaling by n^{-1}
    const MultiplyUIntModOperand& inv_n = tables.inv_degree_modulo();
    const MultiplyUIntModOperand& w = inv_root_powers[root_index];
    
    // Compute scaled twiddle: w * n^{-1}
    MultiplyUIntModOperand scaled_w;
    scaled_w.set(multiply_uint_mod(w.operand, inv_n, tables.modulus()), tables.modulus());
    
    uint64_t* x = operand;
    uint64_t* y = x + gap;
    
    for (size_t j = 0; j < gap; ++j) {
        uint64_t u = guard(*x, two_q);
        uint64_t v = *y;
        
        // x' = (x + y) * n^{-1}
        *x++ = multiply_uint_mod_lazy(guard(u + v, two_q), inv_n, tables.modulus());
        
        // y' = (x - y) * w * n^{-1}
        *y++ = multiply_uint_mod_lazy(u + two_q - v, scaled_w, tables.modulus());
    }
}

void inverse_ntt_negacyclic_harvey(uint64_t* operand, const NTTTables& tables) {
#ifdef __AVX2__
    // Use AVX2 accelerated version when available
    inverse_ntt_negacyclic_harvey_avx2(operand, tables);
#else
    // First do lazy inverse NTT
    inverse_ntt_negacyclic_harvey_lazy(operand, tables);
    
    // Then reduce all values to [0, q)
    size_t n = tables.coeff_count();
    uint64_t q = tables.modulus().value();
    
    for (size_t i = 0; i < n; ++i) {
        if (operand[i] >= q) {
            operand[i] -= q;
        }
    }
#endif
}

// ============================================================================
// AVX2 Accelerated NTT
// ============================================================================

#ifdef __AVX2__

void ntt_negacyclic_harvey_avx2(uint64_t* operand, const NTTTables& tables) {
    size_t n = tables.coeff_count();
    uint64_t q = tables.modulus().value();
    uint64_t two_q = tables.two_times_modulus();
    const MultiplyUIntModOperand* root_powers = tables.root_powers();
    
    __m256i vq = _mm256_set1_epi64x(q);
    __m256i v2q = _mm256_set1_epi64x(two_q);
    
    size_t t = n;
    size_t root_index = 1;
    
    for (size_t m = 1; m < n; m <<= 1) {
        t >>= 1;
        
        for (size_t i = 0; i < m; ++i) {
            const MultiplyUIntModOperand& w = root_powers[root_index];
            root_index++;
            
            __m256i vw = _mm256_set1_epi64x(w.operand);
            __m256i vwq = _mm256_set1_epi64x(w.quotient);
            
            size_t j1 = 2 * i * t;
            size_t j2 = j1 + t;
            
            // Process 4 butterflies at a time when possible
            // FIX: Use offset within butterfly group instead of absolute index
            size_t offset = 0;
            for (; offset + 4 <= t; offset += 4) {
                // Load x and y using correct indices
                __m256i vx = _mm256_loadu_si256((__m256i*)(operand + j1 + offset));
                __m256i vy = _mm256_loadu_si256((__m256i*)(operand + j2 + offset));
                
                // Guard x
                __m256i mask = _mm256_cmpgt_epi64(vx, _mm256_sub_epi64(v2q, _mm256_set1_epi64x(1)));
                vx = _mm256_sub_epi64(vx, _mm256_and_si256(v2q, mask));
                
                // Compute w * y using SEAL-style: result = y * w.operand - q_approx * q
                // This requires 64-bit multiplication which AVX2 doesn't directly support
                // We use _mm256_mul_epu32 for low 32 bits and combine
                
                // For now, fall back to scalar for the modular multiplication
                // Full AVX2 implementation would use MULX or split multiply
                alignas(32) uint64_t x_arr[4], y_arr[4], wt_arr[4];
                _mm256_store_si256((__m256i*)x_arr, vx);
                _mm256_store_si256((__m256i*)y_arr, vy);
                
                for (int k = 0; k < 4; ++k) {
                    wt_arr[k] = multiply_uint_mod_lazy(y_arr[k], w, tables.modulus());
                }
                
                __m256i vwt = _mm256_load_si256((__m256i*)wt_arr);
                
                // x' = x + wt
                __m256i vx_new = _mm256_add_epi64(vx, vwt);
                
                // y' = x - wt + 2q
                __m256i vy_new = _mm256_add_epi64(_mm256_sub_epi64(vx, vwt), v2q);
                
                _mm256_storeu_si256((__m256i*)(operand + j1 + offset), vx_new);
                _mm256_storeu_si256((__m256i*)(operand + j2 + offset), vy_new);
            }
            
            // Handle remaining elements
            for (; offset < t; ++offset) {
                uint64_t x = operand[j1 + offset];
                uint64_t y = operand[j2 + offset];
                
                x = guard(x, two_q);
                uint64_t wt = multiply_uint_mod_lazy(y, w, tables.modulus());
                
                operand[j1 + offset] = x + wt;
                operand[j2 + offset] = x + two_q - wt;
            }
        }
    }
    
    // Final guard to [0, 2q)
    for (size_t i = 0; i + 4 <= n; i += 4) {
        __m256i v = _mm256_loadu_si256((__m256i*)(operand + i));
        __m256i mask = _mm256_cmpgt_epi64(v, _mm256_sub_epi64(v2q, _mm256_set1_epi64x(1)));
        v = _mm256_sub_epi64(v, _mm256_and_si256(v2q, mask));
        _mm256_storeu_si256((__m256i*)(operand + i), v);
    }
    for (size_t i = (n / 4) * 4; i < n; ++i) {
        operand[i] = guard(operand[i], two_q);
    }
    
    // Final reduction to [0, q) to match non-lazy behavior
    for (size_t i = 0; i + 4 <= n; i += 4) {
        __m256i v = _mm256_loadu_si256((__m256i*)(operand + i));
        __m256i mask = _mm256_cmpgt_epi64(v, _mm256_sub_epi64(vq, _mm256_set1_epi64x(1)));
        v = _mm256_sub_epi64(v, _mm256_and_si256(vq, mask));
        _mm256_storeu_si256((__m256i*)(operand + i), v);
    }
    for (size_t i = (n / 4) * 4; i < n; ++i) {
        if (operand[i] >= q) operand[i] -= q;
    }
}

void inverse_ntt_negacyclic_harvey_avx2(uint64_t* operand, const NTTTables& tables) {
    size_t n = tables.coeff_count();
    uint64_t q = tables.modulus().value();
    uint64_t two_q = tables.two_times_modulus();
    const MultiplyUIntModOperand* inv_root_powers = tables.inv_root_powers();
    
    __m256i vq = _mm256_set1_epi64x(q);
    __m256i v2q = _mm256_set1_epi64x(two_q);
    
    // SEAL-compatible Gentleman-Sande DIF
    size_t gap = 1;
    size_t m = n >> 1;
    size_t root_index = 1;
    
    for (; m > 1; m >>= 1) {
        size_t offset = 0;
        
        for (size_t i = 0; i < m; ++i) {
            const MultiplyUIntModOperand& w = inv_root_powers[root_index++];
            
            uint64_t* x_ptr = operand + offset;
            uint64_t* y_ptr = x_ptr + gap;
            
            // AVX2 vectorized when gap >= 4
            size_t j = 0;
            for (; j + 4 <= gap; j += 4) {
                __m256i vx = _mm256_loadu_si256((__m256i*)(x_ptr + j));
                __m256i vy = _mm256_loadu_si256((__m256i*)(y_ptr + j));
                
                // x' = guard(x + y)
                __m256i vsum = _mm256_add_epi64(vx, vy);
                __m256i mask = _mm256_cmpgt_epi64(vsum, _mm256_sub_epi64(v2q, _mm256_set1_epi64x(1)));
                vsum = _mm256_sub_epi64(vsum, _mm256_and_si256(v2q, mask));
                
                // diff = x - y + 2q
                __m256i vdiff = _mm256_add_epi64(_mm256_sub_epi64(vx, vy), v2q);
                
                // y' = diff * w (scalar fallback for 64-bit mod multiply)
                alignas(32) uint64_t diff_arr[4], ynew_arr[4];
                _mm256_store_si256((__m256i*)diff_arr, vdiff);
                
                for (int k = 0; k < 4; ++k) {
                    ynew_arr[k] = multiply_uint_mod_lazy(diff_arr[k], w, tables.modulus());
                }
                
                _mm256_storeu_si256((__m256i*)(x_ptr + j), vsum);
                _mm256_storeu_si256((__m256i*)(y_ptr + j), _mm256_load_si256((__m256i*)ynew_arr));
            }
            
            // Remaining elements
            for (; j < gap; ++j) {
                uint64_t x = x_ptr[j];
                uint64_t y = y_ptr[j];
                
                x_ptr[j] = guard(x + y, two_q);
                y_ptr[j] = multiply_uint_mod_lazy(x + two_q - y, w, tables.modulus());
            }
            
            offset += gap << 1;
        }
        
        gap <<= 1;
    }
    
    // Final iteration with m = 1, also incorporating n^{-1} scaling
    const MultiplyUIntModOperand& inv_n = tables.inv_degree_modulo();
    const MultiplyUIntModOperand& w = inv_root_powers[root_index];
    
    MultiplyUIntModOperand scaled_w;
    scaled_w.set(multiply_uint_mod(w.operand, inv_n, tables.modulus()), tables.modulus());
    
    uint64_t* x_ptr = operand;
    uint64_t* y_ptr = x_ptr + gap;
    
    // Vectorized final iteration
    size_t j = 0;
    for (; j + 4 <= gap; j += 4) {
        __m256i vx = _mm256_loadu_si256((__m256i*)(x_ptr + j));
        __m256i vy = _mm256_loadu_si256((__m256i*)(y_ptr + j));
        
        // Guard x
        __m256i mask = _mm256_cmpgt_epi64(vx, _mm256_sub_epi64(v2q, _mm256_set1_epi64x(1)));
        vx = _mm256_sub_epi64(vx, _mm256_and_si256(v2q, mask));
        
        // Scalar fallback for final operations
        alignas(32) uint64_t x_arr[4], y_arr[4], xnew_arr[4], ynew_arr[4];
        _mm256_store_si256((__m256i*)x_arr, vx);
        _mm256_store_si256((__m256i*)y_arr, vy);
        
        for (int k = 0; k < 4; ++k) {
            uint64_t sum = guard(x_arr[k] + y_arr[k], two_q);
            xnew_arr[k] = multiply_uint_mod_lazy(sum, inv_n, tables.modulus());
            ynew_arr[k] = multiply_uint_mod_lazy(x_arr[k] + two_q - y_arr[k], scaled_w, tables.modulus());
        }
        
        _mm256_storeu_si256((__m256i*)(x_ptr + j), _mm256_load_si256((__m256i*)xnew_arr));
        _mm256_storeu_si256((__m256i*)(y_ptr + j), _mm256_load_si256((__m256i*)ynew_arr));
    }
    
    // Remaining scalar
    for (; j < gap; ++j) {
        uint64_t x = guard(x_ptr[j], two_q);
        uint64_t y = y_ptr[j];
        
        x_ptr[j] = multiply_uint_mod_lazy(guard(x + y, two_q), inv_n, tables.modulus());
        y_ptr[j] = multiply_uint_mod_lazy(x + two_q - y, scaled_w, tables.modulus());
    }
    
    // Final reduction to [0, q)
    for (size_t i = 0; i + 4 <= n; i += 4) {
        __m256i v = _mm256_loadu_si256((__m256i*)(operand + i));
        __m256i mask = _mm256_cmpgt_epi64(v, _mm256_sub_epi64(vq, _mm256_set1_epi64x(1)));
        v = _mm256_sub_epi64(v, _mm256_and_si256(vq, mask));
        _mm256_storeu_si256((__m256i*)(operand + i), v);
    }
    for (size_t i = (n / 4) * 4; i < n; ++i) {
        if (operand[i] >= q) operand[i] -= q;
    }
}

#endif // __AVX2__

// ============================================================================
// Factory Functions
// ============================================================================

std::vector<NTTTables> create_ntt_tables(int coeff_count_power,
                                          const std::vector<Modulus>& moduli) {
    std::vector<NTTTables> tables;
    tables.reserve(moduli.size());
    
    for (const auto& mod : moduli) {
        tables.emplace_back(coeff_count_power, mod);
    }
    
    return tables;
}

bool is_ntt_prime(uint64_t q, size_t n) {
    if (!is_prime_simple(q)) return false;
    
    // Check q ≡ 1 (mod 2n)
    uint64_t two_n = static_cast<uint64_t>(n) * 2;
    return (q % two_n) == 1;
}

std::vector<uint64_t> generate_ntt_primes(int bit_size, size_t n, size_t count) {
    std::vector<uint64_t> primes;
    primes.reserve(count);
    
    uint64_t two_n = static_cast<uint64_t>(n) * 2;
    
    // Start from 2^(bit_size-1) + 1
    uint64_t candidate = (1ULL << (bit_size - 1)) + 1;
    
    // Adjust to be 1 mod 2n
    uint64_t remainder = candidate % two_n;
    if (remainder != 1) {
        candidate += two_n - remainder + 1;
    }
    
    while (primes.size() < count && candidate < (1ULL << bit_size)) {
        if (is_prime_simple(candidate)) {
            primes.push_back(candidate);
        }
        candidate += two_n;
    }
    
    if (primes.size() < count) {
        throw std::runtime_error("Could not generate enough NTT primes");
    }
    
    return primes;
}

} // namespace fhe
} // namespace kctsb
