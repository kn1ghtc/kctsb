/**
 * @file rns_poly.hpp
 * @brief Pure uint64_t RNS Polynomial Representation
 * 
 * Implements SEAL-compatible RNS polynomial representation that avoids
 * expensive ZZ ↔ uint64_t conversions by keeping data in RNS form throughout.
 * 
 * Key Design Decisions (following SEAL 4.1):
 * - Data stored as uint64_t** (level × degree) for cache efficiency
 * - NTT form flag for lazy transformation tracking
 * - Move semantics for zero-copy operations
 * - Memory pooling for reduced allocation overhead
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.9.1
 * @since Phase 4b optimization
 */

#ifndef KCTSB_FHE_RNS_POLY_HPP
#define KCTSB_FHE_RNS_POLY_HPP

#include "modular_ops.hpp"
#include "ntt_harvey.hpp"
#include <vector>
#include <memory>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <numeric>

namespace kctsb {
namespace fhe {

/**
 * @brief RNS context containing moduli chain and NTT tables
 * 
 * Analogous to SEAL's SEALContext::ContextData, holds precomputed
 * values needed for RNS polynomial operations.
 */
class RNSContext {
public:
    /**
     * @brief Construct RNS context with specified parameters
     * @param log_n Log2 of polynomial degree
     * @param primes RNS moduli chain
     */
    RNSContext(int log_n, const std::vector<uint64_t>& primes)
        : log_n_(log_n)
        , n_(1ULL << log_n)
    {
        // Create Modulus objects
        moduli_.reserve(primes.size());
        for (uint64_t p : primes) {
            moduli_.emplace_back(p);
        }
        
        // Create NTT tables for each modulus
        ntt_tables_.reserve(primes.size());
        for (const auto& mod : moduli_) {
            ntt_tables_.emplace_back(log_n, mod);
        }
        
        // Precompute CRT helpers for reconstruction if needed
        precompute_crt_helpers();
    }
    
    // Accessors
    int log_n() const noexcept { return log_n_; }
    size_t n() const noexcept { return n_; }
    size_t level_count() const noexcept { return moduli_.size(); }
    
    const Modulus& modulus(size_t i) const { return moduli_.at(i); }
    const std::vector<Modulus>& moduli() const noexcept { return moduli_; }
    
    const NTTTables& ntt_tables(size_t i) const { return ntt_tables_.at(i); }
    const std::vector<NTTTables>& all_ntt_tables() const noexcept { return ntt_tables_; }
    
    // CRT reconstruction helpers
    const MultiplyUIntModOperand& q_hat_inv(size_t i) const { return q_hat_inv_.at(i); }
    
private:
    int log_n_;
    size_t n_;
    std::vector<Modulus> moduli_;
    std::vector<NTTTables> ntt_tables_;
    
    // CRT: q_hat_i = Q/q_i, q_hat_inv_i = (Q/q_i)^{-1} mod q_i
    std::vector<MultiplyUIntModOperand> q_hat_inv_;
    
    void precompute_crt_helpers() {
        size_t L = moduli_.size();
        q_hat_inv_.resize(L);
        
        // For each modulus, compute (product of all others)^{-1} mod this modulus
        for (size_t i = 0; i < L; ++i) {
            uint64_t qi = moduli_[i].value();
            
            // Compute product of all q_j for j != i, mod q_i
            uint64_t q_hat_i = 1;
            for (size_t j = 0; j < L; ++j) {
                if (j != i) {
                    q_hat_i = multiply_uint_mod(q_hat_i, moduli_[j].value() % qi, moduli_[i]);
                }
            }
            
            // Compute inverse
            uint64_t inv = inv_mod(q_hat_i, moduli_[i]);
            q_hat_inv_[i].set(inv, moduli_[i]);
        }
    }
};

/**
 * @brief Pure uint64_t RNS polynomial representation
 * 
 * Stores polynomial coefficients in RNS form as a 2D array:
 * data_[level][coeff_index]. This avoids expensive ZZ conversions
 * by keeping data in RNS throughout all operations.
 * 
 * Memory Layout:
 * - Contiguous allocation for cache efficiency
 * - data_[i] points to i-th level's coefficients
 * - Each level has n coefficients
 * 
 * NTT State:
 * - is_ntt_form_ tracks whether data is in NTT domain
 * - Operations check and transform as needed
 */
class RNSPoly {
public:
    // ========================================================================
    // Constructors & Destructor
    // ========================================================================
    
    /**
     * @brief Default constructor - creates empty polynomial
     */
    RNSPoly() noexcept
        : context_(nullptr)
        , data_(nullptr)
        , is_ntt_form_(false)
        , current_level_(0)
    {}
    
    /**
     * @brief Construct zero polynomial with given context
     * @param ctx RNS context with parameters and precomputed tables
     */
    explicit RNSPoly(const RNSContext* ctx)
        : context_(ctx)
        , is_ntt_form_(false)
        , current_level_(ctx ? ctx->level_count() : 0)
    {
        if (ctx) {
            allocate_and_zero();
        } else {
            data_ = nullptr;
        }
    }
    
    /**
     * @brief Construct from uint64_t coefficients (single level)
     * @param ctx RNS context
     * @param coeffs Coefficient values (will be reduced mod each prime)
     */
    RNSPoly(const RNSContext* ctx, const std::vector<uint64_t>& coeffs)
        : context_(ctx)
        , is_ntt_form_(false)
        , current_level_(ctx ? ctx->level_count() : 0)
    {
        if (!ctx) {
            data_ = nullptr;
            return;
        }
        
        allocate_and_zero();
        
        size_t n = context_->n();
        size_t copy_len = std::min(coeffs.size(), n);
        
        // Copy coefficients to each level, reducing mod q_i
        for (size_t level = 0; level < current_level_; ++level) {
            uint64_t qi = context_->modulus(level).value();
            for (size_t j = 0; j < copy_len; ++j) {
                data_[level][j] = coeffs[j] % qi;
            }
        }
    }
    
    /**
     * @brief Copy constructor
     */
    RNSPoly(const RNSPoly& other)
        : context_(other.context_)
        , is_ntt_form_(other.is_ntt_form_)
        , current_level_(other.current_level_)
    {
        if (context_ && other.data_) {
            allocate_and_zero();
            size_t n = context_->n();
            for (size_t level = 0; level < current_level_; ++level) {
                std::memcpy(data_[level], other.data_[level], n * sizeof(uint64_t));
            }
        } else {
            data_ = nullptr;
        }
    }
    
    /**
     * @brief Move constructor
     */
    RNSPoly(RNSPoly&& other) noexcept
        : context_(other.context_)
        , data_(other.data_)
        , is_ntt_form_(other.is_ntt_form_)
        , current_level_(other.current_level_)
    {
        other.data_ = nullptr;
        other.current_level_ = 0;
    }
    
    /**
     * @brief Destructor
     */
    ~RNSPoly() {
        deallocate();
    }
    
    /**
     * @brief Copy assignment
     */
    RNSPoly& operator=(const RNSPoly& other) {
        if (this != &other) {
            deallocate();
            context_ = other.context_;
            is_ntt_form_ = other.is_ntt_form_;
            current_level_ = other.current_level_;
            
            if (context_ && other.data_) {
                allocate_and_zero();
                size_t n = context_->n();
                for (size_t level = 0; level < current_level_; ++level) {
                    std::memcpy(data_[level], other.data_[level], n * sizeof(uint64_t));
                }
            }
        }
        return *this;
    }
    
    /**
     * @brief Move assignment
     */
    RNSPoly& operator=(RNSPoly&& other) noexcept {
        if (this != &other) {
            deallocate();
            context_ = other.context_;
            data_ = other.data_;
            is_ntt_form_ = other.is_ntt_form_;
            current_level_ = other.current_level_;
            
            other.data_ = nullptr;
            other.current_level_ = 0;
        }
        return *this;
    }
    
    // ========================================================================
    // Accessors
    // ========================================================================
    
    bool empty() const noexcept { return data_ == nullptr; }
    bool is_ntt_form() const noexcept { return is_ntt_form_; }
    size_t current_level() const noexcept { return current_level_; }
    size_t n() const noexcept { return context_ ? context_->n() : 0; }
    const RNSContext* context() const noexcept { return context_; }
    
    /**
     * @brief Access coefficients at given level
     * @param level RNS level index
     * @return Pointer to n coefficients for this level
     */
    uint64_t* data(size_t level) {
        return data_ ? data_[level] : nullptr;
    }
    
    const uint64_t* data(size_t level) const {
        return data_ ? data_[level] : nullptr;
    }
    
    /**
     * @brief Access single coefficient
     */
    uint64_t& operator()(size_t level, size_t coeff) {
        return data_[level][coeff];
    }
    
    uint64_t operator()(size_t level, size_t coeff) const {
        return data_[level][coeff];
    }
    
    // ========================================================================
    // NTT Transformations
    // ========================================================================
    
    /**
     * @brief Transform to NTT domain (in-place)
     * @note Uses scalar NTT for now; AVX2 optimization pending validation
     */
    void ntt_transform() {
        if (is_ntt_form_ || !data_) return;
        
        for (size_t level = 0; level < current_level_; ++level) {
            const NTTTables& tables = context_->ntt_tables(level);
            // Use scalar version for correctness; AVX2 needs further validation
            ntt_negacyclic_harvey(data_[level], tables);
        }
        
        is_ntt_form_ = true;
    }
    
    /**
     * @brief Transform from NTT domain (in-place)
     * @note Uses scalar INTT for now; AVX2 optimization pending validation
     */
    void intt_transform() {
        if (!is_ntt_form_ || !data_) return;
        
        for (size_t level = 0; level < current_level_; ++level) {
            const NTTTables& tables = context_->ntt_tables(level);
            // Use scalar version for correctness; AVX2 needs further validation
            inverse_ntt_negacyclic_harvey(data_[level], tables);
        }
        
        is_ntt_form_ = false;
    }
    
    // ========================================================================
    // Arithmetic Operations (Component-wise in NTT domain)
    // ========================================================================
    
    /**
     * @brief Add another polynomial (must be same context)
     */
    RNSPoly& operator+=(const RNSPoly& other) {
        if (!data_ || !other.data_) return *this;
        if (is_ntt_form_ != other.is_ntt_form_) {
            throw std::invalid_argument("NTT form mismatch in addition");
        }
        
        size_t n = context_->n();
        for (size_t level = 0; level < current_level_; ++level) {
            const Modulus& mod = context_->modulus(level);
#ifdef __AVX2__
            // AVX2 vectorized loop
            __m256i vq = _mm256_set1_epi64x(mod.value());
            size_t i = 0;
            for (; i + 4 <= n; i += 4) {
                __m256i va = _mm256_loadu_si256((__m256i*)(data_[level] + i));
                __m256i vb = _mm256_loadu_si256((__m256i*)(other.data_[level] + i));
                __m256i vsum = add_uint_mod_avx2(va, vb, vq);
                _mm256_storeu_si256((__m256i*)(data_[level] + i), vsum);
            }
            for (; i < n; ++i) {
                data_[level][i] = add_uint_mod(data_[level][i], other.data_[level][i], mod);
            }
#else
            for (size_t j = 0; j < n; ++j) {
                data_[level][j] = add_uint_mod(data_[level][j], other.data_[level][j], mod);
            }
#endif
        }
        
        return *this;
    }
    
    /**
     * @brief Subtract another polynomial
     */
    RNSPoly& operator-=(const RNSPoly& other) {
        if (!data_ || !other.data_) return *this;
        if (is_ntt_form_ != other.is_ntt_form_) {
            throw std::invalid_argument("NTT form mismatch in subtraction");
        }
        
        size_t n = context_->n();
        for (size_t level = 0; level < current_level_; ++level) {
            const Modulus& mod = context_->modulus(level);
#ifdef __AVX2__
            // AVX2 vectorized loop
            __m256i vq = _mm256_set1_epi64x(mod.value());
            size_t i = 0;
            for (; i + 4 <= n; i += 4) {
                __m256i va = _mm256_loadu_si256((__m256i*)(data_[level] + i));
                __m256i vb = _mm256_loadu_si256((__m256i*)(other.data_[level] + i));
                __m256i vdiff = sub_uint_mod_avx2(va, vb, vq);
                _mm256_storeu_si256((__m256i*)(data_[level] + i), vdiff);
            }
            for (; i < n; ++i) {
                data_[level][i] = sub_uint_mod(data_[level][i], other.data_[level][i], mod);
            }
#else
            for (size_t j = 0; j < n; ++j) {
                data_[level][j] = sub_uint_mod(data_[level][j], other.data_[level][j], mod);
            }
#endif
        }
        
        return *this;
    }
    
    /**
     * @brief Multiply by another polynomial (component-wise in NTT domain)
     */
    RNSPoly& operator*=(const RNSPoly& other) {
        if (!data_ || !other.data_) return *this;
        
        // Both must be in NTT form for component-wise multiplication
        if (!is_ntt_form_ || !other.is_ntt_form_) {
            throw std::invalid_argument("Both polynomials must be in NTT form for multiplication");
        }
        
        size_t n = context_->n();
        for (size_t level = 0; level < current_level_; ++level) {
            const Modulus& mod = context_->modulus(level);
            for (size_t j = 0; j < n; ++j) {
                data_[level][j] = multiply_uint_mod(data_[level][j], other.data_[level][j], mod);
            }
        }
        
        return *this;
    }
    
    /**
     * @brief Negate polynomial
     */
    RNSPoly& negate() {
        if (!data_) return *this;
        
        size_t n = context_->n();
        for (size_t level = 0; level < current_level_; ++level) {
            const Modulus& mod = context_->modulus(level);
            for (size_t j = 0; j < n; ++j) {
                data_[level][j] = negate_uint_mod(data_[level][j], mod);
            }
        }
        
        return *this;
    }
    
    /**
     * @brief Multiply by scalar
     */
    RNSPoly& multiply_scalar(uint64_t scalar) {
        if (!data_) return *this;
        
        size_t n = context_->n();
        for (size_t level = 0; level < current_level_; ++level) {
            const Modulus& mod = context_->modulus(level);
            uint64_t s = scalar % mod.value();
            MultiplyUIntModOperand s_op;
            s_op.set(s, mod);
            
            for (size_t j = 0; j < n; ++j) {
                data_[level][j] = multiply_uint_mod(data_[level][j], s_op, mod);
            }
        }
        
        return *this;
    }
    
    // ========================================================================
    // Modulus Switching (Level Reduction)
    // ========================================================================
    
    /**
     * @brief Drop the last level (rescaling)
     */
    void mod_switch_drop_level() {
        if (current_level_ <= 1) {
            throw std::runtime_error("Cannot drop below level 1");
        }
        
        // Simply reduce the level count
        // The dropped level's data becomes unused
        --current_level_;
    }
    
    // ========================================================================
    // Utility Functions
    // ========================================================================
    
    /**
     * @brief Set all coefficients to zero
     */
    void set_zero() {
        if (!data_) return;
        
        size_t n = context_->n();
        for (size_t level = 0; level < current_level_; ++level) {
            std::memset(data_[level], 0, n * sizeof(uint64_t));
        }
        is_ntt_form_ = false;
    }
    
    /**
     * @brief Check if polynomial is zero
     */
    bool is_zero() const {
        if (!data_) return true;
        
        size_t n = context_->n();
        for (size_t level = 0; level < current_level_; ++level) {
            for (size_t j = 0; j < n; ++j) {
                if (data_[level][j] != 0) return false;
            }
        }
        return true;
    }
    
    /**
     * @brief Create a deep copy
     */
    RNSPoly clone() const {
        return RNSPoly(*this);
    }
    
private:
    const RNSContext* context_;
    uint64_t** data_;
    bool is_ntt_form_;
    size_t current_level_;
    
    void allocate_and_zero() {
        size_t L = context_->level_count();
        size_t n = context_->n();
        
        // Allocate array of pointers
        data_ = new uint64_t*[L];
        
        // Allocate contiguous memory for all levels
        size_t total_size = L * n;
        uint64_t* storage = new uint64_t[total_size]();  // zero-initialized
        
        // Set up pointers
        for (size_t i = 0; i < L; ++i) {
            data_[i] = storage + i * n;
        }
    }
    
    void deallocate() {
        if (data_) {
            // data_[0] points to the contiguous storage
            delete[] data_[0];
            delete[] data_;
            data_ = nullptr;
        }
    }
};

// ============================================================================
// Free Functions for Arithmetic
// ============================================================================

/**
 * @brief Add two RNS polynomials
 */
inline RNSPoly operator+(const RNSPoly& a, const RNSPoly& b) {
    RNSPoly result(a);
    result += b;
    return result;
}

/**
 * @brief Subtract two RNS polynomials
 */
inline RNSPoly operator-(const RNSPoly& a, const RNSPoly& b) {
    RNSPoly result(a);
    result -= b;
    return result;
}

/**
 * @brief Multiply two RNS polynomials (both must be in NTT form)
 */
inline RNSPoly operator*(const RNSPoly& a, const RNSPoly& b) {
    RNSPoly result(a);
    result *= b;
    return result;
}

/**
 * @brief Polynomial multiplication with automatic NTT handling
 * @param a First polynomial (any form)
 * @param b Second polynomial (any form)
 * @param result_in_ntt Whether result should stay in NTT form
 * @return Product polynomial
 */
inline RNSPoly poly_multiply(const RNSPoly& a, const RNSPoly& b, bool result_in_ntt = false) {
    RNSPoly temp_a = a;
    RNSPoly temp_b = b;
    
    // Transform to NTT if needed
    if (!temp_a.is_ntt_form()) temp_a.ntt_transform();
    if (!temp_b.is_ntt_form()) temp_b.ntt_transform();
    
    // Component-wise multiply
    temp_a *= temp_b;
    
    // Transform back if requested
    if (!result_in_ntt) {
        temp_a.intt_transform();
    }
    
    return temp_a;
}

} // namespace fhe
} // namespace kctsb

#endif // KCTSB_FHE_RNS_POLY_HPP
