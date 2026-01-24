/**
 * @file bgv.hpp
 * @brief BGV Homomorphic Encryption Scheme - Main Header (Pure RNS)
 * 
 * This is the main include file for the BGV (Brakerski-Gentry-Vaikuntanathan)
 * homomorphic encryption scheme implementation in kctsb.
 * 
 * v4.11.0: Complete migration to Pure RNS architecture.
 * All operations use RNSPoly representation, zero ZZ_pX/NTL dependencies.
 * 
 * BGV is a leveled fully homomorphic encryption scheme that supports:
 * - Exact integer arithmetic (no approximation)
 * - SIMD operations via batching (CRT packing) [Phase 4d pending]
 * - Efficient modulus switching for noise management [Phase 4d pending]
 * 
 * Quick Start (Pure RNS API):
 * @code
 * #include <kctsb/advanced/fe/bgv/bgv.hpp>
 * 
 * using namespace kctsb::fhe::bgv;
 * 
 * // 1. Create context (Pure RNS)
 * auto ctx = create_default_rns_context();  // n=4096, 3 primes, 128-bit security
 * 
 * // 2. Create evaluator
 * BGVEvaluator evaluator(ctx.get());
 * 
 * // 3. Generate keys
 * auto sk = evaluator.generate_secret_key();
 * auto pk = evaluator.generate_public_key(sk);
 * auto rk = evaluator.generate_relin_key(sk);
 * 
 * // 4. Encrypt
 * std::vector<uint64_t> data = {1, 2, 3, 4};
 * auto ct1 = evaluator.encrypt(pk, data);
 * auto ct2 = evaluator.encrypt(pk, data);
 * 
 * // 5. Homomorphic operations
 * auto ct_sum = evaluator.add(ct1, ct2);
 * auto ct_prod = evaluator.multiply(ct1, ct2);
 * evaluator.relinearize_inplace(ct_prod, rk);
 * 
 * // 6. Decrypt
 * auto result = evaluator.decrypt(sk, ct_sum);
 * @endcode
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.11.0
 * @since Phase 4d - Pure RNS migration
 */

#ifndef KCTSB_ADVANCED_FE_BGV_HPP
#define KCTSB_ADVANCED_FE_BGV_HPP

// Core Pure RNS types
#include "bgv_types.hpp"

// Pure RNS Evaluator (key generation + encrypt/decrypt + homomorphic ops)
#include "bgv_evaluator.hpp"

// NTT Helper utilities for Pure RNS API
#include "bgv_ntt_helper.hpp"

namespace kctsb {
namespace fhe {
namespace bgv {

// Import RNSContext from parent namespace for StandardParams
using ::kctsb::fhe::RNSContext;

/**
 * @brief BGV Library Version (Pure RNS)
 */
constexpr int BGV_VERSION_MAJOR = 4;
constexpr int BGV_VERSION_MINOR = 11;
constexpr int BGV_VERSION_PATCH = 0;

/**
 * @brief Get version string
 * @return Version in "major.minor.patch" format
 */
inline const char* bgv_version() {
    static const char version[] = "4.11.0-rns";
    return version;
}

/**
 * @brief Standard security parameter sets
 * 
 * All parameter sets use pure RNS representation.
 * Security estimates based on lattice-estimator.
 */
namespace StandardParams {

/**
 * @brief Create 128-bit security context (n=4096)
 * Good for 3-level computations
 */
inline std::unique_ptr<RNSContext> SECURITY_128_N4096() {
    // NTT-friendly primes: p ≡ 1 (mod 2n), 60-bit for Barrett reduction
    // These are standard SEAL-compatible primes
    std::vector<uint64_t> primes = {
        0x1FFFFFFFFFE00001ULL,  // 2^61 - 2^21 + 1 = 2305843009213325313 (61-bit)
        0x1FFFFFFFFFC80001ULL,  // 2305843009213292545 (61-bit)  
        0x1FFFFFFFFFB40001ULL   // 2305843009213259777 (61-bit)
    };
    return std::make_unique<RNSContext>(12, primes);  // log_n = 12 means n = 4096
}

/**
 * @brief Create 128-bit security context (n=8192)
 * Good for 5-level computations, recommended for production
 */
inline std::unique_ptr<RNSContext> SECURITY_128_N8192() {
    // NTT-friendly primes for n=8192: p ≡ 1 (mod 16384), max 61-bit for Barrett reduction
    std::vector<uint64_t> primes = {
        0x1FFFFFFFFFFA4001ULL,  // 2305843009213317121 (61-bit)
        0x1FFFFFFFFFF74001ULL,  // 2305843009213120513 (61-bit)
        0x1FFFFFFFFFF0C001ULL,  // 2305843009212694529 (61-bit)
        0x1FFFFFFFFFEC4001ULL,  // 2305843009212399617 (61-bit)
        0x1FFFFFFFFFE10001ULL   // 2305843009211662337 (61-bit)
    };
    return std::make_unique<RNSContext>(13, primes);  // log_n = 13 means n = 8192
}

/**
 * @brief Create 128-bit security context (n=16384)
 * Good for deep circuits (10+ levels)
 */
inline std::unique_ptr<RNSContext> SECURITY_128_N16384() {
    // NTT-friendly primes for n=16384: p ≡ 1 (mod 32768), max 61-bit for Barrett reduction
    std::vector<uint64_t> primes = {
        0x1FFFFFFFFFE10001ULL,  // 2305843009211662337 (61-bit)
        0x1FFFFFFFFFE00001ULL,  // 2305843009211596801 (61-bit)
        0x1FFFFFFFFFDD0001ULL,  // 2305843009211400193 (61-bit)
        0x1FFFFFFFFFD08001ULL,  // 2305843009210580993 (61-bit)
        0x1FFFFFFFFFCF8001ULL,  // 2305843009210515457 (61-bit)
        0x1FFFFFFFFFC80001ULL,  // 2305843009210023937 (61-bit)
        0x1FFFFFFFFFB40001ULL   // 2305843009208713217 (61-bit)
    };
    return std::make_unique<RNSContext>(14, primes);  // log_n = 14 means n = 16384
}

}  // namespace StandardParams

/**
 * @brief Create default RNS context for quick testing
 * 
 * Uses n=4096, 3 primes (~192 bits total Q)
 * Suitable for 128-bit security with 2-3 multiplication depths
 */
inline std::unique_ptr<RNSContext> create_default_rns_context() {
    return StandardParams::SECURITY_128_N4096();
}

/**
 * @brief Create RNS context with custom parameters
 * @param n Polynomial degree (power of 2)
 * @param primes Ciphertext modulus primes (each ~60-62 bits)
 * @return Unique pointer to RNS context
 */
inline std::unique_ptr<RNSContext> create_rns_context(
    size_t n, 
    const std::vector<uint64_t>& primes) {
    return std::make_unique<RNSContext>(n, primes);
}

}  // namespace bgv
}  // namespace fhe
}  // namespace kctsb

#endif // KCTSB_ADVANCED_FE_BGV_HPP
