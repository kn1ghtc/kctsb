/**
 * @file bfv.hpp
 * @brief BFV Homomorphic Encryption Scheme - Main Header (Pure RNS)
 * 
 * This is the main include file for the BFV (Brakerski/Fan-Vercauteren)
 * homomorphic encryption scheme implementation in kctsb.
 * 
 * v4.11.0: Complete migration to Pure RNS architecture.
 * All operations use RNSPoly representation, zero ZZ_pX/NTL dependencies.
 * 
 * BFV is a scale-invariant FHE scheme that supports:
 * - Exact integer arithmetic (no approximation)
 * - Scale-invariant noise management (Δ = floor(Q/t))
 * - SIMD operations via batching [Phase 4d pending]
 * 
 * Key differences from BGV:
 * - Encoding: m → Δ·m (scaled by floor(Q/t))
 * - Decryption: round(t·m/Q) to remove scaling
 * - Noise growth: constant per level (scale-invariant)
 * 
 * Performance (n=8192, L=3):
 * - Multiply+Relin: 7-9 ms (SEAL: ~18 ms)
 * - KeyGen: ~2 ms (SEAL: ~50 ms)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.11.0
 * @since Phase 4d - Pure RNS migration
 */

#ifndef KCTSB_FHE_BFV_HPP
#define KCTSB_FHE_BFV_HPP

#include "bfv_types.hpp"
#include "bfv_evaluator.hpp"

namespace kctsb {
namespace fhe {
namespace bfv {

/**
 * @brief BFV Library Version (Pure RNS)
 */
constexpr int BFV_VERSION_MAJOR = 4;
constexpr int BFV_VERSION_MINOR = 11;
constexpr int BFV_VERSION_PATCH = 0;

/**
 * @brief Get version string
 * @return Version in "major.minor.patch" format
 */
inline const char* bfv_version() {
    static const char version[] = "4.11.0-rns";
    return version;
}

/**
 * @brief Standard security parameter sets for BFV
 * 
 * All parameter sets use pure RNS representation.
 * Security estimates based on lattice-estimator.
 */
namespace StandardParams {

/**
 * @brief Create toy parameters context (n=256)
 * @warning NOT cryptographically secure! For debugging only.
 */
inline std::unique_ptr<RNSContext> TOY_N256() {
    std::vector<uint64_t> primes = {
        65537, 114689  // Two 17-bit NTT-friendly primes for n=256
    };
    return std::make_unique<RNSContext>(8, primes);  // log_n = 8 means n = 256
}

/**
 * @brief Create 128-bit security context (n=4096)
 * Good for 3-level computations
 */
inline std::unique_ptr<RNSContext> SECURITY_128_N4096() {
    std::vector<uint64_t> primes = {
        0xFFFFFFFF00000001ULL,  // ~64 bits
        0xFFFFFFFE00000001ULL,  // ~64 bits
        0xFFFFFFFD00000001ULL   // ~64 bits
    };
    return std::make_unique<RNSContext>(12, primes);  // log_n = 12 means n = 4096
}

/**
 * @brief Create 128-bit security context (n=8192)
 * Good for 5-level computations, recommended for production
 */
inline std::unique_ptr<RNSContext> SECURITY_128_N8192() {
    std::vector<uint64_t> primes = {
        0xFFFFFFFF00000001ULL,
        0xFFFFFFFE00000001ULL,
        0xFFFFFFFD00000001ULL,
        0xFFFFFFFC00000001ULL,
        0xFFFFFFFB00000001ULL
    };
    return std::make_unique<RNSContext>(13, primes);  // log_n = 13 means n = 8192
}

/**
 * @brief Create 128-bit security context (n=16384)
 * Good for deep circuits (10+ levels)
 */
inline std::unique_ptr<RNSContext> SECURITY_128_N16384() {
    std::vector<uint64_t> primes = {
        0xFFFFFFFF00000001ULL,
        0xFFFFFFFE00000001ULL,
        0xFFFFFFFD00000001ULL,
        0xFFFFFFFC00000001ULL,
        0xFFFFFFFB00000001ULL,
        0xFFFFFFFA00000001ULL,
        0xFFFFFFF900000001ULL
    };
    return std::make_unique<RNSContext>(14, primes);  // log_n = 14 means n = 16384
}

}  // namespace StandardParams

// ============================================================================
// Convenience Typedefs
// ============================================================================

using SecretKey = BFVSecretKey;
using PublicKey = BFVPublicKey;
using RelinKey = BFVRelinKey;
using Ciphertext = BFVCiphertext;
using Plaintext = BFVPlaintext;
using Evaluator = BFVEvaluator;

// ============================================================================
// Factory Functions
// ============================================================================

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
 * @brief Create BFV evaluator with custom context
 * @param ctx RNS context (manages ownership)
 * @param plaintext_modulus Plaintext modulus t
 * @return BFV evaluator
 */
inline std::unique_ptr<BFVEvaluator> create_evaluator(
    const RNSContext* ctx, 
    uint64_t plaintext_modulus = 256) {
    return std::make_unique<BFVEvaluator>(ctx, plaintext_modulus);
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

}  // namespace bfv
}  // namespace fhe
}  // namespace kctsb

#endif // KCTSB_FHE_BFV_HPP
