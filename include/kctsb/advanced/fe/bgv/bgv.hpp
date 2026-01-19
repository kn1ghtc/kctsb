/**
 * @file bgv.hpp
 * @brief BGV Homomorphic Encryption Scheme - Main Header
 * 
 * This is the main include file for the BGV (Brakerski-Gentry-Vaikuntanathan)
 * homomorphic encryption scheme implementation in kctsb.
 * 
 * BGV is a leveled fully homomorphic encryption scheme that supports:
 * - Exact integer arithmetic (no approximation)
 * - SIMD operations via batching (CRT packing)
 * - Efficient modulus switching for noise management
 * 
 * This implementation is based on kctsb's bignum library (NTL-compatible)
 * and does not require external HE libraries like SEAL or HElib.
 * 
 * Quick Start:
 * @code
 * #include <kctsb/advanced/fe/bgv/bgv.hpp>
 * 
 * using namespace kctsb::fhe::bgv;
 * 
 * // 1. Create context with standard parameters
 * auto params = StandardParams::SECURITY_128_DEPTH_3();
 * BGVContext context(params);
 * 
 * // 2. Generate keys
 * auto sk = context.generate_secret_key();
 * auto pk = context.generate_public_key(sk);
 * auto rk = context.generate_relin_key(sk);
 * 
 * // 3. Encode and encrypt
 * BGVEncoder encoder(context);
 * auto pt1 = encoder.encode_batch({1, 2, 3, 4});
 * auto pt2 = encoder.encode_batch({5, 6, 7, 8});
 * auto ct1 = context.encrypt(pk, pt1);
 * auto ct2 = context.encrypt(pk, pt2);
 * 
 * // 4. Homomorphic operations
 * BGVEvaluator evaluator(context);
 * auto ct_sum = evaluator.add(ct1, ct2);
 * auto ct_prod = evaluator.multiply_relin(ct1, ct2, rk);
 * 
 * // 5. Decrypt and decode
 * auto result_sum = context.decrypt(sk, ct_sum);
 * auto values = encoder.decode_batch(result_sum);  // {6, 8, 10, 12}
 * @endcode
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_ADVANCED_FE_BGV_HPP
#define KCTSB_ADVANCED_FE_BGV_HPP

// Core types and parameters
#include "bgv_types.hpp"

// Context and key management
#include "bgv_context.hpp"

// Plaintext encoding
#include "bgv_encoder.hpp"

// Homomorphic evaluation
#include "bgv_evaluator.hpp"

namespace kctsb {
namespace fhe {
namespace bgv {

/**
 * @brief BGV Library Version
 */
constexpr int BGV_VERSION_MAJOR = 1;
constexpr int BGV_VERSION_MINOR = 0;
constexpr int BGV_VERSION_PATCH = 0;

/**
 * @brief Get version string
 * @return Version in "major.minor.patch" format
 */
inline const char* bgv_version() {
    static const char version[] = "1.0.0";
    return version;
}

/**
 * @brief Check if build supports SIMD batching
 * 
 * Batching requires computing primitive roots in Z_t,
 * which is only possible for certain choices of t.
 */
inline bool supports_batching(uint64_t t, uint64_t m) {
    // t must be coprime to m and split completely in Z[X]/(Φ_m(X))
    // Simplified check: t = 1 (mod m) or more complex conditions
    return (t % m == 1);
}

/**
 * @brief Convenience function to create complete keyset
 * 
 * @param context BGV context
 * @param rotation_steps Rotation steps to support (empty = all)
 * @return Tuple of (secret_key, public_key, relin_key, galois_keys)
 */
inline std::tuple<BGVSecretKey, BGVPublicKey, BGVRelinKey, BGVGaloisKey>
generate_all_keys(BGVContext& context, 
                  const std::vector<int>& rotation_steps = {}) {
    auto sk = context.generate_secret_key();
    auto pk = context.generate_public_key(sk);
    auto rk = context.generate_relin_key(sk);
    auto gk = context.generate_galois_keys(sk, rotation_steps);
    return {std::move(sk), std::move(pk), std::move(rk), std::move(gk)};
}

} // namespace bgv
} // namespace fhe
} // namespace kctsb

#endif // KCTSB_ADVANCED_FE_BGV_HPP
