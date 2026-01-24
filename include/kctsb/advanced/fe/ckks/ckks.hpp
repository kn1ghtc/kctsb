/**
 * @file ckks.hpp
 * @brief CKKS (Cheon-Kim-Kim-Song) Approximate Homomorphic Encryption Scheme
 * 
 * CKKS enables computation on encrypted floating-point numbers with controlled
 * approximation error. It is the primary scheme for ML inference and statistical
 * computation on encrypted data.
 * 
 * Key differences from BGV/BFV:
 * - Encoding: complex vectors  polynomial via canonical embedding (FFT)
 * - Messages are approximate: decryption returns m + e where |e| is small
 * - Scale management: multiply causes scale  need rescale to restore
 * 
 * @note Phase 4 will migrate to pure RNS architecture like BGV/BFV.
 * @note Currently disabled - awaiting pure RNS migration.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_ADVANCED_FE_CKKS_CKKS_HPP
#define KCTSB_ADVANCED_FE_CKKS_CKKS_HPP

// CKKS module is pending migration to pure RNS architecture
// Current implementation depends on ZZ/ZZ_p/ZZ_pX types which are being deprecated
// TODO: v4.14.0 - Migrate CKKS to pure RNS like BGV/BFV

#define KCTSB_CKKS_DISABLED 1

namespace kctsb::fhe::ckks {

/**
 * @brief Check if CKKS is available
 * @return false - CKKS is pending migration to pure RNS
 */
inline constexpr bool is_available() { return false; }

}  // namespace kctsb::fhe::ckks

#endif  // KCTSB_ADVANCED_FE_CKKS_CKKS_HPP