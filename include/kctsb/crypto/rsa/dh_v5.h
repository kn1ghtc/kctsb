/**
 * @file dh_v5.h
 * @brief Self-Contained Diffie-Hellman Key Exchange v5.0
 * 
 * Complete DH implementation using kctsb BigInt library.
 * No external dependencies (NTL, GMP removed).
 * 
 * Features:
 * - Standard DH Groups (RFC 7919: ffdhe2048, ffdhe3072, ffdhe4096)
 * - PKCS#3 DH parameter encoding
 * - Safe prime group support
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_DH_V5_H
#define KCTSB_CRYPTO_DH_V5_H

#include "kctsb/core/bigint.h"
#include <array>
#include <vector>
#include <cstdint>

namespace kctsb {
namespace dh {

// ============================================================================
// DH Group Types
// ============================================================================

/**
 * @brief Pre-defined DH groups per RFC 7919
 */
enum class DHGroupV5 {
    FFDHE2048 = 0,    ///< 2048-bit safe prime group
    FFDHE3072 = 1,    ///< 3072-bit safe prime group
    FFDHE4096 = 2     ///< 4096-bit safe prime group
};

// ============================================================================
// DH Parameters
// ============================================================================

/**
 * @brief DH Parameters (p, g, q)
 */
template<size_t BITS>
struct DHParamsV5 {
    BigInt<BITS> p;    ///< Prime modulus
    BigInt<BITS> g;    ///< Generator
    BigInt<BITS> q;    ///< Order of generator (optional, for validation)
    
    /**
     * @brief Get byte length of prime
     */
    size_t byte_len() const { return (BITS + 7) / 8; }
};

// ============================================================================
// DH Key Pair
// ============================================================================

/**
 * @brief DH Key Pair
 */
template<size_t BITS>
struct DHKeyPairV5 {
    BigInt<BITS> private_key;
    BigInt<BITS> public_key;
    
    /**
     * @brief Clear private key
     */
    void clear() { private_key.clear(); }
    
    /**
     * @brief Export public key to big-endian bytes
     */
    std::vector<uint8_t> export_public_key() const {
        std::vector<uint8_t> bytes(BITS / 8);
        public_key.to_bytes_be(bytes.data(), bytes.size());
        return bytes;
    }
    
    /**
     * @brief Export private key to big-endian bytes
     */
    std::vector<uint8_t> export_private_key() const {
        std::vector<uint8_t> bytes(BITS / 8);
        private_key.to_bytes_be(bytes.data(), bytes.size());
        return bytes;
    }
};

// ============================================================================
// Pre-defined DH Group Parameters
// ============================================================================

/**
 * @brief Get ffdhe2048 parameters (RFC 7919)
 */
const DHParamsV5<2048>& ffdhe2048_params();

/**
 * @brief Get ffdhe3072 parameters (RFC 7919)
 */
const DHParamsV5<3072>& ffdhe3072_params();

/**
 * @brief Get ffdhe4096 parameters (RFC 7919)
 */
const DHParamsV5<4096>& ffdhe4096_params();

// ============================================================================
// DH Class
// ============================================================================

/**
 * @brief Diffie-Hellman Key Exchange v5.0
 */
template<size_t BITS>
class DHV5 {
public:
    /**
     * @brief Construct with pre-defined group
     */
    explicit DHV5(DHGroupV5 group);
    
    /**
     * @brief Construct with custom parameters
     */
    explicit DHV5(const DHParamsV5<BITS>& params);
    
    /**
     * @brief Get current parameters
     */
    const DHParamsV5<BITS>& params() const { return params_; }
    
    /**
     * @brief Generate key pair
     */
    DHKeyPairV5<BITS> generate_keypair();
    
    /**
     * @brief Derive public key from private key
     */
    BigInt<BITS> derive_public_key(const BigInt<BITS>& private_key);
    
    /**
     * @brief Compute shared secret
     * @param private_key My private key
     * @param peer_public_key Peer's public key
     * @return Shared secret as bytes (big-endian)
     */
    std::vector<uint8_t> compute_shared_secret(
        const BigInt<BITS>& private_key,
        const BigInt<BITS>& peer_public_key);
    
    /**
     * @brief Validate public key
     * @return true if public key is valid (1 < pk < p-1)
     */
    bool validate_public_key(const BigInt<BITS>& public_key);
    
    /**
     * @brief Import public key from bytes
     */
    BigInt<BITS> import_public_key(const uint8_t* data, size_t len);
    
private:
    DHParamsV5<BITS> params_;
    MontgomeryContext<BITS> mont_ctx_;
};

// ============================================================================
// Type Aliases
// ============================================================================

using DH2048 = DHV5<2048>;
using DH3072 = DHV5<3072>;
using DH4096 = DHV5<4096>;

// ============================================================================
// High-Level API
// ============================================================================

/**
 * @brief Generate DH 2048-bit key pair (ffdhe2048)
 * @param private_key Output: 256 bytes private key (big-endian)
 * @param public_key Output: 256 bytes public key (big-endian)
 */
void dh2048_keygen(uint8_t private_key[256], uint8_t public_key[256]);

/**
 * @brief Compute DH 2048-bit shared secret
 * @param my_private My 256-byte private key
 * @param their_public Their 256-byte public key
 * @param shared_secret Output: 256-byte shared secret
 */
void dh2048_shared_secret(const uint8_t my_private[256],
                          const uint8_t their_public[256],
                          uint8_t shared_secret[256]);

} // namespace dh
} // namespace kctsb

#endif // KCTSB_CRYPTO_DH_V5_H
