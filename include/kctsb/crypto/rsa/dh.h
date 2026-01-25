/**
 * @file dh.h
 * @brief Self-Contained Diffie-Hellman Key Exchange
 * 
 * Complete DH implementation using kctsb BigInt library.
 * No external dependencies (NTL, GMP removed).
 * 
 * Features:
 * - Standard DH Groups (RFC 7919: ffdhe2048, ffdhe3072, ffdhe4096)
 * - PKCS#3 DH parameter encoding
 * - Safe prime group support
 * - Montgomery multiplication acceleration
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_DH_H
#define KCTSB_CRYPTO_DH_H

#include "kctsb/core/bigint.h"
#include <array>
#include <vector>
#include <cstdint>
#include <cstring>
#include <random>
#include <stdexcept>

namespace kctsb {
namespace dh {

// ============================================================================
// DH Group Types
// ============================================================================

/**
 * @brief Pre-defined DH groups per RFC 7919
 */
enum class DHGroup {
    FFDHE2048 = 0,    ///< 2048-bit safe prime group
    FFDHE3072 = 1,    ///< 3072-bit safe prime group  
    FFDHE4096 = 2     ///< 4096-bit safe prime group
};

// ============================================================================
// DH Parameters
// ============================================================================

/**
 * @brief DH Parameters (p, g, q) - template based on bit size
 */
template<size_t BITS>
struct DHParams {
    BigInt<BITS> p;    ///< Prime modulus
    BigInt<BITS> g;    ///< Generator
    BigInt<BITS> q;    ///< Order of generator (optional, for validation)
    
    /** @brief Get byte length of prime */
    static constexpr size_t byte_len() { return BITS / 8; }
    
    /** @brief Check if parameters are valid */
    bool is_valid() const {
        // Basic checks: p > 2, g in [2, p-2]
        BigInt<BITS> two(2);
        if (p <= two) return false;
        if (g < two) return false;
        if (g >= p) return false;
        return true;
    }
};

// ============================================================================
// DH Key Pair
// ============================================================================

/**
 * @brief DH Key Pair - template based on bit size
 */
template<size_t BITS>
struct DHKeyPair {
    BigInt<BITS> private_key;
    BigInt<BITS> public_key;
    
    /** @brief Clear private key securely */
    void clear() { 
        private_key.secure_zero(); 
    }
    
    /** @brief Export public key to big-endian bytes */
    std::vector<uint8_t> export_public_key() const {
        return public_key.to_bytes();
    }
    
    /** @brief Export private key to big-endian bytes */
    std::vector<uint8_t> export_private_key() const {
        return private_key.to_bytes();
    }
};

// ============================================================================
// Pre-defined DH Group Parameters (RFC 7919)
// ============================================================================

namespace detail {

// ffdhe2048 prime (RFC 7919)
inline const char* ffdhe2048_p_hex() {
    return "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
           "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
           "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
           "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
           "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
           "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
           "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
           "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
           "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
           "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
           "886B423861285C97FFFFFFFFFFFFFFFF";
}

// ffdhe3072 prime (RFC 7919)
inline const char* ffdhe3072_p_hex() {
    return "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
           "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
           "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
           "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
           "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
           "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
           "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
           "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
           "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
           "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
           "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
           "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
           "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"
           "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
           "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"
           "3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF";
}

// ffdhe4096 prime (RFC 7919)
inline const char* ffdhe4096_p_hex() {
    return "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
           "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
           "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
           "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
           "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
           "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
           "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
           "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
           "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
           "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
           "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
           "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
           "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"
           "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
           "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"
           "3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
           "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004"
           "87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"
           "A907600A918130C46DC778F971AD0038092999A333CB8B7A"
           "1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
           "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6A"
           "FFFFFFFFFFFFFFFF";
}

} // namespace detail

/**
 * @brief Get ffdhe2048 parameters (RFC 7919)
 */
inline DHParams<2048> ffdhe2048_params() {
    DHParams<2048> params;
    params.p.from_hex(detail::ffdhe2048_p_hex());
    params.g = BigInt<2048>(2);
    // q = (p-1)/2 for safe prime
    params.q = params.p;
    params.q -= BigInt<2048>(1);
    params.q >>= 1;
    return params;
}

/**
 * @brief Get ffdhe3072 parameters (RFC 7919)
 */
inline DHParams<3072> ffdhe3072_params() {
    DHParams<3072> params;
    params.p.from_hex(detail::ffdhe3072_p_hex());
    params.g = BigInt<3072>(2);
    params.q = params.p;
    params.q -= BigInt<3072>(1);
    params.q >>= 1;
    return params;
}

/**
 * @brief Get ffdhe4096 parameters (RFC 7919)
 */
inline DHParams<4096> ffdhe4096_params() {
    DHParams<4096> params;
    params.p.from_hex(detail::ffdhe4096_p_hex());
    params.g = BigInt<4096>(2);
    params.q = params.p;
    params.q -= BigInt<4096>(1);
    params.q >>= 1;
    return params;
}

// ============================================================================
// DH Class - Template Implementation
// ============================================================================

/**
 * @brief Diffie-Hellman Key Exchange
 * @tparam BITS Key size in bits (2048, 3072, 4096)
 */
template<size_t BITS>
class DH {
public:
    using Int = BigInt<BITS>;
    using Params = DHParams<BITS>;
    using KeyPair = DHKeyPair<BITS>;
    
    /** @brief Construct with custom parameters */
    explicit DH(const Params& params) 
        : params_(params), mont_ctx_(params.p) {
        if (!params_.is_valid()) {
            throw std::invalid_argument("Invalid DH parameters");
        }
    }
    
    /** @brief Get current parameters */
    const Params& params() const { return params_; }
    
    /** @brief Generate key pair */
    KeyPair generate_keypair() {
        KeyPair kp;
        
        // Generate random private key in [2, q-1]
        std::random_device rd;
        std::mt19937_64 gen(rd());
        
        Int upper = params_.q.is_zero() ? params_.p : params_.q;
        
        do {
            kp.private_key = random_bigint<BITS>(gen);
            // Ensure private key < upper
            while (kp.private_key >= upper) {
                kp.private_key >>= 1;
            }
        } while (kp.private_key <= Int(1));
        
        // Compute public key: y = g^x mod p
        kp.public_key = mont_ctx_.pow_mod(params_.g, kp.private_key);
        
        return kp;
    }
    
    /** @brief Derive public key from private key */
    Int derive_public_key(const Int& private_key) {
        return mont_ctx_.pow_mod(params_.g, private_key);
    }
    
    /**
     * @brief Compute shared secret
     * @param private_key My private key
     * @param peer_public_key Peer's public key
     * @return Shared secret as bytes (big-endian)
     */
    std::vector<uint8_t> compute_shared_secret(
        const Int& private_key,
        const Int& peer_public_key) {
        
        if (!validate_public_key(peer_public_key)) {
            throw std::invalid_argument("Invalid peer public key");
        }
        
        // shared = peer_public^private mod p
        Int shared = mont_ctx_.pow_mod(peer_public_key, private_key);
        
        // Check for weak shared secret
        if (shared <= Int(1)) {
            throw std::runtime_error("DH computation resulted in weak shared secret");
        }
        
        return shared.to_bytes();
    }
    
    /**
     * @brief Validate public key
     * @return true if public key is valid (1 < pk < p-1)
     */
    bool validate_public_key(const Int& public_key) {
        Int one(1);
        Int p_minus_1 = params_.p;
        p_minus_1 -= one;
        
        if (public_key <= one) return false;
        if (public_key >= p_minus_1) return false;
        
        return true;
    }
    
    /** @brief Import public key from bytes */
    Int import_public_key(const uint8_t* data, size_t len) {
        Int pk(data, len);
        if (!validate_public_key(pk)) {
            throw std::invalid_argument("Invalid public key");
        }
        return pk;
    }
    
private:
    Params params_;
    MontgomeryContext<BITS> mont_ctx_;
};

// ============================================================================
// Type Aliases for Common Sizes
// ============================================================================

using DH2048 = DH<2048>;
using DH3072 = DH<3072>;
using DH4096 = DH<4096>;

// ============================================================================
// High-Level C-Style API
// ============================================================================

/**
 * @brief Generate DH 2048-bit key pair (ffdhe2048)
 * @param private_key Output: 256 bytes private key (big-endian)
 * @param public_key Output: 256 bytes public key (big-endian)
 */
inline void dh2048_keygen(uint8_t private_key[256], uint8_t public_key[256]) {
    DH2048 dh(ffdhe2048_params());
    auto kp = dh.generate_keypair();
    kp.private_key.to_bytes(private_key, 256);
    kp.public_key.to_bytes(public_key, 256);
}

/**
 * @brief Compute DH 2048-bit shared secret
 * @param my_private My 256-byte private key
 * @param their_public Their 256-byte public key
 * @param shared_secret Output: 256-byte shared secret
 */
inline void dh2048_shared_secret(const uint8_t my_private[256],
                                  const uint8_t their_public[256],
                                  uint8_t shared_secret[256]) {
    DH2048 dh(ffdhe2048_params());
    BigInt<2048> priv(my_private, 256);
    BigInt<2048> pub(their_public, 256);
    auto secret = dh.compute_shared_secret(priv, pub);
    std::memcpy(shared_secret, secret.data(), 256);
}

} // namespace dh
} // namespace kctsb

#endif // KCTSB_CRYPTO_DH_H
