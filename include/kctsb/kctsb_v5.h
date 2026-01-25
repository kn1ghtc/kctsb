/**
 * @file kctsb_v5.h
 * @brief kctsb v5.0 - Self-Contained Cryptographic Library
 * 
 * Unified header for all v5.0 self-contained cryptographic modules.
 * No external dependencies on NTL, HElib, or GMP for core functionality.
 * 
 * v5.0 Architecture:
 * - BigInt<BITS>: Template-based arbitrary precision integers
 * - Fe256: Optimized 256-bit field elements for ECC
 * - Montgomery arithmetic for modular operations
 * - Constant-time implementations for side-channel resistance
 * 
 * Modules:
 * - Core: BigInt, Fe256, MontgomeryContext
 * - RSA: RSAV5 (PKCS#1 v2.2: OAEP, PSS)
 * - ECC: ECCurveV5, ECDSAV5, ECDHV5 (secp256k1, P-256)
 * - SM2: SM2SignerV5, SM2EncryptorV5 (GM/T 0003-2012)
 * - DH: DHV5 (RFC 7919: ffdhe2048/3072/4096)
 * 
 * Reference Implementation:
 * - OpenSSL 3.6.0: For RSA/DH standards compliance
 * - GmSSL: For SM2 Chinese National Standard
 * - libsecp256k1: For ECC optimization patterns
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_V5_H
#define KCTSB_V5_H

// ============================================================================
// Version Information
// ============================================================================

#define KCTSB_V5_VERSION_MAJOR 5
#define KCTSB_V5_VERSION_MINOR 0
#define KCTSB_V5_VERSION_PATCH 0
#define KCTSB_V5_VERSION_STRING "5.0.0"

// ============================================================================
// Core Modules
// ============================================================================

#include "kctsb/core/bigint.h"    // BigInt<BITS>, MontgomeryContext<BITS>
#include "kctsb/core/fe256.h"     // Fe256, Fe256MontContext

// ============================================================================
// Cryptographic Modules
// ============================================================================

#include "kctsb/crypto/rsa/rsa_v5.h"     // RSAV5, RSA2048, RSA4096
#include "kctsb/crypto/rsa/dh_v5.h"      // DHV5, DH2048, DH4096
#include "kctsb/crypto/ecc/ecc_v5.h"     // ECCurveV5, ECDSAV5, ECDHV5
#include "kctsb/crypto/sm/sm2_v5.h"      // SM2SignerV5, SM2EncryptorV5

// ============================================================================
// Namespace Aliases
// ============================================================================

namespace kctsb {

/**
 * @brief v5.0 API namespace
 * 
 * Contains all self-contained cryptographic implementations.
 * Use this namespace for new code to ensure no external dependencies.
 */
namespace v5 {
    // Core types
    using kctsb::BigInt;
    using kctsb::MontgomeryContext;
    using kctsb::Fe256;
    using kctsb::Fe512;
    using kctsb::Fe256MontContext;
    
    // RSA
    using kctsb::rsa::RSAV5;
    using kctsb::rsa::RSAPublicKeyV5;
    using kctsb::rsa::RSAPrivateKeyV5;
    using kctsb::rsa::RSA2048;
    using kctsb::rsa::RSA3072;
    using kctsb::rsa::RSA4096;
    
    // DH
    using kctsb::dh::DHV5;
    using kctsb::dh::DHParamsV5;
    using kctsb::dh::DHKeyPairV5;
    using kctsb::dh::DH2048;
    using kctsb::dh::DH3072;
    using kctsb::dh::DH4096;
    
    // ECC
    using kctsb::ecc::ECCurveV5;
    using kctsb::ecc::AffinePointV5;
    using kctsb::ecc::JacobianPointV5;
    using kctsb::ecc::CurveTypeV5;
    using kctsb::ecc::ECDSAV5;
    using kctsb::ecc::ECDSASignatureV5;
    using kctsb::ecc::ECDHV5;
    
    // SM2
    using kctsb::sm::SM2PrivateKeyV5;
    using kctsb::sm::SM2PublicKeyV5;
    using kctsb::sm::SM2SignatureV5;
    using kctsb::sm::SM2SignerV5;
    using kctsb::sm::SM2KeyExchangeV5;
    using kctsb::sm::SM2EncryptorV5;
    
} // namespace v5

} // namespace kctsb

// ============================================================================
// Quick Start Examples
// ============================================================================

/**
 * @example rsa_example.cpp
 * @code
 * #include "kctsb/kctsb_v5.h"
 * 
 * using namespace kctsb::v5;
 * 
 * // Generate RSA-2048 key pair
 * RSA2048 rsa;
 * auto [pub, priv] = rsa.generate_keypair();
 * 
 * // Sign with PSS
 * uint8_t hash[32] = {...};
 * auto signature = rsa.sign_pss(hash, sizeof(hash), priv);
 * 
 * // Verify
 * bool valid = rsa.verify_pss(hash, sizeof(hash), signature, pub);
 * @endcode
 * 
 * @example ecdsa_example.cpp
 * @code
 * #include "kctsb/kctsb_v5.h"
 * 
 * using namespace kctsb::ecc;
 * 
 * // Generate secp256k1 key pair
 * uint8_t priv[32], pub[65];
 * secp256k1_keygen(priv, pub);
 * 
 * // Sign hash
 * uint8_t hash[32] = {...};
 * uint8_t sig[64];
 * secp256k1_sign(hash, priv, sig);
 * 
 * // Verify
 * bool valid = secp256k1_verify(hash, pub, sig);
 * @endcode
 * 
 * @example sm2_example.cpp
 * @code
 * #include "kctsb/kctsb_v5.h"
 * 
 * using namespace kctsb::sm;
 * 
 * // Generate SM2 key pair
 * uint8_t priv[32], pub[65];
 * sm2_keygen(priv, pub);
 * 
 * // Sign with default user ID
 * uint8_t msg[] = "Hello SM2";
 * uint8_t sig[64];
 * sm2_sign(msg, sizeof(msg)-1, priv, nullptr, 0, sig);
 * 
 * // Verify
 * bool valid = sm2_verify(msg, sizeof(msg)-1, pub, nullptr, 0, sig);
 * 
 * // Encrypt
 * auto ciphertext = sm2_encrypt(msg, sizeof(msg)-1, pub);
 * 
 * // Decrypt
 * auto plaintext = sm2_decrypt(ciphertext.data(), ciphertext.size(), priv);
 * @endcode
 */

#endif // KCTSB_V5_H
