/**
 * @file kctsb.h
 * @brief kctsb v5.0 - Self-Contained Cryptographic Library
 * 
 * Unified header for all self-contained cryptographic modules.
 * No external dependencies on NTL, HElib, or GMP for core functionality.
 * 
 * Architecture:
 * - BigInt<BITS>: Template-based arbitrary precision integers
 * - Fe256: Optimized 256-bit field elements for ECC
 * - Montgomery arithmetic for modular operations
 * - Constant-time implementations for side-channel resistance
 * 
 * Modules:
 * - Core: BigInt, Fe256, MontgomeryContext
 * - RSA: RSA (PKCS#1 v2.2: OAEP, PSS)
 * - ECC: ECCurve, ECDSA, ECDH (secp256k1, P-256)
 * - SM2: SM2Signer, SM2Encryptor (GM/T 0003-2012)
 * - DH: DH (RFC 7919: ffdhe2048/3072/4096)
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

#ifndef KCTSB_H
#define KCTSB_H

// ============================================================================
// Version Information
// ============================================================================

#define KCTSB_VERSION_MAJOR 5
#define KCTSB_VERSION_MINOR 0
#define KCTSB_VERSION_PATCH 0
#define KCTSB_VERSION_STRING "5.0.0"

// ============================================================================
// Core Modules
// ============================================================================

#include "kctsb/core/bigint.h"    // BigInt<BITS>, MontgomeryContext<BITS>
#include "kctsb/core/fe256.h"     // Fe256, Fe256MontContext

// ============================================================================
// Cryptographic Modules
// ============================================================================

#include "kctsb/crypto/rsa/rsa.h"       // RSA, RSA2048, RSA4096
#include "kctsb/crypto/ecc/ecc.h"       // ECCurve, ECDSA, ECDH
#include "kctsb/crypto/sm/sm2.h"        // SM2Signer, SM2Encryptor

// ============================================================================
// Namespace Aliases
// ============================================================================

namespace kctsb {

// ============================================================================
// Convenience Type Aliases (No V5 suffix - clean API)
// ============================================================================

// Core types are already in kctsb namespace via headers

// RSA convenience aliases
using RSA2048 = rsa::RSA2048;
using RSA3072 = rsa::RSA3072;
using RSA4096 = rsa::RSA4096;

// ECC types (forward declarations - actual types in ecc.h)
// Note: These will be available after ecc.h V5 suffix removal

// SM2 types (forward declarations - actual types in sm2.h)
// Note: These will be available after sm2.h V5 suffix removal

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

#endif // KCTSB_H
