/**
 * @file rsa_padding.cpp
 * @brief RSA Padding Schemes Implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/rsa/rsa_padding.h"
#include "kctsb/crypto/sha256.h"
#include "kctsb/crypto/sha512.h"
#include <cstring>
#include <random>
#include <stdexcept>

namespace kctsb {
namespace rsa {

// ============================================================================
// Helper Functions
// ============================================================================

namespace {

/**
 * @brief Compute hash using specified algorithm
 */
std::vector<uint8_t> compute_hash(
    const uint8_t* data,
    size_t len,
    OAEPParams::HashAlgorithm algo
) {
    std::vector<uint8_t> hash;
    
    switch (algo) {
        case OAEPParams::HashAlgorithm::SHA256: {
            hash.resize(32);
            kctsb_sha256_ctx_t ctx;
            kctsb_sha256_init(&ctx);
            kctsb_sha256_update(&ctx, data, len);
            kctsb_sha256_final(&ctx, hash.data());
            break;
        }
        case OAEPParams::HashAlgorithm::SHA384: {
            hash.resize(48);
            kctsb_sha512_ctx_t ctx;
            kctsb_sha512_init(&ctx);
            kctsb_sha512_update(&ctx, data, len);
            uint8_t tmp[64];
            kctsb_sha512_final(&ctx, tmp);
            std::memcpy(hash.data(), tmp, 48); // SHA-384 is truncated SHA-512
            break;
        }
        case OAEPParams::HashAlgorithm::SHA512: {
            hash.resize(64);
            kctsb_sha512_ctx_t ctx;
            kctsb_sha512_init(&ctx);
            kctsb_sha512_update(&ctx, data, len);
            kctsb_sha512_final(&ctx, hash.data());
            break;
        }
    }
    
    return hash;
}

/**
 * @brief XOR two byte arrays
 */
void xor_arrays(uint8_t* dest, const uint8_t* src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dest[i] ^= src[i];
    }
}

} // anonymous namespace

// ============================================================================
// MGF1 Implementation
// ============================================================================

std::vector<uint8_t> mgf1(
    const uint8_t* seed,
    size_t seed_len,
    size_t mask_len,
    const OAEPParams& params
) {
    size_t hlen = params.hash_length();
    std::vector<uint8_t> mask;
    mask.reserve(mask_len);
    
    // Compute ceil(mask_len / hlen) iterations
    uint32_t counter = 0;
    while (mask.size() < mask_len) {
        // Hash(seed || counter)
        std::vector<uint8_t> input(seed_len + 4);
        std::memcpy(input.data(), seed, seed_len);
        input[seed_len + 0] = static_cast<uint8_t>(counter >> 24);
        input[seed_len + 1] = static_cast<uint8_t>(counter >> 16);
        input[seed_len + 2] = static_cast<uint8_t>(counter >> 8);
        input[seed_len + 3] = static_cast<uint8_t>(counter);
        
        auto hash = compute_hash(input.data(), input.size(), params.hash);
        
        size_t copy_len = std::min(hlen, mask_len - mask.size());
        mask.insert(mask.end(), hash.begin(), hash.begin() + static_cast<std::ptrdiff_t>(copy_len));
        
        counter++;
    }
    
    mask.resize(mask_len);
    return mask;
}

// ============================================================================
// EME-OAEP Implementation
// ============================================================================

std::vector<uint8_t> eme_oaep_encode(
    const uint8_t* message,
    size_t msg_len,
    size_t em_len,
    const OAEPParams& params
) {
    size_t hlen = params.hash_length();
    
    // Check message length: mLen <= k - 2*hLen - 2
    if (msg_len > em_len - 2 * hlen - 2) {
        throw std::invalid_argument("Message too long for OAEP");
    }
    
    // Compute lHash = Hash(label)
    auto lHash = compute_hash(
        params.label.empty() ? nullptr : params.label.data(),
        params.label.size(),
        params.hash
    );
    
    // Construct DB = lHash || PS || 0x01 || M
    size_t ps_len = em_len - msg_len - 2 * hlen - 2;
    std::vector<uint8_t> DB(em_len - hlen - 1);
    std::memcpy(DB.data(), lHash.data(), hlen);
    std::memset(DB.data() + hlen, 0x00, ps_len);
    DB[hlen + ps_len] = 0x01;
    std::memcpy(DB.data() + hlen + ps_len + 1, message, msg_len);
    
    // Generate random seed
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::vector<uint8_t> seed(hlen);
    for (size_t i = 0; i < hlen; i++) {
        seed[i] = static_cast<uint8_t>(gen() & 0xFF);
    }
    
    // Compute dbMask = MGF(seed, k - hLen - 1)
    auto dbMask = mgf1(seed.data(), hlen, em_len - hlen - 1, params);
    
    // Compute maskedDB = DB xor dbMask
    std::vector<uint8_t> maskedDB = DB;
    xor_arrays(maskedDB.data(), dbMask.data(), maskedDB.size());
    
    // Compute seedMask = MGF(maskedDB, hLen)
    auto seedMask = mgf1(maskedDB.data(), maskedDB.size(), hlen, params);
    
    // Compute maskedSeed = seed xor seedMask
    std::vector<uint8_t> maskedSeed = seed;
    xor_arrays(maskedSeed.data(), seedMask.data(), hlen);
    
    // EM = 0x00 || maskedSeed || maskedDB
    std::vector<uint8_t> em(em_len);
    em[0] = 0x00;
    std::memcpy(em.data() + 1, maskedSeed.data(), hlen);
    std::memcpy(em.data() + 1 + hlen, maskedDB.data(), maskedDB.size());
    
    return em;
}

std::vector<uint8_t> eme_oaep_decode(
    const uint8_t* em,
    size_t em_len,
    const OAEPParams& params
) {
    size_t hlen = params.hash_length();
    
    if (em_len < 2 * hlen + 2) {
        throw std::runtime_error("Invalid OAEP ciphertext length");
    }
    
    // Check Y = 0x00
    if (em[0] != 0x00) {
        throw std::runtime_error("Invalid OAEP padding");
    }
    
    // Extract maskedSeed and maskedDB
    std::vector<uint8_t> maskedSeed(em + 1, em + 1 + hlen);
    std::vector<uint8_t> maskedDB(em + 1 + hlen, em + em_len);
    
    // Compute seedMask = MGF(maskedDB, hLen)
    auto seedMask = mgf1(maskedDB.data(), maskedDB.size(), hlen, params);
    
    // Compute seed = maskedSeed xor seedMask
    std::vector<uint8_t> seed = maskedSeed;
    xor_arrays(seed.data(), seedMask.data(), hlen);
    
    // Compute dbMask = MGF(seed, k - hLen - 1)
    auto dbMask = mgf1(seed.data(), hlen, em_len - hlen - 1, params);
    
    // Compute DB = maskedDB xor dbMask
    std::vector<uint8_t> DB = maskedDB;
    xor_arrays(DB.data(), dbMask.data(), DB.size());
    
    // Compute lHash = Hash(label)
    auto lHash = compute_hash(
        params.label.empty() ? nullptr : params.label.data(),
        params.label.size(),
        params.hash
    );
    
    // Check lHash matches
    if (std::memcmp(DB.data(), lHash.data(), hlen) != 0) {
        throw std::runtime_error("OAEP label hash mismatch");
    }
    
    // Find 0x01 separator
    size_t sep = hlen;
    while (sep < DB.size() && DB[sep] == 0x00) sep++;
    
    if (sep >= DB.size() || DB[sep] != 0x01) {
        throw std::runtime_error("Invalid OAEP padding structure");
    }
    
    // Extract message
    return std::vector<uint8_t>(DB.begin() + static_cast<std::ptrdiff_t>(sep) + 1, DB.end());
}

// ============================================================================
// EMSA-PSS Implementation
// ============================================================================

std::vector<uint8_t> emsa_pss_encode(
    const uint8_t* mHash,
    size_t hlen,
    size_t em_bits,
    const PSSParams& params
) {
    size_t em_len = (em_bits + 7) / 8;
    
    if (em_len < hlen + params.salt_length + 2) {
        throw std::invalid_argument("Encoding error: insufficient space");
    }
    
    // Generate random salt
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::vector<uint8_t> salt(params.salt_length);
    for (size_t i = 0; i < params.salt_length; i++) {
        salt[i] = static_cast<uint8_t>(gen() & 0xFF);
    }
    
    // Compute M' = 0x00...00 || mHash || salt
    std::vector<uint8_t> m_prime(8 + hlen + params.salt_length);
    std::memset(m_prime.data(), 0x00, 8);
    std::memcpy(m_prime.data() + 8, mHash, hlen);
    std::memcpy(m_prime.data() + 8 + hlen, salt.data(), params.salt_length);
    
    // Compute H = Hash(M')
    OAEPParams hash_params;
    hash_params.hash = static_cast<OAEPParams::HashAlgorithm>(params.hash);
    auto H = compute_hash(m_prime.data(), m_prime.size(), hash_params.hash);
    
    // Construct DB = PS || 0x01 || salt
    size_t ps_len = em_len - params.salt_length - hlen - 2;
    std::vector<uint8_t> DB(em_len - hlen - 1);
    std::memset(DB.data(), 0x00, ps_len);
    DB[ps_len] = 0x01;
    std::memcpy(DB.data() + ps_len + 1, salt.data(), params.salt_length);
    
    // Compute dbMask = MGF(H, emLen - hLen - 1)
    OAEPParams mgf_params;
    mgf_params.hash = static_cast<OAEPParams::HashAlgorithm>(params.hash);
    auto dbMask = mgf1(H.data(), hlen, em_len - hlen - 1, mgf_params);
    
    // Compute maskedDB = DB xor dbMask
    std::vector<uint8_t> maskedDB = DB;
    xor_arrays(maskedDB.data(), dbMask.data(), maskedDB.size());
    
    // Set leftmost bits to zero
    size_t zero_bits = 8 * em_len - em_bits;
    if (zero_bits > 0) {
        maskedDB[0] &= (0xFF >> zero_bits);
    }
    
    // EM = maskedDB || H || 0xbc
    std::vector<uint8_t> em(em_len);
    std::memcpy(em.data(), maskedDB.data(), maskedDB.size());
    std::memcpy(em.data() + maskedDB.size(), H.data(), hlen);
    em[em_len - 1] = 0xbc;
    
    return em;
}

bool emsa_pss_verify(
    const uint8_t* mHash,
    size_t hlen,
    const uint8_t* em,
    size_t em_bits,
    const PSSParams& params
) {
    size_t em_len = (em_bits + 7) / 8;
    
    if (em_len < hlen + params.salt_length + 2) {
        return false;
    }
    
    // Check rightmost byte is 0xbc
    if (em[em_len - 1] != 0xbc) {
        return false;
    }
    
    // Extract maskedDB and H
    std::vector<uint8_t> maskedDB(em, em + em_len - hlen - 1);
    std::vector<uint8_t> H(em + em_len - hlen - 1, em + em_len - 1);
    
    // Check leftmost bits are zero
    size_t zero_bits = 8 * em_len - em_bits;
    if (zero_bits > 0) {
        uint8_t mask = 0xFF >> zero_bits;
        if ((maskedDB[0] & ~mask) != 0) {
            return false;
        }
    }
    
    // Compute dbMask = MGF(H, emLen - hLen - 1)
    OAEPParams mgf_params;
    mgf_params.hash = static_cast<OAEPParams::HashAlgorithm>(params.hash);
    auto dbMask = mgf1(H.data(), hlen, em_len - hlen - 1, mgf_params);
    
    // Compute DB = maskedDB xor dbMask
    std::vector<uint8_t> DB = maskedDB;
    xor_arrays(DB.data(), dbMask.data(), DB.size());
    
    // Set leftmost bits to zero
    if (zero_bits > 0) {
        DB[0] &= (0xFF >> zero_bits);
    }
    
    // Check DB structure
    size_t ps_len = em_len - params.salt_length - hlen - 2;
    for (size_t i = 0; i < ps_len; i++) {
        if (DB[i] != 0x00) return false;
    }
    if (DB[ps_len] != 0x01) return false;
    
    // Extract salt
    std::vector<uint8_t> salt(DB.begin() + static_cast<std::ptrdiff_t>(ps_len) + 1, DB.end());
    
    // Compute M' = 0x00...00 || mHash || salt
    std::vector<uint8_t> m_prime(8 + hlen + params.salt_length);
    std::memset(m_prime.data(), 0x00, 8);
    std::memcpy(m_prime.data() + 8, mHash, hlen);
    std::memcpy(m_prime.data() + 8 + hlen, salt.data(), params.salt_length);
    
    // Compute H' = Hash(M')
    OAEPParams hash_params;
    hash_params.hash = static_cast<OAEPParams::HashAlgorithm>(params.hash);
    auto H_prime = compute_hash(m_prime.data(), m_prime.size(), hash_params.hash);
    
    // Compare H == H'
    return std::memcmp(H.data(), H_prime.data(), hlen) == 0;
}

// ============================================================================
// PKCS#1 v1.5 Implementation
// ============================================================================

std::vector<uint8_t> eme_pkcs1_encode(
    const uint8_t* message,
    size_t msg_len,
    size_t em_len
) {
    if (msg_len > em_len - 11) {
        throw std::invalid_argument("Message too long for PKCS#1");
    }
    
    // EM = 0x00 || 0x02 || PS || 0x00 || M
    std::vector<uint8_t> em(em_len);
    em[0] = 0x00;
    em[1] = 0x02;
    
    // Generate random non-zero padding
    std::random_device rd;
    std::mt19937_64 gen(rd());
    size_t ps_len = em_len - msg_len - 3;
    for (size_t i = 0; i < ps_len; i++) {
        uint8_t r;
        do {
            r = static_cast<uint8_t>(gen() & 0xFF);
        } while (r == 0);
        em[2 + i] = r;
    }
    
    em[2 + ps_len] = 0x00;
    std::memcpy(em.data() + 3 + ps_len, message, msg_len);
    
    return em;
}

std::vector<uint8_t> eme_pkcs1_decode(
    const uint8_t* em,
    size_t em_len
) {
    // Check format: 0x00 || 0x02 || PS || 0x00 || M
    if (em[0] != 0x00 || em[1] != 0x02) {
        throw std::runtime_error("Invalid PKCS#1 padding");
    }
    
    // Find 0x00 separator
    size_t sep = 2;
    while (sep < em_len && em[sep] != 0x00) sep++;
    
    if (sep >= em_len || sep < 10) {
        throw std::runtime_error("Invalid PKCS#1 padding structure");
    }
    
    return std::vector<uint8_t>(em + sep + 1, em + em_len);
}

std::vector<uint8_t> emsa_pkcs1_encode(
    const uint8_t* mHash,
    size_t hlen,
    size_t em_len
) {
    // EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
    // Simplified: PS = 0xFF bytes
    
    if (em_len < hlen + 11) {
        throw std::invalid_argument("Key too short for PKCS#1 signature");
    }
    
    std::vector<uint8_t> em(em_len);
    em[0] = 0x00;
    em[1] = 0x01;
    
    size_t ps_len = em_len - hlen - 3;
    std::memset(em.data() + 2, 0xFF, ps_len);
    em[2 + ps_len] = 0x00;
    std::memcpy(em.data() + 3 + ps_len, mHash, hlen);
    
    return em;
}

bool emsa_pkcs1_verify(
    const uint8_t* mHash,
    size_t hlen,
    const uint8_t* em,
    size_t em_len
) {
    if (em[0] != 0x00 || em[1] != 0x01) return false;
    
    // Find 0x00 separator
    size_t sep = 2;
    while (sep < em_len && em[sep] == 0xFF) sep++;
    
    if (sep >= em_len || em[sep] != 0x00) return false;
    if (em_len - sep - 1 != hlen) return false;
    
    return std::memcmp(em + sep + 1, mHash, hlen) == 0;
}

} // namespace rsa
} // namespace kctsb
