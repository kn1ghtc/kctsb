/**
 * @file ecdsa.cpp
 * @brief ECDSA Implementation - NTL Backend with RFC 6979
 *
 * Complete ECDSA implementation following:
 * - FIPS 186-4 (ECDSA specification)
 * - RFC 6979 (Deterministic Usage of DSA and ECDSA)
 * - SEC 1 v2.0 (Encoding and serialization)
 *
 * Security features:
 * - Constant-time scalar multiplication (Montgomery ladder)
 * - Deterministic k generation prevents nonce reuse attacks
 * - Signature malleability protection (s normalization)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/crypto/ecc/ecdsa.h"
#include "kctsb/crypto/sha256.h"  // For SHA-256 hashing
#include <array>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <random>
#include <algorithm>

using namespace NTL;

namespace kctsb {
namespace ecc {

// ============================================================================
// ECDSASignature Implementation
// ============================================================================

bool ECDSASignature::is_valid(const ZZ& n) const {
    // 0 < r < n and 0 < s < n
    return !IsZero(r) && !IsZero(s) && r < n && s < n;
}

std::vector<uint8_t> ECDSASignature::to_der() const {
    // DER encoding: SEQUENCE { INTEGER r, INTEGER s }
    std::vector<uint8_t> result;

    auto encode_integer = [](const ZZ& val) -> std::vector<uint8_t> {
        std::vector<uint8_t> bytes;
        long num_bytes = NumBytes(val);
        bytes.resize(static_cast<size_t>(num_bytes));
        BytesFromZZ(bytes.data(), val, num_bytes);

        // Add leading zero if high bit is set (to keep positive)
        if (!bytes.empty() && (bytes[0] & 0x80)) {
            bytes.insert(bytes.begin(), 0x00);
        }

        // DER integer encoding
        std::vector<uint8_t> der;
        der.push_back(0x02);  // INTEGER tag

        if (bytes.size() < 128) {
            der.push_back(static_cast<uint8_t>(bytes.size()));
        } else {
            // Long form length
            size_t len_bytes = 0;
            size_t len = bytes.size();
            while (len > 0) {
                len_bytes++;
                len >>= 8;
            }
            der.push_back(static_cast<uint8_t>(0x80 | len_bytes));
            for (size_t i = len_bytes; i > 0; --i) {
                der.push_back(static_cast<uint8_t>(bytes.size() >> (8 * (i - 1))));
            }
        }

        der.insert(der.end(), bytes.begin(), bytes.end());
        return der;
    };

    std::vector<uint8_t> r_der = encode_integer(r);
    std::vector<uint8_t> s_der = encode_integer(s);

    size_t total_len = r_der.size() + s_der.size();

    result.push_back(0x30);  // SEQUENCE tag
    if (total_len < 128) {
        result.push_back(static_cast<uint8_t>(total_len));
    } else {
        result.push_back(0x81);
        result.push_back(static_cast<uint8_t>(total_len));
    }

    result.insert(result.end(), r_der.begin(), r_der.end());
    result.insert(result.end(), s_der.begin(), s_der.end());

    return result;
}

ECDSASignature ECDSASignature::from_der(const uint8_t* data, size_t len) {
    if (len < 8) {
        throw std::invalid_argument("DER signature too short");
    }

    if (data[0] != 0x30) {
        throw std::invalid_argument("Invalid DER SEQUENCE tag");
    }

    size_t pos = 1;

    // Parse sequence length (validates DER structure)
    if (data[pos] < 128) {
        pos++;
    } else if (data[pos] == 0x81) {
        pos += 2;
    } else {
        throw std::invalid_argument("Unsupported DER length encoding");
    }

    auto parse_integer = [&]() -> ZZ {
        if (data[pos++] != 0x02) {
            throw std::invalid_argument("Expected DER INTEGER tag");
        }

        size_t int_len;
        if (data[pos] < 128) {
            int_len = data[pos++];
        } else {
            throw std::invalid_argument("Unsupported integer length");
        }

        // Skip leading zero if present
        size_t start = pos;
        if (int_len > 1 && data[start] == 0x00) {
            start++;
            int_len--;
        }

        ZZ result = ZZFromBytes(data + start, static_cast<long>(int_len));
        pos = start + int_len;

        return result;
    };

    ECDSASignature sig;
    sig.r = parse_integer();
    sig.s = parse_integer();

    return sig;
}

void ECDSASignature::to_fixed(uint8_t* out, size_t field_size) const {
    // NTL BytesFromZZ outputs little-endian, SEC 1 requires big-endian
    std::vector<uint8_t> r_le(field_size), s_le(field_size);
    BytesFromZZ(r_le.data(), r, static_cast<long>(field_size));
    BytesFromZZ(s_le.data(), s, static_cast<long>(field_size));
    
    // Reverse to big-endian for SEC 1 compliance
    for (size_t i = 0; i < field_size; i++) {
        out[i] = r_le[field_size - 1 - i];
        out[field_size + i] = s_le[field_size - 1 - i];
    }
}

ECDSASignature ECDSASignature::from_fixed(const uint8_t* data, size_t field_size) {
    // SEC 1 input is big-endian, convert to little-endian for NTL
    std::vector<uint8_t> r_le(field_size), s_le(field_size);
    for (size_t i = 0; i < field_size; i++) {
        r_le[i] = data[field_size - 1 - i];
        s_le[i] = data[2 * field_size - 1 - i];
    }
    
    ECDSASignature sig;
    sig.r = ZZFromBytes(r_le.data(), static_cast<long>(field_size));
    sig.s = ZZFromBytes(s_le.data(), static_cast<long>(field_size));
    return sig;
}

// ============================================================================
// ECDSAKeyPair Implementation
// ============================================================================

bool ECDSAKeyPair::is_valid(const ECCurve& curve) const {
    // Check private key range: 0 < d < n
    if (IsZero(private_key) || private_key >= curve.get_order()) {
        return false;
    }

    // Check public key is on curve
    if (!curve.is_on_curve(public_key)) {
        return false;
    }

    // Verify Q = d*G
    JacobianPoint expected = curve.scalar_mult_base(private_key);
    AffinePoint exp_aff = curve.to_affine(expected);
    AffinePoint pub_aff = curve.to_affine(public_key);

    return exp_aff == pub_aff;
}

std::vector<uint8_t> ECDSAKeyPair::export_public_key(const ECCurve& curve) const {
    AffinePoint aff = curve.to_affine(public_key);
    size_t field_size = static_cast<size_t>((curve.get_bit_size() + 7) / 8);

    std::vector<uint8_t> result(1 + 2 * field_size);
    int len = curve.point_to_bytes(aff, result.data(), result.size());

    if (len < 0) {
        throw std::runtime_error("Failed to export public key");
    }

    result.resize(static_cast<size_t>(len));
    return result;
}

std::vector<uint8_t> ECDSAKeyPair::export_private_key(size_t field_size) const {
    // NTL BytesFromZZ outputs little-endian, SEC 1 requires big-endian
    std::vector<uint8_t> le_bytes(field_size);
    BytesFromZZ(le_bytes.data(), private_key, static_cast<long>(field_size));
    
    std::vector<uint8_t> result(field_size);
    for (size_t i = 0; i < field_size; i++) {
        result[i] = le_bytes[field_size - 1 - i];
    }
    return result;
}

// ============================================================================
// ECDSA Class Implementation
// ============================================================================

ECDSA::ECDSA(const ECCurve& curve) : curve_(curve) {}

ECDSA::ECDSA(CurveType curve_type) : curve_(curve_type) {}

ECDSA::ECDSA(const std::string& curve_name) : curve_(ECCurve::from_name(curve_name)) {}

size_t ECDSA::get_field_size() const {
    return static_cast<size_t>((curve_.get_bit_size() + 7) / 8);
}

size_t ECDSA::get_signature_size_der() const {
    // Maximum DER size: 2 + 2 + 33 + 2 + 33 = 72 bytes for 256-bit curves
    size_t field_size = get_field_size();
    return 2 + 2 * (2 + field_size + 1);
}

size_t ECDSA::get_signature_size_fixed() const {
    return 2 * get_field_size();
}

// ============================================================================
// Key Generation
// ============================================================================

ECDSAKeyPair ECDSA::generate_keypair() const {
    ZZ d = generate_k_random();
    return keypair_from_private(d);
}

ECDSAKeyPair ECDSA::keypair_from_private(const ZZ& private_key) const {
    if (IsZero(private_key) || private_key >= curve_.get_order()) {
        throw std::invalid_argument("Invalid private key");
    }

    JacobianPoint public_key = curve_.scalar_mult_base(private_key);
    return ECDSAKeyPair(private_key, public_key);
}

JacobianPoint ECDSA::import_public_key(const uint8_t* data, size_t len) const {
    AffinePoint aff = curve_.point_from_bytes(data, len);
    return curve_.to_jacobian(aff);
}

ECDSAKeyPair ECDSA::import_private_key(const uint8_t* data, size_t len) const {
    ZZ d = ZZFromBytes(data, static_cast<long>(len));
    return keypair_from_private(d);
}

// ============================================================================
// Signing
// ============================================================================

ECDSASignature ECDSA::sign(const uint8_t* message_hash, size_t hash_len,
                          const ZZ& private_key) const {
    ZZ e = bits2int(message_hash, hash_len);
    return sign(e, private_key);
}

ECDSASignature ECDSA::sign(const ZZ& e, const ZZ& private_key) const {
    // Generate deterministic k per RFC 6979
    ZZ k = generate_k_rfc6979(e, private_key);

    return sign_with_k(e, private_key, k);
}

ECDSASignature ECDSA::sign_with_k(const ZZ& e, const ZZ& private_key, const ZZ& k) const {
    const ZZ& n = curve_.get_order();

    if (IsZero(k) || k >= n) {
        throw std::invalid_argument("Invalid k value");
    }

    // Step 1: r = (k * G).x mod n
    JacobianPoint R = curve_.scalar_mult_base(k);
    AffinePoint R_aff = curve_.to_affine(R);

    ZZ r = conv<ZZ>(rep(R_aff.x)) % n;

    if (IsZero(r)) {
        throw std::runtime_error("Generated r is zero, retry with different k");
    }

    // Step 2: s = k^(-1) * (e + r*d) mod n
    ZZ k_inv = InvMod(k, n);
    ZZ s = MulMod(k_inv, AddMod(e % n, MulMod(r, private_key, n), n), n);

    if (IsZero(s)) {
        throw std::runtime_error("Generated s is zero, retry with different k");
    }

    // Normalize s to lower half (prevent signature malleability)
    // If s > n/2, replace s with n - s
    ZZ half_n = n / 2;
    if (s > half_n) {
        s = n - s;
    }

    return ECDSASignature(r, s);
}

// ============================================================================
// Verification
// ============================================================================

bool ECDSA::verify(const uint8_t* message_hash, size_t hash_len,
                  const ECDSASignature& signature,
                  const JacobianPoint& public_key) const {
    ZZ e = bits2int(message_hash, hash_len);
    return verify(e, signature, public_key);
}

bool ECDSA::verify(const ZZ& e, const ECDSASignature& signature,
                  const JacobianPoint& public_key) const {
    const ZZ& n = curve_.get_order();

    // Check signature format
    if (!signature.is_valid(n)) {
        return false;
    }

    // Check public key is on curve
    if (!curve_.is_on_curve(public_key)) {
        return false;
    }

    const ZZ& r = signature.r;
    const ZZ& s = signature.s;

    // Step 1: w = s^(-1) mod n
    ZZ w = InvMod(s, n);

    // Step 2: u1 = e*w mod n, u2 = r*w mod n
    ZZ e_mod = e % n;
    if (e_mod < 0) e_mod += n;

    ZZ u1 = MulMod(e_mod, w, n);
    ZZ u2 = MulMod(r, w, n);

    // Step 3: R = u1*G + u2*Q
    JacobianPoint R = curve_.double_scalar_mult(u1, curve_.get_generator(), u2, public_key);

    if (R.is_infinity()) {
        return false;
    }

    // Step 4: v = R.x mod n
    AffinePoint R_aff = curve_.to_affine(R);
    ZZ v = conv<ZZ>(rep(R_aff.x)) % n;

    // Step 5: Verify v == r
    return v == r;
}

// ============================================================================
// Helper Functions
// ============================================================================

ZZ ECDSA::bits2int(const uint8_t* data, size_t len) const {
    ZZ result = ZZFromBytes(data, static_cast<long>(len));

    // If hash is longer than curve order, truncate
    long n_bits = NumBits(curve_.get_order());
    long hash_bits = static_cast<long>(len) * 8;

    if (hash_bits > n_bits) {
        result >>= (hash_bits - n_bits);
    }

    return result;
}

ZZ ECDSA::generate_k_random() const {
    const ZZ& n = curve_.get_order();
    size_t byte_len = static_cast<size_t>(NumBytes(n));

    std::vector<uint8_t> buffer(byte_len);

    // Use system random source
    std::random_device rd;

    while (true) {
        // Generate random bytes
        for (size_t i = 0; i < byte_len; ++i) {
            buffer[i] = static_cast<uint8_t>(rd() & 0xFF);
        }

        ZZ k = ZZFromBytes(buffer.data(), static_cast<long>(byte_len));
        k = k % n;

        // Ensure k is in valid range [1, n-1]
        if (!IsZero(k) && k < n) {
            // Clear buffer
            std::memset(buffer.data(), 0, buffer.size());
            return k;
        }
    }
}

ZZ ECDSA::generate_k_rfc6979(const ZZ& e, const ZZ& private_key) const {
    // RFC 6979 deterministic k generation using HMAC-DRBG
    const ZZ& n = curve_.get_order();
    size_t qlen = static_cast<size_t>(NumBytes(n));
    size_t hlen = 32;  // SHA-256 output length

    // Convert inputs to byte arrays (RFC 6979 uses big-endian)
    // NTL BytesFromZZ outputs little-endian, convert to big-endian
    std::vector<uint8_t> x_le(qlen);
    BytesFromZZ(x_le.data(), private_key, static_cast<long>(qlen));
    std::vector<uint8_t> x(qlen);
    for (size_t i = 0; i < qlen; i++) {
        x[i] = x_le[qlen - 1 - i];
    }

    std::vector<uint8_t> h1_le(qlen);
    ZZ e_mod = e % n;
    if (e_mod < 0) e_mod += n;
    BytesFromZZ(h1_le.data(), e_mod, static_cast<long>(qlen));
    std::vector<uint8_t> h1(qlen);
    for (size_t i = 0; i < qlen; i++) {
        h1[i] = h1_le[qlen - 1 - i];
    }

    // Initialize V = 0x01 0x01 ... 0x01 (hlen bytes)
    std::vector<uint8_t> V(hlen, 0x01);

    // Initialize K = 0x00 0x00 ... 0x00 (hlen bytes)
    std::vector<uint8_t> K(hlen, 0x00);

    // Build message: V || 0x00 || x || h1
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), V.begin(), V.end());
    msg.push_back(0x00);
    msg.insert(msg.end(), x.begin(), x.end());
    msg.insert(msg.end(), h1.begin(), h1.end());

    // K = HMAC_K(V || 0x00 || x || h1)
    hmac_drbg(K.data(), K.size(), msg.data(), msg.size(), K.data(), hlen);

    // V = HMAC_K(V)
    hmac_drbg(K.data(), K.size(), V.data(), V.size(), V.data(), hlen);

    // K = HMAC_K(V || 0x01 || x || h1)
    msg.clear();
    msg.insert(msg.end(), V.begin(), V.end());
    msg.push_back(0x01);
    msg.insert(msg.end(), x.begin(), x.end());
    msg.insert(msg.end(), h1.begin(), h1.end());
    hmac_drbg(K.data(), K.size(), msg.data(), msg.size(), K.data(), hlen);

    // V = HMAC_K(V)
    hmac_drbg(K.data(), K.size(), V.data(), V.size(), V.data(), hlen);

    // Generate k
    while (true) {
        std::vector<uint8_t> T;

        while (T.size() < qlen) {
            hmac_drbg(K.data(), K.size(), V.data(), V.size(), V.data(), hlen);
            T.insert(T.end(), V.begin(), V.end());
        }

        ZZ k = ZZFromBytes(T.data(), static_cast<long>(qlen));

        // Check if k is valid: 1 <= k < n
        if (!IsZero(k) && k < n) {
            // Clear sensitive data
            std::memset(x.data(), 0, x.size());
            std::memset(K.data(), 0, K.size());
            return k;
        }

        // Update K and V for retry
        msg.clear();
        msg.insert(msg.end(), V.begin(), V.end());
        msg.push_back(0x00);
        hmac_drbg(K.data(), K.size(), msg.data(), msg.size(), K.data(), hlen);
        hmac_drbg(K.data(), K.size(), V.data(), V.size(), V.data(), hlen);
    }
}

void ECDSA::hmac_drbg(const uint8_t* key, size_t key_len,
                      const uint8_t* data, size_t data_len,
                      uint8_t* output, size_t output_len) const {
    // RFC 2104 HMAC-SHA256 implementation
    const size_t block_size = 64;
    const size_t hash_size = 32;

    std::array<uint8_t, block_size> k_block{};

    if (key_len > block_size) {
        // Hash long keys to block size
        kctsb_sha256(key, key_len, k_block.data());
    } else {
        std::memcpy(k_block.data(), key, key_len);
    }

    std::array<uint8_t, block_size> ipad{};
    std::array<uint8_t, block_size> opad{};
    for (size_t i = 0; i < block_size; ++i) {
        ipad[i] = static_cast<uint8_t>(k_block[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(k_block[i] ^ 0x5c);
    }

    auto hmac_once = [&](const uint8_t* msg, size_t msg_len, uint8_t out[hash_size]) {
        kctsb_sha256_ctx_t ctx;

        kctsb_sha256_init(&ctx);
        kctsb_sha256_update(&ctx, ipad.data(), ipad.size());
        if (msg_len > 0) {
            kctsb_sha256_update(&ctx, msg, msg_len);
        }
        uint8_t inner[hash_size];
        kctsb_sha256_final(&ctx, inner);

        kctsb_sha256_init(&ctx);
        kctsb_sha256_update(&ctx, opad.data(), opad.size());
        kctsb_sha256_update(&ctx, inner, sizeof(inner));
        kctsb_sha256_final(&ctx, out);
    };

    size_t generated = 0;
    uint32_t counter = 0;
    while (generated < output_len) {
        std::vector<uint8_t> msg;
        msg.reserve(data_len + sizeof(counter));
        msg.insert(msg.end(), data, data + data_len);
        uint32_t be_counter = ((counter & 0xFF000000u) >> 24) |
                      ((counter & 0x00FF0000u) >> 8)  |
                      ((counter & 0x0000FF00u) << 8)  |
                      ((counter & 0x000000FFu) << 24);
        msg.insert(msg.end(), reinterpret_cast<uint8_t*>(&be_counter),
               reinterpret_cast<uint8_t*>(&be_counter) + sizeof(be_counter));

        uint8_t block[hash_size];
        hmac_once(msg.data(), msg.size(), block);

        size_t to_copy = std::min(hash_size, output_len - generated);
        std::memcpy(output + generated, block, to_copy);
        generated += to_copy;
        ++counter;
    }
}

// ============================================================================
// High-Level API Functions
// ============================================================================

std::vector<uint8_t> ecdsa_sign(const ECCurve& curve,
                                const uint8_t* message_hash, size_t hash_len,
                                const uint8_t* private_key, size_t key_len) {
    ECDSA ecdsa(curve);

    ZZ d = ZZFromBytes(private_key, static_cast<long>(key_len));
    ECDSASignature sig = ecdsa.sign(message_hash, hash_len, d);

    return sig.to_der();
}

bool ecdsa_verify(const ECCurve& curve,
                  const uint8_t* message_hash, size_t hash_len,
                  const uint8_t* signature, size_t sig_len,
                  const uint8_t* public_key, size_t pub_len) {
    ECDSA ecdsa(curve);

    ECDSASignature sig = ECDSASignature::from_der(signature, sig_len);
    JacobianPoint pub = ecdsa.import_public_key(public_key, pub_len);

    return ecdsa.verify(message_hash, hash_len, sig, pub);
}

} // namespace ecc
} // namespace kctsb
