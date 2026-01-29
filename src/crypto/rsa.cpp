/**
 * @file rsa.cpp
 * @brief RSA-PSS/RSAES-OAEP implementation (SHA-256 only, 3072/4096 bits)
 *
 * Single-file RSA implementation optimized for HTTPS usage:
 * - RSASSA-PSS (SHA-256) signature/verification
 * - RSAES-OAEP (SHA-256) encryption/decryption
 * - Key sizes: 3072/4096 only
 * - Montgomery multiplication for fast modular exponentiation
 * - Optional CRT acceleration if p/q provided
 *
 * Design goals:
 * - Self-contained (no OpenSSL/GMP dependencies)
 * - C ABI for stable integration
 * - Constant-time primitives where applicable (hash compare)
 *
 * Performance Optimizations (v5.1.0):
 * - Montgomery modular multiplication (avoids expensive division)
 * - Sliding window exponentiation with configurable window size
 * - CRT-based private key operations (~4x speedup)
 *
 * References:
 * - RFC 8017 (PKCS#1 v2.2)
 * - NIST CAVP RSA PSS vectors (FIPS 186-3)
 * - "Handbook of Applied Cryptography", Chapter 14 - Montgomery Multiplication
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/core/common.h"
#include "kctsb/core/security.h"
#include "kctsb/core/zz.h"
#include "kctsb/kctsb_api.h"
#include "kctsb/crypto/sha256.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace kctsb::crypto::rsa {

using kctsb::GCD;
using kctsb::InvMod;
using kctsb::IsOdd;
using kctsb::NumBits;
using kctsb::bit;
using kctsb::ZZ;

constexpr size_t kHashLen = KCTSB_SHA256_DIGEST_SIZE;
constexpr size_t kPssSaltLen = KCTSB_SHA256_DIGEST_SIZE;

// ============================================================================
// High-Performance Montgomery Multiplication (Limb-Level)
// ============================================================================

using limb_t = uint64_t;
using dlimb_t = unsigned __int128;  // 128-bit for intermediate products
constexpr size_t LIMB_BITS = 64;

/**
 * @brief Compute n0' = -n^(-1) mod 2^64 using Newton iteration
 * 
 * For CIOS Montgomery, we need n0' such that n * n0' ≡ -1 (mod 2^64)
 * This is equivalent to n0' = -n^(-1) mod 2^64
 * 
 * Newton iteration for modular inverse:
 *   If x * n ≡ 1 (mod 2^k), then x' = x * (2 - n*x) satisfies x' * n ≡ 1 (mod 2^(2k))
 */
static limb_t compute_n0_prime(limb_t n0) {
    // n0 must be odd for inverse to exist
    // Initial: x * n ≡ 1 (mod 2), for odd n, x = 1 works
    limb_t x = 1;
    
    // Each iteration doubles the precision: 1 -> 2 -> 4 -> 8 -> 16 -> 32 -> 64 bits
    for (int i = 0; i < 6; ++i) {
        x = x * (2 - n0 * x);  // x = x * (2 - n0 * x) mod 2^64
    }
    
    // x is now n^(-1) mod 2^64, we need -n^(-1) = -x mod 2^64
    return static_cast<limb_t>(0) - x;
}

/**
 * @brief High-performance Montgomery context using limb arrays
 */
class FastMontContext {
public:
    std::vector<limb_t> n;      ///< Modulus limbs
    std::vector<limb_t> r2;     ///< R^2 mod n (for to_mont conversion)
    limb_t n0_prime;            ///< -n^(-1) mod 2^64
    size_t num_limbs;
    
    explicit FastMontContext(const ZZ& modulus) {
        num_limbs = modulus.num_limbs();
        n.resize(num_limbs);
        for (size_t i = 0; i < num_limbs; ++i) {
            n[i] = modulus.limb(i);
        }
        
        // Compute n0' = -n^(-1) mod 2^64
        n0_prime = compute_n0_prime(n[0]);
        
        // Compute R^2 mod n using repeated doubling
        // R = 2^(num_limbs * 64), so R^2 = 2^(2 * num_limbs * 64)
        r2 = compute_r2_mod_n();
    }
    
    /**
     * @brief Convert to Montgomery form: a -> a*R mod n
     */
    std::vector<limb_t> to_mont(const std::vector<limb_t>& a) const {
        return mont_mul(a, r2);
    }
    
    /**
     * @brief Convert from Montgomery form: a*R -> a mod n
     */
    std::vector<limb_t> from_mont(const std::vector<limb_t>& a_mont) const {
        std::vector<limb_t> one(num_limbs, 0);
        one[0] = 1;
        return mont_mul(a_mont, one);
    }
    
    /**
     * @brief Montgomery multiplication: (a*R * b*R) * R^(-1) = a*b*R mod n
     * 
     * Uses CIOS (Coarsely Integrated Operand Scanning) method.
     * Reference: Analyzing and Comparing Montgomery Multiplication Algorithms
     *            by Koç, Acar, and Kaliski (IEEE Micro, 1996)
     */
    std::vector<limb_t> mont_mul(const std::vector<limb_t>& a, 
                                  const std::vector<limb_t>& b) const {
        std::vector<limb_t> t(num_limbs + 2, 0);
        
        for (size_t i = 0; i < num_limbs; ++i) {
            // Step 1: (C, S) = t[0] + a[i]*b[0]
            dlimb_t uv = static_cast<dlimb_t>(a[i]) * b[0] + t[0];
            limb_t C = static_cast<limb_t>(uv >> LIMB_BITS);
            t[0] = static_cast<limb_t>(uv);
            
            // for j = 1 to n-1: (C, t[j]) = t[j] + a[i]*b[j] + C
            for (size_t j = 1; j < num_limbs; ++j) {
                uv = static_cast<dlimb_t>(a[i]) * b[j] + t[j] + C;
                t[j] = static_cast<limb_t>(uv);
                C = static_cast<limb_t>(uv >> LIMB_BITS);
            }
            // (C, t[n]) = t[n] + C
            uv = static_cast<dlimb_t>(t[num_limbs]) + C;
            t[num_limbs] = static_cast<limb_t>(uv);
            limb_t C2 = static_cast<limb_t>(uv >> LIMB_BITS);
            // t[n+1] = t[n+1] + C2
            t[num_limbs + 1] += C2;
            
            // Step 2: m = t[0] * n0' mod 2^64
            limb_t m = t[0] * n0_prime;
            
            // Step 3: (C, _) = t[0] + m*n[0]  (low 64 bits are discarded)
            uv = static_cast<dlimb_t>(m) * n[0] + t[0];
            C = static_cast<limb_t>(uv >> LIMB_BITS);
            
            // for j = 1 to n-1: (C, t[j-1]) = t[j] + m*n[j] + C
            for (size_t j = 1; j < num_limbs; ++j) {
                uv = static_cast<dlimb_t>(m) * n[j] + t[j] + C;
                t[j - 1] = static_cast<limb_t>(uv);
                C = static_cast<limb_t>(uv >> LIMB_BITS);
            }
            // (C, t[n-1]) = t[n] + C
            uv = static_cast<dlimb_t>(t[num_limbs]) + C;
            t[num_limbs - 1] = static_cast<limb_t>(uv);
            C = static_cast<limb_t>(uv >> LIMB_BITS);
            // t[n] = t[n+1] + C
            t[num_limbs] = t[num_limbs + 1] + C;
            t[num_limbs + 1] = 0;
        }
        
        // Conditional subtraction: if t >= n, compute t - n
        std::vector<limb_t> result(num_limbs);
        bool need_sub = (t[num_limbs] != 0) || !less_than(t, n);
        
        if (need_sub) {
            limb_t borrow = 0;
            for (size_t i = 0; i < num_limbs; ++i) {
                limb_t ti = t[i];
                limb_t ni = n[i];
                // Use 128-bit to handle borrow correctly
                dlimb_t diff = static_cast<dlimb_t>(ti) - ni - borrow;
                result[i] = static_cast<limb_t>(diff);
                // If diff wrapped (high bits set), we need to borrow
                borrow = (diff >> LIMB_BITS) ? 1 : 0;
            }
        } else {
            for (size_t i = 0; i < num_limbs; ++i) {
                result[i] = t[i];
            }
        }
        
        return result;
    }
    
    /**
     * @brief Montgomery squaring (uses same algorithm as mul for now)
     */
    std::vector<limb_t> mont_sqr(const std::vector<limb_t>& a) const {
        return mont_mul(a, a);
    }
    
private:
    /**
     * @brief Check if a < n (limb arrays)
     */
    bool less_than(const std::vector<limb_t>& a, const std::vector<limb_t>& b) const {
        for (size_t i = num_limbs; i > 0; --i) {
            limb_t ai = (i - 1 < a.size()) ? a[i - 1] : 0;
            limb_t bi = (i - 1 < b.size()) ? b[i - 1] : 0;
            if (ai < bi) return true;
            if (ai > bi) return false;
        }
        return false;  // Equal
    }
    
    /**
     * @brief Compute R^2 mod n using repeated left shifts
     */
    std::vector<limb_t> compute_r2_mod_n() const {
        // Start with 1
        std::vector<limb_t> result(num_limbs, 0);
        result[0] = 1;
        
        // Compute 2^(2 * num_limbs * 64) mod n by repeated doubling
        size_t total_shifts = 2 * num_limbs * LIMB_BITS;
        for (size_t i = 0; i < total_shifts; ++i) {
            // result = (result * 2) mod n
            limb_t carry = 0;
            for (size_t j = 0; j < num_limbs; ++j) {
                limb_t new_val = (result[j] << 1) | carry;
                carry = result[j] >> (LIMB_BITS - 1);
                result[j] = new_val;
            }
            
            // If result >= n, subtract n
            if (carry || !less_than(result, n)) {
                limb_t borrow = 0;
                for (size_t j = 0; j < num_limbs; ++j) {
                    dlimb_t diff = static_cast<dlimb_t>(result[j]) - n[j] - borrow;
                    result[j] = static_cast<limb_t>(diff);
                    borrow = (diff >> LIMB_BITS) ? 1 : 0;
                }
            }
        }
        
        return result;
    }
};

/**
 * @brief Convert ZZ to limb array
 */
static std::vector<limb_t> zz_to_limbs(const ZZ& z, size_t num_limbs) {
    std::vector<limb_t> result(num_limbs, 0);
    size_t n = std::min(z.num_limbs(), num_limbs);
    for (size_t i = 0; i < n; ++i) {
        result[i] = z.limb(i);
    }
    return result;
}

/**
 * @brief Convert limb array to ZZ
 */
static ZZ limbs_to_zz(const std::vector<limb_t>& limbs) {
    ZZ result(0);
    for (size_t i = limbs.size(); i > 0; --i) {
        result <<= static_cast<long>(LIMB_BITS);
        result += ZZ(limbs[i - 1]);
    }
    return result;
}

/**
 * @brief Fast Montgomery modular exponentiation: base^exp mod n
 */
static ZZ fast_modexp(const ZZ& base, const ZZ& exp, const ZZ& mod) {
    if (mod <= ZZ(0) || !IsOdd(mod)) {
        throw std::domain_error("modexp: modulus must be positive and odd");
    }
    if (exp.is_zero()) {
        return ZZ(1);
    }
    
    FastMontContext ctx(mod);
    
    // Convert base to Montgomery form
    ZZ base_mod = base % mod;
    if (base_mod.is_negative()) base_mod += mod;
    std::vector<limb_t> base_limbs = zz_to_limbs(base_mod, ctx.num_limbs);
    std::vector<limb_t> base_mont = ctx.to_mont(base_limbs);
    
    // Sliding window exponentiation
    long exp_bits = NumBits(exp);
    int window_bits = 5;
    if (exp_bits >= 2048) window_bits = 5;
    if (exp_bits >= 4096) window_bits = 6;
    
    int table_size = 1 << window_bits;
    std::vector<std::vector<limb_t>> table(static_cast<size_t>(table_size));
    
    // Precompute: table[i] = base^i in Montgomery form
    table[0].resize(ctx.num_limbs, 0);
    table[0][0] = 1;
    table[0] = ctx.to_mont(table[0]);  // 1 in Montgomery form = R mod n
    table[1] = base_mont;
    
    for (int i = 2; i < table_size; ++i) {
        table[static_cast<size_t>(i)] = ctx.mont_mul(table[static_cast<size_t>(i - 1)], base_mont);
    }
    
    // Exponentiation using sliding window
    std::vector<limb_t> result = table[0];  // Start with 1 in Montgomery form
    
    long i = exp_bits - 1;
    while (i >= 0) {
        if (bit(exp, i) == 0) {
            result = ctx.mont_sqr(result);
            --i;
            continue;
        }
        
        // Find window
        long j = std::max<long>(0, i - window_bits + 1);
        while (j <= i && bit(exp, j) == 0) {
            ++j;
        }
        
        long window_len = i - j + 1;
        long window_val = 0;
        for (long k = i; k >= j; --k) {
            window_val = (window_val << 1) | bit(exp, k);
        }
        
        // Square window_len times
        for (long k = 0; k < window_len; ++k) {
            result = ctx.mont_sqr(result);
        }
        
        // Multiply by precomputed value
        result = ctx.mont_mul(result, table[static_cast<size_t>(window_val)]);
        
        i = j - 1;
    }
    
    // Convert back from Montgomery form
    std::vector<limb_t> final_result = ctx.from_mont(result);
    return limbs_to_zz(final_result);
}

/**
 * @brief Optimized modexp for e = 65537
 */
static ZZ fast_modexp_65537(const ZZ& base, const ZZ& mod) {
    if (mod <= ZZ(0) || !IsOdd(mod)) {
        throw std::domain_error("modexp: modulus must be positive and odd");
    }
    
    FastMontContext ctx(mod);
    
    ZZ base_mod = base % mod;
    if (base_mod.is_negative()) base_mod += mod;
    std::vector<limb_t> base_limbs = zz_to_limbs(base_mod, ctx.num_limbs);
    std::vector<limb_t> acc = ctx.to_mont(base_limbs);
    
    // 65537 = 2^16 + 1
    // acc = base^(2^16) in Montgomery form
    for (int i = 0; i < 16; ++i) {
        acc = ctx.mont_sqr(acc);
    }
    
    // acc = acc * base = base^(2^16 + 1)
    std::vector<limb_t> base_mont = ctx.to_mont(base_limbs);
    acc = ctx.mont_mul(acc, base_mont);
    
    // Convert back
    std::vector<limb_t> final_result = ctx.from_mont(acc);
    return limbs_to_zz(final_result);
}

// ============================================================================
// Utility Functions
// ============================================================================

static bool is_supported_modulus_bytes(size_t len) {
	return len == KCTSB_RSA_3072_BYTES || len == KCTSB_RSA_4096_BYTES;
}

static std::vector<uint8_t> sha256(const uint8_t* data, size_t len) {
	std::vector<uint8_t> digest(kHashLen);
	kctsb_sha256(data, len, digest.data());
	return digest;
}

static kctsb_error_t random_bytes(uint8_t* buf, size_t len) {
	if (kctsb_random_bytes(buf, len) != KCTSB_SUCCESS) {
		return KCTSB_ERROR_RANDOM_FAILED;
	}
	return KCTSB_SUCCESS;
}

static std::vector<uint8_t> trim_leading_zeros(const uint8_t* data, size_t len) {
	size_t offset = 0;
	while (offset < len && data[offset] == 0) {
		++offset;
	}
	if (offset == len) {
		return std::vector<uint8_t>(1, 0);
	}
	return std::vector<uint8_t>(data + offset, data + len);
}

static ZZ os2ip(const uint8_t* data, size_t len) {
	return ZZ::from_bytes(data, len);
}

static kctsb_error_t i2osp(const ZZ& value, uint8_t* out, size_t len) {
	if (value.num_bytes() > len) {
		return KCTSB_ERROR_BUFFER_TOO_SMALL;
	}
	value.to_bytes(out, len);
	return KCTSB_SUCCESS;
}

static void mgf1_sha256(const uint8_t* seed, size_t seed_len, uint8_t* mask, size_t mask_len) {
	uint32_t counter = 0;
	size_t generated = 0;
	std::array<uint8_t, 4> cbuf{};
	std::array<uint8_t, kHashLen> digest{};

	while (generated < mask_len) {
		cbuf[0] = static_cast<uint8_t>((counter >> 24) & 0xFF);
		cbuf[1] = static_cast<uint8_t>((counter >> 16) & 0xFF);
		cbuf[2] = static_cast<uint8_t>((counter >> 8) & 0xFF);
		cbuf[3] = static_cast<uint8_t>(counter & 0xFF);

		kctsb_sha256_ctx_t ctx;
		kctsb_sha256_init(&ctx);
		kctsb_sha256_update(&ctx, seed, seed_len);
		kctsb_sha256_update(&ctx, cbuf.data(), cbuf.size());
		kctsb_sha256_final(&ctx, digest.data());

		size_t to_copy = std::min(mask_len - generated, digest.size());
		std::memcpy(mask + generated, digest.data(), to_copy);
		generated += to_copy;
		++counter;
	}
}

// ============================================================================
// Key Structures
// ============================================================================

struct PublicKey {
	ZZ n;
	ZZ e;
	size_t n_len = 0;
	size_t bits = 0;
};

struct PrivateKey {
	ZZ n;
	ZZ d;
	ZZ p;
	ZZ q;
	ZZ dp;
	ZZ dq;
	ZZ qinv;
	bool has_crt = false;
	size_t n_len = 0;
	size_t bits = 0;
};

static kctsb_error_t load_public_key(const kctsb_rsa_public_key_t* key, PublicKey& out) {
	if (!key || key->n_len == 0 || key->e_len == 0) {
		return KCTSB_ERROR_INVALID_KEY;
	}
	if (!is_supported_modulus_bytes(key->n_len)) {
		return KCTSB_ERROR_INVALID_KEY;
	}

	auto n_bytes = trim_leading_zeros(key->n, key->n_len);
	auto e_bytes = trim_leading_zeros(key->e, key->e_len);
	out.n = os2ip(n_bytes.data(), n_bytes.size());
	out.e = os2ip(e_bytes.data(), e_bytes.size());
	out.n_len = key->n_len;
	out.bits = key->n_len * 8;
	return KCTSB_SUCCESS;
}

static kctsb_error_t load_private_key(const kctsb_rsa_private_key_t* key, PrivateKey& out) {
	if (!key || key->n_len == 0 || key->d_len == 0) {
		return KCTSB_ERROR_INVALID_KEY;
	}
	if (!is_supported_modulus_bytes(key->n_len)) {
		return KCTSB_ERROR_INVALID_KEY;
	}

	auto n_bytes = trim_leading_zeros(key->n, key->n_len);
	auto d_bytes = trim_leading_zeros(key->d, key->d_len);
	out.n = os2ip(n_bytes.data(), n_bytes.size());
	out.d = os2ip(d_bytes.data(), d_bytes.size());
	out.n_len = key->n_len;
	out.bits = key->n_len * 8;
	out.has_crt = key->has_crt != 0;

	if (out.has_crt && key->p_len > 0 && key->q_len > 0 &&
		key->dp_len > 0 && key->dq_len > 0 && key->qinv_len > 0) {
		auto p_bytes = trim_leading_zeros(key->p, key->p_len);
		auto q_bytes = trim_leading_zeros(key->q, key->q_len);
		auto dp_bytes = trim_leading_zeros(key->dp, key->dp_len);
		auto dq_bytes = trim_leading_zeros(key->dq, key->dq_len);
		auto qinv_bytes = trim_leading_zeros(key->qinv, key->qinv_len);
		out.p = os2ip(p_bytes.data(), p_bytes.size());
		out.q = os2ip(q_bytes.data(), q_bytes.size());
		out.dp = os2ip(dp_bytes.data(), dp_bytes.size());
		out.dq = os2ip(dq_bytes.data(), dq_bytes.size());
		out.qinv = os2ip(qinv_bytes.data(), qinv_bytes.size());
		out.has_crt = true;
	} else {
		out.has_crt = false;
	}
	return KCTSB_SUCCESS;
}

static ZZ rsa_public_op(const ZZ& m, const PublicKey& key) {
	if (m < ZZ(0) || m >= key.n) {
		throw std::domain_error("RSAEP message representative out of range");
	}
	// Use high-performance limb-level Montgomery exponentiation
	if (key.e == ZZ(65537)) {
		return fast_modexp_65537(m, key.n);
	}
	return fast_modexp(m, key.e, key.n);
}

static ZZ rsa_private_op(const ZZ& c, const PrivateKey& key) {
	if (c < ZZ(0) || c >= key.n) {
		throw std::domain_error("RSADP cipher representative out of range");
	}

	if (!key.has_crt) {
		return fast_modexp(c, key.d, key.n);
	}
	// CRT acceleration: compute m1 = c^dp mod p, m2 = c^dq mod q
	ZZ m1 = fast_modexp(c, key.dp, key.p);
	ZZ m2 = fast_modexp(c, key.dq, key.q);
	ZZ h = (key.qinv * (m1 - m2)) % key.p;
	if (h.is_negative()) {
		h += key.p;
	}
	return m2 + key.q * h;
}

static kctsb_error_t oaep_encode(
	const uint8_t* message,
	size_t message_len,
	const uint8_t* label,
	size_t label_len,
	size_t k,
	uint8_t* seed_opt,
	uint8_t* out_em)
{
	if (k < 2 * kHashLen + 2) {
		return KCTSB_ERROR_INVALID_PARAM;
	}
	if (message_len > k - 2 * kHashLen - 2) {
		return KCTSB_ERROR_INVALID_PARAM;
	}

	std::vector<uint8_t> lhash = sha256(label, label_len);
	size_t ps_len = k - message_len - 2 * kHashLen - 2;

	std::vector<uint8_t> db(k - kHashLen - 1, 0);
	std::memcpy(db.data(), lhash.data(), kHashLen);
	db[kHashLen + ps_len] = 0x01;
	std::memcpy(db.data() + kHashLen + ps_len + 1, message, message_len);

	std::array<uint8_t, kHashLen> seed{};
	if (seed_opt) {
		std::memcpy(seed.data(), seed_opt, kHashLen);
	} else {
		kctsb_error_t rng = random_bytes(seed.data(), kHashLen);
		if (rng != KCTSB_SUCCESS) {
			return rng;
		}
	}

	std::vector<uint8_t> db_mask(db.size());
	mgf1_sha256(seed.data(), seed.size(), db_mask.data(), db_mask.size());
	for (size_t i = 0; i < db.size(); ++i) {
		db[i] ^= db_mask[i];
	}

	std::vector<uint8_t> seed_mask(kHashLen);
	mgf1_sha256(db.data(), db.size(), seed_mask.data(), seed_mask.size());
	for (size_t i = 0; i < kHashLen; ++i) {
		seed[i] ^= seed_mask[i];
	}

	out_em[0] = 0x00;
	std::memcpy(out_em + 1, seed.data(), kHashLen);
	std::memcpy(out_em + 1 + kHashLen, db.data(), db.size());

	kctsb_secure_zero(db_mask.data(), db_mask.size());
	kctsb_secure_zero(seed_mask.data(), seed_mask.size());
	return KCTSB_SUCCESS;
}

static kctsb_error_t oaep_decode(
	const uint8_t* em,
	size_t em_len,
	const uint8_t* label,
	size_t label_len,
	std::vector<uint8_t>& out_msg)
{
	if (em_len < 2 * kHashLen + 2) {
		return KCTSB_ERROR_DECRYPTION_FAILED;
	}

	if (em[0] != 0x00) {
		return KCTSB_ERROR_DECRYPTION_FAILED;
	}

	const uint8_t* masked_seed = em + 1;
	const uint8_t* masked_db = em + 1 + kHashLen;
	size_t db_len = em_len - kHashLen - 1;

	std::vector<uint8_t> seed(kHashLen);
	std::vector<uint8_t> db(db_len);
	std::memcpy(seed.data(), masked_seed, kHashLen);
	std::memcpy(db.data(), masked_db, db_len);

	std::vector<uint8_t> seed_mask(kHashLen);
	mgf1_sha256(masked_db, db_len, seed_mask.data(), seed_mask.size());
	for (size_t i = 0; i < kHashLen; ++i) {
		seed[i] ^= seed_mask[i];
	}

	std::vector<uint8_t> db_mask(db_len);
	mgf1_sha256(seed.data(), seed.size(), db_mask.data(), db_mask.size());
	for (size_t i = 0; i < db_len; ++i) {
		db[i] ^= db_mask[i];
	}

	std::vector<uint8_t> lhash = sha256(label, label_len);
	if (kctsb_secure_compare(db.data(), lhash.data(), kHashLen) != 0) {
		return KCTSB_ERROR_DECRYPTION_FAILED;
	}

	size_t idx = kHashLen;
	while (idx < db_len && db[idx] == 0x00) {
		++idx;
	}
	if (idx == db_len || db[idx] != 0x01) {
		return KCTSB_ERROR_DECRYPTION_FAILED;
	}
	++idx;
	out_msg.assign(db.begin() + static_cast<long>(idx), db.end());
	return KCTSB_SUCCESS;
}

static kctsb_error_t pss_encode(
	const uint8_t* mhash,
	size_t mhash_len,
	const uint8_t* salt,
	size_t salt_len,
	size_t em_bits,
	uint8_t* em_out)
{
	if (mhash_len != kHashLen || salt_len != kPssSaltLen) {
		return KCTSB_ERROR_INVALID_PARAM;
	}

	size_t em_len = (em_bits + 7) / 8;
	if (em_len < kHashLen + salt_len + 2) {
		return KCTSB_ERROR_INVALID_PARAM;
	}

	std::vector<uint8_t> mprime(8 + kHashLen + salt_len, 0);
	std::memcpy(mprime.data() + 8, mhash, kHashLen);
	std::memcpy(mprime.data() + 8 + kHashLen, salt, salt_len);

	std::vector<uint8_t> h = sha256(mprime.data(), mprime.size());

	size_t ps_len = em_len - salt_len - kHashLen - 2;
	std::vector<uint8_t> db(ps_len + 1 + salt_len, 0);
	db[ps_len] = 0x01;
	std::memcpy(db.data() + ps_len + 1, salt, salt_len);

	std::vector<uint8_t> db_mask(db.size());
	mgf1_sha256(h.data(), h.size(), db_mask.data(), db_mask.size());
	for (size_t i = 0; i < db.size(); ++i) {
		db[i] ^= db_mask[i];
	}

	size_t unused_bits = (8 * em_len) - em_bits;
	if (unused_bits > 0) {
		db[0] &= static_cast<uint8_t>(0xFF >> unused_bits);
	}

	std::memcpy(em_out, db.data(), db.size());
	std::memcpy(em_out + db.size(), h.data(), h.size());
	em_out[em_len - 1] = 0xBC;
	return KCTSB_SUCCESS;
}

static kctsb_error_t pss_verify(
	const uint8_t* mhash,
	size_t mhash_len,
	const uint8_t* em,
	size_t em_len,
	size_t em_bits)
{
	if (mhash_len != kHashLen) {
		return KCTSB_ERROR_VERIFICATION_FAILED;
	}
	if (em_len < kHashLen + kPssSaltLen + 2) {
		return KCTSB_ERROR_VERIFICATION_FAILED;
	}
	if (em[em_len - 1] != 0xBC) {
		return KCTSB_ERROR_VERIFICATION_FAILED;
	}

	size_t db_len = em_len - kHashLen - 1;
	std::vector<uint8_t> masked_db(db_len);
	std::vector<uint8_t> h(kHashLen);
	std::memcpy(masked_db.data(), em, db_len);
	std::memcpy(h.data(), em + db_len, kHashLen);

	size_t unused_bits = (8 * em_len) - em_bits;
	if (unused_bits > 0) {
		uint8_t mask = static_cast<uint8_t>(0xFF >> unused_bits);
		if ((masked_db[0] & ~mask) != 0) {
			return KCTSB_ERROR_VERIFICATION_FAILED;
		}
	}

	std::vector<uint8_t> db_mask(db_len);
	mgf1_sha256(h.data(), h.size(), db_mask.data(), db_mask.size());
	for (size_t i = 0; i < db_len; ++i) {
		masked_db[i] ^= db_mask[i];
	}

	if (unused_bits > 0) {
		masked_db[0] &= static_cast<uint8_t>(0xFF >> unused_bits);
	}

	size_t ps_end = db_len - kPssSaltLen - 1;
	for (size_t i = 0; i < ps_end; ++i) {
		if (masked_db[i] != 0x00) {
			return KCTSB_ERROR_VERIFICATION_FAILED;
		}
	}
	if (masked_db[ps_end] != 0x01) {
		return KCTSB_ERROR_VERIFICATION_FAILED;
	}

	const uint8_t* salt = masked_db.data() + ps_end + 1;
	std::vector<uint8_t> mprime(8 + kHashLen + kPssSaltLen, 0);
	std::memcpy(mprime.data() + 8, mhash, kHashLen);
	std::memcpy(mprime.data() + 8 + kHashLen, salt, kPssSaltLen);
	std::vector<uint8_t> h_prime = sha256(mprime.data(), mprime.size());
	if (kctsb_secure_compare(h.data(), h_prime.data(), kHashLen) != 0) {
		return KCTSB_ERROR_VERIFICATION_FAILED;
	}

	return KCTSB_SUCCESS;
}

static ZZ random_zz_bits(size_t bits) {
	size_t bytes = (bits + 7) / 8;
	std::vector<uint8_t> buf(bytes, 0);
	if (random_bytes(buf.data(), buf.size()) != KCTSB_SUCCESS) {
		throw std::runtime_error("CSPRNG failed");
	}
	buf[0] |= static_cast<uint8_t>(0x80 >> ((bytes * 8 - bits) & 7));
	buf[bytes - 1] |= 0x01;
	return ZZ::from_bytes(buf.data(), buf.size());
}

static bool is_probable_prime(const ZZ& n, int rounds) {
	if (n <= ZZ(1)) {
		return false;
	}
	if (n == ZZ(2) || n == ZZ(3)) {
		return true;
	}
	if (!IsOdd(n)) {
		return false;
	}

	static const uint32_t small_primes[] = {
		3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
		37, 41, 43, 47, 53, 59, 61, 67, 71, 73
	};
	for (uint32_t p : small_primes) {
		ZZ prime_val(static_cast<uint64_t>(p));
		if ((n % prime_val) == ZZ(0)) {
			return n == prime_val;
		}
	}

	ZZ d = n - ZZ(1);
	long r = 0;
	while (!IsOdd(d)) {
		d >>= 1;
		++r;
	}

	size_t n_bytes = (NumBits(n) + 7) / 8;
	std::vector<uint8_t> rand_buf(n_bytes);

	for (int i = 0; i < rounds; ++i) {
		random_bytes(rand_buf.data(), rand_buf.size());
		ZZ a = ZZ::from_bytes(rand_buf.data(), rand_buf.size());
		a = (a % (n - ZZ(3))) + ZZ(2);

		ZZ x = fast_modexp(a, d, n);
		if (x == ZZ(1) || x == n - ZZ(1)) {
			continue;
		}

		bool witness = true;
		for (long j = 1; j < r; ++j) {
			x = fast_modexp(x, ZZ(2), n);
			if (x == n - ZZ(1)) {
				witness = false;
				break;
			}
		}
		if (witness) {
			return false;
		}
	}
	return true;
}

static ZZ generate_prime_bits(size_t bits) {
	while (true) {
		ZZ candidate = random_zz_bits(bits);
		if (is_probable_prime(candidate, 40)) {
			return candidate;
		}
	}
}

} // namespace kctsb::crypto::rsa

extern "C" {

KCTSB_API kctsb_error_t kctsb_rsa_public_key_init(
	kctsb_rsa_public_key_t* key,
	const uint8_t* n,
	size_t n_len,
	const uint8_t* e,
	size_t e_len)
{
	if (!key || !n || !e || n_len == 0 || e_len == 0) {
		return KCTSB_ERROR_INVALID_PARAM;
	}
	if (!kctsb::crypto::rsa::is_supported_modulus_bytes(n_len)) {
		return KCTSB_ERROR_INVALID_KEY;
	}
	if (n_len > KCTSB_RSA_MAX_MODULUS_BYTES || e_len > KCTSB_RSA_MAX_MODULUS_BYTES) {
		return KCTSB_ERROR_INVALID_PARAM;
	}

	key->bits = static_cast<uint32_t>(n_len * 8);
	key->n_len = static_cast<uint32_t>(n_len);
	key->e_len = static_cast<uint32_t>(e_len);
	std::memset(key->n, 0, sizeof(key->n));
	std::memset(key->e, 0, sizeof(key->e));
	std::memcpy(key->n, n, n_len);
	std::memcpy(key->e, e, e_len);
	return KCTSB_SUCCESS;
}

KCTSB_API kctsb_error_t kctsb_rsa_private_key_init(
	kctsb_rsa_private_key_t* key,
	const uint8_t* n,
	size_t n_len,
	const uint8_t* d,
	size_t d_len)
{
	if (!key || !n || !d || n_len == 0 || d_len == 0) {
		return KCTSB_ERROR_INVALID_PARAM;
	}
	if (!kctsb::crypto::rsa::is_supported_modulus_bytes(n_len)) {
		return KCTSB_ERROR_INVALID_KEY;
	}
	if (n_len > KCTSB_RSA_MAX_MODULUS_BYTES || d_len > KCTSB_RSA_MAX_MODULUS_BYTES) {
		return KCTSB_ERROR_INVALID_PARAM;
	}

	std::memset(key, 0, sizeof(*key));
	key->bits = static_cast<uint32_t>(n_len * 8);
	key->n_len = static_cast<uint32_t>(n_len);
	key->d_len = static_cast<uint32_t>(d_len);
	std::memcpy(key->n, n, n_len);
	std::memcpy(key->d, d, d_len);
	key->has_crt = 0;
	return KCTSB_SUCCESS;
}

KCTSB_API kctsb_error_t kctsb_rsa_private_key_init_crt(
	kctsb_rsa_private_key_t* key,
	const uint8_t* n,
	size_t n_len,
	const uint8_t* d,
	size_t d_len,
	const uint8_t* p,
	size_t p_len,
	const uint8_t* q,
	size_t q_len,
	const uint8_t* dp,
	size_t dp_len,
	const uint8_t* dq,
	size_t dq_len,
	const uint8_t* qinv,
	size_t qinv_len)
{
	kctsb_error_t base = kctsb_rsa_private_key_init(key, n, n_len, d, d_len);
	if (base != KCTSB_SUCCESS) {
		return base;
	}
	if (!p || !q || !dp || !dq || !qinv) {
		return KCTSB_ERROR_INVALID_PARAM;
	}
	if (p_len > KCTSB_RSA_MAX_PRIME_BYTES || q_len > KCTSB_RSA_MAX_PRIME_BYTES ||
		dp_len > KCTSB_RSA_MAX_PRIME_BYTES || dq_len > KCTSB_RSA_MAX_PRIME_BYTES ||
		qinv_len > KCTSB_RSA_MAX_PRIME_BYTES) {
		return KCTSB_ERROR_INVALID_PARAM;
	}
	key->p_len = static_cast<uint32_t>(p_len);
	key->q_len = static_cast<uint32_t>(q_len);
	key->dp_len = static_cast<uint32_t>(dp_len);
	key->dq_len = static_cast<uint32_t>(dq_len);
	key->qinv_len = static_cast<uint32_t>(qinv_len);
	std::memcpy(key->p, p, p_len);
	std::memcpy(key->q, q, q_len);
	std::memcpy(key->dp, dp, dp_len);
	std::memcpy(key->dq, dq, dq_len);
	std::memcpy(key->qinv, qinv, qinv_len);
	key->has_crt = 1;
	return KCTSB_SUCCESS;
}

KCTSB_API kctsb_error_t kctsb_rsa_generate_keypair(
	int bits,
	kctsb_rsa_public_key_t* pub,
	kctsb_rsa_private_key_t* priv)
{
	if (!pub || !priv) {
		return KCTSB_ERROR_INVALID_PARAM;
	}
	if (bits != KCTSB_RSA_3072_BITS && bits != KCTSB_RSA_4096_BITS) {
		return KCTSB_ERROR_INVALID_PARAM;
	}

	try {
		using namespace kctsb::crypto::rsa;
		kctsb::ZZ e = kctsb::ZZ(65537);
		kctsb::ZZ p, q, n, phi, d, dp, dq, qinv;
		size_t prime_bits = static_cast<size_t>(bits / 2);

		while (true) {
			p = generate_prime_bits(prime_bits);
			q = generate_prime_bits(prime_bits);
			if (p == q) {
				continue;
			}
			n = p * q;
			if (NumBits(n) != bits) {
				continue;
			}
			kctsb::ZZ p1 = p - kctsb::ZZ(1);
			kctsb::ZZ q1 = q - kctsb::ZZ(1);
			phi = p1 * q1;
			if (GCD(e, phi) != kctsb::ZZ(1)) {
				continue;
			}
			d = InvMod(e, phi);
			dp = d % p1;
			dq = d % q1;
			qinv = InvMod(q, p);
			break;
		}

		size_t n_len = static_cast<size_t>(bits / 8);
		std::vector<uint8_t> n_bytes(n_len);
		std::array<uint8_t, 3> e_fixed{{0x01, 0x00, 0x01}};
		std::vector<uint8_t> e_bytes = trim_leading_zeros(e_fixed.data(), e_fixed.size());
		std::vector<uint8_t> d_bytes(n_len);
		std::vector<uint8_t> p_bytes(n_len / 2);
		std::vector<uint8_t> q_bytes(n_len / 2);
		std::vector<uint8_t> dp_bytes(n_len / 2);
		std::vector<uint8_t> dq_bytes(n_len / 2);
		std::vector<uint8_t> qinv_bytes(n_len / 2);

		n.to_bytes(n_bytes.data(), n_bytes.size());
		d.to_bytes(d_bytes.data(), d_bytes.size());
		p.to_bytes(p_bytes.data(), p_bytes.size());
		q.to_bytes(q_bytes.data(), q_bytes.size());
		dp.to_bytes(dp_bytes.data(), dp_bytes.size());
		dq.to_bytes(dq_bytes.data(), dq_bytes.size());
		qinv.to_bytes(qinv_bytes.data(), qinv_bytes.size());

		kctsb_error_t pub_rc = kctsb_rsa_public_key_init(
			pub, n_bytes.data(), n_bytes.size(), e_bytes.data(), e_bytes.size());
		if (pub_rc != KCTSB_SUCCESS) {
			return pub_rc;
		}
		kctsb_error_t priv_rc = kctsb_rsa_private_key_init_crt(
			priv,
			n_bytes.data(), n_bytes.size(),
			d_bytes.data(), d_bytes.size(),
			p_bytes.data(), p_bytes.size(),
			q_bytes.data(), q_bytes.size(),
			dp_bytes.data(), dp_bytes.size(),
			dq_bytes.data(), dq_bytes.size(),
			qinv_bytes.data(), qinv_bytes.size());
		return priv_rc;
	} catch (...) {
		return KCTSB_ERROR_INTERNAL;
	}
}

KCTSB_API kctsb_error_t kctsb_rsa_oaep_encrypt_sha256(
	const kctsb_rsa_public_key_t* pub,
	const uint8_t* message,
	size_t message_len,
	const uint8_t* label,
	size_t label_len,
	uint8_t* ciphertext,
	size_t* ciphertext_len)
{
	if (!pub || !message || !ciphertext || !ciphertext_len) {
		return KCTSB_ERROR_INVALID_PARAM;
	}
	if (*ciphertext_len < pub->n_len) {
		return KCTSB_ERROR_BUFFER_TOO_SMALL;
	}

	try {
		using namespace kctsb::crypto::rsa;
		PublicKey key;
		kctsb_error_t rc = load_public_key(pub, key);
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}

		std::vector<uint8_t> em(pub->n_len, 0);
		rc = oaep_encode(message, message_len, label, label_len, pub->n_len, nullptr, em.data());
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}

		kctsb::ZZ m = os2ip(em.data(), em.size());
		kctsb::ZZ c = rsa_public_op(m, key);
		rc = i2osp(c, ciphertext, pub->n_len);
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}
		*ciphertext_len = pub->n_len;
		return KCTSB_SUCCESS;
	} catch (...) {
		return KCTSB_ERROR_ENCRYPTION_FAILED;
	}
}

KCTSB_API kctsb_error_t kctsb_rsa_oaep_decrypt_sha256(
	const kctsb_rsa_private_key_t* priv,
	const uint8_t* ciphertext,
	size_t ciphertext_len,
	const uint8_t* label,
	size_t label_len,
	uint8_t* message,
	size_t* message_len)
{
	if (!priv || !ciphertext || !message || !message_len) {
		return KCTSB_ERROR_INVALID_PARAM;
	}
	if (ciphertext_len != priv->n_len) {
		return KCTSB_ERROR_DECRYPTION_FAILED;
	}

	try {
		using namespace kctsb::crypto::rsa;
		PrivateKey key;
		kctsb_error_t rc = load_private_key(priv, key);
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}

		kctsb::ZZ c = os2ip(ciphertext, ciphertext_len);
		kctsb::ZZ m = rsa_private_op(c, key);
		std::vector<uint8_t> em(priv->n_len, 0);
		rc = i2osp(m, em.data(), em.size());
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}

		std::vector<uint8_t> decoded;
		rc = oaep_decode(em.data(), em.size(), label, label_len, decoded);
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}
		if (*message_len < decoded.size()) {
			return KCTSB_ERROR_BUFFER_TOO_SMALL;
		}
		std::memcpy(message, decoded.data(), decoded.size());
		*message_len = decoded.size();
		return KCTSB_SUCCESS;
	} catch (...) {
		return KCTSB_ERROR_DECRYPTION_FAILED;
	}
}

KCTSB_API kctsb_error_t kctsb_rsa_pss_sign_sha256(
	const kctsb_rsa_private_key_t* priv,
	const uint8_t* mhash,
	size_t mhash_len,
	const uint8_t* salt,
	size_t salt_len,
	uint8_t* signature,
	size_t* signature_len)
{
	if (!priv || !mhash || !signature || !signature_len) {
		return KCTSB_ERROR_INVALID_PARAM;
	}
	if (*signature_len < priv->n_len) {
		return KCTSB_ERROR_BUFFER_TOO_SMALL;
	}
	if (!salt && salt_len != 0) {
		return KCTSB_ERROR_INVALID_PARAM;
	}

	try {
		using namespace kctsb::crypto::rsa;
		PrivateKey key;
		kctsb_error_t rc = load_private_key(priv, key);
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}

		std::array<uint8_t, kPssSaltLen> salt_buf{};
		if (salt) {
			if (salt_len != kPssSaltLen) {
				return KCTSB_ERROR_INVALID_PARAM;
			}
			std::memcpy(salt_buf.data(), salt, kPssSaltLen);
		} else {
			rc = random_bytes(salt_buf.data(), salt_buf.size());
			if (rc != KCTSB_SUCCESS) {
				return rc;
			}
		}

		std::vector<uint8_t> em(priv->n_len, 0);
		rc = pss_encode(mhash, mhash_len, salt_buf.data(), salt_buf.size(), key.bits - 1, em.data());
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}

		kctsb::ZZ m = os2ip(em.data(), em.size());
		kctsb::ZZ s = rsa_private_op(m, key);
		rc = i2osp(s, signature, priv->n_len);
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}
		*signature_len = priv->n_len;
		return KCTSB_SUCCESS;
	} catch (...) {
		return KCTSB_ERROR_ENCRYPTION_FAILED;
	}
}

KCTSB_API kctsb_error_t kctsb_rsa_pss_verify_sha256(
	const kctsb_rsa_public_key_t* pub,
	const uint8_t* mhash,
	size_t mhash_len,
	const uint8_t* signature,
	size_t signature_len)
{
	if (!pub || !mhash || !signature) {
		return KCTSB_ERROR_INVALID_PARAM;
	}
	if (signature_len != pub->n_len) {
		return KCTSB_ERROR_VERIFICATION_FAILED;
	}

	try {
		using namespace kctsb::crypto::rsa;
		PublicKey key;
		kctsb_error_t rc = load_public_key(pub, key);
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}

		kctsb::ZZ s = os2ip(signature, signature_len);
		kctsb::ZZ m = rsa_public_op(s, key);
		std::vector<uint8_t> em(signature_len, 0);
		rc = i2osp(m, em.data(), em.size());
		if (rc != KCTSB_SUCCESS) {
			return rc;
		}
		return pss_verify(mhash, mhash_len, em.data(), em.size(), key.bits - 1);
	} catch (...) {
		return KCTSB_ERROR_VERIFICATION_FAILED;
	}
}

/**
 * @brief Test Montgomery arithmetic internals
 * @return 0 on success, negative on failure
 */
int kctsb_test_montgomery_internal() {
    using namespace kctsb::crypto::rsa;
    
    // Use ZZ::from_string for a 128-bit test prime
    // Or construct it from bytes
    // Let's use a simpler approach: construct a small 2-limb value
    
    // Test modulus: 2^64 + 13 = 18446744073709551629 (this is prime)
    // Actually let's use from_bytes for a proper 128-bit value
    
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC5 = 340282366920938463463374607431768211397
    // This is 2^128 - 59 which is prime
    uint8_t n_bytes[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC5
    };
    kctsb::ZZ test_n = kctsb::ZZ::from_bytes(n_bytes, sizeof(n_bytes));
    
    // Verify n is odd
    if (!IsOdd(test_n)) {
        std::cerr << "Test modulus is not odd!" << std::endl;
        return -1;
    }
    
    FastMontContext ctx(test_n);
    
    // Print basic info
    std::cerr << "=== Montgomery Internal Test ===" << std::endl;
    std::cerr << "num_limbs: " << ctx.num_limbs << std::endl;
    std::cerr << "n[0]: " << std::hex << ctx.n[0] << std::dec << std::endl;
    std::cerr << "n0_prime: " << std::hex << ctx.n0_prime << std::dec << std::endl;
    
    // Verify: n[0] * n0_prime ≡ -1 (mod 2^64)
    uint64_t product = ctx.n[0] * ctx.n0_prime;
    std::cerr << "n[0] * n0_prime (mod 2^64): " << std::hex << product << std::dec << std::endl;
    if (product != static_cast<uint64_t>(-1)) {
        std::cerr << "ERROR: n0_prime verification failed!" << std::endl;
        std::cerr << "Expected: " << std::hex << static_cast<uint64_t>(-1) << std::dec << std::endl;
        return -2;
    }
    std::cerr << "n0_prime verification: PASS" << std::endl;
    
    // Test 1: to_mont then from_mont should return original value
    kctsb::ZZ test_val(12345);
    std::vector<limb_t> val_limbs = zz_to_limbs(test_val, ctx.num_limbs);
    std::vector<limb_t> val_mont = ctx.to_mont(val_limbs);
    std::vector<limb_t> val_back = ctx.from_mont(val_mont);
    kctsb::ZZ val_result = limbs_to_zz(val_back);
    
    std::cerr << "Test value: " << test_val << std::endl;
    std::cerr << "After to_mont/from_mont: " << val_result << std::endl;
    
    if (val_result != test_val) {
        std::cerr << "ERROR: to_mont/from_mont roundtrip failed!" << std::endl;
        return -3;
    }
    std::cerr << "Roundtrip test: PASS" << std::endl;
    
    // Test 2: mont_mul(a_mont, b_mont) then from_mont should equal (a*b) mod n
    kctsb::ZZ a(1234567890);
    kctsb::ZZ b(9876543210ULL);
    kctsb::ZZ expected = (a * b) % test_n;
    
    std::vector<limb_t> a_limbs = zz_to_limbs(a, ctx.num_limbs);
    std::vector<limb_t> b_limbs = zz_to_limbs(b, ctx.num_limbs);
    std::vector<limb_t> a_mont = ctx.to_mont(a_limbs);
    std::vector<limb_t> b_mont = ctx.to_mont(b_limbs);
    std::vector<limb_t> prod_mont = ctx.mont_mul(a_mont, b_mont);
    std::vector<limb_t> prod_limbs = ctx.from_mont(prod_mont);
    kctsb::ZZ prod_result = limbs_to_zz(prod_limbs);
    
    std::cerr << "a * b mod n expected: " << expected << std::endl;
    std::cerr << "Montgomery result: " << prod_result << std::endl;
    
    if (prod_result != expected) {
        std::cerr << "ERROR: Montgomery multiplication failed!" << std::endl;
        return -4;
    }
    std::cerr << "Multiplication test: PASS" << std::endl;
    
    // Test 3: Modular exponentiation 3^17 mod test_n
    kctsb::ZZ base(3);
    kctsb::ZZ exp(17);
    kctsb::ZZ expected_exp(1);
    for (int i = 0; i < 17; ++i) {
        expected_exp = (expected_exp * base) % test_n;
    }
    
    kctsb::ZZ modexp_result = fast_modexp(base, exp, test_n);
    std::cerr << "3^17 mod n expected: " << expected_exp << std::endl;
    std::cerr << "fast_modexp result: " << modexp_result << std::endl;
    
    if (modexp_result != expected_exp) {
        std::cerr << "ERROR: fast_modexp failed!" << std::endl;
        return -5;
    }
    std::cerr << "Modexp test: PASS" << std::endl;
    
    std::cerr << "=== All Montgomery tests PASSED ===" << std::endl;
    return 0;
}

/**
 * @brief Test RSA sign/verify core operations (no PSS encoding)
 * @return 0 on success, negative on failure
 */
int kctsb_test_rsa_core_internal() {
    using namespace kctsb::crypto::rsa;
    
    std::cerr << "\n=== RSA Core Test ===" << std::endl;
    
    // Generate a keypair
    kctsb_rsa_public_key_t pub{};
    kctsb_rsa_private_key_t priv{};
    int rc = kctsb_rsa_generate_keypair(3072, &pub, &priv);
    if (rc != KCTSB_SUCCESS) {
        std::cerr << "Keygen failed: " << rc << std::endl;
        return -1;
    }
    
    // Load keys
    PublicKey pub_key;
    PrivateKey priv_key;
    if (load_public_key(&pub, pub_key) != KCTSB_SUCCESS ||
        load_private_key(&priv, priv_key) != KCTSB_SUCCESS) {
        std::cerr << "Key loading failed" << std::endl;
        return -2;
    }
    
    // Test: m^d^e mod n should equal m
    // And: m^e^d mod n should equal m
    kctsb::ZZ test_msg(42);
    
    // Encrypt then decrypt: c = m^e, m' = c^d
    std::cerr << "Test message: " << test_msg << std::endl;
    kctsb::ZZ c = rsa_public_op(test_msg, pub_key);
    std::cerr << "After public op (encrypt): " << c << std::endl;
    kctsb::ZZ m_prime = rsa_private_op(c, priv_key);
    std::cerr << "After private op (decrypt): " << m_prime << std::endl;
    
    if (m_prime != test_msg) {
        std::cerr << "ERROR: encrypt/decrypt roundtrip failed!" << std::endl;
        return -3;
    }
    std::cerr << "Encrypt/Decrypt roundtrip: PASS" << std::endl;
    
    // Sign then verify: s = m^d, m'' = s^e
    kctsb::ZZ s = rsa_private_op(test_msg, priv_key);
    std::cerr << "After private op (sign): " << s << std::endl;
    kctsb::ZZ m_double_prime = rsa_public_op(s, pub_key);
    std::cerr << "After public op (verify): " << m_double_prime << std::endl;
    
    if (m_double_prime != test_msg) {
        std::cerr << "ERROR: sign/verify roundtrip failed!" << std::endl;
        std::cerr << "Expected: " << test_msg << std::endl;
        std::cerr << "Got: " << m_double_prime << std::endl;
        return -4;
    }
    std::cerr << "Sign/Verify roundtrip: PASS" << std::endl;
    
    std::cerr << "=== RSA Core tests PASSED ===" << std::endl;
    return 0;
}

/**
 * @brief Test PSS encoding/decoding
 * @return 0 on success, negative on failure
 */
int kctsb_test_pss_internal() {
    using namespace kctsb::crypto::rsa;
    
    std::cerr << "\n=== PSS Internal Test ===" << std::endl;
    
    // Generate a keypair
    kctsb_rsa_public_key_t pub{};
    kctsb_rsa_private_key_t priv{};
    int rc = kctsb_rsa_generate_keypair(3072, &pub, &priv);
    if (rc != KCTSB_SUCCESS) {
        std::cerr << "Keygen failed: " << rc << std::endl;
        return -1;
    }
    
    PublicKey pub_key;
    PrivateKey priv_key;
    load_public_key(&pub, pub_key);
    load_private_key(&priv, priv_key);
    
    // Create a message hash
    uint8_t msg[] = "Test message for PSS";
    uint8_t mhash[32];
    kctsb_sha256(msg, sizeof(msg) - 1, mhash);
    
    // Create salt
    uint8_t salt[32];
    random_bytes(salt, 32);
    
    // PSS encode
    size_t em_bits = pub_key.bits - 1;  // 3072 - 1 = 3071
    size_t em_len = (em_bits + 7) / 8;  // 384 bytes
    std::vector<uint8_t> em(em_len, 0);
    
    std::cerr << "em_bits: " << em_bits << ", em_len: " << em_len << std::endl;
    
    rc = pss_encode(mhash, 32, salt, 32, em_bits, em.data());
    if (rc != KCTSB_SUCCESS) {
        std::cerr << "PSS encode failed: " << rc << std::endl;
        return -2;
    }
    std::cerr << "PSS encode: OK" << std::endl;
    std::cerr << "em[0]: " << std::hex << (int)em[0] << ", em[last]: " << (int)em[em_len-1] << std::dec << std::endl;
    
    // Verify the encoded message directly (no RSA operation)
    rc = pss_verify(mhash, 32, em.data(), em_len, em_bits);
    if (rc != KCTSB_SUCCESS) {
        std::cerr << "PSS verify (direct) failed: " << rc << std::endl;
        return -3;
    }
    std::cerr << "PSS verify (direct): PASS" << std::endl;
    
    // Now do the full sign/verify with RSA
    kctsb::ZZ m = os2ip(em.data(), em.size());
    std::cerr << "EM as integer, num_bytes: " << m.num_bytes() << std::endl;
    
    // Check if m < n
    if (m >= pub_key.n) {
        std::cerr << "ERROR: m >= n (message too large)" << std::endl;
        return -4;
    }
    std::cerr << "m < n: OK" << std::endl;
    
    // Sign
    kctsb::ZZ s = rsa_private_op(m, priv_key);
    std::cerr << "Signature computed" << std::endl;
    
    // Verify: compute m' = s^e mod n
    kctsb::ZZ m_prime = rsa_public_op(s, pub_key);
    
    if (m_prime != m) {
        std::cerr << "ERROR: m' != m after RSA ops" << std::endl;
        std::cerr << "m.num_bytes: " << m.num_bytes() << std::endl;
        std::cerr << "m_prime.num_bytes: " << m_prime.num_bytes() << std::endl;
        return -5;
    }
    std::cerr << "RSA sign/verify core: PASS" << std::endl;
    
    // Convert back to bytes
    std::vector<uint8_t> em_recovered(em_len, 0);
    rc = i2osp(m_prime, em_recovered.data(), em_len);
    if (rc != KCTSB_SUCCESS) {
        std::cerr << "i2osp failed: " << rc << std::endl;
        return -6;
    }
    
    // Check if em_recovered == em
    if (memcmp(em.data(), em_recovered.data(), em_len) != 0) {
        std::cerr << "ERROR: em_recovered != em" << std::endl;
        std::cerr << "em[0]: " << std::hex << (int)em[0] << ", recovered[0]: " << (int)em_recovered[0] << std::dec << std::endl;
        return -7;
    }
    std::cerr << "EM roundtrip: PASS" << std::endl;
    
    // Now verify PSS on recovered EM
    rc = pss_verify(mhash, 32, em_recovered.data(), em_len, em_bits);
    if (rc != KCTSB_SUCCESS) {
        std::cerr << "PSS verify (after RSA) failed: " << rc << std::endl;
        return -8;
    }
    std::cerr << "PSS verify (after RSA): PASS" << std::endl;
    
    std::cerr << "=== PSS tests PASSED ===" << std::endl;
    return 0;
}

} // extern "C"
