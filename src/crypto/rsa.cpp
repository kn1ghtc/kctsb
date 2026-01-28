/**
 * @file rsa.cpp
 * @brief RSA-PSS/RSAES-OAEP implementation (SHA-256 only, 3072/4096 bits)
 *
 * Single-file RSA implementation optimized for HTTPS usage:
 * - RSASSA-PSS (SHA-256) signature/verification
 * - RSAES-OAEP (SHA-256) encryption/decryption
 * - Key sizes: 3072/4096 only
 * - Optional CRT acceleration if p/q provided
 *
 * Design goals:
 * - Self-contained (no OpenSSL/GMP dependencies)
 * - C ABI for stable integration
 * - Constant-time primitives where applicable (hash compare)
 *
 * References:
 * - RFC 8017 (PKCS#1 v2.2)
 * - NIST CAVP RSA PSS vectors (FIPS 186-3)
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

constexpr size_t kHashLen = KCTSB_SHA256_DIGEST_SIZE;
constexpr size_t kPssSaltLen = KCTSB_SHA256_DIGEST_SIZE;

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

static ZZ modexp_window(const ZZ& base, const ZZ& exp, const ZZ& mod) {
	if (mod <= ZZ(0)) {
		throw std::domain_error("modexp: modulus must be positive");
	}

	if (exp.is_zero()) {
		return ZZ(1);
	}

	constexpr int window_bits = 5;
	constexpr int table_size = 1 << window_bits;

	ZZ base_mod = base % mod;
	if (base_mod.is_negative()) {
		base_mod += mod;
	}

	std::array<ZZ, table_size> table;
	table[0] = ZZ(1);
	table[1] = base_mod;
	for (int i = 2; i < table_size; ++i) {
		table[i] = (table[i - 1] * base_mod) % mod;
	}

	ZZ result(1);
	long exp_bits = NumBits(exp);
	long i = exp_bits - 1;

	while (i >= 0) {
		if (bit(exp, i) == 0) {
			result = (result * result) % mod;
			--i;
			continue;
		}

		long width = std::min<long>(window_bits, i + 1);
		long window_val = 0;
		long j = i - width + 1;
		while (bit(exp, j) == 0 && width > 1) {
			++j;
			--width;
		}
		for (long k = 0; k < width; ++k) {
			window_val = (window_val << 1) | bit(exp, j + k);
		}

		for (long k = 0; k < width; ++k) {
			result = (result * result) % mod;
		}
		result = (result * table[window_val]) % mod;
		i = j - 1;
	}

	return result;
}

static int select_window_bits(size_t bits) {
	if (bits >= KCTSB_RSA_4096_BITS) {
		return 6;
	}
	return 5;
}

static ZZ modexp_fixed_window(const ZZ& base, const ZZ& exp, const ZZ& mod, int window_bits) {
	if (mod <= ZZ(0)) {
		throw std::domain_error("modexp: modulus must be positive");
	}
	if (exp.is_zero()) {
		return ZZ(1);
	}
	int actual_bits = window_bits < 1 ? 1 : window_bits;

	ZZ base_mod = base % mod;
	if (base_mod.is_negative()) {
		base_mod += mod;
	}

	constexpr int kMaxFixedWindowBits = 6;
	int table_size = 1 << actual_bits;

	ZZ result(1);
	long exp_bits = NumBits(exp);
	long total_windows = (exp_bits + actual_bits - 1) / actual_bits;

	if (actual_bits == kMaxFixedWindowBits) {
		constexpr int kMaxFixedTableSize = 1 << kMaxFixedWindowBits;
		std::array<ZZ, kMaxFixedTableSize> table;
		table[0] = ZZ(1);
		for (int i = 1; i < table_size; ++i) {
			table[static_cast<size_t>(i)] = (table[static_cast<size_t>(i - 1)] * base_mod) % mod;
		}

		for (long w = total_windows - 1; w >= 0; --w) {
			for (int i = 0; i < actual_bits; ++i) {
				result = (result * result) % mod;
			}

			long window_val = 0;
			for (int i = actual_bits - 1; i >= 0; --i) {
				long bit_index = w * actual_bits + i;
				int bit_val = (bit_index < exp_bits) ? bit(exp, bit_index) : 0;
				window_val = (window_val << 1) | bit_val;
			}
			result = (result * table[static_cast<size_t>(window_val)]) % mod;
		}

		return result;
	}

	std::vector<ZZ> table(static_cast<size_t>(table_size));
	table[0] = ZZ(1);
	for (int i = 1; i < table_size; ++i) {
		table[static_cast<size_t>(i)] = (table[static_cast<size_t>(i - 1)] * base_mod) % mod;
	}

	for (long w = total_windows - 1; w >= 0; --w) {
		for (int i = 0; i < actual_bits; ++i) {
			result = (result * result) % mod;
		}

		long window_val = 0;
		for (int i = actual_bits - 1; i >= 0; --i) {
			long bit_index = w * actual_bits + i;
			int bit_val = (bit_index < exp_bits) ? bit(exp, bit_index) : 0;
			window_val = (window_val << 1) | bit_val;
		}
		result = (result * table[static_cast<size_t>(window_val)]) % mod;
	}

	return result;
}

static ZZ modexp_65537(const ZZ& base, const ZZ& mod) {
	if (mod <= ZZ(0)) {
		throw std::domain_error("modexp: modulus must be positive");
	}

	ZZ base_mod = base % mod;
	if (base_mod.is_negative()) {
		base_mod += mod;
	}

	ZZ acc = base_mod;
	for (int i = 0; i < 16; ++i) {
		acc = (acc * acc) % mod;
	}
	return (acc * base_mod) % mod;
}

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
	if (key.e == ZZ(65537)) {
		return modexp_65537(m, key.n);
	}
	return modexp_fixed_window(m, key.e, key.n, select_window_bits(key.bits));
}

static ZZ rsa_private_op(const ZZ& c, const PrivateKey& key) {
	if (c < ZZ(0) || c >= key.n) {
		throw std::domain_error("RSADP cipher representative out of range");
	}

	if (!key.has_crt) {
		return modexp_fixed_window(c, key.d, key.n, select_window_bits(key.bits));
	}
	int window_bits = select_window_bits(key.bits / 2);
	ZZ m1 = modexp_fixed_window(c, key.dp, key.p, window_bits);
	ZZ m2 = modexp_fixed_window(c, key.dq, key.q, window_bits);
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

		ZZ x = modexp_window(a, d, n);
		if (x == ZZ(1) || x == n - ZZ(1)) {
			continue;
		}

		bool witness = true;
		for (long j = 1; j < r; ++j) {
			x = (x * x) % n;
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

} // extern "C"
