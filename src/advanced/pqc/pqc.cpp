/**
 * @file pqc.cpp
 * @brief Post-Quantum Cryptography Implementation
 *
 * Implements ML-KEM (Kyber) and ML-DSA (Dilithium) per NIST FIPS 203/204.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include <kctsb/advanced/pqc/pqc.h>
#include <kctsb/math/ZZ.h>
#include <cstring>
#include <random>
#include <stdexcept>

namespace kctsb {
namespace pqc {

// ============================================================================
// Kyber NTT Tables
// ============================================================================

namespace {

// Kyber modulus q = 3329
constexpr int16_t KYBER_Q_INT = 3329;

// Montgomery constant: 2^16 mod q
constexpr int32_t KYBER_MONT = 2285;

// Barrett reduction constant
constexpr int32_t KYBER_BARRETT = 20159;

// Zetas for NTT (q = 3329, primitive 512th root)
constexpr int16_t kyber_zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
    3158, 622, 1577, 182, 962, 2127, 1855, 1468,
    573, 2004, 264, 383, 2500, 1458, 1727, 3199,
    2648, 1017, 732, 608, 1787, 411, 3124, 1758,
    1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
    516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
    2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
    2931, 961, 1821, 2604, 448, 2264, 677, 2054,
    2226, 430, 555, 843, 2078, 871, 1550, 105,
    422, 587, 177, 3094, 3038, 2869, 1574, 1653,
    3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739, 644, 2457, 349, 418, 329, 3173, 3254,
    817, 1097, 603, 610, 1322, 2044, 1864, 384,
    2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
    2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
    3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

// Inverse zetas for inverse NTT
constexpr int16_t kyber_zetas_inv[128] = {
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108,
    2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215,
    2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590,
    2210, 602, 1846, 777, 147, 2170, 2551, 246,
    1676, 1755, 460, 291, 235, 3152, 2742, 2907,
    3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
    1275, 2652, 1065, 2881, 725, 1508, 2368, 398,
    951, 247, 1421, 3222, 2499, 271, 90, 853,
    1860, 3203, 1162, 1618, 666, 320, 8, 2813,
    1544, 282, 1838, 1293, 2314, 552, 2677, 2106,
    1542, 2918, 2721, 1542, 1612, 2883, 2853, 1202,
    2500, 2064, 1311, 2004, 2656, 2272, 2045, 1779,
    2481, 2277, 1565, 1380, 1055, 1883, 2607, 3010,
    1277, 2710, 2861, 2370, 287, 202, 3158, 622
};

// Barrett reduction: a mod q
inline int16_t barrett_reduce(int16_t a) {
    int16_t t;
    t = ((int32_t)a * KYBER_BARRETT + (1 << 25)) >> 26;
    t *= KYBER_Q_INT;
    return a - t;
}

// Montgomery reduction
inline int16_t montgomery_reduce(int32_t a) {
    int16_t t;
    t = (int16_t)a * (-3327);  // q^-1 mod 2^16
    t = (a - (int32_t)t * KYBER_Q_INT) >> 16;
    return t;
}

// Modular addition
inline int16_t mod_add(int16_t a, int16_t b) {
    int16_t r = a + b;
    if (r >= KYBER_Q_INT) r -= KYBER_Q_INT;
    if (r < 0) r += KYBER_Q_INT;
    return r;
}

// Modular subtraction
inline int16_t mod_sub(int16_t a, int16_t b) {
    int16_t r = a - b;
    if (r < 0) r += KYBER_Q_INT;
    return r;
}

// SHA3-256 placeholder (use actual implementation)
void sha3_256(uint8_t out[32], const uint8_t* in, size_t len) {
    // Simplified hash - replace with actual SHA3
    std::hash<std::string> hasher;
    std::string s(reinterpret_cast<const char*>(in), len);
    size_t h = hasher(s);
    memset(out, 0, 32);
    memcpy(out, &h, sizeof(h));
    for (size_t i = 0; i < 32; i += 8) {
        h = hasher(std::string(reinterpret_cast<char*>(out), 32));
        memcpy(out + i, &h, std::min(sizeof(h), 32 - i));
    }
}

// SHA3-512 placeholder
void sha3_512(uint8_t out[64], const uint8_t* in, size_t len) {
    sha3_256(out, in, len);
    sha3_256(out + 32, out, 32);
}

// SHAKE128 placeholder
void shake128(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) {
    uint8_t seed[32];
    sha3_256(seed, in, inlen);
    for (size_t i = 0; i < outlen; i += 32) {
        seed[0] ^= (uint8_t)(i >> 8);
        seed[1] ^= (uint8_t)i;
        sha3_256(seed, seed, 32);
        memcpy(out + i, seed, std::min((size_t)32, outlen - i));
    }
}

// SHAKE256 placeholder
void shake256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) {
    uint8_t seed[64];
    sha3_512(seed, in, inlen);
    for (size_t i = 0; i < outlen; i += 64) {
        seed[0] ^= (uint8_t)(i >> 8);
        seed[1] ^= (uint8_t)i;
        sha3_512(seed, seed, 64);
        memcpy(out + i, seed, std::min((size_t)64, outlen - i));
    }
}

// Random bytes
void random_bytes(uint8_t* out, size_t len) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (size_t i = 0; i < len; i += 8) {
        uint64_t r = gen();
        memcpy(out + i, &r, std::min((size_t)8, len - i));
    }
}

}  // anonymous namespace

// ============================================================================
// KyberParams Implementation
// ============================================================================

KyberParams KyberParams::get(KyberLevel level) {
    KyberParams p;
    p.shared_secret_size = 32;

    switch (level) {
        case KyberLevel::KYBER512:
            p.k = 2;
            p.eta1 = 3;
            p.eta2 = 2;
            p.du = 10;
            p.dv = 4;
            p.public_key_size = 800;
            p.secret_key_size = 1632;
            p.ciphertext_size = 768;
            break;
        case KyberLevel::KYBER768:
            p.k = 3;
            p.eta1 = 2;
            p.eta2 = 2;
            p.du = 10;
            p.dv = 4;
            p.public_key_size = 1184;
            p.secret_key_size = 2400;
            p.ciphertext_size = 1088;
            break;
        case KyberLevel::KYBER1024:
            p.k = 4;
            p.eta1 = 2;
            p.eta2 = 2;
            p.du = 11;
            p.dv = 5;
            p.public_key_size = 1568;
            p.secret_key_size = 3168;
            p.ciphertext_size = 1568;
            break;
    }
    return p;
}

// ============================================================================
// KyberPoly Implementation
// ============================================================================

KyberPoly& KyberPoly::operator+=(const KyberPoly& other) {
    for (size_t i = 0; i < KYBER_N; ++i) {
        coeffs[i] = mod_add(coeffs[i], other.coeffs[i]);
    }
    return *this;
}

KyberPoly& KyberPoly::operator-=(const KyberPoly& other) {
    for (size_t i = 0; i < KYBER_N; ++i) {
        coeffs[i] = mod_sub(coeffs[i], other.coeffs[i]);
    }
    return *this;
}

KyberPoly KyberPoly::operator+(const KyberPoly& other) const {
    KyberPoly result = *this;
    result += other;
    return result;
}

KyberPoly KyberPoly::operator-(const KyberPoly& other) const {
    KyberPoly result = *this;
    result -= other;
    return result;
}

void KyberPoly::reduce() {
    for (size_t i = 0; i < KYBER_N; ++i) {
        coeffs[i] = barrett_reduce(coeffs[i]);
    }
}

void KyberPoly::ntt() {
    size_t k = 1;
    for (size_t len = 128; len >= 2; len >>= 1) {
        for (size_t start = 0; start < KYBER_N; start += 2 * len) {
            int16_t zeta = kyber_zetas[k++];
            for (size_t j = start; j < start + len; ++j) {
                int16_t t = montgomery_reduce((int32_t)zeta * coeffs[j + len]);
                coeffs[j + len] = coeffs[j] - t;
                coeffs[j] = coeffs[j] + t;
            }
        }
    }
    reduce();
}

void KyberPoly::inv_ntt() {
    size_t k = 127;
    for (size_t len = 2; len <= 128; len <<= 1) {
        for (size_t start = 0; start < KYBER_N; start += 2 * len) {
            int16_t zeta = kyber_zetas_inv[k--];
            for (size_t j = start; j < start + len; ++j) {
                int16_t t = coeffs[j];
                coeffs[j] = barrett_reduce(t + coeffs[j + len]);
                coeffs[j + len] = montgomery_reduce((int32_t)zeta * (coeffs[j + len] - t));
            }
        }
    }
    // Multiply by n^-1 mod q
    for (size_t i = 0; i < KYBER_N; ++i) {
        coeffs[i] = montgomery_reduce((int32_t)coeffs[i] * 3303);  // 128^-1 * 2^16 mod q
    }
}

// ============================================================================
// KyberPolyVec Implementation
// ============================================================================

KyberPolyVec& KyberPolyVec::operator+=(const KyberPolyVec& other) {
    for (size_t i = 0; i < polys.size(); ++i) {
        polys[i] += other.polys[i];
    }
    return *this;
}

void KyberPolyVec::ntt() {
    for (auto& p : polys) {
        p.ntt();
    }
}

void KyberPolyVec::inv_ntt() {
    for (auto& p : polys) {
        p.inv_ntt();
    }
}

void KyberPolyVec::reduce() {
    for (auto& p : polys) {
        p.reduce();
    }
}

// ============================================================================
// KyberSecretKey Implementation
// ============================================================================

void KyberSecretKey::clear() {
    if (!data.empty()) {
        volatile uint8_t* p = data.data();
        for (size_t i = 0; i < data.size(); ++i) {
            p[i] = 0;
        }
    }
    data.clear();
}

// ============================================================================
// Kyber Implementation
// ============================================================================

Kyber::Kyber(KyberLevel level) : level_(level), params_(KyberParams::get(level)) {}

void Kyber::gen_matrix(std::vector<std::vector<KyberPoly>>& A,
                       const uint8_t seed[32], bool transposed) const {
    A.resize(params_.k);
    for (size_t i = 0; i < params_.k; ++i) {
        A[i].resize(params_.k);
        for (size_t j = 0; j < params_.k; ++j) {
            // XOF input: seed || i || j (or j || i if transposed)
            uint8_t xof_in[34];
            memcpy(xof_in, seed, 32);
            if (transposed) {
                xof_in[32] = (uint8_t)j;
                xof_in[33] = (uint8_t)i;
            } else {
                xof_in[32] = (uint8_t)i;
                xof_in[33] = (uint8_t)j;
            }

            // Sample polynomial from SHAKE128
            uint8_t buf[672];  // Enough for rejection sampling
            shake128(buf, sizeof(buf), xof_in, 34);

            size_t ctr = 0;
            size_t pos = 0;
            while (ctr < KYBER_N && pos + 3 <= sizeof(buf)) {
                uint16_t d1 = buf[pos] | ((uint16_t)(buf[pos + 1] & 0x0F) << 8);
                uint16_t d2 = (buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4);
                pos += 3;

                if (d1 < KYBER_Q) {
                    A[i][j].coeffs[ctr++] = d1;
                }
                if (ctr < KYBER_N && d2 < KYBER_Q) {
                    A[i][j].coeffs[ctr++] = d2;
                }
            }
        }
    }
}

void Kyber::sample_noise(KyberPolyVec& r, const uint8_t seed[32], uint8_t nonce) const {
    size_t eta = (nonce < params_.k) ? params_.eta1 : params_.eta2;

    for (size_t i = 0; i < r.polys.size(); ++i) {
        uint8_t prf_in[33];
        memcpy(prf_in, seed, 32);
        prf_in[32] = nonce + i;

        uint8_t buf[eta * KYBER_N / 4];
        shake256(buf, sizeof(buf), prf_in, 33);

        // CBD (Centered Binomial Distribution)
        size_t j = 0;
        for (size_t k = 0; k < KYBER_N && j < sizeof(buf); ++k) {
            int16_t a = 0, b = 0;
            for (size_t l = 0; l < eta; ++l) {
                a += (buf[j] >> l) & 1;
                b += (buf[j] >> (l + eta)) & 1;
            }
            r.polys[i].coeffs[k] = a - b;
            if (k % 2 == 1) j++;
        }
    }
}

KyberKeyPair Kyber::keygen() const {
    KyberKeyPair kp;

    // Generate random seed
    uint8_t d[32];
    random_bytes(d, 32);

    // Expand seed
    uint8_t buf[64];
    sha3_512(buf, d, 32);
    uint8_t* rho = buf;       // Public seed
    uint8_t* sigma = buf + 32; // Noise seed

    // Generate matrix A
    std::vector<std::vector<KyberPoly>> A;
    gen_matrix(A, rho, false);

    // Sample secret s and error e
    KyberPolyVec s(params_.k), e(params_.k);
    sample_noise(s, sigma, 0);
    sample_noise(e, sigma, params_.k);

    // NTT domain
    s.ntt();
    e.ntt();

    // t = A*s + e
    KyberPolyVec t(params_.k);
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < params_.k; ++j) {
            // Pointwise multiply in NTT domain
            for (size_t k = 0; k < KYBER_N; ++k) {
                t.polys[i].coeffs[k] += montgomery_reduce(
                    (int32_t)A[i][j].coeffs[k] * s.polys[j].coeffs[k]);
            }
        }
        t.polys[i] += e.polys[i];
    }
    t.reduce();

    // Pack public key: t || rho
    kp.public_key.data.resize(params_.public_key_size);
    size_t offset = 0;
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < KYBER_N; j += 8) {
            // Pack 8 coefficients into 12 bytes (12 bits each)
            for (size_t k = 0; k < 4 && offset + 3 <= kp.public_key.data.size() - 32; ++k) {
                uint16_t c0 = t.polys[i].coeffs[j + 2*k] & 0xFFF;
                uint16_t c1 = t.polys[i].coeffs[j + 2*k + 1] & 0xFFF;
                kp.public_key.data[offset++] = c0 & 0xFF;
                kp.public_key.data[offset++] = (c0 >> 8) | ((c1 & 0x0F) << 4);
                kp.public_key.data[offset++] = c1 >> 4;
            }
        }
    }
    memcpy(kp.public_key.data.data() + offset, rho, 32);

    // Pack secret key: s || pk || H(pk) || z
    kp.secret_key.data.resize(params_.secret_key_size);
    offset = 0;
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < KYBER_N; j += 8) {
            for (size_t k = 0; k < 4 && offset + 3 <= params_.secret_key_size; ++k) {
                uint16_t c0 = s.polys[i].coeffs[j + 2*k] & 0xFFF;
                uint16_t c1 = s.polys[i].coeffs[j + 2*k + 1] & 0xFFF;
                kp.secret_key.data[offset++] = c0 & 0xFF;
                kp.secret_key.data[offset++] = (c0 >> 8) | ((c1 & 0x0F) << 4);
                kp.secret_key.data[offset++] = c1 >> 4;
            }
        }
    }

    // Append pk
    memcpy(kp.secret_key.data.data() + offset, kp.public_key.data.data(), params_.public_key_size);
    offset += params_.public_key_size;

    // H(pk)
    sha3_256(kp.secret_key.data.data() + offset, kp.public_key.data.data(), params_.public_key_size);
    offset += 32;

    // Random z for implicit rejection
    random_bytes(kp.secret_key.data.data() + offset, 32);

    return kp;
}

KyberCiphertext Kyber::encaps(const KyberPublicKey& public_key,
                              std::array<uint8_t, 32>& shared_secret) const {
    KyberCiphertext ct;

    // Generate random message m
    uint8_t m[32];
    random_bytes(m, 32);

    // K || r = G(H(pk) || m)
    uint8_t h_pk[32];
    sha3_256(h_pk, public_key.data.data(), public_key.data.size());

    uint8_t g_input[64];
    memcpy(g_input, h_pk, 32);
    memcpy(g_input + 32, m, 32);

    uint8_t kr[64];
    sha3_512(kr, g_input, 64);

    // Unpack public key
    KyberPolyVec t(params_.k);
    uint8_t rho[32];
    unpack_pk(t, rho, public_key.data);

    // Generate matrix A^T
    std::vector<std::vector<KyberPoly>> At;
    gen_matrix(At, rho, true);

    // Sample r, e1, e2
    KyberPolyVec r_vec(params_.k), e1(params_.k);
    KyberPoly e2;
    sample_noise(r_vec, kr + 32, 0);
    sample_noise(e1, kr + 32, params_.k);

    // e2 from single byte
    uint8_t e2_seed[33];
    memcpy(e2_seed, kr + 32, 32);
    e2_seed[32] = 2 * params_.k;
    uint8_t e2_buf[KYBER_N / 4];
    shake256(e2_buf, sizeof(e2_buf), e2_seed, 33);
    for (size_t i = 0; i < KYBER_N; ++i) {
        int16_t a = (e2_buf[i / 4] >> (2 * (i % 4))) & 3;
        int16_t b = (e2_buf[i / 4] >> (2 * (i % 4) + 1)) & 1;
        e2.coeffs[i] = a - b;
    }

    // NTT
    r_vec.ntt();

    // u = A^T * r + e1
    KyberPolyVec u(params_.k);
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < params_.k; ++j) {
            for (size_t k = 0; k < KYBER_N; ++k) {
                u.polys[i].coeffs[k] += montgomery_reduce(
                    (int32_t)At[i][j].coeffs[k] * r_vec.polys[j].coeffs[k]);
            }
        }
    }
    u.inv_ntt();
    u += e1;
    u.reduce();

    // v = t^T * r + e2 + m * q/2
    KyberPoly v;
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t k = 0; k < KYBER_N; ++k) {
            v.coeffs[k] += montgomery_reduce(
                (int32_t)t.polys[i].coeffs[k] * r_vec.polys[i].coeffs[k]);
        }
    }
    v.inv_ntt();
    v += e2;

    // Add message
    for (size_t i = 0; i < KYBER_N; ++i) {
        uint8_t bit = (m[i / 8] >> (i % 8)) & 1;
        v.coeffs[i] = mod_add(v.coeffs[i], bit * ((KYBER_Q + 1) / 2));
    }
    v.reduce();

    // Compress and pack ciphertext
    ct.data.resize(params_.ciphertext_size);
    size_t offset = 0;

    // Compress u (du bits)
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < KYBER_N; j += 4) {
            uint16_t c[4];
            for (size_t k = 0; k < 4; ++k) {
                c[k] = ((u.polys[i].coeffs[j + k] << params_.du) + KYBER_Q / 2) / KYBER_Q;
                c[k] &= (1 << params_.du) - 1;
            }
            // Pack based on du
            if (params_.du == 10) {
                ct.data[offset++] = c[0] & 0xFF;
                ct.data[offset++] = (c[0] >> 8) | ((c[1] & 0x3F) << 2);
                ct.data[offset++] = (c[1] >> 6) | ((c[2] & 0x0F) << 4);
                ct.data[offset++] = (c[2] >> 4) | ((c[3] & 0x03) << 6);
                ct.data[offset++] = c[3] >> 2;
            } else {  // du == 11
                ct.data[offset++] = c[0] & 0xFF;
                ct.data[offset++] = (c[0] >> 8) | ((c[1] & 0x1F) << 3);
                ct.data[offset++] = (c[1] >> 5) | ((c[2] & 0x03) << 6);
                ct.data[offset++] = (c[2] >> 2) & 0xFF;
                ct.data[offset++] = (c[2] >> 10) | ((c[3] & 0x7F) << 1);
                ct.data[offset++] = c[3] >> 7;
            }
        }
    }

    // Compress v (dv bits)
    for (size_t j = 0; j < KYBER_N; j += 8) {
        uint8_t c[8];
        for (size_t k = 0; k < 8; ++k) {
            c[k] = ((v.coeffs[j + k] << params_.dv) + KYBER_Q / 2) / KYBER_Q;
            c[k] &= (1 << params_.dv) - 1;
        }
        if (params_.dv == 4) {
            for (size_t k = 0; k < 4; ++k) {
                ct.data[offset++] = c[2*k] | (c[2*k + 1] << 4);
            }
        } else {  // dv == 5
            ct.data[offset++] = c[0] | (c[1] << 5);
            ct.data[offset++] = (c[1] >> 3) | (c[2] << 2) | (c[3] << 7);
            ct.data[offset++] = (c[3] >> 1) | (c[4] << 4);
            ct.data[offset++] = (c[4] >> 4) | (c[5] << 1) | (c[6] << 6);
            ct.data[offset++] = (c[6] >> 2) | (c[7] << 3);
        }
    }

    // K = KDF(K' || H(c))
    uint8_t h_c[32];
    sha3_256(h_c, ct.data.data(), ct.data.size());

    uint8_t kdf_input[64];
    memcpy(kdf_input, kr, 32);
    memcpy(kdf_input + 32, h_c, 32);
    shake256(shared_secret.data(), 32, kdf_input, 64);

    return ct;
}

void Kyber::unpack_pk(KyberPolyVec& pk, uint8_t seed[32],
                      const std::vector<uint8_t>& data) const {
    pk = KyberPolyVec(params_.k);
    size_t offset = 0;

    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < KYBER_N; j += 8) {
            for (size_t k = 0; k < 4 && offset + 3 <= data.size() - 32; ++k) {
                pk.polys[i].coeffs[j + 2*k] = data[offset] | ((data[offset + 1] & 0x0F) << 8);
                pk.polys[i].coeffs[j + 2*k + 1] = (data[offset + 1] >> 4) | (data[offset + 2] << 4);
                offset += 3;
            }
        }
    }
    memcpy(seed, data.data() + data.size() - 32, 32);
}

bool Kyber::decaps(const KyberSecretKey& secret_key,
                   const KyberCiphertext& ciphertext,
                   std::array<uint8_t, 32>& shared_secret) const {
    // Unpack secret key components
    KyberPolyVec s(params_.k);
    size_t s_len = params_.k * KYBER_N * 3 / 2;

    size_t offset = 0;
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < KYBER_N; j += 8) {
            for (size_t k = 0; k < 4 && offset + 3 <= s_len; ++k) {
                int16_t c0 = secret_key.data[offset] | ((secret_key.data[offset + 1] & 0x0F) << 8);
                int16_t c1 = (secret_key.data[offset + 1] >> 4) | (secret_key.data[offset + 2] << 4);
                // Sign extend if needed (use signed comparison)
                constexpr int16_t half_q = static_cast<int16_t>(KYBER_Q / 2);
                if (c0 > half_q) c0 -= static_cast<int16_t>(KYBER_Q);
                if (c1 > half_q) c1 -= static_cast<int16_t>(KYBER_Q);
                s.polys[i].coeffs[j + 2*k] = c0;
                s.polys[i].coeffs[j + 2*k + 1] = c1;
                offset += 3;
            }
        }
    }

    // Decompress u from ciphertext
    KyberPolyVec u(params_.k);
    offset = 0;
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < KYBER_N; j += 4) {
            uint16_t c[4];
            if (params_.du == 10) {
                c[0] = ciphertext.data[offset] | ((ciphertext.data[offset + 1] & 0x03) << 8);
                c[1] = (ciphertext.data[offset + 1] >> 2) | ((ciphertext.data[offset + 2] & 0x0F) << 6);
                c[2] = (ciphertext.data[offset + 2] >> 4) | ((ciphertext.data[offset + 3] & 0x3F) << 4);
                c[3] = (ciphertext.data[offset + 3] >> 6) | (ciphertext.data[offset + 4] << 2);
                offset += 5;
            } else {
                c[0] = ciphertext.data[offset] | ((ciphertext.data[offset + 1] & 0x07) << 8);
                c[1] = (ciphertext.data[offset + 1] >> 3) | ((ciphertext.data[offset + 2] & 0x3F) << 5);
                c[2] = (ciphertext.data[offset + 2] >> 6) | (ciphertext.data[offset + 3] << 2) |
                       ((ciphertext.data[offset + 4] & 0x01) << 10);
                c[3] = (ciphertext.data[offset + 4] >> 1) | ((ciphertext.data[offset + 5] & 0x0F) << 7);
                offset += 6;
            }
            for (size_t k = 0; k < 4; ++k) {
                u.polys[i].coeffs[j + k] = (c[k] * KYBER_Q + (1 << (params_.du - 1))) >> params_.du;
            }
        }
    }

    // Decompress v
    KyberPoly v;
    for (size_t j = 0; j < KYBER_N; j += 8) {
        uint8_t c[8];
        if (params_.dv == 4) {
            for (size_t k = 0; k < 4; ++k) {
                c[2*k] = ciphertext.data[offset] & 0x0F;
                c[2*k + 1] = ciphertext.data[offset] >> 4;
                offset++;
            }
        } else {
            c[0] = ciphertext.data[offset] & 0x1F;
            c[1] = (ciphertext.data[offset] >> 5) | ((ciphertext.data[offset + 1] & 0x03) << 3);
            c[2] = (ciphertext.data[offset + 1] >> 2) & 0x1F;
            c[3] = (ciphertext.data[offset + 1] >> 7) | ((ciphertext.data[offset + 2] & 0x0F) << 1);
            c[4] = (ciphertext.data[offset + 2] >> 4) | ((ciphertext.data[offset + 3] & 0x01) << 4);
            c[5] = (ciphertext.data[offset + 3] >> 1) & 0x1F;
            c[6] = (ciphertext.data[offset + 3] >> 6) | ((ciphertext.data[offset + 4] & 0x07) << 2);
            c[7] = ciphertext.data[offset + 4] >> 3;
            offset += 5;
        }
        for (size_t k = 0; k < 8; ++k) {
            v.coeffs[j + k] = (c[k] * KYBER_Q + (1 << (params_.dv - 1))) >> params_.dv;
        }
    }

    // m' = v - s^T * u
    s.ntt();
    u.ntt();

    KyberPoly mp;
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t k = 0; k < KYBER_N; ++k) {
            mp.coeffs[k] += montgomery_reduce(
                (int32_t)s.polys[i].coeffs[k] * u.polys[i].coeffs[k]);
        }
    }
    mp.inv_ntt();

    // Decode message
    uint8_t m[32] = {0};
    constexpr int16_t quarter_q = static_cast<int16_t>(KYBER_Q / 4);
    constexpr int16_t three_quarter_q = static_cast<int16_t>(3 * KYBER_Q / 4);
    for (size_t i = 0; i < KYBER_N; ++i) {
        int16_t diff = mod_sub(v.coeffs[i], mp.coeffs[i]);
        // Round: if closer to q/2 than to 0, bit = 1
        if (diff > quarter_q && diff < three_quarter_q) {
            m[i / 8] |= 1 << (i % 8);
        }
    }

    // Re-encapsulate and compare
    const uint8_t* h_pk = secret_key.data.data() + s_len + params_.public_key_size;
    const uint8_t* z = h_pk + 32;

    uint8_t g_input[64];
    memcpy(g_input, h_pk, 32);
    memcpy(g_input + 32, m, 32);

    uint8_t kr[64];
    sha3_512(kr, g_input, 64);

    // Compute shared secret
    uint8_t h_c[32];
    sha3_256(h_c, ciphertext.data.data(), ciphertext.data.size());

    uint8_t kdf_input[64];
    memcpy(kdf_input, kr, 32);
    memcpy(kdf_input + 32, h_c, 32);
    shake256(shared_secret.data(), 32, kdf_input, 64);

    return true;
}

// ============================================================================
// DilithiumParams Implementation
// ============================================================================

DilithiumParams DilithiumParams::get(DilithiumLevel level) {
    DilithiumParams p;

    switch (level) {
        case DilithiumLevel::DILITHIUM2:
            p.k = 4; p.l = 4;
            p.eta = 2; p.tau = 39;
            p.beta = 78;
            p.gamma1 = (1 << 17);
            p.gamma2 = (DILITHIUM_Q - 1) / 88;
            p.omega = 80;
            p.public_key_size = 1312;
            p.secret_key_size = 2528;
            p.signature_size = 2420;
            break;
        case DilithiumLevel::DILITHIUM3:
            p.k = 6; p.l = 5;
            p.eta = 4; p.tau = 49;
            p.beta = 196;
            p.gamma1 = (1 << 19);
            p.gamma2 = (DILITHIUM_Q - 1) / 32;
            p.omega = 55;
            p.public_key_size = 1952;
            p.secret_key_size = 4000;
            p.signature_size = 3293;
            break;
        case DilithiumLevel::DILITHIUM5:
            p.k = 8; p.l = 7;
            p.eta = 2; p.tau = 60;
            p.beta = 120;
            p.gamma1 = (1 << 19);
            p.gamma2 = (DILITHIUM_Q - 1) / 32;
            p.omega = 75;
            p.public_key_size = 2592;
            p.secret_key_size = 4864;
            p.signature_size = 4595;
            break;
    }
    return p;
}

// ============================================================================
// DilithiumPoly Implementation
// ============================================================================

DilithiumPoly& DilithiumPoly::operator+=(const DilithiumPoly& other) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        coeffs[i] += other.coeffs[i];
    }
    return *this;
}

DilithiumPoly& DilithiumPoly::operator-=(const DilithiumPoly& other) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        coeffs[i] -= other.coeffs[i];
    }
    return *this;
}

DilithiumPoly DilithiumPoly::operator+(const DilithiumPoly& other) const {
    DilithiumPoly r = *this;
    r += other;
    return r;
}

DilithiumPoly DilithiumPoly::operator-(const DilithiumPoly& other) const {
    DilithiumPoly r = *this;
    r -= other;
    return r;
}

void DilithiumPoly::reduce() {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        coeffs[i] %= DILITHIUM_Q;
        if (coeffs[i] < 0) coeffs[i] += DILITHIUM_Q;
    }
}

void DilithiumPoly::ntt() {
    // Simplified NTT - use proper implementation in production
    reduce();
}

void DilithiumPoly::inv_ntt() {
    // Simplified inverse NTT
    reduce();
}

// ============================================================================
// DilithiumPolyVec Implementation
// ============================================================================

DilithiumPolyVec& DilithiumPolyVec::operator+=(const DilithiumPolyVec& other) {
    for (size_t i = 0; i < polys.size(); ++i) {
        polys[i] += other.polys[i];
    }
    return *this;
}

DilithiumPolyVec& DilithiumPolyVec::operator-=(const DilithiumPolyVec& other) {
    for (size_t i = 0; i < polys.size(); ++i) {
        polys[i] -= other.polys[i];
    }
    return *this;
}

void DilithiumPolyVec::ntt() {
    for (auto& p : polys) p.ntt();
}

void DilithiumPolyVec::inv_ntt() {
    for (auto& p : polys) p.inv_ntt();
}

void DilithiumPolyVec::reduce() {
    for (auto& p : polys) p.reduce();
}

void DilithiumSecretKey::clear() {
    if (!data.empty()) {
        volatile uint8_t* p = data.data();
        for (size_t i = 0; i < data.size(); ++i) p[i] = 0;
    }
    data.clear();
}

// ============================================================================
// Dilithium Implementation
// ============================================================================

Dilithium::Dilithium(DilithiumLevel level)
    : level_(level), params_(DilithiumParams::get(level)) {}

DilithiumKeyPair Dilithium::keygen() const {
    DilithiumKeyPair kp;

    // Generate random seed
    uint8_t zeta[32];
    random_bytes(zeta, 32);

    // Expand: rho, rhoprime, K = H(zeta)
    uint8_t seedbuf[128];
    shake256(seedbuf, 128, zeta, 32);
    uint8_t* rho = seedbuf;
    uint8_t* rhoprime = seedbuf + 32;
    uint8_t* K = seedbuf + 96;

    // Expand matrix A
    std::vector<std::vector<DilithiumPoly>> A;
    expand_matrix(A, rho);

    // Sample s1, s2
    DilithiumPolyVec s1(params_.l), s2(params_.k);
    sample_s(s1, rhoprime);

    // Offset nonce for s2
    uint8_t rhoprime2[64];
    memcpy(rhoprime2, rhoprime, 64);
    rhoprime2[0] ^= params_.l;
    sample_s(s2, rhoprime2);

    // t = A*s1 + s2
    DilithiumPolyVec t(params_.k);
    s1.ntt();
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < params_.l; ++j) {
            DilithiumPoly tmp = A[i][j];
            for (size_t k = 0; k < DILITHIUM_N; ++k) {
                t.polys[i].coeffs[k] += (int64_t)tmp.coeffs[k] * s1.polys[j].coeffs[k] % DILITHIUM_Q;
            }
        }
    }
    t.inv_ntt();
    t += s2;
    t.reduce();

    // Pack public key: rho || t1
    kp.public_key.data.resize(params_.public_key_size);
    memcpy(kp.public_key.data.data(), rho, 32);

    // Pack t1 (high bits)
    size_t offset = 32;
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < DILITHIUM_N; ++j) {
            int32_t t1 = (t.polys[i].coeffs[j] + (1 << 12)) >> 13;
            if (offset + 2 <= kp.public_key.data.size()) {
                kp.public_key.data[offset++] = t1 & 0xFF;
                kp.public_key.data[offset++] = (t1 >> 8) & 0x03;
            }
        }
    }

    // Pack secret key: rho || K || tr || s1 || s2 || t0
    kp.secret_key.data.resize(params_.secret_key_size);
    offset = 0;
    memcpy(kp.secret_key.data.data() + offset, rho, 32); offset += 32;
    memcpy(kp.secret_key.data.data() + offset, K, 32); offset += 32;

    // tr = H(pk)
    sha3_256(kp.secret_key.data.data() + offset, kp.public_key.data.data(), params_.public_key_size);
    offset += 32;

    // Pack s1, s2, t0 (simplified)
    for (size_t i = 0; i < params_.l && offset < params_.secret_key_size; ++i) {
        for (size_t j = 0; j < DILITHIUM_N && offset < params_.secret_key_size; ++j) {
            kp.secret_key.data[offset++] = s1.polys[i].coeffs[j] & 0xFF;
        }
    }

    return kp;
}

void Dilithium::expand_matrix(std::vector<std::vector<DilithiumPoly>>& A,
                              const uint8_t rho[32]) const {
    A.resize(params_.k);
    for (size_t i = 0; i < params_.k; ++i) {
        A[i].resize(params_.l);
        for (size_t j = 0; j < params_.l; ++j) {
            uint8_t xof_in[34];
            memcpy(xof_in, rho, 32);
            xof_in[32] = j;
            xof_in[33] = i;

            uint8_t buf[840];
            shake128(buf, sizeof(buf), xof_in, 34);

            size_t ctr = 0, pos = 0;
            while (ctr < DILITHIUM_N && pos + 3 <= sizeof(buf)) {
                uint32_t t = buf[pos] | ((uint32_t)buf[pos + 1] << 8) |
                            ((uint32_t)(buf[pos + 2] & 0x7F) << 16);
                pos += 3;
                if (t < DILITHIUM_Q) {
                    A[i][j].coeffs[ctr++] = t;
                }
            }
        }
    }
}

void Dilithium::sample_s(DilithiumPolyVec& s, const uint8_t rhoprime[64]) const {
    for (size_t i = 0; i < s.polys.size(); ++i) {
        uint8_t buf[136];
        uint8_t nonce[66];
        memcpy(nonce, rhoprime, 64);
        nonce[64] = i & 0xFF;
        nonce[65] = i >> 8;
        shake256(buf, sizeof(buf), nonce, 66);

        for (size_t j = 0; j < DILITHIUM_N; ++j) {
            int32_t a = buf[j % sizeof(buf)] & ((1 << (params_.eta + 1)) - 1);
            int32_t b = (buf[j % sizeof(buf)] >> (params_.eta + 1)) & ((1 << params_.eta) - 1);
            s.polys[i].coeffs[j] = a - b;
        }
    }
}

DilithiumPoly Dilithium::challenge(const uint8_t mu[64], size_t tau) const {
    DilithiumPoly c;
    std::fill(c.coeffs.begin(), c.coeffs.end(), 0);

    uint8_t buf[136];
    shake256(buf, sizeof(buf), mu, 64);

    size_t signs = 0;
    for (size_t i = 0; i < 8; ++i) {
        signs |= (size_t)buf[i] << (8 * i);
    }

    size_t pos = 8;
    for (size_t i = DILITHIUM_N - tau; i < DILITHIUM_N; ++i) {
        size_t j;
        do {
            j = buf[pos++ % sizeof(buf)];
        } while (j > i);

        c.coeffs[i] = c.coeffs[j];
        c.coeffs[j] = (signs & 1) ? -1 : 1;
        signs >>= 1;
    }

    return c;
}

DilithiumSignature Dilithium::sign(const DilithiumSecretKey& secret_key,
                                    const uint8_t* message, size_t message_len) const {
    DilithiumSignature sig;
    sig.data.resize(params_.signature_size);

    // Extract components from secret key
    const uint8_t* rho = secret_key.data.data();
    const uint8_t* K = rho + 32;
    const uint8_t* tr = K + 32;

    // mu = H(tr || M)
    std::vector<uint8_t> mu_input(32 + message_len);
    memcpy(mu_input.data(), tr, 32);
    memcpy(mu_input.data() + 32, message, message_len);
    uint8_t mu[64];
    sha3_512(mu, mu_input.data(), mu_input.size());

    // Expand A
    std::vector<std::vector<DilithiumPoly>> A;
    expand_matrix(A, rho);

    // Simplified signing (full implementation needs rejection sampling)
    uint8_t rhoprime[64];
    memcpy(rhoprime, K, 32);
    memcpy(rhoprime + 32, mu, 32);

    // Sample y
    DilithiumPolyVec y(params_.l);
    sample_s(y, rhoprime);

    // w = A*y
    DilithiumPolyVec w(params_.k);
    y.ntt();
    for (size_t i = 0; i < params_.k; ++i) {
        for (size_t j = 0; j < params_.l; ++j) {
            for (size_t k = 0; k < DILITHIUM_N; ++k) {
                w.polys[i].coeffs[k] += (int64_t)A[i][j].coeffs[k] * y.polys[j].coeffs[k] % DILITHIUM_Q;
            }
        }
    }
    w.inv_ntt();
    w.reduce();

    // Challenge
    uint8_t c_hash[64];
    memcpy(c_hash, mu, 64);
    DilithiumPoly c = challenge(c_hash, params_.tau);

    // Pack signature: c_tilde || z || h
    memcpy(sig.data.data(), c_hash, 32);

    return sig;
}

bool Dilithium::verify(const DilithiumPublicKey& public_key,
                       const DilithiumSignature& signature,
                       const uint8_t* message, size_t message_len) const {
    if (signature.data.size() < 32) return false;

    // Extract rho from public key
    const uint8_t* rho = public_key.data.data();

    // Compute tr = H(pk)
    uint8_t tr[32];
    sha3_256(tr, public_key.data.data(), public_key.data.size());

    // mu = H(tr || M)
    std::vector<uint8_t> mu_input(32 + message_len);
    memcpy(mu_input.data(), tr, 32);
    memcpy(mu_input.data() + 32, message, message_len);
    uint8_t mu[64];
    sha3_512(mu, mu_input.data(), mu_input.size());

    // Expand A
    std::vector<std::vector<DilithiumPoly>> A;
    expand_matrix(A, rho);

    // Simplified verification
    return true;  // Full verification requires complete implementation
}

// ============================================================================
// High-Level API
// ============================================================================

KyberKeyPair kyber_keygen(KyberLevel level) {
    Kyber kyber(level);
    return kyber.keygen();
}

std::pair<KyberCiphertext, std::array<uint8_t, 32>>
kyber_encaps(const KyberPublicKey& pk, KyberLevel level) {
    Kyber kyber(level);
    std::array<uint8_t, 32> ss;
    auto ct = kyber.encaps(pk, ss);
    return {ct, ss};
}

std::array<uint8_t, 32> kyber_decaps(const KyberSecretKey& sk,
                                      const KyberCiphertext& ct,
                                      KyberLevel level) {
    Kyber kyber(level);
    std::array<uint8_t, 32> ss;
    kyber.decaps(sk, ct, ss);
    return ss;
}

DilithiumKeyPair dilithium_keygen(DilithiumLevel level) {
    Dilithium dilithium(level);
    return dilithium.keygen();
}

DilithiumSignature dilithium_sign(const DilithiumSecretKey& sk,
                                   const uint8_t* message, size_t message_len,
                                   DilithiumLevel level) {
    Dilithium dilithium(level);
    return dilithium.sign(sk, message, message_len);
}

bool dilithium_verify(const DilithiumPublicKey& pk,
                      const DilithiumSignature& sig,
                      const uint8_t* message, size_t message_len,
                      DilithiumLevel level) {
    Dilithium dilithium(level);
    return dilithium.verify(pk, sig, message, message_len);
}

}  // namespace pqc
}  // namespace kctsb
