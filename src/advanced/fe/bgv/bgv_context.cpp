/**
 * @file bgv_context.cpp
 * @brief BGV Context Implementation
 * 
 * Implements BGV parameter setup, key generation, encryption, and decryption.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/advanced/fe/bgv/bgv_context.hpp"
#include <cmath>
#include <algorithm>
#include <stdexcept>
#include <cstring>

namespace kctsb {
namespace fhe {
namespace bgv {

// ============================================================================
// BGVParams Implementation
// ============================================================================

uint64_t BGVParams::slot_count() const {
    // For prime m, slot_count = (m-1) / ord_t(m)
    // where ord_t(m) is the multiplicative order of t mod m
    // Simplified: if t = 1 mod m, slot_count = φ(m) = n
    
    if (m == 0 || t == 0) return 0;
    
    // Compute ord_t(m) - the order of t in (Z/mZ)*
    uint64_t order = 1;
    uint64_t pow_t = t % m;
    while (pow_t != 1 && order < m) {
        pow_t = (pow_t * t) % m;
        order++;
    }
    
    return n / order;
}

double BGVParams::initial_noise_budget() const {
    // Noise budget = log2(q) - log2(B_init)
    // where B_init depends on key distribution and encryption randomness
    if (IsZero(q)) return 0;
    
    double log_q = log(q) / std::log(2.0);
    double log_B = std::log2(n) + std::log2(sigma) + 3;  // Conservative estimate
    
    return log_q - log_B;
}

bool BGVParams::validate() const {
    // Basic validation
    if (m == 0 || n == 0) return false;
    if (IsZero(q)) return false;
    // Check t is positive and reasonable (skip strict comparison to avoid overflow)
    if (t == 0) return false;
    if (L == 0) return false;
    if (sigma <= 0) return false;
    
    // n should be φ(m)
    // For power-of-2 m: φ(m) = m/2
    // For prime m: φ(m) = m-1
    
    // Check RNS primes if provided
    if (!primes.empty()) {
        ZZ product = conv<ZZ>(1);
        for (uint64_t p : primes) {
            product *= p;
        }
        // Product of primes should match q
        // (allowing for special modulus)
    }
    
    return true;
}

BGVParams BGVParams::create_standard(SecurityLevel security, 
                                      uint32_t mult_depth,
                                      uint64_t t_value) {
    BGVParams params;
    params.t = t_value;
    params.sigma = 3.2;
    params.security = security;
    params.L = mult_depth + 1;  // L primes for depth mult_depth
    
    // Parameter selection based on security level and depth
    // These follow HElib/SEAL standard parameter choices
    
    switch (security) {
        case SecurityLevel::NONE:
            // Toy parameters for testing (INSECURE!)
            params.m = 4096;
            params.n = 2048;
            params.primes = {40961, 65537};  // Small primes
            break;
            
        case SecurityLevel::CLASSICAL_128:
            // 128-bit security
            if (mult_depth <= 3) {
                params.m = 8192;
                params.n = 4096;
            } else if (mult_depth <= 5) {
                params.m = 16384;
                params.n = 8192;
            } else {
                params.m = 32768;
                params.n = 16384;
            }
            break;
            
        case SecurityLevel::CLASSICAL_192:
            // 192-bit security
            if (mult_depth <= 3) {
                params.m = 16384;
                params.n = 8192;
            } else {
                params.m = 32768;
                params.n = 16384;
            }
            break;
            
        case SecurityLevel::CLASSICAL_256:
        case SecurityLevel::QUANTUM_128:
        case SecurityLevel::QUANTUM_192:
        case SecurityLevel::QUANTUM_256:
            // Conservative for quantum security
            params.m = 32768;
            params.n = 16384;
            break;
    }
    
    // Generate NTT-friendly primes: q_i = 1 (mod 2n)
    // Each prime ~60 bits for efficient modular arithmetic
    params.primes.clear();
    uint64_t prime_bits = 60;
    uint64_t candidate = (1ULL << prime_bits) - (1ULL << prime_bits) % (2 * params.n) + 1;
    
    for (uint32_t i = 0; i < params.L && params.primes.size() < params.L; i++) {
        // Find next prime = 1 mod 2n
        while (!ProbPrime(to_ZZ(candidate))) {
            candidate += 2 * params.n;
        }
        params.primes.push_back(candidate);
        candidate += 2 * params.n;
    }
    
    // Compute q = product of primes
    params.q = conv<ZZ>(1);
    for (uint64_t p : params.primes) {
        params.q *= p;
    }
    
    return params;
}

// ============================================================================
// Standard Parameter Sets
// ============================================================================

namespace StandardParams {

BGVParams TOY_PARAMS() {
    BGVParams params;
    params.m = 512;
    params.n = 256;  // φ(512) = 256 for power-of-2
    params.t = 257;  // Small prime plaintext modulus
    params.L = 3;    // Three levels for two multiplications (power(3) support)
    params.sigma = 3.2;
    params.security = SecurityLevel::NONE;
    
    // For multiplication support, we need q large enough that:
    // After 2 multiplications + 2 relinearizations, noise ≈ n^2 * t^2 * B^4
    // With n=256, t=257, B~10: need q > 2^60 for two multiplications
    // 
    // Use product of FOUR NTT-friendly primes (= 1 mod 2n = 1 mod 512):
    // - 786433 = 1 + 3*2^18 ≈ 2^20
    // - 65537 = 1 + 128*512 ≈ 2^16 (Fermat prime)
    // - 40961 = 1 + 80*512 ≈ 2^16  
    // - 12289 = 1 + 24*512 ≈ 2^14
    // - Product ≈ 2^66, sufficient for two multiplications with margin
    //
    // Primes ordered from largest to smallest for modulus switching
    params.primes = {786433, 65537, 40961, 12289};
    params.q = conv<ZZ>(786433) * conv<ZZ>(65537) * conv<ZZ>(40961) * conv<ZZ>(12289);
    
    return params;
}

BGVParams SECURITY_128_DEPTH_3() {
    return BGVParams::create_standard(SecurityLevel::CLASSICAL_128, 3, 65537);
}

BGVParams SECURITY_128_DEPTH_5() {
    return BGVParams::create_standard(SecurityLevel::CLASSICAL_128, 5, 65537);
}

BGVParams SECURITY_192_DEPTH_5() {
    return BGVParams::create_standard(SecurityLevel::CLASSICAL_192, 5, 65537);
}

}  // namespace StandardParams

// ============================================================================
// RingElement Implementation
// ============================================================================

RingElement::RingElement(const ZZ_pX& poly) : poly_(poly), is_ntt_(false) {}

ZZ_p RingElement::coeff(long i) const {
    if (i < 0 || i > deg(poly_)) {
        return ZZ_p::zero();
    }
    return kctsb::coeff(poly_, i);
}

void RingElement::set_coeff(long i, const ZZ_p& val) {
    SetCoeff(poly_, i, val);
}

long RingElement::degree() const {
    return deg(poly_);
}

RingElement RingElement::operator+(const RingElement& other) const {
    RingElement result;
    result.poly_ = poly_ + other.poly_;
    return result;
}

RingElement RingElement::operator-(const RingElement& other) const {
    RingElement result;
    result.poly_ = poly_ - other.poly_;
    return result;
}

RingElement RingElement::operator*(const RingElement& other) const {
    // Note: This does NOT reduce by Φ_m(X) automatically
    // The caller must handle reduction in the quotient ring
    RingElement result;
    
    // Use PlainMul (classical algorithm) to avoid FFT precision issues
    // with large moduli. FFT requires the modulus to be small enough
    // for floating-point precision, which is not the case for FHE.
    PlainMul(result.poly_, poly_, other.poly_);
    
    return result;
}

RingElement RingElement::operator-() const {
    RingElement result;
    result.poly_ = -poly_;
    return result;
}

RingElement& RingElement::operator+=(const RingElement& other) {
    poly_ += other.poly_;
    return *this;
}

RingElement& RingElement::operator-=(const RingElement& other) {
    poly_ -= other.poly_;
    return *this;
}

RingElement& RingElement::operator*=(const RingElement& other) {
    poly_ *= other.poly_;
    return *this;
}

RingElement RingElement::operator*(const ZZ_p& scalar) const {
    RingElement result;
    result.poly_ = poly_ * scalar;
    return result;
}

RingElement& RingElement::operator*=(const ZZ_p& scalar) {
    poly_ *= scalar;
    return *this;
}

bool RingElement::operator==(const RingElement& other) const {
    return poly_ == other.poly_;
}

bool RingElement::is_zero() const {
    return IsZero(poly_);
}

void RingElement::clear() {
    kctsb::clear(poly_);
    is_ntt_ = false;
}

RingElement RingElement::reduce_mod(const ZZ& new_mod) const {
    // Change modulus: coefficient-wise reduction
    ZZ_pPush push;  // Save current modulus
    ZZ_p::init(new_mod);
    
    RingElement result;
    for (long i = 0; i <= degree(); i++) {
        ZZ coef = rep(coeff(i));
        SetCoeff(result.poly_, i, conv<ZZ_p>(coef));
    }
    return result;
}

void RingElement::to_ntt() {
    if (is_ntt_) return;
    // TODO: Implement NTT transform
    // For now, we use schoolbook multiplication
    is_ntt_ = true;
}

void RingElement::from_ntt() {
    if (!is_ntt_) return;
    // TODO: Implement inverse NTT
    is_ntt_ = false;
}

// ============================================================================
// BGVCiphertext Implementation
// ============================================================================

void BGVCiphertext::push_back(const RingElement& elem) {
    polys_.push_back(elem);
}

void BGVCiphertext::push_back(RingElement&& elem) {
    polys_.push_back(std::move(elem));
}

std::vector<uint8_t> BGVCiphertext::serialize() const {
    // TODO: Implement proper serialization
    std::vector<uint8_t> data;
    // Placeholder
    return data;
}

BGVCiphertext BGVCiphertext::deserialize(const std::vector<uint8_t>& data) {
    // TODO: Implement proper deserialization
    BGVCiphertext ct;
    return ct;
}

size_t BGVCiphertext::byte_size() const {
    // Estimate: each polynomial has n coefficients of ~log2(q) bits
    // This is a rough approximation
    size_t coef_bits = 64 * polys_.size();  // Simplified
    return (coef_bits + 7) / 8;
}

// ============================================================================
// BGVSecretKey Implementation
// ============================================================================

const RingElement& BGVSecretKey::power(size_t k) const {
    if (k == 0) {
        // Return 1 (constant polynomial)
        static RingElement one;
        // TODO: Initialize to 1
        return one;
    }
    if (k == 1) {
        return s_;
    }
    
    // Compute s^k if not cached
    while (powers_.size() < k) {
        if (powers_.empty()) {
            powers_.push_back(s_);  // s^1
        }
        RingElement next = powers_.back() * s_;
        powers_.push_back(next);
    }
    
    return powers_[k - 1];
}

long BGVSecretKey::degree() const {
    // Return the polynomial degree from stored coefficients
    // Find the highest non-zero coefficient
    if (coeffs_.empty()) {
        return -1;  // Zero polynomial
    }
    
    for (long i = static_cast<long>(coeffs_.size()) - 1; i >= 0; i--) {
        if (coeffs_[static_cast<size_t>(i)] != 0) {
            return i;
        }
    }
    return -1;  // Zero polynomial
}

std::vector<uint8_t> BGVSecretKey::serialize() const {
    // WARNING: Serializing secret keys is security-sensitive
    // TODO: Implement with encryption
    return {};
}

BGVSecretKey BGVSecretKey::deserialize(const std::vector<uint8_t>& data) {
    BGVSecretKey sk;
    // TODO: Implement
    return sk;
}

BGVSecretKey::~BGVSecretKey() {
    // Secure cleanup: zero the secret polynomial
    s_.clear();
    powers_.clear();
}

// ============================================================================
// BGVPublicKey Implementation
// ============================================================================

std::vector<uint8_t> BGVPublicKey::serialize() const {
    // TODO: Implement
    return {};
}

BGVPublicKey BGVPublicKey::deserialize(const std::vector<uint8_t>& data) {
    BGVPublicKey pk;
    // TODO: Implement
    return pk;
}

size_t BGVPublicKey::byte_size() const {
    // Two polynomials
    return 0;  // TODO
}

// ============================================================================
// BGVContext Implementation
// ============================================================================

BGVContext::BGVContext(const BGVParams& params) 
    : params_(params) {
    
    if (!params_.validate()) {
        throw std::invalid_argument("Invalid BGV parameters");
    }
    
    // Seed RNG
    std::random_device rd;
    rng_.seed(rd());
    
    // Initialize polynomial ring
    initialize_ring();
    
    // Initialize modulus levels
    initialize_levels();
}

BGVContext::~BGVContext() {
    // Cleanup
}

BGVContext::BGVContext(BGVContext&& other) noexcept = default;
BGVContext& BGVContext::operator=(BGVContext&& other) noexcept = default;

void BGVContext::initialize_ring() {
    // Set up the polynomial ring R_q = Z_q[X]/(Φ_m(X))
    ZZ_p::init(params_.q);
    
    // Compute cyclotomic polynomial Φ_m(X)
    cyclotomic_ = compute_cyclotomic(params_.m);
}

void BGVContext::initialize_levels() {
    // For each level, set up the modulus and reduction polynomial
    levels_.resize(params_.L);
    
    ZZ q_current = params_.q;
    
    for (uint32_t i = 0; i < params_.L; i++) {
        levels_[i].q = q_current;
        
        // Compute Φ_m(X) mod q_current
        ZZ_pPush push;
        ZZ_p::init(q_current);
        levels_[i].cyclotomic = compute_cyclotomic(params_.m);
        
        // For next level, divide by one prime
        if (i < params_.primes.size()) {
            q_current /= params_.primes[i];
        }
    }
}

ZZ_pX BGVContext::compute_cyclotomic(uint64_t m) {
    // Compute the m-th cyclotomic polynomial Φ_m(X)
    // Φ_m(X) = ∏_{d|m} (X^{m/d} - 1)^{μ(d)}
    
    // For power-of-2 m: Φ_m(X) = X^{m/2} + 1
    if ((m & (m - 1)) == 0) {  // m is power of 2
        ZZ_pX phi;
        SetCoeff(phi, 0, conv<ZZ_p>(1));
        SetCoeff(phi, m / 2, conv<ZZ_p>(1));
        return phi;
    }
    
    // For prime m: Φ_m(X) = 1 + X + X^2 + ... + X^{m-1}
    if (ProbPrime(to_ZZ(m))) {
        ZZ_pX phi;
        for (uint64_t i = 0; i < m; i++) {
            SetCoeff(phi, i, conv<ZZ_p>(1));
        }
        return phi;
    }
    
    // General case: use NTL's CyclotomicPoly or compute via Möbius function
    // Simplified: assume m is a power of 2 for now
    ZZ_pX phi;
    SetCoeff(phi, 0, conv<ZZ_p>(1));
    SetCoeff(phi, params_.n, conv<ZZ_p>(1));
    return phi;
}

ZZ BGVContext::ciphertext_modulus(uint32_t level) const {
    if (level >= levels_.size()) {
        return levels_.back().q;
    }
    return levels_[level].q;
}

// ============================================================================
// Key Generation
// ============================================================================

BGVSecretKey BGVContext::generate_secret_key() {
    BGVSecretKey sk;
    
    // CRITICAL: Set modulus to q for key generation
    ZZ_p::init(params_.q);
    
    // Generate ternary secret key s ∈ {-1, 0, 1}^n
    sk.s_ = sample_ternary(params_.hamming_weight);
    
    // CRITICAL: Store coefficients as ZZ to avoid modulus dependency
    // This allows consistent key access across different modulus contexts
    sk.coeffs_.resize(params_.n);
    for (size_t i = 0; i < params_.n; i++) {
        ZZ coef = rep(sk.s_.coeff(static_cast<long>(i)));
        // Convert to centered representation: if coef > q/2, it's negative
        if (coef > params_.q / 2) {
            sk.coeffs_[i] = coef - params_.q;  // Makes it negative
        } else {
            sk.coeffs_[i] = coef;
        }
    }
    
    return sk;
}

BGVPublicKey BGVContext::generate_public_key(const BGVSecretKey& sk) {
    BGVPublicKey pk;
    
    // CRITICAL: Set modulus to q for key generation
    ZZ_p::init(params_.q);
    
    // Convert secret key from stored ZZ coefficients to ZZ_pX
    // This is modulus-safe because we use the ZZ coefficients directly
    ZZ_pX sk_q;
    long sk_degree = sk.degree();
    for (long j = 0; j <= sk_degree; j++) {
        ZZ coef = sk.coefficients()[static_cast<size_t>(j)];
        if (coef < 0) {
            coef += params_.q;  // Convert negative to positive mod q
        }
        SetCoeff(sk_q, j, conv<ZZ_p>(coef));
    }
    
    // Sample uniform a ∈ R_q
    pk.a_ = sample_uniform();
    
    // Sample error e ∈ χ
    RingElement e = sample_error();
    
    // Compute b = -a*s + t*e (mod Φ_m(X))
    ZZ_pX as;
    PlainMul(as, pk.a_.poly(), sk_q);
    PlainRem(as, as, cyclotomic_);
    
    ZZ_pX te = e.poly() * conv<ZZ_p>(static_cast<long>(params_.t));
    
    pk.b_.poly() = -as + te;
    
    // Reduce mod Φ_m(X)
    PlainRem(pk.b_.poly(), pk.b_.poly(), cyclotomic_);
    
    return pk;
}

BGVRelinKey BGVContext::generate_relin_key(const BGVSecretKey& sk) {
    BGVRelinKey rk;
    
    // CRITICAL: Set modulus to q for relin key generation
    ZZ_p::init(params_.q);
    
    // Convert secret key from stored ZZ coefficients to ZZ_pX
    // This is modulus-safe because we use the ZZ coefficients directly
    ZZ_pX sk_q;
    long sk_degree = sk.degree();
    for (long j = 0; j <= sk_degree; j++) {
        ZZ coef = sk.coefficients()[static_cast<size_t>(j)];
        if (coef < 0) {
            coef += params_.q;  // Convert negative to positive mod q
        }
        SetCoeff(sk_q, j, conv<ZZ_p>(coef));
    }
    RingElement s_ring;
    s_ring.poly() = sk_q;
    
    // Relinearization key: encryptions of s^2 under key s
    // Using digit decomposition with base w
    
    const size_t num_digits = 3;  // Number of decomposition digits
    
    // CRITICAL: Calculate base dynamically - MUST match decompose() in evaluator!
    double log_q = kctsb::log(params_.q) / std::log(2.0);
    size_t base_bits = static_cast<size_t>(std::ceil(log_q / num_digits));
    ZZ base = kctsb::power(to_ZZ(2), static_cast<long>(base_bits));
    
    RingElement s2 = s_ring * s_ring;
    PlainRem(s2.poly(), s2.poly(), cyclotomic_);
    
    for (size_t i = 0; i < num_digits; i++) {
        // Sample a_i uniformly
        RingElement a = sample_uniform();
        
        // Sample error e_i
        RingElement e = sample_error();
        
        // Compute b_i = -a_i*s + t*e_i + base^i * s^2
        RingElement as = a * s_ring;
        PlainRem(as.poly(), as.poly(), cyclotomic_);
        
        ZZ_pX te = e.poly() * conv<ZZ_p>(static_cast<long>(params_.t));
        
        // base^i * s^2
        ZZ_p scale = conv<ZZ_p>(kctsb::power(base, i));
        RingElement scaled_s2 = s2 * scale;
        
        RingElement b;
        b.poly() = -as.poly() + te + scaled_s2.poly();
        PlainRem(b.poly(), b.poly(), cyclotomic_);
        
        rk.key_components_.push_back({b, a});
    }
    
    return rk;
}

BGVGaloisKey BGVContext::generate_galois_keys(const BGVSecretKey& sk,
                                               const std::vector<int>& steps) {
    BGVGaloisKey gk;
    
    // Generate keys for specified rotations
    // For rotation by k slots, need automorphism σ: X -> X^{5^k mod m}
    
    std::vector<int> rotation_steps = steps;
    if (rotation_steps.empty()) {
        // Generate for all rotations
        for (uint64_t i = 1; i < slot_count(); i *= 2) {
            rotation_steps.push_back(static_cast<int>(i));
            rotation_steps.push_back(-static_cast<int>(i));
        }
    }
    
    for (int step : rotation_steps) {
        // Compute Galois element for this rotation
        // For power-of-2 m, Galois element = 5^step mod m or 5^{-step} mod m
        uint64_t galois_elt = 1;
        uint64_t base = 5;
        uint64_t exp = (step > 0) ? static_cast<uint64_t>(step) 
                                  : static_cast<uint64_t>(-step);
        
        for (uint64_t i = 0; i < exp; i++) {
            galois_elt = (galois_elt * base) % params_.m;
        }
        if (step < 0) {
            // Compute inverse
            // galois_elt = modular inverse of current value
        }
        
        // Generate key for this Galois element
        // Key switches from σ(s) to s
        
        // Apply automorphism to s: s(X) -> s(X^{galois_elt})
        RingElement sigma_s;
        for (long i = 0; i <= sk.s_.degree(); i++) {
            long new_idx = (i * galois_elt) % params_.n;
            sigma_s.set_coeff(new_idx, sk.s_.coeff(i));
        }
        
        // Generate key switching key from sigma_s to s
        std::vector<std::pair<RingElement, RingElement>> key;
        
        const size_t num_digits = 3;
        ZZ base_decomp = kctsb::power(to_ZZ(2), 60);
        
        for (size_t d = 0; d < num_digits; d++) {
            RingElement a = sample_uniform();
            RingElement e = sample_error();
            
            RingElement as = a * sk.s_;
            PlainRem(as.poly(), as.poly(), cyclotomic_);
            
            ZZ_pX te = e.poly() * conv<ZZ_p>(static_cast<long>(params_.t));
            
            ZZ_p scale = conv<ZZ_p>(power(base_decomp, d));
            RingElement scaled = sigma_s * scale;
            
            RingElement b;
            b.poly() = -as.poly() + te + scaled.poly();
            PlainRem(b.poly(), b.poly(), cyclotomic_);
            
            key.push_back({b, a});
        }
        
        gk.keys_[galois_elt] = key;
    }
    
    return gk;
}

// ============================================================================
// Encryption/Decryption
// ============================================================================

BGVCiphertext BGVContext::encrypt(const BGVPublicKey& pk, 
                                   const BGVPlaintext& pt) {
    BGVCiphertext ct;
    
    // CRITICAL: Set modulus to q before encryption operations
    ZZ_p::init(params_.q);
    
    // Convert plaintext polynomial coefficients to mod q representation
    // The plaintext was encoded mod t, but we need it as ZZ_p mod q
    ZZ_pX pt_in_q;
    for (long i = 0; i <= pt.data().degree(); i++) {
        ZZ coef = rep(pt.data().coeff(i));  // Get raw ZZ value
        SetCoeff(pt_in_q, i, conv<ZZ_p>(coef));  // Convert to mod q
    }
    
    // Sample random u ∈ {-1, 0, 1}^n
    RingElement u = sample_ternary();
    
    // Sample errors e_0, e_1 ∈ χ
    RingElement e0 = sample_error();
    RingElement e1 = sample_error();
    
    // Convert public key polynomials to current modulus context
    // The public key was generated under mod q, but NTL ZZ_pX stores
    // context-dependent representations that need re-conversion
    ZZ_pX pk_b_q;
    for (long j = 0; j <= pk.b_.degree(); j++) {
        ZZ coef = rep(pk.b_.coeff(j));
        SetCoeff(pk_b_q, j, conv<ZZ_p>(coef));
    }
    
    ZZ_pX pk_a_q;
    for (long j = 0; j <= pk.a_.degree(); j++) {
        ZZ coef = rep(pk.a_.coeff(j));
        SetCoeff(pk_a_q, j, conv<ZZ_p>(coef));
    }
    
    // c_0 = b*u + t*e_0 + m (mod Φ_m(X))
    RingElement c0;
    ZZ_pX bu;
    PlainMul(bu, pk_b_q, u.poly());
    PlainRem(bu, bu, cyclotomic_);
    
    ZZ_pX te0 = e0.poly() * conv<ZZ_p>(static_cast<long>(params_.t));
    
    c0.poly() = bu + te0 + pt_in_q;
    PlainRem(c0.poly(), c0.poly(), cyclotomic_);
    
    // c_1 = a*u + t*e_1 (mod Φ_m(X))
    RingElement c1;
    ZZ_pX au;
    PlainMul(au, pk_a_q, u.poly());
    PlainRem(au, au, cyclotomic_);
    
    ZZ_pX te1 = e1.poly() * conv<ZZ_p>(static_cast<long>(params_.t));
    
    c1.poly() = au + te1;
    PlainRem(c1.poly(), c1.poly(), cyclotomic_);
    
    ct.push_back(c0);
    ct.push_back(c1);
    ct.set_level(0);
    ct.set_noise_budget(params_.initial_noise_budget());
    
    return ct;
}

BGVPlaintext BGVContext::decrypt(const BGVSecretKey& sk, 
                                  const BGVCiphertext& ct) {
    if (ct.size() < 2) {
        throw std::invalid_argument("Invalid ciphertext size");
    }
    
    // CRITICAL: Set modulus to q before decryption operations
    // All ring operations must be performed mod q
    ZZ_p::init(params_.q);
    
    // Convert secret key from stored ZZ coefficients to ZZ_pX
    // This is modulus-safe because we use the ZZ coefficients directly
    ZZ_pX s_q;
    long sk_degree = sk.degree();
    for (long j = 0; j <= sk_degree; j++) {
        ZZ coef = sk.coefficients()[static_cast<size_t>(j)];
        if (coef < 0) {
            coef += params_.q;  // Convert negative to positive mod q
        }
        SetCoeff(s_q, j, conv<ZZ_p>(coef));
    }
    
    // Compute m = c_0 + c_1*s + c_2*s^2 + ... (mod Φ_m(X), mod q)
    // Using Horner's method: result = c[n-1], then result = result*s + c[i] for i = n-2..0
    ZZ_pX result;
    
    // Start from the highest component
    for (long k = static_cast<long>(ct.size()) - 1; k >= 0; k--) {
        // Convert c[k] to current modulus
        ZZ_pX ck_q;
        for (long j = 0; j <= ct[static_cast<size_t>(k)].degree(); j++) {
            ZZ coef = rep(ct[static_cast<size_t>(k)].coeff(j));
            SetCoeff(ck_q, j, conv<ZZ_p>(coef));
        }
        
        if (k == static_cast<long>(ct.size()) - 1) {
            // Initialize with highest component
            result = ck_q;
        } else {
            // result = result * s + c[k]
            ZZ_pX temp;
            PlainMul(temp, result, s_q);
            PlainRem(temp, temp, cyclotomic_);
            result = temp + ck_q;
            PlainRem(result, result, cyclotomic_);
        }
    }
    
    // Reduce coefficients mod t with proper centered representation
    // BGV requires: first interpret coefficients in centered range [-q/2, q/2)
    // then reduce mod t
    BGVPlaintext pt;
    ZZ t = to_ZZ(static_cast<unsigned long>(params_.t));
    ZZ t_half = t / 2;
    ZZ q = params_.q;
    ZZ q_half = q / 2;
    
    for (long i = 0; i <= deg(result); i++) {
        ZZ coef = rep(coeff(result, i));  // In range [0, q-1]
        
        // CRITICAL: Convert to centered representation [-q/2, q/2) FIRST
        // This is essential for correct BGV decryption!
        if (coef > q_half) {
            coef -= q;  // Now in range [-q/2, 0)
        }
        // Now coef is in range (-q/2, q/2]
        
        // Now reduce mod t with proper handling of negative numbers
        // C++ % can return negative for negative inputs, so we need to handle this
        ZZ coef_mod_t = coef % t;
        if (coef_mod_t < 0) {
            coef_mod_t += t;  // Ensure positive representative
        }
        
        // Centered reduction for mod t: if coef_mod_t > t/2, subtract t
        if (coef_mod_t > t_half) {
            coef_mod_t -= t;
        }
        
        // Convert back to positive representative for storage
        if (coef_mod_t < 0) {
            coef_mod_t += t;
        }
        
        ZZ_pPush push;
        ZZ_p::init(t);
        SetCoeff(pt.data().poly(), i, conv<ZZ_p>(coef_mod_t));
    }
    
    return pt;
}

BGVCiphertext BGVContext::encrypt_symmetric(const BGVSecretKey& sk,
                                             const BGVPlaintext& pt) {
    BGVCiphertext ct;
    
    // CRITICAL: Set modulus to q for encryption
    ZZ_p::init(params_.q);
    
    // Convert plaintext polynomial coefficients to mod q representation
    ZZ_pX pt_in_q;
    for (long i = 0; i <= pt.data().degree(); i++) {
        ZZ coef = rep(pt.data().coeff(i));
        SetCoeff(pt_in_q, i, conv<ZZ_p>(coef));
    }
    
    // Sample uniform a ∈ R_q
    RingElement a = sample_uniform();
    
    // Sample error e ∈ χ
    RingElement e = sample_error();
    
    // c_0 = -a*s + t*e + m (mod Φ_m(X))
    RingElement c0;
    RingElement as = a * sk.s_;
    PlainRem(as.poly(), as.poly(), cyclotomic_);
    
    ZZ_pX te = e.poly() * conv<ZZ_p>(static_cast<long>(params_.t));
    
    c0.poly() = -as.poly() + te + pt_in_q;
    PlainRem(c0.poly(), c0.poly(), cyclotomic_);
    
    // c_1 = a
    ct.push_back(c0);
    ct.push_back(a);
    ct.set_level(0);
    ct.set_noise_budget(params_.initial_noise_budget());
    
    return ct;
}

BGVCiphertext BGVContext::encrypt_zero(const BGVPublicKey& pk) {
    // Encrypt the zero polynomial
    BGVPlaintext zero;
    zero.data().clear();
    return encrypt(pk, zero);
}

// ============================================================================
// Noise Management
// ============================================================================

double BGVContext::noise_budget(const BGVSecretKey& sk, 
                                 const BGVCiphertext& ct) {
    // Compute actual noise and return bits of remaining budget
    //
    // SOLUTION: Use pure ZZ arithmetic to avoid NTL's ZZ_p FFT limitations.
    // This is slower but avoids "modulus too big" errors for large q.
    //
    // CRITICAL: Before accessing ZZ_p coefficients, we must ensure the
    // global NTL modulus matches the ciphertext's modulus.
    
    const auto& coeffs = sk.coefficients();
    if (coeffs.empty()) {
        // Cannot compute without coefficients
        return params_.initial_noise_budget();
    }
    
    size_t n = params_.n;
    ZZ q = params_.q;
    
    // CRITICAL FIX: Set NTL modulus to match our ciphertext before extracting coefficients.
    // The ciphertext polynomials are ZZ_pX, and rep() requires the correct modulus context.
    // We use ZZ_pBak to save/restore the previous modulus (avoids FFT reinitialization issues).
    ZZ_pBak modulus_backup;
    modulus_backup.save();
    
    // Use raw modulus setting without triggering FFT table rebuild
    // This sets the modulus for coefficient extraction only
    ZZ_pContext ctx(q);
    ctx.restore();
    
    // Extract ciphertext components as ZZ polynomials
    // ct = (c0, c1, c2, ...)
    // Decrypt: raw = c0 + c1*s + c2*s^2 + ...
    
    // Initialize raw polynomial as ZZ vector (coefficients in [0, q))
    std::vector<ZZ> raw(n);
    
    // Get c0 coefficients
    for (size_t i = 0; i < n; i++) {
        if (static_cast<long>(i) <= ct[0].degree()) {
            raw[i] = rep(ct[0].coeff(static_cast<long>(i)));
        } else {
            raw[i] = conv<ZZ>(0);
        }
    }
    
    // For each additional ciphertext component, add c_j * s^j
    // Use iterative s^j computation: s^1, s^2, ...
    std::vector<ZZ> s_power(n);  // Current s^j
    
    // Initialize s^1 from sk.coefficients()
    for (size_t i = 0; i < n; i++) {
        ZZ coef = coeffs[i];
        if (coef < 0) coef += q;
        s_power[i] = coef;
    }
    
    // Add c1 * s^1, c2 * s^2, ...
    for (size_t j = 1; j < ct.size(); j++) {
        // Multiply ct[j] by s_power (current s^j), add to raw
        // poly_mult(ct[j], s_power) mod (X^n + 1) mod q
        
        std::vector<ZZ> c_j(n);
        for (size_t i = 0; i < n; i++) {
            if (static_cast<long>(i) <= ct[j].degree()) {
                c_j[i] = rep(ct[j].coeff(static_cast<long>(i)));
            } else {
                c_j[i] = conv<ZZ>(0);
            }
        }
        
        // Schoolbook multiplication with negacyclic reduction
        std::vector<ZZ> product(n);
        for (size_t i = 0; i < n; i++) {
            for (size_t k = 0; k < n; k++) {
                size_t idx = i + k;
                ZZ term = c_j[i] * s_power[k];
                if (idx < n) {
                    product[idx] += term;
                } else {
                    // X^n = -1 mod (X^n + 1)
                    product[idx - n] -= term;
                }
            }
        }
        
        // Reduce mod q and add to raw
        for (size_t i = 0; i < n; i++) {
            product[i] = product[i] % q;
            if (product[i] < 0) product[i] += q;
            raw[i] = (raw[i] + product[i]) % q;
        }
        
        // Update s_power to s^(j+1) for next iteration
        if (j + 1 < ct.size()) {
            std::vector<ZZ> new_s_power(n);
            // s_power = s_power * s mod (X^n + 1) mod q
            for (size_t i = 0; i < n; i++) {
                ZZ s_i = coeffs[i];
                if (s_i < 0) s_i += q;
                for (size_t k = 0; k < n; k++) {
                    size_t idx = i + k;
                    ZZ term = s_power[k] * s_i;
                    if (idx < n) {
                        new_s_power[idx] += term;
                    } else {
                        new_s_power[idx - n] -= term;
                    }
                }
            }
            for (size_t i = 0; i < n; i++) {
                s_power[i] = new_s_power[i] % q;
                if (s_power[i] < 0) s_power[i] += q;
            }
        }
    }
    
    // Estimate noise from decrypted polynomial.
    // In BGV, the decrypted value is: m + t*e (mod q)
    // where m is the message and e is the noise.
    // The noise is approximately (decrypted - m) / t, but we can also
    // estimate it by looking at the high-order bits of decrypted.
    //
    // More directly: the noise budget is related to how far the decrypted
    // coefficients are from being exact multiples of t.
    //
    // For each coefficient: let r = raw[i] in centered form [-q/2, q/2]
    // The noise contribution is the distance to the nearest t-multiple.
    ZZ max_noise = conv<ZZ>(0);
    ZZ t_modulus = to_ZZ(static_cast<unsigned long>(params_.t));
    ZZ t_half = t_modulus / 2;
    ZZ q_half = q / 2;
    
    for (size_t i = 0; i < n; i++) {
        // Convert to centered representation
        ZZ centered = raw[i];
        if (centered > q_half) {
            centered = centered - q;
        }
        
        // The "noise" is approximately |centered - t * round(centered / t)|
        // which is the distance to the nearest t-multiple.
        // A simpler estimate: |centered mod t| in centered form
        ZZ coef_mod_t = centered % t_modulus;
        if (coef_mod_t < 0) coef_mod_t = -coef_mod_t;
        if (coef_mod_t > t_half) {
            coef_mod_t = t_modulus - coef_mod_t;
        }
        
        // But a better noise metric is the magnitude of the whole coefficient
        // divided by t. For BGV, the noise is E where Dec = m + t*E,
        // so E = (Dec - m) / t. Since m = Dec mod t, we have:
        // E = (Dec - (Dec mod t)) / t = floor(Dec / t)
        // The magnitude of E tells us noise level.
        ZZ noise_e = abs(centered) / t_modulus;
        if (noise_e > max_noise) {
            max_noise = noise_e;
        }
    }
    
    // If noise is 0 or very small, use initial estimate
    if (max_noise == 0) {
        max_noise = conv<ZZ>(1);
    }
    
    // Noise budget = log2(q/2) - log2(max_noise * t)
    // This represents bits of headroom before noise exceeds q/2
    double log_q = log(params_.q) / std::log(2.0);
    double log_noise = log(max_noise * t_modulus) / std::log(2.0);
    
    // Restore previous NTL modulus context (RAII via ZZ_pBak destructor would also work,
    // but explicit restore ensures immediate cleanup before return)
    modulus_backup.restore();
    
    return log_q - 1 - log_noise;
}


bool BGVContext::is_valid(const BGVSecretKey& sk, const BGVCiphertext& ct) {
    return noise_budget(sk, ct) > 0;
}

// ============================================================================
// Sampling Functions
// ============================================================================

RingElement BGVContext::sample_uniform() {
    RingElement result;
    
    for (uint64_t i = 0; i < params_.n; i++) {
        // Sample uniform in [0, q)
        ZZ coef;
        RandomBnd(coef, params_.q);
        SetCoeff(result.poly(), i, conv<ZZ_p>(coef));
    }
    
    return result;
}

RingElement BGVContext::sample_error() {
    RingElement result;
    
    // Discrete Gaussian with parameter σ
    std::normal_distribution<double> dist(0.0, params_.sigma);
    
    for (uint64_t i = 0; i < params_.n; i++) {
        double val = dist(rng_);
        long rounded = static_cast<long>(std::round(val));
        
        // Convert to mod q - use conv<ZZ>(long) for signed integers
        ZZ coef = conv<ZZ>(rounded);
        if (rounded < 0) {
            coef += params_.q;
        }
        
        SetCoeff(result.poly(), i, conv<ZZ_p>(coef));
    }
    
    return result;
}

RingElement BGVContext::sample_ternary(uint32_t hamming_weight) {
    RingElement result;
    
    if (hamming_weight == 0) {
        // Dense ternary: each coefficient uniformly in {-1, 0, 1}
        std::uniform_int_distribution<int> dist(-1, 1);
        
        for (uint64_t i = 0; i < params_.n; i++) {
            int val = dist(rng_);
            // Use conv<ZZ>(long) for signed integers, not to_ZZ(uint64_t)
            ZZ coef = conv<ZZ>(static_cast<long>(val));
            if (val < 0) {
                coef += params_.q;
            }
            SetCoeff(result.poly(), i, conv<ZZ_p>(coef));
        }
    } else {
        // Sparse ternary with exactly hamming_weight non-zero coefficients
        // Half are +1, half are -1
        
        // Initialize to zero
        for (uint64_t i = 0; i < params_.n; i++) {
            SetCoeff(result.poly(), i, conv<ZZ_p>(0));
        }
        
        // Pick random positions
        std::vector<uint64_t> positions(params_.n);
        for (uint64_t i = 0; i < params_.n; i++) {
            positions[i] = i;
        }
        std::shuffle(positions.begin(), positions.end(), rng_);
        
        // Set first hamming_weight/2 to +1
        for (uint32_t i = 0; i < hamming_weight / 2; i++) {
            SetCoeff(result.poly(), positions[i], conv<ZZ_p>(1));
        }
        
        // Set next hamming_weight/2 to -1
        ZZ_p minus_one = conv<ZZ_p>(params_.q - 1);
        for (uint32_t i = hamming_weight / 2; i < hamming_weight; i++) {
            SetCoeff(result.poly(), positions[i], minus_one);
        }
    }
    
    return result;
}

// ============================================================================
// Serialization
// ============================================================================

std::vector<uint8_t> BGVContext::serialize() const {
    // TODO: Implement proper serialization
    return {};
}

std::unique_ptr<BGVContext> BGVContext::deserialize(
    const std::vector<uint8_t>& data) {
    // TODO: Implement proper deserialization
    return nullptr;
}

} // namespace bgv
} // namespace fhe
} // namespace kctsb
