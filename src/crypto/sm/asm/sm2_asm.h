/**
 * @file sm2_asm.h
 * @brief SM2 Assembly Acceleration Interface
 * 
 * Platform detection and function declarations for SM2 assembly optimizations.
 * Provides C++ wrapper functions that dispatch to assembly or C fallback.
 * 
 * @author knightc
 * @copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_SM2_ASM_H
#define KCTSB_SM2_ASM_H

#include <cstdint>
#include <cstddef>

/* ========== Platform Detection ========== */

/* Check for x86_64 architecture */
#if defined(__x86_64__) || defined(_M_X64)
    #define KCTSB_SM2_X86_64 1
#endif

/* Check for ARM64/AArch64 architecture */
#if defined(__aarch64__) || defined(_M_ARM64)
    #define KCTSB_SM2_ARM64 1
#endif

/* Check for Intel ADX (ADCX/ADOX) and BMI2 (MULX) instructions */
#if defined(__ADX__) && defined(__BMI2__)
    #define KCTSB_SM2_HAS_ADX 1
#endif

/* Check for ARM NEON */
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    #define KCTSB_SM2_HAS_NEON 1
#endif

/* Enable assembly by default on supported platforms */
/* TEMPORARILY DISABLED for debugging - using C++ implementation */
#if 0 && defined(KCTSB_SM2_X86_64) && !defined(KCTSB_SM2_NO_ASM)
    #define KCTSB_SM2_USE_ASM 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ========== Data Types ========== */

/** 
 * @brief 256-bit field element (4 x 64-bit limbs, little-endian)
 * 
 * Layout: d[0] = bits 0-63, d[1] = bits 64-127, d[2] = bits 128-191, d[3] = bits 192-255
 */
typedef struct {
    uint64_t d[4];
} sm2_fe256_t;

/** 
 * @brief 512-bit intermediate product (8 x 64-bit limbs)
 */
typedef struct {
    uint64_t d[8];
} sm2_fe512_t;

/* ========== Assembly Function Declarations ========== */

#if defined(KCTSB_SM2_USE_ASM)

/**
 * @brief Modular addition: r = (a + b) mod p
 */
extern void sm2_z256_modp_add(uint64_t *r, const uint64_t *a, const uint64_t *b);

/**
 * @brief Modular subtraction: r = (a - b) mod p
 */
extern void sm2_z256_modp_sub(uint64_t *r, const uint64_t *a, const uint64_t *b);

/**
 * @brief Modular doubling: r = 2*a mod p
 */
extern void sm2_z256_modp_dbl(uint64_t *r, const uint64_t *a);

/**
 * @brief Modular negation: r = -a mod p = p - a
 */
extern void sm2_z256_modp_neg(uint64_t *r, const uint64_t *a);

/**
 * @brief Modular halving: r = a/2 mod p
 */
extern void sm2_z256_modp_half(uint64_t *r, const uint64_t *a);

/**
 * @brief Montgomery multiplication: r = a * b * R^(-1) mod p
 */
extern void sm2_z256_modp_mont_mul(uint64_t *r, const uint64_t *a, const uint64_t *b);

/**
 * @brief Montgomery squaring: r = a^2 * R^(-1) mod p
 */
extern void sm2_z256_modp_mont_sqr(uint64_t *r, const uint64_t *a);

/**
 * @brief Convert to Montgomery form: r = a * R mod p
 */
extern void sm2_z256_modp_to_mont(uint64_t *r, const uint64_t *a);

/**
 * @brief Convert from Montgomery form: r = a * R^(-1) mod p
 */
extern void sm2_z256_modp_from_mont(uint64_t *r, const uint64_t *a);

#endif  /* KCTSB_SM2_USE_ASM */

#ifdef __cplusplus
}  /* extern "C" */
#endif

/* ========== C++ Wrapper Functions ========== */

#ifdef __cplusplus
namespace kctsb {
namespace sm2_asm {

/**
 * @brief Check if assembly acceleration is available at runtime
 * @return true if assembly routines are available
 */
inline bool is_asm_available() {
#if defined(KCTSB_SM2_USE_ASM)
    return true;
#else
    return false;
#endif
}

/**
 * @brief Get string description of active acceleration
 * @return Description string (e.g., "x86_64 assembly", "C fallback")
 */
inline const char* get_acceleration_info() {
#if defined(KCTSB_SM2_USE_ASM)
    #if defined(KCTSB_SM2_HAS_ADX)
        return "x86_64 assembly (ADX+BMI2)";
    #else
        return "x86_64 assembly";
    #endif
#elif defined(KCTSB_SM2_ARM64)
    #if defined(KCTSB_SM2_HAS_NEON)
        return "ARM64 NEON (future)";
    #else
        return "ARM64 C fallback";
    #endif
#else
    return "Portable C fallback";
#endif
}

/* ========== Type-Safe C++ Wrappers ========== */

#if defined(KCTSB_SM2_USE_ASM)

/**
 * @brief Modular addition using assembly
 */
inline void modp_add(sm2_fe256_t& r, const sm2_fe256_t& a, const sm2_fe256_t& b) {
    sm2_z256_modp_add(r.d, a.d, b.d);
}

/**
 * @brief Modular subtraction using assembly
 */
inline void modp_sub(sm2_fe256_t& r, const sm2_fe256_t& a, const sm2_fe256_t& b) {
    sm2_z256_modp_sub(r.d, a.d, b.d);
}

/**
 * @brief Modular doubling using assembly
 */
inline void modp_dbl(sm2_fe256_t& r, const sm2_fe256_t& a) {
    sm2_z256_modp_dbl(r.d, a.d);
}

/**
 * @brief Modular negation using assembly
 */
inline void modp_neg(sm2_fe256_t& r, const sm2_fe256_t& a) {
    sm2_z256_modp_neg(r.d, a.d);
}

/**
 * @brief Modular halving using assembly
 */
inline void modp_half(sm2_fe256_t& r, const sm2_fe256_t& a) {
    sm2_z256_modp_half(r.d, a.d);
}

/**
 * @brief Montgomery multiplication using assembly
 */
inline void mont_mul(sm2_fe256_t& r, const sm2_fe256_t& a, const sm2_fe256_t& b) {
    sm2_z256_modp_mont_mul(r.d, a.d, b.d);
}

/**
 * @brief Montgomery squaring using assembly
 */
inline void mont_sqr(sm2_fe256_t& r, const sm2_fe256_t& a) {
    sm2_z256_modp_mont_sqr(r.d, a.d);
}

/**
 * @brief Convert to Montgomery form using assembly
 */
inline void to_mont(sm2_fe256_t& r, const sm2_fe256_t& a) {
    sm2_z256_modp_to_mont(r.d, a.d);
}

/**
 * @brief Convert from Montgomery form using assembly
 */
inline void from_mont(sm2_fe256_t& r, const sm2_fe256_t& a) {
    sm2_z256_modp_from_mont(r.d, a.d);
}

#endif  /* KCTSB_SM2_USE_ASM */

}  /* namespace sm2_asm */
}  /* namespace kctsb */
#endif  /* __cplusplus */

#endif  /* KCTSB_SM2_ASM_H */
