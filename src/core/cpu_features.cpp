/**
 * @file cpu_features.cpp
 * @brief CPU Feature Detection for Runtime SIMD Dispatch
 * 
 * Detects hardware capabilities (AVX2, AES-NI, SSE4.2, SHA-NI, etc.)
 * using CPUID instruction on x86_64 or getauxval on ARM.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/core/cpu_features.h"
#include <cstdint>
#include <cstring>

#if defined(_MSC_VER)
    #include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
    #include <cpuid.h>
#endif

#if defined(__linux__)
    #include <sys/auxv.h>
#endif

namespace kctsb {
namespace cpu {

namespace {

/**
 * @brief x86_64 CPUID wrapper
 * @param leaf CPUID function (EAX input)
 * @param subleaf CPUID sub-function (ECX input)
 * @param regs Output: [EAX, EBX, ECX, EDX]
 */
#if defined(__x86_64__) || defined(_M_X64)
static inline void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t regs[4]) {
#if defined(_MSC_VER)
    __cpuidex(reinterpret_cast<int*>(regs), static_cast<int>(leaf), static_cast<int>(subleaf));
#elif defined(__GNUC__) || defined(__clang__)
    __cpuid_count(leaf, subleaf, regs[0], regs[1], regs[2], regs[3]);
#else
    // Fallback: no CPUID support
    std::memset(regs, 0, 4 * sizeof(uint32_t));
#endif
}
#endif

} // anonymous namespace

/**
 * @brief Detect CPU features using CPUID (x86_64) or getauxval (ARM)
 */
CPUFeatures CPUFeatures::detect() noexcept {
    CPUFeatures features{};

#if defined(__x86_64__) || defined(_M_X64)
    // x86_64 CPUID detection
    uint32_t regs[4];

    // Check basic features (Leaf 1)
    cpuid(1, 0, regs);
    // ECX bits
    features.has_sse2    = (regs[3] & (1 << 26)) != 0;  // EDX bit 26
    features.has_sse41   = (regs[2] & (1 << 19)) != 0;  // ECX bit 19
    features.has_sse42   = (regs[2] & (1 << 20)) != 0;  // ECX bit 20
    features.has_aesni   = (regs[2] & (1 << 25)) != 0;  // ECX bit 25
    features.has_pclmul  = (regs[2] & (1 << 1))  != 0;  // ECX bit 1
    features.has_avx     = (regs[2] & (1 << 28)) != 0;  // ECX bit 28

    // Check extended features (Leaf 7, Subleaf 0)
    cpuid(7, 0, regs);
    features.has_avx2       = (regs[1] & (1 << 5))  != 0;  // EBX bit 5
    features.has_bmi2       = (regs[1] & (1 << 8))  != 0;  // EBX bit 8
    features.has_adx        = (regs[1] & (1 << 19)) != 0;  // EBX bit 19
    features.has_sha        = (regs[1] & (1 << 29)) != 0;  // EBX bit 29 (SHA-NI)
    features.has_avx512f    = (regs[1] & (1 << 16)) != 0;  // EBX bit 16
    features.has_avx512ifma = (regs[1] & (1 << 21)) != 0;  // EBX bit 21
    features.has_vaes       = (regs[2] & (1 << 9))  != 0;  // ECX bit 9 (VAES)

    // Determine vendor
    cpuid(0, 0, regs);
    char vendor[13] = {0};
    std::memcpy(vendor, &regs[1], 4);     // EBX
    std::memcpy(vendor + 4, &regs[3], 4); // EDX
    std::memcpy(vendor + 8, &regs[2], 4); // ECX

    if (std::strcmp(vendor, "GenuineIntel") == 0) {
        features.is_intel = true;
    } else if (std::strcmp(vendor, "AuthenticAMD") == 0) {
        features.is_amd = true;
    }

#elif defined(__aarch64__) || defined(_M_ARM64)
    // ARM64 detection via getauxval (Linux) or hardcoded (macOS M1+)
#if defined(__linux__)
    unsigned long hwcaps = getauxval(AT_HWCAP);
    features.has_neon = (hwcaps & HWCAP_ASIMD) != 0;  // Advanced SIMD (NEON)
    features.has_aes  = (hwcaps & HWCAP_AES) != 0;    // ARM Crypto Extensions (AES)
    features.has_sha1 = (hwcaps & HWCAP_SHA1) != 0;   // SHA1 acceleration
    features.has_sha2 = (hwcaps & HWCAP_SHA2) != 0;   // SHA2 acceleration
    features.has_pmull = (hwcaps & HWCAP_PMULL) != 0; // Polynomial multiply
#elif defined(__APPLE__)
    // Apple Silicon (M1/M2/M3) always has full ARM Crypto Extensions
    features.has_neon  = true;
    features.has_aes   = true;
    features.has_sha1  = true;
    features.has_sha2  = true;
    features.has_pmull = true;
#endif
#endif

    return features;
}

/**
 * @brief Get human-readable feature string
 */
std::string CPUFeatures::to_string() const {
    std::string result;

#if defined(__x86_64__) || defined(_M_X64)
    if (is_intel) result += "Intel ";
    if (is_amd) result += "AMD ";

    if (has_sse2) result += "SSE2 ";
    if (has_sse41) result += "SSE4.1 ";
    if (has_sse42) result += "SSE4.2 ";
    if (has_aesni) result += "AES-NI ";
    if (has_pclmul) result += "PCLMUL ";
    if (has_avx) result += "AVX ";
    if (has_avx2) result += "AVX2 ";
    if (has_bmi2) result += "BMI2 ";
    if (has_adx) result += "ADX ";
    if (has_sha) result += "SHA-NI ";
    if (has_avx512f) result += "AVX512F ";
    if (has_avx512ifma) result += "AVX512IFMA ";
    if (has_vaes) result += "VAES ";

#elif defined(__aarch64__) || defined(_M_ARM64)
    result += "ARM64 ";
    if (has_neon) result += "NEON ";
    if (has_aes) result += "ARM-AES ";
    if (has_sha1) result += "SHA1 ";
    if (has_sha2) result += "SHA2 ";
    if (has_pmull) result += "PMULL ";
#endif

    if (result.empty()) {
        return "Generic CPU (no SIMD)";
    }

    // Remove trailing space
    result.pop_back();
    return result;
}

} // namespace cpu
} // namespace kctsb
