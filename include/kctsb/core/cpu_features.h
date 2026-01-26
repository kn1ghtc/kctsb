/**
 * @file cpu_features.h
 * @brief CPU Feature Detection API
 * 
 * Runtime detection of SIMD capabilities for optimized code paths.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CORE_CPU_FEATURES_H
#define KCTSB_CORE_CPU_FEATURES_H

#include "kctsb/core/common.h"
#include <string>

namespace kctsb {
namespace cpu {

/**
 * @brief CPU feature flags detected at runtime
 * 
 * Used for runtime dispatch to optimized code paths.
 * Call CPUFeatures::detect() once at program startup.
 */
struct CPUFeatures {
    // x86_64 features
    bool has_sse2       = false;  ///< SSE2 (baseline for x86_64)
    bool has_sse41      = false;  ///< SSE4.1
    bool has_sse42      = false;  ///< SSE4.2
    bool has_aesni      = false;  ///< AES-NI hardware acceleration
    bool has_pclmul     = false;  ///< PCLMULQDQ for GHASH
    bool has_avx        = false;  ///< AVX 256-bit SIMD
    bool has_avx2       = false;  ///< AVX2 with integer ops
    bool has_bmi2       = false;  ///< BMI2 (MULX instruction)
    bool has_adx        = false;  ///< ADX (ADCX/ADOX)
    bool has_sha        = false;  ///< SHA-NI (SHA1/SHA256 acceleration)
    bool has_avx512f    = false;  ///< AVX-512 Foundation
    bool has_avx512ifma = false;  ///< AVX-512 IFMA (52-bit integer multiply)
    bool has_vaes       = false;  ///< Vector AES (AVX512-AES)

    // ARM64 features
    bool has_neon  = false;  ///< ARM NEON SIMD
    bool has_aes   = false;  ///< ARM Crypto Extensions (AES)
    bool has_sha1  = false;  ///< ARM SHA1 acceleration
    bool has_sha2  = false;  ///< ARM SHA2 acceleration
    bool has_pmull = false;  ///< ARM Polynomial Multiply (for GHASH)

    // CPU vendor
    bool is_intel = false;
    bool is_amd   = false;

    /**
     * @brief Detect CPU features using CPUID/getauxval
     * @return Populated CPUFeatures struct
     */
    static CPUFeatures detect() noexcept;

    /**
     * @brief Get human-readable feature string
     * @return Space-separated feature names
     */
    std::string to_string() const;
};

} // namespace cpu
} // namespace kctsb

#endif // KCTSB_CORE_CPU_FEATURES_H
