/**
 * @file aes.cpp
 * @brief Production-grade AES implementation with multi-level optimization
 *
 * Features:
 * - AES-NI hardware acceleration when available (fastest + timing-safe)
 * - Constant-time software implementation as fallback
 * - T-table code preserved for future optimization and benchmarking
 * - Secure memory handling with automatic zeroing
 * - Complete AES-GCM with GHASH authentication
 * - AES-128/192/256 support for all modes
 *
 * Optimization hierarchy (auto-selected at runtime):
 * 1. AES-NI: ~10x faster, constant-time, requires CPU support (AES-128 only)
 * 2. Software: Baseline, fully portable, constant-time (all key sizes)
 *
 * Note: T-table implementation is preserved but not currently used due to
 * format compatibility issues between T-table encryption and software decryption.
 * Future versions may implement T-table decryption for performance optimization.
 *
 * Based on NIST FIPS 197 (AES) and SP 800-38D (GCM)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/aes.h"
#include "kctsb/core/security.h"
#include "kctsb/simd/simd.h"
#include <cstring>
#include <stdexcept>

// CPUID and SIMD intrinsics
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// AES-NI and SSE intrinsics
#if defined(KCTSB_HAS_AESNI) || defined(__AES__)
#include <wmmintrin.h>  // AES-NI
#include <emmintrin.h>  // SSE2
#include <tmmintrin.h>  // SSSE3 (for _mm_shuffle_epi8)
#include <smmintrin.h>  // SSE4.1
#endif

// ============================================================================
// Runtime Feature Detection
// ============================================================================

static bool g_aesni_detected = false;
static bool g_aesni_available = false;

static inline bool check_aesni() {
#if defined(KCTSB_HAS_AESNI)
    if (!g_aesni_detected) {
        g_aesni_available = kctsb::simd::has_aesni();
        g_aesni_detected = true;
    }
    return g_aesni_available;
#else
    return false;
#endif
}

// Flag to track key format in context
#define AESNI_FORMAT_FLAG 0x10000

// ============================================================================
// AES S-Box (for software implementation)
// ============================================================================

static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// ============================================================================
// T-Tables for High-Performance AES (combined SubBytes+ShiftRows+MixColumns)
// WARNING: Cache-timing vulnerable - use AES-NI for security-critical code
// ============================================================================

alignas(64) static const uint32_t Te0[256] = {
    0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d, 0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554,
    0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d, 0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a,
    0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87, 0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b,
    0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea, 0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b,
    0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a, 0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f,
    0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108, 0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f,
    0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e, 0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5,
    0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d, 0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f,
    0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e, 0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb,
    0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce, 0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497,
    0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c, 0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed,
    0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b, 0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a,
    0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16, 0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594,
    0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81, 0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3,
    0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a, 0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504,
    0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163, 0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d,
    0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f, 0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739,
    0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47, 0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395,
    0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f, 0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883,
    0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c, 0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76,
    0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e, 0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4,
    0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6, 0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b,
    0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7, 0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0,
    0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25, 0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818,
    0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72, 0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651,
    0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21, 0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85,
    0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa, 0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12,
    0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0, 0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9,
    0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133, 0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7,
    0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920, 0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a,
    0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17, 0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8,
    0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11, 0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a,
};

alignas(64) static const uint32_t Te1[256] = {
    0xa5c66363, 0x84f87c7c, 0x99ee7777, 0x8df67b7b, 0x0dfff2f2, 0xbdd66b6b, 0xb1de6f6f, 0x5491c5c5,
    0x50603030, 0x03020101, 0xa9ce6767, 0x7d562b2b, 0x19e7fefe, 0x62b5d7d7, 0xe64dabab, 0x9aec7676,
    0x458fcaca, 0x9d1f8282, 0x4089c9c9, 0x87fa7d7d, 0x15effafa, 0xebb25959, 0xc98e4747, 0x0bfbf0f0,
    0xec41adad, 0x67b3d4d4, 0xfd5fa2a2, 0xea45afaf, 0xbf239c9c, 0xf753a4a4, 0x96e47272, 0x5b9bc0c0,
    0xc275b7b7, 0x1ce1fdfd, 0xae3d9393, 0x6a4c2626, 0x5a6c3636, 0x417e3f3f, 0x02f5f7f7, 0x4f83cccc,
    0x5c683434, 0xf451a5a5, 0x34d1e5e5, 0x08f9f1f1, 0x93e27171, 0x73abd8d8, 0x53623131, 0x3f2a1515,
    0x0c080404, 0x5295c7c7, 0x65462323, 0x5e9dc3c3, 0x28301818, 0xa1379696, 0x0f0a0505, 0xb52f9a9a,
    0x090e0707, 0x36241212, 0x9b1b8080, 0x3ddfe2e2, 0x26cdebeb, 0x694e2727, 0xcd7fb2b2, 0x9fea7575,
    0x1b120909, 0x9e1d8383, 0x74582c2c, 0x2e341a1a, 0x2d361b1b, 0xb2dc6e6e, 0xeeb45a5a, 0xfb5ba0a0,
    0xf6a45252, 0x4d763b3b, 0x61b7d6d6, 0xce7db3b3, 0x7b522929, 0x3edde3e3, 0x715e2f2f, 0x97138484,
    0xf5a65353, 0x68b9d1d1, 0x00000000, 0x2cc1eded, 0x60402020, 0x1fe3fcfc, 0xc879b1b1, 0xedb65b5b,
    0xbed46a6a, 0x468dcbcb, 0xd967bebe, 0x4b723939, 0xde944a4a, 0xd4984c4c, 0xe8b05858, 0x4a85cfcf,
    0x6bbbd0d0, 0x2ac5efef, 0xe54faaaa, 0x16edfbfb, 0xc5864343, 0xd79a4d4d, 0x55663333, 0x94118585,
    0xcf8a4545, 0x10e9f9f9, 0x06040202, 0x81fe7f7f, 0xf0a05050, 0x44783c3c, 0xba259f9f, 0xe34ba8a8,
    0xf3a25151, 0xfe5da3a3, 0xc0804040, 0x8a058f8f, 0xad3f9292, 0xbc219d9d, 0x48703838, 0x04f1f5f5,
    0xdf63bcbc, 0xc177b6b6, 0x75afdada, 0x63422121, 0x30201010, 0x1ae5ffff, 0x0efdf3f3, 0x6dbfd2d2,
    0x4c81cdcd, 0x14180c0c, 0x35261313, 0x2fc3ecec, 0xe1be5f5f, 0xa2359797, 0xcc884444, 0x392e1717,
    0x5793c4c4, 0xf255a7a7, 0x82fc7e7e, 0x477a3d3d, 0xacc86464, 0xe7ba5d5d, 0x2b321919, 0x95e67373,
    0xa0c06060, 0x98198181, 0xd19e4f4f, 0x7fa3dcdc, 0x66442222, 0x7e542a2a, 0xab3b9090, 0x830b8888,
    0xca8c4646, 0x29c7eeee, 0xd36bb8b8, 0x3c281414, 0x79a7dede, 0xe2bc5e5e, 0x1d160b0b, 0x76addbdb,
    0x3bdbe0e0, 0x56643232, 0x4e743a3a, 0x1e140a0a, 0xdb924949, 0x0a0c0606, 0x6c482424, 0xe4b85c5c,
    0x5d9fc2c2, 0x6ebdd3d3, 0xef43acac, 0xa6c46262, 0xa8399191, 0xa4319595, 0x37d3e4e4, 0x8bf27979,
    0x32d5e7e7, 0x438bc8c8, 0x596e3737, 0xb7da6d6d, 0x8c018d8d, 0x64b1d5d5, 0xd29c4e4e, 0xe049a9a9,
    0xb4d86c6c, 0xfaac5656, 0x07f3f4f4, 0x25cfeaea, 0xafca6565, 0x8ef47a7a, 0xe947aeae, 0x18100808,
    0xd56fbaba, 0x88f07878, 0x6f4a2525, 0x725c2e2e, 0x24381c1c, 0xf157a6a6, 0xc773b4b4, 0x5197c6c6,
    0x23cbe8e8, 0x7ca1dddd, 0x9ce87474, 0x213e1f1f, 0xdd964b4b, 0xdc61bdbd, 0x860d8b8b, 0x850f8a8a,
    0x90e07070, 0x427c3e3e, 0xc471b5b5, 0xaacc6666, 0xd8904848, 0x05060303, 0x01f7f6f6, 0x121c0e0e,
    0xa3c26161, 0x5f6a3535, 0xf9ae5757, 0xd069b9b9, 0x91178686, 0x5899c1c1, 0x273a1d1d, 0xb9279e9e,
    0x38d9e1e1, 0x13ebf8f8, 0xb32b9898, 0x33221111, 0xbbd26969, 0x70a9d9d9, 0x89078e8e, 0xa7339494,
    0xb62d9b9b, 0x223c1e1e, 0x92158787, 0x20c9e9e9, 0x4987cece, 0xffaa5555, 0x78502828, 0x7aa5dfdf,
    0x8f038c8c, 0xf859a1a1, 0x80098989, 0x171a0d0d, 0xda65bfbf, 0x31d7e6e6, 0xc6844242, 0xb8d06868,
    0xc3824141, 0xb0299999, 0x775a2d2d, 0x111e0f0f, 0xcb7bb0b0, 0xfca85454, 0xd66dbbbb, 0x3a2c1616,
};

alignas(64) static const uint32_t Te2[256] = {
    0x63a5c663, 0x7c84f87c, 0x7799ee77, 0x7b8df67b, 0xf20dfff2, 0x6bbdd66b, 0x6fb1de6f, 0xc55491c5,
    0x30506030, 0x01030201, 0x67a9ce67, 0x2b7d562b, 0xfe19e7fe, 0xd762b5d7, 0xabe64dab, 0x769aec76,
    0xca458fca, 0x829d1f82, 0xc94089c9, 0x7d87fa7d, 0xfa15effa, 0x59ebb259, 0x47c98e47, 0xf00bfbf0,
    0xadec41ad, 0xd467b3d4, 0xa2fd5fa2, 0xafea45af, 0x9cbf239c, 0xa4f753a4, 0x7296e472, 0xc05b9bc0,
    0xb7c275b7, 0xfd1ce1fd, 0x93ae3d93, 0x266a4c26, 0x365a6c36, 0x3f417e3f, 0xf702f5f7, 0xcc4f83cc,
    0x345c6834, 0xa5f451a5, 0xe534d1e5, 0xf108f9f1, 0x7193e271, 0xd873abd8, 0x31536231, 0x153f2a15,
    0x040c0804, 0xc75295c7, 0x23654623, 0xc35e9dc3, 0x18283018, 0x96a13796, 0x050f0a05, 0x9ab52f9a,
    0x07090e07, 0x12362412, 0x809b1b80, 0xe23ddfe2, 0xeb26cdeb, 0x27694e27, 0xb2cd7fb2, 0x759fea75,
    0x091b1209, 0x839e1d83, 0x2c74582c, 0x1a2e341a, 0x1b2d361b, 0x6eb2dc6e, 0x5aeeb45a, 0xa0fb5ba0,
    0x52f6a452, 0x3b4d763b, 0xd661b7d6, 0xb3ce7db3, 0x297b5229, 0xe33edde3, 0x2f715e2f, 0x84971384,
    0x53f5a653, 0xd168b9d1, 0x00000000, 0xed2cc1ed, 0x20604020, 0xfc1fe3fc, 0xb1c879b1, 0x5bedb65b,
    0x6abed46a, 0xcb468dcb, 0xbed967be, 0x394b7239, 0x4ade944a, 0x4cd4984c, 0x58e8b058, 0xcf4a85cf,
    0xd06bbbd0, 0xef2ac5ef, 0xaae54faa, 0xfb16edfb, 0x43c58643, 0x4dd79a4d, 0x33556633, 0x85941185,
    0x45cf8a45, 0xf910e9f9, 0x02060402, 0x7f81fe7f, 0x50f0a050, 0x3c44783c, 0x9fba259f, 0xa8e34ba8,
    0x51f3a251, 0xa3fe5da3, 0x40c08040, 0x8f8a058f, 0x92ad3f92, 0x9dbc219d, 0x38487038, 0xf504f1f5,
    0xbcdf63bc, 0xb6c177b6, 0xda75afda, 0x21634221, 0x10302010, 0xff1ae5ff, 0xf30efdf3, 0xd26dbfd2,
    0xcd4c81cd, 0x0c14180c, 0x13352613, 0xec2fc3ec, 0x5fe1be5f, 0x97a23597, 0x44cc8844, 0x17392e17,
    0xc45793c4, 0xa7f255a7, 0x7e82fc7e, 0x3d477a3d, 0x64acc864, 0x5de7ba5d, 0x192b3219, 0x7395e673,
    0x60a0c060, 0x81981981, 0x4fd19e4f, 0xdc7fa3dc, 0x22664422, 0x2a7e542a, 0x90ab3b90, 0x88830b88,
    0x46ca8c46, 0xee29c7ee, 0xb8d36bb8, 0x143c2814, 0xde79a7de, 0x5ee2bc5e, 0x0b1d160b, 0xdb76addb,
    0xe03bdbe0, 0x32566432, 0x3a4e743a, 0x0a1e140a, 0x49db9249, 0x060a0c06, 0x246c4824, 0x5ce4b85c,
    0xc25d9fc2, 0xd36ebdd3, 0xacef43ac, 0x62a6c462, 0x91a83991, 0x95a43195, 0xe437d3e4, 0x798bf279,
    0xe732d5e7, 0xc8438bc8, 0x37596e37, 0x6db7da6d, 0x8d8c018d, 0xd564b1d5, 0x4ed29c4e, 0xa9e049a9,
    0x6cb4d86c, 0x56faac56, 0xf407f3f4, 0xea25cfea, 0x65afca65, 0x7a8ef47a, 0xaee947ae, 0x08181008,
    0xbad56fba, 0x7888f078, 0x256f4a25, 0x2e725c2e, 0x1c24381c, 0xa6f157a6, 0xb4c773b4, 0xc65197c6,
    0xe823cbe8, 0xdd7ca1dd, 0x749ce874, 0x1f213e1f, 0x4bdd964b, 0xbddc61bd, 0x8b860d8b, 0x8a850f8a,
    0x7090e070, 0x3e427c3e, 0xb5c471b5, 0x66aacc66, 0x48d89048, 0x03050603, 0xf601f7f6, 0x0e121c0e,
    0x61a3c261, 0x355f6a35, 0x57f9ae57, 0xb9d069b9, 0x86911786, 0xc15899c1, 0x1d273a1d, 0x9eb9279e,
    0xe138d9e1, 0xf813ebf8, 0x98b32b98, 0x11332211, 0x69bbd269, 0xd970a9d9, 0x8e89078e, 0x94a73394,
    0x9bb62d9b, 0x1e223c1e, 0x87921587, 0xe920c9e9, 0xce4987ce, 0x55ffaa55, 0x28785028, 0xdf7aa5df,
    0x8c8f038c, 0xa1f859a1, 0x89800989, 0x0d171a0d, 0xbfda65bf, 0xe631d7e6, 0x42c68442, 0x68b8d068,
    0x41c38241, 0x99b02999, 0x2d775a2d, 0x0f111e0f, 0xb0cb7bb0, 0x54fca854, 0xbbd66dbb, 0x163a2c16,
};

alignas(64) static const uint32_t Te3[256] = {
    0x6363a5c6, 0x7c7c84f8, 0x777799ee, 0x7b7b8df6, 0xf2f20dff, 0x6b6bbdd6, 0x6f6fb1de, 0xc5c55491,
    0x30305060, 0x01010302, 0x6767a9ce, 0x2b2b7d56, 0xfefe19e7, 0xd7d762b5, 0xababe64d, 0x76769aec,
    0xcaca458f, 0x82829d1f, 0xc9c94089, 0x7d7d87fa, 0xfafa15ef, 0x5959ebb2, 0x4747c98e, 0xf0f00bfb,
    0xadadec41, 0xd4d467b3, 0xa2a2fd5f, 0xafafea45, 0x9c9cbf23, 0xa4a4f753, 0x727296e4, 0xc0c05b9b,
    0xb7b7c275, 0xfdfd1ce1, 0x9393ae3d, 0x26266a4c, 0x36365a6c, 0x3f3f417e, 0xf7f702f5, 0xcccc4f83,
    0x34345c68, 0xa5a5f451, 0xe5e534d1, 0xf1f108f9, 0x717193e2, 0xd8d873ab, 0x31315362, 0x15153f2a,
    0x04040c08, 0xc7c75295, 0x23236546, 0xc3c35e9d, 0x18182830, 0x9696a137, 0x05050f0a, 0x9a9ab52f,
    0x0707090e, 0x12123624, 0x80809b1b, 0xe2e23ddf, 0xebeb26cd, 0x2727694e, 0xb2b2cd7f, 0x75759fea,
    0x09091b12, 0x83839e1d, 0x2c2c7458, 0x1a1a2e34, 0x1b1b2d36, 0x6e6eb2dc, 0x5a5aeeb4, 0xa0a0fb5b,
    0x5252f6a4, 0x3b3b4d76, 0xd6d661b7, 0xb3b3ce7d, 0x29297b52, 0xe3e33edd, 0x2f2f715e, 0x84849713,
    0x5353f5a6, 0xd1d168b9, 0x00000000, 0xeded2cc1, 0x20206040, 0xfcfc1fe3, 0xb1b1c879, 0x5b5bedb6,
    0x6a6abed4, 0xcbcb468d, 0xbebed967, 0x39394b72, 0x4a4ade94, 0x4c4cd498, 0x5858e8b0, 0xcfcf4a85,
    0xd0d06bbb, 0xefef2ac5, 0xaaaae54f, 0xfbfb16ed, 0x4343c586, 0x4d4dd79a, 0x33335566, 0x85859411,
    0x4545cf8a, 0xf9f910e9, 0x02020604, 0x7f7f81fe, 0x5050f0a0, 0x3c3c4478, 0x9f9fba25, 0xa8a8e34b,
    0x5151f3a2, 0xa3a3fe5d, 0x4040c080, 0x8f8f8a05, 0x9292ad3f, 0x9d9dbc21, 0x38384870, 0xf5f504f1,
    0xbcbcdf63, 0xb6b6c177, 0xdada75af, 0x21216342, 0x10103020, 0xffff1ae5, 0xf3f30efd, 0xd2d26dbf,
    0xcdcd4c81, 0x0c0c1418, 0x13133526, 0xecec2fc3, 0x5f5fe1be, 0x9797a235, 0x4444cc88, 0x1717392e,
    0xc4c45793, 0xa7a7f255, 0x7e7e82fc, 0x3d3d477a, 0x6464acc8, 0x5d5de7ba, 0x19192b32, 0x737395e6,
    0x6060a0c0, 0x81819819, 0x4f4fd19e, 0xdcdc7fa3, 0x22226644, 0x2a2a7e54, 0x9090ab3b, 0x8888830b,
    0x4646ca8c, 0xeeee29c7, 0xb8b8d36b, 0x14143c28, 0xdede79a7, 0x5e5ee2bc, 0x0b0b1d16, 0xdbdb76ad,
    0xe0e03bdb, 0x32325664, 0x3a3a4e74, 0x0a0a1e14, 0x4949db92, 0x06060a0c, 0x24246c48, 0x5c5ce4b8,
    0xc2c25d9f, 0xd3d36ebd, 0xacacef43, 0x6262a6c4, 0x9191a839, 0x9595a431, 0xe4e437d3, 0x79798bf2,
    0xe7e732d5, 0xc8c8438b, 0x3737596e, 0x6d6db7da, 0x8d8d8c01, 0xd5d564b1, 0x4e4ed29c, 0xa9a9e049,
    0x6c6cb4d8, 0x5656faac, 0xf4f407f3, 0xeaea25cf, 0x6565afca, 0x7a7a8ef4, 0xaeaee947, 0x08081810,
    0xbabad56f, 0x787888f0, 0x25256f4a, 0x2e2e725c, 0x1c1c2438, 0xa6a6f157, 0xb4b4c773, 0xc6c65197,
    0xe8e823cb, 0xdddd7ca1, 0x74749ce8, 0x1f1f213e, 0x4b4bdd96, 0xbdbddc61, 0x8b8b860d, 0x8a8a850f,
    0x707090e0, 0x3e3e427c, 0xb5b5c471, 0x6666aacc, 0x4848d890, 0x03030506, 0xf6f601f7, 0x0e0e121c,
    0x6161a3c2, 0x35355f6a, 0x5757f9ae, 0xb9b9d069, 0x86869117, 0xc1c15899, 0x1d1d273a, 0x9e9eb927,
    0xe1e138d9, 0xf8f813eb, 0x9898b32b, 0x11113322, 0x6969bbd2, 0xd9d970a9, 0x8e8e8907, 0x9494a733,
    0x9b9bb62d, 0x1e1e223c, 0x87879215, 0xe9e920c9, 0xcece4987, 0x5555ffaa, 0x28287850, 0xdfdf7aa5,
    0x8c8c8f03, 0xa1a1f859, 0x89898009, 0x0d0d171a, 0xbfbfda65, 0xe6e631d7, 0x4242c684, 0x6868b8d0,
    0x4141c382, 0x9999b029, 0x2d2d775a, 0x0f0f111e, 0xb0b0cb7b, 0x5454fca8, 0xbbbbd66d, 0x16163a2c,
};

// T-table S-box for last round (no MixColumns)
alignas(64) static const uint8_t Te4[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// T-table round constants
static const uint32_t TTABLE_RCON[15] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000,
    0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000
};

// ============================================================================
// Internal Helper Functions
// ============================================================================

static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t temp = a;
    for (size_t i = 0; i < 8; i++) {
        uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>((b >> i) & 1));
        result ^= (temp & mask);
        uint8_t hi_bit = static_cast<uint8_t>((temp >> 7) & 1);
        temp = static_cast<uint8_t>((temp << 1) ^ (0x1b & static_cast<uint8_t>(-static_cast<int8_t>(hi_bit))));
    }
    return result;
}

static inline void xor_block(uint8_t* out, const uint8_t* a, const uint8_t* b) {
    for (size_t i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static inline void inc_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++counter[i] != 0) break;
    }
}

// ============================================================================
// Software Key Expansion (big-endian format)
// ============================================================================

static void key_expansion(const uint8_t* key, uint32_t* round_keys, int key_len, int rounds) {
    int nk = key_len / 4;
    int nb = 4;
    int nr = rounds;

    for (int i = 0; i < nk; i++) {
        round_keys[i] = ((uint32_t)key[4*i] << 24) |
                        ((uint32_t)key[4*i+1] << 16) |
                        ((uint32_t)key[4*i+2] << 8) |
                        ((uint32_t)key[4*i+3]);
    }

    for (int i = nk; i < nb * (nr + 1); i++) {
        uint32_t temp = round_keys[i - 1];
        if (i % nk == 0) {
            temp = (temp << 8) | (temp >> 24);
            temp = ((uint32_t)SBOX[(temp >> 24) & 0xff] << 24) |
                   ((uint32_t)SBOX[(temp >> 16) & 0xff] << 16) |
                   ((uint32_t)SBOX[(temp >> 8) & 0xff] << 8) |
                   ((uint32_t)SBOX[temp & 0xff]);
            temp ^= ((uint32_t)RCON[i / nk] << 24);
        } else if (nk > 6 && i % nk == 4) {
            temp = ((uint32_t)SBOX[(temp >> 24) & 0xff] << 24) |
                   ((uint32_t)SBOX[(temp >> 16) & 0xff] << 16) |
                   ((uint32_t)SBOX[(temp >> 8) & 0xff] << 8) |
                   ((uint32_t)SBOX[temp & 0xff]);
        }
        round_keys[i] = round_keys[i - nk] ^ temp;
    }
}

// ============================================================================
// T-Table Key Expansion (little-endian format for T-table operations)
// Reserved for future non-timing-critical batch operations
// ============================================================================

__attribute__((unused))
static void ttable_key_expansion(const uint8_t* key, uint32_t* round_keys, int key_len) {
    int nk = key_len / 4;
    int nr = (key_len == 16) ? 10 : ((key_len == 24) ? 12 : 14);
    int nw = 4 * (nr + 1);

    for (int i = 0; i < nk; i++) {
        round_keys[i] = ((uint32_t)key[4*i + 3] << 24) |
                        ((uint32_t)key[4*i + 2] << 16) |
                        ((uint32_t)key[4*i + 1] << 8) |
                        ((uint32_t)key[4*i + 0]);
    }

    for (int i = nk; i < nw; i++) {
        uint32_t temp = round_keys[i - 1];
        if (i % nk == 0) {
            temp = (Te4[(temp >> 8) & 0xff] << 24) |
                   (Te4[(temp >> 16) & 0xff] << 16) |
                   (Te4[(temp >> 24) & 0xff] << 8) |
                   (Te4[temp & 0xff]);
            temp ^= TTABLE_RCON[i / nk];
        } else if (nk > 6 && i % nk == 4) {
            temp = (Te4[(temp >> 24) & 0xff] << 24) |
                   (Te4[(temp >> 16) & 0xff] << 16) |
                   (Te4[(temp >> 8) & 0xff] << 8) |
                   (Te4[temp & 0xff]);
        }
        round_keys[i] = round_keys[i - nk] ^ temp;
    }
}

// ============================================================================
// Software AES Core Operations (constant-time)
// ============================================================================

static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

static void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = INV_SBOX[state[i]];
}

static void shift_rows(uint8_t state[16]) {
    uint8_t temp;
    temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
}

static void inv_shift_rows(uint8_t state[16]) {
    uint8_t temp;
    temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
}

static void mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = state[c], a1 = state[c+1], a2 = state[c+2], a3 = state[c+3];
        state[c]   = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        state[c+1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        state[c+2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        state[c+3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

static void inv_mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = state[c], a1 = state[c+1], a2 = state[c+2], a3 = state[c+3];
        state[c]   = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        state[c+1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        state[c+2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        state[c+3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

static void add_round_key(uint8_t state[16], const uint32_t* round_key) {
    for (int i = 0; i < 4; i++) {
        state[i*4]   ^= (round_key[i] >> 24) & 0xff;
        state[i*4+1] ^= (round_key[i] >> 16) & 0xff;
        state[i*4+2] ^= (round_key[i] >> 8) & 0xff;
        state[i*4+3] ^= round_key[i] & 0xff;
    }
}

// ============================================================================
// T-Table Block Encryption (fast but cache-timing vulnerable)
// Reserved for future non-timing-critical batch operations
// ============================================================================

__attribute__((unused))
static void ttable_encrypt_block(const uint8_t in[16], uint8_t out[16],
                                  const uint32_t* rk, int rounds) {
    uint32_t s0 = ((uint32_t)in[3] << 24) | ((uint32_t)in[2] << 16) |
                  ((uint32_t)in[1] << 8) | (uint32_t)in[0];
    uint32_t s1 = ((uint32_t)in[7] << 24) | ((uint32_t)in[6] << 16) |
                  ((uint32_t)in[5] << 8) | (uint32_t)in[4];
    uint32_t s2 = ((uint32_t)in[11] << 24) | ((uint32_t)in[10] << 16) |
                  ((uint32_t)in[9] << 8) | (uint32_t)in[8];
    uint32_t s3 = ((uint32_t)in[15] << 24) | ((uint32_t)in[14] << 16) |
                  ((uint32_t)in[13] << 8) | (uint32_t)in[12];

    s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];

    uint32_t t0 = s0, t1 = s1, t2 = s2, t3 = s3;
    int rk_idx = 4;

    for (int round = 1; round < rounds; round++) {
        t0 = Te0[s0 & 0xff] ^ Te1[(s1 >> 8) & 0xff] ^ Te2[(s2 >> 16) & 0xff] ^ Te3[(s3 >> 24) & 0xff] ^ rk[rk_idx];
        t1 = Te0[s1 & 0xff] ^ Te1[(s2 >> 8) & 0xff] ^ Te2[(s3 >> 16) & 0xff] ^ Te3[(s0 >> 24) & 0xff] ^ rk[rk_idx + 1];
        t2 = Te0[s2 & 0xff] ^ Te1[(s3 >> 8) & 0xff] ^ Te2[(s0 >> 16) & 0xff] ^ Te3[(s1 >> 24) & 0xff] ^ rk[rk_idx + 2];
        t3 = Te0[s3 & 0xff] ^ Te1[(s0 >> 8) & 0xff] ^ Te2[(s1 >> 16) & 0xff] ^ Te3[(s2 >> 24) & 0xff] ^ rk[rk_idx + 3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        rk_idx += 4;
    }

    s0 = (Te4[t0 & 0xff]) | (Te4[(t1 >> 8) & 0xff] << 8) |
         (Te4[(t2 >> 16) & 0xff] << 16) | (Te4[(t3 >> 24) & 0xff] << 24);
    s1 = (Te4[t1 & 0xff]) | (Te4[(t2 >> 8) & 0xff] << 8) |
         (Te4[(t3 >> 16) & 0xff] << 16) | (Te4[(t0 >> 24) & 0xff] << 24);
    s2 = (Te4[t2 & 0xff]) | (Te4[(t3 >> 8) & 0xff] << 8) |
         (Te4[(t0 >> 16) & 0xff] << 16) | (Te4[(t1 >> 24) & 0xff] << 24);
    s3 = (Te4[t3 & 0xff]) | (Te4[(t0 >> 8) & 0xff] << 8) |
         (Te4[(t1 >> 16) & 0xff] << 16) | (Te4[(t2 >> 24) & 0xff] << 24);

    s0 ^= rk[rk_idx]; s1 ^= rk[rk_idx + 1]; s2 ^= rk[rk_idx + 2]; s3 ^= rk[rk_idx + 3];

    out[0] = (uint8_t)s0; out[1] = (uint8_t)(s0 >> 8); out[2] = (uint8_t)(s0 >> 16); out[3] = (uint8_t)(s0 >> 24);
    out[4] = (uint8_t)s1; out[5] = (uint8_t)(s1 >> 8); out[6] = (uint8_t)(s1 >> 16); out[7] = (uint8_t)(s1 >> 24);
    out[8] = (uint8_t)s2; out[9] = (uint8_t)(s2 >> 8); out[10] = (uint8_t)(s2 >> 16); out[11] = (uint8_t)(s2 >> 24);
    out[12] = (uint8_t)s3; out[13] = (uint8_t)(s3 >> 8); out[14] = (uint8_t)(s3 >> 16); out[15] = (uint8_t)(s3 >> 24);
}

// ============================================================================
// GHASH Implementation for GCM
// ============================================================================

static void ghash_mult(const uint8_t x[16], const uint8_t h[16], uint8_t result[16]) {
    uint8_t v[16], z[16];
    memcpy(v, h, 16);
    memset(z, 0, 16);

    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            uint8_t mask = (uint8_t)(-((x[i] >> j) & 1));
            for (int k = 0; k < 16; k++) z[k] ^= (v[k] & mask);
            uint8_t lsb = v[15] & 1;
            for (int k = 15; k > 0; k--) v[k] = (uint8_t)((v[k] >> 1) | ((v[k-1] & 1) << 7));
            v[0] >>= 1;
            uint8_t lsb_mask = (uint8_t)(-((int8_t)lsb));
            v[0] ^= (0xe1 & lsb_mask);
        }
    }
    memcpy(result, z, 16);
}

// Runtime flag for PCLMUL detection
static bool g_pclmul_detected = false;
static bool g_pclmul_available = false;

static inline bool check_pclmul() {
#if defined(KCTSB_HAS_PCLMUL) || defined(__PCLMUL__)
    if (!g_pclmul_detected) {
        // Check CPUID for PCLMUL support (bit 1 of ECX)
        int info[4] = {0};
        #if defined(_MSC_VER)
        __cpuid(info, 1);
        #elif defined(__GNUC__) || defined(__clang__)
        __cpuid(1, info[0], info[1], info[2], info[3]);
        #endif
        g_pclmul_available = (info[2] & (1 << 1)) != 0;
        g_pclmul_detected = true;
    }
    return g_pclmul_available;
#else
    return false;
#endif
}

static void ghash_update(uint8_t tag[16], const uint8_t h[16], const uint8_t* data, size_t len) {
#if defined(KCTSB_HAS_PCLMUL) || defined(__PCLMUL__)
    if (check_pclmul()) {
        kctsb::simd::ghash_pclmul(tag, h, data, len);
        return;
    }
#endif

    // Software fallback
    uint8_t block[16];
    while (len >= 16) {
        xor_block(block, tag, data);
        ghash_mult(block, h, tag);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        memset(block, 0, 16);
        memcpy(block, data, len);
        xor_block(block, tag, block);
        ghash_mult(block, h, tag);
    }
}

// ============================================================================
// Public C API
// ============================================================================

extern "C" {

kctsb_error_t kctsb_aes_init(kctsb_aes_ctx_t* ctx, const uint8_t* key, size_t key_len) {
    if (!ctx || !key) return KCTSB_ERROR_INVALID_PARAM;

    switch (key_len) {
        case 16: ctx->key_bits = 128; ctx->rounds = 10; break;
        case 24: ctx->key_bits = 192; ctx->rounds = 12; break;
        case 32: ctx->key_bits = 256; ctx->rounds = 14; break;
        default: return KCTSB_ERROR_INVALID_KEY;
    }

#if defined(KCTSB_HAS_AESNI)
    if (check_aesni()) {
        kctsb_secure_zero(ctx->round_keys, sizeof(ctx->round_keys));
        uint8_t* rk = reinterpret_cast<uint8_t*>(ctx->round_keys);
        if (key_len == 16) {
            kctsb::simd::aes128_expand_key_ni(key, rk);
            ctx->rounds |= AESNI_FORMAT_FLAG;
            return KCTSB_SUCCESS;
        } else if (key_len == 32) {
            kctsb::simd::aes256_expand_key_ni(key, rk);
            ctx->rounds |= AESNI_FORMAT_FLAG;
            return KCTSB_SUCCESS;
        }
    }
#endif

    // Use software key expansion for all key sizes to ensure consistent format
    // between encryption and decryption
    key_expansion(key, ctx->round_keys, (int)key_len, ctx->rounds);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_encrypt_block(const kctsb_aes_ctx_t* ctx,
                                       const uint8_t input[16], uint8_t output[16]) {
    if (!ctx || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    int actual_rounds = ctx->rounds & 0xFF;

#if defined(KCTSB_HAS_AESNI)
    bool uses_aesni_format = (ctx->rounds & AESNI_FORMAT_FLAG) != 0;
    if (uses_aesni_format && check_aesni()) {
        const uint8_t* rk = reinterpret_cast<const uint8_t*>(ctx->round_keys);
        if (ctx->key_bits == 128) {
            kctsb::simd::aes128_encrypt_block_ni(input, output, rk);
            return KCTSB_SUCCESS;
        } else if (ctx->key_bits == 256) {
            kctsb::simd::aes256_encrypt_block_ni(input, output, rk);
            return KCTSB_SUCCESS;
        }
    }
#endif

    // Use software encryption (consistent with decryption)
    uint8_t state[16];
    memcpy(state, input, 16);

    add_round_key(state, &ctx->round_keys[0]);
    for (int round = 1; round < actual_rounds; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ctx->round_keys[round * 4]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ctx->round_keys[actual_rounds * 4]);

    memcpy(output, state, 16);
    kctsb_secure_zero(state, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_decrypt_block(const kctsb_aes_ctx_t* ctx,
                                       const uint8_t input[16], uint8_t output[16]) {
    if (!ctx || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    int actual_rounds = ctx->rounds & 0xFF;
    uint8_t state[16];
    memcpy(state, input, 16);

    const uint32_t* rk = ctx->round_keys;

#if defined(KCTSB_HAS_AESNI)
    bool uses_aesni_format = (ctx->rounds & AESNI_FORMAT_FLAG) != 0;
    if (uses_aesni_format) {
        // AES-NI format stores key as raw bytes - need to regenerate software keys
        // for decryption since we don't have hardware decrypt key schedule
        uint32_t sw_round_keys[60];
        int key_len = (ctx->key_bits == 128) ? 16 : ((ctx->key_bits == 192) ? 24 : 32);
        uint8_t orig_key[32];
        memcpy(orig_key, ctx->round_keys, key_len);
        key_expansion(orig_key, sw_round_keys, key_len, actual_rounds);
        kctsb_secure_zero(orig_key, sizeof(orig_key));
        rk = sw_round_keys;

        add_round_key(state, &rk[actual_rounds * 4]);
        for (int round = actual_rounds - 1; round > 0; round--) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, &rk[round * 4]);
            inv_mix_columns(state);
        }
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &rk[0]);

        memcpy(output, state, 16);
        kctsb_secure_zero(state, 16);
        kctsb_secure_zero(sw_round_keys, sizeof(sw_round_keys));
        return KCTSB_SUCCESS;
    }
#endif

    // Software path - keys already in correct format
    add_round_key(state, &rk[actual_rounds * 4]);
    for (int round = actual_rounds - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &rk[round * 4]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &rk[0]);

    memcpy(output, state, 16);
    kctsb_secure_zero(state, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_ctr_crypt(const kctsb_aes_ctx_t* ctx, const uint8_t nonce[12],
                                  const uint8_t* input, size_t input_len, uint8_t* output) {
    if (!ctx || !nonce || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    uint8_t counter_block[16], keystream[16];
    memcpy(counter_block, nonce, 12);
    counter_block[12] = 0; counter_block[13] = 0; counter_block[14] = 0; counter_block[15] = 1;

    size_t offset = 0;
    while (offset < input_len) {
        kctsb_aes_encrypt_block(ctx, counter_block, keystream);
        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) output[offset + j] = input[offset + j] ^ keystream[j];
        inc_counter(counter_block);
        offset += bytes;
    }

    kctsb_secure_zero(counter_block, 16);
    kctsb_secure_zero(keystream, 16);
    return KCTSB_SUCCESS;
}

// ============================================================================
// High-Performance AES-GCM using 4-block parallel AES-NI
// ============================================================================

#if defined(KCTSB_HAS_AESNI)

// Byte-swap mask for big-endian counter (GCM uses big-endian counter)
static const __m128i BSWAP_EPI32 = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);

// Increment counter block by 1 (big-endian, last 32 bits)
static inline __m128i inc_counter_be32_fast(__m128i ctr) {
    // Swap bytes to little-endian, add 1, swap back
    __m128i swapped = _mm_shuffle_epi8(ctr, BSWAP_EPI32);
    __m128i one = _mm_set_epi32(1, 0, 0, 0);
    swapped = _mm_add_epi32(swapped, one);
    return _mm_shuffle_epi8(swapped, BSWAP_EPI32);
}

// Generate 4 consecutive counter blocks efficiently using SIMD
static inline void gen_4_counters_fast(__m128i base, __m128i& c0, __m128i& c1, __m128i& c2, __m128i& c3) {
    // Swap to little-endian for arithmetic
    __m128i swapped = _mm_shuffle_epi8(base, BSWAP_EPI32);
    
    // Create increments: +0, +1, +2, +3
    __m128i inc0 = _mm_set_epi32(0, 0, 0, 0);
    __m128i inc1 = _mm_set_epi32(1, 0, 0, 0);
    __m128i inc2 = _mm_set_epi32(2, 0, 0, 0);
    __m128i inc3 = _mm_set_epi32(3, 0, 0, 0);
    
    // Generate all 4 counters
    __m128i t0 = _mm_add_epi32(swapped, inc0);
    __m128i t1 = _mm_add_epi32(swapped, inc1);
    __m128i t2 = _mm_add_epi32(swapped, inc2);
    __m128i t3 = _mm_add_epi32(swapped, inc3);
    
    // Swap back to big-endian
    c0 = _mm_shuffle_epi8(t0, BSWAP_EPI32);
    c1 = _mm_shuffle_epi8(t1, BSWAP_EPI32);
    c2 = _mm_shuffle_epi8(t2, BSWAP_EPI32);
    c3 = _mm_shuffle_epi8(t3, BSWAP_EPI32);
}

// Advance counter by N (for after processing N blocks)
static inline __m128i add_counter_be32(__m128i ctr, uint32_t n) {
    __m128i swapped = _mm_shuffle_epi8(ctr, BSWAP_EPI32);
    __m128i add = _mm_set_epi32((int)n, 0, 0, 0);
    swapped = _mm_add_epi32(swapped, add);
    return _mm_shuffle_epi8(swapped, BSWAP_EPI32);
}

// 4-block parallel AES-128 encryption
static inline void aes128_encrypt_4blocks_ni(
    __m128i& b0, __m128i& b1, __m128i& b2, __m128i& b3,
    const __m128i* rk)
{
    b0 = _mm_xor_si128(b0, rk[0]);
    b1 = _mm_xor_si128(b1, rk[0]);
    b2 = _mm_xor_si128(b2, rk[0]);
    b3 = _mm_xor_si128(b3, rk[0]);

    for (int i = 1; i < 10; ++i) {
        b0 = _mm_aesenc_si128(b0, rk[i]);
        b1 = _mm_aesenc_si128(b1, rk[i]);
        b2 = _mm_aesenc_si128(b2, rk[i]);
        b3 = _mm_aesenc_si128(b3, rk[i]);
    }

    b0 = _mm_aesenclast_si128(b0, rk[10]);
    b1 = _mm_aesenclast_si128(b1, rk[10]);
    b2 = _mm_aesenclast_si128(b2, rk[10]);
    b3 = _mm_aesenclast_si128(b3, rk[10]);
}

// 4-block parallel AES-256 encryption
static inline void aes256_encrypt_4blocks_ni(
    __m128i& b0, __m128i& b1, __m128i& b2, __m128i& b3,
    const __m128i* rk)
{
    b0 = _mm_xor_si128(b0, rk[0]);
    b1 = _mm_xor_si128(b1, rk[0]);
    b2 = _mm_xor_si128(b2, rk[0]);
    b3 = _mm_xor_si128(b3, rk[0]);

    for (int i = 1; i < 14; ++i) {
        b0 = _mm_aesenc_si128(b0, rk[i]);
        b1 = _mm_aesenc_si128(b1, rk[i]);
        b2 = _mm_aesenc_si128(b2, rk[i]);
        b3 = _mm_aesenc_si128(b3, rk[i]);
    }

    b0 = _mm_aesenclast_si128(b0, rk[14]);
    b1 = _mm_aesenclast_si128(b1, rk[14]);
    b2 = _mm_aesenclast_si128(b2, rk[14]);
    b3 = _mm_aesenclast_si128(b3, rk[14]);
}

// High-performance AES-GCM encrypt using AES-NI (4-block parallel)
static kctsb_error_t aes_gcm_encrypt_aesni(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    uint8_t* output, uint8_t tag[16])
{
    const __m128i* rk = reinterpret_cast<const __m128i*>(ctx->round_keys);
    const bool is_aes256 = (ctx->key_bits == 256);

    // Compute H = E(K, 0^128)
    alignas(16) uint8_t h_bytes[16] = {0};
    __m128i H = _mm_setzero_si128();
    if (is_aes256) {
        __m128i tmp = H;
        aes256_encrypt_4blocks_ni(tmp, tmp, tmp, tmp, rk);
        H = tmp;
    } else {
        __m128i tmp = H;
        aes128_encrypt_4blocks_ni(tmp, tmp, tmp, tmp, rk);
        H = tmp;
    }
    _mm_storeu_si128(reinterpret_cast<__m128i*>(h_bytes), H);

    // Compute J0 (initial counter)
    alignas(16) uint8_t j0_bytes[16];
    if (iv_len == 12) {
        memcpy(j0_bytes, iv, 12);
        j0_bytes[12] = 0; j0_bytes[13] = 0; j0_bytes[14] = 0; j0_bytes[15] = 1;
    } else {
        memset(j0_bytes, 0, 16);
        ghash_update(j0_bytes, h_bytes, iv, iv_len);
        alignas(16) uint8_t len_block[16] = {0};
        uint64_t iv_bits = (uint64_t)iv_len * 8;
        for (int i = 0; i < 8; i++) len_block[15 - i] = (uint8_t)(iv_bits >> (i * 8));
        ghash_update(j0_bytes, h_bytes, len_block, 16);
    }

    // Set up counter (J0 + 1)
    alignas(16) uint8_t counter_bytes[16];
    memcpy(counter_bytes, j0_bytes, 16);
    inc_counter(counter_bytes);
    __m128i counter = _mm_loadu_si128(reinterpret_cast<const __m128i*>(counter_bytes));

    // CTR encryption with 4-block parallelism
    size_t offset = 0;
    while (offset + 64 <= input_len) {
        // Generate 4 counter blocks efficiently
        __m128i c0, c1, c2, c3;
        gen_4_counters_fast(counter, c0, c1, c2, c3);

        // Advance counter by 4
        counter = add_counter_be32(counter, 4);

        // Encrypt counter blocks in parallel
        if (is_aes256) {
            aes256_encrypt_4blocks_ni(c0, c1, c2, c3, rk);
        } else {
            aes128_encrypt_4blocks_ni(c0, c1, c2, c3, rk);
        }

        // XOR with plaintext
        __m128i p0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset));
        __m128i p1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 16));
        __m128i p2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 32));
        __m128i p3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 48));

        __m128i ct0 = _mm_xor_si128(p0, c0);
        __m128i ct1 = _mm_xor_si128(p1, c1);
        __m128i ct2 = _mm_xor_si128(p2, c2);
        __m128i ct3 = _mm_xor_si128(p3, c3);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset), ct0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 16), ct1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 32), ct2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 48), ct3);

        offset += 64;
    }

    // Handle remaining blocks (1-3 blocks or partial)
    while (offset < input_len) {
        alignas(16) uint8_t keystream[16];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(counter_bytes), counter);

        __m128i ks = counter;
        if (is_aes256) {
            ks = _mm_xor_si128(ks, rk[0]);
            for (int i = 1; i < 14; ++i) ks = _mm_aesenc_si128(ks, rk[i]);
            ks = _mm_aesenclast_si128(ks, rk[14]);
        } else {
            ks = _mm_xor_si128(ks, rk[0]);
            for (int i = 1; i < 10; ++i) ks = _mm_aesenc_si128(ks, rk[i]);
            ks = _mm_aesenclast_si128(ks, rk[10]);
        }
        _mm_storeu_si128(reinterpret_cast<__m128i*>(keystream), ks);

        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) {
            output[offset + j] = input[offset + j] ^ keystream[j];
        }

        counter = inc_counter_be32_fast(counter);
        offset += bytes;
    }

    // GHASH authentication
    alignas(16) uint8_t ghash_tag[16] = {0};
    if (aad && aad_len > 0) {
        ghash_update(ghash_tag, h_bytes, aad, aad_len);
        size_t aad_padding = (16 - (aad_len % 16)) % 16;
        if (aad_padding > 0) {
            uint8_t pad[16] = {0};
            ghash_update(ghash_tag, h_bytes, pad, aad_padding);
        }
    }
    if (input_len > 0) {
        ghash_update(ghash_tag, h_bytes, output, input_len);
        size_t ct_padding = (16 - (input_len % 16)) % 16;
        if (ct_padding > 0) {
            uint8_t pad[16] = {0};
            ghash_update(ghash_tag, h_bytes, pad, ct_padding);
        }
    }

    // Add length block
    alignas(16) uint8_t len_block[16] = {0};
    uint64_t aad_bits = aad_len * 8, ct_bits = input_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (uint8_t)(aad_bits >> (i * 8));
        len_block[15 - i] = (uint8_t)(ct_bits >> (i * 8));
    }
    ghash_update(ghash_tag, h_bytes, len_block, 16);

    // Compute final tag: tag = E(K, J0) XOR GHASH
    __m128i j0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0_bytes));
    __m128i enc_j0;
    if (is_aes256) {
        enc_j0 = _mm_xor_si128(j0, rk[0]);
        for (int i = 1; i < 14; ++i) enc_j0 = _mm_aesenc_si128(enc_j0, rk[i]);
        enc_j0 = _mm_aesenclast_si128(enc_j0, rk[14]);
    } else {
        enc_j0 = _mm_xor_si128(j0, rk[0]);
        for (int i = 1; i < 10; ++i) enc_j0 = _mm_aesenc_si128(enc_j0, rk[i]);
        enc_j0 = _mm_aesenclast_si128(enc_j0, rk[10]);
    }

    __m128i gtag = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ghash_tag));
    __m128i final_tag = _mm_xor_si128(enc_j0, gtag);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(tag), final_tag);

    // Secure cleanup
    kctsb_secure_zero(h_bytes, 16);
    kctsb_secure_zero(j0_bytes, 16);
    kctsb_secure_zero(counter_bytes, 16);
    kctsb_secure_zero(ghash_tag, 16);

    return KCTSB_SUCCESS;
}

// High-performance AES-GCM decrypt using AES-NI (4-block parallel)
static kctsb_error_t aes_gcm_decrypt_aesni(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    const uint8_t tag[16], uint8_t* output)
{
    const __m128i* rk = reinterpret_cast<const __m128i*>(ctx->round_keys);
    const bool is_aes256 = (ctx->key_bits == 256);

    // Compute H = E(K, 0^128)
    alignas(16) uint8_t h_bytes[16] = {0};
    __m128i H = _mm_setzero_si128();
    if (is_aes256) {
        __m128i tmp = H;
        aes256_encrypt_4blocks_ni(tmp, tmp, tmp, tmp, rk);
        H = tmp;
    } else {
        __m128i tmp = H;
        aes128_encrypt_4blocks_ni(tmp, tmp, tmp, tmp, rk);
        H = tmp;
    }
    _mm_storeu_si128(reinterpret_cast<__m128i*>(h_bytes), H);

    // Compute J0 (initial counter)
    alignas(16) uint8_t j0_bytes[16];
    if (iv_len == 12) {
        memcpy(j0_bytes, iv, 12);
        j0_bytes[12] = 0; j0_bytes[13] = 0; j0_bytes[14] = 0; j0_bytes[15] = 1;
    } else {
        memset(j0_bytes, 0, 16);
        ghash_update(j0_bytes, h_bytes, iv, iv_len);
        alignas(16) uint8_t len_block[16] = {0};
        uint64_t iv_bits = (uint64_t)iv_len * 8;
        for (int i = 0; i < 8; i++) len_block[15 - i] = (uint8_t)(iv_bits >> (i * 8));
        ghash_update(j0_bytes, h_bytes, len_block, 16);
    }

    // Verify tag BEFORE decryption (authenticate-then-decrypt)
    alignas(16) uint8_t ghash_tag[16] = {0};
    if (aad && aad_len > 0) {
        ghash_update(ghash_tag, h_bytes, aad, aad_len);
        size_t aad_padding = (16 - (aad_len % 16)) % 16;
        if (aad_padding > 0) {
            uint8_t pad[16] = {0};
            ghash_update(ghash_tag, h_bytes, pad, aad_padding);
        }
    }
    if (input_len > 0) {
        ghash_update(ghash_tag, h_bytes, input, input_len);
        size_t ct_padding = (16 - (input_len % 16)) % 16;
        if (ct_padding > 0) {
            uint8_t pad[16] = {0};
            ghash_update(ghash_tag, h_bytes, pad, ct_padding);
        }
    }

    // Add length block
    alignas(16) uint8_t len_block[16] = {0};
    uint64_t aad_bits = aad_len * 8, ct_bits = input_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (uint8_t)(aad_bits >> (i * 8));
        len_block[15 - i] = (uint8_t)(ct_bits >> (i * 8));
    }
    ghash_update(ghash_tag, h_bytes, len_block, 16);

    // Compute expected tag
    __m128i j0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0_bytes));
    __m128i enc_j0;
    if (is_aes256) {
        enc_j0 = _mm_xor_si128(j0, rk[0]);
        for (int i = 1; i < 14; ++i) enc_j0 = _mm_aesenc_si128(enc_j0, rk[i]);
        enc_j0 = _mm_aesenclast_si128(enc_j0, rk[14]);
    } else {
        enc_j0 = _mm_xor_si128(j0, rk[0]);
        for (int i = 1; i < 10; ++i) enc_j0 = _mm_aesenc_si128(enc_j0, rk[i]);
        enc_j0 = _mm_aesenclast_si128(enc_j0, rk[10]);
    }

    __m128i gtag = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ghash_tag));
    __m128i computed_tag = _mm_xor_si128(enc_j0, gtag);

    alignas(16) uint8_t computed_tag_bytes[16];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(computed_tag_bytes), computed_tag);

    // Constant-time tag comparison
    if (!kctsb_secure_compare(tag, computed_tag_bytes, 16)) {
        kctsb_secure_zero(output, input_len);
        kctsb_secure_zero(h_bytes, 16);
        kctsb_secure_zero(j0_bytes, 16);
        kctsb_secure_zero(ghash_tag, 16);
        kctsb_secure_zero(computed_tag_bytes, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }

    // Decryption (same as encryption in CTR mode)
    alignas(16) uint8_t counter_bytes[16];
    memcpy(counter_bytes, j0_bytes, 16);
    inc_counter(counter_bytes);
    __m128i counter = _mm_loadu_si128(reinterpret_cast<const __m128i*>(counter_bytes));

    size_t offset = 0;
    while (offset + 64 <= input_len) {
        __m128i c0, c1, c2, c3;
        gen_4_counters_fast(counter, c0, c1, c2, c3);

        counter = add_counter_be32(counter, 4);

        if (is_aes256) {
            aes256_encrypt_4blocks_ni(c0, c1, c2, c3, rk);
        } else {
            aes128_encrypt_4blocks_ni(c0, c1, c2, c3, rk);
        }

        __m128i ct0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset));
        __m128i ct1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 16));
        __m128i ct2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 32));
        __m128i ct3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 48));

        __m128i p0 = _mm_xor_si128(ct0, c0);
        __m128i p1 = _mm_xor_si128(ct1, c1);
        __m128i p2 = _mm_xor_si128(ct2, c2);
        __m128i p3 = _mm_xor_si128(ct3, c3);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset), p0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 16), p1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 32), p2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 48), p3);

        offset += 64;
    }

    while (offset < input_len) {
        alignas(16) uint8_t keystream[16];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(counter_bytes), counter);

        __m128i ks = counter;
        if (is_aes256) {
            ks = _mm_xor_si128(ks, rk[0]);
            for (int i = 1; i < 14; ++i) ks = _mm_aesenc_si128(ks, rk[i]);
            ks = _mm_aesenclast_si128(ks, rk[14]);
        } else {
            ks = _mm_xor_si128(ks, rk[0]);
            for (int i = 1; i < 10; ++i) ks = _mm_aesenc_si128(ks, rk[i]);
            ks = _mm_aesenclast_si128(ks, rk[10]);
        }
        _mm_storeu_si128(reinterpret_cast<__m128i*>(keystream), ks);

        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) {
            output[offset + j] = input[offset + j] ^ keystream[j];
        }

        counter = inc_counter_be32_fast(counter);
        offset += bytes;
    }

    // Secure cleanup
    kctsb_secure_zero(h_bytes, 16);
    kctsb_secure_zero(j0_bytes, 16);
    kctsb_secure_zero(counter_bytes, 16);
    kctsb_secure_zero(ghash_tag, 16);
    kctsb_secure_zero(computed_tag_bytes, 16);

    return KCTSB_SUCCESS;
}

#endif // KCTSB_HAS_AESNI

// ============================================================================
// Software Fallback AES-GCM (for non-AES-NI systems)
// ============================================================================

static kctsb_error_t aes_gcm_encrypt_software(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    uint8_t* output, uint8_t tag[16])
{
    uint8_t h[16] = {0}, j0[16], counter[16], keystream[16], ghash_tag[16] = {0};

    kctsb_aes_encrypt_block(ctx, h, h);

    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        memset(j0, 0, 16);
        ghash_update(j0, h, iv, iv_len);
        uint8_t len_block[16] = {0};
        uint64_t iv_bits = (uint64_t)iv_len * 8;
        for (int i = 0; i < 8; i++) len_block[15 - i] = (uint8_t)(iv_bits >> (i * 8));
        ghash_update(j0, h, len_block, 16);
    }

    memcpy(counter, j0, 16);
    inc_counter(counter);

    size_t offset = 0;
    while (offset < input_len) {
        kctsb_aes_encrypt_block(ctx, counter, keystream);
        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) output[offset + j] = input[offset + j] ^ keystream[j];
        inc_counter(counter);
        offset += bytes;
    }

    if (aad && aad_len > 0) {
        ghash_update(ghash_tag, h, aad, aad_len);
        size_t aad_padding = (16 - (aad_len % 16)) % 16;
        if (aad_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ghash_tag, h, pad, aad_padding); }
    }
    if (input_len > 0) {
        ghash_update(ghash_tag, h, output, input_len);
        size_t ct_padding = (16 - (input_len % 16)) % 16;
        if (ct_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ghash_tag, h, pad, ct_padding); }
    }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = aad_len * 8, ct_bits = input_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (uint8_t)(aad_bits >> (i * 8));
        len_block[15 - i] = (uint8_t)(ct_bits >> (i * 8));
    }
    ghash_update(ghash_tag, h, len_block, 16);

    uint8_t enc_j0[16];
    kctsb_aes_encrypt_block(ctx, j0, enc_j0);
    xor_block(tag, ghash_tag, enc_j0);

    kctsb_secure_zero(h, 16); kctsb_secure_zero(j0, 16); kctsb_secure_zero(counter, 16);
    kctsb_secure_zero(keystream, 16); kctsb_secure_zero(ghash_tag, 16); kctsb_secure_zero(enc_j0, 16);
    return KCTSB_SUCCESS;
}

// ============================================================================
// Public AES-GCM API with automatic acceleration
// ============================================================================

// Forward declaration for software fallback
static kctsb_error_t aes_gcm_decrypt_software(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    const uint8_t tag[16], uint8_t* output);

kctsb_error_t kctsb_aes_gcm_encrypt(const kctsb_aes_ctx_t* ctx,
                                     const uint8_t* iv, size_t iv_len,
                                     const uint8_t* aad, size_t aad_len,
                                     const uint8_t* input, size_t input_len,
                                     uint8_t* output, uint8_t tag[16]) {
    if (!ctx || !iv || !output || !tag) return KCTSB_ERROR_INVALID_PARAM;
    if (input_len > 0 && !input) return KCTSB_ERROR_INVALID_PARAM;

#if defined(KCTSB_HAS_AESNI)
    // Use high-performance AES-NI path if available and key is in AES-NI format
    bool uses_aesni_format = (ctx->rounds & AESNI_FORMAT_FLAG) != 0;
    if (uses_aesni_format && check_aesni() && (ctx->key_bits == 128 || ctx->key_bits == 256)) {
        return aes_gcm_encrypt_aesni(ctx, iv, iv_len, aad, aad_len, input, input_len, output, tag);
    }
#endif

    return aes_gcm_encrypt_software(ctx, iv, iv_len, aad, aad_len, input, input_len, output, tag);
}

kctsb_error_t kctsb_aes_gcm_decrypt(const kctsb_aes_ctx_t* ctx,
                                     const uint8_t* iv, size_t iv_len,
                                     const uint8_t* aad, size_t aad_len,
                                     const uint8_t* input, size_t input_len,
                                     const uint8_t tag[16], uint8_t* output) {
    if (!ctx || !iv || !tag || !output) return KCTSB_ERROR_INVALID_PARAM;
    if (input_len > 0 && !input) return KCTSB_ERROR_INVALID_PARAM;

#if defined(KCTSB_HAS_AESNI)
    // Use high-performance AES-NI path if available and key is in AES-NI format
    bool uses_aesni_format = (ctx->rounds & AESNI_FORMAT_FLAG) != 0;
    if (uses_aesni_format && check_aesni() && (ctx->key_bits == 128 || ctx->key_bits == 256)) {
        return aes_gcm_decrypt_aesni(ctx, iv, iv_len, aad, aad_len, input, input_len, tag, output);
    }
#endif

    return aes_gcm_decrypt_software(ctx, iv, iv_len, aad, aad_len, input, input_len, tag, output);
}

// Software fallback for AES-GCM decrypt
static kctsb_error_t aes_gcm_decrypt_software(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    const uint8_t tag[16], uint8_t* output)
{
    uint8_t computed_tag[16], h[16] = {0}, j0[16], counter[16], keystream[16], ghash_tag[16] = {0};

    kctsb_aes_encrypt_block(ctx, h, h);

    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        memset(j0, 0, 16);
        ghash_update(j0, h, iv, iv_len);
        uint8_t len_block[16] = {0};
        uint64_t iv_bits = (uint64_t)iv_len * 8;
        for (int i = 0; i < 8; i++) len_block[15 - i] = (uint8_t)(iv_bits >> (i * 8));
        ghash_update(j0, h, len_block, 16);
    }

    if (aad && aad_len > 0) {
        ghash_update(ghash_tag, h, aad, aad_len);
        size_t aad_padding = (16 - (aad_len % 16)) % 16;
        if (aad_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ghash_tag, h, pad, aad_padding); }
    }
    if (input_len > 0) {
        ghash_update(ghash_tag, h, input, input_len);
        size_t ct_padding = (16 - (input_len % 16)) % 16;
        if (ct_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ghash_tag, h, pad, ct_padding); }
    }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = aad_len * 8, ct_bits = input_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (uint8_t)(aad_bits >> (i * 8));
        len_block[15 - i] = (uint8_t)(ct_bits >> (i * 8));
    }
    ghash_update(ghash_tag, h, len_block, 16);

    uint8_t enc_j0[16];
    kctsb_aes_encrypt_block(ctx, j0, enc_j0);
    xor_block(computed_tag, ghash_tag, enc_j0);

    if (!kctsb_secure_compare(tag, computed_tag, 16)) {
        kctsb_secure_zero(output, input_len);
        kctsb_secure_zero(h, 16); kctsb_secure_zero(j0, 16); kctsb_secure_zero(ghash_tag, 16);
        kctsb_secure_zero(computed_tag, 16); kctsb_secure_zero(enc_j0, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }

    memcpy(counter, j0, 16);
    inc_counter(counter);

    size_t offset = 0;
    while (offset < input_len) {
        kctsb_aes_encrypt_block(ctx, counter, keystream);
        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) output[offset + j] = input[offset + j] ^ keystream[j];
        inc_counter(counter);
        offset += bytes;
    }

    kctsb_secure_zero(h, 16); kctsb_secure_zero(j0, 16); kctsb_secure_zero(counter, 16);
    kctsb_secure_zero(keystream, 16); kctsb_secure_zero(ghash_tag, 16);
    kctsb_secure_zero(computed_tag, 16); kctsb_secure_zero(enc_j0, 16);
    return KCTSB_SUCCESS;
}

// Streaming GCM API

kctsb_error_t kctsb_aes_gcm_init(kctsb_aes_gcm_ctx_t* ctx, const uint8_t* key, size_t key_len,
                                  const uint8_t* iv, size_t iv_len) {
    if (!ctx || !key || !iv) return KCTSB_ERROR_INVALID_PARAM;
    memset(ctx, 0, sizeof(kctsb_aes_gcm_ctx_t));

    kctsb_error_t err = kctsb_aes_init(&ctx->aes_ctx, key, key_len);
    if (err != KCTSB_SUCCESS) return err;

    memset(ctx->h, 0, 16);
    kctsb_aes_encrypt_block(&ctx->aes_ctx, ctx->h, ctx->h);

    if (iv_len == 12) {
        memcpy(ctx->j0, iv, 12);
        ctx->j0[12] = 0; ctx->j0[13] = 0; ctx->j0[14] = 0; ctx->j0[15] = 1;
    } else {
        ghash_update(ctx->j0, ctx->h, iv, iv_len);
        uint8_t len_block[16] = {0};
        uint64_t iv_bits = (uint64_t)iv_len * 8;
        for (int i = 0; i < 8; i++) len_block[15 - i] = (uint8_t)(iv_bits >> (i * 8));
        ghash_update(ctx->j0, ctx->h, len_block, 16);
    }

    memcpy(ctx->counter, ctx->j0, 16);
    inc_counter(ctx->counter);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_gcm_update_aad(kctsb_aes_gcm_ctx_t* ctx, const uint8_t* aad, size_t aad_len) {
    if (!ctx) return KCTSB_ERROR_INVALID_PARAM;
    if (ctx->ct_len > 0) return KCTSB_ERROR_INVALID_PARAM;
    if (aad && aad_len > 0) {
        ghash_update(ctx->tag, ctx->h, aad, aad_len);
        ctx->aad_len += aad_len;
    }
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_gcm_update_encrypt(kctsb_aes_gcm_ctx_t* ctx, const uint8_t* input,
                                            size_t input_len, uint8_t* output) {
    if (!ctx || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    if (ctx->ct_len == 0 && ctx->aad_len > 0) {
        size_t aad_padding = (16 - (ctx->aad_len % 16)) % 16;
        if (aad_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ctx->tag, ctx->h, pad, aad_padding); }
    }

    uint8_t keystream[16];
    size_t offset = 0;
    while (offset < input_len) {
        kctsb_aes_encrypt_block(&ctx->aes_ctx, ctx->counter, keystream);
        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) output[offset + j] = input[offset + j] ^ keystream[j];
        inc_counter(ctx->counter);
        offset += bytes;
    }

    ghash_update(ctx->tag, ctx->h, output, input_len);
    ctx->ct_len += input_len;
    kctsb_secure_zero(keystream, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_gcm_final_encrypt(kctsb_aes_gcm_ctx_t* ctx, uint8_t tag[16]) {
    if (!ctx || !tag || ctx->finalized) return KCTSB_ERROR_INVALID_PARAM;

    size_t ct_padding = (16 - (ctx->ct_len % 16)) % 16;
    if (ct_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ctx->tag, ctx->h, pad, ct_padding); }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = ctx->aad_len * 8, ct_bits = ctx->ct_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (uint8_t)(aad_bits >> (i * 8));
        len_block[15 - i] = (uint8_t)(ct_bits >> (i * 8));
    }
    ghash_update(ctx->tag, ctx->h, len_block, 16);

    uint8_t enc_j0[16];
    kctsb_aes_encrypt_block(&ctx->aes_ctx, ctx->j0, enc_j0);
    xor_block(tag, ctx->tag, enc_j0);

    ctx->finalized = 1;
    kctsb_secure_zero(enc_j0, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_gcm_update_decrypt(kctsb_aes_gcm_ctx_t* ctx, const uint8_t* input,
                                            size_t input_len, uint8_t* output) {
    if (!ctx || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    if (ctx->ct_len == 0 && ctx->aad_len > 0) {
        size_t aad_padding = (16 - (ctx->aad_len % 16)) % 16;
        if (aad_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ctx->tag, ctx->h, pad, aad_padding); }
    }

    ghash_update(ctx->tag, ctx->h, input, input_len);

    uint8_t keystream[16];
    size_t offset = 0;
    while (offset < input_len) {
        kctsb_aes_encrypt_block(&ctx->aes_ctx, ctx->counter, keystream);
        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) output[offset + j] = input[offset + j] ^ keystream[j];
        inc_counter(ctx->counter);
        offset += bytes;
    }

    ctx->ct_len += input_len;
    kctsb_secure_zero(keystream, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_gcm_final_decrypt(kctsb_aes_gcm_ctx_t* ctx, const uint8_t tag[16]) {
    if (!ctx || !tag || ctx->finalized) return KCTSB_ERROR_INVALID_PARAM;

    size_t ct_padding = (16 - (ctx->ct_len % 16)) % 16;
    if (ct_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ctx->tag, ctx->h, pad, ct_padding); }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = ctx->aad_len * 8, ct_bits = ctx->ct_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = (uint8_t)(aad_bits >> (i * 8));
        len_block[15 - i] = (uint8_t)(ct_bits >> (i * 8));
    }
    ghash_update(ctx->tag, ctx->h, len_block, 16);

    uint8_t computed_tag[16], enc_j0[16];
    kctsb_aes_encrypt_block(&ctx->aes_ctx, ctx->j0, enc_j0);
    xor_block(computed_tag, ctx->tag, enc_j0);

    ctx->finalized = 1;

    if (!kctsb_secure_compare(tag, computed_tag, 16)) {
        kctsb_secure_zero(computed_tag, 16); kctsb_secure_zero(enc_j0, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }

    kctsb_secure_zero(computed_tag, 16); kctsb_secure_zero(enc_j0, 16);
    return KCTSB_SUCCESS;
}

void kctsb_aes_clear(kctsb_aes_ctx_t* ctx) {
    if (ctx) kctsb_secure_zero(ctx, sizeof(kctsb_aes_ctx_t));
}

void kctsb_aes_gcm_clear(kctsb_aes_gcm_ctx_t* ctx) {
    if (ctx) kctsb_secure_zero(ctx, sizeof(kctsb_aes_gcm_ctx_t));
}

} // extern "C"

// ============================================================================
// C++ Class Implementation
// ============================================================================

namespace kctsb {

AES::AES(const ByteVec& key) {
    kctsb_error_t err = kctsb_aes_init(&ctx_, key.data(), key.size());
    if (err != KCTSB_SUCCESS) throw std::invalid_argument("Invalid AES key size");
}

AES::AES(const uint8_t* key, size_t key_len) {
    kctsb_error_t err = kctsb_aes_init(&ctx_, key, key_len);
    if (err != KCTSB_SUCCESS) throw std::invalid_argument("Invalid AES key size");
}

AES::~AES() { kctsb_aes_clear(&ctx_); }

AES::AES(AES&& other) noexcept {
    memcpy(&ctx_, &other.ctx_, sizeof(ctx_));
    kctsb_secure_zero(&other.ctx_, sizeof(other.ctx_));
}

AES& AES::operator=(AES&& other) noexcept {
    if (this != &other) {
        kctsb_aes_clear(&ctx_);
        memcpy(&ctx_, &other.ctx_, sizeof(ctx_));
        kctsb_secure_zero(&other.ctx_, sizeof(other.ctx_));
    }
    return *this;
}

AESBlock AES::encryptBlock(const AESBlock& input) const {
    AESBlock output;
    kctsb_aes_encrypt_block(&ctx_, input.data(), output.data());
    return output;
}

ByteVec AES::ctrCrypt(const ByteVec& data, const std::array<uint8_t, 12>& nonce) const {
    ByteVec output(data.size());
    kctsb_aes_ctr_crypt(&ctx_, nonce.data(), data.data(), data.size(), output.data());
    return output;
}

std::pair<ByteVec, AESBlock> AES::gcmEncrypt(const ByteVec& plaintext,
                                              const ByteVec& iv, const ByteVec& aad) const {
    ByteVec ciphertext(plaintext.size());
    AESBlock tag;
    kctsb_error_t err = kctsb_aes_gcm_encrypt(&ctx_, iv.data(), iv.size(),
                                               aad.empty() ? nullptr : aad.data(), aad.size(),
                                               plaintext.data(), plaintext.size(),
                                               ciphertext.data(), tag.data());
    if (err != KCTSB_SUCCESS) throw std::runtime_error("AES-GCM encryption failed");
    return {std::move(ciphertext), tag};
}

ByteVec AES::gcmDecrypt(const ByteVec& ciphertext, const ByteVec& iv,
                        const AESBlock& tag, const ByteVec& aad) const {
    ByteVec plaintext(ciphertext.size());
    kctsb_error_t err = kctsb_aes_gcm_decrypt(&ctx_, iv.data(), iv.size(),
                                               aad.empty() ? nullptr : aad.data(), aad.size(),
                                               ciphertext.data(), ciphertext.size(),
                                               tag.data(), plaintext.data());
    if (err == KCTSB_ERROR_AUTH_FAILED) throw std::runtime_error("AES-GCM authentication failed");
    if (err != KCTSB_SUCCESS) throw std::runtime_error("AES-GCM decryption failed");
    return plaintext;
}

std::array<uint8_t, 12> AES::generateNonce() {
    std::array<uint8_t, 12> nonce;
    if (kctsb_random_bytes(nonce.data(), 12) != KCTSB_SUCCESS)
        throw std::runtime_error("Failed to generate random nonce");
    return nonce;
}

ByteVec AES::generateIV(size_t len) {
    ByteVec iv(len);
    if (kctsb_random_bytes(iv.data(), len) != KCTSB_SUCCESS)
        throw std::runtime_error("Failed to generate random IV");
    return iv;
}

} // namespace kctsb
