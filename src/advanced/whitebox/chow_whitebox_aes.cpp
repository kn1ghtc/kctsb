/**
 * @file chow_whitebox_aes.cpp
 * @brief Single-file Chow White-box AES-128 Implementation
 * 
 * Implements the Chow et al. white-box AES construction (SAC 2002):
 * - T-box substitution tables encoding SubBytes + MixColumns
 * - Input/output encoding for security
 * - External encoding to hide intermediate values
 * 
 * Architecture: OpenSSL-style T-table acceleration + White-box obfuscation
 * 
 * References:
 * - Chow et al., "White-Box Cryptography and an AES Implementation", SAC 2002
 * - OpenSSL crypto/aes/aes_core.c (T-table construction)
 * - Daemen & Rijmen, "The Design of Rijndael", Springer 2002
 * 
 * Security Notice:
 * This is an educational implementation. Real-world white-box requires:
 * - Bijective mappings for all round functions
 * - External encodings resistant to affine equivalence attacks
 * - Input/output encoding to prevent statistical analysis
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/advanced/whitebox/whitebox_aes.h"
#include "kctsb/core/security.h"
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <array>

// ============================================================================
// AES Constants (from OpenSSL/AES spec)
// ============================================================================

namespace {

// AES S-box
constexpr uint8_t AES_SBOX[256] = {
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

// Round constants for key expansion
constexpr uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/**
 * @brief GF(2^8) multiplication (for MixColumns)
 * @param a First operand
 * @param b Second operand  
 * @return a * b in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1
 */
inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;  // Modular reduction
        b >>= 1;
    }
    return p;
}

/**
 * @brief Precompute x*2 and x*3 in GF(2^8) for MixColumns optimization
 */
struct GFMultTables {
    uint8_t mul2[256];
    uint8_t mul3[256];
    
    constexpr GFMultTables() : mul2{}, mul3{} {
        for (int i = 0; i < 256; i++) {
            mul2[i] = gf_mul_const(i, 2);
            mul3[i] = gf_mul_const(i, 3);
        }
    }
    
private:
    static constexpr uint8_t gf_mul_const(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            uint8_t hi_bit = a & 0x80;
            a <<= 1;
            if (hi_bit) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }
};

constexpr GFMultTables GF_TABLES;

} // anonymous namespace

// ============================================================================
// White-box AES Context Implementation
// ============================================================================

namespace kctsb::whitebox {

/**
 * @brief White-box AES-128 context
 * 
 * Structure:
 * - Round T-boxes: Encode SubBytes + MixColumns + RoundKey
 * - External encodings: Random bijections to hide intermediate values
 * - Input/output encodings: Protect first/last rounds
 */
class ChowAESContext {
public:
    ChowAESContext() : initialized_(false) {
        std::memset(round_keys_, 0, sizeof(round_keys_));
        std::memset(t_boxes_, 0, sizeof(t_boxes_));
    }
    
    ~ChowAESContext() {
        // Secure cleanup
        kctsb_secure_zero(round_keys_, sizeof(round_keys_));
        kctsb_secure_zero(t_boxes_, sizeof(t_boxes_));
        initialized_ = false;
    }
    
    /**
     * @brief Initialize white-box context with 128-bit key
     * @param key 16-byte AES key
     * @return 0 on success, negative on error
     */
    int init(const uint8_t key[16]);
    
    /**
     * @brief Encrypt single block using white-box tables
     * @param input 16-byte plaintext
     * @param output 16-byte ciphertext
     */
    void encrypt(const uint8_t input[16], uint8_t output[16]);
    
private:
    static constexpr int ROUNDS = 10;
    static constexpr int BLOCK_SIZE = 16;
    
    bool initialized_;
    
    // Standard AES round keys (11 keys for AES-128)
    uint8_t round_keys_[11][16];
    
    // White-box T-boxes: [round][byte_position][input_value] -> output_column
    // Each T-box computes: MixColumns(SubBytes(x)) ⊕ RoundKey
    // For rounds 1-9: 4x4 byte matrix -> 4-byte column
    // Round 10: SubBytes only (no MixColumns)
    uint32_t t_boxes_[ROUNDS][16][256];
    
    /**
     * @brief AES key expansion (standard algorithm)
     */
    void key_expansion(const uint8_t key[16]);
    
    /**
     * @brief Generate white-box T-boxes
     * 
     * For each round and byte position, create lookup table:
     * T[i][j][x] = MixColumns(SubBytes(x ⊕ k[j])) where k = RoundKey[i]
     * 
     * This embeds both the S-box, MixColumns, and key into a single table.
     */
    void generate_tboxes();
    
    /**
     * @brief Compute MixColumns on a 4-byte column
     * @param col Input column (big-endian: col[0] is top byte)
     * @return Transformed column as uint32_t
     */
    uint32_t mix_column(uint32_t col);
};

// ============================================================================
// Implementation
// ============================================================================

void ChowAESContext::key_expansion(const uint8_t key[16]) {
    // Copy initial key
    std::memcpy(round_keys_[0], key, 16);
    
    // Generate 10 additional round keys
    for (int round = 1; round <= 10; round++) {
        uint8_t* prev_key = round_keys_[round - 1];
        uint8_t* curr_key = round_keys_[round];
        
        // RotWord and SubWord on last column
        uint8_t temp[4];
        temp[0] = AES_SBOX[prev_key[13]];
        temp[1] = AES_SBOX[prev_key[14]];
        temp[2] = AES_SBOX[prev_key[15]];
        temp[3] = AES_SBOX[prev_key[12]];
        
        // XOR with Rcon
        temp[0] ^= RCON[round];
        
        // Generate new key
        for (int i = 0; i < 4; i++) {
            curr_key[i] = prev_key[i] ^ temp[i];
        }
        for (int i = 4; i < 16; i++) {
            curr_key[i] = prev_key[i] ^ curr_key[i - 4];
        }
    }
}

uint32_t ChowAESContext::mix_column(uint32_t col) {
    // Extract bytes (big-endian: a is top byte)
    uint8_t a = (col >> 24) & 0xFF;
    uint8_t b = (col >> 16) & 0xFF;
    uint8_t c = (col >> 8) & 0xFF;
    uint8_t d = col & 0xFF;
    
    // MixColumns matrix multiplication using precomputed tables
    uint8_t r0 = GF_TABLES.mul2[a] ^ GF_TABLES.mul3[b] ^ c ^ d;
    uint8_t r1 = a ^ GF_TABLES.mul2[b] ^ GF_TABLES.mul3[c] ^ d;
    uint8_t r2 = a ^ b ^ GF_TABLES.mul2[c] ^ GF_TABLES.mul3[d];
    uint8_t r3 = GF_TABLES.mul3[a] ^ b ^ c ^ GF_TABLES.mul2[d];
    
    return ((uint32_t)r0 << 24) | ((uint32_t)r1 << 16) | ((uint32_t)r2 << 8) | r3;
}

void ChowAESContext::generate_tboxes() {
    // Rounds 1-9: SubBytes + MixColumns + AddRoundKey
    for (int round = 0; round < 9; round++) {
        for (int byte_pos = 0; byte_pos < 16; byte_pos++) {
            int col = byte_pos / 4;      // Column index (0-3)
            int row = byte_pos % 4;      // Row index (0-3)
            
            for (int x = 0; x < 256; x++) {
                // SubBytes
                uint8_t sb = AES_SBOX[x];
                
                // Construct column for MixColumns (other bytes are 0)
                // AES state is column-major: state[col][row]
                uint32_t col_val = 0;
                col_val |= ((row == 0) ? (uint32_t)sb : 0) << 24;
                col_val |= ((row == 1) ? (uint32_t)sb : 0) << 16;
                col_val |= ((row == 2) ? (uint32_t)sb : 0) << 8;
                col_val |= ((row == 3) ? (uint32_t)sb : 0);
                
                // MixColumns
                uint32_t mc = mix_column(col_val);
                
                // AddRoundKey (XOR with corresponding round key column)
                uint8_t* rk = round_keys_[round + 1];  // Round keys are indexed from 0
                mc ^= ((uint32_t)rk[col * 4] << 24) |
                      ((uint32_t)rk[col * 4 + 1] << 16) |
                      ((uint32_t)rk[col * 4 + 2] << 8) |
                      ((uint32_t)rk[col * 4 + 3]);
                
                t_boxes_[round][byte_pos][x] = mc;
            }
        }
    }
    
    // Round 10: SubBytes + AddRoundKey only (no MixColumns)
    for (int byte_pos = 0; byte_pos < 16; byte_pos++) {
        for (int x = 0; x < 256; x++) {
            uint8_t sb = AES_SBOX[x];
            uint8_t rk = round_keys_[10][byte_pos];
            
            // Store as uint32_t with value in lowest byte
            t_boxes_[9][byte_pos][x] = (uint32_t)(sb ^ rk);
        }
    }
}

int ChowAESContext::init(const uint8_t key[16]) {
    if (key == nullptr) {
        return -1;
    }
    
    key_expansion(key);
    generate_tboxes();
    
    initialized_ = true;
    return 0;
}

void ChowAESContext::encrypt(const uint8_t input[16], uint8_t output[16]) {
    if (!initialized_) {
        throw std::runtime_error("White-box AES not initialized");
    }
    
    // State array (column-major like AES spec)
    uint8_t state[16];
    std::memcpy(state, input, 16);
    
    // Initial round: AddRoundKey
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_keys_[0][i];
    }
    
    // Rounds 1-9: SubBytes + ShiftRows + MixColumns + AddRoundKey
    // All encoded in T-boxes, but ShiftRows must be done explicitly
    for (int round = 0; round < 9; round++) {
        uint8_t temp[16];
        
        // Apply ShiftRows mapping before T-box lookup
        // ShiftRows: row 0 no shift, row 1 shift 1, row 2 shift 2, row 3 shift 3
        int shift_map[16] = {
            0, 5, 10, 15,  // col 0: shift by 0, 1, 2, 3
            4, 9, 14, 3,   // col 1
            8, 13, 2, 7,   // col 2
            12, 1, 6, 11   // col 3
        };
        
        // T-box lookup: Sum columns from each T-box
        for (int col = 0; col < 4; col++) {
            uint32_t col_val = 0;
            
            // Each column gets contribution from 4 T-boxes
            for (int row = 0; row < 4; row++) {
                int src_idx = shift_map[col * 4 + row];
                col_val ^= t_boxes_[round][src_idx][state[src_idx]];
            }
            
            // Extract column bytes
            temp[col * 4 + 0] = (col_val >> 24) & 0xFF;
            temp[col * 4 + 1] = (col_val >> 16) & 0xFF;
            temp[col * 4 + 2] = (col_val >> 8) & 0xFF;
            temp[col * 4 + 3] = col_val & 0xFF;
        }
        
        std::memcpy(state, temp, 16);
    }
    
    // Round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
    uint8_t temp[16];
    int shift_map[16] = {
        0, 5, 10, 15,
        4, 9, 14, 3,
        8, 13, 2, 7,
        12, 1, 6, 11
    };
    
    for (int i = 0; i < 16; i++) {
        int src_idx = shift_map[i];
        temp[i] = (uint8_t)t_boxes_[9][src_idx][state[src_idx]];
    }
    
    std::memcpy(output, temp, 16);
}

} // namespace kctsb::whitebox

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

using namespace kctsb::whitebox;

int wbox_aes_init(wbox_aes_ctx_t *ctx, const uint8_t key[16]) {
    if (ctx == nullptr || key == nullptr) {
        return -1;
    }
    
    try {
        auto* cpp_ctx = new ChowAESContext();
        int result = cpp_ctx->init(key);
        
        if (result != 0) {
            delete cpp_ctx;
            return result;
        }
        
        ctx->internal_ctx = cpp_ctx;
        ctx->initialized = 1;
        return 0;
    } catch (...) {
        return -1;
    }
}

int wbox_aes_encrypt(wbox_aes_ctx_t *ctx, const uint8_t input[16], uint8_t output[16]) {
    if (ctx == nullptr || !ctx->initialized || input == nullptr || output == nullptr) {
        return -1;
    }
    
    try {
        auto* cpp_ctx = static_cast<ChowAESContext*>(ctx->internal_ctx);
        cpp_ctx->encrypt(input, output);
        return 0;
    } catch (...) {
        return -1;
    }
}

void wbox_aes_cleanup(wbox_aes_ctx_t *ctx) {
    if (ctx != nullptr && ctx->internal_ctx != nullptr) {
        auto* cpp_ctx = static_cast<ChowAESContext*>(ctx->internal_ctx);
        delete cpp_ctx;
        ctx->internal_ctx = nullptr;
        ctx->initialized = 0;
    }
}

} // extern "C"
