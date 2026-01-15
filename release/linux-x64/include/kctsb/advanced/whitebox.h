/**
 * @file whitebox.h
 * @brief Whitebox cryptography implementations
 * 
 * Provides whitebox AES implementations based on Chow et al. approach.
 * Designed to resist key extraction in white-box attack models.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_ADVANCED_WHITEBOX_H
#define KCTSB_ADVANCED_WHITEBOX_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Whitebox AES table sizes
#define KCTSB_WBAES_TYPE2_SIZE     (16 * 256 * 16)
#define KCTSB_WBAES_TYPE3_SIZE     (16 * 256 * 16)
#define KCTSB_WBAES_XORTABLE_SIZE  (96 * 16 * 16)

// Whitebox AES context (expanded tables)
typedef struct {
    uint8_t type2_tables[10][16][256][16];
    uint8_t type3_tables[9][16][256][16];
    uint8_t xor_tables[9][96][16][16];
    int initialized;
} kctsb_wbaes_ctx_t;

/**
 * @brief Generate whitebox AES tables for a key
 * @param ctx Whitebox context to initialize
 * @param key 16-byte AES key
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_wbaes_generate_tables(
    kctsb_wbaes_ctx_t* ctx,
    const uint8_t key[16]
);

/**
 * @brief Whitebox AES encryption
 * @param ctx Initialized whitebox context
 * @param input 16-byte input block
 * @param output 16-byte output block
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_wbaes_encrypt(
    const kctsb_wbaes_ctx_t* ctx,
    const uint8_t input[16],
    uint8_t output[16]
);

/**
 * @brief Save whitebox tables to file
 * @param ctx Whitebox context
 * @param filename Output filename
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_wbaes_save_tables(
    const kctsb_wbaes_ctx_t* ctx,
    const char* filename
);

/**
 * @brief Load whitebox tables from file
 * @param ctx Whitebox context to initialize
 * @param filename Input filename
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_wbaes_load_tables(
    kctsb_wbaes_ctx_t* ctx,
    const char* filename
);

/**
 * @brief Clear whitebox context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_wbaes_clear(kctsb_wbaes_ctx_t* ctx);

/**
 * @brief Run whitebox AES self test
 * @return KCTSB_SUCCESS if test passes
 */
KCTSB_API kctsb_error_t kctsb_wbaes_self_test(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <string>

namespace kctsb {

/**
 * @brief Whitebox AES implementation
 */
class WhiteboxAES {
public:
    WhiteboxAES();
    ~WhiteboxAES();
    
    /**
     * @brief Generate whitebox tables for key
     * @param key 16-byte AES key
     */
    void generateTables(const AES128Key& key);
    
    /**
     * @brief Encrypt block using whitebox implementation
     * @param input Input block
     * @return Encrypted block
     */
    AESBlock encrypt(const AESBlock& input) const;
    
    /**
     * @brief Save tables to file
     * @param filename Output filename
     */
    void saveTables(const std::string& filename) const;
    
    /**
     * @brief Load tables from file
     * @param filename Input filename
     */
    void loadTables(const std::string& filename);
    
    /**
     * @brief Check if tables are initialized
     */
    bool isInitialized() const;
    
private:
    kctsb_wbaes_ctx_t ctx_;
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_ADVANCED_WHITEBOX_H
