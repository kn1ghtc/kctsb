/**
 * @file ot_extension.h
 * @brief Production-grade OT Extension Implementation
 * 
 * @details Self-contained IKNP OT Extension protocol implementation
 * Reference: [IKNP03] Ishai, Kilian, Nissim, Petrank - "Extending Oblivious Transfers Efficiently"
 * 
 * Features:
 * - IKNP OT Extension (base implementation)
 * - 1-out-of-N random OT
 * - Correlated OT (COT) for malicious security
 * - SIMD optimization with AVX2/NEON
 * - AES-NI for PRG/correlation robustness
 * 
 * Security:
 * - 128-bit computational security (κ = 128)
 * - Semi-honest security by default
 * - Malicious security with consistency check (optional)
 * 
 * Communication:
 * - Base OT: 128 1-out-of-2 OTs (setup phase)
 * - Extension: O(κ·m) bits for m OTs
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#ifndef KCTSB_ADVANCED_OT_EXTENSION_H
#define KCTSB_ADVANCED_OT_EXTENSION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#include <array>
#include <memory>
#include <vector>
#include <string>
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

/** Security parameter (128-bit) */
#define KCTSB_OT_KAPPA 128

/** Block size for AES operations */
#define KCTSB_OT_BLOCK_SIZE 16

/** Base OT count (equals security parameter) */
#define KCTSB_OT_BASE_COUNT KCTSB_OT_KAPPA

/* ============================================================================
 * OT Extension Configuration
 * ============================================================================ */

/**
 * @brief OT Extension security mode
 */
typedef enum {
    KCTSB_OT_SEMI_HONEST,    /**< Semi-honest security (faster) */
    KCTSB_OT_MALICIOUS       /**< Malicious security with consistency check */
} kctsb_ot_security_t;

/**
 * @brief OT Extension type
 */
typedef enum {
    KCTSB_OT_RANDOM,         /**< Random OT (receiver gets random messages) */
    KCTSB_OT_CORRELATED,     /**< Correlated OT (m1 = m0 XOR delta) */
    KCTSB_OT_STANDARD        /**< Standard OT (sender chooses both messages) */
} kctsb_ot_type_t;

/**
 * @brief OT Extension configuration
 */
typedef struct {
    kctsb_ot_security_t security;    /**< Security model */
    kctsb_ot_type_t type;            /**< OT type */
    size_t num_ots;                  /**< Number of OTs to extend */
    size_t msg_byte_len;             /**< Message length in bytes (default: 16) */
    bool enable_simd;                /**< Enable AVX2/NEON acceleration */
    bool enable_aes_ni;              /**< Enable AES-NI for PRG */
    uint8_t seed[32];                /**< RNG seed (optional, random if zero) */
} kctsb_ot_ext_config_t;

/**
 * @brief OT Extension result/statistics
 */
typedef struct {
    size_t num_ots;                  /**< Actual OTs computed */
    size_t base_ot_time_us;          /**< Base OT time (microseconds) */
    size_t extension_time_us;        /**< Extension time (microseconds) */
    size_t total_time_us;            /**< Total execution time */
    size_t communication_bytes;      /**< Total communication */
    bool success;                    /**< Operation success flag */
    char error_message[256];         /**< Error description */
} kctsb_ot_ext_result_t;

/**
 * @brief Base OT keys (κ pairs of messages from base OT)
 */
typedef struct {
    uint8_t sender_keys[KCTSB_OT_BASE_COUNT][2][KCTSB_OT_BLOCK_SIZE]; /**< Sender's κ pairs */
    uint8_t receiver_keys[KCTSB_OT_BASE_COUNT][KCTSB_OT_BLOCK_SIZE];  /**< Receiver's κ keys */
    uint8_t receiver_choice[KCTSB_OT_BASE_COUNT / 8];                  /**< Receiver's choice bits */
} kctsb_base_ot_keys_t;

/**
 * @brief Opaque OT Extension context
 */
typedef struct kctsb_ot_ext_ctx kctsb_ot_ext_ctx_t;

/* ============================================================================
 * Sender API
 * ============================================================================ */

/**
 * @brief Initialize default OT Extension configuration
 * @param config Configuration to initialize
 * @param num_ots Number of OTs to extend
 * @param security Security mode (semi-honest/malicious)
 */
void kctsb_ot_ext_config_init(
    kctsb_ot_ext_config_t *config,
    size_t num_ots,
    kctsb_ot_security_t security
);

/**
 * @brief Create OT Extension sender context
 * @param config Configuration
 * @return Sender context or NULL on failure
 */
kctsb_ot_ext_ctx_t *kctsb_ot_ext_sender_create(const kctsb_ot_ext_config_t *config);

/**
 * @brief Sender: Generate base OT keys (as base OT receiver)
 * @param ctx Sender context
 * @param delta Global correlation delta for correlated OT (NULL for random OT)
 * @param base_keys Output base OT keys
 * @return 0 on success
 */
int kctsb_ot_ext_sender_setup(
    kctsb_ot_ext_ctx_t *ctx,
    const uint8_t *delta,
    kctsb_base_ot_keys_t *base_keys
);

/**
 * @brief Sender: Process receiver's extension matrix and output messages
 * @param ctx Sender context
 * @param base_keys Base OT keys from setup
 * @param receiver_matrix Receiver's T matrix (transposed, κ × m bits)
 * @param matrix_size Size of receiver_matrix in bytes
 * @param messages_0 Output: m messages for choice bit 0
 * @param messages_1 Output: m messages for choice bit 1
 * @param result Output statistics
 * @return 0 on success
 */
int kctsb_ot_ext_sender_extend(
    kctsb_ot_ext_ctx_t *ctx,
    const kctsb_base_ot_keys_t *base_keys,
    const uint8_t *receiver_matrix,
    size_t matrix_size,
    uint8_t *messages_0,
    uint8_t *messages_1,
    kctsb_ot_ext_result_t *result
);

/* ============================================================================
 * Receiver API
 * ============================================================================ */

/**
 * @brief Create OT Extension receiver context
 * @param config Configuration
 * @return Receiver context or NULL on failure
 */
kctsb_ot_ext_ctx_t *kctsb_ot_ext_receiver_create(const kctsb_ot_ext_config_t *config);

/**
 * @brief Receiver: Participate in base OT (as base OT sender)
 * @param ctx Receiver context
 * @param base_keys Sender's base OT keys
 * @param sender_messages Output: Receiver sends these to sender
 * @return 0 on success
 */
int kctsb_ot_ext_receiver_setup(
    kctsb_ot_ext_ctx_t *ctx,
    kctsb_base_ot_keys_t *base_keys,
    uint8_t *sender_messages
);

/**
 * @brief Receiver: Generate extension matrix and receive chosen messages
 * @param ctx Receiver context
 * @param base_keys Base OT keys
 * @param choice_bits m choice bits (bit i = receiver's choice for OT i)
 * @param choice_bits_size Size of choice_bits in bytes (ceil(m/8))
 * @param receiver_matrix Output: T matrix to send to sender
 * @param matrix_size Size of receiver_matrix buffer
 * @param received_messages Output: m chosen messages
 * @param result Output statistics
 * @return 0 on success
 */
int kctsb_ot_ext_receiver_extend(
    kctsb_ot_ext_ctx_t *ctx,
    const kctsb_base_ot_keys_t *base_keys,
    const uint8_t *choice_bits,
    size_t choice_bits_size,
    uint8_t *receiver_matrix,
    size_t *matrix_size,
    uint8_t *received_messages,
    kctsb_ot_ext_result_t *result
);

/* ============================================================================
 * Cleanup API
 * ============================================================================ */

/**
 * @brief Destroy OT Extension context (sender or receiver)
 * @param ctx Context to destroy
 */
void kctsb_ot_ext_destroy(kctsb_ot_ext_ctx_t *ctx);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * @brief Perform base OTs using Simplest OT protocol
 * @details Uses elliptic curve Diffie-Hellman for base OT
 * @param num_ots Number of base OTs (typically κ = 128)
 * @param sender_keys Output: Sender's message pairs
 * @param receiver_keys Output: Receiver's chosen messages
 * @param receiver_choice Receiver's choice bits
 * @return 0 on success
 */
int kctsb_base_ot_execute(
    size_t num_ots,
    uint8_t sender_keys[][2][KCTSB_OT_BLOCK_SIZE],
    uint8_t receiver_keys[][KCTSB_OT_BLOCK_SIZE],
    const uint8_t *receiver_choice
);

/**
 * @brief Compute matrix size required for extension
 * @param num_ots Number of OTs
 * @param msg_byte_len Message length in bytes
 * @return Required buffer size in bytes
 */
size_t kctsb_ot_ext_matrix_size(size_t num_ots, size_t msg_byte_len);

#ifdef __cplusplus
}

/* ============================================================================
 * C++ Wrapper Classes
 * ============================================================================ */

namespace kctsb {
namespace ot {

/**
 * @brief 128-bit block type
 */
using Block = std::array<uint8_t, KCTSB_OT_BLOCK_SIZE>;

/**
 * @brief OT Extension configuration
 */
struct OTExtConfig {
    kctsb_ot_security_t security = KCTSB_OT_SEMI_HONEST;
    kctsb_ot_type_t type = KCTSB_OT_RANDOM;
    size_t num_ots = 0;
    size_t msg_byte_len = KCTSB_OT_BLOCK_SIZE;
    bool enable_simd = true;
    bool enable_aes_ni = true;
};

/**
 * @brief OT Extension result
 */
struct OTExtResult {
    size_t num_ots = 0;
    size_t base_ot_time_us = 0;
    size_t extension_time_us = 0;
    size_t total_time_us = 0;
    size_t communication_bytes = 0;
    bool success = false;
    std::string error_message;
};

/**
 * @brief IKNP OT Extension Sender
 */
class OTExtSender {
public:
    explicit OTExtSender(const OTExtConfig& config);
    ~OTExtSender();

    OTExtSender(const OTExtSender&) = delete;
    OTExtSender& operator=(const OTExtSender&) = delete;
    OTExtSender(OTExtSender&&) noexcept;
    OTExtSender& operator=(OTExtSender&&) noexcept;

    /**
     * @brief Setup phase: generate base OT keys
     * @param delta Optional global delta for correlated OT
     * @return Base OT keys
     */
    kctsb_base_ot_keys_t setup(const Block* delta = nullptr);

    /**
     * @brief Extension phase: compute OT messages
     * @param base_keys Base OT keys
     * @param receiver_matrix Receiver's T matrix
     * @return Pair of (messages_0, messages_1) vectors
     */
    std::pair<std::vector<Block>, std::vector<Block>> extend(
        const kctsb_base_ot_keys_t& base_keys,
        const std::vector<uint8_t>& receiver_matrix);

    /**
     * @brief Get last operation result
     */
    const OTExtResult& get_result() const { return result_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    OTExtResult result_;
};

/**
 * @brief IKNP OT Extension Receiver
 */
class OTExtReceiver {
public:
    explicit OTExtReceiver(const OTExtConfig& config);
    ~OTExtReceiver();

    OTExtReceiver(const OTExtReceiver&) = delete;
    OTExtReceiver& operator=(const OTExtReceiver&) = delete;
    OTExtReceiver(OTExtReceiver&&) noexcept;
    OTExtReceiver& operator=(OTExtReceiver&&) noexcept;

    /**
     * @brief Setup phase: participate in base OT
     * @param base_keys Base OT keys from sender
     * @return Messages to send to sender
     */
    std::vector<uint8_t> setup(kctsb_base_ot_keys_t& base_keys);

    /**
     * @brief Extension phase: receive chosen messages
     * @param base_keys Base OT keys
     * @param choice_bits Choice bits for each OT
     * @return Pair of (T matrix, received messages)
     */
    std::pair<std::vector<uint8_t>, std::vector<Block>> extend(
        const kctsb_base_ot_keys_t& base_keys,
        const std::vector<bool>& choice_bits);

    /**
     * @brief Get last operation result
     */
    const OTExtResult& get_result() const { return result_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    OTExtResult result_;
};

} // namespace ot
} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_ADVANCED_OT_EXTENSION_H
