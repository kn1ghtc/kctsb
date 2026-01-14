/**
 * @file seal_pir.cpp
 * @brief SEAL-PIR Implementation - Microsoft SEAL based Private Information Retrieval
 *
 * @details Real implementation using Microsoft SEAL library (C++)
 * Based on CKKS homomorphic encryption scheme
 *
 * @note This implementation requires Microsoft SEAL 3.x or 4.x
 *       Supports both old API (scheme_type::CKKS) and new API (scheme_type::ckks)
 *
 * @author kn1ghtc
 * @version 3.3.1
 * @date 2026-01-14
 *
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include "kctsb/advanced/psi/psi.h"

#ifdef KCTSB_HAS_SEAL

// SEAL header - in thirdparty/include/SEAL-4.1/
// SEAL 4.1 requires const SEALContext& instead of shared_ptr
#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <memory>
#include <vector>

namespace {

/* ============================================================================
 * Internal Implementation Class
 * ============================================================================ */

class SEALPIRImpl {
public:
    explicit SEALPIRImpl(const std::vector<double>& database);

    int query(size_t target_index, kctsb_pir_result_t* result);

private:
    std::vector<double> database_;
    seal::SEALContext context_;  // SEAL 4.1 uses value type, not shared_ptr
    size_t slot_count_;

    static seal::SEALContext create_context();
};

seal::SEALContext SEALPIRImpl::create_context() {
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(
        poly_modulus_degree, {60, 40, 40, 60}));
    return seal::SEALContext(parms);
}

SEALPIRImpl::SEALPIRImpl(const std::vector<double>& database)
    : database_(database), context_(create_context())
{
    seal::CKKSEncoder encoder(context_);
    slot_count_ = encoder.slot_count();
}

int SEALPIRImpl::query(size_t target_index, kctsb_pir_result_t* result) {
    if (!result) {
        return KCTSB_PSI_ERROR_INVALID_PARAM;
    }

    std::memset(result, 0, sizeof(kctsb_pir_result_t));
    result->query_index = target_index;

    try {
        // Generate keys - SEAL 4.1 uses const SEALContext& instead of shared_ptr
        seal::KeyGenerator keygen(context_);
        auto secret_key = keygen.secret_key();
        seal::PublicKey public_key;
        keygen.create_public_key(public_key);
        seal::RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);

        // Initialize encoders and crypto objects - SEAL 4.1 uses const SEALContext&
        seal::CKKSEncoder encoder(context_);
        seal::Encryptor encryptor(context_, public_key);
        seal::Evaluator evaluator(context_);
        seal::Decryptor decryptor(context_, secret_key);

        double scale = std::pow(2.0, 40);

        // Encrypt database
        size_t db_size = std::min(database_.size(), slot_count_);
        std::vector<double> db_batch(slot_count_, 0.0);
        for (size_t i = 0; i < db_size; i++) {
            db_batch[i] = database_[i];
        }

        seal::Plaintext db_plain;
        encoder.encode(db_batch, scale, db_plain);
        seal::Ciphertext db_encrypted;
        encryptor.encrypt(db_plain, db_encrypted);

        // Generate query vector
        auto query_start = std::chrono::high_resolution_clock::now();

        // Create selection vector (1 at target position, 0 elsewhere)
        std::vector<double> selection_vector(slot_count_, 0.0);
        if (target_index < slot_count_) {
            selection_vector[target_index] = 1.0;
        }

        seal::Plaintext selection_plain;
        encoder.encode(selection_vector, scale, selection_plain);
        seal::Ciphertext selection_encrypted;
        encryptor.encrypt(selection_plain, selection_encrypted);

        auto query_end = std::chrono::high_resolution_clock::now();
        result->query_time_ms = std::chrono::duration<double, std::milli>(
            query_end - query_start).count();

        // Server processing
        auto server_start = std::chrono::high_resolution_clock::now();

        // Homomorphic multiplication: database * selection_vector
        seal::Ciphertext result_encrypted;
        evaluator.multiply(db_encrypted, selection_encrypted, result_encrypted);
        evaluator.relinearize_inplace(result_encrypted, relin_keys);

        auto server_end = std::chrono::high_resolution_clock::now();
        result->server_time_ms = std::chrono::duration<double, std::milli>(
            server_end - server_start).count();

        // Client decryption
        auto decrypt_start = std::chrono::high_resolution_clock::now();

        seal::Plaintext decrypted_plain;
        decryptor.decrypt(result_encrypted, decrypted_plain);

        std::vector<double> decoded_result;
        encoder.decode(decrypted_plain, decoded_result);

        // Sum all slots to get the retrieved value (only target position has non-zero)
        double retrieved = 0.0;
        for (size_t i = 0; i < db_size; i++) {
            retrieved += decoded_result[i];
        }

        auto decrypt_end = std::chrono::high_resolution_clock::now();
        result->client_time_ms = std::chrono::duration<double, std::milli>(
            decrypt_end - decrypt_start).count();

        // Store result
        result->retrieved_value = retrieved;
        result->noise_budget_remaining = decryptor.invariant_noise_budget(result_encrypted);

        // Verify correctness
        double expected = (target_index < database_.size()) ? database_[target_index] : 0.0;
        double tolerance = 1e-3;
        result->is_correct = std::abs(retrieved - expected) < tolerance;

        // Estimate communication bytes
        result->communication_bytes = static_cast<size_t>(
            selection_encrypted.size() * sizeof(uint64_t) +  // Query
            result_encrypted.size() * sizeof(uint64_t)       // Response
        );

    } catch (const std::exception& e) {
        std::strncpy(result->error_message, e.what(), sizeof(result->error_message) - 1);
        result->is_correct = false;
        return KCTSB_PSI_ERROR_SEAL_NOT_AVAILABLE;
    }

    // Total time is implicit from sum of other times
    return KCTSB_PSI_SUCCESS;
}

} // anonymous namespace

/* ============================================================================
 * C API Implementation (SEAL)
 * ============================================================================ */

extern "C" {

struct kctsb_pir_ctx {
    std::unique_ptr<SEALPIRImpl> impl;
};

kctsb_pir_ctx_t* kctsb_seal_pir_create(const double* database, size_t db_size) {
    if (!database || db_size == 0) {
        return nullptr;
    }

    try {
        auto ctx = new kctsb_pir_ctx_t;
        std::vector<double> db_vec(database, database + db_size);
        ctx->impl = std::make_unique<SEALPIRImpl>(db_vec);
        return ctx;
    } catch (...) {
        return nullptr;
    }
}

void kctsb_seal_pir_destroy(kctsb_pir_ctx_t* ctx) {
    delete ctx;
}

int kctsb_seal_pir_query(
    kctsb_pir_ctx_t* ctx,
    size_t target_index,
    kctsb_pir_result_t* result
) {
    if (!ctx || !ctx->impl || !result) {
        return KCTSB_PSI_ERROR_INVALID_PARAM;
    }

    return ctx->impl->query(target_index, result);
}

} // extern "C"

/* ============================================================================
 * C++ API Implementation (SEAL)
 * ============================================================================ */

namespace kctsb {
namespace psi {

struct SEALPIR::Impl {
    std::unique_ptr<SEALPIRImpl> impl;
};

SEALPIR::SEALPIR(const std::vector<double>& database)
    : pimpl_(std::make_unique<Impl>())
{
    pimpl_->impl = std::make_unique<SEALPIRImpl>(database);
}

SEALPIR::~SEALPIR() = default;

SEALPIR::Result SEALPIR::query(size_t target_index) {
    Result result;
    kctsb_pir_result_t c_result;

    int ret = pimpl_->impl->query(target_index, &c_result);

    if (ret == KCTSB_PSI_SUCCESS) {
        result.query_index = c_result.query_index;
        result.retrieved_value = c_result.retrieved_value;
        result.is_correct = c_result.is_correct;
        result.query_time_ms = c_result.query_time_ms;
        result.server_time_ms = c_result.server_time_ms;
        result.client_time_ms = c_result.client_time_ms;
        result.communication_bytes = c_result.communication_bytes;
        result.noise_budget_remaining = c_result.noise_budget_remaining;
        result.error_message = c_result.error_message;
    } else {
        result.is_correct = false;
        result.error_message = kctsb_psi_error_string(ret);
    }

    return result;
}

} // namespace psi
} // namespace kctsb

#endif /* KCTSB_HAS_SEAL */
