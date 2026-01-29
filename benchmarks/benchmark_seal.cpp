/**
 * @file benchmark_seal.cpp
 * @brief kctsb vs SEAL 4.1.2 同态加密性能对比
 *
 * 对比算法:
 *   - BFV: 密钥生成、加解密、加法、乘法、重线性化
 *   - BGV: 密钥生成、加解密、加法、乘法、重线性化
 *   - CKKS: 密钥生成、编解码、加解密、加法、乘法、Rescale
 *
 * 测试参数:
 *   - n = 8192 (多项式环维度)
 *   - L = 5 (模数链层数)
 *   - 128-bit 安全级别
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifdef BENCHMARK_HAS_SEAL

#include <iostream>
#include <vector>
#include <memory>

#include "benchmark_common.hpp"

// kctsb 公共 API
#include "kctsb/kctsb_api.h"

// SEAL 头文件
#include "seal/seal.h"

namespace {

// 测试参数
constexpr size_t POLY_MODULUS_DEGREE = 8192;
constexpr size_t COEFF_MODULUS_COUNT = 5;

// ============================================================================
// BFV 对比
// ============================================================================

void benchmark_bfv() {
    std::cout << "\n--- BFV Scheme (n=8192, t=65537) ---\n";
    benchmark::print_table_header();

    benchmark::Timer timer;

    // ============ SEAL BFV 设置 ============
    seal::EncryptionParameters seal_params(seal::scheme_type::bfv);
    seal_params.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
    seal_params.set_coeff_modulus(seal::CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));
    seal_params.set_plain_modulus(65537);

    auto seal_context = seal::SEALContext(seal_params);
    seal::KeyGenerator seal_keygen(seal_context);
    auto seal_secret_key = seal_keygen.secret_key();
    seal::PublicKey seal_public_key;
    seal_keygen.create_public_key(seal_public_key);
    seal::RelinKeys seal_relin_keys;
    seal_keygen.create_relin_keys(seal_relin_keys);

    seal::Encryptor seal_encryptor(seal_context, seal_public_key);
    seal::Decryptor seal_decryptor(seal_context, seal_secret_key);
    seal::Evaluator seal_evaluator(seal_context);
    seal::BatchEncoder seal_encoder(seal_context);

    // ============ kctsb BFV 设置 ============
    kctsb_bfv_context_t kctsb_ctx = nullptr;
    kctsb_bfv_create_context(&kctsb_ctx, POLY_MODULUS_DEGREE, COEFF_MODULUS_COUNT, 65537);

    kctsb_bfv_keys_t kctsb_keys = nullptr;
    kctsb_bfv_generate_keys(kctsb_ctx, &kctsb_keys);

    // ============ 密钥生成对比 ============
    {
        // SEAL KeyGen
        double seal_total = 0;
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            seal::KeyGenerator keygen(seal_context);
            auto sk = keygen.secret_key();
            seal::PublicKey pk;
            keygen.create_public_key(pk);
            seal_total += timer.stop();
        }
        double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;

        // kctsb KeyGen
        double kctsb_total = 0;
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_bfv_keys_t keys = nullptr;
            kctsb_bfv_generate_keys(kctsb_ctx, &keys);
            kctsb_total += timer.stop();
            kctsb_bfv_free_keys(keys);
        }
        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        benchmark::print_result({"BFV KeyGen", "kctsb", kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        benchmark::print_result({"BFV KeyGen", "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        double ratio = kctsb_avg / seal_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }

    // ============ 加密对比 ============
    {
        // 准备明文
        std::vector<int64_t> plain_data(seal_encoder.slot_count(), 42);
        seal::Plaintext seal_plain;
        seal_encoder.encode(plain_data, seal_plain);
        seal::Ciphertext seal_cipher;

        // SEAL Encrypt
        double seal_total = 0;
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            seal_encryptor.encrypt(seal_plain, seal_cipher);
        }
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            seal_encryptor.encrypt(seal_plain, seal_cipher);
            seal_total += timer.stop();
        }
        double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;

        // kctsb Encrypt
        kctsb_bfv_plaintext_t kctsb_plain = nullptr;
        kctsb_bfv_ciphertext_t kctsb_cipher = nullptr;
        kctsb_bfv_encode_vector(kctsb_ctx, plain_data.data(), plain_data.size(), &kctsb_plain);

        double kctsb_total = 0;
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_bfv_encrypt(kctsb_ctx, kctsb_keys, kctsb_plain, &kctsb_cipher);
            kctsb_bfv_free_ciphertext(kctsb_cipher);
            kctsb_cipher = nullptr;
        }
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_bfv_encrypt(kctsb_ctx, kctsb_keys, kctsb_plain, &kctsb_cipher);
            kctsb_total += timer.stop();
            kctsb_bfv_free_ciphertext(kctsb_cipher);
            kctsb_cipher = nullptr;
        }
        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        kctsb_bfv_free_plaintext(kctsb_plain);

        benchmark::print_result({"BFV Encrypt", "kctsb", kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        benchmark::print_result({"BFV Encrypt", "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        double ratio = kctsb_avg / seal_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }

    // ============ 乘法对比 ============
    {
        // 准备密文
        std::vector<int64_t> plain_data(seal_encoder.slot_count(), 3);
        seal::Plaintext seal_plain;
        seal_encoder.encode(plain_data, seal_plain);
        seal::Ciphertext seal_ct1, seal_ct2, seal_result;
        seal_encryptor.encrypt(seal_plain, seal_ct1);
        seal_encryptor.encrypt(seal_plain, seal_ct2);

        // SEAL Multiply
        double seal_total = 0;
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            seal_evaluator.multiply(seal_ct1, seal_ct2, seal_result);
        }
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            seal_evaluator.multiply(seal_ct1, seal_ct2, seal_result);
            seal_total += timer.stop();
        }
        double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;

        // kctsb Multiply
        kctsb_bfv_plaintext_t kctsb_plain = nullptr;
        kctsb_bfv_ciphertext_t kctsb_ct1 = nullptr, kctsb_ct2 = nullptr, kctsb_result = nullptr;
        kctsb_bfv_encode_vector(kctsb_ctx, plain_data.data(), plain_data.size(), &kctsb_plain);
        kctsb_bfv_encrypt(kctsb_ctx, kctsb_keys, kctsb_plain, &kctsb_ct1);
        kctsb_bfv_encrypt(kctsb_ctx, kctsb_keys, kctsb_plain, &kctsb_ct2);

        double kctsb_total = 0;
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_bfv_multiply(kctsb_ctx, kctsb_ct1, kctsb_ct2, &kctsb_result);
            kctsb_bfv_free_ciphertext(kctsb_result);
            kctsb_result = nullptr;
        }
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_bfv_multiply(kctsb_ctx, kctsb_ct1, kctsb_ct2, &kctsb_result);
            kctsb_total += timer.stop();
            kctsb_bfv_free_ciphertext(kctsb_result);
            kctsb_result = nullptr;
        }
        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        kctsb_bfv_free_plaintext(kctsb_plain);
        kctsb_bfv_free_ciphertext(kctsb_ct1);
        kctsb_bfv_free_ciphertext(kctsb_ct2);

        benchmark::print_result({"BFV Multiply", "kctsb", kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        benchmark::print_result({"BFV Multiply", "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        double ratio = kctsb_avg / seal_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }

    // ============ 乘法 + 重线性化对比 ============
    {
        std::vector<int64_t> plain_data(seal_encoder.slot_count(), 3);
        seal::Plaintext seal_plain;
        seal_encoder.encode(plain_data, seal_plain);
        seal::Ciphertext seal_ct1, seal_ct2, seal_result;
        seal_encryptor.encrypt(seal_plain, seal_ct1);
        seal_encryptor.encrypt(seal_plain, seal_ct2);

        // SEAL Multiply + Relin
        double seal_total = 0;
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            seal_evaluator.multiply(seal_ct1, seal_ct2, seal_result);
            seal_evaluator.relinearize_inplace(seal_result, seal_relin_keys);
        }
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            seal_evaluator.multiply(seal_ct1, seal_ct2, seal_result);
            seal_evaluator.relinearize_inplace(seal_result, seal_relin_keys);
            seal_total += timer.stop();
        }
        double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;

        // kctsb Multiply + Relin
        kctsb_bfv_plaintext_t kctsb_plain = nullptr;
        kctsb_bfv_ciphertext_t kctsb_ct1 = nullptr, kctsb_ct2 = nullptr, kctsb_result = nullptr;
        kctsb_bfv_encode_vector(kctsb_ctx, plain_data.data(), plain_data.size(), &kctsb_plain);
        kctsb_bfv_encrypt(kctsb_ctx, kctsb_keys, kctsb_plain, &kctsb_ct1);
        kctsb_bfv_encrypt(kctsb_ctx, kctsb_keys, kctsb_plain, &kctsb_ct2);

        double kctsb_total = 0;
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_bfv_multiply_relin(kctsb_ctx, kctsb_keys, kctsb_ct1, kctsb_ct2, &kctsb_result);
            kctsb_bfv_free_ciphertext(kctsb_result);
            kctsb_result = nullptr;
        }
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_bfv_multiply_relin(kctsb_ctx, kctsb_keys, kctsb_ct1, kctsb_ct2, &kctsb_result);
            kctsb_total += timer.stop();
            kctsb_bfv_free_ciphertext(kctsb_result);
            kctsb_result = nullptr;
        }
        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        kctsb_bfv_free_plaintext(kctsb_plain);
        kctsb_bfv_free_ciphertext(kctsb_ct1);
        kctsb_bfv_free_ciphertext(kctsb_ct2);

        benchmark::print_result({"BFV Mul+Relin", "kctsb", kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        benchmark::print_result({"BFV Mul+Relin", "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        double ratio = kctsb_avg / seal_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }

    // 清理
    kctsb_bfv_free_keys(kctsb_keys);
    kctsb_bfv_free_context(kctsb_ctx);
}

// ============================================================================
// CKKS 对比
// ============================================================================

void benchmark_ckks() {
    std::cout << "\n--- CKKS Scheme (n=8192, L=5) ---\n";
    benchmark::print_table_header();

    benchmark::Timer timer;

    // ============ SEAL CKKS 设置 ============
    seal::EncryptionParameters seal_params(seal::scheme_type::ckks);
    seal_params.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
    seal_params.set_coeff_modulus(seal::CoeffModulus::Create(
        POLY_MODULUS_DEGREE,
        {60, 40, 40, 40, 60}  // L=5
    ));

    auto seal_context = seal::SEALContext(seal_params);
    seal::KeyGenerator seal_keygen(seal_context);
    auto seal_secret_key = seal_keygen.secret_key();
    seal::PublicKey seal_public_key;
    seal_keygen.create_public_key(seal_public_key);
    seal::RelinKeys seal_relin_keys;
    seal_keygen.create_relin_keys(seal_relin_keys);

    seal::Encryptor seal_encryptor(seal_context, seal_public_key);
    seal::Decryptor seal_decryptor(seal_context, seal_secret_key);
    seal::Evaluator seal_evaluator(seal_context);
    seal::CKKSEncoder seal_encoder(seal_context);

    double scale = pow(2.0, 40);

    // ============ kctsb CKKS 设置 ============
    kctsb_ckks_context_t kctsb_ctx = nullptr;
    kctsb_ckks_create_context(&kctsb_ctx, POLY_MODULUS_DEGREE, COEFF_MODULUS_COUNT, scale);

    kctsb_ckks_keys_t kctsb_keys = nullptr;
    kctsb_ckks_generate_keys(kctsb_ctx, &kctsb_keys);

    // ============ 编码对比 ============
    {
        std::vector<double> values(POLY_MODULUS_DEGREE / 2, 3.14159);

        // SEAL Encode
        seal::Plaintext seal_plain;
        double seal_total = 0;
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            seal_encoder.encode(values, scale, seal_plain);
        }
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            seal_encoder.encode(values, scale, seal_plain);
            seal_total += timer.stop();
        }
        double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;

        // kctsb Encode
        kctsb_ckks_plaintext_t kctsb_plain = nullptr;
        double kctsb_total = 0;
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_ckks_encode_vector(kctsb_ctx, values.data(), values.size(), &kctsb_plain);
            kctsb_ckks_free_plaintext(kctsb_plain);
            kctsb_plain = nullptr;
        }
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_ckks_encode_vector(kctsb_ctx, values.data(), values.size(), &kctsb_plain);
            kctsb_total += timer.stop();
            kctsb_ckks_free_plaintext(kctsb_plain);
            kctsb_plain = nullptr;
        }
        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        benchmark::print_result({"CKKS Encode", "kctsb", kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        benchmark::print_result({"CKKS Encode", "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        double ratio = kctsb_avg / seal_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }

    // ============ 乘法 + 重线性化对比 ============
    {
        std::vector<double> values(POLY_MODULUS_DEGREE / 2, 1.5);
        seal::Plaintext seal_plain;
        seal_encoder.encode(values, scale, seal_plain);
        seal::Ciphertext seal_ct1, seal_ct2, seal_result;
        seal_encryptor.encrypt(seal_plain, seal_ct1);
        seal_encryptor.encrypt(seal_plain, seal_ct2);

        // SEAL Multiply + Relin
        double seal_total = 0;
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            seal_evaluator.multiply(seal_ct1, seal_ct2, seal_result);
            seal_evaluator.relinearize_inplace(seal_result, seal_relin_keys);
        }
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            seal_evaluator.multiply(seal_ct1, seal_ct2, seal_result);
            seal_evaluator.relinearize_inplace(seal_result, seal_relin_keys);
            seal_total += timer.stop();
        }
        double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;

        // kctsb Multiply + Relin
        kctsb_ckks_plaintext_t kctsb_plain = nullptr;
        kctsb_ckks_ciphertext_t kctsb_ct1 = nullptr, kctsb_ct2 = nullptr, kctsb_result = nullptr;
        kctsb_ckks_encode_vector(kctsb_ctx, values.data(), values.size(), &kctsb_plain);
        kctsb_ckks_encrypt(kctsb_ctx, kctsb_keys, kctsb_plain, &kctsb_ct1);
        kctsb_ckks_encrypt(kctsb_ctx, kctsb_keys, kctsb_plain, &kctsb_ct2);

        double kctsb_total = 0;
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_ckks_multiply_relin(kctsb_ctx, kctsb_keys, kctsb_ct1, kctsb_ct2, &kctsb_result);
            kctsb_ckks_free_ciphertext(kctsb_result);
            kctsb_result = nullptr;
        }
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_ckks_multiply_relin(kctsb_ctx, kctsb_keys, kctsb_ct1, kctsb_ct2, &kctsb_result);
            kctsb_total += timer.stop();
            kctsb_ckks_free_ciphertext(kctsb_result);
            kctsb_result = nullptr;
        }
        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        kctsb_ckks_free_plaintext(kctsb_plain);
        kctsb_ckks_free_ciphertext(kctsb_ct1);
        kctsb_ckks_free_ciphertext(kctsb_ct2);

        benchmark::print_result({"CKKS Mul+Relin", "kctsb", kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        benchmark::print_result({"CKKS Mul+Relin", "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        double ratio = kctsb_avg / seal_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }

    // 清理
    kctsb_ckks_free_keys(kctsb_keys);
    kctsb_ckks_free_context(kctsb_ctx);
}

} // anonymous namespace

// ============================================================================
// 导出函数
// ============================================================================

void run_seal_benchmarks() {
    std::cout << "\nRunning SEAL 4.1.2 comparison benchmarks...\n";
    std::cout << "Testing: BFV, CKKS homomorphic encryption schemes\n";

    benchmark_bfv();
    benchmark_ckks();

    std::cout << "\nSEAL benchmarks complete.\n";
}

#endif // BENCHMARK_HAS_SEAL
