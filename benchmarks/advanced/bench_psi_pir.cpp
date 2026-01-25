/**
 * @file bench_psi_pir.cpp
 * @brief PSI/PIR Performance Benchmark
 * 
 * @details Comprehensive performance comparison:
 * - Piano-PSI vs OT-PSI vs Simple-PSI
 * - Native-PIR vs SEAL-PIR (if available)
 * - Various dataset sizes
 * 
 * @author kn1ghtc
 * @version 4.13.0
 * @date 2026-01-25
 */

#include <benchmark/benchmark.h>
#include "kctsb/advanced/psi/psi.h"
#include "kctsb/advanced/psi/native_pir.h"
#include "kctsb/advanced/psi/ot_psi.h"

#include <vector>
#include <random>

/* ============================================================================
 * Test Data Generation
 * ============================================================================ */

static void generate_datasets(size_t client_size, size_t server_size,
                             std::vector<int64_t>& client, std::vector<int64_t>& server) {
    std::mt19937_64 rng(12345);
    std::uniform_int_distribution<int64_t> dist(1, 1000000);
    
    client.resize(client_size);
    server.resize(server_size);
    
    for (auto& v : client) v = dist(rng);
    for (auto& v : server) v = dist(rng);
    
    // Add 20% overlap
    size_t overlap = client_size / 5;
    for (size_t i = 0; i < overlap && i < server_size; ++i) {
        server[i] = client[i];
    }
}

/* ============================================================================
 * Piano-PSI Benchmarks
 * ============================================================================ */

static void BM_PianoPSI_100_100(benchmark::State& state) {
    std::vector<int64_t> client, server;
    generate_datasets(100, 100, client, server);
    
    kctsb_psi_config_t config;
    kctsb_psi_config_init(&config);
    kctsb_psi_ctx_t* ctx = kctsb_piano_psi_create(&config);
    
    for (auto _ : state) {
        kctsb_psi_result_t result;
        kctsb_piano_psi_compute(ctx, client.data(), client.size(),
                               server.data(), server.size(), &result);
        benchmark::DoNotOptimize(result);
    }
    
    kctsb_piano_psi_destroy(ctx);
    state.SetLabel("Piano-PSI 100x100");
}
BENCHMARK(BM_PianoPSI_100_100);

static void BM_PianoPSI_1000_1000(benchmark::State& state) {
    std::vector<int64_t> client, server;
    generate_datasets(1000, 1000, client, server);
    
    kctsb_psi_config_t config;
    kctsb_psi_config_init(&config);
    kctsb_psi_ctx_t* ctx = kctsb_piano_psi_create(&config);
    
    for (auto _ : state) {
        kctsb_psi_result_t result;
        kctsb_piano_psi_compute(ctx, client.data(), client.size(),
                               server.data(), server.size(), &result);
        benchmark::DoNotOptimize(result);
    }
    
    kctsb_piano_psi_destroy(ctx);
    state.SetLabel("Piano-PSI 1000x1000");
}
BENCHMARK(BM_PianoPSI_1000_1000);

/* ============================================================================
 * OT-PSI Benchmarks
 * ============================================================================ */

static void BM_OTPSI_100_100(benchmark::State& state) {
    std::vector<int64_t> client, server;
    generate_datasets(100, 100, client, server);
    
    kctsb_ot_psi_config_t config;
    kctsb_ot_psi_config_init(&config, KCTSB_OT_EXTENSION);
    kctsb_ot_psi_ctx_t* ctx = kctsb_ot_psi_create(&config);
    
    for (auto _ : state) {
        kctsb_ot_psi_result_t result;
        kctsb_ot_psi_compute(ctx, client.data(), client.size(),
                            server.data(), server.size(), &result);
        kctsb_ot_psi_result_free(&result);
        benchmark::DoNotOptimize(result);
    }
    
    kctsb_ot_psi_destroy(ctx);
    state.SetLabel("OT-PSI 100x100");
}
BENCHMARK(BM_OTPSI_100_100);

/* ============================================================================
 * Native PIR Benchmarks
 * ============================================================================ */

static void BM_NativePIR_BGV_100(benchmark::State& state) {
    std::vector<int64_t> database(100);
    for (size_t i = 0; i < 100; ++i) database[i] = i * 10;
    
    kctsb_native_pir_config_t config;
    kctsb_native_pir_config_init(&config, KCTSB_PIR_BGV, database.size());
    kctsb_native_pir_ctx_t* ctx = kctsb_native_pir_create_int(&config, database.data(), database.size());
    
    for (auto _ : state) {
        kctsb_native_pir_result_t result;
        kctsb_native_pir_query(ctx, 42, &result);
        kctsb_native_pir_result_free(&result);
        benchmark::DoNotOptimize(result);
    }
    
    kctsb_native_pir_destroy(ctx);
    state.SetLabel("Native PIR BGV DB=100");
}
BENCHMARK(BM_NativePIR_BGV_100);

static void BM_NativePIR_CKKS_1000(benchmark::State& state) {
    std::vector<double> database(1000);
    for (size_t i = 0; i < 1000; ++i) database[i] = i * 1.5;
    
    kctsb_native_pir_config_t config;
    kctsb_native_pir_config_init(&config, KCTSB_PIR_CKKS, database.size());
    kctsb_native_pir_ctx_t* ctx = kctsb_native_pir_create_double(&config, database.data(), database.size());
    
    for (auto _ : state) {
        kctsb_native_pir_result_t result;
        kctsb_native_pir_query(ctx, 500, &result);
        kctsb_native_pir_result_free(&result);
        benchmark::DoNotOptimize(result);
    }
    
    kctsb_native_pir_destroy(ctx);
    state.SetLabel("Native PIR CKKS DB=1000");
}
BENCHMARK(BM_NativePIR_CKKS_1000);

BENCHMARK_MAIN();
