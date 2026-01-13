/**
 * @file cmd_benchmark.cpp
 * @brief Benchmark subcommand implementation for kctsb CLI
 *
 * Runs performance benchmarks comparing kctsb with OpenSSL
 *
 * Usage:
 *   kctsb benchmark
 *   kctsb benchmark --verbose
 *
 * @author kctsb Development Team
 * @date 2026-01-12
 */

#include <iostream>
#include <string>
#include <cstdlib>
#include <filesystem>

/**
 * @brief Print benchmark subcommand help
 */
void print_benchmark_help() {
    std::cout << "\nUsage: kctsb benchmark [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --verbose      Show detailed output\n";
    std::cout << "  --help         Show this help message\n\n";
    std::cout << "Description:\n";
    std::cout << "  Runs performance benchmarks comparing kctsb implementations\n";
    std::cout << "  against OpenSSL for validation:\n";
    std::cout << "    - AES-256-GCM encryption/decryption\n";
    std::cout << "    - ChaCha20-Poly1305 AEAD\n";
    std::cout << "    - SHA3-256, BLAKE2b hash functions\n\n";
    std::cout << "  Test data sizes: 1KB, 1MB, 10MB\n";
    std::cout << "  Iterations: 100 (warmup: 10)\n\n";
}

/**
 * @brief Find benchmark executable path relative to CLI
 */
static std::string find_benchmark_executable(const char* argv0) {
    namespace fs = std::filesystem;

    // Get directory of current executable
    fs::path exe_path = fs::absolute(argv0);
    fs::path exe_dir = exe_path.parent_path();

    // Look for kctsb_benchmark in same directory
    fs::path benchmark_path = exe_dir / "kctsb_benchmark";
    if (fs::exists(benchmark_path)) {
        return benchmark_path.string();
    }

    // Look in build/bin directory (development)
    benchmark_path = exe_dir / "bin" / "kctsb_benchmark";
    if (fs::exists(benchmark_path)) {
        return benchmark_path.string();
    }

    return "";
}

/**
 * @brief Benchmark subcommand handler
 */
int cmd_benchmark(int argc, char* argv[]) {
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);

        if (arg == "--verbose" || arg == "-v") {
            // Verbose option (pass to benchmark)
        } else if (arg == "--help" || arg == "-h") {
            print_benchmark_help();
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_benchmark_help();
            return 1;
        }
    }

#ifdef KCTSB_BENCHMARK_HAS_OPENSSL
    std::cout << "\nRunning kctsb vs OpenSSL Performance Benchmarks...\n";
    std::cout << "This may take several minutes...\n\n";

    // Find and run the benchmark executable
    std::string benchmark_exe = find_benchmark_executable(argv[0]);
    if (benchmark_exe.empty()) {
        std::cerr << "Error: Benchmark executable not found\n";
        std::cerr << "Make sure kctsb_benchmark is in the same directory as kctsb\n";
        return 1;
    }

    return std::system(benchmark_exe.c_str());
#else
    std::cerr << "Error: Benchmarks not available - OpenSSL not found during build\n";
    std::cerr << "Rebuild with KCTSB_BUILD_BENCHMARKS=ON and OpenSSL available\n";
    return 1;
#endif
}
