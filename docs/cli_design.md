# kctsb CLI Tool Design Document

> **Version**: 3.0.0
> **Date**: 2026-01-12 (Beijing Time, UTC+8)
> **Status**: Architecture Complete, Implementation In Progress

---

## 📋 Overview

The `kctsb` command-line tool provides a unified interface to all cryptographic functions in the kctsb library, inspired by OpenSSL's CLI design pattern.

### Design Goals

1. **OpenSSL-like Interface**: Familiar subcommand structure for cryptographers
2. **Production Ready**: Real file I/O, proper error handling, secure defaults
3. **Modular Architecture**: Each algorithm is a separate subcommand
4. **Cross-Platform**: Windows/Linux/macOS support via CMake
5. **Performance Verification**: Built-in benchmarking against OpenSSL

---

## 🏗️ Architecture

### Directory Structure

```
src/cli/
├── kctsb_main.cpp         # Main entry point, command routing
├── cmd_aes.cpp            # AES encryption/decryption (ECB, CBC, GCM)
├── cmd_hash.cpp           # Hash functions (SHA3-256, BLAKE2b)
├── cmd_rsa.cpp            # RSA operations (genkey, encrypt, sign)
├── cmd_ecc.cpp            # ECC operations (ECDH, ECDSA)
├── cmd_chacha20.cpp       # ChaCha20-Poly1305 AEAD
├── cmd_benchmark.cpp      # Performance benchmarks
└── CMakeLists.txt         # Build configuration
```

### Command Routing Pattern

```cpp
int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    std::string command(argv[1]);
    
    // Route to subcommand handler
    if (command == "aes") {
        return cmd_aes(argc - 1, argv + 1);
    } else if (command == "hash") {
        return cmd_hash(argc - 1, argv + 1);
    }
    // ... other commands
}
```

---

## 📦 Subcommand Specifications

### 1. `kctsb aes` - AES Encryption

**Status**: ✅ Implemented (GCM mode), 🔄 In Progress (ECB, CBC)

**Usage**:
```bash
kctsb aes -encrypt -in plaintext.txt -out ciphertext.bin -key mypassword -mode gcm
kctsb aes -decrypt -in ciphertext.bin -out plaintext.txt -key mypassword -mode gcm
```

**Parameters**:
- `-encrypt` / `-decrypt`: Operation mode
- `-in <file>`: Input file path
- `-out <file>`: Output file path
- `-key <string>`: Encryption key or password
- `-mode <mode>`: AES mode (ecb, cbc, gcm) - default: gcm
- `-keysize <bits>`: Key size (128, 192, 256) - default: 256
- `-iv <hex>`: Initialization vector (optional, auto-generated if not provided)
- `--hex`: Output in hexadecimal format

**Implementation Notes**:
- GCM mode outputs: IV (12 bytes) + Tag (16 bytes) + Ciphertext
- Key derivation: Currently simple padding, TODO: PBKDF2 implementation
- Random IV generation: TODO: Use C++ `<random>` instead of `rand()`

**Files**:
- [src/cli/cmd_aes.cpp](../src/cli/cmd_aes.cpp)

---

### 2. `kctsb hash` - Hash Functions

**Status**: ✅ Implemented (SHA3-256, BLAKE2b), ❌ TODO (SHA-256 requires OpenSSL)

**Usage**:
```bash
kctsb hash -algorithm sha3-256 -in document.pdf
kctsb hash -algorithm blake2b -in large_file.bin -hex
```

**Parameters**:
- `-algorithm <algo>`: Hash algorithm (sha256, sha3-256, blake2b)
- `-in <file>`: Input file path
- `-hex`: Output in hexadecimal (default)
- `-binary`: Output raw binary

**Supported Algorithms**:
| Algorithm | Output Size | Status | Notes |
|-----------|-------------|--------|-------|
| SHA-256 | 32 bytes | ❌ TODO | Requires OpenSSL integration |
| SHA3-256 | 32 bytes | ✅ Ready | NIST FIPS 202 compliant |
| BLAKE2b | 32 bytes | ✅ Ready | High performance |

**Files**:
- [src/cli/cmd_hash.cpp](../src/cli/cmd_hash.cpp)

---

### 3. `kctsb rsa` - RSA Operations

**Status**: 🔄 Placeholder, Awaiting Implementation

**Planned Usage**:
```bash
kctsb rsa -genkey -keysize 2048 -out keypair.pem
kctsb rsa -encrypt -in plaintext.txt -pubkey public.pem -out ciphertext.bin
kctsb rsa -decrypt -in ciphertext.bin -privkey private.pem -out plaintext.txt
kctsb rsa -sign -in document.pdf -privkey private.pem -out signature.sig
kctsb rsa -verify -in document.pdf -pubkey public.pem -sig signature.sig
```

**Parameters**:
- `-genkey`: Generate RSA key pair
- `-encrypt` / `-decrypt`: Encryption/decryption
- `-sign` / `-verify`: Digital signature operations
- `-keysize <bits>`: Key size (2048, 4096) - default: 2048
- `-in <file>`: Input file
- `-out <file>`: Output file
- `-pubkey <file>`: Public key file (PEM format)
- `-privkey <file>`: Private key file (PEM format)
- `-sig <file>`: Signature file

**Implementation Status**:
- Core RSA functions available in `src/crypto/rsa/kc_rsa.cpp`
- TODO: PEM key format encoding/decoding
- TODO: OAEP padding implementation
- TODO: PSS signature scheme

**Files**:
- [src/cli/cmd_rsa.cpp](../src/cli/cmd_rsa.cpp) (placeholder)

---

### 4. `kctsb ecc` - Elliptic Curve Cryptography

**Status**: 🔄 Placeholder, Awaiting Implementation

**Planned Usage**:
```bash
kctsb ecc -genkey -curve secp256k1 -out keypair.pem
kctsb ecc -sign -in message.txt -privkey private.pem -out signature.sig
kctsb ecc -verify -in message.txt -pubkey public.pem -sig signature.sig
kctsb ecc -derive -privkey alice.pem -pubkey bob_public.pem -out shared_secret.bin
```

**Parameters**:
- `-genkey`: Generate ECC key pair
- `-sign` / `-verify`: ECDSA signature operations
- `-derive`: ECDH shared secret derivation
- `-curve <name>`: Curve name (secp256k1, P-256) - default: secp256k1
- `-in <file>`: Input file
- `-out <file>`: Output file

**Supported Curves**:
- secp256k1 (Bitcoin/Ethereum standard)
- P-256 (NIST standard)

**Implementation Status**:
- ECC group operations available in `src/crypto/ecc/eccGroup.hpp`
- TODO: ECDSA signature generation/verification
- TODO: ECDH key derivation
- TODO: Key serialization (PEM format)

**Files**:
- [src/cli/cmd_ecc.cpp](../src/cli/cmd_ecc.cpp) (placeholder)

---

### 5. `kctsb chacha20` - ChaCha20-Poly1305 AEAD

**Status**: 🔄 Placeholder, Awaiting Implementation

**Planned Usage**:
```bash
kctsb chacha20 -encrypt -in plaintext.txt -out ciphertext.bin -key mypassword
kctsb chacha20 -decrypt -in ciphertext.bin -out plaintext.txt -key mypassword
```

**Parameters**:
- `-encrypt` / `-decrypt`: Operation mode
- `-in <file>`: Input file
- `-out <file>`: Output file
- `-key <string>`: 256-bit key or password

**Implementation Status**:
- Core ChaCha20 functions available in `src/crypto/chacha20/`
- TODO: Poly1305 MAC integration
- TODO: AEAD wrapper (nonce + tag + ciphertext)

**Files**:
- [src/cli/cmd_chacha20.cpp](../src/cli/cmd_chacha20.cpp) (placeholder)

---

### 6. `kctsb benchmark` - Performance Benchmarks

**Status**: ✅ Implemented

**Usage**:
```bash
kctsb benchmark
kctsb benchmark --verbose
```

**Features**:
- Compares kctsb implementations against OpenSSL
- Tests: AES-256-GCM, ChaCha20-Poly1305, SHA3-256, BLAKE2b
- Data sizes: 1KB, 1MB, 10MB
- Iterations: 100 (warmup: 10)

**Output Example**:
```
╔════════════════════════════════════════════════════════════════════╗
║         kctsb vs OpenSSL Performance Benchmark Suite              ║
║                     Version 3.0.0                                  ║
╚════════════════════════════════════════════════════════════════════╝

OpenSSL Version: OpenSSL 3.6.0
Test Data Sizes: 1KB, 1MB, 10MB
Iterations per test: 100 (warmup: 10)

=== AES-256-GCM Benchmark ===
...
```

**Files**:
- [src/cli/cmd_benchmark.cpp](../src/cli/cmd_benchmark.cpp)
- [benchmarks/benchmark_main.cpp](../benchmarks/benchmark_main.cpp) (shared logic)

---

### 7. `kctsb version` - Version Information

**Status**: ✅ Implemented

**Usage**:
```bash
kctsb version
kctsb -v
kctsb --version
```

**Output**:
```
╔════════════════════════════════════════════════════════════════╗
║  kctsb - Knight's Cryptographic Trusted Security Base         ║
╚════════════════════════════════════════════════════════════════╝

Version:      3.0.0
Build Date:   2026-01-12 (Beijing Time, UTC+8)
License:      Apache License 2.0
Author:       kctsb Development Team

Supported Algorithms:
  - AES-128/192/256 (ECB, CBC, GCM)
  - ChaCha20-Poly1305 AEAD
  - SHA-256, SHA3-256, BLAKE2b
  - RSA-2048/4096 (OAEP, PSS)
  - ECC (ECDH, ECDSA, secp256k1, P-256)

Dependencies:
  - NTL 11.6.0 (Number Theory Library)
  - GMP 6.3.0 (GNU Multiple Precision Arithmetic)
  - Microsoft SEAL 4.1.2 (Homomorphic Encryption)
  - OpenSSL 3.6.0 (for benchmarking)
```

---

## 🔧 Build Configuration

### CMake Integration

The CLI tool is automatically built when `KCTSB_BUILD_CLI=ON` (default).

**Build Command**:
```powershell
cd D:\pyproject\kctsb\build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build . --target kctsb --parallel
```

**Output**:
- Executable: `build/bin/kctsb.exe` (Windows)
- Executable: `build/bin/kctsb` (Linux/macOS)

### Dependencies

The CLI tool links against:
- `kctsb_static` (main library)
- `NTL::NTL` (if `KCTSB_ENABLE_NTL=ON`)
- `OpenSSL::SSL`, `OpenSSL::Crypto` (if `KCTSB_ENABLE_OPENSSL=ON`)
- `SEAL::seal` (if `KCTSB_ENABLE_SEAL=ON`)

---

## 📝 Development Roadmap

### Phase 1: Core Infrastructure ✅ DONE (2026-01-12)
- [x] Main entry point and command routing
- [x] Help system and usage documentation
- [x] Version information display
- [x] CMake build configuration

### Phase 2: Essential Algorithms 🔄 IN PROGRESS
- [x] AES-GCM encryption/decryption
- [x] SHA3-256, BLAKE2b hash functions
- [x] Benchmark subcommand
- [ ] AES-ECB, AES-CBC modes
- [ ] Proper key derivation (PBKDF2)
- [ ] Secure random number generation

### Phase 3: Advanced Algorithms ⏳ PLANNED
- [ ] RSA key generation, encryption, signing
- [ ] ECC key generation, ECDH, ECDSA
- [ ] ChaCha20-Poly1305 AEAD
- [ ] PEM key format support
- [ ] Base64 encoding/decoding utilities

### Phase 4: Production Hardening ⏳ PLANNED
- [ ] Input validation and sanitization
- [ ] Memory zeroization for sensitive data
- [ ] Constant-time operations for crypto primitives
- [ ] Comprehensive error handling
- [ ] Unit tests for CLI argument parsing
- [ ] Integration tests with file I/O

### Phase 5: OpenSSL Comparison 🎯 GOAL
- [ ] Complete performance benchmark suite
- [ ] Feature parity analysis report
- [ ] Security audit and gap analysis
- [ ] Documentation: `docs/analysis/openssl_comparison.md`

---

## 🎯 Comparison with OpenSSL CLI

### Implemented Features

| Feature | OpenSSL | kctsb | Status |
|---------|---------|-------|--------|
| AES-GCM encryption | ✅ | ✅ | Implemented |
| SHA3-256 hash | ✅ | ✅ | Implemented |
| BLAKE2b hash | ❌ | ✅ | kctsb advantage |
| Benchmark suite | ✅ | ✅ | Implemented |
| Version info | ✅ | ✅ | Implemented |

### Planned Features

| Feature | OpenSSL | kctsb | Priority |
|---------|---------|-------|----------|
| RSA operations | ✅ | 🔄 | High |
| ECC operations | ✅ | 🔄 | High |
| ChaCha20-Poly1305 | ✅ | 🔄 | Medium |
| PEM key format | ✅ | 🔄 | Medium |
| Base64 encoding | ✅ | 🔄 | Low |

### Unique kctsb Features

1. **Integrated Benchmarking**: Built-in performance comparison with OpenSSL
2. **BLAKE2b Support**: High-performance hash function not in OpenSSL standard tools
3. **NTL Integration**: Advanced number theory operations for research
4. **SEAL Support**: Homomorphic encryption capabilities (future)

---

## 📚 References

### OpenSSL CLI Documentation
- [OpenSSL Command-Line Cookbook](https://www.feistyduck.com/library/openssl-cookbook/)
- [OpenSSL Manual Pages](https://www.openssl.org/docs/man3.0/)

### Design Inspirations
- `llmAttack/honorLLM_attack.py` - Argparse patterns
- `NetPenetration/webScan/subdomain.py` - CLI best practices
- `benchmarks/benchmark_main.cpp` - Performance testing framework

---

## 📄 License

Apache License 2.0 - See [LICENSE](../LICENSE)

---

**Last Updated**: 2026-01-12 (Beijing Time, UTC+8)
**Maintainer**: kctsb Development Team
