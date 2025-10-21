# kctsb

A comprehensive C++ cryptographic algorithms library implementing various modern cryptographic primitives and security protocols.

## Overview

**kctsb** (Knight's Cryptographic Toolset and Security Base) is a collection of cryptographic algorithm implementations in C++. This library provides implementations of various encryption algorithms, hash functions, digital signatures, and advanced cryptographic primitives including homomorphic encryption and zero-knowledge proofs.

## Features

### Symmetric Encryption
- **AES (Advanced Encryption Standard)** - Including whitebox implementations
- **ChaCha** - Stream cipher
- **SM4** - Chinese national standard block cipher

### Asymmetric Encryption
- **RSA** - Public-key cryptosystem
- **ECC (Elliptic Curve Cryptography)** - Elliptic curve operations
- **SM2** - Chinese national standard public-key cryptography

### Hash Functions & MAC
- **SHA** - Secure Hash Algorithm family
- **SM3** - Chinese national standard hash function
- **BLAKE** - Cryptographic hash function
- **MAC** - Message Authentication Code implementations

### Advanced Cryptographic Primitives
- **Whitebox Cryptography** - Implementation of Chow's whitebox AES
- **Zero-Knowledge Proofs (ZK)** - Zero-knowledge proof systems
- **Homomorphic Encryption** - Privacy-preserving computation support
- **Lattice-based Cryptography** - Post-quantum cryptographic primitives
- **Secret Sharing Scheme (SSS)** - Threshold cryptography
- **Fuzzy Extractor** - Secure key generation from noisy data
- **Format-Preserving Encryption (FE)** - Encryption that preserves data format

### Mathematical Libraries
- **Polynomials** - Polynomial arithmetic operations
- **Linear Vectors** - Vector and matrix operations
- **Common Math Functions** - GCD, modular arithmetic, etc.
- **Probability & Statistics** - Statistical functions

## Dependencies

This project requires the following third-party libraries:

- **NTL (Number Theory Library)** - For number-theoretic computations
- **GMP (GNU Multiple Precision Arithmetic Library)** - For arbitrary precision arithmetic
- **GF2X** - For arithmetic of polynomials over the binary field
- **HElib** - For homomorphic encryption operations
- **OpenSSL** - For cryptographic primitives
- **SEAL (Simple Encrypted Arithmetic Library)** - For homomorphic encryption

## Project Structure

```
kctsb/
├── kcalg/                      # Main source directory
│   ├── include/opentsb/        # Public header files
│   ├── sec/                    # Security algorithms implementations
│   │   ├── aes/               # AES implementations
│   │   ├── rsa/               # RSA implementations
│   │   ├── ecc/               # Elliptic curve cryptography
│   │   ├── sm/                # Chinese SM algorithms (SM2, SM3, SM4)
│   │   ├── whitebox/          # Whitebox cryptography
│   │   ├── zk/                # Zero-knowledge proofs
│   │   ├── lattice/           # Lattice-based cryptography
│   │   ├── sss/               # Secret sharing schemes
│   │   ├── fuzzyExtrac/       # Fuzzy extractors
│   │   ├── fe/                # Format-preserving encryption
│   │   ├── mac/               # MAC implementations
│   │   ├── sha/               # SHA hash functions
│   │   ├── blake/             # BLAKE hash function
│   │   └── chacha/            # ChaCha cipher
│   ├── math/                  # Mathematical utilities
│   ├── cplus/                 # C++ utilities
│   ├── test/                  # Test files
│   ├── thirdpart/             # Third-party libraries
│   └── main.cpp               # Example usage
├── kcalg.xcodeproj/           # Xcode project files
├── LICENSE                    # Apache 2.0 License
└── README.md                  # This file
```

## Building

This project uses Xcode for building on macOS:

1. Open `kcalg.xcodeproj` in Xcode
2. Configure the build settings and paths to third-party libraries
3. Build the project (⌘+B)

### Prerequisites

Before building, ensure you have installed the required dependencies:

```bash
# Install GMP
brew install gmp

# Install NTL (requires GMP)
brew install ntl

# Install OpenSSL
brew install openssl
```

For HElib and SEAL, you may need to build them from source and configure the library paths in the Xcode project.

## Usage

Include the necessary headers in your C++ code:

```cpp
#include "opentsb/kc_sec.h"
#include "opentsb/kc_sm.h"
#include "opentsb/math.h"
#include "opentsb/aes.h"
// ... other headers as needed
```

See `kcalg/main.cpp` for example usage of the various algorithms.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Author

Created by knightc (owner: tsb)

Copyright © 2019 knightc. All rights reserved.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## Security Notice

This library is provided for educational and research purposes. While implementations follow standard specifications, they have not undergone formal security audits. Use in production environments at your own risk.

## References

- [NTL: A Library for doing Number Theory](https://libntl.org/)
- [GMP: The GNU Multiple Precision Arithmetic Library](https://gmplib.org/)
- [HElib: An Implementation of homomorphic encryption](https://github.com/homenc/HElib)
- [Microsoft SEAL](https://github.com/microsoft/SEAL)
- [OpenSSL](https://www.openssl.org/)
