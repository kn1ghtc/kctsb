# kctsb v5.0.0 - macOS x64 Release

## Quick Start

This is a pre-built release of kctsb cryptographic library for macOS x86_64.

### Contents
```
macos-x64/
├── bin/kctsb              # CLI tool (74KB)
├── lib/
│   ├── libkctsb.5.0.0.dylib  # Main shared library (1.5MB)
│   ├── libkctsb.5.dylib      # Version symlink
│   └── libkctsb.dylib        # Generic symlink
├── include/kctsb_api.h    # Public API header
├── RELEASE_INFO.txt       # Detailed build information
└── README.md              # This file
```

### System Requirements
- **OS**: macOS 11.0+ (Big Sur or later)
- **Architecture**: Intel x86_64 (use Rosetta 2 on Apple Silicon)
- **Dependencies**: System frameworks only (no external libraries required)

### CLI Tool Usage

```bash
# Test the CLI tool
export DYLD_LIBRARY_PATH=/path/to/macos-x64/lib:$DYLD_LIBRARY_PATH
./bin/kctsb version

# Hash examples
./bin/kctsb hash --sha3-256 "Hello, World!"
./bin/kctsb hash --blake2b "Test message"

# Full help
./bin/kctsb --help
```

### Library Integration

**Method 1: Using DYLD_LIBRARY_PATH (Simple)**

```bash
# Compile your app
clang++ -std=c++17 myapp.cpp -I./include -L./lib -lkctsb -o myapp

# Run with library path
export DYLD_LIBRARY_PATH=/path/to/macos-x64/lib:$DYLD_LIBRARY_PATH
./myapp
```

**Method 2: Using install_name_tool (Recommended for distribution)**

```bash
# Compile
clang++ -std=c++17 myapp.cpp -I./include -L./lib -lkctsb -o myapp

# Fix library path
install_name_tool -change @rpath/libkctsb.5.dylib \
  /absolute/path/to/macos-x64/lib/libkctsb.5.dylib myapp

# Now myapp can run without DYLD_LIBRARY_PATH
./myapp
```

**Method 3: Using rpath (Best for relative paths)**

```bash
# Assuming your app structure is:
# myproject/
#   ├── bin/myapp
#   └── lib/libkctsb.5.dylib

clang++ -std=c++17 myapp.cpp -I./include -L./lib -lkctsb \
  -Wl,-rpath,@executable_path/../lib -o bin/myapp

# Copy library to your project
mkdir -p myproject/lib
cp lib/libkctsb.5.dylib myproject/lib/

# Run directly
./myproject/bin/myapp
```

### Example Code

```cpp
#include "kctsb_api.h"
#include <iostream>
#include <iomanip>

int main() {
    // SHA3-256 example
    const char* message = "Hello, kctsb!";
    uint8_t digest[32];

    kctsb_error_t ret = kctsb_sha3_256(
        reinterpret_cast<const uint8_t*>(message),
        strlen(message),
        digest
    );

    if (ret == KCTSB_SUCCESS) {
        std::cout << "SHA3-256: ";
        for (int i = 0; i < 32; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << (int)digest[i];
        }
        std::cout << std::endl;
    }

    return 0;
}
```

### Verify Installation

```bash
# Check library dependencies
otool -L lib/libkctsb.5.0.0.dylib

# Expected output (system libraries only):
#   @rpath/libkctsb.5.dylib
#   /System/Library/Frameworks/Security.framework/...
#   /usr/lib/libc++.1.dylib
#   /usr/lib/libSystem.B.dylib

# Test CLI
DYLD_LIBRARY_PATH=./lib ./bin/kctsb version
```

### Troubleshooting

**Q: "Library not loaded: @rpath/libkctsb.5.dylib"**

A: Use one of these solutions:
```bash
# Option 1: Set library path
export DYLD_LIBRARY_PATH=/path/to/macos-x64/lib:$DYLD_LIBRARY_PATH

# Option 2: Fix the binary
install_name_tool -change @rpath/libkctsb.5.dylib \
  /absolute/path/to/lib/libkctsb.5.dylib ./myapp

# Option 3: Copy library to system location (not recommended)
sudo cp lib/libkctsb.5.dylib /usr/local/lib/
```

**Q: Compatibility with older macOS?**

A: This build requires macOS 11.0+. For older versions, rebuild from source with appropriate deployment target:
```bash
cmake -B build -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15
```

### Features

- **Symmetric Crypto**: AES-GCM, ChaCha20-Poly1305, SM4-GCM
- **Hash Functions**: SHA-256/512, SHA3-256/512, BLAKE2b, SM3
- **Asymmetric**: RSA, ECDSA/ECDH (secp256k1, P-256), SM2
- **Post-Quantum**: Kyber (ML-KEM), Dilithium (ML-DSA)
- **Advanced**: Homomorphic Encryption (BGV/BFV/CKKS), PSI/PIR, Zero-Knowledge Proofs
- **Hardware Acceleration**: AES-NI, PCLMUL, SHA-NI, AVX2 (when available)

### Documentation

- Full API documentation: `include/kctsb_api.h`
- Build information: `RELEASE_INFO.txt`
- Source code: https://github.com/kn1ghtc/kctsb

### License

Apache License 2.0 - See source repository for details

### Contact

For issues and questions: https://github.com/kn1ghtc/kctsb/issues
