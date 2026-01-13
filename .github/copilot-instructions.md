# kctsb C/C++ Coding Standards and Best Practices

> **Target**: GitHub Copilot and AI-assisted development  
> **Project**: kctsb - Knight's Cryptographic Trusted Security Base  
> **Version**: 3.1.0  
> **Last Updated**: 2026-01-13

---

## 🎯 Project Overview

kctsb is a **production-grade** cross-platform cryptographic library designed to replace OpenSSL with native C/C++ implementations. All code must meet the highest standards of security, correctness, and performance.

### Core Principles

1. **Security First**: All cryptographic operations must be constant-time when handling secret data
2. **Production Quality**: No mock/placeholder code - all implementations must pass standard test vectors
3. **Native Implementation**: Core algorithms (src/) **MUST NOT** use OpenSSL - only benchmarks/ may use it for comparison
4. **Cross-Platform**: Support Windows/Linux/macOS with CMake + Ninja
5. **Performance**: Target to match or exceed OpenSSL performance (-O3, -march=native, -flto)

---

## 📋 Code Formatting Standards

### General Rules

- **Indentation**: 4 spaces (NO TABS)
- **Line Length**: 100 characters maximum
- **File Encoding**: UTF-8 without BOM (except Windows-specific files if needed)
- **Line Endings**: LF (Unix-style) for all files

### C Code Style (K&R)

```c
/* Function comment using Doxygen format */
/**
 * @brief Brief description of function
 * @param key Encryption key (must be 32 bytes for AES-256)
 * @param data Input data buffer
 * @param len Length of input data
 * @return KCTSB_SUCCESS on success, error code otherwise
 * @warning This function handles sensitive key material
 */
int kctsb_aes_encrypt(const uint8_t *key, const uint8_t *data, size_t len) {
    if (key == NULL || data == NULL) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    /* Local variables */
    uint8_t temp_buffer[16];
    size_t processed = 0;
    
    /* Main processing loop */
    while (processed < len) {
        /* ... */
        processed += 16;
    }
    
    /* Cleanup sensitive data */
    kctsb_secure_memzero(temp_buffer, sizeof(temp_buffer));
    return KCTSB_SUCCESS;
}
```

### C++ Code Style (Allman)

```cpp
/**
 * @brief AES-GCM encryption class
 * @details Provides AEAD encryption using AES-256 in GCM mode
 */
class AesGcm
{
public:
    /**
     * @brief Constructor with key material
     * @param key 256-bit encryption key
     */
    explicit AesGcm(const std::array<uint8_t, 32>& key)
        : m_key(key)
        , m_initialized(false)
    {
        initialize();
    }
    
    /**
     * @brief Encrypt plaintext with authentication
     * @param plaintext Input data to encrypt
     * @param aad Additional authenticated data (not encrypted)
     * @return Ciphertext with appended authentication tag
     */
    std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad)
    {
        // Validate inputs
        if (plaintext.empty())
        {
            throw std::invalid_argument("Plaintext cannot be empty");
        }
        
        // Process encryption
        std::vector<uint8_t> ciphertext;
        // ... implementation ...
        
        return ciphertext;
    }
    
private:
    std::array<uint8_t, 32> m_key;  ///< Encryption key (sensitive)
    bool m_initialized;              ///< Initialization state
    
    void initialize();
};
```

---

## 🔤 Naming Conventions

### C API Functions

```c
/* Format: kctsb_<module>_<action>() */
int kctsb_aes_gcm_encrypt(/* ... */);
int kctsb_sha3_256_hash(/* ... */);
int kctsb_ecdsa_sign(/* ... */);
void kctsb_secure_memzero(void *ptr, size_t len);
```

### C++ Classes and Methods

```cpp
/* Classes: PascalCase */
class ChaCha20Poly1305;
class EccPoint;
class RsaPrivateKey;

/* Member variables: m_ prefix + camelCase */
class CryptoContext
{
private:
    uint8_t* m_keyMaterial;
    size_t m_keyLength;
    bool m_isInitialized;
};

/* Methods: camelCase */
void initializeContext();
std::vector<uint8_t> encryptData(const std::vector<uint8_t>& input);
```

### Constants and Macros

```c
/* All uppercase with KCTSB_ prefix */
#define KCTSB_AES_BLOCK_SIZE 16
#define KCTSB_SHA3_256_DIGEST_SIZE 32
#define KCTSB_MAX_KEY_LENGTH 256

/* Error codes */
#define KCTSB_SUCCESS 0
#define KCTSB_ERROR_INVALID_PARAM -1
#define KCTSB_ERROR_CRYPTO_FAILURE -2
```

### File Naming

```
/* C files */
src/crypto/aes/aes_gcm.c
src/crypto/hash/sha3.c

/* C++ files */
src/crypto/ecc/ecc_curve.cpp
src/advanced/zk/kc_ffs.cpp

/* Headers - ALL in include/ directory */
include/kctsb/crypto/aes.h
include/kctsb/crypto/hash/sha3.h
include/kctsb/internal/blake2_impl.h
```

---

## 🔒 Security-First Coding Practices

### 1. Constant-Time Operations

**ALWAYS** use constant-time operations when handling secret data:

```c
/* BAD - timing leak */
int compare_keys_unsafe(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return 0;  /* Early exit reveals position of difference! */
        }
    }
    return 1;
}

/* GOOD - constant time */
int kctsb_secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];  /* No early exit */
    }
    return (diff == 0) ? 1 : 0;
}
```

### 2. Secure Memory Handling

**ALWAYS** clear sensitive data after use:

```c
void process_encryption(const uint8_t *key, const uint8_t *data, size_t len) {
    uint8_t temp_key[32];
    uint8_t iv[16];
    
    /* Use key material */
    memcpy(temp_key, key, 32);
    /* ... encryption operations ... */
    
    /* MANDATORY: Zero sensitive data before return */
    kctsb_secure_memzero(temp_key, sizeof(temp_key));
    kctsb_secure_memzero(iv, sizeof(iv));
}

/* Secure memzero implementation (prevents compiler optimization) */
void kctsb_secure_memzero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) return;
    
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}
```

### 3. Input Validation

**ALWAYS** validate inputs before processing:

```c
int kctsb_aes_gcm_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len)
{
    /* Validate pointers */
    if (key == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    /* Validate key length */
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        return KCTSB_ERROR_INVALID_KEY_LENGTH;
    }
    
    /* Validate output buffer size */
    if (*ciphertext_len < plaintext_len + KCTSB_GCM_TAG_SIZE) {
        *ciphertext_len = plaintext_len + KCTSB_GCM_TAG_SIZE;
        return KCTSB_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Process encryption */
    /* ... */
    
    return KCTSB_SUCCESS;
}
```

### 4. Random Number Generation

**NEVER** use `rand()` or `srand()` for cryptographic purposes:

```c
/* BAD - DO NOT USE */
void generate_key_unsafe(uint8_t *key, size_t len) {
    srand(time(NULL));  /* Predictable! */
    for (size_t i = 0; i < len; i++) {
        key[i] = rand() % 256;
    }
}

/* GOOD - Use platform CSPRNG */
int kctsb_random_bytes(uint8_t *buffer, size_t len) {
#ifdef _WIN32
    /* Windows: BCryptGenRandom */
    return BCryptGenRandom(NULL, buffer, (ULONG)len, 
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    /* Linux/macOS: /dev/urandom or getrandom() */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) return KCTSB_ERROR_RANDOM_FAILED;
    
    size_t read = fread(buffer, 1, len, f);
    fclose(f);
    
    return (read == len) ? KCTSB_SUCCESS : KCTSB_ERROR_RANDOM_FAILED;
#endif
}
```

---

## ⚠️ Error Handling Patterns

### C Error Handling

```c
/* Return error codes, never use errno for crypto errors */
typedef enum {
    KCTSB_SUCCESS = 0,
    KCTSB_ERROR_INVALID_PARAM = -1,
    KCTSB_ERROR_BUFFER_TOO_SMALL = -2,
    KCTSB_ERROR_CRYPTO_FAILURE = -3,
    KCTSB_ERROR_RANDOM_FAILED = -4,
    KCTSB_ERROR_SIGNATURE_INVALID = -5
} kctsb_error_t;

/* Usage */
int result = kctsb_aes_encrypt(key, data, len);
if (result != KCTSB_SUCCESS) {
    /* Handle error */
    fprintf(stderr, "Encryption failed: %d\n", result);
    return result;
}
```

### C++ Error Handling

```cpp
/* Use exceptions for exceptional conditions */
class CryptoException : public std::runtime_error
{
public:
    explicit CryptoException(const std::string& message)
        : std::runtime_error(message)
    {
    }
};

/* Usage */
try {
    auto ciphertext = aes.encrypt(plaintext, iv);
} catch (const CryptoException& e) {
    std::cerr << "Encryption failed: " << e.what() << std::endl;
    throw;
}
```

---

## 📖 Documentation Requirements

### Doxygen Comments (Required for All Public APIs)

```c
/**
 * @file aes_gcm.h
 * @brief AES-GCM AEAD encryption implementation
 * @details Provides AES encryption in Galois/Counter Mode with authentication
 * 
 * This implementation follows NIST SP 800-38D specifications.
 * Supports 128-bit, 192-bit, and 256-bit keys.
 * 
 * @warning IV/Nonce must NEVER be reused with the same key
 * @note This is a software implementation - consider AES-NI for production
 */

/**
 * @brief Encrypt data using AES-256-GCM
 * 
 * @param[in] key 256-bit encryption key (32 bytes)
 * @param[in] key_len Length of key in bytes (must be 32)
 * @param[in] iv Initialization vector (12 bytes recommended)
 * @param[in] iv_len Length of IV in bytes
 * @param[in] plaintext Data to encrypt
 * @param[in] plaintext_len Length of plaintext
 * @param[in] aad Additional authenticated data (can be NULL)
 * @param[in] aad_len Length of AAD
 * @param[out] ciphertext Output buffer for encrypted data + tag
 * @param[in,out] ciphertext_len Input: buffer size, Output: actual size
 * 
 * @return KCTSB_SUCCESS on success, error code otherwise
 * @retval KCTSB_ERROR_INVALID_PARAM Invalid input parameters
 * @retval KCTSB_ERROR_BUFFER_TOO_SMALL Output buffer too small
 * 
 * @pre key != NULL && iv != NULL && ciphertext != NULL
 * @post ciphertext contains encrypted data + 16-byte authentication tag
 * 
 * @warning Never reuse the same (key, IV) pair
 * @note IV should be 12 bytes for optimal performance
 * 
 * @par Example:
 * @code
 * uint8_t key[32];
 * uint8_t iv[12];
 * uint8_t plaintext[] = "Hello, World!";
 * uint8_t ciphertext[128];
 * size_t ct_len = sizeof(ciphertext);
 * 
 * kctsb_random_bytes(key, sizeof(key));
 * kctsb_random_bytes(iv, sizeof(iv));
 * 
 * int result = kctsb_aes_gcm_encrypt(
 *     key, sizeof(key),
 *     iv, sizeof(iv),
 *     plaintext, sizeof(plaintext),
 *     NULL, 0,
 *     ciphertext, &ct_len
 * );
 * @endcode
 */
int kctsb_aes_gcm_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t *ciphertext_len);
```

---

## ✅ Testing Requirements

### Unit Test Structure (GoogleTest)

```cpp
#include <gtest/gtest.h>
#include <kctsb/crypto/aes.h>

/* Test fixture */
class AesGcmTest : public ::testing::Test
{
protected:
    void SetUp() override {
        /* Initialize test data */
        kctsb_random_bytes(m_key, sizeof(m_key));
    }
    
    void TearDown() override {
        /* Cleanup sensitive data */
        kctsb_secure_memzero(m_key, sizeof(m_key));
    }
    
    uint8_t m_key[32];
};

/* Test case: Standard test vector */
TEST_F(AesGcmTest, NIST_TestVector_AES256_GCM) {
    /* NIST CAVP test vector */
    const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, /* ... */
    };
    const uint8_t iv[12] = { /* ... */ };
    const uint8_t plaintext[] = "Test message";
    const uint8_t expected_ciphertext[] = { /* ... */ };
    
    uint8_t ciphertext[128];
    size_t ct_len = sizeof(ciphertext);
    
    int result = kctsb_aes_gcm_encrypt(
        key, sizeof(key),
        iv, sizeof(iv),
        plaintext, sizeof(plaintext),
        NULL, 0,
        ciphertext, &ct_len
    );
    
    ASSERT_EQ(result, KCTSB_SUCCESS);
    ASSERT_EQ(ct_len, sizeof(plaintext) + 16);  /* + GCM tag */
    EXPECT_EQ(0, memcmp(ciphertext, expected_ciphertext, ct_len));
}

/* Test case: Error handling */
TEST_F(AesGcmTest, ErrorHandling_NullPointer) {
    uint8_t ciphertext[128];
    size_t ct_len = sizeof(ciphertext);
    
    int result = kctsb_aes_gcm_encrypt(
        NULL, 32,  /* NULL key should fail */
        m_iv, sizeof(m_iv),
        m_plaintext, sizeof(m_plaintext),
        NULL, 0,
        ciphertext, &ct_len
    );
    
    EXPECT_EQ(result, KCTSB_ERROR_INVALID_PARAM);
}
```

### Test Coverage Requirements

- **Minimum coverage**: 80% for new code
- **Standard test vectors**: MUST pass NIST/RFC/GM test vectors
- **Edge cases**: Empty input, maximum sizes, NULL pointers
- **Error paths**: All error returns must be tested
- **Security tests**: Side-channel resistance (where applicable)

---

## 📝 Language and Code Comments

### Code Language Policy

- **Code (src/)**: ALL identifiers, comments, and documentation in **English only**
- **Documentation (docs/)**: Can be bilingual (English + Chinese)
- **Commit messages**: English preferred

```c
/* CORRECT - English comments */
/**
 * @brief Generate random initialization vector
 * @param iv Output buffer for IV (must be 16 bytes)
 * @return KCTSB_SUCCESS or error code
 */
int kctsb_generate_iv(uint8_t *iv);

/* INCORRECT - No Chinese in code */
/* 生成随机初始化向量 */  /* DON'T DO THIS */
int kctsb_generate_iv(uint8_t *iv);
```

---

## 🎯 Code Review Checklist

Before submitting code, verify:

- [ ] All functions have Doxygen comments
- [ ] No Chinese comments/identifiers in src/
- [ ] All sensitive data is cleared with `kctsb_secure_memzero()`
- [ ] Constant-time operations used for secret data
- [ ] Input validation at function entry
- [ ] Error codes returned (C) or exceptions thrown (C++)
- [ ] Standard test vectors pass (NIST/RFC/GM)
- [ ] Code formatted with 4-space indent, 100-char lines
- [ ] No OpenSSL includes in src/ directory
- [ ] Headers in include/, implementations in src/
- [ ] UTF-8 encoding for all files
- [ ] No compiler warnings with -Wall -Wextra
- [ ] GoogleTest unit tests added
- [ ] Performance benchmarked against OpenSSL

---

## 🔗 References

- NIST Cryptographic Standards: https://csrc.nist.gov/publications
- RFC 7539 (ChaCha20-Poly1305): https://tools.ietf.org/html/rfc7539
- RFC 7693 (BLAKE2): https://tools.ietf.org/html/rfc7693
- FIPS 197 (AES): https://csrc.nist.gov/publications/detail/fips/197/final
- FIPS 202 (SHA-3): https://csrc.nist.gov/publications/detail/fips/202/final
- Side-channel attacks: "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS"

---

**Remember**: Security and correctness come before performance. When in doubt, choose the safer implementation.
