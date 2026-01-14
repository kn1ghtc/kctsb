/**
 * @file kctsb.h
 * @brief Main header file for kctsb cryptographic library
 * 
 * This is the primary include file for the kctsb (Knight's Cryptographic
 * Toolset and Security Base) library. Include this file to access all
 * cryptographic algorithms and utilities.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 * @version 3.2.0
 */

#ifndef KCTSB_H
#define KCTSB_H

// Version information
#define KCTSB_VERSION_MAJOR 3
#define KCTSB_VERSION_MINOR 2
#define KCTSB_VERSION_PATCH 0
#define KCTSB_VERSION_STRING "3.2.0"

// Core headers (must be included first - defines KCTSB_API and platform macros)
#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

// Symmetric encryption
#include "kctsb/crypto/aes.h"
#include "kctsb/crypto/chacha.h"

// Hash functions
#include "kctsb/crypto/sha.h"
#include "kctsb/crypto/blake.h"

// MAC algorithms
#include "kctsb/crypto/mac.h"

// Asymmetric encryption
#include "kctsb/crypto/rsa.h"
#include "kctsb/crypto/ecc.h"

// Chinese National Standards (SM series)
#include "kctsb/crypto/sm2.h"
#include "kctsb/crypto/sm3.h"
#include "kctsb/crypto/sm4.h"

// Advanced cryptographic primitives
#include "kctsb/advanced/whitebox.h"
#include "kctsb/advanced/sss.h"
#include "kctsb/advanced/zk.h"
#include "kctsb/advanced/lattice.h"
#include "kctsb/advanced/fuzzy.h"
#include "kctsb/advanced/fe.h"

// Mathematical utilities
#include "kctsb/math/common.h"
#include "kctsb/math/polynomials.h"
#include "kctsb/math/vector.h"

// Utility functions
#include "kctsb/utils/encoding.h"
#include "kctsb/utils/random.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the library version string
 * @return Version string in format "major.minor.patch"
 */
KCTSB_API const char* kctsb_version(void);

/**
 * @brief Get the platform name
 * @return Platform name string
 */
KCTSB_API const char* kctsb_platform(void);

/**
 * @brief Initialize the kctsb library
 * @return 0 on success, non-zero on failure
 */
KCTSB_API int kctsb_init(void);

/**
 * @brief Cleanup and free resources used by kctsb
 */
KCTSB_API void kctsb_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_H
