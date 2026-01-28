/**
 * @file rsa.h
 * @brief RSA-PSS/RSAES-OAEP C ABI (SHA-256 only, 3072/4096 bits)
 *
 * Single-file RSA implementation located at `src/crypto/rsa.cpp`.
 * This header provides the RSA-specific include for the public C ABI.
 *
 * Supported:
 * - RSAES-OAEP (SHA-256, MGF1-SHA256)
 * - RSASSA-PSS (SHA-256, salt length 32)
 * - Key sizes: 3072/4096 only
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_RSA_H
#define KCTSB_CRYPTO_RSA_H

#include "kctsb/kctsb_api.h"

#endif // KCTSB_CRYPTO_RSA_H
