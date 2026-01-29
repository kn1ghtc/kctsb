/**
 * @file kctsb.h
 * @brief kctsb v5.0 - Self-Contained Cryptographic Library
 * 
 * Unified internal header for kctsb cryptographic modules.
 * For external API, use kctsb_api.h instead.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_H
#define KCTSB_H

// ============================================================================
// Version Information (Single Source of Truth)
// ============================================================================

#define KCTSB_VERSION_MAJOR 5
#define KCTSB_VERSION_MINOR 1
#define KCTSB_VERSION_PATCH 0
#define KCTSB_VERSION_STRING "5.1.0"
#define KCTSB_VERSION_NUMBER ((KCTSB_VERSION_MAJOR * 10000) + \
                              (KCTSB_VERSION_MINOR * 100) + \
                              KCTSB_VERSION_PATCH)
#define KCTSB_RELEASE_DATE "2026-01-29"

#define KCTSB_VERSION_AT_LEAST(major, minor, patch) \
    (KCTSB_VERSION_NUMBER >= ((major) * 10000 + (minor) * 100 + (patch)))

// ============================================================================
// Core Modules
// ============================================================================

#include "kctsb/core/bigint.h"
#include "kctsb/core/fe256.h"

// ============================================================================
// Cryptographic Modules
// ============================================================================

#include "kctsb/crypto/rsa.h"
#include "kctsb/crypto/ecc/ecc.h"
#include "kctsb/crypto/sm/sm2.h"

#endif // KCTSB_H
