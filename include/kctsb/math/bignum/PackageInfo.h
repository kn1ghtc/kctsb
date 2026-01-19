/**
 * @file PackageInfo.h
 * @brief Package identification header
 * 
 * This file identifies kctsb as a complete package installation.
 * It replaces NTL's PackageInfo.h for compatibility.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_PACKAGE_INFO_H
#define KCTSB_PACKAGE_INFO_H

// Package identification
#define KCTSB_PACKAGE (1)

// NTL compatibility
#define NTL_PACKAGE (1)

// Bignum module version (based on NTL 11.6.0)
#define KCTSB_BIGNUM_VERSION "11.6.0-kctsb"

#endif // KCTSB_PACKAGE_INFO_H
