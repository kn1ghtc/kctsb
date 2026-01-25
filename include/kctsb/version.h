/**
 * @file version.h
 * @brief Unified Version Information for kctsb Library
 *
 * This is the SINGLE SOURCE OF TRUTH for all version information.
 * All other files should include this header and use these macros.
 *
 * When releasing a new version, ONLY modify this file.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_VERSION_H
#define KCTSB_VERSION_H

/**
 * @defgroup Version Library Version Information
 * @{
 */

/** Major version number (API breaking changes) */
#define KCTSB_VERSION_MAJOR 5

/** Minor version number (new features, backward compatible) */
#define KCTSB_VERSION_MINOR 0

/** Patch version number (bug fixes) */
#define KCTSB_VERSION_PATCH 0

/** Full version string "major.minor.patch" */
#define KCTSB_VERSION_STRING "5.0.0"

/** Version as single integer: (major * 10000 + minor * 100 + patch) */
#define KCTSB_VERSION_NUMBER ((KCTSB_VERSION_MAJOR * 10000) + \
                              (KCTSB_VERSION_MINOR * 100) + \
                              KCTSB_VERSION_PATCH)

/** Release date in YYYY-MM-DD format */
#define KCTSB_RELEASE_DATE "2026-01-25"

/** Library name */
#define KCTSB_LIBRARY_NAME "kctsb"

/** Full library description */
#define KCTSB_DESCRIPTION "Knight's Cryptographic Trusted Security Base"

/** Build type identifier */
#ifdef NDEBUG
#define KCTSB_BUILD_TYPE "Release"
#else
#define KCTSB_BUILD_TYPE "Debug"
#endif

/**
 * @brief Check if library version is at least the specified version
 * @param major Major version to check
 * @param minor Minor version to check
 * @param patch Patch version to check
 */
#define KCTSB_VERSION_AT_LEAST(major, minor, patch) \
    (KCTSB_VERSION_NUMBER >= ((major) * 10000 + (minor) * 100 + (patch)))

/** @} */

#endif /* KCTSB_VERSION_H */
