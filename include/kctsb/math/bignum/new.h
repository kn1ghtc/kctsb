/**
 * @file new.h
 * @brief Memory allocation utilities
 * 
 * Provides nothrow new operator wrapper.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_NEW_H
#define KCTSB_NEW_H

#include <new>

#define KCTSB_NEW_OP new (std::nothrow)

// NTL compatibility
#define NTL_NEW_OP KCTSB_NEW_OP

#endif // KCTSB_NEW_H
