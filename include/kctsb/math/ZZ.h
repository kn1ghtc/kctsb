/**
 * @file ZZ.h
 * @brief NTL Compatibility Layer - Redirects to kctsb::ZZ
 * 
 * This header provides backward compatibility for code that was
 * written for NTL's ZZ class. All functionality is now provided
 * by the self-contained kctsb::ZZ implementation in core/zz.h.
 * 
 * @note For new code, include <kctsb/core/zz.h> directly.
 * 
 * @version 5.0.0 - NTL removed, self-contained implementation
 */

#ifndef KCTSB_MATH_BIGNUM_ZZ_H
#define KCTSB_MATH_BIGNUM_ZZ_H

// v5.0: ZZ is now self-contained in core/zz.h
#include "kctsb/core/zz.h"

#endif // KCTSB_MATH_BIGNUM_ZZ_H
