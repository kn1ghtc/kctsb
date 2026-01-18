/**
 * @file kc_fe.hpp
 * @brief Functional Encryption (FE) module header
 * @note Requires bignum and HElib for full functionality
 * 
 * Original: Created by knightc on 2019/7/19.
 * Copyright © 2019 knightc. All rights reserved.
 */

#ifndef kc_fe_hpp
#define kc_fe_hpp

#include <cstdio>

// Bignum ZZX polynomial type (optional dependency)
#ifdef KCTSB_HAS_BIGNUM_MODULES
#include "kctsb/math/bignum/ZZX.h"
#endif

// HElib BGV scheme types (optional dependency)
#ifdef KCTSB_HAS_HELIB
// Include HElib v2.3.0 headers when available
#endif

#endif /* kc_fe_hpp */
