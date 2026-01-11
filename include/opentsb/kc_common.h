//
//  kc_common.h
//  kctsb - Refactored cross-platform cryptographic library
//
//  Created by knightc on 2019/7/16.
//  Copyright © 2019-2025 knightc. All rights reserved.
//

#ifndef kc_common_h
#define kc_common_h

#include <iostream>
#include <cstdint>
#include <cstring>

// Conditional NTL support
#if defined(KCTSB_HAS_NTL) || defined(KCTSB_USE_NTL)
#include <NTL/vec_ZZ.h>
using namespace NTL;
#endif

using namespace std;

// Quick print macro
#define kprint(X) (std::cout << X << std::endl)

// Calculate array length for any type
template <class T>
long getArrayLen(T& array)
{
    return (sizeof(array) / sizeof(array[0]));
}

// Function declarations
int test_eigamal_main();

// NTL-dependent functions
#if defined(KCTSB_HAS_NTL) || defined(KCTSB_USE_NTL)
ZZ kc_crt(const vec_ZZ& vec_c, const vec_ZZ& vec_m);
#endif

#endif /* kc_common_h */
