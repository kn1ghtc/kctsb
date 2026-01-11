//
//  rsaUtil.hpp
//  kctsb
//
//  Created by knightc on 2019/8/8.
//  Copyright © 2019-2025 knightc. All rights reserved.
//

#ifndef rsaUtil_hpp
#define rsaUtil_hpp

// This header requires NTL library
#if defined(KCTSB_HAS_NTL) || defined(KCTSB_USE_NTL)

#include <NTL/ZZ.h>

using namespace NTL;
using namespace std;

void oula(const ZZ p, const ZZ q, ZZ &n);

#endif // KCTSB_HAS_NTL

#endif /* rsaUtil_hpp */