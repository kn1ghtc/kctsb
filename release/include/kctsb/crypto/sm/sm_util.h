//
//  smUtil.h
//  kcalg
//
//  Created by knightc on 2019/7/26.
//  Copyright © 2019 knightc. All rights reserved.
//

#ifndef smUtil_h
#define smUtil_h

#include "miracl.h"
#include "mirdef.h"

 int Test_Point(epoint* point,big para_p,big para_a ,big para_b);
 int Test_PubKey(epoint *pubKey,big para_p ,big para_a, big para_b,big para_n);

int Test_Zero(big x);
int Test_n(big x);
int Test_Range(big x);

int sm2_init(epoint *G) ;
int SM2_KeyGeneration(big priKey,epoint *pubKey,epoint *G);

#endif /* smUtil_h */
