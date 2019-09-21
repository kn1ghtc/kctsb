//
//  kc_common.h
//  kcalg
//
//  Created by knightc on 2019/7/16.
//  Copyright © 2019 knightc. All rights reserved.
//

#ifndef kc_common_h
#define kc_common_h

#include <NTL/vec_ZZ.h>

using namespace std;
using namespace NTL;

#define kprint(X) (std::cout << X << std::endl) //快速打印，取代 cout

//计算任意类型的一维数组的长度，如果是字符串数组，需要减去末尾，即长度减 1
template <class T>
long getArrayLen(T& array)
{
    return (sizeof(array) / sizeof(array[0]));
    
}


int test_eigamal_main();


ZZ kc_crt(const vec_ZZ& vec_c,const vec_ZZ& vec_m);


#endif /* kc_common_h */
