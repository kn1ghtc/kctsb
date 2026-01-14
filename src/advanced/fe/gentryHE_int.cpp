//
//  gentryHE.cpp
//  kcalg
//
//  Created by knightc on 2019/8/20.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>

/*
 *
 1、set plaintxt is M=m1m2m3m4...,m="0" or "1"
 2、encryption：c= m + 2r' + P * Q';P is the key and is Positive odd number，and Q is big number；r and Q is every time random
 3、decryption：m = （c mod P） mod 2；
 4、m1+m2= decryption（c1+c2）
 M must more then 128bit
 *
 */









//for application,delect r
//for search and compared，set Q = AES（hash1（M），hash2（P）），M（1024bit），P（2050bit），Q（4096bit）
// Only one operation can calculate two numbers，because plain must smaller then module P



