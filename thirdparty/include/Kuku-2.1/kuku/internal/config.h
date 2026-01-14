/*
 * 基础配置文件 for Kuku 
 * 临时解决配置文件缺失问题
 */

#pragma once

#define KUKU_VERSION "2.1.0"
#define KUKU_VERSION_MAJOR 2
#define KUKU_VERSION_MINOR 1
#define KUKU_VERSION_PATCH 0

// 编译器配置
#ifdef _MSC_VER
    #define KUKU_COMPILER_MSVC
#elif defined(__GNUC__)
    #define KUKU_COMPILER_GCC  
#endif

// 特性配置
#define KUKU_DEBUG 0
#define KUKU_USE_STD_BYTE 0