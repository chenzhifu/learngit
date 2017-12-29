//
//  utils.h
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#ifndef execassister_utils_h
#define execassister_utils_h

#include <stdint.h>
#include <sys/types.h>

typedef uint8_t     u1;
typedef uint16_t    u2;
typedef uint32_t    u4;
typedef uint64_t    u8;
typedef int8_t      s1;
typedef int16_t     s2;
typedef int32_t     s4;
typedef int64_t     s8;

typedef u1          byte;
typedef u2          word;
typedef u4          dword;
typedef u8          qword;

typedef int         bool;

#define true        1
#define false       0

#define ARRAY_SIZE(arr, type) sizeof(arr)/sizeof(type)

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_START(x) ((x) & PAGE_MASK)

#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE - 1))

//#define __IA64__
#ifdef __IA64__
typedef u8 addr_t;
#else
typedef u4 addr_t;
#endif

#endif
