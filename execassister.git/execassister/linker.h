//
//  linker.h
//  execassister
//
//  Created by j1gsaw on 14-11-3.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#ifndef execassister_linker_h
#define execassister_linker_h

/* structure of android aosp */

#define SOINFO_NAME_LEN 128

typedef void (*linker_function_t)();

typedef struct {
    char name[SOINFO_NAME_LEN];
    const Elf32_Phdr* phdr;
    size_t phnum;
    Elf32_Addr entry;
    Elf32_Addr base;
    unsigned size;
    
    uint32_t unused1;  // DO NOT USE, maintained for compatibility.
    
    Elf32_Dyn* dynamic;
    
    uint32_t unused2; // DO NOT USE, maintained for compatibility
    uint32_t unused3; // DO NOT USE, maintained for compatibility
    
    struct soinfo* next;
    unsigned flags;
    
    const char* strtab;
    Elf32_Sym* symtab;
    
    size_t nbucket;
    size_t nchain;
    unsigned* bucket;
    unsigned* chain;
    
    unsigned* plt_got;
    
    Elf32_Rel* plt_rel;
    size_t plt_rel_count;
    
    Elf32_Rel* rel;
    size_t rel_count;
    
    linker_function_t* preinit_array;
    size_t preinit_array_count;
    
    linker_function_t* init_array;
    size_t init_array_count;
    linker_function_t* fini_array;
    size_t fini_array_count;
    
    linker_function_t init_func;
    linker_function_t fini_func;
    
    unsigned* ARM_exidx;
    size_t ARM_exidx_count;
} soinfo;

#endif