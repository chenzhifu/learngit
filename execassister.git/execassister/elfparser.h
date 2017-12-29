//
//  elfparser.h
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#ifndef __execassister__elfparser__
#define __execassister__elfparser__

#include "elf.h"
#include "utils.h"
#include "linker.h"

typedef struct {
    Elf32_Ehdr*         header;
    Elf32_Phdr*         phdr_table;
    size_t              phdr_size;
    Elf32_Shdr*         shdr_table;
    Elf32_Shdr*         shdr_sstr;
    char*               sstr;
    size_t              shdr_size;
    
    Elf32_Dyn*          dyn_table;
    size_t              dyn_size;
    
    u1*                 entry;
    u1*                 base;
    unsigned            size;
    unsigned            flags;
    
    const char*         strtab;
    Elf32_Sym*          symtab;
    
    size_t              nbucket;
    size_t              nchain;
    unsigned*           bucket;
    unsigned*           chain;
    
    unsigned*           plt_got;
    
    Elf32_Rel*          plt_rel;
    size_t              plt_rel_count;
    
    Elf32_Rel*          rel;
    size_t              rel_count;
    
    linker_function_t*  preinit_array;
    size_t              preinit_array_count;
    
    linker_function_t*  init_array;
    size_t              init_array_count;
    linker_function_t*  fini_array;
    size_t              fini_array_count;
    
    linker_function_t   init_func;
    linker_function_t   fini_func;
    
    // ARM EABI section used for stack unwinding.
    unsigned*           ARM_exidx;
    size_t              ARM_exidx_count;
} elfparser;

elfparser* elf_parse(int fd, off_t fsize);

#define E_INDEXOUTOFRANGE   1
#define E_ADDROUTOFRANGE    1 << 1
#define E_NAMEUNKNOWN       1 << 2
#define E_NOSECTION         1 << 3
#define E_UNKNOWN           -1

#endif /* defined(__execassister__elfparser__) */
