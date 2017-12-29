//
//  elfloader.h
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#ifndef __execassister__elfloader__
#define __execassister__elfloader__

#include "elf.h"
#include "utils.h"
#include "elfparser.h"

#define MAX_NEEDED 16

typedef struct {
    addr_t      handle;
    addr_t      bias;
} need_t;

typedef struct {
    int         num;
    need_t      info[0];
} elf_needed;

typedef struct {
    int         fd;
    elfparser*  parser;
    elf_needed* needed;

    Elf32_Ehdr  header;
    size_t      phdr_num;
    void*       phdr_mmap;
    Elf32_Phdr* phdr_table;
    addr_t  phdr_size;

    void*       load_start;
    addr_t  load_size;
    addr_t  load_bias;
    Elf32_Phdr* loaded_phdr;
} elf_loader;

#define CAN_R(page_info) (page_info.perm & PF_R)
#define CAN_W(page_info) (page_info.perm & PF_W)
#define CAN_X(page_info) (page_info.perm & PF_X)
#define PAGERANGE(page_info) (page_info.end - page_info.start)

typedef struct {
    addr_t  start;
    addr_t  end;
    int         perm;
} page_info;

typedef struct {
    int         len;
    page_info   pi[0];
} page_perm;

#define PF_TO_PROT(flags) (((flags & PF_R) ? PROT_READ : 0) | \
                           ((flags & PF_W) ? PROT_WRITE : 0) | \
                           ((flags & PF_X) ? PROT_EXEC : 0))

elf_loader* elf_load(int fd, off_t fsize);
int reserve_load_space(elf_loader* loader);
int load_segments(elf_loader* loader);
int find_phdr(elf_loader* loader);
int check_phdr(addr_t phdr_addr, elf_loader* loader);
void elf_unload(elf_loader* loader);

#endif /* defined(__execassister__elfloader__) */
