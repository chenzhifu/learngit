//
//  elfloader.c
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#include "elfloader.h"
#include "elfparser.h"
#include "elfapi.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "utils.h"
#include "elfinfo.h"

elf_loader* elf_load(int fd, off_t fsize)
{
    elf_loader* loader;
    elfparser* parser;
    addr_t page_min, page_max, page_offset;
    void* mem;
    
    if ((loader = malloc(sizeof(elf_loader))) <= 0) {
        log_error("malloc elfloader failed.");
        return 0;
    }
    loader->fd = fd;
    if (read(fd, &loader->header, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
        log_error("read elf header failed.");
        free(loader);
        return 0;
    }
    
    loader->phdr_num = loader->header.e_phnum;
    page_min = PAGE_START(loader->header.e_phoff);
    page_max = PAGE_END(loader->header.e_phoff + (loader->phdr_num * sizeof(Elf32_Phdr)));
    page_offset = PAGE_OFFSET(loader->header.e_phoff);
    loader->phdr_size = page_max - page_min;
    if ((mem = mmap(0, loader->phdr_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, page_min)) <= 0) {
        log_error("elf prog header table mmap failed.");
        free(loader);
        return 0;
    }
    loader->phdr_mmap = mem;
    loader->phdr_table = (Elf32_Phdr *)((u1 *)mem + page_offset);
    
    if (reserve_load_space(loader) < 0) {
        goto load_failed;
    }
    
    if (load_segments(loader) < 0) {
        goto load_failed;
    }
    
    if (find_phdr(loader) < 0) {
        goto load_failed;
    }
    
    if (!(loader->parser = load_to_parse(loader))) {
        goto load_failed;
    }
    
    if (!(loader->needed = load_elf_needed(loader))) {
        goto load_failed;
    }
    
    if (elf_reloc(loader) < 0) {
        goto load_failed;
    }
    log_info("elf load done.");
    return loader;
load_failed:
    log_error("elf load failed.");
    elf_unload(loader);
    return 0;
}

int reserve_load_space(elf_loader* loader)
{
    addr_t min_vaddr = 0xFFFFFFFFU;
    addr_t max_vaddr = 0x00000000U;
    Elf32_Phdr* phdr;
    bool found_pt_load = false;
    int i;
    void* start;
    
    for (i = 0, phdr = loader->phdr_table; i < loader->phdr_num; i++, phdr++) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        found_pt_load = true;
        
        if (phdr->p_vaddr < min_vaddr) {
            min_vaddr = phdr->p_vaddr;
        }
        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
            max_vaddr = phdr->p_vaddr + phdr->p_memsz;
        }
    }
    if (!found_pt_load) {
        min_vaddr = 0;
    }
    min_vaddr = PAGE_START(min_vaddr);
    max_vaddr = PAGE_END(max_vaddr);
    loader->load_size = max_vaddr - min_vaddr;
    
    if (loader->load_size == 0) {
        log_error("no loadable segment.");
        return -1;
    }
    if ((start = mmap(min_vaddr, loader->load_size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0)) <= 0) {
        log_error("reserve load space failed.");
        return -1;
    }
    loader->load_start = start;
    loader->load_bias = (u1 *)start - (u1 *)min_vaddr;
    return 0;
}

page_perm* pageperm;

int load_segments(elf_loader* loader)
{
    int i;
    Elf32_Phdr* phdr;
    addr_t seg_start, seg_end, seg_pagestart, seg_pageend;
    addr_t seg_file_end, file_start, file_end, file_pagestart, file_length;
    void* seg_addr;
    
    pageperm = malloc(sizeof(page_perm) + loader->phdr_num * sizeof(page_info));
    if (pageperm == 0) {
        log_error("page perm malloc failed.");
        return -1;
    }
    pageperm->len = loader->phdr_num;
    
    for (i = 0, phdr = loader->phdr_table; i < loader->phdr_num; i++, phdr++) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        seg_start = phdr->p_vaddr + loader->load_bias;
        seg_end = seg_start + phdr->p_memsz;
        seg_pagestart = PAGE_START(seg_start);
        seg_pageend = PAGE_END(seg_end);
        seg_file_end = seg_start + phdr->p_filesz;
        
        file_start = phdr->p_offset;
        file_end = file_start + phdr->p_filesz;
        file_pagestart = PAGE_START(file_start);
        file_length = file_end - file_pagestart;
        
        if (file_length) {
            seg_addr = mmap(seg_pagestart, file_length, PF_TO_PROT(phdr->p_flags), MAP_FIXED | MAP_PRIVATE, loader->fd, file_pagestart);
            if (seg_addr == 0) {
                log_error("load segment %d failed.", i);
                goto load_seg_failed;
            }
            
            pageperm->pi[i].start = seg_pagestart;
            pageperm->pi[i].end = seg_pageend;
            pageperm->pi[i].perm = phdr->p_flags;
        }
        
        seg_file_end = PAGE_END(seg_file_end);
        if (seg_pageend > seg_file_end) {
            if (mmap(seg_file_end, seg_pageend - seg_file_end, PF_TO_PROT(phdr->p_flags),
                     MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0) <= 0) {
                log_error("zero fill failed.");
                goto load_seg_failed;
            }
        }
    }
    return 0;
    
load_seg_failed:
    free(pageperm);
    return -1;
}

int find_phdr(elf_loader* loader)
{
    int i;
    Elf32_Phdr* phdr;
    Elf32_Ehdr* hdr;
    
    for (i = 0, phdr = loader->phdr_table; i < loader->phdr_num; i++, phdr++) {
        if (phdr->p_type == PT_PHDR) {
            return check_phdr(loader->load_bias + phdr->p_vaddr, loader);
        }
    }
    
    for (i = 0, phdr = loader->phdr_table; i < loader->phdr_num; i++, phdr++) {
        if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
            hdr = (Elf32_Ehdr *)(loader->load_bias + phdr->p_vaddr);
            return check_phdr((addr_t)hdr + hdr->e_phoff, loader);
        }
    }
    
    log_error("find phdr failed.");
    return -1;
}

int check_phdr(addr_t phdr_addr, elf_loader* loader)
{
    int i;
    Elf32_Phdr* phdr;
    addr_t seg_start, seg_end;
    addr_t phdr_end;
    
    phdr_end = phdr_addr + sizeof(Elf32_Phdr) * loader->phdr_num;
    for (i = 0, phdr = loader->phdr_table; i < loader->phdr_num; i++, phdr++) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        seg_start = phdr->p_vaddr + loader->load_bias;
        seg_end = phdr->p_filesz + seg_start;
        
        if (seg_start <= phdr_addr && phdr_end <= seg_end) {
            loader->loaded_phdr = (Elf32_Phdr *)phdr_addr;
            return 0;
        }
    }
    log_error("loaded phdr not in loadable segments.");
    return -1;
}

void elf_unload(elf_loader* loader)
{
    if (loader->parser) {
        free(loader->parser);
    }
    
    if (loader->needed) {
        free(loader->needed);
    }
    
    if (loader->phdr_mmap) {
        munmap(loader->phdr_mmap, loader->phdr_size);
    }
    
    if (loader->load_start) {
        munmap(loader->load_start, loader->load_size);
    }
    
    free(loader);
    log_info("elf unload done.");
}