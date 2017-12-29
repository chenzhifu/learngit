//
//  elfapi.c
//  execassister
//
//  Created by j1gsaw on 14-10-29.
//  Copyright (c) 2014年 j1gsaw. All rights reserved.
//

#include "elfapi.h"
#include "elfverifier.h"
#include "utils.h"
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int parse_elf_header(u1* base, elfparser* parser)
{
    if (is_elf(base)) {
        parser->header = (Elf32_Ehdr *)base;
        parser->entry = parser->header->e_entry;
        parser->flags = parser->header->e_flags;

        verify_header(parser);
        return 0;
    }
    return -1;
}

int parse_elf_segments(u1* base, elfparser* parser)
{
    int i;
    Elf32_Phdr* phdr;

    if (parser->header == 0) {
        parse_elf_header(base, parser);
    }

    parser->phdr_table = (Elf32_Phdr *)(base + parser->header->e_phoff);
    parser->phdr_size = parser->header->e_phnum;

    for (i = 0, phdr = parser->phdr_table; i < parser->phdr_size; i++, phdr++) {
        if (verify_segment(parser, phdr)) {
            continue;
        }
        switch (phdr->p_type) {
            case PT_DYNAMIC:
                parser->dyn_size = phdr->p_filesz / sizeof(Elf32_Dyn);
                parser->dyn_table = (Elf32_Dyn *)(parser->base + phdr->p_offset);
                parse_elf_dynamic(parser->base, phdr, parser);
                break;

            case PT_ARM_EXIDX:
                parser->ARM_exidx = (unsigned *)(parser->base + phdr->p_offset);
                parser->ARM_exidx_count = phdr->p_filesz / 8;
                break;
            default:
                break;
        }
    }
    return 0;
}

int parse_elf_sections(u1* base, elfparser* parser)
{
    int i;
    Elf32_Shdr* shdr;
    Elf32_Shdr* sstr;

    if (parser->header == 0) {
        parse_elf_header(base, parser);
    }

    parser->shdr_table = (Elf32_Shdr *)(base + parser->header->e_shoff);
    parser->shdr_size = parser->header->e_shnum;
    sstr = parser->shdr_table + parser->header->e_shstrndx;

    if (verify_section(parser, sstr)) {
        log_info("section name table abnormal.");
    } else {
        parser->sstr = sstr->sh_offset + parser->base;
        parser->shdr_sstr = sstr;
    }

    for (i = 0, shdr = parser->shdr_table; i < parser->shdr_size; i++, shdr++) {
        switch (shdr->sh_type) {
            case SHT_REL:
            case SHT_RELA:
                parse_elf_section(base, shdr, parser, 0);
                break;

            case SHT_SYMTAB:
            case SHT_DYNSYM:
                parse_elf_section(base, shdr, parser, 0);
                break;

            case SHT_HASH:
                parse_elf_section(base, shdr, parser, 0);
                break;

            case SHT_DYNAMIC:
                parse_elf_section(base, shdr, parser, 0);
                break;

            default:
                break;
        }
    }
    return 0;
}

int parse_elf_section(u1* base, Elf32_Shdr* shdr, elfparser* parser, _section_callback callback)
{
    int e_size;
    void* e_start;

    if (verify_section(parser, shdr) & E_ADDROUTOFRANGE) {
        return -1;
    }

    e_start = base + shdr->sh_offset;
    e_size = shdr->sh_size / shdr->sh_entsize;
    if (callback) {
        callback(base, shdr, parser, e_start, e_size);
    }
    return 0;
}

int parse_elf_dynamic(u1* base, Elf32_Phdr* phdr, elfparser* parser)
{
    Elf32_Dyn* dyn;

    if (parser->dyn_table == 0) {
        parser->dyn_table = (Elf32_Dyn *)(base + phdr->p_offset);
        parser->dyn_size = phdr->p_filesz / sizeof(Elf32_Dyn);
    }

    if (!parser->dyn_table || !parser->dyn_size) {
        log_error("elfparser not init.");
        return -1;
    }

    for (dyn = parser->dyn_table; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_HASH:
                parser->nbucket = ((unsigned *)(parser->base + dyn->d_un.d_ptr))[0];
                parser->nchain = ((unsigned *)(parser->base + dyn->d_un.d_ptr))[1];
                parser->bucket = (unsigned *)(parser->base + dyn->d_un.d_ptr + 8);
                parser->chain = (unsigned *)(parser->base + dyn->d_un.d_ptr + 8 + parser->nbucket * 4);
                break;

            case DT_STRTAB:
                parser->strtab = parser->base + dyn->d_un.d_ptr;
                break;

            case DT_SYMTAB:
                parser->symtab = (Elf32_Sym *)(parser->base + dyn->d_un.d_ptr);
                break;

            case DT_PLTREL:
                if (dyn->d_un.d_val != DT_REL) {
                    log_error("unsupported DT_RELA");
                    return -1;
                }
                break;

            case DT_JMPREL:
                parser->plt_rel = (Elf32_Rel *)(parser->base + dyn->d_un.d_ptr);
                break;

            case DT_PLTRELSZ:
                parser->plt_rel_count = dyn->d_un.d_val / sizeof(Elf32_Rel);
                break;

            case DT_REL:
                parser->rel = (Elf32_Rel *)(parser->base + dyn->d_un.d_ptr);
                break;

            case DT_RELSZ:
                parser->rel_count = dyn->d_un.d_val / sizeof(Elf32_Rel);
                break;

            case DT_PLTGOT:
                parser->plt_got = (unsigned *)(parser->base + dyn->d_un.d_ptr);
                break;

            case DT_DEBUG:
                break;

            case DT_RELA:
                log_error("unsupported DT_RELA");
                return -1;

            case DT_INIT:
                parser->init_func = (linker_function_t)(parser->base + dyn->d_un.d_ptr);
                break;

            case DT_FINI:
                parser->fini_func = (linker_function_t)(parser->base + dyn->d_un.d_ptr);
                break;

            case DT_INIT_ARRAY:
                parser->init_array = (linker_function_t *)(parser->base + dyn->d_un.d_ptr);
                break;

            case DT_INIT_ARRAYSZ:
                parser->init_array_count = ((unsigned)dyn->d_un.d_val) / sizeof(Elf32_Addr);
                break;

            case DT_FINI_ARRAY:
                parser->fini_array = (linker_function_t *)(parser->base + dyn->d_un.d_ptr);
                break;

            case DT_PREINIT_ARRAY:
                parser->preinit_array = (linker_function_t *)(parser->base + dyn->d_un.d_ptr);
                break;

            case DT_PREINIT_ARRAYSZ:
                parser->preinit_array_count = ((unsigned)dyn->d_un.d_val) / sizeof(Elf32_Addr);
                break;

            default:
                break;
        }
    }
    return 0;
}

char* get_section_name(elfparser* parser, Elf32_Shdr* shdr)
{
    if (verify_section(parser, shdr) & E_NAMEUNKNOWN) {
        return "UNKONWN";
    }

    return (parser->sstr + shdr->sh_name);
}

char* get_symbol_name(elfparser* parser, Elf32_Shdr* shdr, Elf32_Sym* sym)
{
    char *str;

    if (verify_symbol(parser, shdr, sym) & E_NAMEUNKNOWN) {
        return "UNKONWN";
    }

    str = parser->base + shdr->sh_offset;
    return (str + sym->st_name);
}

elfparser* load_to_parse(elf_loader* loader)
{
    elfparser* parser;
    int i;
    Elf32_Phdr* phdr;

    if ((parser = malloc(sizeof(elfparser))) == 0) {
        log_error("malloc elfparser failed.");
        return 0;
    }
    memset(parser, 0, sizeof(elfparser));

    if (loader->loaded_phdr == 0 || loader->phdr_num == 0) {
        log_error("elf_loader not init.");
        return 0;
    }

    parser->base = loader->load_bias;
    parser->size = loader->load_size;
    for (i = 0, phdr = loader->loaded_phdr; i < loader->phdr_num; i++, phdr++) {
        switch (phdr->p_type) {
            case PT_DYNAMIC:
                parser->dyn_table = (Elf32_Dyn *)(loader->load_bias + phdr->p_vaddr);
                parser->dyn_size = phdr->p_memsz / sizeof(Elf32_Dyn);
                parse_elf_dynamic(loader->load_start, phdr, parser);
                break;

            case PT_ARM_EXIDX:
                parser->ARM_exidx = (unsigned *)(loader->load_bias + phdr->p_vaddr);
                parser->ARM_exidx_count = phdr->p_memsz / 8;
                break;

            default:
                break;
        }
    }

    return parser;
}

elf_needed* load_elf_needed(elf_loader* loader)
{
    elf_needed* need;
    int i, count, last_num;
    Elf32_Dyn* dyn;
    char* libname;
    addr_t handle;

    count = 0;
    if (!(need = malloc(sizeof(elf_needed) + sizeof(need_t) * MAX_NEEDED))) {
        log_error("malloc elf_needed failed.");
        return 0;
    }
    memset(need, 0, sizeof(elf_needed) + sizeof(need_t) * MAX_NEEDED);
    need->num = MAX_NEEDED;

    for (i = 0, dyn = loader->parser->dyn_table; i < loader->parser->dyn_size; i++, dyn++) {
        if (dyn->d_tag == DT_NEEDED) {
            if (count >= need->num) {
                last_num = need->num;
                if (!(need = realloc(need, sizeof(elf_needed) + sizeof(need_t) * last_num * 2))) {
                    log_error("realloc elf_needed failed.");
                    free(need);
                    return 0;
                }
                need->num = last_num * 2;
            }

            libname = loader->parser->strtab + dyn->d_un.d_val;
            log_info("elf need link %s.", libname);
            if ((handle = (addr_t)dlopen(libname, RTLD_NOW)) <= 0) {
                log_info("need lib %s load failed.", libname);
            } else {
                need->info[count].handle = handle;
                need->info[count].bias = calc_bias(handle);
                count++;
            }
        }
    }
    need->num = count;
    return need;
}

unsigned elf_hash(char* name) {
    unsigned h, g;
    u1* n = (u1 *)name;

    h = 0;
    while (*n) {
        h = (h << 4) + *n++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

int elf_reloc(elf_loader* loader)
{
    if (symbol_reloc(loader, loader->parser->rel, loader->parser->rel_count) < 0) {
        log_error("reloc rel failed.");
        return -1;
    }

    if (symbol_reloc(loader, loader->parser->plt_rel, loader->parser->plt_rel_count) < 0) {
        log_error("reloc plt_rel failed.");
        return -1;
    }
    return 0;
}

extern page_perm* pageperm;

int check_addr_perm(addr_t addr, int flag)
{
    int i;
    int result = 1;

    for (i = 0; i < pageperm->len; i++) {
        if (addr >= pageperm->pi[i].start && addr < pageperm->pi[i].end) {
            if ((flag & ADDR_R) && !CAN_R(pageperm->pi[i])) {
                log_info("address 0x%08x can't read.", addr);
                return 0;
            }
            if ((flag & ADDR_W) && !CAN_W(pageperm->pi[i])) {
                log_info("address 0x%08x can't write.", addr);
                return 0;
            }
            if ((flag & ADDR_X) && !CAN_X(pageperm->pi[i])) {
                log_info("address 0x%08x can't execute.", addr);
                return 0;
            }
            return 1;
        }
    }

    log_info("not in load pages.");
    return 0;
}

int symbol_reloc(elf_loader* loader, Elf32_Rel* rels, int relnum)
{
    int i;
    Elf32_Rel* rel;
    addr_t reladdr;
    int sym_type, sym_index;
    char* sym_name = "";
    addr_t sym_addr;

    Elf32_Sym* symtab = loader->parser->symtab;
    char* strtab = loader->parser->strtab;

    for (i = 0, rel = rels; i < relnum; i++, rel++) {
        sym_type = ELF32_R_TYPE(rel->r_info);
        sym_index = ELF32_R_SYM(rel->r_info);
        reladdr = (addr_t)(rel->r_offset + loader->load_bias);

        if (!check_addr_perm(reladdr, (int)ADDR_W)) {
            continue;
        }

        if (sym_type == R_ARM_NONE) {
            continue;
        }
        if (sym_index != 0) {
            sym_name = strtab + symtab[sym_index].st_name;
            sym_addr = find_symbol(loader->needed, sym_name);

            if (sym_addr == 0) {
                if (ELF32_ST_BIND(symtab[sym_index].st_info) != STB_WEAK) {
                    log_error("locate symbol %s failed, should be weak.", sym_name);
                    return -1;
                }

                switch (sym_type) {
                    case R_ARM_JUMP_SLOT:
                    case R_ARM_GLOB_DAT:
                    case R_ARM_ABS32:
                    case R_ARM_RELATIVE:
                        break;

                    case R_ARM_COPY:

                    default:
                        log_error("symbol %s has unknown weak reloc type .", sym_name);
                        return -1;
                }
            } else {
                // go a symbol definition
            }
        } else {
            sym_addr = 0;
        }

        switch (sym_type) {
            case R_ARM_JUMP_SLOT:
                *((addr_t *)reladdr) = sym_addr;
                break;

            case R_ARM_GLOB_DAT:
                *((addr_t *)reladdr) = sym_addr;
                break;

            case R_ARM_ABS32:
                *((addr_t *)reladdr) += sym_addr;
                break;

            case R_ARM_REL32:
                *((addr_t *)reladdr) += sym_addr - rel->r_offset;
                break;

            case R_ARM_RELATIVE:
                if (sym_index) {
                    log_error("unknown relative symbol %s.", sym_name);
                    return -1;
                }
                *((addr_t *)reladdr) += (addr_t)loader->load_start;
                break;

            case R_ARM_COPY:
                log_error("unexpect copy symbol %s.", sym_name);
                return -1;

            default:
                log_error("symbol %s has unknown reloc type.", sym_name);
                return -1;
        }
        //log_info("reloc symbol %s done.", sym_name);
    }
    return 0;
}

addr_t find_symbol(elf_needed* needed, char* symname)
{
    unsigned findhash = elf_hash(symname);
    int i, n;
    Elf32_Sym* findsym;
    soinfo *si;
    addr_t symaddr;

    for (i = 0; i < needed->num; i++) {
        si = (soinfo *)(needed->info[i].handle);

        for (n = si->bucket[findhash % si->nbucket]; n != 0; n = si->chain[n]) {
            findsym = si->symtab + n;
            if (strcmp(si->strtab + findsym->st_name, symname)) {
                continue;
            }

            switch (ELF32_ST_BIND(findsym->st_info)) {
                case STB_GLOBAL:
                case STB_WEAK:
                    if (findsym->st_shndx == SHN_UNDEF) {
                        continue;
                    }
                    symaddr = (addr_t)findsym->st_value + needed->info[i].bias;
                    log_info("found %s in %s (address = 0x%08x)", symname, si->name, symaddr);
                    return symaddr;

                default:
                    break;
            }
        }
    }
    log_error("symbol %s not found.", symname);
    return 0;
}

addr_t calc_bias(soinfo* si)
{
    int i;
    Elf32_Phdr* phdr;
    addr_t minaddr = 0xFFFFFFFFU;

    if (!strcmp(si->name, "libdl.so")) {
        return 0;
    }

    if (!si->base || !si->phdr || !si->phnum) {
        log_error("%s base = 0x%x, phdr = 0x%x, phnum = %d.", si->name,
                  si->base, si->phdr, si->phnum);
        log_error("calc bias for %s failed.", si->name);
        return 0;
    }

    for (i = 0, phdr = si->phdr; i < si->phnum; i++, phdr++) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        if (phdr->p_vaddr < minaddr) {
            minaddr = phdr->p_vaddr;
        }
    }

    return ((addr_t)si->base - (addr_t)(PAGE_START(minaddr)));
}

int elf_dump(elf_loader* loader, char* dstname)
{
    int dstfd;
    int result = 0;

    if (!loader || !loader->load_start || !loader->load_size) {
        log_error("elf_loader not init, nothing to dump.");
        return -1;
    }

    if ((dstfd = open(dstname, O_RDWR | O_CREAT | O_TRUNC, 0777)) < 0) {
        log_error("create dump file %s failed.", dstname);
        return -1;
    }

    if (mprotect(loader->load_start, loader->load_size, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        log_error("mprotect dump memory area failed.");
        result = -1;
        goto dump_failed;
    }

    if (fix_phdr_table(loader)) {
        log_error("phdr table fix failed.");
        result = -1;
        goto dump_failed;
    }

    if (fix_reloc(loader, loader->parser->rel, loader->parser->rel_count) ||
            fix_reloc(loader, loader->parser->plt_rel, loader->parser->plt_rel_count)) {
        log_error("reloc fix failed.");
        result = -1;
        goto dump_failed;
    }

    if (write(dstfd, loader->load_start, loader->load_size) != loader->load_size) {
        log_error("write dump file %s failed.", dstname);
        result = -1;
        goto dump_failed;
    }

dump_failed:
    close(dstfd);
    return result;
}

// merge PT_LOAD into one
int fix_phdr_table(elf_loader* loader)
{
    int i;
    Elf32_Phdr* phdr;
    bool merged = false;

    for (i = 0, phdr = loader->loaded_phdr; i < loader->phdr_num; i++, phdr++) {
        if (verify_segment(loader->parser, phdr)) {
            if (phdr->p_type == PT_LOAD) {
                log_error("PT_LOAD cannot abnormal.");
                return -1;
            }

            log_info("Phdr %d abnormal, fix it.", i);
            phdr->p_type = PT_NULL;
            continue;
        }

        phdr->p_offset = phdr->p_vaddr;
        phdr->p_filesz = phdr->p_memsz;

        if (!merged && phdr->p_type == PT_LOAD) {
            phdr->p_memsz = loader->load_size;
            phdr->p_filesz = phdr->p_memsz;
            merged = true;
            continue;
        }

        // now merged.
        if (phdr->p_type == PT_LOAD) {
            phdr->p_type = PT_NULL;
        }
    }
    return 0;
}

// because relocation already done, no fault check this time.
//
int fix_reloc(elf_loader* loader, Elf32_Rel* rels, int relnum)
{
    int i;
    Elf32_Rel* rel;
    addr_t reladdr;
    int sym_type, sym_index;
    char* sym_name = "";
    addr_t sym_addr;

    Elf32_Sym* symtab = loader->parser->symtab;
    char* strtab = loader->parser->strtab;

    for (i = 0, rel = rels; i < relnum; i++, rel++) {
        sym_type = ELF32_R_TYPE(rel->r_info);
        sym_index = ELF32_R_SYM(rel->r_info);
        reladdr = (addr_t)(rel->r_offset + loader->load_bias);

        if (!check_addr_perm(reladdr, (int)ADDR_W)) {
            continue;
        }

        if (sym_type == R_ARM_NONE) {
            continue;
        }
        if (sym_index != 0) {
            sym_name = strtab + symtab[sym_index].st_name;
            sym_addr = find_symbol(loader->needed, sym_name);
        } else {
            sym_addr = 0;
        }

        if (sym_addr) {
            continue;
        }

        switch (sym_type) {
            case R_ARM_REL32:
                *((addr_t *)reladdr) = rel->r_offset;
                break;

            case R_ARM_RELATIVE:
                if (sym_index == 0) {
                    *((addr_t *)reladdr) -= (addr_t)loader->load_start;
                }
                break;
        }
    }
    return 0;
}
