#include <dlfcn.h> //turn to dlsym for help at fake load object
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <link.h>
#include <string.h>

#include "Link.h"

// glibc version to hash a symbol
static uint_fast32_t
dl_new_hash(const char *s)
{
    uint_fast32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h & 0xffffffff;
}

// find symbol `name` inside the symbol table of `dep`
void *symbolLookup(LinkMap *dep, const char *name)
{
    if(dep->fake)
    {
        void *handle = dlopen(dep->name, RTLD_LAZY);
        if(!handle)
        {
            fprintf(stderr, "relocLibrary error: cannot dlopen a fake object named %s", dep->name);
            abort();
        }
        dep->fakeHandle = handle;
        return dlsym(handle, name);
    }

    Elf64_Sym *symtab = (Elf64_Sym *)dep->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    const char *strtab = (const char *)dep->dynInfo[DT_STRTAB]->d_un.d_ptr;

    uint_fast32_t new_hash = dl_new_hash(name);
    Elf64_Sym *sym;
    const Elf64_Addr *bitmask = dep->l_gnu_bitmask;
    uint32_t symidx;
    Elf64_Addr bitmask_word = bitmask[(new_hash / __ELF_NATIVE_CLASS) & dep->l_gnu_bitmask_idxbits];
    unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
    unsigned int hashbit2 = ((new_hash >> dep->l_gnu_shift) & (__ELF_NATIVE_CLASS - 1));
    if ((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1)
    {
        Elf32_Word bucket = dep->l_gnu_buckets[new_hash % dep->l_nbuckets];
        if (bucket != 0)
        {
            const Elf32_Word *hasharr = &dep->l_gnu_chain_zero[bucket];
            do
            {
                if (((*hasharr ^ new_hash) >> 1) == 0)
                {
                    symidx = hasharr - dep->l_gnu_chain_zero;
                    /* now, symtab[symidx] is the current symbol.
                       Hash table has done its job */
                    const char *symname = strtab + symtab[symidx].st_name;
                    if (!strcmp(symname, name))
                    {    
                        Elf64_Sym *s = &symtab[symidx];
                        // return the real address of found symbol
                        return (void *)(s->st_value + dep->addr);
                    }
                }
            } while ((*hasharr++ & 1u) == 0);
        }
    }
    return NULL; //not this dependency
}

void *SearchSymbol(LinkMap *lib, char *name)
{
    lib->fake = 0;
    LinkMap *self = symbolLookup(lib, name);
    if (self)
    {
        return self;
    }

    for (int i = 0; i < lib->deps_cnt; i++)
    {
        LinkMap *dep = lib->deps[i];
        dep->fake = 0;
        void *addr = symbolLookup(dep, name);
        if (addr){
            return addr;
        }
    }
    LinkMap *libso = malloc(sizeof(LinkMap));
    libso->fake = 1;

    return symbolLookup(libso, name);
}

void RelocLibrary(LinkMap *lib, int mode)
{
    /* Your code here */
  
    Elf64_Dyn **dyn = lib->dynInfo;
    // if(strcmp(lib->name,"./test_lib/lib1.so")!=0){
    //     return;
    // }

    uint64_t jmp_rel_addr = 0, jmp_rel_size = 0;
    if (dyn[DT_PLTRELSZ] && dyn[DT_JMPREL])
    {
        jmp_rel_addr = dyn[DT_JMPREL]->d_un.d_ptr;
        jmp_rel_size = dyn[DT_PLTRELSZ]->d_un.d_val;
    }
    Elf64_Sym *symtab = (Elf64_Sym *)(dyn[DT_SYMTAB]->d_un.d_ptr);
    char *strtab = (char *)(dyn[DT_STRTAB]->d_un.d_ptr);
    // handle .rela.plt
    Elf64_Rela *start = (Elf64_Rela *)jmp_rel_addr;
    Elf64_Rela * relap = start;
    for (int i = 0; i < jmp_rel_size; i += sizeof(Elf64_Rela))
    {
        unsigned int type = (relap->r_info << 32) >> 32, idx = (relap->r_info) >> 32;

        char *symbol_name = strtab + symtab[idx].st_name;

        if (type == R_X86_64_JUMP_SLOT)
        {
            void *symbol_addr = SearchSymbol(lib, symbol_name);
            *(uint64_t *)(lib->addr + relap->r_offset) = relap->r_addend + (uint64_t)symbol_addr;
        }

        relap++;
    }
    // handle .rela.dyn for init code
    uint64_t rela_dyn_size = 0;
    Elf64_Rela *rela_dyn = NULL, *rela_dyn_p=NULL;
    if (dyn[DT_RELASZ] && dyn[DT_RELA])
    {
        rela_dyn = (Elf64_Rela *)dyn[DT_RELA]->d_un.d_ptr;
        rela_dyn_size = dyn[DT_RELASZ]->d_un.d_val;
        rela_dyn_p = rela_dyn;
    }
    for (int i = 0; i < rela_dyn_size; i += sizeof(Elf64_Rela))
    {
        unsigned int type = ((rela_dyn_p->r_info) << 32) >> 32, idx = (rela_dyn_p->r_info) >> 32;
        if (type == R_X86_64_RELATIVE)
        {
            uint64_t addr = lib->addr + rela_dyn_p->r_addend;
            *(uint64_t *)(rela_dyn_p->r_offset + lib->addr) = addr;
        }
        else if (type == R_X86_64_GLOB_DAT)
        {
            int bind = ELF64_ST_BIND(symtab[idx].st_info);
            if (bind != STB_WEAK)
            {
                char *symbol_name = strtab + symtab[idx].st_name;
                void *symbol_addr = SearchSymbol(lib, symbol_name);
                uint64_t addr = rela_dyn_p->r_addend + (uint64_t)symbol_addr;

                *(uint64_t *)(rela_dyn_p->r_offset + lib->addr) = addr;
            }
        }

        rela_dyn_p++;
    }
}
