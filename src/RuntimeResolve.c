#include <elf.h>
#include <stdlib.h>
#include <stdio.h>

#include "Link.h"
#include "LoaderInternal.h"

extern void *SearchSymbol(LinkMap *lib, char *name);

Elf64_Addr __attribute__((visibility ("hidden"))) //this makes trampoline to call it w/o plt
runtimeResolve(LinkMap *lib, Elf64_Word reloc_entry)
{
    printf("Resolving address for entry %u\n", reloc_entry);
    /* Your code here */
    Elf64_Sym *dynsym = (Elf64_Sym *)lib->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    char *dynstr = (char *)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
    Elf64_Addr symbol_addr;
    if (lib->dynInfo[DT_PLTRELSZ] && lib->dynInfo[DT_JMPREL])
    {
        Elf64_Rela *rela = (Elf64_Rela *)lib->dynInfo[DT_JMPREL]->d_un.d_ptr;

        uint32_t type = (rela[reloc_entry].r_info << 32) >> 32, idx = (rela[reloc_entry].r_info) >> 32;
        char *symbolname = dynstr + dynsym[idx].st_name;

        symbol_addr = (Elf64_Addr)SearchSymbol(lib, symbolname);
        if (symbol_addr == 0)
        {
            printf("Can not find the symbol %s\n", symbol_addr);
            exit(EXIT_FAILURE);
        }
        *(uint64_t *)(lib->addr + rela[reloc_entry].r_offset) = rela[reloc_entry].r_addend + (uint64_t)symbol_addr;
    }
    return symbol_addr;
}