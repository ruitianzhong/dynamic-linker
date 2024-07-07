#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h> //for getpagesize
#include <sys/mman.h>
#include <fcntl.h>

#include "Link.h"
#include "LoaderInternal.h"
#define PANIC     \
    {             \
        while (1) \
            ;     \
    }
#define ALIGN_DOWN(base, size) ((base) & -((__typeof__(base))(size)))
#define ALIGN_UP(base, size) ALIGN_DOWN((base) + (size)-1, (size))

static const char *sys_path[] = {
    "/usr/lib/x86_64-linux-gnu/",
    "/lib/x86_64-linux-gnu/",
    ""
};

static const char *fake_so[] = {
    "libc.so.6",
    "ld-linux.so.2",
    ""
};

static void setup_hash(LinkMap *l)
{
    uint32_t *hash;

    /* borrowed from dl-lookup.c:_dl_setup_hash */
    Elf32_Word *hash32 = (Elf32_Word *)l->dynInfo[DT_GNU_HASH]->d_un.d_ptr;
    l->l_nbuckets = *hash32++;
    Elf32_Word symbias = *hash32++;
    Elf32_Word bitmask_nwords = *hash32++;

    l->l_gnu_bitmask_idxbits = bitmask_nwords - 1;
    l->l_gnu_shift = *hash32++;

    l->l_gnu_bitmask = (Elf64_Addr *)hash32;
    hash32 += 64 / 32 * bitmask_nwords;

    l->l_gnu_buckets = hash32;
    hash32 += l->l_nbuckets;
    l->l_gnu_chain_zero = hash32 - symbias;
}

static void fill_info(LinkMap *lib)
{
    Elf64_Dyn *dyn = lib->dyn;
    Elf64_Dyn **dyn_info = lib->dynInfo;

    while (dyn->d_tag != DT_NULL)
    {
        if ((Elf64_Xword)dyn->d_tag < DT_NUM)
            dyn_info[dyn->d_tag] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_RELACOUNT_)
            dyn_info[DT_RELACOUNT] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_GNU_HASH_)
            dyn_info[DT_GNU_HASH] = dyn;
        ++dyn;
    }
    #define rebase(tag)                             \
        do                                          \
        {                                           \
            if (dyn_info[tag])                          \
                dyn_info[tag]->d_un.d_ptr += lib->addr; \
        } while (0)
    rebase(DT_SYMTAB);
    rebase(DT_STRTAB);
    rebase(DT_RELA);
    rebase(DT_JMPREL);
    rebase(DT_GNU_HASH); //DT_GNU_HASH
    rebase(DT_PLTGOT);
    rebase(DT_INIT);
    rebase(DT_INIT_ARRAY);
}

static int checkElfHeader(Elf64_Ehdr *header)
{
    return header->e_ident[0] == ELFMAG0 && header->e_ident[1] == ELFMAG1 && header->e_ident[2] == ELFMAG2 && header->e_ident[3] == ELFMAG3;
}

static void FindDep(LinkMap *lib)
{
    if (!lib->dynInfo[DT_STRTAB])
        return;

    char *str_tab = (char *)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
    Elf64_Dyn *p = lib->dyn;
    while (p->d_tag != DT_NULL)
    {
        if (p->d_tag == DT_NEEDED)
        {
            char *dep_lib_name = p->d_un.d_ptr + str_tab;
            if (strcmp("libc.so.6", dep_lib_name) == 0)
            {
                p++;
                continue;
            }
            LinkMap *dep = malloc(sizeof(LinkMap));
            dep->deps_cnt = 0;
            char *prefix = "./test_lib/";
            int total = strlen(prefix) + strlen(dep_lib_name);
            char *full_name = malloc(sizeof(char) * (total + 1));

            strncpy(full_name, prefix, strlen(prefix));
            strncat(full_name, dep_lib_name, strlen(dep_lib_name));
            dep->name = full_name;
            if (dep==NULL){
                goto err;
            }
            lib->deps[lib->deps_cnt] = dep;
            lib->deps_cnt++;
        }
        p++;
    }


    err:
        return;
}

static int MapLibraryInternal(LinkMap *lib)
{
    const char *libpath = lib->name;
    int fd = open(libpath, O_RDWR);
    if (fd == -1)
    {
        perror("MapLibrary Open");
        goto err;
    }

    int n;
    // Read out the Elf header
    Elf64_Ehdr header;
    n = read(fd, &header, sizeof(Elf64_Ehdr));
    if (n != sizeof(Elf64_Ehdr) || !checkElfHeader(&header))
    {
        printf("Invalid header\n");
        goto err;
    }

    // Now read out the program header
    if (sizeof(Elf64_Phdr) != header.e_phentsize)
    {
        printf("Bad program header entry size %d\n", header.e_phentsize);
        goto err;
    }
    uint64_t ph_off = header.e_phoff;
    if (lseek(fd, ph_off, SEEK_SET) != ph_off)
    {
        printf("Bad program header offset %ld\n", ph_off);
        goto err;
    }
    // validate phnum
    if (header.e_phnum == 0)
    {
        printf("Bad program header num\n");
        goto err;
    }

    Elf64_Phdr *phdrs = malloc(sizeof(Elf64_Phdr) * header.e_phnum);
    if (phdrs == NULL)
    {
        perror("Allocate program header array");
        goto err;
    }
    uint64_t total = 0, dynamic_vaddr = 0;
    for (int i = 0; i < header.e_phnum; i++)
    {
        if (read(fd, &phdrs[i], sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr))
        {
            perror("Read program header");
            goto cleanup_ph;
        }
        if (phdrs[i].p_type == PT_LOAD)
        {
            if (phdrs[i].p_memsz + phdrs[i].p_vaddr > total)
            {
                total = phdrs[i].p_memsz + phdrs[i].p_vaddr;
            }
        }
        else if (phdrs[i].p_type == PT_DYNAMIC)
        {
            dynamic_vaddr = phdrs[i].p_vaddr;
        }
    }

    void *start = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (start == MAP_FAILED)
    {
        perror("Anonymous mmap");
        goto cleanup_ph;
    }
    for (int i = 0; i < header.e_phnum; i++)
    {
        if (PT_LOAD == phdrs[i].p_type)
        {
            uint64_t seg_start = phdrs[i].p_vaddr + (uint64_t)start;
            uint64_t aligned_start = ALIGN_DOWN(seg_start, 4096);
            uint64_t offset = phdrs[i].p_offset - (seg_start - aligned_start);
            uint64_t length = phdrs[i].p_filesz + (seg_start - aligned_start);
            int prot = 0;
            prot |= (phdrs[i].p_flags & PF_R) ? PROT_READ : 0;
            prot |= (phdrs[i].p_flags & PF_W) ? PROT_WRITE : 0;
            prot |= (phdrs[i].p_flags & PF_X) ? PROT_EXEC : 0;

            if (mmap((void *)aligned_start, length, prot, MAP_FIXED | MAP_PRIVATE, fd, offset) != (void *)aligned_start)
            {
                perror("Fixed map");
                goto cleanup_ph;
            }
        }
    }
    lib->addr = (uint64_t)start;
    lib->dyn = (Elf64_Dyn *)(dynamic_vaddr + start);
    fill_info(lib);
    setup_hash(lib);

    return 0;

cleanup_ph:
    free(phdrs);
err:
    return -1;
}

void *MapLibrary(const char *libpath)
{
    LinkMap *lib = malloc(sizeof(LinkMap));
    lib->deps_cnt = 0;
    if (lib == NULL)
    {
        return NULL;
    }

    lib->name = libpath;
    LinkMap *worklist[20];
    int head = 0, tail = 1;
    worklist[0] = lib;

    while (head != tail)
    {
        LinkMap *lm = worklist[head];
        head = (head + 1) % 20;

        MapLibraryInternal(lm);
        FindDep(lm);
        for (int i = 0; i < lm->deps_cnt; i++)
        {
            worklist[tail] = lm->deps[i];
            if (head == (tail + 1) % 20)
            {
                PANIC;
            }
            tail = (tail + 1) % 20;
        }
    }

    return lib;

err:
    return NULL;
}
