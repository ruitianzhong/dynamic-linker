#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <stdint.h>

#include "Link.h"
#include "LoaderInternal.h"
typedef void (*INITFUNC)(void);
void InitLibrary(LinkMap *l)
{
    /* Your code here */

    // run init code

    if (l->dynInfo[DT_INIT])
    {
        INITFUNC init = (INITFUNC)l->dynInfo[DT_INIT]->d_un.d_ptr;
        init();
    }

    if (l->dynInfo[DT_INIT_ARRAY] && l->dynInfo[DT_INIT_ARRAYSZ])
    {
        uint32_t sz = l->dynInfo[DT_INIT_ARRAYSZ]->d_un.d_val;
        uint64_t *init_array = (uint64_t *)l->dynInfo[DT_INIT_ARRAY]->d_un.d_ptr;
        for (int i = 0; i < sz / sizeof(Elf64_Addr); i++)
        {
            INITFUNC init = (INITFUNC)init_array[i];
            init();
        }
    }
}
