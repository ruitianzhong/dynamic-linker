/*
 *  Private header for functions to be shared among modules
 */
#ifndef _LOADER_PRI_H
#define _LOADER_PRI_H

#include "Link.h"

extern void *MapLibrary(const char *name);
extern void RelocLibrary(LinkMap *l, int mode);

#endif /* LoaderInternal.h */