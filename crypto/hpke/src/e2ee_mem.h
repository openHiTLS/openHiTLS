
#ifndef E2EE_MEM_H
#define E2EE_MEM_H

#include <stdint.h>

void *E2EE_Malloc(uint32_t size);

void *E2EE_Calloc(uint32_t nmemb, uint32_t size);

void E2EE_Free(void *ptr);

void E2EE_ClearFree(void *ptr, uint32_t size);

void *E2EE_Dump(const void *src, uint32_t srcLen);

#endif
