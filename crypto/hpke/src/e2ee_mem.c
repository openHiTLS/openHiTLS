#include <stdint.h>
#include "e2ee_mem.h"
#include "securec.h"
#include "e2ee_key_exch.h"
#include "e2ee_key_exch_err.h"

static E2EE_MemCallback g_memCallback = {NULL, NULL};

int32_t E2EE_RegisterMemCallback(E2EE_MemCallback *memCallback)
{
    if (memCallback == NULL) {
        return E2EE_ERR_INVALID_ARG;
    }
    if (memCallback->fpMalloc != NULL && memCallback->fpFree == NULL) {
        return E2EE_ERR_INVALID_ARG;
    }
    if (memCallback->fpMalloc == NULL && memCallback->fpFree != NULL) {
        return E2EE_ERR_INVALID_ARG;
    }

    if (g_memCallback.fpMalloc != NULL) {
        return E2EE_ERR_CALL;
    }

    g_memCallback = *memCallback;
    return E2EE_SUCCESS;
}

void *E2EE_Malloc(uint32_t size)
{
    if (g_memCallback.fpMalloc != NULL) {
        return g_memCallback.fpMalloc(size);
    }
    return malloc(size);
}

void *E2EE_Calloc(uint32_t nmemb, uint32_t size)
{
    if (nmemb == 0 || size == 0) {
        return E2EE_Malloc(0);
    }
    if (size > UINT32_MAX / nmemb) {
        return NULL;
    }

    uint32_t totalSize = nmemb * size;
    uint8_t *ptr = E2EE_Malloc(totalSize);
    if (ptr == NULL) {
        return NULL;
    }
    (void)memset_s(ptr, totalSize, 0, totalSize);
    return ptr;
}

void E2EE_Free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    if (g_memCallback.fpFree != NULL) {
        g_memCallback.fpFree(ptr);
    } else {
        free(ptr);
    }
}

void E2EE_ClearFree(void *ptr, uint32_t size)
{
    if (ptr == NULL) {
        return;
    }
    memset_s(ptr, size, 0, size);
    if (g_memCallback.fpFree != NULL) {
        g_memCallback.fpFree(ptr);
    } else {
        free(ptr);
    }
}

void *E2EE_Dump(const void *src, uint32_t srcLen)
{
    if (src == NULL) {
        return NULL;
    }
    void *dst = E2EE_Malloc(srcLen);
    if (dst == NULL) {
        return NULL;
    }
    (void)memcpy_s(dst, srcLen, src, srcLen);
    return dst;
}
