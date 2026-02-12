/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdlib.h>
#include <string.h>
#include "hitls_build.h"
#include "bsl_log_internal.h"
#include "bsl_util_internal.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_binlog_id.h"
#include "sal_memimpl.h"

static BSL_SAL_MemCallback g_memCallback = {NULL, NULL};

void *BSL_SAL_Malloc(uint32_t size)
{
    // When size is 0, malloc of different systems may return NULL or non-NULL. Here, a definite result is required.
    // If the callback is registered, everything is determined by the callback.
    if (g_memCallback.pfMalloc != NULL && g_memCallback.pfMalloc != BSL_SAL_Malloc) {
        return g_memCallback.pfMalloc(size);
    }
    if (size == 0) {
        return NULL;
    }
#if defined(HITLS_BSL_SAL_MEM) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_MallocImpl(size);
#else
    return NULL;
#endif
}

void BSL_SAL_Free(void *value)
{
    if (g_memCallback.pfFree == NULL || g_memCallback.pfFree == BSL_SAL_Free) {
#if defined(HITLS_BSL_SAL_MEM) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
        SAL_FreeImpl(value);
#endif
        return;
    }
    g_memCallback.pfFree(value);
}

void *BSL_SAL_Calloc(uint32_t num, uint32_t size)
{
    if (num == 0 || size == 0) {
        return BSL_SAL_Malloc(0);
    }
    if (num > UINT32_MAX / size) { // process the rewinding according to G.INT.02 in the HW C Coding Specifications V5.1
        return NULL;
    }
    uint32_t blockSize = num * size;
    uint8_t *ptr = BSL_SAL_Malloc(blockSize);
    if (ptr == NULL) {
        return NULL;
    }
    memset(ptr, 0, blockSize);
    return ptr;
}

void *BSL_SAL_Dump(const void *src, uint32_t size)
{
    if (src == NULL || size == 0) {
        return NULL;
    }
    void *ptr = BSL_SAL_Malloc(size);
    if (ptr == NULL) {
        return NULL;
    }

    memcpy(ptr, src, size);
    return ptr;
}

void *BSL_SAL_Realloc(void *addr, uint32_t newSize, uint32_t oldSize)
{
#if defined(HITLS_BSL_SAL_MEM) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    (void)oldSize;
    return SAL_ReallocImpl(addr, newSize);
#else
    if (addr == NULL) {
        return BSL_SAL_Malloc(newSize);
    }
    uint32_t minSize = (oldSize > newSize) ? newSize : oldSize;

    void *ptr = BSL_SAL_Malloc(newSize);
    if (ptr == NULL) {
        return NULL;
    }

    if (minSize > 0 && addr != NULL) {
        memcpy(ptr, addr, minSize);
    }
    BSL_SAL_FREE(addr);

    return ptr;
#endif
}

void BSL_SAL_CleanseData(void *ptr, uint32_t size)
{
    if (ptr == NULL || size == 0) {
        return;
    }
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (size--) {
        *p++ = 0;
    }
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

void BSL_SAL_ClearFree(void *ptr, uint32_t size)
{
    if (ptr == NULL) {
        return;
    }
    if (size != 0) {
        BSL_SAL_CleanseData(ptr, size);
    }
    BSL_SAL_Free(ptr);
}

int32_t SAL_MemCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    switch (type) {
        case BSL_SAL_MEM_MALLOC:
            g_memCallback.pfMalloc = funcCb;
            return BSL_SUCCESS;
        case BSL_SAL_MEM_FREE:
            g_memCallback.pfFree = funcCb;
            return BSL_SUCCESS;
        default:
            return BSL_SAL_ERR_BAD_PARAM;
    }
}
