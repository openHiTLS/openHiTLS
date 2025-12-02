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

#include "hitls_build.h"
#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)) && defined(HITLS_BSL_SAL_MEM)

#include <stdint.h>
#include <stdlib.h>

void *SAL_MallocImpl(uint32_t size)
{
    return malloc(size);
}

void SAL_FreeImpl(void *value)
{
    if (value == NULL) {
        return;
    }
    free(value);
}

void *SAL_ReallocImpl(void *addr, uint32_t newSize)
{
    return realloc(addr, newSize);
}

#endif
