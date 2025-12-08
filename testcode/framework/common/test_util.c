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

#include "test.h"

static uint32_t g_malloc_called_idx = 0;
static uint32_t g_malloc_failed_idx = 0;
static bool g_malloc_fail_enabled = true;

void *STUB_BSL_SAL_Malloc(uint32_t size)
{
    if (g_malloc_fail_enabled && g_malloc_called_idx++ == g_malloc_failed_idx) {
        return NULL;
    }
    if (!g_malloc_fail_enabled) {
        g_malloc_called_idx++;
    }
    return malloc(size);
}

void STUB_ResetMallocCount(void)
{
    g_malloc_called_idx = 0;
}

void STUB_SetMallocFailIndex(uint32_t failIdx)
{
    g_malloc_failed_idx = failIdx;
}

uint32_t STUB_GetMallocCallCount(void)
{
    return g_malloc_called_idx;
}

void STUB_EnableMallocFail(bool enable)
{
    g_malloc_fail_enabled = enable;
}
