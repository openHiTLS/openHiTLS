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

#ifdef HITLS_BSL_ASYNC

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "bsl_errno.h"
#include "bsl_async.h"


bool BSL_ASYNC_IsSupported(void)
{
    return false;
}

int32_t BSL_ASYNC_InitThread(uint32_t maxTasks, uint32_t initialTasks, uint32_t stackSize)
{
    (void)maxTasks;
    (void)initialTasks;
    (void)stackSize;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_CleanupThread(void)
{
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_StartTask(BSL_ASYNC_Task **task, int32_t *ret,
    const BSL_ASYNC_TaskParam *param)
{
    (void)task;
    (void)ret;
    (void)param;
    return BSL_ASYNC_UNSUPPORTED;
}

BSL_ASYNC_Task *BSL_ASYNC_GetCurrentTask(void)
{
    return NULL;
}

BSL_ASYNC_NotifyCtx *BSL_ASYNC_TaskGetNotifyCtx(const BSL_ASYNC_Task *task)
{
    (void)task;
    return NULL;
}

int32_t BSL_ASYNC_PauseTask(void)
{
    return BSL_SUCCESS;
}

void BSL_ASYNC_BlockPause(void)
{
    return;
}

void BSL_ASYNC_UnblockPause(void)
{
    return;
}
#endif // HITLS_BSL_ASYNC
