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

BSL_ASYNC_NotifyCtx *BSL_ASYNC_NotifyCtxNew(void)
{
    return NULL;
}

void BSL_ASYNC_NotifyCtxFree(BSL_ASYNC_NotifyCtx *ctx)
{
    (void)ctx;
    return;
}

int32_t BSL_ASYNC_NotifyCtxSetCallback(BSL_ASYNC_NotifyCtx *ctx,
    BSL_ASYNC_NotifyCallback callback, void *callbackArg)
{
    (void)ctx;
    (void)callback;
    (void)callbackArg;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxGetCallback(const BSL_ASYNC_NotifyCtx *ctx,
    BSL_ASYNC_NotifyCallback *callback, void **callbackArg)
{
    (void)ctx;
    (void)callback;
    (void)callbackArg;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxSetStatus(BSL_ASYNC_NotifyCtx *ctx, int32_t status)
{
    (void)ctx;
    (void)status;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxGetStatus(const BSL_ASYNC_NotifyCtx *ctx, int32_t *status)
{
    (void)ctx;
    (void)status;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxSetNotifySource(BSL_ASYNC_NotifyCtx *ctx, const void *key,
    BSL_ASYNC_NotifyHandle handle, void *customData, BSL_ASYNC_NotifySourceCleanup cleanup)
{
    (void)ctx;
    (void)key;
    (void)handle;
    (void)customData;
    (void)cleanup;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxGetNotifySource(const BSL_ASYNC_NotifyCtx *ctx, const void *key,
    BSL_ASYNC_NotifyHandle *handle, void **customData)
{
    (void)ctx;
    (void)key;
    (void)handle;
    (void)customData;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxGetAllNotifySources(const BSL_ASYNC_NotifyCtx *ctx,
    BSL_ASYNC_NotifyHandleList *list)
{
    (void)ctx;
    (void)list;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxClearNotifySource(BSL_ASYNC_NotifyCtx *ctx, const void *key)
{
    (void)ctx;
    (void)key;
    return BSL_SUCCESS;
}

int32_t BSL_ASYNC_NotifyCtxGetChangedNotifySources(const BSL_ASYNC_NotifyCtx *ctx,
    BSL_ASYNC_NotifyHandleList *addList, BSL_ASYNC_NotifyHandleList *delList)
{
    (void)ctx;
    (void)addList;
    (void)delList;
    return BSL_SUCCESS;
}

#endif // HITLS_BSL_ASYNC
