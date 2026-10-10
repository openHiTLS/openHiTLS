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

#include <stdbool.h>
#include <stdint.h>
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "sal_lockimpl.h"

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
#include "sal_threadlocalimpl.h"
#endif

/*
 * ThreadLocal dispatch, in precedence order:
 *   - a callback backend registered through BSL_SAL_CallBack_Ctrl: the four
 *     callbacks are one set (a platform's own TLS implementation, e.g. RTOS
 *     task slots) that takes effect only when complete and then replaces the
 *     built-in backend;
 *   - HITLS_BSL_SAL_LINUX / HITLS_BSL_SAL_DARWIN: POSIX pthread keys,
 *     posix/posix_threadlocal.c;
 *   - otherwise: unsupported; KeyCreate reports BSL_SAL_ERR_NO_MEMORY and
 *     Get reads back NULL, so BSL_ASYNC_InitThread fails cleanly instead of
 *     running on a missing container.
 * A partially registered set is never used: the built-in backend keeps
 * serving, so a key never meets a foreign backend's operation. This layer
 * owns the NULL-input checks and the error stack; every backend, callback
 * or built-in, receives validated arguments and must not push errors
 * itself.
 */

static BSL_SAL_ThreadLocalCallback g_threadLocalCallback = {NULL, NULL, NULL, NULL};

/*
 * The four callbacks form one backend, not four independent overrides: the
 * set takes effect only when every slot is registered (and none is the
 * dispatcher itself - such a callback would recurse forever, the same guard
 * the other SAL callback modules use). While the set is incomplete the
 * built-in backend keeps serving; a key must never meet a foreign backend's
 * operation.
 */
static bool ThreadLocalCbSetActive(void)
{
    return g_threadLocalCallback.pfThreadLocalKeyCreate != NULL &&
           g_threadLocalCallback.pfThreadLocalKeyCreate != BSL_SAL_ThreadLocalKeyCreate &&
           g_threadLocalCallback.pfThreadLocalKeyDelete != NULL &&
           g_threadLocalCallback.pfThreadLocalKeyDelete != BSL_SAL_ThreadLocalKeyDelete &&
           g_threadLocalCallback.pfThreadLocalGet != NULL &&
           g_threadLocalCallback.pfThreadLocalGet != BSL_SAL_ThreadLocalGet &&
           g_threadLocalCallback.pfThreadLocalSet != NULL &&
           g_threadLocalCallback.pfThreadLocalSet != BSL_SAL_ThreadLocalSet;
}

int32_t SAL_ThreadLocalCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type < BSL_SAL_THREAD_LOCAL_KEY_CREATE_CB_FUNC || type > BSL_SAL_THREAD_LOCAL_SET_CB_FUNC) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    uint32_t offset = (uint32_t)(type - BSL_SAL_THREAD_LOCAL_KEY_CREATE_CB_FUNC);
    ((void **)&g_threadLocalCallback)[offset] = funcCb;
    return BSL_SUCCESS;
}

int32_t BSL_SAL_ThreadLocalKeyCreate(BSL_SAL_ThreadLocalKey *key, BSL_SAL_ThreadLocalCleanup cleanup)
{
    int32_t ret;
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (ThreadLocalCbSetActive()) {
        ret = g_threadLocalCallback.pfThreadLocalKeyCreate(key, cleanup);
    } else {
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
        ret = SAL_ThreadLocalKeyCreate(key, cleanup);
#else
        ret = BSL_SAL_ERR_NO_MEMORY;
#endif
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t BSL_SAL_ThreadLocalKeyDelete(BSL_SAL_ThreadLocalKey key)
{
    int32_t ret;
    if (ThreadLocalCbSetActive()) {
        ret = g_threadLocalCallback.pfThreadLocalKeyDelete(key);
    } else {
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
        ret = SAL_ThreadLocalKeyDelete(key);
#else
        ret = BSL_INVALID_ARG;
#endif
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

void *BSL_SAL_ThreadLocalGet(BSL_SAL_ThreadLocalKey key)
{
    if (ThreadLocalCbSetActive()) {
        return g_threadLocalCallback.pfThreadLocalGet(key);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_ThreadLocalGet(key);
#else
    return NULL;
#endif
}

int32_t BSL_SAL_ThreadLocalSet(BSL_SAL_ThreadLocalKey key, void *value)
{
    int32_t ret;
    if (ThreadLocalCbSetActive()) {
        ret = g_threadLocalCallback.pfThreadLocalSet(key, value);
    } else {
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
        ret = SAL_ThreadLocalSet(key, value);
#else
        ret = BSL_INVALID_ARG;
#endif
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#endif
