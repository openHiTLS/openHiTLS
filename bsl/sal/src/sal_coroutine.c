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
#include <stddef.h>
#include <stdint.h>
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "sal_coroutineimpl.h"

/*
 * Coroutine backend dispatch, in precedence order:
 *   - a callback backend registered through BSL_SAL_CallBack_Ctrl: the
 *     five callbacks are one set (a platform's own context implementation,
 *     e.g. fibers or RTOS tasks) that takes effect only when complete and
 *     then replaces the built-in backend;
 *   - HITLS_BSL_ASYNC_UCONTEXT: POSIX ucontext (Linux/macOS),
 *     posix/posix_coroutine.c;
 *   - otherwise: unsupported; reject context requests without allocation.
 * A partially registered set is never used: the built-in backend keeps
 * serving, so a context never meets a foreign backend's operation. This
 * layer owns the NULL-input checks and the error stack; every backend,
 * callback or built-in, receives validated arguments and must not push
 * errors itself.
 */

#if defined(HITLS_BSL_ASYNC_UCONTEXT) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
bool SAL_UC_CoroutineIsSupported(void);
int32_t SAL_UC_CoroutineInitCurrent(BSL_ASYNC_Coroutine **co);
int32_t SAL_UC_CoroutineCreate(BSL_ASYNC_Coroutine **co, uint32_t stackSize, BSL_SAL_CoroutineEntry entry, void *arg);
int32_t SAL_UC_CoroutineSwitch(BSL_ASYNC_Coroutine *from, BSL_ASYNC_Coroutine *to);
void SAL_UC_CoroutineDestroy(BSL_ASYNC_Coroutine *co);
#endif

static BSL_SAL_CoroutineCallback g_coroutineCallback = {NULL, NULL, NULL, NULL, NULL};

/*
 * The five callbacks form one backend, not five independent overrides: the
 * set takes effect only when every slot is registered (and none is the
 * dispatcher itself - such a callback would recurse forever, the same guard
 * the other SAL callback modules use). While the set is incomplete the
 * built-in backend keeps serving; a context must never meet a foreign
 * backend's operation.
 */
static bool CoroutineCbSetActive(void)
{
    return g_coroutineCallback.pfIsSupported != NULL &&
           g_coroutineCallback.pfIsSupported != BSL_SAL_CoroutineIsSupported &&
           g_coroutineCallback.pfInitCurrent != NULL &&
           g_coroutineCallback.pfInitCurrent != BSL_SAL_CoroutineInitCurrent && g_coroutineCallback.pfCreate != NULL &&
           g_coroutineCallback.pfCreate != BSL_SAL_CoroutineCreate && g_coroutineCallback.pfSwitch != NULL &&
           g_coroutineCallback.pfSwitch != BSL_SAL_CoroutineSwitch && g_coroutineCallback.pfDestroy != NULL &&
           g_coroutineCallback.pfDestroy != BSL_SAL_CoroutineDestroy;
}

int32_t SAL_CoroutineCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type < BSL_SAL_COROUTINE_IS_SUPPORTED_CB_FUNC || type > BSL_SAL_COROUTINE_DESTROY_CB_FUNC) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    uint32_t offset = (uint32_t)(type - BSL_SAL_COROUTINE_IS_SUPPORTED_CB_FUNC);
    ((void **)&g_coroutineCallback)[offset] = funcCb;
    return BSL_SUCCESS;
}

bool BSL_SAL_CoroutineIsSupported(void)
{
    if (CoroutineCbSetActive()) {
        return g_coroutineCallback.pfIsSupported();
    }
#if defined(HITLS_BSL_ASYNC_UCONTEXT) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    return SAL_UC_CoroutineIsSupported();
#else
    return false;
#endif
}

int32_t BSL_SAL_CoroutineInitCurrent(BSL_ASYNC_Coroutine **co)
{
    int32_t ret;
    if (co == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (CoroutineCbSetActive()) {
        ret = g_coroutineCallback.pfInitCurrent(co);
    } else {
#if defined(HITLS_BSL_ASYNC_UCONTEXT) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
        ret = SAL_UC_CoroutineInitCurrent(co);
#else
        ret = BSL_ASYNC_ERR_STATE_CONFLICT;
#endif
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t BSL_SAL_CoroutineCreate(BSL_ASYNC_Coroutine **co, uint32_t stackSize, BSL_SAL_CoroutineEntry entry, void *arg)
{
    int32_t ret;
    if (co == NULL || entry == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (CoroutineCbSetActive()) {
        ret = g_coroutineCallback.pfCreate(co, stackSize, entry, arg);
    } else {
#if defined(HITLS_BSL_ASYNC_UCONTEXT) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
        ret = SAL_UC_CoroutineCreate(co, stackSize, entry, arg);
#else
        (void)stackSize;
        (void)arg;
        ret = BSL_ASYNC_ERR_STATE_CONFLICT;
#endif
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t BSL_SAL_CoroutineSwitch(BSL_ASYNC_Coroutine *from, BSL_ASYNC_Coroutine *to)
{
    int32_t ret;
    if (from == NULL || to == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (CoroutineCbSetActive()) {
        ret = g_coroutineCallback.pfSwitch(from, to);
    } else {
#if defined(HITLS_BSL_ASYNC_UCONTEXT) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
        ret = SAL_UC_CoroutineSwitch(from, to);
#else
        ret = BSL_ASYNC_ERR_STATE_CONFLICT;
#endif
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

void BSL_SAL_CoroutineDestroy(BSL_ASYNC_Coroutine *co)
{
    if (co == NULL) {
        /* NULL is an idempotent no-op for every backend. */
        return;
    }
    if (CoroutineCbSetActive()) {
        g_coroutineCallback.pfDestroy(co);
        return;
    }
#if defined(HITLS_BSL_ASYNC_UCONTEXT) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    SAL_UC_CoroutineDestroy(co);
#else
    /* No backend is built: no coroutine object can exist, so there is
     * nothing to release. */
#endif
}

#endif
