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

#include <stddef.h>
#include "bsl_errno.h"
#include "bsl_sal.h"

/*
 * T1 interface-freeze stubs: the symbols declared in bsl_sal.h resolve here
 * with empty bodies. T2 replaces this file with the build-switch backend
 * dispatch (ucontext backend, host context, worker stacks); until then no
 * backend is selected by any build, the capability probe reports "absent"
 * and every context request is rejected without touching any state.
 */

int32_t BSL_SAL_CoroutineIsSupported(void)
{
    return 0;
}

int32_t BSL_SAL_CoroutineInitCurrent(BSL_ASYNC_Coroutine **co)
{
    (void)co;
    return BSL_ASYNC_ERR_STATE_CONFLICT;
}

int32_t BSL_SAL_CoroutineCreate(BSL_ASYNC_Coroutine **co,
    size_t stackSize, BSL_SAL_CoroutineEntry entry, void *arg)
{
    (void)co;
    (void)stackSize;
    (void)entry;
    (void)arg;
    return BSL_ASYNC_ERR_STATE_CONFLICT;
}

int32_t BSL_SAL_CoroutineSwitch(BSL_ASYNC_Coroutine *from, BSL_ASYNC_Coroutine *to)
{
    (void)from;
    (void)to;
    return BSL_ASYNC_ERR_STATE_CONFLICT;
}

int32_t BSL_SAL_CoroutineDestroy(BSL_ASYNC_Coroutine *co)
{
    if (co == NULL) {
        return BSL_SUCCESS;
    }
    return BSL_ASYNC_ERR_STATE_CONFLICT;
}

#endif // HITLS_BSL_ASYNC
