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

#if defined(HITLS_BSL_ASYNC) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "sal_threadlocalimpl.h"

int32_t SAL_ThreadLocalKeyCreate(BSL_SAL_ThreadLocalKey *key, BSL_SAL_ThreadLocalCleanup cleanup)
{
    pthread_key_t posixKey;
    if (pthread_key_create(&posixKey, cleanup) != 0) {
        return BSL_SAL_ERR_NO_MEMORY;
    }
    *key = (BSL_SAL_ThreadLocalKey)posixKey;
    return BSL_SUCCESS;
}

int32_t SAL_ThreadLocalKeyDelete(BSL_SAL_ThreadLocalKey key)
{
    return pthread_key_delete((pthread_key_t)key) == 0 ? BSL_SUCCESS : BSL_INVALID_ARG;
}

void *SAL_ThreadLocalGet(BSL_SAL_ThreadLocalKey key)
{
    return pthread_getspecific((pthread_key_t)key);
}

int32_t SAL_ThreadLocalSet(BSL_SAL_ThreadLocalKey key, void *value)
{
    int pr = pthread_setspecific((pthread_key_t)key, value);
    if (pr == EINVAL) {
        return BSL_INVALID_ARG;
    }
    if (pr != 0) {
        return BSL_SAL_ERR_NO_MEMORY;
    }
    /* value == NULL clears the binding: pthread runs the destructor only for
     * non-NULL values at thread exit, which matches the contract. */
    return BSL_SUCCESS;
}

#endif
