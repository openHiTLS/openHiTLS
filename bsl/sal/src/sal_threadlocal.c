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
#include "bsl_errno.h"
#include "bsl_sal.h"


int32_t BSL_SAL_ThreadLocalKeyCreate(BSL_SAL_ThreadLocalKey *key, BSL_SAL_ThreadLocalCleanup cleanup)
{
    (void)key;
    (void)cleanup;
    return BSL_SUCCESS;
}

int32_t BSL_SAL_ThreadLocalKeyDelete(BSL_SAL_ThreadLocalKey key)
{
    (void)key;
    return BSL_SUCCESS;
}

void *BSL_SAL_ThreadLocalGet(BSL_SAL_ThreadLocalKey key)
{
    (void)key;
    return NULL;
}

int32_t BSL_SAL_ThreadLocalSet(BSL_SAL_ThreadLocalKey key, void *value)
{
    (void)key;
    (void)value;
    return BSL_SUCCESS;
}

#endif // HITLS_BSL_ASYNC
