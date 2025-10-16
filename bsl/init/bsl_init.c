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
#ifdef HITLS_BSL_INIT

#include "bsl_err.h"
#include "bsl_errno.h"
#ifdef HITLS_BSL_OBJ_CUSTOM
#include "bsl_obj_internal.h"
#endif // HITLS_BSL_OBJ

int32_t BSL_GLOBAL_Init(void)
{
    return BSL_ERR_Init();
}

int32_t BSL_GLOBAL_DeInit(void)
{
    BSL_ERR_RemoveErrStringBatch();
    BSL_ERR_RemoveErrorStack(true);
    BSL_ERR_DeInit();
#ifdef HITLS_BSL_OBJ_CUSTOM
    BSL_OBJ_FreeSignHashTable();
    BSL_OBJ_FreeHashTable();
#endif // HITLS_BSL_OBJ_CUSTOM
    return BSL_SUCCESS;
}

#endif /* HITLS_BSL_INIT */
