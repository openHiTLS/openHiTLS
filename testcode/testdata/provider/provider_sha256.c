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

// Source code for the test .so file

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_sha2.h"
#include "bsl_sal.h"
#include "sal_memimpl.h"
#include "bsl_err_internal.h"

#define CRYPT_EAL_DEFAULT_ATTR "provider=sha256_test"


CRYPT_SHA2_256_Ctx *Sha256NewCtx(void *provCtx, int32_t algId)
{
    return CRYPT_SHA2_256_NewCtxEx(provCtx, algId);
}
// SHA256 algorithm function table
const CRYPT_EAL_Func defMdSha256[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, Sha256NewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHA2_256_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHA2_256_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHA2_256_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHA2_256_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHA2_256_DupCtx},
    {CRYPT_EAL_IMPLMD_COPYCTX, CRYPT_SHA2_256_CopyCtx},
    {CRYPT_EAL_IMPLMD_GETPARAM, CRYPT_SHA2_256_GetParam},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHA2_256_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

// Algorithm information table
static const CRYPT_EAL_AlgInfo defMds[] = {
    {CRYPT_MD_SHA256, defMdSha256, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

// Provider query function
static int32_t CRYPT_EAL_Sha256ProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    
    switch (operaId) {
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = defMds;
            return CRYPT_SUCCESS;
        default:
            return CRYPT_NOT_SUPPORT;
    }
}

// Provider free function
static void CRYPT_EAL_Sha256ProvFree(void *provCtx)
{
    (void)provCtx;
    return;
}

// Provider output functions table
static CRYPT_EAL_Func defProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_Sha256ProvQuery},
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_Sha256ProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    CRYPT_EAL_FUNC_END
};

// Provider initialization function
int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx,
    BSL_Param *param, CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    (void)mgrCtx;
    (void)param;
    (void)capFuncs;

    (void)SAL_MemCallBack_Ctrl(BSL_SAL_MEM_MALLOC, malloc);
    (void)SAL_MemCallBack_Ctrl(BSL_SAL_MEM_FREE, free);

    *outFuncs = defProvOutFuncs;
    *provCtx = NULL;

    return CRYPT_SUCCESS;
}
