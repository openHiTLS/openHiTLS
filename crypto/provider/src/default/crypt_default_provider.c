/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>
#include "crypt_eal_implprovider.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_default_provderimpl.h"
#include "crypt_errno.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "crypt_default_provider.h"

#define CRYPT_EAL_DEFAULT_ATTR "provider=default"

static const CRYPT_EAL_AlgInfo defMds[] = {
    {CRYPT_MD_MD5, defMdMd5, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA1, defMdSha1, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA224, defMdSha224, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA256, defMdSha256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA384, defMdSha384, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA512, defMdSha512, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_224, defMdSha3224, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_256, defMdSha3256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_384, defMdSha3384, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_512, defMdSha3512, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHAKE128, defMdShake128, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHAKE256, defMdShake256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SM3, defMdSm3, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static int32_t CRYPT_EAL_DefaultProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void) provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_SYMMCIPHER:
            break;
        case CRYPT_EAL_OPERAID_KEYMGMT:
            break;
        case CRYPT_EAL_OPERAID_SIGN:
            break;
 
        case CRYPT_EAL_OPERAID_ASYMCIPHER:
            break;

        case CRYPT_EAL_OPERAID_KEYEXCH:
            break;

        case CRYPT_EAL_OPERAID_KEM:
            break;
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = defMds;
            break;
        case CRYPT_EAL_OPERAID_MAC:
            break;
        case CRYPT_EAL_OPERAID_KDF:
            break;
        case CRYPT_EAL_OPERAID_RAND:
            break;
        default:
            ret = CRYPT_NOT_SUPPORT;
            break;
    }
    return ret;
}

static void CRYPT_EAL_DefaultProvFree(void *provCtx)
{
    BSL_SAL_Free(provCtx);
}

static CRYPT_EAL_Func defProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_DefaultProvQuery},
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_DefaultProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    CRYPT_EAL_FUNC_END
};

int32_t CRYPT_EAL_DefaultProvInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, CRYPT_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    (void) param;
    (void) capFuncs;
    CRYPT_EAL_DefProvCtx *temp = BSL_SAL_Malloc(sizeof(CRYPT_EAL_DefProvCtx));
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    temp->mgrCtxHandle = mgrCtx;
    *provCtx = temp;
    *outFuncs = defProvOutFuncs;
    return CRYPT_SUCCESS;
}