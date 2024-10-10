/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

// Source code for the test .so file

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"

#define CRYPT_EAL_DEFAULT_ATTR "provider=test2,compare1=one,compare2=two"
#define RESULT 5358979

int32_t MD5_Init(void *mdCtx)
{
    mdCtx = NULL;
    return RESULT;
}

const CRYPT_EAL_Func defMdMd5[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, NULL},
    {CRYPT_EAL_IMPLMD_INITCTX, MD5_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, NULL},
    {CRYPT_EAL_IMPLMD_FINAL, NULL},
    {CRYPT_EAL_IMPLMD_DEINITCTX, NULL},
    {CRYPT_EAL_IMPLMD_COPYCTX, NULL},
    {CRYPT_EAL_IMPLMD_CTRL, NULL},
    {CRYPT_EAL_IMPLMD_FREECTX, NULL},
    CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_AlgInfo defMds[] = {
    {CRYPT_MD_MD5, defMdMd5, CRYPT_EAL_DEFAULT_ATTR},
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
            // *algInfos = defKdfs;
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
    return;
}

static CRYPT_EAL_Func defProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_DefaultProvQuery},
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_DefaultProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    CRYPT_EAL_FUNC_END
};

int32_t CRYPT_EAL_ProviderInitcb(CRYPT_EAL_ProvMgrCtx *mgrCtx,
    CRYPT_Param *param, CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    *outFuncs = defProvOutFuncs;
    return 0;
}
