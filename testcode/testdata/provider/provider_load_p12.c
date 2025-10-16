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
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"

#define CRYPT_EAL_DEFAULT_ATTR "provider?p12Load" // for unload mac and rand.

static int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX);
    }
    return 0;
}

void *DRBG_RandNewCtx(void *provCtx, int32_t algId, BSL_Param *param)
{
    (void)provCtx;
    (void)algId;
    (void)param;
    return malloc(1);
}

int32_t DRBG_Instantiate(void *ctx, const uint8_t *person, uint32_t persLen, BSL_Param *param)
{
    (void)ctx;
    (void)person;
    (void)persLen;
    (void)param;
    return CRYPT_SUCCESS;
}

int32_t DRBG_Uninstantiate(void *ctx)
{
    (void)ctx;
    return CRYPT_SUCCESS;
}

int32_t DRBG_Generate(void *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen,  BSL_Param *param)
{
    (void)ctx;
    (void)adin;
    (void)adinLen;
    (void)param;
    RandFunc(out, outLen);
    return CRYPT_SUCCESS;
}

int32_t DRBG_Reseed(void *ctx, const uint8_t *adin, uint32_t adinLen, BSL_Param *param)
{
    (void)ctx;
    (void)adin;
    (void)adinLen;
    (void)param;
    return CRYPT_SUCCESS;
}

int32_t DRBG_Ctrl(void *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    (void)ctx;
    (void)cmd;
    (void)val;
    (void)valLen;
    return CRYPT_SUCCESS;
}

void DRBG_Free(void *ctx)
{
    free(ctx);
}

void *MAC_NewCtx(void *provCtx, int32_t algid, BSL_Param *param)
{
    (void)provCtx;
    (void)param;
    int *ctx = malloc(sizeof(int));
    return ctx;
}

int32_t MAC_FreeCtx(void *ctx)
{
    free(ctx);
    return CRYPT_SUCCESS;
}

int32_t MAC_Init(void *ctx, const uint8_t *key, uint32_t len, void *param)
{
    (void)ctx;
    (void)key;
    (void)len;
    (void)param;
    return CRYPT_SUCCESS;
}

int32_t MAC_Update(void *ctx, const uint8_t *in, uint32_t len)
{
    (void)ctx;
    (void)in;
    (void)len;
    return CRYPT_SUCCESS;
}

int32_t MAC_Final(void *ctx, uint8_t *out, uint32_t *len)
{
    (void)ctx;
    (void)out;
    (void)len;
    return CRYPT_SUCCESS;
}

const CRYPT_EAL_Func defMacHmac[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, MAC_NewCtx},
    {CRYPT_EAL_IMPLMAC_INIT, MAC_Init},
    {CRYPT_EAL_IMPLMAC_UPDATE, MAC_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, MAC_Final},
    {CRYPT_EAL_IMPLMAC_REINITCTX, NULL},
    {CRYPT_EAL_IMPLMAC_CTRL, NULL},
    {CRYPT_EAL_IMPLMAC_FREECTX, MAC_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_testRand[] = {
    {CRYPT_EAL_IMPLRAND_DRBGNEWCTX, (CRYPT_EAL_ImplRandDrbgNewCtx)DRBG_RandNewCtx},
    {CRYPT_EAL_IMPLRAND_DRBGINST, (CRYPT_EAL_ImplRandDrbgInst)DRBG_Instantiate},
    {CRYPT_EAL_IMPLRAND_DRBGUNINST, (CRYPT_EAL_ImplRandDrbgUnInst)DRBG_Uninstantiate},
    {CRYPT_EAL_IMPLRAND_DRBGGEN, (CRYPT_EAL_ImplRandDrbgGen)DRBG_Generate},
    {CRYPT_EAL_IMPLRAND_DRBGRESEED, (CRYPT_EAL_ImplRandDrbgReSeed)DRBG_Reseed},
    {CRYPT_EAL_IMPLRAND_DRBGCTRL, (CRYPT_EAL_ImplRandDrbgCtrl)DRBG_Ctrl},
    {CRYPT_EAL_IMPLRAND_DRBGFREECTX, (CRYPT_EAL_ImplRandDrbgFreeCtx)DRBG_Free},
    CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_AlgInfo defMacs[] = {
    {CRYPT_MAC_HMAC_SM3, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defRand[] = {
    {CRYPT_RAND_SHA256, g_testRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SM3, g_testRand, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static int32_t CRYPT_EAL_DefaultProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void) provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_MAC:
            *algInfos = defMacs;
            break;
        case CRYPT_EAL_OPERAID_RAND:
            *algInfos = defRand;
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

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx,
    BSL_Param *param, CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    CRYPT_RandSeedMethod entroy = {0};
    CRYPT_EAL_ProvMgrCtrlCb mgrCtrl = NULL;
    int32_t index = 0;
    while (capFuncs[index].id != 0) {
        switch (capFuncs[index].id) {
            case CRYPT_EAL_CAP_GETENTROPY:
                entroy.getEntropy = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_CLEANENTROPY:
                entroy.cleanEntropy = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_GETNONCE:
                entroy.getNonce = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_CLEANNONCE:
                entroy.cleanNonce = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_MGRCTXCTRL:
                mgrCtrl = capFuncs[index].func;
                break;
            default:
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    void *seedCtx = NULL;
    void *libCtx = NULL;
    if (entroy.getEntropy == NULL || entroy.cleanEntropy == NULL || entroy.getNonce == NULL ||
        entroy.cleanNonce == NULL || mgrCtrl == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETSEEDCTX, &seedCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETLIBCTX, &libCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_Data entropy = {NULL, 0};
    CRYPT_Range entropyRange = {32, 2147483632};
    ret = entroy.getEntropy(seedCtx, &entropy, 256, &entropyRange);
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }
    entroy.cleanEntropy(seedCtx, &entropy);
    // check libCtx
    if (param != NULL) {
        if (param[0].value != libCtx) {
            return CRYPT_INVALID_ARG;
        }
    }
    *outFuncs = defProvOutFuncs;
    return 0;
}
