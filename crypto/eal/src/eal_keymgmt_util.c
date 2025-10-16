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
#if defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_CRYPTO_PROVIDER)
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "eal_pkey_local.h"
#include "eal_pkey.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"

CRYPT_EAL_PkeyCtx *CRYPT_EAL_MakeKeyByPkeyAlgInfo(CRYPT_EAL_PkeyMgmtInfo *pkeyAlgInfo, void *keyRef)
{
    if (pkeyAlgInfo == NULL || keyRef == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_EAL_PkeyCtx *pkeyCtx = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_PkeyCtx));
    if (pkeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    pkeyCtx->isProvider = true;
    pkeyCtx->id = pkeyAlgInfo->algId;
    pkeyCtx->key = keyRef;
    pkeyCtx->extData = NULL;
    pkeyCtx->method = pkeyAlgInfo->keyMgmtMethod;
    BSL_SAL_ReferencesInit(&(pkeyCtx->references));
    return pkeyCtx;
}

int32_t CRYPT_EAL_GetPkeyAlgInfo(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    CRYPT_EAL_PkeyMgmtInfo *pkeyAlgInfo)
{
    CRYPT_EAL_AsyAlgFuncsInfo funcInfo = {0};
    int32_t ret = CRYPT_EAL_ProviderGetAsyAlgFuncs(libCtx, algId, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, attrName, &funcInfo);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CRYPT_EAL_SetPkeyMethod(&(pkeyAlgInfo->keyMgmtMethod), funcInfo.funcsKeyMgmt, funcInfo.funcsAsyCipher,
        funcInfo.funcsExch, funcInfo.funcSign, funcInfo.funcKem);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    pkeyAlgInfo->algId = algId;
    pkeyAlgInfo->mgrCtx = funcInfo.mgrCtx;
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_CODECSKEY && CRYPT_EAL_PROVIDER */
