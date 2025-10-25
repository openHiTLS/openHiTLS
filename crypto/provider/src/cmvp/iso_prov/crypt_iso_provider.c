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
#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include <stdint.h>
#include <string.h>
#include "bsl_sal.h"
#include "bsl_obj.h"
#include "bsl_errno.h"
#include "bsl_params.h"
#include "bsl_err_internal.h"
#include "eal_entropy.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "cmvp_iso19790.h"
#include "crypt_eal_entropy.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_provider.h"
#include "crypt_iso_provderimpl.h"
#include "crypt_iso_provider.h"
#include "crypt_iso_selftest.h"
#include "crypt_params_key.h"
#include "crypt_params_key.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "crypt_eal_rand.h"
#include "hitls_type.h"

#define CRYPT_ENTROPY_SOURCE_ENTROPY 8
#define CRYPT_ENTROPY_SEED_POOL_SIZE 4096

static const CRYPT_EAL_AlgInfo g_isoMds[] = {
    {CRYPT_MD_SHA1, g_isoMdSha1, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SHA224, g_isoMdSha224, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SHA256, g_isoMdSha256, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SHA384, g_isoMdSha384, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SHA512, g_isoMdSha512, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SHA3_224, g_isoMdSha3224, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SHA3_256, g_isoMdSha3256, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SHA3_384, g_isoMdSha3384, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SHA3_512, g_isoMdSha3512, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SHAKE128, g_isoMdShake128, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SHAKE256, g_isoMdShake256, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MD_SM3, g_isoMdSm3, CRYPT_EAL_ISO_ATTR},
    CRYPT_EAL_ALGINFO_END
};


static const CRYPT_EAL_AlgInfo g_isoKdfs[] = {
    {CRYPT_KDF_SCRYPT, g_isoKdfScrypt, CRYPT_EAL_ISO_ATTR},
    {CRYPT_KDF_PBKDF2, g_isoKdfPBKdf2, CRYPT_EAL_ISO_ATTR},
    {CRYPT_KDF_KDFTLS12, g_isoKdfKdfTLS12, CRYPT_EAL_ISO_ATTR},
    {CRYPT_KDF_HKDF, g_isoKdfHkdf, CRYPT_EAL_ISO_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_isoKeyMgmt[] = {
    {CRYPT_PKEY_DSA, g_isoKeyMgmtDsa, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_ED25519, g_isoKeyMgmtEd25519, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_X25519, g_isoKeyMgmtX25519, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_RSA, g_isoKeyMgmtRsa, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_DH, g_isoKeyMgmtDh, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_ECDSA, g_isoKeyMgmtEcdsa, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_ECDH, g_isoKeyMgmtEcdh, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_SM2, g_isoKeyMgmtSm2, CRYPT_EAL_ISO_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_isoAsymCiphers[] = {
    {CRYPT_PKEY_RSA, g_isoAsymCipherRsa, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_SM2, g_isoAsymCipherSm2, CRYPT_EAL_ISO_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_isoKeyExch[] = {
    {CRYPT_PKEY_X25519, g_isoExchX25519, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_DH, g_isoExchDh, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_ECDH, g_isoExchEcdh, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_SM2, g_isoExchSm2, CRYPT_EAL_ISO_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_isoSigns[] = {
    {CRYPT_PKEY_DSA, g_isoSignDsa, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_ED25519, g_isoSignEd25519, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_RSA, g_isoSignRsa, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_ECDSA, g_isoSignEcdsa, CRYPT_EAL_ISO_ATTR},
    {CRYPT_PKEY_SM2, g_isoSignSm2, CRYPT_EAL_ISO_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_isoMacs[] = {
    {CRYPT_MAC_HMAC_SHA1, g_isoMacHmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_HMAC_SHA224, g_isoMacHmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_HMAC_SHA256, g_isoMacHmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_HMAC_SHA384, g_isoMacHmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_HMAC_SHA512, g_isoMacHmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_HMAC_SHA3_224, g_isoMacHmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_HMAC_SHA3_256, g_isoMacHmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_HMAC_SHA3_384, g_isoMacHmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_HMAC_SHA3_512, g_isoMacHmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_HMAC_SM3, g_isoMacHmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_CMAC_AES128, g_isoMacCmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_CMAC_AES192, g_isoMacCmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_CMAC_AES256, g_isoMacCmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_CMAC_SM4, g_isoMacCmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_GMAC_AES128, g_isoMacGmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_GMAC_AES192, g_isoMacGmac, CRYPT_EAL_ISO_ATTR},
    {CRYPT_MAC_GMAC_AES256, g_isoMacGmac, CRYPT_EAL_ISO_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_isoRands[] = {
    {CRYPT_RAND_SHA1, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_SHA224, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_SHA256, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_SHA384, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_SHA512, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_SM3, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_HMAC_SHA1, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_HMAC_SHA224, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_HMAC_SHA256, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_HMAC_SHA384, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_HMAC_SHA512, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_AES128_CTR, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_AES192_CTR, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_AES256_CTR, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_AES128_CTR_DF, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_AES192_CTR_DF, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_AES256_CTR_DF, g_isoRand, CRYPT_EAL_ISO_ATTR},
    {CRYPT_RAND_SM4_CTR_DF, g_isoRand, CRYPT_EAL_ISO_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_isoCiphers[] = {
    {CRYPT_CIPHER_AES128_CBC, g_isoCbc, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES192_CBC, g_isoCbc, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES256_CBC, g_isoCbc, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES128_CTR, g_isoCtr, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES192_CTR, g_isoCtr, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES256_CTR, g_isoCtr, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES128_ECB, g_isoEcb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES192_ECB, g_isoEcb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES256_ECB, g_isoEcb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES128_CCM, g_isoCcm, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES192_CCM, g_isoCcm, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES256_CCM, g_isoCcm, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES128_GCM, g_isoGcm, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES192_GCM, g_isoGcm, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES256_GCM, g_isoGcm, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES128_XTS, g_isoXts, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES256_XTS, g_isoXts, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_CHACHA20_POLY1305, g_isoChaCha, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_SM4_XTS, g_isoXts, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_SM4_CBC, g_isoCbc, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_SM4_ECB, g_isoEcb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_SM4_CTR, g_isoCtr, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_SM4_GCM, g_isoGcm, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_SM4_CFB, g_isoCfb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_SM4_OFB, g_isoOfb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES128_CFB, g_isoCfb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES192_CFB, g_isoCfb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES256_CFB, g_isoCfb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES128_OFB, g_isoOfb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES192_OFB, g_isoOfb, CRYPT_EAL_ISO_ATTR},
    {CRYPT_CIPHER_AES256_OFB, g_isoOfb, CRYPT_EAL_ISO_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_isoSelftests[] = {
    {CRYPT_CMVP_PROVIDER_SELFTEST, g_isoSelftest, CRYPT_EAL_ISO_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static int32_t CRYPT_EAL_IsoProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_SYMMCIPHER:
            *algInfos = g_isoCiphers;
            break;
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = g_isoKeyMgmt;
            break;
        case CRYPT_EAL_OPERAID_SIGN:
            *algInfos = g_isoSigns;
            break;
        case CRYPT_EAL_OPERAID_ASYMCIPHER:
            *algInfos = g_isoAsymCiphers;
            break;
        case CRYPT_EAL_OPERAID_KEYEXCH:
            *algInfos = g_isoKeyExch;
            break;
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = g_isoMds;
            break;
        case CRYPT_EAL_OPERAID_MAC:
            *algInfos = g_isoMacs;
            break;
        case CRYPT_EAL_OPERAID_KDF:
            *algInfos = g_isoKdfs;
            break;
        case CRYPT_EAL_OPERAID_RAND:
            *algInfos = g_isoRands;
            break;
        case CRYPT_EAL_OPERAID_SELFTEST:
            *algInfos = g_isoSelftests;
            break;
        default:
            ret = CRYPT_NOT_SUPPORT;
            break;
    }
    return ret;
}

static void CRYPT_EAL_IsoProvFree(void *provCtx)
{
    if (provCtx == NULL) {
        return;
    }
    CRYPT_EAL_IsoProvCtx *temp = (CRYPT_EAL_IsoProvCtx *)provCtx;
    if (temp->es != NULL) {
        CRYPT_EAL_SeedPoolFree(temp->seedCtx);
        CRYPT_EAL_EsFree(temp->es);
    }
    BSL_SAL_Free(provCtx);
}

static CRYPT_EAL_Func g_isoProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_IsoProvQuery},
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_IsoProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    {CRYPT_EAL_PROVCB_GETCAPS, NULL},
    CRYPT_EAL_FUNC_END
};

static void EntropyRunLogCb(int32_t ret)
{
    CMVP_Iso19790EventProcess(CRYPT_EVENT_ES_HEALTH_TEST, 0, 0, ret);
}

static int32_t CreateIsoEs(CRYPT_EAL_Es **es)
{
    int32_t ret = CRYPT_SUCCESS;
    CRYPT_EAL_Es *esTemp = CRYPT_EAL_EsNew();
    RETURN_RET_IF(esTemp == NULL, CRYPT_MEM_ALLOC_FAIL);

    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_SET_CF, "sha256_df", (uint32_t)strlen("sha256_df"));
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_REMOVE_NS, "timestamp", (uint32_t)strlen("timestamp"));
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_SET_LOG_CALLBACK, EntropyRunLogCb, 0);
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    bool healthTest = true;
    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(healthTest));
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    uint32_t size = CRYPT_ENTROPY_SEED_POOL_SIZE;
    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_SET_POOL_SIZE, &size, sizeof(size));
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    ret = CRYPT_EAL_EsInit(esTemp);
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    *es = esTemp;
    return ret;

ERR:
    CRYPT_EAL_EsFree(esTemp);
    return ret;
}

static int32_t CreateSeedPool(void **seedCtx, CRYPT_EAL_Es **es)
{
    CRYPT_EAL_SeedPoolCtx *poolTemp = NULL;
    CRYPT_EAL_Es *esTemp = NULL;

    int32_t ret = CreateIsoEs(&esTemp);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    poolTemp = CRYPT_EAL_SeedPoolNew(true);
    if (poolTemp == NULL) {
        CRYPT_EAL_EsFree(esTemp);
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NEW_ERROR);
        return CRYPT_SEED_POOL_NEW_ERROR;
    }

    CRYPT_EAL_EsPara para = {false, CRYPT_ENTROPY_SOURCE_ENTROPY, esTemp, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ret = CRYPT_EAL_SeedPoolAddEs(poolTemp, &para);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_SeedPoolFree(poolTemp);
        CRYPT_EAL_EsFree(esTemp);
        return ret;
    }

    *seedCtx = poolTemp;
    *es = esTemp;
    return CRYPT_SUCCESS;
}

static int32_t SetEntropyMethod(CRYPT_EAL_IsoProvCtx *provCtx, BSL_Param *param)
{
    BSL_Param *getEnt = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEED_GETENTROPY);
    BSL_Param *cleanEnt = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEED_CLEANENTROPY);
    BSL_Param *getNonce = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEED_GETNONCE);
    BSL_Param *cleanNonce = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEED_CLEANNONCE);
    BSL_Param *ctx = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEEDCTX);

    if (getEnt == NULL && ((cleanEnt != NULL && cleanEnt->value != NULL) ||
        (getNonce != NULL && getNonce->value != NULL) || (cleanNonce != NULL && cleanNonce->value != NULL) ||
        (ctx != NULL && ctx->value != NULL))) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    if (getEnt != NULL) {
        provCtx->seedMethod.getEntropy = getEnt->value;
        provCtx->seedMethod.cleanEntropy = cleanEnt != NULL ? cleanEnt->value : NULL;
        provCtx->seedMethod.getNonce = getNonce != NULL ? getNonce->value : NULL;
        provCtx->seedMethod.cleanNonce = cleanNonce != NULL ? cleanNonce->value : NULL;
        provCtx->seedCtx = ctx != NULL ? ctx->value : NULL;
        return CRYPT_SUCCESS;
    }

    int32_t ret = EAL_SetDefaultEntropyMeth(&provCtx->seedMethod);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CreateSeedPool(&provCtx->seedCtx, &provCtx->es);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static int32_t IsoCreateProvCtx(void *libCtx, CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param, void **provCtx)
{
    CRYPT_EAL_IsoProvCtx *temp = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_IsoProvCtx));
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_Iso_GetLogFunc(param, &temp->runLog);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(temp);
        return ret;
    }
    CRYPT_EAL_SetRandCallBackEx((CRYPT_EAL_RandFuncEx)CRYPT_EAL_RandbytesEx);
    ret = SetEntropyMethod(temp, param);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(temp);
        return ret;
    }
    temp->libCtx = libCtx;
    temp->mgrCtx = mgrCtx;
    *provCtx = temp;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param, CRYPT_EAL_Func *capFuncs,
    CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    void *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtrlCb mgrCtrl = NULL;
    int32_t index = 0;
    int32_t ret;
    while (capFuncs[index].id != 0) {
        switch (capFuncs[index].id) {
            case CRYPT_EAL_CAP_MGRCTXCTRL:
                mgrCtrl = capFuncs[index].func;
                break;
            default:
                break;
        }
        index++;
    }
    if (mgrCtrl == NULL) {
        return CRYPT_PROVIDER_NOT_SUPPORT;
    }
    ret = mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETLIBCTX, &libCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_Iso_Selftest(param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = IsoCreateProvCtx(libCtx, mgrCtx, param, provCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    *outFuncs = g_isoProvOutFuncs;
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
