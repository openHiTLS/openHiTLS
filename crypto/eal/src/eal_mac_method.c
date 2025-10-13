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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MAC)

#include <stdint.h>
#include "securec.h"
#include "crypt_local_types.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "eal_mac_local.h"
#include "eal_cipher_local.h"
#include "eal_md_local.h"
#ifdef HITLS_CRYPTO_HMAC
#include "crypt_hmac.h"
#endif
#ifdef HITLS_CRYPTO_CMAC
#include "crypt_cmac.h"
#endif
#ifdef HITLS_CRYPTO_CBC_MAC
#include "crypt_cbc_mac.h"
#endif
#ifdef HITLS_CRYPTO_GMAC
#include "crypt_gmac.h"
#endif
#ifdef HITLS_CRYPTO_SIPHASH
#include "crypt_siphash.h"
#endif
#include "bsl_err_internal.h"
#include "eal_common.h"

#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_eal_implprovider.h"
#endif

#define CRYPT_MAC_IMPL_METHOD_DECLARE(name)          \
    EAL_MacMethod g_macMethod_##name = {             \
        (MacNewCtx)CRYPT_##name##_NewCtxEx,          \
        (MacInit)CRYPT_##name##_Init,                \
        (MacUpdate)CRYPT_##name##_Update,            \
        (MacFinal)CRYPT_##name##_Final,              \
        (MacDeinit)CRYPT_##name##_Deinit,            \
        (MacReinit)CRYPT_##name##_Reinit,            \
        (MacCtrl)CRYPT_##name##_Ctrl,                \
        (MacSetParam)CRYPT_##name##_SetParam,        \
        (MacFreeCtx)CRYPT_##name##_FreeCtx           \
    }

#ifdef HITLS_CRYPTO_HMAC
CRYPT_MAC_IMPL_METHOD_DECLARE(HMAC);
#endif
#ifdef HITLS_CRYPTO_CMAC
CRYPT_MAC_IMPL_METHOD_DECLARE(CMAC);
#endif

#ifdef HITLS_CRYPTO_CBC_MAC
CRYPT_MAC_IMPL_METHOD_DECLARE(CBC_MAC);
#endif

#ifdef HITLS_CRYPTO_GMAC
CRYPT_MAC_IMPL_METHOD_DECLARE(GMAC);
#endif

#ifdef HITLS_CRYPTO_SIPHASH
CRYPT_MAC_IMPL_METHOD_DECLARE(SIPHASH);
EAL_SiphashMethod g_siphash64Meth = {.hashSize = SIPHASH_MIN_DIGEST_SIZE,
    .compressionRounds = DEFAULT_COMPRESSION_ROUND,
    .finalizationRounds = DEFAULT_FINALIZATION_ROUND};

EAL_SiphashMethod g_siphash128Meth = {.hashSize = SIPHASH_MAX_DIGEST_SIZE,
    .compressionRounds = DEFAULT_COMPRESSION_ROUND,
    .finalizationRounds = DEFAULT_FINALIZATION_ROUND};
#endif

typedef enum {
    CRYPT_MAC_HMAC = 0,
    CRYPT_MAC_CMAC,
    CRYPT_MAC_CBC_MAC,
    CRYPT_MAC_SIPHASH,
    CRYPT_MAC_GMAC,
    CRYPT_MAC_INVALID
} CRYPT_MAC_ID;

static const EAL_MacMethod *g_macMethods[] = {
#ifdef HITLS_CRYPTO_HMAC
    &g_macMethod_HMAC,   // HMAC
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_CMAC
    &g_macMethod_CMAC,   // CMAC
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_CBC_MAC
    &g_macMethod_CBC_MAC,   // CBC-MAC
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_SIPHASH
    &g_macMethod_SIPHASH,   // SIPHASH
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_GMAC
    &g_macMethod_GMAC,   // GMAC
#else
    NULL,
#endif
};

typedef struct {
    uint32_t id;
    CRYPT_MAC_ID macId;
    union {
        CRYPT_MD_AlgId mdId;
        CRYPT_SYM_AlgId symId;
    };
} EAL_MacAlgMap;

static const EAL_MacAlgMap CID_MAC_ALG_MAP[] = {
#ifdef HITLS_CRYPTO_HMAC
    {.id = CRYPT_MAC_HMAC_MD5,      .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_MD5},
    {.id = CRYPT_MAC_HMAC_SHA1,     .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA1},
    {.id = CRYPT_MAC_HMAC_SHA224,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA224},
    {.id = CRYPT_MAC_HMAC_SHA256,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA256},
    {.id = CRYPT_MAC_HMAC_SHA384,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA384},
    {.id = CRYPT_MAC_HMAC_SHA512,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA512},
    {.id = CRYPT_MAC_HMAC_SHA3_224, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_224},
    {.id = CRYPT_MAC_HMAC_SHA3_256, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_256},
    {.id = CRYPT_MAC_HMAC_SHA3_384, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_384},
    {.id = CRYPT_MAC_HMAC_SHA3_512, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_512},
    {.id = CRYPT_MAC_HMAC_SM3,      .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SM3},
#endif // HITLS_CRYPTO_HMAC
#ifdef HITLS_CRYPTO_CMAC_AES
    {.id = CRYPT_MAC_CMAC_AES128,   .macId = CRYPT_MAC_CMAC, .symId = CRYPT_SYM_AES128},
    {.id = CRYPT_MAC_CMAC_AES192,   .macId = CRYPT_MAC_CMAC, .symId = CRYPT_SYM_AES192},
    {.id = CRYPT_MAC_CMAC_AES256,   .macId = CRYPT_MAC_CMAC, .symId = CRYPT_SYM_AES256},
#endif
#ifdef HITLS_CRYPTO_CMAC_SM4
    {.id = CRYPT_MAC_CMAC_SM4,      .macId = CRYPT_MAC_CMAC, .symId = CRYPT_SYM_SM4},
#endif
#ifdef HITLS_CRYPTO_CBC_MAC
    {.id = CRYPT_MAC_CBC_MAC_SM4,   .macId = CRYPT_MAC_CBC_MAC, .symId = CRYPT_SYM_SM4},
#endif
#ifdef HITLS_CRYPTO_GMAC
    {.id = CRYPT_MAC_GMAC_AES128,   .macId = CRYPT_MAC_GMAC, .symId = CRYPT_SYM_AES128},
    {.id = CRYPT_MAC_GMAC_AES192,   .macId = CRYPT_MAC_GMAC, .symId = CRYPT_SYM_AES192},
    {.id = CRYPT_MAC_GMAC_AES256,   .macId = CRYPT_MAC_GMAC, .symId = CRYPT_SYM_AES256},
#endif
#ifdef HITLS_CRYPTO_SIPHASH
    {.id = CRYPT_MAC_SIPHASH64,     .macId = CRYPT_MAC_SIPHASH},
    {.id = CRYPT_MAC_SIPHASH128,    .macId = CRYPT_MAC_SIPHASH}
#endif
};

static const EAL_MacAlgMap *EAL_FindMacAlgMap(CRYPT_MAC_AlgId id)
{
    uint32_t num = sizeof(CID_MAC_ALG_MAP) / sizeof(CID_MAC_ALG_MAP[0]);
    const EAL_MacAlgMap *macAlgMap = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (CID_MAC_ALG_MAP[i].id == id) {
            macAlgMap = &CID_MAC_ALG_MAP[i];
            break;
        }
    }
    return macAlgMap;
}

#if defined(HITLS_CRYPTO_CMAC) || defined(HITLS_CRYPTO_CBC_MAC) || defined(HITLS_CRYPTO_GMAC)
static int32_t ConvertSymId2CipherId(CRYPT_SYM_AlgId algId)
{
    switch (algId) {
        case CRYPT_SYM_AES128:
            return CRYPT_CIPHER_AES128_ECB;
        case CRYPT_SYM_AES192:
            return CRYPT_CIPHER_AES192_ECB;
        case CRYPT_SYM_AES256:
            return CRYPT_CIPHER_AES256_ECB;
        case CRYPT_SYM_SM4:
            return CRYPT_CIPHER_SM4_XTS;
        default:
            return CRYPT_CIPHER_MAX;
    }
}
#endif

const EAL_MacMethod *EAL_MacFindDefaultMethod(CRYPT_MAC_AlgId id)
{
    const EAL_MacAlgMap *macAlgMap = EAL_FindMacAlgMap(id);
    if (macAlgMap == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return NULL;
    }
    return g_macMethods[macAlgMap->macId];
}

EAL_MacMethod *EAL_MacFindMethod(CRYPT_MAC_AlgId id, EAL_MacMethod *method)
{
    EAL_MacMethod *retMethod = method;
    const EAL_MacMethod *findMethod = EAL_MacFindDefaultMethod(id);
    if (findMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return NULL;
    }
    if (retMethod == NULL) {
        retMethod = BSL_SAL_Malloc(sizeof(EAL_MacMethod));
        if (retMethod == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
        (void)memset_s(retMethod, sizeof(EAL_MacMethod), 0, sizeof(EAL_MacMethod));
    }
    *retMethod = *findMethod;
    return retMethod;
}

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t SetMacMethod(const CRYPT_EAL_Func *funcs, EAL_MacMethod *method)
{
    int32_t index = 0;
    while (funcs[index].id != 0) {
        switch (funcs[index].id) {
            case CRYPT_EAL_IMPLMAC_NEWCTX:
                method->newCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_INIT:
                method->init = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_UPDATE:
                method->update = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_FINAL:
                method->final = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_REINITCTX:
                method->reinit = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_DEINITCTX:
                method->deinit = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_CTRL:
                method->ctrl = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_FREECTX:
                method->freeCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMAC_SETPARAM:
                method->setParam = funcs[index].func;
                break;
            default:
                BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    return CRYPT_SUCCESS;
}

static EAL_MacMethod *EAL_ProviderMacFindMethod(CRYPT_MAC_AlgId id, void *libCtx, const char *attrName,
    EAL_MacMethod *method, void **provCtx)
{
    EAL_MacMethod *retMethod = method;
    const CRYPT_EAL_Func *funcs = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_MAC, id, attrName, &funcs, provCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    if (method == NULL) {
        retMethod = (EAL_MacMethod *)BSL_SAL_Malloc(sizeof(EAL_MacMethod));
        if (retMethod == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
        (void)memset_s(retMethod, sizeof(EAL_MacMethod), 0, sizeof(EAL_MacMethod));
    }
    ret = SetMacMethod(funcs, retMethod);
    if (ret != CRYPT_SUCCESS) {
        if (retMethod != method) {
            BSL_SAL_Free(retMethod);
        }
        return NULL;
    }

    return retMethod;
}

#endif // HITLS_CRYPTO_PROVIDER

EAL_MacMethod *EAL_MacFindMethodEx(CRYPT_MAC_AlgId id, void *libCtx, const char *attrName, EAL_MacMethod *method,
    void **provCtx)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return EAL_ProviderMacFindMethod(id, libCtx, attrName, method, provCtx);
#else
    (void)libCtx;
    (void)attrName;
    (void)provCtx;
    return EAL_MacFindMethod(id, method);
#endif
}

int32_t EAL_MacFindDepMethod(CRYPT_MAC_AlgId macId, void *libCtx, const char *attrName, EAL_MacDepMethod *depMeth,
    void **provCtx, bool isProvider)
{
    (void)libCtx;
    (void)attrName;
    (void)provCtx;
    (void)isProvider;
    const EAL_MacAlgMap *macAlgMap = EAL_FindMacAlgMap(macId);
    if (macAlgMap == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

#ifdef HITLS_CRYPTO_HMAC
    EAL_MdMethod *mdMethod = NULL;
#endif
    switch (macAlgMap->macId) {
#ifdef HITLS_CRYPTO_HMAC
        case CRYPT_MAC_HMAC:
            depMeth->id.mdId = macAlgMap->mdId;
            mdMethod = EAL_MdFindMethodEx(macAlgMap->mdId, libCtx, attrName, depMeth->method.md, provCtx, isProvider);
            if (mdMethod == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
                return CRYPT_EAL_ERR_ALGID;
            }
            if (depMeth->method.md == NULL) {
                // if the md pointer is NULL, the md method will be allocated. The caller should free the md method.
                depMeth->method.md = mdMethod;
            } // if the md pointer is not NULL, the md method has been overwritten before.
            return CRYPT_SUCCESS;
#endif
#if defined(HITLS_CRYPTO_CMAC) || defined(HITLS_CRYPTO_CBC_MAC) || defined(HITLS_CRYPTO_GMAC)
        case CRYPT_MAC_CMAC:
        case CRYPT_MAC_CBC_MAC:
        case CRYPT_MAC_GMAC:
            depMeth->id.symId = macAlgMap->symId;
            // sym method is get from global, so no need to free it.
            depMeth->method.sym = EAL_GetSymMethod(ConvertSymId2CipherId(macAlgMap->symId));
            break;
#endif
#ifdef HITLS_CRYPTO_SIPHASH
        case CRYPT_MAC_SIPHASH:
            // sip method is get from global, so no need to free it.
            depMeth->method.sip = (macId == CRYPT_MAC_SIPHASH64) ? &g_siphash64Meth : &g_siphash128Meth;
            break;
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
            return CRYPT_EAL_ERR_ALGID;
    }
    if (depMeth->method.sym == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}
#endif
