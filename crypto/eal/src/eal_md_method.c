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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MD)

#include "securec.h"
#include "crypt_local_types.h"
#include "crypt_algid.h"
#ifdef HITLS_CRYPTO_SHA2
#include "crypt_sha2.h"
#endif
#ifdef HITLS_CRYPTO_SHA1
#include "crypt_sha1.h"
#endif
#ifdef HITLS_CRYPTO_SM3
#include "crypt_sm3.h"
#endif
#ifdef HITLS_CRYPTO_SHA3
#include "crypt_sha3.h"
#endif
#ifdef HITLS_CRYPTO_MD5
#include "crypt_md5.h"
#endif
#include "bsl_err_internal.h"
#include "eal_common.h"
#include "bsl_sal.h"
#include "crypt_errno.h"

#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#endif

typedef struct {
    uint32_t id;
    EAL_MdMethod *mdMeth;
} EAL_CidToMdMeth;

#define CRYPT_MD_IMPL_METHOD_DECLARE(name, id)                                              \
    EAL_MdMethod g_mdMethod_##name = {                                                      \
        id,                                                                                 \
        CRYPT_##name##_BLOCKSIZE,                   CRYPT_##name##_DIGESTSIZE,              \
        (MdNewCtx)CRYPT_##name##_NewCtxEx,          (MdInit)CRYPT_##name##_Init,            \
        (MdUpdate)CRYPT_##name##_Update,            (MdFinal)CRYPT_##name##_Final,          \
        (MdDeinit)CRYPT_##name##_Deinit,            (MdCopyCtx)CRYPT_##name##_CopyCtx,      \
        (MdDupCtx)CRYPT_##name##_DupCtx,            (MdFreeCtx)CRYPT_##name##_FreeCtx,      \
        (MdGetParam)CRYPT_##name##_GetParam,        (MdSqueeze)CRYPT_##name##_Squeeze       \
    }

#ifdef HITLS_CRYPTO_MD5
CRYPT_MD_IMPL_METHOD_DECLARE(MD5, CRYPT_MD_MD5);
#endif
#ifdef HITLS_CRYPTO_SHA1
CRYPT_MD_IMPL_METHOD_DECLARE(SHA1, CRYPT_MD_SHA1);
#endif
#ifdef HITLS_CRYPTO_SHA224
CRYPT_MD_IMPL_METHOD_DECLARE(SHA2_224, CRYPT_MD_SHA224);
#endif
#ifdef HITLS_CRYPTO_SHA256
CRYPT_MD_IMPL_METHOD_DECLARE(SHA2_256, CRYPT_MD_SHA256);
#endif
#ifdef HITLS_CRYPTO_SHA384
CRYPT_MD_IMPL_METHOD_DECLARE(SHA2_384, CRYPT_MD_SHA384);
#endif
#ifdef HITLS_CRYPTO_SHA512
CRYPT_MD_IMPL_METHOD_DECLARE(SHA2_512, CRYPT_MD_SHA512);
#endif
#ifdef HITLS_CRYPTO_SHA3
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_224, CRYPT_MD_SHA3_224);
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_256, CRYPT_MD_SHA3_256);
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_384, CRYPT_MD_SHA3_384);
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_512, CRYPT_MD_SHA3_512);
CRYPT_MD_IMPL_METHOD_DECLARE(SHAKE128, CRYPT_MD_SHAKE128);
CRYPT_MD_IMPL_METHOD_DECLARE(SHAKE256, CRYPT_MD_SHAKE256);
#endif
#ifdef HITLS_CRYPTO_SM3
CRYPT_MD_IMPL_METHOD_DECLARE(SM3, CRYPT_MD_SM3);
#endif

static const EAL_CidToMdMeth ID_TO_MD_METH_TABLE[] = {
#ifdef HITLS_CRYPTO_MD5
    {CRYPT_MD_MD5,      &g_mdMethod_MD5},
#endif
#ifdef HITLS_CRYPTO_SHA1
    {CRYPT_MD_SHA1,     &g_mdMethod_SHA1},
#endif
#ifdef HITLS_CRYPTO_SHA224
    {CRYPT_MD_SHA224,   &g_mdMethod_SHA2_224},
#endif
#ifdef HITLS_CRYPTO_SHA256
    {CRYPT_MD_SHA256,   &g_mdMethod_SHA2_256},
#endif
#ifdef HITLS_CRYPTO_SHA384
    {CRYPT_MD_SHA384,   &g_mdMethod_SHA2_384},
#endif
#ifdef HITLS_CRYPTO_SHA512
    {CRYPT_MD_SHA512,   &g_mdMethod_SHA2_512},
#endif
#ifdef HITLS_CRYPTO_SHA3
    {CRYPT_MD_SHA3_224, &g_mdMethod_SHA3_224},
    {CRYPT_MD_SHA3_256, &g_mdMethod_SHA3_256},
    {CRYPT_MD_SHA3_384, &g_mdMethod_SHA3_384},
    {CRYPT_MD_SHA3_512, &g_mdMethod_SHA3_512},
    {CRYPT_MD_SHAKE128, &g_mdMethod_SHAKE128},
    {CRYPT_MD_SHAKE256, &g_mdMethod_SHAKE256},
#endif
#ifdef HITLS_CRYPTO_SM3
    {CRYPT_MD_SM3,      &g_mdMethod_SM3},
#endif
};

const EAL_MdMethod *EAL_MdFindDefaultMethod(CRYPT_MD_AlgId id)
{
    uint32_t num = sizeof(ID_TO_MD_METH_TABLE) / sizeof(ID_TO_MD_METH_TABLE[0]);
    for (uint32_t i = 0; i < num; i++) {
        if (ID_TO_MD_METH_TABLE[i].id == id) {
            return ID_TO_MD_METH_TABLE[i].mdMeth;
        }
    }
    return NULL;
}

EAL_MdMethod *EAL_MdFindMethod(CRYPT_MD_AlgId id, EAL_MdMethod *method)
{
    EAL_MdMethod *retMethod = method;
    const EAL_MdMethod *findMethod = EAL_MdFindDefaultMethod(id);
    if (findMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return NULL;
    }
    if (retMethod == NULL) {
        retMethod = BSL_SAL_Malloc(sizeof(EAL_MdMethod));
        if (retMethod == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
        (void)memset_s(retMethod, sizeof(EAL_MdMethod), 0, sizeof(EAL_MdMethod));
    }
    *retMethod = *findMethod;
    return retMethod;
}

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t SetMdMethod(const CRYPT_EAL_Func *funcs, EAL_MdMethod *method)
{
    int32_t index = 0;
    while (funcs[index].id != 0) {
        switch (funcs[index].id) {
            case CRYPT_EAL_IMPLMD_NEWCTX:
                method->newCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_INITCTX:
                method->init = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_UPDATE:
                method->update = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_FINAL:
                method->final = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_DEINITCTX:
                method->deinit = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_DUPCTX:
                method->dupCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_GETPARAM:
                method->getParam = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_FREECTX:
                method->freeCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_SQUEEZE:
                method->squeeze = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLMD_COPYCTX:
                method->copyCtx = funcs[index].func;
                break;
            default:
                BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    return CRYPT_SUCCESS;
}

static EAL_MdMethod *EAL_ProviderMdFindMethod(CRYPT_MD_AlgId id, void *libCtx, const char *attrName,
    EAL_MdMethod *method, void **provCtx)
{
    BSL_Param params[] = {{0}, {0}, BSL_PARAM_END};
    EAL_MdMethod *retMethod = method;
    const CRYPT_EAL_Func *funcs = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, id, attrName, &funcs, provCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    if (method == NULL) {
        retMethod = (EAL_MdMethod *)BSL_SAL_Malloc(sizeof(EAL_MdMethod));
        if (retMethod == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
        (void)memset_s(retMethod, sizeof(EAL_MdMethod), 0, sizeof(EAL_MdMethod));
    }

    ret = SetMdMethod(funcs, retMethod);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }

    if (retMethod->getParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_IMPL_NULL);
        goto ERR;
    }
    (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_MD_DIGEST_SIZE, BSL_PARAM_TYPE_UINT16, &retMethod->mdSize,
        sizeof(retMethod->mdSize));
    (void)BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_MD_BLOCK_SIZE, BSL_PARAM_TYPE_UINT16, &retMethod->blockSize,
        sizeof(retMethod->blockSize));
    ret = retMethod->getParam(NULL, &params[0]);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    retMethod->id = id;
    return retMethod;
ERR:
    if (retMethod != method) {
        BSL_SAL_Free(retMethod);
    }
    return NULL;
}
#endif // HITLS_CRYPTO_PROVIDER

EAL_MdMethod *EAL_MdFindMethodEx(CRYPT_MD_AlgId id, void *libCtx, const char *attrName, EAL_MdMethod *method,
    void **provCtx, bool isProvider)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return isProvider == true ? EAL_ProviderMdFindMethod(id, libCtx, attrName, method, provCtx)
                              : EAL_MdFindMethod(id, method);
#else
    (void)libCtx;
    (void)attrName;
    (void)provCtx;
    (void)isProvider;
    return EAL_MdFindMethod(id, method);
#endif
}

int32_t EAL_Md(CRYPT_MD_AlgId id, void *libCtx, const char *attr, const uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen, bool isProvider)
{
    int32_t ret;
    if (out == NULL || outLen == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (in == NULL && inLen != 0) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    EAL_MdMethod method = {0};
    void *provCtx = NULL;
    if (EAL_MdFindMethodEx(id, libCtx, attr, &method, &provCtx, isProvider) == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    if (method.newCtx == NULL || method.init == NULL || method.update == NULL || method.final == NULL ||
        method.freeCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_EAL_MD_METH_NULL);
        return CRYPT_EAL_MD_METH_NULL;
    }

    void *data = method.newCtx(provCtx, id);
    if (data == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = method.init(data, NULL);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, ret);
        goto EXIT;
    }
    if (inLen != 0) {
        ret = method.update(data, in, inLen);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, ret);
            goto EXIT;
        }
    }

    ret = method.final(data, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, ret);
        goto EXIT;
    }

EXIT:
    method.freeCtx(data);
    return ret;
}
#endif
