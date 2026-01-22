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

#define CRYPT_MD_IMPL_METHOD_DECLARE(name)     \
    EAL_MdMethod g_mdMethod_##name = {         \
        CRYPT_##name##_BLOCKSIZE,         CRYPT_##name##_DIGESTSIZE,              \
        (MdNewCtx)CRYPT_##name##_NewCtx,  (MdInit)CRYPT_##name##_Init,            \
        (MdUpdate)CRYPT_##name##_Update,  (MdFinal)CRYPT_##name##_Final,          \
        (MdDeinit)CRYPT_##name##_Deinit,  (MdCopyCtx)CRYPT_##name##_CopyCtx,      \
        (MdDupCtx)CRYPT_##name##_DupCtx,  (MdFreeCtx)CRYPT_##name##_FreeCtx, NULL, NULL \
    }

#ifdef HITLS_CRYPTO_MD5
CRYPT_MD_IMPL_METHOD_DECLARE(MD5);
#endif
#ifdef HITLS_CRYPTO_SHA1
CRYPT_MD_IMPL_METHOD_DECLARE(SHA1);
#endif
#ifdef HITLS_CRYPTO_SHA2
#ifdef HITLS_CRYPTO_SHA224
CRYPT_MD_IMPL_METHOD_DECLARE(SHA2_224);
#endif
#ifdef HITLS_CRYPTO_SHA256
CRYPT_MD_IMPL_METHOD_DECLARE(SHA2_256);
#endif
#ifdef HITLS_CRYPTO_SHA384
CRYPT_MD_IMPL_METHOD_DECLARE(SHA2_384);
#endif
#ifdef HITLS_CRYPTO_SHA512
CRYPT_MD_IMPL_METHOD_DECLARE(SHA2_512);
#endif
#endif
#ifdef HITLS_CRYPTO_SHA3
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_224);
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_256);
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_384);
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_512);
EAL_MdMethod g_mdMethod_SHAKE128 = {
    CRYPT_SHAKE128_BLOCKSIZE,         CRYPT_SHAKE128_DIGESTSIZE,
    (MdNewCtx)CRYPT_SHAKE128_NewCtx,  (MdInit)CRYPT_SHAKE128_Init,
    (MdUpdate)CRYPT_SHAKE128_Update,  (MdFinal)CRYPT_SHAKE128_Final,
    (MdDeinit)CRYPT_SHAKE128_Deinit,  (MdCopyCtx)CRYPT_SHAKE128_CopyCtx,
    (MdDupCtx)CRYPT_SHAKE128_DupCtx,  (MdFreeCtx)CRYPT_SHAKE128_FreeCtx,
    NULL, (MdSqueeze)CRYPT_SHAKE128_Squeeze
};
EAL_MdMethod g_mdMethod_SHAKE256 = {
    CRYPT_SHAKE256_BLOCKSIZE,         CRYPT_SHAKE256_DIGESTSIZE,
    (MdNewCtx)CRYPT_SHAKE256_NewCtx,  (MdInit)CRYPT_SHAKE256_Init,
    (MdUpdate)CRYPT_SHAKE256_Update,  (MdFinal)CRYPT_SHAKE256_Final,
    (MdDeinit)CRYPT_SHAKE256_Deinit,  (MdCopyCtx)CRYPT_SHAKE256_CopyCtx,
    (MdDupCtx)CRYPT_SHAKE256_DupCtx,  (MdFreeCtx)CRYPT_SHAKE256_FreeCtx,
    NULL, (MdSqueeze)CRYPT_SHAKE256_Squeeze
};
#endif
#ifdef HITLS_CRYPTO_SM3
CRYPT_MD_IMPL_METHOD_DECLARE(SM3);
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
    {CRYPT_MD_SM3,      &g_mdMethod_SM3},       // SM3
#endif
};

const EAL_MdMethod *EAL_MdFindMethod(CRYPT_MD_AlgId id)
{
    EAL_MdMethod *pMdMeth = NULL;
    uint32_t num = sizeof(ID_TO_MD_METH_TABLE) / sizeof(ID_TO_MD_METH_TABLE[0]);

    for (uint32_t i = 0; i < num; i++) {
        if (ID_TO_MD_METH_TABLE[i].id == id) {
            pMdMeth = ID_TO_MD_METH_TABLE[i].mdMeth;
            return pMdMeth;
        }
    }

    return NULL;
}

#ifdef HITLS_CRYPTO_MD_MB
#ifdef HITLS_CRYPTO_SHA2_MB
static const EAL_MdMBMethod g_mdMbMethod_SHA256 = {
    (MdMBNewCtx)CRYPT_SHA256_MBNewCtx,
    (MdMBFreeCtx)CRYPT_SHA256_MBFreeCtx,
    (MdMBInit)CRYPT_SHA256_MBInit,
    (MdMBUpdate)CRYPT_SHA256_MBUpdate,
    (MdMBFinal)CRYPT_SHA256_MBFinal
};
#endif

static const EAL_CidToMdMbMeth ID_TO_MD_MB_METH_TABLE[] = {
#ifdef HITLS_CRYPTO_SHA2_MB
    {CRYPT_MD_SHA256_MB, &g_mdMbMethod_SHA256},
#endif
};

static const EAL_MdMBMethod *EAL_MdFindDefaultMbMethod(CRYPT_MD_AlgId id)
{
    uint32_t num = sizeof(ID_TO_MD_MB_METH_TABLE) / sizeof(ID_TO_MD_MB_METH_TABLE[0]);
    for (uint32_t i = 0; i < num; i++) {
        if (ID_TO_MD_MB_METH_TABLE[i].id == id) {
            return ID_TO_MD_MB_METH_TABLE[i].mbMeth;
        }
    }
    return NULL;
}

EAL_MdMBMethod *EAL_MdFindMbMethod(CRYPT_MD_AlgId id, EAL_MdMBMethod *method)
{
    const EAL_MdMBMethod *findMethod = EAL_MdFindDefaultMbMethod(id);
    if (findMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return NULL;
    }
    *method = *findMethod;
    return method;
}
#endif // HITLS_CRYPTO_MD_MB

int32_t EAL_Md(CRYPT_MD_AlgId id, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
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
    const EAL_MdMethod *method = EAL_MdFindMethod(id);
    if (method == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

    void *data = method->newCtx();
    if (data == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = method->init(data, NULL);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, ret);
        goto EXIT;
    }
    if (inLen != 0) {
        ret = method->update(data, in, inLen);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, ret);
            goto EXIT;
        }
    }

    ret = method->final(data, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, id, ret);
        goto EXIT;
    }
    *outLen = method->mdSize;

EXIT:
    method->freeCtx(data);
    return ret;
}
#endif
