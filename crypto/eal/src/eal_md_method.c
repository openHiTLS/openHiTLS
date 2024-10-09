/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

#define CRYPT_MD_IMPL_METHOD_DECLARE(name)     \
    EAL_MdMethod g_mdMethod_##name = {         \
        CRYPT_##name##_BLOCKSIZE,         CRYPT_##name##_DIGESTSIZE,         \
        sizeof(CRYPT_##name##_Ctx),       (MdInit)CRYPT_##name##_Init,       \
        (MdUpdate)CRYPT_##name##_Update,  (MdFinal)CRYPT_##name##_Final,     \
        (MdDeinit)CRYPT_##name##_Deinit,  (MdCopyCtx)CRYPT_##name##_CopyCtx  \
    }

#ifdef HITLS_CRYPTO_MD5
CRYPT_MD_IMPL_METHOD_DECLARE(MD5);
#endif
#ifdef HITLS_CRYPTO_SHA1
CRYPT_MD_IMPL_METHOD_DECLARE(SHA1);
#endif
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
#ifdef HITLS_CRYPTO_SHA3
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_224);
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_256);
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_384);
CRYPT_MD_IMPL_METHOD_DECLARE(SHA3_512);
CRYPT_MD_IMPL_METHOD_DECLARE(SHAKE128);
CRYPT_MD_IMPL_METHOD_DECLARE(SHAKE256);
#endif
#ifdef HITLS_CRYPTO_SM3
CRYPT_MD_IMPL_METHOD_DECLARE(SM3);
#endif

static const EAL_CidToMdMeth ID_TO_MD_METH_TABLE[] = {
    {CRYPT_MD_MD4,      NULL},
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
    {CRYPT_MD_MAX,      NULL}
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
#endif
