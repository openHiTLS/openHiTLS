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
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_SM) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <string.h>
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_md.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_sal.h"

typedef struct {
    uint32_t id;
    const char *msg;
    const char *md;
} CMVP_HASH_VECTOR;

static const CMVP_HASH_VECTOR HASH_VECTOR[] = {
    // CRYPT_MD_MD5
    {
        .id = CRYPT_MD_MD5,
        .msg = NULL,
        .md = NULL
    },
    // CRYPT_MD_SHA1
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHA1,
        .msg = "7e3d7b3eada98866",
        .md = "24a2c34b976305277ce58c2f42d5092031572520"
    },
    // CRYPT_MD_SHA224
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHA224,
        .msg = "5f77b3664823c33e",
        .md = "bdf21ff325f754157ccf417f4855360a72e8fd117d28c8fe7da3ea38"
    },
    // CRYPT_MD_SHA256
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHA256,
        .msg = "5738c929c4f4ccb6",
        .md = "963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf"
    },
    // CRYPT_MD_SHA384
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHA384,
        .msg = "de60275bdafce4b1",
        .md = "a3d861d866c1362423eb21c6bec8e44b74ce993c55baa2b6640567560ebecdaeda07183dbbbd95e0"
            "f522caee5ddbdaf0"
    },
    // CRYPT_MD_SHA512
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHA512,
        .msg = "6f8d58b7cab1888c",
        .md = "a3941def2803c8dfc08f20c06ba7e9a332ae0c67e47ae57365c243ef40059b11be22c91da6a80c2c"
            "ff0742a8f4bcd941bdee0b861ec872b215433ce8dcf3c031"
    },
    // CRYPT_MD_SHA3_224
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHA3_224,
        .msg = "d85e470a7c6988",
        .md = "8a134c33c7abd673cd3d0c33956700760de980c5aee74c96e6ba08b2"
    },
    // CRYPT_MD_SHA3_256
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHA3_256,
        .msg = "8bca931c8a132d2f",
        .md = "dbb8be5dec1d715bd117b24566dc3f24f2cc0c799795d0638d9537481ef1e03e"
    },
    // CRYPT_MD_SHA3_384
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHA3_384,
        .msg = "c44a2c58c84c393a",
        .md = "60ad40f964d0edcf19281e415f7389968275ff613199a069c916a0ff7ef65503b740683162a622b913d43a46559e913c"
    },
    // CRYPT_MD_SHA3_512
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHA3_512,
        .msg = "af53fa3ff8a3cfb2",
        .md = "03c2ac02de1765497a0a6af466fb64758e3283ed83d02c0edb3904fd3cf296442e790018d4bf4ce55bc869"
            "cebb4aa1a799afc9d987e776fef5dfe6628e24de97"
    },
    // CRYPT_MD_SHAKE128
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHAKE128,
        .msg = "7bf2fef375bcaff3",
        .md = "5ef5578b89c50532131b7843de7329a3"
    },
    // CRYPT_MD_SHAKE256
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
    {
        .id = CRYPT_MD_SHAKE256,
        .msg = "587cb398fe82ffda",
        .md = "54f5dddb85f62dba7dc4727d502bdee959fb665bd482bd0ce31cbdd1a042e4b5"
    },
    // CRYPT_MD_SM3
    {
        .id = CRYPT_MD_SM3,
        .msg = "616263",
        .md = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    },
    {
        .id = CRYPT_MD_MAX,
        .msg = NULL,
        .md = NULL
    }
};

static void FreeData(uint8_t *msg, uint8_t *md, uint8_t *expectMd)
{
    BSL_SAL_Free(msg);
    BSL_SAL_Free(md);
    BSL_SAL_Free(expectMd);
}

const CMVP_HASH_VECTOR *FindVectorById(CRYPT_MD_AlgId id)
{
    const CMVP_HASH_VECTOR *pHashVec = NULL;
    uint32_t num = sizeof(HASH_VECTOR) / sizeof(HASH_VECTOR[0]);

    for (uint32_t i = 0; i < num; i++) {
        if (HASH_VECTOR[i].id == id) {
            pHashVec = &HASH_VECTOR[i];
            return pHashVec;
        }
    }

    return NULL;
}

static bool CRYPT_CMVP_SelftestMdInternal(void *libCtx, const char *attrName, CRYPT_MD_AlgId id)
{
    bool ret = false;
    uint8_t *msg = NULL;
    uint8_t *md = NULL;
    uint8_t *expectMd = NULL;
    uint32_t msgLen, mdLen, expectMdLen;
    CRYPT_EAL_MdCTX *ctx = NULL;

    const CMVP_HASH_VECTOR *hashVec = FindVectorById(id);
    if (hashVec == NULL || hashVec->msg == NULL) {
        return false;
    }

    msg = CMVP_StringsToBins(hashVec->msg, &msgLen);
    GOTO_ERR_IF_TRUE(msg == NULL, CRYPT_CMVP_COMMON_ERR);
    expectMd = CMVP_StringsToBins(hashVec->md, &expectMdLen);
    GOTO_ERR_IF_TRUE(expectMd == NULL, CRYPT_CMVP_COMMON_ERR);

    ctx = CRYPT_EAL_ProviderMdNewCtx(libCtx, id, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    if (id == CRYPT_MD_SHAKE128 || id == CRYPT_MD_SHAKE256) {
        mdLen = expectMdLen;
    } else {
        mdLen = CRYPT_EAL_MdGetDigestSize(id);
    }
    md = BSL_SAL_Malloc(mdLen);
    GOTO_ERR_IF_TRUE(md == NULL, CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_MdInit(ctx) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_MdUpdate(ctx, msg, msgLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_MdFinal(ctx, md, &mdLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(mdLen != expectMdLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(expectMd, md, mdLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret =  true;
ERR:
    FreeData(msg, md, expectMd);
    CRYPT_EAL_MdFreeCtx(ctx);
    return ret;
}

bool CRYPT_CMVP_SelftestMd(CRYPT_MD_AlgId id)
{
    return CRYPT_CMVP_SelftestMdInternal(NULL, NULL, id);
}

bool CRYPT_CMVP_SelftestProviderMd(void *libCtx, const char *attrName, CRYPT_MD_AlgId id)
{
    return CRYPT_CMVP_SelftestMdInternal(libCtx, attrName, id);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */
