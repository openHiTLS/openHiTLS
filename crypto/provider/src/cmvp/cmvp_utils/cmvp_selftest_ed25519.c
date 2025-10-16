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
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <string.h>
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_sal.h"

typedef struct {
    const char *prv;
    const char *pub;
    const char *msg;
    const char *sign;
    CRYPT_MD_AlgId mdId;
} CMVP_ED25519_VECTOR;

// https://datatracker.ietf.org/doc/html/rfc8032.html#page-24
static const CMVP_ED25519_VECTOR ED25519_VECTOR = {
    .prv = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    .pub = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    .msg = "72",
    .sign = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e"
        "458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    .mdId = CRYPT_MD_SHA512
};

static void FreeData(uint8_t *prv, uint8_t *pub, uint8_t *msg, uint8_t *expSign, uint8_t *sign)
{
    BSL_SAL_Free(prv);
    BSL_SAL_Free(pub);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(expSign);
    BSL_SAL_Free(sign);
}

static bool CRYPT_CMVP_SelftestEd25519Internal(void *libCtx, const char *attrName)
{
    bool ret = false;
    uint8_t *prv = NULL;
    uint8_t *pub = NULL;
    uint8_t *msg = NULL;
    uint8_t *expSign = NULL;
    uint8_t *sign = NULL;
    uint32_t prvLen, pubLen, msgLen, expSignLen, signLen;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyPrv prvKey = {0};
    CRYPT_EAL_PkeyPub pubKey;

    prv = CMVP_StringsToBins(ED25519_VECTOR.prv, &prvLen);
    GOTO_ERR_IF_TRUE(prv == NULL, CRYPT_CMVP_COMMON_ERR);
    pub = CMVP_StringsToBins(ED25519_VECTOR.pub, &pubLen);
    GOTO_ERR_IF_TRUE(pub == NULL, CRYPT_CMVP_COMMON_ERR);
    msg = CMVP_StringsToBins(ED25519_VECTOR.msg, &msgLen);
    GOTO_ERR_IF_TRUE(msg == NULL, CRYPT_CMVP_COMMON_ERR);
    expSign = CMVP_StringsToBins(ED25519_VECTOR.sign, &expSignLen);
    GOTO_ERR_IF_TRUE(expSign == NULL, CRYPT_CMVP_COMMON_ERR);
    signLen = expSignLen;
    sign = BSL_SAL_Malloc(signLen);
    GOTO_ERR_IF_TRUE(sign == NULL, CRYPT_MEM_ALLOC_FAIL);

    prvKey.id = CRYPT_PKEY_ED25519;
    prvKey.key.curve25519Prv.data = prv;
    prvKey.key.curve25519Prv.len = prvLen;
    prvCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ED25519, 0, attrName);
    GOTO_ERR_IF_TRUE(prvCtx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(prvCtx, &prvKey) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySign(prvCtx, ED25519_VECTOR.mdId, msg, msgLen, sign, &signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(signLen != expSignLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(expSign, sign, signLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    pubKey.id = CRYPT_PKEY_ED25519;
    pubKey.key.curve25519Pub.data = pub;
    pubKey.key.curve25519Pub.len = pubLen;
    pubCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ED25519, 0, attrName);
    GOTO_ERR_IF_TRUE(pubCtx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(pubCtx, &pubKey) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyVerify(pubCtx, ED25519_VECTOR.mdId, msg, msgLen, sign, signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret =  true;
ERR:
    FreeData(prv, pub, msg, expSign, sign);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    return ret;
}

bool CRYPT_CMVP_SelftestEd25519(void)
{
    return CRYPT_CMVP_SelftestEd25519Internal(NULL, NULL);
}

bool CRYPT_CMVP_SelftestProviderEd25519(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestEd25519Internal(libCtx, attrName);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */
