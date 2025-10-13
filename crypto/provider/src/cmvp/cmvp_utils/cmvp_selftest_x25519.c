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
    const char *alicePri;
    const char *alicePub;
    const char *bobPri;
    const char *bobPub;
    const char *share1;
} CMVP_X25519_VECTOR;

// https://datatracker.ietf.org/doc/html/rfc7748.html#page-14
static const CMVP_X25519_VECTOR X25519_VECTOR = {
    .alicePri = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    .alicePub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    .bobPri = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    .bobPub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    .share1 = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
};

static bool GetData(CRYPT_Data *expShare, CRYPT_Data *share1, CRYPT_Data *share2)
{
    expShare->data = CMVP_StringsToBins(X25519_VECTOR.share1, &(expShare->len));
    GOTO_ERR_IF_TRUE(expShare->data == NULL, CRYPT_CMVP_COMMON_ERR);
    share1->len = expShare->len;
    share1->data = BSL_SAL_Malloc(share1->len);
    GOTO_ERR_IF_TRUE(share1->data == NULL, CRYPT_MEM_ALLOC_FAIL);
    share2->len = expShare->len;
    share2->data = BSL_SAL_Malloc(share2->len);
    GOTO_ERR_IF_TRUE(share2->data == NULL, CRYPT_MEM_ALLOC_FAIL);
    return true;
ERR:
    return false;
}

static bool GetKey(CRYPT_EAL_PkeyPrv *alicePri, CRYPT_EAL_PkeyPub *alicePub, CRYPT_EAL_PkeyPrv *bobPri,
    CRYPT_EAL_PkeyPub *bobPub)
{
    alicePri->id = CRYPT_PKEY_X25519;
    alicePri->key.curve25519Prv.data = CMVP_StringsToBins(X25519_VECTOR.alicePri, &(alicePri->key.curve25519Prv.len));
    GOTO_ERR_IF_TRUE(alicePri->key.curve25519Prv.data == NULL, CRYPT_CMVP_COMMON_ERR);

    alicePub->id = CRYPT_PKEY_X25519;
    alicePub->key.curve25519Pub.data = CMVP_StringsToBins(X25519_VECTOR.alicePub, &(alicePub->key.curve25519Pub.len));
    GOTO_ERR_IF_TRUE(alicePub->key.curve25519Pub.data == NULL, CRYPT_CMVP_COMMON_ERR);

    bobPri->id = CRYPT_PKEY_X25519;
    bobPri->key.curve25519Prv.data = CMVP_StringsToBins(X25519_VECTOR.bobPri, &(bobPri->key.curve25519Prv.len));
    GOTO_ERR_IF_TRUE(bobPri->key.curve25519Prv.data == NULL, CRYPT_CMVP_COMMON_ERR);

    bobPub->id = CRYPT_PKEY_X25519;
    bobPub->key.curve25519Pub.data = CMVP_StringsToBins(X25519_VECTOR.bobPub, &(bobPub->key.curve25519Pub.len));
    GOTO_ERR_IF_TRUE(bobPub->key.curve25519Pub.data == NULL, CRYPT_CMVP_COMMON_ERR);
    return true;
ERR:
    return false;
}

static bool CRYPT_CMVP_SelftestX25519Internal(void *libCtx, const char *attrName)
{
    bool ret = false;
    CRYPT_Data expShare = { NULL, 0 };
    CRYPT_Data share1 = { NULL, 0 };
    CRYPT_Data share2 = { NULL, 0 };
    CRYPT_EAL_PkeyCtx *alice = NULL;
    CRYPT_EAL_PkeyCtx *bob = NULL;
    CRYPT_EAL_PkeyPrv alicePri = {0};
    alicePri.key.curve25519Prv.data = NULL;
    CRYPT_EAL_PkeyPub alicePub;
    alicePub.key.curve25519Pub.data = NULL;
    CRYPT_EAL_PkeyPrv bobPri = {0};
    bobPri.key.curve25519Prv.data = NULL;
    CRYPT_EAL_PkeyPub bobPub;
    bobPub.key.curve25519Pub.data = NULL;

    alice = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_X25519, 0, attrName);
    GOTO_ERR_IF_TRUE(alice == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    bob = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_X25519, 0, attrName);
    GOTO_ERR_IF_TRUE(bob == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(GetKey(&alicePri, &alicePub, &bobPri, &bobPub) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(GetData(&expShare, &share1, &share2) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(alice, &alicePri) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(bob, &bobPub) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyComputeShareKey(alice, bob, share1.data, &(share1.len)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(share1.len != expShare.len, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(share1.data, expShare.data, expShare.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(bob, &bobPri) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(alice, &alicePub) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyComputeShareKey(bob, alice, share2.data, &(share2.len)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(share2.len != expShare.len, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(share2.data, expShare.data, expShare.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_Free(alicePri.key.curve25519Prv.data);
    BSL_SAL_Free(alicePub.key.curve25519Pub.data);
    BSL_SAL_Free(bobPri.key.curve25519Prv.data);
    BSL_SAL_Free(bobPub.key.curve25519Pub.data);
    BSL_SAL_Free(expShare.data);
    BSL_SAL_Free(share1.data);
    BSL_SAL_Free(share2.data);
    CRYPT_EAL_PkeyFreeCtx(alice);
    CRYPT_EAL_PkeyFreeCtx(bob);
    return ret;
}

bool CRYPT_CMVP_SelftestX25519(void)
{
    return CRYPT_CMVP_SelftestX25519Internal(NULL, NULL);
}

bool CRYPT_CMVP_SelftestProviderX25519(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestX25519Internal(libCtx, attrName);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */
