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
#include "securec.h"
#include "bsl_sal.h"

typedef struct {
    const char *bobD;
    const char *bobX;
    const char *bobY;
    const char *aliceD;
    const char *aliceX;
    const char *aliceY;
    const char *shareKey;
    int32_t curveId;
    CRYPT_MD_AlgId mdId;
} CMVP_EcdhVector;

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/keymgmt/KASTestVectorsECC2016.zip
static const CMVP_EcdhVector ECDH_VECTOR = {
    .bobD = "d58751997b3a551ccdc6f507bf6ab87e2be7f8267067a455a5815a54",
    .bobX = "c7893ced15c3009b93cb0abeaea2ede308b67fbbd902c6c5d94c24a4",
    .bobY = "858afc2edd61fcefef3469dd5a004e74a3c727d16498a9408a8e3224",
    .aliceD = "e935434303d842605d07112b3b7789ccbe4c6d987db5fa15ea1cdadb",
    .aliceX = "784028a2246950401ec81f8e4e03fd3765c4da4d45eba652ed5ba2b5",
    .aliceY = "d071c32634bcf058f072493b6943453a0bd117f5ee5c5866f037f6ab",
    .shareKey = "dfd0570d4ae5c9f690c757aead04f7e14758fdc4ee05d8f0d089b91a",
    .curveId = CRYPT_ECC_NISTP224,
    .mdId = CRYPT_MD_SHA224
};

static bool GetPkey(void *libCtx, const char *attrName, bool isBob, CRYPT_EAL_PkeyCtx **pkeyPrv,
    CRYPT_EAL_PkeyCtx **pkeyPub, CRYPT_EAL_PkeyPub *pub, CRYPT_EAL_PkeyPrv *prv)
{
    bool ret = false;
    uint8_t *x = NULL;
    uint8_t *y = NULL;
    uint32_t xLen, yLen;

    *pkeyPrv = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, 0, attrName);
    GOTO_ERR_IF_TRUE(*pkeyPrv == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    *pkeyPub = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, 0, attrName);
    GOTO_ERR_IF_TRUE(*pkeyPub == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    prv->id = CRYPT_PKEY_ECDH;
    if (isBob == true) {
        prv->key.eccPrv.data = CMVP_StringsToBins(ECDH_VECTOR.bobD, &(prv->key.eccPrv.len));
    } else {
        prv->key.eccPrv.data = CMVP_StringsToBins(ECDH_VECTOR.aliceD, &(prv->key.eccPrv.len));
    }
    GOTO_ERR_IF_TRUE(prv->key.eccPrv.data == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetParaById(*pkeyPrv, ECDH_VECTOR.curveId) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(*pkeyPrv, prv) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    pub->id = CRYPT_PKEY_ECDH;
    if (isBob == true) {
        x = CMVP_StringsToBins(ECDH_VECTOR.bobX, &xLen);
        y = CMVP_StringsToBins(ECDH_VECTOR.bobY, &yLen);
    } else {
        x = CMVP_StringsToBins(ECDH_VECTOR.aliceX, &xLen);
        y = CMVP_StringsToBins(ECDH_VECTOR.aliceY, &yLen);
    }
    GOTO_ERR_IF_TRUE(x == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(y == NULL, CRYPT_CMVP_COMMON_ERR);
    pub->key.eccPub.len = xLen + yLen + 1;
    pub->key.eccPub.data = BSL_SAL_Malloc(pub->key.eccPub.len);
    GOTO_ERR_IF_TRUE(pub->key.eccPub.data == NULL, CRYPT_MEM_ALLOC_FAIL);
    pub->key.eccPub.data[0] = 0x04; // CRYPT_POINT_UNCOMPRESSED标记头
    GOTO_ERR_IF_TRUE(memcpy_s(pub->key.eccPub.data + 1, pub->key.eccPub.len, x, xLen) != EOK, CRYPT_SECUREC_FAIL);
    GOTO_ERR_IF_TRUE(
        memcpy_s(pub->key.eccPub.data + 1 + xLen, pub->key.eccPub.len, y, yLen) != EOK, CRYPT_SECUREC_FAIL);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetParaById(*pkeyPub, ECDH_VECTOR.curveId) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(*pkeyPub, pub) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_FREE(x);
    BSL_SAL_FREE(y);
    return ret;
}

static bool CRYPT_CMVP_SelftestEcdhInternal(void *libCtx, const char *attrName)
{
    bool ret = false;
    CRYPT_EAL_PkeyCtx *bobPrvPkey = NULL;
    CRYPT_EAL_PkeyCtx *bobPubPkey = NULL;
    CRYPT_EAL_PkeyPub bobPub = { 0 };
    CRYPT_EAL_PkeyPrv bobPrv = { 0 };
    CRYPT_EAL_PkeyCtx *alicePrvPkey = NULL;
    CRYPT_EAL_PkeyCtx *alicePubPkey = NULL;
    CRYPT_EAL_PkeyPub alicePub = { 0 };
    CRYPT_EAL_PkeyPrv alicePrv = { 0 };
    uint8_t *shareKey = NULL;
    uint32_t shareKeyLen;
    uint8_t *expShareKey = NULL;
    uint32_t expShareKeyLen;

    expShareKey = CMVP_StringsToBins(ECDH_VECTOR.shareKey, &expShareKeyLen);
    GOTO_ERR_IF_TRUE(expShareKey == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(GetPkey(libCtx, attrName, true, &bobPrvPkey, &bobPubPkey, &bobPub, &bobPrv) != true,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(GetPkey(libCtx, attrName, false, &alicePrvPkey, &alicePubPkey, &alicePub, &alicePrv) != true,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    shareKeyLen = CRYPT_EAL_PkeyGetKeyLen(bobPrvPkey);
    shareKey = BSL_SAL_Malloc(shareKeyLen);
    GOTO_ERR_IF_TRUE(shareKey == NULL, CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyComputeShareKey(bobPrvPkey, alicePubPkey, shareKey, &shareKeyLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(shareKeyLen != expShareKeyLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(expShareKey, shareKey, shareKeyLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    shareKeyLen = CRYPT_EAL_PkeyGetKeyLen(bobPrvPkey);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyComputeShareKey(alicePrvPkey, bobPubPkey, shareKey, &shareKeyLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(shareKeyLen != expShareKeyLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(expShareKey, shareKey, shareKeyLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_Free(bobPub.key.eccPub.data);
    BSL_SAL_Free(bobPrv.key.eccPrv.data);
    CRYPT_EAL_PkeyFreeCtx(bobPrvPkey);
    CRYPT_EAL_PkeyFreeCtx(bobPubPkey);
    BSL_SAL_Free(alicePub.key.eccPub.data);
    BSL_SAL_Free(alicePrv.key.eccPrv.data);
    CRYPT_EAL_PkeyFreeCtx(alicePrvPkey);
    CRYPT_EAL_PkeyFreeCtx(alicePubPkey);
    BSL_SAL_Free(shareKey);
    BSL_SAL_Free(expShareKey);
    return ret;
}

bool CRYPT_CMVP_SelftestEcdh(void)
{
    return CRYPT_CMVP_SelftestEcdhInternal(NULL, NULL);
}

bool CRYPT_CMVP_SelftestProviderEcdh(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestEcdhInternal(libCtx, attrName);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */
