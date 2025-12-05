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
#include "crypt_bn.h"
#include "crypt_encode.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_util_rand.h"
#include "securec.h"
#include "bsl_sal.h"

#define BITS_OF_BYTE 8

typedef struct {
    const char *msg;
    const char *d;
    const char *qX;
    const char *qY;
    const char *k;
    const char *signR;
    const char *signS;
    int32_t curveId;
    CRYPT_MD_AlgId mdId;
} CMVP_EcdsaVector;

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip
static const CMVP_EcdsaVector ECDSA_VECTOR = {
    .msg = "ff624d0ba02c7b6370c1622eec3fa2186ea681d1659e0a845448e777b75a8e77"
        "a77bb26e5733179d58ef9bc8a4e8b6971aef2539f77ab0963a3415bbd6258339"
        "bd1bf55de65db520c63f5b8eab3d55debd05e9494212170f5d65b3286b8b6687"
        "05b1e2b2b5568610617abb51d2dd0cb450ef59df4b907da90cfa7b268de8c4c2",
    .d = "708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590",
    .qX = "29578c7ab6ce0d11493c95d5ea05d299d536801ca9cbd50e9924e43b733b83ab",
    .qY = "08c8049879c6278b2273348474158515accaa38344106ef96803c5a05adc4800",
    .k = "58f741771620bdc428e91a32d86d230873e9140336fcfb1e122892ee1d501bdc",
    .signR = "4a19274429e40522234b8785dc25fc524f179dcc95ff09b3c9770fc71f54ca0d",
    .signS = "58982b79a65b7320f5b92d13bdaecdd1259e760f0f718ba933fd098f6f75d4b7",
    .curveId = CRYPT_ECC_NISTP256,
    .mdId = CRYPT_MD_SHA224
};

static bool GetPkey(void *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx **pkeyPrv, CRYPT_EAL_PkeyCtx **pkeyPub,
    CRYPT_EAL_PkeyPub *pub, CRYPT_EAL_PkeyPrv *prv)
{
    bool ret = false;
    uint8_t *x = NULL;
    uint8_t *y = NULL;
    uint32_t xLen, yLen;

    *pkeyPrv = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDSA, 0, attrName);
    GOTO_ERR_IF_TRUE(*pkeyPrv == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    *pkeyPub = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDSA, 0, attrName);
    GOTO_ERR_IF_TRUE(*pkeyPub == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    prv->id = CRYPT_PKEY_ECDSA;
    prv->key.eccPrv.data = CMVP_StringsToBins(ECDSA_VECTOR.d, &(prv->key.eccPrv.len));
    GOTO_ERR_IF_TRUE(prv->key.eccPrv.data == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetParaById(*pkeyPrv, ECDSA_VECTOR.curveId) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(*pkeyPrv, prv) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    pub->id = CRYPT_PKEY_ECDSA;
    x = CMVP_StringsToBins(ECDSA_VECTOR.qX, &xLen);
    GOTO_ERR_IF_TRUE(x == NULL, CRYPT_CMVP_COMMON_ERR);
    y = CMVP_StringsToBins(ECDSA_VECTOR.qY, &yLen);
    GOTO_ERR_IF_TRUE(y == NULL, CRYPT_CMVP_COMMON_ERR);
    pub->key.eccPub.len = xLen + yLen + 1;
    pub->key.eccPub.data = BSL_SAL_Malloc(pub->key.eccPub.len);
    GOTO_ERR_IF_TRUE(pub->key.eccPub.data == NULL, CRYPT_MEM_ALLOC_FAIL);
    pub->key.eccPub.data[0] = 0x04; // CRYPT_POINT_UNCOMPRESSED标记头
    GOTO_ERR_IF_TRUE(memcpy_s(pub->key.eccPub.data + 1, pub->key.eccPub.len, x, xLen) != EOK, CRYPT_SECUREC_FAIL);
    GOTO_ERR_IF_TRUE(
        memcpy_s(pub->key.eccPub.data + 1 + xLen, pub->key.eccPub.len, y, yLen) != EOK, CRYPT_SECUREC_FAIL);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetParaById(*pkeyPub, ECDSA_VECTOR.curveId) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(*pkeyPub, pub) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_Free(x);
    BSL_SAL_Free(y);
    return ret;
}

static int32_t TestVectorRandom(uint8_t *r, uint32_t rLen)
{
    uint8_t *rand = NULL;
    uint32_t randLen;

    rand = CMVP_StringsToBins(ECDSA_VECTOR.k, &randLen);
    if (rand == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (randLen < rLen) {
        BSL_SAL_Free(rand);
        return CRYPT_CMVP_ERR_ALGO_SELFTEST;
    }

    for (uint32_t i = 0; i < randLen; i++) {
        r[i] = rand[i];
    }
    BSL_SAL_Free(rand);
    return 0;
}

static int SignEncode(const char *signR, const char *signS, uint8_t *vectorSign, uint32_t *vectorSignLen)
{
    int ret = CRYPT_CMVP_ERR_ALGO_SELFTEST;
    BN_BigNum *bnR = NULL;
    BN_BigNum *bnS = NULL;

    uint8_t *r = NULL;
    uint8_t *s = NULL;
    uint32_t rLen, sLen;

    r = CMVP_StringsToBins(signR, &rLen);
    GOTO_ERR_IF_TRUE(r == NULL, CRYPT_CMVP_COMMON_ERR);
    s = CMVP_StringsToBins(signS, &sLen);
    GOTO_ERR_IF_TRUE(s == NULL, CRYPT_CMVP_COMMON_ERR);

    bnR = BN_Create(rLen * BITS_OF_BYTE);
    bnS = BN_Create(sLen * BITS_OF_BYTE);
    GOTO_ERR_IF_TRUE(BN_Bin2Bn(bnR, r, rLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(BN_Bin2Bn(bnS, s, sLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = CRYPT_EAL_EncodeSign(bnR, bnS, vectorSign, vectorSignLen);
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_Free(r);
    BSL_SAL_Free(s);
    BN_Destroy(bnR);
    BN_Destroy(bnS);
    return ret;
}

static bool CRYPT_CMVP_SelftestEcdsaInternal(void *libCtx, const char *attrName)
{
    bool ret = false;
    uint8_t *sign = NULL;
    uint8_t *signVec = NULL;
    uint32_t signLen;
    uint32_t signVecLen = 0;
    uint8_t *msg = NULL;
    uint32_t msgLen;
    CRYPT_EAL_PkeyCtx *pkeyPrv = NULL;
    CRYPT_EAL_PkeyCtx *pkeyPub = NULL;
    CRYPT_EAL_PkeyPub pub = { 0 };
    CRYPT_EAL_PkeyPrv prv = { 0 };
    CRYPT_EAL_RandFunc func = CRYPT_RandRegistGet();
    CRYPT_EAL_RandFuncEx funcEx = CRYPT_RandRegistExGet();
    CRYPT_RandRegistEx(NULL);

    msg = CMVP_StringsToBins(ECDSA_VECTOR.msg, &msgLen);
    GOTO_ERR_IF_TRUE(msg == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(GetPkey(libCtx, attrName, &pkeyPrv, &pkeyPub, &pub, &prv) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyPrv);
    sign = BSL_SAL_Malloc(signLen);
    signVecLen = signLen;
    GOTO_ERR_IF_TRUE(sign == NULL, CRYPT_MEM_ALLOC_FAIL);
    signVec = BSL_SAL_Malloc(signLen);
    GOTO_ERR_IF_TRUE(signVec == NULL, CRYPT_MEM_ALLOC_FAIL);

    // regist rand function
    CRYPT_RandRegist(TestVectorRandom);
    // sign
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySign(pkeyPrv, ECDSA_VECTOR.mdId, msg, msgLen, sign, &signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    // compare the signature
    GOTO_ERR_IF_TRUE(SignEncode(ECDSA_VECTOR.signR, ECDSA_VECTOR.signS, signVec, &signVecLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(signLen != signVecLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(signVec, sign, signLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    // verify
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyVerify(pkeyPub, ECDSA_VECTOR.mdId, msg, msgLen, sign, signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_Free(pub.key.eccPub.data);
    BSL_SAL_Free(prv.key.eccPrv.data);
    BSL_SAL_Free(sign);
    BSL_SAL_Free(signVec);
    BSL_SAL_Free(msg);
    CRYPT_EAL_PkeyFreeCtx(pkeyPrv);
    CRYPT_EAL_PkeyFreeCtx(pkeyPub);
    CRYPT_RandRegist(func);
    CRYPT_RandRegistEx(funcEx);
    return ret;
}

bool CRYPT_CMVP_SelftestEcdsa(void)
{
    return CRYPT_CMVP_SelftestEcdsaInternal(NULL, NULL);
}

bool CRYPT_CMVP_SelftestProviderEcdsa(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestEcdsaInternal(libCtx, attrName);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */
