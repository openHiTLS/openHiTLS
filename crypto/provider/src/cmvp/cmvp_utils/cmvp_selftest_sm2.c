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

#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_SM) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <string.h>
#include "securec.h"
#include "crypt_bn.h"
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_bn.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "crypt_eal_rand.h"
#include "crypt_encode_internal.h"
#include "crypt_util_rand.h"

#define BITS_OF_BYTE 8
#define MAX_PLAIN_TEXT_LEN 19
#define CIPHER_TEXT_EXTRA_LEN 108

#define SM3_MD_SIZE 32
#define SM2_POINT_SINGLE_COORDINATE_LEN 32
#define SM2_POINT_COORDINATE_LEN 65

const char *consistestdata = "01020304050607080910";
typedef struct {
    const char *d;
    const char *qX;
    const char *qY;
} CMVP_SM2_KEYS;

static const CMVP_SM2_KEYS SM2_TEST_KEYS = {
    .d = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8",
    .qX = "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020",
    .qY = "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
};

typedef struct {
    const char *plain;
    const char *cipher;
    const char *k;
    int32_t curveId;
    CRYPT_MD_AlgId mdId;
} CMVP_SM2CryptVector;

static const CMVP_SM2CryptVector SM2_CRYPT_TEST_VECTOR = {
    .plain = "656e6372797074696f6e207374616e64617264",
    .k = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21",
    .cipher = "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df059983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd876621886ca989ca9c7d58087307ca93092d651efa",
};

typedef struct {
    const char *msg;
    const char *k;
    const char *signR;
    const char *signS;
    const char *userid;
    int32_t curveId;
    CRYPT_MD_AlgId mdId;
} CMVP_SM2SignVector;

static const CMVP_SM2SignVector SM2DSA_VECTOR = {
    .msg = "6d65737361676520646967657374",
    .k = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21",
    .signR = "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3",
    .signS = "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa",
    .userid = "31323334353637383132333435363738",
    .curveId = CRYPT_ECC_SM2,
    .mdId = CRYPT_MD_SM3
};

typedef struct {
    const char *self_d;
    const char *self_x;
    const char *self_y;
    const char *peer_d;
    const char *peer_x;
    const char *peer_y;
    const char *r;
    const char *R;
    const char *sharekey;
    const char *userid1;
    const char *userid2;
    int32_t server;
} CMVP_SM2ExchangeVector;

static const CMVP_SM2ExchangeVector SM2Exchange_VECTOR = {
    .self_d = "81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029",
    .self_x = "160e12897df4edb61dd812feb96748fbd3ccf4ffe26aa6f6db9540af49c94232",
    .self_y = "4a7dad08bb9a459531694beb20aa489d6649975e1bfcf8c4741b78b4b223007f",
    .peer_d = "785129917d45a9ea5437a59356b82338eaadda6ceb199088f14ae10defa229b5",
    .peer_x = "6ae848c57c53c7b1b5fa99eb2286af078ba64c64591b8b566f7357d576f16dfb",
    .peer_y = "ee489d771621a27b36c5c7992062e9cd09a9264386f3fbea54dff69305621c4d",
    .r = "d4de15474db74d06491c440d305e012400990f3e390c7e87153c12db2ea60bb3",
    .R = "04acc27688a6f7b706098bc91ff3ad1bff7dc2802cdb14ccccdb0a90471f9bd7072fedac0494b2ffc4d6853876c79b8f301c6573ad0aa50f39fc87181e1a1b46fe",
    .sharekey = "6c89347354de2484c60b4ab1fde4c6e5",
    .userid1 = "31323334353637383132333435363738",
    .userid2 = "31323334353637383132333435363738",
};

static int32_t SetRandomVector(const char *vector, uint8_t *r, uint32_t rLen)
{
    uint8_t *rand = NULL;
    uint32_t randLen;

    rand = CMVP_StringsToBins(vector, &randLen);
    if (rand == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (randLen < rLen) {
        BSL_SAL_FREE(rand);
        return CRYPT_CMVP_ERR_ALGO_SELFTEST;
    }
    (void)memcpy_s(r, rLen, rand, rLen);
    BSL_SAL_FREE(rand);
    return CRYPT_SUCCESS;
}

static int32_t TestVectorRandom(uint8_t *r, uint32_t rLen)
{
    return SetRandomVector(SM2DSA_VECTOR.k, r, rLen);
}

static bool SetPrvPkey(CRYPT_EAL_PkeyCtx **pkeyPrv, const char qd[])
{
    bool ret = false;
    uint8_t *d = NULL;
    uint32_t dLen;

    CRYPT_EAL_PkeyPrv prv = {0};

    prv.id = CRYPT_PKEY_SM2;

    d = CMVP_StringsToBins(qd, &dLen);
    GOTO_ERR_IF_TRUE(d == NULL, CRYPT_CMVP_COMMON_ERR);

    prv.key.eccPrv.len = dLen;
    prv.key.eccPrv.data = BSL_SAL_Malloc(prv.key.eccPrv.len);
    GOTO_ERR_IF_TRUE(prv.key.eccPrv.data == NULL, CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_TRUE(memcpy_s(prv.key.eccPrv.data, prv.key.eccPrv.len, d, dLen) != EOK, CRYPT_SECUREC_FAIL);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(*pkeyPrv, &prv) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_FREE(prv.key.eccPrv.data);
    BSL_SAL_FREE(d);
    return ret;
}

static bool SetPubPkey(CRYPT_EAL_PkeyCtx **pkeyPub, const char qX[], const char qY[])
{
    bool ret = false;

    CRYPT_EAL_PkeyPub pub = {0};
    uint8_t *x = NULL;
    uint8_t *y = NULL;
    uint32_t xLen, yLen;

    pub.id = CRYPT_PKEY_SM2;

    x = CMVP_StringsToBins(qX, &xLen);
    GOTO_ERR_IF_TRUE(x == NULL, CRYPT_CMVP_COMMON_ERR);
    y = CMVP_StringsToBins(qY, &yLen);
    GOTO_ERR_IF_TRUE(y == NULL, CRYPT_CMVP_COMMON_ERR);
    pub.key.eccPub.len = xLen + yLen + 1;
    pub.key.eccPub.data = BSL_SAL_Malloc(pub.key.eccPub.len);
    GOTO_ERR_IF_TRUE(pub.key.eccPub.data == NULL, CRYPT_MEM_ALLOC_FAIL);
    pub.key.eccPub.data[0] = 0x04;
    GOTO_ERR_IF_TRUE(memcpy_s(pub.key.eccPub.data + 1, pub.key.eccPub.len, x, xLen) != EOK, CRYPT_SECUREC_FAIL);
    GOTO_ERR_IF_TRUE(memcpy_s(pub.key.eccPub.data + 1 + xLen, pub.key.eccPub.len, y, yLen) != EOK, CRYPT_SECUREC_FAIL);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(*pkeyPub, &pub) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_FREE(pub.key.eccPub.data);
    BSL_SAL_FREE(x);
    BSL_SAL_FREE(y);
    return ret;
}

bool CRYPT_CMVP_SelftestSM2Crypt(void *libCtx, const char *attrName)
{
    bool ret = false;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    uint8_t *plain = NULL;
    uint32_t plainLen;
    uint8_t *cipher = NULL;
    uint32_t cipherLen;

    uint8_t cipherText[MAX_PLAIN_TEXT_LEN + CIPHER_TEXT_EXTRA_LEN] = {0};
    uint32_t cipherTextLen = sizeof(cipherText);
    uint8_t decodeText[MAX_PLAIN_TEXT_LEN + CIPHER_TEXT_EXTRA_LEN] = {0};
    uint32_t decodeoutLen = sizeof(decodeText);

    uint8_t plainText[MAX_PLAIN_TEXT_LEN] = {0};
    uint32_t plainTextLen = sizeof(plainText);
    uint8_t encodeText[MAX_PLAIN_TEXT_LEN + CIPHER_TEXT_EXTRA_LEN] = {0};
    uint32_t encodeTextLen = sizeof(encodeText);
    CRYPT_EAL_RandFunc func = CRYPT_RandRegistGet();
    CRYPT_EAL_RandFuncEx funcEx = CRYPT_RandRegistExGet();
    CRYPT_RandRegistEx(NULL);

    pubCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_SM2, 0, attrName);
    GOTO_ERR_IF_TRUE(pubCtx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    prvCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_SM2, 0, attrName);
    GOTO_ERR_IF_TRUE(prvCtx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    SetPrvPkey(&prvCtx, SM2_TEST_KEYS.d);
    SetPubPkey(&pubCtx, SM2_TEST_KEYS.qX, SM2_TEST_KEYS.qY);

    plain = CMVP_StringsToBins(SM2_CRYPT_TEST_VECTOR.plain, &plainLen);
    GOTO_ERR_IF_TRUE(plain == NULL, CRYPT_CMVP_COMMON_ERR);
    cipher = CMVP_StringsToBins(SM2_CRYPT_TEST_VECTOR.cipher, &cipherLen);
    GOTO_ERR_IF_TRUE(cipher == NULL, CRYPT_CMVP_COMMON_ERR);

    CRYPT_RandRegist(TestVectorRandom);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyEncrypt(pubCtx, plain, plainLen, cipherText, &cipherTextLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    CRYPT_SM2_EncryptData data = {
        .x = decodeText + 1,
        .xLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .y = decodeText + SM2_POINT_SINGLE_COORDINATE_LEN + 1,
        .yLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .hash = decodeText + SM2_POINT_COORDINATE_LEN,
        .hashLen = SM3_MD_SIZE,
        .cipher = decodeText + SM2_POINT_COORDINATE_LEN + SM3_MD_SIZE,
        .cipherLen = decodeoutLen - SM2_POINT_COORDINATE_LEN - SM3_MD_SIZE
    };
    GOTO_ERR_IF_TRUE(CRYPT_EAL_DecodeSm2EncryptData(cipherText, cipherTextLen, &data) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    decodeText[0] = 0x04;
    decodeoutLen = SM2_POINT_SINGLE_COORDINATE_LEN + SM2_POINT_SINGLE_COORDINATE_LEN + SM3_MD_SIZE + data.cipherLen;
    GOTO_ERR_IF_TRUE(decodeoutLen + 1 != cipherLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(decodeText, cipher, cipherLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_EncodeSm2EncryptData(&data, encodeText, &encodeTextLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(
        CRYPT_EAL_PkeyDecrypt(prvCtx, encodeText, encodeTextLen, plainText, &plainTextLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(plainTextLen != plainLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(plainText, plain, plainLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_FREE(plain);
    BSL_SAL_FREE(cipher);
    CRYPT_RandRegist(func);
    CRYPT_RandRegistEx(funcEx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    return ret;
}

static int32_t SignEncode(const char *signR, const char *signS, uint8_t *vectorSign, uint32_t *vectorSignLen)
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
ERR:
    BSL_SAL_FREE(r);
    BSL_SAL_FREE(s);
    BN_Destroy(bnR);
    BN_Destroy(bnS);
    return ret;
}

static bool SetUserId(CRYPT_EAL_PkeyCtx *pkey, const char id[])
{
    bool ret = false;
    uint8_t *userId = NULL;

    uint32_t userIdLen;

    userId = CMVP_StringsToBins(id, &(userIdLen));
    GOTO_ERR_IF_TRUE(userId == NULL, CRYPT_CMVP_COMMON_ERR);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SM2_USER_ID, userId, userIdLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_COMMON_ERR);
    ret = true;
ERR:
    BSL_SAL_FREE(userId);
    return ret;
}

bool CRYPT_CMVP_SelftestSM2Sign(void *libCtx, const char *attrName)
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
    CRYPT_EAL_RandFunc func = CRYPT_RandRegistGet();
    CRYPT_EAL_RandFuncEx funcEx = CRYPT_RandRegistExGet();
    CRYPT_RandRegistEx(NULL);
    msg = CMVP_StringsToBins(SM2DSA_VECTOR.msg, &msgLen);
    GOTO_ERR_IF_TRUE(msg == NULL, CRYPT_CMVP_COMMON_ERR);
    pkeyPrv = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_SM2, 0, attrName);
    GOTO_ERR_IF_TRUE(pkeyPrv == NULL, CRYPT_CMVP_COMMON_ERR);
    pkeyPub = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_SM2, 0, attrName);
    GOTO_ERR_IF_TRUE(pkeyPub == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(SetUserId(pkeyPub, SM2DSA_VECTOR.userid) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(SetUserId(pkeyPrv, SM2DSA_VECTOR.userid) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(SetPrvPkey(&pkeyPrv, SM2_TEST_KEYS.d) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(SetPubPkey(&pkeyPub, SM2_TEST_KEYS.qX, SM2_TEST_KEYS.qY) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyPrv);
    sign = BSL_SAL_Malloc(signLen);
    GOTO_ERR_IF_TRUE(sign == NULL, CRYPT_MEM_ALLOC_FAIL);

    // regist rand function
    CRYPT_RandRegist(TestVectorRandom);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySign(pkeyPrv, SM2DSA_VECTOR.mdId, msg, msgLen, sign, &signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    // compare the signature
    signVecLen = CRYPT_EAL_PkeyGetSignLen(pkeyPrv);
    signVec = (uint8_t *)BSL_SAL_Malloc(signVecLen);
    GOTO_ERR_IF_TRUE(signVec == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(SignEncode(SM2DSA_VECTOR.signR, SM2DSA_VECTOR.signS, signVec, &signVecLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(signLen != signVecLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(signVec, sign, signLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(
        CRYPT_EAL_PkeyVerify(pkeyPub, SM2DSA_VECTOR.mdId, msg, msgLen, signVec, signVecLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_FREE(sign);
    BSL_SAL_FREE(signVec);
    BSL_SAL_FREE(msg);
    CRYPT_EAL_PkeyFreeCtx(pkeyPrv);
    CRYPT_EAL_PkeyFreeCtx(pkeyPub);
    CRYPT_RandRegist(func);
    CRYPT_RandRegistEx(funcEx);
    return ret;
}

static int32_t TestExchangeVectorRandom(uint8_t *r, uint32_t rLen)
{
    return SetRandomVector(SM2Exchange_VECTOR.r, r, rLen);
}

bool CRYPT_CMVP_SelftestSM2Exchange(void *libCtx, const char *attrName)
{
    bool ret = false;
    uint8_t *R = NULL;
    uint8_t *out = NULL;
    uint8_t *sharekey = NULL;
    uint8_t localR[65];
    
    int32_t server = 1;

    CRYPT_EAL_PkeyCtx *selfCtx = NULL;
    CRYPT_EAL_PkeyCtx *peerCtx = NULL;
    CRYPT_EAL_RandFunc func = CRYPT_RandRegistGet();
    CRYPT_EAL_RandFuncEx funcEx = CRYPT_RandRegistExGet();
    CRYPT_RandRegistEx(NULL);

    selfCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_SM2, 0, attrName);
    GOTO_ERR_IF_TRUE(selfCtx == NULL, CRYPT_CMVP_COMMON_ERR);
    peerCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_SM2, 0, attrName);
    GOTO_ERR_IF_TRUE(peerCtx == NULL, CRYPT_CMVP_COMMON_ERR);

    uint32_t RLen;
    R = CMVP_StringsToBins(SM2Exchange_VECTOR.R, &RLen);
    GOTO_ERR_IF_TRUE(R == NULL, CRYPT_CMVP_COMMON_ERR);

    uint32_t sharekeyLen;
    sharekey = CMVP_StringsToBins(SM2Exchange_VECTOR.sharekey, &sharekeyLen);
    GOTO_ERR_IF_TRUE(sharekey == NULL, CRYPT_CMVP_COMMON_ERR);

    uint32_t outLen = sharekeyLen;
    out = BSL_SAL_Malloc(outLen);
    GOTO_ERR_IF_TRUE(out == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(SetUserId(selfCtx, SM2Exchange_VECTOR.userid1) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(selfCtx, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    CRYPT_RandRegist(TestExchangeVectorRandom);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(selfCtx, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(SetUserId(peerCtx, SM2Exchange_VECTOR.userid2) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(peerCtx, CRYPT_CTRL_SET_SM2_R, R, RLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(SetPrvPkey(&selfCtx, SM2Exchange_VECTOR.self_d) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(SetPrvPkey(&peerCtx, SM2Exchange_VECTOR.peer_d) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(SetPubPkey(&selfCtx, SM2Exchange_VECTOR.self_x, SM2Exchange_VECTOR.self_y) != true,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(SetPubPkey(&peerCtx, SM2Exchange_VECTOR.peer_x, SM2Exchange_VECTOR.peer_y) != true,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyComputeShareKey(selfCtx, peerCtx, out, &outLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(outLen != sharekeyLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(out, sharekey, sharekeyLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_FREE(sharekey);
    BSL_SAL_FREE(out);
    BSL_SAL_FREE(R);
    CRYPT_EAL_PkeyFreeCtx(peerCtx);
    CRYPT_EAL_PkeyFreeCtx(selfCtx);
    CRYPT_RandRegist(func);
    CRYPT_RandRegistEx(funcEx);
    return ret;
}

static bool SM2_Consistency_Sign(void)
{
    bool ret = false;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t *sign = NULL;
    uint32_t signLen;
    uint8_t *data = NULL;
    uint32_t dataLen;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    GOTO_ERR_IF_TRUE(pkey == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(SetUserId(pkey, SM2DSA_VECTOR.userid) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    sign = BSL_SAL_Malloc(signLen);
    GOTO_ERR_IF_TRUE(sign == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyGen(pkey) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    data = CMVP_StringsToBins(consistestdata, &dataLen);
    GOTO_ERR_IF_TRUE(data == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SM3, data, dataLen, sign, &signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SM3, data, dataLen, sign, signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_FREE(sign);
    BSL_SAL_FREE(data);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

static bool SM2_Consistency_Crypt(void)
{
    bool ret = false;

    uint8_t *plain = NULL;
    uint32_t plainLen;

    uint8_t cipherText[MAX_PLAIN_TEXT_LEN + CIPHER_TEXT_EXTRA_LEN] = {0};
    uint32_t cipherTextLen = sizeof(cipherText);
    uint8_t decodeText[MAX_PLAIN_TEXT_LEN + CIPHER_TEXT_EXTRA_LEN] = {0};
    uint32_t decodeTextLen = sizeof(decodeText);

    uint8_t plainText[MAX_PLAIN_TEXT_LEN] = {0};
    uint32_t plainTextLen = sizeof(plainText);
    uint8_t encodeText[MAX_PLAIN_TEXT_LEN + CIPHER_TEXT_EXTRA_LEN] = {0};
    uint32_t encodeTextLen = sizeof(encodeText);
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    GOTO_ERR_IF_TRUE(pkey == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyGen(pkey) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    plain = CMVP_StringsToBins(SM2_CRYPT_TEST_VECTOR.plain, &plainLen);
    GOTO_ERR_IF_TRUE(plain == NULL, CRYPT_CMVP_COMMON_ERR);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, plain, plainLen, cipherText, &cipherTextLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    CRYPT_SM2_EncryptData data = {
        .x = decodeText+ 1,
        .xLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .y = decodeText + SM2_POINT_SINGLE_COORDINATE_LEN + 1,
        .yLen = SM2_POINT_SINGLE_COORDINATE_LEN,
        .hash = decodeText + SM2_POINT_COORDINATE_LEN,
        .hashLen = SM3_MD_SIZE,
        .cipher = decodeText + SM2_POINT_COORDINATE_LEN + SM3_MD_SIZE,
        .cipherLen = decodeTextLen - SM2_POINT_COORDINATE_LEN - SM3_MD_SIZE
    };
    GOTO_ERR_IF_TRUE(CRYPT_EAL_DecodeSm2EncryptData(cipherText, cipherTextLen, &data) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    decodeText[0] = 0x04;
    GOTO_ERR_IF_TRUE(memcmp(decodeText, plain, plainLen) == 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_EncodeSm2EncryptData(&data, encodeText, &encodeTextLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, encodeText, encodeTextLen, plainText, &plainTextLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(plainTextLen != plainLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(plainText, plain, plainLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_FREE(plain);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

static bool CRYPT_CMVP_SelftestSM2Consistency(void)
{
    return SM2_Consistency_Sign() && SM2_Consistency_Crypt();
}

bool CRYPT_CMVP_SelftestSM2(void)
{
    return CRYPT_CMVP_SelftestSM2Sign(NULL, NULL) && CRYPT_CMVP_SelftestSM2Crypt(NULL, NULL) &&
        CRYPT_CMVP_SelftestSM2Exchange(NULL, NULL) && CRYPT_CMVP_SelftestSM2Consistency();
}

bool CRYPT_CMVP_SelftestProviderSM2(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestSM2Sign(libCtx, attrName) && CRYPT_CMVP_SelftestSM2Crypt(libCtx, attrName) &&
        CRYPT_CMVP_SelftestSM2Exchange(libCtx, attrName);
}
#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */
