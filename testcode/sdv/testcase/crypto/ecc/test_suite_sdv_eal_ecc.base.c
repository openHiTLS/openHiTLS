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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "securec.h"
#include "crypt_bn.h"
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_dsa.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "stub_utils.h"
#include "crypt_util_rand.h"
#include "crypt_encode.h"
#include "crypt_eal_md.h"
#include "crypt_dsa.h"
#include "crypt_ecdh.h"
#include "crypt_ecdsa.h"
#include "crypt_ecc.h"
#include "eal_pkey_local.h"

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, BN_RandRangeEx, void *, BN_BigNum *, const BN_BigNum *);

#define SUCCESS 0
#define ERROR (-1)
#define BITS_OF_BYTE 8
#define KEY_MAX_LEN 133
#define PUBKEY_MAX_LEN 133  // 521(The public key length of the longest curve.) * 2 + 1 1043
#define PRVKEY_MAX_LEN 65
#define ECC_MAX_BIT_LEN 521
static uint8_t gkRandBuf[80];
static uint32_t gkRandBufLen = 0;

typedef struct {
    uint8_t data[KEY_MAX_LEN];
    uint32_t len;
} KeyData;

static int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    const int maxNum = 255;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % maxNum);
    }
    return 0;
}

static int32_t RandFuncEx(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    (void)libCtx;
    const int maxNum = 255;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % maxNum);
    }
    return 0;
}

// Custom random function to return fixed K value for signature tests (macOS provider mode fix)
static int32_t STUB_RandForSignature(uint8_t *byte, uint32_t len)
{
    if (len > sizeof(gkRandBuf)) {
        return CRYPT_NULL_INPUT;
    }
    // Return the fixed K value from test vector
    return memcpy_s(byte, len, gkRandBuf, len);
}

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t STUB_RandForSignatureEx(void *libCtx, uint8_t *byte, uint32_t len)
{
    (void)libCtx;
    return STUB_RandForSignature(byte, len);
}
#endif

static int32_t EccPointToBuffer(Hex *pubKeyX, Hex *pubKeyY, CRYPT_PKEY_PointFormat pointFormat, KeyData *pubKey)
{
    uint8_t value;
    value = *(uint8_t *)(pubKeyY->x + pubKeyY->len - 1);
    int sign = 0; /* The value 0 indicates an odd number.*/
    if (value % 2 == 0) {
        sign = 1;
    }
    switch (pointFormat) {
        case CRYPT_POINT_COMPRESSED: {
            pubKey->data[0] = (sign == 1) ? 0x02 : 0x03;
            ASSERT_TRUE_AND_LOG(
                "memcpy_s", memcpy_s(pubKey->data + 1, pubKey->len - 1, pubKeyX->x, pubKeyX->len) == EOK);
            pubKey->len = pubKeyX->len + 1;
        } break;
        case CRYPT_POINT_UNCOMPRESSED: {
            pubKey->data[0] = 0x04;
            ASSERT_TRUE_AND_LOG(
                "memcpy_s", memcpy_s(pubKey->data + 1, pubKey->len - 1, pubKeyX->x, pubKeyX->len) == EOK);
            ASSERT_TRUE_AND_LOG("memcpy_s",
                memcpy_s(pubKey->data + 1 + pubKeyX->len, pubKey->len - 1 - pubKeyX->len, pubKeyY->x, pubKeyY->len) ==
                    EOK);
            pubKey->len = pubKeyX->len + pubKeyY->len + 1;
        } break;
        case CRYPT_POINT_HYBRID: {
            pubKey->data[0] = (sign == 1) ? 0x06 : 0x07;
            ASSERT_TRUE_AND_LOG(
                "memcpy_s", memcpy_s(pubKey->data + 1, pubKey->len - 1, pubKeyX->x, pubKeyX->len) == EOK);
            ASSERT_TRUE_AND_LOG("memcpy_s",
                memcpy_s(pubKey->data + 1 + pubKeyX->len, pubKey->len - 1 - pubKeyX->len, pubKeyY->x, pubKeyY->len) ==
                    EOK);
            pubKey->len = pubKeyX->len + pubKeyY->len + 1;
        } break;
        default:
            return ERROR;
    }
    return SUCCESS;

EXIT:
    return -1; /* -1 indicates an exception. */
}

static int GetPubKeyLen(int eccId)
{
    switch (eccId) {
        case CRYPT_ECC_NISTP192:
            return 49;           /* SECP192R1 */
        case CRYPT_ECC_NISTP224:
            return 57;           /* SECP224R1 */
        case CRYPT_ECC_NISTP256: /* (32 * 2) + 1 SECP256R1, brainpoolP256r1 */
        case CRYPT_ECC_BRAINPOOLP256R1:
            return 65;
        case CRYPT_ECC_NISTP384: /* (48 * 2) + 1 SECP384R1, brainpoolP384r1 */
        case CRYPT_ECC_BRAINPOOLP384R1:
            return 97;
        case CRYPT_ECC_BRAINPOOLP512R1:
            return 129; /* brainpoolP512r1 */
        case CRYPT_ECC_NISTP521:
            return 133; /* (66 * 2) + 1 SECP521R1 */
        default:
            return SUCCESS;
    }
}

static int GetPrvKeyLen(int eccId)
{
    switch (eccId) {
        case CRYPT_ECC_NISTP192:
            return 24;
        case CRYPT_ECC_NISTP224:
            return 28;
        case CRYPT_ECC_NISTP256:
        case CRYPT_ECC_BRAINPOOLP256R1:
            return 32;
        case CRYPT_ECC_NISTP384:
        case CRYPT_ECC_BRAINPOOLP384R1:
            return 48;
        case CRYPT_ECC_BRAINPOOLP512R1:
            return 64;
        case CRYPT_ECC_NISTP521:
            return 66;
        default:
            return SUCCESS;
    }
}

static void Ecc_SetPubKey(CRYPT_EAL_PkeyPub *pub, int id, uint8_t *key, uint32_t len)
{
    pub->id = id;
    pub->key.eccPub.data = key;
    pub->key.eccPub.len = len;
}

static void Ecc_SetPrvKey(CRYPT_EAL_PkeyPrv *prv, int id, uint8_t *key, uint32_t len)
{
    prv->id = id;
    prv->key.eccPrv.data = key;
    prv->key.eccPrv.len = len;
}

static int Ecc_GenKey(
    int algId, int eccId, Hex *prvKeyVector, Hex *pubKeyX, Hex *pubKeyY, int pointFormat, int isProvider)
{
    int ret;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};
    CRYPT_EAL_PkeyPub ecdsaPubKey = {0};
    CRYPT_EAL_PkeyPrv ecdsaPrvKey = {0};

    /* Init the DRBG */
    TestMemInit();

    /* Create a key structure. */
    pkey = TestPkeyNewCtx(NULL, algId, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, eccId), CRYPT_SUCCESS);

    /* Setup fixed random value for deterministic key generation */
    ASSERT_TRUE(memcpy_s(gkRandBuf, sizeof(gkRandBuf), prvKeyVector->x, prvKeyVector->len) == 0);
    gkRandBufLen = prvKeyVector->len;

    /* Init DRBG first, then register our callback AFTER to override TestSimpleRand */
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    /* Register callback to return fixed random value (must be AFTER TestRandInit) */
    CRYPT_RandRegist(STUB_RandForSignature);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(STUB_RandForSignatureEx);
#endif

    /* Generate a key pair */
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    /* Set point format*/
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_ECC_POINT_FORMAT, &pointFormat, sizeof(uint32_t)), CRYPT_SUCCESS);

    /* Get public key */
    ecdsaPubKey.id = algId;
    ecdsaPubKey.key.eccPub.data = (uint8_t *)malloc(GetPubKeyLen(eccId));
    ASSERT_TRUE(ecdsaPubKey.key.eccPub.data != NULL);
    ecdsaPubKey.key.eccPub.len = GetPubKeyLen(eccId);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &ecdsaPubKey), CRYPT_SUCCESS);

    /* Get private key */
    ecdsaPrvKey.id = algId;
    ecdsaPrvKey.key.eccPrv.data = (uint8_t *)malloc(GetPrvKeyLen(eccId));
    ASSERT_TRUE(ecdsaPrvKey.key.eccPrv.data != NULL);
    ecdsaPrvKey.key.eccPrv.len = GetPrvKeyLen(eccId);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &ecdsaPrvKey), CRYPT_SUCCESS);

    /* Convert the point to buffer */
    ret = EccPointToBuffer(pubKeyX, pubKeyY, pointFormat, &pubKeyVector);
    ASSERT_TRUE_AND_LOG("EccPointToBuffer", ret == CRYPT_SUCCESS);
    ASSERT_COMPARE("Compare PubKey",
        pubKeyVector.data,
        ecdsaPubKey.key.eccPub.len,
        ecdsaPubKey.key.eccPub.data,
        ecdsaPubKey.key.eccPub.len);

    ASSERT_COMPARE("Compare PrvKey",
        prvKeyVector->x,
        ecdsaPrvKey.key.eccPrv.len,
        ecdsaPrvKey.key.eccPrv.data,
        ecdsaPrvKey.key.eccPrv.len);

    free(ecdsaPubKey.key.eccPub.data);
    free(ecdsaPrvKey.key.eccPrv.data);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return SUCCESS;
EXIT:
    free(ecdsaPubKey.key.eccPub.data);
    free(ecdsaPrvKey.key.eccPrv.data);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ERROR;
}

int EAL_PkeyNewCtx_Api_TC001(int algId)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    /* Registers memory functions. */
    TestMemInit();
    pkeyCtx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeyNewCtx", pkeyCtx != NULL);

    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    return SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    return ERROR;
}

int EAL_PkeyFreeCtx_Api_TC001(int algId)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    TestMemInit();
    pkeyCtx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeyNewCtx", pkeyCtx != NULL);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    pkeyCtx = NULL;
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    return SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    return ERROR;
}

int EAL_PkeySetParaById_Api_TC001(int algId)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    TestMemInit();
    pkeyCtx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeyNewCtx", pkeyCtx != NULL);
    ASSERT_TRUE_AND_LOG("Invalid Pkey", CRYPT_EAL_PkeySetParaById(NULL, CRYPT_ECC_NISTP224) == CRYPT_NULL_INPUT);
    ASSERT_TRUE_AND_LOG("CRYPT_ECC_NISTP192", CRYPT_EAL_PkeySetParaById(pkeyCtx, CRYPT_ECC_NISTP192) == CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("CRYPT_ECC_NISTP224", CRYPT_EAL_PkeySetParaById(pkeyCtx, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("CRYPT_ECC_NISTP256", CRYPT_EAL_PkeySetParaById(pkeyCtx, CRYPT_ECC_NISTP256) == CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("CRYPT_ECC_NISTP384", CRYPT_EAL_PkeySetParaById(pkeyCtx, CRYPT_ECC_NISTP384) == CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("CRYPT_ECC_NISTP521", CRYPT_EAL_PkeySetParaById(pkeyCtx, CRYPT_ECC_NISTP521) == CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG(
        "CRYPT_ECC_BRAINPOOLP256R1", CRYPT_EAL_PkeySetParaById(pkeyCtx, CRYPT_ECC_BRAINPOOLP256R1) == CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG(
        "CRYPT_ECC_BRAINPOOLP384R1", CRYPT_EAL_PkeySetParaById(pkeyCtx, CRYPT_ECC_BRAINPOOLP384R1) == CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG(
        "CRYPT_ECC_BRAINPOOLP512R1", CRYPT_EAL_PkeySetParaById(pkeyCtx, CRYPT_ECC_BRAINPOOLP512R1) == CRYPT_SUCCESS);
    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    return ret;
}

int EAL_PkeyCtrl_Api_TC001(int algId, int type, int expect)
{
    int ret = ERROR;
    int32_t value = 1;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    TestMemInit();

    pkeyCtx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeyNewCtx", pkeyCtx != NULL);

    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeyCtrl", CRYPT_EAL_PkeyCtrl(pkeyCtx, type, &value, sizeof(int32_t)) == expect);

    ret = SUCCESS;

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    return ret;
}

int EAL_PkeyCtrl_Api_TC002(int algId)
{
    uint32_t ret, pointFormat;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    TestMemInit();

    pkeyCtx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeyNewCtx", pkeyCtx != NULL);

    pointFormat = 1;
    ret = CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_SET_ECC_POINT_FORMAT, &pointFormat, sizeof(uint32_t));
    ASSERT_TRUE_AND_LOG("pkey = null", ret == CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_ECC_POINT_FORMAT, NULL, 0);
    ASSERT_TRUE_AND_LOG("val = null, len = 0", ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_ECC_POINT_FORMAT, NULL, sizeof(uint32_t));
    ASSERT_TRUE_AND_LOG("val = null, len != 0", ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_ECC_POINT_FORMAT, &pointFormat, 0);
    ASSERT_TRUE_AND_LOG("val != null, len = 0", ret == CRYPT_ECC_PKEY_ERR_CTRL_LEN);

    pointFormat = CRYPT_POINT_MAX;
    ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_ECC_POINT_FORMAT, &pointFormat, sizeof(uint32_t));
    ASSERT_TRUE_AND_LOG("PointFormat = CRYPT_POINT_MAX", ret == CRYPT_ECC_PKEY_ERR_INVALID_POINT_FORMAT);
    pointFormat = CRYPT_POINT_COMPRESSED;
    ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_ECC_POINT_FORMAT, &pointFormat, sizeof(uint32_t));
    ASSERT_TRUE_AND_LOG("PointFormat = CRYPT_POINT_COMPRESSED", ret == CRYPT_SUCCESS);
    pointFormat = CRYPT_POINT_UNCOMPRESSED;
    ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_ECC_POINT_FORMAT, &pointFormat, sizeof(uint32_t));
    ASSERT_TRUE_AND_LOG("PointFormat = CRYPT_POINT_UNCOMPRESSED", ret == CRYPT_SUCCESS);
    pointFormat = CRYPT_POINT_HYBRID;
    ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_ECC_POINT_FORMAT, &pointFormat, sizeof(uint32_t));
    ASSERT_TRUE_AND_LOG("PointFormat = CRYPT_POINT_HYBRID", ret == CRYPT_SUCCESS);

    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    return SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    return ERROR;
}

int EAL_PkeyCtrl_Api_TC003(int algId, int eccId, Hex *pubKeyX, Hex *pubKeyY)
{
    uint32_t ret, pointFormat;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPub pub1 = {0};
    CRYPT_EAL_PkeyPub pub2 = {0};
    KeyData pubKeyVector1 = {{0}, KEY_MAX_LEN};
    KeyData pubKeyVector2 = {{0}, KEY_MAX_LEN};
    KeyData pubKeyVector3 = {{0}, KEY_MAX_LEN};

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    /* Create a key structure. */
    ctx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("NewCtx", ctx != NULL);

    ASSERT_TRUE_AND_LOG("CRYPT_EAL_PkeySetParaById", CRYPT_EAL_PkeySetParaById(ctx, eccId) == CRYPT_SUCCESS);

    /* Convert the format of point to compressed. */
    ret = EccPointToBuffer(pubKeyX, pubKeyY, CRYPT_POINT_COMPRESSED, &pubKeyVector1);
    ASSERT_TRUE_AND_LOG("EccPointToBuffer", ret == CRYPT_SUCCESS);

    /* Set public key. */
    Ecc_SetPubKey(&pub1, algId, pubKeyVector1.data, pubKeyVector1.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub1), CRYPT_SUCCESS);

    /* Set the point format to compressed. */
    pointFormat = CRYPT_POINT_COMPRESSED;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ECC_POINT_FORMAT, &pointFormat, sizeof(uint32_t));
    ASSERT_TRUE_AND_LOG("Set CRYPT_POINT_COMPRESSED", ret == CRYPT_SUCCESS);
    /* Set the point format to hybrid. */
    pointFormat = CRYPT_POINT_HYBRID;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_ECC_POINT_FORMAT, &pointFormat, sizeof(uint32_t));
    ASSERT_TRUE_AND_LOG("Set CRYPT_POINT_HYBRID", ret == CRYPT_SUCCESS);

    /* Get the public key. */
    Ecc_SetPubKey(&pub2, algId, pubKeyVector2.data, GetPubKeyLen(eccId));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub2), CRYPT_SUCCESS);

    /* Convert the format of point to hybrid. */
    ret = EccPointToBuffer(pubKeyX, pubKeyY, pointFormat, &pubKeyVector3);
    ASSERT_TRUE_AND_LOG("EccPointToBuffer", ret == CRYPT_SUCCESS);

    /* Compare */
    ASSERT_TRUE_AND_LOG("Compare PubKey Len", pub2.key.eccPub.len == pubKeyVector3.len);
    ASSERT_TRUE_AND_LOG("Compare PubKey", memcmp(pub2.key.eccPub.data, pubKeyVector3.data, pubKeyVector3.len) == 0);

    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_RandDeinit();
    return SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_RandDeinit();
    return ERROR;
}

int EAL_PkeyGetPrv_Api_TC001(int algId, Hex *prvKey)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prv1 = {0};
    CRYPT_EAL_PkeyPrv prv2 = {0};
    KeyData prvKeyBuffer = {{0}, KEY_MAX_LEN};

    TestMemInit();

    /* Create a key structure. */
    ctx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("NewCtx", ctx != NULL);
    ASSERT_TRUE_AND_LOG("SetParaById", CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);

    /* Get the private key when there is no private key. */
    Ecc_SetPrvKey(&prv2, algId, prvKeyBuffer.data, GetPrvKeyLen(CRYPT_ECC_NISTP224));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv2), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);

    /* Set the private key. */
    Ecc_SetPrvKey(&prv1, algId, prvKey->x, prvKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv1), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeyGetPrv. */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prv2), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, NULL), CRYPT_NULL_INPUT);
    prv2.id = CRYPT_PKEY_DH;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv2), CRYPT_EAL_ERR_ALGID);
    prv2.id = algId;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv2), CRYPT_SUCCESS);

    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

int EAL_PkeyGetPrv_Provider_Api_TC001(int algId, Hex *prvKey)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prv1 = {0};
    CRYPT_EAL_PkeyPrv prv2 = {0};
    KeyData prvKeyBuffer = {{0}, KEY_MAX_LEN};

    TestMemInit();

    /* Create a key structure. */
    ctx = TestPkeyNewCtx(NULL, algId, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", true);
    ASSERT_TRUE_AND_LOG("NewCtx", ctx != NULL);
    ASSERT_TRUE_AND_LOG("SetParaById", CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);

    /* Get the private key when there is no private key. */
    Ecc_SetPrvKey(&prv2, algId, prvKeyBuffer.data, GetPrvKeyLen(CRYPT_ECC_NISTP224));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv2), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);

    /* Set the private key. */
    Ecc_SetPrvKey(&prv1, algId, prvKey->x, prvKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv1), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeyGetPrv. */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prv2), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, NULL), CRYPT_NULL_INPUT);
    prv2.id = CRYPT_PKEY_DH;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv2), CRYPT_EAL_ERR_ALGID);
    prv2.id = algId;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv2), CRYPT_SUCCESS);

    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

int EAL_PkeyGetPub_Api_TC001(int algId, Hex *pubKeyX, Hex *pubKeyY)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPub pub1, pub2;
    KeyData pubKeyVector1 = {{0}, KEY_MAX_LEN};
    KeyData pubKeyVector2 = {{0}, KEY_MAX_LEN};

    TestMemInit();

    /* Create a key structure. */
    ctx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("NewCtx", ctx != NULL);
    ASSERT_TRUE_AND_LOG("SetParaById", CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);

    /* Get the public key when there is no public key. */
    Ecc_SetPubKey(&pub2, algId, pubKeyVector2.data, GetPubKeyLen(CRYPT_ECC_NISTP224));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub2), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);

    /* Set the public key. */
    ASSERT_TRUE_AND_LOG("EccPointToBuffer",
        EccPointToBuffer(pubKeyX, pubKeyY, CRYPT_POINT_UNCOMPRESSED, &pubKeyVector1) == CRYPT_SUCCESS);
    Ecc_SetPubKey(&pub1, algId, pubKeyVector1.data, pubKeyVector1.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub1), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeyGetPub. */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(NULL, &pub2), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, NULL), CRYPT_NULL_INPUT);
    pub2.id = CRYPT_PKEY_DH;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub2), CRYPT_EAL_ERR_ALGID);
    pub2.id = algId;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub2), CRYPT_SUCCESS);

    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

int EAL_PkeyGetPub_Provider_Api_TC001(int algId, Hex *pubKeyX, Hex *pubKeyY)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPub pub1, pub2;
    KeyData pubKeyVector1 = {{0}, KEY_MAX_LEN};
    KeyData pubKeyVector2 = {{0}, KEY_MAX_LEN};

    TestMemInit();

    /* Create a key structure. */
    ctx = TestPkeyNewCtx(NULL, algId, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", true);
    ASSERT_TRUE_AND_LOG("NewCtx", ctx != NULL);
    ASSERT_TRUE_AND_LOG("SetParaById", CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);

    /* Get the public key when there is no public key. */
    Ecc_SetPubKey(&pub2, algId, pubKeyVector2.data, GetPubKeyLen(CRYPT_ECC_NISTP224));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub2), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);

    /* Set the public key. */
    ASSERT_TRUE_AND_LOG("EccPointToBuffer",
        EccPointToBuffer(pubKeyX, pubKeyY, CRYPT_POINT_UNCOMPRESSED, &pubKeyVector1) == CRYPT_SUCCESS);
    Ecc_SetPubKey(&pub1, algId, pubKeyVector1.data, pubKeyVector1.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub1), CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeyGetPub. */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(NULL, &pub2), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, NULL), CRYPT_NULL_INPUT);
    pub2.id = CRYPT_PKEY_DH;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub2), CRYPT_EAL_ERR_ALGID);
    pub2.id = algId;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub2), CRYPT_SUCCESS);

    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

int EAL_PkeySetPrv_Api_TC001(int algId, Hex *prvKey, Hex *errorPrvKey)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};

    TestMemInit();

    /* Create a key structure. */
    ctx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("NewCtx", ctx != NULL);

    /* Set the key without curve */
    Ecc_SetPrvKey(&prv, algId, prvKey->x, prvKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_NULL_INPUT);

    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeySetPrv. */
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(NULL, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, NULL), CRYPT_NULL_INPUT);
    prv.id = CRYPT_PKEY_DH;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_EAL_ERR_ALGID);
    prv.id = algId;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);
    prv.key.eccPrv.data = errorPrvKey->x;
    prv.key.eccPrv.len = errorPrvKey->len;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY);

    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);

    return ret;
}

int EAL_PkeySetPrv_Api_TC002(int algId, Hex *prvKey, Hex *pubKeyX, Hex *pubKeyY)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub1, pub2;
    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};
    KeyData pubKeyVector2 = {{0}, KEY_MAX_LEN};

    TestMemInit();

    /* Create a key structure. */
    ctx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("NewCtx", ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);

    /* Set the public key. */
    ASSERT_TRUE_AND_LOG("EccPointToBuffer",
        EccPointToBuffer(pubKeyX, pubKeyY, CRYPT_POINT_UNCOMPRESSED, &pubKeyVector) == CRYPT_SUCCESS);
    Ecc_SetPubKey(&pub1, algId, pubKeyVector.data, pubKeyVector.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub1), CRYPT_SUCCESS);

    /* Set the private key. */
    Ecc_SetPrvKey(&prv, algId, prvKey->x, prvKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);

    /* Get the public key. */
    Ecc_SetPubKey(&pub2, algId, pubKeyVector2.data, pubKeyVector2.len);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub2), CRYPT_SUCCESS);

    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

int EAL_PkeySetPub_Api_TC001(int algId, Hex *pubKeyVector)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPub pub;

    TestMemInit();

    /* Create a key structure. */
    ctx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("NewCtx", ctx != NULL);

    Ecc_SetPubKey(&pub, algId, pubKeyVector->x, pubKeyVector->len);

    /* Set the pubilc key without curve. */
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_NULL_INPUT);

    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);

    /* Input parameter test of CRYPT_EAL_PkeySetPub. */
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(NULL, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, NULL), CRYPT_NULL_INPUT);
    pub.id = CRYPT_PKEY_DH;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_EAL_ERR_ALGID);
    pub.id = algId;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pub), CRYPT_SUCCESS);

    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);

    return ret;
}

int EAL_PkeySetPub_Api_TC002(int algId, Hex *prvKey, Hex *pubKey)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prv1, prv2;
    (void)memset_s(&prv1.key.rsaPrv, sizeof(prv1.key.rsaPrv), 0, sizeof(prv1.key.rsaPrv));
    (void)memset_s(&prv2.key.rsaPrv, sizeof(prv2.key.rsaPrv), 0, sizeof(prv2.key.rsaPrv));
    CRYPT_EAL_PkeyPub ecdsaPubkey;
    KeyData pubKeyVector = {{0}, KEY_MAX_LEN};

    TestMemInit();

    /* Create a key structure. */
    ctx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE_AND_LOG("NewCtx", ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_NISTP224) == CRYPT_SUCCESS);

    /* Set the private key. */
    Ecc_SetPrvKey(&prv1, algId, prvKey->x, prvKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv1), CRYPT_SUCCESS);

    /* Set the public key. */
    Ecc_SetPubKey(&ecdsaPubkey, algId, pubKey->x, pubKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ecdsaPubkey), CRYPT_SUCCESS);

    /* Get the private key. */
    Ecc_SetPrvKey(&prv2, algId, pubKeyVector.data, pubKeyVector.len);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv2), CRYPT_SUCCESS);

    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

int EAL_PkeySetPub_Api_TC003(int algId, int eccId, Hex *pubKey, Hex *errorPubKey, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pub = {0};

    TestMemInit();
    /* Create a key structure. */
    pkey = TestPkeyNewCtx(NULL, algId, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE_AND_LOG("NewCtx", pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(pkey, eccId) == CRYPT_SUCCESS);

    /* Constructing a public key that is too long. */
    pub.id = algId;
    pub.key.eccPub.data = (uint8_t *)malloc(GetPubKeyLen(eccId) + 1);  // Allocate for 1 more byte.
    ASSERT_TRUE(pub.key.eccPub.data != NULL);
    pub.key.eccPub.len = GetPubKeyLen(eccId) + 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_ECC_ERR_POINT_CODE);
    free(pub.key.eccPub.data);

    /* Constructing a public key that is too short. */
    pub.id = algId;
    pub.key.eccPub.data = (uint8_t *)malloc(GetPubKeyLen(eccId) - 1);  // Allocate 1 byte less.
    ASSERT_TRUE(pub.key.eccPub.data != NULL);
    pub.key.eccPub.len = GetPubKeyLen(eccId) - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_ECC_ERR_POINT_CODE);
    free(pub.key.eccPub.data);
    pub.key.eccPub.data = NULL;

    /* Abnormal public key point: The length is abnormal. */
    if (pubKey->x != NULL) {
        Ecc_SetPubKey(&pub, algId, pubKey->x, pubKey->len);
        ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_ECC_ERR_POINT_CODE);
    }

    if (errorPubKey->x != NULL) {
        Ecc_SetPubKey(&pub, algId, errorPubKey->x, errorPubKey->len);
        ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_ECC_POINT_NOT_ON_CURVE);
    }

    CRYPT_EAL_PkeyFreeCtx(pkey);
    return SUCCESS;
EXIT:
    if (pub.key.eccPub.data != NULL) {
        free(pub.key.eccPub.data);
    }
    CRYPT_EAL_PkeyFreeCtx(pkey);

    return ERROR;
}

int EAL_PkeyGetParaId_Api_TC001(int algId, int paraId)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();

    ASSERT_TRUE(CRYPT_EAL_PkeyGetParaId(pkey) == CRYPT_PKEY_PARAID_MAX);

    pkey = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetParaId(pkey) == CRYPT_PKEY_PARAID_MAX);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(pkey, (CRYPT_PKEY_ParaId)paraId) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetParaId(pkey) == (CRYPT_PKEY_ParaId)paraId);

    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

int EAL_PkeyCmp_Api_TC001(int algId, Hex *pubKeyX, Hex *pubKeyY)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyPub pub = {0};
    KeyData pubkey = {{0}, KEY_MAX_LEN};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *ctx1 = CRYPT_EAL_PkeyNewCtx(algId);
    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL);

    ASSERT_EQ(EccPointToBuffer(pubKeyX, pubKeyY, CRYPT_POINT_COMPRESSED, &pubkey), CRYPT_SUCCESS);
    Ecc_SetPubKey(&pub, algId, pubkey.data, pubkey.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx1, CRYPT_ECC_NISTP224), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx1, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_ECC_ERR_POINT_CODE);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, CRYPT_ECC_NISTP224), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);
    ret = SUCCESS;
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    return ret;
}

int EAL_PkeyCmp_Provider_Api_TC001(int algId, Hex *pubKeyX, Hex *pubKeyY)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyPub pub = {0};
    KeyData pubkey = {{0}, KEY_MAX_LEN};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, algId,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", true);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, algId,
         CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", true);
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL);

    ASSERT_EQ(EccPointToBuffer(pubKeyX, pubKeyY, CRYPT_POINT_COMPRESSED, &pubkey), CRYPT_SUCCESS);
    Ecc_SetPubKey(&pub, algId, pubkey.data, pubkey.len);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx1, CRYPT_ECC_NISTP224), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx1, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_ECC_ERR_POINT_CODE);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, CRYPT_ECC_NISTP224), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);
    ret = SUCCESS;
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    return ret;
}

int EAL_PkeyGetPara_Func_TC001(int algId, Hex *p, Hex *a, Hex *b, Hex *x, Hex *y, Hex *n, Hex *h)
{
    int ret = ERROR;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t pData[ECC_MAX_BIT_LEN] = {0};
    uint8_t aData[ECC_MAX_BIT_LEN] = {0};
    uint8_t bData[ECC_MAX_BIT_LEN] = {0};
    uint8_t nData[ECC_MAX_BIT_LEN] = {0};
    uint8_t xData[ECC_MAX_BIT_LEN] = {0};
    uint8_t yData[ECC_MAX_BIT_LEN] = {0};
    uint8_t hData[ECC_MAX_BIT_LEN] = {0};
    CRYPT_EAL_PkeyPara eccPara = {
        .id = algId,
        .para.eccPara.a = a->x,
        .para.eccPara.aLen = a->len,
        .para.eccPara.b = b->x,
        .para.eccPara.bLen = b->len,
        .para.eccPara.n = n->x,
        .para.eccPara.nLen = n->len,
        .para.eccPara.p = p->x,
        .para.eccPara.pLen = p->len,
        .para.eccPara.x = x->x,
        .para.eccPara.xLen = x->len,
        .para.eccPara.y = y->x,
        .para.eccPara.yLen = y->len,
        .para.eccPara.h = h->x,
        .para.eccPara.hLen = h->len,
    };
    CRYPT_EAL_PkeyPara para = {.id = algId,
        .para.eccPara.a = aData,
        .para.eccPara.aLen = ECC_MAX_BIT_LEN,
        .para.eccPara.b = bData,
        .para.eccPara.bLen = ECC_MAX_BIT_LEN,
        .para.eccPara.n = nData,
        .para.eccPara.nLen = ECC_MAX_BIT_LEN,
        .para.eccPara.p = pData,
        .para.eccPara.pLen = ECC_MAX_BIT_LEN,
        .para.eccPara.x = xData,
        .para.eccPara.xLen = ECC_MAX_BIT_LEN,
        .para.eccPara.y = yData,
        .para.eccPara.yLen = ECC_MAX_BIT_LEN,
        .para.eccPara.h = hData,
        .para.eccPara.hLen = ECC_MAX_BIT_LEN};

    TestMemInit();
    ctx = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    /* Set and get elliptic curve */
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(ctx, &eccPara), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPara(ctx, &para), CRYPT_SUCCESS);

    ASSERT_TRUE(para.para.eccPara.aLen == a->len);
    ASSERT_TRUE(memcmp(aData, a->x, a->len) == 0);

    ASSERT_TRUE(para.para.eccPara.bLen == b->len);
    ASSERT_TRUE(memcmp(bData, b->x, b->len) == 0);

    ASSERT_TRUE(para.para.eccPara.nLen == n->len);
    ASSERT_TRUE(memcmp(nData, n->x, n->len) == 0);

    ASSERT_TRUE(para.para.eccPara.pLen == p->len);
    ASSERT_TRUE(memcmp(pData, p->x, p->len) == 0);

    ASSERT_TRUE(para.para.eccPara.xLen == x->len);
    ASSERT_TRUE(memcmp(xData, x->x, x->len) == 0);

    ASSERT_TRUE(para.para.eccPara.yLen == y->len);
    ASSERT_TRUE(memcmp(yData, y->x, y->len) == 0);

    ASSERT_TRUE(para.para.eccPara.hLen == h->len);
    ASSERT_TRUE(memcmp(hData, h->x, h->len) == 0);
    ret = SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
}

