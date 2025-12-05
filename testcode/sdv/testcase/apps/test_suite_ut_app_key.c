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

/* BEGIN_HEADER */
#include <stdio.h>
#include <string.h>
#include "app_opt.h"
#include "app_print.h"
#include "bsl_uio.h"
#include "bsl_types.h"
#include "uio_abstraction.h"
#include "app_errno.h"
#include "crypt_errno.h"
#include "crypt_eal_codecs.h"
#include "crypt_util_rand.h"
#include "crypt_eal_pkey.h"
#include "app_genpkey.h"
#include "app_pkey.h"
#include "app_function.h"
#include "securec.h"
#include "bsl_err.h"
#include "bsl_sal.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
/* END_HEADER */

#define TMP_BUFF_LEN 2048
#define GENPKEY_PRV_FILE_PATH "genpkey_prv.pem"
#define GENPKEY_ENC_PRV_FILE_PATH "genpkey_enc_prv.pem"
#define PKEY_PRV_FILE_PATH "pkey_prv.pem"
#define PKEY_ENC_PRV_FILE_PATH "pkey_enc_prv.pem"
#define PKEY_PUB_FILE_PATH "pkey_pub.pem"

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_genpkey.c
 * ${HITLS_ROOT_PATH}/apps/src/app_pkey.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c
 */

static void SetRsaKeyInfo(CRYPT_EAL_PkeyCtx *pkey)
{
    uint32_t keyLen = CRYPT_EAL_PkeyGetKeyLen(pkey);
    ASSERT_NE(keyLen, 0);
    uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(keyLen * 8);
    ASSERT_NE(prv, NULL);
    CRYPT_EAL_PkeyPrv rsaPrv = { 0 };
    rsaPrv.id = CRYPT_PKEY_RSA;
    rsaPrv.key.rsaPrv.d = prv;
    rsaPrv.key.rsaPrv.n = prv + keyLen;
    rsaPrv.key.rsaPrv.p = prv + keyLen * 2;    // 2nd buffer
    rsaPrv.key.rsaPrv.q = prv + keyLen * 3;    // 3rd buffer
    rsaPrv.key.rsaPrv.dP = prv + keyLen * 4;   // 4th buffer
    rsaPrv.key.rsaPrv.dQ = prv + keyLen * 5;   // 5th buffer
    rsaPrv.key.rsaPrv.qInv = prv + keyLen * 6; // 6th buffer
    rsaPrv.key.rsaPrv.e = prv + keyLen * 7;    // 7th buffer
    rsaPrv.key.rsaPrv.dLen = keyLen;
    rsaPrv.key.rsaPrv.nLen = keyLen;
    rsaPrv.key.rsaPrv.pLen = keyLen;
    rsaPrv.key.rsaPrv.qLen = keyLen;
    rsaPrv.key.rsaPrv.dPLen = keyLen;
    rsaPrv.key.rsaPrv.dQLen = keyLen;
    rsaPrv.key.rsaPrv.qInvLen = keyLen;
    rsaPrv.key.rsaPrv.eLen = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &rsaPrv), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyPub rsaPub;
    rsaPub.id = CRYPT_PKEY_RSA;
    rsaPub.key.rsaPub.n = rsaPrv.key.rsaPrv.n;
    rsaPub.key.rsaPub.nLen = rsaPrv.key.rsaPrv.nLen;
    rsaPub.key.rsaPub.e = rsaPrv.key.rsaPrv.e;
    rsaPub.key.rsaPub.eLen = rsaPrv.key.rsaPrv.eLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &rsaPub), CRYPT_SUCCESS);
EXIT:
    BSL_SAL_ClearFree(prv, keyLen * 8); // 8 items
}

/**
 * @test UT_HITLS_APP_KEY_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_KEY_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEY_TC001(char *algorithm, char *pkeyopt, int hashId)
{
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    char *genpkeyPrv[20] = {"genpkey", "-algorithm", algorithm, "-pkeyopt", pkeyopt, "-out", GENPKEY_PRV_FILE_PATH};
    char *pkeyPrv[20] = {"pkey", "-in", GENPKEY_PRV_FILE_PATH, "-out", PKEY_PRV_FILE_PATH};
    char *pkeyPub[20] = {"pkey", "-in", PKEY_PRV_FILE_PATH, "-pubout", "-out", PKEY_PUB_FILE_PATH};
    ASSERT_EQ(HITLS_GenPkeyMain(7, genpkeyPrv), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(5, pkeyPrv), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(6, pkeyPub), HITLS_APP_SUCCESS);
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    CRYPT_EAL_PkeyCtx *pkeyPrvCtx = NULL;
    CRYPT_EAL_PkeyCtx *pkeyPubCtx = NULL;

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, PKEY_PRV_FILE_PATH, NULL, 0,
        &pkeyPrvCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(
        CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PUBKEY_SUBKEY, PKEY_PUB_FILE_PATH, NULL, 0, &pkeyPubCtx),
        CRYPT_SUCCESS);

    if (strcasecmp(algorithm, "RSA") == 0) {
        SetRsaKeyInfo(pkeyPrvCtx);
        int32_t pkcsv15 = CRYPT_MD_SHA256;
        ASSERT_EQ(
            CRYPT_EAL_PkeyCtrl(pkeyPrvCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
            0);
        ASSERT_EQ(
            CRYPT_EAL_PkeyCtrl(pkeyPubCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
            0);
    }

    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen(pkeyPrvCtx);
    uint8_t *signdata = (uint8_t *)BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    uint32_t dataLen = sizeof(data);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyPrvCtx, hashId, data, dataLen, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyPubCtx, hashId, data, dataLen, signdata, signLen), CRYPT_SUCCESS);
EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(signdata);
    CRYPT_EAL_PkeyFreeCtx(pkeyPrvCtx);
    CRYPT_EAL_PkeyFreeCtx(pkeyPubCtx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    remove(GENPKEY_PRV_FILE_PATH);
    remove(PKEY_PRV_FILE_PATH);
    remove(PKEY_PUB_FILE_PATH);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEY_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_KEY_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEY_TC002(char *algorithm, char *pkeyopt)
{
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    char *genpkeyPrv[20] = {"genpkey", "-algorithm", algorithm, "-pkeyopt", pkeyopt, "-out", GENPKEY_PRV_FILE_PATH};
    char *pkeyPrv[20] = {"pkey", "-in", GENPKEY_PRV_FILE_PATH, "-out", PKEY_PRV_FILE_PATH};
    ASSERT_EQ(HITLS_GenPkeyMain(7, genpkeyPrv), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(5, pkeyPrv), HITLS_APP_SUCCESS);
    CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_AES128_CTR, "provider=default", NULL, 0, NULL);
    CRYPT_EAL_PkeyCtx *pkeyPrvCtx = NULL;

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, PKEY_PRV_FILE_PATH, NULL, 0,
        &pkeyPrvCtx),
        CRYPT_SUCCESS);

    if (strcasecmp(algorithm, "RSA") == 0) {
        SetRsaKeyInfo(pkeyPrvCtx);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyPrvCtx, CRYPT_CTRL_SET_RSA_OAEP_LABEL, NULL, 0), CRYPT_SUCCESS);
        int32_t hashId = CRYPT_MD_SHA1;
        BSL_Param oaepParam[3] = {
            {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
            {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
            BSL_PARAM_END};
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyPrvCtx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0),
            CRYPT_SUCCESS);
    } else if (strcasecmp(algorithm, "EC") == 0) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyPrvCtx, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0), CRYPT_SUCCESS);
    }

    uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    uint32_t dataLen = sizeof(data);
    uint8_t encrypt[TMP_BUFF_LEN];
    uint32_t encryptLen = TMP_BUFF_LEN;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkeyPrvCtx, data, dataLen, encrypt, &encryptLen), CRYPT_SUCCESS);
    uint8_t decrypt[TMP_BUFF_LEN];
    uint32_t decryptLen = TMP_BUFF_LEN;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkeyPrvCtx, encrypt, encryptLen, decrypt, &decryptLen), CRYPT_SUCCESS);
    ASSERT_TRUE(dataLen == decryptLen);
    ASSERT_TRUE(memcmp(data, decrypt, dataLen) == 0);

EXIT:
    AppPrintErrorUioUnInit();
    CRYPT_EAL_PkeyFreeCtx(pkeyPrvCtx);
    CRYPT_EAL_RandDeinitEx(NULL);
    remove(GENPKEY_PRV_FILE_PATH);
    remove(PKEY_PRV_FILE_PATH);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ENCKEY_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_ENCKEY_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ENCKEY_TC001(char *algorithm, char *pkeyopt, char *cipherAlg, int hashId)
{
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    char *genpkeyEncPrv[20] = {"genpkey", "-algorithm", algorithm, "-pkeyopt", pkeyopt, cipherAlg, "-pass", "pass:123456", "-out", GENPKEY_ENC_PRV_FILE_PATH};
    char *pkeyEncPrv[20] = {"pkey", "-in", GENPKEY_ENC_PRV_FILE_PATH, "-passin", "pass:123456", cipherAlg, "-passout", "pass:123456", "-out", PKEY_ENC_PRV_FILE_PATH};
    char *pkeyPub[20] = {"pkey", "-in", PKEY_ENC_PRV_FILE_PATH, "-passin", "pass:123456", "-pubout", "-out", PKEY_PUB_FILE_PATH};

    ASSERT_EQ(HITLS_GenPkeyMain(10, genpkeyEncPrv), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(10, pkeyEncPrv), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(8, pkeyPub), HITLS_APP_SUCCESS);
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    CRYPT_EAL_PkeyCtx *pkeyEncPrvCtx = NULL;
    CRYPT_EAL_PkeyCtx *pkeyPubCtx = NULL;
    uint8_t pwd[] = { '1', '2', '3', '4', '5', '6' };
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_ENCRYPT, PKEY_ENC_PRV_FILE_PATH,
        pwd, 6, &pkeyEncPrvCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(
        CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PUBKEY_SUBKEY, PKEY_PUB_FILE_PATH, NULL, 0, &pkeyPubCtx),
        CRYPT_SUCCESS);

    if (strcasecmp(algorithm, "RSA") == 0) {
        int32_t pkcsv15 = CRYPT_MD_SHA256;
        ASSERT_EQ(
            CRYPT_EAL_PkeyCtrl(pkeyEncPrvCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
            0);
        ASSERT_EQ(
            CRYPT_EAL_PkeyCtrl(pkeyPubCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
            0);
    }

    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen(pkeyEncPrvCtx);
    uint8_t *signdata = (uint8_t *)BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    uint32_t dataLen = sizeof(data);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyEncPrvCtx, hashId, data, dataLen, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyPubCtx, hashId, data, dataLen, signdata, signLen), CRYPT_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(signdata);
    CRYPT_EAL_PkeyFreeCtx(pkeyEncPrvCtx);
    CRYPT_EAL_PkeyFreeCtx(pkeyPubCtx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    remove(GENPKEY_ENC_PRV_FILE_PATH);
    remove(PKEY_ENC_PRV_FILE_PATH);
    remove(PKEY_PUB_FILE_PATH);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ENCKEY_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_ENCKEY_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ENCKEY_TC002(char *algorithm, char *pkeyopt, char *cipherAlg)
{
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    char *genpkeyEncPrv[20] = {"genpkey", "-algorithm", algorithm, "-pkeyopt", pkeyopt, cipherAlg, "-pass", "pass:123456", "-out", GENPKEY_ENC_PRV_FILE_PATH};
    char *pkeyEncPrv[20] = {"pkey", "-in", GENPKEY_ENC_PRV_FILE_PATH, "-passin", "pass:123456", cipherAlg, "-passout", "pass:123456", "-out", PKEY_ENC_PRV_FILE_PATH};

    ASSERT_EQ(HITLS_GenPkeyMain(10, genpkeyEncPrv), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_PkeyMain(10, pkeyEncPrv), HITLS_APP_SUCCESS);
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    CRYPT_EAL_PkeyCtx *pkeyEncPrvCtx = NULL;
    uint8_t pwd[] = { '1', '2', '3', '4', '5', '6' };
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_ENCRYPT, PKEY_ENC_PRV_FILE_PATH,
        pwd, 6, &pkeyEncPrvCtx),
        CRYPT_SUCCESS);

    if (strcasecmp(algorithm, "RSA") == 0) {
        SetRsaKeyInfo(pkeyEncPrvCtx);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyEncPrvCtx, CRYPT_CTRL_SET_RSA_OAEP_LABEL, NULL, 0), CRYPT_SUCCESS);
        int32_t hashId = CRYPT_MD_SHA1;
        BSL_Param oaepParam[3] = {
            {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
            {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
            BSL_PARAM_END};
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyEncPrvCtx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0),
            CRYPT_SUCCESS);
    } else if (strcasecmp(algorithm, "EC") == 0) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyEncPrvCtx, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0), CRYPT_SUCCESS);
    }

    uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    uint32_t dataLen = sizeof(data);
    uint8_t encrypt[TMP_BUFF_LEN];
    uint32_t encryptLen = TMP_BUFF_LEN;
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkeyEncPrvCtx, data, dataLen, encrypt, &encryptLen), CRYPT_SUCCESS);
    uint8_t decrypt[TMP_BUFF_LEN];
    uint32_t decryptLen = TMP_BUFF_LEN;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkeyEncPrvCtx, encrypt, encryptLen, decrypt, &decryptLen), CRYPT_SUCCESS);
    ASSERT_TRUE(dataLen == decryptLen);
    ASSERT_TRUE(memcmp(data, decrypt, dataLen) == 0);
EXIT:
    AppPrintErrorUioUnInit();
    CRYPT_EAL_PkeyFreeCtx(pkeyEncPrvCtx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    remove(GENPKEY_ENC_PRV_FILE_PATH);
    remove(PKEY_ENC_PRV_FILE_PATH);
    return;
}
/* END_CASE */
