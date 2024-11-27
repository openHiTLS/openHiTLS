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
#include "securec.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_hpke.h"
#include "e2ee_key_exch.h"
/* END_HEADER */

#define HPKE_KEM_MAX_PUBLIC_KEY_LEN  133
#define HPKE_KEM_MAX_PRIVATE_KEY_LEN  66


static inline uint32_t Uint32ToBigEndian(uint32_t value) // 大部分是小端机器，可以考虑使用小端序？
{
    uint16_t a = 0x1213;
    uint8_t *p = (uint8_t *)&a;
    uint8_t *data = (uint8_t *)&value;
    if (p[0] == 0x13) { // little-endian
        return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | ((uint32_t)data[3]);
    } else {
        return value;
    }
}

static inline uint64_t Uint64ToBigEndian(uint64_t value) // 大部分是小端机器，可以考虑使用小端序？
{
    uint16_t a = 0x1213;
    uint8_t *p = (uint8_t *)&a;
    uint32_t *data = (uint32_t *)&value;
    if (p[0] == 0x13) { // little-endian
        return (uint64_t)Uint32ToBigEndian(data[0]) << 32 | (uint64_t)Uint32ToBigEndian(data[1]);
    } else {
        return value;
    }
}

static int32_t GetPubAndPrivKey(CRYPT_EAL_PkeyCtx *pkey, uint8_t *pubKey, uint32_t *pubKeyLen, uint8_t *priKey,
    uint32_t *priKeyLen)
{
    int32_t ret;
    CRYPT_EAL_PkeyPub pub = { 0 };
    pub.id = CRYPT_EAL_PkeyGetId(pkey);
    pub.key.eccPub.data = pubKey;
    pub.key.eccPub.len = *pubKeyLen;
    ret = CRYPT_EAL_PkeyGetPub(pkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_EAL_PkeyPrv priv = { 0 };
    priv.id = CRYPT_EAL_PkeyGetId(pkey);
    priv.key.eccPrv.data = priKey;
    priv.key.eccPrv.len = *priKeyLen;
    ret = CRYPT_EAL_PkeyGetPrv(pkey, &priv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    *pubKeyLen = pub.key.eccPub.len;
    *priKeyLen = priv.key.eccPrv.len;
    return ret;
}


#define E2EE_SERVER_KEY_NUM 5

static int32_t E2EE_test(E2EE_KEM_AlgId kemId, E2EE_KDF_AlgId kdfId, E2EE_AEAD_AlgId aeadId)
{
    int32_t ret = -1;
    CRYPT_HPKE_CipherSuite cipherSuite = {(CRYPT_HPKE_KEM_AlgId)kemId, (CRYPT_HPKE_KDF_AlgId)kdfId, (CRYPT_HPKE_AEAD_AlgId)aeadId};
    E2EE_AlgId e2eeCipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR[E2EE_SERVER_KEY_NUM] = {0};
    uint8_t pkeyRPubKeyBuf[E2EE_SERVER_KEY_NUM][HPKE_KEM_MAX_PUBLIC_KEY_LEN] = {0};
    uint32_t pkeyRPubKeyBufLen[E2EE_SERVER_KEY_NUM] = {0};
    uint8_t pkeyRPrivKeyBuf[E2EE_SERVER_KEY_NUM][HPKE_KEM_MAX_PRIVATE_KEY_LEN] = {0};
    uint32_t pkeyRPrivKeyBufLen[E2EE_SERVER_KEY_NUM] = {0};

    Hex info = { 0 };
    info.len = 16;
    uint8_t infoData[16] = { 0 };
    info.x = infoData;
    CRYPT_EAL_Randbytes(info.x, info.len);

    // prepare Recipient key
    ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, NULL, 0, &pkeyS), CRYPT_SUCCESS);
    int i;
    for (i = 0; i < E2EE_SERVER_KEY_NUM; i++) {
        ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL,cipherSuite, NULL, 0, &pkeyR[i]), CRYPT_SUCCESS);
        pkeyRPubKeyBufLen[i] = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
        pkeyRPrivKeyBufLen[i] = HPKE_KEM_MAX_PRIVATE_KEY_LEN;
        ASSERT_EQ(GetPubAndPrivKey(pkeyR[i], pkeyRPubKeyBuf[i], &pkeyRPubKeyBufLen[i], pkeyRPrivKeyBuf[i], &pkeyRPrivKeyBufLen[i]), CRYPT_SUCCESS);
    }

    E2EE_ClientCtx *client = E2EE_ClientCreate(e2eeCipherSuite);
    ASSERT_TRUE(client != NULL);
    ASSERT_EQ(E2EE_ClientInit(client, pkeyRPubKeyBuf[0], pkeyRPubKeyBufLen[0], info.x, info.len), CRYPT_SUCCESS);

    E2EE_ServerCtx *server = E2EE_ServerCreate();
    ASSERT_TRUE(server != NULL);

    E2EE_KeyType type = E2EE_ECC_P256;
    if (kemId == E2EE_X25519_HKDF_SHA256) {
        type = E2EE_X25519;
    } else if (kemId == E2EE_P256_HKDF_SHA256) {
        type = E2EE_ECC_P256;
    } else if (kemId == E2EE_P384_HKDF_SHA384) {
        type = E2EE_ECC_P384;
    } else if (kemId == E2EE_P521_HKDF_SHA512) {
        type = E2EE_ECC_P521;
    }

    E2EE_ServerKeyExchInfo keyExchInfo[] = {
        {type, pkeyRPrivKeyBuf[0], pkeyRPrivKeyBufLen[0], info.x, info.len},
        {type, pkeyRPrivKeyBuf[1], pkeyRPrivKeyBufLen[1], info.x, info.len},
        {type, pkeyRPrivKeyBuf[2], pkeyRPrivKeyBufLen[2], info.x, info.len},
        {type, pkeyRPrivKeyBuf[3], pkeyRPrivKeyBufLen[3], info.x, info.len},
        {type, pkeyRPrivKeyBuf[4], pkeyRPrivKeyBufLen[4], info.x, info.len} };
    ASSERT_EQ(E2EE_ServerInit(server, keyExchInfo, E2EE_SERVER_KEY_NUM), CRYPT_SUCCESS);

    uint8_t *plain = NULL;
    uint32_t plainLen;
    uint8_t *plainTmp = NULL;
    uint32_t plainLenTmp;
    uint8_t *cipherText = NULL;
    uint32_t cipherTextLen;

    uint64_t count = 9;
    while (count--) {
        
        ASSERT_EQ(CRYPT_EAL_Randbytes((uint8_t *)&plainLen, sizeof(plainLen)), CRYPT_SUCCESS);
        plainLen = plainLen % 65535 + 1;
        plain = (uint8_t *)malloc(plainLen);
        ASSERT_TRUE(plain != NULL);
        ASSERT_EQ(CRYPT_EAL_Randbytes(plain, plainLen), CRYPT_SUCCESS);

        plainLenTmp = plainLen;
        plainTmp = (uint8_t *)malloc(plainLen);
        ASSERT_TRUE(plainTmp != NULL);

        ASSERT_EQ(E2EE_ClientEncrypt(client, plain, plainLen, NULL, 0, NULL, &cipherTextLen), CRYPT_SUCCESS);

        cipherText = (uint8_t *)malloc(cipherTextLen);
        ASSERT_TRUE(cipherText != NULL);

        ASSERT_EQ(E2EE_ClientEncrypt(client, plain, plainLen, NULL, 0, cipherText, &cipherTextLen), CRYPT_SUCCESS);

        // printf("plainLen = %d, cipherTextLen = %d\n", plainLen, cipherTextLen);

        ASSERT_EQ(E2EE_ServerDecrypt(server, cipherText, cipherTextLen, NULL, 0, plainTmp, &plainLenTmp), CRYPT_SUCCESS);
        ASSERT_COMPARE("hpke Seal Open cmp", plain, plainLen, plainTmp, plainLenTmp);

        ASSERT_EQ(E2EE_ServerEncrypt(server, plain, plainLen, NULL, 0, NULL, &cipherTextLen), CRYPT_SUCCESS);

        ASSERT_EQ(E2EE_ServerEncrypt(server, plain, plainLen, NULL, 0, cipherText, &cipherTextLen), CRYPT_SUCCESS);

        ASSERT_EQ(E2EE_ClientDecrypt(client, cipherText, cipherTextLen, NULL, 0, plainTmp, &plainLenTmp), CRYPT_SUCCESS);

        ASSERT_COMPARE("e2ee en/de cmp", plain, plainLen, plainTmp, plainLenTmp);


        free(plain);
        plain = NULL;
        free(plainTmp);
        plainTmp = NULL;
        free(cipherText);
        cipherText = NULL;
    }
    ret = CRYPT_SUCCESS;
exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR[0]);
    CRYPT_EAL_PkeyFreeCtx(pkeyR[1]);
    CRYPT_EAL_PkeyFreeCtx(pkeyR[2]);
    CRYPT_EAL_PkeyFreeCtx(pkeyR[3]);
    CRYPT_EAL_PkeyFreeCtx(pkeyR[4]);
    E2EE_ClientDestroy(client);
    E2EE_ServerDestroy(server);
    free(plain);
    free(plainTmp);
    free(cipherText);
    return ret;
}

static int32_t KemEncapsulate(void *callbackArg, E2EE_KEM_AlgId kemId, uint8_t *serverPubKey,
    uint32_t serverPubKeyLen, E2EE_KemEncapsulateResult *out)
{
    (void)callbackArg;
    int32_t ret = -1;
    CRYPT_HPKE_CipherSuite cipherSuite = {(CRYPT_HPKE_KEM_AlgId)kemId, CRYPT_KDF_HKDF_SHA256, CRYPT_AEAD_AES_128_GCM};
    CRYPT_EAL_HpkeCtx *hpkeCtx = CRYPT_EAL_HpkeNewCtx(NULL, NULL, CRYPT_HPKE_SENDER, CRYPT_HPKE_MODE_BASE, cipherSuite);
    ASSERT_TRUE(hpkeCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_HpkeSetupSender(hpkeCtx, NULL, 0, 0, serverPubKey, serverPubKeyLen, out->encapsulatedKey, &out->encapsulatedKeyLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeGetSharedSecret(hpkeCtx, out->sharedSecret, &out->sharedSecretLen), CRYPT_SUCCESS);
    ret = CRYPT_SUCCESS;
exit:
    CRYPT_EAL_HpkeFreeCtx(hpkeCtx);
    return ret;
}

CRYPT_EAL_PkeyCtx *g_pkeyR = NULL;
static int32_t KemDecapsulate(void *callbackArg, E2EE_KEM_AlgId kemId, uint8_t *encapsulatedKey,
    uint32_t encapsulatedKeyLen, uint8_t *pubKeyId, uint32_t pubKeyIdLen, E2EE_KemDecapsulateResult *out)
{
    (void)callbackArg;
    (void)pubKeyId;
    (void)pubKeyIdLen;
    int32_t ret = -1;
    CRYPT_HPKE_CipherSuite cipherSuite = {(CRYPT_HPKE_KEM_AlgId)kemId, CRYPT_KDF_HKDF_SHA256, CRYPT_AEAD_AES_128_GCM};
    CRYPT_EAL_HpkeCtx *hpkeCtx = CRYPT_EAL_HpkeNewCtx(NULL, NULL, CRYPT_HPKE_RECIPIENT, CRYPT_HPKE_MODE_BASE, cipherSuite);
    ASSERT_TRUE(hpkeCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_HpkeSetupRecipient(hpkeCtx, g_pkeyR, NULL, 0, encapsulatedKey, encapsulatedKeyLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeGetSharedSecret(hpkeCtx, out->sharedSecret, &out->sharedSecretLen), CRYPT_SUCCESS);
    memset_s(out->info, 16, 0, 16);
    out->infoLen = 16;
    ret = CRYPT_SUCCESS;
exit:
    CRYPT_EAL_HpkeFreeCtx(hpkeCtx);
    return ret;
}

static int32_t E2EE_test2(E2EE_KEM_AlgId kemId, E2EE_KDF_AlgId kdfId, E2EE_AEAD_AlgId aeadId)
{
    int32_t ret = -1;
    CRYPT_HPKE_CipherSuite cipherSuite = {(CRYPT_HPKE_KEM_AlgId)kemId, (CRYPT_HPKE_KDF_AlgId)kdfId, (CRYPT_HPKE_AEAD_AlgId)aeadId};
    E2EE_AlgId e2eeCipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR[E2EE_SERVER_KEY_NUM] = {0};
    uint8_t pkeyRPubKeyBuf[E2EE_SERVER_KEY_NUM][HPKE_KEM_MAX_PUBLIC_KEY_LEN] = {0};
    uint32_t pkeyRPubKeyBufLen[E2EE_SERVER_KEY_NUM] = {0};
    uint8_t pkeyRPrivKeyBuf[E2EE_SERVER_KEY_NUM][HPKE_KEM_MAX_PRIVATE_KEY_LEN] = {0};
    uint32_t pkeyRPrivKeyBufLen[E2EE_SERVER_KEY_NUM] = {0};

    Hex info = { 0 };
    info.len = 16;
    uint8_t infoData[16] = { 0 };
    info.x = infoData;
    // CRYPT_EAL_Randbytes(info.x, info.len);
    memset_s(infoData, 16, 0, 16);

    // prepare Recipient key
    ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, NULL, 0, &pkeyS), CRYPT_SUCCESS);
    int i;
    for (i = 0; i < E2EE_SERVER_KEY_NUM; i++) {
        ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL,cipherSuite, NULL, 0, &pkeyR[i]), CRYPT_SUCCESS);
        pkeyRPubKeyBufLen[i] = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
        pkeyRPrivKeyBufLen[i] = HPKE_KEM_MAX_PRIVATE_KEY_LEN;
        ASSERT_EQ(GetPubAndPrivKey(pkeyR[i], pkeyRPubKeyBuf[i], &pkeyRPubKeyBufLen[i], pkeyRPrivKeyBuf[i], &pkeyRPrivKeyBufLen[i]), CRYPT_SUCCESS);
    }

    E2EE_ClientCtx *client = E2EE_ClientCreate(e2eeCipherSuite);
    ASSERT_TRUE(client != NULL);

    E2EE_KemEncapsulateCallbackFunc keyDeriveFunc = KemEncapsulate;
    E2EE_SetClientKemCallback(client, keyDeriveFunc, NULL);

    ASSERT_EQ(E2EE_ClientInit(client, pkeyRPubKeyBuf[0], pkeyRPubKeyBufLen[0], info.x, info.len), CRYPT_SUCCESS);

    // g_pkeyR = CRYPT_EAL_PkeyNewCtx(CRYPT_EAL_PkeyGetId(pkeyR[0]));
    // ASSERT_TRUE(g_pkeyR != NULL);
    // ret = CRYPT_EAL_PkeyCopyCtx(g_pkeyR, pkeyR[0]);
    // ASSERT_EQ(ret, CRYPT_SUCCESS);

    g_pkeyR = CRYPT_EAL_PkeyDupCtx(pkeyR[0]);
    ASSERT_TRUE(g_pkeyR != NULL);

    E2EE_ServerCtx *server = E2EE_ServerCreate();
    ASSERT_TRUE(server != NULL);

    E2EE_SetServerKemCallback(server, KemDecapsulate, NULL);

    E2EE_KeyType type = E2EE_ECC_P256;
    if (kemId == E2EE_X25519_HKDF_SHA256) {
        type = E2EE_X25519;
    } else if (kemId == E2EE_P256_HKDF_SHA256) {
        type = E2EE_ECC_P256;
    } else if (kemId == E2EE_P384_HKDF_SHA384) {
        type = E2EE_ECC_P384;
    } else if (kemId == E2EE_P521_HKDF_SHA512) {
        type = E2EE_ECC_P521;
    }

    E2EE_ServerKeyExchInfo keyExchInfo[] = {
        {type, pkeyRPrivKeyBuf[0], pkeyRPrivKeyBufLen[0], info.x, info.len},
        {type, pkeyRPrivKeyBuf[1], pkeyRPrivKeyBufLen[1], info.x, info.len},
        {type, pkeyRPrivKeyBuf[2], pkeyRPrivKeyBufLen[2], info.x, info.len},
        {type, pkeyRPrivKeyBuf[3], pkeyRPrivKeyBufLen[3], info.x, info.len},
        {type, pkeyRPrivKeyBuf[4], pkeyRPrivKeyBufLen[4], info.x, info.len} };
    ASSERT_EQ(E2EE_ServerInit(server, keyExchInfo, 0), CRYPT_SUCCESS);

    uint8_t *plain = NULL;
    uint32_t plainLen;
    uint8_t *plainTmp = NULL;
    uint32_t plainLenTmp;
    uint8_t *cipherText = NULL;
    uint32_t cipherTextLen;

    uint64_t count = 9;
    while (count--) {
        
        ASSERT_EQ(CRYPT_EAL_Randbytes((uint8_t *)&plainLen, sizeof(plainLen)), CRYPT_SUCCESS);
        plainLen = plainLen % 65535 + 1;
        plain = (uint8_t *)malloc(plainLen);
        ASSERT_TRUE(plain != NULL);
        ASSERT_EQ(CRYPT_EAL_Randbytes(plain, plainLen), CRYPT_SUCCESS);

        plainLenTmp = plainLen;
        plainTmp = (uint8_t *)malloc(plainLen);
        ASSERT_TRUE(plainTmp != NULL);

        ASSERT_EQ(E2EE_ClientEncrypt(client, plain, plainLen, NULL, 0, NULL, &cipherTextLen), CRYPT_SUCCESS);

        cipherText = (uint8_t *)malloc(cipherTextLen);
        ASSERT_TRUE(cipherText != NULL);

        ASSERT_EQ(E2EE_ClientEncrypt(client, plain, plainLen, NULL, 0, cipherText, &cipherTextLen), CRYPT_SUCCESS);

        // printf("plainLen = %d, cipherTextLen = %d\n", plainLen, cipherTextLen);

        ASSERT_EQ(E2EE_ServerDecrypt(server, cipherText, cipherTextLen, NULL, 0, plainTmp, &plainLenTmp), CRYPT_SUCCESS);
        ASSERT_COMPARE("hpke Seal Open cmp", plain, plainLen, plainTmp, plainLenTmp);

        ASSERT_EQ(E2EE_ServerEncrypt(server, plain, plainLen, NULL, 0, NULL, &cipherTextLen), CRYPT_SUCCESS);

        ASSERT_EQ(E2EE_ServerEncrypt(server, plain, plainLen, NULL, 0, cipherText, &cipherTextLen), CRYPT_SUCCESS);

        ASSERT_EQ(E2EE_ClientDecrypt(client, cipherText, cipherTextLen, NULL, 0, plainTmp, &plainLenTmp), CRYPT_SUCCESS);

        ASSERT_COMPARE("e2ee en/de cmp", plain, plainLen, plainTmp, plainLenTmp);


        free(plain);
        plain = NULL;
        free(plainTmp);
        plainTmp = NULL;
        free(cipherText);
        cipherText = NULL;
    }
    ret = CRYPT_SUCCESS;
exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR[0]);
    CRYPT_EAL_PkeyFreeCtx(pkeyR[1]);
    CRYPT_EAL_PkeyFreeCtx(pkeyR[2]);
    CRYPT_EAL_PkeyFreeCtx(pkeyR[3]);
    CRYPT_EAL_PkeyFreeCtx(pkeyR[4]);
    CRYPT_EAL_PkeyFreeCtx(g_pkeyR);
    E2EE_ClientDestroy(client);
    E2EE_ServerDestroy(server);
    free(plain);
    free(plainTmp);
    free(cipherText);
    // exit(0);
    return ret;
}

/**
 * @test   SDV_CRYPT_E2EE_API_TC001
 * @title  test e2ee
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_E2EE_API_TC001(void)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    E2EE_KEM_AlgId kemIds[] = {E2EE_P256_HKDF_SHA256, E2EE_P384_HKDF_SHA384, E2EE_P521_HKDF_SHA512, E2EE_X25519_HKDF_SHA256};
    E2EE_KDF_AlgId kdfIds[] = {E2EE_HKDF_SHA256, E2EE_HKDF_SHA384, E2EE_HKDF_SHA512};
    E2EE_AEAD_AlgId aeadIds[] = {E2EE_AES_128_GCM, E2EE_AES_256_GCM, E2EE_CHACHA20_POLY1305};

    size_t i;
    size_t j;
    size_t k;
    for (i = 0; i < sizeof(kemIds) / sizeof(CRYPT_HPKE_KEM_AlgId); i++) {
        for (j = 0; j < sizeof(kdfIds) / sizeof(CRYPT_HPKE_KDF_AlgId); j++) {
            for (k = 0; k < sizeof(aeadIds) / sizeof(CRYPT_HPKE_AEAD_AlgId); k++) {
                printf("kemId = %d, kdfId = %d, aeadId = %d\n", kemIds[i], kdfIds[j], aeadIds[k]);
                ASSERT_EQ(E2EE_test(kemIds[i], kdfIds[j], aeadIds[k]), CRYPT_SUCCESS);
                ASSERT_EQ(E2EE_test2(kemIds[i], kdfIds[j], aeadIds[k]), CRYPT_SUCCESS);
            }
        }
    }

exit:
    return;
}
/* END_CASE */

// bash build_hitls.sh shared debug && bash build_sdv.sh run-tests=test_suite_sdv_e2ee debug verbose &&  bash execute_sdv.sh test_suite_sdv_e2ee
// bash build_hitls.sh shared debug asan && bash build_sdv.sh run-tests=test_suite_sdv_e2ee asan verbose &&  bash execute_sdv.sh test_suite_sdv_e2ee


// bash build_hitls.sh debug
// bash build_sdv.sh run-tests=test_suite_sdv_e2ee verbose debug
// bash execute_sdv.sh test_suite_sdv_e2ee
// bash execute_sdv.sh test_suite_sdv_e2ee