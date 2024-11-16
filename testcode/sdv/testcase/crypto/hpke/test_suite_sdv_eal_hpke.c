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
/* END_HEADER */

#define HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN 133
#define HPKE_KEM_MAX_PUBLIC_KEY_LEN  133
#define HPKE_KEM_MAX_PRIVATE_KEY_LEN  66

#define HPKE_HKDF_MAX_EXTRACT_KEY_LEN  64

#define HPKE_KEM_MAX_SHARED_KEY_LEN  64

#define HPKE_AEAD_MAX_KEY_LEN  32
#define HPKE_AEAD_NONCE_LEN  12
#define HPKE_AEAD_TAG_LEN  16

static int32_t GenerateHpkeCtxSAndCtxR(int mode, CRYPT_HPKE_CipherSuite cipherSuite, Hex *info, Hex *ikmE, Hex *ikmR,
    CRYPT_EAL_HpkeCtx **ctxS, CRYPT_EAL_HpkeCtx **ctxR, CRYPT_EAL_PkeyCtx **pkeyS, CRYPT_EAL_PkeyCtx **pkeyR,
    uint8_t *encapsulatedKey, uint32_t *encapsulatedKeyLen)
{
    CRYPT_EAL_HpkeCtx *ctxS1 = NULL;
    CRYPT_EAL_HpkeCtx *ctxR1 = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS1 = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR1 = NULL;
    int32_t ret;
    
    ret = CRYPT_EAL_HpkeGenerateKeyPair(cipherSuite, ikmE->x, ikmE->len, &pkeyS1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_HpkeGenerateKeyPair(cipherSuite, ikmR->x, ikmR->len, &pkeyR1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pubR1;
    pubR1.id = CRYPT_EAL_PkeyGetId(pkeyR1);
    pubR1.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    uint8_t pubRKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    pubR1.key.eccPub.data = pubRKeyBuf;
    ret = CRYPT_EAL_PkeyGetPub(pkeyR1, &pubR1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctxS1 = CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_SENDER, mode, cipherSuite);
    ASSERT_TRUE(ctxS1 != NULL);

    ret = CRYPT_EAL_HpkeSetupSender(ctxS1, pkeyS1, info->x, info->len, pubR1.key.eccPub.data, pubR1.key.eccPub.len, encapsulatedKey, encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctxR1 = CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_RECIPIENT, mode, cipherSuite);
    ASSERT_TRUE(ctxR1 != NULL);

    ret = CRYPT_EAL_HpkeSetupRecipient(ctxR1, pkeyR1, info->x, info->len, encapsulatedKey, *encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    *ctxS = ctxS1; 
    *ctxR = ctxR1;
    *pkeyS = pkeyS1;
    *pkeyR = pkeyR1;
    return CRYPT_SUCCESS;
exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS1);
    CRYPT_EAL_HpkeFreeCtx(ctxR1);
    CRYPT_EAL_PkeyFreeCtx(pkeyS1);
    CRYPT_EAL_PkeyFreeCtx(pkeyR1);
    return ret;
}

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC001
 * @title  hpke key derivation test based on standard vectors.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC001(int mode, int kemId, int kdfId, int aeadId, Hex *info,
    Hex *ikmE, Hex *pkEm, Hex *skEm, Hex *ikmR, Hex *pkRm, Hex *skRm, Hex *enc,
    Hex *sharedSecret, Hex *keyScheduleContext, Hex *secret, Hex *key, Hex *baseNonce, Hex *exporterSecret)
{
    (void)secret;
    (void)keyScheduleContext;
    (void)key;
    (void)baseNonce;
    (void)exporterSecret;

    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    int32_t ret;
    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    uint8_t encapsulatedKey[HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN];
    uint32_t encapsulatedKeyLen = HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN;

    ret = GenerateHpkeCtxSAndCtxR(mode, cipherSuite, info, ikmE, ikmR, &ctxS, &ctxR, &pkeyS, &pkeyR, encapsulatedKey, &encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv priS;
    priS.id = CRYPT_EAL_PkeyGetId(pkeyS);
    priS.key.eccPrv.len = HPKE_KEM_MAX_PRIVATE_KEY_LEN;
    uint8_t priSKeyBuf[HPKE_KEM_MAX_PRIVATE_KEY_LEN];
    priS.key.eccPrv.data = priSKeyBuf;
    ret = CRYPT_EAL_PkeyGetPrv(pkeyS, &priS);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke priS cmp", priS.key.eccPrv.data, priS.key.eccPrv.len, skEm->x, skEm->len);

    CRYPT_EAL_PkeyPub pubS;
    pubS.id = CRYPT_EAL_PkeyGetId(pkeyS);
    pubS.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    uint8_t pubSKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    pubS.key.eccPub.data = pubSKeyBuf;
    ret = CRYPT_EAL_PkeyGetPub(pkeyS, &pubS);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke pubS cmp", pubS.key.eccPub.data, pubS.key.eccPub.len, pkEm->x, pkEm->len);

    CRYPT_EAL_PkeyPrv priR;
    priR.id = CRYPT_EAL_PkeyGetId(pkeyR);
    priR.key.eccPrv.len = HPKE_KEM_MAX_PRIVATE_KEY_LEN;
    uint8_t priRKeyBuf[HPKE_KEM_MAX_PRIVATE_KEY_LEN];
    priR.key.eccPrv.data = priRKeyBuf;
    ret = CRYPT_EAL_PkeyGetPrv(pkeyR, &priR);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke priR cmp", priR.key.eccPrv.data, priR.key.eccPrv.len, skRm->x, skRm->len);

    CRYPT_EAL_PkeyPub pubR;
    pubR.id = CRYPT_EAL_PkeyGetId(pkeyR);
    pubR.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    uint8_t pubRKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    pubR.key.eccPub.data = pubRKeyBuf;
    ret = CRYPT_EAL_PkeyGetPub(pkeyR, &pubR);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke pubR cmp", pubR.key.eccPub.data, pubR.key.eccPub.len, pkRm->x, pkRm->len);

    // check enc
    ASSERT_COMPARE("hpke enc cmp", encapsulatedKey, encapsulatedKeyLen, enc->x, enc->len);

    uint8_t sharedSecretBuf[HPKE_KEM_MAX_SHARED_KEY_LEN] = {0};
    uint32_t buffLen = HPKE_KEM_MAX_SHARED_KEY_LEN;
    ret = CRYPT_EAL_HpkeGetSharedSecret(ctxS, sharedSecretBuf, &buffLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke sharedSecret cmp", sharedSecretBuf, buffLen, sharedSecret->x, sharedSecret->len);
    
    (void)memset_s(sharedSecretBuf, 0, HPKE_KEM_MAX_SHARED_KEY_LEN, 0);
    buffLen = HPKE_KEM_MAX_SHARED_KEY_LEN;

    ret = CRYPT_EAL_HpkeGetSharedSecret(ctxR, sharedSecretBuf, &buffLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke sharedSecret cmp", sharedSecretBuf, buffLen, sharedSecret->x, sharedSecret->len);

exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC002
 * @title  hpke seal and open test based on standard vectors.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC002(int mode, int kemId, int kdfId, int aeadId, Hex *info, Hex *ikmE, Hex *ikmR, int seq, Hex *pt, Hex *aad, Hex *ct)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    int32_t ret;
    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    uint8_t encapsulatedKey[HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN];
    uint32_t encapsulatedKeyLen = HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN;

    ret = GenerateHpkeCtxSAndCtxR(mode, cipherSuite, info, ikmE, ikmR, &ctxS, &ctxR, &pkeyS, &pkeyR, encapsulatedKey, &encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint8_t cipher[200] = { 0 };
    uint32_t cipherLen = 200;
    ASSERT_EQ(CRYPT_EAL_HpkeSetSeq(ctxS, seq), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeSeal(ctxS, aad->x, aad->len, pt->x, pt->len, cipher, &cipherLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke seal cmp", cipher, cipherLen, ct->x, ct->len);
    uint64_t nextSeq;
    ASSERT_EQ(CRYPT_EAL_HpkeGetSeq(ctxS, &nextSeq), CRYPT_SUCCESS);
    ASSERT_EQ(nextSeq, seq + 1);

    uint8_t plain[200] = { 0 };
    uint32_t plainLen = 200;
    ASSERT_EQ(CRYPT_EAL_HpkeSetSeq(ctxR, seq), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeOpen(ctxR, aad->x, aad->len, cipher, cipherLen, plain, &plainLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke open cmp", plain, plainLen, pt->x, pt->len);
    ASSERT_EQ(CRYPT_EAL_HpkeGetSeq(ctxR, &nextSeq), CRYPT_SUCCESS);
    ASSERT_EQ(nextSeq, seq + 1);

exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC003
 * @title  hpke export secret test based on standard vectors.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC003(int mode, int kemId, int kdfId, int aeadId, Hex *info, Hex *ikmE, Hex *ikmR, Hex *exporterContext, int L, Hex *exportedValue)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    int32_t ret;
    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    uint8_t encapsulatedKey[HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN];
    uint32_t encapsulatedKeyLen = HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN;

    ret = GenerateHpkeCtxSAndCtxR(mode, cipherSuite, info, ikmE, ikmR, &ctxS, &ctxR, &pkeyS, &pkeyR, encapsulatedKey, &encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint8_t exportedValueBuf[HPKE_HKDF_MAX_EXTRACT_KEY_LEN] = {0};
    ret = CRYPT_EAL_HpkeExportSecret(ctxS, exporterContext->x, exporterContext->len, exportedValueBuf, L);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke S exportedValue cmp", exportedValueBuf, exportedValue->len, exportedValue->x, exportedValue->len);

    memset(exportedValueBuf, 0, HPKE_HKDF_MAX_EXTRACT_KEY_LEN);
    ret = CRYPT_EAL_HpkeExportSecret(ctxR, exporterContext->x, exporterContext->len, exportedValueBuf, L);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke R exportedValue cmp", exportedValueBuf, exportedValue->len, exportedValue->x, exportedValue->len);
exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
}
/* END_CASE */

static int32_t HpkeTestSealAndOpen(CRYPT_EAL_HpkeCtx *ctxS, CRYPT_EAL_HpkeCtx *ctxR)
{
    int32_t ret;
    uint8_t massage[100];
    uint32_t massageLen = 100;
    uint8_t plain[100];
    uint32_t plainLen = 100;
    uint8_t cipherText[116];
    uint32_t cipherTextLen = 116;
    int count = 200;
    while (count--) {
        ret = CRYPT_EAL_Randbytes(massage, massageLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ret = CRYPT_EAL_HpkeSeal(ctxS, NULL, 0, massage, massageLen, cipherText, &cipherTextLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ret = CRYPT_EAL_HpkeOpen(ctxR, NULL, 0, cipherText, cipherTextLen, plain, &plainLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_COMPARE("hpke Seal Open cmp", massage, massageLen, plain, plainLen);
    }

    count = 200;
    ret = CRYPT_EAL_HpkeSetSeq(ctxS, 10000000);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_HpkeSetSeq(ctxR, 10000000);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    while (count--) {
        ret = CRYPT_EAL_Randbytes(massage, massageLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ret = CRYPT_EAL_HpkeSeal(ctxS, NULL, 0, massage, massageLen, cipherText, &cipherTextLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ret = CRYPT_EAL_HpkeOpen(ctxR, NULL, 0, cipherText, cipherTextLen, plain, &plainLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_COMPARE("hpke Seal Open cmp", massage, massageLen, plain, plainLen);
    }

    uint64_t seqS;
    uint64_t seqR;
    ret = CRYPT_EAL_HpkeGetSeq(ctxS, &seqS);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_HpkeGetSeq(ctxR, &seqR);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(seqS, seqR);
    ASSERT_EQ(seqS, 10000200);
exit:
    return ret;
}

static int32_t HpkeRandomTest(CRYPT_HPKE_mode mode, CRYPT_HPKE_KEM_AlgId kemId, CRYPT_HPKE_KDF_AlgId kdfId, CRYPT_HPKE_AEAD_AlgId aeadId)
{
    int32_t ret;
    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    Hex info = { 0 };
    info.len = 16;
    uint8_t infoData[16] = { 0 };
    info.x = infoData;
    CRYPT_EAL_Randbytes(info.x, info.len);

    // prepare Recipient key
    ret = CRYPT_EAL_HpkeGenerateKeyPair(cipherSuite, NULL, 0, &pkeyS);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // prepare Recipient key
    ret = CRYPT_EAL_HpkeGenerateKeyPair(cipherSuite, NULL, 0, &pkeyR);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pubR;
    pubR.id = CRYPT_EAL_PkeyGetId(pkeyR);
    pubR.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    uint8_t pubRKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    pubR.key.eccPub.data = pubRKeyBuf;
    ret = CRYPT_EAL_PkeyGetPub(pkeyR, &pubR);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Sender init
    ctxS = CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_SENDER, mode, cipherSuite);
    ASSERT_TRUE(ctxS != NULL);

    uint8_t encapsulatedKey[HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN];
    uint32_t encapsulatedKeyLen = HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN;
    ret = CRYPT_EAL_HpkeSetupSender(ctxS, NULL, info.x, info.len, pubR.key.eccPub.data, pubR.key.eccPub.len, encapsulatedKey, &encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    CRYPT_EAL_HpkeFreeCtx(ctxS);

    ctxS = CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_SENDER, mode, cipherSuite);
    ASSERT_TRUE(ctxS != NULL);
    ret = CRYPT_EAL_HpkeSetupSender(ctxS, pkeyS, info.x, info.len, pubR.key.eccPub.data, pubR.key.eccPub.len, encapsulatedKey, &encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Recipient init
    ctxR = CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_RECIPIENT, mode, cipherSuite);
    ASSERT_TRUE(ctxR != NULL);

    ret = CRYPT_EAL_HpkeSetupRecipient(ctxR, pkeyR, info.x, info.len, encapsulatedKey, encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // ret = HpkeCheckParamSR(ctxS, ctxR);
    // ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = HpkeTestSealAndOpen(ctxS, ctxR);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
    return ret;
}

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC004
 * @title  test key derivation, seal and open randomly.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC004(void)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_HPKE_mode mode = CRYPT_HPKE_MODE_BASE;
    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384, CRYPT_KEM_DHKEM_P521_HKDF_SHA512, CRYPT_KEM_DHKEM_X25519_HKDF_SHA256};
    CRYPT_HPKE_KDF_AlgId kdfIds[] = {CRYPT_KDF_HKDF_SHA256, CRYPT_KDF_HKDF_SHA384, CRYPT_KDF_HKDF_SHA512};
    CRYPT_HPKE_AEAD_AlgId aeadIds[] = {CRYPT_AEAD_AES_128_GCM, CRYPT_AEAD_AES_256_GCM, CRYPT_AEAD_CHACHA20_POLY1305};

    size_t i;
    size_t j;
    size_t k;
    for (i = 0; i < sizeof(kemIds) / sizeof(CRYPT_HPKE_KEM_AlgId); i++) {
        for (j = 0; j < sizeof(kdfIds) / sizeof(CRYPT_HPKE_KDF_AlgId); j++) {
            for (k = 0; k < sizeof(aeadIds) / sizeof(CRYPT_HPKE_AEAD_AlgId); k++) {
                ASSERT_EQ(HpkeRandomTest(mode, kemIds[i], kdfIds[j], aeadIds[k]), CRYPT_SUCCESS);
            }
        }
    }
exit:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC005
 * @title  hpke abnormal test.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC005(void)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    int32_t ret;
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    CRYPT_HPKE_CipherSuite cipherSuite = {0, 0, 0};
    uint8_t massage[100];
    uint32_t massageLen = 100;
    uint8_t buff[100];
    uint32_t buffLen = 100;
    uint8_t cipherText[116];
    uint32_t cipherTextLen = 116;


    ctxS = CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_SENDER, CRYPT_HPKE_MODE_BASE, cipherSuite);
    ASSERT_TRUE(ctxS == NULL);

    ctxR = CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_RECIPIENT, CRYPT_HPKE_MODE_BASE, cipherSuite);
    ASSERT_TRUE(ctxR == NULL);

    // test sender
    cipherSuite.kemId = CRYPT_KEM_DHKEM_P256_HKDF_SHA256;
    cipherSuite.kdfId = CRYPT_KDF_HKDF_SHA256;
    cipherSuite.aeadId = CRYPT_AEAD_AES_128_GCM;

    ctxS = CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_SENDER, CRYPT_HPKE_MODE_BASE, cipherSuite);
    ASSERT_TRUE(ctxS != NULL);

    ret = CRYPT_EAL_HpkeSetupSender(ctxS, NULL, NULL, 0, NULL, 0, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_HpkeSeal(ctxS, NULL, 0, massage, massageLen, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, CRYPT_HPKE_ERR_CALL);

    ret = CRYPT_EAL_HpkeSeal(NULL, NULL, 0, massage, massageLen, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_HpkeSetSeq(NULL, 0);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_HpkeSetSeq(ctxS, 0xFFFFFFFFFFFFFFFF);
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);

    ret = CRYPT_EAL_HpkeOpen(ctxS, NULL, 0, massage, massageLen, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, CRYPT_HPKE_ERR_CALL);

    ret = CRYPT_EAL_HpkeExportSecret(ctxS, NULL, 0, buff, 0);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_HpkeExportSecret(ctxS, NULL, 0, buff, buffLen);
    ASSERT_EQ(ret, CRYPT_HPKE_ERR_CALL);

exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
}
/* END_CASE */

static CRYPT_EAL_HpkeCtx *GenHpkeCtxWithSharedSecret(CRYPT_HPKE_Role role, CRYPT_HPKE_mode mode,
    CRYPT_HPKE_CipherSuite cipherSuite, uint8_t *info, uint32_t infoLen, uint8_t *sharedSecret, uint32_t sharedSecretLen)
{
    CRYPT_EAL_HpkeCtx *ctx = NULL;

    ctx = CRYPT_EAL_HpkeNewCtx(role, mode, cipherSuite);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_HpkeSetSharedSecret(ctx, info, infoLen, sharedSecret, sharedSecretLen), CRYPT_SUCCESS);
    return ctx;
exit:
    CRYPT_EAL_HpkeFreeCtx(ctx);
    return NULL;
}

static int32_t HpkeTestImportSharedSecret(CRYPT_HPKE_mode mode, CRYPT_HPKE_CipherSuite cipherSuite)
{
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;

    uint32_t sharedSecretLen = 32; // CRYPT_KEM_DHKEM_X25519_HKDF_SHA256 CRYPT_KEM_DHKEM_P256_HKDF_SHA256
    if (cipherSuite.kemId == CRYPT_KEM_DHKEM_P384_HKDF_SHA384) {
        sharedSecretLen = 48;
    } else if (cipherSuite.kemId == CRYPT_KEM_DHKEM_P521_HKDF_SHA512) {
        sharedSecretLen = 64;
    }

    uint8_t sharedSecret[HPKE_KEM_MAX_SHARED_KEY_LEN];

    ctxS = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_SENDER, mode, cipherSuite, NULL, 0, sharedSecret, sharedSecretLen);
    ASSERT_TRUE(ctxS != NULL);

    ctxR = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_RECIPIENT, mode, cipherSuite, NULL, 0, sharedSecret, sharedSecretLen);
    ASSERT_TRUE(ctxR != NULL);

    ASSERT_EQ(HpkeTestSealAndOpen(ctxS, ctxR), CRYPT_SUCCESS);
exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    return CRYPT_SUCCESS;
}

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC006
 * @title  import shared secret test randomly.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC006(void)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_HPKE_mode mode = CRYPT_HPKE_MODE_BASE;
    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384, CRYPT_KEM_DHKEM_P521_HKDF_SHA512};
    CRYPT_HPKE_KDF_AlgId kdfIds[] = {CRYPT_KDF_HKDF_SHA256, CRYPT_KDF_HKDF_SHA384, CRYPT_KDF_HKDF_SHA512};
    CRYPT_HPKE_AEAD_AlgId aeadIds[] = {CRYPT_AEAD_AES_128_GCM, CRYPT_AEAD_AES_256_GCM, CRYPT_AEAD_CHACHA20_POLY1305};

    size_t i;
    size_t j;
    size_t k;
    
    for (i = 0; i < sizeof(kemIds) / sizeof(CRYPT_HPKE_KEM_AlgId); i++) {
        for (j = 0; j < sizeof(kdfIds) / sizeof(CRYPT_HPKE_KDF_AlgId); j++) {
            for (k = 0; k < sizeof(aeadIds) / sizeof(CRYPT_HPKE_AEAD_AlgId); k++) {
                CRYPT_HPKE_CipherSuite cipherSuite = {kemIds[i], kdfIds[j], aeadIds[k]};
                ASSERT_EQ(HpkeTestImportSharedSecret(mode, cipherSuite), CRYPT_SUCCESS);
            }
        }
    }
exit:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC007
 * @title  import sharedSecret and seal/open test based on standard vector.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC007(int mode, int kemId, int kdfId, int aeadId, Hex *info, Hex *sharedSecret, int seq, Hex *pt, Hex *aad, Hex *ct)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;

    ctxS = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_SENDER, mode, cipherSuite, info->x, info->len, sharedSecret->x, sharedSecret->len);
    ASSERT_TRUE(ctxS != NULL);

    ctxR = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_RECIPIENT, mode, cipherSuite, info->x, info->len, sharedSecret->x, sharedSecret->len);
    ASSERT_TRUE(ctxR != NULL);

    uint8_t cipher[200] = { 0 };
    uint32_t cipherLen = 200;
    ASSERT_EQ(CRYPT_EAL_HpkeSetSeq(ctxS, seq), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeSeal(ctxS, aad->x, aad->len, pt->x, pt->len, cipher, &cipherLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke seal cmp", cipher, cipherLen, ct->x, ct->len);
    uint64_t nextSeq;
    ASSERT_EQ(CRYPT_EAL_HpkeGetSeq(ctxS, &nextSeq), CRYPT_SUCCESS);
    ASSERT_EQ(nextSeq, seq + 1);

    uint8_t plain[200] = { 0 };
    uint32_t plainLen = 200;
    ASSERT_EQ(CRYPT_EAL_HpkeSetSeq(ctxR, seq), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeOpen(ctxR, aad->x, aad->len, cipher, cipherLen, plain, &plainLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke open cmp", plain, plainLen, pt->x, pt->len);
    ASSERT_EQ(CRYPT_EAL_HpkeGetSeq(ctxR, &nextSeq), CRYPT_SUCCESS);
    ASSERT_EQ(nextSeq, seq + 1);

exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC008
 * @title  import sharedSecret and export secret test based on standard vector.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC008(int mode, int kemId, int kdfId, int aeadId, Hex *info, Hex *sharedSecret, Hex *exporterContext, int L, Hex *exportedValue)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    int32_t ret;
    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;

    ctxS = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_SENDER, mode, cipherSuite, info->x, info->len, sharedSecret->x, sharedSecret->len);
    ASSERT_TRUE(ctxS != NULL);

    ctxR = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_RECIPIENT, mode, cipherSuite, info->x, info->len, sharedSecret->x, sharedSecret->len);
    ASSERT_TRUE(ctxR != NULL);

    uint8_t exportedValueBuf[HPKE_HKDF_MAX_EXTRACT_KEY_LEN] = {0};
    ret = CRYPT_EAL_HpkeExportSecret(ctxS, exporterContext->x, exporterContext->len, exportedValueBuf, L);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke S exportedValue cmp", exportedValueBuf, exportedValue->len, exportedValue->x, exportedValue->len);

    memset(exportedValueBuf, 0, HPKE_HKDF_MAX_EXTRACT_KEY_LEN);
    ret = CRYPT_EAL_HpkeExportSecret(ctxR, exporterContext->x, exporterContext->len, exportedValueBuf, L);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke R exportedValue cmp", exportedValueBuf, exportedValue->len, exportedValue->x, exportedValue->len);
exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC009
 * @title  hpke generate key pair test.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC009(void)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384, CRYPT_KEM_DHKEM_P521_HKDF_SHA512};
    CRYPT_HPKE_KDF_AlgId kdfIds[] = {CRYPT_KDF_HKDF_SHA256, CRYPT_KDF_HKDF_SHA384, CRYPT_KDF_HKDF_SHA512};
    CRYPT_HPKE_AEAD_AlgId aeadIds[] = {CRYPT_AEAD_AES_128_GCM, CRYPT_AEAD_AES_256_GCM, CRYPT_AEAD_CHACHA20_POLY1305};

    size_t i;
    size_t j;
    size_t k;
    
    for (i = 0; i < sizeof(kemIds) / sizeof(CRYPT_HPKE_KEM_AlgId); i++) {
        for (j = 0; j < sizeof(kdfIds) / sizeof(CRYPT_HPKE_KDF_AlgId); j++) {
            for (k = 0; k < sizeof(aeadIds) / sizeof(CRYPT_HPKE_AEAD_AlgId); k++) {
                CRYPT_HPKE_CipherSuite cipherSuite = {kemIds[i], kdfIds[j], aeadIds[k]};
                CRYPT_EAL_PkeyCtx *pctx = NULL;
                ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(cipherSuite, NULL, 0, &pctx), CRYPT_SUCCESS);
                CRYPT_EAL_PkeyFreeCtx(pctx);

                uint32_t ikmLen = 1024*1024;
                uint8_t *ikm = (uint8_t *)malloc(ikmLen);
                memset_s(ikm, ikmLen, 0xFF, ikmLen);
                ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(cipherSuite, ikm, ikmLen, &pctx), CRYPT_SUCCESS);
                CRYPT_EAL_PkeyFreeCtx(pctx);
                free(ikm);
            }
        }
    }
exit:
    return;
}
/* END_CASE */




// bash build_hitls.sh debug asan && bash build_sdv.sh run-tests=test_suite_sdv_eal_hpke asan verbose &&  bash execute_sdv.sh test_suite_sdv_eal_hpke
// bash build_hitls.sh debug asan && bash build_sdv.sh run-tests=test_suite_sdv_eal_hpke asan verbose &&  bash execute_sdv.sh test_suite_sdv_eal_hpke


// bash build_hitls.sh debug
// bash build_sdv.sh run-tests=test_suite_sdv_eal_hpke verbose debug
// bash execute_sdv.sh test_suite_sdv_eal_hpke
// bash execute_sdv.sh test_suite_sdv_eal_hpke SDV_CRYPT_EAL_HPKE_API_TC005