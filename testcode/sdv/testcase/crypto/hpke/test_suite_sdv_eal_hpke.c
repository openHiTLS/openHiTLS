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

#define HPKE_ERR -1

static int32_t GenerateHpkeCtxSAndCtxR(int mode, CRYPT_HPKE_CipherSuite cipherSuite, Hex *info, Hex *psk, Hex *pskId,
    Hex *ikmE, Hex *ikmR, Hex *ikmS, CRYPT_EAL_HpkeCtx **ctxS, CRYPT_EAL_HpkeCtx **ctxR,
    CRYPT_EAL_PkeyCtx **pkeyE, CRYPT_EAL_PkeyCtx **pkeyR, CRYPT_EAL_PkeyCtx **pkeyS,
    uint8_t *encapsulatedKey, uint32_t *encapsulatedKeyLen)
{
    CRYPT_EAL_HpkeCtx *ctxS1 = NULL;
    CRYPT_EAL_HpkeCtx *ctxR1 = NULL;
    CRYPT_EAL_PkeyCtx *pkeyE1 = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR1 = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS1 = NULL;

    ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, ikmE->x, ikmE->len, &pkeyE1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, ikmR->x, ikmR->len, &pkeyR1), CRYPT_SUCCESS);
    
    if(mode == CRYPT_HPKE_MODE_AUTH || mode ==CRYPT_HPKE_MODE_AUTH_PSK) {
        ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, ikmS->x, ikmS->len, &pkeyS1), CRYPT_SUCCESS);
    }

    CRYPT_EAL_PkeyPub pubR1;
    pubR1.id = CRYPT_EAL_PkeyGetId(pkeyR1);
    pubR1.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    uint8_t pubRKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    pubR1.key.eccPub.data = pubRKeyBuf;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkeyR1, &pubR1), CRYPT_SUCCESS);

    ctxS1 = CRYPT_EAL_HpkeNewCtx(NULL, NULL, CRYPT_HPKE_SENDER, mode, cipherSuite);
    ASSERT_TRUE(ctxS1 != NULL);

    if(mode == CRYPT_HPKE_MODE_PSK || mode == CRYPT_HPKE_MODE_AUTH_PSK) {
        ASSERT_EQ(CRYPT_EAL_HpkeSetPsk(ctxS1, psk->x, psk->len , pskId->x, pskId->len), CRYPT_SUCCESS);
    }
   
    if(mode == CRYPT_HPKE_MODE_AUTH || mode ==CRYPT_HPKE_MODE_AUTH_PSK) {
        ASSERT_EQ(CRYPT_EAL_HpkeSetAuthPriKey(ctxS1, pkeyS1),CRYPT_SUCCESS);    
    }

    ASSERT_EQ(CRYPT_EAL_HpkeSetupSender(ctxS1, pkeyE1, info->x, info->len, pubR1.key.eccPub.data, 
            pubR1.key.eccPub.len, encapsulatedKey, encapsulatedKeyLen), CRYPT_SUCCESS);

    ctxR1 = CRYPT_EAL_HpkeNewCtx(NULL, NULL, CRYPT_HPKE_RECIPIENT, mode, cipherSuite);
    ASSERT_TRUE(ctxR1 != NULL);

    if(mode == CRYPT_HPKE_MODE_PSK || mode == CRYPT_HPKE_MODE_AUTH_PSK){
        ASSERT_EQ(CRYPT_EAL_HpkeSetPsk(ctxR1, psk->x, psk->len , pskId->x, pskId->len), CRYPT_SUCCESS);
    }

    if(mode == CRYPT_HPKE_MODE_AUTH || mode ==CRYPT_HPKE_MODE_AUTH_PSK){
        CRYPT_EAL_PkeyPub pubS1;
        pubS1.id = CRYPT_EAL_PkeyGetId(pkeyS1);
        pubS1.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
        uint8_t pubSKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
        pubS1.key.eccPub.data = pubSKeyBuf;
        ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkeyS1, &pubS1), CRYPT_SUCCESS);

        ASSERT_EQ(CRYPT_EAL_HpkeSetAuthPubKey(ctxR1, pubS1.key.eccPub.data, pubS1.key.eccPub.len),CRYPT_SUCCESS);
    }
 
    ASSERT_EQ(CRYPT_EAL_HpkeSetupRecipient(ctxR1, pkeyR1, info->x, info->len, encapsulatedKey, *encapsulatedKeyLen), CRYPT_SUCCESS);
  
    *ctxS = ctxS1; 
    *ctxR = ctxR1;
    *pkeyS = pkeyS1;
    *pkeyR = pkeyR1;
    *pkeyE = pkeyE1;
    return CRYPT_SUCCESS;
EXIT:
    CRYPT_EAL_HpkeFreeCtx(ctxS1);
    CRYPT_EAL_HpkeFreeCtx(ctxR1);
    CRYPT_EAL_PkeyFreeCtx(pkeyS1);
    CRYPT_EAL_PkeyFreeCtx(pkeyR1);
    CRYPT_EAL_PkeyFreeCtx(pkeyE1);
    return HPKE_ERR;
}

/**
 * @test   SDV_CRYPT_EAL_HPKE_KEM_TC001
 * @title  hpke key derivation test based on standard vectors.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_KEM_TC001(int mode, int kemId, int kdfId, int aeadId, Hex *info, Hex *psk, Hex *pskId,
    Hex *ikmE, Hex *pkEm, Hex *skEm, Hex *ikmR, Hex *pkRm, Hex *skRm, Hex *ikmS, Hex *pkSm, Hex *skSm,
    Hex *enc, Hex *sharedSecret, Hex *keyScheduleContext, Hex *secret, Hex *key, Hex *baseNonce, Hex *exporterSecret)
{
    (void)secret;
    (void)keyScheduleContext;
    (void)key;
    (void)baseNonce;
    (void)exporterSecret;
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyE = NULL;
    uint8_t encapsulatedKey[HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN];
    uint32_t encapsulatedKeyLen = HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN;

    ASSERT_EQ(GenerateHpkeCtxSAndCtxR(mode, cipherSuite, info, psk, pskId, ikmE, ikmR, ikmS, &ctxS, &ctxR, &pkeyE, &pkeyR, &pkeyS,
        encapsulatedKey, &encapsulatedKeyLen), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv priE;
    priE.id = CRYPT_EAL_PkeyGetId(pkeyE);
    priE.key.eccPrv.len = HPKE_KEM_MAX_PRIVATE_KEY_LEN;
    uint8_t priEKeyBuf[HPKE_KEM_MAX_PRIVATE_KEY_LEN];
    priE.key.eccPrv.data = priEKeyBuf;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkeyE, &priE), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke priE cmp", priE.key.eccPrv.data, priE.key.eccPrv.len, skEm->x, skEm->len);
    
    CRYPT_EAL_PkeyPub pubE;
    pubE.id = CRYPT_EAL_PkeyGetId(pkeyE);
    pubE.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    uint8_t pubEKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    pubE.key.eccPub.data = pubEKeyBuf;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkeyE, &pubE), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke pubE cmp", pubE.key.eccPub.data, pubE.key.eccPub.len, pkEm->x, pkEm->len); 

    CRYPT_EAL_PkeyPrv priR;
    priR.id = CRYPT_EAL_PkeyGetId(pkeyR);
    priR.key.eccPrv.len = HPKE_KEM_MAX_PRIVATE_KEY_LEN;
    uint8_t priRKeyBuf[HPKE_KEM_MAX_PRIVATE_KEY_LEN];
    priR.key.eccPrv.data = priRKeyBuf;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkeyR, &priR), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke priR cmp", priR.key.eccPrv.data, priR.key.eccPrv.len, skRm->x, skRm->len);

    CRYPT_EAL_PkeyPub pubR;
    pubR.id = CRYPT_EAL_PkeyGetId(pkeyR);
    pubR.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    uint8_t pubRKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    pubR.key.eccPub.data = pubRKeyBuf;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkeyR, &pubR), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke pubR cmp", pubR.key.eccPub.data, pubR.key.eccPub.len, pkRm->x, pkRm->len);
  
   if(mode == CRYPT_HPKE_MODE_AUTH || mode ==CRYPT_HPKE_MODE_AUTH_PSK){ 
    CRYPT_EAL_PkeyPrv priS;
    priS.id = CRYPT_EAL_PkeyGetId(pkeyS);
    priS.key.eccPrv.len = HPKE_KEM_MAX_PRIVATE_KEY_LEN;
    uint8_t priSKeyBuf[HPKE_KEM_MAX_PRIVATE_KEY_LEN];
    priS.key.eccPrv.data = priSKeyBuf;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkeyS, &priS), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke priS cmp", priS.key.eccPrv.data, priS.key.eccPrv.len, skSm->x, skSm->len);

    CRYPT_EAL_PkeyPub pubS;
    pubS.id = CRYPT_EAL_PkeyGetId(pkeyS);
    pubS.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    uint8_t pubSKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    pubS.key.eccPub.data = pubSKeyBuf;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkeyS, &pubS), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke pubS cmp", pubS.key.eccPub.data, pubS.key.eccPub.len, pkSm->x, pkSm->len);
 }    
 
    // check enc
    ASSERT_COMPARE("hpke enc cmp", encapsulatedKey, encapsulatedKeyLen, enc->x, enc->len);

    uint8_t sharedSecretBuf[HPKE_KEM_MAX_SHARED_KEY_LEN] = {0};
    uint32_t buffLen = HPKE_KEM_MAX_SHARED_KEY_LEN;
    ASSERT_EQ(CRYPT_EAL_HpkeGetSharedSecret(ctxS, sharedSecretBuf, &buffLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke S sharedSecret cmp", sharedSecretBuf, buffLen, sharedSecret->x, sharedSecret->len);
    
    (void)memset_s(sharedSecretBuf, 0, HPKE_KEM_MAX_SHARED_KEY_LEN, 0);
    buffLen = HPKE_KEM_MAX_SHARED_KEY_LEN;

    ASSERT_EQ(CRYPT_EAL_HpkeGetSharedSecret(ctxR, sharedSecretBuf, &buffLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke R sharedSecret cmp", sharedSecretBuf, buffLen, sharedSecret->x, sharedSecret->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
    CRYPT_EAL_PkeyFreeCtx(pkeyE);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_AEAD_TC001
 * @title  hpke seal and open test based on standard vectors.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_AEAD_TC001(int mode, int kemId, int kdfId, int aeadId, Hex *info, Hex *psk, Hex *pskId,
    Hex *ikmE, Hex *ikmR, Hex *ikmS,int seq, Hex *pt, Hex *aad, Hex *ct)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyE = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    uint8_t encapsulatedKey[HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN];
    uint32_t encapsulatedKeyLen = HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN;

    ASSERT_EQ(GenerateHpkeCtxSAndCtxR(mode, cipherSuite, info, psk, pskId, ikmE, ikmR, ikmS, &ctxS, &ctxR, &pkeyE, &pkeyR, &pkeyS,
        encapsulatedKey, &encapsulatedKeyLen), CRYPT_SUCCESS);

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
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyE);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_EXPORT_SECRET_TC001
 * @title  hpke export secret test based on standard vectors.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_EXPORT_SECRET_TC001(int mode, int kemId, int kdfId, int aeadId, Hex *info, Hex *psk, Hex *pskId,
    Hex *ikmE, Hex *ikmR, Hex *ikmS, Hex *exporterContext, int L, Hex *exportedValue)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyE = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    uint8_t encapsulatedKey[HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN];
    uint32_t encapsulatedKeyLen = HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN;

    ASSERT_EQ(GenerateHpkeCtxSAndCtxR(mode, cipherSuite, info, psk, pskId, ikmE, ikmR, ikmS, &ctxS, &ctxR,
        &pkeyE, &pkeyR, &pkeyS, encapsulatedKey, &encapsulatedKeyLen), CRYPT_SUCCESS);

    uint8_t exportedValueBuf[HPKE_HKDF_MAX_EXTRACT_KEY_LEN] = {0};
    ASSERT_EQ(CRYPT_EAL_HpkeExportSecret(ctxS, exporterContext->x, exporterContext->len, exportedValueBuf, L), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke S exportedValue cmp", exportedValueBuf, exportedValue->len, exportedValue->x, exportedValue->len);

    memset(exportedValueBuf, 0, HPKE_HKDF_MAX_EXTRACT_KEY_LEN);
    ASSERT_EQ(CRYPT_EAL_HpkeExportSecret(ctxR, exporterContext->x, exporterContext->len, exportedValueBuf, L), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke R exportedValue cmp", exportedValueBuf, exportedValue->len, exportedValue->x, exportedValue->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyE);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    TestRandDeInit();
}
/* END_CASE */

static int32_t HpkeTestSealAndOpen(CRYPT_EAL_HpkeCtx *ctxS, CRYPT_EAL_HpkeCtx *ctxR)
{
    uint8_t massage[100];
    uint32_t massageLen = 100;
    uint8_t plain[100];
    uint32_t plainLen = 100;
    uint8_t cipherText[116];
    uint32_t cipherTextLen = 116;
    int count = 100;
    while (count--) {
#ifdef HITLS_CRYPTO_PROVIDER
        ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, massage, massageLen), CRYPT_SUCCESS);
#else
        ASSERT_EQ(CRYPT_EAL_Randbytes(massage, massageLen), CRYPT_SUCCESS);
#endif
        ASSERT_EQ(CRYPT_EAL_HpkeSeal(ctxS, NULL, 0, massage, massageLen, cipherText, &cipherTextLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_HpkeOpen(ctxR, NULL, 0, cipherText, cipherTextLen, plain, &plainLen), CRYPT_SUCCESS);
        ASSERT_COMPARE("hpke Seal Open cmp", massage, massageLen, plain, plainLen);
    }
    uint64_t seqS;
    uint64_t seqR;
    ASSERT_EQ(CRYPT_EAL_HpkeGetSeq(ctxS, &seqS), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeGetSeq(ctxR, &seqR), CRYPT_SUCCESS);
    ASSERT_EQ(seqS, seqR);
    ASSERT_EQ(seqS, 100);

    count = 100;
    ASSERT_EQ(CRYPT_EAL_HpkeSetSeq(ctxS, 10000000), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeSetSeq(ctxR, 10000000), CRYPT_SUCCESS);
    while (count--) {
#ifdef HITLS_CRYPTO_PROVIDER
        ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, massage, massageLen), CRYPT_SUCCESS);
#else
        ASSERT_EQ(CRYPT_EAL_Randbytes(massage, massageLen), CRYPT_SUCCESS);
#endif
        ASSERT_EQ(CRYPT_EAL_HpkeSeal(ctxS, NULL, 0, massage, massageLen, NULL, &cipherTextLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_HpkeSeal(ctxS, NULL, 0, massage, massageLen, cipherText, &cipherTextLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_HpkeOpen(ctxR, NULL, 0, cipherText, cipherTextLen, NULL, &plainLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_HpkeOpen(ctxR, NULL, 0, cipherText, cipherTextLen, plain, &plainLen), CRYPT_SUCCESS);
        ASSERT_COMPARE("hpke Seal Open cmp", massage, massageLen, plain, plainLen);
    }

    ASSERT_EQ(CRYPT_EAL_HpkeGetSeq(ctxS, &seqS), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeGetSeq(ctxR, &seqR), CRYPT_SUCCESS);
    ASSERT_EQ(seqS, seqR);
    ASSERT_EQ(seqS, 10000000 + 100);
    return CRYPT_SUCCESS;
EXIT:
    return HPKE_ERR;
}

static int32_t HpkeRandomTest(CRYPT_HPKE_Mode mode, CRYPT_HPKE_KEM_AlgId kemId, CRYPT_HPKE_KDF_AlgId kdfId,
    CRYPT_HPKE_AEAD_AlgId aeadId)
{
    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyE = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    Hex info = { 0 };
    info.len = 16;
    uint8_t infoData[16] = { 0 };
    info.x = infoData;
    int32_t ret = HPKE_ERR;

#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_RandbytesEx(NULL, info.x, info.len);
#else
    CRYPT_EAL_Randbytes(info.x, info.len);
#endif    

    Hex psk = { 0 };
    psk.len = 32;
    uint8_t pskData[32] = { 0 };
    psk.x = pskData;
    CRYPT_EAL_Randbytes(psk.x, psk.len);
     
    Hex pskId = { 0 };
    pskId.len = 16;
    uint8_t pskIdData[16] = { 0 };
    pskId.x = pskIdData;
    CRYPT_EAL_Randbytes(pskId.x, pskId.len);
    (void)TestErrClear();

    // prepare Recipient key
    ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, NULL, 0, &pkeyE), CRYPT_SUCCESS);

    // prepare Recipient key
    ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, NULL, 0, &pkeyR), CRYPT_SUCCESS);
    
    ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, NULL, 0, &pkeyS), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pubR;
    pubR.id = CRYPT_EAL_PkeyGetId(pkeyR);
    pubR.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    uint8_t pubRKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    pubR.key.eccPub.data = pubRKeyBuf;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkeyR, &pubR), CRYPT_SUCCESS);

    // Sender init
    ctxS = CRYPT_EAL_HpkeNewCtx(NULL, NULL, CRYPT_HPKE_SENDER, mode, cipherSuite);
    ASSERT_TRUE(ctxS != NULL);

    uint8_t encapsulatedKey[HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN];
    uint32_t encapsulatedKeyLen = HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN;
    
    if(mode == CRYPT_HPKE_MODE_AUTH || mode ==CRYPT_HPKE_MODE_AUTH_PSK){
        ASSERT_EQ(CRYPT_EAL_HpkeSetAuthPriKey(ctxS, pkeyS), CRYPT_SUCCESS);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

    if (mode != CRYPT_HPKE_MODE_PSK && mode != CRYPT_HPKE_MODE_AUTH_PSK) {
        ASSERT_EQ(CRYPT_EAL_HpkeSetPsk(ctxS, psk.x, psk.len, pskId.x, pskId.len), CRYPT_HPKE_ERR_CALL);
    }

    if(mode != CRYPT_HPKE_MODE_AUTH && mode != CRYPT_HPKE_MODE_AUTH_PSK){
        ASSERT_EQ(CRYPT_EAL_HpkeSetAuthPriKey(ctxS, pkeyS), CRYPT_HPKE_ERR_CALL);
    }
    (void)TestErrClear();

    if(mode == CRYPT_HPKE_MODE_PSK || mode == CRYPT_HPKE_MODE_AUTH_PSK){
        ASSERT_EQ(CRYPT_EAL_HpkeSetPsk(ctxS, psk.x, psk.len, pskId.x, pskId.len), CRYPT_SUCCESS);
    }

    ASSERT_EQ(CRYPT_EAL_HpkeSetupSender(ctxS, NULL, info.x, info.len, pubR.key.eccPub.data, pubR.key.eccPub.len,
        encapsulatedKey, &encapsulatedKeyLen), CRYPT_SUCCESS);
    
    CRYPT_EAL_HpkeFreeCtx(ctxS);

    ctxS = CRYPT_EAL_HpkeNewCtx(NULL, NULL, CRYPT_HPKE_SENDER, mode, cipherSuite);
    ASSERT_TRUE(ctxS != NULL);
    
    if(mode == CRYPT_HPKE_MODE_PSK || mode == CRYPT_HPKE_MODE_AUTH_PSK){
        ASSERT_EQ(CRYPT_EAL_HpkeSetPsk(ctxS, psk.x, psk.len, pskId.x, pskId.len), CRYPT_SUCCESS);
    }
    
    if(mode == CRYPT_HPKE_MODE_AUTH || mode ==CRYPT_HPKE_MODE_AUTH_PSK){
        ASSERT_EQ(CRYPT_EAL_HpkeSetAuthPriKey(ctxS, pkeyS),CRYPT_SUCCESS);
        
    }
    ASSERT_EQ(CRYPT_EAL_HpkeSetupSender(ctxS, pkeyE, info.x, info.len, pubR.key.eccPub.data, pubR.key.eccPub.len,
        encapsulatedKey, &encapsulatedKeyLen), CRYPT_SUCCESS);

    // Recipient init
    ctxR = CRYPT_EAL_HpkeNewCtx(NULL, NULL, CRYPT_HPKE_RECIPIENT, mode, cipherSuite);
    ASSERT_TRUE(ctxR != NULL);

    if(mode == CRYPT_HPKE_MODE_PSK || mode == CRYPT_HPKE_MODE_AUTH_PSK){
        ASSERT_EQ(CRYPT_EAL_HpkeSetPsk(ctxR, psk.x, psk.len, pskId.x, pskId.len), CRYPT_SUCCESS);
    } 
    
    if(mode == CRYPT_HPKE_MODE_AUTH || mode ==CRYPT_HPKE_MODE_AUTH_PSK){
        CRYPT_EAL_PkeyPub pubS;
        pubS.id = CRYPT_EAL_PkeyGetId(pkeyS);
        pubS.key.eccPub.len = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
        uint8_t pubSKeyBuf[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
        pubS.key.eccPub.data = pubSKeyBuf;
        ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkeyS, &pubS), CRYPT_SUCCESS);

        ASSERT_EQ(CRYPT_EAL_HpkeSetAuthPubKey(ctxR,pubS.key.eccPub.data, pubS.key.eccPub.len),CRYPT_SUCCESS);
    }
    
    ASSERT_EQ(CRYPT_EAL_HpkeSetupRecipient(ctxR, pkeyR, info.x, info.len, encapsulatedKey, encapsulatedKeyLen), CRYPT_SUCCESS);

    ASSERT_EQ(HpkeTestSealAndOpen(ctxS, ctxR), CRYPT_SUCCESS);
    ret = CRYPT_SUCCESS;
EXIT:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyE);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
    return ret;
}

/**
 * @test   SDV_CRYPT_EAL_HPKE_TEST_RANDOMLY_TC001
 * @title  test key derivation, seal and open randomly.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_TEST_RANDOMLY_TC001(void)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_Mode modes[] = {CRYPT_HPKE_MODE_BASE};
    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384,
        CRYPT_KEM_DHKEM_P521_HKDF_SHA512, CRYPT_KEM_DHKEM_X25519_HKDF_SHA256};
    CRYPT_HPKE_KDF_AlgId kdfIds[] = {CRYPT_KDF_HKDF_SHA256, CRYPT_KDF_HKDF_SHA384, CRYPT_KDF_HKDF_SHA512};
    CRYPT_HPKE_AEAD_AlgId aeadIds[] = {CRYPT_AEAD_AES_128_GCM, CRYPT_AEAD_AES_256_GCM, CRYPT_AEAD_CHACHA20_POLY1305};

    size_t p;
    size_t i;
    size_t j;
    size_t k;
    for (p = 0; p < sizeof(modes) / sizeof(CRYPT_HPKE_Mode); p++) {
        for (i = 0; i < sizeof(kemIds) / sizeof(CRYPT_HPKE_KEM_AlgId); i++) {
            for (j = 0; j < sizeof(kdfIds) / sizeof(CRYPT_HPKE_KDF_AlgId); j++) {
                for (k = 0; k < sizeof(aeadIds) / sizeof(CRYPT_HPKE_AEAD_AlgId); k++) {
                    ASSERT_EQ(HpkeRandomTest(modes[p], kemIds[i], kdfIds[j], aeadIds[k]), CRYPT_SUCCESS);
                }
            }
        }
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    TestRandDeInit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_TEST_RANDOMLY_TC001
 * @title  test key derivation, seal and open randomly.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_TEST_RANDOMLY_TC002(void)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_Mode modes[] = {CRYPT_HPKE_MODE_PSK};
    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384,
        CRYPT_KEM_DHKEM_P521_HKDF_SHA512, CRYPT_KEM_DHKEM_X25519_HKDF_SHA256};
    CRYPT_HPKE_KDF_AlgId kdfIds[] = {CRYPT_KDF_HKDF_SHA256, CRYPT_KDF_HKDF_SHA384, CRYPT_KDF_HKDF_SHA512};
    CRYPT_HPKE_AEAD_AlgId aeadIds[] = {CRYPT_AEAD_AES_128_GCM, CRYPT_AEAD_AES_256_GCM, CRYPT_AEAD_CHACHA20_POLY1305};

    size_t p;
    size_t i;
    size_t j;
    size_t k;
    for (p = 0; p < sizeof(modes) / sizeof(CRYPT_HPKE_Mode); p++) {
        for (i = 0; i < sizeof(kemIds) / sizeof(CRYPT_HPKE_KEM_AlgId); i++) {
            for (j = 0; j < sizeof(kdfIds) / sizeof(CRYPT_HPKE_KDF_AlgId); j++) {
                for (k = 0; k < sizeof(aeadIds) / sizeof(CRYPT_HPKE_AEAD_AlgId); k++) {
                    ASSERT_EQ(HpkeRandomTest(modes[p], kemIds[i], kdfIds[j], aeadIds[k]), CRYPT_SUCCESS);
                }
            }
        }
    }
EXIT:
    TestRandDeInit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_TEST_RANDOMLY_TC001
 * @title  test key derivation, seal and open randomly.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_TEST_RANDOMLY_TC003(void)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_Mode modes[] = {CRYPT_HPKE_MODE_AUTH};
    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384,
        CRYPT_KEM_DHKEM_P521_HKDF_SHA512, CRYPT_KEM_DHKEM_X25519_HKDF_SHA256};
    CRYPT_HPKE_KDF_AlgId kdfIds[] = {CRYPT_KDF_HKDF_SHA256, CRYPT_KDF_HKDF_SHA384, CRYPT_KDF_HKDF_SHA512};
    CRYPT_HPKE_AEAD_AlgId aeadIds[] = {CRYPT_AEAD_AES_128_GCM, CRYPT_AEAD_AES_256_GCM, CRYPT_AEAD_CHACHA20_POLY1305};

    size_t p;
    size_t i;
    size_t j;
    size_t k;
    for (p = 0; p < sizeof(modes) / sizeof(CRYPT_HPKE_Mode); p++) {
        for (i = 0; i < sizeof(kemIds) / sizeof(CRYPT_HPKE_KEM_AlgId); i++) {
            for (j = 0; j < sizeof(kdfIds) / sizeof(CRYPT_HPKE_KDF_AlgId); j++) {
                for (k = 0; k < sizeof(aeadIds) / sizeof(CRYPT_HPKE_AEAD_AlgId); k++) {
                    ASSERT_EQ(HpkeRandomTest(modes[p], kemIds[i], kdfIds[j], aeadIds[k]), CRYPT_SUCCESS);
                }
            }
        }
    }
EXIT:
    TestRandDeInit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_TEST_RANDOMLY_TC001
 * @title  test key derivation, seal and open randomly.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_TEST_RANDOMLY_TC004(void)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_Mode modes[] = {CRYPT_HPKE_MODE_AUTH_PSK};
    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384,
        CRYPT_KEM_DHKEM_P521_HKDF_SHA512, CRYPT_KEM_DHKEM_X25519_HKDF_SHA256};
    CRYPT_HPKE_KDF_AlgId kdfIds[] = {CRYPT_KDF_HKDF_SHA256, CRYPT_KDF_HKDF_SHA384, CRYPT_KDF_HKDF_SHA512};
    CRYPT_HPKE_AEAD_AlgId aeadIds[] = {CRYPT_AEAD_AES_128_GCM, CRYPT_AEAD_AES_256_GCM, CRYPT_AEAD_CHACHA20_POLY1305};

    size_t p;
    size_t i;
    size_t j;
    size_t k;
    for (p = 0; p < sizeof(modes) / sizeof(CRYPT_HPKE_Mode); p++) {
        for (i = 0; i < sizeof(kemIds) / sizeof(CRYPT_HPKE_KEM_AlgId); i++) {
            for (j = 0; j < sizeof(kdfIds) / sizeof(CRYPT_HPKE_KDF_AlgId); j++) {
                for (k = 0; k < sizeof(aeadIds) / sizeof(CRYPT_HPKE_AEAD_AlgId); k++) {
                    ASSERT_EQ(HpkeRandomTest(modes[p], kemIds[i], kdfIds[j], aeadIds[k]), CRYPT_SUCCESS);
                }
            }
        }
    }
EXIT:
    TestRandDeInit();
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_ABNORMAL_TC001
 * @title  hpke abnormal test.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_ABNORMAL_TC001(int role)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    int32_t ret;
    CRYPT_EAL_HpkeCtx *hpkeCtx = NULL;
    CRYPT_HPKE_CipherSuite cipherSuite = {0, 0, 0};
    uint8_t massage[100];
    uint32_t massageLen = 100;
    uint8_t buff[100];
    uint32_t buffLen = 100;
    uint8_t cipherText[116];
    uint32_t cipherTextLen = 116;


    hpkeCtx = CRYPT_EAL_HpkeNewCtx(NULL, NULL, role, CRYPT_HPKE_MODE_BASE, cipherSuite);
    ASSERT_TRUE(hpkeCtx == NULL);

    // test sender
    cipherSuite.kemId = CRYPT_KEM_DHKEM_P256_HKDF_SHA256;
    cipherSuite.kdfId = CRYPT_KDF_HKDF_SHA256;
    cipherSuite.aeadId = CRYPT_AEAD_AES_128_GCM;
    
#ifdef HITLS_CRYPTO_PROVIDER
    hpkeCtx = CRYPT_EAL_HpkeNewCtx(NULL, "provider=none", role, CRYPT_HPKE_MODE_BASE, cipherSuite);
    ASSERT_TRUE(hpkeCtx == NULL);

    hpkeCtx = CRYPT_EAL_HpkeNewCtx(NULL, "provider=default", role, CRYPT_HPKE_MODE_BASE, cipherSuite);
    ASSERT_TRUE(hpkeCtx != NULL);
    CRYPT_EAL_HpkeFreeCtx(hpkeCtx);
#endif
    hpkeCtx = CRYPT_EAL_HpkeNewCtx(NULL, NULL, role, CRYPT_HPKE_MODE_BASE, cipherSuite);
    ASSERT_TRUE(hpkeCtx != NULL);

    ret = CRYPT_EAL_HpkeSetupSender(hpkeCtx, NULL, NULL, 0, NULL, 0, NULL, NULL);
    if (role == CRYPT_HPKE_SENDER) {
        ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    } else {
        ASSERT_EQ(ret, CRYPT_HPKE_ERR_CALL);
    }

    ret = CRYPT_EAL_HpkeSetupRecipient(hpkeCtx, NULL, NULL, 0, NULL, 0);
    if (role == CRYPT_HPKE_RECIPIENT) {
        ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    } else {
        ASSERT_EQ(ret, CRYPT_HPKE_ERR_CALL);
    }

    ASSERT_EQ(CRYPT_EAL_HpkeSeal(hpkeCtx, NULL, 0, massage, massageLen, cipherText, &cipherTextLen), CRYPT_HPKE_ERR_CALL);

    ASSERT_EQ(CRYPT_EAL_HpkeSeal(NULL, NULL, 0, massage, massageLen, cipherText, &cipherTextLen), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_HpkeSetSeq(NULL, 0), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_HpkeSetSeq(hpkeCtx, 0xFFFFFFFFFFFFFFFF), CRYPT_INVALID_ARG);

    ASSERT_EQ(CRYPT_EAL_HpkeOpen(hpkeCtx, NULL, 0, massage, massageLen, cipherText, &cipherTextLen), CRYPT_HPKE_ERR_CALL);

    ASSERT_EQ(CRYPT_EAL_HpkeExportSecret(hpkeCtx, NULL, 0, buff, 0), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_HpkeExportSecret(hpkeCtx, NULL, 0, buff, buffLen), CRYPT_HPKE_ERR_CALL);

    ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, NULL, 0, NULL), CRYPT_NULL_INPUT);

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t ikm[10];
    ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, ikm, 10, &pkey), CRYPT_INVALID_ARG);
EXIT:
    CRYPT_EAL_HpkeFreeCtx(hpkeCtx);
    TestRandDeInit();
}
/* END_CASE */

static CRYPT_EAL_HpkeCtx *GenHpkeCtxWithSharedSecret(CRYPT_HPKE_Role role, CRYPT_HPKE_Mode mode,
    CRYPT_HPKE_CipherSuite cipherSuite, uint8_t *info, uint32_t infoLen, uint8_t* psk,uint32_t pskLen, uint8_t *pskId, uint32_t pskIdLen,
    uint8_t *sharedSecret, uint32_t sharedSecretLen)
{
    CRYPT_EAL_HpkeCtx *ctx = NULL;

    ctx = CRYPT_EAL_HpkeNewCtx(NULL, NULL, role, mode, cipherSuite);
    ASSERT_TRUE(ctx != NULL);
    
    if(mode == CRYPT_HPKE_MODE_PSK || mode == CRYPT_HPKE_MODE_AUTH_PSK){
        ASSERT_EQ(CRYPT_EAL_HpkeSetPsk(ctx, psk, pskLen, pskId, pskIdLen), CRYPT_SUCCESS);
    }
    
    ASSERT_EQ(CRYPT_EAL_HpkeSetSharedSecret(ctx, info, infoLen, sharedSecret, sharedSecretLen), CRYPT_SUCCESS);
     
    return ctx;
EXIT:
    CRYPT_EAL_HpkeFreeCtx(ctx);
    return NULL;
}

static int32_t HpkeTestImportSharedSecret(CRYPT_HPKE_Mode mode, CRYPT_HPKE_CipherSuite cipherSuite)
{
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;

    uint32_t sharedSecretLen = 32; // CRYPT_KEM_DHKEM_X25519_HKDF_SHA256 CRYPT_KEM_DHKEM_P256_HKDF_SHA256
    if (cipherSuite.kemId == CRYPT_KEM_DHKEM_P384_HKDF_SHA384) {
        sharedSecretLen = 48;
    } else if (cipherSuite.kemId == CRYPT_KEM_DHKEM_P521_HKDF_SHA512) {
        sharedSecretLen = 64;
    }

    uint8_t psk[10]={0};
    uint32_t pskLen=10;
    uint8_t pskId[10]={0};
    uint32_t pskIdLen=10;
    
    uint8_t sharedSecret[HPKE_KEM_MAX_SHARED_KEY_LEN];

    ctxS = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_SENDER, mode, cipherSuite, NULL, 0, 
        psk, pskLen, pskId, pskIdLen, sharedSecret, sharedSecretLen);
    ASSERT_TRUE(ctxS != NULL);

    ctxR = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_RECIPIENT, mode, cipherSuite, NULL, 0,
       psk, pskLen, pskId, pskIdLen, sharedSecret, sharedSecretLen);
    ASSERT_TRUE(ctxR != NULL);

    ASSERT_EQ(HpkeTestSealAndOpen(ctxS, ctxR), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    return CRYPT_SUCCESS;
}

/**
 * @test   SDV_CRYPT_EAL_HPKE_SHARED_SECRET_RANDOMLY_TC001
 * @title  import shared secret test randomly.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_SHARED_SECRET_RANDOMLY_TC001(void)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_Mode mode = CRYPT_HPKE_MODE_BASE;
    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384,
        CRYPT_KEM_DHKEM_P521_HKDF_SHA512};
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
EXIT:
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_SHARED_SECRET_RANDOMLY_TC001
 * @title  import shared secret test randomly.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_SHARED_SECRET_RANDOMLY_TC002(void)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_Mode mode = CRYPT_HPKE_MODE_PSK;
    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384,
        CRYPT_KEM_DHKEM_P521_HKDF_SHA512};
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
EXIT:
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_SHARED_SECRET_RANDOMLY_TC001
 * @title  import shared secret test randomly.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_SHARED_SECRET_RANDOMLY_TC003(void)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_Mode mode = CRYPT_HPKE_MODE_AUTH;
    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384,
        CRYPT_KEM_DHKEM_P521_HKDF_SHA512};
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
EXIT:
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_SHARED_SECRET_RANDOMLY_TC001
 * @title  import shared secret test randomly.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_SHARED_SECRET_RANDOMLY_TC004(void)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_Mode mode = CRYPT_HPKE_MODE_AUTH_PSK;
    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384,
        CRYPT_KEM_DHKEM_P521_HKDF_SHA512};
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
EXIT:
    TestRandDeInit();
}
/* END_CASE */
/**
 * @test   SDV_CRYPT_EAL_HPKE_SHARED_SECRET_TC001
 * @title  import sharedSecret and seal/open test based on standard vector.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_SHARED_SECRET_TC001(int mode, int kemId, int kdfId, int aeadId, Hex *info, Hex *psk, Hex *pskId, Hex *sharedSecret,
    int seq, Hex *pt, Hex *aad, Hex *ct)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;

    ctxS = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_SENDER, mode, cipherSuite, info->x, info->len, psk->x, psk->len, pskId->x, pskId->len,
        sharedSecret->x, sharedSecret->len);
    ASSERT_TRUE(ctxS != NULL);

    ctxR = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_RECIPIENT, mode, cipherSuite, info->x, info->len, psk->x, psk->len, pskId->x, pskId->len,
        sharedSecret->x, sharedSecret->len);
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
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_SHARED_SECRET_TC002
 * @title  import sharedSecret and export secret test based on standard vector.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_SHARED_SECRET_TC002(int mode, int kemId, int kdfId, int aeadId, Hex *info, Hex *psk,Hex *pskId,Hex *sharedSecret,
    Hex *exporterContext, int L, Hex *exportedValue)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_CipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;

    ctxS = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_SENDER, mode, cipherSuite, info->x, info->len, psk->x, psk->len, pskId->x, pskId->len,
        sharedSecret->x, sharedSecret->len);
    ASSERT_TRUE(ctxS != NULL);

    ctxR = GenHpkeCtxWithSharedSecret(CRYPT_HPKE_RECIPIENT, mode, cipherSuite, info->x, info->len, psk->x, psk->len, pskId->x, pskId->len,
        sharedSecret->x, sharedSecret->len);
    ASSERT_TRUE(ctxR != NULL);

    uint8_t exportedValueBuf[HPKE_HKDF_MAX_EXTRACT_KEY_LEN] = {0};
    ASSERT_EQ(CRYPT_EAL_HpkeExportSecret(ctxS, exporterContext->x, exporterContext->len, exportedValueBuf, L), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke S exportedValue cmp", exportedValueBuf, exportedValue->len, exportedValue->x, exportedValue->len);

    memset(exportedValueBuf, 0, HPKE_HKDF_MAX_EXTRACT_KEY_LEN);
    ASSERT_EQ(CRYPT_EAL_HpkeExportSecret(ctxR, exporterContext->x, exporterContext->len, exportedValueBuf, L), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke R exportedValue cmp", exportedValueBuf, exportedValue->len, exportedValue->x, exportedValue->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_GENERATE_KEY_PAIR_TC001
 * @title  hpke generate key pair test.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_GENERATE_KEY_PAIR_TC001(void)
{
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_HPKE_KEM_AlgId kemIds[] = {CRYPT_KEM_DHKEM_P256_HKDF_SHA256, CRYPT_KEM_DHKEM_P384_HKDF_SHA384,
        CRYPT_KEM_DHKEM_P521_HKDF_SHA512};
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
                ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, NULL, 0, &pctx), CRYPT_SUCCESS);
                CRYPT_EAL_PkeyFreeCtx(pctx);
                pctx = NULL;

                uint32_t ikmLen = 1024*1024;
                uint8_t *ikm = (uint8_t *)malloc(ikmLen);
                memset_s(ikm, ikmLen, 0xFF, ikmLen);
                ASSERT_EQ(CRYPT_EAL_HpkeGenerateKeyPair(NULL, NULL, cipherSuite, ikm, ikmLen, &pctx), CRYPT_SUCCESS);
                CRYPT_EAL_PkeyFreeCtx(pctx);
                free(ikm);
            }
        }
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    TestRandDeInit();
}
/* END_CASE */
