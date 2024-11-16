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
#include "crypt_eal_hpke.h"
#include "crypt_eal_rand.h"
#include "test.h"
/* END_HEADER */

#define CRYPT_HPKE_KEM_MAX_NSECRET  64
#define CRYPT_HPKE_KEN_MAX_NENC 133
#define CRYPT_HPKE_KEN_MAX_NPK  133
#define CRYPT_HPKE_KEN_MAX_NSK  66

#define CRYPT_HPKE_HKDF_MAX_LEN  64

#define CRYPT_HPKE_AEAD_MAX_KEY_LEN  32
#define CRYPT_HPKE_AEAD_MAX_NONCE_LEN  12
#define CRYPT_HPKE_AEAD_MAX_TAG_LEN  16

static void PrintfBuf(char *tag, uint8_t *buff, uint32_t len)
{
    printf("\n[%s], len = %d\n", tag, len);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x ", buff[i]);
    }
    printf("\n\n");
}

static int32_t HpkeCheckParam(CRYPT_EAL_HpkeCtx *ctx, Hex *key, Hex *baseNonce, Hex *exporterSecret)
{
    // check symkey
    uint8_t symkey[CRYPT_HPKE_AEAD_MAX_KEY_LEN] = { 0 };
    uint32_t symkeyLen = CRYPT_HPKE_AEAD_MAX_KEY_LEN;
    ASSERT_EQ(CRYPT_EAL_HpkeGetParam(ctx, CRYPT_HPKE_PARAM_SYM_KEY, symkey, &symkeyLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke symkey cmp", symkey, symkeyLen, key->x, key->len);

    // check base nonce
    uint8_t nonce[CRYPT_HPKE_AEAD_MAX_NONCE_LEN] = { 0 };
    uint32_t nonceLen = CRYPT_HPKE_AEAD_MAX_NONCE_LEN;
    ASSERT_EQ(CRYPT_EAL_HpkeGetParam(ctx, CRYPT_HPKE_PARAM_BASE_NONCE, nonce, &nonceLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke base nonce cmp", nonce, nonceLen, baseNonce->x, baseNonce->len);

    // check base nonce
    uint8_t exporterS[CRYPT_HPKE_HKDF_MAX_LEN] = { 0 };
    uint32_t exporterSLen = CRYPT_HPKE_HKDF_MAX_LEN;
    ASSERT_EQ(CRYPT_EAL_HpkeGetParam(ctx, CRYPT_HPKE_PARAM_EXPORTER_SECRET, exporterS, &exporterSLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke exporter secret cmp", exporterS, exporterSLen, exporterSecret->x, exporterSecret->len);
    return CRYPT_SUCCESS;
exit:
    return CRYPT_ERR_ALGID;
}

static int32_t HpkeCheckParamSR(CRYPT_EAL_HpkeCtx *ctxS, CRYPT_EAL_HpkeCtx *ctxR)
{
    // check symkey
    uint8_t symkey[CRYPT_HPKE_AEAD_MAX_KEY_LEN] = { 0 };
    uint32_t symkeyLen = CRYPT_HPKE_AEAD_MAX_KEY_LEN;
    ASSERT_EQ(CRYPT_EAL_HpkeGetParam(ctxS, CRYPT_HPKE_PARAM_SYM_KEY, symkey, &symkeyLen), CRYPT_SUCCESS);

    // check base nonce
    uint8_t baseNonce[CRYPT_HPKE_AEAD_MAX_NONCE_LEN] = { 0 };
    uint32_t baseNonceLen = CRYPT_HPKE_AEAD_MAX_NONCE_LEN;
    ASSERT_EQ(CRYPT_EAL_HpkeGetParam(ctxS, CRYPT_HPKE_PARAM_BASE_NONCE, baseNonce, &baseNonceLen), CRYPT_SUCCESS);

    // check base nonce
    uint8_t exporterS[CRYPT_HPKE_HKDF_MAX_LEN] = { 0 };
    uint32_t exporterSLen = CRYPT_HPKE_HKDF_MAX_LEN;
    ASSERT_EQ(CRYPT_EAL_HpkeGetParam(ctxS, CRYPT_HPKE_PARAM_EXPORTER_SECRET, exporterS, &exporterSLen), CRYPT_SUCCESS);

    Hex key = {symkey, symkeyLen};
    Hex nonce = {baseNonce, baseNonceLen};
    Hex exporterSecret = {exporterS, exporterSLen};
    ASSERT_EQ(HpkeCheckParam(ctxR, &key, &nonce, &exporterSecret), CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
exit:
    return CRYPT_ERR_ALGID;
}

static int32_t GenerateHpkeCtxSAndCtxR(int mode, CRYPT_HpkeCipherSuite cipherSuite, Hex *info, Hex *ikmE, Hex *ikmR,
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
    pubR1.key.eccPub.len = CRYPT_HPKE_KEN_MAX_NPK;
    uint8_t pubRKeyBuf[CRYPT_HPKE_KEN_MAX_NPK];
    pubR1.key.eccPub.data = pubRKeyBuf;
    ret = CRYPT_EAL_PkeyGetPub(pkeyR1, &pubR1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctxS1 = CRYPT_EAL_HpkeNewCtx(mode, cipherSuite);
    ASSERT_TRUE(ctxS1 != NULL);

    ret = CRYPT_EAL_HpkeSetupSender(ctxS1, pkeyS1, info->x, info->len, pubR1.key.eccPub.data, pubR1.key.eccPub.len, encapsulatedKey, encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctxR1 = CRYPT_EAL_HpkeNewCtx(mode, cipherSuite);
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
 * @title  hpke key nonce secret test.
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
    (void)sharedSecret;
    (void)secret;
    (void)keyScheduleContext;

    PrintfBuf("ikmE", ikmE->x, ikmE->len);
    PrintfBuf("ikmR", ikmR->x, ikmR->len);

    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    int32_t ret;
    CRYPT_HpkeCipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    uint8_t encapsulatedKey[CRYPT_HPKE_KEN_MAX_NENC];
    uint32_t encapsulatedKeyLen = CRYPT_HPKE_KEN_MAX_NENC;

    ret = GenerateHpkeCtxSAndCtxR(mode, cipherSuite, info, ikmE, ikmR, &ctxS, &ctxR, &pkeyS, &pkeyR, encapsulatedKey, &encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv priS;
    priS.id = CRYPT_EAL_PkeyGetId(pkeyS);
    priS.key.eccPrv.len = CRYPT_HPKE_KEN_MAX_NSK;
    uint8_t priSKeyBuf[CRYPT_HPKE_KEN_MAX_NSK];
    priS.key.eccPrv.data = priSKeyBuf;
    ret = CRYPT_EAL_PkeyGetPrv(pkeyS, &priS);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke priS cmp", priS.key.eccPrv.data, priS.key.eccPrv.len, skEm->x, skEm->len);

    CRYPT_EAL_PkeyPub pubS;
    pubS.id = CRYPT_EAL_PkeyGetId(pkeyS);
    pubS.key.eccPub.len = CRYPT_HPKE_KEN_MAX_NPK;
    uint8_t pubSKeyBuf[CRYPT_HPKE_KEN_MAX_NPK];
    pubS.key.eccPub.data = pubSKeyBuf;
    ret = CRYPT_EAL_PkeyGetPub(pkeyS, &pubS);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke pubS cmp", pubS.key.eccPub.data, pubS.key.eccPub.len, pkEm->x, pkEm->len);

    CRYPT_EAL_PkeyPrv priR;
    priR.id = CRYPT_EAL_PkeyGetId(pkeyR);
    priR.key.eccPrv.len = CRYPT_HPKE_KEN_MAX_NSK;
    uint8_t priRKeyBuf[CRYPT_HPKE_KEN_MAX_NSK];
    priR.key.eccPrv.data = priRKeyBuf;
    ret = CRYPT_EAL_PkeyGetPrv(pkeyR, &priR);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke priR cmp", priR.key.eccPrv.data, priR.key.eccPrv.len, skRm->x, skRm->len);

    CRYPT_EAL_PkeyPub pubR;
    pubR.id = CRYPT_EAL_PkeyGetId(pkeyR);
    pubR.key.eccPub.len = CRYPT_HPKE_KEN_MAX_NPK;
    uint8_t pubRKeyBuf[CRYPT_HPKE_KEN_MAX_NPK];
    pubR.key.eccPub.data = pubRKeyBuf;
    ret = CRYPT_EAL_PkeyGetPub(pkeyR, &pubR);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke pubR cmp", pubR.key.eccPub.data, pubR.key.eccPub.len, pkRm->x, pkRm->len);

    // check enc
    ASSERT_COMPARE("hpke enc cmp", encapsulatedKey, encapsulatedKeyLen, enc->x, enc->len);

    ASSERT_EQ(HpkeCheckParam(ctxS, key, baseNonce, exporterSecret), CRYPT_SUCCESS);
    ASSERT_EQ(HpkeCheckParam(ctxR, key, baseNonce, exporterSecret), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC002
 * @title  hpke seal and open test.
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
    CRYPT_HpkeCipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    uint8_t encapsulatedKey[CRYPT_HPKE_KEN_MAX_NENC];
    uint32_t encapsulatedKeyLen = CRYPT_HPKE_KEN_MAX_NENC;

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
 * @title  hpke exported values test.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC003(int mode, int kemId, int kdfId, int aeadId, Hex *info, Hex *ikmE, Hex *ikmR, Hex *exporterContext,  int L, Hex *exportedValue)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    int32_t ret;
    CRYPT_HpkeCipherSuite cipherSuite = {kemId, kdfId, aeadId};
    CRYPT_EAL_HpkeCtx *ctxS = NULL;
    CRYPT_EAL_HpkeCtx *ctxR = NULL;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    uint8_t encapsulatedKey[CRYPT_HPKE_KEN_MAX_NENC];
    uint32_t encapsulatedKeyLen = CRYPT_HPKE_KEN_MAX_NENC;

    ret = GenerateHpkeCtxSAndCtxR(mode, cipherSuite, info, ikmE, ikmR, &ctxS, &ctxR, &pkeyS, &pkeyR, encapsulatedKey, &encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint8_t exportedValueBuf[CRYPT_HPKE_HKDF_MAX_LEN] = {0};
    ret = CRYPT_EAL_HpkeExportSecret(ctxS, exporterContext->x, exporterContext->len, exportedValueBuf, L);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("hpke S exportedValue cmp", exportedValueBuf, exportedValue->len, exportedValue->x, exportedValue->len);

    memset(exportedValueBuf, 0, CRYPT_HPKE_HKDF_MAX_LEN);
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

/**
 * @test   SDV_CRYPT_EAL_HPKE_API_TC004
 * @title  hpke rand test.
 * @precon nan
 * @brief
 *    1.NA.
 * @expect
 *    1.NA.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HPKE_API_TC004(int mode, int kemId, int kdfId, int aeadId)
{
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    int32_t ret;
    CRYPT_HpkeCipherSuite cipherSuite = {kemId, kdfId, aeadId};
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
    pubR.key.eccPub.len = CRYPT_HPKE_KEN_MAX_NPK;
    uint8_t pubRKeyBuf[CRYPT_HPKE_KEN_MAX_NPK];
    pubR.key.eccPub.data = pubRKeyBuf;
    ret = CRYPT_EAL_PkeyGetPub(pkeyR, &pubR);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Sender init
    ctxS = CRYPT_EAL_HpkeNewCtx(mode, cipherSuite);
    ASSERT_TRUE(ctxS != NULL);

    uint8_t encapsulatedKey[CRYPT_HPKE_KEN_MAX_NENC];
    uint32_t encapsulatedKeyLen = CRYPT_HPKE_KEN_MAX_NENC;

    ret = CRYPT_EAL_HpkeSetupSender(ctxS, pkeyS, info.x, info.len, pubR.key.eccPub.data, pubR.key.eccPub.len, encapsulatedKey, &encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Recipient init
    ctxR = CRYPT_EAL_HpkeNewCtx(mode, cipherSuite);
    ASSERT_TRUE(ctxR != NULL);

    ret = CRYPT_EAL_HpkeSetupRecipient(ctxR, pkeyR, info.x, info.len, encapsulatedKey, encapsulatedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ASSERT_EQ(HpkeCheckParamSR(ctxS, ctxR), CRYPT_SUCCESS);

    uint8_t massage[100];
    uint32_t massageLen = 100;
    uint8_t plain[100];
    uint32_t plainLen = 100;
    uint8_t cipherText[116];
    uint32_t cipherTextLen = 116;
    int count = 200;
    while (count--) {
        ASSERT_EQ(CRYPT_EAL_Randbytes(massage, massageLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_HpkeSeal(ctxS, NULL, 0, massage, massageLen, cipherText, &cipherTextLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_HpkeOpen(ctxR, NULL, 0, cipherText, cipherTextLen, plain, &plainLen), CRYPT_SUCCESS);
        ASSERT_COMPARE("hpke Seal Open cmp", massage, massageLen, plain, plainLen);
    }

    count = 200;
    ASSERT_EQ(CRYPT_EAL_HpkeSetSeq(ctxS, 10000000), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeSetSeq(ctxR, 10000000), CRYPT_SUCCESS);
    while (count--) {
        ASSERT_EQ(CRYPT_EAL_Randbytes(massage, massageLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_HpkeSeal(ctxS, NULL, 0, massage, massageLen, cipherText, &cipherTextLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_HpkeOpen(ctxR, NULL, 0, cipherText, cipherTextLen, plain, &plainLen), CRYPT_SUCCESS);
        ASSERT_COMPARE("hpke Seal Open cmp", massage, massageLen, plain, plainLen);
    }

    uint64_t seqS;
    uint64_t seqR;
    ASSERT_EQ(CRYPT_EAL_HpkeGetSeq(ctxS, &seqS), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HpkeGetSeq(ctxR, &seqR), CRYPT_SUCCESS);
    ASSERT_EQ(seqS, seqR);
    ASSERT_EQ(seqS, 10000200);

exit:
    CRYPT_EAL_HpkeFreeCtx(ctxS);
    CRYPT_EAL_HpkeFreeCtx(ctxR);
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
}
/* END_CASE */

// bash build_hitls.sh && bash build_sdv.sh run-tests=test_suite_sdv_eal_hpke verbose &&  bash execute_sdv.sh test_suite_sdv_eal_hpke