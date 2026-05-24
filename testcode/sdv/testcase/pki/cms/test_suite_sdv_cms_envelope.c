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

#include <string.h>
#include "bsl_sal.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "bsl_params.h"
#include "crypt_codecskey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "hitls_cms_local.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_params.h"
#include "crypt_eal_pkey.h"
#include "bsl_err.h"
#include "crypt_params_key.h"
#include "hitls_pki_x509.h"
#include "stub_utils.h"
/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

#define CMS_TEST_STREAM_OUT_SIZE 128

static uint32_t AddKtriRecipientParams(BSL_Param *params, HITLS_X509_Cert *cert, CRYPT_EAL_PkeyCtx *privateKey,
    int32_t *recipientType, BslCid *keyEncAlg, int32_t *oaepMdId, int32_t *oaepMgf1Id, const BSL_Buffer *oaepLabel)
{
    uint32_t idx = 0;

    params[idx++] = (BSL_Param){HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32,
        recipientType, sizeof(*recipientType), 0};
    params[idx++] = (BSL_Param){HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR,
        cert, sizeof(HITLS_X509_Cert *), 0};
    params[idx++] = (BSL_Param){HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR,
        privateKey, sizeof(CRYPT_EAL_PkeyCtx *), 0};
    params[idx++] = (BSL_Param){HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32,
        keyEncAlg, sizeof(*keyEncAlg), 0};
    if (oaepMdId != NULL) {
        params[idx++] = (BSL_Param){CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32,
            oaepMdId, sizeof(*oaepMdId), 0};
    }
    if (oaepMgf1Id != NULL) {
        params[idx++] = (BSL_Param){CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32,
            oaepMgf1Id, sizeof(*oaepMgf1Id), 0};
    }
    if (oaepLabel != NULL && (oaepLabel->data != NULL || oaepLabel->dataLen != 0)) {
        params[idx++] = (BSL_Param){CRYPT_PARAM_RSA_OAEP_LABEL, BSL_PARAM_TYPE_OCTETS,
            oaepLabel->data, oaepLabel->dataLen, 0};
    }
    params[idx] = (BSL_Param)BSL_PARAM_END;
    return idx;
}

static void AddContentEncryptParams(BSL_Param *params, uint32_t *idx, BslCid *contentEncAlg, BslCid *contentType)
{
    params[(*idx)++] = (BSL_Param){HITLS_CMS_PARAM_CONTENT_ENC_ALG, BSL_PARAM_TYPE_INT32,
        contentEncAlg, sizeof(BslCid), 0};
    params[(*idx)++] = (BSL_Param){HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32,
        contentType, sizeof(BslCid), 0};
    params[*idx] = (BSL_Param)BSL_PARAM_END;
}

static int32_t AppendBuffer(BSL_Buffer *dst, const BSL_Buffer *src)
{
    if (dst == NULL || src == NULL) {
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (src->dataLen == 0) {
        return HITLS_PKI_SUCCESS;
    }
    if (src->data == NULL || dst->dataLen > UINT32_MAX - src->dataLen) {
        return HITLS_CMS_ERR_INVALID_PARAM;
    }

    uint32_t newLen = dst->dataLen + src->dataLen;
    uint8_t *newData = NULL;
    if (dst->data == NULL) {
        newData = BSL_SAL_Malloc(newLen);
    } else {
        newData = BSL_SAL_Realloc(dst->data, newLen, dst->dataLen);
    }
    if (newData == NULL) {
        return BSL_MALLOC_FAIL;
    }
    (void)memcpy(newData + dst->dataLen, src->data, src->dataLen);
    dst->data = newData;
    dst->dataLen = newLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t StreamEncryptToBuffer(HITLS_CMS *cms, const BSL_Buffer *chunks, uint32_t chunkCnt,
    BSL_Buffer *ciphertext)
{
    if (cms == NULL || chunks == NULL || ciphertext == NULL) {
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    for (uint32_t i = 0; i < chunkCnt; i++) {
        uint8_t outData[CMS_TEST_STREAM_OUT_SIZE];
        BSL_Buffer out = {outData, sizeof(outData)};
        int32_t ret = HITLS_CMS_DataUpdateEx(cms, &chunks[i], &out);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        ret = AppendBuffer(ciphertext, &out);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    uint8_t finalData[CMS_TEST_STREAM_OUT_SIZE];
    BSL_Buffer final = {finalData, sizeof(finalData)};
    int32_t ret = HITLS_CMS_DataFinalEx(cms, NULL, &final);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return AppendBuffer(ciphertext, &final);
}

static int32_t StreamDecryptToBuffer(HITLS_CMS *cms, const BSL_Buffer *chunks, uint32_t chunkCnt,
    BSL_Buffer *plaintext)
{
    if (cms == NULL || chunks == NULL || plaintext == NULL) {
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    for (uint32_t i = 0; i < chunkCnt; i++) {
        uint8_t outData[CMS_TEST_STREAM_OUT_SIZE];
        BSL_Buffer out = {outData, sizeof(outData)};
        int32_t ret = HITLS_CMS_DataUpdateEx(cms, &chunks[i], &out);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        ret = AppendBuffer(plaintext, &out);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    uint8_t finalData[CMS_TEST_STREAM_OUT_SIZE];
    BSL_Buffer final = {finalData, sizeof(finalData)};
    int32_t ret = HITLS_CMS_DataFinalEx(cms, NULL, &final);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return AppendBuffer(plaintext, &final);
}

/**
 * @test   SDV_CMS_ENVELOPEDDATA_MALLOC_TC001
 * @title  Test malloc CMS EnvelopedData
 * @brief
 *    1. Malloc CMS EnvelopedData with valid cid
 * @expect
 *    1. Success
 *    2. No abort
 *    3. Returns NULL
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_MALLOC_TC001(void)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA)
    SKIP_TEST();
#else
    HITLS_CMS *cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(cms, NULL);
    HITLS_CMS_Free(cms);
EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_PARSE_ENCODE_TC001
 * @title Test EnvelopedData parse and encode
 * @brief
 *    1. Parse EnvelopedData from buffer using HITLS_CMS_ProviderParseBuff
 *    2. Verify parsed structure
 *    3. Re-encode using HITLS_CMS_GenBuff
 *    4. Verify encoded result
 * @expect
 *    1. Parse succeeds
 *    2. Re-encode succeeds
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_PARSE_ENCODE_TC001(Hex *envDataBuf)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA)
    (void)envDataBuf;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer inputBuf = {envDataBuf->x, envDataBuf->len};

    // Parse EnvelopedData
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &inputBuf, &cms), HITLS_PKI_SUCCESS);
    ASSERT_NE(cms, NULL);
    ASSERT_EQ(cms->dataType, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(cms->ctx.envelopedData, NULL);

    // Verify parsed structure
    ASSERT_LT(0, BSL_LIST_COUNT(cms->ctx.envelopedData->recipientInfos));

    // Re-encode
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("encode compare", inputBuf.data, inputBuf.dataLen, encoded.data, encoded.dataLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_CMS_Free(cms);
    BSL_SAL_Free(encoded.data);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_ENVELOPEDDATA_PARSE_ENCODE_STUB_TC001
 * @title  Test EnvelopedData parse and encode with malloc failures
 * @brief
 *    1. Parse CMS EnvelopedData successfully to count malloc calls
 *    2. Test parse with systematic malloc failures
 *    3. Encode CMS EnvelopedData successfully to count malloc calls
 *    4. Test encode with systematic malloc failures
 * @expect
 *    1. Parse successful
 *    2. Parse malloc failure paths are covered
 *    3. Encode successful
 *    4. All encode malloc failures return error
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_PARSE_ENCODE_STUB_TC001(Hex *envDataBuf)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA)
    (void)envDataBuf;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms1 = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer inputBuf = {envDataBuf->x, envDataBuf->len};
    uint32_t totalMallocCount = 0;

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &inputBuf, &cms), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_TRUE(TestIsErrStackEmpty());
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        (void)HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &inputBuf, &cms1);
        HITLS_CMS_Free(cms1);
        cms1 = NULL;
    }
    TestErrClear();

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_TRUE(TestIsErrStackEmpty());
    BSL_SAL_Free(encoded.data);
    encoded.data = NULL;

    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    }
EXIT:
    HITLS_CMS_Free(cms);
    STUB_RESTORE(BSL_SAL_Malloc);
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_PARSE_DECRYPT_FILE_TC001
 * @title Parse external EnvelopedData file and verify decrypted content
 * @precon External CMS EnvelopedData file and matching recipient certificate/private key are available
 * @brief
 *    1. Read the original CMS file and expected plaintext file
 *    2. Parse CMS EnvelopedData from file
 *    3. Verify key structure fields from the parsed EnvelopedData
 *    4. Re-encode CMS and compare with the original file bytes
 *    5. Decrypt EnvelopedData with the matching recipient key and certificate
 *    6. Compare decrypted output with the expected plaintext file
 * @expect
 *    1. Parsing succeeds
 *    2. Parsed structure matches the expected rsa + aes256-cbc EnvelopedData layout
 *    3. Re-encoded bytes match the original file
 *    4. Decryption succeeds
 *    5. Decrypted plaintext matches the expected file content
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_PARSE_DECRYPT_FILE_TC001(char *envPath, char *certPath, char *keyPath, char *msgPath,
    int expectedKeyEncAlg)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_AES)
    (void)envPath;
    (void)certPath;
    (void)keyPath;
    (void)msgPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    BSL_Buffer envFile = {0};
    BSL_Buffer expectedMsg = {0};
    BSL_Buffer encoded = {0};
    BSL_Buffer decrypted = {0};
    CMS_RecipientInfo *recipientInfo = NULL;
    CMS_KeyTransRecipientInfo *ktri = NULL;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid recipientKeyEncAlg = (BslCid)expectedKeyEncAlg;
    BSL_Param decryptParams[8];

    // Initialize random number generator
    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);

    ASSERT_EQ(BSL_SAL_ReadFile(envPath, &envFile.data, &envFile.dataLen), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(msgPath, &expectedMsg.data, &expectedMsg.dataLen), BSL_SUCCESS);

    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, envPath, &cms), HITLS_PKI_SUCCESS);
    ASSERT_NE(cms, NULL);
    ASSERT_EQ(cms->dataType, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(cms->ctx.envelopedData, NULL);
    ASSERT_EQ(cms->ctx.envelopedData->version, 0);
    ASSERT_EQ(cms->ctx.envelopedData->originatorInfo, NULL);
    ASSERT_EQ(cms->ctx.envelopedData->unprotectedAttrs, NULL);
    ASSERT_EQ(BSL_LIST_COUNT(cms->ctx.envelopedData->recipientInfos), 1);

    recipientInfo = BSL_LIST_GET_FIRST(cms->ctx.envelopedData->recipientInfos);
    ASSERT_NE(recipientInfo, NULL);
    ASSERT_EQ(recipientInfo->type, CMS_RECIPIENT_TYPE_KTRI);
    ktri = recipientInfo->d.ktri;
    ASSERT_NE(ktri, NULL);
    ASSERT_EQ(ktri->version, 0);
    ASSERT_EQ(ktri->keyEncryAlg, (BslCid)expectedKeyEncAlg);
    ASSERT_EQ(ktri->encryptedKey.dataLen, 256);
    if (expectedKeyEncAlg == BSL_CID_RSA) {
        ASSERT_EQ(ktri->algParams, NULL);
    } else if (expectedKeyEncAlg == BSL_CID_RSAES_OAEP) {
        ASSERT_NE(ktri->algParams, NULL);
        ASSERT_NE(ktri->algParams->data, NULL);
        ASSERT_LT(0, ktri->algParams->dataLen);
    }

    ASSERT_EQ(cms->ctx.envelopedData->encryptedContentInfo.contentType, BSL_CID_PKCS7_SIMPLEDATA);
    ASSERT_EQ(cms->ctx.envelopedData->encryptedContentInfo.contentEncryAlg, BSL_CID_AES256_CBC);
    ASSERT_NE(cms->ctx.envelopedData->encryptedContentInfo.algParams.data, NULL);
    ASSERT_EQ(cms->ctx.envelopedData->encryptedContentInfo.encryptedContent.dataLen, 64);

    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("envdata encode compare", encoded.data, encoded.dataLen, envFile.data, envFile.dataLen);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);

    (void)AddKtriRecipientParams(decryptParams, recipientCert, recipientKey, &recipientType, &recipientKeyEncAlg,
        NULL, NULL, NULL);

    ASSERT_EQ(HITLS_CMS_DataDecrypt(cms, decryptParams, &decrypted), HITLS_PKI_SUCCESS);
    ASSERT_NE(decrypted.data, NULL);
    ASSERT_EQ(decrypted.dataLen, expectedMsg.dataLen);
    ASSERT_COMPARE("decrypted content compare", decrypted.data, decrypted.dataLen, expectedMsg.data, expectedMsg.dataLen);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:

    HITLS_CMS_Free(cms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(envFile.data);
    BSL_SAL_Free(expectedMsg.data);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(decrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_RSA_ONE_SHOT_ENCRYPT_DECRYPT_TC001
 * @title Test EnvelopedData one-shot encryption and decryption
 * @precon Initialize CMS EnvelopedData structure
 * @brief
 *    1. Create CMS EnvelopedData handle
 *    2. Encrypt plaintext using HITLS_CMS_DataEncrypt
 *    3. Parse encrypted data
 *    4. Decrypt using HITLS_CMS_DataDecrypt
 *    5. Verify decrypted plaintext matches original
 * @expect
 *    1. Encryption succeeds
 *    2. Decryption succeeds
 *    3. Plaintext matches original
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_RSA_ONE_SHOT_ENCRYPT_DECRYPT_TC001(int encAlg, char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_AES)
    (void)certPath;
    (void)keyPath;
    (void)encAlg;
    SKIP_TEST();
#else
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    HITLS_CMS *encCms = NULL;
    HITLS_CMS *decCms = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer decrypted = {0};
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid recipientKeyEncAlg = BSL_CID_RSA;

    // Initialize random number generator
    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);

    // Load recipient certificate and key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);

    // Create plaintext
    const char *plaintext = "Hello, EnvelopedData!";
    BSL_Buffer plaintextBuf = {(uint8_t *)plaintext, strlen(plaintext)};

    // Create CMS EnvelopedData for encryption
    encCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(encCms, NULL);

    // Prepare parameters
    BslCid contentEncAlg = (BslCid)encAlg;
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;

    BSL_Param params[10];
    uint32_t paramIdx = AddKtriRecipientParams(params, recipientCert, recipientKey, &recipientType,
        &recipientKeyEncAlg, NULL, NULL, NULL);
    AddContentEncryptParams(params, &paramIdx, &contentEncAlg, &contentType);

    // Encrypt
    ASSERT_EQ(HITLS_CMS_DataEncrypt(encCms, &plaintextBuf, params), HITLS_PKI_SUCCESS);

    // Encode to buffer
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, encCms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_NE(encoded.data, NULL);
    ASSERT_LT(0, encoded.dataLen);

    // Parse encrypted data
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms), HITLS_PKI_SUCCESS);
    ASSERT_NE(decCms, NULL);
    ASSERT_EQ(decCms->dataType, BSL_CID_PKCS7_ENVELOPEDDATA);

    // Prepare decryption parameters
    BSL_Param decryptParams[8];
    (void)AddKtriRecipientParams(decryptParams, recipientCert, recipientKey, &recipientType, &recipientKeyEncAlg,
        NULL, NULL, NULL);

    // Decrypt
    ASSERT_EQ(HITLS_CMS_DataDecrypt(decCms, decryptParams, &decrypted), HITLS_PKI_SUCCESS);
    ASSERT_NE(decrypted.data, NULL);
    ASSERT_EQ(decrypted.dataLen, plaintextBuf.dataLen);
    ASSERT_EQ(memcmp(decrypted.data, plaintextBuf.data, plaintextBuf.dataLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CMS_Free(encCms);
    HITLS_CMS_Free(decCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(decrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_RSA_OAEP_ONE_SHOT_ENCRYPT_DECRYPT_TC001
 * @title Test EnvelopedData RSA-OAEP one-shot encryption and decryption
 * @precon Initialize CMS EnvelopedData structure
 * @brief
 *    1. Verify OAEP recipient parameter validation rejects invalid configurations
 *    2. Create CMS EnvelopedData handle
 *    3. Encrypt plaintext using HITLS_CMS_DataEncrypt with RSAES-OAEP recipient parameters
 *       and a non-empty OAEP label
 *    4. Parse encrypted data
 *    5. Verify parsed recipient key transport algorithm is RSAES-OAEP
 *    6. Verify decryption parameter validation rejects missing private key
 *    7. Decrypt using HITLS_CMS_DataDecrypt
 *    8. Verify decrypted plaintext matches original
 * @expect
 *    1. Invalid OAEP recipient configurations are rejected
 *    2. Encryption with non-empty OAEP label succeeds
 *    3. Parsed recipient key transport algorithm is RSAES-OAEP
 *    4. Invalid decryption recipient configuration is rejected
 *    5. Decryption succeeds
 *    6. Plaintext matches original
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_RSA_OAEP_ONE_SHOT_ENCRYPT_DECRYPT_TC001(int encAlg, char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_RSAES_OAEP)
    (void)certPath;
    (void)keyPath;
    (void)encAlg;
    SKIP_TEST();
#else
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    HITLS_CMS *encCms = NULL;
    HITLS_CMS *decCms = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer decrypted = {0};
    CMS_RecipientInfo *recipientInfo = NULL;
    CMS_KeyTransRecipientInfo *ktri = NULL;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid recipientKeyEncAlg = BSL_CID_RSAES_OAEP;

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);

    {
        const char *plaintext = "Hello, RSA-OAEP EnvelopedData!";
        BSL_Buffer plaintextBuf = {(uint8_t *)plaintext, strlen(plaintext)};
        BslCid contentEncAlg = (BslCid)encAlg;
        BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
        int32_t oaepMdId = CRYPT_MD_SHA256;
        int32_t oaepMgf1Id = CRYPT_MD_SHA256;
        uint8_t oaepLabel[] = "openhitls-oaep-label";
        uint8_t invalidLabel = 0x01;
        BSL_Buffer oaepLabelBuf = {oaepLabel, sizeof(oaepLabel) - 1};

        {
            HITLS_CMS *invalidEncCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
            int32_t invalidRecipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
            BslCid invalidRecipientKeyEncAlg = BSL_CID_RSAES_OAEP;
            BSL_Buffer invalidLabelBuf = {NULL, sizeof(invalidLabel)};
            BSL_Param invalidParams[10];
            ASSERT_NE(invalidEncCms, NULL);

            uint32_t paramIdx = AddKtriRecipientParams(invalidParams, recipientCert, recipientKey,
                &invalidRecipientType, &invalidRecipientKeyEncAlg, &oaepMdId, &oaepMgf1Id, &invalidLabelBuf);
            AddContentEncryptParams(invalidParams, &paramIdx, &contentEncAlg, &contentType);

            ASSERT_NE(HITLS_CMS_DataEncrypt(invalidEncCms, &plaintextBuf, invalidParams), HITLS_PKI_SUCCESS);
            HITLS_CMS_Free(invalidEncCms);
            TestErrClear();
        }

        encCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
        ASSERT_NE(encCms, NULL);
        BSL_Param params[10];
        uint32_t paramIdx = AddKtriRecipientParams(params, recipientCert, recipientKey, &recipientType,
            &recipientKeyEncAlg, &oaepMdId, &oaepMgf1Id, &oaepLabelBuf);
        AddContentEncryptParams(params, &paramIdx, &contentEncAlg, &contentType);

        ASSERT_EQ(HITLS_CMS_DataEncrypt(encCms, &plaintextBuf, params), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, encCms, NULL, &encoded), HITLS_PKI_SUCCESS);
        ASSERT_NE(encoded.data, NULL);
        ASSERT_LT(0, encoded.dataLen);

        ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms), HITLS_PKI_SUCCESS);
        ASSERT_NE(decCms, NULL);
        ASSERT_EQ(decCms->dataType, BSL_CID_PKCS7_ENVELOPEDDATA);
        ASSERT_NE(decCms->ctx.envelopedData, NULL);
        recipientInfo = BSL_LIST_GET_FIRST(decCms->ctx.envelopedData->recipientInfos);
        ASSERT_NE(recipientInfo, NULL);
        ASSERT_EQ(recipientInfo->type, CMS_RECIPIENT_TYPE_KTRI);
        ktri = recipientInfo->d.ktri;
        ASSERT_NE(ktri, NULL);
        ASSERT_EQ(ktri->keyEncryAlg, BSL_CID_RSAES_OAEP);

        BSL_Param decryptParams[8];
        (void)AddKtriRecipientParams(decryptParams, recipientCert, recipientKey, &recipientType,
            &recipientKeyEncAlg, NULL, NULL, NULL);

        {
            int32_t invalidRecipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
            BslCid invalidRecipientKeyEncAlg = BSL_CID_RSAES_OAEP;
            BSL_Param invalidDecryptParams[8];

            (void)AddKtriRecipientParams(invalidDecryptParams, recipientCert, NULL, &invalidRecipientType,
                &invalidRecipientKeyEncAlg, NULL, NULL, NULL);

            ASSERT_NE(HITLS_CMS_DataDecrypt(decCms, invalidDecryptParams, &decrypted), HITLS_PKI_SUCCESS);
            TestErrClear();
        }

        ASSERT_EQ(HITLS_CMS_DataDecrypt(decCms, decryptParams, &decrypted), HITLS_PKI_SUCCESS);
        ASSERT_NE(decrypted.data, NULL);
        ASSERT_EQ(decrypted.dataLen, plaintextBuf.dataLen);
        ASSERT_EQ(memcmp(decrypted.data, plaintextBuf.data, plaintextBuf.dataLen), 0);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CMS_Free(encCms);
    HITLS_CMS_Free(decCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(decrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_ONE_SHOT_ENCRYPT_DECRYPT_STUB_TC001
 * @title Test EnvelopedData one-shot encrypt and decrypt with malloc failures
 * @precon Initialize CMS EnvelopedData structure and prepare recipient cert/key
 * @brief
 *    1. Encrypt plaintext successfully to count malloc calls in HITLS_CMS_DataEncrypt
 *    2. Test encryption with systematic malloc failures
 *    3. Parse encrypted result and decrypt successfully to count malloc calls in HITLS_CMS_DataDecrypt
 *    4. Test decryption with systematic malloc failures
 * @expect
 *    1. Encryption succeeds
 *    2. Encryption malloc failure paths return error
 *    3. Decryption succeeds
 *    4. Decryption malloc failure paths are covered without memory leaks
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_ONE_SHOT_ENCRYPT_DECRYPT_STUB_TC001(int encAlg, char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_AES)
    (void)certPath;
    (void)keyPath;
    (void)encAlg;
    SKIP_TEST();
#else
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    HITLS_CMS *encCms = NULL;
    HITLS_CMS *encCms1 = NULL;
    HITLS_CMS *decCms = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer decrypted = {0};
    const char *plaintext = "Hello, EnvelopedData Stub!";
    BSL_Buffer plaintextBuf = {(uint8_t *)plaintext, strlen(plaintext)};
    uint32_t totalMallocCount = 0;
    BslCid contentEncAlg = (BslCid)encAlg;
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid recipientKeyEncAlg = BSL_CID_RSA;
    BSL_Param encParams[10];
    BSL_Param decryptParams[8];

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);
    uint32_t paramIdx = AddKtriRecipientParams(encParams, recipientCert, recipientKey, &recipientType,
        &recipientKeyEncAlg, NULL, NULL, NULL);
    AddContentEncryptParams(encParams, &paramIdx, &contentEncAlg, &contentType);
    (void)AddKtriRecipientParams(decryptParams, recipientCert, recipientKey, &recipientType, &recipientKeyEncAlg,
        NULL, NULL, NULL);

    encCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(encCms, NULL);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_DataEncrypt(encCms, &plaintextBuf, encParams), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_TRUE(TestIsErrStackEmpty());
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        encCms1 = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
        ASSERT_NE(encCms1, NULL);
        STUB_EnableMallocFail(true);
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(HITLS_CMS_DataEncrypt(encCms1, &plaintextBuf, encParams), HITLS_PKI_SUCCESS);
        STUB_EnableMallocFail(false);
        HITLS_CMS_Free(encCms1);
        encCms1 = NULL;
    }
    TestErrClear();

    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, encCms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms), HITLS_PKI_SUCCESS);
    ASSERT_NE(decCms, NULL);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_DataDecrypt(decCms, decryptParams, &decrypted), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_NE(decrypted.data, NULL);
    ASSERT_EQ(decrypted.dataLen, plaintextBuf.dataLen);
    ASSERT_EQ(memcmp(decrypted.data, plaintextBuf.data, plaintextBuf.dataLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
    BSL_SAL_Free(decrypted.data);
    decrypted.data = NULL;
    decrypted.dataLen = 0;

    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        BSL_Buffer tmp = {0};
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        (void)HITLS_CMS_DataDecrypt(decCms, decryptParams, &tmp);
        BSL_SAL_Free(tmp.data);
    }
    TestErrClear();
EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    HITLS_CMS_Free(encCms);
    HITLS_CMS_Free(encCms1);
    HITLS_CMS_Free(decCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(decrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_STREAM_ENCRYPT_DECRYPT_STUB_TC001
 * @title Test EnvelopedData streaming encrypt and decrypt with malloc failures
 * @precon Initialize CMS EnvelopedData structure and prepare recipient cert/key
 * @brief
 *    1. Streaming encrypt plaintext successfully to count malloc calls
 *    2. Test streaming encryption with systematic malloc failures
 *    3. Parse encrypted result and streaming decrypt successfully to count malloc calls
 *    4. Test streaming decryption with systematic malloc failures
 * @expect
 *    1. Streaming encryption succeeds
 *    2. Streaming encryption malloc failure paths return error
 *    3. Streaming decryption succeeds
 *    4. Streaming decryption malloc failure paths are covered without memory leaks
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_STREAM_ENCRYPT_DECRYPT_STUB_TC001(int encAlg, char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_AES)
    (void)certPath;
    (void)keyPath;
    (void)encAlg;
    SKIP_TEST();
#else
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    HITLS_CMS *streamCms = NULL;
    HITLS_CMS *streamCms1 = NULL;
    HITLS_CMS *streamDecCms = NULL;
    HITLS_CMS *streamDecCms1 = NULL;
    BSL_Buffer streamEncoded = {0};
    BSL_Buffer streamCiphertext = {0};
    BSL_Buffer streamDecrypted = {0};
    const char *streamPlaintext = "Hello, Streaming Stub!";
    BSL_Buffer plainChunks[] = {
        {(uint8_t *)"Hello, ", strlen("Hello, ")},
        {(uint8_t *)"Streaming ", strlen("Streaming ")},
        {(uint8_t *)"Stub!", strlen("Stub!")}
    };
    uint32_t totalMallocCount = 0;
    BslCid contentEncAlg = (BslCid)encAlg;
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid recipientKeyEncAlg = BSL_CID_RSA;
    BSL_Param encParams[10];
    BSL_Param decryptParams[8];

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);
    uint32_t paramIdx = AddKtriRecipientParams(encParams, recipientCert, recipientKey, &recipientType,
        &recipientKeyEncAlg, NULL, NULL, NULL);
    AddContentEncryptParams(encParams, &paramIdx, &contentEncAlg, &contentType);
    (void)AddKtriRecipientParams(decryptParams, recipientCert, recipientKey, &recipientType, &recipientKeyEncAlg,
        NULL, NULL, NULL);

    streamCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(streamCms, NULL);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, streamCms, encParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(streamCms, NULL, encParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(StreamEncryptToBuffer(streamCms, plainChunks, sizeof(plainChunks) / sizeof(plainChunks[0]),
        &streamCiphertext), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_TRUE(TestIsErrStackEmpty());

    for (uint32_t i = 0; i < totalMallocCount; i++) {
        int32_t ret;
        BSL_Buffer tmpCiphertext = {0};

        streamCms1 = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
        ASSERT_NE(streamCms1, NULL);
        STUB_EnableMallocFail(true);
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ret = HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, streamCms1, encParams);
        if (ret == HITLS_PKI_SUCCESS) {
            ret = HITLS_CMS_DataEncrypt(streamCms1, NULL, encParams);
        }
        if (ret == HITLS_PKI_SUCCESS) {
            ret = StreamEncryptToBuffer(streamCms1, plainChunks, sizeof(plainChunks) / sizeof(plainChunks[0]),
                &tmpCiphertext);
        }
        ASSERT_NE(ret, HITLS_PKI_SUCCESS);
        STUB_EnableMallocFail(false);
        BSL_SAL_Free(tmpCiphertext.data);
        HITLS_CMS_Free(streamCms1);
        streamCms1 = NULL;
    }
    TestErrClear();

    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, streamCms, NULL, &streamEncoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &streamEncoded, &streamDecCms), HITLS_PKI_SUCCESS);
    ASSERT_NE(streamDecCms, NULL);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_DECRYPT, streamDecCms, decryptParams), HITLS_PKI_SUCCESS);
    ASSERT_NE(streamDecCms->ctx.envelopedData, NULL);
    uint32_t halfLen = streamCiphertext.dataLen / 2;
    BSL_Buffer cipherChunks[] = {
        {streamCiphertext.data, halfLen},
        {streamCiphertext.data + halfLen, streamCiphertext.dataLen - halfLen}
    };
    ASSERT_EQ(StreamDecryptToBuffer(streamDecCms, cipherChunks, sizeof(cipherChunks) / sizeof(cipherChunks[0]),
        &streamDecrypted), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_NE(streamDecrypted.data, NULL);
    ASSERT_EQ(streamDecrypted.dataLen, strlen(streamPlaintext));
    ASSERT_EQ(memcmp(streamDecrypted.data, streamPlaintext, strlen(streamPlaintext)), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
    BSL_SAL_Free(streamDecrypted.data);
    streamDecrypted.data = NULL;
    streamDecrypted.dataLen = 0;

    for (uint32_t i = 0; i < totalMallocCount; i++) {
        int32_t ret;
        BSL_Buffer tmpPlaintext = {0};

        ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &streamEncoded, &streamDecCms1), HITLS_PKI_SUCCESS);
        ASSERT_NE(streamDecCms1, NULL);
        STUB_EnableMallocFail(true);
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ret = HITLS_CMS_DataInit(HITLS_CMS_OPT_DECRYPT, streamDecCms1, decryptParams);
        if (ret == HITLS_PKI_SUCCESS) {
            ret = StreamDecryptToBuffer(streamDecCms1, cipherChunks, sizeof(cipherChunks) / sizeof(cipherChunks[0]),
                &tmpPlaintext);
        }
        (void)ret;
        STUB_EnableMallocFail(false);
        BSL_SAL_Free(tmpPlaintext.data);
        HITLS_CMS_Free(streamDecCms1);
        streamDecCms1 = NULL;
    }
    TestErrClear();

EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    HITLS_CMS_Free(streamCms);
    HITLS_CMS_Free(streamCms1);
    HITLS_CMS_Free(streamDecCms);
    HITLS_CMS_Free(streamDecCms1);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(streamEncoded.data);
    BSL_SAL_Free(streamCiphertext.data);
    BSL_SAL_Free(streamDecrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_RSA_STREAMING_ENCRYPT_DECRYPT_TC001
 * @title Test EnvelopedData streaming encryption and decryption
 * @precon Initialize CMS EnvelopedData structure
 * @brief
 * 1. Create CMS EnvelopedData handle
 * 2. Initialize streaming encryption with HITLS_CMS_DataInit
 * 3. Update with data chunks using HITLS_CMS_DataUpdateEx
 * 4. Finalize with HITLS_CMS_DataFinalEx
 * 5. Encode and parse the result
 * 6. Initialize streaming decryption with HITLS_CMS_DataInit
 * 7. Update with ciphertext chunks
 * 8. Finalize with HITLS_CMS_DataFinalEx to retrieve plaintext
 * 9. Verify decrypted result
 * @expect
 * 1. All operations succeed
 * 2. Encrypted data can be decoded
 * 3. Decrypted data matches the original string
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_RSA_STREAMING_ENCRYPT_DECRYPT_TC001(int encAlg, char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_AES)
    (void)certPath;
    (void)keyPath;
    (void)encAlg;
    SKIP_TEST();
#else
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    HITLS_CMS *cms = NULL;
    HITLS_CMS *decCms = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer ciphertext = {0};
    BSL_Buffer decrypted = {0};
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid recipientKeyEncAlg = BSL_CID_RSA;

    // Initialize random number generator
    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);

    // Load recipient certificate and private key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);

    // Create CMS EnvelopedData
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(cms, NULL);

    // Prepare parameters
    BslCid contentEncAlg = (BslCid)encAlg;
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;

    BSL_Param initParams[10];
    uint32_t paramIdx = AddKtriRecipientParams(initParams, recipientCert, recipientKey, &recipientType,
        &recipientKeyEncAlg, NULL, NULL, NULL);
    AddContentEncryptParams(initParams, &paramIdx, &contentEncAlg, &contentType);

    // Initialize streaming encryption
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, cms, initParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(cms, NULL, initParams), HITLS_PKI_SUCCESS);

    BSL_Buffer plainChunks[] = {
        {(uint8_t *)"Hello, ", strlen("Hello, ")},
        {(uint8_t *)"Streaming ", strlen("Streaming ")},
        {(uint8_t *)"EnvelopedData!", strlen("EnvelopedData!")}
    };

    ASSERT_EQ(StreamEncryptToBuffer(cms, plainChunks, sizeof(plainChunks) / sizeof(plainChunks[0]), &ciphertext),
        HITLS_PKI_SUCCESS);

    // Encode to buffer
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_NE(encoded.data, NULL);
    ASSERT_LT(0, encoded.dataLen);

    // Parse encrypted data into decCms handle
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms), HITLS_PKI_SUCCESS);
    ASSERT_NE(decCms, NULL);
    ASSERT_EQ(decCms->dataType, BSL_CID_PKCS7_ENVELOPEDDATA);

    // Initialize streaming decryption
    BSL_Param decInitParams[8];
    (void)AddKtriRecipientParams(decInitParams, recipientCert, recipientKey, &recipientType, &recipientKeyEncAlg,
        NULL, NULL, NULL);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_DECRYPT, decCms, decInitParams), HITLS_PKI_SUCCESS);

    ASSERT_NE(decCms->ctx.envelopedData, NULL);

    // Stream ciphertext in chunks
    uint32_t chunkLen = ciphertext.dataLen / 3;
    BSL_Buffer cipherChunks[] = {
        {ciphertext.data, chunkLen},
        {ciphertext.data + chunkLen, chunkLen},
        {ciphertext.data + 2 * chunkLen, ciphertext.dataLen - 2 * chunkLen}
    };

    ASSERT_EQ(StreamDecryptToBuffer(decCms, cipherChunks, sizeof(cipherChunks) / sizeof(cipherChunks[0]), &decrypted),
        HITLS_PKI_SUCCESS);

    // Verify plaintext matches the original stream payload
    const char *expectedPlaintext = "Hello, Streaming EnvelopedData!";
    ASSERT_NE(decrypted.data, NULL);
    ASSERT_EQ(decrypted.dataLen, strlen(expectedPlaintext));
    ASSERT_EQ(memcmp(decrypted.data, expectedPlaintext, decrypted.dataLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(decCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(ciphertext.data);
    BSL_SAL_Free(decrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_RSA_OAEP_STREAMING_ENCRYPT_DECRYPT_TC001
 * @title Test EnvelopedData RSA-OAEP streaming encryption and decryption
 * @precon Initialize CMS EnvelopedData structure
 * @brief
 * 1. Verify OAEP recipient parameter validation rejects invalid streaming init configuration
 * 2. Create CMS EnvelopedData handle
 * 3. Initialize streaming encryption with RSAES-OAEP recipient parameters
 *    and a non-empty OAEP label
 * 4. Update with data chunks using HITLS_CMS_DataUpdateEx
 * 5. Finalize with HITLS_CMS_DataFinalEx
 * 6. Encode and parse the result
 * 7. Verify parsed recipient key transport algorithm is RSAES-OAEP
 * 8. Verify streaming decryption parameter validation rejects missing private key
 * 9. Initialize streaming decryption with HITLS_CMS_DataInit
 * 10. Update with ciphertext chunks
 * 11. Finalize with HITLS_CMS_DataFinalEx to retrieve plaintext
 * 12. Verify decrypted result
 * @expect
 * 1. Invalid OAEP streaming configurations are rejected
 * 2. Streaming encryption with non-empty OAEP label succeeds
 * 3. Parsed recipient key transport algorithm is RSAES-OAEP
 * 4. Decrypted data matches the original string
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_RSA_OAEP_STREAMING_ENCRYPT_DECRYPT_TC001(int encAlg, char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_AES) || !defined(HITLS_CRYPTO_RSAES_OAEP)
    (void)certPath;
    (void)keyPath;
    (void)encAlg;
    SKIP_TEST();
#else
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    HITLS_CMS *cms = NULL;
    HITLS_CMS *decCms = NULL;
    HITLS_CMS *invalidDecCms = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer ciphertext = {0};
    BSL_Buffer decrypted = {0};
    CMS_RecipientInfo *recipientInfo = NULL;
    CMS_KeyTransRecipientInfo *ktri = NULL;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid recipientKeyEncAlg = BSL_CID_RSAES_OAEP;

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(cms, NULL);

    {
        BslCid contentEncAlg = (BslCid)encAlg;
        BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
        int32_t oaepMdId = CRYPT_MD_SHA256;
        int32_t oaepMgf1Id = CRYPT_MD_SHA256;
        uint8_t oaepLabel[] = "openhitls-oaep-label";
        uint8_t invalidLabel = 0x01;
        BSL_Buffer oaepLabelBuf = {oaepLabel, sizeof(oaepLabel) - 1};
        const char *expectedPlaintext = "Hello, Streaming RSA-OAEP EnvelopedData!";
        BSL_Buffer plainChunks[] = {
            {(uint8_t *)"Hello, ", strlen("Hello, ")},
            {(uint8_t *)"Streaming ", strlen("Streaming ")},
            {(uint8_t *)"RSA-OAEP EnvelopedData!", strlen("RSA-OAEP EnvelopedData!")}
        };

        {
            HITLS_CMS *invalidCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
            int32_t invalidRecipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
            BslCid invalidRecipientKeyEncAlg = BSL_CID_RSAES_OAEP;
            BSL_Buffer invalidLabelBuf = {NULL, sizeof(invalidLabel)};
            BSL_Param invalidInitParams[10];
            ASSERT_NE(invalidCms, NULL);

            uint32_t paramIdx = AddKtriRecipientParams(invalidInitParams, recipientCert, recipientKey,
                &invalidRecipientType, &invalidRecipientKeyEncAlg, &oaepMdId, &oaepMgf1Id, &invalidLabelBuf);
            AddContentEncryptParams(invalidInitParams, &paramIdx, &contentEncAlg, &contentType);

            ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, invalidCms, invalidInitParams), HITLS_PKI_SUCCESS);
            ASSERT_NE(HITLS_CMS_DataEncrypt(invalidCms, NULL, invalidInitParams), HITLS_PKI_SUCCESS);
            HITLS_CMS_Free(invalidCms);
            TestErrClear();
        }

        BSL_Param initParams[10];
        uint32_t paramIdx = AddKtriRecipientParams(initParams, recipientCert, recipientKey, &recipientType,
            &recipientKeyEncAlg, &oaepMdId, &oaepMgf1Id, &oaepLabelBuf);
        AddContentEncryptParams(initParams, &paramIdx, &contentEncAlg, &contentType);

        ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, cms, initParams), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataEncrypt(cms, NULL, initParams), HITLS_PKI_SUCCESS);
        ASSERT_EQ(StreamEncryptToBuffer(cms, plainChunks, sizeof(plainChunks) / sizeof(plainChunks[0]), &ciphertext),
            HITLS_PKI_SUCCESS);

        ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
        ASSERT_NE(encoded.data, NULL);
        ASSERT_LT(0, encoded.dataLen);

        ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms), HITLS_PKI_SUCCESS);
        ASSERT_NE(decCms, NULL);
        ASSERT_EQ(decCms->dataType, BSL_CID_PKCS7_ENVELOPEDDATA);
        ASSERT_NE(decCms->ctx.envelopedData, NULL);
        recipientInfo = BSL_LIST_GET_FIRST(decCms->ctx.envelopedData->recipientInfos);
        ASSERT_NE(recipientInfo, NULL);
        ASSERT_EQ(recipientInfo->type, CMS_RECIPIENT_TYPE_KTRI);
        ktri = recipientInfo->d.ktri;
        ASSERT_NE(ktri, NULL);
        ASSERT_EQ(ktri->keyEncryAlg, BSL_CID_RSAES_OAEP);

        BSL_Param decInitParams[8];
        (void)AddKtriRecipientParams(decInitParams, recipientCert, recipientKey, &recipientType,
            &recipientKeyEncAlg, NULL, NULL, NULL);
        {
            int32_t invalidRecipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
            BslCid invalidRecipientKeyEncAlg = BSL_CID_RSAES_OAEP;
            BSL_Param invalidDecInitParams[8];

            (void)AddKtriRecipientParams(invalidDecInitParams, recipientCert, NULL, &invalidRecipientType,
                &invalidRecipientKeyEncAlg, NULL, NULL, NULL);
            ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &invalidDecCms), HITLS_PKI_SUCCESS);
            ASSERT_NE(HITLS_CMS_DataInit(HITLS_CMS_OPT_DECRYPT, invalidDecCms, invalidDecInitParams), HITLS_PKI_SUCCESS);
            HITLS_CMS_Free(invalidDecCms);
            invalidDecCms = NULL;
            TestErrClear();
        }
        ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_DECRYPT, decCms, decInitParams), HITLS_PKI_SUCCESS);

        {
            uint32_t chunkLen;

            chunkLen = ciphertext.dataLen / 3;
            BSL_Buffer cipherChunks[] = {
                {ciphertext.data, chunkLen},
                {ciphertext.data + chunkLen, chunkLen},
                {ciphertext.data + 2 * chunkLen, ciphertext.dataLen - 2 * chunkLen}
            };

            ASSERT_EQ(StreamDecryptToBuffer(decCms, cipherChunks, sizeof(cipherChunks) / sizeof(cipherChunks[0]),
                &decrypted), HITLS_PKI_SUCCESS);
        }

        ASSERT_NE(decrypted.data, NULL);
        ASSERT_EQ(decrypted.dataLen, strlen(expectedPlaintext));
        ASSERT_EQ(memcmp(decrypted.data, expectedPlaintext, decrypted.dataLen), 0);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(decCms);
    HITLS_CMS_Free(invalidDecCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(ciphertext.data);
    BSL_SAL_Free(decrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_RSA_MULTI_RECIPIENT_TC001
 * @title Test EnvelopedData with multiple recipients
 * @precon Multiple recipient certificates
 * @brief
 *    1. Create CMS EnvelopedData with multiple recipients
 *    2. Encrypt plaintext for all recipients
 *    3. Each recipient can decrypt independently
 * @expect
 *    1. Encryption succeeds for all recipients
 *    2. Each recipient can decrypt successfully
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_RSA_MULTI_RECIPIENT_TC001(char *cert1Path, char *key1Path, char *cert2Path, char *key2Path)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_BSL_SAL_FILE) || \
    !defined(HITLS_CRYPTO_AES)
    (void)cert1Path;
    (void)key1Path;
    (void)cert2Path;
    (void)key2Path;
    SKIP_TEST();
#else
    HITLS_X509_Cert *cert1 = NULL;
    HITLS_X509_Cert *cert2 = NULL;
    CRYPT_EAL_PkeyCtx *key1 = NULL;
    CRYPT_EAL_PkeyCtx *key2 = NULL;
    HITLS_CMS *encCms = NULL;
    HITLS_CMS *decCms1 = NULL;
    HITLS_CMS *decCms2 = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer ciphertext = {0};
    BSL_Buffer decrypted1 = {0};
    BSL_Buffer decrypted2 = {0};
    int32_t recipient1Type = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid recipient1KeyEncAlg = BSL_CID_RSAES_OAEP;
    int32_t recipient2Type = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid recipient2KeyEncAlg = BSL_CID_RSA;
    int32_t decryptType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid decryptKeyEncAlg = BSL_CID_RSA;
    int32_t oaepMdId = CRYPT_MD_SHA256;
    int32_t oaepMgf1Id = CRYPT_MD_SHA256;

    // Initialize random number generator
    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);

    // Load certificates and keys
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, cert1Path, &cert1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        key1Path, NULL, 0, &key1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, cert2Path, &cert2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        key2Path, NULL, 0, &key2), HITLS_PKI_SUCCESS);

    // Create plaintext
    const char *plaintext = "Multi-recipient test message";
    BSL_Buffer plaintextBuf = {(uint8_t *)plaintext, strlen(plaintext)};

    // Create and encrypt
    encCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(encCms, NULL);

    BslCid encAlg = BSL_CID_AES256_CBC;
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;

    BSL_Param initParams[] = {
        {HITLS_CMS_PARAM_CONTENT_ENC_ALG, BSL_PARAM_TYPE_INT32, &encAlg, sizeof(BslCid), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(BslCid), 0},
        BSL_PARAM_END
    };
    BSL_Param recipient1Params[8];
    BSL_Param recipient2Params[8];
    (void)AddKtriRecipientParams(recipient1Params, cert1, key1, &recipient1Type, &recipient1KeyEncAlg,
        &oaepMdId, &oaepMgf1Id, NULL);
    (void)AddKtriRecipientParams(recipient2Params, cert2, key2, &recipient2Type, &recipient2KeyEncAlg,
        NULL, NULL, NULL);

    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, encCms, initParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(encCms, NULL, recipient1Params), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(encCms, NULL, recipient2Params), HITLS_PKI_SUCCESS);
    ASSERT_EQ(StreamEncryptToBuffer(encCms, &plaintextBuf, 1, &ciphertext), HITLS_PKI_SUCCESS);

    // Encode
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, encCms, NULL, &encoded), HITLS_PKI_SUCCESS);

    // Decrypt with first recipient
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms1), HITLS_PKI_SUCCESS);
    BSL_Param decryptParams1[8];
    (void)AddKtriRecipientParams(decryptParams1, cert1, key1, &decryptType, &decryptKeyEncAlg,
        NULL, NULL, NULL);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_DECRYPT, decCms1, decryptParams1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(StreamDecryptToBuffer(decCms1, &ciphertext, 1, &decrypted1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(decrypted1.data, plaintextBuf.data, plaintextBuf.dataLen), 0);

    // Decrypt with second recipient
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms2), HITLS_PKI_SUCCESS);
    BSL_Param decryptParams2[8];
    (void)AddKtriRecipientParams(decryptParams2, cert2, key2, &decryptType, &decryptKeyEncAlg,
        NULL, NULL, NULL);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_DECRYPT, decCms2, decryptParams2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(StreamDecryptToBuffer(decCms2, &ciphertext, 1, &decrypted2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(decrypted2.data, plaintextBuf.data, plaintextBuf.dataLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CMS_Free(encCms);
    HITLS_CMS_Free(decCms1);
    HITLS_CMS_Free(decCms2);
    HITLS_X509_CertFree(cert1);
    HITLS_X509_CertFree(cert2);
    CRYPT_EAL_PkeyFreeCtx(key1);
    CRYPT_EAL_PkeyFreeCtx(key2);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(ciphertext.data);
    BSL_SAL_Free(decrypted1.data);
    BSL_SAL_Free(decrypted2.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVDATA_NULL_PARAMS_TC001
 * @title Test EnvelopedData with null parameters
 * @precon Valid CMS handle
 * @brief
 *    1. Call APIs with NULL parameters
 *    2. Verify appropriate errors are returned
 * @expect
 *    1. All operations return appropriate error codes
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_NULL_PARAMS_TC001(void)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_AES)
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *streamCms = NULL;
    HITLS_CMS *finalCms = NULL;
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    BSL_Buffer plaintext = {(uint8_t *)"test", 4};
    BSL_Buffer output = {0};
    uint8_t smallOutputData[1];
    BSL_Buffer outputWithNullData = {NULL, CMS_TEST_STREAM_OUT_SIZE};
    BSL_Buffer smallOutput = {smallOutputData, sizeof(smallOutputData)};
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid recipientKeyEncAlg = BSL_CID_RSA;
    BslCid contentEncAlg = BSL_CID_AES256_CBC;
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
    BSL_Param initParams[] = {
        {HITLS_CMS_PARAM_CONTENT_ENC_ALG, BSL_PARAM_TYPE_INT32, &contentEncAlg, sizeof(BslCid), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(BslCid), 0},
        BSL_PARAM_END
    };
    BSL_Param recipientParams[8];

    // Test NULL cms
    ASSERT_NE(HITLS_CMS_DataEncrypt(NULL, &plaintext, NULL), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_CMS_DataDecrypt(NULL, NULL, &output), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, NULL, NULL), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_CMS_DataUpdateEx(NULL, &plaintext, &output), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_CMS_DataFinalEx(NULL, NULL, &output), HITLS_PKI_SUCCESS);

    // Create valid cms
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(cms, NULL);

    // Test NULL plaintext
    ASSERT_NE(HITLS_CMS_DataEncrypt(cms, NULL, NULL), HITLS_PKI_SUCCESS);

    // Test plaintext encryption without recipient parameters
    ASSERT_NE(HITLS_CMS_DataEncrypt(cms, &plaintext, NULL), HITLS_PKI_SUCCESS);

    // Test invalid state
    ASSERT_NE(HITLS_CMS_DataUpdateEx(cms, &plaintext, &output), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_CMS_DataFinalEx(cms, NULL, &output), HITLS_PKI_SUCCESS);

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1,
        "../testdata/cert/asn1/cms/envelopeddata/rsa/rsa_p1_v1.crt.der", &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        "../testdata/cert/asn1/cms/envelopeddata/rsa/rsa_p1.key.der", NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);
    (void)AddKtriRecipientParams(recipientParams, recipientCert, recipientKey, &recipientType, &recipientKeyEncAlg,
        NULL, NULL, NULL);

    streamCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(streamCms, NULL);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, streamCms, initParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdateEx(streamCms, &plaintext, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataUpdateEx(streamCms, &plaintext, &outputWithNullData), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataUpdateEx(streamCms, &plaintext, &smallOutput), CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
    ASSERT_EQ(HITLS_CMS_DataFinalEx(streamCms, NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(streamCms, NULL, recipientParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinalEx(streamCms, NULL, &outputWithNullData), HITLS_CMS_ERR_NULL_POINTER);

    finalCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(finalCms, NULL);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, finalCms, initParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(finalCms, NULL, recipientParams), HITLS_PKI_SUCCESS);
    smallOutput.dataLen = sizeof(smallOutputData);
    ASSERT_EQ(HITLS_CMS_DataFinalEx(finalCms, NULL, &smallOutput), CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);

EXIT:
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(streamCms);
    HITLS_CMS_Free(finalCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    TestRandDeInit();
#endif
}
/* END_CASE */

static uint32_t AddKemriRecipientParams(BSL_Param *params, HITLS_X509_Cert *cert, CRYPT_EAL_PkeyCtx *privateKey,
    int32_t *recipientType)
{
    uint32_t idx = 0;

    params[idx++] = (BSL_Param){HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32,
        recipientType, sizeof(*recipientType), 0};
    params[idx++] = (BSL_Param){HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR,
        cert, sizeof(HITLS_X509_Cert *), 0};
    if (privateKey != NULL) {
        params[idx++] = (BSL_Param){HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR,
            privateKey, sizeof(CRYPT_EAL_PkeyCtx *), 0};
    }
    params[idx] = (BSL_Param)BSL_PARAM_END;
    return idx;
}

static uint32_t SDV_CMS_CountRecipientType(CMS_RecipientInfos *recipientInfos, CMS_RecipientType type)
{
    uint32_t count = 0;
    if (recipientInfos == NULL) {
        return 0;
    }
    for (CMS_RecipientInfo *recipient = BSL_LIST_GET_FIRST(recipientInfos); recipient != NULL;
        recipient = BSL_LIST_GET_NEXT(recipientInfos)) {
        if (recipient->type == type) {
            ++count;
        }
    }
    return count;
}

static void SDV_CMS_CheckKemRecipientInfo(CMS_RecipientInfos *recipientInfos, BslCid expectedKemAlg,
    int32_t needEncryptedKey)
{
    BslCid expectedWrapAlg = BSL_CID_UNKNOWN;
    uint32_t expectedKekLen = 0;
    CMS_KEMRecipientInfo *kemri = NULL;

    ASSERT_NE(recipientInfos, NULL);
    for (CMS_RecipientInfo *recipient = BSL_LIST_GET_FIRST(recipientInfos); recipient != NULL;
        recipient = BSL_LIST_GET_NEXT(recipientInfos)) {
        if (recipient->type == CMS_RECIPIENT_TYPE_KEMRI) {
            kemri = recipient->d.kemri;
            break;
        }
    }
    ASSERT_NE(kemri, NULL);
    if (expectedKemAlg == BSL_CID_ML_KEM_512) {
        expectedWrapAlg = BSL_CID_AES128_WRAP_NOPAD;
        expectedKekLen = 16;
    } else if (expectedKemAlg == BSL_CID_ML_KEM_768 || expectedKemAlg == BSL_CID_ML_KEM_1024) {
        expectedWrapAlg = BSL_CID_AES256_WRAP_NOPAD;
        expectedKekLen = 32;
    }
    ASSERT_EQ(kemri->version, 0);
    ASSERT_EQ(kemri->kemAlg, expectedKemAlg);
    ASSERT_EQ(kemri->kdfAlg, BSL_CID_HKDF_SHA256);
    ASSERT_EQ(kemri->wrapAlg, expectedWrapAlg);
    ASSERT_EQ(kemri->kekLen, expectedKekLen);
    if (needEncryptedKey) {
        ASSERT_LT(0, kemri->kemCiphertext.dataLen);
        ASSERT_LT(0, kemri->encryptedKey.dataLen);
    }
EXIT:
    return;
}

/**
 * @test SDV_CMS_ENVELOPEDDATA_MLKEM_PARSE_DECRYPT_FILE_TC001
 * @title Parse external ML-KEM EnvelopedData file and verify decrypted content
 * @precon External ML-KEM CMS EnvelopedData file and matching recipient certificate/private key are available
 * @brief
 *    1. Read the original CMS file and expected plaintext file
 *    2. Parse CMS EnvelopedData from file
 *    3. Verify parsed KEMRecipientInfo fields from the parsed EnvelopedData
 *    4. Re-encode CMS and compare with the original file bytes
 *    5. Decrypt EnvelopedData with the matching recipient key and certificate
 *    6. Compare decrypted output with the expected plaintext file
 * @expect
 *    1. Parsing succeeds
 *    2. Parsed structure matches the expected ML-KEM + HKDF-SHA256 + AES-KW layout
 *    3. Re-encoded bytes match the original file
 *    4. Decryption succeeds
 *    5. Decrypted plaintext matches the expected file content
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_MLKEM_PARSE_DECRYPT_FILE_TC001(char *envPath, char *certPath, char *keyPath, int keyType,
    int expectedKemAlg, char *msgPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_MLKEM) || \
    !defined(HITLS_CRYPTO_HKDF) || !defined(HITLS_CRYPTO_AES)
    (void)envPath;
    (void)certPath;
    (void)keyPath;
    (void)keyType;
    (void)expectedKemAlg;
    (void)msgPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    BSL_Buffer envFile = {0};
    BSL_Buffer expectedMsg = {0};
    BSL_Buffer encoded = {0};
    BSL_Buffer decrypted = {0};
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KEMRI;

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(envPath, &envFile.data, &envFile.dataLen), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(msgPath, &expectedMsg.data, &expectedMsg.dataLen), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, keyType, keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, envPath, &cms), HITLS_PKI_SUCCESS);
    ASSERT_NE(cms, NULL);
    ASSERT_EQ(cms->dataType, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(cms->ctx.envelopedData, NULL);
    ASSERT_EQ(cms->ctx.envelopedData->version, 3);
    ASSERT_EQ(BSL_LIST_COUNT(cms->ctx.envelopedData->recipientInfos), 1);

    SDV_CMS_CheckKemRecipientInfo(cms->ctx.envelopedData->recipientInfos, (BslCid)expectedKemAlg, true);

    ASSERT_LT(0, cms->ctx.envelopedData->encryptedContentInfo.encryptedContent.dataLen);

    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("mlkem envdata encode compare", encoded.data, encoded.dataLen, envFile.data, envFile.dataLen);

    BSL_Param decryptParams[8];
    (void)AddKemriRecipientParams(decryptParams, recipientCert, recipientKey, &recipientType);

    ASSERT_EQ(HITLS_CMS_DataDecrypt(cms, decryptParams, &decrypted), HITLS_PKI_SUCCESS);
    ASSERT_NE(decrypted.data, NULL);
    ASSERT_EQ(decrypted.dataLen, expectedMsg.dataLen);
    ASSERT_COMPARE("mlkem decrypted content compare", decrypted.data, decrypted.dataLen, expectedMsg.data,
        expectedMsg.dataLen);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CMS_Free(cms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(envFile.data);
    BSL_SAL_Free(expectedMsg.data);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(decrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_MLKEM_ENCRYPT_DECRYPT_TC001
 * @title Test ML-KEM EnvelopedData one-shot and streaming encryption and decryption
 * @precon Prepare ML-KEM recipient certificate and private key
 * @brief
 *    1. Create CMS EnvelopedData handle
 *    2. Add ML-KEM recipient certificate
 *    3. Encrypt plaintext using HITLS_CMS_DataEncrypt and verify one-shot decrypt
 *    4. Parse encrypted data and verify KEMRecipientInfo fields
 *    5. Re-encode parsed data and compare with the generated bytes
 *    6. Perform streaming encrypt/decrypt using HITLS_CMS_DataInit/Update/Final
 * @expect
 *    1. One-shot encryption succeeds
 *    2. Parsed structure matches the expected ML-KEM profile
 *    3. One-shot and streaming decryption succeed
 *    4. Plaintext matches original in both flows
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_MLKEM_ENCRYPT_DECRYPT_TC001(int encAlg, int keyType, int expectedKemAlg,
    char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_MLKEM) || \
    !defined(HITLS_CRYPTO_HKDF) || !defined(HITLS_CRYPTO_AES)
    (void)encAlg;
    (void)keyType;
    (void)expectedKemAlg;
    (void)certPath;
    (void)keyPath;
    SKIP_TEST();
#else
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    CRYPT_EAL_PkeyCtx *recipientPubKey = NULL;
    HITLS_CMS *encCms = NULL;
    HITLS_CMS *decCms = NULL;
    HITLS_CMS *streamCms = NULL;
    HITLS_CMS *streamDecCms = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer reEncoded = {0};
    BSL_Buffer decrypted = {0};
    BSL_Buffer streamEncoded = {0};
    BSL_Buffer streamCiphertext = {0};
    BSL_Buffer streamDecrypted = {0};
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KEMRI;

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, keyType, keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);

    const char *plaintext = "Hello, ML-KEM EnvelopedData!";
    BSL_Buffer plaintextBuf = {(uint8_t *)plaintext, strlen(plaintext)};
    BslCid contentEncAlg = (BslCid)encAlg;
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
    BSL_Param params[8];
    uint32_t paramIdx = AddKemriRecipientParams(params, recipientCert, NULL, &recipientType);
    AddContentEncryptParams(params, &paramIdx, &contentEncAlg, &contentType);
    BSL_Param decryptParams[8];
    (void)AddKemriRecipientParams(decryptParams, recipientCert, recipientKey, &recipientType);

    encCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(encCms, NULL);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(encCms, &plaintextBuf, params), HITLS_PKI_SUCCESS);
    ASSERT_EQ(encCms->ctx.envelopedData->version, 3);
    SDV_CMS_CheckKemRecipientInfo(encCms->ctx.envelopedData->recipientInfos, (BslCid)expectedKemAlg, true);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, encCms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_NE(encoded.data, NULL);
    ASSERT_LT(0, encoded.dataLen);

    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms), HITLS_PKI_SUCCESS);
    ASSERT_NE(decCms, NULL);
    ASSERT_EQ(decCms->dataType, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_EQ(decCms->ctx.envelopedData->version, 3);
    ASSERT_EQ(BSL_LIST_COUNT(decCms->ctx.envelopedData->recipientInfos), 1);
    SDV_CMS_CheckKemRecipientInfo(decCms->ctx.envelopedData->recipientInfos, (BslCid)expectedKemAlg, true);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, decCms, NULL, &reEncoded), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("mlkem re-encode compare", reEncoded.data, reEncoded.dataLen, encoded.data, encoded.dataLen);
    ASSERT_EQ(HITLS_X509_CertCtrl(recipientCert, HITLS_X509_GET_PUBKEY, &recipientPubKey, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(recipientPubKey, recipientKey), CRYPT_SUCCESS);

    ASSERT_EQ(HITLS_CMS_DataDecrypt(decCms, decryptParams, &decrypted), HITLS_PKI_SUCCESS);
    ASSERT_NE(decrypted.data, NULL);
    ASSERT_EQ(decrypted.dataLen, plaintextBuf.dataLen);
    ASSERT_EQ(memcmp(decrypted.data, plaintextBuf.data, plaintextBuf.dataLen), 0);

    streamCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(streamCms, NULL);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, streamCms, params), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(streamCms, NULL, params), HITLS_PKI_SUCCESS);

    const char *streamPlaintext = "Hello, ML-KEM Streaming EnvelopedData!";
    BSL_Buffer streamChunks[] = {
        {(uint8_t *)"Hello, ", strlen("Hello, ")},
        {(uint8_t *)"ML-KEM ", strlen("ML-KEM ")},
        {(uint8_t *)"Streaming ", strlen("Streaming ")},
        {(uint8_t *)"EnvelopedData!", strlen("EnvelopedData!")}
    };
    ASSERT_EQ(StreamEncryptToBuffer(streamCms, streamChunks, sizeof(streamChunks) / sizeof(streamChunks[0]),
        &streamCiphertext), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, streamCms, NULL, &streamEncoded), HITLS_PKI_SUCCESS);
    ASSERT_NE(streamEncoded.data, NULL);
    ASSERT_LT(0, streamEncoded.dataLen);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &streamEncoded, &streamDecCms), HITLS_PKI_SUCCESS);
    ASSERT_NE(streamDecCms, NULL);
    ASSERT_EQ(streamDecCms->dataType, BSL_CID_PKCS7_ENVELOPEDDATA);

    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_DECRYPT, streamDecCms, decryptParams), HITLS_PKI_SUCCESS);
    ASSERT_NE(streamDecCms->ctx.envelopedData, NULL);
    uint32_t part1Len = streamCiphertext.dataLen / 3;
    uint32_t part2Len = (streamCiphertext.dataLen - part1Len) / 2;
    BSL_Buffer streamCipherChunks[] = {
        {streamCiphertext.data, part1Len},
        {streamCiphertext.data + part1Len, part2Len},
        {streamCiphertext.data + part1Len + part2Len, streamCiphertext.dataLen - part1Len - part2Len}
    };
    ASSERT_EQ(StreamDecryptToBuffer(streamDecCms, streamCipherChunks,
        sizeof(streamCipherChunks) / sizeof(streamCipherChunks[0]), &streamDecrypted), HITLS_PKI_SUCCESS);
    ASSERT_NE(streamDecrypted.data, NULL);
    ASSERT_EQ(streamDecrypted.dataLen, strlen(streamPlaintext));
    ASSERT_EQ(memcmp(streamDecrypted.data, streamPlaintext, streamDecrypted.dataLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_CMS_Free(encCms);
    HITLS_CMS_Free(decCms);
    HITLS_CMS_Free(streamCms);
    HITLS_CMS_Free(streamDecCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    CRYPT_EAL_PkeyFreeCtx(recipientPubKey);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(reEncoded.data);
    BSL_SAL_Free(decrypted.data);
    BSL_SAL_Free(streamEncoded.data);
    BSL_SAL_Free(streamCiphertext.data);
    BSL_SAL_Free(streamDecrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_MLKEM_ONESHOT_STUB_TC001
 * @title Test ML-KEM EnvelopedData one-shot malloc branches
 * @precon Prepare ML-KEM recipient certificate and private key
 * @brief
 *    1. Count malloc calls for ML-KEM one-shot encrypt/decrypt
 *    2. Replay malloc failures for one-shot encrypt/decrypt
 * @expect
 *    1. Valid one-shot encrypt/decrypt succeeds
 *    2. Malloc failure paths do not leak resources
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_MLKEM_ONESHOT_STUB_TC001(int keyType, int expectedKemAlg, char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_MLKEM) || \
    !defined(HITLS_CRYPTO_HKDF) || !defined(HITLS_CRYPTO_AES)
    (void)keyType;
    (void)expectedKemAlg;
    (void)certPath;
    (void)keyPath;
    SKIP_TEST();
#else
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    HITLS_CMS *encCms = NULL;
    HITLS_CMS *encCms1 = NULL;
    HITLS_CMS *decCms = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer decrypted = {0};
    const char *plaintext = "Hello, ML-KEM Stub!";
    BSL_Buffer plaintextBuf = {(uint8_t *)plaintext, strlen(plaintext)};
    BslCid contentEncAlg = BSL_CID_AES256_CBC;
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KEMRI;
    uint32_t totalMallocCount = 0;
    BSL_Param encParams[8];
    BSL_Param decryptParams[8];

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, keyType, keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);
    uint32_t paramIdx = AddKemriRecipientParams(encParams, recipientCert, NULL, &recipientType);
    AddContentEncryptParams(encParams, &paramIdx, &contentEncAlg, &contentType);
    (void)AddKemriRecipientParams(decryptParams, recipientCert, recipientKey, &recipientType);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    encCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(encCms, NULL);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_DataEncrypt(encCms, &plaintextBuf, encParams), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_TRUE(TestIsErrStackEmpty());
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        encCms1 = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
        ASSERT_NE(encCms1, NULL);
        STUB_EnableMallocFail(true);
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(HITLS_CMS_DataEncrypt(encCms1, &plaintextBuf, encParams), HITLS_PKI_SUCCESS);
        STUB_EnableMallocFail(false);
        HITLS_CMS_Free(encCms1);
        encCms1 = NULL;
    }
    TestErrClear();

    SDV_CMS_CheckKemRecipientInfo(encCms->ctx.envelopedData->recipientInfos, (BslCid)expectedKemAlg, true);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, encCms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms), HITLS_PKI_SUCCESS);
    SDV_CMS_CheckKemRecipientInfo(decCms->ctx.envelopedData->recipientInfos, (BslCid)expectedKemAlg, true);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_DataDecrypt(decCms, decryptParams, &decrypted), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_NE(decrypted.data, NULL);
    ASSERT_EQ(decrypted.dataLen, plaintextBuf.dataLen);
    ASSERT_EQ(memcmp(decrypted.data, plaintextBuf.data, plaintextBuf.dataLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
    BSL_SAL_Free(decrypted.data);
    decrypted.data = NULL;
    decrypted.dataLen = 0;

    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        BSL_Buffer tmp = {0};
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        (void)HITLS_CMS_DataDecrypt(decCms, decryptParams, &tmp);
        BSL_SAL_Free(tmp.data);
    }
    TestErrClear();

EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    HITLS_CMS_Free(encCms);
    HITLS_CMS_Free(encCms1);
    HITLS_CMS_Free(decCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(decrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_MLKEM_STREAM_STUB_TC001
 * @title Test ML-KEM EnvelopedData stream malloc branches
 * @precon Prepare ML-KEM recipient certificate and private key
 * @brief
 *    1. Count malloc calls for ML-KEM streaming encrypt/decrypt
 *    2. Replay malloc failures for streaming encrypt/decrypt
 * @expect
 *    1. Valid streaming encrypt/decrypt succeeds
 *    2. Malloc failure paths do not leak resources
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_MLKEM_STREAM_STUB_TC001(int keyType, int expectedKemAlg, char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_MLKEM) || \
    !defined(HITLS_CRYPTO_HKDF) || !defined(HITLS_CRYPTO_AES)
    (void)keyType;
    (void)expectedKemAlg;
    (void)certPath;
    (void)keyPath;
    SKIP_TEST();
#else
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    HITLS_CMS *streamCms = NULL;
    HITLS_CMS *streamCms1 = NULL;
    HITLS_CMS *streamDecCms = NULL;
    HITLS_CMS *streamDecCms1 = NULL;
    BSL_Buffer streamEncoded = {0};
    BSL_Buffer streamCiphertext = {0};
    BSL_Buffer streamDecrypted = {0};
    const char *streamPlaintext = "Hello, ML-KEM Streaming Stub!";
    BSL_Buffer streamChunks[] = {
        {(uint8_t *)"Hello, ", strlen("Hello, ")},
        {(uint8_t *)"ML-KEM ", strlen("ML-KEM ")},
        {(uint8_t *)"Streaming ", strlen("Streaming ")},
        {(uint8_t *)"Stub!", strlen("Stub!")}
    };
    BslCid contentEncAlg = BSL_CID_AES256_CBC;
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KEMRI;
    uint32_t totalMallocCount = 0;
    BSL_Param encParams[8];
    BSL_Param decryptParams[8];

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, keyType, keyPath, NULL, 0, &recipientKey), HITLS_PKI_SUCCESS);
    uint32_t paramIdx = AddKemriRecipientParams(encParams, recipientCert, NULL, &recipientType);
    AddContentEncryptParams(encParams, &paramIdx, &contentEncAlg, &contentType);
    (void)AddKemriRecipientParams(decryptParams, recipientCert, recipientKey, &recipientType);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    streamCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(streamCms, NULL);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, streamCms, encParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(streamCms, NULL, encParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(StreamEncryptToBuffer(streamCms, streamChunks, sizeof(streamChunks) / sizeof(streamChunks[0]),
        &streamCiphertext), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_TRUE(TestIsErrStackEmpty());
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        int32_t ret;
        BSL_Buffer tmpCiphertext = {0};
        streamCms1 = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
        ASSERT_NE(streamCms1, NULL);
        STUB_EnableMallocFail(true);
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ret = HITLS_CMS_DataInit(HITLS_CMS_OPT_ENCRYPT, streamCms1, encParams);
        if (ret == HITLS_PKI_SUCCESS) {
            ret = HITLS_CMS_DataEncrypt(streamCms1, NULL, encParams);
        }
        if (ret == HITLS_PKI_SUCCESS) {
            ret = StreamEncryptToBuffer(streamCms1, streamChunks, sizeof(streamChunks) / sizeof(streamChunks[0]),
                &tmpCiphertext);
        }
        ASSERT_NE(ret, HITLS_PKI_SUCCESS);
        STUB_EnableMallocFail(false);
        BSL_SAL_Free(tmpCiphertext.data);
        HITLS_CMS_Free(streamCms1);
        streamCms1 = NULL;
    }
    TestErrClear();

    SDV_CMS_CheckKemRecipientInfo(streamCms->ctx.envelopedData->recipientInfos, (BslCid)expectedKemAlg, true);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, streamCms, NULL, &streamEncoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &streamEncoded, &streamDecCms), HITLS_PKI_SUCCESS);
    SDV_CMS_CheckKemRecipientInfo(streamDecCms->ctx.envelopedData->recipientInfos, (BslCid)expectedKemAlg, true);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_DECRYPT, streamDecCms, decryptParams), HITLS_PKI_SUCCESS);
    {
        uint32_t part1Len = streamCiphertext.dataLen / 3;
        uint32_t part2Len = (streamCiphertext.dataLen - part1Len) / 2;
        BSL_Buffer cChunks[] = {
            {streamCiphertext.data, part1Len},
            {streamCiphertext.data + part1Len, part2Len},
            {streamCiphertext.data + part1Len + part2Len, streamCiphertext.dataLen - part1Len - part2Len}
        };

        ASSERT_EQ(StreamDecryptToBuffer(streamDecCms, cChunks, sizeof(cChunks) / sizeof(cChunks[0]),
            &streamDecrypted), HITLS_PKI_SUCCESS);
        totalMallocCount = STUB_GetMallocCallCount();
        ASSERT_NE(streamDecrypted.data, NULL);
        ASSERT_EQ(streamDecrypted.dataLen, strlen(streamPlaintext));
        ASSERT_EQ(memcmp(streamDecrypted.data, streamPlaintext, streamDecrypted.dataLen), 0);
        ASSERT_TRUE(TestIsErrStackEmpty());
        BSL_SAL_Free(streamDecrypted.data);
        streamDecrypted.data = NULL;
        streamDecrypted.dataLen = 0;

        for (uint32_t i = 0; i < totalMallocCount; i++) {
            int32_t ret;
            BSL_Buffer tmp = {0};
            STUB_EnableMallocFail(false);
            ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &streamEncoded, &streamDecCms1), HITLS_PKI_SUCCESS);
            STUB_EnableMallocFail(true);
            STUB_ResetMallocCount();
            STUB_SetMallocFailIndex(i);
            ret = HITLS_CMS_DataInit(HITLS_CMS_OPT_DECRYPT, streamDecCms1, decryptParams);
            if (ret == HITLS_PKI_SUCCESS) {
                ret = StreamDecryptToBuffer(streamDecCms1, cChunks, sizeof(cChunks) / sizeof(cChunks[0]), &tmp);
            }
            (void)ret;
            STUB_EnableMallocFail(false);
            BSL_SAL_Free(tmp.data);
            HITLS_CMS_Free(streamDecCms1);
            streamDecCms1 = NULL;
        }
    }
    TestErrClear();

EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    HITLS_CMS_Free(streamCms);
    HITLS_CMS_Free(streamCms1);
    HITLS_CMS_Free(streamDecCms);
    HITLS_CMS_Free(streamDecCms1);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(streamEncoded.data);
    BSL_SAL_Free(streamCiphertext.data);
    BSL_SAL_Free(streamDecrypted.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_ENVELOPEDDATA_MIXED_RECIPIENT_TC001
 * @title Test EnvelopedData with mixed RSA and ML-KEM recipients
 * @precon Prepare one RSA recipient and one ML-KEM recipient
 * @brief
 *    1. Create EnvelopedData with one RSA and one ML-KEM recipient
 *    2. Encrypt plaintext for both recipients
 *    3. Verify recipient list contains both KTRI and KEMRI
 *    4. Each recipient decrypts the same ciphertext independently
 * @expect
 *    1. Encryption succeeds for both recipient types
 *    2. Parsed structure version is upgraded for KEM recipient usage
 *    3. Both RSA and ML-KEM recipients decrypt successfully
 */
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_MIXED_RECIPIENT_TC001(int encAlg, int kemKeyType, int expectedKemAlg, char *rsaCertPath,
    char *rsaKeyPath, char *kemCertPath, char *kemKeyPath)
{
#if !defined(HITLS_PKI_CMS_ENVELOPEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_MLKEM) || !defined(HITLS_CRYPTO_HKDF) || !defined(HITLS_CRYPTO_AES)
    (void)encAlg;
    (void)kemKeyType;
    (void)expectedKemAlg;
    (void)rsaCertPath;
    (void)rsaKeyPath;
    (void)kemCertPath;
    (void)kemKeyPath;
    SKIP_TEST();
#else
    HITLS_X509_Cert *rsaCert = NULL;
    HITLS_X509_Cert *kemCert = NULL;
    CRYPT_EAL_PkeyCtx *rsaKey = NULL;
    CRYPT_EAL_PkeyCtx *kemKey = NULL;
    HITLS_CMS *encCms = NULL;
    HITLS_CMS *decCms1 = NULL;
    HITLS_CMS *decCms2 = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer decrypted1 = {0};
    BSL_Buffer decrypted2 = {0};
    const char *plaintext = "Mixed recipient EnvelopedData";
    BSL_Buffer plaintextBuf = {(uint8_t *)plaintext, strlen(plaintext)};
    BslCid contentEncAlg = (BslCid)encAlg;
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
    int32_t rsaRecipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    int32_t kemRecipientType = HITLS_CMS_RECIPIENT_TYPE_KEMRI;
    BslCid rsaKeyEncAlg = BSL_CID_RSA;
    BSL_Param rsaEncParams[10];
    BSL_Param kemEncParams[8];
    BSL_Param rsaDecryptParams[8];
    BSL_Param kemDecryptParams[8];

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, rsaCertPath, &rsaCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA, rsaKeyPath, NULL, 0, &rsaKey),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, kemCertPath, &kemCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, kemKeyType, kemKeyPath, NULL, 0, &kemKey), HITLS_PKI_SUCCESS);
    uint32_t paramIdx = AddKtriRecipientParams(rsaEncParams, rsaCert, NULL, &rsaRecipientType,
        &rsaKeyEncAlg, NULL, NULL, NULL);
    AddContentEncryptParams(rsaEncParams, &paramIdx, &contentEncAlg, &contentType);
    (void)AddKemriRecipientParams(kemEncParams, kemCert, NULL, &kemRecipientType);
    (void)AddKtriRecipientParams(rsaDecryptParams, rsaCert, rsaKey, &rsaRecipientType, &rsaKeyEncAlg,
        NULL, NULL, NULL);
    (void)AddKemriRecipientParams(kemDecryptParams, kemCert, kemKey, &kemRecipientType);

    encCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_ENVELOPEDDATA);
    ASSERT_NE(encCms, NULL);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(encCms, &plaintextBuf, rsaEncParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataEncrypt(encCms, NULL, kemEncParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(encCms->ctx.envelopedData->version, 3);
    ASSERT_EQ(BSL_LIST_COUNT(encCms->ctx.envelopedData->recipientInfos), 2);
    ASSERT_EQ(SDV_CMS_CountRecipientType(encCms->ctx.envelopedData->recipientInfos, CMS_RECIPIENT_TYPE_KTRI), 1);
    ASSERT_EQ(SDV_CMS_CountRecipientType(encCms->ctx.envelopedData->recipientInfos, CMS_RECIPIENT_TYPE_KEMRI), 1);
    SDV_CMS_CheckKemRecipientInfo(encCms->ctx.envelopedData->recipientInfos, (BslCid)expectedKemAlg, true);

    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, encCms, NULL, &encoded), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(decCms1->ctx.envelopedData->version, 3);
    ASSERT_EQ(BSL_LIST_COUNT(decCms1->ctx.envelopedData->recipientInfos), 2);
    ASSERT_EQ(SDV_CMS_CountRecipientType(decCms1->ctx.envelopedData->recipientInfos, CMS_RECIPIENT_TYPE_KTRI), 1);
    ASSERT_EQ(SDV_CMS_CountRecipientType(decCms1->ctx.envelopedData->recipientInfos, CMS_RECIPIENT_TYPE_KEMRI), 1);
    ASSERT_EQ(HITLS_CMS_DataDecrypt(decCms1, rsaDecryptParams, &decrypted1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(decrypted1.dataLen, plaintextBuf.dataLen);
    ASSERT_EQ(memcmp(decrypted1.data, plaintextBuf.data, plaintextBuf.dataLen), 0);

    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &decCms2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(decCms2->ctx.envelopedData->version, 3);
    ASSERT_EQ(BSL_LIST_COUNT(decCms2->ctx.envelopedData->recipientInfos), 2);
    ASSERT_EQ(SDV_CMS_CountRecipientType(decCms2->ctx.envelopedData->recipientInfos, CMS_RECIPIENT_TYPE_KTRI), 1);
    ASSERT_EQ(SDV_CMS_CountRecipientType(decCms2->ctx.envelopedData->recipientInfos, CMS_RECIPIENT_TYPE_KEMRI), 1);
    SDV_CMS_CheckKemRecipientInfo(decCms2->ctx.envelopedData->recipientInfos, (BslCid)expectedKemAlg, true);
    ASSERT_EQ(HITLS_CMS_DataDecrypt(decCms2, kemDecryptParams, &decrypted2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(decrypted2.dataLen, plaintextBuf.dataLen);
    ASSERT_EQ(memcmp(decrypted2.data, plaintextBuf.data, plaintextBuf.dataLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CMS_Free(encCms);
    HITLS_CMS_Free(decCms1);
    HITLS_CMS_Free(decCms2);
    HITLS_X509_CertFree(rsaCert);
    HITLS_X509_CertFree(kemCert);
    CRYPT_EAL_PkeyFreeCtx(rsaKey);
    CRYPT_EAL_PkeyFreeCtx(kemKey);
    BSL_SAL_Free(encoded.data);
    BSL_SAL_Free(decrypted1.data);
    BSL_SAL_Free(decrypted2.data);
    TestRandDeInit();
#endif
}
/* END_CASE */
