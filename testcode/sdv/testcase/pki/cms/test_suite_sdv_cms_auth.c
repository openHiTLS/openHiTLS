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

#include "bsl_sal.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "bsl_params.h"
#include "crypt_codecskey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "hitls_cms_local.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_x509.h"
#include "hitls_pki_params.h"
#include "bsl_obj_internal.h"
#include "bsl_list.h"
#include "stub_utils.h"
/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

#define SDV_CMS_AUTH_DEFAULT_CERT "../testdata/cert/asn1/cms/authdata/rsa/rsa_p1_v1.crt.der"
#define SDV_CMS_AUTH_DEFAULT_KEY  "../testdata/cert/asn1/cms/authdata/rsa/rsa_p1.key.der"
#define SDV_CMS_AUTH_DEFAULT_MSG  "../testdata/cert/asn1/cms/authdata/rsa/message.txt"

static bool SDV_CMS_HasAttrEntries(HITLS_X509_Attrs *attrs)
{
    return (attrs != NULL && attrs->list != NULL && BSL_LIST_COUNT(attrs->list) > 0);
}

static HITLS_X509_AttrEntry *SDV_CMS_FindAttrEntry(HITLS_X509_Attrs *attrs, BslCid cid)
{
    if (attrs == NULL || attrs->list == NULL) {
        return NULL;
    }
    for (HITLS_X509_AttrEntry *node = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(attrs->list);
        node != NULL; node = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(attrs->list)) {
        if (node->cid == cid) {
            return node;
        }
    }
    return NULL;
}

static int32_t SDV_CMS_LoadRecipient(char *certPath, char *keyPath, HITLS_X509_Cert **cert,
    CRYPT_EAL_PkeyCtx **key)
{
    if (certPath == NULL || keyPath == NULL || cert == NULL || key == NULL) {
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA, keyPath, NULL, 0, key);
}

static void SDV_CMS_SplitMessage(const BSL_Buffer *msg, BSL_Buffer chunks[3])
{
    uint32_t firstLen = 0;
    uint32_t secondLen = 0;
    if (msg == NULL || msg->data == NULL || msg->dataLen == 0) {
        chunks[0].data = NULL;
        chunks[0].dataLen = 0;
        chunks[1].data = NULL;
        chunks[1].dataLen = 0;
        chunks[2].data = NULL;
        chunks[2].dataLen = 0;
        return;
    }
    firstLen = msg->dataLen / 3;
    secondLen = (msg->dataLen - firstLen) / 2;
    chunks[0].data = msg->data;
    chunks[0].dataLen = firstLen;
    chunks[1].data = msg->data + firstLen;
    chunks[1].dataLen = secondLen;
    chunks[2].data = msg->data + firstLen + secondLen;
    chunks[2].dataLen = msg->dataLen - firstLen - secondLen;
}

static void SDV_CMS_ResetBuffer(BSL_Buffer *buf)
{
    if (buf == NULL) {
        return;
    }
    buf->data = NULL;
    buf->dataLen = 0;
}

/*
 * @test   SDV_CMS_AUTHENTICATEDDATA_MALLOC_TC001
 * @title  Test malloc CMS AuthenticatedData
 * @brief
 *    1. Malloc CMS AuthenticatedData with valid cid
 *    2. Free CMS handle with NULL parameter
 *    3. Malloc CMS with invalid cid
 * @expect
 *    1. Success
 *    2. No abort
 *    3. Returns NULL
 */
/* BEGIN_CASE */
void SDV_CMS_AUTHENTICATEDDATA_MALLOC_TC001(void)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA)
    SKIP_TEST();
#else
    HITLS_CMS *cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms, NULL);
    ASSERT_EQ(cms->dataType, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    HITLS_CMS_Free(cms);
EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_PARSE_AUTHENTICATEDDATA_VERIFY_TC001
 * @title  Parse and verify AuthenticatedData with attached/detached and tamper checks
 * @brief
 *    1. Parse AuthenticatedData from file
 *    2. Load recipient certificate and private key
 *    3. For attached content:
 *       - verify with NULL message
 *       - verify with correct external message
 *       - verify with wrong external message
 *    4. For detached content:
 *       - verify with correct external message
 *       - verify with NULL / empty / wrong external message
 *    5. Verify output returns the actual authenticated content
 *    6. Tamper mac and verify failure
 *    7. If authenticated attributes exist, tamper content-type and message-digest and verify failure
 * @expect
 *    1. Parse succeeds
 *    2. Correct verification succeeds
 *    3. Invalid message input returns expected error
 *    4. Tampered mac / attrs verification fails
 */
/* BEGIN_CASE */
void SDV_CMS_PARSE_AUTHENTICATEDDATA_VERIFY_TC001(char *authPath, char *msgPath, int isDetached, int hasAuthAttrs,
    char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA)
    (void)authPath;
    (void)msgPath;
    (void)isDetached;
    (void)hasAuthAttrs;
    (void)certPath;
    (void)keyPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    BSL_Buffer msgBuff = {0};
    BSL_Buffer nullMsgBuf = {0};
    BSL_Buffer wrongMsgBuf = {0};
    BSL_Buffer output = {0};
    HITLS_X509_AttrEntry *msgDigestAttr = NULL;
    uint8_t oldMacByte = 0;
    uint8_t oldDigestByte = 0;
    int32_t oldContentType = 0;

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(msgPath, &msgBuff.data, &msgBuff.dataLen), BSL_SUCCESS);
    ASSERT_LT(0, msgBuff.dataLen);
    if (msgBuff.dataLen > 1) {
        wrongMsgBuf.data = msgBuff.data + 1;
        wrongMsgBuf.dataLen = msgBuff.dataLen - 1;
    } else {
        wrongMsgBuf.data = NULL;
        wrongMsgBuf.dataLen = 0;
    }

    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, authPath, &cms), HITLS_PKI_SUCCESS);
    ASSERT_NE(cms, NULL);
    ASSERT_EQ(cms->dataType, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms->ctx.authenticatedData, NULL);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA, keyPath, NULL, 0, &recipientKey),
        HITLS_PKI_SUCCESS);

    BSL_Param verifyParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        BSL_PARAM_END
    };

    if (isDetached) {
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, &msgBuff, verifyParams, &output), HITLS_PKI_SUCCESS);
        ASSERT_COMPARE("verify detached output", output.data, output.dataLen, msgBuff.data, msgBuff.dataLen);
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, NULL, verifyParams, NULL), HITLS_CMS_ERR_INVALID_DATA);
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, &nullMsgBuf, verifyParams, NULL),
            HITLS_CMS_ERR_VERIFY_FAIL);
        if (wrongMsgBuf.dataLen > 0) {
            ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, &wrongMsgBuf, verifyParams, NULL),
                HITLS_CMS_ERR_VERIFY_FAIL);
        }
    } else {
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, NULL, verifyParams, &output), HITLS_PKI_SUCCESS);
        ASSERT_COMPARE("verify attached output with null msg", output.data, output.dataLen, msgBuff.data, msgBuff.dataLen);
        SDV_CMS_ResetBuffer(&output);
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, &msgBuff, verifyParams, &output), HITLS_PKI_SUCCESS);
        ASSERT_COMPARE("verify attached output", output.data, output.dataLen, msgBuff.data, msgBuff.dataLen);
        if (wrongMsgBuf.dataLen > 0) {
            ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, &wrongMsgBuf, verifyParams, NULL),
                HITLS_CMS_ERR_VERIFY_FAIL);
        }
    }

    ASSERT_NE(cms->ctx.authenticatedData->mac.data, NULL);
    ASSERT_LT(0, cms->ctx.authenticatedData->mac.dataLen);
    oldMacByte = cms->ctx.authenticatedData->mac.data[0];
    cms->ctx.authenticatedData->mac.data[0] ^= 0x01;
    ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, isDetached ? &msgBuff : NULL, verifyParams, NULL),
        HITLS_CMS_ERR_VERIFY_FAIL);
    cms->ctx.authenticatedData->mac.data[0] = oldMacByte;

    if (hasAuthAttrs) {
        oldContentType = cms->ctx.authenticatedData->encapCont.contentType;
        cms->ctx.authenticatedData->encapCont.contentType = BSL_CID_PKCS7_ENVELOPEDDATA;
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, isDetached ? &msgBuff : NULL, verifyParams, NULL),
            HITLS_CMS_ERR_VERIFY_FAIL);
        cms->ctx.authenticatedData->encapCont.contentType = oldContentType;

        msgDigestAttr = SDV_CMS_FindAttrEntry(cms->ctx.authenticatedData->authAttrs, BSL_CID_PKCS9_AT_MESSAGEDIGEST);
        ASSERT_NE(msgDigestAttr, NULL);
        ASSERT_NE(msgDigestAttr->attrValue.buff, NULL);
        ASSERT_LT(0, msgDigestAttr->attrValue.len);
        oldDigestByte = msgDigestAttr->attrValue.buff[msgDigestAttr->attrValue.len - 1];
        msgDigestAttr->attrValue.buff[msgDigestAttr->attrValue.len - 1] ^= 0x01;
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, isDetached ? &msgBuff : NULL, verifyParams, NULL),
            HITLS_CMS_ERR_VERIFY_FAIL);
        msgDigestAttr->attrValue.buff[msgDigestAttr->attrValue.len - 1] = oldDigestByte;
    }

EXIT:
    HITLS_CMS_Free(cms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(msgBuff.data);
    CRYPT_EAL_RandDeinit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_PARSE_AUTHENTICATEDDATA_ENC_DEC_FILE_TC001
 * @title  Parse AuthenticatedData and verify generated-data encode guard
 * @brief
 *    1. Parse AuthenticatedData from file
 *    2. Verify parsed CMS cannot be encoded as generated AuthenticatedData
 *    3. Verify AuthenticatedData using recipient certificate and private key
 *    4. Compare output content with expected message
 * @expect
 *    1. Parse succeeds
 *    2. Encode-to-file returns INVALID_STATE
 *    3. Verification succeeds
 *    4. Verified output matches the expected message
 */
/* BEGIN_CASE */
void SDV_CMS_PARSE_AUTHENTICATEDDATA_ENC_DEC_FILE_TC001(char *authPath, char *msgPath, int isDetached,
    char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA)
    (void)authPath;
    (void)msgPath;
    (void)isDetached;
    (void)certPath;
    (void)keyPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    BSL_Buffer msgBuff = {0};
    BSL_Buffer output = {0};
    const char *writePath = "./authdata_encoded.cms";

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(msgPath, &msgBuff.data, &msgBuff.dataLen), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &recipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA, keyPath, NULL, 0, &recipientKey),
        HITLS_PKI_SUCCESS);

    BSL_Param verifyParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        BSL_PARAM_END
    };

    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, authPath, &cms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenFile(BSL_FORMAT_ASN1, cms, NULL, writePath), HITLS_CMS_ERR_INVALID_STATE);

    if (isDetached) {
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, &msgBuff, verifyParams, &output), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, recipientKey, NULL, verifyParams, &output), HITLS_PKI_SUCCESS);
    }
    ASSERT_COMPARE("verified content compare", output.data, output.dataLen, msgBuff.data, msgBuff.dataLen);

EXIT:
    HITLS_CMS_Free(cms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(msgBuff.data);
    remove(writePath);
    CRYPT_EAL_RandDeinit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_AUTHENTICATEDDATA_ONE_SHOT_TC001
 * @title  Test AuthenticatedData one-shot generate and verify
 * @brief
 *    1. Load recipient certificate/private key and message
 *    2. Generate AuthenticatedData with HITLS_CMS_DataAuth
 *    3. Add another recipient with a subsequent HITLS_CMS_DataAuth call
 *    4. Encode to buffer and parse again
 *    5. Verify generated AuthenticatedData with HITLS_CMS_DataAuthVerify
 * @expect
 *    1. Generation succeeds
 *    2. Recipient append succeeds
 *    3. Parse succeeds
 *    4. Verification succeeds
 *    5. Output content matches original message
 */
/* BEGIN_CASE */
void SDV_CMS_AUTHENTICATEDDATA_ONE_SHOT_TC001(int isDetached, int noAuthAttrs, int contentType, char *certPath,
    char *keyPath, char *msgPath)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_HMAC) || !defined(HITLS_CRYPTO_SHA256)
    (void)isDetached;
    (void)noAuthAttrs;
    (void)contentType;
    (void)certPath;
    (void)keyPath;
    (void)msgPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *parsedCms = NULL;
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    BSL_Buffer msgBuf = {0};
    BSL_Buffer encoded = {0};
    BSL_Buffer output = {0};
    bool detached = (bool)isDetached;
    bool disableAuthAttrs = (bool)noAuthAttrs;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    int32_t invalidRecipientType = 0;
    BslCid keyEncAlg = BSL_CID_RSA;
    int32_t macAlg = CRYPT_MAC_HMAC_SHA256;
    int32_t digestAlg = BSL_CID_SHA256;
    int32_t contentTypeId = contentType;

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(msgPath, &msgBuf.data, &msgBuf.dataLen), BSL_SUCCESS);
    ASSERT_EQ(SDV_CMS_LoadRecipient(certPath, keyPath, &recipientCert, &recipientKey), HITLS_PKI_SUCCESS);

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms, NULL);

    BSL_Param authParamsWithAttrs[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentTypeId, sizeof(contentTypeId), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    BSL_Param authParamsNoAttrs[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentTypeId, sizeof(contentTypeId), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        {HITLS_CMS_PARAM_NO_AUTH_ATTRS, BSL_PARAM_TYPE_BOOL, &disableAuthAttrs, sizeof(disableAuthAttrs), 0},
        BSL_PARAM_END
    };
    BSL_Param verifyParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        BSL_PARAM_END
    };
    BSL_Param invalidAppendParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &invalidRecipientType, sizeof(invalidRecipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        BSL_PARAM_END
    };

    ASSERT_EQ(HITLS_CMS_DataAuth(cms, &msgBuf, disableAuthAttrs ? authParamsNoAttrs : authParamsWithAttrs),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(cms->ctx.authenticatedData->recipientInfos), 1);
    ASSERT_NE(HITLS_CMS_DataAuth(cms, NULL, invalidAppendParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(cms->ctx.authenticatedData->recipientInfos), 1);
    ASSERT_EQ(HITLS_CMS_DataAuth(cms, NULL, disableAuthAttrs ? authParamsNoAttrs : authParamsWithAttrs),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(cms->ctx.authenticatedData->recipientInfos), 2);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedCms->ctx.authenticatedData->detached, detached);
    ASSERT_EQ(parsedCms->ctx.authenticatedData->encapCont.contentType, contentTypeId);
    ASSERT_EQ(parsedCms->ctx.authenticatedData->hasDigestAlg, !disableAuthAttrs);
    ASSERT_EQ(SDV_CMS_HasAttrEntries(parsedCms->ctx.authenticatedData->authAttrs), !disableAuthAttrs);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(parsedCms->ctx.authenticatedData->recipientInfos), 2);
    ASSERT_EQ(HITLS_CMS_DataAuth(parsedCms, NULL, disableAuthAttrs ? authParamsNoAttrs : authParamsWithAttrs),
        HITLS_CMS_ERR_INVALID_STATE);

    if (detached) {
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(parsedCms, recipientKey, &msgBuf, verifyParams, &output), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(parsedCms, recipientKey, NULL, verifyParams, &output), HITLS_PKI_SUCCESS);
        ASSERT_COMPARE("oneshot attached output", output.data, output.dataLen, msgBuf.data, msgBuf.dataLen);
        SDV_CMS_ResetBuffer(&output);
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(parsedCms, recipientKey, &msgBuf, verifyParams, &output), HITLS_PKI_SUCCESS);
    }
    ASSERT_COMPARE("oneshot verify output", output.data, output.dataLen, msgBuf.data, msgBuf.dataLen);

EXIT:
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(parsedCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(msgBuf.data);
    BSL_SAL_Free(encoded.data);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_AUTHENTICATEDDATA_STREAM_TC001
 * @title  Test AuthenticatedData streaming generate and verify for detached content
 * @brief
 *    1. Verify detached content supports streaming generate/verify
 *    2. Verify stream generation adds recipients via HITLS_CMS_DataAuth after init
 *    3. Verify attached content is rejected by streaming APIs
 *    4. Verify one-shot APIs still work for both detached and attached content
 * @expect
 *    1. Detached streaming generate/verify succeeds
 *    2. Recipient append succeeds
 *    3. Attached streaming generate/verify returns ATTACHED_STREAM_UNSUPPORTED
 *    4. One-shot verify output matches original message
 *    5. Invalid call sequences return errors
 */
/* BEGIN_CASE */
void SDV_CMS_AUTHENTICATEDDATA_STREAM_TC001(int isDetached, int noAuthAttrs, int contentType, char *certPath,
    char *keyPath, char *msgPath)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_HMAC) || !defined(HITLS_CRYPTO_SHA256)
    (void)isDetached;
    (void)noAuthAttrs;
    (void)contentType;
    (void)certPath;
    (void)keyPath;
    (void)msgPath;
    SKIP_TEST();
#else
    HITLS_CMS *streamCms = NULL;
    HITLS_CMS *streamParsedCms = NULL;
    HITLS_CMS *oneShotCms = NULL;
    HITLS_CMS *oneShotParsedCms = NULL;
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    BSL_Buffer msgBuf = {0};
    BSL_Buffer emptyBuf = {0};
    BSL_Buffer output = {0};
    BSL_Buffer streamEncoded = {0};
    BSL_Buffer oneShotEncoded = {0};
    BSL_Buffer oneShotOutput = {0};
    BSL_Buffer chunks[3] = {0};
    bool detached = (bool)isDetached;
    bool disableAuthAttrs = (bool)noAuthAttrs;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    int32_t invalidRecipientType = 0;
    BslCid keyEncAlg = BSL_CID_RSA;
    int32_t macAlg = CRYPT_MAC_HMAC_SHA256;
    int32_t digestAlg = BSL_CID_SHA256;
    int32_t contentTypeId = contentType;

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(msgPath, &msgBuf.data, &msgBuf.dataLen), BSL_SUCCESS);
    ASSERT_EQ(SDV_CMS_LoadRecipient(certPath, keyPath, &recipientCert, &recipientKey), HITLS_PKI_SUCCESS);
    SDV_CMS_SplitMessage(&msgBuf, chunks);

    streamCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(streamCms, NULL);
    ASSERT_EQ(HITLS_CMS_DataUpdate(streamCms, &msgBuf), HITLS_CMS_ERR_INVALID_STATE);
    ASSERT_EQ(HITLS_CMS_DataUpdate(streamCms, &emptyBuf), HITLS_CMS_ERR_INVALID_STATE);
    ASSERT_EQ(HITLS_CMS_DataFinal(streamCms, NULL), HITLS_CMS_ERR_INVALID_STATE);

    BSL_Param streamConfigParamsWithAttrs[] = {
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentTypeId, sizeof(contentTypeId), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    BSL_Param streamConfigParamsNoAttrs[] = {
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentTypeId, sizeof(contentTypeId), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        {HITLS_CMS_PARAM_NO_AUTH_ATTRS, BSL_PARAM_TYPE_BOOL, &disableAuthAttrs, sizeof(disableAuthAttrs), 0},
        BSL_PARAM_END
    };
    BSL_Param recipientParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        BSL_PARAM_END
    };
    BSL_Param invalidRecipientParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &invalidRecipientType, sizeof(invalidRecipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        BSL_PARAM_END
    };
    BSL_Param oneShotAuthParamsWithAttrs[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentTypeId, sizeof(contentTypeId), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    BSL_Param oneShotAuthParamsNoAttrs[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentTypeId, sizeof(contentTypeId), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        {HITLS_CMS_PARAM_NO_AUTH_ATTRS, BSL_PARAM_TYPE_BOOL, &disableAuthAttrs, sizeof(disableAuthAttrs), 0},
        BSL_PARAM_END
    };
    BSL_Param streamVerifyInitParams[] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, recipientKey, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        BSL_PARAM_END
    };

    if (detached) {
        ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_AUTH, streamCms,
            disableAuthAttrs ? streamConfigParamsNoAttrs : streamConfigParamsWithAttrs), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamCms, NULL), HITLS_CMS_ERR_NULL_POINTER);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamCms, &emptyBuf), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataFinal(streamCms, NULL), HITLS_CMS_ERR_INVALID_PARAM);
        ASSERT_NE(HITLS_CMS_DataAuth(streamCms, NULL, invalidRecipientParams), HITLS_PKI_SUCCESS);
        ASSERT_EQ((int32_t)BSL_LIST_COUNT(streamCms->ctx.authenticatedData->recipientInfos), 0);
        ASSERT_EQ(HITLS_CMS_DataAuth(streamCms, NULL, recipientParams), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataAuth(streamCms, &msgBuf, recipientParams), HITLS_PKI_SUCCESS);
        ASSERT_EQ((int32_t)BSL_LIST_COUNT(streamCms->ctx.authenticatedData->recipientInfos), 2);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamCms, &chunks[0]), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamCms, &chunks[1]), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamCms, &chunks[2]), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataFinal(streamCms, NULL), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataAuth(streamCms, NULL, recipientParams), HITLS_CMS_ERR_INVALID_STATE);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamCms, &emptyBuf), HITLS_CMS_ERR_INVALID_STATE);
        ASSERT_EQ(HITLS_CMS_DataFinal(streamCms, NULL), HITLS_CMS_ERR_INVALID_STATE);
        ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_AUTH, streamCms, NULL), HITLS_CMS_ERR_INVALID_STATE);

        ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, streamCms, NULL, &streamEncoded), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &streamEncoded, &streamParsedCms), HITLS_PKI_SUCCESS);
        ASSERT_EQ(streamParsedCms->ctx.authenticatedData->encapCont.contentType, contentTypeId);
        ASSERT_EQ((int32_t)BSL_LIST_COUNT(streamParsedCms->ctx.authenticatedData->recipientInfos), 2);

        ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_AUTH_VERIFY, streamParsedCms, streamVerifyInitParams),
            HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamParsedCms, &emptyBuf), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamParsedCms, &chunks[0]), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamParsedCms, &chunks[1]), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamParsedCms, &chunks[2]), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataFinal(streamParsedCms, NULL), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataUpdate(streamParsedCms, &emptyBuf), HITLS_CMS_ERR_INVALID_STATE);
        ASSERT_EQ(HITLS_CMS_DataFinal(streamParsedCms, NULL), HITLS_CMS_ERR_INVALID_STATE);

        ASSERT_EQ(HITLS_CMS_DataAuthVerify(streamParsedCms, recipientKey, &msgBuf, streamVerifyInitParams, &output),
            HITLS_PKI_SUCCESS);
        ASSERT_COMPARE("stream oneshot output", output.data, output.dataLen, msgBuf.data, msgBuf.dataLen);
    } else {
        ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_AUTH, streamCms,
            disableAuthAttrs ? streamConfigParamsNoAttrs : streamConfigParamsWithAttrs),
            HITLS_CMS_ERR_ATTACHED_STREAM_UNSUPPORTED);
    }

    oneShotCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(oneShotCms, NULL);
    ASSERT_EQ(HITLS_CMS_DataAuth(oneShotCms, &msgBuf,
        disableAuthAttrs ? oneShotAuthParamsNoAttrs : oneShotAuthParamsWithAttrs), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, oneShotCms, NULL, &oneShotEncoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &oneShotEncoded, &oneShotParsedCms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(oneShotParsedCms->ctx.authenticatedData->encapCont.contentType, contentTypeId);
    if (!detached) {
        ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_AUTH_VERIFY, oneShotParsedCms, streamVerifyInitParams),
            HITLS_CMS_ERR_ATTACHED_STREAM_UNSUPPORTED);
    }
    if (detached) {
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(oneShotParsedCms, recipientKey, &msgBuf, streamVerifyInitParams, &oneShotOutput),
            HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_CMS_DataAuthVerify(oneShotParsedCms, recipientKey, NULL, streamVerifyInitParams, &oneShotOutput),
            HITLS_PKI_SUCCESS);
    }
    ASSERT_COMPARE("oneshot output", oneShotOutput.data, oneShotOutput.dataLen, msgBuf.data, msgBuf.dataLen);

EXIT:
    HITLS_CMS_Free(streamCms);
    HITLS_CMS_Free(streamParsedCms);
    HITLS_CMS_Free(oneShotCms);
    HITLS_CMS_Free(oneShotParsedCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(msgBuf.data);
    BSL_SAL_Free(streamEncoded.data);
    BSL_SAL_Free(oneShotEncoded.data);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_AUTHENTICATEDDATA_NULL_PARAMS_TC001
 * @title  Test AuthenticatedData NULL parameter handling
 * @brief
 *    1. Call APIs with NULL cms/decryptKey/output parameters
 * @expect
 *    1. All APIs return NULL_POINTER related errors
 */
/* BEGIN_CASE */
void SDV_CMS_AUTHENTICATEDDATA_NULL_PARAMS_TC001(void)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA)
    SKIP_TEST();
#else
    HITLS_CMS *cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    BSL_Buffer msgBuf = {(uint8_t *)"auth", 4};
    ASSERT_NE(cms, NULL);
    ASSERT_EQ(HITLS_CMS_DataAuth(NULL, &msgBuf, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataAuth(cms, NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataAuthVerify(NULL, NULL, NULL, NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataAuthVerify(cms, NULL, NULL, NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_AUTH, NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataUpdate(NULL, &msgBuf), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataFinal(NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
EXIT:
    HITLS_CMS_Free(cms);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_AUTHENTICATEDDATA_INVALID_PARAM_TC001
 * @title  Test AuthenticatedData invalid parameter and negative paths
 * @brief
 *    1. Test detached verify without external message
 *    2. Test verify without recipient certificate
 *    3. Test generation without mac algorithm
 *    4. Test NO_AUTH_ATTRS together with digest algorithm
 *    5. Test non-id-data content type without authenticated attributes
 * @expect
 *    1. APIs return expected invalid-parameter/data errors
 */
/* BEGIN_CASE */
void SDV_CMS_AUTHENTICATEDDATA_INVALID_PARAM_TC001(void)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_RSA) || \
    !defined(HITLS_CRYPTO_HMAC) || !defined(HITLS_CRYPTO_SHA256)
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *parsedCms = NULL;
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    BSL_Buffer msgBuf = {0};
    BSL_Buffer badMsg = {NULL, 1};
    BSL_Buffer encoded = {0};
    BSL_Buffer output = {0};
    bool detached = true;
    bool noAuthAttrs = true;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    int32_t invalidRecipientType = 0;
    BslCid keyEncAlg = BSL_CID_RSA;
    BslCid invalidKeyEncAlg = BSL_CID_UNKNOWN;
    int32_t macAlg = CRYPT_MAC_HMAC_SHA256;
    int32_t digestAlg = BSL_CID_SHA256;
    int32_t contentType = BSL_CID_PKCS7_SIMPLEDATA;
    int32_t nonDataContentType = BSL_CID_PKCS7_SIGNEDDATA;

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(SDV_CMS_AUTH_DEFAULT_MSG, &msgBuf.data, &msgBuf.dataLen), BSL_SUCCESS);
    ASSERT_EQ(SDV_CMS_LoadRecipient(SDV_CMS_AUTH_DEFAULT_CERT, SDV_CMS_AUTH_DEFAULT_KEY, &recipientCert, &recipientKey),
        HITLS_PKI_SUCCESS);

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms, NULL);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_CMS_ERR_INVALID_STATE);
    BSL_Param paramsNoMac[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(contentType), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataAuth(cms, &msgBuf, paramsNoMac), HITLS_CMS_ERR_INVALID_ALGO);

    HITLS_CMS_Free(cms);
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms, NULL);
    BSL_Param paramsConflict[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(contentType), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_NO_AUTH_ATTRS, BSL_PARAM_TYPE_BOOL, &noAuthAttrs, sizeof(noAuthAttrs), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataAuth(cms, &msgBuf, paramsConflict), HITLS_CMS_ERR_INVALID_PARAM);

    HITLS_CMS_Free(cms);
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms, NULL);
    BSL_Param paramsNonIdNoAttrs[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &nonDataContentType, sizeof(nonDataContentType), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_NO_AUTH_ATTRS, BSL_PARAM_TYPE_BOOL, &noAuthAttrs, sizeof(noAuthAttrs), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataAuth(cms, &msgBuf, paramsNonIdNoAttrs), HITLS_CMS_ERR_INVALID_PARAM);

    HITLS_CMS_Free(cms);
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms, NULL);
    BSL_Param paramsMissingRecipientType[] = {
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(contentType), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    BSL_Param paramsMissingRecipientCert[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(contentType), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    BSL_Param paramsMissingKeyEncAlg[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(contentType), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    BSL_Param paramsInvalidRecipientType[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &invalidRecipientType, sizeof(invalidRecipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(contentType), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    BSL_Param paramsInvalidKeyEncAlg[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &invalidKeyEncAlg, sizeof(invalidKeyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(contentType), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    ASSERT_NE(HITLS_CMS_DataAuth(cms, &msgBuf, paramsMissingRecipientType), HITLS_PKI_SUCCESS);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(cms->ctx.authenticatedData->recipientInfos), 0);
    ASSERT_NE(HITLS_CMS_DataAuth(cms, &msgBuf, paramsMissingRecipientCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(cms->ctx.authenticatedData->recipientInfos), 0);
    ASSERT_NE(HITLS_CMS_DataAuth(cms, &msgBuf, paramsMissingKeyEncAlg), HITLS_PKI_SUCCESS);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(cms->ctx.authenticatedData->recipientInfos), 0);
    ASSERT_NE(HITLS_CMS_DataAuth(cms, &msgBuf, paramsInvalidRecipientType), HITLS_PKI_SUCCESS);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(cms->ctx.authenticatedData->recipientInfos), 0);
    ASSERT_NE(HITLS_CMS_DataAuth(cms, &msgBuf, paramsInvalidKeyEncAlg), HITLS_PKI_SUCCESS);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(cms->ctx.authenticatedData->recipientInfos), 0);

    HITLS_CMS_Free(cms);
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms, NULL);
    BSL_Param paramsDetached[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(contentType), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataAuth(cms, &badMsg, paramsDetached), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(cms->ctx.authenticatedData->recipientInfos), 0);
    ASSERT_EQ(cms->ctx.authenticatedData->hasDigestAlg, false);
    ASSERT_EQ(HITLS_CMS_DataAuth(cms, &msgBuf, paramsDetached), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataAuthVerify(parsedCms, recipientKey, NULL, NULL, &output),
        HITLS_CMS_ERR_RECIPIENT_CERT_REQUIRED);

    BSL_Param verifyParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataAuthVerify(parsedCms, recipientKey, NULL, verifyParams, &output), HITLS_CMS_ERR_INVALID_DATA);

    HITLS_CMS_Free(parsedCms);
    parsedCms = NULL;
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms), HITLS_PKI_SUCCESS);
    BSL_Param verifyInitParams[] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, recipientKey, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_AUTH_VERIFY, parsedCms, verifyInitParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinal(parsedCms, NULL), HITLS_CMS_ERR_VERIFY_FAIL);

EXIT:
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(parsedCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(msgBuf.data);
    BSL_SAL_Free(encoded.data);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_AUTHENTICATEDDATA_PARSE_ENCODE_STUB_TC001
 * @title  Test AuthenticatedData parse under malloc failures
 * @brief
 *    1. Parse AuthenticatedData to count malloc calls
 *    2. Systematically inject malloc failure during parse
 *    3. Verify parsed AuthenticatedData is rejected by generated-data encoding path
 * @expect
 *    1. Parse success path works
 *    2. malloc failure paths are covered without leaks
 *    3. Encode returns INVALID_STATE
 */
/* BEGIN_CASE */
void SDV_CMS_AUTHENTICATEDDATA_PARSE_ENCODE_STUB_TC001(Hex *authDataBuf)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA)
    (void)authDataBuf;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms1 = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer inputBuf = {authDataBuf->x, authDataBuf->len};
    uint32_t totalMallocCount = 0;

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &inputBuf, &cms), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        (void)HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &inputBuf, &cms1);
        HITLS_CMS_Free(cms1);
        cms1 = NULL;
    }

    STUB_EnableMallocFail(false);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_CMS_ERR_INVALID_STATE);

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms1);
    BSL_SAL_Free(encoded.data);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_AUTHENTICATEDDATA_AUTH_VERIFY_STUB_TC001
 * @title  Test AuthenticatedData one-shot auth and verify under malloc failures
 * @brief
 *    1. Generate AuthenticatedData successfully to count malloc calls in auth
 *    2. Inject malloc failures during one-shot generation
 *    3. Verify generated AuthenticatedData successfully to count malloc calls in verify
 *    4. Inject malloc failures during verification
 * @expect
 *    1. Success paths work
 *    2. malloc failure paths are covered without leaks
 */
/* BEGIN_CASE */
void SDV_CMS_AUTHENTICATEDDATA_AUTH_VERIFY_STUB_TC001(char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA) || !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_HMAC) || \
    !defined(HITLS_CRYPTO_SHA256)
    (void)certPath;
    (void)keyPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms1 = NULL;
    HITLS_CMS *parsedCms = NULL;
    HITLS_CMS *parsedCms1 = NULL;
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    BSL_Buffer msgBuf = {(uint8_t *)"AuthenticatedData stub test", 27};
    BSL_Buffer encoded = {0};
    uint32_t totalMallocCount = 0;
    bool detached = false;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid keyEncAlg = BSL_CID_RSA;
    int32_t macAlg = CRYPT_MAC_HMAC_SHA256;
    int32_t digestAlg = BSL_CID_SHA256;
    int32_t contentType = BSL_CID_PKCS7_SIMPLEDATA;

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(SDV_CMS_LoadRecipient(certPath, keyPath, &recipientCert, &recipientKey), HITLS_PKI_SUCCESS);

    BSL_Param authParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentType, sizeof(contentType), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    BSL_Param verifyParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        BSL_PARAM_END
    };

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    cms1 = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms, NULL);
    ASSERT_NE(cms1, NULL);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_DataAuth(cms, &msgBuf, authParams), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        (void)HITLS_CMS_DataAuth(cms1, &msgBuf, authParams);
        HITLS_CMS_Free(cms1);
        STUB_EnableMallocFail(false);
        cms1 = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
        ASSERT_NE(cms1, NULL);
        STUB_EnableMallocFail(true);
    }

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataAuthVerify(parsedCms, recipientKey, NULL, verifyParams, NULL), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_EnableMallocFail(false);
        ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms1), HITLS_PKI_SUCCESS);
        STUB_EnableMallocFail(true);
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        (void)HITLS_CMS_DataAuthVerify(parsedCms1, recipientKey, NULL, verifyParams, NULL);
        HITLS_CMS_Free(parsedCms1);
        parsedCms1 = NULL;
    }

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms1);
    HITLS_CMS_Free(parsedCms);
    HITLS_CMS_Free(parsedCms1);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(encoded.data);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_AUTHENTICATEDDATA_PARSE_INVALID_TC001
 * @title  Parse invalid AuthenticatedData encodings
 * @brief
 *    1. Parse AuthenticatedData from invalid buffer
 *    2. Verify parse fails with expected error
 * @expect
 *    1. Parse returns expected RFC-format error
 */
/* BEGIN_CASE */
void SDV_CMS_AUTHENTICATEDDATA_PARSE_INVALID_TC001(Hex *authDataBuf, int expectRet)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA)
    (void)authDataBuf;
    (void)expectRet;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    BSL_Buffer inputBuf = {authDataBuf->x, authDataBuf->len};

    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &inputBuf, &cms), expectRet);
    ASSERT_EQ(cms, NULL);
EXIT:
    HITLS_CMS_Free(cms);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_AUTHENTICATEDDATA_EMPTY_DETACHED_TC001
 * @title  Test detached AuthenticatedData with empty content in one-shot mode
 * @brief
 *    1. Generate detached AuthenticatedData with empty content and authAttrs
 *    2. Encode and parse the generated CMS
 *    3. Verify with empty external content
 *    4. Verify that NULL external content is still rejected
 * @expect
 *    1. Generation succeeds
 *    2. Parse succeeds
 *    3. Verification with empty content succeeds
 *    4. Verification with NULL content returns INVALID_DATA
 */
/* BEGIN_CASE */
void SDV_CMS_AUTHENTICATEDDATA_EMPTY_DETACHED_TC001(void)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA) || !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_CRYPTO_HMAC) || \
    !defined(HITLS_CRYPTO_SHA256)
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *parsedCms = NULL;
    HITLS_X509_Cert *recipientCert = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    BSL_Buffer emptyBuf = {0};
    BSL_Buffer encoded = {0};
    BSL_Buffer output = {0};
    bool detached = true;
    int32_t recipientType = HITLS_CMS_RECIPIENT_TYPE_KTRI;
    BslCid keyEncAlg = BSL_CID_RSA;
    int32_t macAlg = CRYPT_MAC_HMAC_SHA256;
    int32_t digestAlg = BSL_CID_SHA256;
    int32_t contentTypeId = BSL_CID_PKCS7_SIMPLEDATA;

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(SDV_CMS_LoadRecipient(SDV_CMS_AUTH_DEFAULT_CERT, SDV_CMS_AUTH_DEFAULT_KEY, &recipientCert, &recipientKey),
        HITLS_PKI_SUCCESS);

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms, NULL);

    BSL_Param authParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_TYPE, BSL_PARAM_TYPE_INT32, &recipientType, sizeof(recipientType), 0},
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, BSL_PARAM_TYPE_INT32, &keyEncAlg, sizeof(keyEncAlg), 0},
        {HITLS_CMS_PARAM_CONTENT_TYPE, BSL_PARAM_TYPE_INT32, &contentTypeId, sizeof(contentTypeId), 0},
        {HITLS_CMS_PARAM_MAC_ALG, BSL_PARAM_TYPE_INT32, &macAlg, sizeof(macAlg), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(digestAlg), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(detached), 0},
        BSL_PARAM_END
    };
    BSL_Param verifyParams[] = {
        {HITLS_CMS_PARAM_RECIPIENT_CERT, BSL_PARAM_TYPE_CTX_PTR, recipientCert, sizeof(HITLS_X509_Cert *), 0},
        BSL_PARAM_END
    };

    ASSERT_EQ(HITLS_CMS_DataAuth(cms, &emptyBuf, authParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataAuthVerify(parsedCms, recipientKey, &emptyBuf, verifyParams, &output), HITLS_PKI_SUCCESS);
    ASSERT_EQ(output.data, NULL);
    ASSERT_EQ(output.dataLen, 0);
    ASSERT_EQ(HITLS_CMS_DataAuthVerify(parsedCms, recipientKey, NULL, verifyParams, &output), HITLS_CMS_ERR_INVALID_DATA);

    HITLS_CMS_Free(cms);
    cms = NULL;
    HITLS_CMS_Free(parsedCms);
    parsedCms = NULL;
    BSL_SAL_Free(encoded.data);
    encoded.data = NULL;
    encoded.dataLen = 0;
    SDV_CMS_ResetBuffer(&output);
    detached = false;

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms, NULL);
    ASSERT_EQ(HITLS_CMS_DataAuth(cms, &emptyBuf, authParams), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedCms->ctx.authenticatedData->detached, false);
    ASSERT_EQ(HITLS_CMS_DataAuthVerify(parsedCms, recipientKey, NULL, verifyParams, &output), HITLS_PKI_SUCCESS);
    ASSERT_EQ(output.dataLen, 0);

EXIT:
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(parsedCms);
    HITLS_X509_CertFree(recipientCert);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    BSL_SAL_Free(encoded.data);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_AUTHENTICATEDDATA_PARSE_ENCODE_TC001
 * @title  Test AuthenticatedData parse and encode
 * @brief
 *    1. Parse AuthenticatedData from buffer using HITLS_CMS_ProviderParseBuff
 *    2. Verify parsed AuthenticatedData structure fields
 *    3. Verify parsed AuthenticatedData is not accepted by generated-data encoding path
 * @expect
 *    1. Parse succeeds
 *    2. Parsed fields match expected vector metadata
 *    3. Re-encode returns INVALID_STATE
 */
/* BEGIN_CASE */
void SDV_CMS_AUTHENTICATEDDATA_PARSE_ENCODE_TC001(Hex *authDataBuf, int expectVersion, int expectRecipientCnt,
    int expectDetached, int expectMacAlg, int expectDigestAlg, int expectHasAuthAttrs, int expectHasUnauthAttrs)
{
#if !defined(HITLS_PKI_CMS_AUTHENTICATEDDATA)
    (void)authDataBuf;
    (void)expectVersion;
    (void)expectRecipientCnt;
    (void)expectDetached;
    (void)expectMacAlg;
    (void)expectDigestAlg;
    (void)expectHasAuthAttrs;
    (void)expectHasUnauthAttrs;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    BSL_Buffer encoded = {0};
    BSL_Buffer inputBuf = {authDataBuf->x, authDataBuf->len};

    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &inputBuf, &cms), HITLS_PKI_SUCCESS);
    ASSERT_NE(cms, NULL);
    ASSERT_EQ(cms->dataType, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    ASSERT_NE(cms->ctx.authenticatedData, NULL);

    ASSERT_EQ(cms->ctx.authenticatedData->version, expectVersion);
    ASSERT_NE(cms->ctx.authenticatedData->recipientInfos, NULL);
    ASSERT_EQ((int32_t)BSL_LIST_COUNT(cms->ctx.authenticatedData->recipientInfos), expectRecipientCnt);
    ASSERT_EQ(cms->ctx.authenticatedData->detached, (bool)expectDetached);
    ASSERT_EQ(cms->ctx.authenticatedData->macAlg.id, expectMacAlg);

    if (expectDigestAlg == BSL_CID_UNKNOWN) {
        ASSERT_EQ(cms->ctx.authenticatedData->hasDigestAlg, false);
    } else {
        ASSERT_EQ(cms->ctx.authenticatedData->hasDigestAlg, true);
        ASSERT_EQ(cms->ctx.authenticatedData->digestAlg.id, expectDigestAlg);
    }

    ASSERT_EQ(SDV_CMS_HasAttrEntries(cms->ctx.authenticatedData->authAttrs), (bool)expectHasAuthAttrs);
    ASSERT_EQ(SDV_CMS_HasAttrEntries(cms->ctx.authenticatedData->unauthAttrs), (bool)expectHasUnauthAttrs);

    if (expectDetached) {
        ASSERT_TRUE(cms->ctx.authenticatedData->encapCont.content.data == NULL ||
            cms->ctx.authenticatedData->encapCont.content.dataLen == 0);
    } else {
        ASSERT_NE(cms->ctx.authenticatedData->encapCont.content.data, NULL);
        ASSERT_LT(0, cms->ctx.authenticatedData->encapCont.content.dataLen);
    }

    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_CMS_ERR_INVALID_STATE);
EXIT:
    HITLS_CMS_Free(cms);
    BSL_SAL_Free(encoded.data);
    return;
#endif
}
/* END_CASE */
