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
#include "bsl_asn1.h"
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
#include "hitls_cert_local.h"
#include "bsl_obj_internal.h"
#include "bsl_list.h"

// Helper function to determine appropriate digest algorithm based on SLH-DSA variant
static int32_t GetDigestAlgForSlhDsa(const char *certPath)
{
    int32_t isShake = (strstr(certPath, "shake") != NULL);
    if (strstr(certPath, "128") != NULL) {
        return isShake ? BSL_CID_SHAKE128 : BSL_CID_SHA256;
    }
    if (strstr(certPath, "192") != NULL) {
        return isShake ? BSL_CID_SHAKE256 : BSL_CID_SHA512;
    }
    return isShake ? BSL_CID_SHAKE256 : BSL_CID_SHA512;
}

static bool HasSignedAttr(CMS_SignerInfo *si, BslCid cid)
{
    if (si == NULL || si->signedAttrs == NULL) {
        return false;
    }
    for (HITLS_X509_AttrEntry *attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(si->signedAttrs->list); attr != NULL;
         attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(si->signedAttrs->list)) {
        if (attr->cid == cid) {
            return true;
        }
    }
    return false;
}

static HITLS_X509_AttrEntry *FindSignedAttr(CMS_SignerInfo *si, BslCid cid)
{
    if (si == NULL || si->signedAttrs == NULL) {
        return NULL;
    }
    for (HITLS_X509_AttrEntry *attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(si->signedAttrs->list); attr != NULL;
         attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(si->signedAttrs->list)) {
        if (attr->cid == cid) {
            return attr;
        }
    }
    return NULL;
}

static int32_t UpdateDerLen(uint8_t *tlv, uint32_t delta)
{
    if (tlv == NULL) {
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if ((tlv[1] & 0x80) == 0) {
        tlv[1] = (uint8_t)(tlv[1] + delta);
        return HITLS_PKI_SUCCESS;
    }

    uint32_t lenBytes = tlv[1] & 0x7F;
    uint32_t len = 0;
    if (lenBytes == 0 || lenBytes > sizeof(uint32_t)) {
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    for (uint32_t i = 0; i < lenBytes; i++) {
        len = (len << 8) | tlv[2 + i];
    }
    len += delta;
    for (uint32_t i = 0; i < lenBytes; i++) {
        uint32_t shift = (lenBytes - 1 - i) * 8;
        tlv[2 + i] = (uint8_t)((len >> shift) & 0xFF);
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t GetDerTlv(const uint8_t *data, uint32_t dataLen, uint8_t expectedTag, uint32_t *hdrLen, uint32_t *valLen)
{
    uint32_t lenBytes = 0;
    uint32_t len = 0;

    if (data == NULL || hdrLen == NULL || valLen == NULL || dataLen < 2) {
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (data[0] != expectedTag) {
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if ((data[1] & 0x80) == 0) {
        *hdrLen = 2;
        *valLen = data[1];
        return (*hdrLen + *valLen <= dataLen) ? HITLS_PKI_SUCCESS : HITLS_CMS_ERR_INVALID_DATA;
    }

    lenBytes = data[1] & 0x7F;
    if (lenBytes == 0 || lenBytes > sizeof(uint32_t) || dataLen < (2 + lenBytes)) {
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    for (uint32_t i = 0; i < lenBytes; i++) {
        len = (len << 8) | data[2 + i];
    }
    *hdrLen = 2 + lenBytes;
    *valLen = len;
    return (*hdrLen + *valLen <= dataLen) ? HITLS_PKI_SUCCESS : HITLS_CMS_ERR_INVALID_DATA;
}

/*
 * The CMSAlgorithmProtection attrValue.buff has the following DER layout
 * (RFC 6211; outer SEQUENCE wraps the three fields):
 *
 *   30 <outerLen>               -- CMSAlgorithmProtection SEQUENCE
 *     30 <len1>                 -- digestAlgorithm SEQUENCE { OID }
 *       06 <len>  <digest-oid>
 *     A1 <len2>                 -- [1] IMPLICIT signatureAlgorithm { OID }
 *       06 <len>  <sigalg-oid>  -- OID directly inside [1], no inner SEQUENCE
 *
 * We want to insert NULL params (05 00) right after the sigalg OID, so the result becomes:
 *     A1 <len2+2>
 *       06 <len>  <sigalg-oid>
 *       05 00                   -- NULL parameters
 *
 * Both the [1] tag's length and the outer SEQUENCE's length must be
 * updated (each grows by 2 bytes). The digestAlgorithm SEQUENCE is not
 * affected.
 */
static int32_t InsertNullParamIntoAlgProtectSignAlg(HITLS_X509_AttrEntry *attr)
{
    uint32_t itemHdrLen = 0;
    uint32_t itemValLen = 0;
    uint32_t curOffset = 0;
    uint32_t outerHdrLen = 0;
    uint32_t signAlgCtxOffset = 0;  /* offset of the [1] A1 TLV */
    uint8_t *newData = NULL;
    uint32_t insertOffset;
    int32_t ret;
    uint32_t offset;

    if (attr == NULL || attr->attrValue.buff == NULL || attr->attrValue.len == 0) {
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    /* strip the outer CMSAlgorithmProtection SEQUENCE wrapper */
    ret = GetDerTlv(attr->attrValue.buff, attr->attrValue.len,
                    BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &outerHdrLen, &itemValLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    curOffset = outerHdrLen;

    /* skip the digestAlgorithm SEQUENCE (first inner TLV, tag 0x30) */
    ret = GetDerTlv(attr->attrValue.buff + curOffset, attr->attrValue.len - curOffset,
                    BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &itemHdrLen, &itemValLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    curOffset += itemHdrLen + itemValLen;

    /* locate the [1] context-specific tag (signatureAlgorithm) */
    signAlgCtxOffset = curOffset;
    ret = GetDerTlv(attr->attrValue.buff + curOffset, attr->attrValue.len - curOffset,
                    BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0x01, &itemHdrLen, &itemValLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    curOffset += itemHdrLen;  /* now points at the content of [1], i.e. the OID directly */

    /* locate the OID inside [1] — it is directly there, no inner SEQUENCE */
    ret = GetDerTlv(attr->attrValue.buff + curOffset, attr->attrValue.len - curOffset,
                    BSL_ASN1_TAG_OBJECT_ID, &itemHdrLen, &itemValLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    insertOffset = curOffset + itemHdrLen + itemValLen;  /* just after the OID: insert 05 00 here */

    /* Allocate new buffer with 2 extra bytes for the NULL TLV */
    newData = BSL_SAL_Calloc(attr->attrValue.len + 2, 1);
    if (newData == NULL) {
        return BSL_MALLOC_FAIL;
    }
    for (offset = 0; offset < insertOffset; offset++) {
        newData[offset] = attr->attrValue.buff[offset];
    }
    newData[insertOffset] = BSL_ASN1_TAG_NULL;
    newData[insertOffset + 1] = 0x00;
    for (offset = insertOffset; offset < attr->attrValue.len; offset++) {
        newData[offset + 2] = attr->attrValue.buff[offset];
    }

    ret = UpdateDerLen(newData + signAlgCtxOffset, 2);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(newData);
        return ret;
    }
    ret = UpdateDerLen(newData, 2);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(newData);
        return ret;
    }

    BSL_SAL_FREE(attr->attrValue.buff);
    attr->attrValue.buff = newData;
    attr->attrValue.len += 2;
    return HITLS_PKI_SUCCESS;
}

static bool AlgProtectSignAlgHasTrailingNullParam(HITLS_X509_AttrEntry *attr, BslCid *algCid)
{
    uint32_t itemHdrLen = 0;
    uint32_t itemValLen = 0;
    uint32_t curOffset = 0;
    uint32_t signAlgValLen = 0;
    uint32_t oidTlvLen = 0;

    if (algCid != NULL) {
        *algCid = BSL_CID_UNKNOWN;
    }
    if (attr == NULL || attr->attrValue.buff == NULL || attr->attrValue.len == 0) {
        return false;
    }
    /* strip outer CMSAlgorithmProtection SEQUENCE wrapper */
    if (GetDerTlv(attr->attrValue.buff, attr->attrValue.len,
                  BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &itemHdrLen, &itemValLen) != HITLS_PKI_SUCCESS) {
        return false;
    }
    curOffset = itemHdrLen;
    /* skip digestAlgorithm SEQUENCE */
    if (GetDerTlv(attr->attrValue.buff + curOffset, attr->attrValue.len - curOffset,
                  BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &itemHdrLen, &itemValLen) != HITLS_PKI_SUCCESS) {
        return false;
    }
    curOffset += itemHdrLen + itemValLen;
    if (GetDerTlv(attr->attrValue.buff + curOffset, attr->attrValue.len - curOffset,
                  BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0x01,
                  &itemHdrLen, &itemValLen) != HITLS_PKI_SUCCESS) {
        return false;
    }
    signAlgValLen = itemValLen;
    curOffset += itemHdrLen;
    if (GetDerTlv(attr->attrValue.buff + curOffset, attr->attrValue.len - curOffset, BSL_ASN1_TAG_OBJECT_ID,
                  &itemHdrLen, &itemValLen) != HITLS_PKI_SUCCESS) {
        return false;
    }
    if (algCid != NULL) {
        *algCid = BSL_OBJ_GetCidFromOidBuff(attr->attrValue.buff + curOffset + itemHdrLen, itemValLen);
    }
    oidTlvLen = itemHdrLen + itemValLen;
    curOffset += itemHdrLen + itemValLen;
    return (signAlgValLen == oidTlvLen + 2 && attr->attrValue.len >= curOffset + 2 &&
            attr->attrValue.buff[curOffset] == BSL_ASN1_TAG_NULL &&
            attr->attrValue.buff[curOffset + 1] == 0x00);
}

/* END_HEADER */

/**
 * @test   SDV_CMS_SLHDSA_SIGN_VERIFY_TC001
 * @title  Test SLH-DSA signature and verification in CMS SignedData
 * @brief
 *    1. Create CMS SignedData structure
 *    2. Sign data using SLH-DSA with detached/attached mode
 *    3. Encode CMS SignedData to buffer
 *    4. Parse CMS SignedData from buffer
 *    5. Verify signature with correct message (detached) or NULL (attached)
 *    6. For attached: verify content extraction; for detached: verify fails without message
 *    7. Verify fails with wrong message
 * @expect
 *    All operations succeed as expected
 */
/* BEGIN_CASE */
void SDV_CMS_SLHDSA_SIGN_VERIFY_TC001(char *certPath, char *keyPath, int isDetached)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_SLH_DSA) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    (void)isDetached;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_List *untrustedCertList = NULL;
    HITLS_X509_List *caCertList = NULL;
    BSL_Buffer msg = {(uint8_t *)"Test message for SLH-DSA signature", 34};
    BSL_Buffer wrongMsg = {(uint8_t *)"Wrong message", 13};
    BSL_Buffer encoded = {0};
    HITLS_CMS *parsedCms = NULL;
    int32_t ret;

    // Initialize random number generator
    ASSERT_EQ(TestRandInit(), 0);

    // Load certificate
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &cert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(cert, NULL);

    // Load private key
    BSL_Buffer keyBuf = {0};
    ret = BSL_SAL_ReadFile(keyPath, &keyBuf.data, &keyBuf.dataLen);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_NE(prvKey, NULL);

    // Create CMS SignedData
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    int ref;

    // Prepare parameters for signing
    // Select appropriate digest algorithm based on SLH-DSA security level
    int32_t digestAlg = GetDigestAlgForSlhDsa(certPath);
    bool detached = (isDetached != 0);
    bool hasNoSignedAttrs = true;
    BSL_Param params[4] = {
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(int32_t), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(bool), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &hasNoSignedAttrs, sizeof(hasNoSignedAttrs), 0},
        BSL_PARAM_END};

    // Sign data
    ret = HITLS_CMS_DataSign(cms, prvKey, cert, &msg, params);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Encode CMS SignedData
    ret = HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(encoded.data, NULL);
    ASSERT_TRUE(encoded.dataLen > 0);

    // Parse CMS SignedData
    ret = HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(parsedCms, NULL);

    // Create CA certificate list for verification (use the signing cert as trust anchor)
    untrustedCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(untrustedCertList, NULL);
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(untrustedCertList, cert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertList, NULL);
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(caCertList, cert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    // Prepare verification parameters
    BSL_Param verifyParams[3] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, untrustedCertList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END};

    // Test verification based on detached mode
    if (isDetached) {
        // Detached mode: must provide message for verification
        ret = HITLS_CMS_DataVerify(parsedCms, &msg, verifyParams, NULL);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

        // Verify without message should fail
        BSL_Buffer nullMsg = {NULL, 0};
        ret = HITLS_CMS_DataVerify(parsedCms, NULL, verifyParams, NULL);
        ASSERT_EQ(ret, HITLS_CMS_ERR_SIGNEDDATA_NO_CONTENT);
        ret = HITLS_CMS_DataVerify(parsedCms, &nullMsg, verifyParams, NULL);
        ASSERT_EQ(ret, HITLS_CMS_ERR_SIGNEDDATA_NO_CONTENT);

        // Verify with wrong message should fail
        ret = HITLS_CMS_DataVerify(parsedCms, &wrongMsg, verifyParams, NULL);
        ASSERT_NE(ret, HITLS_PKI_SUCCESS);
    } else {
        // Attached mode: can verify without external message
        ret = HITLS_CMS_DataVerify(parsedCms, NULL, verifyParams, NULL);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

        // Can also verify with correct message
        ret = HITLS_CMS_DataVerify(parsedCms, &msg, verifyParams, NULL);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

        // Extract content and verify
        BSL_Buffer output = {0};
        ret = HITLS_CMS_DataVerify(parsedCms, &msg, verifyParams, &output);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
        ASSERT_NE(output.data, NULL);
        ASSERT_EQ(output.dataLen, msg.dataLen);
        ASSERT_EQ(memcmp(output.data, msg.data, msg.dataLen), 0);
        BSL_SAL_Free(output.data);

        // Verify with wrong message should fail with content mismatch
        ret = HITLS_CMS_DataVerify(parsedCms, &wrongMsg, verifyParams, NULL);
        ASSERT_EQ(ret, HITLS_CMS_ERR_SIGNEDDATA_CONTENT_MISMATCH);
    }

EXIT:
    BSL_SAL_Free(keyBuf.data);
    BSL_SAL_Free(encoded.data);
    BSL_LIST_FREE(untrustedCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_CMS_Free(parsedCms);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    HITLS_X509_CertFree(cert);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SLHDSA_SIGNEDATTR_SIGN_VERIFY_TC001
 * @title  Test SLH-DSA CMS SignedData with RFC 9814 signedAttrs path
 * @brief
 *    1. Sign SLH-DSA CMS SignedData with signedAttrs present
 *    2. Encode and parse the CMS structure
 *    3. Check required signedAttrs are present
 *    4. Verify attached or detached content
 * @expect
 *    Signing, parsing, attribute checks, and verification all succeed
 */
/* BEGIN_CASE */
void SDV_CMS_SLHDSA_SIGNEDATTR_SIGN_VERIFY_TC001(char *certPath, char *keyPath, int isDetached)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_SLH_DSA) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    (void)isDetached;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *parsedCms = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_List *untrustedCertList = NULL;
    HITLS_X509_List *caCertList = NULL;
    BSL_Buffer keyBuf = {0};
    BSL_Buffer msg = {(uint8_t *)"Test message for SLH-DSA signedAttrs", 36};
    BSL_Buffer encoded = {0};
    int ref;

    ASSERT_EQ(TestRandInit(), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(keyPath, &keyBuf.data, &keyBuf.dataLen), BSL_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey),
              CRYPT_SUCCESS);

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    int32_t digestAlg = GetDigestAlgForSlhDsa(certPath);
    bool detached = (isDetached != 0);
    BSL_Param params[3] = {{HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(int32_t), 0},
                           {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(bool), 0},
                           BSL_PARAM_END};
    ASSERT_EQ(HITLS_CMS_DataSign(cms, prvKey, cert, &msg, params), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms), HITLS_PKI_SUCCESS);

    CMS_SignerInfo *si = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(parsedCms->ctx.signedData->signerInfos);
    ASSERT_NE(si, NULL);
    ASSERT_TRUE(HasSignedAttr(si, BSL_CID_PKCS9_AT_CONTENTTYPE));
    ASSERT_TRUE(HasSignedAttr(si, BSL_CID_PKCS9_AT_MESSAGEDIGEST));
    ASSERT_TRUE(HasSignedAttr(si, BSL_CID_PKCS9_AT_CMSALGORITHMPROTECTION));

    untrustedCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(untrustedCertList, NULL);
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(untrustedCertList, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, cert, BSL_LIST_POS_END), BSL_SUCCESS);

    BSL_Param verifyParams[3] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, untrustedCertList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END};
    if (isDetached) {
        ASSERT_EQ(HITLS_CMS_DataVerify(parsedCms, &msg, verifyParams, NULL), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_CMS_DataVerify(parsedCms, NULL, verifyParams, NULL), HITLS_PKI_SUCCESS);
    }

EXIT:
    BSL_SAL_Free(keyBuf.data);
    BSL_SAL_Free(encoded.data);
    BSL_LIST_FREE(untrustedCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_CMS_Free(parsedCms);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    HITLS_X509_CertFree(cert);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SLHDSA_NOATTR_SHA256_VERIFY_TC001
 * @title  Verify no-signedAttrs SLH-DSA CMS with RFC 9814 SHA-256 compatibility
 * @brief
 *    1. Generate no-signedAttrs SignedData using SHA-256
 *    2. Encode and parse the CMS structure
 *    3. Verify the CMS with the original content
 * @expect
 *    Verification succeeds for RFC 9814 compatible SHA-256 encodings
 */
/* BEGIN_CASE */
void SDV_CMS_SLHDSA_NOATTR_SHA256_VERIFY_TC001(char *certPath, char *keyPath, int isDetached)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_SLH_DSA) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    (void)isDetached;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *parsedCms = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_List *untrustedCertList = NULL;
    HITLS_X509_List *caCertList = NULL;
    BSL_Buffer keyBuf = {0};
    BSL_Buffer msg = {(uint8_t *)"Test message for SHA-256 compatibility", 38};
    BSL_Buffer encoded = {0};
    int ref;

    ASSERT_EQ(TestRandInit(), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(keyPath, &keyBuf.data, &keyBuf.dataLen), BSL_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey),
              CRYPT_SUCCESS);

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    int32_t digestAlg = BSL_CID_SHA256;
    bool detached = (isDetached != 0);
    bool hasNoSignedAttrs = true;
    BSL_Param params[4] = {
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(int32_t), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(bool), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &hasNoSignedAttrs, sizeof(hasNoSignedAttrs), 0},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_CMS_DataSign(cms, prvKey, cert, &msg, params), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms), HITLS_PKI_SUCCESS);

    untrustedCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(untrustedCertList, NULL);
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(untrustedCertList, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, cert, BSL_LIST_POS_END), BSL_SUCCESS);

    BSL_Param verifyParams[3] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, untrustedCertList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END};
    if (isDetached) {
        ASSERT_EQ(HITLS_CMS_DataVerify(parsedCms, &msg, verifyParams, NULL), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_CMS_DataVerify(parsedCms, NULL, verifyParams, NULL), HITLS_PKI_SUCCESS);
    }

EXIT:
    BSL_SAL_Free(keyBuf.data);
    BSL_SAL_Free(encoded.data);
    BSL_LIST_FREE(untrustedCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_CMS_Free(parsedCms);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    HITLS_X509_CertFree(cert);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SLHDSA_SIGALG_PARAMS_REJECT_TC001
 * @title  Reject SLH-DSA AlgorithmIdentifier parameters in CMSAlgorithmProtection
 * @brief
 *    1. Generate a valid SLH-DSA SignedData with signedAttrs
 *    2. Inject ASN.1 NULL parameters into the signatureAlgorithm inside CMSAlgorithmProtection
 *    3. Re-encode the CMS structure
 *    4. Parse the CMS structure (succeeds; attr content is not validated at parse time)
 *    5. Verify the CMS structure
 * @expect
 *    Verification fails with HITLS_CMS_ERR_PQC_PARAMS_NOT_OMITTED because CMSAlgorithmProtection
 *    is validated during DataVerify, not during parsing
 */
/* BEGIN_CASE */
void SDV_CMS_SLHDSA_SIGALG_PARAMS_REJECT_TC001(char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_SLH_DSA) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *parsedCms = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_List *untrustedCertList = NULL;
    HITLS_X509_List *caCertList = NULL;
    BSL_Buffer keyBuf = {0};
    BSL_Buffer msg = {(uint8_t *)"Test message for omitted parameters", 35};
    BSL_Buffer encoded = {0};
    HITLS_X509_AttrEntry *algProtectAttr = NULL;
    int ref;

    ASSERT_EQ(TestRandInit(), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(keyPath, &keyBuf.data, &keyBuf.dataLen), BSL_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey),
              CRYPT_SUCCESS);

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    int32_t digestAlg = GetDigestAlgForSlhDsa(certPath);
    bool detached = false;
    BSL_Param params[3] = {{HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(int32_t), 0},
                           {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(bool), 0},
                           BSL_PARAM_END};
    ASSERT_EQ(HITLS_CMS_DataSign(cms, prvKey, cert, &msg, params), HITLS_PKI_SUCCESS);

    /* Find CMSAlgorithmProtection attribute in signedAttrs */
    CMS_SignerInfo *si = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(cms->ctx.signedData->signerInfos);
    ASSERT_NE(si, NULL);
    ASSERT_NE(si->signedAttrs, NULL);
    for (HITLS_X509_AttrEntry *attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(si->signedAttrs->list);
         attr != NULL; attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(si->signedAttrs->list)) {
        if (attr->cid == BSL_CID_PKCS9_AT_CMSALGORITHMPROTECTION) {
            algProtectAttr = attr;
            break;
        }
    }
    ASSERT_NE(algProtectAttr, NULL);
    /* Inject NULL parameters into the signatureAlgorithm inside CMSAlgorithmProtection */
    ASSERT_EQ(InsertNullParamIntoAlgProtectSignAlg(algProtectAttr), HITLS_PKI_SUCCESS);

    /* Re-encode: HITLS_CMS_GenBuff uses the tampered attrValue directly */
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded), HITLS_PKI_SUCCESS);

    /* Parse: CMSAlgorithmProtection content is NOT validated at parse time, only raw bytes are stored */
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms), HITLS_PKI_SUCCESS);
    ASSERT_NE(parsedCms, NULL);

    si = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(parsedCms->ctx.signedData->signerInfos);
    ASSERT_NE(si, NULL);
    algProtectAttr = FindSignedAttr(si, BSL_CID_PKCS9_AT_CMSALGORITHMPROTECTION);
    ASSERT_NE(algProtectAttr, NULL);
    BslCid parsedAlgCid = BSL_CID_UNKNOWN;
    ASSERT_TRUE(AlgProtectSignAlgHasTrailingNullParam(algProtectAttr, &parsedAlgCid));
    ASSERT_EQ(parsedAlgCid, si->sigAlg.algId);

    /* Set up verification params */
    untrustedCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(untrustedCertList, NULL);
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(untrustedCertList, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, cert, BSL_LIST_POS_END), BSL_SUCCESS);

    BSL_Param verifyParams[3] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, untrustedCertList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END};

    /* Verify: CMSAlgorithmProtection is validated here, NULL params MUST be rejected */
    ASSERT_EQ(HITLS_CMS_DataVerify(parsedCms, NULL, verifyParams, NULL), HITLS_CMS_ERR_PQC_PARAMS_NOT_OMITTED);

EXIT:
    BSL_SAL_Free(keyBuf.data);
    BSL_SAL_Free(encoded.data);
    BSL_LIST_FREE(untrustedCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_CMS_Free(parsedCms);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    HITLS_X509_CertFree(cert);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SLHDSA_SIGALG_PUBKEY_MISMATCH_TC001
 * @title  Reject SLH-DSA signatureAlgorithm mismatch with signer certificate public key
 * @brief
 *    1. Generate a valid no-signedAttrs SLH-DSA SignedData
 *    2. Tamper SignerInfo.signatureAlgorithm to another SLH-DSA variant
 *    3. Verify the CMS structure
 * @expect
 *    Verification fails with HITLS_CMS_ERR_SIGALG_PUBKEY_MISMATCH
 */
/* BEGIN_CASE */
void SDV_CMS_SLHDSA_SIGALG_PUBKEY_MISMATCH_TC001(char *certPath, char *keyPath, int tamperedSigAlg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_SLH_DSA) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    (void)tamperedSigAlg;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_List *untrustedCertList = NULL;
    HITLS_X509_List *caCertList = NULL;
    BSL_Buffer keyBuf = {0};
    BSL_Buffer msg = {(uint8_t *)"Test message for sigalg mismatch", 32};
    int ref;

    ASSERT_EQ(TestRandInit(), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(keyPath, &keyBuf.data, &keyBuf.dataLen), BSL_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey),
              CRYPT_SUCCESS);

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    int32_t digestAlg = GetDigestAlgForSlhDsa(certPath);
    bool hasNoSignedAttrs = true;
    BSL_Param params[3] = {
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(int32_t), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &hasNoSignedAttrs, sizeof(hasNoSignedAttrs), 0},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_CMS_DataSign(cms, prvKey, cert, &msg, params), HITLS_PKI_SUCCESS);

    CMS_SignerInfo *si = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(cms->ctx.signedData->signerInfos);
    ASSERT_NE(si, NULL);
    si->sigAlg.algId = tamperedSigAlg;

    untrustedCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(untrustedCertList, NULL);
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(untrustedCertList, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, cert, BSL_LIST_POS_END), BSL_SUCCESS);

    BSL_Param verifyParams[3] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, untrustedCertList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msg, verifyParams, NULL), HITLS_CMS_ERR_SIGALG_PUBKEY_MISMATCH);

EXIT:
    BSL_SAL_Free(keyBuf.data);
    BSL_LIST_FREE(untrustedCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    HITLS_X509_CertFree(cert);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SLHDSA_SIGALG_TRAD_PUBKEY_MISMATCH_TC001
 * @title  Reject SLH-DSA signatureAlgorithm with a traditional signer certificate public key
 * @brief
 *    1. Generate a valid traditional SignedData without signedAttrs
 *    2. Tamper SignerInfo.signatureAlgorithm to an SLH-DSA variant
 *    3. Verify the CMS structure
 * @expect
 *    Verification fails with HITLS_CMS_ERR_SIGALG_PUBKEY_MISMATCH
 */
/* BEGIN_CASE */
void SDV_CMS_SLHDSA_SIGALG_TRAD_PUBKEY_MISMATCH_TC001(char *certPath, char *keyPath, int mdId, int tamperedSigAlg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_SLH_DSA) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    (void)mdId;
    (void)tamperedSigAlg;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *caCert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_List *untrustedCertList = NULL;
    HITLS_X509_List *caCertList = NULL;
    BSL_Buffer keyBuf = {0};
    BSL_Buffer msg = {(uint8_t *)"Test message for mixed sigalg mismatch", 38};
    int ref;
    bool hasNoSignedAttrs = true;

    ASSERT_EQ(TestRandInit(), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/asn1/cms/signeddata/ca_cert.pem", &caCert),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(keyPath, &keyBuf.data, &keyBuf.dataLen), BSL_SUCCESS);
    int32_t ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey);
    if (ret != CRYPT_SUCCESS) {
        ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_ECC, &keyBuf, NULL, 0, &prvKey);
    }
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    if (CRYPT_EAL_PkeyGetId(prvKey) == CRYPT_PKEY_RSA) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(prvKey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &mdId, sizeof(mdId)), CRYPT_SUCCESS);
    }

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    BSL_Param params[3] = {
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(int32_t), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &hasNoSignedAttrs, sizeof(hasNoSignedAttrs), 0},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_CMS_DataSign(cms, prvKey, cert, &msg, params), HITLS_PKI_SUCCESS);

    CMS_SignerInfo *si = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(cms->ctx.signedData->signerInfos);
    ASSERT_NE(si, NULL);
    si->sigAlg.algId = tamperedSigAlg;

    untrustedCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(untrustedCertList, NULL);
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(untrustedCertList, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(caCert, HITLS_X509_REF_UP, &ref, sizeof(int)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, caCert, BSL_LIST_POS_END), BSL_SUCCESS);

    BSL_Param verifyParams[3] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, untrustedCertList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msg, verifyParams, NULL), HITLS_CMS_ERR_SIGALG_PUBKEY_MISMATCH);

EXIT:
    BSL_SAL_Free(keyBuf.data);
    BSL_LIST_FREE(untrustedCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    HITLS_X509_CertFree(caCert);
    HITLS_X509_CertFree(cert);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SLHDSA_STREAMING_SIGN_TC001
 * @title  Test SLH-DSA streaming sign final is rejected in CMS SignedData
 * @brief
 *    1. Create CMS SignedData structure
 *    2. Initialize streaming sign with SLH-DSA (detached/attached)
 *    3. Update with multiple data chunks
 *    4. Finalize signature
 *    5. Verify final rejects PQC streaming mode
 * @expect
 *    HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC is returned at finalization
 */
/* BEGIN_CASE */
void SDV_CMS_SLHDSA_STREAMING_SIGN_TC001(char *certPath, char *keyPath)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_SLH_DSA) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    BSL_Buffer chunk1 = {(uint8_t *)"First chunk ", 12};
    BSL_Buffer chunk2 = {(uint8_t *)"Second chunk ", 13};
    BSL_Buffer chunk3 = {(uint8_t *)"Third chunk", 11};
    BSL_Buffer encoded = {0};
    int32_t ret;

    // Initialize random number generator
    ASSERT_EQ(TestRandInit(), 0);

    // Load certificate and private key
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &cert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(cert, NULL);

    BSL_Buffer keyBuf = {0};
    ret = BSL_SAL_ReadFile(keyPath, &keyBuf.data, &keyBuf.dataLen);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_NE(prvKey, NULL);

    // Create CMS SignedData
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    // Prepare init parameters
    // Select appropriate digest algorithm based on SLH-DSA security level
    int32_t digestAlg = GetDigestAlgForSlhDsa(certPath);
    bool hasNoSignedAttrs = true;
    BSL_Param initParams[4] = {
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(int32_t), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &hasNoSignedAttrs, sizeof(hasNoSignedAttrs), 0},
        BSL_PARAM_END};

    // Initialize streaming sign
    ret = HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, initParams);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Update with multiple chunks
    ret = HITLS_CMS_DataUpdate(cms, &chunk1);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_CMS_DataUpdate(cms, &chunk2);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_CMS_DataUpdate(cms, &chunk3);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Prepare final parameters
    BSL_Param finalParams[5] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, prvKey, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &digestAlg, sizeof(int32_t), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &hasNoSignedAttrs, sizeof(hasNoSignedAttrs), 0},
        BSL_PARAM_END};

    // Finalize signature
    ret = HITLS_CMS_DataFinal(cms, finalParams);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC);

EXIT:
    BSL_SAL_Free(keyBuf.data);
    BSL_SAL_Free(encoded.data);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    HITLS_X509_CertFree(cert);
    TestRandDeInit();
#endif
}
/* END_CASE */
/**
 * @test   SDV_CMS_SLHDSA_MIXED_SIGN_TC001
 * @title  Test mixed traditional and SLH-DSA signatures in CMS SignedData
 * @brief
 *    1. Create CMS SignedData structure
 *    2. Sign with traditional algorithm (RSA/ECDSA)
 *    3. Sign with SLH-DSA algorithm
 *    4. Encode and parse CMS SignedData
 *    5. Verify both signatures
 * @expect
 *    All operations succeed, both signatures verify correctly
 */
/* BEGIN_CASE */
void SDV_CMS_SLHDSA_MIXED_SIGN_TC001(char *tradCertPath, char *tradKeyPath, int tradAlgId, char *slhdsaCertPath,
                                     char *slhdsaKeyPath, int isDetached)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_SLH_DSA) || !defined(HITLS_BSL_SAL_FILE)
    (void)tradCertPath;
    (void)tradKeyPath;
    (void)tradAlgId;
    (void)slhdsaCertPath;
    (void)slhdsaKeyPath;
    (void)isDetached;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *tradCert = NULL;
    HITLS_X509_Cert *tradCaCert = NULL;
    HITLS_X509_Cert *slhdsaCert = NULL;
    CRYPT_EAL_PkeyCtx *tradKey = NULL;
    CRYPT_EAL_PkeyCtx *slhdsaKey = NULL;
    HITLS_X509_List *certList = NULL;
    HITLS_X509_List *untrustedCertList = NULL;
    HITLS_X509_List *caCertList = NULL;
    BSL_Buffer msg = {(uint8_t *)"Mixed signature test message", 28};
    BSL_Buffer encoded = {0};
    HITLS_CMS *parsedCms = NULL;
    int32_t ret;

    // Initialize random number generator
    ASSERT_EQ(TestRandInit(), 0);

    // Load traditional certificate
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, tradCertPath, &tradCert);
    if (ret != HITLS_PKI_SUCCESS) {
        ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, tradCertPath, &tradCert);
    }
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(tradCert, NULL);

    // Load traditional CA certificate (for RSA/ECDSA certificates)
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/asn1/cms/signeddata/ca_cert.pem", &tradCaCert);
    if (ret != HITLS_PKI_SUCCESS) {
        tradCaCert = NULL;
    }

    // Load traditional private key
    BSL_Buffer tradKeyBuf = {0};
    ret = BSL_SAL_ReadFile(tradKeyPath, &tradKeyBuf.data, &tradKeyBuf.dataLen);
    ASSERT_EQ(ret, BSL_SUCCESS);

    // Decode traditional key based on algorithm ID
    // BSL_CID_RSA = 6, BSL_CID_ECDSA = 36
    if (tradAlgId == 36) { // BSL_CID_ECDSA
        ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_ECC, &tradKeyBuf, NULL, 0, &tradKey);
    } else { // BSL_CID_RSA = 6
        ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &tradKeyBuf, NULL, 0, &tradKey);
        if (ret == CRYPT_SUCCESS) {
            int32_t pkcsv15 = CRYPT_MD_SHA256;
            ret = CRYPT_EAL_PkeyCtrl(tradKey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15));
            ASSERT_EQ(ret, CRYPT_SUCCESS);
        }
    }
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_NE(tradKey, NULL);

    // Load SLH-DSA certificate and key
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, slhdsaCertPath, &slhdsaCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(slhdsaCert, NULL);

    BSL_Buffer slhdsaKeyBuf = {0};
    ret = BSL_SAL_ReadFile(slhdsaKeyPath, &slhdsaKeyBuf.data, &slhdsaKeyBuf.dataLen);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &slhdsaKeyBuf, NULL, 0, &slhdsaKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_NE(slhdsaKey, NULL);

    // Create CMS SignedData
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    // Create certificate list
    certList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certList, NULL);
    int ref;
    ret = HITLS_X509_CertCtrl(tradCert, HITLS_X509_REF_UP, &ref, sizeof(int));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(certList, tradCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_X509_CertCtrl(slhdsaCert, HITLS_X509_REF_UP, &ref, sizeof(int));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(certList, slhdsaCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    // Sign with traditional algorithm first
    int32_t tradMdId = BSL_CID_SHA256;
    int32_t tradVersion = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    bool detached = (isDetached != 0);
    bool tradNoSignedAttrs = true;
    bool slhdsaNoSignedAttrs = true;
    BSL_Param tradParams[6] = {
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &tradMdId, sizeof(int32_t), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(bool), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &tradNoSignedAttrs, sizeof(tradNoSignedAttrs), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &tradVersion, sizeof(int32_t), 0},
        BSL_PARAM_END};
    ret = HITLS_CMS_DataSign(cms, tradKey, tradCert, &msg, tradParams);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Sign with SLH-DSA
    int32_t slhdsaMdId = GetDigestAlgForSlhDsa(slhdsaCertPath);
    int32_t slhdsaVersion = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    BSL_Param slhdsaParams[6] = {
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &slhdsaMdId, sizeof(int32_t), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &detached, sizeof(bool), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &slhdsaNoSignedAttrs, sizeof(slhdsaNoSignedAttrs), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &slhdsaVersion, sizeof(int32_t), 0},
        BSL_PARAM_END};
    ret = HITLS_CMS_DataSign(cms, slhdsaKey, slhdsaCert, &msg, slhdsaParams);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ASSERT_EQ(BSL_LIST_COUNT(cms->ctx.signedData->signerInfos), 2);

    // Encode CMS SignedData
    ret = HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encoded);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(encoded.data, NULL);
    ASSERT_TRUE(encoded.dataLen > 0);

    // Parse CMS SignedData
    ret = HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encoded, &parsedCms);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(parsedCms, NULL);

    ASSERT_EQ(BSL_LIST_COUNT(parsedCms->ctx.signedData->signerInfos), 2);

    // Create certificate lists for verification
    // Check if certificates are self-signed and CA certificates
    bool tradIsSelfSigned = HITLS_X509_CheckIssued(tradCert, tradCert);
    bool slhdsaIsSelfSigned = HITLS_X509_CheckIssued(slhdsaCert, slhdsaCert);
    bool tradIsCA = HITLS_X509_CertIsCA(tradCert);
    bool slhdsaIsCA = HITLS_X509_CertIsCA(slhdsaCert);

    // Create untrusted cert list
    untrustedCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(untrustedCertList, NULL);
    ret = HITLS_X509_CertCtrl(tradCert, HITLS_X509_REF_UP, &ref, sizeof(int));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(untrustedCertList, tradCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_X509_CertCtrl(slhdsaCert, HITLS_X509_REF_UP, &ref, sizeof(int));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(untrustedCertList, slhdsaCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    // Create CA certificate list
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertList, NULL);

    // Add traditional CA certificate if available
    if (tradCaCert != NULL) {
        ret = HITLS_X509_CertCtrl(tradCaCert, HITLS_X509_REF_UP, &ref, sizeof(int));
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
        ret = BSL_LIST_AddElement(caCertList, tradCaCert, BSL_LIST_POS_END);
        ASSERT_EQ(ret, BSL_SUCCESS);
    } else if (tradIsSelfSigned && tradIsCA) {
        // If no CA cert, use self-signed cert as CA
        ret = HITLS_X509_CertCtrl(tradCert, HITLS_X509_REF_UP, &ref, sizeof(int));
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
        ret = BSL_LIST_AddElement(caCertList, tradCert, BSL_LIST_POS_END);
        ASSERT_EQ(ret, BSL_SUCCESS);
    }

    // Add SLH-DSA certificate as CA if self-signed and CA
    if (slhdsaIsSelfSigned && slhdsaIsCA) {
        ret = HITLS_X509_CertCtrl(slhdsaCert, HITLS_X509_REF_UP, &ref, sizeof(int));
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
        ret = BSL_LIST_AddElement(caCertList, slhdsaCert, BSL_LIST_POS_END);
        ASSERT_EQ(ret, BSL_SUCCESS);
    }

    // Prepare verification parameters
    // Use UNTRUSTED_CERT_LISTS for signing certificates, CA_CERT_LISTS for CA certificates
    BSL_Param verifyParams[3] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, untrustedCertList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END};

    // Verify signatures based on mode
    if (isDetached) {
        // Detached mode: must provide message
        ret = HITLS_CMS_DataVerify(parsedCms, &msg, verifyParams, NULL);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

        // Without message should fail
        ret = HITLS_CMS_DataVerify(parsedCms, NULL, verifyParams, NULL);
        ASSERT_EQ(ret, HITLS_CMS_ERR_SIGNEDDATA_NO_CONTENT);
    } else {
        // Attached mode: can verify without external message
        ret = HITLS_CMS_DataVerify(parsedCms, NULL, verifyParams, NULL);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

        // Can also verify with message
        ret = HITLS_CMS_DataVerify(parsedCms, &msg, verifyParams, NULL);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

        // Extract and verify content
        BSL_Buffer output = {0};
        ret = HITLS_CMS_DataVerify(parsedCms, &msg, verifyParams, &output);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
        ASSERT_NE(output.data, NULL);
        ASSERT_EQ(output.dataLen, msg.dataLen);
        ASSERT_EQ(memcmp(output.data, msg.data, msg.dataLen), 0);
        BSL_SAL_Free(output.data);
    }

EXIT:
    BSL_SAL_Free(tradKeyBuf.data);
    BSL_SAL_Free(slhdsaKeyBuf.data);
    BSL_SAL_Free(encoded.data);
    BSL_LIST_FREE(certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(untrustedCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_CMS_Free(parsedCms);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(tradKey);
    CRYPT_EAL_PkeyFreeCtx(slhdsaKey);
    HITLS_X509_CertFree(tradCert);
    HITLS_X509_CertFree(tradCaCert);
    HITLS_X509_CertFree(slhdsaCert);
    TestRandDeInit();
#endif
}
/* END_CASE */
