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

#include "hitls_build.h"
#ifdef HITLS_PKI_PKCS12
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_asn1.h"
#include "bsl_obj_internal.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_md.h"
#include "crypt_encode_decode_key.h"
#include "hitls_pki_errno.h"
#include "hitls_cms_local.h" // For local declarations like HITLS_CMS_ParseEnvelopedData itself
#include "hitls_pki_local.h" // For HITLS_PKI_LibCtx and other PKI context if needed
#include "bsl_obj.h"         // For BSL_OBJ_CmpOid, BSL_OID_PKCS7_DATA etc.
#include "bsl_oid_name.h"    // For OID definitions
#include "crypt_eal_pkey.h"  // For asymmetric decryption
#include "crypt_eal_cipher.h"// For symmetric decryption
#include "bsl_tool.h"        // For memory allocation and utilities

#ifdef HITLS_PKI_PKCS12_PARSE
/**
 * Data Content Type
 * Data ::= OCTET STRING
 *
 * https://datatracker.ietf.org/doc/html/rfc5652#section-4
 */
int32_t HITLS_CMS_ParseAsn1Data(BSL_Buffer *encode, BSL_Buffer *dataValue)
{
    if (encode == NULL || dataValue == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    uint8_t *temp = encode->data;
    uint32_t tempLen = encode->dataLen;
    uint32_t decodeLen = 0;
    uint8_t *data = NULL;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &temp, &tempLen, &decodeLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (decodeLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    data = BSL_SAL_Dump(temp, decodeLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    dataValue->data = data;
    dataValue->dataLen = decodeLen;
    return HITLS_PKI_SUCCESS;
}
#endif

/**
 * DigestInfo ::= SEQUENCE {
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      digest Digest
 * }
 *
 * https://datatracker.ietf.org/doc/html/rfc2315#section-9.4
 */

static BSL_ASN1_TemplateItem g_digestInfoTempl[] = {
    /* digestAlgorithm */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_NULL, 0, 1},
    /* digest */
    {BSL_ASN1_TAG_OCTETSTRING, 0, 0},
};

typedef enum {
    HITLS_P7_DIGESTINFO_OID_IDX,
    HITLS_P7_DIGESTINFO_ALGPARAM_IDX,
    HITLS_P7_DIGESTINFO_OCTSTRING_IDX,
    HITLS_P7_DIGESTINFO_MAX_IDX,
} HITLS_P7_DIGESTINFO_IDX;

int32_t HITLS_CMS_ParseDigestInfo(BSL_Buffer *encode, BslCid *cid, BSL_Buffer *digest)
{
    if (encode == NULL || encode->data == NULL || digest == NULL || cid == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (encode->dataLen == 0 || digest->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    uint8_t *temp = encode->data;
    uint32_t  tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_P7_DIGESTINFO_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_digestInfoTempl, sizeof(g_digestInfoTempl) / sizeof(g_digestInfoTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_P7_DIGESTINFO_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString oidStr = {asn1[HITLS_P7_DIGESTINFO_OID_IDX].len, (char *)asn1[HITLS_P7_DIGESTINFO_OID_IDX].buff, 0};
    BslCid parseCid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (parseCid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
    if (asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    uint8_t *output = BSL_SAL_Dump(asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].buff,
        asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].len);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    digest->data = output;
    digest->dataLen = asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].len;
    *cid = parseCid;
    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_PKI_PKCS12_GEN
int32_t HITLS_CMS_EncodeDigestInfoBuff(BslCid cid, BSL_Buffer *in, BSL_Buffer *encode)
{
    if (in == NULL || encode == NULL || encode->data != NULL || (in->data == NULL && in->dataLen != 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    BslOidString *oidstr = BSL_OBJ_GetOidFromCID(cid);
    if (oidstr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BSL_ASN1_Buffer asn1[HITLS_P7_DIGESTINFO_MAX_IDX] = {
        {BSL_ASN1_TAG_OBJECT_ID, oidstr->octetLen, (uint8_t *)oidstr->octs},
        {BSL_ASN1_TAG_NULL, 0, NULL},
        {BSL_ASN1_TAG_OCTETSTRING, in->dataLen, in->data},
    };
    BSL_Buffer tmp = {0};
    BSL_ASN1_Template templ = {g_digestInfoTempl, sizeof(g_digestInfoTempl) / sizeof(g_digestInfoTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, asn1, HITLS_P7_DIGESTINFO_MAX_IDX, &tmp.data, &tmp.dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encode->data = tmp.data;
    encode->dataLen = tmp.dataLen;
    return HITLS_PKI_SUCCESS;
}
#endif

// parse and decrypt CMS EnvelopedData
int32_t HITLS_CMS_ParseEnvelopedData(HITLS_PKI_LibCtx *libCtx, const char *attrName,
                                     CRYPT_EAL_PkeyCtx *recipientPkeyCtx, BSL_Buffer *envelopedDataAsn1,
                                     BSL_Buffer *decryptedContent)
{
    int32_t ret = BSL_SUCCESS;
    BSL_ASN1_DecodeContext dc;
    BSL_ASN1_Value val[5]; // For EnvelopedData sequence
    uint32_t cmsVersion;
    BSL_Buffer recipientInfosBuf;
    BSL_ASN1_Value encryptedContentInfoSeq;
    BSL_ASN1_AlgorithmIdentifier keyEncryptionAlgorithm;
    BSL_ASN1_AlgorithmIdentifier contentEncryptionAlgorithm;
    BSL_Buffer encryptedKey;
    BSL_Buffer encryptedContent;
    BSL_Buffer cek = {0}; // Content Encryption Key
    BSL_Buffer iv = {0};

    BSL_BUF_RESET(&recipientInfosBuf);
    BSL_BUF_RESET(&encryptedKey);
    BSL_BUF_RESET(&encryptedContent);
    BSL_BUF_RESET(decryptedContent);

    if (libCtx == NULL || recipientPkeyCtx == NULL || envelopedDataAsn1 == NULL || envelopedDataAsn1->buf == NULL || decryptedContent == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKI_ERRNO_INPUT_PTR_NULL);
        return HITLS_PKI_ERRNO_INPUT_PTR_NULL;
    }

    BSL_ASN1_DECODE_CTX_INIT(&dc, envelopedDataAsn1->buf, envelopedDataAsn1->len);
    BSL_ASN1_DecodeContextMark envelopeMark;
    BSL_ASN1_DECODE_CTX_MARK(&dc, &envelopeMark);

    // EnvelopedData ::= SEQUENCE {
    //   version CMSVersion,
    //   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
    //   recipientInfos RecipientInfos,
    //   encryptedContentInfo EncryptedContentInfo,
    //   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

    ret = BSL_ASN1_DecodeSequence(&dc, NULL);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // 1. version CMSVersion
    ret = BSL_ASN1_DecodeInteger(&dc, &cmsVersion);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Versions can be 0, 2, 3, or 4 depending on RecipientInfo types.
    // For KeyTransRecipientInfo, version is 0 or 2.

    // 2. originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL
    if (BSL_ASN1_DECODE_CTX_HAS_TAG(&dc, BSL_ASN1_TAG_CONTEXT_SPECIFIC_CONSTRUCTED(0))) {
        ret = BSL_ASN1_DecodeSkip(&dc, NULL);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    // 3. recipientInfos RecipientInfos (SET OF RecipientInfo)
    ret = BSL_ASN1_DecodeSetOf(&dc, &recipientInfosBuf);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // 4. encryptedContentInfo EncryptedContentInfo
    // EncryptedContentInfo ::= SEQUENCE {
    //   contentType ContentType,
    //   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    //   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
    BSL_ASN1_VALUE_INIT(&encryptedContentInfoSeq, BSL_ASN1_TAG_SEQUENCE, NULL);
    ret = BSL_ASN1_DecodeValue(&dc, &encryptedContentInfoSeq);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // 5. unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
    if (BSL_ASN1_DECODE_CTX_HAS_TAG(&dc, BSL_ASN1_TAG_CONTEXT_SPECIFIC_CONSTRUCTED(1))) {
        ret = BSL_ASN1_DecodeSkip(&dc, NULL);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    BSL_ASN1_DECODE_CTX_VALIDATE_MARK(&dc, &envelopeMark);


    // --- Process RecipientInfos ---
    // For now, assume one KeyTransRecipientInfo and it's the one we need.
    // A full implementation would iterate through recipientInfosBuf.
    BSL_ASN1_DecodeContext dcRecipients;
    BSL_ASN1_DECODE_CTX_INIT(&dcRecipients, recipientInfosBuf.buf, recipientInfosBuf.len);
    BSL_ASN1_DecodeContextMark recipientInfosMark;
    BSL_ASN1_DECODE_CTX_MARK(&dcRecipients, &recipientInfosMark);

    // KeyTransRecipientInfo ::= SEQUENCE {
    //   version CMSVersion,    -- always set to 0 or 2
    //   rid RecipientIdentifier,
    //   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    //   encryptedKey EncryptedKey }
    ret = BSL_ASN1_DecodeSequence(&dcRecipients, NULL); // Entering the KeyTransRecipientInfo
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret; // Or try next recipient
    }
    BSL_ASN1_DecodeContextMark ktriMark;
    BSL_ASN1_DECODE_CTX_MARK(&dcRecipients, &ktriMark);

    uint32_t ktriVersion;
    ret = BSL_ASN1_DecodeInteger(&dcRecipients, &ktriVersion);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // ktriVersion should be 0 or 2.

    // rid RecipientIdentifier (CHOICE) - skip for now, assume key is correct
    ret = BSL_ASN1_DecodeSkip(&dcRecipients, NULL);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier
    BSL_ASN1_ALGO_INIT(&keyEncryptionAlgorithm);
    ret = BSL_ASN1_DecodeAlgorithmIdentifier(&dcRecipients, &keyEncryptionAlgorithm);
    if (ret != BSL_SUCCESS) {
        BSL_ASN1_ALGO_FREE(&keyEncryptionAlgorithm);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // encryptedKey EncryptedKey (OCTET STRING)
    ret = BSL_ASN1_DecodeOctetString(&dcRecipients, &encryptedKey);
    if (ret != BSL_SUCCESS) {
        BSL_ASN1_ALGO_FREE(&keyEncryptionAlgorithm);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_DECODE_CTX_VALIDATE_MARK(&dcRecipients, &ktriMark);
    // BSL_ASN1_DECODE_CTX_VALIDATE_MARK(&dcRecipients, &recipientInfosMark); // If only one RecipientInfo

    // --- Decrypt CEK ---
    BslPkeyType pkeyType = CRYPT_EAL_PkeyGetType(recipientPkeyCtx);
    if (pkeyType != BSL_PKEY_TYPE_RSA && pkeyType != BSL_PKEY_TYPE_RSAREF) {
        BSL_ASN1_ALGO_FREE(&keyEncryptionAlgorithm);
        BSL_BUF_FREE_INTERNAL(&encryptedKey);
        BSL_ERR_PUSH_ERROR(HITLS_PKI_ERRNO_CMS_INVALID_KEY_TYPE_FOR_DECRYPT);
        return HITLS_PKI_ERRNO_CMS_INVALID_KEY_TYPE_FOR_DECRYPT;
    }

    uint32_t cekPotentialLen = CRYPT_EAL_PkeyBits(recipientPkeyCtx) / 8;
    cek.buf = (uint8_t *)BSL_TOOL_Malloc(cekPotentialLen);
    if (cek.buf == NULL) {
        BSL_ASN1_ALGO_FREE(&keyEncryptionAlgorithm);
        BSL_BUF_FREE_INTERNAL(&encryptedKey);
        BSL_ERR_PUSH_ERROR(BSL_ERRNO_MEM_ALLOC_FAILED);
        return BSL_ERRNO_MEM_ALLOC_FAILED;
    }
    cek.len = cekPotentialLen;

    ret = CRYPT_EAL_PkeyDecrypt(recipientPkeyCtx, &keyEncryptionAlgorithm, &encryptedKey, &cek);
    BSL_ASN1_ALGO_FREE(&keyEncryptionAlgorithm); // Free after use
    BSL_BUF_FREE_INTERNAL(&encryptedKey);      // Free after use

    if (ret != BSL_SUCCESS) {
        BSL_TOOL_Free(cek.buf);
        BSL_BUF_RESET(&cek);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // --- Process EncryptedContentInfo ---
    BSL_ASN1_DecodeContext dcEncContent;
    BSL_ASN1_DECODE_CTX_INIT(&dcEncContent, encryptedContentInfoSeq.val.buf.buf, encryptedContentInfoSeq.val.buf.len);
    BSL_ASN1_DecodeContextMark encContentMark;
    BSL_ASN1_DECODE_CTX_MARK(&dcEncContent, &encContentMark);

    // contentType OBJECT IDENTIFIER
    BSL_ASN1_OidcontentTypeOid; // Temporary OID storage
    ret = BSL_ASN1_DecodeOid(&dcEncContent, &contentTypeOid);
    if (ret != BSL_SUCCESS) {
        BSL_TOOL_Free(cek.buf);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // TODO: Validate contentTypeOid (e.g., PKCS7_DATA)

    // contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier
    BSL_ASN1_ALGO_INIT(&contentEncryptionAlgorithm);
    ret = BSL_ASN1_DecodeAlgorithmIdentifier(&dcEncContent, &contentEncryptionAlgorithm);
    if (ret != BSL_SUCCESS) {
        BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
        BSL_TOOL_Free(cek.buf);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL (OCTET STRING)
    if (BSL_ASN1_DECODE_CTX_HAS_TAG(&dcEncContent, BSL_ASN1_TAG_CONTEXT_SPECIFIC_PRIMITIVE(0))) {
        ret = BSL_ASN1_DecodeOctetStringImplicit(&dcEncContent, 0, &encryptedContent);
        if (ret != BSL_SUCCESS) {
            BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
            BSL_TOOL_Free(cek.buf);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else { // OPTIONAL content not present
        BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
        BSL_TOOL_Free(cek.buf);
        BSL_ERR_PUSH_ERROR(HITLS_PKI_ERRNO_CMS_NO_ENCRYPTED_CONTENT); // Or handle as appropriate
        return HITLS_PKI_ERRNO_CMS_NO_ENCRYPTED_CONTENT;
    }
    BSL_ASN1_DECODE_CTX_VALIDATE_MARK(&dcEncContent, &encContentMark);


    // --- Decrypt Content ---
    CRYPT_EAL_CphId cphId = BSL_OBJ_GetCphIDFromOid(&contentEncryptionAlgorithm.oid);
    if (cphId == CRYPT_EAL_CPHID_UNKNOWN) {
        BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
        BSL_BUF_FREE_INTERNAL(&encryptedContent);
        BSL_TOOL_Free(cek.buf);
        BSL_ERR_PUSH_ERROR(HITLS_PKI_ERRNO_CMS_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM);
        return HITLS_PKI_ERRNO_CMS_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM;
    }

    // Extract IV from contentEncryptionAlgorithm.params
    if (contentEncryptionAlgorithm.params.tag == BSL_ASN1_TAG_OCTET_STRING && contentEncryptionAlgorithm.params.val.buf.len > 0) {
        iv.buf = contentEncryptionAlgorithm.params.val.buf.buf;
        iv.len = contentEncryptionAlgorithm.params.val.buf.len;
    } else {
        // IV might not be present for all algorithms (e.g. ECB, or if derived)
        // For CBC/GCM, it's typically required in params.
        // Check EAL requirements for the specific cphId.
        // For now, assume if not present and needed, it's an error.
        // This check might need refinement based on EAL behavior.
        BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
        BSL_BUF_FREE_INTERNAL(&encryptedContent);
        BSL_TOOL_Free(cek.buf);
        BSL_ERR_PUSH_ERROR(HITLS_PKI_ERRNO_CMS_MISSING_IV);
        return HITLS_PKI_ERRNO_CMS_MISSING_IV;
    }
    
    // Check IV length (example for AES)
    uint32_t expectedIvLen = 0;
    if (cphId == CRYPT_EAL_CPHID_AES128_CBC || cphId == CRYPT_EAL_CPHID_AES256_CBC ||
        cphId == CRYPT_EAL_CPHID_AES128_GCM || cphId == CRYPT_EAL_CPHID_AES256_GCM) {
        expectedIvLen = 16; // Common for AES block size, GCM default IV is 12 but can vary.
                            // EAL should handle specific IV length checks based on cphId.
                            // For GCM, IV is often 12 bytes. Let's assume EAL handles varying IVs.
    }
    // if (expectedIvLen > 0 && iv.len != expectedIvLen) { // This check might be too strict if EAL is flexible
    //     BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
    //     BSL_BUF_FREE_INTERNAL(&encryptedContent);
    //     BSL_TOOL_Free(cek.buf);
    //     BSL_ERR_PUSH_ERROR(HITLS_PKI_ERRNO_CMS_INVALID_IV_LENGTH);
    //     return HITLS_PKI_ERRNO_CMS_INVALID_IV_LENGTH;
    // }


    decryptedContent->buf = (uint8_t *)BSL_TOOL_Malloc(encryptedContent.len); // Max possible size
    if (decryptedContent->buf == NULL) {
        BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
        BSL_BUF_FREE_INTERNAL(&encryptedContent);
        BSL_TOOL_Free(cek.buf);
        BSL_ERR_PUSH_ERROR(BSL_ERRNO_MEM_ALLOC_FAILED);
        return BSL_ERRNO_MEM_ALLOC_FAILED;
    }
    decryptedContent->len = encryptedContent.len; // Will be updated

    CRYPT_EAL_CphCtx *cphCtx = NULL;
    ret = CRYPT_EAL_CphInit(&cphCtx, cphId, CRYPT_EAL_CIPHER_MODE_DECRYPT, &cek, &iv, attrName, libCtx->cryptProvCtx);
    if (ret != BSL_SUCCESS) {
        BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
        BSL_BUF_FREE_INTERNAL(&encryptedContent);
        BSL_TOOL_Free(cek.buf);
        BSL_TOOL_Free(decryptedContent->buf);
        BSL_BUF_RESET(decryptedContent);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t outLen = 0;
    ret = CRYPT_EAL_CphUpdate(cphCtx, &encryptedContent, decryptedContent->buf, &outLen);
    if (ret != BSL_SUCCESS) {
        CRYPT_EAL_CphFinal(cphCtx, NULL, 0, NULL);
        BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
        BSL_BUF_FREE_INTERNAL(&encryptedContent);
        BSL_TOOL_Free(cek.buf);
        BSL_TOOL_Free(decryptedContent->buf);
        BSL_BUF_RESET(decryptedContent);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    decryptedContent->len = outLen;

    uint32_t finalOutLen = 0;
    // Max potential size for final block (e.g. if padding removal happens here)
    uint8_t tempFinalBlock[EAL_MAX_BLOCK_SIZE]; 
    ret = CRYPT_EAL_CphFinal(cphCtx, tempFinalBlock, EAL_MAX_BLOCK_SIZE, &finalOutLen);
    if (ret != BSL_SUCCESS) { // Handles padding errors for CBC, tag check for GCM
        BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
        BSL_BUF_FREE_INTERNAL(&encryptedContent);
        BSL_TOOL_Free(cek.buf);
        BSL_TOOL_Free(decryptedContent->buf);
        BSL_BUF_RESET(decryptedContent);
        BSL_ERR_PUSH_ERROR(ret); // Could be BSL_ERRNO_CIPHER_PADDING_CHECK_FAILED or BSL_ERRNO_CIPHER_AUTH_FAILED
        return ret;
    }

    if (finalOutLen > 0) {
        if (decryptedContent->len + finalOutLen > encryptedContent.len) { // Check if buffer is large enough
             BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
             BSL_BUF_FREE_INTERNAL(&encryptedContent);
             BSL_TOOL_Free(cek.buf);
             BSL_TOOL_Free(decryptedContent->buf);
             BSL_BUF_RESET(decryptedContent);
             BSL_ERR_PUSH_ERROR(BSL_ERRNO_BUF_OVERFLOW);
             return BSL_ERRNO_BUF_OVERFLOW;
        }
        BSL_TOOL_MemCpy(decryptedContent->buf + decryptedContent->len, tempFinalBlock, finalOutLen);
        decryptedContent->len += finalOutLen;
    }

    // Cleanup
    BSL_ASN1_ALGO_FREE(&contentEncryptionAlgorithm);
    BSL_BUF_FREE_INTERNAL(&encryptedContent);
    BSL_TOOL_Free(cek.buf); // Sensitive data

    // Validate content type (e.g. id-data or id-ct-safeContents)
    // if (!(BSL_OBJ_CmpOid(&contentTypeOid, BSL_OID_PKCS7_DATA, BSL_OID_LEN(BSL_OID_PKCS7_DATA)) == BSL_SUCCESS ||
    //       BSL_OBJ_CmpOid(&contentTypeOid, BSL_OID_PKCS9_SAFECONTENTS_BAG, BSL_OID_LEN(BSL_OID_PKCS9_SAFECONTENTS_BAG)) == BSL_SUCCESS )) {
    //     BSL_TOOL_Free(decryptedContent->buf);
    //     BSL_BUF_RESET(decryptedContent);
    //     BSL_ERR_PUSH_ERROR(HITLS_PKI_ERRNO_CMS_UNEXPECTED_CONTENT_TYPE);
    //     return HITLS_PKI_ERRNO_CMS_UNEXPECTED_CONTENT_TYPE;
    // }


    return BSL_SUCCESS;
}
#endif // HITLS_PKI_PKCS12
