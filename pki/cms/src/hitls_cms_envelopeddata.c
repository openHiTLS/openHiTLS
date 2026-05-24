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
#ifdef HITLS_PKI_CMS_ENVELOPEDDATA
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_asn1_internal.h"
#include "bsl_obj_internal.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_params.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_x509.h"
#include "hitls_cms_local.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_codecskey.h"
#include "crypt_params_key.h"

void FreeEncryptedContentInfo(CMS_EncryptedContentInfo *encInfo, uint32_t flag)
{
    if (encInfo == NULL) {
        return;
    }
    if ((flag & HITLS_CMS_FLAG_PARSE) == 0) {
        BSL_SAL_FREE(encInfo->algParams.data);
    }
    if (encInfo->encryptedContent.data != NULL) {
        if ((flag & HITLS_CMS_FLAG_PARSE) == 0) {
            BSL_SAL_FREE(encInfo->encryptedContent.data);
        }
    }
    CRYPT_EAL_CipherFreeCtx(encInfo->cipherCtx);
    encInfo->cipherCtx = NULL;
    BSL_SAL_ClearFree(encInfo->key, encInfo->keyLen);
    encInfo->key = NULL;
    encInfo->keyLen = 0;
}

void CMS_EnvelopedDataFree(CMS_EnvelopedData *envData)
{
    if (envData == NULL) {
        return;
    }
    if (envData->originatorInfo != NULL) {
        BSL_LIST_FREE(envData->originatorInfo->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        BSL_LIST_FREE(envData->originatorInfo->crls, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
        BSL_SAL_Free(envData->originatorInfo);
    }
    BSL_LIST_FREE(envData->recipientInfos, (BSL_LIST_PFUNC_FREE)CMS_RecipientInfoFree);
    FreeEncryptedContentInfo(&envData->encryptedContentInfo, envData->flag);
    HITLS_X509_AttrsFree(envData->unprotectedAttrs, NULL);

    // Clean up streaming operation resources
    if (envData->streamCipherCtx != NULL) {
        CRYPT_EAL_CipherFreeCtx(envData->streamCipherCtx);
    }
    BSL_SAL_ClearFree(envData->key.data, envData->key.dataLen);

    BSL_SAL_Free(envData->initData);
    BSL_SAL_Free(envData);
}

static void ClearEnvDataKey(CMS_EnvelopedData *envData)
{
    if (envData == NULL) {
        return;
    }
    BSL_SAL_ClearFree(envData->key.data, envData->key.dataLen);
    envData->key.data = NULL;
    envData->key.dataLen = 0;
}

static int32_t GenerateCek(CRYPT_EAL_LibCtx *libCtx, BslCid encAlg, uint8_t **cek, uint32_t *cekLen)
{
    if (cek == NULL || cekLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    BSL_SAL_ClearFree(*cek, *cekLen);
    *cek = NULL;
    *cekLen = 0;
    // Get key length
    uint32_t keyLen = 0;
    int32_t ret = CRYPT_EAL_CipherGetInfo((CRYPT_CIPHER_AlgId)encAlg, CRYPT_INFO_KEY_LEN, &keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (keyLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL);
        return HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL;
    }

    uint8_t *tmp = BSL_SAL_Malloc(keyLen);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    // Generate random key
    ret = CRYPT_EAL_RandbytesEx(libCtx, tmp, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(tmp, keyLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *cek = tmp;
    *cekLen = keyLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t GenerateAndEncodeCipherAlgIV(CRYPT_EAL_LibCtx *libCtx, BslCid encAlg, uint8_t **iv, uint32_t *ivLen,
    CMS_EncryptedContentInfo *encInfo)
{
    uint8_t *ivTemp = NULL;
    uint32_t ivTempLen = 0;
    int32_t ret = CRYPT_EAL_CipherGetInfo((CRYPT_CIPHER_AlgId)encAlg, CRYPT_INFO_IV_LEN, &ivTempLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ivTempLen > 0) {
        ivTemp = BSL_SAL_Malloc(ivTempLen);
        if (ivTemp == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        ret = CRYPT_EAL_RandbytesEx(libCtx, ivTemp, ivTempLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_ClearFree(ivTemp, ivTempLen);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        // Save IV as algorithm parameters (IV encoded as OCTET STRING)
        uint8_t *algParamData = BSL_SAL_Dump(ivTemp, ivTempLen);
        if (algParamData == NULL) {
            BSL_SAL_ClearFree(ivTemp, ivTempLen);
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        *iv = ivTemp;
        *ivLen = ivTempLen;
        encInfo->algParams.data = algParamData;
        encInfo->algParams.dataLen = ivTempLen;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t EncryptContentCore(CRYPT_EAL_CipherCtx *ctx, const uint8_t *cek, uint32_t cekLen,
    uint8_t *iv, uint32_t ivLen, const BSL_Buffer *plaintext, BSL_Buffer *encryptedContent)
{
    // Initialize encryption
    int32_t ret = CRYPT_EAL_CipherInit(ctx, cek, cekLen, iv, ivLen, true);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Set PKCS7 padding
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Allocate ciphertext buffer
    uint32_t blockSize;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, &blockSize, sizeof(blockSize));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (plaintext->dataLen > UINT32_MAX - blockSize) {
        BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_LEN_OVERFLOW);
        return BSL_ASN1_ERR_LEN_OVERFLOW;
    }
    uint32_t ciphertextLen = plaintext->dataLen + blockSize;
    uint8_t *ciphertext = BSL_SAL_Malloc(ciphertextLen);
    if (ciphertext == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    // Execute encryption
    uint32_t outLen = ciphertextLen;
    ret = CRYPT_EAL_CipherUpdate(ctx, plaintext->data, plaintext->dataLen, ciphertext, &outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(ciphertext, ciphertextLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t finalLen = ciphertextLen - outLen;
    ret = CRYPT_EAL_CipherFinal(ctx, ciphertext + outLen, &finalLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(ciphertext, ciphertextLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (encryptedContent->data != NULL) {
        BSL_SAL_FREE(encryptedContent->data);
    }
    encryptedContent->data = ciphertext;
    encryptedContent->dataLen = outLen + finalLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncryptContent(CRYPT_EAL_LibCtx *libCtx, const char *attrName, const BSL_Buffer *plaintext,
    BslCid contentType, BslCid encAlg, const uint8_t *cek, uint32_t cekLen, CMS_EncryptedContentInfo *encInfo)
{
    if (plaintext == NULL || cek == NULL || encInfo == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    encInfo->contentType = contentType;
    encInfo->contentEncryAlg = encAlg;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_ProviderCipherNewCtx(libCtx, (CRYPT_CIPHER_AlgId)encAlg, attrName);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL);
        return HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL;
    }
    // Generate IV
    uint8_t *iv = NULL;
    uint32_t ivLen = 0;
    int32_t ret = GenerateAndEncodeCipherAlgIV(libCtx, encAlg, &iv, &ivLen, encInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }
    // Encrypt content
    ret = EncryptContentCore(ctx, cek, cekLen, iv, ivLen, plaintext, &encInfo->encryptedContent);
    BSL_SAL_Free(iv);
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

/**
 * according to the RFC 5652, the version of signed data is determined by the following rules:
 * IF (originatorInfo is present) AND
 * ((any certificates with a type of other are present) OR (any crls with a type of other are present))
 * THEN version is 4
 * ELSE
 * IF ((originatorInfo is present) AND (any version 2 attribute certificates are present)) OR
 * (any RecipientInfo structures include pwri) OR (any RecipientInfo structures include ori)
 * THEN version is 3
 * ELSE
 * IF (originatorInfo is absent) AND (unprotectedAttrs is absent) AND (all RecipientInfo structures are version 0)
 * THEN version is 0
 * ELSE version is 2
 */
static int32_t GetEnvDataVersion(CMS_EnvelopedData *envData)
{
    if (envData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    // not supported other type of cert and crl.
    bool hasPwriOrOri = false;
    CMS_RecipientInfo *recip = BSL_LIST_GET_FIRST(envData->recipientInfos);
    while (recip != NULL) {
        if (recip->type == CMS_RECIPIENT_TYPE_PWRI || recip->type == CMS_RECIPIENT_TYPE_ORI ||
            recip->type == CMS_RECIPIENT_TYPE_KEMRI) {
            hasPwriOrOri = true;
            break;
        }
        recip = BSL_LIST_GET_NEXT(envData->recipientInfos);
    }
    if (hasPwriOrOri) {
        envData->version = 3; // version 3
        return HITLS_PKI_SUCCESS;
    }

    if (envData->originatorInfo == NULL && envData->unprotectedAttrs == NULL) {
        bool allVersion0 = true;
        recip = BSL_LIST_GET_FIRST(envData->recipientInfos);
        while (recip != NULL) {
            if (!(recip->type == CMS_RECIPIENT_TYPE_KTRI && recip->d.ktri != NULL && recip->d.ktri->version == 0)) {
                allVersion0 = false;
                break;
            }
            recip = BSL_LIST_GET_NEXT(envData->recipientInfos);
        }
        if (allVersion0) {
            envData->version = 0; // version 0
            return HITLS_PKI_SUCCESS;
        }
    }
    // Default version 2
    envData->version = 2;
    return HITLS_PKI_SUCCESS;
}

static int32_t CMS_GenerateEnvData(CRYPT_EAL_LibCtx *libCtx, const char *attrName, const BSL_Buffer *plaintext,
    BslCid contentType, BslCid encAlg, CMS_EnvelopedData *envData)
{
    if (plaintext == NULL || envData == NULL || envData->key.data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    // Encrypt plaintext content
    int32_t ret = EncryptContent(libCtx, attrName, plaintext, contentType, encAlg,
        envData->key.data, envData->key.dataLen, &envData->encryptedContentInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    // Set EnvelopedData version number
    ret = GetEnvDataVersion(envData);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    envData->flag |= HITLS_CMS_FLAG_GEN;
    return ret;
ERR:
    BSL_LIST_FREE(envData->recipientInfos, (BSL_LIST_PFUNC_FREE)CMS_RecipientInfoFree);
    FreeEncryptedContentInfo(&envData->encryptedContentInfo, HITLS_CMS_FLAG_GEN);
    return ret;
}

static int32_t DecryptContentCore(CRYPT_EAL_CipherCtx *ctx, const uint8_t *cek, uint32_t cekLen, uint8_t *iv,
    uint32_t ivLen, CMS_EncryptedContentInfo *encInfo, BSL_Buffer *plaintext)
{
    // Initialize decryption (false indicates decryption mode)
    int32_t ret = CRYPT_EAL_CipherInit(ctx, cek, cekLen, iv, ivLen, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Set PKCS7 padding mode (for stripping padding)
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Allocate plaintext buffer (reserve enough space)
    uint32_t blockSize = 0;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, &blockSize, sizeof(blockSize));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (encInfo->encryptedContent.dataLen > UINT32_MAX - blockSize) {
        BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_LEN_OVERFLOW);
        return BSL_ASN1_ERR_LEN_OVERFLOW;
    }
    uint32_t maxPlaintextLen = encInfo->encryptedContent.dataLen + blockSize;
    uint8_t *plaintextData = BSL_SAL_Malloc(maxPlaintextLen);
    if (plaintextData == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    // Execute decryption update
    uint32_t outLen = maxPlaintextLen;
    ret = CRYPT_EAL_CipherUpdate(ctx, encInfo->encryptedContent.data, encInfo->encryptedContent.dataLen,
                                 plaintextData, &outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(plaintextData, maxPlaintextLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Complete decryption (process final block and strip padding)
    uint32_t finalLen = maxPlaintextLen - outLen;
    ret = CRYPT_EAL_CipherFinal(ctx, plaintextData + outLen, &finalLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(plaintextData, maxPlaintextLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    plaintext->data = plaintextData;
    plaintext->dataLen = outLen + finalLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t DecryptContent(CMS_EncryptedContentInfo *encInfo, const uint8_t *cek, uint32_t cekLen,
    BSL_Buffer *plaintext)
{
    if (encInfo->encryptedContent.data == NULL || encInfo->encryptedContent.dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    // Create decryption context
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx((CRYPT_CIPHER_AlgId)encInfo->contentEncryAlg);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL);
        return HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL;
    }
    // Extract IV (from algParams)
    uint8_t *iv = NULL;
    uint32_t ivLen = 0;
    if (encInfo->algParams.data != NULL && encInfo->algParams.dataLen > 0) {
        iv = encInfo->algParams.data;
        ivLen = encInfo->algParams.dataLen;
    }
    // Decrypt content
    int32_t ret = DecryptContentCore(ctx, cek, cekLen, iv, ivLen, encInfo, plaintext);
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

static int32_t CMS_DecryptEnvData(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CMS_EnvelopedData *envData,
    const BSL_Param *param, BSL_Buffer *plaintext)
{
    (void)libCtx;
    (void)attrName;
    if (envData->recipientInfos == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    // Try to decrypt symmetric key (CEK) using provided credentials
    ClearEnvDataKey(envData);
    int32_t ret = CMS_DecryptCekForRecipient(envData->recipientInfos, param,
        &envData->key.data, &envData->key.dataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = DecryptContent(&envData->encryptedContentInfo, envData->key.data, envData->key.dataLen, plaintext);
    ClearEnvDataKey(envData);
    return ret;
}

/**
 * EnvelopedData ::= SEQUENCE {
 *      version CMSVersion,
 *      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *      recipientInfos RecipientInfos,
 *      encryptedContentInfo EncryptedContentInfo,
 *      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 */
static BSL_ASN1_TemplateItem g_envDataTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        /* version (INTEGER) */
        {BSL_ASN1_TAG_INTEGER, 0, 1},
        /* originatorInfo [0] OPTIONAL (SEQUENCE) */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
        /* recipientInfos (SET OF RecipientInfo) */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, BSL_ASN1_FLAG_HEADERONLY, 1},
        /* encryptedContentInfo (SEQUENCE) */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        /* unprotectedAttrs [1] IMPLICIT OPTIONAL (SET OF Attribute) */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
};

typedef enum {
    HITLS_CMS_ENVDATA_VERSION_IDX = 0,
    HITLS_CMS_ENVDATA_ORIGINATORINFO_IDX = 1,
    HITLS_CMS_ENVDATA_RECIPIENTINFOS_IDX = 2,
    HITLS_CMS_ENVDATA_ENCRYPTEDCONTENTINFO_IDX = 3,
    HITLS_CMS_ENVDATA_UNPROTECTEDATTRS_IDX = 4,
    HITLS_CMS_ENVDATA_MAX_IDX = 5,
} HITLS_CMS_ENVDATA_IDX;

/**
 *  EncryptedContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
 */
static BSL_ASN1_TemplateItem g_encryptedContentInfoTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 1},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | 0, BSL_ASN1_FLAG_OPTIONAL, 0},
};

typedef enum {
    HITLS_CMS_ENCRYCONTENTINFO_CONTENTTYPE_IDX = 0,
    HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_OID_IDX = 1,
    HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX = 2,
    HITLS_CMS_ENCRYCONTENTINFO_ENCRYPTEDCONTENT_IDX = 3,
    HITLS_CMS_ENCRYCONTENTINFO_MAX_IDX = 4,
} HITLS_CMS_ENCRYCONTENTINFO_IDX;

static int32_t EncryContentInfoTagGet(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void)idx;
    if (type == BSL_ASN1_TYPE_GET_ANY_TAG) {
        BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *)data;
        BslCid cid = BSL_OBJ_GetCidFromOidBuff(param->buff, param->len);
        if (cid == BSL_CID_UNKNOWN) {
            return HITLS_X509_ERR_GET_ANY_TAG;
        }
        uint32_t ivLen = 0;
        int32_t ret = CRYPT_EAL_CipherGetInfo((CRYPT_CIPHER_AlgId)cid, CRYPT_INFO_IV_LEN, &ivLen);
        if (ret == CRYPT_SUCCESS) {
            *(uint8_t *)expVal = BSL_ASN1_TAG_OCTETSTRING;
        } else {
            *(uint8_t *)expVal = BSL_ASN1_TAG_NULL;
        }
        return BSL_SUCCESS;
    }
    return HITLS_CMS_ERR_PARSE_TYPE;
}

static int32_t ParseContentType(BSL_ASN1_Buffer *asnArr, CMS_EncryptedContentInfo *item)
{
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTTYPE_IDX].buff,
                                           asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTTYPE_IDX].len);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
    item->contentType = cid;
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseEncryptionAlgAndParams(BSL_ASN1_Buffer *asnArr, CMS_EncryptedContentInfo *item)
{
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_OID_IDX].buff,
                                           asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_OID_IDX].len);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
    item->contentEncryAlg = cid;

    item->algParams.data = asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX].buff;
    item->algParams.dataLen = asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX].len;
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseEncryptedContentInfo(BSL_ASN1_Buffer *asn, CMS_EncryptedContentInfo *item)
{
    uint8_t *temp = asn->buff;
    uint32_t tempLen = asn->len;
    BSL_ASN1_Buffer asnArr[HITLS_CMS_ENCRYCONTENTINFO_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_encryptedContentInfoTempl,
        sizeof(g_encryptedContentInfoTempl) / sizeof(g_encryptedContentInfoTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, EncryContentInfoTagGet, &temp,
                                          &tempLen, asnArr, HITLS_CMS_ENCRYCONTENTINFO_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ParseContentType(asnArr, item);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ParseEncryptionAlgAndParams(asnArr, item);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    item->encryptedContent.data = asnArr[HITLS_CMS_ENCRYCONTENTINFO_ENCRYPTEDCONTENT_IDX].buff;
    item->encryptedContent.dataLen = asnArr[HITLS_CMS_ENCRYCONTENTINFO_ENCRYPTEDCONTENT_IDX].len;
    return HITLS_PKI_SUCCESS;
}

// Parse EnvelopedData fields from decoded ASN.1 buffers
static int32_t ParseEnvData(BSL_ASN1_Buffer *asnArr, CMS_EnvelopedData *envData)
{
    // parse version
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_CMS_ENVDATA_VERSION_IDX], &envData->version);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // parse originatorInfo (optional)
    if (asnArr[HITLS_CMS_ENVDATA_ORIGINATORINFO_IDX].tag != BSL_ASN1_TAG_EMPTY) {
        envData->originatorInfo = BSL_SAL_Calloc(1, sizeof(CMS_OriginatorInfo));
        if (envData->originatorInfo == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        ret = CMS_ParseOriginatorInfo(&asnArr[HITLS_CMS_ENVDATA_ORIGINATORINFO_IDX], envData->originatorInfo);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    // parse recipientInfos
    ret = CMS_ParseRecipientList(&asnArr[HITLS_CMS_ENVDATA_RECIPIENTINFOS_IDX], envData->recipientInfos);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // parse encryptedContentInfo
    ret = ParseEncryptedContentInfo(&asnArr[HITLS_CMS_ENVDATA_ENCRYPTEDCONTENTINFO_IDX],
                                    &envData->encryptedContentInfo);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    // parse unprotectedAttrs (optional)
    if (asnArr[HITLS_CMS_ENVDATA_UNPROTECTEDATTRS_IDX].tag != BSL_ASN1_TAG_EMPTY) {
        envData->unprotectedAttrs = HITLS_X509_AttrsNew();
        if (envData->unprotectedAttrs == NULL) {
            ret = BSL_MALLOC_FAIL;
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = HITLS_X509_ParseAttrList(&asnArr[HITLS_CMS_ENVDATA_UNPROTECTEDATTRS_IDX],
                                       envData->unprotectedAttrs, NULL, NULL);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    envData->flag |= HITLS_CMS_FLAG_PARSE;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeContentEncryAlg(BslCid cid, BSL_Buffer *param, BSL_ASN1_Buffer *encode)
{
    BslOidString *oidStr = BSL_OBJ_GetOID(cid);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BSL_ASN1_Buffer asnArr[2] = {0};
    asnArr[0].buff = (uint8_t *)oidStr->octs;
    asnArr[0].len = oidStr->octetLen;
    asnArr[0].tag = BSL_ASN1_TAG_OBJECT_ID;

    uint32_t ivLen = 0;
    int32_t ret = CRYPT_EAL_CipherGetInfo((CRYPT_CIPHER_AlgId)cid, CRYPT_INFO_IV_LEN, &ivLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (param != NULL) {
        if (param->dataLen != ivLen) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        asnArr[1].buff = param->data;
        asnArr[1].len = param->dataLen;
        asnArr[1].tag = BSL_ASN1_TAG_OCTETSTRING;
    } else {
        asnArr[1].buff = NULL;
        asnArr[1].len = 0;
        asnArr[1].tag = BSL_ASN1_TAG_ANY;
    }

    BSL_ASN1_TemplateItem algTempl[] = {
        {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
    };
    BSL_ASN1_Template templ = {algTempl, sizeof(algTempl) / sizeof(algTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 2, &(encode->buff), &(encode->len)); // 2: number of items
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encode->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeEncryContentInfo(CMS_EncryptedContentInfo *item, BSL_ASN1_Buffer *encode)
{
    // content type
    BslOidString *oidStr = BSL_OBJ_GetOID(item->contentType);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    // content encryption algorithm
    BSL_ASN1_Buffer algEncode = {0};
    int32_t ret = EncodeContentEncryAlg(item->contentEncryAlg, &item->algParams, &algEncode);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // encryptedContent is optional
    BSL_ASN1_Buffer asnArr[3] = {0}; // 3: number of items in EncryptedContentInfo
    asnArr[0] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_OBJECT_ID, oidStr->octetLen, (uint8_t *)oidStr->octs};
    asnArr[1] = algEncode;
    if (item->encryptedContent.data != NULL && item->encryptedContent.dataLen > 0) {
        asnArr[2] = (BSL_ASN1_Buffer){BSL_ASN1_CLASS_CTX_SPECIFIC | 0, item->encryptedContent.dataLen,
                                      item->encryptedContent.data};
    } else {
        asnArr[2] = (BSL_ASN1_Buffer){BSL_ASN1_CLASS_CTX_SPECIFIC | 0, 0, NULL};
    }
    BSL_ASN1_TemplateItem encryContentInfoTempl[] = {
        {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | 0, BSL_ASN1_FLAG_OPTIONAL, 0},
    };
    BSL_ASN1_Template templ = {encryContentInfoTempl, sizeof(encryContentInfoTempl) / sizeof(encryContentInfoTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 3, &(encode->buff), &(encode->len)); // 3: number of items in asnArr
    BSL_SAL_FREE(algEncode.buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    encode->tag = BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED;
    return ret;
}

static int32_t PrepareOriginatorInfo(CMS_EnvelopedData *envData, BSL_ASN1_Buffer *originatorInfo)
{
    if (envData->originatorInfo != NULL) {
        if ((BSL_LIST_COUNT(envData->originatorInfo->certs) > 0) ||
            (BSL_LIST_COUNT(envData->originatorInfo->crls) > 0)) {
            return CMS_EncodeOriginatorInfo(envData->originatorInfo, originatorInfo);
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t PrepareUnprotectedAttrs(CMS_EnvelopedData *envData, BSL_ASN1_Buffer *unproAttrs)
{
    if (envData->unprotectedAttrs != NULL) {
        if (BSL_LIST_COUNT(envData->unprotectedAttrs->list) > 0) {
            uint8_t unproAttrsTag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1;
            return HITLS_X509_EncodeAttrList(unproAttrsTag, envData->unprotectedAttrs, NULL, unproAttrs);
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CMS_GenEnvDataBuffAsn1(CMS_EnvelopedData *envData, BSL_Buffer *envBuff)
{
    if ((envData == NULL) || (envBuff == NULL)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t ret;
    BSL_ASN1_Buffer originatorInfo = {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0, 0, NULL};
    BSL_ASN1_Buffer recipientInfos = {0};
    BSL_ASN1_Buffer encryptedContentInfo = {0};
    BSL_ASN1_Buffer unproAttrs = {0};
    // originator (optional)
    ret = PrepareOriginatorInfo(envData, &originatorInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // recipient infos
    ret = CMS_EncodeRecipientList(envData->recipientInfos, &recipientInfos);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    // encrypted content info
    ret = EncodeEncryContentInfo(&envData->encryptedContentInfo, &encryptedContentInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    // unprotected attrs (optional)
    ret = PrepareUnprotectedAttrs(envData, &unproAttrs);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    uint8_t ver = (uint8_t)envData->version;
    BSL_ASN1_Template templ = {g_envDataTempl, sizeof(g_envDataTempl) / sizeof(g_envDataTempl[0])};
    BSL_ASN1_Buffer asnArr[HITLS_CMS_ENVDATA_MAX_IDX] = {
        {BSL_ASN1_TAG_INTEGER, 1, &ver}, // version
        originatorInfo, // originator info
        recipientInfos, // recipient infos
        encryptedContentInfo, // encrypted content info
        unproAttrs,
    };
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_CMS_ENVDATA_MAX_IDX, &envBuff->data, &envBuff->dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BSL_SAL_Free(originatorInfo.buff);
    BSL_SAL_Free(recipientInfos.buff);
    BSL_SAL_Free(encryptedContentInfo.buff);
    BSL_SAL_Free(unproAttrs.buff);
    return ret;
}

// Helper function: Extract encryption parameters from BSL_Param
static int32_t ExtractContentEncryptParams(const BSL_Param *param, BslCid *contentType, BslCid *encAlg)
{
    if (param == NULL) {
        return HITLS_PKI_SUCCESS;
    }

    const BSL_Param *p = BSL_PARAM_FindConstParam(param, HITLS_CMS_PARAM_CONTENT_TYPE);
    if (p != NULL) {
        if (p->valueType != BSL_PARAM_TYPE_INT32 || p->valueLen != sizeof(int32_t)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        *contentType = *(BslCid *)p->value;
    }

    p = BSL_PARAM_FindConstParam(param, HITLS_CMS_PARAM_CONTENT_ENC_ALG);
    if (p != NULL) {
        if (p->valueType != BSL_PARAM_TYPE_INT32 || p->valueLen != sizeof(int32_t)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        *encAlg = *(BslCid *)p->value;
    }
    return HITLS_PKI_SUCCESS;
}

// Unified API: Encrypt data using EnvelopedData (one-shot operation)
int32_t HITLS_CMS_DataEncrypt(HITLS_CMS *cms, const BSL_Buffer *plaintext, const BSL_Param *optionalParam)
{
    if (cms == NULL || cms->ctx.envelopedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (cms->dataType != BSL_CID_PKCS7_ENVELOPEDDATA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    CMS_EnvelopedData *envData = cms->ctx.envelopedData;
    if (envData->state == HITLS_CMS_ENCRYPT_INIT) {
        return CMS_AddRecipientAndWrapCek(envData->recipientInfos, &envData->key, optionalParam);
    }
    if (envData->state != HITLS_CMS_UNINIT || (envData->flag & HITLS_CMS_FLAG_PARSE) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    bool hasRecipient = (BSL_LIST_COUNT(envData->recipientInfos) > 0)? true : false;
    if (!hasRecipient && plaintext == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    // Extract parameters
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
    BslCid encAlg = BSL_CID_AES256_CBC; // Default algorithm
    int32_t ret = ExtractContentEncryptParams(optionalParam, &contentType, &encAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Generate cek
    if (!hasRecipient) {
        ret = GenerateCek(envData->libCtx, encAlg, &envData->key.data, &envData->key.dataLen);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    ret = CMS_AddRecipientAndWrapCek(envData->recipientInfos, &envData->key, optionalParam);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    // Call internal GenerateEnvelopedData
    if (!hasRecipient) {
        ret = CMS_GenerateEnvData(envData->libCtx, envData->attrName, plaintext, contentType, encAlg, envData);
    } else {
        ret = GetEnvDataVersion(envData);
    }
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    return HITLS_PKI_SUCCESS;
ERR:
    ClearEnvDataKey(envData);
    return ret;
}

// Unified API: Decrypt EnvelopedData (one-shot operation)
int32_t HITLS_CMS_DataDecrypt(HITLS_CMS *cms, const BSL_Param *param, BSL_Buffer *plaintext)
{
    if (cms == NULL || cms->ctx.envelopedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (cms->dataType != BSL_CID_PKCS7_ENVELOPEDDATA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    CMS_EnvelopedData *envData = cms->ctx.envelopedData;
    if (envData->state != HITLS_CMS_UNINIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    if (plaintext == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    // Call internal DecryptEnvelopedData
    return CMS_DecryptEnvData(envData->libCtx, envData->attrName, envData, param, plaintext);
}

// Wrapper function: Parse EnvelopedData from buffer
int32_t HITLS_CMS_ParseEnvelopedData(HITLS_PKI_LibCtx *libCtx, const char *attrName, const BSL_Buffer *encode,
    HITLS_CMS **cms)
{
    if (encode == NULL || encode->data == NULL || cms == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (encode->dataLen == 0 || *cms != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }

    HITLS_CMS *ctx = HITLS_CMS_ProviderNew(libCtx, attrName, BSL_CID_PKCS7_ENVELOPEDDATA);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ctx->ctx.envelopedData->flag |= HITLS_CMS_FLAG_PARSE;
    ctx->ctx.envelopedData->initData = BSL_SAL_Dump(encode->data, encode->dataLen);
    if (ctx->ctx.envelopedData->initData == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        HITLS_CMS_Free(ctx);
        return BSL_DUMP_FAIL;
    }

    uint8_t *temp = ctx->ctx.envelopedData->initData;
    uint32_t tempLen = encode->dataLen;
    BSL_ASN1_Buffer asnArr[HITLS_CMS_ENVDATA_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_envDataTempl, sizeof(g_envDataTempl) / sizeof(g_envDataTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_CMS_ENVDATA_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_CMS_Free(ctx);
        return ret;
    }
    ret = ParseEnvData(asnArr, ctx->ctx.envelopedData);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_CMS_Free(ctx);
        return ret;
    }
    *cms = ctx;
    return HITLS_PKI_SUCCESS;
}

// Wrapper function: Generate EnvelopedData buffer
int32_t HITLS_CMS_GenEnvelopedDataBuff(int32_t format, HITLS_CMS *cms, BSL_Buffer *encode)
{
    if (cms == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    if (cms->dataType != BSL_CID_PKCS7_ENVELOPEDDATA || cms->ctx.envelopedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return CMS_GenEnvDataBuffAsn1(cms->ctx.envelopedData, encode);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
            return HITLS_CMS_ERR_INVALID_FORMAT;
    }
}

static int32_t SetEncryCtx(CMS_EnvelopedData *envData, BslCid encAlg)
{
    int32_t ret;
    // Create cipher context
    envData->streamCipherCtx = CRYPT_EAL_CipherNewCtx((CRYPT_CIPHER_AlgId)encAlg);
    if (envData->streamCipherCtx == NULL) {
        ret = HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR_1;
    }
    // Generate IV
    uint32_t ivLen = 0;
    uint8_t *iv = NULL;
    ret = GenerateAndEncodeCipherAlgIV(envData->libCtx, encAlg, &iv, &ivLen, &envData->encryptedContentInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR_2;
    }
    // Initialize cipher context
    ret = CRYPT_EAL_CipherInit(envData->streamCipherCtx, envData->key.data, envData->key.dataLen, iv, ivLen, true);
    BSL_SAL_Free(iv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR_2;
    }
    // Set padding (PKCS7)
    ret = CRYPT_EAL_CipherSetPadding(envData->streamCipherCtx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR_2;
    }
    return HITLS_PKI_SUCCESS;
ERR_2:
    CRYPT_EAL_CipherFreeCtx(envData->streamCipherCtx);
    envData->streamCipherCtx = NULL;
ERR_1:
    ClearEnvDataKey(envData);
    return ret;
}

// Streaming API: Initialize encryption
static int32_t EnvelopedData_EncryptInit(HITLS_CMS *cms, const BSL_Param *param)
{
    if (cms == NULL || cms->ctx.envelopedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CMS_EnvelopedData *envData = cms->ctx.envelopedData;
    if ((envData->flag & HITLS_CMS_FLAG_PARSE) != 0 || envData->state != HITLS_CMS_UNINIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    // Extract content encryption algorithm and content type
    BslCid contentType = BSL_CID_PKCS7_SIMPLEDATA;
    BslCid encAlg = BSL_CID_AES256_CBC;
    int32_t ret = ExtractContentEncryptParams(param, &contentType, &encAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Generate content encryption Key (CEK)
    ret = GenerateCek(envData->libCtx, encAlg, &envData->key.data, &envData->key.dataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Set encryption context
    ret = SetEncryCtx(envData, encAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Set content type and encryption algorithm
    envData->encryptedContentInfo.contentType = contentType;
    envData->encryptedContentInfo.contentEncryAlg = encAlg;
    envData->state = HITLS_CMS_ENCRYPT_INIT;
    return HITLS_PKI_SUCCESS;
}

// Streaming API: Update encryption
static int32_t EnvelopedData_EncryptUpdate(HITLS_CMS *cms, const BSL_Buffer *plaintext, BSL_Buffer *ciphertext)
{
    if (cms == NULL || plaintext == NULL || ciphertext == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (ciphertext->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CMS_EnvelopedData *envData = cms->ctx.envelopedData;
    if (envData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (envData->state != HITLS_CMS_ENCRYPT_INIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    if (envData->streamCipherCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_CTX_IS_NOT_INIT);
        return HITLS_CMS_ERR_CTX_IS_NOT_INIT;
    }
    uint32_t blockSize = 0;
    int32_t ret = CRYPT_EAL_CipherCtrl(envData->streamCipherCtx, CRYPT_CTRL_GET_BLOCKSIZE,
        &blockSize, sizeof(blockSize));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (plaintext->dataLen > UINT32_MAX - blockSize) {
        BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_LEN_OVERFLOW);
        return BSL_ASN1_ERR_LEN_OVERFLOW;
    }
    uint32_t maxOutLen = plaintext->dataLen + blockSize;
    if (ciphertext->dataLen < maxOutLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
    }
    uint32_t outLen = ciphertext->dataLen;
    ret = CRYPT_EAL_CipherUpdate(envData->streamCipherCtx, plaintext->data, plaintext->dataLen,
                                 ciphertext->data, &outLen);
    if (ret != CRYPT_SUCCESS) {
        ciphertext->dataLen = 0;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ciphertext->dataLen = outLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t FinalizeEncry(CMS_EnvelopedData *envData, BSL_Buffer *ciphertext)
{
    if (ciphertext == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (ciphertext->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    uint32_t blockSize = 0;
    int32_t ret = CRYPT_EAL_CipherCtrl(envData->streamCipherCtx, CRYPT_CTRL_GET_BLOCKSIZE,
        &blockSize, sizeof(blockSize));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ciphertext->dataLen < blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
    }
    uint32_t outLen = ciphertext->dataLen;
    ret = CRYPT_EAL_CipherFinal(envData->streamCipherCtx, ciphertext->data, &outLen);
    if (ret != CRYPT_SUCCESS) {
        ciphertext->dataLen = 0;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ciphertext->dataLen = outLen;

    return HITLS_PKI_SUCCESS;
}

static void CleanupStreamCtx(CMS_EnvelopedData *envData)
{
    // Clean up temporary key
    ClearEnvDataKey(envData);

    // Free cipher context
    CRYPT_EAL_CipherFreeCtx(envData->streamCipherCtx);
    envData->streamCipherCtx = NULL;
}

// Streaming API: Finalize encryption
static int32_t EnvelopedData_EncryptFinal(HITLS_CMS *cms, const BSL_Param *param, BSL_Buffer *ciphertext)
{
    (void)param;
    if (cms == NULL || cms->ctx.envelopedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CMS_EnvelopedData *envData = cms->ctx.envelopedData;
    if (envData->state != HITLS_CMS_ENCRYPT_INIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    if (envData->streamCipherCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_CTX_IS_NOT_INIT);
        return HITLS_CMS_ERR_CTX_IS_NOT_INIT;
    }
    int32_t ret = CMS_CheckRecipientsNotEmpty(envData->recipientInfos);
    if (ret != HITLS_PKI_SUCCESS) {
        goto CLEANUP;
    }
    // Finalize encryption
    ret = FinalizeEncry(envData, ciphertext);
    if (ret != HITLS_PKI_SUCCESS) {
        goto CLEANUP;
    }

    // Determine version
    ret = GetEnvDataVersion(envData);
    if (ret != HITLS_PKI_SUCCESS) {
        goto CLEANUP;
    }
CLEANUP:
    // Free stream context
    CleanupStreamCtx(envData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    envData->state = HITLS_CMS_ENCRYPT_FINISHED;
    envData->flag |= HITLS_CMS_FLAG_GEN;
    return HITLS_PKI_SUCCESS;
}

static int32_t SetDecryCtx(CMS_EnvelopedData *envData)
{
    if (envData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (envData->streamCipherCtx != NULL) {
        CRYPT_EAL_CipherFreeCtx(envData->streamCipherCtx);
        envData->streamCipherCtx = NULL;
    }
    // Create cipher context for decryption
    envData->streamCipherCtx = CRYPT_EAL_CipherNewCtx(
        (CRYPT_CIPHER_AlgId)envData->encryptedContentInfo.contentEncryAlg);
    if (envData->streamCipherCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL);
        return HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL;
    }
    // Extract IV from algorithm parameters
    uint8_t *iv = NULL;
    uint32_t ivLen = 0;
    int32_t ret;
    if (envData->encryptedContentInfo.algParams.data != NULL && envData->encryptedContentInfo.algParams.dataLen > 0) {
        iv = envData->encryptedContentInfo.algParams.data;
        ivLen = envData->encryptedContentInfo.algParams.dataLen;
    }
    // Initialize cipher for decryption
    ret = CRYPT_EAL_CipherInit(envData->streamCipherCtx, envData->key.data, envData->key.dataLen, iv, ivLen, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Set padding (PKCS7)
    ret = CRYPT_EAL_CipherSetPadding(envData->streamCipherCtx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    return HITLS_PKI_SUCCESS;
ERR:
    CRYPT_EAL_CipherFreeCtx(envData->streamCipherCtx);
    envData->streamCipherCtx = NULL;
    return ret;
}

// Streaming API: Initialize decryption
static int32_t EnvelopedData_DecryptInit(HITLS_CMS *cms, const BSL_Param *param)
{
    if (cms == NULL || cms->ctx.envelopedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    CMS_EnvelopedData *envData = cms->ctx.envelopedData;
    if (envData->state != HITLS_CMS_UNINIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    uint8_t *cek = NULL;
    uint32_t cekLen = 0;
    int32_t ret = CMS_DecryptCekForRecipient(envData->recipientInfos, param, &cek, &cekLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ClearEnvDataKey(envData);
    envData->key.data = cek;
    envData->key.dataLen = cekLen;
    ret = SetDecryCtx(envData);
    if (ret != HITLS_PKI_SUCCESS) {
        ClearEnvDataKey(envData);
        return ret;
    }
    envData->state = HITLS_CMS_DECRYPT_INIT;
    return HITLS_PKI_SUCCESS;
}

// Streaming API: Update decryption
static int32_t EnvelopedData_DecryptUpdate(HITLS_CMS *cms, const BSL_Buffer *ciphertext, BSL_Buffer *plaintext)
{
    if (cms == NULL || ciphertext == NULL || plaintext == NULL || plaintext->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    CMS_EnvelopedData *envData = cms->ctx.envelopedData;
    if (envData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (envData->state != HITLS_CMS_DECRYPT_INIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    if (envData->streamCipherCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_CTX_IS_NOT_INIT);
        return HITLS_CMS_ERR_CTX_IS_NOT_INIT;
    }
    uint32_t blockSize = 0;
    int32_t ret = CRYPT_EAL_CipherCtrl(envData->streamCipherCtx, CRYPT_CTRL_GET_BLOCKSIZE,
        &blockSize, sizeof(blockSize));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ciphertext->dataLen > UINT32_MAX - blockSize) {
        BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_LEN_OVERFLOW);
        return BSL_ASN1_ERR_LEN_OVERFLOW;
    }
    uint32_t maxOutLen = ciphertext->dataLen + blockSize;
    if (plaintext->dataLen < maxOutLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
    }
    uint32_t outLen = plaintext->dataLen;
    ret = CRYPT_EAL_CipherUpdate(envData->streamCipherCtx, ciphertext->data, ciphertext->dataLen,
                                 plaintext->data, &outLen);
    if (ret != CRYPT_SUCCESS) {
        plaintext->dataLen = 0;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    plaintext->dataLen = outLen;
    return HITLS_PKI_SUCCESS;
}

// Streaming API: Finalize decryption
static int32_t EnvelopedData_DecryptFinal(HITLS_CMS *cms, const BSL_Param *param, BSL_Buffer *plaintext)
{
    (void)param;
    if (cms == NULL || cms->ctx.envelopedData == NULL || plaintext == NULL || plaintext->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CMS_EnvelopedData *envData = cms->ctx.envelopedData;
    if (envData->state != HITLS_CMS_DECRYPT_INIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    if (envData->streamCipherCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_CTX_IS_NOT_INIT);
        return HITLS_CMS_ERR_CTX_IS_NOT_INIT;
    }
    uint32_t blockSize = 0;
    int32_t ret = CRYPT_EAL_CipherCtrl(envData->streamCipherCtx, CRYPT_CTRL_GET_BLOCKSIZE,
        &blockSize, sizeof(blockSize));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto CLEANUP;
    }
    if (plaintext->dataLen < blockSize) {
        ret = CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
        BSL_ERR_PUSH_ERROR(ret);
        goto CLEANUP;
    }
    uint32_t outLen = plaintext->dataLen;
    ret = CRYPT_EAL_CipherFinal(envData->streamCipherCtx, plaintext->data, &outLen);
    if (ret != CRYPT_SUCCESS) {
        plaintext->dataLen = 0;
        BSL_ERR_PUSH_ERROR(ret);
        goto CLEANUP;
    }
    plaintext->dataLen = outLen;
CLEANUP:
    CleanupStreamCtx(envData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    envData->state = HITLS_CMS_DECRYPT_FINISHED;
    return HITLS_PKI_SUCCESS;
}

// Main dispatcher: Initialize streaming operation for EnvelopedData
int32_t HITLS_CMS_EnvelopedDataInit(HITLS_CMS *cms, int32_t option, const BSL_Param *param)
{
    if (option == HITLS_CMS_OPT_ENCRYPT) {
        return EnvelopedData_EncryptInit(cms, param);
    } else if (option == HITLS_CMS_OPT_DECRYPT) {
        return EnvelopedData_DecryptInit(cms, param);
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
    return HITLS_CMS_ERR_INVALID_STATE;
}

// Main dispatcher: Update streaming operation for EnvelopedData
int32_t HITLS_CMS_EnvelopedDataUpdate(HITLS_CMS *cms, const BSL_Buffer *input, BSL_Buffer *output)
{
    if (cms == NULL || cms->ctx.envelopedData == NULL || input == NULL || output == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    CMS_EnvelopedData *envData = cms->ctx.envelopedData;
    if (envData->state == HITLS_CMS_ENCRYPT_INIT) {
        return EnvelopedData_EncryptUpdate(cms, input, output);
    } else if (envData->state == HITLS_CMS_DECRYPT_INIT) {
        return EnvelopedData_DecryptUpdate(cms, input, output);
    }

    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
    return HITLS_CMS_ERR_INVALID_STATE;
}

// Main dispatcher: Finalize streaming operation for EnvelopedData
int32_t HITLS_CMS_EnvelopedDataFinal(HITLS_CMS *cms, const BSL_Param *param, BSL_Buffer *output)
{
    if (cms == NULL || cms->ctx.envelopedData == NULL || output == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CMS_EnvelopedData *envData = cms->ctx.envelopedData;
    if (envData->state == HITLS_CMS_ENCRYPT_INIT) {
        return EnvelopedData_EncryptFinal(cms, param, output);
    } else if (envData->state == HITLS_CMS_DECRYPT_INIT) {
        return EnvelopedData_DecryptFinal(cms, param, output);
    }

    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
    return HITLS_CMS_ERR_INVALID_STATE;
}

// Main control function for EnvelopedData
int32_t HITLS_CMS_EnvelopedDataCtrl(HITLS_CMS *cms, int32_t cmd, void *val, uint32_t valLen)
{
    (void)valLen;
    (void)val;
    if (cms == NULL || cms->ctx.envelopedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    switch (cmd) {
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
    }
}
#endif // HITLS_PKI_CMS_ENVELOPEDDATA
