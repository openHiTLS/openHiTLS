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
#if defined(HITLS_PKI_CMS_ENVELOPEDDATA) || defined(HITLS_PKI_CMS_AUTHENTICATEDDATA)
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_asn1_internal.h"
#include "bsl_obj_internal.h"
#include "crypt_errno.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_codecskey.h"
#include "crypt_params_key.h"
#include "hitls_cms_local.h"
#include "hitls_cms_recipient.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_params.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_x509.h"

/**
 *  OriginatorInfo ::= SEQUENCE {
 *      certs [0] IMPLICIT CertificateSet OPTIONAL,
 *      crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
 */
static BSL_ASN1_TemplateItem g_originatorInfoTempl[] = {
    /* certificates [0] IMPLICIT OPTIONAL (SET OF) - capture headeronly to retrieve raw encoding */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
    /* crls [1] IMPLICIT OPTIONAL (SET OF) - capture headeronly to retrieve raw encoding */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
};

typedef enum {
    HITLS_CMS_ORIGINATORINFO_CERTS_IDX = 0,
    HITLS_CMS_ORIGINATORINFO_CRLS_IDX = 1,
    HITLS_CMS_ORIGINATORINFO_MAX_IDX = 2,
} HITLS_CMS_ORIGINATORINFO_IDX;

int32_t CMS_ParseOriginatorInfo(BSL_ASN1_Buffer *asn, CMS_OriginatorInfo *orig)
{
    if (asn->tag == 0 || asn->buff == NULL || asn->len == 0) {
        return HITLS_PKI_SUCCESS;
    }

    uint8_t *temp = asn->buff;
    uint32_t tempLen = asn->len;
    BSL_ASN1_Buffer asnArr[HITLS_CMS_ORIGINATORINFO_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_originatorInfoTempl, sizeof(g_originatorInfoTempl) / sizeof(g_originatorInfoTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_CMS_ORIGINATORINFO_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (asnArr[HITLS_CMS_ORIGINATORINFO_CERTS_IDX].len > 0) {
        BSL_Buffer certBuf = {asnArr[HITLS_CMS_ORIGINATORINFO_CERTS_IDX].buff,
                              asnArr[HITLS_CMS_ORIGINATORINFO_CERTS_IDX].len};
        ret = HITLS_X509_CertParseBundleBuff(BSL_FORMAT_ASN1, &certBuf, &orig->certs);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    if (asnArr[HITLS_CMS_ORIGINATORINFO_CRLS_IDX].len > 0) {
        BSL_Buffer crlBuf = {asnArr[HITLS_CMS_ORIGINATORINFO_CRLS_IDX].buff,
                             asnArr[HITLS_CMS_ORIGINATORINFO_CRLS_IDX].len};
        return HITLS_X509_CrlParseBundleBuff(BSL_FORMAT_ASN1, &crlBuf, &orig->crls);
    }
    return HITLS_PKI_SUCCESS;
}

int32_t CMS_EncodeOriginatorInfo(CMS_OriginatorInfo *originator, BSL_ASN1_Buffer *encode)
{
    BSL_ASN1_Buffer certsBuff = {0};
    BSL_ASN1_Buffer crlsBuff = {0};
    // certs
    int32_t ret = EncodeCertList(originator->certs, &certsBuff);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    // crls
    ret = EncodeCrlList(originator->crls, &crlsBuff);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    BSL_ASN1_Buffer asnArr[HITLS_CMS_ORIGINATORINFO_MAX_IDX] = {
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0, certsBuff.len, certsBuff.buff},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1, crlsBuff.len, crlsBuff.buff},
    };
    BSL_ASN1_Template templ = {g_originatorInfoTempl, sizeof(g_originatorInfoTempl) / sizeof(g_originatorInfoTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 2, &encode->buff, &encode->len); // 2: number of items in asnArr
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

EXIT:
    BSL_SAL_Free(certsBuff.buff);
    BSL_SAL_Free(crlsBuff.buff);
    return ret;
}

bool CMS_OriginatorInfoIsEmpty(const CMS_OriginatorInfo *originatorInfo)
{
    if (originatorInfo == NULL) {
        return true;
    }

    bool hasCerts = (originatorInfo->certs != NULL && BSL_LIST_COUNT(originatorInfo->certs) > 0);
    bool hasCrls = (originatorInfo->crls != NULL && BSL_LIST_COUNT(originatorInfo->crls) > 0);
    return !hasCerts && !hasCrls;
}

void CMS_OriginatorInfoFree(CMS_OriginatorInfo *originatorInfo)
{
    if (originatorInfo == NULL) {
        return;
    }
    BSL_LIST_FREE(originatorInfo->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(originatorInfo->crls, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    BSL_SAL_Free(originatorInfo);
}

typedef int32_t (*CMS_RecipientInitFunc)(CMS_RecipientInfo *recip, uint32_t flag);
typedef void (*CMS_RecipientFreeFunc)(CMS_RecipientInfo *recip);
typedef int32_t (*CMS_RecipientDecryptFunc)(CMS_RecipientInfo *recip, const BSL_Param *param,
    uint8_t **cek, uint32_t *cekLen);
typedef int32_t (*CMS_RecipientParseFunc)(uint8_t *encode, uint32_t valueLen, CMS_RecipientInfo *recip);
typedef int32_t (*CMS_RecipientEncodeFunc)(CMS_RecipientInfo *recip, BSL_ASN1_Buffer *encode);

typedef struct {
    CMS_RecipientType type;
    CMS_RecipientInitFunc init;
    CMS_RecipientFreeFunc destory;
    CMS_RecipientDecryptFunc decrypt;
    CMS_RecipientParseFunc parse;
    CMS_RecipientEncodeFunc encode;
} CMS_RecipientHandler;

static const CMS_RecipientHandler *GetRecipientHandler(CMS_RecipientType type);

CMS_KeyTransRecipientInfo *CMS_KtriNew(uint32_t flag)
{
    CMS_KeyTransRecipientInfo *ktri = (CMS_KeyTransRecipientInfo *)BSL_SAL_Calloc(1, sizeof(CMS_KeyTransRecipientInfo));
    if (ktri == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    ktri->issuerName = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (ktri->issuerName == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_Free(ktri);
        return NULL;
    }
    ktri->flag |= flag;
    return ktri;
}

CMS_KEMRecipientInfo *CMS_KemriNew(uint32_t flag)
{
    CMS_KEMRecipientInfo *kemri = (CMS_KEMRecipientInfo *)BSL_SAL_Calloc(1, sizeof(CMS_KEMRecipientInfo));
    if (kemri == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    kemri->issuerName = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (kemri->issuerName == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_Free(kemri);
        return NULL;
    }
    kemri->version = 0;
    kemri->flag |= flag;
    return kemri;
}

CMS_RecipientInfo *CMS_RecipientInfoNew(CMS_RecipientType type, uint32_t flag)
{
    CMS_RecipientInfo *recip = BSL_SAL_Calloc(1, sizeof(CMS_RecipientInfo));
    if (recip == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    const CMS_RecipientHandler *handler = GetRecipientHandler(type);
    if (handler == NULL || handler->init == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_RECIPIENT_TYPE);
        goto ERR;
    }
    int32_t ret = handler->init(recip, flag);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    recip->type = type;
    return recip;
ERR:
    BSL_SAL_Free(recip);
    return NULL;
}

void KtriFree(CMS_KeyTransRecipientInfo *ktri)
{
    if (ktri == NULL) {
        return;
    }
    if ((ktri->flag & HITLS_CMS_FLAG_PARSE) == 0) {
        BSL_LIST_FREE(ktri->issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
        BSL_SAL_FREE(ktri->subjectKeyId.kid.data);
        BSL_SAL_FREE(ktri->serialNumber.data);
    } else {
        BSL_LIST_FREE(ktri->issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeParsedNameNode);
    }
    if (ktri->algParams != NULL) {
        if ((ktri->flag & HITLS_CMS_FLAG_PARSE) == 0) {
            BSL_SAL_FREE(ktri->algParams->data);
        }
        BSL_SAL_FREE(ktri->algParams);
    }
    if (ktri->encryptedKey.data != NULL) {
        if ((ktri->flag & HITLS_CMS_FLAG_PARSE) == 0) {
            BSL_SAL_FREE(ktri->encryptedKey.data);
        }
    }
    CRYPT_EAL_PkeyFreeCtx(ktri->pkey);
    BSL_SAL_Free(ktri);
}

static void FreeKemriBuffer(BSL_Buffer **buffer, uint32_t flag)
{
    if (buffer == NULL || *buffer == NULL) {
        return;
    }
    if ((flag & HITLS_CMS_FLAG_PARSE) == 0) {
        BSL_SAL_FREE((*buffer)->data);
    }
    BSL_SAL_FREE(*buffer);
}

static void KemriFree(CMS_KEMRecipientInfo *kemri)
{
    if (kemri == NULL) {
        return;
    }
    if ((kemri->flag & HITLS_CMS_FLAG_PARSE) == 0) {
        BSL_LIST_FREE(kemri->issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
        BSL_SAL_FREE(kemri->subjectKeyId.kid.data);
        BSL_SAL_FREE(kemri->serialNumber.data);
        BSL_SAL_FREE(kemri->kemCiphertext.data);
        BSL_SAL_FREE(kemri->encryptedKey.data);
    } else {
        BSL_LIST_FREE(kemri->issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeParsedNameNode);
    }
    FreeKemriBuffer(&kemri->kemParams, kemri->flag);
    FreeKemriBuffer(&kemri->kdfParams, kemri->flag);
    FreeKemriBuffer(&kemri->ukm, kemri->flag);
    FreeKemriBuffer(&kemri->wrapParams, kemri->flag);
    CRYPT_EAL_PkeyFreeCtx(kemri->pkey);
    BSL_SAL_Free(kemri);
}

void CMS_RecipientInfoFree(CMS_RecipientInfo *recipInfo)
{
    if (recipInfo == NULL) {
        return;
    }

    const CMS_RecipientHandler *handler = GetRecipientHandler(recipInfo->type);
    if (handler == NULL || handler->destory == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        BSL_SAL_Free(recipInfo);
        return;
    }
    handler->destory(recipInfo);
    BSL_SAL_Free(recipInfo);
}

static int32_t GetSubjectKeyIdFromCert(HITLS_X509_Cert *cert, HITLS_X509_ExtSki *subjectKeyId)
{
    HITLS_X509_ExtSki ski = {0};
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Use SubjectKeyIdentifier
    subjectKeyId->kid.data = BSL_SAL_Dump(ski.kid.data, ski.kid.dataLen);
    if (subjectKeyId->kid.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    subjectKeyId->kid.dataLen = ski.kid.dataLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t GetIssuerAndSerialNumFromCert(HITLS_X509_Cert *cert, BSL_ASN1_List **issuerName, BSL_Buffer *serialNum)
{
    BSL_ASN1_List *issuer = NULL;
    BSL_Buffer serialNumber = {0};
    // Get certificate issuer name
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, &issuer, sizeof(BSL_ASN1_List *));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Copy issuer name list
    ret = HITLS_X509_SetNameList(issuerName, issuer, sizeof(BSL_ASN1_List));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Get certificate serial number
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &serialNumber, sizeof(BSL_Buffer));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *data = BSL_SAL_Dump(serialNumber.data, serialNumber.dataLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    serialNum->data = data;
    serialNum->dataLen = serialNumber.dataLen;
    return HITLS_PKI_SUCCESS;
}

static void FreeGeneratedAlgParam(BSL_Buffer **algParam)
{
    if (algParam == NULL || *algParam == NULL) {
        return;
    }
    BSL_SAL_FREE((*algParam)->data);
    BSL_SAL_FREE(*algParam);
}

static int32_t NormalizeRsaOaepParams(CRYPT_RSA_OaepPara *oaepPara, BSL_Buffer *oaepLabel)
{
    const BSL_Buffer emptyLabel = {NULL, 0};

    if (oaepPara == NULL || oaepLabel == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (oaepPara->mdId == 0) {
        oaepPara->mdId = CRYPT_MD_SHA1;
    }
    if (oaepPara->mgfId == 0) {
        oaepPara->mgfId = CRYPT_MD_SHA1;
    }
    if (oaepLabel->data == NULL && oaepLabel->dataLen > 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    if (oaepLabel->data == NULL && oaepLabel->dataLen == 0) {
        *oaepLabel = emptyLabel;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeRsaOaepParams(const CRYPT_RSA_OaepPara *rsaOaepPara,
    const BSL_Buffer *rsaOaepLabel, CMS_KeyTransRecipientInfo *ktri)
{
    if (rsaOaepPara == NULL || rsaOaepLabel == NULL || ktri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    uint8_t *buf = NULL;
    uint32_t bufLen = 0;
    int32_t ret = CRYPT_EAL_EncodeRsaOaepAlgParam(rsaOaepPara, rsaOaepLabel, &buf, &bufLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    FreeGeneratedAlgParam(&ktri->algParams);
    ktri->algParams = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    if (ktri->algParams == NULL) {
        BSL_SAL_Free(buf);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ktri->algParams->data = buf;
    ktri->algParams->dataLen = bufLen;
    ktri->keyEncryAlg = BSL_CID_RSAES_OAEP;
    return HITLS_PKI_SUCCESS;
}

static int32_t ConfigureRsaPkcsv15KeyEncryAlg(CRYPT_EAL_PkeyCtx *pkey)
{
    /* mdId is only passed to satisfy the RSAES-PKCSV15 control interface. */
    int32_t mdId = CRYPT_MD_SHA256;
    int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &mdId, sizeof(mdId));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t ConfigureRsaOaepKeyEncryAlg(CRYPT_EAL_PkeyCtx *pkey, CMS_KeyTransRecipientInfo *ktri)
{
    if (pkey == NULL || ktri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CRYPT_RSA_OaepPara oaepPara = {0};
    BSL_Buffer oaepLabel = {0};
    if (ktri->algParams == NULL || (ktri->algParams->data == NULL && ktri->algParams->dataLen != 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    BSL_ASN1_Buffer oaepParam = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        ktri->algParams->dataLen, ktri->algParams->data};
    int32_t ret = CRYPT_EAL_ParseRsaOaepAlgParam(&oaepParam, &oaepPara, &oaepLabel);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = NormalizeRsaOaepParams(&oaepPara, &oaepLabel);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    BSL_Param oaep[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &oaepPara.mdId, sizeof(oaepPara.mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &oaepPara.mgfId, sizeof(oaepPara.mgfId), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaep, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (oaepLabel.data == NULL && oaepLabel.dataLen == 0) {
        return HITLS_PKI_SUCCESS;
    }
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_OAEP_LABEL, oaepLabel.data, oaepLabel.dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncryptCekForKtri(const uint8_t *cek, uint32_t cekLen, CMS_KeyTransRecipientInfo *ktri)
{
    if (cek == NULL || ktri == NULL || ktri->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CRYPT_EAL_PkeyCtx *pubKey = ktri->pkey;
    uint32_t encKeyLen = CRYPT_EAL_PkeyGetKeyLen(pubKey);
    uint8_t *encKey = BSL_SAL_Malloc(encKeyLen);
    if (encKey == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_PkeyEncrypt(pubKey, cek, cekLen, encKey, &encKeyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(encKey);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_SAL_FREE(ktri->encryptedKey.data);
    ktri->encryptedKey.data = encKey;
    ktri->encryptedKey.dataLen = encKeyLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t GetMlKemParaId(CRYPT_EAL_PkeyCtx *pkey, BslCid *kemAlg)
{
    if (pkey == NULL || kemAlg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t kemParaId = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_PARAID, &kemParaId, sizeof(kemParaId));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (kemParaId != BSL_CID_ML_KEM_512 && kemParaId != BSL_CID_ML_KEM_768 && kemParaId != BSL_CID_ML_KEM_1024) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    *kemAlg = (BslCid)kemParaId;
    return HITLS_PKI_SUCCESS;
}

static int32_t SelectKemriAlgo(BslCid kemAlg, BslCid *kdfAlg, BslCid *wrapAlg, uint32_t *kekLen)
{
    if (kdfAlg == NULL || wrapAlg == NULL || kekLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    /*
     * RFC 9936 Section 2.1 says implementations using ML-KEM in CMS MUST
     * support HKDF with SHA-256 for the KDF field.
     */
    *kdfAlg = BSL_CID_HKDF_SHA256;
    switch (kemAlg) {
        case BSL_CID_ML_KEM_512:
            /*
             * RFC 9936 Section 2.1 requires ML-KEM-512 support for AES-Wrap-128
             * (id-aes128-wrap). The KEK size therefore stays fixed at 16 octets.
             */
            *wrapAlg = BSL_CID_AES128_WRAP_NOPAD;
            *kekLen = 16;
            return HITLS_PKI_SUCCESS;
        case BSL_CID_ML_KEM_768:
        case BSL_CID_ML_KEM_1024:
            /*
             * RFC 9936 Section 2.1 requires ML-KEM-768 / ML-KEM-1024 support
             * for AES-Wrap-256 (id-aes256-wrap). Section 2.2 notes that, for
             * AES Key Wrap, a 256-bit key is typically used for the 192-bit
             * ML-KEM-768 security level as well.
             */
            *wrapAlg = BSL_CID_AES256_WRAP_NOPAD;
            *kekLen = 32;
            return HITLS_PKI_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
            return HITLS_CMS_ERR_INVALID_ALGO;
    }
}

static int32_t WrapKey(BslCid wrapAlg, const uint8_t *kek, uint32_t kekLen, const uint8_t *cek, uint32_t cekLen,
    BSL_Buffer *wrappedKey)
{
    if (kek == NULL || cek == NULL || wrappedKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx((CRYPT_CIPHER_AlgId)wrapAlg);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL);
        return HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL;
    }
    int32_t ret = CRYPT_EAL_CipherInit(ctx, kek, kekLen, NULL, 0, true);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }
    /*
     * RFC 3394 AES Key Wrap adds one 64-bit integrity register (A) in front of
     * the wrapped payload, so the ciphertext length is plaintext length + 8.
     */
    uint8_t *ciphertext = BSL_SAL_Malloc(cekLen + 8);
    if (ciphertext == NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t ciphertextLen = cekLen + 8;
    ret = CRYPT_EAL_CipherUpdate(ctx, cek, cekLen, ciphertext, &ciphertextLen);
    CRYPT_EAL_CipherFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(ciphertext);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    wrappedKey->data = ciphertext;
    wrappedKey->dataLen = ciphertextLen;
    return ret;
}

static int32_t UnwrapKey(BslCid wrapAlg, const uint8_t *kek, uint32_t kekLen, const BSL_Buffer *wrappedKey,
    uint8_t **cek, uint32_t *cekLen)
{
    if (kek == NULL || wrappedKey == NULL || cek == NULL || cekLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    /*
     * For RFC 3394 no-pad AES Key Wrap, the wrapped form is A(8 bytes) || R[1..n].
     * The smallest valid plaintext is one 64-bit block, so the shortest wrapped
     * value is 8 + 8 = 16 bytes.
     */
    if (wrappedKey->data == NULL || wrappedKey->dataLen < 16 || ((wrappedKey->dataLen & 0x7u) != 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx((CRYPT_CIPHER_AlgId)wrapAlg);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL);
        return HITLS_CMS_ERR_ENVELOPEDDATA_CIPHER_FAIL;
    }
    int32_t ret = CRYPT_EAL_CipherInit(ctx, kek, kekLen, NULL, 0, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }
    uint8_t *plaintext = BSL_SAL_Malloc(wrappedKey->dataLen);
    if (plaintext == NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t plaintextLen = wrappedKey->dataLen;
    ret = CRYPT_EAL_CipherUpdate(ctx, wrappedKey->data, wrappedKey->dataLen, plaintext, &plaintextLen);
    CRYPT_EAL_CipherFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(plaintext, wrappedKey->dataLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *cek = plaintext;
    *cekLen = plaintextLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeKeyEncryAlg(BslCid cid, BSL_Buffer *param, BSL_ASN1_Buffer *encode);

static int32_t EncodeKemriOtherInfo(BslCid wrapAlg, BSL_Buffer *wrapParams, uint32_t kekLen, BSL_Buffer *ukm,
    BSL_Buffer *otherInfo)
{
    BSL_ASN1_Buffer wrapAlgId = {0};
    BSL_ASN1_Buffer kekLengthAsn = {0};
    BSL_ASN1_Buffer asnArr[3] = {0};
    BSL_ASN1_TemplateItem templItems[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
            {BSL_ASN1_TAG_INTEGER, 0, 1},
            {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0, BSL_ASN1_FLAG_OPTIONAL, 1},
                {BSL_ASN1_TAG_OCTETSTRING, 0, 2},
    };
    /*
     * RFC 9629 Section 3 defines CMSORIforKEMOtherInfo as:
     *   SEQUENCE { wrap, kekLength, ukm OPTIONAL }
     * The DER encoding of that structure is used as the KDF "info" input,
     * and RFC 9936 reuses the same rule for ML-KEM in CMS.
     */
    int32_t ret = EncodeKeyEncryAlg(wrapAlg, wrapParams, &wrapAlgId);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, (uint64_t)kekLen, &kekLengthAsn);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(wrapAlgId.buff);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asnArr[0] = wrapAlgId;
    asnArr[1] = kekLengthAsn;
    if (ukm != NULL) {
        asnArr[2].tag = BSL_ASN1_TAG_OCTETSTRING;
        asnArr[2].buff = ukm->data;
        asnArr[2].len = ukm->dataLen;
    } else {
        asnArr[2].tag = BSL_ASN1_TAG_EMPTY;
    }
    BSL_ASN1_Template templ = {templItems, sizeof(templItems) / sizeof(templItems[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 3, &otherInfo->data, &otherInfo->dataLen);
    BSL_SAL_Free(wrapAlgId.buff);
    BSL_SAL_Free(kekLengthAsn.buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t DeriveKek(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CMS_KEMRecipientInfo *kemri,
    const uint8_t *sharedSecret, uint32_t sharedSecretLen, uint8_t **kek)
{
    if (kemri == NULL || sharedSecret == NULL || kek == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    BSL_Buffer otherInfo = {0};
    /*
     * RFC 9629 says the KDF output is the KEK used to encrypt the CEK/CAEK.
     * Here the ML-KEM shared secret is the HKDF key input, and the DER-encoded
     * CMSORIforKEMOtherInfo becomes the HKDF info input.
     */
    int32_t ret = EncodeKemriOtherInfo(kemri->wrapAlg, kemri->wrapParams, kemri->kekLen, kemri->ukm, &otherInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_HKDF, attrName);
    if (kdfCtx == NULL) {
        BSL_SAL_Free(otherInfo.data);
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_NOT_SUPPORTED);
        return CRYPT_HKDF_NOT_SUPPORTED;
    }
    /*
     * RFC 9936 Section 2.1: "Implementations MUST support the HMAC-based
     * Key Derivation Function (HKDF) ... with SHA-256" for the KEMRecipientInfo
     * kdf field. HKDF-SHA256 maps to HMAC-SHA256 at the provider KDF interface.
     */
    uint32_t macId = CRYPT_MAC_HMAC_SHA256;
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param params[6] = {
        {CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId), 0},
        {CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode), 0},
        {CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)sharedSecret, sharedSecretLen, 0},
        {CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, otherInfo.data, otherInfo.dataLen, 0},
        BSL_PARAM_END,
    };
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_KdfFreeCtx(kdfCtx);
        BSL_SAL_Free(otherInfo.data);
        return ret;
    }
    uint8_t *tmpKek = BSL_SAL_Malloc(kemri->kekLen);
    if (tmpKek == NULL) {
        CRYPT_EAL_KdfFreeCtx(kdfCtx);
        BSL_SAL_Free(otherInfo.data);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ret = CRYPT_EAL_KdfDerive(kdfCtx, tmpKek, kemri->kekLen);
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    BSL_SAL_Free(otherInfo.data);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(tmpKek, kemri->kekLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *kek = tmpKek;
    return HITLS_PKI_SUCCESS;
}

static int32_t InitKemriEncryptCtx(CMS_KEMRecipientInfo *kemri, CRYPT_EAL_PkeyCtx **pubKey)
{
    if (kemri == NULL || pubKey == NULL || kemri->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    *pubKey = kemri->pkey;
    int32_t ret = GetMlKemParaId(*pubKey, &kemri->kemAlg);
    if (ret == HITLS_PKI_SUCCESS) {
        ret = SelectKemriAlgo(kemri->kemAlg, &kemri->kdfAlg, &kemri->wrapAlg, &kemri->kekLen);
    }
    return ret;
}

static int32_t EncapsulateKemriSecret(CRYPT_EAL_PkeyCtx *pubKey, uint8_t **kemCt, uint32_t *kemCtLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    int32_t ret = CRYPT_EAL_PkeyCtrl(pubKey, CRYPT_CTRL_GET_CIPHERTEXT_LEN, kemCtLen, sizeof(*kemCtLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *kemCt = BSL_SAL_Malloc(*kemCtLen);
    if (*kemCt == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeyEncaps(pubKey, *kemCt, kemCtLen, sharedSecret, sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(*kemCt);
        *kemCt = NULL;
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t AllocKemSharedSecret(CRYPT_EAL_PkeyCtx *pkey, uint8_t **sharedSecret, uint32_t *sharedSecretLen)
{
    if (pkey == NULL || sharedSecret == NULL || sharedSecretLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    *sharedSecret = NULL;
    *sharedSecretLen = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SHARED_KEY_LEN, sharedSecretLen, sizeof(*sharedSecretLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (*sharedSecretLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    *sharedSecret = BSL_SAL_Malloc(*sharedSecretLen);
    if (*sharedSecret == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t EncryptCekForKemri(const uint8_t *cek, uint32_t cekLen, CMS_KEMRecipientInfo *kemri)
{
    if (cek == NULL || kemri == NULL || kemri->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    /*
     * This implementation uses RFC 3394 AES Key Wrap (no padding) for the CEK.
     * RFC 3394 requires the plaintext input to be a multiple of 64 bits and at
     * least one 64-bit block long, hence cekLen must be >= 16 and divisible by 8.
     */
    if (cekLen < 16 || (cekLen & 0x7u) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t ret = InitKemriEncryptCtx(kemri, &pubKey);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    /* EnvelopedData CEK flow: encapsulate -> derive KEK -> AES-KW wrap CEK. */
    uint8_t *kemCt = NULL;
    uint32_t kemCtLen = 0;
    uint8_t *sharedSecret = NULL;
    uint32_t sharedSecretAllocLen = 0;
    ret = AllocKemSharedSecret(pubKey, &sharedSecret, &sharedSecretAllocLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    uint32_t sharedSecretLen = sharedSecretAllocLen;
    ret = EncapsulateKemriSecret(pubKey, &kemCt, &kemCtLen, sharedSecret, &sharedSecretLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_ClearFree(sharedSecret, sharedSecretAllocLen);
        return ret;
    }
    uint8_t *kek = NULL;
    ret = DeriveKek(kemri->libCtx, kemri->attrName, kemri, sharedSecret, sharedSecretLen, &kek);
    BSL_SAL_ClearFree(sharedSecret, sharedSecretAllocLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(kemCt);
        return ret;
    }
    ret = WrapKey(kemri->wrapAlg, kek, kemri->kekLen, cek, cekLen, &kemri->encryptedKey);
    BSL_SAL_ClearFree(kek, kemri->kekLen);
    kemri->kemCiphertext.data = kemCt;
    kemri->kemCiphertext.dataLen = kemCtLen;
    return ret;
}

static bool BufferEquals(const BSL_Buffer *a, const BSL_Buffer *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    if (a->dataLen != b->dataLen) {
        return false;
    }
    return memcmp(a->data, b->data, a->dataLen) == 0;
}

static bool DNListEquals(BSL_ASN1_List *dn1, BSL_ASN1_List *dn2)
{
    if (dn1 == NULL || dn2 == NULL) {
        return false;
    }
    return HITLS_X509_CmpNameNode(dn1, dn2) == 0;
}

static bool MatchRecipientIdByData(BSL_ASN1_List *issuerName, const BSL_Buffer *serialNumber,
    const HITLS_X509_ExtSki *subjectKeyId, bool useSubjectKeyId, HITLS_X509_Cert *cert)
{
    if (!useSubjectKeyId) {
        // Get certificate issuer DN
        BSL_ASN1_List *certIssuer = NULL;
        int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, &certIssuer, sizeof(BSL_ASN1_List *));
        if (ret != HITLS_PKI_SUCCESS || certIssuer == NULL) {
            return false;
        }
        if (!DNListEquals(issuerName, certIssuer)) {
            return false;
        }
        // Get certificate serial number
        BSL_Buffer certSerial = {0};
        ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &certSerial, sizeof(BSL_Buffer));
        if (ret != HITLS_PKI_SUCCESS) {
            return false;
        }
        return BufferEquals(serialNumber, &certSerial);
    } else {
        // Get certificate SubjectKeyIdentifier extension
        HITLS_X509_ExtSki certSki = {0};
        int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &certSki, sizeof(HITLS_X509_ExtSki));
        if (ret != HITLS_PKI_SUCCESS) {
            return false;
        }
        return BufferEquals(&subjectKeyId->kid, &certSki.kid);
    }
}

static bool MatchRecipientId(CMS_RecipientInfo *recip, HITLS_X509_Cert *cert)
{
    if (recip->type == CMS_RECIPIENT_TYPE_KTRI) {
        CMS_KeyTransRecipientInfo *ktri = recip->d.ktri;
        return MatchRecipientIdByData(ktri->issuerName, &ktri->serialNumber, &ktri->subjectKeyId,
            (ktri->version == 2), cert);
    } else {
        CMS_KEMRecipientInfo *kemri = recip->d.kemri;
        return MatchRecipientIdByData(kemri->issuerName, &kemri->serialNumber, &kemri->subjectKeyId,
            kemri->useSki, cert);
    }
}

static int32_t GetInt32Param(const BSL_Param *params, int32_t key, int32_t *value)
{
    const BSL_Param *p = BSL_PARAM_FindConstParam(params, key);
    if (p == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    if (value == NULL || p->value == NULL || p->valueType != BSL_PARAM_TYPE_INT32 ||
        p->valueLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    *value = *(int32_t *)p->value;
    return HITLS_PKI_SUCCESS;
}

static int32_t GetCtxParam(const BSL_Param *params, int32_t key, uint32_t valueLen, void **value)
{
    const BSL_Param *p = BSL_PARAM_FindConstParam(params, key);
    if (p == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    if (value == NULL || p->value == NULL || p->valueType != BSL_PARAM_TYPE_CTX_PTR ||
        p->valueLen != valueLen) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    *value = p->value;
    return HITLS_PKI_SUCCESS;
}

static int32_t GetOctetsParam(const BSL_Param *params, int32_t key, BSL_Buffer *value)
{
    const BSL_Param *p = BSL_PARAM_FindConstParam(params, key);
    if (p == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    if (value == NULL || p->valueType != BSL_PARAM_TYPE_OCTETS || (p->value == NULL && p->valueLen > 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    value->data = p->value;
    value->dataLen = p->valueLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t ExtractRsaOaepParams(const BSL_Param *params, CRYPT_RSA_OaepPara *rsaOaepPara, BSL_Buffer *rsaOaepLabel)
{
    if (rsaOaepPara == NULL || rsaOaepLabel == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    (void)memset(rsaOaepPara, 0, sizeof(*rsaOaepPara));
    (void)memset(rsaOaepLabel, 0, sizeof(*rsaOaepLabel));
    if (params == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    int32_t mdId = 0;
    int32_t mgf1Id = 0;
    int32_t ret = GetInt32Param(params, CRYPT_PARAM_RSA_MD_ID, &mdId);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    rsaOaepPara->mdId = (CRYPT_MD_AlgId)mdId;
    ret = GetInt32Param(params, CRYPT_PARAM_RSA_MGF1_ID, &mgf1Id);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    rsaOaepPara->mgfId = (CRYPT_MD_AlgId)mgf1Id;
    return GetOctetsParam(params, CRYPT_PARAM_RSA_OAEP_LABEL, rsaOaepLabel);
}

static int32_t ConfigKtriDecryptKeyEncryAlg(CRYPT_EAL_PkeyCtx *recipientKey, CMS_KeyTransRecipientInfo *ktri)
{
    int32_t keyType = CRYPT_EAL_PkeyGetId(recipientKey);
    if (keyType != CRYPT_PKEY_RSA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    switch (ktri->keyEncryAlg) {
        case BSL_CID_RSA:
            return ConfigureRsaPkcsv15KeyEncryAlg(recipientKey);
        case BSL_CID_RSAES_OAEP:
            return ConfigureRsaOaepKeyEncryAlg(recipientKey, ktri);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
            return HITLS_CMS_ERR_INVALID_ALGO;
    }
}

static int32_t DecryptCekForKtri(CMS_KeyTransRecipientInfo *ktri, CRYPT_EAL_PkeyCtx *recipientKey,
    HITLS_X509_Cert *recipientCert, uint8_t **cek, uint32_t *cekLen)
{
    if (ktri == NULL || recipientKey == NULL ||recipientCert == NULL || cek == NULL || cekLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    // Set decryption parameters based on key encryption algorithm
    int32_t ret = ConfigKtriDecryptKeyEncryAlg(recipientKey, ktri);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Allocate decryption buffer
    uint32_t tmpCekLen = CRYPT_EAL_PkeyGetKeyLen(recipientKey);
    uint8_t *tmpCek = BSL_SAL_Malloc(tmpCekLen);
    if (tmpCek == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    if (ktri->encryptedKey.data != NULL && ktri->encryptedKey.dataLen > 0) {
        ret = CRYPT_EAL_PkeyDecrypt(recipientKey, ktri->encryptedKey.data,
                                    ktri->encryptedKey.dataLen, tmpCek, &tmpCekLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_ClearFree(tmpCek, tmpCekLen);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else {
        BSL_SAL_ClearFree(tmpCek, tmpCekLen);
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    *cek = tmpCek;
    *cekLen = tmpCekLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t DecryptCekForKemri(CMS_KEMRecipientInfo *kemri, CRYPT_EAL_PkeyCtx *recipientKey,
    HITLS_X509_Cert *recipientCert, uint8_t **cek, uint32_t *cekLen)
{
    if (kemri == NULL || recipientKey == NULL || recipientCert == NULL || cek == NULL || cekLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (kemri->kemCiphertext.data == NULL || kemri->encryptedKey.data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if (!MatchRecipientIdByData(kemri->issuerName, &kemri->serialNumber, &kemri->subjectKeyId,
        kemri->useSki, recipientCert)) {
        return HITLS_CMS_ERR_RECIPIENT_MISMATCH;
    }
    BslCid kemAlg = BSL_CID_UNKNOWN;
    int32_t ret = GetMlKemParaId(recipientKey, &kemAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (kemAlg != kemri->kemAlg) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    uint8_t *sharedSecret = NULL;
    uint32_t sharedSecretAllocLen = 0;
    ret = AllocKemSharedSecret(recipientKey, &sharedSecret, &sharedSecretAllocLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    uint32_t sharedSecretLen = sharedSecretAllocLen;
    ret = CRYPT_EAL_PkeyDecaps(recipientKey, kemri->kemCiphertext.data, kemri->kemCiphertext.dataLen,
        sharedSecret, &sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(sharedSecret, sharedSecretAllocLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *kek = NULL;
    ret = DeriveKek(kemri->libCtx, kemri->attrName, kemri, sharedSecret, sharedSecretLen, &kek);
    BSL_SAL_ClearFree(sharedSecret, sharedSecretAllocLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = UnwrapKey(kemri->wrapAlg, kek, kemri->kekLen, &kemri->encryptedKey, cek, cekLen);
    BSL_SAL_ClearFree(kek, kemri->kekLen);
    return ret;
}

int32_t CMS_DecryptCekForRecipient(CMS_RecipientInfos *recips, const BSL_Param *param, uint8_t **cek, uint32_t *cekLen)
{
    if (recips == NULL || cek == NULL || cekLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    bool found = false;
    CMS_RecipientInfo *recipInfo = BSL_LIST_GET_FIRST(recips);
    // Iterate all RecipientInfos, try to find matching recipient and decrypt CEK
    while (recipInfo != NULL) {
        const CMS_RecipientHandler *handler = GetRecipientHandler(recipInfo->type);
        if (handler == NULL || handler->decrypt == NULL) {
            recipInfo = BSL_LIST_GET_NEXT(recips);
            continue;
        }
        int32_t ret = handler->decrypt(recipInfo, param, cek, cekLen);
        if (ret == HITLS_PKI_SUCCESS) {
            found = true;
            break;
        }
        if (ret == HITLS_CMS_ERR_RECIPIENT_MISMATCH) {
            // RecipientIdentifier mismatch, continue to try next
            recipInfo = BSL_LIST_GET_NEXT(recips);
            continue;
        }
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_RECIPIENT_KEY_DECRYPT_FAIL);
        return HITLS_CMS_ERR_RECIPIENT_KEY_DECRYPT_FAIL;
    }
    // If no matching RecipientInfo found or CEK decryption failed
    if (!found || *cek == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NO_MATCHING_RECIPIENT);
        return HITLS_CMS_ERR_NO_MATCHING_RECIPIENT;
    }
    return HITLS_PKI_SUCCESS;
}

/**
 * RecipientInfo ::= CHOICE {
 *      ktri KeyTransRecipientInfo,
 *      kari [1] KeyAgreeRecipientInfo,
 *      kekri [2] KEKRecipientInfo,
 *      pwri [3] PasswordRecipientinfo,
 *      ori [4] OtherRecipientInfo }
 *
 *  KeyTransRecipientInfo ::= SEQUENCE {
 *      version CMSVersion,  -- always set to 0 or 2
 *      rid RecipientIdentifier,
 *      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *      encryptedKey EncryptedKey }
 */
static BSL_ASN1_TemplateItem g_ktriTempl[] = {
    {BSL_ASN1_TAG_INTEGER, 0, 0}, // version
    {BSL_ASN1_TAG_CHOICE, BSL_ASN1_FLAG_HEADERONLY, 0}, // rid
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, // key encryption algorithm
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
    {BSL_ASN1_TAG_OCTETSTRING, BSL_ASN1_FLAG_HEADERONLY, 0} // encrypted key
};

typedef enum {
    HITLS_CMS_KTRI_VERSION_IDX,
    HITLS_CMS_KTRI_RID_IDX,
    HITLS_CMS_KTRI_KEYENCRYALG_OID_IDX,
    HITLS_CMS_KTRI_KEYENCRYALG_ANY_IDX,
    HITLS_CMS_KTRI_ENCRYPTEDKEY_IDX,
    HITLS_CMS_KTRI_MAX_IDX,
} HITLS_CMS_KTRI_IDX;

#define HITLS_CMS_KTRI_ISSUERANDSERIALNUM_TAG (BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE)
#define HITLS_CMS_KTRI_SUBJECTKEYID_TAG    (BSL_ASN1_CLASS_CTX_SPECIFIC | 0)
static int32_t KtriTagGetOrCheck(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void)idx;
    if (type == BSL_ASN1_TYPE_CHECK_CHOICE_TAG) {
        uint8_t tag = *(uint8_t *)data;
        if ((tag == HITLS_CMS_KTRI_ISSUERANDSERIALNUM_TAG ||
                tag == HITLS_CMS_KTRI_SUBJECTKEYID_TAG)) {
            *(uint8_t *)expVal = tag;
            return BSL_SUCCESS;
        }
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
    if (type == BSL_ASN1_TYPE_GET_ANY_TAG) {
        BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *)data;
        BslCid cid = BSL_OBJ_GetCidFromOidBuff(param->buff, param->len);
        if (cid == BSL_CID_UNKNOWN) {
            return HITLS_X509_ERR_GET_ANY_TAG;
        }
        if (cid == BSL_CID_RSA) {
            *(uint8_t *)expVal = BSL_ASN1_TAG_NULL;
        } else if (cid == BSL_CID_RSAES_OAEP) {
            *(uint8_t *)expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
        } else {
            *(uint8_t *)expVal = BSL_ASN1_TAG_NULL;
        }
        return BSL_SUCCESS;
    }
    return HITLS_CMS_ERR_PARSE_TYPE;
}

static int32_t ParseKtriRid(BSL_ASN1_Buffer *asn, BSL_ASN1_List *issuerName, BSL_Buffer *serialNumber,
    HITLS_X509_ExtSki *subjectKeyId)
{
    /* rid (RecipientIdentifier) in KTRI is a CHOICE, check the tag to determine which option */
    if (asn->tag == HITLS_CMS_KTRI_ISSUERANDSERIALNUM_TAG) {
        uint8_t *temp = asn->buff;
        uint32_t tempLen = asn->len;
        BSL_ASN1_Buffer asnArr[2] = {0};
        /* IssuerAndSerialNumber template - for parsing issuerAndSerialNumber CHOICE */
        BSL_ASN1_TemplateItem issuerAndSerialNumTempl[] = {
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0}, // issuer
            {BSL_ASN1_TAG_INTEGER, 0, 0}, // serial number
        };
        BSL_ASN1_Template templ = {issuerAndSerialNumTempl,
            sizeof(issuerAndSerialNumTempl) / sizeof(issuerAndSerialNumTempl[0])};
        int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, 2);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        // Parse issuer
        ret = HITLS_X509_ParseNameList(&asnArr[0], issuerName);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        // Parse serial number
        serialNumber->data = asnArr[1].buff;
        serialNumber->dataLen = asnArr[1].len;
        return HITLS_PKI_SUCCESS;
    } else if (asn->tag == HITLS_CMS_KTRI_SUBJECTKEYID_TAG) {
        subjectKeyId->kid.data = asn->buff;
        subjectKeyId->kid.dataLen = asn->len;
        return HITLS_PKI_SUCCESS;
    } else {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
}

static int32_t ParseKeyEncryAlg(BSL_ASN1_Buffer *algId, BSL_ASN1_Buffer *algParam, BslCid *keyEncryAlg,
    BSL_Buffer **keyEncryAlgParams)
{
    if (algId == NULL || keyEncryAlg == NULL || keyEncryAlgParams == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    *keyEncryAlgParams = NULL;
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(algId->buff, algId->len);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }

    *keyEncryAlg = cid;
    switch (cid) {
        case BSL_CID_RSA:
            /*
             * RFC 8017: when rsaEncryption appears in AlgorithmIdentifier,
             * the parameters field MUST be present and MUST be NULL.
             */
            if (algParam == NULL || algParam->tag != BSL_ASN1_TAG_NULL || algParam->len != 0) {
                BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
                return HITLS_CMS_ERR_PARSE_TYPE;
            }
            break;
        case BSL_CID_RSAES_OAEP:
            /*
             * RFC 8017: when id-RSAES-OAEP appears in AlgorithmIdentifier,
             * the parameters field MUST be present and MUST be of type
             * RSAES-OAEP-params.
             */
            if (algParam == NULL || algParam->tag != (BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE)) {
                BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
                return HITLS_CMS_ERR_PARSE_TYPE;
            }
            *keyEncryAlgParams = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
            if (*keyEncryAlgParams == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                return BSL_MALLOC_FAIL;
            }
            (*keyEncryAlgParams)->data = algParam->buff;
            (*keyEncryAlgParams)->dataLen = algParam->len;
            break;
        case BSL_CID_ML_KEM_512:
        case BSL_CID_ML_KEM_768:
        case BSL_CID_ML_KEM_1024:
        case BSL_CID_HKDF_SHA256:
        case BSL_CID_AES128_WRAP_NOPAD:
        case BSL_CID_AES256_WRAP_NOPAD:
            if (algParam != NULL && algParam->tag != BSL_ASN1_TAG_EMPTY && algParam->len != 0) {
                BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
                return HITLS_CMS_ERR_PARSE_TYPE;
            }
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
            return HITLS_CMS_ERR_INVALID_ALGO;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseKtri(uint8_t *encode, uint32_t len, CMS_KeyTransRecipientInfo *ktri)
{
    uint8_t *temp = encode;
    uint32_t tempLen = len;
    BSL_ASN1_Buffer asnArr[HITLS_CMS_KTRI_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_ktriTempl, sizeof(g_ktriTempl) / sizeof(g_ktriTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, KtriTagGetOrCheck, &temp, &tempLen, asnArr, HITLS_CMS_KTRI_MAX_IDX);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Parse version
    ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_CMS_KTRI_VERSION_IDX], &ktri->version);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Parse rid
    ret = ParseKtriRid(&asnArr[HITLS_CMS_KTRI_RID_IDX], ktri->issuerName, &ktri->serialNumber, &ktri->subjectKeyId);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Parse key encryption algorithm
    ret = ParseKeyEncryAlg(&asnArr[HITLS_CMS_KTRI_KEYENCRYALG_OID_IDX],
        &asnArr[HITLS_CMS_KTRI_KEYENCRYALG_ANY_IDX], &ktri->keyEncryAlg, &ktri->algParams);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Parse encrypted key
    ktri->encryptedKey.data = asnArr[HITLS_CMS_KTRI_ENCRYPTEDKEY_IDX].buff;
    ktri->encryptedKey.dataLen = asnArr[HITLS_CMS_KTRI_ENCRYPTEDKEY_IDX].len;
    ktri->flag |= HITLS_CMS_FLAG_PARSE;
    return ret;
}

static int32_t OriTagGet(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void)idx;
    if (type == BSL_ASN1_TYPE_GET_ANY_TAG) {
        BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *)data;
        BslCid cid = BSL_OBJ_GetCidFromOidBuff(param->buff, param->len);
        if (cid == BSL_CID_UNKNOWN) {
            return HITLS_X509_ERR_GET_ANY_TAG;
        }
        if (cid == BSL_CID_CMS_ORI_KEM) {
            *(uint8_t *)expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
        } else {
            *(uint8_t *)expVal = BSL_ASN1_TAG_NULL;
        }
        return BSL_SUCCESS;
    }
    return HITLS_CMS_ERR_PARSE_TYPE;
}

static int32_t ParseOriHeader(uint8_t *encode, uint32_t len, BslCid *oriType, BSL_ASN1_Buffer *oriValue)
{
    if (encode == NULL || oriType == NULL || oriValue == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    BSL_ASN1_TemplateItem oriTempl[] = {
        {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_HEADERONLY, 0},
    };
    /* RFC 9629 carries KEMRecipientInfo inside ori[4] using id-ori-kem. */
    BSL_ASN1_Template templ = {oriTempl, sizeof(oriTempl) / sizeof(oriTempl[0])};
    BSL_ASN1_Buffer asnArr[2] = {0};
    uint8_t *temp = encode;
    uint32_t tempLen = len;
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, OriTagGet, &temp, &tempLen, asnArr, 2);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *oriType = BSL_OBJ_GetCidFromOidBuff(asnArr[0].buff, asnArr[0].len);
    if (*oriType == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
    *oriValue = asnArr[1];
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseKemriRid(BSL_ASN1_Buffer *asn, CMS_KEMRecipientInfo *kemri)
{
    int32_t ret = ParseKtriRid(asn, kemri->issuerName, &kemri->serialNumber, &kemri->subjectKeyId);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    kemri->useSki = (asn->tag == HITLS_CMS_KTRI_SUBJECTKEYID_TAG) ? true : false;
    return HITLS_PKI_SUCCESS;
}

static BSL_ASN1_TemplateItem g_kemriTempl[] = {
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_CHOICE, BSL_ASN1_FLAG_HEADERONLY, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
    {BSL_ASN1_TAG_OCTETSTRING, BSL_ASN1_FLAG_HEADERONLY, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0, BSL_ASN1_FLAG_OPTIONAL, 0},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
    {BSL_ASN1_TAG_OCTETSTRING, BSL_ASN1_FLAG_HEADERONLY, 0},
};

typedef enum {
    HITLS_CMS_KEMRI_VERSION_IDX = 0,
    HITLS_CMS_KEMRI_RID_IDX = 1,
    HITLS_CMS_KEMRI_KEM_OID_IDX = 2,
    HITLS_CMS_KEMRI_KEM_PARAM_IDX = 3,
    HITLS_CMS_KEMRI_KEMCT_IDX = 4,
    HITLS_CMS_KEMRI_KDF_OID_IDX = 5,
    HITLS_CMS_KEMRI_KDF_PARAM_IDX = 6,
    HITLS_CMS_KEMRI_KEKLENGTH_IDX = 7,
    HITLS_CMS_KEMRI_UKM_IDX = 8,
    HITLS_CMS_KEMRI_WRAP_OID_IDX = 9,
    HITLS_CMS_KEMRI_WRAP_PARAM_IDX = 10,
    HITLS_CMS_KEMRI_ENCRYPTEDKEY_IDX = 11,
    HITLS_CMS_KEMRI_MAX_IDX = 12,
} HITLS_CMS_KEMRI_IDX;

static int32_t DecodeKemriAsn(uint8_t *encode, uint32_t len, BSL_ASN1_Buffer *asnArr)
{
    uint8_t *temp = encode;
    uint32_t tempLen = len;
    BSL_ASN1_Template templ = {g_kemriTempl, sizeof(g_kemriTempl) / sizeof(g_kemriTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, KtriTagGetOrCheck, &temp, &tempLen, asnArr, HITLS_CMS_KEMRI_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t ParseKemriAlgoInfo(BSL_ASN1_Buffer *asnArr, CMS_KEMRecipientInfo *kemri)
{
    int32_t ret = ParseKeyEncryAlg(&asnArr[HITLS_CMS_KEMRI_KEM_OID_IDX], &asnArr[HITLS_CMS_KEMRI_KEM_PARAM_IDX],
        &kemri->kemAlg, &kemri->kemParams);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ParseKeyEncryAlg(&asnArr[HITLS_CMS_KEMRI_KDF_OID_IDX], &asnArr[HITLS_CMS_KEMRI_KDF_PARAM_IDX],
        &kemri->kdfAlg, &kemri->kdfParams);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ParseKeyEncryAlg(&asnArr[HITLS_CMS_KEMRI_WRAP_OID_IDX], &asnArr[HITLS_CMS_KEMRI_WRAP_PARAM_IDX],
        &kemri->wrapAlg, &kemri->wrapParams);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_CMS_KEMRI_KEKLENGTH_IDX], &kemri->kekLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t ValidateKemriAlgoInfo(CMS_KEMRecipientInfo *kemri)
{
    /*
     * Tighten parsing to the RFC 9936 mandatory ML-KEM profile:
     * HKDF-SHA256 is required, and the wrap algorithm / KEK length must match
     * the selected ML-KEM parameter set.
     */
    if (kemri->kdfAlg != BSL_CID_HKDF_SHA256) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BslCid expKdf = BSL_CID_UNKNOWN;
    BslCid expWrap = BSL_CID_UNKNOWN;
    uint32_t expKekLen = 0;
    int32_t ret = SelectKemriAlgo(kemri->kemAlg, &expKdf, &expWrap, &expKekLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (kemri->wrapAlg != expWrap || kemri->kekLen != expKekLen) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t SetKemriParsedBuffers(BSL_ASN1_Buffer *asnArr, CMS_KEMRecipientInfo *kemri)
{
    kemri->kemCiphertext.data = asnArr[HITLS_CMS_KEMRI_KEMCT_IDX].buff;
    kemri->kemCiphertext.dataLen = asnArr[HITLS_CMS_KEMRI_KEMCT_IDX].len;
    kemri->encryptedKey.data = asnArr[HITLS_CMS_KEMRI_ENCRYPTEDKEY_IDX].buff;
    kemri->encryptedKey.dataLen = asnArr[HITLS_CMS_KEMRI_ENCRYPTEDKEY_IDX].len;
    if (asnArr[HITLS_CMS_KEMRI_UKM_IDX].tag == BSL_ASN1_TAG_EMPTY) {
        kemri->flag |= HITLS_CMS_FLAG_PARSE;
        return HITLS_PKI_SUCCESS;
    }
    kemri->ukm = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    if (kemri->ukm == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    kemri->ukm->data = asnArr[HITLS_CMS_KEMRI_UKM_IDX].buff;
    kemri->ukm->dataLen = asnArr[HITLS_CMS_KEMRI_UKM_IDX].len;
    kemri->flag |= HITLS_CMS_FLAG_PARSE;
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseKemri(uint8_t *encode, uint32_t len, CMS_KEMRecipientInfo *kemri)
{
    if (encode == NULL || kemri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    BSL_ASN1_Buffer asnArr[HITLS_CMS_KEMRI_MAX_IDX] = {0};
    int32_t ret = DecodeKemriAsn(encode, len, asnArr);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_CMS_KEMRI_VERSION_IDX], &kemri->version);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (kemri->version != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERSION_INVALID);
        return HITLS_CMS_ERR_VERSION_INVALID;
    }
    ret = ParseKemriRid(&asnArr[HITLS_CMS_KEMRI_RID_IDX], kemri);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ParseKemriAlgoInfo(asnArr, kemri);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ValidateKemriAlgoInfo(kemri);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return SetKemriParsedBuffers(asnArr, kemri);
}

#define HITLS_CMS_RI_KTRI_TAG  (BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE)
#define HITLS_CMS_RI_KARI_TAG  (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1)
#define HITLS_CMS_RI_KEKRI_TAG (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2)
#define HITLS_CMS_RI_PWRI_TAG  (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 3)
#define HITLS_CMS_RI_ORI_TAG   (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 4)

typedef struct {
    uint8_t tag;
    CMS_RecipientType type;
} CMS_RecipientInfoMap;

static const CMS_RecipientInfoMap g_recipInfoMap[] = {
    {HITLS_CMS_RI_KTRI_TAG, CMS_RECIPIENT_TYPE_KTRI}, {HITLS_CMS_RI_KARI_TAG, CMS_RECIPIENT_TYPE_KARI},
    {HITLS_CMS_RI_KEKRI_TAG, CMS_RECIPIENT_TYPE_KEKRI}, {HITLS_CMS_RI_PWRI_TAG, CMS_RECIPIENT_TYPE_PWRI},
    {HITLS_CMS_RI_ORI_TAG, CMS_RECIPIENT_TYPE_ORI},
};

static int32_t ParseRecipientListItem(uint8_t tag, uint8_t *encode, uint32_t valueLen, CMS_RecipientInfos *list)
{
    CMS_RecipientType type = CMS_RECIPIENT_TYPE_KTRI; // default to KTRI, will be updated after tag check
    bool found = false;
    for (uint32_t i = 0; i < sizeof(g_recipInfoMap) / sizeof(g_recipInfoMap[0]); i++) {
        if (tag == g_recipInfoMap[i].tag) {
            type = g_recipInfoMap[i].type;
            found = true;
            break;
        }
    }
    if (!found) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_RECIPIENT_TYPE);
        return HITLS_CMS_ERR_INVALID_RECIPIENT_TYPE;
    }
    int32_t ret = HITLS_PKI_SUCCESS;
    if (tag == HITLS_CMS_RI_ORI_TAG) {
        BslCid oriType = BSL_CID_UNKNOWN;
        BSL_ASN1_Buffer oriValue = {0};
        ret = ParseOriHeader(encode, valueLen, &oriType, &oriValue);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        type = (oriType == BSL_CID_CMS_ORI_KEM) ? CMS_RECIPIENT_TYPE_KEMRI : CMS_RECIPIENT_TYPE_ORI;
    }
    const CMS_RecipientHandler *handler = GetRecipientHandler(type);
    if (handler == NULL || handler->parse == NULL) {
        ret = HITLS_CMS_ERR_INVALID_RECIPIENT_TYPE;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CMS_RecipientInfo *recip = CMS_RecipientInfoNew(type, HITLS_CMS_FLAG_PARSE);
    if (recip == NULL) {
        return BSL_MALLOC_FAIL;
    }
    ret = handler->parse(encode, valueLen, recip);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BSL_LIST_AddElement(list, recip, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    return ret;
ERR:
    CMS_RecipientInfoFree(recip);
    return ret;
}

int32_t CMS_ParseRecipientList(BSL_ASN1_Buffer *recipSet, CMS_RecipientInfos *list)
{
    uint8_t *buff = recipSet->buff;
    uint32_t buffLen = recipSet->len;
    if (buff == NULL || buffLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t ret = HITLS_PKI_SUCCESS;
    uint32_t valueLen;
    uint8_t tag;
    while (buffLen > 0) {
        // tag
        tag = *buff;
        buff++;
        buffLen--;
        // length
        ret = BSL_ASN1_DecodeLen(&buff, &buffLen, false, &valueLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        if (valueLen == 0) {
            continue;
        }
        // value
        ret = ParseRecipientListItem(tag, buff, valueLen, list);
        if (ret != BSL_SUCCESS) {
            break;
        }
        buff += valueLen;
        buffLen -= valueLen;
    }
    return ret;
}

static int32_t EncodeKtriRid(CMS_KeyTransRecipientInfo *ktri, BSL_ASN1_Buffer *rid)
{
    // Determine which CHOICE to encode based on available data
    if (ktri->version == 2) {
        if (ktri->subjectKeyId.kid.data == NULL || ktri->subjectKeyId.kid.dataLen == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
            return HITLS_CMS_ERR_INVALID_DATA;
        }
        // Encode subjectKeyIdentifier: [0] IMPLICIT OCTET STRING
        uint32_t totalLen = ktri->subjectKeyId.kid.dataLen;
        uint8_t *encoded = BSL_SAL_Malloc(totalLen);
        if (encoded == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        memcpy(encoded, ktri->subjectKeyId.kid.data, totalLen);
        rid->buff = encoded;
        rid->len = totalLen;
        rid->tag = HITLS_CMS_KTRI_SUBJECTKEYID_TAG;
        return HITLS_PKI_SUCCESS;
    }
    if (ktri->version == 0) {
        // Encode issuerAndSerialNumber: SEQUENCE (issuerName, certSerialNum)
        BSL_ASN1_Buffer name = {0};
        int32_t ret = HITLS_X509_EncodeNameList(ktri->issuerName, &name);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        BSL_ASN1_Buffer asnArr[2] = {
            name,
            {BSL_ASN1_TAG_INTEGER, ktri->serialNumber.dataLen, ktri->serialNumber.data},
        };

        BSL_ASN1_TemplateItem templItems[] = {
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0}, // issuer
            {BSL_ASN1_TAG_INTEGER, 0, 0}, // serial number
        };
        BSL_ASN1_Template templ = {templItems, sizeof(templItems) / sizeof(templItems[0])};
        ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 2, &rid->buff, &rid->len); // 2: number of items in asnArr
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
        BSL_SAL_Free(name.buff);
        rid->tag = HITLS_CMS_KTRI_ISSUERANDSERIALNUM_TAG;
        return ret;
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERSION_INVALID);
    return HITLS_CMS_ERR_VERSION_INVALID;
}

static int32_t SetKeyEncryAlgParam(BslCid cid, BSL_Buffer *param, BSL_ASN1_Buffer *algParam)
{
    algParam->buff = NULL;
    algParam->len = 0;
    switch (cid) {
        case BSL_CID_RSA:
            if (param != NULL && (param->data != NULL || param->dataLen != 0)) {
                BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
                return HITLS_CMS_ERR_INVALID_PARAM;
            }
            algParam->tag = BSL_ASN1_TAG_NULL;
            break;
        case BSL_CID_RSAES_OAEP:
            /*
             * RFC 8017 requires id-RSAES-OAEP parameters to be present and
             * encoded as RSAES-OAEP-params.
             */
            if (param == NULL || (param->data == NULL && param->dataLen != 0)) {
                BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
                return HITLS_CMS_ERR_INVALID_PARAM;
            }
            algParam->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
            algParam->buff = param->data;
            algParam->len = param->dataLen;
            break;
        case BSL_CID_ML_KEM_512:
        case BSL_CID_ML_KEM_768:
        case BSL_CID_ML_KEM_1024:
        case BSL_CID_HKDF_SHA256:
        case BSL_CID_AES128_WRAP_NOPAD:
        case BSL_CID_AES256_WRAP_NOPAD:
        default:
            algParam->tag = BSL_ASN1_TAG_ANY;
            break;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeKeyEncryAlg(BslCid cid, BSL_Buffer *param, BSL_ASN1_Buffer *encode)
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
    int32_t ret = SetKeyEncryAlgParam(cid, param, &asnArr[1]);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
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

static int32_t EncodeKtri(CMS_KeyTransRecipientInfo *ktri, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_ASN1_Buffer rid = {0};
    BSL_ASN1_Buffer keyEncryAlg = {0};

    // recipient identifier
    ret = EncodeKtriRid(ktri, &rid);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    // key encryption algorithm
    ret = EncodeKeyEncryAlg(ktri->keyEncryAlg, ktri->algParams, &keyEncryAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    uint8_t ver = (uint8_t)ktri->version;
    BSL_ASN1_Buffer asnArr[HITLS_CMS_KTRI_MAX_IDX] = {
        {BSL_ASN1_TAG_INTEGER, 1, &ver},
        rid,
        keyEncryAlg,
        {BSL_ASN1_TAG_OCTETSTRING, ktri->encryptedKey.dataLen, ktri->encryptedKey.data},
    };
    BSL_ASN1_TemplateItem ktriTempl[] = {
        {BSL_ASN1_TAG_INTEGER, 0, 0}, // version
        {BSL_ASN1_TAG_CHOICE, 0, 0}, // rid
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, // key encryption algorithm
        {BSL_ASN1_TAG_OCTETSTRING, 0, 0} // encrypted key
    };
    BSL_ASN1_Template templ = {ktriTempl, sizeof(ktriTempl) / sizeof(ktriTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 4, &(encode->data), &(encode->dataLen)); // 4: number of items
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BSL_SAL_Free(rid.buff);
    BSL_SAL_Free(keyEncryAlg.buff);
    return ret;
}

static int32_t EncodeKemriRid(CMS_KEMRecipientInfo *kemri, BSL_ASN1_Buffer *rid)
{
    if (kemri->useSki) {
        uint8_t *encoded = BSL_SAL_Dump(kemri->subjectKeyId.kid.data, kemri->subjectKeyId.kid.dataLen);
        if (encoded == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        rid->buff = encoded;
        rid->len = kemri->subjectKeyId.kid.dataLen;
        rid->tag = HITLS_CMS_KTRI_SUBJECTKEYID_TAG;
        return HITLS_PKI_SUCCESS;
    }
    BSL_ASN1_Buffer name = {0};
    int32_t ret = HITLS_X509_EncodeNameList(kemri->issuerName, &name);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer asnArr[2] = {
        name,
        {BSL_ASN1_TAG_INTEGER, kemri->serialNumber.dataLen, kemri->serialNumber.data},
    };
    BSL_ASN1_TemplateItem templItems[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
        {BSL_ASN1_TAG_INTEGER, 0, 0},
    };
    BSL_ASN1_Template templ = {templItems, sizeof(templItems) / sizeof(templItems[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 2, &rid->buff, &rid->len);
    BSL_SAL_Free(name.buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    rid->tag = HITLS_CMS_KTRI_ISSUERANDSERIALNUM_TAG;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeKemriAlgFields(CMS_KEMRecipientInfo *kemri, BSL_ASN1_Buffer *rid, BSL_ASN1_Buffer *kemAlg,
    BSL_ASN1_Buffer *kdfAlg, BSL_ASN1_Buffer *wrapAlg, BSL_ASN1_Buffer *kekLengthAsn)
{
    int32_t ret = EncodeKemriRid(kemri, rid);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = EncodeKeyEncryAlg(kemri->kemAlg, kemri->kemParams, kemAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = EncodeKeyEncryAlg(kemri->kdfAlg, kemri->kdfParams, kdfAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = EncodeKeyEncryAlg(kemri->wrapAlg, kemri->wrapParams, wrapAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, (uint64_t)kemri->kekLen, kekLengthAsn);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static void InitKemriEncodeArr(CMS_KEMRecipientInfo *kemri, BSL_ASN1_Buffer *asnArr, BSL_ASN1_Buffer *fullArr)
{
    for (uint32_t i = 0; i < 6; i++) {
        fullArr[i] = asnArr[i];
    }
    if (kemri->ukm != NULL) {
        fullArr[6].tag = BSL_ASN1_TAG_OCTETSTRING;
        fullArr[6].buff = kemri->ukm->data;
        fullArr[6].len = kemri->ukm->dataLen;
    } else {
        fullArr[6].tag = BSL_ASN1_TAG_EMPTY;
    }
    fullArr[7] = asnArr[7];
    fullArr[8].tag = BSL_ASN1_TAG_OCTETSTRING;
    fullArr[8].buff = kemri->encryptedKey.data;
    fullArr[8].len = kemri->encryptedKey.dataLen;
}

static int32_t EncodeKemri(CMS_KEMRecipientInfo *kemri, BSL_Buffer *encode)
{
    if (kemri == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    BSL_ASN1_Buffer rid = {0};
    BSL_ASN1_Buffer kemAlg = {0};
    BSL_ASN1_Buffer kdfAlg = {0};
    BSL_ASN1_Buffer wrapAlg = {0};
    BSL_ASN1_Buffer kekLengthAsn = {0};
    int32_t ret = EncodeKemriAlgFields(kemri, &rid, &kemAlg, &kdfAlg, &wrapAlg, &kekLengthAsn);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    uint8_t ver = (uint8_t)kemri->version;
    BSL_ASN1_Buffer asnArr[8] = {
        {BSL_ASN1_TAG_INTEGER, 1, &ver},
        rid,
        kemAlg,
        {BSL_ASN1_TAG_OCTETSTRING, kemri->kemCiphertext.dataLen, kemri->kemCiphertext.data},
        kdfAlg,
        kekLengthAsn,
        {0},
        wrapAlg,
    };
    BSL_ASN1_TemplateItem templItems[] = {
        {BSL_ASN1_TAG_INTEGER, 0, 0},
        {BSL_ASN1_TAG_CHOICE, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_INTEGER, 0, 0},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0, BSL_ASN1_FLAG_OPTIONAL, 0},
            {BSL_ASN1_TAG_OCTETSTRING, 0, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 0},
    };
    BSL_ASN1_Template templ = {templItems, sizeof(templItems) / sizeof(templItems[0])};
    BSL_ASN1_Buffer fullArr[9] = {0};
    InitKemriEncodeArr(kemri, asnArr, fullArr);
    ret = BSL_ASN1_EncodeTemplate(&templ, fullArr, 9, &encode->data, &encode->dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BSL_SAL_Free(rid.buff);
    BSL_SAL_Free(kemAlg.buff);
    BSL_SAL_Free(kdfAlg.buff);
    BSL_SAL_Free(wrapAlg.buff);
    BSL_SAL_Free(kekLengthAsn.buff);
    return ret;
}

static int32_t EncodeOriForKem(CMS_KEMRecipientInfo *kemri, BSL_ASN1_Buffer *encode)
{
    BSL_Buffer kemInfo = {0};
    int32_t ret = EncodeKemri(kemri, &kemInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    /* Internal KEMRI is emitted as OtherRecipientInfo/id-ori-kem on the wire. */
    BslOidString *oidStr = BSL_OBJ_GetOID(BSL_CID_CMS_ORI_KEM);
    if (oidStr == NULL) {
        BSL_SAL_Free(kemInfo.data);
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BSL_ASN1_TemplateItem templItems[] = {
        {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_HEADERONLY, 0},
    };
    BSL_ASN1_Template templ = {templItems, sizeof(templItems) / sizeof(templItems[0])};
    BSL_ASN1_Buffer asnArr[2] = {
        {BSL_ASN1_TAG_OBJECT_ID, oidStr->octetLen, (uint8_t *)oidStr->octs},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, kemInfo.dataLen, kemInfo.data},
    };
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 2, &encode->buff, &encode->len);
    BSL_SAL_Free(kemInfo.data);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encode->tag = HITLS_CMS_RI_ORI_TAG;
    return HITLS_PKI_SUCCESS;
}

static int32_t InitKeyTransRecipient(CMS_RecipientInfo *recip, uint32_t flag)
{
    if (recip == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    recip->d.ktri = CMS_KtriNew(flag);
    return (recip->d.ktri == NULL) ? BSL_MALLOC_FAIL : HITLS_PKI_SUCCESS;
}

static int32_t InitKEMRecipient(CMS_RecipientInfo *recip, uint32_t flag)
{
    if (recip == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    recip->d.kemri = CMS_KemriNew(flag);
    return (recip->d.kemri == NULL) ? BSL_MALLOC_FAIL : HITLS_PKI_SUCCESS;
}

static void FreeKeyTransRecipient(CMS_RecipientInfo *recip)
{
    if (recip != NULL && recip->d.ktri != NULL) {
        KtriFree(recip->d.ktri);
        recip->d.ktri = NULL;
    }
}

static void FreeKEMRecipient(CMS_RecipientInfo *recip)
{
    if (recip != NULL && recip->d.kemri != NULL) {
        KemriFree(recip->d.kemri);
        recip->d.kemri = NULL;
    }
}

static int32_t DecryptCekForKtriRecipient(CMS_RecipientInfo *recip, const BSL_Param *param,
    uint8_t **cek, uint32_t *cekLen)
{
    if (recip == NULL || recip->d.ktri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *privateKey = NULL;
    // Extract recipient cert
    int32_t ret = GetCtxParam(param, HITLS_CMS_PARAM_RECIPIENT_CERT, sizeof(HITLS_X509_Cert *), (void **)(&cert));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Extract recipient private key
    ret = GetCtxParam(param, HITLS_CMS_PARAM_PRIVATE_KEY, sizeof(CRYPT_EAL_PkeyCtx *), (void **)(&privateKey));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (cert == NULL || !MatchRecipientId(recip, cert)) {
        return HITLS_CMS_ERR_RECIPIENT_MISMATCH;
    }
    if (privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_RECIPIENT_PRIKEY_REQUIRED);
        return HITLS_CMS_ERR_RECIPIENT_PRIKEY_REQUIRED;
    }
    return DecryptCekForKtri(recip->d.ktri, privateKey, cert, cek, cekLen);
}

static int32_t DecryptCekForKEMRecipient(CMS_RecipientInfo *recip, const BSL_Param *param,
    uint8_t **cek, uint32_t *cekLen)
{
    if (recip == NULL || recip->d.kemri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *privateKey = NULL;
    // Extract recipient cert
    int32_t ret = GetCtxParam(param, HITLS_CMS_PARAM_RECIPIENT_CERT, sizeof(HITLS_X509_Cert *), (void **)(&cert));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Extract recipient private key
    ret = GetCtxParam(param, HITLS_CMS_PARAM_PRIVATE_KEY, sizeof(CRYPT_EAL_PkeyCtx *), (void **)(&privateKey));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (cert == NULL || !MatchRecipientId(recip, cert)) {
        return HITLS_CMS_ERR_RECIPIENT_MISMATCH;
    }
    if (privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_RECIPIENT_PRIKEY_REQUIRED);
        return HITLS_CMS_ERR_RECIPIENT_PRIKEY_REQUIRED;
    }
    return DecryptCekForKemri(recip->d.kemri, privateKey, cert, cek, cekLen);
}

static int32_t ParseKtriRecipient(uint8_t *encode, uint32_t valueLen, CMS_RecipientInfo *recip)
{
    if (recip == NULL || recip->d.ktri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    return ParseKtri(encode, valueLen, recip->d.ktri);
}

static int32_t ParseKEMRecipient(uint8_t *encode, uint32_t valueLen, CMS_RecipientInfo *recip)
{
    if (recip == NULL || recip->d.kemri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    BslCid oriType = BSL_CID_UNKNOWN;
    BSL_ASN1_Buffer oriValue = {0};
    int32_t ret = ParseOriHeader(encode, valueLen, &oriType, &oriValue);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return ParseKemri(oriValue.buff, oriValue.len, recip->d.kemri);
}

static int32_t EncodeKtriRecipient(CMS_RecipientInfo *recip, BSL_ASN1_Buffer *encode)
{
    if (recip == NULL || recip->d.ktri == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    BSL_Buffer enc = {0};
    int32_t ret = EncodeKtri(recip->d.ktri, &enc);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    encode->tag = HITLS_CMS_RI_KTRI_TAG;
    encode->buff = enc.data;
    encode->len = enc.dataLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeKEMRecipient(CMS_RecipientInfo *recip, BSL_ASN1_Buffer *encode)
{
    if (recip == NULL || recip->d.kemri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    return EncodeOriForKem(recip->d.kemri, encode);
}

static const CMS_RecipientHandler g_recipHandlers[] = {
    {CMS_RECIPIENT_TYPE_KTRI, InitKeyTransRecipient, FreeKeyTransRecipient, DecryptCekForKtriRecipient,
        ParseKtriRecipient, EncodeKtriRecipient},
    {CMS_RECIPIENT_TYPE_KARI, NULL, NULL, NULL, NULL, NULL},
    {CMS_RECIPIENT_TYPE_KEKRI, NULL, NULL, NULL, NULL, NULL},
    {CMS_RECIPIENT_TYPE_PWRI, NULL, NULL, NULL, NULL, NULL},
    {CMS_RECIPIENT_TYPE_ORI, NULL, NULL, NULL, NULL, NULL},
    {CMS_RECIPIENT_TYPE_KEMRI, InitKEMRecipient, FreeKEMRecipient, DecryptCekForKEMRecipient,
        ParseKEMRecipient, EncodeKEMRecipient},
};

static const CMS_RecipientHandler *GetRecipientHandler(CMS_RecipientType type)
{
    for (uint32_t i = 0; i < sizeof(g_recipHandlers) / sizeof(g_recipHandlers[0]); i++) {
        if (g_recipHandlers[i].type == type) {
            return &g_recipHandlers[i];
        }
    }
    return NULL;
}

static int32_t EncodeRecipientItem(CMS_RecipientInfo *recip, BSL_ASN1_Buffer *encode)
{
    if (recip == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    const CMS_RecipientHandler *handler = GetRecipientHandler(recip->type);
    if (handler == NULL || handler->encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_RECIPIENT_TYPE);
        return HITLS_CMS_ERR_INVALID_RECIPIENT_TYPE;
    }
    return handler->encode(recip, encode);
}

int32_t CMS_EncodeRecipientList(CMS_RecipientInfos *list, BSL_ASN1_Buffer *encode)
{
    uint32_t count = (uint32_t)BSL_LIST_COUNT(list);
    if (count == 0) {
        encode->buff = NULL;
        encode->len = 0;
        encode->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
        return HITLS_PKI_SUCCESS;
    }

    BSL_ASN1_Buffer *asnBuff = BSL_SAL_Calloc(count, sizeof(BSL_ASN1_Buffer));
    if (asnBuff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t iter = 0;
    int32_t ret = HITLS_PKI_SUCCESS;
    for (CMS_RecipientInfo *recip = BSL_LIST_GET_FIRST(list); recip != NULL; recip = BSL_LIST_GET_NEXT(list)) {
        ret = EncodeRecipientItem(recip, &asnBuff[iter]);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        ++iter;
    }
    BSL_ASN1_TemplateItem recipEntryTempl = {BSL_ASN1_TAG_CHOICE, 0, 0};
    BSL_ASN1_Template templ = {&recipEntryTempl, 1};
    ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, count, &templ, asnBuff, iter, encode);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    HITLS_CMS_FreeAsnList(asnBuff, iter);
    return ret;
}

static int32_t CreateKtriRsaAndWrapCek(BSL_Buffer *cek, const BSL_Param *param, CMS_KeyTransRecipientInfo *ktri)
{
    (void)param;
    if (cek == NULL || cek->data == NULL || ktri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (CRYPT_EAL_PkeyGetId(ktri->pkey) != CRYPT_PKEY_RSA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    FreeGeneratedAlgParam(&ktri->algParams);
    ktri->keyEncryAlg = BSL_CID_RSA;
    /* mdId is only passed to satisfy the RSAES-PKCSV15 control interface. */
    int32_t mdId = CRYPT_MD_SHA256;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ktri->pkey, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &mdId, sizeof(mdId));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return EncryptCekForKtri(cek->data, cek->dataLen, ktri);
}

static int32_t CreateKtriRsaOaepAndWrapCek(BSL_Buffer *cek, const BSL_Param *param, CMS_KeyTransRecipientInfo *ktri)
{
    if (cek == NULL || cek->data == NULL || ktri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CRYPT_RSA_OaepPara rsaOaepPara = {0};
    BSL_Buffer rsaOaepLabel = {0};
    int32_t ret = ExtractRsaOaepParams(param, &rsaOaepPara, &rsaOaepLabel);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = NormalizeRsaOaepParams(&rsaOaepPara, &rsaOaepLabel);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = EncodeRsaOaepParams(&rsaOaepPara, &rsaOaepLabel, ktri);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    BSL_Param oaep[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &rsaOaepPara.mdId, sizeof(rsaOaepPara.mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &rsaOaepPara.mgfId, sizeof(rsaOaepPara.mgfId), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeyCtrl(ktri->pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaep, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(ktri->pkey, CRYPT_CTRL_SET_RSA_OAEP_LABEL, rsaOaepLabel.data, rsaOaepLabel.dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return EncryptCekForKtri(cek->data, cek->dataLen, ktri);
}

int32_t ConfigKtriKeyEncAlgAndWrapCek(CMS_KeyTransRecipientInfo *ktri, const BSL_Param *param, BSL_Buffer *cek)
{
    if (cek == NULL || cek->data == NULL || param == NULL || ktri == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t keyEncAlgVal = 0;
    // Extract key encryption algorithm
    int32_t ret = GetInt32Param(param, HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, &keyEncAlgVal);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    BslCid keyEncAlg = (BslCid)keyEncAlgVal;
    switch (keyEncAlg) {
        case BSL_CID_RSA:
            return CreateKtriRsaAndWrapCek(cek, param, ktri);
        case BSL_CID_RSAES_OAEP:
            return CreateKtriRsaOaepAndWrapCek(cek, param, ktri);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
            return HITLS_CMS_ERR_INVALID_ALGO;
    }
}

static int32_t CreateKemriMlKemAndWrapCek(BSL_Buffer *cek, CMS_KEMRecipientInfo *kemri)
{
    if (cek == NULL || cek->data == NULL || kemri == NULL || kemri->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t ret = GetMlKemParaId(kemri->pkey, &kemri->kemAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = SelectKemriAlgo(kemri->kemAlg, &kemri->kdfAlg, &kemri->wrapAlg, &kemri->kekLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return EncryptCekForKemri(cek->data, cek->dataLen, kemri);
}

int32_t ConfigKemriKeyEncAlgAndWrapCek(CMS_KEMRecipientInfo *kemri, const BSL_Param *param, BSL_Buffer *cek)
{
    if (cek == NULL || cek->data == NULL || param == NULL || kemri == NULL || kemri->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    BslCid certKemAlg = BSL_CID_UNKNOWN;
    int32_t ret = GetMlKemParaId(kemri->pkey, &certKemAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    int32_t keyEncAlgVal = 0;
    ret = GetInt32Param(param, HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, &keyEncAlgVal);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (keyEncAlgVal != 0 && (BslCid)keyEncAlgVal != certKemAlg) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    return CreateKemriMlKemAndWrapCek(cek, kemri);
}

static int32_t GetRidFromCert(HITLS_X509_Cert *cert, CMS_RecipientInfo *recipient, bool *useSki)
{
    bool hasSki = false;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_CHECK_SKI, &hasSki, sizeof(bool));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (hasSki) {
        *useSki = true;
        if (recipient->type == CMS_RECIPIENT_TYPE_KTRI) {
            return GetSubjectKeyIdFromCert(cert, &recipient->d.ktri->subjectKeyId);
        } else {
            return GetSubjectKeyIdFromCert(cert, &recipient->d.kemri->subjectKeyId);
        }
    }
    *useSki = false;
    if (recipient->type == CMS_RECIPIENT_TYPE_KTRI) {
        return GetIssuerAndSerialNumFromCert(cert, &recipient->d.ktri->issuerName, &recipient->d.ktri->serialNumber);
    } else {
        return GetIssuerAndSerialNumFromCert(cert, &recipient->d.kemri->issuerName, &recipient->d.kemri->serialNumber);
    }
}

static int32_t CreateKtriAndWrapCek(CMS_RecipientInfo **recipient, const BSL_Param *param, BSL_Buffer *cek)
{
    HITLS_X509_Cert *cert = NULL;
    bool useSki = false;

    if (cek == NULL || cek->data == NULL || recipient == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    *recipient = CMS_RecipientInfoNew(CMS_RECIPIENT_TYPE_KTRI, HITLS_CMS_FLAG_GEN);
    if (*recipient == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = GetCtxParam(param, HITLS_CMS_PARAM_RECIPIENT_CERT, sizeof(HITLS_X509_Cert *), (void **)&cert);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    if (cert == NULL) {
        ret = HITLS_CMS_ERR_RECIPIENT_CERT_REQUIRED;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = GetRidFromCert(cert, *recipient, &useSki);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    (*recipient)->d.ktri->version = useSki ? 2 : 0;

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &(*recipient)->d.ktri->pkey, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = ConfigKtriKeyEncAlgAndWrapCek((*recipient)->d.ktri, param, cek);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    return HITLS_PKI_SUCCESS;
ERR:
    CMS_RecipientInfoFree(*recipient);
    *recipient = NULL;
    return ret;
}

static int32_t CreateKemriAndWrapCek(CMS_RecipientInfo **recipient, const BSL_Param *param, BSL_Buffer *cek)
{
    HITLS_X509_Cert *cert = NULL;
    bool useSki = false;

    if (cek == NULL || cek->data == NULL || recipient == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    *recipient = CMS_RecipientInfoNew(CMS_RECIPIENT_TYPE_KEMRI, HITLS_CMS_FLAG_GEN);
    if (*recipient == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = GetCtxParam(param, HITLS_CMS_PARAM_RECIPIENT_CERT, sizeof(HITLS_X509_Cert *), (void **)&cert);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    if (cert == NULL) {
        ret = HITLS_CMS_ERR_RECIPIENT_CERT_REQUIRED;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = GetRidFromCert(cert, *recipient, &useSki);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    (*recipient)->d.kemri->useSki = useSki;
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &(*recipient)->d.kemri->pkey, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = ConfigKemriKeyEncAlgAndWrapCek((*recipient)->d.kemri, param, cek);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    return HITLS_PKI_SUCCESS;
ERR:
    CMS_RecipientInfoFree(*recipient);
    *recipient = NULL;
    return ret;
}

static int32_t CreateRecipientAndWrapCek(BSL_Buffer *cek, const BSL_Param *param, CMS_RecipientInfo **recipient)
{
    if (recipient == NULL || cek == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t typeVal = 0;
    int32_t ret = GetInt32Param(param, HITLS_CMS_PARAM_RECIPIENT_TYPE, &typeVal);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    HITLS_CMS_RecipientType type = (HITLS_CMS_RecipientType)typeVal;
    switch (type) {
        case HITLS_CMS_RECIPIENT_TYPE_KTRI:
            return CreateKtriAndWrapCek(recipient, param, cek);
        case HITLS_CMS_RECIPIENT_TYPE_KEMRI:
            return CreateKemriAndWrapCek(recipient, param, cek);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_RECIPIENT_TYPE);
            return HITLS_CMS_ERR_INVALID_RECIPIENT_TYPE;
    }
}

int32_t CMS_AddRecipientAndWrapCek(CMS_RecipientInfos *recips, BSL_Buffer *key, const BSL_Param *param)
{
    if (recips == NULL || key == NULL || key->data == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CMS_RecipientInfo *recipient = NULL;
    int32_t ret = CreateRecipientAndWrapCek(key, param, &recipient);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_LIST_AddElement(recips, recipient, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CMS_RecipientInfoFree(recipient);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t CMS_CheckRecipientsNotEmpty(CMS_RecipientInfos *recips)
{
    if (recips == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (BSL_LIST_GET_FIRST(recips) == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    return HITLS_PKI_SUCCESS;
}

#endif // HITLS_CMS_ENVELOPEDDATA || HITLS_CMS_AUTHENTICATEDDATA
