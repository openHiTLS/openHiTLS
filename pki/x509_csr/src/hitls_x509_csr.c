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
#ifdef HITLS_PKI_X509_CSR
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_asn1_internal.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#ifdef HITLS_BSL_PEM
#include "bsl_pem_internal.h"
#endif // HITLS_BSL_PEM
#include "bsl_log_internal.h"
#include "hitls_pki_errno.h"
#include "crypt_codecskey.h"
#include "crypt_errno.h"
#ifdef HITLS_BSL_SAL_FILE
#include "sal_file.h"
#endif
#include "crypt_eal_codecs.h"
#include "hitls_csr_local.h"
#include "hitls_pki_utils.h"
#include "hitls_pki_csr.h"

#define HITLS_CSR_CTX_SPECIFIC_TAG_ATTRIBUTE  0

#define HITLS_X509_CSR_PARSE_FLAG  0x01
#define HITLS_X509_CSR_GEN_FLAG    0x02

#ifdef HITLS_PKI_X509_CSR_PARSE
/**
 * RFC2986: section 4
 * CertificationRequest ::= SEQUENCE {
 *     certificationRequestInfo CertificationRequestInfo,
 *     signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
 *     signature          BIT STRING
 * }
 */
BSL_ASN1_TemplateItem g_csrTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* PKCS10 csr */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* req info */
            /* 2: version */
            {BSL_ASN1_TAG_INTEGER, 0, 2},
            /* 2: subject name */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
            /* 2: public key info */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 2},
            /* 2: attributes */
            {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CSR_CTX_SPECIFIC_TAG_ATTRIBUTE,
             BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* signAlg */
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
            {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 2},
        {BSL_ASN1_TAG_BITSTRING, 0, 1} /* sig */
};

typedef enum {
    HITLS_X509_CSR_REQINFO_VERSION_IDX = 0,
    HITLS_X509_CSR_REQINFO_SUBJECT_NAME_IDX = 1,
    HITLS_X509_CSR_REQINFO_PUBKEY_INFO_IDX = 2,
    HITLS_X509_CSR_REQINFO_ATTRS_IDX = 3,
    HITLS_X509_CSR_SIGNALG_OID_IDX = 4,
    HITLS_X509_CSR_SIGNALG_ANY_IDX = 5,
    HITLS_X509_CSR_SIGN_IDX = 6,
    HITLS_X509_CSR_MAX_IDX = 7,
} HITLS_X509_CSR_IDX;
#endif // HITLS_PKI_X509_CSR_PARSE

HITLS_X509_Csr *HITLS_X509_CsrNew(void)
{
    HITLS_X509_Csr *csr = NULL;
    BSL_ASN1_List *subjectName = NULL;
    HITLS_X509_Attrs *attributes = NULL;
    csr = (HITLS_X509_Csr *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_Csr));
    subjectName = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    attributes = HITLS_X509_AttrsNew();
    if (csr == NULL || subjectName == NULL || attributes == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_Free(subjectName);
        BSL_SAL_Free(csr);
        HITLS_X509_AttrsFree(attributes, NULL);
        return NULL;
    }

    BSL_SAL_ReferencesInit(&(csr->references));
    csr->reqInfo.subjectName = subjectName;
    csr->reqInfo.attributes = attributes;
    csr->state = HITLS_X509_CSR_STATE_NEW;
    return csr;
}

HITLS_X509_Csr *HITLS_X509_ProviderCsrNew(HITLS_PKI_LibCtx *libCtx, const char *attrName)
{
    HITLS_X509_Csr *csr = HITLS_X509_CsrNew();
    if (csr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    csr->libCtx = libCtx;
    csr->attrName = attrName;
    return csr;
}

void HITLS_X509_CsrFree(HITLS_X509_Csr *csr)
{
    if (csr == NULL) {
        return;
    }
    int ret = 0;
    BSL_SAL_AtomicDownReferences(&(csr->references), &ret);
    if (ret > 0) {
        return;
    }
    BSL_SAL_ReferencesFree(&(csr->references));
    if (csr->flag == HITLS_X509_CSR_GEN_FLAG) {
        BSL_LIST_FREE(csr->reqInfo.subjectName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
        BSL_SAL_FREE(csr->reqInfo.reqInfoRawData);
        BSL_SAL_FREE(csr->signature.buff);
    } else {
        BSL_LIST_FREE(csr->reqInfo.subjectName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeParsedNameNode);
    }
#ifdef HITLS_CRYPTO_SM2
    if (csr->signAlgId.algId == BSL_CID_SM2DSAWITHSM3) {
        BSL_SAL_FREE(csr->signAlgId.sm2UserId.data);
        csr->signAlgId.sm2UserId.dataLen = 0;
    }
#endif
    HITLS_X509_AttrsFree(csr->reqInfo.attributes, NULL);
    csr->reqInfo.attributes = NULL;
    BSL_SAL_FREE(csr->rawData);
    CRYPT_EAL_PkeyFreeCtx(csr->reqInfo.ealPubKey);
    csr->reqInfo.ealPubKey = NULL;

    BSL_SAL_FREE(csr);
}

#ifdef HITLS_PKI_X509_CSR_PARSE
int32_t HITLS_X509_CsrTagGetOrCheck(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void)idx;
    if (type == BSL_ASN1_TYPE_GET_ANY_TAG) {
        BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *)data;
        BslCid cid = BSL_OBJ_GetCidFromOidBuff(param->buff, param->len);
        if (cid == BSL_CID_UNKNOWN) {
            return HITLS_X509_ERR_GET_ANY_TAG;
        }
        if (cid == BSL_CID_RSASSAPSS) {
            /* note: any It can be encoded empty or it can be null */
            *(uint8_t *)expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
            return BSL_SUCCESS;
        } else {
            *(uint8_t *)expVal = BSL_ASN1_TAG_NULL; // is null
            return BSL_SUCCESS;
        }
    }

    return HITLS_X509_ERR_INVALID_PARAM;
}

static int32_t ParseCertRequestInfo(BSL_ASN1_Buffer *asnArr, HITLS_X509_Csr *csr)
{
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CSR_REQINFO_VERSION_IDX], &csr->reqInfo.version);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* subject name */
    ret = HITLS_X509_ParseNameList(&asnArr[HITLS_X509_CSR_REQINFO_SUBJECT_NAME_IDX], csr->reqInfo.subjectName);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* public key info */
    BSL_Buffer subPubKeyBuff = {asnArr[HITLS_X509_CSR_REQINFO_PUBKEY_INFO_IDX].buff,
        asnArr[HITLS_X509_CSR_REQINFO_PUBKEY_INFO_IDX].len};
    ret = CRYPT_EAL_ProviderDecodeBuffKey(csr->libCtx, csr->attrName, BSL_CID_UNKNOWN, "ASN1",
        "PUBKEY_SUBKEY_WITHOUT_SEQ", &subPubKeyBuff, NULL, (CRYPT_EAL_PkeyCtx **)&csr->reqInfo.ealPubKey);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    /* attributes */
    ret = HITLS_X509_ParseAttrList(&asnArr[HITLS_X509_CSR_REQINFO_ATTRS_IDX], csr->reqInfo.attributes, NULL, NULL);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    return ret;

ERR:
    if (csr->reqInfo.ealPubKey != NULL) {
        CRYPT_EAL_PkeyFreeCtx(csr->reqInfo.ealPubKey);
        csr->reqInfo.ealPubKey = NULL;
    }
    BSL_LIST_FREE(csr->reqInfo.subjectName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeParsedNameNode);
    return ret;
}

static int32_t X509CsrBuffAsn1Parse(uint8_t *encode, uint32_t encodeLen, HITLS_X509_Csr *csr)
{
    uint8_t *temp = encode;
    uint32_t tempLen = encodeLen;
    // template parse
    BSL_ASN1_Buffer asnArr[HITLS_X509_CSR_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_csrTempl, sizeof(g_csrTempl) / sizeof(g_csrTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, HITLS_X509_CsrTagGetOrCheck,
        &temp, &tempLen, asnArr, HITLS_X509_CSR_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // parse reqInfo raw data
    ret = HITLS_X509_ParseTbsRawData(encode, encodeLen, &csr->reqInfo.reqInfoRawData,
        &csr->reqInfo.reqInfoRawDataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // parse reqInfo
    ret = ParseCertRequestInfo(asnArr, csr);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    // parse sign alg
    ret = HITLS_X509_ParseSignAlgInfo(&asnArr[HITLS_X509_CSR_SIGNALG_OID_IDX],
        &asnArr[HITLS_X509_CSR_SIGNALG_ANY_IDX], &csr->signAlgId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // parse signature
    ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CSR_SIGN_IDX], &csr->signature);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    csr->rawData = encode;
    csr->rawDataLen = encodeLen - tempLen;
    return HITLS_PKI_SUCCESS;
ERR:
    HITLS_X509_AttrsFree(csr->reqInfo.attributes, NULL);
    csr->reqInfo.attributes = NULL;
    BSL_LIST_FREE(csr->reqInfo.subjectName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeParsedNameNode);
    if (csr->reqInfo.ealPubKey != NULL) {
        CRYPT_EAL_PkeyFreeCtx(csr->reqInfo.ealPubKey);
        csr->reqInfo.ealPubKey = NULL;
    }
    return ret;
}

static int32_t X509CsrAsn1Parse(bool isCopy, const BSL_Buffer *encode, HITLS_X509_Csr *csr)
{
    uint8_t *data = encode->data;
    uint32_t dataLen = encode->dataLen;
    if ((csr->flag & HITLS_X509_CSR_GEN_FLAG) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    uint8_t *tmp = NULL;
    if (isCopy) {
        tmp = (uint8_t *)BSL_SAL_Dump(data, dataLen);
        if (tmp == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        data = tmp;
    }
    int32_t ret = X509CsrBuffAsn1Parse(data, dataLen, csr);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(tmp);
        return ret;
    }
    csr->flag |= HITLS_X509_CSR_PARSE_FLAG;
    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_BSL_PEM
static int32_t X509CsrPemParse(const BSL_Buffer *encode, HITLS_X509_Csr *csr)
{
    uint8_t *tmpBuf = encode->data;
    uint32_t tmpBufLen = encode->dataLen;
    BSL_Buffer asn1Buf = {NULL, 0};
    BSL_PEM_Symbol symbol = {BSL_PEM_CERT_REQ_BEGIN_STR, BSL_PEM_CERT_REQ_END_STR};
    int32_t ret = BSL_PEM_DecodePemToAsn1((char **)&tmpBuf, &tmpBufLen, &symbol, &asn1Buf.data,
        &asn1Buf.dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = X509CsrAsn1Parse(false, &asn1Buf, csr);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(asn1Buf.data);
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}
#endif // HITLS_BSL_PEM

int32_t HITLS_X509_CsrParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_Csr **csr)
{
    if (encode == NULL || csr == NULL || *csr != NULL || encode->data == NULL || encode->dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    int32_t ret;
    HITLS_X509_Csr *tempCsr = HITLS_X509_CsrNew();
    if (tempCsr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    switch (format) {
        case BSL_FORMAT_ASN1:
            ret = X509CsrAsn1Parse(true, encode, tempCsr);
            break;
#ifdef HITLS_BSL_PEM
        case BSL_FORMAT_PEM:
            ret = X509CsrPemParse(encode, tempCsr);
            break;
#endif // HITLS_BSL_PEM
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_FORMAT_UNSUPPORT);
            ret = HITLS_X509_ERR_FORMAT_UNSUPPORT;
            break;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_X509_CsrFree(tempCsr);
        return ret;
    }

    *csr = tempCsr;
    return ret;
}

#ifdef HITLS_BSL_SAL_FILE
int32_t HITLS_X509_CsrParseFile(int32_t format, const char *path, HITLS_X509_Csr **csr)
{
    if (path == NULL || csr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_X509_CsrParseBuff(format, &encode, csr);
    BSL_SAL_Free(data);
    return ret;
}
#endif // HITLS_BSL_SAL_FILE

#endif // HITLS_PKI_X509_CSR_PARSE

#ifdef HITLS_PKI_X509_CSR_GEN
static int32_t CheckCsrValid(HITLS_X509_Csr *csr)
{
    if (csr->reqInfo.ealPubKey == NULL) {
        return HITLS_X509_ERR_CSR_INVALID_PUBKEY;
    }
    if (csr->reqInfo.subjectName == NULL || BSL_LIST_COUNT(csr->reqInfo.subjectName) <= 0) {
        return HITLS_X509_ERR_CSR_INVALID_SUBJECT_DN;
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeCsrReqInfoItem(HITLS_X509_ReqInfo *reqInfo, BSL_ASN1_Buffer *subject,
    BSL_ASN1_Buffer *publicKey, BSL_ASN1_Buffer *attributes)
{
    /* encode subject name */
    int32_t ret = HITLS_X509_EncodeNameList(reqInfo->subjectName, subject);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* encode public key */
    BSL_Buffer pub = {0};
    ret = CRYPT_EAL_EncodePubKeyBuffInternal(reqInfo->ealPubKey, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY,
        false, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

#ifdef HITLS_PKI_X509_CSR_ATTR
    /* encode attribute */
    ret = HITLS_X509_EncodeAttrList(
        BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CSR_CTX_SPECIFIC_TAG_ATTRIBUTE,
        reqInfo->attributes, NULL, attributes);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
#else
    attributes->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CSR_CTX_SPECIFIC_TAG_ATTRIBUTE;
#endif // HITLS_PKI_X509_CSR_ATTR

    publicKey->buff = pub.data;
    publicKey->len = pub.dataLen;
    return ret;
ERR:
    BSL_SAL_FREE(subject->buff);
    BSL_SAL_FREE(pub.data);
#ifdef HITLS_PKI_X509_CSR_ATTR
    BSL_SAL_FREE(attributes->buff);
#endif
    return ret;
}

static BSL_ASN1_TemplateItem g_reqInfoTempl[] = {
    /* version */
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    /* subject name */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
    /* public key */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    /* attributes */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CSR_CTX_SPECIFIC_TAG_ATTRIBUTE,
        BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
};

#define HITLS_X509_CSR_REQINFO_SIZE 4

static int32_t EncodeCsrReqInfo(HITLS_X509_ReqInfo *reqInfo, BSL_ASN1_Buffer *reqInfoBuff)
{
    BSL_ASN1_Buffer subject = {0,  0, NULL};
    BSL_ASN1_Buffer publicKey = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL};
    BSL_ASN1_Buffer attributes = {0, 0, NULL};
    int ret = EncodeCsrReqInfoItem(reqInfo, &subject, &publicKey, &attributes);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    uint8_t version = (uint8_t)reqInfo->version;
    BSL_ASN1_Template templ = { g_reqInfoTempl, sizeof(g_reqInfoTempl) / sizeof(g_reqInfoTempl[0]) };
    BSL_ASN1_Buffer reqInfoAsn[HITLS_X509_CSR_REQINFO_SIZE] = {
        {BSL_ASN1_TAG_INTEGER, 1, &version},
        subject,
        publicKey,
        attributes
    };
    ret = BSL_ASN1_EncodeTemplate(&templ, reqInfoAsn, HITLS_X509_CSR_REQINFO_SIZE, &reqInfoBuff->buff,
        &reqInfoBuff->len);
    BSL_SAL_FREE(subject.buff);
    BSL_SAL_FREE(publicKey.buff);
    BSL_SAL_FREE(attributes.buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

BSL_ASN1_TemplateItem g_briefCsrTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* pkcs10 csr */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* reqInfo */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* signAlg */
        {BSL_ASN1_TAG_BITSTRING, 0, 1}                            /* sig */
};

#define HITLS_X509_CSR_BRIEF_SIZE 3

static int32_t X509EncodeAsn1CsrCore(HITLS_X509_Csr *csr)
{
    if (csr->signature.buff == NULL || csr->signature.len == 0 ||
        csr->reqInfo.reqInfoRawData == NULL || csr->reqInfo.reqInfoRawDataLen == 0 ||
        csr->signAlgId.algId == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CSR_NOT_SIGNED);
        return HITLS_X509_ERR_CSR_NOT_SIGNED;
    }

    BSL_ASN1_Buffer asnArr[HITLS_X509_CSR_BRIEF_SIZE] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, csr->reqInfo.reqInfoRawDataLen, csr->reqInfo.reqInfoRawData},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL},
        {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&csr->signature}
    };
    uint32_t valLen = 0;
    int32_t ret = BSL_ASN1_DecodeTagLen(asnArr[0].tag, &asnArr[0].buff, &asnArr[0].len, &valLen); // 0 is reqInfo
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HITLS_X509_EncodeSignAlgInfo(&csr->signAlgId, &asnArr[1]); // 1 is signAlg
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_ASN1_Template csrTempl = { g_briefCsrTempl, sizeof(g_briefCsrTempl) / sizeof(g_briefCsrTempl[0]) };
    ret = BSL_ASN1_EncodeTemplate(&csrTempl, asnArr, HITLS_X509_CSR_BRIEF_SIZE, &csr->rawData, &csr->rawDataLen);
    BSL_SAL_FREE(asnArr[1].buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/**
 * @brief Encode ASN.1 csr
 *
 * @param csr [IN] Pointer to the csr structure
 * @param buff [OUT] Pointer to the buffer.
 *             If NULL, only the ASN.1 csr is encoded.
 *             If non-NULL, the DER encoding content of the csr is stored in buff
 * @return int32_t Return value, 0 means success, other values mean failure
 */
static int32_t X509EncodeAsn1Csr(HITLS_X509_Csr *csr, BSL_Buffer *buff)
{
    int32_t ret;
    if ((csr->flag & HITLS_X509_CSR_GEN_FLAG) != 0) {
        if (csr->state != HITLS_X509_CSR_STATE_SIGN && csr->state != HITLS_X509_CSR_STATE_GEN) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CSR_NOT_SIGNED);
            return HITLS_X509_ERR_CSR_NOT_SIGNED;
        }
        if (csr->state == HITLS_X509_CSR_STATE_SIGN) {
            ret = X509EncodeAsn1CsrCore(csr);
            if (ret != HITLS_PKI_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            csr->state = HITLS_X509_CSR_STATE_GEN;
        }
    }
    if (csr->rawData == NULL || csr->rawDataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CSR_NOT_SIGNED);
        return HITLS_X509_ERR_CSR_NOT_SIGNED;
    }
    if (buff == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    buff->data = BSL_SAL_Dump(csr->rawData, csr->rawDataLen);
    if (buff->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    buff->dataLen = csr->rawDataLen;
    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_BSL_PEM
static int32_t X509EncodePemCsr(HITLS_X509_Csr *csr, BSL_Buffer *buff)
{
    BSL_Buffer asn1 = {0};
    int32_t ret = X509EncodeAsn1Csr(csr, &asn1);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Buffer base64 = {0};
    BSL_PEM_Symbol symbol = {BSL_PEM_CERT_REQ_BEGIN_STR, BSL_PEM_CERT_REQ_END_STR};
    ret = BSL_PEM_EncodeAsn1ToPem(asn1.data, asn1.dataLen, &symbol, (char **)&base64.data, &base64.dataLen);
    BSL_SAL_FREE(asn1.data);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    buff->data = base64.data;
    buff->dataLen = base64.dataLen;
    return HITLS_PKI_SUCCESS;
}
#endif // HITLS_BSL_PEM

int32_t HITLS_X509_CsrGenBuff(int32_t format, HITLS_X509_Csr *csr, BSL_Buffer *buff)
{
    if (csr == NULL || buff == NULL || buff->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return X509EncodeAsn1Csr(csr, buff);
#ifdef HITLS_BSL_PEM
        case BSL_FORMAT_PEM:
            return X509EncodePemCsr(csr, buff);
#endif // HITLS_BSL_PEM
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_FORMAT_UNSUPPORT);
            return HITLS_X509_ERR_FORMAT_UNSUPPORT;
    }
}

#ifdef HITLS_BSL_SAL_FILE
int32_t HITLS_X509_CsrGenFile(int32_t format, HITLS_X509_Csr *csr, const char *path)
{
    if (path == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    BSL_Buffer encode = { NULL, 0};
    int32_t ret = HITLS_X509_CsrGenBuff(format, csr, &encode);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_SAL_WriteFile(path, encode.data, encode.dataLen);
    BSL_SAL_Free(encode.data);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}
#endif // HITLS_BSL_SAL_FILE

#endif // HITLS_PKI_X509_CSR_GEN

#if defined(HITLS_PKI_X509_CSR_ATTR) && defined(HITLS_PKI_X509_CSR_GET)
static int32_t X509GetAttr(HITLS_X509_Attrs *attrs, HITLS_X509_Attrs **val, uint32_t valLen)
{
    if (val == NULL || valLen != sizeof(HITLS_X509_Attrs *)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = attrs;
    return HITLS_PKI_SUCCESS;
}
#endif

static inline void SetCsrGenFlag(HITLS_X509_Csr *csr)
{
    csr->flag |= HITLS_X509_CSR_GEN_FLAG;
    csr->state = HITLS_X509_CSR_STATE_SET;
}

int32_t HITLS_X509_CsrCtrl(HITLS_X509_Csr *csr, int32_t cmd, void *val, uint32_t valLen)
{
    if (csr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    if (((csr->flag & HITLS_X509_CSR_PARSE_FLAG) != 0) && cmd >= HITLS_X509_SET_VERSION &&
        cmd < HITLS_X509_EXT_SET_SKI) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_AFTER_PARSE);
        return HITLS_X509_ERR_SET_AFTER_PARSE;
    }

    switch (cmd) {
        case HITLS_X509_REF_UP:
            return BSL_SAL_AtomicRefUpCtrl(&(csr->references), val, valLen);
#ifdef HITLS_PKI_X509_CSR_GEN
        case HITLS_X509_SET_PUBKEY:
            SetCsrGenFlag(csr);
            return HITLS_X509_SetPkey(&csr->reqInfo.ealPubKey, val);
        case HITLS_X509_ADD_SUBJECT_NAME:
            SetCsrGenFlag(csr);
            return HITLS_X509_AddDnName(csr->reqInfo.subjectName, (HITLS_X509_DN *)val, valLen);
#ifdef HITLS_CRYPTO_SM2
        case HITLS_X509_SET_VFY_SM2_USER_ID:
            if (csr->signAlgId.algId != BSL_CID_SM2DSA && csr->signAlgId.algId != BSL_CID_SM2DSAWITHSM3) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_SIGNALG_NOT_MATCH);
                return HITLS_X509_ERR_VFY_SIGNALG_NOT_MATCH;
            }
            return HITLS_X509_SetSm2UserId(&csr->signAlgId.sm2UserId, val, valLen);
#endif
#endif
#ifdef HITLS_PKI_X509_CSR_GET
        case HITLS_X509_GET_ENCODELEN:
            return HITLS_X509_GetEncodeLen(csr->rawDataLen, val, valLen);
        case HITLS_X509_GET_ENCODE:
            return HITLS_X509_GetEncodeData(csr->rawData, val);
        case HITLS_X509_GET_PUBKEY:
            return HITLS_X509_GetPubKey(csr->reqInfo.ealPubKey, val);
        case HITLS_X509_GET_SIGNALG:
            return HITLS_X509_GetSignAlg(csr->signAlgId.algId, (int32_t *)val, valLen);
        case HITLS_X509_GET_SUBJECT_DN:
            return HITLS_X509_GetList(csr->reqInfo.subjectName, val, valLen);
#ifdef HITLS_PKI_X509_CSR_ATTR
        case HITLS_X509_CSR_GET_ATTRIBUTES:
            return X509GetAttr(csr->reqInfo.attributes, val, valLen);
#endif // HITLS_PKI_X509_CSR_ATTR
#endif // HITLS_PKI_X509_CSR_GET
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

int32_t HITLS_X509_CsrVerify(HITLS_X509_Csr *csr)
{
    if (csr == NULL || csr->reqInfo.ealPubKey == NULL || csr->reqInfo.reqInfoRawData == NULL ||
        csr->signature.buff == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    int32_t ret = HITLS_X509_CheckSignature((const CRYPT_EAL_PkeyCtx *)csr->reqInfo.ealPubKey,
        csr->reqInfo.reqInfoRawData, csr->reqInfo.reqInfoRawDataLen, &csr->signAlgId, &csr->signature);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

#ifdef HITLS_PKI_X509_CSR_GEN
int32_t CsrSignCb(int32_t mdId, CRYPT_EAL_PkeyCtx *prvKey, HITLS_X509_Asn1AlgId *signAlgId,
    HITLS_X509_Csr *csr)
{
    BSL_ASN1_Buffer reqInfoAsn1 = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL};
    BSL_Buffer signBuff = {NULL, 0};

    csr->signAlgId = *signAlgId;
    int32_t ret = CRYPT_EAL_PkeyPairCheck((CRYPT_EAL_PkeyCtx *)csr->reqInfo.ealPubKey, prvKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = EncodeCsrReqInfo(&csr->reqInfo, &reqInfoAsn1);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_SignAsn1Data(prvKey, mdId, &reqInfoAsn1, &signBuff, &csr->signature);
    BSL_SAL_Free(reqInfoAsn1.buff);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    csr->reqInfo.reqInfoRawData = signBuff.data;
    csr->reqInfo.reqInfoRawDataLen = signBuff.dataLen;
    csr->state = HITLS_X509_CSR_STATE_SIGN;
    return ret;
}

int32_t HITLS_X509_CsrSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
    HITLS_X509_Csr *csr)
{
    if (csr == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if ((csr->flag & HITLS_X509_CSR_PARSE_FLAG) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SIGN_AFTER_PARSE);
        return HITLS_X509_ERR_SIGN_AFTER_PARSE;
    }
    if (csr->state == HITLS_X509_CSR_STATE_SIGN || csr->state == HITLS_X509_CSR_STATE_GEN) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t ret = CheckCsrValid(csr);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_SAL_FREE(csr->signature.buff);
    csr->signature.len = 0;
    BSL_SAL_FREE(csr->reqInfo.reqInfoRawData);
    csr->reqInfo.reqInfoRawDataLen = 0;
    BSL_SAL_FREE(csr->rawData);
    csr->rawDataLen = 0;
#ifdef HITLS_CRYPTO_SM2
    if (csr->signAlgId.algId == BSL_CID_SM2DSAWITHSM3) {
        BSL_SAL_FREE(csr->signAlgId.sm2UserId.data);
        csr->signAlgId.sm2UserId.dataLen = 0;
    }
#endif
    return HITLS_X509_Sign(mdId, prvKey, algParam, csr, (HITLS_X509_SignCb)CsrSignCb);
}
#endif // HITLS_PKI_X509_CSR_GEN

#endif // HITLS_PKI_X509_CSR
