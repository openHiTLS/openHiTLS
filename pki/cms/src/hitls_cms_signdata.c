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
#ifdef HITLS_PKI_CMS_SIGNEDDATA
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_asn1_internal.h"
#include "bsl_list.h"
#include "bsl_obj_internal.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_params.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_x509.h"
#include "hitls_cms_local.h"
#include "hitls_crl_local.h"
#include "hitls_cert_local.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_params.h"
#include "hitls_cms_util.h"
#define MAX_DIGEST_SIZE 64  // Maximum digest size (e.g., SHA-512)

/**
 * SignedData ::= SEQUENCE {
 * digestAlgorithms DigestAlgorithmIdentifiers,
 * encapContentInfo EncapsulatedContentInfo,
 * certificates [0] IMPLICIT CertificateSet OPTIONAL,
 * crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 * signerInfos SignerInfos }
 */
static BSL_ASN1_TemplateItem g_signedDataTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        /* version - CMSVersion (INTEGER) */
        {BSL_ASN1_TAG_INTEGER, 0, 1},
        /* digestAlgorithms - DigestAlgorithmIdentifiers (SET OF DigestAlgorithmIdentifier) */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, BSL_ASN1_FLAG_HEADERONLY, 1},
        /* encapContentInfo - EncapsulatedContentInfo (SEQUENCE) */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        /* certificates [0] IMPLICIT CertificateSet OPTIONAL */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
        /* crls [1] IMPLICIT RevocationInfoChoices OPTIONAL (construct OF RevocationInfoChoice) */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
        /* signerInfos - SignerInfos (SET OF SignerInfo) */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, BSL_ASN1_FLAG_HEADERONLY, 1},
};

typedef enum {
    HITLS_CMS_SIGNEDDATA_VERSION_IDX,
    HITLS_CMS_SIGNEDDATA_DIGESTALGS_IDX,
    HITLS_CMS_SIGNEDDATA_ENCAPCONTENT_IDX,
    HITLS_CMS_SIGNEDDATA_CERTS_IDX,
    HITLS_CMS_SIGNEDDATA_CRLS_IDX,
    HITLS_CMS_SIGNEDDATA_SIGNERINFOS_IDX,
    HITLS_CMS_SIGNEDDATA_MAX_IDX,
} HITLS_CMS_SIGNEDDATA_IDX;

/**
 * Template for AlgorithmIdentifier
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm OBJECT IDENTIFIER,
 *   parameters ANY DEFINED BY algorithm OPTIONAL }
 */
static BSL_ASN1_TemplateItem g_algIdTempl[] = {
    /* algorithm - OBJECT IDENTIFIER */
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    /* parameters - ANY DEFINED BY algorithm OPTIONAL */
    {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
};

typedef enum {
    HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX,
    HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX,
    HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX,
} HITLS_CMS_ALGORITHM_IDENTIFIER_IDX;

// Callback to handle ANY tag in AlgorithmIdentifier parameters
static int32_t CMS_AlgIdAnyTagCb(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void)idx;
    if (type == BSL_ASN1_TYPE_GET_ANY_TAG) {
        *(uint8_t *)expVal = *(uint8_t *)data;
        return BSL_SUCCESS;
    }
    return HITLS_CMS_ERR_PARSE_TYPE;
}

static int32_t ParseAlgId(uint32_t layer, BSL_ASN1_Buffer *asn, void *param,
    BSL_ASN1_List *list)
{
    (void)param;
    (void)layer;
    CMS_AlgId *algId = BSL_SAL_Calloc(1, sizeof(CMS_AlgId));
    if (algId == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint8_t *temp = asn->buff;
    uint32_t tempLen = asn->len;
    BSL_ASN1_Buffer asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_algIdTempl, sizeof(g_algIdTempl) /
        sizeof(g_algIdTempl[0])};

    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, CMS_AlgIdAnyTagCb, &temp, &tempLen, asn1,
        HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        CMS_AlgIdFree(algId);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Parse algorithm OID
    BslOidString oidStr = {asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX].len,
        (char *)asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX].buff, 0};
    algId->id = BSL_OBJ_GetCID(&oidStr);
    if (algId->id == BSL_CID_UNKNOWN) {
        CMS_AlgIdFree(algId);
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }

    // Parse optional parameters
    if (asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].len > 0) {
        algId->param.data = BSL_SAL_Dump(asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].buff,
                                            asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].len);
        if (algId->param.data == NULL) {
            CMS_AlgIdFree(algId);
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        algId->param.dataLen = asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].len;
    } else {
        algId->param.data = NULL;
        algId->param.dataLen = 0;
    }
    if (BSL_LIST_AddElement(list, algId, BSL_LIST_POS_END) != BSL_SUCCESS) {
        CMS_AlgIdFree(algId);
        return BSL_MALLOC_FAIL;
    }
    return HITLS_PKI_SUCCESS;
}

/**
 * Parse DigestAlgorithmIdentifiers from ASN.1 buffer
 * Reference: RFC 5652 Section 5.4
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 */
static int32_t ParseDigestAlgorithms(BSL_ASN1_Buffer *buffer, BslList *digestAlg)
{
    if (buffer->len == 0) {
        return HITLS_PKI_SUCCESS;
    }

    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {1, expTag};
    BSL_ASN1_Buffer asn = {
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        buffer->len,
        buffer->buff,
    };

    int32_t ret = BSL_ASN1_DecodeListItem(&listParam, &asn, &ParseAlgId, NULL, digestAlg);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/**
 * EncapsulatedContentInfo ::= SEQUENCE {
 *   eContentType ContentType,
 *   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 *
 * https://datatracker.ietf.org/doc/html/rfc5652#section-5.2
 */
static BSL_ASN1_TemplateItem g_encapContInfoTempl[] = {
    /* eContentType - ContentType (OBJECT IDENTIFIER) */
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    /* eContent [0] EXPLICIT OCTET STRING OPTIONAL */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, BSL_ASN1_FLAG_OPTIONAL, 0},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1},
};

typedef enum {
    HITLS_CMS_ECI_CONTENT_TYPE_IDX,
    HITLS_CMS_ECI_ECONTENT_BUFF_IDX,
    HITLS_CMS_ECI_MAX_IDX,
} HITLS_CMS_ECI_IDX;

int32_t ParseEncapContentInfo(BSL_ASN1_Buffer *encode, CMS_SignedData *signedData)
{
    uint8_t *temp = encode->buff;
    uint32_t tempLen = encode->len;
    BSL_ASN1_Buffer asn1[HITLS_CMS_ECI_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_encapContInfoTempl, sizeof(g_encapContInfoTempl) / sizeof(g_encapContInfoTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_CMS_ECI_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CMS_EncapContentInfo *encapCont = &signedData->encapCont;
    // parse eContentType OID
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(asn1[HITLS_CMS_ECI_CONTENT_TYPE_IDX].buff,
        asn1[HITLS_CMS_ECI_CONTENT_TYPE_IDX].len);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
    encapCont->contentType = cid;
    // get optional eContent buffer, it's can be NULL.
    encapCont->content.data = asn1[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].buff;
    encapCont->content.dataLen = asn1[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].len;
    if (encapCont->contentType == BSL_CID_PKCS7_SIMPLEDATA && encapCont->content.data != NULL &&
        encapCont->content.dataLen != 0) {
        signedData->detached = false;
    }
    return HITLS_PKI_SUCCESS;
}

/* SignerInfo ::= SEQUENCE {
 *   version CMSVersion,
 *   sid SignerIdentifier,
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
 *   signatureAlgorithm SignatureAlgorithmIdentifier,
 *   signature SignatureValue,
 *   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
 */
/* Callback to check SignerIdentifier CHOICE tag - accepts SEQUENCE or [0] IMPLICIT */
static int32_t SignerIdentifierChoiceCheckCb(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void)idx;
    if (type == BSL_ASN1_TYPE_CHECK_CHOICE_TAG) {
        // For CHOICE type, check if the tag is valid for SignerIdentifier
        uint8_t tag = *(uint8_t *)data;
        /* SignerIdentifier can be:
         * - issuerAndSerialNumber: SEQUENCE (0x30)
         * - subjectKeyIdentifier: [0] BSL_ASN1_TAG_OCTETSTRING
         */
        if (tag == (BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE) ||
            tag == (BSL_ASN1_CLASS_CTX_SPECIFIC)) {
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
        if (cid == BSL_CID_RSASSAPSS) {
            *(uint8_t *)expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
            return BSL_SUCCESS;
        } else {
            *(uint8_t *)expVal = BSL_ASN1_TAG_NULL;
            return BSL_SUCCESS;
        }
    }
    return HITLS_CMS_ERR_PARSE_TYPE;
}

static BSL_ASN1_TemplateItem g_signerInfoTempl[] = {
    /* version */
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    /* sid - SignerIdentifier (CHOICE: can be SEQUENCE or [0] IMPLICIT) */
    {BSL_ASN1_TAG_CHOICE, BSL_ASN1_FLAG_HEADERONLY, 0},
    /* digestAlgorithm - AlgorithmIdentifier */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    /* signedAttrs [0] IMPLICIT SET OF Attribute OPTIONAL */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
    /* signatureAlgorithm - AlgorithmIdentifier */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
    /* signature - OCTET STRING */
    {BSL_ASN1_TAG_OCTETSTRING, BSL_ASN1_FLAG_HEADERONLY, 0},
    /* unsignedAttrs [1] IMPLICIT SET OF Attribute OPTIONAL */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1,
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
};

typedef enum {
    HITLS_CMS_SIGNERINFO_VER_IDX,
    HITLS_CMS_SIGNERINFO_SID_IDX,
    HITLS_CMS_SIGNERINFO_DIGESTALG_IDX,
    HITLS_CMS_SIGNERINFO_SIGNEDATTRS_IDX,
    HITLS_CMS_SIGNERINFO_SIGALG_ALG_IDX,
    HITLS_CMS_SIGNERINFO_SIGALG_PARAMS_IDX,
    HITLS_CMS_SIGNERINFO_SIGNATURE_IDX,
    HITLS_CMS_SIGNERINFO_UNSIGNEDATTRS_IDX,
    HITLS_CMS_SIGNERINFO_MAX_IDX,
} HITLS_CMS_SIGNERINFO_IDX;

/* IssuerAndSerialNumber template - for parsing issuerAndSerialNumber CHOICE */
static BSL_ASN1_TemplateItem g_issuerAndSerialNumTempl[] = {
    /* issuer Name */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    /* serialNumber - CertificateSerialNumber */
    {BSL_ASN1_TAG_INTEGER, 0, 0},
};

typedef enum {
    HITLS_CMS_ISSUERANDSERIALNUMBER_ISSUER_IDX,
    HITLS_CMS_ISSUERANDSERIALNUMBER_SERIALNUM_IDX,
    HITLS_CMS_ISSUERANDSERIALNUMBER_MAX_IDX,
} HITLS_CMS_ISSUERANDSERIALNUMBER_IDX;

static int32_t ParseSignerIdentifier(BSL_ASN1_Buffer *asn, CMS_SignerInfo *si)
{
    if (asn->len == 0) {
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    int32_t ret;
    /* SignerIdentifier is a CHOICE, check the tag to determine which option */
    uint8_t tag = asn->tag;
    if (tag == (BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE)) {
        /* issuerAndSerialNumber: IssuerAndSerialNumber ::= SEQUENCE */
        uint8_t *temp = asn->buff;
        uint32_t tempLen = asn->len;
        BSL_ASN1_Buffer issAsn[HITLS_CMS_ISSUERANDSERIALNUMBER_MAX_IDX] = {0};
        BSL_ASN1_Template issTempl = {g_issuerAndSerialNumTempl,
            sizeof(g_issuerAndSerialNumTempl) / sizeof(g_issuerAndSerialNumTempl[0])};
        ret = BSL_ASN1_DecodeTemplate(&issTempl, NULL, &temp, &tempLen, issAsn,
            HITLS_CMS_ISSUERANDSERIALNUMBER_MAX_IDX);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        ret = HITLS_X509_ParseNameList(&issAsn[HITLS_CMS_ISSUERANDSERIALNUMBER_ISSUER_IDX], si->issuerName);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        si->certSerialNum.data = issAsn[HITLS_CMS_ISSUERANDSERIALNUMBER_SERIALNUM_IDX].buff;
        si->certSerialNum.dataLen = issAsn[HITLS_CMS_ISSUERANDSERIALNUMBER_SERIALNUM_IDX].len;
    } else if (tag == BSL_ASN1_CLASS_CTX_SPECIFIC) {
        si->subjectKeyId.kid.data = asn->buff;
        si->subjectKeyId.kid.dataLen = asn->len;
    } else {
        /* Unsupported SignerIdentifier type */
        return HITLS_CMS_ERR_PARSE_TYPE;
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t ParseDigestSignAlgId(BSL_ASN1_Buffer *asn, CMS_AlgId *algId)
{
    if (asn->len == 0) {
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    uint8_t *temp = asn->buff;
    uint32_t tempLen = asn->len;
    BSL_ASN1_Buffer asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_algIdTempl, sizeof(g_algIdTempl) / sizeof(g_algIdTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, CMS_AlgIdAnyTagCb, &temp, &tempLen, asn1,
        HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    algId->id = BSL_OBJ_GetCidFromOidBuff(asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX].buff,
                                            asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX].len);
    if (algId->id == BSL_CID_UNKNOWN) {
        return HITLS_CMS_ERR_PARSE_TYPE;
    }

    // RFC 9882: ML-DSA AlgorithmIdentifier parameters MUST be omitted
    // Validate that PQC algorithms do not have parameters
    if (HITLS_CMS_PqcShouldOmitParams((BslCid)algId->id) &&
        asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].len > 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PQC_PARAMS_NOT_OMITTED);
        return HITLS_CMS_ERR_PQC_PARAMS_NOT_OMITTED;
    }

    if (asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].len > 0) {
        algId->param.data = BSL_SAL_Dump(asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].buff,
            asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].len);
        if (algId->param.data == NULL) {
            return BSL_DUMP_FAIL;
        }
        algId->param.dataLen = asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].len;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t SignedAttrsCheck(HITLS_X509_Attrs *attrs)
{
    if (attrs == NULL || BSL_LIST_COUNT(attrs->list) == 0) {
        return HITLS_PKI_SUCCESS;
    }
    int32_t nums = 0;
    HITLS_X509_AttrEntry *node = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(attrs->list);
    while (node != NULL) {
        if (node->cid == BSL_CID_PKCS9_AT_MESSAGEDIGEST || node->cid == BSL_CID_PKCS9_AT_CONTENTTYPE) {
            nums++;
        }
        node = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(attrs->list);
    }
    if (nums != 2) { // 2: the minimum number of required signed attributes.
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_SIGNEDATTRS_INVALID);
        return HITLS_CMS_ERR_SIGNEDDATA_SIGNEDATTRS_INVALID;
    }
    return HITLS_PKI_SUCCESS;
}

// Fill SignerInfo fields from decoded ASN.1 buffers
static int32_t FillSignerInfoFields(CMS_SignerInfo *si, BSL_ASN1_Buffer *a)
{
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(&a[HITLS_CMS_SIGNERINFO_VER_IDX], &si->version);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = ParseSignerIdentifier(&a[HITLS_CMS_SIGNERINFO_SID_IDX], si);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ParseDigestSignAlgId(&a[HITLS_CMS_SIGNERINFO_DIGESTALG_IDX], &si->digestAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    si->signData.data = a[HITLS_CMS_SIGNERINFO_SIGNEDATTRS_IDX].buff;
    si->signData.dataLen = a[HITLS_CMS_SIGNERINFO_SIGNEDATTRS_IDX].len;
    ret = HITLS_X509_ParseAttrList(&a[HITLS_CMS_SIGNERINFO_SIGNEDATTRS_IDX], si->signedAttrs, NULL, NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = SignedAttrsCheck(si->signedAttrs);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    si->sigValue.data = a[HITLS_CMS_SIGNERINFO_SIGNATURE_IDX].buff;
    si->sigValue.dataLen = a[HITLS_CMS_SIGNERINFO_SIGNATURE_IDX].len;
    ret = HITLS_X509_ParseSignAlgInfo(&a[HITLS_CMS_SIGNERINFO_SIGALG_ALG_IDX],
        &a[HITLS_CMS_SIGNERINFO_SIGALG_PARAMS_IDX], &si->sigAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_X509_ParseAttrList(&a[HITLS_CMS_SIGNERINFO_UNSIGNEDATTRS_IDX], si->unsignedAttrs, NULL, NULL);
}

static int32_t ParseSignerInfoItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    (void)param;
    (void)layer;
    uint8_t *tmp = asn->buff;
    uint32_t tmpLen = asn->len;
    BSL_ASN1_Buffer a[HITLS_CMS_SIGNERINFO_MAX_IDX] = {0};
    BSL_ASN1_Template t = {g_signerInfoTempl, sizeof(g_signerInfoTempl) / sizeof(g_signerInfoTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&t, SignerIdentifierChoiceCheckCb, &tmp, &tmpLen, a,
        HITLS_CMS_SIGNERINFO_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    CMS_SignerInfo *si = CMS_SignerInfoNew(HITLS_CMS_FLAG_PARSE);
    if (si == NULL) {
        return BSL_MALLOC_FAIL;
    }
    ret = FillSignerInfoFields(si, a);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_CMS_SignerInfoFree(si);
        return ret;
    }
    ret = BSL_LIST_AddElement(list, si, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        HITLS_CMS_SignerInfoFree(si);
    }
    return ret;
}

static int32_t ParseSignerInfos(BSL_ASN1_Buffer *asn, CMS_SignerInfos *infos)
{
    if (asn->len == 0) {
        return HITLS_PKI_SUCCESS;
    }
    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {1, expTag};
    BSL_ASN1_Buffer asnBuff = {
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        asn->len,
        asn->buff,
    };
    return BSL_ASN1_DecodeListItem(&listParam, &asnBuff, &ParseSignerInfoItem, NULL, infos);
}

// Parse SignedData fields from decoded ASN.1 buffers
static int32_t ParseSignedDataFields(CMS_SignedData *sigData, BSL_ASN1_Buffer *asn1)
{
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(&asn1[HITLS_CMS_SIGNEDDATA_VERSION_IDX], &sigData->version);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ParseDigestAlgorithms(&asn1[HITLS_CMS_SIGNEDDATA_DIGESTALGS_IDX], sigData->digestAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ParseEncapContentInfo(&asn1[HITLS_CMS_SIGNEDDATA_ENCAPCONTENT_IDX], sigData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (asn1[HITLS_CMS_SIGNEDDATA_CERTS_IDX].len > 0) {
        BSL_Buffer certBuf = {asn1[HITLS_CMS_SIGNEDDATA_CERTS_IDX].buff, asn1[HITLS_CMS_SIGNEDDATA_CERTS_IDX].len};
        ret = HITLS_X509_CertParseBundleBuff(BSL_FORMAT_ASN1, &certBuf, &sigData->certs);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    if (asn1[HITLS_CMS_SIGNEDDATA_CRLS_IDX].len > 0) {
        BSL_Buffer crlBuf = {asn1[HITLS_CMS_SIGNEDDATA_CRLS_IDX].buff, asn1[HITLS_CMS_SIGNEDDATA_CRLS_IDX].len};
        ret = HITLS_X509_CrlParseBundleBuff(BSL_FORMAT_ASN1, &crlBuf, &sigData->crls);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    return ParseSignerInfos(&asn1[HITLS_CMS_SIGNEDDATA_SIGNERINFOS_IDX], sigData->signerInfos);
}

int32_t HITLS_CMS_ParseSignedData(HITLS_PKI_LibCtx *libCtx, const char *attrName, const BSL_Buffer *encode,
    HITLS_CMS **signedData)
{
    if (encode == NULL || encode->data == NULL || signedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (encode->dataLen == 0 || *signedData != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }

    HITLS_CMS *ctx = HITLS_CMS_ProviderNew(libCtx, attrName, BSL_CID_PKCS7_SIGNEDDATA);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ctx->ctx.signedData->flag |= HITLS_CMS_FLAG_PARSE;
    ctx->ctx.signedData->initData = BSL_SAL_Dump(encode->data, encode->dataLen);
    if (ctx->ctx.signedData->initData == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        HITLS_CMS_Free(ctx);
        return BSL_DUMP_FAIL;
    }

    uint8_t *temp = ctx->ctx.signedData->initData;
    uint32_t tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_CMS_SIGNEDDATA_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_signedDataTempl, sizeof(g_signedDataTempl) / sizeof(g_signedDataTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_CMS_SIGNEDDATA_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_CMS_Free(ctx);
        return ret;
    }

    ret = ParseSignedDataFields(ctx->ctx.signedData, asn1);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_CMS_Free(ctx);
        return ret;
    }
    *signedData = ctx;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeHashAlgId(const CMS_AlgId *alg, BSL_ASN1_Buffer *asn)
{
    if (alg == NULL || asn == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    BslOidString *oidStr = BSL_OBJ_GetOID((BslCid)alg->id);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BSL_ASN1_Buffer items[HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX] = {
        {
            .buff = (uint8_t *)oidStr->octs,
            .len = oidStr->octetLen,
            .tag = BSL_ASN1_TAG_OBJECT_ID,
        },
        {0}
    };

    // https://www.rfc-editor.org/rfc/rfc5754#section-1.1 SHA-2
    // https://www.rfc-editor.org/rfc/rfc3370#section-2 SHA-1, md5
    // those hash param encode with absent parameters.
    items[1].buff = NULL;
    items[1].len = 0;
    items[1].tag = BSL_ASN1_TAG_ANY;

    BSL_ASN1_Template templ = {g_algIdTempl, sizeof(g_algIdTempl) / sizeof(g_algIdTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, items, HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX, &asn->buff, &asn->len);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asn->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

static void FreeAsnList(BSL_ASN1_Buffer *list, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        BSL_SAL_FREE(list[i].buff);
    }
    BSL_SAL_FREE(list);
}

// Callback for encoding items directly to ASN.1 buffer (AlgId, SignerInfo)
typedef int32_t (*EncodeItemToAsnFunc)(void *item, BSL_ASN1_Buffer *encode);

// Callback for encoding X509 items with format parameter (Cert, CRL)
typedef int32_t (*EncodeX509ItemFunc)(int32_t format, void *item, BSL_Buffer *buf);

// Common function to encode a list of items as SET OF SEQUENCE
static int32_t EncodeListToSet(BslList *list, EncodeItemToAsnFunc encodeFunc, BSL_ASN1_Buffer *encode)
{
    if (list == NULL || BSL_LIST_COUNT(list) == 0) {
        encode->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
        return HITLS_PKI_SUCCESS;
    }
    uint32_t count = (uint32_t)BSL_LIST_COUNT(list);
    BSL_ASN1_Buffer *asnArr = (BSL_ASN1_Buffer *)BSL_SAL_Calloc(count, sizeof(BSL_ASN1_Buffer));
    if (asnArr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t i = 0;
    for (void *node = BSL_LIST_GET_FIRST(list); node != NULL; node = BSL_LIST_GET_NEXT(list)) {
        int32_t ret = encodeFunc(node, &asnArr[i]);
        if (ret != HITLS_PKI_SUCCESS) {
            FreeAsnList(asnArr, i);
            return ret;
        }
        i++;
    }
    // every item is a SEQUENCE
    static BSL_ASN1_TemplateItem seqTemplItem = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0};
    BSL_ASN1_Template seqTempl = {&seqTemplItem, 1};
    BSL_ASN1_Buffer outAsn = {0};
    int32_t ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, count, &seqTempl, asnArr, i, &outAsn);
    FreeAsnList(asnArr, i);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encode->buff = outAsn.buff;
    encode->len = outAsn.len;
    encode->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeAlgId(HITLS_X509_List *list, BSL_ASN1_Buffer *encode)
{
    return EncodeListToSet(list, (EncodeItemToAsnFunc)EncodeHashAlgId, encode);
}

static int32_t EncodeEncapContentInfo(CMS_EncapContentInfo encap, BSL_ASN1_Buffer *encode)
{
    BSL_ASN1_Buffer items[HITLS_CMS_ECI_MAX_IDX] = {0};
    int32_t ret = HITLS_X509_EncodeObjIdentity(encap.contentType, &items[HITLS_CMS_ECI_CONTENT_TYPE_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    items[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
    items[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].buff = encap.content.data;
    items[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].len = encap.content.dataLen;

    BSL_ASN1_Template templ = {g_encapContInfoTempl, sizeof(g_encapContInfoTempl) / sizeof(g_encapContInfoTempl[0])};
    BSL_ASN1_Buffer outAsn = {0};
    ret = BSL_ASN1_EncodeTemplate(&templ, items, HITLS_CMS_ECI_MAX_IDX, &outAsn.buff, &outAsn.len);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encode->buff = outAsn.buff;
    encode->len = outAsn.len;
    encode->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

// Common function to encode a list of X509 items (certificates or CRLs)
static int32_t EncodeX509List(HITLS_X509_List *list, uint8_t implicitTag, EncodeX509ItemFunc encodeFunc,
    BSL_ASN1_Buffer *encode)
{
    uint8_t tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | implicitTag;
    if (list == NULL || BSL_LIST_COUNT(list) == 0) {
        encode->tag = tag;
        return HITLS_PKI_SUCCESS;
    }

    uint32_t count = (uint32_t)BSL_LIST_COUNT(list);
    BSL_ASN1_Buffer *asnBuf = BSL_SAL_Calloc(count, sizeof(BSL_ASN1_Buffer));
    if (asnBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    uint32_t i = 0;
    for (void *node = BSL_LIST_GET_FIRST(list); node != NULL; node = BSL_LIST_GET_NEXT(list), i++) {
        BSL_Buffer tmp = {0};
        int32_t ret = encodeFunc(BSL_FORMAT_ASN1, node, &tmp);
        if (ret != HITLS_PKI_SUCCESS) {
            FreeAsnList(asnBuf, i);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        asnBuf[i].buff = tmp.data;
        asnBuf[i].len  = tmp.dataLen;
        asnBuf[i].tag  = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    }
    uint32_t len = 0;
    for (uint32_t j = 0; j < i; j++) {
        len += asnBuf[j].len;
    }
    uint8_t *temp = BSL_SAL_Malloc(len);
    if (temp == NULL) {
        FreeAsnList(asnBuf, i);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t offset = 0;
    for (uint32_t j = 0; j < i; j++) {
        (void)memcpy_s(temp + offset, asnBuf[j].len, asnBuf[j].buff, asnBuf[j].len);
        offset += asnBuf[j].len;
    }
    FreeAsnList(asnBuf, i);
    encode->buff = temp;
    encode->len = len;
    encode->tag = tag;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeCertList(HITLS_X509_List *certs, BSL_ASN1_Buffer *encode)
{
    return EncodeX509List(certs, 0, (EncodeX509ItemFunc)HITLS_X509_CertGenBuff, encode);
}

static int32_t EncodeCrlList(HITLS_X509_List *crls, BSL_ASN1_Buffer *encode)
{
    return EncodeX509List(crls, 1, (EncodeX509ItemFunc)HITLS_X509_CrlGenBuff, encode);
}

static int32_t EncodeSignerIdentifier(CMS_SignerInfo *si, BSL_ASN1_Buffer *sid)
{
    int32_t ret;
    // Determine which CHOICE to encode based on available data
    if (si->version == HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3) {
        // Encode subjectKeyIdentifier: [0] IMPLICIT OCTET STRING
        uint32_t totalLen = si->subjectKeyId.kid.dataLen;
        uint8_t *encoded = BSL_SAL_Malloc(totalLen);
        if (encoded == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        (void)memcpy_s(encoded, totalLen, si->subjectKeyId.kid.data, si->subjectKeyId.kid.dataLen);
        sid->buff = encoded;
        sid->len = totalLen;
        sid->tag = BSL_ASN1_CLASS_CTX_SPECIFIC;
        return HITLS_PKI_SUCCESS;
    }
    if (si->version == HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1) {
        // Encode issuerAndSerialNumber: SEQUENCE (issuerName, certSerialNum)
        BSL_ASN1_Buffer issuer = {0};
        ret = HITLS_X509_EncodeNameList(si->issuerName, &issuer);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        BSL_ASN1_Buffer serial = {
            .buff = si->certSerialNum.data,
            .len = si->certSerialNum.dataLen,
            .tag = BSL_ASN1_TAG_INTEGER,
        };
        BSL_ASN1_Buffer in[HITLS_CMS_ISSUERANDSERIALNUMBER_MAX_IDX] = {issuer, serial};
        BSL_ASN1_Template templ = {g_issuerAndSerialNumTempl,
            sizeof(g_issuerAndSerialNumTempl) / sizeof(g_issuerAndSerialNumTempl[0])};
        ret = BSL_ASN1_EncodeTemplate(&templ, in, HITLS_CMS_ISSUERANDSERIALNUMBER_MAX_IDX, &sid->buff, &sid->len);
        BSL_SAL_FREE(issuer.buff);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        sid->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
        return HITLS_PKI_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERSION_INVALID);
    return HITLS_CMS_ERR_VERSION_INVALID;
}

static int32_t EncodeSignerInfo(CMS_SignerInfo *si, BSL_ASN1_Buffer *asn)
{
    BSL_ASN1_Buffer asnbuff[7] = {0}; // only need 7 temp buffers
    int32_t ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, (uint64_t)si->version, &asnbuff[0]); // 0: version
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = EncodeSignerIdentifier(si, &asnbuff[1]); // 1: sid
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    ret = EncodeHashAlgId(&si->digestAlg, &asnbuff[2]); // 2: digestAlg
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    ret = HITLS_X509_EncodeAttrList(BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,
        si->signedAttrs, NULL, &asnbuff[3]); // 3: signedAttrs
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = HITLS_X509_EncodeSignAlgInfo(&si->sigAlg, &asnbuff[4]); // 4: sigAlg
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    asnbuff[5].tag = BSL_ASN1_TAG_OCTETSTRING; // 5: signature
    asnbuff[5].buff = si->sigValue.data; // 5: signature
    asnbuff[5].len = si->sigValue.dataLen;

    ret = HITLS_X509_EncodeAttrList(BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1,
        si->unsignedAttrs, NULL, &asnbuff[6]); // 6: unsignedAttrs
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    BSL_ASN1_TemplateItem siTemplItems[] = {
        {BSL_ASN1_TAG_INTEGER, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, BSL_ASN1_FLAG_OPTIONAL, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 0},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1, BSL_ASN1_FLAG_OPTIONAL, 0},
    };
    if (si->version == HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3) {
        siTemplItems[1].tag = BSL_ASN1_CLASS_CTX_SPECIFIC;
    }
    BSL_ASN1_Template templ = {siTemplItems, sizeof(siTemplItems) / sizeof(siTemplItems[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnbuff, 7, &asn->buff, &asn->len); // 7: total items
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    asn->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
ERR:
    for (uint32_t i = 0; i < 5; i++) { // 0: version, 1: sid, 2: digestAlg, 3: signedAttrs, 4: sigAlg, 5: not free
        BSL_SAL_FREE(asnbuff[i].buff);
    }
    BSL_SAL_FREE(asnbuff[6].buff); // 6: unsignedAttrs
    return ret;
}

static int32_t EncodeSignerInfoList(CMS_SignerInfos *infos, BSL_ASN1_Buffer *encode)
{
    return EncodeListToSet(infos, (EncodeItemToAsnFunc)EncodeSignerInfo, encode);
}

static int32_t CheckSignerInfosVersion(CMS_SignerInfos *signerInfo)
{
    if (BSL_LIST_COUNT(signerInfo) == 0) {
        return 0;
    }
    CMS_SignerInfo *signerInfoItem = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(signerInfo);
    while (signerInfoItem != NULL) {
        if (signerInfoItem->version != HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3) {
            return 0;
        }
        signerInfoItem = (CMS_SignerInfo *)BSL_LIST_GET_NEXT(signerInfo);
    }
    return HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3;
}

/* according to the RFC 5652, the version of signed data is determined by the following rules:
 * IF ((certificates is present) AND (any certificates with a type of other are present)) OR
 * ((crls is present) AND (any crls with a type of other are present))
 * THEN version MUST be 5
 * ELSE
 * IF (certificates is present) AND (any version 2 attribute certificates are present)
 * THEN version MUST be 4
 * ELSE
 * IF ((certificates is present) AND (any version 1 attribute certificates are present)) OR
 * (any SignerInfo structures are version 3) OR (encapContentInfo eContentType is other than id-data)
 * THEN version MUST be 3
 * ELSE version MUST be 1
 */
static int32_t GetSignedDataVersion(CMS_SignedData *sigData)
{
    // not supported other type of cert and crl.
    if (CheckSignerInfosVersion(sigData->signerInfos) == HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3 ||
        sigData->encapCont.contentType != BSL_CID_PKCS7_SIMPLEDATA) {
        return 3; // version 3
    }
    return 1; // version 1
}

static int32_t CMS_GenSignedDataBuffAsn1(HITLS_CMS *cms, BSL_Buffer *encode)
{
    BSL_ASN1_Buffer asnbuff[HITLS_CMS_SIGNEDDATA_MAX_IDX] = {0};
    CMS_SignedData *sigData = cms->ctx.signedData;
    if (sigData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    sigData->version = GetSignedDataVersion(sigData);
    int32_t ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, (uint64_t)sigData->version, &asnbuff[0]); // 0: version
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = EncodeAlgId(sigData->digestAlg, &asnbuff[1]); // 1: digestAlg
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = EncodeEncapContentInfo(sigData->encapCont, &asnbuff[2]); // 2: encapContent
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = EncodeCertList(sigData->certs, &asnbuff[3]); // 3: certs
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = EncodeCrlList(sigData->crls, &asnbuff[4]); // 4: crls
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = EncodeSignerInfoList(sigData->signerInfos, &asnbuff[5]); // 5: signerInfos
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    BSL_ASN1_Template templ = {g_signedDataTempl, sizeof(g_signedDataTempl) / sizeof(g_signedDataTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnbuff, HITLS_CMS_SIGNEDDATA_MAX_IDX, &encode->data, &encode->dataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
ERR:
    for (uint32_t i = 0; i < HITLS_CMS_SIGNEDDATA_MAX_IDX; i++) {
        BSL_SAL_FREE(asnbuff[i].buff);
    }
    return ret;
}

int32_t HITLS_CMS_GenSignedDataBuff(int32_t format, HITLS_CMS *cms, BSL_Buffer *encode)
{
    switch (format) {
        case BSL_FORMAT_ASN1:
            return CMS_GenSignedDataBuffAsn1(cms, encode);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
            return HITLS_CMS_ERR_INVALID_FORMAT;
    }
}

// Set signer identifier for version 3 (subjectKeyIdentifier)
static int32_t SetSignerIdV3(CMS_SignerInfo *signerInfo, BSL_Buffer *subjectKeyId)
{
    signerInfo->subjectKeyId.kid.data = BSL_SAL_Dump(subjectKeyId->data, subjectKeyId->dataLen);
    if (signerInfo->subjectKeyId.kid.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    signerInfo->subjectKeyId.kid.dataLen = subjectKeyId->dataLen;
    return HITLS_PKI_SUCCESS;
}

// Set signer identifier for version 1 (issuerAndSerialNumber)
static int32_t SetSignerIdV1(CMS_SignerInfo *signerInfo, BSL_ASN1_List *issuerName, BSL_Buffer *serialNum)
{
    int32_t ret = HITLS_X509_SetNameList(&signerInfo->issuerName, issuerName, sizeof(BSL_ASN1_List));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    signerInfo->certSerialNum.data = BSL_SAL_Dump(serialNum->data, serialNum->dataLen);
    if (signerInfo->certSerialNum.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    signerInfo->certSerialNum.dataLen = serialNum->dataLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t CMS_SignerInfoGen(int32_t version, BSL_ASN1_List *issuerName,
    BSL_Buffer *serialNum, BSL_Buffer *subjectKeyId, CMS_SignerInfo **signerinfo, bool hasSignedAttr)
{
    uint32_t flag = (!hasSignedAttr ? (HITLS_CMS_FLAG_GEN | HITLS_CMS_FLAG_NO_SIGNEDATTR) : HITLS_CMS_FLAG_GEN);
    CMS_SignerInfo *signerInfo = CMS_SignerInfoNew(flag);
    if (signerInfo == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret;
    signerInfo->version = version;
    switch (version) {
        case HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1:
            ret = SetSignerIdV1(signerInfo, issuerName, serialNum);
            break;
        case HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3:
            ret = SetSignerIdV3(signerInfo, subjectKeyId);
            break;
        default:
            ret = HITLS_CMS_ERR_VERSION_INVALID;
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERSION_INVALID);
            break;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_CMS_SignerInfoFree(signerInfo);
        return ret;
    }
    *signerinfo = signerInfo;
    return HITLS_PKI_SUCCESS;
}

static int32_t CreateSignerInfoFromCert(int32_t version, HITLS_X509_Cert *cert, CMS_SignerInfo **signerinfo,
    bool hasSignedAttr)
{
    if (version == HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1) {
        BSL_ASN1_List *issuerName = NULL;
        int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, &issuerName, sizeof(BSL_ASN1_List *));
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        BSL_Buffer serialNum = {0};
        ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &serialNum, sizeof(BSL_Buffer));
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        return CMS_SignerInfoGen(version, issuerName, &serialNum, NULL, signerinfo, hasSignedAttr);
    }
    if (version == HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3) {
        HITLS_X509_ExtSki ski = {0};
        int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki));
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        return CMS_SignerInfoGen(version, NULL, NULL, &ski.kid, signerinfo, hasSignedAttr);
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERSION_INVALID);
    return HITLS_CMS_ERR_VERSION_INVALID;
}

// Configure RSA signature algorithm based on padding type
static int32_t ConfigureRsaSignAlg(CRYPT_EAL_PkeyCtx *signKey, HITLS_X509_Asn1AlgId *sigAlg)
{
    CRYPT_RsaPadType pad;
    int32_t ret = CRYPT_EAL_PkeyCtrl(signKey, CRYPT_CTRL_GET_RSA_PADDING, &pad, sizeof(CRYPT_RsaPadType));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (pad == CRYPT_EMSA_PSS) {
        sigAlg->algId = BSL_CID_RSASSAPSS;
        ret = CRYPT_EAL_PkeyCtrl(signKey, CRYPT_CTRL_GET_RSA_MD, &sigAlg->rsaPssParam.mdId, sizeof(CRYPT_MD_AlgId));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = CRYPT_EAL_PkeyCtrl(signKey, CRYPT_CTRL_GET_RSA_MGF, &sigAlg->rsaPssParam.mgfId, sizeof(CRYPT_MD_AlgId));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = CRYPT_EAL_PkeyCtrl(signKey, CRYPT_CTRL_GET_RSA_SALTLEN, &sigAlg->rsaPssParam.saltLen, sizeof(uint32_t));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else if (pad == CRYPT_EMSA_PKCSV15) {
        sigAlg->algId = BSL_CID_RSA;
    } else {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NOT_ENOUGH_INFO_KEY);
        return HITLS_CMS_ERR_NOT_ENOUGH_INFO_KEY;
    }
    return HITLS_PKI_SUCCESS;
}

// Configure signature algorithm based on key type
static int32_t ConfigureSignAlg(const CRYPT_EAL_PkeyCtx *prvKey, int32_t mdId, HITLS_X509_Asn1AlgId *sigAlg)
{
    CRYPT_PKEY_AlgId asymAlg = CRYPT_EAL_PkeyGetId(prvKey);
    CRYPT_EAL_PkeyCtx *signKey = (CRYPT_EAL_PkeyCtx *)(uintptr_t)prvKey;

    if (HITLS_CMS_IsPqcSignAlg((BslCid)asymAlg)) {
        CRYPT_PKEY_ParaId paraId = CRYPT_EAL_PkeyGetParaId(prvKey);
        if (paraId == CRYPT_PKEY_PARAID_MAX) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
            return HITLS_CMS_ERR_INVALID_ALGO;
        }
        sigAlg->algId = (BslCid)paraId;
    } else {
        if (asymAlg == CRYPT_PKEY_RSA) {
            return ConfigureRsaSignAlg(signKey, sigAlg);
        }
    
        BslCid signAlgId = BSL_OBJ_GetSignIdFromHashAndAsymId((BslCid)asymAlg, (BslCid)mdId);
        if (signAlgId == BSL_CID_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
            return HITLS_CMS_ERR_INVALID_ALGO;
        }
        sigAlg->algId = signAlgId;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CreateAndConfigSigner(CRYPT_EAL_PkeyCtx *prvKey, int32_t version, HITLS_X509_Cert *cert, int32_t mdId,
    bool hasSignedAttr, CMS_SignerInfo **signerinfo)
{
    int32_t ret = CreateSignerInfoFromCert(version, cert, signerinfo, hasSignedAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ConfigureSignAlg(prvKey, mdId, &(*signerinfo)->sigAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_CMS_SignerInfoFree(*signerinfo);
        *signerinfo = NULL;
        return ret;
    }
    (*signerinfo)->digestAlg.id = mdId;
    return ret;
}

// Helper function: Set contentType if not already set
static void SetContentType(CMS_SignedData *signedData)
{
    if (signedData->encapCont.contentType == 0) {
        signedData->encapCont.contentType = BSL_CID_PKCS7_SIMPLEDATA;
    }
}

// Helper function: Handle non-detached content
static int32_t HandleNonDetachedContent(CMS_SignedData *signedData, BSL_Buffer *msg)
{
    if (signedData->encapCont.content.data != NULL) {
        // Verify content matches
        if (signedData->encapCont.content.dataLen != msg->dataLen ||
            memcmp(signedData->encapCont.content.data, msg->data, msg->dataLen) != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_CONTENT_MISMATCH);
            return HITLS_CMS_ERR_SIGNEDDATA_CONTENT_MISMATCH;
        }
    } else {
        // Copy content
        signedData->encapCont.content.data = BSL_SAL_Dump(msg->data, msg->dataLen);
        if (signedData->encapCont.content.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        signedData->encapCont.content.dataLen = msg->dataLen;
    }
    return HITLS_PKI_SUCCESS;
}

// Helper function: Create content-type attribute
static int32_t CreateContentTypeAttr(BslCid contentType, HITLS_X509_AttrEntry **outAttr)
{
    HITLS_X509_AttrEntry *ctAttr = (HITLS_X509_AttrEntry *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    if (ctAttr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    ctAttr->cid = BSL_CID_PKCS9_AT_CONTENTTYPE;

    // Encode the attribute OID for attrId field
    int32_t ret = HITLS_X509_EncodeObjIdentity(BSL_CID_PKCS9_AT_CONTENTTYPE, &ctAttr->attrId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(ctAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Encode content type OID for the attribute value
    BslOidString *oidStr = BSL_OBJ_GetOID(contentType);
    if (oidStr == NULL) {
        BSL_SAL_FREE(ctAttr);
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }

    BSL_ASN1_Buffer oidBuf = {
        .tag = BSL_ASN1_TAG_OBJECT_ID,
        .buff = (uint8_t *)oidStr->octs,
        .len = oidStr->octetLen
    };
    BSL_ASN1_TemplateItem oidTempl = {BSL_ASN1_TAG_OBJECT_ID, 0, 0};
    BSL_ASN1_Template oidTemplate = {&oidTempl, 1};
    ret = BSL_ASN1_EncodeTemplate(&oidTemplate, &oidBuf, 1, &ctAttr->attrValue.buff, &ctAttr->attrValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(ctAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ctAttr->attrValue.tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
    *outAttr = ctAttr;
    return HITLS_PKI_SUCCESS;
}

// Helper function: Create message-digest attribute
static int32_t CreateMessageDigestAttr(uint8_t *digest, uint32_t digestLen, HITLS_X509_AttrEntry **outAttr)
{
    HITLS_X509_AttrEntry *mdAttr = (HITLS_X509_AttrEntry *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    if (mdAttr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    mdAttr->cid = BSL_CID_PKCS9_AT_MESSAGEDIGEST;

    // Encode the attribute OID for attrId field
    int32_t ret = HITLS_X509_EncodeObjIdentity(BSL_CID_PKCS9_AT_MESSAGEDIGEST, &mdAttr->attrId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(mdAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Encode digest as OCTET STRING for the attribute value
    BSL_ASN1_Buffer digestBuf = {
        .tag = BSL_ASN1_TAG_OCTETSTRING,
        .buff = (uint8_t *)digest,
        .len = digestLen
    };
    BSL_ASN1_TemplateItem octetStringTempl = {BSL_ASN1_TAG_OCTETSTRING, 0, 0};
    BSL_ASN1_Template octetTempl = {&octetStringTempl, 1};
    ret = BSL_ASN1_EncodeTemplate(&octetTempl, &digestBuf, 1, &mdAttr->attrValue.buff, &mdAttr->attrValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(mdAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    mdAttr->attrValue.tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
    *outAttr = mdAttr;
    return HITLS_PKI_SUCCESS;
}

// Helper function: Create signing-time attribute
static int32_t CreateSigningTimeAttr(HITLS_X509_AttrEntry **outAttr)
{
    HITLS_X509_AttrEntry *stAttr = (HITLS_X509_AttrEntry *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    if (stAttr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    stAttr->cid = BSL_CID_PKCS9_AT_SIGNINGTIME;

    // Encode the attribute OID for attrId field
    int32_t ret = HITLS_X509_EncodeObjIdentity(BSL_CID_PKCS9_AT_SIGNINGTIME, &stAttr->attrId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(stAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Get current system time
    BSL_TIME sysTime = {0};
    ret = BSL_SAL_SysTimeGet(&sysTime);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(stAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Encode time as UTCTime or GeneralizedTime based on year
    BSL_ASN1_Buffer timeBuf = {0};
    timeBuf.tag = (sysTime.year >= 2050) ? BSL_ASN1_TAG_GENERALIZEDTIME : BSL_ASN1_TAG_UTCTIME; // 2050
    timeBuf.len = sizeof(BSL_TIME);
    timeBuf.buff = (uint8_t *)(uintptr_t)&sysTime;

    BSL_ASN1_TemplateItem templItem = {BSL_ASN1_TAG_CHOICE, 0, 0};
    BSL_ASN1_Template templ = {&templItem, 1};
    ret = BSL_ASN1_EncodeTemplate(&templ, &timeBuf, 1, &stAttr->attrValue.buff, &stAttr->attrValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(stAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    stAttr->attrValue.tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
    *outAttr = stAttr;
    return HITLS_PKI_SUCCESS;
}

// Add a required attribute to signedAttrs
static int32_t AddRequiredAttr(HITLS_X509_Attrs *signedAttrs, HITLS_X509_AttrEntry *attr)
{
    int32_t ret = BSL_LIST_AddElement(signedAttrs->list, attr, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(attr->attrValue.buff);
        BSL_SAL_FREE(attr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

// Helper function: Encode signedAttrs and prepare data for signing
static int32_t EncodeSignedAttrsForSigning(CMS_SignerInfo *signerInfo,
                                           uint8_t **signData, uint32_t *signDataLen)
{
    // Encode signedAttrs
    BSL_ASN1_Buffer encAttr = {0};
    int32_t ret = HITLS_X509_EncodeAttrList(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        signerInfo->signedAttrs, NULL, &encAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Store the content (SET OF Attributes without [0] tag)
    // if the signer want to sign, they can use the value directly
    signerInfo->signData.data = encAttr.buff;

    signerInfo->signData.dataLen = encAttr.len;
    // ref RFC 5652 Section 5.4.
    // in the message digest calculation. we need to encode the SET OF Attributes
    // with EXPLICIT SET OF tag rather than of the IMPLICIT [0] tag,
    BSL_ASN1_Buffer asnArr = {
        .tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        .buff = signerInfo->signData.data,
        .len = signerInfo->signData.dataLen
    };
    BSL_ASN1_TemplateItem setTemplItem = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, 0, 0};
    BSL_ASN1_Template setTempl = {&setTemplItem, 1};
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    ret = BSL_ASN1_EncodeTemplate(&setTempl, &asnArr, 1, &data, &dataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *signData = data;
    *signDataLen = dataLen;
    return HITLS_PKI_SUCCESS;
}

// Helper function: Ensure required attributes exist in signedAttrs
static int32_t EnsureRequiredAttrsExist(CMS_SignerInfo *signerInfo, uint8_t *digest, uint32_t digestLen,
    BslCid contentType, uint8_t **signData, uint32_t *signDataLen)
{
    HITLS_X509_AttrEntry *ctAttr = NULL;
    int32_t ret = CreateContentTypeAttr(contentType, &ctAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = AddRequiredAttr(signerInfo->signedAttrs, ctAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    HITLS_X509_AttrEntry *mdAttr = NULL;
    ret = CreateMessageDigestAttr(digest, digestLen, &mdAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = AddRequiredAttr(signerInfo->signedAttrs, mdAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    HITLS_X509_AttrEntry *stAttr = NULL;
    ret = CreateSigningTimeAttr(&stAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // if failed, CreateSigningTimeAttr will free the attr
    ret = AddRequiredAttr(signerInfo->signedAttrs, stAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return EncodeSignedAttrsForSigning(signerInfo, signData, signDataLen);
}

// Generate signature
static int32_t GenerateSignature(const CRYPT_EAL_PkeyCtx *prvKey, int32_t mdId,
    uint8_t *signData, uint32_t signDataLen, BSL_Buffer *sigValue)
{
    uint32_t sigLen = CRYPT_EAL_PkeyGetSignLen(prvKey);
    if (sigLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

    uint8_t *sig = BSL_SAL_Calloc(sigLen, 1);
    if (sig == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = CRYPT_EAL_PkeySign(prvKey, mdId, signData, signDataLen, sig, &sigLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(sig);
        return ret;
    }

    sigValue->data = sig;
    sigValue->dataLen = sigLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t SignAndFinalize(CMS_SignedData *signedData, CMS_SignerInfo *signerInfo,
    const CRYPT_EAL_PkeyCtx *prvKey, uint8_t *signData, uint32_t signDataLen)
{
    // Generate signature
    int32_t ret = GenerateSignature(prvKey, signerInfo->digestAlg.id, signData, signDataLen, &signerInfo->sigValue);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    // Add digest algorithm if not exist
    ret = HITLS_CMS_AddMd(signedData->digestAlg, signerInfo->digestAlg.id);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    // Add SignerInfo to list
    ret = BSL_LIST_AddElement(signedData->signerInfos, signerInfo, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Update SignedData version
    signedData->version = GetSignedDataVersion(signedData);
    return HITLS_PKI_SUCCESS;
}

static int32_t ObtainSignParams(const BSL_Param *params, int32_t *version, int32_t *mdId, bool *isDetached,
    bool *hasSignedAttrs)
{
    if (params == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    const BSL_Param *param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_SIGNERINFO_VERSION);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_INT32 || param->valueLen != sizeof(int32_t) ||
        (*(int32_t *)param->value != HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1 &&
        *(int32_t *)param->value != HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        *version = *(int32_t *)param->value;
    }
    param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_DIGEST);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_INT32 || param->valueLen != sizeof(int32_t)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        *mdId = *(int32_t *)param->value;
    }
    param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_DETACHED);
    if (param != NULL && isDetached != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_BOOL || param->valueLen != sizeof(bool)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        *isDetached = *(bool *)param->value;
    }
    param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_NO_SIGNED_ATTRS);
    if (param != NULL && hasSignedAttrs != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_BOOL || param->valueLen != sizeof(bool)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        *hasSignedAttrs = !(*(bool *)param->value);
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t AddOptionalParams(CMS_SignedData *signedData, const BSL_Param *optionalParam)
{
    HITLS_X509_List *certs = NULL;
    HITLS_X509_List *crls = NULL;
    int32_t ret;
    const BSL_Param *param = BSL_PARAM_FindConstParam(optionalParam, HITLS_CMS_PARAM_CERT_LISTS);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_CTX_PTR || param->valueLen != sizeof(HITLS_X509_List *)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        certs = (HITLS_X509_List *)param->value;
    }
    param = BSL_PARAM_FindConstParam(optionalParam, HITLS_CMS_PARAM_CRL_LISTS);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_CTX_PTR || param->valueLen != sizeof(HITLS_X509_List *)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        crls = (HITLS_X509_List *)param->value;
    }

    for (HITLS_X509_Cert *addCert = BSL_LIST_GET_FIRST(certs); addCert != NULL; addCert = BSL_LIST_GET_NEXT(certs)) {
        ret = HITLS_CMS_AddCert(&signedData->certs, addCert);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    for (HITLS_X509_Crl *addCrl = BSL_LIST_GET_FIRST(crls); addCrl != NULL; addCrl = BSL_LIST_GET_NEXT(crls)) {
        ret = HITLS_CMS_AddCrl(&signedData->crls, addCrl);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t SignedDataCore(CMS_SignedData *signedData, CMS_SignerInfo *signerInfo, CRYPT_EAL_PkeyCtx *prvKey,
    uint8_t *digest, uint32_t digestLen, const BSL_Param *optionalParam)
{
    SetContentType(signedData);
    int32_t ret;
    bool needFree = false;
    uint8_t *signData = digest;
    uint32_t signDataLen = digestLen;
    if ((signerInfo->flag & HITLS_CMS_FLAG_NO_SIGNEDATTR) == 0) {
        // Ensure required attributes exist (content-type, message-digest, signing-time)
        ret = EnsureRequiredAttrsExist(signerInfo, digest, digestLen, signedData->encapCont.contentType,
            &signData, &signDataLen);
        if (ret != HITLS_PKI_SUCCESS) {
            HITLS_CMS_SignerInfoFree(signerInfo);
            return ret;
        }
        needFree = true;
    }
    // Encode signed attributes, generate signature
    ret = SignAndFinalize(signedData, signerInfo, prvKey, signData, signDataLen);
    if (needFree) {
        BSL_SAL_Free(signData);
    }
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_CMS_SignerInfoFree(signerInfo);
        return ret;
    }
    ret = AddOptionalParams(signedData, optionalParam);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    signedData->version = GetSignedDataVersion(signedData);
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckOrGetMdForPqc(CRYPT_PKEY_ParaId algId, bool hasSignedAttr, int32_t *mdId, bool isStream)
{
    if (!hasSignedAttr) {
        if (isStream) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC);
            return HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC;
        } else {
            int32_t md = HITLS_CMS_GetDefaultMlDsaDigestAlg((BslCid)algId, false);
            if (md != BSL_CID_UNKNOWN) {
                *mdId = md;
            }
            // RFC 9882: Validate digest algorithm for ML-DSA
            return HITLS_PKI_SUCCESS;
        }
    } else {
        return HITLS_CMS_ValidatePqcSignDigest((BslCid)algId, *(BslCid *)mdId);
    }
}

static int32_t CMS_CheckKeyAndGetMd(HITLS_X509_Cert *cert, CRYPT_EAL_PkeyCtx *prvKey, int32_t *mdId, bool isStream,
    bool hasSignedAttr)
{
    // Check if the private key matches the certificate's public key
    int32_t ret = HITLS_X509_CheckKey(cert, prvKey);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_PKEY_AlgId signAlgId = CRYPT_EAL_PkeyGetId(prvKey);
    // Check if the digest algorithm is supported
    if (HITLS_CMS_IsPqcSignAlg((BslCid)signAlgId)) {
        CRYPT_PKEY_ParaId algId = CRYPT_EAL_PkeyGetParaId(prvKey);
        if (algId == CRYPT_PKEY_PARAID_MAX) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
            return HITLS_CMS_ERR_INVALID_ALGO;
        }
        ret = CheckOrGetMdForPqc(algId, hasSignedAttr, mdId, isStream);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t CMS_GetOriginSignedData(CMS_SignedData *signedData, CMS_SignerInfo *signerInfo, BSL_Buffer *msg,
    BSL_Buffer *out)
{
    int32_t ret;
    if (!signedData->detached) {
        ret = HandleNonDetachedContent(signedData, msg);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    if ((signerInfo->flag & HITLS_CMS_FLAG_NO_SIGNEDATTR) != 0) {
        out->data = msg->data;
        out->dataLen = msg->dataLen;
        return HITLS_PKI_SUCCESS;
    } else {
        ret = CRYPT_EAL_ProviderMd(signedData->libCtx, signerInfo->digestAlg.id, signedData->attrName, msg->data,
            msg->dataLen, out->data, &out->dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
        return ret;
    }
}

int32_t HITLS_CMS_DataSign(HITLS_CMS *cms, CRYPT_EAL_PkeyCtx *prvKey, HITLS_X509_Cert *cert, BSL_Buffer *msg,
    const BSL_Param *optionalParam)
{
    if (cms == NULL || cms->ctx.signedData == NULL || cert == NULL || prvKey == NULL  || msg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CMS_SignedData *signedData = cms->ctx.signedData;
    if (signedData->flag == HITLS_CMS_FLAG_PARSE) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1; // default version is 1
    int32_t mdId = BSL_CID_UNKNOWN;
    bool hasSignedAttr = true;
    int32_t ret;
    if (BSL_LIST_COUNT(signedData->digestAlg) > 0) {
        ret = ObtainSignParams(optionalParam, &version, &mdId, NULL, &hasSignedAttr);
    } else {
        ret = ObtainSignParams(optionalParam, &version, &mdId, &signedData->detached, &hasSignedAttr);
    }
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Verify that the private key matches the certificate's public key
    ret = CMS_CheckKeyAndGetMd(cert, prvKey, &mdId, false, hasSignedAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CMS_SignerInfo *signerInfo = NULL;
    ret = CreateAndConfigSigner(prvKey, version, cert, mdId, hasSignedAttr, &signerInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    uint8_t digest[MAX_DIGEST_SIZE];
    uint32_t digestLen = sizeof(digest);
    BSL_Buffer signedBuf = {
        .data = digest,
        .dataLen = digestLen
    };
    ret = CMS_GetOriginSignedData(signedData, signerInfo, msg, &signedBuf);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_CMS_SignerInfoFree(signerInfo);
        return ret;
    }
    return SignedDataCore(signedData, signerInfo, prvKey, signedBuf.data, signedBuf.dataLen, optionalParam);
}

// Initialize MD context for all digest algorithms
static int32_t InitMdCtxForAlgs(CMS_SignedData *signedData, const BSL_Param *params)
{
    int32_t mdId = BSL_CID_UNKNOWN;
    int32_t ret;
    const BSL_Param *param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_DIGEST);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_INT32 || param->valueLen != sizeof(int32_t)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        mdId = *(int32_t *)param->value;
        ret = HITLS_CMS_AddMd(signedData->digestAlg, mdId);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    if (BSL_LIST_COUNT(signedData->digestAlg) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH);
        return HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH;
    }
    for (CMS_AlgId *alg = BSL_LIST_GET_FIRST(signedData->digestAlg); alg != NULL;
         alg = BSL_LIST_GET_NEXT(signedData->digestAlg)) {
        if (alg->mdCtx != NULL) {
            CRYPT_EAL_MdFreeCtx(alg->mdCtx);
            alg->mdCtx = NULL;
        }

        alg->mdCtx = CRYPT_EAL_ProviderMdNewCtx(signedData->libCtx, alg->id, signedData->attrName);
        if (alg->mdCtx == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }

        ret = CRYPT_EAL_MdInit(alg->mdCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckSignature(HITLS_X509_Asn1AlgId *alg, CRYPT_EAL_PkeyCtx *pubKey, int32_t hashId, uint8_t *msg,
    uint32_t msgLen, uint8_t *signature, uint32_t signatureLen)
{
    int32_t ret = HITLS_PKI_SUCCESS;
    CRYPT_EAL_PkeyCtx *verifyPubKey = CRYPT_EAL_PkeyDupCtx(pubKey);
    if (verifyPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_DUP_PUBKEY);
        return HITLS_X509_ERR_VFY_DUP_PUBKEY;
    }
    ret = HITLS_X509_CtrlAlgInfo(verifyPubKey, hashId, alg);
    if (ret != HITLS_PKI_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(verifyPubKey);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyVerify(verifyPubKey, hashId, msg, msgLen, signature, signatureLen);
    CRYPT_EAL_PkeyFreeCtx(verifyPubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t CheckSignerCert(HITLS_X509_Cert *cert, uint8_t *msg, uint32_t msgLen, CMS_SignerInfo *signerInfo)
{
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    // Obtaining the Public Key of the Certificate
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &pubKey, sizeof(CRYPT_EAL_PkeyCtx *));
    if (ret != HITLS_PKI_SUCCESS || pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_OBTAIN_PUB_FAILED);
        return HITLS_CMS_ERR_SIGNEDDATA_OBTAIN_PUB_FAILED;
    }
    if (signerInfo->signData.data != NULL && signerInfo->signData.dataLen > 0) {
        uint8_t *data = NULL;
        uint32_t dataLen = 0;
        BSL_ASN1_Buffer asnArr = {
            .tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
            .buff = signerInfo->signData.data,
            .len = signerInfo->signData.dataLen
        };
        BSL_ASN1_TemplateItem nameTemplItem = { BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, 0, 0};
        BSL_ASN1_Template nameTempl = {&nameTemplItem, 1};
        ret = BSL_ASN1_EncodeTemplate(&nameTempl, &asnArr, 1, &data, &dataLen);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            CRYPT_EAL_PkeyFreeCtx(pubKey);
            return ret;
        }
        ret = CheckSignature(&signerInfo->sigAlg, pubKey, signerInfo->digestAlg.id, data, dataLen,
            signerInfo->sigValue.data, signerInfo->sigValue.dataLen);
        BSL_SAL_FREE(data);
    } else {
        ret = CheckSignature(&signerInfo->sigAlg, pubKey, signerInfo->digestAlg.id, msg, msgLen,
            signerInfo->sigValue.data, signerInfo->sigValue.dataLen);
    }
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    return ret;
}

typedef int32_t (*CMS_AttrDecoder)(HITLS_X509_AttrEntry *attr, void *out);

static int32_t CMS_AttrDecodeMessageDigest(HITLS_X509_AttrEntry *attr, void *out)
{
    BSL_Buffer *buff = (BSL_Buffer *)out;
    buff->data = attr->attrValue.buff;
    buff->dataLen = attr->attrValue.len;
    uint32_t tempLen = attr->attrValue.len;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &buff->data, &tempLen, &buff->dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (buff->data == NULL || buff->dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_INVALID_ATTR);
        return HITLS_CMS_ERR_SIGNEDDATA_INVALID_ATTR;
    }
    return HITLS_PKI_SUCCESS;
}

// Decoder: extract OBJECT IDENTIFIER and map to BslCid into *(BslCid*)out
static int32_t CMS_AttrDecodeContentType(HITLS_X509_AttrEntry *attr, void *out)
{
    uint8_t *buff = attr->attrValue.buff;
    uint32_t buffLen = attr->attrValue.len;
    uint32_t tempLen = attr->attrValue.len;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OBJECT_ID, &buff, &tempLen, &buffLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(buff, buffLen);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_INVALID_ATTR);
        return HITLS_CMS_ERR_SIGNEDDATA_INVALID_ATTR;
    }
    *(BslCid *)out = cid;
    return HITLS_PKI_SUCCESS;
}

// Find attribute by CID in signedAttrs list and decode via callback
static int32_t CMS_DecodeAttr(HITLS_X509_Attrs *attrs, BslCid attrCid, CMS_AttrDecoder attrDecode, void *out)
{
    for (HITLS_X509_AttrEntry *node = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(attrs->list);
         node != NULL; node = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(attrs->list)) {
        if (node->cid == attrCid) {
            return attrDecode(node, out);
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_SIGNERINFO_ATTR);
    return HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_SIGNERINFO_ATTR;
}

// Check if certificate matches signerInfo by SKI or DN
static int32_t IsCertMatchingSignerInfo(HITLS_X509_Cert *cert, CMS_SignerInfo *signerInfo)
{
    int32_t ret;
    if (signerInfo->version == HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3) {
        // Check by SKI first
        HITLS_X509_ExtSki ski = {0};
        ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki));
        if (ret == HITLS_PKI_SUCCESS && ski.kid.data != NULL && ski.kid.dataLen > 0) {
            // ski exist, and ski is no need to be free.
            if (ski.kid.dataLen == signerInfo->subjectKeyId.kid.dataLen &&
                memcmp(ski.kid.data, signerInfo->subjectKeyId.kid.data, ski.kid.dataLen) == 0) {
                return HITLS_PKI_SUCCESS;
            }
        }
    }
    // Check by DN and serial number
    if (signerInfo->version == HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1) {
        BSL_Buffer certDnBuff = {0};
        BSL_Buffer signerDnBuff = {0};
        BSL_Buffer serialNum = {0};
        ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN_STR, &certDnBuff, sizeof(BSL_Buffer));
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        ret = HITLS_X509_GetDistinguishNameStrFromList(signerInfo->issuerName, &signerDnBuff);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_SAL_FREE(certDnBuff.data);
            return ret;
        }
        ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &serialNum, sizeof(BSL_Buffer));
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_SAL_FREE(certDnBuff.data);
            BSL_SAL_FREE(signerDnBuff.data);
            return ret;
        }
        bool matched = (certDnBuff.dataLen == signerDnBuff.dataLen &&
            memcmp(certDnBuff.data, signerDnBuff.data, certDnBuff.dataLen) == 0) && (
            serialNum.dataLen == signerInfo->certSerialNum.dataLen &&
            memcmp(serialNum.data, signerInfo->certSerialNum.data, serialNum.dataLen) == 0);
        BSL_SAL_FREE(certDnBuff.data);
        BSL_SAL_FREE(signerDnBuff.data);
        return matched ? HITLS_PKI_SUCCESS : HITLS_CMS_ERR_CERT_NOT_MATCH_SIGNERINFO;
    }
    return HITLS_CMS_ERR_CERT_NOT_MATCH_SIGNERINFO;
}

static int32_t BuildCertChain(HITLS_X509_List **chain, HITLS_X509_Cert *deviceCert,
    HITLS_X509_List *p7certs, HITLS_X509_List *untrustCerts)
{
    int32_t ret = HITLS_CMS_AddCert(chain, deviceCert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    for (HITLS_X509_Cert *cert = BSL_LIST_GET_FIRST(p7certs); cert != NULL; cert = BSL_LIST_GET_NEXT(p7certs)) {
        ret = HITLS_CMS_AddCert(chain, cert);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    for (HITLS_X509_Cert *cert = BSL_LIST_GET_FIRST(untrustCerts); cert != NULL;
         cert = BSL_LIST_GET_NEXT(untrustCerts)) {
        ret = HITLS_CMS_AddCert(chain, cert);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}

typedef struct {
    uint64_t flags;
    HITLS_X509_List *untrustCerts;
    HITLS_X509_List *caCerts;
} ChainVerifyParam;

static int32_t CheckCertIsValid(HITLS_X509_Cert *deviceCert, HITLS_X509_List *p7certs, HITLS_X509_List *crls,
    ChainVerifyParam *verifyParam)
{
    int32_t ret;
    int32_t purpose = HITLS_X509_VFY_PURPOSE_EMAIL_SIGN;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    if (storeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    // Set CRL list to StoreCtx
    for (HITLS_X509_Crl *crl = BSL_LIST_GET_FIRST(crls); crl != NULL; crl = BSL_LIST_GET_NEXT(crls)) {
        ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_CRL, crl, 0);
        if (ret != HITLS_PKI_SUCCESS) {
            goto ERR;
        }
    }
    // Set CA list to StoreCtx
    for (HITLS_X509_Cert *cert = BSL_LIST_GET_FIRST(verifyParam->caCerts); cert != NULL;
         cert = BSL_LIST_GET_NEXT(verifyParam->caCerts)) {
        ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert, 0);
        if (ret != HITLS_PKI_SUCCESS) {
            goto ERR;
        }
    }
    ret = BuildCertChain(&chain, deviceCert, p7certs, verifyParam->untrustCerts);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_PARAM_FLAGS, &verifyParam->flags,
        sizeof(verifyParam->flags));
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_PURPOSE, &purpose, sizeof(purpose));
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = HITLS_X509_CertVerify(storeCtx, chain);
ERR:
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

static int32_t VerifyCertChainAndSignature(HITLS_X509_Cert *cert, CMS_SignedData *sigData,
    BSL_Buffer *msgBuff, CMS_SignerInfo *signerInfo, ChainVerifyParam *verifyParam)
{
    int ret = IsCertMatchingSignerInfo(cert, signerInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = CheckCertIsValid(cert, sigData->certs, sigData->crls, verifyParam);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    return CheckSignerCert(cert, msgBuff->data, msgBuff->dataLen, signerInfo);
}

static int32_t VerifySignedData(CMS_SignedData *sigData, BSL_Buffer *msgBuff, CMS_SignerInfo *signerInfo,
    ChainVerifyParam *verifyParam)
{
    int32_t ret = HITLS_CMS_ERR_CERT_NOT_MATCH_SIGNERINFO; // that the cert is not matched with the signerInfo
    HITLS_X509_List *certs = sigData->certs;
    HITLS_X509_Cert *cert = BSL_LIST_GET_FIRST(certs);
    while (cert != NULL) {
        ret = VerifyCertChainAndSignature(cert, sigData, msgBuff, signerInfo, verifyParam);
        if (ret == HITLS_PKI_SUCCESS) {
            return HITLS_PKI_SUCCESS;
        }
        if (ret != HITLS_CMS_ERR_CERT_NOT_MATCH_SIGNERINFO) {
            return ret;
        }
        cert = (HITLS_X509_Cert *)BSL_LIST_GET_NEXT(certs);
    }
    // if cms has no matched certs, try to find in untrustCerts.
    cert = (HITLS_X509_Cert *)BSL_LIST_GET_FIRST(verifyParam->untrustCerts);
    while (cert != NULL) {
        ret = VerifyCertChainAndSignature(cert, sigData, msgBuff, signerInfo, verifyParam);
        if (ret == HITLS_PKI_SUCCESS) {
            return HITLS_PKI_SUCCESS;
        }
        if (ret != HITLS_CMS_ERR_CERT_NOT_MATCH_SIGNERINFO) {
            return ret;
        }
        cert = (HITLS_X509_Cert *)BSL_LIST_GET_NEXT(verifyParam->untrustCerts);
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_CERT);
    return HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_CERT;
}

static int32_t CheckSignerInfoAttrs(CMS_SignedData *sigData, CMS_SignerInfo *si, BSL_Buffer *buff, CMS_AlgId *digestAlg)
{
    if (si->signedAttrs == NULL || BSL_LIST_COUNT(si->signedAttrs->list) == 0) {
        return HITLS_PKI_SUCCESS;
    }
    int32_t ret = HITLS_PKI_SUCCESS;
    BslCid cid = BSL_CID_UNKNOWN;
    ret = CMS_DecodeAttr(si->signedAttrs, BSL_CID_PKCS9_AT_CONTENTTYPE, CMS_AttrDecodeContentType, &cid);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // the content-type attribute must match the signeddate encapContenType value.
    if (cid != (BslCid)sigData->encapCont.contentType) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ENCAPCONT_TYPE);
        return HITLS_CMS_ERR_ENCAPCONT_TYPE;
    }
    BSL_Buffer targetHash = {0};
    // get hash from signerInfo
    ret = CMS_DecodeAttr(si->signedAttrs, BSL_CID_PKCS9_AT_MESSAGEDIGEST, CMS_AttrDecodeMessageDigest, &targetHash);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (digestAlg != NULL) {
        uint8_t hash[MAX_DIGEST_SIZE];
        uint32_t hashLen = sizeof(hash);
        ret = CRYPT_EAL_ProviderMd(sigData->libCtx, digestAlg->id, sigData->attrName, buff->data, buff->dataLen,
            hash, &hashLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        if (targetHash.dataLen != hashLen || memcmp(targetHash.data, hash, hashLen) != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_MSG_HASH_MISMATCH);
            return HITLS_CMS_ERR_SIGNEDDATA_MSG_HASH_MISMATCH;
        }
    } else {
        // The hash calculation in the streaming verif has been completed.
        if (buff->dataLen != targetHash.dataLen || memcmp(buff->data, targetHash.data, targetHash.dataLen) != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_MSG_HASH_MISMATCH);
            return HITLS_CMS_ERR_SIGNEDDATA_MSG_HASH_MISMATCH;
        }
    }
    return HITLS_PKI_SUCCESS;
}

// Compare CMS_AlgId with a uint32_t algorithm ID
static int32_t CmpAlgId(const CMS_AlgId *algId, const int32_t *mdId)
{
    return (algId->id == *mdId) ? 0 : 1;
}

static int32_t VerifySignerInfo(CMS_SignedData *sigData, CMS_SignerInfo *si, BSL_Buffer *msgBuff,
    ChainVerifyParam *verifyParam)
{
    if (si->signedAttrs == NULL || BSL_LIST_COUNT(si->signedAttrs->list) == 0) {
        if (sigData->encapCont.contentType != BSL_CID_PKCS7_SIMPLEDATA) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ENCAPCONT_TYPE);
            return HITLS_CMS_ERR_ENCAPCONT_TYPE;
        }
    }
    // Check if signerInfo's digest algorithm is in SignedData's digestAlgorithms list
    CMS_AlgId *alg = (CMS_AlgId *)BSL_LIST_Search(sigData->digestAlg, &si->digestAlg.id,
        (BSL_LIST_PFUNC_CMP)CmpAlgId, NULL);
    if (alg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH);
        return HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH;
    }
    int32_t ret = CheckSignerInfoAttrs(sigData, si, msgBuff, &si->digestAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    return VerifySignedData(sigData, msgBuff, si, verifyParam);
}

// Validate and get message content for verification
static int32_t GetVerifyMsgContent(CMS_SignedData *sigData, const BSL_Buffer *msg, BSL_Buffer *finalDataBuff)
{
    if ((msg == NULL || msg->data == NULL || msg->dataLen == 0) && sigData->detached) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_CONTENT);
        return HITLS_CMS_ERR_SIGNEDDATA_NO_CONTENT;
    }
    if (msg != NULL && msg->data != NULL && msg->dataLen != 0 && !sigData->detached) {
        if (msg->dataLen != sigData->encapCont.content.dataLen ||
            memcmp(msg->data, sigData->encapCont.content.data, msg->dataLen) != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_CONTENT_MISMATCH);
            return HITLS_CMS_ERR_SIGNEDDATA_CONTENT_MISMATCH;
        }
    }
    finalDataBuff->data = sigData->detached ? msg->data : sigData->encapCont.content.data;
    finalDataBuff->dataLen = sigData->detached ? msg->dataLen : sigData->encapCont.content.dataLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckPqcSignAlgAndDigest(CMS_SignerInfo *si, bool isStream)
{
    bool hasSignedAttr = (si->signedAttrs != NULL && BSL_LIST_COUNT(si->signedAttrs->list) > 0);
    if (!hasSignedAttr) {
        if (isStream) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC);
            return HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC;
        } else {
            if (si->digestAlg.id != BSL_CID_SHA512) {
                BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_MLDSA_ERROR_DIGEST);
                return HITLS_CMS_ERR_MLDSA_ERROR_DIGEST;
            }
        }
    } else {
        int32_t ret = HITLS_CMS_ValidatePqcSignDigest((BslCid)si->sigAlg.algId, (BslCid)si->digestAlg.id);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t VerifyParamCheckForPqc(HITLS_CMS *cms, bool isStream)
{
    CMS_SignedData *signedData = cms->ctx.signedData;
    for (CMS_SignerInfo *si = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(signedData->signerInfos); si != NULL;
         si = (CMS_SignerInfo *)BSL_LIST_GET_NEXT(signedData->signerInfos)) {
        if (HITLS_CMS_IsPqcSignAlg((BslCid)si->sigAlg.algId)) {
            int32_t ret = CheckPqcSignAlgAndDigest(si, isStream);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t VerifyParamCheck(HITLS_CMS *cms, bool isStream)
{
    if (cms == NULL || cms->ctx.signedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CMS_SignedData *signedData = cms->ctx.signedData;
    if (BSL_LIST_COUNT(signedData->signerInfos) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_SIGNERINFO);
        return HITLS_CMS_ERR_SIGNEDDATA_NO_SIGNERINFO;
    }
    // Check version
    if (GetSignedDataVersion(signedData) != signedData->version) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERSION_INVALID);
        return HITLS_CMS_ERR_VERSION_INVALID;
    }
    return VerifyParamCheckForPqc(cms, isStream);
}

static int32_t InitVerifyParam(const BSL_Param *params, ChainVerifyParam *verifyParam)
{
    if (params == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    const BSL_Param *param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_CTX_PTR) {
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        verifyParam->untrustCerts = (HITLS_X509_List *)param->value;
    }
    param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_CA_CERT_LISTS);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_CTX_PTR) {
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        verifyParam->caCerts = (HITLS_X509_List *)param->value;
    }
    param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_STORE_FLAGS);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_UINT64) {
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        verifyParam->flags = *(uint64_t *)param->value;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_CMS_DataVerify(HITLS_CMS *cms, BSL_Buffer *msg, const BSL_Param *inputParam, BSL_Buffer *output)
{
    int32_t ret = VerifyParamCheck(cms, false);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    CMS_SignedData *signedData = cms->ctx.signedData;
    BSL_Buffer finalDataBuff = {0};
    ret = GetVerifyMsgContent(signedData, msg, &finalDataBuff);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ChainVerifyParam verifyParam = {0};
    ret = InitVerifyParam(inputParam, &verifyParam);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Extract StoreCtx from param if provided
    for (CMS_SignerInfo *si = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(signedData->signerInfos); si != NULL;
         si = (CMS_SignerInfo *)BSL_LIST_GET_NEXT(signedData->signerInfos)) {
        ret = VerifySignerInfo(signedData, si, &finalDataBuff, &verifyParam);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    if (output != NULL) {
        if (output->data != NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
            return HITLS_CMS_ERR_INVALID_DATA;
        }
        output->data = BSL_SAL_Dump(finalDataBuff.data, finalDataBuff.dataLen);
        if (output->data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        output->dataLen = finalDataBuff.dataLen;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t StreamVerifyParamCheck(HITLS_CMS *cms)
{
    int32_t ret = VerifyParamCheck(cms, true);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    CMS_SignedData *signedData = cms->ctx.signedData;
    // Streaming verification can only be used for detached SignedData
    if (!signedData->detached) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_IS_NOT_DETACHED_SIGNEDDATA);
        return HITLS_CMS_ERR_IS_NOT_DETACHED_SIGNEDDATA;
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t SignedData_SignInit(HITLS_CMS *cms, const BSL_Param *params)
{
    if (cms == NULL || cms->ctx.signedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CMS_SignedData *signedData = cms->ctx.signedData;
    if (signedData->flag == HITLS_CMS_FLAG_PARSE) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if (!signedData->detached) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_IS_NOT_DETACHED_SIGNEDDATA);
        return HITLS_CMS_ERR_IS_NOT_DETACHED_SIGNEDDATA;
    }

    int32_t ret = InitMdCtxForAlgs(signedData, params);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (BSL_LIST_COUNT(signedData->signerInfos) > 0) {
        BSL_LIST_DeleteAll(signedData->signerInfos, (BSL_LIST_PFUNC_FREE)HITLS_CMS_SignerInfoFree);
    }
    if (BSL_LIST_COUNT(signedData->certs) > 0) {
        BSL_LIST_DeleteAll(signedData->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    if (BSL_LIST_COUNT(signedData->crls) > 0) {
        BSL_LIST_DeleteAll(signedData->crls, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    }
    // Update state to INITIALIZED
    signedData->state = HITLS_CMS_SIGN_INIT;
    return HITLS_PKI_SUCCESS;
}

static int32_t SignedData_SignUpdate(HITLS_CMS *cms, const BSL_Buffer *msg)
{
    HITLS_X509_List *digestAlg = cms->ctx.signedData->digestAlg;
    if (digestAlg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH);
        return HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH;
    }
    int32_t ret = HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH;
    for (CMS_AlgId *alg = BSL_LIST_GET_FIRST(digestAlg); alg != NULL; alg = BSL_LIST_GET_NEXT(digestAlg)) {
        if (alg->mdCtx == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_CTX_IS_NOT_INIT);
            return HITLS_CMS_ERR_CTX_IS_NOT_INIT;
        }
        ret = CRYPT_EAL_MdUpdate(alg->mdCtx, msg->data, msg->dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return ret;
}

// Get digest from MD context
static int32_t GetDigestValue(CRYPT_EAL_MdCTX *mdCtx, uint8_t *hash, uint32_t *hashLen)
{
    CRYPT_EAL_MdCTX *tmp = CRYPT_EAL_MdDupCtx(mdCtx);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_MdFinal(tmp, hash, hashLen);
    CRYPT_EAL_MdFreeCtx(tmp);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

// Get digest from MD context for specified algorithm
static int32_t GetDigestFromMdCtx(HITLS_X509_List *digestAlg, int32_t mdId, uint8_t *digest, uint32_t *digestLen)
{
    uint8_t tmpDigest[MAX_DIGEST_SIZE];
    uint32_t tmpDigestLen;
    for (CMS_AlgId *alg = BSL_LIST_GET_FIRST(digestAlg); alg != NULL; alg = BSL_LIST_GET_NEXT(digestAlg)) {
        if (alg->id == mdId) {
            tmpDigestLen = MAX_DIGEST_SIZE;
            int32_t ret = GetDigestValue(alg->mdCtx, tmpDigest, &tmpDigestLen);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
            (void)memcpy_s(digest, MAX_DIGEST_SIZE, tmpDigest, tmpDigestLen);
            *digestLen = tmpDigestLen;
            return HITLS_PKI_SUCCESS;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH);
    return HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH;
}

static int32_t GetSignFinalParams(const BSL_Param *params, CRYPT_EAL_PkeyCtx **prvKey, HITLS_X509_Cert **cert)
{
    const BSL_Param *param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_PRIVATE_KEY);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_CTX_PTR || param->valueLen != sizeof(CRYPT_EAL_PkeyCtx *)
        || param->value == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        *prvKey = (CRYPT_EAL_PkeyCtx *)param->value;
    }

    param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_DEVICE_CERT);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_CTX_PTR || param->valueLen != sizeof(HITLS_X509_Cert *)
        || param->value == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        *cert = (HITLS_X509_Cert *)param->value;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t SignedData_SignFinal(HITLS_CMS *cms, const BSL_Param *optionalParam)
{
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = GetSignFinalParams(optionalParam, &prvKey, &cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    CMS_SignedData *signedData = cms->ctx.signedData;
    if (signedData->flag == HITLS_CMS_FLAG_PARSE) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1; // default version is 1
    int32_t mdId = BSL_CID_UNKNOWN;
    bool hasSignedAttr = true;
    ret = ObtainSignParams(optionalParam, &version, &mdId, NULL, &hasSignedAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // Verify that the private key matches the certificate's public key
    ret = CMS_CheckKeyAndGetMd(cert, prvKey, &mdId, true, hasSignedAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_X509_List *digestAlg = signedData->digestAlg;
    if (BSL_LIST_COUNT(digestAlg) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH);
        return HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH;
    }

    uint8_t digest[MAX_DIGEST_SIZE];
    uint32_t digestLen = 0;
    ret = GetDigestFromMdCtx(digestAlg, mdId, digest, &digestLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    CMS_SignerInfo *signerInfo = NULL;
    ret = CreateAndConfigSigner(prvKey, version, cert, mdId, hasSignedAttr, &signerInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = SignedDataCore(signedData, signerInfo, prvKey, digest, digestLen, optionalParam);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    signedData->state = HITLS_CMS_SIGN_FINISHED;
    return HITLS_PKI_SUCCESS;
}

static int32_t SignedData_VerifyInit(HITLS_CMS *cms)
{
    int32_t ret = StreamVerifyParamCheck(cms);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    CMS_SignedData *signedData = cms->ctx.signedData;
    HITLS_X509_List *digestAlg = signedData->digestAlg;
    if (BSL_LIST_COUNT(digestAlg) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH);
        return HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH;
    }
    ret = InitMdCtxForAlgs(signedData, NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    signedData->state = HITLS_CMS_VERIFY_INIT;
    return HITLS_PKI_SUCCESS;
}

static int32_t SignedData_VerifyUpdate(HITLS_CMS *cms, const BSL_Buffer *msg)
{
    int32_t ret = StreamVerifyParamCheck(cms);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return SignedData_SignUpdate(cms, msg);
}

// Verify all SignerInfos
static int32_t VerifyAllSignerInfos(CMS_SignedData *signedData, ChainVerifyParam *verifyParam)
{
    CMS_SignerInfos *signerInfos = signedData->signerInfos;
    BSL_Buffer finalDataBuff = {0};
    if (signerInfos == NULL || BSL_LIST_COUNT(signerInfos) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_SIGNERINFO);
        return HITLS_CMS_ERR_SIGNEDDATA_NO_SIGNERINFO;
    }

    for (CMS_SignerInfo *si = BSL_LIST_GET_FIRST(signerInfos); si != NULL; si = BSL_LIST_GET_NEXT(signerInfos)) {
        if (si->signedAttrs == NULL || BSL_LIST_COUNT(si->signedAttrs->list) == 0) {
            if (signedData->encapCont.contentType != BSL_CID_PKCS7_SIMPLEDATA) {
                BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ENCAPCONT_TYPE);
                return HITLS_CMS_ERR_ENCAPCONT_TYPE;
            }
        }

        CMS_AlgId *alg = (CMS_AlgId *)BSL_LIST_Search(signedData->digestAlg, &si->digestAlg.id,
            (BSL_LIST_PFUNC_CMP)CmpAlgId, NULL);
        if (alg == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH);
            return HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH;
        }
        uint8_t hash[MAX_DIGEST_SIZE];
        uint32_t hashLen = MAX_DIGEST_SIZE;
        BSL_Buffer hashBuff = {.data = hash, .dataLen = hashLen};
        int32_t ret = GetDigestValue(alg->mdCtx, hashBuff.data, &hashBuff.dataLen);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }

        ret = CheckSignerInfoAttrs(signedData, si, &hashBuff, NULL);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }

        ret = VerifySignedData(signedData, &finalDataBuff, si, verifyParam);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t SignedData_VerifyFinal(HITLS_CMS *cms, const BSL_Param *inputParam)
{
    int32_t ret = StreamVerifyParamCheck(cms);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    CMS_SignedData *signedData = cms->ctx.signedData;
    ChainVerifyParam verifyParam = {0};
    ret = InitVerifyParam(inputParam, &verifyParam);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return VerifyAllSignerInfos(signedData, &verifyParam);
}

int32_t HITLS_CMS_SignedDataInit(HITLS_CMS *cms, int32_t option, const BSL_Param *param)
{
    if (option == HITLS_CMS_OPT_SIGN) {
        return SignedData_SignInit(cms, param);
    } else if (option == HITLS_CMS_OPT_VERIFY) {
        return SignedData_VerifyInit(cms);
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
    return HITLS_CMS_ERR_INVALID_STATE;
}

int32_t HITLS_CMS_SignedDataUpdate(HITLS_CMS *cms, const BSL_Buffer *input)
{
    if (cms->dataType != BSL_CID_PKCS7_SIGNEDDATA || cms->ctx.signedData == NULL || input == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    if (!cms->ctx.signedData->detached) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_IS_NOT_DETACHED_SIGNEDDATA);
        return HITLS_CMS_ERR_IS_NOT_DETACHED_SIGNEDDATA;
    }

    if (cms->ctx.signedData->state == HITLS_CMS_SIGN_INIT) {
        return SignedData_SignUpdate(cms, input);
    } else if (cms->ctx.signedData->state == HITLS_CMS_VERIFY_INIT) {
        return SignedData_VerifyUpdate(cms, input);
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
    return HITLS_CMS_ERR_INVALID_STATE;
}

int32_t HITLS_CMS_SignedDataFinal(HITLS_CMS *cms, const BSL_Param *param)
{
    if (cms == NULL || cms->dataType != BSL_CID_PKCS7_SIGNEDDATA || cms->ctx.signedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    if (!cms->ctx.signedData->detached) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_IS_NOT_DETACHED_SIGNEDDATA);
        return HITLS_CMS_ERR_IS_NOT_DETACHED_SIGNEDDATA;
    }
    if ((cms->ctx.signedData->state == HITLS_CMS_SIGN_INIT) ||
        (cms->ctx.signedData->state == HITLS_CMS_SIGN_FINISHED)) {
        return SignedData_SignFinal(cms, param);
    } else if ((cms->ctx.signedData->state == HITLS_CMS_VERIFY_INIT) ||
        (cms->ctx.signedData->state == HITLS_CMS_VERIFY_FINISHED)) {
        return SignedData_VerifyFinal(cms, param);
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
    return HITLS_CMS_ERR_INVALID_STATE;
}

#endif // HITLS_PKI_CMS_SIGNEDDATA
