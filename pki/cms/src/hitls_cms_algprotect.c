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
#include <string.h>
#include "bsl_asn1_internal.h"
#include "bsl_err_internal.h"
#include "bsl_list.h"
#include "bsl_params.h"
#include "bsl_sal.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_params.h"
#include "hitls_pki_x509.h"
#include "hitls_cms_algprotect.h"
#include "hitls_cms_util.h"

/* RFC 6211 Section 2: CMSAlgorithmProtection is a SEQUENCE containing a
 * digestAlgorithm and exactly one implicitly tagged signatureAlgorithm [1]
 * or macAlgorithm [2].
 */
static BSL_ASN1_TemplateItem g_algorithmProtectionTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1,
         BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2,
         BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
};

typedef enum {
    HITLS_CMS_ALGORITHM_PROTECTION_DIGESTALG_IDX,
    HITLS_CMS_ALGORITHM_PROTECTION_SIGNALG_IDX,
    HITLS_CMS_ALGORITHM_PROTECTION_MACALG_IDX,
    HITLS_CMS_ALGORITHM_PROTECTION_MAX_IDX,
} HITLS_CMS_ALGORITHM_PROTECTION_IDX;

static int32_t ParseSignAlgorithmIdentifier(BSL_ASN1_Buffer *asn, HITLS_X509_Asn1AlgId *algId)
{
    if (asn->buff == NULL || asn->len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }

    BSL_ASN1_Buffer algOid = {0};
    BSL_ASN1_Buffer param = {0};
    uint8_t *temp = asn->buff;
    uint32_t tempLen = asn->len;
    int32_t ret = BSL_ASN1_DecodeItem(&temp, &tempLen, &algOid);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (algOid.tag != BSL_ASN1_TAG_OBJECT_ID) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if (tempLen != 0) {
        ret = BSL_ASN1_DecodeItem(&temp, &tempLen, &param);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (tempLen != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
            return HITLS_CMS_ERR_INVALID_DATA;
        }
    }
    ret = HITLS_X509_ParseSignAlgInfo(&algOid, &param, algId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t CMS_ParseAlgorithmProtection(const BSL_Buffer *attrValue, CMS_AlgorithmProtection *algProtect)
{
    if (attrValue->data == NULL || attrValue->dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    uint8_t *temp = attrValue->data;
    uint32_t tempLen = attrValue->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_CMS_ALGORITHM_PROTECTION_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_algorithmProtectionTempl,
        sizeof(g_algorithmProtectionTempl) / sizeof(g_algorithmProtectionTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1,
        HITLS_CMS_ALGORITHM_PROTECTION_MAX_IDX);
    /* RFC 6211 Section 2: the attribute SET OF must contain exactly one value. */
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (tempLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    ret = CMS_ParseAlgIdInfo(&asn1[HITLS_CMS_ALGORITHM_PROTECTION_DIGESTALG_IDX], false,
        &algProtect->digestAlgorithm);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    /* RFC 6211 Section 2: presence is determined by the ASN.1 field, and
     * exactly one of signatureAlgorithm or macAlgorithm SHALL be present.
     */
    if ((asn1[HITLS_CMS_ALGORITHM_PROTECTION_SIGNALG_IDX].buff == NULL) ==
        (asn1[HITLS_CMS_ALGORITHM_PROTECTION_MACALG_IDX].buff == NULL)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if (asn1[HITLS_CMS_ALGORITHM_PROTECTION_SIGNALG_IDX].buff != NULL) {
        return ParseSignAlgorithmIdentifier(&asn1[HITLS_CMS_ALGORITHM_PROTECTION_SIGNALG_IDX],
            &algProtect->signatureAlgorithm);
    } else {
        return CMS_ParseAlgIdInfo(&asn1[HITLS_CMS_ALGORITHM_PROTECTION_MACALG_IDX], false,
            &algProtect->macAlgorithm);
    }
}

int32_t CMS_EncodeAlgorithmProtection(const CMS_AlgorithmProtection *algProtect, BSL_Buffer *encode)
{
    /* RFC 6211 Section 2: exactly one of signatureAlgorithm or macAlgorithm is present. */
    if ((algProtect->signatureAlgorithm.algId == BSL_CID_UNKNOWN) ==
        (algProtect->macAlgorithm.id == BSL_CID_UNKNOWN)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }

    BSL_ASN1_Buffer asn1[HITLS_CMS_ALGORITHM_PROTECTION_MAX_IDX] = {0};
    int32_t ret = CMS_EncodeAlgIdInfo(&algProtect->digestAlgorithm,
        &asn1[HITLS_CMS_ALGORITHM_PROTECTION_DIGESTALG_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (algProtect->signatureAlgorithm.algId != BSL_CID_UNKNOWN) {
        HITLS_X509_Asn1AlgId signAlg = algProtect->signatureAlgorithm;
        ret = HITLS_X509_EncodeSignAlgInfo(&signAlg, &asn1[HITLS_CMS_ALGORITHM_PROTECTION_SIGNALG_IDX]);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
        asn1[HITLS_CMS_ALGORITHM_PROTECTION_SIGNALG_IDX].tag =
            BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1;
    } else {
        ret = CMS_EncodeAlgIdInfo(&algProtect->macAlgorithm,
            &asn1[HITLS_CMS_ALGORITHM_PROTECTION_MACALG_IDX]);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
        asn1[HITLS_CMS_ALGORITHM_PROTECTION_MACALG_IDX].tag =
            BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2;
    }
    BSL_ASN1_Template templ = {g_algorithmProtectionTempl,
        sizeof(g_algorithmProtectionTempl) / sizeof(g_algorithmProtectionTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asn1, HITLS_CMS_ALGORITHM_PROTECTION_MAX_IDX,
        &encode->data, &encode->dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

EXIT:
    BSL_SAL_Free(asn1[HITLS_CMS_ALGORITHM_PROTECTION_DIGESTALG_IDX].buff);
    if (algProtect->signatureAlgorithm.algId != BSL_CID_UNKNOWN) {
        BSL_SAL_Free(asn1[HITLS_CMS_ALGORITHM_PROTECTION_SIGNALG_IDX].buff);
    } else {
        BSL_SAL_Free(asn1[HITLS_CMS_ALGORITHM_PROTECTION_MACALG_IDX].buff);
    }
    return ret;
}

int32_t CMS_CreateAlgorithmProtectionAttr(const CMS_SignerInfo *signerInfo, HITLS_X509_AttrEntry **outAttr)
{
    HITLS_X509_AttrEntry *attr = BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    if (attr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_X509_EncodeObjIdentity(BSL_CID_PKCS9_AT_ALGORITHM_PROTECTION, &attr->attrId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(attr);
        return ret;
    }

    /* RFC 6211 Section 2: a SignerInfo copy contains digestAlgorithm and
     * signatureAlgorithm, and the attribute is placed in signedAttrs.
     */
    CMS_AlgorithmProtection algProtect = {
        .digestAlgorithm = signerInfo->digestAlg,
        .signatureAlgorithm = signerInfo->sigAlg,
    };
    BSL_Buffer encode = {0};
    ret = CMS_EncodeAlgorithmProtection(&algProtect, &encode);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(attr);
        return ret;
    }
    attr->cid = BSL_CID_PKCS9_AT_ALGORITHM_PROTECTION;
    attr->attrValue.buff = encode.data;
    attr->attrValue.len = encode.dataLen;
    attr->attrValue.tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
    *outAttr = attr;
    return HITLS_PKI_SUCCESS;
}

int32_t CMS_GetAlgorithmProtection(const BSL_Param *params, CRYPT_PKEY_AlgId keyAlgId, bool *hasAlgProtection)
{
    /* RFC 9882 Section 4, RFC 9814 Section 5, and
     * draft-ietf-lamps-cms-composite-sigs-05 Section 5 recommend including
     * CMSAlgorithmProtection for these PQC signatures. The optional parameter
     * overrides this default.
     */
    bool result =( keyAlgId == CRYPT_PKEY_ML_DSA || keyAlgId == CRYPT_PKEY_SLH_DSA ||
        keyAlgId == CRYPT_PKEY_COMPOSITE);
    const BSL_Param *param = BSL_PARAM_FindConstParam(params, HITLS_CMS_PARAM_SET_ALG_PROTECTION);
    if (param != NULL) {
        if (param->valueType != BSL_PARAM_TYPE_BOOL || param->valueLen != sizeof(bool)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        result = *(bool *)param->value;
    }
    *hasAlgProtection = result;
    return HITLS_PKI_SUCCESS;
}

int32_t CMS_CheckAlgorithmProtectionAttr(CMS_SignerInfo *si)
{
    /* RFC 6211 Section 2: CMSAlgorithmProtection MUST be a signed attribute
     * and MUST NOT occur as an unsigned attribute.
     */
    if (si->unsignedAttrs != NULL) {
        for (HITLS_X509_AttrEntry *attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(si->unsignedAttrs->list);
            attr != NULL; attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(si->unsignedAttrs->list)) {
            if (attr->cid == BSL_CID_PKCS9_AT_ALGORITHM_PROTECTION) {
                BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_SIGNEDATTRS_INVALID);
                return HITLS_CMS_ERR_SIGNEDDATA_SIGNEDATTRS_INVALID;
            }
        }
    }

    if (si->signedAttrs == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    bool found = false;
    for (HITLS_X509_AttrEntry *attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(si->signedAttrs->list);
        attr != NULL; attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(si->signedAttrs->list)) {
        if (attr->cid != BSL_CID_PKCS9_AT_ALGORITHM_PROTECTION) {
            continue;
        }
        /* RFC 6211 Section 2: SignedAttributes MUST contain at most one
         * instance of CMSAlgorithmProtection.
         */
        if (found) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_SIGNEDATTRS_INVALID);
            return HITLS_CMS_ERR_SIGNEDDATA_SIGNEDATTRS_INVALID;
        }
        found = true;
    }
    return HITLS_PKI_SUCCESS;
}

static bool IsAlgParamEqual(const BSL_ASN1_Buffer *left, const BSL_ASN1_Buffer *right)
{
    /* RFC 6211 Section 3: NULL and omitted parameters may be treated as equal. */
    uint8_t leftTag = left->tag == BSL_ASN1_TAG_NULL ? 0 : left->tag;
    uint8_t rightTag = right->tag == BSL_ASN1_TAG_NULL ? 0 : right->tag;
    if ((leftTag == 0 && left->len != 0) || (rightTag == 0 && right->len != 0)) {
        return false;
    }
    if (leftTag != rightTag) {
        return false;
    }
    if (left->len != right->len) {
        return false;
    }
    return left->len == 0 || memcmp(left->buff, right->buff, left->len) == 0;
}

int32_t CMS_VerifyAlgorithmProtection(CMS_SignerInfo *si)
{
    HITLS_X509_AttrEntry *algAttr = NULL;
    for (HITLS_X509_AttrEntry *attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(si->signedAttrs->list);
        attr != NULL; attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(si->signedAttrs->list)) {
        if (attr->cid == BSL_CID_PKCS9_AT_ALGORITHM_PROTECTION) {
            algAttr = attr;
            break;
        }
    }
    if (algAttr == NULL) {
        return HITLS_PKI_SUCCESS;
    }

    CMS_AlgorithmProtection algProtect = {0};
    BSL_Buffer attrValue = {algAttr->attrValue.buff, algAttr->attrValue.len};
    int32_t ret = CMS_ParseAlgorithmProtection(&attrValue, &algProtect);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    /* RFC 6211 Section 3.1: SignedData uses signatureAlgorithm rather than
     * macAlgorithm, and both protected algorithm identifiers MUST compare
     * equal to their SignerInfo counterparts, modulo encoding.
     */
    if (algProtect.macAlgorithm.id != BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ALG_PROTECTION_MISMATCH);
        return HITLS_CMS_ERR_ALG_PROTECTION_MISMATCH;
    }
    if (si->digestAlg.id != algProtect.digestAlgorithm.id ||
        !IsAlgParamEqual(&si->digestAlg.param, &algProtect.digestAlgorithm.param)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ALG_PROTECTION_MISMATCH);
        return HITLS_CMS_ERR_ALG_PROTECTION_MISMATCH;
    }
    if (HITLS_X509_CheckSignAlgConsistency(&si->sigAlg, &algProtect.signatureAlgorithm) != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ALG_PROTECTION_MISMATCH);
        return HITLS_CMS_ERR_ALG_PROTECTION_MISMATCH;
    }
    return HITLS_PKI_SUCCESS;
}
#endif /* HITLS_PKI_CMS_SIGNEDDATA */
