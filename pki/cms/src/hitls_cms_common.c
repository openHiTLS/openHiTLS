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
#include "bsl_asn1_internal.h"
#include "bsl_obj_internal.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_md.h"
#include "crypt_codecskey.h"
#include "hitls_pki_errno.h"

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
    BslCid parseCid = BSL_OBJ_GetCidFromOidBuff(asn1[HITLS_P7_DIGESTINFO_OID_IDX].buff,
        asn1[HITLS_P7_DIGESTINFO_OID_IDX].len);
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

    BslOidString *oidstr = BSL_OBJ_GetOID(cid);
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
#endif // HITLS_PKI_PKCS12
