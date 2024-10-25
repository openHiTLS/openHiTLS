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

#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_asn1.h"
#include "crypt_errno.h"
#include "bsl_obj_internal.h"
#include "crypt_eal_encode.h"
#include "crypt_eal_md.h"
#include "crypt_encode.h"
#include "hitls_x509_errno.h"

/**
 * Data ::= OCTET STRING
 *
 * https://datatracker.ietf.org/doc/html/rfc5652#page-7
 */
int32_t CRYPT_EAL_ParseAsn1PKCS7Data(BSL_Buffer *encode, BSL_Buffer *dataValue)
{
    if (encode == NULL || dataValue == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
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
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    dataValue->data = data;
    dataValue->dataLen = decodeLen;
    return CRYPT_SUCCESS;
}

/**
 * DigestInfo ::= SEQUENCE {
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      digest Digest
 * }
 *
 * https://datatracker.ietf.org/doc/html/rfc2315#section-9.4
 */

static BSL_ASN1_TemplateItem digestInfoTempl[] = {
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

int32_t CRYPT_EAL_ParseAsn1PKCS7DigestInfo(BSL_Buffer *encode, BslCid *cid, BSL_Buffer *digest)
{
    if (encode == NULL || digest == NULL || cid == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint8_t *temp = encode->data;
    uint32_t  tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_P7_DIGESTINFO_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {digestInfoTempl, sizeof(digestInfoTempl) / sizeof(digestInfoTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_P7_DIGESTINFO_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString oidStr = {asn1[HITLS_P7_DIGESTINFO_OID_IDX].len,
        (char *)asn1[HITLS_P7_DIGESTINFO_OID_IDX].buff, 0};
    BslCid parseCid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (parseCid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }
    if (asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    uint8_t *output = BSL_SAL_Dump(asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].buff,
            asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].len);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    digest->data = output;
    digest->dataLen = asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].len;
    *cid = parseCid;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_EncodePKCS7DigestInfoBuff(BslCid cid, BSL_Buffer *in, BSL_Buffer *encode)
{
    if (in == NULL || encode == NULL || (in->data == NULL && in->dataLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
    BslOidString *oidstr = BSL_OBJ_GetOidFromCID(cid);
    if (oidstr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    BSL_ASN1_Buffer asn1[HITLS_P7_DIGESTINFO_MAX_IDX] = {
        {BSL_ASN1_TAG_OBJECT_ID, oidstr->octetLen, (uint8_t *)oidstr->octs},
        {BSL_ASN1_TAG_NULL, 0, NULL},
        {BSL_ASN1_TAG_OCTETSTRING, in->dataLen, in->data},
    };
    BSL_Buffer tmp = {0};
    BSL_ASN1_Template templ = {digestInfoTempl, sizeof(digestInfoTempl) / sizeof(digestInfoTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asn1, HITLS_P7_DIGESTINFO_MAX_IDX, &tmp.data, &tmp.dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encode->data = tmp.data;
    encode->dataLen = tmp.dataLen;
    return CRYPT_SUCCESS;
}
