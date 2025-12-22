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
#ifdef HITLS_PKI_CMS
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_asn1_internal.h"
#include "bsl_obj_internal.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_md.h"
#include "crypt_codecskey.h"
#include "hitls_pki_errno.h"
#include "hitls_cms_local.h"
#include "hitls_x509_local.h"
#include "crypt_errno.h"
#include "sal_file.h"
#include "hitls_x509_verify.h"
#ifdef HITLS_PKI_CMS_DATA
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
#endif // HITLS_PKI_CMS_DATA

#ifdef HITLS_PKI_CMS_DIGESTINFO

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
#endif // HITLS_PKI_CMS_DIGESTINFO

#ifdef HITLS_PKI_CMS_SIGNEDDATA
/*
 * Defined in RFC 5652
 * ContentInfo ::= SEQUENCE {
 *     contentType ContsentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
*/
static BSL_ASN1_TemplateItem g_cmsContentInfoTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        /* content type */
        {BSL_ASN1_TAG_OBJECT_ID, BSL_ASN1_FLAG_DEFAULT, 1},
        /* content */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0,
            BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_OPTIONAL, 1},
};

typedef enum {
    HITLS_CMS_CONTENT_OID_IDX,
    HITLS_CMS_CONTENT_VALUE_IDX,
    HITLS_CMS_CONTENT_MAX_IDX,
} HITLS_CMS_CONTENT_IDX;

int32_t HITLS_CMS_ProviderParseBuff(HITLS_PKI_LibCtx *libCtx, const char *attrName, const BSL_Param *param,
    const BSL_Buffer *encode, HITLS_CMS **cms)
{
    (void)param;
    if (encode == NULL || cms == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    uint8_t *temp = encode->data;
    uint32_t tempLen = encode->dataLen;
    BSL_ASN1_Template templ = {g_cmsContentInfoTempl,
        sizeof(g_cmsContentInfoTempl) / sizeof(g_cmsContentInfoTempl[0])};
    BSL_ASN1_Buffer asnArr[HITLS_CMS_CONTENT_MAX_IDX] = {0};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_CMS_CONTENT_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(asnArr[HITLS_CMS_CONTENT_OID_IDX].buff,
        asnArr[HITLS_CMS_CONTENT_OID_IDX].len);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
    BSL_Buffer asnArrData = {asnArr[HITLS_CMS_CONTENT_VALUE_IDX].buff, asnArr[HITLS_CMS_CONTENT_VALUE_IDX].len};
    switch (cid) {
        case BSL_CID_PKCS7_SIGNEDDATA:
            return HITLS_CMS_ParseSignedData(libCtx, attrName, &asnArrData, cms);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
            return HITLS_CMS_ERR_PARSE_TYPE;
    }
}

static int32_t CMS_EncodeContent(int32_t dataType, BSL_Buffer *input, BSL_Buffer *encode)
{
    BslOidString *oidStr = BSL_OBJ_GetOID(dataType);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BSL_ASN1_Buffer items[HITLS_CMS_CONTENT_MAX_IDX] = {
        {
            .buff = (uint8_t *)oidStr->octs,
            .len = oidStr->octetLen,
            .tag = BSL_ASN1_TAG_OBJECT_ID,
        }, {
            .buff = input->data,
            .len = input->dataLen,
            .tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0,
        }};
    BSL_ASN1_Template templ = {g_cmsContentInfoTempl, sizeof(g_cmsContentInfoTempl) / sizeof(g_cmsContentInfoTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, items, HITLS_CMS_CONTENT_MAX_IDX, &encode->data, &encode->dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_CMS_GenBuff(int32_t format, HITLS_CMS *cms, const BSL_Param *optionalParam, BSL_Buffer *encode)
{
    (void)optionalParam;
    if (cms == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (encode->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    int32_t ret;
    BSL_Buffer input = {0};
    switch (cms->dataType) {
        case BSL_CID_PKCS7_SIGNEDDATA:
            ret = HITLS_CMS_GenSignedDataBuff(format, cms, &input);
            break;
        default:
            ret = HITLS_CMS_ERR_UNSUPPORTED_TYPE;
            break;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CMS_EncodeContent(cms->dataType, &input, encode);
    BSL_SAL_FREE(input.data);
    return ret;
}

#ifdef HITLS_BSL_SAL_FILE
int32_t HITLS_CMS_ProviderParseFile(HITLS_PKI_LibCtx *libCtx, const char *attrName, const BSL_Param *param,
    const char *path, HITLS_CMS **cms)
{
    if (path == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_CMS_ProviderParseBuff(libCtx, attrName, param, &encode, cms);
    BSL_SAL_Free(data);
    return ret;
}

int32_t HITLS_CMS_GenFile(int32_t format, HITLS_CMS *cms, const BSL_Param *optionalParam, const char *path)
{
    if (path == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    BSL_Buffer encode = {0};
    int32_t ret = HITLS_CMS_GenBuff(format, cms, optionalParam, &encode);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_SAL_WriteFile(path, encode.data, encode.dataLen);
    BSL_SAL_Free(encode.data);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#endif // HITLS_BSL_SAL_FILE

#ifdef HITLS_PKI_CMS_SIGNEDDATA

int32_t HITLS_CMS_DataInit(int32_t option, HITLS_CMS *cms, const BSL_Param *param)
{
    if (cms == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    switch (cms->dataType) {
        case BSL_CID_PKCS7_SIGNEDDATA:
            return HITLS_CMS_SignedDataInit(cms, option, param);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_UNSUPPORTED_TYPE);
            return HITLS_CMS_ERR_UNSUPPORTED_TYPE;
    }
}

int32_t HITLS_CMS_DataUpdate(HITLS_CMS *cms, const BSL_Buffer *input)
{
    if (cms == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    switch (cms->dataType) {
        case BSL_CID_PKCS7_SIGNEDDATA:
            return HITLS_CMS_SignedDataUpdate(cms, input);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_UNSUPPORTED_TYPE);
            return HITLS_CMS_ERR_UNSUPPORTED_TYPE;
    }
}

int32_t HITLS_CMS_DataFinal(HITLS_CMS *cms, const BSL_Param *param)
{
    if (cms == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    switch (cms->dataType) {
        case BSL_CID_PKCS7_SIGNEDDATA:
            return HITLS_CMS_SignedDataFinal(cms, param);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_UNSUPPORTED_TYPE);
            return HITLS_CMS_ERR_UNSUPPORTED_TYPE;
    }
}

#endif // HITLS_PKI_CMS_SIGNEDDATA
#endif // HITLS_PKI_CMS
#endif // HITLS_PKI_CMS