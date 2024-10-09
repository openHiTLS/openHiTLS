/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

static int32_t GenDigestBuffer(const BslCid cid, const BSL_Buffer *in, BSL_Buffer *outBuff)
{
    CRYPT_EAL_MdCTX *mdCtx = CRYPT_EAL_MdNewCtx((CRYPT_MD_AlgId)cid);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    int32_t ret;
    uint8_t *out = NULL;
    uint32_t outLen = 0;
    do {
        ret = CRYPT_EAL_MdInit(mdCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        if (in->dataLen != 0) {
            ret = CRYPT_EAL_MdUpdate(mdCtx, in->data, in->dataLen);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                break;
            }
        }
        outLen = CRYPT_EAL_MdGetDigestSize((CRYPT_MD_AlgId)cid);
        if (outLen == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
            ret = CRYPT_ERR_ALGID;
            break;
        }
        out = (uint8_t *)BSL_SAL_Malloc(outLen);
        if (out == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            ret = CRYPT_MEM_ALLOC_FAIL;
            break;
        }
        ret = CRYPT_EAL_MdFinal(mdCtx, out, &outLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        outBuff->data = out;
        outBuff->dataLen = outLen;
        CRYPT_EAL_MdFreeCtx(mdCtx);
        return CRYPT_SUCCESS;
    } while (0);
    BSL_SAL_FREE(out);
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}

int32_t CRYPT_EAL_EncodePKCS7DigestInfoBuff(BslCid cid, BSL_Buffer *in, BSL_Buffer **encode)
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
    BSL_Buffer outBuff = {0};
    ret = GenDigestBuffer(cid, in, &outBuff);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_ASN1_Buffer asn1[HITLS_P7_DIGESTINFO_MAX_IDX] = {
        {BSL_ASN1_TAG_OBJECT_ID, oidstr->octetLen, (uint8_t *)oidstr->octs},
        {BSL_ASN1_TAG_NULL, 0, NULL},
        {BSL_ASN1_TAG_OCTETSTRING, outBuff.dataLen, outBuff.data},
    };
    BSL_Buffer *tmp = (BSL_Buffer *)BSL_SAL_Calloc(sizeof(BSL_Buffer), 1);
    if (tmp == NULL) {
        BSL_SAL_FREE(outBuff.data);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_ASN1_Template templ = {digestInfoTempl, sizeof(digestInfoTempl) / sizeof(digestInfoTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asn1, HITLS_P7_DIGESTINFO_MAX_IDX, &tmp->data, &tmp->dataLen);
    BSL_SAL_FREE(outBuff.data);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(tmp);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *encode = tmp;
    return CRYPT_SUCCESS;
}
