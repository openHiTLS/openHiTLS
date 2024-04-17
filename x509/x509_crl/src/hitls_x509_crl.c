/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_x509.h"
#include "bsl_sal.h"
#include "securec.h"
#include "hitls_x509_errno.h"
#include "hitls_x509_local.h"
#include "hitls_crl_local.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"

#define HITLS_CRL_CTX_SPECIFIC_TAG_EXTENSION 0

BSL_ASN1_TemplateItem g_crlTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* x509 */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* tbs */
            /* 2: version */
            {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_DEFAULT, 2},
            /* 2: signature info */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
                {BSL_ASN1_TAG_OBJECT_ID, 0, 3},
                {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 3}, // 6
            /* 2: issuer */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
            /* 2: validity */
            {BSL_ASN1_TAG_CHOICE, 0, 2},
            {BSL_ASN1_TAG_CHOICE, BSL_ASN1_FLAG_OPTIONAL, 2},
            /* 2: revoked crl list */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
            BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME | BSL_ASN1_FLAG_OPTIONAL, 2},
            /* 2: extension */
            {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CRL_CTX_SPECIFIC_TAG_EXTENSION,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2}, // 11
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* signAlg */
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
            {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 2},
        {BSL_ASN1_TAG_BITSTRING, 0, 1} /* sig */
};

typedef enum {
    HITLS_X509_CRL_VERSION_IDX,
    HITLS_X509_CRL_TBS_SIGNALG_OID_IDX,
    HITLS_X509_CRL_TBS_SIGNALG_ANY_IDX,
    HITLS_X509_CRL_ISSUER_IDX,
    HITLS_X509_CRL_BEFORE_VALID_IDX,
    HITLS_X509_CRL_AFTER_VALID_IDX,
    HITLS_X509_CRL_CRL_LIST_IDX,
    HITLS_X509_CRL_EXT_IDX,
    HITLS_X509_CRL_SIGNALG_IDX,
    HITLS_X509_CRL_SIGNALG_ANY_IDX,
    HITLS_X509_CRL_SIGN_IDX,
    HITLS_X509_CRL_MAX_IDX,
} HITLS_X509_CRL_IDX;

int32_t HITLS_X509_CrlTagGetOrCheck(int32_t type, int32_t idx, void *data, void *expVal)
{
    (void) idx;
    switch (type) {
        case BSL_ASN1_TYPE_CHECK_CHOICE_TAG: {
            uint8_t tag = *(uint8_t *) data;
            if ((tag & BSL_ASN1_TAG_UTCTIME) || (tag & BSL_ASN1_TAG_GENERALIZEDTIME)) {
                *(uint8_t *) expVal = tag;
                return BSL_SUCCESS;
            }
            return HITLS_X509_ERR_CHECK_TAG;
        }
        case BSL_ASN1_TYPE_GET_ANY_TAG: {
            BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *) data;
            BslOidString oidStr = {param->len, (char *)param->buff, 0};
            BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
            if (cid == BSL_CID_UNKNOWN) {
                return HITLS_X509_ERR_GET_ANY_TAG;
            }
            if (cid == BSL_CID_RSASSAPSS) {
                // note: any It can be encoded empty or it can be null
                *(uint8_t *) expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
                return BSL_SUCCESS;
            } else {
                *(uint8_t *) expVal = BSL_ASN1_TAG_NULL; // is null
                return BSL_SUCCESS;
            }
            return HITLS_X509_ERR_GET_ANY_TAG;
        }
        default:
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

void HITLS_X509_FreeCrl(HITLS_X509_Crl *crl)
{
    if (crl == NULL) {
        return;
    }

    int ret = 0;
    BSL_SAL_AtomicDownReferences(&(crl->references), &ret);
    if (ret > 0) {
        return;
    }

    BSL_LIST_FREE(crl->tbs.issuerName, NULL);
    BSL_LIST_FREE(crl->tbs.revokedCerts, NULL);
    BSL_LIST_FREE(crl->tbs.crlExt.extList, NULL);
    BSL_SAL_ReferencesFree(&(crl->references));
    if (crl->isCopy == true) {
        BSL_SAL_FREE(crl->rawData);
    }
    BSL_SAL_Free(crl);
    return;
}

HITLS_X509_Crl *HITLS_X509_NewCrl()
{
    HITLS_X509_Crl *crl = NULL;
    BSL_ASN1_List *issuerName = NULL;
    BSL_ASN1_List *entryList = NULL;
    BSL_ASN1_List *extList = NULL;
    crl = (HITLS_X509_Crl *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_Crl));
    if (crl == NULL) {
        return NULL;
    }
    
    issuerName = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (issuerName == NULL) {
        goto ERR;
    }
    
    entryList = BSL_LIST_New(sizeof(HITLS_X509_CrlEntry));
    if (entryList == NULL) {
        goto ERR;
    }
    extList = BSL_LIST_New(sizeof(HITLS_X509_ExtEntry));
    if (extList == NULL) {
        goto ERR;
    }
    BSL_SAL_ReferencesInit(&(crl->references));
    crl->tbs.issuerName = issuerName;
    crl->tbs.revokedCerts = entryList;
    crl->tbs.crlExt.extList = extList;
    return crl;
ERR:
    BSL_SAL_Free(crl);
    BSL_SAL_Free(issuerName);
    BSL_SAL_Free(entryList);
    return NULL;
}

int32_t HITLS_CRL_ParseExtAsnItem(BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    (void) param;
    HITLS_X509_ExtEntry extEntry = {0};
    int32_t ret = HITLS_X509_ParseExt(asn, &extEntry);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return HITLS_X509_ParseItemDefault(&extEntry, sizeof(HITLS_X509_ExtEntry), list);
}

int32_t HITLS_CRL_ParseExtSeqof(uint32_t layer, BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    if (layer == 1) {
        return HITLS_X509_SUCCESS;
    }
    return HITLS_CRL_ParseExtAsnItem(asn, param, list);
}

int32_t HITLS_X509_ParseCrlExt(BSL_ASN1_Buffer *ext, HITLS_X509_Crl *crl)
{
    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {2, expTag};
    int ret = BSL_ASN1_DecodeLsitItem(&listParam, ext, &HITLS_CRL_ParseExtSeqof, crl, crl->tbs.crlExt.extList);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteAll(crl->tbs.crlExt.extList, NULL);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

BSL_ASN1_TemplateItem g_crlEntryTempl[] = {
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_CHOICE, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0}
};

typedef enum {
    HITLS_X509_CRLENTRY_NUM_IDX,
    HITLS_X509_CRLENTRY_TIME_IDX,
    HITLS_X509_CRLENTRY_EXT_IDX,
    HITLS_X509_CRLENTRY_MAX_IDX
} HITLS_X509_CRLENTRY_IDX;

int32_t HITLS_X509_CrlEntryChoiceCheck(int32_t type, int32_t idx, void *data, void *expVal)
{
    (void) idx;
    (void) expVal;
    if (type == BSL_ASN1_TYPE_CHECK_CHOICE_TAG) {
        uint8_t tag = *(uint8_t *) data;
        if ((tag & BSL_ASN1_TAG_UTCTIME) || (tag & BSL_ASN1_TAG_GENERALIZEDTIME)) {
            *(uint8_t *) expVal = tag;
            return BSL_SUCCESS;
        }
        return HITLS_X509_ERR_CHECK_TAG;
    }
    return HITLS_X509_ERR_CHECK_TAG;
}

int32_t HITLS_CRL_ParseCrlEntry(BSL_ASN1_Buffer *extItem, HITLS_X509_CrlEntry *crlEntry)
{
    uint8_t *temp = extItem->buff;
    uint32_t tempLen = extItem->len;
    BSL_ASN1_Buffer asnArr[HITLS_X509_CRLENTRY_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_crlEntryTempl, sizeof(g_crlEntryTempl) / sizeof(g_crlEntryTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, &HITLS_X509_CrlEntryChoiceCheck,
        &temp, &tempLen, asnArr, HITLS_X509_CRLENTRY_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    crlEntry->serialNumber = asnArr[HITLS_X509_CRLENTRY_NUM_IDX];

    ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CRLENTRY_TIME_IDX], &crlEntry->time);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // optinal
    crlEntry->entryExt = asnArr[HITLS_X509_CRLENTRY_EXT_IDX];
    return ret;
}

int32_t HITLS_CRL_ParseCrlAsnItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    (void) param;
    (void) layer;
    HITLS_X509_CrlEntry crlEntry = {0};
    int32_t ret = HITLS_CRL_ParseCrlEntry(asn, &crlEntry);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return HITLS_X509_ParseItemDefault(&crlEntry, sizeof(HITLS_X509_CrlEntry), list);
}

int32_t HITLS_X509_ParseCrlList(BSL_ASN1_Buffer *crl, BSL_ASN1_List *list)
{
    // crl is optional
    if (crl->tag == 0) {
        return HITLS_X509_SUCCESS;
    }
    
    uint8_t expTag = (BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE);
    BSL_ASN1_DecodeListParam listParam = {1, &expTag};
    int32_t ret = BSL_ASN1_DecodeLsitItem(&listParam, crl, &HITLS_CRL_ParseCrlAsnItem, NULL, list);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteAll(list, NULL);
        return ret;
    }
    return ret;
}

int32_t HITLS_X509_ParseCrlTbs(BSL_ASN1_Buffer *asnArr, HITLS_X509_Crl *crl)
{
    int32_t ret;
    if (asnArr[HITLS_X509_CRL_VERSION_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CRL_VERSION_IDX], &crl->tbs.version);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else {
        crl->tbs.version = 0;
    }

    // sign alg
    ret = HITLS_X509_ParseSignAlgInfo(&asnArr[HITLS_X509_CRL_TBS_SIGNALG_OID_IDX],
        &asnArr[HITLS_X509_CRL_TBS_SIGNALG_ANY_IDX], &crl->tbs.signAlgId);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // issuer name
    ret = HITLS_X509_ParseNameList(&asnArr[HITLS_X509_CRL_ISSUER_IDX], crl->tbs.issuerName);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    // validity
    ret = HITLS_X509_ParseTime(&asnArr[HITLS_X509_CRL_BEFORE_VALID_IDX], &asnArr[HITLS_X509_CRL_AFTER_VALID_IDX],
        &crl->tbs.validTime);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // crl list
    ret = HITLS_X509_ParseCrlList(&asnArr[HITLS_X509_CRL_CRL_LIST_IDX], crl->tbs.revokedCerts);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // ext
    ret = HITLS_X509_ParseCrlExt(&asnArr[HITLS_X509_CRL_EXT_IDX], crl);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    return ret;
ERR:

    BSL_LIST_DeleteAll(crl->tbs.issuerName, NULL);
    BSL_LIST_DeleteAll(crl->tbs.revokedCerts, NULL);
    return ret;
}

int32_t HITLS_X509_ParseAsn1Crl(bool isCopy, uint8_t **encode, uint32_t *encodeLen, HITLS_X509_Crl *crl)
{
    uint8_t *temp = *encode;
    uint32_t tempLen = *encodeLen;
    crl->isCopy = isCopy;
    // template parse
    BSL_ASN1_Buffer asnArr[HITLS_X509_CRL_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_crlTempl, sizeof(g_crlTempl) / sizeof(g_crlTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, HITLS_X509_CrlTagGetOrCheck,
        &temp, &tempLen, asnArr, HITLS_X509_CRL_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // parse tbs raw data
    ret = HITLS_X509_ParseTbsRawData(*encode, *encodeLen, &crl->tbs.tbsRawData, &crl->tbs.tbsRawDataLen);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // parse tbs
    ret = HITLS_X509_ParseCrlTbs(asnArr, crl);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    // parse sign alg
    ret = HITLS_X509_ParseSignAlgInfo(&asnArr[HITLS_X509_CRL_SIGNALG_IDX],
        &asnArr[HITLS_X509_CRL_SIGNALG_ANY_IDX], &crl->signAlgId);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // parse signature
    ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CRL_SIGN_IDX], &crl->signature);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    crl->rawData = *encode;
    crl->rawDataLen = *encodeLen - tempLen;
    *encode = temp;
    *encodeLen = tempLen;
    return HITLS_X509_SUCCESS;
ERR:
    BSL_LIST_DeleteAll(crl->tbs.issuerName, NULL);
    BSL_LIST_DeleteAll(crl->tbs.revokedCerts, NULL);
    BSL_LIST_DeleteAll(crl->tbs.crlExt.extList, NULL);
    return ret;
}

int32_t HITLS_X509_ParseBuffCrl(bool isCopy, int32_t format, BSL_Buffer *encode, HITLS_X509_Crl *crl)
{
    int32_t ret;
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || crl == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    uint8_t *data = encode->data;
    uint32_t dataLen = encode->dataLen;
    if (isCopy == true) {
        data = BSL_SAL_Malloc(dataLen);
        if (data == NULL) {
            return BSL_MALLOC_FAIL;
        }
        (void)memcpy_s(data, encode->dataLen, encode->data, encode->dataLen);
    }
    
    switch (format) {
        case BSL_PARSE_FORMAT_ASN1:
            ret = HITLS_X509_ParseAsn1Crl(isCopy, &data, &dataLen, crl);
            break;
        case BSL_PARSE_FORMAT_PEM:
            ret = HITLS_X509_ERR_NOT_SUPPORT_FORMAT;
            break;
        case BSL_PARSE_FORMAT_UNKNOWN:
            ret = HITLS_X509_ERR_NOT_SUPPORT_FORMAT;
            break;
        default:
            ret = HITLS_X509_ERR_NOT_SUPPORT_FORMAT;
            break;
    }
    if (ret != HITLS_X509_SUCCESS && isCopy == true) {
        BSL_SAL_Free(data);
    }
    return ret;
}

int32_t HITLS_X509_ParseFileCrl(int32_t format, const char *path, HITLS_X509_Crl *crl)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_X509_ParseBuffCrl(true, format, &encode, crl);
    BSL_SAL_Free(data);
    return ret;
}

static int32_t X509_CrlRefUp(HITLS_X509_Crl *crl, int32_t *val, int32_t valLen)
{
    if (val == NULL || valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    return BSL_SAL_AtomicUpReferences(&crl->references, val);
}

static int32_t X509_CrlRefDown(HITLS_X509_Crl *crl, int32_t *val, int32_t valLen)
{
    if (val == NULL || valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    return BSL_SAL_AtomicDownReferences(&crl->references, val);
}

int32_t HITLS_X509_CtrlCrl(HITLS_X509_Crl *crl, int32_t cmd, void *val, int32_t valLen)
{
    if (crl == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    switch (cmd) {
        case HITLS_X509_CRL_REF_UP:
            return X509_CrlRefUp(crl, val, valLen);
        case HITLS_X509_CRL_REF_DOWN:
            return X509_CrlRefDown(crl, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}