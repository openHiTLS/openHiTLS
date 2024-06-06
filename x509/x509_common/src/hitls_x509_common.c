/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_x509_local.h"
#include "bsl_obj.h"
#include "bsl_sal.h"
#include "hitls_x509_errno.h"
#include "crypt_eal_pkey.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "bsl_pem_internal.h"
#include "securec.h"

int32_t HITLS_X509_ParseTbsRawData(uint8_t *encode, uint32_t encodeLen, uint8_t **tbsRsaData, uint32_t *tbsRsaDataLen)
{
    uint8_t *temp = encode;
    uint32_t tempLen = encodeLen;
    uint32_t valen;
    // x509
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &temp, &tempLen, &valen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t len = tempLen;
    *tbsRsaData = temp;
    // tbs
    ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &temp, &tempLen, &valen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    *tbsRsaDataLen = len - tempLen + valen;
    return ret;
}

#define X509_ASN1_CTX_SPECIFIC_TAG_RSAPSS_HASH    0
#define X509_ASN1_CTX_SPECIFIC_TAG_RSAPSS_MASKGEN 1
#define X509_ASN1_CTX_SPECIFIC_TAG_RSAPSS_SALTlEN 2
#define X509_ASN1_CTX_SPECIFIC_TAG_RSAPSS_TRAILED 3

/**
 * ref: rfc4055
 * RSASSA-PSS-params  ::=  SEQUENCE  {
 *    hashAlgorithm     [0] HashAlgorithm DEFAULT
 *                             sha1Identifier,
 *    maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT
 *                             mgf1SHA1Identifier,
 *    saltLength        [2] INTEGER DEFAULT 20,
 *    trailerField      [3] INTEGER DEFAULT 1
 * }
 * HashAlgorithm  ::=  AlgorithmIdentifier*
 * MaskGenAlgorithm  ::=  AlgorithmIdentifier 
 */
static BSL_ASN1_TemplateItem g_rsaPssTempl[] = {
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | X509_ASN1_CTX_SPECIFIC_TAG_RSAPSS_HASH,
    BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
            {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 2},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | X509_ASN1_CTX_SPECIFIC_TAG_RSAPSS_MASKGEN,
    BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
                {BSL_ASN1_TAG_OBJECT_ID, 0, 3},
                {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 3},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | X509_ASN1_CTX_SPECIFIC_TAG_RSAPSS_SALTlEN,
    BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | X509_ASN1_CTX_SPECIFIC_TAG_RSAPSS_TRAILED,
    BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_TAG_INTEGER, 0, 1}
};

typedef enum {
    HITLS_X509_RSAPSS_HASH_IDX,
    HITLS_X509_RSAPSS_HASHANY_IDX,
    HITLS_X509_RSAPSS_MGF1_IDX,
    HITLS_X509_RSAPSS_MGF1PARAM_IDX,
    HITLS_X509_RSAPSS_MGF1PARAMANY_IDX,
    HITLS_X509_RSAPSS_SALTLEN_IDX,
    HITLS_X509_RSAPSS_TRAILED_IDX,
    HITLS_X509_RSAPSS_MAX
} HITLS_X509_RSAPSS_IDX;

static int32_t HITLS_X509_CertTagGetOrCheck(int32_t type, int32_t idx, void *data, void *expVal)
{
    (void) idx;
    (void) data;
    if (type == BSL_ASN1_TYPE_GET_ANY_TAG) {
        *(uint8_t *) expVal = BSL_ASN1_TAG_NULL; // is null
        return HITLS_X509_SUCCESS;
    }
    return HITLS_X509_ERR_GET_ANY_TAG;
}

static int32_t HITLS_X509_ParseRsaPssAlgParam(BSL_ASN1_Buffer *param, HITLS_X509_Asn1AlgId *x509Alg)
{
    uint8_t *temp = param->buff;
    uint32_t tempLen = param->len;
    BSL_ASN1_Buffer asnArr[HITLS_X509_RSAPSS_MAX] = {0};
    BSL_ASN1_Template templ = {g_rsaPssTempl, sizeof(g_rsaPssTempl) / sizeof(g_rsaPssTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, &HITLS_X509_CertTagGetOrCheck,
        &temp, &tempLen, asnArr, HITLS_X509_RSAPSS_MAX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_PARAM);
        return HITLS_X509_ERR_PARSE_PARAM;
    }
    if (asnArr[HITLS_X509_RSAPSS_HASH_IDX].tag != 0) {
        BslOidString hashOid = {asnArr[HITLS_X509_RSAPSS_HASH_IDX].len,
            (char *)asnArr[HITLS_X509_RSAPSS_HASH_IDX].buff, 0};
        x509Alg->rsaPssParam.mdId = (CRYPT_MD_AlgId)BSL_OBJ_GetCIDFromOid(&hashOid);
        if (x509Alg->rsaPssParam.mdId == (CRYPT_MD_AlgId)BSL_CID_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ALG_OID);
            return HITLS_X509_ERR_ALG_OID;
        }
    } else { // default
        x509Alg->rsaPssParam.mdId = (CRYPT_MD_AlgId)BSL_CID_SHA1;
    }
    if (asnArr[HITLS_X509_RSAPSS_MGF1PARAM_IDX].tag != 0) {
        BslOidString mgf1ParamOid = {asnArr[HITLS_X509_RSAPSS_MGF1PARAM_IDX].len,
            (char *)asnArr[HITLS_X509_RSAPSS_MGF1PARAM_IDX].buff, 0};
        x509Alg->rsaPssParam.mgfId = (CRYPT_MD_AlgId)BSL_OBJ_GetCIDFromOid(&mgf1ParamOid);
        if (x509Alg->rsaPssParam.mgfId == (CRYPT_MD_AlgId)BSL_CID_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ALG_OID);
            return HITLS_X509_ERR_ALG_OID;
        }
    } else { // default
        x509Alg->rsaPssParam.mgfId = (CRYPT_MD_AlgId)BSL_CID_SHA1;
    }

    if (asnArr[HITLS_X509_RSAPSS_SALTLEN_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_RSAPSS_SALTLEN_IDX],
            &x509Alg->rsaPssParam.saltLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else { // default
        x509Alg->rsaPssParam.saltLen = 20;
    }

    if (asnArr[HITLS_X509_RSAPSS_TRAILED_IDX].tag != 0) {
        uint32_t trailerField;
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_RSAPSS_TRAILED_IDX], &trailerField);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (trailerField != 1) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_PARAM);
            return HITLS_X509_ERR_PARSE_PARAM;
        }
    }
    return ret;
}

int32_t HITLS_X509_ParseSignAlgInfo(BSL_ASN1_Buffer *algId, BSL_ASN1_Buffer *param, HITLS_X509_Asn1AlgId *x509Alg)
{
    int32_t ret;
    BslOidString oidStr = {algId->len, (char *)algId->buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ALG_OID);
        return HITLS_X509_ERR_ALG_OID;
    }
    if (cid == BSL_CID_RSASSAPSS) {
        ret = HITLS_X509_ParseRsaPssAlgParam(param, x509Alg);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }
    x509Alg->algId = cid;
    return HITLS_X509_SUCCESS;
}

static int32_t HITLS_X509_ParseNameNode(BSL_ASN1_Buffer *asn, HITLS_X509_NameNode *node)
{
    uint8_t *temp = asn->buff;
    uint32_t tempLen = asn->len;
    // parse oid
    if (*temp != BSL_ASN1_TAG_OBJECT_ID) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_NAME_OID);
        return HITLS_X509_ERR_NAME_OID;
    }

    int32_t ret = BSL_ASN1_DecodeItem(&temp, &tempLen, &node->nameType);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // parse string
    if (*temp != BSL_ASN1_TAG_UTF8STRING && *temp != BSL_ASN1_TAG_PRINTABLESTRING &&
        *temp != BSL_ASN1_TAG_IA5STRING) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_STR);
        return HITLS_X509_ERR_PARSE_STR;
    }

    ret = BSL_ASN1_DecodeItem(&temp, &tempLen, &node->nameValue);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}


int32_t HITLS_X509_ParseListAsnItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *cbParam, BSL_ASN1_List *list)
{
    (void) cbParam;
    int32_t ret = HITLS_X509_SUCCESS;
    HITLS_X509_NameNode *node = BSL_SAL_Calloc(1, sizeof(HITLS_X509_NameNode));
    if (node == NULL) {
        return BSL_MALLOC_FAIL;
    }

    if (layer == 1) {
        node->layer = 1;
    } else { // layer == 2
        node->layer = 2;
        ret = HITLS_X509_ParseNameNode(asn, node);
        if (ret != HITLS_X509_SUCCESS) {
            goto ERR;
        }
    }

    ret = BSL_LIST_AddElement(list, node, BSL_LIST_POS_AFTER);
    if (ret != BSL_SUCCESS) {
        goto ERR;
    }
    return ret;
ERR:
    BSL_SAL_Free(node);
    return ret;
}

int32_t HITLS_X509_ParseNameList(BSL_ASN1_Buffer *name, BSL_ASN1_List *list)
{
    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {2, expTag};
    int32_t ret = BSL_ASN1_DecodeListItem(&listParam, name, &HITLS_X509_ParseListAsnItem, NULL, list);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteAll(list, NULL);
        return ret;
    }
    return ret;
}

static BSL_ASN1_TemplateItem g_x509ExtTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_TAG_BOOLEAN, BSL_ASN1_FLAG_DEFAULT, 0},
    {BSL_ASN1_TAG_OCTETSTRING, 0, 0},
};

typedef enum {
    HITLS_X509_EXT_OID_IDX,
    HITLS_X509_EXT_CRITICAL_IDX,
    HITLS_X509_EXT_VALUE_IDX,
    HITLS_X509_EXT_MAX
} HITLS_X509_EXT_IDX;

int32_t HITLS_X509_ParseExt(BSL_ASN1_Buffer *extItem, HITLS_X509_ExtEntry *extEntry)
{
    uint8_t *temp = extItem->buff;
    uint32_t tempLen = extItem->len;
    BSL_ASN1_Buffer asnArr[HITLS_X509_EXT_MAX] = {0};
    BSL_ASN1_Template templ = {g_x509ExtTempl, sizeof(g_x509ExtTempl) / sizeof(g_x509ExtTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_X509_EXT_MAX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    extEntry->extnId = asnArr[HITLS_X509_EXT_OID_IDX];
    // critical
    if (asnArr[HITLS_X509_EXT_CRITICAL_IDX].tag == 0) {
        extEntry->critical = false;
    } else {
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_EXT_CRITICAL_IDX], &extEntry->critical);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    extEntry->extnValue = asnArr[HITLS_X509_EXT_VALUE_IDX];
    return ret;
}

int32_t HITLS_X509_ParseItemDefault(void *item, uint32_t len,  BSL_ASN1_List *list)
{
    void *node = BSL_SAL_Malloc(len);
    if (node == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    (void)memcpy_s(node, len, item, len);
    int32_t ret = BSL_LIST_AddElement(list, node, BSL_LIST_POS_AFTER);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(node);
    }
    return ret;
}

int32_t HITLS_X509_ParseTime(BSL_ASN1_Buffer *before, BSL_ASN1_Buffer *after, HITLS_X509_ValidTime *time)
{
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(before, &time->start);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (before->buff[before->len - 1] == 'Z') {
        time->flag |= BSL_TIME_BEFORE_TIME_IS_GMT;
    }
    // crl after time is optional
    if (after->tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(after, &time->end);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (after->buff[after->len - 1] == 'Z') {
            time->flag |= BSL_TIME_AFTER_TIME_IS_GMT;
        }
    } else {
        time->flag |= BSL_TIME_AFTER_TIME_ABSENT;
    }
    return ret;
}

static void X509_GetPemSymbol(bool isCert, BSL_PEM_Symbol *symbol)
{
    if (isCert) {
        symbol->head = BSL_PEM_CERT_BEGIN_STR;
        symbol->tail = BSL_PEM_CERT_END_STR;
    } else {
        symbol->head = BSL_PEM_CRL_BEGIN_STR;
        symbol->tail = BSL_PEM_CRL_END_STR;
    }
}

static int32_t X509_ParseAndAddRes(BSL_Buffer *asn1Buf, bool isCopy, X509_ParseFuncCbk *parsefun, HITLS_X509_List *list)
{
    void *res = parsefun->x509New();
    if (res == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = parsefun->asn1Parse(isCopy, &(asn1Buf->data), &(asn1Buf->dataLen), res);
    if (ret != HITLS_X509_SUCCESS) {
        parsefun->x509Free(res);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_LIST_AddElement(list, res, BSL_LIST_POS_AFTER);
    if (ret != BSL_SUCCESS) {
        parsefun->x509Free(res);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_ParseAsn1(BSL_Buffer *encode, bool isCopy, X509_ParseFuncCbk *parsefun, HITLS_X509_List *list)
{
    uint8_t *data = encode->data;
    uint32_t dataLen = encode->dataLen;
    while (dataLen > 0) {
        uint32_t elemLen = dataLen;
        int32_t ret = BSL_ASN1_GetCompleteLen(data, &elemLen);
        if (ret != HITLS_X509_SUCCESS) {
            return ret;
        }
        BSL_Buffer asn1Buf = {data, elemLen};
        if (isCopy) {
            asn1Buf.data = BSL_SAL_Malloc(elemLen);
            if (asn1Buf.data == NULL) {
                return BSL_MALLOC_FAIL;
            }
            (void)memcpy_s(asn1Buf.data, dataLen, data, elemLen);
        }
        ret = X509_ParseAndAddRes(&asn1Buf, isCopy, parsefun, list);
        if (ret != HITLS_X509_SUCCESS) {
            BSL_SAL_Free(asn1Buf.data);
            return ret;
        }
        data += elemLen;
        dataLen -= elemLen;
    }
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_ParsePem(BSL_Buffer *encode, bool isCert, X509_ParseFuncCbk *parsefun,
    HITLS_X509_List *list)
{
    char *nextEncode = (char *)(encode->data);
    uint32_t nextEncodeLen = encode->dataLen;
    BSL_PEM_Symbol symbol = {NULL};
    X509_GetPemSymbol(isCert, &symbol);
    while (nextEncodeLen > 0) {
        BSL_Buffer asn1Buf = {NULL};
        int32_t ret = BSL_PEM_ParsePem2Asn1(&nextEncode, &nextEncodeLen, &symbol, &(asn1Buf.data),
            &(asn1Buf.dataLen));
        if (ret != HITLS_X509_SUCCESS) {
            break;
        }
        ret = X509_ParseAndAddRes(&asn1Buf, true, parsefun, list);
        if (ret != HITLS_X509_SUCCESS) {
            BSL_SAL_Free(asn1Buf.data);
            return ret;
        }
    }
    if (BSL_LIST_COUNT(list) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_NO_ELEMENT);
        return HITLS_X509_ERR_PARSE_NO_ELEMENT;
    }
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_ParseUnkonw(BSL_Buffer *encode, bool isCopy, bool isCert, X509_ParseFuncCbk *parsefun,
    HITLS_X509_List *list)
{
    bool isPem = BSL_PEM_IsPemFormat((char *)(encode->data), encode->dataLen);
    if (isPem) {
        return HITLS_X509_ParsePem(encode, isCert, parsefun, list);
    } else {
        return HITLS_X509_ParseAsn1(encode, isCopy, parsefun, list);
    }
}

int32_t HITLS_X509_ParseX509(int32_t format, BSL_Buffer *encode, bool isCert, X509_ParseFuncCbk *parsefun,
    HITLS_X509_List *list)
{
    int32_t ret;
    switch (format) {
        case BSL_PARSE_FORMAT_ASN1:
            ret = HITLS_X509_ParseAsn1(encode, true, parsefun, list);
            break;
        case BSL_PARSE_FORMAT_PEM:
            ret = HITLS_X509_ParsePem(encode, isCert, parsefun, list);
            break;
        case BSL_PARSE_FORMAT_UNKNOWN:
            ret = HITLS_X509_ParseUnkonw(encode, true, isCert, parsefun, list);
            break;
        default:
            ret = HITLS_X509_ERR_NOT_SUPPORT_FORMAT;
            break;
    }
    return ret;
}

static int32_t X509_NodeNameCompare(BSL_ASN1_Buffer *src, BSL_ASN1_Buffer *dest)
{
    if (src->tag != dest->tag) {
        return 1;
    }
    if (src->len != dest->len) {
        return 1;
    }
    return memcmp(src->buff, dest->buff, dest->len);
}

static int32_t X509_NodeNameCaseCompare(BSL_ASN1_Buffer *src, BSL_ASN1_Buffer *dest)
{
    if ((src->tag == BSL_ASN1_TAG_UTF8STRING || src->tag == BSL_ASN1_TAG_PRINTABLESTRING) &&
        (dest->tag == BSL_ASN1_TAG_UTF8STRING || dest->tag == BSL_ASN1_TAG_PRINTABLESTRING)) {
        if (src->len != dest->len) {
            return 1;
        }
        for (uint32_t i = 0; i < src->len; i++) {
            if (src->buff[i] == dest->buff[i]) {
                continue;
            }
            if ('a' <= src->buff[i] && src->buff[i] <= 'z' && src->buff[i] - dest->buff[i] == 32) {
                continue;
            }
            if ('a' <= dest->buff[i] && dest->buff[i] <= 'z' && dest->buff[i] - src->buff[i] == 32) {
                continue;
            }
            return 1;
        }
        return 0;
    }
    return 1;
}

static int32_t X509_NodeNameValueCompare(BSL_ASN1_Buffer *src, BSL_ASN1_Buffer *dest)
{
    // quick comparison
    if (X509_NodeNameCompare(src, dest) == 0) {
        return 0;
    }
    return X509_NodeNameCaseCompare(src, dest);
}


static int32_t X509_NodeCompare(BSL_ASN1_Buffer *buffOri, BSL_ASN1_Buffer *buff)
{
    if (buffOri->tag != buff->tag) {
        return 1;
    }
    if (buffOri->len != buff->len) {
        return 1;
    }
    return memcmp(buffOri->buff, buff->buff, buff->len);
}

int32_t HITLS_X509_CmpNameNode(BSL_ASN1_List *nameOri, BSL_ASN1_List *name)
{
    HITLS_X509_NameNode *nodeOri = BSL_LIST_GET_FIRST(nameOri);
    HITLS_X509_NameNode *node = BSL_LIST_GET_FIRST(name);
    while(nodeOri != NULL || node != NULL) {
        if (nodeOri == NULL || node == NULL) {
            return 1;
        }
        if (X509_NodeCompare(&nodeOri->nameType, &node->nameType) != 0) {
            return 1;
        }
        if (nodeOri->layer != node->layer) {
            return 1;
        }
        if (X509_NodeNameValueCompare(&nodeOri->nameValue, &node->nameValue) != 0) {
            return 1;
        }
        nodeOri = (HITLS_X509_NameNode *)BSL_LIST_GET_NEXT(nameOri);
        node = (HITLS_X509_NameNode *)BSL_LIST_GET_NEXT(name);
    }
    return 0;
}

int32_t HITLS_X509_CheckAlg(CRYPT_EAL_PkeyCtx *pubkey, HITLS_X509_Asn1AlgId *subAlg)
{
    uint32_t pubKeyId = CRYPT_EAL_PkeyGetId(pubkey);
    if (pubKeyId == BSL_CID_UNKNOWN) {      
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_GET_SIGNID);
        return HITLS_X509_ERR_VFY_GET_SIGNID;
    }
    BslCid subSignAlg = BSL_OBJ_GetAsymIdFromSignId(subAlg->algId);
    if (subSignAlg == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_GET_SIGNID);
        return HITLS_X509_ERR_VFY_GET_SIGNID;
    }
    if (pubKeyId != subSignAlg) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_SIGNALG_NOT_MATCH);
        return HITLS_X509_ERR_VFY_SIGNALG_NOT_MATCH;
    }
    return HITLS_X509_SUCCESS;
}