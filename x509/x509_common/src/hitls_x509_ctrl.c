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

#include "hitls_x509_local.h"
#include <stdint.h>
#include "securec.h"
#include "bsl_obj.h"
#include "bsl_sal.h"
#include "sal_atomic.h"
#include "hitls_x509_errno.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "crypt_encode.h"

#define HITLS_X509_DNNAME_MAX_NUM  100

int32_t HITLS_X509_RefUp(BSL_SAL_RefCount *references, int32_t *val, int32_t valLen)
{
    if (val == NULL || valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    return BSL_SAL_AtomicUpReferences(references, val);
}

int32_t HITLS_X509_GetList(BslList *list, void *val, int32_t valLen)
{
    if (list == NULL || val == NULL || valLen != sizeof(BslList *)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *(BslList **)val = list;
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_GetPubKey(void *ealPubKey, void **val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    int32_t ret = CRYPT_EAL_PkeyUpRef((CRYPT_EAL_PkeyCtx *)ealPubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *val = ealPubKey;
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_GetSignAlg(BslCid signAlgId, int32_t *val, int32_t valLen)
{
    if (val == NULL || valLen != sizeof(BslCid)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = signAlgId;
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_GetEncodeLen(uint32_t encodeLen, uint32_t *val, int32_t valLen)
{
    if (val == NULL || valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *(uint32_t *)val = encodeLen;
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_GetEncodeData(uint8_t *rawData, uint8_t **val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = rawData;
    return HITLS_X509_SUCCESS;
}

bool X509_IsValidHashAlg(CRYPT_MD_AlgId id)
{
    return id == CRYPT_MD_MD5 || id == CRYPT_MD_SHA1 || id == CRYPT_MD_SHA224 || id == CRYPT_MD_SHA256 ||
        id == CRYPT_MD_SHA384 || id == CRYPT_MD_SHA512 || id == CRYPT_MD_SM3;
}

int32_t HITLS_X509_SetPkey(void **pkey, void *val)
{
    CRYPT_EAL_PkeyCtx *src = (CRYPT_EAL_PkeyCtx *)val;
    CRYPT_EAL_PkeyCtx **dest = (CRYPT_EAL_PkeyCtx **)pkey;

    if (*dest != NULL) {
        CRYPT_EAL_PkeyFreeCtx(*dest);
        *dest = NULL;
    }

    *dest = CRYPT_EAL_PkeyDupCtx(src);
    if (*dest == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_KEY);
        return HITLS_X509_ERR_SET_KEY;
    }
    return HITLS_X509_SUCCESS;
}

static HITLS_X509_NameNode *DupNameNode(const HITLS_X509_NameNode *src)
{
    /* Src is not null. */
    HITLS_X509_NameNode *dest = BSL_SAL_Malloc(sizeof(HITLS_X509_NameNode));
    if (dest == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    dest->layer = src->layer;

    // nameType
    dest->nameType = src->nameType;
    dest->nameType.len = src->nameType.len;
    if (dest->nameType.len != 0) {
        dest->nameType.buff = BSL_SAL_Dump(src->nameType.buff, src->nameType.len);
        if (dest->nameType.buff == NULL) {
            BSL_SAL_Free(dest);
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return NULL;
        }
    }

    // nameValue
    dest->nameValue = src->nameValue;
    dest->nameValue.len = src->nameValue.len;
    if (dest->nameValue.len != 0) {
        dest->nameValue.buff = BSL_SAL_Dump(src->nameValue.buff, src->nameValue.len);
        if (dest->nameValue.buff == NULL) {
            BSL_SAL_Free(dest->nameType.buff);
            BSL_SAL_Free(dest);
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return NULL;
        }
    }
    return dest;
}

#define X509_DN_NAME_ELEM_NUMBER 2

static int32_t X509EncodeNameNodeEntry(const HITLS_X509_NameNode *nameNode, BSL_ASN1_Buffer *asn1Buff)
{
    BSL_ASN1_Buffer asnArr[X509_DN_NAME_ELEM_NUMBER] = {
        nameNode->nameType,
        nameNode->nameValue,
    };
    BSL_ASN1_TemplateItem dnTempl[] = {
        {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
        {BSL_ASN1_TAG_ANY, 0, 0}
    };

    BSL_ASN1_Buffer asnDnBuff = {};
    BSL_ASN1_Template dntTempl = {dnTempl, sizeof(dnTempl) / sizeof(dnTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&dntTempl, asnArr, X509_DN_NAME_ELEM_NUMBER,
        &asnDnBuff.buff, &asnDnBuff.len);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asnDnBuff.tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    BSL_ASN1_TemplateItem seqItem = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0};
    BSL_ASN1_Template seqTempl = {&seqItem, 1};
    ret = BSL_ASN1_EncodeTemplate(&seqTempl, &asnDnBuff, 1, &asn1Buff->buff, &asn1Buff->len);
    BSL_SAL_FREE(asnDnBuff.buff);
    return ret;
}

/**
 *  X.690: 11.6 Set-of components
 *  https://www.itu.int/rec/T-REC-X.690-202102-I/en
 * The encodings of the component values of a set-of value shall appear in ascending order, the encodings
 * being compared as octet strings with the shorter components being padded at their trailing end with 0-octets.
 * NOTE – The padding octets are for comparison purposes only and do not appear in the encodings.
*/
static int32_t g_cmpRes = HITLS_X509_SUCCESS;
static int32_t CmpDnNameByEncode(const void *pDnName1, const void *pDnName2)
{
    if (pDnName1 == NULL || pDnName2 == NULL) {
        g_cmpRes = HITLS_X509_ERR_CERT_INVALID_DN;
        return 0;
    }
    const HITLS_X509_NameNode *node1 = *(const HITLS_X509_NameNode **)pDnName1;
    const HITLS_X509_NameNode *node2 = *(const HITLS_X509_NameNode **)pDnName2;
    int res;
    BSL_ASN1_Buffer asn1Buff = {0};
    BSL_ASN1_Buffer asn2Buff = {0};
    int32_t ret = X509EncodeNameNodeEntry(node1, &asn1Buff);
    if (ret != HITLS_X509_SUCCESS) {
        g_cmpRes = HITLS_X509_ERR_SORT_NAME_NODE;
        BSL_ERR_PUSH_ERROR(ret);
        return 0;
    }

    ret = X509EncodeNameNodeEntry(node2, &asn2Buff);
    if (ret != HITLS_X509_SUCCESS) {
        g_cmpRes = HITLS_X509_ERR_SORT_NAME_NODE;
        BSL_SAL_FREE(asn1Buff.buff);
        BSL_ERR_PUSH_ERROR(ret);
        return 0;
    }

    if (asn1Buff.len == asn2Buff.len) {
        res = memcmp(asn1Buff.buff, asn2Buff.buff, asn2Buff.len);
    } else {
        uint32_t minSize = asn1Buff.len < asn2Buff.len ? asn1Buff.len : asn2Buff.len;
        res = memcmp(asn1Buff.buff, asn2Buff.buff, minSize);
        if (res == 0) {
            res = asn1Buff.len == minSize ? -1 : 1;
        }
    }
    g_cmpRes = HITLS_X509_SUCCESS;
    BSL_SAL_FREE(asn1Buff.buff);
    BSL_SAL_FREE(asn2Buff.buff);
    return res;
}

/**
 * RFC 5280:
 *   section 7.1:
 *      Representation of internationalized names in distinguished names is
 *      covered in Sections 4.1.2.4, Issuer Name, and 4.1.2.6, Subject Name.
 *      Standard naming attributes, such as common name, employ the
 *      DirectoryString type, which supports internationalized names through
 *      a variety of language encodings.  Conforming implementations MUST
 *      support UTF8String and PrintableString.
 *   appendix-A.1:
 *      X520SerialNumber ::=    PrintableString (SIZE (1..ub-serial-number))
 *      X520countryName ::=     PrintableString
 *      X520dnQualifier ::=     PrintableString
 */
static int32_t GetAsn1TypeByCid(BslCid cid)
{
    switch (cid) {
        case BSL_CID_SERIALNUMBER:
        case BSL_CID_COUNTRYNAME:
        case BSL_CID_DNQUALIFIER:
            return BSL_ASN1_TAG_PRINTABLESTRING;
        case BSL_CID_DOMAINCOMPONENT:
            return BSL_ASN1_TAG_IA5STRING;
        default:
            return BSL_ASN1_TAG_UTF8STRING;
    }
}

void HITLS_X509_FreeNameNode(HITLS_X509_NameNode *node)
{
    if (node == NULL) {
        return;
    }
    BSL_SAL_FREE(node->nameType.buff);
    node->nameType.len = 0;
    node->nameType.tag = 0;
    BSL_SAL_FREE(node->nameValue.buff);
    node->nameValue.len = 0;
    node->nameValue.tag = 0;
    BSL_SAL_Free(node);
}

int32_t HITLS_X509_SetNameList(BslList **dest, void *val, int32_t valLen)
{
    if (dest == NULL || val == NULL || valLen != sizeof(BslList)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    BslList *src = (BslList *)val;

    BSL_LIST_FREE(*dest, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
    *dest = BSL_LIST_Copy(src, (BSL_LIST_PFUNC_DUP)DupNameNode, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
    if (*dest == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_NAME_LIST);
        return HITLS_X509_ERR_SET_NAME_LIST;
    }
    return HITLS_X509_SUCCESS;
}

static int32_t FillNameNodes(HITLS_X509_NameNode *layer2, uint8_t *data, uint32_t dataLen, BslOidString *oid)
{
    layer2->layer = 2; // 2: The layer of sequence
    layer2->nameType.tag = BSL_ASN1_TAG_OBJECT_ID;
    
    layer2->nameType.buff = BSL_SAL_Dump((uint8_t *)oid->octs, oid->octetLen);
    layer2->nameValue.buff = BSL_SAL_Dump(data, dataLen);
    if (layer2->nameType.buff == NULL || layer2->nameValue.buff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }

    layer2->nameType.len = oid->octetLen;
    layer2->nameValue.len = dataLen;
    return HITLS_X509_SUCCESS;
}

static int32_t X509AddDnNameItemToList(BslList *dnNameList, BslCid cid, uint8_t *data, uint32_t dataLen)
{
    if (data == NULL || dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    const BslAsn1StrInfo *asn1StrInfo = BSL_OBJ_GetAsn1StrFromCid(cid);
    if (asn1StrInfo == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_DNNAME_UNKKOWN);
        return HITLS_X509_ERR_SET_DNNAME_UNKKOWN;
    }
    if (asn1StrInfo->max != -1 && ((int32_t)dataLen < asn1StrInfo->min || (int32_t)dataLen > asn1StrInfo->max)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_DNNAME_INVALID_LEN);
        return HITLS_X509_ERR_SET_DNNAME_INVALID_LEN;
    }
    BslOidString *oid = BSL_OBJ_GetOidFromCID(cid);
    if (oid == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_DNNAME_UNKKOWN);
        return HITLS_X509_ERR_SET_DNNAME_UNKKOWN;
    }

    HITLS_X509_NameNode *layer2 = BSL_SAL_Calloc(1, sizeof(HITLS_X509_NameNode));
    if (layer2 == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    layer2->nameValue.tag = GetAsn1TypeByCid(cid);
    int32_t ret = FillNameNodes(layer2, data, dataLen, oid);
    if (ret != HITLS_X509_SUCCESS) {
        HITLS_X509_FreeNameNode(layer2);
        return ret;
    }

    ret = BSL_LIST_AddElement(dnNameList, layer2, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_FreeNameNode(layer2);
    }

    return ret;
}

static int32_t X509AddDnNamesToList(BslList *list, const BslList *dnNameList)
{
    HITLS_X509_NameNode *layer1 = BSL_SAL_Calloc(1, sizeof(HITLS_X509_NameNode));
    if (layer1 == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    layer1->layer = 1;

    int32_t ret = BSL_LIST_AddElement(list, layer1, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_X509_FreeNameNode(layer1);
        return ret;
    }

    list = BSL_LIST_Concat(list, dnNameList);
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_ERR_CONCAT);
        HITLS_X509_FreeNameNode(layer1);
        return BSL_LIST_ERR_CONCAT;
    }

    return ret;
}

int32_t HITLS_X509_AddDnName(BslList *list, HITLS_X509_DN *dnNames, int32_t size)
{
    if (list == NULL || dnNames == NULL || size <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (BSL_LIST_COUNT(list) == HITLS_X509_DNNAME_MAX_NUM) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_DNNAME_TOOMUCH);
        return HITLS_X509_ERR_SET_DNNAME_TOOMUCH;
    }

    BslList *dnNameList = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (dnNameList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret;
    for (int32_t i = 0; i < size; i++) {
        ret = X509AddDnNameItemToList(dnNameList, dnNames[i].cid, dnNames[i].data, dnNames[i].dataLen);
        if (ret != HITLS_X509_SUCCESS) {
            goto ERR;
        }
    }
    // sort
    dnNameList = BSL_LIST_Sort(dnNameList, CmpDnNameByEncode);
    if (g_cmpRes != HITLS_X509_SUCCESS) {
        ret = g_cmpRes;
        goto ERR;
    }
    // add dnNameList to list
    ret = X509AddDnNamesToList(list, dnNameList);
    if (ret != HITLS_X509_SUCCESS) {
        goto ERR;
    }
    BSL_SAL_FREE(dnNameList);
    return ret;
ERR:
    BSL_ERR_PUSH_ERROR(ret);
    BSL_LIST_FREE(dnNameList, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
    return ret;
}

int32_t HITLS_X509_SetSerial(BSL_ASN1_Buffer *serial, const void *val, int32_t valLen)
{
    if (valLen <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_INVALID_SERIAL_NUM);
        return HITLS_X509_ERR_CERT_INVALID_SERIAL_NUM;
    }
    const uint8_t *src = (const uint8_t *)val;
    serial->buff = BSL_SAL_Dump(src, valLen);
    if (serial->buff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    serial->len = valLen;
    serial->tag = BSL_ASN1_TAG_INTEGER;
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_GetSerial(BSL_ASN1_Buffer *serial, const void *val, int32_t valLen)
{
    if (valLen != sizeof(BSL_Buffer)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (serial->buff == NULL || serial->len == 0 || serial->tag != BSL_ASN1_TAG_INTEGER) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    BSL_Buffer *buff = (BSL_Buffer *)val;
    buff->data = serial->buff;
    buff->dataLen = serial->len;
    return HITLS_X509_SUCCESS;
}
