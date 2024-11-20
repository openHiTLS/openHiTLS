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

#include <stdint.h>
#include "securec.h"
#include "hitls_pki.h"
#include "hitls_x509_local.h"
#include "bsl_obj.h"
#include "bsl_sal.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "hitls_pki_errno.h"

/**
 * RFC 2985: section-5.4.2
 *  extensionRequest ATTRIBUTE ::= {
 *          WITH SYNTAX ExtensionRequest
 *          SINGLE VALUE TRUE
 *          ID pkcs-9-at-extensionRequest
 *  }
 * ExtensionRequest ::= Extensions
 */
static BSL_ASN1_TemplateItem g_x509AttrTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, BSL_ASN1_FLAG_HEADERONLY, 0},
};

typedef enum {
    HITLS_X509_ATTR_OID_IDX,
    HITLS_X509_ATTR_SET_IDX,
    HITLS_X509_ATTR_INDEX_MAX
} HITLS_X509_ATTR_IDX;

#define HITLS_X509_ATTR_MAX_NUM  20

int32_t HITLS_X509_EncodeObjIdentity(BslCid cid, BSL_ASN1_Buffer *asnBuff)
{
    BslOidString *oidStr = BSL_OBJ_GetOidFromCID(cid);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    asnBuff->tag = BSL_ASN1_TAG_OBJECT_ID;
    asnBuff->buff = (uint8_t *)oidStr->octs;
    asnBuff->len = oidStr->octetLen;

    return HITLS_X509_SUCCESS;
}

void HITLS_X509_AttrEntryFree(HITLS_X509_AttrEntry *attr)
{
    if (attr == NULL) {
        return;
    }
    BSL_SAL_Free(attr->attrValue.buff);
    BSL_SAL_Free(attr);
}

int32_t HITLS_X509_ParseAttr(BSL_ASN1_Buffer *attrItem, HITLS_X509_AttrEntry *attrEntry)
{
    uint8_t *temp = attrItem->buff;
    uint32_t tempLen = attrItem->len;
    BSL_ASN1_Buffer asnArr[HITLS_X509_ATTR_INDEX_MAX] = {0};
    BSL_ASN1_Template templ = {g_x509AttrTempl, sizeof(g_x509AttrTempl) / sizeof(g_x509AttrTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_X509_ATTR_INDEX_MAX);
    if (tempLen != 0) {
        ret = HITLS_X509_ERR_PARSE_ATTR_BUF;
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* parse attribute id */
    BslOidString oid = {asnArr[HITLS_X509_ATTR_OID_IDX].len, (char *)asnArr[HITLS_X509_ATTR_OID_IDX].buff, 0};
    attrEntry->cid = BSL_OBJ_GetCIDFromOid(&oid);
    if (attrEntry->cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_OBJ_ID);
        return HITLS_X509_ERR_PARSE_OBJ_ID;
    }
    /* set id and value asn1 buffer */
    attrEntry->attrId = asnArr[HITLS_X509_ATTR_OID_IDX];
    attrEntry->attrValue = asnArr[HITLS_X509_ATTR_SET_IDX];
    return ret;
}

int32_t HITLS_X509_ParseAttrsListAsnItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *cbParam, BSL_ASN1_List *list)
{
    (void)layer;
    (void)cbParam;
    HITLS_X509_AttrEntry *node = BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    if (node == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    /* parse attribute entry */
    int32_t ret = HITLS_X509_ParseAttr(asn, node);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = BSL_LIST_AddElement(list, node, BSL_LIST_POS_AFTER);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    return ret;
ERR:
    HITLS_X509_AttrEntryFree(node);
    return ret;
}

int32_t HITLS_X509_ParseAttrList(BSL_ASN1_Buffer *attrs, BSL_ASN1_List *list)
{
    if (attrs->tag == 0 || attrs->buff == NULL || attrs->len == 0) {
        return HITLS_X509_SUCCESS;
    }

    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {1, expTag};
    int32_t ret = BSL_ASN1_DecodeListItem(&listParam, attrs, HITLS_X509_ParseAttrsListAsnItem, NULL, list);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteAll(list, NULL);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t CmpAttrEntryByCid(const void *attrEntry, const void *cid)
{
    const HITLS_X509_AttrEntry *node = attrEntry;
    const BslCid *oid = cid;

    return node->cid == *(BslCid *)oid ? 0 : 1;
}

typedef int32_t (*EncodeAttrCb)(void *attrItem, BSL_ASN1_Buffer *attrValue);

typedef int32_t (*DecodeAttrCb)(HITLS_X509_AttrEntry *attrEntry, void *attrItem);

static int32_t EncodeReqExtAttr(void *attrItem, BSL_ASN1_Buffer *attrValue)
{
    if (attrItem == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    HITLS_X509_Ext *ext = (HITLS_X509_Ext *)attrItem;
    return HITLS_X509_EncodeExt(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, ext->extList, attrValue);
}

static int32_t SetAttr(BSL_ASN1_List *attributes, void *val, uint32_t valLen, EncodeAttrCb encodeAttrCb)
{
    HITLS_X509_Attr *attr = (HITLS_X509_Attr *)val;
    if (valLen != sizeof(HITLS_X509_Attr)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    /* Check if the attribute already exists. */
    if (BSL_LIST_Search(attributes, &attr->cid, CmpAttrEntryByCid, NULL) != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_ATTR_REPEAT);
        return HITLS_X509_ERR_SET_ATTR_REPEAT;
    }

    HITLS_X509_AttrEntry *attrEntry = BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    if (attrEntry == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_X509_EncodeObjIdentity(attr->cid, &attrEntry->attrId);
    if (ret != HITLS_X509_SUCCESS) {
        goto ERR;
    }

    ret = encodeAttrCb(attr->value, &attrEntry->attrValue);
    if (ret != HITLS_X509_SUCCESS) {
        goto ERR;
    }
    attrEntry->cid = attr->cid;
    ret = BSL_LIST_AddElement(attributes, attrEntry, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        goto ERR;
    }

    return ret;

ERR:
    BSL_ERR_PUSH_ERROR(ret);
    HITLS_X509_AttrEntryFree(attrEntry);
    return ret;
}

static int32_t DecodeReqExtAttr(HITLS_X509_AttrEntry *attrEntry, void *attrItem)
{
    HITLS_X509_Ext *ext = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
    if (ext == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_X509_ParseExt(&attrEntry->attrValue, ext);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_ExtFree(ext);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *(HITLS_X509_Ext **)attrItem = ext;
    return HITLS_X509_SUCCESS;
}

static int32_t GetAttr(BSL_ASN1_List *attributes, void *val, int32_t valLen, DecodeAttrCb decodeAttrCb)
{
    HITLS_X509_Attr *attr = val;
    if (attr->value != NULL || valLen != sizeof(HITLS_X509_Attr)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    HITLS_X509_AttrEntry *attrEntry = BSL_LIST_Search(attributes, &attr->cid, CmpAttrEntryByCid, NULL);
    if (attrEntry == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ATTR_NOT_FOUND);
        return HITLS_X509_ERR_ATTR_NOT_FOUND;
    }
    return decodeAttrCb(attrEntry, &attr->value);
}

int32_t HITLS_X509_AttrCtrl(BslList *attributes, int32_t cmd, void *val, int32_t valLen)
{
    if (attributes == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    switch (cmd) {
        case HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS:
            return SetAttr(attributes, val, valLen, EncodeReqExtAttr);
        case HITLS_X509_ATTR_GET_REQUESTED_EXTENSIONS:
            ((HITLS_X509_Attr *)val)->cid = BSL_CID_REQ_EXTENSION;
            return GetAttr(attributes, val, valLen, DecodeReqExtAttr);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

#define X509_CSR_ATTR_ELEM_NUMBER 2
static BSL_ASN1_TemplateItem g_x509AttrEntryTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, 0, 0},
};

int32_t HITLS_X509_EncodeAttrEntry(HITLS_X509_AttrEntry *node, BSL_ASN1_Buffer *attrBuff)
{
    BSL_ASN1_Buffer asnBuf[X509_CSR_ATTR_ELEM_NUMBER] = {0};
    asnBuf[0] = node->attrId;
    asnBuf[1] = node->attrValue;
    BSL_ASN1_Template templ = {g_x509AttrEntryTempl, sizeof(g_x509AttrEntryTempl) / sizeof(g_x509AttrEntryTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, asnBuf, X509_CSR_ATTR_ELEM_NUMBER, &attrBuff->buff, &attrBuff->len);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    attrBuff->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return ret;
}

void FreeAsnAttrsBuff(BSL_ASN1_Buffer *asnBuf, int32_t count)
{
    for (int32_t i = 0; i < count; i++) {
        BSL_SAL_FREE(asnBuf[i].buff);
    }
    BSL_SAL_FREE(asnBuf);
}

int32_t HITLS_X509_EncodeAttrList(uint8_t tag, BSL_ASN1_List *list, BSL_ASN1_Buffer *attr)
{
    int32_t count = BSL_LIST_COUNT(list);
    /* no attribute */
    if (count <= 0) {
        attr->tag = tag;
        attr->buff = NULL;
        attr->len = 0;
        return HITLS_X509_SUCCESS;
    }
    BSL_ASN1_Buffer *asnBuf = BSL_SAL_Calloc(count, sizeof(BSL_ASN1_Buffer));
    if (asnBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t iter = 0;
    int32_t ret;
    HITLS_X509_AttrEntry *node = NULL;
    for (node = BSL_LIST_GET_FIRST(list); node != NULL; node = BSL_LIST_GET_NEXT(list), iter++) {
        ret = HITLS_X509_EncodeAttrEntry(node, &asnBuf[iter]);
        if (ret != HITLS_X509_SUCCESS) {
            FreeAsnAttrsBuff(asnBuf, count);
            return  ret;
        }
    }
    static BSL_ASN1_TemplateItem attrSeqTempl = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0 };
    BSL_ASN1_Template templ = {&attrSeqTempl, 1};
    ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, count, &templ, asnBuf, iter, attr);
    FreeAsnAttrsBuff(asnBuf, count);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    attr->tag = tag;
    return HITLS_X509_SUCCESS;
}
