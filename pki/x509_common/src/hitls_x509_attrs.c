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
#if (defined(HITLS_PKI_X509_CSR) && defined(HITLS_PKI_X509_CSR_ATTR)) || defined(HITLS_PKI_PKCS12)
#include <stdint.h>
#include "securec.h"
#include "hitls_x509_local.h"
#include "bsl_obj.h"
#include "bsl_sal.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_utils.h"

#if defined(HITLS_PKI_X509_CSR_PARSE) || defined(HITLS_PKI_PKCS12_PARSE)
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
#endif

#define HITLS_X509_ATTR_MAX_NUM  20
#define HITLS_X509_ATTRS_PARSE_FLAG  0x01
#define HITLS_X509_ATTRS_GEN_FLAG    0x02

HITLS_X509_Attrs *HITLS_X509_AttrsNew(void)
{
    HITLS_X509_Attrs *attrs = (HITLS_X509_Attrs *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_Attrs));
    if (attrs == NULL) {
        return NULL;
    }
    attrs->list = BSL_LIST_New(sizeof(HITLS_X509_AttrEntry *));
    if (attrs->list == NULL) {
        BSL_SAL_Free(attrs);
        return NULL;
    }

    attrs->flag = HITLS_X509_ATTRS_GEN_FLAG;
    return attrs;
}

/*
* For pkcs12, parsing and encoding operation uses deep copy, and it use callback function to free
* For csr, parsing operation uses shallow copy, and encoding operation uses deep copy
*/
void HITLS_X509_AttrsFree(HITLS_X509_Attrs *attrs, HITLS_X509_FreeAttrItemCb freeItem)
{
    if (attrs == NULL) {
        return;
    }
    if (freeItem != NULL) {
        BSL_LIST_FREE(attrs->list, (BSL_LIST_PFUNC_FREE)freeItem);
        BSL_SAL_Free(attrs);
        return;
    }

    if ((attrs->flag & HITLS_X509_ATTRS_PARSE_FLAG) != 0) {
        BSL_LIST_FREE(attrs->list, NULL);
    } else {
        BSL_LIST_FREE(attrs->list, (BSL_LIST_PFUNC_FREE)HITLS_X509_AttrEntryFree);
    }
    BSL_SAL_Free(attrs);
}

#if defined(HITLS_PKI_X509_CSR_GEN) || defined(HITLS_PKI_PKCS12_GEN)
int32_t HITLS_X509_EncodeObjIdentity(BslCid cid, BSL_ASN1_Buffer *asnBuff)
{
    BslOidString *oidStr = BSL_OBJ_GetOID(cid);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    asnBuff->tag = BSL_ASN1_TAG_OBJECT_ID;
    asnBuff->buff = (uint8_t *)oidStr->octs;
    asnBuff->len = oidStr->octetLen;

    return HITLS_PKI_SUCCESS;
}
#endif

#ifdef HITLS_PKI_PKCS12_GEN
HITLS_X509_Attrs *HITLS_X509_AttrsDup(const HITLS_X509_Attrs *src, HITLS_X509_DupAttrItemCb dupCb,
    HITLS_X509_FreeAttrItemCb freeCb)
{
    if (src == NULL || BSL_LIST_COUNT(src->list) <= 0 ||
        dupCb == NULL || freeCb == NULL) {
        return NULL;
    }
    HITLS_X509_Attrs *dst = HITLS_X509_AttrsNew();
    if (dst == NULL) {
        return NULL;
    }
    void *node = NULL;
    for (node = BSL_LIST_GET_FIRST(src->list); node != NULL; node = BSL_LIST_GET_NEXT(src->list)) {
        void *dstEntry = dupCb(node);
        if (dstEntry == NULL) {
            HITLS_X509_AttrsFree(dst, freeCb);
            return NULL;
        }
        int32_t ret = BSL_LIST_AddElement(dst->list, dstEntry, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            freeCb(dstEntry);
            HITLS_X509_AttrsFree(dst, freeCb);
            return NULL;
        }
    }
    dst->flag = src->flag;
    return dst;
}
#endif

void HITLS_X509_AttrEntryFree(HITLS_X509_AttrEntry *attr)
{
    if (attr == NULL) {
        return;
    }
    BSL_SAL_Free(attr->attrValue.buff);
    BSL_SAL_Free(attr);
}

#if defined(HITLS_PKI_X509_CSR_PARSE) || defined(HITLS_PKI_PKCS12_PARSE)
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
    attrEntry->cid = BSL_OBJ_GetCidFromOidBuff(asnArr[HITLS_X509_ATTR_OID_IDX].buff,
        asnArr[HITLS_X509_ATTR_OID_IDX].len);
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
    HITLS_X509_ParseAttrItemCb parseCb = cbParam;
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
    if (parseCb != NULL) {
        ret = parseCb(list, node);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
        goto ERR;
    }

    ret = BSL_LIST_AddElement(list, node, BSL_LIST_POS_AFTER);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    return ret;
ERR:
    BSL_SAL_FREE(node);
    return ret;
}

int32_t HITLS_X509_ParseAttrList(BSL_ASN1_Buffer *attrBuff, HITLS_X509_Attrs *attrs, HITLS_X509_ParseAttrItemCb parseCb,
    HITLS_X509_FreeAttrItemCb freeItem)
{
    if (attrBuff->tag == 0 || attrBuff->buff == NULL || attrBuff->len == 0) {
        return HITLS_PKI_SUCCESS;
    }

    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {1, expTag};
    int32_t ret = BSL_ASN1_DecodeListItem(&listParam, attrBuff, &HITLS_X509_ParseAttrsListAsnItem, parseCb,
        attrs->list);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteAll(attrs->list, freeItem);
        return ret;
    }
    attrs->flag = HITLS_X509_ATTRS_PARSE_FLAG;
    return ret;
}
#endif

static int32_t CmpAttrEntryByCid(const void *attrEntry, const void *cid)
{
    const HITLS_X509_AttrEntry *node = attrEntry;
    return node->cid == *(const BslCid *)cid ? 0 : 1;
}

typedef int32_t (*DecodeAttrCb)(HITLS_X509_Attrs *attributes, HITLS_X509_AttrEntry *attrEntry, void *val,
    uint32_t valLen);

#if defined(HITLS_PKI_X509_CSR_GEN) || defined(HITLS_PKI_PKCS12_GEN)

typedef int32_t (*EncodeAttrCb)(HITLS_X509_Attrs *attributes, void *val, uint32_t valLen, BSL_ASN1_Buffer *attrValue);

static int32_t EncodeReqExtAttr(HITLS_X509_Attrs *attributes, void *val, uint32_t valLen, BSL_ASN1_Buffer *attrValue)
{
    (void)valLen;
    (void)attributes;
    HITLS_X509_Ext *ext = (HITLS_X509_Ext *)val;
    return HITLS_X509_EncodeExt(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, ext->extList, attrValue);
}

static int32_t SetAttr(HITLS_X509_Attrs *attributes, BslCid cid, void *val, uint32_t valLen, EncodeAttrCb encodeAttrCb)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    /* Check if the attribute already exists. */
    if (BSL_LIST_Search(attributes->list, &cid, CmpAttrEntryByCid, NULL) != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_ATTR_REPEAT);
        return HITLS_X509_ERR_SET_ATTR_REPEAT;
    }

    HITLS_X509_AttrEntry *attrEntry = BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    if (attrEntry == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_X509_EncodeObjIdentity(cid, &attrEntry->attrId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = encodeAttrCb(attributes, val, valLen, &attrEntry->attrValue);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    attrEntry->cid = cid;
    ret = BSL_LIST_AddElement(attributes->list, attrEntry, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    return ret;

ERR:
    HITLS_X509_AttrEntryFree(attrEntry);
    return ret;
}
#endif // HITLS_PKI_X509_CSR_GEN || HITLS_PKI_PKCS12_GEN

static int32_t DecodeReqExtAttr(HITLS_X509_Attrs *attributes, HITLS_X509_AttrEntry *attrEntry, void *val,
    uint32_t valLen)
{
    (void)attributes;
    if (valLen != sizeof(HITLS_X509_Ext *)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
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
    *(HITLS_X509_Ext **)val = ext;
    return HITLS_PKI_SUCCESS;
}

static int32_t GetAttr(HITLS_X509_Attrs *attributes, BslCid cid, void *val, uint32_t valLen, DecodeAttrCb decodeAttrCb)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    HITLS_X509_AttrEntry *attrEntry = BSL_LIST_Search(attributes->list, &cid, CmpAttrEntryByCid, NULL);
    if (attrEntry == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ATTR_NOT_FOUND);
        return HITLS_X509_ERR_ATTR_NOT_FOUND;
    }

    return decodeAttrCb(attributes, attrEntry, val, valLen);
}

int32_t HITLS_X509_AttrCtrl(HITLS_X509_Attrs *attributes, HITLS_X509_AttrCmd cmd, void *val, uint32_t valLen)
{
    if (attributes == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    switch (cmd) {
#if defined(HITLS_PKI_X509_CSR_GEN) || defined(HITLS_PKI_PKCS12_GEN)
        case HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS:
            return SetAttr(attributes, BSL_CID_EXTENSIONREQUEST, val, valLen, EncodeReqExtAttr);
#endif
        case HITLS_X509_ATTR_GET_REQUESTED_EXTENSIONS:
            return GetAttr(attributes, BSL_CID_EXTENSIONREQUEST, val, valLen, DecodeReqExtAttr);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

#if defined(HITLS_PKI_X509_CSR_GEN) || defined(HITLS_PKI_PKCS12_GEN)

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
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    attrBuff->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return ret;
}

void FreeAsnAttrsBuff(BSL_ASN1_Buffer *asnBuf, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        BSL_SAL_FREE(asnBuf[i].buff);
    }
    BSL_SAL_FREE(asnBuf);
}

int32_t HITLS_X509_EncodeAttrList(uint8_t tag, HITLS_X509_Attrs *attrs, HITLS_X509_EncodeAttrItemCb encodeCb,
    BSL_ASN1_Buffer *attrAsn1)
{
    if (attrs == NULL || attrs->list == NULL || BSL_LIST_COUNT(attrs->list) <= 0) {
        attrAsn1->tag = tag;
        attrAsn1->buff = NULL;
        attrAsn1->len = 0;
        return HITLS_PKI_SUCCESS;
    }
    uint32_t count = (uint32_t)BSL_LIST_COUNT(attrs->list);
    /* no attribute */
    BSL_ASN1_Buffer *asnBuf = BSL_SAL_Calloc(count, sizeof(BSL_ASN1_Buffer));
    if (asnBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t iter = 0;
    int32_t ret;
    void *node = NULL;
    for (node = BSL_LIST_GET_FIRST(attrs->list); node != NULL; node = BSL_LIST_GET_NEXT(attrs->list), iter++) {
        HITLS_X509_AttrEntry attrEntry = {};
        if (encodeCb != NULL) {
            ret = encodeCb(node, &attrEntry);
            if (ret != HITLS_PKI_SUCCESS) {
                FreeAsnAttrsBuff(asnBuf, count);
                return ret;
            }
        } else {
            attrEntry = *(HITLS_X509_AttrEntry *)node;
        }
        ret = HITLS_X509_EncodeAttrEntry(&attrEntry, &asnBuf[iter]);
        if (encodeCb != NULL) {
            BSL_SAL_FREE(attrEntry.attrValue.buff);
        }
        if (ret != HITLS_PKI_SUCCESS) {
            FreeAsnAttrsBuff(asnBuf, count);
            return ret;
        }
    }
    static BSL_ASN1_TemplateItem attrSeqTempl = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0 };
    BSL_ASN1_Template templ = {&attrSeqTempl, 1};
    ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, count, &templ, asnBuf, iter, attrAsn1);
    FreeAsnAttrsBuff(asnBuf, count);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    attrAsn1->tag = tag;
    return ret;
}
#endif // HITLS_PKI_X509_CSR_GEN || HITLS_PKI_PKCS12_GEN

#endif // (HITLS_PKI_X509_CSR && HITLS_PKI_X509_CSR_ATTR) || HITLS_PKI_PKCS12
