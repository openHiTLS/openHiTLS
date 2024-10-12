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

#include "hitls_x509.h"
#include "bsl_sal.h"
#include "sal_file.h"
#include "securec.h"
#include "hitls_x509_errno.h"
#include "hitls_x509_local.h"
#include "hitls_cert_local.h"
#include "hitls_cms_local.h"

#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "hitls_pkcs12_local.h"
#include "crypt_encode.h"
#include "crypt_eal_encode.h"
#include "bsl_type.h"

#define HITLS_P12_CTX_SPECIFIC_TAG_EXTENSION 0

/* common Bag, including crl, cert, secret ... */
BSL_ASN1_TemplateItem g_pk12CommonBagTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        /* bagId */
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        /* bagValue */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_P12_CTX_SPECIFIC_TAG_EXTENSION, 0, 1},
            {BSL_ASN1_TAG_OCTETSTRING, 0, 2},
};

typedef enum {
    HITLS_PKCS12_COMMON_SAFEBAG_OID_IDX,
    HITLS_PKCS12_COMMON_SAFEBAG_BAGVALUES_IDX,
    HITLS_PKCS12_COMMON_SAFEBAG_MAX_IDX,
} HITLS_PKCS12_COMMON_SAFEBAG_IDX;

/* parse bags, and revoker already knows they are one of the Commonbags */
static int32_t ParseCommonSafeBag(BSL_Buffer *buffer, HTILS_PKCS12_CommonSafeBag *bag)
{
    uint8_t *temp = buffer->data;
    uint32_t  tempLen = buffer->dataLen;
    BSL_ASN1_Buffer asnArr[HITLS_PKCS12_COMMON_SAFEBAG_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_pk12CommonBagTempl, sizeof(g_pk12CommonBagTempl) / sizeof(g_pk12CommonBagTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL,
        &temp, &tempLen, asnArr, HITLS_PKCS12_COMMON_SAFEBAG_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString oidStr = {asnArr[HITLS_PKCS12_COMMON_SAFEBAG_OID_IDX].len,
        (char *)asnArr[HITLS_PKCS12_COMMON_SAFEBAG_OID_IDX].buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (cid == BSL_CID_UNKNOWN) {
        ret = HITLS_PKCS12_ERR_PARSE_TYPE;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bag->bagId = cid;
    bag->bagValue = BSL_SAL_Malloc(sizeof(BSL_Buffer));
    if (bag->bagValue == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bag->bagValue->data = asnArr[HITLS_PKCS12_COMMON_SAFEBAG_BAGVALUES_IDX].buff;
    bag->bagValue->dataLen = asnArr[HITLS_PKCS12_COMMON_SAFEBAG_BAGVALUES_IDX].len;
    return HITLS_X509_SUCCESS;
}

/* Convert commonBags to the cert */
static int32_t ConverCertBag(HTILS_PKCS12_CommonSafeBag *bag, HITLS_X509_Cert **cert)
{
    if (bag == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (bag->bagId != BSL_CID_X509CERTIFICATE) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_CERTYPES);
        return HITLS_PKCS12_ERR_INVALID_CERTYPES;
    }
    return HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, bag->bagValue, cert);
}

static int32_t ConverAttributes(BslCid cid, BSL_ASN1_Buffer *buffer, BSL_Buffer *output)
{
    uint8_t *temp = buffer->buff;
    uint32_t tempLen = buffer->len;
    uint32_t valueLen = buffer->len;
    int32_t ret;
    switch (cid) {
        case BSL_CID_FRIENDLYNAME:
            ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_BMPSTRING, &temp, &tempLen, &valueLen);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            output->data = BSL_SAL_Dump(temp, valueLen);
            if (output->data == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                return BSL_MALLOC_FAIL;
            }
            output->dataLen = valueLen;
            return HITLS_X509_SUCCESS;
        case BSL_CID_LOCATEDID:
            ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &temp, &tempLen, &valueLen);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            output->data = BSL_SAL_Dump(temp, valueLen);
            if (output->data == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                return BSL_MALLOC_FAIL;
            }
            output->dataLen = valueLen;
            return HITLS_X509_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES;
    }
}

static int32_t ParseAttr(HITLS_X509_AttrEntry *entry, BSL_ASN1_List *list)
{
    HTILS_PKCS12_SafeBagAttr attr = {0};
    attr.attrId = entry->cid;
    attr.attrValue = BSL_SAL_Malloc(sizeof(BSL_Buffer));
    if (attr.attrValue == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = ConverAttributes(entry->cid, &entry->attrValue, attr.attrValue);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_SAL_Free(attr.attrValue);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_ParseItemDefault(&attr, sizeof(HTILS_PKCS12_SafeBagAttr), list);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(attr.attrValue->data);
        BSL_SAL_Free(attr.attrValue);
    }
    return ret;
}

int32_t HITLS_PKCS12_ParseSafeBagAttr(BSL_ASN1_Buffer *attribute, BSL_ASN1_List *attriList)
{
    if (attribute->len == 0) {
        return HITLS_X509_SUCCESS; //  bagAttributes are OPTIONAL
    }

    BSL_ASN1_List *list = BSL_LIST_New(sizeof(HITLS_X509_AttrEntry));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_X509_ParseAttrList(attribute, list);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_FREE(list, NULL);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_List *tmpList = list;
    HITLS_X509_AttrEntry *node = BSL_LIST_GET_FIRST(tmpList);
    while (node != NULL) {
        ret = ParseAttr(node, attriList);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto err;
        }
        node = BSL_LIST_GET_NEXT(tmpList);
    }
err:
    BSL_LIST_FREE(list, NULL);
    return ret;
}

/*
 SafeBag ::= SEQUENCE {
     bagId          BAG-TYPE.&id ({PKCS12BagSet})
     bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
     bagAttributes  SET OF PKCS12Attribute OPTIONAL
 }
*/
BSL_ASN1_TemplateItem g_pk12SafeBagTempl[] = {
        /* bagId */
        {BSL_ASN1_TAG_OBJECT_ID, BSL_ASN1_FLAG_DEFAULT, 0},
        /* bagValue */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_P12_CTX_SPECIFIC_TAG_EXTENSION,
            BSL_ASN1_FLAG_HEADERONLY, 0},
        /* bagAttributes */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_OPTIONAL, 0},
};

typedef enum {
    HITLS_PKCS12_SAFEBAG_OID_IDX,
    HITLS_PKCS12_SAFEBAG_BAGVALUES_IDX,
    HITLS_PKCS12_SAFEBAG_BAGATTRIBUTES_IDX,
    HITLS_PKCS12_SAFEBAG_MAX_IDX,
} HITLS_PKCS12_SAFEBAG_IDX;

/*
 * Parse the 'safeBag' of p12. This interface only parses the outermost layer and attributes of safeBag,
 * others are handed over to the next layer for parsing
*/
static int32_t ParseSafeBag(BSL_Buffer *buffer, HTILS_PKCS12_SafeBag *safeBag)
{
    uint8_t *temp = buffer->data;
    uint32_t tempLen = buffer->dataLen;
    BSL_ASN1_Template templ = {g_pk12SafeBagTempl, sizeof(g_pk12SafeBagTempl) / sizeof(g_pk12SafeBagTempl[0])};
    BSL_ASN1_Buffer asnArr[HITLS_PKCS12_SAFEBAG_MAX_IDX] = {0};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_PKCS12_SAFEBAG_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BslOidString oid = {asnArr[HITLS_PKCS12_SAFEBAG_OID_IDX].len, (char *)asnArr[HITLS_PKCS12_SAFEBAG_OID_IDX].buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oid);
    if (cid == BSL_CID_UNKNOWN) {
        ret = HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_List *attributes = NULL;
    BSL_Buffer *bag = BSL_SAL_Malloc(sizeof(BSL_Buffer));
    if (bag == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    bag->data = BSL_SAL_Dump(asnArr[HITLS_PKCS12_SAFEBAG_BAGVALUES_IDX].buff,
        asnArr[HITLS_PKCS12_SAFEBAG_BAGVALUES_IDX].len);
    if (bag->data == NULL) {
        ret = BSL_MALLOC_FAIL;
        goto err;
    }
    bag->dataLen = asnArr[HITLS_PKCS12_SAFEBAG_BAGVALUES_IDX].len;
    attributes = BSL_LIST_New(sizeof(HTILS_PKCS12_SafeBagAttr));
    if (attributes == NULL) {
        ret = BSL_MALLOC_FAIL;
        goto err;
    }
    ret = HITLS_PKCS12_ParseSafeBagAttr(asnArr + HITLS_PKCS12_SAFEBAG_BAGATTRIBUTES_IDX, attributes);
    if (ret != HITLS_X509_SUCCESS) {
        goto err;
    }
    safeBag->attributes = attributes;
    safeBag->bagId = cid;
    safeBag->bag = bag;
    return ret;
err:
    BSL_ERR_PUSH_ERROR(ret);
    BSL_SAL_FREE(bag->data);
    BSL_SAL_FREE(bag);
    BSL_LIST_FREE(attributes, HTILS_PKCS12_AttributesFree);
    return ret;
}

static int32_t ParsePKCS8ShroudedKeyBags(HTILS_PKCS12_p12Info *p12, const uint8_t *pwd, uint32_t pwdlen,
    HTILS_PKCS12_SafeBag *safeBag)
{
    CRYPT_EAL_PkeyCtx *prikey = NULL;
    int32_t ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_ENCRYPT,
        safeBag->bag, pwd, pwdlen, &prikey);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    p12->key->value.key = prikey;
    p12->key->attributes = safeBag->attributes;
    safeBag->attributes = NULL;
    return HITLS_X509_SUCCESS;
}

static int32_t ParseCertBagAndAddList(HTILS_PKCS12_p12Info *p12, HTILS_PKCS12_SafeBag *safeBag)
{
    HTILS_PKCS12_CommonSafeBag bag = {0};
    int32_t ret = ParseCommonSafeBag(safeBag->bag, &bag);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_X509_Cert *cert = NULL;
    ret = ConverCertBag(&bag, &cert);
    BSL_SAL_FREE(bag.bagValue);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HTILS_PKCS12_Bag *bagData = BSL_SAL_Malloc(sizeof(HTILS_PKCS12_Bag));
    if (bagData == NULL) {
        HITLS_X509_CertFree(cert);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    bagData->attributes = safeBag->attributes;
    bagData->value.cert = cert;
    ret = BSL_LIST_AddElement(p12->certList, bagData, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        bagData->attributes = NULL;
        BSL_SAL_Free(bagData);
        HITLS_X509_CertFree(cert);
        BSL_ERR_PUSH_ERROR(ret);
    }
    safeBag->attributes = NULL;
    return ret;
}

/* Parse a Safebag to the data we need, such as a private key, etc */
int32_t HITLS_PKCS12_ConverSafeBag(HTILS_PKCS12_SafeBag *safeBag, const uint8_t *pwd, uint32_t pwdlen,
    HTILS_PKCS12_p12Info *p12)
{
    if (safeBag == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    switch (safeBag->bagId) {
        case BSL_CID_PKCS8SHROUDEDKEYBAG:
            if (p12->key->value.key != NULL) {
                return HITLS_X509_SUCCESS;
            }
            return ParsePKCS8ShroudedKeyBags(p12, pwd, pwdlen, safeBag);
        case BSL_CID_CERTBAG:
            return ParseCertBagAndAddList(p12, safeBag);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
    }
}

static void BagListsDestroyCb(void *bag)
{
    HTILS_PKCS12_SafeBagFree((HTILS_PKCS12_SafeBag *)bag);
}

/*
 * Defined in RFC 2531
 * ContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
*/
BSL_ASN1_TemplateItem g_pk12ContentInfoTempl[] = {
        /* content type */
        {BSL_ASN1_TAG_OBJECT_ID, BSL_ASN1_FLAG_DEFAULT, 0},
        /* content */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_P12_CTX_SPECIFIC_TAG_EXTENSION,
            BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_OPTIONAL, 0},
};

typedef enum {
    HITLS_PKCS12_CONTENT_OID_IDX,
    HITLS_PKCS12_CONTENT_VALUE_IDX,
    HITLS_PKCS12_CONTENT_MAX_IDX,
} HITLS_PKCS12_CONTENT_IDX;

int32_t HITLS_PKCS12_ParseContentInfo(BSL_Buffer *encode, const uint8_t *password, uint32_t passLen, BSL_Buffer *data)
{
    uint8_t *temp = encode->data;
    uint32_t tempLen = encode->dataLen;
    BSL_ASN1_Template templ = {g_pk12ContentInfoTempl,
        sizeof(g_pk12ContentInfoTempl) / sizeof(g_pk12ContentInfoTempl[0])};
    BSL_ASN1_Buffer asnArr[HITLS_PKCS12_CONTENT_MAX_IDX] = {0};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_PKCS12_CONTENT_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString oid = {asnArr[HITLS_PKCS12_CONTENT_OID_IDX].len, (char *)asnArr[HITLS_PKCS12_CONTENT_OID_IDX].buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oid);
    if (cid == BSL_CID_UNKNOWN) {
        ret = HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer asnArrdata = {asnArr[HITLS_PKCS12_CONTENT_VALUE_IDX].buff, asnArr[HITLS_PKCS12_CONTENT_VALUE_IDX].len};
    switch (cid) {
        case BSL_CID_DATA:
            return CRYPT_EAL_ParseAsn1PKCS7Data(&asnArrdata, data);
        case BSL_CID_ENCRYPTEDDATA:
            return CRYPT_EAL_ParseAsn1PKCS7EncryptedData(&asnArrdata, password, passLen, data);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
    }
}

/* Parse each safebag from list, and extract the data we need, such as a private key, etc */
int32_t HITLS_PKCS12_ParseSafeBagList(BSL_ASN1_List *bagList, const uint8_t *password,
    uint32_t passLen, HTILS_PKCS12_p12Info *p12)
{
    if (bagList == NULL || BSL_LIST_COUNT(bagList) == 0) {
        return HITLS_X509_SUCCESS;
    }
    int32_t ret;
    HTILS_PKCS12_SafeBag *node = BSL_LIST_GET_FIRST(bagList);
    while (node != NULL) {
        ret = HITLS_PKCS12_ConverSafeBag(node, password, passLen, p12);
        if (ret != HITLS_X509_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        node = BSL_LIST_GET_NEXT(bagList);
    }
    return HITLS_X509_SUCCESS;
}

static BSL_Buffer *FindLocatedId(BSL_ASN1_List *attributes)
{
    if (attributes == NULL) {
        return NULL;
    }
    HTILS_PKCS12_SafeBagAttr *node = BSL_LIST_GET_FIRST(attributes);
    while (node != NULL) {
        if (node->attrId == BSL_CID_LOCATEDID) {
            return node->attrValue;
        }
        node = BSL_LIST_GET_NEXT(attributes);
    }
    return NULL;
}

static int32_t SetEntityCert(HTILS_PKCS12_p12Info *p12)
{
    if (p12->key == NULL) {
        return HITLS_X509_SUCCESS;
    }

    BSL_Buffer *keyId = FindLocatedId(p12->key->attributes);
    if (keyId == NULL) {
        return HITLS_X509_SUCCESS;
    }

    BSL_ASN1_List *bags = p12->certList;
    HTILS_PKCS12_Bag *node = BSL_LIST_GET_FIRST(bags);
    while (node != NULL) {
        BSL_Buffer *certId = FindLocatedId(node->attributes);
        if (certId != NULL && certId->dataLen == keyId->dataLen) {
            if (memcmp(certId->data, keyId->data, keyId->dataLen) == 0) {
                p12->entityCert->attributes = node->attributes;
                p12->entityCert->value.cert = node->value.cert;
                BSL_LIST_DeleteCurrent(bags, NULL);
                return HITLS_X509_SUCCESS;
            }
        }
        node = BSL_LIST_GET_NEXT(bags);
    }
    BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NO_ENTITYCERT);
    return HITLS_PKCS12_ERR_NO_ENTITYCERT;
}

static int32_t ParseSafeBagList(BSL_Buffer *node, const uint8_t *password, uint32_t passLen, BSL_ASN1_List *bagLists)
{
    BSL_Buffer safeContent = {0};
    int32_t ret = HITLS_PKCS12_ParseContentInfo(node, password, passLen, &safeContent);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_PKCS12_ParseAsn1AddList(&safeContent, bagLists, BSL_CID_SAFECONTENT);
    BSL_SAL_Free(safeContent.data);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

// The caller guarantees that the input is not empty
int32_t HITLS_PKCS12_ParseAuthSafeData(BSL_Buffer *encode, const uint8_t *password, uint32_t passLen,
    HTILS_PKCS12_p12Info *p12)
{
    BSL_ASN1_List *bagLists = NULL;
    BSL_Buffer *node = NULL;
    BSL_ASN1_List *contentList = BSL_LIST_New(sizeof(BSL_Buffer));
    if (contentList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_PKCS12_ParseAsn1AddList(encode, contentList, BSL_CID_CONTENTINFO);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto err;
    }
    node = BSL_LIST_GET_FIRST(contentList);

    bagLists = BSL_LIST_New(sizeof(HTILS_PKCS12_SafeBag));
    if (bagLists == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto err;
    }

    while (node != NULL) {
        ret = ParseSafeBagList(node, password, passLen, bagLists);
        if (ret != HITLS_X509_SUCCESS) {
            goto err;
        }
        node = BSL_LIST_GET_NEXT(contentList);
    }
    ret = HITLS_PKCS12_ParseSafeBagList(bagLists, password, passLen, p12);
    if (ret != HITLS_X509_SUCCESS) {
        goto err;
    }
    ret = SetEntityCert(p12);
err:
    BSL_LIST_DeleteAll(bagLists, BagListsDestroyCb);
    BSL_SAL_Free(bagLists);
    BSL_LIST_DeleteAll(contentList, NULL);
    BSL_SAL_Free(contentList);
    return ret;
}

static int32_t ParseContentInfoAsnItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *param,
    BSL_ASN1_List *list)
{
    (void) param;
    if (layer == 1) {
        return HITLS_X509_SUCCESS;
    }
    BSL_Buffer buffer = {asn->buff, asn->len};
    return HITLS_X509_ParseItemDefault(&buffer, sizeof(BSL_Buffer), list);
}

static int32_t ParseSafeContentAsnItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *param,
    BSL_ASN1_List *list)
{
    (void) param;
    if (layer == 1) {
        return HITLS_X509_SUCCESS;
    }
    BSL_Buffer buffer = {asn->buff, asn->len};
    HTILS_PKCS12_SafeBag safeBag = {0};
    int32_t ret = ParseSafeBag(&buffer, &safeBag);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_ParseItemDefault(&safeBag, sizeof(HTILS_PKCS12_SafeBag), list);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_SAL_FREE(safeBag.bag);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_PKCS12_ParseAsn1AddList(BSL_Buffer *encode, BSL_ASN1_List *list, uint32_t parseType)
{
    if (encode == NULL || encode->data == NULL || list == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }

    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {2, expTag};
    BSL_ASN1_Buffer asn = {
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        encode->dataLen,
        encode->data,
    };
    int32_t ret;
    switch (parseType) {
        case BSL_CID_CONTENTINFO:
            ret = BSL_ASN1_DecodeListItem(&listParam, &asn, &ParseContentInfoAsnItem, NULL, list);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret); // Resources are released by the caller.
                return ret;
            }
            return HITLS_X509_SUCCESS;

        case BSL_CID_SAFECONTENT:
            ret = BSL_ASN1_DecodeListItem(&listParam, &asn, &ParseSafeContentAsnItem, NULL, list);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret); // Resources are released by the caller.
                return ret;
            }
            return HITLS_X509_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
    }
}

/*
 *  MacData ::= SEQUENCE {
 *     mac         DigestInfo,
 *     macSalt     OCTET STRING,
 *     iterations  INTEGER DEFAULT 1
 *     -- Note: The default is for historical reasons and its
 *     --       use is deprecated.
 *  }
*/
BSL_ASN1_TemplateItem g_p12MacDataTempl[] = {
        /* DigestInfo */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
        /* macSalt */
        {BSL_ASN1_TAG_OCTETSTRING, 0, 0},
        /* iterations */
        {BSL_ASN1_TAG_INTEGER, 0, 0},
};

typedef enum {
    HITLS_PKCS12_MACDATA_DIGESTINFO_IDX,
    HITLS_PKCS12_MACDATA_SALT_IDX,
    HITLS_PKCS12_MACDATA_ITER_IDX,
    HITLS_PKCS12_MACDATA_MAX_IDX,
} HITLS_PKCS12_MACDATA_IDX;

int32_t HITLS_PKCS12_ParseMacData(BSL_Buffer *encode, HTILS_PKCS12_MacData *macData)
{
    if (encode == NULL || encode->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }

    uint8_t *temp = encode->data;
    uint32_t  tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_PKCS12_MACDATA_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_p12MacDataTempl, sizeof(g_p12MacDataTempl) / sizeof(g_p12MacDataTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_PKCS12_MACDATA_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Buffer mac = {0};
    BSL_Buffer digestInfo = {asn1[HITLS_PKCS12_MACDATA_DIGESTINFO_IDX].buff,
        asn1[HITLS_PKCS12_MACDATA_DIGESTINFO_IDX].len};
    BslCid cid = BSL_CID_UNKNOWN;
    ret = CRYPT_EAL_ParseAsn1PKCS7DigestInfo(&digestInfo, &cid, &mac);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *salt = BSL_SAL_Malloc(asn1[HITLS_PKCS12_MACDATA_SALT_IDX].len);
    if (salt == NULL) {
        BSL_SAL_Free(mac.data);
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return ret;
    }
    (void)memcpy_s(salt, asn1[HITLS_PKCS12_MACDATA_SALT_IDX].len, asn1[HITLS_PKCS12_MACDATA_SALT_IDX].buff,
        asn1[HITLS_PKCS12_MACDATA_SALT_IDX].len);
    uint32_t iter = 0;
    ret = BSL_ASN1_DecodePrimitiveItem(&asn1[HITLS_PKCS12_MACDATA_ITER_IDX], &iter);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    macData->mac->data = mac.data;
    macData->mac->dataLen = mac.dataLen;
    macData->alg = cid;
    macData->macSalt->data = salt;
    macData->macSalt->dataLen = asn1[HITLS_PKCS12_MACDATA_SALT_IDX].len;
    macData->interation = iter;
    return HITLS_X509_SUCCESS;
}

/*
 * PFX ::= SEQUENCE {
 *  version INTEGER {v3(3)}(v3,...),
 *  authSafe ContentInfo,
 *  macData MacData OPTIONAL
 * }
*/
BSL_ASN1_TemplateItem g_p12TopLevelTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* pkcs12 */
        /* version */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* tbs */
        /* authSafe */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        /* macData */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_OPTIONAL, 1},
};

typedef enum {
    HITLS_PKCS12_TOPLEVEL_VERSION_IDX,
    HITLS_PKCS12_TOPLEVEL_AUTHSAFE_IDX,
    HITLS_PKCS12_TOPLEVEL_MACDATA_IDX,
    HITLS_PKCS12_TOPLEVEL_MAX_IDX,
} HITLS_PKCS12_TOPLEVEL_IDX;

static void ClearMacData(HTILS_PKCS12_MacData *p12Mac)
{
    BSL_SAL_FREE(p12Mac->mac->data);
    BSL_SAL_FREE(p12Mac->macSalt->data);
    p12Mac->macSalt->dataLen = 0;
    p12Mac->mac->dataLen = 0;
    p12Mac->mac->data = NULL;
    p12Mac->macSalt->data = NULL;
    p12Mac->interation = 0;
    p12Mac->alg = BSL_CID_UNKNOWN;
}

static int32_t ParseMacDataAndVerify(BSL_Buffer *initData, BSL_Buffer *macData, const HTILS_PKCS12_PwdParam *pwdParam,
    HTILS_PKCS12_MacData *p12Mac)
{
    int32_t ret = HITLS_PKCS12_ParseMacData(macData, p12Mac);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer verify = {0};
    ret = HTILS_PKCS12_CalMac(&verify, pwdParam->macPwd, initData, p12Mac);
    if (ret != HITLS_X509_SUCCESS) {
        ClearMacData(p12Mac);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (p12Mac->mac->dataLen != verify.dataLen || memcmp(verify.data, p12Mac->mac->data, verify.dataLen != 0)) {
        ClearMacData(p12Mac);
        BSL_SAL_Free(verify.data);
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_VERIFY_FAIL);
        return HITLS_PKCS12_ERR_VERIFY_FAIL;
    }
    BSL_SAL_Free(verify.data);
    return HITLS_X509_SUCCESS;
}

static int32_t ParseAsn1PKCS12(BSL_Buffer *encode, const HTILS_PKCS12_PwdParam *pwdParam,
    HTILS_PKCS12_p12Info *p12, bool needMacVerify)
{
    uint32_t version = 0;
    uint8_t *temp = encode->data;
    uint32_t  tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_PKCS12_TOPLEVEL_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_p12TopLevelTempl, sizeof(g_p12TopLevelTempl) / sizeof(g_p12TopLevelTempl[0])};
    HTILS_PKCS12_MacData *p12Mac = p12->macData;
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_PKCS12_TOPLEVEL_MAX_IDX);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&asn1[HITLS_PKCS12_TOPLEVEL_VERSION_IDX], &version);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (version != 3) { // RFC 7292 requires that version = 3.
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PFX);
        return HITLS_PKCS12_ERR_INVALID_PFX;
    }

    BSL_Buffer macData = {asn1[HITLS_PKCS12_TOPLEVEL_MACDATA_IDX].buff, asn1[HITLS_PKCS12_TOPLEVEL_MACDATA_IDX].len};
    BSL_Buffer contentInfo = {asn1[HITLS_PKCS12_TOPLEVEL_AUTHSAFE_IDX].buff,
        asn1[HITLS_PKCS12_TOPLEVEL_AUTHSAFE_IDX].len};
    BSL_Buffer initData = {0};
    ret = HITLS_PKCS12_ParseContentInfo(&contentInfo, NULL, 0, &initData);
    if (ret != HITLS_X509_SUCCESS) {
        return ret; // has pushed error code.
    }
    if (needMacVerify) {
        ret = ParseMacDataAndVerify(&initData, &macData, pwdParam, p12Mac);
        if (ret != HITLS_X509_SUCCESS) {
            BSL_SAL_Free(initData.data);
            return ret; // has pushed error code.
        }
    }
    ret = HITLS_PKCS12_ParseAuthSafeData(&initData, pwdParam->encPwd->data, pwdParam->encPwd->dataLen, p12);
    BSL_SAL_Free(initData.data);
    if (ret != HITLS_X509_SUCCESS) {
        ClearMacData(p12Mac);
        return ret; // has pushed error code.
    }
    p12->version = version;
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_PKCS12_ParseBuffer(int32_t format, BSL_Buffer *encode, const HTILS_PKCS12_PwdParam *pwdParam,
    HTILS_PKCS12_p12Info *p12, bool needMacVerify)
{
    if (encode == NULL || pwdParam == NULL || pwdParam->encPwd == NULL || pwdParam->encPwd->data == NULL
        || p12 == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return ParseAsn1PKCS12(encode, pwdParam, p12, needMacVerify);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NOT_SUPPORT_FORMAT);
            return HITLS_PKCS12_ERR_NOT_SUPPORT_FORMAT;
    }
}

