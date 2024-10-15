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
#include "bsl_bytes.h"

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

static int32_t DecodeFriendlyName(BSL_ASN1_Buffer *buffer, BSL_Buffer *output)
{
    uint8_t *temp = buffer->buff;
    uint32_t tempLen = buffer->len;
    uint32_t valueLen = buffer->len;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_BMPSTRING, &temp, &tempLen, &valueLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer input = {
        .buff = temp,
        .len = valueLen,
        .tag = BSL_ASN1_TAG_BMPSTRING,
    };
    BSL_ASN1_Buffer decode = {0};
    ret = BSL_ASN1_DecodePrimitiveItem(&input, &decode);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    output->data = decode.buff;
    output->dataLen = decode.len;
    return ret;
}

static int32_t ConverAttributes(BslCid cid, BSL_ASN1_Buffer *buffer, BSL_Buffer *output)
{
    int32_t ret;
    uint8_t *temp = buffer->buff;
    uint32_t tempLen = buffer->len;
    uint32_t valueLen = buffer->len;
    switch (cid) {
        case BSL_CID_FRIENDLYNAME:
            return DecodeFriendlyName(buffer, output);
        case BSL_CID_LOCALKEYID:
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
    ret = HITLS_X509_AddListItemDefault(&attr, sizeof(HTILS_PKCS12_SafeBagAttr), list);
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

static int32_t ParsePKCS8ShroudedKeyBags(HTILS_PKCS12_P12Info *p12, const uint8_t *pwd, uint32_t pwdlen,
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

static int32_t ParseCertBagAndAddList(HTILS_PKCS12_P12Info *p12, HTILS_PKCS12_SafeBag *safeBag)
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
    HTILS_PKCS12_P12Info *p12)
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
    uint32_t passLen, HTILS_PKCS12_P12Info *p12)
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
        if (node->attrId == BSL_CID_LOCALKEYID) {
            return node->attrValue;
        }
        node = BSL_LIST_GET_NEXT(attributes);
    }
    return NULL;
}

static int32_t SetEntityCert(HTILS_PKCS12_P12Info *p12)
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
    HTILS_PKCS12_P12Info *p12)
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
    return HITLS_X509_AddListItemDefault(&buffer, sizeof(BSL_Buffer), list);
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
    ret = HITLS_X509_AddListItemDefault(&safeBag, sizeof(HTILS_PKCS12_SafeBag), list);
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
    HTILS_PKCS12_P12Info *p12, bool needMacVerify)
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

int32_t HITLS_PKCS12_ParseBuff(int32_t format, BSL_Buffer *encode, const HTILS_PKCS12_PwdParam *pwdParam,
    HTILS_PKCS12_P12Info *p12, bool needMacVerify)
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

int32_t HITLS_PKCS12_ParseFile(int32_t format, const char *path, const HTILS_PKCS12_PwdParam *pwdParam,
    HTILS_PKCS12_P12Info *p12, bool needMacVerify)
{
    if (path == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_PKCS12_ParseBuff(format, &encode, pwdParam, p12, needMacVerify);
    BSL_SAL_Free(data);
    return ret;
}

static void FreeListBuff(BSL_ASN1_Buffer *asnBuf, int32_t count)
{
    for (int32_t i = 0; i < count; i++) {
        BSL_SAL_FREE(asnBuf[i].buff);
    }
    BSL_SAL_FREE(asnBuf);
}

static int32_t EncodeAttrValue(HTILS_PKCS12_SafeBagAttr *attribute, BSL_Buffer *encode)
{
    BSL_ASN1_Buffer asnArr = {0};
    int32_t ret;

    asnArr.buff = attribute->attrValue->data;
    asnArr.len = attribute->attrValue->dataLen;
    switch (attribute->attrId) {
        case BSL_CID_FRIENDLYNAME:
            asnArr.tag = BSL_ASN1_TAG_BMPSTRING;
            BSL_ASN1_TemplateItem nameTemplItem = {BSL_ASN1_TAG_BMPSTRING, 0, 0};
            BSL_ASN1_Template nameTempl = {&nameTemplItem, 1};
            ret = BSL_ASN1_EncodeTemplate(&nameTempl, &asnArr, 1, &encode->data, &encode->dataLen);
            break;
        case BSL_CID_LOCALKEYID:
            asnArr.tag = BSL_ASN1_TAG_OCTETSTRING;
            BSL_ASN1_TemplateItem locatedIdTemplItem = {BSL_ASN1_TAG_OCTETSTRING, 0, 0};
            BSL_ASN1_Template locatedIdTempl = {&locatedIdTemplItem, 1};
            ret = BSL_ASN1_EncodeTemplate(&locatedIdTempl, &asnArr, 1, &encode->data, &encode->dataLen);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES;
    }
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_PKCS12_EncodeAttrList(BSL_ASN1_List *list, BSL_ASN1_Buffer *attr)
{
    int32_t count = BSL_LIST_COUNT(list);
    /* no attributes */
    if (count <= 0) {
        attr->buff = NULL;
        attr->len = 0;
        return HITLS_X509_SUCCESS;
    }
    int32_t ret;
    BSL_ASN1_List *attrList = BSL_LIST_New(sizeof(HITLS_X509_AttrEntry));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        goto err;
    }

    HTILS_PKCS12_SafeBagAttr *node = NULL;
    for (node = BSL_LIST_GET_FIRST(list); node != NULL; node = BSL_LIST_GET_NEXT(list)) {
        HITLS_X509_AttrEntry entry = {0};
        BslOidString *oidStr = BSL_OBJ_GetOidFromCID(node->attrId);
        if (oidStr == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES);
            ret = HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES;
            goto err;
        }
        entry.attrId.tag = BSL_ASN1_TAG_OBJECT_ID;
        entry.attrId.buff = (uint8_t *)oidStr->octs;
        entry.attrId.len = oidStr->octetLen;
        BSL_Buffer buffer = {0};
        ret = EncodeAttrValue(node, &buffer);
        if (ret != HITLS_X509_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto err;
        }
        entry.attrValue.tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
        entry.attrValue.buff = buffer.data;
        entry.attrValue.len = buffer.dataLen;
        entry.cid = node->attrId;
        ret = HITLS_X509_AddListItemDefault(&entry, sizeof(HITLS_X509_AttrEntry), attrList);
        if (ret != HITLS_X509_SUCCESS) {
            BSL_SAL_FREE(buffer.data);
            BSL_ERR_PUSH_ERROR(ret);
            goto err;
        }
    }
    ret = HITLS_X509_EncodeAttrList(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, attrList, attr);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
err:
    BSL_LIST_FREE(attrList, (BSL_LIST_PFUNC_FREE)HITLS_X509_AttrEntryFree);
    return ret;
}

static int32_t EncodeCertBag(HITLS_X509_Cert *cert, uint32_t certType, uint8_t **encode, uint32_t *encodeLen)
{
    int32_t ret;
    BslOidString *oidStr = BSL_OBJ_GetOidFromCID(certType);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_ALGO);
        return HITLS_PKCS12_ERR_INVALID_ALGO;
    }
    BSL_Buffer certBuff = {0};
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &certBuff);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer asnArr[HITLS_PKCS12_COMMON_SAFEBAG_MAX_IDX] = {
        {
            .buff = (uint8_t *)oidStr->octs,
            .len = oidStr->octetLen,
            .tag = BSL_ASN1_TAG_OBJECT_ID,
        }, {
            .buff = certBuff.data,
            .len = certBuff.dataLen,
            .tag = BSL_ASN1_TAG_OCTETSTRING,
        }};

    BSL_ASN1_Template templ = {g_pk12CommonBagTempl, sizeof(g_pk12CommonBagTempl) / sizeof(g_pk12CommonBagTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_PKCS12_COMMON_SAFEBAG_MAX_IDX, encode, encodeLen);
    BSL_SAL_Free(certBuff.data);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeSafeBag(HTILS_PKCS12_Bag *bag, uint32_t encodeType, const CRYPT_EncodeParam *encryptParam,
    uint8_t **output, uint32_t *outputLen)
{
    int32_t ret;
    BslOidString *oidStr = BSL_OBJ_GetOidFromCID(encodeType);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_ALGO);
        return HITLS_PKCS12_ERR_INVALID_ALGO;
    }
    BSL_Buffer encode = {0};
    switch (encodeType) {
        case BSL_CID_PKCS8SHROUDEDKEYBAG:
            ret = CRYPT_EAL_EncodeBuffKey(bag->value.key, encryptParam, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_ENCRYPT,
                &encode);
            break;
        case BSL_CID_CERTBAG:
            ret = EncodeCertBag(bag->value.cert, BSL_CID_X509CERTIFICATE, &encode.data, &encode.dataLen);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
    }
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer asnArr[HITLS_PKCS12_SAFEBAG_MAX_IDX] = {
        {
            .buff = (uint8_t *)oidStr->octs,
            .len = oidStr->octetLen,
            .tag = BSL_ASN1_TAG_OBJECT_ID,
        }, {
            .buff = encode.data,
            .len = encode.dataLen,
            .tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_P12_CTX_SPECIFIC_TAG_EXTENSION,
        }};

    ret = HITLS_PKCS12_EncodeAttrList(bag->attributes, &asnArr[HITLS_PKCS12_SAFEBAG_BAGATTRIBUTES_IDX]);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(encode.data);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asnArr[HITLS_PKCS12_SAFEBAG_BAGATTRIBUTES_IDX].tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;

    BSL_ASN1_Template templ = {g_pk12SafeBagTempl, sizeof(g_pk12SafeBagTempl) / sizeof(g_pk12SafeBagTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_PKCS12_SAFEBAG_MAX_IDX, output, outputLen);
    BSL_SAL_Free(encode.data);
    BSL_SAL_Free(asnArr[HITLS_PKCS12_SAFEBAG_BAGATTRIBUTES_IDX].buff);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeP7Data(BSL_Buffer *input, BSL_Buffer *encode)
{
    BSL_ASN1_Buffer asnArr = {0};
    asnArr.buff = input->data;
    asnArr.tag = BSL_ASN1_TAG_OCTETSTRING;
    asnArr.len = input->dataLen;
    BSL_ASN1_TemplateItem dataTemplItem = {BSL_ASN1_TAG_OCTETSTRING, 0, 0};
    BSL_ASN1_Template dataTempl = {&dataTemplItem, 1};
    int32_t ret = BSL_ASN1_EncodeTemplate(&dataTempl, &asnArr, 1, &encode->data, &encode->dataLen);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_PKCS12_EncodeContentInfo(BSL_Buffer *input, uint32_t encodeType, const CRYPT_EncodeParam *encryptParam,
    BSL_Buffer *encode)
{
    int32_t ret;
    BslOidString *oidStr = BSL_OBJ_GetOidFromCID(encodeType);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_ALGO);
        return HITLS_PKCS12_ERR_INVALID_ALGO;
    }
    BSL_Buffer initData = {0};
    switch (encodeType) {
        case BSL_CID_DATA:
            ret = EncodeP7Data(input, &initData);
            break;
        case BSL_CID_ENCRYPTEDDATA:
            ret = CRYPT_EAL_EncodePKCS7EncryptDataBuff(input, encryptParam, &initData);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_CONTENTINFO);
            return HITLS_PKCS12_ERR_INVALID_CONTENTINFO;
    }
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer asnArr[HITLS_PKCS12_CONTENT_MAX_IDX] = {
        {
            .buff = (uint8_t *)oidStr->octs,
            .len = oidStr->octetLen,
            .tag = BSL_ASN1_TAG_OBJECT_ID,
        }, {
            .buff = initData.data,
            .len = initData.dataLen,
            .tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_P12_CTX_SPECIFIC_TAG_EXTENSION,
        }};

    BSL_ASN1_Template templ = {g_pk12ContentInfoTempl,
        sizeof(g_pk12ContentInfoTempl) / sizeof(g_pk12ContentInfoTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_PKCS12_CONTENT_MAX_IDX, &encode->data, &encode->dataLen);
    BSL_SAL_Free(initData.data);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeSafeContent(BSL_ASN1_Buffer **output, BSL_ASN1_List *list, uint32_t encodeType,
    const CRYPT_EncodeParam *encryptParam)
{
    BSL_ASN1_Buffer *asnBuf = BSL_SAL_Calloc(list->count, sizeof(BSL_ASN1_Buffer));
    if (asnBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t iter = 0;
    int32_t ret = HITLS_X509_SUCCESS;
    HTILS_PKCS12_Bag *node = NULL;
    for (node = BSL_LIST_GET_FIRST(list); node != NULL; node = BSL_LIST_GET_NEXT(list), iter++) {
        ret = EncodeSafeBag(node, encodeType, encryptParam, &asnBuf[iter].buff, &asnBuf[iter].len);
        if (ret != BSL_SUCCESS) {
            FreeListBuff(asnBuf, iter);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        asnBuf[iter].tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    }
    *output = asnBuf;
    return ret;
}

static int32_t EncodeContentInfoList(BSL_ASN1_Buffer **output, BSL_ASN1_List *list)
{
    BSL_ASN1_Buffer *asnBuf = BSL_SAL_Calloc(list->count, sizeof(BSL_ASN1_Buffer));
    if (asnBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t iter = 0;
    int32_t ret = HITLS_X509_SUCCESS;
    BSL_Buffer *node = NULL;
    for (node = BSL_LIST_GET_FIRST(list); node != NULL; node = BSL_LIST_GET_NEXT(list), iter++) {
        asnBuf[iter].buff = BSL_SAL_Dump(node->data, node->dataLen);
        if (asnBuf[iter].buff == NULL) {
            FreeListBuff(asnBuf, iter);
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        asnBuf[iter].len = node->dataLen;
        asnBuf[iter].tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    }
    *output = asnBuf;
    return ret;
}

int32_t HITLS_PKCS12_EncodeAsn1List(BSL_ASN1_List *list, uint32_t encodeType, const CRYPT_EncodeParam *encryptParam,
    BSL_Buffer *encode)
{
    int32_t count = BSL_LIST_COUNT(list);
    BSL_ASN1_Buffer *asnBuf = NULL;
    int32_t ret;
    switch (encodeType) {
        case BSL_CID_CONTENTINFO:
            ret = EncodeContentInfoList(&asnBuf, list);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            break;
        case BSL_CID_PKCS8SHROUDEDKEYBAG:
        case BSL_CID_CERTBAG:
            ret = EncodeSafeContent(&asnBuf, list, encodeType, encryptParam);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_CONTENTINFO);
            return HITLS_PKCS12_ERR_INVALID_CONTENTINFO;
    }
    static BSL_ASN1_TemplateItem listTempl = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0 };
    BSL_ASN1_Template templ = {&listTempl, 1};
    BSL_ASN1_Buffer out = {0};
    ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, count, &templ, asnBuf, count, &out);
    if (ret != HITLS_X509_SUCCESS) {
        FreeListBuff(asnBuf, count);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_EncodeTemplate(&templ, &out, 1, &encode->data, &encode->dataLen);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    FreeListBuff(asnBuf, count);
    BSL_SAL_FREE(out.buff);
    return ret;
}

int32_t HITLS_PKCS12_EncodeMacData(BSL_Buffer *initData, const HTILS_PKCS12_HmacParam *macParam,
    HTILS_PKCS12_MacData *p12Mac, BSL_Buffer *encode)
{
    BSL_Buffer mac = {0};
    BSL_Buffer digestInfo = {0};
    p12Mac->alg = macParam->macId;
    p12Mac->interation = macParam->itCnt;
    p12Mac->macSalt->dataLen = macParam->saltLen;
    BSL_Buffer macPwd = {macParam->pwd, macParam->pwdLen};
    int32_t ret = HTILS_PKCS12_CalMac(&mac, &macPwd, initData, p12Mac);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_EAL_EncodePKCS7DigestInfoBuff(p12Mac->alg, &mac, &digestInfo);
    BSL_SAL_FREE(mac.data);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer asnArr[HITLS_PKCS12_MACDATA_MAX_IDX] = {
        {
            .buff = digestInfo.data,
            .len = digestInfo.dataLen,
            .tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        }, {
            .buff = p12Mac->macSalt->data,
            .len = p12Mac->macSalt->dataLen,
            .tag = BSL_ASN1_TAG_OCTETSTRING,
        }};

    ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, p12Mac->interation, &asnArr[HITLS_PKCS12_MACDATA_ITER_IDX]);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_SAL_Free(digestInfo.data);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Template templ = {g_p12MacDataTempl, sizeof(g_p12MacDataTempl) / sizeof(g_p12MacDataTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_PKCS12_MACDATA_MAX_IDX, &encode->data, &encode->dataLen);
    BSL_SAL_Free(digestInfo.data);
    BSL_SAL_Free(asnArr[HITLS_PKCS12_MACDATA_ITER_IDX].buff);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeCertListAddList(HTILS_PKCS12_P12Info *p12, const CRYPT_EncodeParam *encParam, BSL_ASN1_List *list,
    bool isNeedMac)
{
    int32_t ret;
    HTILS_PKCS12_Bag *bag = NULL;
    BSL_Buffer certEncode = {0};
    if (p12->entityCert->value.cert != NULL) {
        bag = BSL_SAL_Malloc(sizeof(HTILS_PKCS12_Bag));
        if (bag == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        bag->attributes = p12->entityCert->attributes;
        bag->value.cert = p12->entityCert->value.cert;
        ret = BSL_LIST_AddElement(p12->certList, bag, BSL_LIST_POS_BEGIN);
        if (ret != HITLS_X509_SUCCESS) {
            BSL_SAL_FREE(bag);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (BSL_LIST_COUNT(p12->certList) <= 0) {
        return HITLS_X509_SUCCESS;
    }
    ret = HITLS_PKCS12_EncodeAsn1List(p12->certList, BSL_CID_CERTBAG, NULL, &certEncode);
    if (p12->entityCert->value.cert != NULL) {
        BSL_LIST_First(p12->certList);
        BSL_LIST_DeleteCurrent(p12->certList, NULL);
    }
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Buffer contentInfoEncode = {0};
    if (isNeedMac) {
        ret = HITLS_PKCS12_EncodeContentInfo(&certEncode, BSL_CID_ENCRYPTEDDATA, encParam, &contentInfoEncode);
    } else {
        ret = HITLS_PKCS12_EncodeContentInfo(&certEncode, BSL_CID_DATA, encParam, &contentInfoEncode);
    }
    BSL_SAL_FREE(certEncode.data);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_AddListItemDefault(&contentInfoEncode, sizeof(BSL_Buffer), list);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_SAL_FREE(contentInfoEncode.data);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeKeyAddList(HTILS_PKCS12_P12Info *p12, const CRYPT_EncodeParam *encParam, BSL_ASN1_List *list)
{
    if (p12->key->value.key == NULL) {
        return HITLS_X509_SUCCESS;
    }

    BSL_ASN1_List *keyList = BSL_LIST_New(sizeof(HTILS_PKCS12_Bag));
    if (keyList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    HTILS_PKCS12_Bag bag = {0};
    BSL_Buffer keyEncode = {0};
    BSL_Buffer contentInfoEncode = {0};
    bag.attributes = p12->key->attributes;
    bag.value.key = p12->key->value.key;
    int32_t ret = HITLS_X509_AddListItemDefault(&bag, sizeof(HTILS_PKCS12_Bag), keyList);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_SAL_FREE(keyList);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_PKCS12_EncodeAsn1List(keyList, BSL_CID_PKCS8SHROUDEDKEYBAG, encParam, &keyEncode);
    BSL_LIST_FREE(keyList, NULL);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HITLS_PKCS12_EncodeContentInfo(&keyEncode, BSL_CID_DATA, NULL, &contentInfoEncode);
    BSL_SAL_FREE(keyEncode.data);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_AddListItemDefault(&contentInfoEncode, sizeof(BSL_Buffer), list);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_SAL_FREE(contentInfoEncode.data);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static void FreeBuffer(void *buffer)
{
    if (buffer == NULL) {
        return;
    }

    BSL_Buffer *tmp = (BSL_Buffer *)buffer;
    BSL_SAL_FREE(tmp->data);
    BSL_SAL_Free(tmp);
}

static int32_t EncodePkcs12(uint32_t version, BSL_Buffer *authSafe, BSL_Buffer *macData, BSL_Buffer *encode)
{
    BSL_ASN1_Buffer asnArr[HITLS_PKCS12_TOPLEVEL_MAX_IDX] = {
        {
            .buff = NULL,
            .len = 0,
            .tag = BSL_ASN1_TAG_INTEGER,
        }, {
            .buff = authSafe->data,
            .len = authSafe->dataLen,
            .tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        }, {
            .buff = macData->data,
            .len = macData->dataLen,
            .tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        }};

    int32_t ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, version, asnArr);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_ASN1_Template templ = {g_p12TopLevelTempl, sizeof(g_p12TopLevelTempl) / sizeof(g_p12TopLevelTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_PKCS12_TOPLEVEL_MAX_IDX,
        &encode->data, &encode->dataLen);
    BSL_SAL_Free(asnArr[HITLS_PKCS12_TOPLEVEL_VERSION_IDX].buff);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeP12Info(HTILS_PKCS12_P12Info *p12, const HTILS_PKCS12_EncodeParam *encodeParam, bool isNeedMac,
    BSL_Buffer *encode)
{
    int32_t ret;
    BSL_ASN1_List *list = BSL_LIST_New(sizeof(BSL_Buffer));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ret = EncodeCertListAddList(p12, &encodeParam->certEncParam, list, isNeedMac);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_LIST_FREE(list, FreeBuffer);
        return ret;
    }

    ret = EncodeKeyAddList(p12, &encodeParam->keyEncParam, list);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_LIST_FREE(list, FreeBuffer);
        return ret;
    }
    if (BSL_LIST_COUNT(list) <= 0) {
        BSL_LIST_FREE(list, FreeBuffer);
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NONE_DATA);
        return HITLS_PKCS12_ERR_NONE_DATA;
    }
    BSL_Buffer initData = {0};
    ret = HITLS_PKCS12_EncodeAsn1List(list, BSL_CID_CONTENTINFO, NULL, &initData);
    BSL_LIST_FREE(list, FreeBuffer);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }

    BSL_Buffer macData = {0};
    if (isNeedMac) {
        ret = HITLS_PKCS12_EncodeMacData(&initData, &encodeParam->macParam, p12->macData, &macData);
        if (ret != HITLS_X509_SUCCESS) {
            BSL_SAL_FREE(initData.data);
            return ret;
        }
    }
    
    BSL_Buffer authSafe = {0};
    ret = HITLS_PKCS12_EncodeContentInfo(&initData, BSL_CID_DATA, NULL, &authSafe);
    BSL_SAL_FREE(initData.data);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_SAL_FREE(macData.data);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = EncodePkcs12(p12->version, &authSafe, &macData, encode);
    BSL_SAL_FREE(authSafe.data);
    BSL_SAL_FREE(macData.data);
    return ret;
}

int32_t HITLS_PKCS12_GenBuff(int32_t format, HTILS_PKCS12_P12Info *p12, const HTILS_PKCS12_EncodeParam *encodeParam,
    bool isNeedMac, BSL_Buffer *encode)
{
    if (p12 == NULL || encodeParam == NULL || encode == NULL || encode->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    switch (format) {
        case BSL_FORMAT_ASN1:
            return EncodeP12Info(p12, encodeParam, isNeedMac, encode);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NOT_SUPPORT_FORMAT);
            return HITLS_PKCS12_ERR_NOT_SUPPORT_FORMAT;
    }
}

int32_t HITLS_PKCS12_GenFile(int32_t format, HTILS_PKCS12_P12Info *p12, const HTILS_PKCS12_EncodeParam *encodeParam,
    bool isNeedMac, const char *path)
{
    if (path == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }

    BSL_Buffer encode = {0};
    int32_t ret = HITLS_PKCS12_GenBuff(format, p12, encodeParam, isNeedMac, &encode);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_SAL_WriteFile(path, encode.data, encode.dataLen);
    BSL_SAL_Free(encode.data);
    return ret;
}
