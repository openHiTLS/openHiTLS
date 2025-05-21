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
#ifdef HITLS_PKI_PKCS12
#include "bsl_sal.h"
#ifdef HITLS_BSL_SAL_FILE
#include "sal_file.h"
#endif
#include "securec.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_local.h"
#include "hitls_cms_local.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "crypt_encode_decode_key.h"
#include "crypt_eal_codecs.h"
#include "bsl_bytes.h"
#include "crypt_eal_md.h"
#include "hitls_pki_pkcs12.h"
#include "hitls_pkcs12_local.h"

#define HITLS_P12_CTX_SPECIFIC_TAG_EXTENSION 0

/* common Bag, including crl, cert, secret ... */
static BSL_ASN1_TemplateItem g_pk12CommonBagTempl[] = {
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

/*
 SafeBag ::= SEQUENCE {
     bagId          BAG-TYPE.&id ({PKCS12BagSet})
     bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
     bagAttributes  SET OF PKCS12Attribute OPTIONAL
 }
*/
static BSL_ASN1_TemplateItem g_pk12SafeBagTempl[] = {
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
 * Defined in RFC 2531
 * ContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
*/
static BSL_ASN1_TemplateItem g_pk12ContentInfoTempl[] = {
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

/*
 *  MacData ::= SEQUENCE {
 *     mac         DigestInfo,
 *     macSalt     OCTET STRING,
 *     iterations  INTEGER DEFAULT 1
 *     -- Note: The default is for historical reasons and its
 *     --       use is deprecated.
 *  }
*/
static BSL_ASN1_TemplateItem g_p12MacDataTempl[] = {
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

/*
 * PFX ::= SEQUENCE {
 *  version INTEGER {v3(3)}(v3,...),
 *  authSafe ContentInfo,
 *  macData MacData OPTIONAL
 * }
*/
static BSL_ASN1_TemplateItem g_p12TopLevelTempl[] = {
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

#ifdef HITLS_PKI_PKCS12_PARSE
/* parse bags, and revoker already knows they are one of CommonBags */
static int32_t ParseCommonSafeBag(BSL_Buffer *buffer, HITLS_PKCS12_CommonSafeBag *bag)
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
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_PARSE_TYPE);
        return HITLS_PKCS12_ERR_PARSE_TYPE;
    }
    bag->bagId = cid;
    bag->bagValue = BSL_SAL_Malloc(sizeof(BSL_Buffer));
    if (bag->bagValue == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    bag->bagValue->data = asnArr[HITLS_PKCS12_COMMON_SAFEBAG_BAGVALUES_IDX].buff;
    bag->bagValue->dataLen = asnArr[HITLS_PKCS12_COMMON_SAFEBAG_BAGVALUES_IDX].len;
    return HITLS_PKI_SUCCESS;
}

/* Convert commonBags to the cert */
static int32_t ConvertCertBag(HITLS_PKCS12_CommonSafeBag *bag, HITLS_X509_Cert **cert)
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

static int32_t ConvertAttributes(BslCid cid, BSL_ASN1_Buffer *buffer, BSL_Buffer *output)
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
                BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
                return BSL_DUMP_FAIL;
            }
            output->dataLen = valueLen;
            return HITLS_PKI_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES;
    }
}

static int32_t X509_ParseP12AttrItem(BslList *attrList, HITLS_X509_AttrEntry *attrEntry)
{
    HITLS_PKCS12_SafeBagAttr attr = {0};
    attr.attrId = attrEntry->cid;
    int32_t ret = ConvertAttributes(attrEntry->cid, &attrEntry->attrValue, &attr.attrValue);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_AddListItemDefault(&attr, sizeof(HITLS_PKCS12_SafeBagAttr), attrList);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(attr.attrValue.data);
    }
    return ret;
}

int32_t HITLS_PKCS12_ParseSafeBagAttr(BSL_ASN1_Buffer *attrBuff, HITLS_X509_Attrs *attrList)
{
    return HITLS_X509_ParseAttrList(attrBuff, attrList, X509_ParseP12AttrItem, HITLS_PKCS12_AttributesFree);
}

/*
 * Parse the 'safeBag' of p12. This interface only parses the outermost layer and attributes of safeBag,
 * others are handed over to the next layer for parsing
*/
static int32_t ParseSafeBag(BSL_Buffer *buffer, HITLS_PKCS12_SafeBag *safeBag)
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
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE);
        return HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
    }
    HITLS_X509_Attrs *attributes = NULL;
    BSL_Buffer *bag = BSL_SAL_Calloc(1u, sizeof(BSL_Buffer));
    if (bag == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    bag->data = BSL_SAL_Dump(asnArr[HITLS_PKCS12_SAFEBAG_BAGVALUES_IDX].buff,
        asnArr[HITLS_PKCS12_SAFEBAG_BAGVALUES_IDX].len);
    if (bag->data == NULL) {
        ret = BSL_DUMP_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    bag->dataLen = asnArr[HITLS_PKCS12_SAFEBAG_BAGVALUES_IDX].len;
    attributes = HITLS_X509_AttrsNew();
    if (attributes == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = HITLS_PKCS12_ParseSafeBagAttr(asnArr + HITLS_PKCS12_SAFEBAG_BAGATTRIBUTES_IDX, attributes);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    safeBag->attributes = attributes;
    safeBag->bagId = cid;
    safeBag->bag = bag;
    return ret;
ERR:
    BSL_SAL_FREE(bag->data);
    BSL_SAL_FREE(bag);
    HITLS_X509_AttrsFree(attributes, HITLS_PKCS12_AttributesFree);
    return ret;
}

static int32_t ParsePKCS8ShroudedKeyBags(HITLS_PKCS12 *p12, const uint8_t *pwd, uint32_t pwdlen,
    HITLS_PKCS12_SafeBag *safeBag)
{
    CRYPT_EAL_PkeyCtx *prikey = NULL;
    const BSL_Buffer pwdBuff = {(uint8_t *)(uintptr_t)pwd, pwdlen};
    int32_t ret = CRYPT_EAL_ProviderDecodeBuffKey(p12->libCtx, p12->attrName, BSL_CID_UNKNOWN, "ASN1",
        "PRIKEY_PKCS8_ENCRYPT", safeBag->bag, &pwdBuff, &prikey);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_PKCS12_Bag *keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, prikey);
    CRYPT_EAL_PkeyFreeCtx(prikey);
    if (keyBag == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    keyBag->attributes = safeBag->attributes;
    safeBag->attributes = NULL;
    p12->key = keyBag;
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseCertBagAndAddList(HITLS_PKCS12 *p12, HITLS_PKCS12_SafeBag *safeBag)
{
    HITLS_PKCS12_CommonSafeBag bag = {0};
    int32_t ret = ParseCommonSafeBag(safeBag->bag, &bag);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_X509_Cert *cert = NULL;
    ret = ConvertCertBag(&bag, &cert);
    BSL_SAL_FREE(bag.bagValue);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_PKCS12_Bag *bagData = BSL_SAL_Malloc(sizeof(HITLS_PKCS12_Bag));
    if (bagData == NULL) {
        HITLS_X509_CertFree(cert);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    bagData->attributes = safeBag->attributes;
    bagData->value.cert = cert;
    bagData->type = BSL_CID_CERTBAG;
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

/* Parse a SafeBag to the data we need, such as a private key, etc */
int32_t HITLS_PKCS12_ConvertSafeBag(HITLS_PKCS12_SafeBag *safeBag, const uint8_t *pwd, uint32_t pwdlen,
    HITLS_PKCS12 *p12)
{
    if (safeBag == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    switch (safeBag->bagId) {
        case BSL_CID_PKCS8SHROUDEDKEYBAG:
            if (p12->key != NULL) {
                return HITLS_PKI_SUCCESS;
            }
            return ParsePKCS8ShroudedKeyBags(p12, pwd, pwdlen, safeBag);
        case BSL_CID_CERTBAG:
            return ParseCertBagAndAddList(p12, safeBag);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
    }
}

int32_t HITLS_PKCS12_ParseContentInfo(HITLS_PKI_LibCtx *libCtx, const char *attrName,
    CRYPT_EAL_PkeyCtx *recipientPkeyCtx, BSL_Buffer *encode, const uint8_t *password, uint32_t passLen,
    BSL_Buffer *data)
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
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE);
        return HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
    }
    BSL_Buffer asnArrData = {asnArr[HITLS_PKCS12_CONTENT_VALUE_IDX].buff, asnArr[HITLS_PKCS12_CONTENT_VALUE_IDX].len};
    switch (cid) {
        case BSL_CID_PKCS7_SIMPLEDATA:
            return HITLS_CMS_ParseAsn1Data(&asnArrData, data);
        case BSL_CID_PKCS7_ENCRYPTEDDATA:
            return CRYPT_EAL_ParseAsn1PKCS7EncryptedData(libCtx, attrName, &asnArrData, password, passLen, data);
        case BSL_CID_PKCS7_ENVELOPEDDATA:
            if (recipientPkeyCtx == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NO_RECIPIENT_KEY);
                return HITLS_PKCS12_ERR_NO_RECIPIENT_KEY;
            }
            return HITLS_CMS_ParseEnvelopedData(libCtx, attrName, recipientPkeyCtx, &asnArrData, data);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
    }
}

/* Parse each safeBag from list, and extract the data we need, such as a private key, etc */
int32_t HITLS_PKCS12_ParseSafeBagList(BSL_ASN1_List *bagList, const uint8_t *password,
    uint32_t passLen, HITLS_PKCS12 *p12)
{
    if (BSL_LIST_COUNT(bagList) == 0) {
        return HITLS_PKI_SUCCESS;
    }
    int32_t ret;
    HITLS_PKCS12_SafeBag *node = BSL_LIST_GET_FIRST(bagList);
    const uint8_t *currentPassword = NULL; // Will be set if pwdParam is available
    uint32_t currentPassLen = 0;

    // This function is called from HITLS_PKCS12_ParseAuthSafeData,
    // which now receives HITLS_PKCS12_PwdParam.
    // We need to pass down the encPwd for SafeBag decryption.
    // However, the signature of ParseSafeBagList only takes (password, passLen)
    // This implies that HITLS_PKCS12_ParseAuthSafeData needs to extract encPwd from pwdParam.
    // For now, let's assume `password` and `passLen` are correctly supplied from the caller.
    // The `recipientPkeyCtx` is already in `p12->recipientPkeyCtx`.

    while (node != NULL) {
        // HITLS_PKCS12_ConvertSafeBag is called here. This function handles BSL_CID_PKCS8SHROUDEDKEYBAG
        // which uses password-based encryption.
        // If a SafeBag itself is EnvelopedData, that would be handled by HITLS_PKCS12_ParseContentInfo
        // if the SafeBag's content type was EnvelopedData.
        // The current structure is: PFX -> AuthSafe (ContentInfo: Data) -> SafeContents (SEQUENCE OF ContentInfo)
        // Each ContentInfo in SafeContents can be EncryptedData or EnvelopedData.
        // So, HITLS_PKCS12_ConvertSafeBag doesn't directly decrypt EnvelopedData SafeBags,
        // it decrypts ShroudedKeyBags. The EnvelopedData part is for the ContentInfo that wraps SafeContents.
        ret = HITLS_PKCS12_ConvertSafeBag(node, password, passLen, p12);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        node = BSL_LIST_GET_NEXT(bagList);
    }
    return HITLS_PKI_SUCCESS;
}

static BSL_Buffer *FindLocatedId(HITLS_X509_Attrs *attributes)
{
    if (attributes == NULL) {
        return NULL;
    }
    HITLS_PKCS12_SafeBagAttr *node = BSL_LIST_GET_FIRST(attributes->list);
    while (node != NULL) {
        if (node->attrId == BSL_CID_LOCALKEYID) {
            return &node->attrValue;
        }
        node = BSL_LIST_GET_NEXT(attributes->list);
    }
    return NULL;
}

static int32_t SetEntityCert(HITLS_PKCS12 *p12)
{
    if (p12->key == NULL) {
        return HITLS_PKI_SUCCESS;
    }

    BSL_Buffer *keyId = FindLocatedId(p12->key->attributes);
    if (keyId == NULL) {
        return HITLS_PKI_SUCCESS;
    }

    BSL_ASN1_List *bags = p12->certList;
    HITLS_PKCS12_Bag *node = BSL_LIST_GET_FIRST(bags);
    while (node != NULL) {
        BSL_Buffer *certId = FindLocatedId(node->attributes);
        if (certId != NULL && certId->dataLen == keyId->dataLen &&
            memcmp(certId->data, keyId->data, keyId->dataLen) == 0) {
            HITLS_PKCS12_Bag *certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, node->value.cert);
            if (certBag == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                return BSL_MALLOC_FAIL;
            }
            HITLS_X509_CertFree(node->value.cert); // This node will be released immediately.
            certBag->attributes = node->attributes;
            certBag->type = BSL_CID_CERTBAG;
            p12->entityCert = certBag;
            BSL_LIST_DeleteCurrent(bags, NULL);
            return HITLS_PKI_SUCCESS;
        }
        node = BSL_LIST_GET_NEXT(bags);
    }
    BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NO_ENTITYCERT);
    return HITLS_PKCS12_ERR_NO_ENTITYCERT;
}

static int32_t ParseSafeBagListInner(HITLS_PKI_LibCtx *libCtx, const char *attrName,
    CRYPT_EAL_PkeyCtx *recipientPkeyCtx, BSL_Buffer *node, const uint8_t *password, uint32_t passLen,
    BSL_ASN1_List *bagLists)
{
    BSL_Buffer safeContent = {0};
    // This is where HITLS_PKCS12_ParseContentInfo is called for items within SafeContents.
    // It needs recipientPkeyCtx.
    int32_t ret = HITLS_PKCS12_ParseContentInfo(libCtx, attrName, recipientPkeyCtx, node, password, passLen, &safeContent);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_PKCS12_ParseAsn1AddList(&safeContent, bagLists, BSL_CID_SAFECONTENTSBAG);
    BSL_SAL_Free(safeContent.data);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

// The caller guarantees that the input is not empty.
// Updated signature to take HITLS_PKCS12_PwdParam
int32_t HITLS_PKCS12_ParseAuthSafeData(BSL_Buffer *encode, const HITLS_PKCS12_PwdParam *pwdParam, HITLS_PKCS12 *p12)
{
    BSL_ASN1_List *bagLists = NULL;
    BSL_Buffer *node = NULL;
    BSL_ASN1_List *contentList = BSL_LIST_New(sizeof(BSL_Buffer));
    if (contentList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_PKCS12_ParseAsn1AddList(encode, contentList, BSL_CID_PKCS7_CONTENTINFO);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    bagLists = BSL_LIST_New(sizeof(HITLS_PKCS12_SafeBag));
    if (bagLists == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    node = BSL_LIST_GET_FIRST(contentList);
    const uint8_t *encPwdData = (pwdParam && pwdParam->encPwd) ? pwdParam->encPwd->data : NULL;
    uint32_t encPwdLen = (pwdParam && pwdParam->encPwd) ? pwdParam->encPwd->dataLen : 0;

    while (node != NULL) {
        // Pass recipientPkeyCtx and encPwd/encPwdLen to ParseSafeBagListInner
        ret = ParseSafeBagListInner(p12->libCtx, p12->attrName, p12->recipientPkeyCtx, node, encPwdData, encPwdLen, bagLists);
        if (ret != HITLS_PKI_SUCCESS) {
            goto ERR;
        }
        node = BSL_LIST_GET_NEXT(contentList);
    }
    // This call to HITLS_PKCS12_ParseSafeBagList processes the collected SafeBag structures.
    // It needs the encPwd for shrouded key bags.
    ret = HITLS_PKCS12_ParseSafeBagList(bagLists, encPwdData, encPwdLen, p12);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = SetEntityCert(p12);
ERR:
    BSL_LIST_FREE(bagLists, (BSL_LIST_PFUNC_FREE)HITLS_PKCS12_SafeBagFree);
    BSL_LIST_FREE(contentList, NULL);
    return ret;
}

static int32_t ParseContentInfoAsnItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *param,
    BSL_ASN1_List *list)
{
    (void) param;
    if (layer == 1) {
        return HITLS_PKI_SUCCESS;
    }
    BSL_Buffer buffer = {asn->buff, asn->len};
    return HITLS_X509_AddListItemDefault(&buffer, sizeof(BSL_Buffer), list);
}

static int32_t ParseSafeContentAsnItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *param,
    BSL_ASN1_List *list)
{
    (void) param;
    if (layer == 1) {
        return HITLS_PKI_SUCCESS;
    }
    BSL_Buffer buffer = {asn->buff, asn->len};
    HITLS_PKCS12_SafeBag safeBag = {0};
    int32_t ret = ParseSafeBag(&buffer, &safeBag);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_AddListItemDefault(&safeBag, sizeof(HITLS_PKCS12_SafeBag), list);
    if (ret != HITLS_PKI_SUCCESS) {
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
        case BSL_CID_PKCS7_CONTENTINFO:
            ret = BSL_ASN1_DecodeListItem(&listParam, &asn, &ParseContentInfoAsnItem, NULL, list);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret); // Resources are released by the caller.
            }
            return ret;

        case BSL_CID_SAFECONTENTSBAG:
            ret = BSL_ASN1_DecodeListItem(&listParam, &asn, &ParseSafeContentAsnItem, NULL, list);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret); // Resources are released by the caller.
            }
            return ret;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
    }
}

int32_t HITLS_PKCS12_ParseMacData(BSL_Buffer *encode, HITLS_PKCS12_MacData *macData)
{
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0) {
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
    ret = HITLS_CMS_ParseDigestInfo(&digestInfo, &cid, &mac);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *salt = BSL_SAL_Dump(asn1[HITLS_PKCS12_MACDATA_SALT_IDX].buff, asn1[HITLS_PKCS12_MACDATA_SALT_IDX].len);
    if (salt == NULL) {
        BSL_SAL_Free(mac.data);
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    uint32_t iter = 0;
    ret = BSL_ASN1_DecodePrimitiveItem(&asn1[HITLS_PKCS12_MACDATA_ITER_IDX], &iter);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(mac.data);
        BSL_SAL_Free(salt);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    macData->mac->data = mac.data;
    macData->mac->dataLen = mac.dataLen;
    macData->alg = cid;
    macData->macSalt->data = salt;
    macData->macSalt->dataLen = asn1[HITLS_PKCS12_MACDATA_SALT_IDX].len;
    macData->iteration = iter;
    return HITLS_PKI_SUCCESS;
}

static void ClearMacData(HITLS_PKCS12_MacData *p12Mac)
{
    BSL_SAL_FREE(p12Mac->mac->data);
    BSL_SAL_FREE(p12Mac->macSalt->data);
    p12Mac->macSalt->dataLen = 0;
    p12Mac->mac->dataLen = 0;
    p12Mac->iteration = 0;
    p12Mac->alg = BSL_CID_UNKNOWN;
}

static int32_t ParseMacDataAndVerify(BSL_Buffer *initData, BSL_Buffer *macData, const HITLS_PKCS12_PwdParam *pwdParam,
    HITLS_PKCS12_MacData *p12Mac)
{
    int32_t ret = HITLS_PKCS12_ParseMacData(macData, p12Mac);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer verify = {0};
    ret = HITLS_PKCS12_CalMac(&verify, pwdParam->macPwd, initData, p12Mac);
    if (ret != HITLS_PKI_SUCCESS) {
        ClearMacData(p12Mac);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (p12Mac->mac->dataLen != verify.dataLen || memcmp(verify.data, p12Mac->mac->data, verify.dataLen) != 0) {
        ClearMacData(p12Mac);
        BSL_SAL_Free(verify.data);
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_VERIFY_FAIL);
        return HITLS_PKCS12_ERR_VERIFY_FAIL;
    }
    BSL_SAL_Free(verify.data);
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseAsn1PKCS12(const BSL_Buffer *encode, const HITLS_PKCS12_PwdParam *pwdParam,
    HITLS_PKCS12 *p12, bool needMacVerify)
{
    uint32_t version = 0;
    uint8_t *temp = encode->data;
    uint32_t  tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_PKCS12_TOPLEVEL_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_p12TopLevelTempl, sizeof(g_p12TopLevelTempl) / sizeof(g_p12TopLevelTempl[0])};
    HITLS_PKCS12_MacData *p12Mac = p12->macData;

    if (pwdParam != NULL) {
        p12->recipientPkeyCtx = pwdParam->recipientPkeyCtx;
    } else {
        p12->recipientPkeyCtx = NULL;
    }

    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_PKCS12_TOPLEVEL_MAX_IDX);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&asn1[HITLS_PKCS12_TOPLEVEL_VERSION_IDX], &version);
    if (ret != HITLS_PKI_SUCCESS) {
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
    // For the outer authSafe, it's typically PKCS7-Data, not EnvelopedData. 
    // EnvelopedData is usually inside the SafeBags.
    // So, pass NULL for recipientPkeyCtx here, or more correctly, ensure ParseContentInfo can handle it.
    // Let's assume the top-level authSafe is NOT EnvelopedData handled by recipientPkeyCtx.
    // If it could be, this call would need p12->recipientPkeyCtx.
    // For now, keeping it as it was, assuming outer is not enveloped for recipient.
    ret = HITLS_PKCS12_ParseContentInfo(p12->libCtx, p12->attrName, NULL /* recipientPkeyCtx for outer authSafe */, &contentInfo, NULL, 0, &initData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret; // has pushed error code.
    }
    if (needMacVerify) {
        // MacVerify uses macPwd, not recipientPkeyCtx
        ret = ParseMacDataAndVerify(&initData, &macData, pwdParam, p12Mac);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_SAL_Free(initData.data);
            return ret; // has pushed error code.
        }
    }
    // ParseAuthSafeData will internally use p12->recipientPkeyCtx when it calls ParseContentInfo for SafeContents
    ret = HITLS_PKCS12_ParseAuthSafeData(&initData, pwdParam, p12); // Pass full pwdParam
    BSL_SAL_Free(initData.data);
    if (ret != HITLS_PKI_SUCCESS) {
        ClearMacData(p12Mac);
        return ret; // has pushed error code.
    }
    p12->version = version;
    return HITLS_PKI_SUCCESS;
}

static int32_t ProviderParseBuffInternal(HITLS_PKI_LibCtx *libCtx, const char *attrName, int32_t format,
    const BSL_Buffer *encode, const HITLS_PKCS12_PwdParam *pwdParam, HITLS_PKCS12 **p12, bool needMacVerify)
{
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 ||
        pwdParam == NULL || pwdParam->encPwd == NULL || pwdParam->encPwd->data == NULL || p12 == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (*p12 != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    int32_t ret;
    HITLS_PKCS12 *temP12 = HITLS_PKCS12_ProviderNew(libCtx, attrName);
    if (temP12 == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    switch (format) {
        case BSL_FORMAT_ASN1:
            ret = ParseAsn1PKCS12(encode, pwdParam, temP12, needMacVerify);
            break;
        default:
            ret = HITLS_PKCS12_ERR_FORMAT_UNSUPPORT;
            break;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_PKCS12_Free(temP12);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *p12 = temP12;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_PKCS12_ProviderParseBuff(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const BSL_Buffer *encode, const HITLS_PKCS12_PwdParam *pwdParam, HITLS_PKCS12 **p12, bool needMacVerify)
{
    int32_t encodeFormat = CRYPT_EAL_GetEncodeFormat(format);
    return ProviderParseBuffInternal(libCtx, attrName, encodeFormat, encode, pwdParam, p12, needMacVerify);
}

#ifdef HITLS_BSL_SAL_FILE
int32_t HITLS_PKCS12_ProviderParseFile(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const char *path, const HITLS_PKCS12_PwdParam *pwdParam, HITLS_PKCS12 **p12, bool needMacVerify)
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
    ret = HITLS_PKCS12_ProviderParseBuff(libCtx, attrName, format, &encode, pwdParam, p12, needMacVerify);
    BSL_SAL_Free(data);
    return ret;
}

int32_t HITLS_PKCS12_ParseFile(int32_t format, const char *path, const HITLS_PKCS12_PwdParam *pwdParam,
    HITLS_PKCS12 **p12, bool needMacVerify)
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
#endif // HITLS_BSL_SAL_FILE

int32_t HITLS_PKCS12_ParseBuff(int32_t format, const BSL_Buffer *encode, const HITLS_PKCS12_PwdParam *pwdParam,
    HITLS_PKCS12 **p12, bool needMacVerify)
{
    return ProviderParseBuffInternal(NULL, NULL, format, encode, pwdParam, p12, needMacVerify);
}

#endif // HITLS_PKI_PKCS12_PARSE

#ifdef HITLS_PKI_PKCS12_GEN
static void FreeListBuff(BSL_ASN1_Buffer *asnBuf, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        BSL_SAL_FREE(asnBuf[i].buff);
    }
    BSL_SAL_FREE(asnBuf);
}

static int32_t EncodeAttrValue(HITLS_PKCS12_SafeBagAttr *attribute, BSL_Buffer *encode)
{
    BSL_ASN1_Buffer asnArr = {0};
    int32_t ret;

    asnArr.buff = attribute->attrValue.data;
    asnArr.len = attribute->attrValue.dataLen;
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
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t X509_EncodeP12AttrItem(void *attrNode, HITLS_X509_AttrEntry *attrEntry)
{
    if (attrNode == NULL || attrEntry == NULL) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    HITLS_PKCS12_SafeBagAttr *p12Attr = attrNode;
    BslOidString *oidStr = BSL_OBJ_GetOidFromCID(p12Attr->attrId);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES);
        return HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES;
    }
    attrEntry->attrId.tag = BSL_ASN1_TAG_OBJECT_ID;
    attrEntry->attrId.buff = (uint8_t *)oidStr->octs;
    attrEntry->attrId.len = oidStr->octetLen;
    BSL_Buffer buffer = {0};
    int32_t ret = EncodeAttrValue(p12Attr, &buffer);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    attrEntry->attrValue.tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
    attrEntry->attrValue.buff = buffer.data;
    attrEntry->attrValue.len = buffer.dataLen;
    attrEntry->cid = p12Attr->attrId;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_PKCS12_EncodeAttrList(HITLS_X509_Attrs *attrs, BSL_ASN1_Buffer *attrBuff)
{
    return HITLS_X509_EncodeAttrList(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, attrs,
        X509_EncodeP12AttrItem, attrBuff);
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
    if (ret != HITLS_PKI_SUCCESS) {
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
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeSafeBag(HITLS_PKCS12_Bag *bag, uint32_t encodeType, const CRYPT_EncodeParam *encryptParam,
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
    if (ret != HITLS_PKI_SUCCESS) {
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
    BSL_SAL_FREE(asnArr[HITLS_PKCS12_SAFEBAG_BAGATTRIBUTES_IDX].buff);
    if (ret != HITLS_PKI_SUCCESS) {
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
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_PKCS12_EncodeContentInfo(HITLS_PKI_LibCtx *libCtx, const char *attrName, BSL_Buffer *input,
    uint32_t encodeType, const CRYPT_EncodeParam *encryptParam, BSL_Buffer *encode)
{
    int32_t ret;
    BslOidString *oidStr = BSL_OBJ_GetOidFromCID(encodeType);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_ALGO);
        return HITLS_PKCS12_ERR_INVALID_ALGO;
    }
    BSL_Buffer initData = {0};
    switch (encodeType) {
        case BSL_CID_PKCS7_SIMPLEDATA:
            ret = EncodeP7Data(input, &initData);
            break;
        case BSL_CID_PKCS7_ENCRYPTEDDATA:
            ret = CRYPT_EAL_EncodePKCS7EncryptDataBuff(libCtx, attrName, input, encryptParam, &initData);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_CONTENTINFO);
            return HITLS_PKCS12_ERR_INVALID_CONTENTINFO;
    }
    if (ret != HITLS_PKI_SUCCESS) {
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
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeSafeContent(BSL_ASN1_Buffer **output, BSL_ASN1_List *list, uint32_t encodeType,
    const CRYPT_EncodeParam *encryptParam)
{
    BSL_ASN1_Buffer *asnBuf = BSL_SAL_Calloc((uint32_t)list->count, sizeof(BSL_ASN1_Buffer));
    if (asnBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t iter = 0;
    int32_t ret = HITLS_PKI_SUCCESS;
    HITLS_PKCS12_Bag *node = NULL;
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
    BSL_ASN1_Buffer *asnBuf = BSL_SAL_Calloc((uint32_t)list->count, sizeof(BSL_ASN1_Buffer));
    if (asnBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t iter = 0;
    int32_t ret = HITLS_PKI_SUCCESS;
    BSL_Buffer *node = NULL;
    for (node = BSL_LIST_GET_FIRST(list); node != NULL; node = BSL_LIST_GET_NEXT(list), iter++) {
        asnBuf[iter].buff = BSL_SAL_Dump(node->data, node->dataLen);
        if (asnBuf[iter].buff == NULL) {
            FreeListBuff(asnBuf, iter);
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
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
    uint32_t count = (uint32_t)BSL_LIST_COUNT(list);
    BSL_ASN1_Buffer *asnBuffers = NULL;
    int32_t ret;
    switch (encodeType) {
        case BSL_CID_PKCS7_CONTENTINFO:
            ret = EncodeContentInfoList(&asnBuffers, list);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            break;
        case BSL_CID_PKCS8SHROUDEDKEYBAG:
        case BSL_CID_CERTBAG:
            ret = EncodeSafeContent(&asnBuffers, list, encodeType, encryptParam);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_CONTENTINFO);
            return HITLS_PKCS12_ERR_INVALID_CONTENTINFO;
    }
    BSL_ASN1_TemplateItem listTempl = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0 };
    BSL_ASN1_Template templ = {&listTempl, 1};
    BSL_ASN1_Buffer out = {0};
    ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, count, &templ, asnBuffers, count, &out);
    FreeListBuff(asnBuffers, count);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_EncodeTemplate(&templ, &out, 1, &encode->data, &encode->dataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_FREE(out.buff);
    return ret;
}

int32_t HITLS_PKCS12_EncodeMacData(BSL_Buffer *initData, const HITLS_PKCS12_MacParam *macParam,
    HITLS_PKCS12_MacData *p12Mac, BSL_Buffer *encode)
{
    if (macParam->algId != BSL_CID_PKCS12KDF) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_ALGO);
        return HITLS_PKCS12_ERR_INVALID_ALGO;
    }
    if (macParam->para == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    BSL_Buffer mac = {0};
    BSL_Buffer digestInfo = {0};
    HITLS_PKCS12_KdfParam *param = (HITLS_PKCS12_KdfParam *)macParam->para;
    p12Mac->alg = param->macId;
    p12Mac->iteration = param->itCnt;
    p12Mac->macSalt->dataLen = param->saltLen;
    BSL_Buffer macPwd = {param->pwd, param->pwdLen};
    int32_t ret = HITLS_PKCS12_CalMac(&mac, &macPwd, initData, p12Mac);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HITLS_CMS_EncodeDigestInfoBuff(p12Mac->alg, &mac, &digestInfo);
    BSL_SAL_FREE(mac.data);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer asnArr[HITLS_PKCS12_MACDATA_MAX_IDX] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, digestInfo.dataLen, digestInfo.data},
        {BSL_ASN1_TAG_OCTETSTRING, p12Mac->macSalt->dataLen, p12Mac->macSalt->data}};

    ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, p12Mac->iteration, &asnArr[HITLS_PKCS12_MACDATA_ITER_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(digestInfo.data);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Template templ = {g_p12MacDataTempl, sizeof(g_p12MacDataTempl) / sizeof(g_p12MacDataTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_PKCS12_MACDATA_MAX_IDX, &encode->data, &encode->dataLen);
    BSL_SAL_Free(digestInfo.data);
    BSL_SAL_Free(asnArr[HITLS_PKCS12_MACDATA_ITER_IDX].buff);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeCertListAddList(HITLS_PKCS12 *p12, const CRYPT_EncodeParam *encParam, BSL_ASN1_List *list,
    bool isNeedMac)
{
    int32_t ret;
    HITLS_PKCS12_Bag *bag = NULL;
    BSL_Buffer certEncode = {0};
    if (p12->entityCert != NULL && p12->entityCert->value.cert != NULL) {
        bag = BSL_SAL_Malloc(sizeof(HITLS_PKCS12_Bag));
        if (bag == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        bag->attributes = p12->entityCert->attributes;
        bag->value.cert = p12->entityCert->value.cert;
        ret = BSL_LIST_AddElement(p12->certList, bag, BSL_LIST_POS_BEGIN);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_SAL_FREE(bag);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (BSL_LIST_COUNT(p12->certList) <= 0) {
        return HITLS_PKI_SUCCESS;
    }
    ret = HITLS_PKCS12_EncodeAsn1List(p12->certList, BSL_CID_CERTBAG, NULL, &certEncode);
    if (p12->entityCert != NULL && p12->entityCert->value.cert != NULL) {
        BSL_LIST_First(p12->certList);
        BSL_LIST_DeleteCurrent(p12->certList, NULL);
    }
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Buffer contentInfoEncode = {0};
    if (isNeedMac) {
        ret = HITLS_PKCS12_EncodeContentInfo(p12->libCtx, p12->attrName, &certEncode, BSL_CID_PKCS7_ENCRYPTEDDATA,
            encParam, &contentInfoEncode);
    } else {
        ret = HITLS_PKCS12_EncodeContentInfo(p12->libCtx, p12->attrName, &certEncode, BSL_CID_PKCS7_SIMPLEDATA,
            encParam, &contentInfoEncode);
    }
    BSL_SAL_FREE(certEncode.data);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_AddListItemDefault(&contentInfoEncode, sizeof(BSL_Buffer), list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(contentInfoEncode.data);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeKeyAddList(HITLS_PKCS12 *p12, const CRYPT_EncodeParam *encParam, BSL_ASN1_List *list)
{
    if (p12->key == NULL || p12->key->value.key == NULL) {
        return HITLS_PKI_SUCCESS;
    }

    BSL_ASN1_List *keyList = BSL_LIST_New(sizeof(HITLS_PKCS12_Bag));
    if (keyList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    HITLS_PKCS12_Bag bag = {0};
    BSL_Buffer keyEncode = {0};
    BSL_Buffer contentInfoEncode = {0};
    bag.attributes = p12->key->attributes;
    bag.value.key = p12->key->value.key;
    int32_t ret = HITLS_X509_AddListItemDefault(&bag, sizeof(HITLS_PKCS12_Bag), keyList);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(keyList);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_PKCS12_EncodeAsn1List(keyList, BSL_CID_PKCS8SHROUDEDKEYBAG, encParam, &keyEncode);
    BSL_LIST_FREE(keyList, NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HITLS_PKCS12_EncodeContentInfo(p12->libCtx, p12->attrName, &keyEncode, BSL_CID_PKCS7_SIMPLEDATA, NULL, &contentInfoEncode);
    BSL_SAL_FREE(keyEncode.data);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_AddListItemDefault(&contentInfoEncode, sizeof(BSL_Buffer), list);
    if (ret != HITLS_PKI_SUCCESS) {
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
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_ASN1_Template templ = {g_p12TopLevelTempl, sizeof(g_p12TopLevelTempl) / sizeof(g_p12TopLevelTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_PKCS12_TOPLEVEL_MAX_IDX,
        &encode->data, &encode->dataLen);
    BSL_SAL_Free(asnArr[HITLS_PKCS12_TOPLEVEL_VERSION_IDX].buff);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t PwdConsistencyCheck(const HITLS_PKCS12_EncodeParam *encodeParam, bool isNeedMac)
{
    CRYPT_Pbkdf2Param *keyParam = (CRYPT_Pbkdf2Param *)encodeParam->keyEncParam.param;
    CRYPT_Pbkdf2Param *certParam = (CRYPT_Pbkdf2Param *)encodeParam->certEncParam.param;
    if (!isNeedMac) {
        // Certificates do not require encryption when integrity verification is disabled.
        if (keyParam == NULL || keyParam->pwd == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
            return HITLS_PKCS12_ERR_INVALID_PARAM;
        }
        return HITLS_PKI_SUCCESS;
    }
    if (keyParam == NULL || certParam == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    uint8_t *certPwd = certParam->pwd;
    uint8_t *keyPwd = keyParam->pwd;
    // Both certificate and key encryption passwords can be NULL simultaneously.
    if (certPwd == NULL && keyPwd == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    if (certPwd == NULL || keyPwd == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (keyParam->pwdLen == certParam->pwdLen && memcmp(certPwd, keyPwd, certParam->pwdLen) == 0) {
        return HITLS_PKI_SUCCESS;
    }
    // Error if certificate and private key encryption passwords do not match.
    BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
    return HITLS_PKCS12_ERR_INVALID_PARAM;
}

static int32_t EncodeP12Info(HITLS_PKCS12 *p12, const HITLS_PKCS12_EncodeParam *encodeParam, bool isNeedMac,
    BSL_Buffer *encode)
{
    int32_t ret = PwdConsistencyCheck(encodeParam, isNeedMac);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    BSL_ASN1_List *list = BSL_LIST_New(sizeof(BSL_Buffer));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ret = EncodeCertListAddList(p12, &encodeParam->certEncParam, list, isNeedMac);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(list, FreeBuffer);
        return ret;
    }

    ret = EncodeKeyAddList(p12, &encodeParam->keyEncParam, list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(list, FreeBuffer);
        return ret;
    }
    if (BSL_LIST_COUNT(list) <= 0) {
        BSL_SAL_Free(list);
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NONE_DATA);
        return HITLS_PKCS12_ERR_NONE_DATA;
    }
    BSL_Buffer initData = {0};
    ret = HITLS_PKCS12_EncodeAsn1List(list, BSL_CID_PKCS7_CONTENTINFO, NULL, &initData);
    BSL_LIST_FREE(list, FreeBuffer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    BSL_Buffer macData = {0};
    if (isNeedMac) {
        ret = HITLS_PKCS12_EncodeMacData(&initData, &encodeParam->macParam, p12->macData, &macData);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_SAL_FREE(initData.data);
            return ret;
        }
    }

    BSL_Buffer authSafe = {0};
    ret = HITLS_PKCS12_EncodeContentInfo(p12->libCtx, p12->attrName, &initData, BSL_CID_PKCS7_SIMPLEDATA, NULL,
        &authSafe);
    BSL_SAL_FREE(initData.data);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(macData.data);
        return ret;
    }
    ret = EncodePkcs12(p12->version, &authSafe, &macData, encode);
    BSL_SAL_FREE(authSafe.data);
    BSL_SAL_FREE(macData.data);
    return ret;
}

int32_t HITLS_PKCS12_GenBuff(int32_t format, HITLS_PKCS12 *p12, const HITLS_PKCS12_EncodeParam *encodeParam,
    bool isNeedMac, BSL_Buffer *encode)
{
    if (p12 == NULL || encodeParam == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (encode->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    switch (format) {
        case BSL_FORMAT_ASN1:
            return EncodeP12Info(p12, encodeParam, isNeedMac, encode);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_FORMAT_UNSUPPORT);
            return HITLS_PKCS12_ERR_FORMAT_UNSUPPORT;
    }
}

#ifdef HITLS_BSL_SAL_FILE
int32_t HITLS_PKCS12_GenFile(int32_t format, HITLS_PKCS12 *p12, const HITLS_PKCS12_EncodeParam *encodeParam,
    bool isNeedMac, const char *path)
{
    if (path == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }

    BSL_Buffer encode = {0};
    int32_t ret = HITLS_PKCS12_GenBuff(format, p12, encodeParam, isNeedMac, &encode);
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
#endif

static void DeleteAttribute(HITLS_PKCS12_Bag *bag, uint32_t type)
{
    if (bag->attributes == NULL) {
        return;
    }
    BSL_ASN1_List *list = bag->attributes->list;
    HITLS_PKCS12_SafeBagAttr *node = BSL_LIST_GET_FIRST(list);
    while (node != NULL) {
        if (node->attrId == type) {
            return BSL_LIST_DeleteCurrent(list, HITLS_PKCS12_AttributesFree);
        }
        node = BSL_LIST_GET_NEXT(list);
    }
    return;
}

static bool IsAttrExist(HITLS_PKCS12_Bag *bag, uint32_t type)
{
    if (bag->attributes == NULL || bag->attributes->list == NULL) {
        return false;
    }
    BSL_ASN1_List *list = bag->attributes->list;
    HITLS_PKCS12_SafeBagAttr *node = BSL_LIST_GET_FIRST(list);
    while (node != NULL) {
        if (node->attrId == type) {
            return true;
        }
        node = BSL_LIST_GET_NEXT(list);
    }
    return false;
}

int32_t HITLS_PKCS12_BagAddAttr(HITLS_PKCS12_Bag *bag, uint32_t type, const BSL_Buffer *attrValue)
{
    if (bag == NULL || attrValue == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (attrValue->data == NULL || attrValue->dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (type != BSL_CID_LOCALKEYID && type != BSL_CID_FRIENDLYNAME) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES);
        return HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES;
    }
    if (IsAttrExist(bag, type)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_ATTR_REPEAT);
        return HITLS_X509_ERR_SET_ATTR_REPEAT;
    }

    HITLS_PKCS12_SafeBagAttr attr = {0};
    attr.attrId = type;
    attr.attrValue.data = BSL_SAL_Dump(attrValue->data, attrValue->dataLen);
    if (attr.attrValue.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    attr.attrValue.dataLen = attrValue->dataLen;
    if (bag->attributes == NULL) {
        bag->attributes = HITLS_X509_AttrsNew();
        if (bag->attributes == NULL) {
            BSL_SAL_FREE(attr.attrValue.data);
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }
    int32_t ret = HITLS_X509_AddListItemDefault(&attr, sizeof(HITLS_PKCS12_SafeBagAttr), bag->attributes->list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(attr.attrValue.data);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static void *AttrCopy(const void *val)
{
    const HITLS_PKCS12_SafeBagAttr *input = (const HITLS_PKCS12_SafeBagAttr *)val;
    HITLS_PKCS12_SafeBagAttr *output = BSL_SAL_Malloc(sizeof(HITLS_PKCS12_SafeBagAttr));
    if (output == NULL) {
        return NULL;
    }
    output->attrValue.data = BSL_SAL_Dump(input->attrValue.data, input->attrValue.dataLen);
    if (output->attrValue.data == NULL) {
        BSL_SAL_Free(output);
        return NULL;
    }
    output->attrValue.dataLen = input->attrValue.dataLen;
    output->attrId = input->attrId;
    return output;
}

static HITLS_PKCS12_Bag *BagDump(HITLS_PKCS12_Bag *input)
{
    HITLS_PKCS12_Bag *target = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *cert = NULL;
    switch (input->type) {
        case BSL_CID_PKCS8SHROUDEDKEYBAG:
            pkey = CRYPT_EAL_PkeyDupCtx(input->value.key);
            if (pkey == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                return NULL;
            }
            target = HITLS_PKCS12_BagNew(input->type, pkey);
            break;
        case BSL_CID_CERTBAG:
            cert = HITLS_X509_CertDup(input->value.cert);
            if (cert == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_DUP_FAIL);
                return NULL;
            }
            target = HITLS_PKCS12_BagNew(input->type, cert);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
            return NULL;
    }
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    if (target == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    if (input->attributes != NULL) {
        target->attributes = HITLS_X509_AttrsDup(input->attributes, AttrCopy, HITLS_PKCS12_AttributesFree);
        if (target->attributes == NULL) {
            HITLS_PKCS12_BagFree(target);
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return NULL;
        }
    }
    return target;
}

static int32_t PKCS12_SetEntityKey(HITLS_PKCS12 *p12, void *val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (p12->key != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_REPEATED_SET_KEY);
        return HITLS_PKCS12_ERR_REPEATED_SET_KEY;
    }

    HITLS_PKCS12_Bag *input = (HITLS_PKCS12_Bag *)val;
    if (input->type != BSL_CID_PKCS8SHROUDEDKEYBAG) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (input->value.key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    HITLS_PKCS12_Bag *output = BagDump(input);
    if (output == NULL) {
        return BSL_MALLOC_FAIL; // has pushed error code.
    }
    p12->key = output;
    return HITLS_PKI_SUCCESS;
}

static int32_t PKCS12_SetEntityCert(HITLS_PKCS12 *p12, void *val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (p12->entityCert != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_REPEATED_SET_ENTITYCERT);
        return HITLS_PKCS12_ERR_REPEATED_SET_ENTITYCERT;
    }

    HITLS_PKCS12_Bag *input = (HITLS_PKCS12_Bag *)val;
    if (input->type != BSL_CID_CERTBAG) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (input->value.cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    HITLS_PKCS12_Bag *output = BagDump(input);
    if (output == NULL) {
        return BSL_MALLOC_FAIL; // has pushed error code.
    }
    p12->entityCert = output;
    return HITLS_PKI_SUCCESS;
}

static int32_t PKCS12_AddCertBag(HITLS_PKCS12 *p12, void *val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    int32_t ret;
    HITLS_PKCS12_Bag *input = (HITLS_PKCS12_Bag *)val;
    if (input->type != BSL_CID_CERTBAG) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (input->value.cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    HITLS_PKCS12_Bag *target = BagDump(input);
    if (target == NULL) {
        return BSL_MALLOC_FAIL;
    }
    ret = BSL_LIST_AddElement(p12->certList, target, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        HITLS_PKCS12_BagFree(target);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t PKCS12_SetLocalKeyId(HITLS_PKCS12 *p12, CRYPT_MD_AlgId *algId, uint32_t algIdLen)
{
    if (algId == NULL || p12->entityCert == NULL || p12->key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (algIdLen != sizeof(CRYPT_MD_AlgId)) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (p12->entityCert->value.cert == NULL || p12->key->value.key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NO_PAIRED_CERT_AND_KEY);
        return HITLS_PKCS12_ERR_NO_PAIRED_CERT_AND_KEY;
    }
    uint32_t mdSize = CRYPT_EAL_MdGetDigestSize(*algId);
    if (mdSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    uint8_t *md = BSL_SAL_Malloc(mdSize);
    if (md == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_X509_CertDigest(p12->entityCert->value.cert, *algId, md, &mdSize);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(md);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer buffer = {.data = md, .dataLen = mdSize};
    ret = HITLS_PKCS12_BagAddAttr(p12->key, BSL_CID_LOCALKEYID, &buffer);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(md);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HITLS_PKCS12_BagAddAttr(p12->entityCert, BSL_CID_LOCALKEYID, &buffer);
    BSL_SAL_Free(md);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        DeleteAttribute(p12->key, BSL_CID_LOCALKEYID);
    }
    return ret;
}
#endif // HITLS_PKI_PKCS12_GEN

static int32_t PKCS12_GetEntityCert(HITLS_PKCS12 *p12, void **val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (*val != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (p12->entityCert == NULL || p12->entityCert->value.cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NO_ENTITYCERT);
        return HITLS_PKCS12_ERR_NO_ENTITYCERT;
    }
    HITLS_X509_Cert *dest = HITLS_X509_CertDup(p12->entityCert->value.cert);
    if (dest == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_DUP_FAIL);
        return HITLS_X509_ERR_CERT_DUP_FAIL;
    }
    *val = dest;
    return HITLS_PKI_SUCCESS;
}

static int32_t PKCS12_GetEntityKey(HITLS_PKCS12 *p12, void **val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (*val != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (p12->key == NULL || p12->key->value.key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NO_ENTITYKEY);
        return HITLS_PKCS12_ERR_NO_ENTITYKEY;
    }
    CRYPT_EAL_PkeyCtx *dest = CRYPT_EAL_PkeyDupCtx(p12->key->value.key);
    if (dest == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    *val = dest;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_PKCS12_Ctrl(HITLS_PKCS12 *p12, int32_t cmd, void *val, uint32_t valLen)
{
#ifndef HITLS_PKI_PKCS12_GEN
    (void)valLen;
#endif
    if (p12 == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    switch (cmd) {
#ifdef HITLS_PKI_PKCS12_GEN
        case HITLS_PKCS12_GEN_LOCALKEYID:
            return PKCS12_SetLocalKeyId(p12, val, valLen);
        case HITLS_PKCS12_SET_ENTITY_KEYBAG:
            return PKCS12_SetEntityKey(p12, val);
        case HITLS_PKCS12_SET_ENTITY_CERTBAG:
            return PKCS12_SetEntityCert(p12, val);
        case HITLS_PKCS12_ADD_CERTBAG:
            return PKCS12_AddCertBag(p12, val);
#endif
        case HITLS_PKCS12_GET_ENTITY_CERT:
            return PKCS12_GetEntityCert(p12, val);
        case HITLS_PKCS12_GET_ENTITY_KEY:
            return PKCS12_GetEntityKey(p12, val);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
            return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
}
#endif // HITLS_PKI_PKCS12
