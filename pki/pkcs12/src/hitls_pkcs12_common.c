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
#include "crypt_codecskey.h"
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
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(asnArr[HITLS_PKCS12_COMMON_SAFEBAG_OID_IDX].buff,
        asnArr[HITLS_PKCS12_COMMON_SAFEBAG_OID_IDX].len);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_PARSE_TYPE);
        return HITLS_PKCS12_ERR_PARSE_TYPE;
    }
    bag->bagType = cid;
    bag->bagValue.data = asnArr[HITLS_PKCS12_COMMON_SAFEBAG_BAGVALUES_IDX].buff;
    bag->bagValue.dataLen = asnArr[HITLS_PKCS12_COMMON_SAFEBAG_BAGVALUES_IDX].len;
    return HITLS_PKI_SUCCESS;
}

/* Convert commonBags to the cert */
static int32_t ConvertCertBag(HITLS_PKCS12 *p12, HITLS_PKCS12_CommonSafeBag *bag, HITLS_X509_Cert **cert)
{
    if (bag == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (bag->bagType != BSL_CID_X509CERTIFICATE) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_CERTYPES);
        return HITLS_PKCS12_ERR_INVALID_CERTYPES;
    }
    return HITLS_X509_ProviderCertParseBuff(p12->libCtx, p12->attrName, "ASN1", &bag->bagValue, cert);
}

/* Convert commonBags to the crl */
static int32_t ConvertCrlBag(HITLS_PKCS12 *p12, HITLS_PKCS12_CommonSafeBag *bag, HITLS_X509_Crl **crl)
{
    (void)p12;
    if (bag == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (bag->bagType != BSL_CID_X509CRL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_CERTYPES);
        return HITLS_PKCS12_ERR_INVALID_CERTYPES;
    }
    return HITLS_X509_CrlParseBuff(BSL_FORMAT_ASN1, &bag->bagValue, crl);
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

    BslCid cid = BSL_OBJ_GetCidFromOidBuff(asnArr[HITLS_PKCS12_SAFEBAG_OID_IDX].buff,
        asnArr[HITLS_PKCS12_SAFEBAG_OID_IDX].len);
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
    HITLS_PKCS12_Bag *keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, prikey);
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

static int32_t ParseKeyBagAndAddList(HITLS_PKCS12 *p12, HITLS_PKCS12_SafeBag *safeBag)
{
    CRYPT_EAL_PkeyCtx *prikey = NULL;
    int32_t ret = CRYPT_EAL_ProviderDecodeBuffKey(p12->libCtx, p12->attrName, BSL_CID_UNKNOWN, "ASN1",
        "PRIKEY_PKCS8_UNENCRYPT", safeBag->bag, NULL, &prikey);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_PKCS12_Bag *keyBag = HITLS_PKCS12_BagNew(BSL_CID_KEYBAG, 0, prikey);
    CRYPT_EAL_PkeyFreeCtx(prikey);
    if (keyBag == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    keyBag->attributes = safeBag->attributes;
    ret = BSL_LIST_AddElement(p12->keyList, keyBag, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        keyBag->attributes = NULL;
        HITLS_PKCS12_BagFree(keyBag);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    safeBag->attributes = NULL;
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
    ret = ConvertCertBag(p12, &bag, &cert);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_PKCS12_Bag *bagData = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, cert);
    HITLS_X509_CertFree(cert);
    if (bagData == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    bagData->attributes = safeBag->attributes;
    ret = BSL_LIST_AddElement(p12->certList, bagData, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        bagData->attributes = NULL;
        HITLS_PKCS12_BagFree(bagData);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    safeBag->attributes = NULL;
    return ret;
}

static int32_t ParseCrlBagAndAddList(HITLS_PKCS12 *p12, HITLS_PKCS12_SafeBag *safeBag)
{
    HITLS_PKCS12_CommonSafeBag bag = {0};
    int32_t ret = ParseCommonSafeBag(safeBag->bag, &bag);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_X509_Crl *crl = NULL;
    ret = ConvertCrlBag(p12, &bag, &crl);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_PKCS12_Bag *bagData = HITLS_PKCS12_BagNew(BSL_CID_CRLBAG, BSL_CID_X509CRL, crl);
    HITLS_X509_CrlFree(crl);
    if (bagData == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    bagData->attributes = safeBag->attributes;
    ret = BSL_LIST_AddElement(p12->crlList, bagData, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        bagData->attributes = NULL;
        HITLS_PKCS12_BagFree(bagData);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    safeBag->attributes = NULL;
    return ret;
}

static int32_t ParseSecretBagAndAddList(HITLS_PKCS12 *p12, HITLS_PKCS12_SafeBag *safeBag)
{
    HITLS_PKCS12_CommonSafeBag bag = {0};
    int32_t ret = ParseCommonSafeBag(safeBag->bag, &bag);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_PKCS12_Bag *bagData = HITLS_PKCS12_BagNew(BSL_CID_SECRETBAG, bag.bagType, &bag.bagValue);
    if (bagData == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    bagData->attributes = safeBag->attributes;
    ret = BSL_LIST_AddElement(p12->secretBags, bagData, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        bagData->attributes = NULL;
        HITLS_PKCS12_BagFree(bagData);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
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
        case BSL_CID_CRLBAG:
            return ParseCrlBagAndAddList(p12, safeBag);
        case BSL_CID_SECRETBAG:
            return ParseSecretBagAndAddList(p12, safeBag);
        case BSL_CID_KEYBAG:
            return ParseKeyBagAndAddList(p12, safeBag);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE);
            return HITLS_PKCS12_ERR_INVALID_SAFEBAG_TYPE;
    }
}

int32_t HITLS_PKCS12_ParseContentInfo(HITLS_PKI_LibCtx *libCtx, const char *attrName, BSL_Buffer *encode,
    const uint8_t *password, uint32_t passLen, BSL_Buffer *data)
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
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(asnArr[HITLS_PKCS12_CONTENT_OID_IDX].buff,
        asnArr[HITLS_PKCS12_CONTENT_OID_IDX].len);
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
    while (node != NULL) {
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
            p12->entityCert = node;
            BSL_LIST_DetachCurrent(bags);
            return HITLS_PKI_SUCCESS;
        }
        node = BSL_LIST_GET_NEXT(bags);
    }
    BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NO_ENTITYCERT);
    return HITLS_PKCS12_ERR_NO_ENTITYCERT;
}

static int32_t ParseSafeBagList(HITLS_PKI_LibCtx *libCtx, const char *attrName, BSL_Buffer *node,
    const uint8_t *password, uint32_t passLen, BSL_ASN1_List *bagLists)
{
    BSL_Buffer safeContent = {0};
    int32_t ret = HITLS_PKCS12_ParseContentInfo(libCtx, attrName, node, password, passLen, &safeContent);
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
int32_t HITLS_PKCS12_ParseAuthSafeData(BSL_Buffer *encode, const uint8_t *password, uint32_t passLen,
    HITLS_PKCS12 *p12)
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
    while (node != NULL) {
        ret = ParseSafeBagList(p12->libCtx, p12->attrName, node, password, passLen, bagLists);
        if (ret != HITLS_PKI_SUCCESS) {
            goto ERR;
        }
        node = BSL_LIST_GET_NEXT(contentList);
    }
    ret = HITLS_PKCS12_ParseSafeBagList(bagLists, password, passLen, p12);
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
    HITLS_PKCS12_SafeBag *safeBag = BSL_SAL_Calloc(sizeof(HITLS_PKCS12_SafeBag), 1);
    if (safeBag == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = ParseSafeBag(&buffer, safeBag);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(safeBag);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_AddListItemDefault(safeBag, sizeof(HITLS_PKCS12_SafeBag), list);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_PKCS12_SafeBagFree(safeBag);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_SAL_Free(safeBag);
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
    if (ret != BSL_SUCCESS) {
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
    if (p12Mac == NULL) {
        return;
    }
    BSL_SAL_FREE(p12Mac->mac->data);
    BSL_SAL_FREE(p12Mac->macSalt->data);
    p12Mac->macSalt->dataLen = 0;
    p12Mac->mac->dataLen = 0;
    p12Mac->iteration = 0;
    p12Mac->alg = BSL_CID_UNKNOWN;
}

static int32_t ParseMacDataAndVerify(HITLS_PKCS12 *p12, BSL_Buffer *initData, BSL_Buffer *macData,
    const HITLS_PKCS12_PwdParam *pwdParam)
{
    int32_t ret = HITLS_PKCS12_ParseMacData(macData, p12->macData);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer verify = {0};
    ret = HITLS_PKCS12_CalMac(p12, pwdParam->macPwd, initData, &verify);
    if (ret != HITLS_PKI_SUCCESS) {
        ClearMacData(p12->macData);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (p12->macData->mac->dataLen != verify.dataLen ||
        memcmp(verify.data, p12->macData->mac->data, verify.dataLen) != 0) {
        ClearMacData(p12->macData);
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
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_PKCS12_TOPLEVEL_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&asn1[HITLS_PKCS12_TOPLEVEL_VERSION_IDX], &version);
    if (ret != BSL_SUCCESS) {
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
    ret = HITLS_PKCS12_ParseContentInfo(p12->libCtx, p12->attrName, &contentInfo, NULL, 0, &initData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret; // has pushed error code.
    }
    if (needMacVerify) {
        ret = ParseMacDataAndVerify(p12, &initData, &macData, pwdParam);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_SAL_Free(initData.data);
            return ret; // has pushed error code.
        }
    }
    ret = HITLS_PKCS12_ParseAuthSafeData(&initData, pwdParam->encPwd->data, pwdParam->encPwd->dataLen, p12);
    BSL_SAL_Free(initData.data);
    if (ret != HITLS_PKI_SUCCESS) {
        ClearMacData(p12->macData);
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

typedef int32_t (*CommonBagGenBuffFunc)(void *value, BSL_Buffer *buffer, bool *needFree);

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
    if (ret != BSL_SUCCESS) {
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
    BslOidString *oidStr = BSL_OBJ_GetOID(p12Attr->attrId);
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

static int32_t EncodeCommonBag(void *value, uint32_t type, CommonBagGenBuffFunc genBuffFunc,
    uint8_t **encode, uint32_t *encodeLen)
{
    int32_t ret;
    BslOidString *oidStr = BSL_OBJ_GetOID(type);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_ALGO);
        return HITLS_PKCS12_ERR_INVALID_ALGO;
    }

    BSL_Buffer valueBuff = {0};
    bool needFree = false;
    ret = genBuffFunc(value, &valueBuff, &needFree);
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
            .buff = valueBuff.data,
            .len = valueBuff.dataLen,
            .tag = BSL_ASN1_TAG_OCTETSTRING,
        }};

    BSL_ASN1_Template templ = {g_pk12CommonBagTempl, sizeof(g_pk12CommonBagTempl) / sizeof(g_pk12CommonBagTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_PKCS12_COMMON_SAFEBAG_MAX_IDX, encode, encodeLen);
    if (needFree) {
        BSL_SAL_Free(valueBuff.data);
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t GenCertBuff(void *value, BSL_Buffer *buffer, bool *needFree)
{
    *needFree = true;
    return HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, (HITLS_X509_Cert *)value, buffer);
}

static int32_t GenCrlBuff(void *value, BSL_Buffer *buffer, bool *needFree)
{
    *needFree = true;
    return HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, (HITLS_X509_Crl *)value, buffer);
}

static int32_t GenSecretBuff(void *value, BSL_Buffer *buffer, bool *needFree)
{
    BSL_Buffer *secret = (BSL_Buffer *)value;
    buffer->data = secret->data;
    buffer->dataLen = secret->dataLen;
    *needFree = false;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeSafeBag(HITLS_PKCS12 *p12, HITLS_PKCS12_Bag *bag, uint32_t encodeType,
    const CRYPT_EncodeParam *encryptParam, uint8_t **output, uint32_t *outputLen)
{
    int32_t ret;
    BslOidString *oidStr = BSL_OBJ_GetOID(encodeType);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_ALGO);
        return HITLS_PKCS12_ERR_INVALID_ALGO;
    }
    BSL_Buffer encode = {0};
    switch (encodeType) {
        case BSL_CID_PKCS8SHROUDEDKEYBAG:
            if (encryptParam == NULL || encryptParam->param == NULL) {
                ret = HITLS_PKCS12_ERR_NO_ENCRYPT_PARAM;
                break;
            }
            ret = CRYPT_EAL_ProviderEncodeBuffKey(p12->libCtx, p12->attrName, bag->value.key, encryptParam,
                "ASN1", "PRIKEY_PKCS8_ENCRYPT", &encode);
            break;
        case BSL_CID_KEYBAG:
            ret = CRYPT_EAL_ProviderEncodeBuffKey(p12->libCtx, p12->attrName, bag->value.key, NULL, "ASN1",
                "PRIKEY_PKCS8_UNENCRYPT", &encode);
            break;
        case BSL_CID_CERTBAG:
            ret = EncodeCommonBag(bag->value.cert, BSL_CID_X509CERTIFICATE, GenCertBuff, &encode.data, &encode.dataLen);
            break;
        case BSL_CID_CRLBAG:
            ret = EncodeCommonBag(bag->value.crl, BSL_CID_X509CRL, GenCrlBuff, &encode.data, &encode.dataLen);
            break;
        case BSL_CID_SECRETBAG:
            ret = EncodeCommonBag(&bag->value.secret, bag->type, GenSecretBuff, &encode.data, &encode.dataLen);
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
    if (ret != BSL_SUCCESS) {
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
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_PKCS12_EncodeContentInfo(HITLS_PKI_LibCtx *libCtx, const char *attrName, BSL_Buffer *input,
    uint32_t encodeType, const CRYPT_EncodeParam *encryptParam, BSL_Buffer *encode)
{
    int32_t ret;
    BslOidString *oidStr = BSL_OBJ_GetOID(encodeType);
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
            if (encryptParam == NULL || encryptParam->param == NULL) {
                ret = HITLS_PKCS12_ERR_NO_ENCRYPT_PARAM;
                break;
            }
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
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeSafeContent(HITLS_PKCS12 *p12, BSL_ASN1_Buffer **output, BSL_ASN1_List *list, uint32_t encodeType,
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
        ret = EncodeSafeBag(p12, node, encodeType, encryptParam, &asnBuf[iter].buff, &asnBuf[iter].len);
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

int32_t HITLS_PKCS12_EncodeAsn1List(HITLS_PKCS12 *p12, BSL_ASN1_List *list, uint32_t encodeType,
    const CRYPT_EncodeParam *encryptParam, BSL_Buffer *encode)
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
        case BSL_CID_SECRETBAG:
        case BSL_CID_PKCS8SHROUDEDKEYBAG:
        case BSL_CID_KEYBAG:
        case BSL_CID_CERTBAG:
        case BSL_CID_CRLBAG:
            ret = EncodeSafeContent(p12, &asnBuffers, list, encodeType, encryptParam);
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
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_EncodeTemplate(&templ, &out, 1, &encode->data, &encode->dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_FREE(out.buff);
    return ret;
}

int32_t HITLS_PKCS12_EncodeMacData(HITLS_PKCS12 *p12, BSL_Buffer *initData, const HITLS_PKCS12_MacParam *macParam,
    BSL_Buffer *encode)
{
    HITLS_PKCS12_MacData *p12Mac = p12->macData;
    if (macParam->algId != BSL_CID_PKCS12KDF) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_ALGO);
        return HITLS_PKCS12_ERR_INVALID_ALGO;
    }
    if (macParam->para == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NO_MAC_PARAM);
        return HITLS_PKCS12_ERR_NO_MAC_PARAM;
    }
    BSL_Buffer mac = {0};
    BSL_Buffer digestInfo = {0};
    HITLS_PKCS12_KdfParam *param = (HITLS_PKCS12_KdfParam *)macParam->para;
    p12Mac->alg = param->macId;
    p12Mac->iteration = param->itCnt;
    p12Mac->macSalt->dataLen = param->saltLen;
    BSL_Buffer macPwd = {param->pwd, param->pwdLen};
    int32_t ret = HITLS_PKCS12_CalMac(p12, &macPwd, initData, &mac);
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
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(digestInfo.data);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Template templ = {g_p12MacDataTempl, sizeof(g_p12MacDataTempl) / sizeof(g_p12MacDataTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_PKCS12_MACDATA_MAX_IDX, &encode->data, &encode->dataLen);
    BSL_SAL_Free(digestInfo.data);
    BSL_SAL_Free(asnArr[HITLS_PKCS12_MACDATA_ITER_IDX].buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeCertListAddList(HITLS_PKCS12 *p12, const CRYPT_EncodeParam *encParam, BSL_ASN1_List *list,
    bool isNeedMac)
{
    int32_t ret;
    BSL_Buffer certEncode = {0};
    if (p12->entityCert != NULL && p12->entityCert->value.cert != NULL) {
        HITLS_PKCS12_Bag *bag = BSL_SAL_Malloc(sizeof(HITLS_PKCS12_Bag));
        if (bag == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        bag->attributes = p12->entityCert->attributes;
        bag->value.cert = p12->entityCert->value.cert;
        ret = BSL_LIST_AddElement(p12->certList, bag, BSL_LIST_POS_BEGIN);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_FREE(bag);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (BSL_LIST_COUNT(p12->certList) <= 0) {
        return HITLS_PKI_SUCCESS;
    }
    ret = HITLS_PKCS12_EncodeAsn1List(p12, p12->certList, BSL_CID_CERTBAG, NULL, &certEncode);
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

static int32_t EncodeUnitListAddList(HITLS_PKCS12 *p12, const CRYPT_EncodeParam *encParam, BSL_ASN1_List *list,
    bool isNeedMac, BSL_ASN1_List *uintBags)
{
    if (BSL_LIST_COUNT(uintBags) <= 0) {
        return HITLS_PKI_SUCCESS;
    }
    BSL_Buffer uintEncode = {0};
    HITLS_PKCS12_Bag *bag = BSL_LIST_GET_FIRST(uintBags);
    int32_t ret = HITLS_PKCS12_EncodeAsn1List(p12, uintBags, bag->id, NULL, &uintEncode);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer contentInfoEncode = {0};
    if (isNeedMac) {
        ret = HITLS_PKCS12_EncodeContentInfo(p12->libCtx, p12->attrName, &uintEncode, BSL_CID_PKCS7_ENCRYPTEDDATA,
            encParam, &contentInfoEncode);
    } else {
        ret = HITLS_PKCS12_EncodeContentInfo(p12->libCtx, p12->attrName, &uintEncode, BSL_CID_PKCS7_SIMPLEDATA,
            encParam, &contentInfoEncode);
    }
    BSL_SAL_FREE(uintEncode.data);
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

static int32_t EncodeShroudedKeyAddList(HITLS_PKCS12 *p12, const CRYPT_EncodeParam *encParam, BSL_ASN1_List *list)
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
    ret = HITLS_PKCS12_EncodeAsn1List(p12, keyList, BSL_CID_PKCS8SHROUDEDKEYBAG, encParam, &keyEncode);
    BSL_LIST_FREE(keyList, NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HITLS_PKCS12_EncodeContentInfo(p12->libCtx, p12->attrName, &keyEncode, BSL_CID_PKCS7_SIMPLEDATA,
        NULL, &contentInfoEncode);
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
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_ASN1_Template templ = {g_p12TopLevelTempl, sizeof(g_p12TopLevelTempl) / sizeof(g_p12TopLevelTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_PKCS12_TOPLEVEL_MAX_IDX,
        &encode->data, &encode->dataLen);
    BSL_SAL_Free(asnArr[HITLS_PKCS12_TOPLEVEL_VERSION_IDX].buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeP12Info(HITLS_PKCS12 *p12, const HITLS_PKCS12_EncodeParam *encodeParam, bool isNeedMac,
    BSL_Buffer *encode)
{
    BSL_ASN1_List *list = BSL_LIST_New(sizeof(BSL_Buffer));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    // encode certBags.
    int32_t ret = EncodeCertListAddList(p12, &encodeParam->encParam, list, isNeedMac);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(list, FreeBuffer);
        return ret;
    }
    // encode shrouded key bags.
    ret = EncodeShroudedKeyAddList(p12, &encodeParam->encParam, list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(list, FreeBuffer);
        return ret;
    }
    // encode keyBags.
    ret = EncodeUnitListAddList(p12, &encodeParam->encParam, list, isNeedMac, p12->keyList);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(list, FreeBuffer);
        return ret;
    }
    // encode secretBags.
    ret = EncodeUnitListAddList(p12, &encodeParam->encParam, list, isNeedMac, p12->secretBags);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(list, FreeBuffer);
        return ret;
    }
    // encode crlBags.
    ret = EncodeUnitListAddList(p12, &encodeParam->encParam, list, isNeedMac, p12->crlList);
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
    ret = HITLS_PKCS12_EncodeAsn1List(p12, list, BSL_CID_PKCS7_CONTENTINFO, NULL, &initData);
    BSL_LIST_FREE(list, FreeBuffer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    BSL_Buffer macData = {0};
    if (isNeedMac) {
        ret = HITLS_PKCS12_EncodeMacData(p12, &initData, &encodeParam->macParam, &macData);
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
    if (ret != BSL_SUCCESS) {
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
    if (input->id != BSL_CID_PKCS8SHROUDEDKEYBAG) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (input->value.key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    int32_t ret = HITLS_PKCS12_BagRefUp(input);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    p12->key = input;
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
    if (input->id != BSL_CID_CERTBAG) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (input->value.cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    int32_t ret = HITLS_PKCS12_BagRefUp(input);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    p12->entityCert = input;
    return HITLS_PKI_SUCCESS;
}

static int32_t PKCS12_AddUnitBag(HITLS_PKCS12 *p12, void *val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    int32_t ret;
    HITLS_PKCS12_Bag *input = (HITLS_PKCS12_Bag *)val;
    BSL_ASN1_List *bagList = NULL;
    switch (input->id) {
        case BSL_CID_SECRETBAG:
            bagList = p12->secretBags;
            break;
        case BSL_CID_KEYBAG:
            bagList = p12->keyList;
            if (input->value.key == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
                return HITLS_PKCS12_ERR_INVALID_PARAM;
            }
            break;
        case BSL_CID_CERTBAG:
            if (input->value.cert == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
                return HITLS_PKCS12_ERR_INVALID_PARAM;
            }
            bagList = p12->certList;
            break;
        case BSL_CID_CRLBAG:
            if (input->value.crl == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
                return HITLS_PKCS12_ERR_INVALID_PARAM;
            }
            bagList = p12->crlList;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
            return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    ret = HITLS_PKCS12_BagRefUp(input);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_LIST_AddElement(bagList, input, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        HITLS_PKCS12_BagFree(input);
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

static int32_t PKCS12_GetEntityCert(HITLS_PKCS12 *p12, int32_t cmd, void **val)
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
    if (cmd == HITLS_PKCS12_GET_ENTITY_CERT) {
        int ref;
        int32_t ret = HITLS_X509_CertCtrl(p12->entityCert->value.cert, HITLS_X509_REF_UP, &ref, sizeof(int));
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        *val = p12->entityCert->value.cert;
    } else if (cmd == HITLS_PKCS12_GET_ENTITY_CERTBAG) {
        int32_t ret = HITLS_PKCS12_BagRefUp(p12->entityCert);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        *val = p12->entityCert;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t PKCS12_GetEntityKey(HITLS_PKCS12 *p12, int32_t cmd, void **val)
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
    if (cmd == HITLS_PKCS12_GET_ENTITY_KEY) {
        int32_t ret = CRYPT_EAL_PkeyUpRef(p12->key->value.key);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        *val = p12->key->value.key;
    } else if (cmd == HITLS_PKCS12_GET_ENTITY_KEYBAG) {
        int32_t ret = HITLS_PKCS12_BagRefUp(p12->key);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        *val = p12->key;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t PKCS12_GetKeyBags(HITLS_PKCS12 *p12, void **val)
{
    if (p12->keyList == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (val == NULL || *val != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    *val = p12->keyList;
    return HITLS_PKI_SUCCESS;
}

static int32_t PKCS12_GetSecretBags(HITLS_PKCS12 *p12, void **val)
{
    if (p12->secretBags == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (val == NULL || *val != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    *val = p12->secretBags;
    return HITLS_PKI_SUCCESS;
}

static int32_t PKCS12_GetCertBags(HITLS_PKCS12 *p12, void **val)
{
    if (p12->certList == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (val == NULL || *val != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    *val = p12->certList;
    return HITLS_PKI_SUCCESS;
}

static int32_t PKCS12_GetCrlBags(HITLS_PKCS12 *p12, void **val)
{
    if (p12->crlList == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (val == NULL || *val != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    *val = p12->crlList;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_PKCS12_Ctrl(HITLS_PKCS12 *p12, int32_t cmd, void *val, uint32_t valType)
{
#ifndef HITLS_PKI_PKCS12_GEN
    (void)valType;
#endif
    if (p12 == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    switch (cmd) {
#ifdef HITLS_PKI_PKCS12_GEN
        case HITLS_PKCS12_GEN_LOCALKEYID:
            return PKCS12_SetLocalKeyId(p12, val, valType);
        case HITLS_PKCS12_SET_ENTITY_KEYBAG:
            return PKCS12_SetEntityKey(p12, val);
        case HITLS_PKCS12_SET_ENTITY_CERTBAG:
            return PKCS12_SetEntityCert(p12, val);
        case HITLS_PKCS12_ADD_CERTBAG:
        case HITLS_PKCS12_ADD_CRLBAG:
        case HITLS_PKCS12_ADD_SECRETBAG:
        case HITLS_PKCS12_ADD_KEYBAG:
            return PKCS12_AddUnitBag(p12, val);
#endif
        case HITLS_PKCS12_GET_ENTITY_CERT:
        case HITLS_PKCS12_GET_ENTITY_CERTBAG:
            return PKCS12_GetEntityCert(p12, cmd, val);
        case HITLS_PKCS12_GET_ENTITY_KEY:
        case HITLS_PKCS12_GET_ENTITY_KEYBAG:
            return PKCS12_GetEntityKey(p12, cmd, val);
        case HITLS_PKCS12_GET_CERTBAGS:
            return PKCS12_GetCertBags(p12, val);
        case HITLS_PKCS12_GET_CRLBAGS:
            return PKCS12_GetCrlBags(p12, val);
        case HITLS_PKCS12_GET_SECRETBAGS:
            return PKCS12_GetSecretBags(p12, val);
        case HITLS_PKCS12_GET_KEYBAGS:
            return PKCS12_GetKeyBags(p12, val);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
            return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
}
#endif // HITLS_PKI_PKCS12
