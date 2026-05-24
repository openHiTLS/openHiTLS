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
#ifdef HITLS_PKI_CMS_AUTHENTICATEDDATA
#include <string.h>
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "bsl_asn1_internal.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_obj_internal.h"
#include "bsl_params.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_codecskey.h"
#include "crypt_params_key.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_params.h"
#include "hitls_pki_x509.h"
#include "hitls_cms_local.h"

/**
 * AuthenticatedData ::= SEQUENCE {
 *      version CMSVersion,
 *      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *      recipientInfos RecipientInfos,
 *      macAlgorithm MessageAuthenticationCodeAlgorithm,
 *      digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
 *      encapContentInfo EncapsulatedContentInfo,
 *      authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
 *      mac MessageAuthenticationCode,
 *      unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
 */
static BSL_ASN1_TemplateItem g_authDataTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_INTEGER, 0, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_TAG_OCTETSTRING, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 3,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
};

typedef enum {
    HITLS_CMS_AUTHDATA_VERSION_IDX = 0,
    HITLS_CMS_AUTHDATA_ORIGINATORINFO_IDX = 1,
    HITLS_CMS_AUTHDATA_RECIPIENTINFOS_IDX = 2,
    HITLS_CMS_AUTHDATA_MACALG_IDX = 3,
    HITLS_CMS_AUTHDATA_DIGESTALG_IDX = 4,
    HITLS_CMS_AUTHDATA_ENCAPCONTENT_IDX = 5,
    HITLS_CMS_AUTHDATA_AUTHATTRS_IDX = 6,
    HITLS_CMS_AUTHDATA_MAC_IDX = 7,
    HITLS_CMS_AUTHDATA_UNAUTHATTRS_IDX = 8,
    HITLS_CMS_AUTHDATA_MAX_IDX = 9,
} HITLS_CMS_AUTHDATA_IDX;

static BSL_ASN1_TemplateItem g_encapContInfoTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, BSL_ASN1_FLAG_OPTIONAL, 0},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1},
};

static BSL_ASN1_TemplateItem g_encapContInfoWithContentTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, 0, 0},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1},
};

typedef enum {
    HITLS_CMS_ECI_CONTENT_TYPE_IDX = 0,
    HITLS_CMS_ECI_ECONTENT_BUFF_IDX = 1,
    HITLS_CMS_ECI_MAX_IDX = 2,
} HITLS_CMS_ECI_IDX;

static BSL_ASN1_TemplateItem g_algIdTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
};

typedef enum {
    HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX = 0,
    HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX = 1,
    HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX = 2,
} HITLS_CMS_ALGORITHM_IDENTIFIER_IDX;

#define HITLS_CMS_AUTHDATA_MAX_DIGEST_LEN 64

static bool HasAttrEntries(HITLS_X509_Attrs *attrs);
static int32_t CheckAuthDataStructFormat(CMS_AuthenticatedData *authData);
static int32_t CheckAuthDataFinalFormat(CMS_AuthenticatedData *authData);
static int32_t CheckAuthDataGenerateParams(CMS_AuthenticatedData *authData);

static uint8_t GetAlgIdDefaultParamTag(int32_t algId)
{
    /*
     * RFC 4231 Section 3.1:
     *   For id-hmacWithSHA224/256/384/512, the AlgorithmIdentifier
     *   parameters SHOULD be present and have type NULL.
     *
     * RFC 5754 Section 2:
     *   For CMS SHA-224/256/384/512 digest AlgorithmIdentifiers,
     *   implementations MUST generate absent parameters.
     */
    switch (algId) {
        case CRYPT_MAC_HMAC_SHA224:
        case CRYPT_MAC_HMAC_SHA256:
        case CRYPT_MAC_HMAC_SHA384:
        case CRYPT_MAC_HMAC_SHA512:
            return BSL_ASN1_TAG_NULL;
        case BSL_CID_SHA224:
        case BSL_CID_SHA256:
        case BSL_CID_SHA384:
        case BSL_CID_SHA512:
            return BSL_ASN1_TAG_ANY;
        default:
            return BSL_ASN1_TAG_ANY;
    }
}

static int32_t ParseAlgId(BSL_ASN1_Buffer *asn, int32_t *algId, BSL_Buffer *algParam)
{
    if (asn == NULL || algId == NULL || algParam == NULL || asn->buff == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    uint8_t *temp = asn->buff;
    uint32_t tempLen = asn->len;
    uint32_t oidLen = 0;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OBJECT_ID, &temp, &tempLen, &oidLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BslCid cid = BSL_OBJ_GetCidFromOidBuff(temp, oidLen);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
    *algId = cid;

    temp += oidLen;
    tempLen -= oidLen;
    if (tempLen == 0) {
        algParam->data = NULL;
        algParam->dataLen = 0;
        return HITLS_PKI_SUCCESS;
    }

    algParam->data = BSL_SAL_Dump(temp, tempLen);
    if (algParam->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    algParam->dataLen = tempLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseDigestAlg(BSL_ASN1_Buffer *asn, CMS_AlgId *algId)
{
    return ParseAlgId(asn, &algId->id, &algId->param);
}

static int32_t ParseMacAlg(BSL_ASN1_Buffer *asn, CMS_MacAlg *algId)
{
    return ParseAlgId(asn, &algId->id, &algId->param);
}

static int32_t ParseEncapContentInfo(BSL_ASN1_Buffer *encode, CMS_EncapContentInfo *encapCont, bool *detached)
{
    if (encode == NULL || encapCont == NULL || detached == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    uint8_t *temp = encode->buff;
    uint32_t tempLen = encode->len;
    BSL_ASN1_Buffer asn1[HITLS_CMS_ECI_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_encapContInfoTempl, sizeof(g_encapContInfoTempl) / sizeof(g_encapContInfoTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_CMS_ECI_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BslCid cid = BSL_OBJ_GetCidFromOidBuff(asn1[HITLS_CMS_ECI_CONTENT_TYPE_IDX].buff,
        asn1[HITLS_CMS_ECI_CONTENT_TYPE_IDX].len);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
    encapCont->contentType = cid;
    encapCont->content.data = asn1[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].buff;
    encapCont->content.dataLen = asn1[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].len;
    if (asn1[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].tag != BSL_ASN1_TAG_EMPTY) {
        *detached = false;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseAuthDataAttrs(BSL_ASN1_Buffer *asn, HITLS_X509_Attrs **attrs)
{
    if (asn == NULL || attrs == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (asn->tag == BSL_ASN1_TAG_EMPTY) {
        return HITLS_PKI_SUCCESS;
    }

    *attrs = HITLS_X509_AttrsNew();
    if (*attrs == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    return HITLS_X509_ParseAttrList(asn, *attrs, NULL, NULL);
}

static int32_t ParseAuthDataOriginatorInfo(CMS_AuthenticatedData *authData, BSL_ASN1_Buffer *asn)
{
    if (asn->tag == BSL_ASN1_TAG_EMPTY) {
        return HITLS_PKI_SUCCESS;
    }

    authData->originatorInfo = BSL_SAL_Calloc(1, sizeof(CMS_OriginatorInfo));
    if (authData->originatorInfo == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    return CMS_ParseOriginatorInfo(asn, authData->originatorInfo);
}

static int32_t ParseAuthDataRecipientInfos(CMS_AuthenticatedData *authData, BSL_ASN1_Buffer *asn)
{
    int32_t ret = CMS_ParseRecipientList(asn, authData->recipientInfos);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseAuthDataDigestAlg(CMS_AuthenticatedData *authData, BSL_ASN1_Buffer *asn)
{
    if (asn->tag == BSL_ASN1_TAG_EMPTY) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t ret = ParseDigestAlg(asn, &authData->digestAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    authData->hasDigestAlg = true;
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseAuthDataContentAndAttrs(CMS_AuthenticatedData *authData, BSL_ASN1_Buffer *asn1)
{
    int32_t ret = ParseEncapContentInfo(&asn1[HITLS_CMS_AUTHDATA_ENCAPCONTENT_IDX], &authData->encapCont,
        &authData->detached);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ParseAuthDataAttrs(&asn1[HITLS_CMS_AUTHDATA_AUTHATTRS_IDX], &authData->authAttrs);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    authData->mac.data = asn1[HITLS_CMS_AUTHDATA_MAC_IDX].buff;
    authData->mac.dataLen = asn1[HITLS_CMS_AUTHDATA_MAC_IDX].len;
    return ParseAuthDataAttrs(&asn1[HITLS_CMS_AUTHDATA_UNAUTHATTRS_IDX], &authData->unauthAttrs);
}

static int32_t ParseAuthDataFields(CMS_AuthenticatedData *authData, BSL_ASN1_Buffer *asn1)
{
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(&asn1[HITLS_CMS_AUTHDATA_VERSION_IDX], &authData->version);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = ParseAuthDataOriginatorInfo(authData, &asn1[HITLS_CMS_AUTHDATA_ORIGINATORINFO_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = ParseAuthDataRecipientInfos(authData, &asn1[HITLS_CMS_AUTHDATA_RECIPIENTINFOS_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = ParseMacAlg(&asn1[HITLS_CMS_AUTHDATA_MACALG_IDX], &authData->macAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = ParseAuthDataDigestAlg(authData, &asn1[HITLS_CMS_AUTHDATA_DIGESTALG_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = ParseAuthDataContentAndAttrs(authData, asn1);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = CheckAuthDataFinalFormat(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    authData->flag |= HITLS_CMS_FLAG_PARSE;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_CMS_ParseAuthenticatedData(HITLS_PKI_LibCtx *libCtx, const char *attrName, const BSL_Buffer *encode,
    HITLS_CMS **cms)
{
    if (encode == NULL || encode->data == NULL || cms == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (encode->dataLen == 0 || *cms != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }

    HITLS_CMS *ctx = HITLS_CMS_ProviderNew(libCtx, attrName, BSL_CID_PKCS7_AUTHENTICATEDDATA);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ctx->ctx.authenticatedData->flag |= HITLS_CMS_FLAG_PARSE;
    ctx->ctx.authenticatedData->initData = BSL_SAL_Dump(encode->data, encode->dataLen);
    if (ctx->ctx.authenticatedData->initData == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        HITLS_CMS_Free(ctx);
        return BSL_DUMP_FAIL;
    }

    uint8_t *temp = ctx->ctx.authenticatedData->initData;
    uint32_t tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_CMS_AUTHDATA_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_authDataTempl, sizeof(g_authDataTempl) / sizeof(g_authDataTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_CMS_AUTHDATA_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_CMS_Free(ctx);
        return ret;
    }

    ret = ParseAuthDataFields(ctx->ctx.authenticatedData, asn1);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_CMS_Free(ctx);
        return ret;
    }
    *cms = ctx;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeAlgId(int32_t algId, const BSL_Buffer *param, BSL_ASN1_Buffer *encode)
{
    if (encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    BslOidString *oidStr = BSL_OBJ_GetOID((BslCid)algId);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }

    BSL_ASN1_Buffer items[HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX] = {
        {
            .tag = BSL_ASN1_TAG_OBJECT_ID,
            .buff = (uint8_t *)oidStr->octs,
            .len = oidStr->octetLen,
        },
        {0},
    };
    items[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].tag = GetAlgIdDefaultParamTag(algId);
    items[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].buff = param->data;
    items[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].len = param->dataLen;

    BSL_ASN1_Template templ = {g_algIdTempl, sizeof(g_algIdTempl) / sizeof(g_algIdTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, items, HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX,
        &encode->buff, &encode->len);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encode->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeDigestAlg(CMS_AlgId *algId, BSL_ASN1_Buffer *encode)
{
    return EncodeAlgId(algId->id, &algId->param, encode);
}

static int32_t EncodeMacAlg(CMS_MacAlg *algId, BSL_ASN1_Buffer *encode)
{
    return EncodeAlgId(algId->id, &algId->param, encode);
}

static int32_t EncodeEncapContentInfo(CMS_EncapContentInfo *encapCont, bool detached, BSL_ASN1_Buffer *encode)
{
    if (encapCont == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    BSL_ASN1_Buffer items[HITLS_CMS_ECI_MAX_IDX] = {0};
    BslOidString *oidStr = BSL_OBJ_GetOID(encapCont->contentType);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    items[HITLS_CMS_ECI_CONTENT_TYPE_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
    items[HITLS_CMS_ECI_CONTENT_TYPE_IDX].buff = (uint8_t *)oidStr->octs;
    items[HITLS_CMS_ECI_CONTENT_TYPE_IDX].len = oidStr->octetLen;

    if (detached) {
        items[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].tag = BSL_ASN1_TAG_EMPTY;
    } else {
        items[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
        items[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].buff = encapCont->content.data;
        items[HITLS_CMS_ECI_ECONTENT_BUFF_IDX].len = encapCont->content.dataLen;
    }

    BSL_ASN1_Template templ = {g_encapContInfoTempl, sizeof(g_encapContInfoTempl) / sizeof(g_encapContInfoTempl[0])};
    if (!detached) {
        templ.templItems = g_encapContInfoWithContentTempl;
        templ.templNum = sizeof(g_encapContInfoWithContentTempl) / sizeof(g_encapContInfoWithContentTempl[0]);
    }
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, items, HITLS_CMS_ECI_MAX_IDX, &encode->buff, &encode->len);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encode->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

static bool HasAttrEntries(HITLS_X509_Attrs *attrs)
{
    return (attrs != NULL && attrs->list != NULL && BSL_LIST_COUNT(attrs->list) > 0);
}

static int32_t EncodeOptionalAttrs(HITLS_X509_Attrs *attrs, uint8_t tag, BSL_ASN1_Buffer *asn)
{
    if (asn == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    asn->tag = BSL_ASN1_TAG_EMPTY;
    if (!HasAttrEntries(attrs)) {
        return HITLS_PKI_SUCCESS;
    }
    return HITLS_X509_EncodeAttrList(tag, attrs, NULL, asn);
}

static int32_t EncodeAuthAttrsMacInput(HITLS_X509_Attrs *attrs, BSL_Buffer *macInput)
{
    if (macInput == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    macInput->data = NULL;
    macInput->dataLen = 0;
    if (!HasAttrEntries(attrs)) {
        return HITLS_PKI_SUCCESS;
    }

    BSL_ASN1_Buffer attrSet = {0};
    int32_t ret = HITLS_X509_EncodeAttrList(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, attrs, NULL, &attrSet);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_ASN1_TemplateItem setTemplItem = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, 0, 0};
    BSL_ASN1_Template setTempl = {&setTemplItem, 1};
    BSL_ASN1_Buffer setAsn = {
        .tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        .buff = attrSet.buff,
        .len = attrSet.len,
    };
    ret = BSL_ASN1_EncodeTemplate(&setTempl, &setAsn, 1, &macInput->data, &macInput->dataLen);
    BSL_SAL_FREE(attrSet.buff);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t PrepareOriginatorInfo(CMS_AuthenticatedData *authData, BSL_ASN1_Buffer *originatorInfo)
{
    if (originatorInfo == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    originatorInfo->tag = BSL_ASN1_TAG_EMPTY;
    if (authData->originatorInfo == NULL || CMS_OriginatorInfoIsEmpty(authData->originatorInfo)) {
        return HITLS_PKI_SUCCESS;
    }
    originatorInfo->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0;
    return CMS_EncodeOriginatorInfo(authData->originatorInfo, originatorInfo);
}

static void CleanupAuthDataAsn1Buffers(BSL_ASN1_Buffer *asnArr, BSL_Buffer *authAttrsInput)
{
    BSL_SAL_FREE(asnArr[HITLS_CMS_AUTHDATA_VERSION_IDX].buff);
    BSL_SAL_FREE(asnArr[HITLS_CMS_AUTHDATA_ORIGINATORINFO_IDX].buff);
    BSL_SAL_FREE(asnArr[HITLS_CMS_AUTHDATA_RECIPIENTINFOS_IDX].buff);
    BSL_SAL_FREE(asnArr[HITLS_CMS_AUTHDATA_MACALG_IDX].buff);
    BSL_SAL_FREE(asnArr[HITLS_CMS_AUTHDATA_DIGESTALG_IDX].buff);
    BSL_SAL_FREE(asnArr[HITLS_CMS_AUTHDATA_ENCAPCONTENT_IDX].buff);
    BSL_SAL_FREE(asnArr[HITLS_CMS_AUTHDATA_AUTHATTRS_IDX].buff);
    BSL_SAL_FREE(asnArr[HITLS_CMS_AUTHDATA_UNAUTHATTRS_IDX].buff);
    BSL_SAL_FREE(authAttrsInput->data);
}

static int32_t EncodeAuthDataBaseFields(CMS_AuthenticatedData *authData, BSL_ASN1_Buffer *asnArr)
{
    int32_t ret = CMS_GetAuthenticatedDataVersion(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, (uint64_t)authData->version,
        &asnArr[HITLS_CMS_AUTHDATA_VERSION_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = PrepareOriginatorInfo(authData, &asnArr[HITLS_CMS_AUTHDATA_ORIGINATORINFO_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CMS_EncodeRecipientList(authData->recipientInfos, &asnArr[HITLS_CMS_AUTHDATA_RECIPIENTINFOS_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = EncodeMacAlg(&authData->macAlg, &asnArr[HITLS_CMS_AUTHDATA_MACALG_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    asnArr[HITLS_CMS_AUTHDATA_DIGESTALG_IDX].tag = BSL_ASN1_TAG_EMPTY;
    if (authData->hasDigestAlg) {
        ret = EncodeDigestAlg(&authData->digestAlg, &asnArr[HITLS_CMS_AUTHDATA_DIGESTALG_IDX]);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        asnArr[HITLS_CMS_AUTHDATA_DIGESTALG_IDX].tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1;
    }
    return EncodeEncapContentInfo(&authData->encapCont, authData->detached,
        &asnArr[HITLS_CMS_AUTHDATA_ENCAPCONTENT_IDX]);
}

static int32_t EncodeAuthDataAttrsAndMac(CMS_AuthenticatedData *authData, BSL_ASN1_Buffer *asnArr,
    BSL_Buffer *authAttrsInput)
{
    int32_t ret = EncodeOptionalAttrs(authData->authAttrs, BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2,
        &asnArr[HITLS_CMS_AUTHDATA_AUTHATTRS_IDX]);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (HasAttrEntries(authData->authAttrs)) {
        ret = EncodeAuthAttrsMacInput(authData->authAttrs, authAttrsInput);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    asnArr[HITLS_CMS_AUTHDATA_MAC_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
    asnArr[HITLS_CMS_AUTHDATA_MAC_IDX].buff = authData->mac.data;
    asnArr[HITLS_CMS_AUTHDATA_MAC_IDX].len = authData->mac.dataLen;
    return EncodeOptionalAttrs(authData->unauthAttrs, BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 3,
        &asnArr[HITLS_CMS_AUTHDATA_UNAUTHATTRS_IDX]);
}

static int32_t CMS_GenAuthDataBuffAsn1(CMS_AuthenticatedData *authData, BSL_Buffer *encode)
{
    if (authData == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if ((authData->flag & HITLS_CMS_FLAG_GEN) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    int32_t ret = CheckAuthDataStructFormat(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    BSL_ASN1_Buffer asnArr[HITLS_CMS_AUTHDATA_MAX_IDX] = {0};
    BSL_Buffer authAttrsInput = {0};
    ret = EncodeAuthDataBaseFields(authData, asnArr);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = EncodeAuthDataAttrsAndMac(authData, asnArr, &authAttrsInput);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    BSL_ASN1_Template templ = {g_authDataTempl, sizeof(g_authDataTempl) / sizeof(g_authDataTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, HITLS_CMS_AUTHDATA_MAX_IDX, &encode->data, &encode->dataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

ERR:
    CleanupAuthDataAsn1Buffers(asnArr, &authAttrsInput);
    return ret;
}

static int32_t CheckConfigureState(CMS_AuthenticatedData *authData)
{
    if (authData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if ((authData->flag & HITLS_CMS_FLAG_PARSE) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if ((authData->flag & HITLS_CMS_FLAG_GEN) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    if (authData->state != HITLS_CMS_UNINIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t SetMacAlg(CMS_AuthenticatedData *authData, void *val)
{
    int32_t ret = CheckConfigureState(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    int32_t macAlg = *(int32_t *)val;
    if (BSL_OBJ_GetOID((BslCid)macAlg) == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BSL_SAL_FREE(authData->macAlg.param.data);
    authData->macAlg.param.data = NULL;
    authData->macAlg.param.dataLen = 0;
    authData->macAlg.id = macAlg;
    return HITLS_PKI_SUCCESS;
}

static int32_t SetDigestAlg(CMS_AuthenticatedData *authData, void *val)
{
    int32_t ret = CheckConfigureState(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if ((authData->flag & HITLS_CMS_FLAG_NO_AUTHATTR) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }

    int32_t digestAlg = *(int32_t *)val;
    if (BSL_OBJ_GetOID((BslCid)digestAlg) == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BSL_SAL_FREE(authData->digestAlg.param.data);
    authData->digestAlg.param.data = NULL;
    authData->digestAlg.param.dataLen = 0;
    authData->digestAlg.id = digestAlg;
    authData->hasDigestAlg = true;
    return HITLS_PKI_SUCCESS;
}

static int32_t SetContentType(CMS_AuthenticatedData *authData, void *val)
{
    int32_t ret = CheckConfigureState(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    BslCid contentType = *(BslCid *)val;
    if (BSL_OBJ_GetOID(contentType) == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    if (contentType != BSL_CID_PKCS7_SIMPLEDATA && (authData->flag & HITLS_CMS_FLAG_NO_AUTHATTR) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    authData->encapCont.contentType = contentType;
    return HITLS_PKI_SUCCESS;
}

static int32_t SetDetached(CMS_AuthenticatedData *authData, bool detached)
{
    int32_t ret = CheckConfigureState(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    authData->detached = detached;
    return HITLS_PKI_SUCCESS;
}

static int32_t SetNoAuthAttrs(CMS_AuthenticatedData *authData, bool noAuthAttrs)
{
    int32_t ret = CheckConfigureState(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (!noAuthAttrs) {
        authData->flag &= ~HITLS_CMS_FLAG_NO_AUTHATTR;
        return HITLS_PKI_SUCCESS;
    }
    if (HasAttrEntries(authData->authAttrs) || authData->hasDigestAlg ||
        authData->encapCont.contentType != BSL_CID_PKCS7_SIMPLEDATA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    authData->flag |= HITLS_CMS_FLAG_NO_AUTHATTR;
    return HITLS_PKI_SUCCESS;
}

typedef int32_t (*CMS_AuthDataBoolSetter)(CMS_AuthenticatedData *authData, bool value);

static int32_t ApplyAuthDataBoolParam(CMS_AuthenticatedData *authData, const BSL_Param *params, int32_t paramId,
    CMS_AuthDataBoolSetter setter)
{
    const BSL_Param *p = BSL_PARAM_FindConstParam(params, paramId);
    if (p == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    if (p->valueType != BSL_PARAM_TYPE_BOOL || p->valueLen != sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    return setter(authData, *(bool *)p->value);
}

static int32_t ApplyAuthDataIntParam(CMS_AuthenticatedData *authData, const BSL_Param *params, int32_t paramId,
    int32_t (*setter)(CMS_AuthenticatedData *authData, void *val))
{
    const BSL_Param *p = BSL_PARAM_FindConstParam(params, paramId);
    if (p == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    if (p->valueType != BSL_PARAM_TYPE_INT32 || p->valueLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    return setter(authData, p->value);
}

int32_t ApplyAuthDataParams(HITLS_CMS *cms, const BSL_Param *params)
{
    if (cms == NULL || cms->ctx.authenticatedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (params == NULL) {
        return HITLS_PKI_SUCCESS;
    }

    CMS_AuthenticatedData *authData = cms->ctx.authenticatedData;
    int32_t ret = ApplyAuthDataBoolParam(authData, params, HITLS_CMS_PARAM_NO_AUTH_ATTRS, SetNoAuthAttrs);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ApplyAuthDataBoolParam(authData, params, HITLS_CMS_PARAM_DETACHED, SetDetached);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ApplyAuthDataIntParam(authData, params, HITLS_CMS_PARAM_CONTENT_TYPE, SetContentType);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ApplyAuthDataIntParam(authData, params, HITLS_CMS_PARAM_MAC_ALG, SetMacAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ApplyAuthDataIntParam(authData, params, HITLS_CMS_PARAM_DIGEST, SetDigestAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_CMS_GenAuthenticatedDataBuff(int32_t format, HITLS_CMS *cms, BSL_Buffer *encode)
{
    if (cms == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return CMS_GenAuthDataBuffAsn1(cms->ctx.authenticatedData, encode);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
            return HITLS_CMS_ERR_INVALID_FORMAT;
    }
}

static int32_t AuthData_GenerateInit(HITLS_CMS *cms, const BSL_Param *param);

static int32_t AuthData_VerifyInit(HITLS_CMS *cms, const BSL_Param *param);

static void CleanupAuthDataStream(CMS_AuthenticatedData *authData);

static int32_t PerformAuthDataVerify(CMS_AuthenticatedData *authData, const BSL_Buffer *msg, BSL_Buffer *macKey,
    BSL_Buffer *output);

static int32_t ComputeAuthDataMac(CMS_AuthenticatedData *authData, const BSL_Buffer *msg);

static int32_t SetAuthenticatedContent(CMS_AuthenticatedData *authData, const BSL_Buffer *msg);

static int32_t FinalizeDetachedAuthDataMac(CMS_AuthenticatedData *authData);

static int32_t PrepareAuthAttrsWithDigest(CMS_AuthenticatedData *authData, const uint8_t *digest,
    uint32_t digestLen, BSL_Buffer *macInput);

static int32_t VerifyAuthAttrsWithDigest(CMS_AuthenticatedData *authData, const uint8_t *digest, uint32_t digestLen,
    BSL_Buffer *macInput);

static int32_t GetDigestValue(CRYPT_EAL_MdCtx *mdCtx, uint8_t *digest, uint32_t *digestLen);

static int32_t GetStreamMacValue(CRYPT_EAL_MacCtx *macCtx, BSL_Buffer *mac);

static int32_t InitStreamDigestCtx(CMS_AuthenticatedData *authData);

static int32_t InitStreamMacCtx(CMS_AuthenticatedData *authData);

int32_t HITLS_CMS_AuthenticatedDataInit(HITLS_CMS *cms, int32_t option, const BSL_Param *param)
{
    if (option == HITLS_CMS_OPT_AUTH) {
        return AuthData_GenerateInit(cms, param);
    }
    if (option == HITLS_CMS_OPT_AUTH_VERIFY) {
        return AuthData_VerifyInit(cms, param);
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
    return HITLS_CMS_ERR_INVALID_STATE;
}

static int32_t AuthData_GenerateUpdate(CMS_AuthenticatedData *authData, const BSL_Buffer *input)
{
    if ((authData->flag & HITLS_CMS_FLAG_NO_AUTHATTR) != 0) {
        if (authData->macAlg.macCtx == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_CTX_IS_NOT_INIT);
            return HITLS_CMS_ERR_CTX_IS_NOT_INIT;
        }
        int32_t ret = CRYPT_EAL_MacUpdate(authData->macAlg.macCtx, input->data, input->dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        return HITLS_PKI_SUCCESS;
    }
    if (authData->digestAlg.mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_CTX_IS_NOT_INIT);
        return HITLS_CMS_ERR_CTX_IS_NOT_INIT;
    }
    int32_t ret = CRYPT_EAL_MdUpdate(authData->digestAlg.mdCtx, input->data, input->dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t AuthData_VerifyUpdate(CMS_AuthenticatedData *authData, const BSL_Buffer *input)
{
    if (authData->authAttrs == NULL) {
        if (authData->macAlg.macCtx == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_CTX_IS_NOT_INIT);
            return HITLS_CMS_ERR_CTX_IS_NOT_INIT;
        }
        int32_t ret = CRYPT_EAL_MacUpdate(authData->macAlg.macCtx, input->data, input->dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        return HITLS_PKI_SUCCESS;
    }
    if (authData->digestAlg.mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_CTX_IS_NOT_INIT);
        return HITLS_CMS_ERR_CTX_IS_NOT_INIT;
    }
    int32_t ret = CRYPT_EAL_MdUpdate(authData->digestAlg.mdCtx, input->data, input->dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_CMS_AuthenticatedDataUpdate(HITLS_CMS *cms, const BSL_Buffer *input)
{
    if (cms == NULL || input == NULL || cms->ctx.authenticatedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (cms->dataType != BSL_CID_PKCS7_AUTHENTICATEDDATA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }

    CMS_AuthenticatedData *authData = cms->ctx.authenticatedData;
    if (!authData->detached) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ATTACHED_STREAM_UNSUPPORTED);
        return HITLS_CMS_ERR_ATTACHED_STREAM_UNSUPPORTED;
    }
    if (input->data == NULL && input->dataLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (authData->state == HITLS_CMS_AUTH_INIT) {
        return AuthData_GenerateUpdate(authData, input);
    } else if (authData->state == HITLS_CMS_AUTH_VERIFY_INIT) {
        return AuthData_VerifyUpdate(authData, input);
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
    return HITLS_CMS_ERR_INVALID_STATE;
}

static void ClearAuthDataKey(CMS_AuthenticatedData *authData)
{
    if (authData == NULL) {
        return;
    }
    BSL_SAL_ClearFree(authData->macKey.data, authData->macKey.dataLen);
    authData->macKey.data = NULL;
    authData->macKey.dataLen = 0;
}

static int32_t AuthData_GenerateFinal(CMS_AuthenticatedData *authData, const BSL_Param *param)
{
    (void)param;
    if (authData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t ret = CMS_CheckRecipientsNotEmpty(authData->recipientInfos);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    BSL_Buffer empty = {0};
    ret = SetAuthenticatedContent(authData, &empty);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = FinalizeDetachedAuthDataMac(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CMS_GetAuthenticatedDataVersion(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CheckAuthDataFinalFormat(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    CleanupAuthDataStream(authData);
    ClearAuthDataKey(authData);
    authData->state = HITLS_CMS_AUTH_FINISHED;
    authData->flag |= HITLS_CMS_FLAG_GEN;
    return HITLS_PKI_SUCCESS;
}

static int32_t AuthData_VerifyFinal(CMS_AuthenticatedData *authData, const BSL_Param *param)
{
    (void)param;
    if (authData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t ret = PerformAuthDataVerify(authData, NULL, &authData->macKey, NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    CleanupAuthDataStream(authData);
    ClearAuthDataKey(authData);
    authData->state = HITLS_CMS_AUTH_VERIFY_FINISHED;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_CMS_AuthenticatedDataFinal(HITLS_CMS *cms, const BSL_Param *param)
{
    if (cms == NULL || cms->ctx.authenticatedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (cms->dataType != BSL_CID_PKCS7_AUTHENTICATEDDATA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    CMS_AuthenticatedData *authData = cms->ctx.authenticatedData;
    if (!authData->detached) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ATTACHED_STREAM_UNSUPPORTED);
        return HITLS_CMS_ERR_ATTACHED_STREAM_UNSUPPORTED;
    }
    if (authData->state == HITLS_CMS_AUTH_INIT) {
        return AuthData_GenerateFinal(authData, param);
    } else if (authData->state == HITLS_CMS_AUTH_VERIFY_INIT) {
        return AuthData_VerifyFinal(authData, param);
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
    return HITLS_CMS_ERR_INVALID_STATE;
}

int32_t HITLS_CMS_AuthenticatedDataCtrl(HITLS_CMS *cms, int32_t cmd, void *val, uint32_t valLen)
{
    (void)valLen;
    (void)val;
    if (cms == NULL || cms->ctx.authenticatedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    switch (cmd) {
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
    }
}

static int32_t GetHmacDigestAlg(int32_t macAlg, int32_t *digestAlg)
{
    if (digestAlg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    switch (macAlg) {
        case CRYPT_MAC_HMAC_MD5:
            *digestAlg = CRYPT_MD_MD5;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_HMAC_SHA1:
            *digestAlg = CRYPT_MD_SHA1;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_HMAC_SHA224:
            *digestAlg = CRYPT_MD_SHA224;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_HMAC_SHA256:
            *digestAlg = CRYPT_MD_SHA256;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_HMAC_SHA384:
            *digestAlg = CRYPT_MD_SHA384;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_HMAC_SHA512:
            *digestAlg = CRYPT_MD_SHA512;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_HMAC_SHA3_224:
            *digestAlg = CRYPT_MD_SHA3_224;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_HMAC_SHA3_256:
            *digestAlg = CRYPT_MD_SHA3_256;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_HMAC_SHA3_384:
            *digestAlg = CRYPT_MD_SHA3_384;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_HMAC_SHA3_512:
            *digestAlg = CRYPT_MD_SHA3_512;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_HMAC_SM3:
            *digestAlg = CRYPT_MD_SM3;
            return HITLS_PKI_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
            return HITLS_CMS_ERR_INVALID_ALGO;
    }
}

static int32_t GetDefaultMacKeyLen(int32_t macAlg, uint32_t *keyLen)
{
    if (keyLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    switch (macAlg) {
        case CRYPT_MAC_CMAC_AES128:
        case CRYPT_MAC_GMAC_AES128:
            *keyLen = 16;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_CMAC_AES192:
        case CRYPT_MAC_GMAC_AES192:
            *keyLen = 24;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_CMAC_AES256:
        case CRYPT_MAC_GMAC_AES256:
            *keyLen = 32;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_CMAC_SM4:
        case CRYPT_MAC_CBC_MAC_SM4:
            *keyLen = 16;
            return HITLS_PKI_SUCCESS;
        case CRYPT_MAC_SIPHASH64:
        case CRYPT_MAC_SIPHASH128:
            *keyLen = 16;
            return HITLS_PKI_SUCCESS;
        default: {
            int32_t digestAlg = BSL_CID_UNKNOWN;
            int32_t ret = GetHmacDigestAlg(macAlg, &digestAlg);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
            *keyLen = CRYPT_EAL_MdGetDigestSize((CRYPT_MD_AlgId)digestAlg);
            if (*keyLen == 0) {
                BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
                return HITLS_CMS_ERR_INVALID_ALGO;
            }
            return HITLS_PKI_SUCCESS;
        }
    }
}

static bool BufferDataEquals(const uint8_t *left, uint32_t leftLen, const uint8_t *right, uint32_t rightLen)
{
    if (leftLen != rightLen) {
        return false;
    }
    if (leftLen == 0) {
        return true;
    }
    if (left == NULL || right == NULL) {
        return false;
    }
    return ConstTimeMemcmp(left, right, leftLen) != 0;
}

static int32_t SetAuthenticatedContent(CMS_AuthenticatedData *authData, const BSL_Buffer *msg)
{
    if (authData == NULL || msg == NULL || (msg->data == NULL && msg->dataLen != 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    BSL_SAL_FREE(authData->encapCont.content.data);
    authData->encapCont.content.data = NULL;
    authData->encapCont.content.dataLen = 0;
    if (authData->detached) {
        return HITLS_PKI_SUCCESS;
    }
    if (msg->dataLen == 0) {
        return HITLS_PKI_SUCCESS;
    }

    authData->encapCont.content.data = BSL_SAL_Dump(msg->data, msg->dataLen);
    if (authData->encapCont.content.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    authData->encapCont.content.dataLen = msg->dataLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t EnsureMacKey(CMS_AuthenticatedData *authData)
{
    if (authData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (!CRYPT_EAL_MacIsValidAlgId((CRYPT_MAC_AlgId)authData->macAlg.id)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    if (authData->macKey.data != NULL && authData->macKey.dataLen > 0) {
        return HITLS_PKI_SUCCESS;
    }

    uint32_t keyLen = 0;
    int32_t ret = GetDefaultMacKeyLen(authData->macAlg.id, &keyLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    uint8_t *key = BSL_SAL_Malloc(keyLen);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ret = CRYPT_EAL_RandbytesEx(authData->libCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(key, keyLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    authData->macKey.data = key;
    authData->macKey.dataLen = keyLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t GenerateFallbackMacKey(CMS_AuthenticatedData *authData, BSL_Buffer *macKey)
{
    if (authData == NULL || macKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    uint32_t keyLen = 0;
    int32_t ret = GetDefaultMacKeyLen(authData->macAlg.id, &keyLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    uint8_t *key = BSL_SAL_Malloc(keyLen);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    ret = CRYPT_EAL_RandbytesEx(authData->libCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(key, keyLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    macKey->data = key;
    macKey->dataLen = keyLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t CreateContentTypeAttr(BslCid contentType, HITLS_X509_AttrEntry **outAttr)
{
    HITLS_X509_AttrEntry *ctAttr = (HITLS_X509_AttrEntry *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    if (ctAttr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ctAttr->cid = BSL_CID_PKCS9_AT_CONTENTTYPE;
    int32_t ret = HITLS_X509_EncodeObjIdentity(BSL_CID_PKCS9_AT_CONTENTTYPE, &ctAttr->attrId);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_AttrEntryFree(ctAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BslOidString *oidStr = BSL_OBJ_GetOID(contentType);
    if (oidStr == NULL) {
        HITLS_X509_AttrEntryFree(ctAttr);
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BSL_ASN1_Buffer oidBuf = {
        .tag = BSL_ASN1_TAG_OBJECT_ID,
        .buff = (uint8_t *)oidStr->octs,
        .len = oidStr->octetLen,
    };
    BSL_ASN1_TemplateItem oidTemplItem = {BSL_ASN1_TAG_OBJECT_ID, 0, 0};
    BSL_ASN1_Template oidTempl = {&oidTemplItem, 1};
    ret = BSL_ASN1_EncodeTemplate(&oidTempl, &oidBuf, 1, &ctAttr->attrValue.buff, &ctAttr->attrValue.len);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_AttrEntryFree(ctAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ctAttr->attrValue.tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
    *outAttr = ctAttr;
    return HITLS_PKI_SUCCESS;
}

static int32_t CreateMessageDigestAttr(const uint8_t *digest, uint32_t digestLen, HITLS_X509_AttrEntry **outAttr)
{
    if (digest == NULL || outAttr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    HITLS_X509_AttrEntry *mdAttr = (HITLS_X509_AttrEntry *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    if (mdAttr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    mdAttr->cid = BSL_CID_PKCS9_AT_MESSAGEDIGEST;
    int32_t ret = HITLS_X509_EncodeObjIdentity(BSL_CID_PKCS9_AT_MESSAGEDIGEST, &mdAttr->attrId);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_AttrEntryFree(mdAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_ASN1_Buffer digestBuf = {
        .tag = BSL_ASN1_TAG_OCTETSTRING,
        .buff = (uint8_t *)(uintptr_t)digest,
        .len = digestLen,
    };
    BSL_ASN1_TemplateItem octetTemplItem = {BSL_ASN1_TAG_OCTETSTRING, 0, 0};
    BSL_ASN1_Template octetTempl = {&octetTemplItem, 1};
    ret = BSL_ASN1_EncodeTemplate(&octetTempl, &digestBuf, 1, &mdAttr->attrValue.buff, &mdAttr->attrValue.len);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_AttrEntryFree(mdAttr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    mdAttr->attrValue.tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
    *outAttr = mdAttr;
    return HITLS_PKI_SUCCESS;
}

static int32_t AddRequiredAttr(HITLS_X509_Attrs *attrs, HITLS_X509_AttrEntry *attr)
{
    if (attrs == NULL || attr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t ret = BSL_LIST_AddElement(attrs->list, attr, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_AttrEntryFree(attr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t EnsureDigestAlg(CMS_AuthenticatedData *authData)
{
    if (authData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (authData->hasDigestAlg) {
        return HITLS_PKI_SUCCESS;
    }
    int32_t digestAlg = BSL_CID_UNKNOWN;
    int32_t ret = GetHmacDigestAlg(authData->macAlg.id, &digestAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    authData->digestAlg.id = digestAlg;
    authData->hasDigestAlg = true;
    return HITLS_PKI_SUCCESS;
}

static int32_t ComputeContentDigest(CMS_AuthenticatedData *authData, const BSL_Buffer *msg,
    uint8_t *digest, uint32_t *digestLen)
{
    if (authData == NULL || msg == NULL || digest == NULL || digestLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t ret = EnsureDigestAlg(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_ProviderMd(authData->libCtx, (CRYPT_MD_AlgId)authData->digestAlg.id, authData->attrName,
        msg->data, msg->dataLen, digest, digestLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

typedef int32_t (*CMS_AuthAttrDecoder)(HITLS_X509_AttrEntry *attr, void *out);

static int32_t AuthDataNewMacCtx(CMS_AuthenticatedData *authData, BSL_Buffer *macKey, CRYPT_EAL_MacCtx **macCtx)
{
    *macCtx = CRYPT_EAL_ProviderMacNewCtx(authData->libCtx, authData->macAlg.id, authData->attrName);
    if (*macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    int32_t ret = CRYPT_EAL_MacInit(*macCtx, macKey->data, macKey->dataLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(*macCtx);
        *macCtx = NULL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t AuthDataFinalizeMac(CRYPT_EAL_MacCtx *macCtx, BSL_Buffer *mac)
{
    uint32_t macLen = CRYPT_EAL_GetMacLen(macCtx);
    if (macLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }

    uint8_t *macValue = BSL_SAL_Malloc(macLen);
    if (macValue == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_MacFinal(macCtx, macValue, &macLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(macValue, macLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    mac->data = macValue;
    mac->dataLen = macLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t ComputeMacValue(CMS_AuthenticatedData *authData, BSL_Buffer *macKey,
    const uint8_t *input, uint32_t inputLen, BSL_Buffer *mac)
{
    if (authData == NULL || macKey == NULL || macKey->data == NULL || macKey->dataLen == 0 || mac == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (inputLen > 0 && input == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (!CRYPT_EAL_MacIsValidAlgId((CRYPT_MAC_AlgId)authData->macAlg.id)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    if (authData->macAlg.id == CRYPT_MAC_GMAC_AES128 || authData->macAlg.id == CRYPT_MAC_GMAC_AES192 ||
        authData->macAlg.id == CRYPT_MAC_GMAC_AES256 || authData->macAlg.id == CRYPT_MAC_CBC_MAC_SM4) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_UNSUPPORTED_TYPE);
        return HITLS_CMS_ERR_UNSUPPORTED_TYPE;
    }

    mac->data = NULL;
    mac->dataLen = 0;
    CRYPT_EAL_MacCtx *macCtx = NULL;
    int32_t ret = AuthDataNewMacCtx(authData, macKey, &macCtx);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (inputLen > 0) {
        ret = CRYPT_EAL_MacUpdate(macCtx, input, inputLen);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_MacFreeCtx(macCtx);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    ret = AuthDataFinalizeMac(macCtx, mac);
    CRYPT_EAL_MacFreeCtx(macCtx);
    return ret;
}

static int32_t DecodeMessageDigestAttr(HITLS_X509_AttrEntry *attr, void *out)
{
    if (attr == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    BSL_Buffer *buff = (BSL_Buffer *)out;
    buff->data = attr->attrValue.buff;
    buff->dataLen = attr->attrValue.len;
    uint32_t tempLen = attr->attrValue.len;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &buff->data, &tempLen, &buff->dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (buff->data == NULL || buff->dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t DecodeContentTypeAttr(HITLS_X509_AttrEntry *attr, void *out)
{
    if (attr == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    uint8_t *buff = attr->attrValue.buff;
    uint32_t buffLen = attr->attrValue.len;
    uint32_t tempLen = attr->attrValue.len;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OBJECT_ID, &buff, &tempLen, &buffLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(buff, buffLen);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    *(BslCid *)out = cid;
    return HITLS_PKI_SUCCESS;
}

static int32_t DecodeAuthAttr(HITLS_X509_Attrs *attrs, BslCid attrCid, CMS_AuthAttrDecoder attrDecode, void *out)
{
    if (attrs == NULL || attrs->list == NULL || attrDecode == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    for (HITLS_X509_AttrEntry *node = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(attrs->list);
        node != NULL; node = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(attrs->list)) {
        if (node->cid == attrCid) {
            return attrDecode(node, out);
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}

static int32_t CheckAuthDataAttrSet(HITLS_X509_Attrs *attrs)
{
    if (attrs == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    if (!HasAttrEntries(attrs)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
        return HITLS_CMS_ERR_INVALID_FORMAT;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckAuthDataStructFormat(CMS_AuthenticatedData *authData)
{
    if (authData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    int32_t ret = CheckAuthDataAttrSet(authData->authAttrs);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CheckAuthDataAttrSet(authData->unauthAttrs);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    bool hasAuthAttrs = HasAttrEntries(authData->authAttrs);
    if (hasAuthAttrs != authData->hasDigestAlg) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
        return HITLS_CMS_ERR_INVALID_FORMAT;
    }
    if (authData->encapCont.contentType != BSL_CID_PKCS7_SIMPLEDATA && !hasAuthAttrs) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
        return HITLS_CMS_ERR_INVALID_FORMAT;
    }
    if (!hasAuthAttrs) {
        return HITLS_PKI_SUCCESS;
    }

    BSL_Buffer targetDigest = {0};
    return DecodeAuthAttr(authData->authAttrs, BSL_CID_PKCS9_AT_MESSAGEDIGEST, DecodeMessageDigestAttr, &targetDigest);
}

static int32_t CheckAuthDataFinalFormat(CMS_AuthenticatedData *authData)
{
    int32_t ret = CheckAuthDataStructFormat(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (!HasAttrEntries(authData->authAttrs)) {
        return HITLS_PKI_SUCCESS;
    }

    BslCid contentType = BSL_CID_UNKNOWN;
    ret = DecodeAuthAttr(authData->authAttrs, BSL_CID_PKCS9_AT_CONTENTTYPE, DecodeContentTypeAttr, &contentType);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (contentType != (BslCid)authData->encapCont.contentType) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
        return HITLS_CMS_ERR_INVALID_FORMAT;
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t CheckAuthDataGenerateParams(CMS_AuthenticatedData *authData)
{
    if (authData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if ((authData->flag & HITLS_CMS_FLAG_NO_AUTHATTR) == 0) {
        return HITLS_PKI_SUCCESS;
    }
    if (authData->hasDigestAlg || HasAttrEntries(authData->authAttrs) ||
        authData->encapCont.contentType != BSL_CID_PKCS7_SIMPLEDATA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t GetVerifyContent(CMS_AuthenticatedData *authData, const BSL_Buffer *msg, BSL_Buffer *content)
{
    if (authData == NULL || content == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (authData->detached) {
        if (msg == NULL || (msg->data == NULL && msg->dataLen != 0)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
            return HITLS_CMS_ERR_INVALID_DATA;
        }
        *content = *msg;
        return HITLS_PKI_SUCCESS;
    }

    if (authData->encapCont.content.data == NULL && authData->encapCont.content.dataLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if (msg != NULL) {
        if (msg->dataLen != authData->encapCont.content.dataLen ||
            !BufferDataEquals(msg->data, msg->dataLen, authData->encapCont.content.data,
            authData->encapCont.content.dataLen)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERIFY_FAIL);
            return HITLS_CMS_ERR_VERIFY_FAIL;
        }
    }
    *content = authData->encapCont.content;
    return HITLS_PKI_SUCCESS;
}

static int32_t GetRecipientCertParam(const BSL_Param *param, const BSL_Param **certParam)
{
    if (certParam == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_RECIPIENT_CERT_REQUIRED);
        return HITLS_CMS_ERR_RECIPIENT_CERT_REQUIRED;
    }

    const BSL_Param *p = BSL_PARAM_FindConstParam(param, HITLS_CMS_PARAM_RECIPIENT_CERT);
    if (p == NULL || p->value == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_RECIPIENT_CERT_REQUIRED);
        return HITLS_CMS_ERR_RECIPIENT_CERT_REQUIRED;
    }
    if (p->valueType != BSL_PARAM_TYPE_CTX_PTR || p->valueLen != sizeof(HITLS_X509_Cert *)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    *certParam = p;
    return HITLS_PKI_SUCCESS;
}

static int32_t RecoverMacKey(CMS_AuthenticatedData *authData, CRYPT_EAL_PkeyCtx *decryptKey, const BSL_Param *param,
    BSL_Buffer *macKey)
{
    if (authData == NULL || decryptKey == NULL || macKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    const BSL_Param *certParam = NULL;
    int32_t ret = GetRecipientCertParam(param, &certParam);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    BSL_Param decryptParams[3] = {
        *certParam,
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, decryptKey, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        BSL_PARAM_END
    };
    ret = CMS_DecryptCekForRecipient(authData->recipientInfos, decryptParams, &macKey->data, &macKey->dataLen);
    if (ret == HITLS_CMS_ERR_RECIPIENT_KEY_DECRYPT_FAIL) {
        // Use a random fallback key so unwrap failures converge on the later MAC verification result.
        return GenerateFallbackMacKey(authData, macKey);
    }
    return ret;
}

static int32_t VerifyAuthAttrs(CMS_AuthenticatedData *authData, const BSL_Buffer *msg, BSL_Buffer *macInput)
{
    if (authData == NULL || msg == NULL || macInput == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (authData->authAttrs == NULL || !HasAttrEntries(authData->authAttrs)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if (!authData->hasDigestAlg) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
        return HITLS_CMS_ERR_INVALID_FORMAT;
    }

    BslCid contentType = BSL_CID_UNKNOWN;
    int32_t ret = DecodeAuthAttr(authData->authAttrs, BSL_CID_PKCS9_AT_CONTENTTYPE, DecodeContentTypeAttr,
        &contentType);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (contentType != (BslCid)authData->encapCont.contentType) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERIFY_FAIL);
        return HITLS_CMS_ERR_VERIFY_FAIL;
    }

    uint8_t digest[HITLS_CMS_AUTHDATA_MAX_DIGEST_LEN] = {0};
    uint32_t digestLen = sizeof(digest);
    ret = ComputeContentDigest(authData, msg, digest, &digestLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return VerifyAuthAttrsWithDigest(authData, digest, digestLen, macInput);
}

static int32_t VerifyAuthAttrsWithDigest(CMS_AuthenticatedData *authData, const uint8_t *digest, uint32_t digestLen,
    BSL_Buffer *macInput)
{
    if (authData == NULL || digest == NULL || macInput == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (authData->authAttrs == NULL || !HasAttrEntries(authData->authAttrs)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if (!authData->hasDigestAlg) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
        return HITLS_CMS_ERR_INVALID_FORMAT;
    }

    BslCid contentType = BSL_CID_UNKNOWN;
    int32_t ret = DecodeAuthAttr(authData->authAttrs, BSL_CID_PKCS9_AT_CONTENTTYPE, DecodeContentTypeAttr,
        &contentType);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (contentType != (BslCid)authData->encapCont.contentType) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERIFY_FAIL);
        return HITLS_CMS_ERR_VERIFY_FAIL;
    }

    BSL_Buffer targetDigest = {0};
    ret = DecodeAuthAttr(authData->authAttrs, BSL_CID_PKCS9_AT_MESSAGEDIGEST, DecodeMessageDigestAttr, &targetDigest);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (!BufferDataEquals(digest, digestLen, targetDigest.data, targetDigest.dataLen)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERIFY_FAIL);
        return HITLS_CMS_ERR_VERIFY_FAIL;
    }

    return EncodeAuthAttrsMacInput(authData->authAttrs, macInput);
}

static int32_t BuildVerifyMacInput(CMS_AuthenticatedData *authData, const BSL_Buffer *msg, BSL_Buffer *macInput)
{
    if (authData == NULL || msg == NULL || macInput == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    macInput->data = NULL;
    macInput->dataLen = 0;
    if (authData->authAttrs == NULL) {
        if (authData->hasDigestAlg) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
            return HITLS_CMS_ERR_INVALID_FORMAT;
        }
        return HITLS_PKI_SUCCESS;
    }
    return VerifyAuthAttrs(authData, msg, macInput);
}

static void CleanupAuthDataStream(CMS_AuthenticatedData *authData)
{
    if (authData == NULL) {
        return;
    }
    CRYPT_EAL_MacFreeCtx(authData->macAlg.macCtx);
    authData->macAlg.macCtx = NULL;
    CRYPT_EAL_MdFreeCtx(authData->digestAlg.mdCtx);
    authData->digestAlg.mdCtx = NULL;
}

static int32_t FinalizeDetachedAuthDataMac(CMS_AuthenticatedData *authData)
{
    BSL_Buffer mac = {0};
    int32_t ret;
    if ((authData->flag & HITLS_CMS_FLAG_NO_AUTHATTR) != 0) {
        ret = GetStreamMacValue(authData->macAlg.macCtx, &mac);
    } else {
        uint8_t digest[HITLS_CMS_AUTHDATA_MAX_DIGEST_LEN] = {0};
        uint32_t digestLen = sizeof(digest);
        ret = GetDigestValue(authData->digestAlg.mdCtx, digest, &digestLen);
        if (ret == HITLS_PKI_SUCCESS) {
            BSL_Buffer macInput = {0};
            ret = PrepareAuthAttrsWithDigest(authData, digest, digestLen, &macInput);
            if (ret == HITLS_PKI_SUCCESS) {
                ret = ComputeMacValue(authData, &authData->macKey, macInput.data, macInput.dataLen,
                    &mac);
            }
            BSL_SAL_FREE(macInput.data);
        }
    }
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if ((authData->flag & HITLS_CMS_FLAG_PARSE) == 0) {
        BSL_SAL_FREE(authData->mac.data);
    }
    authData->mac = mac;
    return HITLS_PKI_SUCCESS;
}

static int32_t FinalizeAuthDataGenerate(CMS_AuthenticatedData *authData, const BSL_Buffer *msg, const BSL_Param *param)
{
    (void)param;
    if (authData == NULL || msg == NULL || (msg->data == NULL && msg->dataLen != 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (authData->macAlg.id == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    int32_t ret = SetAuthenticatedContent(authData, msg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ComputeAuthDataMac(authData, msg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CMS_GetAuthenticatedDataVersion(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CheckAuthDataFinalFormat(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    authData->flag |= HITLS_CMS_FLAG_GEN;
    return HITLS_PKI_SUCCESS;
}

static int32_t VerifyDetachedAuthData(CMS_AuthenticatedData *authData, BSL_Buffer *macKey, BSL_Buffer *calcMac)
{
    if (authData->authAttrs == NULL) {
        if (authData->hasDigestAlg) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
            return HITLS_CMS_ERR_INVALID_FORMAT;
        }
        return GetStreamMacValue(authData->macAlg.macCtx, calcMac);
    }

    uint8_t digest[HITLS_CMS_AUTHDATA_MAX_DIGEST_LEN] = {0};
    uint32_t digestLen = sizeof(digest);
    int32_t ret = GetDigestValue(authData->digestAlg.mdCtx, digest, &digestLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    BSL_Buffer macInput = {0};
    ret = VerifyAuthAttrsWithDigest(authData, digest, digestLen, &macInput);
    if (ret == HITLS_PKI_SUCCESS) {
        ret = ComputeMacValue(authData, macKey, macInput.data, macInput.dataLen, calcMac);
    }
    BSL_SAL_FREE(macInput.data);
    return ret;
}

static int32_t VerifyAttachedAuthData(CMS_AuthenticatedData *authData, const BSL_Buffer *msg, BSL_Buffer *macKey,
    BSL_Buffer *calcMac, BSL_Buffer *output)
{
    BSL_Buffer content = {0};
    int32_t ret = GetVerifyContent(authData, msg, &content);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    BSL_Buffer macInput = {0};
    const uint8_t *input = content.data;
    uint32_t inputLen = content.dataLen;
    if (authData->authAttrs != NULL) {
        ret = BuildVerifyMacInput(authData, &content, &macInput);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        input = macInput.data;
        inputLen = macInput.dataLen;
    } else if (authData->hasDigestAlg) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
        return HITLS_CMS_ERR_INVALID_FORMAT;
    }

    ret = ComputeMacValue(authData, macKey, input, inputLen, calcMac);
    BSL_SAL_FREE(macInput.data);
    if (ret == HITLS_PKI_SUCCESS && output != NULL) {
        *output = content;
    }
    return ret;
}

static int32_t PerformAuthDataVerify(CMS_AuthenticatedData *authData, const BSL_Buffer *msg, BSL_Buffer *macKey,
    BSL_Buffer *output)
{
    if (authData == NULL || macKey == NULL || macKey->data == NULL || macKey->dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (authData->recipientInfos == NULL || BSL_LIST_COUNT(authData->recipientInfos) == 0 ||
        authData->mac.data == NULL || authData->mac.dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    int32_t ret = CheckAuthDataStructFormat(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    BSL_Buffer calcMac = {0};
    ret = HITLS_PKI_SUCCESS;
    if (authData->detached && msg == NULL && (authData->macAlg.macCtx != NULL || authData->digestAlg.mdCtx != NULL)) {
        ret = VerifyDetachedAuthData(authData, macKey, &calcMac);
    } else {
        ret = VerifyAttachedAuthData(authData, msg, macKey, &calcMac, output);
    }
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (!BufferDataEquals(calcMac.data, calcMac.dataLen, authData->mac.data, authData->mac.dataLen)) {
        BSL_SAL_ClearFree(calcMac.data, calcMac.dataLen);
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_VERIFY_FAIL);
        return HITLS_CMS_ERR_VERIFY_FAIL;
    }
    BSL_SAL_ClearFree(calcMac.data, calcMac.dataLen);
    return HITLS_PKI_SUCCESS;
}

static int32_t GetDigestValue(CRYPT_EAL_MdCtx *mdCtx, uint8_t *digest, uint32_t *digestLen)
{
    if (mdCtx == NULL || digest == NULL || digestLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CRYPT_EAL_MdCtx *tmp = CRYPT_EAL_MdDupCtx(mdCtx);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_MdFinal(tmp, digest, digestLen);
    CRYPT_EAL_MdFreeCtx(tmp);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t GetStreamMacValue(CRYPT_EAL_MacCtx *macCtx, BSL_Buffer *mac)
{
    if (macCtx == NULL || mac == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    CRYPT_EAL_MacCtx *tmp = CRYPT_EAL_MacDupCtx(macCtx);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t macLen = CRYPT_EAL_GetMacLen(tmp);
    if (macLen == 0) {
        CRYPT_EAL_MacFreeCtx(tmp);
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    uint8_t *macValue = BSL_SAL_Malloc(macLen);
    if (macValue == NULL) {
        CRYPT_EAL_MacFreeCtx(tmp);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_MacFinal(tmp, macValue, &macLen);
    CRYPT_EAL_MacFreeCtx(tmp);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(macValue, macLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    mac->data = macValue;
    mac->dataLen = macLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t InitStreamDigestCtx(CMS_AuthenticatedData *authData)
{
    if (authData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t ret = EnsureDigestAlg(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    authData->digestAlg.mdCtx = CRYPT_EAL_ProviderMdNewCtx(authData->libCtx, authData->digestAlg.id, authData->attrName);
    if (authData->digestAlg.mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ret = CRYPT_EAL_MdInit(authData->digestAlg.mdCtx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(authData->digestAlg.mdCtx);
        authData->digestAlg.mdCtx = NULL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t InitStreamMacCtx(CMS_AuthenticatedData *authData)
{
    if (authData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (authData->macAlg.id == CRYPT_MAC_GMAC_AES128 || authData->macAlg.id == CRYPT_MAC_GMAC_AES192 ||
        authData->macAlg.id == CRYPT_MAC_GMAC_AES256 || authData->macAlg.id == CRYPT_MAC_CBC_MAC_SM4) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_UNSUPPORTED_TYPE);
        return HITLS_CMS_ERR_UNSUPPORTED_TYPE;
    }
    authData->macAlg.macCtx = CRYPT_EAL_ProviderMacNewCtx(authData->libCtx, authData->macAlg.id, authData->attrName);
    if (authData->macAlg.macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    int32_t ret = CRYPT_EAL_MacInit(authData->macAlg.macCtx, authData->macKey.data, authData->macKey.dataLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(authData->macAlg.macCtx);
        authData->macAlg.macCtx = NULL;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t GetStreamVerifyPrivateKey(const BSL_Param *param, CRYPT_EAL_PkeyCtx **decryptKey)
{
    if (decryptKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    const BSL_Param *p = BSL_PARAM_FindConstParam(param, HITLS_CMS_PARAM_PRIVATE_KEY);
    if (p == NULL || p->value == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (p->valueType != BSL_PARAM_TYPE_CTX_PTR || p->valueLen != sizeof(CRYPT_EAL_PkeyCtx *)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    *decryptKey = (CRYPT_EAL_PkeyCtx *)p->value;
    return HITLS_PKI_SUCCESS;
}

static int32_t InitAuthDataVerifyCtx(CMS_AuthenticatedData *authData)
{
    int32_t ret = CheckAuthDataStructFormat(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (authData->authAttrs == NULL) {
        if (authData->hasDigestAlg) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
            return HITLS_CMS_ERR_INVALID_FORMAT;
        }
        return InitStreamMacCtx(authData);
    }
    if (!authData->hasDigestAlg) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_FORMAT);
        return HITLS_CMS_ERR_INVALID_FORMAT;
    }
    return InitStreamDigestCtx(authData);
}

static int32_t AuthData_GenerateInit(HITLS_CMS *cms, const BSL_Param *param)
{
    if (cms == NULL || cms->ctx.authenticatedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (cms->dataType != BSL_CID_PKCS7_AUTHENTICATEDDATA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    CMS_AuthenticatedData *authData = cms->ctx.authenticatedData;
    if ((authData->flag & (HITLS_CMS_FLAG_PARSE | HITLS_CMS_FLAG_GEN)) != 0 ||
        authData->state != HITLS_CMS_UNINIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    int32_t ret = ApplyAuthDataParams(cms, param);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CheckAuthDataGenerateParams(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (!authData->detached) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ATTACHED_STREAM_UNSUPPORTED);
        return HITLS_CMS_ERR_ATTACHED_STREAM_UNSUPPORTED;
    }
    CleanupAuthDataStream(authData);
    ret = EnsureMacKey(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if ((authData->flag & HITLS_CMS_FLAG_NO_AUTHATTR) != 0) {
        ret = InitStreamMacCtx(authData);
        if (ret != HITLS_PKI_SUCCESS) {
            ClearAuthDataKey(authData);
            return ret;
        }
    } else {
        ret = InitStreamDigestCtx(authData);
        if (ret != HITLS_PKI_SUCCESS) {
            ClearAuthDataKey(authData);
            return ret;
        }
    }
    authData->state = HITLS_CMS_AUTH_INIT;
    return HITLS_PKI_SUCCESS;
}

static int32_t AuthData_VerifyInit(HITLS_CMS *cms, const BSL_Param *param)
{
    if (cms == NULL || cms->ctx.authenticatedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (cms->dataType != BSL_CID_PKCS7_AUTHENTICATEDDATA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }

    CMS_AuthenticatedData *authData = cms->ctx.authenticatedData;
    if (authData->state != HITLS_CMS_UNINIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    if (!authData->detached) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_ATTACHED_STREAM_UNSUPPORTED);
        return HITLS_CMS_ERR_ATTACHED_STREAM_UNSUPPORTED;
    }

    CRYPT_EAL_PkeyCtx *decryptKey = NULL;
    int32_t ret = GetStreamVerifyPrivateKey(param, &decryptKey);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    BSL_Buffer macKey = {0};
    ret = RecoverMacKey(authData, decryptKey, param, &macKey);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ClearAuthDataKey(authData);
    authData->macKey = macKey;

    CleanupAuthDataStream(authData);
    ret = InitAuthDataVerifyCtx(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        CleanupAuthDataStream(authData);
        ClearAuthDataKey(authData);
        return ret;
    }
    authData->state = HITLS_CMS_AUTH_VERIFY_INIT;
    return HITLS_PKI_SUCCESS;
}

static int32_t PrepareAuthAttrs(CMS_AuthenticatedData *authData, const BSL_Buffer *msg, BSL_Buffer *macInput)
{
    if (authData == NULL || msg == NULL || macInput == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    uint8_t digest[HITLS_CMS_AUTHDATA_MAX_DIGEST_LEN] = {0};
    uint32_t digestLen = sizeof(digest);
    int32_t ret = ComputeContentDigest(authData, msg, digest, &digestLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return PrepareAuthAttrsWithDigest(authData, digest, digestLen, macInput);
}

static int32_t PrepareAuthAttrsWithDigest(CMS_AuthenticatedData *authData, const uint8_t *digest,
    uint32_t digestLen, BSL_Buffer *macInput)
{
    if (authData == NULL || digest == NULL || macInput == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    macInput->data = NULL;
    macInput->dataLen = 0;
    if ((authData->flag & HITLS_CMS_FLAG_NO_AUTHATTR) != 0) {
        return HITLS_PKI_SUCCESS;
    }
    if (authData->authAttrs == NULL) {
        authData->authAttrs = HITLS_X509_AttrsNew();
        if (authData->authAttrs == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }

    HITLS_X509_AttrEntry *ctAttr = NULL;
    int32_t ret = CreateContentTypeAttr(authData->encapCont.contentType, &ctAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = AddRequiredAttr(authData->authAttrs, ctAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    HITLS_X509_AttrEntry *mdAttr = NULL;
    ret = CreateMessageDigestAttr(digest, digestLen, &mdAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = AddRequiredAttr(authData->authAttrs, mdAttr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    return EncodeAuthAttrsMacInput(authData->authAttrs, macInput);
}

static int32_t ComputeAuthDataMac(CMS_AuthenticatedData *authData, const BSL_Buffer *msg)
{
    if (authData == NULL || msg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    BSL_Buffer macInput = {0};
    const uint8_t *input = msg->data;
    uint32_t inputLen = msg->dataLen;
    if ((authData->flag & HITLS_CMS_FLAG_NO_AUTHATTR) == 0) {
        int32_t ret = PrepareAuthAttrs(authData, msg, &macInput);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        input = macInput.data;
        inputLen = macInput.dataLen;
    }
    BSL_Buffer mac = {0};
    int32_t ret = ComputeMacValue(authData, &authData->macKey, input, inputLen, &mac);
    BSL_SAL_FREE(macInput.data);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    if ((authData->flag & HITLS_CMS_FLAG_PARSE) == 0) {
        BSL_SAL_FREE(authData->mac.data);
    }
    authData->mac = mac;
    return HITLS_PKI_SUCCESS;
}

static void CleanupAuthDataGenerateState(CMS_AuthenticatedData *authData)
{
    if (authData == NULL) {
        return;
    }

    BSL_LIST_DeleteAll(authData->recipientInfos, (BSL_LIST_PFUNC_FREE)CMS_RecipientInfoFree);

    HITLS_X509_AttrsFree(authData->authAttrs, NULL);
    authData->authAttrs = NULL;

    BSL_SAL_FREE(authData->encapCont.content.data);
    authData->encapCont.content.data = NULL;
    authData->encapCont.content.dataLen = 0;

    BSL_SAL_FREE(authData->mac.data);
    authData->mac.data = NULL;
    authData->mac.dataLen = 0;

    CRYPT_EAL_MdFreeCtx(authData->digestAlg.mdCtx);
    authData->digestAlg.mdCtx = NULL;
    BSL_SAL_FREE(authData->digestAlg.param.data);
    authData->digestAlg.param.data = NULL;
    authData->digestAlg.param.dataLen = 0;
    authData->digestAlg.id = BSL_CID_UNKNOWN;
    authData->hasDigestAlg = false;

    ClearAuthDataKey(authData);
    authData->version = 0;
    authData->state = HITLS_CMS_UNINIT;
    authData->flag &= ~HITLS_CMS_FLAG_GEN;
}

static int32_t AuthData_GenerateOneShot(HITLS_CMS *cms, const BSL_Buffer *msg, const BSL_Param *optionalParam)
{
    if (msg == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    CMS_AuthenticatedData *authData = cms->ctx.authenticatedData;
    int32_t ret = ApplyAuthDataParams(cms, optionalParam);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CheckAuthDataGenerateParams(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = EnsureMacKey(authData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CMS_AddRecipientAndWrapCek(authData->recipientInfos, &authData->macKey, optionalParam);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = FinalizeAuthDataGenerate(authData, msg, optionalParam);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    return HITLS_PKI_SUCCESS;
ERR:
    CleanupAuthDataGenerateState(authData);
    return ret;
}

int32_t HITLS_CMS_DataAuth(HITLS_CMS *cms, const BSL_Buffer *msg, const BSL_Param *optionalParam)
{
    if (cms == NULL || cms->ctx.authenticatedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (cms->dataType != BSL_CID_PKCS7_AUTHENTICATEDDATA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
    CMS_AuthenticatedData *authData = cms->ctx.authenticatedData;
    if (authData->recipientInfos == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (authData->state == HITLS_CMS_AUTH_INIT) {
        return CMS_AddRecipientAndWrapCek(authData->recipientInfos, &authData->macKey, optionalParam);
    }
    if (authData->state != HITLS_CMS_UNINIT || (authData->flag & HITLS_CMS_FLAG_PARSE) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    bool hasRecipient = (BSL_LIST_COUNT(authData->recipientInfos) > 0)? true : false;
    if (hasRecipient && authData->macKey.data != NULL && authData->macKey.dataLen > 0) {
        return CMS_AddRecipientAndWrapCek(authData->recipientInfos, &authData->macKey, optionalParam);
    }
    return AuthData_GenerateOneShot(cms, msg, optionalParam);
}

int32_t HITLS_CMS_DataAuthVerify(HITLS_CMS *cms, CRYPT_EAL_PkeyCtx *decryptKey, BSL_Buffer *msg,
    const BSL_Param *param, BSL_Buffer *output)
{
    if (cms == NULL || decryptKey == NULL || cms->ctx.authenticatedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (cms->dataType != BSL_CID_PKCS7_AUTHENTICATEDDATA) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }

    CMS_AuthenticatedData *authData = cms->ctx.authenticatedData;
    if (authData->recipientInfos == NULL || BSL_LIST_COUNT(authData->recipientInfos) == 0 ||
        authData->mac.data == NULL || authData->mac.dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }

    BSL_Buffer macKey = {0};
    int32_t ret = RecoverMacKey(authData, decryptKey, param, &macKey);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = PerformAuthDataVerify(authData, msg, &macKey, output);
    BSL_SAL_ClearFree(macKey.data, macKey.dataLen);
    return ret;
}

#endif // HITLS_PKI_CMS_AUTHENTICATEDDATA
