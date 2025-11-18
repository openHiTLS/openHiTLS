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
#ifdef HITLS_PKI_X509

#include <stdint.h>
#include "securec.h"
#include "sal_atomic.h"
#include "bsl_obj.h"
#include "bsl_sal.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_codecskey.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_local.h"

#define HITLS_X509_DNNAME_MAX_NUM  100
#define MAX_DN_STR_LEN 256

#define SM2_MAX_ID_BITS 65535
#define SM2_MAX_ID_LENGTH (SM2_MAX_ID_BITS / 8)

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

int32_t HITLS_X509_GetList(BslList *list, void *val, uint32_t valLen)
{
    if (list == NULL || val == NULL || valLen != sizeof(BslList *)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *(BslList **)val = list;
    return HITLS_PKI_SUCCESS;
}

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CSR_GEN) || \
    defined(HITLS_PKI_X509_CRT_AUTH)
int32_t HITLS_X509_GetEncodeDn(BslList *list, void *val, uint32_t valLen)
{
    if (list == NULL || val == NULL || valLen != sizeof(BslList *)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    BSL_ASN1_Buffer tmp = {0};
    int32_t ret = HITLS_X509_EncodeNameList((BSL_ASN1_List *)list, &tmp);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer *res = (BSL_Buffer *)val;
    BSL_ASN1_TemplateItem item[] = {{BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}};
    BSL_ASN1_Template templ = {item, 1};

    ret = BSL_ASN1_EncodeTemplate(&templ, &tmp, 1, &res->data, &res->dataLen);
    BSL_SAL_Free(tmp.buff);
    return ret;
}
#endif

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
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_GetSignAlg(BslCid signAlgId, int32_t *val, uint32_t valLen)
{
    if (val == NULL || valLen != sizeof(BslCid)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = signAlgId;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_GetSignMdAlg(const HITLS_X509_Asn1AlgId *signAlgId, int32_t *val, int32_t valLen)
{
    if (val == NULL || valLen != sizeof(BslCid)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = signAlgId->algId == BSL_CID_RSASSAPSS ?
        signAlgId->rsaPssParam.mdId : BSL_OBJ_GetHashIdFromSignId(signAlgId->algId);
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_GetEncodeLen(uint32_t encodeLen, uint32_t *val, uint32_t valLen)
{
    if (val == NULL || valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *(uint32_t *)val = encodeLen;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_GetEncodeData(uint8_t *rawData, uint8_t **val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = rawData;
    return HITLS_PKI_SUCCESS;
}

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CSR_GEN) || defined(HITLS_PKI_X509_CRL_GEN)

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
    return HITLS_PKI_SUCCESS;
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
    if (ret != BSL_SUCCESS) {
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

typedef struct {
    HITLS_X509_NameNode *node;
    BSL_ASN1_Buffer *encode;
} NameNodePack;

/**
 *  X.690: 11.6 Set-of components
 *  https://www.itu.int/rec/T-REC-X.690-202102-I/en
 * The encodings of the component values of a set-of value shall appear in ascending order, the encodings
 * being compared as octet strings with the shorter components being padded at their trailing end with 0-octets.
 * NOTE - The padding octets are for comparison purposes only and do not appear in the encodings.
*/
static int32_t CmpDnNameByEncode(const void *pDnName1, const void *pDnName2)
{
    const NameNodePack *node1 = *(const NameNodePack **)(uintptr_t)pDnName1;
    const NameNodePack *node2 = *(const NameNodePack **)(uintptr_t)pDnName2;
    int res;
    BSL_ASN1_Buffer *asn1Buff = node1->encode;
    BSL_ASN1_Buffer *asn2Buff = node2->encode;

    if (asn1Buff->len == asn2Buff->len) {
        res = memcmp(asn1Buff->buff, asn2Buff->buff, asn2Buff->len);
    } else {
        uint32_t minSize = asn1Buff->len < asn2Buff->len ? asn1Buff->len : asn2Buff->len;
        res = memcmp(asn1Buff->buff, asn2Buff->buff, minSize);
        if (res == 0) {
            res = asn1Buff->len == minSize ? -1 : 1;
        }
    }
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
static uint8_t GetAsn1TypeByCid(BslCid cid)
{
    switch (cid) {
        case BSL_CID_AT_SERIALNUMBER:
        case BSL_CID_AT_COUNTRYNAME:
        case BSL_CID_AT_DNQUALIFIER:
            return BSL_ASN1_TAG_PRINTABLESTRING;
        case BSL_CID_DOMAINCOMPONENT:
            return BSL_ASN1_TAG_IA5STRING;
        default:
            return BSL_ASN1_TAG_UTF8STRING;
    }
}

static void FreeNodePack(NameNodePack *node)
{
    if (node == NULL) {
        return;
    }
    if (node->encode != NULL) { // the node->node has been pushed in other list.
        BSL_SAL_FREE(node->encode->buff);
        BSL_SAL_Free(node->encode);
    }
    BSL_SAL_Free(node);
}

int32_t HITLS_X509_SetNameList(BslList **dest, void *val, uint32_t valLen)
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
    return HITLS_PKI_SUCCESS;
}

static int32_t FillNameNodes(HITLS_X509_NameNode *layer2, BslCid cid, uint8_t *data, uint32_t dataLen)
{
    BslOidString *oid = BSL_OBJ_GetOID(cid);
    if (oid == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_DNNAME_UNKNOWN);
        return HITLS_X509_ERR_SET_DNNAME_UNKNOWN;
    }

    layer2->layer = 2; // 2: The layer of sequence
    layer2->nameType.tag = BSL_ASN1_TAG_OBJECT_ID;

    layer2->nameValue.tag = GetAsn1TypeByCid(cid);
    layer2->nameType.buff = BSL_SAL_Dump((uint8_t *)oid->octs, oid->octetLen);
    layer2->nameValue.buff = BSL_SAL_Dump(data, dataLen);
    if (layer2->nameType.buff == NULL || layer2->nameValue.buff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }

    layer2->nameType.len = oid->octetLen;
    layer2->nameValue.len = dataLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509AddDnNameItemToList(BslList *dnNameList, BslCid cid, uint8_t *data, uint32_t dataLen)
{
    if (data == NULL || dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    const BslAsn1DnInfo *asn1StrInfo = BSL_OBJ_GetDnInfoFromCid(cid);
    if (asn1StrInfo == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_DNNAME_UNKNOWN);
        return HITLS_X509_ERR_SET_DNNAME_UNKNOWN;
    }
    if (asn1StrInfo->max != -1 && ((int32_t)dataLen < asn1StrInfo->min || (int32_t)dataLen > asn1StrInfo->max)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_DNNAME_INVALID_LEN);
        return HITLS_X509_ERR_SET_DNNAME_INVALID_LEN;
    }
    BSL_ASN1_Buffer *encode = BSL_SAL_Calloc(1u, sizeof(HITLS_X509_NameNode));
    if (encode == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    HITLS_X509_NameNode *layer2 = BSL_SAL_Calloc(1, sizeof(HITLS_X509_NameNode));
    if (layer2 == NULL) {
        BSL_SAL_FREE(encode);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = FillNameNodes(layer2, cid, data, dataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(encode);
        HITLS_X509_FreeNameNode(layer2);
        return ret;
    }
    ret = X509EncodeNameNodeEntry(layer2, encode);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(encode);
        HITLS_X509_FreeNameNode(layer2);
        return ret;
    }
    NameNodePack pack = {layer2, encode};
    ret = HITLS_X509_AddListItemDefault(&pack, sizeof(NameNodePack), dnNameList);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_FreeNameNode(layer2);
        BSL_SAL_FREE(encode->buff);
        BSL_SAL_Free(encode);
    }
    return ret;
}

static int32_t X509AddDnNamesToList(BslList *list, BslList *dnNameList)
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
    NameNodePack *node = BSL_LIST_GET_FIRST(dnNameList);
    while (node != NULL) {
        ret = BSL_LIST_AddElement(list, node->node, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        node = BSL_LIST_GET_NEXT(dnNameList);
    }

    return ret;
}

BslList *HITLS_X509_DnListNew(void)
{
    return BSL_LIST_New(sizeof(HITLS_X509_NameNode));
}

void HITLS_X509_DnListFree(BslList *dnList)
{
    BSL_LIST_FREE(dnList, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
}

int32_t HITLS_X509_AddDnName(BslList *list, HITLS_X509_DN *dnNames, uint32_t size)
{
    if (list == NULL || dnNames == NULL || size == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (BSL_LIST_COUNT(list) == HITLS_X509_DNNAME_MAX_NUM) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_DNNAME_TOOMUCH);
        return HITLS_X509_ERR_SET_DNNAME_TOOMUCH;
    }

    BslList *dnNameList = BSL_LIST_New(sizeof(NameNodePack));
    if (dnNameList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret;
    for (uint32_t i = 0; i < size; i++) {
        ret = X509AddDnNameItemToList(dnNameList, dnNames[i].cid, dnNames[i].data, dnNames[i].dataLen);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
    }
    // sort
    dnNameList = BSL_LIST_Sort(dnNameList, CmpDnNameByEncode);
    if (dnNameList == NULL) {
        ret = HITLS_X509_ERR_SORT_NAME_NODE;
        goto EXIT;
    }
    // add dnNameList to list
    ret = X509AddDnNamesToList(list, dnNameList);
EXIT:
    BSL_LIST_FREE(dnNameList, (BSL_LIST_PFUNC_FREE)FreeNodePack);
    return ret;
}
#endif

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CRL_GEN)
int32_t HITLS_X509_SetSerial(BSL_ASN1_Buffer *serial, const void *val, uint32_t valLen)
{
    if (valLen == 0) {
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
    return HITLS_PKI_SUCCESS;
}
#endif

#if defined(HITLS_PKI_X509_CRT) || defined(HITLS_PKI_X509_CRL)
int32_t HITLS_X509_GetSerial(BSL_ASN1_Buffer *serial, void *val, uint32_t valLen)
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
    return HITLS_PKI_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_SM2
int32_t HITLS_X509_SetSm2UserId(BSL_Buffer *sm2UserId, void *val, uint32_t valLen)
{
    if (valLen == 0 || valLen > SM2_MAX_ID_LENGTH) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    BSL_SAL_FREE(sm2UserId->data);
    sm2UserId->data = BSL_SAL_Calloc(valLen, 1u);
    if (sm2UserId->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    (void) memcpy_s(sm2UserId->data, valLen, (uint8_t *)val, valLen);
    sm2UserId->dataLen = (uint32_t)valLen;
    return HITLS_PKI_SUCCESS;
}
#endif // HITLS_CRYPTO_SM2

/* RFC2253 https://www.rfc-editor.org/rfc/rfc2253 */
static int32_t X509GetPrintSNStr(const BSL_ASN1_Buffer *nameType, char *buff, uint32_t buffLen, uint32_t *usedLen)
{
    if (nameType == NULL || nameType->buff == NULL || nameType->len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    const char *oidName = BSL_OBJ_GetOidNameFromOidBuff(nameType->buff, nameType->len);
    if (oidName == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_INVALID_DN);
        return HITLS_X509_ERR_CERT_INVALID_DN;
    }
    if (strcpy_s(buff, buffLen, oidName) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_INVALID_DN);
        return HITLS_X509_ERR_CERT_INVALID_DN;
    }

    *usedLen = (uint32_t)strlen(oidName);
    return HITLS_PKI_SUCCESS;
}

static int32_t X509PrintNameNode(const HITLS_X509_NameNode *nameNode, char *buff, uint32_t buffLen, uint32_t *usedLen)
{
    if (nameNode->layer == 1) {
        return HITLS_PKI_SUCCESS;
    }
    uint32_t offset = 0;
    *usedLen = 0;
    /* Get the printable type */
    int32_t ret = X509GetPrintSNStr(&nameNode->nameType, buff, buffLen, &offset);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    /* print '=' between type and value */
    if (buffLen - offset < 2) { // 2 denote buffer is enough to place two character, i.e '=' and '\0'
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    buff[offset] = '=';
    offset++;
    /* print 'value' */
    if (nameNode->nameValue.buff == NULL || nameNode->nameValue.len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (memcpy_s(buff + offset, buffLen - offset, nameNode->nameValue.buff, nameNode->nameValue.len) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_INVALID_DN);
        return HITLS_X509_ERR_CERT_INVALID_DN;
    }
    offset += nameNode->nameValue.len;
    *usedLen = offset;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_GetDistinguishNameStrFromList(BSL_ASN1_List *nameList, BSL_Buffer *buff)
{
    if (nameList == NULL || BSL_LIST_COUNT(nameList) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    uint32_t offset = 0;
    char tmpBuffStr[MAX_DN_STR_LEN] = {0};
    char *tmpBuff = tmpBuffStr;
    uint32_t tmpBuffLen = MAX_DN_STR_LEN;
    (void)BSL_LIST_GET_FIRST(nameList);
    HITLS_X509_NameNode *firstNameNode = BSL_LIST_GET_NEXT(nameList);
    HITLS_X509_NameNode *nameNode = firstNameNode;
    while (nameNode != NULL) {
        if (tmpBuffLen - offset < 2) { // 2 denote buffer is enough to place two character, i.e ',' and '\0'
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
        }
        if (nameNode != firstNameNode && nameNode->layer == 2) {  // Is 2 nodes.
            *tmpBuff = ',';
            tmpBuff++;
            offset++;
        }
        uint32_t eachUsedLen = 0;
        int32_t ret = X509PrintNameNode(nameNode, tmpBuff, tmpBuffLen - offset, &eachUsedLen);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        tmpBuff += eachUsedLen;
        offset += eachUsedLen;
        nameNode = BSL_LIST_GET_NEXT(nameList);
    }
    buff->data = BSL_SAL_Calloc(offset + 1, sizeof(char));
    if (buff->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    (void)memcpy_s(buff->data, offset + 1, tmpBuffStr, offset);
    buff->dataLen = offset;
    return HITLS_PKI_SUCCESS;
}

#endif // HITLS_PKI_X509
