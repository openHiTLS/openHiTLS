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

#include "securec.h"
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "bsl_err_internal.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_local.h"

#define BITS_OF_BYTE 8
#define HITLS_X509_EXT_NOT_FOUND 1
#define HITLS_X509_EXT_KEYUSAGE_UNUSED_BIT 0xFFFF7F00 // Only 9 bits are used.

typedef enum {
    HITLS_X509_EXT_OID_IDX,
    HITLS_X509_EXT_CRITICAL_IDX,
    HITLS_X509_EXT_VALUE_IDX,
    HITLS_X509_EXT_MAX
} HITLS_X509_EXT_IDX;

/**
 * RFC 5280: section-4.2.1.9
 * BasicConstraints ::= SEQUENCE {
 *   cA                      BOOLEAN DEFAULT FALSE,
 *   pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 */
static BSL_ASN1_TemplateItem g_bConsTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
    {BSL_ASN1_TAG_BOOLEAN, BSL_ASN1_FLAG_DEFAULT, 1},
    {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_OPTIONAL, 1},
};

typedef enum {
    HITLS_X509_EXT_BC_CA_IDX,
    HITLS_X509_EXT_BC_PATHLEN_IDX,
    HITLS_X509_EXT_BC_MAX
} HITLS_X509_EXT_BASICCONSTRAINTS;

/**
 * RFC 5280: section-4.2.1.1
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 */
#define HITLS_X509_CTX_SPECIFIC_TAG_AKID_KID    0
#define HITLS_X509_CTX_SPECIFIC_TAG_AKID_ISSUER 1
#define HITLS_X509_CTX_SPECIFIC_TAG_AKID_SERIAL 2

static BSL_ASN1_TemplateItem g_akidTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        /* KeyIdentifier */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_AKID_KID, BSL_ASN1_FLAG_OPTIONAL, 1},
        /* authorityCertIssuer */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_X509_CTX_SPECIFIC_TAG_AKID_ISSUER,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
        /* authorityCertSerialNumber */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_AKID_SERIAL, BSL_ASN1_FLAG_OPTIONAL, 1},
};

typedef enum {
    HITLS_X509_EXT_AKI_KID_IDX,
    HITLS_X509_EXT_AKI_ISSUER_IDX,
    HITLS_X509_EXT_AKI_SERIAL_IDX,
    HITLS_X509_EXT_AKI_MAX,
} HITLS_X509_EXT_AKI;

/**
 * RFC 5280: section-4.2.1.2
 * Two common methods for generating key identifiers from the public key are:
 * (1) The kid is composed of 160-bit sha1 hash of the BIT STRING subjectPublicKey.
 * (2) The kid is composed of a 4-bit type field with the value 0100 followed by the lease significant 60 bits of the
 *     sha1 hash of the BIT STRING subjectPublicKey.
 */
#define HITLS_X509_KID_MIN_LEN 8
#define HITLS_X509_KID_MAX_LEN 20
#define HITLS_X509_CRLNUMBER_MIN_LEN 1
#define HITLS_X509_CRLNUMBER_MAX_LEN 20

/**
 * RFC 5280: section-4.2.1.6
 * SubjectAltName ::= GeneralNames
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 * GeneralName ::= CHOICE {
 *   otherName                       [0]     OtherName,         -- not support
 *   rfc822Name                      [1]     IA5String,
 *   dNSName                         [2]     IA5String,
 *   x400Address                     [3]     ORAddress,         -- not support
 *   directoryName                   [4]     Name,
 *   ediPartyName                    [5]     EDIPartyName,      -- not support
 *   uniformResourceIdentifier       [6]     IA5String,
 *   iPAddress                       [7]     OCTET STRING,
 *   registeredID                    [8]     OBJECT IDENTIFIER  -- not support
 * }
 */
#define HITLS_X509_GENERALNAME_OTHER_TAG    (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0)
#define HITLS_X509_GENERALNAME_RFC822_TAG   (BSL_ASN1_CLASS_CTX_SPECIFIC | 1)
#define HITLS_X509_GENERALNAME_DNS_TAG      (BSL_ASN1_CLASS_CTX_SPECIFIC | 2)
#define HITLS_X509_GENERALNAME_X400_TAG     (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 3)
#define HITLS_X509_GENERALNAME_DIR_TAG      (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 4)
#define HITLS_X509_GENERALNAME_EDI_TAG      (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 5)
#define HITLS_X509_GENERALNAME_URI_TAG      (BSL_ASN1_CLASS_CTX_SPECIFIC | 6)
#define HITLS_X509_GENERALNAME_IP_TAG       (BSL_ASN1_CLASS_CTX_SPECIFIC | 7)
#define HITLS_X509_GENERALNAME_RID_TAG      (BSL_ASN1_CLASS_CTX_SPECIFIC | 8)

typedef struct {
    uint8_t tag;
    int32_t type;
} HITLS_X509_GeneralNameMap;

static HITLS_X509_GeneralNameMap g_generalNameMap[] = {
    {HITLS_X509_GENERALNAME_OTHER_TAG, HITLS_X509_GN_OTHER},
    {HITLS_X509_GENERALNAME_RFC822_TAG, HITLS_X509_GN_EMAIL},
    {HITLS_X509_GENERALNAME_DNS_TAG, HITLS_X509_GN_DNS},
    {HITLS_X509_GENERALNAME_X400_TAG, HITLS_X509_GN_X400},
    {HITLS_X509_GENERALNAME_DIR_TAG, HITLS_X509_GN_DNNAME},
    {HITLS_X509_GENERALNAME_EDI_TAG, HITLS_X509_GN_EDI},
    {HITLS_X509_GENERALNAME_URI_TAG, HITLS_X509_GN_URI},
    {HITLS_X509_GENERALNAME_IP_TAG, HITLS_X509_GN_IP},
    {HITLS_X509_GENERALNAME_RID_TAG, HITLS_X509_GN_RID},
};

static int32_t CmpExtByCid(const void *pExt, const void *pCid)
{
    const HITLS_X509_ExtEntry *ext = pExt;
    BslCid cid = *(const BslCid *)pCid;

    return cid == ext->cid ? 0 : HITLS_X509_EXT_NOT_FOUND;
}

#if defined(HITLS_PKI_X509_CRT_PARSE) || defined(HITLS_PKI_X509_CRL_PARSE) || defined(HITLS_PKI_X509_CSR)
static int32_t CmpExtByOid(const void *pExt, const void *pOid)
{
    const HITLS_X509_ExtEntry *ext = pExt;
    const BSL_ASN1_Buffer *oid = pOid;
    if (ext->extnId.len != oid->len) {
        return HITLS_X509_EXT_NOT_FOUND;
    }
    return memcmp(ext->extnId.buff, oid->buff, oid->len) == 0 ? 0 : HITLS_X509_EXT_NOT_FOUND;
}

static int32_t ParseExtKeyUsage(HITLS_X509_ExtEntry *extEntry, HITLS_X509_CertExt *ext)
{
    uint32_t len;
    uint8_t *temp = extEntry->extnValue.buff;
    uint32_t tempLen = extEntry->extnValue.len;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_BITSTRING, &temp, &tempLen, &len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BITSTRING, len, temp};
    BSL_ASN1_BitString bitString = {0};
    ret = BSL_ASN1_DecodePrimitiveItem(&asn, &bitString);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (bitString.len > sizeof(ext->keyUsage)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_EXT_KU);
        return HITLS_X509_ERR_PARSE_EXT_KU;
    }
    for (uint32_t i = 0; i < bitString.len; i++) {
        ext->keyUsage |= (bitString.buff[i] << (BITS_OF_BYTE * i));
    }
    ext->extFlags |= HITLS_X509_EXT_FLAG_KUSAGE;
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseExtBasicConstraints(HITLS_X509_ExtEntry *extEntry, HITLS_X509_CertExt *ext)
{
    uint8_t *temp = extEntry->extnValue.buff;
    uint32_t tempLen = extEntry->extnValue.len;
    BSL_ASN1_Buffer asnArr[HITLS_X509_EXT_BC_MAX] = {0};
    BSL_ASN1_Template templ = {g_bConsTempl, sizeof(g_bConsTempl) / sizeof(g_bConsTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_X509_EXT_BC_MAX);
    if (tempLen != 0) {
        ret = HITLS_X509_ERR_PARSE_EXT_BUF;
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (asnArr[HITLS_X509_EXT_BC_CA_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_EXT_BC_CA_IDX], &ext->isCa);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    if (asnArr[HITLS_X509_EXT_BC_PATHLEN_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_EXT_BC_PATHLEN_IDX], &ext->maxPathLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    ext->extFlags |= HITLS_X509_EXT_FLAG_BCONS;
    return ret;
}
#endif

static int32_t ParseDirName(uint8_t **encode, uint32_t *encLen, BslList **list)
{
    uint32_t valueLen;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, encode, encLen, &valueLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *list = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (*list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    BSL_ASN1_Buffer asn = {.buff = *encode, .len = valueLen};
    ret = HITLS_X509_ParseNameList(&asn, *list);
    if (ret == BSL_SUCCESS) {
        *encode += valueLen;
        *encLen -= valueLen;
    } else {
        BSL_LIST_FREE(*list, NULL);
    }
    return ret;
}

static int32_t ParseGeneralName(uint8_t tag, uint8_t **encode, uint32_t *encLen, uint32_t nameLen, BslList *list)
{
    int32_t type = -1;
    int32_t ret;
    BslList *dirNames = NULL;
    BSL_Buffer value = {0};
    for (uint32_t i = 0; i < sizeof(g_generalNameMap) / sizeof(g_generalNameMap[0]); i++) {
        if (g_generalNameMap[i].tag == tag) {
            type = g_generalNameMap[i].type;
            break;
        }
    }
    if (type == -1) {
        return HITLS_X509_ERR_PARSE_SAN_ITEM_UNKNOW;
    }
    if (tag == HITLS_X509_GENERALNAME_DIR_TAG) {
        ret = ParseDirName(encode, encLen, &dirNames);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        value.data = (uint8_t *)dirNames;
        value.dataLen = sizeof(BslList *);
    } else {
        value.data = *encode;
        value.dataLen = nameLen;
    }
    HITLS_X509_GeneralName *name = BSL_SAL_Calloc(1, sizeof(HITLS_X509_GeneralName));
    if (name == NULL) {
        if (dirNames != NULL) {
            BSL_LIST_FREE(dirNames, NULL);
        }
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    name->type = type;
    name->value = value;
    ret = BSL_LIST_AddElement(list, name, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_FREE(dirNames, NULL);
        BSL_SAL_Free(name);
    }
    return ret;
}

static void FreeGeneralName(void *data)
{
    HITLS_X509_GeneralName *name = (HITLS_X509_GeneralName *)data;
    if (name->type == HITLS_X509_GN_DNNAME) {
        BSL_LIST_DeleteAll((BslList *)(uintptr_t)name->value.data, NULL);
        BSL_SAL_Free(name->value.data);
    }
    BSL_SAL_Free(data);
}

void HITLS_X509_FreeGeneralName(HITLS_X509_GeneralName *data)
{
    if (data == NULL) {
        return;
    }
    if (data->type == HITLS_X509_GN_DNNAME) {
        BSL_LIST_DeleteAll((BslList *)(uintptr_t)data->value.data, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
    }
    BSL_SAL_Free(data->value.data);
    BSL_SAL_Free(data);
}

void HITLS_X509_ClearGeneralNames(BslList *names)
{
    if (names == NULL) {
        return;
    }
    BSL_LIST_DeleteAll(names, (BSL_LIST_PFUNC_FREE)FreeGeneralName);
}

HITLS_X509_Ext *X509_ExtNew(HITLS_X509_Ext *ext, int32_t type)
{
    HITLS_X509_Ext *tmp = NULL;
    if (ext == NULL) {
        tmp = (HITLS_X509_Ext *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_Ext));
        if (tmp == NULL) {
            return NULL;
        }
        ext = tmp;
    }
    ext->type = type;
    ext->extList = BSL_LIST_New(sizeof(HITLS_X509_ExtEntry *));
    if (ext->extList == NULL) {
        BSL_SAL_Free(tmp);
        return NULL;
    }
    if (type != HITLS_X509_EXT_TYPE_CRL) {
        ext->extData = BSL_SAL_Calloc(1, sizeof(HITLS_X509_CertExt));
        if (ext->extData == NULL) {
            BSL_SAL_Free(ext->extList);
            ext->extList = NULL;
            BSL_SAL_Free(tmp);
            return NULL;
        }
        ((HITLS_X509_CertExt *)(ext->extData))->maxPathLen = -1;
    }
    return ext;
}

void X509_ExtFree(HITLS_X509_Ext *ext, bool isFreeOut)
{
    if (ext == NULL) {
        return;
    }
    if ((ext->flag & HITLS_X509_EXT_FLAG_PARSE) != 0) {
        BSL_LIST_FREE(ext->extList, NULL);
    } else {
        BSL_LIST_FREE(ext->extList, (BSL_LIST_PFUNC_FREE)HITLS_X509_ExtEntryFree);
    }
    if (ext->type == HITLS_X509_EXT_TYPE_CERT && ext->extData != NULL) {
        HITLS_X509_CertExt *c = (HITLS_X509_CertExt *)ext->extData;
        if ((c->extFlags & HITLS_X509_EXT_FLAG_EXKUSAGE) != 0) {
            HITLS_X509_ClearExtendedKeyUsage(&c->exKeyUsage);
        }
    }
    BSL_SAL_Free(ext->extData);
    if (isFreeOut) {
        BSL_SAL_Free(ext);
    }
}

int32_t HITLS_X509_ParseGeneralNames(uint8_t *encode, uint32_t encLen, BslList *list)
{
    uint8_t *buff = encode;
    uint32_t buffLen = encLen;
    uint32_t nameValueLen;
    uint8_t tag;
    int32_t ret = HITLS_PKI_SUCCESS;

    while (buffLen != 0) {
        // tag
        tag = *buff;
        buff++;
        buffLen--;
        // length
        ret = BSL_ASN1_DecodeLen(&buff, &buffLen, false, &nameValueLen);
        if (ret != BSL_SUCCESS) {
            break;
        }
        if (nameValueLen == 0) {
            continue;
        }
        // value
        ret = ParseGeneralName(tag, &buff, &buffLen, nameValueLen, list);
        if (ret != BSL_SUCCESS) {
            break;
        }
        if (tag != HITLS_X509_GENERALNAME_DIR_TAG) {
            buff += nameValueLen;
            buffLen -= nameValueLen;
        }
    }
    if (ret != BSL_SUCCESS) {
        HITLS_X509_ClearGeneralNames(list);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

void HITLS_X509_ClearAuthorityKeyId(HITLS_X509_ExtAki *aki)
{
    if (aki == NULL) {
        return;
    }
    if (aki->issuerName != NULL) {
        HITLS_X509_ClearGeneralNames(aki->issuerName);
        BSL_SAL_Free(aki->issuerName);
        aki->issuerName = NULL;
    }
}

int32_t HITLS_X509_ParseAuthorityKeyId(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtAki *aki)
{
    uint8_t *temp = extEntry->extnValue.buff;
    uint32_t tempLen = extEntry->extnValue.len;
    BslList *list = NULL;
    BSL_ASN1_Buffer asnArr[HITLS_X509_EXT_AKI_MAX] = {0};
    BSL_ASN1_Template templ = {g_akidTempl, sizeof(g_akidTempl) / sizeof(g_akidTempl[0])};

    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_X509_EXT_AKI_MAX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (asnArr[HITLS_X509_EXT_AKI_KID_IDX].tag != 0) {
        aki->kid.data = asnArr[HITLS_X509_EXT_AKI_KID_IDX].buff;
        aki->kid.dataLen = asnArr[HITLS_X509_EXT_AKI_KID_IDX].len;
    }
    /**
     * ITU-T x509: 8.2.2.1 Authority key identifier extension
     * authorityCertIssuer PRESENT, authorityCertSerialNumber PRESENT
     * authorityCertIssuer ABSENT, authorityCertSerialNumber ABSENT
     */
    if ((asnArr[HITLS_X509_EXT_AKI_SERIAL_IDX].buff != NULL && asnArr[HITLS_X509_EXT_AKI_ISSUER_IDX].buff == NULL) ||
        (asnArr[HITLS_X509_EXT_AKI_SERIAL_IDX].buff == NULL && asnArr[HITLS_X509_EXT_AKI_ISSUER_IDX].buff != NULL)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_ILLEGAL_AKI);
        return HITLS_X509_ERR_EXT_ILLEGAL_AKI;
    }
    if (asnArr[HITLS_X509_EXT_AKI_SERIAL_IDX].tag != 0) {
        aki->serialNum.data = asnArr[HITLS_X509_EXT_AKI_SERIAL_IDX].buff;
        aki->serialNum.dataLen = asnArr[HITLS_X509_EXT_AKI_SERIAL_IDX].len;
    }
    if (asnArr[HITLS_X509_EXT_AKI_ISSUER_IDX].tag != 0) {
        list = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
        if (list == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_AKI);
            return HITLS_X509_ERR_PARSE_AKI;
        }
        ret = HITLS_X509_ParseGeneralNames(
            asnArr[HITLS_X509_EXT_AKI_ISSUER_IDX].buff, asnArr[HITLS_X509_EXT_AKI_ISSUER_IDX].len, list);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_SAL_Free(list);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        aki->issuerName = list;
    }
    aki->critical = extEntry->critical;
    return ret;
}

int32_t HITLS_X509_ParseSubjectKeyId(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtSki *ski)
{
    uint8_t *temp = extEntry->extnValue.buff;
    uint32_t tempLen = extEntry->extnValue.len;
    uint32_t kidLen = 0;

    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &temp, &tempLen, &kidLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ski->kid.data = temp;
    ski->kid.dataLen = kidLen;
    ski->critical = extEntry->critical;
    return ret;
}

int32_t X509_ParseCrlNumber(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtCrlNumber *crlNumber)
{
    uint8_t *temp = extEntry->extnValue.buff;
    uint32_t tempLen = extEntry->extnValue.len;
    uint32_t valueLen = 0;

    // CRL Number is encoded as an INTEGER
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_INTEGER, &temp, &tempLen, &valueLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Check CRL Number length
    if (valueLen < HITLS_X509_CRLNUMBER_MIN_LEN || valueLen > HITLS_X509_CRLNUMBER_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_CRLNUMBER);
        return HITLS_X509_ERR_EXT_CRLNUMBER;
    }

    // Store CRL Number value
    crlNumber->crlNumber.data = temp;
    crlNumber->crlNumber.dataLen = valueLen;
    crlNumber->critical = extEntry->critical;

    return HITLS_PKI_SUCCESS;
}

#if defined(HITLS_PKI_X509_CRT_PARSE) || defined(HITLS_PKI_X509_CSR) || defined(HITLS_PKI_X509_CRL_PARSE) ||\
    defined(HITLS_PKI_INFO_CRT) || defined(HITLS_PKI_INFO_CSR)
static int32_t ParseExKeyUsageList(uint32_t layer, BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    (void)param;
    if (layer == 1) {
        return HITLS_PKI_SUCCESS;
    }

    BSL_Buffer *buff = BSL_SAL_Malloc(sizeof(BSL_Buffer));
    if (buff == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_EXKU_ITEM);
        return HITLS_X509_ERR_PARSE_EXKU_ITEM;
    }
    buff->data = asn->buff;
    buff->dataLen = asn->len;
    int32_t ret = BSL_LIST_AddElement(list, buff, BSL_LIST_POS_AFTER);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(buff);
    }
    return ret;
}

int32_t HITLS_X509_ParseExtendedKeyUsage(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtExKeyUsage *exku)
{
    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_TAG_OBJECT_ID};
    BSL_ASN1_DecodeListParam listParam = {sizeof(expTag) / sizeof(uint8_t), expTag};

    BslList *list = BSL_LIST_New(sizeof(BSL_Buffer));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_EXKU);
        return HITLS_X509_ERR_PARSE_EXKU;
    }

    int32_t ret = BSL_ASN1_DecodeListItem(&listParam, &extEntry->extnValue, ParseExKeyUsageList, NULL, list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_DeleteAll(list, NULL);
        BSL_SAL_Free(list);
        return ret;
    }

    exku->critical = extEntry->critical;
    exku->oidList = list;
    return ret;
}

void HITLS_X509_ClearExtendedKeyUsage(HITLS_X509_ExtExKeyUsage *exku)
{
    if (exku == NULL) {
        return;
    }
    BSL_LIST_FREE(exku->oidList, NULL);
}
#endif

void HITLS_X509_ClearSubjectAltName(HITLS_X509_ExtSan *san)
{
    if (san == NULL) {
        return;
    }
    if (san->names != NULL) {
        HITLS_X509_ClearGeneralNames(san->names);
        BSL_SAL_Free(san->names);
        san->names = NULL;
    }
}

int32_t HITLS_X509_ParseSubjectAltName(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtSan *san)
{
    uint32_t len;
    uint8_t *buff = extEntry->extnValue.buff;
    uint32_t buffLen = extEntry->extnValue.len;
    // skip the sequence
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &buff, &buffLen, &len);
    if (ret == BSL_SUCCESS && buffLen != len) {
        ret = HITLS_X509_ERR_PARSE_NO_ENOUGH;
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslList *list = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_SAN);
        return HITLS_X509_ERR_PARSE_SAN;
    }
    ret = HITLS_X509_ParseGeneralNames(buff, len, list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(list);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    san->names = list;
    san->critical = extEntry->critical;
    return ret;
}

#if defined(HITLS_PKI_X509_CRT_PARSE) || defined(HITLS_PKI_X509_CRL_PARSE) || defined(HITLS_PKI_X509_CSR)
static BSL_ASN1_TemplateItem g_x509ExtTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_TAG_BOOLEAN, BSL_ASN1_FLAG_DEFAULT, 0},
    {BSL_ASN1_TAG_OCTETSTRING, 0, 0},
};

int32_t HITLS_X509_ParseExtItem(BSL_ASN1_Buffer *extItem, HITLS_X509_ExtEntry *extEntry)
{
    uint8_t *temp = extItem->buff;
    uint32_t tempLen = extItem->len;
    BSL_ASN1_Buffer asnArr[HITLS_X509_EXT_MAX] = {0};
    BSL_ASN1_Template templ = {g_x509ExtTempl, sizeof(g_x509ExtTempl) / sizeof(g_x509ExtTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_X509_EXT_MAX);
    if (tempLen != 0) {
        ret = HITLS_X509_ERR_PARSE_EXT_BUF;
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // extnid
    extEntry->extnId = asnArr[HITLS_X509_EXT_OID_IDX];
    extEntry->cid = BSL_OBJ_GetCidFromOidBuff(extEntry->extnId.buff, extEntry->extnId.len);
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
#endif

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CSR_GEN)
static void FreeExtEntryCont(HITLS_X509_ExtEntry *entry)
{
    BSL_SAL_FREE(entry->extnId.buff);
    BSL_SAL_FREE(entry->extnValue.buff);
    entry->extnId.len = 0;
    entry->extnValue.len = 0;
}

static int32_t GetExtEntryByCid(BslList *extList, BslCid cid, HITLS_X509_ExtEntry **entry, bool *isNew)
{
    BslOidString *oid = BSL_OBJ_GetOID(cid);
    if (oid == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_OID);
        return HITLS_X509_ERR_EXT_OID;
    }
    HITLS_X509_ExtEntry *extEntry = BSL_LIST_Search(extList, &cid, CmpExtByCid, NULL);
    if (extEntry != NULL) {
        *isNew = false;
        FreeExtEntryCont(extEntry);
        extEntry->critical = false;
    } else {
        extEntry = BSL_SAL_Calloc(1, sizeof(HITLS_X509_ExtEntry));
        if (extEntry == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        *isNew = true;
    }

    extEntry->cid = cid;
    extEntry->extnId.tag = BSL_ASN1_TAG_OBJECT_ID;
    extEntry->extnId.len = oid->octetLen;
    if (extEntry->extnId.len != 0) {
        extEntry->extnId.buff = BSL_SAL_Dump(oid->octs, oid->octetLen);
        if (extEntry->extnId.buff == NULL) {
            if (*isNew) {
                BSL_SAL_Free(extEntry);
            }
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
    }
    extEntry->extnValue.tag = BSL_ASN1_TAG_OCTETSTRING;
    *entry = extEntry;
    return HITLS_PKI_SUCCESS;
}
#endif

#if defined(HITLS_PKI_X509_CRT_PARSE) || defined(HITLS_PKI_X509_CRL_PARSE) || defined(HITLS_PKI_X509_CSR)
static int32_t ParseExtAsnItem(BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    HITLS_X509_Ext *ext = param;
    HITLS_X509_ExtEntry extEntry = {0};
    int32_t ret = HITLS_X509_ParseExtItem(asn, &extEntry);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Check if the extension already exists.
    if (BSL_LIST_Search(list, &extEntry.extnId, CmpExtByOid, NULL) != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_EXT_REPEAT);
        return HITLS_X509_ERR_PARSE_EXT_REPEAT;
    }

    // Add the extension to list.
    ret =  HITLS_X509_AddListItemDefault(&extEntry, sizeof(HITLS_X509_ExtEntry), list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    switch (BSL_OBJ_GetCidFromOidBuff(extEntry.extnId.buff, extEntry.extnId.len)) {
        case BSL_CID_CE_KEYUSAGE:
            return ParseExtKeyUsage(&extEntry, (HITLS_X509_CertExt *)ext->extData);
        case BSL_CID_CE_BASICCONSTRAINTS:
            return ParseExtBasicConstraints(&extEntry, (HITLS_X509_CertExt *)ext->extData);
        case BSL_CID_CE_EXTKEYUSAGE: {
            HITLS_X509_CertExt *c = (HITLS_X509_CertExt *)ext->extData;
            ret = HITLS_X509_ParseExtendedKeyUsage(&extEntry, &c->exKeyUsage);
            if (ret == HITLS_PKI_SUCCESS) {
                c->extFlags |= HITLS_X509_EXT_FLAG_EXKUSAGE;
            }
            return ret;
        }
        default:
            return HITLS_PKI_SUCCESS;
    }
}

static int32_t ParseExtSeqof(uint32_t layer, BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    return layer == 1 ? HITLS_PKI_SUCCESS : ParseExtAsnItem(asn, param, list);
}

int32_t HITLS_X509_ParseExt(BSL_ASN1_Buffer *ext, HITLS_X509_Ext *certExt)
{
    if (certExt == NULL || certExt->extData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_PARSE_AFTER_SET);
        return HITLS_X509_ERR_EXT_PARSE_AFTER_SET;
    }

    if ((certExt->flag & HITLS_X509_EXT_FLAG_GEN) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_PARSE_AFTER_SET);
        return HITLS_X509_ERR_EXT_PARSE_AFTER_SET;
    }
    // x509 v1
    if (ext->tag == 0) {
        return HITLS_PKI_SUCCESS;
    }

    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
                        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {2, expTag};
    int ret = BSL_ASN1_DecodeListItem(&listParam, ext, &ParseExtSeqof, certExt, certExt->extList);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteAll(certExt->extList, NULL);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    certExt->flag |= HITLS_X509_EXT_FLAG_PARSE;
    return ret;
}
#endif

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CSR_GEN)
static int32_t SetExtBCons(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    const HITLS_X509_ExtBCons *bCons = (const HITLS_X509_ExtBCons *)val;
    BSL_ASN1_Template templ = {g_bConsTempl, sizeof(g_bConsTempl) / sizeof(g_bConsTempl[0])};
    /**
     * RFC 5280: section-4.2.1.9
     * BasicConstraints ::= SEQUENCE {
     *   cA                      BOOLEAN DEFAULT FALSE,
     *   pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
     */
    BSL_ASN1_Buffer asns[] = {
        {BSL_ASN1_TAG_BOOLEAN, bCons->isCa ? sizeof(bool) : 0, bCons->isCa ? (uint8_t *)(uintptr_t)&bCons->isCa : NULL},
        {BSL_ASN1_TAG_INTEGER, 0, NULL},
    };
    int32_t ret;

    if (bCons->maxPathLen >= 0) {
        ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, (uint64_t)bCons->maxPathLen, asns + 1);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    ret = BSL_ASN1_EncodeTemplate(
        &templ, asns, sizeof(asns) / sizeof(asns[0]), &entry->extnValue.buff, &entry->extnValue.len);
    BSL_SAL_Free(asns[1].buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    entry->critical = bCons->critical;
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)ext->extData;
    certExt->isCa = bCons->isCa;
    certExt->maxPathLen = bCons->maxPathLen;
    certExt->extFlags |= HITLS_X509_EXT_FLAG_BCONS;
    return HITLS_PKI_SUCCESS;
}

static int32_t SetExtKeyUsage(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    const HITLS_X509_ExtKeyUsage *ku = (const HITLS_X509_ExtKeyUsage *)val;
    if (ku->keyUsage == 0 || (ku->keyUsage & HITLS_X509_EXT_KEYUSAGE_UNUSED_BIT) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_KU);
        return HITLS_X509_ERR_EXT_KU;
    }

    // bit string
    uint16_t keyUsage = (uint16_t)ku->keyUsage;
    BSL_ASN1_BitString bs = {0};
    bs.len = (keyUsage & HITLS_X509_EXT_KU_DECIPHER_ONLY) == 0 ? 1 : 2; // 2: decipher only is not 0
    uint8_t buff[2] = {0}; // The max length of content(BitString, except unused bits) is 2 bytes.
    buff[0] = (uint8_t)keyUsage;
    buff[1] = (uint8_t)(keyUsage >> 8); // 8: 8 bits per byte
    bs.buff = buff;
    uint8_t tmp = bs.len == 1 ? (uint8_t)keyUsage : (uint8_t)(keyUsage >> BITS_OF_BYTE);
    for (int32_t i = 1; i < BITS_OF_BYTE; i++) {
        if ((uint8_t)(tmp << i) == 0) {
            bs.unusedBits = BITS_OF_BYTE - i;
            break;
        }
    }

    // encode bit string
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&bs};
    BSL_ASN1_TemplateItem item = {BSL_ASN1_TAG_BITSTRING, 0, 0};
    BSL_ASN1_Template templ = {&item, 1};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &entry->extnValue.buff, &entry->extnValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    entry->critical = ku->critical;
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)ext->extData;
    certExt->extFlags |= HITLS_X509_EXT_FLAG_KUSAGE;
    return ret;
}

static int32_t SetExtAki(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    (void)ext;
    const HITLS_X509_ExtAki *aki = (const HITLS_X509_ExtAki *)val;
    entry->critical = aki->critical;

    if (aki->kid.dataLen < HITLS_X509_KID_MIN_LEN || aki->kid.dataLen > HITLS_X509_KID_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_KID);
        return HITLS_X509_ERR_EXT_KID;
    }

    BSL_ASN1_Buffer asns[] = {
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_AKID_KID, aki->kid.dataLen, aki->kid.data},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_X509_CTX_SPECIFIC_TAG_AKID_ISSUER, 0, NULL},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_AKID_SERIAL, 0, NULL},
    };
    BSL_ASN1_Template templ = {g_akidTempl, sizeof(g_akidTempl) / sizeof(g_akidTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(
        &templ, asns, sizeof(asns) / sizeof(asns[0]), &entry->extnValue.buff, &entry->extnValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t SetExtSki(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    (void)ext;
    const HITLS_X509_ExtSki *ski = (const HITLS_X509_ExtSki *)val;
    entry->critical = ski->critical;

    if (ski->kid.dataLen < HITLS_X509_KID_MIN_LEN || ski->kid.dataLen > HITLS_X509_KID_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_KID);
        return HITLS_X509_ERR_EXT_KID;
    }

    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_OCTETSTRING, ski->kid.dataLen, ski->kid.data};
    BSL_ASN1_TemplateItem item = {BSL_ASN1_TAG_OCTETSTRING, 0, 0};
    BSL_ASN1_Template templ = {&item, 1};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &entry->extnValue.buff, &entry->extnValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static inline void SetAsn1Templ(BSL_Buffer *value, uint8_t tag, BSL_ASN1_TemplateItem *item, BSL_ASN1_Buffer *asn)
{
    item->tag = tag;
    asn->tag = tag;
    asn->len = value->dataLen;
    asn->buff = value->data;
}

static void FreeGnAsns(BSL_ASN1_Buffer *asns, uint32_t number)
{
    for (uint32_t i = 0; i < number; i++) {
        if (asns[i].tag == HITLS_X509_GENERALNAME_DIR_TAG) {
            BSL_SAL_Free(asns[i].buff);
        }
    }
    BSL_SAL_Free(asns);
}

static int32_t EncodeGnDirNameValue(BslList *dirNames, BSL_ASN1_Buffer *extnValue)
{
    /* Reuse common encoder to avoid duplicated logic */
    BSL_Buffer res = {0};
    int32_t ret = HITLS_X509_GetEncodeDn(dirNames, &res, sizeof(BslList *));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    extnValue->tag = HITLS_X509_GENERALNAME_DIR_TAG;
    extnValue->buff = res.data;
    extnValue->len = res.dataLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t SetGnEncodeParam(BslList *names, BSL_ASN1_TemplateItem *items, BSL_ASN1_Buffer *asns)
{
    HITLS_X509_GeneralName **name = BSL_LIST_First(names);
    BSL_ASN1_TemplateItem *item = items;
    BSL_ASN1_Buffer *asn = asns;
    int32_t ret;
    while (name != NULL) {
        if ((*name)->value.data == NULL || (*name)->value.dataLen == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SAN_ELE);
            return HITLS_X509_ERR_EXT_SAN_ELE;
        }
        switch ((*name)->type) {
            case HITLS_X509_GN_EMAIL:
                SetAsn1Templ(&(*name)->value, HITLS_X509_GENERALNAME_RFC822_TAG, item, asn);
                break;
            case HITLS_X509_GN_DNS:
                SetAsn1Templ(&(*name)->value, HITLS_X509_GENERALNAME_DNS_TAG, item, asn);
                break;
            case HITLS_X509_GN_DNNAME:
                ret = EncodeGnDirNameValue((BSL_ASN1_List *)(uintptr_t)(*name)->value.data, asn);
                if (ret != HITLS_PKI_SUCCESS) {
                    return ret;
                }
                item->tag = HITLS_X509_GENERALNAME_DIR_TAG;
                break;
            case HITLS_X509_GN_URI:
                SetAsn1Templ(&(*name)->value, HITLS_X509_GENERALNAME_URI_TAG, item, asn);
                break;
            case HITLS_X509_GN_IP:
                SetAsn1Templ(&(*name)->value, HITLS_X509_GENERALNAME_IP_TAG, item, asn);
                break;
            default:
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_GN_UNSUPPORT);
                return HITLS_X509_ERR_EXT_GN_UNSUPPORT;
        }
        item->depth = 1;
        item++;
        asn++;
        name = BSL_LIST_Next(names);
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t AllocEncodeParam(BSL_ASN1_TemplateItem **items, uint32_t itemNum, BSL_ASN1_Buffer **asns,
    uint32_t asnNum)
{
    *items = BSL_SAL_Calloc(itemNum, sizeof(BSL_ASN1_TemplateItem)); // sequence + names
    if (*items == NULL) {
        return BSL_MALLOC_FAIL;
    }
    *asns = BSL_SAL_Calloc(asnNum, sizeof(BSL_ASN1_Buffer));
    if (*asns == NULL) {
        BSL_SAL_Free(*items);
        *items = NULL;
        return BSL_MALLOC_FAIL;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t SetExtGeneralNames(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    (void)ext;
    const HITLS_X509_ExtSan *san = (const HITLS_X509_ExtSan *)val;
    if (san->names == NULL || BSL_LIST_COUNT(san->names) <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SAN);
        return HITLS_X509_ERR_EXT_SAN;
    }
    entry->critical = san->critical;

    /* Encode extnValue */
    BSL_ASN1_TemplateItem *items = NULL;
    BSL_ASN1_Buffer *asns = NULL;
    uint32_t number = (uint32_t)BSL_LIST_COUNT(san->names);
    int32_t ret = AllocEncodeParam(&items, 1 + number, &asns, number);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    items[0].depth = 0;
    items[0].tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    ret = SetGnEncodeParam(san->names, items + 1, asns);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    BSL_ASN1_Template templ = {items, number + 1};
    ret = BSL_ASN1_EncodeTemplate(&templ, asns, number, &entry->extnValue.buff, &entry->extnValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BSL_SAL_Free(items);
    FreeGnAsns(asns, number);
    return ret;
}

static int32_t SetExtExKeyUsage(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    (void)ext;
    const HITLS_X509_ExtExKeyUsage *exku = (const HITLS_X509_ExtExKeyUsage *)val;
    if (exku->oidList == NULL || BSL_LIST_COUNT(exku->oidList) <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_EXTENDED_KU);
        return HITLS_X509_ERR_EXT_EXTENDED_KU;
    }
    entry->critical = exku->critical;

    BSL_ASN1_TemplateItem *items = NULL;
    BSL_ASN1_Buffer *asns = NULL;
    uint32_t number = (uint32_t)BSL_LIST_COUNT(exku->oidList);
    int32_t ret = AllocEncodeParam(&items, number + 1, &asns, number);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    items[0].depth = 0;
    items[0].tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    BSL_Buffer **buffer = BSL_LIST_First(exku->oidList);
    for (uint32_t i = 0; i < number; i++) {
        if (buffer == NULL || *buffer == NULL || (*buffer)->dataLen == 0 || (*buffer)->data == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_EXTENDED_KU_ELE);
            ret = HITLS_X509_ERR_EXT_EXTENDED_KU_ELE;
            goto EXIT;
        }
        items[i + 1].depth = 1;
        items[i + 1].tag = BSL_ASN1_TAG_OBJECT_ID;
        asns[i].tag = BSL_ASN1_TAG_OBJECT_ID;
        asns[i].len = (*buffer)->dataLen;
        asns[i].buff = (*buffer)->data;
        buffer = BSL_LIST_Next(exku->oidList);
    }

    BSL_ASN1_Template templ = {items, number + 1};
    ret = BSL_ASN1_EncodeTemplate(&templ, asns, number, &entry->extnValue.buff, &entry->extnValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BSL_SAL_Free(items);
    BSL_SAL_Free(asns);
    return ret;
}

static int32_t SetExtCrlNumber(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    if (ext->type != HITLS_X509_EXT_TYPE_CRL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SET);
        return HITLS_X509_ERR_EXT_SET;
    }
    const HITLS_X509_ExtCrlNumber *crlNumber = (const HITLS_X509_ExtCrlNumber *)val;
    entry->critical = crlNumber->critical;

    if (crlNumber->crlNumber.dataLen < HITLS_X509_CRLNUMBER_MIN_LEN ||
        crlNumber->crlNumber.dataLen > HITLS_X509_CRLNUMBER_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_CRLNUMBER);
        return HITLS_X509_ERR_EXT_CRLNUMBER;
    }

    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_INTEGER, crlNumber->crlNumber.dataLen, crlNumber->crlNumber.data};
    BSL_ASN1_TemplateItem item = {BSL_ASN1_TAG_INTEGER, 0, 0};
    BSL_ASN1_Template templ = {&item, 1};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &entry->extnValue.buff, &entry->extnValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_X509_SetExtList(void *param, BslList *extList, BslCid cid, BSL_Buffer *val, EncodeExtCb encodeExt)
{
    HITLS_X509_ExtEntry *extEntry = NULL;
    bool isNew;
    int32_t ret = GetExtEntryByCid(extList, cid, &extEntry, &isNew);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = encodeExt(param, extEntry, val->data);
    if (ret != HITLS_PKI_SUCCESS) {
        FreeExtEntryCont(extEntry);
        if (isNew) {
            BSL_SAL_Free(extEntry);
        }
        return ret;
    }
    if (isNew) {
        ret = BSL_LIST_AddElement(extList, extEntry, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            FreeExtEntryCont(extEntry);
            BSL_SAL_Free(extEntry);
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t SetExt(HITLS_X509_Ext *ext, BslCid cid, BSL_Buffer *val, uint32_t expectLen, EncodeExtCb encodeExt)
{
    if ((ext->flag & HITLS_X509_EXT_FLAG_PARSE) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SET_AFTER_PARSE);
        return HITLS_X509_ERR_EXT_SET_AFTER_PARSE;
    }
    if (val->dataLen != expectLen) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    int32_t ret = HITLS_X509_SetExtList(ext, ext->extList, cid, val, encodeExt);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ext->flag |= HITLS_X509_EXT_FLAG_GEN;
    return ret;
}

static int32_t SetExtCtrl(HITLS_X509_Ext *ext, int32_t cmd, void *val, uint32_t valLen)
{
    BSL_Buffer buff = {val, valLen};
    switch (cmd) {
        case HITLS_X509_EXT_SET_BCONS:
            return SetExt(ext, BSL_CID_CE_BASICCONSTRAINTS, &buff, sizeof(HITLS_X509_ExtBCons),
                (EncodeExtCb)SetExtBCons);
        case HITLS_X509_EXT_SET_KUSAGE:
            return SetExt(ext, BSL_CID_CE_KEYUSAGE, &buff, sizeof(HITLS_X509_ExtKeyUsage), (EncodeExtCb)SetExtKeyUsage);
        case HITLS_X509_EXT_SET_AKI:
            return SetExt(ext, BSL_CID_CE_AUTHORITYKEYIDENTIFIER, &buff, sizeof(HITLS_X509_ExtAki),
                (EncodeExtCb)SetExtAki);
        case HITLS_X509_EXT_SET_SKI:
            return SetExt(ext, BSL_CID_CE_SUBJECTKEYIDENTIFIER, &buff, sizeof(HITLS_X509_ExtSki),
                (EncodeExtCb)SetExtSki);
        case HITLS_X509_EXT_SET_SAN:
            return SetExt(ext, BSL_CID_CE_SUBJECTALTNAME, &buff, sizeof(HITLS_X509_ExtSan),
                (EncodeExtCb)SetExtGeneralNames);
        case HITLS_X509_EXT_SET_EXKUSAGE:
            return SetExt(ext, BSL_CID_CE_EXTKEYUSAGE, &buff, sizeof(HITLS_X509_ExtExKeyUsage),
                (EncodeExtCb)SetExtExKeyUsage);
        case HITLS_X509_EXT_SET_CRLNUMBER:
            return SetExt(ext, BSL_CID_CE_CRLNUMBER, &buff, sizeof(HITLS_X509_ExtCrlNumber),
                (EncodeExtCb)SetExtCrlNumber);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

int32_t HITLS_X509_SetGeneralNames(HITLS_X509_ExtEntry *extEntry, void *val)
{
    if (extEntry == NULL || val == NULL) {
        return BSL_NULL_INPUT;
    }

    return SetExtGeneralNames(NULL, extEntry, val);
}
#endif

int32_t HITLS_X509_GetExt(BslList *ext, BslCid cid, BSL_Buffer *val, uint32_t expectLen, DecodeExtCb decodeExt)
{
    if (ext == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_NOT_FOUND);
        return HITLS_X509_ERR_EXT_NOT_FOUND;
    }
    if (val->dataLen != expectLen) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    HITLS_X509_ExtEntry *extEntry = BSL_LIST_Search(ext, &cid, CmpExtByCid, NULL);
    if (extEntry == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_NOT_FOUND);
        return HITLS_X509_ERR_EXT_NOT_FOUND;
    }
    return decodeExt(extEntry, val->data);
}

static int32_t GetExtKeyUsage(HITLS_X509_Ext *ext, uint32_t *val, uint32_t valLen)
{
    if (val == NULL || valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)ext->extData;
    *val = certExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE ? certExt->keyUsage : HITLS_X509_EXT_KU_NONE;
    return HITLS_PKI_SUCCESS;
}

static int32_t GetExtBCons(HITLS_X509_Ext *ext, uint32_t *val, uint32_t valLen)
{
    if (val == NULL || valLen != sizeof(HITLS_X509_ExtBCons)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    HITLS_X509_ExtBCons *bCons = (HITLS_X509_ExtBCons *)val;
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)ext->extData;
    if ((certExt->extFlags & HITLS_X509_EXT_FLAG_BCONS) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_NO_BCONS);
        return HITLS_X509_ERR_EXT_NO_BCONS;
    }
    BslCid cid = BSL_CID_CE_BASICCONSTRAINTS;
    HITLS_X509_ExtEntry *entry = BSL_LIST_Search(ext->extList, &cid, CmpExtByCid, NULL);
    if (entry == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_UNKNOWN_ERROR);
        return HITLS_X509_ERR_EXT_UNKNOWN_ERROR;
    }
    bCons->isCa = certExt->isCa;
    bCons->maxPathLen = certExt->maxPathLen;
    bCons->critical = entry->critical;
    return HITLS_PKI_SUCCESS;
}

static int32_t GetExtCtrl(HITLS_X509_Ext *ext, int32_t cmd, void *val, uint32_t valLen)
{
    BSL_Buffer buff = {val, valLen};
    switch (cmd) {
        case HITLS_X509_EXT_GET_SKI:
            return HITLS_X509_GetExt(ext->extList, BSL_CID_CE_SUBJECTKEYIDENTIFIER, &buff, sizeof(HITLS_X509_ExtSki),
                (DecodeExtCb)HITLS_X509_ParseSubjectKeyId);
        case HITLS_X509_EXT_GET_AKI:
            return HITLS_X509_GetExt(ext->extList, BSL_CID_CE_AUTHORITYKEYIDENTIFIER, &buff, sizeof(HITLS_X509_ExtAki),
                (DecodeExtCb)HITLS_X509_ParseAuthorityKeyId);
        case HITLS_X509_EXT_GET_CRLNUMBER:
            return HITLS_X509_GetExt(ext->extList, BSL_CID_CE_CRLNUMBER, &buff, sizeof(HITLS_X509_ExtCrlNumber),
                (DecodeExtCb)X509_ParseCrlNumber);
        case HITLS_X509_EXT_GET_KUSAGE:
            return GetExtKeyUsage(ext, val, valLen);
        case HITLS_X509_EXT_GET_BCONS:
            return GetExtBCons(ext, val, valLen);
        case HITLS_X509_EXT_GET_SAN:
            return HITLS_X509_GetExt(ext->extList, BSL_CID_CE_SUBJECTALTNAME, &buff, sizeof(HITLS_X509_ExtSan),
                (DecodeExtCb)HITLS_X509_ParseSubjectAltName);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

static int32_t CheckExtByCid(HITLS_X509_Ext *ext, int32_t cid, bool *val, uint32_t valLen)
{
    if (valLen != sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = BSL_LIST_Search(ext->extList, &cid, CmpExtByCid, NULL) != NULL;
    return HITLS_PKI_SUCCESS;
}

bool X509_CheckCmdValid(int32_t *cmdSet, uint32_t cmdSize, int32_t cmd)
{
    for (uint32_t i = 0; i < cmdSize; i++) {
        if (cmd == cmdSet[i]) {
            return true;
        }
    }
    return false;
}

int32_t X509_ExtCtrl(HITLS_X509_Ext *ext, int32_t cmd, void *val, uint32_t valLen)
{
#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CSR_GEN)
    if (cmd >= HITLS_X509_EXT_SET_SKI && cmd < HITLS_X509_EXT_GET_SKI) {
        return SetExtCtrl(ext, cmd, val, valLen);
    }
#endif
    if (cmd >= HITLS_X509_EXT_GET_SKI && cmd < HITLS_X509_EXT_CHECK_SKI) {
        return GetExtCtrl(ext, cmd, val, valLen);
    }
    if (cmd >= HITLS_X509_EXT_CHECK_SKI && cmd < HITLS_X509_CSR_GET_ATTRIBUTES) {
        return CheckExtByCid(ext, BSL_CID_CE_SUBJECTKEYIDENTIFIER, val, valLen);
    }
    BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
    return HITLS_X509_ERR_INVALID_PARAM;
}

int32_t HITLS_X509_ExtCtrl(HITLS_X509_Ext *ext, int32_t cmd, void *val, uint32_t valLen)
{
    if (ext == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (ext->type == HITLS_X509_EXT_TYPE_CERT || ext->type == HITLS_X509_EXT_TYPE_CRL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_UNSUPPORT);
        return HITLS_X509_ERR_EXT_UNSUPPORT;
    }
    static int32_t cmdSet[] = {HITLS_X509_EXT_SET_SKI, HITLS_X509_EXT_SET_AKI, HITLS_X509_EXT_SET_KUSAGE,
        HITLS_X509_EXT_SET_SAN, HITLS_X509_EXT_SET_BCONS, HITLS_X509_EXT_SET_EXKUSAGE, HITLS_X509_EXT_GET_SKI,
        HITLS_X509_EXT_GET_AKI, HITLS_X509_EXT_CHECK_SKI, HITLS_X509_EXT_GET_KUSAGE};
    if (!X509_CheckCmdValid(cmdSet, sizeof(cmdSet) / sizeof(int32_t), cmd)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_UNSUPPORT);
        return HITLS_X509_ERR_EXT_UNSUPPORT;
    }

    return X509_ExtCtrl(ext, cmd, val, valLen);
}

void HITLS_X509_ExtEntryFree(HITLS_X509_ExtEntry *entry)
{
    if (entry == NULL) {
        return;
    }
    BSL_SAL_FREE(entry->extnId.buff);
    BSL_SAL_FREE(entry->extnValue.buff);
    BSL_SAL_Free(entry);
}

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CSR_GEN)
/**
 * RFC 5280: section-4.1
 * Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }
 */
static BSL_ASN1_TemplateItem g_extSeqTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_BOOLEAN, BSL_ASN1_FLAG_DEFAULT, 1},
        {BSL_ASN1_TAG_OCTETSTRING, 1, 1},
};

#define X509_CRLEXT_ELEM_NUMBER 3
int32_t HITLS_X509_EncodeExtEntry(BSL_ASN1_List *list, BSL_ASN1_Buffer *ext)
{
    uint32_t count = (uint32_t)BSL_LIST_COUNT(list);
    BSL_ASN1_Buffer *asnBuf = BSL_SAL_Malloc(count * X509_CRLEXT_ELEM_NUMBER * sizeof(BSL_ASN1_Buffer));
    if (asnBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t iter = 0;
    HITLS_X509_ExtEntry *node = NULL;
    for (node = BSL_LIST_GET_FIRST(list); node != NULL; node = BSL_LIST_GET_NEXT(list)) {
        asnBuf[iter].tag = node->extnId.tag;
        asnBuf[iter].buff = node->extnId.buff;
        asnBuf[iter++].len = node->extnId.len;
        asnBuf[iter].tag = BSL_ASN1_TAG_BOOLEAN;
        asnBuf[iter].len = node->critical ? 1 : 0;
        asnBuf[iter++].buff = node->critical ? (uint8_t *)&(node->critical) : NULL;
        asnBuf[iter].tag = node->extnValue.tag;
        asnBuf[iter].buff = node->extnValue.buff;
        asnBuf[iter++].len = node->extnValue.len;
    }

    BSL_ASN1_Template templ = {g_extSeqTempl, sizeof(g_extSeqTempl) / sizeof(g_extSeqTempl[0])};
    int32_t ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, count, &templ, asnBuf, iter, ext);
    BSL_SAL_Free(asnBuf);
    return ret;
}

int32_t HITLS_X509_EncodeExt(uint8_t tag, BSL_ASN1_List *list, BSL_ASN1_Buffer *ext)
{
    if (BSL_LIST_COUNT(list) <= 0) {
        ext->tag = tag;
        ext->len = 0;
        ext->buff = NULL;
        return HITLS_PKI_SUCCESS;
    }
    BSL_ASN1_Buffer extbuff = {0};
    int32_t ret = HITLS_X509_EncodeExtEntry(list, &extbuff);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    BSL_ASN1_TemplateItem extTempl[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
    };
    BSL_ASN1_Template templ = {extTempl, 1};
    ret = BSL_ASN1_EncodeTemplate(&templ, &extbuff, 1, &(ext->buff), &(ext->len));
    BSL_SAL_Free(extbuff.buff);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ext->tag = tag;
    return HITLS_PKI_SUCCESS;
}
#endif // HITLS_PKI_X509_CRT_GEN || HITLS_PKI_X509_CRL_GEN || HITLS_PKI_X509_CSR_GEN

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CRL_GEN)
HITLS_X509_ExtEntry *X509_DupExtEntry(const HITLS_X509_ExtEntry *src)
{
    /* Src is not null. */
    HITLS_X509_ExtEntry *dest = BSL_SAL_Malloc(sizeof(HITLS_X509_ExtEntry));
    if (dest == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    dest->cid = src->cid;
    dest->critical = src->critical;

    // extId
    dest->extnId.tag = src->extnId.tag;
    dest->extnId.len = src->extnId.len;
    if (src->extnId.len != 0) {
        dest->extnId.buff = BSL_SAL_Dump(src->extnId.buff, src->extnId.len);
        if (dest->extnId.buff == NULL) {
            BSL_SAL_Free(dest);
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return NULL;
        }
    }
    // extnValue
    dest->extnValue.tag = src->extnValue.tag;
    dest->extnValue.len = src->extnValue.len;
    if (src->extnValue.len != 0) {
        dest->extnValue.buff = BSL_SAL_Dump(src->extnValue.buff, src->extnValue.len);
        if (dest->extnValue.buff == NULL) {
            BSL_SAL_Free(dest->extnId.buff);
            BSL_SAL_Free(dest);
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return NULL;
        }
    }
    return dest;
}
#endif

#ifdef HITLS_PKI_X509_CRT_GEN
int32_t HITLS_X509_ExtReplace(HITLS_X509_Ext *dest, HITLS_X509_Ext *src)
{
    if (dest == NULL || dest->extData == NULL || src == NULL || src->extData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if ((dest->flag & HITLS_X509_EXT_FLAG_PARSE) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SET_AFTER_PARSE);
        return HITLS_X509_ERR_EXT_SET_AFTER_PARSE;
    }
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)dest->extData;
    HITLS_X509_CertExt *srcExt = (HITLS_X509_CertExt *)src->extData;
    certExt->isCa = srcExt->isCa;
    certExt->maxPathLen = srcExt->maxPathLen;
    certExt->keyUsage = srcExt->keyUsage;
    certExt->extFlags = srcExt->extFlags;

    if (BSL_LIST_COUNT(src->extList) <= 0) {
        BSL_LIST_DeleteAll(dest->extList, (BSL_LIST_PFUNC_FREE)HITLS_X509_ExtEntryFree);
        return HITLS_PKI_SUCCESS;
    }
    BslList *list =
        BSL_LIST_Copy(src->extList, (BSL_LIST_PFUNC_DUP)X509_DupExtEntry, (BSL_LIST_PFUNC_FREE)HITLS_X509_ExtEntryFree);
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SET);
        return HITLS_X509_ERR_EXT_SET;
    }
    BSL_LIST_FREE(dest->extList, (BSL_LIST_PFUNC_FREE)HITLS_X509_ExtEntryFree);
    dest->extList = list;
    dest->flag |= HITLS_X509_EXT_FLAG_GEN;
    return HITLS_PKI_SUCCESS;
}
#endif

HITLS_X509_Ext *HITLS_X509_ExtNew(int32_t type)
{
    if (type == HITLS_X509_EXT_TYPE_CERT || type == HITLS_X509_EXT_TYPE_CRL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return NULL;
    }
    return X509_ExtNew(NULL, type);
}

void HITLS_X509_ExtFree(HITLS_X509_Ext *ext)
{
    X509_ExtFree(ext, true);
}
#endif // HITLS_PKI_X509
