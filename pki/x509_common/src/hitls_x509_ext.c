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

#include <string.h>
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
#include "bsl_sal.h"
#include "bsl_list.h"
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

#define HITLS_X509_CTX_SPECIFIC_TAG_CRLDP_DPNAME   0
#define HITLS_X509_CTX_SPECIFIC_TAG_CRLDP_REASONS  1
#define HITLS_X509_CTX_SPECIFIC_TAG_CRLDP_ISSUER   2

#define HITLS_X509_CTX_SPECIFIC_TAG_DPNAME_FULLNAME      0
#define HITLS_X509_CTX_SPECIFIC_TAG_DPNAME_RELATIVENAME  1

#define HITLS_X509_DPNAME_FULLNAME_TAG \
    (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_X509_CTX_SPECIFIC_TAG_DPNAME_FULLNAME)
#define HITLS_X509_DPNAME_RELATIVENAME_TAG \
    (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_X509_CTX_SPECIFIC_TAG_DPNAME_RELATIVENAME)

static BSL_ASN1_TemplateItem g_crlDpPointTempl[] = {
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_X509_CTX_SPECIFIC_TAG_CRLDP_DPNAME,
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_CRLDP_REASONS, BSL_ASN1_FLAG_OPTIONAL, 0},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_X509_CTX_SPECIFIC_TAG_CRLDP_ISSUER,
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
};

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

#define HITLS_X509_CTX_SPECIFIC_TAG_IDP_DISTPOINT 0
#define HITLS_X509_CTX_SPECIFIC_TAG_IDP_ONLYUSER 1
#define HITLS_X509_CTX_SPECIFIC_TAG_IDP_ONLYCA 2
#define HITLS_X509_CTX_SPECIFIC_TAG_IDP_REASONS 3
#define HITLS_X509_CTX_SPECIFIC_TAG_IDP_INDIRECTCRL 4
#define HITLS_X509_CTX_SPECIFIC_TAG_IDP_ONLYATTR 5

#define HITLS_X509_IDP_DISTPOINT_TAG \
    (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_X509_CTX_SPECIFIC_TAG_IDP_DISTPOINT)

static BSL_ASN1_TemplateItem g_idpTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {HITLS_X509_IDP_DISTPOINT_TAG, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_IDP_ONLYUSER, BSL_ASN1_FLAG_DEFAULT, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_IDP_ONLYCA, BSL_ASN1_FLAG_DEFAULT, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_IDP_REASONS, BSL_ASN1_FLAG_OPTIONAL, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_IDP_INDIRECTCRL, BSL_ASN1_FLAG_DEFAULT, 1},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_IDP_ONLYATTR, BSL_ASN1_FLAG_DEFAULT, 1},
};

static BSL_ASN1_TemplateItem g_idpDistPointNameTempl[] = {
    {BSL_ASN1_TAG_CHOICE, 0, 0},
};

typedef enum {
    HITLS_X509_EXT_IDP_DISTPOINT_IDX,
    HITLS_X509_EXT_IDP_ONLYUSER_IDX,
    HITLS_X509_EXT_IDP_ONLYCA_IDX,
    HITLS_X509_EXT_IDP_REASONS_IDX,
    HITLS_X509_EXT_IDP_INDIRECTCRL_IDX,
    HITLS_X509_EXT_IDP_ONLYATTR_IDX,
    HITLS_X509_EXT_IDP_MAX,
} HITLS_X509_EXT_IDP;

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CSR_GEN)
static int32_t SetExtGeneralNames(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val);
static int32_t EncodeGeneralNamesList(BslList *names, BSL_ASN1_Buffer *out);
static int32_t BuildGeneralNameAsns(BslList *names, BSL_ASN1_Buffer *asns);
static void FreeGnAsns(BSL_ASN1_Buffer *asns, uint32_t number);
#endif
static void FreeDistPointName(HITLS_X509_DistPointName *name);

typedef enum {
    HITLS_X509_EXT_CRLDP_DPNAME_IDX,
    HITLS_X509_EXT_CRLDP_REASONS_IDX,
    HITLS_X509_EXT_CRLDP_ISSUER_IDX,
    HITLS_X509_EXT_CRLDP_MAX,
} HITLS_X509_EXT_CRLDP;

static int32_t CmpExtByCid(const void *pExt, const void *pCid)
{
    const HITLS_X509_ExtEntry *ext = pExt;
    return ext->cid == *(const BslCid *)pCid ? 0 : 1;
}

static int32_t IdpDistPointNameTagCheck(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void)idx;
    if (type != BSL_ASN1_TYPE_CHECK_CHOICE_TAG) {
        return HITLS_X509_ERR_EXT_DISTPOINT;
    }

    uint8_t tag = *(uint8_t *)data;
    if (tag == HITLS_X509_DPNAME_FULLNAME_TAG || tag == HITLS_X509_DPNAME_RELATIVENAME_TAG) {
        *(uint8_t *)expVal = tag;
        return BSL_SUCCESS;
    }
    return HITLS_X509_ERR_EXT_DISTPOINT;
}

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

static uint8_t MaskBitStringUnusedBits(uint8_t octet, uint8_t unusedBits)
{
    return unusedBits == 0 ? octet : (uint8_t)(octet & (uint8_t)(0xFFu << unusedBits));
}

#if defined(HITLS_PKI_X509_CRT_PARSE) || defined(HITLS_PKI_X509_CRL_PARSE) || defined(HITLS_PKI_X509_CSR)
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
        uint8_t octet = bitString.buff[i];
        if (i + 1 == bitString.len) {
            octet = MaskBitStringUnusedBits(octet, bitString.unusedBits);
        }
        ext->keyUsage |= ((uint32_t)octet << (BITS_OF_BYTE * i));
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
        BSL_LIST_FREE(*list, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeParsedNameNode);
    }
    return ret;
}

static int32_t ParseSrvName(uint8_t **encode, uint32_t *encLen, uint32_t nameLen, BSL_Buffer *value, bool *isSrvName)
{
    uint8_t *buff = *encode;
    uint32_t buffLen = nameLen;
    uint32_t valueLen;
    *isSrvName = false;

    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OBJECT_ID, &buff, &buffLen, &valueLen);
    if (ret != BSL_SUCCESS) {
        return HITLS_PKI_SUCCESS;
    }
    if (BSL_OBJ_GetCidFromOidBuff(buff, valueLen) != BSL_CID_ON_DNSSRV) {
        return HITLS_PKI_SUCCESS;
    }
    buff += valueLen;
    buffLen -= valueLen;

    ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, &buff, &buffLen, &valueLen);
    if (ret != BSL_SUCCESS || buffLen != valueLen) {
        return ret != BSL_SUCCESS ? ret : HITLS_X509_ERR_PARSE_SAN_ITEM;
    }

    ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_IA5STRING, &buff, &buffLen, &valueLen);
    if (ret != BSL_SUCCESS || buffLen != valueLen) {
        return ret != BSL_SUCCESS ? ret : HITLS_X509_ERR_PARSE_SAN_ITEM;
    }

    value->data = buff;
    value->dataLen = valueLen;
    *isSrvName = true;
    *encode += nameLen;
    *encLen -= nameLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseGeneralName(uint8_t tag, uint8_t **encode, uint32_t *encLen, uint32_t nameLen, BslList *list)
{
    int32_t type = -1;
    int32_t ret;
    BslList *dirNames = NULL;
    BSL_Buffer value = {0};
    bool isSrvName = false;
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
    } else if (tag == HITLS_X509_GENERALNAME_OTHER_TAG) {
        ret = ParseSrvName(encode, encLen, nameLen, &value, &isSrvName);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        if (isSrvName) {
            type = HITLS_X509_GN_SRV;
        } else {
            value.data = *encode;
            value.dataLen = nameLen;
        }
    } else {
        value.data = *encode;
        value.dataLen = nameLen;
    }
    HITLS_X509_GeneralName *name = BSL_SAL_Calloc(1, sizeof(HITLS_X509_GeneralName));
    if (name == NULL) {
        BSL_LIST_FREE(dirNames, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeParsedNameNode);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    name->type = type;
    name->value = value;
    ret = BSL_LIST_AddElement(list, name, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_FREE(dirNames, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeParsedNameNode);
        BSL_SAL_Free(name);
    }
    return ret;
}

static void FreeGeneralName(void *data)
{
    HITLS_X509_GeneralName *name = (HITLS_X509_GeneralName *)data;
    if (name->type == HITLS_X509_GN_DNNAME) {
        BSL_LIST_DeleteAll((BslList *)(uintptr_t)name->value.data, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeParsedNameNode);
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

void HITLS_X509_FreeGeneralNames(BslList *names)
{
    BSL_LIST_DeleteAll(names, (BSL_LIST_PFUNC_FREE)FreeGeneralName);
    BSL_SAL_Free(names);
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
    ext->extList = BSL_LIST_New(sizeof(HITLS_X509_ExtEntry));
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
        // This initial value -1 cannot be modified because it is used in X509_CheckExt.
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

    if ((ext->type == HITLS_X509_EXT_TYPE_CERT || ext->type == HITLS_X509_EXT_TYPE_CSR) &&
        ext->extData != NULL) {
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

int32_t HITLS_X509_ParseGeneralNames(uint8_t *encode, uint32_t encLen, BslList **list)
{
    uint8_t *buff = encode;
    uint32_t buffLen = encLen;
    uint32_t nameValueLen;
    uint8_t tag;
    int32_t ret = HITLS_PKI_SUCCESS;
    BslList *tmpList = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    if (tmpList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

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
        // value
        uint8_t *nameBuff = buff;
        uint32_t nameBuffLen = nameValueLen;
        ret = ParseGeneralName(tag, &nameBuff, &nameBuffLen, nameValueLen, tmpList);
        if (ret != BSL_SUCCESS) {
            break;
        }
        if (tag == HITLS_X509_GENERALNAME_DIR_TAG && nameBuffLen != 0) {
            ret = HITLS_X509_ERR_PARSE_SAN_ITEM;
            break;
        }
        buff += nameValueLen;
        buffLen -= nameValueLen;
    }
    if (ret != BSL_SUCCESS) {
        HITLS_X509_FreeGeneralNames(tmpList);
        BSL_ERR_PUSH_ERROR(ret);
    } else {
        *list = tmpList;
    }
    return ret;
}

void HITLS_X509_ClearAuthorityKeyId(HITLS_X509_ExtAki *aki)
{
    if (aki == NULL) {
        return;
    }
    if (aki->issuerName != NULL) {
        HITLS_X509_FreeGeneralNames(aki->issuerName);
        aki->issuerName = NULL;
    }
}

int32_t HITLS_X509_ParseAuthorityKeyId(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtAki *aki)
{
    uint8_t *temp = extEntry->extnValue.buff;
    uint32_t tempLen = extEntry->extnValue.len;

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
        ret = HITLS_X509_ParseGeneralNames(
            asnArr[HITLS_X509_EXT_AKI_ISSUER_IDX].buff, asnArr[HITLS_X509_EXT_AKI_ISSUER_IDX].len, &aki->issuerName);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
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

static int32_t ParseBool(BSL_ASN1_Buffer *asn, bool *val)
{
    if (asn->tag == 0) {
        return HITLS_PKI_SUCCESS;
    }
    BSL_ASN1_Buffer boolAsn = {BSL_ASN1_TAG_BOOLEAN, asn->len, asn->buff};
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(&boolAsn, val);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static uint16_t ParseReasonFlags(BSL_ASN1_Buffer *asn)
{
    uint16_t reasons = 0;
    uint32_t octetCount = asn->len - 1;
    if (octetCount > sizeof(reasons)) {
        octetCount = sizeof(reasons);
    }
    for (uint32_t i = 0; i < octetCount; i++) {
        uint8_t octet = asn->buff[i + 1];
        if (i + 1 == octetCount) {
            octet = MaskBitStringUnusedBits(octet, asn->buff[0]);
        }
        reasons |= ((uint16_t)octet << (BITS_OF_BYTE * i));
    }
    return reasons & HITLS_X509_REASON_FLAG_ALL;
}

static int32_t ParseReasons(BSL_ASN1_Buffer *asn, bool *hasReasons, uint16_t *reasons)
{
    if (asn->tag == 0) {
        return HITLS_PKI_SUCCESS;
    }
    // Parse ReasonFlags leniently by truncating overlong octets to the uint16_t public model.
    if (asn->len == 0 || asn->buff == NULL || asn->buff[0] >= BITS_OF_BYTE) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_REASONFLAGS);
        return HITLS_X509_ERR_EXT_REASONFLAGS;
    }
    *hasReasons = true;
    *reasons = ParseReasonFlags(asn);
    return HITLS_PKI_SUCCESS;
}

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CSR_GEN)
static int32_t EncodeRawTlv(uint8_t tag, uint8_t *value, uint32_t valueLen, BSL_ASN1_Buffer *out)
{
    BSL_ASN1_Buffer asn = {tag, valueLen, value};
    BSL_ASN1_TemplateItem item = {tag, 0, 0};
    BSL_ASN1_Template templ = {&item, 1};
    return BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &out->buff, &out->len);
}

static int32_t EncodeGeneralNamesContent(BslList *names, BSL_ASN1_Buffer *out)
{
    BSL_ASN1_Buffer generalNames = {0};

    int32_t ret = EncodeGeneralNamesList(names, &generalNames);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = EncodeRawTlv(HITLS_X509_DPNAME_FULLNAME_TAG, generalNames.buff, generalNames.len, out);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_Free(generalNames.buff);
    return ret;
}

static int32_t CheckDistPointNameList(const BslList *name, int32_t expectSize)
{
    if (name == NULL || BSL_LIST_COUNT(name) == 0 || name->dataSize != expectSize) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
        return HITLS_X509_ERR_EXT_DISTPOINT;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckSingleRdnList(BslList *name)
{
    if (BSL_LIST_COUNT(name) <= 1) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
        return HITLS_X509_ERR_EXT_DISTPOINT;
    }

    BslListNode *node = BSL_LIST_FirstNode(name);
    HITLS_X509_NameNode *nameNode = (HITLS_X509_NameNode *)BSL_LIST_GetData(node);
    if (nameNode == NULL || nameNode->layer != 1) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
        return HITLS_X509_ERR_EXT_DISTPOINT;
    }

    for (node = BSL_LIST_GetNextNode(name, node); node != NULL; node = BSL_LIST_GetNextNode(name, node)) {
        nameNode = (HITLS_X509_NameNode *)BSL_LIST_GetData(node);
        if (nameNode == NULL || nameNode->layer != 2) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
            return HITLS_X509_ERR_EXT_DISTPOINT;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeRelativeNameContent(BslList *name, BSL_ASN1_Buffer *out)
{
    BSL_ASN1_Buffer rdn = {0};
    const BslListNode *rdnNode = NULL;
    const BslListNode *nextRdnNode = NULL;

    int32_t ret = CheckSingleRdnList(name);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    rdnNode = BSL_LIST_FirstNode(name);
    ret = X509_EncodeRdName(name, rdnNode, &rdn, &nextRdnNode);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = EncodeRawTlv(HITLS_X509_DPNAME_RELATIVENAME_TAG, rdn.buff, rdn.len, out);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_Free(rdn.buff);
    return ret;
}

static int32_t EncodeIdpDistPoint(const HITLS_X509_DistPointName *distPoint, BSL_ASN1_Buffer *out)
{
    BSL_ASN1_Buffer inner = {0};
    int32_t ret;

    switch (distPoint->type) {
        case HITLS_X509_DP_FULLNAME:
            ret = CheckDistPointNameList(distPoint->name, (int32_t)sizeof(HITLS_X509_GeneralName));
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
            ret = EncodeGeneralNamesContent(distPoint->name, &inner);
            break;
        case HITLS_X509_DP_RELATIVENAME:
            ret = CheckDistPointNameList(distPoint->name, (int32_t)sizeof(HITLS_X509_NameNode));
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
            ret = EncodeRelativeNameContent(distPoint->name, &inner);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
            return HITLS_X509_ERR_EXT_DISTPOINT;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    out->tag = HITLS_X509_IDP_DISTPOINT_TAG;
    out->len = inner.len;
    out->buff = inner.buff;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeReasonFlags(uint16_t reasons, uint8_t tag, BSL_ASN1_Buffer *asn, uint8_t *reasonBuff)
{
    if ((reasons & ~HITLS_X509_REASON_FLAG_ALL) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_REASONFLAGS);
        return HITLS_X509_ERR_EXT_REASONFLAGS;
    }

    uint8_t bsBuff[2] = {(uint8_t)reasons, (uint8_t)(reasons >> BITS_OF_BYTE)};
    BSL_ASN1_BitString bs = {bsBuff, 0, 0};
    bs.len = (reasons == 0) ? 0 : ((reasons & HITLS_X509_REASON_FLAG_AA_COMPROMISE) == 0 ? 1 : 2);
    if (bs.len != 0) {
        uint8_t tmp = bs.len == 1 ? (uint8_t)reasons : (uint8_t)(reasons >> BITS_OF_BYTE);
        for (int32_t i = 1; i < BITS_OF_BYTE; i++) {
            if ((uint8_t)(tmp << i) == 0) {
                bs.unusedBits = BITS_OF_BYTE - i;
                break;
            }
        }
    }
    reasonBuff[0] = bs.unusedBits;
    for (uint32_t i = 0; i < bs.len; i++) {
        reasonBuff[i + 1] = bs.buff[i];
    }
    asn->tag = tag;
    asn->len = bs.len + 1;
    asn->buff = reasonBuff;
    return HITLS_PKI_SUCCESS;
}

static int32_t SetExtIdp(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    if (ext->type != HITLS_X509_EXT_TYPE_CRL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SET);
        return HITLS_X509_ERR_EXT_SET;
    }
    const HITLS_X509_ExtIdp *idp = (const HITLS_X509_ExtIdp *)val;
    /*
     * RFC5280 5.2.5 Issuing Distribution Point
     * The issuing distribution point is a critical CRL extension that identifies the CRL...
     */
    if (!idp->critical) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SET);
        return HITLS_X509_ERR_EXT_SET;
    }
    int32_t ret = HITLS_X509_CheckIdp(idp);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    uint8_t boolTrue = 0xFF;
    uint8_t reasonBuff[3] = {0};

    BSL_ASN1_Buffer asns[] = {
        {0},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_IDP_ONLYUSER,
            idp->onlyContainsUserCerts ? sizeof(boolTrue) : 0,
            idp->onlyContainsUserCerts ? &boolTrue : NULL},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_IDP_ONLYCA,
            idp->onlyContainsCACerts ? sizeof(boolTrue) : 0,
            idp->onlyContainsCACerts ? &boolTrue : NULL},
        {0},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_IDP_INDIRECTCRL,
            idp->indirectCrl ? sizeof(boolTrue) : 0,
            idp->indirectCrl ? &boolTrue : NULL},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_IDP_ONLYATTR,
            idp->onlyContainsAttributeCerts ? sizeof(boolTrue) : 0,
            idp->onlyContainsAttributeCerts ? &boolTrue : NULL},
    };
    BSL_ASN1_Template templ = {g_idpTempl, sizeof(g_idpTempl) / sizeof(g_idpTempl[0])};

    if (idp->distPoint != NULL) {
        ret = EncodeIdpDistPoint(idp->distPoint, &asns[HITLS_X509_EXT_IDP_DISTPOINT_IDX]);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    if (idp->hasReasons) {
        ret = EncodeReasonFlags(idp->onlySomeReasons,
            BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_IDP_REASONS,
            &asns[HITLS_X509_EXT_IDP_REASONS_IDX], reasonBuff);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
    }

    ret = BSL_ASN1_EncodeTemplate(&templ, asns, HITLS_X509_EXT_IDP_MAX, &entry->extnValue.buff,
        &entry->extnValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    entry->critical = true;
EXIT:
    BSL_SAL_Free(asns[HITLS_X509_EXT_IDP_DISTPOINT_IDX].buff);
    return ret;
}
#endif

void HITLS_X509_ClearIdp(HITLS_X509_ExtIdp *idp)
{
    if (idp == NULL) {
        return;
    }
    FreeDistPointName(idp->distPoint);
    idp->distPoint = NULL;
}

static int32_t DupAsn1Buffer(const BSL_ASN1_Buffer *src, BSL_ASN1_Buffer *dest)
{
    dest->tag = src->tag;
    dest->len = src->len;
    if (src->len == 0) {
        return HITLS_PKI_SUCCESS;
    }
    dest->buff = BSL_SAL_Dump(src->buff, src->len);
    if (dest->buff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t NewRelativeNameNode(const BSL_ASN1_Buffer *type, const BSL_ASN1_Buffer *val,
    HITLS_X509_NameNode **out)
{
    HITLS_X509_NameNode *node = BSL_SAL_Calloc(1, sizeof(HITLS_X509_NameNode));
    if (node == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    node->layer = 2;
    int32_t ret = DupAsn1Buffer(type, &node->nameType);
    if (ret == HITLS_PKI_SUCCESS) {
        ret = DupAsn1Buffer(val, &node->nameValue);
    }
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_FreeNameNode(node);
        return ret;
    }
    *out = node;
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseRelativeNameAsnItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *cbParam, BSL_ASN1_List *list)
{
    (void)layer;
    (void)cbParam;

    HITLS_X509_NameNode parsedNode = {0};
    HITLS_X509_NameNode *node = NULL;

    int32_t ret = HITLS_X509_ParseNameNode(asn, &parsedNode);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = NewRelativeNameNode(&parsedNode.nameType, &parsedNode.nameValue, &node);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_LIST_AddElement(list, node, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_X509_FreeNameNode(node);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseRelativeName(uint8_t *encode, uint32_t encLen, BslList **list)
{
    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {1, expTag};
    BslList *name = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (name == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_X509_AddDnNameLayer1(name);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, encLen, encode};
    ret = BSL_ASN1_DecodeListItem(&listParam, &asn, ParseRelativeNameAsnItem, NULL, name);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    *list = name;
    return HITLS_PKI_SUCCESS;
ERR:
    HITLS_X509_DnListFree(name);
    return ret;
}

static int32_t ParseDistPointName(BSL_ASN1_Buffer *asn, HITLS_X509_DistPointName **distPointName)
{
    if (asn->tag == 0) {
        return HITLS_PKI_SUCCESS;
    }

    uint8_t *tmp = asn->buff;
    uint32_t tmpLen = asn->len;
    BSL_ASN1_Buffer dpName = {0};
    BSL_ASN1_Template templ = {g_idpDistPointNameTempl,
        sizeof(g_idpDistPointNameTempl) / sizeof(g_idpDistPointNameTempl[0])};
    if (tmpLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
        return HITLS_X509_ERR_EXT_DISTPOINT;
    }
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, IdpDistPointNameTagCheck, &tmp, &tmpLen, &dpName, 1);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (tmpLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_EXT_BUF);
        return HITLS_X509_ERR_PARSE_EXT_BUF;
    }

    *distPointName = BSL_SAL_Calloc(1, sizeof(**distPointName));
    if (*distPointName == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    if (dpName.tag == HITLS_X509_DPNAME_FULLNAME_TAG) {
        (*distPointName)->type = HITLS_X509_DP_FULLNAME;
        ret = HITLS_X509_ParseGeneralNames(dpName.buff, dpName.len, &(*distPointName)->name);
    } else if (dpName.tag == HITLS_X509_DPNAME_RELATIVENAME_TAG) {
        (*distPointName)->type = HITLS_X509_DP_RELATIVENAME;
        ret = ParseRelativeName(dpName.buff, dpName.len, &(*distPointName)->name);
    } else {
        ret = HITLS_X509_ERR_EXT_DISTPOINT;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        FreeDistPointName(*distPointName);
        *distPointName = NULL;
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_ParseIdp(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtIdp *idp)
{
    uint8_t *temp = extEntry->extnValue.buff;
    uint32_t tempLen = extEntry->extnValue.len;
    BSL_ASN1_Buffer asnArr[HITLS_X509_EXT_IDP_MAX] = {0};
    BSL_ASN1_Template templ = {g_idpTempl, sizeof(g_idpTempl) / sizeof(g_idpTempl[0])};

    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_X509_EXT_IDP_MAX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (tempLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_EXT_BUF);
        return HITLS_X509_ERR_PARSE_EXT_BUF;
    }

    ret = ParseDistPointName(&asnArr[HITLS_X509_EXT_IDP_DISTPOINT_IDX], &idp->distPoint);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = ParseBool(&asnArr[HITLS_X509_EXT_IDP_ONLYUSER_IDX], &idp->onlyContainsUserCerts);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = ParseBool(&asnArr[HITLS_X509_EXT_IDP_ONLYCA_IDX], &idp->onlyContainsCACerts);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = ParseReasons(&asnArr[HITLS_X509_EXT_IDP_REASONS_IDX], &idp->hasReasons, &idp->onlySomeReasons);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = ParseBool(&asnArr[HITLS_X509_EXT_IDP_INDIRECTCRL_IDX], &idp->indirectCrl);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = ParseBool(&asnArr[HITLS_X509_EXT_IDP_ONLYATTR_IDX], &idp->onlyContainsAttributeCerts);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    idp->critical = extEntry->critical;
    return HITLS_PKI_SUCCESS;
EXIT:
    HITLS_X509_ClearIdp(idp);
    return ret;
}

int32_t HITLS_X509_CheckIdp(const HITLS_X509_ExtIdp *idp)
{
    if (idp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    uint32_t onlyCount = 0;
    if (idp->onlyContainsUserCerts) {
        onlyCount++;
    }
    if (idp->onlyContainsCACerts) {
        onlyCount++;
    }
    if (idp->onlyContainsAttributeCerts) {
        onlyCount++;
    }
    if (onlyCount > 1) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_IDP);
        return HITLS_X509_ERR_EXT_IDP;
    }

    if (idp->distPoint != NULL) {
        if (idp->distPoint->type != HITLS_X509_DP_FULLNAME &&
            idp->distPoint->type != HITLS_X509_DP_RELATIVENAME) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
            return HITLS_X509_ERR_EXT_DISTPOINT;
        }
        if (idp->distPoint->name == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
            return HITLS_X509_ERR_EXT_DISTPOINT;
        }
    }

    /*
     * RFC 5280 requires at least distributionPoint or onlySomeReasons if all
     * scope booleans are FALSE.
     */
    if (idp->distPoint == NULL && !idp->hasReasons &&
        !idp->onlyContainsUserCerts && !idp->onlyContainsCACerts && !idp->indirectCrl &&
        !idp->onlyContainsAttributeCerts) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_IDP);
        return HITLS_X509_ERR_EXT_IDP;
    }

    return HITLS_PKI_SUCCESS;
}

#if defined(HITLS_PKI_X509_CRT_PARSE) || defined(HITLS_PKI_X509_CSR) || defined(HITLS_PKI_X509_CRL_PARSE) || \
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
    int32_t ret = BSL_LIST_AddElement(list, buff, BSL_LIST_POS_END);
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
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteAll(list, NULL);
        BSL_SAL_Free(list);
        return ret;
    }

    exku->critical = extEntry->critical;
    exku->oidList = list;
    return ret;
}
#endif

void HITLS_X509_ClearExtendedKeyUsage(HITLS_X509_ExtExKeyUsage *exku)
{
    if (exku == NULL) {
        return;
    }
    BSL_LIST_FREE(exku->oidList, NULL);
}

void HITLS_X509_ClearSubjectAltName(HITLS_X509_ExtSan *san)
{
    if (san == NULL) {
        return;
    }
    if (san->names != NULL) {
        HITLS_X509_FreeGeneralNames(san->names);
        san->names = NULL;
    }
}

static void FreeDistPointName(HITLS_X509_DistPointName *name)
{
    if (name == NULL) {
        return;
    }
    if (name->type == HITLS_X509_DP_FULLNAME) {
        HITLS_X509_FreeGeneralNames(name->name);
    } else if (name->type == HITLS_X509_DP_RELATIVENAME) {
        HITLS_X509_DnListFree(name->name);
    }
    BSL_SAL_Free(name);
}

static void FreeCrlDpPoint(void *data)
{
    HITLS_X509_CrlDistPoint *point = (HITLS_X509_CrlDistPoint *)data;
    if (point == NULL) {
        return;
    }
    FreeDistPointName(point->distPointName);
    HITLS_X509_FreeGeneralNames(point->crlIssuer);
    BSL_SAL_Free(point);
}

void HITLS_X509_ClearCdp(HITLS_X509_ExtCdp *cdp)
{
    if (cdp == NULL) {
        return;
    }
    BSL_LIST_FREE(cdp->points, (BSL_LIST_PFUNC_FREE)FreeCrlDpPoint);
}

static int32_t ParseDistPoint(uint8_t *encode, uint32_t encLen, HITLS_X509_CrlDistPoint *point)
{
    uint8_t *temp = encode;
    uint32_t tempLen = encLen;
    BSL_ASN1_Buffer asnArr[HITLS_X509_EXT_CRLDP_MAX] = {0};
    BSL_ASN1_Template templ = {g_crlDpPointTempl, sizeof(g_crlDpPointTempl) / sizeof(g_crlDpPointTempl[0])};

    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_X509_EXT_CRLDP_MAX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (tempLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_CRLDP);
        return HITLS_X509_ERR_PARSE_CRLDP;
    }

    ret = ParseDistPointName(&asnArr[HITLS_X509_EXT_CRLDP_DPNAME_IDX], &point->distPointName);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = ParseReasons(&asnArr[HITLS_X509_EXT_CRLDP_REASONS_IDX], &point->hasReasons, &point->reasons);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (asnArr[HITLS_X509_EXT_CRLDP_ISSUER_IDX].tag != 0) {
        ret = HITLS_X509_ParseGeneralNames(asnArr[HITLS_X509_EXT_CRLDP_ISSUER_IDX].buff,
            asnArr[HITLS_X509_EXT_CRLDP_ISSUER_IDX].len, &point->crlIssuer);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseCrlDpSeqOf(uint32_t layer, BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    (void)param;
    if (layer == 1) {
        return HITLS_PKI_SUCCESS;
    }

    HITLS_X509_CrlDistPoint *point = BSL_SAL_Calloc(1, sizeof(HITLS_X509_CrlDistPoint));
    if (point == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = ParseDistPoint(asn->buff, asn->len, point);
    if (ret != HITLS_PKI_SUCCESS) {
        FreeCrlDpPoint(point);
        return ret;
    }
    ret = BSL_LIST_AddElement(list, point, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        FreeCrlDpPoint(point);
    }
    return ret;
}

int32_t HITLS_X509_ParseCdp(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtCdp *crldp)
{
    if (crldp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    crldp->critical = false;
    crldp->points = NULL;
    BslList *points = BSL_LIST_New(sizeof(HITLS_X509_CrlDistPoint));
    if (points == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
                        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {sizeof(expTag) / sizeof(uint8_t), expTag};
    int32_t ret = BSL_ASN1_DecodeListItem(&listParam, &extEntry->extnValue, ParseCrlDpSeqOf, NULL, points);
    if (ret != BSL_SUCCESS) {
        goto ERR;
    }

    crldp->critical = extEntry->critical;
    crldp->points = points;
    return HITLS_PKI_SUCCESS;
ERR:
    BSL_LIST_FREE(points, (BSL_LIST_PFUNC_FREE)FreeCrlDpPoint);
    return ret;
}

/*
 * RFC 5280 4.2.1.13 cRLDistributionPoints:
 * "While each of these fields is optional, a DistributionPoint MUST NOT consist of only the reasons field;
 * either distributionPoint or cRLIssuer MUST be present."
 */
int32_t HITLS_X509_CheckCdp(const HITLS_X509_ExtCdp *crldp)
{
    for (BslListNode *node = BSL_LIST_FirstNode(crldp->points); node != NULL;
        node = BSL_LIST_GetNextNode(crldp->points, node)) {
        const HITLS_X509_CrlDistPoint *point = (const HITLS_X509_CrlDistPoint *)BSL_LIST_GetData(node);
        if (point->distPointName != NULL) {
            continue;
        }
        if (point->crlIssuer == NULL || BSL_LIST_COUNT(point->crlIssuer) <= 0) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRLDP_INVALID);
            return HITLS_X509_ERR_CRLDP_INVALID;
        }
    }
    return HITLS_PKI_SUCCESS;
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

    ret = HITLS_X509_ParseGeneralNames(buff, len, &san->names);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
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
    BSL_ERR_SET_MARK();
    extEntry->cid = BSL_OBJ_GetCidFromOidBuff(extEntry->extnId.buff, extEntry->extnId.len);
    BSL_ERR_POP_TO_MARK();
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
    if (BSL_LIST_SearchDataConst(list, &extEntry.extnId, HITLS_X509_CmpExtByOid, NULL) != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PARSE_EXT_REPEAT);
        return HITLS_X509_ERR_PARSE_EXT_REPEAT;
    }

    // Add the extension to list.
    ret =  HITLS_X509_AddListItemDefault(&extEntry, sizeof(HITLS_X509_ExtEntry), list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_ERR_SET_MARK();
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
            BSL_ERR_POP_TO_MARK();
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
    certExt->keyUsage = keyUsage;
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

static inline void SetAsn1Buffer(BSL_Buffer *value, uint8_t tag, BSL_ASN1_Buffer *asn)
{
    asn->tag = tag;
    asn->len = value->dataLen;
    asn->buff = value->data;
}

static void FreeGnAsns(BSL_ASN1_Buffer *asns, uint32_t number)
{
    for (uint32_t i = 0; i < number; i++) {
        if (asns[i].tag == HITLS_X509_GENERALNAME_DIR_TAG || asns[i].tag == HITLS_X509_GENERALNAME_OTHER_TAG) {
            BSL_SAL_Free(asns[i].buff);
        }
    }
    BSL_SAL_Free(asns);
}

static int32_t EncodeSrvNameValue(const BSL_Buffer *value, BSL_ASN1_Buffer *extnValue)
{
    if (value->dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SAN_ELE);
        return HITLS_X509_ERR_EXT_SAN_ELE;
    }
    BslOidString *srvNameOid = BSL_OBJ_GetOID(BSL_CID_ON_DNSSRV);
    if (srvNameOid == NULL || srvNameOid->octs == NULL || srvNameOid->octetLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_OID);
        return HITLS_X509_ERR_EXT_OID;
    }
    BSL_ASN1_TemplateItem items[] = {
        {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, 0, 0},
        {BSL_ASN1_TAG_IA5STRING, 0, 1},
    };
    BSL_ASN1_Buffer asns[] = {
        {BSL_ASN1_TAG_OBJECT_ID, srvNameOid->octetLen, (uint8_t *)srvNameOid->octs},
        {BSL_ASN1_TAG_IA5STRING, value->dataLen, value->data},
    };
    BSL_ASN1_Template templ = {items, sizeof(items) / sizeof(items[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, asns, sizeof(asns) / sizeof(asns[0]),
        &extnValue->buff, &extnValue->len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    extnValue->tag = HITLS_X509_GENERALNAME_OTHER_TAG;
    return HITLS_PKI_SUCCESS;
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

static void SetGnTemplateItems(BSL_ASN1_TemplateItem *items, const BSL_ASN1_Buffer *asns, uint32_t number)
{
    for (uint32_t i = 0; i < number; i++) {
        items[i].tag = asns[i].tag;
        items[i].depth = 1;
    }
}

static int32_t BuildGeneralNameAsns(BslList *names, BSL_ASN1_Buffer *asns)
{
    BSL_ASN1_Buffer *asn = asns;
    int32_t ret;
    for (BslListNode *nameNode = BSL_LIST_FirstNode(names); nameNode != NULL;
        nameNode = BSL_LIST_GetNextNode(names, nameNode)) {
        HITLS_X509_GeneralName *name = (HITLS_X509_GeneralName *)BSL_LIST_GetData(nameNode);
        if (name->value.data == NULL || name->value.dataLen == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SAN_ELE);
            return HITLS_X509_ERR_EXT_SAN_ELE;
        }
        switch (name->type) {
            case HITLS_X509_GN_EMAIL:
                SetAsn1Buffer(&name->value, HITLS_X509_GENERALNAME_RFC822_TAG, asn);
                break;
            case HITLS_X509_GN_DNS:
                SetAsn1Buffer(&name->value, HITLS_X509_GENERALNAME_DNS_TAG, asn);
                break;
            case HITLS_X509_GN_DNNAME:
                ret = EncodeGnDirNameValue((BSL_ASN1_List *)(uintptr_t)name->value.data, asn);
                if (ret != HITLS_PKI_SUCCESS) {
                    return ret;
                }
                break;
            case HITLS_X509_GN_URI:
                SetAsn1Buffer(&name->value, HITLS_X509_GENERALNAME_URI_TAG, asn);
                break;
            case HITLS_X509_GN_IP:
                SetAsn1Buffer(&name->value, HITLS_X509_GENERALNAME_IP_TAG, asn);
                break;
            case HITLS_X509_GN_SRV:
                ret = EncodeSrvNameValue(&name->value, asn);
                if (ret != HITLS_PKI_SUCCESS) {
                    return ret;
                }
                break;
            default:
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_GN_UNSUPPORT);
                return HITLS_X509_ERR_EXT_GN_UNSUPPORT;
        }
        asn++;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeGeneralNamesList(BslList *names, BSL_ASN1_Buffer *out)
{
    uint32_t number = (uint32_t)BSL_LIST_COUNT(names);
    BSL_ASN1_Buffer *asns = BSL_SAL_Calloc(number, sizeof(BSL_ASN1_Buffer));
    if (asns == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    BSL_ASN1_TemplateItem item = {BSL_ASN1_TAG_ANY, 0, 0};
    BSL_ASN1_Template templ = {&item, 1};
    int32_t ret = BuildGeneralNameAsns(names, asns);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, number, &templ, asns, number, out);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    FreeGnAsns(asns, number);
    return ret;
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
    ret = BuildGeneralNameAsns(san->names, asns);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    SetGnTemplateItems(items + 1, asns, number);

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
    uint32_t i = 0;
    for (BslListNode *oidNode = BSL_LIST_FirstNode(exku->oidList); oidNode != NULL;
        oidNode = BSL_LIST_GetNextNode(exku->oidList, oidNode), i++) {
        BSL_Buffer *buffer = (BSL_Buffer *)BSL_LIST_GetData(oidNode);
        if (buffer == NULL || buffer->dataLen == 0 || buffer->data == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_EXTENDED_KU_ELE);
            ret = HITLS_X509_ERR_EXT_EXTENDED_KU_ELE;
            goto EXIT;
        }
        items[i + 1].depth = 1;
        items[i + 1].tag = BSL_ASN1_TAG_OBJECT_ID;
        asns[i].tag = BSL_ASN1_TAG_OBJECT_ID;
        asns[i].len = buffer->dataLen;
        asns[i].buff = buffer->data;
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

static int32_t SetExtDeltaCrl(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    const HITLS_X509_ExtDeltaCrl *delta = (const HITLS_X509_ExtDeltaCrl *)val;

    /*
     * RFC5280 5.2.4 Delta CRL Indicator
     * The delta CRL indicator is a critical CRL extension that identifies a CRL as being a delta CRL.
     */
    if (!delta->critical) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SET);
        return HITLS_X509_ERR_EXT_SET;
    }
    return SetExtCrlNumber(ext, entry, val);
}

static int32_t CheckDistPointNameForEncode(const HITLS_X509_DistPointName *name)
{
    if (name == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    switch (name->type) {
        case HITLS_X509_DP_FULLNAME:
            return CheckDistPointNameList(name->name, (int32_t)sizeof(HITLS_X509_GeneralName));
        case HITLS_X509_DP_RELATIVENAME: {
            int32_t ret = CheckDistPointNameList(name->name, (int32_t)sizeof(HITLS_X509_NameNode));
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
            return CheckSingleRdnList(name->name);
        }
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
            return HITLS_X509_ERR_EXT_DISTPOINT;
    }
}

static int32_t CheckReasonsForEncode(bool hasReasons, uint16_t reasons)
{
    if (!hasReasons) {
        return HITLS_PKI_SUCCESS;
    }
    if ((reasons & ~HITLS_X509_REASON_FLAG_ALL) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
        return HITLS_X509_ERR_EXT_DISTPOINT;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckCrlDpPointForEncode(const HITLS_X509_CrlDistPoint *point)
{
    if (point == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
        return HITLS_X509_ERR_EXT_DISTPOINT;
    }
    int32_t ret = CheckDistPointNameForEncode(point->distPointName);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CheckReasonsForEncode(point->hasReasons, point->reasons);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (point->crlIssuer != NULL) {
        return CheckDistPointNameList(point->crlIssuer, (int32_t)sizeof(HITLS_X509_GeneralName));
    }
    /* CDP encoding does not support all three optional DistributionPoint fields being absent. */
    if (point->distPointName == NULL && !point->hasReasons) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_DISTPOINT);
        return HITLS_X509_ERR_EXT_DISTPOINT;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckCrlDpForEncode(const HITLS_X509_ExtCdp *crldp)
{
    if (crldp == NULL || crldp->points == NULL || crldp->points->dataSize != sizeof(HITLS_X509_CrlDistPoint) ||
        BSL_LIST_COUNT(crldp->points) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_CRLDP);
        return HITLS_X509_ERR_EXT_CRLDP;
    }

    for (BslListNode *node = BSL_LIST_FirstNode(crldp->points); node != NULL;
        node = BSL_LIST_GetNextNode(crldp->points, node)) {
        int32_t ret = CheckCrlDpPointForEncode((const HITLS_X509_CrlDistPoint *)BSL_LIST_GetData(node));
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeDistPointName(const HITLS_X509_DistPointName *name, BSL_ASN1_Buffer *asn)
{
    int32_t ret;
    BSL_ASN1_Buffer inner = {0};

    if (name->type == HITLS_X509_DP_FULLNAME) {
        ret = EncodeGeneralNamesContent(name->name, &inner);
    } else {
        ret = EncodeRelativeNameContent(name->name, &inner);
    }
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    asn->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_X509_CTX_SPECIFIC_TAG_CRLDP_DPNAME;
    asn->len = inner.len;
    asn->buff = inner.buff;
    return HITLS_PKI_SUCCESS;
}

static int32_t EncodeDistPoint(const HITLS_X509_CrlDistPoint *point, BSL_ASN1_Buffer *out)
{
    int32_t ret;
    uint8_t reasonBuff[3] = {0};
    BSL_ASN1_Buffer fields[HITLS_X509_EXT_CRLDP_MAX] = {0};
    BSL_ASN1_Template templ = {g_crlDpPointTempl, sizeof(g_crlDpPointTempl) / sizeof(g_crlDpPointTempl[0])};

    if (point->distPointName != NULL) {
        ret = EncodeDistPointName(point->distPointName, &fields[HITLS_X509_EXT_CRLDP_DPNAME_IDX]);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
    }
    if (point->hasReasons) {
        ret = EncodeReasonFlags(point->reasons,
            BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_X509_CTX_SPECIFIC_TAG_CRLDP_REASONS,
            &fields[HITLS_X509_EXT_CRLDP_REASONS_IDX], reasonBuff);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
    }
    if (point->crlIssuer != NULL) {
        ret = EncodeGeneralNamesList(point->crlIssuer, &fields[HITLS_X509_EXT_CRLDP_ISSUER_IDX]);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
        fields[HITLS_X509_EXT_CRLDP_ISSUER_IDX].tag =
            BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_X509_CTX_SPECIFIC_TAG_CRLDP_ISSUER;
    }

    ret = BSL_ASN1_EncodeTemplate(&templ, fields, HITLS_X509_EXT_CRLDP_MAX, &out->buff, &out->len);
    if (ret != BSL_SUCCESS) {
        goto EXIT;
    }
    out->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
EXIT:
    BSL_SAL_Free(fields[HITLS_X509_EXT_CRLDP_DPNAME_IDX].buff);
    BSL_SAL_Free(fields[HITLS_X509_EXT_CRLDP_ISSUER_IDX].buff);
    return ret;
}

static int32_t SetExtCrlDp(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    BSL_ASN1_Buffer crlDpSeqOf = {0};
    if (ext->type == HITLS_X509_EXT_TYPE_CRL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_CRLDP);
        return HITLS_X509_ERR_EXT_CRLDP;
    }

    const HITLS_X509_ExtCdp *crldp = (const HITLS_X509_ExtCdp *)val;
    int32_t ret = CheckCrlDpForEncode(crldp);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_CheckCdp(crldp);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    uint32_t count = (uint32_t)BSL_LIST_COUNT(crldp->points);
    BSL_ASN1_Buffer *asnArr = BSL_SAL_Calloc(count, sizeof(BSL_ASN1_Buffer));
    if (asnArr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t index = 0;
    for (BslListNode *node = BSL_LIST_FirstNode(crldp->points); node != NULL;
        node = BSL_LIST_GetNextNode(crldp->points, node), index++) {
        ret = EncodeDistPoint((const HITLS_X509_CrlDistPoint *)BSL_LIST_GetData(node), &asnArr[index]);
        if (ret != BSL_SUCCESS) {
            goto EXIT;
        }
    }
    BSL_ASN1_TemplateItem crlDpPointTempl[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
    };
    BSL_ASN1_Template templ = {crlDpPointTempl, sizeof(crlDpPointTempl) / sizeof(crlDpPointTempl[0])};
    ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, count, &templ, asnArr, count, &crlDpSeqOf);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = EncodeRawTlv(crlDpSeqOf.tag, crlDpSeqOf.buff, crlDpSeqOf.len, &entry->extnValue);
    if (ret != BSL_SUCCESS) {
        goto EXIT;
    }
    entry->critical = crldp->critical;
    ret = HITLS_PKI_SUCCESS;
EXIT:
    BSL_SAL_Free(crlDpSeqOf.buff);
    for (uint32_t i = 0; i < count; i++) {
        BSL_SAL_Free(asnArr[i].buff);
    }
    BSL_SAL_Free(asnArr);
    return ret;
}

static int32_t SetExtGeneric(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, const void *val)
{
    (void)ext;
    const HITLS_X509_ExtGeneric *generic = (const HITLS_X509_ExtGeneric *)val;

    entry->critical = generic->critical;

    entry->extnValue.len = generic->value.dataLen;
    entry->extnValue.buff = BSL_SAL_Dump(generic->value.data, generic->value.dataLen);
    if (entry->extnValue.buff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    return HITLS_PKI_SUCCESS;
}

static HITLS_X509_ExtEntry *GetExtEntry(BslList *extList, BslCid cid, void *val)
{
    if (cid == BSL_CID_UNKNOWN) {
        HITLS_X509_ExtGeneric *generic = (HITLS_X509_ExtGeneric *)val;
        BSL_ASN1_Buffer oidBuf = {BSL_ASN1_TAG_OBJECT_ID, generic->oid.dataLen, generic->oid.data};
        return BSL_LIST_SearchDataConst(extList, &oidBuf, HITLS_X509_CmpExtByOid, NULL);
    }
    return BSL_LIST_SearchDataConst(extList, &cid, CmpExtByCid, NULL);
}

static int32_t GetOidBuffer(BslCid cid, void *val, BSL_Buffer *oidBuf)
{
    if (cid == BSL_CID_UNKNOWN) {
        HITLS_X509_ExtGeneric *generic = (HITLS_X509_ExtGeneric *)val;
        oidBuf->data = generic->oid.data;
        oidBuf->dataLen = generic->oid.dataLen;
        return HITLS_PKI_SUCCESS;
    }
    BslOidString *oid = BSL_OBJ_GetOID(cid);
    if (oid == NULL || oid->octetLen == 0 || oid->octs == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_OID);
        return HITLS_X509_ERR_EXT_OID;
    }
    oidBuf->data = (uint8_t *)oid->octs;
    oidBuf->dataLen = oid->octetLen;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_SetExtList(void *param, BslList *extList, BslCid cid, void *val, EncodeExtCb encodeExt)
{
    HITLS_X509_ExtEntry *existingEntry = GetExtEntry(extList, cid, val);
    int32_t ret;
    /* Replace existing extension */
    if (existingEntry != NULL) {
        HITLS_X509_ExtEntry tmpEntry = {0, {0}, false, {BSL_ASN1_TAG_OCTETSTRING, 0, NULL}};
        ret = encodeExt(param, &tmpEntry, val);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        BSL_SAL_Free(existingEntry->extnValue.buff);
        existingEntry->extnValue = tmpEntry.extnValue;
        existingEntry->critical = tmpEntry.critical;
        return HITLS_PKI_SUCCESS;
    }

    /* Add new extension */
    BSL_Buffer oidBuf = {0};
    if ((ret = GetOidBuffer(cid, val, &oidBuf)) != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    HITLS_X509_ExtEntry *newEntry = BSL_SAL_Calloc(1, sizeof(HITLS_X509_ExtEntry));
    if (newEntry == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    newEntry->cid = cid;
    newEntry->extnId.tag = BSL_ASN1_TAG_OBJECT_ID;
    newEntry->extnId.len = oidBuf.dataLen;
    newEntry->extnValue.tag = BSL_ASN1_TAG_OCTETSTRING;
    newEntry->extnId.buff = BSL_SAL_Dump(oidBuf.data, oidBuf.dataLen);
    if (newEntry->extnId.buff == NULL) {
        ret = BSL_DUMP_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if ((ret = encodeExt(param, newEntry, val)) != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if ((ret = BSL_LIST_AddElement(extList, newEntry, BSL_LIST_POS_END)) == BSL_SUCCESS) {
        return HITLS_PKI_SUCCESS;
    }
ERR:
    if (newEntry != NULL) {
        BSL_SAL_FREE(newEntry->extnValue.buff);
        BSL_SAL_FREE(newEntry->extnId.buff);
        BSL_SAL_Free(newEntry);
    }
    return ret;
}

static int32_t SetExt(HITLS_X509_Ext *ext, BslCid cid, BSL_Buffer *val, uint32_t expectLen, EncodeExtCb encodeExt)
{
    if (val->dataLen != expectLen) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (cid == BSL_CID_UNKNOWN) {
        HITLS_X509_ExtGeneric *generic = (HITLS_X509_ExtGeneric *)(void *)val->data;
        if (generic->oid.data == NULL || generic->oid.dataLen == 0 ||
            generic->value.data == NULL || generic->value.dataLen == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
        }
    }

    int32_t ret = HITLS_X509_SetExtList(ext, ext->extList, cid, val->data, encodeExt);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ext->flag |= HITLS_X509_EXT_FLAG_GEN;
    return ret;
}

static int32_t SetExtCtrl(HITLS_X509_Ext *ext, int32_t cmd, void *val, uint32_t valLen)
{
    if ((ext->flag & HITLS_X509_EXT_FLAG_PARSE) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SET_AFTER_PARSE);
        return HITLS_X509_ERR_EXT_SET_AFTER_PARSE;
    }
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
        case HITLS_X509_EXT_SET_CDP:
            return SetExt(ext, BSL_CID_CE_CRLDISTRIBUTIONPOINTS, &buff, sizeof(HITLS_X509_ExtCdp),
                (EncodeExtCb)SetExtCrlDp);
        case HITLS_X509_EXT_SET_CRLNUMBER:
            return SetExt(ext, BSL_CID_CE_CRLNUMBER, &buff, sizeof(HITLS_X509_ExtCrlNumber),
                (EncodeExtCb)SetExtCrlNumber);
        case HITLS_X509_EXT_SET_DELTA_CRL:
            return SetExt(ext, BSL_CID_CE_DELTACRLINDICATOR, &buff, sizeof(HITLS_X509_ExtDeltaCrl),
                (EncodeExtCb)SetExtDeltaCrl);
        case HITLS_X509_EXT_SET_IDP:
            return SetExt(ext, BSL_CID_CE_ISSUINGDISTRIBUTIONPOINT, &buff, sizeof(HITLS_X509_ExtIdp),
                (EncodeExtCb)SetExtIdp);
        case HITLS_X509_EXT_SET_GENERIC:
            return SetExt(ext, BSL_CID_UNKNOWN, &buff, sizeof(HITLS_X509_ExtGeneric), (EncodeExtCb)SetExtGeneric);
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
        return HITLS_X509_ERR_EXT_NOT_FOUND;
    }
    if (val->dataLen != expectLen) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    HITLS_X509_ExtEntry *extEntry = BSL_LIST_SearchDataConst(ext, &cid, CmpExtByCid, NULL);
    if (extEntry == NULL) {
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
    if ((certExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) == 0) {
        return HITLS_X509_ERR_KU_IS_NONE;
    }
    *val = certExt->keyUsage;
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
    HITLS_X509_ExtEntry *entry = BSL_LIST_SearchDataConst(ext->extList, &cid, CmpExtByCid, NULL);
    if (entry == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_UNKNOWN_ERROR);
        return HITLS_X509_ERR_EXT_UNKNOWN_ERROR;
    }
    bCons->isCa = certExt->isCa;
    bCons->maxPathLen = certExt->maxPathLen;
    bCons->critical = entry->critical;
    return HITLS_PKI_SUCCESS;
}

/* Generic extension get: user provides DER-encoded OID buffer and output buffer */
static int32_t GetGenericExt(HITLS_X509_Ext *ext, HITLS_X509_ExtGeneric *generic, uint32_t valLen)
{
    if (valLen != sizeof(HITLS_X509_ExtGeneric) ||
        generic->oid.data == NULL || generic->oid.dataLen == 0 || generic->value.data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    BSL_ASN1_Buffer oidBuf = {BSL_ASN1_TAG_OBJECT_ID, generic->oid.dataLen, generic->oid.data};
    HITLS_X509_ExtEntry *extEntry = BSL_LIST_SearchDataConst(ext->extList, &oidBuf, HITLS_X509_CmpExtByOid, NULL);
    if (extEntry == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_NOT_FOUND);
        return HITLS_X509_ERR_EXT_NOT_FOUND;
    }

    generic->value.data = BSL_SAL_Dump(extEntry->extnValue.buff, extEntry->extnValue.len);
    if (generic->value.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    generic->value.dataLen = extEntry->extnValue.len;
    generic->critical = extEntry->critical;
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
        case HITLS_X509_EXT_GET_CDP:
            return HITLS_X509_GetExt(ext->extList, BSL_CID_CE_CRLDISTRIBUTIONPOINTS, &buff,
                sizeof(HITLS_X509_ExtCdp), (DecodeExtCb)HITLS_X509_ParseCdp);
        case HITLS_X509_EXT_GET_CRLNUMBER:
            return HITLS_X509_GetExt(ext->extList, BSL_CID_CE_CRLNUMBER, &buff, sizeof(HITLS_X509_ExtCrlNumber),
                (DecodeExtCb)X509_ParseCrlNumber);
        case HITLS_X509_EXT_GET_DELTA_CRL:
            return HITLS_X509_GetExt(ext->extList, BSL_CID_CE_DELTACRLINDICATOR, &buff,
                sizeof(HITLS_X509_ExtDeltaCrl), (DecodeExtCb)X509_ParseCrlNumber);
        case HITLS_X509_EXT_GET_IDP:
            return HITLS_X509_GetExt(ext->extList, BSL_CID_CE_ISSUINGDISTRIBUTIONPOINT, &buff,
                sizeof(HITLS_X509_ExtIdp), (DecodeExtCb)HITLS_X509_ParseIdp);
        case HITLS_X509_EXT_GET_KUSAGE:
            return GetExtKeyUsage(ext, val, valLen);
        case HITLS_X509_EXT_GET_BCONS:
            return GetExtBCons(ext, val, valLen);
        case HITLS_X509_EXT_GET_SAN:
            return HITLS_X509_GetExt(ext->extList, BSL_CID_CE_SUBJECTALTNAME, &buff, sizeof(HITLS_X509_ExtSan),
                (DecodeExtCb)HITLS_X509_ParseSubjectAltName);
        case HITLS_X509_EXT_GET_GENERIC:
            return GetGenericExt(ext, (HITLS_X509_ExtGeneric *)val, valLen);
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
    *val = BSL_LIST_SearchDataConst(ext->extList, &cid, CmpExtByCid, NULL) != NULL;
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
        HITLS_X509_EXT_SET_SAN, HITLS_X509_EXT_SET_BCONS, HITLS_X509_EXT_SET_EXKUSAGE, HITLS_X509_EXT_SET_CDP,
        HITLS_X509_EXT_SET_GENERIC, HITLS_X509_EXT_GET_SKI, HITLS_X509_EXT_GET_AKI, HITLS_X509_EXT_GET_CDP,
        HITLS_X509_EXT_CHECK_SKI, HITLS_X509_EXT_GET_KUSAGE, HITLS_X509_EXT_GET_BCONS, HITLS_X509_EXT_GET_SAN,
        HITLS_X509_EXT_GET_GENERIC};
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
    for (BslListNode *listNode = BSL_LIST_FirstNode(list); listNode != NULL;
        listNode = BSL_LIST_GetNextNode(list, listNode)) {
        HITLS_X509_ExtEntry *node = (HITLS_X509_ExtEntry *)BSL_LIST_GetData(listNode);
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
    if (ret != BSL_SUCCESS) {
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
    HITLS_X509_ExtEntry *dest = BSL_SAL_Calloc(1, sizeof(HITLS_X509_ExtEntry));
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
