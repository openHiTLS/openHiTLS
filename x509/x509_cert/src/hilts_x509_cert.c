/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "securec.h"
#include "hitls_x509.h"
#include "bsl_sal.h"
#include "hitls_x509_errno.h"
#include "hitls_x509_local.h"
#include "crypt_eal_encode.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "hitls_x509_local.h"
#include "bsl_obj_internal.h"
#include "bsl_pem_internal.h"
#include "bsl_err_internal.h"
#include "hitls_cert_local.h"
#include "crypt_encode.h"

#define HITLS_CERT_CTX_SPECIFIC_TAG_VER       0
#define HITLS_CERT_CTX_SPECIFIC_TAG_ISSUERID  1
#define HITLS_CERT_CTX_SPECIFIC_TAG_SUBJECTID 2
#define HITLS_CERT_CTX_SPECIFIC_TAG_EXTENSION 3

BSL_ASN1_TemplateItem g_certTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* x509 */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* tbs */
            /* 2: version */
            {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CERT_CTX_SPECIFIC_TAG_VER,
            BSL_ASN1_FLAG_DEFAULT, 2},
                {BSL_ASN1_TAG_INTEGER, 0, 3},
            /* 2: serial number */
            {BSL_ASN1_TAG_INTEGER, 0, 2},
            /* 2: signature info */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
                {BSL_ASN1_TAG_OBJECT_ID, 0, 3},
                {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 3}, // 8
            /* 2: issuer */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
            /* 2: validity */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
                {BSL_ASN1_TAG_CHOICE, 0, 3},
                {BSL_ASN1_TAG_CHOICE, 0, 3}, // 12
            /* 2: subject ref: issuer */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
            /* 2: subject public key info ref signature info */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 2},
            /* 2: issuer id, subject id */
            {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_CERT_CTX_SPECIFIC_TAG_ISSUERID, BSL_ASN1_FLAG_OPTIONAL, 2},
            {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_CERT_CTX_SPECIFIC_TAG_SUBJECTID, BSL_ASN1_FLAG_OPTIONAL, 2},
            /* 2: extension */
            {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CERT_CTX_SPECIFIC_TAG_EXTENSION,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2}, // 17
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* signAlg */
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
            {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 2}, // 20
        {BSL_ASN1_TAG_BITSTRING, 0, 1} /* sig */
};

typedef enum {
    HITLS_X509_CERT_VERSION_IDX = 0,
    HITLS_X509_CERT_SERIAL_IDX = 1,
    HITLS_X509_CERT_TBS_SIGNALG_OID_IDX = 2,
    HITLS_X509_CERT_TBS_SIGNALG_ANY_IDX = 3,
    HITLS_X509_CERT_ISSUER_IDX = 4,
    HITLS_X509_CERT_BEFORE_VALID_IDX = 5,
    HITLS_X509_CERT_AFTER_VALID_IDX = 6,
    HITLS_X509_CERT_SUBJECT_IDX = 7,
    HITLS_X509_CERT_SUBKEYINFO_IDX = 8,
    HITLS_X509_CERT_ISSUERID_IDX = 9,
    HITLS_X509_CERT_SUBJECTID_IDX = 10,
    HITLS_X509_CERT_EXT_IDX = 11,
    HITLS_X509_CERT_SIGNALG_IDX = 12,
    HITLS_X509_CERT_SIGNALG_ANY_IDX = 13,
    HITLS_X509_CERT_SIGN_IDX = 14,
    HITLS_X509_CERT_MAX_IDX = 15,
} HITLS_X509_CERT_IDX;

#define X509_ASN1_START_TIME_IDX 10
#define X509_ASN1_END_TIME_IDX 11

#define X509_ASN1_TBS_SIGNALG_ANY 7
#define X509_ASN1_SIGNALG_ANY 19

int32_t HITLS_X509_CertTagGetOrCheck(int32_t type, int32_t idx, void *data, void *expVal)
{
    switch (type) {
        case BSL_ASN1_TYPE_CHECK_CHOICE_TAG: {
            if (idx == X509_ASN1_START_TIME_IDX || idx == X509_ASN1_END_TIME_IDX) {
                uint8_t tag = *(uint8_t *) data;
                if ((tag == BSL_ASN1_TAG_UTCTIME) || (tag == BSL_ASN1_TAG_GENERALIZEDTIME)) {
                    *(uint8_t *) expVal = tag;
                    return BSL_SUCCESS;
                }
            }
            return HITLS_X509_ERR_CHECK_TAG;
        }
        case BSL_ASN1_TYPE_GET_ANY_TAG: {
            if (idx == X509_ASN1_TBS_SIGNALG_ANY || idx == X509_ASN1_SIGNALG_ANY) {
                BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *) data;
                BslOidString oidStr = {param->len, (char *)param->buff, 0};
                BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
                if (cid == BSL_CID_UNKNOWN) {
                    return HITLS_X509_ERR_GET_ANY_TAG;
                }
                if (cid == BSL_CID_RSASSAPSS) {
                    // note: any It can be encoded empty or it can be null
                    *(uint8_t *) expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
                    return BSL_SUCCESS;
                } else {
                    *(uint8_t *) expVal = BSL_ASN1_TAG_NULL; // is null
                    return BSL_SUCCESS;
                }
            }
            return HITLS_X509_ERR_GET_ANY_TAG;
        }
        default:
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

void HITLS_X509_FreeCert(HITLS_X509_Cert *cert)
{
    if (cert == NULL) {
        return;
    }

    int ret = 0;
    BSL_SAL_AtomicDownReferences(&(cert->references), &ret);
    if (ret > 0) {
        return;
    }
    
    BSL_LIST_FREE(cert->tbs.issuerName, NULL);
    BSL_LIST_FREE(cert->tbs.subjectName, NULL);
    BSL_LIST_FREE(cert->tbs.ext.list, NULL);
    CRYPT_EAL_PkeyFreeCtx(cert->tbs.ealPubKey);
    BSL_SAL_ReferencesFree(&(cert->references));
    if (cert->isCopy == true) {
        BSL_SAL_FREE(cert->rawData);
    }
    BSL_SAL_Free(cert);
    return;
}

HITLS_X509_Cert *HITLS_X509_NewCert()
{
    HITLS_X509_Cert *cert = NULL;
    BSL_ASN1_List *issuerName = NULL;
    BSL_ASN1_List *subjectName = NULL;
    BSL_ASN1_List *extList = NULL;
    cert = (HITLS_X509_Cert *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_Cert));
    if (cert == NULL) {
        return NULL;
    }
    
    issuerName = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (issuerName == NULL) {
        goto ERR;
    }
    
    subjectName = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (subjectName == NULL) {
        goto ERR;
    }
    extList = BSL_LIST_New(sizeof(HITLS_X509_ExtEntry));
    if (extList == NULL) {
        goto ERR;
    }
    BSL_SAL_ReferencesInit(&(cert->references));
    cert->tbs.issuerName = issuerName;
    cert->tbs.subjectName = subjectName;
    cert->tbs.ext.list = extList;
    cert->tbs.ext.maxPathLen = -1;
    return cert;
ERR:
    BSL_SAL_Free(cert);
    BSL_SAL_Free(issuerName);
    BSL_SAL_Free(subjectName);
    return NULL;
}


int32_t HITLS_X509_ParseExtKeyUsage(HITLS_X509_ExtEntry *extEntry, HITLS_X509_Cert *cert)
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
    if (bitString.len > sizeof(cert->tbs.ext.keyUsage)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_INVALID_KEYUSAGE);
        return HITLS_X509_ERR_CERT_INVALID_KEYUSAGE;
    }
    for (size_t i = 0; i < bitString.len; i++) {
        cert->tbs.ext.keyUsage |= (bitString.buff[i] << (8 * i));
    }
    cert->tbs.ext.extFlags |= HITLS_X509_CERT_EXT_FLAG_KUSAGE;
    return HITLS_X509_SUCCESS;
}

static BSL_ASN1_TemplateItem g_basicConstaintsTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_BOOLEAN, BSL_ASN1_FLAG_DEFAULT, 1},
        {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_OPTIONAL, 1}
};

typedef enum {
    HITLS_X509_EXT_BC_CA_IDX,
    HITLS_X509_EXT_BC_PATHLEN_IDX,
    HITLS_X509_EXT_BC_MAX
} HITLS_X509_EXT_BASICCONTRAINS;

int32_t HITLS_X509_ParseExtBasicContaints(HITLS_X509_ExtEntry *extEntry, HITLS_X509_Cert *cert)
{
    uint8_t *temp = extEntry->extnValue.buff;
    uint32_t tempLen = extEntry->extnValue.len;
    BSL_ASN1_Buffer asnArr[HITLS_X509_EXT_BC_MAX] = {0};
    BSL_ASN1_Template templ = {g_basicConstaintsTempl,
        sizeof(g_basicConstaintsTempl) / sizeof(g_basicConstaintsTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asnArr, HITLS_X509_EXT_BC_MAX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (asnArr[HITLS_X509_EXT_BC_CA_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_EXT_BC_CA_IDX], &cert->tbs.ext.isCa);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    
    if (asnArr[HITLS_X509_EXT_BC_PATHLEN_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_EXT_BC_PATHLEN_IDX], &cert->tbs.ext.maxPathLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    cert->tbs.ext.extFlags |= HITLS_X509_CERT_EXT_FLAG_BCONS;
    return ret;
}

int32_t HITLS_CERT_ParseExtAsnItem(BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    HITLS_X509_Cert *cert = param;
    HITLS_X509_ExtEntry extEntry = {0};
    int32_t ret = HITLS_X509_ParseExt(asn, &extEntry);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString oid = {extEntry.extnId.len, (char *)extEntry.extnId.buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oid);
    switch (cid) {
        case BSL_CID_CE_KEYUSAGE:
            return HITLS_X509_ParseExtKeyUsage(&extEntry, cert);
        case BSL_CID_CE_BASICCONSTRAINTS:
            return HITLS_X509_ParseExtBasicContaints(&extEntry, cert);
        default:
            return HITLS_X509_ParseItemDefault(&extEntry, sizeof(HITLS_X509_ExtEntry), list);
    }
}

int32_t HITLS_CERT_ParseExtSeqof(uint32_t layer, BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    if (layer == 1) {
        return HITLS_X509_SUCCESS;
    }
    return HITLS_CERT_ParseExtAsnItem(asn, param, list);
}

int32_t HITLS_X509_ParseCertExt(BSL_ASN1_Buffer *ext, HITLS_X509_Cert *cert)
{
    // x509 v1
    if (ext->tag == 0) {
        return HITLS_X509_SUCCESS;
    }

    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {2, expTag};
    int ret = BSL_ASN1_DecodeListItem(&listParam, ext, &HITLS_CERT_ParseExtSeqof, cert, cert->tbs.ext.list);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteAll(cert->tbs.ext.list, NULL);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

int32_t HITLS_X509_ParseCertTbs(BSL_ASN1_Buffer *asnArr, HITLS_X509_Cert *cert)
{
    int32_t ret;
    // version
    if (asnArr[HITLS_X509_CERT_VERSION_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CERT_VERSION_IDX], &cert->tbs.version);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else {
        cert->tbs.version = 0;
    }

    // serialNum
    cert->tbs.serialNum = asnArr[HITLS_X509_CERT_SERIAL_IDX];

    // sign alg
    ret = HITLS_X509_ParseSignAlgInfo(&asnArr[HITLS_X509_CERT_TBS_SIGNALG_OID_IDX],
        &asnArr[HITLS_X509_CERT_TBS_SIGNALG_ANY_IDX], &cert->tbs.signAlgId);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // issuer name
    ret = HITLS_X509_ParseNameList(&asnArr[HITLS_X509_CERT_ISSUER_IDX], cert->tbs.issuerName);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    // validity
    ret = HITLS_X509_ParseTime(&asnArr[HITLS_X509_CERT_BEFORE_VALID_IDX], &asnArr[HITLS_X509_CERT_AFTER_VALID_IDX],
        &cert->tbs.validTime);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // subject name
    ret = HITLS_X509_ParseNameList(&asnArr[HITLS_X509_CERT_SUBJECT_IDX], cert->tbs.subjectName);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // subject public key info
    ret = CRYPT_EAL_ParseAsn1SubPubkey(asnArr[HITLS_X509_CERT_SUBKEYINFO_IDX].buff,
        asnArr[HITLS_X509_CERT_SUBKEYINFO_IDX].len, &cert->tbs.ealPubKey, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    
    // ext
    ret = HITLS_X509_ParseCertExt(&asnArr[HITLS_X509_CERT_EXT_IDX], cert);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    
    return ret;
ERR:
    if (cert->tbs.ealPubKey != NULL) {
        CRYPT_EAL_PkeyFreeCtx(cert->tbs.ealPubKey);
        cert->tbs.ealPubKey = NULL;
    }
    BSL_LIST_DeleteAll(cert->tbs.issuerName, NULL);
    BSL_LIST_DeleteAll(cert->tbs.subjectName, NULL);
    return ret;
}

int32_t HITLS_X509_ParseAsn1Cert(bool isCopy, uint8_t **encode, uint32_t *encodeLen, HITLS_X509_Cert *cert)
{
    uint8_t *temp = *encode;
    uint32_t tempLen = *encodeLen;
    cert->isCopy = isCopy;
    // template parse
    BSL_ASN1_Buffer asnArr[HITLS_X509_CERT_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_certTempl, sizeof(g_certTempl) / sizeof(g_certTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, HITLS_X509_CertTagGetOrCheck,
        &temp, &tempLen, asnArr, HITLS_X509_CERT_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // parse tbs raw data
    ret = HITLS_X509_ParseTbsRawData(*encode, *encodeLen, &cert->tbs.tbsRawData, &cert->tbs.tbsRawDataLen);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // parse tbs
    ret = HITLS_X509_ParseCertTbs(asnArr, cert);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    // parse sign alg
    ret = HITLS_X509_ParseSignAlgInfo(&asnArr[HITLS_X509_CERT_SIGNALG_IDX],
        &asnArr[HITLS_X509_CERT_SIGNALG_ANY_IDX], &cert->signAlgId);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // parse signature
    ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CERT_SIGN_IDX], &cert->signature);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    cert->rawData = *encode;
    cert->rawDataLen = *encodeLen - tempLen;
    *encode = temp;
    *encodeLen = tempLen;
    return HITLS_X509_SUCCESS;
ERR:
    CRYPT_EAL_PkeyFreeCtx(cert->tbs.ealPubKey);
    cert->tbs.ealPubKey = NULL;
    BSL_LIST_DeleteAll(cert->tbs.issuerName, NULL);
    BSL_LIST_DeleteAll(cert->tbs.subjectName, NULL);
    BSL_LIST_DeleteAll(cert->tbs.ext.list, NULL);
    return ret;
}


int32_t HITLS_X509_ParseBuffCertMul(int32_t format, BSL_Buffer *encode, HITLS_X509_List **certlist)
{
    int32_t ret;
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || certlist == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    X509_ParseFuncCbk certCbk = {
        (HITLS_X509_Asn1Parse)HITLS_X509_ParseAsn1Cert,
        (HITLS_X509_New)HITLS_X509_NewCert,
        (HITLS_X509_Free)HITLS_X509_FreeCert
    };
    HITLS_X509_List *list = BSL_LIST_New(sizeof(HITLS_X509_Cert));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    ret = HITLS_X509_ParseX509(format, encode, true, &certCbk, list);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *certlist = list;
    return ret;
}

int32_t HITLS_X509_ParseBuffCert(int32_t format, BSL_Buffer *encode, HITLS_X509_Cert **cert)
{
    HITLS_X509_List *list = NULL;
    if (cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    int32_t ret = HITLS_X509_ParseBuffCertMul(format, encode, &list);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_X509_Cert *tmp = BSL_LIST_GET_FIRST(list);
    int ref;
    ret = HITLS_X509_CtrlCert(tmp, HITLS_X509_CERT_REF_UP, &ref, sizeof(int));
    BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    *cert = tmp;
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_ParseFileCert(int32_t format, const char *path, HITLS_X509_Cert **cert)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_X509_ParseBuffCert(format, &encode, cert);
    BSL_SAL_Free(data);
    return ret;
}

int32_t HITLS_X509_ParseFileCertMul(int32_t format, const char *path, HITLS_X509_List **certlist)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_X509_ParseBuffCertMul(format, &encode, certlist);
    BSL_SAL_Free(data);
    return ret;
}

static int32_t X509_CertGetEncodeLen(HITLS_X509_Cert *cert, uint32_t *val, int32_t valLen)
{
    if (val == NULL || valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *(uint32_t *)val = cert->rawDataLen;
    return HITLS_X509_SUCCESS;
}

static int32_t X509_CertGetEncodeData(HITLS_X509_Cert *cert, uint8_t **val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = cert->rawData;
    return HITLS_X509_SUCCESS;
}

static int32_t X509_CertGetPubKey(HITLS_X509_Cert *cert, void **val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    int32_t ret = CRYPT_EAL_PkeyUpRef(cert->tbs.ealPubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *val = cert->tbs.ealPubKey;
    return HITLS_X509_SUCCESS;
}

static int32_t X509_CertGetSignAlg(HITLS_X509_Cert *cert, int32_t *val, int32_t valLen)
{
    if (val == NULL || valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = cert->signAlgId.algId;
    return HITLS_X509_SUCCESS;
}

static int32_t X509_CertRefUp(HITLS_X509_Cert *cert, int32_t *val, int32_t valLen)
{
    if (val == NULL || valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    return BSL_SAL_AtomicUpReferences(&cert->references, val);
}

int32_t X509_KeyUsageCheck(HITLS_X509_Cert *cert, bool *val, int32_t valLen, uint64_t exp)
{
    if (val == NULL || valLen != sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = (cert->tbs.ext.keyUsage & exp);
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_CtrlCert(HITLS_X509_Cert *cert, int32_t cmd, void *val, int32_t valLen)
{
    if (cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    switch (cmd) {
        case HITLS_X509_CERT_GET_ENCODELEN:
            return X509_CertGetEncodeLen(cert, val, valLen);
        case HITLS_X509_CERT_ENCODE:
            return X509_CertGetEncodeData(cert, val);
        case HITLS_X509_CERT_GET_PUBKEY:
            return X509_CertGetPubKey(cert, val);
        case HITLS_X509_CERT_GET_SIGNALG:
            return X509_CertGetSignAlg(cert, val, valLen);
        case HITLS_X509_CERT_REF_UP:
            return X509_CertRefUp(cert, val, valLen);
        case HITLS_X509_CERT_EXT_KU_DIGITALSIGN:
            return X509_KeyUsageCheck(cert, val, valLen, HITLS_X509_EXT_KU_DIGITAL_SIGN);
        case HITLS_X509_CERT_EXT_KU_CERTSIGN:
            return X509_KeyUsageCheck(cert, val, valLen, HITLS_X509_EXT_KU_KEY_CERT_SIGN);
        case HITLS_X509_CERT_EXT_KU_KEYAGREEMENT:
            return X509_KeyUsageCheck(cert, val, valLen, HITLS_X509_EXT_KU_KEY_AGREEMENT);
        case HITLS_X509_CERT_EXT_KU_KEYENC:
            return X509_KeyUsageCheck(cert, val, valLen, HITLS_X509_EXT_KU_KEY_ENCIPHERMENT);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

int32_t HITLS_X509_DupCert(HITLS_X509_Cert *src, HITLS_X509_Cert **dest)
{
    if (src == NULL || dest == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    HITLS_X509_Cert *tempCert = NULL;
    BSL_Buffer encode = {src->rawData, src->rawDataLen};
    int32_t ret = HITLS_X509_ParseBuffCert(BSL_PARSE_FORMAT_ASN1, &encode, &tempCert);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    *dest = tempCert;
    return ret;
}

#define HITLS_CERT_VERSION_V3 2

/**
 * Confirm whether the certificate is the issuer of the current certificate
 *   1. Check if the issueName matches the subjectname
 *   2. Is the issuer certificate a CA
 *   3. Check if the algorithm of the issuer certificate matches that of the sub certificate
 *   4. Check if the certificate keyusage has a certificate sign
 */
int32_t HITLS_X509_CheckIssued(HITLS_X509_Cert *issue, HITLS_X509_Cert *subject, bool *res)
{
    int32_t ret = HITLS_X509_CmpNameNode(issue->tbs.subjectName, subject->tbs.issuerName);
    if (ret != 0) {
        *res = false;
        return HITLS_X509_SUCCESS;
    }
    /**
     * If the basic constraints extension is not present in a version 3 certificate, or the extension is present but the cA boolean is not asserted,
     * then the certified public key MUST NOT be used to verify certificate signatures.
     */
    if (issue->tbs.version == HITLS_CERT_VERSION_V3 && !(issue->tbs.ext.extFlags & HITLS_X509_CERT_EXT_FLAG_BCONS) && !issue->tbs.ext.isCa) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_NOT_CA);
        return HITLS_X509_ERR_CERT_NOT_CA;
    }

    ret = HITLS_X509_CheckAlg(issue->tbs.ealPubKey, &subject->tbs.signAlgId);
    if (ret != HITLS_X509_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /**
     * Conforming CAs MUST include this extension in certificates that contain public keys that are used to validate digital signatures on
     * other public key certificates or CRLs.
     */
    if (issue->tbs.ext.extFlags & HITLS_X509_CERT_EXT_FLAG_KUSAGE) {
    	if (((issue->tbs.ext.keyUsage & HITLS_X509_EXT_KU_KEY_CERT_SIGN)) == 0) {
        	BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_KU_NO_CERTSIGN);
        	return HITLS_X509_ERR_VFY_KU_NO_CERTSIGN;
    	}
	}
    *res = true;
    return HITLS_X509_SUCCESS;
}

static uint32_t X509_GetHashId(HITLS_X509_Asn1AlgId *alg)
{
    uint32_t hashId = BSL_OBJ_GetHashIdFromSignId(alg->algId);
    if (hashId != BSL_CID_UNKNOWN) {
        return hashId;
    }
    if (alg->algId == BSL_CID_RSASSAPSS) {
        return alg->rsaPssParam.mdId;
    }
    return BSL_CID_UNKNOWN;
}

static int32_t X509_CtrlAlgInfo(const CRYPT_EAL_PkeyCtx *pubKey, uint32_t hashId, HITLS_X509_Asn1AlgId *alg)
{
    int32_t ret;
    switch (alg->algId) {
        case BSL_CID_SHA224WITHRSAENCRYPTION:
        case BSL_CID_SHA256WITHRSAENCRYPTION:
        case BSL_CID_SHA384WITHRSAENCRYPTION:
        case BSL_CID_SHA512WITHRSAENCRYPTION:
        case BSL_CID_SM3WITHRSAENCRYPTION:
            {
                CRYPT_RSA_PkcsV15Para pkcs15Para = {hashId};
                ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)(uintptr_t)pubKey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcs15Para, sizeof(CRYPT_RSA_PkcsV15Para));
                break;
            }
        case BSL_CID_RSASSAPSS:
            ret = CRYPT_EAL_PkeyCtrl((CRYPT_EAL_PkeyCtx *)(uintptr_t)pubKey, CRYPT_CTRL_SET_RSA_EMSA_PSS, &alg->rsaPssParam, sizeof(CRYPT_RSA_PssPara));
            break;
        default:
            ret = HITLS_X509_SUCCESS;
            break;
    }
    return ret;
}

int32_t HITLS_X509_CheckSignature(const CRYPT_EAL_PkeyCtx *pubKey, uint8_t *rawData, uint32_t rawDataLen,
    HITLS_X509_Asn1AlgId *alg, BSL_ASN1_BitString *signature)
{
    uint32_t hashId = X509_GetHashId(alg);
    if (hashId == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_GET_HASHID);
        return HITLS_X509_ERR_VFY_GET_HASHID;
    }
    CRYPT_EAL_PkeyCtx *verifyPubKey = CRYPT_EAL_PkeyDupCtx(pubKey);
    if (verifyPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_DUP_PUBKEY);
        return HITLS_X509_ERR_VFY_DUP_PUBKEY;
    }
    int32_t ret = X509_CtrlAlgInfo(verifyPubKey, hashId, alg);
    if (ret != HITLS_X509_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(verifyPubKey);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyVerify(verifyPubKey, hashId, rawData, rawDataLen, signature->buff, signature->len);
    CRYPT_EAL_PkeyFreeCtx(verifyPubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

int32_t HITLS_X509_CertIsCA(HITLS_X509_Cert *cert, bool *res)
{
    *res = true;
    if (cert->tbs.version == HITLS_CERT_VERSION_V3) {
        if (!(cert->tbs.ext.extFlags & HITLS_X509_CERT_EXT_FLAG_BCONS)) {
            *res = false;
        } else {
            *res = cert->tbs.ext.isCa;
        }
    }
    return HITLS_X509_SUCCESS;
}
