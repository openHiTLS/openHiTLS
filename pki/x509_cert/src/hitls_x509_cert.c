/**
 * @copyright Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @file      hitls_x509_cert.c
 * @brief     x509 certificate resolution.
 * @create:   2024-07-08
 */

#include "hitls_build.h"
#ifdef HITLS_PKI_X509_CRT
#include <stdio.h>
#include "securec.h"
#include "bsl_sal.h"
#ifdef HITLS_BSL_SAL_FILE
#include "sal_file.h"
#endif
#include "sal_time.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_obj_internal.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_local.h"
#include "crypt_eal_codecs.h"
#include "crypt_codecskey.h"
#include "crypt_errno.h"
#include "crypt_eal_md.h"

#ifdef HITLS_BSL_PEM
#include "bsl_pem_internal.h"
#endif // HITLS_BSL_PEM

#include "bsl_err_internal.h"
#include "hitls_csr_local.h"
#include "hitls_cert_local.h"

#include "bsl_print.h"

#include "hitls_pki_utils.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_cert.h"

#define HITLS_CERT_CTX_SPECIFIC_TAG_VER       0
#define HITLS_CERT_CTX_SPECIFIC_TAG_ISSUERID  1
#define HITLS_CERT_CTX_SPECIFIC_TAG_SUBJECTID 2
#define HITLS_CERT_CTX_SPECIFIC_TAG_EXTENSION 3
#define PRINT_TIME_MAX_SIZE 32

#define HITLS_X509_CERT_PARSE_FLAG  0x01
#define HITLS_X509_CERT_GEN_FLAG    0x02

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

#ifdef HITLS_PKI_X509_CRT_PARSE
int32_t HITLS_X509_CertTagGetOrCheck(int32_t type, uint32_t idx, void *data, void *expVal)
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
                BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *)data;
                BslCid cid = BSL_OBJ_GetCidFromOidBuff(param->buff, param->len);
                if (cid == BSL_CID_UNKNOWN) {
                    return HITLS_X509_ERR_GET_ANY_TAG;
                }
                if (cid == BSL_CID_RSASSAPSS) {
                    // note: any can be encoded empty or null
                    *(uint8_t *)expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
                    return BSL_SUCCESS;
                } else {
                    *(uint8_t *)expVal = BSL_ASN1_TAG_NULL; // is null
                    return BSL_SUCCESS;
                }
            }
            return HITLS_X509_ERR_GET_ANY_TAG;
        }
        default:
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}
#endif // HITLS_PKI_X509_CRT_PARSE

void HITLS_X509_CertFree(HITLS_X509_Cert *cert)
{
    if (cert == NULL) {
        return;
    }

    int ret = 0;
    BSL_SAL_AtomicDownReferences(&(cert->references), &ret);
    if (ret > 0) {
        return;
    }

    if (cert->flag == HITLS_X509_CERT_GEN_FLAG) {
        BSL_SAL_FREE(cert->tbs.serialNum.buff);
        BSL_SAL_FREE(cert->tbs.tbsRawData);
        BSL_SAL_FREE(cert->signature.buff);
        BSL_LIST_FREE(cert->tbs.issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
        BSL_LIST_FREE(cert->tbs.subjectName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
    } else {
        BSL_LIST_FREE(cert->tbs.issuerName, NULL);
        BSL_LIST_FREE(cert->tbs.subjectName, NULL);
    }
#ifdef HITLS_CRYPTO_SM2
    if (cert->signAlgId.algId == BSL_CID_SM2DSAWITHSM3) {
        BSL_SAL_FREE(cert->signAlgId.sm2UserId.data);
    }
#endif
    X509_ExtFree(&cert->tbs.ext, false);
    BSL_SAL_FREE(cert->rawData);
    CRYPT_EAL_PkeyFreeCtx(cert->tbs.ealPubKey);
    BSL_SAL_ReferencesFree(&(cert->references));
    BSL_SAL_Free(cert);
}

HITLS_X509_Cert *HITLS_X509_CertNew(void)
{
    BSL_ASN1_List *issuerName = NULL;
    BSL_ASN1_List *subjectName = NULL;
    HITLS_X509_Ext *ext = NULL;
    HITLS_X509_Cert *cert = (HITLS_X509_Cert *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_Cert));
    issuerName = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    subjectName = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (cert == NULL || issuerName == NULL || subjectName == NULL) {
        goto ERR;
    }
    ext = X509_ExtNew(&cert->tbs.ext, HITLS_X509_EXT_TYPE_CERT);
    if (ext == NULL) {
        goto ERR;
    }
    BSL_SAL_ReferencesInit(&(cert->references));
    cert->tbs.issuerName = issuerName;
    cert->tbs.subjectName = subjectName;
    cert->state = HITLS_X509_CERT_STATE_NEW;
    return cert;
ERR:
    BSL_SAL_Free(cert);
    BSL_SAL_Free(issuerName);
    BSL_SAL_Free(subjectName);
    return NULL;
}

#ifdef HITLS_PKI_X509_CRT_PARSE
int32_t HITLS_X509_ParseCertTbs(BSL_ASN1_Buffer *asnArr, HITLS_X509_Cert *cert)
{
    int32_t ret;
    // version: default is 0
    if (asnArr[HITLS_X509_CERT_VERSION_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CERT_VERSION_IDX], &cert->tbs.version);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    // serialNum
    cert->tbs.serialNum = asnArr[HITLS_X509_CERT_SERIAL_IDX];

    // sign alg
    ret = HITLS_X509_ParseSignAlgInfo(&asnArr[HITLS_X509_CERT_TBS_SIGNALG_OID_IDX],
        &asnArr[HITLS_X509_CERT_TBS_SIGNALG_ANY_IDX], &cert->tbs.signAlgId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // issuer name
    ret = HITLS_X509_ParseNameList(&asnArr[HITLS_X509_CERT_ISSUER_IDX], cert->tbs.issuerName);
    if (ret != HITLS_PKI_SUCCESS) {
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
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // subject public key info
    BSL_Buffer subPubKeyBuff = {asnArr[HITLS_X509_CERT_SUBKEYINFO_IDX].buff,
        asnArr[HITLS_X509_CERT_SUBKEYINFO_IDX].len};
    ret = CRYPT_EAL_ProviderDecodeBuffKey(cert->libCtx, cert->attrName, BSL_CID_UNKNOWN, "ASN1",
        "PUBKEY_SUBKEY_WITHOUT_SEQ", &subPubKeyBuff, NULL, (CRYPT_EAL_PkeyCtx **)&cert->tbs.ealPubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // ext
    ret = HITLS_X509_ParseExt(&asnArr[HITLS_X509_CERT_EXT_IDX], &cert->tbs.ext);
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

int32_t HITLS_X509_ParseAsn1Cert(uint8_t *encode, uint32_t encodeLen, HITLS_X509_Cert *cert)
{
    uint8_t *temp = encode;
    uint32_t tempLen = encodeLen;
    cert->rawData = encode; // cert takes over the encode immediately.
    if ((cert->flag & HITLS_X509_CERT_GEN_FLAG) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
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
    ret = HITLS_X509_ParseTbsRawData(encode, encodeLen, &cert->tbs.tbsRawData, &cert->tbs.tbsRawDataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // parse tbs
    ret = HITLS_X509_ParseCertTbs(asnArr, cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // parse sign alg
    ret = HITLS_X509_ParseSignAlgInfo(&asnArr[HITLS_X509_CERT_SIGNALG_IDX],
        &asnArr[HITLS_X509_CERT_SIGNALG_ANY_IDX], &cert->signAlgId);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    // parse signature
    ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CERT_SIGN_IDX], &cert->signature);
    if (ret != BSL_SUCCESS) {
        goto ERR;
    }
    cert->rawDataLen = encodeLen - tempLen;
    cert->flag |= HITLS_X509_CERT_PARSE_FLAG;
    return HITLS_PKI_SUCCESS;
ERR:
    CRYPT_EAL_PkeyFreeCtx(cert->tbs.ealPubKey);
    cert->tbs.ealPubKey = NULL;
    BSL_LIST_DeleteAll(cert->tbs.issuerName, NULL);
    BSL_LIST_DeleteAll(cert->tbs.subjectName, NULL);
    BSL_LIST_DeleteAll(cert->tbs.ext.extList, NULL);
    return ret;
}

int32_t HITLS_X509_CertMulParseBuff(CRYPT_EAL_LibCtx *libCtx, const char *attrName, int32_t format,
    const BSL_Buffer *encode, HITLS_X509_List **certlist)
{
    int32_t ret;
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || certlist == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    X509_ParseFuncCbk certCbk = {
        .asn1Parse = (HITLS_X509_Asn1Parse)HITLS_X509_ParseAsn1Cert,
        .x509ProviderNew = (HITLS_X509_ProviderNew)HITLS_X509_ProviderCertNew,
        .x509Free = (HITLS_X509_Free)HITLS_X509_CertFree
    };
    HITLS_X509_List *list = BSL_LIST_New(sizeof(HITLS_X509_Cert));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    ret = HITLS_X509_ParseX509(libCtx, attrName, format, encode, true, &certCbk, list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return ret;
    }
    *certlist = list;
    return ret;
}

static int32_t ProviderCertParseBuffInternal(HITLS_PKI_LibCtx *libCtx, const char *attrName, int32_t format,
    const BSL_Buffer *encode, HITLS_X509_Cert **cert)
{
    HITLS_X509_List *list = NULL;
    if (cert == NULL || *cert != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    int32_t ret = HITLS_X509_CertMulParseBuff(libCtx, attrName, format, encode, &list);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    HITLS_X509_Cert *tmp = BSL_LIST_GET_FIRST(list);
    int ref;
    ret = HITLS_X509_CertCtrl(tmp, HITLS_X509_REF_UP, &ref, sizeof(int));
    BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    *cert = tmp;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_CertParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_Cert **cert)
{
    return ProviderCertParseBuffInternal(NULL, NULL, format, encode, cert);
}

int32_t HITLS_X509_CertParseBundleBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_List **certlist)
{
    return HITLS_X509_CertMulParseBuff(NULL, NULL, format, encode, certlist);
}

int32_t HITLS_X509_ProviderCertParseBundleBuff(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const BSL_Buffer *encode, HITLS_X509_List **certlist)
{
    int32_t encodeFormat = CRYPT_EAL_GetEncodeFormat(format);
    return HITLS_X509_CertMulParseBuff(libCtx, attrName, encodeFormat, encode, certlist);
}

#ifdef HITLS_BSL_SAL_FILE
static int32_t ProviderCertParseBundleFileInternal(HITLS_PKI_LibCtx *libCtx, const char *attrName, int32_t format,
    const char *path, HITLS_X509_List **certlist)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_X509_CertMulParseBuff(libCtx, attrName, format, &encode, certlist);
    BSL_SAL_Free(data);
    return ret;
}

int32_t HITLS_X509_CertParseFile(int32_t format, const char *path, HITLS_X509_Cert **cert)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Buffer encode = {data, dataLen};
    ret = ProviderCertParseBuffInternal(NULL, NULL, format, &encode, cert);
    BSL_SAL_Free(data);
    return ret;
}

int32_t HITLS_X509_CertParseBundleFile(int32_t format, const char *path, HITLS_X509_List **certlist)
{
    return ProviderCertParseBundleFileInternal(NULL, NULL, format, path, certlist);
}
#endif // HITLS_BSL_SAL_FILE
#endif // HITLS_PKI_X509_CRT_PARSE

static int32_t X509_GetSerialNumStr(HITLS_X509_Cert *cert, BSL_Buffer *val)
{
    if (val == NULL || cert->tbs.serialNum.buff == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    BSL_ASN1_Buffer serialNum = cert->tbs.serialNum;
    if (serialNum.tag != BSL_ASN1_TAG_INTEGER || serialNum.len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    val->data = BSL_SAL_Calloc(serialNum.len * 3, sizeof(uint8_t));  // "%02x:" Use 3 bytes.
    if (val->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    static const char HEX_CHARS[] = "0123456789abcdef";
    char *outPtr = (char *)val->data;
    
    for (size_t i = 0; i < serialNum.len - 1; i++) {
        uint8_t byte = serialNum.buff[i];
        *outPtr++ = HEX_CHARS[(byte >> 4) & 0xF];  // High 4 bits
        *outPtr++ = HEX_CHARS[byte & 0xF];         // Low 4 bits
        *outPtr++ = ':';                           // Separator
    }

    // Last byte (without colon)
    uint8_t lastByte = serialNum.buff[serialNum.len - 1];
    *outPtr++ = HEX_CHARS[(lastByte >> 4) & 0xF];  // High 4 bits
    *outPtr++ = HEX_CHARS[lastByte & 0xF];         // Low 4 bits
    *outPtr = '\0';                                // Null terminator
    
    val->dataLen = 3 * serialNum.len - 1;  // 3 chars per byte (xx:) except last byte (xx)
    
    return HITLS_PKI_SUCCESS;
}

#ifndef HITLS_BSL_PRINT
#define BSL_PRINT_TIME_FMT "%s %u %02u:%02u:%02u %u GMT"

// rfc822: https://www.w3.org/Protocols/rfc822/
const char BSL_PRINT_MONTH_STR[12][4] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
#endif
static int32_t X509_GetAsn1BslTimeStr(const BSL_TIME *time, BSL_Buffer *val)
{
    if (time == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    val->data = BSL_SAL_Calloc(PRINT_TIME_MAX_SIZE, sizeof(uint8_t));
    if (val->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    if (sprintf_s((char *)val->data, PRINT_TIME_MAX_SIZE, BSL_PRINT_TIME_FMT,
        BSL_PRINT_MONTH_STR[time->month - 1], time->day, time->hour, time->minute, time->second, time->year) == -1) {
        BSL_SAL_FREE(val->data);
        val->dataLen = 0;
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_INVALID_TIME);
        return HITLS_X509_ERR_CERT_INVALID_TIME;
    }
    val->dataLen = (uint32_t)strlen((char *)val->data);
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_GetCNStrFromList(BSL_ASN1_List *nameList, BSL_Buffer *buff, uint32_t valLen)
{
    if (nameList == NULL || BSL_LIST_COUNT(nameList) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (buff == NULL || buff->data != NULL || valLen != sizeof(BSL_Buffer)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    HITLS_X509_NameNode *nameNode = BSL_LIST_GET_FIRST(nameList);
    while (nameNode != NULL) {
        BslOidString oid = {
            .octs = (char *)nameNode->nameType.buff,
            .octetLen = nameNode->nameType.len,
        };
        const char *oidName = BSL_OBJ_GetOidNameFromOid(&oid);
        if (oidName == NULL || strcmp(oidName, "CN") != 0) {
            nameNode = BSL_LIST_GET_NEXT(nameList);
            continue;
        }
        buff->data = BSL_SAL_Malloc(nameNode->nameValue.len + 1);
        if (buff->data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        (void)memcpy_s(buff->data, nameNode->nameValue.len + 1, nameNode->nameValue.buff, nameNode->nameValue.len);
        buff->data[nameNode->nameValue.len] = '\0';
        buff->dataLen = nameNode->nameValue.len;
        return HITLS_PKI_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_CN_NOT_FOUND);
    return HITLS_X509_ERR_CERT_CN_NOT_FOUND;
}

static int32_t X509_CertGetCtrl(HITLS_X509_Cert *cert, int32_t cmd, void *val, uint32_t valLen)
{
    switch (cmd) {
        case HITLS_X509_GET_ENCODELEN:
            return HITLS_X509_GetEncodeLen(cert->rawDataLen, val, valLen);
        case HITLS_X509_GET_ENCODE:
            return HITLS_X509_GetEncodeData(cert->rawData, val);
        case HITLS_X509_GET_PUBKEY:
            return HITLS_X509_GetPubKey(cert->tbs.ealPubKey, val);
        case HITLS_X509_GET_SIGNALG:
            return HITLS_X509_GetSignAlg(cert->signAlgId.algId, val, valLen);
        case HITLS_X509_GET_SIGN_MDALG:
            return HITLS_X509_GetSignMdAlg(&cert->signAlgId, val, (int32_t)valLen);
        case HITLS_X509_GET_SUBJECT_DN:
            return HITLS_X509_GetList(cert->tbs.subjectName, val, valLen);
        case HITLS_X509_GET_ISSUER_DN:
            return HITLS_X509_GetList(cert->tbs.issuerName, val, valLen);
        case HITLS_X509_GET_SERIALNUM:
            return HITLS_X509_GetSerial(&cert->tbs.serialNum, val, valLen);
        case HITLS_X509_GET_SUBJECT_DN_STR:
            return HITLS_X509_GetDistinguishNameStrFromList(cert->tbs.subjectName, val);
        case HITLS_X509_GET_ISSUER_DN_STR:
            return HITLS_X509_GetDistinguishNameStrFromList(cert->tbs.issuerName, val);
        case HITLS_X509_GET_SUBJECT_CN_STR:
            return X509_GetCNStrFromList(cert->tbs.subjectName, val, valLen);
        case HITLS_X509_GET_SERIALNUM_STR:
            return X509_GetSerialNumStr(cert, val);
        case HITLS_X509_GET_BEFORE_TIME_STR:
            return X509_GetAsn1BslTimeStr(&cert->tbs.validTime.start, val);
        case HITLS_X509_GET_AFTER_TIME_STR:
            return X509_GetAsn1BslTimeStr(&cert->tbs.validTime.end, val);
#ifdef HITLS_PKI_X509_CRT_AUTH
        case HITLS_X509_GET_ENCODE_SUBJECT_DN:
            return HITLS_X509_GetEncodeDn(cert->tbs.subjectName, val, valLen);
#endif
#ifdef HITLS_PKI_X509_VFY
        case HITLS_X509_IS_SELF_SIGNED: {
            if (val == NULL || valLen != sizeof(bool)) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
                return HITLS_X509_ERR_INVALID_PARAM;
            }
            *(bool *)val = HITLS_X509_CheckIssued(cert, cert);
            return HITLS_PKI_SUCCESS;
        }
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

#ifdef HITLS_PKI_X509_CRT_GEN
typedef bool (*SetParamCheck)(const void *val, uint32_t valLen);

static bool VersionCheck(const void *val, uint32_t valLen)
{
    return valLen == sizeof(int32_t) && *(const int32_t *)val >= HITLS_X509_VERSION_1 &&
        *(const int32_t *)val <= HITLS_X509_VERSION_3;
}

static bool TimeCheck(const void *val, uint32_t valLen)
{
    (void)val;
    return valLen == sizeof(BSL_TIME) && BSL_DateTimeCheck((const BSL_TIME *)val);
}

static int32_t CertSet(void *dest, uint32_t size, void *val, uint32_t valLen, SetParamCheck check)
{
    if (check(val, valLen) != true) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    (void)memcpy_s(dest, size, val, size);
    return HITLS_PKI_SUCCESS;
}

#if defined(HITLS_PKI_X509_CSR) && defined(HITLS_PKI_X509_CSR_ATTR)
static int32_t HITLS_X509_SetCsrExt(HITLS_X509_Ext *ext, HITLS_X509_Csr *csr)
{
    HITLS_X509_Ext *csrExt = NULL;
    int32_t ret = HITLS_X509_AttrCtrl(
        csr->reqInfo.attributes, HITLS_X509_ATTR_GET_REQUESTED_EXTENSIONS, &csrExt, sizeof(HITLS_X509_Ext *));
    if (ret == HITLS_X509_ERR_ATTR_NOT_FOUND) {
        return ret;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_ExtReplace(ext, csrExt);
    X509_ExtFree(csrExt, true);
    return ret;
}
#endif

static int32_t X509_CertSetCtrl(HITLS_X509_Cert *cert, int32_t cmd, void *val, uint32_t valLen)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if ((cert->flag & HITLS_X509_CERT_PARSE_FLAG) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_AFTER_PARSE);
        return HITLS_X509_ERR_SET_AFTER_PARSE;
    }
    cert->flag |= HITLS_X509_CERT_GEN_FLAG;
    cert->state = HITLS_X509_CERT_STATE_SET;
    int32_t ret;
    switch (cmd) {
        case HITLS_X509_SET_VERSION:
            return CertSet(&cert->tbs.version, sizeof(int32_t), val, valLen, VersionCheck);
        case HITLS_X509_SET_SERIALNUM:
            return HITLS_X509_SetSerial(&cert->tbs.serialNum, val, valLen);
        case HITLS_X509_SET_BEFORE_TIME:
            ret = CertSet(&cert->tbs.validTime.start, sizeof(BSL_TIME), val, valLen, TimeCheck);
            if (ret == HITLS_PKI_SUCCESS) {
                cert->tbs.validTime.flag |= BSL_TIME_BEFORE_SET;
                cert->tbs.validTime.flag |=
                    cert->tbs.validTime.start.year <= BSL_TIME_UTC_MAX_YEAR ? BSL_TIME_BEFORE_IS_UTC : 0;
            }
            return ret;
        case HITLS_X509_SET_AFTER_TIME:
            ret = CertSet(&cert->tbs.validTime.end, sizeof(BSL_TIME), val, valLen, TimeCheck);
            if (ret == HITLS_PKI_SUCCESS) {
                cert->tbs.validTime.flag |= BSL_TIME_AFTER_SET;
                cert->tbs.validTime.flag |=
                    cert->tbs.validTime.end.year <= BSL_TIME_UTC_MAX_YEAR ? BSL_TIME_AFTER_IS_UTC : 0;
            }
            return ret;
        case HITLS_X509_SET_PUBKEY:
            return HITLS_X509_SetPkey(&cert->tbs.ealPubKey, val);
        case HITLS_X509_SET_ISSUER_DN:
            return HITLS_X509_SetNameList(&cert->tbs.issuerName, val, valLen);
        case HITLS_X509_SET_SUBJECT_DN:
            return HITLS_X509_SetNameList(&cert->tbs.subjectName, val, valLen);
#if defined(HITLS_PKI_X509_CSR) && defined(HITLS_PKI_X509_CSR_ATTR)
        case HITLS_X509_SET_CSR_EXT:
            return HITLS_X509_SetCsrExt(&cert->tbs.ext, val);
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}
#endif // HITLS_PKI_X509_CRT_GEN


int32_t HITLS_X509_CertCtrl(HITLS_X509_Cert *cert, int32_t cmd, void *val, uint32_t valLen)
{
    if (cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (cmd == HITLS_X509_REF_UP) {
        return BSL_SAL_AtomicRefUpCtrl(&(cert->references), val, valLen);
    } else if (cmd >= HITLS_X509_GET_ENCODELEN && cmd < HITLS_X509_SET_VERSION) {
        return X509_CertGetCtrl(cert, cmd, val, valLen);
#ifdef HITLS_PKI_X509_CRT_GEN
    } else if (cmd >= HITLS_X509_SET_VERSION && cmd < HITLS_X509_EXT_SET_SKI) {
        return X509_CertSetCtrl(cert, cmd, val, valLen);
#endif
    } else if (cmd <= HITLS_X509_EXT_CHECK_SKI) {
        static int32_t cmdSet[] = {HITLS_X509_EXT_SET_SKI, HITLS_X509_EXT_SET_AKI, HITLS_X509_EXT_SET_KUSAGE,
            HITLS_X509_EXT_SET_SAN, HITLS_X509_EXT_SET_BCONS, HITLS_X509_EXT_SET_EXKUSAGE, HITLS_X509_EXT_GET_SKI,
            HITLS_X509_EXT_GET_AKI, HITLS_X509_EXT_CHECK_SKI, HITLS_X509_EXT_GET_KUSAGE, HITLS_X509_EXT_GET_BCONS,
            HITLS_X509_EXT_GET_SAN};
        if (!X509_CheckCmdValid(cmdSet, sizeof(cmdSet) / sizeof(int32_t), cmd)) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_UNSUPPORT);
            return HITLS_X509_ERR_EXT_UNSUPPORT;
        }
        return X509_ExtCtrl(&cert->tbs.ext, cmd, val, valLen);
    } else {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
}

#ifdef HITLS_PKI_X509_CRT_PARSE
HITLS_X509_Cert *HITLS_X509_CertDup(HITLS_X509_Cert *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return NULL;
    }
    HITLS_X509_Cert *tempCert = NULL;
    BSL_Buffer encode = {src->rawData, src->rawDataLen};
    int32_t ret = HITLS_X509_ProviderCertParseBuff(src->libCtx, src->attrName, "ASN1", &encode, &tempCert);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    return tempCert;
}
#endif // HITLS_PKI_X509_CRT_PARSE

#ifdef HITLS_PKI_X509_VFY
/**
 * Confirm whether the certificate is the issuer of the current certificate
 *   1. Check if the issueName matches the subjectName
 *   2. Is the issuer certificate a CA
 *   3. Check if the algorithm of the issuer certificate matches that of the sub certificate
 *   4. Check if the certificate keyusage has a certificate sign
 */
bool HITLS_X509_CheckIssued(HITLS_X509_Cert *issue, HITLS_X509_Cert *subject)
{
    int32_t ret = HITLS_X509_CmpNameNode(issue->tbs.subjectName, subject->tbs.issuerName);
    if (ret != HITLS_PKI_SUCCESS) {
        return false;
    }
    if (issue->tbs.version == HITLS_X509_VERSION_3 && subject->tbs.version == HITLS_X509_VERSION_3) {
        ret = HITLS_X509_CheckAki(&issue->tbs.ext, &subject->tbs.ext, issue->tbs.issuerName, &issue->tbs.serialNum);
        if (ret != HITLS_PKI_SUCCESS) {
            return false;
        }
    }

    ret = HITLS_X509_CheckAlg(issue->tbs.ealPubKey, &subject->tbs.signAlgId);
    if (ret != HITLS_PKI_SUCCESS) {
        return false;
    }

    return true;
}

bool HITLS_X509_CertIsCA(HITLS_X509_Cert *cert)
{
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)cert->tbs.ext.extData;
    if (cert->tbs.version == HITLS_X509_VERSION_3) {
        if ((certExt->extFlags & HITLS_X509_EXT_FLAG_BCONS) == 0) {
            return false;
        } else {
            return certExt->isCa;
        }
    }
    return true;
}
#endif // HITLS_PKI_X509_VFY

#ifdef HITLS_PKI_X509_CRT_GEN
static int32_t EncodeTbsItems(HITLS_X509_CertTbs *tbs, BSL_ASN1_Buffer *signAlg, BSL_ASN1_Buffer *issuer,
    BSL_ASN1_Buffer *subject, BSL_ASN1_Buffer *pubkey, BSL_ASN1_Buffer *ext)
{
    BSL_Buffer pub = {0};
    int32_t ret = HITLS_X509_EncodeSignAlgInfo(&tbs->signAlgId, signAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HITLS_X509_EncodeNameList(tbs->issuerName, issuer);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = HITLS_X509_EncodeNameList(tbs->subjectName, subject);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = CRYPT_EAL_EncodePubKeyBuffInternal(tbs->ealPubKey, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, false, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    if (tbs->version == HITLS_X509_VERSION_3) {
        ret = HITLS_X509_EncodeExt(BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED |
            HITLS_CERT_CTX_SPECIFIC_TAG_EXTENSION, tbs->ext.extList, ext);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
    }
    pubkey->buff = pub.data;
    pubkey->len = pub.dataLen;
    return ret;
ERR:
    BSL_SAL_Free(signAlg->buff);
    BSL_SAL_Free(issuer->buff);
    BSL_SAL_Free(subject->buff);
    BSL_SAL_Free(pub.data);
    return ret;
}

BSL_ASN1_TemplateItem g_tbsTempl[] = {
    /* version */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CERT_CTX_SPECIFIC_TAG_VER,
     BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_DEFAULT, 1},
    /* serial number */
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    /* signature info */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
    /* issuer */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
    /* validity */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CHOICE, 0, 1},
        {BSL_ASN1_TAG_CHOICE, 0, 1},
    /* subject ref: issuer */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
    /* subject public key info ref signature info */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    /* Note!!: issuer id, subject id are not supported */
    /* extension */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CERT_CTX_SPECIFIC_TAG_EXTENSION,
     BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
};
#define HITLS_X509_CERT_TBS_SIZE 9

static int32_t EncodeTbsCertificate(HITLS_X509_CertTbs *tbs, BSL_ASN1_Buffer *tbsBuff)
{
    BSL_ASN1_Buffer signAlg = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL};
    BSL_ASN1_Buffer issuer = {0};
    BSL_ASN1_Buffer subject = {0};
    BSL_ASN1_Buffer pubkey = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL};
    BSL_ASN1_Buffer ext = {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED |
        HITLS_CERT_CTX_SPECIFIC_TAG_EXTENSION, 0, NULL};

    int32_t ret = EncodeTbsItems(tbs, &signAlg, &issuer, &subject, &pubkey, &ext);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t ver = (uint8_t)tbs->version;
    BSL_ASN1_Template templ = {g_tbsTempl, sizeof(g_tbsTempl) / sizeof(g_tbsTempl[0])};
    BSL_ASN1_Buffer asns[HITLS_X509_CERT_TBS_SIZE] = {
        {BSL_ASN1_TAG_INTEGER, ver == HITLS_X509_VERSION_1 ? 0 : 1, ver == HITLS_X509_VERSION_1 ? NULL : &ver}, // 0
        tbs->serialNum,                                        // 1 serial number
        signAlg,                                               // 2 sigAlg
        issuer,                                                // 3 issuer
        {(tbs->validTime.flag & BSL_TIME_BEFORE_IS_UTC) != 0 ? BSL_ASN1_TAG_UTCTIME : BSL_ASN1_TAG_GENERALIZEDTIME,
         sizeof(BSL_TIME), (uint8_t *)&tbs->validTime.start},  // 4 start
        {(tbs->validTime.flag & BSL_TIME_AFTER_IS_UTC) != 0 ? BSL_ASN1_TAG_UTCTIME : BSL_ASN1_TAG_GENERALIZEDTIME,
         sizeof(BSL_TIME), (uint8_t *)&tbs->validTime.end},    // 5 end
        subject,                                               // 6 subject
        pubkey,                                                // 7 pubkey info
        ext,                                                   // 8 extensions, only for v3
    };
    ret = BSL_ASN1_EncodeTemplate(&templ, asns, HITLS_X509_CERT_TBS_SIZE, &tbsBuff->buff, &tbsBuff->len);
    BSL_SAL_Free(signAlg.buff);
    BSL_SAL_Free(issuer.buff);
    BSL_SAL_Free(subject.buff);
    BSL_SAL_Free(pubkey.buff);
    if (ver == HITLS_X509_VERSION_3 && ext.buff != NULL) {
        BSL_SAL_Free(ext.buff);
    }
    return ret;
}

BSL_ASN1_TemplateItem g_briefCertTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* x509 */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* tbs */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* signAlg */
        {BSL_ASN1_TAG_BITSTRING, 0, 1}                            /* sig */
};

#define HITLS_X509_CERT_BRIEF_SIZE 3

static int32_t EncodeAsn1Cert(HITLS_X509_Cert *cert)
{
    if (cert->signature.buff == NULL || cert->signature.len == 0 ||
        cert->tbs.tbsRawData == NULL || cert->tbs.tbsRawDataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_NOT_SIGNED);
        return HITLS_X509_ERR_CERT_NOT_SIGNED;
    }

    BSL_ASN1_Buffer asns[HITLS_X509_CERT_BRIEF_SIZE] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, cert->tbs.tbsRawDataLen, cert->tbs.tbsRawData},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL},
        {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&cert->signature},
    };
    uint32_t valLen = 0;
    int32_t ret = BSL_ASN1_DecodeTagLen(asns[0].tag, &asns[0].buff, &asns[0].len, &valLen); // 0 is tbs
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HITLS_X509_EncodeSignAlgInfo(&cert->signAlgId, &asns[1]); // 1 is signAlg
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_ASN1_Template templ = {g_briefCertTempl, sizeof(g_briefCertTempl) / sizeof(g_briefCertTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asns, HITLS_X509_CERT_BRIEF_SIZE, &cert->rawData, &cert->rawDataLen);
    BSL_SAL_Free(asns[1].buff);
    return ret;
}

static int32_t CheckCertTbs(HITLS_X509_Cert *cert)
{
    if (cert == NULL) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (BSL_LIST_COUNT(cert->tbs.ext.extList) > 0 && cert->tbs.version != HITLS_X509_VERSION_3) {
        return HITLS_X509_ERR_CERT_INACCURACY_VERSION;
    }
    if (cert->tbs.serialNum.buff == NULL || cert->tbs.serialNum.len == 0) {
        return HITLS_X509_ERR_CERT_INVALID_SERIAL_NUM;
    }
    if (BSL_LIST_COUNT(cert->tbs.issuerName) <= 0 || BSL_LIST_COUNT(cert->tbs.subjectName) <= 0) {
        return HITLS_X509_ERR_CERT_INVALID_DN;
    }
    if ((cert->tbs.validTime.flag & BSL_TIME_BEFORE_SET) == 0 || (cert->tbs.validTime.flag & BSL_TIME_AFTER_SET) == 0) {
        return HITLS_X509_ERR_CERT_INVALID_TIME;
    }
    int32_t ret = BSL_SAL_DateTimeCompare(&cert->tbs.validTime.start, &cert->tbs.validTime.end, NULL);
    if (ret != BSL_TIME_DATE_BEFORE && ret != BSL_TIME_CMP_EQUAL) {
        return HITLS_X509_ERR_CERT_START_TIME_LATER;
    }
    if (cert->tbs.ealPubKey == NULL) {
        return HITLS_X509_ERR_CERT_INVALID_PUBKEY;
    }

    return HITLS_PKI_SUCCESS;
}

/**
 * @brief Encode ASN.1 certificate
 *
 * @param cert [IN] Pointer to the certificate structure
 * @param buff [OUT] Pointer to the buffer.
 *             If NULL, only the ASN.1 certificate is encoded.
 *             If non-NULL, the DER encoding content of the certificate is stored in buff
 * @return int32_t Return value, 0 means success, other values mean failure
 */
static int32_t HITLS_X509_EncodeAsn1Cert(HITLS_X509_Cert *cert, BSL_Buffer *buff)
{
    int32_t ret;
    if ((cert->flag & HITLS_X509_CERT_GEN_FLAG) != 0) {
        if (cert->state != HITLS_X509_CERT_STATE_SIGN && cert->state != HITLS_X509_CERT_STATE_GEN) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_NOT_SIGNED);
            return HITLS_X509_ERR_CERT_NOT_SIGNED;
        }
        if (cert->state == HITLS_X509_CERT_STATE_SIGN) {
            ret = EncodeAsn1Cert(cert);
            if (ret != HITLS_PKI_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            cert->state = HITLS_X509_CERT_STATE_GEN;
        }
    }
    if (cert->rawData == NULL || cert->rawDataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_NOT_SIGNED);
        return HITLS_X509_ERR_CERT_NOT_SIGNED;
    }
    if (buff == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    buff->data = BSL_SAL_Dump(cert->rawData, cert->rawDataLen);
    if (buff->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    buff->dataLen = cert->rawDataLen;
    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_BSL_PEM
int32_t HITLS_X509_EncodePemCert(HITLS_X509_Cert *cert, BSL_Buffer *buff)
{
    int32_t ret = HITLS_X509_EncodeAsn1Cert(cert, NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_PEM_Symbol symbol = {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR};
    return BSL_PEM_EncodeAsn1ToPem(cert->rawData, cert->rawDataLen, &symbol, (char **)&buff->data, &buff->dataLen);
}
#endif // HITLS_BSL_PEM

int32_t HITLS_X509_CertGenBuff(int32_t format, HITLS_X509_Cert *cert, BSL_Buffer *buff)
{
    if (cert == NULL || buff == NULL || buff->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    switch (format) {
        case BSL_FORMAT_ASN1:
            return HITLS_X509_EncodeAsn1Cert(cert, buff);
#ifdef HITLS_BSL_PEM
        case BSL_FORMAT_PEM:
            return HITLS_X509_EncodePemCert(cert, buff);
#endif // HITLS_BSL_PEM
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

#ifdef HITLS_BSL_SAL_FILE
int32_t HITLS_X509_CertGenFile(int32_t format, HITLS_X509_Cert *cert, const char *path)
{
    if (path == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    BSL_Buffer encode = {0};
    int32_t ret = HITLS_X509_CertGenBuff(format, cert, &encode);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_SAL_WriteFile(path, encode.data, encode.dataLen);
    BSL_SAL_Free(encode.data);
    return ret;
}
#endif // HITLS_BSL_SAL_FILE

#endif // HITLS_PKI_X509_CRT_GEN

int32_t HITLS_X509_CertDigest(HITLS_X509_Cert *cert, CRYPT_MD_AlgId mdId, uint8_t *data, uint32_t *dataLen)
{
    if (cert == NULL || data == NULL || dataLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if ((cert->flag & HITLS_X509_CERT_PARSE_FLAG) != 0 || (cert->state == HITLS_X509_CERT_STATE_GEN)) {
        goto EXIT;
    }

#ifdef HITLS_PKI_X509_CRT_GEN
    int32_t ret = HITLS_X509_EncodeAsn1Cert(cert, NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    goto EXIT;
#else
    BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_FUNC_UNSUPPORT);
    return HITLS_X509_ERR_FUNC_UNSUPPORT;
#endif

EXIT:
    return cert->isProvider == true
        ? CRYPT_EAL_ProviderMd(cert->libCtx, mdId, cert->attrName, cert->rawData, cert->rawDataLen, data, dataLen)
        : CRYPT_EAL_Md(mdId, cert->rawData, cert->rawDataLen, data, dataLen);
}

#ifdef HITLS_PKI_X509_CRT_GEN
static int32_t CertSignCb(int32_t mdId, CRYPT_EAL_PkeyCtx *pivKey, HITLS_X509_Asn1AlgId *signAlgId,
    HITLS_X509_Cert *cert)
{
    BSL_ASN1_Buffer tbsAsn1 = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL};
    BSL_Buffer signBuff = {0};

    cert->signAlgId = *signAlgId;
    cert->tbs.signAlgId = *signAlgId;
    int32_t ret = EncodeTbsCertificate(&cert->tbs, &tbsAsn1);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_SignAsn1Data(pivKey, mdId, &tbsAsn1, &signBuff, &cert->signature);
    BSL_SAL_Free(tbsAsn1.buff);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    cert->tbs.tbsRawData = signBuff.data;
    cert->tbs.tbsRawDataLen = signBuff.dataLen;
    cert->state = HITLS_X509_CERT_STATE_SIGN;
    return ret;
}

int32_t HITLS_X509_CertSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
    HITLS_X509_Cert *cert)
{
    if (cert == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if ((cert->flag & HITLS_X509_CERT_PARSE_FLAG) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SIGN_AFTER_PARSE);
        return HITLS_X509_ERR_SIGN_AFTER_PARSE;
    }
    if (cert->state == HITLS_X509_CERT_STATE_SIGN || cert->state == HITLS_X509_CERT_STATE_GEN) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t ret = CheckCertTbs(cert);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_SAL_FREE(cert->signature.buff);
    cert->signature.len = 0;
    BSL_SAL_FREE(cert->tbs.tbsRawData);
    cert->tbs.tbsRawDataLen = 0;
    BSL_SAL_FREE(cert->rawData);
    cert->rawDataLen = 0;
#ifdef HITLS_CRYPTO_SM2
    if (cert->signAlgId.algId == BSL_CID_SM2DSAWITHSM3) {
        BSL_SAL_FREE(cert->signAlgId.sm2UserId.data);
        cert->signAlgId.sm2UserId.dataLen = 0;
    }
#endif
    return HITLS_X509_Sign(mdId, prvKey, algParam, cert, (HITLS_X509_SignCb)CertSignCb);
}
#endif // HITLS_PKI_X509_CRT_GEN

HITLS_X509_Cert *HITLS_X509_ProviderCertNew(HITLS_PKI_LibCtx *libCtx, const char *attrName)
{
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    if (cert == NULL) {
        return NULL;
    }
    cert->libCtx = libCtx;
    cert->attrName = attrName;
    cert->isProvider = true;
    return cert;
}

#ifdef HITLS_PKI_X509_CRT_PARSE
int32_t HITLS_X509_ProviderCertParseBuff(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const BSL_Buffer *encode, HITLS_X509_Cert **cert)
{
    int32_t encodeFormat = CRYPT_EAL_GetEncodeFormat(format);
    return ProviderCertParseBuffInternal(libCtx, attrName, encodeFormat, encode, cert);
}

#ifdef HITLS_BSL_SAL_FILE
int32_t HITLS_X509_ProviderCertParseFile(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const char *path, HITLS_X509_Cert **cert)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_X509_ProviderCertParseBuff(libCtx, attrName, format, &encode, cert);
    BSL_SAL_Free(data);
    return ret;
}

int32_t HITLS_X509_ProviderCertParseBundleFile(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const char *path, HITLS_X509_List **certlist)
{
    int32_t encodeFormat = CRYPT_EAL_GetEncodeFormat(format);
    return ProviderCertParseBundleFileInternal(libCtx, attrName, encodeFormat, path, certlist);
}
#endif // HITLS_BSL_SAL_FILE
#endif // HITLS_PKI_X509_CRT_PARSE
#endif // HITLS_PKI_X509_CRT
