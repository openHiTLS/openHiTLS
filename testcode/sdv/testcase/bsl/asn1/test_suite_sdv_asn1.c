/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "bsl_sal.h"
#include "bsl_asn1.h"
#include "bsl_err.h"
#include "bsl_log.h"

/* END_HEADER */

/* They are placed in their respective implementations and belong to specific applications, not asn1 modules */
#define BSL_ASN1_CTX_SPECIFIC_TAG_VER       0
#define BSL_ASN1_CTX_SPECIFIC_TAG_ISSUERID  1
#define BSL_ASN1_CTX_SPECIFIC_TAG_SUBJECTID 2
#define BSL_ASN1_CTX_SPECIFIC_TAG_EXTENSION 3

BSL_ASN1_TemplateItem certTempl[] = {
 {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* x509 */
  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* tbs */
   /* 2: version */
   {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_CTX_SPECIFIC_TAG_VER, BSL_ASN1_FLAG_DEFAULT, 2},
    {BSL_ASN1_TAG_INTEGER, 0, 3},
   /* 2: serial number */
   {BSL_ASN1_TAG_INTEGER, 0, 2},
   /* 2: signature info */
   {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
    {BSL_ASN1_TAG_OBJECT_ID, 0, 3},
    {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 3}, // 8
   /* 2: issuer */
   {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, BSL_ASN1_FLAG_SAME, 3},
     {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 4},
      {BSL_ASN1_TAG_OBJECT_ID, 0, 5},
      {BSL_ASN1_TAG_ANY, 0, 5},
   /* 2: validity */
   {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
    {BSL_ASN1_TAG_CHOICE, 0, 3},
    {BSL_ASN1_TAG_CHOICE, 0, 3}, // 16
   /* 2: subject ref: issuer */
   {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, BSL_ASN1_FLAG_SAME, 3},
     {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 4},
      {BSL_ASN1_TAG_OBJECT_ID, 0, 5},
      {BSL_ASN1_TAG_ANY, 0, 5},
   /* 2: subject public key info ref signature info */
   {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 3},
     {BSL_ASN1_TAG_OBJECT_ID, 0, 4},
     {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 4}, // 25
    {BSL_ASN1_TAG_BITSTRING, 0, 3},
   /* 2: issuer id, subject id */
   {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_CTX_SPECIFIC_TAG_ISSUERID, BSL_ASN1_FLAG_OPTIONAL, 2},
   {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_CTX_SPECIFIC_TAG_SUBJECTID, BSL_ASN1_FLAG_OPTIONAL, 2},
   /* 2: extension */
   {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_CTX_SPECIFIC_TAG_EXTENSION,
   BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
    {BSL_ASN1_TAG_OBJECT_ID, 0, 3},
    {BSL_ASN1_TAG_BOOLEAN, BSL_ASN1_FLAG_DEFAULT, 3},
    {BSL_ASN1_TAG_OCTETSTRING, 0, 3},
  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* signAlg */
    {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
    {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 2}, // 35
  {BSL_ASN1_TAG_BITSTRING, 0, 1} /* sig */
};

typedef enum {
    BSL_ASN1_TAG_VERSION_IDX = 0,
    BSL_ASN1_TAG_SERIAL_IDX = 1,
    BSL_ASN1_TAG_SIGNINFO_OID_IDX = 2,
    BSL_ASN1_TAG_SIGNINFO_ANY_IDX = 3,
    BSL_ASN1_TAG_ISSUER_IDX = 4,
    BSL_ASN1_TAG_BEFORE_VALID_IDX = 5,
    BSL_ASN1_TAG_AFTER_VALID_IDX = 6,
    BSL_ASN1_TAG_SUBJECT_IDX = 7,
    BSL_ASN1_TAG_SUBKEYINFO_IDX = 8,
    BSL_ASN1_TAG_SUBKEYINFO_ANY_IDX = 9,
    BSL_ASN1_TAG_SUBKEYINFO_BITSTRING_IDX = 10,
    BSL_ASN1_TAG_ISSUERID_IDX = 11,
    BSL_ASN1_TAG_SUBJECTID_IDX = 12,
    BSL_ASN1_TAG_EXT_IDX = 13,
    BSL_ASN1_TAG_SIGNALG_IDX = 14,
    BSL_ASN1_TAG_SIGNALG_ANY_IDX = 15,
    BSL_ASN1_TAG_SIGN_IDX = 16
} CERT_TEMPL_IDX;

#define BSL_ASN1_TIME_UTC_1 14
#define BSL_ASN1_TIME_UTC_2 15

#define BSL_ASN1_ID_ANY_1 7
#define BSL_ASN1_ID_ANY_2 24
#define BSL_ASN1_ID_ANY_3 34

char *g_oidEcc = "\x2a\x86\x48\xce\x3d\x02\01";
char *g_oidRsaPss = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a";

int32_t BSL_ASN1_CertTagGetOrCheck(int32_t type, int32_t idx,
    void *data, void *expVal)
{
    BSL_ASN1_Buffer *param = NULL;
    uint32_t len = 0;
    switch (type) {
        case BSL_ASN1_TYPE_CHECK_CHOICE_TAG:
            if (idx == BSL_ASN1_TIME_UTC_1 || idx == BSL_ASN1_TIME_UTC_2) {
                uint8_t tag = *(uint8_t *) data;
                if ((tag & BSL_ASN1_TAG_UTCTIME) || (tag & BSL_ASN1_TAG_GENERALIZEDTIME)) {
                    *(uint8_t *) expVal = tag;
                    return BSL_SUCCESS;
                }
            }
            return BSL_ASN1_FAIL;
        case BSL_ASN1_TYPE_GET_ANY_TAG:
            param = (BSL_ASN1_Buffer *) data;
            len = param->len;
            if (idx == BSL_ASN1_ID_ANY_1 || idx == BSL_ASN1_ID_ANY_3) {
                if (strlen(g_oidRsaPss) == len && memcmp(param->buff, g_oidRsaPss, len) == 0) {
                    // note: any It can be encoded empty or it can be null
                    *(uint8_t *) expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
                    return BSL_SUCCESS;
                } else {
                    *(uint8_t *) expVal = BSL_ASN1_TAG_NULL; // is null
                    return BSL_SUCCESS;
                }
            }
            if (idx == BSL_ASN1_ID_ANY_2) {
                if (strlen(g_oidEcc) == len && memcmp(param->buff, g_oidEcc, len) == 0) {
                    // note: any It can be encoded empty or it can be null
                    *(uint8_t *) expVal = BSL_ASN1_TAG_OBJECT_ID;
                    return BSL_SUCCESS;
                } else { //
                    *(uint8_t *) expVal = BSL_ASN1_TAG_NULL; // is null
                    return BSL_SUCCESS;
                }
            }
            return BSL_ASN1_FAIL;
        default:
            break;
    }
    return BSL_ASN1_FAIL;
}

static int32_t ReadCert(const char *path, uint8_t **buff, uint32_t *len)
{
    size_t readLen;
    size_t fileLen = 0;
    int32_t ret = BSL_SAL_FileLength(path, &fileLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    bsl_sal_file_handle stream = NULL;
    ret = BSL_SAL_FileOpen(&stream, path, "rb");
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    uint8_t *fileBuff = BSL_SAL_Malloc(fileLen);
    if (fileBuff == NULL) {
        BSL_SAL_FileClose(stream);
        return BSL_MALLOC_FAIL;
    }
    do {
        ret = BSL_SAL_FileRead(stream, fileBuff, 1, fileLen, &readLen);
        BSL_SAL_FileClose(stream);
        if (ret != BSL_SUCCESS) {
            break;
        }
        
        *buff = fileBuff;
        *len = (uint32_t)fileLen;
        return ret;
    } while (0);
    BSL_SAL_FREE(fileBuff);
    return ret;
}

void BinLogFixLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4)
{
    (void)logLevel;
    (void)logType;
    printf("logId:%u\t", logId);
    printf(format, para1, para2, para3, para4);
    printf("\n");
}

void BinLogVarLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para)
{
    (void)logLevel;
    (void)logType;
    printf("logId:%u\t", logId);
    printf(format, para);
    printf("\n");
}

/* BEGIN_CASE */
void SDV_BSL_ASN1_DecodeTemplate_TC001(char *path)
{
    BSL_LOG_BinLogFuncs func = {0};
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    uint32_t fileLen = 0;
    uint8_t *fileBuff = NULL;
    int32_t ret = ReadCert(path, &fileBuff, &fileLen);
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint8_t *rawBuff = fileBuff;
    BSL_ASN1_Buffer asnArr[BSL_ASN1_TAG_SIGN_IDX + 1] = {0};
    BSL_ASN1_Template templ = {certTempl, sizeof(certTempl) / sizeof(certTempl[0])};
    ret = BSL_ASN1_DecodeTemplate(NULL, BSL_ASN1_CertTagGetOrCheck, &fileBuff, &fileLen, asnArr, BSL_ASN1_TAG_SIGN_IDX + 1);
    ASSERT_EQ(ret, BSL_NULL_INPUT);
    ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &fileBuff, &fileLen, asnArr, BSL_ASN1_TAG_SIGN_IDX + 1);
    ASSERT_EQ(ret, BSL_ASN1_ERR_NO_CALLBACK);
    ret = BSL_ASN1_DecodeTemplate(&templ, BSL_ASN1_CertTagGetOrCheck, NULL, &fileLen, asnArr, BSL_ASN1_TAG_SIGN_IDX + 1);
    ASSERT_EQ(ret, BSL_NULL_INPUT);
    ret = BSL_ASN1_DecodeTemplate(&templ, BSL_ASN1_CertTagGetOrCheck, &fileBuff, NULL, asnArr, BSL_ASN1_TAG_SIGN_IDX + 1);
    ASSERT_EQ(ret, BSL_NULL_INPUT);
    ret = BSL_ASN1_DecodeTemplate(&templ, BSL_ASN1_CertTagGetOrCheck, &fileBuff, &fileLen, NULL, BSL_ASN1_TAG_SIGN_IDX + 1);
    ASSERT_EQ(ret, BSL_NULL_INPUT);
    ret = BSL_ASN1_DecodeTemplate(&templ, BSL_ASN1_CertTagGetOrCheck, &fileBuff, &fileLen, asnArr, 0);
    ASSERT_EQ(ret, BSL_ASN1_ERR_OVERFLOW);
exit:
    BSL_SAL_FREE(rawBuff);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_CERT_FUNC_TC001(char *path, Hex *version, Hex *serial, Hex *algId, Hex *anyAlgId,
    Hex *issuer, Hex *before, Hex *after, Hex *subject, Hex *pubId, Hex *pubAny, Hex *pubKey, Hex *issuerId,
    Hex *subjectId, Hex *ext, Hex *signAlg, Hex *signAlgAny, Hex *sign)
{
    BSL_LOG_BinLogFuncs func = {0};
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    uint32_t fileLen = 0;
    uint8_t *fileBuff = NULL;
    int32_t ret = ReadCert(path, &fileBuff, &fileLen);
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint8_t *rawBuff = fileBuff;
    BSL_ASN1_Buffer asnArr[BSL_ASN1_TAG_SIGN_IDX + 1] = {0};
    BSL_ASN1_Template templ = {certTempl, sizeof(certTempl) / sizeof(certTempl[0])};
    ret = BSL_ASN1_DecodeTemplate(&templ, BSL_ASN1_CertTagGetOrCheck,
        &fileBuff, &fileLen, asnArr, BSL_ASN1_TAG_SIGN_IDX + 1);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(fileLen, 0);
    // 证书对比
    if (version->len != 0) {
        ASSERT_EQ_LOG("version compare tag", asnArr[BSL_ASN1_TAG_VERSION_IDX].tag, BSL_ASN1_TAG_INTEGER);
        ASSERT_COMPARE("version compare", version->x, version->len,
            asnArr[BSL_ASN1_TAG_VERSION_IDX].buff, asnArr[BSL_ASN1_TAG_VERSION_IDX].len);
    }

    ASSERT_EQ_LOG("serial compare tag", asnArr[BSL_ASN1_TAG_SERIAL_IDX].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_COMPARE("serial compare", serial->x, serial->len,
        asnArr[BSL_ASN1_TAG_SERIAL_IDX].buff, asnArr[BSL_ASN1_TAG_SERIAL_IDX].len);

    ASSERT_EQ_LOG("algid compare tag", asnArr[BSL_ASN1_TAG_SIGNINFO_OID_IDX].tag, BSL_ASN1_TAG_OBJECT_ID);
    ASSERT_COMPARE("algid compare", algId->x, algId->len,
        asnArr[BSL_ASN1_TAG_SIGNINFO_OID_IDX].buff, asnArr[BSL_ASN1_TAG_SIGNINFO_OID_IDX].len);

    if (anyAlgId->len != 0) {
        ASSERT_COMPARE("any algid compare", anyAlgId->x, anyAlgId->len,
            asnArr[BSL_ASN1_TAG_SIGNINFO_ANY_IDX].buff, asnArr[BSL_ASN1_TAG_SIGNINFO_ANY_IDX].len);
    } else {
        ASSERT_EQ(asnArr[BSL_ASN1_TAG_SIGNINFO_ANY_IDX].buff, NULL);
        ASSERT_EQ(asnArr[BSL_ASN1_TAG_SIGNINFO_ANY_IDX].len, 0);
    }

    ASSERT_EQ_LOG("issuer compare tag", asnArr[BSL_ASN1_TAG_ISSUER_IDX].tag,
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE);
    ASSERT_COMPARE("issuer compare", issuer->x, issuer->len,
        asnArr[BSL_ASN1_TAG_ISSUER_IDX].buff, asnArr[BSL_ASN1_TAG_ISSUER_IDX].len);

    ASSERT_COMPARE("before compare", before->x, before->len,
        asnArr[BSL_ASN1_TAG_BEFORE_VALID_IDX].buff, asnArr[BSL_ASN1_TAG_BEFORE_VALID_IDX].len);
    
    ASSERT_COMPARE("after compare", after->x, after->len,
        asnArr[BSL_ASN1_TAG_AFTER_VALID_IDX].buff, asnArr[BSL_ASN1_TAG_AFTER_VALID_IDX].len);

    ASSERT_EQ_LOG("subject compare tag", asnArr[BSL_ASN1_TAG_SUBJECT_IDX].tag,
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE);
    ASSERT_COMPARE("subject compare", subject->x, subject->len,
        asnArr[BSL_ASN1_TAG_SUBJECT_IDX].buff, asnArr[BSL_ASN1_TAG_SUBJECT_IDX].len);

    ASSERT_EQ_LOG("subject pub key compare tag", asnArr[BSL_ASN1_TAG_SUBKEYINFO_IDX].tag, BSL_ASN1_TAG_OBJECT_ID);
    ASSERT_COMPARE("subject pub key id compare", pubId->x, pubId->len,
        asnArr[BSL_ASN1_TAG_SUBKEYINFO_IDX].buff, asnArr[BSL_ASN1_TAG_SUBKEYINFO_IDX].len);

    if (pubAny->len != 0) {
        ASSERT_COMPARE("any pub key compare", pubAny->x, pubAny->len,
            asnArr[BSL_ASN1_TAG_SUBKEYINFO_ANY_IDX].buff, asnArr[BSL_ASN1_TAG_SUBKEYINFO_ANY_IDX].len);
    } else {
        ASSERT_EQ(asnArr[BSL_ASN1_TAG_SUBKEYINFO_ANY_IDX].buff, NULL);
        ASSERT_EQ(asnArr[BSL_ASN1_TAG_SUBKEYINFO_ANY_IDX].len, 0);
    }

    ASSERT_EQ_LOG("subject pub key compare tag", asnArr[BSL_ASN1_TAG_SUBKEYINFO_BITSTRING_IDX].tag,
        BSL_ASN1_TAG_BITSTRING);
    ASSERT_COMPARE("subject pub key compare", pubKey->x, pubKey->len,
        asnArr[BSL_ASN1_TAG_SUBKEYINFO_BITSTRING_IDX].buff, asnArr[BSL_ASN1_TAG_SUBKEYINFO_BITSTRING_IDX].len);
    
    if (issuerId->len != 0) {
        ASSERT_COMPARE("issuerId compare", issuerId->x, issuerId->len,
            asnArr[BSL_ASN1_TAG_ISSUERID_IDX].buff, asnArr[BSL_ASN1_TAG_ISSUERID_IDX].len);
    } else {
        ASSERT_EQ(asnArr[BSL_ASN1_TAG_ISSUERID_IDX].buff, NULL);
        ASSERT_EQ(asnArr[BSL_ASN1_TAG_ISSUERID_IDX].len, 0);
    }
    if (subjectId->len != 0) {
        ASSERT_COMPARE("subjectId compare", subjectId->x, subjectId->len,
            asnArr[BSL_ASN1_TAG_SUBJECTID_IDX].buff, asnArr[BSL_ASN1_TAG_SUBJECTID_IDX].len);
    } else {
        ASSERT_EQ(asnArr[BSL_ASN1_TAG_SUBJECTID_IDX].buff, NULL);
        ASSERT_EQ(asnArr[BSL_ASN1_TAG_SUBJECTID_IDX].len, 0);
    }

    if (ext->len != 0) { // v1 没有ext
        ASSERT_EQ_LOG("ext compare tag", asnArr[BSL_ASN1_TAG_EXT_IDX].tag,
            BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_CTX_SPECIFIC_TAG_EXTENSION);
        ASSERT_COMPARE("ext compare", ext->x, ext->len,
            asnArr[BSL_ASN1_TAG_EXT_IDX].buff, asnArr[BSL_ASN1_TAG_EXT_IDX].len);
    }
    
    ASSERT_EQ_LOG("signAlg compare tag", asnArr[BSL_ASN1_TAG_SIGNALG_IDX].tag, BSL_ASN1_TAG_OBJECT_ID);
    ASSERT_COMPARE("signAlg compare", signAlg->x, signAlg->len,
        asnArr[BSL_ASN1_TAG_SIGNALG_IDX].buff, asnArr[BSL_ASN1_TAG_SIGNALG_IDX].len);

    if (signAlgAny->len != 0) {
        ASSERT_COMPARE("signAlgAny compare", signAlgAny->x, signAlgAny->len,
            asnArr[BSL_ASN1_TAG_SIGNALG_ANY_IDX].buff, asnArr[BSL_ASN1_TAG_SIGNALG_ANY_IDX].len);
    } else {
        ASSERT_EQ(asnArr[BSL_ASN1_TAG_SIGNALG_ANY_IDX].buff, NULL);
        ASSERT_EQ(asnArr[BSL_ASN1_TAG_SIGNALG_ANY_IDX].len, 0);
    }

    ASSERT_EQ_LOG("sign compare tag", asnArr[BSL_ASN1_TAG_SIGN_IDX].tag, BSL_ASN1_TAG_BITSTRING);
    ASSERT_COMPARE("sign compare", sign->x, sign->len,
        asnArr[BSL_ASN1_TAG_SIGN_IDX].buff, asnArr[BSL_ASN1_TAG_SIGN_IDX].len);
exit:
    BSL_SAL_FREE(rawBuff);
}
/* END_CASE */


/* BEGIN_CASE */
void SDV_BSL_ASN1_DecodePrimitiveItem_FUNC_TC001(Hex *val)
{
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BOOLEAN, val->len, val->x};
    bool res;
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(NULL, &res);
    ASSERT_EQ(ret, BSL_NULL_INPUT);
    ret = BSL_ASN1_DecodePrimitiveItem(&asn, NULL);
    ASSERT_EQ(ret, BSL_NULL_INPUT);
exit:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DecodePrimitiveItem_FUNC_TC002(int tag, Hex *val)
{
    BSL_ASN1_Buffer asn = {(uint8_t)tag, val->len, val->x};
    int32_t res;
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(NULL, &res);
    ASSERT_EQ(ret, BSL_NULL_INPUT);
    ret = BSL_ASN1_DecodePrimitiveItem(&asn, NULL);
    ASSERT_EQ(ret, BSL_NULL_INPUT);
exit:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DecodePrimitiveItem_FUNC_TC003(Hex *val)
{
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BITSTRING, val->len, val->x};
    BSL_ASN1_BitString res;
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(NULL, &res);
    ASSERT_EQ(ret, BSL_NULL_INPUT);
    ret = BSL_ASN1_DecodePrimitiveItem(&asn, NULL);
    ASSERT_EQ(ret, BSL_NULL_INPUT);
exit:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_BOOL_PRIMITIVEITEM_FUNC(Hex *val, int expectVal)
{
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BOOLEAN, val->len, val->x};
    bool res;
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(&asn, &res);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ((bool)expectVal, res);
exit:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_INT_PRIMITIVEITEM_FUNC(int tag, Hex *val, int result, int expectVal)
{
    BSL_ASN1_Buffer asn = {(uint8_t)tag, val->len, val->x};
    int32_t res;
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(&asn, &res);
    ASSERT_EQ(ret, result);
    if (ret == BSL_SUCCESS) {
        ASSERT_EQ((uint32_t)expectVal, res);
    }
    
exit:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_BITSTRING_PRIMITIVEITEM_FUNC(Hex *val, int result, int unusedBits)
{
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BITSTRING, val->len, val->x};
    BSL_ASN1_BitString res;
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(&asn, &res);
    ASSERT_EQ(ret, result);
    if (ret == BSL_SUCCESS) {
        ASSERT_EQ((uint32_t)unusedBits, res.unusedBits);
        ASSERT_EQ(val->len - 1, res.len);
        ASSERT_COMPARE("bit string", res.buff, res.len, val->x + 1, val->len - 1);
    }
    
exit:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_TIME_PRIMITIVEITEM_FUNC(int tag, Hex *val, int result,
    int year, int month, int day, int hour, int minute, int second)
{
    BSL_ASN1_Buffer asn = {tag, val->len, val->x};
    BSL_TIME res = {0};
    int32_t ret = BSL_ASN1_DecodePrimitiveItem(&asn, &res);
    ASSERT_EQ(ret, result);
    if (ret == BSL_SUCCESS) {
        ASSERT_EQ(res.year, year);
        ASSERT_EQ(res.month, month);
        ASSERT_EQ(res.day, day);
        ASSERT_EQ(res.hour, hour);
        ASSERT_EQ(res.minute, minute);
        ASSERT_EQ(res.second, second);
    }
exit:
    return;
}
/* END_CASE */
