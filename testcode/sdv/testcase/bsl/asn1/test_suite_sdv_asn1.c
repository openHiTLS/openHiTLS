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

/* BEGIN_HEADER */

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "bsl_sal.h"
#include "bsl_asn1_internal.h"
#include "bsl_err.h"
#include "bsl_log.h"
#include "sal_time.h"
#include "sal_file.h"
#include "bsl_obj_internal.h"
#include "hitls_x509_local.h"

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

BSL_ASN1_TemplateItem maxDepthTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 7},
};

#ifdef HITLS_BSL_SAL_FILE
static BSL_ASN1_TemplateItem g_rsaPub[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* ignore seq */
            {BSL_ASN1_TAG_INTEGER, 0, 1},                         /* n */
            {BSL_ASN1_TAG_INTEGER, 0, 1},                         /* e */
    };

static BSL_ASN1_TemplateItem g_rsaPrv[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* ignore seq header */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* version */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* n */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* e */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* d */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* p */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* q */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* d mod (p-1) */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* d mod (q-1) */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* q^-1 mod p */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
         BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 1}, /* OtherPrimeInfos OPTIONAL */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2}, /* OtherPrimeInfo */
                {BSL_ASN1_TAG_INTEGER, 0, 3}, /* ri */
                {BSL_ASN1_TAG_INTEGER, 0, 3}, /* di */
                {BSL_ASN1_TAG_INTEGER, 0, 3} /* ti */
};

typedef struct {
    BSL_ASN1_TemplateItem *items;
    uint32_t itemNum;
    uint32_t asnNum;
} TestAsn1Param;

static TestAsn1Param g_tests[] = {
    {g_rsaPub, sizeof(g_rsaPub) / sizeof(g_rsaPub[0]), 2},
    {g_rsaPrv, sizeof(g_rsaPrv) / sizeof(g_rsaPrv[0]), 10},
};
#endif

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

int32_t BSL_ASN1_CertTagGetOrCheck(int32_t type, uint32_t idx, void *data, void *expVal)
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

#ifdef HITLS_BSL_SAL_FILE
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
#else
static int32_t ReadCert(const char *path, uint8_t **buff, uint32_t *len)
{
    (void)path;
    (void)buff;
    (void)len;
    return BSL_INTERNAL_EXCEPTION;
}
#endif

#ifdef HITLS_BSL_LOG
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
#endif

/* BEGIN_CASE */
void SDV_BSL_ASN1_DecodeTemplate_TC001(char *path)
{
#ifndef HITLS_BSL_SAL_FILE
    SKIP_TEST();
#endif
#ifdef HITLS_BSL_LOG
    BSL_LOG_BinLogFuncs func = {0};
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);
#endif

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
    ASSERT_EQ(ret, BSL_NULL_INPUT);
EXIT:
    BSL_SAL_FREE(rawBuff);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_TEMPLATE_TC002(char *path)
{
#ifndef HITLS_BSL_SAL_FILE
    SKIP_TEST();
#endif
#ifdef HITLS_BSL_LOG
    BSL_LOG_BinLogFuncs func = {0};
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);
#endif

    uint32_t fileLen = 0;
    uint8_t *fileBuff = NULL;
    int32_t ret = ReadCert(path, &fileBuff, &fileLen);
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint8_t *rawBuff = fileBuff;
    BSL_ASN1_Buffer asnArr[BSL_ASN1_TAG_SIGN_IDX + 1] = {0};
    BSL_ASN1_Template templ = {maxDepthTempl, sizeof(maxDepthTempl) / sizeof(maxDepthTempl[0])};
    ret = BSL_ASN1_DecodeTemplate(&templ, BSL_ASN1_CertTagGetOrCheck, &fileBuff, &fileLen, asnArr, BSL_ASN1_TAG_SIGN_IDX + 1);
    ASSERT_EQ(ret, BSL_ASN1_ERR_MAX_DEPTH);
EXIT:
    BSL_SAL_FREE(rawBuff);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_TEMPLATE_DEPTH_MAX_SUCCESS_TC001(Hex *encode)
{
    BSL_ASN1_TemplateItem items[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
                {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
                    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 3},
                        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 4},
                            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 5},
                                {BSL_ASN1_TAG_INTEGER, 0, 6},
    };
    BSL_ASN1_Template templ = {items, sizeof(items) / sizeof(items[0])};
    BSL_ASN1_Buffer asnArr[1] = {0}; /* only one primitive item */

    uint8_t *tmp = encode->x;
    uint32_t tmpLen = encode->len;
    ASSERT_EQ(BSL_ASN1_DecodeTemplate(&templ, NULL, &tmp, &tmpLen, asnArr, 1), BSL_SUCCESS);
    ASSERT_EQ(tmpLen, 0);
    ASSERT_EQ(asnArr[0].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_EQ(asnArr[0].len, 1);
    ASSERT_EQ(asnArr[0].buff[0], 0x01);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_TEMPLATE_LAYER_END_OPTIONAL_TC001(Hex *encode)
{
    BSL_ASN1_TemplateItem items[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* outer */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* inner */
                {BSL_ASN1_TAG_INTEGER, 0, 2}, /* inner int */
                {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
                    BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 2}, /* OPTIONAL inner seq */
                    {BSL_ASN1_TAG_INTEGER, 0, 3}, /* child (skipped by HEADERONLY) */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* outer sibling seq */
                {BSL_ASN1_TAG_INTEGER, 0, 2}, /* sibling int */
    };
    BSL_ASN1_Template templ = {items, sizeof(items) / sizeof(items[0])};
    BSL_ASN1_Buffer asnArr[3] = {0}; /* inner int, optional seq(headeronly), sibling int */

    uint8_t *tmp = encode->x;
    uint32_t tmpLen = encode->len;
    ASSERT_EQ(BSL_ASN1_DecodeTemplate(&templ, NULL, &tmp, &tmpLen, asnArr, 3), BSL_SUCCESS);
    ASSERT_EQ(tmpLen, 0);

    ASSERT_EQ(asnArr[0].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_EQ(asnArr[0].len, 1);
    ASSERT_EQ(asnArr[0].buff[0], 0x01);

    /* optional SEQUENCE not present => tag 0 */
    ASSERT_EQ(asnArr[1].tag, 0);
    ASSERT_EQ(asnArr[1].len, 0);
    ASSERT_EQ(asnArr[1].buff, NULL);

    ASSERT_EQ(asnArr[2].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_EQ(asnArr[2].len, 1);
    ASSERT_EQ(asnArr[2].buff[0], 0x02);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_TEMPLATE_LAYER_END_REQUIRED_TC001(Hex *encode, int expectRet)
{
    BSL_ASN1_TemplateItem items[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_INTEGER, 0, 1},
            {BSL_ASN1_TAG_NULL, BSL_ASN1_FLAG_OPTIONAL, 1},
            {BSL_ASN1_TAG_INTEGER, 0, 1},
    };
    BSL_ASN1_Template templ = {items, sizeof(items) / sizeof(items[0])};
    BSL_ASN1_Buffer asnArr[3] = {0}; /* INTEGER, optional NULL, INTEGER */

    uint8_t *tmp = encode->x;
    uint32_t tmpLen = encode->len;
    ASSERT_EQ(BSL_ASN1_DecodeTemplate(&templ, NULL, &tmp, &tmpLen, asnArr, 3), expectRet);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_TEMPLATE_INVALID_DEPTH_SKIP_TC001(Hex *encode, int expectRet)
{
    BSL_ASN1_TemplateItem items[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_INTEGER, 0, 2},  /* Invalid: depth jumps from 0 to 2 */
    };
    BSL_ASN1_Template templ = {items, sizeof(items) / sizeof(items[0])};
    BSL_ASN1_Buffer asnArr[1] = {0};

    uint8_t *tmp = encode->x;
    uint32_t tmpLen = encode->len;
    ASSERT_EQ(BSL_ASN1_DecodeTemplate(&templ, NULL, &tmp, &tmpLen, asnArr, 1), expectRet);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_CERT_FUNC_TC001(char *path, Hex *version, Hex *serial, Hex *algId, Hex *anyAlgId,
    Hex *issuer, Hex *before, Hex *after, Hex *subject, Hex *pubId, Hex *pubAny, Hex *pubKey, Hex *issuerId,
    Hex *subjectId, Hex *ext, Hex *signAlg, Hex *signAlgAny, Hex *sign)
{
#ifndef HITLS_BSL_SAL_FILE
    SKIP_TEST();
#endif
#ifdef HITLS_BSL_LOG
    BSL_LOG_BinLogFuncs func = {0};
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);
#endif

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
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
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
EXIT:
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
EXIT:
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
EXIT:
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
EXIT:
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
    
EXIT:
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
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
    
EXIT:
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
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODELEN_FUNC(int flag, Hex *val, int res)
{
    uint8_t *encode = val->x;
    uint32_t encodeLen = val->len;
    uint32_t len = 0;
    ASSERT_EQ(BSL_ASN1_DecodeLen(&encode, &encodeLen, flag, &len), res);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_WRONG_INPUT_FUNC()
{
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;
    uint32_t valueLen = 0;
    bool completeLen = 0;
    uint8_t tag = 0x30;
    BSL_ASN1_Buffer asnItem = {0};
    ASSERT_EQ(BSL_ASN1_DecodeLen(&encode, &encodeLen, completeLen, &valueLen), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASN1_DecodeTagLen(tag, &encode, &encodeLen, &valueLen), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_ASN1_DecodeItem(&encode, &encodeLen, &asnItem), BSL_NULL_INPUT);
    BSL_ASN1_TemplateItem listTempl = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0};
    BSL_ASN1_Template templ = {&listTempl, 1};
    ASSERT_EQ(BSL_ASN1_DecodeTemplate(&templ, NULL, &encode, &encodeLen, &asnItem, 1), BSL_NULL_INPUT);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODECOMPLETELEN_FUNC(Hex *val, int ecpLen, int res)
{
    uint8_t *encode = val->x;
    uint32_t encodeLen = val->len;
    ASSERT_EQ(BSL_ASN1_GetCompleteLen(encode, &encodeLen), res);
    if (res == BSL_SUCCESS) {
        ASSERT_EQ(encodeLen, ecpLen);
    }
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_TEMPLATE_API_TC001(void)
{
    BSL_ASN1_TemplateItem item[] = {{BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}};
    BSL_ASN1_Template templ = {item, 1};
    BSL_ASN1_Buffer asnArr[1] = {0};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    /* templ */
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(NULL, asnArr, 1, &encode, &encodeLen), BSL_INVALID_ARG);
    templ.templItems = NULL;
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asnArr, 1, &encode, &encodeLen), BSL_INVALID_ARG);
    templ.templItems = item;
    templ.templNum = 0;
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asnArr, 1, &encode, &encodeLen), BSL_INVALID_ARG);
    templ.templNum = 1;

    /* asnArr */
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, NULL, 1, &encode, &encodeLen), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asnArr, 0, &encode, &encodeLen), BSL_INVALID_ARG);

    /* encode */
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asnArr, 1, NULL, &encodeLen), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asnArr, 1, &encode, NULL), BSL_INVALID_ARG);
    encode = (uint8_t*)&encodeLen;
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asnArr, 1, &encode, &encodeLen), BSL_INVALID_ARG);

EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_TEMPLATE_ERROR_TC001(void)
{
    BSL_ASN1_Template templ = {maxDepthTempl, sizeof(maxDepthTempl) / sizeof(maxDepthTempl[0])};
    BSL_ASN1_Buffer asnArr[1] = {0};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;
    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asnArr, 1, &encode, &encodeLen), BSL_ASN1_ERR_MAX_DEPTH);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_TEMPLATE_ERROR_TC002(int tag, int len, int ret)
{
    BSL_ASN1_TemplateItem item[] = {{tag, 0, 0}};
    BSL_ASN1_Template templ = {item, 1};
    uint8_t data = 1;
    BSL_ASN1_Buffer asn = {tag, len, &data};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &encode, &encodeLen), ret);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_TEMPLATE_ERROR_TC003(Hex *data)
{
    BSL_ASN1_TemplateItem items[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_INTEGER, 0, 1},
            {BSL_ASN1_TAG_ANY, 0, 1},
            {BSL_ASN1_TAG_CHOICE, 0, 1}
    };
    BSL_ASN1_Template templ = {items, sizeof(items) / sizeof(items[0])};
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_INTEGER, data->len, data->x};
    BSL_ASN1_Buffer asns[] = {asn, asn, asn, asn};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;
    uint32_t expectAsnNum = 3;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asns, expectAsnNum - 1, &encode, &encodeLen),
              BSL_ASN1_ERR_ENCODE_ASN_LACK);
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asns, expectAsnNum + 1, &encode, &encodeLen),
              BSL_ASN1_ERR_ENCODE_ASN_TOO_MUCH);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_TEMPLATE_ERROR_TC004(void)
{
    BSL_ASN1_TemplateItem items[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_INTEGER, 0, 1},
    };
    BSL_ASN1_Template templ = {items, sizeof(items) / sizeof(items[0])};
    int iData = 256;
    BSL_ASN1_Buffer asn[] = {{BSL_ASN1_TAG_ENUMERATED, sizeof(int), (uint8_t *)&iData}};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asn, sizeof(asn) / sizeof(asn[0]), &encode, &encodeLen),
              BSL_ASN1_ERR_TAG_EXPECTED);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_BOOL_FUNC(int data, Hex *expect)
{
    bool bData = (bool)data;
    BSL_ASN1_TemplateItem item[] = {{BSL_ASN1_TAG_BOOLEAN, 0, 0}};
    BSL_ASN1_Template templ = {item, 1};
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BOOLEAN, 1, (uint8_t *)&bData};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &encode, &encodeLen), BSL_SUCCESS);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode bool", expect->x, expect->len, encode, encodeLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(encode);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_INT_LIMB_FUNC(int ret, int data, Hex *expect)
{
    BSL_ASN1_TemplateItem item[] = {{BSL_ASN1_TAG_INTEGER, 0, 0}};
    BSL_ASN1_Template templ = {item, 1};
    BSL_ASN1_Buffer asn = {0};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, data, &asn), BSL_SUCCESS);

    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &encode, &encodeLen), ret);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode int", expect->x, expect->len, encode, encodeLen);
EXIT:
    BSL_SAL_Free(asn.buff);
    if (ret == BSL_SUCCESS) {
        BSL_SAL_Free(encode);
    }
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_INT_BN_FUNC(Hex *bn, Hex *expect)
{
    BSL_ASN1_TemplateItem item[] = {{BSL_ASN1_TAG_INTEGER, 0, 0}};
    BSL_ASN1_Template templ = {item, 1};
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_INTEGER, bn->len, bn->x};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &encode, &encodeLen), BSL_SUCCESS);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode int", expect->x, expect->len, encode, encodeLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(encode);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_BITSTRING_FUNC(int ret, Hex *data, int unusedBits, Hex *expect)
{
    BSL_ASN1_TemplateItem item[] = {{BSL_ASN1_TAG_BITSTRING, 0, 0}};
    BSL_ASN1_Template templ = {item, 1};
    BSL_ASN1_BitString bs = {data->x, data->len, unusedBits};
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BITSTRING,
                           data->len == 0 ? 0 : sizeof(BSL_ASN1_BitString),
                           data->len == 0 ? NULL : (uint8_t *)&bs};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &encode, &encodeLen), ret);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode bitstring", expect->x, expect->len, encode, encodeLen);
EXIT:
    if (ret == BSL_SUCCESS) {
        BSL_SAL_Free(encode);
    }
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_TIME_FUNC(int tag, int ret, int year, int month, int day, int hour, int minute, int second,
    Hex *expect)
{
    BSL_ASN1_TemplateItem item[] = {{tag, 0, 0}};
    BSL_ASN1_Template templ = {item, 1};
    BSL_TIME time = {year, month, day, hour, minute, 0, second, 0};
    BSL_ASN1_Buffer asn = {tag, sizeof(BSL_TIME), (uint8_t *)&time};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &encode, &encodeLen), ret);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode time", expect->x, expect->len, encode, encodeLen);
EXIT:
    if (ret == BSL_SUCCESS) {
        BSL_SAL_Free(encode);
    }
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_NULL_FUNC_TC001(Hex *expect)
{
    BSL_ASN1_TemplateItem item[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_NULL, 0, 1},
            {BSL_ASN1_TAG_NULL, BSL_ASN1_FLAG_OPTIONAL, 1},
            {BSL_ASN1_TAG_NULL, BSL_ASN1_FLAG_DEFAULT, 1},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
                {BSL_ASN1_TAG_NULL, 0, 2},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_OPTIONAL, 1},
                {BSL_ASN1_TAG_NULL, 0, 2},
    };
    BSL_ASN1_Template templ = {item, sizeof(item) / sizeof(item[0])};
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_NULL, 0, NULL};
    BSL_ASN1_Buffer asns[] = {asn, asn, asn, asn, asn};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asns, sizeof(asns) / sizeof(asn), &encode, &encodeLen), BSL_SUCCESS);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode null", expect->x, expect->len, encode, encodeLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(encode);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_NULL_FUNC_TC002(Hex *expect)
{
    uint8_t data = 1;
    BSL_ASN1_TemplateItem item[] = {{BSL_ASN1_TAG_NULL, 0, 0}};
    BSL_ASN1_Template templ = {item, sizeof(item) / sizeof(item[0])};
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_NULL, 1, &data};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, &asn, 1, &encode, &encodeLen), BSL_SUCCESS);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode null", expect->x, expect->len, encode, encodeLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(encode);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_TEMPLATE_FUNC_TC001(Hex *expect)
{
    BSL_ASN1_TemplateItem items[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_INTEGER, 0, 1},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
                {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
                    {BSL_ASN1_TAG_INTEGER, 0, 3},
                    {BSL_ASN1_TAG_INTEGER, 0, 3},
            {BSL_ASN1_TAG_INTEGER, 0, 1},
    };
    BSL_ASN1_Template templ = {items, sizeof(items) / sizeof(items[0])};
    uint8_t iData[] = {0x01, 0x00};
    uint8_t data = 0x12;
    BSL_ASN1_Buffer asns[] = {
        {BSL_ASN1_TAG_INTEGER, sizeof(iData) / sizeof(uint8_t), iData},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 1, &data},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 1, &data},
        {BSL_ASN1_TAG_INTEGER, sizeof(iData) / sizeof(uint8_t), iData},
    };
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asns, sizeof(asns) / sizeof(asns[0]), &encode, &encodeLen), BSL_SUCCESS);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode headonly", expect->x, expect->len, encode, encodeLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(encode);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_TEMPLATE_FUNC_TC002(Hex *data, Hex *expect)
{
    BSL_ASN1_TemplateItem items[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_INTEGER, 0, 1},
            {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_OPTIONAL, 1},
            {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_DEFAULT, 1},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
                {BSL_ASN1_TAG_INTEGER, 0, 2},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_OPTIONAL, 1},
                {BSL_ASN1_TAG_INTEGER, 0, 2},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_DEFAULT, 1},
                {BSL_ASN1_TAG_INTEGER, 0, 2},
    };
    BSL_ASN1_Template templ = {items, sizeof(items) / sizeof(items[0])};
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_INTEGER, data->len, data->x};
    BSL_ASN1_Buffer asns[] = {asn, asn, asn, asn, asn, asn};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asns, sizeof(asns) / sizeof(asn), &encode, &encodeLen), BSL_SUCCESS);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode optional|default", expect->x, expect->len, encode, encodeLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(encode);
}
/* END_CASE */

static BSL_ASN1_TemplateItem g_templItem1[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_INTEGER, 0, 1},
        {BSL_ASN1_TAG_INTEGER, 0, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
            {BSL_ASN1_TAG_INTEGER, 0, 2},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
            {BSL_ASN1_TAG_INTEGER, 0, 2},
};

static BSL_ASN1_TemplateItem g_templItem2[] = {
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_INTEGER, 0, 0},
};

static BSL_ASN1_TemplateItem g_templItem3[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_OPTIONAL, 1},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
            {BSL_ASN1_TAG_INTEGER, 0, 2},
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_OPTIONAL, 0},
};

static BSL_ASN1_Template g_templ[] = {
    {g_templItem1, sizeof(g_templItem1) / sizeof(g_templItem1[0])},
    {g_templItem2, sizeof(g_templItem2) / sizeof(g_templItem2[0])},
    {g_templItem3, sizeof(g_templItem3) / sizeof(g_templItem3[0])},
};

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_TEMPLATE_FUNC_TC003(Hex *data, int templIdx, Hex *expect)
{
#define MAX_INT_ASN_NUM 4
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_INTEGER, data->len, data->x};
    BSL_ASN1_Buffer asns[MAX_INT_ASN_NUM] = {asn, asn, asn, asn};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    TestMemInit();
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(g_templ + templIdx, asns, MAX_INT_ASN_NUM, &encode, &encodeLen), BSL_SUCCESS);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode", expect->x, expect->len, encode, encodeLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(encode);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_LIST_API_TC001(void)
{
    BSL_ASN1_TemplateItem item[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_NULL, 0, 1},
            {BSL_ASN1_TAG_NULL, 0, 1},
    };
    BSL_ASN1_Template templ = {item, sizeof(item) / sizeof(item[0])};
    BSL_ASN1_Buffer asnArr[] = {
        {BSL_ASN1_TAG_NULL, 0, NULL},
        {BSL_ASN1_TAG_NULL, 0, NULL},
    };
    uint32_t arrNum = sizeof(asnArr) / sizeof(asnArr[0]);
    BSL_ASN1_Buffer out = {0};

    /* tag */
    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_TIME, 1, &templ, asnArr, arrNum, &out), BSL_INVALID_ARG);

    /* listSize */
    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_TIME, 0, &templ, asnArr, arrNum, &out), BSL_INVALID_ARG);

    /* templ */
    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, 1, NULL, asnArr, arrNum, &out), BSL_INVALID_ARG);
    templ.templItems = NULL;
    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, 1, &templ, asnArr, arrNum, &out), BSL_INVALID_ARG);
    templ.templItems = item;
    templ.templNum = 0;
    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, 1, &templ, asnArr, arrNum, &out), BSL_INVALID_ARG);
    templ.templNum = sizeof(item) / sizeof(item[0]);

    /* asnArr */
    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, 1, &templ, NULL, arrNum, &out), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, 1, &templ, asnArr, 0, &out), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, arrNum + 1, &templ, asnArr, arrNum, &out), BSL_INVALID_ARG);

    /* out */
    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, 1, &templ, asnArr, arrNum, NULL), BSL_INVALID_ARG);
    out.buff = (uint8_t *)&arrNum;
    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, 1, &templ, asnArr, arrNum, &out), BSL_INVALID_ARG);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_LIST_ERROR_TC001(void)
{
    BSL_ASN1_TemplateItem item[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_NULL, 0, 1},
    }; /* The expected number of asns in the current template is 1. */
    BSL_ASN1_Template templ = {item, sizeof(item) / sizeof(item[0])};
    BSL_ASN1_Buffer asnArr[] = {{BSL_ASN1_TAG_INTEGER, 0, NULL}};
    BSL_ASN1_Buffer out = {0};

    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, 1, &templ, asnArr, 1, &out), BSL_ASN1_ERR_TAG_EXPECTED);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_LIST_ERROR_TC002(void)
{
    BSL_ASN1_TemplateItem item[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_NULL, 0, 1},
            {BSL_ASN1_TAG_NULL, 0, 1},
    }; /* The expected number of asns in the current template is 2. */
    BSL_ASN1_Template templ = {item, sizeof(item) / sizeof(item[0])};
    BSL_ASN1_Buffer asnArr[] = {
        {BSL_ASN1_TAG_NULL, 0, NULL},
        {BSL_ASN1_TAG_NULL, 0, NULL},
        {BSL_ASN1_TAG_NULL, 0, NULL},
    };
    uint32_t arrNum = sizeof(asnArr) / sizeof(asnArr[0]);
    BSL_ASN1_Buffer out = {0};

    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, 1, &templ, asnArr, 1, &out), BSL_ASN1_ERR_ENCODE_ASN_LACK);

    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, 1, &templ, asnArr, arrNum, &out),
              BSL_ASN1_ERR_ENCODE_ASN_TOO_MUCH);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_LIST_ERROR_TC003(int tag, int ret)
{
    BSL_ASN1_TemplateItem item[] = {{tag, 0, 0}};
    BSL_ASN1_Template templ = {item, 1};
    uint8_t data = 1;
    BSL_ASN1_Buffer asn = {tag, 1, &data};
    BSL_ASN1_Buffer out = {0};

    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SET, 1, &templ, &asn, 1, &out), ret);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_LIST_TC001(int listSize, Hex *encode)
{
#ifndef HITLS_BSL_OBJ
    (void)listSize;
    (void)encode;
    SKIP_TEST();
#else
    BSL_ASN1_TemplateItem x509Name[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, 0, 0},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
                {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
                {BSL_ASN1_TAG_ANY, 0, 2}
    };
    BSL_ASN1_Template templ = {x509Name, sizeof(x509Name) / sizeof(x509Name[0])};
    BslOidString *o = BSL_OBJ_GetOID(BSL_CID_AT_ORGANIZATIONNAME);
    char *oName = "Energy TEST";
    BslOidString *cn = BSL_OBJ_GetOID(BSL_CID_AT_COMMONNAME);
    char *cnName = "Energy ECC Equipment Root CA 1";
    BSL_ASN1_Buffer in[] = {
        {BSL_ASN1_TAG_OBJECT_ID, o->octetLen, (uint8_t *)o->octs},
        {BSL_ASN1_TAG_PRINTABLESTRING, strlen(oName), (uint8_t *)oName},
        {BSL_ASN1_TAG_OBJECT_ID, cn->octetLen, (uint8_t *)cn->octs},
        {BSL_ASN1_TAG_PRINTABLESTRING, strlen(cnName), (uint8_t *)cnName},
    };
    BSL_ASN1_Buffer out = {0};

    ASSERT_EQ(BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, listSize, &templ, in, sizeof(in) / sizeof(in[0]), &out),
              BSL_SUCCESS);
    ASSERT_EQ(encode->len, out.len);
    ASSERT_COMPARE("Encode list", encode->x, encode->len, out.buff, out.len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_FREE(out.buff);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_THEN_ENCODE_FUNC_TC001(int testIdx, char *path)
{
#ifndef HITLS_BSL_SAL_FILE
    (void)testIdx;
    (void)path;
    SKIP_TEST();
#else
    BSL_ASN1_Template templ = {g_tests[testIdx].items, g_tests[testIdx].itemNum};
    uint32_t asnNum = g_tests[testIdx].asnNum;
    uint8_t *rawData = NULL;
    uint32_t dataLen = 0;
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    BSL_ASN1_Buffer *decodeAsns = (BSL_ASN1_Buffer *)BSL_SAL_Calloc(asnNum, sizeof(BSL_ASN1_Buffer));
    ASSERT_TRUE(decodeAsns != NULL);

    /* Decode */
    ASSERT_EQ(BSL_SAL_ReadFile(path, &rawData, &dataLen), BSL_SUCCESS);
    uint8_t *decode = rawData;
    uint32_t decodeLen = dataLen;
    ASSERT_EQ(BSL_ASN1_DecodeTemplate(&templ, NULL, &decode, &decodeLen, decodeAsns, asnNum),
              BSL_SUCCESS);
    ASSERT_EQ(decodeLen, 0);

    /* Encode */
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, decodeAsns, asnNum, &encode, &encodeLen), BSL_SUCCESS);
    ASSERT_EQ(encodeLen, dataLen);
    ASSERT_COMPARE("Decode then encode", rawData, dataLen, encode, encodeLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(decodeAsns);
    BSL_SAL_Free(rawData);
    BSL_SAL_Free(encode);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_THEN_DECODE_FUNC_TC001(int boolData, int number, Hex *bitString, int unusedBits, Hex *utf8,
    int year, int month, int day, int hour, int minute, int second, Hex *headonly, Hex *expect)
{
    bool bData = (bool)boolData;
    BSL_ASN1_TemplateItem items[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_BOOLEAN, 0, 1},
        {BSL_ASN1_TAG_INTEGER, 0, 1},
        {BSL_ASN1_TAG_BITSTRING, 0, 1},
        {BSL_ASN1_TAG_NULL, BSL_ASN1_FLAG_OPTIONAL, 1},
        {BSL_ASN1_TAG_UTF8STRING, 0, 1},
        {BSL_ASN1_TAG_UTCTIME, 0, 1},
        {BSL_ASN1_TAG_UTCTIME, BSL_ASN1_FLAG_OPTIONAL, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
            {BSL_ASN1_TAG_NULL, 0, 2},
    };
    BSL_ASN1_Buffer integer = {0};
    ASSERT_EQ(BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, number, &integer), BSL_SUCCESS);
    BSL_ASN1_BitString bs = {bitString->x, bitString->len, unusedBits};
    BSL_TIME time = {year, month, day, hour, minute, 0, second, 0};
    BSL_ASN1_Buffer asns[] = {
        {BSL_ASN1_TAG_BOOLEAN, sizeof(bool), (uint8_t *)&bData},                     // 0
        integer,                                                                        // 1
        {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&bs},           // 2
        {BSL_ASN1_TAG_NULL, 0, NULL},                                                   // 3
        {BSL_ASN1_TAG_UTF8STRING, utf8->len, utf8->x},                                  // 4
        {BSL_ASN1_TAG_UTCTIME, sizeof(BSL_TIME), (uint8_t *)&time},                     // 5
        {BSL_ASN1_TAG_UTCTIME, 0, NULL},                                                // 6
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, headonly->len, headonly->x}, // 7
    };
    uint32_t asnNum = sizeof(asns) / sizeof(asns[0]);
    BSL_ASN1_Template templ = {items, sizeof(items) / sizeof(items[0])};
    uint8_t *encode = NULL;
    uint32_t encodeLen = 0;

    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, asns, asnNum, &encode, &encodeLen), BSL_SUCCESS);
    ASSERT_EQ(encodeLen, expect->len);
    ASSERT_COMPARE("Encode", expect->x, expect->len, encode, encodeLen);

    uint8_t *tmp = encode;
    uint32_t tmpLen = encodeLen;
    BSL_ASN1_Buffer decAns[8] = {0}; // 8 is asnNum
    ASSERT_EQ(BSL_ASN1_DecodeTemplate(&templ, NULL, &tmp, &tmpLen, decAns, asnNum), BSL_SUCCESS);
    ASSERT_EQ(tmpLen, 0);

    bool bRes;
    ASSERT_EQ(BSL_ASN1_DecodePrimitiveItem(decAns + 0, &bRes), BSL_SUCCESS); // Check the decoded data with index 0.
    ASSERT_EQ(bRes, boolData);

    int iRes;
    ASSERT_EQ(BSL_ASN1_DecodePrimitiveItem(decAns + 1, &iRes), BSL_SUCCESS); // Check the decoded data with index 1.
    ASSERT_EQ(iRes, number);

    BSL_ASN1_BitString bs2 = {0};
    ASSERT_EQ(BSL_ASN1_DecodePrimitiveItem(decAns + 2, &bs2), BSL_SUCCESS); // Check the decoded data with index 2.
    ASSERT_EQ(bs.unusedBits, unusedBits);

    BSL_TIME time2 = {0};
    ASSERT_EQ(BSL_ASN1_DecodePrimitiveItem(decAns + 5, &time2), BSL_SUCCESS); // Check the decoded data with index 5.
    ASSERT_EQ(time2.year, year);
    ASSERT_EQ(time2.month, month);
    ASSERT_EQ(time2.day, day);
    ASSERT_EQ(time2.hour, hour);
    ASSERT_EQ(time2.minute, minute);
    ASSERT_EQ(time2.second, second);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_Free(integer.buff);
    BSL_SAL_Free(encode);
}
/* END_CASE */

/**
 * For test bmpString.
*/
/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_BMPSTRING_TC001(Hex *enc, char *dec)
{
    int32_t ret;
    BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BMPSTRING, enc->len, enc->x};
    BSL_ASN1_Buffer decode = {BSL_ASN1_TAG_BMPSTRING, 0, NULL};
    BSL_ASN1_Buffer encode = {0};
    uint8_t tmp[10] = {0xff}; // select len 10.
    BSL_ASN1_Buffer wrong = {BSL_ASN1_TAG_BMPSTRING, 10, tmp};

    TestMemInit();
    ret = BSL_ASN1_DecodePrimitiveItem(&asn, &decode);
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint32_t decLen = (uint32_t)strlen(dec);
    ASSERT_COMPARE("Decode String", decode.buff, decode.len, dec, decLen);

    BSL_ASN1_TemplateItem testTempl[] = {
        {BSL_ASN1_TAG_BMPSTRING, 0, 0}
    };
    BSL_ASN1_Template templ = {testTempl, sizeof(testTempl) / sizeof(testTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, &decode, 1, &encode.buff, &encode.len);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_COMPARE("Encode String", encode.buff + 2, encode.len - 2, enc->x, enc->len); // skip 2 bytes header
    ASSERT_TRUE(TestIsErrStackEmpty());

    BSL_SAL_FREE(encode.buff);
    ret = BSL_ASN1_EncodeTemplate(&templ, &wrong, 1, &encode.buff, &encode.len);
    ASSERT_EQ(ret, BSL_INVALID_ARG);
EXIT:
    BSL_SAL_FREE(decode.buff);
    BSL_SAL_FREE(encode.buff);
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASN1_GET_ENCODE_LEN_FUNC_TC001
 * @title  Test BSL_ASN1_GetEncodeLen function
 */
/* BEGIN_CASE */
void SDV_BSL_ASN1_GET_ENCODE_LEN_FUNC_TC001(int contentLen, int expectLen, int ret)
{
    uint32_t encodeLen = 0;
    ASSERT_EQ(BSL_ASN1_GetEncodeLen(contentLen, &encodeLen), ret);
    if (ret == BSL_SUCCESS) {
        ASSERT_EQ(encodeLen, expectLen);
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASN1_GET_ENCODE_LEN_API_TC001
 * @title  Test BSL_ASN1_GetEncodeLen abnormal input parameter
 */
/* BEGIN_CASE */
void SDV_BSL_ASN1_GET_ENCODE_LEN_API_TC001(void)
{
    uint32_t encodeLen = 0;
    // Test null pointer
    ASSERT_EQ(BSL_ASN1_GetEncodeLen(1, NULL), BSL_NULL_INPUT);

    // Test length overflow
    ASSERT_EQ(BSL_ASN1_GetEncodeLen(UINT32_MAX, &encodeLen), BSL_ASN1_ERR_LEN_OVERFLOW);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASN1_TO_UTF8_STRING_INLEN_EMPTY_FUNC_TC001
 * @title  Test BSL_ASN1_ToUtf8String with empty input length.
 * @brief  Input ASN.1 buffer has valid UTF8String tag but length is 0.
 * @expect Convert successful and output buffer is empty.
 */
/* BEGIN_CASE */
void SDV_BSL_ASN1_TO_UTF8_STRING_INLEN_EMPTY_FUNC_TC001(void)
{
    BSL_ASN1_Buffer in = {0};
    BSL_ASN1_Buffer out = {0};

    in.tag = BSL_ASN1_TAG_UTF8STRING;
    ASSERT_EQ(BSL_ASN1_ToUtf8String(&in, &out), BSL_SUCCESS);

    ASSERT_EQ(out.tag, BSL_ASN1_TAG_UTF8STRING);
    ASSERT_EQ(out.len, 0);
    ASSERT_EQ(out.buff, NULL);

EXIT:
    return;
}
/* END_CASE */

static int32_t ReadHexFileAsBytes(const char *path, BSL_ASN1_Buffer *data)
{
    BSL_ASN1_Buffer temp = {0};
    int32_t ret = BSL_SAL_ReadFile(path, &temp.buff, &temp.len);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    Hex hex = {0};
    if (ConvertHex((const char *)temp.buff, &hex) != 0) {
        BSL_SAL_FREE(temp.buff);
        return BSL_INVALID_ARG;
    }
    BSL_SAL_FREE(temp.buff);

    data->buff = hex.x;
    data->len = hex.len;
    return BSL_SUCCESS;
}

/**
 * @test   SDV_BSL_ASN1_TO_UTF8_STRING_FUNC_TC001
 * @title  Test BSL_ASN1_ToUtf8String with normal ASN.1 input from file.
 * @brief  Input data is read from hex file, converted to UTF8 string.
 * @expect Convert successful and output matches expected UTF8 data.
 */
/* BEGIN_CASE */
void SDV_BSL_ASN1_TO_UTF8_STRING_FUNC_TC001(int tag, char *path, char *expectPath)
{
    BSL_ERR_Init();
    BSL_ASN1_Buffer in = {0};
    BSL_ASN1_Buffer out = {0};
    BSL_ASN1_Buffer expectOut = {0};
    in.tag = (uint8_t)tag;
    ASSERT_EQ(ReadHexFileAsBytes(path, &in), BSL_SUCCESS);
    ASSERT_EQ(ReadHexFileAsBytes(expectPath, &expectOut), BSL_SUCCESS);

    ASSERT_EQ(BSL_ASN1_ToUtf8String(&in, &out), BSL_SUCCESS);

    ASSERT_EQ(out.tag, BSL_ASN1_TAG_UTF8STRING);
    ASSERT_EQ(out.len, expectOut.len);
    ASSERT_TRUE(out.buff != in.buff);
    ASSERT_COMPARE("Convert String", expectOut.buff, expectOut.len, out.buff, out.len);

EXIT:
    BSL_SAL_FREE(in.buff);
    BSL_SAL_FREE(out.buff);
    BSL_SAL_FREE(expectOut.buff);
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASN1_TO_UTF8_STRING_FUNC_TC002
 * @title  Test BSL_ASN1_ToUtf8String with PrintableString and IA5String extended characters.
 * @brief  Input data uses PrintableString and IA5String encoding types and contains
 *         single-byte Unicode characters that are outside the valid character set
 *         defined for these types.
 * @expect Convert successful and extended characters are preserved in UTF8 output.
 */
/* BEGIN_CASE */
void SDV_BSL_ASN1_TO_UTF8_STRING_FUNC_TC002(int tag, Hex *data, Hex *expectData)
{
    BSL_ASN1_Buffer in = {0};
    BSL_ASN1_Buffer out = {0};

    in.tag = (uint8_t)tag;
    in.len  = data->len;
    in.buff = data->x;

    ASSERT_EQ(BSL_ASN1_ToUtf8String(&in, &out), BSL_SUCCESS);
    ASSERT_EQ(out.tag, BSL_ASN1_TAG_UTF8STRING);
    ASSERT_EQ(out.len, expectData->len);
    ASSERT_TRUE(out.buff != in.buff);
    ASSERT_COMPARE("Convert String", expectData->x, expectData->len, out.buff, out.len);

EXIT:
    BSL_SAL_FREE(out.buff);
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASN1_TO_UTF8_STRING_ERR_API_TC001
 * @title  Test BSL_ASN1_ToUtf8String with invalid input parameters.
 * @brief  Input parameters are abnormal.
 * @expect Return corresponding error code.
 */
/* BEGIN_CASE */
void SDV_BSL_ASN1_TO_UTF8_STRING_ERR_API_TC001(int tag, Hex *data, int expect)
{
    BSL_ASN1_Buffer in = {0};
    BSL_ASN1_Buffer out = {0};

    in.tag = (uint8_t)tag;
    in.len  = data->len;
    in.buff = data->x;

    ASSERT_EQ(BSL_ASN1_ToUtf8String(&in, &out), expect);
EXIT:
    return;
}
/* END_CASE */