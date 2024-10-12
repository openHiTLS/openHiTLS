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

#include "bsl_sal.h"
#include "securec.h"
#include "stub_replace.h"
#include "hitls_x509.h"
#include "hitls_x509_errno.h"
#include "bsl_type.h"
#include "bsl_log.h"
#include "hitls_cert_local.h"
#include "bsl_init.h"
#include "bsl_obj_internal.h"
#include "sal_time.h"
#include "sal_file.h"
#include "crypt_encode.h"
#include "crypt_eal_encode.h"
#include "hitls_x509_local.h"

/* END_HEADER */

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
void SDV_X509_CERT_PARSE_FUNC_TC001(int format, char *path)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_X509_CertParseFile(format, path, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

static int32_t HITLS_ParseCertTest(char *path, int32_t fromat, HITLS_X509_Cert **cert)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    int32_t ret = BSL_LOG_RegBinLogFunc(&func);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    return HITLS_X509_CertParseFile(fromat, path, cert);
}

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_VERSION_FUNC_TC001(char *path, int version)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->tbs.version, version);
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SERIALNUM_FUNC_TC001(char *path, Hex *serialNum)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->tbs.serialNum.tag, 2);
    ASSERT_COMPARE("serialNum", cert->tbs.serialNum.buff, cert->tbs.serialNum.len,
        serialNum->x, serialNum->len);
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_TBS_SIGNALG_FUNC_TC001(char *path, int signAlg,
    int rsaPssHash, int rsaPssMgf1, int rsaPssSaltLen)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(cert->tbs.signAlgId.algId, signAlg);
    ASSERT_EQ(cert->tbs.signAlgId.rsaPssParam.mdId, rsaPssHash);
    ASSERT_EQ(cert->tbs.signAlgId.rsaPssParam.mgfId, rsaPssMgf1);
    ASSERT_EQ(cert->tbs.signAlgId.rsaPssParam.saltLen, rsaPssSaltLen);

exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_ISSUERNAME_FUNC_TC001(char *path, int count,
    Hex *type1, int tag1, Hex *value1,
    Hex *type2, int tag2, Hex *value2,
    Hex *type3, int tag3, Hex *value3,
    Hex *type4, int tag4, Hex *value4,
    Hex *type5, int tag5, Hex *value5,
    Hex *type6, int tag6, Hex *value6)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x},
        {6, type2->len, type2->x}, {(uint8_t)tag2, value2->len, value2->x},
        {6, type3->len, type3->x}, {(uint8_t)tag3, value3->len, value3->x},
        {6, type4->len, type4->x}, {(uint8_t)tag4, value4->len, value4->x},
        {6, type5->len, type5->x}, {(uint8_t)tag5, value5->len, value5->x},
        {6, type6->len, type6->x}, {(uint8_t)tag6, value6->len, value6->x},
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.issuerName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.issuerName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
    }
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_ISSUERNAME_FUNC_TC002(char *path, int count,
    Hex *type1, int tag1, Hex *value1)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x}
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.issuerName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.issuerName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
    }
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_ISSUERNAME_FUNC_TC003(char *path, int count,
    Hex *type1, int tag1, Hex *value1,
    Hex *type2, int tag2, Hex *value2,
    Hex *type3, int tag3, Hex *value3,
    Hex *type4, int tag4, Hex *value4,
    Hex *type5, int tag5, Hex *value5)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x},
        {6, type2->len, type2->x}, {(uint8_t)tag2, value2->len, value2->x},
        {6, type3->len, type3->x}, {(uint8_t)tag3, value3->len, value3->x},
        {6, type4->len, type4->x}, {(uint8_t)tag4, value4->len, value4->x},
        {6, type5->len, type5->x}, {(uint8_t)tag5, value5->len, value5->x}
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.issuerName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.issuerName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
    }
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_TIME_FUNC_TC001(char *path)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_ERR_CHECK_TAG);

exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_START_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(cert->tbs.validTime.start.year, year);
    ASSERT_EQ(cert->tbs.validTime.start.month, month);
    ASSERT_EQ(cert->tbs.validTime.start.day, day);
    ASSERT_EQ(cert->tbs.validTime.start.hour, hour);
    ASSERT_EQ(cert->tbs.validTime.start.minute, minute);
    ASSERT_EQ(cert->tbs.validTime.start.second, second);
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_END_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(cert->tbs.validTime.end.year, year);
    ASSERT_EQ(cert->tbs.validTime.end.month, month);
    ASSERT_EQ(cert->tbs.validTime.end.day, day);
    ASSERT_EQ(cert->tbs.validTime.end.hour, hour);
    ASSERT_EQ(cert->tbs.validTime.end.minute, minute);
    ASSERT_EQ(cert->tbs.validTime.end.second, second);
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SUBJECTNAME_FUNC_TC001(char *path, int count,
    Hex *type1, int tag1, Hex *value1,
    Hex *type2, int tag2, Hex *value2,
    Hex *type3, int tag3, Hex *value3,
    Hex *type4, int tag4, Hex *value4,
    Hex *type5, int tag5, Hex *value5,
    Hex *type6, int tag6, Hex *value6)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x},
        {6, type2->len, type2->x}, {(uint8_t)tag2, value2->len, value2->x},
        {6, type3->len, type3->x}, {(uint8_t)tag3, value3->len, value3->x},
        {6, type4->len, type4->x}, {(uint8_t)tag4, value4->len, value4->x},
        {6, type5->len, type5->x}, {(uint8_t)tag5, value5->len, value5->x},
        {6, type6->len, type6->x}, {(uint8_t)tag6, value6->len, value6->x},
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.subjectName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.subjectName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
    }
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SUBJECTNAME_FUNC_TC002(char *path, int count,
    Hex *type1, int tag1, Hex *value1)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x}
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.subjectName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.subjectName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
    }
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SUBJECTNAME_FUNC_TC003(char *path, int count,
    Hex *type1, int tag1, Hex *value1,
    Hex *type2, int tag2, Hex *value2,
    Hex *type3, int tag3, Hex *value3,
    Hex *type4, int tag4, Hex *value4,
    Hex *type5, int tag5, Hex *value5)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x},
        {6, type2->len, type2->x}, {(uint8_t)tag2, value2->len, value2->x},
        {6, type3->len, type3->x}, {(uint8_t)tag3, value3->len, value3->x},
        {6, type4->len, type4->x}, {(uint8_t)tag4, value4->len, value4->x},
        {6, type5->len, type5->x}, {(uint8_t)tag5, value5->len, value5->x}
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.subjectName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.subjectName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
    }
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_CTRL_FUNC_TC001(char *path, int expRawDataLen, int expSignAlg,
    int expKuDigitailSign, int expKuCertSign, int expKuKeyAgreement)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    int32_t rawDataLen;
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODELEN, &rawDataLen, sizeof(rawDataLen));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(rawDataLen, expRawDataLen);

    uint8_t *rawData = NULL;
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODE, &rawData, 0);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(rawData, NULL);

    void *ealKey = NULL;
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &ealKey, 0);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(ealKey, NULL);
    CRYPT_EAL_PkeyFreeCtx(ealKey);

    int32_t alg = 0;
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SIGNALG, &alg, sizeof(alg));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(alg, expSignAlg);

    int32_t ref = 0;
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(ref));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(ref, 2);
    HITLS_X509_CertFree(cert);

    bool isTrue = false;
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_KU_DIGITALSIGN, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuDigitailSign);

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_KU_CERTSIGN, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuCertSign);

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_KU_KEYAGREEMENT, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuKeyAgreement);

exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_CTRL_FUNC_TC002(char *path, char *expectedSerialNum, char *expectedSubjectName,
    char *expectedIssueName, char *expectedBeforeTime, char *expectedAfterTime)
{
    HITLS_X509_Cert *cert = NULL;
    BSL_Buffer subjectName = { NULL, 0 };
    BSL_Buffer issuerName = { NULL, 0 };
    BSL_Buffer serialNum = { NULL, 0 };
    BSL_Buffer beforeTime = { NULL, 0 };
    BSL_Buffer afterTime = { NULL, 0 };

    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_DNNAME_STR, &subjectName, sizeof(BSL_Buffer));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(subjectName.data, NULL);
    ASSERT_EQ(subjectName.dataLen, strlen(expectedSubjectName));
    ASSERT_EQ(strcmp((char *)subjectName.data, expectedSubjectName), 0);

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DNNAME_STR, &issuerName, sizeof(BSL_Buffer));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(issuerName.data, NULL);
    ASSERT_EQ(issuerName.dataLen, strlen(expectedIssueName));
    ASSERT_EQ(strcmp((char *)issuerName.data, expectedIssueName), 0);

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &serialNum, sizeof(BSL_Buffer));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(serialNum.data, NULL);
    ASSERT_EQ(serialNum.dataLen, strlen(expectedSerialNum));
    ASSERT_EQ(strcmp((char *)serialNum.data, expectedSerialNum), 0);

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_BEFORE_TIME, &beforeTime, sizeof(BSL_Buffer));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(beforeTime.data, NULL);
    ASSERT_EQ(beforeTime.dataLen, strlen(expectedBeforeTime));
    ASSERT_EQ(strcmp((char *)beforeTime.data, expectedBeforeTime), 0);

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_AFTER_TIME, &afterTime, sizeof(BSL_Buffer));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(afterTime.data, NULL);
    ASSERT_EQ (afterTime.dataLen, strlen(expectedAfterTime));
    ASSERT_EQ(strcmp((char *)afterTime.data, expectedAfterTime), 0);
exit:
    HITLS_X509_CertFree(cert);
    BSL_SAL_FREE(subjectName.data);
    BSL_SAL_FREE(issuerName.data);
    BSL_SAL_FREE(serialNum.data);
    BSL_SAL_FREE(beforeTime.data);
    BSL_SAL_FREE(afterTime.data);
    BSL_GLOBAL_DeInit();
    return;
}

/* END_CASE */
// subkey
/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_PUBKEY_FUNC_TC001(char *path, char *path2)
{
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *cert2 = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ret = HITLS_ParseCertTest(path2, BSL_FORMAT_ASN1, &cert2);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ret = HITLS_X509_CheckSignature(cert2->tbs.ealPubKey, cert->tbs.tbsRawData, cert->tbs.tbsRawDataLen,
        &cert->signAlgId, &cert->signature);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
exit:
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(cert2);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_DUP_FUNC_TC001(char *path, int expSignAlg,
    int expKuDigitailSign, int expKuCertSign, int expKuKeyAgreement)
{
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *dest = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ret = HITLS_X509_CertDup(cert, &dest);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    int32_t alg = 0;
    ret = HITLS_X509_CertCtrl(dest, HITLS_X509_GET_SIGNALG, &alg, sizeof(alg));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(alg, expSignAlg);

    bool isTrue = false;
    ret = HITLS_X509_CertCtrl(dest, HITLS_X509_EXT_KU_DIGITALSIGN, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuDigitailSign);

    ret = HITLS_X509_CertCtrl(dest, HITLS_X509_EXT_KU_CERTSIGN, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuCertSign);

    ret = HITLS_X509_CertCtrl(dest, HITLS_X509_EXT_KU_KEYAGREEMENT, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuKeyAgreement);

exit:
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(dest);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_EXT_ERROR_TC001(char *path, int ret)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert), ret);

exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_EXTENSIONS_FUNC_TC001(char *path, int extNum, int isCA, int maxPathLen, int keyUsage,
    int cid1, Hex *oid1, int cr1, Hex *val1,
    int cid2, Hex *oid2, int cr2, Hex *val2,
    int cid3, Hex *oid3, int cr3, Hex *val3)
{
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_ExtEntry **node = NULL;
    ASSERT_EQ(HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert), HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->tbs.ext.isCa, isCA);
    ASSERT_EQ(cert->tbs.ext.maxPathLen, maxPathLen);
    ASSERT_EQ(cert->tbs.ext.keyUsage, keyUsage);
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.ext.list), extNum);

    HITLS_X509_ExtEntry arr[] = {
        {cid1, {BSL_ASN1_TAG_OBJECT_ID, oid1->len, oid1->x}, cr1, {BSL_ASN1_TAG_OCTETSTRING, val1->len, val1->x}},
        {cid2, {BSL_ASN1_TAG_OBJECT_ID, oid2->len, oid2->x}, cr2, {BSL_ASN1_TAG_OCTETSTRING, val2->len, val2->x}},
        {cid3, {BSL_ASN1_TAG_OBJECT_ID, oid3->len, oid3->x}, cr3, {BSL_ASN1_TAG_OCTETSTRING, val3->len, val3->x}},
    };
    node = BSL_LIST_First(cert->tbs.ext.list);
    for (int i = 0; i < 3; i++) { // Check the first 3 extensions
        ASSERT_NE((*node), NULL);
        ASSERT_EQ((*node)->critical, arr[i].critical);
        ASSERT_EQ((*node)->extnId.tag, arr[i].extnId.tag);
        ASSERT_COMPARE("oid", (*node)->extnId.buff, (*node)->extnId.len, arr[i].extnId.buff, arr[i].extnId.len);
        ASSERT_EQ((*node)->extnValue.tag, arr[i].extnValue.tag);
        ASSERT_COMPARE(
            "value", (*node)->extnValue.buff, (*node)->extnValue.len, arr[i].extnValue.buff, arr[i].extnValue.len);
        node = BSL_LIST_Next(cert->tbs.ext.list);
    }
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

// sign alg
/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SIGNALG_FUNC_TC001(char *path, int signAlg,
    int rsaPssHash, int rsaPssMgf1, int rsaPssSaltLen)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(cert->signAlgId.algId, signAlg);
    ASSERT_EQ(cert->signAlgId.rsaPssParam.mdId, rsaPssHash);
    ASSERT_EQ(cert->signAlgId.rsaPssParam.mgfId, rsaPssMgf1);
    ASSERT_EQ(cert->signAlgId.rsaPssParam.saltLen, rsaPssSaltLen);

exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

// signature
/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SIGNATURE_FUNC_TC001(char *path, Hex *buff, int unusedBits)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->signature.len, buff->len);
    ASSERT_COMPARE("signature", cert->signature.buff, cert->signature.len, buff->x, buff->len);
    ASSERT_EQ(cert->signature.unusedBits, unusedBits);
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_MUL_CERT_PARSE_FUNC_TC001(int format, char *path, int certNum)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_List *list = NULL;
    int32_t ret = HITLS_X509_CertMulParseFile(format, path, &list);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(list), certNum);
exit:
    BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_VERIOSN_FUNC_TC001(void)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(cert->tbs.version, HITLS_CERT_VERSION_1);

    int32_t version = HITLS_CERT_VERSION_2;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(int32_t)), HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->tbs.version, version);

    version = HITLS_CERT_VERSION_3;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(int32_t)), HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->tbs.version, version);

    // valLen
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, 1), HITLS_X509_ERR_INVALID_PARAM);

    // val
    version = HITLS_CERT_VERSION_3 + 1;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(int32_t)),
              HITLS_X509_ERR_INVALID_PARAM);

exit:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_SERIAL_FUNC_TC001(Hex *serial)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    uint8_t *val = serial->x;
    uint32_t valLen = serial->len;

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(cert->tbs.serialNum.len, 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, val, 0), HITLS_X509_ERR_CERT_INVALID_SERIAL_NUM);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, val, valLen), HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->tbs.serialNum.len, valLen);
    ASSERT_COMPARE("serial", cert->tbs.serialNum.buff, valLen, val, valLen);

exit:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_TIME_FUNC_TC001(void)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    BSL_TIME time = {2024, 8, 22, 1, 1, 0, 1, 0};

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(cert->tbs.validTime.flag, 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &time, 0), HITLS_X509_ERR_INVALID_PARAM);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &time, sizeof(BSL_TIME)), HITLS_X509_SUCCESS);
    ASSERT_TRUE((cert->tbs.validTime.flag & BSL_TIME_BEFORE_SET) != 0);
    ASSERT_EQ(BSL_SAL_DateTimeCompare(&cert->tbs.validTime.start, &time, NULL), BSL_TIME_CMP_EQUAL);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &time, sizeof(BSL_TIME)), HITLS_X509_SUCCESS);
    ASSERT_TRUE((cert->tbs.validTime.flag & BSL_TIME_AFTER_SET) != 0);
    ASSERT_EQ(BSL_SAL_DateTimeCompare(&cert->tbs.validTime.end, &time, NULL), BSL_TIME_CMP_EQUAL);

exit:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_SING_MD_FUNC_TC001(void)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    int32_t mdId = CRYPT_MD_SHA3_384;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_MD_ID, &mdId, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_MD_ID, &mdId, sizeof(int32_t)),
              HITLS_X509_ERR_INVALID_PARAM);

    mdId = CRYPT_MD_MD5;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_MD_ID, &mdId, sizeof(int32_t)), HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->signMdId, mdId);

exit:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_DNNAME_FUNC_TC001(int unknownCid, int cid, Hex *oid, Hex *value)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_TRUE(cert->tbs.issuerName != NULL);
    ASSERT_TRUE(cert->tbs.subjectName != NULL);

    BslList *list = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DNNAME, &list, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DNNAME, &list, sizeof(BslList **)), 0);
    ASSERT_TRUE(list != NULL);
    ASSERT_TRUE(list == cert->tbs.issuerName);

    HITLS_X509_DN unknownName[1] = {{unknownCid, value->x, value->len}};
    HITLS_X509_DN dnName[1] = {{cid, value->x, value->len}};
    HITLS_X509_DN dnNullName[1] = {{cid, NULL, value->len}};
    HITLS_X509_DN dnZeroLenName[1] = {{cid, value->x, 0}};
    ASSERT_EQ(HITLS_X509_AddDnName(list, unknownName, 1), HITLS_X509_ERR_SET_DNNAME_UNKKOWN);

    ASSERT_EQ(HITLS_X509_AddDnName(list, dnName, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_AddDnName(list, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_AddDnName(list, dnNullName, 1), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_AddDnName(list, dnZeroLenName, 1), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_AddDnName(list, dnName, 1), HITLS_X509_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(list), 2); // layer 1 and layer 2

    HITLS_X509_NameNode **node = BSL_LIST_First(list);
    ASSERT_EQ((*node)->layer, 1); // layer 1
    ASSERT_EQ((*node)->nameType.tag, 0);
    ASSERT_EQ((*node)->nameType.buff, NULL);
    ASSERT_EQ((*node)->nameType.len, 0);
    ASSERT_EQ((*node)->nameValue.tag, 0);
    ASSERT_EQ((*node)->nameValue.buff, NULL);
    ASSERT_EQ((*node)->nameValue.len, 0);
    node = BSL_LIST_Next(list);
    ASSERT_EQ((*node)->layer, 2); // layer 2
    ASSERT_EQ((*node)->nameType.tag, BSL_ASN1_TAG_OBJECT_ID);
    ASSERT_COMPARE("nameOid", (*node)->nameType.buff, (*node)->nameType.len, oid->x, oid->len);
    ASSERT_EQ((*node)->nameValue.tag, BSL_ASN1_TAG_UTF8STRING);
    ASSERT_COMPARE("nameValue", (*node)->nameValue.buff, (*node)->nameValue.len, value->x, value->len);

    /* subject name can add repeat name */
    ASSERT_EQ(HITLS_X509_AddDnName(cert->tbs.issuerName, dnName, 1), HITLS_X509_SUCCESS);

    list->count = 100; // 100: the max number of name type.
    ASSERT_EQ(HITLS_X509_AddDnName(cert->tbs.issuerName, dnName, 1), HITLS_X509_ERR_SET_DNNAME_TOOMUCH);

exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

int32_t TestListAddFail(BslList *pList, void *pData, BslListPosition enPosition)
{
    (void)pList;
    (void)pData;
    (void)enPosition;
    return 1;
}

/* BEGIN_CASE */
void SDV_X509_CERT_SET_DNNAME_ERROR_TC001(int cid, Hex *value)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    BslList *list = NULL;
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DNNAME, &list, sizeof(BslList **)), 0);
    ASSERT_TRUE(list != NULL);

    FuncStubInfo tmpRpInfo;
    STUB_Init();
    STUB_Replace(&tmpRpInfo, BSL_LIST_AddElement, TestListAddFail);

    HITLS_X509_DN dnName[1] = {{cid, value->x, value->len}};
    ASSERT_NE(HITLS_X509_AddDnName(list, dnName, 1), HITLS_X509_SUCCESS);

exit:
    STUB_Reset(&tmpRpInfo);
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_RSAPARAM_FUNC_TC001(char *privPath, int keyType)
{
    TestMemInit();
    BSL_GLOBAL_Init();

    int32_t pad = CRYPT_PKEY_EMSA_PKCSV15;
    CRYPT_RSA_PssPara para = {20, CRYPT_MD_SHA256, CRYPT_MD_SHA256}; // 20: saltlen
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(CRYPT_EAL_PriKeyParseFile(BSL_FORMAT_ASN1, keyType, privPath, NULL, 0, &ctx), 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_RSA_PADDING, &pad, sizeof(int32_t)),
              HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_RSA_PSS_PARAM, &para, sizeof(int32_t)),
              HITLS_X509_ERR_INVALID_PARAM);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PRIVKEY, ctx, sizeof(void *)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_RSA_PADDING, &pad, sizeof(int32_t)), 0);

    pad = CRYPT_PKEY_EMSA_PSS;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_RSA_PADDING, &pad, sizeof(int32_t)),
              HITLS_X509_ERR_SET_RSA_PAD_DIFF);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_RSA_PSS_PARAM, &para, sizeof(int32_t)),
              HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_RSA_PSS_PARAM, &para, sizeof(CRYPT_RSA_PssPara)),
              HITLS_X509_ERR_SET_RSAPSS_PARA);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PRIVKEY, ctx, sizeof(void *)), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(int32_t)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_RSA_PADDING, &pad, sizeof(int32_t)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_RSA_PSS_PARAM, &para, sizeof(CRYPT_RSA_PssPara)), 0);
    para.mdId = CRYPT_MD_SHA224;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_RSA_PSS_PARAM, &para, sizeof(CRYPT_RSA_PssPara)),
              HITLS_X509_ERR_MD_NOT_MATCH);
    para.mdId = CRYPT_MD_SHA256;
    para.mgfId = CRYPT_MD_SHA224;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SIGN_RSA_PSS_PARAM, &para, sizeof(CRYPT_RSA_PssPara)),
              HITLS_X509_ERR_MGF_NOT_MATCH);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_ENCODE_CERT_EXT_TC001(char *path, Hex *expectExt)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = NULL;
    BSL_ASN1_Buffer ext = {0};

    ASSERT_EQ(HITLS_ParseCertTest(path, BSL_FORMAT_ASN1, &cert), HITLS_X509_SUCCESS);
    uint8_t tag = 0xA3;
    ASSERT_EQ(HITLS_X509_EncodeExt(tag, cert->tbs.ext.list, &ext), HITLS_X509_SUCCESS);

    ASSERT_EQ(ext.len, expectExt->len);
    if (expectExt->len != 0) {
        ASSERT_EQ(ext.tag, tag);
        ASSERT_COMPARE("extensions", ext.buff, ext.len, expectExt->x, expectExt->len);
    }

exit:
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(ext.buff);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_GEN_BUFF_API_TC001(void)
{
    TestMemInit();
    BSL_GLOBAL_Init();

    BSL_Buffer buff = {0};
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_UNKNOWN, cert, &buff), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, NULL, &buff), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, NULL), HITLS_X509_ERR_INVALID_PARAM);

    cert->tbs.version = HITLS_CERT_VERSION_1;
    cert->tbs.ext.list->count = 1;
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &buff), HITLS_X509_ERR_CERT_INACCRACY_VERSION);

exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_GEN_FILE_API_TC001(char *destPath)
{
    TestMemInit();
    BSL_GLOBAL_Init();

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_TRUE(cert != NULL);

    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_UNKNOWN, cert, destPath), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, NULL, destPath), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, NULL), HITLS_X509_ERR_INVALID_PARAM);

exit:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_FORMAT_CONVERT_FUNC_TC001(char *inCert, int inForm, char *outCert, int outForm)
{
    TestRandInit();
    HITLS_X509_Cert *cert = NULL;
    BSL_Buffer encodeCert = {0};
    BSL_Buffer expectCert = {0};

    ASSERT_EQ(HITLS_X509_CertParseFile(inForm, inCert, &cert), 0);
    ASSERT_EQ(BSL_SAL_ReadFile(outCert, &expectCert.data, &expectCert.dataLen), 0);
    ASSERT_EQ(HITLS_X509_CertGenBuff(outForm, cert, &encodeCert), 0);

    ASSERT_COMPARE("Format convert", expectCert.data, expectCert.dataLen, encodeCert.data, encodeCert.dataLen);

exit:
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(expectCert.data);
    BSL_SAL_Free(encodeCert.data);
}
/* END_CASE */

static int32_t SetCert(HITLS_X509_Cert *raw, HITLS_X509_Cert *new, CRYPT_EAL_PkeyCtx *priv, int32_t mdId)
{
    int32_t ret = 1;
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_VERSION, &raw->tbs.version, sizeof(int32_t)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_SERIALNUM, raw->tbs.serialNum.buff, raw->tbs.serialNum.len), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_BEFORE_TIME, &raw->tbs.validTime.start, sizeof(BSL_TIME)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_AFTER_TIME, &raw->tbs.validTime.end, sizeof(BSL_TIME)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_PUBKEY, raw->tbs.ealPubKey, sizeof(void *)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_PRIVKEY, priv, sizeof(void *)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_SIGN_MD_ID, &mdId, sizeof(int32_t)), 0);

    BslList *rawSubject = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(raw, HITLS_X509_GET_SUBJECT_DNNAME, &rawSubject, sizeof(BslList *)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_SUBJECT_DNNAME, rawSubject, sizeof(BslList)), 0);

    BslList *rawIssuer = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(raw, HITLS_X509_GET_ISSUER_DNNAME, &rawIssuer, sizeof(BslList *)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_ISSUER_DNNAME, rawIssuer, sizeof(BslList)), 0);

    ret = 0;
exit:
    return ret;
}

/* BEGIN_CASE */
void SDV_X509_CERT_SETANDGEN_TC001(char *derCertPath, char *privPath, int keyType, int pkeyId, int pad, int mdId,
    int mgfId, int saltLen)
{
    HITLS_X509_Cert *raw = NULL;
    HITLS_X509_Cert *new = NULL;
    HITLS_X509_Cert *parse = NULL;
    CRYPT_EAL_PkeyCtx *privKey = NULL;
    BSL_Buffer encodeRaw = {0};
    BSL_Buffer encodeNew = {0};
    BslList *tmp = NULL;

    TestRandInit();
    ASSERT_EQ(CRYPT_EAL_PriKeyParseFile(BSL_FORMAT_ASN1, keyType, privPath, NULL, 0, &privKey), 0);
    ASSERT_EQ(BSL_SAL_ReadFile(derCertPath, &encodeRaw.data, &encodeRaw.dataLen), 0);
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &encodeRaw, &raw), 0);

    // new cert
    new = HITLS_X509_CertNew();
    ASSERT_TRUE(new != NULL);
    ASSERT_EQ(SetCert(raw, new, privKey, mdId), 0);
    tmp = new->tbs.ext.list;
    new->tbs.ext.list = raw->tbs.ext.list;
    if (pkeyId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_SIGN_RSA_PADDING, &pad, sizeof(int32_t)), 0);
        if (pad == CRYPT_PKEY_EMSA_PSS) {
            CRYPT_RSA_PssPara para = {saltLen, mdId, mgfId};
            ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_SIGN_RSA_PSS_PARAM, &para, sizeof(CRYPT_RSA_PssPara)), 0);
        }
    }
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, new, &encodeNew), 0);
    if (pad != CRYPT_PKEY_EMSA_PSS) {
        ASSERT_EQ(encodeRaw.dataLen, encodeNew.dataLen);
    }
    if (pkeyId == CRYPT_PKEY_RSA && pad == CRYPT_PKEY_EMSA_PKCSV15) {
        ASSERT_COMPARE("Gen cert", encodeNew.data, encodeNew.dataLen, encodeRaw.data, encodeRaw.dataLen);
    }

exit:
    HITLS_X509_CertFree(raw);
    BSL_SAL_Free(encodeRaw.data);
    if (tmp != NULL) {
        new->tbs.ext.list = tmp;
    }
    HITLS_X509_CertFree(new);
    HITLS_X509_CertFree(parse);
    CRYPT_EAL_PkeyFreeCtx(privKey);
    BSL_SAL_Free(encodeNew.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_GEN_CERT_ERROR_TC001(char *derCertPath, char *privPath, int keyType, int mdId, int ret)
{
    HITLS_X509_Cert *raw = NULL;
    HITLS_X509_Cert *new = NULL;
    CRYPT_EAL_PkeyCtx *privKey = NULL;
    BSL_Buffer encodeCert = {0};
    BslList *tmp = NULL;

    ASSERT_EQ(CRYPT_EAL_PriKeyParseFile(BSL_FORMAT_ASN1, keyType, privPath, NULL, 0, &privKey), 0);
    ASSERT_EQ(HITLS_ParseCertTest(derCertPath, BSL_FORMAT_ASN1, &raw), HITLS_X509_SUCCESS);

    new = HITLS_X509_CertNew();
    ASSERT_TRUE(new != NULL);
    ASSERT_EQ(SetCert(raw, new, privKey, mdId), 0);
    tmp = new->tbs.ext.list;
    new->tbs.ext.list = raw->tbs.ext.list;

    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, new, &encodeCert), ret);

exit:
    raw->flag = HITLS_X509_CERT_PARSE_FLAG;
    HITLS_X509_CertFree(raw);
    if (tmp != NULL) {
        new->tbs.ext.list = tmp;
    }
    HITLS_X509_CertFree(new);
    CRYPT_EAL_PkeyFreeCtx(privKey);
    BSL_SAL_Free(encodeCert.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_GEN_CERT_ERROR_TC002(char *derCertPath, char *privPath, int keyType, int mdId, char *destPath)
{
    HITLS_X509_Cert *raw = NULL;
    HITLS_X509_Cert *new = NULL;
    CRYPT_EAL_PkeyCtx *privKey = NULL;
    BSL_Buffer encodeRaw = {0};
    BslList *tmp = NULL;
    uint8_t *tmpBuff = NULL;

    ASSERT_EQ(CRYPT_EAL_PriKeyParseFile(BSL_FORMAT_ASN1, keyType, privPath, NULL, 0, &privKey), 0);
    ASSERT_EQ(BSL_SAL_ReadFile(derCertPath, &encodeRaw.data, &encodeRaw.dataLen), 0);
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &encodeRaw, &raw), 0);

    new = HITLS_X509_CertNew();
    ASSERT_TRUE(new != NULL);
    ASSERT_EQ(SetCert(raw, new, privKey, mdId), 0);
    tmp = new->tbs.ext.list;
    new->tbs.ext.list = raw->tbs.ext.list;

    tmpBuff = new->tbs.serialNum.buff;
    new->tbs.serialNum.buff = NULL;
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, new, destPath), HITLS_X509_ERR_CERT_INVALID_SERIAL_NUM);
    new->tbs.serialNum.buff = tmpBuff;
    new->tbs.validTime.flag = 0;
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, new, destPath), HITLS_X509_ERR_CERT_INVALID_TIME);
    new->tbs.validTime.flag = BSL_TIME_BEFORE_SET | BSL_TIME_AFTER_SET;

    BSL_TIME time = {2050, 1, 1, 1, 1, 0, 1, 0};
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_BEFORE_TIME, &time, sizeof(BSL_TIME)), 0);
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, new, destPath), HITLS_X509_ERR_CERT_START_TIME_LATER);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_BEFORE_TIME, &raw->tbs.validTime.start, sizeof(BSL_TIME)),
              0);

    new->signMdId = 0;
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, new, destPath), HITLS_X509_ERR_CERT_INVALID_SIGN_MD);

exit:
    HITLS_X509_CertFree(raw);
    BSL_SAL_Free(encodeRaw.data);
    if (tmp != NULL) {
        new->tbs.ext.list = tmp;
    }
    HITLS_X509_CertFree(new);
    CRYPT_EAL_PkeyFreeCtx(privKey);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_GEN_CERT_ERROR_TC003(char *derCertPath)
{
    HITLS_X509_Cert *parse = NULL;
    HITLS_X509_Cert *new = NULL;
    int32_t ver = 0;
    HITLS_X509_Ext *ext = NULL;

    // Test: Set after parse
    ASSERT_EQ(HITLS_ParseCertTest(derCertPath, BSL_FORMAT_ASN1, &parse), HITLS_X509_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertCtrl(parse, HITLS_X509_SET_VERSION, &ver, sizeof(int32_t)),
        HITLS_X509_ERR_SET_AFTER_PARSE);

    ASSERT_EQ(HITLS_X509_CertCtrl(parse, HITLS_X509_GET_EXT, &ext, sizeof(HITLS_X509_Ext *)), 0);
    HITLS_X509_ExtBCons bCons = {true, true, 1};
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_BCONS, &bCons, sizeof(HITLS_X509_ExtBCons)),
        HITLS_X509_ERR_EXT_SET_AFTER_PARSE);

    // Test: Parse after set
    new = HITLS_X509_CertNew();
    ASSERT_NE(new, NULL);
    ASSERT_EQ(HITLS_ParseCertTest(derCertPath, BSL_FORMAT_ASN1, &parse), HITLS_X509_ERR_INVALID_PARAM);
exit:
    HITLS_X509_CertFree(parse);
    HITLS_X509_CertFree(new);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_DIGEST_FUNC_TC001(char *inCert, int inForm, int mdId, Hex *expect)
{
    TestRandInit();
    BSL_Buffer encodeRaw = {0};
    BSL_Buffer encodeNew = {0};
    HITLS_X509_Cert *cert = NULL;
    uint8_t md[64] = {0}; // 64 : max md len
    uint32_t mdLen = 64;  // 64 : max md len

    ASSERT_EQ(BSL_SAL_ReadFile(inCert, &encodeRaw.data, &encodeRaw.dataLen), 0);
    ASSERT_EQ(HITLS_X509_CertParseBuff(inForm, &encodeRaw, &cert), 0);

    ASSERT_EQ(HITLS_X509_CertDigest(cert, mdId, md, &mdLen), 0);
    ASSERT_COMPARE("cert digest", expect->x, expect->len, md, mdLen);

    ASSERT_EQ(HITLS_X509_CertGenBuff(inForm, cert, &encodeNew), 0);
    ASSERT_COMPARE("digest then gen", encodeRaw.data, encodeRaw.dataLen, encodeNew.data, encodeNew.dataLen);

exit:
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(encodeRaw.data);
    BSL_SAL_Free(encodeNew.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_CSR_EXT_FUNC_TC001(int inForm, char *inCsr, int ret, Hex *expect)
{
    TestRandInit();

    BSL_ASN1_Buffer encodeExt = {0};
    HITLS_X509_Csr *csr = NULL;
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    ASSERT_EQ(HITLS_X509_CsrParseFile(inForm, inCsr, &csr), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_CSR_EXT, csr, 0), ret);
    ASSERT_EQ(HITLS_X509_EncodeExt(0, cert->tbs.ext.list, &encodeExt), 0);
    if (expect->len != 0) {
        ASSERT_TRUE((cert->tbs.ext.extFlags & HITLS_X509_EXT_FLAG_PARSE) == 0);
        ASSERT_TRUE((cert->tbs.ext.extFlags & HITLS_X509_EXT_FLAG_SET) != 0);
        ASSERT_COMPARE("Csr ext", encodeExt.buff, encodeExt.len, expect->x, expect->len);
    }
exit:
    HITLS_X509_CertFree(cert);
    HITLS_X509_CsrFree(csr);
    BSL_SAL_Free(encodeExt.buff);
}
/* END_CASE */
