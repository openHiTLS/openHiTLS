/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */

#include "bsl_sal.h"
#include "securec.h"
#include "hitls_x509.h"
#include "hitls_x509_errno.h"
#include "bsl_type.h"
#include "bsl_log.h"
#include "hitls_cert_local.h"
#include "bsl_init.h"

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
    int32_t ret = HITLS_X509_ParseFileCert(format, path, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
exit:
    HITLS_X509_FreeCert(cert);
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

    ret = HITLS_X509_ParseFileCert(fromat, path, cert);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    return ret;
}

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_VERSION_FUNC_TC001(char *path, int version)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->tbs.version, version);
exit:
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SERIALNUM_FUNC_TC001(char *path, Hex *serialNum)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->tbs.serialNum.tag, 2);
    ASSERT_COMPARE("serialNum", cert->tbs.serialNum.buff, cert->tbs.serialNum.len,
        serialNum->x, serialNum->len);
exit:
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_TBS_SIGNALG_FUNC_TC001(char *path, int signAlg,
    int rsaPssHash, int rsaPssMgf1, int rsaPssSaltLen)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(cert->tbs.signAlgId.algId, signAlg);
    ASSERT_EQ(cert->tbs.signAlgId.rsaPssParam.mdId, rsaPssHash);
    ASSERT_EQ(cert->tbs.signAlgId.rsaPssParam.mgfId, rsaPssMgf1);
    ASSERT_EQ(cert->tbs.signAlgId.rsaPssParam.saltLen, rsaPssSaltLen);

exit:
    HITLS_X509_FreeCert(cert);
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
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
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
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_ISSUERNAME_FUNC_TC002(char *path, int count,
    Hex *type1, int tag1, Hex *value1)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
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
    HITLS_X509_FreeCert(cert);
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
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
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
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_TIME_FUNC_TC001(char *path)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_ERR_CHECK_TAG);

exit:
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_START_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(cert->tbs.validTime.start.year, year);
    ASSERT_EQ(cert->tbs.validTime.start.month, month);
    ASSERT_EQ(cert->tbs.validTime.start.day, day);
    ASSERT_EQ(cert->tbs.validTime.start.hour, hour);
    ASSERT_EQ(cert->tbs.validTime.start.minute, minute);
    ASSERT_EQ(cert->tbs.validTime.start.second, second);
exit:
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_END_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(cert->tbs.validTime.end.year, year);
    ASSERT_EQ(cert->tbs.validTime.end.month, month);
    ASSERT_EQ(cert->tbs.validTime.end.day, day);
    ASSERT_EQ(cert->tbs.validTime.end.hour, hour);
    ASSERT_EQ(cert->tbs.validTime.end.minute, minute);
    ASSERT_EQ(cert->tbs.validTime.end.second, second);
exit:
    HITLS_X509_FreeCert(cert);
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
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
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
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SUBJECTNAME_FUNC_TC002(char *path, int count,
    Hex *type1, int tag1, Hex *value1)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
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
    HITLS_X509_FreeCert(cert);
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
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
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
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_CTRL_FUNC_TC001(char *path, int expRawDataLen, int expSignAlg,
    int expKuDigitailSign, int expKuCertSign, int expKuKeyAgreement)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    int32_t rawDataLen;
    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_GET_ENCODELEN, &rawDataLen, sizeof(rawDataLen));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(rawDataLen, expRawDataLen);

    uint8_t *rawData = NULL;
    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_ENCODE, &rawData, 0);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(rawData, NULL);

    void *ealKey = NULL;
    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_GET_PUBKEY, &ealKey, 0);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(ealKey, NULL);
    CRYPT_EAL_PkeyFreeCtx(ealKey);

    int32_t alg = 0;
    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_GET_SIGNALG, &alg, sizeof(alg));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(alg, expSignAlg);

    int32_t ref = 0;
    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_REF_UP, &ref, sizeof(ref));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(ref, 2);
    HITLS_X509_FreeCert(cert);

    bool isTrue = false;
    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_EXT_KU_DIGITALSIGN, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuDigitailSign);

    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_EXT_KU_CERTSIGN, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuCertSign);

    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_EXT_KU_KEYAGREEMENT, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuKeyAgreement);

exit:
    HITLS_X509_FreeCert(cert);
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

    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_GET_SUBJECT_DNNAME, &subjectName, sizeof(BSL_Buffer));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(subjectName.data, NULL);
    ASSERT_EQ(subjectName.dataLen, strlen(expectedSubjectName));
    ASSERT_EQ(strcmp(subjectName.data, expectedSubjectName), 0);

    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_GET_ISSUER_DNNAME, &issuerName, sizeof(BSL_Buffer));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(issuerName.data, NULL);
    ASSERT_EQ(issuerName.dataLen, strlen(expectedIssueName));
    ASSERT_EQ(strcmp(issuerName.data, expectedIssueName), 0);

    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_GET_SERIALNUM, &serialNum, sizeof(BSL_Buffer));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(serialNum.data, NULL);
    ASSERT_EQ(serialNum.dataLen, strlen(expectedSerialNum));
    ASSERT_EQ(strcmp(serialNum.data, expectedSerialNum), 0);

    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_GET_BEFORE_TIME, &beforeTime, sizeof(BSL_Buffer));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(beforeTime.data, NULL);
    ASSERT_EQ(beforeTime.dataLen, strlen(expectedBeforeTime));
    ASSERT_EQ(strcmp(beforeTime.data, expectedBeforeTime), 0);

    ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_GET_AFTER_TIME, &afterTime, sizeof(BSL_Buffer));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(afterTime.data, NULL);
    ASSERT_EQ (afterTime.dataLen, strlen(expectedAfterTime));
    ASSERT_EQ(strcmp(afterTime.data, expectedAfterTime), 0);
exit:
    HITLS_X509_FreeCert(cert);
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
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ret = HITLS_ParseCertTest(path2, BSL_PARSE_FORMAT_ASN1, &cert2);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ret = HITLS_X509_CheckSignature(cert2->tbs.ealPubKey, cert->tbs.tbsRawData, cert->tbs.tbsRawDataLen,
        &cert->signAlgId, &cert->signature);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
exit:
    HITLS_X509_FreeCert(cert);
    HITLS_X509_FreeCert(cert2);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_DUP_FUNC_TC001(char *path, int expSignAlg,
    int expKuDigitailSign, int expKuCertSign, int expKuKeyAgreement)
{
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *dest = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ret = HITLS_X509_DupCert(cert, &dest);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    int32_t alg = 0;
    ret = HITLS_X509_CtrlCert(dest, HITLS_X509_CERT_GET_SIGNALG, &alg, sizeof(alg));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(alg, expSignAlg);

    bool isTrue = false;
    ret = HITLS_X509_CtrlCert(dest, HITLS_X509_CERT_EXT_KU_DIGITALSIGN, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuDigitailSign);

    ret = HITLS_X509_CtrlCert(dest, HITLS_X509_CERT_EXT_KU_CERTSIGN, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuCertSign);

    ret = HITLS_X509_CtrlCert(dest, HITLS_X509_CERT_EXT_KU_KEYAGREEMENT, &isTrue, sizeof(isTrue));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(isTrue, expKuKeyAgreement);
    
exit:
    HITLS_X509_FreeCert(cert);
    HITLS_X509_FreeCert(dest);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

// ext
/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_EXTENSIONS_FUNC_TC001(char *path, int isCA, int maxPathLen, int keyUsage,
    int tag1, Hex *value1, int tag2, Hex *value2,
    int tag3, Hex *value3, int tag4, Hex *value4)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->tbs.ext.isCa, isCA);
    ASSERT_EQ(cert->tbs.ext.maxPathLen, maxPathLen);
    ASSERT_EQ(cert->tbs.ext.keyUsage, keyUsage);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {tag1, value1->len, value1->x}, {tag2, value2->len, value2->x},
        {tag3, value3->len, value3->x}, {tag4, value4->len, value4->x},
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.ext.list), 2);
    HITLS_X509_ExtEntry **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.ext.list);
    for (size_t i = 0; i < sizeof(expAsan1Arr) / sizeof(expAsan1Arr[0]); i+=2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->critical, 0);
        ASSERT_EQ((*nameNode)->extnId.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("ext", (*nameNode)->extnId.buff, (*nameNode)->extnId.len, expAsan1Arr[i].buff, expAsan1Arr[i].len);
        ASSERT_EQ((*nameNode)->extnValue.tag, expAsan1Arr[i+1].tag);
        ASSERT_COMPARE("extnValue", (*nameNode)->extnValue.buff, (*nameNode)->extnValue.len, expAsan1Arr[i+1].buff, expAsan1Arr[i+1].len);
        nameNode = BSL_LIST_Next(cert->tbs.ext.list);
    }
exit:
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

// sign alg
/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SIGNALG_FUNC_TC001(char *path, int signAlg,
    int rsaPssHash, int rsaPssMgf1, int rsaPssSaltLen)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(cert->signAlgId.algId, signAlg);
    ASSERT_EQ(cert->signAlgId.rsaPssParam.mdId, rsaPssHash);
    ASSERT_EQ(cert->signAlgId.rsaPssParam.mgfId, rsaPssMgf1);
    ASSERT_EQ(cert->signAlgId.rsaPssParam.saltLen, rsaPssSaltLen);

exit:
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

// signature
/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SIGNATURE_FUNC_TC001(char *path, Hex *buff, int unusedBits)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_ParseCertTest(path, BSL_PARSE_FORMAT_ASN1, &cert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(cert->signature.len, buff->len);
    ASSERT_COMPARE("signature", cert->signature.buff, cert->signature.len, buff->x, buff->len);
    ASSERT_EQ(cert->signature.unusedBits, unusedBits);
exit:
    HITLS_X509_FreeCert(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_MUL_CERT_PARSE_FUNC_TC001(int format, char *path, int certNum)
{
    HITLS_X509_List *list = NULL;
    int32_t ret = HITLS_X509_ParseFileCertMul(format, path, &list);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(list), certNum);
exit:
    BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
}
/* END_CASE */