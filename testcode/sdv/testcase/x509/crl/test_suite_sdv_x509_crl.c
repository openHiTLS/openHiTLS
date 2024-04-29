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
#include "bsl_init.h"
#include "hitls_crl_local.h"


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


static int32_t HITLS_ParseCrlTest(char *path, HITLS_X509_Crl **crl)
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
    
    *crl = HITLS_X509_NewCrl();
    if (*crl == NULL) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    ret = HITLS_X509_ParseFileCrl(BSL_PARSE_FORMAT_ASN1, path, *crl);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    return ret;
}

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FUNC_TC001(char *path)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);
    HITLS_X509_Crl *crl = HITLS_X509_NewCrl();
    ASSERT_TRUE(crl != NULL);
    int32_t ret = HITLS_X509_ParseFileCrl(BSL_PARSE_FORMAT_ASN1, path, crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_CTRL_FUNC_TC001(char *path)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    int32_t ref = 0;
    ret = HITLS_X509_CtrlCrl(crl, HITLS_X509_CRL_REF_UP, &ref, sizeof(ref));
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(ref, 2);
    HITLS_X509_FreeCrl(crl);

exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_VERSION_FUNC_TC001(char *path, int version)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(crl->tbs.version, version);
exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_TBS_SIGNALG_FUNC_TC001(char *path, int signAlg,
    int rsaPssHash, int rsaPssMgf1, int rsaPssSaltLen)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(crl->tbs.signAlgId.algId, signAlg);
    ASSERT_EQ(crl->tbs.signAlgId.rsaPssParam.mdId, rsaPssHash);
    ASSERT_EQ(crl->tbs.signAlgId.rsaPssParam.mgfId, rsaPssMgf1);
    ASSERT_EQ(crl->tbs.signAlgId.rsaPssParam.saltLen, rsaPssSaltLen);

exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_ISSUERNAME_FUNC_TC001(char *path, int count,
    Hex *type1, int tag1, Hex *value1,
    Hex *type2, int tag2, Hex *value2,
    Hex *type3, int tag3, Hex *value3,
    Hex *type4, int tag4, Hex *value4,
    Hex *type5, int tag5, Hex *value5)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x},
        {6, type2->len, type2->x}, {(uint8_t)tag2, value2->len, value2->x},
        {6, type3->len, type3->x}, {(uint8_t)tag3, value3->len, value3->x},
        {6, type4->len, type4->x}, {(uint8_t)tag4, value4->len, value4->x},
        {6, type5->len, type5->x}, {(uint8_t)tag5, value5->len, value5->x},
    };
    ASSERT_EQ(BSL_LIST_COUNT(crl->tbs.issuerName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(crl->tbs.issuerName);
    for (size_t i = 0; i < count; i+=2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(crl->tbs.issuerName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(crl->tbs.issuerName);
    }
exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_REVOKED_FUNC_TC001(char *path)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, BSL_SAL_ERR_FILE_LENGTH);
exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_REVOKED_FUNC_TC003(char *path, int count, int num,
    int tag1, Hex *value1, int year1, int month1, int day1, int hour1, int minute1, int second1)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(crl->tbs.revokedCerts), count);
    HITLS_X509_CrlEntry **nameNode = NULL;
    nameNode = BSL_LIST_First(crl->tbs.revokedCerts);
    for (size_t i = 1; i < num; i++) {
        nameNode = BSL_LIST_Next(crl->tbs.revokedCerts);
    }

    ASSERT_EQ((*nameNode)->serialNumber.tag, tag1);
    ASSERT_COMPARE("", (*nameNode)->serialNumber.buff, (*nameNode)->serialNumber.len,
        value1->x, value1->len);
    ASSERT_EQ((*nameNode)->time.year, year1);
    ASSERT_EQ((*nameNode)->time.month, month1);
    ASSERT_EQ((*nameNode)->time.day, day1);
    ASSERT_EQ((*nameNode)->time.hour, hour1);
    ASSERT_EQ((*nameNode)->time.minute, minute1);
    ASSERT_EQ((*nameNode)->time.second, second1);
exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_START_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(crl->tbs.validTime.start.year, year);
    ASSERT_EQ(crl->tbs.validTime.start.month, month);
    ASSERT_EQ(crl->tbs.validTime.start.day, day);
    ASSERT_EQ(crl->tbs.validTime.start.hour, hour);
    ASSERT_EQ(crl->tbs.validTime.start.minute, minute);
    ASSERT_EQ(crl->tbs.validTime.start.second, second);
exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_END_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(crl->tbs.validTime.end.year, year);
    ASSERT_EQ(crl->tbs.validTime.end.month, month);
    ASSERT_EQ(crl->tbs.validTime.end.day, day);
    ASSERT_EQ(crl->tbs.validTime.end.hour, hour);
    ASSERT_EQ(crl->tbs.validTime.end.minute, minute);
    ASSERT_EQ(crl->tbs.validTime.end.second, second);
exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_EXTENSIONS_FUNC_TC001(char *path,
    int tag1, Hex *value1, int tag2, Hex *value2)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(BSL_LIST_COUNT(crl->tbs.crlExt.extList), 1);
    HITLS_X509_ExtEntry **nameNode = NULL;
    nameNode = BSL_LIST_First(crl->tbs.crlExt.extList);
    ASSERT_NE((*nameNode), NULL);
    ASSERT_EQ((*nameNode)->critical, 0);
    ASSERT_EQ((*nameNode)->extnId.tag, tag1);
    ASSERT_COMPARE("extnId", (*nameNode)->extnId.buff, (*nameNode)->extnId.len, value1->x, value1->len);
    ASSERT_EQ((*nameNode)->extnValue.tag, tag2);
    ASSERT_COMPARE("extnValue", (*nameNode)->extnValue.buff, (*nameNode)->extnValue.len, value2->x, value2->len);
exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_SIGNALG_FUNC_TC001(char *path, int signAlg,
    int rsaPssHash, int rsaPssMgf1, int rsaPssSaltLen)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ASSERT_EQ(crl->signAlgId.algId, signAlg);
    ASSERT_EQ(crl->signAlgId.rsaPssParam.mdId, rsaPssHash);
    ASSERT_EQ(crl->signAlgId.rsaPssParam.mgfId, rsaPssMgf1);
    ASSERT_EQ(crl->signAlgId.rsaPssParam.saltLen, rsaPssSaltLen);

exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_SIGNATURE_FUNC_TC001(char *path, Hex *buff, int unusedBits)
{
    HITLS_X509_Crl *crl = NULL;
    int32_t ret = HITLS_ParseCrlTest(path, &crl);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(crl->signature.len, buff->len);
    ASSERT_COMPARE("signature", crl->signature.buff, crl->signature.len, buff->x, buff->len);
    ASSERT_EQ(crl->signature.unusedBits, unusedBits);
exit:
    HITLS_X509_FreeCrl(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */
