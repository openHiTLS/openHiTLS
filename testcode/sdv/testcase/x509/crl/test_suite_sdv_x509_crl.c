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