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
#include "hitls_error.h"
#include "hitls_x509.h"
#include "hitls_x509_errno.h"
#include "hitls_x509_verify.h"
#include "bsl_type.h"
#include "bsl_log.h"
#include "hitls_cert_local.h"
#include "hitls_crl_local.h"
#include "bsl_init.h"
#include "bsl_obj_internal.h"
#include "crypt_errno.h"
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

static void FreeListData(void *data)
{
    (void)data;
    return;
}

static void FreeSanListData(void *data)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_GeneralName *name = (HITLS_X509_GeneralName *)data;
    if (name->type == HITLS_X509_GN_DNNAME) {
        BSL_LIST_DeleteAll((BslList *)name->value.data, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
        BSL_SAL_Free(name->value.data);
    }
}

/* BEGIN_CASE */
void SDV_HITLS_X509_FreeStoreCtx_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    HITLS_X509_StoreCtxFree(NULL);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_CtrlStoreCtx_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(NULL, 0, NULL, 0), HITLS_INVALID_INPUT);
    HITLS_X509_StoreCtx storeCtx = {0};
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(&storeCtx, 0, NULL, 0), HITLS_INVALID_INPUT);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_VerifyCert_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertVerify(NULL, NULL), HITLS_INVALID_INPUT);
    HITLS_X509_StoreCtx storeCtx = {0};
    ASSERT_EQ(HITLS_X509_CertVerify(&storeCtx, NULL), HITLS_INVALID_INPUT);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_BuildCertChain_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertChainBuild(NULL, NULL, NULL), HITLS_INVALID_INPUT);
    HITLS_X509_StoreCtx storeCtx = {0};
    ASSERT_EQ(HITLS_X509_CertChainBuild(&storeCtx, NULL, NULL), HITLS_INVALID_INPUT);
    HITLS_X509_Cert cert = {0};
    ASSERT_EQ(HITLS_X509_CertChainBuild(&storeCtx, &cert, NULL), HITLS_INVALID_INPUT);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_BuildCertChainWithRoot_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertChainBuildWithRoot(NULL, NULL, NULL), HITLS_INVALID_INPUT);
    HITLS_X509_StoreCtx storeCtx = {0};
    ASSERT_EQ(HITLS_X509_CertChainBuildWithRoot(&storeCtx, NULL, NULL), HITLS_INVALID_INPUT);
    HITLS_X509_Cert cert = {0};
    ASSERT_EQ(HITLS_X509_CertChainBuildWithRoot(&storeCtx, &cert, NULL), HITLS_INVALID_INPUT);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_FreeCert_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    HITLS_X509_CertFree(NULL);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_ParseBuffCert_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    HITLS_X509_Cert *cert = NULL;
    uint8_t buffData[10] = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertParseBuff(0, NULL, NULL), HITLS_X509_ERR_INVALID_PARAM);
    BSL_Buffer buff = {0};
    ASSERT_EQ(HITLS_X509_CertParseBuff(0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    buff.data = buffData;
    ASSERT_EQ(HITLS_X509_CertParseBuff(0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    buff.dataLen = 1;
    ASSERT_EQ(HITLS_X509_CertParseBuff(0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertParseBuff(0xff, &buff, &cert), HITLS_X509_ERR_NOT_SUPPORT_FORMAT);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_ParseFileCert_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, NULL, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/asn1/nist384ca.crt", NULL),
        HITLS_X509_ERR_INVALID_PARAM);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_CtrlCert_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertCtrl(NULL, 0xff, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    HITLS_X509_Cert cert = {0};
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, 0xff, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_ENCODELEN, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_ENCODELEN, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_ENCODE, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_PUBKEY, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_PUBKEY, &cert, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_SIGNALG, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_SIGNALG, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_REF_UP, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_REF_UP, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_EXT_KU_DIGITALSIGN, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_EXT_KU_DIGITALSIGN, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_EXT_KU_CERTSIGN, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_EXT_KU_CERTSIGN, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_EXT_KU_KEYAGREEMENT, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_EXT_KU_KEYAGREEMENT, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_SUBJECT_DNNAME_STR, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_ISSUER_DNNAME_STR, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_SERIALNUM, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_BEFORE_TIME, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertCtrl(&cert, HITLS_X509_GET_AFTER_TIME, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_DupCert_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    HITLS_X509_Cert src = {0};
    HITLS_X509_Cert *dest = NULL;
    ASSERT_EQ(HITLS_X509_CertDup(NULL, NULL), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertDup(&src, NULL), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertDup(&src, &dest), HITLS_X509_ERR_INVALID_PARAM);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_FreeCrl_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    HITLS_X509_CrlFree(NULL);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_CtrlCrl_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CrlCtrl(NULL, 0xff, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    HITLS_X509_Crl crl = {0};
    ASSERT_EQ(HITLS_X509_CrlCtrl(&crl, 0xff, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CrlCtrl(&crl, HITLS_X509_CRL_REF_UP, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CrlCtrl(&crl, HITLS_X509_CRL_REF_UP, &crl, 0), HITLS_X509_ERR_INVALID_PARAM);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_ParseBuffCrl_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    HITLS_X509_Crl *crl = NULL;
    uint8_t buffData[10] = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CrlParseBuff(0, NULL, NULL), HITLS_X509_ERR_INVALID_PARAM);
    BSL_Buffer buff = {0};
    ASSERT_EQ(HITLS_X509_CrlParseBuff(0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    buff.data = buffData;
    ASSERT_EQ(HITLS_X509_CrlParseBuff(0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    buff.dataLen = 1;
    ASSERT_EQ(HITLS_X509_CrlParseBuff(0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CrlParseBuff(0xff, &buff, &crl), HITLS_X509_ERR_NOT_SUPPORT_FORMAT);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */ // todo
void SDV_HITLS_X509_ParseFileCrl_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, NULL, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, "../testdata/cert/asn1/ca-1-rsa-sha256-v2.der",
        NULL), HITLS_X509_ERR_INVALID_PARAM);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_ParseBuffPubKey_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    BSL_Buffer buff = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, 0xff, &buff, NULL, 0, &pkey), CRYPT_DECODE_NO_SUPPORT_TYPE);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PUBKEY_SUBKEY, NULL, NULL, 0, &pkey), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PUBKEY_RSA, NULL, NULL, 0, &pkey), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PUBKEY_SUBKEY, &buff, NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PUBKEY_RSA, &buff, NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PUBKEY_SUBKEY, &buff, NULL, 0, &pkey), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PUBKEY_RSA, &buff, NULL, 0, &pkey), CRYPT_INVALID_ARG);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_ParseFilePubKey_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(0xff, 0, NULL, NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, NULL, NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY,
        "../testdata/cert/asn1/prime256v1pub.der", NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_RSA, NULL, NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_RSA,
        "../testdata/cert/asn1/rsa2048pub_pkcs1.der", NULL, 0, NULL), CRYPT_INVALID_ARG);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_ParseBuffPriKey_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    BSL_Buffer buff = {0};
    uint8_t pwd = 0;
    CRYPT_EAL_PkeyCtx *key = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, 0xff, &buff, &pwd, 0, &key), CRYPT_DECODE_NO_SUPPORT_TYPE);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_ECC, NULL, &pwd, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_RSA, NULL, &pwd, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_PKCS8_UNENCRYPT, NULL, &pwd, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_PKCS8_ENCRYPT, NULL, &pwd, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_ECC, &buff, NULL, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_RSA, &buff, NULL, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &buff, NULL, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_PKCS8_ENCRYPT, &buff, NULL, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_ECC, &buff, &pwd, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_RSA, &buff, &pwd, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &buff, &pwd, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_PKCS8_ENCRYPT, &buff, &pwd, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_ECC, &buff, &pwd, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_RSA, &buff, &pwd, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &buff, &pwd, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(0, CRYPT_PRIKEY_PKCS8_ENCRYPT, &buff, &pwd, 0, &key), CRYPT_INVALID_ARG);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_ParseFilePriKey_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(0xff, 0, NULL, NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_ECC, NULL, NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_ECC,
        "../testdata/cert/asn1/prime256v1.der", NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA, NULL, NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        "../testdata/cert/asn1/rsa2048key_pkcs1.der", NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, NULL, NULL, 0,
        NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/prime256v1_pkcs8.der", NULL, 0, NULL), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_ENCRYPT, NULL, NULL, 0, NULL),
        CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_ENCRYPT,
        "../testdata/cert/asn1/prime256v1_pkcs8_enc.der", NULL, 0, NULL), CRYPT_INVALID_ARG);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_ParseFilePriKeyFormat_TC001(int format, int type, char *path)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(format, type, path, NULL, 0, &key), CRYPT_SUCCESS);
exit:
    CRYPT_EAL_PkeyFreeCtx(key);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_ParseFilePubKeyFormat_TC001(int format, int type, char *path)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(format, type, path, NULL, 0, &key), CRYPT_SUCCESS);
exit:
    CRYPT_EAL_PkeyFreeCtx(key);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EncodeNameList_TC001(int format, char *certPath, Hex *expect)
{
    HITLS_X509_Cert *cert = NULL;
    BSL_ASN1_Buffer name = {0};

    TestMemInit();
    BSL_GLOBAL_Init();
    ASSERT_EQ(HITLS_X509_CertParseFile(format, certPath, &cert), 0);
    ASSERT_EQ(HITLS_X509_EncodeNameList(cert->tbs.issuerName, &name), 0);

    ASSERT_COMPARE("Encode names", name.buff, name.len, expect->x, expect->len);

exit:
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(name.buff);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_SetBCons_TC001(void)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    HITLS_X509_Ext *ext = &cert->tbs.ext;
    ASSERT_EQ(ext->extFlags, 0);
    ASSERT_EQ(ext->isCa, false);
    ASSERT_EQ(ext->maxPathLen, -1);

    HITLS_X509_ExtBCons bCons = {true, true, 1};

    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_BCONS, &bCons, 0), HITLS_X509_ERR_INVALID_PARAM);

    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_BCONS, &bCons, sizeof(HITLS_X509_ExtBCons)), 0);
    ASSERT_EQ(BSL_LIST_COUNT(ext->list), 1);
    ASSERT_NE(ext->extFlags & HITLS_X509_EXT_FLAG_BCONS, 0);
    ASSERT_EQ(ext->isCa, true);
    ASSERT_EQ(ext->maxPathLen, 1);

exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_SetAkiSki_TC001(Hex *kid)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    HITLS_X509_Ext *ext = &cert->tbs.ext;
    HITLS_X509_ExtAki aki = {true, {kid->x, kid->len}, NULL, {0}};
    HITLS_X509_ExtSki ski = {true, {kid->x, kid->len}};

    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SKI, &ski, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_AKI, &aki, 0), HITLS_X509_ERR_INVALID_PARAM);

    aki.kid.dataLen = 0;
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), HITLS_X509_ERR_EXT_KID);
    aki.kid.dataLen = kid->len;

    ski.kid.dataLen = 0;
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), HITLS_X509_ERR_EXT_KID);
    ski.kid.dataLen = kid->len;

    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), 0);
    ASSERT_EQ(BSL_LIST_COUNT(ext->list), 1);
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), 0);
    ASSERT_NE(ext->extFlags & HITLS_X509_EXT_FLAG_SET, 0);
    ASSERT_EQ(BSL_LIST_COUNT(ext->list), 1 + 1);
exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_SetKeyUsage_TC001(void)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    HITLS_X509_Ext *ext = &cert->tbs.ext;
    ASSERT_EQ(ext->keyUsage, 0);

    HITLS_X509_ExtKeyUsage ku = {true, 0};

    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_KUSAGE, &ku, 0), HITLS_X509_ERR_INVALID_PARAM);

    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)),
              HITLS_X509_ERR_EXT_KU);

    ku.keyUsage = HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_NON_REPUDIATION |
        HITLS_X509_EXT_KU_KEY_ENCIPHERMENT | HITLS_X509_EXT_KU_DATA_ENCIPHERMENT | HITLS_X509_EXT_KU_KEY_AGREEMENT |
        HITLS_X509_EXT_KU_KEY_CERT_SIGN | HITLS_X509_EXT_KU_CRL_SIGN | HITLS_X509_EXT_KU_ENCIPHER_ONLY |
        HITLS_X509_EXT_KU_DECIPHER_ONLY;
    ku.keyUsage = ~ku.keyUsage;
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)),
              HITLS_X509_ERR_EXT_KU);

    ku.keyUsage = ~ku.keyUsage;
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)), 0);
    ASSERT_EQ(BSL_LIST_COUNT(ext->list), 1);
    ASSERT_NE(ext->extFlags & HITLS_X509_EXT_FLAG_KUSAGE, 0);
    ASSERT_NE(ext->extFlags & HITLS_X509_EXT_FLAG_SET, 0);

exit:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_SetExtendKeyUsage_TC001(void)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    BslList *oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_NE(oidList, NULL);

    HITLS_X509_Ext *ext = &cert->tbs.ext;
    HITLS_X509_ExtExKeyUsage exku = {true, NULL};

    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_EXKUSAGE, &exku, 0), HITLS_X509_ERR_INVALID_PARAM);

    // error: list is null
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_EXKUSAGE, &exku, sizeof(HITLS_X509_ExtExKeyUsage)),
              HITLS_X509_ERR_EXT_EXTENDED_KU);
    // werror: list is empty
    exku.oidList = oidList;
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_EXKUSAGE, &exku, sizeof(HITLS_X509_ExtExKeyUsage)),
              HITLS_X509_ERR_EXT_EXTENDED_KU);
    // error: oid is null
    BSL_Buffer emptyOid = {0};
    ASSERT_EQ(BSL_LIST_AddElement(oidList, &emptyOid, BSL_LIST_POS_END), 0);
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_EXKUSAGE, &exku, sizeof(HITLS_X509_ExtExKeyUsage)),
              HITLS_X509_ERR_EXT_EXTENDED_KU_ELE);
    BSL_LIST_DeleteAll(oidList, FreeListData);

    // success: normal oid
    BslOidString *oid = BSL_OBJ_GetOidFromCID(BSL_CID_CE_SERVERAUTH);
    ASSERT_NE(oid, NULL);
    BSL_Buffer oidBuff = {(uint8_t *)oid->octs, oid->octetLen};
    ASSERT_EQ(BSL_LIST_AddElement(oidList, &oidBuff, BSL_LIST_POS_END), 0);
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_EXKUSAGE, &exku, sizeof(HITLS_X509_ExtExKeyUsage)), 0);
    ASSERT_NE(ext->extFlags & HITLS_X509_EXT_FLAG_SET, 0);

exit:
    HITLS_X509_CertFree(cert);
    BSL_LIST_FREE(oidList, FreeListData);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_SetSan_TC001(void)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    BslList *list = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    ASSERT_NE(list, NULL);

    HITLS_X509_Ext *ext = &cert->tbs.ext;
    HITLS_X509_ExtSan san = {true, NULL};

    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SAN, &san, 0), HITLS_X509_ERR_INVALID_PARAM);

    // error: list is null
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), HITLS_X509_ERR_EXT_SAN);
    // error: list is empty
    san.names = list;
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), HITLS_X509_ERR_EXT_SAN);
    // error: list data content is null
    HITLS_X509_GeneralName empty = {0};
    ASSERT_EQ(BSL_LIST_AddElement(list, &empty, BSL_LIST_POS_END), 0);
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)),
              HITLS_X509_ERR_EXT_SAN_ELE);
    BSL_LIST_DeleteAll(list, FreeListData);

    // error: name type
    char *email = "test@a.com";
    HITLS_X509_GeneralName errType = {HITLS_X509_GN_IP + 1, {(uint8_t *)email, (uint32_t)strlen(email)}};
    ASSERT_EQ(BSL_LIST_AddElement(list, &errType, BSL_LIST_POS_END), 0);
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)),
              HITLS_X509_ERR_EXT_GN_UNSUPPORT);
    BSL_LIST_DeleteAll(list, FreeListData);
    // success
    HITLS_X509_GeneralName nomal = {HITLS_X509_GN_EMAIL, {(uint8_t *)email, (uint32_t)strlen(email)}};
    ASSERT_EQ(BSL_LIST_AddElement(list, &nomal, BSL_LIST_POS_END), 0);
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), 0);
    ASSERT_NE(ext->extFlags & HITLS_X509_EXT_FLAG_SET, 0);

exit:
    HITLS_X509_CertFree(cert);
    BSL_LIST_FREE(list, FreeListData);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_EncodeBCons_TC001(int critical, int isCa, int maxPathLen, Hex *expect)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    int8_t tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    HITLS_X509_ExtBCons bCons = {critical, isCa, maxPathLen};
    BSL_ASN1_Buffer encode = {0};

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    ASSERT_EQ(HITLS_X509_ExtCtrl(&cert->tbs.ext, HITLS_X509_EXT_SET_BCONS, &bCons, sizeof(HITLS_X509_ExtBCons)), 0);
    ASSERT_EQ(HITLS_X509_EncodeExt(tag, cert->tbs.ext.list, &encode), HITLS_X509_SUCCESS);
    ASSERT_EQ(encode.len, expect->len);
    ASSERT_COMPARE("Ext: bCons", encode.buff, encode.len, expect->x, expect->len);
exit:
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(encode.buff);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_EncodeExtendKeyUsage_TC001(int critical, Hex *oid1, Hex *oid2, Hex *expect)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    int8_t tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    BSL_ASN1_Buffer encode = {0};
    HITLS_X509_ExtExKeyUsage exku = {critical, NULL};

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    exku.oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_NE(exku.oidList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(exku.oidList, oid1, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(exku.oidList, oid2, BSL_LIST_POS_END), 0);

    ASSERT_EQ(HITLS_X509_ExtCtrl(&cert->tbs.ext, HITLS_X509_EXT_SET_EXKUSAGE, &exku, sizeof(HITLS_X509_ExtExKeyUsage)),
              0);
    ASSERT_EQ(HITLS_X509_EncodeExt(tag, cert->tbs.ext.list, &encode), HITLS_X509_SUCCESS);
    ASSERT_EQ(encode.len, expect->len);
    ASSERT_COMPARE("Ext: extendKeyUsage", encode.buff, encode.len, expect->x, expect->len);

exit:
    HITLS_X509_CertFree(cert);
    BSL_LIST_DeleteAll(exku.oidList, FreeListData);
    BSL_SAL_Free(exku.oidList);
    BSL_SAL_Free(encode.buff);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_EncodeSan_TC001(int critical, int type1, int type2, int type3, int type4, int dirCid1,
    int dirCid2, Hex *value, Hex *expect)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    int8_t tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    BSL_ASN1_Buffer encode = {0};
    HITLS_X509_ExtSan san = {critical, NULL};

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    san.names = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_NE(san.names, NULL);

    // Generate san
    BslList *dirNames = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    ASSERT_NE(dirNames, NULL);
    HITLS_X509_DN dnName1[1] = {{(BslCid)dirCid1, value->x, value->len}};
    HITLS_X509_DN dnName2[1] = {{(BslCid)dirCid2, value->x, value->len}};
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName1, 1), 0);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName2, 1), 0);
    HITLS_X509_GeneralName names[] = {
        {type1, {value->x, value->len}},
        {type2, {value->x, value->len}},
        {type3, {value->x, value->len}},
        {type4, {value->x, value->len}},
        {HITLS_X509_GN_DNNAME, {(uint8_t *)dirNames, sizeof(BslList *)}},
    };
    for (uint32_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        ASSERT_EQ(BSL_LIST_AddElement(san.names, &names[i], BSL_LIST_POS_END), 0);
    }

    // set san and encode ext
    ASSERT_EQ(HITLS_X509_ExtCtrl(&cert->tbs.ext, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), 0);
    ASSERT_EQ(HITLS_X509_EncodeExt(tag, cert->tbs.ext.list, &encode), HITLS_X509_SUCCESS);
    ASSERT_EQ(encode.len, expect->len);
    ASSERT_COMPARE("Ext: san", encode.buff, encode.len, expect->x, expect->len);

exit:
    HITLS_X509_CertFree(cert);
    BSL_LIST_DeleteAll(san.names, FreeSanListData);
    BSL_SAL_Free(san.names);
    BSL_SAL_Free(encode.buff);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_EncodeKeyUsage_TC001(int critical, int usage, Hex *expect)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    int8_t tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    HITLS_X509_ExtKeyUsage ku = {critical, usage};
    BSL_ASN1_Buffer encode = {0};

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    ASSERT_EQ(HITLS_X509_ExtCtrl(&cert->tbs.ext, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)), 0);
    ASSERT_EQ(HITLS_X509_EncodeExt(tag, cert->tbs.ext.list, &encode), HITLS_X509_SUCCESS);
    ASSERT_EQ(encode.len, expect->len);
    ASSERT_COMPARE("Ext: keyUsage", encode.buff, encode.len, expect->x, expect->len);
exit:
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(encode.buff);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_EncodeAKiSki_TC001(int critical1, int critical2, Hex *kid1, Hex *kid2, Hex *expect)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    int8_t tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    HITLS_X509_ExtAki aki = {critical1, {kid1->x, kid1->len}, NULL, {0}};
    HITLS_X509_ExtSki ski = {critical2, {kid2->x, kid2->len}};
    BSL_ASN1_Buffer encode = {0};

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    ASSERT_EQ(HITLS_X509_ExtCtrl(&cert->tbs.ext, HITLS_X509_EXT_SET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), 0);
    ASSERT_EQ(HITLS_X509_ExtCtrl(&cert->tbs.ext, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), 0);
    ASSERT_EQ(HITLS_X509_EncodeExt(tag, cert->tbs.ext.list, &encode), HITLS_X509_SUCCESS);
    ASSERT_EQ(encode.len, expect->len);
    ASSERT_COMPARE("Ext:aki ski", encode.buff, encode.len, expect->x, expect->len);
exit:
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(encode.buff);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

typedef struct {
    int32_t type;
    Hex *value;
} TestGeneralNameMap;

/* BEGIN_CASE */
void SDV_X509_EXT_ParseGeneralNames_TC001(Hex *encode, Hex *ip, Hex *uri, Hex *rfc822, Hex *regId, Hex *dns)
{
    TestGeneralNameMap map[] = {
        {HITLS_X509_GN_DNNAME, NULL},
        {HITLS_X509_GN_IP, ip},
        {HITLS_X509_GN_URI, uri},
        {HITLS_X509_GN_OTHER, NULL},
        {HITLS_X509_GN_EMAIL, rfc822},
        {HITLS_X509_GN_RID, regId},
        {HITLS_X509_GN_DNS, dns},
    };

    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    ASSERT_NE(list, NULL);

    ASSERT_EQ(HITLS_X509_ParseGeneralNames(encode->x, encode->len, list), HITLS_X509_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(list), sizeof(map) / sizeof(map[0]));

    HITLS_X509_GeneralName *name = NULL;
    uint32_t idx = 0;
    for (name = BSL_LIST_GET_FIRST(list); name != NULL; name = BSL_LIST_GET_NEXT(list), idx++) {
        ASSERT_EQ(name->type, map[idx].type);
        if (map[idx].value != NULL) {
            ASSERT_COMPARE("gn", name->value.data, name->value.dataLen, map[idx].value->x, map[idx].value->len);
        }
    }

exit:
    HITLS_X509_ClearGeneralNames(list);
    BSL_SAL_Free(list);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_ParseGeneralNames_Error_TC001(Hex *encode, int ret)
{
    BSL_GLOBAL_Init();
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    ASSERT_NE(list, NULL);

    ASSERT_EQ(HITLS_X509_ParseGeneralNames(encode->x, encode->len, list), ret);

exit:
    BSL_SAL_Free(list);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_ParseSki_TC001(Hex *encode, int ret, Hex *kid)
{
    BSL_GLOBAL_Init();
    TestMemInit();
    HITLS_X509_ExtSki ski = {0};
    HITLS_X509_ExtEntry entry = {BSL_CID_CE_SUBJECTKEYID, {0}, true, {0, encode->len, encode->x}};

    ASSERT_EQ(HITLS_X509_ParseSubjectKeyId(&entry, &ski), ret);
    if (ret == 0) {
        ASSERT_EQ(ski.critical, entry.critical);
        ASSERT_COMPARE("Subject kid", kid->x, kid->len, ski.kid.data, ski.kid.dataLen);
    }

exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_ParseExtendedKu_TC001(Hex *encode, Hex *ku1, Hex *ku2, Hex *ku3)
{
    BSL_GLOBAL_Init();
    TestMemInit();

    Hex *values[] = {ku1, ku2, ku3};
    uint32_t cnt = sizeof(values) / sizeof(values[0]);
    HITLS_X509_ExtExKeyUsage exku = {0};
    HITLS_X509_ExtEntry entry = {BSL_CID_CE_EXTENDEDKEYUSAGE, {0}, true, {0, encode->len, encode->x}};

    ASSERT_EQ(HITLS_X509_ParseExtendedKeyUsage(&entry, &exku), 0);
    ASSERT_EQ(exku.critical, entry.critical);
    ASSERT_EQ(BSL_LIST_COUNT(exku.oidList), cnt);
    uint32_t idx = 0;
    for (BSL_Buffer *data = BSL_LIST_GET_FIRST(exku.oidList); data != NULL; data = BSL_LIST_GET_NEXT(exku.oidList)) {
        ASSERT_COMPARE("Extended key usage", values[idx]->x, values[idx]->len, data->data, data->dataLen);
        idx++;
    }

exit:
    HITLS_X509_ClearExtendedKeyUsage(&exku);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_ParseAki_TC001(Hex *encode, Hex *kid, Hex *serial, int nameCnt)
{
    HITLS_X509_ExtAki aki = {0};
    HITLS_X509_ExtEntry entry = {BSL_CID_CE_AUTHORITYKEYID, {0}, true, {0, encode->len, encode->x}};

    TestMemInit();
    ASSERT_EQ(HITLS_X509_ParseAuthorityKeyId(&entry, &aki), 0);

    ASSERT_EQ(aki.critical, entry.critical);
    ASSERT_COMPARE("kid", aki.kid.data, aki.kid.dataLen, kid->x, kid->len);
    ASSERT_COMPARE("serial", aki.serialNum.data, aki.serialNum.dataLen, serial->x, serial->len);

    ASSERT_EQ(BSL_LIST_COUNT(aki.issuerName), nameCnt);

exit:
    HITLS_X509_ClearAuthorityKeyId(&aki);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_ParseSan_TC001(Hex *encode, int gnNameCnt, int gnType1, int gnType2, Hex *rfc822, Hex *dnType,
                                 Hex *dnValue)
{
    HITLS_X509_ExtSan san = {0};
    HITLS_X509_ExtEntry entry = {BSL_CID_CE_SUBJECTALTNAME, {0}, true, {0, encode->len, encode->x}};
    HITLS_X509_GeneralName *gnName = NULL;
    BslList *dirNameList = NULL;
    HITLS_X509_NameNode *dirName = NULL;

    TestMemInit();
    ASSERT_EQ(HITLS_X509_ParseSubjectAltName(&entry, &san), 0);
    ASSERT_EQ(san.critical, entry.critical);
    ASSERT_EQ(BSL_LIST_COUNT(san.names), gnNameCnt);

    gnName = BSL_LIST_GET_FIRST(san.names);
    ASSERT_EQ(gnName->type, gnType1);
    ASSERT_COMPARE("gnName 1", rfc822->x, rfc822->len, gnName->value.data, gnName->value.dataLen);

    gnName = BSL_LIST_GET_NEXT(san.names);
    ASSERT_EQ(gnName->type, gnType2);
    dirNameList = (BslList *)gnName->value.data;
    ASSERT_EQ(BSL_LIST_COUNT(dirNameList), 1 + 1); // layer 1 and layer 2
    dirName = BSL_LIST_GET_FIRST(dirNameList);     // layer 1
    dirName = BSL_LIST_GET_NEXT(dirNameList);      // layer 2
    ASSERT_COMPARE("dnname type", dirName->nameType.buff, dirName->nameType.len, dnType->x, dnType->len);
    ASSERT_COMPARE("dnname value", dirName->nameValue.buff, dirName->nameValue.len, dnValue->x, dnValue->len);

exit:
    HITLS_X509_ClearSubjectAltName(&san);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_EXT_GetSki_TC001(Hex *encode, int ret, int critical, Hex *kid)
{
    TestMemInit();

    BSL_ASN1_Buffer asnExt = {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, encode->len, encode->x};
    bool getIsExist;
    HITLS_X509_ExtSki ski = {0};

    HITLS_X509_Ext *ext = HITLS_X509_ExtNew();
    ASSERT_NE(ext, NULL);
    ASSERT_EQ(HITLS_X509_ParseExt(&asnExt, ext), 0);

    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_CHECK_SKI, &getIsExist, sizeof(bool)), 0);
    ASSERT_EQ(getIsExist, ret == HITLS_X509_SUCCESS);

    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), ret);
    ASSERT_EQ(ski.critical, critical);
    ASSERT_COMPARE("Get ski", ski.kid.data, ski.kid.dataLen, kid->x, kid->len);

exit:
    HITLS_X509_ExtFree(ext);
}
/* END_CASE */
