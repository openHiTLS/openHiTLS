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
#include "crypt_errno.h"
#include "crypt_eal_encode.h"

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
void SDV_HITLS_X509_FreeStoreCtx_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    HITLS_X509_FreeStoreCtx(NULL);
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

    ASSERT_EQ(HITLS_X509_CtrlStoreCtx(NULL, 0, NULL, 0), HITLS_INVALID_INPUT);
    HITLS_X509_StoreCtx storeCtx = {0};
    ASSERT_EQ(HITLS_X509_CtrlStoreCtx(&storeCtx, 0, NULL, 0), HITLS_INVALID_INPUT);
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

    ASSERT_EQ(HITLS_X509_VerifyCert(NULL, NULL), HITLS_INVALID_INPUT);
    HITLS_X509_StoreCtx storeCtx = {0};
    ASSERT_EQ(HITLS_X509_VerifyCert(&storeCtx, NULL), HITLS_INVALID_INPUT);
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

    ASSERT_EQ(HITLS_X509_BuildCertChain(NULL, NULL, NULL), HITLS_INVALID_INPUT);
    HITLS_X509_StoreCtx storeCtx = {0};
    ASSERT_EQ(HITLS_X509_BuildCertChain(&storeCtx, NULL, NULL), HITLS_INVALID_INPUT);
    HITLS_X509_Cert cert = {0};
    ASSERT_EQ(HITLS_X509_BuildCertChain(&storeCtx, &cert, NULL), HITLS_INVALID_INPUT);
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

    HITLS_X509_FreeCert(NULL);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_ParseBuffCert_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_ParseBuffCert(0, 0, NULL, NULL), HITLS_X509_ERR_INVALID_PARAM);
    BSL_Buffer buff = {0};
    ASSERT_EQ(HITLS_X509_ParseBuffCert(0, 0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    buff.data = &buff;
    ASSERT_EQ(HITLS_X509_ParseBuffCert(0, 0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    buff.dataLen = 1;
    ASSERT_EQ(HITLS_X509_ParseBuffCert(0, 0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_ParseBuffCert(0, 0xff, &buff, &buff), HITLS_X509_ERR_NOT_SUPPORT_FORMAT);
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

    ASSERT_EQ(HITLS_X509_ParseFileCert(BSL_PARSE_FORMAT_ASN1, NULL, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(HITLS_X509_ParseFileCert(BSL_PARSE_FORMAT_ASN1, "../testdata/cert/asn1/nist384ca.crt", NULL), HITLS_X509_ERR_INVALID_PARAM);
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

    ASSERT_EQ(HITLS_X509_CtrlCert(NULL, 0xff, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    HITLS_X509_Cert cert = {0};
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, 0xff, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_GET_ENCODELEN, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_GET_ENCODELEN, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_ENCODE, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_GET_PUBKEY, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_GET_PUBKEY, &cert, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_GET_SIGNALG, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_GET_SIGNALG, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_REF_UP, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_REF_UP, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_EXT_KU_DIGITALSIGN, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_EXT_KU_DIGITALSIGN, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_EXT_KU_CERTSIGN, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_EXT_KU_CERTSIGN, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_EXT_KU_KEYAGREEMENT, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCert(&cert, HITLS_X509_CERT_EXT_KU_KEYAGREEMENT, &cert, 0), HITLS_X509_ERR_INVALID_PARAM);
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
    ASSERT_EQ(HITLS_X509_DupCert(NULL, NULL), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_DupCert(&src, NULL), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_DupCert(&src, &dest), HITLS_X509_ERR_INVALID_PARAM);
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

    HITLS_X509_FreeCrl(NULL);
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

    ASSERT_EQ(HITLS_X509_CtrlCrl(NULL, 0xff, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    HITLS_X509_Crl crl = {0};
    ASSERT_EQ(HITLS_X509_CtrlCrl(&crl, 0xff, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCrl(&crl, HITLS_X509_CRL_REF_UP, NULL, 0), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CtrlCrl(&crl, HITLS_X509_CRL_REF_UP, &crl, 0), HITLS_X509_ERR_INVALID_PARAM);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_X509_ParseBuffCrl_TC001(void)
{
    TestMemInit();
    BSL_LOG_BinLogFuncs func = {0};
    BSL_GLOBAL_Init();
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_ParseBuffCrl(0, 0, NULL, NULL), HITLS_X509_ERR_INVALID_PARAM);
    BSL_Buffer buff = {0};
    ASSERT_EQ(HITLS_X509_ParseBuffCrl(0, 0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    buff.data = &buff;
    ASSERT_EQ(HITLS_X509_ParseBuffCrl(0, 0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    buff.dataLen = 1;
    ASSERT_EQ(HITLS_X509_ParseBuffCrl(0, 0, &buff, NULL), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_ParseBuffCrl(0, 0xff, &buff, &buff), HITLS_X509_ERR_NOT_SUPPORT_FORMAT);
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

    ASSERT_EQ(HITLS_X509_ParseFileCrl(BSL_PARSE_FORMAT_ASN1, NULL, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(HITLS_X509_ParseFileCrl(BSL_PARSE_FORMAT_ASN1, "../testdata/cert/asn1/ca-1-rsa-sha256-v2.der", NULL), HITLS_X509_ERR_INVALID_PARAM);
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
    ASSERT_EQ(CRYPT_EAL_ParseBuffPubKey(0, 0xff, &buff, &pkey), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPubKey(0, CRYPT_PUBKEY_SUBKEY, NULL, &pkey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPubKey(0, CRYPT_PUBKEY_RSA, NULL, &pkey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPubKey(0, CRYPT_PUBKEY_SUBKEY, &buff, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPubKey(0, CRYPT_PUBKEY_RSA, &buff, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPubKey(0, CRYPT_PUBKEY_SUBKEY, &buff, &pkey), BSL_ASN1_ERR_DECODE_LEN);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPubKey(0, CRYPT_PUBKEY_RSA, &buff, &pkey), BSL_ASN1_ERR_DECODE_LEN);
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

    ASSERT_EQ(CRYPT_EAL_ParseFilePubKey(0xff, 0, NULL, NULL), CRYPT_DECODE_UNSUPPORTED_FILE_FORMAT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePubKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, NULL, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePubKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, "../testdata/cert/asn1/prime256v1pub.der", NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePubKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PUBKEY_RSA, NULL, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePubKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PUBKEY_RSA, "../testdata/cert/asn1/rsa2048pub_pkcs1.der", NULL), CRYPT_NULL_INPUT);
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
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, 0xff, &buff, &pwd, 0, &key), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_ECC, NULL, &pwd, 0, &key), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_RSA, NULL, &pwd, 0, &key), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_PKCS8_UNENCRYPT, NULL, &pwd, 0, &key), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_PKCS8_ENCRYPT, NULL, &pwd, 0, &key), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_ECC, &buff, NULL, 0, &key), BSL_ASN1_ERR_DECODE_LEN);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_RSA, &buff, NULL, 0, &key), BSL_ASN1_ERR_DECODE_LEN);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &buff, NULL, 0, &key), BSL_ASN1_ERR_DECODE_LEN);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_PKCS8_ENCRYPT, &buff, NULL, 0, &key), BSL_ASN1_ERR_DECODE_LEN);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_ECC, &buff, &pwd, 0, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_RSA, &buff, &pwd, 0, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &buff, &pwd, 0, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_PKCS8_ENCRYPT, &buff, &pwd, 0, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_ECC, &buff, &pwd, 0, &key), BSL_ASN1_ERR_DECODE_LEN);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_RSA, &buff, &pwd, 0, &key), BSL_ASN1_ERR_DECODE_LEN);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &buff, &pwd, 0, &key), BSL_ASN1_ERR_DECODE_LEN);
    ASSERT_EQ(CRYPT_EAL_ParseBuffPriKey(0, CRYPT_PRIKEY_PKCS8_ENCRYPT, &buff, &pwd, 0, &key), BSL_ASN1_ERR_DECODE_LEN);
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

    ASSERT_EQ(CRYPT_EAL_ParseFilePriKey(0xff, 0, NULL, NULL, 0, NULL), CRYPT_DECODE_UNSUPPORTED_FILE_FORMAT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePriKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PRIKEY_ECC, NULL, NULL, 0, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePriKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PRIKEY_ECC, "../testdata/cert/asn1/prime256v1.der", NULL, 0, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePriKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PRIKEY_RSA, NULL, NULL, 0, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePriKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PRIKEY_RSA, "../testdata/cert/asn1/rsa2048key_pkcs1.der", NULL, 0, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePriKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, NULL, NULL, 0, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePriKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, "../testdata/cert/asn1/prime256v1_pkcs8.der", NULL, 0, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePriKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_ENCRYPT, NULL, NULL, 0, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_ParseFilePriKey(BSL_PARSE_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_ENCRYPT, "../testdata/cert/asn1/prime256v1_pkcs8_enc.der", NULL, 0, NULL), CRYPT_NULL_INPUT);
exit:
    BSL_GLOBAL_DeInit();
}
/* END_CASE */
