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
#include "hitls_pki_crl.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "bsl_obj.h"
#include "crypt_codecskey.h"
#include "crypt_eal_codecs.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "crypt_errno.h"
#include "hitls_crl_local.h"
#include "hitls_cert_local.h"
#include "hitls_pki_utils.h"
#include "hitls_pki_x509.h"
#include "hitls_x509_verify.h"
/* END_HEADER */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Verify the consistency between signatureAlgorithm and signature in the CRL.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC001(char *path, char *pathChangeCid, int cid)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(cid, crl->tbs.signAlgId.algId);
    ASSERT_EQ(cid, crl->signAlgId.algId);
    HITLS_X509_CrlFree(crl);
    crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, pathChangeCid, &crl), HITLS_PKI_SUCCESS);
    ASSERT_NE(crl->signAlgId.algId, crl->tbs.signAlgId.algId);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the version field in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC002(char *pathv1, char *pathv2)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, pathv1, &crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(crl->tbs.version, 0);
    HITLS_X509_CrlFree(crl);
    crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, pathv2, &crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(crl->tbs.version, 5); // 5 is invalid version.
    // Test getting the version number
    uint32_t version = 0;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_VERSION, &version, sizeof(uint32_t)), HITLS_PKI_SUCCESS);
    // The CRL version should be 0 (v1) or 1 (v2), 5 is invalid version.
    ASSERT_TRUE(version == 5);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test CRL files containing invalid CID fields.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC003(char *path, int res)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), res);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the supported encoding formats for the Issuer Name field in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC004(char *path, int res, Hex *dn)
{
    HITLS_X509_Crl *crl = NULL;
    BSL_Buffer issuerDN = {0};
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), res);
    if (res == HITLS_PKI_SUCCESS) {
        // Test getting the issuer DN name
        ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_ISSUER_DN_STR, &issuerDN, sizeof(BSL_Buffer)),
            HITLS_PKI_SUCCESS);
        ASSERT_COMPARE("crl dn name", issuerDN.data, issuerDN.dataLen, dn->x, dn->len);
    }

EXIT:
    BSL_SAL_Free(issuerDN.data);
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the parsing capability of UTCTime and GeneralizedTime in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC005(char *path, int beforeYear, int afterYear)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), HITLS_PKI_SUCCESS);
    BSL_TIME beforeTime = {0};
    BSL_TIME afterTime = {0};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(beforeTime.year, beforeYear);
    ASSERT_EQ(afterTime.year, afterYear);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the parsing of abnormally formatted timestamps in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC006(char *path, int res)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), res);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the parsing capability of abnormal timestamps in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC007(char *path, int res)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), res);
    if (res == HITLS_PKI_SUCCESS) {
        BSL_TIME beforeTime = {0};
        BSL_TIME afterTime = {0};
        ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)),
            HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
        ASSERT_TRUE(beforeTime.year > afterTime.year);
    }

EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the parsing capability of the Revoked Certificates field in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC008(char *path, int res)
{
    HITLS_X509_Crl *crl = NULL;
    BslList *revokeList = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), res);
    if (res == HITLS_PKI_SUCCESS) {
        ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_REVOKELIST, &revokeList, sizeof(BslList *)),
            HITLS_PKI_SUCCESS);
        ASSERT_TRUE(revokeList != NULL);
        ASSERT_EQ(BSL_LIST_COUNT(revokeList), 0);
    }
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the parsing capability of the CRL Number extension field in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC009(char *path, int critical, Hex *crlNumber, int res)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), HITLS_PKI_SUCCESS);
    HITLS_X509_ExtCrlNumber crlNumExt = {0};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_GET_CRLNUMBER, &crlNumExt, sizeof(HITLS_X509_ExtCrlNumber)), res);
    ASSERT_EQ(crlNumExt.critical, critical);
    ASSERT_EQ(crlNumExt.crlNumber.dataLen, crlNumber->len);
    ASSERT_EQ(memcmp(crlNumber->x, crlNumExt.crlNumber.data, crlNumber->len), 0);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the parsing capability of the Authority Key Identifier extension field in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC010(char *path, int critical)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), HITLS_PKI_SUCCESS);
    HITLS_X509_ExtAki getaki = {0};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_GET_AKI, &getaki, sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(getaki.critical, critical);

EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the parsing capability of the Reason Code extension field in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC011(char *path, int res, int reasonCode)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), res);
    HITLS_X509_CrlEntry *entry = BSL_LIST_GET_FIRST(crl->tbs.revokedCerts);
    int32_t getReason = 0;
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_REASON, &getReason, sizeof(getReason)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(reasonCode, getReason);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the parsing capability of the Invalidity Date extension field in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC012(char *path, int yesr, int res)
{
    HITLS_X509_Crl *crl = NULL;
    BSL_TIME invalidTime = {0};
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), res);
    HITLS_X509_CrlEntry *entry = BSL_LIST_GET_FIRST(crl->tbs.revokedCerts);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_INVALID_TIME, &invalidTime,
        sizeof(invalidTime)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(invalidTime.year, yesr);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test the parsing capability of the Certificate Issuer extension field in CRL files.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FILE_FUNC_TC013(char *path, int res1, int res2)
{
    HITLS_X509_Crl *crl = NULL;
    char certIssuer[256] = {0};
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, path, &crl), res1);
    if (res1 == HITLS_PKI_SUCCESS) {
        HITLS_X509_CrlEntry *entry = BSL_LIST_GET_FIRST(crl->tbs.revokedCerts);
        ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_CERTISSUER, &certIssuer,
            sizeof(certIssuer)), res2);
    }
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC001
* @title  Test verification of revoked certificates.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_FILE_VERIFY_FUNC_TC001(char *caPath, char *crlPath, char *certPath, int flags, int crlVerResult,
    int expResult)
{
    TestMemInit();
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);
    storeCtx->verifyParam.flags = flags; // HITLS_X509_VFY_FLAG_CRL_ALL or HITLS_X509_VFY_FLAG_CRL_DEV

    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *testCert = NULL;
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(storeCtx->store, caCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    HITLS_X509_Crl *crl = NULL;
    ret = HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, crlPath, &crl);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(storeCtx->crl, crl, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = HITLS_X509_VerifyCrl(storeCtx, storeCtx->store);
    ASSERT_EQ(ret, crlVerResult);

    HITLS_X509_List *certChain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certChain != NULL);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &testCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(certChain, testCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = HITLS_X509_CertVerify(storeCtx, certChain);
    ASSERT_EQ(ret, expResult);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_LIST_FREE(certChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_FILE_VERIFY_FUNC_TC002
* @title  Verify CRL with intermediate certificates present.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_FILE_VERIFY_FUNC_TC002(char *rootCaPath, char *caPath, char *rootCrlPath, char *crlPath,
    char *certPath, int flags, int certVerResult, int crlVerResult)
{
    TestMemInit();
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);
    storeCtx->verifyParam.flags = flags; // HITLS_X509_VFY_FLAG_CRL_ALL or HITLS_X509_VFY_FLAG_CRL_DEV

    HITLS_X509_Cert *rootCaCert = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *testCert = NULL;
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, rootCaPath, &rootCaCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(storeCtx->store, rootCaCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(storeCtx->store, caCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    HITLS_X509_Crl *crl = NULL;
    ret = HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, crlPath, &crl);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(storeCtx->crl, crl, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    if (strlen(rootCrlPath) > 0) {
        HITLS_X509_Crl *rootCrl = NULL;
        ret = HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, rootCrlPath, &rootCrl);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
        ret = BSL_LIST_AddElement(storeCtx->crl, rootCrl, BSL_LIST_POS_END);
        ASSERT_EQ(ret, BSL_SUCCESS);
    }

    ret = HITLS_X509_VerifyCrl(storeCtx, storeCtx->store);
    ASSERT_EQ(ret, crlVerResult);

    HITLS_X509_List *certChain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certChain != NULL);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &testCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(certChain, testCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = HITLS_X509_CertVerify(storeCtx, certChain);
    ASSERT_EQ(ret, certVerResult);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_LIST_FREE(certChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_FILE_VERIFY_FUNC_TC003
* @title  Verify CRL with tampered fields.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_FILE_VERIFY_FUNC_TC003(char *caPath, char *crlPath, char *certPath, int flags,
    int crlVerResult, int certVerResult)
{
    TestMemInit();
    char *rootCaPath = "../testdata/cert/test_for_crl/crl_verify/certs/ca.crt";
    char *rootCrlPath = "../testdata/cert/test_for_crl/crl_verify/crl/root_updated.crl";
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);
    storeCtx->verifyParam.flags = flags; // HITLS_X509_VFY_FLAG_CRL_ALL or HITLS_X509_VFY_FLAG_CRL_DEV

    HITLS_X509_Cert *rootCaCert = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *testCert = NULL;
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, rootCaPath, &rootCaCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(storeCtx->store, rootCaCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(storeCtx->store, caCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    HITLS_X509_Crl *crl = NULL;
    ret = HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, crlPath, &crl);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(storeCtx->crl, crl, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    HITLS_X509_Crl *rootCrl = NULL;
    ret = HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, rootCrlPath, &rootCrl);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(storeCtx->crl, rootCrl, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = HITLS_X509_VerifyCrl(storeCtx, storeCtx->store);
    ASSERT_EQ(ret, crlVerResult);

    HITLS_X509_List *certChain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certChain != NULL);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &testCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(certChain, testCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = HITLS_X509_CertVerify(storeCtx, certChain);
    ASSERT_EQ(ret, certVerResult);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_LIST_FREE(certChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* @
* @test  SDV_X509_CRL_PARSE_FILE_FUNC_TC004
* @title  Test verification of revoked certificates: set sm2UserId.
@ */
/* BEGIN_CASE */
void SDV_X509_CRL_FILE_VERIFY_FUNC_TC004(char *caPath, char *crlPath, char *certPath, int flags, int crlVerResult,
    int expResult)
{
    TestMemInit();
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);
    storeCtx->verifyParam.flags = flags; // HITLS_X509_VFY_FLAG_CRL_ALL or HITLS_X509_VFY_FLAG_CRL_DEV

    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *testCert = NULL;
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(storeCtx->store, caCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    HITLS_X509_Crl *crl = NULL;
    ret = HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, crlPath, &crl);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(storeCtx->crl, crl, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    const char *sm2UserId = "1234567812345678";
    uint32_t sm2UserIdLen = (uint32_t)strlen(sm2UserId);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_VFY_SM2_USERID,
        (void *)sm2UserId, sm2UserIdLen), HITLS_PKI_SUCCESS);

    ret = HITLS_X509_VerifyCrl(storeCtx, storeCtx->store);
    ASSERT_EQ(ret, crlVerResult);

    HITLS_X509_List *certChain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certChain != NULL);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &testCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(certChain, testCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = HITLS_X509_CertVerify(storeCtx, certChain);
    ASSERT_EQ(ret, expResult);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_LIST_FREE(certChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */