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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "bsl_init.h"
#include "bsl_list.h"
#include "hitls_pki_x509.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_verify.h"
#include "hitls_cert_local.h"
#include "hitls_crl_local.h"
#include "bsl_list_internal.h"
#include "sal_atomic.h"
#include "hitls_x509_verify.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "bsl_uio.h"
#include "hitls_pki_utils.h"
#include "bsl_asn1.h"
#include "stub_utils.h"
#include "bsl_err_internal.h"

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, HITLS_X509_CheckCertTime, HITLS_X509_StoreCtx *, HITLS_X509_Cert *, int32_t);

/* ============================================================================
 * Helper Macros for Verification Callback
 * ============================================================================ */
#ifdef HITLS_PKI_X509_VFY_CB
// Define internal helper and macro needed for stub implementations
static int32_t VerifyCertCbk(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t errDepth, int32_t errCode)
{
    if (cert != NULL) {
        storeCtx->curCert = cert;
    }
    if (errDepth >= 0) {
        storeCtx->curDepth = errDepth;
    }
    if (errCode != HITLS_PKI_SUCCESS) {
        storeCtx->error = errCode;
    }
    return storeCtx->verifyCb(errCode, storeCtx);
}

#define VFYCBK_FAIL_IF(cond, storeCtx, cert, depth, err)                 \
    do {                                                                 \
        if (cond) {                                                      \
            int32_t cbkRet = VerifyCertCbk(storeCtx, cert, depth, err);  \
            if (cbkRet != HITLS_PKI_SUCCESS) {                           \
                BSL_ERR_PUSH_ERROR(err);                                 \
                return cbkRet;                                           \
            }                                                            \
        }                                                                \
    } while (0)
#else
// When callback feature is disabled, use simple error checking
#define VFYCBK_FAIL_IF(cond, storeCtx, cert, depth, err)                 \
    do {                                                                 \
        if (cond) {                                                      \
            BSL_ERR_PUSH_ERROR(err);                                     \
            return err;                                                  \
        }                                                                \
    } while (0)
#endif


void HITLS_X509_FreeStoreCtxMock(HITLS_X509_StoreCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int ret;
    (void)BSL_SAL_AtomicDownReferences(&ctx->references, &ret);
    if (ret > 0) {
        return;
    }

    if (ctx->store != NULL) {
        BSL_LIST_FREE(ctx->store, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    if (ctx->crl != NULL) {
        BSL_LIST_FREE(ctx->crl, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    }

    BSL_SAL_ReferencesFree(&ctx->references);
    BSL_SAL_Free(ctx);
}
#ifdef HITLS_PKI_X509_VFY_CB
static int32_t HITLS_X509_VerifyCbkMock(int32_t errcode, HITLS_X509_StoreCtx *storeCtx)
{
    (void)storeCtx;
    return errcode;
}
#endif

HITLS_X509_StoreCtx *HITLS_X509_NewStoreCtxMock(void)
{
    HITLS_X509_StoreCtx *ctx = (HITLS_X509_StoreCtx *)BSL_SAL_Malloc(sizeof(HITLS_X509_StoreCtx));
    if (ctx == NULL) {
        return NULL;
    }

    (void)memset_s(ctx, sizeof(HITLS_X509_StoreCtx), 0, sizeof(HITLS_X509_StoreCtx));
    ctx->store = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (ctx->store == NULL) {
        BSL_SAL_Free(ctx);
        return NULL;
    }
    ctx->crl = BSL_LIST_New(sizeof(HITLS_X509_Crl *));
    if (ctx->crl == NULL) {
        BSL_SAL_FREE(ctx->store);
        BSL_SAL_Free(ctx);
        return NULL;
    }
    ctx->verifyParam.maxDepth = 20;
    ctx->verifyParam.securityBits = 128;
    ctx->verifyParam.flags |= HITLS_X509_VFY_FLAG_CRL_ALL;
    ctx->verifyParam.flags |= HITLS_X509_VFY_FLAG_SECBITS;
#ifdef HITLS_PKI_X509_VFY_CB
    ctx->verifyCb = HITLS_X509_VerifyCbkMock;
#endif
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

static int32_t HITLS_BuildChain(BslList *list, int type, char *path1, char *path2, char *path3, char *path4,
                                char *path5)
{
    int32_t ret;
    char *path[] = {path1, path2, path3, path4, path5};
    for (size_t i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
        if (path[i] == NULL) {
            continue;
        }
        if (type == 0) { // cert
            HITLS_X509_Cert *cert = NULL;
            ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path[i], &cert);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
            ret = BSL_LIST_AddElement(list, cert, BSL_LIST_POS_END);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        } else { // crl
            HITLS_X509_Crl *crl = NULL;
            ret = HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path[i], &crl);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
            ret = BSL_LIST_AddElement(list, crl, BSL_LIST_POS_END);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        }
    }
    return ret;
}

/* BEGIN_CASE */
void SDV_X509_STORE_VFY_PARAM_EXR_FUNC_TC001(char *path1, char *path2, char *path3, int secBits, int exp)
{
    int ret;
    TestMemInit();
    HITLS_X509_StoreCtx *storeCtx = NULL;
    storeCtx = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(storeCtx, NULL);
    storeCtx->verifyParam.securityBits = secBits;
    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ret = HITLS_BuildChain(chain, 0, path1, path2, path3, NULL, NULL);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_VerifyParamAndExt(storeCtx, chain);
    ASSERT_EQ(ret, exp);
    if (exp == HITLS_PKI_SUCCESS) {
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    HITLS_X509_FreeStoreCtxMock(storeCtx);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_VFY_CRL_FUNC_TC001(int type, int expResult, char *path1, char *path2, char *path3, char *crl1,
                                       char *crl2)
{
    int ret;
    TestMemInit();
    HITLS_X509_StoreCtx *storeCtx = NULL;
    storeCtx = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(storeCtx, NULL);
    if (type == 1) {
        storeCtx->verifyParam.flags ^= HITLS_X509_VFY_FLAG_CRL_ALL;
        storeCtx->verifyParam.flags |= HITLS_X509_VFY_FLAG_CRL_DEV;
    }

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ret = HITLS_BuildChain(chain, 0, path1, path2, path3, NULL, NULL);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_BuildChain(storeCtx->crl, 1, crl1, crl2, NULL, NULL, NULL);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_VerifyCrl(storeCtx, chain);
    ASSERT_EQ(ret, expResult);
    if (ret == HITLS_PKI_SUCCESS) {
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    HITLS_X509_FreeStoreCtxMock(storeCtx);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_CTRL_FUNC_TC001(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    int32_t val = 20;
    int32_t ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH, &val, sizeof(int32_t));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(store->verifyParam.maxDepth, val);
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_SECBITS, &val, sizeof(int32_t));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(store->verifyParam.securityBits, val);
    ASSERT_EQ(store->verifyParam.flags, HITLS_X509_VFY_FLAG_SECBITS);
    int64_t timeval = 55;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(store->verifyParam.time, timeval);
    ASSERT_EQ(store->verifyParam.flags & HITLS_X509_VFY_FLAG_TIME, HITLS_X509_VFY_FLAG_TIME);
    timeval = HITLS_X509_VFY_FLAG_TIME;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &timeval, sizeof(timeval));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(store->verifyParam.flags & HITLS_X509_VFY_FLAG_TIME, 0);
    ASSERT_EQ(store->verifyParam.flags, HITLS_X509_VFY_FLAG_SECBITS);
    int ref;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_REF_UP, &ref, sizeof(int));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(ref, 2);
    HITLS_X509_StoreCtxFree(store);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_CTRL_CERT_FUNC_TC002(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/asn1/rsa2048ssa-pss.crt", &cert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert, sizeof(HITLS_X509_Cert));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(cert->references.count, 2);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert, sizeof(HITLS_X509_Cert));
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
    HITLS_X509_Crl *crl = NULL;
    ret = HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, "../testdata/cert/asn1/ca-empty-rsa-sha256-v2.der", &crl);
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_CRL, crl, sizeof(HITLS_X509_Crl));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(crl->references.count, 2);
    ASSERT_EQ(BSL_LIST_COUNT(store->crl), 1);
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_CRL, crl, sizeof(HITLS_X509_Crl));
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

#ifdef HITLS_PKI_X509_VFY_CB
static int32_t X509StoreCtrlCbkSuc(int32_t err, HITLS_X509_StoreCtx *ctx)
{
    (void)ctx;
    (void)err;
    return HITLS_PKI_SUCCESS;
}
#endif

/* BEGIN_CASE */
void SDV_X509_STORE_CTRL_NEW_FIELDS_FUNC_TC003(void)
{
#ifdef HITLS_PKI_X509_VFY_CB
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);

    /* Test error field */
    int32_t errorVal = 12345;
    int32_t ret;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_ERROR, &errorVal, sizeof(int32_t)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(store->error, errorVal);

    int32_t getErrorVal = 0;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_ERROR, &getErrorVal, sizeof(int32_t)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(getErrorVal, errorVal);

    /* Test current field */
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/asn1/rsa2048ssa-pss.crt", &cert),
              HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *getCurrentCert = NULL;
    ASSERT_EQ(
        HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CUR_CERT, &getCurrentCert, sizeof(HITLS_X509_Cert *)),
        HITLS_PKI_SUCCESS);

    /* Test verify callback field */
    int32_t (*testCallback)(int32_t, HITLS_X509_StoreCtx*) = X509StoreCtrlCbkSuc;
    int32_t (*getCallback)(int32_t, HITLS_X509_StoreCtx*) = NULL;

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_VERIFY_CB, testCallback, sizeof(testCallback)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(store->verifyCb, testCallback);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_VERIFY_CB, &getCallback, sizeof(getCallback)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(getCallback, testCallback);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_USR_DATA, &ret, sizeof(void *)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(store->usrData, &ret);
    void *tmp = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_USR_DATA, &tmp, sizeof(void *)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(tmp, &ret);

    /* Test current depth field */
    int32_t depthVal = 5;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_CUR_DEPTH, &depthVal, sizeof(int32_t)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(store->curDepth, depthVal);

    int32_t getDepthVal = 0;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CUR_DEPTH, &getDepthVal, sizeof(int32_t)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(getDepthVal, depthVal);
    ASSERT_TRUE(TestIsErrStackEmpty());

    /* Test invalid parameters */
    ASSERT_NE(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_ERROR, &errorVal, sizeof(int32_t) - 1),
              HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_ERROR, &getErrorVal, sizeof(int32_t) - 1),
              HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(cert);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_CTRL_NEW_FIELDS_INVALID_FUNC_TC004(void)
{
#ifdef HITLS_PKI_X509_VFY_CB
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);

    /* Test with NULL parameters */
    ASSERT_NE(HITLS_X509_StoreCtxCtrl(NULL, HITLS_X509_STORECTX_SET_ERROR, NULL, 0), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_ERROR, NULL, sizeof(int32_t)), HITLS_PKI_SUCCESS);

    ASSERT_NE(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_USR_DATA, NULL, 0), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_USR_DATA, NULL, sizeof(int32_t)),
              HITLS_PKI_SUCCESS);

    /* Test with invalid command */
    int32_t val = 0;
    ASSERT_NE(HITLS_X509_StoreCtxCtrl(store, 999, &val, sizeof(int32_t)), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_StoreCtxFree(store);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

static int32_t HITLS_AddCertToStoreTest(char *path, HITLS_X509_StoreCtx *store, HITLS_X509_Cert **cert)
{
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, path, cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, *cert, sizeof(HITLS_X509_Cert));
}

static int32_t HITLS_AddCrlToStoreTest(char *path, HITLS_X509_StoreCtx *store, HITLS_X509_Crl **crl)
{
    int32_t ret = HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN, path, crl);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_CRL, *crl, sizeof(HITLS_X509_Crl));
}

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC001(char *rootPath, char *caPath, char *cert, char *crlPath)
{
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_StoreCtx *store = NULL;
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_List *chain = NULL;
    int64_t timeval = time(NULL);
    int64_t flag = HITLS_X509_VFY_FLAG_CRL_ALL;
    bool withIntCa = strlen(caPath) > 0;

    TestMemInit();

    store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);

    ASSERT_EQ(HITLS_AddCertToStoreTest(rootPath, store, &root), HITLS_PKI_SUCCESS);
    if (withIntCa) {
        ASSERT_EQ(HITLS_AddCertToStoreTest(caPath, store, &ca), HITLS_PKI_SUCCESS);
    }

    ASSERT_TRUE(HITLS_AddCertToStoreTest(cert, store, &entity) != HITLS_PKI_SUCCESS);
    TestErrClear();
    ASSERT_EQ(HITLS_AddCrlToStoreTest(crlPath, store, &crl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(BSL_LIST_COUNT(store->crl), 1);
    if (withIntCa) {
        ASSERT_EQ(BSL_LIST_COUNT(store->store), 2);
    } else {
        ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);
    }
    ASSERT_TRUE(HITLS_X509_CertChainBuild(store, false, entity, &chain) == HITLS_PKI_SUCCESS);
    if (withIntCa) {
        ASSERT_EQ(BSL_LIST_COUNT(chain), 2);
    } else {
        ASSERT_EQ(BSL_LIST_COUNT(chain), 1);
    }
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval)), 0);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &flag, sizeof(flag)), 0);
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    HITLS_X509_CrlFree(crl);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC002(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *ca = NULL;
    int32_t ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/inter.der", store, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *entity = NULL;
    ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/end.der", store, &entity);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
    TestErrClear();
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);
    HITLS_X509_List *chain = NULL;
    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_TRUE(ret == HITLS_PKI_SUCCESS);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_Cert *root = NULL;
    ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/ca.der", store, &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 2);
    int64_t timeval = time(NULL);
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

static int32_t X509_AddCertToChainTest(HITLS_X509_List *chain, HITLS_X509_Cert *cert)
{
    int ref;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_LIST_AddElement(chain, cert, BSL_LIST_POS_END);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_CertFree(cert);
    }
    return ret;
}

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC003(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *root = NULL;
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/ca.der", &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/inter.der", store, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *entity = NULL;
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/end.der", &entity);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);
    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(chain != NULL);
    ret = X509_AddCertToChainTest(chain, entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = X509_AddCertToChainTest(chain, ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC004(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *root = NULL;
    int32_t ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/ca.der", store, &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);
    HITLS_X509_List *chain = NULL;
    ret = HITLS_X509_CertChainBuild(store, false, root, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(chain != NULL);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 1);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC005(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *root = NULL;
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/ca.der", &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 0);
    HITLS_X509_List *chain = NULL;
    ret = HITLS_X509_CertChainBuild(store, false, root, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(chain != NULL);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 1);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC006(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *root = NULL;
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/ca.der", &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 0);
    HITLS_X509_List *chain = NULL;
    ret = HITLS_X509_CertChainBuild(store, false, root, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(chain != NULL);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 1);
    int64_t timeval = 5555;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC007(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *root = NULL;
    int32_t ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-v3/rootca.der", store, &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *ca = NULL;
    ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-v3/ca.der", store, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *entity = NULL;
    ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-v3/cert.der", store, &entity);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
    TestErrClear();
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 2);
    int32_t depth = 2;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH, &depth, sizeof(depth));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_List *chain = NULL;
    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_TRUE(ret == HITLS_PKI_SUCCESS);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(chain != NULL);
    ret = X509_AddCertToChainTest(chain, entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    int64_t timeval = time(NULL);
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

#ifdef HITLS_PKI_X509_VFY_CB
#define HITLS_X509_CBK_ERR (-1)

static int32_t X509_STORECTX_VerifyCb1(int32_t err, HITLS_X509_StoreCtx *ctx)
{
    (void)ctx;
    switch (err) {
        case HITLS_X509_ERR_VFY_SKI_NOT_FOUND:
        case HITLS_X509_ERR_VFY_GET_NOTBEFORE_FAIL:
        case HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE:
        case HITLS_X509_ERR_VFY_GET_NOTAFTER_FAIL:
        case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
        case HITLS_X509_ERR_VFY_GET_THISUPDATE_FAIL:
        case HITLS_X509_ERR_VFY_THISUPDATE_IN_FUTURE:
        case HITLS_X509_ERR_VFY_GET_NEXTUPDATE_FAIL:
        case HITLS_X509_ERR_VFY_NEXTUPDATE_EXPIRED:
        case HITLS_X509_ERR_VFY_CRLSIGN_FAIL:
        case HITLS_X509_ERR_VFY_CERT_SIGN_FAIL:
        case HITLS_X509_ERR_VFY_GET_PUBKEY_SIGNID:
        case HITLS_X509_ERR_VFY_CRL_NOT_FOUND:
        case HITLS_X509_ERR_VFY_CERT_REVOKED:
        default:
            return 0;
    }
}

static int32_t X509_STORECTX_VerifyCb2(int32_t err, HITLS_X509_StoreCtx *ctx)
{
    (void)ctx;
    if (err != 0) {
        return err;
    }
    return HITLS_X509_CBK_ERR;
}

static int32_t X509_STORECTX_VerifyCb3(int32_t err, HITLS_X509_StoreCtx *ctx)
{
    (void)ctx;
    if (err == HITLS_X509_ERR_CHAIN_DEPTH_UP_LIMIT) {
        return 0;
    }
    return err;
}

static int32_t X509StoreCtrlCbk(HITLS_X509_StoreCtx *store, int cbkflag)
{
    if (cbkflag == 0) {
        return HITLS_PKI_SUCCESS;
    }
    X509_STORECTX_VerifyCb cbk = NULL;
    if (cbkflag == 1) {
        cbk = X509_STORECTX_VerifyCb1;
    } else {
        cbk = X509_STORECTX_VerifyCb2;
    }

    return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_VERIFY_CB, cbk, sizeof(X509_STORECTX_VerifyCb));
}
#endif

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC008(char *rootPath, char *caPath, char *cert, char *rootcrlpath, char *cacrlpath,
                                          int flag, int cbk, int except)
{
    TestMemInit();
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *root = NULL;
    int32_t ret = HITLS_AddCertToStoreTest(rootPath, store, &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *ca = NULL;
    ret = HITLS_AddCertToStoreTest(caPath, store, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *entity = NULL;
    ret = HITLS_AddCertToStoreTest(cert, store, &entity);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
    TestErrClear();
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 2);
    HITLS_X509_Crl *rootcrl = NULL;
    if (strlen(rootcrlpath) != 0) {
        ret = HITLS_AddCrlToStoreTest(rootcrlpath, store, &rootcrl);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    }
    HITLS_X509_Crl *cacrl = NULL;
    ret = HITLS_AddCrlToStoreTest(cacrlpath, store, &cacrl);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    if (strlen(rootcrlpath) == 0) {
        ASSERT_EQ(BSL_LIST_COUNT(store->crl), 1);
    } else {
        ASSERT_EQ(BSL_LIST_COUNT(store->crl), 2);
    }
#ifndef HITLS_PKI_X509_VFY_CB
    if (cbk != 0) {
        goto EXIT;
    }
#else
    ASSERT_EQ(X509StoreCtrlCbk(store, cbk), HITLS_PKI_SUCCESS);
#endif

    int32_t depth = 3;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH, &depth, sizeof(depth));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_List *chain = NULL;
    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    int64_t setFlag = (int64_t)flag;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_FLAGS, &setFlag, sizeof(int64_t));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    int64_t timeval = time(NULL);
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_TRUE(ret == except);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    HITLS_X509_CrlFree(rootcrl);
    HITLS_X509_CrlFree(cacrl);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC009(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
    TestErrClear();
    HITLS_X509_Cert *root = NULL;
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/ca.der", &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = X509_AddCertToChainTest(chain, root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElementInt(chain, NULL, BSL_LIST_POS_BEGIN);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_WITH_ROOT_FUNC_TC001(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *entity = NULL;
    int32_t ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-v3/cert.der", store, &entity);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 0);
    HITLS_X509_Cert *ca = NULL;
    ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-v3/ca.der", store, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);
    HITLS_X509_List *chain = NULL;
    ret = HITLS_X509_CertChainBuild(store, true, entity, &chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
    HITLS_X509_Cert *root = NULL;
    ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-v3/rootca.der", store, &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 2);
    ret = HITLS_X509_CertChainBuild(store, true, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 3);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_SM2_CERT_USERID_FUNC_TC001(char *caCertPath, char *interCertPath, char *entityCertPath,
                                         int isUseDefaultUserId)
{
    TestMemInit();
    TestRandInit();
    HITLS_X509_Cert *entityCert = NULL;
    HITLS_X509_Cert *interCert = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_List *chain = NULL;
    char sm2DefaultUserid[] = "1234567812345678";
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_NE(storeCtx, NULL);
    ASSERT_EQ(HITLS_AddCertToStoreTest(caCertPath, storeCtx, &caCert), 0);
    ASSERT_EQ(HITLS_AddCertToStoreTest(interCertPath, storeCtx, &interCert), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, entityCertPath, &entityCert), 0);
    ASSERT_EQ(BSL_LIST_COUNT(storeCtx->store), 2);
    if (isUseDefaultUserId != 0) {
        ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_VFY_SM2_USERID, sm2DefaultUserid,
                                          strlen(sm2DefaultUserid)),
                  0);
    }
    ASSERT_EQ(HITLS_X509_CertChainBuild(storeCtx, false, entityCert, &chain), 0);
    ASSERT_EQ(HITLS_X509_CertVerify(storeCtx, chain), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_CertFree(entityCert);
    HITLS_X509_CertFree(interCert);
    HITLS_X509_CertFree(caCert);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_LOAD_CA_PATH_FUNC_TC001(void)
{
    TestMemInit();
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_NE(storeCtx, NULL);

    // Test adding additional CA path
    const char *testPath1 = "/usr/local/ssl/certs";
    int32_t ret =
        HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH, (void *)testPath1, strlen(testPath1));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_StoreCtxCtrl(NULL, HITLS_X509_STORECTX_ADD_CA_PATH, (void *)testPath1, strlen(testPath1));
    ASSERT_EQ(ret, HITLS_X509_ERR_INVALID_PARAM);

    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH, NULL, strlen(testPath1));
    ASSERT_EQ(ret, HITLS_X509_ERR_INVALID_PARAM);

    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH, (void *)testPath1, 0);
    ASSERT_EQ(ret, HITLS_X509_ERR_INVALID_PARAM);

    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH, (void *)testPath1, 4097);
    ASSERT_EQ(ret, HITLS_X509_ERR_INVALID_PARAM);

EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_LOAD_CA_PATH_CHAIN_BUILD_TC001(void)
{
    TestMemInit();
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_NE(storeCtx, NULL);

    // Add additional CA paths
    const char *caPath = "../testdata/tls/certificate/pem/rsa_sha256";
    int32_t ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH, (void *)caPath, strlen(caPath));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Load the certificate to be verified
    const char *certToVerify = "../testdata/tls/certificate/pem/rsa_sha256/client.pem";
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certToVerify, &cert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Build certificate chain with on-demand CA loading from multiple paths
    ret = HITLS_X509_CertChainBuild(storeCtx, true, cert, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(chain, NULL);

    uint32_t chainLength = BSL_LIST_COUNT(chain);
    ASSERT_TRUE(chainLength >= 1);

    // Verify the certificate chain
    ret = HITLS_X509_CertVerify(storeCtx, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_LOAD_CA_PATH_CHAIN_BUILD_TC002(void)
{
    TestMemInit();
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_NE(storeCtx, NULL);

    // Add additional CA paths
    const char *caPath = "../testdata/tls/certificate/pem/ed25519";
    int32_t ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH, (void *)caPath, strlen(caPath));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Load the certificate to be verified
    const char *certToVerify = "../testdata/tls/certificate/pem/rsa_sha256/client.pem";
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certToVerify, &cert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    // Build certificate chain with on-demand CA loading from multiple paths
    ret = HITLS_X509_CertChainBuild(storeCtx, true, cert, &chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
    ASSERT_EQ(chain, NULL);
EXIT:
    HITLS_X509_CertFree(cert);
    HITLS_X509_StoreCtxFree(storeCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_LOAD_CA_PATH_CHAIN_BUILD_TC003(void)
{
    TestMemInit();
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_NE(storeCtx, NULL);

    // Add additional CA paths
    const char *caPath = "../testdata/tls/certificate/pem/test_dir";
    int32_t ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH, (void *)caPath, strlen(caPath));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Load the certificate to be verified
    const char *certToVerify = "../testdata/tls/certificate/pem/rsa_sha256/client.pem";
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certToVerify, &cert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Build certificate chain with on-demand CA loading from multiple paths
    ret = HITLS_X509_CertChainBuild(storeCtx, true, cert, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(chain, NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_StoreCtxFree(storeCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_LOAD_CA_PATH_CHAIN_BUILD_TC004(void)
{
    TestMemInit();
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_NE(storeCtx, NULL);

    // Add additional CA paths
    const char *caPath = "../testdata/tls/certificate/pem/test_dir";
    int32_t ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH, (void *)caPath, strlen(caPath));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Load the certificate to be verified
    const char *certToVerify = "../testdata/tls/certificate/pem/ecdsa_sha256/client.pem";

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certToVerify, &cert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Build certificate chain with on-demand CA loading from multiple paths
    ret = HITLS_X509_CertChainBuild(storeCtx, true, cert, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(chain, NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_StoreCtxFree(storeCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_CTRL_GET_CERT_CHAIN_FUNC_TC018(void)
{
#ifdef HITLS_PKI_X509_VFY_CB
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);

    // Test getting certificate chain when it's NULL (before verification)
    HITLS_X509_List *certChain = NULL;
    int32_t ret =
        HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &certChain, sizeof(HITLS_X509_List *));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(certChain, NULL);

    // Load test certificates to build a chain
    HITLS_X509_Cert *rootCert = NULL;
    HITLS_X509_Cert *leafCert = NULL;

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/asn1/rsa2048ssa-pss.crt", &rootCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/asn1/rsa2048ssa-pss.crt", &leafCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Add root certificate to store
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, rootCert, sizeof(HITLS_X509_Cert));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Create a certificate chain for verification
    HITLS_X509_List *inputChain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(inputChain != NULL);

    // Add leaf certificate to chain
    int ref;
    ret = HITLS_X509_CertCtrl(leafCert, HITLS_X509_REF_UP, &ref, sizeof(int));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(inputChain, leafCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    // Perform certificate verification (this should populate the certificate chain during verification)
    ret = HITLS_X509_CertVerify(store, inputChain);
    // Note: The verification may fail due to test certificate issues, but we're testing chain storage

    // Test getting the certificate chain after verification (should be NULL as it's cleared after verification)
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &certChain, sizeof(HITLS_X509_List *));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(certChain, NULL); // Chain is cleared after verification

    // Test invalid parameters
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &certChain, sizeof(HITLS_X509_List *) - 1);
    ASSERT_NE(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(ret, HITLS_X509_ERR_INVALID_PARAM);

    ret = HITLS_X509_StoreCtxCtrl(NULL, HITLS_X509_STORECTX_GET_CERT_CHAIN, &certChain, sizeof(HITLS_X509_List *));
    ASSERT_NE(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(ret, HITLS_X509_ERR_INVALID_PARAM);

    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, NULL, sizeof(HITLS_X509_List *));
    ASSERT_NE(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(ret, HITLS_X509_ERR_INVALID_PARAM);

    // Test with manually set certificate chain (simulate verification process)
    store->certChain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(store->certChain != NULL);

    // Add a certificate to the chain
    ret = HITLS_X509_CertCtrl(leafCert, HITLS_X509_REF_UP, &ref, sizeof(int));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElement(store->certChain, leafCert, BSL_LIST_POS_END);
    ASSERT_EQ(ret, BSL_SUCCESS);

    // Now test getting the certificate chain
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &certChain, sizeof(HITLS_X509_List *));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(certChain, store->certChain);
    ASSERT_TRUE(certChain != NULL);
    ASSERT_EQ(BSL_LIST_COUNT(certChain), 1);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(rootCert);
    HITLS_X509_CertFree(leafCert);
    BSL_LIST_FREE(inputChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

#ifdef HITLS_PKI_X509_VFY_CB
int32_t HITLS_X509_CheckCertTimeStub(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t depth)
{
    (void)depth;  // Parameter used by VFYCBK_FAIL_IF macro
    int64_t start = 0;
    int64_t end = 0;
    HITLS_X509_ValidTime *validTime = &cert->tbs.validTime;
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_TIME) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t ret = BSL_SAL_DateToUtcTimeConvert(&validTime->start, &start);
    VFYCBK_FAIL_IF(ret != BSL_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_GET_NOTBEFORE_FAIL);
    VFYCBK_FAIL_IF(start > storeCtx->verifyParam.time, storeCtx, cert, depth, HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE);
    if ((validTime->flag & BSL_TIME_AFTER_SET) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    ret = BSL_SAL_DateToUtcTimeConvert(&validTime->end, &end);
    VFYCBK_FAIL_IF(ret != BSL_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_GET_NOTAFTER_FAIL);
    VFYCBK_FAIL_IF(end < storeCtx->verifyParam.time, storeCtx, cert, depth, HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED);
    return HITLS_PKI_SUCCESS;
}

int32_t CheckCertTimeGetNotBefore(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t depth)
{
    cert->tbs.validTime.start.month = 13;
    return HITLS_X509_CheckCertTimeStub(storeCtx, cert, depth);
}

int32_t CheckCertTimeCheckNotBefore(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t depth)
{
    cert->tbs.validTime.start.year += 10;
    cert->tbs.validTime.end.year += 10;
    return HITLS_X509_CheckCertTimeStub(storeCtx, cert, depth);
}

int32_t CheckCertTimeGetNotAfter(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t depth)
{
    cert->tbs.validTime.end.month = 13;
    return HITLS_X509_CheckCertTimeStub(storeCtx, cert, depth);
}

int32_t CheckCertTimeCheckNotAfter(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t depth)
{
    cert->tbs.validTime.start.year -= 10;
    cert->tbs.validTime.end.year -= 10;
    return HITLS_X509_CheckCertTimeStub(storeCtx, cert, depth);
}

static void TestReplace(int flag)
{
    switch (flag) {
        case HITLS_X509_ERR_VFY_GET_NOTBEFORE_FAIL:
            STUB_REPLACE(HITLS_X509_CheckCertTime, CheckCertTimeGetNotBefore);
            return;
        case HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE:
            STUB_REPLACE(HITLS_X509_CheckCertTime, CheckCertTimeCheckNotBefore);
            return;
        case HITLS_X509_ERR_VFY_GET_NOTAFTER_FAIL:
            STUB_REPLACE(HITLS_X509_CheckCertTime, CheckCertTimeGetNotAfter);
            return;
        case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
            STUB_REPLACE(HITLS_X509_CheckCertTime, CheckCertTimeCheckNotAfter);
            return;
        default:
            return;
    }
}

static int32_t X509_STORECTX_VerifyCbStub2(int32_t err, HITLS_X509_StoreCtx *ctx)
{
    switch (err) {
        case HITLS_X509_ERR_VFY_GET_NOTBEFORE_FAIL:
        case HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE:
        case HITLS_X509_ERR_VFY_GET_NOTAFTER_FAIL:
        case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
        case HITLS_X509_ERR_VFY_GET_THISUPDATE_FAIL:
        case HITLS_X509_ERR_VFY_THISUPDATE_IN_FUTURE:
        case HITLS_X509_ERR_VFY_GET_NEXTUPDATE_FAIL:
        case HITLS_X509_ERR_VFY_NEXTUPDATE_EXPIRED:
            return err - HITLS_X509_ERR_TIME_EXPIRED + 1;
        case HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND:
            if (ctx->curDepth != 0 || ctx->curCert == NULL) {
                return -1;
            }
            return -2;
        default:
            return 0;
    }
}

static int32_t X509StoreCtrlCbk2(HITLS_X509_StoreCtx *store, int cbkflag)
{
    if (cbkflag == 0) {
        return HITLS_PKI_SUCCESS;
    }
    X509_STORECTX_VerifyCb cbk = NULL;
    switch (cbkflag) {
        case HITLS_X509_ERR_VFY_GET_NOTBEFORE_FAIL:
        case HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE:
        case HITLS_X509_ERR_VFY_GET_NOTAFTER_FAIL:
        case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
        case HITLS_X509_ERR_VFY_GET_THISUPDATE_FAIL:
        case HITLS_X509_ERR_VFY_THISUPDATE_IN_FUTURE:
        case HITLS_X509_ERR_VFY_GET_NEXTUPDATE_FAIL:
        case HITLS_X509_ERR_VFY_NEXTUPDATE_EXPIRED:
        case HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND:
            cbk = X509_STORECTX_VerifyCbStub2;
            break;
        default:
            return HITLS_PKI_SUCCESS;
    }
    return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_VERIFY_CB, cbk, sizeof(X509_STORECTX_VerifyCb));
}
#endif

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_CBK_FUNC_TC001(int flag, int ecp)
{
#ifdef HITLS_PKI_X509_VFY_CB
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *ca = NULL;
    if (flag != HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND) {
        ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/inter.der", store, &ca),
                  HITLS_PKI_SUCCESS);
    }
    HITLS_X509_Cert *entity = NULL;
    ASSERT_TRUE(HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/end.der", store, &entity) !=
                HITLS_PKI_SUCCESS);
    if (flag != HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND) {
        ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);
    }
    TestErrClear();
    HITLS_X509_List *chain = NULL;
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entity, &chain), HITLS_PKI_SUCCESS);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/ca.der", store, &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entity, &chain), HITLS_PKI_SUCCESS);
    if (flag != HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND) {
        ASSERT_EQ(BSL_LIST_COUNT(store->store), 2);
    }
    ASSERT_EQ(X509StoreCtrlCbk2(store, flag), HITLS_PKI_SUCCESS);
    int64_t timeval = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval)),
              HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    TestReplace(flag);
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), ecp);

EXIT:
    STUB_RESTORE(HITLS_X509_CheckCertTime);
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_GLOBAL_DeInit();
#else
    (void)flag;
    (void)ecp;
    SKIP_TEST();
#endif
}
/* END_CASE */

#ifdef HITLS_PKI_X509_VFY_CB
static int32_t X509StoreCbk3(int32_t err, HITLS_X509_StoreCtx *ctx)
{
    (void)ctx;
    if (err == HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND) {
        return 0;
    }
    return err;
}
static int32_t X509StoreCtrlCbk3(HITLS_X509_StoreCtx *store, int cbkflag)
{
    if (cbkflag == 0) {
        return HITLS_PKI_SUCCESS;
    }
    X509_STORECTX_VerifyCb cbk = X509StoreCbk3;
    return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_VERIFY_CB, cbk, sizeof(X509_STORECTX_VerifyCb));
}
#endif

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_CBK_FUNC_TC002(int flag, int ecp)
{
#ifdef HITLS_PKI_X509_VFY_CB
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *ca = NULL;
    if (flag != HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND) {
        ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/inter.der", store, &ca),
                  HITLS_PKI_SUCCESS);
    }
    HITLS_X509_Cert *entity = NULL;
    ASSERT_TRUE(HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/end.der", store, &entity) !=
                HITLS_PKI_SUCCESS);
    if (flag != HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND) {
        ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);
    }
    TestErrClear();
    HITLS_X509_List *chain = NULL;
    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/ca.der", store, &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entity, &chain), HITLS_PKI_SUCCESS);
    if (flag != HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND) {
        ASSERT_EQ(BSL_LIST_COUNT(store->store), 2);
    }
    ASSERT_EQ(X509StoreCtrlCbk3(store, flag), HITLS_PKI_SUCCESS);
    int64_t timeval = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval)),
              HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), ecp);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_GLOBAL_DeInit();
#else
    (void)flag;
    (void)ecp;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VERIFY_CERT_CHAIN_FUNC_TC001(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *entity = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/ca.der", store, &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/inter.der", store, &ca), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 2);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/end.der", &entity),
              HITLS_PKI_SUCCESS);
    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(chain != NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, entity), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, ca), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)ca->tbs.ext.extData;
    certExt->extFlags &= ~HITLS_X509_EXT_FLAG_BCONS;
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_X509_ERR_VFY_INVALID_CA);
    certExt->extFlags |= HITLS_X509_EXT_FLAG_BCONS;
    certExt->isCa = false;
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_X509_ERR_VFY_INVALID_CA);
    certExt->isCa = true;
    certExt->extFlags |= HITLS_X509_EXT_FLAG_KUSAGE;
    certExt->keyUsage &= ~HITLS_X509_EXT_KU_KEY_CERT_SIGN;
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_X509_ERR_VFY_KU_NO_CERTSIGN);
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_BUILD_MLDSA_CERT_CHAIN_FUNC_TC001(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *ca = NULL;
    int32_t ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/mldsa-v3/inter.crt", store, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *entity = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/mldsa-v3/end.crt", &entity),
              HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *entityWithInvalidKu = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
                                       "../testdata/cert/chain/mldsa-v3/end_with_invalid_key_usage.crt",
                                       &entityWithInvalidKu),
              HITLS_PKI_SUCCESS);
    HITLS_X509_List *chain = NULL;
    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_TRUE(ret == HITLS_PKI_SUCCESS);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/mldsa-v3/root.crt", store, &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entity, &chain), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_PKI_SUCCESS);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);

    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entityWithInvalidKu, &chain), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_TRUE(HITLS_X509_CertVerify(store, chain) != HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    HITLS_X509_CertFree(entityWithInvalidKu);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_BUILD_SLHDSA_CERT_CHAIN_FUNC_TC001(char *variant)
{
    char rootPath[256] = {0};
    char interPath[256] = {0};
    char endPath[256] = {0};
    int ret = snprintf_s(rootPath, sizeof(rootPath), sizeof(rootPath) - 1, "../testdata/cert/chain/slhdsa/%s/root.crt",
                         variant);
    ASSERT_TRUE(ret > 0);
    ret = snprintf_s(interPath, sizeof(interPath), sizeof(interPath) - 1, "../testdata/cert/chain/slhdsa/%s/inter.crt",
                     variant);
    ASSERT_TRUE(ret > 0);
    ret =
        snprintf_s(endPath, sizeof(endPath), sizeof(endPath) - 1, "../testdata/cert/chain/slhdsa/%s/end.crt", variant);
    ASSERT_TRUE(ret > 0);

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);

    // Step 1: Add intermediate CA to store
    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest(interPath, store, &inter), HITLS_PKI_SUCCESS);

    // Step 2: Parse end entity certificate
    HITLS_X509_Cert *entity = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, endPath, &entity), HITLS_PKI_SUCCESS);

    // Step 3: Build certificate chain (should succeed)
    HITLS_X509_List *chain = NULL;
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entity, &chain), HITLS_PKI_SUCCESS);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);

    // Step 4: Add root CA to store
    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest(rootPath, store, &root), HITLS_PKI_SUCCESS);

    // Step 5: Rebuild certificate chain (should contain full chain)
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entity, &chain), HITLS_PKI_SUCCESS);

    // Step 6: Verify certificate chain (should succeed)
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_PKI_SUCCESS);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);

    // Step 7: Test invalid key usage certificates (only for sha2_128s variant)
    if (strcmp(variant, "sha2_128s") == 0) {
        // Test 7a: Certificate with forbidden key usage (keyEncipherment)
        HITLS_X509_Cert *entityInvalidKu = NULL;
        char invalidKuPath[256];
        ret = snprintf_s(invalidKuPath, sizeof(invalidKuPath), sizeof(invalidKuPath) - 1,
                         "../testdata/cert/chain/slhdsa/%s/end_invalid_ku.crt", variant);
        ASSERT_TRUE(ret > 0);
        ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, invalidKuPath, &entityInvalidKu), HITLS_PKI_SUCCESS);

        ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entityInvalidKu, &chain), HITLS_PKI_SUCCESS);
        ASSERT_TRUE(TestIsErrStackEmpty());
        // Verification should fail due to forbidden keyEncipherment
        ASSERT_NE(HITLS_X509_CertVerify(store, chain), HITLS_PKI_SUCCESS);
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        HITLS_X509_CertFree(entityInvalidKu);

        // Test 7b: Certificate with missing required key usage
        HITLS_X509_Cert *entityMissingKu = NULL;
        char missingKuPath[256] = {0};
        ret = snprintf_s(missingKuPath, sizeof(missingKuPath), sizeof(missingKuPath) - 1,
                         "../testdata/cert/chain/slhdsa/%s/end_missing_ku.crt", variant);
        ASSERT_TRUE(ret > 0);
        ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, missingKuPath, &entityMissingKu), HITLS_PKI_SUCCESS);

        ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entityMissingKu, &chain), HITLS_PKI_SUCCESS);
        // Verification should fail due to missing required key usage
        ASSERT_TRUE(HITLS_X509_CertVerify(store, chain) != HITLS_PKI_SUCCESS);
        HITLS_X509_CertFree(entityMissingKu);
    }

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * @test SDV_X509_BUILD_MLKEM_CERT_CHAIN_FUNC_TC001
 * @title Test ML-KEM certificate chain build and verify
 * @precon ML-KEM certificate chain: root(ML-DSA-65) -> inter(ML-DSA-65) -> end(ML-KEM-768)
 * @brief
 *   1. Add intermediate CA to store
 *   2. Parse ML-KEM end entity certificate
 *   3. Build certificate chain
 *   4. Add root CA to store
 *   5. Rebuild and verify certificate chain
 *   6. Test invalid key usage (digitalSignature instead of keyEncipherment)
 *   7. Test missing key usage
 * @expect
 *   1. Certificate chain build should succeed
 *   2. Certificate chain verify should succeed for valid cert
 *   3. Certificate chain verify should fail for invalid keyUsage cert
 */
/* BEGIN_CASE */
void SDV_X509_BUILD_MLKEM_CERT_CHAIN_FUNC_TC001(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);

    // Step 1: Add intermediate CA to store
    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/mlkem/inter.crt", store, &inter), HITLS_PKI_SUCCESS);

    // Step 2: Parse ML-KEM end entity certificate
    HITLS_X509_Cert *entity = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/mlkem/end.crt", &entity),
              HITLS_PKI_SUCCESS);

    // Step 3: Build certificate chain (should succeed)
    HITLS_X509_List *chain = NULL;
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entity, &chain), HITLS_PKI_SUCCESS);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);

    // Step 4: Add root CA to store
    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/mlkem/root.crt", store, &root), HITLS_PKI_SUCCESS);

    // Step 5: Rebuild certificate chain (should contain full chain)
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entity, &chain), HITLS_PKI_SUCCESS);

    // Step 6: Verify certificate chain (should succeed)
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_PKI_SUCCESS);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * @test SDV_X509_VFY_MLKEM_KEYUSAGE_TC001
 * @title Test ML-KEM certificate keyUsage validation
 * @precon ML-KEM certificate chain with valid/invalid keyUsage certificates
 * @brief
 *   1. Test ML-KEM certificate with correct keyUsage (keyEncipherment only) - should pass
 *   2. Test ML-KEM certificate with invalid keyUsage (digitalSignature) - should fail
 *   3. Test ML-KEM certificate with missing keyUsage - behavior depends on implementation
 * @expect
 *   1. Valid keyUsage certificate verification succeeds
 *   2. Invalid keyUsage certificate verification fails with HITLS_X509_ERR_EXT_KU
 */
/* BEGIN_CASE */
void SDV_X509_VFY_MLKEM_KEYUSAGE_TC001(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);

    // Setup: Add CA certificates to store
    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/mlkem/inter.crt", store, &inter), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/chain/mlkem/root.crt", store, &root), HITLS_PKI_SUCCESS);

    // Test 1: Valid keyUsage (keyEncipherment only) - should pass
    HITLS_X509_Cert *entityValid = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/mlkem/end.crt", &entityValid),
              HITLS_PKI_SUCCESS);
    HITLS_X509_List *chain = NULL;
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entityValid, &chain), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_PKI_SUCCESS);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    chain = NULL;

    // Test 2: Invalid keyUsage (digitalSignature - forbidden for ML-KEM) - should fail
    HITLS_X509_Cert *entityInvalidKu = NULL;
    ASSERT_EQ(
        HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/mlkem/end_invalid_ku.crt", &entityInvalidKu),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entityInvalidKu, &chain), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    // According to draft-ietf-lamps-kyber-certificates-11 Section 5:
    // ML-KEM certificates MUST have keyEncipherment as the ONLY key usage
    // digitalSignature is forbidden, verification should fail
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_X509_ERR_EXT_KU);
    TestErrClear();
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    chain = NULL;

    // Test 3: Missing keyUsage - according to RFC 5280, keyUsage is OPTIONAL
    // If not present, no restrictions apply (verification should succeed)
    HITLS_X509_Cert *entityMissingKu = NULL;
    ASSERT_EQ(
        HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/mlkem/end_missing_ku.crt", &entityMissingKu),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertChainBuild(store, false, entityMissingKu, &chain), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(entityValid);
    HITLS_X509_CertFree(entityInvalidKu);
    HITLS_X509_CertFree(entityMissingKu);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

// root(pathLen=0);leaf->inter->root;non-self-issued intermediate CA appears → expected PATHLEN_EXCEEDED
/* BEGIN_CASE */
void SDV_X509_VFY_PATHLEN_FAIL_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-v3/rootca.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-v3/ca.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-v3/cert.der", &leaf),
              HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf,  BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root,  BSL_LIST_POS_END), BSL_SUCCESS);

    // Set root BasicConstraints: isCa=true, maxPathLen=0
    HITLS_X509_CertExt *ext = (HITLS_X509_CertExt *)root->tbs.ext.extData;
    ASSERT_TRUE(ext != NULL);
    ext->extFlags  |= HITLS_X509_EXT_FLAG_BCONS;
    ext->isCa       = true;
    ext->maxPathLen = 0;

    // Put the same root into the truststore (it must come from the store to be a "trusted root")
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    // Disable strong CRL verification to avoid premature failure without CRL
    int64_t clr = (int64_t)HITLS_X509_VFY_FLAG_CRL_ALL;
#ifdef HITLS_X509_VFY_FLAG_CRL_DEV
    clr |= (int64_t)HITLS_X509_VFY_FLAG_CRL_DEV;
#endif
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clr,
        sizeof(clr)), HITLS_PKI_SUCCESS);

    // Disable security bit check (SECBITS) to avoid being intercepted before pathLen/EKU
    int64_t clrSec = (int64_t)HITLS_X509_VFY_FLAG_SECBITS;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clrSec,
        sizeof(clrSec)), HITLS_PKI_SUCCESS);

    // Set the time
    int64_t now = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    // Inter(CA) fails even when pathLen=0
    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_PATHLEN_EXCEEDED);

    // Release the internally constructed certChain to avoid leakage
    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built,
        sizeof(built)), HITLS_PKI_SUCCESS);
    if (built) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

EXIT:
    HITLS_X509_FreeStoreCtxMock(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

// root(pathLen=1),leaf->inter->root, allow 1 "non-self-issued intermediate CA", expect verification to succeed
/* BEGIN_CASE */
void SDV_X509_VFY_PATHLEN_PASS_TC002(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-v3/rootca.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-v3/ca.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-v3/cert.der", &leaf),
              HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf,  BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root,  BSL_LIST_POS_END), BSL_SUCCESS);

    HITLS_X509_CertExt *ext = (HITLS_X509_CertExt *)root->tbs.ext.extData;
    ASSERT_TRUE(ext != NULL);
    ext->extFlags  |= HITLS_X509_EXT_FLAG_BCONS;
    ext->isCa       = true;
    ext->maxPathLen = 1;

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t clr = (int64_t)HITLS_X509_VFY_FLAG_CRL_ALL;
#ifdef HITLS_X509_VFY_FLAG_CRL_DEV
    clr |= (int64_t)HITLS_X509_VFY_FLAG_CRL_DEV;
#endif
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clr, sizeof(clr)),
              HITLS_PKI_SUCCESS);
    int64_t clrSec = (int64_t)HITLS_X509_VFY_FLAG_SECBITS;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clrSec, sizeof(clrSec)),
              HITLS_PKI_SUCCESS);

    int64_t now = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_FreeStoreCtxMock(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

// root(maxPathLen = -1) is considered "unlimited" ,should pass
/* BEGIN_CASE */
void SDV_X509_VFY_PATHLEN_UNLIMITED_PASS_TC003(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/ca.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/inter.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/end.der", &leaf),
              HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf,  BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root,  BSL_LIST_POS_END), BSL_SUCCESS);

    HITLS_X509_CertExt *ext = (HITLS_X509_CertExt *)root->tbs.ext.extData;
    ASSERT_TRUE(ext != NULL);
    ext->extFlags  |= HITLS_X509_EXT_FLAG_BCONS;
    ext->isCa       = true;
    ext->maxPathLen = -1;

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t clr = (int64_t)HITLS_X509_VFY_FLAG_CRL_ALL;
#ifdef HITLS_X509_VFY_FLAG_CRL_DEV
    clr |= (int64_t)HITLS_X509_VFY_FLAG_CRL_DEV;
#endif
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clr, sizeof(clr)),
              HITLS_PKI_SUCCESS);
    int64_t clrSec = (int64_t)HITLS_X509_VFY_FLAG_SECBITS;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clrSec, sizeof(clrSec)),
              HITLS_PKI_SUCCESS);

    int64_t now = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_FreeStoreCtxMock(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* Ensure pathLenConstraint is rejected when the issuing CA lacks keyCertSign per RFC 5280. */
/* BEGIN_CASE */
void SDV_X509_VFY_PATHLEN_KEYCERTSIGN_MISSING_FAIL_TC004(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/anyEKU/rootca.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/anyEKU/ca.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/anyEKU/anyeku_good.der",
        &leaf), HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root, BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t clr = (int64_t)HITLS_X509_VFY_FLAG_CRL_ALL;
#ifdef HITLS_X509_VFY_FLAG_CRL_DEV
    clr |= (int64_t)HITLS_X509_VFY_FLAG_CRL_DEV;
#endif
#ifdef HITLS_X509_VFY_FLAG_OCSP
    clr |= (int64_t)HITLS_X509_VFY_FLAG_OCSP;
#endif
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clr, sizeof(clr)),
              HITLS_PKI_SUCCESS);

    int64_t clrSec = (int64_t)HITLS_X509_VFY_FLAG_SECBITS;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clrSec, sizeof(clrSec)),
              HITLS_PKI_SUCCESS);

    int64_t now = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    HITLS_X509_CertExt *interExt = (HITLS_X509_CertExt *)inter->tbs.ext.extData;
    ASSERT_TRUE(interExt != NULL);
    interExt->extFlags |= HITLS_X509_EXT_FLAG_BCONS;
    interExt->isCa = true;
    interExt->extFlags |= HITLS_X509_EXT_FLAG_KUSAGE;
    interExt->keyUsage &= ~HITLS_X509_EXT_KU_KEY_CERT_SIGN;

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_KU_NO_CERTSIGN);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

EXIT:
    HITLS_X509_FreeStoreCtxMock(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

// Leaf: client_good.der (EKU=clientAuth, KU includes digitalSignature) → TLS_CLIENT should pass
/* BEGIN_CASE */
void SDV_X509_VFY_TLS_CLIENT_KU_EKU_BOTH_MATCH_PASS_TC01(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/rootca.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/ca.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/client_good.der", &leaf),
              HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf,  BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root,  BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    /* Disable CRL/OCSP, SECBITS interference; set usage to TLS_SERVER; set time */
    int64_t clr = (int64_t)HITLS_X509_VFY_FLAG_CRL_ALL;
#ifdef HITLS_X509_VFY_FLAG_CRL_DEV
    clr |= (int64_t)HITLS_X509_VFY_FLAG_CRL_DEV;
#endif
#ifdef HITLS_X509_VFY_FLAG_OCSP
    clr |= (int64_t)HITLS_X509_VFY_FLAG_OCSP;
#endif
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clr, sizeof(clr)),
              HITLS_PKI_SUCCESS);

    int64_t clrSec = (int64_t)HITLS_X509_VFY_FLAG_SECBITS;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clrSec, sizeof(clrSec)),
              HITLS_PKI_SUCCESS);
    int32_t purpose = HITLS_X509_VFY_PURPOSE_TLS_CLIENT;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PURPOSE, &purpose, sizeof(purpose)),
              HITLS_PKI_SUCCESS);
    int64_t now = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_FreeStoreCtxMock(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

// Leaf: client_badku.der (EKU=clientAuth, but KU has no digitalSignature) → expect KU_UNMATCH
/* BEGIN_CASE */
void SDV_X509_VFY_TLS_CLIENT_EKU_ONLY_KU_MISSING_FAIL_TC02(void)
{
    TestMemInit();
    HITLS_X509_StoreCtx *store = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/rootca.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/ca.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/client_badku.der", &leaf),
              HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf,  BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root,  BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t clr = (int64_t)HITLS_X509_VFY_FLAG_CRL_ALL;
#ifdef HITLS_X509_VFY_FLAG_CRL_DEV
    clr |= (int64_t)HITLS_X509_VFY_FLAG_CRL_DEV;
#endif
#ifdef HITLS_X509_VFY_FLAG_OCSP
    clr |= (int64_t)HITLS_X509_VFY_FLAG_OCSP;
#endif
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clr, sizeof(clr)),
              HITLS_PKI_SUCCESS);

    int64_t clrSec = (int64_t)HITLS_X509_VFY_FLAG_SECBITS;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clrSec, sizeof(clrSec)),
              HITLS_PKI_SUCCESS);
    int32_t purpose = HITLS_X509_VFY_PURPOSE_TLS_CLIENT;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PURPOSE, &purpose, sizeof(purpose)),
              HITLS_PKI_SUCCESS);

    int64_t now = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_PURPOSE_UNMATCH);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

EXIT:
    HITLS_X509_FreeStoreCtxMock(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

// Leaf: server_good.der (EKU=serverAuth, KU includes digitalSignature, keyEncipherment) → TLS_SERVER should pass
/* BEGIN_CASE */
void SDV_X509_VFY_TLS_SERVER_KU_EKU_BOTH_MATCH_PASS_TC03(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/rootca.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/ca.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/server_good.der", &leaf),
              HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf,  BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root,  BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t clr = (int64_t)HITLS_X509_VFY_FLAG_CRL_ALL;
#ifdef HITLS_X509_VFY_FLAG_CRL_DEV
    clr |= (int64_t)HITLS_X509_VFY_FLAG_CRL_DEV;
#endif
#ifdef HITLS_X509_VFY_FLAG_OCSP
    clr |= (int64_t)HITLS_X509_VFY_FLAG_OCSP;
#endif
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clr, sizeof(clr)),
              HITLS_PKI_SUCCESS);

    int64_t clrSec = (int64_t)HITLS_X509_VFY_FLAG_SECBITS;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clrSec, sizeof(clrSec)),
              HITLS_PKI_SUCCESS);
    int32_t purpose = HITLS_X509_VFY_PURPOSE_TLS_SERVER;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PURPOSE, &purpose, sizeof(purpose)),
              HITLS_PKI_SUCCESS);

    int64_t now = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_FreeStoreCtxMock(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

// Leaf: server_badku.der (EKU=serverAuth, but KU=nonRepudiation) → expecting KU_UNMATCH
/* BEGIN_CASE */
void SDV_X509_VFY_TLS_SERVER_EKU_ONLY_KU_MISSING_FAIL_TC04(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/rootca.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/ca.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/server_badku.der", &leaf),
              HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf,  BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root,  BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t clr = (int64_t)HITLS_X509_VFY_FLAG_CRL_ALL;
#ifdef HITLS_X509_VFY_FLAG_CRL_DEV
    clr |= (int64_t)HITLS_X509_VFY_FLAG_CRL_DEV;
#endif
#ifdef HITLS_X509_VFY_FLAG_OCSP
    clr |= (int64_t)HITLS_X509_VFY_FLAG_OCSP;
#endif
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clr, sizeof(clr)),
              HITLS_PKI_SUCCESS);

    int64_t clrSec = (int64_t)HITLS_X509_VFY_FLAG_SECBITS;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clrSec, sizeof(clrSec)),
              HITLS_PKI_SUCCESS);
    int32_t purpose = HITLS_X509_VFY_PURPOSE_TLS_SERVER;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PURPOSE, &purpose, sizeof(purpose)),
              HITLS_PKI_SUCCESS);

    int64_t now = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_PURPOSE_UNMATCH);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

EXIT:
    HITLS_X509_FreeStoreCtxMock(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

// set any-purpose, certificate module does not verify any ext key usage of the certificate.
/* BEGIN_CASE */
void SDV_X509_VFY_ANYEKU_EKU_ALLOW_KU_MATCH_PASS_TC05(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/anyEKU/rootca.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/anyEKU/ca.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/anyEKU/anyeku_good.der",
        &leaf), HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf,  BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root,  BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t clr = (int64_t)HITLS_X509_VFY_FLAG_CRL_ALL;
#ifdef HITLS_X509_VFY_FLAG_CRL_DEV
    clr |= (int64_t)HITLS_X509_VFY_FLAG_CRL_DEV;
#endif
#ifdef HITLS_X509_VFY_FLAG_OCSP
    clr |= (int64_t)HITLS_X509_VFY_FLAG_OCSP;
#endif
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clr, sizeof(clr)),
              HITLS_PKI_SUCCESS);

    int64_t clrSec = (int64_t)HITLS_X509_VFY_FLAG_SECBITS;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clrSec, sizeof(clrSec)),
              HITLS_PKI_SUCCESS);
    int32_t purpose = HITLS_X509_VFY_PURPOSE_ANY;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PURPOSE, &purpose, sizeof(purpose)),
              HITLS_PKI_SUCCESS);

    int64_t now = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_FreeStoreCtxMock(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

// anyeku_badku.der: EKU=anyExtendedKeyUsage but KU=keyEncipherment(no digitalSignature) → expected KU_UNMATCH
/* BEGIN_CASE */
void SDV_X509_VFY_ANYEKU_KU_MISSING_FAIL_TC06(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/anyEKU/rootca.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/anyEKU/ca.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/eku_suite/anyEKU/anyeku_badku.der",
        &leaf), HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf,  BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root,  BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t clr = (int64_t)HITLS_X509_VFY_FLAG_CRL_ALL;
#ifdef HITLS_X509_VFY_FLAG_CRL_DEV
    clr |= (int64_t)HITLS_X509_VFY_FLAG_CRL_DEV;
#endif
#ifdef HITLS_X509_VFY_FLAG_OCSP
    clr |= (int64_t)HITLS_X509_VFY_FLAG_OCSP;
#endif
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clr, sizeof(clr)),
              HITLS_PKI_SUCCESS);

    int64_t clrSec = (int64_t)HITLS_X509_VFY_FLAG_SECBITS;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &clrSec, sizeof(clrSec)),
              HITLS_PKI_SUCCESS);
    int32_t purpose = HITLS_X509_VFY_PURPOSE_TLS_CLIENT;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PURPOSE, &purpose, sizeof(purpose)),
              HITLS_PKI_SUCCESS);
    int64_t now = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_PURPOSE_UNMATCH);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

EXIT:
    HITLS_X509_FreeStoreCtxMock(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * Construct a certificate chain, ensure that the validity period of all certificates covers the current system time,
 * call HITLS_X509_CertVerify for verification, which should pass successfully
 */
/* BEGIN_CASE */
void SDV_X509_VFY_CERT_TIME_CURRENT_PASS_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/root_current.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/inter_current.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/leaf_current.der", &leaf),
              HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root, BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_StoreCtxFree(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * Construct an expired certificate chain and set the verification parameter verifyParam.
 * time to a historical moment within the certificate's validity period. Verification should succeed.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_CERT_TIME_HISTORY_PASS_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/root_expired.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/inter_expired.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/leaf_expired.der", &leaf),
              HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root, BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t start = 0;
    int64_t end = 0;
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&leaf->tbs.validTime.start, &start), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&leaf->tbs.validTime.end, &end), BSL_SUCCESS);
    int64_t history = start + (end - start) / 2;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &history, sizeof(history)),
              HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * Using the same certificate chain, if the verification time is set to later than notAfter or
 * earlier than notBefore, the validator should reject the request and return a time-related error code.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_CERT_TIME_OUT_OF_RANGE_FAIL_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/root_expired.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/inter_expired.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/leaf_expired.der", &leaf),
              HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root, BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t start = 0;
    int64_t end = 0;
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&leaf->tbs.validTime.start, &start), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&leaf->tbs.validTime.end, &end), BSL_SUCCESS);

    int64_t before = start - 60;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &before, sizeof(before)),
              HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

    int64_t after = end + 60;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &after, sizeof(after)),
              HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED);

    built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

EXIT:
    HITLS_X509_StoreCtxFree(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

static int VerifyAtTime(HITLS_X509_StoreCtx *store, HITLS_X509_List *chain, int64_t t)
{
    int ret;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &t, sizeof(t));
    if (ret != HITLS_PKI_SUCCESS) {
        return -1;
    }

    ret = HITLS_X509_CertVerify(store, chain);
    if (ret != HITLS_PKI_SUCCESS) {
        return -1;
    }

    HITLS_X509_List *built = NULL;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built));
    if (ret != HITLS_PKI_SUCCESS) {
        return -1;
    }

    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    return HITLS_PKI_SUCCESS;
}
/**
 * Leaf certificate: verification time equal to notBefore/notAfter is treated as valid.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_CERT_TIME_BOUNDARY_PASS_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    HITLS_X509_List *chain = NULL;

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/root_expired.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/inter_expired.der", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/leaf_expired.der", &leaf),
              HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf),  HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root),  HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t start = 0;
    int64_t end   = 0;
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&leaf->tbs.validTime.start, &start), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&leaf->tbs.validTime.end,   &end),   BSL_SUCCESS);

    int vret = VerifyAtTime(store, chain, start);
    ASSERT_EQ(vret, HITLS_PKI_SUCCESS);

    vret = VerifyAtTime(store, chain, end);
    ASSERT_EQ(vret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(leaf);
}
/* END_CASE */

/**
 * Intermediate CA certificate: verification time equal to notBefore/notAfter is treated as valid.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_CERT_TIME_BOUNDARY_PASS_TC002(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_List *chain = NULL;

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/root_expired.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/inter_expired.der", &inter),
              HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t start = 0;
    int64_t end = 0;
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&inter->tbs.validTime.start, &start), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&inter->tbs.validTime.end, &end), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &start, sizeof(start)),
              HITLS_PKI_SUCCESS);
    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &end, sizeof(end)),
              HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(inter);
}
/* END_CASE */

/**
 * Root CA certificate: verification time equal to notBefore/notAfter is treated as valid.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_CERT_TIME_BOUNDARY_PASS_TC003(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_List *chain = NULL;

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/time/root_expired.der", &root),
              HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t start = 0;
    int64_t end = 0;
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&root->tbs.validTime.start, &start), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&root->tbs.validTime.end, &end), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &start, sizeof(start)),
              HITLS_PKI_SUCCESS);
    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &end, sizeof(end)),
              HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(root);
}
/* END_CASE */


/**
 * Constructing a certificate chain where the intermediate CA certificate contains an unsupported
 * but non-critical extension (e.g., Policy Mappings) and verifying the expected result succeeds.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_EXT_UNSUPPORTED_NONCRIT_EXT_PASS_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/ext/root_ext.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1,
        "../testdata/cert/chain/ext/inter_policy_noncrit.der", &inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1,
        "../testdata/cert/chain/ext/leaf_ext_via_noncrit.der", &leaf), HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root, BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * Constructing a certificate chain where the leaf certificate or intermediate CA certificate contains
 * an unsupported extension marked as critical (such as Policy Mappings) will result in verification failure.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_EXT_UNSUPPORTED_CRIT_EXT_FAIL_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/ext/root_ext.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1,
        "../testdata/cert/chain/ext/inter_policy_critical.der", &inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1,
        "../testdata/cert/chain/ext/leaf_ext_via_critical.der", &leaf), HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, leaf, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, inter, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, root, BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_PROCESS_CRITICALEXT);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

EXIT:
    HITLS_X509_StoreCtxFree(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * Construct a certificate chain that includes supported extensions (such as the Basic Constraints extension)
 * and tests them for cases where they are marked as critical and non-critical, respectively,
 * with the expectation that validation will succeed.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_EXT_SUPPORTED_EXT_PASS_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *leafNonCrit = NULL;
    HITLS_X509_Cert *leafCrit = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/ext/root_ext.der", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1,
        "../testdata/cert/chain/ext/leaf_support_noncrit.der", &leafNonCrit), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1,
        "../testdata/cert/chain/ext/leaf_support_critical.der", &leafCrit), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leafNonCrit), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    chain = NULL;

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leafCrit), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_CertFree(leafCrit);
    HITLS_X509_CertFree(leafNonCrit);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/**
 * Build a full trust anchor -> intermediate -> end-entity chain and verify binding succeeds.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_CERT_CHAIN_BINDING_PASS_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leaf = NULL;
    HITLS_X509_List *chain = NULL;

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/certVer/certVer_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/certVer/certVer_inter.pem", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/certVer/certVer_leaf.pem", &leaf),
              HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/**
 * The target certificate has a tampered signature and must fail signature verification.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_CERT_CHAIN_BINDING_FAIL_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *leafTampered = NULL;
    HITLS_X509_List *chain = NULL;

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/certVer/certVer_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/certVer/certVer_inter.pem", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_leaf_tampered.pem", &leafTampered), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leafTampered), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_CERT_SIGN_FAIL);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leafTampered);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/**
 * Target certificate is itself a CA; the verifier must still succeed for a valid chain.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_CA_CHAIN_BINDING_PASS_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *targetCa = NULL;
    HITLS_X509_List *chain = NULL;

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/certVer/certVer_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/certVer/certVer_inter.pem", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_target_ca.pem", &targetCa), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, targetCa), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(targetCa);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/**
 * Tampered CA target must fail signature verification even when chain building succeeds.
 */
/* BEGIN_CASE */
void SDV_X509_VFY_CA_CHAIN_BINDING_FAIL_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    HITLS_X509_Cert *targetCaTampered = NULL;
    HITLS_X509_List *chain = NULL;

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/certVer/certVer_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/certVer/certVer_inter.pem", &inter),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_target_ca_tampered.pem", &targetCaTampered), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
        root, sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, targetCaTampered), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_CERT_SIGN_FAIL);

    HITLS_X509_List *built = NULL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_GET_CERT_CHAIN, &built, sizeof(built)),
              HITLS_PKI_SUCCESS);
    if (built != NULL) {
        BSL_LIST_FREE(built, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        store->certChain = NULL;
    }

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(targetCaTampered);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_AKI_SKI_KEYID_PASS_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert)),
              HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_inter.pem", &inter),
              HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/aki_leaf_keymatch.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_AKI_SKI_KEYID_FAIL_TC002(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert)),
              HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_inter.pem", &inter),
              HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/aki_leaf_keymismatch.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_AKI_SKI_UPPER_SKI_MISSING_PASS_TC003(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert)),
              HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/aki_inter_noski.pem", &inter), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/aki_leaf_parent_noski_match.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_AKI_SKI_LOWER_AKI_MISSING_PASS_TC004(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert)),
              HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_inter.pem", &inter),
              HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/aki_leaf_noaki.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_AKI_SKI_ISSUER_SERIAL_FAIL_TC006(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert)),
              HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_inter.pem", &inter),
              HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/aki_leaf_issuer_serial_mismatch.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_AKI_SKI_CRITICAL_PASS_TC007(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert)),
              HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_inter.pem", &inter),
              HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/aki_leaf_critical.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_AKI_SKI_MULTILEVEL_PASS_TC008(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_root.pem", &root),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert)),
              HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "../testdata/cert/chain/akiski_suite/aki_inter.pem", &inter),
              HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *subinter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/aki_subinter.pem", &subinter), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/aki_leaf_multilevel.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, subinter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)), HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(subinter);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_NOAKID_CERT_PASS_TC009(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/root_cert.pem", &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/ca_cert.pem", &inter), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/akiski_suite/device_cert.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_BC_MISSING_FAIL_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/bc_root_general.pem", &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/bc_inter_missing_bc.pem", &inter), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/bc_leaf_missing_bc.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_INVALID_CA);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_BC_CA_FALSE_FAIL_TC002(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/bc_root_general.pem", &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/bc_inter_ca_false.pem", &inter), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/bc_leaf_ca_false.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_INVALID_CA);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_BC_PATHLEN_ROOT_LIMIT_FAIL_TC003(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/pathlen_root_pl1.pem", &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter1 = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/pathlen_inter_lvl1.pem", &inter1), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *inter2 = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/pathlen_inter_lvl2.pem", &inter2), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/pathlen_leaf_pl_exceed.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_PATHLEN_EXCEEDED);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter2);
    HITLS_X509_CertFree(inter1);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_BC_PATHLEN_MULTI_LIMIT_FAIL_TC004(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/pathlen_multi_root.pem", &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter1 = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/pathlen_multi_inter1.pem", &inter1), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *inter2 = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/pathlen_multi_inter2.pem", &inter2), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *inter3 = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/pathlen_multi_inter3.pem", &inter3), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/pathlen_multi_leaf.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter3), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_PATHLEN_EXCEEDED);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter3);
    HITLS_X509_CertFree(inter2);
    HITLS_X509_CertFree(inter1);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_DEPTH_CHAINLEN_PASS_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/depth_suite/depth_root.pem", &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int32_t maxDepth = 3;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH,
        &maxDepth, sizeof(maxDepth)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter1 = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/depth_suite/depth_inter1.pem", &inter1), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/depth_suite/depth_leaf_lvl1.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = NULL;
    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter1);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/**
 * @brief Test incomplete certificate chain with intermediate trusted CA
 */
/* BEGIN_CASE */
void SDV_X509_PARTIAL_CERT_VFY_FUNC_TC001(char *caCertPath, char *interCertPath, char *entityCertPath)
{
    (void) caCertPath;
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);

    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, entityCertPath, &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 1); // only device cert in chain

    ret = HITLS_AddCertToStoreTest(interCertPath, store, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);

    int64_t setFlag = HITLS_X509_VFY_FLAG_PARTIAL_CHAIN;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_FLAGS, &setFlag, sizeof(setFlag));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * @brief Test partial certificate chain with trusted root CA
*/
/* BEGIN_CASE */
void SDV_X509_PARTIAL_CERT_VFY_FUNC_TC002(char *caCertPath, char *interCertPath, char *entityCertPath)
{
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_Cert *interCa = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);

    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, entityCertPath, &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 1); // only device cert in chain

    ret = HITLS_AddCertToStoreTest(interCertPath, store, &interCa);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_AddCertToStoreTest(caCertPath, store, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    int64_t setFlag = HITLS_X509_VFY_FLAG_PARTIAL_CHAIN;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_FLAGS, &setFlag, sizeof(setFlag));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    // Even if a complete chain can be built, if PARTIAL_CHAIN open, it will still be a partial chain
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    HITLS_X509_CertFree(interCa);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_DEPTH_CHAINLEN_FAIL_TC002(void)
{
    TestMemInit();
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter1 = NULL;
    HITLS_X509_Cert *inter2 = NULL;
    HITLS_X509_Cert *leaf = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/depth_suite/depth_root.pem", &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    int32_t maxDepth = 3;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH,
        &maxDepth, sizeof(maxDepth)), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/depth_suite/depth_inter1.pem", &inter1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/depth_suite/depth_inter2.pem", &inter2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/bcExt/depth_suite/depth_leaf_lvl2.pem", &leaf), HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_CHAIN_DEPTH_UP_LIMIT);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter2);
    HITLS_X509_CertFree(inter1);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_SIGALG_RSA_ROOT_PASS_TC001(void)
{
    TestMemInit();
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *leaf = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/sigParam/rsa_root.pem", &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/sigParam/rsa_leaf.pem", &leaf), HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_SIGALG_TRUST_ANCHOR_ALG_MISMATCH_FAIL_TC002(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/sigParam/rsa_root.pem", &root), HITLS_PKI_SUCCESS);
    (void)memset_s(&root->signAlgId, sizeof(root->signAlgId), 0, sizeof(root->signAlgId));
    root->signAlgId.algId = BSL_CID_ECDSAWITHSHA256;
    (void)memset_s(&root->tbs.signAlgId, sizeof(root->tbs.signAlgId), 0, sizeof(root->tbs.signAlgId));
    root->tbs.signAlgId.algId = BSL_CID_ECDSAWITHSHA256;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/sigParam/rsa_leaf.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_SIGALG_RSA_PSS_PARAM_MISSING_FAIL_TC003(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/sigParam/rsa_pss_root.pem", &root), HITLS_PKI_SUCCESS);
    root->signAlgId.algId = BSL_CID_RSASSAPSS;
    root->signAlgId.rsaPssParam.saltLen = 0;
    root->signAlgId.rsaPssParam.mdId = CRYPT_MD_SHA1;
    root->signAlgId.rsaPssParam.mgfId = CRYPT_MD_SHA1;
    root->tbs.signAlgId.algId = BSL_CID_RSASSAPSS;
    root->tbs.signAlgId.rsaPssParam.saltLen = 0;
    root->tbs.signAlgId.rsaPssParam.mdId = CRYPT_MD_SHA1;
    root->tbs.signAlgId.rsaPssParam.mgfId = CRYPT_MD_SHA1;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/sigParam/rsa_pss_leaf.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_CERT_SIGN_FAIL);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_SIGALG_SM2_USERID_MISMATCH_FAIL_TC004(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/sigParam/sm2_root.pem", &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    const char *mismatchId = "sigparam-mismatch-id";
    uint32_t mismatchIdLen = (uint32_t)strlen(mismatchId);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_VFY_SM2_USERID,
        (void *)mismatchId, mismatchIdLen), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/sigParam/sm2_leaf.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_CERT_SIGN_FAIL);
    uint8_t *storeSm2UserId = NULL;

EXIT:
#ifdef HITLS_CRYPTO_SM2
    storeSm2UserId = (store != NULL) ? store->verifyParam.sm2UserId.data : NULL;
    if (leaf != NULL && leaf->signAlgId.algId == BSL_CID_SM2DSAWITHSM3 &&
        leaf->signAlgId.sm2UserId.data == storeSm2UserId) {
        /* Detach shared SM2 UserID before the store frees it to avoid double free */
        leaf->signAlgId.sm2UserId.data = NULL;
        leaf->signAlgId.sm2UserId.dataLen = 0;
    }
    if (root != NULL && root->signAlgId.algId == BSL_CID_SM2DSAWITHSM3 &&
        root->signAlgId.sm2UserId.data == storeSm2UserId) {
        root->signAlgId.sm2UserId.data = NULL;
        root->signAlgId.sm2UserId.dataLen = 0;
    }
#endif
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_CHAIN_SUBJECT_ISSUER_MISMATCH_FAIL_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_name_mismatch_root.pem", &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *wrongInter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_name_mismatch_wrong_inter.pem", &wrongInter), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_name_mismatch_leaf.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, wrongInter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(wrongInter);
    HITLS_X509_CertFree(root);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_TRUST_ANCHOR_NOT_FOUND_FAIL_TC002(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    HITLS_X509_Cert *fakeRoot = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_wrong_anchor_fake_root.pem", &fakeRoot), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, fakeRoot,
        sizeof(HITLS_X509_Cert)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_wrong_anchor_root.pem", &root), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *inter = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_wrong_anchor_inter.pem", &inter), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *leaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_wrong_anchor_leaf.pem", &leaf), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, leaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, inter), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, root), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_ROOT_CERT_NOT_FOUND);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(leaf);
    HITLS_X509_CertFree(inter);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(fakeRoot);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_VFY_CHAIN_LOOP_DEPTH_FAIL_TC001(void)
{
    TestMemInit();

    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    int32_t maxDepth = 4;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH,
        &maxDepth, sizeof(maxDepth)), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *loopLeaf = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_cycle_a.pem", &loopLeaf), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *loopIssuer = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_cycle_b.pem", &loopIssuer), HITLS_PKI_SUCCESS);

    HITLS_X509_Cert *loopRoot = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_cycle_a.pem", &loopRoot), HITLS_PKI_SUCCESS);

    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, loopLeaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, loopIssuer), HITLS_PKI_SUCCESS);
    /* Reuse the same certificate as both leaf and root to form a->b->a loop */
    ASSERT_EQ(X509_AddCertToChainTest(chain, loopRoot), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_CHAIN_DEPTH_UP_LIMIT);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(loopRoot);
    HITLS_X509_CertFree(loopIssuer);
    HITLS_X509_CertFree(loopLeaf);
}
/* END_CASE */

/**
 * @brief Test partial certificate verification, Although there is a root certificate, it is not in the trusted store
*/
/* BEGIN_CASE */
void SDV_X509_PARTIAL_CERT_VFY_FUNC_TC003(char *caCertPath, char *interCertPath, char *entityCertPath)
{
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *interCa = NULL;
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);

    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, entityCertPath, &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 1); // only device cert in chain

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, caCertPath, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    int ref = 0;
    ret = HITLS_X509_CertCtrl(ca, HITLS_X509_REF_UP, &ref, sizeof(int));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(chain, ca, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 2); // device cert and ca cert in chain

    ret = HITLS_AddCertToStoreTest(interCertPath, store, &interCa);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_ROOT_CERT_NOT_FOUND);

    int64_t setFlag = HITLS_X509_VFY_FLAG_PARTIAL_CHAIN;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_FLAGS, &setFlag, sizeof(setFlag));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    HITLS_X509_CertFree(interCa);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * @brief Test partial certificate verification, Trusted intermediate certificate comes from trusted directory
*/
/* BEGIN_CASE */
void SDV_X509_PARTIAL_CERT_VFY_FUNC_TC004(void)
{
    TestMemInit();
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_NE(storeCtx, NULL);

    // Load the certificate to be verified
    const char *certToVerify = "../testdata/tls/certificate/pem/rsa_sha256_no_ca/client.pem";
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certToVerify, &cert), HITLS_PKI_SUCCESS);

    // Build certificate chain with on-demand CA loading from multiple paths
    ASSERT_EQ(HITLS_X509_CertChainBuild(storeCtx, false, cert, &chain), HITLS_PKI_SUCCESS);
    ASSERT_NE(chain, NULL);

    uint32_t chainLength = BSL_LIST_COUNT(chain);
    ASSERT_TRUE(chainLength == 1);

    // Add additional CA paths
    const char *caPath = "../testdata/tls/certificate/pem/rsa_sha256_no_ca";
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH,
        (void *)caPath, strlen(caPath)), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertVerify(storeCtx, chain), HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);

    int64_t setFlag = HITLS_X509_VFY_FLAG_PARTIAL_CHAIN;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_PARAM_FLAGS, &setFlag, sizeof(setFlag)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertVerify(storeCtx, chain), HITLS_PKI_SUCCESS);

    BSL_LIST_FREE(storeCtx->caPaths, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);

    // The test has already cached the trust store
    setFlag = HITLS_X509_VFY_FLAG_PARTIAL_CHAIN;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &setFlag, sizeof(setFlag)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertVerify(storeCtx, chain), HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);

    setFlag = HITLS_X509_VFY_FLAG_PARTIAL_CHAIN;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_PARAM_FLAGS, &setFlag, sizeof(setFlag)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertVerify(storeCtx, chain), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/**
 * @brief Circular certificate chain, triggering infinite loop, but can exit normally
*/
/* BEGIN_CASE */
void SDV_X509_PARTIAL_CERT_VFY_FUNC_TC005(void)
{
    TestMemInit();
    HITLS_X509_Cert *loopLeaf = NULL;
    HITLS_X509_Cert *loopIssuer = NULL;
    HITLS_X509_Cert *loopRoot = NULL;
    HITLS_X509_List *chain = NULL;
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    int32_t maxDepth = 4;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH,
        &maxDepth, sizeof(maxDepth)), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_cycle_a.pem", &loopLeaf), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_cycle_b.pem", &loopIssuer), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/chain/certVer/certVer_cycle_a.pem", &loopRoot), HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, loopLeaf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, loopIssuer), HITLS_PKI_SUCCESS);
    /* Reuse the same certificate as both leaf and root to form a->b->a loop */
    ASSERT_EQ(X509_AddCertToChainTest(chain, loopRoot), HITLS_PKI_SUCCESS);

    int64_t now = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &now, sizeof(now)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    int32_t ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_CHAIN_DEPTH_UP_LIMIT);
    
    // Disable the maximum depth, triggering an infinite loop.
    int32_t (*testCallback)(int32_t, HITLS_X509_StoreCtx*) = X509_STORECTX_VerifyCb3;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_VERIFY_CB,
        testCallback, sizeof(testCallback)), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_X509_ERR_ROOT_CERT_NOT_FOUND);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    if (chain != NULL) {
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    HITLS_X509_CertFree(loopRoot);
    HITLS_X509_CertFree(loopIssuer);
    HITLS_X509_CertFree(loopLeaf);
}
/* END_CASE */

/**
 * @brief Test HITLS_X509_CertVerifyByPubKey:
 *        - Use issuer certificate's public key to verify end-entity certificate (success case)
 *        - Use an unrelated certificate's public key to verify the same certificate (fail case)
 */
/* BEGIN_CASE */
void SDV_X509_CERT_VERIFY_BY_PUBKEY_FUNC_TC001(char *CertPath, char *CertPathVerify, char *otherCertPath)
{
    TestMemInit();

    HITLS_X509_Cert *certTest = NULL;
    HITLS_X509_Cert *certVrtify = NULL;
    HITLS_X509_Cert *otherCert = NULL;

    /* Parse end-entity certificate, its issuer certificate, and an unrelated certificate */
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, CertPath, &certTest), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, CertPathVerify, &certVrtify), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, otherCertPath, &otherCert), HITLS_PKI_SUCCESS);

    /* Get public key contexts from issuer certificate and unrelated certificate via CertCtrl */
    CRYPT_EAL_PkeyCtx *issuerPubKey = NULL;
    CRYPT_EAL_PkeyCtx *otherPubKey = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(certVrtify, HITLS_X509_GET_PUBKEY, &issuerPubKey, sizeof(CRYPT_EAL_PkeyCtx *)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(otherCert, HITLS_X509_GET_PUBKEY, &otherPubKey, sizeof(CRYPT_EAL_PkeyCtx *)),
        HITLS_PKI_SUCCESS);
    ASSERT_NE(issuerPubKey, NULL);
    ASSERT_NE(otherPubKey, NULL);

    /* Positive case: verify end-entity certificate with issuer's public key */
    ASSERT_EQ(HITLS_X509_CertVerifyByPubKey(certTest, issuerPubKey), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    /* Negative case: verify the same end-entity certificate with an unrelated certificate's public key */
    ASSERT_NE(HITLS_X509_CertVerifyByPubKey(certTest, otherPubKey), HITLS_PKI_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(issuerPubKey);
    CRYPT_EAL_PkeyFreeCtx(otherPubKey);
    HITLS_X509_CertFree(certTest);
    HITLS_X509_CertFree(certVrtify);
    HITLS_X509_CertFree(otherCert);
}
/* END_CASE */

/**
 * @test   SDV_X509_CA_PATH_WITH_VARIOUS_CHARSET_FUNC_TC001
 * @title  Test X509 chain verification via CA path with various charsets.
 * @brief  1. Verify that parent and child certificates can be matched successfully
 *         when issuerName and AKI fields use different encoding types but identical content.
 *         2. Verify that certificate chain validation succeeds after name normalization
 *         (collapse consecutive spaces and case-insensitive match).
 *         3. Verify that chain validation fails when abnormal input causes encoding
 *         type conversion failure.
 * @expect 1. Certificate chain verification successful.
 *         2. Certificate chain verification successful.
 *         3. Issuer certificate not found.
 */
/* BEGIN_CASE */
void SDV_X509_CA_PATH_WITH_VARIOUS_CHARSET_FUNC_TC001(char *caPath, char *entityCertPath, int expectedResult)
{
    int32_t ret;
    HITLS_X509_StoreCtx *store = NULL;
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_List *chain = NULL;

    TestMemInit();
    store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_ADD_CA_PATH, (void *)caPath, strlen(caPath));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, entityCertPath, &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 1);

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, expectedResult);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * @test   SDV_X509_CERT_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC001
 * @title  Test X509 chain verification via store with various charsets.
 * @brief  1. Verify that parent and child certificates can be matched successfully
 *         when issuerName and AKI fields use different encoding types but identical content.
 *         2. Verify that certificate chain validation succeeds after name normalization
 *         (collapse consecutive spaces and case-insensitive match).
 * @expect 1. Certificate chain verification successful.
 *         2. Certificate chain verification successful.
 *         3. Issuer certificate not found.
 */
/* BEGIN_CASE */
void SDV_X509_CERT_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC001(char *caCertPath, char *entityCertPath, int expectedResult)
{
    int32_t ret;
    HITLS_X509_StoreCtx *store = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_List *chain = NULL;

    TestMemInit();
    store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    ret = HITLS_AddCertToStoreTest(caCertPath, store, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, entityCertPath, &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 1);

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, expectedResult);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * @test   SDV_X509_CERT_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC002
 * @title  Test X509 chain verification with intermediate CA using normalization.
 * @brief  Verify that certificate chain validation succeeds after name normalization
 *         (collapse consecutive spaces and case-insensitive match).
 * @expect Certificate chain verification successful.
 */
/* BEGIN_CASE */
void SDV_X509_CERT_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC002(char *rootCertPath, char *caCertPath, char *entityCertPath)
{
    int32_t ret;
    HITLS_X509_StoreCtx *store = NULL;
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_List *chain = NULL;

    TestMemInit();
    store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    ret = HITLS_AddCertToStoreTest(rootCertPath, store, &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, caCertPath, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, entityCertPath, &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(chain != NULL);
    ret = X509_AddCertToChainTest(chain, entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = X509_AddCertToChainTest(chain, ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    /* 2:include inter CA */
    ASSERT_EQ(BSL_LIST_COUNT(chain), 2);

    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * @test   SDV_X509_CRL_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC001
 * @title  Test X509 chain and CRL verification with various charsets.
 * @brief  1. Verify that certificates and CRL entries can be matched successfully
 *         when issuerName and AKI fields use different encoding types but identical content.
 *         2. Verify that CRL identification fails when abnormal input causes encoding
 *         type conversion failure.
 * @expect 1. CRL is matched successfully; if the CRL contains the end-entity certificate,
 *            the certificate is treated as revoked, otherwise certificate chain
 *            verification succeeds.
 *         2. Corresponding CRL not found.
 */
/* BEGIN_CASE */
void SDV_X509_CRL_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC001(char *caCertPath, char *entityCertPath,
    char *crlPath, int expectedResult)
{
    int32_t ret;
    HITLS_X509_StoreCtx *store = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_List *chain = NULL;

    TestMemInit();
    store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);

    ret = HITLS_AddCertToStoreTest(caCertPath, store, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_AddCrlToStoreTest(crlPath, store, &crl);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 1);
    ASSERT_EQ(BSL_LIST_COUNT(store->crl), 1);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, entityCertPath, &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 1);

    store->verifyParam.flags = HITLS_X509_VFY_FLAG_CRL_DEV;
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, expectedResult);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    HITLS_X509_CrlFree(crl);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */