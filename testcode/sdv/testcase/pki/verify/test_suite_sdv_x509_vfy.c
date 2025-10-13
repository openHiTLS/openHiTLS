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
#include "stub_replace.h"
#include "../../../../../pki/x509_verify/src/hitls_x509_verify.c"

/* END_HEADER */

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
    int32_t ret = HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, crl);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_CRL, *crl, sizeof(HITLS_X509_Crl));
}

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC001(char *rootPath, char *caPath, char *cert, char *crlPath)
{
    TestMemInit();
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(store != NULL);
    HITLS_X509_Cert *root = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest(rootPath, store, &root), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *ca = NULL;
    ASSERT_EQ(HITLS_AddCertToStoreTest(caPath, store, &ca), HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *entity = NULL;

    ASSERT_TRUE(HITLS_AddCertToStoreTest(cert, store, &entity) != HITLS_PKI_SUCCESS);
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_AddCrlToStoreTest(crlPath, store, &crl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(BSL_LIST_COUNT(store->crl), 1);
    ASSERT_EQ(BSL_LIST_COUNT(store->store), 2);
    HITLS_X509_List *chain = NULL;
    ASSERT_TRUE(HITLS_X509_CertChainBuild(store, false, entity, &chain) == HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(chain), 2);
    int64_t timeval = time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval)), 0);
    int64_t flag = HITLS_X509_VFY_FLAG_CRL_ALL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_CLR_PARAM_FLAGS, &flag, sizeof(flag)), 0);
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), HITLS_PKI_SUCCESS);

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
    HITLS_X509_Cert *root = NULL;
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/ca.der", &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = X509_AddCertToChainTest(chain, root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = BSL_LIST_AddElementInt(chain, NULL, BSL_LIST_POS_BEGIN);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
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

static void TestReplace(FuncStubInfo *stubInfo, int flag)
{
    switch (flag) {
        case HITLS_X509_ERR_VFY_GET_NOTBEFORE_FAIL:
            STUB_Replace(stubInfo, HITLS_X509_CheckCertTime, CheckCertTimeGetNotBefore);
            return;
        case HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE:
            STUB_Replace(stubInfo, HITLS_X509_CheckCertTime, CheckCertTimeCheckNotBefore);
            return;
        case HITLS_X509_ERR_VFY_GET_NOTAFTER_FAIL:
            STUB_Replace(stubInfo, HITLS_X509_CheckCertTime, CheckCertTimeGetNotAfter);
            return;
        case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
            STUB_Replace(stubInfo, HITLS_X509_CheckCertTime, CheckCertTimeCheckNotAfter);
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
    FuncStubInfo stubInfo = {0};
    STUB_Init();
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
    TestReplace(&stubInfo, flag);
    ASSERT_EQ(HITLS_X509_CertVerify(store, chain), ecp);

EXIT:
    STUB_Reset(&stubInfo);
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