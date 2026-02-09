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
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

static int32_t HITLS_BuildChain(BslList *list, int type,
    char *path1, char *path2, char *path3, char *path4, char *path5)
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
    BSL_GLOBAL_Init();
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
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_VFY_CRL_FUNC_TC001(int type, int expResult, char *path1, char *path2, char *path3,
    char *crl1, char *crl2)
{
    int ret;
    TestMemInit();
    BSL_GLOBAL_Init();
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
    BSL_GLOBAL_DeInit();
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
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_STORE_CTRL_CERT_FUNC_TC002(void)
{
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/asn1/rsa2048ssa-pss.crt", &cert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
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
    BSL_GLOBAL_DeInit();
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

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    HITLS_X509_CrlFree(crl);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_GLOBAL_DeInit();
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
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_GLOBAL_DeInit();
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
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_GLOBAL_DeInit();
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
    BSL_GLOBAL_DeInit();
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
    BSL_GLOBAL_DeInit();
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
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_GLOBAL_DeInit();
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
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_BUILD_CERT_CHAIN_FUNC_TC008(char *rootPath, char *caPath, char *cert, char *rootcrlpath, char *cacrlpath, int flag, int except)
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
    int32_t depth = 3;
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH, &depth, sizeof(depth));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_List *chain = NULL;
    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
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
    BSL_GLOBAL_DeInit();
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
    BSL_GLOBAL_DeInit();
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
    BSL_GLOBAL_DeInit();
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
            strlen(sm2DefaultUserid)), 0);
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
    
    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH,
                                  NULL, strlen(testPath1));
    ASSERT_EQ(ret, HITLS_X509_ERR_INVALID_PARAM);

    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH,
                                  (void *)testPath1, 0);
    ASSERT_EQ(ret, HITLS_X509_ERR_INVALID_PARAM);

    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH,
                                  (void *)testPath1, 4097);
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
 * @brief Test HITLS_X509_CheckTime with needAfterTime parameter:
 *        - CRL verification (needAfterTime=false): can skip afterTime check if flag is not set
 *        - Certificate verification (needAfterTime=true): must check afterTime even if flag is cleared
 */
/* BEGIN_CASE */
void SDV_X509_CHECK_TIME_NEED_AFTER_TIME_FUNC_TC001(char *caPath, char *userPath, char *crlPath)
{
    TestMemInit();
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *user = NULL;
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_List *chain = NULL;

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, caPath, &ca), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, ca, sizeof(HITLS_X509_Cert)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, userPath, &user), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN, crlPath, &crl), HITLS_PKI_SUCCESS);

    // Clear BSL_TIME_AFTER_SET flag from CRL
    crl->tbs.validTime.flag &= ~BSL_TIME_AFTER_SET;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_CRL, crl, sizeof(HITLS_X509_Crl)),
        HITLS_PKI_SUCCESS);
    // Clear BSL_TIME_AFTER_SET flag from user certificate
    user->tbs.validTime.flag &= ~BSL_TIME_AFTER_SET;

    // Set verification time to current time (cert and CRL are already expired)
    int64_t currentTime = (int64_t)time(NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &currentTime, sizeof(currentTime)),
        HITLS_PKI_SUCCESS);

    // Enable CRL verification
    uint64_t flag = HITLS_X509_VFY_FLAG_CRL_ALL;
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_FLAGS, &flag, sizeof(flag)),
        HITLS_PKI_SUCCESS);

    // Build certificate chain (add both user cert and CA to ensure CRL verification runs)
    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(X509_AddCertToChainTest(chain, user), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_AddCertToChainTest(chain, ca), HITLS_PKI_SUCCESS);

    // Step 1: Test CRL verification separately (should pass with needAfterTime=false)
    int32_t ret = HITLS_X509_VerifyCrl(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    // Step 2: Test full certificate verification (should fail with needAfterTime=true)
    // Expected: HITLS_X509_ERR_TIME_EXPIRED because cert afterTime check is enforced
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_X509_ERR_TIME_EXPIRED);

EXIT:
    HITLS_X509_StoreCtxFree(store);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(user);
    HITLS_X509_CrlFree(crl);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */
