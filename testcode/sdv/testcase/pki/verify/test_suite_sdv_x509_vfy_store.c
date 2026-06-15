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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "bsl_sal.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "bsl_init.h"
#include "hitls_pki_x509.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_store_local.h"
#include "hitls_x509_verify.h"
#include "hitls_cert_local.h"
#include "hitls_crl_local.h"
#include "bsl_list_internal.h"
#include "sal_atomic.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "bsl_uio.h"
#include "hitls_pki_utils.h"
#include "bsl_asn1.h"
#include "bsl_obj.h"
#include "bsl_err_internal.h"

/* END_HEADER */

static int32_t HITLS_AddCertToStoreTest(const char *certPath, HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert **cert)
{
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, certPath, cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, *cert, sizeof(HITLS_X509_Cert));
}

static int32_t HITLS_AddCrlToStoreTest(const char *crlPath, HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Crl **crl)
{
    int32_t ret = HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN, crlPath, crl);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_CRL, *crl, sizeof(HITLS_X509_Crl));
}

static int32_t HITLS_BuildChainFromFileTest(HITLS_X509_StoreCtx *storeCtx, const char *certPath, bool withRoot,
    HITLS_X509_List **chain)
{
    HITLS_X509_Cert *entity = NULL;
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, certPath, &entity);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = HITLS_X509_CertChainBuild(storeCtx, withRoot, entity, chain);
    HITLS_X509_CertFree(entity);
    return ret;
}

static uint32_t X509_TestListCount(BslList *list)
{
    if (list == NULL) {
        return 0;
    }
    return (uint32_t)BSL_LIST_COUNT(list);
}

/**
 * @test   SDV_STORE_CTX_DUP_REF_COUNT_TC001
 * @title  Shared Store reference count stays valid across REF_UP, duplication, and partial free.
 * @brief  1. Create a StoreCtx, perform REF_UP, and load one CA certificate into the shared Store.
 *         2. Duplicate the StoreCtx twice to create three handles that reference the same inner Store.
 *         3. Release the original handle first, then continue to use a duplicated handle to build a chain.
 *         4. Release the remaining duplicated handles and confirm the full lifecycle completes cleanly.
 * @expect 1. REF_UP and duplication succeed without corrupting the StoreCtx state.
 *         2. Releasing one handle does not invalidate the shared Store for the remaining handles.
 *         3. A duplicated handle can still build the certificate chain successfully.
 *         4. All handles are released without leaving errors on the stack.
 */
/* BEGIN_CASE */
void SDV_STORE_CTX_DUP_REF_COUNT_TC001(void)
{
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_StoreCtx *dup1 = NULL;
    HITLS_X509_StoreCtx *dup2 = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_List *chain = NULL;
    int32_t depth = 0;

    TestMemInit();

    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);

    /* Keep one extra StoreCtx reference so the original handle can be released before the duplicated ones. */
    int ref = 0;
    int32_t ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_REF_UP, &ref, sizeof(ref));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(ref, 2);

    ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/ca.der", storeCtx, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    dup1 = HITLS_X509_StoreCtxDup(storeCtx);
    ASSERT_NE(dup1, NULL);

    dup2 = HITLS_X509_StoreCtxDup(storeCtx);
    ASSERT_NE(dup2, NULL);
    ASSERT_EQ(dup1->store, dup2->store);

    /* The first free only drops the extra ctx reference; the shared Store must still serve duplicated handles. */
    HITLS_X509_StoreCtxFree(storeCtx);

    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_GET_PARAM_DEPTH, &depth, sizeof(depth));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(depth, 20);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/end.der", &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertChainBuild(dup1, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_X509_StoreCtxFree(storeCtx);
    storeCtx = NULL;

    HITLS_X509_StoreCtxFree(dup2);
    dup2 = NULL;

    HITLS_X509_StoreCtxFree(dup1);
    dup1 = NULL;

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_StoreCtxFree(dup1);
    HITLS_X509_StoreCtxFree(dup2);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * @test   SDV_STORE_CTX_DUP_SHARE_STORE_TC001
 * @title  Duplicated StoreCtx immediately observes trust-store mutations through the shared inner Store.
 * @brief  1. Create a StoreCtx and duplicate it before loading any trust certificate.
 *         2. Verify that the source and duplicated handles point to the same inner Store object.
 *         3. Add a CA certificate through the source handle and build a chain through the duplicated handle.
 *         4. Confirm the duplicated handle can observe the shared Store contents and continue normal use.
 * @expect 1. StoreCtx duplication succeeds and both handles share the same inner Store.
 *         2. Trust data inserted through the source handle becomes visible to the duplicated handle.
 *         3. The duplicated handle can build the certificate chain successfully.
 *         4. No unexpected error or callback state is left behind.
 */
/* BEGIN_CASE */
void SDV_STORE_CTX_DUP_SHARE_STORE_TC001(void)
{
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_StoreCtx *dupStore = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_List *chain = NULL;

    TestMemInit();

    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);

    dupStore = HITLS_X509_StoreCtxDup(storeCtx);
    ASSERT_NE(dupStore, NULL);

    /* Dup should immediately share the same inner Store before any trust data is inserted. */
    ASSERT_TRUE(dupStore->store == storeCtx->store);

    int32_t ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/ca.der", storeCtx, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/end.der", &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    /* Build through the duplicate to prove the newly added CA is visible across both handles. */
    ret = HITLS_X509_CertChainBuild(dupStore, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(BSL_LIST_COUNT(chain) >= 1);

#ifdef HITLS_PKI_X509_VFY_CB
    ASSERT_EQ(dupStore->error, 0);
    ASSERT_EQ(dupStore->curDepth, 0);
#endif

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_StoreCtxFree(dupStore);
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/**
 * @test   SDV_PROVIDER_STORE_CTX_DUP_TC001
 * @title  Provider store context constructor keeps shared-store defaults.
 * @brief  1. Create a plain StoreCtx and a ProviderStoreCtx with custom libCtx/attrName markers.
 *         2. Verify that ProviderStoreCtx inherits the same default initialization path as StoreCtxNew.
 *         3. Duplicate the ProviderStoreCtx and verify shared-store and provider metadata propagation.
 * @expect 1. ProviderStoreCtx creation succeeds with a valid inner Store.
 *         2. Provider-specific libCtx/attrName are stored correctly while the default callback stays aligned
 *            with the normal constructor path.
 *         3. Duplicated ProviderStoreCtx shares the same Store and preserves provider metadata.
 */
/* BEGIN_CASE */
void SDV_PROVIDER_STORE_CTX_DUP_TC001(void)
{
    int32_t libCtxMarker = 0;
    const char *attrName = "provider-store-refactor";
    HITLS_PKI_LibCtx *libCtx = (HITLS_PKI_LibCtx *)(uintptr_t)&libCtxMarker;
    HITLS_X509_StoreCtx *plainStore = NULL;
    HITLS_X509_StoreCtx *providerStore = NULL;
    HITLS_X509_StoreCtx *dupStore = NULL;

    TestMemInit();

    plainStore = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(plainStore != NULL);

    providerStore = HITLS_X509_ProviderStoreCtxNew(libCtx, attrName);
    ASSERT_TRUE(providerStore != NULL);
    /* Provider constructor still goes through the same shared-Store initialization path as the plain ctor. */
    ASSERT_TRUE(providerStore->store != NULL);
    ASSERT_EQ(providerStore->libCtx, libCtx);
    ASSERT_EQ(providerStore->attrName, attrName);
    ASSERT_EQ(providerStore->verifyParam.maxDepth, plainStore->verifyParam.maxDepth);

#ifdef HITLS_PKI_X509_VFY_CB
    ASSERT_TRUE(providerStore->verifyCb == plainStore->verifyCb);
#endif

    dupStore = HITLS_X509_StoreCtxDup(providerStore);
    ASSERT_TRUE(dupStore != NULL);
    /* Dup should preserve provider metadata while reusing the same inner Store object. */
    ASSERT_TRUE(dupStore->store == providerStore->store);
    ASSERT_EQ(dupStore->libCtx, providerStore->libCtx);
    ASSERT_EQ(dupStore->attrName, providerStore->attrName);

#ifdef HITLS_PKI_X509_VFY_CB
    ASSERT_TRUE(dupStore->verifyCb == providerStore->verifyCb);
#endif

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_StoreCtxFree(dupStore);
    HITLS_X509_StoreCtxFree(providerStore);
    HITLS_X509_StoreCtxFree(plainStore);
}
/* END_CASE */

/**
 * @test   SDV_STORE_CTX_DUP_VPARAM_ISOLATION_TC001
 * @title  Duplicated StoreCtx keeps verify parameters isolated while sharing only the inner Store.
 * @brief  1. Create a StoreCtx and configure verify parameters such as purpose, security bits, and identity data.
 *         2. Duplicate the StoreCtx and confirm identity-related buffers and lists are deep-copied.
 *         3. Mutate verify parameters on the duplicated handle.
 *         4. Verify that the original handle retains its original verify configuration.
 * @expect 1. StoreCtx duplication succeeds while preserving the source verify configuration.
 *         2. Identity and SM2 userId data are copied into independent storage.
 *         3. Changes made on the duplicated handle do not leak back to the source handle.
 *         4. Source and duplicated handles each preserve their own verifyParam values.
 */
/* BEGIN_CASE */
void SDV_STORE_CTX_DUP_VPARAM_ISOLATION_TC001(void)
{
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_StoreCtx *dupStore = NULL;

    TestMemInit();

    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);

    /* Seed the source ctx with per-verify state that should be deep-copied rather than shared. */
    storeCtx->verifyParam.purpose = 1;
    storeCtx->verifyParam.securityBits = 128;
    int32_t ret;
    (void)ret;
#ifdef HITLS_PKI_X509_VFY_IDENTITY
    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_HOST,
        (void *)"www.example.com", 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
#endif
#ifdef HITLS_CRYPTO_SM2
    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_VFY_SM2_USERID,
        "user_A", strlen("user_A"));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
#endif

    dupStore = HITLS_X509_StoreCtxDup(storeCtx);
    ASSERT_NE(dupStore, NULL);

    /* Identity buffers/lists must be duplicated even though the inner Store itself is shared. */
#ifdef HITLS_PKI_X509_VFY_IDENTITY
    ASSERT_EQ(X509_TestListCount(dupStore->verifyParam.hostnames), X509_TestListCount(storeCtx->verifyParam.hostnames));
    ASSERT_TRUE(dupStore->verifyParam.hostnames != storeCtx->verifyParam.hostnames);
#endif
#ifdef HITLS_CRYPTO_SM2
    ASSERT_EQ(dupStore->verifyParam.sm2UserId.dataLen, storeCtx->verifyParam.sm2UserId.dataLen);
    ASSERT_TRUE(dupStore->verifyParam.sm2UserId.data != storeCtx->verifyParam.sm2UserId.data);
#endif

    dupStore->verifyParam.purpose = 2;
    dupStore->verifyParam.securityBits = 256;
    /* Mutate only the duplicate and confirm the source verify parameters stay unchanged. */
#ifdef HITLS_PKI_X509_VFY_IDENTITY
    ret = HITLS_X509_StoreCtxCtrl(dupStore, HITLS_X509_STORECTX_SET_HOST,
        (void *)"www.other.com", 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
#endif
#ifdef HITLS_CRYPTO_SM2
    ret = HITLS_X509_StoreCtxCtrl(dupStore, HITLS_X509_STORECTX_SET_VFY_SM2_USERID,
        "user_B", strlen("user_B"));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
#endif

    ASSERT_EQ(storeCtx->verifyParam.purpose, 1);
    ASSERT_EQ(storeCtx->verifyParam.securityBits, 128);
#ifdef HITLS_PKI_X509_VFY_IDENTITY
    ASSERT_EQ(X509_TestListCount(storeCtx->verifyParam.hostnames), 1);
#endif
#ifdef HITLS_CRYPTO_SM2
    ASSERT_EQ(storeCtx->verifyParam.sm2UserId.dataLen, strlen("user_A"));
    ASSERT_TRUE(memcmp(storeCtx->verifyParam.sm2UserId.data, "user_A", strlen("user_A")) == 0);
#endif

    ASSERT_EQ(dupStore->verifyParam.purpose, 2);
    ASSERT_EQ(dupStore->verifyParam.securityBits, 256);
#ifdef HITLS_PKI_X509_VFY_IDENTITY
    ASSERT_EQ(X509_TestListCount(dupStore->verifyParam.hostnames), 1);
#endif
#ifdef HITLS_CRYPTO_SM2
    ASSERT_EQ(dupStore->verifyParam.sm2UserId.dataLen, strlen("user_B"));
    ASSERT_TRUE(memcmp(dupStore->verifyParam.sm2UserId.data, "user_B", strlen("user_B")) == 0);
#endif

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_StoreCtxFree(dupStore);
    HITLS_X509_StoreCtxFree(storeCtx);
}
/* END_CASE */

/**
 * @test   SDV_STORE_CLEAR_CRL_SHARE_TC001
 * @title  CLEAR_CRL mutates the shared inner Store for all duplicated handles.
 * @brief  1. Add two CRLs into the source StoreCtx and duplicate it.
 *         2. Confirm both handles observe the same shared CRL list before clearing.
 *         3. Call CLEAR_CRL from the duplicated handle.
 *         4. Verify the source and duplicated handles both observe the cleared shared Store.
 * @expect 1. CRL setup and duplication succeed.
 *         2. Both handles initially see the same shared CRL contents.
 *         3. CLEAR_CRL succeeds through the duplicated handle.
 *         4. The shared CRL list becomes empty for all handles.
 */
/* BEGIN_CASE */
void SDV_STORE_CLEAR_CRL_SHARE_TC001(void)
{
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_StoreCtx *dupStore = NULL;
    HITLS_X509_Crl *rootCrl = NULL;
    HITLS_X509_Crl *intermediateCrl = NULL;

    TestMemInit();

    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);

    ASSERT_EQ(HITLS_AddCrlToStoreTest("../testdata/cert/test_for_crl/crl_verify/crl/ca.crl",
        storeCtx, &rootCrl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_AddCrlToStoreTest(
        "../testdata/cert/test_for_crl/crl_verify/intermediate/crl/intermediate.crl",
        storeCtx, &intermediateCrl), HITLS_PKI_SUCCESS);

    dupStore = HITLS_X509_StoreCtxDup(storeCtx);
    ASSERT_TRUE(dupStore != NULL);
    ASSERT_TRUE(dupStore->store == storeCtx->store);
    ASSERT_EQ(X509_TestListCount(storeCtx->store->crls), 2);
    ASSERT_EQ(X509_TestListCount(dupStore->store->crls), 2);

    /* CLEAR_CRL runs through one handle, but the effect must be visible to every ctx sharing that Store. */
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(dupStore, HITLS_X509_STORECTX_CLEAR_CRL, NULL, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_TestListCount(storeCtx->store->crls), 0);
    ASSERT_EQ(X509_TestListCount(dupStore->store->crls), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_StoreCtxFree(dupStore);
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_CrlFree(rootCrl);
    HITLS_X509_CrlFree(intermediateCrl);
}
/* END_CASE */

typedef struct {
    HITLS_X509_StoreCtx *srcStore;
    uint32_t loops;
    int32_t result;
} StoreRefractorConcurrentReadArg;

static void *StoreRefractorConcurrentReadThread(void *arg)
{
    StoreRefractorConcurrentReadArg *threadArg = (StoreRefractorConcurrentReadArg *)arg;
    threadArg->result = BSL_INTERNAL_EXCEPTION;

    for (uint32_t i = 0; i < threadArg->loops; i++) {
        /* Each iteration duplicates the ctx and walks a read-only chain build to stress shared-Store readers. */
        HITLS_X509_StoreCtx *dupStore = HITLS_X509_StoreCtxDup(threadArg->srcStore);
        if (dupStore == NULL) {
            threadArg->result = BSL_MALLOC_FAIL;
            return NULL;
        }
        HITLS_X509_Cert *entity = NULL;
        HITLS_X509_List *chain = NULL;
        int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1,
            "../testdata/cert/chain/rsa-pss-v3/end.der", &entity);
        if (ret != HITLS_PKI_SUCCESS) {
            HITLS_X509_StoreCtxFree(dupStore);
            threadArg->result = ret;
            return NULL;
        }
        ret = HITLS_X509_CertChainBuild(dupStore, false, entity, &chain);
        HITLS_X509_CertFree(entity);
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        HITLS_X509_StoreCtxFree(dupStore);
        if (ret != HITLS_PKI_SUCCESS) {
            threadArg->result = ret;
            return NULL;
        }
    }
    threadArg->result = HITLS_PKI_SUCCESS;
    return NULL;
}

/**
 * @test   SDV_STORE_CTX_DUP_CHAIN_BUILD_TC001
 * @title  Concurrent duplicated read paths remain stable when multiple threads share the same Store.
 * @brief  1. Create a StoreCtx, load one CA certificate, and use it as the shared source handle.
 *         2. Start multiple threads that repeatedly duplicate the source StoreCtx.
 *         3. Let each thread parse the same entity certificate and build a chain from its duplicated handle.
 *         4. Wait for all threads to finish and validate the result from every thread.
 * @expect 1. Every thread duplicates the StoreCtx successfully across repeated iterations.
 *         2. Concurrent read-side duplication and chain building complete without race-induced failures.
 *         3. Each worker thread reports HITLS_PKI_SUCCESS.
 *         4. The error stack remains empty after all threads exit.
 */
/* BEGIN_CASE */
void SDV_STORE_CTX_DUP_CHAIN_BUILD_TC001(void)
{
    enum {
        THREAD_NUM = 10,
        THREAD_LOOPS = 100
    };
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_Cert *ca = NULL;
    pthread_t threads[THREAD_NUM] = {0};
    StoreRefractorConcurrentReadArg args[THREAD_NUM];
    int createdThreads = 0;
    int joinedThreads = 0;

    TestMemInit();

    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);

    int32_t ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/ca.der", storeCtx, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    /* Fan out several duplicate-only readers against one shared Store and require every worker to finish cleanly. */
    for (int i = 0; i < THREAD_NUM; i++) {
        args[i].srcStore = storeCtx;
        args[i].loops = THREAD_LOOPS;
        args[i].result = BSL_INTERNAL_EXCEPTION;
        ASSERT_TRUE(pthread_create(&threads[i], NULL,
            StoreRefractorConcurrentReadThread, &args[i]) == 0);
        createdThreads++;
    }

    for (int i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
        joinedThreads++;
    }
    for (int i = 0; i < THREAD_NUM; i++) {
        ASSERT_EQ(args[i].result, HITLS_PKI_SUCCESS);
    }

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    for (int i = joinedThreads; i < createdThreads; i++) {
        pthread_join(threads[i], NULL);
    }
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_CertFree(ca);
}
/* END_CASE */

typedef struct {
    HITLS_X509_StoreCtx *srcStore;
    uint32_t loops;
    int32_t result;
    bool isWriter;
    HITLS_X509_Cert *writerCa;
} StoreRefractorRwArg;

static void *StoreRefractorRwThread(void *arg)
{
    StoreRefractorRwArg *threadArg = (StoreRefractorRwArg *)arg;
    threadArg->result = BSL_INTERNAL_EXCEPTION;

    for (uint32_t i = 0; i < threadArg->loops; i++) {
        if (threadArg->isWriter) {
            /* Writer path repeatedly replays the same CA insertion to stress duplicate-detect and write locking. */
            int32_t ret = HITLS_X509_StoreCtxCtrl(threadArg->srcStore,
                HITLS_X509_STORECTX_DEEP_COPY_SET_CA, threadArg->writerCa, sizeof(HITLS_X509_Cert));
            if (ret != HITLS_PKI_SUCCESS) {
                threadArg->result = ret;
                return NULL;
            }
        } else {
            /* Reader path keeps duplicating and building chains while the writer is mutating the same Store. */
            HITLS_X509_StoreCtx *dupStore = HITLS_X509_StoreCtxDup(threadArg->srcStore);
            if (dupStore == NULL) {
                threadArg->result = BSL_MALLOC_FAIL;
                return NULL;
            }
            HITLS_X509_List *chain = NULL;
            int32_t ret = HITLS_BuildChainFromFileTest(dupStore, "../testdata/cert/chain/rsa-pss-v3/end.der",
                false, &chain);
            BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
            HITLS_X509_StoreCtxFree(dupStore);
            if (ret != HITLS_PKI_SUCCESS) {
                threadArg->result = ret;
                return NULL;
            }
        }
    }
    threadArg->result = HITLS_PKI_SUCCESS;
    return NULL;
}

/**
 * @test   SDV_STORE_RW_MULTI_THREAD_TC001
 * @title  Shared Store read-write locking protects concurrent writer and duplicated reader activity.
 * @brief  1. Create a StoreCtx and preload one CA certificate into the shared Store.
 *         2. Start multiple writer threads that repeatedly replay the same CA insertion.
 *         3. Start multiple reader threads that repeatedly duplicate the source handle and build a chain.
 *         4. Join all threads and validate that concurrent read-write activity completes successfully.
 * @expect 1. Writer and reader threads all complete their loops successfully.
 *         2. Concurrent Store mutation and duplicated read access do not corrupt shared state.
 *         3. The duplicated reader path remains usable during repeated writes.
 *         4. The error stack stays empty after the concurrent run.
 */
/* BEGIN_CASE */
void SDV_STORE_RW_MULTI_THREAD_TC001(void)
{
    enum {
        THREAD_NUM = 10,
        WRITER_NUM = 4,
        RW_LOOPS = 200
    };
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *writerCa = NULL;
    pthread_t threads[THREAD_NUM] = {0};
    StoreRefractorRwArg args[THREAD_NUM];
    int createdThreads = 0;
    int joinedThreads = 0;

    TestMemInit();

    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);

    int32_t ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/ca.der", storeCtx, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/ca.der", &writerCa);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    /* Mix several writers and duplicated readers together so cert-store locking is exercised under real contention. */
    for (int i = 0; i < THREAD_NUM; i++) {
        args[i].srcStore = storeCtx;
        args[i].loops = RW_LOOPS;
        args[i].isWriter = (i < WRITER_NUM);
        args[i].writerCa = writerCa;
        args[i].result = BSL_INTERNAL_EXCEPTION;
        ASSERT_TRUE(pthread_create(&threads[i], NULL, StoreRefractorRwThread, &args[i]) == 0);
        createdThreads++;
    }

    for (int i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
        joinedThreads++;
    }
    for (int i = 0; i < THREAD_NUM; i++) {
        ASSERT_EQ(args[i].result, HITLS_PKI_SUCCESS);
    }

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    for (int i = joinedThreads; i < createdThreads; i++) {
        pthread_join(threads[i], NULL);
    }
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(writerCa);
}
/* END_CASE */

typedef struct {
    HITLS_X509_StoreCtx *srcStore;
    const char *entityPath;
    uint32_t loops;
    int32_t result;
} StoreConcurrentCrlReadArg;

static void *StoreConcurrentCrlReadThread(void *arg)
{
    StoreConcurrentCrlReadArg *threadArg = (StoreConcurrentCrlReadArg *)arg;
    threadArg->result = BSL_INTERNAL_EXCEPTION;

    for (uint32_t i = 0; i < threadArg->loops; i++) {
        HITLS_X509_StoreCtx *dupStore = HITLS_X509_StoreCtxDup(threadArg->srcStore);
        if (dupStore == NULL) {
            threadArg->result = BSL_MALLOC_FAIL;
            return NULL;
        }
        HITLS_X509_List *chain = NULL;
        int32_t ret = HITLS_BuildChainFromFileTest(dupStore, threadArg->entityPath, true, &chain);
        if (ret == HITLS_PKI_SUCCESS) {
            ret = HITLS_X509_VerifyCrl(dupStore, chain, NULL);
        }
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        HITLS_X509_StoreCtxFree(dupStore);
        if (ret != HITLS_PKI_SUCCESS) {
            threadArg->result = ret;
            return NULL;
        }
    }
    threadArg->result = HITLS_PKI_SUCCESS;
    return NULL;
}

/**
 * @test   SDV_STORE_CRL_READ_MULTI_THREAD_TC001
 * @title  Concurrent duplicated CRL verification can snapshot the shared CRL store safely.
 * @brief  1. Preload root/intermediate trust certificates and valid CRLs into one shared Store.
 *         2. Configure CRL verification flags on the source StoreCtx.
 *         3. Start at least ten reader threads that repeatedly duplicate the source ctx, build a chain,
 *            and call VerifyCrl.
 *         4. Wait for all threads and require every CRL verification loop to succeed.
 * @expect 1. Each duplicated reader can obtain a stable CRL snapshot from the shared Store.
 *         2. Concurrent VerifyCrl calls do not race on store->crls.
 *         3. Every worker thread reports HITLS_PKI_SUCCESS.
 *         4. The error stack remains empty after the stress run.
 */
/* BEGIN_CASE */
void SDV_STORE_CRL_READ_MULTI_THREAD_TC001(void)
{
    enum {
        THREAD_NUM = 10,
        THREAD_LOOPS = 60
    };
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *intermediate = NULL;
    HITLS_X509_Crl *rootCrl = NULL;
    HITLS_X509_Crl *intermediateCrl = NULL;
    pthread_t threads[THREAD_NUM] = {0};
    StoreConcurrentCrlReadArg args[THREAD_NUM];
    int createdThreads = 0;
    int joinedThreads = 0;

    TestMemInit();

    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);

    ASSERT_EQ(HITLS_AddCertToStoreTest("../testdata/cert/test_for_crl/crl_verify/certs/ca.crt",
        storeCtx, &root), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_AddCertToStoreTest(
        "../testdata/cert/test_for_crl/crl_verify/intermediate/certs/intermediate.crt",
        storeCtx, &intermediate), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_AddCrlToStoreTest("../testdata/cert/test_for_crl/crl_verify/crl/root_updated.crl",
        storeCtx, &rootCrl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_AddCrlToStoreTest(
        "../testdata/cert/test_for_crl/crl_verify/intermediate/crl/intermediate.crl",
        storeCtx, &intermediateCrl), HITLS_PKI_SUCCESS);
    storeCtx->verifyParam.flags = HITLS_X509_VFY_FLAG_CRL_ALL | HITLS_X509_VFY_FLAG_DISABLE_TIME_CHECK;

    for (int i = 0; i < THREAD_NUM; i++) {
        args[i].srcStore = storeCtx;
        args[i].entityPath = "../testdata/cert/test_for_crl/crl_verify/intermediate/certs/device1.crt";
        args[i].loops = THREAD_LOOPS;
        args[i].result = BSL_INTERNAL_EXCEPTION;
        ASSERT_TRUE(pthread_create(&threads[i], NULL, StoreConcurrentCrlReadThread, &args[i]) == 0);
        createdThreads++;
    }

    for (int i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
        joinedThreads++;
    }
    for (int i = 0; i < THREAD_NUM; i++) {
        ASSERT_EQ(args[i].result, HITLS_PKI_SUCCESS);
    }

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    for (int i = joinedThreads; i < createdThreads; i++) {
        pthread_join(threads[i], NULL);
    }
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(intermediate);
    HITLS_X509_CrlFree(rootCrl);
    HITLS_X509_CrlFree(intermediateCrl);
}
/* END_CASE */

typedef struct {
    HITLS_X509_StoreCtx *srcStore;
    HITLS_X509_Crl *rootCrl;
    HITLS_X509_Crl *intermediateCrl;
    uint32_t loops;
    int32_t result;
    bool isWriter;
} StoreConcurrentCrlRwArg;

static void *StoreConcurrentCrlRwThread(void *arg)
{
    StoreConcurrentCrlRwArg *threadArg = (StoreConcurrentCrlRwArg *)arg;
    threadArg->result = BSL_INTERNAL_EXCEPTION;

    for (uint32_t i = 0; i < threadArg->loops; i++) {
        if (threadArg->isWriter) {
            int32_t ret = HITLS_X509_StoreCtxCtrl(threadArg->srcStore, HITLS_X509_STORECTX_CLEAR_CRL, NULL, 0);
            if (ret != HITLS_PKI_SUCCESS) {
                threadArg->result = ret;
                return NULL;
            }
            usleep(100);
            ret = HITLS_X509_StoreCtxCtrl(threadArg->srcStore, HITLS_X509_STORECTX_SET_CRL,
                threadArg->rootCrl, sizeof(HITLS_X509_Crl));
            if (ret == HITLS_X509_ERR_CRL_EXIST) {
                (void)TestErrClear();
            } else if (ret != HITLS_PKI_SUCCESS) {
                threadArg->result = ret;
                return NULL;
            }
            usleep(100);
            ret = HITLS_X509_StoreCtxCtrl(threadArg->srcStore, HITLS_X509_STORECTX_SET_CRL,
                threadArg->intermediateCrl, sizeof(HITLS_X509_Crl));
            if (ret == HITLS_X509_ERR_CRL_EXIST) {
                (void)TestErrClear();
            } else if (ret != HITLS_PKI_SUCCESS) {
                threadArg->result = ret;
                return NULL;
            }
        } else {
            HITLS_X509_List *crlList = NULL;
            int32_t ret = HITLS_X509_StoreGetCrlList(threadArg->srcStore->store, &crlList);
            if (ret != HITLS_PKI_SUCCESS) {
                threadArg->result = ret;
                return NULL;
            }
            for (BslListNode *node = BSL_LIST_FirstNode(crlList); node != NULL;
                node = BSL_LIST_GetNextNode(crlList, node)) {
                if (BSL_LIST_GetData(node) == NULL) {
                    BSL_LIST_FREE(crlList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
                    threadArg->result = BSL_INTERNAL_EXCEPTION;
                    return NULL;
                }
            }
            BSL_LIST_FREE(crlList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
        }
    }
    threadArg->result = HITLS_PKI_SUCCESS;
    return NULL;
}

/**
 * @test   SDV_STORE_CRL_RW_MULTI_THREAD_TC001
 * @title  Shared CRL store remains consistent while writers clear/reload and readers snapshot concurrently.
 * @brief  1. Parse one root CRL and one intermediate CRL and preload them into the shared Store.
 *         2. Start multiple writer threads that repeatedly CLEAR_CRL and reload the same CRLs.
 *         3. Start multiple reader threads that repeatedly take CRL snapshots from the shared Store.
 *         4. Join all threads and validate every reader/writer result.
 * @expect 1. Writers serialize CLEAR_CRL and SET_CRL correctly under the Store write lock.
 *         2. Readers always obtain a freeable CRL snapshot without use-after-free.
 *         3. Snapshot nodes remain valid while readers traverse and free the returned list.
 *         4. All worker threads finish with HITLS_PKI_SUCCESS and no error-stack residue.
 */
/* BEGIN_CASE */
void SDV_STORE_CRL_RW_MULTI_THREAD_TC001(void)
{
    enum {
        THREAD_NUM = 10,
        WRITER_NUM = 4,
        THREAD_LOOPS = 100
    };
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_Crl *rootCrl = NULL;
    HITLS_X509_Crl *intermediateCrl = NULL;
    pthread_t threads[THREAD_NUM] = {0};
    StoreConcurrentCrlRwArg args[THREAD_NUM];
    int createdThreads = 0;
    int joinedThreads = 0;

    TestMemInit();

    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);

    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN,
        "../testdata/cert/test_for_crl/crl_verify/crl/root_updated.crl", &rootCrl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN,
        "../testdata/cert/test_for_crl/crl_verify/intermediate/crl/intermediate.crl",
        &intermediateCrl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_CRL,
        rootCrl, sizeof(HITLS_X509_Crl)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_CRL,
        intermediateCrl, sizeof(HITLS_X509_Crl)), HITLS_PKI_SUCCESS);

    for (int i = 0; i < THREAD_NUM; i++) {
        args[i].srcStore = storeCtx;
        args[i].rootCrl = rootCrl;
        args[i].intermediateCrl = intermediateCrl;
        args[i].loops = THREAD_LOOPS;
        args[i].isWriter = (i < WRITER_NUM);
        args[i].result = BSL_INTERNAL_EXCEPTION;
        ASSERT_TRUE(pthread_create(&threads[i], NULL, StoreConcurrentCrlRwThread, &args[i]) == 0);
        createdThreads++;
    }

    for (int i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
        joinedThreads++;
    }
    for (int i = 0; i < THREAD_NUM; i++) {
        ASSERT_EQ(args[i].result, HITLS_PKI_SUCCESS);
    }

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    for (int i = joinedThreads; i < createdThreads; i++) {
        pthread_join(threads[i], NULL);
    }
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_CrlFree(rootCrl);
    HITLS_X509_CrlFree(intermediateCrl);
}
/* END_CASE */

typedef struct {
    HITLS_X509_StoreCtx *srcStore;
    const char *caPath1;
    const char *caPath2;
    const char *entityPath;
    uint32_t loops;
    int32_t result;
    bool isWriter;
} StoreConcurrentCaPathArg;

static void *StoreConcurrentCaPathThread(void *arg)
{
    StoreConcurrentCaPathArg *threadArg = (StoreConcurrentCaPathArg *)arg;
    threadArg->result = BSL_INTERNAL_EXCEPTION;

    for (uint32_t i = 0; i < threadArg->loops; i++) {
        if (threadArg->isWriter) {
            int32_t ret = HITLS_X509_StoreCtxCtrl(threadArg->srcStore, HITLS_X509_STORECTX_ADD_CA_PATH,
                (void *)threadArg->caPath1, strlen(threadArg->caPath1));
            if (ret != HITLS_PKI_SUCCESS) {
                threadArg->result = ret;
                return NULL;
            }
            ret = HITLS_X509_StoreCtxCtrl(threadArg->srcStore, HITLS_X509_STORECTX_ADD_CA_PATH,
                (void *)threadArg->caPath2, strlen(threadArg->caPath2));
            if (ret != HITLS_PKI_SUCCESS) {
                threadArg->result = ret;
                return NULL;
            }
        } else {
            HITLS_X509_StoreCtx *dupStore = HITLS_X509_StoreCtxDup(threadArg->srcStore);
            if (dupStore == NULL) {
                threadArg->result = BSL_MALLOC_FAIL;
                return NULL;
            }
            HITLS_X509_List *chain = NULL;
            int32_t ret = HITLS_BuildChainFromFileTest(dupStore, threadArg->entityPath, true, &chain);
            if (ret == HITLS_PKI_SUCCESS) {
                ret = HITLS_X509_CertVerify(dupStore, chain);
            }
            BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
            HITLS_X509_StoreCtxFree(dupStore);
            if (ret != HITLS_PKI_SUCCESS) {
                threadArg->result = ret;
                return NULL;
            }
        }
    }
    threadArg->result = HITLS_PKI_SUCCESS;
    return NULL;
}

/**
 * @test   SDV_STORE_CAPATH_RW_MULTI_THREAD_TC001
 * @title  CA-path readers and writers can share one Store while issuer loading updates trust cache on demand.
 * @brief  1. Seed one valid CA path into the shared Store and leave trust certificates to be loaded lazily.
 *         2. Start writer threads that repeatedly add the same CA directories.
 *         3. Start reader threads that duplicate the source ctx, build a chain from a PEM leaf cert,
 *            and verify it so issuer lookup runs through caPaths and store->certs together.
 *         4. Join all threads and require every path-based build/verify attempt to succeed.
 * @expect 1. ADD_CA_PATH remains safe under repeated duplicate insertions.
 *         2. Concurrent issuer lookup can copy caPaths, load issuers, and publish them into store->certs safely.
 *         3. All worker threads complete successfully with no deadlock or corruption.
 *         4. The error stack remains empty after the concurrent run.
 */
/* BEGIN_CASE */
void SDV_STORE_CAPATH_RW_MULTI_THREAD_TC001(void)
{
#ifdef HITLS_PKI_X509_VFY_LOCATION
    enum {
        THREAD_NUM = 10,
        WRITER_NUM = 2,
        THREAD_LOOPS = 60
    };
    HITLS_X509_StoreCtx *storeCtx = NULL;
    pthread_t threads[THREAD_NUM] = {0};
    StoreConcurrentCaPathArg args[THREAD_NUM];
    const char *caPath1 = "../testdata/tls/certificate/pem/rsa_sha256";
    const char *caPath2 = "../testdata/tls/certificate/pem/test_dir";
    const char *entityPath = "../testdata/tls/certificate/pem/rsa_sha256/client.pem";
    int createdThreads = 0;
    int joinedThreads = 0;

    TestMemInit();

    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_ADD_CA_PATH,
        (void *)caPath1, strlen(caPath1)), HITLS_PKI_SUCCESS);

    for (int i = 0; i < THREAD_NUM; i++) {
        args[i].srcStore = storeCtx;
        args[i].caPath1 = caPath1;
        args[i].caPath2 = caPath2;
        args[i].entityPath = entityPath;
        args[i].loops = THREAD_LOOPS;
        args[i].isWriter = (i < WRITER_NUM);
        args[i].result = BSL_INTERNAL_EXCEPTION;
        ASSERT_TRUE(pthread_create(&threads[i], NULL, StoreConcurrentCaPathThread, &args[i]) == 0);
        createdThreads++;
    }

    for (int i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
        joinedThreads++;
    }
    for (int i = 0; i < THREAD_NUM; i++) {
        ASSERT_EQ(args[i].result, HITLS_PKI_SUCCESS);
    }

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    for (int i = joinedThreads; i < createdThreads; i++) {
        pthread_join(threads[i], NULL);
    }
    HITLS_X509_StoreCtxFree(storeCtx);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

#ifdef HITLS_PKI_X509_VFY_CB
static HITLS_X509_Cert *g_storeRefactorCbCert = NULL;
static int32_t g_storeRefactorCbRet = HITLS_PKI_SUCCESS;
static uint32_t g_storeRefactorCbCalls = 0;

static int32_t StoreRefractorDeadlockCb(int32_t errCode, HITLS_X509_StoreCtx *storeCtx)
{
    g_storeRefactorCbCalls++;
    /* The first callback attempts a Store write to prove verify-time lock dropping avoids self-deadlock. */
    if (g_storeRefactorCbCalls == 1 && g_storeRefactorCbCert != NULL) {
        g_storeRefactorCbRet = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
            g_storeRefactorCbCert, sizeof(HITLS_X509_Cert));
    }
    if (g_storeRefactorCbRet != HITLS_PKI_SUCCESS) {
        return g_storeRefactorCbRet;
    }
    return errCode;
}
#endif

/**
 * @test   SDV_STORE_VERIFY_CBK_WRITELOCK_TC001
 * @title  Verify callback can upgrade from verify-time read path to Store write command safely.
 * @brief  1. Configure a valid verification chain and register a callback that performs DEEP_COPY_SET_CA.
 *         2. Trigger CertVerify while the implementation holds the Store read lock for verification.
 *         3. Let the callback request a Store write command on the first invocation.
 *         4. Verify that CertVerify completes successfully and the callback mutation becomes visible.
 * @expect 1. Verification callback is invoked at least once.
 *         2. The callback's Store write command succeeds without deadlock.
 *         3. CertVerify completes successfully and the shared Store reflects the new certificate.
 */
/* BEGIN_CASE */
void SDV_STORE_VERIFY_CBK_WRITELOCK_TC001(void)
{
#ifdef HITLS_PKI_X509_VFY_CB
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *ca = NULL;
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_Cert *extraCa = NULL;
    HITLS_X509_List *chain = NULL;

    TestMemInit();

    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_TRUE(storeCtx != NULL);

    int32_t ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/ca.der", storeCtx, &root);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_AddCertToStoreTest("../testdata/cert/chain/rsa-pss-v3/inter.der", storeCtx, &ca);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-v3/ca.der", &extraCa);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    g_storeRefactorCbCert = extraCa;
    g_storeRefactorCbRet = HITLS_PKI_SUCCESS;
    g_storeRefactorCbCalls = 0;

    /* Register the callback before verify so the first callback invocation performs a Store mutation. */
    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_VERIFY_CB,
        StoreRefractorDeadlockCb, sizeof(X509_STORECTX_VerifyCb));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/rsa-pss-v3/end.der", &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertChainBuild(storeCtx, false, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    int64_t timeval = time(NULL);
    ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    /* Verify should complete and leave the callback-added CA visible in the shared Store. */
    ret = HITLS_X509_CertVerify(storeCtx, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(g_storeRefactorCbCalls > 0);
    ASSERT_EQ(g_storeRefactorCbRet, HITLS_PKI_SUCCESS);
    ASSERT_EQ(X509_TestListCount(storeCtx->store->certs), 3);

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    g_storeRefactorCbCert = NULL;
    g_storeRefactorCbRet = HITLS_PKI_SUCCESS;
    g_storeRefactorCbCalls = 0;
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(ca);
    HITLS_X509_CertFree(entity);
    HITLS_X509_CertFree(extraCa);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */
