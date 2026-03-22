/*
 * Post-quantum PKI certificate verification example.
 */

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "bsl_list.h"
#include "bsl_types.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_x509.h"

#define PQ_CHAIN_DIR "assets/pki_pq_mlkem/"

static int32_t PqVerifyParseAndAddCa(HITLS_X509_StoreCtx *store, const char *path, HITLS_X509_Cert **certOut)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret;

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, path, &cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert, sizeof(HITLS_X509_Cert *));
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_CertFree(cert);
        return ret;
    }

    *certOut = cert;
    return HITLS_PKI_SUCCESS;
}

int main(void)
{
    HITLS_X509_StoreCtx *store = NULL;
    HITLS_X509_Cert *intermediate = NULL;
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *entity = NULL;
    HITLS_X509_List *chain = NULL;
    CRYPT_EAL_PkeyCtx *issuerPubKey = NULL;
    int64_t verifyTime = (int64_t)time(NULL);
    int32_t depth = 4;
    int32_t signAlg = 0;
    int32_t mdAlg = 0;
    int32_t ret;

    printf("=== PQ Certificate Verify Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    store = HITLS_X509_StoreCtxNew();
    if (store == NULL) {
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH, &depth, sizeof(depth));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &verifyTime, sizeof(verifyTime));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    ret = PqVerifyParseAndAddCa(store, PQ_CHAIN_DIR "inter.crt", &intermediate);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = PqVerifyParseAndAddCa(store, PQ_CHAIN_DIR "root.crt", &root);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, PQ_CHAIN_DIR "end.crt", &entity);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    ret = HITLS_X509_CertCtrl(intermediate, HITLS_X509_GET_PUBKEY, &issuerPubKey, sizeof(issuerPubKey));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertVerifyByPubKey(entity, issuerPubKey);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(entity, HITLS_X509_GET_SIGNALG, &signAlg, sizeof(signAlg));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(entity, HITLS_X509_GET_SIGN_MDALG, &mdAlg, sizeof(mdAlg));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertVerify(store, chain);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    printf("Verified ML-KEM certificate chain: root.crt -> inter.crt -> end.crt\n");
    printf("Built chain elements: %u\n", BSL_LIST_COUNT(chain));
    printf("End-entity signature algorithm id: %d\n", signAlg);
    printf("End-entity digest algorithm id: %d\n", mdAlg);
    ret = 0;

cleanup:
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    CRYPT_EAL_PkeyFreeCtx(issuerPubKey);
    HITLS_X509_CertFree(entity);
    HITLS_X509_CertFree(root);
    HITLS_X509_CertFree(intermediate);
    HITLS_X509_StoreCtxFree(store);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
