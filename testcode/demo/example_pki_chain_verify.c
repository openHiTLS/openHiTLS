/*
 * PKI certificate chain verification example.
 */

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "bsl_list.h"
#include "bsl_types.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_x509.h"

#define CHAIN_DIR "assets/tls_ecdsa_der/"

static void PkiPrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    uint32_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int32_t ChainDemoAddCertToStore(HITLS_X509_StoreCtx *store, const char *path)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret;

    ret = HITLS_X509_ProviderCertParseFile(NULL, NULL, "ASN1", path, &cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert, sizeof(HITLS_X509_Cert *));
    HITLS_X509_CertFree(cert);
    if (ret != HITLS_PKI_SUCCESS) {
    }
    return ret;
}

static int32_t ChainDemoAddCertToChain(HITLS_X509_List *chain, const char *path)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret;

    ret = HITLS_X509_ProviderCertParseFile(NULL, NULL, "ASN1", path, &cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_LIST_AddElement(chain, cert, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_CertFree(cert);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

int main(void)
{
    HITLS_X509_StoreCtx *store = NULL;
    HITLS_X509_List *chain = NULL;
    uint8_t digest[32];
    uint32_t digestLen = sizeof(digest);
    int64_t verifyTime = (int64_t)time(NULL);
    int32_t depth = 4;
    int32_t ret;

    printf("=== PKI Certificate Chain Verify Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    store = HITLS_X509_ProviderStoreCtxNew(NULL, NULL);
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
    ret = ChainDemoAddCertToStore(store, CHAIN_DIR "ca.der");
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = ChainDemoAddCertToStore(store, CHAIN_DIR "inter.der");
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (chain == NULL) {
        ret = -1;
        goto cleanup;
    }
    ret = ChainDemoAddCertToChain(chain, CHAIN_DIR "server.der");
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertVerify(store, chain);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertDigest(BSL_LIST_FirstNodeData(chain), CRYPT_MD_SHA256, digest, &digestLen);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    printf("Verified chain: ca.der -> inter.der -> server.der\n");
    printf("Verified chain elements: %u\n", BSL_LIST_COUNT(chain));
    PkiPrintHex("server.der SHA-256", digest, digestLen);
    ret = 0;

cleanup:
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_StoreCtxFree(store);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
