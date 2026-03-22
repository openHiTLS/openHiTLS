/*
 * PKI parse variants and bundle example.
 */

#include <stdio.h>
#include <stdint.h>
#include "bsl_list.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_x509.h"

int32_t BSL_SAL_ReadFile(const char *path, uint8_t **buff, uint32_t *len);

static int32_t PkiReadBinaryFile(const char *path, BSL_Buffer *buffer)
{
    uint8_t *data = NULL;
    uint32_t readLen = 0;
    int32_t ret;

    ret = BSL_SAL_ReadFile(path, &data, &readLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    buffer->data = data;
    buffer->dataLen = readLen;
    return HITLS_PKI_SUCCESS;
}

#include "crypt_eal_codecs.h"

#define RSA_PEM_DIR "assets/pki_rsa_pem/"
#define CRL_BUNDLE_FILE "assets/pki/mulcrls.pem"

static int32_t ParseDemoVerifyByIssuerKey(HITLS_X509_Cert *cert)
{
    HITLS_X509_Cert *issuer = NULL;
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t ret;

    ret = HITLS_X509_ProviderCertParseFile(NULL, NULL, "PEM", RSA_PEM_DIR "inter.pem", &issuer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_CertCtrl(issuer, HITLS_X509_GET_PUBKEY, &pubKey, sizeof(pubKey));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertVerifyByPubKey(cert, pubKey);
    if (ret != HITLS_PKI_SUCCESS) {
    }

cleanup:
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    HITLS_X509_CertFree(issuer);
    return ret;
}

static int32_t ParseDemoCheckKey(HITLS_X509_Cert *cert)
{
    CRYPT_EAL_PkeyCtx *key = NULL;
    int32_t ret;

    ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        RSA_PEM_DIR "server.key.pem", NULL, 0, &key);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_CheckKey(cert, key);
    if (ret != HITLS_PKI_SUCCESS) {
    }
    CRYPT_EAL_PkeyFreeCtx(key);
    return ret;
}

int main(void)
{
    BSL_Buffer certPem = {0};
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_List *certBundle = NULL;
    HITLS_X509_List *crlBundle = NULL;
    int32_t ret;

    printf("=== PKI Parse Variants Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = PkiReadBinaryFile(RSA_PEM_DIR "server.pem", &certPem);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_ProviderCertParseBuff(NULL, NULL, "PEM", &certPem, &cert);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Parsed certificate from PEM buffer: %u bytes\n", certPem.dataLen);

    ret = HITLS_X509_ProviderCertParseBundleFile(NULL, NULL, "PEM", RSA_PEM_DIR "cert_chain.pem", &certBundle);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Parsed certificate bundle elements: %u\n", BSL_LIST_COUNT(certBundle));

    ret = HITLS_X509_CrlParseBundleFile(BSL_FORMAT_PEM, CRL_BUNDLE_FILE, &crlBundle);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Parsed CRL bundle elements: %u\n", BSL_LIST_COUNT(crlBundle));

    ret = ParseDemoVerifyByIssuerKey(cert);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = ParseDemoCheckKey(cert);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Verified server certificate by issuer public key and matched private key.\n");
    ret = 0;

cleanup:
    BSL_SAL_Free(certPem.data);
    HITLS_X509_CertFree(cert);
    BSL_LIST_FREE(certBundle, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(crlBundle, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
