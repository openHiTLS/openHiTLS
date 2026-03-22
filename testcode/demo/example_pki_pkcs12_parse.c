/*
 * PKI PKCS12 parsing example.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "bsl_types.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_pkcs12.h"
#include "hitls_pki_x509.h"

#define PKCS12_FILE "assets/pki/p12_1.p12"

int main(void)
{
    char password[] = "";
    BSL_Buffer pwd = {(uint8_t *)password, (uint32_t)strlen(password)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &pwd, .macPwd = &pwd};
    HITLS_PKCS12 *p12 = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *key = NULL;
    BSL_Buffer subject = {0};
    BSL_Buffer issuer = {0};
    int32_t ret;

    printf("=== PKI PKCS12 Parse Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = HITLS_PKCS12_ProviderParseFile(NULL, NULL, "ASN1", PKCS12_FILE, &pwdParam, &p12, true);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_CERT, &cert, sizeof(cert));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_KEY, &key, sizeof(key));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CheckKey(cert, key);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_DN_STR, &subject, sizeof(subject));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN_STR, &issuer, sizeof(issuer));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    printf("Parsed PKCS12 file: %s\n", PKCS12_FILE);
    printf("Entity certificate subject: %s\n", subject.data);
    printf("Entity certificate issuer: %s\n", issuer.data);
    printf("Entity certificate/private key match: yes\n");
    ret = 0;

cleanup:
    BSL_SAL_Free(issuer.data);
    BSL_SAL_Free(subject.data);
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_PKCS12_Free(p12);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
