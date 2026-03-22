/*
 * PKI certificate parsing example.
 */

#include <stdio.h>
#include <stdint.h>
#include "bsl_sal.h"
#include "bsl_types.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_x509.h"

#define CHAIN_DIR "assets/tls_ecdsa_der/"

int main(void)
{
    HITLS_X509_Cert *cert = NULL;
    BSL_Buffer subject = {0};
    BSL_Buffer issuer = {0};
    BSL_Buffer serial = {0};
    BSL_Buffer beforeTime = {0};
    BSL_Buffer afterTime = {0};
    int32_t ret;

    printf("=== PKI Certificate Parse Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = HITLS_X509_ProviderCertParseFile(NULL, NULL, "ASN1", CHAIN_DIR "server.der", &cert);
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
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM_STR, &serial, sizeof(serial));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_BEFORE_TIME_STR, &beforeTime, sizeof(beforeTime));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_AFTER_TIME_STR, &afterTime, sizeof(afterTime));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    printf("Parsed certificate: %sserver.der\n", CHAIN_DIR);
    printf("Subject: %s\n", subject.data);
    printf("Issuer: %s\n", issuer.data);
    printf("Serial number: %s\n", serial.data);
    printf("Not before: %s\n", beforeTime.data);
    printf("Not after: %s\n", afterTime.data);
    ret = 0;

cleanup:
    BSL_SAL_Free(afterTime.data);
    BSL_SAL_Free(beforeTime.data);
    BSL_SAL_Free(serial.data);
    BSL_SAL_Free(issuer.data);
    BSL_SAL_Free(subject.data);
    HITLS_X509_CertFree(cert);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
