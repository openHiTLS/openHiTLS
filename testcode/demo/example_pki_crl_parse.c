/*
 * PKI CRL parsing example.
 */

#include <stdio.h>
#include <stdint.h>
#include "bsl_list.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_types.h"

#define CRL_FILE "assets/pki/crl_v1.crl"

int main(void)
{
    HITLS_X509_Crl *crl = NULL;
    BSL_Buffer issuer = {0};
    BslList *revokeList = NULL;
    int32_t version = 0;
    int32_t ret;

    printf("=== PKI CRL Parse Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, CRL_FILE, &crl);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_VERSION, &version, sizeof(version));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_ISSUER_DN_STR, &issuer, sizeof(issuer));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_REVOKELIST, &revokeList, sizeof(revokeList));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Parsed CRL file: %s\n", CRL_FILE);
    printf("CRL version: v%d\n", version + 1);
    printf("Issuer: %s\n", issuer.data);
    printf("Revoked certificate entries: %u\n", BSL_LIST_COUNT(revokeList));
    ret = 0;

cleanup:
    BSL_SAL_Free(issuer.data);
    HITLS_X509_CrlFree(crl);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
