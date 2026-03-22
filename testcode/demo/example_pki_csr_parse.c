/*
 * PKI CSR parsing example.
 */

#include <stdio.h>
#include <stdint.h>
#include "bsl_sal.h"
#include "bsl_types.h"
#include "bsl_uio.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_utils.h"

#define CSR_FILE "assets/pki/server.csr"

int main(void)
{
    HITLS_X509_Csr *csr = NULL;
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    BSL_UIO *uio = NULL;
    int32_t ret;

    printf("=== PKI CSR Parse Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = HITLS_X509_CsrParseFile(BSL_FORMAT_PEM, CSR_FILE, &csr);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrVerify(csr);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_PUBKEY, &pubKey, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    uio = BSL_UIO_New(BSL_UIO_FileMethod());
    if (uio == NULL) {
        ret = -1;
        goto cleanup;
    }
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_FILE_PTR, 0, (void *)stdout);
    if (ret != BSL_SUCCESS) {
        goto cleanup;
    }

    printf("Parsed and verified CSR: %s\n", CSR_FILE);
    printf("CSR details:\n");
    ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_CSR, csr, sizeof(csr), uio);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Public key extracted: %s\n", pubKey != NULL ? "yes" : "no");
    ret = 0;

cleanup:
    BSL_UIO_Free(uio);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    HITLS_X509_CsrFree(csr);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
