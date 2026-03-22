/*
 * PKI CSR generation example.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "bsl_sal.h"
#include "bsl_types.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_errno.h"

static int32_t PkiGenerateRsa2048Key(CRYPT_EAL_PkeyCtx **key)
{
    static uint8_t exponent[] = {0x01, 0x00, 0x01};
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t ret;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_SIGN_OPERATE, NULL);
    if (ctx == NULL) {
        return -1;
    }

    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.bits = 2048;
    para.para.rsaPara.e = exponent;
    para.para.rsaPara.eLen = sizeof(exponent);

    ret = CRYPT_EAL_PkeySetPara(ctx, &para);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return ret;
    }

    *key = ctx;
    return HITLS_PKI_SUCCESS;
}

static int32_t PkiGenerateCsr(CRYPT_EAL_PkeyCtx *key, HITLS_X509_Csr **csr)
{
    HITLS_X509_Csr *tmp = NULL;
    HITLS_X509_DN dnCountry = {BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2};
    HITLS_X509_DN dnOrg = {BSL_CID_AT_ORGANIZATIONNAME, (uint8_t *)"openHiTLS Demo", 13};
    HITLS_X509_DN dnCN = {BSL_CID_AT_COMMONNAME, (uint8_t *)"openHiTLS Demo CSR", 18};
    int32_t ret;

    tmp = HITLS_X509_ProviderCsrNew(NULL, NULL);
    if (tmp == NULL) {
        return -1;
    }

    ret = HITLS_X509_CsrCtrl(tmp, HITLS_X509_SET_PUBKEY, key, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrCtrl(tmp, HITLS_X509_ADD_SUBJECT_NAME, &dnCountry, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrCtrl(tmp, HITLS_X509_ADD_SUBJECT_NAME, &dnOrg, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrCtrl(tmp, HITLS_X509_ADD_SUBJECT_NAME, &dnCN, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrSign(CRYPT_MD_SHA256, key, NULL, tmp);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    *csr = tmp;
    return HITLS_PKI_SUCCESS;

cleanup:
    HITLS_X509_CsrFree(tmp);
    return ret;
}

int main(void)
{
    CRYPT_EAL_PkeyCtx *key = NULL;
    HITLS_X509_Csr *csr = NULL;
    BSL_Buffer pem = {0};
    int32_t ret;

    printf("=== PKI CSR Generate Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = PkiGenerateRsa2048Key(&key);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    /*
     * PkiGenerateCsr internally demonstrates the Ctrl-driven generation
     * path: CsrNew -> CsrCtrl(SET_PUBKEY/ADD_SUBJECT_NAME) -> CsrSign.
     */
    ret = PkiGenerateCsr(key, &csr);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrVerify(csr);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrGenBuff(BSL_FORMAT_PEM, csr, &pem);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    printf("Generated CSR and exported PEM: %u bytes\n", pem.dataLen);
    ret = 0;

cleanup:
    BSL_SAL_Free(pem.data);
    HITLS_X509_CsrFree(csr);
    CRYPT_EAL_PkeyFreeCtx(key);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
