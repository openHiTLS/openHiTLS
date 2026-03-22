/*
 * ECDSA sign and verify demo.
 */

#include <stdint.h>
#include <stdio.h>

#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"

static void EcdsaPrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    uint32_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int32_t EcdsaCreateSigner(CRYPT_EAL_PkeyCtx **ctx)
{
    CRYPT_EAL_PkeyCtx *tmp = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA, CRYPT_EAL_PKEY_SIGN_OPERATE, NULL);
    int32_t ret;

    if (tmp == NULL) {
        return -1;
    }
    ret = CRYPT_EAL_PkeySetParaById(tmp, CRYPT_ECC_NISTP256);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmp);
        return ret;
    }
    ret = CRYPT_EAL_PkeyGen(tmp);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmp);
        return ret;
    }

    *ctx = tmp;
    return CRYPT_SUCCESS;
}

static int32_t EcdsaCreateVerifier(CRYPT_EAL_PkeyCtx *signer, CRYPT_EAL_PkeyCtx **verifier)
{
    CRYPT_EAL_PkeyCtx *tmp = NULL;
    CRYPT_EAL_PkeyPub pub = {0};
    uint8_t pubData[133] = {0};
    int32_t ret;

    tmp = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA, CRYPT_EAL_PKEY_SIGN_OPERATE, NULL);
    if (tmp == NULL) {
        return -1;
    }
    ret = CRYPT_EAL_PkeySetParaById(tmp, CRYPT_ECC_NISTP256);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    pub.id = CRYPT_PKEY_ECDSA;
    pub.key.eccPub.data = pubData;
    pub.key.eccPub.len = sizeof(pubData);
    ret = CRYPT_EAL_PkeyGetPub(signer, &pub);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeySetPub(tmp, &pub);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    *verifier = tmp;
    return CRYPT_SUCCESS;

cleanup:
    CRYPT_EAL_PkeyFreeCtx(tmp);
    return ret;
}

int main(void)
{
    static const uint8_t message[] = "openHiTLS ECDSA signing example";
    CRYPT_EAL_PkeyCtx *signer = NULL;
    CRYPT_EAL_PkeyCtx *verifier = NULL;
    uint8_t signature[128] = {0};
    uint32_t signatureLen;
    int32_t ret;

    printf("=== ECDSA Sign/Verify Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = EcdsaCreateSigner(&signer);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = EcdsaCreateVerifier(signer, &verifier);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    signatureLen = CRYPT_EAL_PkeyGetSignLen(signer);
    ret = CRYPT_EAL_PkeySign(signer, CRYPT_MD_SHA256, message, sizeof(message) - 1, signature, &signatureLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeyVerify(verifier, CRYPT_MD_SHA256, message, sizeof(message) - 1, signature, signatureLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    printf("ECDSA signature verified successfully.\n");
    EcdsaPrintHex("Signature", signature, signatureLen);
    ret = 0;

cleanup:
    CRYPT_EAL_PkeyFreeCtx(verifier);
    CRYPT_EAL_PkeyFreeCtx(signer);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
