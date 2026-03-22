/*
 * ML-DSA sign and verify demo.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"

#define MLDSA_PARAMETER_ID CRYPT_MLDSA_TYPE_MLDSA_44

static void MldsaPrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    uint32_t shown = len > 64 ? 64 : len;
    uint32_t i;

    printf("%s: ", label);
    for (i = 0; i < shown; ++i) {
        printf("%02x", data[i]);
    }
    if (shown < len) {
        printf("...");
    }
    printf("\n");
}

static CRYPT_EAL_PkeyCtx *MldsaNewCtx(void)
{
    return CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
}

static int32_t MldsaCreateSigner(CRYPT_EAL_PkeyCtx **ctx)
{
    CRYPT_EAL_PkeyCtx *tmp = MldsaNewCtx();
    int32_t ret;

    if (tmp == NULL) {
        return -1;
    }
    ret = CRYPT_EAL_PkeySetParaById(tmp, MLDSA_PARAMETER_ID);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeyGen(tmp);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    *ctx = tmp;
    return CRYPT_SUCCESS;

cleanup:
    CRYPT_EAL_PkeyFreeCtx(tmp);
    return ret;
}

static int32_t MldsaCreateVerifier(CRYPT_EAL_PkeyCtx *signer, CRYPT_EAL_PkeyCtx **verifier)
{
    CRYPT_EAL_PkeyCtx *tmp = MldsaNewCtx();
    CRYPT_EAL_PkeyPub pub = {0};
    uint8_t *pubKeyBuf = NULL;
    uint32_t pubKeyLen = 0;
    int32_t ret;

    if (tmp == NULL) {
        return -1;
    }
    ret = CRYPT_EAL_PkeySetParaById(tmp, MLDSA_PARAMETER_ID);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeyCtrl(signer, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    pubKeyBuf = malloc(pubKeyLen);
    if (pubKeyBuf == NULL) {
        ret = -1;
        goto cleanup;
    }

    pub.id = CRYPT_PKEY_ML_DSA;
    pub.key.mldsaPub.data = pubKeyBuf;
    pub.key.mldsaPub.len = pubKeyLen;
    ret = CRYPT_EAL_PkeyGetPub(signer, &pub);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeySetPub(tmp, &pub);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    free(pubKeyBuf);
    *verifier = tmp;
    return CRYPT_SUCCESS;

cleanup:
    free(pubKeyBuf);
    CRYPT_EAL_PkeyFreeCtx(tmp);
    return ret;
}

int main(void)
{
    static const uint8_t message[] = "openHiTLS ML-DSA signing example";
    CRYPT_EAL_PkeyCtx *signer = NULL;
    CRYPT_EAL_PkeyCtx *verifier = NULL;
    uint8_t *signature = NULL;
    uint32_t signatureLen;
    int32_t ret;

    printf("=== ML-DSA Sign/Verify Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = MldsaCreateSigner(&signer);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = MldsaCreateVerifier(signer, &verifier);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    signatureLen = CRYPT_EAL_PkeyGetSignLen(signer);
    signature = malloc(signatureLen);
    if (signature == NULL) {
        ret = -1;
        goto cleanup;
    }

    ret = CRYPT_EAL_PkeySign(signer, CRYPT_MD_SHA256, message, sizeof(message) - 1, signature, &signatureLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeyVerify(verifier, CRYPT_MD_SHA256, message, sizeof(message) - 1, signature, signatureLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    printf("ML-DSA signature verified successfully.\n");
    printf("Signature length: %u bytes\n", signatureLen);
    MldsaPrintHex("Signature", signature, signatureLen);
    ret = 0;

cleanup:
    free(signature);
    CRYPT_EAL_PkeyFreeCtx(verifier);
    CRYPT_EAL_PkeyFreeCtx(signer);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
