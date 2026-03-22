/*
 * ML-KEM encapsulation and decapsulation demo.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"

#define MLKEM_PARAMETER_ID CRYPT_KEM_TYPE_MLKEM_768

static void MlkemPrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    uint32_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static CRYPT_EAL_PkeyCtx *MlkemNewCtx(void)
{
    return CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
}

static int32_t MlkemPrepareDecapsCtx(CRYPT_EAL_PkeyCtx **ctx)
{
    CRYPT_EAL_PkeyCtx *tmp = MlkemNewCtx();
    int32_t ret;

    if (tmp == NULL) {
        return -1;
    }
    ret = CRYPT_EAL_PkeySetParaById(tmp, MLKEM_PARAMETER_ID);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeyDecapsInit(tmp, NULL);
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

static int32_t MlkemPrepareEncapsCtx(CRYPT_EAL_PkeyCtx **ctx)
{
    CRYPT_EAL_PkeyCtx *tmp = MlkemNewCtx();
    int32_t ret;

    if (tmp == NULL) {
        return -1;
    }
    ret = CRYPT_EAL_PkeySetParaById(tmp, MLKEM_PARAMETER_ID);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeyEncapsInit(tmp, NULL);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    *ctx = tmp;
    return CRYPT_SUCCESS;

cleanup:
    CRYPT_EAL_PkeyFreeCtx(tmp);
    return ret;
}

int main(void)
{
    CRYPT_EAL_PkeyCtx *encapsCtx = NULL;
    CRYPT_EAL_PkeyCtx *decapsCtx = NULL;
    CRYPT_EAL_PkeyPub publicKey = {0};
    uint8_t *publicKeyBuf = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *encapsSecret = NULL;
    uint8_t *decapsSecret = NULL;
    uint32_t publicKeyLen = 0;
    uint32_t ciphertextLen = 0;
    uint32_t sharedSecretLen = 0;
    int32_t ret;

    printf("=== ML-KEM Encaps/Decaps Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = MlkemPrepareDecapsCtx(&decapsCtx);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = MlkemPrepareEncapsCtx(&encapsCtx);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    ret = CRYPT_EAL_PkeyCtrl(decapsCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &publicKeyLen, sizeof(publicKeyLen));
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeyCtrl(decapsCtx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ciphertextLen, sizeof(ciphertextLen));
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeyCtrl(decapsCtx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedSecretLen, sizeof(sharedSecretLen));
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    publicKeyBuf = malloc(publicKeyLen);
    ciphertext = malloc(ciphertextLen);
    encapsSecret = malloc(sharedSecretLen);
    decapsSecret = malloc(sharedSecretLen);
    if (publicKeyBuf == NULL || ciphertext == NULL || encapsSecret == NULL || decapsSecret == NULL) {
        ret = -1;
        goto cleanup;
    }

    publicKey.id = CRYPT_PKEY_ML_KEM;
    publicKey.key.kemEk.data = publicKeyBuf;
    publicKey.key.kemEk.len = publicKeyLen;

    /* Export the receiver's encapsulation key so the sender can create a ciphertext for it. */
    ret = CRYPT_EAL_PkeyGetPub(decapsCtx, &publicKey);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeySetPub(encapsCtx, &publicKey);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    /* The sender encapsulates once and gets both the ciphertext and its shared secret. */
    ret = CRYPT_EAL_PkeyEncaps(encapsCtx, ciphertext, &ciphertextLen, encapsSecret, &sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    /* The receiver decapsulates the ciphertext and must derive the same shared secret. */
    ret = CRYPT_EAL_PkeyDecaps(decapsCtx, ciphertext, ciphertextLen, decapsSecret, &sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    if (memcmp(encapsSecret, decapsSecret, sharedSecretLen) != 0) {
        printf("ML-KEM shared secret mismatch\n");
        ret = -1;
        goto cleanup;
    }

    printf("ML-KEM encapsulation and decapsulation succeeded.\n");
    printf("Ciphertext length: %u bytes\n", ciphertextLen);
    printf("Shared secret length: %u bytes\n", sharedSecretLen);
    MlkemPrintHex("Shared secret", encapsSecret, sharedSecretLen);
    ret = 0;

cleanup:
    free(decapsSecret);
    free(encapsSecret);
    free(ciphertext);
    free(publicKeyBuf);
    CRYPT_EAL_PkeyFreeCtx(encapsCtx);
    CRYPT_EAL_PkeyFreeCtx(decapsCtx);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
