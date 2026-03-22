/*
 * AES-GCM Authenticated Encryption Example
 * This example demonstrates AES-256-GCM authenticated encryption and decryption
 *
 * GCM (Galois/Counter Mode) provides both confidentiality and authenticity
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypt_eal_cipher.h"
#include "crypt_eal_init.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_err.h"

void PrintHex(const char *label, uint8_t *data, uint32_t len)
{
    printf("%s: ", label);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void)
{
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = NULL;

    /* Plaintext message */
    uint8_t plaintext[] = "This is a secret message protected by AES-GCM!";
    uint32_t plaintextLen = sizeof(plaintext) - 1;

    /* Key: 32 bytes for AES-256 */
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    /* IV (Initialization Vector): 12 bytes recommended for GCM */
    uint8_t iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b
    };

    /* AAD (Additional Authenticated Data): Optional data that is authenticated but not encrypted */
    uint8_t aad[] = "Additional authenticated data";
    uint32_t aadLen = sizeof(aad) - 1;

    /* Buffers for encryption and decryption */
    uint8_t ciphertext[128];
    uint8_t decrypted[128];
    uint8_t tag[16];  /* Authentication tag: 16 bytes recommended */
    uint8_t verifyTag[16];
    uint32_t ciphertextLen, decryptedLen;
    uint32_t outLen;

    printf("=== AES-256-GCM Authenticated Encryption Example ===\n\n");

    /* Initialize cryptographic library */
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed, error code: 0x%x\n", ret);
        return -1;
    }

    printf("Plaintext: %s\n", plaintext);
    printf("Plaintext length: %u bytes\n", plaintextLen);
    printf("AAD: %s\n", aad);
    printf("AAD length: %u bytes\n", aadLen);
    PrintHex("IV", iv, sizeof(iv));
    PrintHex("Key", key, sizeof(key));
    printf("\n");

    /* ============================================
     * ENCRYPTION
     * ============================================ */

    printf("=== Encryption ===\n");

    /* Create AES-256-GCM context */
    ctx = CRYPT_EAL_ProviderCipherNewCtx(NULL, CRYPT_CIPHER_AES256_GCM, NULL);
    if (ctx == NULL) {
        printf("CRYPT_EAL_CipherNewCtx failed\n");
        ret = -1;
        goto cleanup;
    }

    /* Initialize for encryption */
    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_CipherInit (encrypt) failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    /* Set AAD (Additional Authenticated Data) */
    if (aadLen > 0) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, aadLen);
        if (ret != CRYPT_SUCCESS) {
            printf("CRYPT_EAL_CipherCtrl (SET_AAD) failed, error code: 0x%x\n", ret);
            goto cleanup;
        }
        printf("AAD set successfully\n");
    }

    /* Encrypt the plaintext */
    outLen = sizeof(ciphertext);
    ret = CRYPT_EAL_CipherUpdate(ctx, plaintext, plaintextLen, ciphertext, &outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_CipherUpdate (encrypt) failed, error code: 0x%x\n", ret);
        goto cleanup;
    }
    ciphertextLen = outLen;

    /* Get authentication tag */
    uint32_t tagLen = sizeof(tag);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_CipherCtrl (GET_GCM_TAG) failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    printf("\nEncryption successful!\n");
    printf("Ciphertext length: %u bytes\n", ciphertextLen);
    PrintHex("Ciphertext", ciphertext, ciphertextLen);
    printf("Authentication tag length: %u bytes\n", tagLen);
    PrintHex("Authentication tag", tag, tagLen);
    printf("\n");

    /* ============================================
     * DECRYPTION
     * ============================================ */

    printf("=== Decryption ===\n");

    /* Re-initialize for decryption */
    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_CipherInit (decrypt) failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    /* Set the same AAD */
    if (aadLen > 0) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, aadLen);
        if (ret != CRYPT_SUCCESS) {
            printf("CRYPT_EAL_CipherCtrl (SET_AAD) failed, error code: 0x%x\n", ret);
            goto cleanup;
        }
        printf("AAD set successfully\n");
    }

    /* Set the expected authentication tag before decryption */
    /* Decrypt the ciphertext */
    outLen = sizeof(decrypted);
    ret = CRYPT_EAL_CipherUpdate(ctx, ciphertext, ciphertextLen, decrypted, &outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_CipherUpdate (decrypt) failed, error code: 0x%x\n", ret);
        goto cleanup;
    }
    decryptedLen = outLen;

    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, verifyTag, tagLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_CipherCtrl (GET_TAG after decrypt) failed, error code: 0x%x\n", ret);
        goto cleanup;
    }
    if (memcmp(verifyTag, tag, tagLen) != 0) {
        printf("\n✗ Authentication failed: Tag mismatch!\n");
        ret = -1;
        goto cleanup;
    }
    printf("Authentication tag verified\n");

    printf("\nDecryption successful!\n");
    printf("Decrypted length: %u bytes\n", decryptedLen);
    PrintHex("Decrypted", decrypted, decryptedLen);
    printf("\n");

    /* Verify the result */
    if (decryptedLen == plaintextLen &&
        memcmp(decrypted, plaintext, plaintextLen) == 0) {
        printf("✓ Verification successful!\n");
        printf("✓ Authentication tag verified: Data integrity confirmed!\n");
        printf("✓ Decrypted data matches original plaintext!\n");
        ret = 0;
    } else {
        printf("✗ Verification failed: Data mismatch!\n");
        ret = -1;
    }

cleanup:
    if (ctx != NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);

    return ret;
}
