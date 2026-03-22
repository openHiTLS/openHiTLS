/*
 * RSA Encryption and Decryption Example
 * This example demonstrates RSA-2048 public key encryption and private key decryption
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypt_eal_pkey.h"
#include "crypt_eal_init.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_types.h"

void PrintHex(const char *label, uint8_t *data, uint32_t len)
{
    printf("%s: ", label);
    for (uint32_t i = 0; i < len && i < 64; i++) {  /* Limit to 64 bytes for readability */
        printf("%02x", data[i]);
    }
    if (len > 64) {
        printf("...");
    }
    printf("\n");
}

int main(void)
{
    int32_t ret;
    int32_t exitCode = -1;
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    /* Message to encrypt (should be smaller than RSA key size - padding overhead)
     * For RSA-2048 with PKCS#1 padding, max plaintext is 245 bytes */
    uint8_t plaintext[] = "Secret message: RSA encryption protects this data!";
    uint32_t plaintextLen = sizeof(plaintext) - 1;

    /* Buffers for encryption and decryption */
    uint8_t ciphertext[512];  /* RSA-2048 produces 256-byte ciphertext */
    uint8_t decrypted[512];
    uint32_t ciphertextLen = sizeof(ciphertext);
    uint32_t decryptedLen = sizeof(decrypted);

    printf("=== RSA-2048 Encryption/Decryption Example ===\n\n");

    /* Initialize cryptographic library */
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed, error code: 0x%x\n", ret);
        return -1;
    }

    printf("Plaintext: %s\n", plaintext);
    printf("Plaintext length: %u bytes\n\n", plaintextLen);

    /* Create RSA context */
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_CIPHER_OPERATE, NULL);
    if (ctx == NULL) {
        printf("CRYPT_EAL_PkeyNewCtx failed\n");
        ret = -1;
        goto cleanup;
    }

    /* Set RSA key size to 2048 bits */
    static uint8_t exponent[] = {0x01, 0x00, 0x01};
    CRYPT_EAL_PkeyPara para;
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.bits = 2048;
    para.para.rsaPara.e = exponent;
    para.para.rsaPara.eLen = sizeof(exponent);

    ret = CRYPT_EAL_PkeySetPara(ctx, &para);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeySetPara failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    printf("RSA parameters set: 2048-bit key\n");

    /* Generate RSA key pair */
    printf("Generating RSA-2048 key pair (this may take a few seconds)...\n");
    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyGen failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    printf("RSA key pair generated successfully!\n\n");

    int32_t padType = CRYPT_RSAES_PKCSV15;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_PADDING, &padType, sizeof(padType));
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyCtrl (SET_RSA_PADDING) failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    /* ============================================
     * ENCRYPTION (using public key)
     * ============================================ */

    printf("=== Encryption (with Public Key) ===\n");

    ret = CRYPT_EAL_PkeyEncrypt(ctx, plaintext, plaintextLen, ciphertext, &ciphertextLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyEncrypt failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    printf("Encryption successful!\n");
    printf("Ciphertext length: %u bytes (%u bits)\n", ciphertextLen, ciphertextLen * 8);
    PrintHex("Ciphertext", ciphertext, ciphertextLen);
    printf("\n");

    /* ============================================
     * DECRYPTION (using private key)
     * ============================================ */

    printf("=== Decryption (with Private Key) ===\n");

    decryptedLen = sizeof(decrypted);
    ret = CRYPT_EAL_PkeyDecrypt(ctx, ciphertext, ciphertextLen, decrypted, &decryptedLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyDecrypt failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    printf("Decryption successful!\n");
    printf("Decrypted length: %u bytes\n", decryptedLen);
    decrypted[decryptedLen] = '\0';
    printf("Decrypted text: %s\n\n", (char *)decrypted);

    /* Verify the result */
    if (decryptedLen == plaintextLen &&
        memcmp(decrypted, plaintext, plaintextLen) == 0) {
        printf("✓ Verification successful: Decrypted data matches original plaintext!\n");
        exitCode = 0;
    } else {
        printf("✗ Verification failed: Data mismatch!\n");
        exitCode = -1;
        goto cleanup;
    }

    /* Get public key */
    CRYPT_EAL_PkeyPub publicKey;
    ret = CRYPT_EAL_PkeyGetPub(ctx, &publicKey);
    if (ret == CRYPT_SUCCESS) {
        printf("Public key exported successfully\n");
        printf("Public key type: RSA\n");
    }

    /* Get private key */
    CRYPT_EAL_PkeyPrv privateKey;
    ret = CRYPT_EAL_PkeyGetPrv(ctx, &privateKey);
    if (ret == CRYPT_SUCCESS) {
        printf("Private key exported successfully\n");
    }

cleanup:
    if (ctx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);

    return exitCode;
}
