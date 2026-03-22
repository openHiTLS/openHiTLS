/*
 * AES-CBC with PKCS7 padding example.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"

static void AesCbcPrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    uint32_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void)
{
    static const uint8_t plaintext[] = "AES-CBC with PKCS7 padding example";
    uint8_t key[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    uint8_t iv[16] = {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    uint8_t ciphertext[128] = {0};
    uint8_t decrypted[128] = {0};
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint32_t outLen = 0;
    uint32_t totalLen = 0;
    uint32_t cipherLen = 0;
    int32_t ret;

    printf("=== AES-CBC PKCS7 Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    printf("Plaintext: %s\n", plaintext);
    AesCbcPrintHex("Key", key, sizeof(key));
    AesCbcPrintHex("IV", iv, sizeof(iv));

    ctx = CRYPT_EAL_ProviderCipherNewCtx(NULL, CRYPT_CIPHER_AES128_CBC, NULL);
    if (ctx == NULL) {
        ret = -1;
        goto cleanup;
    }

    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    outLen = sizeof(ciphertext);
    ret = CRYPT_EAL_CipherUpdate(ctx, plaintext, sizeof(plaintext) - 1, ciphertext, &outLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    totalLen = outLen;
    outLen = sizeof(ciphertext) - totalLen;
    ret = CRYPT_EAL_CipherFinal(ctx, ciphertext + totalLen, &outLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    totalLen += outLen;
    cipherLen = totalLen;

    printf("\nEncryption successful.\n");
    AesCbcPrintHex("Ciphertext", ciphertext, cipherLen);

    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    outLen = sizeof(decrypted);
    ret = CRYPT_EAL_CipherUpdate(ctx, ciphertext, cipherLen, decrypted, &outLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    totalLen = outLen;
    outLen = sizeof(decrypted) - totalLen;
    ret = CRYPT_EAL_CipherFinal(ctx, decrypted + totalLen, &outLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    totalLen += outLen;

    printf("\nDecryption successful.\n");
    printf("Recovered plaintext: %.*s\n", (int)totalLen, decrypted);

    if (totalLen != sizeof(plaintext) - 1 || memcmp(decrypted, plaintext, sizeof(plaintext) - 1) != 0) {
        printf("plaintext comparison failed\n");
        ret = -1;
        goto cleanup;
    }

    printf("PKCS7 padding round-trip verified.\n");
    ret = 0;

cleanup:
    CRYPT_EAL_CipherFreeCtx(ctx);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
