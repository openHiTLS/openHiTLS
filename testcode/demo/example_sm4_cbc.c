

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "crypt_eal_cipher.h" // Header file of the interfaces for symmetric encryption and decryption.
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h" // Algorithm ID list.
#include "crypt_eal_init.h"
#include "crypt_errno.h" // Error code list.

static void Sm4CbcPrintHex(const char *label, const uint8_t *data, uint32_t dataLen)
{
    printf("%s", label);
    for (uint32_t i = 0; i < dataLen; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int32_t Sm4CbcRunCipher(CRYPT_EAL_CipherCtx *ctx, const uint8_t *key, uint32_t keyLen,
    const uint8_t *iv, uint32_t ivLen, bool isEncrypt, const uint8_t *input, uint32_t inputLen,
    uint8_t *output, uint32_t outputSize, uint32_t *outputLen)
{
    int32_t ret;
    uint32_t updateLen = outputSize;
    uint32_t finalLen = 0;

    if (ctx == NULL || key == NULL || iv == NULL || input == NULL || output == NULL || outputLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* The encrypt and decrypt path share the same CBC state machine. */
    ret = CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, isEncrypt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CRYPT_EAL_CipherUpdate(ctx, input, inputLen, output, &updateLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    finalLen = outputSize - updateLen;
    ret = CRYPT_EAL_CipherFinal(ctx, output + updateLen, &finalLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    *outputLen = updateLen + finalLen;
    return CRYPT_SUCCESS;
}

int main(void)
{
    uint8_t data[10] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x1c, 0x14};
    uint8_t iv[16] = {0};
    uint8_t key[16] = {0};
    uint32_t dataLen = sizeof(data);
    uint8_t cipherText[100] = {0};
    uint8_t plainText[100] = {0};
    uint32_t cipherTextLen = 0;
    uint32_t plainTextLen = 0;
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = NULL;

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return ret;
    }

    Sm4CbcPrintHex("plain text to be encrypted: ", data, dataLen);

    /* One CBC context is enough because the demo runs encrypt/decrypt sequentially. */
    ctx = CRYPT_EAL_ProviderCipherNewCtx(NULL, CRYPT_CIPHER_SM4_CBC, NULL);
    if (ctx == NULL) {
        printf("CRYPT_EAL_ProviderCipherNewCtx failed.\n");
        ret = 1;
        goto EXIT;
    }
    ret = Sm4CbcRunCipher(ctx, key, sizeof(key), iv, sizeof(iv), true, data, dataLen,
        cipherText, sizeof(cipherText), &cipherTextLen);
    if (ret != CRYPT_SUCCESS) {
        printf("SM4-CBC encrypt failed: 0x%x\n", ret);
        goto EXIT;
    }

    Sm4CbcPrintHex("cipher text value is: ", cipherText, cipherTextLen);

    ret = Sm4CbcRunCipher(ctx, key, sizeof(key), iv, sizeof(iv), false, cipherText, cipherTextLen,
        plainText, sizeof(plainText), &plainTextLen);
    if (ret != CRYPT_SUCCESS) {
        printf("SM4-CBC decrypt failed: 0x%x\n", ret);
        goto EXIT;
    }

    Sm4CbcPrintHex("decrypted plain text value is: ", plainText, plainTextLen);

    if (plainTextLen != dataLen || memcmp(plainText, data, dataLen) != 0) {
        printf("plaintext comparison failed\n");
        ret = CRYPT_EAL_CIPHER_DATA_ERROR;
        goto EXIT;
    }
    printf("pass \n");

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
