/* Copyright (c) 2025，Shandong University — School of Cyber Science and Technology
* Contributor: Zihao Mei
 * Instructor:  Weijia Wang
*/
/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"

#define BYTES_PER_LINE          16

/* Bundle the input and output buffers so encrypt/decrypt share one helper. */
typedef struct {
    const uint8_t *key;
    uint32_t keyLength;
    const uint8_t *nonce;
    uint32_t nonceLength;
    const uint8_t *inputData;
    uint32_t inputLength;
    uint8_t *outputData;
    uint32_t *outputLength;
} Chacha20Params;

static void DisplayHexadecimalData(const char *description, const uint8_t *dataBuffer, uint32_t dataLength)
{
    printf("%s [Length: %u]: ", description, dataLength);
    for (uint32_t index = 0; index < dataLength; index++) {
        printf("%02X", dataBuffer[index]);
        if (((index + 1) % BYTES_PER_LINE == 0) && (index + 1 < dataLength)) {
            printf("\n                     ");
        }
    }
    printf("\n");
}

static void Chacha20FreeBuffers(uint8_t *ciphertext, uint32_t cipherLen, uint8_t *decryptedText,
    uint32_t decryptedCap)
{
    if (ciphertext != NULL) {
        BSL_SAL_CleanseData(ciphertext, cipherLen);
        free(ciphertext);
    }
    if (decryptedText != NULL) {
        BSL_SAL_CleanseData(decryptedText, decryptedCap);
        free(decryptedText);
    }
}

static int32_t Chacha20Process(const Chacha20Params *params, int32_t encryptMode)
{
    if (params == NULL) {
        return CRYPT_NULL_INPUT;
    }

    CRYPT_EAL_CipherCtx *ctx = NULL;
    int32_t ret;

    // Create ChaCha20 context
    ctx = CRYPT_EAL_ProviderCipherNewCtx(NULL, CRYPT_CIPHER_CHACHA20_POLY1305, NULL);
    if (ctx == NULL) {
        printf("CRYPT_EAL_ProviderCipherNewCtx failed.\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }

    // Initialize context for encryption/decryption
    ret = CRYPT_EAL_CipherInit(ctx, params->key, params->keyLength,
                               params->nonce, params->nonceLength, encryptMode);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_CipherInit failed: 0x%x\n", ret);
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }

    // Process the data directly
    uint32_t outSize = *params->outputLength;
    ret = CRYPT_EAL_CipherUpdate(ctx, params->inputData, params->inputLength,
                                 params->outputData, &outSize);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_CipherUpdate failed: 0x%x\n", ret);
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }

    /* Stream ciphers finish in Update; there is no padding/final block handling here. */
    *params->outputLength = outSize;

    CRYPT_EAL_CipherFreeCtx(ctx);
    return CRYPT_SUCCESS;
}

static int ExecuteChacha20Demo(void)
{
    // Test data
    const uint8_t plaintext[] = "0123456789ABCDEFFEDCBA09876543210";
    const uint32_t plaintextLength = strlen((const char *)plaintext);

    // ChaCha20 key (32 bytes)
    const uint8_t key[32] = {
        0x1F, 0x3E, 0x5D, 0x7C, 0x9B, 0xBA, 0xD9, 0xF8,
        0x17, 0x36, 0x55, 0x74, 0x93, 0xB2, 0xD1, 0xF0,
        0x1F, 0x3E, 0x5D, 0x7C, 0x9B, 0xBA, 0xD9, 0xF8,
        0x17, 0x36, 0x55, 0x74, 0x93, 0xB2, 0xD1, 0xF0
    };

    // Nonce (12 bytes)
    const uint8_t nonce[12] = {
        0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81,
        0x92, 0xA3, 0xB4, 0xC5
    };

    // Allocate and zero-initialize ciphertext buffer
    uint8_t *ciphertext = (uint8_t *)malloc(plaintextLength);
    if (ciphertext == NULL) {
        printf("malloc failed for ciphertext.\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memset(ciphertext, 0, plaintextLength);

    // Allocate and zero-initialize decrypted text buffer (with null-terminator space)
    uint8_t *decryptedText = (uint8_t *)malloc(plaintextLength + 1);
    if (decryptedText == NULL) {
        printf("malloc failed for decryptedText.\n");
        Chacha20FreeBuffers(ciphertext, plaintextLength, NULL, 0);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memset(decryptedText, 0, plaintextLength + 1);

    // Display demonstration information
    printf("\n================ ChaCha20 Stream Cipher Demonstration ================\n\n");
    printf("[Encryption Parameters]\n");
    DisplayHexadecimalData("Key", key, (uint32_t)sizeof(key));
    DisplayHexadecimalData("Nonce", nonce, (uint32_t)sizeof(nonce));

    printf("\n[Encryption Process]\n");
    DisplayHexadecimalData("Original Plaintext", plaintext, plaintextLength);
    printf("Plaintext string: %s\n\n", plaintext);

    // Execute encryption
    Chacha20Params encryptParams = {
        .key = key,
        .keyLength = (uint32_t)sizeof(key),
        .nonce = nonce,
        .nonceLength = (uint32_t)sizeof(nonce),
        .inputData = plaintext,
        .inputLength = plaintextLength,
        .outputData = ciphertext,
        .outputLength = NULL
    };

    uint32_t ciphertextLength = plaintextLength;
    encryptParams.outputLength = &ciphertextLength;

    int32_t ret = Chacha20Process(&encryptParams, 1);
    if (ret != CRYPT_SUCCESS) {
        Chacha20FreeBuffers(ciphertext, plaintextLength, decryptedText, plaintextLength + 1);
        return ret;
    }

    // Display encryption results
    DisplayHexadecimalData("Encrypted Ciphertext", ciphertext, ciphertextLength);
    printf("Encryption completed, ciphertext length: %u bytes\n\n", ciphertextLength);

    printf("[Decryption Process]\n");

    /* Reuse the same key/nonce pair to validate round-trip correctness in one process. */
    Chacha20Params decryptParams = {
        .key = key,
        .keyLength = (uint32_t)sizeof(key),
        .nonce = nonce,
        .nonceLength = (uint32_t)sizeof(nonce),
        .inputData = ciphertext,
        .inputLength = plaintextLength,
        .outputData = decryptedText,
        .outputLength = NULL
    };

    uint32_t decryptedLength = plaintextLength;
    decryptParams.outputLength = &decryptedLength;

    ret = Chacha20Process(&decryptParams, 0);
    if (ret != CRYPT_SUCCESS) {
        Chacha20FreeBuffers(ciphertext, plaintextLength, decryptedText, plaintextLength + 1);
        return ret;
    }

    // Ensure decrypted text is properly terminated
    decryptedText[decryptedLength] = '\0';

    // Display decryption results
    DisplayHexadecimalData("Decrypted Plaintext", decryptedText, decryptedLength);
    printf("Decrypted string: %s\n", decryptedText);
    printf("Decryption completed, plaintext length: %u bytes\n\n", decryptedLength);

    // Verify lengths
    if (decryptedLength != plaintextLength) {
        Chacha20FreeBuffers(ciphertext, plaintextLength, decryptedText, plaintextLength + 1);
        return CRYPT_INCONSISTENT_OPERATION;
    }

    // Verify contents
    if (memcmp(plaintext, decryptedText, plaintextLength) != 0) {
        Chacha20FreeBuffers(ciphertext, plaintextLength, decryptedText, plaintextLength + 1);
        return CRYPT_INCONSISTENT_OPERATION;
    }

    printf("Verification successful: Decrypted result matches original plaintext exactly\n");
    printf("\n==================================================\n");

    /* One cleanup helper keeps the success and failure paths consistent. */
    Chacha20FreeBuffers(ciphertext, plaintextLength, decryptedText, plaintextLength + 1);
    return CRYPT_SUCCESS;
}

int main(void)
{
    int32_t ret;

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return ret;
    }

    ret = ExecuteChacha20Demo();
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
        return ret;
    }

    printf("\nDemo completed successfully.\n");
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return CRYPT_SUCCESS;
}
