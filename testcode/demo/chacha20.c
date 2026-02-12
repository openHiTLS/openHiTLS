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
#include "crypt_errno.h"

#define BYTES_PER_LINE          16

// ChaCha20 encryption parameters structure
typedef struct {
    const uint8_t* key;
    uint32_t keyLength;
    const uint8_t* nonce;
    uint32_t nonceLength;
    const uint8_t* inputData;
    uint32_t inputLength;
    uint8_t* outputData;
    uint32_t* outputLength;
} Chacha20Params;

void PrintLastError(void)
{
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %d\n", file, line);
}

// Hexadecimal data display utility
static void DisplayHexadecimalData(const char* description, const uint8_t* dataBuffer, uint32_t dataLength)
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

// Unified ChaCha20 encryption/decryption function
int Chacha20Process(const Chacha20Params* params, int encryptMode)
{
    if (params == NULL) {
        return CRYPT_NULL_INPUT;
    }

    CRYPT_EAL_CipherCtx* ctx = NULL;
    int ret;

    // Create ChaCha20 context
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    if (ctx == NULL) {
        PrintLastError();
        return CRYPT_MEM_ALLOC_FAIL;
    }

    // Initialize context for encryption/decryption
    ret = CRYPT_EAL_CipherInit(ctx, params->key, params->keyLength,
                               params->nonce, params->nonceLength, encryptMode);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }

    // Process the data directly
    uint32_t outSize = *params->outputLength;
    ret = CRYPT_EAL_CipherUpdate(ctx, params->inputData, params->inputLength,
                                 params->outputData, &outSize);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }

    // Note: For stream ciphers like ChaCha20, CRYPT_EAL_CipherFinal is not required
    // as stream ciphers don't have finalization steps like block cipher modes.
    // The entire data processing is completed in CipherUpdate.
    *params->outputLength = outSize;
    
    // Cleanup resources
    CRYPT_EAL_CipherFreeCtx(ctx);
    
    return CRYPT_SUCCESS;
}

// ChaCha20 encryption/decryption demonstration
static int ExecuteChacha20Demo(void)
{
    // Test data
    const uint8_t plaintext[] = "0123456789ABCDEFFEDCBA09876543210";
    uint32_t plaintextLength = (uint32_t)strlen((const char *)plaintext);

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
    uint8_t* ciphertext = (uint8_t*)malloc(plaintextLength);
    if (ciphertext == NULL) {
        PrintLastError();
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memset(ciphertext, 0, plaintextLength);

    // Allocate and zero-initialize decrypted text buffer (with null-terminator space)
    uint8_t* decryptedText = (uint8_t*)malloc(plaintextLength + 1);
    if (decryptedText == NULL) {
        PrintLastError();

        // Cleanup: decryptedText allocation failed, secure wipe and free ciphertext
        memset(ciphertext, 0, plaintextLength);
        free(ciphertext);
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
    uint32_t ciphertextLength = plaintextLength;

    Chacha20Params encryptParams = {
        .key = key,
        .keyLength = (uint32_t)sizeof(key),
        .nonce = nonce,
        .nonceLength = (uint32_t)sizeof(nonce),
        .inputData = plaintext,
        .inputLength = plaintextLength,
        .outputData = ciphertext,
        .outputLength = &ciphertextLength
    };

    int ret = Chacha20Process(&encryptParams, 1);
    if (ret != CRYPT_SUCCESS) {
        memset(ciphertext, 0, plaintextLength);
        memset(decryptedText, 0, plaintextLength + 1);
        free(ciphertext);
        free(decryptedText);
        return ret;
    }

    // Display encryption results
    DisplayHexadecimalData("Encrypted Ciphertext", ciphertext, ciphertextLength);
    printf("Encryption completed, ciphertext length: %u bytes\n\n", ciphertextLength);

    // Execute decryption
    printf("[Decryption Process]\n");

    uint32_t decryptedLength = plaintextLength;

    Chacha20Params decryptParams = {
        .key = key,
        .keyLength = (uint32_t)sizeof(key),
        .nonce = nonce,
        .nonceLength = (uint32_t)sizeof(nonce),
        .inputData = ciphertext,
        .inputLength = plaintextLength,
        .outputData = decryptedText,
        .outputLength = &decryptedLength
    };

    ret = Chacha20Process(&decryptParams, 0);
    if (ret != CRYPT_SUCCESS) {
        memset(ciphertext, 0, plaintextLength);
        memset(decryptedText, 0, plaintextLength + 1);
        free(ciphertext);
        free(decryptedText);
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
        memset(ciphertext, 0, plaintextLength);
        memset(decryptedText, 0, plaintextLength + 1);
        free(ciphertext);
        free(decryptedText);
        return CRYPT_INCONSISTENT_OPERATION;
    }

    // Verify contents
    if (memcmp(plaintext, decryptedText, plaintextLength) != 0) {
        memset(ciphertext, 0, plaintextLength);
        memset(decryptedText, 0, plaintextLength + 1);
        free(ciphertext);
        free(decryptedText);
        return CRYPT_INCONSISTENT_OPERATION;
    }

    printf("Verification successful: Decrypted result matches original plaintext exactly\n");
    printf("\n==================================================\n");

    // Free resources with secure wiping
    memset(ciphertext, 0, plaintextLength);
    memset(decryptedText, 0, plaintextLength + 1);
    free(ciphertext);
    free(decryptedText);
    return CRYPT_SUCCESS;
}

int main(void)
{
    printf("\n==============================================================\n");
    printf("      ChaCha20 Stream Cipher - OpenHiTLS Interface Demo        \n");
    printf("==============================================================\n");

    int ret = ExecuteChacha20Demo();
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_DeInit();
        return ret;
    }

    printf("\nDemo completed successfully! ChaCha20 stream cipher working properly via OpenHiTLS interfaces\n");
    BSL_ERR_DeInit();
    return CRYPT_SUCCESS;
}
