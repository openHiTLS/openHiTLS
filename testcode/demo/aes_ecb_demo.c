/* Copyright (c) 2025，Shandong University — School of Cyber Science and Technology
* Contributor:  Fuzhi Wang
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
#include "crypt_eal_cipher.h" // Header for symmetric encryption/decryption
#include "bsl_err.h"
#include "crypt_algid.h"     // Header for algorithm IDs
#include "crypt_errno.h"     // Header for error codes

// Define macros for constants to avoid magic numbers
#define AES_KEY_SIZE 16
#define BUFFER_SIZE 256
#define MODE_ENCRYPT 1
#define MODE_DECRYPT 0

// A helper function to print error location
static void PrintLastError(void)
{
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line); // Get the file name and line number of the error
    printf("Error occurred at file: %s, line: %u\n", file, line);
}

static int32_t AesEcbDemoVerify(const unsigned char *plain, const unsigned char *decrypted, uint32_t len)
{
    printf("--- Verifying Result ---\n");
    if (memcmp(plain, decrypted, len) != 0) {
        printf("Verification FAILED! Decrypted text does not match original plaintext.\n");
        return -1;
    }
    printf("Verification PASSED! The decrypted text matches the original.\n");
    return 0;
}

static int32_t AesEcbDemoEncrypt(CRYPT_EAL_CipherCtx *ctx, const unsigned char *in, uint32_t inLen,
                                 unsigned char *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t updateLen = *outLen;
    uint32_t finalLen = 0;
    uint32_t totalLen = 0;

    ret = CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &updateLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        return ret;
    }
    totalLen = updateLen;

    finalLen = *outLen - totalLen;
    ret = CRYPT_EAL_CipherFinal(ctx, out + totalLen, &finalLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        return ret;
    }

    *outLen = totalLen + finalLen;
    printf("\nCiphertext Length: %u\n\n", *outLen);
    return CRYPT_SUCCESS;
}

static int32_t AesEcbDemoDecrypt(CRYPT_EAL_CipherCtx *ctx, const unsigned char *in, uint32_t inLen,
                                 unsigned char *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t updateLen = *outLen;
    uint32_t finalLen = 0;
    uint32_t totalLen = 0;

    ret = CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &updateLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        return ret;
    }
    totalLen = updateLen;

    finalLen = *outLen - totalLen;
    ret = CRYPT_EAL_CipherFinal(ctx, out + totalLen, &finalLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        return ret;
    }

    *outLen = totalLen + finalLen;
    return CRYPT_SUCCESS;
}

static int32_t AesEcbDemoProcess(CRYPT_EAL_CipherCtx *ctx, const unsigned char *key,
                                 const unsigned char *plain, uint32_t plainLen)
{
    int32_t ret;
    unsigned char cipher[BUFFER_SIZE] = {0};
    unsigned char decrypted[BUFFER_SIZE] = {0};
    uint32_t cipherLen = BUFFER_SIZE;
    uint32_t decryptedLen = BUFFER_SIZE;

    printf("--- Starting AES-ECB Encryption ---\n");
    ret = CRYPT_EAL_CipherInit(ctx, key, AES_KEY_SIZE, NULL, 0, 1);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        return ret;
    }
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        return ret;
    }

    ret = AesEcbDemoEncrypt(ctx, plain, plainLen, cipher, &cipherLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    printf("--- Starting AES-ECB Decryption ---\n");
    ret = CRYPT_EAL_CipherInit(ctx, key, AES_KEY_SIZE, NULL, 0, 0);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        return ret;
    }
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        return ret;
    }

    ret = AesEcbDemoDecrypt(ctx, cipher, cipherLen, decrypted, &decryptedLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    printf("Decrypted Plaintext: \"%s\"\nDecrypted Length: %u\n\n", decrypted, decryptedLen);

    if (decryptedLen != plainLen) {
        return -1;
    }
    return AesEcbDemoVerify(plain, decrypted, plainLen);
}

static int32_t RunAesEcbDemo(void)
{
    CRYPT_EAL_CipherCtx *ctx = NULL;
    unsigned char plainTextData[] = "This is a test message for AES-ECB.";
    unsigned char key[AES_KEY_SIZE] = "a_different_key!";
    int32_t ret;

    printf("Original Plaintext: \"%s\"\nOriginal Length: %zu\n\n", plainTextData, sizeof(plainTextData) - 1);

    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
    if (ctx == NULL) {
        printf("CRYPT_EAL_CipherNewCtx failed.\n");
        PrintLastError();
        return -1;
    }

    ret = AesEcbDemoProcess(ctx, key, plainTextData, sizeof(plainTextData) - 1);

    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

int main(void)
{
    int32_t ret = RunAesEcbDemo();
    if (ret == 0) {
        printf("\nAES-ECB Demo finished successfully!\n");
    }
    return ret;
}