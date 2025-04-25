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
#include "crypt_eal_cipher.h" // Header file of the interfaces for symmetric encryption and decryption.
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h" // Algorithm ID list.
#include "crypt_errno.h" // Error code list.

void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line); // Obtain the name and number of lines of the error file.
    printf("failed at file %s at line %d\n", file, line);
}

int main(void)
{
    uint8_t data[10] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x1c, 0x14};
    uint8_t iv[16] = {0};
    uint8_t key[16] = {0};
    uint32_t dataLen = sizeof(data);
    uint8_t cipherText[100];
    uint8_t plainText[100];
    uint32_t outTotalLen = 0;
    uint32_t outLen = sizeof(cipherText);
    uint32_t cipherTextLen;
    int32_t ret;

    printf("plain text to be encrypted: ");
    for (uint32_t i = 0; i < dataLen; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");

    // Initialize the error code module.
    BSL_ERR_Init();

    /**
     * Before calling the algorithm APIs,
     * call the BSL_SAL_CallBack_Ctrl function to register the malloc and free functions.
     * Execute this step only once. If the memory allocation ability of Linux is available,
     * the two functions can be registered using Linux by default.
    */
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);

    // Create a context.
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
    if (ctx == NULL) {
        PrintLastError();
        BSL_ERR_DeInit();
        return 1;
    }
    /*
     * During initialization, the last input parameter can be true or false. true indicates encryption,
     * and false indicates decryption.
     */
    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true);
    if (ret != CRYPT_SUCCESS) {
        // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }
    // Set the padding mode.
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }
    /**
     * Enter the data to be calculated. This interface can be called for multiple times.
     * The input value of **outLen** is the length of the ciphertext,
     * and the output value is the amount of processed data.
     * 
    */
    ret = CRYPT_EAL_CipherUpdate(ctx, data, dataLen, cipherText, &outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    outTotalLen += outLen;
    outLen = sizeof(cipherText) - outTotalLen;

    ret = CRYPT_EAL_CipherFinal(ctx, cipherText + outTotalLen, &outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    outTotalLen += outLen;
    printf("cipher text value is: ");

    for (uint32_t i = 0; i < outTotalLen; i++) {
        printf("%02x", cipherText[i]);
    }
    printf("\n");

    // Start decryption.
    cipherTextLen = outTotalLen;
    outTotalLen = 0;
    outLen = sizeof(plainText);

    // When initializing the decryption function, set the last input parameter to false.
    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Set the padding mode, which must be the same as that for encryption.
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Enter the ciphertext data.
    ret = CRYPT_EAL_CipherUpdate(ctx, cipherText, cipherTextLen, plainText, &outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }
    outTotalLen += outLen;
    outLen = sizeof(plainText) - outTotalLen;

    // Decrypt the last segment of data and remove the filled content.
    ret = CRYPT_EAL_CipherFinal(ctx, plainText + outTotalLen, &outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    outTotalLen += outLen;

    printf("decrypted plain text value is: ");
    for (uint32_t i = 0; i < outTotalLen; i++) {
        printf("%02x", plainText[i]);
    }
    printf("\n");

    if (outTotalLen != dataLen || memcmp(plainText, data, dataLen) != 0) {
        printf("plaintext comparison failed\n");
        goto EXIT;
    }
    printf("pass \n");

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    BSL_ERR_DeInit();
    return ret;
}