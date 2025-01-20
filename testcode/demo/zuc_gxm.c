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
    const uint8_t key[][32] = {
        {0}, 
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    };
    const uint8_t iv[][23] = {
        {0},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    };
    const uint32_t keyStream[][2][20] = {
        {   // GM/T 33133.1 ——2016
            {
                0x27bede74, 0x018082da,
            },
            {
                0x0657cfa0, 0x7096398b
            }
        },
        {   // ZUC-256 流密码算法 (184 bits iv)
            {
                0x58d03ad6, 0x2e032ce2, 0xdafc683a, 0x39bdcb03, 0x52a2bc67, 0xf1b7de74, 0x163ce3a1, 0x01ef5558, 0x9639d75b, 0x95fa681b,
                0x7f090df7, 0x56391ccc, 0x903b7612, 0x744d544c, 0x17bc3fad, 0x8b163b08, 0x21787c0b, 0x97775bb8, 0x4943c6bb, 0xe8ad8afd
            },
            {
                0x3356cbae, 0xd1a1c18b, 0x6baa4ffe, 0x343f777c, 0x9e15128f, 0x251ab65b, 0x949f7b26, 0xef7157f2, 0x96dd2fa9, 0xdf95e3ee,
                0x7a5be02e, 0xc32ba585, 0x505af316, 0xc2f9ded2, 0x7cdbd935, 0xe441ce11, 0x15fd0a80, 0xbb7aef67, 0x68989416, 0xb8fac8c2
            }
        },
        {    // An Addendum to the ZUC-256 Stream Cipher(128 bits iv)
            {
                0xe457e206, 0xcee79e16, 0x7da20fd0, 0x3bbb22cc, 0xa2ec34f0, 0xe4e12c0b, 0x0ad0fb23, 0x6051348a, 0xf9779552, 0x454c3dbb,
                0x397d19b3, 0x28390332, 0x11b9ae54, 0x6094770b, 0x5016e134, 0x620ebf4a, 0x302c9be3, 0xb65db142, 0x2b564caa, 0x9caeca83
            },
            {
                0x7f860542, 0x9c82e263, 0x4ad9a83a, 0xe7d711f6, 0x4eba1791, 0xdfa21089, 0x78d9af94, 0x124a3eee, 0x31feb686, 0xbe91bfd5,
                0x148b5e71, 0x9ce309ec, 0x21238b2d, 0xec2acee4, 0xdf347052, 0x2c5ac5c3, 0x3dc68a27, 0x05c09c6f, 0x2396a67b, 0x091ca2e0
            }
        }
    };
    uint8_t cipherText[100] = {0};
    uint8_t data[100] = {0};
    uint32_t dataLen = 8;
    uint8_t plainText[100] = {0};
    uint32_t outTotalLen = 0;
    uint32_t outLen = sizeof(cipherText);
    uint32_t cipherTextLen;
    int32_t ret;
    uint8_t sessionID[32];
    uint8_t clientTS[32];
    uint8_t serverTS[32];
    uint8_t AAD[96];
    memcpy(AAD, sessionID, 32);
    memcpy(AAD + 32, clientTS, 32);
    memcpy(AAD + 64, serverTS, 32);
    uint8_t tag1[16];
    uint8_t tag2[16];

    printf("plain text to be encrypted: ");
    for (uint32_t i = 0; i < dataLen; i++) {
        printf("0x%02x ", plainText[i]);
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
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC_CB_FUNC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE_CB_FUNC, free);

    CRYPT_EAL_CipherCtx *ctx;

    // Create a context ZUC128_GXM.
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ZUC128_GXM);
    if (ctx == NULL) {
        PrintLastError();
        BSL_ERR_DeInit();
        return 1;
    }
    for(uint8_t j = 0; j < 2; j++){
        /*
        * During initialization, the last input parameter can be true or false. true indicates encryption,
        * and false indicates decryption.
        */
        outTotalLen = 0;
        outLen = sizeof(cipherText);
        ret = CRYPT_EAL_CipherInit(ctx, key[j], 16, iv[j], 16, true);
        if (ret != CRYPT_SUCCESS) {
            // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, AAD, 96);
        if (ret != CRYPT_SUCCESS) {
            // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }
        /**
         * Enter the data to be calculated. This interface can be called for multiple times.
         * The input value of **outLen** is the length of the ciphertext,
         * and the output value is the amount of processed data.
         * 
        */
        ret = CRYPT_EAL_CipherUpdate(ctx, plainText, dataLen, cipherText, &outLen);
        if (ret != CRYPT_SUCCESS) {
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        outTotalLen += outLen;
        outLen = sizeof(cipherText) - outTotalLen;

        // Get tag1, set state to final
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag1, 16);
        if (ret != CRYPT_SUCCESS) {
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }


        outLen = 0;
        outTotalLen += outLen;
        printf("cipher text value is: ");

        for (uint32_t i = 0; i < outTotalLen; i++) {
            printf("0x%02x ", cipherText[i]);
        }
        printf("\n");

        // Start decryption.
        cipherTextLen = outTotalLen;
        outTotalLen = 0;
        outLen = sizeof(plainText);

        // When initializing the decryption function, set the last input parameter to false.
        ret = CRYPT_EAL_CipherInit(ctx, key[j], 16, iv[j], 16, false);
        if (ret != CRYPT_SUCCESS) {
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }
        
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, AAD, 96);
        if (ret != CRYPT_SUCCESS) {
            // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        // Enter the ciphertext data.
        ret = CRYPT_EAL_CipherUpdate(ctx, cipherText, dataLen, plainText, &outLen);
        if (ret != CRYPT_SUCCESS) {
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }
        outTotalLen += outLen;
        outLen = sizeof(plainText) - outTotalLen;

        // Get tag2, set state to final
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag2, 16);
        if (ret != CRYPT_SUCCESS) {
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        outLen = 0;
        outTotalLen += outLen;

        printf("decrypted plain text value is: ");
        for (uint32_t i = 0; i < outTotalLen; i++) {
            printf("0x%02x ", plainText[i]);
        }
        printf("\n");

        if (outTotalLen != dataLen || memcmp(plainText, data, dataLen) != 0) {
            printf("plaintext comparison failed\n");
            goto EXIT;
        }
        if(memcmp(tag1, tag2, 16) != 0){
            printf("tag comparison failed\n");
            goto EXIT;
        }
        printf("ZUC128 key %d pass \n", j);
    }
    CRYPT_EAL_CipherFreeCtx(ctx);
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_ZUC256_GXM);
    dataLen = 80 - 16; // inithash table = 16 bytes
    if (ctx == NULL) {
        PrintLastError();
        BSL_ERR_DeInit();
        return 1;
    }
    for(uint8_t j = 0; j < 2; j++){
        /*
        * During initialization, the last input parameter can be true or false. true indicates encryption,
        * and false indicates decryption.
        */
        outTotalLen = 0;
        outLen = sizeof(cipherText);
        ret = CRYPT_EAL_CipherInit(ctx, key[j], 32, iv[j], 23, true);
        if (ret != CRYPT_SUCCESS) {
            // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
            printf("1 error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }
    
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, AAD, 96);
        if (ret != CRYPT_SUCCESS) {
            // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
            printf("2 error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }
        /**
         * Enter the data to be calculated. This interface can be called for multiple times.
         * The input value of **outLen** is the length of the ciphertext,
         * and the output value is the amount of processed data.
         * 
        */
        ret = CRYPT_EAL_CipherUpdate(ctx, plainText, dataLen, cipherText, &outLen);
        if (ret != CRYPT_SUCCESS) {
            printf("3 error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        outTotalLen += outLen;
        outLen = sizeof(cipherText) - outTotalLen;

        // Get tag1, set state to final
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag1, 16);
        if (ret != CRYPT_SUCCESS) {
            printf("4 error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        outLen = 0;
        outTotalLen += outLen;
        printf("cipher text value is: ");

        for (uint32_t i = 0; i < outTotalLen; i++) {
            printf("0x%02x ", cipherText[i]);
        }
        printf("\n");

        // Start decryption.
        cipherTextLen = outTotalLen;
        outTotalLen = 0;
        outLen = sizeof(plainText);

        // When initializing the decryption function, set the last input parameter to false.
        ret = CRYPT_EAL_CipherInit(ctx, key[j], 32, iv[j], 23, false);
        if (ret != CRYPT_SUCCESS) {
            printf("1 error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, AAD, 96);
        if (ret != CRYPT_SUCCESS) {
            // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
            printf("2 error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        // Enter the ciphertext data.
        ret = CRYPT_EAL_CipherUpdate(ctx, cipherText, dataLen, plainText, &outLen);
        if (ret != CRYPT_SUCCESS) {
            printf("3 error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }
        outTotalLen += outLen;
        outLen = sizeof(plainText) - outTotalLen;

        // Get tag2, set state to final
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag2, 16);
        if (ret != CRYPT_SUCCESS) {
            printf("4 error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        outLen = 0;
        outTotalLen += outLen;

        printf("decrypted plain text value is: ");
        for (uint32_t i = 0; i < outTotalLen; i++) {
            printf("0x%02x ", plainText[i]);
        }
        printf("\n");

        if (outTotalLen != dataLen || memcmp(plainText, data, dataLen) != 0) {
            printf("plaintext comparison failed\n");
            goto EXIT;
        }
        if(memcmp(tag1, tag2, 16) != 0){
            printf("tag comparison failed\n");
            goto EXIT;
        }
        printf("ZUC256 23B IV key %d pass \n", j);
    }
    for(uint8_t j = 0; j < 2; j++){
        /*
        * During initialization, the last input parameter can be true or false. true indicates encryption,
        * and false indicates decryption.
        */
        outTotalLen = 0;
        outLen = sizeof(cipherText);
        ret = CRYPT_EAL_CipherInit(ctx, key[j], 32, iv[j], 16, true);
        if (ret != CRYPT_SUCCESS) {
            // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, AAD, 96);
        if (ret != CRYPT_SUCCESS) {
            // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }
        /**
         * Enter the data to be calculated. This interface can be called for multiple times.
         * The input value of **outLen** is the length of the ciphertext,
         * and the output value is the amount of processed data.
         * 
        */
        ret = CRYPT_EAL_CipherUpdate(ctx, plainText, dataLen, cipherText, &outLen);
        if (ret != CRYPT_SUCCESS) {
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        outTotalLen += outLen;
        outLen = sizeof(cipherText) - outTotalLen;

        // Get tag1, set state to final
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag1, 16);
        if (ret != CRYPT_SUCCESS) {
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        outLen = 0;
        outTotalLen += outLen;
        printf("cipher text value is: ");

        for (uint32_t i = 0; i < outTotalLen; i++) {
            printf("0x%02x ", cipherText[i]);
        }
        printf("\n");

        // Start decryption.
        cipherTextLen = outTotalLen;
        outTotalLen = 0;
        outLen = sizeof(plainText);

        // When initializing the decryption function, set the last input parameter to false.
        ret = CRYPT_EAL_CipherInit(ctx, key[j], 32, iv[j], 16, false);
        if (ret != CRYPT_SUCCESS) {
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, AAD, 96);
        if (ret != CRYPT_SUCCESS) {
            // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        // Enter the ciphertext data.
        ret = CRYPT_EAL_CipherUpdate(ctx, cipherText, dataLen, plainText, &outLen);
        if (ret != CRYPT_SUCCESS) {
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }
        outTotalLen += outLen;
        outLen = sizeof(plainText) - outTotalLen;

        // get tag2, set state to final
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag2, 16);
        if (ret != CRYPT_SUCCESS) {
            printf("error code is %d\n", ret);
            PrintLastError();
            goto EXIT;
        }

        outLen = 0;
        outTotalLen += outLen;

        printf("decrypted plain text value is: ");
        for (uint32_t i = 0; i < outTotalLen; i++) {
            printf("0x%02x ", plainText[i]);
        }
        printf("\n");

        if (outTotalLen != dataLen || memcmp(plainText, data, dataLen) != 0) {
            printf("plaintext comparison failed\n");
            goto EXIT;
        }
        if(memcmp(tag1, tag2, 16) != 0){
            printf("tag comparison failed\n");
            goto EXIT;
        }
        printf("ZUC256 16B IV %d pass \n", j);
    }
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    BSL_ERR_DeInit();
    return ret;
}