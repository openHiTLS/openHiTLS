/* Copyright (c) 2025，Shandong University — School of Cyber Science and Technology
* Contributor:  Zengji Sun
 * Instructor:  Weijia Wang
*/
/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 * http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypt_eal_cipher.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "crypt_algid.h"

#define AES_XTS_KEY_LEN 64
#define AES_XTS_TWEAK_LEN 16
#define AES_XTS_DATA_LEN 32

static const uint8_t DEMO_KEY[AES_XTS_KEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
};

static const uint8_t DEMO_TWEAK[AES_XTS_TWEAK_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

static const uint8_t DEMO_DATA[AES_XTS_DATA_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

static void PrintLastError(void)
{
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %u\n", file, line);
}

static void PrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    printf("%s", label);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* Helper to perform AES-XTS operation */
static int DoCipherOp(CRYPT_EAL_CipherCtx *ctx, uint8_t *in, uint32_t inLen,
                      uint8_t *out, bool isEncrypt)
{
    uint32_t outLen = inLen;
    uint32_t finalLen = 0;
    int ret;

    ret = CRYPT_EAL_CipherInit(ctx, (uint8_t *)DEMO_KEY, AES_XTS_KEY_LEN,
                               (uint8_t *)DEMO_TWEAK, AES_XTS_TWEAK_LEN, isEncrypt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    finalLen = inLen - outLen;
    ret = CRYPT_EAL_CipherFinal(ctx, out + outLen, &finalLen);
    return ret;
}

static int RunAesXtsDemo(void)
{
    uint8_t cipherText[AES_XTS_DATA_LEN] = {0};
    uint8_t plainText[AES_XTS_DATA_LEN] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES256_XTS);

    if (ctx == NULL) {
        printf("CipherNewCtx failed.\n");
        return -1;
    }

    /* Encrypt */
    if (DoCipherOp(ctx, (uint8_t *)DEMO_DATA, AES_XTS_DATA_LEN, cipherText, true) != CRYPT_SUCCESS) {
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return -1;
    }
    PrintHex("cipher text value is: ", cipherText, AES_XTS_DATA_LEN);

    /* Decrypt */
    if (DoCipherOp(ctx, cipherText, AES_XTS_DATA_LEN, plainText, false) != CRYPT_SUCCESS) {
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return -1;
    }
    PrintHex("decrypted plain text value is: ", plainText, AES_XTS_DATA_LEN);

    int finalRet = (memcmp(DEMO_DATA, plainText, AES_XTS_DATA_LEN) == 0) ? 0 : -1;
    if (finalRet == 0) {
        printf("AES-XTS Test Passed!\n");
    } else {
        printf("AES-XTS Test Failed: Plaintext mismatch.\n");
    }

    CRYPT_EAL_CipherFreeCtx(ctx);
    return finalRet;
}

int main(void)
{
    return RunAesXtsDemo();
}
