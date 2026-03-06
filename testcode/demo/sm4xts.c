/* Copyright (c) 2025, Shandong University — School of Cyber Science and Technology
 * Contributor:  Haolin Du
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

#define SM4_XTS_KEY_LEN    32U
#define SM4_XTS_TWEAK_LEN  16U
#define SM4_XTS_DATA_LEN   1024U  // Maximum test data length

static const uint8_t DEMO_KEY[SM4_XTS_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const uint8_t DEMO_TWEAK[SM4_XTS_TWEAK_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// Test data
static uint8_t g_demoData[SM4_XTS_DATA_LEN] = {0};

static void PrintLastError(void)
{
    const char *file = NULL;
    uint32_t line = 0U;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %u\n", file, line);
}

static void PrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    printf("%s", label);
    uint32_t printLen = (len > 32U) ? 32U : len;
    for (uint32_t i = 0U; i < printLen; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32U) {
        printf("... (total %u bytes)", len);
    }
    printf("\n");
}

/* Helper to perform SM4-XTS operation */
static int DoCipherOp(CRYPT_EAL_CipherCtx *ctx, uint8_t *in, uint32_t inLen,
                      uint8_t *out, bool isEncrypt)
{
    uint32_t outLen = inLen;
    uint32_t finalLen = 0U;
    int ret;

    ret = CRYPT_EAL_CipherInit(ctx, (uint8_t *)DEMO_KEY, SM4_XTS_KEY_LEN,
                               (uint8_t *)DEMO_TWEAK, SM4_XTS_TWEAK_LEN, isEncrypt);
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

static int RunSm4XtsDemo(void)
{
    // use fixed-size array instead of malloc, initialize directly with ={0}
    uint8_t cipherText[SM4_XTS_DATA_LEN] = {0};
    uint8_t plainText[SM4_XTS_DATA_LEN] = {0};
    
    // Initialize test data (increment from 1 to 1024 bytes)
    for (uint32_t i = 0; i < SM4_XTS_DATA_LEN; i++) {
        g_demoData[i] = (uint8_t)(i % 256U);
    }

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_XTS);
    if (ctx == NULL) {
        printf("CipherNewCtx failed.\n");
        return -1;
    }

    /* Encrypt */
    if (DoCipherOp(ctx, (uint8_t *)g_demoData, SM4_XTS_DATA_LEN, cipherText, true) != CRYPT_SUCCESS) {
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return -1;
    }
    PrintHex("cipher text value is: ", cipherText, SM4_XTS_DATA_LEN);

    /* Decrypt */
    if (DoCipherOp(ctx, cipherText, SM4_XTS_DATA_LEN, plainText, false) != CRYPT_SUCCESS) {
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return -1;
    }
    PrintHex("decrypted plain text value is: ", plainText, SM4_XTS_DATA_LEN);

    // Verify result
    int finalRet = (memcmp(g_demoData, plainText, SM4_XTS_DATA_LEN) == 0) ? 0U : -1U;
    if (finalRet == 0U) {
        printf("SM4-XTS Test Passed!\n");
    } else {
        printf("SM4-XTS Test Failed: Plaintext mismatch.\n");
    }

    CRYPT_EAL_CipherFreeCtx(ctx);
    return finalRet;
}

int main(void)
{
    return RunSm4XtsDemo();
}
