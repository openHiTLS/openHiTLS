/* Copyright (c) 2025, Shandong University — School of Cyber Science and Technology
 * Contributor: Ziyi Wang
 * Instructor:  Weijia Wang
 *
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
#include <stdint.h>
#include <string.h>

#include "crypt_eal_cipher.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "bsl_err.h"

static const uint8_t DATA[] = "OpenHiTLS";

static const uint8_t KEY[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static const uint8_t IV[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};

typedef struct {
    const uint8_t *in;
    uint32_t inLen;
    uint8_t *out;
    uint32_t outCap;
    uint32_t outLen;
} CryptBuf;

static void PrintLastError(void)
{
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %u\n", file, line);
}

static void PrintHex(const char *label, const uint8_t *buf, uint32_t len)
{
    printf("%s: ", label);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static int32_t AesCfbCrypt(CRYPT_EAL_CipherCtx *ctx, int32_t enc, CryptBuf *buf)
{
    uint32_t keyLen = (uint32_t)sizeof(KEY);
    uint32_t ivLen = (uint32_t)sizeof(IV);

    int32_t ret = CRYPT_EAL_CipherInit(ctx, KEY, keyLen, IV, ivLen, (enc != 0));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t total = 0;
    uint32_t outLen = buf->outCap;

    ret = CRYPT_EAL_CipherUpdate(ctx, buf->in, buf->inLen, buf->out, &outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    total += outLen;
    outLen = buf->outCap - total;

    ret = CRYPT_EAL_CipherFinal(ctx, buf->out + total, &outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    total += outLen;
    buf->outLen = total;
    return CRYPT_SUCCESS;
}

static int32_t RunDemo(CRYPT_EAL_CipherCtx *ctx)
{
    uint8_t cipherText[128];
    uint8_t plainText[128];
    CryptBuf buf;
    int32_t ret;

    uint32_t dataLen = (uint32_t)(sizeof(DATA) - 1);
    PrintHex("plain text value is", DATA, dataLen);

    buf.in = DATA;
    buf.inLen = dataLen;
    buf.out = cipherText;
    buf.outCap = (uint32_t)sizeof(cipherText);
    buf.outLen = 0;

    ret = AesCfbCrypt(ctx, 1, &buf);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        return ret;
    }

    PrintHex("cipher text value is", cipherText, buf.outLen);

    uint32_t cipherLen = buf.outLen;
    buf.in = cipherText;
    buf.inLen = cipherLen;
    buf.out = plainText;
    buf.outCap = (uint32_t)sizeof(plainText);
    buf.outLen = 0;

    ret = AesCfbCrypt(ctx, 0, &buf);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        return ret;
    }

    PrintHex("decrypted plain text value is", plainText, buf.outLen);

    if (buf.outLen != dataLen || memcmp(plainText, DATA, dataLen) != 0) {
        printf("plaintext comparison failed\n");
        return CRYPT_INVALID_ARG;
    }

    printf("pass\n");
    return CRYPT_SUCCESS;
}

int main(void)
{
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        BSL_ERR_DeInit();
        return ret;
    }

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CFB);
    if (ctx == NULL) {
        PrintLastError();
        BSL_ERR_DeInit();
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = RunDemo(ctx);

    CRYPT_EAL_CipherFreeCtx(ctx);
    BSL_ERR_DeInit();
    return ret;
}

