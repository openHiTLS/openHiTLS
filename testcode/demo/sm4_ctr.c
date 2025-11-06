/* Copyright (c) 2025, Shandong University — School of Cyber Science and Technology
 * Contributor: Xinye Wang
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

/*
 * SM4 CTR Demo for openHiTLS
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "crypt_eal_cipher.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_errno.h"

#define DEMO_ENCRYPT 1
#define DEMO_DECRYPT 0

static void PrintLastError(void)
{
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %u\n", file, line);
}

static void PrintHex(const char *label, const uint8_t *buf, uint32_t len)
{
    uint32_t i;
    if (label != NULL) {
        printf("%s", label);
    }
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

typedef struct {
    const uint8_t *key;
    uint32_t keyLen;
    const uint8_t *iv;
    uint32_t ivLen;
} Sm4CtrKeyIv;

typedef struct {
    const uint8_t *in;
    uint32_t inLen;
    uint8_t *out;
    uint32_t outSize;
    uint32_t *outUsed;
} Sm4CtrIO;

static int32_t Sm4CtrCrypt(int32_t isEncrypt, const Sm4CtrKeyIv *kiv, const Sm4CtrIO *io)
{
    int32_t ret;
    uint32_t outLen;
    CRYPT_EAL_CipherCtx *ctx = NULL;

    if (kiv == NULL || io == NULL || io->outUsed == NULL ||
        kiv->key == NULL || kiv->iv == NULL ||
        io->in == NULL || io->out == NULL) {
        return CRYPT_NULL_INPUT;
    }
    *io->outUsed = 0;

    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CTR);
    if (ctx == NULL) {
        PrintLastError();
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = CRYPT_EAL_CipherInit(ctx, kiv->key, kiv->keyLen, kiv->iv, kiv->ivLen, isEncrypt);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }

    outLen = io->outSize;
    ret = CRYPT_EAL_CipherUpdate(ctx, io->in, io->inLen, io->out, &outLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        CRYPT_EAL_CipherFreeCtx(ctx);
        return ret;
    }

    *io->outUsed = outLen;
    CRYPT_EAL_CipherFreeCtx(ctx);
    return CRYPT_SUCCESS;
}

int main(void)
{
    uint8_t data[10] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x1c, 0x14};
    uint8_t iv[16]  = {0};
    uint8_t key[16] = {0};
    uint32_t dataLen = (uint32_t)sizeof(data);

    uint8_t cipherText[64];
    uint32_t cipherLen = 0;

    uint8_t plainText[64];
    uint32_t plainLen = 0;

    int32_t ret;

    Sm4CtrKeyIv kiv = { key, (uint32_t)sizeof(key), iv, (uint32_t)sizeof(iv) };
    PrintHex("plain text to be encrypted: ", data, dataLen);

    /* ---------------- Encrypt ---------------- */
    Sm4CtrIO encIO = { data, dataLen, cipherText, (uint32_t)sizeof(cipherText), &cipherLen };
    ret = Sm4CtrCrypt(DEMO_ENCRYPT, &kiv, &encIO);
    if (ret != CRYPT_SUCCESS) {
        /* Stop on encryption failure to prevent misleading decryption/memcmp results. */
        BSL_ERR_DeInit();
        return ret;
    }

    PrintHex("cipher text value is: ", cipherText, cipherLen);

    /* ---------------- Decrypt ---------------- */
    Sm4CtrIO decIO = { cipherText, cipherLen, plainText, (uint32_t)sizeof(plainText), &plainLen };
    ret = Sm4CtrCrypt(DEMO_DECRYPT, &kiv, &decIO);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_DeInit();
        return ret;
    }

    PrintHex("decrypted plain text value is: ", plainText, plainLen);

    if (plainLen != dataLen || memcmp(plainText, data, dataLen) != 0) {
        printf("plaintext comparison failed\n");
        BSL_ERR_DeInit();
        return CRYPT_EAL_CIPHER_DATA_ERROR;
    }

    printf("pass\n");
    BSL_ERR_DeInit();
    return CRYPT_SUCCESS;
}