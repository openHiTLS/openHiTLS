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

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <string.h>
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_sal.h"

typedef struct {
    const char *key;
    const char *iv;
    const char *aad;
    const char *plaintext;
    const char *ciphertext;
    const char *tag;
} CMVP_CHACHA20POLY1305_VECTOR;

// https://datatracker.ietf.org/doc/html/rfc7539.html#page-22
static const CMVP_CHACHA20POLY1305_VECTOR CHACHA20POLY1305_VECTOR = {
    .key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    .iv = "070000004041424344454647",
    .aad = "50515253c0c1c2c3c4c5c6c7",
    .plaintext = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f6620273939"
        "3a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220"
        "746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    .ciphertext = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca96712"
        "82fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
    .tag = "1ae10b594f09e26a7e902ecbd0600691"
};

static bool GetData(CRYPT_Data *key, CRYPT_Data *iv, CRYPT_Data *aad, CRYPT_Data *data, CRYPT_Data *cipher)
{
    key->data = CMVP_StringsToBins(CHACHA20POLY1305_VECTOR.key, &(key->len));
    GOTO_ERR_IF_TRUE(key->data == NULL, CRYPT_CMVP_COMMON_ERR);
    iv->data = CMVP_StringsToBins(CHACHA20POLY1305_VECTOR.iv, &(iv->len));
    GOTO_ERR_IF_TRUE(iv->data == NULL, CRYPT_CMVP_COMMON_ERR);
    aad->data = CMVP_StringsToBins(CHACHA20POLY1305_VECTOR.aad, &(aad->len));
    GOTO_ERR_IF_TRUE(aad->data == NULL, CRYPT_CMVP_COMMON_ERR);
    data->data = CMVP_StringsToBins(CHACHA20POLY1305_VECTOR.plaintext, &(data->len));
    GOTO_ERR_IF_TRUE(data->data == NULL, CRYPT_CMVP_COMMON_ERR);
    cipher->data = CMVP_StringsToBins(CHACHA20POLY1305_VECTOR.ciphertext, &(cipher->len));
    GOTO_ERR_IF_TRUE(cipher->data == NULL, CRYPT_CMVP_COMMON_ERR);
    return true;
ERR:
    return false;
}

static void FreeData(CRYPT_Data key, CRYPT_Data iv, CRYPT_Data aad, CRYPT_Data data, CRYPT_Data cipher)
{
    BSL_SAL_Free(key.data);
    BSL_SAL_Free(iv.data);
    BSL_SAL_Free(aad.data);
    BSL_SAL_Free(data.data);
    BSL_SAL_Free(cipher.data);
}

static bool CRYPT_CMVP_SelftestChacha20poly1305Internal(void *libCtx, const char *attrName)
{
    bool ret = false;
    CRYPT_Data key = { NULL, 0 };
    CRYPT_Data iv = { NULL, 0 };
    CRYPT_Data aad = { NULL, 0 };
    CRYPT_Data data = { NULL, 0 };
    CRYPT_Data cipher = { NULL, 0 };
    CRYPT_Data tag = { NULL, 0 };
    uint8_t *out = NULL;
    uint8_t *outTag = NULL;
    uint32_t outLen;
    uint32_t first;
    int32_t err = CRYPT_CMVP_ERR_ALGO_SELFTEST;
    CRYPT_EAL_CipherCtx *ctx = NULL;

    GOTO_ERR_IF_TRUE(!GetData(&key, &iv, &aad, &data, &cipher), err);
    tag.data = CMVP_StringsToBins(CHACHA20POLY1305_VECTOR.tag, &(tag.len));
    GOTO_ERR_IF_TRUE(tag.data == NULL, CRYPT_CMVP_COMMON_ERR);
    outTag = BSL_SAL_Malloc(tag.len);
    outLen = cipher.len;
    out = BSL_SAL_Malloc(outLen);
    GOTO_ERR_IF_TRUE(outTag == NULL || out == NULL, CRYPT_MEM_ALLOC_FAIL);
    first = data.len / 2;       // The length of the data in the first operation is 1/2 of the data.

    ctx = CRYPT_EAL_ProviderCipherNewCtx(libCtx, CRYPT_CIPHER_CHACHA20_POLY1305, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, err);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherInit(ctx, key.data, key.len, iv.data, iv.len, true) != CRYPT_SUCCESS, err);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad.data, aad.len) != CRYPT_SUCCESS, err);
    outLen = first;
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherUpdate(ctx, data.data, first, out, &outLen) != CRYPT_SUCCESS, err);
    outLen = data.len - first;
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherUpdate(ctx, data.data + first, data.len - first,
        out + first, &outLen) != CRYPT_SUCCESS, err);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, outTag, (uint32_t)tag.len) != CRYPT_SUCCESS, err);

    GOTO_ERR_IF_TRUE(memcmp(out, cipher.data, cipher.len) != 0, err);
    GOTO_ERR_IF_TRUE(memcmp(outTag, tag.data, tag.len) != 0, err);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherInit(ctx, key.data, key.len, iv.data, iv.len, false) != CRYPT_SUCCESS, err);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad.data, aad.len) != CRYPT_SUCCESS, err);
    outLen = cipher.len;
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherUpdate(ctx, cipher.data, cipher.len, out, &outLen) != CRYPT_SUCCESS, err);
    GOTO_ERR_IF_TRUE(memcmp(out, data.data, data.len) != 0, err);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, outTag, (uint32_t)tag.len) != CRYPT_SUCCESS, err);
    GOTO_ERR_IF_TRUE(memcmp(outTag, tag.data, tag.len) != 0, err);

    ret = true;
ERR:
    FreeData(key, iv, aad, data, cipher);
    BSL_SAL_Free(tag.data);
    BSL_SAL_Free(outTag);
    BSL_SAL_Free(out);
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

bool CRYPT_CMVP_SelftestChacha20poly1305(void)
{
    return CRYPT_CMVP_SelftestChacha20poly1305Internal(NULL, NULL);
}

bool CRYPT_CMVP_SelftestProviderChacha20poly1305(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestChacha20poly1305Internal(libCtx, attrName);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */