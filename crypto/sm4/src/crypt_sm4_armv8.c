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
#ifdef HITLS_CRYPTO_SM4

#include "crypt_sm4_armv8.h"
#include "crypt_sm4.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"

#ifdef HITLS_CRYPTO_XTS
// key[0..16]: data key
// key[16..32]: tweak key
int32_t CRYPT_SM4_XTS_SetEncryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (len != XTS_KEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_KEY_LEN);
        return CRYPT_SM4_ERR_KEY_LEN;
    }

    if (memcmp(key, key + CRYPT_SM4_BLOCKSIZE, CRYPT_SM4_BLOCKSIZE) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_UNSAFE_KEY);
        return CRYPT_SM4_UNSAFE_KEY;
    }
    CRYPT_SM4_Ctx *tmk = (CRYPT_SM4_Ctx *)&ctx[1];
    Vpsm4SetEncryptKey(key, (SM4_KEY *)ctx->rk);
    Vpsm4SetEncryptKey(key + CRYPT_SM4_BLOCKSIZE, (SM4_KEY *)tmk->rk);

    return CRYPT_SUCCESS;
}

// key[0..16]: data key
// key[16..32]: tweak key
int32_t CRYPT_SM4_XTS_SetDecryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (len != XTS_KEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_KEY_LEN);
        return CRYPT_SM4_ERR_KEY_LEN;
    }

    if (memcmp(key, key + CRYPT_SM4_BLOCKSIZE, CRYPT_SM4_BLOCKSIZE) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_UNSAFE_KEY);
        return CRYPT_SM4_UNSAFE_KEY;
    }
    CRYPT_SM4_Ctx *tmk = (CRYPT_SM4_Ctx *)&ctx[1];
    Vpsm4SetDecryptKey(key, (SM4_KEY *)ctx->rk);
    Vpsm4SetEncryptKey(key + CRYPT_SM4_BLOCKSIZE, (SM4_KEY *)tmk->rk);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_XTS_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    CRYPT_SM4_Ctx *tmk = NULL;
    if (ctx == NULL || iv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (len < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN);
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    tmk = (CRYPT_SM4_Ctx *)&ctx[1];
    Vpsm4XtsCipher(in, out, len, (const SM4_KEY *)ctx->rk, (const SM4_KEY *)tmk->rk, iv, 1);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_XTS_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    CRYPT_SM4_Ctx *tmk = NULL;
    if (ctx == NULL || iv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (len < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN);
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    tmk = (CRYPT_SM4_Ctx *)&ctx[1];
    Vpsm4XtsCipher(in, out, len, (const SM4_KEY *)ctx->rk, (const SM4_KEY *)tmk->rk, iv, 0);

    return CRYPT_SUCCESS;
}
#endif

int32_t CRYPT_SM4_SetEncryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (len != SM4_KEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_KEY_LEN);
        return CRYPT_SM4_ERR_KEY_LEN;
    }
    Vpsm4SetEncryptKey(key, (SM4_KEY *)ctx->rk);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_SetDecryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (len != SM4_KEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_KEY_LEN);
        return CRYPT_SM4_ERR_KEY_LEN;
    }

    Vpsm4SetDecryptKey(key, (SM4_KEY *)ctx->rk);
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_ECB
int32_t CRYPT_SM4_ECB_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN);
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    Vpsm4EcbEncrypt(in, out, len, ctx->rk);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_ECB_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN);
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    Vpsm4EcbEncrypt(in, out, len, ctx->rk);
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_CBC
int32_t CRYPT_SM4_CBC_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len % CRYPT_SM4_BLOCKSIZE != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN);
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    Vpsm4CbcEncrypt(in, out, len, ctx->rk, iv, 1);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_CBC_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len % CRYPT_SM4_BLOCKSIZE != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN);
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    Vpsm4CbcEncrypt(in, out, len, ctx->rk, iv, 0);
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_CBC

#ifdef HITLS_CRYPTO_CFB
int32_t CRYPT_SM4_CFB_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len,
    uint8_t *iv, uint8_t *offset)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int tmp = *offset;
    Vpsm4Cfb128Encrypt(in, out, len, ctx->rk, iv, &tmp);
    *offset = (uint8_t)tmp;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_CFB_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len,
    uint8_t *iv, uint8_t *offset)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int tmp = *offset;
    Vpsm4Cfb128Decrypt(in, out, len, ctx->rk, iv, &tmp);
    *offset = (uint8_t)tmp;
    return CRYPT_SUCCESS;
}
#endif

#if defined(HITLS_CRYPTO_CTR) || defined(HITLS_CRYPTO_GCM)
int32_t CRYPT_SM4_CTR_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    Vpsm4Ctr32EncryptBlocks(in, out, len, ctx->rk, iv);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_CTR_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    Vpsm4Ctr32EncryptBlocks(in, out, len, ctx->rk, iv);
    return CRYPT_SUCCESS;
}
#endif

#endif // HITLS_CRYPTO_SM4
