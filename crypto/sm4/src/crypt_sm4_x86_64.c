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

#include "crypt_sm4_x86_64.h"
#include "crypt_sm4.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "securec.h"

#define XTS_KEY_LEN 32
#define SM4_KEY_LEN 16
#define XTS_POLYNOMIAL 0xe1
#define LAST_BLOCK_HEAD 240
#define BYTE_MOST_SIG 128
#define BYTE 8

void SM4_XTS_Calculate_Tweak(unsigned char *t, const unsigned int idx)
{
    uint32_t j;
    uint8_t tweak_in, tweak_out;

    tweak_in = 0;
    for (j = 0; j < CRYPT_SM4_BLOCKSIZE; j++) {
        tweak_out = (t[idx + j] << (BYTE - 1)) & BYTE_MOST_SIG;
        t[j] = (t[idx + j] >> 1) + tweak_in;
        tweak_in = tweak_out;
    }
    if (tweak_out) {
        t[0] ^= XTS_POLYNOMIAL;
    }
}

static void SM4_XTS_Encrypt_Helper(uint32_t left, const uint32_t dataLen, uint8_t* t, uint8_t *x,
                                   const uint8_t* plain, uint8_t* cipher, const uint32_t* dataRk)
{
    uint32_t i, j;
    uint32_t init;

    init = dataLen - left;
    if (left >= CRYPT_SM4_BLOCKSIZE) {
        left = left % CRYPT_SM4_BLOCKSIZE;

        for (i = init; i < (dataLen - left); i += CRYPT_SM4_BLOCKSIZE) {
            for (j = 0; j < CRYPT_SM4_BLOCKSIZE; j++) {
                t[j + CRYPT_SM4_BLOCKSIZE] = t[j];
            }
            for (j = 0; j < CRYPT_SM4_BLOCKSIZE; j++) {
                x[j] = plain[i + j] ^ t[j];
            }

            SM4_Encrypt(x, cipher + i, dataRk);

            for (j = 0; j < CRYPT_SM4_BLOCKSIZE; j++) {
                cipher[i + j] = cipher[i + j] ^ t[j];
            }
            SM4_XTS_Calculate_Tweak(t, CRYPT_SM4_BLOCKSIZE);
        }
    }
    init = dataLen - left;

    if (left != 0) {
        for (i = 0; i < left; i++) {
            cipher[init + i] = cipher[init - CRYPT_SM4_BLOCKSIZE + i];
            x[i] = plain[init + i];
        }
        for (i = left; i < CRYPT_SM4_BLOCKSIZE; i++) {
            x[i] = cipher[init - CRYPT_SM4_BLOCKSIZE + i];
        }
        for (i = 0; i < CRYPT_SM4_BLOCKSIZE; i++) {
            x[i] = x[i] ^ t[i];
        }

        SM4_Encrypt(x, cipher + init - CRYPT_SM4_BLOCKSIZE, dataRk);
        for (i = 0; i < CRYPT_SM4_BLOCKSIZE; i++) {
            cipher[init - CRYPT_SM4_BLOCKSIZE + i] = cipher[init - CRYPT_SM4_BLOCKSIZE + i] ^ t[i];
        }
    }
}

int32_t SM4_XTS_En(uint8_t* cipher, const uint8_t* plain, const uint32_t* dataRk,
                   const uint8_t* tweak, const uint32_t dataLen)
{
    uint32_t left;

    uint8_t x[CRYPT_SM4_BLOCKSIZE_16] = {0};
    uint8_t t[CRYPT_SM4_BLOCKSIZE_16] = {0};

    if (dataLen < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN);
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    left = dataLen % CRYPT_SM4_BLOCKSIZE_16;

    // MODES_XTS_Ctrl has TW = Enc_K2(iv) done
    memcpy_s(t, CRYPT_SM4_BLOCKSIZE_16, tweak, CRYPT_SM4_BLOCKSIZE);

    if (dataLen >= CRYPT_SM4_BLOCKSIZE_16) {
        SM4_XTS_Encrypt_Blocks(plain, cipher, dataLen, dataRk, t);
    }

    if (left == 0) {
        return CRYPT_SUCCESS;
    } else {
        if (dataLen >= CRYPT_SM4_BLOCKSIZE_16) {
            SM4_XTS_Calculate_Tweak(t, LAST_BLOCK_HEAD);
        }
        SM4_XTS_Encrypt_Helper(left, dataLen, t, x, plain, cipher, dataRk);
    }
    return CRYPT_SUCCESS;
}

static void SM4_XTS_Decrypt_Helper(uint32_t left, const uint32_t dataLen, uint8_t* t, uint8_t *x,
                                   uint8_t* plain, const uint8_t* cipher, const uint32_t* dataRk)
{
    uint32_t i, j;
    uint32_t init;

    init = dataLen - left;
    if (left >= CRYPT_SM4_BLOCKSIZE) {
        left = left % CRYPT_SM4_BLOCKSIZE;

        for (i = init; i < (dataLen - left); i += CRYPT_SM4_BLOCKSIZE) {
            for (j = 0; j < CRYPT_SM4_BLOCKSIZE; j++) {
                t[j + CRYPT_SM4_BLOCKSIZE] = t[j];
            }
            for (j = 0; j < CRYPT_SM4_BLOCKSIZE; j++) {
                x[j] = cipher[i + j] ^ t[j];
            }

            SM4_Decrypt(x, plain + i, dataRk);

            for (j = 0; j < CRYPT_SM4_BLOCKSIZE; j++) {
                plain[i + j] = plain[i + j] ^ t[j];
            }
            SM4_XTS_Calculate_Tweak(t, CRYPT_SM4_BLOCKSIZE);
        }
    }

    init = dataLen - left;

    if (left != 0) {
        // recompute
        // m-T
        for (j = 0; j < CRYPT_SM4_BLOCKSIZE; j++) {
            x[j] = cipher[init - CRYPT_SM4_BLOCKSIZE + j] ^ t[j];
        }
        SM4_Decrypt(x, plain + init - CRYPT_SM4_BLOCKSIZE, dataRk);

        for (j = 0; j < CRYPT_SM4_BLOCKSIZE; j++) {
            plain[init - CRYPT_SM4_BLOCKSIZE + j] = plain[init - CRYPT_SM4_BLOCKSIZE + j] ^ t[j];
        }
        for (i = 0; i < left; i++) {
            plain[init + i] = plain[init - CRYPT_SM4_BLOCKSIZE + i];
            x[i] = cipher[init + i];
        }
        for (i = left; i < CRYPT_SM4_BLOCKSIZE; i++) {
            x[i] = plain[init - CRYPT_SM4_BLOCKSIZE + i];
        }
        // (m-1)-T
        for (i = 0; i < CRYPT_SM4_BLOCKSIZE; i++) {
            x[i] = x[i] ^ t[CRYPT_SM4_BLOCKSIZE + i];
        }

        SM4_Decrypt(x, plain + init - CRYPT_SM4_BLOCKSIZE, dataRk);

        for (i = 0; i < CRYPT_SM4_BLOCKSIZE; i++) {
            plain[init - CRYPT_SM4_BLOCKSIZE + i] = plain[init - CRYPT_SM4_BLOCKSIZE + i]
                                                    ^ t[CRYPT_SM4_BLOCKSIZE + i];
        }
    }
}

int32_t SM4_XTS_De(uint8_t* plain, const uint8_t* cipher, const uint32_t* dataRk,
                   const uint8_t* tweak, const uint32_t dataLen)
{
    uint32_t j;
    uint32_t left;

    uint8_t t[CRYPT_SM4_BLOCKSIZE_16] = {0};
    uint8_t x[CRYPT_SM4_BLOCKSIZE_16] = {0};

    if (dataLen < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN); // need push error code for error point
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    left = dataLen % CRYPT_SM4_BLOCKSIZE_16;

    // MODES_XTS_Ctrl has TW = Enc_K2(iv) done
    (void)memcpy_s(t, CRYPT_SM4_BLOCKSIZE_16, tweak, CRYPT_SM4_BLOCKSIZE);

    if (dataLen >= CRYPT_SM4_BLOCKSIZE_16) {
        SM4_XTS_Encrypt_Blocks(cipher, plain, dataLen, dataRk, t);
    }

    if (left != 0) {
        if (dataLen >= CRYPT_SM4_BLOCKSIZE_16) {
            SM4_XTS_Calculate_Tweak(t, LAST_BLOCK_HEAD);
            for (j = 0; j < CRYPT_SM4_BLOCKSIZE; j++) {
                t[j + CRYPT_SM4_BLOCKSIZE] = t[j + LAST_BLOCK_HEAD];
            }
        }
        SM4_XTS_Decrypt_Helper(left, dataLen, t, x, plain, cipher, dataRk);
    }
    return CRYPT_SUCCESS;
}

// key[0..16]: data key
// key[16..32]: tweak key
int32_t CRYPT_SM4_XTS_SetEncryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    CRYPT_SM4_Ctx *tmk = NULL;
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

    tmk = (CRYPT_SM4_Ctx *)&ctx[1];
    SM4_SetEncKey(key, ctx->rk);
    SM4_SetEncKey(key + CRYPT_SM4_BLOCKSIZE, tmk->rk);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_XTS_SetDecryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    CRYPT_SM4_Ctx *tmk = NULL;
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

    tmk = (CRYPT_SM4_Ctx *)&ctx[1];
    SM4_SetDecKey(key, ctx->rk);
    SM4_SetEncKey(key + CRYPT_SM4_BLOCKSIZE, tmk->rk);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_XTS_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL || iv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    return SM4_XTS_En(out, in, ctx->rk, iv, len);
}

int32_t CRYPT_SM4_XTS_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL || iv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    return SM4_XTS_De(out, in, ctx->rk, iv, len);
}

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

    SM4_SetEncKey(key, ctx->rk);

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

    SM4_SetDecKey(key, ctx->rk);

    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_ECB
int32_t SM4_ECB_Crypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN);
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    SM4_ECB_Encrypt(in, out, len, ctx->rk);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_ECB_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return SM4_ECB_Crypt(ctx, in, out, len);
}

int32_t CRYPT_SM4_ECB_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return SM4_ECB_Crypt(ctx, in, out, len);
}
#endif

#ifdef HITLS_CRYPTO_CBC
int32_t CRYPT_SM4_CBC_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN);
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    SM4_CBC_Encrypt(in, out, len, ctx->rk, iv, 1);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_CBC_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len < CRYPT_SM4_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM4_ERR_MSG_LEN);
        return CRYPT_SM4_ERR_MSG_LEN;
    }
    SM4_CBC_Encrypt(in, out, len, ctx->rk, iv, 0);
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_OFB
int32_t SM4_OFB_Crypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv, uint8_t *offset)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int tmp = *offset;
    SM4_OFB_Encrypt(in, out, len, ctx->rk, iv, &tmp);
    *offset = (uint8_t)tmp;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_OFB_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len,
    uint8_t *iv, uint8_t *offset)
{
    return SM4_OFB_Crypt(ctx, in, out, len, iv, offset);
}

int32_t CRYPT_SM4_OFB_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len,
    uint8_t *iv, uint8_t *offset)
{
    return SM4_OFB_Crypt(ctx, in, out, len, iv, offset);
}
#endif

#ifdef HITLS_CRYPTO_CFB
int32_t CRYPT_SM4_CFB_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv, uint8_t *offset)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int tmp = *offset;
    SM4_CFB128_Encrypt(in, out, len, ctx->rk, iv, &tmp);
    *offset = (uint8_t)tmp;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_CFB_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv, uint8_t *offset)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int tmp = *offset;
    SM4_CFB128_Decrypt(in, out, len, ctx->rk, iv, &tmp);
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
    SM4_CTR_EncryptBlocks(in, out, len, ctx->rk, iv);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM4_CTR_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    SM4_CTR_EncryptBlocks(in, out, len, ctx->rk, iv);
    return CRYPT_SUCCESS;
}
#endif

#endif /* HITLS_CRYPTO_SM4 */
