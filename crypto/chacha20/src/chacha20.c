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
#ifdef HITLS_CRYPTO_CHACHA20

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_chacha20.h"
#include "chacha20_local.h"

#define KEYSET 0x01
#define NONCESET 0x02

// RFC7539-2.1
#define QUARTER(a, b, c, d) \
    do { \
        (a) += (b); (d) ^= (a); (d) = ROTL32((d), 16); \
        (c) += (d); (b) ^= (c); (b) = ROTL32((b), 12); \
        (a) += (b); (d) ^= (a); (d) = ROTL32((d), 8);  \
        (c) += (d); (b) ^= (c); (b) = ROTL32((b), 7);  \
    } while (0)

#define QUARTERROUND(state, a, b, c, d) QUARTER((state)[(a)], (state)[(b)], (state)[(c)], (state)[(d)])

int32_t CRYPT_CHACHA20_SetKey(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *key, uint32_t keyLen)
{
    if (ctx == NULL || key == NULL || keyLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (keyLen != CHACHA20_KEYLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CHACHA20_KEYLEN_ERROR);
        return CRYPT_CHACHA20_KEYLEN_ERROR;
    }
    /**
     * RFC7539-2.3
     * cccccccc cccccccc cccccccc cccccccc
     * kkkkkkkk kkkkkkkk kkkkkkkk kkkkkkkk
     * kkkkkkkk kkkkkkkk kkkkkkkk kkkkkkkk
     * bbbbbbbb nnnnnnnn nnnnnnnn nnnnnnnn
     */
    // The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    /**
     * The next eight words (4-11) are taken from the 256-bit key by
     * reading the bytes in little-endian order, in 4-byte chunks.
     */
    ctx->state[4] = GET_UINT32_LE(key, 0);
    ctx->state[5] = GET_UINT32_LE(key, 4);
    ctx->state[6] = GET_UINT32_LE(key, 8);
    ctx->state[7] = GET_UINT32_LE(key, 12);
    ctx->state[8] = GET_UINT32_LE(key, 16);
    ctx->state[9] = GET_UINT32_LE(key, 20);
    ctx->state[10] = GET_UINT32_LE(key, 24);
    ctx->state[11] = GET_UINT32_LE(key, 28);
    // Word 12 is a block counter
    // RFC7539-2.4: It makes sense to use one if we use the zero block
    ctx->state[12] = 1;
    ctx->set |= KEYSET;
    ctx->lastLen = 0;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CHACHA20_SetNonce(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *nonce, uint32_t nonceLen)
{
    // RFC7539-2.3
    if (ctx == NULL || nonce == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (nonceLen != CHACHA20_NONCELEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CHACHA20_NONCELEN_ERROR);
        return CRYPT_CHACHA20_NONCELEN_ERROR;
    }
    /**
     * Words 13-15 are a nonce, which should not be repeated for the same
     * key. The 13th word is the first 32 bits of the input nonce taken
     * as a little-endian integer, while the 15th word is the last 32
     * bits.
     */
    ctx->state[13] = GET_UINT32_LE(nonce, 0);
    ctx->state[14] = GET_UINT32_LE(nonce, 4);
    ctx->state[15] = GET_UINT32_LE(nonce, 8);
    ctx->set |= NONCESET;
    ctx->lastLen = 0;
    return CRYPT_SUCCESS;
}

// Little-endian data input
static int32_t CRYPT_CHACHA20_SetCount(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *cnt, uint32_t cntLen)
{
    if (ctx == NULL || cnt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (cntLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_CHACHA20_COUNTLEN_ERROR);
        return CRYPT_CHACHA20_COUNTLEN_ERROR;
    }
    /**
     * RFC7539-2.4
     * This can be set to any number, but will
     * usually be zero or one. It makes sense to use one if we use the
     * zero block for something else, such as generating a one-time
     * authenticator key as part of an AEAD algorithm
     */
    ctx->state[12] = GET_UINT32_LE((uintptr_t)cnt, 0);
    ctx->lastLen = 0;
    return CRYPT_SUCCESS;
}

void CHACHA20_Block(CRYPT_CHACHA20_Ctx *ctx)
{
    uint32_t i;
    // The length defined by ctx->last.c is the same as that defined by ctx->state.
    // Therefore, the returned value is not out of range.
    (void)memcpy_s(ctx->last.c, CHACHA20_STATEBYTES, ctx->state, sizeof(ctx->state));
    /* RFC7539-2.3 These are 20 round in this function */
    for (i = 0; i < 10; i++) {
        /* column round */
        QUARTERROUND(ctx->last.c, 0, 4, 8, 12);
        QUARTERROUND(ctx->last.c, 1, 5, 9, 13);
        QUARTERROUND(ctx->last.c, 2, 6, 10, 14);
        QUARTERROUND(ctx->last.c, 3, 7, 11, 15);
        /* diagonal round */
        QUARTERROUND(ctx->last.c, 0, 5, 10, 15);
        QUARTERROUND(ctx->last.c, 1, 6, 11, 12);
        QUARTERROUND(ctx->last.c, 2, 7, 8, 13);
        QUARTERROUND(ctx->last.c, 3, 4, 9, 14);
    }
    /* Reference from rfc 7539, At the end of 20 rounds (or 10 iterations of the above list),
     * we add the original input words to the output words
     */
    for (i = 0; i < CHACHA20_STATESIZE; i++) {
        ctx->last.c[i] += ctx->state[i];
        ctx->last.c[i] = CRYPT_HTOLE32(ctx->last.c[i]);
    }
    ctx->state[12]++;
}

int32_t CRYPT_CHACHA20_Update(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || out == NULL || in == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((ctx->set & KEYSET) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CHACHA20_NO_KEYINFO);
        return CRYPT_CHACHA20_NO_KEYINFO;
    }
    if ((ctx->set & NONCESET) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CHACHA20_NO_NONCEINFO);
        return CRYPT_CHACHA20_NO_NONCEINFO;
    }
    uint32_t i;
    const uint8_t *offIn = in;
    uint8_t *offOut = out;
    uint32_t tLen = len;
    if (ctx->lastLen != 0) { // has remaining data during the last processing
        uint32_t num = (tLen < ctx->lastLen) ? tLen : ctx->lastLen;
        uint8_t *tLast = ctx->last.u + CHACHA20_STATEBYTES - ctx->lastLen; // offset
        for (i = 0; i < num; i++) {
            offOut[i] = tLast[i] ^ offIn[i];
        }
        offIn += num;
        offOut += num;
        tLen -= num;
        ctx->lastLen -= num;
    }
    if (tLen >= CHACHA20_STATEBYTES) { // which is greater than or equal to an integer multiple of 64 bytes
        CHACHA20_Update(ctx, offIn, offOut, tLen); // processes data that is an integer multiple of 64 bytes
        uint32_t vLen = tLen - (tLen & 0x3f); // 0x3f = %CHACHA20_STATEBYTES
        offIn += vLen;
        offOut += vLen;
        tLen -= vLen;
    }
    // Process the remaining data
    if (tLen > 0) {
        CHACHA20_Block(ctx);
        uint32_t t = tLen & 0xf8; // processing length is a multiple of 8
        if (t != 0) {
            DATA64_XOR(ctx->last.u, offIn, offOut, t);
        }
        for (i = t; i < tLen; i++) {
            offOut[i] = ctx->last.u[i] ^ offIn[i];
        }
        ctx->lastLen = CHACHA20_STATEBYTES - tLen;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CHACHA20_Ctrl(CRYPT_CHACHA20_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    switch (opt) {
        case CRYPT_CTRL_SET_IV: // in chacha20_poly1305 mode, the configured IV is the nonce of chacha20.
            /**
             * RFC_7539-2.8.1
             * chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
             * nonce = constant | iv
             */
            return CRYPT_CHACHA20_SetNonce(ctx, val, len);
        case CRYPT_CTRL_SET_COUNT:
            return CRYPT_CHACHA20_SetCount(ctx, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_CHACHA20_CTRLTYPE_ERROR);
            return CRYPT_CHACHA20_CTRLTYPE_ERROR;
    }
}

void CRYPT_CHACHA20_Clean(CRYPT_CHACHA20_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    (void)memset_s(ctx, sizeof(CRYPT_CHACHA20_Ctx), 0, sizeof(CRYPT_CHACHA20_Ctx));
}
#endif // HITLS_CRYPTO_CHACHA20
