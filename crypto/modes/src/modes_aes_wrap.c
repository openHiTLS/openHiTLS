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
#ifdef HITLS_CRYPTO_WRAP

#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes_aes_wrap.h"
#include "crypt_modes.h"
#include "modes_local.h"

#define AES_ENCRYPT_BUF_SIZE (2 * CRYPT_WRAP_BLOCKSIZE)
#define WRAP_BLOCKSIZE 8

/* The number of blocks multiplied by the number of rounds does not exceed the value of
 * CRYPT_WRAP_MAX_INPUT_LEN / CRYPT_WRAP_BLOCKSIZE * 6, the maximum number of bytes is 4.
 */
#define AES_WRAP_T_LEN_BYTE_OFFSET (CRYPT_WRAP_BLOCKSIZE - 4)

static const uint8_t DEFAULT_IV[CRYPT_WRAP_BLOCKSIZE] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};

static const uint8_t DEFAULT_AIV[CRYPT_WRAP_AIV_SIZE] = {
    0xA6, 0x59, 0x59, 0xA6
};

void MODE_WRAP_Clean(MODES_CipherWRAPCtx *ctx)
{
    if (ctx == NULL || ctx->ciphMeth == NULL || ctx->ciphMeth->cipherDeInitCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return;
    }
    ctx->ciphMeth->cipherDeInitCtx(ctx->ciphCtx);
    return;
}

int32_t MODE_WRAP_DeInitCtx(MODES_WRAP_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    MODE_WRAP_Clean(&modeCtx->wrapCtx);
    return CRYPT_SUCCESS;
}

static void WRAP_DataBytesXor(uint8_t *out, uint32_t val)
{
    uint8_t t = (uint8_t)(val & 0xff);
    out[3] ^= t;    // out[3] is the least byte.
    if ((uint32_t)t == val) {    // The high 24 bits of t is 0.
        return;
    }
    out[2] ^= (uint8_t)((val >> 8) & 0xff);  // out[2] is the least byte of val shifted right by 8 bits.
    out[1] ^= (uint8_t)((val >> 16) & 0xff); // out[1] is the least byte of val shifted right by 16 bits.
    out[0] ^= (uint8_t)((val >> 24) & 0xff); // out[0] is the least byte of val shifted right by 24 bits.
}

// Refer to RFC3394 2.2.1 Key Wrap.
static int32_t WRAP_Encrypt(MODES_CipherWRAPCtx *ctx, uint8_t *out, uint32_t inLen, uint8_t *iv)
{
    uint32_t t = 1;
    uint8_t *ptr = NULL;
    int32_t ret;
    uint8_t encBuf[AES_ENCRYPT_BUF_SIZE];
    if (inLen < AES_ENCRYPT_BUF_SIZE || inLen > CRYPT_WRAP_MAX_INPUT_LEN || (inLen & 0x07) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }
    (void)memcpy_s(encBuf, AES_ENCRYPT_BUF_SIZE, iv, CRYPT_WRAP_BLOCKSIZE);
    // 6 round cycle
    for (uint32_t j = 0; j < 6; j++) {
        ptr = out + CRYPT_WRAP_BLOCKSIZE;
        for (uint32_t i = 0; i < inLen; i += CRYPT_WRAP_BLOCKSIZE) {
            (void)memcpy_s(encBuf + CRYPT_WRAP_BLOCKSIZE, CRYPT_WRAP_BLOCKSIZE, ptr, CRYPT_WRAP_BLOCKSIZE);
            ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, encBuf, encBuf, AES_ENCRYPT_BUF_SIZE);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            WRAP_DataBytesXor(encBuf + AES_WRAP_T_LEN_BYTE_OFFSET, t);
            t++;
            (void)memcpy_s(ptr, CRYPT_WRAP_BLOCKSIZE, encBuf + CRYPT_WRAP_BLOCKSIZE, CRYPT_WRAP_BLOCKSIZE);
            ptr += CRYPT_WRAP_BLOCKSIZE;
        }
    }
    (void)memcpy_s(out, CRYPT_WRAP_BLOCKSIZE, encBuf, CRYPT_WRAP_BLOCKSIZE);
    return CRYPT_SUCCESS;
}

// Refer to RFC3394 2.2.2 Key Unwrap.
static int32_t WRAP_Decrypt(MODES_CipherWRAPCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t inLen, uint8_t *aiv)
{
    uint8_t decBuf[AES_ENCRYPT_BUF_SIZE];
    uint8_t *ptr = NULL;
    int32_t ret;
    uint32_t outLen = inLen - CRYPT_WRAP_BLOCKSIZE;
    uint32_t t = 6 * (outLen >> 3);
    (void)memcpy_s(decBuf, AES_ENCRYPT_BUF_SIZE, in, CRYPT_WRAP_BLOCKSIZE);
    (void)memmove_s(out, outLen, in + CRYPT_WRAP_BLOCKSIZE, outLen);

    // 6 round cycle
    for (uint32_t j = 0; j < 6; j++) {
        ptr = out + outLen - CRYPT_WRAP_BLOCKSIZE;
        for (uint32_t i = 0; i < outLen; i += CRYPT_WRAP_BLOCKSIZE) {
            WRAP_DataBytesXor(decBuf + AES_WRAP_T_LEN_BYTE_OFFSET, t);
            t--;
            (void)memcpy_s(decBuf + CRYPT_WRAP_BLOCKSIZE, CRYPT_WRAP_BLOCKSIZE, ptr, CRYPT_WRAP_BLOCKSIZE);
            ret = ctx->ciphMeth->decryptBlock(ctx->ciphCtx, decBuf, decBuf, AES_ENCRYPT_BUF_SIZE);
            if (ret != CRYPT_SUCCESS) {
                (void)memset_s(out, outLen, 0, outLen);
                (void)memset_s(decBuf, AES_ENCRYPT_BUF_SIZE, 0, AES_ENCRYPT_BUF_SIZE);
                return ret;
            }
            (void)memcpy_s(ptr, CRYPT_WRAP_BLOCKSIZE, decBuf + CRYPT_WRAP_BLOCKSIZE, CRYPT_WRAP_BLOCKSIZE);
            ptr -= CRYPT_WRAP_BLOCKSIZE;
        }
    }
    if (ctx->flagPad != false) {  // In pad mode, aiv not NULL.
        (void)memcpy_s(aiv, CRYPT_WRAP_BLOCKSIZE, decBuf, CRYPT_WRAP_BLOCKSIZE);
        ret = CRYPT_SUCCESS;
    } else if (memcmp(ctx->iv, decBuf, CRYPT_WRAP_BLOCKSIZE) != 0) {
        (void)memset_s(out, outLen, 0, outLen);
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_WRAP_DEC_ERROR);
        ret = CRYPT_MODES_WRAP_DEC_ERROR;
    }
    (void)memset_s(decBuf, AES_ENCRYPT_BUF_SIZE, 0, AES_ENCRYPT_BUF_SIZE);
    return ret;
}

// Refer to RFC5649 Section 4.1. Extended Key Wrapping Process
static int32_t WRAP_EncryptPad(MODES_CipherWRAPCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t inLen,
    uint32_t *outLen)
{
    if (inLen == 0 || inLen > CRYPT_WRAP_MAX_INPUT_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }
    int32_t ret;
    uint8_t aiv[CRYPT_WRAP_BLOCKSIZE] = { 0 };
    uint32_t padLen = 0;
    if (inLen % CRYPT_WRAP_BLOCKSIZE != 0) {
        padLen = CRYPT_WRAP_BLOCKSIZE - inLen % CRYPT_WRAP_BLOCKSIZE;
    }
    if (*outLen < inLen + padLen + CRYPT_WRAP_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }
    (void)memmove_s(out + CRYPT_WRAP_BLOCKSIZE, *outLen - CRYPT_WRAP_BLOCKSIZE, in, inLen);
    (void)memset_s(out + inLen + CRYPT_WRAP_BLOCKSIZE, padLen, 0, padLen);

    (void)memcpy_s(aiv, CRYPT_WRAP_BLOCKSIZE, ctx->iv, CRYPT_WRAP_AIV_SIZE);
    WRAP_DataBytesXor(aiv + AES_WRAP_T_LEN_BYTE_OFFSET, inLen);

    if (inLen <= CRYPT_WRAP_BLOCKSIZE) {
        (void)memcpy_s(out, CRYPT_WRAP_BLOCKSIZE, aiv, CRYPT_WRAP_BLOCKSIZE);
        ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, out, out, AES_ENCRYPT_BUF_SIZE);
    } else {
        ret = WRAP_Encrypt(ctx, out, inLen + padLen, aiv);
    }
    if (ret != CRYPT_SUCCESS) {
        (void)memset_s(out, *outLen, 0, *outLen);  // Erasing sensitive information.
        return ret;
    }
    *outLen = inLen + padLen + CRYPT_WRAP_BLOCKSIZE;
    return CRYPT_SUCCESS;
}

static int32_t DecryptResultGetLen(MODES_CipherWRAPCtx *ctx, uint8_t *plaintext, uint8_t *aiv, uint32_t padLen,
    uint32_t inLen, uint32_t *outLen)
{
    uint8_t zeroBuf[CRYPT_WRAP_BLOCKSIZE] = { 0 };
    if (memcmp(aiv, ctx->iv, CRYPT_WRAP_AIV_SIZE) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_WRAP_DEC_ERROR);
        return CRYPT_MODES_WRAP_DEC_ERROR;
    }
    uint32_t plaintextLen = ((uint32_t)aiv[4] << 24) | ((uint32_t)aiv[5] << 16) |
            ((uint32_t)aiv[6] << 8) | (uint32_t)aiv[7];
    // The value of inLen is greater than or equal to CRYPT_WRAP_BLOCKSIZE * 2.
    if (plaintextLen > padLen || plaintextLen <= inLen - AES_ENCRYPT_BUF_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_WRAP_DEC_ERROR);
        return CRYPT_MODES_WRAP_DEC_ERROR;
    }

    if (memcmp(plaintext + plaintextLen, zeroBuf, padLen - plaintextLen) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_WRAP_DEC_ERROR);
        return CRYPT_MODES_WRAP_DEC_ERROR;
    }
    *outLen = plaintextLen;
    return CRYPT_SUCCESS;
}

// Refer to RFC5649 Section 4.2. Extended Key Unwrapping Process
static int32_t WRAP_DecryptPad(MODES_CipherWRAPCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t inLen,
    uint32_t *outLen)
{
    int32_t ret;
    uint8_t aiv[CRYPT_WRAP_BLOCKSIZE] = { 0 };
    uint8_t tmpBuf[AES_ENCRYPT_BUF_SIZE] = { 0 };
    uint32_t padLen;

    if (inLen == AES_ENCRYPT_BUF_SIZE) {  // The padded plaintext contains exactly eight octets.
        ret = ctx->ciphMeth->decryptBlock(ctx->ciphCtx, in, tmpBuf, inLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        (void)memcpy_s(aiv, CRYPT_WRAP_BLOCKSIZE, tmpBuf, CRYPT_WRAP_BLOCKSIZE);
        (void)memcpy_s(out, CRYPT_WRAP_BLOCKSIZE, tmpBuf + CRYPT_WRAP_BLOCKSIZE, CRYPT_WRAP_BLOCKSIZE);
        padLen = CRYPT_WRAP_BLOCKSIZE;
    } else {
        ret = WRAP_Decrypt(ctx, in, out, inLen, aiv);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        padLen = inLen - CRYPT_WRAP_BLOCKSIZE;
    }
    ret = DecryptResultGetLen(ctx, out, aiv, padLen, inLen, outLen);
    if (ret != CRYPT_SUCCESS) {
        (void)memset_s(out, *outLen, 0, *outLen);  // Erasing sensitive information.
    }
    return ret;
}

int32_t MODE_WRAP_Encrypt(MODES_CipherWRAPCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t inLen,
    uint32_t *outLen)
{
    if (ctx == NULL || ctx->ciphCtx == NULL || ctx->ciphMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    if (ctx->flagPad == false) {    // No padding
        if (*outLen < inLen + CRYPT_WRAP_BLOCKSIZE) {
            BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
            return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
        }
        (void)memmove_s(out + CRYPT_WRAP_BLOCKSIZE, *outLen - CRYPT_WRAP_BLOCKSIZE, in, inLen);
        ret = WRAP_Encrypt(ctx, out, inLen, ctx->iv);
        if (ret != CRYPT_SUCCESS) {
            (void)memset_s(out, *outLen, 0, *outLen);  // Erasing sensitive information.
            return ret;
        }
        *outLen = inLen + CRYPT_WRAP_BLOCKSIZE;
        return CRYPT_SUCCESS;
    } else {
        return WRAP_EncryptPad(ctx, in, out, inLen, outLen);
    }
}

int32_t MODE_WRAP_Decrypt(MODES_CipherWRAPCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t inLen,
    uint32_t *outLen)
{
    if (ctx == NULL || ctx->ciphCtx == NULL || ctx->ciphMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (*outLen < inLen) {
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }
    if (inLen < AES_ENCRYPT_BUF_SIZE || inLen > CRYPT_WRAP_MAX_INPUT_LEN || ((inLen & 0x07) != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }
    if (ctx->flagPad == false) {    // No padding
        *outLen = inLen - CRYPT_WRAP_BLOCKSIZE;
        return WRAP_Decrypt(ctx, in, out, inLen, NULL);
    } else {
        return WRAP_DecryptPad(ctx, in, out, inLen, outLen);
    }
}

static int32_t WRAP_SetIV(MODES_CipherWRAPCtx *ctx, const uint8_t *val, uint32_t len)
{
    if (val == NULL) {
        return CRYPT_SUCCESS;    // Use the default iv.
    }
    if ((ctx->flagPad && len != CRYPT_WRAP_AIV_SIZE) || (!ctx->flagPad && len != CRYPT_WRAP_BLOCKSIZE)) {
        return CRYPT_MODES_IVLEN_ERROR;
    }
    if (memcpy_s(ctx->iv, CRYPT_WRAP_BLOCKSIZE, val, len) != EOK) {
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t WRAP_GetIV(MODES_CipherWRAPCtx *ctx, uint8_t *val, uint32_t len)
{
    if (val == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->flagPad && len >= CRYPT_WRAP_AIV_SIZE) {
        (void)memcpy_s(val, len, ctx->iv, CRYPT_WRAP_AIV_SIZE);
        return CRYPT_SUCCESS;
    } else if (!ctx->flagPad && len >= CRYPT_WRAP_BLOCKSIZE) {
        (void)memcpy_s(val, len, ctx->iv, CRYPT_WRAP_BLOCKSIZE);
        return CRYPT_SUCCESS;
    }
    return CRYPT_MODES_IVLEN_ERROR;
}

MODES_WRAP_Ctx *MODES_WRAP_NewCtx(int32_t algId, bool isPad)
{
    const EAL_SymMethod *method = EAL_GetSymMethod(algId);
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    MODES_WRAP_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(MODES_WRAP_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return ctx;
    }
    ctx->algId = algId;
    ctx->wrapCtx.ciphCtx = BSL_SAL_Calloc(1, method->ctxSize);
    if (ctx->wrapCtx.ciphCtx  == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(ctx);
        return NULL;
    }
    ctx->wrapCtx.blockSize = CRYPT_WRAP_BLOCKSIZE;
    ctx->wrapCtx.ciphMeth = method;
    ctx->wrapCtx.flagPad = isPad;
    if (isPad) {
        (void)memcpy_s(ctx->wrapCtx.iv, CRYPT_WRAP_BLOCKSIZE, DEFAULT_AIV, sizeof(DEFAULT_AIV));
    } else {
        (void)memcpy_s(ctx->wrapCtx.iv, CRYPT_WRAP_BLOCKSIZE, DEFAULT_IV, sizeof(DEFAULT_IV));
    }
    return ctx;
}

MODES_WRAP_Ctx *MODES_WRAP_PadNewCtx(int32_t algId)
{
    return MODES_WRAP_NewCtx(algId, true);
}

MODES_WRAP_Ctx *MODES_WRAP_NoPadNewCtx(int32_t algId)
{
    return MODES_WRAP_NewCtx(algId, false);
}

MODES_WRAP_Ctx *MODES_WRAP_PadNewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    return MODES_WRAP_NewCtx(algId, true);
}

MODES_WRAP_Ctx *MODES_WRAP_NoPadNewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    return MODES_WRAP_NewCtx(algId, false);
}

int32_t MODES_WRAP_InitCtx(MODES_WRAP_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc)
{
    (void)param;
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    if (enc) {
        ret = modeCtx->wrapCtx.ciphMeth->setEncryptKey(modeCtx->wrapCtx.ciphCtx, key, keyLen);
    } else {
        ret = modeCtx->wrapCtx.ciphMeth->setDecryptKey(modeCtx->wrapCtx.ciphCtx, key, keyLen);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = WRAP_SetIV(&modeCtx->wrapCtx, iv, ivLen);
    if (ret != CRYPT_SUCCESS) {
        modeCtx->wrapCtx.ciphMeth->cipherDeInitCtx(modeCtx->wrapCtx.ciphCtx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    modeCtx->enc = enc;
    return ret;
}

int32_t MODES_WRAP_Update(MODES_WRAP_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if ((*outLen) < (inLen / (modeCtx->wrapCtx.blockSize) * (modeCtx->wrapCtx.blockSize))) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }
    return modeCtx->enc ?
        MODE_WRAP_Encrypt(&modeCtx->wrapCtx, in, out, inLen, outLen) :
        MODE_WRAP_Decrypt(&modeCtx->wrapCtx, in, out, inLen, outLen);
}

int32_t MODES_WRAP_Final(MODES_WRAP_Ctx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    if (outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void) modeCtx;
    (void) out;
    *outLen = 0;
    return CRYPT_SUCCESS;
}

void MODES_WRAP_FreeCtx(MODES_WRAP_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return ;
    }
    (void)MODE_WRAP_DeInitCtx(modeCtx);
    BSL_SAL_CleanseData((void *)(modeCtx->wrapCtx.iv), CRYPT_WRAP_BLOCKSIZE);
    BSL_SAL_Free(modeCtx->wrapCtx.ciphCtx);
    BSL_SAL_Free(modeCtx);
}

int32_t MODE_WRAP_Ctrl(MODES_WRAP_Ctx *modeCtx, int32_t opt, void *val, uint32_t len)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    switch (opt) {
        case CRYPT_CTRL_REINIT_STATUS:
            return WRAP_SetIV(&modeCtx->wrapCtx, val, len);
        case CRYPT_CTRL_GET_IV:
            return WRAP_GetIV(&modeCtx->wrapCtx, (uint8_t *)val, len);
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || len != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(int32_t *)val = WRAP_BLOCKSIZE;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TYPE_ERROR);
            return CRYPT_MODES_CTRL_TYPE_ERROR;
    }
}

#endif
