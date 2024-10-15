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
#ifdef HITLS_CRYPTO_CCM

#include <stdint.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes.h"
#include "ccm_core.h"
#include "crypt_modes_ccm.h"


int32_t MODES_CCM_InitCtx(MODES_CCM_Ctx *ctx, const struct EAL_CipherMethod *m)
{
    if (ctx == NULL || m == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)memset_s(ctx, sizeof(MODES_CCM_Ctx), 0, sizeof(MODES_CCM_Ctx));
    ctx->ciphMeth = m;
    ctx->ciphCtx = BSL_SAL_Malloc(m->ctxSize);
    if (ctx->ciphCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

void MODES_CCM_DeinitCtx(MODES_CCM_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_CleanseData(ctx->ciphCtx, ctx->ciphMeth->ctxSize);
    BSL_SAL_FREE(ctx->ciphCtx);
    BSL_SAL_CleanseData(ctx, sizeof(MODES_CCM_Ctx));
}

void MODES_CCM_Clean(MODES_CCM_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    void *ciphCtx = ctx->ciphCtx;
    const EAL_CipherMethod *ciphMeth = ctx->ciphMeth;
    BSL_SAL_CleanseData((void *)(ctx->ciphCtx), ctx->ciphMeth->ctxSize);
    BSL_SAL_CleanseData((void *)(ctx), sizeof(MODES_CCM_Ctx));

    ctx->ciphCtx = ciphCtx;
    ctx->ciphMeth = ciphMeth;
}

int32_t MODES_CCM_SetKey(MODES_CCM_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    MODES_CCM_Clean(ctx);
    ctx->tagLen = 16;
    return ctx->ciphMeth->setEncryptKey(ctx->ciphCtx, key, len);
}

void XorInEncrypt(XorCryptData *data, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i++) {
        data->tag[i] ^= data->in[i];
        data->out[i] = data->in[i] ^ data->ctr[i];
    }
}

void XorInEncryptBlock(XorCryptData *data)
{
    DATA64_XOR(data->in, data->tag, data->tag, CCM_BLOCKSIZE);
    DATA64_XOR(data->in, data->ctr, data->out, CCM_BLOCKSIZE);
}

void XorInDecrypt(XorCryptData *data, uint32_t len)
{
    uint32_t i;
    // Decryption
    for (i = 0; i < len; i++) {
        data->out[i] = data->in[i] ^ data->ctr[i];
        data->tag[i] ^= data->out[i];
    }
}

void XorInDecryptBlock(XorCryptData *data)
{
    DATA64_XOR(data->in, data->ctr, data->out, CCM_BLOCKSIZE);
    DATA64_XOR(data->out, data->tag, data->tag, CCM_BLOCKSIZE);
}

// Process the remaining data in the last update.
static uint32_t LastHandle(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    uint32_t lastLen = (ctx->lastLen < len) ? ctx->lastLen : len;
    if (ctx->lastLen > 0) {
        XorCryptData data;
        data.in = in;
        data.out = out;
        data.ctr = &(ctx->last[CCM_BLOCKSIZE - ctx->lastLen]);
        data.tag = &(ctx->tag[CCM_BLOCKSIZE - ctx->lastLen]);
        if (enc) {
            XorInEncrypt(&data, lastLen);
        } else {
            XorInDecrypt(&data, lastLen);
        }
        // Refresh the remaining length.
        // The judgment of the function entry ensures that lastLen does not exceed ctx->lastLen,
        // and this forcible transition does not occur truncation.
        ctx->lastLen -= (uint8_t)lastLen;
    }
    return lastLen;
}

static void RefreshNonce(MODES_CCM_Ctx *ctx)
{
    if ((ctx->nonce[0] & (~0x07)) != 0) {
        /**
         * RFC_3610-2.3
         * Bit Number   Contents
         * ----------   ----------------------
         * 7            Reserved (always zero)
         * 6            Reserved (always zero)
         * 5 ... 3      Zero
         * 2 ... 0      L'
         */
        ctx->nonce[0] &= 0x07;

        /**
         * RFC_3610-2.3
         * Octet Number   Contents
         * ------------   ---------
         * 0              Flags
         * 1 ... 15-L     Nonce N
         * 16-L ... 15    Counter i
         */
        uint8_t i;
        uint8_t l = ctx->nonce[0] + 1;
        for (i = 1; i < l; i++) {
            ctx->nonce[CCM_BLOCKSIZE - 1 - i] = 0;
        }
        /**
         * RFC_3610-2.3
         * The message is encrypted by XORing the octets of message m with the
         * first l(m) octets of the concatenation of S_1, S_2, S_3, ... .  Note
         * that S_0 is not used to encrypt the message.
         */
        ctx->nonce[CCM_BLOCKSIZE - 1] = 1;
    }
}

static int32_t TagInit(MODES_CCM_Ctx *ctx)
{
    if (ctx->tagInit == 0) {
        int32_t ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->nonce, ctx->tag, CCM_BLOCKSIZE);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ctx->tagInit = 1;
    }
    return CRYPT_SUCCESS;
}

static int32_t CcmBlocks(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    XorCryptData data;
    data.in = in;
    data.out = out;
    data.ctr = ctx->last;
    data.tag = ctx->tag;

    uint8_t countLen = (ctx->nonce[0] & 0x07) + 1;
    uint32_t dataLen = len;
    void (*xorBlock)(XorCryptData *data) = enc ? XorInEncryptBlock : XorInDecryptBlock;
    void (*xor)(XorCryptData *data, uint32_t len) = enc ? XorInEncrypt : XorInDecrypt;
    while (dataLen >= CCM_BLOCKSIZE) { // process the integer multiple of 16bytes data
        (void)ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->nonce, ctx->last, CCM_BLOCKSIZE);
        xorBlock(&data);
        (void)ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->tag, ctx->tag, CCM_BLOCKSIZE);
        MODE_IncCounter(ctx->nonce + CCM_BLOCKSIZE - countLen, countLen); // counter +1
        dataLen -= CCM_BLOCKSIZE;
        data.in += CCM_BLOCKSIZE;
        data.out += CCM_BLOCKSIZE;
    }
    if (dataLen > 0) { // process the integer multiple of 16bytes data
        (void)ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->nonce, ctx->last, CCM_BLOCKSIZE);
        xor(&data, dataLen);
        MODE_IncCounter(ctx->nonce + CCM_BLOCKSIZE - countLen, countLen); // counter +1
    }
    return CRYPT_SUCCESS;
}

// Enc: true for encryption and false for decryption.
int32_t CcmCrypt(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc, const CcmCore func)
{
    if (ctx == NULL || ctx->ciphCtx == NULL || in == NULL || out == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (len > ctx->msgLen) {
        // The message length is exceeded.
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_MSGLEN_OVERFLOW);
        return CRYPT_MODES_MSGLEN_OVERFLOW;
    }
    int32_t ret = TagInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Determine whether to start encryption and update the nonce information.
    RefreshNonce(ctx);

    uint32_t lastLen = LastHandle(ctx, in, out, len, enc);
    if (lastLen != 0 && ctx->lastLen == 0) {
        ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->tag, ctx->tag, CCM_BLOCKSIZE);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    // Data processing is complete and exits in advance.
    if (lastLen == len) {
        ctx->msgLen -= len; // Refresh the remaining length.
        return CRYPT_SUCCESS;
    }

    uint32_t tmpLen = len - lastLen;
    ret = func(ctx, in + lastLen, out + lastLen, tmpLen, enc);
    if (ret != CRYPT_SUCCESS) {
        // Returned by the internal function. No redundant push err is required.
        return ret;
    }
    ctx->lastLen = (CCM_BLOCKSIZE - (tmpLen % CCM_BLOCKSIZE)) % CCM_BLOCKSIZE;
    ctx->msgLen -= len; // Refresh the remaining length.
    return CRYPT_SUCCESS;
}

int32_t MODES_CCM_Encrypt(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return CcmCrypt(ctx, in, out, len, true, CcmBlocks);
}

int32_t MODES_CCM_Decrypt(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return CcmCrypt(ctx, in, out, len, false, CcmBlocks);
}

// 7 <= ivLen <= 13
static int32_t SetIv(MODES_CCM_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    /**
     * RFC_3610-2
     * Valid values of L range between 2 octets and 8 octets
     */
    // L = 15 - ivLen that is 7 <= ivLen <= 13
    if (len < 7 || len > 13) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_IVLEN_ERROR);
        return CRYPT_MODES_IVLEN_ERROR;
    }
    // The previous judgment limits the size of iv to [7, 13]. Therefore, forcible conversion does not cause truncation.
    uint8_t l = CCM_BLOCKSIZE - 1 - (uint8_t)len;

    // Clear data.
    void *ciphCtx = ctx->ciphCtx; // Handle used by the method
    const EAL_CipherMethod *ciphMeth = ctx->ciphMeth; // algorithm method
    uint8_t tagLen = ctx->tagLen;
    (void)memset_s(ctx, sizeof(MODES_CCM_Ctx), 0, sizeof(MODES_CCM_Ctx));
    ctx->ciphCtx = ciphCtx;
    ctx->ciphMeth = ciphMeth;
    ctx->tagLen = tagLen;

    uint8_t m = (ctx->tagLen - 2) / 2; // M' = (M - 2)/2
    ctx->nonce[0] = (uint8_t)((l - 1) & 0x7); // set L
    ctx->nonce[0] |= (m << 3); // set M. The default value of TagLen is 16bytes. (bit2 bit3 bit4) indicating the tagLen
    (void)memcpy_s(ctx->nonce + 1, CCM_BLOCKSIZE - 1, val, len);

    return CRYPT_SUCCESS;
}

// The input data is the uint64_t.
static int32_t SetMsgLen(MODES_CCM_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint64_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_MSGLEN_ERROR);
        return CRYPT_MODES_CTRL_MSGLEN_ERROR;
    }
    if ((ctx->nonce[0] & 0x40) != 0) {
        // If aad has been set, msgLen cannot be set.
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_AAD_IS_SET_ERROR);
        return CRYPT_MODES_AAD_IS_SET_ERROR;
    }
    const uint64_t msgLen = *(const uint64_t *)val;
    uint8_t l = (ctx->nonce[0] & 0x7) + 1;
    /**
     * RFC_3610-7
     * octet aligned message of arbitrary length, up to 2^(8*L) octets,
     * and octet aligned arbitrary additional authenticated data, up to
     * 2^64 octets
     */
    if (l < 8 && msgLen >= ((uint64_t)1 << (8 * l))) { // When l is 8, the condition must be met.
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_MSGLEN_ERROR);
        return CRYPT_MODES_CTRL_MSGLEN_ERROR;
    }
    uint8_t i;
    /**
     * RFC_3610-2.3
     * Octet Number   Contents
     * ------------   ---------
     * 0              Flags
     * 1 ... 15-L     Nonce N
     * 16-L ... 15    Counter i
     */
    uint8_t bytes[sizeof(uint64_t)];
    Uint64ToBeBytes(msgLen, bytes);
    for (i = 0; i < l; i++) {
        ctx->nonce[CCM_BLOCKSIZE - 1 - i] = bytes[8 - 1 - i]; // 8 bit msgLen information
    }
    ctx->msgLen = msgLen;
    return CRYPT_SUCCESS;
}

static int32_t SetTagLen(MODES_CCM_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TAGLEN_ERROR);
        return CRYPT_MODES_CTRL_TAGLEN_ERROR;
    }
    if ((ctx->nonce[0] & 0x40) != 0) {
        // If aad has been set, tagLen cannot be set.
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_AAD_IS_SET_ERROR);
        return CRYPT_MODES_AAD_IS_SET_ERROR;
    }
    /**
     * RFC_3610-2
     * Valid values are 4, 6, 8, 10, 12, 14, and 16 octets
     */
    uint32_t tagLen = *((const uint32_t *)val);
    // 4 <= tagLen <= 16 and tagLen is an even number.
    if (tagLen > 16 || tagLen < 4 || ((tagLen & 0x01) != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TAGLEN_ERROR);
        return CRYPT_MODES_CTRL_TAGLEN_ERROR;
    }
    ctx->tagLen = (uint8_t)tagLen;
    uint8_t m = (ctx->tagLen - 2) / 2; // M' = (M - 2)/2
    ctx->nonce[0] &= ~(0x7 << 3); // Clear 3|4|5 three bits
    ctx->nonce[0] |= (m << 3); // Set M
    return CRYPT_SUCCESS;
}

static uint32_t XorAadLen(MODES_CCM_Ctx *ctx, uint32_t aadLen)
{
    /**
     * RFC_3610-2.2
     * First two octets   Followed by       Comment
     * -----------------  ----------------  -------------------------------
     * 0x0000             Nothing           Reserved
     * 0x0001 ... 0xFEFF  Nothing           For 0 < l(a) < (2^16 - 2^8)
     * 0xFF00 ... 0xFFFD  Nothing           Reserved
     * 0xFFFE             4 octets of l(a)  For (2^16 - 2^8) <= l(a) < 2^32
     * 0xFFFF             8 octets of l(a)  For 2^32 <= l(a) < 2^64
     */
    uint32_t record; /* In order to record aadlen */
    // For 0 < l(a) < (2^16 - 2^8)
    if (aadLen < (((size_t)1 << 16) - ((size_t)1 << 8))) {
        /* 0 < l(a) < (2^16 - 2^8) */
        record = 2;          /* 2 octets */
        ctx->tag[1] ^= (uint8_t)aadLen;
        ctx->tag[0] ^= (uint8_t)(aadLen >> 8); // 1byte = 8bit
    } else {
        /* (2^16 - 2^8) <= l(a) < 2^32 */
        record = 6;          /* 6 octets */
        ctx->tag[5] ^= (uint8_t)aadLen;  // base offset = 5
        ctx->tag[4] ^= (uint8_t)(aadLen >> 8); // 1byte(off 5 -> 4) == 8bit
        ctx->tag[3] ^= (uint8_t)(aadLen >> 16); // 2byte(off 5 -> 3) == 16bit
        ctx->tag[2] ^= (uint8_t)(aadLen >> 24); // 3byte(off 5 -> 2) == 24bit
        ctx->tag[1] ^= 0xfe;
        ctx->tag[0] ^= 0xff;
    }
    return record;
}

// 0 < aadLen < 2^32
static int32_t SetAad(MODES_CCM_Ctx *ctx, const void *val, uint32_t len)
{
    if ((ctx->nonce[0] & 0x40) != 0) {
        // If aad has been set, the setting cannot be repeated.
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_AAD_REPEAT_SET_ERROR);
        return CRYPT_MODES_AAD_REPEAT_SET_ERROR;
    }
    if (len == 0) { // If AAD is 0, returned directly.
        return CRYPT_SUCCESS;
    }
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // bit6 Adata
    ctx->nonce[0] |= 0x40;
    // X_1 := E( K, B_0 )
    int32_t ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->nonce, ctx->tag, CCM_BLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ctx->tagInit = 1;

    uint32_t i;
    uint32_t aadLen = len;
    uint32_t record = XorAadLen(ctx, aadLen);
    const uint8_t *aad = val;
    uint32_t use = CCM_BLOCKSIZE - record;
    use = (use < aadLen) ? use : aadLen;
    for (i = 0; i < use; i++) {
        ctx->tag[i + record] ^= aad[i];
    }
    aad += use;
    aadLen -= use;
    ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->tag, ctx->tag, CCM_BLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    while (aadLen > 0) {
        uint32_t blockLen = (aadLen < CCM_BLOCKSIZE) ? aadLen : CCM_BLOCKSIZE;
        for (i = 0; i < blockLen; i++) {
            ctx->tag[i] ^= aad[i];
        }
        aad += blockLen;
        aadLen -= blockLen;
        ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->tag, ctx->tag, CCM_BLOCKSIZE);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t CtrTagCalc(MODES_CCM_Ctx *ctx)
{
    /**
     * RFC_3610-2.3
     * The authentication value U is computed by encrypting T with the ciphCtx
     * stream block S_0 and truncating it to the desired length.
     */
    ctx->nonce[0] &= 0x07; // update the nonce
    uint8_t l = (ctx->nonce[0] & 0x07) + 1;
    (void)memset_s(ctx->nonce + CCM_BLOCKSIZE - l, l, 0, l);
    int32_t ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->nonce, ctx->nonce, CCM_BLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t GetTag(MODES_CCM_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != ctx->tagLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_TAGLEN_ERROR);
        return CRYPT_MODES_TAGLEN_ERROR;
    }
    if (ctx->msgLen != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_MSGLEN_LEFT_ERROR);
        return CRYPT_MODES_MSGLEN_LEFT_ERROR;
    }
    int32_t ret = TagInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CtrTagCalc(ctx);
    if (ret != CRYPT_SUCCESS) {
        // An error is reported by the internal function, and no redundant pushErr is required.
        return ret;
    }
    if (ctx->lastLen != 0) {
        ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->tag, ctx->tag, CCM_BLOCKSIZE);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    uint32_t i;
    uint8_t *tag = val;
    /**
     * RFC_3610-2.3
     * U := T XOR first-M-bytes( S_0 )
     */
    for (i = 0; i < len; i++) {
        tag[i] = ctx->tag[i] ^ ctx->nonce[i];
    }
    return CRYPT_SUCCESS;
}

int32_t MODES_CCM_Ctrl(MODES_CCM_Ctx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_IV:
            return SetIv(ctx, val, len);
        case CRYPT_CTRL_SET_TAGLEN:
            return SetTagLen(ctx, val, len);
        case CRYPT_CTRL_SET_MSGLEN:
            return SetMsgLen(ctx, val, len);
        case CRYPT_CTRL_SET_AAD:
            return SetAad(ctx, val, len);
        case CRYPT_CTRL_GET_TAG:
            return GetTag(ctx, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_METHODS_NOT_SUPPORT);
            return CRYPT_MODES_METHODS_NOT_SUPPORT;
    }
}
#endif