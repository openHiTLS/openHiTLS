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
#ifdef HITLS_CRYPTO_GCM

#include <stdint.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes_gcm.h"
#include "modes_local.h"
#include "crypt_modes.h"

int32_t MODES_GCM_SetKey(MODES_CipherGCMCtx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = ctx->ciphMeth->setEncryptKey(ctx->ciphCtx, key, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return MODES_GCM_InitHashTable(ctx);
}

int32_t MODES_GCM_InitHashTable(MODES_CipherGCMCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint8_t gcmKey[GCM_BLOCKSIZE] = { 0 };
    int32_t ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, gcmKey, gcmKey, GCM_BLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    GcmTableGen4bit(gcmKey, ctx->hTable);
    ctx->tagLen = GCM_BLOCKSIZE;
    BSL_SAL_CleanseData(gcmKey, sizeof(gcmKey));
    return CRYPT_SUCCESS;
}

// Update the number of usage times.
static int32_t CheckUseCnt(const MODES_CipherGCMCtx *ctx)
{
    // 128, 120, 112, 104, or 96 that is 12 byte - 16 byte
    if (ctx->cryptCnt == GCM_MAX_INVOCATIONS_TIMES) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_KEYUSE_TOOMANY_TIME);
        return CRYPT_MODES_KEYUSE_TOOMANY_TIME;
    }
    return CRYPT_SUCCESS;
}

/**
 * NIST_800-38D-5.2
 * 1 ≤ len(IV) ≤ 2^64 - 1 (bit)
 * It is currently restricted to no more than 2^32 - 1 bytes
 */
int32_t MODES_GCM_SetIv(MODES_CipherGCMCtx *ctx, const uint8_t *iv, uint32_t ivLen)
{
    if (iv == NULL || ivLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CheckUseCnt(ctx); // Check the number of usage times.
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t i;
    uint64_t len = (uint64_t)ivLen;
    // when ivLen == 0, do reinit, no need to refersh iv
    if (len == 12) { // len(IV ) = 96bit = 12byte
        const uint8_t ivPad[4] = {0x00, 0x00, 0x00, 0x01};
        /* Y0 = IV || 0^31 || 1  if len(IV ) = 96 = 12byte */
        (void)memcpy_s(ctx->iv, GCM_BLOCKSIZE, iv, 12);
        (void)memcpy_s(ctx->iv + 12, GCM_BLOCKSIZE - 12, ivPad, sizeof(ivPad)); // pad last 4bit(base = 12)
    } else {
        /* Y0 = GHASH(H, {}, IV ) otherwise */
        (void)memset_s(ctx->iv, GCM_BLOCKSIZE, 0, GCM_BLOCKSIZE);
        const uint8_t *off = iv;
        uint32_t blockLen = ivLen & GCM_BLOCK_MASK;
        uint32_t lastLen = ivLen - blockLen;
        uint8_t tmp[GCM_BLOCKSIZE] = {0};
        if (blockLen > 0) {
            GcmHashMultiBlock(ctx->iv, ctx->hTable, off, blockLen);
            off += blockLen;
        }
        if (lastLen > 0) {
            for (i = 0; i < lastLen; i++) {
                tmp[i] = off[i];
            }
            GcmHashMultiBlock(ctx->iv, ctx->hTable, tmp, GCM_BLOCKSIZE);
        }
        len = (uint64_t)ivLen << 3; // bitLen = byteLen << 3
        (void)BSL_SAL_CleanseData(tmp, GCM_BLOCKSIZE);
        Uint64ToBeBytes(len, tmp + 8); // The last 8 bytes store the length of the IV.
        GcmHashMultiBlock(ctx->iv, ctx->hTable, tmp, GCM_BLOCKSIZE);
    }
    /**
     * NIST_800-38D-7.1
     * GCTR(J0)
     */
    ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->iv, ctx->ek0, GCM_BLOCKSIZE);

    /**
     * NIST_800-38D-7.1
     * INC32
     * the 32-bit incrementing function is applied to the pre-counter block
     * to produce the initial counter block for an invocation of the GCTR
     * function on the plaintext
     */
    uint32_t ctr = GET_UINT32_BE(ctx->iv, 12); // Offset of 12 bytes. Use the last four bytes.
    ctr++;
    PUT_UINT32_BE(ctr, ctx->iv, 12); // Writeback of offset 12 bytes

    // Reset information.
    (void)memset_s(ctx->ghash, GCM_BLOCKSIZE, 0, GCM_BLOCKSIZE);
    ctx->aadLen = 0;
    (void)memset_s(ctx->last, GCM_BLOCKSIZE, 0, GCM_BLOCKSIZE);
    ctx->lastLen = 0;
    ctx->plaintextLen = 0;
    (void)memset_s(ctx->remCt, GCM_BLOCKSIZE, 0, GCM_BLOCKSIZE);

    // Clear sensitive information.
    BSL_SAL_CleanseData(&ctr, sizeof(uint32_t));
    return CRYPT_SUCCESS;
}

/**
 * NIST_800-38D-5.2
 * len(AAD) ≤ 2^64 - 1 (bit)
 * Currently, it is restricted to no more than 2^32 - 1 bytes.
 */
static int32_t SetAad(MODES_CipherGCMCtx *ctx, const uint8_t *aad, uint32_t aadLen)
{
    if (aad == NULL && aadLen != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const uint8_t *off = aad;
    uint32_t i;
    if (ctx->aadLen != 0 || ctx->plaintextLen != 0) { // aad is set
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_AAD_REPEAT_SET_ERROR);
        return CRYPT_MODES_AAD_REPEAT_SET_ERROR;
    }
    uint32_t blockLen = aadLen & GCM_BLOCK_MASK;
    uint32_t lastLen = aadLen - blockLen;
    if (blockLen > 0) {
        GcmHashMultiBlock(ctx->ghash, ctx->hTable, off, blockLen);
        off += blockLen;
    }
    if (lastLen > 0) {
        uint8_t temp[GCM_BLOCKSIZE] = {0};
        for (i = 0; i < lastLen; i++) {
            temp[i] = off[i];
        }
        GcmHashMultiBlock(ctx->ghash, ctx->hTable, temp, GCM_BLOCKSIZE);
    }
    ctx->aadLen = aadLen;
    return CRYPT_SUCCESS;
}

// Overflow occurs when the encryption length is determined and the encrypted length information is updated.
int32_t CryptLenCheckAndRefresh(MODES_CipherGCMCtx *ctx, uint32_t len)
{
    // The length of len is only 32 bits. This calculation does not cause overflow.
    uint64_t plaintextLen = ctx->plaintextLen + len;
    if (plaintextLen > GCM_MAX_COMBINED_LENGTH) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
        return CRYPT_MODES_CRYPTLEN_OVERFLOW;
    }
    ctx->plaintextLen = plaintextLen;
    return CRYPT_SUCCESS;
}

static void GcmXorInEncrypt(XorCryptData *data, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i++) {
        data->out[i] = data->in[i] ^ data->ctr[i];
        data->tag[i] = data->out[i];
    }
}

static void GcmXorInDecrypt(XorCryptData *data, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i++) {
        data->tag[i] = data->in[i];
        data->out[i] = data->in[i] ^ data->ctr[i];
    }
}

// Process the remaining data in the last update.
uint32_t MODES_GCM_LastHandle(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    uint32_t lastLen = 0;
    if (ctx->lastLen > 0) {
        XorCryptData data;
        lastLen = (ctx->lastLen < len) ? ctx->lastLen : len;
        data.in = in;
        data.out = out;
        data.ctr = &(ctx->last[GCM_BLOCKSIZE - ctx->lastLen]);
        data.tag = &(ctx->remCt[GCM_BLOCKSIZE - ctx->lastLen]);
        if (enc) { // ctx->lastLen must be smaller than the GCM_BLOCKSIZE
            GcmXorInEncrypt(&data, lastLen);
        } else {
            GcmXorInDecrypt(&data, lastLen);
        }
        // Refresh the remaining length.
        ctx->lastLen -= lastLen;
        if (ctx->lastLen == 0) {
            GcmHashMultiBlock(ctx->ghash, ctx->hTable, ctx->remCt, GCM_BLOCKSIZE);
        }
    }
    return lastLen;
}

static void GcmMultiBlockCrypt(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    uint32_t blockLen = len;
    const uint8_t *dataIn = in;
    uint8_t *dataOut = out;
    // count information, last 32 bits of the IV, with an offset of 12 bytes (16-4 = 12)
    uint32_t ctr = GET_UINT32_BE(ctx->iv, 12);
    if (enc == false) {
        GcmHashMultiBlock(ctx->ghash, ctx->hTable, in, len);
    }
    while (blockLen > 0) {
        ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->iv, ctx->last, GCM_BLOCKSIZE);
        DATA64_XOR(dataIn, ctx->last, dataOut, GCM_BLOCKSIZE);
        /**
        * NIST_800-38D-7.1
        * INC32
        */
        ctr++;
        PUT_UINT32_BE(ctr, ctx->iv, 12); // Offset of 12 bytes. Use the last four bytes.
        // Refresh the remaining length.
        blockLen -= GCM_BLOCKSIZE;
        // offset
        dataIn += GCM_BLOCKSIZE;
        dataOut += GCM_BLOCKSIZE;
    }
    if (enc) {
        GcmHashMultiBlock(ctx->ghash, ctx->hTable, out, len);
    }
    // Clear sensitive information.
    BSL_SAL_CleanseData(&ctr, sizeof(uint32_t));
}

// enc: true: the encryption operation, false: the decryption operation
static int32_t MODES_GCM_Crypt(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    if (ctx == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != 0 && in == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CryptLenCheckAndRefresh(ctx, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t lastLen = MODES_GCM_LastHandle(ctx, in, out, len, enc);
    // Data processing is complete. Exit.
    if (lastLen == len) {
        return CRYPT_SUCCESS;
    }

    XorCryptData data;
    data.in = in + lastLen;
    data.out = out + lastLen;
    data.ctr = ctx->last;
    data.tag = ctx->remCt;

    uint32_t multiBlockLen = (len - lastLen) & GCM_BLOCK_MASK;
    if (multiBlockLen > 0) {
        GcmMultiBlockCrypt(ctx, data.in, data.out, multiBlockLen, enc);
        data.in += multiBlockLen;
        data.out += multiBlockLen;
    }
    uint32_t remLen = len - lastLen - multiBlockLen;
    if (remLen > 0) {
        // count information, last 32 bits of the IV, with an offset of 12 bytes (16-4 = 12)
        uint32_t ctr = GET_UINT32_BE(ctx->iv, 12);
        (void)ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->iv, ctx->last, GCM_BLOCKSIZE);
        if (enc) {
            GcmXorInEncrypt(&data, remLen);
        } else {
            GcmXorInDecrypt(&data, remLen);
        }
        /**
         * NIST_800-38D-7.1
         * INC32
         */
        ctr++;
        PUT_UINT32_BE(ctr, ctx->iv, 12); // Offset of 12 bytes. Use the last four bytes.
        // Clear sensitive information.
        BSL_SAL_CleanseData(&ctr, sizeof(uint32_t));
    }
    ctx->lastLen = (remLen > 0) ? (GCM_BLOCKSIZE - remLen) : 0;

    return CRYPT_SUCCESS;
}

static void GcmPad(MODES_CipherGCMCtx *ctx)
{
    // S = GHASHH (A || 0v || C || 0u || [len(A)]64 || [len(C)]64).
    if (ctx->lastLen != 0) {
        uint32_t offset = GCM_BLOCKSIZE - ctx->lastLen;
        (void)memset_s(ctx->remCt + offset, GCM_BLOCKSIZE - offset, 0, ctx->lastLen);
        GcmHashMultiBlock(ctx->ghash, ctx->hTable, ctx->remCt, GCM_BLOCKSIZE);
    }
    uint64_t aadLen = (uint64_t)(ctx->aadLen) << 3; // bitLen = byteLen << 3
    uint64_t plaintextLen = ctx->plaintextLen << 3; // bitLen = byteLen << 3
    uint8_t padBuf[GCM_BLOCKSIZE];
    Uint64ToBeBytes(aadLen, padBuf);
    Uint64ToBeBytes(plaintextLen, padBuf + 8); // The last 64 bits (8 bytes) is the length of the ciphertext.

    GcmHashMultiBlock(ctx->ghash, ctx->hTable, padBuf, GCM_BLOCKSIZE);
}

static int32_t SetTagLen(MODES_CipherGCMCtx *ctx, const uint8_t *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TAGLEN_ERROR);
        return CRYPT_MODES_CTRL_TAGLEN_ERROR;
    }
    /**
     * NIST_800-38D-5.2.1.2
     * The bit length of the tag, denoted t, is a security parameter, as discussed in Appendix B.
     * In general, t may be any one of the following five values: 128, 120, 112, 104, or 96. For certain
     * applications, t may be 64 or 32; guidance for the use of these two tag lengths, including
     * requirements on the length of the input data and the lifetime of the ciphCtx in these cases,
     * is given in Appendix C
     */
    uint32_t tagLen = *((const uint32_t *)val);
    // 32bit is 4 bytes, 64bit is 8 bytes, 128, 120, 112, 104, or 96 is 12byte - 16byte
    if (tagLen == 4 || tagLen == 8 || (tagLen >= 12 && tagLen <= 16)) {
        ctx->tagLen = (uint8_t)tagLen;
        return CRYPT_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TAGLEN_ERROR);
    return CRYPT_MODES_CTRL_TAGLEN_ERROR;
}

static int32_t GetTag(MODES_CipherGCMCtx *ctx, uint8_t *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != ctx->tagLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_TAGLEN_ERROR);
        return CRYPT_MODES_TAGLEN_ERROR;
    }
    ctx->cryptCnt++; // The encryption/decryption process ends. Key usage times + 1
    GcmPad(ctx);
    uint32_t i;
    for (i = 0; i < len; i++) {
        val[i] = ctx->ghash[i] ^ ctx->ek0[i];
    }
    return CRYPT_SUCCESS;
}

int32_t MODES_GCM_Encrypt(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODES_GCM_Crypt(ctx, in, out, len, true);
}

int32_t MODES_GCM_Decrypt(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return MODES_GCM_Crypt(ctx, in, out, len, false);
}

int32_t MODES_GCM_Ctrl(MODES_GCM_Ctx *modeCtx, int32_t opt, void *val, uint32_t len)
{
    if (modeCtx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_IV:
        case CRYPT_CTRL_REINIT_STATUS:
            return MODES_GCM_SetIv(&modeCtx->gcmCtx, val, len);
        case CRYPT_CTRL_SET_TAGLEN:
            return SetTagLen(&modeCtx->gcmCtx, val, len);
        case CRYPT_CTRL_SET_AAD:
            return SetAad(&modeCtx->gcmCtx, val, len);
        case CRYPT_CTRL_GET_TAG:
            return GetTag(&modeCtx->gcmCtx, val, len);
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(int32_t *)val = 1;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TYPE_ERROR);
            return CRYPT_MODES_CTRL_TYPE_ERROR;
    }
}

MODES_GCM_Ctx *MODES_GCM_NewCtx(int32_t algId)
{
    const EAL_SymMethod *method = EAL_GetSymMethod(algId);
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    MODES_GCM_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(MODES_GCM_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return ctx;
    }
    ctx->algId = algId;

    ctx->gcmCtx.ciphCtx = BSL_SAL_Calloc(1, method->ctxSize);
    if (ctx->gcmCtx.ciphCtx  == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(ctx);
        return NULL;
    }

    ctx->gcmCtx.ciphMeth = method;
    return ctx;
}

MODES_GCM_Ctx *MODES_GCM_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    return MODES_GCM_NewCtx(algId);
}

int32_t MODES_GCM_InitCtx(MODES_GCM_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = MODES_GCM_SetKey(&modeCtx->gcmCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = MODES_GCM_SetIv(&modeCtx->gcmCtx, iv, ivLen);
    if (ret != CRYPT_SUCCESS) {
        (void)MODES_GCM_DeInitCtx(modeCtx);
        return ret;
    }
    modeCtx->enc = enc;
    return ret;
}

int32_t MODES_GCM_Update(MODES_GCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(modeCtx->enc ? MODES_GCM_Encrypt : MODES_GCM_Decrypt, &modeCtx->gcmCtx,
        in, inLen, out, outLen);
}

int32_t MODES_GCM_Final(MODES_GCM_Ctx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    (void) modeCtx;
    (void) out;
    (void) outLen;
    return CRYPT_EAL_CIPHER_FINAL_WITH_AEAD_ERROR;
}

int32_t MODES_GCM_DeInitCtx(MODES_GCM_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t algId = modeCtx->algId;
    void *ciphCtx = modeCtx->gcmCtx.ciphCtx;
    const EAL_SymMethod *ciphMeth = modeCtx->gcmCtx.ciphMeth;
    modeCtx->gcmCtx.ciphMeth->cipherDeInitCtx(ciphCtx);
    BSL_SAL_CleanseData((void *)(&(modeCtx->gcmCtx)), sizeof(MODES_CipherGCMCtx));
    modeCtx->gcmCtx.ciphCtx = ciphCtx;
    modeCtx->gcmCtx.ciphMeth = ciphMeth;
    modeCtx->algId = algId;
    return CRYPT_SUCCESS;
}

void MODES_GCM_FreeCtx(MODES_GCM_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return;
    }
    (void)BSL_SAL_ClearFree(modeCtx->gcmCtx.ciphCtx, modeCtx->gcmCtx.ciphMeth->ctxSize);
    (void)BSL_SAL_CleanseData(modeCtx, sizeof(MODES_GCM_Ctx));
    BSL_SAL_Free(modeCtx);
}


int32_t MODES_GCM_InitCtxEx(MODES_GCM_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc)
{
    (void)param;
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_SM4_GCM:
#ifdef HITLS_CRYPTO_SM4
            return SM4_GCM_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_GCM_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
    }
}

int32_t MODES_GCM_UpdateEx(MODES_GCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_AES128_GCM:
        case CRYPT_CIPHER_AES192_GCM:
        case CRYPT_CIPHER_AES256_GCM:
#ifdef HITLS_CRYPTO_AES
            return AES_GCM_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        case CRYPT_CIPHER_SM4_GCM:
#ifdef HITLS_CRYPTO_SM4
            return SM4_GCM_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_GCM_Update(modeCtx, in, inLen, out, outLen);
    }
}

#endif