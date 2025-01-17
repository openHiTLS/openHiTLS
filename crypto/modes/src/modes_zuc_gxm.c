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
#if defined(HITLS_CRYPTO_ZUC_GXM) && defined(HITLS_CRYPTO_GCM)

#include <stdint.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes_zuc_gxm.h"
#include "modes_local.h"
#include "crypt_modes.h"

/**
 * len(P) ≤ 2^39-256 (bit)
 * Equivalent to len(P) ≤ 2^36 - 32 (byte)
 */
#define GCM_MAX_COMBINED_LENGTH     (((uint64_t)1 << 36) - 32)
/**
 * The total number of invocations of the authenticated encryption function shall not exceed
 * 2^32, including all IV lengths and all instances of the authenticated encryption function with
 * the given ciphCtx
 */
#define GCM_MAX_INVOCATIONS_TIMES   ((uint32_t)(-1))
#define GCM_BLOCK_MASK (0xfffffff0)

int32_t MODES_ZUC_GXM_SetKey(MODES_CipherZUCGXMCtx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = ctx->ciphMeth->setEncryptKey(ctx->ciphCtx, key, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // if iv not set in zuc, the stream cipher can't encrypt
    return CRYPT_SUCCESS;
}

int32_t MODES_ZUC_GXM_InitHashTable(MODES_CipherZUCGXMCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // H(ctx->hTable) = CIPH_{N, K}(0^128)
    uint8_t zeros[GCM_BLOCKSIZE] = {0};
    // ghash as temporary H key storage
    int32_t ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, zeros, ctx->ghash, GCM_BLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    GcmTableGen4bit(ctx->ghash, ctx->hTable);
    ctx->tagLen = 16;
    memset_s(ctx->ghash, GCM_BLOCKSIZE, 0, GCM_BLOCKSIZE);
    return CRYPT_SUCCESS;
}

// Update the number of usage times.
static int32_t CheckUseCnt(const MODES_CipherZUCGXMCtx *ctx)
{
    // 128, 120, 112, 104, or 96 that is 12 byte - 16 byte
    if (ctx->cryptCnt == GCM_MAX_INVOCATIONS_TIMES) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_KEYUSE_TOOMANY_TIME);
        return CRYPT_MODES_KEYUSE_TOOMANY_TIME;
    }
    return CRYPT_SUCCESS;
}

/**
 * len(IV) == 16 bytes (128 bits) or 23 bytes (184 bits)
 */
int32_t MODES_ZUC_GXM_SetIv(MODES_CipherZUCGXMCtx *ctx, const uint8_t *iv, uint32_t ivLen)
{
    if (iv == NULL || ivLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CheckUseCnt(ctx); // Check the number of usage times.
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint64_t len = (uint64_t)ivLen;
    uint8_t off[ivLen];
    memcpy_s(off, ivLen, iv, ivLen);
    // when ivLen == 0, do reinit, no need to refersh iv
    ret = ctx->ciphMeth->CipherCtrl(ctx->ciphCtx, CRYPT_CTRL_SET_IV, off, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    } // no else, if the iv not set in zuc, the stream cipher can't encrypt

    ret = MODES_ZUC_GXM_InitHashTable(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // Reset information.
    (void)memset_s(ctx->ghash, GCM_BLOCKSIZE, 0, GCM_BLOCKSIZE);
    (void)memset_s(ctx->lastz0, GCM_BLOCKSIZE, 0, GCM_BLOCKSIZE);
    ctx->aadLen = 0;
    ctx->plaintextLen = 0;

    BSL_SAL_CleanseData(off, sizeof(off));

    return CRYPT_SUCCESS;
}

/**
 * len(Plaintext) + len(AAD) ≤ 2^64 - 1 (bit)
 * Currently, it is restricted to no more than 2^32 - 1 bits.
 * This function sets Aad in ctx->ghash
 */
static int32_t SetAad(MODES_CipherZUCGXMCtx *ctx, const uint8_t *aad, uint32_t aadLen)
{
    if (aad == NULL && aadLen != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const uint8_t *off = aad;
    uint32_t i;
    if (ctx->aadLen != 0) { // aad is set
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_AAD_REPEAT_SET_ERROR);
        return CRYPT_MODES_AAD_REPEAT_SET_ERROR;
    }
    /**
     * aadLen = blockLen + lastLen, where blockLen mod 16 = 0,
     * AAD(A): As a |A| bit binary string, A can be represented as 
     * A[0] || ... || A[x-1] || A[x] || 0^{128*x - |A|}, x = ceil(|A|/128)
     * if blockLen > 0, loop: Y = H*(Y XOR A[i]), each A[i] represents a 128 bit string,
     * if lastLen > 0, Y = H*(Y XOR (A[x] || 0^{128*x - |A|}))
     */ 
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
static int32_t CryptLenCheckAndRefresh(MODES_CipherZUCGXMCtx *ctx, uint32_t len)
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

static void GcmPad(MODES_CipherZUCGXMCtx *ctx)
{
    // S = GHASHH (A || 0v || C || 0u || [len(A)]64 || [len(C)]64).
    uint64_t aadLen = (uint64_t)(ctx->aadLen) << 3; // bitLen = byteLen << 3
    uint64_t plaintextLen = ctx->plaintextLen << 3; // bitLen = byteLen << 3
    uint8_t padBuf[GCM_BLOCKSIZE];
    Uint64ToBeBytes(aadLen, padBuf);
    Uint64ToBeBytes(plaintextLen, padBuf + 8); // The last 64 bits (8 bytes) is the length of the ciphertext.

    GcmHashMultiBlock(ctx->ghash, ctx->hTable, padBuf, GCM_BLOCKSIZE);
}

static int32_t SetTagLen(MODES_CipherZUCGXMCtx *ctx, const uint8_t *val, uint32_t len)
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

// TAG = GHASH_H(A, C) XOR z0
static int32_t GetTag(MODES_CipherZUCGXMCtx *ctx, uint8_t *val, uint32_t len)
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
        val[i] = ctx->ghash[i] ^ ctx->lastz0[i];
    }
    return CRYPT_SUCCESS;
}

/**
 * ZUC-GXM(E)_{H,K}(N; A; P)
 * H, K, N, A: preset in ctx
 * in: Plaintext need to send
 * len: Plaintext length
 * out: Ciphertext
*/ 
int32_t MODES_ZUC_GXM_Encrypt(MODES_CipherZUCGXMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CryptLenCheckAndRefresh(ctx, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, in, out, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // z0 = 0^128 XOR 128 bits keystream
    uint8_t zeros[GCM_BLOCKSIZE] = {0};
    ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, zeros, ctx->lastz0, GCM_BLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // GHASH_H(A, C)
    GcmHashMultiBlock(ctx->ghash, ctx->hTable, out, len);
    // Calculate Tag only when CIPHER_CTRL(GET_TAG) called
    ctx->plaintextLen += (uint64_t)len;
    return CRYPT_SUCCESS;
}

/**
 * ZUC-GXM(D)_{H,K}(N; A; C; Tag)
 * H, K, N, A: preset in ctx
 * Tag: ctx->ghash
 * in: Ciphertext
 * out: Plaintext
 * len: Plaintext length
*/ 
int32_t MODES_ZUC_GXM_Decrypt(MODES_CipherZUCGXMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || in == NULL || out == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CryptLenCheckAndRefresh(ctx, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // GHASH_H(A, C)
    GcmHashMultiBlock(ctx->ghash, ctx->hTable, in, len);
    ctx->plaintextLen += (uint64_t)len;

    ret = ctx->ciphMeth->decryptBlock(ctx->ciphCtx, in, out, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // z0 = 0^128 XOR 128 bits keystream
    uint8_t zeros[GCM_BLOCKSIZE] = {0};
    ret = ctx->ciphMeth->decryptBlock(ctx->ciphCtx, zeros, ctx->lastz0, GCM_BLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t MODES_ZUC_GXM_Ctrl(MODES_ZUC_GXM_Ctx *modeCtx, int32_t opt, void *val, uint32_t len)
{
    if (modeCtx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_REINIT_STATUS:
            return MODES_ZUC_GXM_SetIv(&modeCtx->gxmCtx, val, len);
        case CRYPT_CTRL_SET_TAGLEN:
            return SetTagLen(&modeCtx->gxmCtx, val, len);
        case CRYPT_CTRL_SET_AAD:
            return SetAad(&modeCtx->gxmCtx, val, len);
        case CRYPT_CTRL_GET_TAG:
            return GetTag(&modeCtx->gxmCtx, val, len);
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(int32_t *)val = 1;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_METHODS_NOT_SUPPORT);
            return CRYPT_MODES_METHODS_NOT_SUPPORT;
    }
}

MODES_ZUC_GXM_Ctx *MODES_ZUC_GXM_NewCtx(int32_t algId)
{
    const EAL_SymMethod *method = MODES_GetSymMethod(algId);
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    MODES_ZUC_GXM_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(MODES_ZUC_GXM_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return ctx;
    }

    ctx->algId = algId;

    ctx->gxmCtx.ciphCtx = BSL_SAL_Calloc(1, method->ctxSize);
    if (ctx->gxmCtx.ciphCtx  == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(ctx);
        return NULL;
    }

    ctx->gxmCtx.ciphMeth = method;
    return ctx;
}


/**
 * For a stream cipher, key and iv are needed in initialization,
 * so firstly set key, then set iv and init zuc,
 * finally set H key for GHASH_H using encrypt function.
 */ 
int32_t MODES_ZUC_GXM_InitCtx(MODES_ZUC_GXM_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, const BSL_Param *param, bool enc)
{
    (void)param;
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = MODES_ZUC_GXM_SetKey(&modeCtx->gxmCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = MODES_ZUC_GXM_SetIv(&modeCtx->gxmCtx, iv, ivLen);
    if (ret != CRYPT_SUCCESS) {
        MODES_ZUC_GXM_DeInitCtx(modeCtx);
        return ret;
    }
    modeCtx->enc = enc;
    return CRYPT_SUCCESS;
}

int32_t MODES_ZUC_GXM_Update(MODES_ZUC_GXM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(modeCtx->enc ? MODES_ZUC_GXM_Encrypt : MODES_ZUC_GXM_Decrypt, &modeCtx->gxmCtx,
        in, inLen, out, outLen);
}

int32_t MODES_ZUC_GXM_Final(MODES_ZUC_GXM_Ctx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    (void) modeCtx;
    (void) out;
    *outLen = 0;
    return CRYPT_SUCCESS;
}

int32_t MODES_ZUC_GXM_DeInitCtx(MODES_ZUC_GXM_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    void *ciphCtx = modeCtx->gxmCtx.ciphCtx;
    const EAL_SymMethod *ciphMeth = modeCtx->gxmCtx.ciphMeth;
    BSL_SAL_CleanseData((void *)(ciphCtx), ciphMeth->ctxSize);
    BSL_SAL_CleanseData((void *)(modeCtx), sizeof(MODES_ZUC_GXM_Ctx));
    modeCtx->gxmCtx.ciphCtx = ciphCtx;
    modeCtx->gxmCtx.ciphMeth = ciphMeth;
    return CRYPT_SUCCESS;
}

void MODES_ZUC_GXM_FreeCtx(MODES_ZUC_GXM_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return;
    }
    (void)BSL_SAL_ClearFree(modeCtx->gxmCtx.ciphCtx, modeCtx->gxmCtx.ciphMeth->ctxSize);
    (void)BSL_SAL_CleanseData(modeCtx, sizeof(MODES_ZUC_GXM_Ctx));
    BSL_SAL_Free(modeCtx);
    modeCtx = NULL;
}

#endif