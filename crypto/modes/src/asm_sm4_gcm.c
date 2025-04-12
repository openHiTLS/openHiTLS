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
#if defined(HITLS_CRYPTO_SM4) && defined(HITLS_CRYPTO_GCM)

#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "modes_local.h"
#include "crypt_modes_gcm.h"

int32_t MODES_SM4_GCM_SetKey(MODES_CipherGCMCtx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint8_t gcmKey[GCM_BLOCKSIZE] = { 0 };
    int32_t ret = CRYPT_SM4_SetEncryptKey(ctx->ciphCtx, key, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, gcmKey, gcmKey, GCM_BLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    GcmTableGen4bit(gcmKey, ctx->hTable);
    ctx->tagLen = 16; // The default tag length is 128 bits, that is, 16 bytes.
    BSL_SAL_CleanseData(gcmKey, sizeof(gcmKey));
    return CRYPT_SUCCESS;
}

static void GcmRemHandle(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    (void)ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->iv, ctx->last, GCM_BLOCKSIZE);
    uint32_t i;
    if (enc) {
        for (i = 0; i < len; i++) {
            out[i] = in[i] ^ ctx->last[i];
            ctx->remCt[i] = out[i];
        }
    } else {
        for (i = 0; i < len; i++) {
            ctx->remCt[i] = in[i];
            out[i] = in[i] ^ ctx->last[i];
        }
    }

    uint32_t ctr = GET_UINT32_BE(ctx->iv, 12); // offset 12 bytes and obtain the last four bytes
    ctr++;
    PUT_UINT32_BE(ctr, ctx->iv, 12); // offset 12 bytes and obtain the last four bytes
    ctx->lastLen = GCM_BLOCKSIZE - len;
}

int32_t MODES_SM4_GCM_EncryptBlock(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    ctx->plaintextLen += len;
    uint32_t lastLen = MODES_GCM_LastHandle(ctx, in, out, len, true);
    // Data processing is complete. Exit.
    if (lastLen == len) {
        return CRYPT_SUCCESS;
    }
    const uint8_t *tmpIn = in + lastLen;
    uint8_t *tmpOut = out + lastLen;
    uint32_t clen = len - lastLen;
    if (clen >= GCM_BLOCKSIZE) {
        uint32_t calLen = clen & 0xfffffff0;
        (void)CRYPT_SM4_CTR_Encrypt(ctx->ciphCtx, tmpIn, tmpOut, calLen / GCM_BLOCKSIZE, ctx->iv);
        GcmHashMultiBlock(ctx->ghash, ctx->hTable, tmpOut, calLen);
        clen -= calLen;
        tmpIn += calLen;
        tmpOut += calLen;
    }
    if (clen > 0) { // tail processing
        GcmRemHandle(ctx, tmpIn, tmpOut, clen, true);
    }
    return CRYPT_SUCCESS;
}

int32_t MODES_SM4_GCM_DecryptBlock(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    ctx->plaintextLen += len;
    uint32_t lastLen = MODES_GCM_LastHandle(ctx, in, out, len, false);
    // Data processing is complete. Exit.
    if (lastLen == len) {
        return CRYPT_SUCCESS;
    }
    const uint8_t *tmpIn = in + lastLen;
    uint8_t *tmpOut = out + lastLen;
    uint32_t clen = len - lastLen;
    if (clen >= GCM_BLOCKSIZE) {
        uint32_t calLen = clen & 0xfffffff0; // Obtains the length that is an integer multiple of 16 bytes.
        GcmHashMultiBlock(ctx->ghash, ctx->hTable, tmpIn, calLen);
        (void)CRYPT_SM4_CTR_Encrypt(ctx->ciphCtx, tmpIn, tmpOut, calLen / GCM_BLOCKSIZE, ctx->iv);
        tmpIn += calLen;
        tmpOut += calLen;
        clen -= calLen;
    }
    if (clen > 0) { // tail processing
        GcmRemHandle(ctx, tmpIn, tmpOut, clen, false);
    }
    return CRYPT_SUCCESS;
}

int32_t SM4_GCM_InitCtx(MODES_GCM_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    int32_t ret = MODES_SM4_GCM_SetKey(&modeCtx->gcmCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    ret = MODES_GCM_SetIv(&modeCtx->gcmCtx, iv, ivLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        (void)MODES_GCM_DeInitCtx(modeCtx);
        return ret;
    }
    modeCtx->enc = enc;
    return ret;
}

int32_t SM4_GCM_Update(MODES_GCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(modeCtx->enc ? MODES_SM4_GCM_EncryptBlock : MODES_SM4_GCM_DecryptBlock,
        &modeCtx->gcmCtx, in, inLen, out, outLen);
}
#endif
