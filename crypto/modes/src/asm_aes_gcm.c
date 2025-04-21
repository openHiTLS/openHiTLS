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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_GCM)

#include "crypt_aes.h"
#include "asm_aes_gcm.h"
#include "modes_local.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes_gcm.h"

int32_t AES_GCM_EncryptBlock(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx->ciphCtx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CryptLenCheckAndRefresh(ctx, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t lastLen = MODES_GCM_LastHandle(ctx, in, out, len, true);
    // Data processing is complete. Exit.
    if (lastLen == len) {
        return CRYPT_SUCCESS;
    }
    uint32_t clen = len - lastLen;
    if (clen >= 64) { // If the value is greater than 64, the logic for processing large blocks is used.
        // invoke the assembly API
        uint32_t finishedLen = AES_GCM_EncryptBlockAsm(ctx, in + lastLen, out + lastLen, clen, ctx->ciphCtx);
        lastLen += finishedLen; // add the processed length
        clen -= finishedLen; // subtract the processed length
    }
    if (clen >= 16) { // Remaining 16, use small block processing logic
        AES_GCM_Encrypt16BlockAsm(ctx, in + lastLen, out + lastLen, clen, ctx->ciphCtx); // call the assembly API
        lastLen += clen & 0xfffffff0;
        clen = clen & 0x0f; // take the remainder of 16
    }
    AES_GCM_ClearAsm(); // clear the Neon register
    if (clen > 0) { // tail processing
        uint32_t ctr = GET_UINT32_BE(ctx->iv, 12);
        ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->iv, ctx->last, GCM_BLOCKSIZE);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        uint32_t i;
        // encryption
        const uint8_t *cin = (const uint8_t *)(in + lastLen);
        uint8_t *cout = out + lastLen;
        for (i = 0; i < clen; i++) {
            cout[i] = cin[i] ^ ctx->last[i];
            ctx->remCt[i] = cout[i];
        }
        
        ctr++;
        PUT_UINT32_BE(ctr, ctx->iv, 12); // offset of 12 bytes, the last four bytes are used
        ctx->lastLen = GCM_BLOCKSIZE - clen;
    }
    return CRYPT_SUCCESS;
}

int32_t AES_GCM_DecryptBlock(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx->ciphCtx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CryptLenCheckAndRefresh(ctx, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t lastLen = MODES_GCM_LastHandle(ctx, in, out, len, false);
    // Data processing is complete. Exit.
    if (lastLen == len) {
        return CRYPT_SUCCESS;
    }
    uint32_t clen = len - lastLen;
    if (clen >= 64) { // If the value is greater than 64, the logic for processing large blocks is used.
        // invoke the assembly API
        uint32_t finishedLen = AES_GCM_DecryptBlockAsm(ctx, in + lastLen, out + lastLen, clen, ctx->ciphCtx);
        lastLen += finishedLen; // add the processed length
        clen -= finishedLen; // subtract the processed length
    }
    if (clen >= 16) { // Remaining 16, use small block processing logic
        AES_GCM_Decrypt16BlockAsm(ctx, in + lastLen, out + lastLen, clen, ctx->ciphCtx); // call the assembly API
        lastLen += clen & 0xfffffff0;
        clen = clen & 0x0f; // take the remainder of 16
    }
    AES_GCM_ClearAsm(); // clear the Neon register
    if (clen > 0) { // tail processing
        uint32_t ctr = GET_UINT32_BE(ctx->iv, 12);
        ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->iv, ctx->last, GCM_BLOCKSIZE);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        uint32_t i;
        // encryption
        const uint8_t *cin = (const uint8_t *)(in + lastLen);
        uint8_t *cout = out + lastLen;
        for (i = 0; i < clen; i++) {
            ctx->remCt[i] = cin[i];
            cout[i] = cin[i] ^ ctx->last[i];
        }
        ctr++;
        PUT_UINT32_BE(ctr, ctx->iv, 12); // offset of 12 bytes, the last four bytes are used
        ctx->lastLen = GCM_BLOCKSIZE - clen;
    }
    return CRYPT_SUCCESS;
}

int32_t AES_GCM_Update(MODES_GCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(modeCtx->enc ? AES_GCM_EncryptBlock : AES_GCM_DecryptBlock, &modeCtx->gcmCtx,
        in, inLen, out, outLen);
}

#endif