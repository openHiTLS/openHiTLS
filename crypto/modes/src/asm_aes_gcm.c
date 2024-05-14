/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_GCM)

#include "crypt_aes.h"
#include "asm_aes_gcm.h"
#include "modes_local.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes_gcm.h"

int32_t AES_GCM_EncryptBlock(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx->ciphCtx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CryptLenCheckAndRefresh(ctx, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t lastLen = LastHandle(ctx, in, out, len, true);
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
        ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->iv, ctx->last, GCM_BLOCKSIZE);
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

int32_t AES_GCM_DecryptBlock(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    if (ctx->ciphCtx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CryptLenCheckAndRefresh(ctx, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t lastLen = LastHandle(ctx, in, out, len, false);
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
        ret = ctx->ciphMeth->encrypt(ctx->ciphCtx, ctx->iv, ctx->last, GCM_BLOCKSIZE);
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
#endif