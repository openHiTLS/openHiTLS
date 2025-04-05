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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CCM)

#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "asm_aes_ccm.h"
#include "ccm_core.h"
#include "crypt_modes_ccm.h"
#include "modes_local.h"

static int32_t AesCcmBlocks(MODES_CipherCCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc)
{
    if (ctx->ciphCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    XorCryptData data;
    data.in = in;
    data.out = out;
    data.ctr = ctx->last;
    data.tag = ctx->tag;

    uint8_t countLen = (ctx->nonce[0] & 0x07) + 1;
    uint32_t dataLen = len;
    void (*xor)(XorCryptData *data, uint32_t len) = enc ? XorInEncrypt : XorInDecrypt;
    void (*crypt_asm)(void *key, uint8_t *nonce, const uint8_t *in, uint8_t *out, uint32_t len) =
        enc ? AesCcmEncryptAsm : AesCcmDecryptAsm;
    crypt_asm(ctx->ciphCtx, ctx->nonce, data.in, data.out, dataLen);
    uint32_t tmpOffset = dataLen & 0xfffffff0;
    dataLen &= 0x0fU;
    data.in += tmpOffset;
    data.out += tmpOffset;
    if (dataLen > 0) { // data processing with less than 16 bytes
        (void)ctx->ciphMeth->encryptBlock(ctx->ciphCtx, ctx->nonce, ctx->last, CCM_BLOCKSIZE);
        xor(&data, dataLen);
        MODE_IncCounter(ctx->nonce + CCM_BLOCKSIZE - countLen, countLen); // counter +1
    }
    return CRYPT_SUCCESS;
}

int32_t MODES_AES_CCM_Encrypt(MODES_CipherCCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return CcmCrypt(ctx, in, out, len, true, AesCcmBlocks);
}

int32_t MODES_AES_CCM_Decrypt(MODES_CipherCCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    return CcmCrypt(ctx, in, out, len, false, AesCcmBlocks);
}


int32_t AES_CCM_Update(MODES_CCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(modeCtx->enc ? MODES_AES_CCM_Encrypt : MODES_AES_CCM_Decrypt, &modeCtx->ccmCtx,
        in, inLen, out, outLen);
}

#endif