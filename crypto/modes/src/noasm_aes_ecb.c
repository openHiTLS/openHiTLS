/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_ECB)

#include "crypt_errno.h"
#include "crypt_modes_ecb.h"
#include "bsl_err_internal.h"

#define AES_ECB_BLOCK_SIZE 16

// process 64block
int32_t AES_ECB_EncryptBlock(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    // ctx, in, out, these pointer have been judged at the EAL layer and is not judged again here.
    if (ctx->ciphCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t count = len >> 4; // aes block must be 16 bytes
    uint32_t i;
    const uint8_t *input = in;
    uint8_t *output = out;
    for (i = 0; i < count; i++) {
        (void)ctx->ciphMeth->encrypt(ctx->ciphCtx, input, output, AES_ECB_BLOCK_SIZE);
        input += AES_ECB_BLOCK_SIZE;
        output += AES_ECB_BLOCK_SIZE;
    }
    return CRYPT_SUCCESS;
}

int32_t AES_ECB_DecryptBlock(MODE_CipherCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    // ctx, in, out, these pointer have been judged at the EAL layer and is not judged again here.
    if (ctx->ciphCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((len & 0x0f) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }
    uint32_t count = len >> 4; // aes block must be 16 bytes
    uint32_t i;
    const uint8_t *input = in;
    uint8_t *output = out;
    for (i = 0; i < count; i++) {
        (void)ctx->ciphMeth->decrypt(ctx->ciphCtx, input, output, AES_ECB_BLOCK_SIZE);
        input += AES_ECB_BLOCK_SIZE;
        output += AES_ECB_BLOCK_SIZE;
    }
    return CRYPT_SUCCESS;
}
#endif