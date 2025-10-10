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
#ifdef HITLS_CRYPTO_CMAC

#include <stdlib.h>
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "cipher_mac_common.h"
#include "crypt_cmac.h"
#include "eal_mac_local.h"

CRYPT_CMAC_Ctx *CRYPT_CMAC_NewCtx(CRYPT_MAC_AlgId id)
{
    EAL_MacDepMethod method = {{0}, {NULL}};
    int32_t ret = EAL_MacFindDepMethod(id, NULL, NULL, &method, NULL, false);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }
    CRYPT_CMAC_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_CMAC_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ret = CipherMacInitCtx(ctx, method.method.sym);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(ctx);
        return NULL;
    }
    return ctx;
}

CRYPT_CMAC_Ctx *CRYPT_CMAC_NewCtxEx(void *libCtx, CRYPT_MAC_AlgId id)
{
    (void)libCtx;
    return CRYPT_CMAC_NewCtx(id);
}

int32_t CRYPT_CMAC_Init(CRYPT_CMAC_Ctx *ctx, const uint8_t *key, uint32_t len, void *param)
{
    (void)param;
    return CipherMacInit((Cipher_MAC_Common_Ctx *)ctx, key, len);
}

int32_t CRYPT_CMAC_Update(CRYPT_CMAC_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    return CipherMacUpdate((Cipher_MAC_Common_Ctx *)ctx, in, len);
}

static inline void LeftShiftOneBit(const uint8_t *in, uint32_t len, uint8_t *out)
{
    uint32_t i = len - 1;

    out[i] = (in[i] << 1) | 0;
    do {
        i--;
        out[i] = (in[i] << 1) | (in[i + 1] >> 7); // 7 is used to obtain the most significant bit of the 8-bit data.
    } while (i != 0);
}

static void CMAC_Final(CRYPT_CMAC_Ctx *ctx)
{
    const uint8_t z[CIPHER_MAC_MAXBLOCKSIZE] = {0};
    uint8_t rb;
    uint8_t l[CIPHER_MAC_MAXBLOCKSIZE];
    uint8_t k1[CIPHER_MAC_MAXBLOCKSIZE];
    const EAL_SymMethod *method = ctx->method;
    uint32_t blockSize = method->blockSize;

    int32_t ret = method->encryptBlock(ctx->key, z, l, blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return;
    }
    LeftShiftOneBit(l, blockSize, k1);

    if (blockSize == CIPHER_MAC_MAXBLOCKSIZE) {
        rb = 0x87; /* When the AES algorithm is used and the blocksize is 128 bits, rb uses 0x87. */
    } else {
        rb = 0x1B; /* When the DES and TDES algorithms are used and blocksize is 64 bits, rb uses 0x1B. */
    }
    if ((l[0] & 0x80) != 0) {
        k1[blockSize - 1] ^= rb;
    }
    uint32_t length = ctx->len;
    if (length == blockSize) {  // When the message length is an integer multiple of blockSize, use K1
        DATA_XOR(ctx->left, k1, ctx->left, blockSize);
    } else {  // The message length is not an integer multiple of blockSize. Use K2 after padding.
        /* padding */
        ctx->left[length++] = 0x80;  // 0x80 indicates that the first bit of the data is added with 1.
        while (length < blockSize) {
            ctx->left[length++] = 0;
        }

        uint8_t k2[CIPHER_MAC_MAXBLOCKSIZE];
        LeftShiftOneBit(k1, blockSize, k2);
        if ((k1[0] & 0x80) != 0) {
            k2[blockSize - 1] ^= rb;
        }
        DATA_XOR(ctx->left, k2, ctx->left, blockSize);
        ctx->len = blockSize;
    }
}

int32_t CRYPT_CMAC_Final(CRYPT_CMAC_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    if (ctx == NULL || ctx->method == NULL || len == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const EAL_SymMethod *method = ctx->method;
    uint32_t blockSize = method->blockSize;
    if (*len < blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_CMAC_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_CMAC_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    CMAC_Final(ctx);
    DATA_XOR(ctx->left, ctx->data, ctx->left, blockSize);
    int32_t ret = method->encryptBlock(ctx->key, ctx->left, out, blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *len = blockSize;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CMAC_Reinit(CRYPT_CMAC_Ctx *ctx)
{
    return CipherMacReinit((Cipher_MAC_Common_Ctx *)ctx);
}

int32_t CRYPT_CMAC_Deinit(CRYPT_CMAC_Ctx *ctx)
{
    return CipherMacDeinit((Cipher_MAC_Common_Ctx *)ctx);
}

int32_t CRYPT_CMAC_Ctrl(CRYPT_CMAC_Ctx *ctx, uint32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GET_MACLEN:
            return CipherMacGetMacLen(ctx, val, len);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_CMAC_ERR_UNSUPPORTED_CTRL_OPTION);
    return CRYPT_CMAC_ERR_UNSUPPORTED_CTRL_OPTION;
}

void CRYPT_CMAC_FreeCtx(CRYPT_CMAC_Ctx *ctx)
{
    CipherMacDeinitCtx(ctx);
    BSL_SAL_Free(ctx);
}

#endif /* HITLS_CRYPTO_CMAC */
