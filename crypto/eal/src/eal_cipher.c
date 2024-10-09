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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_CIPHER)

#include "securec.h"
#include "crypt_algid.h"
#include "crypt_eal_cipher.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "eal_cipher_local.h"
#include "eal_common.h"
#include "crypt_method.h"
#include "crypt_utils.h"
#include "crypt_ealinit.h"

// Block encryption or not
#define EAL_IS_BLOCKCIPHER(blockSize) ((blockSize) != 1)    // 1: stream encryption
#define MODE_XTS_BLOCKSIZE 16

int32_t ProcessUpdateCache(CRYPT_EAL_CipherCtx *ctx, const uint8_t **in, uint32_t *inLen, uint8_t **out,
    uint32_t *outLen);
int32_t CheckUpdateParam(const CRYPT_EAL_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, const uint8_t *out,
    const uint32_t *outLen);
int32_t CheckFinalParam(const CRYPT_EAL_CipherCtx *ctx, const uint8_t *out, const uint32_t *outLen);
int32_t Padding(CRYPT_EAL_CipherCtx *ctx);
int32_t Unpadding(const uint8_t *pad, uint32_t padLen, uint32_t *dataLen, CRYPT_PaddingType type);
int32_t UnpaddingISO7816(const uint8_t *pad, uint32_t padLen, uint32_t *finLen);
int32_t UnpaddingX923(const uint8_t *pad, uint32_t padLen, uint32_t *finLen);
int32_t UnpaddingPkcs(const uint8_t *pad, uint32_t padLen, uint32_t *finLen);

static CRYPT_EAL_CipherCtx *CipherNewDefaultCtx(CRYPT_CIPHER_AlgId id)
{
    int32_t ret;
    EAL_Cipher m;
    ret = EAL_FindCipher(id, &m);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, id, CRYPT_EAL_ERR_ALGID);
        return NULL;
    }

    CRYPT_EAL_CipherCtx *ctx =
        (CRYPT_EAL_CipherCtx *)BSL_SAL_Calloc(1u, sizeof(struct CryptEalCipherCtx) + m.modeMethod->ctxSize);

    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    // Assign the value to modeCtx.
    void *modeCtx = ctx + 1;

    // Use keymothod as the input parameter to initialize modeCtx.
    // If init fails, this memory will be processed by init, and does not need to be processed at the EAL layer.
    ret = m.modeMethod->initCtx(modeCtx, m.ciphMeth);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, id, ret);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    uint32_t blockSize;
    ret = CRYPT_EAL_CipherGetInfo(id, CRYPT_INFO_BLOCK_LEN, &blockSize);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, id, ret);
        BSL_SAL_FREE(ctx);
        return NULL;
    }

    // Assign these values to eal ctx
    ctx->blockSize = blockSize;
    ctx->id = id;
    ctx->method = m.modeMethod;
    ctx->ctx = modeCtx;
    ctx->states = EAL_CIPHER_STATE_NEW;

    return ctx;
}

CRYPT_EAL_CipherCtx *CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AlgId id)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Cipher(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    return CipherNewDefaultCtx(id);
}

void CRYPT_EAL_CipherFreeCtx(CRYPT_EAL_CipherCtx *ctx)
{
    if (ctx == NULL) {
        // If the input parameter is NULL, it is not considered as an error.
        return;
    }
    if (ctx->method == NULL || ctx->method->deinitCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        BSL_SAL_FREE(ctx);
        return;
    }
    // Clear cache and sensitive information before free.
    CRYPT_EAL_CipherDeinit(ctx);

    (void)ctx->method->deinitCtx(ctx->ctx);
    // Free the memory eal ctx and mode ctx at the EAL layer.
    BSL_SAL_FREE(ctx);
}

static const uint32_t CIPHER_NO_IV[] = {
};

static const uint32_t CIPHER_NO_PADDING[] = {
    CRYPT_CIPHER_AES128_CTR,
    CRYPT_CIPHER_AES192_CTR,
    CRYPT_CIPHER_AES256_CTR,
    CRYPT_CIPHER_SM4_CTR,
    CRYPT_CIPHER_SM4_XTS,
};

static const uint32_t CIPHER_IS_AEAD[] = {
    CRYPT_CIPHER_AES128_CCM,
    CRYPT_CIPHER_AES192_CCM,
    CRYPT_CIPHER_AES256_CCM,
    CRYPT_CIPHER_AES128_GCM,
    CRYPT_CIPHER_AES192_GCM,
    CRYPT_CIPHER_AES256_GCM,
    CRYPT_CIPHER_CHACHA20_POLY1305,
    CRYPT_CIPHER_SM4_GCM,
};

int32_t CRYPT_EAL_CipherInit(CRYPT_EAL_CipherCtx *ctx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    int32_t ret;
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, CRYPT_CIPHER_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->method == NULL || ctx->method->setEncryptKey == NULL || ctx->method->setDecryptKey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    // Clear the cache and sensitive information before initialization.
    CRYPT_EAL_CipherDeinit(ctx);

    ctx->enc = enc;
    // Set the key. Check the validity of the key in each mode.
    if (enc) {
        ret = ctx->method->setEncryptKey(ctx->ctx, key, keyLen);
    } else {
        ret = ctx->method->setDecryptKey(ctx->ctx, key, keyLen);
    }
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return ret;
    }

    // The IV parameter is not set in ECB mode.
    if (!ParamIdIsValid(ctx->id, CIPHER_NO_IV, sizeof(CIPHER_NO_IV) / sizeof(CIPHER_NO_IV[0]))) {
        // Set the IV. The ctrl function of each mode checks the validity of parameters. The upper layer does not check.
        ret = ctx->method->ctrl(ctx->ctx, CRYPT_CTRL_SET_IV, (uint8_t *)(uintptr_t)iv, ivLen);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
            return ret;
        }
    }
    EAL_EventReport(CRYPT_EVENT_SETSSP, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_SUCCESS);
    // Initialize the pad and states.
    ctx->pad = CRYPT_PADDING_NONE;
    ctx->states = EAL_CIPHER_STATE_INIT;
    return CRYPT_SUCCESS;
}

static bool IsNoNeedIsoAuth(CRYPT_CIPHER_AlgId id)
{
    // The ISO19790 authentication is not required.
    switch (id) {
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES256_CBC:
        case CRYPT_CIPHER_AES128_CTR:
        case CRYPT_CIPHER_AES192_CTR:
        case CRYPT_CIPHER_AES256_CTR:
        case CRYPT_CIPHER_AES128_CCM:
        case CRYPT_CIPHER_AES192_CCM:
        case CRYPT_CIPHER_AES256_CCM:
        case CRYPT_CIPHER_AES128_GCM:
        case CRYPT_CIPHER_AES192_GCM:
        case CRYPT_CIPHER_AES256_GCM:
        case CRYPT_CIPHER_CHACHA20_POLY1305:
        case CRYPT_CIPHER_AES128_CFB:
        case CRYPT_CIPHER_AES192_CFB:
        case CRYPT_CIPHER_AES256_CFB:
        case CRYPT_CIPHER_AES128_OFB:
        case CRYPT_CIPHER_AES192_OFB:
        case CRYPT_CIPHER_AES256_OFB:
            return false;
        default:
            return true;
    }
}

void CRYPT_EAL_CipherDeinit(CRYPT_EAL_CipherCtx *ctx)
{
    if (ctx == NULL) {
        // If the ctx is NULL during deinit, it is not considered as an error.
        return;
    }
    if (ctx->method == NULL || ctx->method->clean == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return;
    }
    EAL_EventReport(CRYPT_EVENT_ZERO, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_SUCCESS);
    // Initialize the pad.
    ctx->pad = CRYPT_PADDING_NONE;
    // Clear cache data.
    if (IsNoNeedIsoAuth(ctx->id)) {
        (void)memset_s(ctx->data, EAL_MAX_BLOCK_LENGTH, 0, EAL_MAX_BLOCK_LENGTH);
    } else {
        // ISO19790 certification requires that the secure function library cannot be directly invoked.
        BSL_SAL_CleanseData((void *)(ctx->data), EAL_MAX_BLOCK_LENGTH);
    }
    ctx->dataLen = 0;
    // Clear keys and sensitive information.
    ctx->method->clean(ctx->ctx);
    // Restore the state to the state after the new is successful.
    ctx->states = EAL_CIPHER_STATE_NEW;
}

int32_t CRYPT_EAL_CipherReinit(CRYPT_EAL_CipherCtx *ctx, uint8_t *iv, uint32_t ivLen)
{
    int32_t ret;
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, CRYPT_CIPHER_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    // Without init, reinit cannot be invoked directly.
    if (ctx->states == EAL_CIPHER_STATE_NEW) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    // Clear cache data.
    (void)memset_s(ctx->data, EAL_MAX_BLOCK_LENGTH, 0, EAL_MAX_BLOCK_LENGTH);
    ctx->dataLen = 0;

    // The IV parameter is not set in ECB mode.
    if (!ParamIdIsValid(ctx->id, CIPHER_NO_IV, sizeof(CIPHER_NO_IV) / sizeof (CIPHER_NO_IV[0]))) {
        // Reset the IV. In this case, reset the IV is not restricted by the states.
        if (ctx->method == NULL || ctx->method->ctrl == NULL) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
            return CRYPT_EAL_ALG_NOT_SUPPORT;
        }
        ret = ctx->method->ctrl(ctx->ctx, CRYPT_CTRL_SET_IV, (uint8_t *)iv, ivLen);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
            return ret;
        }
    }
    // Reset the states.
    ctx->states = EAL_CIPHER_STATE_INIT;
    EAL_EventReport(CRYPT_EVENT_SETSSP, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
}

static bool IsPartialOverLap(const void *out, const void *in, uint32_t len)
{
    uintptr_t diff;
    if ((uintptr_t)out > (uintptr_t)in) {
        diff = (uintptr_t)out - (uintptr_t)in;
        return diff < (uintptr_t)len;
    }
    // If in >= out, this case is valid.
    return false;
}

int32_t CheckUpdateParam(const CRYPT_EAL_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, const uint8_t *out,
    const uint32_t *outLen)
{
    if (ctx == NULL || out == NULL || outLen == NULL || (in == NULL && inLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((in != NULL && inLen != 0) && IsPartialOverLap(out, in, inLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_PART_OVERLAP);
        return CRYPT_EAL_ERR_PART_OVERLAP;
    }
    // If the state is not init or update, the state is regarded as an error.
    // If the state is final or new, update cannot be directly invoked.
    if (!(ctx->states == EAL_CIPHER_STATE_INIT || ctx->states == EAL_CIPHER_STATE_UPDATE)) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (ctx->blockSize == 1) { // processing stream encryption
        if ((*outLen) < inLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
            return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
        }
        return CRYPT_SUCCESS;
    }
    uint8_t blockSize = ctx->blockSize;
    // If it's block encryption and the outLen is insufficient for the output result, an error is returned.
    if (inLen + ctx->dataLen < inLen) {
        // In this case, the outLen must be insufficient.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
    }
    if ((*outLen) < ((inLen + ctx->dataLen) / blockSize * blockSize)) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
    }
    if (ctx->method == NULL || ctx->method->encrypt == NULL || ctx->method->decrypt == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}

int32_t ProcessUpdateCache(CRYPT_EAL_CipherCtx *ctx, const uint8_t **in, uint32_t *inLen, uint8_t **out,
    uint32_t *outLen)
{
    int32_t ret;
    uint8_t blockSize = ctx->blockSize;
    // Process the cache. If there is cached data, the cache data is padded into a block first.
    if (ctx->dataLen > 0) {
        uint8_t padding = blockSize - ctx->dataLen;
        padding = (*inLen) > (padding) ? padding : (uint8_t)(*inLen);
        if (padding != 0) {
            if (memcpy_s(ctx->data + ctx->dataLen, (EAL_MAX_BLOCK_LENGTH - ctx->dataLen), (*in), padding) != EOK) {
                BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
                return CRYPT_SECUREC_FAIL;
            }
            (*inLen) -= padding;
            (*in) += padding;
            ctx->dataLen += padding;
        }
    }
    // No block is formed, return.
    if (ctx->dataLen != blockSize) {
        return CRYPT_SUCCESS;
    }

    // If the block is padded, perform operations on this block first.
    if (ctx->enc) {
        ret = ctx->method->encrypt(ctx->ctx, ctx->data, *out, blockSize);
    } else {
        // If it's decryption and the cached data + input data is equal to blockSize,
        // may be it's the last piece of data with padding, the data is cached in the ctx and left for final processing.
        if ((*inLen) == 0 && (ctx->pad != CRYPT_PADDING_NONE)) {
            (*outLen) = 0;
            return CRYPT_SUCCESS;
        }
        ret = ctx->method->decrypt(ctx->ctx, ctx->data, *out, blockSize);
    }

    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ctx->dataLen = 0;
    (*outLen) = blockSize;
    (*out) += blockSize;

    return CRYPT_SUCCESS;
}

static int32_t ProcessStream(CRYPT_EAL_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen)
{
    if (inLen == 0) {
        ctx->states = EAL_CIPHER_STATE_UPDATE;
        return CRYPT_SUCCESS;
    }
    int32_t ret;
    if (ctx->enc) {
        ret = ctx->method->encrypt(ctx->ctx, in, out, inLen);
    } else {
        ret = ctx->method->decrypt(ctx->ctx, in, out, inLen);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (*outLen) = inLen;
    ctx->states = EAL_CIPHER_STATE_UPDATE;
    return CRYPT_SUCCESS;
}

static int32_t CipherUpdate(CRYPT_EAL_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen)
{
    int32_t ret;
    uint32_t tmpLen = inLen;
    const uint8_t *tmpIn = in;
    uint8_t *tmpOut = (uint8_t *)out;

   // After verifying that the outLen value is valid, the value of outLen is initialized to 0.
    *outLen = 0;
    uint8_t blockSize = ctx->blockSize;
    // If block encryption is not used, no data is cached. Therefore, the cache does not need to be processed.
    if (blockSize == 1) { // Process stream encryption
        return ProcessStream(ctx, in, inLen, out, outLen);
    }
    ret = ProcessUpdateCache(ctx, &tmpIn, &tmpLen, &tmpOut, outLen);
    if (ret != CRYPT_SUCCESS) {
        // ProcessUpdateCache has a push error that can locate the only error location. No need to add push error here.
        return ret;
    }

    // If the length of input data plus the length of cached data <= blockSize, return success.
    if (tmpLen == 0) {
        ctx->states = EAL_CIPHER_STATE_UPDATE;
        return CRYPT_SUCCESS;
    }

    // In this case, tmpLen is the length which minus the buffer length in the original ctx.
    uint8_t left = tmpLen % blockSize;
    uint32_t len = tmpLen - left;

    if (len > 0) {
        if (ctx->enc) {
            ret = ctx->method->encrypt(ctx->ctx, tmpIn, tmpOut, len);
        } else {
            // If it's block decryption and left is 0, a complete block must be left for final processing.
            // If left is not 0, subsequent update data exists.
            // In addition, the sum of the cached data and the subsequent update data
            // must be an integer multiple of blockSize. Otherwise, an error is reported in the final.
            if ((ctx->pad != CRYPT_PADDING_NONE) && left == 0) {
                left = blockSize;
                len -= blockSize;
            }
            if (len > 0) {
                ret = ctx->method->decrypt(ctx->ctx, tmpIn, tmpOut, len);
            }
        }
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    // Process the new cache.
    if (left > 0 && (memcpy_s(ctx->data, blockSize, tmpIn + len, left) != EOK)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    ctx->dataLen = left;

    // The encryption/decryption is successful. OutLen is updated.
    (*outLen) += len;

    ctx->states = EAL_CIPHER_STATE_UPDATE;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_CipherUpdate(CRYPT_EAL_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen)
{
    int32_t ret = CheckUpdateParam(ctx, in, inLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        // The push error in CheckUpdateParam can be locate the only error location. No need to add the push error here.
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, (ctx == NULL) ? CRYPT_CIPHER_MAX : ctx->id, ret);
        return ret;
    }
    ret = CipherUpdate(ctx, in, inLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
    }
    return ret;
}

int32_t CheckFinalParam(const CRYPT_EAL_CipherCtx *ctx, const uint8_t *out, const uint32_t *outLen)
{
    if (ctx == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // If the state is not init or update, the state is regarded as an error.
    // If the state is final or new, update cannot be directly invoked.
    if (!(ctx->states == EAL_CIPHER_STATE_UPDATE || ctx->states == EAL_CIPHER_STATE_INIT)) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    uint8_t blockSize = ctx->blockSize;
    // The output buffer is not enough.
    if (ctx->pad != CRYPT_PADDING_NONE && (*outLen) < blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
    }
    if (ctx->method == NULL || ctx->method->encrypt == NULL || ctx->method->decrypt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}

int32_t FinalEncrypt(CRYPT_EAL_CipherCtx *ctx, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    ret = Padding(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ctx->dataLen == 0) {
        return CRYPT_SUCCESS;
    }
    ret = ctx->method->encrypt(ctx->ctx, ctx->data, out, ctx->dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (*outLen) = ctx->dataLen;
    return CRYPT_SUCCESS;
}

int32_t FinalDecrypt(CRYPT_EAL_CipherCtx *ctx, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    uint8_t blockSize = ctx->blockSize;
    uint32_t dataLen;

    if (ctx->dataLen == 0) {
        return CRYPT_SUCCESS;
    }
    ret = ctx->method->decrypt(ctx->ctx, ctx->data, out, ctx->dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    dataLen = ctx->dataLen;
    ret = Unpadding(out, blockSize, &dataLen, ctx->pad);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    *outLen = dataLen;
    return CRYPT_SUCCESS;
}

// Check whether the algorithm is the AEAD algorithm. If yes, true is returned. Otherwise, false is returned.
static bool IsAeadAlg(CRYPT_CIPHER_AlgId id)
{
    if (ParamIdIsValid(id, CIPHER_IS_AEAD, sizeof(CIPHER_IS_AEAD) / sizeof(CIPHER_IS_AEAD[0]))) {
        return true;
    }
    return false;
}

int32_t CRYPT_EAL_CipherFinal(CRYPT_EAL_CipherCtx *ctx, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    ret = CheckFinalParam(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, (ctx == NULL) ? CRYPT_CIPHER_MAX : ctx->id, ret);
        return ret;
    }
    // The AEAD algorithm uses GetTag to end the encryption process.
    if (IsAeadAlg(ctx->id)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_CIPHER_FIANL_WITH_AEAD_ERROR);
        return CRYPT_EAL_CIPHER_FIANL_WITH_AEAD_ERROR;
    }
    // After checking the validity of the outLen, the outLen can be initialized to 0.
    *outLen = 0;

    if (ctx->enc) {
        ret = FinalEncrypt(ctx, out, outLen);
    } else {
        ret = FinalDecrypt(ctx, out, outLen);
    }
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return ret;
    }

    ctx->dataLen = 0;
    ctx->states = EAL_CIPHER_STATE_FINAL;
    EAL_EventReport((ctx->enc) ? CRYPT_EVENT_ENC : CRYPT_EVENT_DEC, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
}

static bool IfXts(CRYPT_CIPHER_AlgId id)
{
    CRYPT_CIPHER_AlgId XTS_list[] = {
        CRYPT_CIPHER_SM4_XTS,
    };
    for (uint32_t i = 0; i < sizeof(XTS_list) / sizeof(XTS_list[0]); i++) {
        if (id == XTS_list[i]) {
            return true;
        }
    }
    return false;
}

// For performance reasons, it is not recommended that the padding code be split if the padding code is not complex.
int32_t Padding(CRYPT_EAL_CipherCtx *ctx)
{
    uint8_t *pad = ctx-> data + ctx->dataLen;
    uint8_t padLen = ctx->blockSize - ctx->dataLen;
    uint8_t i;
    uint8_t len = ctx->dataLen;
    ctx->dataLen += padLen;
    switch (ctx->pad) {
        case CRYPT_PADDING_NONE:
            ctx->dataLen = len;
            if (len % (ctx->blockSize) != 0) {
                return IfXts(ctx->id) ? CRYPT_SUCCESS : CRYPT_MODE_ERR_INPUT_LEN;
            }
            break;
        case CRYPT_PADDING_ZEROS:
            for (i = 0; i < padLen; i++) {
                pad[i] = 0x00L;
            }
            break;
        case CRYPT_PADDING_ISO7816:
            pad[0] = 0x80;
            for (i = 1; i < padLen; i++) {
                pad[i] = 0x00L;
            }
            break;
        case CRYPT_PADDING_X923:
            for (i = 0; i < padLen - 1; i++) {
                pad[i] = 0x00L;
            }
            pad[padLen - 1] = padLen;
            break;
        case CRYPT_PADDING_PKCS5:
        case CRYPT_PADDING_PKCS7:
            for (i = 0; i < padLen; i++) {
                pad[i] = padLen;
            }
            break;
        default:
            ctx->dataLen = len;
            break;
    }
    return CRYPT_SUCCESS;
}

int32_t UnpaddingISO7816(const uint8_t *pad, uint32_t padLen, uint32_t *finLen)
{
    uint32_t len;
    const uint8_t *p = pad;
    len = padLen - 1;
    while (*(p + len) == 0 && len > 0) {
        len--;
    }
    len = (*(p + len) == 0x80) ? len : padLen;

    if (len == padLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_CIPHER_DATA_ERROR);
        return CRYPT_EAL_CIPHER_DATA_ERROR;
    }
    (*finLen) = len;
    return CRYPT_SUCCESS;
}

int32_t UnpaddingX923(const uint8_t *pad, uint32_t padLen, uint32_t *finLen)
{
    uint32_t len, pos, i;
    uint32_t check = 0;
    len = pad[padLen - 1];

    check |= (uint32_t)(len > padLen);

    pos = padLen - len;
    for (i = 0; i < padLen - 1; i++) {
        check |= (pad[i] * (uint32_t)(i >= pos));
    }

    if (check != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_CIPHER_DATA_ERROR);
        return CRYPT_EAL_CIPHER_DATA_ERROR;
    }

    (*finLen) = padLen - len;
    return CRYPT_SUCCESS;
}

int32_t UnpaddingPkcs(const uint8_t *pad, uint32_t padLen, uint32_t *finLen)
{
    uint32_t len, pos, i;
    uint32_t check = 0;

    len = pad[padLen - 1];
    check |= (uint32_t)((len == 0) || (len > padLen));

    pos = padLen - len;
    for (i = 0; i < padLen; i++) {
        check |= ((pad[i] ^ len) * (uint32_t)(i >= pos));
    }

    if (check != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_CIPHER_DATA_ERROR);
        return CRYPT_EAL_CIPHER_DATA_ERROR;
    }

    (*finLen) = padLen - len;
    return CRYPT_SUCCESS;
}

int32_t Unpadding(const uint8_t *pad, uint32_t padLen, uint32_t *dataLen, CRYPT_PaddingType type)
{
    int32_t ret = 0;
    uint32_t len = *dataLen;
    switch (type) {
        case CRYPT_PADDING_ISO7816:
            ret = UnpaddingISO7816(pad, padLen, &len);
            break;
        case CRYPT_PADDING_X923:
            ret = UnpaddingX923(pad, padLen, &len);
            break;
        case CRYPT_PADDING_PKCS5:
        case CRYPT_PADDING_PKCS7:
            ret = UnpaddingPkcs(pad, padLen, &len);
            break;
        default:
            break;
    }

    *dataLen = len;
    return ret;
}

// Check whether the operation is write operation. New write operations need to be added here
// to prevent them from being modified during calculation.
static bool CipherCtrlIsCanSet(const CRYPT_EAL_CipherCtx *ctx, int32_t type)
{
    if (type == CRYPT_CTRL_DES_NOKEYCHECK || type == CRYPT_CTRL_RC2_SETEFFLEN) {
        return true;
    }
    if (ctx->states == EAL_CIPHER_STATE_NEW) {
        return false;
    }
    if (ctx->states == EAL_CIPHER_STATE_FINAL) {
        return false;
    }
    if ((ctx->states == EAL_CIPHER_STATE_UPDATE) &&
        (type == CRYPT_CTRL_SET_COUNT || type == CRYPT_CTRL_SET_TAGLEN ||
        type == CRYPT_CTRL_SET_MSGLEN || type == CRYPT_CTRL_SET_AAD)) {
        return false;
    }
    return true;
}

static void ReportCtrlEvent(CRYPT_EAL_CipherCtx *ctx, int32_t type, int32_t ret)
{
    if (ret != CRYPT_SUCCESS) { // report abnormal events
        EAL_EventReport(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return;
    }
    if (type == CRYPT_CTRL_GET_TAG) { // report the encryption/decryption service is executed
        EAL_EventReport((ctx->enc) ? CRYPT_EVENT_ENC : CRYPT_EVENT_DEC, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return;
    }
    if (type == CRYPT_CTRL_SET_IV) { // report the sensitive information is added
        EAL_EventReport(CRYPT_EVENT_SETSSP, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return;
    }
    if (type == CRYPT_CTRL_GET_IV) { // report sensitive information is accessed
        EAL_EventReport(CRYPT_EVENT_GETSSP, CRYPT_ALGO_CIPHER, ctx->id, ret);
        return;
    }
    return;
}

int32_t CRYPT_EAL_CipherCtrl(CRYPT_EAL_CipherCtx *ctx, int32_t type, void *data, uint32_t len)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, CRYPT_CIPHER_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    // The IV cannot be set through the Ctrl. You need to set the IV through the init and reinit.
    if (type == CRYPT_CTRL_SET_IV) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_CIPHER_CTRL_ERROR);
        return CRYPT_EAL_CIPHER_CTRL_ERROR;
    }

    // If the algorithm is running in the intermediate state, write operations are not allowed.
    if (!CipherCtrlIsCanSet(ctx, type)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    // Setting AAD indicates that the encryption operation has started and no more write operations are allowed.
    if (type == CRYPT_CTRL_SET_AAD) {
        ctx->states = EAL_CIPHER_STATE_UPDATE;
    }
    // After getTag the system enters the final state.
    if (type == CRYPT_CTRL_GET_TAG) {
        ctx->states = EAL_CIPHER_STATE_FINAL;
    }
    if (type == CRYPT_CTRL_GET_BLOCKSIZE) {
        if (data == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
            return CRYPT_NULL_INPUT;
        }
        if (len != sizeof(uint32_t)) {
            BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
            return CRYPT_MODE_ERR_INPUT_LEN;
        }
        *(uint32_t *)data = (uint32_t)ctx->blockSize;
        return CRYPT_SUCCESS;
    }
    if (ctx->method == NULL || ctx->method->ctrl == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    int32_t ret = ctx->method->ctrl(ctx->ctx, type, data, len);
    ReportCtrlEvent(ctx, type, ret);
    return ret;
}

int32_t CRYPT_EAL_CipherSetPadding(CRYPT_EAL_CipherCtx *ctx, CRYPT_PaddingType type)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, CRYPT_CIPHER_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->blockSize == 1) { // blockSize == 1, no pad is required.
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_PADDING_NOT_SUPPORT);
        return CRYPT_EAL_PADDING_NOT_SUPPORT;
    }

    // The algorithm does not support invalid padding types.
    if (type < 0 || type >= CRYPT_PADDING_MAX_COUNT) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_PADDING_NOT_SUPPORT);
        return CRYPT_EAL_PADDING_NOT_SUPPORT;
    }
    // XTS and CTR do not support padding.
    if (ParamIdIsValid(ctx->id, CIPHER_NO_PADDING, sizeof(CIPHER_NO_PADDING) / sizeof(CIPHER_NO_PADDING[0]))) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_PADDING_NOT_SUPPORT);
        return CRYPT_EAL_PADDING_NOT_SUPPORT;
    }
    uint8_t blockSize = ctx->blockSize;
    // The non-block encryption algorithm does not support padding. During decryption, padding 0 cannot be set
    // because it cannot be determined whether 0 is user data or padding data and users need to determine it.
    if (!EAL_IS_BLOCKCIPHER(blockSize) || (!ctx->enc && ctx->pad == CRYPT_PADDING_ZEROS)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, ctx->id, CRYPT_EAL_PADDING_NOT_SUPPORT);
        return CRYPT_EAL_PADDING_NOT_SUPPORT;
    }
    ctx->pad = type;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_CipherGetPadding(CRYPT_EAL_CipherCtx *ctx)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, CRYPT_CIPHER_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ctx->pad;
}

bool CRYPT_EAL_CipherIsValidAlgId(CRYPT_CIPHER_AlgId id)
{
    EAL_Cipher m;
    return EAL_FindCipher(id, &m) == CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_AlgId id, int32_t type, uint32_t *infoValue)
{
    if (infoValue == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, id, CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    CRYPT_CipherInfo info = {0};
    if (EAL_GetCipherInfo(id, &info) != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, id, CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }

    switch (type) {
        case CRYPT_INFO_IS_AEAD:
            (*infoValue) = IsAeadAlg(id) ? 1 : 0;
            break;
        case CRYPT_INFO_IS_STREAM:
            (*infoValue) = (uint32_t)!EAL_IS_BLOCKCIPHER(info.blockSize);
            break;
        case CRYPT_INFO_IV_LEN:
            (*infoValue) = info.ivLen;
            break;
        case CRYPT_INFO_KEY_LEN:
            (*infoValue) = info.keyLen;
            break;
        case CRYPT_INFO_BLOCK_LEN:
            (*infoValue) = (uint32_t)info.blockSize;
            break;
        default:
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_CIPHER, id, CRYPT_EAL_INTO_TYPE_NOT_SUPPORT);
            return CRYPT_EAL_INTO_TYPE_NOT_SUPPORT;
    }

    return CRYPT_SUCCESS;
}
#endif
