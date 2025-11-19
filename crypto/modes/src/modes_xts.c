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
#ifdef HITLS_CRYPTO_XTS

#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_modes_xts.h"
#include "modes_local.h"
#include "crypt_modes.h"


#define MODES_XTS_BLOCKSIZE 16
#define SM4_XTS_POLYNOMIAL 0xE1
#define XTS_UPDATE_VALUES(l, i, o, len) \
    do { \
        (l) -= (len); \
        (i) += (len); \
        (o) += (len); \
    } while (false)

int32_t MODES_XTS_CheckPara(const uint8_t *key, uint32_t len, const uint8_t *iv)
{
    if (key == NULL || iv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // The key length supports only 256 bytes (32 bytes) and 512 bytes (64 bytes), corresponding to AES-128 and AES-256.
    if (len != 32 && len != 64) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_KEYLEN);
        return CRYPT_MODES_ERR_KEYLEN;
    }
    return CRYPT_SUCCESS;
}

int32_t MODES_XTS_SetEncryptKey(MODES_CipherXTSCtx *ctx, const uint8_t *key, uint32_t len)
{
    int32_t ret;
    uint32_t keyLen = len >> 1;
    if (memcmp(key, key + keyLen, keyLen) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_KEY);
        return CRYPT_MODES_ERR_KEY;
    }
    ret = ctx->ciphMeth->setEncryptKey(ctx->ciphCtx, key, keyLen); // key1
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ctx->ciphMeth->setEncryptKey((uint8_t*)ctx->ciphCtx + ctx->ciphMeth->ctxSize, key + keyLen, keyLen); // key2
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t MODES_XTS_SetDecryptKey(MODES_CipherXTSCtx *ctx, const uint8_t *key, uint32_t len)
{
    int32_t ret;
    uint32_t keyLen = len >> 1;
    if (memcmp(key + keyLen, key, keyLen) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_KEY);
        return CRYPT_MODES_ERR_KEY;
    }
    ret = ctx->ciphMeth->setEncryptKey((uint8_t*)ctx->ciphCtx + ctx->ciphMeth->ctxSize, key + keyLen, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ctx->ciphMeth->setDecryptKey(ctx->ciphCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
	return ret;
}

#ifdef HITLS_BIG_ENDIAN
// AES XTS IEEE P1619/D16 Annex C
// Pseudocode for XTS-AES-128 and XTS-AES-256 Encryption
void GF128Mul(uint8_t *a, uint32_t len)
{
    uint8_t in;
    uint8_t out = 0;
    in = 0;
    // xts blocksize MODES_XTS_BLOCKSIZE
    for (uint32_t j = 0; j < len; j++) {
        out = (a[j] >> 7) & 1;  // >> 7
        a[j] = (uint8_t)((a[j] << 1) + in) & 0xFFu;  // << 1
        in = out;
    }
    if (out > 0) {
        a[0] ^= 0x87;  // 0x87 gf 128
    }
}
#else
// AES XTS IEEE P1619/D16 5.2
// Multiplication by a primitive element |ив
void GF128Mul(uint8_t *a, uint32_t len)
{
    (void)len;
    uint64_t *t = (uint64_t *)a;
    uint8_t c = (t[1] >> 63) & 0xff; // 63 is the last bit of the last eight bytes.
    t[1] = t[1] << 1 | t[0] >> 63; // 63 is the last bit of the first eight bytes
    t[0] = t[0] << 1;
    if (c != 0) {
        t[0] ^= 0x87;
    }
}
#endif

void GF128Mul_GM(uint8_t *a, uint32_t len)
{
    uint8_t in = 0;
    uint8_t out = 0;

    for (uint32_t j = 0; j < len; j++) {
        out = (a[j] << 7) & 0x80; // shift left by 7 bits
        a[j] = (uint8_t)((a[j] >> 1) + in) & 0xFFu;
        in = out;
    }
    if (out > 0) {
        a[0] ^= SM4_XTS_POLYNOMIAL; // reverse (10000111)2
    }
}

int32_t BlockCrypt(MODES_CipherXTSCtx *ctx, const uint8_t *in, const uint8_t *t, uint8_t *pp, bool enc)
{
    int32_t ret;
    uint32_t blockSize = ctx->blockSize;
    DATA64_XOR(in, t, pp, blockSize);

    if (enc) {
        ret = ctx->ciphMeth->encryptBlock(ctx->ciphCtx, pp, pp, blockSize);
    } else {
        ret = ctx->ciphMeth->decryptBlock(ctx->ciphCtx, pp, pp, blockSize);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    DATA64_XOR(pp, t, pp, blockSize);

    return CRYPT_SUCCESS;
}

int32_t BlocksCrypt(MODES_CipherXTSCtx *ctx, const uint8_t **in, uint8_t **out, uint32_t *tmpLen,
    bool enc)
{
    int32_t ret;
    uint32_t blockSize = ctx->blockSize;
    const uint8_t *tmpIn = *in;
    uint8_t *tmpOut = *out;
    while (*tmpLen >= 2 * blockSize) {  // If the value is greater than blockSize * 2, process the tmpIn.
        ret = BlockCrypt(ctx, tmpIn, ctx->tweak, tmpOut, enc);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }

        XTS_UPDATE_VALUES(*tmpLen, tmpIn, tmpOut, blockSize);
        if (ctx->ciphMeth->algId == CRYPT_SYM_SM4) {
            GF128Mul_GM(ctx->tweak, blockSize);
        } else {
            GF128Mul(ctx->tweak, blockSize);
        }
    }
    *in = tmpIn;
    *out = tmpOut;
    return CRYPT_SUCCESS;
}

int32_t MODES_XTS_Encrypt(MODES_CipherXTSCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    int32_t ret;
    uint32_t i;
    uint8_t pp[MODES_XTS_BLOCKSIZE];
    uint32_t tmpLen = len;
    const uint8_t *tmpIn = in;
    uint8_t *tmpOut = out;
    uint8_t *lastBlock = NULL;
    uint32_t blockSize = ctx->blockSize;

    if (len < blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }

    ret = BlocksCrypt(ctx, &tmpIn, &tmpOut, &tmpLen, true);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // Encryption
    ret = BlockCrypt(ctx, tmpIn, ctx->tweak, tmpOut, true);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    XTS_UPDATE_VALUES(tmpLen, tmpIn, tmpOut, blockSize);

    if (ctx->ciphMeth->algId == CRYPT_SYM_SM4) {
        GF128Mul_GM(ctx->tweak, blockSize);
    } else {
        GF128Mul(ctx->tweak, blockSize);
    }
    if (tmpLen == 0) {
        // If len is an integer multiple of blockSize, the subsequent calculations is not required.
        return CRYPT_SUCCESS;
    }

    lastBlock = tmpOut - blockSize;
    // Process the subsequent two pieces of data.
    for (i = 0; i < tmpLen; i++) {
        tmpOut[i] = lastBlock[i];
        pp[i] = tmpIn[i];
    }

    for (i = tmpLen; i < blockSize; i++) {
        pp[i] = lastBlock[i];
    }
    ret = BlockCrypt(ctx, pp, ctx->tweak, pp, true);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // set c m-1
    tmpOut -= blockSize;
    if (memcpy_s(tmpOut, blockSize + tmpLen, pp, blockSize) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t MODES_XTS_Decrypt(MODES_CipherXTSCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    int32_t ret;
    uint8_t pp[MODES_XTS_BLOCKSIZE], t2[MODES_XTS_BLOCKSIZE]; // xts blocksize MODES_XTS_BLOCKSIZE
    uint32_t i;
    uint32_t tmpLen = len;
    const uint8_t *tmpIn = in;
    uint32_t blockSize = ctx->blockSize;
    uint8_t *tmpOut = out;

    if (len < blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }

    ret = BlocksCrypt(ctx, &tmpIn, &tmpOut, &tmpLen, false);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // If len is an integer multiple of blockSize, the subsequent calculations is not required.
    if (tmpLen == blockSize) {
        ret = BlockCrypt(ctx, tmpIn, ctx->tweak, tmpOut, false);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (ctx->ciphMeth->algId == CRYPT_SYM_SM4) {
            GF128Mul_GM(ctx->tweak, blockSize);
        } else {
            GF128Mul(ctx->tweak, blockSize);
        }
        return CRYPT_SUCCESS;
    }

    (void)memcpy_s(t2, MODES_XTS_BLOCKSIZE, ctx->tweak, blockSize);

    if (ctx->ciphMeth->algId == CRYPT_SYM_SM4) {
        GF128Mul_GM(ctx->tweak, blockSize);
    } else {
        GF128Mul(ctx->tweak, blockSize);
    }
    ret = BlockCrypt(ctx, tmpIn, ctx->tweak, pp, false);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    tmpLen -= blockSize;

    for (i = 0; i < tmpLen; i++) {
        tmpOut[i + blockSize] = pp[i];
        pp[i] = tmpIn[i + blockSize];
    }

    ret = BlockCrypt(ctx, pp, t2, pp, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (memcpy_s(tmpOut, blockSize + tmpLen, pp, blockSize) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

void MODES_XTS_Clean(MODES_CipherXTSCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_CleanseData((void *)(ctx->iv), MODES_MAX_IV_LENGTH);
    BSL_SAL_CleanseData((void *)(ctx->tweak), MODES_MAX_IV_LENGTH);
    if (ctx->ciphMeth != NULL && ctx->ciphMeth->cipherDeInitCtx != NULL) {
        ctx->ciphMeth->cipherDeInitCtx(ctx->ciphCtx);
        ctx->ciphMeth->cipherDeInitCtx((void *)((uintptr_t)ctx->ciphCtx + ctx->ciphMeth->ctxSize));
    }
}

int32_t MODES_XTS_SetIv(MODES_CipherXTSCtx *ctx, const uint8_t *val, uint32_t len)
{
    int32_t ret;
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != ctx->blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_IVLEN_ERROR);
        return CRYPT_MODES_IVLEN_ERROR;
    }
    if (memcpy_s(ctx->iv, MODES_MAX_IV_LENGTH, val, len) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }

    // Use key2 and i to encrypt to obtain the tweak.
    ret = ctx->ciphMeth->encryptBlock((uint8_t*)ctx->ciphCtx + ctx->ciphMeth->ctxSize,
        ctx->iv, ctx->tweak, ctx->blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t GetIv(MODES_CipherXTSCtx *ctx, uint8_t *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != ctx->blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_ERR_INPUT_LEN);
        return CRYPT_MODE_ERR_INPUT_LEN;
    }
    if (memcpy_s(val, len, ctx->iv, ctx->blockSize) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t MODES_XTS_Ctrl(MODES_XTS_Ctx *modeCtx, int32_t cmd, void *val, uint32_t len)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_REINIT_STATUS:
            (void)memset_s(modeCtx->data, EAL_MAX_BLOCK_LENGTH, 0, EAL_MAX_BLOCK_LENGTH);
            modeCtx->dataLen = 0;
            return MODES_XTS_SetIv(&modeCtx->xtsCtx, val, len);
        case CRYPT_CTRL_GET_IV:
            return GetIv(&modeCtx->xtsCtx, (uint8_t *)val, len);
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_MODE_ERR_INPUT_LEN;
            }
            *(int32_t *)val = 1;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TYPE_ERROR);
            return CRYPT_MODES_CTRL_TYPE_ERROR;
    }
}

MODES_XTS_Ctx *MODES_XTS_NewCtx(int32_t algId)
{
    const EAL_SymMethod *method = EAL_GetSymMethod(algId);
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    MODES_XTS_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(MODES_XTS_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return ctx;
    }
    ctx->algId = algId;

    ctx->xtsCtx.ciphCtx = BSL_SAL_Calloc(2, method->ctxSize);
    if (ctx->xtsCtx.ciphCtx  == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(ctx);
        return NULL;
    }

    ctx->xtsCtx.blockSize = method->blockSize;
    ctx->xtsCtx.ciphMeth = method;
    return ctx;
}

int32_t MODES_XTS_InitCtx(MODES_XTS_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc)
{
    int32_t ret;
    ret = MODES_XTS_CheckPara(key, keyLen, iv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (enc) {
        ret = MODES_XTS_SetEncryptKey(&modeCtx->xtsCtx, key, keyLen);
    } else {
        ret = MODES_XTS_SetDecryptKey(&modeCtx->xtsCtx, key, keyLen);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = MODES_XTS_SetIv(&modeCtx->xtsCtx, iv, ivLen);
    if (ret != CRYPT_SUCCESS) {
        (void)MODES_XTS_DeInitCtx(modeCtx);
        return ret;
    }
    
    modeCtx->enc = enc;
    return ret;
}

int32_t MODES_XTS_Update(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return MODES_CipherStreamProcess(modeCtx->enc ? MODES_XTS_Encrypt : MODES_XTS_Decrypt, &modeCtx->xtsCtx,
        in, inLen, out, outLen);
}

int32_t MODES_XTS_Final(MODES_XTS_Ctx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    (void) modeCtx;
    (void) out;
    *outLen = 0;
    return CRYPT_SUCCESS;
}

int32_t MODES_XTS_DeInitCtx(MODES_XTS_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    MODES_XTS_Clean(&modeCtx->xtsCtx);
    (void)memset_s(modeCtx->data, EAL_MAX_BLOCK_LENGTH, 0, EAL_MAX_BLOCK_LENGTH);
    modeCtx->dataLen = 0;
    modeCtx->pad = CRYPT_PADDING_NONE;
    return CRYPT_SUCCESS;
}


void MODES_XTS_FreeCtx(MODES_XTS_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return;
    }
    MODES_XTS_Clean(&modeCtx->xtsCtx);
    BSL_SAL_FREE(modeCtx->xtsCtx.ciphCtx);
    BSL_SAL_FREE(modeCtx);
}


int32_t MODES_XTS_InitCtxEx(MODES_XTS_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc)
{
    (void)param;
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_SM4_XTS:
#ifdef HITLS_CRYPTO_SM4
            return SM4_XTS_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_XTS_InitCtx(modeCtx, key, keyLen, iv, ivLen, enc);
    }
}

int32_t MODES_XTS_UpdateEx(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = MODE_CheckUpdateParam(modeCtx->xtsCtx.blockSize, modeCtx->dataLen, inLen, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    switch (modeCtx->algId) {
        case CRYPT_CIPHER_AES128_XTS:
        case CRYPT_CIPHER_AES256_XTS:
#ifdef HITLS_CRYPTO_AES
            return AES_XTS_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        case CRYPT_CIPHER_SM4_XTS:
#ifdef HITLS_CRYPTO_SM4
            return SM4_XTS_Update(modeCtx, in, inLen, out, outLen);
#else
            return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
        default:
            return MODES_XTS_Update(modeCtx, in, inLen, out, outLen);
    }
}

#endif // HITLS_CRYPTO_XTS
