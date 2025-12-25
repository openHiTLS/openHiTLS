/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 * http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HCTR

#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_modes_hctr.h"
#include "modes_local.h"

#define HCTR_BLOCK_SIZE 16
#define HCTR_K1_LEN HCTR_BLOCK_SIZE
#define HCTR_K2_LEN HCTR_BLOCK_SIZE
#define HCTR_KEY_LEN (HCTR_K1_LEN + HCTR_K2_LEN)
#define HCTR_TW_LEN HCTR_BLOCK_SIZE
#define HCTR_MIN_DATA_LEN HCTR_BLOCK_SIZE
#define HCTR_DEFAULT_BUF_SIZE 4096

typedef struct HCTR_Inner_Ctx {
    uint8_t k1[HCTR_BLOCK_SIZE];
    uint8_t k2[HCTR_BLOCK_SIZE];
    uint8_t tw[HCTR_BLOCK_SIZE];
    MODES_HCTR_Buffer dataBuffer;
} HCTR_Inner_Ctx;

typedef struct HCTR_Pack_Ctx {
    void *algCtx;
    HCTR_Inner_Ctx hctrCtx;
} HCTR_Pack_Ctx;

static void HctrGf128Mul(const uint8_t a[HCTR_BLOCK_SIZE], const uint8_t b[HCTR_BLOCK_SIZE],
                        uint8_t res[HCTR_BLOCK_SIZE])
{
    uint8_t z[HCTR_BLOCK_SIZE];
    uint32_t i;

    (void)memset_s(res, HCTR_BLOCK_SIZE, 0, HCTR_BLOCK_SIZE);
    (void)memcpy_s(z, HCTR_BLOCK_SIZE, a, HCTR_BLOCK_SIZE);

    for (i = 0; i < 128; i++) {
        // Process multiplier 'b' from MSB (bit 7 of b[0])
        if ((b[i / 8] >> (7 - (i % 8))) & 1) {
            DATA64_XOR(res, z, res, HCTR_BLOCK_SIZE);
        }

        // Update z (right-shift and reduce)
        uint8_t lsbSet = (z[15] & 0x01);
        for (uint32_t j = HCTR_BLOCK_SIZE - 1; j > 0; j--) {
            z[j] = (z[j] >> 1) | (z[j - 1] << 7);
        }
        z[0] >>= 1;
        if (lsbSet) {
            z[0] ^= 0xE1; // Reduction for x^128 + x^7 + x^2 + x + 1
        }
    }
}

static int32_t HctrUniversalHash(const uint8_t *k, const uint8_t *data, uint32_t dataLen,
                                 const uint8_t *tw, uint8_t *out)
{
    uint8_t hashVal[HCTR_BLOCK_SIZE] = {0};
    uint8_t currentBlock[HCTR_BLOCK_SIZE] = {0};
    uint8_t *allData = NULL;
    uint8_t **kPowers = NULL;
    uint32_t allocatedPowers = 0;
    uint64_t effectiveLen = (uint64_t)dataLen + HCTR_TW_LEN;
    uint32_t m, i;
    int32_t ret = CRYPT_SUCCESS;

    allData = BSL_SAL_Malloc(effectiveLen > 0 ? effectiveLen : 1);
    if (allData == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (effectiveLen > 0) {
        (void)memcpy_s(allData, effectiveLen, data, dataLen);
        (void)memcpy_s(allData + dataLen, effectiveLen - dataLen, tw, HCTR_TW_LEN);
    }

    m = (uint32_t)((effectiveLen + HCTR_BLOCK_SIZE - 1) / HCTR_BLOCK_SIZE);
    if (effectiveLen == 0) {
        m = 0;
    }

    // Pre-calculate powers of K: K^2, ..., K^(m+1)
    if (m > 0) {
        kPowers = (uint8_t **)BSL_SAL_Malloc(sizeof(uint8_t *) * m);
        if (kPowers == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
            goto ERR;
        }
        (void)memset_s(kPowers, sizeof(uint8_t *) * m, 0, sizeof(uint8_t *) * m);

        for (i = 0; i < m; i++) {
            kPowers[i] = (uint8_t *)BSL_SAL_Malloc(HCTR_BLOCK_SIZE);
            if (kPowers[i] == NULL) {
                ret = CRYPT_MEM_ALLOC_FAIL;
                goto ERR;
            }
            allocatedPowers++;
        }
        
        uint8_t kPow1[HCTR_BLOCK_SIZE];
        (void)memcpy_s(kPow1, HCTR_BLOCK_SIZE, k, HCTR_BLOCK_SIZE);
        HctrGf128Mul(kPow1, k, kPowers[0]); // kPowers[0] = K^2

        for (i = 1; i < m; i++) {
            HctrGf128Mul(kPowers[i - 1], k, kPowers[i]); // kPowers[i] = K^(i+2)
        }
    }

    // Direct summation
    (void)memset_s(hashVal, HCTR_BLOCK_SIZE, 0, HCTR_BLOCK_SIZE);
    if (m > 0) {
        for (i = 0; i < m; i++) {
            uint32_t offset = i * HCTR_BLOCK_SIZE;
            uint32_t chunkLen = (effectiveLen - offset < HCTR_BLOCK_SIZE) ?
                                (uint32_t)(effectiveLen - offset) : HCTR_BLOCK_SIZE;
            (void)memset_s(currentBlock, sizeof(currentBlock), 0, sizeof(currentBlock));
            (void)memcpy_s(currentBlock, sizeof(currentBlock), allData + offset, chunkLen);

            // Term is M_{i+1} * K^{m-i+1}. Powers are K^(m+1), K^m, ..., K^2
            // This corresponds to kPowers[m-1-i]
            uint8_t term[HCTR_BLOCK_SIZE];
            HctrGf128Mul(currentBlock, kPowers[m - 1 - i], term);
            DATA64_XOR(hashVal, term, hashVal, HCTR_BLOCK_SIZE);
        }
    }

    // Process length block term: L * K
    uint8_t lenBlock[HCTR_BLOCK_SIZE] = {0};
    uint64_t totalLenBits = effectiveLen * 8;
    PUT_UINT64_BE(totalLenBits, lenBlock, 8);

    uint8_t lenTerm[HCTR_BLOCK_SIZE];
    HctrGf128Mul(lenBlock, k, lenTerm);
    DATA64_XOR(hashVal, lenTerm, hashVal, HCTR_BLOCK_SIZE);

    (void)memcpy_s(out, HCTR_BLOCK_SIZE, hashVal, HCTR_BLOCK_SIZE);

ERR:
    BSL_SAL_Free(allData);
    if (kPowers != NULL) {
        for (i = 0; i < allocatedPowers; i++) {
            if (kPowers[i] != NULL) {
                BSL_SAL_Free(kPowers[i]);
            }
        }
        BSL_SAL_Free(kPowers);
    }
    return ret;
}

void *MODES_HCTR_NewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;

    int32_t underlyingAlgId;
    switch (algId) {
        case CRYPT_CIPHER_SM4_HCTR:
            underlyingAlgId = CRYPT_CIPHER_SM4_ECB;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return NULL;
    }
    const EAL_SymMethod *method = EAL_GetSymMethod(underlyingAlgId);
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }

    MODES_CipherCtx *ctx = (MODES_CipherCtx *)BSL_SAL_Calloc(1, sizeof(MODES_CipherCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    HCTR_Pack_Ctx *packCtx = (HCTR_Pack_Ctx *)BSL_SAL_Calloc(1, sizeof(HCTR_Pack_Ctx));
    if (packCtx == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    packCtx->algCtx = BSL_SAL_Calloc(1, method->ctxSize);
    if (packCtx->algCtx == NULL) {
        BSL_SAL_Free(packCtx);
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    packCtx->hctrCtx.dataBuffer.buffer = (uint8_t *)BSL_SAL_Calloc(1, HCTR_DEFAULT_BUF_SIZE);
    if (packCtx->hctrCtx.dataBuffer.buffer == NULL) {
        BSL_SAL_Free(packCtx->algCtx);
        BSL_SAL_Free(packCtx);
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    packCtx->hctrCtx.dataBuffer.bufSize = HCTR_DEFAULT_BUF_SIZE;

    ctx->algId = algId;
    ctx->commonCtx.blockSize = method->blockSize;
    ctx->commonCtx.ciphMeth = method;
    ctx->commonCtx.ciphCtx = packCtx;

    return ctx;
}

int32_t MODES_HCTR_Init(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
                        uint32_t ivLen, void *param, bool enc)
{
    (void)param;
    if (modeCtx == NULL || key == NULL || iv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (keyLen != HCTR_KEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ivLen != HCTR_TW_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_IVLEN_ERROR);
        return CRYPT_MODES_IVLEN_ERROR;
    }

    HCTR_Pack_Ctx *packCtx = (HCTR_Pack_Ctx *)modeCtx->commonCtx.ciphCtx;
    HCTR_Inner_Ctx *hctrCtx = &packCtx->hctrCtx;

    (void)memcpy_s(hctrCtx->k1, sizeof(hctrCtx->k1), key, HCTR_BLOCK_SIZE);
    (void)memcpy_s(hctrCtx->k2, sizeof(hctrCtx->k2), key + HCTR_BLOCK_SIZE, HCTR_BLOCK_SIZE);
    (void)memcpy_s(hctrCtx->tw, sizeof(hctrCtx->tw), iv, ivLen);

    int32_t ret = modeCtx->commonCtx.ciphMeth->setEncryptKey(packCtx->algCtx, hctrCtx->k1, HCTR_BLOCK_SIZE);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    hctrCtx->dataBuffer.dataLen = 0;
    modeCtx->enc = enc;
    return CRYPT_SUCCESS;
}

static int32_t HctrBufferEnsureCapacity(MODES_HCTR_Buffer *buffer, uint32_t additionalDataLen)
{
    if (buffer->bufSize - buffer->dataLen >= additionalDataLen) {
        return CRYPT_SUCCESS;
    }

    uint64_t newSize64 = (uint64_t)buffer->dataLen + additionalDataLen;
    if (newSize64 > UINT32_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t newSize = (uint32_t)newSize64;
    uint8_t *newBuf = (uint8_t *)BSL_SAL_Malloc(newSize);
    if (newBuf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    if (buffer->dataLen > 0) {
        (void)memcpy_s(newBuf, newSize, buffer->buffer, buffer->dataLen);
    }

    BSL_SAL_Free(buffer->buffer);
    buffer->buffer = newBuf;
    buffer->bufSize = newSize;

    return CRYPT_SUCCESS;
}

int32_t MODES_HCTR_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    (void)out;
    if (modeCtx == NULL || outLen == NULL || (inLen > 0 && in == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (inLen == 0) {
        *outLen = 0;
        return CRYPT_SUCCESS;
    }
    
    HCTR_Pack_Ctx *packCtx = (HCTR_Pack_Ctx *)modeCtx->commonCtx.ciphCtx;
    MODES_HCTR_Buffer *buffer = &packCtx->hctrCtx.dataBuffer;

    int32_t ret = HctrBufferEnsureCapacity(buffer, inLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    (void)memcpy_s(buffer->buffer + buffer->dataLen, buffer->bufSize - buffer->dataLen, in, inLen);
    buffer->dataLen += inLen;

    *outLen = 0;
    return CRYPT_SUCCESS;
}

int32_t MODES_HCTR_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    HCTR_Pack_Ctx *packCtx = (HCTR_Pack_Ctx *)modeCtx->commonCtx.ciphCtx;
    HCTR_Inner_Ctx *hctrCtx = &packCtx->hctrCtx;
    uint32_t dataLen = hctrCtx->dataBuffer.dataLen;

    if (dataLen < HCTR_MIN_DATA_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_HCTR_DATA_TOO_SHORT);
        *outLen = 0;
        return CRYPT_MODES_ERR_HCTR_DATA_TOO_SHORT;
    }
    
    if (*outLen < dataLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
        *outLen = 0;
        return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
    }

    void *algCtx = packCtx->algCtx;
    uint8_t *data = hctrCtx->dataBuffer.buffer;
    uint32_t restLen = dataLen - HCTR_BLOCK_SIZE;
    uint8_t z1[HCTR_BLOCK_SIZE];
    uint8_t z2[HCTR_BLOCK_SIZE];
    uint8_t hVal[HCTR_BLOCK_SIZE];
    uint8_t ctrBase[HCTR_BLOCK_SIZE];
    int32_t ret;
    uint64_t i;

    if (modeCtx->enc) {
        /* --- ENCRYPTION PATH --- */
        GOTO_ERR_IF(modeCtx->commonCtx.ciphMeth->setEncryptKey(packCtx->algCtx, hctrCtx->k1, HCTR_BLOCK_SIZE), ret);

        const uint8_t *p1 = data;
        const uint8_t *pRest = data + HCTR_BLOCK_SIZE;
        uint8_t *c1 = out;
        uint8_t *cRest = out + HCTR_BLOCK_SIZE;

        GOTO_ERR_IF(HctrUniversalHash(hctrCtx->k2, pRest, restLen, hctrCtx->tw, hVal), ret);
        DATA64_XOR(p1, hVal, z1, HCTR_BLOCK_SIZE);
        GOTO_ERR_IF(modeCtx->commonCtx.ciphMeth->encryptBlock(algCtx, z1, z2, HCTR_BLOCK_SIZE), ret);
        DATA64_XOR(z1, z2, ctrBase, HCTR_BLOCK_SIZE);

        uint8_t counterBlock[HCTR_BLOCK_SIZE];
        uint8_t keystreamBlock[HCTR_BLOCK_SIZE];
        uint32_t processedLen = 0;
        
        i = 1;
        uint32_t numFullBlocks = restLen / HCTR_BLOCK_SIZE;

        /* OPTIMIZATION: Process all full blocks first */
        for (uint32_t j = 0; j < numFullBlocks; j++) {
            (void)memcpy_s(counterBlock, sizeof(counterBlock), ctrBase, sizeof(ctrBase));
            uint8_t iBe[sizeof(uint64_t)];
            PUT_UINT64_BE(i, iBe, 0);
            DATA_XOR(counterBlock + (HCTR_BLOCK_SIZE - sizeof(uint64_t)), iBe,
                     counterBlock + (HCTR_BLOCK_SIZE - sizeof(uint64_t)), sizeof(uint64_t));

            GOTO_ERR_IF(modeCtx->commonCtx.ciphMeth->encryptBlock(algCtx, counterBlock, keystreamBlock, HCTR_BLOCK_SIZE), ret);
            DATA_XOR(pRest + processedLen, keystreamBlock, cRest + processedLen, HCTR_BLOCK_SIZE);
            processedLen += HCTR_BLOCK_SIZE;
            i++;
        }

        /* OPTIMIZATION: Process the final partial block separately */
        uint32_t lastChunkLen = restLen - processedLen;
        if (lastChunkLen > 0) {
            (void)memcpy_s(counterBlock, sizeof(counterBlock), ctrBase, sizeof(ctrBase));
            uint8_t iBe[sizeof(uint64_t)];
            PUT_UINT64_BE(i, iBe, 0);
            DATA_XOR(counterBlock + (HCTR_BLOCK_SIZE - sizeof(uint64_t)), iBe,
                     counterBlock + (HCTR_BLOCK_SIZE - sizeof(uint64_t)), sizeof(uint64_t));
            
            GOTO_ERR_IF(modeCtx->commonCtx.ciphMeth->encryptBlock(algCtx, counterBlock, keystreamBlock, HCTR_BLOCK_SIZE), ret);
            DATA_XOR(pRest + processedLen, keystreamBlock, cRest + processedLen, lastChunkLen);
        }

        GOTO_ERR_IF(HctrUniversalHash(hctrCtx->k2, cRest, restLen, hctrCtx->tw, hVal), ret);
        DATA64_XOR(z2, hVal, c1, HCTR_BLOCK_SIZE);
    } else {
        /* --- DECRYPTION PATH --- */
        GOTO_ERR_IF(modeCtx->commonCtx.ciphMeth->setDecryptKey(packCtx->algCtx, hctrCtx->k1, HCTR_BLOCK_SIZE), ret);

        const uint8_t *c1 = data;
        const uint8_t *cRest = data + HCTR_BLOCK_SIZE;
        uint8_t *p1 = out;
        uint8_t *pRest = out + HCTR_BLOCK_SIZE;

        GOTO_ERR_IF(HctrUniversalHash(hctrCtx->k2, cRest, restLen, hctrCtx->tw, hVal), ret);
        DATA64_XOR(c1, hVal, z2, HCTR_BLOCK_SIZE);
        GOTO_ERR_IF(modeCtx->commonCtx.ciphMeth->decryptBlock(algCtx, z2, z1, HCTR_BLOCK_SIZE), ret);
        DATA64_XOR(z1, z2, ctrBase, HCTR_BLOCK_SIZE);
        GOTO_ERR_IF(modeCtx->commonCtx.ciphMeth->setEncryptKey(packCtx->algCtx, hctrCtx->k1, HCTR_BLOCK_SIZE), ret);
            
        uint8_t counterBlock[HCTR_BLOCK_SIZE];
        uint8_t keystreamBlock[HCTR_BLOCK_SIZE];
        uint32_t processedLen = 0;
        
        i = 1;
        uint32_t numFullBlocks = restLen / HCTR_BLOCK_SIZE;
        
        for (uint32_t j = 0; j < numFullBlocks; j++) {
            (void)memcpy_s(counterBlock, sizeof(counterBlock), ctrBase, sizeof(ctrBase));
            uint8_t iBe[sizeof(uint64_t)];
            PUT_UINT64_BE(i, iBe, 0);
            DATA_XOR(counterBlock + (HCTR_BLOCK_SIZE - sizeof(uint64_t)), iBe,
                     counterBlock + (HCTR_BLOCK_SIZE - sizeof(uint64_t)), sizeof(uint64_t));

            GOTO_ERR_IF(modeCtx->commonCtx.ciphMeth->encryptBlock(algCtx, counterBlock, keystreamBlock, HCTR_BLOCK_SIZE), ret);
            DATA_XOR(cRest + processedLen, keystreamBlock, pRest + processedLen, HCTR_BLOCK_SIZE);
            processedLen += HCTR_BLOCK_SIZE;
            i++;
        }

        uint32_t lastChunkLen = restLen - processedLen;
        if (lastChunkLen > 0) {
            (void)memcpy_s(counterBlock, sizeof(counterBlock), ctrBase, sizeof(ctrBase));
            uint8_t iBe[sizeof(uint64_t)];
            PUT_UINT64_BE(i, iBe, 0);
            DATA_XOR(counterBlock + (HCTR_BLOCK_SIZE - sizeof(uint64_t)), iBe,
                     counterBlock + (HCTR_BLOCK_SIZE - sizeof(uint64_t)), sizeof(uint64_t));

            GOTO_ERR_IF(modeCtx->commonCtx.ciphMeth->encryptBlock(algCtx, counterBlock, keystreamBlock, HCTR_BLOCK_SIZE), ret);
            DATA_XOR(cRest + processedLen, keystreamBlock, pRest + processedLen, lastChunkLen);
        }

        GOTO_ERR_IF(HctrUniversalHash(hctrCtx->k2, pRest, restLen, hctrCtx->tw, hVal), ret);
        DATA64_XOR(z1, hVal, p1, HCTR_BLOCK_SIZE);
    }

    *outLen = dataLen;
    ret = CRYPT_SUCCESS;

ERR:
    (void)memset_s(z1, sizeof(z1), 0, sizeof(z1));
    (void)memset_s(z2, sizeof(z2), 0, sizeof(z2));
    (void)memset_s(hVal, sizeof(hVal), 0, sizeof(hVal));
    (void)memset_s(ctrBase, sizeof(ctrBase), 0, sizeof(ctrBase));
    hctrCtx->dataBuffer.dataLen = 0;
    return ret;
}

int32_t MODES_HCTR_DeInit(MODES_CipherCtx *modeCtx)
{
    if (modeCtx == NULL || modeCtx->commonCtx.ciphCtx == NULL) {
        return CRYPT_SUCCESS;
    }
    HCTR_Pack_Ctx *packCtx = (HCTR_Pack_Ctx *)modeCtx->commonCtx.ciphCtx;
    HCTR_Inner_Ctx *hctrCtx = &packCtx->hctrCtx;

    (void)BSL_SAL_CleanseData(hctrCtx->k1, sizeof(hctrCtx->k1));
    (void)BSL_SAL_CleanseData(hctrCtx->k2, sizeof(hctrCtx->k2));
    (void)BSL_SAL_CleanseData(hctrCtx->tw, sizeof(hctrCtx->tw));
    
    if (hctrCtx->dataBuffer.buffer != NULL) {
        (void)BSL_SAL_CleanseData(hctrCtx->dataBuffer.buffer, hctrCtx->dataBuffer.bufSize);
    }
    hctrCtx->dataBuffer.dataLen = 0;
    
    if (packCtx->algCtx != NULL && modeCtx->commonCtx.ciphMeth->cipherDeInitCtx != NULL) {
        (void)modeCtx->commonCtx.ciphMeth->cipherDeInitCtx(packCtx->algCtx);
    }
    
    return CRYPT_SUCCESS;
}

void MODES_HCTR_Free(MODES_CipherCtx *modeCtx)
{
    if (modeCtx == NULL) {
        return;
    }

    (void)MODES_HCTR_DeInit(modeCtx);

    if (modeCtx->commonCtx.ciphCtx != NULL) {
        HCTR_Pack_Ctx *packCtx = (HCTR_Pack_Ctx *)modeCtx->commonCtx.ciphCtx;
        
        if (packCtx->hctrCtx.dataBuffer.buffer != NULL) {
            BSL_SAL_Free(packCtx->hctrCtx.dataBuffer.buffer);
            packCtx->hctrCtx.dataBuffer.buffer = NULL;
        }
        
        BSL_SAL_Free(packCtx->algCtx);
        BSL_SAL_Free(packCtx);
        modeCtx->commonCtx.ciphCtx = NULL;
    }
    
    BSL_SAL_Free(modeCtx);
}

int32_t MODES_HCTR_Ctrl(MODES_CipherCtx *modeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    HCTR_Pack_Ctx *packCtx = (HCTR_Pack_Ctx *)modeCtx->commonCtx.ciphCtx;
    
    switch (cmd) {
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || valLen != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = 1; // HCTR is a stream-like mode
            return CRYPT_SUCCESS;
        default:
            if (modeCtx->commonCtx.ciphMeth->cipherCtrl != NULL) {
                return modeCtx->commonCtx.ciphMeth->cipherCtrl(packCtx->algCtx, cmd, val, valLen);
            }
            return CRYPT_NOT_SUPPORT;
    }
}

MODES_CipherCtx *MODES_HCTR_DupCtx(const MODES_CipherCtx *modeCtx)
{
    if (modeCtx == NULL) {
        return NULL;
    }
    MODES_CipherCtx *ctx = BSL_SAL_Dump(modeCtx, sizeof(MODES_CipherCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return ctx;
    }

    HCTR_Pack_Ctx *packCtx = (HCTR_Pack_Ctx *)modeCtx->commonCtx.ciphCtx;
    HCTR_Pack_Ctx *newPackCtx = BSL_SAL_Dump(packCtx, sizeof(HCTR_Pack_Ctx));
    if (newPackCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_ClearFree(ctx, sizeof(MODES_CipherCtx));
        return NULL;
    }

    newPackCtx->hctrCtx.dataBuffer.buffer = BSL_SAL_Dump(packCtx->hctrCtx.dataBuffer.buffer, HCTR_DEFAULT_BUF_SIZE);
    if (newPackCtx->hctrCtx.dataBuffer.buffer == NULL) {
        BSL_SAL_ClearFree(newPackCtx, sizeof(HCTR_Pack_Ctx));
        BSL_SAL_ClearFree(ctx, sizeof(MODES_CipherCtx));
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    newPackCtx->algCtx = BSL_SAL_Dump(packCtx->algCtx, modeCtx->commonCtx.ciphMeth->ctxSize);
    if (packCtx->algCtx == NULL) {
        BSL_SAL_ClearFree(newPackCtx->hctrCtx.dataBuffer.buffer, HCTR_DEFAULT_BUF_SIZE);
        BSL_SAL_ClearFree(newPackCtx, sizeof(HCTR_Pack_Ctx));
        BSL_SAL_ClearFree(ctx, sizeof(MODES_CipherCtx));
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    ctx->commonCtx.ciphCtx = newPackCtx;
    return ctx;
}

#endif /* HITLS_CRYPTO_HCTR */