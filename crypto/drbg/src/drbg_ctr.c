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
#ifdef HITLS_CRYPTO_DRBG_CTR

#include <stdlib.h>
#include <securec.h>
#include "crypt_errno.h"
#include "crypt_local_types.h"
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "crypt_types.h"
#include "bsl_err_internal.h"
#include "drbg_local.h"


#define DRBG_CTR_MAX_KEYLEN (32)
#define AES_BLOCK_LEN (16)
#define DRBG_CTR_MAX_SEEDLEN (48)
#define DRBG_CTR_MIN_ENTROPYLEN (32)

typedef struct {
    uint8_t k[DRBG_CTR_MAX_KEYLEN];   // DRBG_CTR_MAX_KEYLEN 32
    uint8_t v[AES_BLOCK_LEN];		  // AES_BLOCK_LEN 16 (blockLen)
    uint8_t kx[DRBG_CTR_MAX_SEEDLEN]; // DRBG_CTR_MAX_SEEDLEN 48
    uint32_t keyLen;
    uint32_t seedLen;
    const EAL_SymMethod *ciphMeth;
    void *ctrCtx;
    void *dfCtx;
    bool isUsedDf;
} DRBG_CtrCtx;

static void DRBG_CtrXor(CRYPT_Data *dst, const CRYPT_Data *src)
{
    uint32_t xorlen;

    if (CRYPT_IsDataNull(dst) || CRYPT_IsDataNull(src)) {
        return;
    }

    xorlen = (dst->len > src->len) ? src->len : dst->len;

    DATA_XOR(dst->data, src->data, dst->data, xorlen);
}

static void DRBG_CtrInc(uint8_t *v, uint32_t len)
{
    uint32_t i;
    uint8_t *p = v + len - 1;
    for (i = 0; i < len; i++, p--) {
        (*p)++;
        if (*p != 0) {
            break;
        }
    }
}

int32_t DRBG_CtrUpdate(DRBG_Ctx *drbg, const CRYPT_Data *in1, const CRYPT_Data *in2)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    const EAL_SymMethod *ciphMeth = ctx->ciphMeth;
    int32_t ret;
    uint8_t tempData[DRBG_CTR_MAX_SEEDLEN];
    CRYPT_Data temp;
    uint32_t offset;

    if ((ret = ciphMeth->setEncryptKey(ctx->ctrCtx, ctx->k, ctx->keyLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /**
    While (len (temp) < seedlen) do
        If ctr_len < blocklen
            inc = (rightmost (V, ctr_len) + 1) mod 2ctr_len .
            V = leftmost (V, blocklen-ctr_len) || inc.
        Else V = (V+1) mod 2blocklen .
        output_block = Block_Encrypt (Key, V).
        temp = temp || output_block.
    */
    for (offset = 0; offset < ctx->seedLen; offset += AES_BLOCK_LEN) {
        DRBG_CtrInc(ctx->v, AES_BLOCK_LEN);
        if ((ret = ciphMeth->encryptBlock(ctx->ctrCtx, ctx->v, tempData + offset, AES_BLOCK_LEN)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
    }

    // temp = temp ⊕ provided_data
    temp.data = tempData;
    temp.len = ctx->seedLen;
    DRBG_CtrXor(&temp, in1);
    DRBG_CtrXor(&temp, in2);

    // Key = leftmost (temp, keylen). V = rightmost (temp, blocklen).
    if (memcpy_s(ctx->k, DRBG_CTR_MAX_KEYLEN, temp.data, ctx->keyLen) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        ret = CRYPT_SECUREC_FAIL;
        goto EXIT;
    }
    // The length to be copied of ctx->V is AES_BLOCK_LEN, which is also the array length.
    // The lower bits of temp.data are used for ctx->K, and the upper bits are used for ctx->V.
    (void)memcpy_s(ctx->v, AES_BLOCK_LEN, temp.data + ctx->keyLen, AES_BLOCK_LEN);
EXIT:
    ciphMeth->cipherDeInitCtx(ctx->ctrCtx);
    return ret;
}

// BCC implementation, BCC is CBC-MAC: CBC encryption + IV(0) + last ciphertext returned.
static int32_t DRBG_CtrBCCUpdateBlock(DRBG_Ctx *drbg, const uint8_t *in, uint8_t *out, uint32_t len)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    int32_t ret;
    /**
    4.	For i = 1 to n do
        4.1 input_block = chaining_value ⊕ blocki.
        4.2 chaining_value = Block_Encrypt (Key, input_block).
    */
    DATA_XOR(out, in, out, len);
    if ((ret = ctx->ciphMeth->encryptBlock(ctx->dfCtx, out, out, AES_BLOCK_LEN)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        ctx->ciphMeth->cipherDeInitCtx(ctx->dfCtx);
    }

    return ret;
}

static int32_t DRBG_CtrBCCInit(DRBG_Ctx *drbg)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    uint8_t *out = ctx->kx;
    int32_t ret = CRYPT_SUCCESS;
    uint8_t in[16] = { 0 };
    uint32_t offset = 0;

    while (offset < ctx->seedLen) {
        if ((ret = DRBG_CtrBCCUpdateBlock(drbg, in, out + offset, AES_BLOCK_LEN)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        in[3]++; // Each cycle is incremented by 1 at the 3rd position.
        offset += AES_BLOCK_LEN;
    }

    return ret;
}

static int32_t DRBG_CtrBCCUpdateKX(DRBG_Ctx *drbg, const uint8_t *in)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    uint8_t *out = ctx->kx;
    int32_t ret = CRYPT_SUCCESS;
    uint32_t offset = 0;

    while (offset < ctx->seedLen) {
        if ((ret = DRBG_CtrBCCUpdateBlock(drbg, in, out + offset, AES_BLOCK_LEN)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        offset += AES_BLOCK_LEN;
    }

    return ret;
}

// Temporary block storage used by ctr_df
static int32_t DRBG_CtrBCCUpdate(DRBG_Ctx *drbg, const CRYPT_Data *in, uint8_t temp[16], uint32_t *tempLen)
{
    uint32_t dataLeft;
    uint32_t offset = 0;
    uint32_t tempPos = *tempLen;
    int32_t ret = CRYPT_SUCCESS;

    if (CRYPT_IsDataNull(in) || in->len == 0) {
        return ret;
    }

    dataLeft = in->len;

    do {
        const uint32_t left = AES_BLOCK_LEN - tempPos;
        const uint32_t cpyLen = (left > dataLeft) ? dataLeft : left;
        if (memcpy_s(temp + tempPos, left, in->data + offset, cpyLen) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }

        if (left == cpyLen) {
            if ((ret = DRBG_CtrBCCUpdateKX(drbg, temp)) != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            tempPos = 0;
        } else {
            tempPos += cpyLen;
        }

        dataLeft -= cpyLen;
        offset += cpyLen;
    } while (dataLeft > 0);

    *tempLen = tempPos;

    return ret;
}

static int32_t DRBG_CtrBCCFinal(DRBG_Ctx *drbg, uint8_t temp[16], uint32_t tempLen)
{
    int32_t ret;
    uint32_t i;

    for (i = tempLen; i < AES_BLOCK_LEN; i++) {
        temp[i] = 0;
    }

    if ((ret = DRBG_CtrBCCUpdateKX(drbg, temp)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

static int32_t BlockCipherDfCal(DRBG_Ctx *drbg, CRYPT_Data *out)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    const EAL_SymMethod *ciphMeth = ctx->ciphMeth;
    int32_t ret;
    uint32_t kOffset = 0;
    uint32_t vOffset = ctx->keyLen;

    /* Set up key K */
    if ((ret = ciphMeth->setEncryptKey(ctx->ctrCtx, ctx->kx, ctx->keyLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    while (kOffset < ctx->seedLen) {
        ret = ciphMeth->encryptBlock(ctx->ctrCtx, ctx->kx + vOffset, ctx->kx + kOffset, AES_BLOCK_LEN);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }

        vOffset = kOffset;
        kOffset += AES_BLOCK_LEN;
    }

    out->data = ctx->kx;
    out->len = ctx->seedLen;

EXIT:
    ciphMeth->cipherDeInitCtx(ctx->ctrCtx);
    return ret;
}

static int32_t BlockCipherDf(DRBG_Ctx *drbg, const CRYPT_Data *in1, const CRYPT_Data *in2,
    const CRYPT_Data *in3, CRYPT_Data *out)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    int32_t ret;
    uint32_t tempLen = 8;
    uint8_t temp[16] = { 0 };
    uint32_t l;

    BSL_SAL_CleanseData(ctx->kx, sizeof(ctx->kx));

    if ((ret = DRBG_CtrBCCInit(drbg)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /**
    2. L = len (input_string)/8.
    3. N = number_of_bits_to_return/8.
    4. S = L || N || input_string || 0x80.
    5. While (len (S) mod outlen) ≠ 0, do
        S = S || 0x00.
    6. temp = the Null string.
    9. While len (temp) < keylen + outlen, do
        9.1	IV = i || 0^(outlen - len (i))
        9.2 temp = temp || BCC (K, (IV || S)).
        9.3	i = i + 1.
    */

    l = (in1 ? in1->len : 0) + (in2 ? in2->len : 0) + (in3 ? in3->len : 0);

    temp[0] = (uint8_t)((l >> 24) & 0xff);
    temp[1] = (uint8_t)((l >> 16) & 0xff);
    temp[2] = (uint8_t)((l >> 8) & 0xff);
    temp[3] = (uint8_t)(l & 0xff);
    temp[4] = 0;
    temp[5] = 0;
    temp[6] = 0;
    temp[7] = (uint8_t)ctx->seedLen;

    if ((ret = DRBG_CtrBCCUpdate(drbg, in1, temp, &tempLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if ((ret = DRBG_CtrBCCUpdate(drbg, in2, temp, &tempLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if ((ret = DRBG_CtrBCCUpdate(drbg, in3, temp, &tempLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    temp[tempLen++] = 0x80;
    if ((ret = DRBG_CtrBCCFinal(drbg, temp, tempLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /**
    13. While len (temp) < number_of_bits_to_return, do
        13.1 X = Block_Encrypt (K, X).
        13.2 temp = temp || X.
    */
    if ((ret = BlockCipherDfCal(drbg, out)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

static int32_t DRBG_CtrSetDfKey(DRBG_Ctx *drbg)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    const EAL_SymMethod *ciphMeth = ctx->ciphMeth;
    int32_t ret = CRYPT_SUCCESS;

    BSL_SAL_CleanseData(ctx->ctrCtx, ciphMeth->ctxSize);

    if (ctx->isUsedDf) {
        /* df initialisation */
        const uint8_t dfKey[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        BSL_SAL_CleanseData(ctx->dfCtx, ciphMeth->ctxSize);

        /* Set key schedule for dfKey */
        if ((ret = ctx->ciphMeth->setEncryptKey(ctx->dfCtx, dfKey, ctx->keyLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
    }

    return ret;
}

int32_t DRBG_CtrInstantiate(DRBG_Ctx *drbg, const CRYPT_Data *entropy, const CRYPT_Data *nonce, const CRYPT_Data *pers)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    CRYPT_Data seedMaterial;
    int32_t ret;

    if ((ret = DRBG_CtrSetDfKey(drbg)) != CRYPT_SUCCESS) {
        return ret;
    }
    /**
     * 4. Key = 0(keylen)
     * 5. V = 0(blocklen)
     */
    BSL_SAL_CleanseData(ctx->k, sizeof(ctx->k));
    BSL_SAL_CleanseData(ctx->v, sizeof(ctx->v));

    /* seed_material = entropy_input ⊕ personalization_string.
       (Key, V) = CTR_DRBG_Update (seed_material, Key, V).
    */
    if (!ctx->isUsedDf) {
        if ((ret = DRBG_CtrUpdate(drbg, entropy, pers)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
        return ret;
    }
    // seed_material = entropy_input || nonce || personalization_string.
    if ((ret = BlockCipherDf(drbg, entropy, nonce, pers, &seedMaterial)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        ctx->ciphMeth->cipherDeInitCtx(ctx->dfCtx);
        return ret;
    }

    if ((ret = DRBG_CtrUpdate(drbg, &seedMaterial, NULL)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

int32_t DRBG_CtrReseed(DRBG_Ctx *drbg, const CRYPT_Data *entropy, const CRYPT_Data *adin)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    CRYPT_Data seedMaterial;
    int32_t ret;

    if (!ctx->isUsedDf) {
        if ((ret = DRBG_CtrUpdate(drbg, entropy, adin)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
        return ret;
    }

    // seed_material = entropy_input || additional_input.
    if ((ret = BlockCipherDf(drbg, entropy, adin, NULL, &seedMaterial)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if ((ret = DRBG_CtrUpdate(drbg, &seedMaterial, NULL)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

static int32_t DRBG_CtrGenerateBlock(DRBG_Ctx *drbg, uint8_t *out, uint32_t outLen)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    int32_t ret;

    DRBG_CtrInc(ctx->v, outLen);

    if ((ret = ctx->ciphMeth->encryptBlock(ctx->ctrCtx, ctx->v, out, outLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        ctx->ciphMeth->cipherDeInitCtx(ctx->ctrCtx);
    }
    return ret;
}

static int32_t DRBG_CtrGenerateBlocks(DRBG_Ctx *drbg, uint8_t *out, uint32_t outLen)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    uint32_t offset = 0;
    uint32_t tmpOutLen = outLen;
    int32_t ret;

    if ((ret = ctx->ciphMeth->setEncryptKey(ctx->ctrCtx, ctx->k, ctx->keyLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    while (tmpOutLen >= AES_BLOCK_LEN) {
        if ((ret = DRBG_CtrGenerateBlock(drbg, out + offset, AES_BLOCK_LEN)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        tmpOutLen -= AES_BLOCK_LEN;
        offset += AES_BLOCK_LEN;
    }

    if (tmpOutLen > 0) {
        uint8_t temp[AES_BLOCK_LEN];
        if ((ret = DRBG_CtrGenerateBlock(drbg, temp, AES_BLOCK_LEN)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        // tmpOutLen indicates the length of the out remaining. In the last part of DRBG generation,
        // truncate the length of tmpOutLen and assign it to the out remaining.
        (void)memcpy_s(out + offset, tmpOutLen, temp, tmpOutLen);
    }

    return ret;
}

int32_t DRBG_CtrGenerate(DRBG_Ctx *drbg, uint8_t *out, uint32_t outLen, const CRYPT_Data *adin)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx *)drbg->ctx;
    int32_t ret;
    /**
    If (additional_input ≠ Null), then
        temp = len (additional_input)
        If (temp < seedlen), then
            additional_input = additional_input || 0^(seedlen - temp).
        (Key, V) = CTR_DRBG_Update (additional_input, Key, V)
    Else additional_input = 0seedlen.
    */
    if (adin != NULL && adin->data != NULL && adin->len != 0) {
        if (!ctx->isUsedDf) {
            if ((ret = DRBG_CtrUpdate(drbg, adin, NULL)) != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        } else {
            // additional_input = Block_Cipher_df (additional_input, seedlen).
            if ((ret = BlockCipherDf(drbg, adin, NULL, NULL, (CRYPT_Data *)(uintptr_t)adin)) != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            if ((ret = DRBG_CtrUpdate(drbg, adin, NULL)) != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
    }

    /**
    3. temp = Null.
    4. While (len (temp) < requested_number_of_bits) do:
        4.1	If ctr_len < blocklen
                4.1.1 inc = (rightmost (V, ctr_len) + 1) mod 2ctr_len .
                4.1.2 V = leftmost (V, blocklen-ctr_len) || inc.
            Else V = (V+1) mod 2blocklen .
        4.2 output_block = Block_Encrypt (Key, V).
        4.3 temp = temp || output_block.
    5. returned_bits = leftmost (temp, requested_number_of_bits).
    */

    if ((ret = DRBG_CtrGenerateBlocks(drbg, out, outLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // (Key, V) = CTR_DRBG_Update (additional_input, Key, V).
    if ((ret = DRBG_CtrUpdate(drbg, adin, NULL)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

void DRBG_CtrUnInstantiate(DRBG_Ctx *drbg)
{
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx*)drbg->ctx;

    ctx->ciphMeth->cipherDeInitCtx(ctx->ctrCtx);
    ctx->ciphMeth->cipherDeInitCtx(ctx->dfCtx);
    BSL_SAL_CleanseData((void *)(ctx->k), sizeof(ctx->k));
    BSL_SAL_CleanseData((void *)(ctx->v), sizeof(ctx->v));
    BSL_SAL_CleanseData((void *)(ctx->kx), sizeof(ctx->kx));
}

DRBG_Ctx *DRBG_CtrDup(DRBG_Ctx *drbg)
{
    DRBG_CtrCtx *ctx = NULL;

    if (drbg == NULL) {
        return NULL;
    }

    ctx = (DRBG_CtrCtx*)drbg->ctx;
    return DRBG_NewCtrCtx(ctx->ciphMeth, ctx->keyLen,  drbg->isGm, ctx->isUsedDf, &(drbg->seedMeth), drbg->seedCtx);
}

void DRBG_CtrFree(DRBG_Ctx *drbg)
{
    if (drbg == NULL) {
        return;
    }

    DRBG_CtrUnInstantiate(drbg);
    DRBG_CtrCtx *ctx = (DRBG_CtrCtx*)drbg->ctx;
    BSL_SAL_FREE(ctx->dfCtx);
    BSL_SAL_FREE(drbg);
    return;
}

DRBG_Ctx *DRBG_NewCtrCtx(const EAL_SymMethod *ciphMeth, const uint32_t keyLen, bool isGm, const bool isUsedDf,
    const CRYPT_RandSeedMethod *seedMeth, void *seedCtx)
{
    static DRBG_Method meth = {
        DRBG_CtrInstantiate,
        DRBG_CtrGenerate,
        DRBG_CtrReseed,
        DRBG_CtrUnInstantiate,
        DRBG_CtrDup,
        DRBG_CtrFree
    };

    if (ciphMeth == NULL || keyLen == 0 || seedMeth == NULL) {
        return NULL;
    }

    DRBG_Ctx *drbg = (DRBG_Ctx*)BSL_SAL_Malloc(sizeof(DRBG_Ctx) + sizeof(DRBG_CtrCtx) + ciphMeth->ctxSize);
    if (drbg == NULL) {
        return NULL;
    }
    void *dfCtx = (void*)BSL_SAL_Malloc(ciphMeth->ctxSize); // have 2 contexts
    if (dfCtx == NULL) {
        BSL_SAL_FREE(drbg);
        return NULL;
    }

    DRBG_CtrCtx *ctx = (DRBG_CtrCtx*)(drbg + 1);
    ctx->ctrCtx = (void*)(ctx + 1);
    ctx->dfCtx = dfCtx;

    ctx->ciphMeth = ciphMeth;

    drbg->state = DRBG_STATE_UNINITIALISED;
    drbg->isGm = isGm;
    drbg->reseedInterval = (drbg->isGm) ? HITLS_CRYPTO_RESEED_INTERVAL_GM : DRBG_MAX_RESEED_INTERVAL;
#if defined(HITLS_CRYPTO_DRBG_GM)
    drbg->reseedIntervalTime = (drbg->isGm) ? HITLS_CRYPTO_DRBG_RESEED_TIME_GM : 0;
#endif

    ctx->keyLen = keyLen;
    ctx->seedLen = AES_BLOCK_LEN + keyLen;
    ctx->isUsedDf = isUsedDf;
    drbg->meth = &meth;
    drbg->ctx = ctx;
    drbg->seedMeth = *seedMeth;
    drbg->seedCtx = seedCtx;

    drbg->strength = keyLen * 8;
    drbg->maxRequest = (drbg->isGm) ? DRBG_MAX_REQUEST_SM4 : DRBG_MAX_REQUEST;
    drbg->forkId = BSL_SAL_GetPid();
    // NIST.SP.800-90Ar1, Section 10.3.1 Table 3 defined those initial value.
    if (isUsedDf) {
        // shift rightwards by 3, converting from bit length to byte length
        drbg->entropyRange.min = (drbg->isGm) ? DRBG_CTR_MIN_ENTROPYLEN : keyLen;
        drbg->entropyRange.max = DRBG_MAX_LEN;
        drbg->maxPersLen = DRBG_MAX_LEN;
        drbg->maxAdinLen = DRBG_MAX_LEN;

        // NIST.SP.800-90Ar1, Section 8.6.7 defined, a nonce needs (security_strength/2) bits of entropy at least.
        drbg->nonceRange.min = drbg->entropyRange.min / DRBG_NONCE_FROM_ENTROPY;
        drbg->nonceRange.max = DRBG_MAX_LEN;
    } else {
        drbg->entropyRange.min = ctx->seedLen;
        drbg->entropyRange.max = ctx->seedLen;
        drbg->maxPersLen = ctx->seedLen;
        drbg->maxAdinLen = ctx->seedLen;

        drbg->nonceRange.min = 0;
        drbg->nonceRange.max = 0;
    }

    return drbg;
}
#endif
