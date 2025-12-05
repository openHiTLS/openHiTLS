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
#ifdef HITLS_CRYPTO_SIPHASH

#include <stdlib.h>
#include <stdio.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_siphash.h"
#include "eal_mac_local.h"

#define SIPHASH_HALF_KEY_SIZE 8
#define BYTE_TO_BITS_RATIO 8
#define LROT_UINT64(num, bits) (uint64_t)(((num) << (bits)) | ((num) >> (64 - (bits))))
#define SIPHASH_SIX_OCTET_TO_BITS ((BYTE_TO_BITS_RATIO) * 6)
#define SIPHASH_FIVE_OCTET_TO_BITS ((BYTE_TO_BITS_RATIO) * 5)
#define SIPHASH_FOUR_OCTET_TO_BITS ((BYTE_TO_BITS_RATIO) * 4)
#define SIPHASH_THREE_OCTET_TO_BITS ((BYTE_TO_BITS_RATIO) * 3)
#define SIPHASH_TWO_OCTET_TO_BITS ((BYTE_TO_BITS_RATIO) * 2)
#define SIPHASH_ONE_OCTET_TO_BITS ((BYTE_TO_BITS_RATIO) * 1)

struct SIPHASH_Ctx {
    uint64_t state0;
    uint64_t state1;
    uint64_t state2;
    uint64_t state3;
    uint16_t compressionRounds;
    uint16_t finalizationRounds;
    uint32_t hashSize;
    uint32_t accInLen;
    uint32_t offset;
    uint8_t remainder[SIPHASH_WORD_SIZE];
};

static inline uint64_t BytesToUint64LittleEndian(const uint8_t key[SIPHASH_WORD_SIZE])
{
    uint64_t ret = 0ULL;
    for (uint32_t i = 0; i < SIPHASH_WORD_SIZE; i++) {
        ret = ret | (((uint64_t)key[i]) << (i * BYTE_TO_BITS_RATIO));
    }
    return ret;
}

static void Uint64ToBytesLittleEndian(uint64_t src, uint8_t out[SIPHASH_WORD_SIZE])
{
    for (uint32_t i = 0; i < SIPHASH_WORD_SIZE; i++) {
        out[i] = (uint8_t)(src >> (i * BYTE_TO_BITS_RATIO));
    }
}

static uint64_t DealLastWord(uint64_t lastWord, const uint8_t *bytes, size_t bytesLen)
{
    uint64_t tmpLastWord = lastWord;
    switch (bytesLen) {
        case 7:
            // Do not need to run break from the case, fall through the switch-case.
            // The remaining 7 bytes are to be processed and shift to left by 6 bytes.
            tmpLastWord |= ((uint64_t)bytes[6]) << SIPHASH_SIX_OCTET_TO_BITS;
            /* fall-through */
        case 6:
            tmpLastWord |= ((uint64_t)bytes[5]) << SIPHASH_FIVE_OCTET_TO_BITS;
            /* fall-through */
        case 5:
            tmpLastWord |= ((uint64_t)bytes[4]) << SIPHASH_FOUR_OCTET_TO_BITS;
            /* fall-through */
        case 4:
            tmpLastWord |= ((uint64_t)bytes[3]) << SIPHASH_THREE_OCTET_TO_BITS;
            /* fall-through */
        case 3:
            tmpLastWord |= ((uint64_t)bytes[2]) << SIPHASH_TWO_OCTET_TO_BITS;
            /* fall-through */
        case 2:
            tmpLastWord |= ((uint64_t)bytes[1]) << SIPHASH_ONE_OCTET_TO_BITS;
            /* fall-through */
        case 1:
            tmpLastWord |= ((uint64_t)bytes[0]);
            /* fall-through */
        default: // case 0
            break;
    }
    return tmpLastWord;
}

static void SiproundOperation(uint64_t *state0, uint64_t *state1, uint64_t *state2, uint64_t *state3)
{
    (*state0) += (*state1);
    (*state1) = LROT_UINT64(*state1, 13);
    (*state1) ^= (*state0);
    (*state0) = LROT_UINT64(*state0, 32);
    (*state2) += (*state3);
    (*state3) = LROT_UINT64(*state3, 16);
    (*state3) ^= (*state2);
    (*state0) += (*state3);
    (*state3) = LROT_UINT64(*state3, 21);
    (*state3) ^= (*state0);
    (*state2) += (*state1);
    (*state1) = LROT_UINT64(*state1, 17);
    (*state1) ^= (*state2);
    (*state2) = LROT_UINT64(*state2, 32);
}

static void UpdateInternalState(uint64_t curWord, CRYPT_SIPHASH_Ctx *ctx, uint16_t rounds)
{
    (ctx->state3) ^= curWord;
    for (uint16_t j = 0; j < rounds; j++) {
        SiproundOperation(&(ctx->state0), &(ctx->state1), &(ctx->state2), &(ctx->state3));
    }
    (ctx->state0) ^= curWord;
}

static int32_t CRYPT_SIPHASH_GetMacLen(const CRYPT_SIPHASH_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    *(uint32_t *)val = ctx->hashSize;
    return CRYPT_SUCCESS;
}

CRYPT_SIPHASH_Ctx *CRYPT_SIPHASH_NewCtx(CRYPT_MAC_AlgId id)
{
    EAL_MacDepMethod macMethod = {0};
    int32_t ret = EAL_MacFindDepMethod(id, NULL, NULL, &macMethod, NULL, false);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }
    CRYPT_SIPHASH_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_SIPHASH_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    const EAL_SiphashMethod *method = macMethod.method.sip;

    uint16_t cRounds = method->compressionRounds;
    uint16_t dRounds = method->finalizationRounds;
    // fill compressionRounds and finalizationRounds
    ctx->compressionRounds = ((cRounds == 0) ? DEFAULT_COMPRESSION_ROUND : cRounds);
    ctx->finalizationRounds = ((dRounds == 0) ? DEFAULT_FINALIZATION_ROUND : dRounds);
    ctx->hashSize = method->hashSize;
    ctx->accInLen = 0;
    ctx->offset = 0;
    return ctx;
}

CRYPT_SIPHASH_Ctx *CRYPT_SIPHASH_NewCtxEx(void *libCtx, CRYPT_MAC_AlgId id)
{
    (void)libCtx;
    return CRYPT_SIPHASH_NewCtx(id);
}

int32_t CRYPT_SIPHASH_Init(CRYPT_SIPHASH_Ctx *ctx, const uint8_t *key, uint32_t keyLen)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // invalid key size
    size_t hashSize = ctx->hashSize;
    if (keyLen != SIPHASH_KEY_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    // invalid digest size
    if (!((hashSize == SIPHASH_MIN_DIGEST_SIZE) || (hashSize == SIPHASH_MAX_DIGEST_SIZE))) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    // split key byte array to two parts: k0, k1
    uint64_t numKey0 = BytesToUint64LittleEndian(key);
    uint64_t numKey1 = BytesToUint64LittleEndian(key + SIPHASH_HALF_KEY_SIZE);

    // fill internal state
    ctx->state0 = numKey0 ^ 0x736f6d6570736575ULL;
    ctx->state1 = numKey1 ^ 0x646f72616e646f6dULL;
    ctx->state2 = numKey0 ^ 0x6c7967656e657261ULL;
    ctx->state3 = numKey1 ^ 0x7465646279746573ULL;
    if (hashSize == SIPHASH_MAX_DIGEST_SIZE) {
        ctx->state1 ^= 0xee;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SIPHASH_InitEx(CRYPT_SIPHASH_Ctx *ctx, const uint8_t *key, uint32_t keyLen, void *param)
{
    (void)param;
    return CRYPT_SIPHASH_Init(ctx, key, keyLen);
}

int32_t CRYPT_SIPHASH_Update(CRYPT_SIPHASH_Ctx *ctx, const uint8_t *in, uint32_t inlen)
{
    if (ctx == NULL || (in == NULL && inlen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (inlen > UINT32_MAX - ctx->accInLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_SIPHASH_INPUT_OVERFLOW);
        return CRYPT_SIPHASH_INPUT_OVERFLOW;
    }
    const uint8_t *tmpIn = in;
    uint32_t tmpInlen = inlen;
    ctx->accInLen += tmpInlen;
    uint64_t curWord = 0;

    if (ctx->offset != 0) {
        size_t emptySpaceLen = SIPHASH_WORD_SIZE - ctx->offset;
        if (tmpInlen < emptySpaceLen) {
            (void)memcpy_s(ctx->remainder + (ctx->offset), tmpInlen, tmpIn, tmpInlen);
            // update offset, emptySpaceLen shrinks
            ctx->offset += tmpInlen;
            return CRYPT_SUCCESS;
        }
        // fill ctx->remainder[SIPHASH_WORD_SIZE - ctx->offset] to ctx->remainder[SIPHASH_WORD_SIZE - 1] using in
        (void)memcpy_s(ctx->remainder + (ctx->offset), emptySpaceLen, tmpIn, emptySpaceLen);
        // update inlen
        tmpInlen -= (uint32_t)emptySpaceLen;
        // consume emptySpaceLen data of in
        tmpIn += emptySpaceLen;
        curWord = BytesToUint64LittleEndian(ctx->remainder);
        (void)UpdateInternalState(curWord, ctx, ctx->compressionRounds);
    }

    size_t remainLen = tmpInlen & (SIPHASH_WORD_SIZE - 1); // inlen mod 8
    const uint8_t *lastWordPos = tmpIn + tmpInlen - remainLen;
    while (tmpIn != lastWordPos) {
        curWord = BytesToUint64LittleEndian(tmpIn);
        (void)UpdateInternalState(curWord, ctx, ctx->compressionRounds);
        tmpIn += SIPHASH_WORD_SIZE;
    }
    if (remainLen > 0) {
        (void)memcpy_s(ctx->remainder, remainLen, lastWordPos, remainLen);
    }
    ctx->offset = (uint32_t)remainLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SIPHASH_Final(CRYPT_SIPHASH_Ctx *ctx, uint8_t *out, uint32_t *outlen)
{
    if (ctx == NULL || out == NULL || outlen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (*outlen < ctx->hashSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_SIPHASH_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_SIPHASH_OUT_BUFF_LEN_NOT_ENOUGH;
    }
    *outlen = ctx->hashSize;

    uint64_t mLen = ctx->accInLen;  // message length
    uint64_t tmpLastWord = mLen << 56; // put (mLen mod 256) at high address
    size_t remainLen = ctx->offset;
    uint64_t curWord = DealLastWord(tmpLastWord, ctx->remainder, remainLen);
    (void)UpdateInternalState(curWord, ctx, ctx->compressionRounds);

    if (*outlen == SIPHASH_MIN_DIGEST_SIZE) {
        (ctx->state2) ^= 0xff;
    } else {
        (ctx->state2) ^= 0xee;
    }
    for (uint16_t j = 0; j < ctx->finalizationRounds; j++) {
        (void)SiproundOperation(&(ctx->state0), &(ctx->state1), &(ctx->state2), &(ctx->state3));
    }
    uint64_t state = (ctx->state0) ^ (ctx->state1) ^ (ctx->state2) ^ (ctx->state3);
    (void)Uint64ToBytesLittleEndian(state, out);
    if (*outlen == SIPHASH_MIN_DIGEST_SIZE) {
        return CRYPT_SUCCESS;
    }
    (ctx->state1) ^= 0xdd;
    for (uint16_t j = 0; j < ctx->finalizationRounds; j++) {
        (void)SiproundOperation(&(ctx->state0), &(ctx->state1), &(ctx->state2), &(ctx->state3));
    }
    state = (ctx->state0) ^ (ctx->state1) ^ (ctx->state2) ^ (ctx->state3);
    (void)Uint64ToBytesLittleEndian(state, out + SIPHASH_WORD_SIZE);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SIPHASH_Reinit(CRYPT_SIPHASH_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ctx->state0 = 0;
    ctx->state1 = 0;
    ctx->state2 = 0;
    ctx->state3 = 0;
    ctx->accInLen = 0;
    ctx->offset = 0;
    (void)memset_s(ctx->remainder, SIPHASH_WORD_SIZE, 0, SIPHASH_WORD_SIZE);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SIPHASH_Deinit(CRYPT_SIPHASH_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SIPHASH_Ctrl(CRYPT_SIPHASH_Ctx *ctx, uint32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GET_MACLEN:
            return CRYPT_SIPHASH_GetMacLen(ctx, val, len);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_SIPHASH_ERR_UNSUPPORTED_CTRL_OPTION);
    return CRYPT_SIPHASH_ERR_UNSUPPORTED_CTRL_OPTION;
}

void CRYPT_SIPHASH_FreeCtx(CRYPT_SIPHASH_Ctx *ctx)
{
    if (ctx != NULL) {
        BSL_SAL_Free(ctx);
    }
}
#endif /* HITLS_CRYPTO_SIPHASH */
