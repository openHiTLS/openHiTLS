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
#if defined(HITLS_CRYPTO_GCM) && defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_GHASH)

#include <stdint.h>
#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "eal_cipher_local.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_aes.h"
#include "modes_local.h"
#include "crypt_modes_gcm.h"
#include "crypt_modes_gcm_siv.h"

#define GCM_SIV_NONCE_LEN 12u

typedef struct {
    uint8_t *ptr;
    uint32_t len;
    uint32_t cap;
} GcmSivOutSeg;

struct ModesGcmSivCtx {
    int32_t algId;
    CRYPT_AES_Key masterAes;
    uint8_t masterKey[32];
    uint32_t masterKeyLen;
    uint8_t nonce[GCM_SIV_NONCE_LEN];
    uint8_t *aadBuf;
    uint32_t aadLen;
    uint8_t *msgBuf;
    uint32_t msgLen;
    GcmSivOutSeg *outSegs;
    uint32_t outSegCnt;
    uint32_t outSegCap;
    uint8_t tagLen;
    bool enc;
    uint8_t recvTag[GCM_BLOCKSIZE];
    bool hasRecvTag;
};

static void FreeOutSegs(struct ModesGcmSivCtx *ctx)
{
    if (ctx->outSegs != NULL) {
        uint32_t segBytes = ctx->outSegCap * (uint32_t)sizeof(GcmSivOutSeg);
        BSL_SAL_ClearFree(ctx->outSegs, segBytes);
        ctx->outSegs = NULL;
    }
    ctx->outSegCnt = 0;
    ctx->outSegCap = 0;
}

static int32_t RememberOutSeg(struct ModesGcmSivCtx *ctx, uint8_t *out, uint32_t len, uint32_t cap)
{
    if (len != 0 && out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (len != 0 && (ctx->enc || ctx->hasRecvTag) && len > cap) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }
    if (len == 0) {
        if (out == NULL) {
            return CRYPT_SUCCESS;
        }
        if (ctx->outSegCnt > 0) {
            return CRYPT_SUCCESS;
        }
    }
    if (ctx->outSegCnt == ctx->outSegCap) {
        uint32_t ncap = (ctx->outSegCap == 0) ? 4u : ctx->outSegCap * 2u;
        uint32_t oldBytes = ctx->outSegCap * (uint32_t)sizeof(GcmSivOutSeg);
        uint32_t newBytes = ncap * (uint32_t)sizeof(GcmSivOutSeg);
        GcmSivOutSeg *n = (GcmSivOutSeg *)BSL_SAL_Realloc(ctx->outSegs, newBytes, oldBytes);
        if (n == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ctx->outSegs = n;
        ctx->outSegCap = ncap;
    }
    ctx->outSegs[ctx->outSegCnt].ptr = out;
    ctx->outSegs[ctx->outSegCnt].len = len;
    ctx->outSegs[ctx->outSegCnt].cap = cap;
    ctx->outSegCnt++;
    return CRYPT_SUCCESS;
}

static int32_t ValidateOutSegs(struct ModesGcmSivCtx *ctx, uint32_t totalLen)
{
    uint32_t sum = 0;
    uint32_t i;
    for (i = 0; i < ctx->outSegCnt; i++) {
        sum += ctx->outSegs[i].len;
    }
    if (sum != totalLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    if (totalLen > 0 && ctx->outSegCnt == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    return CRYPT_SUCCESS;
}

static int32_t EmitCiphertextToOutput(struct ModesGcmSivCtx *ctx, const uint8_t *src, uint32_t totalLen)
{
    uint32_t i;
    uint32_t off = 0;
    int32_t ret = ValidateOutSegs(ctx, totalLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    for (i = 0; i < ctx->outSegCnt; i++) {
        if (ctx->outSegs[i].len > 0) {
            if (ctx->outSegs[i].len > ctx->outSegs[i].cap) {
                BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
                return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
            }
            memcpy(ctx->outSegs[i].ptr, src + off, ctx->outSegs[i].len);
            off += ctx->outSegs[i].len;
        }
    }
    return CRYPT_SUCCESS;
}

static void ByteReverseBlock(uint8_t b[GCM_BLOCKSIZE])
{
    uint32_t i;
    for (i = 0; i < 8; i++) {
        uint8_t t = b[i];
        b[i] = b[GCM_BLOCKSIZE - 1 - i];
        b[GCM_BLOCKSIZE - 1 - i] = t;
    }
}

/* GHASH multiply-by-x; same convention as mbedTLS / RFC 8452 Appendix A examples */
static void MulXGhash(uint8_t block[GCM_BLOCKSIZE])
{
    uint8_t carry = block[15] & 0x01u;
    uint32_t i;
    for (i = 15; i > 0; i--) {
        block[i] = (uint8_t)(block[i] >> 1) | (uint8_t)(block[i - 1] << 7);
    }
    block[0] = (uint8_t)(block[0] >> 1);
    if (carry != 0) {
        block[0] ^= 0xe1u;
    }
}

static int32_t Polyval(const uint8_t authKey[GCM_BLOCKSIZE], const uint8_t *data, uint32_t dataLen,
    uint8_t polyOut[GCM_BLOCKSIZE])
{
    uint8_t h[GCM_BLOCKSIZE];
    MODES_GCM_GF128 hTable[16];
    memcpy(h, authKey, GCM_BLOCKSIZE);
    ByteReverseBlock(h);
    MulXGhash(h);
    GcmTableGen4bit(h, hTable);
    memset(polyOut, 0, GCM_BLOCKSIZE);
    uint32_t off = 0;
    while (off < dataLen) {
        uint8_t x[GCM_BLOCKSIZE];
        memcpy(x, data + off, GCM_BLOCKSIZE);
        ByteReverseBlock(x);
        GcmHashMultiBlock(polyOut, hTable, x, GCM_BLOCKSIZE);
        off += GCM_BLOCKSIZE;
    }
    ByteReverseBlock(polyOut);
    (void)BSL_SAL_CleanseData(h, sizeof(h));
    (void)BSL_SAL_CleanseData(hTable, sizeof(hTable));
    return CRYPT_SUCCESS;
}

static int32_t DeriveKeys(struct ModesGcmSivCtx *ctx, uint8_t authKey[GCM_BLOCKSIZE], uint8_t encKey[32],
    uint32_t *encKeyLen)
{
    uint32_t nblocks = (ctx->masterKeyLen == 16) ? 4u : 6u;
    uint8_t block[16];
    uint8_t blkOut[6][16];
    uint32_t c;
    int32_t ret = CRYPT_SUCCESS;

    for (c = 0; c < nblocks; c++) {
        PUT_UINT32_LE(c, block, 0);
        memcpy(block + 4, ctx->nonce, GCM_SIV_NONCE_LEN);
        ret = CRYPT_AES_Encrypt(&ctx->masterAes, block, blkOut[c], GCM_BLOCKSIZE);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto cleanup;
        }
    }
    memcpy(authKey, blkOut[0], 8);
    memcpy(authKey + 8, blkOut[1], 8);
    memcpy(encKey, blkOut[2], 8);
    memcpy(encKey + 8, blkOut[3], 8);
    *encKeyLen = 16;
    if (ctx->masterKeyLen == 32) {
        memcpy(encKey + 16, blkOut[4], 8);
        memcpy(encKey + 24, blkOut[5], 8);
        *encKeyLen = 32;
    }

cleanup:
    (void)BSL_SAL_CleanseData(block, sizeof(block));
    (void)BSL_SAL_CleanseData(blkOut, sizeof(blkOut));
    return ret;
}

static int32_t AesCtrGcmSiv(const uint8_t encKey[32], uint32_t encKeyLen, const uint8_t initialCtr[GCM_BLOCKSIZE],
    const uint8_t *in, uint32_t len, uint8_t *out)
{
    CRYPT_AES_Key aes;
    int32_t ret;
    if (encKeyLen == 16) {
        ret = CRYPT_AES_SetEncryptKey128(&aes, encKey, 16);
    } else {
        ret = CRYPT_AES_SetEncryptKey256(&aes, encKey, 32);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t ctr[GCM_BLOCKSIZE];
    memcpy(ctr, initialCtr, GCM_BLOCKSIZE);
    uint32_t pos = 0;
    while (pos < len) {
        uint8_t ks[GCM_BLOCKSIZE];
        ret = CRYPT_AES_Encrypt(&aes, ctr, ks, GCM_BLOCKSIZE);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            (void)BSL_SAL_CleanseData(ks, sizeof(ks));
            (void)BSL_SAL_CleanseData(ctr, sizeof(ctr));
            (void)CRYPT_AES_Clean(&aes);
            return ret;
        }
        uint32_t chunk = len - pos;
        if (chunk > GCM_BLOCKSIZE) {
            chunk = GCM_BLOCKSIZE;
        }
        uint32_t j;
        for (j = 0; j < chunk; j++) {
            out[pos + j] = in[pos + j] ^ ks[j];
        }
        (void)BSL_SAL_CleanseData(ks, sizeof(ks));
        uint32_t c = GET_UINT32_LE(ctr, 0);
        c++;
        PUT_UINT32_LE(c, ctr, 0);
        pos += chunk;
    }
    (void)BSL_SAL_CleanseData(ctr, sizeof(ctr));
    (void)CRYPT_AES_Clean(&aes);
    return CRYPT_SUCCESS;
}

static int32_t Pad16LenSafe(uint32_t len, uint32_t *out)
{
    if (len > UINT32_MAX - (GCM_BLOCKSIZE - 1u)) {
        return CRYPT_MODES_CRYPTLEN_OVERFLOW;
    }
    *out = (len + GCM_BLOCKSIZE - 1u) & ~(GCM_BLOCKSIZE - 1u);
    return CRYPT_SUCCESS;
}

static int32_t BuildPolyInput(struct ModesGcmSivCtx *ctx, const uint8_t *plaintext, uint32_t ptLen,
    uint8_t **polyBuf, uint32_t *polyLen)
{
    uint32_t padAad;
    uint32_t padPt;
    if (Pad16LenSafe(ctx->aadLen, &padAad) != CRYPT_SUCCESS || Pad16LenSafe(ptLen, &padPt) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
        return CRYPT_MODES_CRYPTLEN_OVERFLOW;
    }
    if (padAad > UINT32_MAX - padPt) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
        return CRYPT_MODES_CRYPTLEN_OVERFLOW;
    }
    uint32_t padSum = padAad + padPt;
    if (padSum > UINT32_MAX - GCM_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
        return CRYPT_MODES_CRYPTLEN_OVERFLOW;
    }
    uint32_t total = padSum + GCM_BLOCKSIZE;
    uint8_t *buf = BSL_SAL_Malloc(total);
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memset(buf, 0, total);
    if (ctx->aadLen > 0 && ctx->aadBuf != NULL) {
        memcpy(buf, ctx->aadBuf, ctx->aadLen);
    }
    if (ptLen > 0 && plaintext != NULL) {
        memcpy(buf + padAad, plaintext, ptLen);
    }
    uint8_t *lb = buf + padAad + padPt;
    PUT_UINT64_LE((uint64_t)ctx->aadLen * 8u, lb, 0);
    PUT_UINT64_LE((uint64_t)ptLen * 8u, lb, 8);
    *polyBuf = buf;
    *polyLen = total;
    return CRYPT_SUCCESS;
}

static int32_t TagFromPolyval(const uint8_t encKey[32], uint32_t encKeyLen, const uint8_t polyOut[GCM_BLOCKSIZE],
    const uint8_t nonce[GCM_SIV_NONCE_LEN], uint8_t tag[GCM_BLOCKSIZE])
{
    uint8_t s[GCM_BLOCKSIZE];
    memcpy(s, polyOut, GCM_BLOCKSIZE);
    uint32_t i;
    for (i = 0; i < GCM_SIV_NONCE_LEN; i++) {
        s[i] ^= nonce[i];
    }
    s[15] &= 0x7fu;
    CRYPT_AES_Key aes;
    int32_t ret;
    if (encKeyLen == 16) {
        ret = CRYPT_AES_SetEncryptKey128(&aes, encKey, 16);
    } else {
        ret = CRYPT_AES_SetEncryptKey256(&aes, encKey, 32);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        (void)BSL_SAL_CleanseData(s, sizeof(s));
        return ret;
    }
    ret = CRYPT_AES_Encrypt(&aes, s, tag, GCM_BLOCKSIZE);
    (void)CRYPT_AES_Clean(&aes);
    (void)BSL_SAL_CleanseData(s, sizeof(s));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t CstTimeTagCmp(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint8_t d = 0;
    uint32_t i;
    for (i = 0; i < len; i++) {
        d |= (uint8_t)(a[i] ^ b[i]);
    }
    return (d == 0) ? CRYPT_SUCCESS : CRYPT_MODES_TAG_ERROR;
}

static int32_t GcmSivEncryptFinish(struct ModesGcmSivCtx *ctx, uint8_t *tagBuf, uint32_t tagLen)
{
    if (tagLen != ctx->tagLen || tagBuf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_TAGLEN_ERROR);
        return CRYPT_MODES_TAGLEN_ERROR;
    }
    int32_t vret = ValidateOutSegs(ctx, ctx->msgLen);
    if (vret != CRYPT_SUCCESS) {
        return vret;
    }
    uint8_t authKey[16];
    uint8_t encKey[32];
    uint32_t encKeyLen = 0;
    int32_t ret = DeriveKeys(ctx, authKey, encKey, &encKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint8_t *polyIn = NULL;
    uint32_t polyInLen = 0;
    ret = BuildPolyInput(ctx, ctx->msgBuf, ctx->msgLen, &polyIn, &polyInLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint8_t polyOut[GCM_BLOCKSIZE];
    ret = Polyval(authKey, polyIn, polyInLen, polyOut);
    if (polyIn != NULL) {
        BSL_SAL_ClearFree(polyIn, polyInLen);
        polyIn = NULL;
    }
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint8_t tag[GCM_BLOCKSIZE];
    ret = TagFromPolyval(encKey, encKeyLen, polyOut, ctx->nonce, tag);
    if (ret != CRYPT_SUCCESS) {
        (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
        (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
        return ret;
    }
    uint8_t ctr[GCM_BLOCKSIZE];
    memcpy(ctr, tag, GCM_BLOCKSIZE);
    ctr[15] |= 0x80u;
    if (ctx->msgLen > 0) {
        if (ctx->outSegCnt == 1 && ctx->outSegs[0].len == ctx->msgLen) {
            if (ctx->outSegs[0].cap < ctx->msgLen) {
                (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
                (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
                BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
                return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
            }
            ret = AesCtrGcmSiv(encKey, encKeyLen, ctr, ctx->msgBuf, ctx->msgLen, ctx->outSegs[0].ptr);
        } else {
            uint8_t *tmp = BSL_SAL_Malloc(ctx->msgLen);
            if (tmp == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
                (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
                return CRYPT_MEM_ALLOC_FAIL;
            }
            ret = AesCtrGcmSiv(encKey, encKeyLen, ctr, ctx->msgBuf, ctx->msgLen, tmp);
            if (ret == CRYPT_SUCCESS) {
                ret = EmitCiphertextToOutput(ctx, tmp, ctx->msgLen);
            }
            (void)BSL_SAL_CleanseData(tmp, ctx->msgLen);
            BSL_SAL_Free(tmp);
        }
    }
    memcpy(tagBuf, tag, ctx->tagLen);
    (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
    (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
    return ret;
}

/*
 * Decrypt Update records each segment length as that Update's input size (ciphertext || tag).
 * The last GCM_BLOCKSIZE bytes of msgBuf are the tag; plaintext length is msgLen - GCM_BLOCKSIZE.
 * Rewrite segment lengths to the overlap with [0, ctEnd) so sums match ctLen (SET_TAG path skips).
 */
static void GcmSivFinalizeDecryptOutSegs(struct ModesGcmSivCtx *ctx)
{
    uint32_t ctEnd;
    uint32_t pos = 0;
    uint32_t i;
    if (ctx->hasRecvTag || ctx->msgLen < GCM_BLOCKSIZE || ctx->outSegCnt == 0) {
        return;
    }
    ctEnd = ctx->msgLen - GCM_BLOCKSIZE;
    for (i = 0; i < ctx->outSegCnt; i++) {
        uint32_t segStart = pos;
        uint32_t origLen = ctx->outSegs[i].len;
        uint32_t segEnd = pos + origLen;
        uint32_t pe = segEnd < ctEnd ? segEnd : ctEnd;
        if (segStart >= pe) {
            ctx->outSegs[i].len = 0;
        } else {
            ctx->outSegs[i].len = pe - segStart;
        }
        pos = segEnd;
    }
}

static int32_t GcmSivDecryptFinish(struct ModesGcmSivCtx *ctx, uint8_t *tagOut, uint32_t tagLen)
{
    if (tagLen != ctx->tagLen || tagOut == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_TAGLEN_ERROR);
        return CRYPT_MODES_TAGLEN_ERROR;
    }
    const uint8_t *recvTagPtr;
    uint32_t ctLen;
    if (ctx->hasRecvTag) {
        ctLen = ctx->msgLen;
        recvTagPtr = ctx->recvTag;
    } else {
        if (ctx->msgLen < GCM_BLOCKSIZE) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        ctLen = ctx->msgLen - GCM_BLOCKSIZE;
        recvTagPtr = ctx->msgBuf + ctLen;
    }
    GcmSivFinalizeDecryptOutSegs(ctx);
    int32_t vret = ValidateOutSegs(ctx, ctLen);
    if (vret != CRYPT_SUCCESS) {
        return vret;
    }
    uint8_t authKey[16];
    uint8_t encKey[32];
    uint32_t encKeyLen = 0;
    int32_t ret = DeriveKeys(ctx, authKey, encKey, &encKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint8_t ctr[GCM_BLOCKSIZE];
    memcpy(ctr, recvTagPtr, GCM_BLOCKSIZE);
    ctr[15] |= 0x80u;
    uint8_t *plain = NULL;
    if (ctLen > 0) {
        plain = BSL_SAL_Malloc(ctLen);
        if (plain == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
            (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ret = AesCtrGcmSiv(encKey, encKeyLen, ctr, ctx->msgBuf, ctLen, plain);
    } else {
        ret = CRYPT_SUCCESS;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(plain, ctLen);
        (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
        (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
        return ret;
    }
    uint8_t *polyIn = NULL;
    uint32_t polyInLen = 0;
    ret = BuildPolyInput(ctx, plain, ctLen, &polyIn, &polyInLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(plain, ctLen);
        (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
        (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
        return ret;
    }
    uint8_t polyOut[GCM_BLOCKSIZE];
    ret = Polyval(authKey, polyIn, polyInLen, polyOut);
    if (polyIn != NULL) {
        BSL_SAL_ClearFree(polyIn, polyInLen);
        polyIn = NULL;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(plain, ctLen);
        (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
        (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
        return ret;
    }
    uint8_t expectedTag[GCM_BLOCKSIZE];
    ret = TagFromPolyval(encKey, encKeyLen, polyOut, ctx->nonce, expectedTag);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(plain, ctLen);
        (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
        (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
        return ret;
    }
    ret = CstTimeTagCmp(expectedTag, recvTagPtr, GCM_BLOCKSIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(plain, ctLen);
        (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
        (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
        (void)BSL_SAL_CleanseData(expectedTag, sizeof(expectedTag));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ctLen > 0 && plain != NULL) {
        ret = EmitCiphertextToOutput(ctx, plain, ctLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_ClearFree(plain, ctLen);
            (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
            (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
            return ret;
        }
    }
    if (plain != NULL) {
        BSL_SAL_ClearFree(plain, ctLen);
    }
    memcpy(tagOut, expectedTag, ctx->tagLen);
    (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
    (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
    (void)BSL_SAL_CleanseData(expectedTag, sizeof(expectedTag));
    return CRYPT_SUCCESS;
}

MODES_GCM_SIV_Ctx *MODES_GCM_SIV_NewCtx(int32_t algId)
{
    if (algId != CRYPT_CIPHER_AES128_GCM_SIV && algId != CRYPT_CIPHER_AES256_GCM_SIV) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    struct ModesGcmSivCtx *ctx = BSL_SAL_Calloc(1, sizeof(struct ModesGcmSivCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->algId = algId;
    ctx->tagLen = GCM_BLOCKSIZE;
    return ctx;
}

MODES_GCM_SIV_Ctx *MODES_GCM_SIV_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    return MODES_GCM_SIV_NewCtx(algId);
}

int32_t MODES_GCM_SIV_InitCtxEx(struct ModesGcmSivCtx *modeCtx, const uint8_t *key, uint32_t keyLen,
    const uint8_t *iv, uint32_t ivLen, void *param, bool enc)
{
    (void)param;
    if (modeCtx == NULL || key == NULL || (ivLen > 0 && iv == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ivLen != GCM_SIV_NONCE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_IVLEN_ERROR);
        return CRYPT_MODES_IVLEN_ERROR;
    }
    if ((modeCtx->algId == CRYPT_CIPHER_AES128_GCM_SIV && keyLen != 16) ||
        (modeCtx->algId == CRYPT_CIPHER_AES256_GCM_SIV && keyLen != 32)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_ERR_KEYLEN);
        return CRYPT_MODES_ERR_KEYLEN;
    }
    int32_t ret;
    memcpy(modeCtx->masterKey, key, keyLen);
    if (keyLen == 16) {
        ret = CRYPT_AES_SetEncryptKey128(&modeCtx->masterAes, key, keyLen);
    } else {
        ret = CRYPT_AES_SetEncryptKey256(&modeCtx->masterAes, key, keyLen);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    modeCtx->masterKeyLen = keyLen;
    memcpy(modeCtx->nonce, iv, GCM_SIV_NONCE_LEN);
    modeCtx->enc = enc;
    FreeOutSegs(modeCtx);
    if (modeCtx->aadBuf != NULL) {
        BSL_SAL_ClearFree(modeCtx->aadBuf, modeCtx->aadLen);
        modeCtx->aadBuf = NULL;
    }
    modeCtx->aadLen = 0;
    if (modeCtx->msgBuf != NULL) {
        BSL_SAL_ClearFree(modeCtx->msgBuf, modeCtx->msgLen);
        modeCtx->msgBuf = NULL;
    }
    modeCtx->msgLen = 0;
    memset(modeCtx->recvTag, 0, sizeof(modeCtx->recvTag));
    modeCtx->hasRecvTag = false;
    return CRYPT_SUCCESS;
}

int32_t MODES_GCM_SIV_Update(struct ModesGcmSivCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen)
{
    if (modeCtx == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (inLen != 0 && in == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (inLen > 0 && out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (inLen == 0) {
        if (out != NULL && modeCtx->outSegCnt == 0) {
            int32_t r = RememberOutSeg(modeCtx, out, 0, *outLen);
            if (r != CRYPT_SUCCESS) {
                return r;
            }
        }
        *outLen = 0;
        return CRYPT_SUCCESS;
    }
    uint32_t outBufCap = *outLen;
    int32_t r = RememberOutSeg(modeCtx, out, inLen, outBufCap);
    if (r != CRYPT_SUCCESS) {
        return r;
    }
    if (inLen > UINT32_MAX - modeCtx->msgLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
        return CRYPT_MODES_CRYPTLEN_OVERFLOW;
    }
    uint32_t newMsgLen = modeCtx->msgLen + inLen;
    uint8_t *nbuf = BSL_SAL_Malloc(newMsgLen);
    if (nbuf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (modeCtx->msgBuf != NULL && modeCtx->msgLen != 0) {
        memcpy(nbuf, modeCtx->msgBuf, modeCtx->msgLen);
        BSL_SAL_ClearFree(modeCtx->msgBuf, modeCtx->msgLen);
    }
    modeCtx->msgBuf = nbuf;
    memcpy(modeCtx->msgBuf + modeCtx->msgLen, in, inLen);
    modeCtx->msgLen = newMsgLen;
    *outLen = 0;
    return CRYPT_SUCCESS;
}

int32_t MODES_GCM_SIV_Final(MODES_GCM_SIV_Ctx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    (void)out;
    if (modeCtx == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (modeCtx->enc) {
        uint8_t tag[GCM_BLOCKSIZE];
        int32_t ret = GcmSivEncryptFinish(modeCtx, tag, modeCtx->tagLen);
        if (ret == CRYPT_SUCCESS) {
            *outLen = modeCtx->msgLen;
        } else {
            *outLen = 0;
        }
        return ret;
    }

    *outLen = 0;
    uint8_t tag[GCM_BLOCKSIZE];
    return GcmSivDecryptFinish(modeCtx, tag, modeCtx->tagLen);
}

int32_t MODES_GCM_SIV_DeInitCtx(MODES_GCM_SIV_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    (void)CRYPT_AES_Clean(&modeCtx->masterAes);
    (void)BSL_SAL_CleanseData(modeCtx->masterKey, sizeof(modeCtx->masterKey));
    if (modeCtx->aadBuf != NULL) {
        BSL_SAL_ClearFree(modeCtx->aadBuf, modeCtx->aadLen);
        modeCtx->aadBuf = NULL;
    }
    modeCtx->aadLen = 0;
    if (modeCtx->msgBuf != NULL) {
        BSL_SAL_ClearFree(modeCtx->msgBuf, modeCtx->msgLen);
        modeCtx->msgBuf = NULL;
    }
    modeCtx->msgLen = 0;
    FreeOutSegs(modeCtx);
    (void)BSL_SAL_CleanseData(modeCtx->recvTag, sizeof(modeCtx->recvTag));
    modeCtx->hasRecvTag = false;
    return CRYPT_SUCCESS;
}

static int32_t SetRecvTag(struct ModesGcmSivCtx *ctx, const uint8_t *tag, uint32_t len)
{
    if (ctx->enc) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TYPE_ERROR);
        return CRYPT_MODES_CTRL_TYPE_ERROR;
    }
    if (tag == NULL || len != GCM_BLOCKSIZE || len != (uint32_t)ctx->tagLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_TAGLEN_ERROR);
        return CRYPT_MODES_TAGLEN_ERROR;
    }
    memcpy(ctx->recvTag, tag, len);
    ctx->hasRecvTag = true;
    return CRYPT_SUCCESS;
}

static int32_t SetAad(struct ModesGcmSivCtx *ctx, const uint8_t *aad, uint32_t aadLen)
{
    if (aad == NULL && aadLen != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->aadLen != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_AAD_REPEAT_SET_ERROR);
        return CRYPT_MODES_AAD_REPEAT_SET_ERROR;
    }
    if (ctx->msgLen != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_AAD_REPEAT_SET_ERROR);
        return CRYPT_MODES_AAD_REPEAT_SET_ERROR;
    }
    if (aadLen == 0) {
        return CRYPT_SUCCESS;
    }
    uint8_t *buf = BSL_SAL_Malloc(aadLen);
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memcpy(buf, aad, aadLen);
    if (ctx->aadBuf != NULL) {
        BSL_SAL_ClearFree(ctx->aadBuf, ctx->aadLen);
    }
    ctx->aadBuf = buf;
    ctx->aadLen = aadLen;
    return CRYPT_SUCCESS;
}

static int32_t SetNonce(struct ModesGcmSivCtx *ctx, const uint8_t *iv, uint32_t ivLen)
{
    if (iv == NULL || ivLen != GCM_SIV_NONCE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_IVLEN_ERROR);
        return CRYPT_MODES_IVLEN_ERROR;
    }
    memcpy(ctx->nonce, iv, GCM_SIV_NONCE_LEN);
    if (ctx->aadBuf != NULL) {
        BSL_SAL_ClearFree(ctx->aadBuf, ctx->aadLen);
        ctx->aadBuf = NULL;
    }
    ctx->aadLen = 0;
    if (ctx->msgBuf != NULL) {
        BSL_SAL_ClearFree(ctx->msgBuf, ctx->msgLen);
        ctx->msgBuf = NULL;
    }
    ctx->msgLen = 0;
    FreeOutSegs(ctx);
    (void)BSL_SAL_CleanseData(ctx->recvTag, sizeof(ctx->recvTag));
    ctx->hasRecvTag = false;
    return CRYPT_SUCCESS;
}

static int32_t SetTagLen(struct ModesGcmSivCtx *ctx, const uint32_t *val, uint32_t len)
{
    if (val == NULL || len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TAGLEN_ERROR);
        return CRYPT_MODES_CTRL_TAGLEN_ERROR;
    }
    if (*val != GCM_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TAGLEN_ERROR);
        return CRYPT_MODES_CTRL_TAGLEN_ERROR;
    }
    ctx->tagLen = GCM_BLOCKSIZE;
    return CRYPT_SUCCESS;
}

int32_t MODES_GCM_SIV_Ctrl(MODES_GCM_SIV_Ctx *modeCtx, int32_t cmd, void *val, uint32_t len)
{
    if (modeCtx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    struct ModesGcmSivCtx *ctx = modeCtx;
    switch (cmd) {
        case CRYPT_CTRL_SET_IV:
        case CRYPT_CTRL_REINIT_STATUS:
            return SetNonce(ctx, val, len);
        case CRYPT_CTRL_SET_TAGLEN:
            return SetTagLen(ctx, val, len);
        case CRYPT_CTRL_SET_TAG:
            return SetRecvTag(ctx, val, len);
        case CRYPT_CTRL_SET_AAD:
            return SetAad(ctx, val, len);
        case CRYPT_CTRL_GET_TAG:
            if (ctx->enc) {
                return GcmSivEncryptFinish(ctx, val, len);
            }
            return GcmSivDecryptFinish(ctx, val, len);
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(int32_t *)val = 1;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_CTRL_TYPE_ERROR);
            return CRYPT_MODES_CTRL_TYPE_ERROR;
    }
}

void MODES_GCM_SIV_FreeCtx(MODES_GCM_SIV_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return;
    }
    (void)MODES_GCM_SIV_DeInitCtx(modeCtx);
    BSL_SAL_ClearFree(modeCtx, (uint32_t)sizeof(struct ModesGcmSivCtx));
}

MODES_GCM_SIV_Ctx *MODES_GCM_SIV_DupCtx(const MODES_GCM_SIV_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return NULL;
    }
    const struct ModesGcmSivCtx *src = modeCtx;
    struct ModesGcmSivCtx *ctx = BSL_SAL_Dump(src, sizeof(struct ModesGcmSivCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->aadBuf = NULL;
    ctx->msgBuf = NULL;
    ctx->outSegs = NULL;
    ctx->outSegCnt = 0;
    ctx->outSegCap = 0;
    if (src->aadLen > 0 && src->aadBuf != NULL) {
        ctx->aadBuf = BSL_SAL_Dump(src->aadBuf, src->aadLen);
        if (ctx->aadBuf == NULL) {
            goto ERR;
        }
    }
    if (src->msgLen > 0 && src->msgBuf != NULL) {
        ctx->msgBuf = BSL_SAL_Dump(src->msgBuf, src->msgLen);
        if (ctx->msgBuf == NULL) {
            goto ERR;
        }
    }
    return ctx;
ERR:
    if (ctx->aadBuf != NULL) {
        BSL_SAL_ClearFree(ctx->aadBuf, ctx->aadLen);
    }
    BSL_SAL_ClearFree(ctx, (uint32_t)sizeof(struct ModesGcmSivCtx));
    BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
    return NULL;
}

#endif /* HITLS_CRYPTO_GCM && HITLS_CRYPTO_AES && HITLS_CRYPTO_GHASH */