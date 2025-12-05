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
#ifdef HITLS_CRYPTO_DRBG_HASH
#include <stdint.h>
#include <stdlib.h>
#include <securec.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_local_types.h"
#include "crypt_utils.h"
#include "crypt_types.h"
#include "drbg_local.h"

#define DRBG_HASH_MAX_SEEDLEN  (111)

typedef enum {
    DRBG_SHA1MDSIZE = 20,
    DRBG_SHA224MDSIZE = 28,
    DRBG_SHA256MDSIZE = 32,
    DRBG_SHA384MDSIZE = 48,
    DRBG_SHA512MDSIZE = 64,
    DRBG_SM3MDSIZE = 32,
} DRBG_MdSize;

typedef struct {
    uint8_t v[DRBG_HASH_MAX_SEEDLEN];
    uint8_t c[DRBG_HASH_MAX_SEEDLEN];
    uint32_t seedLen;
    const EAL_MdMethod *md;
    void *mdCtx;
} DRBG_HashCtx;

// This function performs the ctx->V += xxx operation.
static void DRBG_HashAddV(uint8_t *v, uint32_t vLen, uint8_t *src, uint32_t srcLen)
{
    uint8_t *d = v + vLen - 1;
    uint8_t *s = src + srcLen - 1;
    uint8_t c = 0;
    uint32_t r;

    while (s >= src) {
        r = (uint32_t)(*d) + (*s) + c;
        *d = (uint8_t)(r & 0xff);
        c = (r > 0xff) ? 1 : 0;
        d--;
        s--;
    }

    while (d >= v && c > 0) {
        r = (uint32_t)(*d) + c;
        *d = (uint8_t)(r & 0xff);
        c = (r > 0xff) ? 1 : 0;
        d--;
    }
}

static int32_t DRBG_UpdateDataInHashDf(DRBG_HashCtx *ctx,
                                       const CRYPT_Data *in1, const CRYPT_Data *in2,
                                       const CRYPT_Data *in3, const CRYPT_Data *in4)
{
    const EAL_MdMethod *meth = ctx->md;
    void *mdCtx = ctx->mdCtx;
    int32_t ret = CRYPT_SUCCESS;

    if (!CRYPT_IsDataNull(in1)) {
        ret = meth->update(mdCtx, in1->data, in1->len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    if (!CRYPT_IsDataNull(in2)) {
        ret = meth->update(mdCtx, in2->data, in2->len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    if (!CRYPT_IsDataNull(in3)) {
        ret = meth->update(mdCtx, in3->data, in3->len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    if (!CRYPT_IsDataNull(in4)) {
        ret = meth->update(mdCtx, in4->data, in4->len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
    }

    return ret;
}

static void DRBG_HashDfValuesAssig(uint8_t values[5], uint32_t len)
{
    // The value of values is the same as that of counter || no_of_bits_to_return in Hash_df Process
    // in section 10.3.1 in NIST 800-90a.
    values[0] = 0x1;
    // len is shifted leftward by 3, then byte-to-bit. Shift rightwards by 24 bits to get the highest 8 bits.
    values[1] = (uint8_t)(((len << 3) >> 24) & 0xff);
    // 2nd, len is shifted leftward by 3, then byte-to-bit. Shift rightwards by 16 bits to get the second 8 bits.
    values[2] = (uint8_t)(((len << 3) >> 16) & 0xff);
    // 3rd, len is shifted leftward by 3, then byte-to-bit. Shift rightwards by 8 bits to get the third 8 bits.
    values[3] = (uint8_t)(((len << 3) >> 8) & 0xff);
    values[4] = (uint8_t)((len << 3) & 0xff);           // 4th, len is shifted leftward by 3, then byte-to-bit.
}

static int32_t DRBG_HashDf(DRBG_HashCtx *ctx, uint8_t *out, uint32_t outLen,  const CRYPT_Data *in1,
    const CRYPT_Data *in2, const CRYPT_Data *in3, const CRYPT_Data *in4)
{
    const EAL_MdMethod *meth = ctx->md;
    void *mdCtx = ctx->mdCtx;
    uint32_t mdSize = meth->mdSize;
    uint8_t *buf = out;
    uint32_t len = outLen;
    int32_t ret;
    // The temp is the same as that of counter || no_of_bits_to_return in Hash_df Process
    // in section 10.3.1 in NIST 800-90a.
    uint8_t temp[5];
    // len = floor(no_of_bits_to_return / outlen)
    DRBG_HashDfValuesAssig(temp, len);

    do {
        // temp = temp || Hash (counter || no_of_bits_to_return || input_string).
        if ((ret = meth->init(mdCtx, NULL)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        // 5 indicates the maximum length of temp. For details, see the temp statement.
        if ((ret = meth->update(mdCtx, temp, 5)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }

        if ((ret = DRBG_UpdateDataInHashDf(ctx, in1, in2, in3, in4)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }

        uint8_t tmpOut[DRBG_HASH_MAX_MDSIZE];
        uint32_t tmpOutLen = DRBG_HASH_MAX_MDSIZE;
        if (len < mdSize) {
            if ((ret = meth->final(mdCtx, tmpOut, &tmpOutLen)) != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                goto EXIT;
            }
            // tmpOutLen is the maximum supported MD length,
            // and len is the actual length, which must be smaller than tmpOutLen.
            // Only the len length needs to be truncated as the output.
            (void)memcpy_s(buf, len, tmpOut, len);
            break;
        }
        if ((ret = meth->final(mdCtx, buf, &tmpOutLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }

        buf += mdSize;
        len -= mdSize;
        temp[0]++;
    } while (len > 0);

EXIT:
    meth->deinit(mdCtx);
    return ret;
}

static int32_t DRBG_Hashgen(DRBG_HashCtx *ctx, uint8_t *out, uint32_t outLen)
{
    uint8_t data[DRBG_HASH_MAX_SEEDLEN];
    const EAL_MdMethod *md = ctx->md;
    void *mdCtx = ctx->mdCtx;
    int32_t ret = CRYPT_SUCCESS;
    uint32_t mdSize = md->mdSize;
    uint32_t tmpLen = mdSize;
    uint32_t len = outLen;
    uint8_t *buf = out;

    // The length of the V array is the longest seedLen. Therefore, there is no failure.
    (void)memcpy_s(data, sizeof(data), ctx->v, ctx->seedLen);

    while (len > 0) {
        uint8_t n = 1;
        if ((ret = md->init(mdCtx, NULL)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        if ((ret = md->update(mdCtx, data, ctx->seedLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }

        if (len >= mdSize) {
            if ((ret = md->final(mdCtx, buf, &tmpLen)) != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                goto EXIT;
            }
        } else {
            uint8_t temp[DRBG_HASH_MAX_SEEDLEN];
            uint32_t tempLen = DRBG_HASH_MAX_SEEDLEN;
            if ((ret = md->final(mdCtx, temp, &tempLen)) != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                goto EXIT;
            }

            (void)memcpy_s(buf, len, temp, len);
            break;
        }
        buf += mdSize;
        len -= mdSize;

        DRBG_HashAddV(data, ctx->seedLen, &n, 1);
    }

EXIT:
    // Clear MD data.
    md->deinit(mdCtx);
    return ret;
}

int32_t DRBG_HashInstantiate(DRBG_Ctx *drbg, const CRYPT_Data *entropy, const CRYPT_Data *nonce, const CRYPT_Data *pers)
{
    DRBG_HashCtx *ctx = (DRBG_HashCtx*)drbg->ctx;
    CRYPT_Data seed = {ctx->v, (uint32_t)(ctx->seedLen)};
    uint8_t c = 0;
    CRYPT_Data temp = {&c, 1};

    /**
    1. seed_material = entropy || nonce || pers
    2. seed = Hash_df(seed_material)
    3. V = seed
    4. C = Hash_df(0x00 || V)
    */
    int32_t ret = DRBG_HashDf(ctx, ctx->v, ctx->seedLen, entropy, nonce, pers, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = DRBG_HashDf(ctx, ctx->c, ctx->seedLen, &temp, &seed, NULL, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t DRBG_HashAdinInHashGenerate(DRBG_HashCtx *ctx, const CRYPT_Data *adin)
{
    void *mdCtx = ctx->mdCtx;
    const EAL_MdMethod *md = ctx->md;
    uint32_t mdSize = md->mdSize;
    int32_t ret;
    uint8_t temp = 0x2;
    uint8_t w[DRBG_HASH_MAX_MDSIZE];
    uint32_t wLen = DRBG_HASH_MAX_MDSIZE;

    RETURN_RET_IF_ERR(md->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(md->update(mdCtx, &temp, 1), ret);
    GOTO_ERR_IF(md->update(mdCtx, ctx->v, ctx->seedLen), ret);
    GOTO_ERR_IF(md->update(mdCtx, adin->data, adin->len), ret);
    GOTO_ERR_IF(md->final(mdCtx, w, &wLen), ret);

    DRBG_HashAddV(ctx->v, ctx->seedLen, w, mdSize);

ERR:
    // Clear MD data.
    md->deinit(mdCtx);
    return ret;
}

int32_t DRBG_HashGenerate(DRBG_Ctx *drbg, uint8_t *out, uint32_t outLen, const CRYPT_Data *adin)
{
    DRBG_HashCtx *ctx = (DRBG_HashCtx*)drbg->ctx;
    const EAL_MdMethod *md = ctx->md;
    void *mdCtx = ctx->mdCtx;
    uint32_t mdSize = md->mdSize;
    uint8_t h[DRBG_HASH_MAX_MDSIZE];
    uint32_t len = outLen;
    int32_t ret;
    uint32_t reseedCtrBe;

    /* if adin :
            w = HASH(0x02 || V || adin)
            V = (V + w) mod 2^seedLen
    */
    if (!CRYPT_IsDataNull(adin)) {
        ret = DRBG_HashAdinInHashGenerate(ctx, adin);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    // Hashgen(V, out, len)
    ret = DRBG_Hashgen(ctx, out, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // H = HASH(0x03 || V)
    uint8_t temp = 0x3;

    RETURN_RET_IF_ERR(md->init(mdCtx, NULL), ret);

    GOTO_ERR_IF(md->update(mdCtx, &temp, 1), ret);
    GOTO_ERR_IF(md->update(mdCtx, ctx->v, ctx->seedLen), ret);
    GOTO_ERR_IF(md->final(mdCtx, h, &mdSize), ret);

    // V = (V + H + C + reseed_counter) mod 2^seedlen
    DRBG_HashAddV(ctx->v, ctx->seedLen, h, mdSize);
    DRBG_HashAddV(ctx->v, ctx->seedLen, ctx->c, ctx->seedLen);
    reseedCtrBe = CRYPT_HTONL((uint32_t)(drbg->reseedCtr));
    DRBG_HashAddV(ctx->v, ctx->seedLen, (uint8_t*)&reseedCtrBe, sizeof(reseedCtrBe));

ERR:
    // Clear MD data.
    md->deinit(mdCtx);
    return ret;
}

int32_t DRBG_HashReseed(DRBG_Ctx *drbg, const CRYPT_Data *entropy, const CRYPT_Data *adin)
{
    int32_t ret;
    DRBG_HashCtx *ctx = (DRBG_HashCtx*)drbg->ctx;
    CRYPT_Data v = {ctx->v, ctx->seedLen};
    uint8_t c = 0x1;
    CRYPT_Data temp = {&c, 1};

    /**
    seed_material = 0x01 || V || entropy_input || additional_input.
    seed = Hash_Df(seed_material) // The memory of C is reused.
    V = seed
    C = Hash_Df(0x00 || V)
    */
    if (drbg->isGm) {
        ret = DRBG_HashDf(ctx, ctx->c, ctx->seedLen, &temp, entropy, &v, adin);
    } else {
        ret = DRBG_HashDf(ctx, ctx->c, ctx->seedLen, &temp, &v, entropy, adin);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // The length of the C array is the longest seedLen. Therefore, there is no failure.
    (void)memcpy_s(ctx->v, sizeof(ctx->v), ctx->c, ctx->seedLen);

    c = 0x0;
    ret = DRBG_HashDf(ctx, ctx->c, ctx->seedLen, &temp, &v, NULL, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

void DRBG_HashUnInstantiate(DRBG_Ctx *drbg)
{
    DRBG_HashCtx *ctx = (DRBG_HashCtx*)drbg->ctx;

    ctx->md->deinit(ctx->mdCtx);
    BSL_SAL_CleanseData((void *)(ctx->c), sizeof(ctx->c));
    BSL_SAL_CleanseData((void *)(ctx->v), sizeof(ctx->v));
}

DRBG_Ctx *DRBG_HashDup(DRBG_Ctx *drbg)
{
    if (drbg == NULL) {
        return NULL;
    }

    DRBG_HashCtx *ctx = (DRBG_HashCtx*)drbg->ctx;
    DRBG_Ctx *newDrbg = DRBG_NewHashCtx(ctx->md, drbg->isGm, &(drbg->seedMeth), drbg->seedCtx);
    if (newDrbg == NULL) {
        return NULL;
    }
    newDrbg->libCtx = drbg->libCtx;
    return newDrbg;
}

void DRBG_HashFree(DRBG_Ctx *drbg)
{
    if (drbg == NULL) {
        return;
    }

    DRBG_HashUnInstantiate(drbg);
    DRBG_HashCtx *ctx = (DRBG_HashCtx*)drbg->ctx;
    ctx->md->freeCtx(ctx->mdCtx);
    ctx->mdCtx = NULL;
    BSL_SAL_FREE(drbg);
}

static int32_t DRBG_NewHashCtxBase(uint32_t mdSize, DRBG_Ctx *drbg, DRBG_HashCtx *ctx)
{
    switch (mdSize) {
        case DRBG_SHA1MDSIZE:
            drbg->strength = 128;   // 128 is the standard content length of nist 800-90a.
            ctx->seedLen = 55;      // 55 is the standard content length of nist 800-90a.
            return CRYPT_SUCCESS;
        case DRBG_SHA224MDSIZE:
            drbg->strength = 192;   // 192 is the standard content length of nist 800-90a.
            ctx->seedLen = 55;      // 55 is the standard content length of nist 800-90a.
            return CRYPT_SUCCESS;
        case DRBG_SHA256MDSIZE:
            drbg->strength = 256;   // 256 is the standard content length of nist 800-90a.
            ctx->seedLen = 55;      // 55 is the standard content length of nist 800-90a.
            return CRYPT_SUCCESS;
        case DRBG_SHA384MDSIZE:
        case DRBG_SHA512MDSIZE:
            drbg->strength = 256;   // 256 is the standard content length of nist 800-90a.
            ctx->seedLen = 111;     // 111 is the standard content length of nist 800-90a.
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DRBG_ALG_NOT_SUPPORT);
            return CRYPT_DRBG_ALG_NOT_SUPPORT;
    }
}

DRBG_Ctx *DRBG_NewHashCtx(const EAL_MdMethod *md, bool isGm, const CRYPT_RandSeedMethod *seedMeth, void *seedCtx)
{
    DRBG_Ctx *drbg = NULL;
    DRBG_HashCtx *ctx = NULL;
    static DRBG_Method meth = {
        DRBG_HashInstantiate,
        DRBG_HashGenerate,
        DRBG_HashReseed,
        DRBG_HashUnInstantiate,
        DRBG_HashDup,
        DRBG_HashFree
    };

    if (md == NULL || md->newCtx == NULL || md->freeCtx == NULL || seedMeth == NULL) {
        return NULL;
    }

    drbg = (DRBG_Ctx*)BSL_SAL_Malloc(sizeof(DRBG_Ctx) + sizeof(DRBG_HashCtx));
    if (drbg == NULL) {
        return NULL;
    }

    ctx = (DRBG_HashCtx*)(drbg + 1);
    ctx->md = md;
    ctx->mdCtx = md->newCtx(NULL, md->id);
    if (ctx->mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_FREE(drbg);
        return NULL;
    }
    if (DRBG_NewHashCtxBase(md->mdSize, drbg, ctx) != CRYPT_SUCCESS) {
        md->freeCtx(ctx->mdCtx);
        ctx->mdCtx = NULL;
        BSL_SAL_FREE(drbg);
        return NULL;
    }

    drbg->state = DRBG_STATE_UNINITIALISED;
    drbg->isGm = isGm;
    drbg->reseedInterval = (drbg->isGm) ? HITLS_CRYPTO_RESEED_INTERVAL_GM : DRBG_MAX_RESEED_INTERVAL;
#if defined(HITLS_CRYPTO_DRBG_GM)
    drbg->reseedIntervalTime = (drbg->isGm) ? HITLS_CRYPTO_DRBG_RESEED_TIME_GM : 0;
#endif

    drbg->meth = &meth;
    drbg->ctx = ctx;
    drbg->seedMeth = *seedMeth;
    drbg->seedCtx = seedCtx;

    // Shift right by 3, from bit length to byte length
    drbg->entropyRange.min = drbg->strength >> 3;
    drbg->entropyRange.max = DRBG_MAX_LEN;

    drbg->nonceRange.min = drbg->entropyRange.min / DRBG_NONCE_FROM_ENTROPY;
    drbg->nonceRange.max = DRBG_MAX_LEN;

    drbg->maxPersLen = DRBG_MAX_LEN;
    drbg->maxAdinLen = DRBG_MAX_LEN;
    drbg->maxRequest = (drbg->isGm) ? DRBG_MAX_REQUEST_SM3 : DRBG_MAX_REQUEST;

    drbg->predictionResistance = false;
    drbg->forkId = BSL_SAL_GetPid();

    return drbg;
}
#endif
