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
#ifdef HITLS_CRYPTO_DRBG_HMAC

#include <stdlib.h>
#include <securec.h>
#include "crypt_errno.h"
#include "crypt_local_types.h"
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "crypt_types.h"
#include "bsl_err_internal.h"
#include "drbg_local.h"

#define DRBG_HMAC_MAX_MDLEN (64)

typedef enum {
    DRBG_HMAC_SHA1SIZE = 20,
    DRBG_HMAC_SHA224SIZE = 28,
    DRBG_HMAC_SHA256SIZE = 32,
    DRBG_HMAC_SHA384SIZE = 48,
    DRBG_HMAC_SHA512SIZE = 64,
} DRBG_HmacSize;

typedef struct {
    uint8_t k[DRBG_HMAC_MAX_MDLEN];
    uint8_t v[DRBG_HMAC_MAX_MDLEN];
    uint32_t blockLen;
    const EAL_MacMethod *hmacMeth;
    CRYPT_MAC_AlgId macId;
    void *hmacCtx;
} DRBG_HmacCtx;


static int32_t Hmac(DRBG_HmacCtx *ctx, uint8_t mark, const CRYPT_Data *provData[], int32_t provDataLen)
{
    int32_t ret;
    uint32_t ctxKLen = sizeof(ctx->k);
    uint32_t ctxVLen = sizeof(ctx->v);
    // K = HMAC (K, V || mark || provided_data). mark can be 0x00 or 0x01,
    // provided_data = in1 || in2 || in3, private_data can be NULL
    if ((ret = ctx->hmacMeth->init(ctx->hmacCtx, ctx->k, ctx->blockLen, NULL)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if ((ret = ctx->hmacMeth->update(ctx->hmacCtx, ctx->v, ctx->blockLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if ((ret = ctx->hmacMeth->update(ctx->hmacCtx, &mark, 1)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    for (int32_t i = 0; i < provDataLen; i++) {
        if ((ret = ctx->hmacMeth->update(ctx->hmacCtx, provData[i]->data, provData[i]->len)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
    }
    if ((ret = ctx->hmacMeth->final(ctx->hmacCtx, ctx->k, &ctxKLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // V = HMAC (K, V).
    if ((ret = ctx->hmacMeth->init(ctx->hmacCtx, ctx->k, ctx->blockLen, NULL)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if ((ret = ctx->hmacMeth->update(ctx->hmacCtx, ctx->v, ctx->blockLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if ((ret = ctx->hmacMeth->final(ctx->hmacCtx, ctx->v, &ctxVLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    // clear hmacCtx
    ctx->hmacMeth->deinit(ctx->hmacCtx);
    return ret;
}

/**
 * Ref: NIST.SP.800-90Ar1 https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-90ar1.pdf
 * Section: 10.1.2.2 HMAC_DRBG Update Process
 */
static int32_t DRBG_HmacUpdate(DRBG_Ctx *drbg, const CRYPT_Data *provData[], int32_t provDataLen)
{
    DRBG_HmacCtx *ctx = (DRBG_HmacCtx *)drbg->ctx;
    // K = HMAC (K, V || 0x00 || provided_data).  V = HMAC (K, V), provided_data have 3 input
    int32_t ret = Hmac(ctx, 0x00, provData, provDataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // If (provided_data = Null), then return K and V. It's not an error, it's algorithmic.
    if (provDataLen == 0) {
        return ret;
    }
    // K = HMAC (K, V || 0x01 || provided_data).  V = HMAC (K, V)
    ret = Hmac(ctx, 0x01, provData, provDataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/**
 * Ref: NIST.SP.800-90Ar1 https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-90ar1.pdf
 * Section: 10.1.2.3 Instantiation of HMAC_DRBG
 */
int32_t DRBG_HmacInstantiate(DRBG_Ctx *drbg, const CRYPT_Data *entropyInput, const CRYPT_Data *nonce,
    const CRYPT_Data *perstr)
{
    DRBG_HmacCtx *ctx = (DRBG_HmacCtx *)drbg->ctx;
    const CRYPT_Data *provData[3] = {0}; // We only need 3 at most.
    int32_t index = 0;
    if (!CRYPT_IsDataNull(entropyInput)) {
        provData[index++] = entropyInput;
    }
    if (!CRYPT_IsDataNull(nonce)) {
        provData[index++] = nonce;
    }
    if (!CRYPT_IsDataNull(perstr)) {
        provData[index++] = perstr;
    }

    // Key = 0x00 00...00.
    (void)memset_s(ctx->k, sizeof(ctx->k), 0, ctx->blockLen);

    // V = 0x01 01...01.
    (void)memset_s(ctx->v, sizeof(ctx->v), 1, ctx->blockLen);

    // seed_material = entropy_input || nonce || personalization_string.
    // (Key, V) = HMAC_DRBG_Update (seed_material, Key, V).
    int32_t ret = DRBG_HmacUpdate(drbg, provData, index);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

/**
 * Ref: NIST.SP.800-90Ar1 https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-90ar1.pdf
 * Section: 10.1.2.4 HMAC_DRBG Reseed Process
 */
int32_t DRBG_HmacReseed(DRBG_Ctx *drbg, const CRYPT_Data *entropyInput, const CRYPT_Data *adin)
{
    // seed_material = entropy_input || additional_input.
    const CRYPT_Data *seedMaterial[2] = {0}; // This stage only needs 2 at most.
    int32_t index = 0;
    if (!CRYPT_IsDataNull(entropyInput)) {
        seedMaterial[index++] = entropyInput;
    }
    if (!CRYPT_IsDataNull(adin)) {
        seedMaterial[index++] = adin;
    }
    // (Key, V) = HMAC_DRBG_Update (seed_material, Key, V).
    int32_t ret = DRBG_HmacUpdate(drbg, seedMaterial, index);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

/**
 * Ref: NIST.SP.800-90Ar1 https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-90ar1.pdf
 * Section: 10.1.2.5 HMAC_DRBG Generate Process
 */
int32_t DRBG_HmacGenerate(DRBG_Ctx *drbg, uint8_t *out, uint32_t outLen, const CRYPT_Data *adin)
{
    DRBG_HmacCtx *ctx = (DRBG_HmacCtx *)drbg->ctx;
    const EAL_MacMethod *hmacMeth = ctx->hmacMeth;
    const uint8_t *temp = ctx->v;
    uint32_t tmpLen = ctx->blockLen;
    uint32_t len = outLen;
    uint8_t *buf = out;
    int32_t ret;
    uint32_t ctxVLen;
    int32_t hasAdin = CRYPT_IsDataNull(adin) ? 0 : 1;
    // If additional_input ≠ Null, then (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
    if (hasAdin == 1) {
        if ((ret = DRBG_HmacUpdate(drbg, &adin, hasAdin)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    /**
    While (len (temp) < requested_number_of_bits) do:
        V = HMAC (Key, V).
        temp = temp || V.
    */
    while (len > 0) {
        if ((ret = hmacMeth->init(ctx->hmacCtx, ctx->k, ctx->blockLen, NULL)) != CRYPT_SUCCESS ||
            (ret = hmacMeth->update(ctx->hmacCtx, temp, ctx->blockLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        if (len <= ctx->blockLen) {
            break;
        }
        if ((ret = hmacMeth->final(ctx->hmacCtx, buf, &tmpLen)) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        temp = buf;
        buf += ctx->blockLen;
        len -= ctx->blockLen;
    }

    ctxVLen = sizeof(ctx->v);
    if ((ret = hmacMeth->final(ctx->hmacCtx, ctx->v, &ctxVLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // Intercepts the len-length V-value as an output, and because of len <= blockLen,
    // length of V is always greater than blockLen，Therefore, this problem does not exist.
    (void)memcpy_s(buf, len, ctx->v, len);

    //  (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
    if ((ret = DRBG_HmacUpdate(drbg, &adin, hasAdin)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    // clear hmacCtx
    hmacMeth->deinit(ctx->hmacCtx);
    return ret;
}

void DRBG_HmacUnInstantiate(DRBG_Ctx *drbg)
{
    DRBG_HmacCtx *ctx = (DRBG_HmacCtx*)drbg->ctx;
    ctx->hmacMeth->deinit(ctx->hmacCtx);
    BSL_SAL_CleanseData((void *)(ctx->k), sizeof(ctx->k));
    BSL_SAL_CleanseData((void *)(ctx->v), sizeof(ctx->v));
}

DRBG_Ctx *DRBG_HmacDup(DRBG_Ctx *drbg)
{
    if (drbg == NULL) {
        return NULL;
    }

    DRBG_HmacCtx *ctx = (DRBG_HmacCtx*)drbg->ctx;
    DRBG_Ctx *newDrbg = DRBG_NewHmacCtx(drbg->libCtx, ctx->hmacMeth, ctx->macId, &(drbg->seedMeth), drbg->seedCtx);
    if (newDrbg == NULL) {
        return NULL;
    }
    newDrbg->libCtx = drbg->libCtx;
    return newDrbg;
}

void DRBG_HmacFree(DRBG_Ctx *drbg)
{
    if (drbg == NULL) {
        return;
    }

    DRBG_HmacUnInstantiate(drbg);
    DRBG_HmacCtx *ctx = (DRBG_HmacCtx*)drbg->ctx;
    ctx->hmacMeth->freeCtx(ctx->hmacCtx);
    BSL_SAL_FREE(drbg);
    return;
}

static int32_t DRBG_NewHmacCtxBase(uint32_t hmacSize, DRBG_Ctx *drbg)
{
    switch (hmacSize) {
        case DRBG_HMAC_SHA1SIZE:
            drbg->strength = 128;   // nist 800-90a specified the length must be 128
            return CRYPT_SUCCESS;
        case DRBG_HMAC_SHA224SIZE:
            drbg->strength = 192;   // nist 800-90a specified the length must be 192
            return CRYPT_SUCCESS;
        case DRBG_HMAC_SHA256SIZE:
        case DRBG_HMAC_SHA384SIZE:
        case DRBG_HMAC_SHA512SIZE:
            drbg->strength = 256;   // nist 800-90a specified the length must be 256
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DRBG_ALG_NOT_SUPPORT);
            return CRYPT_DRBG_ALG_NOT_SUPPORT;
    }
}

DRBG_Ctx *DRBG_NewHmacCtx(void *libCtx, const EAL_MacMethod *hmacMeth, CRYPT_MAC_AlgId macId,
    const CRYPT_RandSeedMethod *seedMeth, void *seedCtx)
{
    DRBG_Ctx *drbg = NULL;
    DRBG_HmacCtx *ctx = NULL;
    static DRBG_Method meth = {
        DRBG_HmacInstantiate,
        DRBG_HmacGenerate,
        DRBG_HmacReseed,
        DRBG_HmacUnInstantiate,
        DRBG_HmacDup,
        DRBG_HmacFree
    };

    if (hmacMeth == NULL || seedMeth == NULL) {
        return NULL;
    }

    drbg = (DRBG_Ctx*)BSL_SAL_Malloc(sizeof(DRBG_Ctx) + sizeof(DRBG_HmacCtx));
    if (drbg == NULL) {
        return NULL;
    }

    ctx = (DRBG_HmacCtx*)(drbg + 1);
    ctx->hmacMeth = hmacMeth;
    ctx->macId = macId;
    void *macCtx = hmacMeth->newCtx(libCtx, ctx->macId);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(drbg);
        return NULL;
    }
    ctx->hmacCtx = macCtx;

    uint32_t tempLen = 0;
    int32_t ret = hmacMeth->ctrl(ctx->hmacCtx, CRYPT_CTRL_GET_MACLEN, &tempLen, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        hmacMeth->freeCtx(ctx->hmacCtx);
        BSL_SAL_FREE(drbg);
        return NULL;
    }
    ctx->blockLen = tempLen;

    if (DRBG_NewHmacCtxBase(ctx->blockLen, drbg) != CRYPT_SUCCESS) {
        hmacMeth->freeCtx(ctx->hmacCtx);
        BSL_SAL_FREE(drbg);
        return NULL;
    }

    drbg->state = DRBG_STATE_UNINITIALISED;
    drbg->reseedInterval = DRBG_MAX_RESEED_INTERVAL;

    drbg->meth = &meth;
    drbg->ctx = ctx;
    drbg->seedMeth = *seedMeth;
    drbg->seedCtx = seedCtx;

    // shift rightwards by 3, converting from bit length to byte length
    drbg->entropyRange.min = drbg->strength >> 3;
    drbg->entropyRange.max = DRBG_MAX_LEN;

    drbg->nonceRange.min = drbg->entropyRange.min / DRBG_NONCE_FROM_ENTROPY;
    drbg->nonceRange.max = DRBG_MAX_LEN;

    drbg->maxPersLen = DRBG_MAX_LEN;
    drbg->maxAdinLen = DRBG_MAX_LEN;
    drbg->maxRequest = DRBG_MAX_REQUEST;
    drbg->libCtx = libCtx;

    drbg->predictionResistance = false;
    drbg->forkId = BSL_SAL_GetPid();

    return drbg;
}
#endif
