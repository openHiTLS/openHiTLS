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
#ifdef HITLS_CRYPTO_FRODOKEM
#include <stdio.h>

#include "bsl_sal.h"
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "securec.h"
#include "frodo_local.h"
#include "crypt_frodokem.h"
#include "bsl_params.h"
#include "crypt_util_rand.h"
#include "bsl_err_internal.h"
#include "crypt_util_ctrl.h"

#define FRODOKEM_LEN_A        16
#define FRODO_HASH_PK_MAX_LEN 32
#define CHECK_IF_NULL_RET(PTR, RET)  \
    do {                             \
        if (PTR == NULL) {           \
            BSL_ERR_PUSH_ERROR(RET); \
            return RET;              \
        }                            \
    } while (0)

static int32_t FrodoKemRandombytes(uint8_t *buffer, size_t len)
{
    return CRYPT_Rand(buffer, len);
}

typedef int32_t (*FrodoShakeFunc)(uint8_t *output, uint32_t outLen, const uint8_t *input, uint32_t inLen);

// Input: rnd = s || seedSE || z
// Output: pk = seedA || B, sk = s || pk || S^T || H(pk), where B = A*S + E, seedA = H(z)， S and E are sampled from seedSE
static int32_t FrodoKemKeypairInternal(const uint8_t *rnd, const FrodoKemParams *params, uint8_t *pk, uint8_t *sk,
                                       size_t lenSk)
{
    // n is the number of rows of matrix S
    const uint16_t n = params->n;
    // nBar is the number of columns of matrix S
    const uint16_t nBar = params->nBar;
    // The length of matrix
    const size_t matrixSize = (size_t)n * nBar * sizeof(uint16_t);

    const uint8_t *s = rnd; // secret seed s
    const uint8_t *seedSE = rnd + params->ss; // seedSE for sampling S and E
    const uint8_t *z = rnd + params->ss + params->lenSeedSE; // seed z for generating seedA

    // Select a shake function according to the param
    FrodoShakeFunc FrodoShake = n == FRODO_PARA_640_N ? FrodoKemShake128 : FrodoKemShake256;
    // allocate S^T
    uint16_t *sTranspose = (uint16_t *)BSL_SAL_Malloc(matrixSize);
    if (sTranspose == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint8_t seedA[FRODOKEM_LEN_A];
    int32_t ret = FrodoShake(seedA, FRODOKEM_LEN_A, z, FRODOKEM_LEN_A);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = FrodoPkeKeygenSeeded(params, pk, sTranspose, seedA, seedSE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    uint8_t *skSec = sk;
    uint8_t *skPk = sk + params->ss;
    uint8_t *skS = skPk + params->pkSize;
    uint8_t *skPkh = skS + matrixSize;

    (void)memcpy_s(skSec, lenSk, s, params->ss);
    (void)memcpy_s(skPk, lenSk - params->ss, pk, params->pkSize);
    (void)memcpy_s(skS, lenSk - params->ss - params->pkSize, (uint8_t *)sTranspose, matrixSize);

    ret = FrodoShake(skPkh, params->lenPkHash, pk, params->pkSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
EXIT:
    BSL_SAL_CleanseData(sTranspose, matrixSize);
    BSL_SAL_FREE(sTranspose);
    return ret;
}

static int32_t FrodoKemEncapsInternal(const uint8_t *mu, const FrodoKemParams *params, uint8_t *ct, uint8_t *ss,
                                      const uint8_t *pk)
{
    FrodoShakeFunc FrodoShake = params->n == FRODO_PARA_640_N ? FrodoKemShake128 : FrodoKemShake256;

    uint8_t pkh[FRODO_HASH_PK_MAX_LEN];
    if (params->lenPkHash > sizeof(pkh)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = FrodoShake(pkh, params->lenPkHash, pk, params->pkSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t seedkLen = params->lenSeedSE + params->ss;
    uint8_t *seedk = (uint8_t *)BSL_SAL_Malloc(seedkLen);
    if (seedk == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t inLen = params->lenPkHash + params->lenMu + params->lenSalt;
    uint8_t *in = (uint8_t *)BSL_SAL_Malloc(inLen);
    if (in == NULL) {
        BSL_SAL_FREE(seedk);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memcpy_s(in, inLen, pkh, params->lenPkHash);
    (void)memcpy_s(in + params->lenPkHash, inLen - params->lenPkHash, mu, params->lenMu + params->lenSalt);

    ret = FrodoShake(seedk, seedkLen, in, inLen);
    BSL_SAL_FREE(in);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(seedk);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t *seedSEp = seedk;
    uint8_t *k = seedk + params->lenSeedSE;

    ret = FrodoPkeEncrypt(params, pk, mu, seedSEp, ct);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(seedk);
        return ret;
    }

    for (int32_t i = 0; i < params->lenSalt; i++) {
        ct[params->ctxSize - params->lenSalt + i] = mu[params->lenMu + i];
    }

    uint32_t ctKLen = params->ctxSize + params->ss;
    uint8_t *ctK = (uint8_t *)BSL_SAL_Malloc(ctKLen);
    if (ctK == NULL) {
        BSL_SAL_FREE(seedk);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    (void)memcpy_s(ctK, ctKLen, ct, params->ctxSize);
    (void)memcpy_s(ctK + params->ctxSize, ctKLen - params->ctxSize, k, params->ss);

    ret = FrodoShake(ss, params->ss, ctK, ctKLen);

    BSL_SAL_FREE(ctK);
    BSL_SAL_FREE(seedk);
    return ret;
}

static int32_t FrodoKemKeypair(const FrodoKemParams *params, uint8_t *pk, uint8_t *sk, size_t lenSk)
{
    const size_t randLen = (size_t)params->ss + params->lenSeedSE + params->lenSeedA;
    uint8_t *rnd = BSL_SAL_Malloc(randLen);
    if (rnd == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = FrodoKemRandombytes(rnd, randLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(rnd, randLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = FrodoKemKeypairInternal(rnd, params, pk, sk, lenSk);
    BSL_SAL_ClearFree(rnd, randLen);
    return ret;
}

static int32_t FrodoKemEncaps(const FrodoKemParams *params, uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    uint8_t mu[FRODO_M_SALT_LEN];

    int32_t ret = FrodoKemRandombytes(mu, params->lenMu + params->lenSalt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = FrodoKemEncapsInternal(mu, params, ct, ss, pk);
    BSL_SAL_CleanseData(mu, params->lenMu + params->lenSalt);
    return ret;
}

static int32_t FrodoKemDecaps(const FrodoKemParams *params, uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    FrodoShakeFunc FrodoShake = params->n == FRODO_PARA_640_N ? FrodoKemShake128 : FrodoKemShake256;

    const uint8_t *skSec = sk;
    const uint8_t *skPk = sk + params->ss;
    const uint8_t *skS = skPk + params->pkSize;
    const uint8_t *skPkh = skS + (params->n * params->nBar * sizeof(uint16_t));

    uint32_t pkhMuSaltLen = params->lenPkHash + params->lenMu + params->lenSalt; // the length of H(pk) + m + salt
    uint32_t ctLen = params->ctxSize; // the length of the ct
    uint32_t seedKLen = params->lenSeedSE + params->ss; // the length of the shake output
    uint32_t bufLen = pkhMuSaltLen + seedKLen + ctLen;
    // buf = H(pk) || mu || salt || seedK || ctVerify, where seedK = H(H(pk) || mu || salt) = seedSE || k
    uint8_t *buf = (uint8_t *)BSL_SAL_Malloc(bufLen);
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint8_t *pkhMuSalt = buf; // H(pk) || mu || salt
    uint8_t *pkh = buf;
    uint8_t *mu = pkh + params->lenPkHash;
    uint8_t *salt = mu + params->lenMu;
    uint8_t *seedK = pkhMuSalt + pkhMuSaltLen;
    uint8_t *ctVerify = seedK + seedKLen;

    // Decrypt mu
    int32_t ret = FrodoPkeDecrypt(params, skS, ct, mu);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    (void)memcpy_s(pkh, bufLen, skPkh, params->lenPkHash);
    (void)memcpy_s(salt, bufLen - (salt - buf), ct + ctLen - params->lenSalt, params->lenSalt);

    ret = FrodoShake(seedK, seedKLen, pkhMuSalt, pkhMuSaltLen); //
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    uint8_t *seedSEPrime = seedK;
    uint8_t *kPrime = seedK + params->lenSeedSE;
    // Re-encrypt to verify the ciphertext
    ret = FrodoPkeEncrypt(params, skPk, mu, seedSEPrime, ctVerify);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    int8_t selector = FrodoCommonCtVerify((const uint16_t *)ct, (uint16_t *)ctVerify,
                                          (params->ctxSize - params->lenSalt) / sizeof(uint16_t));
    // if ct == ctVerify, kPrime = kPrime, else kPrime = skSec
    FrodoCommonCtSelect(kPrime, kPrime, skSec, params->ss, selector);

    uint32_t ctKLen = params->ctxSize + params->ss; // the length of ct || k
    uint8_t *ctKBuf = (uint8_t *)BSL_SAL_Malloc(ctKLen);
    if (ctKBuf == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto EXIT;
    }
    (void)memcpy_s(ctKBuf, ctKLen, ct, params->ctxSize);
    (void)memcpy_s(ctKBuf + ctLen, ctKLen - ctLen, kPrime, params->ss);
    ret = FrodoShake(ss, params->ss, ctKBuf, ctKLen);
    BSL_SAL_FREE(ctKBuf);
EXIT:
    BSL_SAL_ClearFree(buf, bufLen);
    return ret;
}

CRYPT_FRODOKEM_Ctx *CRYPT_FRODOKEM_NewCtx(void)
{
    CRYPT_FRODOKEM_Ctx *ctx = BSL_SAL_Malloc(sizeof(CRYPT_FRODOKEM_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_FRODOKEM_Ctx), 0, sizeof(CRYPT_FRODOKEM_Ctx));

    return ctx;
}

CRYPT_FRODOKEM_Ctx *CRYPT_FRODOKEM_NewCtxEx(void *libCtx)
{
    CRYPT_FRODOKEM_Ctx *ctx = CRYPT_FRODOKEM_NewCtx();
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

int32_t CRYPT_FRODOKEM_Gen(CRYPT_FRODOKEM_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEYINFO_NOT_SET);
        return CRYPT_FRODOKEM_KEYINFO_NOT_SET;
    }
    if (ctx->publicKey != NULL) {
        BSL_SAL_FREE(ctx->publicKey);
    }
    if (ctx->privateKey != NULL) {
        (void)memset_s(ctx->privateKey, ctx->para->kemSkSize, 0, ctx->para->kemSkSize);
        BSL_SAL_FREE(ctx->privateKey);
    }
    ctx->publicKey = BSL_SAL_Calloc(ctx->para->pkSize, sizeof(uint8_t));
    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->privateKey = BSL_SAL_Calloc(ctx->para->kemSkSize, sizeof(uint8_t));
    if (ctx->privateKey == NULL) {
        BSL_SAL_FREE(ctx->publicKey);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = FrodoKemKeypair(ctx->para, ctx->publicKey, ctx->privateKey, ctx->para->kemSkSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(ctx->publicKey);
        BSL_SAL_FREE(ctx->privateKey);
    }
    return ret;
}

int32_t CRYPT_FRODOKEM_SetPrvKeyEx(CRYPT_FRODOKEM_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEYINFO_NOT_SET);
        return CRYPT_FRODOKEM_KEYINFO_NOT_SET;
    }
    if (ctx->privateKey != NULL || ctx->publicKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEY_REPEATED_SET);
        return CRYPT_FRODOKEM_KEY_REPEATED_SET;
    }
    const BSL_Param *prv = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_FRODOKEM_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para->kemSkSize > prv->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
        return CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH;
    }
    if (ctx->privateKey == NULL) {
        ctx->privateKey = BSL_SAL_Calloc(ctx->para->kemSkSize, sizeof(uint8_t));
        if (ctx->privateKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }

    uint32_t useLen = ctx->para->kemSkSize;
    (void)memcpy_s(ctx->privateKey, useLen, prv->value, useLen);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_FRODOKEM_SetPubKeyEx(CRYPT_FRODOKEM_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEYINFO_NOT_SET);
        return CRYPT_FRODOKEM_KEYINFO_NOT_SET;
    }
    if (ctx->privateKey != NULL || ctx->publicKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEY_REPEATED_SET);
        return CRYPT_FRODOKEM_KEY_REPEATED_SET;
    }
    const BSL_Param *pub = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_FRODOKEM_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para->pkSize > pub->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
        return CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH;
    }
    if (ctx->publicKey == NULL) {
        ctx->publicKey = BSL_SAL_Calloc(ctx->para->pkSize, sizeof(uint8_t));
        if (ctx->publicKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    uint32_t useLen = ctx->para->pkSize;
    (void)memcpy_s(ctx->publicKey, useLen, pub->value, useLen);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_FRODOKEM_GetPrvKeyEx(CRYPT_FRODOKEM_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEYINFO_NOT_SET);
        return CRYPT_FRODOKEM_KEYINFO_NOT_SET;
    }
    BSL_Param *prv = BSL_PARAM_FindParam(param, CRYPT_PARAM_FRODOKEM_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_ABSENT_PRVKEY);
        return CRYPT_FRODOKEM_ABSENT_PRVKEY;
    }
    if (ctx->para->kemSkSize > prv->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
        return CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH;
    }
    uint32_t useLen = ctx->para->kemSkSize;
    (void)memcpy_s(prv->value, useLen, ctx->privateKey, useLen);
    prv->useLen = useLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_FRODOKEM_GetPubKeyEx(CRYPT_FRODOKEM_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEYINFO_NOT_SET);
        return CRYPT_FRODOKEM_KEYINFO_NOT_SET;
    }
    BSL_Param *pub = BSL_PARAM_FindParam(param, CRYPT_PARAM_FRODOKEM_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_ABSENT_PUBKEY);
        return CRYPT_FRODOKEM_ABSENT_PUBKEY;
    }
    if (ctx->para->pkSize > pub->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
        return CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH;
    }
    uint32_t useLen = ctx->para->pkSize;
    (void)memcpy_s(pub->value, useLen, ctx->publicKey, useLen);
    pub->useLen = useLen;
    return CRYPT_SUCCESS;
}

CRYPT_FRODOKEM_Ctx *CRYPT_FRODOKEM_DupCtx(CRYPT_FRODOKEM_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_FRODOKEM_Ctx *ctx = CRYPT_FRODOKEM_NewCtx();
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    if (src->para != NULL) {
        ctx->para = src->para;
    }
    if (src->publicKey != NULL) {
        ctx->publicKey = BSL_SAL_Calloc(src->para->pkSize, sizeof(uint8_t));
        if (ctx->publicKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            CRYPT_FRODOKEM_FreeCtx(ctx);
            return NULL;
        }
        (void)memcpy_s(ctx->publicKey, ctx->para->pkSize, src->publicKey, ctx->para->pkSize);
    }
    if (src->privateKey != NULL) {
        ctx->privateKey = BSL_SAL_Calloc(src->para->kemSkSize, sizeof(uint8_t));
        if (ctx->privateKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            CRYPT_FRODOKEM_FreeCtx(ctx);
            return NULL;
        }
        (void)memcpy_s(ctx->privateKey, ctx->para->kemSkSize, src->privateKey, ctx->para->kemSkSize);
    }
    ctx->libCtx = src->libCtx;
    return ctx;
}

int32_t CRYPT_FRODOKEM_Cmp(CRYPT_FRODOKEM_Ctx *ctx1, CRYPT_FRODOKEM_Ctx *ctx2)
{
    if (ctx1 == NULL || ctx2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx1->para != ctx2->para) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEY_NOT_EQUAL);
        return CRYPT_FRODOKEM_KEY_NOT_EQUAL;
    }
    if (ctx1->publicKey != NULL && ctx2->publicKey != NULL) {
        if (memcmp(ctx1->publicKey, ctx2->publicKey, ctx1->para->pkSize) != 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEY_NOT_EQUAL);
            return CRYPT_FRODOKEM_KEY_NOT_EQUAL;
        }
    } else if (ctx1->publicKey != NULL || ctx2->publicKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEY_NOT_EQUAL);
        return CRYPT_FRODOKEM_KEY_NOT_EQUAL;
    }
    if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
        if (memcmp(ctx1->privateKey, ctx2->privateKey, ctx1->para->kemSkSize) != 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEY_NOT_EQUAL);
            return CRYPT_FRODOKEM_KEY_NOT_EQUAL;
        }
    } else if (ctx1->privateKey != NULL || ctx2->privateKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEY_NOT_EQUAL);
        return CRYPT_FRODOKEM_KEY_NOT_EQUAL;
    }
    return CRYPT_SUCCESS;
}

static int32_t FrodoSetParaById(CRYPT_FRODOKEM_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->para != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_CTRL_INIT_REPEATED);
        return CRYPT_FRODOKEM_CTRL_INIT_REPEATED;
    }
    int32_t algId = *(int32_t *)val;
    ctx->para = FrodoGetParamsById(algId);
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_FRODOKEM_Ctrl(CRYPT_FRODOKEM_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return FrodoSetParaById(ctx, val, valLen);
        case CRYPT_CTRL_GET_CIPHERTEXT_LEN: {
            CHECK_IF_NULL_RET(ctx->para, CRYPT_FRODOKEM_KEYINFO_NOT_SET);
            return CRYPT_CTRL_GetNum32(ctx->para->ctxSize, val, valLen);
        }
        case CRYPT_CTRL_GET_SECBITS: {
            CHECK_IF_NULL_RET(ctx->para, CRYPT_FRODOKEM_KEYINFO_NOT_SET);
            return CRYPT_CTRL_GetNum32(ctx->para->ss * 8, val, valLen);
        }
        case CRYPT_CTRL_GET_PUBKEY_LEN: {
            CHECK_IF_NULL_RET(ctx->para, CRYPT_FRODOKEM_KEYINFO_NOT_SET);
            return CRYPT_CTRL_GetNum32(ctx->para->pkSize, val, valLen);
        }
        case CRYPT_CTRL_GET_PRVKEY_LEN: {
            CHECK_IF_NULL_RET(ctx->para, CRYPT_FRODOKEM_KEYINFO_NOT_SET);
            return CRYPT_CTRL_GetNum32(ctx->para->kemSkSize, val, valLen);
        }
        case CRYPT_CTRL_GET_SHARED_KEY_LEN: {
            CHECK_IF_NULL_RET(ctx->para, CRYPT_FRODOKEM_KEYINFO_NOT_SET);
            return CRYPT_CTRL_GetNum32(ctx->para->ss, val, valLen);
        }
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_CTRL_NOT_SUPPORT);
            return CRYPT_FRODOKEM_CTRL_NOT_SUPPORT;
    }
}

void CRYPT_FRODOKEM_FreeCtx(CRYPT_FRODOKEM_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->publicKey != NULL) {
        BSL_SAL_FREE(ctx->publicKey);
    }
    if (ctx->privateKey != NULL) {
        BSL_SAL_ClearFree(ctx->privateKey, ctx->para->kemSkSize);
    }
    BSL_SAL_FREE(ctx);
}

int32_t CRYPT_FRODOKEM_EncapsInit(CRYPT_FRODOKEM_Ctx *ctx, const BSL_Param *params)
{
    (void)ctx;
    (void)params;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_FRODOKEM_DecapsInit(CRYPT_FRODOKEM_Ctx *ctx, const BSL_Param *params)
{
    (void)ctx;
    (void)params;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_FRODOKEM_Encaps(CRYPT_FRODOKEM_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen, uint8_t *sharedSecret,
                              uint32_t *ssLen)
{
    if (ctx == NULL || ctx->publicKey == NULL || ciphertext == NULL || sharedSecret == NULL || ctLen == NULL ||
        ssLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEYINFO_NOT_SET);
        return CRYPT_FRODOKEM_KEYINFO_NOT_SET;
    }
    if (ctx->para->ctxSize > *ctLen || ctx->para->ss > *ssLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
        return CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH;
    }
    int32_t ret = FrodoKemEncaps(ctx->para, ciphertext, sharedSecret, ctx->publicKey);
    if (ret == CRYPT_SUCCESS) {
        *ssLen = ctx->para->ss;
        *ctLen = ctx->para->ctxSize;
    }
    return ret;
}

int32_t CRYPT_FRODOKEM_Decaps(CRYPT_FRODOKEM_Ctx *ctx, const uint8_t *ciphertext, uint32_t ctLen, uint8_t *sharedSecret,
                              uint32_t *ssLen)
{
    if (ctx == NULL || ciphertext == NULL || sharedSecret == NULL || ssLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_KEYINFO_NOT_SET);
        return CRYPT_FRODOKEM_KEYINFO_NOT_SET;
    }
    if (ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_ABSENT_PRVKEY);
        return CRYPT_FRODOKEM_ABSENT_PRVKEY;
    }
    if (ctLen != ctx->para->ctxSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_INVALID_CIPHER);
        return CRYPT_FRODOKEM_INVALID_CIPHER;
    }
    if (ctx->para->ss > *ssLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
        return CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH;
    }
    int32_t ret = FrodoKemDecaps(ctx->para, sharedSecret, ciphertext, ctx->privateKey);
    if (ret == CRYPT_SUCCESS) {
        *ssLen = ctx->para->ss;
    }
    return ret;
}
#endif
