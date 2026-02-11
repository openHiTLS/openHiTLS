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
#ifdef HITLS_CRYPTO_CLASSIC_MCELIECE
#include "crypt_mceliece.h"
#include "bsl_sal.h"
#include "crypt_params_key.h"
#include "mceliece_local.h"
#include "crypt_types.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_util_rand.h"
#include "crypt_util_ctrl.h"

#define CHECK_IF_NULL_RET(PTR, RET)  \
    do {                             \
        if (PTR == NULL) {           \
            BSL_ERR_PUSH_ERROR(RET); \
            return RET;              \
        }                            \
    } while (0)

static void PrivateKeyFree(CMPrivateKey *sk, const McelieceParams *params)
{
    if (sk != NULL) {
        if (sk->controlbits != NULL) {
            BSL_SAL_CleanseData(sk->controlbits, sk->controlbitsLen);
            BSL_SAL_FREE(sk->controlbits);
        }
        if (sk->g.coeffs != NULL) {
            BSL_SAL_CleanseData(sk->g.coeffs, params->t * sizeof(GFElement));
            BSL_SAL_FREE(sk->g.coeffs);
        }
        if (sk->alpha != NULL) {
            BSL_SAL_CleanseData(sk->alpha, MCELIECE_Q * sizeof(GFElement));
            BSL_SAL_FREE(sk->alpha);
        }
        if (sk->s != NULL) {
            BSL_SAL_CleanseData(sk->s, params->nBytes);
            BSL_SAL_FREE(sk->s);
        }
        BSL_SAL_FREE(sk);
    }
}

static CMPrivateKey *PrivateKeyCreate(const McelieceParams *params)
{
    CMPrivateKey *sk = BSL_SAL_Calloc(sizeof(CMPrivateKey), sizeof(uint8_t));
    if (sk == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    size_t cbLen = (size_t)((((2 * params->m - 1) * MCELIECE_Q / 2) + 7) / 8);
    sk->controlbitsLen = cbLen;

    sk->controlbits = (uint8_t *)BSL_SAL_Malloc(sk->controlbitsLen);
    if (sk->controlbits == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        PrivateKeyFree(sk, params);
        return NULL;
    }

    // init Goppa poly
    GFPolynomial *g = PolynomialCreate(params->t);
    if (g == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        PrivateKeyFree(sk, params);
        return NULL;
    }
    sk->g.coeffs = g->coeffs;
    sk->g.degree = g->degree;
    sk->g.maxDegree = g->maxDegree;
    BSL_SAL_FREE(g);

    sk->alpha = BSL_SAL_Calloc(MCELIECE_Q, sizeof(GFElement));
    if (sk->alpha == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        PrivateKeyFree(sk, params);
        return NULL;
    }

    sk->s = BSL_SAL_Calloc(params->nBytes, sizeof(uint8_t));
    if (sk->s == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        PrivateKeyFree(sk, params);
        return NULL;
    }
    sk->c = (1ULL << 32) - 1;
    return sk;
}

// Public key deallocation
static void PublicKeyFree(CMPublicKey *pk)
{
    if (pk != NULL) {
        if (pk->matT.data != NULL) {
            BSL_SAL_FREE(pk->matT.data);
        }
        BSL_SAL_FREE(pk);
    }
}

// Public key creation
static CMPublicKey *PublicKeyCreate(const McelieceParams *params)
{
    CMPublicKey *pk = BSL_SAL_Calloc(sizeof(CMPublicKey), sizeof(uint8_t));
    if (pk == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    GFMatrix *matT = MatrixCreate(params->mt, params->k);
    if (matT == NULL) {
        BSL_SAL_FREE(pk);
        return NULL;
    }
    pk->matT.data = matT->data;
    pk->matT.rows = matT->rows;
    pk->matT.cols = matT->cols;
    pk->matT.colsBytes = matT->colsBytes;
    BSL_SAL_FREE(matT);

    return pk;
}

CRYPT_MCELIECE_Ctx *CRYPT_MCELIECE_NewCtx(void)
{
    CRYPT_MCELIECE_Ctx *ctx = BSL_SAL_Malloc(sizeof(CRYPT_MCELIECE_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_MCELIECE_Ctx), 0, sizeof(CRYPT_MCELIECE_Ctx));
    return ctx;
}

CRYPT_MCELIECE_Ctx *CRYPT_MCELIECE_NewCtxEx(void *libCtx)
{
    CRYPT_MCELIECE_Ctx *ctx = CRYPT_MCELIECE_NewCtx();
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

int32_t CRYPT_MCELIECE_Gen(CRYPT_MCELIECE_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEYINFO_NOT_SET);
        return CRYPT_MCELIECE_KEYINFO_NOT_SET;
    }
    if (ctx->publicKey != NULL) {
        PublicKeyFree(ctx->publicKey);
        ctx->publicKey = NULL;
    }
    if (ctx->privateKey != NULL) {
        PrivateKeyFree(ctx->privateKey, ctx->para);
        ctx->privateKey = NULL;
    }
    ctx->publicKey = PublicKeyCreate(ctx->para);
    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->privateKey = PrivateKeyCreate(ctx->para);
    if (ctx->privateKey == NULL) {
        PublicKeyFree(ctx->publicKey);
        ctx->publicKey = NULL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint8_t delta[MCELIECE_L_BYTES];
    int32_t ret = CRYPT_RandEx(ctx->libCtx, delta, MCELIECE_L_BYTES);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return SeededKeyGenInternal(delta, ctx->publicKey, ctx->privateKey, ctx->para, ctx->para->semi != 0);
}

static void McelieceParsePrvKey(uint8_t *prvKeyBuf, CMPrivateKey *sk, const McelieceParams *params)
{
    uint8_t *p = prvKeyBuf;
    /* 1. delta 32 B */
    (void)memcpy_s(sk->delta, MCELIECE_L_BYTES, p, MCELIECE_L_BYTES);
    p += MCELIECE_L_BYTES;
    /* 2. c (pivot mask) 8 B */
    sk->c = CMLoad8(p);
    p += 8;

    /* 3. g (irr polynomial) */
    for (int32_t i = 0; i < params->t; i++) {
        uint16_t temp = ((uint16_t)p[1] << 8) | p[0];
        sk->g.coeffs[i] = temp;
        p += 2;
    }
    PolynomialSetCoeff(&sk->g, params->t, 1);

    /* 4. controlbits */
    (void)memcpy_s(sk->controlbits, sk->controlbitsLen, p, sk->controlbitsLen);
    p += sk->controlbitsLen;

    /* 5. s (random string) */
    (void)memcpy_s(sk->s, params->nBytes, p, params->nBytes);
}

int32_t CRYPT_MCELIECE_SetPrvKeyEx(CRYPT_MCELIECE_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEYINFO_NOT_SET);
        return CRYPT_MCELIECE_KEYINFO_NOT_SET;
    }
    if (ctx->privateKey != NULL || ctx->publicKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_REPEATED_SET);
        return CRYPT_MCELIECE_KEY_REPEATED_SET;
    }
    const BSL_Param *prv = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_MCELIECE_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((uint32_t)ctx->para->privateKeyBytes > prv->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
        return CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH;
    }

    ctx->privateKey = PrivateKeyCreate(ctx->para);
    if (ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    McelieceParsePrvKey(prv->value, ctx->privateKey, ctx->para);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_MCELIECE_SetPubKeyEx(CRYPT_MCELIECE_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->publicKey != NULL || ctx->privateKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_REPEATED_SET);
        return CRYPT_MCELIECE_KEY_REPEATED_SET;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEYINFO_NOT_SET);
        return CRYPT_MCELIECE_KEYINFO_NOT_SET;
    }
    const BSL_Param *pub = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_MCELIECE_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((uint32_t)ctx->para->publicKeyBytes > pub->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
        return CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH;
    }
    ctx->publicKey = PublicKeyCreate(ctx->para);
    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t useLen = ctx->para->publicKeyBytes;
    (void)memcpy_s(ctx->publicKey->matT.data, useLen, pub->value, useLen);
    return CRYPT_SUCCESS;
}

static void McelieceExportPrvKey(const CMPrivateKey *sk, uint8_t *prvKeyBuf, const McelieceParams *params)
{
    uint8_t *p = prvKeyBuf;
    /* 1. delta 32 B */
    (void)memcpy_s(p, MCELIECE_L_BYTES, sk->delta, MCELIECE_L_BYTES);
    p += MCELIECE_L_BYTES;
    /* 2. c (pivot mask) 8 B */
    CMStore8(p, sk->c);
    p += 8;

    /* 3. g (irr polynomial) */
    for (int32_t i = 0; i < params->t; i++) {
        p[0] = sk->g.coeffs[i] & 0xFF;
        p[1] = (sk->g.coeffs[i] >> 8) & 0xFF;
        p += 2;
    }

    /* 4. controlbits */
    (void)memcpy_s(p, sk->controlbitsLen, sk->controlbits, sk->controlbitsLen);
    p += sk->controlbitsLen;

    /* 5. s (random string) */
    (void)memcpy_s(p, params->nBytes, sk->s, params->nBytes);
}

int32_t CRYPT_MCELIECE_GetPrvKeyEx(CRYPT_MCELIECE_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEYINFO_NOT_SET);
        return CRYPT_MCELIECE_KEYINFO_NOT_SET;
    }
    if (ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_ABSENT_PRVKEY);
        return CRYPT_MCELIECE_ABSENT_PRVKEY;
    }
    BSL_Param *prv = BSL_PARAM_FindParam(param, CRYPT_PARAM_MCELIECE_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((uint32_t)ctx->para->privateKeyBytes > prv->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
        return CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH;
    }
    McelieceExportPrvKey(ctx->privateKey, prv->value, ctx->para);
    prv->useLen = ctx->para->privateKeyBytes;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_MCELIECE_GetPubKeyEx(CRYPT_MCELIECE_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEYINFO_NOT_SET);
        return CRYPT_MCELIECE_KEYINFO_NOT_SET;
    }
    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_ABSENT_PUBKEY);
        return CRYPT_MCELIECE_ABSENT_PUBKEY;
    }
    BSL_Param *pub = BSL_PARAM_FindParam(param, CRYPT_PARAM_MCELIECE_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((uint32_t)ctx->para->publicKeyBytes > pub->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
        return CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH;
    }
    uint32_t useLen = ctx->para->publicKeyBytes;
    (void)memcpy_s(pub->value, useLen, ctx->publicKey->matT.data, useLen);
    pub->useLen = useLen;
    return CRYPT_SUCCESS;
}

static int32_t McElieceSetParaById(CRYPT_MCELIECE_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->para != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_CTRL_INIT_REPEATED);
        return CRYPT_MCELIECE_CTRL_INIT_REPEATED;
    }
    int32_t algId = *(int32_t *)val;
    ctx->para = McelieceGetParamsById(algId);
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_MCELIECE_Ctrl(CRYPT_MCELIECE_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return McElieceSetParaById(ctx, val, valLen);
        case CRYPT_CTRL_GET_CIPHERTEXT_LEN: {
            CHECK_IF_NULL_RET(ctx->para, CRYPT_MCELIECE_KEYINFO_NOT_SET);
            return CRYPT_CTRL_GetNum32(ctx->para->cipherBytes, val, valLen);
        }
        case CRYPT_CTRL_GET_SECBITS: {
            CHECK_IF_NULL_RET(ctx->para, CRYPT_MCELIECE_KEYINFO_NOT_SET);
            return CRYPT_CTRL_GetNum32(ctx->para->sharedKeyBytes * 8, val, valLen);
        }
        case CRYPT_CTRL_GET_PUBKEY_LEN: {
            CHECK_IF_NULL_RET(ctx->para, CRYPT_MCELIECE_KEYINFO_NOT_SET);
            return CRYPT_CTRL_GetNum32(ctx->para->publicKeyBytes, val, valLen);
        }
        case CRYPT_CTRL_GET_PRVKEY_LEN: {
            CHECK_IF_NULL_RET(ctx->para, CRYPT_MCELIECE_KEYINFO_NOT_SET);
            return CRYPT_CTRL_GetNum32(ctx->para->privateKeyBytes, val, valLen);
        }
        case CRYPT_CTRL_GET_SHARED_KEY_LEN: {
            CHECK_IF_NULL_RET(ctx->para, CRYPT_MCELIECE_KEYINFO_NOT_SET);
            return CRYPT_CTRL_GetNum32(ctx->para->sharedKeyBytes, val, valLen);
        }
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_CTRL_NOT_SUPPORT);
            return CRYPT_MCELIECE_CTRL_NOT_SUPPORT;
    }
}
static int32_t MceliecePrvKeyCmp(CRYPT_MCELIECE_Ctx *ctx1, CRYPT_MCELIECE_Ctx *ctx2)
{
    if (ctx1->privateKey->c != ctx2->privateKey->c) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    if (memcmp(ctx1->privateKey->delta, ctx2->privateKey->delta, MCELIECE_L_BYTES) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    if (memcmp(ctx1->privateKey->g.coeffs, ctx2->privateKey->g.coeffs, ctx1->para->t * sizeof(GFElement)) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    if (ctx1->privateKey->controlbitsLen != ctx2->privateKey->controlbitsLen ||
        memcmp(ctx1->privateKey->controlbits, ctx2->privateKey->controlbits, ctx1->privateKey->controlbitsLen) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    if (memcmp(ctx1->privateKey->s, ctx2->privateKey->s, ctx1->para->nBytes) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    return CRYPT_SUCCESS;
}
static int32_t MceliecePubKeyCmp(CRYPT_MCELIECE_Ctx *ctx1, CRYPT_MCELIECE_Ctx *ctx2)
{
    if (memcmp(ctx1->publicKey->matT.data, ctx2->publicKey->matT.data, ctx1->para->publicKeyBytes) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    if (ctx1->publicKey->matT.cols != ctx2->publicKey->matT.cols ||
        ctx1->publicKey->matT.rows != ctx2->publicKey->matT.rows ||
        ctx1->publicKey->matT.colsBytes != ctx2->publicKey->matT.colsBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_MCELIECE_Cmp(CRYPT_MCELIECE_Ctx *ctx1, CRYPT_MCELIECE_Ctx *ctx2)
{
    if (ctx1 == NULL || ctx2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx1->para != ctx2->para) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    if (ctx1->publicKey != NULL && ctx2->publicKey != NULL) {
        if (MceliecePubKeyCmp(ctx1, ctx2) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
            return CRYPT_MCELIECE_KEY_NOT_EQUAL;
        }
    } else if (ctx1->publicKey != NULL || ctx2->publicKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }

    if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
        if (MceliecePrvKeyCmp(ctx1, ctx2) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
            return CRYPT_MCELIECE_KEY_NOT_EQUAL;
        }
    } else if (ctx1->privateKey != NULL || ctx2->privateKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }

    return CRYPT_SUCCESS;
}

static void MceliecePrvKeyCopy(CMPrivateKey *dest, const CMPrivateKey *src, const McelieceParams *params)
{
    dest->g.degree = src->g.degree;
    dest->c = src->c;
    (void)memcpy_s(dest->delta, MCELIECE_L_BYTES, src->delta, MCELIECE_L_BYTES);
    (void)memcpy_s(dest->g.coeffs, (params->t + 1) * sizeof(GFElement), src->g.coeffs,
                   (params->t + 1) * sizeof(GFElement));
    (void)memcpy_s(dest->alpha, sizeof(GFElement) * MCELIECE_Q, src->alpha, sizeof(GFElement) * MCELIECE_Q);
    (void)memcpy_s(dest->s, params->nBytes, src->s, params->nBytes);
    (void)memcpy_s(dest->controlbits, dest->controlbitsLen, src->controlbits, src->controlbitsLen);
}

static void MceliecePubKeyCopy(CMPublicKey *dest, const CMPublicKey *src, const McelieceParams *params)
{
    dest->matT.rows = src->matT.rows;
    dest->matT.cols = src->matT.cols;
    dest->matT.colsBytes = src->matT.colsBytes;
    (void)memcpy_s(dest->matT.data, params->publicKeyBytes, src->matT.data, params->publicKeyBytes);
}

CRYPT_MCELIECE_Ctx *CRYPT_MCELIECE_DupCtx(const CRYPT_MCELIECE_Ctx *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_MCELIECE_Ctx *ctx = CRYPT_MCELIECE_NewCtx();
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->libCtx = src->libCtx;
    ctx->para = src->para;
    if (src->publicKey != NULL) {
        ctx->publicKey = PublicKeyCreate(ctx->para);
        if (ctx->publicKey == NULL) {
            CRYPT_MCELIECE_FreeCtx(ctx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
        MceliecePubKeyCopy(ctx->publicKey, src->publicKey, ctx->para);
    }
    if (src->privateKey != NULL) {
        ctx->privateKey = PrivateKeyCreate(ctx->para);
        if (ctx->privateKey == NULL) {
            CRYPT_MCELIECE_FreeCtx(ctx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
        MceliecePrvKeyCopy(ctx->privateKey, src->privateKey, ctx->para);
    }
    return ctx;
}

void CRYPT_MCELIECE_FreeCtx(CRYPT_MCELIECE_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->publicKey != NULL) {
        PublicKeyFree(ctx->publicKey);
    }
    if (ctx->privateKey != NULL) {
        PrivateKeyFree(ctx->privateKey, ctx->para);
    }
    BSL_SAL_FREE(ctx);
}

int32_t CRYPT_MCELIECE_EncapsInit(CRYPT_MCELIECE_Ctx *ctx, const BSL_Param *params)
{
    (void)ctx;
    (void)params;
    return CRYPT_SUCCESS; // GF tables are pre-computed, no initialization needed
}

int32_t CRYPT_MCELIECE_DecapsInit(CRYPT_MCELIECE_Ctx *ctx, const BSL_Param *params)
{
    (void)ctx;
    (void)params;
    return CRYPT_SUCCESS; // GF tables are pre-computed, no initialization needed
}

int32_t CRYPT_MCELIECE_Encaps(CRYPT_MCELIECE_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen, uint8_t *sharedSecret,
                              uint32_t *ssLen)
{
    if (ctx == NULL || ctLen == NULL || ciphertext == NULL || sharedSecret == NULL || ssLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEYINFO_NOT_SET);
        return CRYPT_MCELIECE_KEYINFO_NOT_SET;
    }
    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_ABSENT_PUBKEY);
        return CRYPT_MCELIECE_ABSENT_PUBKEY;
    }
    if (*ctLen < (uint32_t)ctx->para->cipherBytes || *ssLen < (uint32_t)ctx->para->sharedKeyBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
        return CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH;
    }
    int32_t ret = McElieceEncapsInternal(ctx, ciphertext, sharedSecret, ctx->para->pc != 0);
    if (ret == CRYPT_SUCCESS) {
        *ctLen = ctx->para->cipherBytes;
        *ssLen = ctx->para->sharedKeyBytes;
    }
    return ret;
}

int32_t CRYPT_MCELIECE_Decaps(CRYPT_MCELIECE_Ctx *ctx, const uint8_t *ciphertext, uint32_t ctLen, uint8_t *sharedSecret,
                              uint32_t *ssLen)
{
    if (ctx == NULL || ssLen == NULL || ciphertext == NULL || sharedSecret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEYINFO_NOT_SET);
        return CRYPT_MCELIECE_KEYINFO_NOT_SET;
    }
    if (ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_ABSENT_PRVKEY);
        return CRYPT_MCELIECE_ABSENT_PRVKEY;
    }
    if (ctLen != (uint32_t)ctx->para->cipherBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_INVALID_CIPHER);
        return CRYPT_MCELIECE_INVALID_CIPHER;
    }
    if (*ssLen < (uint32_t)ctx->para->sharedKeyBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
        return CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH;
    }
    int32_t ret = McElieceDecapsInternal(ciphertext, ctx->privateKey, sharedSecret, ctx->para, ctx->para->pc != 0);
    if (ret == CRYPT_SUCCESS) {
        *ssLen = ctx->para->sharedKeyBytes;
    }
    return ret;
}
#endif
