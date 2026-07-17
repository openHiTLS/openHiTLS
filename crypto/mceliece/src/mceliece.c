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
#ifdef HITLS_CRYPTO_MCELIECE
#include <string.h>

#include "crypt_mceliece.h"
#include "bsl_sal.h"
#include "crypt_params_key.h"
#include "mceliece_local.h"
#include "crypt_types.h"
#include "bsl_err_internal.h"
#include "crypt_util_rand.h"
#include "crypt_util_ctrl.h"
#include "bsl_bytes.h"
#include "crypt_utils.h"
#include "eal_md_local.h"

#define CHECK_IF_NULL_RET(PTR, RET)  \
    do {                             \
        if ((PTR) == NULL) {           \
            BSL_ERR_PUSH_ERROR(RET); \
            return (RET);              \
        }                            \
    } while (0)

static McelieceParams g_allMcelieceParams[] = {
    /* [PQC_ALG_ID_MCELIECE_6688128] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6688128,
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664,
        .k = 5024,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 836,
        .mtBytes = 208,
        .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 208,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6688128_F] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6688128_F,
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664,
        .k = 5024,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 836,
        .mtBytes = 208,
        .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 208,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6688128_PC] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6688128_PC,
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664,
        .k = 5024,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 836,
        .mtBytes = 208,
        .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 240,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_6688128_PCF] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6688128_PCF,
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664,
        .k = 5024,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 836,
        .mtBytes = 208,
        .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 240,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6960119,
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547,
        .k = 5413,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 870,
        .mtBytes = 194,
        .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 194,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119_F] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6960119_F,
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547,
        .k = 5413,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 870,
        .mtBytes = 194,
        .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 194,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119_PC] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6960119_PC,
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547,
        .k = 5413,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 870,
        .mtBytes = 194,
        .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 226,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119_PCF] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6960119_PCF,
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547,
        .k = 5413,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 870,
        .mtBytes = 194,
        .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 226,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_8192128] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_8192128,
        .m = 13,
        .n = 8192,
        .t = 128,
        .mt = 1664,
        .k = 6528,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 1024,
        .mtBytes = 208,
        .kBytes = 816,
        .privateKeyBytes = 14120,
        .publicKeyBytes = 1357824,
        .cipherBytes = 208,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_8192128_F] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_8192128_F,
        .m = 13,
        .n = 8192,
        .t = 128,
        .mt = 1664,
        .k = 6528,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 1024,
        .mtBytes = 208,
        .kBytes = 816,
        .privateKeyBytes = 14120,
        .publicKeyBytes = 1357824,
        .cipherBytes = 208,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_8192128_PC] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_8192128_PC,
        .m = 13,
        .n = 8192,
        .t = 128,
        .mt = 1664,
        .k = 6528,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 1024,
        .mtBytes = 208,
        .kBytes = 816,
        .privateKeyBytes = 14120,
        .publicKeyBytes = 1357824,
        .cipherBytes = 240,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_8192128_PCF] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_8192128_PCF,
        .m = 13,
        .n = 8192,
        .t = 128,
        .mt = 1664,
        .k = 6528,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 1024,
        .mtBytes = 208,
        .kBytes = 816,
        .privateKeyBytes = 14120,
        .publicKeyBytes = 1357824,
        .cipherBytes = 240,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 1,
    },
};

static McelieceParams *McelieceGetParamsById(int32_t algId)
{
    const int32_t base = CRYPT_KEM_TYPE_MCELIECE_6688128;
    const int32_t max = CRYPT_KEM_TYPE_MCELIECE_8192128_PCF;

    if (algId > max || algId < base) {
        return NULL;
    }

    return &g_allMcelieceParams[algId - base];
}

static void PrivateKeyFree(CMPrivateKey *sk, const McelieceParams *params)
{
    if (sk != NULL) {
        if (sk->controlbits != NULL) {
            BSL_SAL_CleanseData(sk->controlbits, sk->controlbitsLen);
            BSL_SAL_FREE(sk->controlbits);
        }
        GFPolyFree(sk->g);
        if (sk->alpha != NULL) {
            BSL_SAL_CleanseData(sk->alpha, MCELIECE_Q * (uint32_t)sizeof(uint16_t));
            BSL_SAL_FREE(sk->alpha);
        }
        if (sk->s != NULL) {
            BSL_SAL_CleanseData(sk->s, params->nBytes);
            BSL_SAL_FREE(sk->s);
        }
        BSL_SAL_CleanseData(sk->delta, MCELIECE_L_BYTES);
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
    uint32_t cbLen = (((2 * params->m - 1) * MCELIECE_Q / 2) + 7) / 8;
    sk->controlbitsLen = cbLen;

    sk->controlbits = BSL_SAL_Malloc(sk->controlbitsLen);
    if (sk->controlbits == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        PrivateKeyFree(sk, params);
        return NULL;
    }

    // init Goppa poly
    sk->g = GFPolyCreate(params->t);
    if (sk->g == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        PrivateKeyFree(sk, params);
        return NULL;
    }
    sk->alpha = BSL_SAL_Calloc(MCELIECE_Q, sizeof(uint16_t));
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
    CRYPT_MCELIECE_Ctx *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_MCELIECE_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
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

static int32_t McelieceParsePrvKey(uint8_t *prvKeyBuf, CMPrivateKey *sk, const McelieceParams *params)
{
    uint8_t *p = prvKeyBuf;
    /* 1. delta 32 B */
    memcpy(sk->delta, p, MCELIECE_L_BYTES);
    p += MCELIECE_L_BYTES;
    /* 2. c (pivot mask) 8 B */
    sk->c = GET_UINT64_LE(p, 0);
    p += 8;

    /* 3. g (irr polynomial) */
    for (uint32_t i = 0; i < params->t; i++) {
        uint16_t temp = ((uint16_t)p[1] << 8) | p[0];
        GFPolySetCoeff(sk->g, i, temp);
        p += 2;
    }
    GFPolySetCoeff(sk->g, params->t, 1);

    /* 4. controlbits */
    memcpy(sk->controlbits, p, sk->controlbitsLen);
    p += sk->controlbitsLen;
    int32_t ret = SupportSetFromControlbits(sk->alpha, sk->controlbits, params->m, MCELIECE_Q);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* 5. s (random string) */
    memcpy(sk->s, p, params->nBytes);
    return CRYPT_SUCCESS;
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
    if (ctx->para->privateKeyBytes > prv->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
        return CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH;
    }

    ctx->privateKey = PrivateKeyCreate(ctx->para);
    if (ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = McelieceParsePrvKey(prv->value, ctx->privateKey, ctx->para);
    if (ret != CRYPT_SUCCESS) {
        PrivateKeyFree(ctx->privateKey, ctx->para);
        ctx->privateKey = NULL;
        return ret;
    }
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
    if (ctx->para->publicKeyBytes > pub->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
        return CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH;
    }
    ctx->publicKey = PublicKeyCreate(ctx->para);
    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t useLen = ctx->para->publicKeyBytes;
    memcpy(ctx->publicKey->matT.data, pub->value, useLen);
    return CRYPT_SUCCESS;
}

static void McelieceExportPrvKey(const CMPrivateKey *sk, uint8_t *prvKeyBuf, const McelieceParams *params)
{
    uint8_t *p = prvKeyBuf;
    /* 1. delta 32 B */
    memcpy(p, sk->delta, MCELIECE_L_BYTES);
    p += MCELIECE_L_BYTES;
    /* 2. c (pivot mask) 8 B */
    PUT_UINT64_LE(sk->c, p, 0);
    p += 8;

    /* 3. g (irr polynomial) */
    for (uint32_t i = 0; i < params->t; i++) {
        uint16_t coeff = GFPolyGetCoeff(sk->g, i);
        p[0] = coeff & 0xFF;
        p[1] = (coeff >> 8) & 0xFF;
        p += 2;
    }

    /* 4. controlbits */
    memcpy(p, sk->controlbits, sk->controlbitsLen);
    p += sk->controlbitsLen;

    /* 5. s (random string) */
    memcpy(p, sk->s, params->nBytes);
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
    if (ctx->para->privateKeyBytes > prv->valueLen) {
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
    if (ctx->para->publicKeyBytes > pub->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
        return CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH;
    }
    uint32_t useLen = ctx->para->publicKeyBytes;
    memcpy(pub->value, ctx->publicKey->matT.data, useLen);
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
    if (ConstTimeMemcmp(ctx1->privateKey->delta, ctx2->privateKey->delta, MCELIECE_L_BYTES) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    if (GFPolyConstTimeEqual(ctx1->privateKey->g, ctx2->privateKey->g) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    if (ctx1->privateKey->controlbitsLen != ctx2->privateKey->controlbitsLen ||
        ConstTimeMemcmp(ctx1->privateKey->controlbits, ctx2->privateKey->controlbits,
                        ctx1->privateKey->controlbitsLen) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEY_NOT_EQUAL);
        return CRYPT_MCELIECE_KEY_NOT_EQUAL;
    }
    if (ConstTimeMemcmp(ctx1->privateKey->s, ctx2->privateKey->s, ctx1->para->nBytes) == 0) {
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
    GFPolyCopy(dest->g, src->g);
    dest->c = src->c;
    memcpy(dest->delta, src->delta, MCELIECE_L_BYTES);
    memcpy(dest->alpha, src->alpha, sizeof(uint16_t) * MCELIECE_Q);
    memcpy(dest->s, src->s, params->nBytes);
    memcpy(dest->controlbits, src->controlbits, src->controlbitsLen);
}

static void MceliecePubKeyCopy(CMPublicKey *dest, const CMPublicKey *src, const McelieceParams *params)
{
    dest->matT.rows = src->matT.rows;
    dest->matT.cols = src->matT.cols;
    dest->matT.colsBytes = src->matT.colsBytes;
    memcpy(dest->matT.data, src->matT.data, params->publicKeyBytes);
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

// K = Hash(prefix, e, C)
static int32_t ComputeSessionKeyWithPrefix(uint8_t *sessionKey, uint8_t prefix, const uint8_t *e, const uint8_t *c,
    const McelieceParams *params)
{
    uint32_t inLen = 1 + params->nBytes + params->cipherBytes;
    uint8_t *hashIn = BSL_SAL_Malloc(inLen);
    if (hashIn == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    hashIn[0] = prefix;
    memcpy(hashIn + 1, e, params->nBytes);
    memcpy(hashIn + 1 + params->nBytes, c, params->cipherBytes);
    int32_t ret = McElieceShake256(sessionKey, MCELIECE_L_BYTES, hashIn, inLen);
    BSL_SAL_ClearFree(hashIn, inLen);
    return ret;
}

int32_t McElieceShake256(uint8_t *output, const uint32_t outlen, const uint8_t *input, uint32_t inLen)
{
    uint32_t len = outlen;
    return EAL_Md(CRYPT_MD_SHAKE256, NULL, NULL, input, inLen, output, &len, false, false);
}

int32_t McElieceEncapsInternal(CRYPT_MCELIECE_Ctx *ctx, uint8_t *ciphertext, uint8_t *sessionKey, bool isPc)
{
    int32_t ret;
    uint8_t *c0 = ciphertext;
    uint8_t *c1 = ciphertext + ctx->para->cipherBytes - MCELIECE_L_BYTES;
    memset(c0, 0, ctx->para->cipherBytes);
    uint8_t *e = BSL_SAL_Malloc(ctx->para->nBytes);
    if (e == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(FixedWeightVector(ctx, e), ret);
    EncodeVector(e, &ctx->publicKey->matT, c0, ctx->para);
    if (isPc) {
        // PC only: C1 = H(2, e)
        uint8_t hashIn[1 + MCELIECE_NBYTES_MAX];
        hashIn[0] = 2;
        memcpy(hashIn + 1, e, ctx->para->nBytes);
        GOTO_ERR_IF(McElieceShake256(c1, MCELIECE_L_BYTES, hashIn, ctx->para->nBytes + 1), ret);
    }
    uint8_t prefix = 1;
    ret = ComputeSessionKeyWithPrefix(sessionKey, prefix, e, ciphertext, ctx->para);
ERR:
    BSL_SAL_CleanseData(e, ctx->para->nBytes);
    BSL_SAL_FREE(e);
    return ret;
}

static int32_t BuildVectorAndDecoding(const uint8_t *c0, const CMPrivateKey *sk, const McelieceParams *params,
    uint8_t *e, uint16_t *decodeSyndrome)
{
    uint8_t *v = BSL_SAL_Calloc(params->nBytes, 1);
    if (v == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    for (uint32_t i = 0; i < params->mt; i++) {
        uint32_t bit = VectorGetBit(c0, i);
        VectorSetBitMasked(v, i, bit);
    }
    int32_t ret = DecodeGoppa(v, sk->g, sk->alpha, params, e, decodeSyndrome);
    BSL_SAL_FREE(v);
    return ret;
}

// Decap algorithm (unified for both pc and non-pc parameter sets)
int32_t McElieceDecapsInternal(const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey,
    const McelieceParams *params, bool isPc)
{
    int32_t ret;
    const uint8_t *c0 = ciphertext;
    const uint8_t *c1 = ciphertext + params->cipherBytes - MCELIECE_L_BYTES;
    // e + decodeSyndrome + veirfySyndrome: params->nBytes || 2 * params->t * sizeof(uint16_t) || 2 * params->t * sizeof(uint16_t)
    uint32_t memPoolBytes = params->nBytes + 4U * params->t * (uint32_t)sizeof(uint16_t);
    uint8_t *memPool = BSL_SAL_Calloc(memPoolBytes, 1U);
    if (memPool == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint8_t *e = memPool;
    uint16_t *decodeSyndrome = (uint16_t *)(memPool + params->nBytes);
    uint16_t *verifySyndrome = (uint16_t *)(memPool + params->nBytes + 2U * params->t * sizeof(uint16_t));
    GOTO_ERR_IF(BuildVectorAndDecoding(c0, sk, params, e, decodeSyndrome), ret);
    // Recompute syndrome from e
    GOTO_ERR_IF(ComputeSyndrome(e, sk->g, sk->alpha, params, verifySyndrome), ret);
    // Verify decodeSyndrome == verifySyndrome
    uint32_t mask = ConstTimeMemcmp((uint8_t *)decodeSyndrome, (uint8_t *)verifySyndrome,
        2U * params->t * (uint32_t)sizeof(uint16_t));
    // Verify error weight == t
    mask &= Uint32ConstTimeEqual(VectoWeight(e, params->nBytes), params->t);
    if (isPc) {
        // PC only: verify C1
        uint8_t hashIn[1 + MCELIECE_NBYTES_MAX];
        hashIn[0] = 2;
        memcpy(hashIn + 1, e, params->nBytes);
        uint8_t c1Prime[MCELIECE_L_BYTES];
        GOTO_ERR_IF(McElieceShake256(c1Prime, MCELIECE_L_BYTES, hashIn, 1 + params->nBytes), ret);
        mask &= ConstTimeMemcmp(c1Prime, c1, MCELIECE_L_BYTES); // If C' != C1, set b <- 0
    }
    // b = 1 if errorWeight == t, 0 otherwise
    uint8_t b = (1 & mask) | (0 & (~mask));
    // if mask is invalid (0), e[i] = s[i], refernce: https://classic.mceliece.org/mceliece-spec-20221023.pdf, Section 5.6
    for (uint32_t i = 0; i < params->nBytes; i++) {
        e[i] = (e[i] & mask) | (sk->s[i] & ~mask);
    }
    ret = ComputeSessionKeyWithPrefix(sessionKey, b, e, ciphertext, params);
ERR:
    BSL_SAL_ClearFree(memPool, memPoolBytes);
    return ret;
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
    if (*ctLen < ctx->para->cipherBytes || *ssLen < ctx->para->sharedKeyBytes) {
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
    if (ctLen != ctx->para->cipherBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_INVALID_CIPHER);
        return CRYPT_MCELIECE_INVALID_CIPHER;
    }
    if (*ssLen < ctx->para->sharedKeyBytes) {
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
