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

#include "mceliece.h"
#include "mceliece_kem.h"
#include "mceliece_types.h"
#include "bsl_sal.h"
#include "mceliece_keygen.h"
#include "securec.h"
#include "pqcp_err.h"
#include "pqcp_types.h"

static int McelieceKeypair(const McelieceParams *params, CMPublicKey *pk, CMPrivateKey *sk)
{
    McElieceError ret;
    if (params->semi) {
        ret = McElieceKeygenSemi(pk, sk, params);
    } else {
        ret = McElieceKeygen(pk, sk, params);
    }

    if (ret != MCELIECE_SUCCESS) {
        return ret;
    }
    return PQCP_SUCCESS;
};

static int McelieceEncaps(const McelieceParams *params, uint8_t *ss, uint8_t *ct, const CMPublicKey *pk)
{
    McElieceError ret;
    if (params->pc) {
        ret = McElieceEncapsPC(ct, pk, ss, params);
    } else {
        ret = McElieceEncaps(ct, pk, ss, params);
    }

    if (ret != MCELIECE_SUCCESS) {
        return ret;
    }

    return PQCP_SUCCESS;
};

static int McelieceDecaps(const McelieceParams *params, uint8_t *ss, const uint8_t *ct, const CMPrivateKey *sk)
{
    McElieceError ret;
    if (params->pc) {
        ret = McElieceDecapPC(ct, sk, ss, params);
    } else {
        ret = McElieceDecaps(ct, sk, ss, params);
    }

    if (ret != MCELIECE_SUCCESS) {
        return ret;
    }

    return PQCP_SUCCESS;
};

void *PQCP_MCELIECE_NewCtx(void)
{
    Mceliece_Ctx *ctx = BSL_SAL_Malloc(sizeof(Mceliece_Ctx));
    if (ctx == NULL) {
        return NULL;
    }
    (void)memset_s(ctx, sizeof(Mceliece_Ctx), 0, sizeof(Mceliece_Ctx));

    return ctx;
}

int32_t PQCP_MCELIECE_Gen(Mceliece_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL) {
        return PQCP_NULL_INPUT;
    }

    if (ctx->publicKey != NULL) {
        PublicKeyFree(ctx->publicKey);
    }

    if (ctx->privateKey != NULL) {
        PrivateKeyFree(ctx->privateKey);
    }

    ctx->publicKey = PublicKeyCreate(ctx->para);
    if (ctx->publicKey == NULL) {
        return PQCP_MALLOC_FAIL;
    }

    ctx->privateKey = PrivateKeyCreate(ctx->para);
    if (ctx->privateKey == NULL) {
        PublicKeyFree(ctx->publicKey);
        return PQCP_MALLOC_FAIL;
    }

    int32_t ret = McelieceKeypair(ctx->para, ctx->publicKey, ctx->privateKey);

    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }

    return PQCP_SUCCESS;

EXIT:
    if (ctx->publicKey != NULL) {
        PublicKeyFree(ctx->publicKey);
    }
    if (ctx->privateKey != NULL) {
        PrivateKeyFree(ctx->privateKey);
    }
    return ret;
}

int32_t PQCP_MCELIECE_SetPrvKey(Mceliece_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    const BSL_Param *prv = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_MCELIECE_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->privateKeyBytes > prv->valueLen) {
        return PQCP_MCELIECE_INVALID_ARG;
    }
    if (ctx->privateKey == NULL) {
        ctx->privateKey = PrivateKeyCreate(ctx->para);
        if (ctx->privateKey == NULL) {
            return PQCP_MEM_ALLOC_FAIL;
        }
    }

    if (prv->valueLen != ctx->para->privateKeyBytes) {
        return PQCP_MCELIECE_INVALID_ARG;
    }
    uint8_t *p = prv->value;

    // 1. delta 32 B
    memcpy_s(ctx->privateKey->delta, MCELIECE_L_BYTES, p, MCELIECE_L_BYTES);
    p += MCELIECE_L_BYTES;

    // 2. c (pivot mask) 8 B
    ctx->privateKey->c = CMLoad8(p);
    p += 8;

    // 3. g (irr polynomial) 256 B = MCELIECE_T * 2
    for (int i = 0, j = 0; i < 2 * (ctx->para->t); i += 2, j++) {
        uint16_t temp = 0;
        temp = (uint16_t)(p[1]) << 8;
        temp |= (uint16_t)p[0];
        temp &= 0xFFFF;
        ctx->privateKey->g.coeffs[j] = temp;
        p += 2;
    }

    // 4. controlbits
    memcpy_s(ctx->privateKey->controlbits, ctx->privateKey->controlbitsLen, p, ctx->privateKey->controlbitsLen);
    p += ctx->privateKey->controlbitsLen;

    // 5. s (random string)
    memcpy_s(ctx->privateKey->s, ctx->para->nBytes, p, ctx->para->nBytes);

    return PQCP_SUCCESS;
}

int32_t PQCP_MCELIECE_SetPubKey(Mceliece_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    const BSL_Param *pub = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_MCELIECE_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->publicKeyBytes > pub->valueLen) {
        return PQCP_MCELIECE_INVALID_ARG;
    }
    if (ctx->publicKey == NULL) {
        ctx->publicKey = PublicKeyCreate(ctx->para);
        if (ctx->publicKey == NULL) {
            return PQCP_MEM_ALLOC_FAIL;
        }
    }

    uint32_t useLen = ctx->para->publicKeyBytes;
    (void)memcpy_s(ctx->publicKey->matT.data, useLen, pub->value, useLen);
    return PQCP_SUCCESS;
}

int32_t PQCP_MCELIECE_GetPrvKey(Mceliece_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    BSL_Param *prv = BSL_PARAM_FindParam(param, CRYPT_PARAM_MCELIECE_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->privateKey == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (sizeof(CMPrivateKey) > prv->valueLen) {
        return PQCP_MCELIECE_INVALID_ARG;
    }

    uint8_t *p = prv->value;

    // 1. delta 32 B
    memcpy_s(p, MCELIECE_L_BYTES, ctx->privateKey->delta, MCELIECE_L_BYTES);
    p += MCELIECE_L_BYTES;

    // 2. c (pivot mask) 8 B
    CMStore8(p, ctx->privateKey->c);
    p += 8;

    // 3. g (irr polynomial) 256 B = MCELIECE_T * 2
    for (int i = 0; i < ctx->para->t; i++) {
        p[0] = ctx->privateKey->g.coeffs[i] & 0xFF;         // low 8 bits
        p[1] = (ctx->privateKey->g.coeffs[i] >> 8) & 0xFF;  // high 8 bits
        p += 2;
    }

    // 4. controlbits
    memcpy_s(p, ctx->privateKey->controlbitsLen, ctx->privateKey->controlbits, ctx->privateKey->controlbitsLen);
    p += ctx->privateKey->controlbitsLen;

    // 5. s (random string)
    memcpy_s(p, ctx->para->nBytes, ctx->privateKey->s, ctx->para->nBytes);

    prv->useLen = ctx->para->privateKeyBytes;

    return PQCP_SUCCESS;
}

int32_t PQCP_MCELIECE_GetPubKey(Mceliece_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL) {
        return PQCP_NULL_INPUT;
    }
    BSL_Param *pub = BSL_PARAM_FindParam(param, CRYPT_PARAM_MCELIECE_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->publicKey == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->para->publicKeyBytes > pub->valueLen) {
        return PQCP_MCELIECE_INVALID_ARG;
    }
    uint32_t useLen = ctx->para->publicKeyBytes;
    (void)memcpy_s(pub->value, useLen, ctx->publicKey->matT.data, useLen);
    pub->useLen = useLen;
    return PQCP_SUCCESS;
}

int32_t PQCP_MCELIECE_Ctrl(Mceliece_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL) {
        return PQCP_NULL_INPUT;
    }
    switch (cmd) {
        case PQCP_MCELIECE_ALG_PARAMS: {
            if (val == NULL || valLen != sizeof(uint32_t)) {
                return PQCP_NULL_INPUT;
            }
            int32_t algId = *(int32_t *)val;
            ctx->para = McelieceGetParamsById(algId);
            if (ctx->para == NULL) {
                return PQCP_MCELIECE_INVALID_ARG;
            }
            return PQCP_SUCCESS;
        }
        case PQCP_MCELIECE_GET_PARA: {
            if (ctx->para == NULL || val == NULL || valLen != sizeof(McelieceParams)) {
                return PQCP_NULL_INPUT;
            }
            (void)memcpy_s(val, sizeof(McelieceParams), ctx->para, sizeof(McelieceParams));
            return PQCP_SUCCESS;
        }
        case PQCP_MCELIECE_GET_CIPHERLEN: {
            if (ctx->para == NULL || val == NULL || valLen != sizeof(uint32_t)) {
                return PQCP_NULL_INPUT;
            }
            *(uint32_t *)val = ctx->para->cipherBytes;
            return PQCP_SUCCESS;
        }
        case PQCP_MCELIECE_GET_SECBITS: {
            if (ctx->para == NULL || val == NULL || valLen != sizeof(uint32_t)) {
                return PQCP_NULL_INPUT;
            }
            *(uint32_t *)val = ctx->para->sharedKeyBytes * 8;
            return PQCP_SUCCESS;
        }
        default:
            return PQCP_MCELIECE_INVALID_ARG;
    }
}

int32_t PQCP_MCELIECE_Cmp(Mceliece_Ctx *ctx1, Mceliece_Ctx *ctx2)
{
    if (ctx1 == NULL || ctx2 == NULL || ctx1->para == NULL || ctx2->para == NULL) {
        return PQCP_NULL_INPUT;
    }

    if (ctx1->publicKey != NULL && ctx2->publicKey != NULL) {
        if ((ctx1->para->publicKeyBytes != ctx2->para->publicKeyBytes) ||
            (memcmp(ctx1->publicKey->matT.data, ctx2->publicKey->matT.data, ctx1->para->publicKeyBytes) != 0)) {
            return PQCP_MCELIECE_CMP_FALSE;
        }
        if ((ctx1->publicKey->matT.cols != ctx2->publicKey->matT.cols) ||
            (ctx1->publicKey->matT.rows != ctx2->publicKey->matT.rows) ||
            (ctx1->publicKey->matT.colsBytes != ctx2->publicKey->matT.colsBytes)) {
            return PQCP_MCELIECE_CMP_FALSE;
        }
    } else {
        return PQCP_MCELIECE_CMP_FALSE;
    }

    if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
        if (memcmp(ctx1->privateKey->delta, ctx2->privateKey->delta, MCELIECE_L_BYTES) != 0) {
            return PQCP_MCELIECE_CMP_FALSE;
        }
        if (memcmp(ctx1->privateKey->g.coeffs, ctx2->privateKey->g.coeffs, ctx1->para->t * sizeof(GFElement)) != 0) {
            return PQCP_MCELIECE_CMP_FALSE;
        }
        if ((ctx1->privateKey->controlbitsLen != ctx2->privateKey->controlbitsLen) ||
            (memcmp(ctx1->privateKey->controlbits, ctx2->privateKey->controlbits, ctx1->privateKey->controlbitsLen) !=
                0)) {
            return PQCP_MCELIECE_CMP_FALSE;
        }
        if (memcmp(ctx1->privateKey->s, ctx2->privateKey->s, ctx1->para->nBytes) != 0) {
            return PQCP_MCELIECE_CMP_FALSE;
        }
        if (ctx1->privateKey->c != ctx2->privateKey->c) {
            return PQCP_MCELIECE_CMP_FALSE;
        }
    } else {
        return PQCP_MCELIECE_CMP_FALSE;
    }

    return PQCP_SUCCESS;
}

Mceliece_Ctx *PQCP_MCELIECE_DupCtx(Mceliece_Ctx *src)
{
    if (src == NULL) {
        return NULL;
    }
    Mceliece_Ctx *ctx = PQCP_MCELIECE_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    if (src->para != NULL) {
        ctx->para = BSL_SAL_Malloc(sizeof(McelieceParams));
        if (ctx->para == NULL) {
            PQCP_MCELIECE_FreeCtx(ctx);
            return NULL;
        }
        (void)memcpy_s(ctx->para, sizeof(McelieceParams), src->para, sizeof(McelieceParams));
    }
    if (src->publicKey != NULL) {
        ctx->publicKey = PublicKeyCreate(ctx->para);
        if (ctx->publicKey == NULL) {
            PQCP_MCELIECE_FreeCtx(ctx);
            return NULL;
        }
        (void)memcpy_s(ctx->publicKey, sizeof(CMPublicKey), src->publicKey, sizeof(CMPublicKey));
        (void)memcpy_s(
            ctx->publicKey->matT.data, ctx->para->publicKeyBytes, src->publicKey->matT.data, ctx->para->publicKeyBytes);
    }
    if (src->privateKey != NULL) {
        ctx->privateKey = PrivateKeyCreate(ctx->para);
        if (ctx->privateKey == NULL) {
            PQCP_MCELIECE_FreeCtx(ctx);
            return NULL;
        }
        (void)memcpy_s(ctx->privateKey, sizeof(CMPrivateKey), src->privateKey, sizeof(CMPrivateKey));
        (void)memcpy_s(ctx->privateKey->alpha,
            sizeof(GFElement) * MCELIECE_Q,
            src->privateKey->alpha,
            sizeof(GFElement) * MCELIECE_Q);
        (void)memcpy_s(ctx->privateKey->s, ctx->para->nBytes, src->privateKey->s, src->para->nBytes);
        (void)memcpy_s(
            ctx->privateKey->controlbits, ctx->privateKey->controlbitsLen, src->privateKey->s, src->para->nBytes);
        (void)memcpy_s(ctx->privateKey->g.coeffs,
            ctx->para->t * sizeof(GFElement),
            src->privateKey->g.coeffs,
            src->para->t * sizeof(GFElement));
    }
    return ctx;
}

void PQCP_MCELIECE_FreeCtx(Mceliece_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->publicKey != NULL) {
        PublicKeyFree(ctx->publicKey);
    }
    if (ctx->privateKey != NULL) {
        PrivateKeyFree(ctx->privateKey);
    }
    BSL_SAL_FREE(ctx);
}

int32_t PQCP_MCELIECE_EncapsInit(Mceliece_Ctx *ctx, const BSL_Param *params)
{
    (void)ctx;
    (void)params;
    return 0;
}

int32_t PQCP_MCELIECE_DecapsInit(Mceliece_Ctx *ctx, const BSL_Param *params)
{
    (void)ctx;
    (void)params;
    return 0;
}

int32_t PQCP_MCELIECE_Encaps(
    Mceliece_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen, uint8_t *sharedSecret, uint32_t *ssLen)
{
    if (ctx == NULL || ctx->para == NULL || ctx->publicKey == NULL || ciphertext == NULL || sharedSecret == NULL) {
        return PQCP_NULL_INPUT;
    }

    return McelieceEncaps(ctx->para, sharedSecret, ciphertext, ctx->publicKey);
}

int32_t PQCP_MCELIECE_Decaps(
    Mceliece_Ctx *ctx, const uint8_t *ciphertext, uint32_t ctLen, uint8_t *sharedSecret, uint32_t *ssLen)
{
    if (ctx == NULL || ctx->para == NULL || ctx->privateKey == NULL || ciphertext == NULL || sharedSecret == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctLen != ctx->para->cipherBytes) {
        return PQCP_MCELIECE_INVALID_ARG;
    }

    return McelieceDecaps(ctx->para, sharedSecret, ciphertext, ctx->privateKey);
}