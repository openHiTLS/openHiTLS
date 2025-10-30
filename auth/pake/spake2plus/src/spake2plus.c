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

#include <string.h>
#include <stdbool.h>
#include "auth_pake.h"
#include "crypt_ecc.h"
#include "spake2plus_ecc.h"
#include "auth_errno.h"
#include "securec.h"
#include "crypt_bn.h"
#include "crypt_eal_md.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_pkey.h"
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"

#include "spake2plus.h"

#define SPAKE2PLUS_INVALID_ALG_INDEX 0xFF
#define MAX_ECC_PARAM_LEN 66  // Maximum length of elliptic curve parameters (in bytes)
#define MAX_ECC_KEY_LEN  133  // Maximum length of elliptic curve public key (in bytes)
#define LITTLE_BYTEORDER_LEN 8 // Length for little-endian byte order representation of 64-bit values
#define MAX_KEY_LEN 64

typedef struct Spake2plusCtx {
    uint8_t index;
    BSL_Buffer w0;
    BSL_Buffer w1;
    BSL_Buffer l;
    BSL_Buffer x;
    BSL_Buffer share;
    BSL_Buffer key_shared;
    BSL_Buffer confirmP;
    BSL_Buffer confirmV;
    BSL_Buffer m;
    BSL_Buffer n;
} Spake2plusCtx;

typedef enum {
    ECC_PARAM_P,
    ECC_PARAM_N
} EccParamType;

typedef struct {
    CRYPT_PKEY_ParaId curveId;
    CRYPT_MD_AlgId hashId;
    CRYPT_KDF_HKDF_AlgId kdfId;
    CRYPT_MAC_AlgId macId;
    uint16_t hashKeyLen;
    uint16_t macKeyLen;
} Spake2Plus_AlgInfo;

static Spake2Plus_AlgInfo g_spake2PlusAlgInfo[] = {
    {CRYPT_ECC_NISTP256, CRYPT_MD_SHA256, CRYPT_HKDF_SHA256, CRYPT_MAC_HMAC_SHA256, 32, 32},
    {CRYPT_ECC_NISTP256, CRYPT_MD_SHA512, CRYPT_HKDF_SHA512, CRYPT_MAC_HMAC_SHA512, 64, 64},
    {CRYPT_ECC_NISTP384, CRYPT_MD_SHA256, CRYPT_HKDF_SHA256, CRYPT_MAC_HMAC_SHA256, 32, 32},
    {CRYPT_ECC_NISTP384, CRYPT_MD_SHA512, CRYPT_HKDF_SHA512, CRYPT_MAC_HMAC_SHA512, 64, 64},
    {CRYPT_ECC_NISTP521, CRYPT_MD_SHA512, CRYPT_HKDF_SHA512, CRYPT_MAC_HMAC_SHA512, 64, 64},
    {CRYPT_ECC_NISTP256, CRYPT_MD_SHA256, CRYPT_HKDF_SHA256, CRYPT_MAC_CMAC_AES128, 32, 16},
    {CRYPT_ECC_NISTP256, CRYPT_MD_SHA512, CRYPT_HKDF_SHA512, CRYPT_MAC_CMAC_AES128, 64, 16},
};

void Spake2PlusFreeCtx(Spake2plusCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    BSL_SAL_ClearFree(ctx->w0.data, ctx->w0.dataLen);
    BSL_SAL_ClearFree(ctx->w1.data, ctx->w1.dataLen);
    BSL_SAL_ClearFree(ctx->l.data, ctx->l.dataLen);
    BSL_SAL_ClearFree(ctx->x.data, ctx->x.dataLen);
    BSL_SAL_ClearFree(ctx->share.data, ctx->share.dataLen);
    BSL_SAL_ClearFree(ctx->key_shared.data, ctx->key_shared.dataLen);
    BSL_SAL_ClearFree(ctx->confirmP.data, ctx->confirmP.dataLen);
    BSL_SAL_ClearFree(ctx->confirmV.data, ctx->confirmV.dataLen);
    BSL_SAL_ClearFree(ctx, sizeof(Spake2plusCtx));
}

int32_t Spake2PlusInitCipherSuite(Spake2plusCtx* ctx, HITLS_AUTH_PAKE_CipherSuite* ciphersuite)
{
    uint8_t position = SPAKE2PLUS_INVALID_ALG_INDEX;

    if (ciphersuite == NULL || ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    for (uint8_t i = 0; i < sizeof(g_spake2PlusAlgInfo) / sizeof(Spake2Plus_AlgInfo); i++) {
        if (ciphersuite->params.spake2plus.curve == g_spake2PlusAlgInfo[i].curveId &&
            ciphersuite->params.spake2plus.hash == g_spake2PlusAlgInfo[i].hashId &&
            ciphersuite->params.spake2plus.kdf == g_spake2PlusAlgInfo[i].kdfId &&
            ciphersuite->params.spake2plus.mac == g_spake2PlusAlgInfo[i].macId) {
            position = i;
            break;
        }
    }

    if (position == SPAKE2PLUS_INVALID_ALG_INDEX) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    ctx->index = position;
    return HITLS_AUTH_SUCCESS;
}

Spake2plusCtx* Spake2PlusNewCtx(CRYPT_PKEY_ParaId curve)
{
    Spake2plusCtx *ctx = (Spake2plusCtx*)BSL_SAL_Calloc(1, sizeof(Spake2plusCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return NULL;
    }

    ctx->w0 = (BSL_Buffer){.data = BSL_SAL_Malloc(MAX_ECC_PARAM_LEN), .dataLen = MAX_ECC_PARAM_LEN};
    ctx->w1 = (BSL_Buffer){.data = BSL_SAL_Malloc(MAX_ECC_PARAM_LEN), .dataLen = MAX_ECC_PARAM_LEN};
    ctx->l = (BSL_Buffer){.data = BSL_SAL_Malloc(MAX_ECC_KEY_LEN), .dataLen = MAX_ECC_KEY_LEN};
    ctx->x = (BSL_Buffer){.data = BSL_SAL_Malloc(MAX_ECC_PARAM_LEN), .dataLen = MAX_ECC_PARAM_LEN};
    ctx->share = (BSL_Buffer){.data = BSL_SAL_Malloc(MAX_ECC_KEY_LEN), .dataLen = MAX_ECC_KEY_LEN};
    ctx->key_shared = (BSL_Buffer){.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};
    ctx->confirmP = (BSL_Buffer){.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};
    ctx->confirmV = (BSL_Buffer){.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};

    if (ctx->w0.data == NULL || ctx->w1.data == NULL || ctx->l.data == NULL || ctx->x.data == NULL ||
        ctx->key_shared.data == NULL || ctx->confirmP.data == NULL || ctx->confirmV.data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_MEM_ALLOC_FAIL);
        goto err;
    }

    if (curve == CRYPT_ECC_NISTP256) {
        ctx->m = (BSL_Buffer){.data = ECC_NISTP256_M, .dataLen = sizeof(ECC_NISTP256_M)};
        ctx->n = (BSL_Buffer){.data = ECC_NISTP256_N, .dataLen= sizeof(ECC_NISTP256_N)};
    }
    if (curve == CRYPT_ECC_NISTP384) {
        ctx->m = (BSL_Buffer){.data = ECC_NISTP384_M, .dataLen = sizeof(ECC_NISTP384_M)};
        ctx->n = (BSL_Buffer){.data = ECC_NISTP384_N, .dataLen = sizeof(ECC_NISTP384_N)};
    }
    if (curve==CRYPT_ECC_NISTP521) {
        ctx->m = (BSL_Buffer){.data = ECC_NISTP521_M, .dataLen = sizeof(ECC_NISTP521_M)};
        ctx->n = (BSL_Buffer){.data = ECC_NISTP521_N, .dataLen = sizeof(ECC_NISTP521_N)};
    }
    return ctx;
err:
    Spake2PlusFreeCtx(ctx);
    return NULL;
}

static int32_t GetPubKeyData(CRYPT_EAL_PkeyCtx *pkey, uint8_t *out, uint32_t *outLen)
{
    CRYPT_EAL_PkeyPub ephemPub = { 0 };
    ephemPub.id = CRYPT_EAL_PkeyGetId(pkey);
    ephemPub.key.eccPub.data = out;
    ephemPub.key.eccPub.len = *outLen;

    int32_t ret = CRYPT_EAL_PkeyGetPub(pkey, &ephemPub);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }

    *outLen = ephemPub.key.eccPub.len;
    return HITLS_AUTH_SUCCESS;
}

static int32_t Spake2PlusGetEcc(CRYPT_EAL_PkeyCtx *pkey, EccParamType type, uint8_t *out, uint32_t *outLen)
{
    uint8_t ecP[MAX_ECC_PARAM_LEN];
    uint8_t ecA[MAX_ECC_PARAM_LEN];
    uint8_t ecB[MAX_ECC_PARAM_LEN];
    uint8_t ecN[MAX_ECC_PARAM_LEN];
    uint8_t ecH[MAX_ECC_PARAM_LEN];
    uint8_t ecX[MAX_ECC_PARAM_LEN];
    uint8_t ecY[MAX_ECC_PARAM_LEN];

    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_EAL_PkeyGetId(pkey);
    para.para.eccPara.p = ecP;
    para.para.eccPara.a = ecA;
    para.para.eccPara.b = ecB;
    para.para.eccPara.n = ecN;
    para.para.eccPara.h = ecH;
    para.para.eccPara.x = ecX;
    para.para.eccPara.y = ecY;
    para.para.eccPara.pLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.aLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.bLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.nLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.hLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.xLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.yLen = MAX_ECC_PARAM_LEN;
    int32_t ret = CRYPT_EAL_PkeyGetPara(pkey, &para);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }

    switch (type) {
        case ECC_PARAM_P:
            (void)memcpy_s(out, para.para.eccPara.pLen, para.para.eccPara.p, para.para.eccPara.pLen);
            *outLen = para.para.eccPara.pLen;
            break;
        case ECC_PARAM_N:
            (void)memcpy_s(out, para.para.eccPara.nLen, para.para.eccPara.n, para.para.eccPara.nLen);
            *outLen = para.para.eccPara.nLen;
            break;
        default:
            return HITLS_AUTH_INVALID_ARG;
    }
    return HITLS_AUTH_SUCCESS;
}

int32_t HITLS_AUTH_Spake2plusReqRegister(HITLS_AUTH_PakeCtx* ctx, CRYPT_EAL_KdfCTX* kdfCtx, BSL_Buffer exist_w0,
    BSL_Buffer exist_w1, BSL_Buffer exist_l)
{
    bool allNull = (exist_w0.data == NULL && exist_w1.data == NULL && exist_l.data == NULL);
    bool allNotNull = (exist_w0.data != NULL && exist_w1.data != NULL && exist_l.data != NULL);

    if (!allNull && !allNotNull) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    Spake2plusCtx *spakeCtx = (Spake2plusCtx *)HITLS_AUTH_PakeGetInternalCtx(ctx);
    if (spakeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_CONTEXT);
        return HITLS_AUTH_PAKE_INVALID_CONTEXT;
    }
    if (allNotNull) {
        spakeCtx->w0.dataLen = exist_w0.dataLen;
        spakeCtx->w1.dataLen = exist_w1.dataLen;
        spakeCtx->l.dataLen = exist_l.dataLen;
        (void)memcpy_s(spakeCtx->w0.data, exist_w0.dataLen, exist_w0.data, exist_w0.dataLen);
        (void)memcpy_s(spakeCtx->w1.data, exist_w1.dataLen, exist_w1.data, exist_w1.dataLen);
        (void)memcpy_s(spakeCtx->l.data, exist_l.dataLen, exist_l.data, exist_l.dataLen);
        return HITLS_AUTH_SUCCESS;
    }

    // data from rfc9383 section 3.2, length>=2*ceil(log2(p))+64 bits
    uint32_t outLen = 0;
    if (g_spake2PlusAlgInfo[spakeCtx->index].curveId == CRYPT_ECC_NISTP256) {
        outLen = 80;
    } else if (g_spake2PlusAlgInfo[spakeCtx->index].curveId == CRYPT_ECC_NISTP384) {
        outLen = 112;
    } else if (g_spake2PlusAlgInfo[spakeCtx->index].curveId == CRYPT_ECC_NISTP521) {
        outLen = 148;
    } else {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }
    uint8_t out[outLen];
    uint8_t w0s[outLen/2];
    uint32_t w0sLen = outLen/2;
    uint8_t w1s[outLen/2];
    uint32_t w1sLen = outLen/2;
    uint8_t p[MAX_ECC_PARAM_LEN];
    uint32_t pLen = MAX_ECC_PARAM_LEN;
    uint8_t w0_data[outLen/2];
    uint32_t w0_dataLen = outLen/2;
    uint8_t w1_data[outLen/2];
    uint32_t w1_dataLen = outLen/2;
    uint8_t l_data[MAX_ECC_KEY_LEN];
    uint32_t l_dataLen = MAX_ECC_KEY_LEN;
    int32_t ret = HITLS_AUTH_SUCCESS;

    BN_BigNum* w0s0 = BN_Create(w0sLen*8);
    BN_BigNum* w1s0 = BN_Create(w1sLen*8);
    BN_BigNum* p0 = BN_Create(pLen*8);
    BN_BigNum *result = BN_Create(pLen*8);
    ECC_Para *para = ECC_NewPara(g_spake2PlusAlgInfo[spakeCtx->index].curveId);
    ECC_Point* L = ECC_NewPoint(para);
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL || w0s0 == NULL || w1s0 == NULL || p0 == NULL || result == NULL || para == NULL ||
        L == NULL || pkeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_MEM_ALLOC_FAIL);
        ret = HITLS_AUTH_MEM_ALLOC_FAIL;
        goto ERR;
    }

    ret = CRYPT_EAL_KdfDerive(kdfCtx, out, outLen);
    if (ret!=HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    (void)memcpy_s(w0s, sizeof(w0s), out, w0sLen);
    (void)memcpy_s(w1s, sizeof(w1s), out + w0sLen, outLen - w0sLen);

    ret = BN_Bin2Bn(w0s0, w0s, w0sLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = BN_Bin2Bn(w1s0, w1s, w1sLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = CRYPT_EAL_PkeySetParaById(pkeyCtx, g_spake2PlusAlgInfo[spakeCtx->index].curveId);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = Spake2PlusGetEcc(pkeyCtx, ECC_PARAM_P, p, &pLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = BN_Bin2Bn(p0, p, pLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = BN_Mod(result, w0s0, p0, opt);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = BN_Bn2Bin(result, w0_data, &w0_dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = BN_Mod(result, w1s0, p0, opt);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = BN_Bn2Bin(result, w1_data, &w1_dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = ECC_PointMul(para, L, result, NULL);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = ECC_EncodePoint(para, L, l_data, &l_dataLen, CRYPT_POINT_UNCOMPRESSED);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    spakeCtx->w0.dataLen = w0_dataLen;
    spakeCtx->w1.dataLen = w1_dataLen;
    spakeCtx->l.dataLen = l_dataLen;
    (void)memcpy_s(spakeCtx->w0.data, w0_dataLen, w0_data, w0_dataLen);
    (void)memcpy_s(spakeCtx->w1.data, w1_dataLen, w1_data, w1_dataLen);
    (void)memcpy_s(spakeCtx->l.data, l_dataLen, l_data, l_dataLen);

ERR:
    BN_Destroy(w0s0);
    BN_Destroy(w1s0);
    BN_Destroy(p0);
    BN_Destroy(result);
    BN_OptimizerDestroy(opt);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    ECC_FreePoint(L);
    ECC_FreePara(para);
    if (ret != HITLS_AUTH_SUCCESS) {
        Spake2PlusFreeCtx(spakeCtx);
    }
    return ret;
}

int32_t HITLS_AUTH_Spake2plusRespRegister(HITLS_AUTH_PakeCtx* ctx, BSL_Buffer exist_w0,
    BSL_Buffer exist_w1, BSL_Buffer exist_l)
{
    Spake2plusCtx *spakeCtx = (Spake2plusCtx *)HITLS_AUTH_PakeGetInternalCtx(ctx);
    if (spakeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    if (exist_w0.data != NULL && exist_w1.data != NULL && exist_l.data != NULL) {
        spakeCtx->w0.dataLen = exist_w0.dataLen;
        spakeCtx->w1.dataLen = exist_w1.dataLen;
        spakeCtx->l.dataLen = exist_l.dataLen;
        (void)memcpy_s(spakeCtx->w0.data, exist_w0.dataLen, exist_w0.data, exist_w0.dataLen);
        (void)memcpy_s(spakeCtx->w1.data, exist_w1.dataLen, exist_w1.data, exist_w1.dataLen);
        (void)memcpy_s(spakeCtx->l.data, exist_l.dataLen, exist_l.data, exist_l.dataLen);
        return HITLS_AUTH_SUCCESS;
    }
    Spake2PlusFreeCtx(spakeCtx);
    return HITLS_AUTH_PAKE_INVALID_PARAM;
}

static int32_t Spake2PlusCreatePkeyCtx(uint8_t index, CRYPT_EAL_PkeyCtx **pkeyCtx)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    if (pkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        return HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
    }

    CRYPT_PKEY_ParaId curveId = g_spake2PlusAlgInfo[index].curveId;
    int32_t ret = CRYPT_EAL_PkeySetParaById(pkey, curveId);
    if (ret != HITLS_AUTH_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return ret;
    }

    *pkeyCtx = pkey;
    return HITLS_AUTH_SUCCESS;
}

static int32_t Spake2PlusCreatePubKey(Spake2plusCtx* ctx, uint8_t *pubKey, uint32_t pubKeyLen, CRYPT_EAL_PkeyCtx **pkey)
{
    CRYPT_EAL_PkeyCtx *tmpKey = NULL;
    int32_t ret = Spake2PlusCreatePkeyCtx(ctx->index, &tmpKey);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }

    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = CRYPT_EAL_PkeyGetId(tmpKey);
    pub.key.eccPub.data = pubKey;
    pub.key.eccPub.len = pubKeyLen;

    ret = CRYPT_EAL_PkeySetPub(tmpKey, &pub);
    if (ret != HITLS_AUTH_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmpKey);
        return ret;
    }

    *pkey = tmpKey;
    return HITLS_AUTH_SUCCESS;
}

static int32_t Spake2PlusGenerateRandNum(uint8_t *num, uint8_t *p, uint32_t pLen)
{
    BN_BigNum *p0 = BN_Create(pLen*8);
    BN_BigNum *x0 = BN_Create(pLen*8);
    if (p0 == NULL || x0 == NULL) {
        BN_Destroy(p0);
        BN_Destroy(x0);
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        return HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
    }
    int32_t ret = HITLS_AUTH_SUCCESS;
    ret = BN_Bin2Bn(p0, p, pLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BN_Destroy(p0);
        BN_Destroy(x0);
        return ret;
    }
    
    uint8_t *x = BSL_SAL_Malloc(pLen);
    if (x == NULL) {
        BN_Destroy(p0);
        BN_Destroy(x0);
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        return HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
    }

    (void)memset_s(x, pLen, 0, pLen);
    
    uint32_t retryCount = 0;
    const uint32_t MAX_RETRIES = 1000;
    bool success = false;
    while (retryCount < MAX_RETRIES) {
        ret = CRYPT_EAL_RandbytesEx(NULL, x, pLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            break;
        }

        ret = BN_Bin2Bn(x0, x, pLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            break;
        }

        if (BN_Cmp(x0, p0) == -1) {
            success = true;
            break;
        }
        ++retryCount;
    }

    if (ret != HITLS_AUTH_SUCCESS) {
        ret = CRYPT_NO_REGIST_RAND;
    } else if (!success) {
        ret = CRYPT_NO_REGIST_RAND;
    } else {
        (void)memcpy_s(num, pLen, x, pLen);
        ret = HITLS_AUTH_SUCCESS;
    }

    BSL_SAL_Free(x);
    BN_Destroy(p0);
    BN_Destroy(x0);
    return ret;
}

static int32_t Spake2PlusInit(Spake2plusCtx *ctx, uint8_t *randnum, uint32_t *randnumLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }
    
    uint8_t p[MAX_ECC_PARAM_LEN];
    uint32_t pLen = MAX_ECC_PARAM_LEN;
    
    CRYPT_EAL_PkeyCtx* mKey = NULL;
    int32_t ret = Spake2PlusCreatePubKey(ctx, ctx->m.data, ctx->m.dataLen, &mKey);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = Spake2PlusGetEcc(mKey, ECC_PARAM_P, p, &pLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    
    ret = Spake2PlusGenerateRandNum(randnum, p, pLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    *randnumLen = pLen;
ERR:
    if (mKey != NULL) {
        CRYPT_EAL_PkeyFreeCtx(mKey);
    }
    return ret;
}

static int32_t Spake2PlusProverComputeX(Spake2plusCtx* ctx, uint8_t *x, uint32_t xLen,
    uint8_t *shareP, uint32_t *sharePLen)
{
    if (ctx == NULL || x == NULL || xLen <= 0 || shareP == NULL || sharePLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    ECC_Para *para = ECC_NewPara(g_spake2PlusAlgInfo[ctx->index].curveId);
    ECC_Point *X = ECC_NewPoint(para);
    ECC_Point *m = ECC_NewPoint(para);
    BN_BigNum *x0 = BN_Create(xLen * 8);
    BN_BigNum *w0 = BN_Create(ctx->w0.dataLen * 8);
    int32_t ret = HITLS_AUTH_SUCCESS;

    if (para == NULL || X == NULL || m == NULL || x0 == NULL || w0 == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        ret = HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
        goto EXIT;
    }
    
    ret = BN_Bin2Bn(x0, x, xLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto EXIT;
    }
    ret = BN_Bin2Bn(w0, ctx->w0.data, ctx->w0.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto EXIT;
    }

    ret = ECC_DecodePoint(para, m, ctx->m.data, ctx->m.dataLen);
    if (ret !=HITLS_AUTH_SUCCESS || ECC_PointCheck(m) != HITLS_AUTH_SUCCESS) {
        goto EXIT;
    }

    // shareP(X)=x*G+w0*m
    ret = ECC_PointMulAdd(para, X, x0, w0, m);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto EXIT;
    }

    ret = ECC_EncodePoint(para, X, shareP, sharePLen, CRYPT_POINT_UNCOMPRESSED);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto EXIT;
    }

EXIT:
    BN_Destroy(x0);
    BN_Destroy(w0);
    ECC_FreePoint(X);
    ECC_FreePoint(m);
    ECC_FreePara(para);
    return ret;
}

static int32_t Spake2PlusVerifierComputeY(Spake2plusCtx* ctx, uint8_t *y, uint32_t yLen,
    uint8_t *shareV, uint32_t *shareVLen)
{
    if (ctx == NULL || y == NULL || yLen <= 0 || shareV == NULL || shareVLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    ECC_Para *para = ECC_NewPara(g_spake2PlusAlgInfo[ctx->index].curveId);
    ECC_Point *Y = ECC_NewPoint(para);
    ECC_Point *n = ECC_NewPoint(para);
    BN_BigNum *y0 = BN_Create(yLen * 8);
    BN_BigNum *w0 = BN_Create(ctx->w0.dataLen * 8);
    int32_t ret = HITLS_AUTH_SUCCESS;
    if (para == NULL || Y == NULL || n == NULL || y0 == NULL || w0 == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        ret = HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
        goto EXIT;
    }

    ret = BN_Bin2Bn(y0, y, yLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto EXIT;
    }
    ret = BN_Bin2Bn(w0, ctx->w0.data, ctx->w0.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto EXIT;
    }

    ret = ECC_DecodePoint(para, n, ctx->n.data, ctx->n.dataLen);
    if (ret!=HITLS_AUTH_SUCCESS || ECC_PointCheck(n) != HITLS_AUTH_SUCCESS) {
        goto EXIT;
    }
    
    // shareV(Y)=y*G+w0*n
    ret = ECC_PointMulAdd(para, Y, y0, w0, n);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto EXIT;
    }

    ret = ECC_EncodePoint(para, Y, shareV, shareVLen, CRYPT_POINT_UNCOMPRESSED);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto EXIT;
    }

EXIT:
    BN_Destroy(y0);
    BN_Destroy(w0);
    ECC_FreePoint(Y);
    ECC_FreePoint(n);
    ECC_FreePara(para);
    return ret;
}

static int32_t Spake2PlusProverFinish(Spake2plusCtx *ctx, BSL_Buffer x, BSL_Buffer shareV,
    BSL_Buffer *z, BSL_Buffer *v)
{
    if (ctx == NULL || x.data == NULL || x.dataLen <= 0 || shareV.data == NULL || shareV.dataLen <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    BN_BigNum *w0 = BN_Create(ctx->w0.dataLen * 8);
    BN_BigNum *w1 = BN_Create(ctx->w1.dataLen * 8);
    BN_BigNum *w2 = BN_Create(ctx->w0.dataLen * 8);
    BN_BigNum *n0 = BN_Create(ctx->w0.dataLen * 8);
    BN_BigNum *x0 = BN_Create(x.dataLen * 8);

    ECC_Para *para = ECC_NewPara(g_spake2PlusAlgInfo[ctx->index].curveId);
    ECC_Point *Z = ECC_NewPoint(para);
    ECC_Point *N = ECC_NewPoint(para);
    ECC_Point *Y = ECC_NewPoint(para);
    ECC_Point *Z0 = ECC_NewPoint(para);
    ECC_Point *V0 = ECC_NewPoint(para);
    CRYPT_EAL_PkeyCtx* shareVKey = NULL;
    int32_t ret = HITLS_AUTH_SUCCESS;

    if (para == NULL || Z == NULL || N == NULL || Y == NULL || Z0 == NULL || V0 == NULL ||
        w0 == NULL || w1 == NULL || w2 == NULL || n0 == NULL || x0 == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        ret = HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
        goto ERR;
    }

    ret = BN_Bin2Bn(w0, ctx->w0.data, ctx->w0.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = BN_Bin2Bn(w1, ctx->w1.data, ctx->w1.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = BN_Bin2Bn(x0, x.data, x.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    uint8_t n[MAX_ECC_PARAM_LEN];
    uint32_t nLen = MAX_ECC_PARAM_LEN;

    ret = Spake2PlusCreatePubKey(ctx, shareV.data, shareV.dataLen, &shareVKey);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = Spake2PlusGetEcc(shareVKey, ECC_PARAM_N, n, &nLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = BN_Bin2Bn(n0, n, nLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = BN_Sub(w2, n0, w0);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    
    ret = ECC_DecodePoint(para, N, ctx->n.data, ctx->n.dataLen);
    if (ret != HITLS_AUTH_SUCCESS || ECC_PointCheck(N) != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = ECC_PointMul(para, Z, w2, N);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = ECC_DecodePoint(para, Y, shareV.data, shareV.dataLen);
    if (ret != HITLS_AUTH_SUCCESS || ECC_PointCheck(Y) != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = ECC_PointAddAffine(para, Z, Z, Y);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    
    ret = ECC_PointMul(para, Z0, x0, Z);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = ECC_EncodePoint(para, Z0, z->data, &(z->dataLen), CRYPT_POINT_UNCOMPRESSED);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = ECC_PointMul(para, V0, w1, Z);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = ECC_EncodePoint(para, V0, v->data, &(v->dataLen), CRYPT_POINT_UNCOMPRESSED);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

ERR:
    BN_Destroy(w0);
    BN_Destroy(w1);
    BN_Destroy(w2);
    BN_Destroy(n0);
    BN_Destroy(x0);
    ECC_FreePoint(Z);
    ECC_FreePoint(N);
    ECC_FreePoint(Y);
    ECC_FreePoint(Z0);
    ECC_FreePoint(V0);
    ECC_FreePara(para);
    CRYPT_EAL_PkeyFreeCtx(shareVKey);
    return ret;
}

static int32_t Spake2PlusVerifierFinish(Spake2plusCtx *ctx, BSL_Buffer y, BSL_Buffer shareP,
    BSL_Buffer *z, BSL_Buffer *v)
{
    if (ctx == NULL || y.data == NULL || y.dataLen <= 0 || shareP.data == NULL || shareP.dataLen <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    BN_BigNum *w0 = BN_Create(ctx->w0.dataLen * 8);
    BN_BigNum *n0 = BN_Create(ctx->w0.dataLen * 8);
    BN_BigNum *w2 = BN_Create(ctx->w0.dataLen * 8);
    BN_BigNum *y0 = BN_Create(y.dataLen * 8);

    ECC_Para *para = ECC_NewPara(g_spake2PlusAlgInfo[ctx->index].curveId);
    ECC_Point *Z = ECC_NewPoint(para);
    ECC_Point *M = ECC_NewPoint(para);
    ECC_Point *X = ECC_NewPoint(para);
    ECC_Point *Z0 = ECC_NewPoint(para);
    ECC_Point *V0 = ECC_NewPoint(para);
    ECC_Point *L = ECC_NewPoint(para);
    CRYPT_EAL_PkeyCtx* sharePKey = NULL;
    int32_t ret = HITLS_AUTH_SUCCESS;

    if (para == NULL || Z == NULL || M == NULL || X == NULL || Z0 == NULL || V0 == NULL ||
        L == NULL || w0 == NULL || w2 == NULL || n0 == NULL || y0 == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        ret = HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
        goto ERR;
    }
    uint8_t n[MAX_ECC_PARAM_LEN];
    uint32_t nLen = MAX_ECC_PARAM_LEN;

    ret = BN_Bin2Bn(w0, ctx->w0.data, ctx->w0.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = BN_Bin2Bn(y0, y.data, y.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = Spake2PlusCreatePubKey(ctx, shareP.data, shareP.dataLen, &sharePKey);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = Spake2PlusGetEcc(sharePKey, ECC_PARAM_N, n, &nLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = BN_Bin2Bn(n0, n, nLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = BN_Sub(w2, n0, w0);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = ECC_DecodePoint(para, M, ctx->m.data, ctx->m.dataLen);
    if (ret != HITLS_AUTH_SUCCESS || ECC_PointCheck(M) != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = ECC_PointMul(para, Z, w2, M);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = ECC_DecodePoint(para, X, shareP.data, shareP.dataLen);
    if (ret != HITLS_AUTH_SUCCESS || ECC_PointCheck(X) != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = ECC_PointAddAffine(para, Z, Z, X);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = ECC_PointMul(para, Z0, y0, Z);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = ECC_EncodePoint(para, Z0, z->data, &(z->dataLen), CRYPT_POINT_UNCOMPRESSED);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
   
    ret = ECC_DecodePoint(para, L, ctx->l.data, ctx->l.dataLen);
    if (ret != HITLS_AUTH_SUCCESS || ECC_PointCheck(L) != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = ECC_PointMul(para, V0, y0, L);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = ECC_EncodePoint(para, V0, v->data, &(v->dataLen), CRYPT_POINT_UNCOMPRESSED);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

ERR:
    BN_Destroy(w0);
    BN_Destroy(w2);
    BN_Destroy(n0);
    BN_Destroy(y0);
    ECC_FreePoint(Z);
    ECC_FreePoint(M);
    ECC_FreePoint(X);
    ECC_FreePoint(L);
    ECC_FreePoint(Z0);
    ECC_FreePoint(V0);
    ECC_FreePara(para);
    CRYPT_EAL_PkeyFreeCtx(sharePKey);
    return ret;
}

static void uint32_to_le_bytes(uint32_t len, uint8_t out[8])
{
    out[0] = (uint8_t)(len & 0xFF);
    out[1] = (uint8_t)((len >> 8) & 0xFF);
    out[2] = (uint8_t)((len >> 16) & 0xFF);
    out[3] = (uint8_t)((len >> 24) & 0xFF);
    out[4] = out[5] = out[6] = out[7] = 0;
}

#define APPEND_FIELD(data, len) ({ \
    int32_t __ret = HITLS_AUTH_SUCCESS; \
    uint8_t len_bytes[8]; \
    uint32_to_le_bytes(len, len_bytes); \
    if (remaining < 8 + len) { \
        __ret = CRYPT_MEM_ALLOC_FAIL; \
    } else { \
        (void)memcpy_s(pos, 8, len_bytes, 8); \
        pos += 8; remaining -= 8; \
        (void)memcpy_s(pos, len, data, len); \
        pos += len; remaining -= len; \
    } \
    __ret; \
})

static int32_t Spake2PlusComputeTranscript(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer shareP, BSL_Buffer shareV,
    BSL_Buffer z, BSL_Buffer v, BSL_Buffer *tt, uint32_t *totalSize)
{
    if (ctx == NULL || shareP.data == NULL || shareP.dataLen <= 0 || shareV.data == NULL || shareV.dataLen <= 0 ||
        z.data == NULL || z.dataLen <= 0 || v.data == NULL || v.dataLen <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    uint8_t *pos = tt ? tt->data : NULL;
    size_t remaining = tt ? tt->dataLen : 0;
    CRYPT_EAL_PkeyCtx* mKey = NULL;
    CRYPT_EAL_PkeyCtx* nKey = NULL;

    Spake2plusCtx *spakeCtx = (Spake2plusCtx *)HITLS_AUTH_PakeGetInternalCtx(ctx);
    if (spakeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_CONTEXT);
        return HITLS_AUTH_PAKE_INVALID_CONTEXT;
    }

    uint8_t m[MAX_ECC_KEY_LEN];
    uint32_t mLen = MAX_ECC_KEY_LEN;
    uint8_t n[MAX_ECC_KEY_LEN];
    uint32_t nLen = MAX_ECC_KEY_LEN;
    BSL_Buffer prover = HITLS_AUTH_PakeGetProver(ctx);
    BSL_Buffer verifier = HITLS_AUTH_PakeGetVerifier(ctx);
    BSL_Buffer context = HITLS_AUTH_PakeGetContext(ctx);

    int32_t ret = HITLS_AUTH_SUCCESS;
    ret = Spake2PlusCreatePubKey(spakeCtx, spakeCtx->m.data, spakeCtx->m.dataLen, &mKey);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = GetPubKeyData(mKey, m, &mLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = Spake2PlusCreatePubKey(spakeCtx, spakeCtx->n.data, spakeCtx->n.dataLen, &nKey);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = GetPubKeyData(nKey, n, &nLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    if (totalSize) {
        *totalSize = 8 + context.dataLen + 8 + prover.dataLen + 8 + verifier.dataLen + 8 + mLen + 8 + nLen +
        8 + shareP.dataLen + 8 + shareV.dataLen + 8 + z.dataLen + 8 + v.dataLen + 8 + spakeCtx->w0.dataLen;
    }
    if (tt) {
        ret = APPEND_FIELD(context.data, context.dataLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto ERR;
        }
        ret = APPEND_FIELD(prover.data, prover.dataLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto ERR;
        }
        ret = APPEND_FIELD(verifier.data, verifier.dataLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto ERR;
        }
        ret = APPEND_FIELD(m, mLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto ERR;
        }
        ret = APPEND_FIELD(n, nLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto ERR;
        }
        ret = APPEND_FIELD(shareP.data, shareP.dataLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto ERR;
        }
        ret = APPEND_FIELD(shareV.data, shareV.dataLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto ERR;
        }
        ret = APPEND_FIELD(z.data, z.dataLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto ERR;
        }
        ret = APPEND_FIELD(v.data, v.dataLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto ERR;
        }
        ret = APPEND_FIELD(spakeCtx->w0.data, spakeCtx->w0.dataLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto ERR;
        }

        tt->dataLen = pos - tt->data;
    }
ERR:
    CRYPT_EAL_PkeyFreeCtx(mKey);
    CRYPT_EAL_PkeyFreeCtx(nKey);
    if (ret != HITLS_AUTH_SUCCESS) {
        Spake2PlusFreeCtx(spakeCtx);
    }
    return ret;
}

static int32_t Spake2PlusComputeKeySchedule(Spake2plusCtx *ctx, BSL_Buffer tt, BSL_Buffer *kConfirmP,
    BSL_Buffer *kConfirmV, BSL_Buffer *kShared)
{
    if (ctx == NULL || tt.data == NULL || tt.dataLen <= 0 || kConfirmP->data == NULL ||
        kConfirmV->data == NULL || kShared->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    uint8_t kMain[g_spake2PlusAlgInfo[ctx->index].hashKeyLen];
    uint32_t kMainLen = g_spake2PlusAlgInfo[ctx->index].hashKeyLen;

    int32_t ret = CRYPT_EAL_Md(g_spake2PlusAlgInfo[ctx->index].hashId, tt.data, tt.dataLen, kMain, &kMainLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }

    CRYPT_MAC_AlgId macId;
    if (g_spake2PlusAlgInfo[ctx->index].kdfId == CRYPT_HKDF_SHA256) {
        macId=CRYPT_MAC_HMAC_SHA256;
    }
    if (g_spake2PlusAlgInfo[ctx->index].kdfId == CRYPT_HKDF_SHA512) {
        macId=CRYPT_MAC_HMAC_SHA512;
    }

    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (kdfCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        return HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
    }

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    uint8_t *salt = NULL;
    uint32_t saltLen = 0;
    uint8_t *info = (uint8_t*)"ConfirmationKeys"; // data from rfc 9383, section 3.4
    uint32_t infoLen = strlen("ConfirmationKeys");
    uint8_t out[g_spake2PlusAlgInfo[ctx->index].macKeyLen * 2];
    uint32_t outLen = g_spake2PlusAlgInfo[ctx->index].macKeyLen * 2;
    uint8_t out0[g_spake2PlusAlgInfo[ctx->index].hashKeyLen];
    uint32_t out0Len = g_spake2PlusAlgInfo[ctx->index].hashKeyLen;

    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ret = BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId));
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode));
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, kMain, kMainLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, info, infoLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = CRYPT_EAL_KdfSetParam(kdfCtx, params);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = CRYPT_EAL_KdfDerive(kdfCtx, out, outLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    (void)memcpy_s(kConfirmP->data, g_spake2PlusAlgInfo[ctx->index].macKeyLen,
        out, g_spake2PlusAlgInfo[ctx->index].macKeyLen);
    (void)memcpy_s(kConfirmV->data, g_spake2PlusAlgInfo[ctx->index].macKeyLen,
        out + g_spake2PlusAlgInfo[ctx->index].macKeyLen, g_spake2PlusAlgInfo[ctx->index].macKeyLen);
    kConfirmP->dataLen = g_spake2PlusAlgInfo[ctx->index].macKeyLen;
    kConfirmV->dataLen = g_spake2PlusAlgInfo[ctx->index].macKeyLen;

    uint8_t *info0 = (uint8_t*)"SharedKey"; // data from rfc 9383, section 3.4
    uint32_t info0Len = strlen("SharedKey");
    
    ret = BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, info0, info0Len);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = CRYPT_EAL_KdfSetParam(kdfCtx, params);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    ret = CRYPT_EAL_KdfDerive(kdfCtx, out0, out0Len);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

    (void)memcpy_s(kShared->data, out0Len, out0, out0Len);
    kShared->dataLen = out0Len;

    (void)memset_s(kMain, sizeof(kMain), 0, sizeof(kMain));
    (void)memset_s(out, sizeof(out), 0, sizeof(out));
    (void)memset_s(out0, sizeof(out0), 0, sizeof(out0));

ERR:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    return ret;
}

static int32_t Spake2PlusComputeExpectedConfirm(Spake2plusCtx *ctx, BSL_Buffer kConfirm, BSL_Buffer share,
    BSL_Buffer *outHmac)
{
    if (ctx == NULL || kConfirm.data == NULL || kConfirm.dataLen <= 0 ||
        share.data == NULL || share.dataLen <= 0 || outHmac->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ARG);
        return HITLS_AUTH_INVALID_ARG;
    }

    CRYPT_EAL_MacCtx *MacCtx = CRYPT_EAL_MacNewCtx(g_spake2PlusAlgInfo[ctx->index].macId);
    if (MacCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        return HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
    }

    int32_t ret = HITLS_AUTH_SUCCESS;
    if (MacCtx == NULL) {
        ret = HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        return ret;
    }

    ret = CRYPT_EAL_MacInit(MacCtx, kConfirm.data, kConfirm.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = CRYPT_EAL_MacUpdate(MacCtx, share.data, share.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    outHmac->dataLen = g_spake2PlusAlgInfo[ctx->index].macKeyLen;
    ret = CRYPT_EAL_MacFinal(MacCtx, outHmac->data, &(outHmac->dataLen));
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }

ERR:
    CRYPT_EAL_MacDeinit(MacCtx);
    CRYPT_EAL_MacFreeCtx(MacCtx);
    return ret;
}

int32_t HITLS_AUTH_Spake2plusReqSetup(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer randnumx, BSL_Buffer *share)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }

    Spake2plusCtx *spakeCtx = (Spake2plusCtx *)HITLS_AUTH_PakeGetInternalCtx(ctx);
    if (spakeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_CONTEXT);
        return HITLS_AUTH_NULL_INPUT;
    }
    int32_t ret = HITLS_AUTH_SUCCESS;

    uint8_t randnum[MAX_ECC_PARAM_LEN] = { 0 };
    uint32_t randnumLen = MAX_ECC_PARAM_LEN;

    if (randnumx.data != NULL) {
        randnumLen = randnumx.dataLen;
        (void)memcpy_s(randnum, randnumx.dataLen, randnumx.data, randnumx.dataLen);
    } else {
        ret = Spake2PlusInit(spakeCtx, randnum, &randnumLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            Spake2PlusFreeCtx(spakeCtx);
            return ret;
        }
    }

    spakeCtx->x.dataLen = randnumLen;
    (void)memcpy_s(spakeCtx->x.data, randnumLen, randnum, randnumLen);

    uint8_t shareP[MAX_ECC_KEY_LEN] = { 0 };
    uint32_t sharePLen = MAX_ECC_KEY_LEN;

    ret = Spake2PlusProverComputeX(spakeCtx, randnum, randnumLen, shareP, &sharePLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        Spake2PlusFreeCtx(spakeCtx);
        return ret;
    }
    
    spakeCtx->share.dataLen = sharePLen;
    (void)memcpy_s(spakeCtx->share.data, sharePLen, shareP, sharePLen);

    share->dataLen = sharePLen;
    (void)memcpy_s(share->data, sharePLen, shareP, sharePLen);

    return ret;
}

int32_t HITLS_AUTH_Spake2plusRespSetup(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer y, BSL_Buffer shareP,
    BSL_Buffer *shareV, BSL_Buffer *confirmV)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }
    Spake2plusCtx *spakeCtx = (Spake2plusCtx *)HITLS_AUTH_PakeGetInternalCtx(ctx);
    if (spakeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_CONTEXT);
        return HITLS_AUTH_NULL_INPUT;
    }

    int32_t ret = HITLS_AUTH_SUCCESS;
    uint8_t randnum[MAX_ECC_PARAM_LEN] = { 0 };
    uint32_t randnumLen = MAX_ECC_PARAM_LEN;

    BSL_Buffer zBuffer = {.data = BSL_SAL_Malloc(MAX_ECC_KEY_LEN), .dataLen = MAX_ECC_KEY_LEN};
    BSL_Buffer vBuffer = {.data = BSL_SAL_Malloc(MAX_ECC_KEY_LEN), .dataLen = MAX_ECC_KEY_LEN};
    BSL_Buffer randnumBuffer = {.data = BSL_SAL_Malloc(MAX_ECC_PARAM_LEN), .dataLen = MAX_ECC_PARAM_LEN};
    BSL_Buffer ttBuffer = {.data = NULL, .dataLen = 0};
    BSL_Buffer kConfirmPBuffer = {.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};
    BSL_Buffer kConfirmVBuffer = {.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};
    BSL_Buffer kSharedBuffer = {.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};
    BSL_Buffer outHmacBuffer = {.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};
    if (zBuffer.data == NULL || vBuffer.data == NULL || randnumBuffer.data == NULL ||
        kConfirmPBuffer.data == NULL || kConfirmVBuffer.data == NULL || kSharedBuffer.data == NULL ||
        outHmacBuffer.data == NULL) {
        ret = HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        goto err;
    }

    if (y.data != NULL) {
        randnumLen = y.dataLen;
        (void)memcpy_s(randnum, y.dataLen, y.data, y.dataLen);
    } else {
        ret = Spake2PlusInit(spakeCtx, randnum, &randnumLen);
        if (ret != HITLS_AUTH_SUCCESS) {
            goto err;
        }
    }

    uint8_t shareV0[MAX_ECC_KEY_LEN] = {0};
    uint32_t shareV0Len = MAX_ECC_KEY_LEN;
    ret = Spake2PlusVerifierComputeY(spakeCtx, randnum, randnumLen, shareV0, &shareV0Len);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }

    shareV->dataLen = shareV0Len;
    (void)memcpy_s(shareV->data, shareV0Len, shareV0, shareV0Len);

    randnumBuffer.dataLen = randnumLen;
    (void)memcpy_s(randnumBuffer.data, randnumLen, randnum, randnumLen);

    ret = Spake2PlusVerifierFinish(spakeCtx, randnumBuffer, shareP, &zBuffer, &vBuffer);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }

    uint32_t ttSize = 0;

    ret = Spake2PlusComputeTranscript(ctx, shareP, *shareV, zBuffer, vBuffer, NULL, &ttSize);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }
    ttBuffer.data = BSL_SAL_Malloc(ttSize);
    ttBuffer.dataLen = ttSize;
    ret = Spake2PlusComputeTranscript(ctx, shareP, *shareV, zBuffer, vBuffer, &ttBuffer, NULL);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }

    ret = Spake2PlusComputeKeySchedule(spakeCtx, ttBuffer, &kConfirmPBuffer, &kConfirmVBuffer, &kSharedBuffer);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }

    spakeCtx->key_shared.dataLen = kSharedBuffer.dataLen;
    (void)memcpy_s(spakeCtx->key_shared.data, kSharedBuffer.dataLen, kSharedBuffer.data, kSharedBuffer.dataLen);
    
    ret = Spake2PlusComputeExpectedConfirm(spakeCtx, kConfirmVBuffer, shareP, &outHmacBuffer);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }

    spakeCtx->confirmV.dataLen = outHmacBuffer.dataLen;
    (void)memcpy_s(spakeCtx->confirmV.data, outHmacBuffer.dataLen, outHmacBuffer.data, outHmacBuffer.dataLen);

    confirmV->dataLen = outHmacBuffer.dataLen;
    (void)memcpy_s(confirmV->data, outHmacBuffer.dataLen, outHmacBuffer.data, outHmacBuffer.dataLen);

    ret = Spake2PlusComputeExpectedConfirm(spakeCtx, kConfirmPBuffer, *shareV, &outHmacBuffer);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }

    spakeCtx->confirmP.dataLen = outHmacBuffer.dataLen;
    (void)memcpy_s(spakeCtx->confirmP.data, outHmacBuffer.dataLen, outHmacBuffer.data, outHmacBuffer.dataLen);

err:
    if (ret != HITLS_AUTH_SUCCESS) {
        Spake2PlusFreeCtx(spakeCtx);
    }
    BSL_SAL_ClearFree(zBuffer.data, zBuffer.dataLen);
    BSL_SAL_ClearFree(vBuffer.data, vBuffer.dataLen);
    BSL_SAL_ClearFree(randnumBuffer.data, randnumBuffer.dataLen);
    BSL_SAL_ClearFree(ttBuffer.data, ttBuffer.dataLen);
    BSL_SAL_ClearFree(kConfirmPBuffer.data, kConfirmPBuffer.dataLen);
    BSL_SAL_ClearFree(kConfirmVBuffer.data, kConfirmVBuffer.dataLen);
    BSL_SAL_ClearFree(kSharedBuffer.data, kSharedBuffer.dataLen);
    BSL_SAL_ClearFree(outHmacBuffer.data, outHmacBuffer.dataLen);
    return ret;
}

int32_t HITLS_AUTH_Spake2plusReqDerive(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer shareV, BSL_Buffer confirmV,
    BSL_Buffer *confirmP, BSL_Buffer *out)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }
    Spake2plusCtx *spakeCtx = (Spake2plusCtx*)HITLS_AUTH_PakeGetInternalCtx(ctx);
    if (spakeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_CONTEXT);
        return HITLS_AUTH_NULL_INPUT;
    }

    int32_t ret = HITLS_AUTH_SUCCESS;
    BSL_Buffer zBuffer = {.data = BSL_SAL_Malloc(MAX_ECC_KEY_LEN), .dataLen = MAX_ECC_KEY_LEN};
    BSL_Buffer vBuffer = {.data = BSL_SAL_Malloc(MAX_ECC_KEY_LEN), .dataLen = MAX_ECC_KEY_LEN};
    BSL_Buffer ttBuffer = {.data = NULL, .dataLen = 0};
    BSL_Buffer kConfirmPBuffer = {.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};
    BSL_Buffer kConfirmVBuffer = {.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};
    BSL_Buffer kSharedBuffer = {.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};
    BSL_Buffer outHmacBuffer = {.data = BSL_SAL_Malloc(MAX_KEY_LEN), .dataLen = MAX_KEY_LEN};
    if (zBuffer.data == NULL || vBuffer.data == NULL ||
        kConfirmPBuffer.data == NULL || kConfirmVBuffer.data == NULL || kSharedBuffer.data == NULL ||
        outHmacBuffer.data == NULL) {
        ret = HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        goto err;
    }

    ret = Spake2PlusProverFinish(spakeCtx, spakeCtx->x, shareV, &zBuffer, &vBuffer);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }
    
    uint32_t ttSize = 0;
    ret = Spake2PlusComputeTranscript(ctx, spakeCtx->share, shareV, zBuffer, vBuffer, NULL, &ttSize);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }
    ttBuffer.data = BSL_SAL_Malloc(ttSize);
    ttBuffer.dataLen = ttSize;
    ret = Spake2PlusComputeTranscript(ctx, spakeCtx->share, shareV, zBuffer, vBuffer, &ttBuffer, NULL);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }

    ret = Spake2PlusComputeKeySchedule(spakeCtx, ttBuffer, &kConfirmPBuffer, &kConfirmVBuffer, &kSharedBuffer);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }

    spakeCtx->key_shared.dataLen = kSharedBuffer.dataLen;
    (void)memcpy_s(spakeCtx->key_shared.data, kSharedBuffer.dataLen, kSharedBuffer.data, kSharedBuffer.dataLen);

    ret = Spake2PlusComputeExpectedConfirm(spakeCtx, kConfirmPBuffer, shareV, &outHmacBuffer);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }

    spakeCtx->confirmP.dataLen = outHmacBuffer.dataLen;
    (void)memcpy_s(spakeCtx->confirmP.data, outHmacBuffer.dataLen, outHmacBuffer.data, outHmacBuffer.dataLen);

    confirmP->dataLen = outHmacBuffer.dataLen;
    (void)memcpy_s(confirmP->data, outHmacBuffer.dataLen, outHmacBuffer.data, outHmacBuffer.dataLen);

    ret = Spake2PlusComputeExpectedConfirm(spakeCtx, kConfirmVBuffer, spakeCtx->share, &outHmacBuffer);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto err;
    }

    spakeCtx->confirmV.dataLen = outHmacBuffer.dataLen;
    (void)memcpy_s(spakeCtx->confirmV.data, outHmacBuffer.dataLen, outHmacBuffer.data, outHmacBuffer.dataLen);

    if (memcmp(spakeCtx->confirmV.data, confirmV.data, confirmV.dataLen) != 0 &&
    spakeCtx->confirmV.dataLen == confirmV.dataLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_PARAM);
        goto err;
    }

    out->dataLen = kSharedBuffer.dataLen;
    (void)memcpy_s(out->data, kSharedBuffer.dataLen, kSharedBuffer.data, kSharedBuffer.dataLen);
err:
    if (ret != HITLS_AUTH_SUCCESS) {
        Spake2PlusFreeCtx(spakeCtx);
    }
    BSL_SAL_ClearFree(zBuffer.data, zBuffer.dataLen);
    BSL_SAL_ClearFree(vBuffer.data, vBuffer.dataLen);
    BSL_SAL_ClearFree(ttBuffer.data, ttBuffer.dataLen);
    BSL_SAL_ClearFree(kConfirmPBuffer.data, kConfirmPBuffer.dataLen);
    BSL_SAL_ClearFree(kConfirmVBuffer.data, kConfirmVBuffer.dataLen);
    BSL_SAL_ClearFree(kSharedBuffer.data, kSharedBuffer.dataLen);
    BSL_SAL_ClearFree(outHmacBuffer.data, outHmacBuffer.dataLen);
    return ret;
}

int32_t HITLS_AUTH_Spake2plusRespDerive(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer confirmP, BSL_Buffer *out)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }
    Spake2plusCtx *spakeCtx = (Spake2plusCtx *)HITLS_AUTH_PakeGetInternalCtx(ctx);
    if (spakeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_CONTEXT);
        return HITLS_AUTH_NULL_INPUT;
    }

    if (memcmp(spakeCtx->confirmP.data, confirmP.data, confirmP.dataLen) != 0 &&
    spakeCtx->confirmP.dataLen == confirmP.dataLen) {
        Spake2PlusFreeCtx(spakeCtx);
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_PARAM);
        return HITLS_AUTH_PAKE_INVALID_PARAM;
    }

    out->dataLen = spakeCtx->key_shared.dataLen;
    (void)memcpy_s(out->data, spakeCtx->key_shared.dataLen, spakeCtx->key_shared.data, spakeCtx->key_shared.dataLen);

    return HITLS_AUTH_SUCCESS;
}
