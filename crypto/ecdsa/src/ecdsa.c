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
#ifdef HITLS_CRYPTO_ECDSA

#include <stdbool.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "crypt_util_ctrl.h"
#include "bsl_err_internal.h"
#include "crypt_bn.h"
#include "crypt_encode_internal.h"
#include "crypt_ecc.h"
#include "bsl_sal.h"
#include "crypt_ecc_pkey.h"
#include "eal_pkey_local.h"
#include "eal_md_local.h"
#include "crypt_ecdsa.h"

CRYPT_ECDSA_Ctx *CRYPT_ECDSA_NewCtx(void)
{
    CRYPT_ECDSA_Ctx *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_ECDSA_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->pointFormat = CRYPT_POINT_UNCOMPRESSED;    // point format is uncompressed by default.
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

CRYPT_ECDSA_Ctx *CRYPT_ECDSA_NewCtxEx(void *libCtx)
{
    CRYPT_ECDSA_Ctx *ctx = CRYPT_ECDSA_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

CRYPT_EcdsaPara *CRYPT_ECDSA_NewPara(const CRYPT_EccPara *eccPara)
{
    CRYPT_PKEY_ParaId id = GetCurveId(eccPara);
    if (id == CRYPT_PKEY_PARAID_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_PARA);
        return NULL;
    }
    return CRYPT_ECDSA_NewParaById(id);
}

CRYPT_PKEY_ParaId CRYPT_ECDSA_GetParaId(const CRYPT_ECDSA_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_PKEY_PARAID_MAX;
    }
    return ECC_GetParaId(ctx->para);
}

int32_t CRYPT_ECDSA_SetPara(CRYPT_ECDSA_Ctx *ctx, const CRYPT_EccPara *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ECC_SetPara(ctx, CRYPT_ECDSA_NewPara(para));
}

#ifdef HITLS_BSL_PARAMS
int32_t CRYPT_ECDSA_SetParaEx(CRYPT_ECDSA_Ctx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
#ifdef HITLS_CRYPTO_PROVIDER
    int32_t ret;
    const BSL_Param *temp = NULL;
    if ((temp = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_MD_ATTR)) != NULL) {
        ret = CRYPT_PkeySetMdAttr((const char *)(temp->value), temp->valueLen, &(ctx->mdAttr));
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
#endif
    if (BSL_PARAM_FindConstParam(para, CRYPT_PARAM_EC_P) == NULL) {
        return CRYPT_SUCCESS;
    }
    CRYPT_EccPara eccPara = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_EC_P, &(eccPara.p), &(eccPara.pLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_EC_A, &(eccPara.a), &(eccPara.aLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_EC_B, &(eccPara.b), &(eccPara.bLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_EC_N, &(eccPara.n), &(eccPara.nLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_EC_H, &(eccPara.h), &(eccPara.hLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_EC_X, &(eccPara.x), &(eccPara.xLen));
    (void)GetConstParamValue(para, CRYPT_PARAM_EC_Y, &(eccPara.y), &(eccPara.yLen));
    return CRYPT_ECDSA_SetPara(ctx, &eccPara);
}
#endif

uint32_t CRYPT_ECDSA_GetSignLen(const CRYPT_ECDSA_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }

    /**
     * https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-integer
     * If the integer is positive but the high order bit is set to 1,
     * a leading 0x00 is added to the content to indicate that the number is not negative
     */
    // When the number of bits is a multiple of 8 and the most significant bit is 1, 0x00 needs to be added.
    // If the number of bits is not a multiple of 8,
    // an extra byte needs to be added to store the data with less than 8 bits.
    uint32_t qLen = (ECC_ParaBits(ctx->para) / 8) + 1;    // divided by 8 to converted to bytes
    uint32_t maxSignLen = 0;
    int32_t ret = CRYPT_EAL_GetSignEncodeLen(qLen, qLen, &maxSignLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return 0;
    }
    return maxSignLen;
}

// Obtain the input hash data. For details, see RFC6979-2.4.1 and RFC6979-2.3.2
static BN_BigNum *GetBnByData(const BN_BigNum *n, const uint8_t *data, uint32_t dataLen)
{
    uint32_t nBits = BN_Bits(n);
    BN_BigNum *d = BN_Create(nBits); // each byte has 8bits
    if (d == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    if (data == NULL) {
        return d;
    }

    uint32_t dLen = dataLen;
    if (8 * dLen > nBits) {         // bytes * 8 = bits
        dLen = (nBits + 7) >> 3;    // Add 7 and shift rightward by 3 (equal to /8) to achieve the effect of bits2bytes.
    }
    // The input parameters of the function have been verified, and no failure case exists.
    (void)BN_Bin2Bn(d, data, dLen);
    if (8 * dLen > nBits) {         // bytes * 8 = bits
        // Subtracted by 8 and &7 to be accurate to bits.
        int32_t ret = BN_Rshift(d, d, (8 - (nBits & 7)));
        if (ret != CRYPT_SUCCESS) {
            BN_Destroy(d);
            BSL_ERR_PUSH_ERROR(ret);
            return NULL;
        }
    }

    return d;
}

static int32_t EcdsaSignCore(const CRYPT_ECDSA_Ctx *ctx, const BN_BigNum *paraN, BN_BigNum *d,
                             BN_BigNum *r, BN_BigNum *s)
{
    uint32_t keyBits = CRYPT_ECDSA_GetBits(ctx);    // input parameter has been checked externally.
    BN_BigNum *k = BN_Create(keyBits);
    BN_BigNum *k2 = BN_Create(keyBits);
    ECC_Point *pt = ECC_NewPoint(ctx->para);
    BN_BigNum *ptX = BN_Create(keyBits);
    BN_Optimizer *opt = BN_OptimizerCreate();
    int32_t ret;
    int32_t i;

    if ((k == NULL) || (k2 == NULL) || (pt == NULL) || (opt == NULL) || (ptX == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }

    for (i = 0; i < CRYPT_ECC_TRY_MAX_CNT; i++) {
        GOTO_ERR_IF(BN_RandRangeEx(ctx->libCtx, k, paraN), ret);
        if (BN_IsZero(k)) {
            continue;
        }

        // pt = k * G
        GOTO_ERR_IF(ECC_PointMul(ctx->para, pt, k, NULL), ret);

        // r = pt->x mod n
        GOTO_ERR_IF_EX(ECC_GetPointDataX(ctx->para, pt, ptX), ret);
        GOTO_ERR_IF(BN_Mod(r, ptX, paraN, opt), ret);

        // if r == 0, then restart
        if (BN_IsZero(r)) {
            continue;
        }

        // prvkey * r mod n
        GOTO_ERR_IF(BN_ModMul(s, ctx->prvkey, r, paraN, opt), ret);

        // hash + prvkey * r mod n
        GOTO_ERR_IF(BN_ModAddQuick(s, d, s, paraN, opt), ret);

        // 1/k mod n
        GOTO_ERR_IF(ECC_ModOrderInv(ctx->para, k2, k), ret);

        // s = (1/k) * (hash + prvkey * r) mod n
        GOTO_ERR_IF(BN_ModMul(s, k2, s, paraN, opt), ret);

        // if s == 0, then restart
        if (BN_IsZero(s) != true) {
            break;
        }
    }

    if (i >= CRYPT_ECC_TRY_MAX_CNT) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECDSA_ERR_TRY_CNT);
        ret = CRYPT_ECDSA_ERR_TRY_CNT;
    }

ERR:
    BN_Destroy(k);
    BN_Destroy(k2);
    BN_Destroy(ptX);
    ECC_FreePoint(pt);
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t CryptEcdsaSign(const CRYPT_ECDSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
                              BN_BigNum **r, BN_BigNum **s)
{
    int32_t rc = CRYPT_SUCCESS;
    BN_BigNum *signR = NULL;
    BN_BigNum *signS = NULL;
    BN_BigNum *d = NULL;
    BN_BigNum *paraN = ECC_GetParaN(ctx->para);
    if (paraN == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t keyBits = ECC_PkeyGetBits(ctx);
    signR = BN_Create(keyBits);
    signS = BN_Create(keyBits);
    if ((signR == NULL) || (signS == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        rc = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }

    d = GetBnByData(paraN, data, dataLen);
    if (d == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        rc = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    GOTO_ERR_IF_EX(EcdsaSignCore(ctx, paraN, d, signR, signS), rc);

    *r = signR;
    *s = signS;
    goto OK;
ERR:
    BN_Destroy(signR);
    BN_Destroy(signS);
OK:
    BN_Destroy(paraN);
    BN_Destroy(d);
    return rc;
}

// Data with a value of 0 can also be signed.
int32_t CRYPT_ECDSA_SignData(const CRYPT_ECDSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    bool nullInput = (ctx == NULL) || (ctx->para == NULL) || (sign == NULL) || (signLen == NULL) ||
        ((data == NULL) && (dataLen != 0));
    if (nullInput == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->prvkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECDSA_ERR_EMPTY_KEY);
        return CRYPT_ECDSA_ERR_EMPTY_KEY;
    }

    if (*signLen < CRYPT_ECDSA_GetSignLen(ctx)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH;
    }

    int32_t ret;
    BN_BigNum *r = NULL;
    BN_BigNum *s = NULL;
    ret = CryptEcdsaSign(ctx, data, dataLen, &r, &s);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_EncodeSign(r, s, sign, signLen);
    BN_Destroy(r);
    BN_Destroy(s);
    return ret;
}

int32_t CRYPT_ECDSA_Sign(const CRYPT_ECDSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint8_t hash[64]; // 64 is max hash len
    uint32_t hashDataLen = sizeof(hash) / sizeof(hash[0]);
    int32_t ret = EAL_Md(algId, ctx->libCtx, ctx->mdAttr, data, dataLen, hash, &hashDataLen, ctx->libCtx != NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_ECDSA_SignData(ctx, hash, hashDataLen, sign, signLen);
}

static int32_t VerifyCheckSign(const BN_BigNum *paraN, BN_BigNum *r, BN_BigNum *s)
{
    if ((BN_Cmp(r, paraN) >= 0) || (BN_Cmp(s, paraN) >= 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECDSA_VERIFY_FAIL);
        return CRYPT_ECDSA_VERIFY_FAIL;
    }
    if (BN_IsZero(r) || BN_IsZero(s)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECDSA_VERIFY_FAIL);
        return CRYPT_ECDSA_VERIFY_FAIL;
    }

    return CRYPT_SUCCESS;
}

static int32_t EcdsaVerifyCore(const CRYPT_ECDSA_Ctx *ctx, const BN_BigNum *paraN, BN_BigNum *d, const BN_BigNum *r,
    const BN_BigNum *s)
{
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)OptimizerStart(opt);
    ECC_Point *tpt = ECC_NewPoint(ctx->para);
    uint32_t keyBits = CRYPT_ECDSA_GetBits(ctx);
    uint32_t room = BITS_TO_BN_UNIT(keyBits);
    BN_BigNum *w = OptimizerGetBn(opt, room);
    BN_BigNum *u1 = OptimizerGetBn(opt, room);
    BN_BigNum *u2 = OptimizerGetBn(opt, room);
    BN_BigNum *v = OptimizerGetBn(opt, room);
    BN_BigNum *tptX = OptimizerGetBn(opt, room);
    int32_t ret;
    if (tpt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if ((w == NULL) || (u1 == NULL) || (u2 == NULL) || (v == NULL) || (tptX == NULL)) {
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // w = 1/s mod n
    GOTO_ERR_IF(ECC_ModOrderInv(ctx->para, w, s), ret);

    // u1 = msg*(1/s) mod n
    GOTO_ERR_IF(BN_ModMul(u1, d, w, paraN, opt), ret);

    // u2 = r*(1/s) mod n
    GOTO_ERR_IF(BN_ModMul(u2, r, w, paraN, opt), ret);

    // tpt : u1*G + u2*pubkey
    GOTO_ERR_IF(ECC_PointMulAdd(ctx->para, tpt, u1, u2, ctx->pubkey), ret);

    GOTO_ERR_IF(ECC_GetPointDataX(ctx->para, tpt, tptX), ret);
    GOTO_ERR_IF(BN_Mod(v, tptX, paraN, opt), ret);

    if (BN_Cmp(v, r) != 0) {
        BSL_ERR_PUSH_ERROR(ret);
        ret = CRYPT_ECDSA_VERIFY_FAIL;
    }

ERR:
    ECC_FreePoint(tpt);
    OptimizerEnd(opt);
    BN_OptimizerDestroy(opt);
    return ret;
}

int32_t CRYPT_ECDSA_VerifyData(const CRYPT_ECDSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    bool nullInput = (ctx == NULL) || (ctx->para == NULL) || ((data == NULL) && (dataLen != 0)) ||
        (sign == NULL) || (signLen == 0);
    if (nullInput == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->pubkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECDSA_ERR_EMPTY_KEY);
        return CRYPT_ECDSA_ERR_EMPTY_KEY;
    }

    int32_t ret;
    BN_BigNum *paraN = ECC_GetParaN(ctx->para);
    if (paraN == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t keyBits = ECC_PkeyGetBits(ctx);
    BN_BigNum *r = BN_Create(keyBits);
    BN_BigNum *s = BN_Create(keyBits);
    BN_BigNum *d = GetBnByData(paraN, data, dataLen);
    if (r == NULL || s == NULL || d == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }

    GOTO_ERR_IF(CRYPT_EAL_DecodeSign(sign, signLen, r, s), ret);

    GOTO_ERR_IF(VerifyCheckSign(paraN, r, s), ret);

    GOTO_ERR_IF(EcdsaVerifyCore(ctx, paraN, d, r, s), ret);
ERR:
    BN_Destroy(paraN);
    BN_Destroy(r);
    BN_Destroy(s);
    BN_Destroy(d);
    return ret;
}

int32_t CRYPT_ECDSA_Verify(const CRYPT_ECDSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint8_t hash[64]; // 64 is max hash len
    uint32_t hashLen = sizeof(hash) / sizeof(hash[0]);
    int32_t ret = EAL_Md(algId, ctx->libCtx, ctx->mdAttr, data, dataLen, hash, &hashLen, ctx->libCtx != NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_ECDSA_VerifyData(ctx, hash, hashLen, sign, signLen);
}

int32_t CRYPT_ECDSA_Ctrl(CRYPT_ECDSA_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_ECC_USE_COFACTOR_MODE:
            BSL_ERR_PUSH_ERROR(CRYPT_ECDSA_ERR_UNSUPPORTED_CTRL_OPTION);
            return CRYPT_ECDSA_ERR_UNSUPPORTED_CTRL_OPTION;
        case CRYPT_CTRL_GET_PARAID:
            return CRYPT_CTRL_GET_NUM32_EX(ECC_GetParaId, ctx->para, val, len);
        case CRYPT_CTRL_GET_BITS:
            return CRYPT_CTRL_GET_NUM32_EX(ECC_PkeyGetBits, ctx, val, len);
        case CRYPT_CTRL_GET_SIGNLEN:
            return CRYPT_CTRL_GET_NUM32_EX(CRYPT_ECDSA_GetSignLen, ctx, val, len);
        case CRYPT_CTRL_GET_SECBITS:
            return CRYPT_CTRL_GET_NUM32_EX(ECC_GetSecBits, ctx->para, val, len);
        case CRYPT_CTRL_SET_PARA_BY_ID:
            if (val == NULL || len != sizeof(CRYPT_PKEY_ParaId)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            return ECC_SetPara(ctx, CRYPT_ECDSA_NewParaById(*(CRYPT_PKEY_ParaId *)val));
        default:
            return ECC_PkeyCtrl(ctx, opt, val, len);
    }
}

int32_t CRYPT_ECDSA_GetSecBits(const CRYPT_ECDSA_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return ECC_GetSecBits(ctx->para);
}

#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN

static int32_t SetCurveInfo(CRYPT_ECDSA_Ctx *ctx, const BSL_Param *curve)
{
    if (curve->value == NULL || curve->valueType != BSL_PARAM_TYPE_INT32 ||
        curve->valueLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_PKEY_ParaId paraId = *(CRYPT_PKEY_ParaId *)curve->value;
    int32_t ret = ECC_SetPara(ctx, CRYPT_ECDSA_NewParaById((int32_t)paraId));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_ECDSA_Import(CRYPT_ECDSA_Ctx *ctx, const BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
    const BSL_Param *prv = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_EC_PRVKEY);
    const BSL_Param *pub = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_EC_PUBKEY);
    const BSL_Param *curve = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_EC_CURVE_ID);
    if (curve != NULL) {
        ret = SetCurveInfo(ctx, curve);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (prv != NULL) {
        ret = CRYPT_ECDSA_SetPrvKeyEx(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (pub != NULL) {
        ret = CRYPT_ECDSA_SetPubKeyEx(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return ret;
}

int32_t CRYPT_ECDSA_Export(const CRYPT_ECDSA_Ctx *ctx, BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_PKEY_ParaId curveId = CRYPT_ECDSA_GetParaId(ctx);
    if (curveId == CRYPT_PKEY_PARAID_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_PARA);
        return CRYPT_ECC_ERR_PARA;
    }
    uint32_t keyBytes = (CRYPT_ECDSA_GetBits(ctx) + 7) / 8;
    if (keyBytes == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int index = 1;
    void *args = NULL;
    CRYPT_EAL_ProcessFuncCb processCb = NULL;
    BSL_Param ecdsaParams[4] = {
        {CRYPT_PARAM_EC_CURVE_ID, BSL_PARAM_TYPE_INT32, (int32_t *)&curveId, sizeof(int32_t), 0},
        {0}, {0}, BSL_PARAM_END
    };
    int32_t ret = CRYPT_GetPkeyProcessParams(params, &processCb, &args);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *buffer = BSL_SAL_Calloc(1, keyBytes * 2); // 2 denote private + public key
    if (buffer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (ctx->pubkey != NULL) {
        (void)BSL_PARAM_InitValue(&ecdsaParams[index], CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS,
            buffer, keyBytes);
        ret = CRYPT_ECDSA_GetPubKeyEx(ctx, ecdsaParams);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(buffer);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ecdsaParams[index].valueLen = ecdsaParams[index].useLen;
        index++;
    }
    if (ctx->prvkey != NULL) {
        (void)BSL_PARAM_InitValue(&ecdsaParams[index], CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS,
            buffer + keyBytes, keyBytes);
        ret = CRYPT_ECDSA_GetPrvKeyEx(ctx, ecdsaParams);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(buffer);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ecdsaParams[index].valueLen = ecdsaParams[index].useLen;
        index++;
    }
    ret = processCb(ecdsaParams, args);
    BSL_SAL_Free(buffer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_CRYPTO_KEY_DECODE_CHAIN

#ifdef HITLS_CRYPTO_ECDSA_CHECK

int32_t CRYPT_ECDSA_Check(uint32_t checkType, const CRYPT_ECDSA_Ctx *pkey1, const CRYPT_ECDSA_Ctx *pkey2)
{
    int32_t ret = ECC_PkeyCheck(pkey1, pkey2, checkType);
    if (ret == CRYPT_ECC_PAIRWISE_CHECK_FAIL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECDSA_PAIRWISE_CHECK_FAIL);
        return CRYPT_ECDSA_PAIRWISE_CHECK_FAIL;
    }
    if (ret == CRYPT_ECC_INVALID_PRVKEY) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECDSA_INVALID_PRVKEY);
        return CRYPT_ECDSA_INVALID_PRVKEY;
    }
    return ret; // may be other error occurred.
}

#endif // HITLS_CRYPTO_ECDSA_CHECK

#endif /* HITLS_CRYPTO_ECDSA */
