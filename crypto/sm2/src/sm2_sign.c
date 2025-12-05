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
#ifdef HITLS_CRYPTO_SM2

#include <stdbool.h>
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_bn.h"
#include "crypt_encode_internal.h"
#include "crypt_ecc.h"
#include "crypt_ecc_pkey.h"
#include "crypt_local_types.h"
#include "crypt_sm2.h"
#include "sm2_local.h"
#include "eal_md_local.h"
#include "crypt_params_key.h"

static int32_t Sm2SetUserId(CRYPT_SM2_Ctx *ctx, const uint8_t *val, uint32_t len)
{
    ctx->userId = BSL_SAL_Calloc(len, 1u);
    if (ctx->userId == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void) memcpy_s(ctx->userId, len, val, len);
    ctx->userIdLen = len;
    return CRYPT_SUCCESS;
}

CRYPT_SM2_Ctx *CRYPT_SM2_NewCtx(void)
{
    CRYPT_SM2_Ctx *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_SM2_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    ctx->pkey = ECC_PkeyNewCtx(CRYPT_ECC_SM2);
    if (ctx->pkey == NULL) {
        CRYPT_SM2_FreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    const EAL_MdMethod *mdMethod = EAL_MdFindMethod(CRYPT_MD_SM3);
    if (mdMethod == NULL) {
        CRYPT_SM2_FreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_EVENT_ERR);
        return NULL;
    }
    ctx->hashMethod = (const EAL_MdMethod *)mdMethod;
    ctx->server = 1; // Indicates the initiator by default.
    ctx->isSumValid = 0; // checksum is invalid by default.
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

CRYPT_SM2_Ctx *CRYPT_SM2_NewCtxEx(void *libCtx)
{
    CRYPT_SM2_Ctx *ctx = CRYPT_SM2_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->pkey->libCtx = libCtx;
    ECC_SetLibCtx(ctx->pkey->libCtx, ctx->pkey->para);
    return ctx;
}

CRYPT_SM2_Ctx *CRYPT_SM2_DupCtx(CRYPT_SM2_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_SM2_Ctx *newCtx = BSL_SAL_Calloc(1u, sizeof(CRYPT_SM2_Ctx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->pkey, ctx->pkey, ECC_DupCtx(ctx->pkey), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->pointR, ctx->pointR, ECC_DupPoint(ctx->pointR), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->r, ctx->r, BN_Dup(ctx->r), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->userId, ctx->userId, BSL_SAL_Dump(ctx->userId, ctx->userIdLen),
        CRYPT_MEM_ALLOC_FAIL);
    newCtx->userIdLen = ctx->userIdLen;

    newCtx->pkgImpl = ctx->pkgImpl;
    newCtx->hashMethod = ctx->hashMethod;
    newCtx->server = ctx->server;
    newCtx->isSumValid = ctx->isSumValid;
    BSL_SAL_ReferencesInit(&(newCtx->references));
    (void)memcpy_s(newCtx->sumCheck, SM3_MD_SIZE, ctx->sumCheck, SM3_MD_SIZE);
    (void)memcpy_s(newCtx->sumSend, SM3_MD_SIZE, ctx->sumSend, SM3_MD_SIZE);

    return newCtx;
ERR:
    CRYPT_SM2_FreeCtx(newCtx);
    return NULL;
}

void CRYPT_SM2_FreeCtx(CRYPT_SM2_Ctx *ctx)
{
    int val = 0;
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_AtomicDownReferences(&(ctx->references), &val);
    if (val > 0) {
        return;
    }
    BSL_SAL_ReferencesFree(&(ctx->references));
    ECC_FreeCtx(ctx->pkey);

    BSL_SAL_FREE(ctx->userId);
    BN_Destroy(ctx->r);
    ECC_FreePoint(ctx->pointR);
    BSL_SAL_FREE(ctx);
    return;
}

int32_t Sm2ComputeZDigest(const CRYPT_SM2_Ctx *ctx, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    if (ctx->userIdLen >= (UINT16_MAX / 8)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ID_TOO_LARGE);
        return CRYPT_SM2_ID_TOO_LARGE;
    }
    /* 2-byte id length in bits */
    uint16_t entl = (uint16_t)(8 * ctx->userIdLen);
    uint8_t eByte = (uint8_t)(entl >> 8);
    uint8_t maxPubData[SM2_MAX_PUBKEY_DATA_LENGTH] = {0};
    CRYPT_Sm2Pub pub = {maxPubData, SM2_MAX_PUBKEY_DATA_LENGTH};
    uint32_t keyBits = CRYPT_SM2_GetBits(ctx);
    BN_BigNum *a = ECC_GetParaA(ctx->pkey->para);
    BN_BigNum *b = ECC_GetParaB(ctx->pkey->para);
    BN_BigNum *xG = ECC_GetParaX(ctx->pkey->para);
    BN_BigNum *yG = ECC_GetParaY(ctx->pkey->para);
    void *mdCtx = ctx->hashMethod->newCtx();
    uint8_t *buf = BSL_SAL_Calloc(1u, keyBits);
    if (a == NULL || b == NULL || xG == NULL || yG == NULL || buf == NULL || mdCtx == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    BSL_Param tmpPara[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, maxPubData,
        SM2_MAX_PUBKEY_DATA_LENGTH, 0}, BSL_PARAM_END};
    GOTO_ERR_IF(CRYPT_SM2_GetPubKey(ctx, tmpPara), ret);
    pub.len = tmpPara[0].useLen;
    GOTO_ERR_IF(ctx->hashMethod->init(mdCtx, NULL), ret);
    // User A has a distinguishable identifier IDA with a length of entlenA bits,
    // and ENTLA is two bytes converted from an integer entlenA
    // H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
    GOTO_ERR_IF(ctx->hashMethod->update(mdCtx, &eByte, 1), ret); // ENTLA
    eByte = entl & 0xFF;
    GOTO_ERR_IF(ctx->hashMethod->update(mdCtx, &eByte, 1), ret); // ENTLA
    if (ctx->userIdLen > 0) {
        GOTO_ERR_IF(ctx->hashMethod->update(mdCtx, ctx->userId, ctx->userIdLen), ret); // IDA
    }
    GOTO_ERR_IF_EX(BN_Bn2Bin(a, buf, &keyBits), ret);
    GOTO_ERR_IF(ctx->hashMethod->update(mdCtx, buf, keyBits), ret); // a
    GOTO_ERR_IF_EX(BN_Bn2Bin(b, buf, &keyBits), ret);
    GOTO_ERR_IF(ctx->hashMethod->update(mdCtx, buf, keyBits), ret); // b
    GOTO_ERR_IF_EX(BN_Bn2Bin(xG, buf, &keyBits), ret);
    GOTO_ERR_IF(ctx->hashMethod->update(mdCtx, buf, keyBits), ret); // xG
    keyBits =  CRYPT_SM2_GetBits(ctx);
    GOTO_ERR_IF_EX(BN_Bn2Bin(yG, buf, &keyBits), ret);
    GOTO_ERR_IF(ctx->hashMethod->update(mdCtx, buf, keyBits), ret); // yG
    GOTO_ERR_IF(ctx->hashMethod->update(mdCtx, pub.data + 1, pub.len - 1), ret); // xA and yA
    GOTO_ERR_IF(ctx->hashMethod->final(mdCtx, out, outLen), ret);
ERR:
    ctx->hashMethod->freeCtx(mdCtx);
    BN_Destroy(a);
    BN_Destroy(b);
    BN_Destroy(xG);
    BN_Destroy(yG);
    BSL_SAL_FREE(buf);
    return ret;
}

#ifdef HITLS_CRYPTO_SM2_SIGN
static int32_t Sm2ComputeMsgHash(const CRYPT_SM2_Ctx *ctx, const uint8_t *msg, uint32_t msgLen, BN_BigNum *e)
{
    int ret;
    uint8_t out[SM3_MD_SIZE];
    uint32_t outLen = sizeof(out);
    void *mdCtx = ctx->hashMethod->newCtx();
    if (mdCtx == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF_EX(Sm2ComputeZDigest(ctx, out, &outLen), ret);
    GOTO_ERR_IF(ctx->hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(ctx->hashMethod->update(mdCtx, out, outLen), ret);
    GOTO_ERR_IF(ctx->hashMethod->update(mdCtx, msg, msgLen), ret);
    GOTO_ERR_IF(ctx->hashMethod->final(mdCtx, out, &outLen), ret);
    GOTO_ERR_IF_EX(BN_Bin2Bn(e, out, outLen), ret);
ERR:
    ctx->hashMethod->freeCtx(mdCtx);
    return ret;
}
#endif

uint32_t CRYPT_SM2_GetBits(const CRYPT_SM2_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return ECC_PkeyGetBits(ctx->pkey);
}

int32_t CRYPT_SM2_SetPrvKey(CRYPT_SM2_Ctx *ctx, const BSL_Param *para)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ECC_PkeySetPrvKey(ctx->pkey, para);
}

int32_t CRYPT_SM2_SetPubKey(CRYPT_SM2_Ctx *ctx, const BSL_Param *para)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ECC_PkeySetPubKey(ctx->pkey, para);
}

int32_t CRYPT_SM2_GetPrvKey(const CRYPT_SM2_Ctx *ctx, BSL_Param *para)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    return ECC_PkeyGetPrvKey(ctx->pkey, para);
}

int32_t CRYPT_SM2_GetPubKey(const CRYPT_SM2_Ctx *ctx, BSL_Param *para)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    return ECC_PkeyGetPubKey(ctx->pkey, para);
}

int32_t CRYPT_SM2_Gen(CRYPT_SM2_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    return ECC_PkeyGen(ctx->pkey);
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_SM2_Import(CRYPT_SM2_Ctx *ctx, const BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    const BSL_Param *prv = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_EC_PRVKEY);
    const BSL_Param *pub = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_EC_PUBKEY);
    if (prv != NULL) {
        ret = CRYPT_SM2_SetPrvKey(ctx, prv);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (pub != NULL) {
        ret = CRYPT_SM2_SetPubKey(ctx, pub);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM2_Export(const CRYPT_SM2_Ctx *ctx, BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t index = 0;
    uint32_t keyBytes = (CRYPT_SM2_GetBits(ctx) + 7) / 8;
    CRYPT_EAL_ProcessFuncCb processCb = NULL;
    void *args = NULL;
    BSL_Param sm2Params[3] = {0};
    int32_t ret = CRYPT_GetPkeyProcessParams(params, &processCb, &args);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *buffer = BSL_SAL_Calloc(1, keyBytes * 2);
    if (buffer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (ctx->pkey->prvkey != NULL) {
        (void)BSL_PARAM_InitValue(&sm2Params[index], CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, buffer, keyBytes);
        ret = CRYPT_SM2_GetPrvKey(ctx, sm2Params);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(buffer);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        sm2Params[index].valueLen = sm2Params[index].useLen;
        index++;
    }
    if (ctx->pkey->pubkey != NULL) {
        (void)BSL_PARAM_InitValue(&sm2Params[index], CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS,
            buffer + keyBytes, keyBytes);
        ret = CRYPT_SM2_GetPubKey(ctx, sm2Params);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(buffer);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        sm2Params[index].valueLen = sm2Params[index].useLen;
        index++;
    }
    ret = processCb(sm2Params, args);
    BSL_SAL_Free(buffer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif
#ifdef HITLS_CRYPTO_SM2_SIGN
uint32_t CRYPT_SM2_GetSignLen(const CRYPT_SM2_Ctx *ctx)
{
    if (ctx == NULL || ctx->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    uint32_t qLen = (ECC_ParaBits(ctx->pkey->para) / 8) + 1;
    uint32_t maxSignLen = 0;
    int32_t ret = CRYPT_EAL_GetSignEncodeLen(qLen, qLen, &maxSignLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return 0;
    }
    return maxSignLen;
}

static int32_t Sm2SignCore(const CRYPT_SM2_Ctx *ctx, BN_BigNum *e, BN_BigNum *r, BN_BigNum *s)
{
    uint32_t keyBits = CRYPT_SM2_GetBits(ctx);
    BN_BigNum *k = BN_Create(keyBits);
    BN_BigNum *tmp = BN_Create(keyBits);
    // An extra bit is allocated to prevent the number of bits in the result of adding BNs from exceeding the keybits.
    BN_BigNum *t = BN_Create(keyBits + 1);
    BN_BigNum *paraN = ECC_GetParaN(ctx->pkey->para);
    ECC_Point *pt = ECC_NewPoint(ctx->pkey->para);
    BN_Optimizer *opt = BN_OptimizerCreate();
    int32_t ret, i;

    if ((k == NULL) || (tmp == NULL) || (t == NULL) || (pt == NULL) || (paraN == NULL) || (opt == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    for (i = 0; i < CRYPT_ECC_TRY_MAX_CNT; i++) {
        GOTO_ERR_IF(BN_RandRangeEx(ctx->pkey->libCtx, k, paraN), ret);
        if (BN_IsZero(k)) {
            continue;
        }
        // pt = k * G
        GOTO_ERR_IF(ECC_PointMul(ctx->pkey->para, pt, k, NULL), ret);
        // r = (e + pt->x) mod n
        GOTO_ERR_IF(ECC_GetPointDataX(ctx->pkey->para, pt, tmp), ret);
        GOTO_ERR_IF(BN_ModAdd(r, e, tmp, paraN, opt), ret);
        // if r == 0 || r + k == n, then restart
        GOTO_ERR_IF(BN_Add(t, r, k), ret);
        if (BN_IsZero(r) || BN_Cmp(t, paraN) == 0) {
            continue;
        }
        // prvkey * r mod n == (r * dA) mod n
        GOTO_ERR_IF(BN_ModMul(s, ctx->pkey->prvkey, r, paraN, opt), ret);
        // k - prvkey * r mod n
        GOTO_ERR_IF(BN_ModSub(s, k, s, paraN, opt), ret);
        // 1/(1 + d) mod n, tmp stores 1/(1 + d)
        GOTO_ERR_IF(BN_AddLimb(t, ctx->pkey->prvkey, 1), ret);
        GOTO_ERR_IF(ECC_ModOrderInv(ctx->pkey->para, tmp, t), ret);
        // s = (1/(1+d)) * (k - prvkey * r) mod n
        GOTO_ERR_IF(BN_ModMul(s, tmp, s, paraN, opt), ret);
        // if s == 0, then restart
        if (BN_IsZero(s) != true) {
            break;
        }
    }

    if (i >= CRYPT_ECC_TRY_MAX_CNT) {
        ret = CRYPT_SM2_ERR_TRY_CNT;
        BSL_ERR_PUSH_ERROR(ret);
    }

ERR:
    BN_Destroy(k);
    BN_Destroy(tmp);
    BN_Destroy(t);
    BN_Destroy(paraN);
    ECC_FreePoint(pt);
    BN_OptimizerDestroy(opt);
    return ret;
}

int32_t KeyCheckAndPubGen(const CRYPT_SM2_Ctx *ctx)
{
    int32_t ret;
    if (ctx->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_EMPTY_KEY);
        return CRYPT_SM2_ERR_EMPTY_KEY;
    }

    if (ctx->pkey->prvkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_NO_PRVKEY);
        return CRYPT_SM2_NO_PRVKEY;
    }
    if (ctx->pkey->pubkey != NULL) {
        return CRYPT_SUCCESS;
    }
    ret = ECC_GenPublicKey(ctx->pkey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_SM2_Sign(const CRYPT_SM2_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    int32_t ret;
    if (algId != CRYPT_MD_SM3) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    
    if ((ctx == NULL) || (sign == NULL) || (signLen == NULL) || ((data == NULL) && (dataLen != 0))) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ret = KeyCheckAndPubGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (ctx->hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_NO_HASH_METHOD);
        return CRYPT_SM2_ERR_NO_HASH_METHOD;
    }
    if (*signLen < CRYPT_SM2_GetSignLen(ctx)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_SM2_BUFF_LEN_NOT_ENOUGH;
    }

    uint32_t keyBits = CRYPT_SM2_GetBits(ctx);
    BN_BigNum *r = BN_Create(keyBits);
    BN_BigNum *s = BN_Create(keyBits);
    BN_BigNum *d = BN_Create(keyBits);
    if (r == NULL || s == NULL || d == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    GOTO_ERR_IF_EX(Sm2ComputeMsgHash(ctx, data, dataLen, d), ret);
    GOTO_ERR_IF_EX(Sm2SignCore(ctx, d, r, s), ret);
    ret = CRYPT_EAL_EncodeSign(r, s, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    BN_Destroy(r);
    BN_Destroy(s);
    BN_Destroy(d);
    return ret;
}

int32_t CRYPT_SM2_SignData(const CRYPT_SM2_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    int32_t ret = CRYPT_SUCCESS;
    RETURN_RET_IF((ctx == NULL || sign == NULL || signLen == NULL || ((data == NULL) && (dataLen != 0))),
        CRYPT_NULL_INPUT);

    RETURN_RET_IF((ctx->pkey == NULL || ctx->pkey->prvkey == NULL), CRYPT_SM2_NO_PRVKEY);
    RETURN_RET_IF((dataLen != SM3_MD_SIZE), CRYPT_INVALID_ARG);

    if (*signLen < CRYPT_SM2_GetSignLen(ctx)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_SM2_BUFF_LEN_NOT_ENOUGH;
    }

    uint32_t keyBits = CRYPT_SM2_GetBits(ctx);
    BN_BigNum *d = BN_Create(keyBits);
    BN_BigNum *r = BN_Create(keyBits);
    BN_BigNum *s = BN_Create(keyBits);
    if (r == NULL || s == NULL || d == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    GOTO_ERR_IF_EX(BN_Bin2Bn(d, data, dataLen), ret);
    GOTO_ERR_IF_EX(Sm2SignCore(ctx, d, r, s), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_EncodeSign(r, s, sign, signLen), ret);
ERR:
    BN_Destroy(d);
    BN_Destroy(r);
    BN_Destroy(s);
    return ret;
}

static int32_t VerifyCheckSign(const CRYPT_SM2_Ctx *ctx, BN_BigNum *r, BN_BigNum *s)
{
    if (ctx->pkey->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BN_BigNum *paraN = ECC_GetParaN(ctx->pkey->para);
    if (paraN == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    if ((BN_Cmp(r, paraN) >= 0) || (BN_Cmp(s, paraN) >= 0)) {
        BN_Destroy(paraN);
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_VERIFY_FAIL);
        return CRYPT_SM2_VERIFY_FAIL;
    }
    BN_Destroy(paraN);
    if (BN_IsZero(r) || BN_IsZero(s)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_VERIFY_FAIL);
        return CRYPT_SM2_VERIFY_FAIL;
    }

    return CRYPT_SUCCESS;
}

static int32_t Sm2VerifyCore(const CRYPT_SM2_Ctx *ctx, BN_BigNum *e, const BN_BigNum *r, const BN_BigNum *s)
{
    uint32_t keyBits = CRYPT_SM2_GetBits(ctx);
    BN_BigNum *t = BN_Create(keyBits);
    ECC_Point *tpt = ECC_NewPoint(ctx->pkey->para);
    BN_BigNum *tptX = BN_Create(keyBits);
    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_BigNum *paraN = ECC_GetParaN(ctx->pkey->para);
    int32_t ret;

    if ((t == NULL) || (tpt == NULL) || (tptX == NULL) || (paraN == NULL) || (opt == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
     // B5: calculate t = (r' + s') modn, verification failed if t=0
    GOTO_ERR_IF_EX(BN_ModAddQuick(t, r, s, paraN, opt), ret);
    if (BN_IsZero(t)) {
        ret = CRYPT_SM2_VERIFY_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
    }
    // calculate the point (x1', y1')=[s']G + [t]PA
    GOTO_ERR_IF(ECC_PointMulAdd(ctx->pkey->para, tpt, s, t, ctx->pkey->pubkey), ret);
    GOTO_ERR_IF_EX(ECC_GetPointDataX(ctx->pkey->para, tpt, tptX), ret);
    // calculate R=(e'+x1') modn, verification pass if yes, otherwise failed
    GOTO_ERR_IF_EX(BN_ModAdd(t, e, tptX, paraN, opt), ret);
    if (BN_Cmp(r, t) != 0) {
        ret = CRYPT_SM2_VERIFY_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
    }

ERR:
    BN_Destroy(t);
    BN_Destroy(paraN);
    ECC_FreePoint(tpt);
    BN_Destroy(tptX);
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t IsParaVaild(const CRYPT_SM2_Ctx *ctx)
{
    if (ctx->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_EMPTY_KEY);
        return CRYPT_SM2_ERR_EMPTY_KEY;
    }

    if (ctx->pkey->pubkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_NO_PUBKEY);
        return CRYPT_SM2_NO_PUBKEY;
    }

    if (ctx->hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_NO_HASH_METHOD);
        return CRYPT_SM2_ERR_NO_HASH_METHOD;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM2_Verify(const CRYPT_SM2_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    if (algId != CRYPT_MD_SM3) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    if ((ctx == NULL) || ((data == NULL) && (dataLen != 0)) || (sign == NULL) || (signLen == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t keyBits = CRYPT_SM2_GetBits(ctx);
    int32_t ret = IsParaVaild(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_BigNum *r = BN_Create(keyBits);
    BN_BigNum *s = BN_Create(keyBits);
    BN_BigNum *e = BN_Create(keyBits);
    if (r == NULL || s == NULL || e == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF_EX(Sm2ComputeMsgHash(ctx, data, dataLen, e), ret);
    GOTO_ERR_IF(CRYPT_EAL_DecodeSign(sign, signLen, r, s), ret);
    // Verify that r->s and s->s are within the range of 1~n-1.
    GOTO_ERR_IF_EX(VerifyCheckSign(ctx, r, s), ret);
    GOTO_ERR_IF_EX(Sm2VerifyCore(ctx, e, r, s), ret);
ERR:
    BN_Destroy(r);
    BN_Destroy(s);
    BN_Destroy(e);
    return ret;
}

int32_t CRYPT_SM2_VerifyData(const CRYPT_SM2_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    int32_t ret = CRYPT_SUCCESS;
    RETURN_RET_IF(((ctx == NULL) || ((data == NULL) && (dataLen != 0)) || (sign == NULL) || (signLen == 0)),
        CRYPT_NULL_INPUT);
    RETURN_RET_IF((ctx->pkey == NULL || ctx->pkey->pubkey == NULL), CRYPT_SM2_NO_PUBKEY);
    RETURN_RET_IF((dataLen != SM3_MD_SIZE), CRYPT_INVALID_ARG);

    uint32_t keyBits = CRYPT_SM2_GetBits(ctx);
    BN_BigNum *e = BN_Create(keyBits);
    BN_BigNum *r = BN_Create(keyBits);
    BN_BigNum *s = BN_Create(keyBits);
    if (r == NULL || s == NULL || e == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    GOTO_ERR_IF_EX(BN_Bin2Bn(e, data, dataLen), ret);
    GOTO_ERR_IF(CRYPT_EAL_DecodeSign(sign, signLen, r, s), ret);
    // Verify that r->s and s->s are within the range of 1~n-1.
    GOTO_ERR_IF_EX(VerifyCheckSign(ctx, r, s), ret);
    GOTO_ERR_IF_EX(Sm2VerifyCore(ctx, e, r, s), ret);
ERR:
    BN_Destroy(e);
    BN_Destroy(r);
    BN_Destroy(s);
    return ret;
}
#endif

static void Sm2Clean(CRYPT_SM2_Ctx *ctx)
{
    BN_Destroy(ctx->r);
    ctx->r = NULL;
    ECC_FreePoint(ctx->pointR);
    ctx->pointR = NULL;
    ctx->isSumValid = 0;
    return;
}

static int32_t Sm2GenerateR(CRYPT_SM2_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    Sm2Clean(ctx);
    uint32_t keyBits = CRYPT_SM2_GetBits(ctx);
    int32_t tryNum = 0;
    BN_BigNum *order = ECC_GetParaN(ctx->pkey->para);
    ctx->r = BN_Create(keyBits);
    ctx->pointR = ECC_NewPoint(ctx->pkey->para);
    BN_BigNum *tmp = BN_Create(keyBits);
    if (order == NULL || ctx->r == NULL || ctx->pointR == NULL || tmp == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    for (; tryNum < CRYPT_ECC_TRY_MAX_CNT; tryNum++) {
        GOTO_ERR_IF_EX(BN_RandRangeEx(ctx->pkey->libCtx, ctx->r, order), ret);
        if (!BN_IsZero(ctx->r)) {
            break;
        }
    }

    if (tryNum >= CRYPT_ECC_TRY_MAX_CNT) {
        ret = CRYPT_SM2_ERR_TRY_CNT;
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_TRY_CNT);
        goto ERR;
    }

    GOTO_ERR_IF(ECC_PointMul(ctx->pkey->para, ctx->pointR, ctx->r, NULL), ret);
    GOTO_ERR_IF(ECC_GetPointDataX(ctx->pkey->para, ctx->pointR, tmp), ret);
    GOTO_ERR_IF(ECC_EncodePoint(ctx->pkey->para, ctx->pointR, (uint8_t *)val, &len, CRYPT_POINT_UNCOMPRESSED), ret);
    BN_Destroy(tmp);
    BN_Destroy(order);
    return ret;
ERR:
    BN_Destroy(tmp);
    BN_Destroy(order);
    Sm2Clean(ctx);
    return ret;
}

static int32_t Sm2SetR(CRYPT_SM2_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    Sm2Clean(ctx);
    ECC_Point *rs = ECC_NewPoint(ctx->pkey->para);
    if (rs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = ECC_DecodePoint(ctx->pkey->para, rs, (const uint8_t *)val, len);
    if (ret != CRYPT_SUCCESS) {
        ECC_FreePoint(rs);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ctx->pointR = rs;
    return ret;
}

static int32_t Sm2SetRandom(CRYPT_SM2_Ctx *ctx, const void *val, uint32_t len)
{
    int32_t ret;
    uint32_t keyBits = CRYPT_SM2_GetBits(ctx);
    BN_BigNum *order = ECC_GetParaN(ctx->pkey->para);
    ctx->r = BN_Create(keyBits);
    ctx->pointR = ECC_NewPoint(ctx->pkey->para);
    BN_BigNum *tmp = BN_Create(keyBits);
    if (order == NULL || ctx->r == NULL || ctx->pointR == NULL || tmp == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = BN_Bin2Bn(ctx->r, (const uint8_t *)val, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    GOTO_ERR_IF(ECC_PointMul(ctx->pkey->para, ctx->pointR, ctx->r, NULL), ret);
    GOTO_ERR_IF(ECC_GetPointDataX(ctx->pkey->para, ctx->pointR, tmp), ret);
    BN_Destroy(order);
    BN_Destroy(tmp);
    return ret;
ERR:
    BN_Destroy(order);
    BN_Destroy(tmp);
    Sm2Clean(ctx);
    return ret;
}

static int32_t Sm2GetSumSend(CRYPT_SM2_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    if (ctx->isSumValid != 1) {
        ret = CRYPT_SM2_ERR_S_NOT_SET;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (len != SM3_MD_SIZE) {
        ret = CRYPT_SM2_BUFF_LEN_NOT_ENOUGH;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = memcpy_s((uint8_t *)val, len, ctx->sumSend, SM3_MD_SIZE);
    if (ret != EOK) {
        ret = CRYPT_SM2_ERR_GET_S;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return CRYPT_SUCCESS;
}

/* consttime memcmp function */
static int32_t IsDataEqual(const uint8_t *data1, const uint8_t *data2, uint32_t len)
{
    uint8_t check = 0;
    for (uint32_t i = 0; i < len; i++) {
        check |= data1[i] ^ data2[i];
    }
    if (check != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_EXCH_VERIFY_FAIL);
        return CRYPT_SM2_EXCH_VERIFY_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t Sm2DoCheck(CRYPT_SM2_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    if (ctx->isSumValid != 1) {
        ret = CRYPT_SM2_ERR_S_NOT_SET;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (len != SM3_MD_SIZE) {
        ret = CRYPT_SM2_ERR_DATA_LEN;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = IsDataEqual(ctx->sumCheck, val, len);
    if (ret != CRYPT_SUCCESS) {
        ctx->isSumValid = 0;
    }
    return ret;
}

static int32_t CtrlServerSet(CRYPT_SM2_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_CTRL_LEN);
        return CRYPT_SM2_ERR_CTRL_LEN;
    }
    const int32_t t = *(const int32_t *)val;
    if (t != 0 && t != 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_INVALID_SERVER_TYPE);
        return CRYPT_SM2_INVALID_SERVER_TYPE;
    }
    ctx->server = t;
    return CRYPT_SUCCESS;
}

static int32_t CtrlUserId(CRYPT_SM2_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len == 0 || len > SM2_MAX_ID_LENGTH) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_CTRL_LEN);
        return CRYPT_ECC_PKEY_ERR_CTRL_LEN;
    }
    BSL_SAL_FREE(ctx->userId);
    return Sm2SetUserId(ctx, val, len);
}

static int32_t Sm2SetPKG(CRYPT_SM2_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SM2_ERR_CTRL_LEN);
        return CRYPT_SM2_ERR_CTRL_LEN;
    }
    if (*(const uint32_t *)val != 0 && *(const uint32_t *)val != 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->pkgImpl = *(const uint32_t *)val;
    return CRYPT_SUCCESS;
}

static int32_t SM2UpReferences(CRYPT_SM2_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL || len != (uint32_t)sizeof(int)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return BSL_SAL_AtomicUpReferences(&(ctx->references), (int *)val);
}

static int32_t CRYPT_SM2_GetLen(const CRYPT_SM2_Ctx *ctx, GetLenFunc func, void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    *(int32_t *)val = func(ctx);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM2_Ctrl(CRYPT_SM2_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SM2_ERR_UNSUPPORTED_CTRL_OPTION;
    switch (opt) {
        case CRYPT_CTRL_GET_BITS:
            return CRYPT_SM2_GetLen(ctx, (GetLenFunc)CRYPT_SM2_GetBits, val, len);
#ifdef HITLS_CRYPTO_SM2_SIGN
        case CRYPT_CTRL_GET_SIGNLEN:
            return CRYPT_SM2_GetLen(ctx, (GetLenFunc)CRYPT_SM2_GetSignLen, val, len);
#endif
        case CRYPT_CTRL_GET_SECBITS:
            return CRYPT_SM2_GetLen(ctx, (GetLenFunc)CRYPT_SM2_GetSecBits, val, len);
        case CRYPT_CTRL_SET_SM2_SERVER:
            ret = CtrlServerSet(ctx, val, len);
            break;
        case CRYPT_CTRL_SET_SM2_USER_ID:
            ret = CtrlUserId(ctx, val, len);
            break;
        case CRYPT_CTRL_GENE_SM2_R:
            ret = Sm2GenerateR(ctx, val, len);
            break;
        case CRYPT_CTRL_SET_SM2_R:
            ret = Sm2SetR(ctx, val, len);
            break;
        case CRYPT_CTRL_SET_SM2_RANDOM:
            ret = Sm2SetRandom(ctx, val, len);
            break;
        case CRYPT_CTRL_GET_SM2_SEND_CHECK:
            ret = Sm2GetSumSend(ctx, val, len);
            break;
        case CRYPT_CTRL_SM2_DO_CHECK:
            ret = Sm2DoCheck(ctx, val, len);
            break;
        case CRYPT_CTRL_SET_SM2_PKG:
            ret = Sm2SetPKG(ctx, val, len);
            break;
        case CRYPT_CTRL_UP_REFERENCES:
            ret = SM2UpReferences(ctx, val, len);
            break;
        default:
            ret = ECC_PkeyCtrl(ctx->pkey, opt, val, len);
            break;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_SM2_Cmp(const CRYPT_SM2_Ctx *a, const CRYPT_SM2_Ctx *b)
{
    if (a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ECC_PkeyCmp(a->pkey, b->pkey);
}

int32_t CRYPT_SM2_GetSecBits(const CRYPT_SM2_Ctx *ctx)
{
    if (ctx == NULL || ctx->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return ECC_GetSecBits(ctx->pkey->para);
}

#endif // HITLS_CRYPTO_SM2_SIGN
