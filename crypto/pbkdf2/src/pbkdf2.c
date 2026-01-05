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
#ifdef HITLS_CRYPTO_PBKDF2

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_pbkdf2.h"
#include "crypt_algid.h"
#include "eal_mac_local.h"
#include "crypt_ealinit.h"
#include "pbkdf2_local.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

#define PBKDF2_MAX_BLOCKSIZE 64

static const uint32_t PBKDF_ID_LIST[] = {
    CRYPT_MAC_HMAC_MD5,
    CRYPT_MAC_HMAC_SHA1,
    CRYPT_MAC_HMAC_SHA224,
    CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512,
    CRYPT_MAC_HMAC_SM3,
    CRYPT_MAC_HMAC_SHA3_224,
    CRYPT_MAC_HMAC_SHA3_256,
    CRYPT_MAC_HMAC_SHA3_384,
    CRYPT_MAC_HMAC_SHA3_512,
};

struct CryptPbkdf2Ctx {
    CRYPT_MAC_AlgId macId;
    const EAL_MacMethod *macMeth;
    const EAL_MdMethod *mdMeth;
    void *macCtx;
    uint8_t *password;
    uint32_t passLen;
    uint8_t *salt;
    uint32_t saltLen;
    uint32_t iterCnt;
};

bool CRYPT_PBKDF2_IsValidAlgId(CRYPT_MAC_AlgId id)
{
    return ParamIdIsValid(id, PBKDF_ID_LIST, sizeof(PBKDF_ID_LIST) / sizeof(PBKDF_ID_LIST[0]));
}


int32_t CRYPT_PBKDF2_U1(const CRYPT_PBKDF2_Ctx *pCtx, uint32_t blockCount, uint8_t *u, uint32_t *blockSize)
{
    int32_t ret;
    const EAL_MacMethod *macMeth = pCtx->macMeth;
    void *macCtx = pCtx->macCtx;
    (void)macMeth->reinit(macCtx);
    if ((ret = macMeth->update(macCtx, pCtx->salt, pCtx->saltLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* processing the big endian */
    uint32_t blockCnt = CRYPT_HTONL(blockCount);
    if ((ret = macMeth->update(macCtx, (uint8_t *)&blockCnt, sizeof(blockCnt))) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if ((ret = macMeth->final(macCtx, u, blockSize)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_Un(const CRYPT_PBKDF2_Ctx *pCtx, uint8_t *u, uint32_t *blockSize, uint8_t *t, uint32_t tLen)
{
    int32_t ret;
    const EAL_MacMethod *macMeth = pCtx->macMeth;
    void *macCtx = pCtx->macCtx;

    macMeth->reinit(macCtx);
    if ((ret = macMeth->update(macCtx, u, *blockSize)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if ((ret = macMeth->final(macCtx, u, blockSize)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    DATA_XOR(t, u, t, tLen);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_CalcT(const CRYPT_PBKDF2_Ctx *pCtx, uint32_t blockCount, uint8_t *t, uint32_t *tlen)
{
    uint8_t u[PBKDF2_MAX_BLOCKSIZE] = {0};
    uint8_t tmpT[PBKDF2_MAX_BLOCKSIZE] = {0};
    uint32_t blockSize = PBKDF2_MAX_BLOCKSIZE;
    int32_t ret;
    uint32_t iterCnt = pCtx->iterCnt;
    /* U1 = PRF(Password, Salt + INT_32_BE(i))
       tmpT = U1 */
    ret = CRYPT_PBKDF2_U1(pCtx, blockCount, u, &blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(tmpT, PBKDF2_MAX_BLOCKSIZE, u, blockSize);
    for (uint32_t un = 1; un < iterCnt; un++) {
        /* t = t ^ Un */
        ret = CRYPT_PBKDF2_Un(pCtx, u, &blockSize, tmpT, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    uint32_t len = (*tlen > blockSize) ? blockSize : (*tlen);
    (void)memcpy_s(t, *tlen, tmpT, len);
    *tlen = len;
    BSL_SAL_CleanseData(u, PBKDF2_MAX_BLOCKSIZE);
    BSL_SAL_CleanseData(tmpT, PBKDF2_MAX_BLOCKSIZE);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_GenDk(const CRYPT_PBKDF2_Ctx *pCtx, uint8_t *dk, uint32_t dkLen)
{
    uint32_t curLen;
    uint8_t *t = dk;
    uint32_t tlen;
    uint32_t i;
    int32_t ret;

    ret = pCtx->macMeth->init(pCtx->macCtx, pCtx->password, pCtx->passLen, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* DK = T1 + T2 + ⋯ + Tdklen/hlen */
    for (i = 1, curLen = dkLen; curLen > 0; i++) {
        tlen = curLen;
        ret = CRYPT_PBKDF2_CalcT(pCtx, i, t, &tlen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        curLen -= tlen;
        t += tlen;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_HMAC(const EAL_MacMethod *macMeth, CRYPT_MAC_AlgId macId, const EAL_MdMethod *mdMeth,
    const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen,
    uint32_t iterCnt, uint8_t *out, uint32_t len)
{
    int32_t ret;
    CRYPT_PBKDF2_Ctx pCtx;

    if (macMeth == NULL || mdMeth == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // check mdSize validity: mdSize must be non-zero for PBKDF2 to work correctly
    // PBKDF2 requires a fixed hash output size (hLen), and mdSize == 0 would cause
    // logic errors in key derivation
    // Note: dkLen limit check is not needed here since len is uint32_t (max 0xFFFFFFFF)
    // so max len/mdSize = 0x0FFFFFFF < 0xFFFFFFFF, satisfying RFC 2898
    if (mdMeth->mdSize == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_PARAM_ERROR);
        return CRYPT_PBKDF2_PARAM_ERROR;
    }
    if (salt == NULL && saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((len == 0) || (iterCnt == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_PARAM_ERROR);
        return CRYPT_PBKDF2_PARAM_ERROR;
    }

    void *macCtx = macMeth->newCtx(macId);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    pCtx.macMeth = macMeth;
    pCtx.macCtx = macCtx;
    pCtx.password = (uint8_t *)(uintptr_t)key;
    pCtx.passLen = keyLen;
    pCtx.salt = (uint8_t *)(uintptr_t)salt;
    pCtx.saltLen = saltLen;
    pCtx.iterCnt = iterCnt;
    ret = CRYPT_PBKDF2_GenDk(&pCtx, out, len);

    macMeth->deinit(macCtx);
    macMeth->freeCtx(macCtx);
    macCtx = NULL;
    return ret;
}

CRYPT_PBKDF2_Ctx* CRYPT_PBKDF2_NewCtx(void)
{
    CRYPT_PBKDF2_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_PBKDF2_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ctx;
}

int32_t CRYPT_PBKDF2_SetMacMethod(CRYPT_PBKDF2_Ctx *ctx, const CRYPT_MAC_AlgId id)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Mac(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    EAL_MacMethLookup method;
    if (!CRYPT_PBKDF2_IsValidAlgId(id)) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_PARAM_ERROR);
        return  CRYPT_PBKDF2_PARAM_ERROR;
    }
    int32_t ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }
    ctx->macMeth = method.macMethod;
    ctx->macId = id;
    ctx->mdMeth = method.md;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_SetPassWord(CRYPT_PBKDF2_Ctx *ctx, const uint8_t *password, uint32_t passLen)
{
    if (password == NULL && passLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_ClearFree(ctx->password, ctx->passLen);

    ctx->password = BSL_SAL_Dump(password, passLen);
    if (ctx->password == NULL && passLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->passLen = passLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_SetSalt(CRYPT_PBKDF2_Ctx *ctx, const uint8_t *salt, uint32_t saltLen)
{
    if (salt == NULL && saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_FREE(ctx->salt);

    ctx->salt = BSL_SAL_Dump(salt, saltLen);
    if (ctx->salt == NULL && saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->saltLen = saltLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_SetCnt(CRYPT_PBKDF2_Ctx *ctx, const uint32_t iterCnt)
{
    if (iterCnt == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_PARAM_ERROR);
        return CRYPT_PBKDF2_PARAM_ERROR;
    }
    ctx->iterCnt = iterCnt;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_SetParam(CRYPT_PBKDF2_Ctx *ctx, const BSL_Param *param)
{
    uint32_t val = 0;
    uint32_t len = 0;
    const BSL_Param *temp = NULL;
    int32_t ret = CRYPT_PBKDF2_PARAM_ERROR;
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_MAC_ID)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_MAC_ID,
            BSL_PARAM_TYPE_UINT32, &val, &len), ret);
        GOTO_ERR_IF(CRYPT_PBKDF2_SetMacMethod(ctx, val), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_PASSWORD)) != NULL) {
        GOTO_ERR_IF(CRYPT_PBKDF2_SetPassWord(ctx, temp->value, temp->valueLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_SALT)) != NULL) {
        GOTO_ERR_IF(CRYPT_PBKDF2_SetSalt(ctx, temp->value, temp->valueLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_ITER)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_ITER,
            BSL_PARAM_TYPE_UINT32, &val, &len), ret);
        GOTO_ERR_IF(CRYPT_PBKDF2_SetCnt(ctx, val), ret);
    }
ERR:
    return ret;
}

int32_t CRYPT_PBKDF2_Derive(CRYPT_PBKDF2_Ctx *ctx, uint8_t *out, uint32_t len)
{
    int32_t ret;

    if (ctx == NULL || ctx->macMeth == NULL || ctx->mdMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->password == NULL && ctx->passLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // check mdSize validity: mdSize must be non-zero for PBKDF2 to work correctly
    // PBKDF2 requires a fixed hash output size (hLen), and mdSize == 0 would cause
    // logic errors in key derivation
    // Note: dkLen limit check is not needed here since len is uint32_t (max 0xFFFFFFFF)
    // so max len/mdSize = 0x0FFFFFFF < 0xFFFFFFFF, satisfying RFC 2898
    if (ctx->mdMeth->mdSize == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_PARAM_ERROR);
        return CRYPT_PBKDF2_PARAM_ERROR;
    }
    if (ctx->salt == NULL && ctx->saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((len == 0) || (ctx->iterCnt == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_PARAM_ERROR);
        return CRYPT_PBKDF2_PARAM_ERROR;
    }

    void *macCtx = ctx->macMeth->newCtx(ctx->macId);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->macCtx = macCtx;

    ret = CRYPT_PBKDF2_GenDk(ctx, out, len);

    ctx->macMeth->deinit(ctx->macCtx);
    ctx->macMeth->freeCtx(ctx->macCtx);
    ctx->macCtx = NULL;
    return ret;
}


int32_t CRYPT_PBKDF2_Deinit(CRYPT_PBKDF2_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_SAL_ClearFree((void *)ctx->password, ctx->passLen);
    BSL_SAL_FREE(ctx->salt);
    (void)memset_s(ctx, sizeof(CRYPT_PBKDF2_Ctx), 0, sizeof(CRYPT_PBKDF2_Ctx));
    return CRYPT_SUCCESS;
}

void CRYPT_PBKDF2_FreeCtx(CRYPT_PBKDF2_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_ClearFree((void *)ctx->password, ctx->passLen);
    BSL_SAL_FREE(ctx->salt);
    BSL_SAL_Free(ctx);
}

CRYPT_PBKDF2_Ctx *CRYPT_PBKDF2_DupCtx(const CRYPT_PBKDF2_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    uint8_t *password = NULL;
    uint8_t *salt = NULL;
    CRYPT_PBKDF2_Ctx *newCtx = BSL_SAL_Dump(ctx, sizeof(CRYPT_PBKDF2_Ctx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    void *macCtx = NULL;
    if (ctx->macCtx != NULL) {
        macCtx = ctx->macMeth->dupCtx(ctx->macCtx);
        GOTO_EXIT_IF((macCtx == NULL), CRYPT_MEM_ALLOC_FAIL);
    }

    if (ctx->password != NULL) {
        password = BSL_SAL_Dump(ctx->password, ctx->passLen);
        GOTO_EXIT_IF((password == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    if (ctx->salt != NULL) {
        salt = BSL_SAL_Dump(ctx->salt, ctx->saltLen);
        GOTO_EXIT_IF((salt == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    newCtx->macCtx = macCtx;
    newCtx->password = password;
    newCtx->salt = salt;
    return newCtx;
EXIT:
    if (macCtx != NULL) {
        ctx->macMeth->freeCtx(macCtx);
    }
    BSL_SAL_ClearFree(password, ctx->passLen);
    BSL_SAL_Free(salt);
    BSL_SAL_Free(newCtx);
    return NULL;
}

#endif // HITLS_CRYPTO_PBKDF2
