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
#include "crypt_util_ctrl.h"
#include "crypt_utils.h"
#include "crypt_algid.h"
#include "eal_mac_local.h"
#include "crypt_ealinit.h"
#include "pbkdf2_local.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "crypt_pbkdf2.h"

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
    EAL_MacMethod macMeth;
    uint32_t mdSize;
    void *macCtx;
    uint8_t *password;
    uint32_t passLen;
    uint8_t *salt;
    uint32_t saltLen;
    uint32_t iterCnt;
#ifdef HITLS_CRYPTO_PROVIDER
    void *libCtx;
#endif
    bool hasGetMdSize;
};

bool CRYPT_PBKDF2_IsValidAlgId(CRYPT_MAC_AlgId id)
{
    return ParamIdIsValid(id, PBKDF_ID_LIST, sizeof(PBKDF_ID_LIST) / sizeof(PBKDF_ID_LIST[0]));
}

int32_t CRYPT_PBKDF2_U1(const CRYPT_PBKDF2_Ctx *pCtx, uint32_t blockCount, uint8_t *u, uint32_t *blockSize)
{
    int32_t ret;
    const EAL_MacMethod *macMeth = &pCtx->macMeth;
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
    const EAL_MacMethod *macMeth = &pCtx->macMeth;
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

    ret = pCtx->macMeth.init(pCtx->macCtx, pCtx->password, pCtx->passLen, NULL);
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

int32_t CRYPT_PBKDF2_HMAC(void *libCtx, const EAL_MacMethod *macMeth, CRYPT_MAC_AlgId macId, const EAL_MdMethod *mdMeth,
    const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen,
    uint32_t iterCnt, uint8_t *out, uint32_t len)
{
    int32_t ret;
    CRYPT_PBKDF2_Ctx pCtx = {0};

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

    void *macCtx = macMeth->newCtx(libCtx, macId);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    pCtx.macId = macId;
    pCtx.macMeth = *macMeth;
    pCtx.macCtx = macCtx;
    pCtx.password = (uint8_t *)(uintptr_t)key;
    pCtx.passLen = keyLen;
    pCtx.salt = (uint8_t *)(uintptr_t)salt;
    pCtx.saltLen = saltLen;
    pCtx.iterCnt = iterCnt;
    ret = CRYPT_PBKDF2_GenDk(&pCtx, out, len);

    macMeth->deinit(macCtx);
    macMeth->freeCtx(macCtx);
    return ret;
}

CRYPT_PBKDF2_Ctx *CRYPT_PBKDF2_NewCtx(void)
{
    CRYPT_PBKDF2_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_PBKDF2_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ctx;
}

CRYPT_PBKDF2_Ctx *CRYPT_PBKDF2_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    (void)algId;
    CRYPT_PBKDF2_Ctx *ctx = CRYPT_PBKDF2_NewCtx();
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
#ifdef HITLS_CRYPTO_PROVIDER
    ctx->libCtx = libCtx;
#endif
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
    if (!CRYPT_PBKDF2_IsValidAlgId(id)) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_PARAM_ERROR);
        return  CRYPT_PBKDF2_PARAM_ERROR;
    }
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_CTRL_SetMacMethod(ctx->libCtx, id, CRYPT_PBKDF2_ERR_MAC_METH, &ctx->macCtx, &ctx->macMeth,
        &ctx->macId);
#else
    return CRYPT_CTRL_SetMacMethod(NULL, id, CRYPT_PBKDF2_ERR_MAC_METH, &ctx->macCtx, &ctx->macMeth, &ctx->macId);
#endif
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

static int32_t Pbkdf2GetMdSize(CRYPT_PBKDF2_Ctx *ctx, const char *mdAttr)
{
    if (ctx->hasGetMdSize) {
        return CRYPT_SUCCESS;
    }
    void *libCtx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    libCtx = ctx->libCtx;
#endif

    EAL_MdMethod mdMeth = {0};
    EAL_MacDepMethod depMeth = {.method = {.md = &mdMeth}};
    int32_t ret = EAL_MacFindDepMethod(ctx->macId, libCtx, mdAttr, &depMeth, NULL, libCtx != NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ctx->mdSize = mdMeth.mdSize;
    ctx->hasGetMdSize = true;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t CRYPT_PBKDF2_SetMdAttr(CRYPT_PBKDF2_Ctx *ctx, const char *mdAttr, uint32_t valLen)
{
    int32_t ret = CRYPT_CTRL_SetMdAttrToHmac(mdAttr, valLen, ctx->macMeth.setParam, ctx->macCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return Pbkdf2GetMdSize(ctx, mdAttr);
}
#endif

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
        GOTO_ERR_IF(CRYPT_CTRL_SetData(temp->value, temp->valueLen, &ctx->password, &ctx->passLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_SALT)) != NULL) {
        GOTO_ERR_IF(CRYPT_CTRL_SetData(temp->value, temp->valueLen, &ctx->salt, &ctx->saltLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_ITER)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_ITER,
            BSL_PARAM_TYPE_UINT32, &val, &len), ret);
        GOTO_ERR_IF(CRYPT_PBKDF2_SetCnt(ctx, val), ret);
    }
#ifdef HITLS_CRYPTO_PROVIDER
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_MD_ATTR)) != NULL) {
        GOTO_ERR_IF(CRYPT_PBKDF2_SetMdAttr(ctx, temp->value, temp->valueLen), ret);
    }
#endif
ERR:
    return ret;
}

static inline bool IsMacMethodValid(EAL_MacMethod *method)
{
    return method->deinit != NULL && method->freeCtx != NULL && method->init != NULL &&
        method->reinit != NULL && method->update != NULL && method->final != NULL;
}

int32_t CRYPT_PBKDF2_Derive(CRYPT_PBKDF2_Ctx *ctx, uint8_t *out, uint32_t len)
{
    if (ctx == NULL || out == NULL || ctx->macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (IsMacMethodValid(&ctx->macMeth) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_ERR_MAC_METH);
        return CRYPT_PBKDF2_ERR_MAC_METH;
    }
    if (ctx->password == NULL && ctx->passLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = Pbkdf2GetMdSize(ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // check mdSize validity: mdSize must be non-zero for PBKDF2 to work correctly
    // PBKDF2 requires a fixed hash output size (hLen), and mdSize == 0 would cause
    // logic errors in key derivation
    // Note: dkLen limit check is not needed here since len is uint32_t (max 0xFFFFFFFF)
    // so max len/mdSize = 0x0FFFFFFF < 0xFFFFFFFF, satisfying RFC 2898
    if (ctx->mdSize == 0) {
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

    return CRYPT_PBKDF2_GenDk(ctx, out, len);
}

int32_t CRYPT_PBKDF2_Deinit(CRYPT_PBKDF2_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->macMeth.freeCtx != NULL) {
        ctx->macMeth.freeCtx(ctx->macCtx);
        ctx->macCtx = NULL;
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
    if (ctx->macMeth.freeCtx != NULL) {
        ctx->macMeth.freeCtx(ctx->macCtx);
    }
    BSL_SAL_ClearFree((void *)ctx->password, ctx->passLen);
    BSL_SAL_FREE(ctx->salt);
    BSL_SAL_Free(ctx);
}

#endif // HITLS_CRYPTO_PBKDF2
