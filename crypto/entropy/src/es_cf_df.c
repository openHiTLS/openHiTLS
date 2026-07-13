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
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "es_cf.h"

/* Extra assessed input entropy required for a full-entropy output claim. */
#define CF_FE_EXLEN 64
#define CF_BYTE_TO_BIT 8

/* AIS 20/31 NTG.1.4: each credited source must deliver at least this much
   entropy during startup. The per-source startup quota is exactly this
   conditioner's need, so a digest too narrow to reach the floor is refused
   at selection instead of silently lowering the quota. */
#define CF_NTG1_STARTUP_SOURCE_BITS 240

typedef struct {
    void *ctx; // Hash algorithm handle
    EAL_MdMethod meth; // Hash algorithm operation function
    bool prefixPending;
} ES_CfDfCtx;

static void ES_CfDfDeinit(void *ctx)
{
    ES_CfDfCtx *cfCtx = (ES_CfDfCtx *)ctx;
    if (cfCtx == NULL) {
        return;
    }
    if (cfCtx->ctx != NULL) {
        cfCtx->meth.freeCtx(cfCtx->ctx);
    }
    BSL_SAL_Free(cfCtx);
    return;
}

static void *ES_CfDfInit(void *mdMeth)
{
    ES_CfDfCtx *ctx = BSL_SAL_Malloc(sizeof(ES_CfDfCtx));
    EAL_MdMethod *meth = (EAL_MdMethod *)mdMeth;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    memcpy(&ctx->meth, meth, sizeof(EAL_MdMethod));
    ctx->ctx = meth->newCtx(NULL, meth->id);
    if (ctx->ctx == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    int32_t ret = meth->init(ctx->ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        ES_CfDfDeinit(ctx);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    ctx->prefixPending = true;
    return ctx;
}

static void DfI32ToByte(uint8_t values[4], uint32_t len)
{
    values[0] = (uint8_t)(((len << 3) >> 24) & 0xff); /* leftward by 3, rightwards by 24 */
    values[1] = (uint8_t)(((len << 3) >> 16) & 0xff); /* leftward by 3, rightwards by 16 */
    values[2] = (uint8_t)(((len << 3) >> 8) & 0xff); /* leftward by 3, rightwards by 8 */
    values[3] = (uint8_t)((len << 3) & 0xff); /* leftward by 3 */
    return;
}

static int32_t ES_CfDfUpdateData(void *ctx, uint8_t *data, uint32_t dataLen)
{
    ES_CfDfCtx *cfCtx = (ES_CfDfCtx *)ctx;
    int32_t ret;
    if (cfCtx->prefixPending) {
        uint8_t prefix[5] = {0x01};
        DfI32ToByte(prefix + 1, cfCtx->meth.mdSize);
        ret = cfCtx->meth.update(cfCtx->ctx, prefix, sizeof(prefix));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        cfCtx->prefixPending = false;
    }
    ret = cfCtx->meth.update(cfCtx->ctx, data, dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static uint8_t *ES_CfDfGetEntropyData(void *cfCtx, uint32_t *len)
{
    ES_CfDfCtx *ctx = (ES_CfDfCtx *)cfCtx;
    uint32_t bufLen = ctx->meth.mdSize;
    uint8_t *buf = BSL_SAL_Malloc(bufLen);
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    int32_t ret = ctx->meth.final(ctx->ctx, buf, &bufLen);
    if (ret != CRYPT_SUCCESS) {
        /* A failing final may still have written digest bytes. */
        BSL_SAL_ClearFree(buf, ctx->meth.mdSize);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    ctx->meth.deinit(ctx->ctx);
    ret = ctx->meth.init(ctx->ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        /* buf already holds a live conditioner output block here. */
        BSL_SAL_ClearFree(buf, bufLen);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    ctx->prefixPending = true;
    *len = bufLen;
    return buf;
}

static uint32_t ES_CfDfGetCfOutLen(void *cfCtx)
{
    ES_CfDfCtx *ctx = (ES_CfDfCtx *)cfCtx;
    return ctx->meth.mdSize;
}

static uint32_t ES_CfDfGetNeedEntropy(void *cfCtx)
{
    ES_CfDfCtx *ctx = (ES_CfDfCtx *)cfCtx;
    return ctx->meth.mdSize * CF_BYTE_TO_BIT + CF_FE_EXLEN;
}

ES_CfMethod *ES_CFGetDfMethod(EAL_MdMethod *mdMeth)
{
    if (mdMeth == NULL ||
        mdMeth->mdSize * CF_BYTE_TO_BIT + CF_FE_EXLEN < CF_NTG1_STARTUP_SOURCE_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ECF_ALG_ERROR);
        return NULL;
    }
    ES_CfMethod *meth = BSL_SAL_Malloc(sizeof(ES_CfMethod));
    if (meth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    meth->ctx = NULL;
    meth->meth.mdMeth = *mdMeth;
    meth->init = ES_CfDfInit;
    meth->update = ES_CfDfUpdateData;
    meth->deinit = ES_CfDfDeinit;
    meth->getCfOutLen = ES_CfDfGetCfOutLen;
    meth->getEntropyData = ES_CfDfGetEntropyData;
    meth->getNeedEntropy = ES_CfDfGetNeedEntropy;
    return meth;
}
#endif
