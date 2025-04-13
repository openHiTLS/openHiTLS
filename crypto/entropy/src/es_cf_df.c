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

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "es_cf.h"

/*
 * see FIPS 140-3 section Full Entropy
 * To receive full entropy from the output of a conditioning component, the following criteria must be met:
 *   The conditioning component shall be vetted,
 *   ℎin shall be greater than or equal to 𝑛𝑛out + 64 bits,
 *   𝑛𝑛out shall be less than or equal to the security strength of the cryptographic function used as the 
 *    conditioning component.
 */
#define CF_FE_EXLEN 64
#define CF_BYTE_TO_BIT 8

typedef struct {
    void *ctx; // Hash algorithm handle
    EAL_MdMethod meth; // Hash algorithm operation function
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
    (void)memcpy_s(&ctx->meth, sizeof(EAL_MdMethod), meth, sizeof(EAL_MdMethod));
    ctx->ctx = meth->newCtx();
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
    uint8_t tmp[1] = { 0x01};
    int32_t ret = cfCtx->meth.update(cfCtx->ctx, tmp, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t values[4] = {0}; // 4 is sizeof(uint32_t)
    DfI32ToByte(values, cfCtx->meth.mdSize);
    ret = cfCtx->meth.update(cfCtx->ctx, values, sizeof(values));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
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
        BSL_SAL_Free(buf);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    ctx->meth.deinit(ctx->ctx);
    ret = ctx->meth.init(ctx->ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(buf);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
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