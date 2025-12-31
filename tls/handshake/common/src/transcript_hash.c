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

#include <string.h>
#include "hitls_build.h"
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "transcript_hash.h"

int32_t VERIFY_SetHash(HITLS_Lib_Ctx *libCtx, const char *attrName, VerifyCtx *ctx, HITLS_HashAlgo hashAlgo)
{
    int32_t ret;
    /* the value must be the same as the PRF function, use the digest algorithm with SHA-256 or higher strength */
    HITLS_HashAlgo prfAlgo = (hashAlgo == HITLS_HASH_SHA1) ? HITLS_HASH_SHA_256 : hashAlgo;

    SAL_CRYPT_DigestFree(ctx->hashCtx);
    ctx->hashCtx = SAL_CRYPT_DigestInit(libCtx, attrName, prfAlgo);
    if (ctx->hashCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15716, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Verify set hash error: digest init fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }

    HsMsgCache *dataBuf = ctx->dataBuf;
    while ((dataBuf != NULL) && (dataBuf->dataSize > 0u)) {
        ret = SAL_CRYPT_DigestUpdate(ctx->hashCtx, dataBuf->data, dataBuf->dataSize);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15717, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Verify set hash error: digest update fail.", 0, 0, 0, 0);
            SAL_CRYPT_DigestFree(ctx->hashCtx);
            ctx->hashCtx = NULL;
            return ret;
        }
        dataBuf = dataBuf->next;
    }
    ctx->hashAlgo = prfAlgo;
    return HITLS_SUCCESS;
}

static HsMsgCache *GetLastCache(HsMsgCache *dataBuf)
{
    HsMsgCache *cacheBuf = dataBuf;
    while (cacheBuf->next != NULL) {
        cacheBuf = cacheBuf->next;
    }
    return cacheBuf;
}

static int32_t CacheMsgData(HsMsgCache *dataBuf, const uint8_t *data, uint32_t len)
{
    HsMsgCache *lastCache = GetLastCache(dataBuf);

    lastCache->next = BSL_SAL_Calloc(1u, sizeof(HsMsgCache));
    if (lastCache->next == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15718, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc HsMsgCache fail when append msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_SAL_FREE(lastCache->data);
    lastCache->data = BSL_SAL_Dump(data, len);
    if (lastCache->data == NULL) {
        BSL_SAL_FREE(lastCache->next);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15719, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc HsMsgCache data fail when append msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    lastCache->dataSize = len;

    return HITLS_SUCCESS;
}

int32_t VERIFY_Append(VerifyCtx *ctx, const uint8_t *data, uint32_t len)
{
    int32_t ret;
    if (ctx->hashCtx != NULL) {
        ret = SAL_CRYPT_DigestUpdate(ctx->hashCtx, data, len);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15720, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Verify append error: digest update fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    if (ctx->dataBuf != NULL) {
        return CacheMsgData(ctx->dataBuf, data, len);
    }
    return HITLS_SUCCESS;
}

int32_t VERIFY_CalcSessionHash(VerifyCtx *ctx, uint8_t *digest, uint32_t *digestLen)
{
    int32_t ret;

    HITLS_HASH_Ctx *tmpHashCtx = SAL_CRYPT_DigestCopy(ctx->hashCtx);
    if (tmpHashCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_DIGEST);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15721, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Verify data calculate error: digest copy fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }

    /* get the hash result */
    ret = SAL_CRYPT_DigestFinal(tmpHashCtx, digest, digestLen);
    SAL_CRYPT_DigestFree(tmpHashCtx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15722, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Verify data calculate error: digest final fail.", 0, 0, 0, 0);
    }

    return ret;
}

void VERIFY_FreeMsgCache(VerifyCtx *ctx)
{
    HsMsgCache *nextBuf = NULL;
    HsMsgCache *dataBuf = ctx->dataBuf;
    while (dataBuf != NULL) {
        nextBuf = dataBuf->next;
        BSL_SAL_FREE(dataBuf->data);
        BSL_SAL_FREE(dataBuf);
        dataBuf = nextBuf;
    }
    ctx->dataBuf = NULL;
}
