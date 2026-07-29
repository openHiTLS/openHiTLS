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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_msg.h"
#include "transcript_hash.h"

static VERIFY_TranscriptStyle GetCacheTranscriptStyle(const HsMsgCache *cache, uint16_t version)
{
    if (cache->type == HS_MSG_CACHE_DTLS_RAW && version == HITLS_VERSION_DTLS13) {
        return VERIFY_TRANSCRIPT_DTLS13;
    }
    return VERIFY_TRANSCRIPT_RAW;
}

int32_t VERIFY_UpdateTranscriptHash(HITLS_HASH_Ctx *hashCtx, const uint8_t *msg, uint32_t msgLen,
    VERIFY_TranscriptStyle style)
{
    if (hashCtx == NULL || msg == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (style == VERIFY_TRANSCRIPT_RAW) {
        return SAL_CRYPT_DigestUpdate(hashCtx, msg, msgLen);
    }
    if (msgLen < DTLS_HS_MSG_HEADER_SIZE) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret = SAL_CRYPT_DigestUpdate(hashCtx, msg, HS_MSG_HEADER_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return SAL_CRYPT_DigestUpdate(hashCtx, &msg[DTLS_HS_MSG_HEADER_SIZE], msgLen - DTLS_HS_MSG_HEADER_SIZE);
}

static uint32_t GetCacheBlockCount(const HsMsgCache *cache)
{
    uint32_t count = 0;
    while (cache != NULL && cache->dataSize > 0u) {
        count++;
        cache = cache->next;
    }
    return count;
}

int32_t VERIFY_UpdateCachedTranscriptHash(HITLS_HASH_Ctx *hashCtx, const HsMsgCache *cache, uint16_t version,
    uint32_t skipLastCount)
{
    uint32_t count = GetCacheBlockCount(cache);
    if (skipLastCount > count) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    count -= skipLastCount;

    for (uint32_t i = 0; i < count; i++) {
        int32_t ret = VERIFY_UpdateTranscriptHash(hashCtx, cache->data, cache->dataSize,
            GetCacheTranscriptStyle(cache, version));
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        cache = cache->next;
    }
    return HITLS_SUCCESS;
}

int32_t VERIFY_SetHashWithVersion(HITLS_Lib_Ctx *libCtx, const char *attrName, VerifyCtx *ctx,
    HITLS_HashAlgo hashAlgo, uint16_t version)
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

    ret = VERIFY_UpdateCachedTranscriptHash(ctx->hashCtx, ctx->dataBuf, version, 0);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15717, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Verify set hash error: digest update fail.", 0, 0, 0, 0);
        SAL_CRYPT_DigestFree(ctx->hashCtx);
        ctx->hashCtx = NULL;
        return ret;
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

static int32_t CacheMsgData(HsMsgCache *dataBuf, const uint8_t *data, uint32_t len, HsMsgCacheType type)
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
    lastCache->type = type;

    return HITLS_SUCCESS;
}

static int32_t VerifyAppend(VerifyCtx *ctx, const uint8_t *data, uint32_t len, HsMsgCacheType type,
    VERIFY_TranscriptStyle liveStyle)
{
    int32_t ret;
    if (ctx->hashCtx != NULL) {
        ret = VERIFY_UpdateTranscriptHash(ctx->hashCtx, data, len, liveStyle);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15720, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Verify append error: digest update fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    if (ctx->dataBuf != NULL) {
        return CacheMsgData(ctx->dataBuf, data, len, type);
    }
    return HITLS_SUCCESS;
}

int32_t VERIFY_Append(VerifyCtx *ctx, const uint8_t *data, uint32_t len)
{
    return VerifyAppend(ctx, data, len, HS_MSG_CACHE_CANONICAL, VERIFY_TRANSCRIPT_RAW);
}

int32_t VERIFY_AppendDtlsRaw(VerifyCtx *ctx, const uint8_t *data, uint32_t len, VERIFY_TranscriptStyle liveStyle)
{
    return VerifyAppend(ctx, data, len, HS_MSG_CACHE_DTLS_RAW, liveStyle);
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
