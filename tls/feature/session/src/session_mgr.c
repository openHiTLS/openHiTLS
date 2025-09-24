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
#ifdef HITLS_TLS_FEATURE_SESSION
#include <stdbool.h>
#include "securec.h"
#include "bsl_sal.h"
#include "sal_time.h"
#include "bsl_hash.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "tls_config.h"
#include "session.h"
#include "bsl_errno.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "crypt.h"
#include "tls.h"
#include "session_type.h"
#include "session_mgr.h"

#define SESSION_DEFAULT_TIMEOUT 7200u
#ifdef HITLS_TLS_FEATURE_SESSION
#define SESSION_DEFAULT_CACHE_SIZE 256u
#endif
#define SESSION_GERNERATE_RETRY_MAX_TIMES 10

#define SESSION_DEFAULT_HASH_BKT_SZIE 64u

typedef struct {
    uint32_t sessionIdSize;
    uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE];
} SessionKey;

/* For details about the SessKey hash function, see BSL_CstlHashCodeCalcStr */
static uint32_t SessKeyHashCodeCal(uintptr_t key, uint32_t bktSize)
{
    if (bktSize == 0) {
        return 0;
    }

    SessionKey *tmpKey = (SessionKey *)key;
    uint32_t hashCode =  BSL_HASH_CodeCalc(tmpKey, sizeof(SessionKey));
    return hashCode % bktSize;
}

static bool SessKeyHashMacth(uintptr_t key1, uintptr_t key2)
{
    SessionKey *tkey1 = (SessionKey *)key1;
    SessionKey *tkey2 = (SessionKey *)key2;

    if (memcmp(tkey1, tkey2, sizeof(SessionKey)) == 0) {
        return true;
    }

    return false;
}

/* Session key copy function, which returns the address for storing character strings */
static void *SessKeyDupFunc(void *src, size_t size)
{
    if (src == NULL || size == 0) {
        return NULL;
    }

    SessionKey *dupKey = (SessionKey *)BSL_SAL_Dump(src, (uint32_t)size);

    return (void *)dupKey;
}

static void SessKeyFreeFunc(void *ptr)
{
    BSL_SAL_FREE(ptr);
    return;
}

/* Session copy function */
static void *SessionDupFunc(void *src, size_t size)
{
    (void)size;
    return (void *)HITLS_SESS_Dup((HITLS_Session *)src);
}

static void SessionFreeFunc(void *ptr)
{
    HITLS_SESS_Free((HITLS_Session *)ptr);
    return;
}

TLS_SessionMgr *SESSMGR_New(HITLS_Lib_Ctx *libCtx)
{
    TLS_SessionMgr *mgr = (TLS_SessionMgr *)BSL_SAL_Calloc(1u, sizeof(TLS_SessionMgr));
    if (mgr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16702, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return NULL;
    }

    if (BSL_SAL_ThreadLockNew(&mgr->lock) != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16703, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ThreadLockNew fail", 0, 0, 0, 0);
        BSL_SAL_FREE(mgr);
        return NULL;
    }

    /* Prepare the default ticket key */
    if (SAL_CRYPT_Rand(libCtx, mgr->ticketKeyName, sizeof(mgr->ticketKeyName)) != HITLS_SUCCESS ||
        SAL_CRYPT_Rand(libCtx, mgr->ticketAesKey, sizeof(mgr->ticketAesKey)) != HITLS_SUCCESS ||
        SAL_CRYPT_Rand(libCtx, mgr->ticketHmacKey, sizeof(mgr->ticketHmacKey)) != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16704, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Rand fail", 0, 0, 0, 0);
        BSL_SAL_ThreadLockFree(mgr->lock);
        BSL_SAL_FREE(mgr);
        return NULL;
    }

    // Apply for a hash table from mgr->hash
    ListDupFreeFuncPair keyFunc = {.dupFunc = SessKeyDupFunc, .freeFunc = SessKeyFreeFunc};
    ListDupFreeFuncPair valueFunc = {.dupFunc = SessionDupFunc, .freeFunc = SessionFreeFunc};
    mgr->hash = BSL_HASH_Create(SESSION_DEFAULT_HASH_BKT_SZIE,
        SessKeyHashCodeCal, SessKeyHashMacth, &keyFunc, &valueFunc);
    if (mgr->hash == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16705, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HASH_Create fail", 0, 0, 0, 0);
        BSL_SAL_ThreadLockFree(mgr->lock);
        BSL_SAL_FREE(mgr);
        return NULL;
    }

#ifdef HITLS_TLS_FEATURE_SESSION
    mgr->sessCacheMode = HITLS_SESS_CACHE_SERVER;
    mgr->sessCacheSize = SESSION_DEFAULT_CACHE_SIZE;
#endif
    mgr->sessTimeout = SESSION_DEFAULT_TIMEOUT;
    mgr->references = 1;
    return mgr;
}

/* Copy the number of references. The number of references increases by 1 */
TLS_SessionMgr *SESSMGR_Dup(TLS_SessionMgr *mgr)
{
    if (mgr == NULL) {
        return NULL;
    }

    BSL_SAL_ThreadWriteLock(mgr->lock);
    mgr->references++;
    BSL_SAL_ThreadUnlock(mgr->lock);

    return mgr;
}

void SESSMGR_Free(TLS_SessionMgr *mgr)
{
    if (mgr != NULL) {
        BSL_SAL_ThreadWriteLock(mgr->lock);
        mgr->references--;
        if (mgr->references > 0) {
            BSL_SAL_ThreadUnlock(mgr->lock);
            return;
        }
        BSL_SAL_ThreadUnlock(mgr->lock);

        // Delete all sessions
        BSL_HASH_Destory(mgr->hash);
        mgr->hash = NULL;

        BSL_SAL_ThreadLockFree(mgr->lock);
        BSL_SAL_FREE(mgr);
    }
    return;
}

void SESSMGR_SetTimeout(TLS_SessionMgr *mgr, uint64_t sessTimeout)
{
    if (mgr != NULL) {
        BSL_SAL_ThreadWriteLock(mgr->lock);
        mgr->sessTimeout = sessTimeout;
        BSL_SAL_ThreadUnlock(mgr->lock);
    }
    return;
}

uint64_t SESSMGR_GetTimeout(TLS_SessionMgr *mgr)
{
    if (mgr == NULL) {
        return SESSION_DEFAULT_TIMEOUT;
    }
    uint64_t sessTimeout;
    BSL_SAL_ThreadReadLock(mgr->lock);
    sessTimeout = mgr->sessTimeout;
    BSL_SAL_ThreadUnlock(mgr->lock);

    return sessTimeout;
}

#ifdef HITLS_TLS_FEATURE_SESSION
void SESSMGR_SetCacheMode(TLS_SessionMgr *mgr, uint32_t mode)
{
    if (mgr != NULL) {
        BSL_SAL_ThreadWriteLock(mgr->lock);
        mgr->sessCacheMode = mode;
        BSL_SAL_ThreadUnlock(mgr->lock);
    }
    return;
}

uint32_t SESSMGR_GetCacheMode(TLS_SessionMgr *mgr)
{
    uint32_t mode = HITLS_SESS_CACHE_NO;
    if (mgr == NULL) {
        return mode;
    }
    BSL_SAL_ThreadReadLock(mgr->lock);
    mode = mgr->sessCacheMode;
    BSL_SAL_ThreadUnlock(mgr->lock);

    return mode;
}

/* Set the maximum number of cache sessions */
void SESSMGR_SetCacheSize(TLS_SessionMgr *mgr, uint32_t sessCacheSize)
{
    if (mgr != NULL) {
        BSL_SAL_ThreadWriteLock(mgr->lock);
        mgr->sessCacheSize = sessCacheSize;
        BSL_SAL_ThreadUnlock(mgr->lock);
    }
    return;
}

/* Obtain the maximum number of cached sessions. Ensure that the pointer is not NULL */
uint32_t SESSMGR_GetCacheSize(TLS_SessionMgr *mgr)
{
    uint32_t sessCacheSize = 0u;
    BSL_SAL_ThreadReadLock(mgr->lock);
    sessCacheSize = mgr->sessCacheSize;
    BSL_SAL_ThreadUnlock(mgr->lock);

    return sessCacheSize;
}
#endif

void SESSMGR_InsertSession(TLS_SessionMgr *mgr, HITLS_Session *sess, bool isStore)
{
    if (mgr == NULL || sess == NULL || !isStore) {
        return;
    }

    BSL_SAL_ThreadReadLock(mgr->lock);
    HITLS_SESS_CACHE_MODE mode = mgr->sessCacheMode;
    BSL_SAL_ThreadUnlock(mgr->lock);

    SessionKey key = {0};
    key.sessionIdSize = sizeof(key.sessionId);
    if (HITLS_SESS_GetSessionId(sess, key.sessionId, &(key.sessionIdSize)) != HITLS_SUCCESS) {
        return;
    }

    if (key.sessionIdSize == 0) {
        return;
    }

    BSL_SAL_ThreadWriteLock(mgr->lock);

    if (BSL_HASH_Size(mgr->hash) < mgr->sessCacheSize) {
        HITLS_Session *tmpSess = NULL;
        if (BSL_HASH_At(mgr->hash, (uintptr_t)&key, (uintptr_t *)&tmpSess) == BSL_SUCCESS) {
            BSL_HASH_Erase(mgr->hash, (uintptr_t)&key);
        }
        /* Insert a session node */
        BSL_HASH_Insert(mgr->hash, (uintptr_t)&key, sizeof(key), (uintptr_t)sess, 0);
    } else {
        BSL_LOG_BINLOG_FIXLEN(
            BINLOG_ID15305, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN, "over sess cache size", 0, 0, 0, 0);
    }
    BSL_SAL_ThreadUnlock(mgr->lock);
    if (mode & HITLS_SESS_ENABLE_TIME_UPDATE) {
        uint64_t curTime = (uint64_t)BSL_SAL_CurrentSysTimeGet();
        SESS_SetStartTime(sess, curTime);
    }
    return;
}

#ifdef HITLS_TLS_FEATURE_SESSION_ID
/* Find the matching session */
HITLS_Session *SESSMGR_Find(TLS_Ctx *ctx, uint8_t *sessionId, uint8_t sessionIdSize)
{
    if (ctx == NULL || ctx->globalConfig == NULL || ctx->globalConfig->sessMgr == NULL || sessionId == NULL ||
        sessionIdSize == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16706, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        return NULL;
    }
    HITLS_Session *sess = NULL;
    if ((SESSMGR_GetCacheMode(ctx->globalConfig->sessMgr) & HITLS_SESS_DISABLE_INTERNAL_LOOKUP) == 0) {
        SessionKey key = {0};
        key.sessionIdSize = sessionIdSize;
        if (memcpy_s(key.sessionId, sizeof(key.sessionId), sessionId, sessionIdSize) == EOK) {
            // Query the session corresponding to the key
            BSL_SAL_ThreadReadLock(ctx->globalConfig->sessMgr->lock);
            if (BSL_HASH_At(ctx->globalConfig->sessMgr->hash, (uintptr_t)&key, (uintptr_t *)&sess) != BSL_SUCCESS) {
                BSL_LOG_BINLOG_FIXLEN(
                    BINLOG_ID15353, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN, "not find sess", 0, 0, 0, 0);
                    sess = NULL;
            }
            BSL_SAL_ThreadUnlock(ctx->globalConfig->sessMgr->lock);
        }

        uint64_t curTime = (uint64_t)BSL_SAL_CurrentSysTimeGet();
        /* Check whether the validity is valid */
        if (SESS_CheckValidity(sess, curTime) == false) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16707, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN, "sess time out", 0, 0, 0,
                                  0);
            sess = NULL;
        }
    }
#ifdef HITLS_TLS_FEATURE_SESSION_CACHE_CB
    if (sess == NULL && ctx->globalConfig->sessionGetCb != NULL) {
        int32_t copy = 1;
        sess = ctx->globalConfig->sessionGetCb(ctx, sessionId, sessionIdSize, &copy);
        if (sess != NULL) {
            if (!HITLS_SESS_IsResumable(sess)) {
                HITLS_SESS_Free(sess);
                sess = NULL;
                goto EXIT;
            }
            if (copy != 0) {
                sess = HITLS_SESS_Dup(sess);
            }
            if ((SESSMGR_GetCacheMode(ctx->globalConfig->sessMgr) & HITLS_SESS_DISABLE_INTERNAL_STORE) == 0) {
                // Store the session in the internal cache, unlock the lock first,
                // and then lock it again in SESSMGR_InsertSession
                SESSMGR_InsertSession(ctx->globalConfig->sessMgr, sess, true);
            }
        }
    }
#endif /* HITLS_TLS_FEATURE_SESSION_CACHE_CB */
EXIT:
    return sess;
}

#endif /* HITLS_TLS_FEATURE_SESSION_ID */
/* Search for the matched session without checking the validity of the session */
bool SESSMGR_HasMacthSessionId(TLS_SessionMgr *mgr, uint8_t *sessionId, uint8_t sessionIdSize)
{
    if (mgr == NULL || sessionId == NULL || sessionIdSize == 0) {
        return false;
    }
    HITLS_Session *sess = NULL;

    BSL_SAL_ThreadReadLock(mgr->lock);
    SessionKey key = {0};
    key.sessionIdSize = sessionIdSize;
    if (memcpy_s(key.sessionId, sizeof(key.sessionId), sessionId, sessionIdSize) == EOK) {
        // Query the session corresponding to the key
        BSL_HASH_At(mgr->hash, (uintptr_t)&key, (uintptr_t *)&sess);
    }

    BSL_SAL_ThreadUnlock(mgr->lock);
    return (sess == NULL) ? false : true;
}

/* Clear timeout sessions */
void SESSMGR_ClearTimeout(HITLS_Config *config, uint64_t time)
{
    if (config == NULL || config->sessMgr == NULL) {
        return;
    }
    BSL_SAL_ThreadWriteLock(config->sessMgr->lock);
    BSL_HASH_Iterator it = BSL_HASH_IterBegin(config->sessMgr->hash);
    while (it != BSL_HASH_IterEnd(config->sessMgr->hash)) {
        uintptr_t ptr = BSL_HASH_IterValue(config->sessMgr->hash, it);
        HITLS_Session *sess = (HITLS_Session *)ptr;
        if (time == 0 ||SESS_CheckValidity(sess, time) == false) {
            SESS_Disable(sess);
            /* Delete the node if it is invalid */
            uintptr_t tmpKey = BSL_HASH_HashIterKey(config->sessMgr->hash, it);
            // Returns the next iterator of the iterator where the key resides
            it = BSL_HASH_Erase(config->sessMgr->hash, tmpKey);
#ifdef HITLS_TLS_FEATURE_SESSION_CACHE_CB
            if (config->sessionRemoveCb != NULL) {
                config->sessionRemoveCb(config, sess);
            }
#endif /* HITLS_TLS_FEATURE_SESSION_CACHE_CB */
        } else {
            it = BSL_HASH_IterNext(config->sessMgr->hash, it);
        }
    }

    BSL_SAL_ThreadUnlock(config->sessMgr->lock);
}

int32_t SESSMGR_RemoveSession(HITLS_Config *config, HITLS_Session *sess)
{
    if (config == NULL || sess == NULL) {
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(config->sessMgr->lock);
    SessionKey key = {0};
    key.sessionIdSize = sizeof(key.sessionId);
    if (HITLS_SESS_GetSessionId(sess, key.sessionId, &(key.sessionIdSize)) != HITLS_SUCCESS) {
        BSL_SAL_ThreadUnlock(config->sessMgr->lock);
        return HITLS_SESS_ERR_NOT_FOUND;
    }
    if (BSL_HASH_At(config->sessMgr->hash, (uintptr_t)&key, (uintptr_t *)&sess) != BSL_SUCCESS) {
        BSL_SAL_ThreadUnlock(config->sessMgr->lock);
        return HITLS_SESS_ERR_NOT_FOUND;
    }

    BSL_HASH_Erase(config->sessMgr->hash, (uintptr_t)&key);
#ifdef HITLS_TLS_FEATURE_SESSION_CACHE_CB
    if (config->sessionRemoveCb != NULL) {
        config->sessionRemoveCb(config, sess);
    }
#endif /* HITLS_TLS_FEATURE_SESSION_CACHE_CB */
    BSL_SAL_ThreadUnlock(config->sessMgr->lock);
    return HITLS_SUCCESS;
}

int32_t SESSMGR_GernerateSessionId(TLS_Ctx *ctx, uint8_t *sessionId, uint32_t sessionIdSize)
{
    int32_t ret = 0;
    int32_t retry = 0;

    do {
        ret = SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), sessionId, sessionIdSize);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        /* If duplicate session IDs already exist, generate new session ID */
        if (SESSMGR_HasMacthSessionId(ctx->globalConfig->sessMgr, sessionId, (uint8_t)sessionIdSize) == false) {
            return HITLS_SUCCESS;
        }

        retry++;
    } while (retry < SESSION_GERNERATE_RETRY_MAX_TIMES); // Maximum number of attempts is 10

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15961, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Gernerate server session id error.", 0, 0, 0, 0);
    BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_SESSION_ID_GENRATE);
    return HITLS_SESS_ERR_SESSION_ID_GENRATE;
}

#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
void SESSMGR_SetTicketKeyCb(TLS_SessionMgr *mgr, HITLS_TicketKeyCb ticketKeyCb)
{
    if (mgr != NULL) {
        BSL_SAL_ThreadWriteLock(mgr->lock);
        mgr->ticketKeyCb = ticketKeyCb;
        BSL_SAL_ThreadUnlock(mgr->lock);
    }
    return;
}

HITLS_TicketKeyCb SESSMGR_GetTicketKeyCb(TLS_SessionMgr *mgr)
{
    if (mgr == NULL) {
        return NULL;
    }
    HITLS_TicketKeyCb ticketKeyCb;
    BSL_SAL_ThreadReadLock(mgr->lock);
    ticketKeyCb = mgr->ticketKeyCb;
    BSL_SAL_ThreadUnlock(mgr->lock);

    return ticketKeyCb;
}

int32_t SESSMGR_GetTicketKey(const TLS_SessionMgr *mgr, uint8_t *key, uint32_t keySize, uint32_t *outSize)
{
    if (mgr == NULL || key == NULL || outSize == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16708, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(mgr->lock);

    uint32_t offset = 0;
    if (memcpy_s(key, keySize, mgr->ticketKeyName, HITLS_TICKET_KEY_NAME_SIZE) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16709, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_SAL_ThreadUnlock(mgr->lock);
        return HITLS_MEMCPY_FAIL;
    }
    offset += HITLS_TICKET_KEY_NAME_SIZE;

    if (memcpy_s(&key[offset], keySize - offset, mgr->ticketAesKey, HITLS_TICKET_KEY_SIZE) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16710, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_SAL_ThreadUnlock(mgr->lock);
        return HITLS_MEMCPY_FAIL;
    }
    offset += HITLS_TICKET_KEY_SIZE;

    if (memcpy_s(&key[offset], keySize - offset, mgr->ticketHmacKey, HITLS_TICKET_KEY_SIZE) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16711, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_SAL_ThreadUnlock(mgr->lock);
        return HITLS_MEMCPY_FAIL;
    }
    offset += HITLS_TICKET_KEY_SIZE;

    *outSize = offset;

    BSL_SAL_ThreadUnlock(mgr->lock);

    return HITLS_SUCCESS;
}

int32_t SESSMGR_SetTicketKey(TLS_SessionMgr *mgr, const uint8_t *key, uint32_t keySize)
{
    if (mgr == NULL || key == NULL ||
        (keySize != HITLS_TICKET_KEY_NAME_SIZE + HITLS_TICKET_KEY_SIZE + HITLS_TICKET_KEY_SIZE)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16712, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(mgr->lock);

    uint32_t offset = 0;
    (void)memcpy_s(mgr->ticketKeyName, HITLS_TICKET_KEY_NAME_SIZE, key, HITLS_TICKET_KEY_NAME_SIZE);
    offset += HITLS_TICKET_KEY_NAME_SIZE;

    (void)memcpy_s(mgr->ticketAesKey, HITLS_TICKET_KEY_SIZE, &key[offset], HITLS_TICKET_KEY_SIZE);
    offset += HITLS_TICKET_KEY_SIZE;

    (void)memcpy_s(mgr->ticketHmacKey, HITLS_TICKET_KEY_SIZE, &key[offset], HITLS_TICKET_KEY_SIZE);

    BSL_SAL_ThreadUnlock(mgr->lock);

    return HITLS_SUCCESS;
}
#endif /* #ifdef HITLS_TLS_FEATURE_SESSION_TICKET */
#endif /* HITLS_TLS_FEATURE_SESSION */