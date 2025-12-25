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
#include <time.h>
#include <stdarg.h>
#include "securec.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "bsl_list.h"
#include "bsl_err_internal.h"
#include "bsl_errno.h"
#include "tls_binlog_id.h"
#include "cert_method.h"
#include "cert.h"
#include "cert_mgr.h"
#include "session_type.h"
#include "session.h"
#include "cert_mgr_ctx.h"
#ifdef HITLS_TLS_FEATURE_SESSION
#define MAX_PRINTF_BUF 1024
#define CTIME_BUF 26
#endif
/**
 * Apply for a session
 */
HITLS_Session *HITLS_SESS_New(void)
{
    HITLS_Session *sess = (HITLS_Session *)BSL_SAL_Calloc(1u, sizeof(HITLS_Session));
    if (sess == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16714, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return NULL;
    }

    sess->certMgrCtx = SAL_CERT_MgrCtxNew();
    if (sess->certMgrCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16715, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "MgrCtxNew fail", 0, 0, 0, 0);
        BSL_SAL_FREE(sess);
        return NULL;
    }

    if (BSL_SAL_ThreadLockNew(&sess->lock) != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16716, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ThreadLockNew fail", 0, 0, 0, 0);
        SAL_CERT_MgrCtxFree(sess->certMgrCtx);
        BSL_SAL_FREE(sess);
        return NULL;
    }

    sess->startTime = (uint64_t)BSL_SAL_CurrentSysTimeGet();  // default value
    sess->references = 1;
    sess->enable = true;
    sess->cipherSuite = HITLS_AES_128_GCM_SHA256;
    return sess;
}

/**
 * To copy a session, increase the number of references by 1
 */
HITLS_Session *HITLS_SESS_Dup(HITLS_Session *sess)
{
    if (sess == NULL) {
        return NULL;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->references++;
    BSL_SAL_ThreadUnlock(sess->lock);

    return sess;
}

/**
 * Increase the number of references by 1
 */
void HITLS_SESS_UpRef(HITLS_Session *sess)
{
    if (sess == NULL) {
        return;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->references++;
    BSL_SAL_ThreadUnlock(sess->lock);

    return;
}

void HITLS_SESS_Free(HITLS_Session *sess)
{
    if (sess != NULL) {
        BSL_SAL_ThreadWriteLock(sess->lock);
        sess->references--;
        if (sess->references > 0) {
            BSL_SAL_ThreadUnlock(sess->lock);
            return;
        }
        BSL_SAL_ThreadUnlock(sess->lock);
        if (sess->peerCert != NULL) {
            SAL_CERT_PairFree(sess->certMgrCtx, sess->peerCert);
        }
        sess->peerCert = NULL;
        BSL_SAL_FREE(sess->ticket);
#ifdef HITLS_TLS_FEATURE_SNI
        BSL_SAL_FREE(sess->hostName);
#endif
        BSL_SAL_CleanseData(sess->masterKey, MAX_MASTER_KEY_SIZE);
        SAL_CERT_MgrCtxFree(sess->certMgrCtx);
        BSL_SAL_ThreadLockFree(sess->lock);
        BSL_SAL_FREE(sess);
    }
}

static HITLS_Session *DeepCopySess(HITLS_Session *src, HITLS_Session *dest)
{
    dest->certMgrCtx = SAL_CERT_MgrCtxProviderNew(LIBCTX_FROM_CERT_MGR_CTX(src->certMgrCtx),
        ATTRIBUTE_FROM_CERT_MGR_CTX(src->certMgrCtx));
    if (dest->certMgrCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16717, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "MgrCtxNew fail", 0, 0, 0, 0);
        return NULL;
    }

    if (src->peerCert != NULL) {
        dest->peerCert = SAL_CERT_PairDup(dest->certMgrCtx, src->peerCert);
        if (dest->peerCert == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16718, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "PairDup fail", 0, 0, 0, 0);
            return NULL;
        }
    }

#ifdef HITLS_TLS_FEATURE_SNI
    if (src->hostNameSize > 0) {
        if (SESS_SetHostName(dest, src->hostNameSize, src->hostName) != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16719, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "SetHostName fail", 0, 0, 0, 0);
            return NULL;
        }
    }
#endif

    if (src->ticketSize > 0) {
        if (SESS_SetTicket(dest, src->ticket, src->ticketSize) != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16722, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "SetTicket fail", 0, 0, 0, 0);
            return NULL;
        }
    }
    return dest;
}

HITLS_Session *SESS_Copy(HITLS_Session *src)
{
    HITLS_Session *dest = (HITLS_Session *)BSL_SAL_Dump(src, sizeof(HITLS_Session));
    if (dest == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16723, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "dump fail", 0, 0, 0, 0);
        return NULL;
    }

    if (BSL_SAL_ThreadLockNew(&dest->lock) != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16724, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ThreadLockNew fail", 0, 0, 0, 0);
        BSL_SAL_FREE(dest);
        return NULL;
    }

    dest->references = 1;
    dest->enable = true;

    dest->peerCert = NULL;
#ifdef HITLS_TLS_FEATURE_SNI
    dest->hostName = NULL;
#endif
    dest->ticket = NULL;

    if (DeepCopySess(src, dest) == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16725, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DeepCopySess fail", 0, 0, 0, 0);
        HITLS_SESS_Free(dest);
        return NULL;
    }

    return dest;
}

/* Just make a simple judgment */
bool HITLS_SESS_IsResumable(const HITLS_Session *sess)
{
    bool isResumable = 0;
    if (sess != NULL) {
        BSL_SAL_ThreadReadLock(sess->lock);
        isResumable = (sess->enable && (sess->sessionIdSize > 0 || sess->ticketSize > 0));
        BSL_SAL_ThreadUnlock(sess->lock);
    }
    return isResumable;
}
/**
 * Session is deprecated
 */
void SESS_Disable(HITLS_Session *sess)
{
    if (sess != NULL) {
        BSL_SAL_ThreadWriteLock(sess->lock);
        sess->enable = false;
        BSL_SAL_ThreadUnlock(sess->lock);
    }
    return;
}

int32_t HITLS_SESS_GetSessionId(const HITLS_Session *sess, uint8_t *sessionId, uint32_t *sessionIdSize)
{
    if (sess == NULL || sessionId == NULL || sessionIdSize == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16726, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    if (memcpy_s(sessionId, *sessionIdSize, sess->sessionId, sess->sessionIdSize) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16727, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    *sessionIdSize = sess->sessionIdSize;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_SESSION_ID
int32_t HITLS_SESS_SetSessionIdCtx(HITLS_Session *sess, uint8_t *sessionIdCtx, uint32_t sessionIdCtxSize)
{
    if (sess == NULL || sessionIdCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16728, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    if (sessionIdCtxSize != 0 &&
        memcpy_s(sess->sessionIdCtx, sizeof(sess->sessionIdCtx), sessionIdCtx, sessionIdCtxSize) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16729, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    /* The allowed value for sessionIdCtxSize is 0 */
    sess->sessionIdCtxSize = sessionIdCtxSize;

    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_GetSessionIdCtx(const HITLS_Session *sess, uint8_t *sessionIdCtx, uint32_t *sessionIdCtxSize)
{
    if (sess == NULL || sessionIdCtx == NULL || sessionIdCtxSize == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16730, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    if (memcpy_s(sessionIdCtx, *sessionIdCtxSize, sess->sessionIdCtx, sess->sessionIdCtxSize) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16731, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    *sessionIdCtxSize = sess->sessionIdCtxSize;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION_ID */

int32_t HITLS_SESS_SetSessionId(HITLS_Session *sess, uint8_t *sessionId, uint32_t sessionIdSize)
{
    if (sess == NULL || sessionId == NULL || sessionIdSize == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16732, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    if (memcpy_s(sess->sessionId, sizeof(sess->sessionId), sessionId, sessionIdSize) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16733, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    sess->sessionIdSize = sessionIdSize;

    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_SetHaveExtMasterSecret(HITLS_Session *sess, uint8_t haveExtMasterSecret)
{
    if (sess == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16734, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->haveExtMasterSecret = (haveExtMasterSecret > 0);
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_GetHaveExtMasterSecret(HITLS_Session *sess, bool *haveExtMasterSecret)
{
    if (sess == NULL || haveExtMasterSecret == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16735, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    *haveExtMasterSecret = sess->haveExtMasterSecret;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

#if defined(HITLS_TLS_FEATURE_SNI) && defined(HITLS_TLS_FEATURE_SESSION)
/* Set the server_name extension required for TLS1.2 session resumption */
int32_t SESS_SetHostName(HITLS_Session *sess, uint32_t hostNameSize, uint8_t *hostName)
{
    if (sess == NULL || hostName == NULL || hostNameSize == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16736, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    BSL_SAL_FREE(sess->hostName);
    sess->hostName = (uint8_t *)BSL_SAL_Dump(hostName, hostNameSize * sizeof(uint8_t));
    if (sess->hostName == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16737, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    sess->hostNameSize = hostNameSize;
    BSL_SAL_ThreadUnlock(sess->lock);

    return HITLS_SUCCESS;
}
/* Get the server_name extension required for TLS1.2 session resumption */
int32_t SESS_GetHostName(HITLS_Session *sess, uint32_t  *hostNameSize, uint8_t **hostName)
{
    if (sess == NULL || hostNameSize == NULL || hostName == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16738, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    *hostName = sess->hostName;
    *hostNameSize = sess->hostNameSize;
    BSL_SAL_ThreadUnlock(sess->lock);

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SNI */

int32_t HITLS_SESS_SetProtocolVersion(HITLS_Session *sess, uint16_t version)
{
    if (sess == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16739, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->version = version;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_GetProtocolVersion(const HITLS_Session *sess, uint16_t *version)
{
    if (sess == NULL || version == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16740, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    *version = sess->version;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
int32_t SESS_SetPeerCert(HITLS_Session *sess, CERT_Pair *peerCert, bool isClient)
{
    int32_t ret = HITLS_SUCCESS;
    if (sess == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16741, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "sess null", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->peerCert = peerCert;
    /* The peer_cert_chain of the client stores the device certificate of the server */
    if (isClient && peerCert != NULL) {
        /* Obtain the cert */
        HITLS_CERT_X509 *tmpCert = SAL_CERT_PairGetX509(peerCert);
        if (tmpCert == NULL) {
            /* If cert in CERT_Pair is empty, the unlocking is returned */
            goto EXIT;
        }
        /* Obtain the chain */
        HITLS_CERT_Chain *tmpChain = SAL_CERT_PairGetChain(peerCert);
        if (tmpChain == NULL) {
            /* If the chain in CERT_Pair is empty, the unlocking is returned */
            goto EXIT;
        }

        /* Make a copy of the cert */
        HITLS_CERT_X509 *newSubjectCert = SAL_CERT_X509Dup(sess->certMgrCtx, tmpCert);
        if (newSubjectCert == NULL) {
            ret = HITLS_CERT_ERR_X509_DUP;
            goto EXIT;
        }

        ret = (int32_t)BSL_LIST_AddElement(tmpChain, newSubjectCert, BSL_LIST_POS_BEGIN);
        if (ret != 0) {
            SAL_CERT_X509Free(newSubjectCert);
        }
    }
EXIT:
    BSL_SAL_ThreadUnlock(sess->lock);
    return ret;
}

int32_t SESS_GetPeerCert(HITLS_Session *sess, CERT_Pair **peerCert)
{
    if (sess == NULL || peerCert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16742, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    *peerCert = sess->peerCert;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_CONNECTION_INFO_NEGOTIATION */

uint64_t SESS_GetStartTime(HITLS_Session *sess)
{
    if (sess == NULL) {
        return 0;
    }

    uint64_t startTime = 0u;

    BSL_SAL_ThreadReadLock(sess->lock);
    startTime = sess->startTime;
    BSL_SAL_ThreadUnlock(sess->lock);

    return startTime;
}

int32_t SESS_SetStartTime(HITLS_Session *sess, uint64_t startTime)
{
    if (sess == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16743, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->startTime = startTime;
    BSL_SAL_ThreadUnlock(sess->lock);

    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_SetTimeout(HITLS_Session *sess, uint64_t timeout)
{
    if (sess == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16744, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->timeout = timeout;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

uint64_t HITLS_SESS_GetTimeout(HITLS_Session *sess)
{
    if (sess == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16744, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return 0;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    uint64_t timeout = sess->timeout;
    BSL_SAL_ThreadUnlock(sess->lock);
    return timeout;
}

int32_t HITLS_SESS_SetCipherSuite(HITLS_Session *sess, uint16_t cipherSuite)
{
    if (sess == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16745, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->cipherSuite = cipherSuite;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}
int32_t HITLS_SESS_GetCipherSuite(const HITLS_Session *sess, uint16_t *cipherSuite)
{
    if (sess == NULL || cipherSuite == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16746, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    *cipherSuite = sess->cipherSuite;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_SetMasterKey(HITLS_Session *sess, const uint8_t *masterKey, uint32_t masterKeySize)
{
    if (sess == NULL || masterKey == NULL || masterKeySize == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16747, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    if (memcpy_s(sess->masterKey, sizeof(sess->masterKey), masterKey, masterKeySize) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16748, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    sess->masterKeySize = masterKeySize;

    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_SESSION
uint32_t HITLS_SESS_GetMasterKeyLen(const HITLS_Session *sess)
{
    uint32_t masterKeySize = 0;
    if (sess == NULL) {
        return 0;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    masterKeySize = sess->masterKeySize;
    BSL_SAL_ThreadUnlock(sess->lock);
    return masterKeySize;
}
#endif

int32_t HITLS_SESS_GetMasterKey(const HITLS_Session *sess, uint8_t *masterKey, uint32_t *masterKeySize)
{
    if (sess == NULL || masterKey == NULL || masterKeySize == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16749, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    if (memcpy_s(masterKey, *masterKeySize, sess->masterKey, sess->masterKeySize) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16750, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    *masterKeySize = sess->masterKeySize;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t SESS_SetTicket(HITLS_Session *sess, uint8_t *ticket, uint32_t ticketSize)
{
    if (sess == NULL || ticket == NULL || ticketSize == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16751, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);

    BSL_SAL_FREE(sess->ticket);
    sess->ticket = (uint8_t *)BSL_SAL_Dump(ticket, ticketSize);
    if (sess->ticket == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16752, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    sess->ticketSize = ticketSize;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t SESS_GetTicket(const HITLS_Session *sess, uint8_t **ticket, uint32_t *ticketSize)
{
    if (sess == NULL || ticket == NULL || ticketSize == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    *ticket = sess->ticket;
    *ticketSize = sess->ticketSize;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
bool HITLS_SESS_HasTicket(const HITLS_Session *sess)
{
    if (sess == NULL) {
        return false;
    }

    bool flag = 0;
    BSL_SAL_ThreadReadLock(sess->lock);
    flag = (sess->ticket != NULL);
    BSL_SAL_ThreadUnlock(sess->lock);

    return flag;
}
#endif

bool SESS_CheckValidity(HITLS_Session *sess, uint64_t curTime)
{
    if (sess == NULL) {
        return false;
    }

    bool flag = false;

    BSL_SAL_ThreadReadLock(sess->lock);
    if ((sess->enable) && (curTime < sess->startTime + sess->timeout)) {
        flag = true;
    }
    BSL_SAL_ThreadUnlock(sess->lock);

    return flag;
}

int32_t SESS_SetTicketAgeAdd(HITLS_Session *sess, uint32_t ticketAgeAdd)
{
    if (sess == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16754, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->ticketAgeAdd = ticketAgeAdd;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

uint32_t SESS_GetTicketAgeAdd(const HITLS_Session *sess)
{
    uint32_t ticketAgeAdd = 0;
    if (sess == NULL) {
        return 0;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    ticketAgeAdd = sess->ticketAgeAdd;
    BSL_SAL_ThreadUnlock(sess->lock);
    return ticketAgeAdd;
}

void *HITLS_SESS_GetUserData(const HITLS_Session *sess)
{
    if (sess == NULL) {
        return NULL;
    }
    void *data = NULL;
    BSL_SAL_ThreadReadLock(sess->lock);
    data = sess->userData;
    BSL_SAL_ThreadUnlock(sess->lock);
    return data;
}

int32_t HITLS_SESS_SetUserData(HITLS_Session *sess, void *userData)
{
    if (sess == NULL) {
        return HITLS_NULL_INPUT;
    }
    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->userData = userData;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION */