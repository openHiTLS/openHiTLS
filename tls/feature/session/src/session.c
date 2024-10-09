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

#include <stdbool.h>
#include <time.h>
#include "securec.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "bsl_list.h"
#include "bsl_err_internal.h"
#include "bsl_errno.h"
#include "cert_method.h"
#include "cert.h"
#include "cert_mgr.h"
#include "session_type.h"
#include "session.h"

#define MAX_PRINTF_BUF 1024
#define CTIME_BUF 26
/* RFC8446 8.3 Freshness Checks: For clients on the Internet, this
   implies windows on the order of ten seconds to account for errors in
   clocks and variations in measurements; other deployment scenarios may
   have different needs. */
#define TICKET_AGE_WINDOWS (10 * 1000)
#define MS_CONVERT 1000
#define ONE_SECOND 1000
/**
 * Apply for a session
 */
HITLS_Session *HITLS_SESS_New(void)
{
    HITLS_Session *sess = (HITLS_Session *)BSL_SAL_Calloc(1u, sizeof(HITLS_Session));
    if (sess == NULL) {
        return NULL;
    }

    sess->certMgrCtx = SAL_CERT_MgrCtxNew();
    if (sess->certMgrCtx == NULL) {
        BSL_SAL_FREE(sess);
        return NULL;
    }

    if (BSL_SAL_ThreadLockNew(&sess->lock) != BSL_SUCCESS) {
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
        BSL_SAL_FREE(sess->hostName);
        BSL_SAL_FREE(sess->pskIdentity);
        memset_s(sess->masterKey, MAX_MASTER_KEY_SIZE, 0, MAX_MASTER_KEY_SIZE);
        SAL_CERT_MgrCtxFree(sess->certMgrCtx);
        BSL_SAL_ThreadLockFree(sess->lock);
        BSL_SAL_FREE(sess);
    }
}

HITLS_Session *SESS_Copy(HITLS_Session *src)
{
    HITLS_Session *dest = (HITLS_Session *)BSL_SAL_Dump(src, sizeof(HITLS_Session));
    if (dest == NULL) {
        return NULL;
    }

    if (BSL_SAL_ThreadLockNew(&dest->lock) != BSL_SUCCESS) {
        BSL_SAL_FREE(dest);
        return NULL;
    }

    dest->references = 1;
    dest->enable = true;

    dest->peerCert = NULL;
    dest->hostName = NULL;
    dest->pskIdentity = NULL;
    dest->ticket = NULL;

    dest->certMgrCtx = SAL_CERT_MgrCtxNew();
    if (dest->certMgrCtx == NULL) {
        goto ERR;
    }

    if (src->peerCert != NULL) {
        dest->peerCert = SAL_CERT_PairDup(dest->certMgrCtx, src->peerCert);
        if (dest->peerCert == NULL) {
            goto ERR;
        }
    }

    if (src->hostNameSize > 0) {
        if (SESS_SetHostName(dest, src->hostNameSize, src->hostName) != HITLS_SUCCESS) {
            goto ERR;
        }
    }

    if (src->pskIdentitySize > 0) {
        dest->pskIdentity = (uint8_t *)BSL_SAL_Calloc(1u, (src->pskIdentitySize + 1) * sizeof(uint8_t));
        if (dest->pskIdentity == NULL) {
            goto ERR;
        }
        if (memcpy_s(dest->pskIdentity, src->pskIdentitySize + 1, src->pskIdentity, src->pskIdentitySize) != EOK) {
            goto ERR;
        }
        dest->pskIdentitySize = src->pskIdentitySize;
    }

    if (src->ticketSize > 0) {
        if (SESS_SetTicket(dest, src->ticket, src->ticketSize) != HITLS_SUCCESS) {
            goto ERR;
        }
    }

    return dest;
ERR:
    HITLS_SESS_Free(dest);
    return NULL;
}

/* Simple judgment only */
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
        BSL_SAL_ThreadReadLock(sess->lock);
        sess->enable = false;
        BSL_SAL_ThreadUnlock(sess->lock);
    }
    return;
}

int32_t HITLS_SESS_SetSessionIdCtx(HITLS_Session *sess, uint8_t *sessionIdCtx, uint32_t sessionIdCtxSize)
{
    if (sess == NULL || sessionIdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    if (sessionIdCtxSize != 0 &&
        memcpy_s(sess->sessionIdCtx, sizeof(sess->sessionIdCtx), sessionIdCtx, sessionIdCtxSize) != EOK) {
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    /* The sessionIdCtxSize allowed value is 0 */
    sess->sessionIdCtxSize = sessionIdCtxSize;

    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_GetSessionIdCtx(const HITLS_Session *sess, uint8_t *sessionIdCtx, uint32_t *sessionIdCtxSize)
{
    if (sess == NULL || sessionIdCtx == NULL || sessionIdCtxSize == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    if (memcpy_s(sessionIdCtx, *sessionIdCtxSize, sess->sessionIdCtx, sess->sessionIdCtxSize) != EOK) {
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    *sessionIdCtxSize = sess->sessionIdCtxSize;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_SetSessionId(HITLS_Session *sess, uint8_t *sessionId, uint32_t sessionIdSize)
{
    if (sess == NULL || sessionId == NULL || sessionIdSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    if (memcpy_s(sess->sessionId, sizeof(sess->sessionId), sessionId, sessionIdSize) != EOK) {
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    sess->sessionIdSize = sessionIdSize;

    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_GetSessionId(const HITLS_Session *sess, uint8_t *sessionId, uint32_t *sessionIdSize)
{
    if (sess == NULL || sessionId == NULL || sessionIdSize == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    if (memcpy_s(sessionId, *sessionIdSize, sess->sessionId, sess->sessionIdSize) != EOK) {
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    *sessionIdSize = sess->sessionIdSize;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_SetHaveExtMasterSecret(HITLS_Session *sess, uint8_t haveExtMasterSecret)
{
    if (sess == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->haveExtMasterSecret = (haveExtMasterSecret > 0);
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_GetHaveExtMasterSecret(HITLS_Session *sess, uint8_t *haveExtMasterSecret)
{
    if (sess == NULL || haveExtMasterSecret == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    *haveExtMasterSecret = (uint8_t)sess->haveExtMasterSecret;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

/* Set the server_name extension required for TLS1.2 session resumption */
int32_t SESS_SetHostName(HITLS_Session *sess, uint32_t hostNameSize, uint8_t *hostName)
{
    if (sess == NULL || hostName == NULL || hostNameSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->hostName = (uint8_t *)BSL_SAL_Dump(hostName, hostNameSize * sizeof(uint8_t));
    if (sess->hostName == NULL) {
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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    *hostName = sess->hostName;
    *hostNameSize = sess->hostNameSize;
    BSL_SAL_ThreadUnlock(sess->lock);

    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_SetProtocolVersion(HITLS_Session *sess, uint16_t version)
{
    if (sess == NULL) {
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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    *version = sess->version;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t SESS_SetPeerCert(HITLS_Session *sess, CERT_Pair *peerCert, bool isClient)
{
    int32_t ret = 0;
    if (sess == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
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
            ret = HITLS_SUCCESS;
            goto EXIT;
        }
        /* Obtain the chain */
        HITLS_CERT_Chain *tmpChain = SAL_CERT_PairGetChain(peerCert);
        if (tmpChain == NULL) {
            /* If the chain in CERT_Pair is empty, unlocking is returned */
            ret = HITLS_SUCCESS;
            goto EXIT;
        }

        /* Make a copy of cert */
        HITLS_CERT_X509 *newSubjectCert = SAL_CERT_X509Dup(sess->certMgrCtx, tmpCert);
        if (newSubjectCert == NULL) {
            ret = HITLS_CERT_ERR_X509_DUP;
            goto EXIT;
        }

        ret = (int32_t)BSL_LIST_AddElement(tmpChain, newSubjectCert, BSL_LIST_POS_BEGIN);
        if (ret != 0) {
            SAL_CERT_X509Free(newSubjectCert);
            goto EXIT;
        }
    }

    ret = HITLS_SUCCESS;
EXIT:
    BSL_SAL_ThreadUnlock(sess->lock);
    return ret;
}

int32_t SESS_GetPeerCert(HITLS_Session *sess, CERT_Pair **peerCert)
{
    if (sess == NULL || peerCert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    *peerCert = sess->peerCert;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    sess->timeout = timeout;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

int32_t HITLS_SESS_SetCipherSuite(HITLS_Session *sess, uint16_t cipherSuite)
{
    if (sess == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    sess->cipherSuite = cipherSuite;
    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}
int32_t HITLS_SESS_GetCipherSuite(HITLS_Session *sess, uint16_t *cipherSuite)
{
    if (sess == NULL || cipherSuite == NULL) {
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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);
    if (memcpy_s(sess->masterKey, sizeof(sess->masterKey), masterKey, masterKeySize) != EOK) {
        BSL_SAL_ThreadUnlock(sess->lock);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    sess->masterKeySize = masterKeySize;

    BSL_SAL_ThreadUnlock(sess->lock);
    return HITLS_SUCCESS;
}

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

int32_t HITLS_SESS_GetMasterKey(const HITLS_Session *sess, uint8_t *masterKey, uint32_t *masterKeySize)
{
    if (sess == NULL || masterKey == NULL || masterKeySize == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadReadLock(sess->lock);
    if (memcpy_s(masterKey, *masterKeySize, sess->masterKey, sess->masterKeySize) != EOK) {
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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    BSL_SAL_ThreadWriteLock(sess->lock);

    BSL_SAL_FREE(sess->ticket);
    sess->ticket = (uint8_t *)BSL_SAL_Dump(ticket, ticketSize);
    if (sess->ticket == NULL) {
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

bool SESS_CheckObfuscatedTicketAge(HITLS_Session *sess, uint64_t curTime, uint64_t obfuscatedTicketAge)
{
    if (sess == NULL) {
        return false;
    }

    bool flag = false;
    BSL_SAL_ThreadReadLock(sess->lock);
    uint64_t ticketTmLocal = curTime - sess->startTime;
    uint64_t ticketTmLocalMs = ticketTmLocal * MS_CONVERT;
    uint64_t ticketAgeClient = obfuscatedTicketAge - sess->ticketAgeAdd;
    if ((sess->enable) && (curTime < sess->startTime + sess->timeout) &&
        ((ticketTmLocalMs / (uint64_t)MS_CONVERT) == ticketTmLocal) &&
        ticketAgeClient <= ticketTmLocalMs + ONE_SECOND &&
        ticketAgeClient + TICKET_AGE_WINDOWS >= ticketTmLocalMs + ONE_SECOND) {
        flag = true;
    }
    BSL_SAL_ThreadUnlock(sess->lock);

    return flag;
}

int32_t SESS_SetTicketAgeAdd(HITLS_Session *sess, uint32_t ticketAgeAdd)
{
    if (sess == NULL) {
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
