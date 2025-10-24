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

#include <stdint.h>
#include <stdbool.h>
#include "hitls_build.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_log.h"
#include "tls_binlog_id.h"
#include "hitls_error.h"
#include "rec.h"
#ifdef HITLS_TLS_FEATURE_PSK
#include "hitls_psk.h"
#endif
#ifdef HITLS_TLS_FEATURE_ALPN
#include "hitls_alpn.h"
#endif
#ifdef HITLS_TLS_FEATURE_SNI
#include "hitls_sni.h"
#endif
#ifdef HITLS_TLS_FEATURE_SESSION
#include "session_mgr.h"
#endif

#ifdef HITLS_TLS_FEATURE_MAX_SEND_FRAGMENT
#define MAX_PLAINTEXT_LEN 16384u
#define MIN_MAX_SEND_FRAGMENT 512u
#endif
#ifdef HITLS_TLS_FEATURE_REC_INBUFFER_SIZE
#define MAX_INBUFFER_SIZE 18432u
#define MIN_INBUFFER_SIZE 512u
#endif

#ifdef HITLS_TLS_FEATURE_SNI
int32_t HITLS_CFG_SetServerName(HITLS_Config *config, uint8_t *serverName, uint32_t serverNameStrlen)
{
    if ((config == NULL) || (serverName == NULL) || (serverNameStrlen == 0)) {
        return HITLS_NULL_INPUT;
    }

    if (serverNameStrlen > HITLS_CFG_MAX_SIZE) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }
    uint32_t serverNameSize = serverNameStrlen;
    if (serverName[serverNameStrlen - 1] != '\0') {
        serverNameSize += 1;
    }
    uint8_t *newData = (uint8_t *) BSL_SAL_Malloc(serverNameSize * sizeof(uint8_t));
    if (newData == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16606, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)memcpy_s(newData, serverNameSize, serverName, serverNameStrlen);
    newData[serverNameSize - 1] = '\0';

    BSL_SAL_FREE(config->serverName);
    config->serverName = newData;
    config->serverNameSize = serverNameSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetServerName(HITLS_Config *config, uint8_t **serverName, uint32_t *serverNameStrlen)
{
    if (config == NULL || serverName == NULL || serverNameStrlen == NULL) {
        return HITLS_NULL_INPUT;
    }

    *serverName = config->serverName;
    *serverNameStrlen =  config->serverNameSize;

    return HITLS_SUCCESS;
}
int32_t HITLS_CFG_SetServerNameCb(HITLS_Config *config, HITLS_SniDealCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->sniDealCb = callback;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetServerNameArg(HITLS_Config *config, void *arg)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->sniArg = arg;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetServerNameCb(HITLS_Config *config, HITLS_SniDealCb *callback)
{
    if (config == NULL || callback == NULL) {
        return HITLS_NULL_INPUT;
    }

    *callback = config->sniDealCb;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetServerNameArg(HITLS_Config *config, void **arg)
{
    if (config == NULL || arg == NULL) {
        return HITLS_NULL_INPUT;
    }

    *arg = config->sniArg;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SNI */

#ifdef HITLS_TLS_FEATURE_ALPN
static int32_t AlpnListValidationCheck(const uint8_t *alpnList, uint32_t alpnProtosLen)
{
    uint32_t index = 0u;

    while (index < alpnProtosLen) {
        if (alpnList[index] == 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16608, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "alpnList null", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
            return HITLS_CONFIG_INVALID_LENGTH;
        }
        index += (alpnList[index] + 1);
    }

    if (index != alpnProtosLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16609, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "alpnProtosLen err", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetAlpnProtos(HITLS_Config *config, const uint8_t *alpnProtos, uint32_t alpnProtosLen)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    /* If the input parameter is empty or the length is 0, clear the original alpn list */
    if (alpnProtosLen == 0 || alpnProtos == NULL) {
        BSL_SAL_FREE(config->alpnList);
        config->alpnListSize = 0;
        return HITLS_SUCCESS;
    }

    /* Add the check on alpnList. The expected format is |protoLen1|proto1|protoLen2|proto2|...| */
    if (AlpnListValidationCheck(alpnProtos, alpnProtosLen) != HITLS_SUCCESS) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint8_t *alpnListTmp = (uint8_t *)BSL_SAL_Calloc(alpnProtosLen + 1, sizeof(uint8_t));
    if (alpnListTmp == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16610, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    (void)memcpy_s(alpnListTmp, alpnProtosLen + 1, alpnProtos, alpnProtosLen);

    BSL_SAL_FREE(config->alpnList);
    config->alpnList = alpnListTmp;
    /* Ignore ending 0s */
    config->alpnListSize = alpnProtosLen;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetAlpnProtosSelectCb(HITLS_Config *config, HITLS_AlpnSelectCb callback, void *userData)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->alpnSelectCb = callback;
    config->alpnUserData = userData;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_ALPN */

#ifdef HITLS_TLS_FEATURE_PSK
// Configure clientCb, which is used to obtain the PSK through identity hints
int32_t HITLS_CFG_SetPskClientCallback(HITLS_Config *config, HITLS_PskClientCb callback)
{
    if (config == NULL || callback == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->pskClientCb = callback;
    return HITLS_SUCCESS;
}

// Set serverCb to obtain the PSK through identity.
int32_t HITLS_CFG_SetPskServerCallback(HITLS_Config *config, HITLS_PskServerCb callback)
{
    if (config == NULL || callback == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->pskServerCb = callback;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_PSK */

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
int32_t HITLS_CFG_SetClientRenegotiateSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->allowClientRenegotiate = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetClientRenegotiateSupport(HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }
    *isSupport = config->allowClientRenegotiate;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetRenegotiationSupport(const HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportRenegotiation;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */

#if defined(HITLS_TLS_FEATURE_RENEGOTIATION) && defined(HITLS_TLS_FEATURE_SESSION)
int32_t HITLS_CFG_SetResumptionOnRenegoSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->isResumptionOnRenego = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetResumptionOnRenegoSupport(HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }
    *isSupport = config->isResumptionOnRenego;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION && HITLS_TLS_FEATURE_SESSION */

#ifdef HITLS_TLS_FEATURE_SESSION
int32_t HITLS_CFG_SetSessionTimeout(HITLS_Config *config, uint64_t timeout)
{
    if (config == NULL || config->sessMgr == NULL) {
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetTimeout(config->sessMgr, timeout);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionTimeout(const HITLS_Config *config, uint64_t *timeout)
{
    if (config == NULL || config->sessMgr == NULL || timeout == NULL) {
        return HITLS_NULL_INPUT;
    }

    *timeout = SESSMGR_GetTimeout(config->sessMgr);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetNewSessionCb(HITLS_Config *config, const HITLS_NewSessionCb newSessionCb)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->newSessionCb = newSessionCb;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSessionCacheMode(HITLS_Config *config, uint32_t mode)
{
    if (config == NULL || config->sessMgr == NULL) {
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetCacheMode(config->sessMgr, mode);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionCacheMode(HITLS_Config *config, uint32_t *mode)
{
    if (config == NULL || config->sessMgr == NULL || mode == NULL) {
        return HITLS_NULL_INPUT;
    }

    *mode = SESSMGR_GetCacheMode(config->sessMgr);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSessionCacheSize(HITLS_Config *config, uint32_t size)
{
    if (config == NULL || config->sessMgr == NULL) {
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetCacheSize(config->sessMgr, size);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionCacheSize(HITLS_Config *config, uint32_t *size)
{
    if (config == NULL || config->sessMgr == NULL || size == NULL) {
        return HITLS_NULL_INPUT;
    }

    *size = SESSMGR_GetCacheSize(config->sessMgr);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_ClearTimeoutSession(HITLS_Config *config, uint64_t nowTime)
{
    if (config == NULL || config->sessMgr == NULL) {
        return HITLS_NULL_INPUT;
    }
    SESSMGR_ClearTimeout(config, nowTime);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_RemoveSession(HITLS_Config *config, HITLS_Session *sess)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    return SESSMGR_RemoveSession(config, sess);
}
#endif /* HITLS_TLS_FEATURE_SESSION */

#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
int32_t HITLS_CFG_SetSessionTicketSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isSupportSessionTicket = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionTicketSupport(const HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportSessionTicket;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetTicketKeyCallback(HITLS_Config *config, HITLS_TicketKeyCb callback)
{
    if (config == NULL || config->sessMgr == NULL) {
        return HITLS_NULL_INPUT;
    }

    SESSMGR_SetTicketKeyCb(config->sessMgr, callback);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetSessionTicketKey(const HITLS_Config *config, uint8_t *key, uint32_t keySize, uint32_t *outSize)
{
    if (config == NULL || config->sessMgr == NULL || key == NULL || outSize == NULL) {
        return HITLS_NULL_INPUT;
    }

    return SESSMGR_GetTicketKey(config->sessMgr, key, keySize, outSize);
}

int32_t HITLS_CFG_SetSessionTicketKey(HITLS_Config *config, const uint8_t *key, uint32_t keySize)
{
    if (config == NULL || config->sessMgr == NULL || key == NULL ||
        (keySize != HITLS_TICKET_KEY_NAME_SIZE + HITLS_TICKET_KEY_SIZE + HITLS_TICKET_KEY_SIZE)) {
        return HITLS_NULL_INPUT;
    }

    return SESSMGR_SetTicketKey(config->sessMgr, key, keySize);
}

int32_t HITLS_CFG_SetTicketNums(HITLS_Config *config, uint32_t ticketNums)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->ticketNums = ticketNums;
    return HITLS_SUCCESS;
}

uint32_t HITLS_CFG_GetTicketNums(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    return config->ticketNums;
}
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */

#ifdef HITLS_TLS_FEATURE_SESSION_ID
int32_t HITLS_CFG_SetSessionIdCtx(HITLS_Config *config, const uint8_t *sessionIdCtx, uint32_t len)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (len != 0 && memcpy_s(config->sessionIdCtx, sizeof(config->sessionIdCtx), sessionIdCtx, len) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }

    /* The allowed value is 0 */
    config->sessionIdCtxSize = len;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION_ID */

#ifdef HITLS_TLS_FEATURE_SESSION_CACHE_CB
int32_t HITLS_CFG_SetSessionGetCb(HITLS_Config *config, const HITLS_SessionGetCb sessionGetCb)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->sessionGetCb = sessionGetCb;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetSessionRemoveCb(HITLS_Config *config, const HITLS_SessionRemoveCb sessionRemoveCb)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->sessionRemoveCb = sessionRemoveCb;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION_CACHE_CB */

#if defined(HITLS_TLS_FEATURE_CERT_MODE) && defined(HITLS_TLS_FEATURE_RENEGOTIATION)
int32_t HITLS_CFG_SetClientOnceVerifySupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->isSupportClientOnceVerify = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetClientOnceVerifySupport(HITLS_Config *config, bool *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = config->isSupportClientOnceVerify;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_CERT_MODE && HITLS_TLS_FEATURE_RENEGOTIATION */

#ifdef HITLS_TLS_FEATURE_FLIGHT
int32_t HITLS_CFG_SetFlightTransmitSwitch(HITLS_Config *config, bool isEnable)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isFlightTransmitEnable = isEnable;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetFlightTransmitSwitch(const HITLS_Config *config, bool *isEnable)
{
    if (config == NULL || isEnable == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isEnable = config->isFlightTransmitEnable;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_FLIGHT */

#ifdef HITLS_TLS_FEATURE_MAX_SEND_FRAGMENT
int32_t HITLS_CFG_SetMaxSendFragment(HITLS_Config *config, uint16_t maxSendFragment)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (maxSendFragment > MAX_PLAINTEXT_LEN || maxSendFragment < MIN_MAX_SEND_FRAGMENT) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    config->maxSendFragment = maxSendFragment;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetMaxSendFragment(const HITLS_Config *config, uint16_t *maxSendFragment)
{
    if (config == NULL || maxSendFragment == NULL) {
        return HITLS_NULL_INPUT;
    }
    *maxSendFragment = config->maxSendFragment;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_MAX_SEND_FRAGMENT */

#ifdef HITLS_TLS_FEATURE_REC_INBUFFER_SIZE
int32_t HITLS_CFG_SetRecInbufferSize(HITLS_Config *config, uint32_t recInbufferSize)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (recInbufferSize > MAX_INBUFFER_SIZE || recInbufferSize < MIN_INBUFFER_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_LENGTH);
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    config->recInbufferSize = recInbufferSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetRecInbufferSize(const HITLS_Config *config, uint32_t *recInbufferSize)
{
    if (config == NULL || recInbufferSize == NULL) {
        return HITLS_NULL_INPUT;
    }
    *recInbufferSize = config->recInbufferSize;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_REC_INBUFFER_SIZE */

#ifdef HITLS_TLS_FEATURE_MODE
int32_t HITLS_CFG_SetModeSupport(HITLS_Config *config, uint32_t mode)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->modeSupport |= mode;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_ClearModeSupport(HITLS_Config *config, uint32_t mode)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->modeSupport &= (~mode);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetModeSupport(const HITLS_Config *config, uint32_t *mode)
{
    if (config == NULL || mode == NULL) {
        return HITLS_NULL_INPUT;
    }

    *mode = config->modeSupport;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_MODE */

#ifdef HITLS_TLS_FEATURE_CLIENT_HELLO_CB
int32_t HITLS_CFG_SetClientHelloCb(HITLS_Config *config, HITLS_ClientHelloCb callback, void *arg)
{
    if (config == NULL || callback == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->clientHelloCb = callback;
    config->clientHelloCbArg = arg;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_CLIENT_HELLO_CB */
