/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "tls.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls_psk.h"
#include "hitls_alpn.h"
#include "hs.h"
#include "alert.h"
#include "app.h"
#include "session.h"
#include "indicator.h"
#include "rec.h"
#include "hs_ctx.h"
#include "conn_common.h"

static const char *GetStateString(uint32_t state)
{
    /* * Unknown status */
    if (state >= CM_STATE_END) {
        return "Unknown";
    }

    static const char *stateMachineStr[CM_STATE_END] = {
        [CM_STATE_IDLE] = "Idle",
        [CM_STATE_RENEGOTIATION] = "SecRenego",
        [CM_STATE_HANDSHAKING] = "Handshaking",
        [CM_STATE_TRANSPORTING] = "Transporting",
        [CM_STATE_ALERTING] = "Alerting",
        [CM_STATE_ALERTED] = "Alerted",
        [CM_STATE_CLOSED] = "Closed",
    };
    /** Current status */
    return stateMachineStr[state];
}

void ChangeConnState(HITLS_Ctx *ctx, CM_State state)
{
    if (GetConnState(ctx) == state) {
        return;
    }

    ctx->preState = ctx->state;
    ctx->state = state;
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15839, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN, "state [%s]",
        GetStateString(ctx->preState));
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15840, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN, "change to [%s]",
        GetStateString(state));
    return;
}

int32_t CommonEventInAlertingState(HITLS_Ctx *ctx)
{
    /* The alerting state indicates that an alert message is being sent over the current link. In this case, the alert
     * message should firstly be sent and then the link status will be updated */
    ALERT_Info alertInfo = {0};
    ALERT_GetInfo(ctx, &alertInfo);

    if (alertInfo.level > ALERT_LEVEL_FATAL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret = ALERT_Flush(ctx);
    if (ret != HITLS_SUCCESS) {
        /* If the alert fails to be sent, return error code to user */
        return ret;
    }

    uint8_t data[2] = {alertInfo.level, alertInfo.description};
    INDICATOR_MessageIndicate(1, HS_GetVersion(ctx), REC_TYPE_ALERT, data, (uint32_t)(sizeof(data) / sizeof(uint8_t)),
                              ctx, ctx->config.tlsConfig.msgArg);

    INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_WRITE_ALERT,
        (int32_t)(((uint32_t)(alertInfo.level) << INDICATOR_ALERT_LEVEL_OFFSET) | (uint32_t)(alertInfo.description)));

    /* If a fatal alert is sent, the link must be disconnected */
    if (alertInfo.level == ALERT_LEVEL_FATAL) {
        SESS_Disable(ctx->session);
        ChangeConnState(ctx, CM_STATE_ALERTED);
        return HITLS_SUCCESS;
    }

    /* If the close_notify message is sent, the link must be disconnected */
    if ((alertInfo.description == ALERT_CLOSE_NOTIFY) && (ctx->userShutDown == true)) {
        ChangeConnState(ctx, CM_STATE_CLOSED);
        ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
        return HITLS_SUCCESS;
    }

    if ((alertInfo.description == ALERT_CLOSE_NOTIFY) && (ctx->userShutDown == false)) {
        ChangeConnState(ctx, CM_STATE_ALERTED);
        ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
        return HITLS_SUCCESS;
    }

    /* Other warning alerts will not terminate the connection and the status will be restored to the previous status */
    ctx->state = ctx->preState;
    ALERT_CleanInfo(ctx);
    return HITLS_SUCCESS;
}

static int32_t AlertRecvProcess(HITLS_Ctx *ctx, const ALERT_Info *alertInfo)
{
    uint8_t data[2] = {alertInfo->level, alertInfo->description};
    INDICATOR_MessageIndicate(0, HS_GetVersion(ctx), REC_TYPE_ALERT, data,
        (uint32_t)(sizeof(data) / sizeof(uint8_t)), ctx, ctx->config.tlsConfig.msgArg);

    INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_READ_ALERT,
        (int32_t)(((uint32_t)(alertInfo->level) << INDICATOR_ALERT_LEVEL_OFFSET) | (uint32_t)(alertInfo->description)));

    /* If a fatal alert is received, the link must be disconnected */
    if (alertInfo->level == ALERT_LEVEL_FATAL) {
        SESS_Disable(ctx->session);
        ChangeConnState(ctx, CM_STATE_ALERTED);
        ctx->shutdownState |= HITLS_RECEIVED_SHUTDOWN;
        return HITLS_SUCCESS;
    }

    /* If a warning alert is received, the connection must be terminated if the alert is close_notify. Otherwise, the
     * alert will not be processed  */
    ALERT_CleanInfo(ctx);
    if (alertInfo->description != ALERT_CLOSE_NOTIFY) {
        /* Other warning alerts will not be processed */
        return HITLS_SUCCESS;
    }

    ctx->shutdownState |= HITLS_RECEIVED_SHUTDOWN;

    /* In quiet disconnection mode, close_notify does not need to be sent */
    if (ctx->config.tlsConfig.isQuietShutdown) {
        ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
        ChangeConnState(ctx, CM_STATE_ALERTED);
        return HITLS_SUCCESS;
    }

    if ((ctx->shutdownState & HITLS_SENT_SHUTDOWN) == 0) {
        /* If the close_notify message is received, the close_notify message must be sent to the peer */
        ALERT_Send(ctx, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
        ChangeConnState(ctx, CM_STATE_ALERTING);
        int32_t ret = ALERT_Flush(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
    }

    if (ctx->state != CM_STATE_CLOSED) {
        ChangeConnState(ctx, CM_STATE_ALERTED);
    }
    return HITLS_SUCCESS;
}

int32_t AlertEventProcess(HITLS_Ctx *ctx)
{
    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(ctx, &alertInfo);

    /* An alert message is received. */
    if (alertInfo.flag == ALERT_FLAG_RECV) {
        return AlertRecvProcess(ctx, &alertInfo);
    }

    /* An alert message needs to be sent */
    if (alertInfo.flag == ALERT_FLAG_SEND) {
        ChangeConnState(ctx, CM_STATE_ALERTING);
        return CommonEventInAlertingState(ctx);
    }

    return HITLS_SUCCESS;
}

int32_t CommonEventInHandshakingState(HITLS_Ctx *ctx)
{
    int32_t ret;
    int32_t alertRet;
    uint32_t alertCount = 0;

    do {
        ret = HS_DoHandshake(ctx);
        if (ret == HITLS_SUCCESS) {
            /* The handshake has completed */
            break;
        }

        if (!ALERT_GetFlag(ctx)) {
            /* The handshake fails, but no alert is received. Return the error code to the user */
            return ret;
        }

        alertCount++;
        if (alertCount >= MAX_ALERT_COUNT) {
            /* If there are multiple consecutive alerts, the link is abnormal and needs to be terminated. */
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
            alertRet = AlertEventProcess(ctx);
            return (alertRet == HITLS_SUCCESS) ? ret : alertRet;
        }

        alertRet = AlertEventProcess(ctx);
        if (alertRet != HITLS_SUCCESS) {
            /* If the alert message fails to be sent, return the error code to the user */
            return alertRet;
        }

        /* If fatal alert or close_notify has been processed, the handshake must be terminated */
        if (ctx->state == CM_STATE_ALERTED) {
            return ret;
        }
    } while (ret != HITLS_SUCCESS);

    // If HS_DoHandshake returns success, the connection has been established.
    ChangeConnState(ctx, CM_STATE_TRANSPORTING);
    HS_DeInit(ctx);

    return HITLS_SUCCESS;
}

const HITLS_Config *HITLS_GetConfig(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return &(ctx->config.tlsConfig);
}

int32_t HITLS_ClearTLS13CipherSuites(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_ClearTLS13CipherSuites(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetCipherSuites(HITLS_Ctx *ctx, const uint16_t *cipherSuites, uint32_t cipherSuitesSize)
{
    if (ctx == NULL || cipherSuites == NULL || cipherSuitesSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetCipherSuites(&(ctx->config.tlsConfig), cipherSuites, cipherSuitesSize);
}

int32_t HITLS_SetAlpnProtos(HITLS_Ctx *ctx, const uint8_t *protos, uint32_t protosLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetAlpnProtos(&(ctx->config.tlsConfig), protos, protosLen);
}

int32_t HITLS_SetPskClientCallback(HITLS_Ctx *ctx, HITLS_PskClientCb cb)
{
    if (ctx == NULL || cb == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetPskClientCallback(&(ctx->config.tlsConfig), cb);
}

int32_t HITLS_SetPskServerCallback(HITLS_Ctx *ctx, HITLS_PskServerCb cb)
{
    if (ctx == NULL || cb == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetPskServerCallback(&(ctx->config.tlsConfig), cb);
}

int32_t HITLS_SetPskIdentityHint(HITLS_Ctx *ctx, const uint8_t *identityHint, uint32_t identityHintLen)
{
    return HITLS_CFG_SetPskIdentityHint(&(ctx->config.tlsConfig), identityHint, identityHintLen);
}

const HITLS_Cipher *HITLS_GetCurrentCipher(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return &(ctx->negotiatedInfo.cipherSuiteInfo);
}

int32_t HITLS_GetRandom(const HITLS_Ctx *ctx, uint8_t *out, uint32_t *outlen, bool isClient)
{
    if (ctx == NULL || outlen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (*outlen == 0) {
        *outlen = RANDOM_SIZE;
        return HITLS_SUCCESS;
    }

    uint32_t resLen = *outlen;

    if (resLen > RANDOM_SIZE) {
        resLen = RANDOM_SIZE;
    }

    if (out == NULL) {
        *outlen = resLen;
        return HITLS_SUCCESS;
    }

    if (isClient) {
        if (memcpy_s(out, resLen, ctx->negotiatedInfo.clientRandom, resLen) != EOK) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            return HITLS_MEMCPY_FAIL;
        }
    } else {
        if (memcpy_s(out, resLen, ctx->negotiatedInfo.serverRandom, resLen) != EOK) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            return HITLS_MEMCPY_FAIL;
        }
    }

    *outlen = resLen;
    return HITLS_SUCCESS;
}

int32_t HITLS_IsClient(const HITLS_Ctx *ctx, bool *isClient)
{
    if (ctx == NULL || isClient == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    *isClient = ctx->isClient;
    return HITLS_SUCCESS;
}

/**
 * If current endpoint is a server and the server preference is supported, the local server group array is preferred.
 * If current endpoint is a server and the client preference is supported, the peer (client)group array is preferred
 */
static uint16_t FindPreference(const HITLS_Ctx *ctx, int32_t nmatch, bool *haveFound)
{
    uint16_t ans = 0;
    uint32_t preferGroupSize = 0;
    uint32_t secondPreferGroupSize = 0;
    uint16_t *preferGroups = NULL;
    uint16_t *secondPreferGroups = NULL;
    uint32_t peerGroupSize = ctx->peerInfo.groupsSize;
    uint32_t localGroupSize = ctx->config.tlsConfig.groupsSize;
    uint16_t *peerGroups = ctx->peerInfo.groups;
    uint16_t *localGroups = ctx->config.tlsConfig.groups;
    bool chooseServerPre = ctx->config.tlsConfig.isSupportServerPreference;
    uint16_t intersectionCnt = 0;

    preferGroupSize = (chooseServerPre == true) ? localGroupSize : peerGroupSize;
    secondPreferGroupSize = (chooseServerPre == true) ? peerGroupSize : localGroupSize;
    preferGroups = (chooseServerPre == true) ? localGroups : peerGroups;
    secondPreferGroups = (chooseServerPre == true) ? peerGroups : localGroups;

    for (uint32_t i = 0; i < preferGroupSize; i++) {
        for (uint32_t j = 0; j < secondPreferGroupSize; j++) {
            if (preferGroups[i] == secondPreferGroups[j]) {
                intersectionCnt++;
                // Currently, the preferred nmatch is already matched
                bool isMatch = (intersectionCnt == nmatch);
                *haveFound = (isMatch ? true : (*haveFound));
                ans = (isMatch ? preferGroups[i] : ans);
                // Jump out of the inner village and change
                break;
            }
        }
        if (*haveFound) {
            // Exit a loop
            break;
        }
    }
    if (nmatch == GET_GROUPS_CNT) {
        return (uint16_t)intersectionCnt;
    }
    return ans;
}

/**
 * nmatch Value range: - 1 or a positive integer
 * This function can be invoked only after negotiation and can be invoked only by the server.
 * When nmatch is a positive integer, check the intersection of groups on the client and server, and return the nmatch
 * group in the intersection by groupId. If the value of nmatch is - 1, the number of intersection groups on the client
 * and server is returned based on groupId.
 */
int32_t HITLS_GetSharedGroup(const HITLS_Ctx *ctx, int32_t nmatch, uint16_t *groupId)
{
    bool haveFound = false;
    if (ctx == NULL || groupId == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    *groupId = 0;
    // Check the value range of nmatch and whether the interface is invoked by the server. The client cannot invoke the
    // interface because the client cannot sense the peerInfo.
    if (nmatch < GET_GROUPS_CNT || nmatch == 0 || ctx->isClient) {
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }

    *groupId = FindPreference(ctx, nmatch, &haveFound);

    if (nmatch == GET_GROUPS_CNT) {
        // The value of *groupId is the number of intersections
        return HITLS_SUCCESS;
    } else if (haveFound == false) {
        // If nmatch is not equal to GET_GROUPS_CNT and haveFound is false
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_GetPeerFinishVerifyData(const HITLS_Ctx *ctx, void *buf, uint32_t bufLen, uint32_t *dataLen)
{
    int32_t ret;
    uint32_t verifyDataSize, bufSize;
    const uint8_t *verifyData = NULL;

    if (ctx == NULL || buf == NULL || dataLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (ctx->isClient) {
        verifyDataSize = ctx->negotiatedInfo.serverVerifyDataSize;
        verifyData = ctx->negotiatedInfo.serverVerifyData;
    } else {
        verifyDataSize = ctx->negotiatedInfo.clientVerifyDataSize;
        verifyData = ctx->negotiatedInfo.clientVerifyData;
    }

    if (bufLen > verifyDataSize) {
        bufSize = verifyDataSize;
    } else {
        bufSize = bufLen;
    }

    ret = memcpy_s(buf, bufLen, verifyData, bufSize);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }
    *dataLen = verifyDataSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetFinishVerifyData(const HITLS_Ctx *ctx, void *buf, uint32_t bufLen, uint32_t *dataLen)
{
    int32_t ret;
    uint32_t verifyDataSize, bufSize;
    const uint8_t *verifyData = NULL;

    if (ctx == NULL || buf == NULL || dataLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (ctx->isClient) {
        verifyDataSize = ctx->negotiatedInfo.clientVerifyDataSize;
        verifyData = ctx->negotiatedInfo.clientVerifyData;
    } else {
        verifyDataSize = ctx->negotiatedInfo.serverVerifyDataSize;
        verifyData = ctx->negotiatedInfo.serverVerifyData;
    }

    if (bufLen > verifyDataSize) {
        bufSize = verifyDataSize;
    } else {
        bufSize = bufLen;
    }

    ret = memcpy_s(buf, bufLen, verifyData, bufSize);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }
    *dataLen = verifyDataSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetVersionSupport(const HITLS_Ctx *ctx, uint32_t *version)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetVersionSupport(&(ctx->config.tlsConfig), version);
}

int32_t HITLS_SetVersionSupport(HITLS_Ctx *ctx, uint32_t version)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetVersionSupport(&(ctx->config.tlsConfig), version);
}

int32_t HITLS_SetNeedCheckPmsVersion(HITLS_Ctx *ctx, bool needCheck)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetNeedCheckPmsVersion(&(ctx->config.tlsConfig), needCheck);
}

static int32_t CheckSecRenegotiationCb(HITLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    if (ctx->config.tlsConfig.noSecRenegotiationCb != NULL) {
        /* If the peer end does not support the renegotiation, stop the renegotiation. In this case, the link
         * establishment is complete and messages are sent and received. You can determine whether to disconnect the
         * link when the peer end does not support security renegotiation. */
        ret = ctx->config.tlsConfig.noSecRenegotiationCb(ctx);
        if (ret != HITLS_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15951, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "noSecRenegotiationCb return fail during renegotiataion.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        }
    }
    return ret;
}

int32_t CommonEventInRenegotiationState(HITLS_Ctx *ctx)
{
    int32_t ret;
    int32_t alertRet;
    uint32_t alertCount = 0;

    do {
        ret = HS_DoHandshake(ctx);
        if (ret == HITLS_SUCCESS) { /* The handshake has completed */
            break;
        }
        /* The handshake fails, but no alert is displayed. The system returns a message
        * to the user for processing */
        if (!ALERT_GetFlag(ctx)) {
            return ret;
        }
        ALERT_Info alertInfo = { 0 };
        ALERT_GetInfo(ctx, &alertInfo);
        if ((alertInfo.level == ALERT_LEVEL_WARNING) && (alertInfo.description == ALERT_NO_RENEGOTIATION)) {
            if (ctx->hsCtx->state == TRY_RECV_SERVER_HELLO || ctx->hsCtx->state == TRY_RECV_CLIENT_HELLO) {
                ctx->userRenego = false;
                ret = CheckSecRenegotiationCb(ctx);
            } else {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15330, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "Receive no renegotiation alert during renegotiation process", 0, 0, 0, 0);
                ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
            }
        }

        alertCount++;
        if (alertCount >= MAX_ALERT_COUNT) {
            /* If multiple consecutive alerts exist, the link is abnormal and needs to be terminated */
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        }

        alertRet = AlertEventProcess(ctx);
        if (alertRet != HITLS_SUCCESS) {
            /* If the alert fails to be sent, the system sends a message to the user for processing */
            return alertRet;
        }

        /**
            If fatal alert or close_notify has been processed, the handshake must be terminated.
        */
        if (ctx->state == CM_STATE_ALERTED) {
            return ret;
        }
    } while (ret != HITLS_SUCCESS);

    // If the HS_DoHandshake message is returned successfully, the link has been terminated.
    ChangeConnState(ctx, CM_STATE_TRANSPORTING);
    HS_DeInit(ctx);

    ctx->negotiatedInfo.isRenegotiation = false; /* Disabling renegotiation */
    BSL_LOG_BINLOG_FIXLEN(
        BINLOG_ID15952, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN, "renegotiate completed.", 0, 0, 0, 0);
    return HITLS_SUCCESS;
}

int32_t HITLS_SetPskFindSessionCallback(HITLS_Ctx *ctx, HITLS_PskFindSessionCb cb)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetPskFindSessionCallback(&(ctx->config.tlsConfig), cb);
}

int32_t HITLS_SetPskUseSessionCallback(HITLS_Ctx *ctx, HITLS_PskUseSessionCb cb)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetPskUseSessionCallback(&(ctx->config.tlsConfig), cb);
}

int32_t HITLS_GetNegotiateGroup(const HITLS_Ctx *ctx, uint16_t *group)
{
    if (ctx == NULL || group == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *group = ctx->negotiatedInfo.negotiatedGroup;
    return HITLS_SUCCESS;
}

int HITLS_EventProcWrapper(void *arg)
{
    HITLSAsyncArgs *args = (HITLSAsyncArgs *)arg;
    switch (args->evenType) {
        case READ_EVENT:
            return ((ReadEventProcess)args->func)(args->ctx, args->buf, args->bufSize, args->size);
        case WRITE_EVENT:
            return ((WriteEventProcess)args->func)(args->ctx, args->buf, args->bufSize);
        case MANAGER_EVENT:
            return ((ManageEventProcess)args->func)(args->ctx);
        default:
            break;
    }

    return -1;
}