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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "bsl_sal.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "frame_tls.h"
#include "frame_msg.h"
#include "frame_link.h"
#include "frame_io.h"
#include "simulate_io.h"

#define DEFAUTL_COOKIE_LEN 32

/* Used to establish a link and stop in the state. */
typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    BSL_UIO_TransportType transportType;
} LinkPara;

static void CleanLinkPara(LinkPara *linkPara)
{
    HITLS_CFG_FreeConfig(linkPara->config);
    FRAME_FreeLink(linkPara->client);
    FRAME_FreeLink(linkPara->server);
}

static int32_t PauseState(LinkPara *linkPara, uint16_t version)
{
    (void)version;

    BSL_UIO_TransportType transportType = linkPara->transportType;
#ifdef HITLS_TLS_PROTO_TLCP11
    /* Constructing a Link */
    if ( version == HITLS_VERSION_TLCP_DTLCP11 ) {
        linkPara->client = FRAME_CreateTLCPLink(linkPara->config, transportType, true);
        linkPara->server = FRAME_CreateTLCPLink(linkPara->config, transportType, false);
    } else
#endif /* HITLS_TLS_PROTO_TLCP11 */
    {
        linkPara->client = FRAME_CreateLink(linkPara->config, transportType);
        linkPara->server = FRAME_CreateLink(linkPara->config, transportType);
    }

    if (linkPara->client == NULL || linkPara->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Establish a link and stop in a certain state. */
    if (FRAME_CreateConnection(linkPara->client, linkPara->server,
                               linkPara->isClient, linkPara->state) != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Check whether the status is consistent. */
    HITLS_Ctx *ctx = linkPara->isClient ? linkPara->client->ssl : linkPara->server->ssl;
    if ((ctx->hsCtx == NULL) || (ctx->hsCtx->state != linkPara->state)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

static int32_t SetLinkState(HS_MsgType hsType, LinkPara *linkPara)
{
    linkPara->isClient = true;
    switch (hsType) {
        case CLIENT_HELLO:
            linkPara->isClient = false;
            linkPara->state = TRY_RECV_CLIENT_HELLO;
            return HITLS_SUCCESS;
        case SERVER_HELLO:
            linkPara->state = TRY_RECV_SERVER_HELLO;
            return HITLS_SUCCESS;
        case CERTIFICATE:
            linkPara->state = TRY_RECV_CERTIFICATE;
            return HITLS_SUCCESS;
        case SERVER_KEY_EXCHANGE:
            linkPara->state = TRY_RECV_SERVER_KEY_EXCHANGE;
            return HITLS_SUCCESS;
        case CERTIFICATE_REQUEST:
            linkPara->state = TRY_RECV_CERTIFICATE_REQUEST;
            return HITLS_SUCCESS;
        case SERVER_HELLO_DONE:
            linkPara->state = TRY_RECV_SERVER_HELLO_DONE;
            return HITLS_SUCCESS;
        case CERTIFICATE_VERIFY:
            linkPara->isClient = false;
            linkPara->state = TRY_RECV_CERTIFICATE_VERIFY;
            return HITLS_SUCCESS;
        case CLIENT_KEY_EXCHANGE:
            linkPara->isClient = false;
            linkPara->state = TRY_RECV_CLIENT_KEY_EXCHANGE;
            return HITLS_SUCCESS;
        case FINISHED:
            // The existing framework does not support parsing of encrypted finished messages.
            // Therefore, finished messages cannot be obtained.
            break;
        default:
            break;
    }
    return HITLS_INTERNAL_EXCEPTION;
}

static int32_t SetLinkConfig(uint16_t version, HITLS_KeyExchAlgo keyExAlgo, LinkPara *linkPara)
{
    if (linkPara == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    linkPara->config = NULL;
    if (IS_DTLS_VERSION(version)) {
        linkPara->config = HITLS_CFG_NewDTLS12Config();
    } else if (version == HITLS_VERSION_TLS12) {
        linkPara->config = HITLS_CFG_NewTLS12Config();
    } else if (version == HITLS_VERSION_TLS13) {
        linkPara->config = HITLS_CFG_NewTLS13Config();
    } else if (version == HITLS_VERSION_TLCP_DTLCP11) {
        if (IS_TRANSTYPE_DATAGRAM(linkPara->transportType)) {
            linkPara->config = HITLS_CFG_NewDTLCPConfig();
        } else {
            linkPara->config = HITLS_CFG_NewTLCPConfig();
        }

        return HITLS_SUCCESS;
    }
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
    HITLS_CFG_SetCheckKeyUsage(linkPara->config, false);
#endif /* HITLS_TLS_CONFIG_KEY_USAGE */

#ifdef HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY
    int32_t ret = HITLS_CFG_SetClientVerifySupport(linkPara->config, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif /* HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY */
    if (keyExAlgo == HITLS_KEY_EXCH_DHE) {
        uint16_t cipherSuites[] = {HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256};
        HITLS_CFG_SetCipherSuites(linkPara->config, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
        uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
        HITLS_CFG_SetSignature(linkPara->config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    } else {
        uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1};
        HITLS_CFG_SetGroups(linkPara->config, groups, sizeof(groups) / sizeof(uint16_t));
        uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
        HITLS_CFG_SetSignature(linkPara->config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    }

    return HITLS_SUCCESS;
}

static int32_t GetdefaultHsMsg(FRAME_Type *frameType, FRAME_Msg *parsedMsg)
{
    int32_t ret;
    LinkPara linkPara = {0};

    /* Configure config. */
    linkPara.transportType = frameType->transportType;
    ret = SetLinkConfig(frameType->versionType, frameType->keyExType, &linkPara);
    if (ret != HITLS_SUCCESS) {
        CleanLinkPara(&linkPara);
        return ret;
    }

    /* Setting the parked state */
    ret = SetLinkState(frameType->handshakeType, &linkPara);
    if (ret != HITLS_SUCCESS) {
        CleanLinkPara(&linkPara);
        return ret;
    }

    /* Stop in this state */
    ret = PauseState(&linkPara, frameType->versionType);
    if (ret != HITLS_SUCCESS) {
        CleanLinkPara(&linkPara);
        return ret;
    }

    /* Obtain the message buffer. */
    FRAME_LinkObj *link = linkPara.isClient ? linkPara.client : linkPara.server;
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(link->io);
    uint8_t *buffer = ioUserData->recMsg.msg;
    uint32_t len = ioUserData->recMsg.len;
    if (len == 0) {
        CleanLinkPara(&linkPara);
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Parse to msg structure */
    uint32_t parseLen = 0;
    ret = FRAME_ParseMsg(frameType, buffer, len, parsedMsg, &parseLen);
    if ((ret != HITLS_SUCCESS) || (len != parseLen)) {
        CleanLinkPara(&linkPara);
        return HITLS_INTERNAL_EXCEPTION;
    }

    CleanLinkPara(&linkPara);
    return HITLS_SUCCESS;
}

static void SetDefaultRecordHeader(FRAME_Type *frameType, FRAME_Msg *msg, REC_Type recType)
{
    msg->recType.state = INITIAL_FIELD;
    msg->recType.data = recType;
    msg->recVersion.state = INITIAL_FIELD;
    if (IS_DTLS_VERSION(frameType->versionType)) {
        msg->recVersion.data = HITLS_VERSION_DTLS12;
    } else if (frameType->versionType == HITLS_VERSION_TLCP_DTLCP11) {
        msg->recVersion.data = HITLS_VERSION_TLCP_DTLCP11;
    } else {
        msg->recVersion.data = HITLS_VERSION_TLS12;
    }
    msg->epoch.state = INITIAL_FIELD;
    /* In the default message, the value is set to 0 by default. You need to assign a value to the value. */
    msg->epoch.data = 0;
    msg->sequence.state = INITIAL_FIELD;
    /* In the default message, the value is set to 0 by default. You need to assign a value to the value. */
    msg->sequence.data = 0;
    msg->length.state = INITIAL_FIELD;
    /* The value of length is automatically calculated during assembly.
     * Therefore, the value of length is initialized to 0. */
    msg->length.data = 0;
}

static int32_t GetdefaultCcsMsg(FRAME_Type *frameType, FRAME_Msg *msg)
{
    SetDefaultRecordHeader(frameType, msg, REC_TYPE_CHANGE_CIPHER_SPEC); /* Setting the Default Record Header */
    msg->body.ccsMsg.ccsType.state = INITIAL_FIELD;
    msg->body.ccsMsg.ccsType.data = 1u; /* In the protocol, the CCS type has only this value. */
    return HITLS_SUCCESS;
}

static int32_t GetdefaultAlertMsg(FRAME_Type *frameType, FRAME_Msg *msg)
{
    SetDefaultRecordHeader(frameType, msg, REC_TYPE_ALERT); /* Setting the Default Record Header */
    msg->body.alertMsg.alertLevel.state = INITIAL_FIELD;
    /*Default value. You can change the default value as required. */
    msg->body.alertMsg.alertLevel.data = ALERT_LEVEL_FATAL;
    msg->body.alertMsg.alertDescription.state = INITIAL_FIELD;
     /*Default value. You can change the default value as required. */
    msg->body.alertMsg.alertDescription.data = ALERT_HANDSHAKE_FAILURE;
    return HITLS_SUCCESS;
}

int32_t FRAME_GetDefaultMsg(FRAME_Type *frameType, FRAME_Msg *msg)
{
    if ((frameType == NULL) || (msg == NULL)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    switch (frameType->recordType) {
        case REC_TYPE_HANDSHAKE:
            return GetdefaultHsMsg(frameType, msg);
        case REC_TYPE_CHANGE_CIPHER_SPEC:
            return GetdefaultCcsMsg(frameType, msg);
        case REC_TYPE_ALERT:
            return GetdefaultAlertMsg(frameType, msg);
        default:
            break;
    }
    return HITLS_INTERNAL_EXCEPTION;
}

int32_t FRAME_ModifyMsgInteger(const uint64_t data, FRAME_Integer *frameInteger)
{
    if (frameInteger == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    frameInteger->state = ASSIGNED_FIELD;
    frameInteger->data = data;
    return HITLS_SUCCESS;
}

int32_t FRAME_ModifyMsgArray8(const uint8_t *data, uint32_t dataLen,
                              FRAME_Array8 *frameArray, FRAME_Integer *frameArrayLen)
{
    if ((data == NULL) || (frameArray == NULL) || (dataLen == 0)) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    BSL_SAL_FREE(frameArray->data); /* Clear the old memory. */

    frameArray->data = BSL_SAL_Dump(data, dataLen);
    if (frameArray->data == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    frameArray->state = ASSIGNED_FIELD;
    frameArray->size = dataLen;

    if (frameArrayLen != NULL) {
        frameArrayLen->state = ASSIGNED_FIELD;
        frameArrayLen->data = dataLen;
    }

    return HITLS_SUCCESS;
}

int32_t FRAME_AppendMsgArray8(const uint8_t *data, uint32_t dataLen,
                              FRAME_Array8 *frameArray, FRAME_Integer *frameArrayLen)
{
    if ((data == NULL) || (frameArray == NULL) || (dataLen == 0)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* extended memory */
    uint32_t newDataLen = dataLen + frameArray->size;
    uint8_t *newData = (uint8_t *)BSL_SAL_Calloc(1u, newDataLen);
    if (newData == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    if (memcpy_s(newData, newDataLen, frameArray->data, frameArray->size) != EOK) {
        BSL_SAL_FREE(newData);
        return HITLS_MEMCPY_FAIL;
    }
    if (memcpy_s(&newData[frameArray->size], newDataLen - frameArray->size, data, dataLen) != EOK) {
        BSL_SAL_FREE(newData);
        return HITLS_MEMCPY_FAIL;
    }

    BSL_SAL_FREE(frameArray->data); /* Clear the old memory. */
    frameArray->state = ASSIGNED_FIELD;
    frameArray->data = newData;
    frameArray->size = newDataLen;

    if (frameArrayLen != NULL) {
        frameArrayLen->state = ASSIGNED_FIELD;
        frameArrayLen->data = newDataLen;
    }

    return HITLS_SUCCESS;
}

int32_t FRAME_ModifyMsgArray16(const uint16_t *data, uint32_t dataLen,
                               FRAME_Array16 *frameArray, FRAME_Integer *frameArrayLen)
{
    if ((data == NULL) || (frameArray == NULL) || (dataLen == 0)) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    BSL_SAL_FREE(frameArray->data); /* Clear the old memory. */

    frameArray->data = (uint16_t *)BSL_SAL_Dump(data, dataLen * sizeof(uint16_t));
    if (frameArray->data == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    frameArray->state = ASSIGNED_FIELD;
    frameArray->size = dataLen;

    if (frameArrayLen != NULL) {
        frameArrayLen->state = ASSIGNED_FIELD;
        frameArrayLen->data = dataLen * sizeof(uint16_t);
    }

    return HITLS_SUCCESS;
}

int32_t FRAME_AppendMsgArray16(const uint16_t *data, uint32_t dataLen,
                               FRAME_Array16 *frameArray, FRAME_Integer *frameArrayLen)
{
    if ((data == NULL) || (frameArray == NULL) || (dataLen == 0)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* extended memory */
    uint32_t newDataLen = (frameArray->size + dataLen) * sizeof(uint16_t); /* Data length */
    uint16_t *newData = (uint16_t *)BSL_SAL_Calloc(1u, newDataLen);
    if (newData == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    for (uint32_t i = 0; i < frameArray->size; i++) {
        newData[i] = frameArray->data[i];
    }
    for (uint32_t i = 0; i < dataLen; i++) {
        newData[frameArray->size + i] = data[i];
    }

    BSL_SAL_FREE(frameArray->data); /* Clear the old memory. */
    frameArray->state = ASSIGNED_FIELD;
    frameArray->data = newData;
    frameArray->size = newDataLen / sizeof(uint16_t); /* Number of data records */

    if (frameArrayLen != NULL) {
        frameArrayLen->state = ASSIGNED_FIELD;
        frameArrayLen->data = newDataLen;
    }

    return HITLS_SUCCESS;
}
