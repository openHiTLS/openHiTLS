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
#ifdef HITLS_BSL_UIO_SCTP

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "sal_net.h"
#include "uio_base.h"
#include "uio_abstraction.h"

#define SCTP_SHARE_AUTHKEY_ID_MAX 65535

typedef struct {
    bool peerAuthed;                /* Whether auth is enabled at the peer end */
    /* Whether authkey is added: If authkey is added but not active, success is returned when authkey is added again. */
    bool isAddAuthkey;
    bool reserved[2];                /* Four-byte alignment is reserved. */

    uint16_t sendAppStreamId;       /* ID of the stream sent by the user-specified app. */
    uint16_t prevShareKeyId;
    uint16_t shareKeyId;
    uint16_t reserved1;              /* Four-byte alignment is reserved. */
} BslSctpData;

typedef struct {
    BslSctpData data;
    int32_t fd;                 // Network socket
    uint32_t ipLen;
    uint8_t ip[IP_ADDR_MAX_LEN];
    struct BSL_UIO_MethodStruct method;
    bool isAppMsg;              // whether the message sent is the app message
} SctpParameters;

static int32_t BslSctpNew(BSL_UIO *uio)
{
    SctpParameters *parameters = (SctpParameters *)BSL_SAL_Calloc(1u, sizeof(SctpParameters));
    if (parameters == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05031, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: sctp param malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    parameters->fd = -1;
    parameters->method.uioType = BSL_UIO_SCTP;
    uio->ctx = parameters;
    uio->ctxLen = sizeof(SctpParameters);
    // The default value of init is 0. Set the value of init to 1 after the fd is set.
    return BSL_SUCCESS;
}

static int32_t BslSctpDestroy(BSL_UIO *uio)
{
    if (uio == NULL) {
        return BSL_SUCCESS;
    }
    SctpParameters *ctx = BSL_UIO_GetCtx(uio);
    uio->init = 0;
    if (ctx != NULL) {
        if (BSL_UIO_GetIsUnderlyingClosedByUio(uio) && ctx->fd != -1) {
            (void)BSL_SAL_SockClose(ctx->fd);
        }
        BSL_SAL_FREE(ctx);
        BSL_UIO_SetCtx(uio, NULL);
    }
    return BSL_SUCCESS;
}

static int32_t BslSctpWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    if (uio == NULL || uio->ctx == NULL || ((SctpParameters *)uio->ctx)->method.uioWrite == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05081, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Sctp write input error.", 0, 0, 0, 0);
        return BSL_INVALID_ARG;
    }
    *writeLen = 0;
    return ((SctpParameters *)uio->ctx)->method.uioWrite(uio, buf, len, writeLen);
}

static int32_t BslSctpRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    if (uio == NULL || uio->ctx == NULL || ((SctpParameters *)uio->ctx)->method.uioRead == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05082, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Sctp read input error.", 0, 0, 0, 0);
        return BSL_INVALID_ARG;
    }
    *readLen = 0;
    SctpParameters *parameters = (SctpParameters *)uio->ctx;
    if (!parameters->data.peerAuthed) {
        if (parameters->method.uioCtrl == NULL || parameters->method.uioCtrl(uio, BSL_UIO_SCTP_CHECK_PEER_AUTH,
            sizeof(parameters->data.peerAuthed), &parameters->data.peerAuthed) != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05083, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Uio: Check peer auth failed.", 0, 0, 0, 0);
            return BSL_UIO_IO_EXCEPTION;
        }
        parameters->data.peerAuthed = true;
    }
    return parameters->method.uioRead(uio, buf, len, readLen);
}

static int32_t BslSctpAddAuthKey(BSL_UIO *uio, const uint8_t *parg, uint16_t larg)
{
    SctpParameters *parameters = (SctpParameters *)BSL_UIO_GetCtx(uio);
    if (parg == NULL || larg != sizeof(BSL_UIO_SctpAuthKey)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05062, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "add auth key failed", 0, 0, 0, 0);
        return BSL_INVALID_ARG;
    }

    if (parameters->data.isAddAuthkey) {
        return BSL_SUCCESS;
    }

    uint16_t prevShareKeyId = parameters->data.shareKeyId;
    if (parameters->data.shareKeyId >= SCTP_SHARE_AUTHKEY_ID_MAX) {
        parameters->data.shareKeyId = 1;
    } else {
        parameters->data.shareKeyId++;
    }
    BSL_UIO_SctpAuthKey key = { 0 };
    key.shareKeyId = parameters->data.shareKeyId;
    key.authKey = parg;
    key.authKeySize = larg;

    int32_t ret = parameters->method.uioCtrl(uio, BSL_UIO_SCTP_ADD_AUTH_SHARED_KEY, (int32_t)sizeof(key), &key);
    if (ret != BSL_SUCCESS) {
        parameters->data.shareKeyId = prevShareKeyId;
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "add auth key failed", 0, 0, 0, 0);
        return BSL_UIO_IO_EXCEPTION;
    }
    parameters->data.isAddAuthkey = true;
    parameters->data.prevShareKeyId = prevShareKeyId;
    return BSL_SUCCESS;
}

static int32_t BslSctpActiveAuthKey(BSL_UIO *uio)
{
    SctpParameters *parameters = BSL_UIO_GetCtx(uio);
    if (parameters == NULL || parameters->method.uioCtrl == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (!parameters->data.isAddAuthkey) {
        return BSL_SUCCESS;
    }
    uint16_t shareKeyId = parameters->data.shareKeyId;
    int32_t ret = parameters->method.uioCtrl(uio, BSL_UIO_SCTP_ACTIVE_AUTH_SHARED_KEY,
        (int32_t)sizeof(shareKeyId), &shareKeyId);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05066, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "active auth key failed", 0, 0, 0, 0);
        return BSL_UIO_IO_EXCEPTION;
    }
    parameters->data.isAddAuthkey = false;
    return BSL_SUCCESS;
}

static int32_t BslSctpDelPreAuthKey(BSL_UIO *uio)
{
    SctpParameters *parameters = BSL_UIO_GetCtx(uio);
    if (parameters == NULL || parameters->method.uioCtrl == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    uint16_t delShareKeyId = parameters->data.prevShareKeyId;
    int32_t ret = parameters->method.uioCtrl(uio, BSL_UIO_SCTP_DEL_PRE_AUTH_SHARED_KEY,
        (int32_t)sizeof(delShareKeyId), &delShareKeyId);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05067, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "del pre auth key failed", 0, 0, 0, 0);
        return BSL_UIO_IO_EXCEPTION;
    }
    return BSL_SUCCESS;
}

static int32_t BslSctpIsSndBuffEmpty(BSL_UIO *uio, void *parg, int32_t larg)
{
    SctpParameters *parameters = BSL_UIO_GetCtx(uio);
    if (parameters == NULL || parameters->method.uioCtrl == NULL || parg == NULL || larg != sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    uint8_t isEmpty = 0;
    if (parameters->method.uioCtrl(uio, BSL_UIO_SCTP_SND_BUFF_IS_EMPTY,
        (int32_t)sizeof(uint8_t), &isEmpty) != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05068, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get sctp status failed", 0, 0, 0, 0);
        return BSL_UIO_IO_EXCEPTION;
    }
    *(bool *)parg = (isEmpty > 0);
    return BSL_SUCCESS;
}

static int32_t BslSctpGetSendStreamId(const SctpParameters *parameters, void *parg, int32_t larg)
{
    if (larg != (int32_t)sizeof(uint16_t) || parg == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05046, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Sctp input err.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    uint16_t *sendStreamId = (uint16_t *)parg;
    if (parameters->isAppMsg) {
        *sendStreamId = parameters->data.sendAppStreamId;
    } else {
        *sendStreamId = 0;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05047, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "Uio: User Get SCTP send StreamId [%hu].", *sendStreamId, 0, 0, 0);
    return BSL_SUCCESS;
}

int32_t BslSctpSetAppStreamId(SctpParameters *parameters, const void *parg, int32_t larg)
{
    if (larg != (int32_t)sizeof(uint16_t) || parg == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05048, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Sctp input err.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    parameters->data.sendAppStreamId = *(const uint16_t *)parg;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05055, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "Uio: User set SCTP AppStreamId [%hu].", parameters->data.sendAppStreamId, 0, 0, 0);
    return BSL_SUCCESS;
}

static int32_t BslSctpSetPeerIpAddr(SctpParameters *parameters, const uint8_t *addr, int32_t size)
{
    if (addr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05049, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: NULL error.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (size != IP_ADDR_V4_LEN && size != IP_ADDR_V6_LEN) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05050, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Set peer ip address input error.", 0, 0, 0, 0);
        return BSL_UIO_FAIL;
    }

    (void)memcpy_s(parameters->ip, sizeof(parameters->ip), addr, size);
    parameters->ipLen = (uint32_t)size;
    return BSL_SUCCESS;
}

static int32_t BslSctpGetPeerIpAddr(SctpParameters *parameters, void *parg, int32_t larg)
{
    BSL_UIO_CtrlGetPeerIpAddrParam *para = (BSL_UIO_CtrlGetPeerIpAddrParam *)parg;
    if (parg == NULL || larg != (int32_t)sizeof(BSL_UIO_CtrlGetPeerIpAddrParam) ||
        para->addr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05051, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Get peer ip address input error.", 0, 0, 0, 0);
        return BSL_NULL_INPUT;
    }

    /* Check whether the IP address is set. */
    if (parameters->ipLen == 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05052, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Ip address is already existed.", 0, 0, 0, 0);
        return BSL_UIO_FAIL;
    }

    if (para->size < parameters->ipLen) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05053, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Ip address length err.", 0, 0, 0, 0);
        return BSL_UIO_FAIL;
    }

    (void)memcpy_s(para->addr, para->size, parameters->ip, parameters->ipLen);
    para->size = parameters->ipLen;
    return BSL_SUCCESS;
}

static int32_t BslSctpSetFd(BSL_UIO *uio, void *parg, int32_t larg)
{
    if (larg != (int32_t)sizeof(int32_t) || parg == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    int32_t *fd = (int32_t *)parg;
    SctpParameters *parameters = BSL_UIO_GetCtx(uio);
    if (parameters->fd != -1) {
        if (BSL_UIO_GetIsUnderlyingClosedByUio(uio)) {
            (void)BSL_SAL_SockClose(parameters->fd);
        }
    }
    parameters->fd = *fd;
    uio->init = true;
    return BSL_SUCCESS;
}

static int32_t BslSctpGetFd(SctpParameters *parameters, void *parg, int32_t larg)
{
    if (larg != (int32_t)sizeof(int32_t) || parg == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05054, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get fd handle invalid parameter.", 0, 0, 0, 0);
        return BSL_INVALID_ARG;
    }
    *(int32_t *)parg = parameters->fd;
    return BSL_SUCCESS;
}

static int32_t BslSctpMaskAppMsg(SctpParameters *parameters, void *parg, int32_t larg)
{
    if (parg == NULL || larg != sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05030, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "mask app msg failed", 0, 0, 0, 0);
        return BSL_INVALID_ARG;
    }
    parameters->isAppMsg = *(bool *)parg;
    return BSL_SUCCESS;
}

static int32_t BslSctpSetCtxCb(SctpParameters *parameters, int32_t type, void *func)
{
    if (parameters == NULL || func == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    switch (type) {
        case BSL_UIO_WRITE_CB:
            parameters->method.uioWrite = func;
            break;
        case BSL_UIO_READ_CB:
            parameters->method.uioRead = func;
            break;
        case BSL_UIO_CTRL_CB:
            parameters->method.uioCtrl = func;
            break;
        default:
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return BSL_INVALID_ARG;
    }
    return BSL_SUCCESS;
}

int32_t BslSctpCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    if (uio->ctx == NULL) {
        return BSL_NULL_INPUT;
    }
    SctpParameters *parameters = BSL_UIO_GetCtx(uio);
    switch (cmd) {
        case BSL_UIO_SET_PEER_IP_ADDR:
            return BslSctpSetPeerIpAddr(parameters, parg, larg);
        case BSL_UIO_GET_PEER_IP_ADDR:
            return BslSctpGetPeerIpAddr(parameters, parg, larg);
        case BSL_UIO_SET_FD:
            return BslSctpSetFd(uio, parg, larg);
        case BSL_UIO_GET_FD:
            return BslSctpGetFd(parameters, parg, larg);
        case BSL_UIO_SCTP_GET_SEND_STREAM_ID:
            return BslSctpGetSendStreamId(parameters, parg, larg);
        case BSL_UIO_SCTP_SET_APP_STREAM_ID:
            return BslSctpSetAppStreamId(parameters, parg, larg);
        case BSL_UIO_SCTP_ADD_AUTH_SHARED_KEY:
            if (larg < 0 || larg > UINT16_MAX) {
                break;
            }
            return BslSctpAddAuthKey(uio, parg, larg);
        case BSL_UIO_SCTP_ACTIVE_AUTH_SHARED_KEY:
            return BslSctpActiveAuthKey(uio);
        case BSL_UIO_SCTP_DEL_PRE_AUTH_SHARED_KEY:
            return BslSctpDelPreAuthKey(uio);
        case BSL_UIO_SCTP_MASK_APP_MESSAGE:
            return BslSctpMaskAppMsg(parameters, parg, larg);
        case BSL_UIO_SCTP_SND_BUFF_IS_EMPTY:
            return BslSctpIsSndBuffEmpty(uio, parg, larg);
        case BSL_UIO_SCTP_SET_CALLBACK:
            return BslSctpSetCtxCb(parameters, larg, parg);
        case BSL_UIO_FLUSH:
            return BSL_SUCCESS;
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05069, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "invalid args", 0, 0, 0, 0);
    return BSL_INVALID_ARG;
}

const BSL_UIO_Method *BSL_UIO_SctpMethod(void)
{
    static const BSL_UIO_Method method = {
        BSL_UIO_SCTP,
        BslSctpWrite,
        BslSctpRead,
        BslSctpCtrl,
        NULL,
        NULL,
        BslSctpNew,
        BslSctpDestroy
    };
    return &method;
}
#endif /* HITLS_BSL_UIO_SCTP */
