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

#include <unistd.h>
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

#define SCTP_DATA_CHUNK_TYPE 0x00
#define SCTP_FORWARD_TSN_CHUNK_TYPE 0xc0
#define SCTP_GAUTH_CHUNKS_SIZE 256u
#define SCTP_SHARED_AUTHKEY_LEN 64u
#define SCTP_SHARE_AUTHKEY_ID_MAX 65535

typedef struct {
    bool peerAuthed;                /* Whether auth is enabled at the peer end */
    /* Whether authkey is added: If authkey is added but not active, success is returned when authkey is added again. */
    bool isAddAuthkey;
    bool reverse[2];                /* Four-byte alignment is reserved. */

    uint16_t sendAppStreamId;       /* ID of the stream sent by the user-specified app. */
    uint16_t prevShareKeyId;
    uint16_t shareKeyId;
    uint16_t reverse1;              /* Four-byte alignment is reserved. */

    int32_t fd;                 // Network socket
    uint8_t ip[IP_ADDR_MAX_LEN];
    uint32_t ipLen;
    bool isAppMsg;              // whether the message sent is the app message
} SctpParameters;

static int32_t SctpNew(BSL_UIO *uio)
{
    SctpParameters *parameters = (SctpParameters *)BSL_SAL_Calloc(1u, sizeof(SctpParameters));
    if (parameters == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05031, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: sctp param malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    parameters->fd = -1;
    uio->ctx = parameters;
    uio->ctxLen = sizeof(SctpParameters);
    // Specifies whether to be closed by uio when setting fd.
    // The default value of init is 0. Set the value of init to 1 after the fd is set.
    return BSL_SUCCESS;
}

static int32_t SctpDestroy(BSL_UIO *uio)
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

static int32_t BslSctpGetSendStreamId(const BSL_UIO *uio, void *parg, int32_t larg)
{
    SctpParameters *parameters = uio->ctx;
    if (larg != (int32_t)sizeof(uint16_t) || parg == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05046, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Sctp input err.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    uint16_t *sendStreamId = (uint16_t *)parg;
    if (parameters->isAppMsg) {
        *sendStreamId = parameters->sendAppStreamId;
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
    parameters->sendAppStreamId = *(const uint16_t *)parg;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05055, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "Uio: User set SCTP AppStreamId [%hu].", parameters->sendAppStreamId, 0, 0, 0);
    return BSL_SUCCESS;
}

static int32_t BslSctpSetPeerIpAddr(SctpParameters *parameters, const uint8_t *addr, uint32_t size)
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
    parameters->ipLen = size;
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

static int32_t BslSctpSetFd(BSL_UIO *uio, int32_t size, const int32_t *fd)
{
    if (fd == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(*fd)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    SctpParameters *sctpCtx = BSL_UIO_GetCtx(uio);
    if (sctpCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (sctpCtx->fd != -1) {
        if (BSL_UIO_GetIsUnderlyingClosedByUio(uio)) {
            (void)BSL_SAL_SockClose(sctpCtx->fd);
        }
    }
    sctpCtx->fd = *fd;
    uio->init = 1;
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

static bool BslSctpCheckPeerAuth(BSL_UIO *uio, void *parg, int32_t larg)
{
    if (parg == NULL || larg != sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05061, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "check peer auth failed", 0, 0, 0, 0);
        return BSL_INVALID_ARG;
    }
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }

    int32_t optLen = (int32_t)sizeof(struct sctp_authchunks) + SCTP_GAUTH_CHUNKS_SIZE;
    struct sctp_authchunks *auth = (struct sctp_authchunks*)BSL_SAL_Calloc(1u, optLen);
    if (auth == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = BSL_SAL_GetSockopt(fd, IPPROTO_SCTP, SCTP_PEER_AUTH_CHUNKS, auth, &optLen);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(auth);
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_NET_GETSOCKOPT);
        return BSL_SAL_ERR_NET_GETSOCKOPT;
    }
    bool dataChunkFlag = false;
    bool forwardTsnChunkFlag = false;
    for (uint32_t i = 0; i < auth->gauth_number_of_chunks; i++) {
        if (auth->gauth_chunks[i] == SCTP_DATA_CHUNK_TYPE) {
            dataChunkFlag = true;
        } else if (auth->gauth_chunks[i] == SCTP_FORWARD_TSN_CHUNK_TYPE) {
            forwardTsnChunkFlag = true;
        }
    }
    if (dataChunkFlag && forwardTsnChunkFlag) {
        *(bool *)parg = true;
    }
    BSL_SAL_Free(auth);
    return BSL_SUCCESS;
}

static int32_t AddAuthKey(BSL_UIO *uio, SctpParameters *parameters, struct sctp_authkey *auth, socklen_t optLen,
    uint16_t prevShareKeyId)
{
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        parameters->shareKeyId = prevShareKeyId;
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    int32_t ret = BSL_SAL_SetSockopt(fd, IPPROTO_SCTP, SCTP_AUTH_KEY, auth, optLen);
    if (ret != BSL_SUCCESS) {
        parameters->shareKeyId = prevShareKeyId;
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_NET_SETSOCKOPT);
        return BSL_SAL_ERR_NET_SETSOCKOPT;
    }
    parameters->isAddAuthkey = true;
    parameters->prevShareKeyId = prevShareKeyId;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05035, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "Uio: SCTP Set auth key(id:%u) success.", parameters->shareKeyId, 0, 0, 0);
    return BSL_SUCCESS;
}

static int32_t BslSctpAddAuthKey(BSL_UIO *uio, void *parg, int32_t larg)
{
    if (parg == NULL || larg != sizeof(BSL_UIO_SctpAuthKey)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05062, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "add auth key failed", 0, 0, 0, 0);
        return BSL_INVALID_ARG;
    }
    BSL_UIO_SctpAuthKey *key = (BSL_UIO_SctpAuthKey *)parg;
    SctpParameters *parameters = (SctpParameters *)BSL_UIO_GetCtx(uio);

    if (parameters->isAddAuthkey) {
        return BSL_SUCCESS;
    }

    uint16_t prevShareKeyId = parameters->shareKeyId;
    if (parameters->shareKeyId >= SCTP_SHARE_AUTHKEY_ID_MAX) {
        parameters->shareKeyId = 1;
    } else {
        parameters->shareKeyId++;
    }
    key->shareKeyId = parameters->shareKeyId;
    const uint8_t *authKey = key->authKey;
    uint16_t size = key->authKeySize;
    if (size != SCTP_SHARED_AUTHKEY_LEN) {
        parameters->shareKeyId = prevShareKeyId;
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    socklen_t optLen = sizeof(struct sctp_authkey) + SCTP_SHARED_AUTHKEY_LEN * sizeof(uint8_t);
    struct sctp_authkey *auth = (struct sctp_authkey *)BSL_SAL_Calloc(1u, optLen);
    if (auth == NULL) {
        parameters->shareKeyId = prevShareKeyId;
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    auth->sca_keylength = SCTP_SHARED_AUTHKEY_LEN;
    auth->sca_keynumber = key->shareKeyId;
    (void)memcpy_s(&auth->sca_key[0], SCTP_SHARED_AUTHKEY_LEN, authKey, size);
    int32_t ret = AddAuthKey(uio, parameters, auth, optLen, prevShareKeyId);
    BSL_SAL_Free(auth);
    return ret;
}

static int32_t CheckArgsAvalid(const void *parg, int32_t larg)
{
    if (parg == NULL || larg != sizeof(uint16_t)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05063, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid args", 0, 0, 0, 0);
        return BSL_INVALID_ARG;
    }
    return BSL_SUCCESS;
}

static int32_t BslSctpActiveAuthKey(BSL_UIO *uio, void *parg, int32_t larg)
{
    int32_t ret = CheckArgsAvalid(parg, larg);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    SctpParameters *parameters = BSL_UIO_GetCtx(uio);
    uint16_t shareKeyId = *(uint16_t*)parg;
    /* Active shared key id */
    struct sctp_authkeyid authKeyId = {0};
    authKeyId.scact_keynumber = shareKeyId;
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    ret = BSL_SAL_SetSockopt(fd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY, &authKeyId, sizeof(struct sctp_authkeyid));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_NET_SETSOCKOPT);
        return BSL_SAL_ERR_NET_SETSOCKOPT;
    }
    parameters->isAddAuthkey = false;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05038, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "Uio: SCTP active auth key(id:%u) success.", parameters->shareKeyId, 0, 0, 0);

    return BSL_SUCCESS;
}

static int32_t BslSctpDelAuthKey(BSL_UIO *uio, void *parg, int32_t larg)
{
    int32_t ret = CheckArgsAvalid(parg, larg);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    uint16_t delShareKeyId = *(uint16_t*)parg;
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    /* Delete old sharekey */
    struct sctp_authkeyid authKeyId = {0};
    authKeyId.scact_keynumber = delShareKeyId;
    ret = BSL_SAL_SetSockopt(fd, IPPROTO_SCTP, SCTP_AUTH_DELETE_KEY, &authKeyId, sizeof(struct sctp_authkeyid));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_NET_SETSOCKOPT);
        return BSL_SAL_ERR_NET_SETSOCKOPT;
    }
    return BSL_SUCCESS;
}

static int32_t BslSctpIsSndBuffEmpty(BSL_UIO *uio, void *parg, int32_t larg)
{
    if (parg == NULL || larg != sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05064, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get sctp status failed", 0, 0, 0, 0);
        return BSL_INVALID_ARG;
    }

    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }

    struct sctp_status status = {0};
    int32_t statusLen = sizeof(status);
    int32_t ret = BSL_SAL_GetSockopt(fd, IPPROTO_SCTP, SCTP_STATUS, &status, &statusLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_NET_GETSOCKOPT);
        return BSL_SAL_ERR_NET_GETSOCKOPT;
    }

    uint8_t *isEmpty = (uint8_t *)parg;
    *isEmpty = false;

    if (status.sstat_unackdata == 0) {
        *isEmpty = true;
    }

    return BSL_SUCCESS;
}

int32_t SctpCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    if (uio->ctx == NULL) {
        return BSL_NULL_INPUT;
    }
    SctpParameters *parameters = BSL_UIO_GetCtx(uio);
    switch (cmd) {
        case BSL_UIO_SET_PEER_IP_ADDR:
            return BslSctpSetPeerIpAddr(parameters, parg, (uint32_t)larg);
        case BSL_UIO_GET_PEER_IP_ADDR:
            return BslSctpGetPeerIpAddr(parameters, parg, larg);
        case BSL_UIO_SCTP_GET_SEND_STREAM_ID:
            return BslSctpGetSendStreamId(uio, parg, larg);
        case BSL_UIO_SCTP_SET_APP_STREAM_ID:
            return BslSctpSetAppStreamId(parameters, parg, larg);
        case BSL_UIO_SET_FD:
            return BslSctpSetFd(uio, larg, parg);
        case BSL_UIO_GET_FD:
            return BslSctpGetFd(parameters, parg, larg);
        case BSL_UIO_SCTP_MASK_APP_MESSAGE:
            return BslSctpMaskAppMsg(parameters, parg, larg);
        case BSL_UIO_SCTP_CHECK_PEER_AUTH:
            return BslSctpCheckPeerAuth(uio, parg, larg);
        case BSL_UIO_SCTP_ADD_AUTH_SHARED_KEY:
            return BslSctpAddAuthKey(uio, parg, larg);
        case BSL_UIO_SCTP_ACTIVE_AUTH_SHARED_KEY:
            return BslSctpActiveAuthKey(uio, &parameters->shareKeyId, sizeof(parameters->shareKeyId));
        case BSL_UIO_SCTP_DEL_PRE_AUTH_SHARED_KEY:
            return BslSctpDelAuthKey(uio, &parameters->prevShareKeyId, sizeof(parameters->shareKeyId));
        case BSL_UIO_SCTP_SND_BUFF_IS_EMPTY:
            return BslSctpIsSndBuffEmpty(uio, parg, larg);
        default:
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
    }
}

static int32_t SctpWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    /* set flags */
    const uint32_t flags = SCTP_SACK_IMMEDIATELY;
    uint16_t sendStreamId = 0;
    int32_t ret = BSL_UIO_Ctrl(uio, BSL_UIO_SCTP_GET_SEND_STREAM_ID, sizeof(sendStreamId), &sendStreamId);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    ret = sctp_sendmsg(fd, buf, len, NULL, 0, 0, flags, sendStreamId, 0, 0);
    if (ret <= 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    *writeLen = ret;

    return BSL_SUCCESS;
}

static int32_t SctpRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    *readLen = 0;
    SctpParameters *parameters = BSL_UIO_GetCtx(uio);
    if (parameters == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (BSL_UIO_Ctrl(uio, BSL_UIO_SCTP_CHECK_PEER_AUTH, sizeof(parameters->peerAuthed), &parameters->peerAuthed) !=
        BSL_SUCCESS ||
        parameters->peerAuthed == false) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05032, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio:Check SCTP Peer Auth ERROR.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }

    struct sctp_sndrcvinfo sinfo;
    int32_t flags = 0;
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    int32_t ret = sctp_recvmsg(fd, buf, len, NULL, NULL, &sinfo, &flags);
    if (ret <= 0) {
        if (UioIsNonFatalErr(errno) == true) {
            return BSL_SUCCESS;
        }
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }

    *readLen = ret;
    return BSL_SUCCESS;
}

const BSL_UIO_Method *BSL_UIO_SctpMethod(void)
{
    static const BSL_UIO_Method method = {
        BSL_UIO_SCTP,
        SctpWrite,
        SctpRead,
        SctpCtrl,
        NULL,
        NULL,
        SctpNew,
        SctpDestroy
    };
    return &method;
}
#endif /* HITLS_BSL_UIO_SCTP */
