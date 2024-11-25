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
#ifdef HITLS_BSL_UIO_UDP

#include <unistd.h>
#include <errno.h>
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

typedef struct {
    bool connected;
    uint8_t reverse[3];

    int32_t fd; // Network socket
    struct sockaddr_in peer;
    uint32_t addrLen;
} UdpParameters;

static int32_t UdpNew(BSL_UIO *uio)
{
    UdpParameters *parameters = (UdpParameters *)BSL_SAL_Calloc(1u, sizeof(UdpParameters));
    if (parameters == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05031, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "Uio: sctp param malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    parameters->fd = -1;
    uio->ctx = parameters;
    uio->ctxLen = sizeof(UdpParameters);
    // Specifies whether to be closed by uio when setting fd.
    // The default value of init is 0. Set the value of init to 1 after the fd is set.
    return BSL_SUCCESS;
}

static int32_t UdpDestroy(BSL_UIO *uio)
{
    if (uio == NULL) {
        return BSL_SUCCESS;
    }
    UdpParameters *ctx = BSL_UIO_GetCtx(uio);
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

static int32_t BslUdpGetPeer(UdpParameters *parameters, const struct sockaddr_in *addr, uint32_t size)
{
    if (addr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05049, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Uio: NULL error.", 0, 0, 0,
                              0);
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (size != sizeof(struct sockaddr_in)) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05050, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "Uio: Set peer ip address input error.", 0, 0, 0, 0);
        return BSL_UIO_FAIL;
    }

    (void)memcpy_s(&parameters->peer, sizeof(parameters->peer), addr, size);
    parameters->addrLen = size;
    return BSL_SUCCESS;
}

static int32_t BslUdpSetPeer(UdpParameters *parameters, const struct sockaddr_in *addr, uint32_t size)
{
    if (addr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05049, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Uio: NULL error.", 0, 0, 0,
                              0);
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (size != IP_ADDR_V4_LEN && size != IP_ADDR_V6_LEN) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05050, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "Uio: Set peer ip address input error.", 0, 0, 0, 0);
        return BSL_UIO_FAIL;
    }

    (void)memcpy_s(&parameters->peer, sizeof(parameters->peer), addr, size);
    parameters->addrLen = size;
    return BSL_SUCCESS;
}

static int32_t BslUdpSetFd(BSL_UIO *uio, int32_t size, const int32_t *fd)
{
    if (fd == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(*fd)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    UdpParameters *udpCtx = BSL_UIO_GetCtx(uio);
    if (udpCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (udpCtx->fd != -1) {
        if (BSL_UIO_GetIsUnderlyingClosedByUio(uio)) {
            (void)BSL_SAL_SockClose(udpCtx->fd);
        }
    }
    udpCtx->fd = *fd;
    uio->init = 1;
    return BSL_SUCCESS;
}

static int32_t BslUdpGetFd(UdpParameters *parameters, void *parg, int32_t larg)
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

int32_t UdpCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    if (uio->ctx == NULL) {
        return BSL_NULL_INPUT;
    }
    UdpParameters *parameters = BSL_UIO_GetCtx(uio);
    socklen_t sz = sizeof(struct timeval);
    switch (cmd) {
        case BSL_UIO_FLUSH:
            return BSL_SUCCESS;
        case BSL_UIO_SET_FD:
            return BslUdpSetFd(uio, larg, parg);
        case BSL_UIO_GET_FD:
            return BslUdpGetFd(parameters, parg, larg);
        case BSL_UIO_DGRAM_SET_PEER:
            parameters->connected = 1;
            return BslUdpSetPeer(parameters, parg, (uint32_t)larg);
        case BSL_UIO_DGRAM_GET_PEER:
            return BslUdpGetPeer(parameters, parg, larg);
        case BSL_UIO_DGRAM_SET_RECV_TIMEOUT:
            if ((setsockopt(parameters->fd, SOL_SOCKET, SO_RCVTIMEO, parg, sizeof(struct timeval))) < 0) {
                return BSL_UIO_FAIL;
            }
            return BSL_SUCCESS;
        case BSL_UIO_DGRAM_GET_RECV_TIMEOUT:
            if ((getsockopt(parameters->fd, SOL_SOCKET, SO_RCVTIMEO, parg, &sz)) < 0) {
                return BSL_UIO_FAIL;
            }
            return BSL_SUCCESS;
        case BSL_UIO_DGRAM_SET_SEND_TIMEOUT:
            if ((setsockopt(parameters->fd, SOL_SOCKET, SO_SNDTIMEO, parg, sizeof(struct timeval))) < 0) {
                return BSL_UIO_FAIL;
            }
            return BSL_SUCCESS;
        case BSL_UIO_DGRAM_GET_SEND_TIMEOUT:
            if ((getsockopt(parameters->fd, SOL_SOCKET, SO_SNDTIMEO, parg, &sz)) < 0) {
                return BSL_UIO_FAIL;
            }
            return BSL_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
    }
}

static int32_t UdpWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    UdpParameters *parameters = (UdpParameters *)BSL_UIO_GetCtx(uio);
    int32_t ret = 0;
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    if (parameters->connected) {
        ret = write(fd, buf, len);
    } else {
        ret = sendto(fd, buf, len, 0, (const struct sockaddr *)&parameters->peer, len);
    }

    if (ret <= 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    if (ret > 0) {
        *writeLen = (uint32_t)ret;
        return BSL_SUCCESS;
    }

    if (UioIsNonFatalErr(errno)) { // Indicates the errno for determining whether retry is allowed.
        (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_WRITE | BSL_UIO_FLAGS_SHOULD_RETRY);
        return BSL_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
    return BSL_UIO_IO_EXCEPTION;
}

static int32_t UdpRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    *readLen = 0;

    int32_t ret = 0;
    UdpParameters *parameters = BSL_UIO_GetCtx(uio);
    if (parameters == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    struct sockaddr_in recvAddr;
    int32_t fd = BSL_UIO_GetFd(uio);
    uint32_t addrlen = sizeof(struct sockaddr_in);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }

    ret = recvfrom(fd, buf, len, 0, (struct sockaddr *)&recvAddr, &addrlen);
    if (ret <= 0) {
        if (UioIsNonFatalErr(errno) == true) {
            return BSL_SUCCESS;
        }
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    if (!parameters->connected) {
        UdpCtrl(uio, BSL_UIO_DGRAM_SET_PEER, 0, &recvAddr);
    }

    *readLen = ret;
    return BSL_SUCCESS;
}

const BSL_UIO_Method *BSL_UIO_UdpMethod(void)
{
    static const BSL_UIO_Method method = {
        BSL_UIO_UDP,
        UdpWrite,
        UdpRead,
        UdpCtrl,
        NULL,
        NULL,
        UdpNew,
        UdpDestroy
    };
    return &method;
}
#endif /* HITLS_BSL_UIO_UDP */
