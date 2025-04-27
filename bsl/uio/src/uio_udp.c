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
#include <sys/socket.h>
#include <sys/un.h>
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
#include "uio_local.h"
#include "uio_abstraction.h"

typedef struct {
    BSL_UIO_Addr peer;
    int32_t fd; // Network socket
    uint32_t connected;
} UdpParameters;

static int32_t UdpNew(BSL_UIO *uio)
{
    if (uio->ctx != NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05056, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: ctx is already existed.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    UdpParameters *parameters = (UdpParameters *)BSL_SAL_Calloc(1u, sizeof(UdpParameters));
    if (parameters == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05073, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "Uio: udp param malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    parameters->fd = -1;
    uio->ctx = parameters;
    uio->ctxLen = sizeof(UdpParameters);
    parameters->connected = 0;
    // Specifies whether to be closed by uio when setting fd.
    // The default value of init is 0. Set the value of init to 1 after the fd is set.
    return BSL_SUCCESS;
}

static int32_t UdpSocketDestroy(BSL_UIO *uio)
{
    if (uio == NULL) {
        return BSL_SUCCESS;
    }
    UdpParameters *ctx = BSL_UIO_GetCtx(uio);
    if (ctx != NULL) {
        if (BSL_UIO_GetIsUnderlyingClosedByUio(uio) && ctx->fd != -1) {
            (void)BSL_SAL_SockClose(ctx->fd);
        }
        BSL_SAL_FREE(ctx);
        BSL_UIO_SetCtx(uio, NULL);
    }
    uio->init = false;
    return BSL_SUCCESS;
}

static int32_t UdpGetPeerIpAddr(UdpParameters *parameters, int32_t larg,  uint8_t *parg)
{
    if (parameters == NULL || parg == NULL || larg < (int32_t)sizeof(BSL_UIO_Addr)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05074, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Get peer ip address input error.", 0, 0, 0, 0);
        return BSL_NULL_INPUT;
    }
    if (memcpy_s(parg, sizeof(BSL_UIO_Addr), &parameters->peer, BSL_UIO_SockAddrSize(&parameters->peer)) != EOK) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    return BSL_SUCCESS;
}

static int32_t UdpSetPeerIpAddr(UdpParameters *parameters, const uint8_t *addr, uint32_t size)
{
    if (parameters == NULL || addr == NULL || size < (int32_t)sizeof(struct sockaddr)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05073, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: NULL error.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    int32_t ret = BSL_UIO_AddrMake(&parameters->peer, (const struct sockaddr *)addr);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    return BSL_SUCCESS;
}

static int32_t UdpSetFd(BSL_UIO *uio, int32_t size, const int32_t *fd)
{
    if (fd == NULL || uio == NULL) {
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
    uio->init = true;
    return BSL_SUCCESS;
}

static int32_t UdpGetFd(BSL_UIO *uio, int32_t size, int32_t *fd)
{
    if (uio == NULL || fd == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(*fd)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    UdpParameters *ctx = BSL_UIO_GetCtx(uio);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    *fd = ctx->fd;
    return BSL_SUCCESS;
}

int32_t UdpSocketCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    if (uio == NULL || uio->ctx == NULL) {
        return BSL_NULL_INPUT;
    }
    UdpParameters *parameters = BSL_UIO_GetCtx(uio);
    switch (cmd) {
        case BSL_UIO_SET_FD:
            return UdpSetFd(uio, larg, parg);
        case BSL_UIO_GET_FD:
            return UdpGetFd(uio, larg, parg);
        case BSL_UIO_SET_PEER_IP_ADDR:
            return UdpSetPeerIpAddr(parameters, parg, (uint32_t)larg);
        case BSL_UIO_GET_PEER_IP_ADDR:
            return UdpGetPeerIpAddr(parameters, larg, parg);
        case BSL_UIO_UDP_SET_CONNECTED:
            if (parg != NULL) {
                parameters->connected = 1;
                return UdpSetPeerIpAddr(parameters, parg, (uint32_t)larg);
            } else {
                parameters->connected = 0;
                return BSL_SUCCESS;
            }
        case BSL_UIO_FLUSH:
            return BSL_SUCCESS;
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    return BSL_UIO_FAIL;
}

static int32_t UdpWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    UdpParameters *parameters = (UdpParameters *)BSL_UIO_GetCtx(uio);
    int32_t ret = 0, err = 0;
    BSL_UIO_Addr peerAddr = {0};
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    errno = 0;
    if (parameters->connected) {
        ret = BSL_SAL_Write(fd, buf, len, &err);
    } else {
        ret = BSL_UIO_Ctrl(uio, BSL_UIO_GET_PEER_IP_ADDR, sizeof(peerAddr), &peerAddr);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
        }
        ret = sendto(fd, buf, len, 0, (struct sockaddr *)&peerAddr.addrIn, sizeof(peerAddr.addrIn));
    }
    err = errno;
    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    if (ret > 0) {
        *writeLen = (uint32_t)ret;
        return BSL_SUCCESS;
    }

    if (ret != 0 && UioIsNonFatalErr(err)) { // Indicates the errno for determining whether retry is allowed.
        (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_WRITE | BSL_UIO_FLAGS_SHOULD_RETRY);
        return BSL_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
    return BSL_UIO_IO_EXCEPTION;
}

static int32_t UdpRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    *readLen = 0;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in sockAddr;
    int32_t ret = 0, err = 0;
    int32_t fd = BSL_UIO_GetFd(uio);
    UdpParameters *parameters = BSL_UIO_GetCtx(uio);
    if (fd < 0 || parameters == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }

    errno = 0;
    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    ret = recvfrom(fd, buf, len, 0, (struct sockaddr *)&sockAddr, &addrlen);
    err = errno;
    if (ret < 0) {
        if (UioIsNonFatalErr(err) == true) {
            (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_READ | BSL_UIO_FLAGS_SHOULD_RETRY);
            return BSL_SUCCESS;
        }
        /* Fatal error */
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    } else if (ret == 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    *readLen = (uint32_t)ret;
    if (parameters->connected == 0) {
        ret = UdpSocketCtrl(uio, BSL_UIO_SET_PEER_IP_ADDR, sizeof(sockAddr), &sockAddr);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
            return BSL_UIO_IO_EXCEPTION;
        }
    }
    return BSL_SUCCESS;
}

const BSL_UIO_Method *BSL_UIO_UdpMethod(void)
{
    static const BSL_UIO_Method method = {
        BSL_UIO_UDP,
        UdpWrite,
        UdpRead,
        UdpSocketCtrl,
        NULL,
        NULL,
        UdpNew,
        UdpSocketDestroy
    };
    return &method;
}
#endif /* HITLS_BSL_UIO_UDP */
