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

#include "securec.h"
#include "bsl_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "sal_net.h"
#include "uio_base.h"
#include "uio_abstraction.h"

#define IPV4_WITH_UDP_HEADER_LEN 28                     /* IPv4 protocol header 20 + UDP header 8 */
#define IPV6_WITH_UDP_HEADER_LEN 48                     /* IPv6 protocol header 40 + UDP header 8 */

typedef struct {
    BSL_SAL_SockAddr peer;
    int32_t fd; // Network socket
    uint32_t isConnected;
    int32_t sysErrno;
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
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05057, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "Uio: udp param malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    int32_t ret = SAL_SockAddrNew(&(parameters->peer));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(parameters);
        return ret;
    }
    parameters->fd = -1;
    parameters->isConnected = 0;

    uio->ctx = parameters;
    uio->ctxLen = sizeof(UdpParameters);
    // Specifies whether to be closed by uio when setting fd.
    // The default value of init is 0. Set the value of init to 1 after the fd is set.
    return BSL_SUCCESS;
}

static int32_t UdpSocketWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    int32_t err = 0;
    int32_t fd = BSL_UIO_GetFd(uio);
    UdpParameters *ctx = (UdpParameters *)BSL_UIO_GetCtx(uio);
    if (ctx == NULL || fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    ctx->sysErrno = 0;
    uint32_t peerAddrSize = SAL_SockAddrSize(ctx->peer);
    int32_t sendBytes = 0;
    if (ctx->isConnected == 1) {
        sendBytes = SAL_Write(fd, buf, len, &err);
    } else {
        sendBytes = SAL_Sendto(fd, buf, len, 0, ctx->peer, peerAddrSize, &err);
    }

    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    if (sendBytes < 0) {
        /* None-fatal error */
        if (UioIsNonFatalErr(err)) {
            (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_WRITE | BSL_UIO_FLAGS_SHOULD_RETRY);
            ctx->sysErrno = err;
            return BSL_SUCCESS;
        }
        /* Fatal error */
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }

    *writeLen = (uint32_t)sendBytes;
    return BSL_SUCCESS;
}

static int32_t UdpSocketRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    *readLen = 0;
    int32_t err = 0;
    int32_t fd = BSL_UIO_GetFd(uio);
    UdpParameters *ctx = BSL_UIO_GetCtx(uio);
    if (ctx == NULL || fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    int32_t addrlen = (int32_t)SAL_SockAddrSize(ctx->peer);
    int32_t ret = SAL_Recvfrom(fd, buf, len, 0, ctx->peer, &addrlen, &err);
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
        SAL_SockAddrFree(ctx->peer);
        BSL_SAL_Free(ctx);
        BSL_UIO_SetCtx(uio, NULL);
    }
    uio->init = false;
    return BSL_SUCCESS;
}

static int32_t UdpSetPeerIpAddr(UdpParameters *parameters, uint32_t size, const uint8_t *addr)
{
    uint32_t uniAddrSize = SAL_SockAddrSize(parameters->peer);
    if (addr == NULL || uniAddrSize == 0 || size > uniAddrSize) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05073, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: NULL error.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    SAL_SockAddrCopy(parameters->peer, (BSL_SAL_SockAddr)(uintptr_t)addr);
    return BSL_SUCCESS;
}

static int32_t UdpGetPeerIpAddr(UdpParameters *parameters, int32_t larg, uint8_t *parg)
{
    uint32_t uniAddrSize = SAL_SockAddrSize(parameters->peer);
    if (parg == NULL || (uint32_t)larg < uniAddrSize) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05074, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Get peer ip address input error.", 0, 0, 0, 0);
        return BSL_NULL_INPUT;
    }
    SAL_SockAddrCopy(parg, parameters->peer);
    return BSL_SUCCESS;
}

static int32_t UdpSetFd(BSL_UIO *uio, int32_t size, const int32_t *fd)
{
    if (fd == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(*fd)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    UdpParameters *ctx = BSL_UIO_GetCtx(uio); // ctx is not NULL
    if (ctx->fd != -1) {
        if (BSL_UIO_GetIsUnderlyingClosedByUio(uio)) {
            (void)BSL_SAL_SockClose(ctx->fd);
        }
    }
    ctx->fd = *fd;
    uio->init = true;
    return BSL_SUCCESS;
}

static int32_t UdpGetMtuOverhead(UdpParameters *parameters, int32_t size, uint8_t *overhead)
{
    if (overhead == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (size != (int32_t)sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    switch (SAL_SockAddrGetFamily(parameters->peer)) {
        case SAL_IPV4:
            /* 20 for ipv4, 8 for udp */
            *overhead = IPV4_WITH_UDP_HEADER_LEN;
            break;
        case SAL_IPV6:
            *overhead = IPV6_WITH_UDP_HEADER_LEN;
            break;
        default:
            *overhead = IPV4_WITH_UDP_HEADER_LEN;
            break;
    }

    return BSL_SUCCESS;
}

static int32_t UdpQueryMtu(UdpParameters *parameters, int32_t size, uint32_t *mtu)
{
    if (mtu == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (size != (int32_t)sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    int32_t socketVal = 0;
    int32_t socketOptLen = sizeof(socketVal);
    switch (SAL_SockAddrGetFamily(parameters->peer)) {
        case SAL_IPV4:
            if (BSL_SAL_GetSockopt(parameters->fd, SAL_PROTO_IP_LEVEL, SAL_MTU_OPTION,
                (void *)&socketVal, &socketOptLen) != BSL_SUCCESS || socketVal < IPV4_WITH_UDP_HEADER_LEN) {
                *mtu = 0;
            } else {
                *mtu = (uint32_t)socketVal - IPV4_WITH_UDP_HEADER_LEN;
            }
            break;
        case SAL_IPV6:
            if (BSL_SAL_GetSockopt(parameters->fd, SAL_PROTO_IPV6_LEVEL, SAL_IPV6_MTU_OPTION,
                (void *)&socketVal, &socketOptLen) != BSL_SUCCESS || socketVal < IPV6_WITH_UDP_HEADER_LEN) {
                *mtu = 0;
            } else {
                *mtu = (uint32_t)socketVal - IPV6_WITH_UDP_HEADER_LEN;
            }
            break;
        default:
            *mtu = 0;
            break;
    }

    return BSL_SUCCESS;
}

static int32_t UdpIsMtuExceeded(UdpParameters *parameters, int32_t size, bool *exceeded)
{
    if (exceeded == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (size != (int32_t)sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    (void)parameters;
#ifdef EMSGSIZE
    if (parameters->sysErrno == EMSGSIZE) {
        *exceeded = true;
        parameters->sysErrno = 0;
    } else {
#endif
        *exceeded = false;
#ifdef EMSGSIZE
    }
#endif
    return BSL_SUCCESS;
}

static int32_t UdpGetFd(BSL_UIO *uio, int32_t size, int32_t *fd)
{
    if (fd == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    UdpParameters *ctx = BSL_UIO_GetCtx(uio); // ctx is not NULL
    *fd = ctx->fd;
    return BSL_SUCCESS;
}

int32_t UdpSocketCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    UdpParameters *ctx = BSL_UIO_GetCtx(uio);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    switch (cmd) {
        case BSL_UIO_SET_FD:
            return UdpSetFd(uio, larg, parg);
        case BSL_UIO_GET_FD:
            return UdpGetFd(uio, larg, parg);
        case BSL_UIO_SET_PEER_IP_ADDR:
            return UdpSetPeerIpAddr(ctx, (uint32_t)larg, parg);
        case BSL_UIO_GET_PEER_IP_ADDR:
            return UdpGetPeerIpAddr(ctx, larg, parg);
        case BSL_UIO_UDP_SET_CONNECTED:
            if (parg != NULL) {
                ctx->isConnected = 1;
                return UdpSetPeerIpAddr(ctx, (uint32_t)larg, parg);
            } else {
                ctx->isConnected = 0;
                return BSL_SUCCESS;
            }
        case BSL_UIO_UDP_GET_MTU_OVERHEAD:
            return UdpGetMtuOverhead(ctx, larg, parg);
        case BSL_UIO_UDP_QUERY_MTU:
            return UdpQueryMtu(ctx, larg, parg);
        case BSL_UIO_UDP_MTU_EXCEEDED:
            return UdpIsMtuExceeded(ctx, larg, parg);
        case BSL_UIO_FLUSH:
            return BSL_SUCCESS;
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    return BSL_UIO_FAIL;
}

const BSL_UIO_Method *BSL_UIO_UdpMethod(void)
{
    static const BSL_UIO_Method method = {
        BSL_UIO_UDP,
        UdpSocketWrite,
        UdpSocketRead,
        UdpSocketCtrl,
        NULL,
        NULL,
        UdpNew,
        UdpSocketDestroy
    };
    return &method;
}
#endif /* HITLS_BSL_UIO_UDP */
