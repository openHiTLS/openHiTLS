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
#include "uio_abstraction.h"

typedef struct {
    bool connected;
    uint8_t reverse[3];

    int32_t fd; // Network socket
    uint8_t ip[DGRAM_SOCKADDR_MAX_LEN];
    uint32_t ipLen;
} UdpParameters;

static uint32_t Family2Len(const struct sockaddr *addr)
{
    switch (addr->sa_family) {
        case AF_INET:
            return sizeof(struct sockaddr_in);
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
        case AF_UNIX:
            return sizeof(struct sockaddr_un);
        default:
            return BSL_UIO_IO_EXCEPTION;
    }
}

static int32_t UdpNew(BSL_UIO *uio)
{
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

static int32_t BslUdpGetPeerIpAddr(UdpParameters *parameters, void *parg, uint32_t larg)
{
    BSL_UIO_CtrlGetPeerIpAddrParam *para = (BSL_UIO_CtrlGetPeerIpAddrParam *)parg;
    if (parg == NULL || larg != (int32_t)sizeof(BSL_UIO_CtrlGetPeerIpAddrParam) ||
        para->addr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05074, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Get peer ip address input error.", 0, 0, 0, 0);
        return BSL_NULL_INPUT;
    }

    /* Check whether the IP address is set. */
    if (parameters->ipLen == 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05075, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Ip address is already existed.", 0, 0, 0, 0);
        return BSL_UIO_FAIL;
    }

    if (para->size < parameters->ipLen) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05076, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: Ip address length err.", 0, 0, 0, 0);
        return BSL_UIO_FAIL;
    }

    (void)memcpy_s(para->addr, para->size, parameters->ip, parameters->ipLen);
    para->size = parameters->ipLen;
    return BSL_SUCCESS;
}

static int32_t BslUdpSetPeerIpAddr(UdpParameters *parameters, const uint8_t *addr, uint32_t size)
{
    if (addr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05077, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Uio: NULL error.", 0, 0, 0,
                              0);
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (size != SOCK_ADDR_V4_LEN && size != SOCK_ADDR_V6_LEN && size != SOCK_ADDR_UNIX_LEN) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05078, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                              "Uio: Set peer ip address input error.", 0, 0, 0, 0);
        return BSL_UIO_FAIL;
    }

    (void)memcpy_s(&parameters->ip, sizeof(parameters->ip), addr, size);
    parameters->ipLen = size;
    return BSL_SUCCESS;
}

static int32_t ClearPeerIpAddr(UdpParameters *parameters)
{
    memset_s(parameters->ip, DGRAM_SOCKADDR_MAX_LEN, 0, DGRAM_SOCKADDR_MAX_LEN);
    parameters->ipLen = 0;
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
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05079, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
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
    switch (cmd) {
        case BSL_UIO_SET_FD:
            return BslUdpSetFd(uio, larg, parg);
        case BSL_UIO_GET_FD:
            return BslUdpGetFd(parameters, parg, larg);
        case BSL_UIO_FLUSH:
            return BSL_SUCCESS;
        case BSL_UIO_SET_PEER_IP_ADDR:
            return BslUdpSetPeerIpAddr(parameters, parg, (uint32_t)larg);
        case BSL_UIO_GET_PEER_IP_ADDR:
            return BslUdpGetPeerIpAddr(parameters, parg, larg);
        case BSL_UIO_DGRAM_SET_CONNECTED:
            if (parg != NULL) {
                parameters->connected = 1;
                return BslUdpSetPeerIpAddr(parameters, parg, (uint32_t)larg);
            } else {
                parameters->connected = 0;
                return ClearPeerIpAddr(parameters);
            }
        default:
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
    }
}

static int32_t UdpWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    UdpParameters *parameters = (UdpParameters *)BSL_UIO_GetCtx(uio);
    int32_t ret = 0, err = 0;
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    errno = 0;
    if (parameters->connected) {
        ret = BSL_SAL_Write(fd, buf, len, &err);
    } else {
        ret = sendto(fd, buf, len, 0, (const struct sockaddr *)&parameters->ip, parameters->ipLen);
    }

    err = errno;
    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    if (ret > 0) {
        *writeLen = (uint32_t)ret;
        return BSL_SUCCESS;
    }

    if (UioIsNonFatalErr(err)) { // Indicates the errno for determining whether retry is allowed.
        (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_WRITE | BSL_UIO_FLAGS_SHOULD_RETRY);
        return BSL_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
    return BSL_UIO_IO_EXCEPTION;
}

static int32_t UdpRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    *readLen = 0;

    int32_t ret = 0, err = 0;
    errno = 0;
    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);

    uint8_t ip[DGRAM_SOCKADDR_MAX_LEN];
    UdpParameters *parameters = BSL_UIO_GetCtx(uio);
    if (parameters == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    int32_t fd = BSL_UIO_GetFd(uio);
    uint32_t iplen = sizeof(ip);

    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }

    ret = recvfrom(fd, buf, len, 0, (struct sockaddr *)&ip, &iplen);

    err = errno;
    if (ret > 0) {
        *readLen = ret;
        if (!parameters->connected) {
            ret = UdpCtrl(uio, BSL_UIO_SET_PEER_IP_ADDR, Family2Len((const struct sockaddr *)&ip), ip);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
                return BSL_UIO_IO_EXCEPTION;
            }
        }
        return BSL_SUCCESS;
    }

    if (UioIsNonFatalErr(err) == true) {
        (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_READ | BSL_UIO_FLAGS_SHOULD_RETRY);
        return BSL_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
    return BSL_UIO_IO_EXCEPTION;
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
