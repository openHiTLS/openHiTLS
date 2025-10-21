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
#ifdef HITLS_BSL_UIO_ACCEPT

#include "securec.h"
#include "uio_base.h"
#include "uio_abstraction.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_binlog_id.h"
#include "sal_file.h"
#include "sal_net.h"

#define UIO_ACCEPT_MAX_LISTEN  32

typedef enum {
    UIO_ACCEPT_STATE_BEFORE = 1,
    UIO_ACCEPT_STATE_GET_ADDR = 2,
    UIO_ACCEPT_STATE_CREATE_SOCKET,
    UIO_ACCEPT_STATE_LISTEN,
    UIO_ACCPET_STATE_ACCEPT,
    UIO_ACCEPT_STATE_OK,
} HITLS_AcceptState;

typedef struct {
    HITLS_AcceptState state;         // 当前状态，用于状态机
    int32_t acceptFamily;  // 接受连接的地址族（IPv4、IPv6 或任意）
    int32_t fd;
    int32_t bindMode;      // 绑定模式（阻塞或非阻塞）
    char *paramAddress;   // 主机地址
    char *paramService;   // 端口号
    uint32_t acceptMode;
    BSL_UIO_AddrInfo *addrFirst;   // 地址信息链表的头
    const BSL_UIO_AddrInfo *addrIter;  // 当前迭代位置
    BSL_UIO_Addr cacheAcceptingAddr; // 缓存的接受地址、主机名和端口号。
    char *cacheAcceptingName;
    char *cacheAcceptingServ;
    BSL_UIO_Addr cachePeerAddr; // 缓存的对等地址、主机名和端口号。
    char *cachePeerName;
    char *cachePeerServ;
} UIO_Accept;

static int32_t AcceptSockListen(int32_t fd, const BSL_UIO_Addr *uioAddr, int32_t family, uint32_t options)
{
    const int32_t on = 1;
    if (fd == -1) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    int32_t ret = BSL_SAL_SetBlockMode(fd, (options & BSL_UIO_SOCK_NONBLOCK) == 0);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    if ((options & BSL_UIO_SOCK_KEEPALIVE) != 0) {
        ret = BSL_SAL_SetSockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const void *)&on, sizeof(on));
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }

    if ((options & BSL_UIO_SOCK_NODELAY) != 0) {
        ret = BSL_SAL_SetSockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const void *)&on, sizeof(on));
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }
    if (family == AF_INET6 && (options & BSL_UIO_SOCK_NODELAY) != 0) {
        ret = BSL_SAL_SetSockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&on, sizeof(on));
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }
    if ((options & BSL_UIO_SOCK_REUSEADDR) != 0) {
        ret = BSL_SAL_SetSockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof(on));
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }
    ret = BSL_SAL_SockBind(fd, ((struct sockaddr *)(uintptr_t)&uioAddr->addr), BSL_UIO_SockAddrSize(uioAddr));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_SAL_SockListen(fd, UIO_ACCEPT_MAX_LISTEN);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    return BSL_SUCCESS;
}

static int32_t AcceptStateGetAddr(UIO_Accept *accept)
{
    int32_t family = AF_UNSPEC;
    switch (accept->acceptFamily) {
        case BSL_UIO_FAMILY_IPV6:
            family = AF_INET6;
            break;
        case BSL_UIO_FAMILY_IPV4:
            family = AF_INET;
            break;
        case BSL_UIO_FAMILY_IPANY:
            family = AF_UNSPEC;
            break;
        default:
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
    }
    if (BSL_UIO_LookUp(accept->paramAddress, accept->paramService, BSL_UIO_LOOKUP_SERVER, family, SOCK_STREAM,
        &accept->addrFirst) != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    if (accept->addrFirst == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    accept->addrIter = accept->addrFirst;
    accept->state = UIO_ACCEPT_STATE_CREATE_SOCKET;
    return BSL_SUCCESS;
}

static int32_t AcceptStateCreateSocket(UIO_Accept *accept)
{
    int32_t fd = BSL_SAL_Socket(BSL_UIO_AddrInfoGetFamily(accept->addrIter),
        BSL_UIO_AddrInfoGetSocktype(accept->addrIter), BSL_UIO_AddrInfoGetProtocol(accept->addrIter));
    if (fd < 0) {
        if ((accept->addrIter = BSL_UIO_AddrInfoNext(accept->addrIter)) != NULL) {
            return BSL_SUCCESS;
        }
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    accept->fd = fd;
    accept->state = UIO_ACCEPT_STATE_LISTEN;
    return BSL_SUCCESS;
}


static int32_t AcceptStateListen(UIO_Accept *accept)
{
    const BSL_UIO_Addr *addr = BSL_UIO_AddrInfoGetAddress(accept->addrIter);
    int32_t family = BSL_UIO_AddrInfoGetFamily(accept->addrIter);
    int32_t ret = AcceptSockListen(accept->fd, addr, family, accept->bindMode);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return BSL_UIO_FAIL;
    }

    size_t len = BSL_UIO_SockAddrSize(&accept->cacheAcceptingAddr);
    ret = BSL_SAL_GetSockName(accept->fd, &(accept->cacheAcceptingAddr.addr), &len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return BSL_UIO_FAIL;
    }
    char *host = BSL_UIO_AddrGetHostNameStr(&accept->cacheAcceptingAddr, 1);
    char *service = BSL_UIO_AddrGetServiceStr(&accept->cacheAcceptingAddr, 1);
    if (host != NULL && service != NULL) {
        BSL_SAL_FREE(accept->cacheAcceptingName);
        accept->cacheAcceptingName = host;
        BSL_SAL_FREE(accept->cacheAcceptingServ);
        accept->cacheAcceptingServ = service;
    } else {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        BSL_SAL_FREE(host);
        BSL_SAL_FREE(service);
    }
    accept->state = UIO_ACCPET_STATE_ACCEPT;
    return BSL_SUCCESS;
}

static int32_t AcceptStateAccept(BSL_UIO *uio, UIO_Accept *accept)
{
    if (uio->next != NULL) {
        accept->state = UIO_ACCEPT_STATE_OK;
        return BSL_SUCCESS;
    }
    BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    uio->retryReason = 0;
    size_t len = BSL_UIO_SockAddrSize(&accept->cachePeerAddr);
    int32_t acceptSock = BSL_SAL_SockAccept(accept->fd, &accept->cachePeerAddr.addr, &len);
    if (acceptSock < 0) {
        if (BSL_UIO_SockShouldRetry(acceptSock) == BSL_SUCCESS) {
            (void)BSL_UIO_SetFlags(uio, (BSL_UIO_FLAGS_IO_SPECIAL | BSL_UIO_FLAGS_SHOULD_RETRY));
            uio->retryReason = BSL_UIO_RR_ACCEPT;
        }
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    int ret = BSL_SAL_SetBlockMode(acceptSock, (accept->acceptMode & BSL_UIO_SOCK_NONBLOCK));
    if (ret != BSL_SUCCESS) {
        BSL_SAL_SockClose(acceptSock);
        BSL_ERR_PUSH_ERROR(ret);
        return BSL_UIO_FAIL;
    }
    BSL_UIO *uioTcp = BSL_UIO_NewTcp(acceptSock, 1);
    if (uioTcp == NULL) {
        BSL_SAL_SockClose(acceptSock);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    if (BSL_UIO_Append(uio, uioTcp) != BSL_SUCCESS) {
        BSL_SAL_SockClose(acceptSock);
        BSL_UIO_Free(uioTcp);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    char *host = BSL_UIO_AddrGetHostNameStr(&accept->cachePeerAddr, 1);
    char *service = BSL_UIO_AddrGetServiceStr(&accept->cachePeerAddr, 1);
    if (host != NULL && service != NULL) {
        BSL_SAL_FREE(accept->cachePeerName);
        accept->cachePeerName = host;
        BSL_SAL_FREE(accept->cachePeerServ);
        accept->cachePeerServ = service;
    } else {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        BSL_SAL_FREE(host);
        BSL_SAL_FREE(service);
    }
    accept->state = UIO_ACCEPT_STATE_OK;
    return BSL_SUCCESS;
}

static int32_t AcceptState(BSL_UIO *uio, UIO_Accept *accept)
{
    int ret = BSL_UIO_FAIL;
    while (true) {
        switch (accept->state) {
            case UIO_ACCEPT_STATE_BEFORE:
                if (accept->paramAddress == NULL && accept->paramService == NULL) {
                    BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
                    return BSL_UIO_FAIL;
                }
                BSL_SAL_FREE(accept->cacheAcceptingName);
                BSL_SAL_FREE(accept->cacheAcceptingServ);
                BSL_SAL_FREE(accept->cachePeerName);
                BSL_SAL_FREE(accept->cachePeerServ);
                accept->state = UIO_ACCEPT_STATE_GET_ADDR;
                ret = BSL_SUCCESS;
                break;
            case UIO_ACCEPT_STATE_GET_ADDR:
                ret = AcceptStateGetAddr(accept);
                break;
            case UIO_ACCEPT_STATE_CREATE_SOCKET:
                ret = AcceptStateCreateSocket(accept);
                break;
            case UIO_ACCEPT_STATE_LISTEN:
                return AcceptStateListen(accept);
            case UIO_ACCPET_STATE_ACCEPT:
                return AcceptStateAccept(uio, accept);
            case UIO_ACCEPT_STATE_OK:
                if (uio->next == NULL) {
                    accept->state = UIO_ACCPET_STATE_ACCEPT;
                    ret = BSL_SUCCESS;
                    break;
                }
                return BSL_SUCCESS;
            default:
                ret = BSL_UIO_FAIL;
                break;
        }
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return ret;
}

static int32_t SetHostName(BSL_UIO *uio, UIO_Accept *accept, const void *ptr)
{
    if (ptr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    char *address = NULL;
    char *service = NULL;
    int32_t ret = BSL_UIO_ParseHostService(ptr, &address, &service, BSL_UIO_PARSE_PRIO_SERV);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uio->init = true;
    BSL_SAL_FREE(accept->paramAddress);
    BSL_SAL_FREE(accept->paramService);
    accept->paramAddress = address;
    accept->paramService = service;
    return BSL_SUCCESS;
}

static int32_t SetPort(BSL_UIO *uio, UIO_Accept *accept, const void *ptr)
{
    if (ptr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    char *tmpServ = BSL_SAL_Dump(ptr, (uint32_t)(strlen((const char *)ptr) + 1));
    if (tmpServ == NULL) {
        return BSL_UIO_FAIL;
    }
    BSL_SAL_FREE(accept->paramService);
    accept->paramService = tmpServ;
    uio->init = true;
    return BSL_SUCCESS;
}

static int32_t SetFamily(UIO_Accept *accept, const void *ptr)
{
    if (ptr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    int tmpFamily = *(const int *)ptr;
    if (tmpFamily == BSL_UIO_FAMILY_IPANY || tmpFamily == BSL_UIO_FAMILY_IPV4 ||
        tmpFamily == BSL_UIO_FAMILY_IPV6) {
        accept->acceptFamily = tmpFamily;
        return BSL_SUCCESS;
    }
    return BSL_UIO_CTRL_INVALID_PARAM;
}

static int32_t AcceptSet(BSL_UIO *uio, UIO_Accept *accept, int32_t val, const void *ptr)
{
    if (val == ACCEPT_NOBLOCK_OPTION) {
        if (ptr != NULL) {
            accept->bindMode |= BSL_UIO_SOCK_NONBLOCK;
        } else {
            accept->bindMode &= ~BSL_UIO_SOCK_NONBLOCK;
        }
        return BSL_SUCCESS;
    } else {
        if (val == ACCEPT_HOSTNAME_OPTION) {
            return SetHostName(uio, accept, ptr);
        } else if (val == ACCEPT_PORT_OPTION) {
            return SetPort(uio, accept, ptr);
        } else if (val == ACCEPT_FAMILY_OPTION) {
            return SetFamily(accept, ptr);
        } else {
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
        }
    }
    return BSL_UIO_FAIL;
}

static int32_t AcceptGetFamily(UIO_Accept *accept, int *ptr)
{
    if (accept->addrIter == NULL) {
        *ptr = accept->acceptFamily;
        return BSL_SUCCESS;
    }
    switch (BSL_UIO_AddrInfoGetFamily(accept->addrIter)) {
        case AF_INET6:
            *ptr = BSL_UIO_FAMILY_IPV6;
            return BSL_SUCCESS;
        case AF_INET:
            *ptr = BSL_UIO_FAMILY_IPV4;
            return BSL_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
    }
}

static int32_t AcceptGet(BSL_UIO *uio, UIO_Accept *accept, int32_t val, void *ptr)
{
    if (ptr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (!uio->init) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_UNINITIALIZED);
        return BSL_UIO_UNINITIALIZED;
    }
    char **tmp;
    switch (val) {
        case ACCEPT_HOSTNAME_OPTION:
            tmp = (char **)ptr;
            *tmp = accept->cacheAcceptingName;
            return BSL_SUCCESS;
        case ACCEPT_PORT_OPTION:
            tmp = (char **)ptr;
            *tmp = accept->cacheAcceptingServ;
            return BSL_SUCCESS;
        case ACCEPT_PEER_HOSTNAME_OPTION:
            tmp = (char **)ptr;
            *tmp = accept->cachePeerName;
            return BSL_SUCCESS;
        case ACCEPT_PEER_PORT_OPTION:
            tmp = (char **)ptr;
            *tmp = accept->cachePeerServ;
            return BSL_SUCCESS;
        case ACCEPT_FAMILY_OPTION:
            return AcceptGetFamily(accept, ptr);
        default:
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
    }
}

static int32_t AcceptNew(BSL_UIO *uio)
{
    UIO_Accept *accept = BSL_SAL_Calloc(1, sizeof(UIO_Accept));
    if (accept == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05064, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: uio_Accept malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    uio->flags = 0;
    uio->init = false;
    accept->state = UIO_ACCEPT_STATE_BEFORE;
    accept->acceptFamily = BSL_UIO_FAMILY_IPANY;
    accept->fd = -1;
    (void)BSL_UIO_SetCtx(uio, accept);
    uio->ctxLen = sizeof(UIO_Accept);
    (void)BSL_UIO_SetIsUnderlyingClosedByUio(uio, true);
    return BSL_SUCCESS;
}

void BSL_AcceptFree(UIO_Accept *accept)
{
    if (accept == NULL) {
        return;
    }
    BSL_SAL_FREE(accept->paramAddress);
    BSL_SAL_FREE(accept->paramService);
    BSL_SAL_FREE(accept->cacheAcceptingName);
    BSL_SAL_FREE(accept->cacheAcceptingServ);
    BSL_SAL_FREE(accept->cachePeerName);
    BSL_SAL_FREE(accept->cachePeerServ);
    BSL_UIO_AddrInfoFree(accept->addrFirst);
}

static void AcceptCloseSocket(UIO_Accept *accept)
{
    if (accept->fd != -1) {
        BSL_SAL_SockClose(accept->fd);
        accept->fd = -1;
    }
}

static int32_t AcceptFree(BSL_UIO *uio)
{
    if (uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    UIO_Accept *accept = BSL_UIO_GetCtx(uio);
    if (BSL_UIO_GetIsUnderlyingClosedByUio(uio)) {
        if (accept != NULL) {
            AcceptCloseSocket(accept);
        }
    }
    BSL_AcceptFree(accept);
    BSL_SAL_FREE(accept);
    (void)BSL_UIO_SetCtx(uio, NULL);
    uio->flags = 0;
    uio->init = false;
    return BSL_SUCCESS;
}

static int32_t AcceptRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    int32_t ret = BSL_SUCCESS;
    if (uio == NULL || uio->ctx == NULL || readLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    UIO_Accept *accept = (UIO_Accept *)uio->ctx;
    while (uio->next == NULL) {
        ret = AcceptState(uio, accept);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    ret = BSL_UIO_Read(uio->next, buf, len, readLen);
    (void)BSL_UIO_SetFlagsFromNext(uio);
    uio->retryReason = uio->next->retryReason;
    return ret;
}

static int32_t AcceptWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    int32_t ret = BSL_SUCCESS;
    if (uio == NULL || uio->ctx == NULL || writeLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    UIO_Accept *accept = (UIO_Accept *)uio->ctx;
    while (uio->next == NULL) {
        ret = AcceptState(uio, accept);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    ret = BSL_UIO_Write(uio->next, buf, len, writeLen);
    (void)BSL_UIO_SetFlagsFromNext(uio);
    uio->retryReason = uio->next->retryReason;
    return ret;
}

static int32_t AcceptPuts(BSL_UIO *uio, const char *buf, uint32_t *writeLen)
{
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    size_t len = strlen(buf);
    return AcceptWrite(uio, buf, len, writeLen);
}

static int32_t AcceptGetFd(BSL_UIO *uio, UIO_Accept *accept, int32_t size, int32_t *fd)
{
    if (accept == NULL || fd == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(*fd)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    if (!uio->init) {
        *fd = -1;
    } else {
        *fd = accept->fd;
    }
    return BSL_SUCCESS;
}

static int32_t AcceptGetClose(BSL_UIO *uio, int32_t size, bool *ptr)
{
    if (ptr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(*ptr)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    *ptr = BSL_UIO_GetIsUnderlyingClosedByUio(uio);
    return BSL_SUCCESS;
}

static int32_t AcceptGetBindMode(UIO_Accept *accept, int32_t size, int32_t *mode)
{
    if (accept == NULL || mode == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(*mode)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    *mode = accept->bindMode;
    return BSL_SUCCESS;
}

static void SetAcceptMode(UIO_Accept *accept, int32_t val)
{
    if (val != 0) {
        accept->acceptMode |= BSL_UIO_SOCK_NONBLOCK;
    } else {
        accept->acceptMode &= ~BSL_UIO_SOCK_NONBLOCK;
    }
}

static void ResetAccept(BSL_UIO *uio, UIO_Accept *accept)
{
    if (accept->fd != -1) {
        BSL_SAL_SockClose(accept->fd);
        accept->fd = -1;
    }
    uio->flags = 0;
    BSL_UIO_AddrInfoFree(accept->addrFirst);
    accept->addrFirst = NULL;
    accept->state = UIO_ACCEPT_STATE_BEFORE;
}

static int32_t SetFd(BSL_UIO *uio, UIO_Accept *accept, int32_t val, void *ptr)
{
    if (ptr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    accept->fd = *((int *)ptr);
    BSL_UIO_SetIsUnderlyingClosedByUio(uio, val);
    accept->state = UIO_ACCPET_STATE_ACCEPT;
    uio->init = true;
    return BSL_SUCCESS;
}

static int32_t SetBindMode(UIO_Accept *accept, int32_t val)
{
    if (val <= 0) {
        return BSL_UIO_FAIL;
    }
    accept->bindMode = val;
    return BSL_SUCCESS;
}

static int32_t AcceptCtrl(BSL_UIO *uio, int32_t cmd, int32_t val, void *ptr)
{
    if (uio == NULL || uio->ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    UIO_Accept *accept = (UIO_Accept *)uio->ctx;
    switch (cmd) {
        case BSL_UIO_RESET:
            ResetAccept(uio, accept);
            return BSL_SUCCESS;
        case BSL_UIO_DO_HANDSHAKE:
            return AcceptState(uio, accept);
        case BSL_UIO_SET_NOBLOCK:
            SetAcceptMode(accept, val);
            return BSL_SUCCESS;
        case BSL_UIO_SET_ACCEPT:
            return AcceptSet(uio, accept, val, ptr);
        case BSL_UIO_SET_FD:
            return SetFd(uio, accept, val, ptr);
        case BSL_UIO_GET_FD:
            return AcceptGetFd(uio, accept, val, ptr);
        case BSL_UIO_GET_ACCEPT:
            return AcceptGet(uio, accept, val, ptr);
        case BSL_UIO_GET_CLOSE:
            return AcceptGetClose(uio, val, ptr);
        case BSL_UIO_SET_CLOSE:
            BSL_UIO_SetIsUnderlyingClosedByUio(uio, val);
            return BSL_SUCCESS;
        case BSL_UIO_WPENDING:
        case BSL_UIO_PENDING:
            return BSL_UIO_FAIL;
        case BSL_UIO_FLUSH:
            return BSL_SUCCESS;
        case BSL_UIO_SET_BIND_MODE:
            return SetBindMode(accept, val);
        case BSL_UIO_GET_BIND_MODE:
            return AcceptGetBindMode(accept, val, ptr);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    return BSL_UIO_FAIL;
}

BSL_UIO *BSL_UIO_NewAccept(const char *hostName)
{
    if (hostName == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return NULL;
    }
    BSL_UIO *ret = BSL_UIO_New(BSL_UIO_AcceptMethod());
    if (BSL_UIO_Ctrl(ret, BSL_UIO_SET_ACCEPT, ACCEPT_HOSTNAME_OPTION, (char *)(uintptr_t)hostName) == BSL_SUCCESS) {
        return ret;
    }
    BSL_UIO_Free(ret);
    return NULL;
}

const BSL_UIO_Method *BSL_UIO_AcceptMethod(void)
{
    static const BSL_UIO_Method METHOD = {
        BSL_UIO_ACCEPT,
        AcceptWrite,
        AcceptRead,
        AcceptCtrl,
        AcceptPuts,
        NULL,
        AcceptNew,
        AcceptFree,
        NULL,
        NULL,
    };
    return &METHOD;
}

#endif /* HITLS_BSL_UIO_ACCEPT */
