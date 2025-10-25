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

#if defined(HITLS_BSL_SAL_NET)
#include <stdint.h>
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "sal_netimpl.h"

static BSL_SAL_NetCallback g_netCallback = {0};

int32_t SAL_NetCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type > BSL_SAL_NET_GETFAMILY_CB_FUNC || type < BSL_SAL_NET_WRITE_CB_FUNC) {
        return BSL_SAL_NET_NO_REG_FUNC;
    }
    uint32_t offset = (uint32_t)(type - BSL_SAL_NET_WRITE_CB_FUNC);
    ((void **)&g_netCallback)[offset] = funcCb;
    return BSL_SUCCESS;
}

int32_t SAL_Write(int32_t fd, const void *buf, uint32_t len, int32_t *err)
{
    if (buf == NULL || len == 0 || err == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_netCallback.pfWrite != NULL && g_netCallback.pfWrite != SAL_Write) {
        return g_netCallback.pfWrite(fd, buf, len, err);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_Write(fd, buf, len, err);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t SAL_Read(int32_t fd, void *buf, uint32_t len, int32_t *err)
{
    if (buf == NULL || len == 0 || err == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_netCallback.pfRead != NULL && g_netCallback.pfRead != SAL_Read) {
        return g_netCallback.pfRead(fd, buf, len, err);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_Read(fd, buf, len, err);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t SAL_Sendto(int32_t sock, const void *buf, size_t len, int32_t flags, BSL_SAL_SockAddr address,
                   int32_t addrLen, int32_t *err)
{
    if (buf == NULL || len == 0 || address == NULL || addrLen == 0 || err == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_netCallback.pfSendTo != NULL && g_netCallback.pfSendTo != SAL_Sendto) {
        return g_netCallback.pfSendTo(sock, buf, len, flags, address, addrLen, err);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_Sendto(sock, buf, len, flags, address, addrLen, err);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t SAL_RecvFrom(int32_t sock, void *buf, size_t len, int32_t flags, BSL_SAL_SockAddr address,
                     int32_t *addrLen, int32_t *err)
{
    if (buf == NULL || len == 0 || err == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_netCallback.pfRecvFrom != NULL && g_netCallback.pfRecvFrom != SAL_RecvFrom) {
        return g_netCallback.pfRecvFrom(sock, buf, len, flags, address, addrLen, err);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_RecvFrom(sock, buf, len, flags, address, addrLen, err);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t SAL_SockAddrNew(BSL_SAL_SockAddr *sockAddr)
{
    if (g_netCallback.pfSockAddrNew != NULL && g_netCallback.pfSockAddrNew != SAL_SockAddrNew) {
        return g_netCallback.pfSockAddrNew(sockAddr);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockAddrNew(sockAddr);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

void SAL_SockAddrFree(BSL_SAL_SockAddr sockAddr)
{
    if (g_netCallback.pfSockAddrFree != NULL && g_netCallback.pfSockAddrFree != SAL_SockAddrFree) {
        return g_netCallback.pfSockAddrFree(sockAddr);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    SAL_NET_SockAddrFree(sockAddr);
    return;
#endif
}

int32_t SAL_SockAddrGetFamily(const BSL_SAL_SockAddr sockAddr)
{
    if (g_netCallback.pfSockAddrGetFamily != NULL && g_netCallback.pfSockAddrGetFamily != SAL_SockAddrGetFamily) {
        return g_netCallback.pfSockAddrGetFamily(sockAddr);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockAddrGetFamily(sockAddr);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

uint32_t SAL_SockAddrSize(const BSL_SAL_SockAddr sockAddr)
{
    if (g_netCallback.pfSockAddrSize != NULL && g_netCallback.pfSockAddrSize != SAL_SockAddrSize) {
        return g_netCallback.pfSockAddrSize(sockAddr);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockAddrSize(sockAddr);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

void SAL_SockAddrCopy(BSL_SAL_SockAddr dst, BSL_SAL_SockAddr src)
{
    if (g_netCallback.pfSockAddrCopy != NULL && g_netCallback.pfSockAddrCopy != SAL_SockAddrCopy) {
        return g_netCallback.pfSockAddrCopy(src, dst);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    SAL_NET_SockAddrCopy(src, dst);
    return;
#endif
}

int32_t BSL_SAL_Socket(int32_t af, int32_t type, int32_t protocol)
{
    if (g_netCallback.pfSocket != NULL && g_netCallback.pfSocket != BSL_SAL_Socket) {
        return g_netCallback.pfSocket(af, type, protocol);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_Socket(af, type, protocol);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockClose(int32_t sockId)
{
    if (g_netCallback.pfSockClose != NULL && g_netCallback.pfSockClose != BSL_SAL_SockClose) {
        return g_netCallback.pfSockClose(sockId);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_SockClose(sockId);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SetSockopt(int32_t sockId, int32_t level, int32_t name, const void *val, int32_t len)
{
    if (g_netCallback.pfSetSockopt != NULL && g_netCallback.pfSetSockopt != BSL_SAL_SetSockopt) {
        return g_netCallback.pfSetSockopt(sockId, level, name, val, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_SetSockopt(sockId, level, name, val, len);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_GetSockopt(int32_t sockId, int32_t level, int32_t name, void *val, int32_t *len)
{
    if (g_netCallback.pfGetSockopt != NULL && g_netCallback.pfGetSockopt != BSL_SAL_GetSockopt) {
        return g_netCallback.pfGetSockopt(sockId, level, name, val, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_GetSockopt(sockId, level, name, val, len);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockListen(int32_t sockId, int32_t backlog)
{
    if (g_netCallback.pfSockListen != NULL && g_netCallback.pfSockListen != BSL_SAL_SockListen) {
        return g_netCallback.pfSockListen(sockId, backlog);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_SockListen(sockId, backlog);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockBind(int32_t sockId, BSL_SAL_SockAddr addr, size_t len)
{
    if (g_netCallback.pfSockBind != NULL && g_netCallback.pfSockBind != BSL_SAL_SockBind) {
        return g_netCallback.pfSockBind(sockId, addr, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_SockBind(sockId, addr, len);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockConnect(int32_t sockId, BSL_SAL_SockAddr addr, size_t len)
{
    if (g_netCallback.pfSockConnect != NULL && g_netCallback.pfSockConnect != BSL_SAL_SockConnect) {
        return g_netCallback.pfSockConnect(sockId, addr, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_SockConnect(sockId, addr, len);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockSend(int32_t sockId, const void *msg, size_t len, int32_t flags)
{
    if (g_netCallback.pfSockSend != NULL && g_netCallback.pfSockSend != BSL_SAL_SockSend) {
        return g_netCallback.pfSockSend(sockId, msg, len, flags);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_SockSend(sockId, msg, len, flags);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockRecv(int32_t sockfd, void *buff, size_t len, int32_t flags)
{
    if (g_netCallback.pfSockRecv != NULL && g_netCallback.pfSockRecv != BSL_SAL_SockRecv) {
        return g_netCallback.pfSockRecv(sockfd, buff, len, flags);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_SockRecv(sockfd, buff, len, flags);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_Select(int32_t nfds, void *readfds, void *writefds, void *exceptfds, void *timeout)
{
    if (g_netCallback.pfSelect != NULL && g_netCallback.pfSelect != BSL_SAL_Select) {
        return g_netCallback.pfSelect(nfds, readfds, writefds, exceptfds, timeout);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_Select(nfds, readfds, writefds, exceptfds, timeout);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_Ioctlsocket(int32_t sockId, long cmd, unsigned long *arg)
{
    if (g_netCallback.pfIoctlsocket != NULL && g_netCallback.pfIoctlsocket != BSL_SAL_Ioctlsocket) {
        return g_netCallback.pfIoctlsocket(sockId, cmd, arg);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_Ioctlsocket(sockId, cmd, arg);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockGetLastSocketError(void)
{
    if (g_netCallback.pfSockGetLastSocketError != NULL &&
        g_netCallback.pfSockGetLastSocketError != BSL_SAL_SockGetLastSocketError) {
        return g_netCallback.pfSockGetLastSocketError();
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_SockGetLastSocketError();
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

#endif
