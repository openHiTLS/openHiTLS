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
#include "bsl_err_internal.h"
#include "sal_netimpl.h"

static BSL_SAL_NetCallback g_netCallBack = {0};

int32_t SAL_NetCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type > BSL_SAL_NET_GETFAMILY_CB_FUNC || type < BSL_SAL_NET_WRITE_CB_FUNC) {
        return BSL_SAL_NET_NO_REG_FUNC;
    }
    uint32_t offset = (uint32_t)(type - BSL_SAL_NET_WRITE_CB_FUNC);
    ((void **)&g_netCallBack)[offset] = funcCb;
    return BSL_SUCCESS;
}

int32_t SAL_Write(int32_t fd, const void *buf, uint32_t len, int32_t *err)
{
    if (buf == NULL || len == 0 || err == NULL) {
        return -1;
    }
    if (g_netCallBack.pfWrite != NULL && g_netCallBack.pfWrite != SAL_Write) {
        return g_netCallBack.pfWrite(fd, buf, len, err);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_Write(fd, buf, len, err);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return -1;
#endif
}

int32_t SAL_Read(int32_t fd, void *buf, uint32_t len, int32_t *err)
{
    if (buf == NULL || len == 0 || err == NULL) {
        return -1;
    }
    if (g_netCallBack.pfRead != NULL && g_netCallBack.pfRead != SAL_Read) {
        return g_netCallBack.pfRead(fd, buf, len, err);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_Read(fd, buf, len, err);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return -1;
#endif
}

int32_t SAL_Sendto(int32_t sock, const void *buf, size_t len, int32_t flags, BSL_SAL_SockAddr address,
                   int32_t addrLen, int32_t *err)
{
    if (buf == NULL || len == 0 || address == NULL || addrLen == 0 || err == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_netCallBack.pfSendTo != NULL && g_netCallBack.pfSendTo != SAL_Sendto) {
        return g_netCallBack.pfSendTo(sock, buf, len, flags, address, addrLen, err);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_Sendto(sock, buf, len, flags, address, addrLen, err);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return -1;
#endif
}

int32_t SAL_Recvfrom(int32_t sock, void *buf, size_t len, int32_t flags, BSL_SAL_SockAddr address,
                     int32_t *addrLen, int32_t *err)
{
    if (buf == NULL || len == 0 || err == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_netCallBack.pfRecvFrom != NULL && g_netCallBack.pfRecvFrom != SAL_Recvfrom) {
        return g_netCallBack.pfRecvFrom(sock, buf, len, flags, address, addrLen, err);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_Recvfrom(sock, buf, len, flags, address, addrLen, err);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return -1;
#endif
}

int32_t BSL_SAL_Select(int32_t nfds, void *readfds, void *writefds, void *exceptfds, void *timeout)
{
    if (g_netCallBack.pfSelect != NULL && g_netCallBack.pfSelect != BSL_SAL_Select) {
        return g_netCallBack.pfSelect(nfds, readfds, writefds, exceptfds, timeout);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_Select(nfds, readfds, writefds, exceptfds, timeout);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return -1;
#endif
}

int32_t BSL_SAL_Ioctlsocket(int32_t sockId, long cmd, unsigned long *arg)
{
    if (g_netCallBack.pfIoctlsocket != NULL && g_netCallBack.pfIoctlsocket != BSL_SAL_Ioctlsocket) {
        return g_netCallBack.pfIoctlsocket(sockId, cmd, arg);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_Ioctlsocket(sockId, cmd, arg);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return -1;
#endif
}

int32_t BSL_SAL_SockGetLastSocketError(void)
{
    if (g_netCallBack.pfGetErrno != NULL &&
        g_netCallBack.pfGetErrno != BSL_SAL_SockGetLastSocketError) {
        return g_netCallBack.pfGetErrno();
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockGetErrno();
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t SAL_SockAddrNew(BSL_SAL_SockAddr *sockAddr)
{
    if (g_netCallBack.pfSockAddrNew != NULL && g_netCallBack.pfSockAddrNew != SAL_SockAddrNew) {
        return g_netCallBack.pfSockAddrNew(sockAddr);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockAddrNew(sockAddr);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

void SAL_SockAddrFree(BSL_SAL_SockAddr sockAddr)
{
    if (g_netCallBack.pfSockAddrFree != NULL && g_netCallBack.pfSockAddrFree != SAL_SockAddrFree) {
        return g_netCallBack.pfSockAddrFree(sockAddr);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    SAL_NET_SockAddrFree(sockAddr);
    return;
#endif
}

int32_t SAL_SockAddrGetFamily(const BSL_SAL_SockAddr sockAddr)
{
    if (g_netCallBack.pfSockAddrGetFamily != NULL && g_netCallBack.pfSockAddrGetFamily != SAL_SockAddrGetFamily) {
        return g_netCallBack.pfSockAddrGetFamily(sockAddr);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockAddrGetFamily(sockAddr);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

uint32_t SAL_SockAddrSize(const BSL_SAL_SockAddr sockAddr)
{
    if (g_netCallBack.pfSockAddrSize != NULL && g_netCallBack.pfSockAddrSize != SAL_SockAddrSize) {
        return g_netCallBack.pfSockAddrSize(sockAddr);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockAddrSize(sockAddr);
#else
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

void SAL_SockAddrCopy(BSL_SAL_SockAddr dst, BSL_SAL_SockAddr src)
{
    if (g_netCallBack.pfSockAddrCopy != NULL && g_netCallBack.pfSockAddrCopy != SAL_SockAddrCopy) {
        return g_netCallBack.pfSockAddrCopy(dst, src);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    SAL_NET_SockAddrCopy(dst, src);
    return;
#endif
}

int32_t BSL_SAL_Socket(int32_t af, int32_t type, int32_t protocol)
{
    if (g_netCallBack.pfSocket != NULL && g_netCallBack.pfSocket != BSL_SAL_Socket) {
        return g_netCallBack.pfSocket(af, type, protocol);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_Socket(af, type, protocol);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return -1;
#endif
}

int32_t BSL_SAL_SockClose(int32_t sockId)
{
    if (g_netCallBack.pfSockClose != NULL && g_netCallBack.pfSockClose != BSL_SAL_SockClose) {
        return g_netCallBack.pfSockClose(sockId);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockClose(sockId);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SetSockopt(int32_t sockId, int32_t level, int32_t name, const void *val, int32_t len)
{
    if (val == NULL || len == 0) {
        return BSL_NULL_INPUT;
    }
    if (g_netCallBack.pfSetSocketopt != NULL && g_netCallBack.pfSetSocketopt != BSL_SAL_SetSockopt) {
        return g_netCallBack.pfSetSocketopt(sockId, level, name, val, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SetSockopt(sockId, level, name, val, len);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_GetSockopt(int32_t sockId, int32_t level, int32_t name, void *val, int32_t *len)
{
    if (val == NULL || len == NULL) {
        return BSL_NULL_INPUT;
    }
    if (g_netCallBack.pfGetSocketopt != NULL && g_netCallBack.pfGetSocketopt != BSL_SAL_GetSockopt) {
        return g_netCallBack.pfGetSocketopt(sockId, level, name, val, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_GetSockopt(sockId, level, name, val, len);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockListen(int32_t sockId, int32_t backlog)
{
    if (g_netCallBack.pfSockListen != NULL && g_netCallBack.pfSockListen != BSL_SAL_SockListen) {
        return g_netCallBack.pfSockListen(sockId, backlog);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockListen(sockId, backlog);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockBind(int32_t sockId, BSL_SAL_SockAddr addr, size_t len)
{
    if (addr == NULL || len == 0) {
        return BSL_NULL_INPUT;
    }
    if (g_netCallBack.pfSockBind != NULL && g_netCallBack.pfSockBind != BSL_SAL_SockBind) {
        return g_netCallBack.pfSockBind(sockId, addr, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockBind(sockId, addr, len);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockConnect(int32_t sockId, BSL_SAL_SockAddr addr, size_t len)
{
    if (addr == NULL || len == 0) {
        return BSL_NULL_INPUT;
    }
    if (g_netCallBack.pfSockConnect != NULL && g_netCallBack.pfSockConnect != BSL_SAL_SockConnect) {
        return g_netCallBack.pfSockConnect(sockId, addr, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockConnect(sockId, addr, len);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return BSL_SAL_NET_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SockSend(int32_t sockId, const void *msg, size_t len, int32_t flags)
{
    if (msg == NULL || len == 0) {
        return -1;
    }
    if (g_netCallBack.pfSockSend != NULL && g_netCallBack.pfSockSend != BSL_SAL_SockSend) {
        return g_netCallBack.pfSockSend(sockId, msg, len, flags);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockSend(sockId, msg, len, flags);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return -1;
#endif
}

int32_t BSL_SAL_SockRecv(int32_t sockfd, void *buff, size_t len, int32_t flags)
{
    if (buff == NULL || len == 0) {
        return -1;
    }
    if (g_netCallBack.pfSockRecv != NULL && g_netCallBack.pfSockRecv != BSL_SAL_SockRecv) {
        return g_netCallBack.pfSockRecv(sockfd, buff, len, flags);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockRecv(sockfd, buff, len, flags);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return -1;
#endif
}

#endif
