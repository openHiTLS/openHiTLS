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
#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)) && defined(HITLS_BSL_SAL_NET)

#include <stdbool.h>

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "sal_net.h"

typedef union {
    struct sockaddr addr;
    struct sockaddr_in6 addrIn6;
    struct sockaddr_in addrIn;
    struct sockaddr_un addrUn;
} LinuxSockAddr;

int32_t SAL_NET_Write(int32_t fd, const void *buf, uint32_t len, int32_t *err)
{
    if (err == NULL) {
        return BSL_NULL_INPUT;
    }
    int32_t ret = (int32_t)write(fd, buf, len);
    if (ret < 0) {
        *err = errno;
    }
    return ret;
}

int32_t SAL_NET_Read(int32_t fd, void *buf, uint32_t len, int32_t *err)
{
    if (err == NULL) {
        return BSL_NULL_INPUT;
    }
    int32_t ret = (int32_t)read(fd, buf, len);
    if (ret < 0) {
        *err = errno;
    }
    return ret;
}

int32_t SAL_NET_Sendto(int32_t sock, const void *buf, size_t len, int32_t flags, void *address, int32_t addrLen,
                       int32_t *err)
{
    if (err == NULL) {
        return BSL_NULL_INPUT;
    }
    int32_t ret = (int32_t)sendto(sock, buf, len, flags, (struct sockaddr *)address, (socklen_t)addrLen);
    if (ret <= 0) {
        *err = errno;
    }
    return ret;
}

int32_t SAL_NET_RecvFrom(int32_t sock, void *buf, size_t len, int32_t flags, void *address, int32_t *addrLen,
                         int32_t *err)
{
    if (err == NULL) {
        return BSL_NULL_INPUT;
    }
    int32_t ret = (int32_t)recvfrom(sock, buf, len, flags, (struct sockaddr *)address, (socklen_t *)addrLen);
    if (ret <= 0) {
        *err = errno;
    }
    return ret;
}

int32_t SAL_NET_SockAddrNew(BSL_SAL_SockAddr *sockAddr)
{
    LinuxSockAddr *addr = (LinuxSockAddr *)BSL_SAL_Calloc(1, sizeof(LinuxSockAddr));
    if (addr == NULL) {
        return BSL_MALLOC_FAIL;
    }
    *sockAddr = (BSL_SAL_SockAddr)addr;
    return BSL_SUCCESS;
}

void SAL_NET_SockAddrFree(BSL_SAL_SockAddr sockAddr)
{
    BSL_SAL_Free(sockAddr);
}

int32_t SAL_NET_SockAddrGetFamily(const BSL_SAL_SockAddr sockAddr)
{
    const LinuxSockAddr *addr = (const LinuxSockAddr *)sockAddr;
    if (addr == NULL) {
        return AF_UNSPEC;
    }
    return addr->addr.sa_family;
}

uint32_t SAL_NET_SockAddrSize(const BSL_SAL_SockAddr sockAddr)
{
    const LinuxSockAddr *addr = (const LinuxSockAddr *)sockAddr;
    if (addr == NULL) {
        return 0;
    }
    switch (addr->addr.sa_family) {
        case AF_INET:
            return sizeof(addr->addrIn);
        case AF_INET6:
            return sizeof(addr->addrIn6);
        case AF_UNIX:
            return sizeof(addr->addrUn);
        default:
            break;
    }
    return sizeof(LinuxSockAddr);
}

void SAL_NET_SockAddrCopy(BSL_SAL_SockAddr dst, BSL_SAL_SockAddr src)
{
    memcpy_s(dst, sizeof(LinuxSockAddr), src, sizeof(LinuxSockAddr));
}

int32_t SAL_Socket(int32_t af, int32_t type, int32_t protocol)
{
    return (int32_t)socket(af, type, protocol);
}

int32_t SAL_SockClose(int32_t sockId)
{
    if (close((int32_t)(long)sockId) != 0) {
        return BSL_SAL_ERR_NET_SOCKCLOSE;
    }
    return BSL_SUCCESS;
}

int32_t SAL_SetSockopt(int32_t sockId, int32_t level, int32_t name, const void *val, int32_t len)
{
    if (setsockopt((int32_t)sockId, level, name, (char *)(uintptr_t)val, (socklen_t)len) != 0) {
        return BSL_SAL_ERR_NET_SETSOCKOPT;
    }
    return BSL_SUCCESS;
}

int32_t SAL_GetSockopt(int32_t sockId, int32_t level, int32_t name, void *val, int32_t *len)
{
    if (getsockopt((int32_t)sockId, level, name, val, (socklen_t *)len) != 0) {
        return BSL_SAL_ERR_NET_GETSOCKOPT;
    }
    return BSL_SUCCESS;
}

int32_t SAL_SockListen(int32_t sockId, int32_t backlog)
{
    if (listen(sockId, backlog) != 0) {
        return BSL_SAL_ERR_NET_LISTEN;
    }
    return BSL_SUCCESS;
}

int32_t SAL_SockBind(int32_t sockId, BSL_SAL_SockAddr addr, size_t len)
{
    if (bind(sockId, (struct sockaddr *)addr, (socklen_t)len) != 0) {
        return BSL_SAL_ERR_NET_BIND;
    }
    return BSL_SUCCESS;
}

int32_t SAL_SockConnect(int32_t sockId, BSL_SAL_SockAddr addr, size_t len)
{
    if (connect(sockId, (struct sockaddr *)addr, (socklen_t)len) != 0) {
        return BSL_SAL_ERR_NET_CONNECT;
    }
    return BSL_SUCCESS;
}

int32_t SAL_SockSend(int32_t sockId, const void *msg, size_t len, int32_t flags)
{
    return (int32_t)send(sockId, msg, len, flags);
}

int32_t SAL_SockRecv(int32_t sockfd, void *buff, size_t len, int32_t flags)
{
    return (int32_t)recv(sockfd, (char *)buff, len, flags);
}

int32_t SAL_Select(int32_t nfds, void *readfds, void *writefds, void *exceptfds, void *timeout)
{
    return select(nfds, (fd_set *)readfds, (fd_set *)writefds, (fd_set *)exceptfds, (struct timeval *)timeout);
}

int32_t SAL_Ioctlsocket(int32_t sockId, long cmd, unsigned long *arg)
{
    if (ioctl(sockId, (unsigned long)cmd, arg) != 0) {
        return BSL_SAL_ERR_NET_IOCTL;
    }
    return BSL_SUCCESS;
}

int32_t SAL_SockGetLastSocketError(void)
{
    return errno;
}

#endif
