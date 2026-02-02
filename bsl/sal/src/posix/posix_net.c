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

typedef struct sockaddr_storage BSL_SOCKADDR_STORAGE;

#define ADDRESS_FAMILY_HITLS_2_POSIX(hitlsType)       (hitlsType)
#define ADDRESS_SOCKET_TYPE_HITLS_2_POSIX(hitlsType)  (hitlsType)
#define ADDRESS_PROTOCOL_HITLS_2_POSIX(hitlsType)     (hitlsType)
#ifdef __APPLE__
#define ADDRESS_LEVEL_HITLS_2_POSIX(hitlsType)        ((hitlsType) == SAL_NET_SOL_SOCKET ? 65535 : (hitlsType))
#else
#define ADDRESS_LEVEL_HITLS_2_POSIX(hitlsType)        (hitlsType)
#endif
#define ADDRESS_OPTION_HITLS_2_POSIX(hitlsType)       (hitlsType)
#define ADDRESS_FAMILY_POSIX_2_HITLS(hitlsType)       (hitlsType)

int32_t SAL_NET_Write(int32_t fd, const void *buf, uint32_t len, int32_t *err)
{
    if (err == NULL) {
        return -1;
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
        return -1;
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

int32_t SAL_NET_Recvfrom(int32_t sock, void *buf, size_t len, int32_t flags, void *address, int32_t *addrLen,
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
    BSL_SOCKADDR_STORAGE *addr = (BSL_SOCKADDR_STORAGE *)BSL_SAL_Calloc(1, sizeof(BSL_SOCKADDR_STORAGE));
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
    const BSL_SOCKADDR_STORAGE *addr = (const BSL_SOCKADDR_STORAGE *)sockAddr;
    if (addr == NULL) {
        return ADDRESS_FAMILY_POSIX_2_HITLS(AF_UNSPEC);
    }
    return ADDRESS_FAMILY_POSIX_2_HITLS(addr->ss_family);
}

uint32_t SAL_NET_SockAddrSize(const BSL_SAL_SockAddr sockAddr)
{
    const BSL_SOCKADDR_STORAGE *addr = (const BSL_SOCKADDR_STORAGE *)sockAddr;
    if (addr == NULL) {
        return 0;
    }
    switch (addr->ss_family) {
        case AF_INET:
            return sizeof(struct sockaddr_in);
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
        case AF_UNIX:
            return sizeof(struct sockaddr_un);
        default:
            break;
    }
    return sizeof(BSL_SOCKADDR_STORAGE);
}

void SAL_NET_SockAddrCopy(BSL_SAL_SockAddr dst, BSL_SAL_SockAddr src)
{
    BSL_SOCKADDR_STORAGE *dstAddr = (BSL_SOCKADDR_STORAGE *)dst;
    BSL_SOCKADDR_STORAGE *srcAddr = (BSL_SOCKADDR_STORAGE *)src;
    uint32_t srcAddrLen = 0;
    switch (srcAddr->ss_family) {
        case AF_INET:
            srcAddrLen = sizeof(struct sockaddr_in);
            break;
        case AF_INET6:
            srcAddrLen = sizeof(struct sockaddr_in6);
            break;
#ifdef AF_UNIX
        case AF_UNIX:
            srcAddrLen = sizeof(struct sockaddr_un);
            break;
#endif
        default:
            break;
    }
    memcpy_s(dstAddr, sizeof(BSL_SOCKADDR_STORAGE), srcAddr, srcAddrLen);
}

int32_t SAL_NET_Socket(int32_t af, int32_t type, int32_t protocol)
{
    int32_t posixFamily = ADDRESS_FAMILY_HITLS_2_POSIX(af);
    int32_t posixType = ADDRESS_SOCKET_TYPE_HITLS_2_POSIX(type);
    int32_t posixProtocol = ADDRESS_PROTOCOL_HITLS_2_POSIX(protocol);
    return (int32_t)socket(posixFamily, posixType, posixProtocol);
}

int32_t SAL_NET_SockClose(int32_t sockId)
{
    if (close((int32_t)(long)sockId) != 0) {
        return BSL_SAL_ERR_NET_SOCKCLOSE;
    }
    return BSL_SUCCESS;
}

int32_t SAL_NET_SetSockopt(int32_t sockId, int32_t level, int32_t name, const void *val, int32_t len)
{
    int32_t posixLevel = ADDRESS_LEVEL_HITLS_2_POSIX(level);
    int32_t posixName = ADDRESS_OPTION_HITLS_2_POSIX(name);
    if (setsockopt((int32_t)sockId, posixLevel, posixName, (char *)(uintptr_t)val, (socklen_t)len) != 0) {
        return BSL_SAL_ERR_NET_SETSOCKOPT;
    }
    return BSL_SUCCESS;
}

int32_t SAL_NET_GetSockopt(int32_t sockId, int32_t level, int32_t name, void *val, int32_t *len)
{
    int32_t posixLevel = ADDRESS_LEVEL_HITLS_2_POSIX(level);
    int32_t posixName = ADDRESS_OPTION_HITLS_2_POSIX(name);
    if (getsockopt((int32_t)sockId, posixLevel, posixName, val, (socklen_t *)len) != 0) {
        return BSL_SAL_ERR_NET_GETSOCKOPT;
    }
    return BSL_SUCCESS;
}

int32_t SAL_NET_SockListen(int32_t sockId, int32_t backlog)
{
    if (listen(sockId, backlog) != 0) {
        return BSL_SAL_ERR_NET_LISTEN;
    }
    return BSL_SUCCESS;
}

int32_t SAL_NET_SockBind(int32_t sockId, BSL_SAL_SockAddr addr, size_t len)
{
    if (bind(sockId, (struct sockaddr *)addr, (socklen_t)len) != 0) {
        return BSL_SAL_ERR_NET_BIND;
    }
    return BSL_SUCCESS;
}

int32_t SAL_NET_SockConnect(int32_t sockId, BSL_SAL_SockAddr addr, size_t len)
{
    if (connect(sockId, (struct sockaddr *)addr, (socklen_t)len) != 0) {
        return BSL_SAL_ERR_NET_CONNECT;
    }
    return BSL_SUCCESS;
}

int32_t SAL_NET_SockSend(int32_t sockId, const void *msg, size_t len, int32_t flags)
{
    return (int32_t)send(sockId, msg, len, flags);
}

int32_t SAL_NET_SockRecv(int32_t sockfd, void *buff, size_t len, int32_t flags)
{
    return (int32_t)recv(sockfd, (char *)buff, len, flags);
}

int32_t SAL_NET_Select(int32_t nfds, void *readfds, void *writefds, void *exceptfds, void *timeout)
{
    return select(nfds, (fd_set *)readfds, (fd_set *)writefds, (fd_set *)exceptfds, (struct timeval *)timeout);
}

int32_t SAL_NET_Ioctlsocket(int32_t sockId, long cmd, unsigned long *arg)
{
    if (ioctl(sockId, (unsigned long)cmd, arg) != 0) {
        return BSL_SAL_ERR_NET_IOCTL;
    }
    return BSL_SUCCESS;
}

int32_t SAL_NET_SockGetErrno(void)
{
    return errno;
}

#endif
