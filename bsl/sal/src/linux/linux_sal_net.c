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
#if defined(HITLS_BSL_SAL_LINUX) && defined(HITLS_BSL_SAL_NET)

#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include "bsl_sal.h"
#include "bsl_errno.h"
#include "sal_net.h"

int32_t SAL_Write(int32_t fd, const void *buf, uint32_t len, int32_t *err)
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

int32_t SAL_Read(int32_t fd, void *buf, uint32_t len, int32_t *err)
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
