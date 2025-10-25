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

#ifndef SAL_NETIMPL_H
#define SAL_NETIMPL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_NET

#include <stdint.h>
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    BslSalWrite pfWrite;
    BslSalRead pfRead;
    BslSalSocket pfSocket;
    BslSalSockClose pfSockClose;
    BslSalSetSockopt pfSetSockopt;
    BslSalGetSockopt pfGetSockopt;
    BslSalSockListen pfSockListen;
    BslSalSockBind pfSockBind;
    BslSalSockConnect pfSockConnect;
    BslSalSockSend pfSockSend;
    BslSalSockRecv pfSockRecv;
    BslSalSelect pfSelect;
    BslSalIoctlsocket pfIoctlsocket;
    BslSalSockGetLastSocketError pfSockGetLastSocketError;
    BslSalSockAddrNew pfSockAddrNew;
    BslSalSockAddrFree pfSockAddrFree;
    BslSalSockAddrSize pfSockAddrSize;
    BslSalSockAddrCopy pfSockAddrCopy;
    BslSalNetSendTo pfSendTo;
    BslSalNetRecvFrom pfRecvFrom;
    BslSalSockAddrGetFamily pfSockAddrGetFamily;
} BSL_SAL_NetCallback;

int32_t SAL_NetCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
int32_t SAL_NET_Write(int32_t fd, const void *buf, uint32_t len, int32_t *err);
int32_t SAL_NET_Read(int32_t fd, void *buf, uint32_t len, int32_t *err);
int32_t SAL_NET_SockAddrNew(BSL_SAL_SockAddr *sockAddr);
void SAL_NET_SockAddrFree(BSL_SAL_SockAddr sockAddr);
int32_t SAL_NET_SockAddrGetFamily(const BSL_SAL_SockAddr sockAddr);
uint32_t SAL_NET_SockAddrSize(const BSL_SAL_SockAddr sockAddr);
void SAL_NET_SockAddrCopy(BSL_SAL_SockAddr dst, BSL_SAL_SockAddr src);
int32_t SAL_NET_Sendto(int32_t sock, const void *buf, size_t len, int32_t flags, void *address, int32_t addrLen,
                       int32_t *err);
int32_t SAL_NET_RecvFrom(int32_t sock, void *buf, size_t len, int32_t flags, void *address, int32_t *addrLen,
                         int32_t *err);

int32_t SAL_Socket(int32_t af, int32_t type, int32_t protocol);
int32_t SAL_SockClose(int32_t sockId);
int32_t SAL_SetSockopt(int32_t sockId, int32_t level, int32_t name, const void *val, int32_t len);
int32_t SAL_GetSockopt(int32_t sockId, int32_t level, int32_t name, void *val, int32_t *len);
int32_t SAL_SockListen(int32_t sockId, int32_t backlog);
int32_t SAL_SockBind(int32_t sockId, BSL_SAL_SockAddr addr, size_t len);
int32_t SAL_SockConnect(int32_t sockId, BSL_SAL_SockAddr addr, size_t len);
int32_t SAL_SockSend(int32_t sockId, const void *msg, size_t len, int32_t flags);
int32_t SAL_SockRecv(int32_t sockfd, void *buff, size_t len, int32_t flags);
int32_t SAL_Select(int32_t nfds, void *readfds, void *writefds, void *exceptfds, void *timeout);
int32_t SAL_Ioctlsocket(int32_t sockId, long cmd, unsigned long *arg);
int32_t SAL_SockGetLastSocketError(void);

#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_BSL_SAL_NET
#endif // SAL_NETIMPL_H
