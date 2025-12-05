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
    BslSalNetWrite pfWrite;
    BslSalNetRead pfRead;
    BslSalSocket pfSocket;
    BslSalSockClose pfSockClose;
    BslSalSetSockopt pfSetSocketopt;
    BslSalGetSockopt pfGetSocketopt;
    BslSalSockListen pfSockListen;
    BslSalSockBind pfSockBind;
    BslSalSockConnect pfSockConnect;
    BslSalSockSend pfSockSend;
    BslSalSockRecv pfSockRecv;
    BslSelect pfSelect;
    BslIoctlSocket pfIoctlsocket;
    BslGetErrno pfGetErrno;
    BslSalSockAddrNew pfSockAddrNew;
    BslSalSockAddrFree pfSockAddrFree;
    BslSalSockAddrSize pfSockAddrSize;
    BslSalSockAddrCopy pfSockAddrCopy;
    BslSalNetSendTo pfSendTo;
    BslSalNetRecvFrom pfRecvFrom;
    BslSalSockAddrGetFamily pfSockAddrGetFamily;
} BSL_SAL_NetCallback;

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
int32_t SAL_NET_SockAddrNew(BSL_SAL_SockAddr *sockAddr);
void SAL_NET_SockAddrFree(BSL_SAL_SockAddr sockAddr);
uint32_t SAL_NET_SockAddrSize(const BSL_SAL_SockAddr sockAddr);
void SAL_NET_SockAddrCopy(BSL_SAL_SockAddr dst, BSL_SAL_SockAddr src);
int32_t SAL_NET_SockAddrGetFamily(const BSL_SAL_SockAddr sockAddr);

int32_t SAL_NET_Write(int32_t fd, const void *buf, uint32_t len, int32_t *err);

int32_t SAL_NET_Read(int32_t fd, void *buf, uint32_t len, int32_t *err);
int32_t SAL_NET_Socket(int32_t af, int32_t type, int32_t protocol);

int32_t SAL_NET_SockClose(int32_t sockId);

int32_t SAL_NET_SetSockopt(int32_t sockId, int32_t level, int32_t name, const void *val, int32_t len);

int32_t SAL_NET_GetSockopt(int32_t sockId, int32_t level, int32_t name, void *val, int32_t *len);

int32_t SAL_NET_SockListen(int32_t sockId, int32_t backlog);

int32_t SAL_NET_SockBind(int32_t sockId, BSL_SAL_SockAddr addr, size_t len);

int32_t SAL_NET_SockConnect(int32_t sockId, BSL_SAL_SockAddr addr, size_t len);

int32_t SAL_NET_SockSend(int32_t sockId, const void *msg, size_t len, int32_t flags);

int32_t SAL_NET_SockRecv(int32_t sockfd, void *buff, size_t len, int32_t flags);

int32_t SAL_NET_Select(int32_t nfds, void *readfds, void *writefds, void *exceptfds, void *timeout);

int32_t SAL_NET_Ioctlsocket(int32_t sockId, long cmd, unsigned long *arg);

int32_t SAL_NET_SockGetErrno(void);

int32_t SAL_NET_Sendto(int32_t sock, const void *buf, size_t len, int32_t flags, void *address, int32_t addrLen,
                       int32_t *err);
int32_t SAL_NET_Recvfrom(int32_t sock, void *buf, size_t len, int32_t flags, void *address, int32_t *addrLen,
                         int32_t *err);

#endif

BSL_SAL_NetCallback SAL_GetNetCallBack(void);

int32_t SAL_NetCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_BSL_SAL_NET
#endif // SAL_NETIMPL_H
