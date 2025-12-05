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

#ifdef HITLS_BSL_SAL_NET
#include <stdint.h>
#include <stdlib.h>
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "sal_netimpl.h"

int32_t BSL_SAL_Socket(int32_t af, int32_t type, int32_t protocol)
{
    if (SAL_GetNetCallBack().pfSocket != NULL && SAL_GetNetCallBack().pfSocket != BSL_SAL_Socket) {
        return SAL_GetNetCallBack().pfSocket(af, type, protocol);
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
    if (SAL_GetNetCallBack().pfSockClose != NULL && SAL_GetNetCallBack().pfSockClose != BSL_SAL_SockClose) {
        return SAL_GetNetCallBack().pfSockClose(sockId);
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
    if (SAL_GetNetCallBack().pfSetSocketopt != NULL && SAL_GetNetCallBack().pfSetSocketopt != BSL_SAL_SetSockopt) {
        return SAL_GetNetCallBack().pfSetSocketopt(sockId, level, name, val, len);
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
    if (SAL_GetNetCallBack().pfGetSocketopt != NULL && SAL_GetNetCallBack().pfGetSocketopt != BSL_SAL_GetSockopt) {
        return SAL_GetNetCallBack().pfGetSocketopt(sockId, level, name, val, len);
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
    if (SAL_GetNetCallBack().pfSockListen != NULL && SAL_GetNetCallBack().pfSockListen != BSL_SAL_SockListen) {
        return SAL_GetNetCallBack().pfSockListen(sockId, backlog);
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
    if (SAL_GetNetCallBack().pfSockBind != NULL && SAL_GetNetCallBack().pfSockBind != BSL_SAL_SockBind) {
        return SAL_GetNetCallBack().pfSockBind(sockId, addr, len);
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
    if (SAL_GetNetCallBack().pfSockConnect != NULL && SAL_GetNetCallBack().pfSockConnect != BSL_SAL_SockConnect) {
        return SAL_GetNetCallBack().pfSockConnect(sockId, addr, len);
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
    if (SAL_GetNetCallBack().pfSockSend != NULL && SAL_GetNetCallBack().pfSockSend != BSL_SAL_SockSend) {
        return SAL_GetNetCallBack().pfSockSend(sockId, msg, len, flags);
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
    if (SAL_GetNetCallBack().pfSockRecv != NULL && SAL_GetNetCallBack().pfSockRecv != BSL_SAL_SockRecv) {
        return SAL_GetNetCallBack().pfSockRecv(sockfd, buff, len, flags);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_NET_SockRecv(sockfd, buff, len, flags);
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_NET_NO_REG_FUNC);
    return -1;
#endif
}

#endif