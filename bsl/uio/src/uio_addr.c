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
#ifdef HITLS_BSL_UIO_ADDR

#include <stdlib.h>
#include <stdbool.h>
#include "securec.h"
#include "uio_local.h"
#include "uio_abstraction.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_uio.h"

#define DECIMAL_BASE 10
#define BUF_SIZE 1024

#ifdef HITLS_BSL_UIO_CONNECT

// Obtain the UIO_AddrInfo address
const BSL_UIO_Addr *BSL_UIO_AddrInfoGetAddress(const BSL_UIO_AddrInfo *uioAddrInfo)
{
    if (uioAddrInfo == NULL) {
        return NULL;
    }
    return (BSL_UIO_Addr *)uioAddrInfo->uaiAddr;
}

// Obtain the protocol family of UIO_AddrInfo.
int32_t BSL_UIO_AddrInfoGetFamily(const BSL_UIO_AddrInfo *uioAddrInfo)
{
    if (uioAddrInfo == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    return uioAddrInfo->uaiFamily;
}

// Obtain the UIO_AddrInfo protocol
int32_t BSL_UIO_AddrInfoGetProtocol(const BSL_UIO_AddrInfo *uioAddrInfo)
{
    if (uioAddrInfo == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (uioAddrInfo->uaiProtocol != 0) {
        return uioAddrInfo->uaiProtocol;
    }
    if (uioAddrInfo->uaiFamily == AF_UNIX) {
        return 0;
    }
    switch (uioAddrInfo->uaiSocktype) {
        case SOCK_STREAM:
            return IPPROTO_TCP;
        case SOCK_DGRAM:
            return IPPROTO_UDP;
        default:
            break;
    }
    return 0;
}

// Obtain the socket type of UIO_AddrInfo
int32_t BSL_UIO_AddrInfoGetSocktype(const BSL_UIO_AddrInfo *uioAddrInfo)
{
    if (uioAddrInfo == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    return uioAddrInfo->uaiSocktype;
}

// Release the UIO_AddrInfo object
void BSL_UIO_AddrInfoFree(BSL_UIO_AddrInfo *uioAddrInfo)
{
    if (uioAddrInfo == NULL) {
        return;
    }
#ifdef AI_PASSIVE
#ifdef AF_UNIX
#define COND uioAddrInfo->uaiFamily != AF_UNIX
#else
#define COND 1
#endif
    if (COND) {
        freeaddrinfo(uioAddrInfo);
        return;
    }
#endif
    BSL_UIO_AddrInfo *curInfo = uioAddrInfo;
    BSL_UIO_AddrInfo *nextInfo = NULL;
    while (curInfo != NULL) {
        nextInfo = curInfo->uaiNext;
        BSL_SAL_FREE(curInfo->uaiAddr);
        BSL_SAL_FREE(curInfo);
        curInfo = nextInfo;
    }
}

const BSL_UIO_AddrInfo *BSL_UIO_AddrInfoNext(const BSL_UIO_AddrInfo *uioAddrInfo)
{
    if (uioAddrInfo == NULL) {
        return NULL;
    }
    return uioAddrInfo->uaiNext;
}

// Obtain protocol family of the UIO_Addr
int32_t BSL_UIO_AddrGetFamily(const BSL_UIO_Addr *uioAddr)
{
    if (uioAddr == NULL) {
        return AF_UNSPEC;
    }
    return uioAddr->addr.sa_family;
}

int32_t BSL_UIO_AddrRawMake(BSL_UIO_Addr *uioAddr, int32_t family, const void *where, uint32_t whereLen, uint16_t port)
{
    if (uioAddr == NULL || where == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (family == AF_INET) {
        if (whereLen != sizeof(struct in_addr)) {
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return BSL_INVALID_ARG;
        }
        (void)memset_s(&uioAddr->addrIn, sizeof(struct in_addr), 0, sizeof(struct in_addr));
        uioAddr->addrIn.sin_family = (uint16_t)family;
        uioAddr->addrIn.sin_port = port;
        uioAddr->addrIn.sin_addr = *(const struct in_addr *)where;
        return BSL_SUCCESS;
    }

    if (family == AF_INET6) {
        if (whereLen != sizeof(struct in6_addr)) {
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return BSL_INVALID_ARG;
        }
        (void)memset_s(&uioAddr->addrIn6, sizeof(struct in6_addr), 0, sizeof(struct in6_addr));
        uioAddr->addrIn6.sin6_family = (uint16_t)family;
        uioAddr->addrIn6.sin6_port = port;
        uioAddr->addrIn6.sin6_addr = *(const struct in6_addr *)where;
        return BSL_SUCCESS;
    }

    if (family == AF_UNIX) {
        if (whereLen + 1 > sizeof(uioAddr->addrUn.sun_path)) {
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_INVALID_ARG;
        }
        (void)memset_s(&uioAddr->addrUn, sizeof(uioAddr->addrUn), 0, sizeof(uioAddr->addrUn));
        uioAddr->addrUn.sun_family = (uint16_t)family;
        uint32_t pathLen = sizeof(uioAddr->addrUn.sun_path) - 1;
        (void)strncpy_s(uioAddr->addrUn.sun_path, pathLen, where, whereLen);
        return BSL_SUCCESS;
    }

    return BSL_UIO_FAIL;
}

int32_t BSL_UIO_AddrGetRawAddress(const BSL_UIO_Addr *uioAddr, void *addrPtr, size_t *length)
{
    if (uioAddr == NULL || (addrPtr == NULL && length == NULL)) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    uint32_t len = 0;
    const void *ptr = NULL;

    if (uioAddr->addr.sa_family == AF_INET) {
        len = sizeof(uioAddr->addrIn.sin_addr);
        ptr = &uioAddr->addrIn.sin_addr;
    } else if (uioAddr->addr.sa_family == AF_INET6) {
        len = sizeof(uioAddr->addrIn6.sin6_addr);
        ptr = &uioAddr->addrIn6.sin6_addr;
    } else if (uioAddr->addr.sa_family == AF_UNIX) {
        len = sizeof(uioAddr->addrUn.sun_path);
        ptr = &uioAddr->addrUn.sun_path;
    }

    if (ptr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    if (length != NULL) {
        *length = len;
    }

    if (addrPtr != NULL) {
        if (memcpy_s(addrPtr, length == NULL ? len : *length, ptr, len) != EOK) {
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
        }
    }

    return BSL_SUCCESS;
}

uint16_t BSL_UIO_AddrGetRawPort(const BSL_UIO_Addr *uioAddr)
{
    if (uioAddr == NULL) {
        return 0;
    }
    if (uioAddr->addr.sa_family == AF_INET) {
        return uioAddr->addrIn.sin_port;
    }
    if (uioAddr->addr.sa_family == AF_INET6) {
        return uioAddr->addrIn6.sin6_port;
    }
    return 0;
}


static int32_t GetHostName(const BSL_UIO_Addr *uioAddr, int32_t numeric, char **hostname)
{
#ifdef AI_PASSIVE
    char hostBuf[NI_MAXHOST] = "";
    int32_t flags = 0; // 0: Return the actual names; 1: Return the numeric expression.
    if ((bool)numeric) {
        flags = (int32_t)((uint32_t)flags | NI_NUMERICHOST | NI_NUMERICSERV);
    }
    if (getnameinfo(&(uioAddr->addr), BSL_UIO_SockAddrSize(uioAddr), hostBuf,
        sizeof(hostBuf), NULL, 0, flags) != 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    *hostname = BSL_SAL_Dump(hostBuf, (uint32_t)(strlen(hostBuf) + 1));
#else
    (void)numeric;
    char dottedNotation[INET_ADDRSTRLEN + 1] = {0};
    if (inet_ntop(AF_INET, (const void *)&uioAddr->addrIn.sin_addr, dottedNotation, INET_ADDRSTRLEN + 1) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    *hostname = BSL_SAL_Dump(dottedNotation, strlen(dottedNotation) + 1);
#endif
    if (*hostname == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_MEM_ALLOC_FAIL);
        return BSL_UIO_MEM_ALLOC_FAIL;
    }
    return BSL_SUCCESS;
}

static int32_t GetService(const BSL_UIO_Addr *uioAddr, int32_t numeric, char **service)
{
#ifdef AI_PASSIVE
    char serviceBuf[NI_MAXSERV] = "";
    int32_t flags = 0; // 0: Return the actual names; 1: Return the numeric expression.
    if ((bool)numeric) {
        flags = (int32_t)((uint32_t)flags | NI_NUMERICHOST | NI_NUMERICSERV);
    }
    if (getnameinfo(&(uioAddr->addr), BSL_UIO_SockAddrSize(uioAddr), NULL,
        0, serviceBuf, sizeof(serviceBuf), flags) != 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    if (serviceBuf[0] == '\0') {
        (void)sprintf_s(serviceBuf, sizeof(serviceBuf), "%u", ntohs(BSL_UIO_AddrGetRawPort(uioAddr)));
    }
    *service = BSL_SAL_Dump(serviceBuf, (uint32_t)(strlen(serviceBuf) + 1));
#else
#define U16_DECIMAL_DIGITS 5    // a uint16_t number occupies 5 decimal digits at most
    (void)numeric;
    char serv[U16_DECIMAL_DIGITS + 1] = {0};
    (void)sprintf_s(serv, sizeof(serv), "%u", ntohs(uioAddr->addrIn.sin_port));
    *service = BSL_SAL_Dump(serv, strlen(serv) + 1);
#endif
    if (*service == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_MEM_ALLOC_FAIL);
        return BSL_UIO_MEM_ALLOC_FAIL;
    }
    return BSL_SUCCESS;
}

char *BSL_UIO_AddrGetHostNameStr(const BSL_UIO_Addr *uioAddr, int32_t numeric)
{
    if (uioAddr == NULL) {
        return NULL;
    }
    char *hostname = NULL;
    if (GetHostName(uioAddr, numeric, &hostname) == BSL_SUCCESS) {
        return hostname;
    }
    return NULL;
}

char *BSL_UIO_AddrGetServiceStr(const BSL_UIO_Addr *uioAddr, int32_t numeric)
{
    if (uioAddr == NULL) {
        return NULL;
    }
    char *service = NULL;
    if (GetService(uioAddr, numeric, &service) == BSL_SUCCESS) {
        return service;
    }
    return NULL;
}


typedef struct {
    uint32_t whereLen;
    const void *where;
} Where;

// dealing non-IP protocol family
static int32_t SingleAddrInfoNodeFill(
    int32_t family, int32_t socktype, uint16_t port, const Where *from, BSL_UIO_AddrInfo **addrinfo)
{
    if (addrinfo == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    BSL_UIO_AddrInfo *info = (BSL_UIO_AddrInfo *)BSL_SAL_Calloc(1u, sizeof(BSL_UIO_AddrInfo));
    if (info == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    info->uaiFamily = family;
    info->uaiSocktype = socktype;
    if (socktype == SOCK_STREAM) {
        info->uaiProtocol = IPPROTO_TCP;
    } else if (socktype == SOCK_DGRAM) {
        info->uaiProtocol = IPPROTO_UDP;
    }
    if (family == AF_UNIX) {
        info->uaiProtocol = 0;
    }

    BSL_UIO_Addr *addr = BSL_UIO_AddrNew();
    int32_t ret = BSL_UIO_AddrRawMake(addr, family, from->where, from->whereLen, port);
    if (ret != BSL_SUCCESS) {
        BSL_UIO_AddrFree(addr);
        BSL_UIO_AddrInfoFree(info);
        *addrinfo = NULL;
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    info->uaiAddr = &(addr->addr);
    info->uaiNext = NULL;
    *addrinfo = info;
    return BSL_SUCCESS;
}

typedef struct {
    const char *host;
    const char *service;
    BSL_UIO_LookUpType lookUpType;
    int32_t family;
    int32_t socktype;
} LookUpPriorInfo;

#ifdef AI_PASSIVE
static int32_t DealAiPassive(const LookUpPriorInfo *info, BSL_UIO_AddrInfo **addrInfoList)
{
    struct addrinfo hints = {0};

    hints.ai_family = info->family;
    hints.ai_socktype = info->socktype;

    if (info->host != NULL && info->family == AF_UNSPEC) {
        hints.ai_flags = (int)(((unsigned int)hints.ai_flags) | AI_ADDRCONFIG);
    }

    if (info->lookUpType == BSL_UIO_LOOKUP_SERVER) {
        hints.ai_flags = (int)(((unsigned int)hints.ai_flags) | AI_PASSIVE);
    }
    int32_t ret = BSL_UIO_FAIL;

#if defined(AI_ADDRCONFIG) && defined(AI_NUMERICHOST)
retry:
#endif
    switch (getaddrinfo(info->host, info->service, &hints, addrInfoList)) {
#ifdef EAI_SYSTEM
        case EAI_SYSTEM:
            ret = BSL_UIO_FAIL;
            break;
#endif
#ifdef EAI_MEMORY
        case EAI_MEMORY:
            ret = BSL_UIO_FAIL;
            break;
#endif
        case 0:
            ret = BSL_SUCCESS;
            break;
        default:
#if defined(AI_ADDRCONFIG) && defined(AI_NUMERICHOST)
            if ((((unsigned int)hints.ai_flags) & AI_ADDRCONFIG) != 0) {
                hints.ai_flags = (int)(((unsigned int)hints.ai_flags) & ~AI_ADDRCONFIG);
                hints.ai_flags = (int)(((unsigned int)hints.ai_flags) | AI_NUMERICHOST);
                goto retry;
            }
#endif
            break;
    }
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}
#endif

static int32_t DealAddrInfoList(const struct hostent *he, const struct servent *se, int32_t socktype,
    BSL_UIO_AddrInfo **addrInfoList)
{
    *addrInfoList = NULL;

    BSL_UIO_AddrInfo *tmpAddrInfo = NULL;
    char **addrListPtr = he->h_addr_list;
    // Move to the end of h_addr_list.
    while (*addrListPtr != NULL) {
        addrListPtr++;
    }
    // There are (addrlistp - he->h_addr_list) addresses in total.
    // One address is processed each time from the end of the linked list.
    for (uint32_t addrNum = addrListPtr - he->h_addr_list; addrNum > 0; addrNum--) {
        addrListPtr--;
        Where cur = { 0 };
        cur.where = *addrListPtr;
        cur.whereLen = (uint32_t)he->h_length;
        if (SingleAddrInfoNodeFill(he->h_addrtype, socktype, (uint16_t)se->s_port, &cur, &tmpAddrInfo) != BSL_SUCCESS) {
            BSL_UIO_AddrInfoFree(*addrInfoList);
            *addrInfoList = NULL;
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
        }
        // Appends a new node forward from the end of the linked list.
        tmpAddrInfo->uaiNext = *addrInfoList;
        *addrInfoList = tmpAddrInfo;
    }
    return BSL_SUCCESS;
}

static int32_t DealServent(const char *service, int32_t socktype, struct servent *seFallback, struct servent **sePtr)
{
    int32_t ret = 0;
    if (service == NULL) {
        seFallback->s_port = 0;
        seFallback->s_proto = NULL;
        *sePtr = seFallback;
        return BSL_SUCCESS;
    } else {
        char *endp = NULL;
        // Convert the service string to the port number.
        long portnum = strtol(service, &endp, DECIMAL_BASE);
        const char *protocolStr = NULL;
        if (socktype == SOCK_STREAM) {
            protocolStr = "tcp";
        } else if (socktype == SOCK_DGRAM) {
            protocolStr = "udp";
        }
        if (endp != service && *endp == '\0' && portnum > 0 && portnum < UINT16_MAX) {
            seFallback->s_port = htons((uint16_t)portnum);
            seFallback->s_proto = (char *)(uintptr_t)protocolStr;
            *sePtr = seFallback;
            return BSL_SUCCESS;
        } else if (endp == service) {
            *sePtr = getservbyname(service, protocolStr);
            if (*sePtr == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
                return BSL_UIO_FAIL;
            }
            ret = BSL_SUCCESS;
        } else {
            ret = BSL_UIO_FAIL;
        }
    }
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}

/* Handle of the thread lock */
static BSL_SAL_ThreadLockHandle g_errLock = NULL;

static int32_t DealLookUp(const LookUpPriorInfo *info, BSL_UIO_AddrInfo **addrInfoList)
{
    int32_t ret = 0;
    if (true) {
#ifdef AI_PASSIVE
        ret = DealAiPassive(info, addrInfoList);
        if (ret != 0) {
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
        }
    } else {
#endif
        struct hostent *he = NULL;
        static in_addr_t heFallbackAddress;
        static char *heFallbackAddresses[] = {(char *)&heFallbackAddress, NULL};
        static struct hostent heFallback = {
            NULL, NULL, AF_INET, sizeof(heFallbackAddress), (char **)&heFallbackAddresses};

        BSL_SAL_ThreadWriteLock(g_errLock);
        // The backup address is the local address.
        heFallbackAddress = INADDR_ANY;
        // Process the he based on whether the host is not empty.
        if (info->host == NULL) {
            he = &heFallback;
            if (info->lookUpType == BSL_UIO_LOOKUP_CLIENT) {
                heFallbackAddress = INADDR_LOOPBACK;
            }
        } else {
            char buf[BUF_SIZE] = {0};
            struct hostent hostRet = {0};
            int errnop = 0;
            if (gethostbyname_r(info->host, &hostRet, buf, BUF_SIZE, (struct hostent **)&he, &errnop) != 0 ||
                he == NULL) {
                BSL_SAL_ThreadUnlock(g_errLock);
                BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
                return BSL_UIO_FAIL;
            }
        }
        struct servent *se = NULL;
        struct servent seFallback = {NULL, NULL, 0, NULL};
        ret = DealServent(info->service, info->socktype, &seFallback, &se);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_ThreadUnlock(g_errLock);
            return ret;
        }
        ret = DealAddrInfoList(he, se, info->socktype, addrInfoList);
        BSL_SAL_ThreadUnlock(g_errLock);
    }
    return ret;
}

int32_t BSL_UIO_LookUp(const char *host, const char *service, BSL_UIO_LookUpType lookUpType, int32_t family,
    int32_t socktype, BSL_UIO_AddrInfo **addrInfoList)
{
    if (!(family == AF_INET || family == AF_INET6 || family == AF_UNIX || family == AF_UNSPEC)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    if (family == AF_UNIX) {
        Where destHost = {0};
        destHost.where = host;
        destHost.whereLen = (uint32_t)strlen(host);
        return SingleAddrInfoNodeFill(family, socktype, 0, &destHost, addrInfoList);
    }
    LookUpPriorInfo info = {host, service, lookUpType, family, socktype};

    return DealLookUp(&info, addrInfoList);
}

static int32_t ParseIPv6HostService(const char *hostService, const char **hostName, size_t *hostLength,
    const char **serviceName)
{
    const char *service = NULL;
    const char *host = NULL;
    if ((service = strchr(hostService, ']')) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    host = hostService + 1;
    *hostLength = service - host;
    service++;
    if (*service == '\0') {
        service = NULL;
    } else if (*service != ':') {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    } else {
        service++;
    }
    *hostName = host;
    *serviceName = service;

    return BSL_SUCCESS;
}

static int32_t ParseIPv4HostService(const char *hostService, const char **hostName, size_t *hostLength,
    const char **serviceName, BSL_UIO_HostServicePriorities hostServicePrio)
{
    const char *service = NULL;
    const char *host = NULL;
    const char *lastColon = strrchr(hostService, ':');
    service = strchr(hostService, ':');
    // Forbid the number of addresses exceed one colon in IPv6.
    if (service != lastColon) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    if (service != NULL) {
        host = hostService;
        *hostLength = service - host;
        service++;
    } else if (hostServicePrio == BSL_UIO_PARSE_PRIO_HOST) {
        host = hostService;
        *hostLength = strlen(host);
    } else {
        service = hostService;
    }
    *hostName = host;
    *serviceName = service;
    return BSL_SUCCESS;
}

static int32_t GetHostService(const char *hostName, size_t hostLength, const char *serviceName,
    char **host, char **service)
{
    if (hostName != NULL && host != NULL) {
        if (hostLength == 0 || (hostLength == 1 && hostName[0] == '*')) {
            *host = NULL;
        } else {
            *host = (char *)BSL_SAL_Dump(hostName, (uint32_t)hostLength + 1);
            if (*host == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
                return BSL_UIO_FAIL;
            }
            (*host)[hostLength] = '\0';
        }
    }
    if (serviceName != NULL && service != NULL) {
        uint32_t serviceLength = (uint32_t)strlen(serviceName);
        if (serviceLength == 0 || (serviceLength == 1 && serviceName[0] == '*')) {
            *service = NULL;
        } else {
            *service = (char *)BSL_SAL_Dump(serviceName, serviceLength + 1);
            if (*service == NULL) {
                char *hostPtr = (host != NULL) ? *host : NULL;
                BSL_SAL_FREE(hostPtr);
                BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
                return BSL_UIO_FAIL;
            }
            (*service)[serviceLength] = '\0';
        }
    }

    return BSL_SUCCESS;
}

int32_t BSL_UIO_ParseHostService(const char *hostService, char **host, char **service,
    BSL_UIO_HostServicePriorities hostServicePrio)
{
    if (hostService == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    const char *hostName = NULL;
    size_t hostLength = 0;
    const char *serviceName = NULL;
    int32_t ret = BSL_SUCCESS;

    if (*hostService == '[') {
        ret = ParseIPv6HostService(hostService, &hostName, &hostLength, &serviceName);
    } else {
        ret = ParseIPv4HostService(hostService, &hostName, &hostLength, &serviceName, hostServicePrio);
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    if (serviceName != NULL && strchr(serviceName, ':')) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    return GetHostService(hostName, hostLength, serviceName, host, service);
}

#endif  // end HITLS_BSL_UIO_CONNECT

// Release the UIO_Addr object
void BSL_UIO_AddrFree(BSL_UIO_Addr *uioAddr)
{
    BSL_SAL_FREE(uioAddr);
}

// Create the UIO_Addr object
BSL_UIO_Addr *BSL_UIO_AddrNew(void)
{
    BSL_UIO_Addr *addr = (BSL_UIO_Addr *)BSL_SAL_Calloc(1u, sizeof(BSL_UIO_Addr));
    if (addr == NULL) {
        return NULL;
    }
    addr->addr.sa_family = AF_UNSPEC;
    return addr;
}

int32_t BSL_UIO_AddrMake(BSL_UIO_Addr *uioAddr, const struct sockaddr *sockAddr)
{
    if (sockAddr->sa_family == AF_INET) {
        (void)memcpy_s(&(uioAddr->addrIn), sizeof(BSL_UIO_Addr), sockAddr, sizeof(struct sockaddr_in));
    } else if (sockAddr->sa_family == AF_INET6) {
        (void)memcpy_s(&(uioAddr->addrIn6), sizeof(BSL_UIO_Addr), sockAddr, sizeof(struct sockaddr_in6));
    } else if (sockAddr->sa_family == AF_UNIX) {
        (void)memcpy_s(&(uioAddr->addrUn), sizeof(BSL_UIO_Addr), sockAddr, sizeof(struct sockaddr_un));
    } else {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    return BSL_SUCCESS;
}

uint32_t BSL_UIO_SockAddrSize(const BSL_UIO_Addr *uioAddr)
{
    switch (uioAddr->addr.sa_family) {
        case AF_INET:
            return sizeof(uioAddr->addrIn);
        case AF_INET6:
            return sizeof(uioAddr->addrIn6);
        case AF_UNIX:
            return sizeof(uioAddr->addrUn);
        default:
            break;
    }
    return sizeof(BSL_UIO_Addr);
}

#endif /* HITLS_BSL_UIO_ADDR */
