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

#ifndef UIO_LOCAL_H
#define UIO_LOCAL_H
#if defined(__linux__) || defined(__unix__)
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>
#else
#error "only support linux"
#endif
#include "sal_atomic.h"
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef AI_PASSIVE
# if defined(__INITIAL_POINTER_SIZE) && __INITIAL_POINTER_SIZE == 64
#define addrinfo __addrinfo64
# endif

#define UIO_AddressInfo addrinfo
#define uaiFamily ai_family
#define uaiSocktype ai_socktype
#define uaiProtocol ai_protocol
#define uaiAddrLen ai_addrlen
#define uaiAddr ai_addr
#define uaiNext ai_next
#else
struct UIO_AddressInfo {
    int32_t uaiFamily;
    int32_t uaiSocktype;
    int32_t uaiProtocol;
    uint32_t uaiAddrLen;
    struct sockaddr *uaiAddr;
    struct UIO_AddressInfo *uaiNext;
};
#endif

union UIO_Address {
    struct sockaddr addr;
    struct sockaddr_in6 addrIn6;
    struct sockaddr_in addrIn;
    struct sockaddr_un addrUn;
};

#ifdef HITLS_BSL_UIO_ADDR

/**
 * @ingroup bsl
 * @brief   Create a BSL_UIO_Addr
 *
 * @return New BSL_UIO_Addr object
 */
BSL_UIO_Addr *BSL_UIO_AddrNew(void);

/**
 * @ingroup bsl
 * @brief   Release the UIO_Addr object.
 *
 * @param   uioAddr [IN] UIO_Addr object
 */
void BSL_UIO_AddrFree(BSL_UIO_Addr *uioAddr);

/**
 * @ingroup bsl
 *
 * @brief   Obtain the size of the BSL_UIO_Addr address.
 * @details Only for internal use
 *
 * @param   uioAddr   [IN] UIO object
 * @retval  Address size
 */
uint32_t BSL_UIO_SockAddrSize(const BSL_UIO_Addr *uioAddr);

/**
 * @ingroup bsl
 *
 * @brief   Assign the address of sockaddr to BSL_UIO_Addr.
 * @details Only for internal use
 *
 * @param   uioAddr   [IN/OUT] UIO object
 * @param   sockAddr  [IN] sockAddr
 * @retval  BSL_SUCCESS, indicating success
 * @retval  BSL_UIO_FAIL, indicating failure
 */
int32_t BSL_UIO_AddrMake(BSL_UIO_Addr *uioAddr, const struct sockaddr *sockAddr);


# ifdef HITLS_BSL_UIO_CONNECT

#define CONN_HOSTNAME_OPTION 0
#define CONN_PORT_OPTION     1
#define CONN_ADDRESS_OPTION  2
#define CONN_FAMILY_OPTION   3

/**
 * @ingroup bsl
 *
 * @brief   UIO_AddrInfo structure
 */
typedef struct UIO_AddressInfo BSL_UIO_AddrInfo;

/**
 * @ingroup bsl
 *
 * @brief   UIO_AddrInfo lookup type
 */

typedef enum {
    BSL_UIO_LOOKUP_CLIENT,
    BSL_UIO_LOOKUP_SERVER
} BSL_UIO_LookUpType;

typedef enum {
    BSL_UIO_PARSE_PRIO_HOST, BSL_UIO_PARSE_PRIO_SERV
} BSL_UIO_HostServicePriorities;

#define BSL_UIO_FAMILY_IPV4         4
#define BSL_UIO_FAMILY_IPV6         6
#define BSL_UIO_FAMILY_IPANY        256
#define BSL_UIO_SOCK_REUSEADDR          0x01
#define BSL_UIO_SOCK_V6_ONLY            0x02
#define BSL_UIO_SOCK_KEEPALIVE          0x04
#define BSL_UIO_SOCK_NONBLOCK           0x08
#define BSL_UIO_SOCK_NODELAY            0x10

/* RR indicates RetryReason */
#define BSL_UIO_RR_SSL_X509_LOOKUP      0x01
#define BSL_UIO_RR_CONNECT              0x02
#define BSL_UIO_RR_ACCEPT               0x03

/**
 * @ingroup bsl
 * @brief   Obtain the UIO_AddrInfo address.
 *
 * @param   uioAddrInfo [IN] UIO_AddrInfo Object
 *
 * @return BSL_UIO address
 */
const BSL_UIO_Addr *BSL_UIO_AddrInfoGetAddress(const BSL_UIO_AddrInfo *uioAddrInfo);

/**
 * @ingroup bsl
 * @brief   Obtain the UIO_AddrInfo protocol suite
 *
 * @param   uioAddrInfo [IN] UIO_AddrInfo Object
 *
 * @return Protocol family
 */
int32_t BSL_UIO_AddrInfoGetFamily(const BSL_UIO_AddrInfo *uioAddrInfo);

/**
 * @ingroup bsl
 * @brief   obtain the Protocol of UIO_AddrInfo
 *
 * @param   uioAddrInfo [IN] UIO_AddrInfo Object
 *
 * @return Protocol type.
 */
int32_t BSL_UIO_AddrInfoGetProtocol(const BSL_UIO_AddrInfo *uioAddrInfo);

/**
 * @ingroup bsl
 * @brief   Obtain the socket type of UIO_AddrInfo.
 *
 * @param   uioAddrInfo [IN] UIO_AddrInfo Object
 *
 * @return Socket type
 */
int32_t BSL_UIO_AddrInfoGetSocktype(const BSL_UIO_AddrInfo *uioAddrInfo);

/**
 * @ingroup bsl
 * @brief   Release the UIO_AddrInfo object
 *
 * @param   uioAddrInfo [IN] UIO_AddrInfo Object
 */
void BSL_UIO_AddrInfoFree(BSL_UIO_AddrInfo *uioAddrInfo);

/**
 * @ingroup bsl
 * @brief   Obtain the UIO_AddrInfo protocol family
 *
 * @param   uioAddrInfo [IN] UIO_AddrInfo Object
 *
 * @return Next UIO_AddrInfo object
 */
const BSL_UIO_AddrInfo *BSL_UIO_AddrInfoNext(const BSL_UIO_AddrInfo *uioAddrInfo);

/**
 * @ingroup bsl
 * @brief   Find the host and service you want to connect to.
 *
 * @param   host [IN] Host to be connected
 * @param   service [IN] Service to be connected
 * @param   lookUpType [IN] Client or SERVER
 * @param   family [IN] Protocol family used by the local end
 * @param   socktype [IN] Socket type used by the local end
 * @param   addrInfoList [OUT] UIO_AddrInfo chain of the address information to be connected.
 * @retval BSL_SUCCESS, succeeded.
 * @retval Non-BSL_SUCCESS, failure. For details, see bsl_errno.h.
 */
int32_t BSL_UIO_LookUp(const char *host, const char *service, BSL_UIO_LookUpType lookUpType,
                       int32_t family, int32_t socktype, BSL_UIO_AddrInfo **addrInfoList);

/**
 * @ingroup bsl
 * @brief   Obtain the UIO_Addr protocol family
 *
 * @param   uioAddr [IN] UIO_AddrInfo Object
 *
 * @return Protocol family
 */
int32_t BSL_UIO_AddrGetFamily(const BSL_UIO_Addr *uioAddr);

/**
 * @ingroup bsl
 * @brief   Obtain the string of the host name corresponding to the specified UIO_Addr.
 *
 * @param   uioAddr [IN] UIO_Addr object
 * @param   numeric [IN] Return the format setting.
 * The value 0 indicates the actual host name, and the value 1 indicates the number.
 *
 * @return Character string of the host name
 */
char *BSL_UIO_AddrGetHostNameStr(const BSL_UIO_Addr *uioAddr, int32_t numeric);

/**
 * @ingroup bsl
 * @brief    Obtain the service string corresponding to the specified UIO_Addr.
 *
 * @param   uioAddr [IN] UIO_Addr object
 * @param   numeric [IN] Return the format setting. If the value is 1, the string contains the port number.
 *
 * @return Service name string
 */
char *BSL_UIO_AddrGetServiceStr(const BSL_UIO_Addr *uioAddr, int32_t numeric);

/**
 * @ingroup bsl
 * @brief   Fill BSL_UIO_Addr with the given value
 *
 * @param   uioAddr [OUT] BSL_UIO_Addr object to be filled
 * @param   family [IN] Padding protocol family
 * @param   where [IN] Peer address in network byte order
 * @param   whereLen [IN] Peer address length
 * @param   port [IN] Fill in port number
 * @retval BSL_SUCCESS, succeeded.
 * @retval Non-BSL_SUCCESS, failure.
 */
int32_t BSL_UIO_AddrRawMake(BSL_UIO_Addr *uioAddr, int32_t family, const void *where,
                            uint32_t whereLen, uint16_t port);

/**
 * @ingroup bsl
 * @brief   Fill the value of BSL_UIO_Addr to the specified address pointer.
 *
 * @param   uioAddr [IN] BSL_UIO_Addr object to be filled
 * @param   addrPtr [OUT] Pointer to the target padding address
 * @param   length [OUT] Padding length
 * @retval BSL_SUCCESS, succeeded.
 * @retval Non-BSL_SUCCESS, failure.
 */
int32_t BSL_UIO_AddrGetRawAddress(const BSL_UIO_Addr *uioAddr, void *addrPtr, size_t *length);

/**
 * @ingroup bsl
 * @brief   Get the original port with the given UIO_Addr
 *
 * @param   uioAddr [IN] UIO_Addr object
 *
 * @return Original port number of UIO_Addr
 */
uint16_t BSL_UIO_AddrGetRawPort(const BSL_UIO_Addr *uioAddr);

/**
 * @ingroup bsl
 * @brief Parses the information given in hostService, creates a string containing the host name and
 * service name, and returns these strings as formal parameters
 *
 * @param hostService  [IN] A string containing the host and service names.
 * @param host  [OUT] Host name.
 * @param service  [OUT] Service name.
 * @param hostServicePrio  [IN] Priority of the host or service.
 *
 * @retval BSL_SUCCESS, parsed successfully.
 *         BSL_UIO_FAIL, parsing the message fails.
 */
int32_t BSL_UIO_ParseHostService(const char *hostService, char **host, char **service,
    BSL_UIO_HostServicePriorities hostServicePrio);

/**
 * @ingroup bsl
 * @brief   This function is used to create and return a UIO of the connection type and call
 * BSL_UIO_ConnMethod(), BSL_UIO_New, and BSL_UIO_setConnHostname function completes the entire operation.
 * If the operation is successful, a UIO is returned. Otherwise, NULL is returned.
 *
 * @param   hostName [IN] Host name
 *
 * @return UIO of a connection type
 */
BSL_UIO *BSL_UIO_NewConnect(const char *hostName);

# endif /* HITLS_BSL_UIO_CONNECT */

#endif /* HITLS_BSL_UIO_ADDR */

#ifdef __cplusplus
}
#endif

#endif
