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

#endif /* HITLS_BSL_UIO_ADDR */

#ifdef __cplusplus
}
#endif

#endif
