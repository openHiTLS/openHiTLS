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
    switch (sockAddr->sa_family) {
        case AF_INET:
            (void)memcpy_s(&(uioAddr->addrIn), sizeof(BSL_UIO_Addr), sockAddr, sizeof(struct sockaddr_in));
            break;
        case AF_INET6:
            (void)memcpy_s(&(uioAddr->addrIn6), sizeof(BSL_UIO_Addr), sockAddr, sizeof(struct sockaddr_in6));
            break;
        case AF_UNIX:
            (void)memcpy_s(&(uioAddr->addrUn), sizeof(BSL_UIO_Addr), sockAddr, sizeof(struct sockaddr_un));
            break;
        default:
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
