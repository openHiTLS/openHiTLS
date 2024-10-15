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

#ifndef UIO_BASE_H
#define UIO_BASE_H

#include "hitls_build.h"
#ifdef HITLS_BSL_UIO_PLT

#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

struct BSL_UIO_MethodStruct {
    int32_t type;
    BslUioWriteCb write;
    BslUioReadCb read;
    BslUioCtrlCb ctrl;
    BslUioPutsCb puts;
    BslUioGetsCb gets;
    BslUioCreateCb create;
    BslUioDestroyCb destroy;
};

/**
 * @ingroup bsl_uio
 *
 * @brief   Get the fd of the UIO object
 * @param   uio [IN] UIO object
 * @retval  File Descriptor fd
 */
int32_t BSL_UIO_GetFd(BSL_UIO *uio);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_UIO_PLT */

#endif // UIO_BASE_H

