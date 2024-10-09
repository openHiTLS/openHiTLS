/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

