/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef UIO_TCP_H
#define UIO_TCP_H

#include "hitls_build.h"
#ifdef HITLS_BSL_UIO_TCP

#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t TcpWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen);
int32_t TcpRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_UIO_TCP */

#endif // UIO_TCP_H
