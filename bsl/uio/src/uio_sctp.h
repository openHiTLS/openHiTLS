/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef UIO_SCTP_H
#define UIO_SCTP_H

#include "hitls_build.h"
#ifdef HITLS_BSL_UIO_SCTP

#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTLS_SCTP_SHARE_AUTHKEY_ID_MAX 65535

int32_t SctpWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen);
int32_t SctpRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_UIO_SCTP */

#endif // UIO_SCTP_H

