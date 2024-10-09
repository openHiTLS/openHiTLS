/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SAL_NET_H
#define SAL_NET_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_NET

#include <stdint.h>
#include <fcntl.h>
#include <netinet/in.h>

#ifdef HITLS_BSL_SAL_LINUX
#include <arpa/inet.h>
#include <netinet/tcp.h>
#endif

#ifdef HITLS_BSL_UIO_SCTP
#include <netinet/sctp.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

int32_t BSL_SAL_Write(int32_t fd, const void *buf, uint32_t len, int32_t *err);

int32_t BSL_SAL_Read(int32_t fd, void *buf, uint32_t len, int32_t *err);

int32_t BSL_SAL_SetSockopt(int32_t sockId, int32_t level, int32_t name, const void *val, uint32_t len);

int32_t BSL_SAL_GetSockopt(int32_t sockId, int32_t level, int32_t name, void *val, uint32_t *len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_BSL_SAL_NET */

#endif // SAL_NET_H
