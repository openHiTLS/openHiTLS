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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_BSL_SAL_NET */

#endif // SAL_NET_H
