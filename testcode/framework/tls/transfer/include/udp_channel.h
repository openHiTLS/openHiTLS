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

#ifndef UDP_CHANNEL_H
#define UDP_CHANNEL_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Connects to the peer and returns a socket descriptor. */
int UdpConnect(const char *targetIP, const int targetPort);

/* listen */
int UdpBind(const int localPort);

/* accept */
int UdpAccept(int32_t fd, struct sockaddr *sockAddr);

/* write */
int32_t UdpFrameWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen);

void UdpClose(int sd);

/* Default UDP method based on Linux */
void *UdpGetDefaultMethod(void);

#ifdef __cplusplus
}
#endif

#endif  // UDP_CHANNEL_H
