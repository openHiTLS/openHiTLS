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

#ifndef TCP_CHANNEL_H
#define TCP_CHANNEL_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Connects to the peer and returns a socket descriptor. */
int TcpConnect(const char *targetIP, const int targetPort);

/* listen */
int TcpBind(const int localPort);

/* accept */
int TcpAccept(char *ip, int listenFd, bool isBlock, bool needClose);

/* write */
int32_t TcpFrameWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen);

/*
 * When the Windows TCP server is used, the socket that is closed accept cannot be cleaned up.
 * Otherwise, the next accept operation will fail
 */
void TcpClose(int sd);

/* Default TCP method based on Linux */
void *TcpGetDefaultMethod(void);

#ifdef __cplusplus
}
#endif

#endif  // TCP_CHANNEL_H
