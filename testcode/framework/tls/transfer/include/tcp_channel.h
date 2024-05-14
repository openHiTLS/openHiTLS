/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
