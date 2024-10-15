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

#ifndef SCTP_CHANNEL_H
#define SCTP_CHANNEL_H

#include <netinet/in.h>
#include <stdint.h>
#include "hitls.h"
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Initiate an SCTP connection
 */
int32_t SctpConnect(char *targetIP, int32_t targetPort, bool isBlock);

/**
 * @brief  Waiting for SCTP connection
 */
int32_t SctpAccept(char *ip, int listenFd, bool isBlock);

/**
 * @brief  Disable the SCTP connection
 */
void SctpClose(int fd);

/**
 * @brief  Obtain the default SCTP method
 */
BSL_UIO_Method *SctpGetDefaultMethod(void);

/**
 * @brief  Set the Ctrl command for registering the hook
 */
void SetNeedCbSctpCtrlCmd(int cmd);

int32_t SctpBind(int port);

// Default SCTP connection method
int32_t SctpDefaultWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen);
int32_t SctpDefaultRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen);
int32_t SctpDefaultCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *param);

// Change the SCTP connection of the message
int32_t SctpFrameWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen);
int32_t SctpFrameRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen);

#ifdef __cplusplus
}
#endif

#endif // SCTP_CHANNEL_H
