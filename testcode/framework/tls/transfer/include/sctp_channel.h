/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
