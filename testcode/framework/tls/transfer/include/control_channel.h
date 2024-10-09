/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CONTROL_CHANNEL_H
#define CONTROL_CHANNEL_H

#include "channel_res.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Initialize the control channel
 */
int ControlChannelInit(ControlChannelRes *info);

/**
 * @brief  Close the control channel
 */
int ControlChannelClose(ControlChannelRes *info);

/**
 * @brief  Read data from the control channel
 */
int ControlChannelRead(int32_t sockFd, ControlChannelBuf *dataBuf);

/**
 * @brief  Write data to the control channel
 */
int ControlChannelWrite(int32_t sockFd, char *peerDomainPath, ControlChannelBuf *dataBuf);

/**
 * @brief  Control channel initiation
 */
int ControlChannelConnect(ControlChannelRes *info);

/**
 * @brief  The control channel waits for a connection
 */
int ControlChannelAccept(ControlChannelRes *info);

#ifdef __cplusplus
}
#endif

#endif // CONTROL_CHANNEL_H