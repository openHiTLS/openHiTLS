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