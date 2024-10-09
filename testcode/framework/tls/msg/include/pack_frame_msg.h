/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef PACK_FRAME_MSG_H
#define PACK_FRAME_MSG_H

#include "frame_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Generate a framework message based on the content in the message buffer.
*
* @return Returns the CTX object of the TLS.
*/
int32_t PackFrameMsg(FRAME_Msg *msg);

#ifdef __cplusplus
}
#endif

#endif // PACK_FRAME_MSG_H