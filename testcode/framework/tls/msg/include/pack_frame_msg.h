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