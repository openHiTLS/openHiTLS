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

#ifndef FRAME_IO_H
#define FRAME_IO_H

#include "bsl_errno.h"
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_RECORD_LENTH (20 * 1024) // Simulates the bottom-layer sending and receiving processing of the DT framework.

typedef struct FrameUioUserData_ FrameUioUserData;

/**
 * @brief SCTP bottom-layer I/O function, which is used to simulate the SCTP message sending interface.
 *
 * @par Description:
 * SCTP bottom-layer I/O function, which is used to simulate the SCTP message sending interface.
 *
 * @attention
 * @return If the operation is successful, success is returned. Otherwise, other values are returned. In this framework,
 *         a success message is returned without special reasons.
 */
int32_t FRAME_Write(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen);


/**
 * @brief SCTP bottom-layer I/O function, which is used to simulate the SCTP message receiving interface.
 *
 * @par Description:
 * SCTP bottom-layer I/O function, which is used to simulate the SCTP message receiving interface.
 *
 * @attention
 * @return If the operation is successful, success is returned. Otherwise, other values are returned.
 */
int32_t FRAME_Read(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen);


/**
 * @brief SCTP bottom-layer I/O function, which is used to simulate the SCTP control interface.
 *
 * @par Description:
 * SCTP bottom-layer I/O function, which is used to simulate the SCTP control interface.
 *
 * @attention
 * @return If the operation is successful, success is returned. Otherwise, other values are returned.
 */
int32_t FRAME_Ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *param);

/**
* @brief  Create a UIO user data. The user data must be used when the I/O of the test framework is used. The user data
*         stores the data to be sent and received by the I/O.
*
* @return If the operation is successful, the pointer of userdata is returned.
*/
FrameUioUserData *FRAME_IO_CreateUserData(void);

/**
* @brief  Releases userdata created by the Frame_IO_CreateUserData function.
*
* @return  NA
*/
void FRAME_IO_FreeUserData(FrameUioUserData *userData);

/**
* @brief  Frame_TransportSendMsg sends the messages in the sending buffer in the I/O.
*
* @return  If the operation is successful, 0 is returned. Otherwise, another value is returned.
*/
int32_t FRAME_TransportSendMsg(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen);

/**
* @brief  Frame_TransportRecMsg simulates receiving messages from the I/O.
*
* @return  If the operation is successful, 0 is returned. Otherwise, another value is returned.
*/
int32_t FRAME_TransportRecMsg(BSL_UIO *uio, void *buf, uint32_t len);
#ifdef __cplusplus
}
#endif

#endif // FRAME_IO_H
