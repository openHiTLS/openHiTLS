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

#ifndef SOCKET_COMMON_H
#define SOCKET_COMMON_H

#include <stdint.h>
#include "hlt_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Sock Set the block
 */
int32_t SetBlockMode(int32_t sd, bool isBlock);

/**
 * @brief   Check whether there are fatal I/O errors
 */
bool IsNonFatalErr(int32_t err);

/**
 * @brief  Set the message injection parameter, which must be used with the CleantFrameHandle
 */
int32_t SetFrameHandle(HLT_FrameHandle *frameHandle);

/**
 * @brief  Clear message injection parameters
 */
void CleanFrameHandle(void);

/**
 * @brief  Obtain message injection parameters
 */
HLT_FrameHandle *GetFrameHandle(void);

/**
 * @brief  Obtain the newbuf by parsing the buf. Constraint: The input parameter of packLen cannot be empty
 */
uint8_t *GetNewBuf(const void *buf, uint32_t len, uint32_t *packLen);

/**
 * @brief  Release the newbuf applied by GetNewBuf
 */
void FreeNewBuf(void *newBuf);

#ifdef __cplusplus
}
#endif

#endif  // SOCKET_COMMON_H