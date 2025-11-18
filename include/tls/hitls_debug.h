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

/**
 * @defgroup hitls_crypt_reg
 * @ingroup hitls
 * @brief  hitls maintenance and debugging
 */

#ifndef HITLS_DEBUG_H
#define HITLS_DEBUG_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INDICATE_VALUE_SUCCESS               1u

#define INDICATE_EVENT_LOOP                  0x01    // 0000 0000 0000 0001, Handshake state transition
#define INDICATE_EVENT_EXIT                  0x02    // 0000 0000 0000 0010, Handshake status exit
#define INDICATE_EVENT_READ                  0x04    // 0000 0000 0000 0100, Read event
#define INDICATE_EVENT_WRITE                 0x08    // 0000 0000 0000 1000, Write event
#define INDICATE_EVENT_HANDSHAKE_START       0x10    // 0000 0000 0001 0000, Handshake Start
#define INDICATE_EVENT_HANDSHAKE_DONE        0x20    // 0000 0000 0010 0000, Handshake completed
#define INDICATE_EVENT_STATE_CONNECT         0x1000  // 0001 0000 0000 0000, Local client
#define INDICATE_EVENT_STATE_ACCEPT          0x2000  // 0010 0000 0000 0000, Local server
#define INDICATE_EVENT_ALERT                 0x4000  // 0100 0000 0000 0000, Warning Time

#define INDICATE_EVENT_READ_ALERT            (INDICATE_EVENT_ALERT | INDICATE_EVENT_READ)
#define INDICATE_EVENT_WRITE_ALERT           (INDICATE_EVENT_ALERT | INDICATE_EVENT_WRITE)
#define INDICATE_EVENT_STATE_ACCEPT_LOOP     (INDICATE_EVENT_STATE_ACCEPT | INDICATE_EVENT_LOOP)
#define INDICATE_EVENT_STATE_ACCEPT_EXIT     (INDICATE_EVENT_STATE_ACCEPT | INDICATE_EVENT_EXIT)
#define INDICATE_EVENT_STATE_CONNECT_LOOP    (INDICATE_EVENT_STATE_CONNECT | INDICATE_EVENT_LOOP)
#define INDICATE_EVENT_STATE_CONNECT_EXIT    (INDICATE_EVENT_STATE_CONNECT | INDICATE_EVENT_EXIT)

/**
 * @ingroup hitls_debug
 * @brief   Information prompt callback prototype
 *
 * @attention The message prompt callback function does not return a value
 * @param   ctx       [IN] Ctx context
 * @param   eventType [IN] EventType Event type
 * @param   value     [IN] Value Function return value or Alert type that matches the event type
 * @retval  No value is returned.
 */
typedef void (*HITLS_InfoCb)(const HITLS_Ctx *ctx, int32_t eventType, int32_t value);

/**
 * @ingroup hitls_debug
 * @brief   Set the callback for prompt information.
 *
 * @param   ctx      [OUT] Ctx context
 * @param   callback [IN] Callback function for prompting information
 * @retval  HITLS_SUCCESS, if successful.
 *          For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetInfoCb(HITLS_Ctx *ctx, HITLS_InfoCb callback);

/**
 * @ingroup hitls_debug
 * @brief   Callback for obtaining information
 *
 * @param   ctx [IN] Ctx context
 * @retval  Callback function of the current information prompt.
 *          If this parameter is not set, NULL is returned.
 */
HITLS_InfoCb HITLS_GetInfoCb(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_debug
 * @brief   Set the callback function for prompting information.
 *
 * @param   config [OUT] Config Context
 * @param   callback [IN] Client callback
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetInfoCb(HITLS_Config *config, HITLS_InfoCb callback);

/**
 * @ingroup hitls_debug
 * @brief   Callback function for obtaining information prompts
 *
 * @param   config  [IN] config Context
 * @retval  Callback function of the current information prompt.
 * If this parameter is not set, NULL is returned.
 */
HITLS_InfoCb HITLS_CFG_GetInfoCb(const HITLS_Config *config);

/**
 * @ingroup hitls_debug
 * @brief   Callback prototype of a protocol message
 *
 * @attention:  The callback function for messages in the retention protocol does not return any value.
 * @param   writePoint [IN] writePoint  Message direction in the callback ">>>" or "<<<"
 * @param   tlsVersion [IN] tlsVersion  TLS version, for example, HITLS_VERSION_TLS12.
 * @param   contentType[IN] contentType Type of the processed message body.
 * @param   msg        [IN] msg         callback internal message processing instruction data
 * @param   msgLen     [IN] msgLen      Processing instruction data length
 * @param   ctx        [IN] ctx         HITLS context
 * @param   arg        [IN] arg         User data, for example, BIO
 * @retval  No value is returned.
*/
typedef void (*HITLS_MsgCb) (int32_t writePoint, int32_t tlsVersion, int32_t contentType, const void *msg,
    uint32_t msgLen, HITLS_Ctx *ctx, void *arg);

/**
 * @ingroup hitls_debug
 * @brief   Set the protocol message callback function, cb can be NULL.
 *
 * @param   ctx      [OUT] Ctx context
 * @param   callback [IN] Protocol message callback function
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetMsgCb(HITLS_Ctx *ctx, HITLS_MsgCb callback);

/**
 * @ingroup hitls_debug
 * @brief   Set the protocol message callback function, cb can be NULL.
 *
 * @param   config   [OUT] Config Context
 * @param   callback [IN] Protocol message callback
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetMsgCb(HITLS_Config *config, HITLS_MsgCb callback);

/**
 * @ingroup hitls_debug
 * @brief   Set the related parameters arg required by the protocol message callback function.
 *
 * @param   ctx   [OUT] Ctx Context.
 * @param   arg [IN] Related parameters arg.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetMsgCbArg(HITLS_Ctx *ctx, void *arg);

/**
 * @ingroup hitls_debug
 * @brief   Set the related parameters arg required by the protocol message callback function.
 *
 * @param   config   [OUT] Config Context.
 * @param   arg [IN] Related parameters arg.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetMsgCbArg(HITLS_Config *config, void *arg);

#ifdef __cplusplus
}
#endif

#endif // HITLS_DEBUG_H

