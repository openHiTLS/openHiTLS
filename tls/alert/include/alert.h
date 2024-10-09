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

#ifndef ALTER_H
#define ALTER_H

#include <stdbool.h>
#include <stdint.h>
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ALERT_FLAG_NO = 0,      /* no alert message */
    ALERT_FLAG_RECV,        /* received the alert message */
    ALERT_FLAG_SEND,        /* the alert message needs to be sent */
} ALERT_FLAG;

/** obtain the messages about receiving and sending by Alert */
typedef struct {
    uint8_t flag;           /* send and receive flags, see ALERT_FLAG */
    uint8_t level;          /* Alert level. For details, see ALERT_Level. */
    uint8_t description;    /* Alert description. For details, see ALERT_Description. */
    uint8_t reverse;        /* reserve, 4-byte aligned */
} ALERT_Info;

/**
 * @ingroup alert
 * @brief Alert initialization function
 *
 * @param ctx [IN] tls Context
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_INTERNAL_EXCEPTION An unexpected internal error occurs.
 * @retval HITLS_MEMALLOC_FAIL Failed to apply for memory.
 */
int32_t ALERT_Init(TLS_Ctx *ctx);

/**
 * @ingroup alert
 * @brief Alert deinitialization function
 *
 * @param ctx [IN] tls Context
 *
 */
void ALERT_Deinit(TLS_Ctx *ctx);

/**
 * @ingroup alert
 * @brief Check whether there are received or sent alert messages to be processed.
 *
 * @attention ctx cannot be empty.
 * @param ctx [IN] tls Context
 *
 * @retval true: The processing is required.
 * @retval false: No processing is required.
 */
bool ALERT_GetFlag(const TLS_Ctx *ctx);

/**
 * @ingroup alert
 * @brief Obtain the alert information.
 *
 * @attention ctx and info cannot be empty. Ensure that the value is used when Alert_GetFlag is true.
 * @param ctx [IN] tls Context
 * @param info [IN] Alert information record
 */
void ALERT_GetInfo(const TLS_Ctx *ctx, ALERT_Info *info);

/**
 * @brief Clear the alert information.
 *
 * @attention ctx cannot be empty.
 * @param ctx [IN] tls Context
 */
void ALERT_CleanInfo(const TLS_Ctx *ctx);

/**
 * @brief Send an alert message and cache it in the alert module.
 *
 * @attention ctx cannot be empty.
 * @param ctx [IN] tls Context
 * @param level [IN] Alert level
 * @param description [IN] alert Description
 *
 */
void ALERT_Send(TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description);

/**
 * @brief Send the alert message cached by the alert module to the network layer.
 *
 * @attention ctx cannot be empty. Alert_Send must be invoked before flushing.
 * @param ctx [IN] tls Context
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval See REC_Write
 */
int32_t ALERT_Flush(TLS_Ctx *ctx);

/**
 * @ingroup alert
 * @brief Alert receiving interface
 *
 * @attention ctx cannot be empty.
 * @param ctx [IN] tls Context
 * @param data [IN] Alert message body
 * @param len [IN] Alert message length
 *
 */
void ALERT_Recv(TLS_Ctx *ctx, const uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* ALTER_H */