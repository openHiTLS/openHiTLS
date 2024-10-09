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

#ifndef REC_ALERT_H
#define REC_ALERT_H

#include <stdint.h>
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   record Send an alert and determine whether to discard invalid records
 * based on RFC6347 4.1.2.7. Handling Invalid Records
 *
 * @param   ctx [IN] tls Context
 * @param   level [IN] Alert level
 * @param   description [IN] alert Description
 *
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY Discarding message
 * @retval  Other invalid message error codes, such as HITLS_REC_INVLAID_RECORD and HITLS_REC_INVALID_PROTOCOL_VERSION
 */
int32_t RecordSendAlertMsg(TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description);

#ifdef __cplusplus
}
#endif

#endif
