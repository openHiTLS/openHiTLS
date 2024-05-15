/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
