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

#ifndef INDICATOR_H
#define INDICATOR_H
#include "hitls_build.h"
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INDICATOR_ALERT_LEVEL_OFFSET 8

#define INDICATE_INFO_STATE_MASK            0x0FFF  // 0000 1111 1111 1111

/**
 * @ingroup indicator
 * @brief   Indicate the status or event to the upper layer through the infoCb
 * @param   ctx       [IN] TLS context
 * @param   eventType [IN]
 * @param   value     [IN] Return value of a function in the event or alert type
 */
void INDICATOR_StatusIndicate(const HITLS_Ctx *ctx, int32_t eventType, int32_t value);

/**
 * @ingroup indicator
 * @brief   Indicate the status or event to the upper layer through msgCb
 * @param   writePoint [IN] Message direction in the callback ">>>" or "<<<"
 * @param   tlsVersion [IN] TLS version
 * @param   contentType[IN] Type of the message to be processed.
 * @param   msg        [IN] Internal message processing instruction data in callback
 * @param   msgLen     [IN] Data length of the processing instruction
 * @param   ctx        [IN] HITLS context
 * @param   arg        [IN] User data such as BIO
 */
void INDICATOR_MessageIndicate(int32_t writePoint, uint32_t tlsVersion, int32_t contentType, const void *msg,
                               uint32_t msgLen, HITLS_Ctx *ctx, void *arg);

#ifdef __cplusplus
}
#endif

#endif // INDICATOR_H