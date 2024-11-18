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

#ifndef PACK_H
#define PACK_H

#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Pack handshake messages
 *
 * @param   ctx  [IN] TLS context
 * @param   type  [IN] Message type
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Input buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t HS_PackMsg(TLS_Ctx *ctx, HS_MsgType type, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif