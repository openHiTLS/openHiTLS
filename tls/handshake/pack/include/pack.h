/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
int32_t HS_PackMsg(const TLS_Ctx *ctx, HS_MsgType type, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif