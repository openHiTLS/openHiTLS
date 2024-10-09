/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HS_REASS_H
#define HS_REASS_H

#include <stdint.h>
#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HITLS_NO_DTLS12

/**
 * @brief Create a message reassembly queue.
 *
 * @return Return the header of the linked list. If NULL is returned, memory application fails.
 */
HS_ReassQueue *HS_ReassNew(void);

/**
 * @brief Release the reassembly message queue.
 *
 * @param reass [IN] Reassemble the message queue.
 */
void HS_ReassFree(HS_ReassQueue *reassQueue);

/**
 * @brief Reassemble a fragmented handshake message.
 *
 * @param ctx [IN] TLS object
 * @param msgInfo [IN] Message structure to be reassembled
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_REASS_INVALID_FRAGMENT An invalid fragment message is received.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 * @retval HITLS_MEMCPY_FAIL Memory Copy Failure
 */
int32_t HS_ReassAppend(TLS_Ctx *ctx, HS_MsgInfo *msgInfo);

/**
 * @brief Read the complete message of the expected sequence number.
 *
 * @param ctx [IN] TLS object
 * @param msgInfo [OUT] Message structure
 * @param len [OUT] Message length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MEMCPY_FAIL Memory Copy Failure
 */
int32_t HS_GetReassMsg(TLS_Ctx *ctx, HS_MsgInfo *msgInfo, uint32_t *len);

#endif /* end #ifndef HITLS_NO_DTLS12 */

#ifdef __cplusplus
}
#endif

#endif  // HS_REASS_H
