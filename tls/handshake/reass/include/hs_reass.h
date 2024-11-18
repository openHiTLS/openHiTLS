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

#ifndef HS_REASS_H
#define HS_REASS_H

#include <stdint.h>
#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HITLS_TLS_PROTO_DTLS12

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

#endif /* end #ifdef HITLS_TLS_PROTO_DTLS12 */

#ifdef __cplusplus
}
#endif

#endif  // HS_REASS_H
