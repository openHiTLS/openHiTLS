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

#ifndef HS_SEND_PAKE_H
#define HS_SEND_PAKE_H

#include "hs_common.h"    /* For HS_CTX */
#include "hitls_error.h"  /* For HITLS_SUCCESS etc. */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(HITLS_TLS_PKEY_SPAKE2P) /* Guard for PAKE feature */

/**
 * @brief Sends a PAKE Client Message.
 *        This function constructs and sends the client's PAKE message,
 *        which typically contains the client's public PAKE value (e.g., pU for SPAKE2+).
 *
 * @param ctx [IN] TLS context, containing the handshake context.
 * @return HITLS_SUCCESS on success, or an error code on failure.
 * @return HITLS_HS_WANT_SEND if the message was prepared but not fully sent (e.g. DTLS needs retransmission).
 */
int32_t HITLS_HS_SendPakeClientMessage(TLS_Ctx *ctx);

/**
 * @brief Sends a PAKE Server Message. (Stub for client-side, but good for symmetry)
 *        This function would construct and send the server's PAKE message.
 *        Primarily for server-side implementation, but defined for completeness.
 *
 * @param ctx [IN] TLS context, containing the handshake context.
 * @return HITLS_SUCCESS on success, or an error code on failure.
 */
// int32_t HITLS_HS_SendPakeServerMessage(TLS_Ctx *ctx); // This would be for server side

#endif /* HITLS_TLS_PKEY_SPAKE2P */

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* HS_SEND_PAKE_H */
