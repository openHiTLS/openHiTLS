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

#ifndef HS_RECV_PAKE_H
#define HS_RECV_PAKE_H

#include "hs_common.h"    /* For HS_CTX */
#include "hitls_error.h"  /* For HITLS_SUCCESS etc. */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(HITLS_TLS_PKEY_SPAKE2P) /* Guard for PAKE feature */

/**
 * @brief Receives and processes a PAKE Server Message.
 *        This function handles the receipt of the server's PAKE message,
 *        which typically contains the server's public PAKE value (e.g., pV for SPAKE2+)
 *        and potentially a server confirmation MAC.
 *
 * @param ctx [IN] TLS context, containing the handshake context.
 * @return HITLS_SUCCESS on success, or an error code on failure.
 * @return HITLS_HS_WANT_RECV if more data is needed.
 * @return HITLS_FATAL_ERROR on critical errors like MAC verification failure.
 */
int32_t HITLS_HS_RecvPakeServerMessage(TLS_Ctx *ctx);

/**
 * @brief Receives and processes a PAKE Client Message. (Stub for server-side, but good for symmetry)
 *        This function would handle the receipt of the client's PAKE message.
 *        Primarily for server-side implementation, but defined for completeness.
 *
 * @param ctx [IN] TLS context, containing the handshake context.
 * @return HITLS_SUCCESS on success, or an error code on failure.
 */
// int32_t HITLS_HS_RecvPakeClientMessage(TLS_Ctx *ctx); // This would be for server side

#endif /* HITLS_TLS_PKEY_SPAKE2P */

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* HS_RECV_PAKE_H */
