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

#ifndef HS_PACK_PAKE_H
#define HS_PACK_PAKE_H

#include "hs_common.h"    /* For HS_CTX */
#include "hs_msg_pake.h"  /* For PAKE message structures */
#include "bsl_buffer.h"   /* For HITLS_Buffer */
#include "hitls_error.h"  /* For HITLS_SUCCESS etc. */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(HITLS_TLS_PKEY_SPAKE2P) /* Guard for PAKE feature */

/**
 * @brief Packs a PAKE Client Message.
 *
 * @param hsCtx [IN] Handshake context.
 * @param pakeClientMsg [IN] Pointer to the PAKE client message data to pack.
 * @param buf [OUT] Buffer to write the packed message to.
 * @return HITLS_SUCCESS on success, or an error code on failure.
 */
int32_t HITLS_HS_PackPakeClientMessage(HITLS_HS_CTX *hsCtx, const PakeClientMessage *pakeClientMsg, HITLS_Buffer *buf);

/**
 * @brief Packs a PAKE Server Message.
 *
 * @param hsCtx [IN] Handshake context.
 * @param pakeServerMsg [IN] Pointer to the PAKE server message data to pack.
 * @param buf [OUT] Buffer to write the packed message to.
 * @return HITLS_SUCCESS on success, or an error code on failure.
 */
int32_t HITLS_HS_PackPakeServerMessage(HITLS_HS_CTX *hsCtx, const PakeServerMessage *pakeServerMsg, HITLS_Buffer *buf);

#endif /* HITLS_TLS_PKEY_SPAKE2P */

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* HS_PACK_PAKE_H */
