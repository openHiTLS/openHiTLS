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

#ifndef HS_PARSE_PAKE_H
#define HS_PARSE_PAKE_H

#include "hs_common.h"    /* For HS_CTX */
#include "hs_msg_pake.h"  /* For PAKE message structures */
#include "bsl_buffer.h"   /* For HITLS_Buffer */
#include "hitls_error.h"  /* For HITLS_SUCCESS etc. */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(HITLS_TLS_PKEY_SPAKE2P) /* Guard for PAKE feature */

/**
 * @brief Parses a PAKE Client Message.
 *
 * @param hsCtx [IN] Handshake context.
 * @param buf [IN] Buffer containing the raw message data.
 * @param pakeClientMsg [OUT] Pointer to the structure to populate with parsed data.
 * @return HITLS_SUCCESS on success, or an error code on failure.
 */
int32_t HITLS_HS_ParsePakeClientMessage(HITLS_HS_CTX *hsCtx, HITLS_Buffer *buf, PakeClientMessage *pakeClientMsg);

/**
 * @brief Parses a PAKE Server Message.
 *
 * @param hsCtx [IN] Handshake context.
 * @param buf [IN] Buffer containing the raw message data.
 * @param pakeServerMsg [OUT] Pointer to the structure to populate with parsed data.
 * @return HITLS_SUCCESS on success, or an error code on failure.
 */
int32_t HITLS_HS_ParsePakeServerMessage(HITLS_HS_CTX *hsCtx, HITLS_Buffer *buf, PakeServerMessage *pakeServerMsg);

#endif /* HITLS_TLS_PKEY_SPAKE2P */

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* HS_PARSE_PAKE_H */
