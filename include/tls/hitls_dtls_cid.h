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

/**
 * @defgroup hitls_dtls_cid
 * @ingroup tls
 * @brief DTLS 1.3 Connection ID (RFC 9147) public APIs
 */

#ifndef HITLS_DTLS_CID_H
#define HITLS_DTLS_CID_H

#include <stdint.h>
#include <stdbool.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CID public types (HITLS_DtlsCidUsage, HITLS_DtlsCidEntry, HITLS_RecvRequestConnectionIdCb)
 * and length macros live in hitls_type.h, because internal structs (e.g. DTLS_CidSendEntry in
 * tls.h) reuse them and must not depend on this feature header.
 */

/**
 * @ingroup hitls_dtls_cid
 * @brief   Set the local receive CID value declared in the DTLS connection_id extension.
 *
 * @attention This function must be called before HITLS_Connect or HITLS_Accept starts the handshake.
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   cid [IN] Local receive CID bytes. It can be NULL only when cidLen is 0.
 * @param   cidLen [IN] Local receive CID length. Non-empty CIDs must not exceed HITLS_DTLS_CID_LOCAL_MAX_LEN.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetDtlsRecvCid(HITLS_Ctx *ctx, const uint8_t *cid, uint8_t cidLen);

/**
 * @ingroup hitls_dtls_cid
 * @brief   Export local receive CIDs currently accepted by this connection.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   entries [OUT] Destination array. If NULL, only entryCount is returned.
 * @param   entryCount [IN/OUT] Input capacity and output required/filled count.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_INVALID_INPUT, if entries is too small.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_GetDtlsRecvCid(const HITLS_Ctx *ctx, HITLS_DtlsCidEntry *entries, uint8_t *entryCount);

/**
 * @ingroup hitls_dtls_cid
 * @brief   Export peer CIDs currently known for outbound records.
 *
 * @details Returns every non-free send slot: spare CIDs not yet selected (UNUSED), the currently
 *          active outbound CID (INUSE), and CIDs already used at least once (USED). Use this to
 *          discover which peer CIDs may be passed to @ref HITLS_SwitchSendCid.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   entries [OUT] Destination array. If NULL, only entryCount is returned.
 * @param   entryCount [IN/OUT] Input capacity and output required/filled count.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_INVALID_INPUT, if entries is too small.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_GetDtlsSendCid(const HITLS_Ctx *ctx, HITLS_DtlsCidEntry *entries, uint8_t *entryCount);

/**
 * @ingroup hitls_dtls_cid
 * @brief   Query whether CID negotiation completed for this connection.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   isNegotiated [OUT] true when the connection_id extension was negotiated.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_GetDtlsIsCidNegotiated(const HITLS_Ctx *ctx, bool *isNegotiated);

/**
 * @ingroup hitls_dtls_cid
 * @brief   Queue a DTLS 1.3 RequestConnectionId post-handshake message.
 *
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   numCids [IN] Number of fresh peer receive CIDs requested for use by this endpoint's outbound records.
 * @retval  HITLS_SUCCESS, if the send state is queued successfully.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_RequestConnectionId(HITLS_Ctx *ctx, uint8_t numCids);

/**
 * @ingroup hitls_dtls_cid
 * @brief   Queue a DTLS 1.3 NewConnectionId post-handshake message.
 *
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   inCids [IN] Local receive CIDs to advertise to the peer.
 * @param   cidCount [IN/OUT] Requested count on input and accepted count on output.
 * @param   usage [IN] Whether advertised CIDs are IMMEDIATE replacements or SPARE CIDs.
 * @retval  HITLS_SUCCESS, if the send state is queued successfully.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_NewConnectionId(HITLS_Ctx *ctx, const HITLS_DtlsCidEntry *inCids, uint8_t *cidCount,
                              HITLS_DtlsCidUsage usage);

/**
 * @ingroup hitls_dtls_cid
 * @brief   Switch send CID.
 *
 * @details Before each switch, call @ref HITLS_GetDtlsSendCid to inspect the peer CIDs
 *          currently available for outbound records.
 *          - If @p cid is NULL, an UNUSED peer CID is selected.
 *            A previously used (USED) CID is never picked in this automatic mode.
 *          - If @p cid is non-NULL, any peer CIDs currently available may be selected.
 *
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   cid [IN] Target peer CID.
 * @param   cidLen [IN] Target CID length when cid is not NULL.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SwitchSendCid(HITLS_Ctx *ctx, const uint8_t *cid, uint8_t cidLen);

/**
 * @ingroup hitls_dtls_cid
 * @brief   Register the callback invoked when a peer RequestConnectionId is received.
 *
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   cb [IN] Callback. It may call HITLS_NewConnectionId to queue a reply.
 * @param   userData [IN] Opaque user data passed to cb.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetRecvRequestConnectionIdCb(HITLS_Ctx *ctx, HITLS_RecvRequestConnectionIdCb cb, void *userData);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_DTLS_CID_H */
