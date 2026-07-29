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
 * @defgroup dtls_cid
 * @ingroup  tls
 * @brief    DTLS 1.3 Connection ID internal helpers for handshake and record layer.
 */

#ifndef DTLS_CID_H
#define DTLS_CID_H

#include <stdbool.h>
#include <stdint.h>
#include "hitls_build.h"
#include "hitls_type.h"
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Shared utilities and slot-table lifecycle (used by both negotiate and
 * update paths).
 */

/**
 * @ingroup dtls_cid
 * @brief   Compare two CID byte sequences for equality.
 *
 * @param   left     [IN] First CID bytes.
 * @param   leftLen  [IN] First CID length.
 * @param   right    [IN] Second CID bytes.
 * @param   rightLen [IN] Second CID length.
 *
 * @retval  true   Both CIDs are identical in length and content.
 * @retval  false  Otherwise.
 */
bool DTLS_CID_IsEq(const uint8_t *left, uint8_t leftLen, const uint8_t *right, uint8_t rightLen);

/*
 * Negotiate path: ClientHello/ServerHello extension pack/parse helpers.
 */

/**
 * @ingroup dtls_cid
 * @brief   Decide whether to pack connection_id(54) in ClientHello.
 *
 * Returns true when all of the following hold:
 *   - The context is a DTLS connection.
 *   - The application has enabled CID (state != DISABLED).
 * A zero-length local CID is legal (RFC 9146 Section 3) and still requires
 * sending the extension so the server knows this endpoint supports CID.
 *
 * @param   ctx [IN] TLS context.
 *
 * @retval  true   Pack the extension.
 * @retval  false  Skip: not DTLS, or CID not enabled.
 */
bool DTLS_CID_NeedCidExtForClientHello(const TLS_Ctx *ctx);


/**
 * @ingroup dtls_cid
 * @brief   Process the connection_id extension received in a ClientHello.
 *
 * @param   ctx              [IN] TLS context.
 * @param   haveConnectionId [IN] Whether ClientHello carried connection_id.
 * @param   connectionId     [IN] Peer CID value.
 * @param   connectionIdLen  [IN] Peer CID length.
 * @param   isNeedSendHrr    [IN] Whether the server is about to send HRR.
 *
 * @retval  HITLS_SUCCESS on success.
 * @retval  Other error codes on failure.
 */
int32_t DTLS_CID_ProcessClientHello(TLS_Ctx *ctx, bool haveConnectionId,
    const uint8_t *connectionId, uint8_t connectionIdLen, bool isNeedSendHrr);

/**
 * @ingroup dtls_cid
 * @brief   Process the connection_id extension received in a ServerHello.
 *
 * @param   ctx              [IN] TLS context.
 * @param   haveConnectionId [IN] Whether ServerHello carried connection_id.
 * @param   connectionId     [IN] Peer CID value.
 * @param   connectionIdLen  [IN] Peer CID length.
 *
 * @retval  HITLS_SUCCESS on success.
 * @retval  Other error codes on failure.
 */
int32_t DTLS_CID_ProcessServerHello(TLS_Ctx *ctx, bool haveConnectionId,
    const uint8_t *connectionId, uint8_t connectionIdLen);

/*
 * Record-layer accessors: configured during negotiate, consumed by record
 * read/write hot paths.
 */

/**
 * @ingroup dtls_cid
 * @brief   Check whether an inbound CID matches a recv list entry
 *
 * @param   ctx    [IN] TLS context.
 * @param   cid    [IN] CID bytes from the inbound record header.
 * @param   cidLen [IN] CID length.
 *
 * @retval  true   CID matches a recv list entry.
 * @retval  false  No match.
 */
bool DTLS_CID_IsExpectedCid(const TLS_Ctx *ctx, const uint8_t *cid, uint8_t cidLen);

/*
 * Update path: post-handshake NewConnectionId / RequestConnectionId events.
 */

/**
 * @ingroup dtls_cid
 * @brief   Mark a previously sent RequestConnectionId as fulfilled.
 *
 * Per RFC 9147 Section 5.2, a RequestConnectionId is considered fulfilled when
 * its handshake record is acknowledged by the peer. The DTLS 1.3 ACK is a
 * record-layer event independent of any peer NewConnectionId message, so this
 * hook is invoked from the ACK processing path (or the SDV test mock) to flip
 * the send state machine SENT -> IDLE. It serves directly as the
 * REC_Dtls13RetransmitAckCb for the REQUEST_CONNECTION_ID message.
 *
 * @param   ctx [IN] TLS context.
 * @return  HITLS_SUCCESS (the notification never fails).
 */
int32_t DTLS_CID_OnRequestConnectionIdAcked(TLS_Ctx *ctx);

/**
 * @ingroup dtls_cid
 * @brief   Finalize a sent NewConnectionId once the peer ACKs its record.
 *          Registered as the REC_Dtls13RetransmitAckCb for NEW_CONNECTION_ID.
 *
 * On ACK this callback:
 *   - SENT -> IDLE: re-arm the sub-state machine for the next post-handshake;
 *   - free recv slots an IMMEDIATE NewConnectionId marked DEPRECATING
 *
 * @param   ctx [IN] TLS context.
 * @return  HITLS_SUCCESS.
 */
int32_t DTLS_CID_OnNewConnectionIdAcked(TLS_Ctx *ctx);

/**
 * @ingroup dtls_cid
 * @brief   Process peer NewConnectionId payload into send CID slots.
 *
 * @param   ctx     [IN] TLS context.
 * @param   cids    [IN] Serialized CID list [len][cid]...
 * @param   cidsLen [IN] Serialized CID list length.
 * @param   usage   [IN] ConnectionIdUsage value.
 *
 * @retval  HITLS_SUCCESS on success.
 * @retval  Other error codes on fatal malformed input.
 */
int32_t DTLS_CID_ProcessPeerNewConnectionId(TLS_Ctx *ctx, const uint8_t *cids, uint32_t cidsLen, uint8_t usage);

#ifdef __cplusplus
}
#endif

#endif /* DTLS_CID_H */
