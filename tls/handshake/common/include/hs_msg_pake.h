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

#ifndef HS_MSG_PAKE_H
#define HS_MSG_PAKE_H

#include "tls_type_common.h" /* For TLS_Data */
#include "hs_common.h"       /* For HS_CTX, and potentially to include hs_msg.h for HS_MsgType */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Structure for PAKE Client Key Exchange Payload.
 * This would typically be part of a ClientKeyExchange message if PAKE is
 * integrated into existing TLS 1.2 flows, or part of a new PAKE-specific message.
 * It contains the client's PAKE message (e.g., pU from SPAKE2+).
 */
typedef struct {
    TLS_Data pake_message; /* The PAKE payload from the client (e.g., Ed25519 point) */
    /* If draft-bmw-tls-pake13 specifies other fields here, add them.
       For example, if a PAKE ciphersuite identifier or group identifier is sent. */
} TLS_HS_MSG_PAKE_CLIENT_KEY_EXCHANGE_PAYLOAD;

/*
 * Structure for PAKE Server Key Exchange Payload.
 * This would typically be part of a ServerKeyExchange message or a new PAKE-specific message.
 * It contains the server's PAKE message (e.g., pV from SPAKE2+) and potentially a confirmation.
 * Confirmation MACs are often part of the Finished message or a dedicated confirmation message
 * following the PAKE exchange.
 */
typedef struct {
    TLS_Data pake_message; /* The PAKE payload from the server (e.g., Ed25519 point) */
    /* If draft-bmw-tls-pake13 specifies other fields here, add them. */
} TLS_HS_MSG_PAKE_SERVER_KEY_EXCHANGE_PAYLOAD;


/*
 * If PAKE messages are new top-level handshake messages, their structures would be:
 */
typedef struct {
    TLS_HS_MSG_PAKE_CLIENT_KEY_EXCHANGE_PAYLOAD client_pake_payload;
} PakeClientMessage; // Placeholder name if it's a top-level message

typedef struct {
    TLS_HS_MSG_PAKE_SERVER_KEY_EXCHANGE_PAYLOAD server_pake_payload;
    /* Potentially server's confirmation MAC if sent immediately, though often part of Finished */
    TLS_Data confirmation_mac; /* Example if server sends its MAC here */
} PakeServerMessage; // Placeholder name if it's a top-level message


#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end HS_MSG_PAKE_H */
