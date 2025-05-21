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

#include "hs_pack_pake.h"
#include "tls_util_pack.h" /* For common packing utilities like PackUint16, PackOpaqueData */
#include "bsl_err_internal.h"
#include "bsl_log_internal.h" /* For BSL_LOG_ERROR etc. */

#if defined(HITLS_TLS_PKEY_SPAKE2P) /* Guard for PAKE feature */

/*
 * Stub implementation for packing PAKE Client Message.
 * Actual implementation will depend on the final structure of PakeClientMessage
 * and how it's encapsulated (e.g., within ClientKeyExchange or as a new message type).
 */
int32_t HITLS_HS_PackPakeClientMessage(HITLS_HS_CTX *hsCtx, const PakeClientMessage *pakeClientMsg, HITLS_Buffer *buf)
{
    if (hsCtx == NULL || pakeClientMsg == NULL || buf == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Null parameter(s) to PackPakeClientMessage");
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    // Example: Pack the pake_payload from TLS_HS_MSG_PAKE_CLIENT_KEY_EXCHANGE_PAYLOAD
    // This assumes PakeClientMessage contains a pake_payload to be packed.
    // The actual packing logic will depend on whether it's a new message type (with header)
    // or part of an existing message.

    // If it's a new message type, a handshake header needs to be packed first.
    // e.g., PackUint8(buf, PAKE_CLIENT_MESSAGE); // Message Type
    //         PackUint24(buf, length_of_payload); // Length

    // Pack the opaque pake_payload
    // Assuming pakeClientMsg->client_pake_payload.pake_message is a TLS_Data structure
    if (TLS_UTIL_PackOpaqueData(buf, pakeClientMsg->client_pake_payload.pake_message.data,
                                pakeClientMsg->client_pake_payload.pake_message.len,
                                sizeof(uint16_t)) != HITLS_SUCCESS) { // Assuming 2-byte length prefix
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to pack PAKE client payload");
        return HITLS_HS_PACK_ERR;
    }

    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "PackPakeClientMessage: STUB IMPLEMENTATION");
    // For a stub, we might just return success or a specific "not implemented" error.
    // For now, let's assume a very basic packing of the payload.
    return HITLS_SUCCESS;
}

/*
 * Stub implementation for packing PAKE Server Message.
 */
int32_t HITLS_HS_PackPakeServerMessage(HITLS_HS_CTX *hsCtx, const PakeServerMessage *pakeServerMsg, HITLS_Buffer *buf)
{
    if (hsCtx == NULL || pakeServerMsg == NULL || buf == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Null parameter(s) to PackPakeServerMessage");
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    // Example: Pack the pake_payload from TLS_HS_MSG_PAKE_SERVER_KEY_EXCHANGE_PAYLOAD
    if (TLS_UTIL_PackOpaqueData(buf, pakeServerMsg->server_pake_payload.pake_message.data,
                                pakeServerMsg->server_pake_payload.pake_message.len,
                                sizeof(uint16_t)) != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to pack PAKE server payload");
        return HITLS_HS_PACK_ERR;
    }

    // Example: Pack the confirmation_mac if it's part of this message
    if (pakeServerMsg->confirmation_mac.len > 0) {
        if (TLS_UTIL_PackOpaqueData(buf, pakeServerMsg->confirmation_mac.data,
                                    pakeServerMsg->confirmation_mac.len,
                                    sizeof(uint8_t)) != HITLS_SUCCESS) { // Assuming 1-byte length prefix for MAC
            BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to pack PAKE server confirmation MAC");
            return HITLS_HS_PACK_ERR;
        }
    }

    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "PackPakeServerMessage: STUB IMPLEMENTATION");
    return HITLS_SUCCESS;
}

#endif /* HITLS_TLS_PKEY_SPAKE2P */
