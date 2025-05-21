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

#include "hs_parse_pake.h"
#include "tls_util_parse.h" /* For common parsing utilities like ParseOpaqueData */
#include "bsl_err_internal.h"
#include "bsl_log_internal.h" /* For BSL_LOG_ERROR etc. */
#include "bsl_buffer.h"       /* For HITLS_BufferIsEmpty etc. */

#if defined(HITLS_TLS_PKEY_SPAKE2P) /* Guard for PAKE feature */

/*
 * Stub implementation for parsing PAKE Client Message.
 */
int32_t HITLS_HS_ParsePakeClientMessage(HITLS_HS_CTX *hsCtx, HITLS_Buffer *buf, PakeClientMessage *pakeClientMsg)
{
    if (hsCtx == NULL || buf == NULL || pakeClientMsg == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Null parameter(s) to ParsePakeClientMessage");
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (HITLS_BufferIsEmpty(buf)) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Buffer is empty for ParsePakeClientMessage");
        BSL_ERR_PUSH_ERROR(HITLS_HS_PARSE_EMPTY_BUF_ERR);
        return HITLS_HS_PARSE_EMPTY_BUF_ERR;
    }

    // Example: Parse the opaque pake_payload
    // Assuming pakeClientMsg->client_pake_payload.pake_message is a TLS_Data structure
    // and it expects a 2-byte length prefix.
    if (TLS_UTIL_ParseOpaqueData(buf, &pakeClientMsg->client_pake_payload.pake_message.data,
                                 &pakeClientMsg->client_pake_payload.pake_message.len,
                                 sizeof(uint16_t), hsCtx->memTrack) != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to parse PAKE client payload");
        return HITLS_HS_PARSE_ERR;
    }

    // After parsing, ensure the buffer is now empty if this was the only field.
    if (!HITLS_BufferIsEmpty(buf)) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Extra data in buffer after parsing PakeClientMessage");
        // Free allocated data if any before returning error
        BSL_TRD_FREE_PARA(pakeClientMsg->client_pake_payload.pake_message.data, hsCtx->memTrack);
        pakeClientMsg->client_pake_payload.pake_message.data = NULL;
        pakeClientMsg->client_pake_payload.pake_message.len = 0;
        return HITLS_HS_PARSE_LEN_ERR;
    }

    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "ParsePakeClientMessage: STUB IMPLEMENTATION");
    return HITLS_SUCCESS;
}

/*
 * Stub implementation for parsing PAKE Server Message.
 */
int32_t HITLS_HS_ParsePakeServerMessage(HITLS_HS_CTX *hsCtx, HITLS_Buffer *buf, PakeServerMessage *pakeServerMsg)
{
    if (hsCtx == NULL || buf == NULL || pakeServerMsg == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Null parameter(s) to ParsePakeServerMessage");
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (HITLS_BufferIsEmpty(buf)) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Buffer is empty for ParsePakeServerMessage");
        BSL_ERR_PUSH_ERROR(HITLS_HS_PARSE_EMPTY_BUF_ERR);
        return HITLS_HS_PARSE_EMPTY_BUF_ERR;
    }

    // Example: Parse the pake_payload
    if (TLS_UTIL_ParseOpaqueData(buf, &pakeServerMsg->server_pake_payload.pake_message.data,
                                 &pakeServerMsg->server_pake_payload.pake_message.len,
                                 sizeof(uint16_t), hsCtx->memTrack) != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to parse PAKE server payload");
        return HITLS_HS_PARSE_ERR;
    }

    // Example: Parse the confirmation_mac if it's part of this message
    // Check if there's more data before attempting to parse MAC (could be optional)
    if (!HITLS_BufferIsEmpty(buf)) {
        if (TLS_UTIL_ParseOpaqueData(buf, &pakeServerMsg->confirmation_mac.data,
                                     &pakeServerMsg->confirmation_mac.len,
                                     sizeof(uint8_t), hsCtx->memTrack) != HITLS_SUCCESS) { // Assuming 1-byte length for MAC
            BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to parse PAKE server confirmation MAC");
            // Free already allocated data
            BSL_TRD_FREE_PARA(pakeServerMsg->server_pake_payload.pake_message.data, hsCtx->memTrack);
            pakeServerMsg->server_pake_payload.pake_message.data = NULL;
            pakeServerMsg->server_pake_payload.pake_message.len = 0;
            return HITLS_HS_PARSE_ERR;
        }
    } else {
        // No confirmation MAC present, clear fields
        pakeServerMsg->confirmation_mac.data = NULL;
        pakeServerMsg->confirmation_mac.len = 0;
    }


    // After parsing, ensure the buffer is now empty if this was the only field.
    if (!HITLS_BufferIsEmpty(buf)) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Extra data in buffer after parsing PakeServerMessage");
        BSL_TRD_FREE_PARA(pakeServerMsg->server_pake_payload.pake_message.data, hsCtx->memTrack);
        BSL_TRD_FREE_PARA(pakeServerMsg->confirmation_mac.data, hsCtx->memTrack);
        // Clear fields
        pakeServerMsg->server_pake_payload.pake_message.data = NULL;
        pakeServerMsg->server_pake_payload.pake_message.len = 0;
        pakeServerMsg->confirmation_mac.data = NULL;
        pakeServerMsg->confirmation_mac.len = 0;
        return HITLS_HS_PARSE_LEN_ERR;
    }

    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "ParsePakeServerMessage: STUB IMPLEMENTATION");
    return HITLS_SUCCESS;
}

#endif /* HITLS_TLS_PKEY_SPAKE2P */
