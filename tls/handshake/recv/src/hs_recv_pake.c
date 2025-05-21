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

#include "hitls_build.h"
#if defined(HITLS_TLS_PKEY_SPAKE2P) // Guard for PAKE feature

#include "hs_recv_pake.h"
#include "hs_ctx.h"
#include "hs_msg.h"         // For HS_Msg and PakeClientMessage
#include "hs_msg_pake.h"    // For PakeClientMessage structure
#include "hs_common.h"      // For HS_ChangeState, HS_MsgType
#include "crypt_eal_pkey.h"
#include "crypt_spake2p.h"
#include "crypt_algid.h"    // For CRYPT_PKEY_SPAKE2P, etc.
#include "alert.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls_util_common.h"
#include "tls.h"
#include "cipher_suite.h"    // For CipherSuiteInfo
#include "securec.h"


/*
 * Handles the server's receipt and processing of a PAKE Client Message.
 * This function is called when the server is in state TLS_HS_SERVER_STATE_RECV_PAKE_MESSAGE.
 * Assumes hsCtx->pake_ctx was initialized after ServerHello was sent.
 * Assumes hsCtx->msg contains the parsed PakeClientMessage.
 */
#if defined(HITLS_TLS_HOST_SERVER)
int32_t HITLS_HS_ServerRecvPakeClientMessage(TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->hsCtx == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Null context for ServerRecvPakeClientMessage");
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_HS_CTX *hsCtx = TLS_GET_HS_CTX(ctx);
    int32_t ret;

    if (hsCtx->pake_ctx == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "PAKE context not initialized for ServerRecvPakeClientMessage. Should be done after ServerHello.");
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_STATE);
        return HITLS_INVALID_STATE;
    }

    if (hsCtx->msg == NULL || hsCtx->msg->type != PAKE_CLIENT_MESSAGE) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "No parsed PAKE_CLIENT_MESSAGE or wrong type in hsCtx->msg.");
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_HS_UNEXPECTED_MESSAGE;
    }
    // The HS_Msg union was updated in Obj5, Turn1 to include pakeClientMsg
    PakeClientMessage *parsedMsg = &hsCtx->msg->body.pakeClientMsg;

    const TLS_Data *client_pake_data = &parsedMsg->client_pake_payload.pake_message;
    if (client_pake_data->data == NULL || client_pake_data->len == 0) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Client PAKE payload (pU) is empty.");
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_HS_PARSE_ERR;
    }

    CRYPT_SPAKE2P_DATA_PARAM eal_pake_data_param;
    eal_pake_data_param.data = client_pake_data->data;
    eal_pake_data_param.dataLen = client_pake_data->len;

    BSL_LOG_DEBUG(BSL_MODULE_TLS_HS, "Server: Processing Client PAKE data (pU) via EAL.");
    PRINT_HEX_DATA(BSL_MODULE_TLS_HS, BSL_LOG_LEVEL_DEBUG, "Received Client PAKE Payload (pU)",
                   client_pake_data->data, client_pake_data->len);

    // For server, this first call to PROCESS_PEER_MSG_AND_CONFIRM with client's pU
    // primarily serves to store pU and compute w0_peer, w1_peer.
    // The SPAKE2+ EAL implementation should handle this logic.
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_PROCESS_PEER_MSG_AND_CONFIRM,
                             &eal_pake_data_param, sizeof(eal_pake_data_param));
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Server: Failed to process client PAKE message (pU) via EAL: %x", ret);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        return ret;
    }

    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Server: Successfully processed PakeClientMessage. Transitioning to send PakeServerMessage.");
    return HS_ChangeState(ctx, TLS_HS_SERVER_STATE_SEND_PAKE_MESSAGE);
}
#endif /* HITLS_TLS_HOST_SERVER */


/*
 * Handles the client's receipt and processing of a PAKE Server Message.
 * (Implementation from Objective 4, Turn 3 - verified to be mostly complete)
 */
#if defined(HITLS_TLS_HOST_CLIENT)
int32_t HITLS_HS_ClientRecvPakeServerMessage(TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->hsCtx == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Null context for ClientRecvPakeServerMessage");
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_HS_CTX *hsCtx = TLS_GET_HS_CTX(ctx);

    if (hsCtx->pake_ctx == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "PAKE context not initialized for ClientRecvPakeServerMessage");
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_STATE);
        return HITLS_INVALID_STATE;
    }

    if (hsCtx->msg == NULL || hsCtx->msg->type != PAKE_SERVER_MESSAGE) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "No parsed PAKE_SERVER_MESSAGE or wrong type in hsCtx->msg.");
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_HS_UNEXPECTED_MESSAGE;
    }
    PakeServerMessage *parsedMsg = &hsCtx->msg->body.pakeServerMsg;

    int32_t ret;
    const TLS_Data *server_pake_data = &parsedMsg->server_pake_payload.pake_message;
    const TLS_Data *server_mac_data  = &parsedMsg->confirmation_mac;

    if (server_pake_data->data == NULL || server_pake_data->len == 0) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Server PAKE payload (pV) is empty.");
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_HS_PARSE_ERR;
    }
    
    CRYPT_SPAKE2P_DATA_PARAM eal_pake_data_param;
    eal_pake_data_param.data = server_pake_data->data;
    eal_pake_data_param.dataLen = server_pake_data->len;

    BSL_LOG_DEBUG(BSL_MODULE_TLS_HS, "Client: Processing Server PAKE data (pV) via EAL.");
    PRINT_HEX_DATA(BSL_MODULE_TLS_HS, BSL_LOG_LEVEL_DEBUG, "Received Server PAKE Payload (pV)",
                   server_pake_data->data, server_pake_data->len);
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_PROCESS_PEER_MSG_AND_CONFIRM,
                             &eal_pake_data_param, sizeof(eal_pake_data_param));
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Client: Failed to process server PAKE message (pV) via EAL: %x", ret);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        return ret;
    }

    if (server_mac_data->data != NULL && server_mac_data->len > 0) {
        CRYPT_SPAKE2P_DATA_PARAM eal_mac_data_param;
        eal_mac_data_param.data = server_mac_data->data;
        eal_mac_data_param.dataLen = server_mac_data->len;
        BSL_LOG_DEBUG(BSL_MODULE_TLS_HS, "Client: Verifying Server PAKE MAC via EAL.");
        PRINT_HEX_DATA(BSL_MODULE_TLS_HS, BSL_LOG_LEVEL_DEBUG, "Received Server PAKE MAC",
                       server_mac_data->data, server_mac_data->len);
        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_VERIFY_PEER_CONFIRMATION_MAC,
                                 &eal_mac_data_param, sizeof(eal_mac_data_param));
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Client: Server PAKE MAC verification failed: %x", ret);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECRYPT_ERROR); // Using DECRYPT_ERROR as per RFC for bad MAC
            return ret;
        }
        BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Client: Server PAKE MAC verified successfully.");
    } else {
        BSL_LOG_WARN(BSL_MODULE_TLS_HS, "Client: No Server PAKE MAC received in PakeServerMessage. Assuming MAC in Finished.");
    }

    CRYPT_SPAKE2P_BUFFER_PARAM eal_buffer_param_get_mac;
    hsCtx->pake_client_confirmation_mac_len = sizeof(hsCtx->pake_client_confirmation_mac);
    eal_buffer_param_get_mac.buffer = hsCtx->pake_client_confirmation_mac;
    eal_buffer_param_get_mac.bufferLen = &hsCtx->pake_client_confirmation_mac_len;
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_GET_OUR_CONFIRMATION_MAC,
                             &eal_buffer_param_get_mac, sizeof(eal_buffer_param_get_mac));
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Client: Failed to get PAKE confirmation MAC: %x", ret);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    uint8_t ke_buffer[MASTER_SECRET_LEN]; 
    uint32_t ke_buffer_len = sizeof(ke_buffer);
    CRYPT_SPAKE2P_BUFFER_PARAM eal_buffer_param_get_ke = {ke_buffer, &ke_buffer_len};
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_GET_DERIVED_SECRET_KE,
                             &eal_buffer_param_get_ke, sizeof(eal_buffer_param_get_ke));
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Client: Failed to get derived secret Ke for PAKE: %x", ret);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
    if (ke_buffer_len > MASTER_SECRET_LEN) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Client: Derived Ke length (%u) > MASTER_SECRET_LEN (%u)", ke_buffer_len, MASTER_SECRET_LEN);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_INTERNAL_ERROR;
    }
    if (memset_s(hsCtx->masterKey, MASTER_SECRET_LEN, 0, MASTER_SECRET_LEN) != EOK ||
        memcpy_s(hsCtx->masterKey, MASTER_SECRET_LEN, ke_buffer, ke_buffer_len) != EOK) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Client: Failed to copy Ke to masterKey.");
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMCPY_FAIL;
    }
    hsCtx->pake_ke_len = ke_buffer_len; // Store the length of Ke
    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Client: PAKE Ke derived (len %u) and stored.", ke_buffer_len);
    PRINT_HEX_DATA(BSL_MODULE_TLS_HS, BSL_LOG_LEVEL_DEBUG, "Client: Derived Ke (PAKE)", hsCtx->masterKey, ke_buffer_len);

    ret = HS_ChangeState(ctx, TRY_SEND_CHANGE_CIPHER_SPEC); 
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    
    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Client: Successfully processed PakeServerMessage. Transitioning to send CCS.");
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_CLIENT */


#else // Not (HITLS_TLS_PKEY_SPAKE2P)
// Stubs for non-PAKE builds if these functions are referenced by generic state machine logic.
#if defined(HITLS_TLS_HOST_SERVER)
int32_t HITLS_HS_ServerRecvPakeClientMessage(TLS_Ctx *ctx)
{
    (void)ctx;
    BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "PAKE support not compiled in (ServerRecvPakeClientMessage).");
    BSL_ERR_PUSH_ERROR(HITLS_NOT_SUPPORTED);
    return HITLS_NOT_SUPPORTED;
}
#endif
#if defined(HITLS_TLS_HOST_CLIENT)
int32_t HITLS_HS_ClientRecvPakeServerMessage(TLS_Ctx *ctx)
{
    (void)ctx;
    BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "PAKE support not compiled in (ClientRecvPakeServerMessage).");
    BSL_ERR_PUSH_ERROR(HITLS_NOT_SUPPORTED);
    return HITLS_NOT_SUPPORTED;
}
#endif
#endif /* HITLS_TLS_PKEY_SPAKE2P */
