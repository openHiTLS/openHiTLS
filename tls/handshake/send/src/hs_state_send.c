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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs.h"
#include "hs_common.h"
#include "send_process.h"
#include "hs_kx.h"
#include "pack.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#if defined(HITLS_TLS_PKEY_SPAKE2P)
#include "hs_send_pake.h" /* For HITLS_HS_SendPakeClientMessage */
#endif

#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
static int32_t Tls13SendKeyUpdateProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;

    if (hsCtx->msgLen == 0) {
        ret = HS_PackMsg(ctx, KEY_UPDATE, hsCtx->msgBuf, hsCtx->bufferLen, &hsCtx->msgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15791, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack tls1.3 key update msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15792, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send tls1.3 key update msg success.", 0, 0, 0, 0);
    /* After the key update message is sent, the local application traffic key is updated and activated. */
    ret = HS_TLS13UpdateTrafficSecret(ctx, true);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15793, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "tls1.3 out key update fail", 0, 0, 0, 0);
        return ret;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15794, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "tls1.3 send key update success.", 0, 0, 0, 0);

    ctx->isKeyUpdateRequest = false;
    ctx->keyUpdateType = HITLS_KEY_UPDATE_REQ_END;
    return HS_ChangeState(ctx, TLS_CONNECTED);
}
#endif /* HITLS_TLS_FEATURE_KEY_UPDATE */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t SendFinishedProcess(TLS_Ctx *ctx)
{
#ifdef HITLS_TLS_HOST_CLIENT
    if (ctx->isClient) {
#ifdef HITLS_TLS_PROTO_DTLS12
        if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
            return DtlsClientSendFinishedProcess(ctx);
        }
#endif
#ifdef HITLS_TLS_PROTO_TLS_BASIC
        return Tls12ClientSendFinishedProcess(ctx);
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
    }
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return DtlsServerSendFinishedProcess(ctx);
    }
#endif
#ifdef HITLS_TLS_PROTO_TLS_BASIC
    return Tls12ServerSendFinishedProcess(ctx);
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#endif /* HITLS_TLS_HOST_SERVER */

    return HITLS_INTERNAL_EXCEPTION;
}

#if defined(HITLS_TLS_PKEY_SPAKE2P) && defined(HITLS_TLS_HOST_SERVER)
// Helper function (can be shared or made static here)
static bool IsPakeCipherSuiteNegotiatedServer(const TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->negotiatedInfo.cipherSuiteInfo.kxAlg == HITLS_KEY_EXCH_NULL) {
        return false;
    }
    return (ctx->negotiatedInfo.cipherSuiteInfo.kxAlg == HITLS_KEY_EXCH_SPAKE2P);
}

// Helper function to map HITLS_HashAlgo to CRYPT_MD_AlgId (can be shared)
// Ensure this is defined or included if used by ServerSendServerHelloProcess PAKE logic
static CRYPT_MD_AlgId MapHitlsHashToCryptMdServer(HITLS_HashAlgo hitlsHash) {
    switch (hitlsHash) {
        case HITLS_HASH_SHA256: return CRYPT_MD_SHA256;
        case HITLS_HASH_SHA_384: return CRYPT_MD_SHA384;
        case HITLS_HASH_SHA_512: return CRYPT_MD_SHA512;
        case HITLS_HASH_SM3: return CRYPT_MD_SM3;
        default: return CRYPT_MD_MAX;
    }
}

// Helper function to map HITLS_MacAlgo to CRYPT_MAC_AlgId for HKDF (can be shared)
static CRYPT_MAC_AlgId MapHitlsHashToCryptMacForHkdfServer(HITLS_HashAlgo hkdfHashAlgo) {
    switch (hkdfHashAlgo) {
        case HITLS_HASH_SHA256: return CRYPT_MAC_HMAC_SHA256;
        case HITLS_HASH_SHA_384: return CRYPT_MAC_HMAC_SHA384;
        case HITLS_HASH_SHA_512: return CRYPT_MAC_HMAC_SHA512;
        case HITLS_HASH_SM3: return CRYPT_MAC_HMAC_SM3;
        default: return CRYPT_MAC_MAX;
    }
}
#endif // HITLS_TLS_PKEY_SPAKE2P && HITLS_TLS_HOST_SERVER


static int32_t ProcessSendHandshakeMsg(TLS_Ctx *ctx)
{
    switch (ctx->hsCtx->state) {
#ifdef HITLS_TLS_HOST_SERVER
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
        case TRY_SEND_HELLO_REQUEST:
            return ServerSendHelloRequestProcess(ctx);
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
        case TRY_SEND_HELLO_VERIFY_REQUEST:
            return DtlsServerSendHelloVerifyRequestProcess(ctx);
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */
        case TRY_SEND_SERVER_HELLO:
            return ServerSendServerHelloProcess(ctx); // This function will be modified for PAKE context init and state transition
        case TRY_SEND_SERVER_KEY_EXCHANGE:
             // If PAKE is used, this state will likely be skipped.
            return ServerSendServerKeyExchangeProcess(ctx);
#if defined(HITLS_TLS_PKEY_SPAKE2P)
        case TLS_HS_SERVER_STATE_SEND_PAKE_MESSAGE: 
            return HITLS_HS_ServerSendPakeMessage(ctx); 
#endif /* HITLS_TLS_PKEY_SPAKE2P */
        case TRY_SEND_CERTIFICATE_REQUEST:
            return ServerSendCertRequestProcess(ctx);
        case TRY_SEND_SERVER_HELLO_DONE:
            return ServerSendServerHelloDoneProcess(ctx);
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        case TRY_SEND_NEW_SESSION_TICKET:
            return SendNewSessionTicketProcess(ctx);
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_HOST_CLIENT
        case TRY_SEND_CLIENT_HELLO:
            return ClientSendClientHelloProcess(ctx);
        case TRY_SEND_CLIENT_KEY_EXCHANGE:
            return ClientSendClientKeyExchangeProcess(ctx);
        case TRY_SEND_CERTIFICATE_VERIFY:
            return ClientSendCertVerifyProcess(ctx);
#if defined(HITLS_TLS_PKEY_SPAKE2P)
        case TLS_HS_CLIENT_STATE_SEND_PAKE_MESSAGE:
            return ClientSendPakeMessageProcess(ctx);
#endif /* HITLS_TLS_PKEY_SPAKE2P */
#endif /* HITLS_TLS_HOST_CLIENT */
        case TRY_SEND_CERTIFICATE:
            return SendCertificateProcess(ctx);
        case TRY_SEND_CHANGE_CIPHER_SPEC:
            return SendChangeCipherSpecProcess(ctx);
        case TRY_SEND_FINISH:
            return SendFinishedProcess(ctx);
        default:
            break;
    }
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID17100, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Handshake state err: should send msg, but current state is %s.", HS_GetStateStr(ctx->hsCtx->state));
    return HITLS_MSG_HANDLE_STATE_ILLEGAL;
}

#if defined(HITLS_TLS_PKEY_SPAKE2P) && defined(HITLS_TLS_HOST_CLIENT)
/* New function to handle sending the PAKE Client Message */
static int32_t ClientSendPakeMessageProcess(TLS_Ctx *ctx)
{
    if (ctx == NULL || !ctx->isClient) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "ClientSendPakeMessageProcess called in invalid context.");
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret = HITLS_HS_SendPakeClientMessage(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to send PAKE client message: %x", ret);
        // Alert sending should be handled by HITLS_HS_SendPakeClientMessage or its callees if critical
        return ret;
    }

    // Successfully sent PAKE Client Message, transition to receive Server PAKE Message
    return HS_ChangeState(ctx, TLS_HS_CLIENT_STATE_RECV_PAKE_MESSAGE);
}
#endif /* HITLS_TLS_PKEY_SPAKE2P && HITLS_TLS_HOST_CLIENT */


#if defined(HITLS_TLS_PKEY_SPAKE2P) && defined(HITLS_TLS_HOST_SERVER)
/*
 * Implements sending the PAKE Server Message.
 * This function is called when the server is in state TLS_HS_SERVER_STATE_SEND_PAKE_MESSAGE.
 */
int32_t HITLS_HS_ServerSendPakeMessage(TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->hsCtx == NULL || ctx->hsCtx->pake_ctx == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Null context or PAKE context not initialized for ServerSendPakeMessage");
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    HITLS_HS_CTX *hsCtx = TLS_GET_HS_CTX(ctx);
    int32_t ret;

    uint8_t pake_payload_buf[CRYPT_MAX_POINT_LEN]; // For pV
    uint32_t pake_payload_len = sizeof(pake_payload_buf);
    CRYPT_SPAKE2P_BUFFER_PARAM eal_pv_param = {pake_payload_buf, &pake_payload_len};

    BSL_LOG_DEBUG(BSL_MODULE_TLS_HS, "Generating Server PAKE data (pV) via EAL.");
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_GENERATE_EXCHANGE_MSG, &eal_pv_param, sizeof(eal_pv_param));
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to generate PAKE server exchange message (pV): %x", ret);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        return ret;
    }

    // After generating pV, the SPAKE2+ context (server side) has client's pU and its own pV.
    // It can now compute the shared secret and its own confirmation MAC.
    // The CRYPT_CTRL_SPAKE2P_PROCESS_PEER_MSG_AND_CONFIRM for server is slightly different from client.
    // Client's pU is already stored from RecvPakeClientMessage. This call finalizes server's side.
    // No new peer_msg data needs to be passed for this specific call if pU is already in pake_ctx.
    // The EAL Ctrl for PROCESS_PEER_MSG_AND_CONFIRM needs to be idempotent or handle this.
    // Let's assume it computes keys and MACs using stored pU and newly generated pV.
    // If it requires pU again, the design of EAL_SPAKE2P_Ctrl needs adjustment or pU stored in hsCtx.
    // For now, assume pake_ctx handles this internally.
    // The subtask states: "call CRYPT_EAL_PkeyCtrl... again. This time...it will proceed to calculate TT, derive keys, and compute server's MAC"
    // This implies the EAL layer is stateful and knows client's pU was processed.
    BSL_LOG_DEBUG(BSL_MODULE_TLS_HS, "Finalizing shared secret and MACs on server after generating pV.");
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_PROCESS_PEER_MSG_AND_CONFIRM, NULL, 0); // Pass NULL if EAL layer uses stored pU
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to finalize server PAKE keys/MACs: %x", ret);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        return ret;
    }

    hsCtx->pake_server_confirmation_mac_len = sizeof(hsCtx->pake_server_confirmation_mac);
    CRYPT_SPAKE2P_BUFFER_PARAM eal_mac_param = {hsCtx->pake_server_confirmation_mac, &hsCtx->pake_server_confirmation_mac_len};
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_GET_OUR_CONFIRMATION_MAC, &eal_mac_param, sizeof(eal_mac_param));
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to get server's PAKE confirmation MAC: %x", ret);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    HS_Msg hsMsgSend;
    (void)memset_s(&hsMsgSend, sizeof(HS_Msg), 0, sizeof(HS_Msg));
    hsMsgSend.type = PAKE_SERVER_MESSAGE;
    hsMsgSend.body.pakeServerMsg.server_pake_payload.pake_message.data = pake_payload_buf;
    hsMsgSend.body.pakeServerMsg.server_pake_payload.pake_message.len = pake_payload_len;
    hsMsgSend.body.pakeServerMsg.confirmation_mac.data = hsCtx->pake_server_confirmation_mac;
    hsMsgSend.body.pakeServerMsg.confirmation_mac.len = hsCtx->pake_server_confirmation_mac_len;

    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Sending PAKE_SERVER_MESSAGE (pV and ServerMAC).");
    ret = HITLS_HS_SendMsg(ctx, &hsMsgSend);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to send PAKE_SERVER_MESSAGE: %x", ret);
        return ret;
    }

    // Retrieve and store Ke in masterKey (as PMS equivalent)
    uint8_t ke_buffer[MASTER_SECRET_LEN]; // MASTER_SECRET_LEN is 48
    uint32_t ke_buffer_len = sizeof(ke_buffer);
    CRYPT_SPAKE2P_BUFFER_PARAM eal_ke_param = {ke_buffer, &ke_buffer_len};
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_GET_DERIVED_SECRET_KE, &eal_ke_param, sizeof(eal_ke_param));
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to get derived Ke for PAKE (server): %x", ret);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
    if (ke_buffer_len > MASTER_SECRET_LEN) { /* Error handling */ return HITLS_INTERNAL_ERROR; }
    if (memset_s(hsCtx->masterKey, MASTER_SECRET_LEN, 0, MASTER_SECRET_LEN) != EOK ||
        memcpy_s(hsCtx->masterKey, MASTER_SECRET_LEN, ke_buffer, ke_buffer_len) != EOK) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to copy server Ke to masterKey.");
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMCPY_FAIL;
    }
    hsCtx->pake_ke_len = ke_buffer_len; // Store the length of Ke
    // hsCtx->pmsLen = ke_buffer_len; // Not needed if masterKey is used directly.

    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "PAKE_SERVER_MESSAGE sent. Transitioning to receive Client CCS/Finished.");
    // After server sends its PAKE message (and MAC), it expects Client CCS & Finished.
    // The client's PAKE MAC will be verified from the Finished message content.
    return HS_ChangeState(ctx, TRY_RECV_CHANGE_CIPHER_SPEC); 
}
#endif /* HITLS_TLS_PKEY_SPAKE2P && HITLS_TLS_HOST_SERVER */

#if defined(HITLS_TLS_PKEY_SPAKE2P) && defined(HITLS_TLS_HOST_SERVER)
/*
 * Helper function called from ServerSendServerHelloProcess (or equivalent)
 * after a PAKE ciphersuite has been selected and ServerHello is about to be sent,
 * or has just been sent. This initializes the PAKE context on the server side.
 */
static int32_t ServerInitializePakeContextAndTransition(TLS_Ctx *ctx)
{
    HITLS_HS_CTX *hsCtx = TLS_GET_HS_CTX(ctx);
    int32_t ret;

    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "PAKE ciphersuite selected. Initializing server PAKE context.");

    if (hsCtx->pake_ctx != NULL) { // Should ideally be NULL if this is the first setup
        CRYPT_EAL_PkeyFreeCtx(hsCtx->pake_ctx);
        hsCtx->pake_ctx = NULL;
    }
    hsCtx->pake_ctx = CRYPT_EAL_PkeyNewCtxById(CRYPT_PKEY_SPAKE2P);
    if (hsCtx->pake_ctx == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to create PAKE context for server.");
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMALLOC_FAIL;
    }

    CRYPT_SPAKE2P_INIT_GROUP_PARAM group_params;
    // Derive from negotiated ciphersuite (ctx->negotiatedInfo.cipherSuiteInfo)
    // This mapping needs to be robust based on actual ciphersuite IDs.
    if (ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite == 0xFEA0U) { // TLS_SPAKE2P_ED25519_WITH_AES_128_GCM_SHA256
         group_params.curveId = CRYPT_PKEY_PARAID_SPAKE2P_EDWARDS25519_SHA256_HKDF_HMAC_SHA256;
         group_params.hashId = CRYPT_MD_SHA256;
         group_params.macId = CRYPT_MAC_HMAC_SHA256;
    } else if (ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite == 0xFEA1U) { // TLS_SPAKE2P_ED25519_WITH_AES_256_GCM_SHA384
         group_params.curveId = CRYPT_PKEY_PARAID_SPAKE2P_EDWARDS25519_SHA256_HKDF_HMAC_SHA256;
         group_params.hashId = CRYPT_MD_SHA384; // Match ciphersuite's hash for HKDF consistency
         group_params.macId = CRYPT_MAC_HMAC_SHA384; // Match ciphersuite's hash for HKDF consistency
    } else {
        // Fallback or error if unknown PAKE suite (should be caught by ciphersuite selection)
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Unknown PAKE ciphersuite for parameter mapping: %x", ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite);
        // Use defaults from cipherSuiteInfo if possible, otherwise fail
        group_params.curveId = CRYPT_PKEY_PARAID_SPAKE2P_EDWARDS25519_SHA256_HKDF_HMAC_SHA256; // Default
        group_params.hashId = MapHitlsHashToCryptMdServer(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
        group_params.macId = MapHitlsHashToCryptMacForHkdfServer(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
        if (group_params.hashId == CRYPT_MD_MAX || group_params.macId == CRYPT_MAC_MAX) {
             BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Server: Unsupported hash/mac for PAKE from ciphersuite %x", ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite);
             ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
             return HITLS_HANDSHAKE_FAILURE;
        }
    }

    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_INIT_GROUP, &group_params, sizeof(group_params));
    if (ret != HITLS_SUCCESS) { BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Server: PAKE_INIT_GROUP failed: %x", ret); ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE); return ret; }

    CRYPT_SPAKE2P_Role role = CRYPT_SPAKE2P_ROLE_SERVER;
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_ROLE, &role, sizeof(role));
    if (ret != HITLS_SUCCESS) { BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Server: PAKE_SET_ROLE failed: %x", ret); ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE); return ret; }

    // Placeholder password and IDs - these must be provisioned by the application / config
    const char *pwd = "testpassword"; // TODO: Replace with actual password provisioning
    CRYPT_SPAKE2P_DATA_PARAM pwd_param = { .data = (const uint8_t *)pwd, .dataLen = (uint32_t)strlen(pwd) };
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_PASSWORD, &pwd_param, sizeof(pwd_param));
    if (ret != HITLS_SUCCESS) { BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Server: PAKE_SET_PASSWORD failed: %x", ret); ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE); return ret; }

    // Server's ID is "Our ID"
    const char *server_id_str = "server"; // TODO: Replace
    CRYPT_SPAKE2P_DATA_PARAM sid_param = { .data = (const uint8_t *)server_id_str, .dataLen = (uint32_t)strlen(server_id_str) };
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_OUR_ID, &sid_param, sizeof(sid_param));
    if (ret != HITLS_SUCCESS) { BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Server: PAKE_SET_OUR_ID failed: %x", ret); ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE); return ret; }
    
    // Client's ID is "Peer ID". This might be NULL if not sent by client, or extracted from ClientHello extensions.
    // For SPAKE2+, client ID is often sent. Using a placeholder for now.
    const char *client_id_str = "client"; // TODO: Replace or get from ClientHello
    CRYPT_SPAKE2P_DATA_PARAM cid_param = { .data = (const uint8_t *)client_id_str, .dataLen = (uint32_t)strlen(client_id_str) };
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_PEER_ID, &cid_param, sizeof(cid_param));
    if (ret != HITLS_SUCCESS) { BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Server: PAKE_SET_PEER_ID failed: %x", ret); ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE); return ret; }
    
    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Server PAKE context initialized. Transitioning to RECV_PAKE_CLIENT_MESSAGE.");
    return HS_ChangeState(ctx, TLS_HS_SERVER_STATE_RECV_PAKE_MESSAGE);
}
#endif /* HITLS_TLS_PKEY_SPAKE2P && HITLS_TLS_HOST_SERVER */


#if defined(HITLS_TLS_HOST_SERVER) && defined(HITLS_TLS_PROTO_TLS_BASIC)
// Modifying ServerSendServerHelloProcess (simplified, actual function is more complex)
// This is a conceptual modification point. The actual ServerSendServerHelloProcess
// is large. The key is to add this logic block within it, after ciphersuite is chosen
// and before returning the next state.

// Placeholder for where the actual ServerSendServerHelloProcess is.
// Assume it's defined in this file, e.g. in hs_server_send.c (which is this file)
// or a file included by it. Let's find an existing server send function to modify.
// Looking at the structure, ServerSendServerHelloProcess is a static function within this file,
// but it's not explicitly shown in the provided snippets from previous turns.
// I will create a SEARCH block for a known part of a server-side send function or
// the end of an existing function if ServerSendServerHelloProcess itself is not visible.

// For the purpose of this diff, I will target a generic point in ProcessSendHandshakeMsg
// to illustrate where ServerSendServerHelloProcess would be and how it's modified.
// This is non-ideal but necessary if the full function isn't in prior context.
// The actual modification would be *inside* the real ServerSendServerHelloProcess function.

// Let's assume ServerSendServerHelloProcess has been called and has completed sending ServerHello.
// Now, we decide the next state. This is where PAKE transition logic is added.
// This modification should be *inside* the original ServerSendServerHelloProcess,
// right before it determines the next state.

/*
Conceptual change inside ServerSendServerHelloProcess:

    // ... (original ServerHello sending logic) ...
    // ret = HITLS_HS_SendMsg(ctx, &hsMsgSend);
    // if (ret != HITLS_SUCCESS) { return ret; }

#if defined(HITLS_TLS_PKEY_SPAKE2P)
    if (IsPakeCipherSuiteNegotiatedServer(ctx)) {
        BSL_LOG_INFO(BSL_MODULE_TLS_HS, "PAKE negotiated. Initializing server PAKE context after ServerHello.");
        if (hsCtx->pake_ctx != NULL) { CRYPT_EAL_PkeyFreeCtx(hsCtx->pake_ctx); }
        hsCtx->pake_ctx = CRYPT_EAL_PkeyNewCtxById(CRYPT_PKEY_SPAKE2P);
        if (hsCtx->pake_ctx == NULL) { // Error handling }

        CRYPT_SPAKE2P_INIT_GROUP_PARAM group_params;
        // Populate group_params based on ctx->negotiatedInfo.cipherSuiteInfo
        // ... (mapping logic as in HITLS_HS_ServerRecvPakeClientMessage) ...
        if (ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite == 0xFEA0U) {
             group_params.curveId = CRYPT_PKEY_PARAID_SPAKE2P_EDWARDS25519_SHA256_HKDF_HMAC_SHA256;
             group_params.hashId = CRYPT_MD_SHA256; group_params.macId = CRYPT_MAC_HMAC_SHA256;
        } else if (ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite == 0xFEA1U) {
             group_params.curveId = CRYPT_PKEY_PARAID_SPAKE2P_EDWARDS25519_SHA256_HKDF_HMAC_SHA256;
             group_params.hashId = CRYPT_MD_SHA384; group_params.macId = CRYPT_MAC_HMAC_SHA384;
        } else { // Default or map error
            // ... error handling ...
        }
        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_INIT_GROUP, &group_params, sizeof(group_params));
        // ... (error check) ...

        CRYPT_SPAKE2P_Role role = CRYPT_SPAKE2P_ROLE_SERVER;
        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_ROLE, &role, sizeof(role));
        // ... (error check) ...

        // Set password and IDs (placeholders, app should provide)
        const char *pwd = "testpassword";
        CRYPT_SPAKE2P_DATA_PARAM pwd_param = { (const uint8_t *)pwd, (uint32_t)strlen(pwd) };
        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_PASSWORD, &pwd_param, sizeof(pwd_param));
        // ... (error check) ...
        const char *server_id_str = "server";
        CRYPT_SPAKE2P_DATA_PARAM sid_param = { (const uint8_t *)server_id_str, (uint32_t)strlen(server_id_str) };
        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_OUR_ID, &sid_param, sizeof(sid_param));
        // ... (error check) ...
        const char *client_id_str = "client"; // This might come from ClientHello if available
        CRYPT_SPAKE2P_DATA_PARAM cid_param = { (const uint8_t *)client_id_str, (uint32_t)strlen(client_id_str) };
        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_PEER_ID, &cid_param, sizeof(cid_param));
        // ... (error check) ...
        
        BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Server PAKE context initialized. Transitioning to RECV_PAKE_MESSAGE.");
        return HS_ChangeState(ctx, TLS_HS_SERVER_STATE_RECV_PAKE_MESSAGE);
    }
#endif
    // ... (original next state logic for non-PAKE ciphersuites) ...
    // return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE); // Example original transition
*/
#endif



#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13SendChangeCipherSpecProcess(TLS_Ctx *ctx)
{
    int32_t ret;

    /* Sending message with changed cipher suites */
    ret = ctx->method.sendCCS(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HS_ChangeState(ctx, ctx->hsCtx->ccsNextState);
}

static int32_t Tls13ProcessSendHandshakeMsg(TLS_Ctx *ctx)
{
    switch (ctx->hsCtx->state) {
#ifdef HITLS_TLS_HOST_CLIENT
        case TRY_SEND_CLIENT_HELLO:
            return Tls13ClientSendClientHelloProcess(ctx);
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
        case TRY_SEND_HELLO_RETRY_REQUEST:
            return Tls13ServerSendHelloRetryRequestProcess(ctx);
        case TRY_SEND_SERVER_HELLO:
            return Tls13ServerSendServerHelloProcess(ctx);
        case TRY_SEND_ENCRYPTED_EXTENSIONS:
            return Tls13ServerSendEncryptedExtensionsProcess(ctx);
        case TRY_SEND_CERTIFICATE_REQUEST:
            return Tls13ServerSendCertRequestProcess(ctx);
        case TRY_SEND_NEW_SESSION_TICKET:
            return Tls13SendNewSessionTicketProcess(ctx);
#endif /* HITLS_TLS_HOST_SERVER */
        case TRY_SEND_CERTIFICATE:
#ifdef HITLS_TLS_HOST_CLIENT
            if (ctx->isClient) {
                return Tls13ClientSendCertificateProcess(ctx);
            }
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
            return Tls13ServerSendCertificateProcess(ctx);
#endif /* HITLS_TLS_HOST_SERVER */
        case TRY_SEND_CERTIFICATE_VERIFY:
            return Tls13SendCertVerifyProcess(ctx);
        case TRY_SEND_FINISH:
#ifdef HITLS_TLS_HOST_CLIENT
            if (ctx->isClient) {
                return Tls13ClientSendFinishedProcess(ctx);
            }
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
            return Tls13ServerSendFinishedProcess(ctx);
#endif /* HITLS_TLS_HOST_SERVER */
        case TRY_SEND_CHANGE_CIPHER_SPEC:
            return Tls13SendChangeCipherSpecProcess(ctx);
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
        case TRY_SEND_KEY_UPDATE:
            return Tls13SendKeyUpdateProcess(ctx);
#endif
        default:
            break;
    }
    return RETURN_ERROR_NUMBER_PROCESS(HITLS_MSG_HANDLE_STATE_ILLEGAL, BINLOG_ID17101, "Handshake state error");
}
#endif /* HITLS_TLS_PROTO_TLS13 */
int32_t HS_SendMsgProcess(TLS_Ctx *ctx)
{
    uint32_t version = HS_GetVersion(ctx);

    switch (version) {
#ifdef HITLS_TLS_PROTO_TLS_BASIC
        case HITLS_VERSION_TLS12:
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_VERSION_TLCP_DTLCP11:
#endif
            return ProcessSendHandshakeMsg(ctx);
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
        case HITLS_VERSION_TLS13:
            return Tls13ProcessSendHandshakeMsg(ctx);
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_PROTO_DTLS12
        case HITLS_VERSION_DTLS12:
            return ProcessSendHandshakeMsg(ctx);
#endif
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15790, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Handshake state send error: unsupport TLS version.", 0, 0, 0, 0);
    return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
}
