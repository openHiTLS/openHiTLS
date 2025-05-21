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
#if defined(HITLS_TLS_PKEY_SPAKE2P) && defined(HITLS_TLS_HOST_CLIENT)

#include "hs_send_pake.h"
#include "hs_ctx.h"         /* For HITLS_HS_CTX */
#include "hs_msg.h"         /* For HS_Msg and PakeClientMessage (via hs_msg_pake.h included by hs_common.h->hs_msg.h) */
#include "hs_msg_pake.h"    /* Explicit include for PakeClientMessage structure if not pulled by hs_msg.h */
// #include "hs_pack_pake.h"   /* Not directly used; HITLS_HS_SendMsg calls HITLS_HS_PackMsgBody */
#include "hs_send.h"        /* For HITLS_HS_SendMsg */
#include "hs_common.h"      /* For HS_ChangeState, HS_MsgType */
#include "crypt_eal_pkey.h" /* For CRYPT_EAL_PkeyCtx, CRYPT_EAL_PkeyNewCtxById, CRYPT_EAL_PkeyCtrl */
#include "crypt_spake2p.h"  /* For PAKE control commands and CRYPT_SPAKE2P_... structures */
#include "crypt_algid.h"    /* For CRYPT_PKEY_SPAKE2P, CRYPT_PKEY_PARAID_*, CRYPT_MD_*, CRYPT_MAC_* */
#include "alert.h"          /* For ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE etc. */
#include "bsl_err_internal.h"
#include "bsl_log_internal.h"
#include "tls_util_common.h" /* For TLS_GET_HS_CTX */
#include "tls.h"             /* For HITLS_HandshakeState definitions, TLS_Ctx */
#include "cipher_suite.h"    /* For CipherSuiteInfo and IsPakeCipherSuiteNegotiated (if moved there or kxAlg) */
#include "securec.h"         /* For memset_s, strlen */


// Helper function to map HITLS_HashAlgo to CRYPT_MD_AlgId (if not already globally available)
// This is a simplified example; a robust implementation would have a comprehensive mapping function.
static CRYPT_MD_AlgId MapHitlsHashToCryptMdLocal(HITLS_HashAlgo hitlsHash)
{
    switch (hitlsHash) {
        case HITLS_HASH_SHA256: return CRYPT_MD_SHA256;
        case HITLS_HASH_SHA_384: return CRYPT_MD_SHA384;
        case HITLS_HASH_SHA_512: return CRYPT_MD_SHA512;
        case HITLS_HASH_SM3: return CRYPT_MD_SM3;
        default: return CRYPT_MD_MAX; // Unknown or unsupported
    }
}

// Helper function to map HITLS_MacAlgo to CRYPT_MAC_AlgId for HKDF context
static CRYPT_MAC_AlgId MapHitlsHashToCryptMacForHkdfLocal(HITLS_HashAlgo hkdfHashAlgo)
{
    switch (hkdfHashAlgo) {
        case HITLS_HASH_SHA256: return CRYPT_MAC_HMAC_SHA256;
        case HITLS_HASH_SHA_384: return CRYPT_MAC_HMAC_SHA384;
        case HITLS_HASH_SHA_512: return CRYPT_MAC_HMAC_SHA512;
        case HITLS_HASH_SM3: return CRYPT_MAC_HMAC_SM3;
        default: return CRYPT_MAC_MAX;
    }
}


/*
 * Implements sending the PAKE Client Message.
 * This function is called when the client is in state TLS_HS_CLIENT_STATE_SEND_PAKE_MESSAGE.
 */
int32_t HITLS_HS_ClientSendPakeMessage(TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->hsCtx == NULL) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Null context for ClientSendPakeMessage");
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_HS_CTX *hsCtx = TLS_GET_HS_CTX(ctx);
    int32_t ret;

    // Fallback initialization of pake_ctx if not done in ClientRecvServerHelloProcess
    // This is as per subtask description, though ideally it's initialized earlier.
    if (hsCtx->pake_ctx == NULL) {
        BSL_LOG_WARN(BSL_MODULE_TLS_HS, "PAKE context was NULL; attempting fallback initialization.");
        hsCtx->pake_ctx = CRYPT_EAL_PkeyNewCtxById(CRYPT_PKEY_SPAKE2P);
        if (hsCtx->pake_ctx == NULL) {
            BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Fallback: Failed to create PAKE context.");
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return HITLS_MEMALLOC_FAIL;
        }

        CRYPT_SPAKE2P_INIT_GROUP_PARAM group_params;
        // These should be derived from the selected ciphersuite (ctx->negotiatedInfo.cipherSuiteInfo)
        // For example, if cipherSuite is TLS_SPAKE2P_ED25519_WITH_AES_128_GCM_SHA256 (0xFEA0)
        // curveId should be for Ed25519, hashId for SHA256, macId for HMAC-SHA256 (for HKDF)
        // This mapping needs to be robust.
        if (ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite == 0xFEA0U) { // TLS_SPAKE2P_ED25519_WITH_AES_128_GCM_SHA256
             group_params.curveId = CRYPT_PKEY_PARAID_SPAKE2P_EDWARDS25519_SHA256_HKDF_HMAC_SHA256; // This ID implies group and hash/mac for HKDF
             group_params.hashId = CRYPT_MD_SHA256; // Main hash for pw
             group_params.macId = CRYPT_MAC_HMAC_SHA256; // For HKDF
        } else if (ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite == 0xFEA1U) { // TLS_SPAKE2P_ED25519_WITH_AES_256_GCM_SHA384
             group_params.curveId = CRYPT_PKEY_PARAID_SPAKE2P_EDWARDS25519_SHA256_HKDF_HMAC_SHA256; // Assuming same group, but hash/mac for HKDF might differ if ciphersuite implies it
             group_params.hashId = CRYPT_MD_SHA384;
             group_params.macId = CRYPT_MAC_HMAC_SHA384;
        } else {
            // Fallback to defaults or use mapped values from cipherSuiteInfo
            group_params.curveId = CRYPT_PKEY_PARAID_SPAKE2P_EDWARDS25519_SHA256_HKDF_HMAC_SHA256; // Default
            group_params.hashId = MapHitlsHashToCryptMdLocal(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
            group_params.macId = MapHitlsHashToCryptMacForHkdfLocal(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg); // Assuming HKDF uses the main hash
            if (group_params.hashId == CRYPT_MD_MAX || group_params.macId == CRYPT_MAC_MAX) {
                 BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Fallback: Unsupported hash/mac for PAKE from ciphersuite.");
                 ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
                 return HITLS_HANDSHAKE_FAILURE;
            }
        }

        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_INIT_GROUP, &group_params, sizeof(group_params));
        if (ret != HITLS_SUCCESS) { BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Fallback: PAKE_INIT_GROUP failed: %x", ret); ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE); return ret; }

        CRYPT_SPAKE2P_Role role = CRYPT_SPAKE2P_ROLE_CLIENT;
        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_ROLE, &role, sizeof(role));
        if (ret != HITLS_SUCCESS) { BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Fallback: PAKE_SET_ROLE failed: %x", ret); ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE); return ret; }

        // Placeholder password and IDs - these must be provisioned by the application
        const char *pwd = "testpassword"; // TODO: Replace with actual password provisioning
        CRYPT_SPAKE2P_DATA_PARAM pwd_param = { .data = (const uint8_t *)pwd, .dataLen = (uint32_t)strlen(pwd) };
        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_PASSWORD, &pwd_param, sizeof(pwd_param));
        if (ret != HITLS_SUCCESS) { BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Fallback: PAKE_SET_PASSWORD failed: %x", ret); ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE); return ret; }

        const char *client_id_str = "client"; // TODO: Replace with actual ID provisioning
        CRYPT_SPAKE2P_DATA_PARAM cid_param = { .data = (const uint8_t *)client_id_str, .dataLen = (uint32_t)strlen(client_id_str) };
        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_OUR_ID, &cid_param, sizeof(cid_param));
        if (ret != HITLS_SUCCESS) { BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Fallback: PAKE_SET_OUR_ID failed: %x", ret); ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE); return ret; }
        
        const char *server_id_str = "server"; // TODO: Replace with actual ID provisioning
        CRYPT_SPAKE2P_DATA_PARAM sid_param = { .data = (const uint8_t *)server_id_str, .dataLen = (uint32_t)strlen(server_id_str) };
        ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_SET_PEER_ID, &sid_param, sizeof(sid_param));
        if (ret != HITLS_SUCCESS) { BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Fallback: PAKE_SET_PEER_ID failed: %x", ret); ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE); return ret; }
        BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Fallback PAKE context initialization complete.");
    }


    uint8_t pake_payload_buf[CRYPT_MAX_POINT_LEN]; 
    uint32_t pake_payload_len = sizeof(pake_payload_buf);

    CRYPT_SPAKE2P_BUFFER_PARAM eal_buffer_param;
    eal_buffer_param.buffer = pake_payload_buf;
    eal_buffer_param.bufferLen = &pake_payload_len;

    BSL_LOG_DEBUG(BSL_MODULE_TLS_HS, "Generating Client PAKE data (pU) via EAL.");
    ret = CRYPT_EAL_PkeyCtrl(hsCtx->pake_ctx, CRYPT_CTRL_SPAKE2P_GENERATE_EXCHANGE_MSG,
                             &eal_buffer_param, sizeof(eal_buffer_param));
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to generate PAKE client exchange message from EAL: %x", ret);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        return ret;
    }
    BSL_LOG_DEBUG(BSL_MODULE_TLS_HS, "Client PAKE data (pU) generated, len %u.", pake_payload_len);
    PRINT_HEX_DATA(BSL_MODULE_TLS_HS, BSL_LOG_LEVEL_DEBUG, "Client PAKE Payload (pU) to send",
                   pake_payload_buf, pake_payload_len);

    HS_Msg hsMsgSend;
    (void)memset_s(&hsMsgSend, sizeof(HS_Msg), 0, sizeof(HS_Msg));
    hsMsgSend.type = PAKE_CLIENT_MESSAGE;

    hsMsgSend.body.pakeClientMsg.client_pake_payload.pake_message.data = pake_payload_buf;
    hsMsgSend.body.pakeClientMsg.client_pake_payload.pake_message.len = pake_payload_len;

    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "Sending PAKE_CLIENT_MESSAGE.");
    ret = HITLS_HS_SendMsg(ctx, &hsMsgSend); 
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_ERROR(BSL_MODULE_TLS_HS, "Failed to send PAKE_CLIENT_MESSAGE: %x", ret);
        return ret;
    }

    BSL_LOG_INFO(BSL_MODULE_TLS_HS, "PAKE_CLIENT_MESSAGE sent successfully.");
    return HITLS_SUCCESS;
}

#endif /* HITLS_TLS_PKEY_SPAKE2P && HITLS_TLS_HOST_CLIENT */
