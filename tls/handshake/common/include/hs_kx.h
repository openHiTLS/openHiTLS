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

#ifndef HS_KX_H
#define HS_KX_H

#include <stdint.h>
#include "hs_ctx.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MASTER_SECRET_LABEL "CLIENT_RANDOM"
#define CLIENT_EARLY_LABEL "CLIENT_EARLY_TRAFFIC_SECRET"
#define CLIENT_HANDSHAKE_LABEL "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
#define SERVER_HANDSHAKE_LABEL "SERVER_HANDSHAKE_TRAFFIC_SECRET"
#define CLIENT_APPLICATION_LABEL "CLIENT_TRAFFIC_SECRET_0"
#define SERVER_APPLICATION_LABEL "SERVER_TRAFFIC_SECRET_0"
#define EARLY_EXPORTER_SECRET_LABEL "EARLY_EXPORTER_SECRET"
#define EXPORTER_SECRET_LABEL "EXPORTER_SECRET"

/* The maximum premaster secret calculated by using the PSK may be:
 * |uint16_t|MAX_OTHER_SECRET_SIZE|uint16_t|HS_PSK_MAX_LEN| */
#define MAX_OTHER_SECRET_SIZE 1536
#define MAX_PRE_MASTER_SECRET_SIZE (sizeof(uint16_t) + MAX_OTHER_SECRET_SIZE + sizeof(uint16_t) + HS_PSK_MAX_LEN)
#define MAX_SHA1_SIZE 20
#define MAX_MD5_SIZE 16

/**
 * @brief Create a key exchange context.
 *
 * @return A KeyExchCtx pointer is returned. If NULL is returned, the creation fails.
 */
KeyExchCtx *HS_KeyExchCtxNew(void);

/**
 * @brief   Release the key exchange context
 *
 * @param   keyExchCtx [IN] Key exchange context. KeyExchCtx is left empty by the invoker
 */
void HS_KeyExchCtxFree(KeyExchCtx *keyExchCtx);

/**
 * @brief   Process the server ECDHE key exchange message
 *
 * @param ctx [IN] TLS context
 * @param serverKxMsg [IN] Parsed handshake message
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 * @retval HITLS_MSG_HANDLE_UNKNOWN_CURVE_TYPE Unsupported elliptic curve type
 * @retval HITLS_MSG_HANDLE_UNSUPPORT_NAMED_CURVE Unsupported ECDH elliptic curve
 * @retval HITLS_MSG_HANDLE_ERR_ENCODE_ECDH_KEY Failed to obtain the ECDH public key.
 */
int32_t HS_ProcessServerKxMsgEcdhe(TLS_Ctx *ctx, const ServerKeyExchangeMsg *serverKxMsg);

/**
 * @brief Process the client ECDHE key exchange message
 *
 * @param ctx [IN] TLS context
 * @param clientKxMsg [IN] Parsed handshake message
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 * @retval HITLS_MSG_HANDLE_UNKNOWN_CURVE_TYPE Unsupported elliptic curve type
 * @retval HITLS_MSG_HANDLE_UNSUPPORT_NAMED_CURVE Unsupported ECDH elliptic curve
 */
int32_t HS_ProcessClientKxMsgEcdhe(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg);

/**
 * @brief Process the server DH key exchange message
 *
 * @param ctx [IN] TLS context
 * @param serverKxMsg [IN] Parsed handshake message
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 * @retval HITLS_MSG_HANDLE_ERR_ENCODE_DH_KEY Failed to obtain the DH public key.
 */
int32_t HS_ProcessServerKxMsgDhe(TLS_Ctx *ctx, const ServerKeyExchangeMsg *serverKxMsg);

/**
 * @brief Process the client DH key exchange message
 *
 * @param ctx [IN] TLS context
 * @param clientKxMsg [IN] Parsed handshake message
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 */
int32_t HS_ProcessClientKxMsgDhe(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg);

int32_t HS_ProcessClientKxMsgRsa(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg);

int32_t HS_ProcessClientKxMsgSm2(TLS_Ctx *ctx, const ClientKeyExchangeMsg *clientKxMsg);

/**
 * @brief Derive the master secret.
 *
 * @param ctx [IN] TLS context
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MSG_HANDLE_UNSUPPORT_KX_ALG Unsupported Key Exchange Algorithm
 * @retval For other error codes, see SAL_CRYPT_CalcEcdhSharedSecret.
 */
int32_t HS_GenerateMasterSecret(TLS_Ctx *ctx);

/**
 * @brief Process the identity hint contained in ServerKeyExchange during PSK negotiation.
 *
 * @param ctx [IN] TLS context
 * @param serverKxMsg [IN] Parsed handshake message
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK The callback for obtaining the PSK on the client is not set.
 * @retval HITLS_CONFIG_INVALID_LENGTH The length of the prompt message is incorrect.
 * @retval HITLS_MEMALLOC_FAIL Memory application failed.
 */
int32_t HS_ProcessServerKxMsgIdentityHint(TLS_Ctx *ctx, const ServerKeyExchangeMsg *serverKxMsg);

/**
 * @brief TLS1.3 derived secret
 *
 * @param deriveInfo [IN] secret derivation material
 * @param isHashed [IN] true: indicates that the seed has been hashed false: indicates that the seed has not been
 * hashed.
 * @param outSecret [OUT] Output secret
 * @param outLen [IN] Output secret length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST hash calculation fails.
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND HKDF-Expand calculation fails.
 */
int32_t HS_TLS13DeriveSecret(CRYPT_KeyDeriveParameters *deriveInfo, bool isHashed, uint8_t *outSecret, uint32_t outLen);

int32_t HS_TLS13DeriveBinderKey(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, bool isExternalPsk, uint8_t *earlySecret, uint32_t secretLen,
    uint8_t *binderKey, uint32_t keyLen);

/**
 * @brief TLS1.3 Calculate the early secret.
 *
 * @param hashAlg [IN] secret derivation material
 * @param psk [IN] PSK
 * @param pskLen [OUT] PSK length
 * @param earlySecret [IN] Output secret
 * @param outLen [IN] Output secret length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval HITLS_CRYPT_ERR_HKDF_EXTRACT HKDF-Extract calculation failure
 */
int32_t HS_TLS13DeriveEarlySecret(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, uint8_t *psk, uint32_t pskLen, uint8_t *earlySecret, uint32_t *outLen);

/**
 * @brief TLS1.3 Calculate the secret in the next phase.
 *
 * @param hashAlg [IN] Hash algorithm
 * @param inSecret [IN] secret of the current phase
 * @param inLen [OUT] Current secret length
 * @param givenSecret [IN] The secret specified by the
 * @param givenLen [IN] Specify the secret length.
 * @param outSecret [IN] Output secret
 * @param outLen [IN/OUT] IN: Maximum buffer length OUT: Output secret length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST hash calculation fails.
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND HKDF-Expand calculation fails.
 * @retval HITLS_CRYPT_ERR_HKDF_EXTRACT HKDF-Extract calculation failure
 */
int32_t HS_TLS13DeriveNextStageSecret(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, uint8_t *inSecret, uint32_t inLen, uint8_t *givenSecret,
    uint32_t givenLen, uint8_t *outSecret, uint32_t *outLen);

/**
 * @brief TLS1.3 Calculate the FinishedKey.
 *
 * @param hashAlg [IN] Hash algorithm
 * @param baseKey [IN] Key of the current phase
 * @param baseKeyLen [IN] Current key length
 * @param finishedkey [OUT] Output key
 * @param finishedkeyLen [IN] Output key length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST hash calculation failed.
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND HKDF-Expand calculation fails.
 */
int32_t HS_TLS13DeriveFinishedKey(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_HashAlgo hashAlgo, uint8_t *baseKey, uint32_t baseKeyLen, uint8_t *finishedkey, uint32_t finishedkeyLen);

/**
 * @brief TLS1.3 Switch the traffickey.
 *
 * @param ctx [IN] TLS context
 * @param secret [IN] secret for calculating writekey and writeiv
 * @param secretLen [IN] Input the secret length.
 * @param isOut [IN] It is used to determine writeSate and readState.
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST hash calculation failed.
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND HKDF-Expand calculation fails.
 * @retval HITLS_INTERNAL_EXCEPTION Invalid null pointer
 */
int32_t HS_SwitchTrafficKey(TLS_Ctx *ctx, uint8_t *secret, uint32_t secretLen, bool isOut);

/**
 * @brief Set parameters for initializing the panding state of the record layer.
 *
 * @param ctx [IN] TLS context
 * @param isClient [IN] Whether it is a client
 * @param keyPara [OUT] Output parameter
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MEMCPY_FAIL Memory Copy Failure
 */
int32_t HS_SetInitPendingStateParam(const TLS_Ctx *ctx, bool isClient, REC_SecParameters *keyPara);

/**
 * @brief TLS1.3 Derives the secret of the ServerHello procedure.
 *
 * @param ctx [IN] TLS context
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND HKDF-Expand calculation fails.
 * @retval HITLS_CRYPT_ERR_HKDF_EXTRACT HKDF-Extract calculation failed.
 * @retval HITLS_CRYPT_ERR_CALC_SHARED_KEY Failed to calculate the shared key.
 * @retval HITLS_CRYPT_ERR_DIGEST hash calculation fails.
 * @retval For details about other error codes, see the SAL_CRYPT_DigestFinal interface.
 */
int32_t HS_TLS13CalcServerHelloProcessSecret(TLS_Ctx *ctx);

/**
 * @brief TLS1.3 Derives the secret of the ServerFinish process.
 *
 * @param ctx [IN] TLS context
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST hash calculation failed.
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND HKDF-Expand calculation fails.
 * @retval HITLS_CRYPT_ERR_HKDF_EXTRACT HKDF-Extract calculation failed.
 * @retval For details about other error codes, see the SAL_CRYPT_DigestFinal interface.
 */
int32_t HS_TLS13CalcServerFinishProcessSecret(TLS_Ctx *ctx);

/**
 * @brief TLS1.3 Update the traffic secret.
 *
 * @param ctx [IN] TLS context
 * @param isOut [IN] It is used to determine writeSate and readState.
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST hash calculation failed.
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND HKDF-Expand calculation fails.
 * @retval HITLS_CRYPT_ERR_HKDF_EXTRACT HKDF-Extract calculation failure
 * @retval For other error codes, see the SAL_CRYPT_DigestFinal interface.
 */
int32_t HS_TLS13UpdateTrafficSecret(TLS_Ctx *ctx, bool isOut);

/**
 * @brief TLS1.3 Derived by resumption_master_secret
 *
 * @param ctx [IN] TLS context
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND HKDF-Expand calculation fails.
 * @retval HITLS_CRYPT_ERR_HKDF_EXTRACT HKDF-Extract calculation failure
 * @retval HITLS_CRYPT_ERR_CALC_SHARED_KEY Failed to calculate the shared key.
 * @retval HITLS_CRYPT_ERR_DIGEST hash calculation failed.
 * @retval For other error codes, see the SAL_CRYPT_DigestFinal interface
 */
int32_t HS_TLS13DeriveResumptionMasterSecret(TLS_Ctx *ctx);

/**
 * @brief TLS1.3 calculate session resumption PSK
 *
 * @param ctx [IN] TLS context
 * @param ticketNonce [IN] Unique ID of the ticket issued on the, which is used to calculate the PSK for session
 *  resumption.
 * @param ticketNonceSize [IN] ticketNonce length
 * @param resumePsk [OUT] Output the PSK key.
 * @param resumePskLen [IN] Output the PSK length.
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval HITLS_CRYPT_ERR_DIGEST hash calculation fails.
 * @retval HITLS_CRYPT_ERR_HKDF_EXPAND HKDF-Expand calculation fails.
 */
int32_t HS_TLS13DeriveResumePsk(
    TLS_Ctx *ctx, const uint8_t *ticketNonce, uint32_t ticketNonceSize, uint8_t *resumePsk, uint32_t resumePskLen);

int32_t HS_TLS13DeriveHandshakeTrafficSecret(TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
