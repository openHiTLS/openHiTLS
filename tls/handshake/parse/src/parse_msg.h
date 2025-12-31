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

#ifndef PARSE_MSG_H
#define PARSE_MSG_H

#include <stdint.h>
#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Parse client Hello message
 *
 * @param   ctx [IN] TLS context
 * @param   data [IN] Message buffer
 * @param   len [IN] Message buffer length
 * @param   hsMsg [OUT] Parsed message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG Extension duplicated
 */
int32_t ParseClientHello(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg);

/**
 * @brief   Parse Server Hello message
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer
 * @param   bufLen [IN] Maximum message length
 * @param   hsMsg [OUT] Message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_PARSE_DUPLICATE_EXTENDED_MSG Extension duplicated
 */
int32_t ParseServerHello(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg);

/**
 * @brief   Parse TLS 1.3 EncryptedExtensions message
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer
 * @param   bufLen [IN] Maximum message length
 * @param   hsMsg [OUT] Message structure
 *
 * @return  HITLS_SUCCESS
 *          HITLS_INVALID_PARAMETERS The input parameter is a null pointer
 *          HITLS_ALERT_FATAL Message error
 *          HITLS_MEMALLOC_FAIL Memory allocated failed
 */
int32_t ParseEncryptedExtensions(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg);

/**
 * @brief   Parse Hello Verify Request message
 *
 * @param   ctx [IN] TLS context
 * @param   data [IN] Message buffer
 * @param   len [IN] Maximum message length
 * @param   hsMsg [OUT] Message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseHelloVerifyRequest(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg);

/**
 * @brief   Parse certificate message
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer
 * @param   bufLen [IN] Maximum message length
 * @param   hsMsg [OUT] Message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLSPARSE_CERT_ERR Failed to parse the certificate
 * @retval  HITLSPARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseCertificate(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg);
/**
 * @brief   Parse TLS 1.3 certificate message
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer
 * @param   bufLen [IN] Maximum message length
 * @param   hsMsg [OUT] Message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLSPARSE_CERT_ERR Failed to parse the certificate
 * @retval  HITLSPARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t Tls13ParseCertificate(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg);
/**
 * @brief   Parse Server Key Exchange message
 *
 * @param   ctx [IN] TLS context
 * @param   data [IN] Message buffer
 * @param   len [IN] Message buffer length
 * @param   hsMsg [OUT] Parsed message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_PARSE_UNSUPPORT_KX_CURVE_TYPE Unsupported ECC curve type
 * @retval  HITLS_PARSE_ECDH_PUBKEY_ERR Failed to parse the ECDH public key
 * @retval  HITLS_PARSE_ECDH_SIGN_ERR Failed to parse the ECDH signature
 * @retval  HITLS_PARSE_UNSUPPORT_KX_ALG Unsupported key exchange algorithm
 */
int32_t ParseServerKeyExchange(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg);

/**
 * @brief   Parse certificate request message, which is applicable to TLS1.2/DTLS/TLS1.3 protocols
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer
 * @param   bufLen [IN] Maximum message length
 * @param   hsMsg [OUT] Message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 */
int32_t ParseCertificateRequest(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg);
/**
 * @brief   Parse TLS1.3 certificate request message
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer
 * @param   bufLen [IN] Maximum message length
 * @param   hsMsg [OUT] Message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 */
int32_t Tls13ParseCertificateRequest(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg);
/**
 * @brief   Parse Client Key Exchange message
 *
 * @param   ctx [IN] TLS context
 * @param   data [IN] Message buffer
 * @param   len [IN] Message buffer length
 * @param   hsMsg [OUT] Parsed Message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseClientKeyExchange(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg);

/**
 * @brief   Parse Certificate Verify message
 *
 * @param   ctx [IN] TLS context
 * @param   buf [IN] Message buffer
 * @param   bufLen [IN] Maximum message length
 * @param   hsMsg [OUT] Message structure
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 */
int32_t ParseCertificateVerify(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg);

/**
 * @brief   Parse Finished message
 *
 * @param   ctx [IN] TLS context
 * @param   hsMsg [OUT] Message structure
 * @param   buf [IN] Message buffer
 * @param   bufLen [IN] Maximum message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseFinished(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg);
/**
 * @brief   Parse KeyUpdate message
 *
 * @param   ctx [IN] TLS context
 * @param   hsMsg [OUT] Message structure
 * @param   buf [IN] Message buffer
 * @param   bufLen [IN] Maximum message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseKeyUpdate(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg);

/**
 * @brief   Parse new sessionticket message
 *
 * @param   ctx [IN] TLS context
 * @param   hsMsg [OUT] Message structure
 * @param   buf [IN] Message buffer
 * @param   bufLen [IN] Maximum message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_PARSE_INVALID_MSG_LEN The message length is incorrect
 */
int32_t ParseNewSessionTicket(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg);

/**
 * @brief   Clear the memory allocated in the Client Hello message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanClientHello(ClientHelloMsg *msg);

/**
 * @brief   Clear the memory allocated in the Server Hello message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanServerHello(ServerHelloMsg *msg);

/**
 * @brief   Clear the memory allocated in the Hello Verify Request message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanHelloVerifyRequest(HelloVerifyRequestMsg *msg);
/**
 * @brief   Clear the memory allocated in the EncryptedExtensions message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanEncryptedExtensions(EncryptedExtensions *msg);
/**
 * @brief  Clear the memory allocated in the certificate message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanCertificate(CertificateMsg *msg);

/**
 * @brief   Clear the memory allocated in the ServerKeyExchangeMsg message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanServerKeyExchange(ServerKeyExchangeMsg *msg);

/**
 * @brief   Clear the memory allocated in the Certificate Request message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanCertificateRequest(CertificateRequestMsg *msg);

/**
 * @brief   Clear the memory allocated in the Client KeyExchange message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanClientKeyExchange(ClientKeyExchangeMsg *msg);

/**
 * @brief   Clear the memory allocated in the Certificate Verify message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanCertificateVerify(CertificateVerifyMsg *msg);

/**
 * @brief   Clear the memory allocated in the NewSessionTicket message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanNewSessionTicket(NewSessionTicketMsg *msg);

/**
 * @brief   Clear the memory allocated in the Finished message structure
 *
 * @param   msg [IN] Message structure
 */
void CleanFinished(FinishedMsg *msg);

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end PARSE_MSG_H */