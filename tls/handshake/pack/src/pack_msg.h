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

#ifndef PACK_MSG_H
#define PACK_MSG_H

#include <stdint.h>
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Pack ClientHello message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackClientHello(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Pack HelloVerifyRequest message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackHelloVerifyRequest(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Pack ServertHello message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackServerHello(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Pack Encrypted Extensions message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackEncryptedExtensions(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);
/**
 * @brief   Pack Tls1.3 Certificate message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13PackCertificate(TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);
/**
 * @brief   Pack certificate message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackCertificate(TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Pack CertificateRequest message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackCertificateRequest(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Pack Tls1.3 CertificateRequest message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13PackCertificateRequest(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);
/**
 * @brief   Pack CertificateVerify message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackCertificateVerify(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Pack new session ticket message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackNewSessionTicket(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Pack TLS1.3 new session ticket message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13PackNewSessionTicket(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);
/**
 * @brief   Pack ServerKeyExchange message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackServerKeyExchange(TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Pack ClientKeyExchange message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackClientKeyExchange(TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

/**
 * @brief   Pack Finished message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackFinished(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);
/**
 * @brief   Pack KeyUpdate message
 *
 * @param   ctx  [IN] TLS context
 * @param   buf [OUT] Returned handshake message
 * @param   bufLen [IN] Buffer size
 * @param   usedLen  [OUT] Returned message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t PackKeyUpdate(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);
#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end PACK_MSG_H */