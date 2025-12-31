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

#ifndef SEND_PROCESS_H
#define SEND_PROCESS_H

#include <stdint.h>
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Send a handshake message
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_UNREGISTERED_CALLBACK
 * @retval  HITLS_CRYPT_ERR_DIGEST hash operation failed
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 * @return  For details, see REC_Write
 */
int32_t HS_SendMsg(TLS_Ctx *ctx);

/**
 * @brief   Server sends Hello Request messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t ServerSendHelloRequestProcess(TLS_Ctx *ctx);

/**
 * @brief   Client sends client hello messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t ClientSendClientHelloProcess(TLS_Ctx *ctx);

/**
 * @brief   Server sends hello verify request messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t DtlsServerSendHelloVerifyRequestProcess(TLS_Ctx *ctx);

/**
 * @brief   Server sends server hello messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @return  For details, see hitls_error.h
 */
int32_t ServerSendServerHelloProcess(TLS_Ctx *ctx);

/**
 * @brief   send certificate messsage
 * @attention The certificates sent by client and server are the same, except for the processing empty certificates
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @return  For details, see hitls_error.h
 */
int32_t SendCertificateProcess(TLS_Ctx *ctx);

/**
 * @brief   Server sends server keyExchange messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @return  For details, see hitls_error.h
 */
int32_t ServerSendServerKeyExchangeProcess(TLS_Ctx *ctx);

/**
 * @brief   Server sends server certificate request messsage
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @return  For details, see hitls_error.h
 */
int32_t ServerSendCertRequestProcess(TLS_Ctx *ctx);

/**
 * @brief   Server sends server hello done message
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @return  For details, see hitls_error.h
 */
int32_t ServerSendServerHelloDoneProcess(TLS_Ctx *ctx);

/**
 * @brief   Client sends client key exchange messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t ClientSendClientKeyExchangeProcess(TLS_Ctx *ctx);

/**
 * @brief   Client sends client certificate verify messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t ClientSendCertVerifyProcess(TLS_Ctx *ctx);

/**
 * @brief   Server sends ccs messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @return  For details, see hitls_error.h
 */
int32_t SendChangeCipherSpecProcess(TLS_Ctx *ctx);

/**
 * @brief   Server sends new session messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @return  For details, see hitls_error.h
 */
int32_t SendNewSessionTicketProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS1.3 Server sends new session messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @return  For details, see hitls_error.h
 */
int32_t Tls13SendNewSessionTicketProcess(TLS_Ctx *ctx);

int32_t Tls12ClientSendFinishedProcess(TLS_Ctx *ctx);

int32_t Tls12ServerSendFinishedProcess(TLS_Ctx *ctx);

/**
 * @brief   Client sends finished messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
#ifdef HITLS_TLS_PROTO_DTLS12
int32_t DtlsClientSendFinishedProcess(TLS_Ctx *ctx);
#endif

/**
 * @brief   Server sends dtls finished messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @return  For details, see hitls_error.h
 */
#ifdef HITLS_TLS_PROTO_DTLS12
int32_t DtlsServerSendFinishedProcess(TLS_Ctx *ctx);
#endif

/**
 * @brief   TLS 1.3 Client sends client hello messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t Tls13ClientSendClientHelloProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS 1.3 Server sends hello retry request messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t Tls13ServerSendHelloRetryRequestProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS 1.3 Server sends server hello messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t Tls13ServerSendServerHelloProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS 1.3 Server sends encrypted extensions messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t Tls13ServerSendEncryptedExtensionsProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS 1.3 Server sends certificate request messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t Tls13ServerSendCertRequestProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS 1.3 Client sends certificate messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t Tls13ClientSendCertificateProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS 1.3 Server sends certificate messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t Tls13ServerSendCertificateProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS 1.3 send certificate verify messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t Tls13SendCertVerifyProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS 1.3 Server sends finished messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t Tls13ServerSendFinishedProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS 1.3 Client sends finished messsage
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t Tls13ClientSendFinishedProcess(TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
