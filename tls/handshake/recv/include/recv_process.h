/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef RECV_PROCESS_H
#define RECV_PROCESS_H

#include <stdint.h>
#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t Tls12ServerRecvClientHelloProcess(TLS_Ctx *ctx, const HS_Msg *msg);

/**
 * @brief   Server processes DTLS client hello message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] client hello message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */

#ifndef HITLS_NO_DTLS12
int32_t DtlsServerRecvClientHelloProcess(TLS_Ctx *ctx, const HS_Msg *msg);
#endif

/**
 * @brief   Client processes Server Hello message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] server hello message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t ClientRecvServerHelloProcess(TLS_Ctx *ctx, const HS_Msg *msg);

/**
 * @brief   Process peer certificate
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] certificate message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t RecvCertificateProcess(TLS_Ctx *ctx, const HS_Msg *msg);

/**
 * @brief   Process server key exchange
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] server key exchange message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t ClientRecvServerKxProcess(TLS_Ctx *ctx, HS_Msg *msg);

/**
 * @brief   Process server certificate request
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] server certificate request message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t ClientRecvCertRequestProcess(TLS_Ctx *ctx, HS_Msg *msg);

/**
 * @brief   Process sever hello done
 *
 * @param   ctx [IN] TLS context
 *
 * @return  HITLS_SUCCESS
 */
int32_t ClientRecvServerHelloDoneProcess(TLS_Ctx *ctx);

/**
 * @brief   The server processes the client key exchange
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] Parsed handshake message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t ServerRecvClientKxProcess(TLS_Ctx *ctx, const HS_Msg *msg);

/**
 * @brief   Server process client certificate verification message
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t ServerRecvClientCertVerifyProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS1.2 client processes the new session ticket message
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls12ClientRecvNewSeesionTicketProcess(TLS_Ctx *ctx, HS_Msg *hsMsg);

/**
 * @brief   TLS1.3 client processes the new session ticket message
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13ClientRecvNewSessionTicketProcess(TLS_Ctx *ctx, HS_Msg *hsMsg);

int32_t Tls12ServerRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg);

int32_t Tls12ClientRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg);

/**
 * @brief   Server processes dlts client finished message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] finished message
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL Failed to verify the finished message
 */

#ifndef HITLS_NO_DTLS12
int32_t DtlsServerRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg);
#endif

/**
 * @brief   Client processes dlts server finished message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] finished message
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL Failed to verify the finished message
 */

#ifndef HITLS_NO_DTLS12
int32_t DtlsClientRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg);
#endif

/**
 * @brief   TLS1.3 server process client hello message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] client hello message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13ServerRecvClientHelloProcess(TLS_Ctx *ctx, HS_Msg *msg);

/**
 * @brief   TLS1.3 client process server hello message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] server hello message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13ClientRecvServerHelloProcess(TLS_Ctx *ctx, const HS_Msg *msg);

/**
 * @brief   TLS1.3 client process encrypted extensions message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] encrypted extensions message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13ClientRecvEncryptedExtensionsProcess(TLS_Ctx *ctx, const HS_Msg *msg);

/**
 * @brief   TLS1.3 client processes certificate request message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] certificate request message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13ClientRecvCertRequestProcess(TLS_Ctx *ctx, const HS_Msg *msg);

/**
 * @brief   TLS1.3 process certificate message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] certificate message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13RecvCertificateProcess(TLS_Ctx *ctx, const HS_Msg *msg);

/**
 * @brief   TLS1.3 process certificate verify message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] certificate verify message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13RecvCertVerifyProcess(TLS_Ctx *ctx);

/**
 * @brief   TLS1.3 client process finished message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] finished message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13ClientRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg);

/**
 * @brief   TLS1.3 server process finished message
 *
 * @param   ctx [IN] TLS context
 * @param   msg [IN] finished message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t Tls13ServerRecvFinishedProcess(TLS_Ctx *ctx, const HS_Msg *msg);

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end RECV_PROCESS_H */
