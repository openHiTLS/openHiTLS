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

#ifndef HS_H
#define HS_H

#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Initialize the handshake context
 *
 * @param   ctx [IN] TLS object
 *
 * @retval  HITLS_SUCCESS succeeded
 */
int32_t HS_Init(TLS_Ctx *ctx);

/**
 * @brief   Release the handshake context
 *
 * @param   ctx [IN] TLS object
 */
void HS_DeInit(TLS_Ctx *ctx);

/**
 * @brief   Establish a TLS connection
 *
 * @param   ctx [IN] TLS object
 *
 * @retval  HITLS_SUCCESS The connection is successfully established.
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t HS_DoHandshake(TLS_Ctx *ctx);


/**
 * @brief   Generate the session key
 *
 * @param   ctx [IN] TLS context
 * @param   isClient [IN] Client or Not
 *
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t HS_KeyEstablish(TLS_Ctx *ctx, bool isClient);

/**
 * @brief   Session recovery Generate a session key.
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t HS_ResumeKeyEstablish(TLS_Ctx *ctx);

/**
 * @brief   Obtain the current handshake status
 *
 * @param   ctx [IN] TLS context
 *
 * @retval  Current handshake status
 */
uint32_t HS_GetState(const TLS_Ctx *ctx);

/**
 * @brief Obtain the version number. If the version number is not negotiated, the latest version
 * supported by the local is returned.
 *
 * @param ctx [IN] TLS context
 *
 * @return Return the version number.
 */
uint32_t HS_GetVersion(const TLS_Ctx *ctx);

/**
 * @brief Obtain the handshake status character string.
 *
 * @param state [IN] Handshake status
 *
 * @return Character string corresponding to the handshake status
 */
const char *HS_GetStateStr(uint32_t state);

/**
 * @brief  Check whether the conditions for sending keyupdate are met
 *
 * @param ctx [IN] TLS context
 * @param updateType [IN] keyupdate type
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t HS_CheckKeyUpdateState(TLS_Ctx *ctx, uint32_t updateType);


/**
 * @brief  Obtain the server_name in the handshake TLS context.
 *
 * @param  ctx [IN] TLS context
 *
 * @return string of server_name in the TLS context during the handshake
 */
const char *HS_GetServerName(const TLS_Ctx *ctx);

/**
 * @brief   Determine and handle the 2MSL timeout
 *
 * @param ctx [IN] TLS context
 *
 * @return string of server_name in the TLS context during the handshake
 */
#ifdef HITLS_TLS_PROTO_DTLS12
int32_t HS_CheckAndProcess2MslTimeout(TLS_Ctx *ctx);
#endif

int32_t HS_CheckPostHandshakeAuth(TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif
#endif /* HS_H */