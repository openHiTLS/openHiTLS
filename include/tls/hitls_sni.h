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

/**
 * @defgroup hitls_sni
 * @ingroup hitls
 * @brief TLS SNI correlation type
 */

#ifndef HITLS_SNI_H
#define HITLS_SNI_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_sni
 * @brief   Enumerated type for Server Name Indication (SNI) types.
 *
 * Currently, the SNI supports only the host name type.
 */
typedef enum {
    HITLS_SNI_HOSTNAME_TYPE,
    HITLS_SNI_BUTT = 255                    /* Maximum enumerated value */
} SNI_Type;

#define HITLS_ACCEPT_SNI_ERR_OK  0              /* Accepts the request and continues handshake. */
#define HITLS_ACCEPT_SNI_ERR_ALERT_FATAL  2     /* Do not accept the request and aborts the handshake. */
#define HITLS_ACCEPT_SNI_ERR_NOACK  3           /* Do not accept the request but continues the handshake. */

/**
 * @ingroup hitls_sni
 * @brief   Obtain the value of server_name before, during, or after the handshake on the client or server.\
 * @param   ctx [IN] TLS connection handle
 * @param   type  [IN] serverName type
 * @return  The value of server_name, if successful.
 *          NULL, if failure.
 */
const char *HITLS_GetServerName(const HITLS_Ctx *ctx, const int type);

/**
 * @ingroup hitls_sni
 * @brief   Obtain the server_name type before, during, or after the handshake on the client or server.
 * @param   ctx [IN] TLS connection handle
 * @return  HITLS_SNI_HOSTNAME_TYPE, if successful.
 *          -1: if failure.
 */
int32_t HITLS_GetServernameType(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_sni
 * @brief   Set server_name.
 *
 * @param   config  [OUT] config Context
 * @param   serverName  [IN] serverName
 * @param   serverNameStrlen [IN] serverName length
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetServerName(HITLS_Config *config, uint8_t *serverName, uint32_t serverNameStrlen);

/**
 * @ingroup hitls_sni
 * @brief   Obtain the value of server_name configured on the client.
 *
 * @param   config [IN] config Context
 * @param   serverName [OUT] serverName
 * @param   serverNameStrlen [OUT] serverName length
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetServerName(HITLS_Config *config, uint8_t **serverName, uint32_t *serverNameStrlen);

/**
 * @ingroup hitls_sni
 * @brief   Set the extension prototype for the server to process Client Hello server_name.
 *
 * @param   ctx   [IN] ctx context.
 * @param   alert [IN] Warning information.
 * @param   arg   [IN] The server supports the input parameters related to server_name.
 * @return  The user return value contains:
 *         HITLS_ACCEPT_SNI_ERR_OK 0 (received, server_name null extension)
 *         HITLS_ACCEPT_SNI_ERR_ALERT_FATAL 2 (Do not accept, abort handshake)
 *         HITLS_ACCEPT_SNI_ERR_NOACK 3 (not accepted, but continue handshake, not sending server_name null extension)
 */
typedef int32_t (*HITLS_SniDealCb)(HITLS_Ctx *ctx, int *alert, void *arg);

/**
 * @ingroup hitls_sni
 * @brief   Set the server_name callback function on the server, which is used for SNI negotiation, cb can be NULL.
 *
 * @param   config  [OUT] Config Context
 * @param   callback [IN] Server callback implemented by the user
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetServerNameCb(HITLS_Config *config, HITLS_SniDealCb callback);

/**
 * @ingroup hitls_sni
 * @brief   Set the server_name parameters required during SNI negotiation on the server.
 *
 * @param   config  [OUT] Config context
 * @param   arg  [IN] Set parameters related to server_name.
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetServerNameArg(HITLS_Config *config, void *arg);

/**
 * @ingroup hitls_sni
 * @brief   Obtain the server_name callback settings on the server.
 *
 * @param   config  [IN] config Context
 * @param   callback [IN] [OUT] Server callback implemented by the user
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetServerNameCb(HITLS_Config *config, HITLS_SniDealCb *callback);

/**
 * @ingroup hitls_sni
 * @brief   Obtain the server_name required during SNI negotiation on the server, related Parameter arg.
 *
 * @param   config  [IN] Config context
 * @param   arg  [IN] [OUT] Set parameters related to server_name.arg
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetServerNameArg(HITLS_Config *config, void **arg);

/**
 * @ingroup hitls_sni
 * @brief   Set a new configuration for an existing TLS handle. Currently this parameter is used only in SNI callback.
 * @param   ctx [OUT] TLS connection handle.
 * @param   newConfig [IN] config Context
 * @return  Return the global configuration pointer currently used by the CTX, or NULL indicates that memory
 * allocation fails.
 */
HITLS_Config *HITLS_SetNewConfig(HITLS_Ctx *ctx, HITLS_Config *newConfig);

#ifdef __cplusplus
}
#endif

#endif