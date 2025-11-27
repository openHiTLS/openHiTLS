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
 * @defgroup hitls_alpn
 * @ingroup  hitls
 * @brief    TLS ALPN related type
 */

#ifndef HITLS_ALPN_H
#define HITLS_ALPN_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_ALPN_ERR_OK 0                 /* Correct execution. */
#define HITLS_ALPN_ERR_ALERT_WARNING 1      /* Execution error, sent warning alert. */
#define HITLS_ALPN_ERR_ALERT_FATAL 2        /* Execution error, sent fatal alert. */
#define HITLS_ALPN_ERR_NOACK 3              /* Execution exception, ignore processing. */

/**
 * @ingroup hitls_alpn
 * @brief   Callback prototype for selecting the ALPN protocol on the server, which is used to select
 * the application layer protocol during ALPN negotiation.
 *
 * @param   ctx  [IN] Ctx context.
 * @param   selectedProto   [OUT] Indicates the initial IP address of the protocol that is being matched.
 * @param   selectedProtoLen  [OUT] Matching protocol length.
 * @param   clientAlpnList   [IN] Client ALPN List.
 * @param   clientAlpnListSize  [IN] Client ALPN List length.
 * @param   userData   [IN] Context transferred by the user.
 * @retval  HITLS_ALPN_ERR_OK 0, indicates success.
            HITLS_ALPN_ERR_ALERT_WARNING 1, indicates send warning alert.
            HITLS_ALPN_ERR_ALERT_FATAL 2, indicates send fatal alert.
            HITLS_ALPN_ERR_NOACK 3, indicates no processing.
 */
typedef int32_t (*HITLS_AlpnSelectCb)(HITLS_Ctx *ctx, uint8_t **selectedProto, uint8_t *selectedProtoSize,
    uint8_t *clientAlpnList, uint32_t clientAlpnListSize, void *userData);

/**
 * @ingroup hitls_alpn
 * @brief   Sets the ALPN list on the client, which is used to negotiate the application layer protocol
 * with the server in the handshake phase.
 *
 * @param   config  [OUT] Config context.
 * @param   alpnProtos    [IN] Application layer protocol list.
 * @param   alpnProtosLen    [IN] Length of the application layer protocol list.
 * @retval  If success, return HITLS_SUCCESS.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetAlpnProtos(HITLS_Config *config, const uint8_t *alpnProtos, uint32_t alpnProtosLen);

/**
 * @ingroup hitls_alpn
 * @brief   Sets the ALPN selection callback on the server.
 *
 * The callback is used to select the application layer protocol in the handshake phase, cb can be NULL.
 *
 * @param   config  [OUT] Config context.
 * @param   callback    [IN] Server callback implemented by the user.
 * @param   userData    [IN] Product context.
 * @retval  If success, return HITLS_SUCCESS.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetAlpnProtosSelectCb(HITLS_Config *config, HITLS_AlpnSelectCb callback, void *userData);

/**
 * @ingroup hitls_alpn
 * @brief   Sets the client ALPN list, which is used to negotiate the application layer protocol
 * with the server in the handshake phase.
 *
 * @param   ctx  [OUT] TLS connection Handle.
 * @param   protos    [IN] Application layer protocol list.
 * @param   protosLen    [IN] Length of the application layer protocol list.
 * @retval  If success, return HITLS_SUCCESS.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetAlpnProtos(HITLS_Ctx *ctx, const uint8_t *protos, uint32_t protosLen);

/**
 * @ingroup hitls_alpn
 * @brief   Obtaining the ALPN Negotiation Result
 *
 * @param   ctx  [IN] Ctx context.
 * @param   proto    [OUT] Header address of the outgoing selected protocol.
 * @param   protoLen    [OUT] Length of the outgoing selected protocol.
 * @retval  If success, return HITLS_SUCCESS.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetSelectedAlpnProto(HITLS_Ctx *ctx, uint8_t **proto, uint32_t *protoLen);

/**
 * @ingroup hitls_alpn
 * @brief   Obtaining the ALPN Negotiation Result
 * The server selects an appropriate ALPN based on the ALPN provided by the client and its own configured ALPN.
 * @param   out  [OUT] Outgoing selected protocol.
 * @param   outLen    [OUT] Length of the outgoing selected protocol.
 * @param   servAlpnList        [IN] Header address of the server ALPN list.
 * @param   servAlpnListLen     [IN] Length of the server ALPN list.
 * @param   clientAlpnList      [IN] Header address of the client ALPN list.
 * @param   clientAlpnListLen   [IN] Length of the client ALPN list.
 *
 * @retval  HITLS_SUCCESS, succeeded. Note: Success does not necessarily mean negotiating ALPN; it requires making a
 * judgment on out.
 * @retval  HITLS_NULL_INPUT, the input is NULL.
 * @retval  HITLS_CONFIG_INVALID_LENGTH, ALPN length does not match the actual length.
 */
int32_t HITLS_SelectAlpnProtocol(uint8_t **out, uint8_t *outLen, const uint8_t *servAlpnList, uint32_t servAlpnListLen,
    const uint8_t *clientAlpnList, uint32_t clientAlpnListLen);

#ifdef __cplusplus
}
#endif

#endif // HITLS_ALPN_H