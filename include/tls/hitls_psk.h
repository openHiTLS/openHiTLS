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
 * @defgroup hitls_psk
 * @ingroup hitls
 * @brief Basic functions for link establishment based on PSK
 */

#ifndef HITLS_PSK_H
#define HITLS_PSK_H

#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_psk
 * @brief PSK Maximum size of the identity message
 */
#define HS_PSK_IDENTITY_MAX_LEN 256u
#define HS_PSK_MAX_LEN 512u
#define HITLS_PSK_FIND_SESSION_CB_SUCCESS 1
#define HITLS_PSK_FIND_SESSION_CB_FAIL 0
#define HITLS_PSK_USE_SESSION_CB_SUCCESS 1
#define HITLS_PSK_USE_SESSION_CB_FAIL 0

/**
 * @ingroup hitls_psk
 * @brief   Obtain the PSK prototype on the client.
 *
 * @param   ctx              [IN] Context.
 * @param   hint             [IN] Message.
 * @param   identity         [OUT] Identity information written back by the user.
 * @param   maxIdentityLen   [IN] Maximum length of the identity buffer.
 * @param   psk              [OUT] PSK information written back by the user.
 * @param   maxPskLen        [IN] Maximum length of the psk buffer.
 * @return  Return the PSK length.
 */
typedef uint32_t (*HITLS_PskClientCb)(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity, uint32_t maxIdentityLen,
    uint8_t *psk, uint32_t maxPskLen);

/**
 * @ingroup hitls_psk
 * @brief   Obtain the PSK prototype on the server.
 *
 * @param   ctx         [IN] Context.
 * @param   identity    [IN] Identity information.
 * @param   psk         [OUT] PSK information written back by the user.
 * @param   maxPskLen   [IN] Maximum length of the psk buffer.
 * @return  Return the PSK length.
 */
typedef uint32_t (*HITLS_PskServerCb)(HITLS_Ctx *ctx, const uint8_t *identity, uint8_t *psk, uint32_t maxPskLen);

/**
 * @ingroup hitls_psk
 * @brief   TLS1.3 server PSK negotiation callback
 *
 * @param   ctx          [IN] ctx context
 * @param   identity     [OUT] Identity information
 * @param   identityLen  [OUT] Identity information length
 * @param   session      [OUT] session
 * @return  HITLS_PSK_FIND_SESSION_CB_SUCCESS, if successful.
 *          HITLS_PSK_FIND_SESSION_CB_FAIL, if failed
 */
typedef int32_t (*HITLS_PskFindSessionCb)(HITLS_Ctx *ctx, const uint8_t *identity, uint32_t identityLen,
    HITLS_Session **session);

/**
 * @ingroup hitls_psk
 * @brief   TLS1.3 client PSK negotiation callback
 *
 * @param   ctx       [IN] ctx context
 * @param   hashAlgo  [IN] Hash algorithm
 * @param   id        [IN] Identity information
 * @param   idLen     [IN] Identity information length
 * @param   session   [OUT] session
 * @return  HITLS_PSK_USE_SESSION_CB_SUCCESS, if successful.
 *          HITLS_PSK_USE_SESSION_CB_FAIL, if failed
 */
typedef int32_t (*HITLS_PskUseSessionCb)(HITLS_Ctx *ctx, uint32_t hashAlgo, const uint8_t **id,
    uint32_t *idLen, HITLS_Session **session);

/**
 * @ingroup hitls_psk
 * @brief   Set the PSK prompt information for PSK negotiation.
 *
 * @param   config     [OUT] config Context
 * @param   hint       [IN] Hint
 * @param   hintSize   [IN] Hint length
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetPskIdentityHint(HITLS_Config *config, const uint8_t *hint, uint32_t hintSize);

/**
 * @ingroup hitls_psk
 * @brief   Set the PSK callback function on the client, which is used to obtain the identity
 * and PSK during PSK negotiation.
 * @param   config    [OUT] config Context
 * @param   callback  [IN] Client callback
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetPskClientCallback(HITLS_Config *config, HITLS_PskClientCb callback);

/**
 * @ingroup hitls_psk
 * @brief   Set the PSK callback on the server, which is used to obtain the PSK during PSK negotiation.
 *
 * @param   config   [OUT] config Context
 * @param   callback [IN] Client callback
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetPskServerCallback(HITLS_Config *config, HITLS_PskServerCb callback);

/**
 * @ingroup hitls_psk
 * @brief    Set the PSK callback function on the client, which is used to obtain the identity and PSK
 * during PSK negotiation.
 * @param   ctx   [OUT] TLS connection handle
 * @param   cb    [IN] Client callback
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetPskClientCallback(HITLS_Ctx *ctx, HITLS_PskClientCb cb);

/**
 * @ingroup hitls_psk
 * @brief   Set the PSK callback on the server, which is used to obtain the PSK during PSK negotiation.
 *
 * @param   ctx   [OUT] TLS connection handle
 * @param   cb    [IN] Server callback
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetPskServerCallback(HITLS_Ctx *ctx, HITLS_PskServerCb cb);

/**
 * @ingroup hitls_psk
 * @brief   Set the PSK identity hint on the server, which is used to provide identity hints for the
 * client during PSK negotiation.
 * @param   ctx  [OUT] TLS connection handle
 * @param   identityHint       [IN] psk identity prompt
 * @param   identityHineLen    [IN] psk Length of the identity message
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetPskIdentityHint(HITLS_Ctx *ctx, const uint8_t *identityHint, uint32_t identityHintLen);

/**
 * @ingroup hitls_psk
 * @brief   Set the server callback, which is used to restore the PSK session of TLS1.3, cb can be NULL.
 *
 * @param   ctx       [OUT] TLS connection handle
 * @param   callback  [IN] Callback function
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetPskFindSessionCallback(HITLS_Config *config, HITLS_PskFindSessionCb callback);

/**
 * @ingroup hitls_psk
 * @brief   Set the server callback, which is used to restore the PSK session of TLS1.3, cb can be NULL.
 *
 * @param   ctx       [OUT] TLS connection handle
 * @param   callback  [IN] Callback function
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetPskUseSessionCallback(HITLS_Config *config, HITLS_PskUseSessionCb callback);

/**
 * @ingroup hitls_psk
 * @brief   Set the server callback, which is used to restore the PSK session of TLS1.3, cb can be NULL.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   cb  [IN] Callback function
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetPskFindSessionCallback(HITLS_Ctx *ctx, HITLS_PskFindSessionCb cb);

/**
 * @ingroup hitls_psk
 * @brief   Set the client callback, which is used to restore the PSK session of TLS1.3, cb can be NULL.
 *
 * @param   ctx   [OUT] TLS connection handle
 * @param   cb    [IN] Callback function
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetPskUseSessionCallback(HITLS_Ctx *ctx, HITLS_PskUseSessionCb cb);

#ifdef __cplusplus
}
#endif

#endif