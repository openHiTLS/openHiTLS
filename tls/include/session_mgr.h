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

#ifndef SESSION_MGR_H
#define SESSION_MGR_H

#include <stdint.h>
#include <stdbool.h>
#include "hitls_build.h"
#include "hitls.h"
#include "tls.h"
#include "session.h"
#include "tls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Application */
TLS_SessionMgr *SESSMGR_New(HITLS_Lib_Ctx *libCtx);

/* Copy the number of references. The number of references increases by 1 */
TLS_SessionMgr *SESSMGR_Dup(TLS_SessionMgr *mgr);

/* Release */
void SESSMGR_Free(TLS_SessionMgr *mgr);

/* Configure the timeout period */
void SESSMGR_SetTimeout(TLS_SessionMgr *mgr, uint64_t sessTimeout);

/* Obtain the timeout configuration */
uint64_t SESSMGR_GetTimeout(TLS_SessionMgr *mgr);

/* Set the mode */
void SESSMGR_SetCacheMode(TLS_SessionMgr *mgr, uint32_t mode);

/* Set the mode: Ensure that the pointer is not null */
uint32_t SESSMGR_GetCacheMode(TLS_SessionMgr *mgr);

/* Set the maximum number of cache sessions */
void SESSMGR_SetCacheSize(TLS_SessionMgr *mgr, uint32_t sessCacheSize);

/* Set the maximum number of cached sessions. Ensure that the pointer is not null */
uint32_t SESSMGR_GetCacheSize(TLS_SessionMgr *mgr);

/* add */
void SESSMGR_InsertSession(TLS_SessionMgr *mgr, HITLS_Session *sess, bool isStore);

/* Find the matching session and verify the validity of the session (time) */
HITLS_Session *SESSMGR_Find(TLS_Ctx *ctx, uint8_t *sessionId, uint8_t sessionIdSize);

/* Search for the matching session without checking the validity of the session (time) */
bool SESSMGR_HasMacthSessionId(TLS_SessionMgr *mgr, uint8_t *sessionId, uint8_t sessionIdSize);

/* Clear timeout sessions */
void SESSMGR_ClearTimeout(HITLS_Config *config, uint64_t time);

int32_t SESSMGR_RemoveSession(HITLS_Config *config, HITLS_Session *sess);

/* Generate session IDs to prevent duplicate session IDs */
int32_t SESSMGR_GernerateSessionId(TLS_Ctx *ctx, uint8_t *sessionId, uint32_t sessionIdSize);

void SESSMGR_SetTicketKeyCb(TLS_SessionMgr *mgr, HITLS_TicketKeyCb ticketKeyCb);

HITLS_TicketKeyCb SESSMGR_GetTicketKeyCb(TLS_SessionMgr *mgr);

/**
 * @brief   Obtain the default ticket key of the HITLS. The key is used to encrypt and decrypt the ticket
 *          in the new session ticket when the HITLS_TicketKeyCb callback function is not set.
 *
 * @attention The returned key value is as follows: 16-byte key name + 32-byte AES key + 32-byte HMAC key
 *
 * @param   mgr [IN] Session management context
 * @param   key [OUT] Obtained ticket key
 * @param   keySize [IN] Size of the key array
 * @param   outSize [OUT] Size of the obtained ticket key
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t SESSMGR_GetTicketKey(const TLS_SessionMgr *mgr, uint8_t *key, uint32_t keySize, uint32_t *outSize);

/**
 * @brief   Set the default ticket key of the HITLS. The key is used to encrypt and decrypt tickets
 *          in the new session ticket when the HITLS_TicketKeyCb callback function is not set.
 *
 * @attention The returned key value is as follows: 16-byte key name + 32-byte AES key + 32-byte HMAC key
 *
 * @param   mgr [OUT] Session management context
 * @param   key [IN] Ticket key to be set
 * @param   keySize [IN] Size of the ticket key
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t SESSMGR_SetTicketKey(TLS_SessionMgr *mgr, const uint8_t *key, uint32_t keySize);

/**
 * @brief   Encrypt the session ticket, which is invoked when a new session ticket is sent
 *
 * @param   sessMgr [IN] Session management context
 * @param   sess [IN] sess structure, used to generate ticket data
 * @param   ticketBuf [OUT] ticket. The return value may be empty, that is, an empty new session ticket message is sent
 * @param   ticketBufSize [IN] Size of the ticketBuf
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t SESSMGR_EncryptSessionTicket(TLS_Ctx *ctx, const TLS_SessionMgr *sessMgr, const HITLS_Session *sess,
    uint8_t **ticketBuf, uint32_t *ticketBufSize);

/**
 * @brief   Decrypt the session ticket. This interface is invoked when the session ticket of the clientHello is received
 *
 * @attention The output parameters are as follows:
 *            If the sess field is empty and the ticketExcept field is set to true, the new session ticket message
 *            is sent but the session is not resumed
 *            If the sess field is empty and the ticketExcept field is false, the session is not resumed
 *            and the new session ticket message is not sent
 *            If sess is not empty and ticketExcept is true, the session is resumed and
 *            a new session ticket message is sent, which means the session ticket is renewed
 *            If sess is not empty and ticketExcept is false,
 *            the session is resumed and the new session ticket message is not sent
 *
 * @param   sessMgr [IN] Session management context
 * @param   sess [OUT] Session structure generated by the ticket. The return value may be empty,
 *          so that, the corresponding session cannot be generated and the session cannot be resumed
 * @param   ticketBuf [IN] ticket data
 * @param   ticketBufSize [IN] Ticket data size
 * @param   isTicketExcept [OUT] Indicates whether to send a new session ticket.
 *          The options are as follows: true: yes; false: no.
 *
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t SESSMGR_DecryptSessionTicket(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const TLS_SessionMgr *sessMgr, HITLS_Session **sess, const uint8_t *ticketBuf,
    uint32_t ticketBufSize, bool *isTicketExcept);

#ifdef __cplusplus
}
#endif

#endif // SESSION_MGR_H
