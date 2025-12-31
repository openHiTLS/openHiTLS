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
 * @defgroup hitls_session
 * @ingroup hitls
 * @brief TLS session
 */

#ifndef HITLS_SESSION_H
#define HITLS_SESSION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hitls_type.h"
#include "hitls_crypt_type.h"
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_session
 * @brief Session id Maximum size of the CTX.
 */
#define HITLS_SESSION_ID_CTX_MAX_SIZE 32u

/**
 * @ingroup hitls_session
 * @brief Maximum size of a session ID
 */
#define HITLS_SESSION_ID_MAX_SIZE 32u

/**
 * @ingroup hitls_session
 * @brief   Set whether to support the session ticket function.
 *
 * @param   config  [OUT] Config handle
 * @param   support [IN] Whether to support the session ticket. The options are as follows: true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetSessionTicketSupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_session
 * @brief   Query whether the session ticket function is supported.
 *
 * @param   config      [IN] Config handle
 * @param   isSupport   [OUT] Whether to support the session ticket.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_GetSessionTicketSupport(const HITLS_Config *config, bool *isSupport);

/**
 * @ingroup hitls_session
 * @brief   Setting TLS1.3, number of new session tickets sent after a complete link is established.
 * @details This interface should be called before handshake. The default number is 2.
 *          If the number is greater than or equal to 1, only one ticket is sent after the session is resumed.
 *          When this parameter is set to 0, the ticket is not sent for the complete handshake and session resumption.
 * @param   config     [OUT] Config handle
 * @param   ticketNums [IN] Number of new session tickets sent.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is empty.
 */
int32_t HITLS_CFG_SetTicketNums(HITLS_Config *config, uint32_t ticketNums);

/**
 * @ingroup hitls_session
 * @brief   Obtain TLS1.3, number of new session tickets sent after complete link establishment.
 *
 * @param   config [IN] config handle
 * @return  Number of tickets.
 */
uint32_t HITLS_CFG_GetTicketNums(HITLS_Config *config);

/**
 * @ingroup hitls_session
 * @brief   Setting TLS1.3, number of new session tickets sent after complete link establishment
 * @details This interface should be called before handshake. The default number is 2.
 *          If the number is greater than or equal to 1, only one ticket is sent after the session is resumed.
 *          When this parameter is set to 0, tickets will not be sent for the complete handshake and session recovery.
 * @param   ctx        [OUT] ctx context
 * @param   ticketNums [IN] Number of sent new session tickets.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 */
int32_t HITLS_SetTicketNums(HITLS_Ctx *ctx, uint32_t ticketNums);

/**
 * @ingroup hitls_session
 * @brief   Obtain TLS1.3, Number of new session tickets sent after complete link establishment.
 *
 * @param   ctx  [IN] ctx context
 * @return  Number of tickets.
 */
uint32_t HITLS_GetTicketNums(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_session
 * @brief   This callback is called when a new session is negotiated. Users can use sessions.
 *
 * @param   ctx     [IN] ctx context
 * @param   session [IN] Session handle
 * @retval  1 Success. If a user removes a session, the user needs to release the session handle.
 * @retval  0 failed. The user does not use the session.
 */
typedef int32_t (*HITLS_NewSessionCb) (HITLS_Ctx *ctx, HITLS_Session *session);

/**
 * @ingroup hitls_session
 * @brief   Remove a session.
 *
 * @param   ctx [IN]    Context
 * @param   sess [IN]   Session
 */
typedef void (*HITLS_SessionRemoveCb)(HITLS_Config *config, HITLS_Session *sess);

/**
 * @ingroup hitls_session
 * @brief   Get a session based on the session ID.
 *
 * @param   ctx [IN]    Context
 * @param   data [IN]   Session ID data
 * @param   len [IN]    Session ID length
 * @param   copy [OUT]  Whether to copy the session. 1: copy; 0: do not copy
 * @retval  Session handle, if successful.
 *          NULL, if failure.
 */
typedef HITLS_Session *(*HITLS_SessionGetCb) (HITLS_Ctx *ctx, const uint8_t *data, int32_t len, int32_t *copy);

/**
 * @ingroup hitls_session
 * @brief Session ticket extension callback.
 * @param   ctx  [IN] ctx context
 * @param   data [IN]  Session ticket extension data
 * @param   len  [IN]  Session ticket extension data length
 * @param   arg  [IN]  User-defined parameter
 * @retval  1, if successful.
 * @retval  For other error codes, see hitls_error.h
 */
typedef int32_t (*HITLS_SessionTicketExtProcessCb)(HITLS_Ctx *ctx, const uint8_t *data, int32_t len, void *arg);

/**
 * @ingroup hitls_session
 * @brief   Set a callback for negotiating a new session call.
 *
 * @param   config       [OUT] config handle
 * @param   newSessionCb [IN] Callback.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetNewSessionCb(HITLS_Config *config, const HITLS_NewSessionCb newSessionCb);

/**
 * @ingroup hitls_session
 * @brief   Set a callback for obtaining a session based on the session ID.
 *
 * @param   config      [OUT] config handle
 * @param   sessionGetCb [IN] Callback.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetSessionGetCb(HITLS_Config *config, const HITLS_SessionGetCb sessionGetCb);

/**
 * @ingroup hitls_session
 * @brief   Set a callback for removing a session.
 *
 * @param   config              [OUT] config handle
 * @param   sessionRemoveCb     [IN] Callback.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetSessionRemoveCb(HITLS_Config *config, const HITLS_SessionRemoveCb sessionRemoveCb);

/**
 * @ingroup hitls_session
 * @brief   Set a callback for processing the session ticket extension.
 *
 * @param   ctx                  [OUT] config handle
 * @param   extSessionTicketCb      [IN] Callback.
 * @param   arg                     [IN]  User-defined parameter
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_SetSessionTicketExtProcessCb(HITLS_Ctx *ctx, const HITLS_SessionTicketExtProcessCb sessionTicketExtCb,
                                           void *arg);

/**
 * @ingroup hitls_session
 * @brief   Set the session ticket extension data.
 *
 * @param   ctx             [OUT] config handle
 * @param   data            [IN] Session ticket extension data.
 * @param   dataSize        [IN] Size of the session ticket extension data.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 * @retval  HITLS_MEMCPY_FAIL, memory copy fails.
 */
int32_t HITLS_SetSessionTicketExtData(HITLS_Ctx *ctx, uint8_t *data, uint32_t dataSize);

#define HITLS_TICKET_KEY_RET_NEED_ALERT    (-1)   // callback fails. A fatal error occurs.
                                                  // You need to send an alert
#define HITLS_TICKET_KEY_RET_FAIL          0      // callback returns a failure, but the error is not a fatal error,
                                                  // for example, key_name matching fails.
#define HITLS_TICKET_KEY_RET_SUCCESS       1      // If the callback is successful,
                                                  // the key can be used for encryption and decryption
#define HITLS_TICKET_KEY_RET_SUCCESS_RENEW 2      // If the callback is successful, the key can be used for encryption
                                                  // and decryption. In the decryption scenario,
                                                  // the ticket needs to be renewed
/**
 * @ingroup hitls_session
 * @brief   Obtain and verify ticket_key on the server.
 *
 * @attention  keyName is fixed at 16 bytes, and iv is fixed at 16 bytes.
 *     During encryption, the keyName and cipher need to be returned.
 * The encryption type, encryption algorithm, key, iv, and hmacKey need to be filled in.
 *     During decryption, the HiTLS transfers the keyName.
 * The user needs to find the corresponding key based on the keyName and return the corresponding encryption type,
 * encryption algorithm, and key. (HiTLS uses the iv value sent by the client,
 * so the iv value does not need to be returned.)
 *
 * @param   keyName     [IN/OUT] name values corresponding to aes_key and hmac_key
 * @param   keyNameSize [IN] length of keyName
 * @param   cipher      [IN/OUT] Encryption information
 * @param   isEncrypt   [IN] Indicates whether to encrypt data. true: encrypt data. false: decrypt data.
 *
 * @return  TICKET_KEY_RET_NEED_ALERT     : indicates that the function fails to be called. A fatal error occurs.
 *                                          An alert message needs to be sent.
 *          TICKET_KEY_RET_FAIL           : During encryption, the failure to obtain the key_name is not a fatal error.
 *                                          In this case, the HiTLS sends an empty new session ticket message
 *                                          to the client.During decryption, the key_name matching fails,
 *                                          but it is not a fatal error. If the return value is the same,
 *                                          the HiTLS performs a complete handshake process or uses the
 *                                          session ID to restore the session.
 *          TICKET_KEY_RET_SUCCESS        : indicates that the encryption is successful. Decryption succeeds.
 *          TICKET_KEY_RET_SUCCESS_RENEW  : indicates that the encryption is successful.
 *                                          The value is the same as the returned value TICKET_KEY_RET_SUCCESS.
 *                                          If the decryption succeeds and the ticket needs to be renewed or changed,
 *                                          the HiTLS calls the callback again to encrypt the ticket
 *                                          when sending a new session ticket.
 */
typedef int32_t (*HITLS_TicketKeyCb)(uint8_t *keyName, uint32_t keyNameSize, HITLS_CipherParameters *cipher,
    uint8_t isEncrypt);

/**
 * @ingroup hitls_session
 * @brief   Set the ticket key callback, which is used only by the server, cb can be NULL.
 *
 * @param   config  [OUT] Config Context
 * @param   callback    [IN] Ticket key callback
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetTicketKeyCallback(HITLS_Config *config, HITLS_TicketKeyCb callback);

/**
 * @ingroup hitls_session
 * @brief   Obtain the default ticket key of the HiTLS.
 * The key is used to encrypt and decrypt the ticket in the new session ticket when the HITLS_TicketKeyCb callback
 * function is not set.
 *
 * @attention The returned key value is as follows: 16-byte key name + 32-byte AES key + 32-byte HMAC key
 *
 * @param   config [IN] Config Context.
 * @param   key [OUT] Obtained ticket key.
 * @param   keySize [IN] Size of the key array.
 * @param   outSize [OUT] Size of the obtained ticket key.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetSessionTicketKey(const HITLS_Config *config, uint8_t *key, uint32_t keySize, uint32_t *outSize);

/**
 * @ingroup hitls_session
 * @brief   Set the default ticket key of the HiTLS. The key is used to encrypt and decrypt tickets in the new
 * session ticket when the HITLS_TicketKeyCb callback function is not set.
 *
 * @attention The returned key value is as follows: 16-byte key name + 32-byte AES key + 32-byte HMAC key
 *
 * @param   config [OUT] Config Context.
 * @param   key [IN] Ticket key to be set.
 * @param   keySize [IN] Size of the ticket key.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetSessionTicketKey(HITLS_Config *config, const uint8_t *key, uint32_t keySize);

/**
 * @ingroup hitls_session
 * @brief   Set the user-specific session ID ctx, only on the server.
 * @attention session id ctx is different from session id, session recovery can be performed only after
 * session id ctx matching.
 * @param   config  [OUT] Config context.
 * @param   sessionIdCtx [IN] Session ID Context.
 * @param   len [IN] Session id context length, a maximum of 32 bytes.
 * @return  HITLS_SUCCESS, if successful.
 *          For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetSessionIdCtx(HITLS_Config *config, const uint8_t *sessionIdCtx, uint32_t len);

/**
 * @ingroup hitls_session
 * @brief   Set the session cache mode.
 *
 * @param   config  [OUT] Config context.
 * @param   mode [IN] Cache mode, corresponding to the HITLS_SESS_CACHE_MODE enumerated value.
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetSessionCacheMode(HITLS_Config *config, uint32_t mode);

/**
 * @ingroup hitls_session
 * @brief   Obtain the session cache mode.
 *
 * @param   config  [IN] config Context.
 * @param   mode [OUT] Cache mode, corresponding to the HITLS_SESS_CACHE_MODE enumerated value.
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetSessionCacheMode(HITLS_Config *config, uint32_t *mode);

/**
 * @ingroup hitls_session
 * @brief   Set the maximum number of sessions in the session cache.
 *
 * @param   config  [OUT] Config context.
 * @param   size [IN] Maximum number of sessions in the cache.
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetSessionCacheSize(HITLS_Config *config, uint32_t size);

/**
 * @ingroup hitls_session
 * @brief   Obtain the maximum number of sessions in the session cache.
 *
 * @param   config  [IN] Config context.
 * @param   size [OUT] Maximum number of sessions in the cache.
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetSessionCacheSize(HITLS_Config *config, uint32_t *size);

/**
 * @ingroup hitls_session
 * @brief   Set the session timeout interval.
 *
 * @param   config  [OUT] Config context.
 * @param   timeout [IN] Session timeout interval, in seconds.
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetSessionTimeout(HITLS_Config *config, uint64_t timeout);

/**
 * @ingroup hitls_session
 * @brief   Obtain the timeout interval of a session.
 *
 * @param   config  [IN] Config context.
 * @param   timeout [OUT] Session timeout interval, in seconds.
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetSessionTimeout(const HITLS_Config *config, uint64_t *timeout);

/**
 * @ingroup hitls_session
 * @brief   Whether the link is multiplexed with a session
 * @param   ctx  [IN] config Context.
 * @param   isReused [OUT] Indicates whether to reuse a session.
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_IsSessionReused(HITLS_Ctx *ctx, bool *isReused);

/**
 * @ingroup hitls_session
 * @brief   Set the user-specific session ID ctx of the HiTLS link, only on the server.
 * @attention session id ctx is different from sessio id, session recovery can be performed only after
 * session id ctx matching.
 * @param   ctx  [OUT] Config context.
 * @param   sessionIdCtx [IN] Session ID Context.
 * @param   len [IN] Session ID context length, which cannot exceed 32 bytes.
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetSessionIdCtx(HITLS_Ctx *ctx, const uint8_t *sessionIdCtx, uint32_t len);

/**
 * @ingroup hitls_session
 * @brief   Obtain the default ticket key of the HiTLS.
 * The key is used to encrypt and decrypt the ticket in the new session ticket
 * when the HITLS_TicketKeyCb callback function is not set.
 *
 * @attention The returned key value is as follows: 16-byte key name + 32-byte AES key + 32-byte HMAC key
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   key [OUT] Obtained ticket key
 * @param   keySize [IN] Size of the key array
 * @param   outSize [OUT] Size of the obtained ticket key.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_GetSessionTicketKey(const HITLS_Ctx *ctx, uint8_t *key, uint32_t keySize, uint32_t *outSize);

/**
 * @ingroup hitls_session
 * @brief   Set the default ticket key of the HiTLS. The key is used to encrypt and decrypt the ticket
 * in the new session ticket when the HITLS_TicketKeyCb callback function is not set.
 *
 * @attention The returned key value is as follows: 16-byte key name + 32-byte AES key + 32-byte HMAC key
 *
 * @param   ctx [OUT] TLS connection handle.
 * @param   key [IN] Ticket key to be set.
 * @param   keySize [IN] Size of the ticket key.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetSessionTicketKey(HITLS_Ctx *ctx, const uint8_t *key, uint32_t keySize);

/**
 * @ingroup hitls_session
 * @brief   Set the handle for the session information about the HiTLS link.
 * @attention Used only by the client.
 * @param   ctx [OUT] TLS connection handle
 * @param   session [IN] Session information handle.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetSession(HITLS_Ctx *ctx, HITLS_Session *session);

/**
 * @ingroup hitls_session
 * @brief   Obtain the handle of the session information and directly obtain the pointer.
 * @attention Directly obtain the pointer.
 * Ensure that the invoking is correct and avoid the pointer being a wild pointer.
 * @param   ctx [IN] TLS connection handle
 * @return  Session information handle
 */
HITLS_Session *HITLS_GetSession(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_session
 * @brief   Obtain the handle of the copied session information.
 * @attention The number of times that the call is called increases by 1.
 *            The call is released by calling HITLS_SESS_Free.
 * @param   ctx [IN] TLS connection handle
 * @return  Session information handle
 */
HITLS_Session *HITLS_GetDupSession(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_session
 * @brief   Apply for a new session.
 *
 * @param   void
 * @return Session handle.
 */
HITLS_Session *HITLS_SESS_New(void);

/**
 * @ingroup hitls_session
 * @brief   Duplicate a session, the number of reference times increases by 1.
 * @param   sess [IN] Session information handle
 * @return Session handle.
 */
HITLS_Session *HITLS_SESS_Dup(HITLS_Session *sess);

/**
 * @ingroup hitls_session
 * @brief   Release the session information handle.
 *
 * @param   sess [IN] Session information handle
 * @retval  void
 */
void HITLS_SESS_Free(HITLS_Session *sess);

/**
 * @ingroup hitls_session
 * @brief   Set the master key of a session.
 *
 * @param   sess [OUT] Session information handle.
 * @param   masterKey [IN] Master key.
 * @param   masterKeySize [IN] Size of the master key.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_SetMasterKey(HITLS_Session *sess, const uint8_t *masterKey, uint32_t masterKeySize);

/**
 * @ingroup hitls_session
 * @brief   Obtain the master key length of a session.
 *
 * @param   sess [IN] Session information handle
 * @return  Size of the master key
 */
uint32_t HITLS_SESS_GetMasterKeyLen(const HITLS_Session *sess);

/**
 * @ingroup hitls_session
 * @brief   Obtain the master key of a session.
 *
 * @param   sess [IN] Session information handle.
 * @param   masterKey [OUT] Master key.
 * @param   masterKeySize [OUT] Size of the master key.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_GetMasterKey(const HITLS_Session *sess, uint8_t *masterKey, uint32_t *masterKeySize);

/**
 * @ingroup hitls_session
 * @brief   Obtain the session protocol version.
 *
 * @param   sess [IN] Session information handle.
 * @param   version [OUT] Protocol version.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_GetProtocolVersion(const HITLS_Session *sess, uint16_t *version);

/**
 * @ingroup hitls_session
 * @brief   Set the session protocol version.
 *
 * @param   sess [OUT] Session information handle
 * @param   version [IN] Protocol version
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_SetProtocolVersion(HITLS_Session *sess, uint16_t version);

/**
 * @ingroup hitls_session
 * @brief   Set the session password suite.
 *
 * @param   sess [OUT] Session information handle.
 * @param   cipherSuite [IN] Password suite.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_SetCipherSuite(HITLS_Session *sess, uint16_t cipherSuite);

/**
 * @ingroup hitls_session
 * @brief   Obtain the session password suite.
 *
 * @param   sess [IN] Session information handle.
 * @param   cipherSuite [OUT] Cipher suite.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_GetCipherSuite(const HITLS_Session *sess, uint16_t *cipherSuite);

/**
 * @ingroup hitls_session
 * @brief   Set the session ID ctx.
 *
 * @param   sess [OUT] Session information handle.
 * @param   sessionIdCtx [IN] Session ID Context.
 * @param   sessionIdCtxSize [IN] Session ID Context length. The maximum length is 32 bytes.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_SetSessionIdCtx(HITLS_Session *sess, uint8_t *sessionIdCtx, uint32_t sessionIdCtxSize);

/**
 * @ingroup hitls_session
 * @brief   Obtain the session ID ctx.
 *
 * @param   sess [IN] Session information handle.
 * @param   sessionIdCtx [OUT] Session ID Context.
 * @param   sessionIdCtxSize [OUT] Session id Context length.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
*/
int32_t HITLS_SESS_GetSessionIdCtx(const HITLS_Session *sess, uint8_t *sessionIdCtx, uint32_t *sessionIdCtxSize);

/**
 * @ingroup hitls_session
 * @brief   Set the session ID.
 *
 * @param   sess [OUT] Session information handle.
 * @param   sessionId [IN] Session id.
 * @param   sessionIdSize [IN] The session ID contains a maximum of 32 bytes.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_SetSessionId(HITLS_Session *sess, uint8_t *sessionId, uint32_t sessionIdSize);

/**
 * @ingroup hitls_session
 * @brief   Obtain the session ID.
 *
 * @param   sess [IN] Session information handle
 * @param   sessionId [OUT] Session id
 * @param   sessionIdSize [OUT] Session ID length
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_GetSessionId(const HITLS_Session *sess, uint8_t *sessionId, uint32_t *sessionIdSize);

/**
 * @ingroup hitls_session
 * @brief   Set whether to contain the master key extension.
 *
 * @param   sess [OUT] Session information handle.
 * @param   haveExtMasterSecret [IN] Whether the master key extension is include.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_SetHaveExtMasterSecret(HITLS_Session *sess, uint8_t haveExtMasterSecret);

/**
 * @ingroup hitls_session
 * @brief   Obtain the master key extension.
 *
 * @param   sess [IN] Session information handle.
 * @param   haveExtMasterSecret [OUT] Whether the master key extension is contained.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_GetHaveExtMasterSecret(HITLS_Session *sess, bool *haveExtMasterSecret);

/**
 * @ingroup hitls_session
 * @brief   Set the timeout interval, in seconds.
 *
 * @param   sess [OUT] Session information handle
 * @param   timeout [IN] Timeout interval, in seconds.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_SetTimeout(HITLS_Session *sess, uint64_t timeout);

/**
 * @ingroup hitls_session
 * @brief   Get the timeout interval, in seconds.
 *
 * @param   sess [OUT] Session information handle
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
uint64_t HITLS_SESS_GetTimeout(HITLS_Session *sess);

/**
 * @ingroup hitls_session
 * @brief   Check whether the session can be recovered. Only simple check is performed, but the validity period
 * is not checked.
 *
 * @param   sess [IN] Session information handle.
 * @return  Indicates whether the recovery can be performed.
 */
bool HITLS_SESS_IsResumable(const HITLS_Session *sess);

/**
 * @ingroup hitls_session
 * @brief   Check whether the session has a ticket.
 *
 * @param   sess [IN] Session information handle
 * @return  Indicates whether a ticket exists.
 */
bool HITLS_SESS_HasTicket(const HITLS_Session *sess);

/**
 * @ingroup hitls_session
 * @brief   Obtain the user data in the session object.
 * @param   sess [IN] Pointer to the HITLS session to be printed.
 * @return  HITLS_NULL_INPUT, the TLS object pointer of the input parameter is null.
 */

void *HITLS_SESS_GetUserData(const HITLS_Session *sess);

/**
 * @ingroup hitls_session
 * @brief   Set the user data in the session object.
 * @param   userData [IN] Pointer to the user data.
 * @param   sess [IN] Pointer to the HITLS session to be printed.
 * @retval  HITLS_SUCCESS if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SESS_SetUserData(HITLS_Session *sess, void *userData);
/**
 * @ingroup hitls_session
 * @brief   Clear the timeout session.
 *
 * @param   config [IN] Configuration handle.
 * @param   nowTime [IN] Current time.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_ClearTimeoutSession(HITLS_Config *config, uint64_t nowTime);

/**
 * @ingroup hitls_session
 * @brief   Remove the session.
 *
 * @param   config [IN] Configuration handle.
 * @param   sess [IN] Session information handle.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_RemoveSession(HITLS_Config *config, HITLS_Session *sess);
#ifdef __cplusplus
}
#endif

#endif /* HITLS_SESSION_H */
