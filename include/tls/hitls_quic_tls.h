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
 * @defgroup hitls_quic_tls
 * @ingroup tls
 * @brief QUIC-TLS public APIs
 */

#ifndef HITLS_QUIC_TLS_H
#define HITLS_QUIC_TLS_H

#include <stddef.h>
#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_quic_tls
 * @brief   TLS 1.3 encryption levels used by QUIC callbacks.
 */
typedef enum {
    HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL = 0,
    HITLS_QUIC_TLS_ENCRYPTION_LEVEL_EARLY_DATA = 1,
    HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE = 2,
    HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION = 3
} HITLS_QUIC_TLS_EncryptionLevel;

/**
 * @ingroup hitls_quic_tls
 * @brief   Callback for installing a read traffic secret at one encryption level.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   level [IN] Encryption level associated with the secret.
 * @param   cipher [IN] Negotiated cipher information, valid only during the callback.
 * @param   secret [IN] Read traffic secret, valid only during the callback.
 * @param   secretLen [IN] Read traffic secret length in bytes.
 * @param   arg [IN] Opaque callback argument registered by @ref HITLS_QUIC_TLS_SetQuicTlsMethod.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
typedef int32_t (*HITLS_QUIC_TLS_SetReadSecretFunc)(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
                                                    const HITLS_Cipher *cipher, const uint8_t *secret, size_t secretLen,
                                                    void *arg);

/**
 * @ingroup hitls_quic_tls
 * @brief   Callback for installing a write traffic secret at one encryption level.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   level [IN] Encryption level associated with the secret.
 * @param   cipher [IN] Negotiated cipher information, valid only during the callback.
 * @param   secret [IN] Write traffic secret, valid only during the callback.
 * @param   secretLen [IN] Write traffic secret length in bytes.
 * @param   arg [IN] Opaque callback argument registered by @ref HITLS_QUIC_TLS_SetQuicTlsMethod.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
typedef int32_t (*HITLS_QUIC_TLS_SetWriteSecretFunc)(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
                                                     const HITLS_Cipher *cipher, const uint8_t *secret,
                                                     size_t secretLen, void *arg);

/**
 * @ingroup hitls_quic_tls
 * @brief   Callback for appending TLS Handshake bytes to a QUIC CRYPTO stream.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   level [IN] Encryption level of the CRYPTO stream.
 * @param   data [IN] TLS Handshake bytes, valid only during the callback.
 * @param   dataLen [IN] Length of data in bytes.
 * @param   arg [IN] Opaque callback argument registered by @ref HITLS_QUIC_TLS_SetQuicTlsMethod.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
typedef int32_t (*HITLS_QUIC_TLS_AddHandshakeDataFunc)(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
                                                       const uint8_t *data, size_t dataLen, void *arg);

/**
 * @ingroup hitls_quic_tls
 * @brief   Callback for marking the end of the current TLS flight.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   arg [IN] Opaque callback argument registered by @ref HITLS_QUIC_TLS_SetQuicTlsMethod.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
typedef int32_t (*HITLS_QUIC_TLS_FlushFlightFunc)(HITLS_Ctx *ctx, void *arg);

/**
 * @ingroup hitls_quic_tls
 * @brief   Callback for reporting a fatal TLS alert associated with the current TLS failure.
 *
 * @details The callback can run before the invoking TLS API returns, so the caller must treat the alert as provisional
 *          and defer the final QUIC close decision. The API return value is authoritative: if it is
 *          HITLS_QUIC_TLS_PROTOCOL_VIOLATION, override the reported alert and close with QUIC transport error
 *          PROTOCOL_VIOLATION (0x000a). Otherwise, map the fatal alert to CRYPTO_ERROR(alert).
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   level [IN] Encryption level at which the alert occurred.
 * @param   alert [IN] TLS alert description.
 * @param   arg [IN] Opaque callback argument registered by @ref HITLS_QUIC_TLS_SetQuicTlsMethod.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
typedef int32_t (*HITLS_QUIC_TLS_SendAlertFunc)(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level, uint8_t alert,
                                                void *arg);

/**
 * @ingroup hitls_quic_tls
 * @brief   QUIC-TLS callback function IDs.
 * @details ID 0 is reserved as the array terminator, so callback IDs start
 *          at 1:
 *          1 = HITLS_QUIC_TLS_FUNC_SET_READ_SECRET,
 *          2 = HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET,
 *          3 = HITLS_QUIC_TLS_FUNC_ADD_HANDSHAKE_DATA,
 *          4 = HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT,
 *          5 = HITLS_QUIC_TLS_FUNC_SEND_ALERT.
 */
#define HITLS_QUIC_TLS_FUNC_SET_READ_SECRET    1
#define HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET   2
#define HITLS_QUIC_TLS_FUNC_ADD_HANDSHAKE_DATA 3
#define HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT       4
#define HITLS_QUIC_TLS_FUNC_SEND_ALERT         5

/**
 * @ingroup hitls_quic_tls
 * @brief   QUIC-TLS callback table entry.
 * @details Each entry pairs a function ID with the matching callback from
 *          this group. A callback table is an array of these entries
 *          terminated by HITLS_QUIC_TLS_CALLBACKS_END. The layout matches
 *          CRYPT_EAL_Func, but the definition is deliberately self-contained:
 *          TLS public headers stay independent of the crypto layer (see
 *          HITLS_Lib_Ctx, which is likewise opaque).
 */
typedef struct {
    int32_t id; /* HITLS_QUIC_TLS_FUNC_* function ID. */
    void *func; /* Callback matching the ID; cast to the typed pointer when read. */
} HITLS_QUIC_TLS_Callbacks;

/* Terminator of a HITLS_QUIC_TLS_Callbacks array; id 0 marks the end. */
#define HITLS_QUIC_TLS_CALLBACKS_END {0, NULL}

/**
 * @ingroup hitls_quic_tls
 * @brief   Enable QUIC mode and register callbacks on a stream TLS connection.
 *
 * @details The callback table must contain all mandatory callbacks and end with
 *          HITLS_QUIC_TLS_CALLBACKS_END. Unknown function IDs are ignored. If a
 *          recognized ID appears more than once, the last entry is used. The
 *          callbacks are replaced as one unit only after validation succeeds.
 *          The replacement is retained across HITLS_Clear.
 *
 * @attention This function must be called before HITLS_Connect or HITLS_Accept starts the handshake.
 * @attention QUIC handshakes require TLS 1.3; the handshake enforces it even if the configuration
 *            also allows earlier TLS versions.
 * @note QUIC application data and connection shutdown are owned by the QUIC stack. HITLS_Read, HITLS_Write,
 *       HITLS_Close, HITLS_KeyUpdate, and post-handshake client authentication are unsupported in QUIC mode.
 * @note HITLS_QUIC_TLS_PROTOCOL_VIOLATION requires the caller to close the QUIC connection with transport error
 *       PROTOCOL_VIOLATION (0x000a). The sendAlert callback may already have reported the underlying TLS alert;
 *       this return code takes precedence and must override that alert for the final QUIC close code.
 * @param   ctx [IN] TLS connection handle.
 * @param   callbacks [IN] Callback table terminated by HITLS_QUIC_TLS_CALLBACKS_END.
 * @param   arg [IN] Opaque callback argument borrowed until HITLS_Free or successful replacement.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_QUIC_TLS_SetQuicTlsMethod(HITLS_Ctx *ctx, const HITLS_QUIC_TLS_Callbacks *callbacks, void *arg);

/**
 * @ingroup hitls_quic_tls
 * @brief   Provide reassembled QUIC CRYPTO stream bytes to TLS.
 *
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   level [IN] Encryption level of the supplied CRYPTO stream bytes. It must equal the current read
 *          level reported by @ref HITLS_QUIC_TLS_GetReadLevel; otherwise HITLS_INVALID_INPUT is returned.
 * @param   data [IN] Reassembled CRYPTO stream bytes. It can be NULL only when dataLen is 0.
 * @param   dataLen [IN] Length of data in bytes.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_QUIC_TLS_ProvideData(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level, const uint8_t *data,
                                   size_t dataLen);

/**
 * @ingroup hitls_quic_tls
 * @brief   Process buffered TLS 1.3 post-handshake messages.
 *
 * @details This function processes messages such as NewSessionTicket. If a fragmented message needs more
 *          Application-level CRYPTO bytes, provide them with @ref HITLS_QUIC_TLS_ProvideData and call this function again.
 * @param   ctx [IN/OUT] TLS connection handle.
 * @retval  HITLS_SUCCESS, if all currently buffered post-handshake messages were processed.
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY, if a fragmented message needs more CRYPTO stream bytes.
 * @retval  HITLS_QUIC_TLS_PROTOCOL_VIOLATION, if a peer message must fail with transport error PROTOCOL_VIOLATION
 *          (for example a post-handshake CertificateRequest, RFC 9001 s4.4). The sendAlert callback may report
 *          unexpected_message while TLS enters its terminal alerted state; this return code is authoritative, so
 *          the caller must override the alert and close with PROTOCOL_VIOLATION (0x000a). Later calls on this TLS
 *          connection fail the state check.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_QUIC_TLS_ProcessPostHandshake(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_quic_tls
 * @brief   Set the local opaque QUIC transport-parameters value.
 *
 * @attention Clients must call this function before the first HITLS_Connect. Servers must call it before
 *            EncryptedExtensions is emitted; it may be called from the write-secret callback during the handshake.
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   params [IN] Local QUIC transport parameters. It must not be NULL.
 * @param   paramsLen [IN] Length of params in bytes. It must be greater than 0 and no greater than UINT16_MAX.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_QUIC_TLS_SetTransportParams(HITLS_Ctx *ctx, const uint8_t *params, size_t paramsLen);

/**
 * @ingroup hitls_quic_tls
 * @brief   Get the peer opaque QUIC transport-parameters value.
 *
 * @details The returned pointer is borrowed and remains valid until HITLS_Clear or HITLS_Free. Before a peer value
 *          is received, this function returns HITLS_SUCCESS with *params set to NULL and *paramsLen set to 0. A
 *          received zero-length value has the same representation; extension presence is checked by the handshake.
 *          After HelloRetryRequest, the server requires the second ClientHello to repeat the same value.
 * @param   ctx [IN] TLS connection handle.
 * @param   params [OUT] Borrowed peer transport-parameters value.
 * @param   paramsLen [OUT] Length of the peer transport-parameters value in bytes.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_QUIC_TLS_GetPeerTransportParams(const HITLS_Ctx *ctx, const uint8_t **params, size_t *paramsLen);

/**
 * @ingroup hitls_quic_tls
 * @brief   Get the current read encryption level.
 *
 * @param   ctx [IN] TLS connection handle.
 * @return  Current read encryption level. Returns HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL if ctx is not in QUIC mode.
 */
HITLS_QUIC_TLS_EncryptionLevel HITLS_QUIC_TLS_GetReadLevel(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_quic_tls
 * @brief   Get the current write encryption level.
 *
 * @param   ctx [IN] TLS connection handle.
 * @return  Current write encryption level. Returns HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL if ctx is not in QUIC mode.
 */
HITLS_QUIC_TLS_EncryptionLevel HITLS_QUIC_TLS_GetWriteLevel(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_quic_tls
 * @brief   Get the CRYPTO input-buffer limit for one encryption level.
 *
 * @details This is the per-level limit enforced by @ref HITLS_QUIC_TLS_ProvideData. INITIAL and APPLICATION
 *          use the 16 KiB flight default. HANDSHAKE allows a client to buffer CertificateRequest and Certificate
 *          from one flight while each individual handshake message remains subject to the TLS message-size limit;
 *          a server that requests a client certificate allows one certificate-sized message. EARLY_DATA returns 0
 *          because QUIC carries no CRYPTO frames at that level and this API does not support 0-RTT.
 * @param   ctx [IN] TLS connection handle.
 * @param   level [IN] Encryption level to query.
 * @return  Maximum buffered CRYPTO stream length in bytes, or 0 for an invalid or unsupported level.
 */
size_t HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(const HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_QUIC_TLS_H */
