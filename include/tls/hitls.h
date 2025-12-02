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
 * @defgroup hitls
 * @ingroup hitls
 * @brief TLS parameter configuration
 */

#ifndef HITLS_H
#define HITLS_H

#include <stdint.h>
#include <stddef.h>
#include "hitls_type.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls
 * @brief   Create a TLS object and deep copy the HITLS_Config to the HITLS_Ctx.
 *
 * This is the main TLS structure, which starts to establish a secure link through the client or server
 * on the basis that the link has been established at the network layer.
 *
 * @attention The HITLS_Config can be released after the creation is successful.
 * @param   config [IN] Config context
 * @retval  HITLS_Ctx pointer. If the operation fails, a null value is returned.
 */
HITLS_Ctx *HITLS_New(HITLS_Config *config);

/**
 * @ingroup hitls
 * @brief   Release the TLS connection.
 *
 * @param   ctx [IN] TLS connection handle.
 * @retval  void
 */
void HITLS_Free(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Set the UIO object for the HiTLS context.
 *
 * Bind the HiTLS context to the UIO object, through which the TLS object sends data, reads data,
 * and controls the connection status at the network layer.
 * After successfully setting, the number of times the UIO object is referenced increases by 1.
 * BSL_UIO_Free is called to release the association between the HiTLS and UIO when HITLS_Free is called.
 *
 * @attention After a HiTLS context is bound to a UIO object, the UIO object cannot be bound to other HiTLS contexts.
 * This function must be called before HITLS_Connect and HITLS_Accept.
 * @param   ctx [OUT] TLS connection handle.
 * @param   uio [IN] UIO object.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetUio(HITLS_Ctx *ctx, BSL_UIO *uio);

/**
 * @ingroup hitls
 * @brief   Read UIO for the HiTLS context.
 *
 * @attention Must be called before HITLS_Connect and HITLS_Accept and released after HITLS_Free.
 * If this function has been called, you must call BSL_UIO_Free to release the UIO.
 * @param   ctx [OUT] TLS connection handle.
 * @param   uio [IN] UIO object.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetReadUio(HITLS_Ctx *ctx, BSL_UIO *uio);

/**
 * @ingroup hitls
 * @brief   Obtain the UIO object from the HiTLS context.
 *
 * @param   ctx [IN] TLS object.
 * @retval  UIO object.
 */
BSL_UIO *HITLS_GetUio(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Obtain the UIO object of the read data.
 *
 * @param   ctx [IN] TLS object
 * @retval  UIO object
 */
BSL_UIO *HITLS_GetReadUio(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   The client starts the handshake with the TLS server.
 *
 * Starting the handshake with the TLS server using HITLS_Connect.
 * The UIO object must be created and bound to the HiTLS context.
 * HITLS_Connect is designed as a non-blocking interface. If the handshake cannot be continued,
 * the returned value will not be HITLS_SUCCESS.
 * If the return value is HITLS_REC_NORMAL_RECV_BUF_EMPTY or HITLS_REC_NORMAL_IO_BUSY,
 * no fatal error occurs. Problems such as network congestion or network delay may occur.
 * You can continue to call HITLS_Connect. Note that if UIO is blocked, HITLS_Connect will also block,
 * but the return value is processed in the same way.
 *
 * @attention Only clients can call this interface.
 * @param   ctx [IN] TLS connection handle.
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY, record The receiving buffer is NULL and the handshake can be continued.
 * @retval  HITLS_REC_NORMAL_IO_BUSY, the network I/O is busy and needs to wait for the next sending.
 * You can continue the handshake.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_Connect(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Set the initial status of the connection.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   isClient [IN] Set the current client or server.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetEndPoint(HITLS_Ctx *ctx, bool isClient);

/**
 * @ingroup hitls
 * @brief   The server waits for the client to start handshake.
 *
 * The server waits for the client to initiate the handshake.
 * The UIO object must be created and bound to the HiTLS context.\n
 * HITLS_Accept is designed for non-blocking interfaces.
 * If the handshake cannot be continued, the system returns. The return value is not success.
 * If the return value is HITLS_REC_NORMAL_RECV_BUF_EMPTY or HITLS_REC_NORMAL_IO_BUSY, no fatal error occurs.
 * Problems such as network congestion or network delay may occur. You can continue to call HITLS_Accept.
 * Note that if the UIO is blocked, the HITLS_Accept will also be blocked, but the processing
 * of the returned value is the same.
 *
 * @attention Only the server calls this API.
 * @param   ctx [IN] TLS connection handle.
 * @retval  HITLS_SUCCESS, the handshake is successful.
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY, record The receiving buffer is NULL and the handshake can continue.
 * @retval  HITLS_REC_NORMAL_IO_BUSY, the network I/O is busy and needs to wait for the next sending.
 * You can continue the handshake.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_Accept(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Read application data
 *
 * @attention Only the application data decrypted by one record can be read by HiTLS at a time
 * HiTLS copies the application data to the input cache.
 * If the cache size is less than 16 KB, the maximum size of the application message decrypted
 * by a single record is 16 KB. This will result in a partial copy of the application data
 * You can call HITLS_GetReadPendingBytes to obtain the size of the remaining readable application data
 * in the current record. This is useful in DTLS scenarios.
 * @param   ctx [IN] TLS context
 * @param   data [OUT] Read data
 * @param   bufSize [IN] Size of the buffer
 * @param   readLen [OUT] Read length
 * @retval  HITLS_SUCCESS, if successful
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY, record The receiving buffer is NULL and can be read again.
 * @retval  HITLS_REC_NORMAL_IO_BUSY, the network I/O is busy and needs to wait for the next sending
 * You can continue to read the I/O.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_Read(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen);

/**
 * @ingroup hitls
 * @brief   read application data from a TLS/SSL connection
 * @attention HITLS_Peek() is identical to HITLS_Read() except no bytes are actually
              removed from the underlying BIO during the read
 * @param   ctx [IN] TLS context
 * @param   data [OUT] data buffer
 * @param   bufSize [IN] data buffer size
 * @param   readLen [OUT] store the number of bytes actually read in *readLen
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY, read buffer is empty, more bytes can be read.
 * @retval  HITLS_REC_NORMAL_IO_BUSY, IO budy, waiting for next calling to read more.
 * @retval  Refer to hitls_error.h for more
 */
int32_t HITLS_Peek(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen);

/**
 * @ingroup hitls
 * @brief   Write data.
 *
 * Encrypts and packs data with the specified length dataLen into a single record and sends the record.
 *
 * @attention The length of the data to be sent cannot exceed the maximum writable length,
 *            which can be obtained by calling HITLS_GetMaxWriteSize.
 * @param   ctx [IN] TLS context
 * @param   data [IN] Data to be written
 * @param   dataLen [IN] Length to be written
 * @param   writeLen [OUT] Length of Successful Writes
 * @retval  HITLS_SUCCESS is sent successfully.
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY, record If the receiving buffer is NULL, the message can be sent again.
 * @retval  HITLS_REC_NORMAL_IO_BUSY, The network I/O is busy and needs to wait for the next sending.
 *                                   You can continue sending the I/O.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_Write(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen);

/**
 * @ingroup hitls
 * @brief   Obtain the maximum writable (plaintext) length.
 *
 * @param   ctx [OUT] TLS connection handle.
 * @param   len [OUT] Maximum writable plaintext length (within 16 KB)
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_GetMaxWriteSize(const HITLS_Ctx *ctx, uint32_t *len);

/**
 * @ingroup hitls
 * @brief   Obtain user data from the HiTLS context. This interface is called in the callback registered with the HiTLS.
 *
 * @attention must be called before HITLS_Connect and HITLS_Accept.
 *            The life cycle of the user data pointer must be longer than the life cycle of the TLS object.
 * @param   ctx [OUT] TLS connection handle.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the TLS object pointer of the input parameter is null.
 */
void *HITLS_GetUserData(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Save the user data in the HiTLS context, which can be obtained from the callback registered with the HiTLS.
 *
 * @attention must be called before HITLS_Connect and HITLS_Accept.
 * The life cycle of the user data pointer must be greater than the life cycle of the TLS object.\n
 * If the user data needs to be cleared, the HITLS_SetUserData(ctx, NULL) interface can be called directly.
 * The Clean interface is not provided separately.
 * @param   ctx [OUT] TLS connection handle.
 * @param   userData [IN] Pointer to the user data.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the TLS object pointer of the input parameter is null.
 */
int32_t HITLS_SetUserData(HITLS_Ctx *ctx, void *userData);

/**
 * @ingroup hitls
 * @brief   Close the TLS connection.
 *
 * If the peer end is not closed, the system sends a closed notify message to the peer end.
 * HITLS_Close must not be called if a fatal error has occurred on the link.
 *
 * @param   ctx [IN] TLS connection handle.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_Close(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Set the shutdown status of the TLS link.
 *
 * In HITLS_Close, if the peer end is not closed, a closed notification message is sent to the peer end.
 * When the local end sends a closed notify message, the HiTLS sets the HITLS_SENT_SHUTDOWN flag bit.
 * When the local end receives the closed notify message, the HiTLS sets the HITLS_RECEIVED_SHUTDOWN flag bit.
 * By default, the HiTLS needs to send and receive closed notifications.
 * The actual condition for properly closing a session is HITLS_SENT_SHUTDOWN. (According to the TLS RFC,
 * it is acceptable to send only close_notify alerts without waiting for a reply from the peer.)
 * If HITLS_RECEIVED_SHUTDOWN is set, it indicates that the peer end does not need to wait for the closed notification.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   mode [IN] TLS shutdown status: HITLS_SENT_SHUTDOWN / HITLS_RECEIVED_SHUTDOWN.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetShutdownState(HITLS_Ctx *ctx, uint32_t mode);

/**
 * @ingroup hitls
 * @brief   Obtain the shutdown status of the TLS link.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   mode [OUT] TLS shutdown status: HITLS_SENT_SHUTDOWN / HITLS_RECEIVED_SHUTDOWN.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
*/
int32_t HITLS_GetShutdownState(const HITLS_Ctx *ctx, uint32_t *mode);

/**
 * @ingroup hitls
 * @brief   Obtain the HiTLS negotiation version.
 *
 * @param   ctx [IN] TLS object
 * @param   version [OUT] Negotiated version
 * @retval  HITLS_SUCCESS, obtained successfully.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetNegotiatedVersion(const HITLS_Ctx *ctx, uint16_t *version);

/**
 * @ingroup hitls
 * @brief   Obtain the latest protocol version.
 *
 * @param   ctx [IN] TLS object
 * @param   maxVersion [OUT] Latest protocol version supported
 * @retval  HITLS_SUCCESS, obtained successfully.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetMaxProtoVersion(const HITLS_Ctx *ctx, uint16_t *maxVersion);

/**
 * @ingroup hitls
 * @brief   Obtain the latest protocol version.
 *
 * @param   ctx [IN] TLS object
 * @param   maxVersion [OUT] Latest protocol version supported
 * @retval  HITLS_SUCCESS, obtained successfully.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetMinProtoVersion(const HITLS_Ctx *ctx, uint16_t *minVersion);

/**
 * @ingroup hitls
 * @brief   Set the minimum protocol version based on the specified version.
 *
 * @param   ctx [OUT] TLS object
 * @param   versiion [IN] The given version
 * @attention   The maximum version number and minimum version number must be both TLS and DTLS. Currently,
 * only DTLS 1.2 is supported. This interface is used together with the full configuration interfaces,
 * such as HITLS_CFG_NewDTLSConfig and HITLS_CFG_NewTLSConfig.
 * If the TLS full configuration is configured, only the TLS version can be set.
 * If full DTLS configuration is configured, only the DTLS version can be set.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetMinProtoVersion(HITLS_Ctx *ctx, uint16_t version);

/**
 * @ingroup hitls
 * @brief   Set the maximum protocol version that is supported based on the specified version.
 *
 * @param   ctx [OUT] TLS object
 * @param   versiion [IN] The given version
 * @attention   The maximum version number and minimum version number must be both TLS and DTLS. Currently,
 * only DTLS 1.2 is supported. This function is used together with the full configuration interfaces,
 * such as HITLS_CFG_NewDTLSConfig and HITLS_CFG_NewTLSConfig.
 * If the TLS full configuration is configured, only the TLS version can be set.
 * If full DTLS configuration is configured, only the DTLS version can be set.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetMaxProtoVersion(HITLS_Ctx *ctx, uint16_t version);

/**
 * @ingroup hitls
 * @brief   Obtain whether to use the AEAD algorithm.
 *
 * @param   ctx [IN] TLS object
 * @param   isAead [OUT] Indicates whether to use the AEAD algorithm.
 * @retval  HITLS_SUCCESS, obtained successfully.
 *          HITLS_NULL_INPUT, The input parameter pointer is null.
 */
int32_t HITLS_IsAead(const HITLS_Ctx *ctx, bool *isAead);

/**
 * @ingroup hitls
 * @brief   Check whether DTLS is used.
 *
 * @param   ctx [IN] TLS object
 * @param   isDtls [OUT] Indicates whether to use DTLS.
 * @retval  HITLS_SUCCESS, is obtained successfully.
 *          HITLS_NULL_INPUT, The input parameter pointer is null.
 */
int32_t HITLS_IsDtls(const HITLS_Ctx *ctx, bool *isDtls);

/**
 * @ingroup hitls
 * @brief   Record the error value of the HiTLS link.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   errorCode [IN] Error value
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetErrorCode(HITLS_Ctx *ctx, int32_t errorCode);

/**
 * @ingroup hitls
 * @brief   Obtain the error value of the HiTLS link.
 *
 * @param   ctx [OUT] TLS connection handle
 * @retval  Link error value
 */
int32_t HITLS_GetErrorCode(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Obtain the information about whether the handshake is complete.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   isDone [IN] Indicates whether the handshake is complete.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_IsHandShakeDone(const HITLS_Ctx *ctx, uint8_t *isDone);

/**
 * @ingroup hitls
 * @brief   Indicates whether the HiTLS object functions as the server.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   isServer [IN] Indicates whether to function as the server.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_IsServer(const HITLS_Ctx *ctx, bool *isServer);

/**
 * @ingroup hitls
 * @brief   Check the HiTLS object in the read cache.
 *
 * (including processed and unprocessed data, excluding the network layer) Whether there is data
 *
 * @param   ctx [IN] TLS connection handle
 * @param   isPending [OUT] Whether there is data. The options are as follows: 1: yes; 0: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_ReadHasPending(const HITLS_Ctx *ctx, bool *isPending);

/**
 * @ingroup hitls
 * @brief   Obtain the number of bytes of application data to be read from the current record from the HiTLS object.
 *
 * @attention When the HiTLS works in data packet transmission (DTLS), the HITLS_Read may
 * copy part of the application packet because the input buffer is not large enough.
 * This function is used to obtain the remaining size of the application packet.
 * This is useful for transport over DTLS.
 * @param   ctx [IN] TLS connection handle
 * @retval  Number of bytes of application data that can be read.
 */
uint32_t HITLS_GetReadPendingBytes(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Obtain the signature hash algorithm used by the peer end.
 *
 * @param   ctx [IN] TLS connection handle
 * @param   peerSignScheme [OUT] Peer signature hash algorithm
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_GetPeerSignScheme(const HITLS_Ctx *ctx, HITLS_SignHashAlgo *peerSignScheme);

/**
 * @ingroup hitls
 * @brief   Obtain the signature hash algorithm used by the local end.
 *
 * @param   ctx [IN] TLS connection handle
 * @param   localSignScheme [OUT] Local signature hash algorithm
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_GetLocalSignScheme(const HITLS_Ctx *ctx, HITLS_SignHashAlgo *localSignScheme);

/**
 * @ingroup hitls
 * @brief   Get shared signature algorithms (negotiated)
 *
 * This function returns the list of signature algorithms supported by both client and server.
 * The algorithms are sorted according to the configured priority policy:
 * - If server preference is enabled (isSupportServerPreference), sorted by server configuration order
 * - Otherwise sorted by peer's sending order
 *
 * @attention
 * - Must be called after peer sends signature_algorithms extension
 * - Only supports TLS 1.2 and above
 * - Server side: after receiving ClientHello
 * - Client side: after receiving CertificateRequest
 *
 * @param   ctx [IN] TLS connection handle
 * @param   idx [IN] Index of algorithm to query (starting from 0)
 *               - idx >= 0: return information for the specified index
 *               - idx = -1: only return total count, do not fill output parameters
 * @param   signatureScheme [OUT] IANA-defined signature scheme value (uint16_t), can be NULL
 * @param   keyType [OUT] Certificate key type (HITLS_CERT_KeyType), can be NULL
 * @param   paraId [OUT] Key parameter ID (CRYPT_PKEY_ParaId), can be NULL
 *
 * @retval  > 0 Total number of shared signature algorithms
 * @retval  0 Failed (no shared algorithms/idx out of range/version not supported/parameter is NULL)
 */
int32_t HITLS_GetSharedSigAlgs(const HITLS_Ctx *ctx, int32_t idx, uint16_t *signatureScheme, int32_t *keyType,
    int32_t *paraId);

/**
 * @ingroup hitls
 * @brief Set the group supported by the hitls object.
 *
 * @param ctx [OUT] hitls context
 * @param lst [IN] group list
 * @param groupSize [IN] List length
 * @retval HITLS_SUCCESS is set successfully.
 * For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetEcGroups(HITLS_Ctx *ctx, uint16_t *lst, uint32_t groupSize);

/**
 * @ingroup hitls
 * @brief   Set the signature algorithm supported by the hitls object.
 *
 * @param   ctx [OUT] hitls context.
 * @param   signAlgs [IN] List of supported signature algorithms.
 * @param   signAlgsSize [IN] Length of the signature algorithm list.
 * @retval  HITLS_SUCCESS, set successfully.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetSigalgsList(HITLS_Ctx *ctx, const uint16_t *signAlgs, uint16_t signAlgsSize);

/**
 * @ingroup hitls
 * @brief   Set the EC point format of the hitls.
 *
 * @attention Currently, the value can only be HITLS_ECPOINTFORMAT_UNCOMPRESSED.
 * @param   ctx [OUT] hitls context.
 * @param   pointFormats [IN] ec point format, corresponding to the HITLS_ECPointFormat enumerated value.
 * @param   pointFormatsSize [IN] Length of the ec point format
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetEcPointFormats(HITLS_Ctx *ctx, const uint8_t *pointFormats, uint32_t pointFormatsSize);

/**
 * @ingroup hitls
 * @brief   Set whether to verify the client certificate.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   support [IN] Indicates whether to verify the client certificate, the options are
 * as follows: true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_SetClientVerifySupport(HITLS_Ctx *ctx, bool support);

/**
 * @ingroup hitls
 * @brief   Set whether to support the function without the client certificate, Takes effect only when the client
 * certificate is verified.
 *
 * Client: This setting has no impact.
 * Server: When an NULL certificate is received from the client, indicates whether the certificate passes
 *         the verification, the verification fails by default.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   support [IN] Indicates whether the authentication is successful when there is no client certificate.
            true: If the certificate sent by the client is NULL, the server still passes the verification.
            false: If the certificate sent by the client is NULL, the server fails the verification.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_SetNoClientCertSupport(HITLS_Ctx *ctx, bool support);

/**
 * @ingroup hitls
 * @brief   Set whether to support post-handshake AUTH.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   support [IN] true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_SetPostHandshakeAuthSupport(HITLS_Ctx *ctx, bool support);

/**
 * @ingroup hitls
 * @brief   Set whether to support do not proceed dual-ended verification.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   support [IN] true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_SetVerifyNoneSupport(HITLS_Ctx *ctx, bool support);

/**
 * @ingroup hitls
 * @brief   Set whether the client certificate can be requested only once.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   support [IN] true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_SetClientOnceVerifySupport(HITLS_Ctx *ctx, bool support);

/**
 * @ingroup hitls
 * @brief   Obtain the value of hitlsConfig.
 *
 * @param   ctx [IN] TLS connection handle
 * @retval  NULL, The input parameter pointer is null.
 * @retval  hitlsConfig in ctx.
 */
const HITLS_Config *HITLS_GetConfig(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Obtain the point of GlobalConfig
 * @param   ctx [IN] TLS connection handle
 * @retval  NULL The input parameter pointer is null
 * @retval  GlobalConfig in ctx
 */
HITLS_Config *HITLS_GetGlobalConfig(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Clears the configured TLS1.3 cipher suite.
 *
 * @param   ctx [IN] TLS connection handle.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_ClearTLS13CipherSuites(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief    Set the supported cipher suites.
 *
 * The sequence of the cipher suites affects the priority of the selected cipher suites.
 * The cipher suites with the highest priority are selected first.
 *
 * @attention Do not check the cipher suite to meet the changes in the supported version.
 * @param   ctx [OUT] TLS connection handle.
 * @param   cipherSuites [IN] Key suite array, corresponding to the HITLS_CipherSuite enumerated value.
 * @param   cipherSuitesSize [IN] Key suite array length.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetCipherSuites(HITLS_Ctx *ctx, const uint16_t *cipherSuites, uint32_t cipherSuitesSize);

/**
 * @ingroup hitls
 * @brief   Obtain the negotiated cipher suite pointer.
 *
 * @param   ctx  [IN] TLS connection handle
 * @retval  Pointer to the negotiated cipher suite.
 *          NULL, the input parameter pointer is null.
 */
const HITLS_Cipher *HITLS_GetCurrentCipher(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Obtain the random number of the client and server during the handshake.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   out  [OUT] Random number obtained
 * @param   outlen  [OUT] Length of the input parameter out.
 *                        If the length is greater than the maximum random number length, the value will be changed.
 * @param   isClient  [IN] True, obtain the random number of the client.
 *                         False, obtain the random number of the server.
 * @retval  HITLS_SUCCESS, obtaining the status succeeded.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetHsRandom(const HITLS_Ctx *ctx, uint8_t *out, uint32_t *outlen, bool isClient);

/**
 * @ingroup hitls
 * @brief   Obtain the current handshake status.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   state  [OUT] Current handshake status
 * @retval  HITLS_SUCCESS, Obtaining the status succeeded.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetHandShakeState(const HITLS_Ctx *ctx, uint32_t *state);

/**
 * @brief   Obtain the handshake status character string.
 *
 * @param   state [IN] Handshake status
 * @retval  Character string corresponding to the handshake status
 */
const char *HITLS_GetStateString(uint32_t state);

/**
 * @ingroup hitls
 * @brief   Check whether a handshake is being performed.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   isHandShaking  [OUT] Indicates whether the handshake is in progress.
 * @retval  HITLS_SUCCESS, Obtaining the status succeeded.
 *          For other error codes, see hitls_error.h.
 */
int32_t HITLS_IsHandShaking(const HITLS_Ctx *ctx, bool *isHandShaking);

/**
 * @ingroup hitls
 * @brief   Obtain whether renegotiation is supported.
 *
 * @param   ctx [IN] hitls Context
 * @param   isSupportRenegotiation [OUT] Whether to support renegotiation
 * @retval  HITLS_SUCCESS, obtain successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetRenegotiationSupport(const HITLS_Ctx *ctx, bool *isSupportRenegotiation);

/**
 * @ingroup hitls
 * @brief   Check whether the handshake has not been performed.
 *
 * @param   ctx [IN] TLS connection handle
 * @param   isBefore [OUT] Indicates whether the handshake has not been performed.
 * @retval  HITLS_SUCCESS, obtaining the status succeeded.
 *          For other error codes, see hitls_error.h.
 */
int32_t HITLS_IsBeforeHandShake(const HITLS_Ctx *ctx, bool *isBefore);

/**
 * @ingroup hitls
 * @brief   Set the MTU of Data Link layer.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   linkMtu  [IN] MTU of Data Link layer.
 * @retval  HITLS_SUCCESS, set the mtu succeeded.
 * @retval  HITLS_CONFIG_INVALID_LENGTH, the mtu is invalid
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetLinkMtu(HITLS_Ctx *ctx, uint16_t linkMtu);

/**
 * @ingroup hitls
 * @brief   Set the MTU of a path.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   mtu  [IN] Set the MTU.
 * @retval  HITLS_SUCCESS, set the mtu succeeded.
 * @retval  HITLS_CONFIG_INVALID_LENGTH, the mtu is invalid
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetMtu(HITLS_Ctx *ctx, uint16_t mtu);

/**
 * @ingroup hitls
 * @brief   Set the option that don't query mtu from the bio.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   noQueryMtu  [IN] whether not to query the mtu from the bio.
 * @retval  HITLS_SUCCESS, set the option succeeded.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetNoQueryMtu(HITLS_Ctx *ctx, bool noQueryMtu);

/**
 * @ingroup hitls
 * @brief   Querying whether the EMSGSIZE error occur and mtu need be modified
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   needQueryMtu [IN] Indicates whether the EMSGSIZE error occur and mtu need be modified
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetNeedQueryMtu(HITLS_Ctx *ctx, bool *needQueryMtu);

/**
 * @ingroup hitls
 * @brief   Obtain the version number set by the client in ClientHello.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   clientVersion [OUT] Obtained version number
 * @retval  HITLS_SUCCESS, obtaining the status succeeded.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetClientVersion(const HITLS_Ctx *ctx, uint16_t *clientVersion);

/**
 * @ingroup hitls
 * @brief   The client/server starts handshake.
 *
 * @attention In the IDLE state, the HITLS_SetEndPoint must be called first.
 * @param   ctx  [IN] TLS connection handle
 * @retval  HITLS_SUCCESS, obtaining the status succeeded.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_DoHandShake(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Check whether the current end is client.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   isClient  [OUT] Client or not.
 * @retval  HITLS_SUCCESS, obtaining the status succeeded.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_IsClient(const HITLS_Ctx *ctx, bool *isClient);

/**
 * @ingroup hitls
 * @brief   Set the keyupdate type of the current context and send the keyupdate message.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   updateType [IN] keyupdate type
 * @retval  HITLS_SUCCESS, if successful.
 *          For other error codes, see hitls_error.h.
 */
int32_t HITLS_KeyUpdate(HITLS_Ctx *ctx, uint32_t updateType);

/**
 * @ingroup hitls
 * @brief   Return the keyupdate type of the current context.
 *
 * @param   ctx  [IN] TLS connection handle
 * @retval  KeyUpdateType in ctx
 * @retval  NULL, the input parameter pointer is null.
 */
int32_t HITLS_GetKeyUpdateType(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Obtain the supported peer group or the number of supported peer groups of the nth match.
 *
 * nmatch Value range: - 1 or a positive integer
 * This function can be called only after negotiation and can be called only by the server.
 * If nmatch is a positive integer, check the intersection of groups on the client and server,
 * and return the nmatch group in the intersection by groupId.
 * If the value of nmatch is - 1, the number of intersection groups on the client and server is
 * returned based on groupId.
 *
 * @param   ctx  [IN] TLS connection handle.
 * @param   nmatch  [IN] Sequence number of the group to be obtained, -1 Return the number of supported peer groups.
 * @param   groupId  [OUT] Returned result.
 * @retval  HITLS_SUCCESS, Obtaining the status succeeded.
 *          For details about other error codes, see hitls_error.h.
 *
 */
int32_t HITLS_GetSharedGroup(const HITLS_Ctx *ctx, int32_t nmatch, uint16_t *groupId);

/**
 * @ingroup hitls
 * @brief   Set the DTLS timeout interval callback.
 * @param   ctx [IN] TLS connection handle.
 * @param   cb [IN] DTLS obtaining timeout interval callback.
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetDtlsTimerCb(HITLS_Ctx *ctx, HITLS_DtlsTimerCb cb);


/**
 * @ingroup hitls
 * @brief   Obtain the supported version number.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   version [OUT] Supported version number.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_GetVersionSupport(const HITLS_Ctx *ctx, uint32_t *version);

/**
 * @ingroup hitls
 * @brief   Set the supported version number.
 *
 * @param   ctx  [OUT] TLS connection handle
 * @param   version [IN] Supported version number.
 * @attention   The maximum version number and minimum version number must be both TLS and DTLS. Currently,
 * only DTLS 1.2 is supported. This function is used together with the full configuration interfaces,
 * such as HITLS_CFG_NewDTLSConfig and HITLS_CFG_NewTLSConfig.
 *     If the TLS full configuration is configured, only the TLS version can be set. If full DTLS configuration
 * is configured, only the DTLS version can be set.
 *     The versions must be consecutive. By default, the minimum and maximum versions are supported.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_SetVersionSupport(HITLS_Ctx *ctx, uint32_t version);

/**
 * @ingroup hitls
 * @brief   Set the supported version number range.
 *
 * @param   ctx  [OUT] TLS connection handle
 * @param   minVersion [IN] Minimum version number supported.
 * @param   maxVersion [IN] Maximum version number supported.
 * @attention   The maximum version number and minimum version number must be both TLS and DTLS.
 *     Currently, only DTLS 1.2 is supported. This function is used together with the full configuration interfaces,
 * such as HITLS_CFG_NewDTLSConfig and HITLS_CFG_NewTLSConfig.
 *     If the TLS full configuration is configured, only the TLS version can be set. If full DTLS configuration is
 * configured, only the DTLS version can be set.
 * @retval HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_SetVersion(HITLS_Ctx *ctx, uint32_t minVersion, uint32_t maxVersion);

/**
 * @ingroup hitls
 * @brief   Set the version number to be disabled.
 *
 * @param   ctx  [OUT] TLS connection handle
 * @param   noVersion [IN] Disabled version number.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_SetVersionForbid(HITLS_Ctx *ctx, uint32_t noVersion);

/**
 * @ingroup hitls
 * @brief   Sets whether to verify the version in the premaster secret.
 *
 * @param   ctx  [OUT] TLS Connection Handle.
 * @param   needCheck [IN] Indicates whether to perform check.
 * @attention   This parameter is valid for versions earlier than TLS1.1.
 *     true indicates that verification is supported, and false indicates that verification is not supported. In
 * this case, rollback attacks may occur. For versions later than TLS1.1, forcible verification is supported.
 * This interface takes effect on the server.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_SetNeedCheckPmsVersion(HITLS_Ctx *ctx, bool needCheck);

/**
 * @ingroup hitls
 * @brief   Set the silent disconnection mode.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   mode [IN] Mode type. The value 0 indicates that the quiet disconnection mode is disabled, and the value 1
 * indicates that the quiet disconnection mode is enabled.
 * @retval  HITLS_SUCCESS, if successful.
 * For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetQuietShutdown(HITLS_Ctx *ctx, int32_t mode);

/**
 * @ingroup hitls
 * @brief   Obtain the current silent disconnection mode.
 *
 * @param   ctx [IN] TLS connection handle
 * @param   mode [OUT] Mode type.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetQuietShutdown(const HITLS_Ctx *ctx, int32_t *mode);

/**
 * @ingroup hitls
 * @brief   Sets whether to support the function of automatically selecting DH parameters.
 *
 * If the value is true, the DH parameter is automatically selected based on the length of the certificate private key.
 * If the value is false, the DH parameter needs to be set.
 *
 * @param   ctx  [IN/OUT] hitls context.
 * @param   support [IN] Whether to support. The options are as follows: true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 */
int32_t HITLS_SetDhAutoSupport(HITLS_Ctx *ctx, bool support);

/**
 * @ingroup hitls
 * @brief   Set the DH parameter specified by the user.
 *
 * @param   ctx [IN/OUT] hitls context.
 * @param   dhPkey [IN] User-specified DH key.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT ctx or dhPkey field is NULL
 */
int32_t HITLS_SetTmpDh(HITLS_Ctx *ctx, HITLS_CRYPT_Key *dhPkey);

/**
 * @ingroup hitls
 * @brief   Set the TmpDh callback function.
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   callback [IN] Set the TmpDh callback.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetTmpDhCb(HITLS_Ctx *ctx, HITLS_DhTmpCb callback);

/**
 * @ingroup hitls
 * @brief   Sets the RecordPadding callback.
 *
 * @param   ctx [IN/OUT] TLS Connection Handle
 * @param   callback [IN] Sets the RecordPadding callback.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetRecordPaddingCb(HITLS_Ctx *ctx, HITLS_RecordPaddingCb callback);

/**
 * @ingroup hitls
 * @brief   Obtains the RecordPadding callback function.
 *
 * @param   ctx [IN/OUT] TLS Connection Handle
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
HITLS_RecordPaddingCb HITLS_GetRecordPaddingCb(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Sets the parameters arg required by the RecordPadding callback function.
 *
 * @param   ctx [IN/OUT] TLS Connection Handle
 * @param   arg [IN] Related Parameter arg
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetRecordPaddingCbArg(HITLS_Ctx *ctx, void *arg);

/**
 * @ingroup hitls
 * @brief   Obtains the parameter arg required by the RecordPadding callback function.
 *
 * @param   ctx [IN/OUT] TLS Connection Handle
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
void *HITLS_GetRecordPaddingCbArg(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Obtain the verification data and length of the peer end based on the received finished message.
 *
 * @param   ctx [IN] TLS context
 * @param   buf [OUT] verify data
 * @param   bufLen [IN] Length of the buffer to be obtained
 * @param   dataLen [OUT] Actual length of the buf
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetPeerFinishVerifyData(const HITLS_Ctx *ctx, void *buf, uint32_t bufLen, uint32_t *dataLen);

/**
 * @ingroup hitls
 * @brief   Disables the verification of keyusage in the certificate. This function is enabled by default.
 *
 * @param   ctx [OUT] config context
 * @param   isCheck [IN] Sets whether to check key usage.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetCheckKeyUsage(HITLS_Ctx *ctx, bool isCheck);

/**
 * @ingroup hitls
 * @brief   Obtain the verification data and length of the local end based on the sent finished message.
 *
 * @param   ctx [IN] TLS context
 * @param   buf [OUT] verify data
 * @param   bufLen [IN] Length of the buffer to be obtained
 * @param   dataLen [OUT] Indicates the actual length of the buffer
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetFinishVerifyData(const HITLS_Ctx *ctx, void *buf, uint32_t bufLen, uint32_t *dataLen);

/**
 * @ingroup hitls
 * @brief   Obtains whether security renegotiation is supported.
 *
 * @param   ctx [IN] hitls context.
 * @param   isSecureRenegotiation [OUT] Whether to support security renegotiation
 * @retval  HITLS_SUCCESS, obtained successfully.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetSecureRenegotiationSupport(const HITLS_Ctx *ctx, bool *isSecureRenegotiation);

/**
 * @ingroup hitls
 * @brief Perform renegotiation.
 *
 * @attention 1. After this interface is called, the user needs to call one of the
 *               HITLS_Connect / HITLS_Accept / HITLS_Read / HITLS_Write interfaces again,
 *               The HITLS_Renegotiate interface is used only for setting and initialization of renegotiation,
 *               The renegotiation process is performed when the user calls the
 *               HITLS_Connect / HITLS_Accept / HITLS_Read / HITLS_Write.
 *            2. You are advised to use the HITLS_Connect / HITLS_Accept interface for renegotiation.
 *               After the negotiation is complete, call the HITLS_Read / HITLS_Write interface.
 *            3. If the user uses HITLS_Read to perform renegotiation,
 *               the user may receive the app message from the peer end during the renegotiation.
 *               (1) If the renegotiation has not started, the HiTLS will return the message to the user.
 *               (2) If the renegotiation is in progress, no app message is received in this scenario,
 *                   and the HiTLS sends an alert message to disconnect the link.
 *            4. If the user uses the HITLS_Connect / HITLS_Accept / HITLS_Write for renegotiation,
 *               the user may receive the app message from the peer end during the renegotiation,
 *               HiTLS caches the message, the message is returned when a user calls HITLS_Read.
 *               Maximum of 50 app messages can be cached, if the cache is full, subsequent app messages will be
 *               ignored.
 *            5. In the DTLS over UDP scenario, if the user functions as the server,
 *               packet loss occurs in the renegotiation request(hello request).
 *               (1) If the user calls the HITLS_Write for renegotiation, the app message to be sent is
 *                   sent to the peer end after packet loss occurs in the renegotiation request.
 *               (2) The HiTLS does not retransmit the renegotiation request. The user needs to call the
 *                   HITLS_Renegotiate and HITLS_Accept interfaces again to continue the renegotiation.
 *                   You can call the HITLS_GetRenegotiationState interface to determine
 *                   whether the current renegotiation is in the renegotiation state,
 *                   If the renegotiation is not in the renegotiation state,
 *                   call the HITLS_Renegotiate and HITLS_Accept interfaces again to continue the renegotiation.
 *            6. In the DTLS over UDP scenario, if the user as the client,
 *               packet loss occurs in the renegotiation request (client hello).
 *               (1) If the user calls the HITLS_Write to perform renegotiation, the app message is not
 *                   sent to the peer end after packet loss occurs in the renegotiation request.
 *                   Instead, the user waits for the response from the peer end.
 *               (2) The client hello message is retransmitted inside the HiTLS,
 *                   and the user does not need to initiate renegotiation again.
 * @param   ctx  [IN] TLS Connection Handle
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_Renegotiate(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Obtain the current is whether in the renegotiation state.
 *
 * @attention For the server, the server does not enter the renegotiation state by sending only the hello request
 * message, The server enters the renegotiation state only after receiving the client hello message.
 *
 * @param   ctx  [IN] TLS Connection Handle.
 * @param   isRenegotiationState  [OUT] Indicates whether the renegotiation is in the renegotiation state.
 * true: in the renegotiation state; false: not in the renegotiation state.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetRenegotiationState(const HITLS_Ctx *ctx, bool *isRenegotiationState);


/**
 * @ingroup hitls
 * @brief   Obtain the current internal status.
 *
 * @param   ctx  [IN] TLS connection Handle.
 * @param   rwState  [OUT] Current internal status information.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetRwstate(const HITLS_Ctx *ctx, uint8_t *rwstate);

/**
 * @ingroup hitls
 * @brief   Check whether the client certificate can be verified.
 *
 * @param   ctx  [IN] TLS connection Handle.
 * @param   isSupport   [OUT] Indicates whether to verify the client certificate.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 */
int32_t HITLS_GetClientVerifySupport(HITLS_Ctx *ctx, bool *isSupport);

/**
 * @ingroup hitls
 * @brief   Check whether no client certificate is supported, This command is valid only when client certificate
 * verification is enabled.
 *
 * @param   ctx  [IN] TLS Connection Handle.
 * @param   isSupport   [OUT] Whether no client certificate is supported.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 */
int32_t HITLS_GetNoClientCertSupport(HITLS_Ctx *ctx, bool *isSupport);

/**
 * @ingroup hitls
 * @brief   Query whether post-handshake AUTH is supported
 *
 * @param   ctx  [IN] TLS connection Handle.
 * @param   isSupport   [OUT] indicates whether to support post-handshake AUTH.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 */
int32_t HITLS_GetPostHandshakeAuthSupport(HITLS_Ctx *ctx, bool *isSupport);

/**
 * @ingroup hitls
 * @brief   Query if support is available for not performing dual-end verification.
 *
 * @param   ctx  [IN] TLS Connection Handle.
 * @param   isSupport   [OUT] if support is available for not performing dual-end verification.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 */
int32_t HITLS_GetVerifyNoneSupport(HITLS_Ctx *ctx, bool *isSupport);

/**
 * @ingroup hitls
 * @brief   Query whether the client certificate can be requested only once.
 *
 * @param   ctx  [IN] TLS Connection Handle.
 * @param   isSupport   [OUT] Indicates whether the client certificate can be requested only once.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 */
int32_t HITLS_GetClientOnceVerifySupport(HITLS_Ctx *ctx, bool *isSupport);


/**
 * @ingroup hitls
 * @brief   Clears the renegotiation count.
 *
 * @param   ctx [IN] hitls context.
 * @param   renegotiationNum [OUT] Number of incoming renegotiations.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_ClearRenegotiationNum(HITLS_Ctx *ctx, uint32_t *renegotiationNum);

/**
 * @ingroup hitls
 * @brief   Obtain the negotiated group information.
 *
 * @param   ctx  [IN] TLS Connection Handle.
 * @param   group   [OUT] Negotiated group information.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 */
int32_t HITLS_GetNegotiateGroup(const HITLS_Ctx *ctx, uint16_t *group);

/**
 * @ingroup hitls
 * @brief   Set the function to support the specified feature.
 *
 * @param   ctx [OUT] TLS Connection Handle
 * @param   mode [IN] Mode features to enabled.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetModeSupport(HITLS_Ctx *ctx, uint32_t mode);

/**
 * @ingroup hitls
 * @brief   Function to clear the specified feature.
 *
 * @param   ctx [OUT] TLS Connection Handle
 * @param   mode [IN] Mode features to clear.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_ClearModeSupport(HITLS_Ctx *ctx, uint32_t mode);

/**
 * @ingroup hitls
 * @brief   Obtain the mode of the function feature in the config file.
 *
 * @param   ctx [OUT] TLS Connection Handle
 * @param   mode [OUT] Mode obtain the output parameters of the mode.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetModeSupport(const HITLS_Ctx *ctx, uint32_t *mode);

/**
 * @ingroup hitls
 * @brief   Setting the Encrypt-Then-Mac mode.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   encryptThenMacType [IN] Current Encrypt-Then-Mac mode.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetEncryptThenMac(HITLS_Ctx *ctx, bool encryptThenMacType);

/**
 * @ingroup hitls
 * @brief   Obtains the Encrypt-Then-Mac type
 *
 * @param   ctx [IN] TLS connection Handle.
 * @param   encryptThenMacType [OUT] Current Encrypt-Then-Mac mode.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetEncryptThenMac(const HITLS_Ctx *ctx, bool *encryptThenMacType);

/**
 * @ingroup hitls
 * @brief   Setting the value of server_name.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   serverName  [IN] serverName.
 * @param   serverNameStrlen [IN] serverName length.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetServerName(HITLS_Ctx *ctx, uint8_t *serverName, uint32_t serverNameStrlen);

/**
 * @ingroup hitls
 * @brief   The algorithm suite can be preferentially selected from the algorithm list supported by the server.
 *
 * @param   ctx [IN] TLS Connection Handle.
 * @param   isSupport [IN] Support or Not.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetCipherServerPreference(HITLS_Ctx *ctx, bool isSupport);

/**
 * @ingroup hitls
 * @brief   Obtains whether the current cipher suite supports preferential selection
 * from the list of algorithms supported by the server.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   isSupport [OUT] Support or Not.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetCipherServerPreference(const HITLS_Ctx *ctx, bool *isSupport);

/**
 * @ingroup hitls
 * @brief   Sets whether to support renegotiation.
 *
 * @param   ctx   [IN/OUT] TLS connection handle.
 * @param   isSupport  [IN] Support or Not, true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 */
int32_t HITLS_SetRenegotiationSupport(HITLS_Ctx *ctx, bool isSupport);

/**
 * @ingroup hitls
 * @brief   Set whether to allow a renegotiate request from the client
 * @param   ctx   [IN/OUT] TLS connection handle.
 * @param   isSupport  [IN] Support or Not, true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 */
int32_t HITLS_SetClientRenegotiateSupport(HITLS_Ctx *ctx, bool isSupport);

/**
 * @ingroup hitls
 * @brief   Set whether to abort handshake when server doesn't support SecRenegotiation
 * @param   ctx   [IN/OUT] TLS connection handle.
 * @param   isSupport  [IN] Support or Not, true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 */
int32_t HITLS_SetLegacyRenegotiateSupport(HITLS_Ctx *ctx, bool isSupport);

/**
 * @ingroup hitls
 * @brief   Sets whether to support session tickets.
 *
 * @param   ctx  [IN/OUT] TLS connection handle.
 * @param   isSupport [IN] whether to support session tickets, true: yes; false: no
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 */
int32_t HITLS_SetSessionTicketSupport(HITLS_Ctx *ctx, bool isSupport);

/**
 * @ingroup hitls
 * @brief   Check whether the session ticket is supported.
 *
 * @param   ctx  [IN] TLS connection handle.
 * @param   isSupport [OUT] whether to support session tickets, true: yes; false: no
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 */
int32_t HITLS_GetSessionTicketSupport(const HITLS_Ctx *ctx, bool *isSupport);

/**
 * @ingroup hitls
 * @brief   Sets whether to perform cookie exchange in the dtls.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   isSupport [IN] Indicates whether to perform cookie exchange
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetDtlsCookieExangeSupport(HITLS_Ctx *ctx, bool isSupport);

/**
 * @ingroup hitls
 * @brief   Querying whether the DTLS performs cookie exchange.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   isSupport [IN] Indicates whether to perform cookie exchange.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetDtlsCookieExangeSupport(const HITLS_Ctx *ctx, bool *isSupport);

/**
 * @ingroup hitls
 * @brief   Sets whether to send handshake messages by flight distance.
 *
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   isEnable [IN] Indicates whether to enable handshake information sending by flight distance.
 * The value 0 indicates disable, other values indicate enable.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetFlightTransmitSwitch(HITLS_Ctx *ctx, bool isEnable);

/**
 * @ingroup hitls
 * @brief   Obtains the status of whether to send handshake information according to the flight distance.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   isEnable [OUT] Indicates whether to send handshake information by flight distance
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetFlightTransmitSwitch(const HITLS_Ctx *ctx, bool *isEnable);

/**
 * @ingroup hitls
 * @brief   set the max empty records number can be received
 *
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   emptyNum [IN] Indicates the max number of empty records can be received
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetEmptyRecordsNum(HITLS_Ctx *ctx, uint32_t emptyNum);

/**
 * @ingroup hitls
 * @brief   Obtain the max empty records number can be received
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   emptyNum [OUT] Indicates the max number of empty records can be received
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetEmptyRecordsNum(const HITLS_Ctx *ctx, uint32_t *emptyNum);


/**
 * @ingroup hitls
 * @brief   set the max send fragment to restrict the amount of plaintext bytes in any record
 *
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   maxSendFragment [IN] Indicates the max send fragment
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_CONFIG_INVALID_LENGTH, the maxSendFragment is less than 64 or greater than 16384.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetMaxSendFragment(HITLS_Ctx *ctx, uint16_t maxSendFragment);

/**
 * @ingroup hitls
 * @brief   Obtain the max send fragment to restrict the amount of plaintext bytes in any record
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   maxSendFragment [OUT] Indicates the max send fragment
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetMaxSendFragment(const HITLS_Ctx *ctx, uint16_t *maxSendFragment);

/**
 * @ingroup hitls
 * @brief   Set the rec inbuffer inital size
 *
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   recInbufferSize [IN] Indicates the rec inbuffer inital size
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_CONFIG_INVALID_LENGTH, the recInbufferSize is less than 512 or greater than 18432.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetRecInbufferSize(HITLS_Ctx *ctx, uint32_t recInbufferSize);

/**
 * @ingroup hitls
 * @brief   Obtain the rec inbuffer inital size
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   recInbufferSize [OUT] Indicates the rec inbuffer inital size
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetRecInbufferSize(const HITLS_Ctx *ctx, uint32_t *recInbufferSize);

/**
 * @ingroup hitls
 * @brief   Sets the maximum size of the certificate chain that can be sent from the peer end.
 *
 * @param   ctx [IN/OUT] TLS connection handle.
 * @param   maxSize [IN] Sets the maximum size of the certificate chain that can be sent from the peer end.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetMaxCertList(HITLS_Ctx *ctx, uint32_t maxSize);

/**
 * @ingroup hitls
 * @brief   Obtains the maximum size of the certificate chain that can be sent by the peer end.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   maxSize [OUT] Maximum size of the certificate chain that can be sent from the peer end.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetMaxCertList(const HITLS_Ctx *ctx, uint32_t *maxSize);

/**
 * @ingroup hitls
 * @brief   This interface is valid only on the server. When the post-handshake command is configured,
 *          the client identity is verified through this interface.
 *
 * @param   ctx [IN] TLS Connection Handle
 * @retval  HITLS_INVALID_INPUT, invalid input parameter.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_VerifyClientPostHandshake(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Obtain the legacy version from client hello.
 * @attention This interface is valid only in client hello callback.
 * @param   ctx [IN] TLS connection handle.
 * @param   out [OUT] Pointer to the output buffer for legacy version.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_ClientHelloGetLegacyVersion(HITLS_Ctx *ctx, uint16_t *version);

/**
 * @ingroup hitls
 * @brief   Obtain the random value from client hello.
 *
 * @attention This interface is valid only in client hello callback.
 * @param   ctx [IN] TLS connection handle.
 * @param   out [OUT] Pointer to the output buffer for random value.
 * @param   outlen [IN] Length of the output buffer.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_ClientHelloGetRandom(HITLS_Ctx *ctx, uint8_t **out, uint8_t *outlen);

/**
 * @ingroup hitls
 * @brief   Obtain the session ID from client hello.
 *
 * @attention This interface is valid only in client hello callback.
 * @param   ctx [IN] TLS connection handle.
 * @param   out [OUT] Pointer to the output buffer for session ID.
 * @param   outlen [OUT] Length of the output buffer.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_ClientHelloGetSessionID(HITLS_Ctx *ctx, uint8_t **out, uint8_t *outlen);

/**
 * @ingroup hitls
 * @brief   Obtain the cipher suites from client hello.
 *
 * @attention This interface is valid only in client hello callback.
 * @param   ctx [IN] TLS connection handle.
 * @param   out [OUT] Pointer to the output buffer for cipher suites.
 * @param   outlen [OUT] Length of the output buffer.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_ClientHelloGetCiphers(HITLS_Ctx *ctx, uint16_t **out, uint16_t *outlen);

/**
* @ingroup hitls
* @brief   Obtain the all extension types from client hello.
*
* @attention This interface is valid only in client hello callback.
* @attention the caller must release the storage allocated for *out using BSL_SAL_FREE().
* @param   ctx [IN] TLS connection handle.
* @param   out [OUT] Pointer to the output buffer for all extensions.
* @param   outlen [OUT] Length of the output buffer.
* @retval  HITLS_SUCCESS, if successful.
*          For details about other error codes, see hitls_error.h.
    */
int32_t HITLS_ClientHelloGetExtensionsPresent(HITLS_Ctx *ctx, uint16_t **out, uint8_t *outlen);

/**
 * @ingroup hitls
 * @brief   Obtain a specific extension from client hello.
 *
 * @attention This interface is valid only in client hello callback.
 * @param   ctx [IN] TLS connection handle.
 * @param   type [IN] Type of the extension to be obtained.
 * @param   out [OUT] Pointer to the output buffer for the extension.
 * @param   outlen [OUT] Length of the output buffer.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_ClientHelloGetExtension(HITLS_Ctx *ctx, uint16_t type, uint8_t **out, uint32_t *outlen);

/**
 * @ingroup hitls
 * @brief   Handle the timeout of sending and receiving DTLS messages.
 *
 * @param   ctx [IN] TLS Connection Handle
 * @retval  HITLS_SUCCESS, if retransmit the message successful.
 * @retval  HITLS_MSG_HANDLE_DTLS_RETRANSMIT_NOT_TIMEOUT, It hasn't timed out yet.
 * @retval  For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_DtlsProcessTimeout(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Get the remaining timeout time for timeout retransmission.
 *
 * @param   ctx [IN] TLS Connection Handle
 * @param   remainTimeOut [OUT] remaining timeout time for timeout retransmission, unit: us
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_MSG_HANDLE_ERR_WITHOUT_TIMEOUT_ACTION, Indicates non UDP links or absence of timeout behavior.
 * @retval  For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_DtlsGetTimeout(HITLS_Ctx *ctx, uint64_t *remainTimeOut);

/**
 * @ingroup hitls
 * @brief   Sets whether to support middle box compat mode.
 *
 * @param   ctx [IN] TLS Connection Handle.
 * @param   isMiddleBox [IN] Support or Not.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_SetMiddleBoxCompat(HITLS_Ctx *ctx, bool isMiddleBox);

/**
 * @ingroup hitls
 * @brief   Obtain whether middle box compat mode is supported.
 *
 * @param   ctx [IN] TLS connection handle.
 * @param   isMiddleBox [OUT] Support or Not.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetMiddleBoxCompat(HITLS_Ctx *ctx, bool *isMiddleBox);

/**
 * @brief   Obtain the record out buffer remaining size
 *
 * @param   ctx [IN] TLS connection handle
 * @param   size [OUT] record out buffer remaining size
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_GetOutPendingSize(const HITLS_Ctx *ctx, uint32_t *size);

/**
 * @brief   Flush the record out buffer
 *
 * @param   ctx [IN] TLS connection handle
 *
 * @retval  HITLS_SUCCESS Out buffer is empty or flush success
 * @retval  HITLS_REC_NORMAL_IO_BUSY Out buffer is not empty, but the IO operation is busy
 */
int32_t HITLS_Flush(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Sets whether to forcibly support extended master keys.
 *
 * @param   ctx [IN] TLS connection handle
 * @param   support [IN] Indicates whether to forcibly support extended master keys.
                         The options are as follows: True: yes; False: no. The default value is true.
 * @retval  HITLS_SUCCESS.
 * @retval  HITLS_NULL_INPUT, ctx is NULL.
 */
int32_t HITLS_SetExtenedMasterSecretSupport(HITLS_Ctx *ctx, bool support);

/**
 * @ingroup hitls
 * @brief   Query whether extended master keys are supported.
 *
 * @param   ctx [IN] TLS connection handle
 * @param   isSupport   [OUT] Indicates whether to support the extended master key.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is NULL.
 */
int32_t HITLS_GetExtenedMasterSecretSupport(HITLS_Ctx *ctx, bool *isSupport);

/**
 * @ingroup hitls
 * @brief   Set whether to support session restoration during renegotiation.
 * By default, session restoration is not supported.
 * @param   ctx [IN] TLS connection handle
 * @param   support  [IN] Whether to support the function. The options are as follows: True: yes; False: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 */
int32_t HITLS_SetResumptionOnRenegoSupport(HITLS_Ctx *ctx, bool support);

/**
 * @ingroup hitls
 * @brief   Get whether to support session restoration during renegotiation.
 * By default, session restoration is not supported.
 * @param   ctx [IN] TLS connection handle
 * @param   isSupport  [OUT] Indicates whether to support session restoration during renegotiation.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, ctx is null.
 */
int32_t HITLS_GetResumptionOnRenegoSupport(HITLS_Ctx *ctx, bool *isSupport);

/**
 * @ingroup hitls
 * @brief   Get whether to allow a renegotiate request from the client
 * @param   ctx   [IN] TLS connection handle.
 * @param   isSupport  [OUT] Indicates whether to allow a renegotiate request from the client
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is NULL.
 */
int32_t HITLS_GetClientRenegotiateSupport(HITLS_Ctx *ctx, bool *isSupport);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_H */