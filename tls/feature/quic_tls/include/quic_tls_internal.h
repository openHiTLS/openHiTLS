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

#ifndef QUIC_TLS_INTERNAL_H
#define QUIC_TLS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "hitls_quic_tls.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TlsCtx TLS_Ctx;

/* ---- per-connection QUIC context (types and constants) ---- */

/* Number of TLS 1.3 encryption levels tracked per connection (INITIAL,
 * EARLY_DATA, HANDSHAKE, APPLICATION). Indexes the per-level input buffers. */
#define QUIC_TLS_ENCRYPTION_LEVEL_COUNT 4u

#define QUIC_TLS_DEFAULT_LEVEL_DATA_LIMIT 16384u

/* Growable receive buffer for one encryption level. Reassembled CRYPTO stream
 * bytes are appended at [length] and drained from [offset]; the window
 * [offset, length) is the data still to be consumed by the handshake. */
typedef struct {
    uint8_t *data; /* Backing storage, reallocated on demand up to the per-level cap. */
    uint32_t capacity; /* Allocated size of data in bytes. */
    uint32_t offset; /* Read cursor: start of unconsumed bytes. */
    uint32_t length; /* Write cursor: end of buffered bytes. */
} QUIC_TLS_InputBuffer;

/* The five QUIC callbacks. Also used as the staging form parsed from a
 * HITLS_QUIC_TLS_Callbacks table before being committed to a live connection,
 * which keeps a replacement atomic: an incomplete table never partially
 * overwrites active callbacks. */
typedef struct {
    HITLS_QUIC_TLS_SetReadSecretFunc setReadSecret; /* install a read traffic secret. */
    HITLS_QUIC_TLS_SetWriteSecretFunc setWriteSecret; /* install a write traffic secret. */
    HITLS_QUIC_TLS_AddHandshakeDataFunc addHandshakeData; /* hand TLS handshake bytes to QUIC. */
    HITLS_QUIC_TLS_FlushFlightFunc flushFlight; /* mark end of the current flight. */
    HITLS_QUIC_TLS_SendAlertFunc sendAlert; /* map a fatal alert to CRYPTO_ERROR. */
} QUIC_TLS_Callbacks;

/* QUIC data owned by one TLS_Ctx. The callbacks and callback argument
 * are retained across HITLS_Clear, while handshake buffers, transport
 * parameters, encryption levels, and other transient state are reset. */
typedef struct QuicTlsCtx {
    QUIC_TLS_Callbacks cbs; /* Active callbacks; the struct assignment replaces them as one unit. */
    void *callbackArg; /* Opaque arg passed back to every callback. */
    QUIC_TLS_InputBuffer input[QUIC_TLS_ENCRYPTION_LEVEL_COUNT]; /* Inbound CRYPTO bytes, one buffer per level. */
    uint8_t *localTransportParams; /* Local QUIC transport parameters (owned copy). */
    uint32_t localTransportParamsLen; /* Length of localTransportParams in bytes. */
    uint8_t *peerTransportParams; /* Peer QUIC transport parameters (owned copy). */
    uint32_t peerTransportParamsLen; /* Length of peerTransportParams in bytes. */
    HITLS_QUIC_TLS_EncryptionLevel readLevel; /* Current inbound CRYPTO encryption level. */
    HITLS_QUIC_TLS_EncryptionLevel writeLevel; /* Current level outbound handshake bytes belong to. */
    bool readSecretInstalled[QUIC_TLS_ENCRYPTION_LEVEL_COUNT]; /* Whether a read secret was installed per level. */
    bool writeSecretInstalled[QUIC_TLS_ENCRYPTION_LEVEL_COUNT]; /* Whether a write secret was installed per level. */
    bool flightPending; /* Handshake bytes are buffered awaiting a flush. */
} QUIC_TLS_Ctx;

/**
 * @brief Allocate and initialize a per-connection QUIC context.
 *
 * The read and write levels are set to INITIAL; all other fields are zeroed.
 *
 * @return Pointer to the new QUIC_TLS_Ctx, or NULL on allocation failure.
 */
QUIC_TLS_Ctx *QUIC_TLS_CtxNew(void);

/**
 * @brief Release a QUIC context and all buffers it owns.
 *
 * Frees the per-level input buffers and both transport-parameter copies,
 * cleanses the structure, then frees it. A NULL argument is a no-op.
 *
 * @param quicTlsCtx [IN] QUIC context to free.
 */
void QUIC_TLS_CtxFree(QUIC_TLS_Ctx *quicTlsCtx);

/**
 * @brief Reset transient QUIC state for connection reuse.
 *
 * Frees the per-level input buffers and transport-parameter copies, clears
 * handshake state, and restores the read/write levels to INITIAL. The active
 * callbacks, callback argument, and QUIC mode are retained across HITLS_Clear.
 * A NULL argument is a no-op.
 *
 * @param quicTlsCtx [IN] QUIC context to reset.
 */
void QUIC_TLS_CtxReset(QUIC_TLS_Ctx *quicTlsCtx);

/**
 * @brief Report whether an encryption level has unconsumed buffered data.
 *
 * @param quicTlsCtx [IN] QUIC context.
 * @param level   [IN] Encryption level to query.
 *
 * @return true if bytes remain to be read, false otherwise or on invalid input.
 */
bool QUIC_TLS_BufferHasData(const QUIC_TLS_Ctx *quicTlsCtx, HITLS_QUIC_TLS_EncryptionLevel level);

/* ---- QUIC-mode helpers used by record / key-schedule / CM ---- */

/**
 * @brief Report whether a connection has QUIC mode enabled.
 *
 * @param ctx [IN] TLS context (may be NULL).
 *
 * @return true if ctx is non-NULL and QUIC mode is active, false otherwise.
 */
bool QUIC_TLS_IsMode(const TLS_Ctx *ctx);

/**
 * @brief Map a failed QUIC callback to the record-layer callback error.
 *
 * @param callbackId  [IN] ID of the callback that failed.
 * @param callbackRet [IN] Return value from the callback.
 *
 * @retval HITLS_REC_CB_FAIL always.
 */
int32_t QUIC_TLS_CallbackFailed(uint32_t callbackId, int32_t callbackRet);

/**
 * @brief Deliver a newly derived traffic secret to the QUIC stack.
 *
 * Maps the secret to its encryption level (HANDSHAKE or APPLICATION), rejects a
 * duplicate install, and invokes the read or write secret callback. Switching
 * the read level while the old level still holds unconsumed data is a protocol
 * violation. On success advances the corresponding read/write level.
 *
 * @param ctx       [IN] TLS context.
 * @param secret    [IN] Traffic secret buffer (identified by pointer identity).
 * @param secretLen [IN] Length of secret in bytes.
 * @param isOut     [IN] true for the write (outbound) secret, false for read (inbound).
 *
 * @retval HITLS_SUCCESS                     succeeded.
 * @retval HITLS_MSG_HANDLE_STATE_ILLEGAL    not in QUIC mode, bad input, or duplicate install.
 * @retval HITLS_CONFIG_UNSUPPORT            secret does not map to a QUIC encryption level.
 * @retval HITLS_QUIC_TLS_PROTOCOL_VIOLATION     read-level switch left unconsumed data behind.
 * @retval HITLS_REC_CB_FAIL                 the setReadSecret/setWriteSecret callback failed.
 */
int32_t QUIC_TLS_SetTrafficSecret(TLS_Ctx *ctx, const uint8_t *secret, uint32_t secretLen, bool isOut);

/**
 * @brief Report whether a cipher suite is usable under QUIC.
 *
 * RFC 9001 Section 5.3 excludes TLS_AES_128_CCM_8_SHA256 because it defines no
 * QUIC header-protection scheme for that suite. Non-QUIC connections are not
 * subject to this restriction.
 *
 * @param ctx         [IN] TLS context.
 * @param cipherSuite [IN] Cipher suite identifier to check.
 *
 * @return true if the suite is allowed, false if forbidden under QUIC.
 */
bool QUIC_TLS_IsCipherSuiteSupported(const TLS_Ctx *ctx, uint16_t cipherSuite);

#ifdef __cplusplus
}
#endif

#endif /* QUIC_TLS_INTERNAL_H */
