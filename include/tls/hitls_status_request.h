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
 * @defgroup hitls_status_request
 * @ingroup tls
 * @brief Certificate status request / stapling (RFC 6066) client and server interfaces.
 *
 * The mechanism-level interfaces (status request type, status/stapling callbacks)
 * are status-type agnostic. The OCSP data interfaces (OCSP response list set/get)
 * operate on HITLS_OCSP_Resp objects, which is the only status type defined by
 * RFC 6066.
 */

#ifndef HITLS_STATUS_REQUEST_H
#define HITLS_STATUS_REQUEST_H

#include <stdint.h>
#include "hitls_type.h"
/* OCSP responses are referenced by pointer only in this header; the complete
 * type is defined in include/pki/hitls_pki_ocsp.h and remains opaque here so
 * this TLS header does not pull in the pki headers. */
typedef struct Resp_St HITLS_OCSP_Resp;

#ifdef __cplusplus
extern "C" {
#endif

/** OCSP certificate status type (RFC 6066). */
#define HITLS_STATUS_REQUEST_TYPE_OCSP 1

/** Disable the certificate status request. Never sent on the wire. */
#define HITLS_STATUS_REQUEST_TYPE_DISABLE (-1)

/* Client status callback (HITLS_StatusCb) return values. */
#define HITLS_STATUS_OK 0 /* The stapled response is satisfactory; continue the handshake. */
#define HITLS_STATUS_REJECT \
    1 /* The response failed to parse or the certificate is revoked. The library
                                    aborts with the fatal bad_certificate_status_response alert. */
#define HITLS_STATUS_ERROR \
    2 /* Internal error (e.g., memory allocation failure). The library aborts with
                                    the fatal internal_error alert. */

/* Server stapling callback (HITLS_StaplingCb) return values. */
#define HITLS_STAPLING_SEND  1 /* Send the status (acknowledge and send CertificateStatus / embed). */
#define HITLS_STAPLING_SKIP  0 /* Do not send the status; the handshake continues without stapling. */
#define HITLS_STAPLING_ERROR 2 /* Internal error; the handshake is aborted with the fatal internal_error alert. */

/**
 * @ingroup hitls_status_request
 * @brief Client notification callback. Invoked when the peer certificate status
 *        responses are ready. The application can call HITLS_GetPeerOcspResponseList
 *        in the callback to obtain the raw responses, validate them, and report the
 *        result through the return value. No response data is passed in.
 *
 * @param ctx [IN] TLS connection handle
 * @param arg [IN] User data registered with the callback
 * @retval HITLS_STATUS_OK, the response is satisfactory; continue.
 * @retval HITLS_STATUS_REJECT, the response failed to parse or the certificate is revoked;
 *         the library aborts with bad_certificate_status_response.
 * @retval HITLS_STATUS_ERROR, an internal error occurred; the library aborts with internal_error.
 */
typedef int32_t (*HITLS_StatusCb)(HITLS_Ctx *ctx, void *arg);

/**
 * @ingroup hitls_status_request
 * @brief Server notification callback. Invoked before the CertificateStatus
 *        message (TLS 1.2) or the Certificate message (TLS 1.3) is built so
 *        that the application can set the responses to be stapled by calling
 *        HITLS_SetOcspResponseList.
 *
 * @param ctx [IN] TLS connection handle
 * @param arg [IN] User data registered with the callback
 * @retval HITLS_STAPLING_SEND, send the status (provided a response is set).
 * @retval HITLS_STAPLING_SKIP, do not send the status; the handshake continues.
 * @retval HITLS_STAPLING_ERROR, an internal error occurred; the handshake is aborted.
 */
typedef int32_t (*HITLS_StaplingCb)(HITLS_Ctx *ctx, void *arg);

/**
 * @ingroup hitls_status_request
 * @brief Enable or disable the certificate status request on a client config.
 *
 * @param config [IN] TLS config handle
 * @param type   [IN] HITLS_STATUS_REQUEST_TYPE_OCSP(1) to enable,
 *                    HITLS_STATUS_REQUEST_TYPE_DISABLE(-1) to disable.
 *                    Other values are rejected. The default is disabled.
 * @retval HITLS_SUCCESS, success.
 * @retval HITLS_NULL_INPUT, config is NULL.
 * @retval HITLS_INVALID_INPUT, type is outside the supported set.
 */
int32_t HITLS_CFG_SetStatusRequestType(HITLS_Config *config, int32_t type);

/**
 * @ingroup hitls_status_request
 * @brief Register a client certificate status notification callback at the
 *        config level.
 *
 * @param config [IN] TLS config handle
 * @param cb     [IN] Client status callback
 * @param arg    [IN] User data passed to the callback
 * @retval HITLS_SUCCESS, success.
 * @retval HITLS_NULL_INPUT, config is NULL.
 */
int32_t HITLS_CFG_SetStatusCb(HITLS_Config *config, HITLS_StatusCb cb, void *arg);

/**
 * @ingroup hitls_status_request
 * @brief Register a client certificate status notification callback at the ctx
 *        level. The ctx-level callback takes priority over the config-level
 *        callback.
 *
 * @param ctx [IN] TLS connection handle
 * @param cb  [IN] Client status callback
 * @param arg [IN] User data passed to the callback
 * @retval HITLS_SUCCESS, success.
 * @retval HITLS_NULL_INPUT, ctx is NULL.
 */
int32_t HITLS_SetStatusCb(HITLS_Ctx *ctx, HITLS_StatusCb cb, void *arg);

/**
 * @ingroup hitls_status_request
 * @brief Register a server certificate status stapling callback at the config
 *        level.
 *
 * @param config [IN] TLS config handle
 * @param cb     [IN] Server stapling callback
 * @param arg    [IN] User data passed to the callback
 * @retval HITLS_SUCCESS, success.
 * @retval HITLS_NULL_INPUT, config is NULL.
 */
int32_t HITLS_CFG_SetStaplingCb(HITLS_Config *config, HITLS_StaplingCb cb, void *arg);

/**
 * @ingroup hitls_status_request
 * @brief Register a server certificate status stapling callback at the ctx
 *        level. The ctx-level callback takes priority over the config-level
 *        callback.
 *
 * @param ctx [IN] TLS connection handle
 * @param cb  [IN] Server stapling callback
 * @param arg [IN] User data passed to the callback
 * @retval HITLS_SUCCESS, success.
 * @retval HITLS_NULL_INPUT, ctx is NULL.
 */
int32_t HITLS_SetStaplingCb(HITLS_Ctx *ctx, HITLS_StaplingCb cb, void *arg);

/**
 * @ingroup hitls_status_request
 * @brief Obtain the OCSP responses stapled by the peer.
 *        TLS 1.2 returns one entry; TLS 1.3 returns one entry per certificate
 *        (chainidx 0 is the EE certificate). The returned array is a borrowed
 *        reference owned by the ctx and is only valid until the handshake (or
 *        the ctx) is torn down; the application must not free it. Each element
 *        is a parsed HITLS_OCSP_Resp; a NULL element means the certificate at
 *        that chain index carried no status_request extension.
 *
 * @param ctx   [IN] TLS connection handle
 * @param list  [OUT] Peer OCSP response array (HITLS_OCSP_Resp * entries);
 *                    *list is NULL and *count is 0 when the peer sent no response
 * @param count [OUT] Number of entries in the array
 * @retval HITLS_SUCCESS, success.
 * @retval HITLS_NULL_INPUT, ctx, list or count is NULL.
 */
int32_t HITLS_GetPeerOcspResponseList(const HITLS_Ctx *ctx, HITLS_OCSP_Resp ***list, uint32_t *count);

/**
 * @ingroup hitls_status_request
 * @brief Set the OCSP responses to be stapled on the server. The array index
 *        matches the certificate chain depth: 0 is the EE certificate, 1 and
 *        above are intermediate CA certificates. A NULL entry means "no
 *        response for that certificate" and is skipped. The array is owned by
 *        the application and must stay alive until the handshake completes.
 *
 * @param ctx   [IN] TLS connection handle
 * @param list  [IN] OCSP response array (HITLS_OCSP_Resp * entries); NULL with
 *                   count 0 clears the previously set responses
 * @param count [IN] Number of entries in the array
 * @retval HITLS_SUCCESS, success.
 * @retval HITLS_NULL_INPUT, ctx is NULL.
 * @retval HITLS_INVALID_INPUT, list/count are inconsistent (NULL list with a
 *         non-zero count, a non-NULL list with count 0) or count exceeds the
 *         maximum supported number of entries.
 */
int32_t HITLS_SetOcspResponseList(HITLS_Ctx *ctx, HITLS_OCSP_Resp **list, uint32_t count);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_STATUS_REQUEST_H */
