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
 * @defgroup bsl_http HTTP Client
 * @ingroup bsl
 * @brief Generic HTTP/1.x client (request construction, send/receive state machine,
 *        response parsing and security limits). Used by the OCSP-HTTP adapter layer.
 */

#ifndef BSL_HTTP_H
#define BSL_HTTP_H

#include <stdint.h>
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup bsl_http */
typedef struct HITLS_HTTP_ReqCtx_St HITLS_HTTP_ReqCtx;

/**
 * @ingroup bsl_http
 * @brief HTTP request methods supported by the client. Only POST is currently
 *        supported; other methods (e.g. GET) can be added later by extending
 *        this enum, widening the check in HITLS_HTTP_ReqCtxNew and extending
 *        the request-line formatting.
 */
typedef enum {
    HITLS_HTTP_METHOD_POST = 0,
} HITLS_HTTP_Method;

/**
 * @ingroup bsl_http
 * @brief Ctrl commands for HITLS_HTTP_ReqCtx.
 */
typedef enum {
    HITLS_HTTP_CTRL_SET_MAX_RESP_LEN = 0x0100, /**< val = uint32_t*, set max response body size.
                                                    Default 100KB; 0 rejected; max UINT32_MAX. */
    HITLS_HTTP_CTRL_GET_MAX_RESP_LEN, /**< val = uint32_t*, get max response body size. */
    HITLS_HTTP_CTRL_SET_MAX_RESP_HDR_LINES, /**< val = uint32_t*, set max response header lines.
                                                    Default 256; 0 rejected; max UINT32_MAX. */
    HITLS_HTTP_CTRL_GET_MAX_RESP_HDR_LINES, /**< val = uint32_t*, get max response header lines. */
    HITLS_HTTP_CTRL_SET_MAX_LINE_LEN, /**< val = uint32_t*, set max response line length.
                                                    Default 4096; range [256, 4096]. */
    HITLS_HTTP_CTRL_GET_MAX_LINE_LEN, /**< val = uint32_t*, get max response line length. */
    HITLS_HTTP_CTRL_SET_EXP_CONTENT_TYPE, /**< val = const char* (valLen = 0), expected Content-Type
                                                              (NULL = skip check; max 128 chars). */
    HITLS_HTTP_CTRL_SET_TIMEOUT, /**< val = uint32_t*, transfer deadline in seconds; 0 disables it. */
    HITLS_HTTP_CTRL_GET_RESP_STATUS, /**< val = uint32_t*, get the HTTP response status code
                                        (valid after the status line was parsed). */
} HITLS_HTTP_CtrlCmd;

/**
 * @brief Create the HTTP request context. A memory UIO is initialized for the
 *        request header: the request line and headers added via
 *        HITLS_HTTP_ReqCtxAddHeader are accumulated there and sent at the first
 *        HITLS_HTTP_ReqCtxExchange call.
 * @param uio    [IN] Connected UIO handle (TCP).
 * @param method [IN] HTTP method; only HITLS_HTTP_METHOD_POST is currently
 *                    accepted (other methods are reserved for future extension
 *                    and are rejected).
 * @param path   [IN] Request path (e.g. "/responder/ocsp", must be non-empty;
 *                    an empty path would produce a malformed request line).
 * @retval HITLS_HTTP_ReqCtx * on success, NULL on failure (uio/path is NULL, path is empty,
 *         an unsupported method, or OOM).
 * @note No Host header is sent by default (HTTP/1.0, RFC 1945); set one with
 *       HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", ...) before the transfer when needed.
 */
HITLS_HTTP_ReqCtx *HITLS_HTTP_ReqCtxNew(BSL_UIO *uio, int32_t method, const char *path);

/**
 * @brief Free the context.
 * @param ctx [IN] Context to free (NULL safe). uio is managed by the caller.
 */
void HITLS_HTTP_ReqCtxFree(HITLS_HTTP_ReqCtx *ctx);

/**
 * @brief Set the request body and append its framing headers (Content-Type and
 *        Content-Length) to the request header memory UIO. Custom headers added
 *        with HITLS_HTTP_ReqCtxAddHeader are order-independent: they may be
 *        added before or after this call, all before the transfer starts.
 *        Can be called only once, before the transfer starts; a repeated call
 *        (the request body cannot be replaced) is rejected.
 * @param ctx         [IN] Context.
 * @param contentType [IN] Content-Type (e.g. "application/ocsp-request").
 * @param req         [IN] Request body data (DER encoded); may be NULL for an empty body.
 * @param reqLen      [IN] Request body length (must be 0 when req is NULL).
 * @retval BSL_SUCCESS / error code.
 */
int32_t HITLS_HTTP_ReqCtxSetReq(HITLS_HTTP_ReqCtx *ctx, const char *contentType, const uint8_t *req, uint32_t reqLen);

/**
 * @brief Add a custom request header, written directly into the request header
 *        memory UIO. Order-independent with HITLS_HTTP_ReqCtxSetReq (may be
 *        called before or after it), but only while the context is in the INIT
 *        (configuration) state, i.e. before the first HITLS_HTTP_ReqCtxExchange call.
 *        The Host header is added here like any other header (no Host header is
 *        sent unless it is added). Reserved headers (Content-Type/Content-Length
 *        generated internally, plus Transfer-Encoding/Connection which would
 *        conflict with the fixed Content-Length + raw body framing) are rejected.
 *        The count shares the max_hdr_lines limit (default 256), which also caps
 *        the response header lines.
 * @param ctx   [IN] Context.
 * @param name  [IN] Header name, must be a valid RFC 7230 token (e.g. "Accept").
 * @param value [IN] Header value (e.g. "application/ocsp-response").
 * @retval BSL_SUCCESS / error code (invalid parameter / header count overflow).
 */
int32_t HITLS_HTTP_ReqCtxAddHeader(HITLS_HTTP_ReqCtx *ctx, const char *name, const char *value);

/**
 * @brief Drive the HTTP send/receive state machine.
 * @param ctx       [IN] Context.
 * @param respBody  [OUT] Response body (filled when ret == BSL_SUCCESS as a shallow reference into the ctx
 *                        internal buffer whose lifetime follows ctx; NULL when the body is empty.
 *                        Must be non-NULL with *respBody == NULL on input).
 * @param respLen   [OUT] Response body length (filled when ret == BSL_SUCCESS. Must be non-NULL
 *                        with *respLen == 0 on input).
 * @retval BSL_SUCCESS = complete (respBody/respLen filled).
 * @retval BSL_HTTP_ERR_IN_PROGRESS = in progress (non-blocking I/O, retry).
 * @retval BSL_HTTP_ERR_RESP_STATUS = the response status code is not 200 (the
 *         transfer stops at the status line; the code is available via
 *         HITLS_HTTP_CTRL_GET_RESP_STATUS).
 * @retval BSL_HTTP_ERR_PARAM / _IO / _RESP_PARSE / _RESP_HDR_LINES / _RESP_TOO_LARGE / _CONTENT_TYPE /
 *         _STATE / BSL_MALLOC_FAIL = error (pushed once; later calls return the same code unchanged).
 *         BSL_HTTP_ERR_PARAM is also returned when *respBody is non-NULL or *respLen is non-zero on input.
 * @retval BSL_HTTP_ERR_REQ_NOT_SET = the request body has not been set with
 *         HITLS_HTTP_ReqCtxSetReq yet (a POST always carries a body).
 * @note When ret == BSL_SUCCESS, *respBody points to the ctx internal buffer (shallow reference).
 *       When ret != BSL_SUCCESS, *respBody = NULL, *respLen = 0.
 */
int32_t HITLS_HTTP_ReqCtxExchange(HITLS_HTTP_ReqCtx *ctx, const uint8_t **respBody, uint32_t *respLen);

/**
 * @brief Ctrl command dispatch: set/get security limits and expected Content-Type.
 *        SET_* commands (HITLS_HTTP_CTRL_SET_MAX_RESP_LEN, _SET_MAX_RESP_HDR_LINES,
 *        _SET_MAX_LINE_LEN, _SET_EXP_CONTENT_TYPE, _SET_TIMEOUT) apply only while the
 *        context is in the INIT (configuration) state, before the first
 *        HITLS_HTTP_ReqCtxExchange call; the GET_* commands may be called at any time.
 * @param ctx    [IN] Context.
 * @param cmd    [IN] Ctrl command (see HITLS_HTTP_CtrlCmd).
 * @param val    [IN/OUT] Data pointer (type depends on cmd).
 * @param valLen [IN] Data length.
 * @retval BSL_SUCCESS / error code.
 */
int32_t HITLS_HTTP_ReqCtxCtrl(HITLS_HTTP_ReqCtx *ctx, int32_t cmd, void *val, uint32_t valLen);

#ifdef __cplusplus
}
#endif

#endif /* BSL_HTTP_H */
