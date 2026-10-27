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

#ifndef BSL_HTTP_INTERNAL_H
#define BSL_HTTP_INTERNAL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_HTTP

#include <stdint.h>
#include "bsl_http.h"
#include "bsl_uio.h"
#include "bsl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum length of a single response header line. */
#define HITLS_HTTP_MAX_LINE_LEN 4096
#define HITLS_HTTP_MIN_LINE_LEN 256
/* Chunk size used when filling the response header line buffer and reading the
 * response body into the memory UIO. */
#define HITLS_HTTP_READ_CHUNK 256
/* Defaults for the SET_MAX_RESP_LEN / SET_MAX_RESP_HDR_LINES controls (the
 * public header documents them in the HITLS_HTTP_CtrlCmd enum comments). */
#define HITLS_HTTP_DEFAULT_MAX_RESP_LEN       (100 * 1024)
#define HITLS_HTTP_DEFAULT_MAX_RESP_HDR_LINES 256
/* Request-side length limits. */
#define HITLS_HTTP_MAX_PATH_LEN         1024
#define HITLS_HTTP_MAX_CONTENT_TYPE_LEN 128
#define HITLS_HTTP_MAX_HDR_NAME_LEN     128
#define HITLS_HTTP_MAX_HDR_VALUE_LEN    4096

typedef enum {
    /* Configuration phase: headers and transfer settings may be changed. Exchange
     * leaves this state as soon as it is called. */
    HITLS_HTTP_STATE_INIT = 0,
    HITLS_HTTP_STATE_WRITE_HDR = 1,
    HITLS_HTTP_STATE_WRITE_REQ = 2,
    HITLS_HTTP_STATE_FLUSH = 3,
    HITLS_HTTP_STATE_READ_HDR = 4,
    HITLS_HTTP_STATE_READ_BODY = 5,
    HITLS_HTTP_STATE_DONE = 6,
    /* Terminal error state: the error was pushed once, later calls return it again unchanged. */
    HITLS_HTTP_STATE_ERROR = 7,
} HITLS_HTTP_State;

struct HITLS_HTTP_ReqCtx_St {
    /* Core I/O. */
    BSL_UIO *uio; /* UIO handle (ownership stays with the caller). */
    int32_t method; /* Request method (HITLS_HTTP_METHOD_POST only for now). */
    char *path; /* Request path. */

    /* Limits and expectations. */
    uint32_t maxRespLen; /* Max response body size (default 100KB). */
    uint32_t maxHdrLines; /* Max response header lines (default 256). */
    uint32_t maxLineLen; /* Max response line length (default 4KB, settable [MIN, MAX]). */
    int64_t deadline; /* Absolute transfer deadline as UTC seconds (0 = no deadline). */
    char *expectedCt; /* Expected Content-Type (NULL = skip check). */

    /* Request side (send). */
    BSL_UIO *reqHdrMem; /* Request header memory UIO (request line + headers + CT/CL). */
    BSL_Buffer reqBody; /* Request body (data, dataLen). */
    uint32_t reqHdrSent; /* Bytes of the request header already written to the uio. */
    uint32_t reqBodySent; /* Bytes of the request body already written to the uio. */
    uint32_t reqHdrCount; /* Number of custom request headers added. */
    uint32_t reqSet; /* 1 once SetReq has been called. */
    uint32_t hdrTerminated; /* 1 once the request header has been terminated (blank line appended). */

    /* Response side (receive). */
    BSL_UIO *respMem; /* Response body memory UIO (grown by the mem UIO, capped at maxRespLen). */
    uint32_t respBodyLen; /* Bytes accumulated in respMem. */
    uint32_t respStatusCode; /* Parsed numeric HTTP status code. */
    uint32_t hdrLineCount; /* Response header lines seen. */
    uint32_t firstHdrLine; /* 1 while the status line has not been parsed. */
    uint32_t hasContentLength; /* 1 once a Content-Length was received. */
    uint32_t respContentLength; /* Declared response body length. */
    char *respCt; /* Response Content-Type value (deep copy). */
    uint8_t *lineBuf; /* Response line buffer, allocated to maxLineLen. */
    uint32_t lineBufLen; /* Bytes valid in lineBuf. */
    uint32_t lineConsumed; /* Bytes of the line at the start of lineBuf, counted through its '\n'. */

    /* State machine. */
    HITLS_HTTP_State state;
    int32_t errCode; /* Latched error code returned by later HITLS_HTTP_ReqCtxExchange calls. */
};

/* HITLS_HTTP_STATUS_PARSE_OK: HttpParseStatusLine succeeded. HITLS_HTTP_STATUS_OK: HTTP 200. */
#define HITLS_HTTP_STATUS_PARSE_OK 0
#define HITLS_HTTP_STATUS_OK       200

/**
 * @brief Validate and parse the HTTP status line. Must start with "HTTP/1.";
 *        the code is parsed with strtoul and the whole code token must be
 *        decimal.
 * @param line       [IN] NUL-terminated status line (modified in place).
 * @param statusCode [OUT] Parsed numeric status code.
 * @retval HITLS_HTTP_STATUS_PARSE_OK on success, error code on failure.
 */
int32_t HttpParseStatusLine(char *line, uint32_t *statusCode);

/**
 * @brief Split a header line into name and value at the first ':'. The field
 *        name is taken raw (whitespace before the colon prevents a match with
 *        known headers); leading whitespace after the colon is skipped, the
 *        value's trailing OWS is stripped (RFC 7230 Section 3.2.4) and the
 *        value is cut at the first CR/LF.
 * @param line  [IN] NUL-terminated header line (modified in place).
 * @param name  [OUT] Pointer to the header name (within line).
 * @param value [OUT] Pointer to the header value (within line).
 * @retval HITLS_HTTP_HEADER_PARSE_OK on success, HITLS_HTTP_HEADER_PARSE_IGNORE
 *         when the line has no ':' or only whitespace after the colon (the
 *         caller must skip such lines), HITLS_HTTP_HEADER_PARSE_ERR on a
 *         malformed line (e.g. obs-fold, RFC 7230 §3.2.4), error code on
 *         NULL input.
 */
#define HITLS_HTTP_HEADER_PARSE_OK     0
#define HITLS_HTTP_HEADER_PARSE_IGNORE 1
#define HITLS_HTTP_HEADER_PARSE_ERR    (-1)
int32_t HttpParseHeaderLine(char *line, const char **name, const char **value);

/**
 * @brief Parse a decimal string into a uint32_t with strtoul base 10
 *        semantics: the first character must be a digit (a leading sign or
 *        whitespace is rejected) and the whole string must be consumed; a
 *        trailing character after the digits is not. Trailing OWS is expected
 *        to have been stripped by the caller (HttpParseHeaderLine).
 * @param value [IN] NUL-terminated decimal string.
 * @param len   [OUT] Parsed value.
 * @retval 0 on success, error code on empty/garbled/out-of-range input.
 */
#define HITLS_HTTP_DECIMAL_PARSE_OK 0
int32_t HttpParseDecimal(const char *value, uint32_t *len);

/**
 * @brief Return the accumulated response body bytes (deep view into the response
 *        body memory UIO) and their length. NULL/0 until the body has been read.
 * @param ctx [IN] Context.
 * @param len [OUT] Length of the returned bytes.
 * @retval Pointer into the ctx response body memory UIO (valid until the ctx is
 *         freed), or NULL on error / empty body.
 */
const uint8_t *HttpGetRespBody(const HITLS_HTTP_ReqCtx *ctx, uint32_t *len);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_HTTP */
#endif /* BSL_HTTP_INTERNAL_H */
