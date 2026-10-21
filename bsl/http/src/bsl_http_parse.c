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

#include "hitls_build.h"
#ifdef HITLS_BSL_HTTP

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "bsl_errno.h"
#include "bsl_http_internal.h"

static bool IsHttpVersionLine(const char *line)
{
    /* HTTP-version = "HTTP/" DIGIT "." DIGIT (RFC 7230 Section 2.6); only the
     * HTTP/1.x family is accepted. The minor-version token after "HTTP/1." must
     * be digits: reject an empty, non-digit or trailing-garbage token (e.g.
     * "HTTP/1. 200", "HTTP/1.x" or "HTTP/1.1x"). */
    static const char prefix[] = "HTTP/1.";
    if (strncmp(line, prefix, sizeof(prefix) - 1) != 0) {
        return false;
    }
    const char *p = line + sizeof(prefix) - 1;
    if (!isdigit((unsigned char)*p)) {
        return false;
    }
    for (; *p != '\0' && !isspace((unsigned char)*p); p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    return true;
}

/* Parse the response status line (RFC 7230 Section 3.1.2):
 *   status-line = HTTP-version SP status-code SP reason-phrase
 * The version must start with "HTTP/1."; the status-code is 3DIGIT (000-999);
 * the reason-phrase is optional and its content is arbitrary - it is ignored
 * here. */
int32_t HttpParseStatusLine(char *line, uint32_t *statusCode)
{
    if (line == NULL || statusCode == NULL) {
        return BSL_HTTP_ERR_RESP_PARSE;
    }
    if (!IsHttpVersionLine(line)) {
        return BSL_HTTP_ERR_RESP_PARSE;
    }
    /* Skip the protocol version past the "HTTP/1." prefix to the first
     * whitespace, then to the status code. */
    char *p = line + sizeof("HTTP/1.") - 1;
    while (*p != '\0' && !isspace((unsigned char)*p)) {
        p++;
    }
    if (*p == '\0') {
        return BSL_HTTP_ERR_RESP_PARSE;
    }
    while (isspace((unsigned char)*p)) {
        p++;
    }
    if (*p == '\0') {
        return BSL_HTTP_ERR_RESP_PARSE;
    }
    /* Terminate the code token at the next whitespace (or at the line end,
     * which stands in for the CR/LF stripped by line extraction). Anything
     * after that whitespace is the reason phrase and is ignored. */
    char *codeStart = p;
    while (*p != '\0' && !isspace((unsigned char)*p)) {
        p++;
    }
    *p = '\0';
    /* The status-code is exactly 3DIGIT, i.e. three digits (RFC 7230
     * Section 3.1.2): check the token length before parsing, so "20",
     * "0200" and "2000" are rejected without a decimal conversion. */
    if (strlen(codeStart) != 3) {
        return BSL_HTTP_ERR_RESP_PARSE;
    }
    /* Reuse the decimal parser: the token must be all digits (no sign/leading
     * whitespace) and be consumed entirely - a non-whitespace character right
     * after the code (e.g. "200OK") is rejected by its end-of-string check. */
    uint32_t code = 0;
    if (HttpParseDecimal(codeStart, &code) != HITLS_HTTP_DECIMAL_PARSE_OK) {
        return BSL_HTTP_ERR_RESP_PARSE;
    }
    *statusCode = code;
    return HITLS_HTTP_STATUS_PARSE_OK;
}

int32_t HttpParseHeaderLine(char *line, const char **name, const char **value)
{
    if (line == NULL || name == NULL || value == NULL) {
        return BSL_HTTP_ERR_RESP_PARSE;
    }
    char *colon = strchr(line, ':');
    if (colon == NULL) {
        /* A header line without a colon is silently skipped. */
        return HITLS_HTTP_HEADER_PARSE_IGNORE;
    }
    *colon = '\0';
    if (line == colon) {
        /* RFC 7230 field-name must be a non-empty token; a line whose first
         * character is the colon (e.g. ": value") has an empty field name and
         * is dropped. */
        return HITLS_HTTP_HEADER_PARSE_IGNORE;
    }
    char *v = colon + 1;
    while (isspace((unsigned char)*v)) {
        v++;
    }
    if (*v == '\0') {
        /* Only whitespace follows the colon: skipping the leading whitespace
         * would consume the line terminator here and leave no value, so the
         * line is dropped without processing it. */
        return HITLS_HTTP_HEADER_PARSE_IGNORE;
    }
    /* Cut the value at the first CR/LF before comparing it. */
    char *vEnd = v;
    while (*vEnd != '\0' && *vEnd != '\r' && *vEnd != '\n') {
        vEnd++;
    }
    *vEnd = '\0';
    /* Strip trailing OWS (RFC 7230 Section 3.2.4: field-content excludes
     * trailing whitespace, so "Content-Length: 5 " is still 5). Only SP/HTAB
     * are stripped - trailing non-whitespace garbage (e.g. "5 x") still fails
     * the strict decimal/Content-Type checks below. */
    while (vEnd > v && (vEnd[-1] == ' ' || vEnd[-1] == '\t')) {
        vEnd--;
    }
    *vEnd = '\0';
    /* Whitespace before the colon is not removed: the raw field name is kept,
     * so such a line never matches a known header. */
    *name = line;
    *value = v;
    return HITLS_HTTP_HEADER_PARSE_OK;
}

int32_t HttpParseDecimal(const char *value, uint32_t *len)
{
    if (value == NULL || len == NULL) {
        return BSL_HTTP_ERR_RESP_PARSE;
    }
    /* HTTP numeric field values are 1*DIGIT (RFC 7230 Section 3.2.5): strtoul
     * would accept a sign or leading whitespace, so require a digit up front
     * (a leading '-' would otherwise wrap into a huge value on 32-bit). */
    if (!isdigit((unsigned char)value[0])) {
        return BSL_HTTP_ERR_RESP_PARSE;
    }
    /* strtoul base 10 with the whole string consumed. Garbage or a trailing
     * character after the digits is not. Trailing OWS is stripped by the
     * caller (HttpParseHeaderLine), so it never reaches this check. errno is
     * cleared first so the ERANGE check below reflects only this call
     * (strtoul leaves errno untouched on success; a stale ERANGE from an
     * earlier library call would otherwise reject a valid value as an
     * overflow). */
    int savedErrno = errno;
    errno = 0;
    char *end = NULL;
    unsigned long num = strtoul(value, &end, 10);
    /* strtoul signals an overflow with ERANGE; it must be captured before the
     * caller's errno is restored (on a 32-bit unsigned long, an overflow of
     * UINT32_MAX+1 otherwise wraps to UINT32_MAX and slips past the range check). */
    bool overflow = (errno == ERANGE);
    errno = savedErrno;
    if (overflow || end == value || *end != '\0' || num > UINT32_MAX) {
        return BSL_HTTP_ERR_RESP_PARSE;
    }
    *len = (uint32_t)num;
    return HITLS_HTTP_DECIMAL_PARSE_OK;
}

#endif /* HITLS_BSL_HTTP */
