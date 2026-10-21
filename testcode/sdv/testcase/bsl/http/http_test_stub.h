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

#ifndef HTTP_TEST_STUB_H
#define HTTP_TEST_STUB_H

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "bsl_uio.h"
#include "uio_base.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_http.h"
#include "bsl_http_internal.h"

#if defined(__GNUC__) || defined(__clang__)
#define HTTP_TEST_UNUSED __attribute__((unused))
#else
#define HTTP_TEST_UNUSED
#endif

#define HTTP_TEST_WRITE_BUF_SIZE 65536

static uint8_t HTTP_TEST_UNUSED g_httpWriteBuf[HTTP_TEST_WRITE_BUF_SIZE];
static uint32_t HTTP_TEST_UNUSED g_httpWriteLen;
static int32_t HTTP_TEST_UNUSED g_httpWriteRet;
static uint32_t HTTP_TEST_UNUSED g_httpMaxWrite;
static int32_t HTTP_TEST_UNUSED g_httpWriteBlockFirst;

static const uint8_t *HTTP_TEST_UNUSED g_httpRespData;
static uint32_t HTTP_TEST_UNUSED g_httpRespLen;
static uint32_t HTTP_TEST_UNUSED g_httpRespRead;
static int32_t HTTP_TEST_UNUSED g_httpReadRet;
static uint32_t HTTP_TEST_UNUSED g_httpMaxRead;
static int32_t HTTP_TEST_UNUSED g_httpEof;
static int32_t HTTP_TEST_UNUSED g_httpReadBlockFirst;

static int32_t HTTP_TEST_UNUSED g_httpFlushRet;

static void HTTP_TEST_UNUSED HttpTestReset(void)
{
    g_httpWriteLen = 0;
    g_httpWriteRet = BSL_SUCCESS;
    g_httpMaxWrite = 0;
    g_httpWriteBlockFirst = 0;
    g_httpRespData = NULL;
    g_httpRespLen = 0;
    g_httpRespRead = 0;
    g_httpReadRet = BSL_SUCCESS;
    g_httpMaxRead = 0;
    g_httpEof = 0;
    g_httpReadBlockFirst = 0;
    g_httpFlushRet = BSL_SUCCESS;
}

static int32_t HTTP_TEST_UNUSED HttpTestStubWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    (void)uio;
    *writeLen = 0;
    if (g_httpWriteRet != BSL_SUCCESS) {
        return g_httpWriteRet;
    }
    if (g_httpWriteBlockFirst) {
        g_httpWriteBlockFirst = 0;
        return BSL_SUCCESS;
    }
    uint32_t w = len;
    if (g_httpMaxWrite != 0 && w > g_httpMaxWrite) {
        w = g_httpMaxWrite;
    }
    if (w == 0) {
        return BSL_SUCCESS;
    }
    if (g_httpWriteLen + w > HTTP_TEST_WRITE_BUF_SIZE) {
        return BSL_UIO_IO_EXCEPTION;
    }
    (void)memcpy(g_httpWriteBuf + g_httpWriteLen, buf, w);
    g_httpWriteLen += w;
    *writeLen = w;
    return BSL_SUCCESS;
}

static int32_t HTTP_TEST_UNUSED HttpTestStubRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    (void)uio;
    *readLen = 0;
    if (g_httpReadRet != BSL_SUCCESS) {
        return g_httpReadRet;
    }
    if (g_httpReadBlockFirst) {
        g_httpReadBlockFirst = 0;
        return BSL_SUCCESS;
    }
    uint32_t r = g_httpRespLen - g_httpRespRead;
    if (r > len) {
        r = len;
    }
    if (g_httpMaxRead != 0 && r > g_httpMaxRead) {
        r = g_httpMaxRead;
    }
    if (r == 0) {
        if (g_httpEof != 0) {
            return BSL_UIO_IO_EOF;
        }
        return BSL_SUCCESS;
    }
    (void)memcpy(buf, g_httpRespData + g_httpRespRead, r);
    g_httpRespRead += r;
    *readLen = r;
    return BSL_SUCCESS;
}

static int32_t HTTP_TEST_UNUSED HttpTestStubCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    (void)uio;
    (void)larg;
    (void)parg;
    if (cmd == BSL_UIO_FLUSH) {
        return g_httpFlushRet;
    }
    return BSL_UIO_FAIL;
}

static BSL_UIO *HTTP_TEST_UNUSED HttpTestNewUio(void)
{
    BSL_UIO_Method m;
    (void)memset(&m, 0, sizeof(m));
    m.uioType = BSL_UIO_TCP;
    m.uioWrite = HttpTestStubWrite;
    m.uioRead = HttpTestStubRead;
    m.uioCtrl = HttpTestStubCtrl;
    BSL_UIO *uio = BSL_UIO_New(&m);
    if (uio != NULL) {
        BSL_UIO_SetInit(uio, true);
    }
    return uio;
}

static void HTTP_TEST_UNUSED HttpTestSetResponse(const char *resp)
{
    g_httpRespData = (const uint8_t *)resp;
    g_httpRespLen = (uint32_t)strlen(resp);
    g_httpRespRead = 0;
}

static void HTTP_TEST_UNUSED HttpTestSetResponseBuf(const uint8_t *data, uint32_t len)
{
    g_httpRespData = data;
    g_httpRespLen = len;
    g_httpRespRead = 0;
}

static bool HTTP_TEST_UNUSED HttpTestWrittenContains(const char *needle)
{
    if (g_httpWriteLen == 0) {
        return false;
    }
    /* The NUL terminator needs a free byte past the written data; an exactly
     * full buffer (65536) cannot be searched in place. */
    if (g_httpWriteLen >= HTTP_TEST_WRITE_BUF_SIZE) {
        return false;
    }
    g_httpWriteBuf[g_httpWriteLen] = '\0';
    return strstr((const char *)g_httpWriteBuf, needle) != NULL;
}

/* Mirror of the internal BSL_BufMem (same layout: { size_t length; char *data;
 * size_t max; }) so the request header can be read without an internal header. */
typedef struct {
    size_t length;
    char *data;
    size_t max;
} HttpTestBufMem;

/* Test accessor for the accumulated request header (request line + headers +
 * Content-Type/Content-Length), returning the raw bytes and their length. The
 * buffer is NOT NUL-terminated: search it with HttpTestHdrContains, not strstr. */
static const uint8_t *HTTP_TEST_UNUSED HttpTestGetReqHdr(const HITLS_HTTP_ReqCtx *ctx, uint32_t *len)
{
    if (ctx == NULL || ctx->reqHdrMem == NULL || len == NULL) {
        return NULL;
    }
    HttpTestBufMem *bm = NULL;
    if (BSL_UIO_Ctrl(ctx->reqHdrMem, BSL_UIO_MEM_GET_PTR, (int32_t)sizeof(HttpTestBufMem *), &bm) != BSL_SUCCESS ||
        bm == NULL) {
        return NULL;
    }
    *len = (uint32_t)bm->length;
    return (const uint8_t *)bm->data;
}

/* Bounded substring search over the non-NUL-terminated request header. */
static bool HTTP_TEST_UNUSED HttpTestHdrContains(const char *hdr, uint32_t hdrLen, const char *needle)
{
    uint32_t needleLen = (uint32_t)strlen(needle);
    if (needleLen == 0) {
        return true;
    }
    if (needleLen > hdrLen) {
        return false;
    }
    for (uint32_t i = 0; i + needleLen <= hdrLen; i++) {
        if (memcmp(hdr + i, needle, needleLen) == 0) {
            return true;
        }
    }
    return false;
}

#endif /* HTTP_TEST_STUB_H */
