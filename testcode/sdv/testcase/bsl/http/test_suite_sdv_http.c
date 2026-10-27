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

/* BEGIN_HEADER */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "bsl_http.h"
#include "bsl_http_internal.h"
#include "http_test_stub.h"
#include "stub_utils.h"
STUB_DEFINE_RET2(void *, BSL_SAL_Calloc, uint32_t, uint32_t);
static uint32_t g_callocFailNext;
static void *STUB_BSL_SAL_Calloc(uint32_t num, uint32_t size)
{
    if (g_callocFailNext > 0) {
        g_callocFailNext--;
        return NULL;
    }
    return get_real_BSL_SAL_Calloc()(num, size);
}

/* END_HEADER */

static const char RESP_OK[] = "HTTP/1.0 200 OK\r\n"
                              "Content-Type: application/ocsp-response\r\n"
                              "Content-Length: 5\r\n"
                              "\r\n"
                              "12345";

static const char RESP_DUP_CT_SAME[] = "HTTP/1.0 200 OK\r\n"
                                       "Content-Type: application/ocsp-response\r\n"
                                       "Content-Type: application/ocsp-response\r\n"
                                       "Content-Length: 5\r\n"
                                       "\r\n"
                                       "12345";

static const char RESP_DUP_CT_DIFF[] = "HTTP/1.0 200 OK\r\n"
                                       "Content-Type: application/ocsp-response\r\n"
                                       "Content-Type: text/plain\r\n"
                                       "Content-Length: 5\r\n"
                                       "\r\n"
                                       "12345";

static const char RESP_CT_MISMATCH[] = "HTTP/1.0 200 OK\r\n"
                                       "Content-Type: text/html\r\n"
                                       "Content-Length: 5\r\n"
                                       "\r\n"
                                       "12345";

static const char RESP_HTTP11[] = "HTTP/1.1 200 OK\r\n"
                                  "Content-Type: application/ocsp-response\r\n"
                                  "Content-Length: 5\r\n"
                                  "\r\n"
                                  "12345";

static const char RESP_MALFORMED[] = "INVALID 200 OK\r\n"
                                     "Content-Length: 5\r\n"
                                     "\r\n"
                                     "12345";

/* RFC 7230 §3.2.4 obs-fold: a continuation header line starting with SP/HTAB. */
static const char RESP_OBSFOLD[] = "HTTP/1.0 200 OK\r\n"
                                   "Content-Type: application/ocsp-response\r\n"
                                   "  Content-Length: 5\r\n"
                                   "\r\n"
                                   "12345";

static const char RESP_STATUS_SIGNED[] = "HTTP/1.0 +200 OK\r\n"
                                         "Content-Length: 5\r\n"
                                         "\r\n"
                                         "12345";

static const char RESP_STATUS_TRAILING[] = "HTTP/1.0 200OK\r\n"
                                           "Content-Length: 5\r\n"
                                           "\r\n"
                                           "12345";

static const char RESP_STATUS_LEADING_ZERO[] = "HTTP/1.0 0200 OK\r\n"
                                               "Content-Length: 5\r\n"
                                               "\r\n"
                                               "12345";

static const char RESP_STATUS_4DIGIT[] = "HTTP/1.0 2000 OK\r\n"
                                         "Content-Length: 5\r\n"
                                         "\r\n"
                                         "12345";

static const char RESP_CHUNKED[] = "HTTP/1.1 200 OK\r\n"
                                   "Transfer-Encoding: chunked\r\n"
                                   "\r\n"
                                   "5\r\n12345\r\n0\r\n\r\n";

static const char RESP_TE_IDENTITY[] = "HTTP/1.1 200 OK\r\n"
                                       "Transfer-Encoding: identity\r\n"
                                       "Content-Length: 5\r\n"
                                       "\r\n"
                                       "12345";

static const char RESP_REDIRECT[] = "HTTP/1.1 302 Found\r\n"
                                    "Location: /other\r\n"
                                    "Content-Length: 0\r\n"
                                    "\r\n";

static const char RESP_500_TEXT[] = "HTTP/1.1 500 Internal Server Error\r\n"
                                    "Content-Type: text/html\r\n"
                                    "Content-Length: 5\r\n"
                                    "\r\n"
                                    "error";

/* Drive Exchange until completion/error; return the final ret, out params and the
 * number of BSL_HTTP_ERR_IN_PROGRESS returns. */
static int32_t HttpTestDrive(HITLS_HTTP_ReqCtx *ctx, const uint8_t **body, uint32_t *len, uint32_t *progressCount)
{
    uint32_t count = 0;
    for (;;) {
        const uint8_t *b = NULL;
        uint32_t l = 0;
        int32_t ret = HITLS_HTTP_ReqCtxExchange(ctx, &b, &l);
        if (ret == BSL_HTTP_ERR_IN_PROGRESS) {
            count++;
            continue;
        }
        if (body != NULL) {
            *body = b;
        }
        if (len != NULL) {
            *len = l;
        }
        if (progressCount != NULL) {
            *progressCount = count;
        }
        return ret;
    }
}

/**
 * @test  SDV_BSL_HTTP_CTX_TC001
 * @title  ReqCtxNew main path
 * @precon  nan
 * @brief
 *    1. Create a stub uio.
 *    2. Call HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp"). Expected result 2 is obtained.
 * @expect
 *    1. The uio is created successfully.
 *    2. Return a non-NULL context whose request line is accumulated, security limits are the
 *       defaults and the state is INIT.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC001(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(ctx->state, HITLS_HTTP_STATE_INIT);
    ASSERT_EQ(ctx->maxRespLen, HITLS_HTTP_DEFAULT_MAX_RESP_LEN);
    ASSERT_EQ(ctx->maxHdrLines, HITLS_HTTP_DEFAULT_MAX_RESP_HDR_LINES);
    ASSERT_TRUE(strcmp(ctx->path, "/responder/ocsp") == 0);
    uint32_t hdrLen = 0;
    const char *hdr = (const char *)HttpTestGetReqHdr(ctx, &hdrLen);
    ASSERT_TRUE(hdr != NULL);
    ASSERT_TRUE(HttpTestHdrContains(hdr, hdrLen, "POST /responder/ocsp HTTP/1.0\r\n"));
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
    ASSERT_TRUE(true);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC002
 * @title  ReqCtxNew with uio NULL
 * @precon  nan
 * @brief
 *    1. Call HITLS_HTTP_ReqCtxNew(NULL, HITLS_HTTP_METHOD_POST, "/responder/ocsp").
 * @expect
 *    1. Return NULL.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC002(void)
{
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(NULL, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx == NULL);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC003
 * @title  ReqCtxNew with path NULL
 * @precon  nan
 * @brief
 *    1. Create a stub uio.
 *    2. Call HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, NULL).
 * @expect
 *    1. The uio is created successfully.
 *    2. Return NULL.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC003(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, NULL);
    ASSERT_TRUE(ctx == NULL);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC004
 * @title  ReqCtxNew with memory allocation failure
 * @precon  nan
 * @brief
 *    1. Create a stub uio.
 *    2. Make the first BSL_SAL_Calloc fail.
 *    3. Call HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp").
 * @expect
 *    1. The uio is created successfully.
 *    2. The first allocation fails.
 *    3. Return NULL.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC004(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    STUB_REPLACE(BSL_SAL_Calloc, STUB_BSL_SAL_Calloc);
    g_callocFailNext = 1;
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    STUB_RESTORE(BSL_SAL_Calloc);
    ASSERT_TRUE(ctx == NULL);
    BSL_UIO_Free(uio);
EXIT:
    STUB_RESTORE(BSL_SAL_Calloc);
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC005
 * @title  SetReq main path
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxSetReq with a 100-byte request body.
 * @expect
 *    1. The context is created successfully.
 *    2. Return 0 and the request header contains Content-Length: 100 and the request line,
 *       but no Host header (none was set).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC005(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint8_t der[100];
    (void)memset(der, 0xAB, sizeof(der));
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", der, sizeof(der));
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint32_t hdrLen = 0;
    const char *hdr = (const char *)HttpTestGetReqHdr(ctx, &hdrLen);
    ASSERT_TRUE(hdr != NULL);
    ASSERT_TRUE(HttpTestHdrContains(hdr, hdrLen, "POST /responder/ocsp HTTP/1.0\r\n"));
    ASSERT_TRUE(HttpTestHdrContains(hdr, hdrLen, "Content-Type: application/ocsp-request\r\n"));
    ASSERT_TRUE(HttpTestHdrContains(hdr, hdrLen, "Content-Length: 100\r\n"));
    /* No Host header is emitted unless set explicitly. */
    ASSERT_TRUE(!HttpTestHdrContains(hdr, hdrLen, "Host:"));
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC006
 * @title  SetReq with an empty request body
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxSetReq with a NULL body of length 0.
 * @expect
 *    1. The context is created successfully.
 *    2. Return 0 and the request header contains Content-Length: 0.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC006(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint32_t hdrLen = 0;
    const char *hdr = (const char *)HttpTestGetReqHdr(ctx, &hdrLen);
    ASSERT_TRUE(hdr != NULL);
    ASSERT_TRUE(HttpTestHdrContains(hdr, hdrLen, "Content-Length: 0\r\n"));
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC007
 * @title  SetReq with ctx NULL
 * @precon  nan
 * @brief
 *    1. Call HITLS_HTTP_ReqCtxSetReq(NULL, "application/ocsp-request", data, 100).
 * @expect
 *    1. Return a non-zero parameter error.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC007(void)
{
    uint8_t der[100];
    (void)memset(der, 0xAB, sizeof(der));
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(NULL, "application/ocsp-request", der, sizeof(der));
    ASSERT_NE(ret, BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC008
 * @title  SetReq with contentType NULL
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxSetReq(ctx, NULL, data, 100).
 * @expect
 *    1. The context is created successfully.
 *    2. Return a non-zero parameter error.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC008(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint8_t der[100];
    (void)memset(der, 0xAB, sizeof(der));
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, NULL, der, sizeof(der));
    ASSERT_NE(ret, BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC025
 * @title  ReqCtxFree main path
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Free the context.
 *    3. Verify that the uio remains usable.
 * @expect
 *    1. The context is created and configured successfully.
 *    2. No crash and all internal buffers are released.
 *    3. The uio can still be written to.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC025(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint8_t der[16];
    (void)memset(der, 0xCD, sizeof(der));
    (void)HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", der, sizeof(der));
    HITLS_HTTP_ReqCtxFree(ctx);
    uint32_t writeLen = 0;
    int32_t ret = BSL_UIO_Write(uio, "x", 1, &writeLen);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(writeLen, 1);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC026
 * @title  ReqCtxFree with ctx NULL
 * @precon  nan
 * @brief
 *    1. Call HITLS_HTTP_ReqCtxFree(NULL).
 * @expect
 *    1. No operation and no crash.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC026(void)
{
    HITLS_HTTP_ReqCtxFree(NULL);
    ASSERT_TRUE(true);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC027
 * @title  ReqCtxNew rejects an over-long path
 * @precon  nan
 * @brief
 *    1. Create a stub uio.
 *    2. Call HITLS_HTTP_ReqCtxNew with a path longer than the limit.
 * @expect
 *    1. The uio is created successfully.
 *    2. Return NULL.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC027(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    char longPath[HITLS_HTTP_MAX_PATH_LEN + 32];
    (void)memset(longPath, 'a', sizeof(longPath) - 1);
    longPath[sizeof(longPath) - 1] = '\0';
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, longPath);
    ASSERT_TRUE(ctx == NULL);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC028
 * @title  SetReq rejects an over-long Content-Type
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxSetReq with a Content-Type longer than the limit.
 * @expect
 *    1. The context is created successfully.
 *    2. Return a non-zero parameter error.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC028(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    char longCt[HITLS_HTTP_MAX_CONTENT_TYPE_LEN + 32];
    (void)memset(longCt, 'b', sizeof(longCt) - 1);
    longCt[sizeof(longCt) - 1] = '\0';
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, longCt, NULL, 0);
    ASSERT_NE(ret, BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC001
 * @title  AddHeader main path
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxAddHeader(ctx, "Accept", "application/ocsp-response").
 *    3. Call HITLS_HTTP_ReqCtxSetReq and inspect the request header buffer.
 * @expect
 *    1. The context is created successfully.
 *    2. Return 0.
 *    3. The request header contains the custom Accept header.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC001(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxAddHeader(ctx, "Accept", "application/ocsp-response");
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint32_t hdrLen = 0;
    const char *hdr = (const char *)HttpTestGetReqHdr(ctx, &hdrLen);
    ASSERT_TRUE(hdr != NULL);
    ASSERT_TRUE(HttpTestHdrContains(hdr, hdrLen, "Accept: application/ocsp-response\r\n"));
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC002
 * @title  AddHeader with NULL parameters
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxAddHeader(NULL, "Accept", "x"), then with name NULL,
 *       then with value NULL.
 * @expect
 *    1. The context is created successfully.
 *    2. All calls return a non-zero parameter error.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC002(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxAddHeader(NULL, "Accept", "x");
    ASSERT_NE(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxAddHeader(ctx, NULL, "x");
    ASSERT_NE(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxAddHeader(ctx, "Accept", NULL);
    ASSERT_NE(ret, BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC003
 * @title  AddHeader rejects framing headers but accepts Host
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxAddHeader with "Host", "Content-Type" and
 *       "Content-Length" as header names.
 * @expect
 *    1. The context is created successfully.
 *    2. "Host" is accepted (a normal header); "Content-Type"/"Content-Length"
 *       are rejected with a non-zero parameter error.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC003(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", "evil.com"), BSL_SUCCESS);
    ASSERT_NE(HITLS_HTTP_ReqCtxAddHeader(ctx, "Content-Type", "text/html"), BSL_SUCCESS);
    ASSERT_NE(HITLS_HTTP_ReqCtxAddHeader(ctx, "Content-Length", "9999"), BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC004
 * @title  AddHeader rejects header injection characters
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxAddHeader(ctx, "X-Extra", "1\r\nSet-Cookie: evil=1").
 * @expect
 *    1. The context is created successfully.
 *    2. Return a non-zero parameter error.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC004(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxAddHeader(ctx, "X-Extra", "1\r\nSet-Cookie: evil=1");
    ASSERT_NE(ret, BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC005
 * @title  AddHeader after SetReq succeeds (header and req are order-independent)
 * @precon  nan
 * @brief
 *    1. Create a context and call HITLS_HTTP_ReqCtxSetReq.
 *    2. Call HITLS_HTTP_ReqCtxAddHeader(ctx, "X-Extra", "1").
 * @expect
 *    1. SetReq succeeds.
 *    2. AddHeader succeeds and the custom header is appended to the request header.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC005(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxAddHeader(ctx, "X-Extra", "1");
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint32_t hdrLen = 0;
    const char *hdr = (const char *)HttpTestGetReqHdr(ctx, &hdrLen);
    ASSERT_TRUE(hdr != NULL);
    ASSERT_TRUE(HttpTestHdrContains(hdr, hdrLen, "X-Extra: 1\r\n"));
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC006
 * @title  AddHeader rejects an over-long header value
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxAddHeader with a value longer than the limit.
 * @expect
 *    1. The context is created successfully.
 *    2. Return a non-zero parameter error.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC006(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    char longVal[HITLS_HTTP_MAX_HDR_VALUE_LEN + 32];
    (void)memset(longVal, 'c', sizeof(longVal) - 1);
    longVal[sizeof(longVal) - 1] = '\0';
    int32_t ret = HITLS_HTTP_ReqCtxAddHeader(ctx, "X-Extra", longVal);
    ASSERT_NE(ret, BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC007
 * @title  AddHeader rejects an over-long header name
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxAddHeader with a name longer than the limit.
 * @expect
 *    1. The context is created successfully.
 *    2. Return a non-zero parameter error.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC007(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    char longName[HITLS_HTTP_MAX_HDR_NAME_LEN + 32];
    (void)memset(longName, 'd', sizeof(longName) - 1);
    longName[sizeof(longName) - 1] = '\0';
    int32_t ret = HITLS_HTTP_ReqCtxAddHeader(ctx, longName, "1");
    ASSERT_NE(ret, BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC008
 * @title  AddHeader header count limit is enforced
 * @precon  nan
 * @brief
 *    1. Create a context with max header lines set to 2.
 *    2. Add three custom headers.
 * @expect
 *    1. The context is configured successfully.
 *    2. The first two succeed and the third returns a parameter error.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC008(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t maxLines = 2;
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_HDR_LINES, &maxLines, sizeof(maxLines));
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxAddHeader(ctx, "X-A", "1");
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxAddHeader(ctx, "X-B", "2");
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxAddHeader(ctx, "X-C", "3");
    ASSERT_NE(ret, BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC001
 * @title  Set and get MAX_RESP_LEN
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Set the max response length to 50KB and read it back.
 * @expect
 *    1. The context is created successfully.
 *    2. Both calls return 0 and the read-back value equals 50KB.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC001(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t setLen = 50 * 1024;
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_LEN, &setLen, sizeof(setLen));
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint32_t getLen = 0;
    ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_GET_MAX_RESP_LEN, &getLen, sizeof(getLen));
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(getLen, setLen);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC002
 * @title  Set and get MAX_RESP_HDR_LINES
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Set the max response header lines to 128 and read it back.
 * @expect
 *    1. The context is created successfully.
 *    2. Both calls return 0 and the read-back value equals 128.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC002(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t setLines = 128;
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_HDR_LINES, &setLines, sizeof(setLines));
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint32_t getLines = 0;
    ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_GET_MAX_RESP_HDR_LINES, &getLines, sizeof(getLines));
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(getLines, setLines);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC003
 * @title  Set EXP_CONTENT_TYPE stores a deep copy
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Set the expected Content-Type to "application/ocsp-response".
 * @expect
 *    1. The context is created successfully.
 *    2. The call returns 0 and ctx->expectedCt is a deep copy.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC003(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_EXP_CONTENT_TYPE, "application/ocsp-response", 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(ctx->expectedCt != NULL);
    ASSERT_TRUE(strcmp(ctx->expectedCt, "application/ocsp-response") == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC004
 * @title  Set EXP_CONTENT_TYPE with NULL clears the value
 * @precon  nan
 * @brief
 *    1. Create a context and set an expected Content-Type.
 *    2. Set the expected Content-Type to NULL.
 * @expect
 *    1. The context is created successfully.
 *    2. The call returns 0 and ctx->expectedCt becomes NULL.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC004(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_EXP_CONTENT_TYPE, "application/ocsp-response", 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(ctx->expectedCt != NULL);
    ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_EXP_CONTENT_TYPE, NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(ctx->expectedCt == NULL);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC005
 * @title  Invalid Ctrl command is rejected
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxCtrl with cmd 9999.
 * @expect
 *    1. The context is created successfully.
 *    2. Return a non-zero parameter error.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC005(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t val = 0;
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, 9999, &val, sizeof(val));
    ASSERT_NE(ret, BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC006
 * @title  AddHeader("Host") appends the Host header, order-independent with SetReq
 * @precon  nan
 * @brief
 *    1. Create a context without a host (no Host header by default).
 *    2. Add the "Host" header as "ocsp.example.com" and build the request with SetReq.
 *    3. Add a second Host header after SetReq (still before the transfer starts).
 * @expect
 *    1. The context is created with no Host header.
 *    2. The call returns 0 and the request header carries "Host: ocsp.example.com".
 *    3. The call returns 0 (order-independent) and a second Host header is appended.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC006(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t hdrLen = 0;
    const char *hdr = (const char *)HttpTestGetReqHdr(ctx, &hdrLen);
    ASSERT_TRUE(hdr != NULL);
    ASSERT_TRUE(!HttpTestHdrContains(hdr, hdrLen, "Host:"));
    int32_t ret = HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", "ocsp.example.com");
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    hdr = (const char *)HttpTestGetReqHdr(ctx, &hdrLen);
    ASSERT_TRUE(hdr != NULL);
    ASSERT_TRUE(HttpTestHdrContains(hdr, hdrLen, "Host: ocsp.example.com\r\n"));
    ret = HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", "other.example.com");
    ASSERT_EQ(ret, BSL_SUCCESS);
    hdr = (const char *)HttpTestGetReqHdr(ctx, &hdrLen);
    ASSERT_TRUE(hdr != NULL);
    ASSERT_TRUE(HttpTestHdrContains(hdr, hdrLen, "Host: other.example.com\r\n"));
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC007
 * @title  AddHeader("Host") rejects NULL and bad values
 * @precon  nan
 * @brief
 *    1. Create a context (host unset by default).
 *    2. Add the Host header with a NULL, a control-character and an over-long value.
 * @expect
 *    1. The context is created with no Host header.
 *    2. Every call returns a non-zero parameter error (no NULL/fallback value;
 *       values are subject to the regular header value limits).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC007(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", NULL), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", "bad\r\nX-Inject: 1"), BSL_HTTP_ERR_PARAM);
    char tooLong[HITLS_HTTP_MAX_HDR_VALUE_LEN + 2];
    (void)memset(tooLong, 'a', sizeof(tooLong) - 1);
    tooLong[sizeof(tooLong) - 1] = '\0';
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", tooLong), BSL_HTTP_ERR_PARAM);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC008
 * @title  SET ctrl commands are rejected once the transfer starts
 * @precon  nan
 * @brief
 *    1. Set a request body and drive Exchange once so the state leaves INIT.
 *    2. Apply SET_MAX_RESP_LEN, SET_EXP_CONTENT_TYPE and SET_TIMEOUT.
 * @expect
 *    1. Exchange returns IN_PROGRESS.
 *    2. Every SET command returns BSL_HTTP_ERR_PARAM (transfer settings are frozen).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC008(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    g_httpWriteBlockFirst = 1;
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxExchange(ctx, &body, &len), BSL_HTTP_ERR_IN_PROGRESS);
    uint32_t v = 1024;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_LEN, &v, sizeof(v)), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_EXP_CONTENT_TYPE, "text/html", 0), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_TIMEOUT, &v, sizeof(v)), BSL_HTTP_ERR_PARAM);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC009
 * @title  Setting a 0 response limit is rejected
 * @precon  nan
 * @brief
 *    1. Set SET_MAX_RESP_LEN and SET_MAX_RESP_HDR_LINES to 0.
 *    2. Read both limits back.
 * @expect
 *    1. Both SET calls return BSL_HTTP_ERR_PARAM (0 would reject every real response).
 *    2. The limits are unchanged (the defaults).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC009(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t zero = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_LEN, &zero, sizeof(zero)), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_HDR_LINES, &zero, sizeof(zero)),
              BSL_HTTP_ERR_PARAM);
    uint32_t getLen = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_GET_MAX_RESP_LEN, &getLen, sizeof(getLen)), BSL_SUCCESS);
    ASSERT_EQ(getLen, HITLS_HTTP_DEFAULT_MAX_RESP_LEN);
    uint32_t getLines = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_GET_MAX_RESP_HDR_LINES, &getLines, sizeof(getLines)),
              BSL_SUCCESS);
    ASSERT_EQ(getLines, HITLS_HTTP_DEFAULT_MAX_RESP_HDR_LINES);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC010
 * @title  Set/get max response line length and reject out-of-range values
 * @precon  nan
 * @brief
 *    1. Set SET_MAX_LINE_LEN to 2048 and read it back.
 *    2. Set it to 0 and to MAX_LINE_LEN + 1.
 * @expect
 *    1. GET returns 2048.
 *    2. Both out-of-range SET calls return BSL_HTTP_ERR_PARAM and the value is unchanged.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC010(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t lineLen = 2048;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_LINE_LEN, &lineLen, sizeof(lineLen)), BSL_SUCCESS);
    uint32_t getLine = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_GET_MAX_LINE_LEN, &getLine, sizeof(getLine)), BSL_SUCCESS);
    ASSERT_EQ(getLine, 2048);
    uint32_t bad = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_LINE_LEN, &bad, sizeof(bad)), BSL_HTTP_ERR_PARAM);
    bad = HITLS_HTTP_MAX_LINE_LEN + 1;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_LINE_LEN, &bad, sizeof(bad)), BSL_HTTP_ERR_PARAM);
    getLine = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_GET_MAX_LINE_LEN, &getLine, sizeof(getLine)), BSL_SUCCESS);
    ASSERT_EQ(getLine, 2048);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTRL_TC011
 * @title  A response line longer than maxLineLen is rejected
 * @precon  nan
 * @brief
 *    1. Set maxLineLen to the minimum and drive a short-header response.
 *    2. On a fresh context, drive a response with a header line over the limit.
 * @expect
 *    1. The short response completes.
 *    2. Exchange returns BSL_HTTP_ERR_RESP_PARSE.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTRL_TC011(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t lineLen = HITLS_HTTP_MIN_LINE_LEN;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_LINE_LEN, &lineLen, sizeof(lineLen)), BSL_SUCCESS);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_OK);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ASSERT_EQ(HttpTestDrive(ctx, &body, &len, NULL), BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);

    HttpTestReset();
    ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_LINE_LEN, &lineLen, sizeof(lineLen)), BSL_SUCCESS);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    char resp[1024];
    int pos = snprintf(resp, sizeof(resp), "HTTP/1.0 200 OK\r\nX-Long: ");
    ASSERT_TRUE(pos > 0 && (uint32_t)pos < sizeof(resp));
    for (int i = 0; i < 300; i++) {
        resp[pos++] = 'a';
    }
    resp[pos++] = '\r';
    resp[pos++] = '\n';
    resp[pos++] = '\r';
    resp[pos++] = '\n';
    HttpTestSetResponseBuf((const uint8_t *)resp, (uint32_t)pos);
    body = NULL;
    len = 0;
    ASSERT_EQ(HttpTestDrive(ctx, &body, &len, NULL), BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_PARSE_TC001
 * @title  HttpParseDecimal ignores a stale errno
 * @precon  nan
 * @brief
 *    1. Pre-set errno to ERANGE (as if a previous call overflowed).
 *    2. Parse a valid decimal, then a value that overflows uint32.
 * @expect
 *    1. The valid value parses and errno is restored afterwards.
 *    2. A genuine overflow is still rejected.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_PARSE_TC001(void)
{
    uint32_t len = 0;
    errno = ERANGE;
    ASSERT_EQ(HttpParseDecimal("100", &len), HITLS_HTTP_DECIMAL_PARSE_OK);
    ASSERT_EQ(len, 100);
    ASSERT_EQ(errno, ERANGE); /* restored to the caller's value */
    errno = 0;
    ASSERT_NE(HttpParseDecimal("4294967296", &len), HITLS_HTTP_DECIMAL_PARSE_OK);
    errno = 0;
    ASSERT_EQ(HttpParseDecimal("12345", &len), HITLS_HTTP_DECIMAL_PARSE_OK);
    ASSERT_EQ(len, 12345);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_PARSE_TC002
 * @title  HttpParseStatusLine validates the minor-version token
 * @precon  nan
 * @brief
 *    1. Parse malformed versions (empty, non-digit, trailing-garbage minor).
 *    2. Parse valid versions.
 * @expect
 *    1. "HTTP/1. ", "HTTP/1.x", "HTTP/1.1x" are rejected.
 *    2. "HTTP/1.1" and "HTTP/1.12" are accepted with the correct code.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_PARSE_TC002(void)
{
    char line[64];
    uint32_t code = 0;
    (void)snprintf(line, sizeof(line), "HTTP/1. 200 OK");
    ASSERT_NE(HttpParseStatusLine(line, &code), HITLS_HTTP_STATUS_PARSE_OK);
    (void)snprintf(line, sizeof(line), "HTTP/1.x 200 OK");
    ASSERT_NE(HttpParseStatusLine(line, &code), HITLS_HTTP_STATUS_PARSE_OK);
    (void)snprintf(line, sizeof(line), "HTTP/1.1x 200 OK");
    ASSERT_NE(HttpParseStatusLine(line, &code), HITLS_HTTP_STATUS_PARSE_OK);
    (void)snprintf(line, sizeof(line), "HTTP/1.1 200 OK");
    ASSERT_EQ(HttpParseStatusLine(line, &code), HITLS_HTTP_STATUS_PARSE_OK);
    ASSERT_EQ(code, 200);
    (void)snprintf(line, sizeof(line), "HTTP/1.12 404 Not Found");
    ASSERT_EQ(HttpParseStatusLine(line, &code), HITLS_HTTP_STATUS_PARSE_OK);
    ASSERT_EQ(code, 404);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_PARSE_TC003
 * @title  HttpParseHeaderLine rejects an empty field name
 * @precon  nan
 * @brief
 *    1. Parse a line starting with a colon and a normal header line.
 * @expect
 *    1. ": value" is ignored (empty field name, RFC 7230); a normal line parses
 *       with its name and value.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_PARSE_TC003(void)
{
    char line1[] = ": value";
    const char *name = NULL;
    const char *value = NULL;
    ASSERT_EQ(HttpParseHeaderLine(line1, &name, &value), HITLS_HTTP_HEADER_PARSE_IGNORE);
    char line2[] = "X-Test: ok";
    ASSERT_EQ(HttpParseHeaderLine(line2, &name, &value), HITLS_HTTP_HEADER_PARSE_OK);
    ASSERT_TRUE(strcmp(name, "X-Test") == 0);
    ASSERT_TRUE(strcmp(value, "ok") == 0);
    char line3[] = ":";
    ASSERT_EQ(HttpParseHeaderLine(line3, &name, &value), HITLS_HTTP_HEADER_PARSE_IGNORE);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC001
 * @title  Non-blocking full send/receive round trip
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Drive HITLS_HTTP_ReqCtxExchange until completion.
 * @expect
 *    1. The request is configured successfully.
 *    2. Exchange returns BSL_SUCCESS, the request was sent and the response body is returned.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC001(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    const uint8_t reqBody[] = "abcdef";
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", reqBody, sizeof(reqBody) - 1);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_OK);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    uint32_t progress = 0;
    ret = HttpTestDrive(ctx, &body, &len, &progress);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    ASSERT_TRUE(HttpTestWrittenContains("POST /responder/ocsp HTTP/1.0\r\n"));
    ASSERT_TRUE(HttpTestWrittenContains("Content-Length: 6\r\n"));
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC002
 * @title  Non-blocking retry does not lose intermediate state
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Make the first write and the first read report would-block.
 *    3. Drive HITLS_HTTP_ReqCtxExchange repeatedly until completion.
 * @expect
 *    1. The request is configured successfully.
 *    2. The first write and the first read block once.
 *    3. Exchange returns at least twice BSL_HTTP_ERR_IN_PROGRESS and finally BSL_SUCCESS
 *       with the correct response body.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC002(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    const uint8_t reqBody[] = "abcdef";
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", reqBody, sizeof(reqBody) - 1);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_OK);
    g_httpWriteBlockFirst = 1;
    g_httpReadBlockFirst = 1;
    const uint8_t *body = NULL;
    uint32_t len = 0;
    uint32_t progress = 0;
    ret = HttpTestDrive(ctx, &body, &len, &progress);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(progress >= 2);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC003
 * @title  Blocking mode loops until completion
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Loop HITLS_HTTP_ReqCtxExchange like a blocking adapter until completion.
 * @expect
 *    1. The request is configured successfully.
 *    2. Exchange finally returns BSL_SUCCESS with the correct response body.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC003(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    const uint8_t reqBody[] = "abcdef";
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", reqBody, sizeof(reqBody) - 1);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_OK);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    uint32_t progress = 0;
    ret = HttpTestDrive(ctx, &body, &len, &progress);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    (void)progress;
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC004
 * @title  Response header line limit is enforced
 * @precon  nan
 * @brief
 *    1. Create a context with max header lines set to 2.
 *    2. Drive Exchange against a response with 3 header lines.
 * @expect
 *    1. The context is configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_RESP_HDR_LINES.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC004(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t maxLines = 2;
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_HDR_LINES, &maxLines, sizeof(maxLines));
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse("HTTP/1.0 200 OK\r\n"
                        "Content-Type: application/ocsp-response\r\n"
                        "Content-Length: 1\r\n"
                        "X-Extra: 1\r\n"
                        "\r\n"
                        "b");
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_HDR_LINES);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC015
 * @title  Transfer-Encoding is rejected
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Drive Exchange against a response with Transfer-Encoding: identity.
 * @expect
 *    1. The request is configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_RESP_PARSE: this client only supports
 *       identity framing, so any Transfer-Encoding is rejected explicitly.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC015(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_TE_IDENTITY);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    ASSERT_TRUE(body == NULL);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC016
 * @title  Redirect status is rejected
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Drive Exchange against a 302 Found response.
 * @expect
 *    1. The request is configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_RESP_STATUS: any non-200 status stops the transfer.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC016(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_REDIRECT);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_STATUS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC017
 * @title  Server error status is rejected before the Content-Type check
 * @precon  nan
 * @brief
 *    1. Create a context expecting "application/ocsp-response".
 *    2. Drive Exchange against a 500 response with Content-Type text/html.
 * @expect
 *    1. The context is configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_RESP_STATUS: the non-200 status stops the transfer
 *       before the Content-Type check is reached.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC017(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_EXP_CONTENT_TYPE, "application/ocsp-response", 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_500_TEXT);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_STATUS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC005
 * @title  Response body size limit is enforced
 * @precon  nan
 * @brief
 *    1. Create a context with max response length set to 10.
 *    2. Drive Exchange against a response whose declared Content-Length exceeds the limit.
 *    3. Drive Exchange against a response without Content-Length whose body exceeds the limit.
 * @expect
 *    1. The context is configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_RESP_TOO_LARGE.
 *    3. Exchange returns BSL_HTTP_ERR_RESP_TOO_LARGE.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC005(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t maxLen = 10;
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_LEN, &maxLen, sizeof(maxLen));
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    /* Declared Content-Length exceeds the limit. */
    HttpTestSetResponse("HTTP/1.0 200 OK\r\n"
                        "Content-Length: 20\r\n"
                        "\r\n"
                        "01234567890123456789");
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_TOO_LARGE);
    /* The first failure latched the ERROR state, so the close-delimited scenario
     * must run on a fresh context to actually exercise the parser. */
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
    HttpTestReset();
    uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_LEN, &maxLen, sizeof(maxLen));
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    /* No Content-Length, body grows past the limit. */
    HttpTestSetResponse("HTTP/1.0 200 OK\r\n"
                        "\r\n"
                        "012345678901234567890123456789");
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_TOO_LARGE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC006
 * @title  Content-Type mismatch is rejected
 * @precon  nan
 * @brief
 *    1. Create a context expecting "application/ocsp-response".
 *    2. Drive Exchange against a response with Content-Type text/html.
 * @expect
 *    1. The context is configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_CONTENT_TYPE.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC006(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_EXP_CONTENT_TYPE, "application/ocsp-response", 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_CT_MISMATCH);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_CONTENT_TYPE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC007
 * @title  I/O error is reported
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Make the stub write fail.
 *    3. Drive Exchange.
 * @expect
 *    1. The request is configured successfully.
 *    2. The stub write fails.
 *    3. Exchange returns BSL_HTTP_ERR_IO.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC007(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    const uint8_t reqBody[] = "abcdef";
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", reqBody, sizeof(reqBody) - 1);
    ASSERT_EQ(ret, BSL_SUCCESS);
    g_httpWriteRet = BSL_UIO_IO_EXCEPTION;
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_IO);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC008
 * @title  HTTP/1.1 response is accepted
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Drive Exchange against an HTTP/1.1 response.
 * @expect
 *    1. The request is configured successfully.
 *    2. Exchange returns BSL_SUCCESS and the response body is returned.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC008(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_HTTP11);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC009
 * @title  Malformed status lines are rejected
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Drive Exchange against responses whose status line is not HTTP/, has a
 *       signed code ("+200"), trailing garbage ("200OK"), a 4-digit code
 *       ("2000") or a leading zero ("0200").
 * @expect
 *    1. The request is configured successfully.
 *    2. All drives return BSL_HTTP_ERR_RESP_PARSE: the status-code must be
 *       exactly 3DIGIT (RFC 7230 Section 3.1.2).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC009(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_MALFORMED);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);

    uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_STATUS_SIGNED);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);

    uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_STATUS_TRAILING);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);

    uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_STATUS_4DIGIT);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);

    uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_STATUS_LEADING_ZERO);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC010
 * @title  Set EXP_CONTENT_TYPE enforcement (regression of T2 pending case)
 * @precon  nan
 * @brief
 *    1. Create a context expecting "application/ocsp-response".
 *    2. Drive Exchange against a response with Content-Type text/html.
 * @expect
 *    1. The context is configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_CONTENT_TYPE, proving the Content-Type check is enforced.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC010(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_EXP_CONTENT_TYPE, "application/ocsp-response", 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_CT_MISMATCH);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_CONTENT_TYPE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC011
 * @title  Set EXP_CONTENT_TYPE(NULL) skips the check (regression of T2 pending case)
 * @precon  nan
 * @brief
 *    1. Create a context without an expected Content-Type.
 *    2. Drive Exchange against a response with Content-Type text/html.
 * @expect
 *    1. The context is configured successfully.
 *    2. Exchange returns BSL_SUCCESS, proving the Content-Type check is skipped.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC011(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_CT_MISMATCH);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC012
 * @title  Exchange out params return the response body on success
 * @precon  nan
 * @brief
 *    1. Create a context, set a request body and drive Exchange to completion.
 *    2. Validate the out parameters.
 * @expect
 *    1. Exchange returns BSL_SUCCESS.
 *    2. The out body is a shallow reference to the response body memory UIO and the length matches.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC012(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_OK);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint32_t expLen = 0;
    const uint8_t *expBody = HttpGetRespBody(ctx, &expLen);
    ASSERT_TRUE(body == expBody);
    ASSERT_EQ(len, expLen);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC013
 * @title  Exchange out params are cleared while in progress
 * @precon  nan
 * @brief
 *    1. Create a context, set a request body and make the first write block.
 *    2. Call Exchange once and inspect the out parameters.
 * @expect
 *    1. The request is configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_IN_PROGRESS and the out parameters are NULL/0.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC013(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    g_httpWriteBlockFirst = 1;
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ret = HITLS_HTTP_ReqCtxExchange(ctx, &body, &len);
    ASSERT_EQ(ret, BSL_HTTP_ERR_IN_PROGRESS);
    ASSERT_TRUE(body == NULL);
    ASSERT_EQ(len, 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC014
 * @title  Chunked transfer encoding is rejected
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Drive Exchange against a response with Transfer-Encoding: chunked but no
 *       Content-Length.
 * @expect
 *    1. The request is configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_RESP_PARSE: this client cannot decode a
 *       chunked transfer coding, so the response is rejected instead of handing
 *       the raw chunk framing to the caller.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC014(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_CHUNKED);
    g_httpEof = 1;
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    ASSERT_TRUE(body == NULL);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC029
 * @title  Close-delimited body grows on demand up to maxRespLen
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Drive Exchange against a no-Content-Length response with a 12KB body.
 * @expect
 *    1. The request is configured successfully.
 *    2. Exchange returns BSL_SUCCESS with the full 12KB body: the response body memory
 *       UIO grows internally up to maxRespLen instead of pre-allocating up front.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC029(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    /* No Content-Length: close-delimited body of 12KB (> 10KB initial cap). */
    uint32_t bodyLen = 12 * 1024;
    char *resp = (char *)malloc(64 + bodyLen);
    ASSERT_TRUE(resp != NULL);
    (void)snprintf(resp, 64, "HTTP/1.0 200 OK\r\n\r\n");
    size_t hdrLen = strlen(resp);
    (void)memset(resp + hdrLen, 'a', bodyLen);
    HttpTestSetResponseBuf((const uint8_t *)resp, (uint32_t)hdrLen + bodyLen);
    g_httpEof = 1;
    const uint8_t *body = NULL;
    uint32_t len = 0;
    int32_t     ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, bodyLen);
    ASSERT_TRUE(body != NULL);
    ASSERT_EQ(memcmp(body, resp + hdrLen, len), 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
    free(resp);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC030
 * @title  Transfer deadline bounds a close-delimited response that never EOFs
 * @precon  nan
 * @brief
 *    1. Create a context, set a 1-second transfer deadline and a request body.
 *    2. Drive Exchange against a no-Content-Length response that sends some body bytes
 *       but never closes the connection (no EOF).
 * @expect
 *    1. The request and the timeout are configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_TIMEOUT once the deadline passes (the body can
 *       only end at connection close, which never happens).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC030(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    uint32_t timeout = 1;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_TIMEOUT, &timeout, sizeof(timeout)), BSL_SUCCESS);
    /* No Content-Length and the stub never returns EOF (g_httpEof is 0). */
    HttpTestSetResponse("HTTP/1.0 200 OK\r\n\r\nabc");
    int32_t ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_TIMEOUT);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC031
 * @title  Close-delimited body of exactly maxRespLen is accepted
 * @precon  nan
 * @brief
 *    1. Create a context with max response length set to 20 and set a request body.
 *    2. Drive Exchange against a no-Content-Length response whose body is exactly 20 bytes
 *       followed by EOF.
 * @expect
 *    1. The request is configured successfully.
 *    2. Exchange returns BSL_SUCCESS with the full 20-byte body: a body that ends exactly
 *       at the cap is completed by the EOF probe instead of being rejected as too large.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC031(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    uint32_t maxLen = 20;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_LEN, &maxLen, sizeof(maxLen)), BSL_SUCCESS);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    /* No Content-Length; the 20-byte body fills the buffer exactly to maxRespLen. */
    char resp[64];
    (void)snprintf(resp, sizeof(resp), "HTTP/1.0 200 OK\r\n\r\n");
    size_t hdrLen = strlen(resp);
    uint8_t body[20];
    (void)memset(body, 'x', sizeof(body));
    uint8_t *payload = (uint8_t *)malloc(hdrLen + sizeof(body));
    ASSERT_TRUE(payload != NULL);
    (void)memcpy(payload, resp, hdrLen);
    (void)memcpy(payload + hdrLen, body, sizeof(body));
    HttpTestSetResponseBuf(payload, (uint32_t)hdrLen + (uint32_t)sizeof(body));
    g_httpEof = 1;
    const uint8_t *outBody = NULL;
    uint32_t len = 0;
    int32_t ret = HttpTestDrive(ctx, &outBody, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 20);
    ASSERT_TRUE(outBody != NULL && memcmp(outBody, body, len) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
    free(payload);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC033
 * @title  A deadline already passed before the flush is checked
 * @precon  nan
 * @brief
 *    1. Create a context with a 1-second transfer deadline and set a request body.
 *    2. Let the deadline expire, then drive Exchange: the write succeeds and the flush
 *       completes, at which point the deadline check fires.
 * @expect
 *    1. The request and the timeout are configured successfully.
 *    2. Exchange returns BSL_HTTP_ERR_TIMEOUT: the write phase consumed the whole
 *       deadline, so the flush success path must report the timeout before reading.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC033(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    uint32_t timeout = 1;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_TIMEOUT, &timeout, sizeof(timeout)), BSL_SUCCESS);
    /* The write phase (simulated by waiting) consumes the whole deadline. */
    BSL_SAL_Sleep(2);
    HttpTestSetResponse("HTTP/1.0 200 OK\r\n\r\n");
    int32_t ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_TIMEOUT);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC034
 * @title  Exchange rejects a non-NULL *respBody or non-zero *respLen
 * @precon  nan
 * @brief
 *    1. Create a context and set a request body.
 *    2. Call Exchange with a non-NULL *respBody, then with a non-zero *respLen.
 * @expect
 *    1. The request is configured successfully.
 *    2. Both calls return BSL_HTTP_ERR_PARAM and the passed values are unchanged.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC034(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    const uint8_t *body = (const uint8_t *)0x1;
    uint32_t len = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxExchange(ctx, &body, &len), BSL_HTTP_ERR_PARAM);
    ASSERT_TRUE(body == (const uint8_t *)0x1);
    body = NULL;
    len = 1;
    ASSERT_EQ(HITLS_HTTP_ReqCtxExchange(ctx, &body, &len), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(len, 1);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC035
 * @title  Exchange rejects a request without SetReq and recovers after it
 * @precon  nan
 * @brief
 *    1. Create a context without setting the request body.
 *    2. Call Exchange, then call SetReq and drive a full exchange.
 * @expect
 *    1. The first Exchange returns BSL_HTTP_ERR_REQ_NOT_SET without touching the uio.
 *    2. After SetReq the exchange returns BSL_SUCCESS with the 5-byte body.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC035(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxExchange(ctx, &body, &len), BSL_HTTP_ERR_REQ_NOT_SET);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_OK);
    ASSERT_EQ(HttpTestDrive(ctx, &body, &len, NULL), BSL_SUCCESS);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC036
 * @title  Repeated Content-Type with the same value is accepted
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a response carrying Content-Type twice with the same value.
 * @expect
 *    1. Exchange returns BSL_SUCCESS with the 5-byte body.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC036(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_DUP_CT_SAME);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    int32_t ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC037
 * @title  Conflicting Content-Type values are rejected
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a response carrying two different Content-Type values.
 * @expect
 *    1. Exchange returns BSL_HTTP_ERR_RESP_PARSE (RFC 7230: Content-Type is not a
 *       comma-separated list, so a repeated field with a different value is
 *       a malformed response).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC037(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_DUP_CT_DIFF);
    int32_t ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC038
 * @title  Body bytes exceeding the declared Content-Length are rejected
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a response that declares Content-Length: 5 but whose
 *       body bytes read together with the headers exceed that value.
 * @expect
 *    1. Exchange returns BSL_HTTP_ERR_RESP_PARSE (RFC 9112 6.3: the server sent
 *       more body than the announced Content-Length, so the framing is invalid).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC038(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    /* Declared Content-Length is 5 but 10 body bytes arrive in the same read. */
    HttpTestSetResponse("HTTP/1.0 200 OK\r\n"
                        "Content-Length: 5\r\n"
                        "\r\n"
                        "0123456789");
    int32_t ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/* Response fixtures for parsing-spec cases (aligned with OpenSSL http_client). */
static const char RESP_TRAILING_OWS[] = "HTTP/1.0 200 OK\r\n"
                                        "Content-Type: application/ocsp-response \r\n"
                                        "Content-Length: 5 \r\n"
                                        "\r\n"
                                        "12345";

static const char RESP_CL_TRAILING_WS[] = "HTTP/1.0 200 OK\r\n"
                                          "Content-Type: application/ocsp-response\r\n"
                                          "Content-Length: 5 \r\n"
                                          "\r\n"
                                          "12345";

static const char RESP_CL_SIGNED[] = "HTTP/1.0 200 OK\r\n"
                                     "Content-Type: application/ocsp-response\r\n"
                                     "Content-Length: +5\r\n"
                                     "\r\n"
                                     "12345";

static const char RESP_CL_NEGATIVE[] = "HTTP/1.0 200 OK\r\n"
                                       "Content-Type: application/ocsp-response\r\n"
                                       "Content-Length: -1\r\n"
                                       "\r\n"
                                       "12345";

static const char RESP_NAME_PRECOLON_WS[] = "HTTP/1.0 200 OK\r\n"
                                            "Content-Type: application/ocsp-response\r\n"
                                            "Content-Length : 5\r\n"
                                            "\r\n"
                                            "1234567890";

static const char RESP_BROKEN_LINES[] = "HTTP/1.0 200 OK\r\n"
                                        "Content-Type: application/ocsp-response\r\n"
                                        "no-colon-here\r\n"
                                        ": orphan\r\n"
                                        "Content-Length: 5\r\n"
                                        "\r\n"
                                        "12345";

static const char RESP_HTTP2[] = "HTTP/2.0 200 OK\r\n"
                                 "Content-Type: application/ocsp-response\r\n"
                                 "Content-Length: 5\r\n"
                                 "\r\n"
                                 "12345";

static const char RESP_404[] = "HTTP/1.0 404 Not Found\r\n"
                               "Content-Type: application/ocsp-response\r\n"
                               "Content-Length: 5\r\n"
                               "\r\n"
                               "12345";

static const char RESP_BARE_LF[] = "HTTP/1.0 200 OK\n"
                                   "Content-Type: application/ocsp-response\n"
                                   "Content-Length: 5\n"
                                   "\n"
                                   "12345";

static const char RESP_DUP_CL_SAME[] = "HTTP/1.0 200 OK\r\n"
                                       "Content-Type: application/ocsp-response\r\n"
                                       "Content-Length: 5\r\n"
                                       "Content-Length: 5\r\n"
                                       "\r\n"
                                       "12345";

static const char RESP_DUP_CL_DIFF[] = "HTTP/1.0 200 OK\r\n"
                                       "Content-Type: application/ocsp-response\r\n"
                                       "Content-Length: 5\r\n"
                                       "Content-Length: 6\r\n"
                                       "\r\n"
                                       "12345";

static const char RESP_CT_PARAMS[] = "HTTP/1.0 200 OK\r\n"
                                     "Content-Type: application/ocsp-response; p1=x\r\n"
                                     "Content-Length: 5\r\n"
                                     "\r\n"
                                     "12345";

/**
 * @test  SDV_BSL_HTTP_CTX_TC029
 * @title  SetReq rejects a NULL body with a non-zero length
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxSetReq(ctx, ct, NULL, 10).
 * @expect
 *    1. The context is created successfully.
 *    2. Return BSL_HTTP_ERR_PARAM so the write path never sees a NULL body with a length.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC029(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 10);
    ASSERT_EQ(ret, BSL_HTTP_ERR_PARAM);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC030
 * @title  ReqCtxNew rejects a path that breaks the request line
 * @precon  nan
 * @brief
 *    1. Call HITLS_HTTP_ReqCtxNew with paths containing CRLF, a space or a
 *       control character.
 * @expect
 *    1. All calls return NULL so the request line cannot be forged. Only the
 *       request line framing is checked; the URI character set itself is not
 *       validated (a caller must pass a percent-encoded path).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC030(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    ASSERT_TRUE(HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/a\r\nX-Inject: 1") == NULL);
    ASSERT_TRUE(HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/a b") == NULL);
    ASSERT_TRUE(HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/a\x01") == NULL);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC031
 * @title  SetReq rejects a Content-Type with control characters
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxSetReq with a Content-Type carrying CRLF and another carrying 0x01.
 * @expect
 *    1. The context is created successfully.
 *    2. Both calls return BSL_HTTP_ERR_PARAM so no header can be injected.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC031(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request\r\nX-Inject: 1", NULL, 0), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/\x01ocsp-request", NULL, 0), BSL_HTTP_ERR_PARAM);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC032
 * @title  SetReq can be called only once
 * @precon  nan
 * @brief
 *    1. Run a full request/response exchange to completion.
 *    2. Call HITLS_HTTP_ReqCtxSetReq again on the completed ctx.
 *    3. On a fresh ctx, call HITLS_HTTP_ReqCtxSetReq again while a transfer is in flight.
 * @expect
 *    1. The first exchange returns BSL_SUCCESS with the 5-byte body.
 *    2. The second SetReq returns BSL_HTTP_ERR_PARAM (the request body cannot be replaced).
 *    3. The in-flight SetReq returns BSL_HTTP_ERR_PARAM.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC032(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    int32_t ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    HttpTestSetResponse(RESP_OK);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    /* A completed transfer cannot be re-armed: the request body cannot be replaced. */
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_HTTP_ERR_PARAM);
    HITLS_HTTP_ReqCtxFree(ctx);

    /* A transfer in flight cannot be re-armed either. */
    HttpTestReset();
    ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ret = HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0);
    ASSERT_EQ(ret, BSL_SUCCESS);
    body = NULL;
    len = 0;
    ret = HITLS_HTTP_ReqCtxExchange(ctx, &body, &len);
    ASSERT_EQ(ret, BSL_HTTP_ERR_IN_PROGRESS);
    ASSERT_EQ(ctx->state, HITLS_HTTP_STATE_READ_HDR);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_HTTP_ERR_PARAM);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_CTX_TC033
 * @title  SetReq rejects empty and whitespace-only Content-Type
 * @precon  nan
 * @brief
 *    1. Create a context.
 *    2. Call HITLS_HTTP_ReqCtxSetReq with an empty Content-Type and with a
 *       whitespace-only Content-Type.
 * @expect
 *    1. The context is created successfully.
 *    2. Both calls return BSL_HTTP_ERR_PARAM so no degenerate
 *       "Content-Type: \r\n" / "Content-Type:  \r\n" header is emitted
 *       (RFC 7231 requires a non-empty media type).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_CTX_TC033(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "", NULL, 0), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, " \t ", NULL, 0), BSL_HTTP_ERR_PARAM);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC009
 * @title  AddHeader rejects framing headers
 * @precon  nan
 * @brief
 *    1. Add Transfer-Encoding and Connection headers.
 *    2. Add a regular Accept header.
 * @expect
 *    1. Both framing headers are rejected with BSL_HTTP_ERR_PARAM (they conflict with
 *       the fixed Content-Length + raw body framing).
 *    2. Accept is accepted with BSL_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC009(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "Transfer-Encoding", "chunked"), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "connection", "close"), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "Accept", "application/ocsp-response"), BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC010
 * @title  AddHeader rejects names that are not RFC 7230 tokens
 * @precon  nan
 * @brief
 *    1. Add headers with an empty name, a name containing a space and a name containing ':'.
 * @expect
 *    1. All three return BSL_HTTP_ERR_PARAM.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC010(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "", "value"), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "Bad Name", "value"), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "Co:nt", "value"), BSL_HTTP_ERR_PARAM);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC011
 * @title  AddHeader rejects control characters in the value
 * @precon  nan
 * @brief
 *    1. Add a header whose value contains 0x01 and another whose value contains CR/LF.
 * @expect
 *    1. Both return BSL_HTTP_ERR_PARAM.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC011(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "X-Test", "bad\x01value"), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "X-Test", "a\r\nb"), BSL_HTTP_ERR_PARAM);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "X-Test", "ok\ttab value"), BSL_SUCCESS);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC012
 * @title  AddHeader is rejected once the transfer starts
 * @precon  nan
 * @brief
 *    1. Set a request body and make the first header write block (partial send).
 *    2. Call Exchange once so the state leaves INIT, then add a header.
 * @expect
 *    1. Exchange returns IN_PROGRESS and the state is no longer INIT.
 *    2. AddHeader returns BSL_HTTP_ERR_PARAM (headers are frozen once the transfer starts).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC012(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    g_httpWriteBlockFirst = 1;
    const uint8_t *body = NULL;
    uint32_t len = 0;
    int32_t ret = HITLS_HTTP_ReqCtxExchange(ctx, &body, &len);
    ASSERT_EQ(ret, BSL_HTTP_ERR_IN_PROGRESS);
    ASSERT_TRUE(ctx->state != HITLS_HTTP_STATE_INIT);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "X-Test", "late"), BSL_HTTP_ERR_PARAM);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_ADDHEADER_TC013
 * @title  AddHeader is rejected after the transfer completes
 * @precon  nan
 * @brief
 *    1. Set a request body and drive a full exchange to completion.
 *    2. Add a header afterwards.
 * @expect
 *    1. The exchange returns BSL_SUCCESS.
 *    2. AddHeader returns BSL_HTTP_ERR_PARAM (headers are frozen once the transfer starts).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_ADDHEADER_TC013(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_OK);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ASSERT_EQ(HttpTestDrive(ctx, &body, &len, NULL), BSL_SUCCESS);
    ASSERT_EQ(ctx->state, HITLS_HTTP_STATE_DONE);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "X-Test", "late"), BSL_HTTP_ERR_PARAM);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC018
 * @title  Trailing OWS in a header value is stripped (RFC 7230 3.2.4)
 * @precon  nan
 * @brief
 *    1. Set the expected Content-Type and drive Exchange against a response whose
 *       Content-Type and Content-Length carry trailing spaces.
 * @expect
 *    1. The context is configured successfully.
 *    2. The trailing OWS is stripped, so the Content-Type matches, the
 *       Content-Length parses as 5 and the body is received as "12345"
 *       (Exchange returns BSL_SUCCESS).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC018(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_EXP_CONTENT_TYPE, "application/ocsp-response", 0), BSL_SUCCESS);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_TRAILING_OWS);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    int32_t ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC019
 * @title  Response lines terminated by a bare LF are accepted
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a response whose lines end with LF only (no CR).
 * @expect
 *    1. Exchange returns BSL_SUCCESS with the 5-byte body (RFC 7230 Section 3.5 tolerant parsing).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC019(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_BARE_LF);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    int32_t ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC020
 * @title  Repeated Content-Length with the same value is accepted
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a response carrying Content-Length twice with the same value.
 * @expect
 *    1. Exchange returns BSL_SUCCESS with the 5-byte body (RFC 7230 Section 3.3.3).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC020(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_DUP_CL_SAME);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    int32_t ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC021
 * @title  Conflicting Content-Length values are rejected
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a response carrying two different Content-Length values.
 * @expect
 *    1. Exchange returns BSL_HTTP_ERR_RESP_PARSE (RFC 7230 Section 3.3.3 ambiguous framing).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC021(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_DUP_CL_DIFF);
    int32_t ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC022
 * @title  Content-Type with media type parameters matches
 * @precon  nan
 * @brief
 *    1. Set the expected Content-Type and drive Exchange against a response whose
 *       Content-Type carries parameters after ';'.
 * @expect
 *    1. Exchange returns BSL_SUCCESS since parameters do not change the media type.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC022(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_EXP_CONTENT_TYPE, "application/ocsp-response", 0), BSL_SUCCESS);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_CT_PARAMS);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    int32_t ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC023
 * @title  A hard error is latched in a terminal state
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a malformed response until it fails.
 *    2. Call Exchange again with the same context.
 * @expect
 *    1. The first call returns BSL_HTTP_ERR_RESP_PARSE and the state becomes ERROR.
 *    2. The second call returns the same code without re-running the failing handler.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC023(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_MALFORMED);
    int32_t ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    ASSERT_EQ(ctx->state, HITLS_HTTP_STATE_ERROR);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    ret = HITLS_HTTP_ReqCtxExchange(ctx, &body, &len);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_OBSFOLD_TC023A
 * @title  Exchange rejects an obs-fold continuation header line.
 * @precon  nan
 * @brief
 *   1. Drive Exchange against a response whose header contains an obs-fold
 *      line (leading SP/HTAB, RFC 7230 §3.2.4).
 * @expect
 *   1. The transfer fails with BSL_HTTP_ERR_RESP_PARSE.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_OBSFOLD_TC023A(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_OBSFOLD);
    int32_t ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC024
 * @title  Exchange with a NULL context
 * @precon  nan
 * @brief
 *    1. Call HITLS_HTTP_ReqCtxExchange(NULL, NULL, NULL).
 * @expect
 *    1. Return BSL_HTTP_ERR_PARAM and push the error once.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC024(void)
{
    ASSERT_EQ(HITLS_HTTP_ReqCtxExchange(NULL, NULL, NULL), BSL_HTTP_ERR_PARAM);
    ASSERT_TRUE(true);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC025
 * @title  Content-Length trailing OWS is stripped (RFC 7230 3.2.4)
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a response whose Content-Length value carries a
 *       trailing space.
 * @expect
 *    1. The trailing OWS is stripped, so the Content-Length parses as 5 and
 *       the body is received as "12345" (Exchange returns BSL_SUCCESS).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC025(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_CL_TRAILING_WS);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    int32_t ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC032
 * @title  Content-Length with a sign is rejected
 * @precon  nan
 * @brief
 *    1. Drive Exchange against responses whose Content-Length value is "+5" and "-1".
 * @expect
 *    1. Both drives return BSL_HTTP_ERR_RESP_PARSE: HTTP numeric field values
 *       are 1*DIGIT (RFC 7230 Section 3.2.5) and strtoul would otherwise accept
 *       a sign (a leading '-' even wraps to a huge value on 32-bit).
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC032(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_CL_SIGNED);
    int32_t ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);

    uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_CL_NEGATIVE);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC026
 * @title  Whitespace before the header name colon prevents a match
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a response whose Content-Length line is written as
 *       "Content-Length : 5" and whose body is 10 bytes long.
 * @expect
 *    1. Exchange returns BSL_SUCCESS with all 10 body bytes: like OpenSSL, the raw
 *       field name never matches, the line is ignored and the body is read to
 *       EOF instead of stopping at 5 bytes.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC026(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_NAME_PRECOLON_WS);
    g_httpEof = 1;
    const uint8_t *body = NULL;
    uint32_t len = 0;
    int32_t ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 10);
    ASSERT_TRUE(body != NULL && memcmp(body, "1234567890", 10) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC027
 * @title  Header lines without a colon and with an empty name are skipped
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a response that contains a line without a colon and
 *       a line whose field name is empty.
 * @expect
 *    1. Exchange returns BSL_SUCCESS with the 5-byte body: both lines are dropped
 *       without processing, matching the OpenSSL header loop.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC027(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_BROKEN_LINES);
    const uint8_t *body = NULL;
    uint32_t len = 0;
    int32_t ret = HttpTestDrive(ctx, &body, &len, NULL);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(len, 5);
    ASSERT_TRUE(body != NULL && memcmp(body, "12345", 5) == 0);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_HTTP_EXCHANGE_TC028
 * @title  Only HTTP/1.x status lines are accepted; a non-200 status stops the transfer
 * @precon  nan
 * @brief
 *    1. Drive Exchange against a response whose status line starts with "HTTP/2.0".
 *    2. Drive a fresh context against a 404 response with a body.
 * @expect
 *    1. The first drive returns BSL_HTTP_ERR_RESP_PARSE (OpenSSL
 *       parse_http_line1 requires the "HTTP/1." prefix).
 *    2. The second drive returns BSL_HTTP_ERR_RESP_STATUS: a non-200 status stops
 *       the transfer and the error body is not read.
 */
/* BEGIN_CASE */
void SDV_BSL_HTTP_EXCHANGE_TC028(void)
{
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    HITLS_HTTP_ReqCtx *ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_HTTP2);
    int32_t ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_PARSE);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);

    uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    ctx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, "/responder/ocsp");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxSetReq(ctx, "application/ocsp-request", NULL, 0), BSL_SUCCESS);
    HttpTestSetResponse(RESP_404);
    ret = HttpTestDrive(ctx, NULL, NULL, NULL);
    ASSERT_EQ(ret, BSL_HTTP_ERR_RESP_STATUS);
    uint32_t status = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_GET_RESP_STATUS, &status, sizeof(status)), BSL_SUCCESS);
    ASSERT_EQ(status, 404);
    HITLS_HTTP_ReqCtxFree(ctx);
    BSL_UIO_Free(uio);
EXIT:
    return;
}
/* END_CASE */
