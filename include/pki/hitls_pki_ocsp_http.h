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
 * @defgroup pki_ocsp_http
 * @ingroup pki
 * @brief OCSP-over-HTTP transport. Creates a generic HTTP Client context
 *        (bsl/http) carrying the DER-encoded OCSPRequest, and decodes the
 *        received OCSPResponse. All further configuration (extra headers,
 *        security limits, timeout, Host header) is done through the bsl_http.h
 *        API on the returned HITLS_HTTP_ReqCtx.
 */

#ifndef HITLS_PKI_OCSP_HTTP_H
#define HITLS_PKI_OCSP_HTTP_H

#include <stdint.h>
#include "bsl_uio.h"
#include "bsl_http.h"
#include "hitls_pki_ocsp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create an OCSP-over-HTTP request context (a generic HTTP Client ctx).
 * @param uio  [IN] Connected UIO handle (TCP).
 * @param path [IN] Request path (e.g. "/responder/ocsp").
 * @param req  [IN] OCSPRequest object (DER-encoded into the request body).
 * @retval HITLS_HTTP_ReqCtx * on success, NULL on failure (any NULL parameter
 *         or an internal error such as DER encoding failure / OOM).
 * @note The returned context is a bsl/http HITLS_HTTP_ReqCtx. Continue with the
 *       bsl_http.h API for further steps - e.g. HITLS_HTTP_ReqCtxAddHeader to
 *       add extra headers, HITLS_HTTP_ReqCtxCtrl to set parameters (Host header,
 *       max response length, header-line limit, timeout), then drive the transfer
 *       with HITLS_OCSP_HttpReqCtxExchange. Free it with HITLS_OCSP_HttpReqCtxFree (the uio stays owned by the caller).
 */
HITLS_HTTP_ReqCtx *HITLS_OCSP_HttpReqCtxNew(BSL_UIO *uio, const char *path, const HITLS_OCSP_Req *req);

/**
 * @brief Drive one non-blocking step of the HTTP exchange and, on completion,
 *        decode the OCSP response.
 * @param ctx  [IN] OCSP-over-HTTP context (from HITLS_OCSP_HttpReqCtxNew).
 * @param resp [OUT] Decoded OCSPResponse (caller releases); only filled when
 *               ret == HITLS_PKI_SUCCESS.
 * @retval HITLS_PKI_SUCCESS = complete (*resp filled).
 * @retval HITLS_OCSP_ERR_IN_PROGRESS = non-blocking in progress; the caller
 *         retries (typically sleeping between attempts).
 * @retval HITLS_OCSP_ERR_HTTP_STATUS = the responder returned a non-200 HTTP
 *         status (the code is available via HITLS_HTTP_CTRL_GET_RESP_STATUS).
 * @retval other error codes (HTTP layer errors pass through; DER decode
 *         failures return the codec error).
 */
int32_t HITLS_OCSP_HttpReqCtxExchange(HITLS_HTTP_ReqCtx *ctx, HITLS_OCSP_Resp **resp);

/**
 * @brief Release the OCSP-over-HTTP context.
 * @param ctx [IN] Context (from HITLS_OCSP_HttpReqCtxNew); NULL safe.
 * @note Alias of HITLS_HTTP_ReqCtxFree: the OCSP-over-HTTP context IS a
 *       bsl/http HITLS_HTTP_ReqCtx (the uio stays owned by the caller).
 */
#define HITLS_OCSP_HttpReqCtxFree(ctx) HITLS_HTTP_ReqCtxFree(ctx)

#ifdef __cplusplus
}
#endif

#endif /* HITLS_PKI_OCSP_HTTP_H */
