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
#if defined(HITLS_TLS_FEATURE_STATUS_REQUEST) && defined(HITLS_TLS_HOST_CLIENT)
#include <string.h>
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "hitls_error.h"
#include "hs_msg.h"
#include "parse_msg.h"
#include "parse_common.h"

/**
 * @brief Parse the CertificateStatus message body.
 *
 * The message body is: status_type(1) + response length(3) + OCSP response DER.
 *
 * @param ctx [IN] TLS context
 * @param buf [IN] message buffer
 * @param bufLen [IN] message length
 * @param hsMsg [OUT] message structure
 */
int32_t ParseCertificateStatus(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HS_Msg *hsMsg)
{
    if (bufLen < (sizeof(uint8_t) + UINT24_SIZE)) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID17433,
                                 BINGLOG_STR("certificate status length is incorrect"), ALERT_DECODE_ERROR);
    }
    CertificateStatusMsg *msg = &hsMsg->body.certificateStatus;
    /* Always initialize the output fields so a zero-length response leaves the
     * message clean for the consumer and the cleaner. */
    msg->response = NULL;
    msg->responseLen = 0;
    msg->statusType = buf[0];
    uint32_t respLen = BSL_ByteToUint24(&buf[1]);
    if (respLen > (bufLen - (sizeof(uint8_t) + UINT24_SIZE))) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID17434,
                                 BINGLOG_STR("certificate status response length is incorrect"), ALERT_DECODE_ERROR);
    }
    if (respLen != 0) {
        msg->response = (uint8_t *)BSL_SAL_Dump(&buf[sizeof(uint8_t) + UINT24_SIZE], respLen);
        if (msg->response == NULL) {
            return ParseErrorProcess(ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID17435,
                                     BINGLOG_STR("certificate status response malloc fail"), ALERT_UNKNOWN);
        }
        msg->responseLen = respLen;
    }
    return HITLS_SUCCESS;
}

void CleanCertificateStatus(CertificateStatusMsg *msg)
{
    if (msg != NULL) {
        BSL_SAL_FREE(msg->response);
        msg->response = NULL;
    }
}
#endif /* HITLS_TLS_FEATURE_STATUS_REQUEST && HITLS_TLS_HOST_CLIENT */
