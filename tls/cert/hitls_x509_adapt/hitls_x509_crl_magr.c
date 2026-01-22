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
#if (defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER)) && defined(HITLS_TLS_CONFIG_CERT_CRL)
#include <stdint.h>
#include <string.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_cert_type.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_adapt.h"

static int32_t LoadCrlFromBuffer(
    const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format, HITLS_X509_List **crlList)
{
    BSL_Buffer buffer = {(uint8_t *)(uintptr_t)buf, bufLen};
    return HITLS_X509_CrlParseBundleBuff(format, &buffer, crlList);
}

HITLS_CERT_CRLList *HITLS_X509_Adapt_CrlParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    (void)config;  /* config parameter not used for CRL parsing */

    if (buf == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return NULL;
    }

    HITLS_X509_List *crlList = NULL;
    int32_t ret;
    switch (type) {
#ifdef HITLS_TLS_CONFIG_CERT_LOAD_FILE
        case TLS_PARSE_TYPE_FILE:
            ret = HITLS_X509_CrlParseBundleFile(format, (const char *)buf, &crlList);
            break;
#endif
        case TLS_PARSE_TYPE_BUFF:
            ret = LoadCrlFromBuffer(buf, len, format, &crlList);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
            return NULL;
    }

    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16572, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CRL parse failed, ret = %d", ret, 0, 0, 0);
        return NULL;
    }

    return (HITLS_CERT_CRLList *)crlList;
}

void HITLS_X509_Adapt_CrlFree(HITLS_CERT_CRLList *crlList)
{
    if (crlList != NULL) {
        HITLS_X509_List *list = (HITLS_X509_List *)crlList;
        BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    }
}
#endif /* HITLS_TLS_CALLBACK_CERT && HITLS_TLS_CONFIG_CERT_CRL */