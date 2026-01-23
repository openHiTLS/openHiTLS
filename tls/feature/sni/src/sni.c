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
#ifdef HITLS_TLS_FEATURE_SNI
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include "securec.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "hitls_sni.h"
#include "session.h"
#include "tls_binlog_id.h"
#include "tls.h"
#include "hs.h"
#include "sni.h"

const char *HITLS_GetServerName(const HITLS_Ctx *ctx, const int type)
{
    if (ctx == NULL || type != HITLS_SNI_HOSTNAME_TYPE) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16756, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        return NULL;
    }
    bool isClient = ctx->isClient;
    bool isResume = ctx->negotiatedInfo.isResume;
    uint16_t version = ctx->config.tlsConfig.maxVersion;
    uint8_t *hostName = NULL;
    uint32_t nameSize = 0u;
    if (ctx->session != NULL) {
        SESS_GetHostName(ctx->session, &nameSize, &hostName);
    }
    if (!isClient) {
        /* Before Handshake */
        if (ctx->state == CM_STATE_IDLE) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16757, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ctx->state is CM_STATE_IDLE", 0, 0, 0, 0);
            return NULL;
        }
        /* During or after handshake */
        /* TLS protocol version < TLS1.3 session resumption */
        if ((version < HITLS_VERSION_TLS13 || version == HITLS_VERSION_DTLS12) && isResume && ctx->session != NULL) {
            return (char *)hostName;
        }
    } else {
        /* Before Handshake */
        if (ctx->state == CM_STATE_IDLE) {
            /* resume the session */
            if (ctx->config.tlsConfig.serverName == NULL && ctx->session != NULL &&
                (version < HITLS_VERSION_TLS13 || version == HITLS_VERSION_DTLS12)) {
                return (char *)hostName;
            }
            /* resume non-session */
            return (char *)ctx->config.tlsConfig.serverName;
        } else {
            /* During or after handshake */
            /* resume the session */
            if (ctx->session != NULL && (version < HITLS_VERSION_TLS13 || version == HITLS_VERSION_DTLS12)) {
                return (char *)hostName;
            }
            /* resume non-session */
            return (char *)ctx->config.tlsConfig.serverName;
        }
    }

    return HS_GetServerName(ctx);
}

int32_t HITLS_GetServernameType(const HITLS_Ctx *ctx)
{
    int32_t ret = -1;
    if (HITLS_GetServerName(ctx, HITLS_SNI_HOSTNAME_TYPE) != NULL) {
        return HITLS_SNI_HOSTNAME_TYPE;
    }
    return ret;
}

/* Check whether the host names are the same */
int32_t SNI_StrcaseCmp(const char *s1, const char *s2)
{
    int32_t ret = -1;

    if (s1 == NULL && s2 == NULL) {
        return 0;
    }
    if (s1 == NULL || s2 == NULL) {
        return ret;
    }
    const char *a = s1;
    const char *b = s2;
    int32_t len1 = (int32_t)strlen(s1);
    int32_t len2 = (int32_t)strlen(s2);
    if (len1 != len2) {
        return ret;
    }

    while (tolower((int32_t)*a) == tolower((int32_t)*b)) {
        if (*a == '\0') {
            return 0;
        }

        a++;
        b++;
    }

    return ret;
}

HITLS_Config *HITLS_SetNewConfig(HITLS_Ctx *ctx, HITLS_Config *newConfig)
{
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16758, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "ctx null", 0, 0, 0, 0);
        return NULL;
    }
    if (ctx->globalConfig == newConfig || newConfig == NULL) {
        return ctx->globalConfig;
    }

    if (newConfig->certMgrCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16759, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "certMgrCtx null", 0, 0, 0, 0);
        return NULL;
    }

    HITLS_Config *srcConfig = &ctx->config.tlsConfig;

    SAL_CERT_MgrCtxFree(srcConfig->certMgrCtx);
    srcConfig->certMgrCtx = NULL;
    srcConfig->certMgrCtx = SAL_CERT_MgrCtxDup(newConfig->certMgrCtx);
    if (srcConfig->certMgrCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16760, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "MgrCtxDup fail", 0, 0, 0, 0);
        return NULL;
    }

    if (srcConfig->sessionIdCtxSize == ctx->globalConfig->sessionIdCtxSize &&
        (memcmp(srcConfig->sessionIdCtx, ctx->globalConfig->sessionIdCtx, srcConfig->sessionIdCtxSize) == 0)) {
            (void)memcpy_s(srcConfig->sessionIdCtx, sizeof(srcConfig->sessionIdCtx),
                           newConfig->sessionIdCtx, newConfig->sessionIdCtxSize);
            srcConfig->sessionIdCtxSize = newConfig->sessionIdCtxSize;
    }
    srcConfig->userData = newConfig->userData;
    srcConfig->userDataFreeCb = newConfig->userDataFreeCb;
    HITLS_CFG_FreeConfig(ctx->globalConfig);
    HITLS_CFG_UpRef(newConfig);
    ctx->globalConfig = newConfig;
    return ctx->globalConfig;
}
#endif /* HITLS_TLS_FEATURE_SNI */