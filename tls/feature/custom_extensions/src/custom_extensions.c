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
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "tls.h"
#include "hs_msg.h"
#include "hs_ctx.h"
#include "hs.h"
#include "securec.h"
#include "bsl_sal.h"
#include "custom_extensions.h"
#include "alert.h"
#include "pack.h"

bool IsPackNeedCustomExtensions(CustomExtMethods *exts, uint32_t context)
{
    if (exts == NULL || exts->meths == NULL) {
        return false;
    }

    CustomExtMethod *meth = exts->meths;
    for (uint32_t i = 0; i < exts->methsCount; i++, meth++) {
        if ((context & meth->context) != 0) {
            return true;
        }
    }

    return false;
}

bool IsParseNeedCustomExtensions(CustomExtMethods *exts, uint16_t extType, uint32_t context)
{
    if (exts == NULL || exts->meths == NULL) {
        return false;
    }

    CustomExtMethod *meth = exts->meths;
    for (uint32_t i = 0; i < exts->methsCount; i++, meth++) {
        if (extType == meth->extType && (context & meth->context) != 0) {
            return true;
        }
    }
    return false;
}

bool IsCustomExtensionTypeAdded(CustomExtMethods *exts, uint16_t extType)
{
    if (exts == NULL || exts->meths == NULL) {
        return false;
    }

    CustomExtMethod *meth = exts->meths;
    for (uint32_t i = 0; i < exts->methsCount; i++, meth++) {
        if (extType == meth->extType) {
            return true;
        }
    }
    return false;
}

CustomExtMethod *FindCustomExtensions(CustomExtMethods *exts, uint16_t extType, uint32_t context)
{
    if (exts == NULL || exts->meths == NULL) {
        return NULL;
    }

    CustomExtMethod *meth = exts->meths;
    for (uint32_t i = 0; i < exts->methsCount; i++, meth++) {
        if (extType == meth->extType && (context & meth->context) != 0) {
            return meth;
        }
    }
    return NULL;
}

uint32_t HITLS_CFG_AddCustomExtension(HITLS_Config *config, const HITLS_CustomExtParams *params)
{
    CustomExtMethod *meth = NULL;
    CustomExtMethod *tmp = NULL;

    if (config == NULL || params == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (params->addCb == NULL && params->freeCb != NULL) {
        return HITLS_INVALID_INPUT;
    }

    CustomExtMethods *exts = config->customExts;

    if (IsCustomExtensionTypeAdded(exts, params->extType) ||
        FindCustomExtensions(exts, params->extType, params->context) != NULL) {
        return HITLS_CONFIG_DUP_CUSTOM_EXT;
    }

    if (exts == NULL) {
        exts = (CustomExtMethods *)BSL_SAL_Malloc(sizeof(CustomExtMethods));
        if (exts == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        exts->meths = NULL;
        exts->methsCount = 0;
        config->customExts = exts;
    }
    if (exts->methsCount >= MAX_LIMIT_CUSTOM_EXT) {
        return HITLS_CONFIG_ERR_MAX_LIMIT_CUSTOM_EXT;
    }

    tmp = BSL_SAL_Realloc(exts->meths, (exts->methsCount + 1) * sizeof(CustomExtMethod),
                          exts->methsCount * sizeof(CustomExtMethod));
    if (tmp == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    exts->meths = tmp;
    meth = exts->meths + exts->methsCount;

    (void)memset_s(meth, sizeof(*meth), 0, sizeof(*meth));
    meth->extType = params->extType;
    meth->context = params->context;
    meth->addCb = params->addCb;
    meth->freeCb = params->freeCb;
    meth->addArg = params->addArg;
    meth->parseCb = params->parseCb;
    meth->parseArg = params->parseArg;
    exts->methsCount++;

    return HITLS_SUCCESS;
}

uint32_t HITLS_AddCustomExtension(HITLS_Ctx *ctx, const HITLS_CustomExtParams *params)
{
    if (ctx == NULL || params == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_AddCustomExtension(&(ctx->config.tlsConfig), params);
}

int32_t PackCustomExtensions(const struct TlsCtx *ctx, PackPacket *pkt, uint32_t context,
    HITLS_CERT_X509 *cert, uint32_t certIndex)
{
    uint32_t alert = 0u;

    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    CustomExtMethods *exts = CUSTOM_EXT_FROM_CTX(ctx);
    CustomExtMethod *meth = NULL;
    if (exts == NULL) {
        return HITLS_SUCCESS;
    }

    for (uint32_t i = 0; i < exts->methsCount; i++) {
        uint8_t *out = NULL;
        uint32_t outLen = 0;
        int32_t ret = HITLS_ADD_CUSTOM_EXTENSION_RET_PASS;

        meth = exts->meths + i;

        if ((meth->context & context) == 0 || meth->addCb == NULL) {
            continue;
        }

        ret = meth->addCb(ctx, meth->extType, context, &out, &outLen, cert, certIndex, &alert, meth->addArg);
        if (ret != HITLS_ADD_CUSTOM_EXTENSION_RET_PACK && ret != HITLS_ADD_CUSTOM_EXTENSION_RET_PASS) {
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, alert);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17350, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack custom extension content fail.", 0, 0, 0, 0);
            return ret;
        }
        if (ret == HITLS_ADD_CUSTOM_EXTENSION_RET_PASS) {
            continue;
        }
        if (outLen >= UINT16_MAX) {
            if (meth->freeCb != NULL) {
                meth->freeCb(ctx, meth->extType, context, out, meth->addArg);
            }
            return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
        }

        ret = PackReserveBytes(pkt, sizeof(uint16_t) + sizeof(uint16_t) + outLen, NULL);
        if (ret != HITLS_SUCCESS) {
            if (meth->freeCb != NULL) {
                meth->freeCb(ctx, meth->extType, context, out, meth->addArg);
            }
            return ret;
        }
        (void)PackAppendUint16ToBuf(pkt, meth->extType);

        (void)PackAppendUint16ToBuf(pkt, outLen);
        
        (void)PackAppendDataToBuf(pkt, out, outLen);

        if (meth->freeCb != NULL) {
            meth->freeCb(ctx, meth->extType, context, out, meth->addArg);
        }
    }

    return HITLS_SUCCESS;
}

int32_t ParseCustomExtensions(const struct TlsCtx *ctx, const uint8_t *buf, uint16_t extType, uint32_t extLen,
    uint32_t context, HITLS_CERT_X509 *cert, uint32_t certIndex)
{
    uint32_t alert = 0u;

    CustomExtMethods *exts = CUSTOM_EXT_FROM_CTX(ctx);
    CustomExtMethod *meth = FindCustomExtensions(exts, extType, context);
    if (meth == NULL) {
        return HITLS_SUCCESS;
    }

    // Create a local pointer starting from the position after the type byte
    if (meth->parseCb != NULL) {
        int32_t ret = meth->parseCb(ctx, meth->extType, context, &buf, &extLen, cert, certIndex, &alert,
            meth->parseArg);
        if (ret != HITLS_SUCCESS) {
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, alert);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17351, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                                  "parse custom extension content fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    return HITLS_SUCCESS;
}

void FreeCustomExtensions(CustomExtMethods *exts)
{
    if (exts == NULL) {
        return;
    }
    if (exts->meths == NULL) {
        BSL_SAL_Free(exts);
        return;
    }
    BSL_SAL_Free(exts->meths);
    BSL_SAL_Free(exts);
}

CustomExtMethods *DupCustomExtensions(CustomExtMethods *exts)
{
    if (exts == NULL) {
        return NULL;
    }
    CustomExtMethods *newExts = (CustomExtMethods *)BSL_SAL_Malloc(sizeof(CustomExtMethods));
    if (newExts == NULL) {
        return NULL;
    }
    newExts->meths = (CustomExtMethod *)BSL_SAL_Dump(exts->meths, exts->methsCount * sizeof(CustomExtMethod));
    if (newExts->meths == NULL) {
        BSL_SAL_Free(newExts);
        return NULL;
    }
    newExts->methsCount = exts->methsCount;
    return newExts;
}
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
