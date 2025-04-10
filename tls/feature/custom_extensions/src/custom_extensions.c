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

#include <stdlib.h>
#include <stdint.h>
#include "hitls_build.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "tls.h"
#include "hs_msg.h"
#include "hs_ctx.h"
#include "hs.h"
#include "securec.h"
#include "bsl_errno.h"
#include "auth_errno.h"
#include "bsl_sal.h"
#include "custom_extensions.h"

static uint32_t JudgeCustomExtension(uint32_t extContext, uint32_t context)
{
    if ((extContext & context) == 0) {
        return 0;
    }
    return 1;
}

CustomExt_Method *FindCustomExtensions(CustomExt_Methods *exts,
                                   uint16_t extType,
                                   uint32_t context)
{
    uint32_t i = 0;

    if(exts == NULL){
        return NULL;
    }

    CustomExt_Method *meth = exts->meths;

    if(meth == NULL){
        return NULL;
    }

    for (i = 0; i < exts->methsCount; i++, meth++) {
        if (extType == meth->extType && (context & meth->context) != 0) {
            return meth;
        }
    }
    return NULL;
}

uint32_t HITLS_AddCustomExtension(struct TlsCtx *ctx, uint16_t extType,
                                  uint32_t context,
                                  HITLS_AddCustomExtCallback addCb,
                                  HITLS_FreeCustomExtCallback freeCb,
                                  void *addArg,
                                  HITLS_ParseCustomExtCallback parseCb,
                                  void *parseArg)
{
    CustomExt_Method *meth = NULL, *tmp = NULL;

    if (addCb == NULL && freeCb != NULL) {
        return 0;
    }

    if(ctx == NULL){
        return 0;
    }
    CustomExt_Methods *exts = ctx->customExts;

    if (FindCustomExtensions(exts, extType, context) != NULL) {
        return 0;
    }

    if (exts == NULL) {
        exts = (CustomExt_Methods *)BSL_SAL_Malloc(sizeof(CustomExt_Methods));
        if (exts == NULL) {
            return 0;
        }
        exts->meths = NULL;
        exts->methsCount = 0;
        ctx->customExts = exts;
    }

    tmp = BSL_SAL_Realloc(exts->meths,
                          (exts->methsCount + 1) * sizeof(CustomExt_Method),
                          exts->methsCount * sizeof(CustomExt_Method));
    if (tmp == NULL) {
        return 0;
    }

    exts->meths = tmp;
    meth = exts->meths + exts->methsCount;
    memset_s(meth, sizeof(*meth), 0, sizeof(*meth));
    meth->context = context;
    meth->parseCb = parseCb;
    meth->addCb = addCb;
    meth->freeCb = freeCb;
    meth->extType = extType;
    meth->addArg = addArg;
    meth->parseArg = parseArg;
    exts->methsCount++;

    return HITLS_SUCCESS;
}


int32_t PackCustomExtensions(const struct TlsCtx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len, uint32_t context)
{
    uint32_t offset = 0u;
    void *msg = NULL;

    CustomExt_Methods *exts = ctx->customExts;
    CustomExt_Method *meth;

    if(exts == NULL){
        return HITLS_SUCCESS;
    }

    for (uint32_t i = 0; i < exts->methsCount; i++) {
        uint8_t *out = NULL;
        uint32_t outLen = 0;

        meth = exts->meths + i;

        if (!JudgeCustomExtension(meth->context, context)) {
            continue;
        }

        if (meth->addCb != NULL) {
            int cbRetval = meth->addCb(ctx,
                                         meth->extType, context, &out,
                                         &outLen, msg,
                                         meth->addArg);
            if (cbRetval != 0) {
                continue;
            }
        }

        if (outLen > 0)
        {
            // Save the custom extension version
            BSL_Uint16ToByte(meth->extType, &buf[offset]);
            offset += 2;

            BSL_Uint16ToByte(outLen, &buf[offset]);
            offset += 2;

            (void)memcpy_s(&buf[offset], bufLen - offset, out, outLen);
            offset += outLen;
        }

        if (meth->freeCb != NULL) {
            meth->freeCb(ctx, meth->extType,
                          context, out, meth->addArg);
        }
    }

    *len = offset;
    return HITLS_SUCCESS;
}

int32_t ParseCustomExtensions(const struct TlsCtx *ctx, const uint8_t *buf, uint32_t *bufOffset, uint16_t extType, uint32_t extLen, uint32_t context)
{
    CustomExt_Methods *exts = ctx->customExts;
    CustomExt_Method *meth;
    void *msg = NULL;

    meth = FindCustomExtensions(exts, extType, context);
    if (meth == NULL) {
        return HITLS_SUCCESS;
    }
    const uint8_t *offset = buf + *bufOffset;
    // Create a local pointer starting from the position after the type byte
    if (meth->parseCb != NULL) {
        int cbRetval = meth->parseCb(ctx,
                                       meth->extType, context, &offset,
                                       &extLen, msg,
                                       meth->parseArg);
        if (cbRetval != 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15864, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                                  "parse custom extension content fail.", 0, 0, 0, 0);
            return cbRetval;  // Error handling
        }
    }

    return HITLS_SUCCESS;
}




