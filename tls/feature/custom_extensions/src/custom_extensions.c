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

static uint32_t JudgeCustomExtension(uint8_t ext_context, uint8_t context)
{
    if (ext_context != context) {
        return 0;
    }
    return 1;
}

CustomExt_Method *FindCustomExtensions(CustomExt_Methods *exts,
                                   uint8_t ext_type,
                                   uint8_t context)
{
    uint32_t i;

    if(!exts)
        return NULL;

    CustomExt_Method *meth = exts->meths;

    if(!meth)
        return NULL;

    for (i = 0; i < exts->meths_count; i++, meth++) {
        if (ext_type == meth->ext_type && context == meth->context) {
            return meth;
        }
    }
    return NULL;
}

uint32_t HITLS_AddCustomExtension(struct TlsCtx *ctx, uint8_t ext_type,
                                  uint8_t context,
                                  HITLS_CustomExt_Add_Callback add_cb,
                                  HITLS_CustomExt_Free_Callback free_cb,
                                  void *add_arg,
                                  HITLS_CustomExt_Parse_Callback parse_cb,
                                  void *parse_arg)
{
    CustomExt_Method *meth = NULL, *tmp = NULL;

    if (add_cb == NULL && free_cb != NULL) {
        return 0;
    }
    CustomExt_Methods *exts = ctx->customExts;

    if (FindCustomExtensions(exts, ext_type, context)) {
        return 0;
    }

    if (exts == NULL) {
        exts = (CustomExt_Methods *)BSL_SAL_Malloc(sizeof(CustomExt_Methods));
        if (exts == NULL) {
            return 0;
        }
        exts->meths = NULL;
        exts->meths_count = 0;
        ctx->customExts = exts;
    }

    tmp = BSL_SAL_Realloc(exts->meths,
                          (exts->meths_count + 1) * sizeof(CustomExt_Method),
                          exts->meths_count * sizeof(CustomExt_Method));
    if (tmp == NULL) {
        return 0;
    }

    exts->meths = tmp;
    meth = exts->meths + exts->meths_count;
    memset_s(meth, sizeof(*meth), 0, sizeof(*meth));
    meth->context = context;
    meth->parse_cb = parse_cb;
    meth->add_cb = add_cb;
    meth->free_cb = free_cb;
    meth->ext_type = ext_type;
    meth->add_arg = add_arg;
    meth->parse_arg = parse_arg;
    exts->meths_count++;

    return HITLS_SUCCESS;
}


int32_t PackCustomExtensions(const struct TlsCtx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len, uint8_t context)
{
    uint32_t offset = 0u;
    // uint32_t exLen = 0u;
    uint32_t al = 0;
    void *msg = NULL;

    CustomExt_Methods *exts = ctx->customExts;
    CustomExt_Method *meth;

    if(exts == NULL)
        return HITLS_SUCCESS;

    for (uint32_t i = 0; i < exts->meths_count; i++) {
        uint8_t *out = NULL;
        uint32_t outlen = 0;

        meth = exts->meths + i;

        if (!JudgeCustomExtension(meth->context, context)) {
            continue;
        }

        if (meth->add_cb != NULL) {
            int cb_retval = meth->add_cb(ctx,
                                         meth->ext_type, context, &out,
                                         &outlen, msg, &al,
                                         meth->add_arg);
            if (cb_retval <= 0) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15864, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                                      "pack custom extension content fail.", 0, 0, 0, 0);
                return cb_retval;       /* error */
            }
            if (cb_retval == 0) {
                continue;
            }
        }

        if (outlen > 0)
        {
            // Save the custom extension version
            buf[offset] = (uint8_t)meth->ext_type;
            offset++;

            (void)memcpy_s(&buf[offset], bufLen - offset, out, outlen);
            offset += outlen;
        }

        if (meth->free_cb != NULL) {
            meth->free_cb(ctx, meth->ext_type,
                          context, out, meth->add_arg);
        }
    }

    *len = offset;
    return HITLS_SUCCESS;
}

int32_t ParseCustomExtensions(const struct TlsCtx *ctx, const uint8_t *buf, uint32_t *bufOffset, uint8_t context)
{
    uint32_t al = 0;
    CustomExt_Methods *exts = ctx->customExts;
    CustomExt_Method *meth;
    void *msg = NULL;
    uint32_t offset = 0u;

    // Read the extension type
    uint8_t ext_type = buf[offset];
    offset++;  // offset becomes 1, indicating to skip the type byte
    meth = FindCustomExtensions(exts, ext_type, context);
    if (!meth) {
        return HITLS_SUCCESS;
    }

    uint32_t len = 0;
    // Create a local pointer starting from the position after the type byte
    const uint8_t *current = buf + offset;
    if (meth->parse_cb != NULL) {
        int cb_retval = meth->parse_cb(ctx,
                                       meth->ext_type, context, &current,
                                       &len, msg, &al,
                                       meth->parse_arg);
        if (cb_retval <= 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15864, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                                  "parse custom extension content fail.", 0, 0, 0, 0);
            return cb_retval;  // Error handling
        }
    }

    // Update bufOffset: type byte count (offset) + bytes parsed by parse_cb (len)
    *bufOffset += offset + len;
    return HITLS_SUCCESS;
}


