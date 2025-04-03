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

static uint32_t JudgeCustomExtension(uint8_t context, uint8_t type)
{
    if (context != type) {
        return 0;
    }
    return 1;
}

custom_ext_method *custom_ext_find(const custom_ext_methods *exts,
                                   uint8_t ext_type,
                                   uint32_t *idx)
{
    uint32_t i;
    custom_ext_method *meth = exts->meths;

    if(!meth)
        return NULL;

    for (i = 0; i < exts->meths_count; i++, meth++) {
        if (ext_type == meth->ext_type) {
            if (idx != NULL) {
                *idx = i;
            }
            return meth;
        }
    }
    return NULL;
}

int32_t PackCustomExtensions(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len, uint8_t type)
{
    //int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    //uint32_t exLen = 0u;
    uint32_t al = 0;
    void *msg = NULL;

    //custom_ext_methods *exts = ctx->custext;
    custom_ext_methods *exts = NULL;
    custom_ext_method *meth;

    for (uint32_t i = 0; i < exts->meths_count; i++) {
        uint8_t *out = NULL;
        uint32_t outlen = 0;

        meth = exts->meths + i;

        if (!JudgeCustomExtension(meth->context, type)) {
            continue;
        }

        if (meth->add_cb != NULL) {
            int cb_retval = meth->add_cb(ctx,
                                         meth->ext_type, type, &out,
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

        // Save the custom extension version
        buf[offset] = (uint8_t)meth->ext_type;
        offset++;

        (void)memcpy_s(&buf[offset], bufLen - offset, &out, outlen);
        offset += outlen;

        if (meth->free_cb != NULL) {
            meth->free_cb(ctx, meth->ext_type,
                          type, out, meth->add_arg);
        }
    }

    *len = offset;
    return HITLS_SUCCESS;
}

int32_t ParseCustomExtensions(const TLS_Ctx *ctx, const uint8_t *buf, uint32_t *bufOffset, uint8_t type)
{
    uint32_t al = 0;
    //custom_ext_methods *exts = ctx->custext;
    custom_ext_methods *exts = NULL;
    custom_ext_method *meth;
    void *msg = NULL;
    uint32_t offset = 0u;

    uint8_t ext_type = buf[offset];
    offset++;
    meth = custom_ext_find(exts, ext_type, NULL);
    if (!meth) {
        return HITLS_SUCCESS;
    }

    uint32_t len = buf[offset];
    offset += sizeof(uint32_t);

    if (meth->parse_cb != NULL) {
        int cb_retval = meth->parse_cb(ctx,
                                       meth->ext_type, type, &buf,
                                       len, msg, &al,
                                       meth->parse_arg);
        if (cb_retval <= 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15864, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                                  "parse custom extension content fail.", 0, 0, 0, 0);
            return cb_retval;       /* error */
        }
    }

    *bufOffset += len;
    return HITLS_SUCCESS;
}
