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

#include <stdint.h>
#include "hitls_build.h"
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "tls.h"
#include "pack_common.h"
#include "hs_ctx.h"

// pack the Finished message.
int32_t PackFinished(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    const HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    if (bufLen < hsCtx->verifyCtx->verifyDataSize) {
        return PackBufLenError(BINLOG_ID15861, BINGLOG_STR("finish"));
    }

    (void)memcpy_s(buf, bufLen, hsCtx->verifyCtx->verifyData, hsCtx->verifyCtx->verifyDataSize);
    *usedLen = hsCtx->verifyCtx->verifyDataSize;
    return HITLS_SUCCESS;
}