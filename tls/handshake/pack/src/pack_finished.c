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

#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"

// pack the Finished message.
int32_t PackFinished(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = 0;
    const HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    if (bufLen < hsCtx->verifyCtx->verifyDataSize) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15861, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer length of finished message is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    ret = memcpy_s(buf, bufLen, hsCtx->verifyCtx->verifyData, hsCtx->verifyCtx->verifyDataSize);
    if (ret != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15862, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "memcpy verify data fail when pack finished msg.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    *usedLen = hsCtx->verifyCtx->verifyDataSize;
    return HITLS_SUCCESS;
}
