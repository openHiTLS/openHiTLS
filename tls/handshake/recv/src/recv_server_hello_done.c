/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "rec.h"
#include "hs_ctx.h"
#include "hs_common.h"

int32_t ClientRecvServerHelloDoneProcess(TLS_Ctx *ctx)
{
    /** get client infomation */
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** Certificate messages are sent whenever a server certificate request is received,
        regardless of whether the client has a proper certificate. */
    if (hsCtx->isNeedClientCert) {
        return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE);
    }
    return HS_ChangeState(ctx, TRY_SEND_CLIENT_KEY_EXCHANGE);
}