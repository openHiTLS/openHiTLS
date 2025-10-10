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
#ifdef HITLS_CRYPTO_GMAC

#include <stdlib.h>
#include "crypt_gmac.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"

static int32_t GmacIdToSymId(CRYPT_MAC_AlgId algId)
{
    switch (algId) {
        case CRYPT_MAC_GMAC_AES128:
            return CRYPT_CIPHER_AES128_GCM;
        case CRYPT_MAC_GMAC_AES192:
            return CRYPT_CIPHER_AES192_GCM;
        case CRYPT_MAC_GMAC_AES256:
            return CRYPT_CIPHER_AES256_GCM;
        default:
            return CRYPT_CIPHER_MAX;
    }
}

MODES_GCM_Ctx *CRYPT_GMAC_NewCtx(CRYPT_MAC_AlgId id)
{
    return MODES_GCM_NewCtx(GmacIdToSymId(id));
}

MODES_GCM_Ctx *CRYPT_GMAC_NewCtxEx(void *libCtx, CRYPT_MAC_AlgId id)
{
    return MODES_GCM_NewCtxEx(libCtx, GmacIdToSymId(id));
}

int32_t CRYPT_GMAC_Init(MODES_GCM_Ctx *ctx, const uint8_t *key, uint32_t len, void *param)
{
    (void)param;
    return MODES_GCM_SetKey(&ctx->gcmCtx, key, len);
}

int32_t CRYPT_GMAC_Update(MODES_GCM_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    return MODES_GCM_Ctrl(ctx, CRYPT_CTRL_SET_AAD, (void *)(uintptr_t)in, len);
}

int32_t CRYPT_GMAC_Final(MODES_GCM_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    if (len == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return MODES_GCM_Ctrl(ctx, CRYPT_CTRL_GET_TAG, (void *)(uintptr_t)out, *len);
}

void CRYPT_GMAC_FreeCtx(MODES_GCM_Ctx *ctx)
{
    MODES_GCM_FreeCtx(ctx);
}

int32_t CRYPT_GMAC_Deinit(MODES_GCM_Ctx *ctx)
{
    return MODES_GCM_DeInitCtx(ctx);
}

int32_t CRYPT_GMAC_Ctrl(MODES_GCM_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    switch (opt) {
        case CRYPT_CTRL_SET_IV:
            return MODES_GCM_Ctrl(ctx, CRYPT_CTRL_REINIT_STATUS, val, len);
        case CRYPT_CTRL_GET_MACLEN:
            return MODES_GCM_Ctrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, val, len);
        case CRYPT_CTRL_SET_TAGLEN:
            return MODES_GCM_Ctrl(ctx, CRYPT_CTRL_SET_TAGLEN, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_MAC_CTRL_TYPE_ERROR);
            return CRYPT_EAL_MAC_CTRL_TYPE_ERROR;
    }
}

#endif /* HITLS_CRYPTO_GMAC */
