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
#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include "crypt_eal_implprovider.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_iso_selftest.h"
#include "crypt_provider.h"
#include "crypt_iso_provider.h"

#define ISO_19790_PROVIDER_VERSION "openHiTLS ISO 19790 Provider Version : V0.2.0"

typedef struct {
    void *ctx;
    void *mgrCtx;
    void *libCtx;
} IsoSelftestCtx;

static IsoSelftestCtx *CRYPT_Selftest_NewCtx(CRYPT_EAL_IsoProvCtx *provCtx)
{
    if (provCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    IsoSelftestCtx *ctx = (IsoSelftestCtx *)BSL_SAL_Calloc(1, sizeof(IsoSelftestCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->mgrCtx = provCtx->mgrCtx;
    ctx->libCtx = provCtx->libCtx;
    return ctx;
}

static const char *CRYPT_Selftest_GetVersion(IsoSelftestCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    int32_t ret = CRYPT_Iso_Log(ctx->mgrCtx, CRYPT_EVENT_GET_VERSION, 0, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    return ISO_19790_PROVIDER_VERSION;
}

static int32_t CRYPT_Selftest_Selftest(IsoSelftestCtx *ctx, int32_t type)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t event = 0;
    switch (type) {
        case CRYPT_CMVP_INTEGRITY_TEST:
            event = CRYPT_EVENT_INTEGRITY_TEST;
            break;
        case CRYPT_CMVP_KAT_TEST:
            event = CRYPT_EVENT_KAT_TEST;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }

    BSL_Param param[3] = {{0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_EVENT, BSL_PARAM_TYPE_INT32, &event, sizeof(event));
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_LIB_CTX, BSL_PARAM_TYPE_CTX_PTR, ctx->libCtx, 0);
    return CRYPT_EAL_SelftestOperation(ctx->mgrCtx, param);
}

static void CRYPT_Selftest_FreeCtx(IsoSelftestCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_Free(ctx);
}

const CRYPT_EAL_Func g_isoSelftest[] = {
    {CRYPT_EAL_IMPLSELFTEST_NEWCTX, (CRYPT_EAL_ImplSelftestNewCtx)CRYPT_Selftest_NewCtx},
    {CRYPT_EAL_IMPLSELFTEST_GETVERSION, (CRYPT_EAL_ImplSelftestGetVersion)CRYPT_Selftest_GetVersion},
    {CRYPT_EAL_IMPLSELFTEST_SELFTEST, (CRYPT_EAL_ImplSelftestSelftest)CRYPT_Selftest_Selftest},
    {CRYPT_EAL_IMPLSELFTEST_FREECTX, (CRYPT_EAL_ImplSelftestFreeCtx)CRYPT_Selftest_FreeCtx},
    CRYPT_EAL_FUNC_END
};

#endif // HITLS_CRYPTO_CMVP_ISO19790
