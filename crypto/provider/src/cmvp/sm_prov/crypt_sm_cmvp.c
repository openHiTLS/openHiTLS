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
#ifdef HITLS_CRYPTO_CMVP_SM

#include "crypt_eal_implprovider.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_cmvp_selftest.h"
#include "cmvp_sm.h"
#include "crypt_params_key.h"
#include "crypt_sm_provider.h"

#define SM_PROVIDER_VERSION "openHiTLS Crypto Module 0.3.0"

typedef struct {
    void *provCtx;
    void *libCtx;
} SmSelftestCtx;

static SmSelftestCtx *CRYPT_Selftest_NewCtx(CRYPT_EAL_SmProvCtx *provCtx)
{
    if (provCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    SmSelftestCtx *ctx = (SmSelftestCtx *)BSL_SAL_Calloc(1, sizeof(SmSelftestCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->provCtx = provCtx;
    ctx->libCtx = provCtx->libCtx;
    return ctx;
}

static const char *CRYPT_Selftest_GetVersion(SmSelftestCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    return SM_PROVIDER_VERSION;
}

static int32_t CRYPT_Selftest_Selftest(SmSelftestCtx *ctx, const BSL_Param *param)
{
    int32_t type = 0;
    uint32_t len = sizeof(type);
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    const BSL_Param *temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_CMVP_SELFTEST_TYPE);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = BSL_PARAM_GetValue(temp, CRYPT_PARAM_CMVP_SELFTEST_TYPE, BSL_PARAM_TYPE_INT32, &type, &len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    switch (type) {
        case CRYPT_CMVP_INTEGRITY_TEST:
            ret = CMVP_SmCheckIntegrity(ctx->libCtx, CRYPT_EAL_SM_ATTR);
            break;
        case CRYPT_CMVP_KAT_TEST:
            ret = CMVP_SmKat(ctx->libCtx, CRYPT_EAL_SM_ATTR);
            break;
        case CRYPT_CMVP_RANDOMNESS_TEST:
            if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_CMVP_RANDOM)) == NULL ||
                temp->valueType != BSL_PARAM_TYPE_OCTETS || temp->value == NULL || temp->valueLen == 0) {
                ret = CRYPT_INVALID_ARG;
                break;
            }
            ret = CRYPT_CMVP_RandomnessTest(temp->value, temp->valueLen);
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static void CRYPT_Selftest_FreeCtx(SmSelftestCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_Free(ctx);
}

const CRYPT_EAL_Func g_smSelftest[] = {
    {CRYPT_EAL_IMPLSELFTEST_NEWCTX, (CRYPT_EAL_ImplSelftestNewCtx)CRYPT_Selftest_NewCtx},
    {CRYPT_EAL_IMPLSELFTEST_GETVERSION, (CRYPT_EAL_ImplSelftestGetVersion)CRYPT_Selftest_GetVersion},
    {CRYPT_EAL_IMPLSELFTEST_SELFTEST, (CRYPT_EAL_ImplSelftestSelftest)CRYPT_Selftest_Selftest},
    {CRYPT_EAL_IMPLSELFTEST_FREECTX, (CRYPT_EAL_ImplSelftestFreeCtx)CRYPT_Selftest_FreeCtx},
    CRYPT_EAL_FUNC_END
};

#endif // HITLS_CRYPTO_CMVP_SM
