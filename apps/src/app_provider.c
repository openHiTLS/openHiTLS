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
 
#ifdef HITLS_CRYPTO_PROVIDER
#include "app_provider.h"
#include <limits.h>
#include "string.h"
#include "securec.h"
#include "app_errno.h"
#include "app_print.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "crypt_eal_provider.h"

static CRYPT_EAL_LibCtx *g_libCtx = NULL;

CRYPT_EAL_LibCtx *APP_GetCurrent_LibCtx(void)
{
    return g_libCtx;
}

CRYPT_EAL_LibCtx *APP_Create_LibCtx(void)
{
    if (g_libCtx == NULL) {
        g_libCtx = CRYPT_EAL_LibCtxNew();
    }
    return g_libCtx;
}

int32_t HITLS_APP_LoadProvider(const char *searchPath, const char *providerName)
{
    CRYPT_EAL_LibCtx *ctx = g_libCtx;
    int32_t ret = HITLS_APP_SUCCESS;
    if (ctx == NULL) {
        (void)AppPrintError("Lib not initialized\n");
        return HITLS_APP_INVALID_ARG;
    }
    if (searchPath != NULL) {
        ret = CRYPT_EAL_ProviderSetLoadPath(ctx, searchPath);
        if (ret != HITLS_APP_SUCCESS) {
            (void)AppPrintError("Load SetSearchPath failed. ERR:%d\n", ret);
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    if (providerName != NULL) {
        ret = CRYPT_EAL_ProviderLoad(ctx, BSL_SAL_LIB_FMT_OFF, providerName, NULL, NULL);
        if (ret != HITLS_APP_SUCCESS) {
            (void)AppPrintError("Load provider failed. ERR:%d\n", ret);
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}

void HITLS_APP_FreeLibCtx(void)
{
    if (g_libCtx != NULL) {
        CRYPT_EAL_LibCtxFree(g_libCtx);
        g_libCtx = NULL;
    }
}

#endif // HITLS_CRYPTO_PROVIDER
