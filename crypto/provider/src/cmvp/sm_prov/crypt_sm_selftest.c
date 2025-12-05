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

#include "securec.h"
#include "crypt_types.h"
#include "crypt_errno.h"
#include "bsl_params.h"
#include "cmvp_sm.h"
#include "cmvp_common.h"
#include "crypt_sm_selftest.h"
#include "crypt_eal_provider.h"

int32_t CRYPT_SM_Selftest(BSL_Param *param)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    if (CMVP_CheckIsInternalLibCtx(param)) {
        return CRYPT_SUCCESS;
    }
    int32_t ret = CMVP_CreateInternalLibCtx(param, &libCtx, CRYPT_SM_Selftest);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CMVP_SmCheckIntegrity(libCtx, CRYPT_EAL_SM_ATTR);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_LibCtxFree(libCtx);
        return ret;
    }

    ret = CMVP_SmKat(libCtx, CRYPT_EAL_SM_ATTR);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_LibCtxFree(libCtx);
        return ret;
    }

    ret = CMVP_SmRandomStartupSelftest(libCtx, CRYPT_EAL_SM_ATTR);
    CRYPT_EAL_LibCtxFree(libCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_CMVP_SM */