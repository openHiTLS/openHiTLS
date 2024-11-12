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
#ifdef HITLS_CRYPTO_PROVIDER

#include "crypt_eal_implprovider.h"
#include "crypt_drbg.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"

void *CRYPT_EAL_DefRandNewCtx(void *provCtx, int32_t algId, CRYPT_Param *param)
{
    (void) provCtx;
    void *randCtx = NULL;
    randCtx = DRBG_New(algId, param);
    if (randCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return randCtx;
}

const CRYPT_EAL_Func g_defRand[] = {
    {CRYPT_EAL_IMPLRAND_DRBGNEWCTX, CRYPT_EAL_DefRandNewCtx},
    {CRYPT_EAL_IMPLRAND_DRBGINST, DRBG_Instantiate},
    {CRYPT_EAL_IMPLRAND_DRBGUNINST, DRBG_Uninstantiate},
    {CRYPT_EAL_IMPLRAND_DRBGGEN, DRBG_Generate},
    {CRYPT_EAL_IMPLRAND_DRBGRESEED, DRBG_Reseed},
    {CRYPT_EAL_IMPLRAND_DRBGCTRL, DRBG_Ctrl},
    {CRYPT_EAL_IMPLRAND_DRBGFREECTX, DRBG_Free},
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */