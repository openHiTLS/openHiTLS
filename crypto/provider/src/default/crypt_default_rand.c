/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
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

const CRYPT_EAL_Func defRand[] = {
    {CRYPT_EAL_IMPLRAND_DRBGNEWCTX, CRYPT_EAL_DefRandNewCtx},
    {CRYPT_EAL_IMPLRAND_DRBGINST, DRBG_Instantiate},
    {CRYPT_EAL_IMPLRAND_DRBGUNINST, DRBG_Uninstantiate},
    {CRYPT_EAL_IMPLRAND_DRBGGEN, DRBG_Generate},
    {CRYPT_EAL_IMPLRAND_DRBGRESEED, DRBG_Reseed},
    {CRYPT_EAL_IMPLRAND_DRBGCTRL, DRBG_Ctrl},
    {CRYPT_EAL_IMPLRAND_DRBGFREECTX, DRBG_Free},
    CRYPT_EAL_FUNC_END,
};
