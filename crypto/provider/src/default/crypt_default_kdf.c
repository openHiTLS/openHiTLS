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
#include "crypt_pbkdf2.h"
#include "crypt_kdf_tls12.h"
#include "crypt_hkdf.h"
#include "crypt_scrypt.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"


void *CRYPT_EAL_DefKdfNewCtx(void *provCtx, int32_t algId)
{
    (void) provCtx;

    switch (algId) {
#ifdef HITLS_CRYPTO_SCRYPT
        case CRYPT_KDF_SCRYPT:
            return CRYPT_SCRYPT_NewCtx();
#endif
#ifdef HITLS_CRYPTO_PBKDF2
        case CRYPT_KDF_PBKDF2:
            return CRYPT_PBKDF2_NewCtx();
#endif
#ifdef HITLS_CRYPTO_KDFTLS12
        case CRYPT_KDF_KDFTLS12:
            return CRYPT_KDFTLS12_NewCtx();
#endif
#ifdef HITLS_CRYPTO_HKDF
        case CRYPT_KDF_HKDF:
            return CRYPT_HKDF_NewCtx();
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
            return NULL;
    }
}

int32_t CRYPT_EAL_DefKdfCtrl(void *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    (void) ctx;
    (void) cmd;
    (void) val;
    (void) valLen;
    BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
    return CRYPT_NOT_SUPPORT;
}

const CRYPT_EAL_Func g_defEalKdfScrypt[] = {
#ifdef HITLS_CRYPTO_SCRYPT
    {CRYPT_EAL_IMPLKDF_NEWCTX, (CRYPT_EAL_ImplKdfNewCtx)CRYPT_EAL_DefKdfNewCtx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (CRYPT_EAL_ImplKdfSetParam)CRYPT_SCRYPT_SetParam},
    {CRYPT_EAL_IMPLKDF_DERIVE, (CRYPT_EAL_ImplKdfDerive)CRYPT_SCRYPT_Derive},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, (CRYPT_EAL_ImplKdfDeInitCtx)CRYPT_SCRYPT_Deinit},
    {CRYPT_EAL_IMPLKDF_CTRL, (CRYPT_EAL_ImplKdfCtrl)CRYPT_EAL_DefKdfCtrl},
    {CRYPT_EAL_IMPLKDF_FREECTX, (CRYPT_EAL_ImplKdfFreeCtx)CRYPT_SCRYPT_FreeCtx},
    {CRYPT_EAL_IMPLKDF_DUPCTX, (CRYPT_EAL_ImplKdfDupCtx)CRYPT_SCRYPT_DupCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defEalKdfPBKdf2[] = {
#ifdef HITLS_CRYPTO_PBKDF2
    {CRYPT_EAL_IMPLKDF_NEWCTX, (CRYPT_EAL_ImplKdfNewCtx)CRYPT_EAL_DefKdfNewCtx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (CRYPT_EAL_ImplKdfSetParam)CRYPT_PBKDF2_SetParam},
    {CRYPT_EAL_IMPLKDF_DERIVE, (CRYPT_EAL_ImplKdfDerive)CRYPT_PBKDF2_Derive},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, (CRYPT_EAL_ImplKdfDeInitCtx)CRYPT_PBKDF2_Deinit},
    {CRYPT_EAL_IMPLKDF_CTRL, (CRYPT_EAL_ImplKdfCtrl)CRYPT_EAL_DefKdfCtrl},
    {CRYPT_EAL_IMPLKDF_FREECTX, (CRYPT_EAL_ImplKdfFreeCtx)CRYPT_PBKDF2_FreeCtx},
    {CRYPT_EAL_IMPLKDF_DUPCTX, (CRYPT_EAL_ImplKdfDupCtx)CRYPT_PBKDF2_DupCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defEalKdfKdfTLS12[] = {
#ifdef HITLS_CRYPTO_KDFTLS12
    {CRYPT_EAL_IMPLKDF_NEWCTX, (CRYPT_EAL_ImplKdfNewCtx)CRYPT_EAL_DefKdfNewCtx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (CRYPT_EAL_ImplKdfSetParam)CRYPT_KDFTLS12_SetParam},
    {CRYPT_EAL_IMPLKDF_DERIVE, (CRYPT_EAL_ImplKdfDerive)CRYPT_KDFTLS12_Derive},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, (CRYPT_EAL_ImplKdfDeInitCtx)CRYPT_KDFTLS12_Deinit},
    {CRYPT_EAL_IMPLKDF_CTRL, (CRYPT_EAL_ImplKdfCtrl)CRYPT_EAL_DefKdfCtrl},
    {CRYPT_EAL_IMPLKDF_FREECTX, (CRYPT_EAL_ImplKdfFreeCtx)CRYPT_KDFTLS12_FreeCtx},
    {CRYPT_EAL_IMPLKDF_DUPCTX, (CRYPT_EAL_ImplKdfDupCtx)CRYPT_KDFTLS12_DupCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defEalKdfHkdf[] = {
#ifdef HITLS_CRYPTO_HKDF
    {CRYPT_EAL_IMPLKDF_NEWCTX, (CRYPT_EAL_ImplKdfNewCtx)CRYPT_EAL_DefKdfNewCtx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (CRYPT_EAL_ImplKdfSetParam)CRYPT_HKDF_SetParam},
    {CRYPT_EAL_IMPLKDF_DERIVE, (CRYPT_EAL_ImplKdfDerive)CRYPT_HKDF_Derive},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, (CRYPT_EAL_ImplKdfDeInitCtx)CRYPT_HKDF_Deinit},
    {CRYPT_EAL_IMPLKDF_CTRL, (CRYPT_EAL_ImplKdfCtrl)CRYPT_EAL_DefKdfCtrl},
    {CRYPT_EAL_IMPLKDF_FREECTX, (CRYPT_EAL_ImplKdfFreeCtx)CRYPT_HKDF_FreeCtx},
    {CRYPT_EAL_IMPLKDF_DUPCTX, (CRYPT_EAL_ImplKdfDupCtx)CRYPT_HKDF_DupCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */