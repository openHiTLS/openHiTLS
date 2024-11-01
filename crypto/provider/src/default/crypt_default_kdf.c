#include "hitls_build.h"
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
    void *kdfCtx = NULL;

    switch (algId) {
        case CRYPT_KDF_SCRYPT:
            kdfCtx = CRYPT_SCRYPT_NewCtx();
            break;
        case CRYPT_KDF_PBKDF2:
            kdfCtx = CRYPT_PBKDF2_NewCtx();
            break;
        case CRYPT_KDF_KDFTLS12:
            kdfCtx = CRYPT_KDFTLS12_NewCtx();
            break;
        case CRYPT_KDF_HKDF:
            kdfCtx = CRYPT_HKDF_NewCtx();
            break;
    }
    if (kdfCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return kdfCtx;
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

const CRYPT_EAL_Func defKdfScrypt[] = {
    {CRYPT_EAL_IMPLKDF_NEWCTX, CRYPT_EAL_DefKdfNewCtx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, CRYPT_SCRYPT_SetParam},
    {CRYPT_EAL_IMPLKDF_DERIVE, CRYPT_SCRYPT_Derive},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, CRYPT_SCRYPT_Deinit},
    {CRYPT_EAL_IMPLKDF_CTRL, CRYPT_EAL_DefKdfCtrl},
    {CRYPT_EAL_IMPLKDF_FREECTX, CRYPT_SCRYPT_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defKdfPBKdf2[] = {
    {CRYPT_EAL_IMPLKDF_NEWCTX, CRYPT_EAL_DefKdfNewCtx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, CRYPT_PBKDF2_SetParam},
    {CRYPT_EAL_IMPLKDF_DERIVE, CRYPT_PBKDF2_Derive},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, CRYPT_PBKDF2_Deinit},
    {CRYPT_EAL_IMPLKDF_CTRL, CRYPT_EAL_DefKdfCtrl},
    {CRYPT_EAL_IMPLKDF_FREECTX, CRYPT_PBKDF2_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defKdfKdfTLS12[] = {
    {CRYPT_EAL_IMPLKDF_NEWCTX, CRYPT_EAL_DefKdfNewCtx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, CRYPT_KDFTLS12_SetParam},
    {CRYPT_EAL_IMPLKDF_DERIVE, CRYPT_KDFTLS12_Derive},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, CRYPT_KDFTLS12_Deinit},
    {CRYPT_EAL_IMPLKDF_CTRL, CRYPT_EAL_DefKdfCtrl},
    {CRYPT_EAL_IMPLKDF_FREECTX, CRYPT_KDFTLS12_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defKdfHkdf[] = {
    {CRYPT_EAL_IMPLKDF_NEWCTX, CRYPT_EAL_DefKdfNewCtx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, CRYPT_HKDF_SetParam},
    {CRYPT_EAL_IMPLKDF_DERIVE, CRYPT_HKDF_Derive},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, CRYPT_HKDF_Deinit},
    {CRYPT_EAL_IMPLKDF_CTRL, CRYPT_EAL_DefKdfCtrl},
    {CRYPT_EAL_IMPLKDF_FREECTX, CRYPT_HKDF_FreeCtx},
    CRYPT_EAL_FUNC_END,
};