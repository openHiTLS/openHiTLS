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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_KDF)

#include "securec.h"
#include "crypt_local_types.h"
#include "crypt_algid.h"
#ifdef HITLS_CRYPTO_PBKDF2
#include "crypt_pbkdf2.h"
#endif
#ifdef HITLS_CRYPTO_HKDF
#include "crypt_hkdf.h"
#endif
#ifdef HITLS_CRYPTO_KDFTLS12
#include "crypt_kdf_tls12.h"
#endif
#ifdef HITLS_CRYPTO_SCRYPT
#include "crypt_scrypt.h"
#endif
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "eal_common.h"
#include "bsl_sal.h"

#define CRYPT_KDF_IMPL_METHOD_DECLARE(name)      \
    EAL_KdfMethod g_kdfMethod_##name = {         \
        (KdfNewCtx)CRYPT_##name##_NewCtxEx,  (KdfSetParam)CRYPT_##name##_SetParam,      \
        (KdfDerive)CRYPT_##name##_Derive,  (KdfDeinit)CRYPT_##name##_Deinit,            \
        NULL, (KdfFreeCtx)CRYPT_##name##_FreeCtx                                        \
    }

#ifdef HITLS_CRYPTO_PBKDF2
CRYPT_KDF_IMPL_METHOD_DECLARE(PBKDF2);
#endif

#ifdef HITLS_CRYPTO_HKDF
CRYPT_KDF_IMPL_METHOD_DECLARE(HKDF);
#endif

#ifdef HITLS_CRYPTO_KDFTLS12
CRYPT_KDF_IMPL_METHOD_DECLARE(KDFTLS12);
#endif

#ifdef HITLS_CRYPTO_SCRYPT
CRYPT_KDF_IMPL_METHOD_DECLARE(SCRYPT);
#endif

static const EAL_CidToKdfMeth ID_TO_KDF_METH_TABLE[] = {
#ifdef HITLS_CRYPTO_PBKDF2
    {CRYPT_KDF_PBKDF2,  &g_kdfMethod_PBKDF2},
#endif
#ifdef HITLS_CRYPTO_HKDF
    {CRYPT_KDF_HKDF,    &g_kdfMethod_HKDF},
#endif
#ifdef HITLS_CRYPTO_KDFTLS12
    {CRYPT_KDF_KDFTLS12,    &g_kdfMethod_KDFTLS12},
#endif
#ifdef HITLS_CRYPTO_SCRYPT
    {CRYPT_KDF_SCRYPT,    &g_kdfMethod_SCRYPT},
#endif
};

int32_t EAL_KdfFindMethod(CRYPT_KDF_AlgId id, EAL_KdfMethod *method)
{
    if (method == NULL) {
        return CRYPT_NULL_INPUT;
    }

    EAL_KdfMethod *pKdfMeth = NULL;
    uint32_t num = sizeof(ID_TO_KDF_METH_TABLE) / sizeof(ID_TO_KDF_METH_TABLE[0]);
    for (uint32_t i = 0; i < num; i++) {
        if (ID_TO_KDF_METH_TABLE[i].id == id) {
            pKdfMeth = ID_TO_KDF_METH_TABLE[i].kdfMeth;
            break;
        }
    }

    if (pKdfMeth == NULL) {
        return CRYPT_EAL_ERR_ALGID;
    }

    (void)memcpy_s(method, sizeof(EAL_KdfMethod), pKdfMeth, sizeof(EAL_KdfMethod));
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t SetKdfMethod(const CRYPT_EAL_Func *funcs, EAL_KdfMethod *method)
{
    int32_t index = 0;
    while (funcs[index].id != 0) {
        switch (funcs[index].id) {
            case CRYPT_EAL_IMPLKDF_NEWCTX:
                method->newCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLKDF_SETPARAM:
                method->setParam = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLKDF_DERIVE:
                method->derive = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLKDF_DEINITCTX:
                method->deinit = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLKDF_CTRL:
                method->ctrl = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLKDF_FREECTX:
                method->freeCtx = funcs[index].func;
                break;
            default:
                BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    return CRYPT_SUCCESS;
}

int32_t EAL_ProviderKdfFindMethod(CRYPT_KDF_AlgId id, void *libCtx, const char *attrName, EAL_KdfMethod *method,
    void **provCtx)
{
    if (method == NULL) {
        return CRYPT_NULL_INPUT;
    }

    const CRYPT_EAL_Func *funcs = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_KDF, id, attrName, &funcs, provCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return SetKdfMethod(funcs, method);
}
#endif // HITLS_CRYPTO_PROVIDER

#endif // HITLS_CRYPTO_EAL && HITLS_CRYPTO_KDF
