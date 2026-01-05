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
#include "bsl_err_internal.h"
#include "eal_common.h"
#include "bsl_sal.h"

#define CRYPT_KDF_IMPL_METHOD_DECLARE(name)      \
    EAL_KdfMethod g_kdfMethod_##name = {         \
        (KdfNewCtx)CRYPT_##name##_NewCtx,  (KdfSetParam)CRYPT_##name##_SetParam,      \
        (KdfDerive)CRYPT_##name##_Derive,  (KdfDeinit)CRYPT_##name##_Deinit,          \
        (KdfFreeCtx)CRYPT_##name##_FreeCtx, NULL, (KdfDupCtx)CRYPT_##name##_DupCtx    \
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

const EAL_KdfMethod *EAL_KdfFindMethod(CRYPT_KDF_AlgId id)
{
    EAL_KdfMethod *pKdfMeth = NULL;
    uint32_t num = sizeof(ID_TO_KDF_METH_TABLE) / sizeof(ID_TO_KDF_METH_TABLE[0]);

    for (uint32_t i = 0; i < num; i++) {
        if (ID_TO_KDF_METH_TABLE[i].id == id) {
            pKdfMeth = ID_TO_KDF_METH_TABLE[i].kdfMeth;
            return pKdfMeth;
        }
    }

    return NULL;
}

#endif
