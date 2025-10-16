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
#if defined(HITLS_CRYPTO_PKEY_KEM) && defined(HITLS_CRYPTO_PROVIDER)

#include "crypt_eal_implprovider.h"
#ifdef HITLS_CRYPTO_MLKEM
#include "crypt_mlkem.h"
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
#include "crypt_hybridkem.h"
#endif

#ifdef HITLS_CRYPTO_MLKEM
const CRYPT_EAL_Func g_defEalMlKem[] = {
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE, (CRYPT_EAL_ImplPkeyKemEncapsulate)CRYPT_ML_KEM_Encaps},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE, (CRYPT_EAL_ImplPkeyKemDecapsulate)CRYPT_ML_KEM_Decaps},
    CRYPT_EAL_FUNC_END
};
#endif

#ifdef HITLS_CRYPTO_HYBRIDKEM
const CRYPT_EAL_Func g_defEalHybridKeyKem[] = {
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE, (CRYPT_EAL_ImplPkeyKemEncapsulate)CRYPT_HYBRID_KEM_Encaps},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE, (CRYPT_EAL_ImplPkeyKemDecapsulate)CRYPT_HYBRID_KEM_Decaps},
    CRYPT_EAL_FUNC_END
};
#endif
#endif
