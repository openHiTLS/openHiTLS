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
#if defined(HITLS_CRYPTO_PKEY_EXCH) && defined(HITLS_CRYPTO_PROVIDER)

#include "crypt_eal_implprovider.h"
#include "crypt_curve25519.h"
#include "crypt_dh.h"
#include "crypt_ecdh.h"
#include "crypt_sm2.h"

#ifdef HITLS_CRYPTO_X25519
const CRYPT_EAL_Func g_defEalExchX25519[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (CRYPT_EAL_ImplPkeyExch)CRYPT_CURVE25519_ComputeSharedKey},
    CRYPT_EAL_FUNC_END
};
#endif

#ifdef HITLS_CRYPTO_DH
const CRYPT_EAL_Func g_defEalExchDh[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (CRYPT_EAL_ImplPkeyExch)CRYPT_DH_ComputeShareKey},
    CRYPT_EAL_FUNC_END
};
#endif

#ifdef HITLS_CRYPTO_ECDH
const CRYPT_EAL_Func g_defEalExchEcdh[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (CRYPT_EAL_ImplPkeyExch)CRYPT_ECDH_ComputeShareKey},
    CRYPT_EAL_FUNC_END
};
#endif

#ifdef HITLS_CRYPTO_SM2_EXCH
const CRYPT_EAL_Func g_defEalExchSm2[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (CRYPT_EAL_ImplPkeyExch)CRYPT_SM2_KapComputeKey},
    CRYPT_EAL_FUNC_END
};
#endif

#endif /* HITLS_CRYPTO_PKEY_EXCH && HITLS_CRYPTO_PROVIDER */