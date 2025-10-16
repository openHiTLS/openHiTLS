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
#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include "crypt_eal_implprovider.h"
#include "crypt_curve25519.h"
#include "crypt_dh.h"
#include "crypt_ecdh.h"
#include "crypt_sm2.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_iso_selftest.h"
#include "crypt_iso_provderimpl.h"
 
#define KEY_EXCH_FUNC(name)                                                                                     \
    static int32_t name##Wrapper(const CRYPT_Iso_Pkey_Ctx *prvKey, const CRYPT_Iso_Pkey_Ctx *pubKey,            \
        uint8_t *sharedKey, uint32_t *shareKeyLen)                                                              \
    {                                                                                                           \
        if (prvKey == NULL || pubKey == NULL) {                                                                 \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                               \
            return CRYPT_NULL_INPUT;                                                                            \
        }                                                                                                       \
        int32_t ret = CRYPT_Iso_Log(prvKey->provCtx, CRYPT_EVENT_KEYAGGREMENT, CRYPT_ALGO_PKEY, prvKey->algId); \
        if (ret != CRYPT_SUCCESS) {                                                                             \
            return ret;                                                                                         \
        }                                                                                                       \
        return (name)(prvKey->ctx, pubKey->ctx, sharedKey, shareKeyLen);                                        \
    }

#ifdef HITLS_CRYPTO_X25519
KEY_EXCH_FUNC(CRYPT_CURVE25519_ComputeSharedKey)
#endif
#ifdef HITLS_CRYPTO_DH
KEY_EXCH_FUNC(CRYPT_DH_ComputeShareKey)
#endif
#ifdef HITLS_CRYPTO_ECDH
KEY_EXCH_FUNC(CRYPT_ECDH_ComputeShareKey)
#endif
#ifdef HITLS_CRYPTO_SM2_EXCH
KEY_EXCH_FUNC(CRYPT_SM2_KapComputeKey)
#endif

const CRYPT_EAL_Func g_isoExchX25519[] = {
#ifdef HITLS_CRYPTO_X25519
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (CRYPT_EAL_ImplPkeyExch)CRYPT_CURVE25519_ComputeSharedKeyWrapper},
#endif
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_isoExchDh[] = {
#ifdef HITLS_CRYPTO_DH
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (CRYPT_EAL_ImplPkeyExch)CRYPT_DH_ComputeShareKeyWrapper},
#endif
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_isoExchEcdh[] = {
#ifdef HITLS_CRYPTO_ECDH
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (CRYPT_EAL_ImplPkeyExch)CRYPT_ECDH_ComputeShareKeyWrapper},
#endif
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_isoExchSm2[] = {
#if defined(HITLS_CRYPTO_SM2_EXCH)
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (CRYPT_EAL_ImplPkeyExch)CRYPT_SM2_KapComputeKeyWrapper},
#endif
    CRYPT_EAL_FUNC_END
};

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */