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
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_PKEY_SIGN)

#include "crypt_eal_implprovider.h"
#ifdef HITLS_CRYPTO_DSA
#include "crypt_dsa.h"
#endif
#if defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY)
#include "crypt_rsa.h"
#endif
#ifdef HITLS_CRYPTO_ECDSA
#include "crypt_ecdsa.h"
#endif
#ifdef HITLS_CRYPTO_SM2_SIGN
#include "crypt_sm2.h"
#endif
#ifdef HITLS_CRYPTO_ED25519
#include "crypt_curve25519.h"
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
#include "crypt_slh_dsa.h"
#endif
#ifdef HITLS_CRYPTO_MLDSA
#include "crypt_mldsa.h"
#endif

#ifdef HITLS_CRYPTO_DSA
const CRYPT_EAL_Func g_defEalSignDsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_DSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, (CRYPT_EAL_ImplPkeySignData)CRYPT_DSA_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_DSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, (CRYPT_EAL_ImplPkeyVerifyData)CRYPT_DSA_VerifyData},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_ED25519
const CRYPT_EAL_Func g_defEalSignEd25519[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_CURVE25519_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_CURVE25519_Verify},
    CRYPT_EAL_FUNC_END,
};
#endif

#if defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY)
const CRYPT_EAL_Func g_defEalSignRsa[] = {
#ifdef HITLS_CRYPTO_RSA_SIGN
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_RSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, (CRYPT_EAL_ImplPkeySignData)CRYPT_RSA_SignData},
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_RSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, (CRYPT_EAL_ImplPkeyVerifyData)CRYPT_RSA_VerifyData},
#ifdef HITLS_CRYPTO_RSA_RECOVER
    {CRYPT_EAL_IMPLPKEYSIGN_RECOVER, (CRYPT_EAL_ImplPkeyRecover)CRYPT_RSA_Recover},
#endif
#endif
#ifdef HITLS_CRYPTO_RSA_BSSA
#ifdef HITLS_CRYPTO_RSA_SIGN
    {CRYPT_EAL_IMPLPKEYSIGN_BLIND, (CRYPT_EAL_ImplPkeyBlind)CRYPT_RSA_Blind},
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
    {CRYPT_EAL_IMPLPKEYSIGN_UNBLIND, (CRYPT_EAL_ImplPkeyUnBlind)CRYPT_RSA_UnBlind},
#endif
#endif
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_ECDSA
const CRYPT_EAL_Func g_defEalSignEcdsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_ECDSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, (CRYPT_EAL_ImplPkeySignData)CRYPT_ECDSA_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_ECDSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, (CRYPT_EAL_ImplPkeyVerifyData)CRYPT_ECDSA_VerifyData},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_SM2_SIGN
const CRYPT_EAL_Func g_defEalSignSm2[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_SM2_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, (CRYPT_EAL_ImplPkeySignData)CRYPT_SM2_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_SM2_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, (CRYPT_EAL_ImplPkeyVerifyData)CRYPT_SM2_VerifyData},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_SLH_DSA
const CRYPT_EAL_Func g_defEalSignSlhDsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_SLH_DSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_SLH_DSA_Verify},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_MLDSA
const CRYPT_EAL_Func g_defEalSignMlDsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_ML_DSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_ML_DSA_Verify},
    CRYPT_EAL_FUNC_END,
};
#endif

#endif /* HITLS_CRYPTO_PROVIDER && HITLS_CRYPTO_PKEY_SIGN */