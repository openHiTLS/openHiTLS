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
#include "crypt_rsa.h"
#include "crypt_sm2.h"
#include "crypt_paillier.h"
#include "crypt_elgamal.h"

const CRYPT_EAL_Func g_defAsymCipherRsa[] = {
#ifdef HITLS_CRYPTO_RSA_ENCRYPT
    {CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, (CRYPT_EAL_ImplPkeyEncrypt)CRYPT_RSA_Encrypt},
#endif
#ifdef HITLS_CRYPTO_RSA_DECRYPT
    {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, (CRYPT_EAL_ImplPkeyDecrypt)CRYPT_RSA_Decrypt},
#endif
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_defAsymCipherSm2[] = {
#ifdef HITLS_CRYPTO_SM2_CRYPT
    {CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, (CRYPT_EAL_ImplPkeyEncrypt)CRYPT_SM2_Encrypt},
    {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, (CRYPT_EAL_ImplPkeyDecrypt)CRYPT_SM2_Decrypt},
#endif
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_defAsymCipherPaillier[] = {
#ifdef HITLS_CRYPTO_PAILLIER
    {CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, (CRYPT_EAL_ImplPkeyEncrypt)CRYPT_PAILLIER_Encrypt},
    {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, (CRYPT_EAL_ImplPkeyDecrypt)CRYPT_PAILLIER_Decrypt},
#endif
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_defAsymCipherElGamal[] = {
#ifdef HITLS_CRYPTO_ELGAMAL
    {CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, CRYPT_ELGAMAL_Encrypt},
    {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, CRYPT_ELGAMAL_Decrypt},
#endif
    CRYPT_EAL_FUNC_END
};

#endif /* HITLS_CRYPTO_PROVIDER */