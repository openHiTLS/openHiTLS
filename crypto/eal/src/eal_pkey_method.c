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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_PKEY)

#include "securec.h"
#include "crypt_local_types.h"
#include "crypt_algid.h"
#include "eal_pkey_local.h"
#ifdef HITLS_CRYPTO_RSA
#include "crypt_rsa.h"
#endif
#ifdef HITLS_CRYPTO_DSA
#include "crypt_dsa.h"
#endif
#ifdef HITLS_CRYPTO_CURVE25519
#include "crypt_curve25519.h"
#endif
#ifdef HITLS_CRYPTO_DH
#include "crypt_dh.h"
#endif
#ifdef HITLS_CRYPTO_ECDH
#include "crypt_ecdh.h"
#endif
#ifdef HITLS_CRYPTO_ECDSA
#include "crypt_ecdsa.h"
#endif
#ifdef HITLS_CRYPTO_SM2
#include "crypt_sm2.h"
#endif
#ifdef HITLS_CRYPTO_PAILLIER
#include "crypt_paillier.h"
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
#include "crypt_elgamal.h"
#endif
#ifdef HITLS_CRYPTO_KEM
#include "crypt_mlkem.h"
#endif
#ifdef HITLS_CRYPTO_MLDSA
#include "crypt_mldsa.h"
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
#include "crypt_slh_dsa.h"
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
#include "crypt_hybridkem.h"
#endif
#include "bsl_err_internal.h"
#include "crypt_types.h"
#include "crypt_errno.h"
#include "eal_common.h"
#include "bsl_sal.h"

#define EAL_PKEY_METHOD_DEFINE(id, \
    newCtx, dupCtx, freeCtx, setPara, getPara, gen, ctrl, setPub, setPrv, getPub, getPrv, sign, signData, verify, \
    verifyData, recover, computeShareKey, encrypt, decrypt, check, cmp, copyParam, encaps, decaps, blind, unBlind) { \
    id, (PkeyNew)(newCtx), (PkeyDup)(dupCtx), (PkeyFree)(freeCtx), \
    (PkeySetPara)(setPara), (PkeyGetPara)(getPara), (PkeyGen)(gen), (PkeyCtrl)(ctrl), \
    (PkeySetPub)(setPub), (PkeySetPrv)(setPrv), (PkeyGetPub)(getPub), (PkeyGetPrv)(getPrv), \
    (PkeySign)(sign), (PkeySignData)(signData), (PkeyVerify)(verify), (PkeyVerifyData)(verifyData), \
    (PkeyRecover)(recover), (PkeyComputeShareKey)(computeShareKey), \
    (PkeyCrypt)(encrypt), (PkeyCrypt)(decrypt), (PkeyCheck)(check), (PkeyCmp)(cmp), (PkeyCopyParam)(copyParam), \
    (PkeyEncapsulate)(encaps), (PkeyDecapsulate)(decaps), (PkeyBlind)(blind), (PkeyUnBlind)(unBlind)}

static const EAL_PkeyMethod METHODS[] = {
#ifdef HITLS_CRYPTO_DSA
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_DSA,
        CRYPT_DSA_NewCtx,
        CRYPT_DSA_DupCtx,
        CRYPT_DSA_FreeCtx,
        CRYPT_DSA_SetPara,
        CRYPT_DSA_GetPara,
        CRYPT_DSA_Gen,
        CRYPT_DSA_Ctrl,
        CRYPT_DSA_SetPubKey,
        CRYPT_DSA_SetPrvKey,
        CRYPT_DSA_GetPubKey,
        CRYPT_DSA_GetPrvKey,
        CRYPT_DSA_Sign,
        CRYPT_DSA_SignData,
        CRYPT_DSA_Verify,
        CRYPT_DSA_VerifyData,
        NULL, // recover
        NULL, // computeShareKey
        NULL, // encrypt
        NULL, // decrypt
        NULL, // check
        CRYPT_DSA_Cmp,
        NULL, // copyPara
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
        NULL, // blind
        NULL  // unBlind
    ), // CRYPT_PKEY_DSA
#endif
#ifdef HITLS_CRYPTO_ED25519
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_ED25519,
        CRYPT_ED25519_NewCtx,
        CRYPT_CURVE25519_DupCtx,
        CRYPT_CURVE25519_FreeCtx,
        NULL, // setPara
        NULL, // getPara
        CRYPT_ED25519_GenKey,
        CRYPT_CURVE25519_Ctrl,
        CRYPT_CURVE25519_SetPubKey,
        CRYPT_CURVE25519_SetPrvKey,
        CRYPT_CURVE25519_GetPubKey,
        CRYPT_CURVE25519_GetPrvKey,
        CRYPT_CURVE25519_Sign,
        NULL, // signData
        CRYPT_CURVE25519_Verify,
        NULL, // verifyData
        NULL, // recover
        NULL, // computeShareKey
        NULL, // encrypt
        NULL, // decrypt
        NULL, // check
        CRYPT_CURVE25519_Cmp,
        NULL, // copyPara
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
        NULL, // blind
        NULL  // unBlind
    ), // CRYPT_PKEY_ED25519
#endif
#ifdef HITLS_CRYPTO_X25519
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_X25519,
        CRYPT_X25519_NewCtx,
        CRYPT_CURVE25519_DupCtx,
        CRYPT_CURVE25519_FreeCtx,
        NULL, // setPara
        NULL, // getPara
        CRYPT_X25519_GenKey,
        CRYPT_CURVE25519_Ctrl,
        CRYPT_CURVE25519_SetPubKey,
        CRYPT_CURVE25519_SetPrvKey,
        CRYPT_CURVE25519_GetPubKey,
        CRYPT_CURVE25519_GetPrvKey,
        NULL, // sign
        NULL, // signData
        NULL, // verify
        NULL, // verifyData
        NULL, // recover
        CRYPT_CURVE25519_ComputeSharedKey,
        NULL, // encrypt
        NULL, // decrypt
        NULL, // check
        CRYPT_CURVE25519_Cmp,
        NULL, // copyPara
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
        NULL, // blind
        NULL  // unBlind
    ), // CRYPT_PKEY_X25519
#endif
#ifdef HITLS_CRYPTO_RSA
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_RSA,
        CRYPT_RSA_NewCtx,
        CRYPT_RSA_DupCtx,
        CRYPT_RSA_FreeCtx,
        CRYPT_RSA_SetPara,
        NULL, // getPara
#ifdef HITLS_CRYPTO_RSA_GEN
        CRYPT_RSA_Gen,
#else
        NULL, // gen
#endif
        CRYPT_RSA_Ctrl,
        CRYPT_RSA_SetPubKey,
        CRYPT_RSA_SetPrvKey,
        CRYPT_RSA_GetPubKey,
        CRYPT_RSA_GetPrvKey,
#ifdef HITLS_CRYPTO_RSA_SIGN
        CRYPT_RSA_Sign,
        CRYPT_RSA_SignData,
#else
        NULL, // sign
        NULL, // signData
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
        CRYPT_RSA_Verify,
        CRYPT_RSA_VerifyData,
        CRYPT_RSA_Recover,
#else
        NULL, // verify
        NULL, // verifyData
        NULL, // recover
#endif
        NULL, // computeShareKey
#ifdef HITLS_CRYPTO_RSA_ENCRYPT
        CRYPT_RSA_Encrypt,
#else
        NULL, // encrypt
#endif
#ifdef HITLS_CRYPTO_RSA_DECRYPT
        CRYPT_RSA_Decrypt,
#else
        NULL, // decrypt
#endif
        NULL, // check
        CRYPT_RSA_Cmp,
        NULL, // copyPara
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
#ifdef HITLS_CRYPTO_RSA_BSSA
#ifdef HITLS_CRYPTO_RSA_SIGN
        CRYPT_RSA_Blind, // blind
#else
        NULL, // blind
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
        CRYPT_RSA_UnBlind  // unBlind
#else
        NULL  // unBlind
#endif
#else
        NULL, // blind
        NULL  // unBlind
#endif
    ),
#endif
#ifdef HITLS_CRYPTO_DH
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_DH,
        CRYPT_DH_NewCtx,
        CRYPT_DH_DupCtx,
        CRYPT_DH_FreeCtx,
        CRYPT_DH_SetPara,
        CRYPT_DH_GetPara,
        CRYPT_DH_Gen,
        CRYPT_DH_Ctrl,
        CRYPT_DH_SetPubKey,
        CRYPT_DH_SetPrvKey,
        CRYPT_DH_GetPubKey,
        CRYPT_DH_GetPrvKey,
        NULL, // sign
        NULL, // signData
        NULL, // verify
        NULL, // verifyData
        NULL, // recover
        CRYPT_DH_ComputeShareKey,
        NULL, // encrypt
        NULL, // decrypt
        NULL,
        CRYPT_DH_Cmp,
        NULL,
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
        NULL, // blind
        NULL  // unBlind
    ),
#endif
#ifdef HITLS_CRYPTO_ECDSA
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_ECDSA,
        CRYPT_ECDSA_NewCtx,
        CRYPT_ECDSA_DupCtx,
        CRYPT_ECDSA_FreeCtx,
        CRYPT_ECDSA_SetPara,
        CRYPT_ECDSA_GetPara,
        CRYPT_ECDSA_Gen,
        CRYPT_ECDSA_Ctrl,
        CRYPT_ECDSA_SetPubKey,
        CRYPT_ECDSA_SetPrvKey,
        CRYPT_ECDSA_GetPubKey,
        CRYPT_ECDSA_GetPrvKey,
        CRYPT_ECDSA_Sign,
        CRYPT_ECDSA_SignData,
        CRYPT_ECDSA_Verify,
        CRYPT_ECDSA_VerifyData,
        NULL, // recover
        NULL, // computeShareKey
        NULL, // encrypt
        NULL, // decrypt
        NULL, // check
        CRYPT_ECDSA_Cmp,
        NULL, // copyPara
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
        NULL, // blind
        NULL  // unBlind
    ),
#endif
#ifdef HITLS_CRYPTO_ECDH
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_ECDH,
        CRYPT_ECDH_NewCtx,
        CRYPT_ECDH_DupCtx,
        CRYPT_ECDH_FreeCtx,
        CRYPT_ECDH_SetPara,
        CRYPT_ECDH_GetPara,
        CRYPT_ECDH_Gen,
        CRYPT_ECDH_Ctrl,
        CRYPT_ECDH_SetPubKey,
        CRYPT_ECDH_SetPrvKey,
        CRYPT_ECDH_GetPubKey,
        CRYPT_ECDH_GetPrvKey,
        NULL, // sign
        NULL, // signData
        NULL, // verify
        NULL, // verifyData
        NULL, // recover
        CRYPT_ECDH_ComputeShareKey,
        NULL, // encrypt
        NULL, // decrypt
        NULL, // check
        CRYPT_ECDH_Cmp,
        NULL, // copyPara
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
        NULL, // blind
        NULL  // unBlind
    ),
#endif
#ifdef HITLS_CRYPTO_SM2
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_SM2,
        CRYPT_SM2_NewCtx,
        CRYPT_SM2_DupCtx,
        CRYPT_SM2_FreeCtx,
        NULL,  // setPara
        NULL,  // getPara
        CRYPT_SM2_Gen,
        CRYPT_SM2_Ctrl,
        CRYPT_SM2_SetPubKey,
        CRYPT_SM2_SetPrvKey,
        CRYPT_SM2_GetPubKey,
        CRYPT_SM2_GetPrvKey,
#ifdef HITLS_CRYPTO_SM2_SIGN
        CRYPT_SM2_Sign,
        CRYPT_SM2_SignData,
        CRYPT_SM2_Verify,
        CRYPT_SM2_VerifyData,
#else
        NULL, // sign
        NULL, // signData
        NULL, // verify
        NULL, // verifyData
#endif
        NULL, // recover
#ifdef HITLS_CRYPTO_SM2_EXCH
        CRYPT_SM2_KapComputeKey,   // compute share key
#else
        NULL, // computeShareKey
#endif
#ifdef HITLS_CRYPTO_SM2_CRYPT
        CRYPT_SM2_Encrypt,   // encrypt
        CRYPT_SM2_Decrypt,   // decrypt
#else
        NULL, // encrypt
        NULL, // decrypt
#endif
        NULL,
        CRYPT_SM2_Cmp,
        NULL, // copyPara
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
        NULL, // blind
        NULL  // unBlind
    ), // CRYPT_PKEY_SM2
#endif
#ifdef HITLS_CRYPTO_PAILLIER
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_PAILLIER,
        CRYPT_PAILLIER_NewCtx,
        CRYPT_PAILLIER_DupCtx,
        CRYPT_PAILLIER_FreeCtx,
        CRYPT_PAILLIER_SetPara,
        NULL,
        CRYPT_PAILLIER_Gen,
        CRYPT_PAILLIER_Ctrl,
        CRYPT_PAILLIER_SetPubKey,
        CRYPT_PAILLIER_SetPrvKey,
        CRYPT_PAILLIER_GetPubKey,
        CRYPT_PAILLIER_GetPrvKey,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL, // recover
        NULL,
        CRYPT_PAILLIER_Encrypt,
        CRYPT_PAILLIER_Decrypt,
        NULL,
        NULL,  // cmp
        NULL, // copyPara
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
        NULL, // blind
        NULL  // unBlind
    ), // CRYPT_PKEY_PAILLIER
#endif
#ifdef HITLS_CRYPTO_ELGAMAL
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_ELGAMAL,
        CRYPT_ELGAMAL_NewCtx,
        CRYPT_ELGAMAL_DupCtx,
        CRYPT_ELGAMAL_FreeCtx,
        CRYPT_ELGAMAL_SetPara,
        NULL,
        CRYPT_ELGAMAL_Gen,
        CRYPT_ELGAMAL_Ctrl,
        CRYPT_ELGAMAL_SetPubKey,
        CRYPT_ELGAMAL_SetPrvKey,
        CRYPT_ELGAMAL_GetPubKey,
        CRYPT_ELGAMAL_GetPrvKey,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL, // recover
        NULL,
        CRYPT_ELGAMAL_Encrypt,
        CRYPT_ELGAMAL_Decrypt,
        NULL,
        NULL,  // cmp
        NULL, // copyPara
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
        NULL, // blind
        NULL  // unBlind
    ), // CRYPT_PKEY_ELGAMAL
#endif
#ifdef HITLS_CRYPTO_MLKEM
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_ML_KEM,
        CRYPT_ML_KEM_NewCtx,
        CRYPT_ML_KEM_DupCtx,
        CRYPT_ML_KEM_FreeCtx,
        NULL, // setPara
        NULL, // getPara
        CRYPT_ML_KEM_GenKey,
        CRYPT_ML_KEM_Ctrl,
        CRYPT_ML_KEM_SetEncapsKey,
        CRYPT_ML_KEM_SetDecapsKey,
        CRYPT_ML_KEM_GetEncapsKey,
        CRYPT_ML_KEM_GetDecapsKey,
        NULL, // sign
        NULL, // signData
        NULL, // verify
        NULL, // verifyData
        NULL, // recover
        NULL, // computeShareKey
        NULL, // encrypt
        NULL, // decrypt
        NULL, // check
        CRYPT_ML_KEM_Cmp,
        NULL, // copyPara
        CRYPT_ML_KEM_Encaps,
        CRYPT_ML_KEM_Decaps,
        NULL, // blind
        NULL  // unBlind
    ),
#endif
#ifdef HITLS_CRYPTO_MLDSA
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_ML_DSA,
        CRYPT_ML_DSA_NewCtx,
        CRYPT_ML_DSA_DupCtx,
        CRYPT_ML_DSA_FreeCtx,
        NULL, // setPara
        NULL, // getPara
        CRYPT_ML_DSA_GenKey,
        CRYPT_ML_DSA_Ctrl,
        CRYPT_ML_DSA_SetPubKey,
        CRYPT_ML_DSA_SetPrvKey,
        CRYPT_ML_DSA_GetPubKey,
        CRYPT_ML_DSA_GetPrvKey,
        CRYPT_ML_DSA_Sign, // sign
        NULL, // signData
        CRYPT_ML_DSA_Verify, // verify
		NULL, // verifyData
        NULL, // recover
        NULL, // computeShareKey
        NULL, // encrypt
        NULL, // decrypt
        NULL, // check
        CRYPT_ML_DSA_Cmp,
        NULL, // copyPara
        NULL, // pkeyEncaps
        NULL, // pkeyDecaps
        NULL, // blind
        NULL  // unBlind
    ),
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_SLH_DSA,
        CRYPT_SLH_DSA_NewCtx,
        NULL, // dupCtx
        CRYPT_SLH_DSA_FreeCtx,
        NULL, // setPara
        NULL, // getPara
        CRYPT_SLH_DSA_Gen,
        CRYPT_SLH_DSA_Ctrl,
        CRYPT_SLH_DSA_SetPubKey,
        CRYPT_SLH_DSA_SetPrvKey,
        CRYPT_SLH_DSA_GetPubKey,
        CRYPT_SLH_DSA_GetPrvKey,
        CRYPT_SLH_DSA_Sign,
        NULL,
        CRYPT_SLH_DSA_Verify,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    ),
#endif
#ifdef HITLS_CRYPTO_HYBRIDKEM
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_HYBRID_KEM,
        CRYPT_HYBRID_KEM_NewCtx,
        NULL,
        CRYPT_HYBRID_KEM_FreeCtx,
        NULL, // setPara
        NULL, // getPara
        CRYPT_HYBRID_KEM_GenKey,
        CRYPT_HYBRID_KEM_KeyCtrl,
        CRYPT_HYBRID_KEM_SetEncapsKey,
        CRYPT_HYBRID_KEM_SetDecapsKey,
        CRYPT_HYBRID_KEM_GetEncapsKey,
        CRYPT_HYBRID_KEM_GetDecapsKey,
        NULL, // sign
        NULL, // signData
        NULL, // verify
        NULL, // verifyData
        NULL, // recover
        NULL, // computeShareKey
        NULL, // encrypt
        NULL, // decrypt
        NULL, // check
        NULL,
        NULL, // copyPara
        CRYPT_HYBRID_KEM_Encaps,
        CRYPT_HYBRID_KEM_Decaps,
        NULL, // blind
        NULL  // unBlind
    ),
#endif
};

const EAL_PkeyMethod *CRYPT_EAL_PkeyFindMethod(CRYPT_PKEY_AlgId id)
{
    uint32_t num = sizeof(METHODS) / sizeof(METHODS[0]);
    const EAL_PkeyMethod *pkeyMeth = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (METHODS[i].id == id) {
            pkeyMeth = &METHODS[i];
            return pkeyMeth;
        }
    }
    return NULL;
}
#endif
