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

#ifndef CRYPT_DECODER_LOCAL_H
#define CRYPT_DECODER_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN

#include "bsl_types.h"
#include "bsl_asn1.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"

#ifdef HITLS_CRYPTO_RSA
#include "crypt_rsa.h"
#endif
#ifdef HITLS_CRYPTO_SM2
#include "crypt_sm2.h"
#endif
#ifdef HITLS_CRYPTO_ED25519
#include "crypt_curve25519.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#ifdef HITLS_CRYPTO_RSA
int32_t CRYPT_RSA_ParsePubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *param,
    CRYPT_RSA_Ctx **rsaPubKey, BslCid cid);
int32_t CRYPT_RSA_ParsePkcs8Key(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_RSA_Ctx **rsaPriKey);

int32_t CRYPT_RSA_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_RSA_Ctx **pubKey,
    bool isComplete);

int32_t CRYPT_RSA_ParsePrikeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *rsaPssParam,
    CRYPT_RSA_Ctx **rsaPriKey);
#endif

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_ECDH)
int32_t CRYPT_ECC_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, void **pubKey, bool isComplete);

int32_t CRYPT_ECC_ParsePkcs8Key(void *libCtx, uint8_t *buff, uint32_t buffLen, void **ecdsaPriKey);

int32_t CRYPT_ECC_ParsePrikeyAsn1Buff(void *libCtx, uint8_t *buffer, uint32_t bufferLen, BSL_ASN1_Buffer *pk8AlgoParam,
    void **ecPriKey);
#endif

#ifdef HITLS_CRYPTO_SM2
int32_t CRYPT_SM2_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_SM2_Ctx **pubKey,
    bool isComplete);
int32_t CRYPT_SM2_ParsePrikeyAsn1Buff(void *libCtx, uint8_t *buffer, uint32_t bufferLen, BSL_ASN1_Buffer *pk8AlgoParam,
    CRYPT_SM2_Ctx **sm2PriKey);
int32_t CRYPT_SM2_ParsePkcs8Key(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_SM2_Ctx **sm2PriKey);
#endif

#ifdef HITLS_CRYPTO_ED25519
int32_t CRYPT_ED25519_ParsePkcs8Key(void *libCtx, uint8_t *buffer, uint32_t bufferLen,
    CRYPT_CURVE25519_Ctx **ed25519PriKey);
int32_t CRYPT_ED25519_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen,
    CRYPT_CURVE25519_Ctx **pubKey, bool isComplete);
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_KEY_DECODE_CHAIN

#endif // CRYPT_DECODER_LOCAL_H
