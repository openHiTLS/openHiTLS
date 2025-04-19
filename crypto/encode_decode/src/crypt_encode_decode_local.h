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

#ifndef CRYPT_EAL_ENCODE_LOCAL_H
#define CRYPT_EAL_ENCODE_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ENCODE_DECODE

#include "bsl_types.h"
#include "bsl_asn1.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct {
    BSL_Buffer *derivekeyData;
    BSL_Buffer *ivData;
    BSL_Buffer *enData;
} EncryptPara;

#define PATH_MAX_LEN 4096

#ifdef HITLS_CRYPTO_KEY_DECODE
int32_t ParseSubPubkeyAsn1(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_ASN1_Buffer *encode,
    CRYPT_EAL_PkeyCtx **ealPubKey);

int32_t ParseRsaPubkeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff,
    uint32_t buffLen, BSL_ASN1_Buffer *param, CRYPT_EAL_PkeyCtx **ealPubKey, BslCid cid);

int32_t ParseRsaPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *rsaPssParam, BslCid cid, CRYPT_EAL_PkeyCtx **ealPriKey);

int32_t ParseEccPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *pk8AlgoParam, CRYPT_EAL_PkeyCtx **ealPriKey);

int32_t ParsePk8PriKeyBuff(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *buff,
    CRYPT_EAL_PkeyCtx **ealPriKey);

#ifdef HITLS_CRYPTO_KEY_EPKI
int32_t ParsePk8EncPriKeyBuff(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *buff,
    const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPriKey);
#endif

int32_t CRYPT_EAL_ParseAsn1SubPubkey(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff,
    uint32_t buffLen, void **ealPubKey, bool isComplete);
#endif

#ifdef HITLS_CRYPTO_KEY_ENCODE
int32_t EncodeRsaPubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_ASN1_Buffer *pssParam, BSL_Buffer *encodePub);

int32_t EncodeRsaPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_PKEY_AlgId cid, BSL_Buffer *encode);

int32_t EncodeEccPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_ASN1_Buffer *pk8AlgoParam, BSL_Buffer *encode);

int32_t EncodePk8PriKeyBuff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *asn1);

#ifdef HITLS_CRYPTO_KEY_EPKI
int32_t EncodePk8EncPriKeyBuff(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPriKey,
    const CRYPT_EncodeParam *encodeParam, BSL_Buffer *encode);
#endif

int32_t CRYPT_EAL_EncodeAsn1SubPubkey(CRYPT_EAL_PkeyCtx *ealPubKey, bool isComplete, BSL_Buffer *encodeH);
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ENCODE_DECODE

#endif // CRYPT_EAL_ENCODE_LOCAL_H
