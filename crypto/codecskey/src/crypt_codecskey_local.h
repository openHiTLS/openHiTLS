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

#ifndef CRYPT_CODECSKEY_LOCAL_H
#define CRYPT_CODECSKEY_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CODECSKEY

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
#ifdef HITLS_CRYPTO_MLDSA
#include "crypt_mldsa.h"
#define MLDSA_SEED_BYTES_LEN 32
#endif
#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct {
    BSL_Buffer *derivekeyData;
    BSL_Buffer *ivData;
    BSL_Buffer *enData;
} EncryptPara;

typedef enum {
    CRYPT_RSA_PUB_N_IDX = 0,
    CRYPT_RSA_PUB_E_IDX = 1,
} CRYPT_RSA_PUB_TEMPL_IDX;

typedef enum {
    BSL_ASN1_TAG_ALGOID_IDX = 0,
    BSL_ASN1_TAG_ALGOID_ANY_IDX = 1,
} ALGOID_TEMPL_IDX;

typedef enum {
    CRYPT_SUBKEYINFO_ALGOID_IDX = 0,
    CRYPT_SUBKEYINFO_BITSTRING_IDX = 1,
} CRYPT_SUBKEYINFO_TEMPL_IDX;

typedef enum {
    CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX,
    CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX,
    CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX,
    CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX,
    CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX,
    CRYPT_PKCS_ENCPRIKEY_MAX
} CRYPT_PKCS_ENCPRIKEY_TEMPL_IDX;

typedef enum {
    CRYPT_ECPRIKEY_VERSION_IDX = 0,
    CRYPT_ECPRIKEY_PRIKEY_IDX = 1,
    CRYPT_ECPRIKEY_PARAM_IDX = 2,
    CRYPT_ECPRIKEY_PUBKEY_IDX = 3,
} CRYPT_ECPRIKEY_TEMPL_IDX;

typedef enum {
    CRYPT_ML_DSA_PRVKEY_SEED_IDX = 0,
    CRYPT_ML_DSA_PRVKEY_IDX = 1,
} CRYPT_ML_DSA_PRV_TEMPL_IDX;

typedef enum {
    CRYPT_RSA_PRV_VERSION_IDX = 0,
    CRYPT_RSA_PRV_N_IDX = 1,
    CRYPT_RSA_PRV_E_IDX = 2,
    CRYPT_RSA_PRV_D_IDX = 3,
    CRYPT_RSA_PRV_P_IDX = 4,
    CRYPT_RSA_PRV_Q_IDX = 5,
    CRYPT_RSA_PRV_DP_IDX = 6,
    CRYPT_RSA_PRV_DQ_IDX = 7,
    CRYPT_RSA_PRV_QINV_IDX = 8,
    CRYPT_RSA_PRV_OTHER_PRIME_IDX = 9
} CRYPT_RSA_PRV_TEMPL_IDX;

#define CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_HASH    0
#define CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_MASKGEN 1
#define CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_SALTLEN 2
#define CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_TRAILED 3

#define PATH_MAX_LEN 4096
#define PWD_MAX_LEN 4096

#ifdef HITLS_CRYPTO_KEY_DECODE

#ifdef HITLS_CRYPTO_RSA
int32_t ParseRsaPubkeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *param, CRYPT_EAL_PkeyCtx **ealPubKey, BslCid cid);

int32_t ParseRsaPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *rsaPssParam, BslCid cid, CRYPT_EAL_PkeyCtx **ealPriKey);
#endif

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
int32_t ParseEccPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *pk8AlgoParam, CRYPT_EAL_PkeyCtx **ealPriKey);
#endif

int32_t ParsePk8PriKeyBuff(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *buff,
    CRYPT_EAL_PkeyCtx **ealPriKey);

#ifdef HITLS_CRYPTO_KEY_EPKI
int32_t ParsePk8EncPriKeyBuff(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *buff, const BSL_Buffer *pwd,
    CRYPT_EAL_PkeyCtx **ealPriKey);

int32_t CRYPT_DECODE_Pkcs8PrvDecrypt(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *buff,
    const BSL_Buffer *pwd, BSL_ASN1_DecTemplCallBack keyInfoCb, BSL_Buffer *decode);

int32_t CRYPT_DECODE_ParseEncDataAsn1(CRYPT_EAL_LibCtx *libctx, const char *attrName, BslCid symAlg,
    EncryptPara *encPara, const BSL_Buffer *pwd, BSL_ASN1_DecTemplCallBack keyInfoCb, BSL_Buffer *decode);

#endif

int32_t CRYPT_EAL_ParseAsn1SubPubkey(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    void **ealPubKey, bool isComplete);

int32_t CRYPT_DECODE_AlgoIdAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_DecTemplCallBack keyInfoCb,
    BSL_ASN1_Buffer *algoId, uint32_t algoIdNum);

int32_t CRYPT_DECODE_ConstructBufferOutParam(const BSL_Param *inParam, BSL_Param **outParam, uint8_t *buffer,
    uint32_t bufferLen);

int32_t CRYPT_DECODE_ParseSubKeyInfo(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *pubAsn1, bool isComplete);

int32_t CRYPT_DECODE_PrikeyAsn1Buff(uint8_t *buffer, uint32_t bufferLen, BSL_ASN1_Buffer *asn1, uint32_t arrNum);

#ifdef HITLS_CRYPTO_RSA
int32_t CRYPT_DECODE_RsaPubkeyAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *pubAsn1, uint32_t arrNum);

int32_t CRYPT_DECODE_RsaPrikeyAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *asn1, uint32_t asn1Num);
#endif

#ifdef HITLS_CRYPTO_MLDSA
int32_t CRYPT_MLDSA_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen,
    CRYPT_ML_DSA_Ctx **pubKey, bool isComplete);
int32_t CRYPT_DECODE_MldsaPrikeyAsn1Buff(uint8_t *buffer, uint32_t bufferLen, BSL_ASN1_Buffer *asn1, uint32_t arrNum);
int32_t CRYPT_MLDSA_ParsePkcs8key(void *libCtx, uint8_t *buffer, uint32_t bufferLen,
    CRYPT_ML_DSA_Ctx **mldsaPriKey);
#endif
#endif


#ifdef HITLS_CRYPTO_KEY_ENCODE
#ifdef HITLS_CRYPTO_RSA
int32_t EncodeRsaPubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_ASN1_Buffer *pssParam, BSL_Buffer *encodePub);

int32_t EncodeRsaPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *encode);
#endif

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
int32_t EncodeEccPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_ASN1_Buffer *pk8AlgoParam, BSL_Buffer *encode);
int32_t CRYPT_ENCODE_EccPrikeyAsn1Buff(BSL_ASN1_Buffer *asn1, uint32_t asn1Num, BSL_Buffer *encode);
#endif

int32_t EncodePk8PriKeyBuff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *asn1);

int32_t CRYPT_ENCODE_SubPubkeyByInfo(BSL_ASN1_Buffer *algo, BSL_Buffer *bitStr, BSL_Buffer *encodeH,
    bool isComplete);

int32_t CRYPT_ENCODE_AlgoIdAsn1Buff(BSL_ASN1_Buffer *algoId, uint32_t algoIdNum, uint8_t **buff,
    uint32_t *buffLen);

int32_t CRYPT_ENCODE_PkcsEncryptedBuff(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_Pbkdf2Param *pkcsParam,
    BSL_Buffer *unEncrypted, BSL_ASN1_Buffer *asn1);

#ifdef HITLS_CRYPTO_KEY_EPKI
int32_t EncodePk8EncPriKeyBuff(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPriKey,
    const CRYPT_EncodeParam *encodeParam, BSL_Buffer *encode);
#endif

int32_t CRYPT_EAL_EncodeAsn1SubPubkey(CRYPT_EAL_PkeyCtx *ealPubKey, bool isComplete, BSL_Buffer *encodeH);

#ifdef HITLS_CRYPTO_RSA
int32_t CRYPT_ENCODE_RsaPrikeyAsn1Buff(BSL_ASN1_Buffer *asn1, uint32_t asn1Num, BSL_Buffer *encode);

int32_t CRYPT_ENCODE_RsaPubkeyAsn1Buff(BSL_ASN1_Buffer *pubAsn1, BSL_Buffer *encodePub);
#endif
#endif

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
static inline bool IsEcdsaEcParaId(int32_t paraId)
{
    return paraId == CRYPT_ECC_NISTP224 || paraId == CRYPT_ECC_NISTP256 ||
        paraId == CRYPT_ECC_NISTP384 || paraId == CRYPT_ECC_NISTP521 ||
        paraId == CRYPT_ECC_BRAINPOOLP256R1 || paraId == CRYPT_ECC_BRAINPOOLP384R1 ||
        paraId == CRYPT_ECC_BRAINPOOLP512R1;
}
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_CODECSKEY

#endif // CRYPT_CODECSKEY_LOCAL_H
