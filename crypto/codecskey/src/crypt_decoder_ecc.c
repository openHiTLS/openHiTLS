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
#if defined(HITLS_CRYPTO_KEY_DECODE_CHAIN) && \
    (defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2) || defined(HITLS_CRYPTO_ED25519))

#include "crypt_ecc.h"
#ifdef HITLS_CRYPTO_ECDSA
#include "crypt_ecdsa.h"
#endif
#ifdef HITLS_CRYPTO_SM2
#include "crypt_sm2.h"
#endif
#ifdef HITLS_CRYPTO_ED25519
#include "crypt_curve25519.h"
#endif
#include "crypt_params_key.h"
#include "bsl_asn1_internal.h"
#include "bsl_params.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_codecskey_local.h"
#include "crypt_codecskey.h"

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
typedef struct {
    int32_t version;
    BSL_ASN1_Buffer param;
    BSL_ASN1_Buffer prikey;
    BSL_ASN1_Buffer pubkey;
} CRYPT_DECODE_EccPrikeyInfo;

static int32_t ParsePrikeyAsn1Info(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *pk8AlgoParam,
    CRYPT_DECODE_EccPrikeyInfo *eccPrvInfo)
{
    BSL_ASN1_Buffer asn1[CRYPT_ECPRIKEY_PUBKEY_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_PrikeyAsn1Buff(buff, buffLen, asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    int32_t version;
    BSL_ASN1_Buffer *prikey = &asn1[CRYPT_ECPRIKEY_PRIKEY_IDX]; // the ECC OID
    BSL_ASN1_Buffer *ecParamOid = &asn1[CRYPT_ECPRIKEY_PARAM_IDX]; // the parameters OID
    BSL_ASN1_Buffer *pubkey = &asn1[CRYPT_ECPRIKEY_PUBKEY_IDX]; // the ECC OID
    BSL_ASN1_Buffer *param = pk8AlgoParam;
    if (ecParamOid->len != 0) {
        // has a valid Algorithm param
        param = ecParamOid;
    } else {
        if (param == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
            return CRYPT_NULL_INPUT;
        }
        if (param->len == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM);
            return CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM;
        }
    }
    if (pubkey->len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ASN1_BUFF_FAILED);
        return CRYPT_DECODE_ASN1_BUFF_FAILED;
    }

    ret = BSL_ASN1_DecodePrimitiveItem(&asn1[CRYPT_ECPRIKEY_VERSION_IDX], &version);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    eccPrvInfo->version = version;
    eccPrvInfo->param = *param;
    eccPrvInfo->prikey = *prikey;
    eccPrvInfo->pubkey = *pubkey;
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_ECDSA || HITLS_CRYPTO_SM2

#ifdef HITLS_CRYPTO_ECDSA
// ecdh is not considered, and it will be improved in the future
static int32_t EccKeyNew(void *libCtx, BSL_ASN1_Buffer *ecParamOid, void **ecKey)
{
    int32_t paraId = BSL_OBJ_GetCidFromOidBuff(ecParamOid->buff, ecParamOid->len);
    if (!IsEcdsaEcParaId(paraId)) {
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    CRYPT_ECDSA_Ctx *key = CRYPT_ECDSA_NewCtxEx(libCtx);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = ECC_SetPara(key, ECC_NewPara(paraId));
    if (ret != CRYPT_SUCCESS) {
        ECC_FreeCtx(key);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ecKey = (void *)key;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ECC_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, void **pubKey, bool isComplete)
{
    if (buff == NULL || buffLen == 0 || pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    void *pctx = NULL;
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (subPubkeyInfo.keyType != BSL_CID_EC_PUBLICKEY) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    ret = EccKeyNew(libCtx, &subPubkeyInfo.keyParam, &pctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Param pubParam[2] = {
        {CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo.pubKey.buff,
            subPubkeyInfo.pubKey.len, 0},
        BSL_PARAM_END
    };
    ret = ECC_PkeySetPubKeyEx(pctx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        ECC_FreeCtx(pctx);
        return ret;
    }
    *pubKey = (void *)pctx;
    return ret;
}

int32_t CRYPT_ECC_ParsePrikeyAsn1Buff(void *libCtx, uint8_t *buffer, uint32_t bufferLen, BSL_ASN1_Buffer *pk8AlgoParam,
    void **ecPriKey)
{
    if (buffer == NULL || bufferLen == 0 || ecPriKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    CRYPT_DECODE_EccPrikeyInfo eccPrvInfo = {0};
    int32_t ret = ParsePrikeyAsn1Info(buffer, bufferLen, pk8AlgoParam, &eccPrvInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    void *pctx = NULL;
    ret = EccKeyNew(libCtx, &eccPrvInfo.param, &pctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Param pubParam[2] = {
        {CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, (eccPrvInfo.pubkey.buff + 1),
            eccPrvInfo.pubkey.len - 1, 0},
        BSL_PARAM_END
    };
    ret = ECC_PkeySetPubKeyEx(pctx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    BSL_Param prvParam[2] = {
        {CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, eccPrvInfo.prikey.buff, eccPrvInfo.prikey.len, 0},
        BSL_PARAM_END
    };
    ret = ECC_PkeySetPrvKeyEx(pctx, prvParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    *ecPriKey = pctx;
    return ret;
ERR:
    ECC_FreeCtx(pctx);
    return ret;
}

int32_t CRYPT_ECC_ParsePkcs8Key(void *libCtx, uint8_t *buff, uint32_t buffLen, void **ecdsaPriKey)
{
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8Info(buff, buffLen, NULL, &pk8PrikeyInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (pk8PrikeyInfo.keyType != BSL_CID_EC_PUBLICKEY) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    ret = CRYPT_ECC_ParsePrikeyAsn1Buff(libCtx, pk8PrikeyInfo.pkeyRawKey, pk8PrikeyInfo.pkeyRawKeyLen,
        &pk8PrikeyInfo.keyParam, ecdsaPriKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_CRYPTO_ECDSA
#ifdef HITLS_CRYPTO_SM2
static int32_t Sm2KeyNew(void *libCtx, BSL_ASN1_Buffer *ecParamOid, CRYPT_SM2_Ctx **ecKey)
{
    CRYPT_SM2_Ctx *key = NULL;
    int32_t paraId = BSL_OBJ_GetCidFromOidBuff(ecParamOid->buff, ecParamOid->len);
    if (paraId != CRYPT_ECC_SM2) {
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    key = CRYPT_SM2_NewCtxEx(libCtx);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    *ecKey = key;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM2_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_SM2_Ctx **pubKey,
    bool isComplete)
{
    if (buff == NULL || buffLen == 0 || pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    CRYPT_SM2_Ctx *pctx = NULL;
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (subPubkeyInfo.keyType != BSL_CID_EC_PUBLICKEY && subPubkeyInfo.keyType != BSL_CID_SM2PRIME256) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    ret = Sm2KeyNew(libCtx, &subPubkeyInfo.keyParam, &pctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Param pubParam[2] = {
        {CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo.pubKey.buff,
            subPubkeyInfo.pubKey.len, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_SM2_SetPubKeyEx(pctx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_SM2_FreeCtx(pctx);
        return ret;
    }
    *pubKey = pctx;
    return ret;
}

int32_t CRYPT_SM2_ParsePrikeyAsn1Buff(void *libCtx, uint8_t *buffer, uint32_t bufferLen, BSL_ASN1_Buffer *pk8AlgoParam,
    CRYPT_SM2_Ctx **sm2PriKey)
{
    CRYPT_DECODE_EccPrikeyInfo eccPrvInfo = {0};
    int32_t ret = ParsePrikeyAsn1Info(buffer, bufferLen, pk8AlgoParam, &eccPrvInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_SM2_Ctx *pctx = NULL;
    ret = Sm2KeyNew(libCtx, &eccPrvInfo.param, &pctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Param pubParam[2] = {
        {CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, eccPrvInfo.pubkey.buff + 1,
            eccPrvInfo.pubkey.len - 1, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_SM2_SetPubKeyEx(pctx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    BSL_Param prvParam[2] = {
        {CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, eccPrvInfo.prikey.buff, eccPrvInfo.prikey.len, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_SM2_SetPrvKeyEx(pctx, prvParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    *sm2PriKey = pctx;
    return ret;
ERR:
    CRYPT_SM2_FreeCtx(pctx);
    return ret;
}

int32_t CRYPT_SM2_ParsePkcs8Key(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_SM2_Ctx **sm2PriKey)
{
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8Info(buff, buffLen, NULL, &pk8PrikeyInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (pk8PrikeyInfo.keyType != BSL_CID_EC_PUBLICKEY) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    ret = CRYPT_SM2_ParsePrikeyAsn1Buff(libCtx, pk8PrikeyInfo.pkeyRawKey, pk8PrikeyInfo.pkeyRawKeyLen,
        &pk8PrikeyInfo.keyParam, sm2PriKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_CRYPTO_SM2

#ifdef HITLS_CRYPTO_ED25519
static int32_t ParseEd25519PrikeyAsn1Buff(void *libCtx, uint8_t *buffer, uint32_t bufferLen,
    CRYPT_CURVE25519_Ctx **ed25519PriKey)
{
    uint8_t *tmpBuff = buffer;
    uint32_t tmpBuffLen = bufferLen;

    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &tmpBuff, &tmpBuffLen, &tmpBuffLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    CRYPT_CURVE25519_Ctx *pctx = CRYPT_ED25519_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_Param prvParam[2] = {
        {CRYPT_PARAM_CURVE25519_PRVKEY, BSL_PARAM_TYPE_OCTETS, tmpBuff, tmpBuffLen, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_CURVE25519_SetPrvKeyEx(pctx, prvParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_CURVE25519_FreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ed25519PriKey = pctx;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ED25519_ParsePkcs8Key(void *libCtx, uint8_t *buffer, uint32_t bufferLen,
    CRYPT_CURVE25519_Ctx **ed25519PriKey)
{
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8Info(buffer, bufferLen, NULL, &pk8PrikeyInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (pk8PrikeyInfo.keyType != BSL_CID_ED25519) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    return ParseEd25519PrikeyAsn1Buff(libCtx, pk8PrikeyInfo.pkeyRawKey, pk8PrikeyInfo.pkeyRawKeyLen, ed25519PriKey);
}

int32_t CRYPT_ED25519_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen,
    CRYPT_CURVE25519_Ctx **pubKey, bool isComplete)
{
    if (buff == NULL || buffLen == 0 || pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (subPubkeyInfo.keyType != BSL_CID_ED25519) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    CRYPT_CURVE25519_Ctx *pctx = CRYPT_ED25519_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_Param pubParam[2] = {
        {CRYPT_PARAM_CURVE25519_PUBKEY, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo.pubKey.buff, subPubkeyInfo.pubKey.len, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_CURVE25519_SetPubKeyEx(pctx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_CURVE25519_FreeCtx(pctx);
        return ret;
    }
    *pubKey = pctx;
    return ret;
}
#endif // HITLS_CRYPTO_ED25519
#endif
