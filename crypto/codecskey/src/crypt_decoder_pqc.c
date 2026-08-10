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
#if defined(HITLS_CRYPTO_KEY_DECODE_CHAIN) &&                                                       \
    (defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_MLKEM) || defined(HITLS_CRYPTO_SLH_DSA) || \
        defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT))

#include <string.h>

#ifdef HITLS_CRYPTO_MLDSA
#include "crypt_mldsa.h"
#endif

#ifdef HITLS_CRYPTO_SLH_DSA
#include "crypt_slh_dsa.h"
#endif

#ifdef HITLS_CRYPTO_MLKEM
#include "crypt_mlkem.h"
#endif

#ifdef HITLS_CRYPTO_XMSS
#include "crypt_xmss.h"
#endif
#ifdef HITLS_CRYPTO_XMSSMT
#include "crypt_xmssmt.h"
#endif

#include "crypt_params_key.h"
#include "bsl_asn1_internal.h"
#include "bsl_params.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_codecskey_local.h"
#include "crypt_codecskey.h"

#ifdef HITLS_CRYPTO_MLDSA
static int32_t MldsaCheckPkcs8PublicKey(const CRYPT_ENCODE_DECODE_Pk8PrikeyInfo *info, CRYPT_ML_DSA_Ctx *pctx)
{
    uint32_t publicKeyLen = 0;
    int32_t ret = CRYPT_ML_DSA_Ctrl(pctx, CRYPT_CTRL_GET_PUBKEY_LEN, &publicKeyLen, sizeof(publicKeyLen));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (publicKeyLen != info->publicKey.len) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_PAIRWISE_CHECK_FAIL);
        return CRYPT_MLDSA_PAIRWISE_CHECK_FAIL;
    }
    uint8_t *publicKey = BSL_SAL_Malloc(publicKeyLen);
    if (publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_Param publicKeyParam[2] = {
        {CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, publicKey, publicKeyLen, 0},
        BSL_PARAM_END,
    };
    ret = CRYPT_ML_DSA_GetPubKeyEx(pctx, publicKeyParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(publicKey);
        return ret;
    }
    if (memcmp(publicKey, info->publicKey.buff, publicKeyLen) != 0) {
        ret = CRYPT_MLDSA_PAIRWISE_CHECK_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_Free(publicKey);
    return ret;
}

int32_t CRYPT_MLDSA_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_ML_DSA_Ctx **pubKey,
    bool isComplete)
{
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bool isMldsaPubkey = (subPubkeyInfo.keyType == BSL_CID_ML_DSA_44 || subPubkeyInfo.keyType == BSL_CID_ML_DSA_65 ||
        subPubkeyInfo.keyType == BSL_CID_ML_DSA_87);
    if (!isMldsaPubkey) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    CRYPT_ML_DSA_Ctx *pctx = CRYPT_ML_DSA_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_Param pubParam[2] = {
        {CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo.pubKey.buff, subPubkeyInfo.pubKey.len, 0},
        BSL_PARAM_END
    };
    int32_t keyType = (int32_t)subPubkeyInfo.keyType;
    ret = CRYPT_ML_DSA_Ctrl(pctx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&keyType, sizeof(keyType));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ML_DSA_FreeCtx(pctx);
        return ret;
    }
    ret = CRYPT_ML_DSA_SetPubKeyEx(pctx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_ML_DSA_FreeCtx(pctx);
        return ret;
    }
    *pubKey = pctx;
    return ret;
}

int32_t CRYPT_MLDSA_ParsePkcs8key(void *libCtx, uint8_t *buffer, uint32_t bufferLen, CRYPT_ML_DSA_Ctx **mldsaPriKey)
{
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8Info(buffer, bufferLen, NULL, &pk8PrikeyInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bool isMldsaKey = (pk8PrikeyInfo.keyType == BSL_CID_ML_DSA_44 || pk8PrikeyInfo.keyType == BSL_CID_ML_DSA_65 ||
        pk8PrikeyInfo.keyType == BSL_CID_ML_DSA_87);
    if (!isMldsaKey) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    uint8_t *tmpBuff = pk8PrikeyInfo.pkeyRawKey;
    uint32_t tmpBuffLen = pk8PrikeyInfo.pkeyRawKeyLen;
    BSL_ASN1_Buffer asn1[CRYPT_ML_DSA_PRVKEY_IDX + 1] = {0};
    ret = CRYPT_DECODE_MldsaPrikeyAsn1Buff(tmpBuff, tmpBuffLen, asn1, CRYPT_ML_DSA_PRVKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *prvKeyBuff = asn1[CRYPT_ML_DSA_PRVKEY_IDX].buff;
    uint32_t prvKeyBuffLen = asn1[CRYPT_ML_DSA_PRVKEY_IDX].len;
    uint8_t *seedBuff = asn1[CRYPT_ML_DSA_PRVKEY_SEED_IDX].buff;
    uint32_t seedBuffLen = asn1[CRYPT_ML_DSA_PRVKEY_SEED_IDX].len;
    CRYPT_ML_DSA_Ctx *pctx = CRYPT_ML_DSA_NewCtxEx(libCtx);
    if (pctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t keyType = (int32_t)pk8PrikeyInfo.keyType;
    ret = CRYPT_ML_DSA_Ctrl(pctx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&keyType, sizeof(keyType));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ML_DSA_FreeCtx(pctx);
        return ret;
    }
    BSL_Param priParam[3] = {
        {CRYPT_PARAM_ML_DSA_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyBuff, prvKeyBuffLen, 0},
        {CRYPT_PARAM_ML_DSA_PRVKEY_SEED, BSL_PARAM_TYPE_OCTETS, seedBuff, seedBuffLen, 0},
        BSL_PARAM_END,
    };
    ret = CRYPT_ML_DSA_SetPrvKeyEx(pctx, priParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ML_DSA_FreeCtx(pctx);
        return ret;
    }
    if (pk8PrikeyInfo.publicKey.buff != NULL) {
        ret = MldsaCheckPkcs8PublicKey(&pk8PrikeyInfo, pctx);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_ML_DSA_FreeCtx(pctx);
            return ret;
        }
    }
    *mldsaPriKey = pctx;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_MLDSA

#ifdef HITLS_CRYPTO_SLH_DSA

static inline bool IsSlhDsaKeyType(BslCid keyType)
{
    switch (keyType) {
        case BSL_CID_SLH_DSA_SHA2_128S:
        case BSL_CID_SLH_DSA_SHAKE_128S:
        case BSL_CID_SLH_DSA_SHA2_128F:
        case BSL_CID_SLH_DSA_SHAKE_128F:
        case BSL_CID_SLH_DSA_SHA2_192S:
        case BSL_CID_SLH_DSA_SHAKE_192S:
        case BSL_CID_SLH_DSA_SHA2_192F:
        case BSL_CID_SLH_DSA_SHAKE_192F:
        case BSL_CID_SLH_DSA_SHA2_256S:
        case BSL_CID_SLH_DSA_SHAKE_256S:
        case BSL_CID_SLH_DSA_SHA2_256F:
        case BSL_CID_SLH_DSA_SHAKE_256F:
        case BSL_CID_HASH_SLH_DSA_SHA2_128S_WITH_SHA256:
        case BSL_CID_HASH_SLH_DSA_SHA2_128F_WITH_SHA256:
        case BSL_CID_HASH_SLH_DSA_SHA2_192S_WITH_SHA512:
        case BSL_CID_HASH_SLH_DSA_SHA2_192F_WITH_SHA512:
        case BSL_CID_HASH_SLH_DSA_SHA2_256S_WITH_SHA512:
        case BSL_CID_HASH_SLH_DSA_SHA2_256F_WITH_SHA512:
        case BSL_CID_HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128:
        case BSL_CID_HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128:
        case BSL_CID_HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256:
        case BSL_CID_HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256:
        case BSL_CID_HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256:
        case BSL_CID_HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256:
            return true;
        default:
            return false;
    }
}

int32_t CRYPT_SLHDSA_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, CryptSlhDsaCtx **pubKey,
    bool isComplete)
{
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (!IsSlhDsaKeyType(subPubkeyInfo.keyType)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    CryptSlhDsaCtx *pctx = CRYPT_SLH_DSA_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t halfLen = subPubkeyInfo.pubKey.len / 2;
    BSL_Param pubParam[3] = {
        {CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo.pubKey.buff, halfLen, 0},
        {CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo.pubKey.buff + halfLen, halfLen, 0},
        BSL_PARAM_END
    };
    int32_t keyType = (int32_t)subPubkeyInfo.keyType;
    ret = CRYPT_SLH_DSA_Ctrl(pctx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&keyType, sizeof(keyType));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_SLH_DSA_FreeCtx(pctx);
        return ret;
    }
    ret = CRYPT_SLH_DSA_SetPubKeyEx(pctx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_SLH_DSA_FreeCtx(pctx);
        return ret;
    }
    *pubKey = pctx;
    return ret;
}

int32_t CRYPT_SLHDSA_ParsePkcs8key(void *libCtx, uint8_t *buffer, uint32_t bufferLen, CryptSlhDsaCtx **slhDsaPriKey)
{
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8Info(buffer, bufferLen, NULL, &pk8PrikeyInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (!IsSlhDsaKeyType(pk8PrikeyInfo.keyType)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    uint8_t *rawKeyBuff = pk8PrikeyInfo.pkeyRawKey;
    uint32_t rawKeyBuffLen = pk8PrikeyInfo.pkeyRawKeyLen;

    CryptSlhDsaCtx *pctx = CRYPT_SLH_DSA_NewCtxEx(libCtx);
    if (pctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t keyType = (int32_t)pk8PrikeyInfo.keyType;
    ret = CRYPT_SLH_DSA_Ctrl(pctx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&keyType, sizeof(keyType));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_SLH_DSA_FreeCtx(pctx);
        return ret;
    }
    uint32_t n = 0;
    ret = CRYPT_SLH_DSA_Ctrl(pctx, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &n, sizeof(n));
    if (ret != CRYPT_SUCCESS || rawKeyBuffLen != 4 * n) {
        CRYPT_SLH_DSA_FreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
        return CRYPT_SLHDSA_ERR_INVALID_KEYLEN;
    }
    if (pk8PrikeyInfo.publicKey.buff != NULL &&
        (pk8PrikeyInfo.publicKey.len != 2 * n ||
            memcmp(pk8PrikeyInfo.publicKey.buff, rawKeyBuff + 2 * n, 2 * n) != 0)) {
        CRYPT_SLH_DSA_FreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL);
        return CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL;
    }
    BSL_Param priParam[5] = {
        {CRYPT_PARAM_SLH_DSA_PRV_SEED, BSL_PARAM_TYPE_OCTETS, rawKeyBuff, n, 0},
        {CRYPT_PARAM_SLH_DSA_PRV_PRF, BSL_PARAM_TYPE_OCTETS, rawKeyBuff + n, n, 0},
        {CRYPT_PARAM_SLH_DSA_PUB_SEED, BSL_PARAM_TYPE_OCTETS, rawKeyBuff + n * 2, n, 0},
        {CRYPT_PARAM_SLH_DSA_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, rawKeyBuff + n * 3, n, 0},
        BSL_PARAM_END,
    };
    ret = CRYPT_SLH_DSA_SetPrvKeyEx(pctx, priParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_SLH_DSA_FreeCtx(pctx);
        return ret;
    }
#ifdef HITLS_CRYPTO_SLH_DSA_CHECK
    if (pk8PrikeyInfo.publicKey.buff != NULL) {
        ret = CRYPT_SLH_DSA_Check(CRYPT_PKEY_CHECK_PRVKEY, pctx, NULL);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_SLH_DSA_FreeCtx(pctx);
            return ret;
        }
    }
#endif
    *slhDsaPriKey = pctx;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_SLH_DSA

#ifdef HITLS_CRYPTO_MLKEM

static inline bool IsMlKemKeyType(BslCid keyType)
{
    return keyType == BSL_CID_ML_KEM_512 || keyType == BSL_CID_ML_KEM_768 || keyType == BSL_CID_ML_KEM_1024;
}

int32_t CRYPT_MLKEM_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_ML_KEM_Ctx **pubKey,
    bool isComplete)
{
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (!IsMlKemKeyType(subPubkeyInfo.keyType)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    CRYPT_ML_KEM_Ctx *pctx = CRYPT_ML_KEM_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_Param pubParam[2] = {
        {CRYPT_PARAM_ML_KEM_PUBKEY, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo.pubKey.buff, subPubkeyInfo.pubKey.len, 0},
        BSL_PARAM_END
    };
    int32_t keyType = (int32_t)subPubkeyInfo.keyType;
    ret = CRYPT_ML_KEM_Ctrl(pctx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&keyType, sizeof(keyType));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ML_KEM_FreeCtx(pctx);
        return ret;
    }
    ret = CRYPT_ML_KEM_SetEncapsKeyEx(pctx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_ML_KEM_FreeCtx(pctx);
        return ret;
    }
    *pubKey = pctx;
    return ret;
}

int32_t CRYPT_MLKEM_ParsePkcs8key(void *libCtx, uint8_t *buffer, uint32_t bufferLen, CRYPT_ML_KEM_Ctx **mlkemPriKey)
{
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8Info(buffer, bufferLen, NULL, &pk8PrikeyInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (!IsMlKemKeyType(pk8PrikeyInfo.keyType)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    uint8_t *tmpBuff = pk8PrikeyInfo.pkeyRawKey;
    uint32_t tmpBuffLen = pk8PrikeyInfo.pkeyRawKeyLen;
    BSL_ASN1_Buffer asn1[CRYPT_ML_KEM_PRVKEY_IDX + 1] = {0};
    ret = CRYPT_DECODE_MlkemPrikeyAsn1Buff(tmpBuff, tmpBuffLen, asn1, CRYPT_ML_KEM_PRVKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *decapsKeyBuff = asn1[CRYPT_ML_KEM_PRVKEY_IDX].buff;
    uint32_t decapsKeyBuffLen = asn1[CRYPT_ML_KEM_PRVKEY_IDX].len;
    uint8_t *seedBuff = asn1[CRYPT_ML_KEM_PRVKEY_SEED_IDX].buff;
    uint32_t seedBuffLen = asn1[CRYPT_ML_KEM_PRVKEY_SEED_IDX].len;

    CRYPT_ML_KEM_Ctx *pctx = CRYPT_ML_KEM_NewCtxEx(libCtx);
    if (pctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t keyType = (int32_t)pk8PrikeyInfo.keyType;
    ret = CRYPT_ML_KEM_Ctrl(pctx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&keyType, sizeof(keyType));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ML_KEM_FreeCtx(pctx);
        return ret;
    }
    BSL_Param priParam[3] = {
        {CRYPT_PARAM_ML_KEM_PRVKEY, BSL_PARAM_TYPE_OCTETS, decapsKeyBuff, decapsKeyBuffLen, 0},
        {CRYPT_PARAM_ML_KEM_PRVKEY_SEED, BSL_PARAM_TYPE_OCTETS, seedBuff, seedBuffLen, 0}, BSL_PARAM_END
    };
    ret = CRYPT_ML_KEM_SetDecapsKeyEx(pctx, priParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ML_KEM_FreeCtx(pctx);
        return ret;
    }
    ret = CRYPT_ML_KEM_PrvKeyValidCheck(pctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ML_KEM_FreeCtx(pctx);
        return ret;
    }
    *mlkemPriKey = pctx;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_MLKEM

#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT)
static int32_t XmssDecodeSubPubkeyInfo(uint8_t *buff, uint32_t buffLen, bool isComplete, BslCid expectedType,
    CRYPT_DECODE_SubPubkeyInfo *subPubkeyInfo)
{
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (subPubkeyInfo->keyType != expectedType) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    if (subPubkeyInfo->pubKey.len <= 4 || (subPubkeyInfo->pubKey.len - 4) % 2 != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_KEY);
        return CRYPT_XMSS_ERR_INVALID_KEY;
    }
    return CRYPT_SUCCESS;
}

typedef struct {
    void *libCtx;
    uint8_t *buff;
    uint32_t buffLen;
    bool isComplete;
    BslCid expectedType;
} XmssSubPubkeyParseInput;

static int32_t XmssSetCtxFromSubPubkey(void *libCtx, const CRYPT_DECODE_SubPubkeyInfo *subPubkeyInfo, void **pubKey)
{
    uint32_t hashLen = (subPubkeyInfo->pubKey.len - 4) / 2;
    BSL_Param pubParam[4] = {
        {CRYPT_PARAM_XMSS_XDR_TYPE, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo->pubKey.buff, 4, 0},
        {CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo->pubKey.buff + 4, hashLen, 0},
        {CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo->pubKey.buff + 4 + hashLen, hashLen, 0},
        BSL_PARAM_END
    };

#ifdef HITLS_CRYPTO_XMSS
    if (subPubkeyInfo->keyType == BSL_CID_XMSS) {
        CryptXmssCtx *pctx = CRYPT_XMSS_NewCtxEx(libCtx);
        if (pctx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        int32_t ret = CRYPT_XMSS_Ctrl(pctx, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, subPubkeyInfo->pubKey.buff, 4);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_XMSS_FreeCtx(pctx);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = CRYPT_XMSS_SetPubKey(pctx, pubParam);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            CRYPT_XMSS_FreeCtx(pctx);
            return ret;
        }
        *pubKey = pctx;
        return CRYPT_SUCCESS;
    }
#endif

#ifdef HITLS_CRYPTO_XMSSMT
    if (subPubkeyInfo->keyType == BSL_CID_XMSSMT) {
        CryptXmssmtCtx *pctx = CRYPT_XMSSMT_NewCtxEx(libCtx);
        if (pctx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        int32_t ret = CRYPT_XMSSMT_Ctrl(pctx, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, subPubkeyInfo->pubKey.buff, 4);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_XMSSMT_FreeCtx(pctx);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = CRYPT_XMSSMT_SetPubKey(pctx, pubParam);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            CRYPT_XMSSMT_FreeCtx(pctx);
            return ret;
        }
        *pubKey = pctx;
        return CRYPT_SUCCESS;
    }
#endif

    BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
    return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
}

static int32_t XmssParseSubPubkeyAsn1BuffImpl(const XmssSubPubkeyParseInput *input, void **pubKey)
{
    if (input == NULL || pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    int32_t ret = XmssDecodeSubPubkeyInfo(input->buff, input->buffLen, input->isComplete, input->expectedType,
        &subPubkeyInfo);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return XmssSetCtxFromSubPubkey(input->libCtx, &subPubkeyInfo, pubKey);
}

#ifdef HITLS_CRYPTO_XMSS
int32_t CRYPT_XMSS_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, CryptXmssCtx **pubKey,
    bool isComplete)
{
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    XmssSubPubkeyParseInput input = {libCtx, buff, buffLen, isComplete, BSL_CID_XMSS};
    void *pctx = NULL;
    int32_t ret = XmssParseSubPubkeyAsn1BuffImpl(&input, &pctx);
    if (ret == CRYPT_SUCCESS) {
        *pubKey = (CryptXmssCtx *)pctx;
    }
    return ret;
}
#endif

#ifdef HITLS_CRYPTO_XMSSMT
int32_t CRYPT_XMSSMT_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, CryptXmssmtCtx **pubKey,
    bool isComplete)
{
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    XmssSubPubkeyParseInput input = {libCtx, buff, buffLen, isComplete, BSL_CID_XMSSMT};
    void *pctx = NULL;
    int32_t ret = XmssParseSubPubkeyAsn1BuffImpl(&input, &pctx);
    if (ret == CRYPT_SUCCESS) {
        *pubKey = (CryptXmssmtCtx *)pctx;
    }
    return ret;
}
#endif
#endif

#endif /* HITLS_CRYPTO_KEY_DECODE_CHAIN && PQC key algorithms */
