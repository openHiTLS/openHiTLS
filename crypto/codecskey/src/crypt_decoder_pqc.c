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
#ifdef HITLS_CRYPTO_MLDSA
#include "crypt_mldsa.h"
#endif
#include "crypt_params_key.h"
#include "bsl_asn1_internal.h"
#include "bsl_params.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_codecskey_local.h"
#include "crypt_codecskey.h"

#ifdef HITLS_CRYPTO_MLDSA

int32_t CRYPT_MLDSA_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen,
    CRYPT_ML_DSA_Ctx **pubKey, bool isComplete)
{
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bool isMldsaPubkey =
        (subPubkeyInfo.keyType == BSL_CID_ML_DSA_44 || subPubkeyInfo.keyType == BSL_CID_ML_DSA_65 ||
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
    ret = CRYPT_ML_DSA_Ctrl(pctx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&subPubkeyInfo.keyType,
        sizeof(subPubkeyInfo.keyType));
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

int32_t CRYPT_MLDSA_ParsePkcs8key(void *libCtx, uint8_t *buffer, uint32_t bufferLen,
    CRYPT_ML_DSA_Ctx **mldsaPriKey)
{
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8Info(buffer, bufferLen, NULL, &pk8PrikeyInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bool isMldsaKey =
        (pk8PrikeyInfo.keyType == BSL_CID_ML_DSA_44 || pk8PrikeyInfo.keyType == BSL_CID_ML_DSA_65 ||
         pk8PrikeyInfo.keyType == BSL_CID_ML_DSA_87);
    if (!isMldsaKey) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    uint8_t* tmpBuff = pk8PrikeyInfo.pkeyRawKey;
    uint32_t tmpBuffLen = pk8PrikeyInfo.pkeyRawKeyLen;
    BSL_ASN1_Buffer asn1[CRYPT_ML_DSA_PRVKEY_IDX + 1] = {0};
    ret = CRYPT_DECODE_MldsaPrikeyAsn1Buff(tmpBuff, tmpBuffLen, asn1, CRYPT_ML_DSA_PRVKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t* prvKeyBuff = asn1[CRYPT_ML_DSA_PRVKEY_IDX].buff;
    uint32_t prvKeyBuffLen = asn1[CRYPT_ML_DSA_PRVKEY_IDX].len;
    uint8_t* seedBuff = asn1[CRYPT_ML_DSA_PRVKEY_SEED_IDX].buff;
    uint32_t seedBuffLen = asn1[CRYPT_ML_DSA_PRVKEY_SEED_IDX].len;
    CRYPT_ML_DSA_Ctx *pctx = CRYPT_ML_DSA_NewCtxEx(libCtx);
    if (pctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_ML_DSA_Ctrl(pctx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&pk8PrikeyInfo.keyType,
        sizeof(pk8PrikeyInfo.keyType));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ML_DSA_FreeCtx(pctx);
        return ret;
    }
    BSL_Param priParam[3] = {
        {CRYPT_PARAM_ML_DSA_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyBuff, prvKeyBuffLen, 0},
        {CRYPT_PARAM_ML_DSA_PRVKEY_SEED, BSL_PARAM_TYPE_OCTETS, seedBuff, seedBuffLen, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_ML_DSA_SetPrvKeyEx(pctx, priParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_ML_DSA_FreeCtx(pctx);
        return ret;
    }
    *mldsaPriKey = pctx;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_MLDSA