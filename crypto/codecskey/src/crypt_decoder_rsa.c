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
#if defined(HITLS_CRYPTO_KEY_DECODE_CHAIN) && defined(HITLS_CRYPTO_RSA)
#include "crypt_rsa.h"
#include "bsl_asn1_internal.h"
#include "bsl_params.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "crypt_codecskey_local.h"
#include "crypt_codecskey.h"

static int32_t ProcRsaPubKey(const BSL_ASN1_Buffer *asn1, CRYPT_RSA_Ctx *rsaKey)
{
    const BSL_Param param[3] = {
        {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_E_IDX].buff,
            asn1[CRYPT_RSA_PRV_E_IDX].len, 0},
        {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_N_IDX].buff,
            asn1[CRYPT_RSA_PRV_N_IDX].len, 0},
        BSL_PARAM_END
    };
    return CRYPT_RSA_SetPubKeyEx(rsaKey, param);
}

static int32_t ProcRsaPrivKey(const BSL_ASN1_Buffer *asn1, CRYPT_RSA_Ctx *rsaKey)
{
    const BSL_Param param[10] = {
        {CRYPT_PARAM_RSA_D, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_D_IDX].buff,
            asn1[CRYPT_RSA_PRV_D_IDX].len, 0},
        {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_N_IDX].buff,
            asn1[CRYPT_RSA_PRV_N_IDX].len, 0},
        {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_E_IDX].buff,
            asn1[CRYPT_RSA_PRV_E_IDX].len, 0},
        {CRYPT_PARAM_RSA_P, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_P_IDX].buff,
            asn1[CRYPT_RSA_PRV_P_IDX].len, 0},
        {CRYPT_PARAM_RSA_Q, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_Q_IDX].buff,
            asn1[CRYPT_RSA_PRV_Q_IDX].len, 0},
        {CRYPT_PARAM_RSA_DP, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_DP_IDX].buff,
            asn1[CRYPT_RSA_PRV_DP_IDX].len, 0},
        {CRYPT_PARAM_RSA_DQ, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_DQ_IDX].buff,
            asn1[CRYPT_RSA_PRV_DQ_IDX].len, 0},
        {CRYPT_PARAM_RSA_QINV, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_QINV_IDX].buff,
            asn1[CRYPT_RSA_PRV_QINV_IDX].len, 0},
        BSL_PARAM_END
    };
    return CRYPT_RSA_SetPrvKeyEx(rsaKey, param);
}


static int32_t ProcRsaKeyPair(uint8_t *buff, uint32_t buffLen, CRYPT_RSA_Ctx *rsaKey)
{
    // decode n and e
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_RsaPrikeyAsn1Buff(buff, buffLen, asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = ProcRsaPrivKey(asn1, rsaKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ProcRsaPubKey(asn1, rsaKey);
}

static int32_t ProcRsaPssParam(BSL_ASN1_Buffer *rsaPssParam, CRYPT_RSA_Ctx *rsaPriKey)
{
    int32_t padType = CRYPT_EMSA_PSS;
    int32_t ret = CRYPT_RSA_Ctrl(rsaPriKey, CRYPT_CTRL_SET_RSA_PADDING, &padType, sizeof(padType));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (rsaPssParam == NULL || rsaPssParam->buff == NULL) {
        return CRYPT_SUCCESS;
    }

    CRYPT_RSA_PssPara para = {0};
    ret = CRYPT_EAL_ParseRsaPssAlgParam(rsaPssParam, &para);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_Param param[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &para.mdId, sizeof(para.mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &para.mgfId, sizeof(para.mgfId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &para.saltLen, sizeof(para.saltLen), 0},
        BSL_PARAM_END};
    return CRYPT_RSA_Ctrl(rsaPriKey, CRYPT_CTRL_SET_RSA_EMSA_PSS, param, 0);
}

static int32_t DecodeRsaPrikeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *rsaPssParam,
    BslCid cid, CRYPT_RSA_Ctx **rsaPriKey)
{
    CRYPT_RSA_Ctx *pctx = CRYPT_RSA_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = ProcRsaKeyPair(buff, buffLen, pctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_RSA_FreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (cid != BSL_CID_RSASSAPSS) {
        *rsaPriKey = pctx;
        return CRYPT_SUCCESS;
    }

    ret = ProcRsaPssParam(rsaPssParam, pctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_RSA_FreeCtx(pctx);
        return ret;
    }
    *rsaPriKey = pctx;
    return ret;
}

int32_t CRYPT_RSA_ParsePrikeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *rsaPssParam,
    CRYPT_RSA_Ctx **rsaPriKey)
{
    return DecodeRsaPrikeyAsn1Buff(libCtx, buff, buffLen, rsaPssParam, BSL_CID_UNKNOWN, rsaPriKey);
}

int32_t CRYPT_RSA_ParsePubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *param,
    CRYPT_RSA_Ctx **rsaPubKey, BslCid cid)
{
    // decode n and e
    BSL_ASN1_Buffer pubAsn1[CRYPT_RSA_PUB_E_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_RsaPubkeyAsn1Buff(buff, buffLen, pubAsn1, CRYPT_RSA_PUB_E_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_RSA_Ctx *pctx = CRYPT_RSA_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_Param pubParam[3] = {
        {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, pubAsn1[CRYPT_RSA_PUB_E_IDX].buff,
            pubAsn1[CRYPT_RSA_PUB_E_IDX].len, 0},
        {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, pubAsn1[CRYPT_RSA_PUB_N_IDX].buff,
            pubAsn1[CRYPT_RSA_PUB_N_IDX].len, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_RSA_SetPubKeyEx(pctx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_RSA_FreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (cid != BSL_CID_RSASSAPSS) {
        *rsaPubKey = pctx;
        return CRYPT_SUCCESS;
    }

    ret = ProcRsaPssParam(param, pctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_RSA_FreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *rsaPubKey = pctx;
    return ret;
}

int32_t CRYPT_RSA_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_RSA_Ctx **pubKey,
    bool isComplete)
{
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    CRYPT_RSA_Ctx *pctx = NULL;
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (subPubkeyInfo.keyType != BSL_CID_RSASSAPSS && subPubkeyInfo.keyType != BSL_CID_RSA) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }

    ret = CRYPT_RSA_ParsePubkeyAsn1Buff(libCtx, subPubkeyInfo.pubKey.buff, subPubkeyInfo.pubKey.len,
        &subPubkeyInfo.keyParam, &pctx, subPubkeyInfo.keyType);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *pubKey = pctx;
    return ret;
}

int32_t CRYPT_RSA_ParsePkcs8Key(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_RSA_Ctx **rsaPriKey)
{
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8Info(buff, buffLen, NULL, &pk8PrikeyInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (pk8PrikeyInfo.keyType != BSL_CID_RSASSAPSS && pk8PrikeyInfo.keyType != BSL_CID_RSA) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    ret = DecodeRsaPrikeyAsn1Buff(libCtx, pk8PrikeyInfo.pkeyRawKey, pk8PrikeyInfo.pkeyRawKeyLen,
        &pk8PrikeyInfo.keyParam, pk8PrikeyInfo.keyType, rsaPriKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_CRYPTO_KEY_DECODE && HITLS_CRYPTO_RSA
