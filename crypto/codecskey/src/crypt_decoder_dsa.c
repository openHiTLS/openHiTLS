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
#if defined(HITLS_CRYPTO_KEY_DECODE_CHAIN) && defined(HITLS_CRYPTO_DSA)
#include "crypt_dsa.h"
#include "bsl_asn1_internal.h"
#include "bsl_params.h"
#include "bsl_err_internal.h"
#include "bsl_obj.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "crypt_codecskey.h"
#include "crypt_codecskey_local.h"

static int32_t SetDsaParameters(CRYPT_DSA_Ctx *dsaKey, const BSL_ASN1_Buffer *keyParam)
{
    BSL_ASN1_Buffer paraAsn1[CRYPT_DSA_PRV_G_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_DsaKeyParamAsn1Buff(keyParam->buff, keyParam->len, paraAsn1, CRYPT_DSA_PRV_G_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    const BSL_Param para[] = {
        {CRYPT_PARAM_DSA_P, BSL_PARAM_TYPE_OCTETS, paraAsn1[CRYPT_DSA_PRV_P_IDX].buff,
            paraAsn1[CRYPT_DSA_PRV_P_IDX].len, 0},
        {CRYPT_PARAM_DSA_Q, BSL_PARAM_TYPE_OCTETS, paraAsn1[CRYPT_DSA_PRV_Q_IDX].buff,
            paraAsn1[CRYPT_DSA_PRV_Q_IDX].len, 0},
        {CRYPT_PARAM_DSA_G, BSL_PARAM_TYPE_OCTETS, paraAsn1[CRYPT_DSA_PRV_G_IDX].buff,
            paraAsn1[CRYPT_DSA_PRV_G_IDX].len, 0},
        BSL_PARAM_END
    };
    return CRYPT_DSA_SetParaEx(dsaKey, para);
}

static int32_t SetDsaPublicKey(CRYPT_DSA_Ctx *dsaKey, const BSL_ASN1_BitString *pubKey)
{
    BSL_ASN1_Buffer pubAsn1 = {0};
    int32_t ret = CRYPT_DECODE_DsaPubkeyAsn1Buff(pubKey->buff, pubKey->len, &pubAsn1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    const BSL_Param pub[] = {
        {CRYPT_PARAM_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubAsn1.buff, pubAsn1.len, 0},
        BSL_PARAM_END
    };
    return CRYPT_DSA_SetPubKeyEx(dsaKey, pub);
}

int32_t CRYPT_DSA_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen, CRYPT_DSA_Ctx **pubKey,
                                         bool isComplete)
{
    if (buff == NULL || buffLen == 0 || pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (subPubkeyInfo.keyType != BSL_CID_DSA) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }

    CRYPT_DSA_Ctx *dsaKey = CRYPT_DSA_NewCtxEx(libCtx);
    if (dsaKey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = SetDsaParameters(dsaKey, &subPubkeyInfo.keyParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DSA_FreeCtx(dsaKey);
        return ret;
    }
    ret = SetDsaPublicKey(dsaKey, &subPubkeyInfo.pubKey);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DSA_FreeCtx(dsaKey);
        return ret;
    }
    *pubKey = dsaKey;
    return CRYPT_SUCCESS;
}
#endif
