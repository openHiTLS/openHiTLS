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
#if defined(HITLS_CRYPTO_KEY_DECODE) && defined(HITLS_CRYPTO_XMSS)
#include "crypt_xmss.h"
#include "bsl_asn1.h"
#include "bsl_params.h"
#include "bsl_errno.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "crypt_encode_decode_local.h"
#include "crypt_encode_decode_key.h"

static int32_t __attribute__((unused)) ProcXmssPubKey(const BSL_ASN1_Buffer *asn1, CryptXmssCtx *xmssKey)
{
    const BSL_Param param[3] = {
        // pubRoot
        {CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_XMSS_PUB_ROOT_IDX].buff,
            asn1[CRYPT_XMSS_PUB_ROOT_IDX].len, 0},
        // pubSeed
        {CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_XMSS_PUB_SEED_IDX].buff,
            asn1[CRYPT_XMSS_PUB_SEED_IDX].len, 0},
        BSL_PARAM_END
    };

    return CRYPT_XMSS_SetPubKey(xmssKey, param);
}

static int32_t __attribute__((unused)) ProcXmssPrivKey(const BSL_ASN1_Buffer *asn1, CryptXmssCtx *xmssKey)
{
    const BSL_Param param[] = {
        // seed 
        { CRYPT_PARAM_XMSS_PRV_SEED, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_XMSS_PRV_SEED_IDX].buff,
            asn1[CRYPT_XMSS_PRV_SEED_IDX].len, 0 },
        // prf 
        { CRYPT_PARAM_XMSS_PRV_PRF, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_XMSS_PRV_PRF_IDX].buff, 
            asn1[CRYPT_XMSS_PRV_PRF_IDX].len, 0 },
        // pubSeed
        { CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_XMSS_PRV_PUBSEED_IDX].buff, 
            asn1[CRYPT_XMSS_PRV_PUBSEED_IDX].len, 0 },
        // pubRoot 
        { CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_XMSS_PRV_PUBROOT_IDX].buff, 
            asn1[CRYPT_XMSS_PRV_PUBROOT_IDX].len, 0 },
        BSL_PARAM_END
    };
    return CRYPT_XMSS_SetPrvKey(xmssKey, param);
}

int32_t CRYPT_XMSS_ParseSubPubkeyAsn1Buff(uint8_t *buff, uint32_t buffLen, CryptXmssCtx **pubKey, bool isComplete)
{
  
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (subPubkeyInfo.keyType != BSL_CID_XMSS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    CryptXmssCtx *pctx = CRYPT_XMSS_NewCtx();
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (subPubkeyInfo.pubKey.unusedBits != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_FORMAT);
        return CRYPT_DECODE_NO_SUPPORT_FORMAT;
    }
    uint8_t hashLen = (subPubkeyInfo.pubKey.len - 5) / 2;
    uint8_t *rootHash = buff + 5;
    uint8_t *seedHash = buff + hashLen;
    BSL_Param pubParam[3] = {
        {CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, rootHash, hashLen, 0},
        {CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, seedHash, hashLen, 0},
        BSL_PARAM_END
    };
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