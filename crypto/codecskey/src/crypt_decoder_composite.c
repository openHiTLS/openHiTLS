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
#if defined(HITLS_CRYPTO_COMPOSITE) && defined(HITLS_CRYPTO_KEY_DECODE)
#include "crypt_composite.h"
#include "crypt_params_key.h"
#include "bsl_asn1_internal.h"
#include "bsl_params.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_codecskey_local.h"
#include "crypt_codecskey.h"

int32_t CRYPT_COMPOSITE_ParseSubPubkeyAsn1Buff(void *libCtx, uint8_t *buff, uint32_t buffLen,
                                               CRYPT_CompositeCtx **pubKey, bool isComplete)
{
    CRYPT_DECODE_SubPubkeyInfo subPubkeyInfo = {0};
    int32_t ret = CRYPT_DECODE_SubPubkey(buff, buffLen, NULL, &subPubkeyInfo, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bool isCompositePubkey = (subPubkeyInfo.keyType >= BSL_CID_MLDSA44_RSA2048_PSS_SHA256 &&
                                   subPubkeyInfo.keyType <= BSL_CID_MLDSA87_ECDSA_P521_SHA512);
    if (!isCompositePubkey) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    CRYPT_CompositeCtx *pctx = CRYPT_COMPOSITE_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_Param pubParam[2] = {{CRYPT_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, subPubkeyInfo.pubKey.buff,
                              subPubkeyInfo.pubKey.len, 0},
                             BSL_PARAM_END};
    ret = CRYPT_COMPOSITE_Ctrl(pctx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&subPubkeyInfo.keyType,
                               sizeof(subPubkeyInfo.keyType));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_COMPOSITE_FreeCtx(pctx);
        return ret;
    }
    ret = CRYPT_COMPOSITE_SetPubKeyEx(pctx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_COMPOSITE_FreeCtx(pctx);
        return ret;
    }
    *pubKey = pctx;
    return ret;
}

int32_t CRYPT_COMPOSITE_ParsePkcs8key(void *libCtx, uint8_t *buffer, uint32_t bufferLen,
                                      CRYPT_CompositeCtx **compositePriKey)
{
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8Info(buffer, bufferLen, NULL, &pk8PrikeyInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bool isCompositeKey = (pk8PrikeyInfo.keyType >= BSL_CID_MLDSA44_RSA2048_PSS_SHA256 &&
                                pk8PrikeyInfo.keyType <= BSL_CID_MLDSA87_ECDSA_P521_SHA512);
    if (!isCompositeKey) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH);
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }
    CRYPT_CompositeCtx *pctx = CRYPT_COMPOSITE_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_COMPOSITE_Ctrl(pctx, CRYPT_CTRL_SET_PARA_BY_ID, (void *)&pk8PrikeyInfo.keyType,
                               sizeof(pk8PrikeyInfo.keyType));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_COMPOSITE_FreeCtx(pctx);
        return ret;
    }
    BSL_Param priParam[2] = {{CRYPT_PARAM_COMPOSITE_PRVKEY, BSL_PARAM_TYPE_OCTETS, pk8PrikeyInfo.pkeyRawKey,
                              pk8PrikeyInfo.pkeyRawKeyLen, 0},
                             BSL_PARAM_END};
    ret = CRYPT_COMPOSITE_SetPrvKeyEx(pctx, priParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_COMPOSITE_FreeCtx(pctx);
        return ret;
    }
    *compositePriKey = pctx;
    return CRYPT_SUCCESS;
}
#endif
