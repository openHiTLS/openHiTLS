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

#include "securec.h"
#include "crypt_eal_pkey.h"
#include "auth_params.h"
#include "auth_errno.h"
#include "privpass_token.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "crypt_eal_encode.h"

void *PrivPassNewPkeyCtx(int32_t algId)
{
    return CRYPT_EAL_PkeyNewCtx(algId);
}

void PrivPassFreePkeyCtx(void *pkeyCtx)
{
    if (pkeyCtx == NULL) {
        return;
    }
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}

int32_t PrivPassDigest(int32_t algId, const uint8_t *input, uint32_t inputLen, uint8_t *digest, uint32_t *digestLen)
{
    if (input == NULL || inputLen == 0 || digest == NULL || digestLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    
    uint32_t mdSize = CRYPT_EAL_MdGetDigestSize(algId);
    if (mdSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    if (*digestLen < mdSize) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(algId);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_MdFreeCtx(ctx);
        return ret;
    }
    ret = CRYPT_EAL_MdUpdate(ctx, input, inputLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_MdFreeCtx(ctx);
        return ret;
    }
    ret = CRYPT_EAL_MdFinal(ctx, digest, digestLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_MdFreeCtx(ctx);
        return ret;
    }
    *digestLen = mdSize;
    CRYPT_EAL_MdFreeCtx(ctx);
    return CRYPT_SUCCESS;
}

int32_t PrivPassBlind(void *pkeyCtx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *blindedData,
    uint32_t *blindedDataLen)
{
    if (pkeyCtx == NULL || data == NULL || dataLen == 0 || blindedData == NULL || blindedDataLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)pkeyCtx;
    uint32_t flag = CRYPT_RSA_BSSA;
    uint32_t padType = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_RSA_PADDING, &padType, sizeof(padType));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (padType != CRYPT_PKEY_EMSA_PSS) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ALG);
        return HITLS_AUTH_INVALID_ALG;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_EAL_PkeyBlind(ctx, algId, data, dataLen, blindedData, blindedDataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t PrivPassUnblind(void *pkeyCtx, const uint8_t *blindedData, uint32_t blindedDataLen, uint8_t *data, uint32_t *dataLen)
{
    if (pkeyCtx == NULL || blindedData == NULL || blindedDataLen == 0 || data == NULL || dataLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)pkeyCtx;
    return CRYPT_EAL_PkeyUnBlind(ctx, blindedData, blindedDataLen, data, dataLen);
}

int32_t PrivPassSignData(void *pkeyCtx, const uint8_t *data, uint32_t dataLen, uint8_t *sign, uint32_t *signLen)
{
    if (pkeyCtx == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)pkeyCtx;
    uint32_t flag = CRYPT_RSA_BSSA;
    uint32_t padType = CRYPT_PKEY_EMSA_PSS;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_PADDING, &padType, sizeof(padType));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_EAL_PkeySignData(ctx, data, dataLen, sign, signLen);
}

int32_t PrivPassVerify(void *pkeyCtx, int32_t id, const uint8_t *data, uint32_t dataLen, const uint8_t *sign,
    uint32_t signLen)
{
    if (pkeyCtx == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)pkeyCtx;
    uint32_t flag = CRYPT_RSA_BSSA;
    uint32_t padType = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_RSA_PADDING, &padType, sizeof(padType));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (padType != CRYPT_PKEY_EMSA_PSS) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_ALG);
        return HITLS_AUTH_INVALID_ALG;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_EAL_PkeyVerify(ctx, id, data, dataLen, sign, signLen);
}

int32_t PrivPassDecodePubKey(void **pkeyCtx, uint8_t *pubKey, uint32_t pubKeyLen)
{
    if (pkeyCtx == NULL || *pkeyCtx != NULL || pubKey == NULL || pubKeyLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx **ctx = (CRYPT_EAL_PkeyCtx **)pkeyCtx;
    BSL_Buffer encode = {.data = pubKey, .dataLen = pubKeyLen};
    return CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encode, NULL, 0, ctx);
}

int32_t PrivPassDecodePrvKey(void **pkeyCtx, uint8_t *prvKey, uint32_t prvKeyLen)
{
    if (pkeyCtx == NULL || *pkeyCtx != NULL || prvKey == NULL || prvKeyLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx **ctx = (CRYPT_EAL_PkeyCtx **)pkeyCtx;
    BSL_Buffer encode = {.data = prvKey, .dataLen = prvKeyLen};
    return CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_UNKNOWN, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encode, NULL, 0, ctx);
}

int32_t PrivPassCheckKeyPair(void *pubKeyCtx, void *prvKeyCtx)
{
    int32_t ret = CRYPT_EAL_PkeyPairCheck(pubKeyCtx, prvKeyCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

HiTLS_Auth_PrivPassCryptCb PrivPassCryptDefaultCb(void)
{
    HiTLS_Auth_PrivPassCryptCb method = {
        .newPkeyCtx = PrivPassNewPkeyCtx,
        .freePkeyCtx = PrivPassFreePkeyCtx,
        .digest = PrivPassDigest,
        .blind = PrivPassBlind,
        .unblind = PrivPassUnblind,
        .signData = PrivPassSignData,
        .verify = PrivPassVerify,
        .decodePubKey = PrivPassDecodePubKey,
        .decodePrvKey = PrivPassDecodePrvKey,
        .checkKeyPair = PrivPassCheckKeyPair,
    };
    return method;
}