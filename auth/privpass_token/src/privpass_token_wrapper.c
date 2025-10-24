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
#include "crypt_eal_rand.h"
#include "auth_params.h"
#include "auth_errno.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "crypt_eal_codecs.h"
#include "auth_privpass_token.h"
#include "privpass_token.h"
#include "bsl_sal.h"

static void *PrivPassNewPkeyCtx(void *libCtx, const char *attrName, int32_t algId)
{
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_PkeyNewCtx(algId);
}

static void PrivPassFreePkeyCtx(void *pkeyCtx)
{
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}

int32_t PrivPassPubDigest(void *libCtx, const char *attrName, int32_t algId, const uint8_t *input,
    uint32_t inputLen, uint8_t *digest, uint32_t *digestLen)
{
    (void)libCtx;
    (void)attrName;
    if (input == NULL || inputLen == 0 || digest == NULL || digestLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    uint32_t mdSize = CRYPT_EAL_MdGetDigestSize(algId);
    if (mdSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    if (*digestLen < mdSize) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
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
    CRYPT_EAL_MdFreeCtx(ctx);
    return CRYPT_SUCCESS;
}

static int32_t SetRsaBssaFlag(CRYPT_EAL_PkeyCtx *ctx, bool setPadding)
{
    uint32_t flag = CRYPT_RSA_BSSA;
    uint32_t padType = 0;
    int32_t ret;

    if (setPadding == true) {
        padType = CRYPT_EMSA_PSS;
        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_PADDING, &padType, sizeof(padType));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else {
        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_RSA_PADDING, &padType, sizeof(padType));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (padType != CRYPT_EMSA_PSS) {
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_ALG);
            return HITLS_AUTH_PRIVPASS_INVALID_ALG;
        }
    }

    return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_FLAG, (void *)&flag, sizeof(uint32_t));
}

static int32_t PrivPassPubBlind(void *pkeyCtx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *blindedData, uint32_t *blindedDataLen)
{
    if (pkeyCtx == NULL || data == NULL || dataLen == 0 || blindedData == NULL || blindedDataLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)pkeyCtx;
    int32_t ret = SetRsaBssaFlag(ctx, false); // false means get and verify padding type
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_EAL_PkeyBlind(ctx, algId, data, dataLen, blindedData, blindedDataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t PrivPassPubUnBlind(void *pkeyCtx, const uint8_t *blindedData, uint32_t blindedDataLen, uint8_t *data,
    uint32_t *dataLen)
{
    if (pkeyCtx == NULL || blindedData == NULL || blindedDataLen == 0 || data == NULL || dataLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)pkeyCtx;
    return CRYPT_EAL_PkeyUnBlind(ctx, blindedData, blindedDataLen, data, dataLen);
}

static int32_t PrivPassPubSignData(void *pkeyCtx, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
    uint32_t *signLen)
{
    if (pkeyCtx == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)pkeyCtx;
    int32_t ret = SetRsaBssaFlag(ctx, true); // true means set padding type to CRYPT_EMSA_PSS
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_EAL_PkeySignData(ctx, data, dataLen, sign, signLen);
}

static int32_t PrivPassPubVerify(void *pkeyCtx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    if (pkeyCtx == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx *ctx = (CRYPT_EAL_PkeyCtx *)pkeyCtx;
    int32_t ret = SetRsaBssaFlag(ctx, false); // false means get and verify padding type
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_EAL_PkeyVerify(ctx, algId, data, dataLen, sign, signLen);
}

static int32_t PubKeyCheck(CRYPT_EAL_PkeyCtx *ctx)
{
    uint32_t padType = 0;
    uint32_t keyBits = 0;
    CRYPT_MD_AlgId mdType = 0;

    int32_t ret = CRYPT_EAL_PkeyGetId(ctx);
    if (ret != CRYPT_PKEY_RSA) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_TYPE);
        return HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_TYPE;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_RSA_PADDING, &padType, sizeof(padType));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (padType != CRYPT_EMSA_PSS) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_PADDING_INFO);
        return HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_PADDING_INFO;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_RSA_MD, &mdType, sizeof(CRYPT_MD_AlgId));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (mdType != CRYPT_MD_SHA384) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_PADDING_MD);
        return HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_PADDING_MD;
    }
    keyBits = CRYPT_EAL_PkeyGetKeyBits(ctx);
    if (keyBits != 2048) { // now only support rsa-2048
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_BITS);
        return HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_BITS;
    }
    return CRYPT_SUCCESS;
}

static int32_t PrivPassPubDecodePubKey(void *libCtx, const char *attrName, uint8_t *pubKey, uint32_t pubKeyLen,
    void **pkeyCtx)
{
    (void)libCtx;
    (void)attrName;
    if (pkeyCtx == NULL || *pkeyCtx != NULL || pubKey == NULL || pubKeyLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    BSL_Buffer encode = {.data = pubKey, .dataLen = pubKeyLen};
    int32_t ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encode, NULL, 0, &ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = PubKeyCheck(ctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return ret;
    }
    *pkeyCtx = ctx;
    return CRYPT_SUCCESS;
}

static int32_t PrivPassPubDecodePrvKey(void *libCtx, const char *attrName, void *param, uint8_t *prvKey,
    uint32_t prvKeyLen, void **pkeyCtx)
{
    (void)libCtx;
    (void)attrName;
    (void)param;
    if (pkeyCtx == NULL || *pkeyCtx != NULL || prvKey == NULL || prvKeyLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint32_t keyBits = 0;
    uint8_t *tmpBuff = BSL_SAL_Malloc(prvKeyLen + 1);
    if (tmpBuff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    (void)memcpy_s(tmpBuff, prvKeyLen, prvKey, prvKeyLen);
    tmpBuff[prvKeyLen] = '\0';
    BSL_Buffer encode = {.data = tmpBuff, .dataLen = prvKeyLen};
    int32_t ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encode, NULL, 0, &ctx);
    (void)memset_s(tmpBuff, prvKeyLen, 0, prvKeyLen);
    BSL_SAL_Free(tmpBuff);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (CRYPT_EAL_PkeyGetId(ctx) != CRYPT_PKEY_RSA) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_PRVKEY_TYPE);
        return HITLS_AUTH_PRIVPASS_INVALID_PRVKEY_TYPE;
    }
    keyBits = CRYPT_EAL_PkeyGetKeyBits(ctx);
    if (keyBits != 2048) { // now only support rsa-2048
        CRYPT_EAL_PkeyFreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_PRVKEY_BITS);
        return HITLS_AUTH_PRIVPASS_INVALID_PRVKEY_BITS;
    }
    *pkeyCtx = ctx;
    return CRYPT_SUCCESS;
}

static int32_t PrivPassPubCheckKeyPair(void *pubKeyCtx, void *prvKeyCtx)
{
    if (pubKeyCtx == NULL || prvKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    int32_t ret = CRYPT_EAL_PkeyPairCheck(pubKeyCtx, prvKeyCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t PrivPassPubRandom(uint8_t *buffer, uint32_t bufferLen)
{
    if (buffer == NULL || bufferLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    return CRYPT_EAL_RandbytesEx(NULL, buffer, bufferLen);
}

PrivPassCryptCb PrivPassCryptPubCb(void)
{
    PrivPassCryptCb method = {
        .newPkeyCtx = PrivPassNewPkeyCtx,
        .freePkeyCtx = PrivPassFreePkeyCtx,
        .digest = PrivPassPubDigest,
        .blind = PrivPassPubBlind,
        .unBlind = PrivPassPubUnBlind,
        .signData = PrivPassPubSignData,
        .verify = PrivPassPubVerify,
        .decodePubKey = PrivPassPubDecodePubKey,
        .decodePrvKey = PrivPassPubDecodePrvKey,
        .checkKeyPair = PrivPassPubCheckKeyPair,
        .random = PrivPassPubRandom,
    };
    return method;
}