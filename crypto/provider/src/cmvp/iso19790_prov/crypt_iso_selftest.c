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
#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include "securec.h"
#include "crypt_types.h"
#include "crypt_errno.h"
#include "crypt_iso_provider.h"
#include "bsl_params.h"
#include "bsl_err_internal.h"
#include "cmvp_iso19790.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_provider.h"
#include "cmvp_common.h"
#include "crypt_iso_selftest.h"

#define BSL_PARAM_MAX_NUMBER 1000

int32_t CRYPT_Iso_Log(void *mgrCtx, CRYPT_EVENT_TYPE event, CRYPT_ALGO_TYPE type, int32_t id)
{
    int32_t algId = id;
    int32_t algType = type;
    BSL_Param param[4] = {{0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_EVENT, BSL_PARAM_TYPE_INT32, &event, sizeof(event));
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_ALGID, BSL_PARAM_TYPE_INT32, &algId, sizeof(algId));
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_ALGO_TYPE, BSL_PARAM_TYPE_INT32, &algType, sizeof(algType));
    return CRYPT_EAL_SelftestOperation(mgrCtx, param);
}

static bool KatTestCipher(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_CIPHER_AES128_ECB, CRYPT_CIPHER_AES192_ECB, CRYPT_CIPHER_AES256_ECB,
        CRYPT_CIPHER_AES128_CBC, CRYPT_CIPHER_AES192_CBC, CRYPT_CIPHER_AES256_CBC,
        CRYPT_CIPHER_AES128_CTR, CRYPT_CIPHER_AES192_CTR, CRYPT_CIPHER_AES256_CTR,
        CRYPT_CIPHER_AES128_CCM, CRYPT_CIPHER_AES192_CCM, CRYPT_CIPHER_AES256_CCM,
        CRYPT_CIPHER_AES128_GCM, CRYPT_CIPHER_AES192_GCM, CRYPT_CIPHER_AES256_GCM,
        CRYPT_CIPHER_AES128_XTS, CRYPT_CIPHER_AES256_XTS,
        CRYPT_CIPHER_AES128_OFB, CRYPT_CIPHER_AES192_OFB, CRYPT_CIPHER_AES256_OFB,
        CRYPT_CIPHER_AES128_CFB, CRYPT_CIPHER_AES192_CFB, CRYPT_CIPHER_AES256_CFB,
        CRYPT_CIPHER_CHACHA20_POLY1305,
        CRYPT_CIPHER_SM4_XTS, CRYPT_CIPHER_SM4_CBC, CRYPT_CIPHER_SM4_ECB,
        CRYPT_CIPHER_SM4_CTR, CRYPT_CIPHER_SM4_GCM, CRYPT_CIPHER_SM4_CFB,
        CRYPT_CIPHER_SM4_OFB,
    };

    bool ret = false;
    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (list[i] == CRYPT_CIPHER_CHACHA20_POLY1305) {
            ret = CRYPT_CMVP_SelftestProviderChacha20poly1305(libCtx, attrName);
        } else {
            ret = CRYPT_CMVP_SelftestProviderCipher(libCtx, attrName, list[i]);
        }
        if (!ret) {
            return false;
        }
    }
    return true;
}

static bool KatTestMd(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_MD_SHA1,
        CRYPT_MD_SHA224, CRYPT_MD_SHA256, CRYPT_MD_SHA384, CRYPT_MD_SHA512,
        CRYPT_MD_SHA3_224, CRYPT_MD_SHA3_256, CRYPT_MD_SHA3_384, CRYPT_MD_SHA3_512,
        CRYPT_MD_SHAKE128, CRYPT_MD_SHAKE256, CRYPT_MD_SM3,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (!CRYPT_CMVP_SelftestProviderMd(libCtx, attrName, list[i])) {
            return false;
        }
    }
    return true;
}

static bool KatTestMac(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_MAC_CMAC_AES128, CRYPT_MAC_CMAC_AES192, CRYPT_MAC_CMAC_AES256,
        CRYPT_MAC_GMAC_AES128, CRYPT_MAC_GMAC_AES192, CRYPT_MAC_GMAC_AES256,
        CRYPT_MAC_HMAC_SHA1, CRYPT_MAC_HMAC_SHA224, CRYPT_MAC_HMAC_SHA256, CRYPT_MAC_HMAC_SHA384, CRYPT_MAC_HMAC_SHA512,
        // CRYPT_MAC_HMAC_SM3, // TODO: add kat test for sm3 hmac
        // CRYPT_MAC_CMAC_SM4, // TODO: add kat test for sm4 cmac
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (!CRYPT_CMVP_SelftestProviderMac(libCtx, attrName, list[i])) {
            return false;
        }
    }
    return true;
}

static bool KatTestDrbg(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_RAND_AES128_CTR, CRYPT_RAND_AES192_CTR, CRYPT_RAND_AES256_CTR,
        CRYPT_RAND_AES128_CTR_DF, CRYPT_RAND_AES192_CTR_DF, CRYPT_RAND_AES256_CTR_DF,
        CRYPT_RAND_HMAC_SHA1, CRYPT_RAND_HMAC_SHA224, CRYPT_RAND_HMAC_SHA256, CRYPT_RAND_HMAC_SHA384, CRYPT_RAND_HMAC_SHA512,
        CRYPT_RAND_SHA1, CRYPT_RAND_SHA224, CRYPT_RAND_SHA256, CRYPT_RAND_SHA384, CRYPT_RAND_SHA512,
        // CRYPT_RAND_SM4_CTR_DF, // TODO: add kat test for sm4 ctr df
        // CRYPT_RAND_SM3, // TODO: add kat test for sm3
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (!CRYPT_CMVP_SelftestProviderDrbg(libCtx, attrName, list[i])) {
            return false;
        }
    }
    return true;
}

static bool KatTestKdf(void *libCtx, const char *attrName)
{
    if (!CRYPT_CMVP_SelftestProviderKdfTls12(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderHkdf(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderScrypt(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderPbkdf2(libCtx, attrName, CRYPT_MAC_HMAC_SHA1)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderPbkdf2(libCtx, attrName, CRYPT_MAC_HMAC_SM3)) {
        return false;
    }
    return true;
}

static bool KatTestPkey(void *libCtx, const char *attrName)
{
    if (!CRYPT_CMVP_SelftestProviderDsa(libCtx, attrName)) {
        return false;
    }
    // TODO: add brainpoolp256r1 kat test for ecdsa
    if (!CRYPT_CMVP_SelftestProviderEcdsa(libCtx, attrName)) {
        return false;
    }
    // TODO: add rsa encrypt and decrypt kat test for rsa
    if (!CRYPT_CMVP_SelftestProviderRsa(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderEd25519(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderSM2(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderEcdh(libCtx, attrName)) {
        return false;
    }
    //TODO: add ffdhe2048 dh kat test
    if (!CRYPT_CMVP_SelftestProviderDh(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderX25519(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderMlkemEncapsDecaps(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderMldsaSignVerify(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderSlhdsaSignVerify(libCtx, attrName)) {
        return false;
    }
    return true;
}

static int32_t KatTestInternal(void *libCtx, const char *attrName)
{
    bool ret = KatTestCipher(libCtx, attrName) &&
        KatTestMd(libCtx, attrName) &&
        KatTestMac(libCtx, attrName) &&
        KatTestDrbg(libCtx, attrName) &&
        KatTestKdf(libCtx, attrName) &&
        KatTestPkey(libCtx, attrName);
    return ret ? CRYPT_SUCCESS : CRYPT_CMVP_ERR_ALGO_SELFTEST;
}

static int32_t IsoPctTest(void *provCtx, BSL_Param *param)
{
    void *pkeyCtx = NULL;
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_PCT_CTX);
    int32_t ret = BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_PCT_CTX, BSL_PARAM_TYPE_CTX_PTR, &pkeyCtx, NULL);
    if (ret != BSL_SUCCESS || pkeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_ALGID);
    if (temp == NULL || temp->valueType != BSL_PARAM_TYPE_INT32) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t algId = *(int32_t *)(uintptr_t)temp->value;
    CRYPT_EAL_IsoProvCtx *ctx = (CRYPT_EAL_IsoProvCtx *)provCtx;
    ctx->runLog(CRYPT_EVENT_PCT_TEST, CRYPT_ALGO_PKEY, algId, CRYPT_SUCCESS);
    return CMVP_Pct(pkeyCtx) ? CRYPT_SUCCESS : CRYPT_CMVP_ERR_ALGO_SELFTEST;
}

static int32_t IsoLog(CRYPT_EVENT_TYPE event, void *provCtx, BSL_Param *param, int32_t ret)
{
    CRYPT_EAL_IsoProvCtx *ctx = (CRYPT_EAL_IsoProvCtx *)provCtx;
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_ALGID);
    if (temp == NULL || temp->valueType != BSL_PARAM_TYPE_INT32) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t id = *(int32_t *)(uintptr_t)temp->value;
    
    temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_ALGO_TYPE);
    if (temp == NULL || temp->valueType != BSL_PARAM_TYPE_INT32) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t type = *(int32_t *)(uintptr_t)temp->value;
    ctx->runLog(event, type, id, ret);
    return CRYPT_SUCCESS;
}

static int32_t IsoIntegrityTest(void *provCtx, BSL_Param *param)
{
    void *libCtx = NULL;
    CRYPT_EAL_IsoProvCtx *ctx = (CRYPT_EAL_IsoProvCtx *)provCtx;
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_LIB_CTX);
    int32_t ret = BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_LIB_CTX, BSL_PARAM_TYPE_CTX_PTR, &libCtx, NULL);
    if (ret != BSL_SUCCESS || libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->runLog(CRYPT_EVENT_INTEGRITY_TEST, 0, 0, CRYPT_SUCCESS);
    ret = CMVP_CheckIntegrity(libCtx, CRYPT_EAL_ISO_ATTR, CRYPT_MAC_HMAC_SHA256);
    if (ret != CRYPT_SUCCESS) {
        ctx->runLog(CRYPT_EVENT_INTEGRITY_TEST, 0, 0, ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static int32_t IsoKatTest(void *provCtx, BSL_Param *param)
{
    void *libCtx = NULL;
    CRYPT_EAL_IsoProvCtx *ctx = (CRYPT_EAL_IsoProvCtx *)provCtx;
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_LIB_CTX);
    int32_t ret = BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_LIB_CTX, BSL_PARAM_TYPE_CTX_PTR, &libCtx, NULL);
    if (ret != BSL_SUCCESS || libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->runLog(CRYPT_EVENT_KAT_TEST, 0, 0, CRYPT_SUCCESS);
    ret = KatTestInternal(libCtx, CRYPT_EAL_ISO_ATTR);
    if (ret != CRYPT_SUCCESS) {
        ctx->runLog(CRYPT_EVENT_KAT_TEST, 0, 0, ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static int32_t Iso_selftest_cb(void *provCtx, BSL_Param *param)
{
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_EVENT);
    if (temp == NULL || temp->valueType != BSL_PARAM_TYPE_INT32) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t event = *(int32_t *)(uintptr_t)temp->value;
    switch (event) {
        case CRYPT_EVENT_PCT_TEST:
            return IsoPctTest(provCtx, param);
        case CRYPT_EVENT_KAT_TEST:
            return IsoKatTest(provCtx, param);
        case CRYPT_EVENT_INTEGRITY_TEST:
            return IsoIntegrityTest(provCtx, param);
        case CRYPT_EVENT_PARAM_CHECK:
            return IsoLog(event, provCtx, param, CRYPT_CMVP_ERR_PARAM_CHECK);
        case CRYPT_EVENT_ENC:
        case CRYPT_EVENT_DEC:
        case CRYPT_EVENT_GEN:
        case CRYPT_EVENT_SIGN:
        case CRYPT_EVENT_VERIFY:
        case CRYPT_EVENT_MD:
        case CRYPT_EVENT_MAC:
        case CRYPT_EVENT_KDF:
        case CRYPT_EVENT_KEYAGGREMENT:
        case CRYPT_EVENT_RANDGEN:
        case CRYPT_EVENT_ZERO:
        case CRYPT_EVENT_SETSSP:
        case CRYPT_EVENT_GETSSP:
        case CRYPT_EVENT_ENCAPS:
        case CRYPT_EVENT_DECAPS:
        case CRYPT_EVENT_BLIND:
        case CRYPT_EVENT_UNBLIND:
        case CRYPT_EVENT_GET_VERSION:
            return IsoLog(event, provCtx, param, CRYPT_SUCCESS);
        default:
            break;
    }
    return CRYPT_NOT_SUPPORT;
}

static int32_t CopyParam(BSL_Param *param, int32_t *selfTestFlag, BSL_Param **newParam)
{
    int32_t index = 0;
    if (param != NULL) {
        while (param[index].key != 0 && index < BSL_PARAM_MAX_NUMBER) {
            index++;
        }
        if (index >= BSL_PARAM_MAX_NUMBER) {
            BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_SELFTEST);
            return CRYPT_PROVIDER_ERR_SELFTEST;
        }
    }
    int32_t count = index + 2;
    *newParam = (BSL_Param *)BSL_SAL_Calloc(count, sizeof(BSL_Param));
    if (*newParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (param != NULL) {
        (void)memcpy_s(*newParam, count * sizeof(BSL_Param), param, index * sizeof(BSL_Param));
    }
    int32_t ret = BSL_PARAM_InitValue(&(*newParam)[index], CRYPT_PARAM_SELF_TEST_FLAG, BSL_PARAM_TYPE_INT32,
        selfTestFlag, sizeof(int32_t));
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(*newParam);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static int32_t CreateInternalLibCtx(BSL_Param *param, CRYPT_EAL_LibCtx **libCtx)
{
    int32_t selfTestFlag = 1;
    int32_t ret = CRYPT_SUCCESS;
    char *libPath = NULL;
    BSL_Param *newParam = NULL;
    CRYPT_EAL_LibCtx *ctx = NULL;

    do {
        ret = CopyParam(param, &selfTestFlag, &newParam);
        if (ret != CRYPT_SUCCESS) {
            break;
        }

        ctx = CRYPT_EAL_LibCtxNew();
        if (ctx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            ret = CRYPT_MEM_ALLOC_FAIL;
            break;
        }

        libPath = CMVP_GetLibPath(CreateInternalLibCtx);
        if (libPath == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_SELFTEST);
            ret = CRYPT_PROVIDER_ERR_SELFTEST;
            break;
        }

        ret = CRYPT_EAL_ProviderLoad(ctx, 0, libPath, newParam, NULL);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        *libCtx = ctx;
    } while (0);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_LibCtxFree(ctx);
    }
    BSL_SAL_Free(libPath);
    BSL_SAL_FREE(newParam);
    return ret;
}

static bool CheckIsInternalLibCtx(BSL_Param *param)
{
    if (param != NULL) {
        BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_SELF_TEST_FLAG);
        if (temp != NULL && temp->valueType == BSL_PARAM_TYPE_INT32) {
            return true;
        }
    }
    return false;
}

int32_t CRYPT_Iso_Selftest(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    int32_t ret = CRYPT_EAL_SelftestSetCb(mgrCtx, Iso_selftest_cb);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (CheckIsInternalLibCtx(param)) {
        return CRYPT_SUCCESS;
    }
    ret = CreateInternalLibCtx(param, &libCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    Iso19790_log_cb runLog = NULL;
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_RUN_LOG_CB);
    ret = BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RUN_LOG_CB, BSL_PARAM_TYPE_FUNC_PTR, (void **)&runLog, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (runLog == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    runLog(CRYPT_EVENT_INTEGRITY_TEST, 0, 0, CRYPT_SUCCESS);
    ret = CMVP_CheckIntegrity(libCtx, CRYPT_EAL_ISO_ATTR, CRYPT_MAC_HMAC_SHA256);
    if (ret != CRYPT_SUCCESS) {
        runLog(CRYPT_EVENT_INTEGRITY_TEST, 0, 0, ret);
        CRYPT_EAL_LibCtxFree(libCtx);
        return ret;
    }

    runLog(CRYPT_EVENT_KAT_TEST, 0, 0, CRYPT_SUCCESS);
    ret = KatTestInternal(libCtx, CRYPT_EAL_ISO_ATTR);
    CRYPT_EAL_LibCtxFree(libCtx);
    if (ret != CRYPT_SUCCESS) {
        runLog(CRYPT_EVENT_KAT_TEST, 0, 0, ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */