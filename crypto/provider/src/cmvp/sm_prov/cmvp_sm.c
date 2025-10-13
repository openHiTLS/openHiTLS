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
#ifdef HITLS_CRYPTO_CMVP_SM

#include "cmvp_sm.h"
#include "cmvp_common.h"
#include "crypt_errno.h"
#include "crypt_cmvp_selftest.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "cmvp_integrity_hmac.h"
#include "crypt_params_key.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_sm2.h"

static bool CMVP_Sm2SignVerifyPct(void *ctx)
{
    bool ret = false;
    uint8_t *sign = NULL;
    uint32_t signLen = 0;
    const uint8_t msg[] = {0x01, 0x02, 0x03, 0x04};
    uint32_t mdId = CRYPT_MD_SM3;

    GOTO_ERR_IF_TRUE(CRYPT_SM2_Ctrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &signLen, sizeof(signLen)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    sign = BSL_SAL_Malloc(signLen);
    GOTO_ERR_IF_TRUE(sign == NULL, CRYPT_MEM_ALLOC_FAIL);

    GOTO_ERR_IF_TRUE(CRYPT_SM2_Sign(ctx, mdId, msg, sizeof(msg), sign, &signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(CRYPT_SM2_Verify(ctx, mdId, msg, sizeof(msg), sign, signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_Free(sign);
    return ret;
}

bool CMVP_SmPkeyPct(void *ctx, int32_t algId)
{
    if (algId != CRYPT_PKEY_SM2) {
        return false;
    }
    return CMVP_Sm2SignVerifyPct(ctx);
}

bool CMVP_SmPkeyC2(int32_t algId)
{
    if (algId != CRYPT_MD_SM3) {
        return false;
    }
    return true;
}

bool CMVP_SmKdfC2(const CRYPT_EAL_KdfC2Data *data)
{
    // According to GM/T 0091-2020 A1.1 and A1.2, min saltLen is 8, min iter is 1024.
    if (data->pbkdf2->macId != CRYPT_MAC_HMAC_SM3 || data->pbkdf2->saltLen < 8 || data->pbkdf2->iter < 1024) {
        return false;
    }
    return true;
}

static bool CipherKat(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_CIPHER_SM4_XTS, CRYPT_CIPHER_SM4_CBC, CRYPT_CIPHER_SM4_ECB,
        CRYPT_CIPHER_SM4_CTR, CRYPT_CIPHER_SM4_GCM, CRYPT_CIPHER_SM4_CFB,
        CRYPT_CIPHER_SM4_OFB,
    };

    bool ret = false;
    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        ret = CRYPT_CMVP_SelftestProviderCipher(libCtx, attrName, list[i]);
        if (!ret) {
            return false;
        }
    }
    return true;
}

static bool MdKat(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestProviderMd(libCtx, attrName, CRYPT_MD_SM3);
}

static bool MacKat(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_MAC_HMAC_SM3,
        CRYPT_MAC_CBC_MAC_SM4,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (!CRYPT_CMVP_SelftestProviderMac(libCtx, attrName, list[i])) {
            return false;
        }
    }
    return true;
}

static bool DrbgKat(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_RAND_SM4_CTR_DF,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (!CRYPT_CMVP_SelftestProviderDrbg(libCtx, attrName, list[i])) {
            return false;
        }
    }
    return true;
}

static bool KdfKat(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestProviderPbkdf2(libCtx, attrName, CRYPT_MAC_HMAC_SM3);
}

static bool PkeyKat(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestProviderSM2(libCtx, attrName);
}

int32_t CMVP_SmKat(void *libCtx, const char *attrName)
{
    bool ret = CipherKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_CIPHER_SELFTEST);
    ret = MdKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_MD_SELFTEST);
    ret = MacKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_MAC_SELFTEST);
    ret = DrbgKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_DRBG_SELFTEST);
    ret = KdfKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_KDF_SELFTEST);
    ret = PkeyKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_PKEY_SELFTEST);
    return CRYPT_SUCCESS;
}

int32_t CMVP_SmCheckIntegrity(void *libCtx, const char *attrName)
{
    return CMVP_CheckIntegrity(libCtx, attrName, CRYPT_MAC_HMAC_SM3);
}

static int32_t RandomSelftest(CRYPT_EAL_RndCtx *randCtx)
{
    // GM/T 0062-2018:
    // Random number power-on self-test parameters:
    // a) Test quantity: Collect 20 * 10^4 bits of random numbers, divided into 20 groups, each with 10^4 bits.
    uint32_t groups = 20;
    uint32_t bitsPerGroup = 10000;
    // b) Test item: Poker test, parameter m=2.
    // c) Test criteria: If 2 or more groups fail the test criteria, an alert is triggered indicating test failure.
    //    One retry of random number collection and testing is allowed. If the repeated test still fails,
    //    the product's random number generator is deemed to have failed.
    uint32_t retry = 2;
    uint32_t threshold = 2;
    const uint32_t bytesPerGroup = (bitsPerGroup + 7) >> 3;
    const uint32_t totalLen = groups * bytesPerGroup;

    uint8_t *data = BSL_SAL_Malloc(totalLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    bool isSuccess = false;
    for (uint32_t attempt = 0; attempt < retry; attempt++) {
        int32_t ret = CRYPT_EAL_Drbgbytes(randCtx, data, totalLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_Free(data);
            return ret;
        }
        uint32_t failCnt = 0;
        for (uint32_t i = 0; i < groups; i++) {
            ret = CRYPT_CMVP_RandomnessTest(data + i * bytesPerGroup, bytesPerGroup);
            if (ret == CRYPT_SUCCESS) {
                continue;
            }
            failCnt++;
            if (failCnt >= threshold) {
                break;
            }
        }
        if (failCnt < threshold) {
            isSuccess = true;
            break;
        }
    }
    BSL_SAL_Free(data);
    return isSuccess ? CRYPT_SUCCESS : CRYPT_CMVP_RANDOMNESS_ERR;
}

static int32_t RandomStartupSelftest(void *libCtx, const char *attrName, int32_t algId)
{
    int32_t ret = CRYPT_SUCCESS;
    CRYPT_EAL_RndCtx *randCtx = CRYPT_EAL_ProviderDrbgNewCtx(libCtx, algId, attrName, NULL);
    if (randCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t selfTest = 0;
    ret = CRYPT_EAL_DrbgCtrl(randCtx, CRYPT_CTRL_SET_SELFTEST_FLAG, &selfTest, sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_DrbgDeinit(randCtx);
        return ret;
    }
    ret = CRYPT_EAL_DrbgInstantiate(randCtx, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_DrbgDeinit(randCtx);
        return ret;
    }

    ret = RandomSelftest(randCtx);
    CRYPT_EAL_DrbgDeinit(randCtx);
    return ret;
}

int32_t CMVP_SmRandomStartupSelftest(void *libCtx, const char *attrName)
{
    return RandomStartupSelftest(libCtx, attrName, CRYPT_RAND_SM4_CTR_DF);
}

#endif /* HITLS_CRYPTO_CMVP_SM */
