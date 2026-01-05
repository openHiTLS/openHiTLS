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

#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

#include "hitls_build.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_eal_md.h"
#include "eal_md_local.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_init.h"

#include "test.h"
#include "helper.h"
#include "crypto_test_util.h"

#include "securec.h"
#include "crypt_util_rand.h"

#ifndef HITLS_BSL_SAL_MEM
void *TestMalloc(uint32_t len)
{
    return malloc((size_t)len);
}
#endif

void TestMemInit(void)
{
#ifdef HITLS_BSL_SAL_MEM
    return;
#else
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, TestMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
#endif
}

#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_DRBG)
typedef struct {
    CRYPT_Data *entropy;
    CRYPT_Data *nonce;
    CRYPT_Data *pers;

    CRYPT_Data *addin1;
    CRYPT_Data *entropyPR1;

    CRYPT_Data *addin2;
    CRYPT_Data *entropyPR2;

    CRYPT_Data *retBits;
} DRBG_Vec_t;

#ifndef HITLS_CRYPTO_ENTROPY
static int32_t GetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    if (lenRange == NULL) {
        Print("getEntropy Error lenRange NULL\n");
        return CRYPT_NULL_INPUT;
    }
    if (ctx == NULL || entropy == NULL) {
        Print("getEntropy Error\n");
        lenRange->max = strength;
        return CRYPT_NULL_INPUT;
    }

    DRBG_Vec_t *seedCtx = (DRBG_Vec_t *)ctx;

    entropy->data = seedCtx->entropy->data;
    entropy->len = seedCtx->entropy->len;

    return CRYPT_SUCCESS;
}

static void CleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    (void)entropy;
    return;
}
#endif

int32_t TestSimpleRand(uint8_t *buff, uint32_t len)
{
    int rand = open("/dev/urandom", O_RDONLY);
    if (rand < 0) {
        printf("open /dev/urandom failed.\n");
        return -1;
    }
    int l = read(rand, buff, len);
    if (l < 0) {
        printf("read from /dev/urandom failed. errno: %d.\n", errno);
        close(rand);
        return -1;
    }
    close(rand);
    return 0;
}

int32_t TestSimpleRandEx(void *libCtx, uint8_t *buff, uint32_t len)
{
    (void)libCtx;
    return TestSimpleRand(buff, len);
}

int TestRandInit(void)
{
    int drbgAlgId = GetAvailableRandAlgId();
    int32_t ret;
    if (drbgAlgId == -1) {
        Print("Drbg algs are disabled.");
        return CRYPT_NOT_SUPPORT;
    }

#ifndef HITLS_CRYPTO_ENTROPY
    CRYPT_RandSeedMethod seedMeth = {GetEntropy, CleanEntropy, NULL, NULL};
    uint8_t entropy[64] = {0};
    CRYPT_Data tempEntropy = {entropy, sizeof(entropy)};
    DRBG_Vec_t seedCtx = {0};
    seedCtx.entropy = &tempEntropy;
#endif

#ifdef HITLS_CRYPTO_PROVIDER
 #ifndef HITLS_CRYPTO_ENTROPY
    BSL_Param param[4] = {0};
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, &seedCtx, 0);
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.getEntropy, 0);
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth.cleanEntropy, 0);
    ret = CRYPT_EAL_ProviderRandInitCtx(NULL, (CRYPT_RAND_AlgId)drbgAlgId, "provider=default", NULL, 0, param);
 #else
    ret = CRYPT_EAL_ProviderRandInitCtx(NULL, (CRYPT_RAND_AlgId)drbgAlgId, "provider=default", NULL, 0, NULL);
 #endif
#else
 #ifndef HITLS_CRYPTO_ENTROPY
    ret = CRYPT_EAL_RandInit(drbgAlgId, &seedMeth, (void *)&seedCtx, NULL, 0);
 #else
    ret = CRYPT_EAL_RandInit(drbgAlgId, NULL, NULL, NULL, 0);
 #endif
#endif
    if (ret == CRYPT_EAL_ERR_DRBG_REPEAT_INIT) {
        ret = CRYPT_SUCCESS;
    }
    return ret;
}

void TestRandDeInit(void)
{
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_RandDeinitEx(NULL);
#else
    CRYPT_EAL_RandDeinit();
#endif
}
#endif

#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MAC)

uint32_t TestGetMacLen(int algId)
{
    switch (algId) {
        case CRYPT_MAC_HMAC_MD5:
            return 16;
        case CRYPT_MAC_HMAC_SHA1:
            return 20;
        case CRYPT_MAC_HMAC_SHA224:
        case CRYPT_MAC_HMAC_SHA3_224:
            return 28;
        case CRYPT_MAC_HMAC_SHA256:
        case CRYPT_MAC_HMAC_SHA3_256:
            return 32;
        case CRYPT_MAC_HMAC_SHA384:
        case CRYPT_MAC_HMAC_SHA3_384:
            return 48;
        case CRYPT_MAC_HMAC_SHA512:
        case CRYPT_MAC_HMAC_SHA3_512:
            return 64;
        case CRYPT_MAC_HMAC_SM3:
            return 32;
        case CRYPT_MAC_CMAC_AES128:
        case CRYPT_MAC_CMAC_AES192:
        case CRYPT_MAC_CMAC_AES256:
            return 16; // AES block size
        case CRYPT_MAC_CMAC_SM4:
            return 16;// SM4 block size
        case CRYPT_MAC_CBC_MAC_SM4:
            return 16;// SM4 block size
        case CRYPT_MAC_SIPHASH64:
            return 8;
        case CRYPT_MAC_SIPHASH128:
            return 16;
        default:
            return 0;
    }
}

void TestMacSameAddr(int algId, Hex *key, Hex *data, Hex *mac)
{
    uint32_t outLen = data->len > mac->len ? data->len : mac->len;
    uint8_t out[outLen];
    CRYPT_EAL_MacCtx *ctx = NULL;
    int padType = CRYPT_PADDING_ZEROS;

    ASSERT_EQ(memcpy_s(out, outLen, data->x, data->len), 0);
    TestMemInit();

    ASSERT_TRUE((ctx = CRYPT_EAL_MacNewCtx(algId)) != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);
    if (algId == CRYPT_MAC_CBC_MAC_SM4) {
        ASSERT_EQ(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(int)), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, out, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac result cmp", out, outLen, mac->x, mac->len);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}

void TestMacAddrNotAlign(int algId, Hex *key, Hex *data, Hex *mac)
{
    uint32_t outLen = data->len > mac->len ? data->len : mac->len;
    uint8_t out[outLen];
    CRYPT_EAL_MacCtx *ctx = NULL;
    int padType = CRYPT_PADDING_ZEROS;
    uint8_t keyTmp[key->len + 1] __attribute__((aligned(8)));
    uint8_t dataTmp[data->len + 1] __attribute__((aligned(8)));
    uint8_t *pKey = keyTmp + 1;
    uint8_t *pData = dataTmp + 1;

    ASSERT_TRUE(memcpy_s(pKey, key->len, key->x, key->len) == EOK);
    ASSERT_TRUE(memcpy_s(pData, data->len, data->x, data->len) == EOK);
    TestMemInit();

    ASSERT_TRUE((ctx = CRYPT_EAL_MacNewCtx(algId)) != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, pKey, key->len), CRYPT_SUCCESS);
    if (algId == CRYPT_MAC_CBC_MAC_SM4) {
        ASSERT_EQ(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(int)), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, pData, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac result cmp", out, outLen, mac->x, mac->len);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
#endif

#ifdef HITLS_CRYPTO_CIPHER
CRYPT_EAL_CipherCtx *TestCipherNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t id, const char *attrName, int isProvider)
{
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        if (CRYPT_EAL_Init(0) != CRYPT_SUCCESS) {
            return NULL;
        }
        return CRYPT_EAL_ProviderCipherNewCtx(libCtx, id, attrName);
    } else {
        return CRYPT_EAL_CipherNewCtx(id);
    }
#else
    (void)libCtx;
    (void)attrName;
    (void)isProvider;
    return CRYPT_EAL_CipherNewCtx(id);
#endif
}
#endif

#ifdef HITLS_CRYPTO_PKEY
CRYPT_EAL_PkeyCtx *TestPkeyNewCtx(
    CRYPT_EAL_LibCtx *libCtx, int32_t id, uint32_t operType, const char *attrName, int isProvider)
{
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        if (CRYPT_EAL_Init(0) != CRYPT_SUCCESS) {
            return NULL;
        }
        return CRYPT_EAL_ProviderPkeyNewCtx(libCtx, id, operType, attrName);
    } else {
        return CRYPT_EAL_PkeyNewCtx(id);
    }
#else
    (void)libCtx;
    (void)operType;
    (void)attrName;
    (void)isProvider;
    return CRYPT_EAL_PkeyNewCtx(id);
#endif
}
#endif

static volatile uint32_t g_malloc_called_idx = 0;
static volatile uint32_t g_malloc_failed_idx = 0;
static volatile bool g_malloc_fail_enabled = true;

void *STUB_BSL_SAL_Malloc(uint32_t size)
{
    uint32_t current_call_index = g_malloc_called_idx;
    g_malloc_called_idx = current_call_index + 1;

    if (g_malloc_fail_enabled && current_call_index == g_malloc_failed_idx) {
        return NULL;
    }

    return malloc(size);
}

void STUB_ResetMallocCount(void)
{
    g_malloc_called_idx = 0;
}

void STUB_SetMallocFailIndex(uint32_t failIdx)
{
    g_malloc_failed_idx = failIdx;
}

uint32_t STUB_GetMallocCallCount(void)
{
    return g_malloc_called_idx;
}

void STUB_EnableMallocFail(bool enable)
{
    g_malloc_fail_enabled = enable;
}
