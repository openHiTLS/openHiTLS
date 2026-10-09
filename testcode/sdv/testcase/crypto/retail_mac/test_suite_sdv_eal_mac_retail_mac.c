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

/* BEGIN_HEADER */
#include <pthread.h>
#include <string.h>
#include "securec.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "eal_mac_local.h"
#include "stub_utils.h"

#define RETAIL_MAC_KEY_LEN 16
#define RETAIL_MAC_LEN 8

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
static bool IsRetailMacDisabled(void)
{
    return !CRYPT_EAL_MacIsValidAlgId(CRYPT_MAC_RETAIL_MAC_DES);
}

static int32_t RetailMacCbcLastBlock(const uint8_t *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t outLen)
{
    if (key == NULL || out == NULL || outLen < RETAIL_MAC_LEN) {
        return CRYPT_NULL_INPUT;
    }

    const uint32_t blockSize = RETAIL_MAC_LEN;
    uint32_t padLen = blockSize - (inLen % blockSize);
    if (padLen == 0) {
        padLen = blockSize;
    }
    uint32_t totalLen = inLen + padLen;
    uint8_t *buf = BSL_SAL_Calloc(totalLen, 1);
    if (buf == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (inLen > 0 && memcpy_s(buf, totalLen, in, inLen) != EOK) {
        BSL_SAL_FREE(buf);
        return CRYPT_SECUREC_FAIL;
    }
    buf[inLen] = 0x80;

    int32_t ret = CRYPT_SUCCESS;
    uint8_t prev[RETAIL_MAC_LEN] = {0};
    uint8_t block[RETAIL_MAC_LEN] = {0};
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_DES_ECB);
    if (ctx == NULL) {
        BSL_SAL_FREE(buf);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = CRYPT_EAL_CipherInit(ctx, key, blockSize, NULL, 0, true);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_NONE);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    for (uint32_t offset = 0; offset < totalLen; offset += blockSize) {
        for (uint32_t i = 0; i < blockSize; i++) {
            block[i] = (uint8_t)(buf[offset + i] ^ prev[i]);
        }
        uint32_t outBlockLen = blockSize;
        ret = CRYPT_EAL_CipherUpdate(ctx, block, blockSize, prev, &outBlockLen);
        if (ret != CRYPT_SUCCESS) {
            goto EXIT;
        }
        if (outBlockLen != blockSize) {
            ret = CRYPT_EAL_ERR_STATE;
            goto EXIT;
        }
    }

    if (memcpy_s(out, outLen, prev, blockSize) != EOK) {
        ret = CRYPT_SECUREC_FAIL;
    }

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    BSL_SAL_FREE(buf);
    return ret;
}
/* END_HEADER */

/* @
* @test  SDV_CRYPT_EAL_RETAIL_MAC_FUNC_TC001
* @spec  -
* @title  Retail MAC KAT test
* @precon  nan
* @brief  1.Invoke new/init/update/final with KAT vector. Expected result 1 is obtained.
* @expect  1.mac equals expected vector
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RETAIL_MAC_FUNC_TC001(int algId, Hex *key, Hex *data, Hex *vecMac)
{
    if (IsRetailMacDisabled()) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = RETAIL_MAC_LEN;
    uint8_t mac[RETAIL_MAC_LEN] = {0};
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("mac result cmp", mac, macLen, vecMac->x, vecMac->len);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_RETAIL_MAC_FUNC_TC002
* @spec  -
* @title  Compare one-shot update and byte-by-byte update
* @precon  nan
* @brief  1.Update in one-shot. 2.Update byte-by-byte. Expected results are the same.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RETAIL_MAC_FUNC_TC002(int algId, Hex *key, Hex *data)
{
    if (IsRetailMacDisabled()) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen1 = RETAIL_MAC_LEN;
    uint32_t macLen2 = RETAIL_MAC_LEN;
    uint8_t mac1[RETAIL_MAC_LEN] = {0};
    uint8_t mac2[RETAIL_MAC_LEN] = {0};
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac1, &macLen1) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    for (uint32_t i = 0; i < data->len; i++) {
        ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x + i, 1) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac2, &macLen2) == CRYPT_SUCCESS);
    ASSERT_TRUE(macLen1 == macLen2);
    ASSERT_COMPARE("mac1 vs mac2 result cmp", mac2, macLen2, mac1, macLen1);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_RETAIL_MAC_FUNC_TC003
* @spec  -
* @title  Compare one-shot update and 7+1 update
* @precon  nan
* @brief  1.Update in one-shot. 2.Update 7 bytes then 1 byte then the rest.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RETAIL_MAC_FUNC_TC003(int algId, Hex *key, Hex *data)
{
    if (IsRetailMacDisabled()) {
        SKIP_TEST();
    }
    
    TestMemInit();
    uint32_t macLen1 = RETAIL_MAC_LEN;
    uint32_t macLen2 = RETAIL_MAC_LEN;
    uint8_t mac1[RETAIL_MAC_LEN] = {0};
    uint8_t mac2[RETAIL_MAC_LEN] = {0};
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(data->len > 8);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac1, &macLen1) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, 7) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x + 7, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x + 8, data->len - 8) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac2, &macLen2) == CRYPT_SUCCESS);
    ASSERT_TRUE(macLen1 == macLen2);
    ASSERT_COMPARE("mac1 vs mac2 result cmp", mac2, macLen2, mac1, macLen1);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_RETAIL_MAC_FUNC_TC004
* @spec  -
* @title  K1=K2 should reduce to CBC chain result
* @precon  nan
* @brief  1.Compute retail mac with K1=K2. 2.Compute CBC chain last block with K1. Expected results are the same.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RETAIL_MAC_FUNC_TC004(int algId, Hex *key, Hex *data)
{
    if (IsRetailMacDisabled() || !CRYPT_EAL_CipherIsValidAlgId(CRYPT_CIPHER_DES_ECB)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = RETAIL_MAC_LEN;
    uint8_t mac[RETAIL_MAC_LEN] = {0};
    uint8_t cbcLast[RETAIL_MAC_LEN] = {0};
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(key->len == RETAIL_MAC_KEY_LEN);
    ASSERT_TRUE(memcmp(key->x, key->x + RETAIL_MAC_LEN, RETAIL_MAC_LEN) == 0);

    ASSERT_TRUE(RetailMacCbcLastBlock(key->x, data->x, data->len, cbcLast, sizeof(cbcLast)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("retail mac vs cbc last block", mac, macLen, cbcLast, RETAIL_MAC_LEN);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_RETAIL_MAC_API_TC001
* @spec  -
* @title  Final output buffer length too small
* @precon  nan
* @brief  1.Invoke final with outLen smaller than mac length. Expected result 1 is obtained.
* @expect  1.return CRYPT_RETAIL_MAC_OUT_BUFF_LEN_NOT_ENOUGH
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RETAIL_MAC_API_TC001(int algId, Hex *key, Hex *data)
{
    if (IsRetailMacDisabled()) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = RETAIL_MAC_LEN - 1;
    uint8_t mac[RETAIL_MAC_LEN] = {0};
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_RETAIL_MAC_OUT_BUFF_LEN_NOT_ENOUGH);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_RETAIL_MAC_API_TC002
* @spec  -
* @title  Invalid key length test
* @precon  nan
* @brief  1.Invoke init with invalid key length. Expected result 1 is obtained.
* @expect  1.return CRYPT_RETAIL_MAC_ERR_KEYLEN
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RETAIL_MAC_API_TC002(int algId, Hex *key)
{
    if (IsRetailMacDisabled()) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(key->len >= 24);
    const uint32_t invalidLen[] = {0, 8, 15, 17, 24};
    for (uint32_t i = 0; i < (uint32_t)(sizeof(invalidLen) / sizeof(invalidLen[0])); i++) {
        ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, invalidLen[i]) == CRYPT_RETAIL_MAC_ERR_KEYLEN);
    }

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_RETAIL_MAC_API_TC003
* @spec  -
* @title  Reinit state behavior
* @precon  nan
* @brief  1.Call reinit before init. 2.Init->Update->Final->Reinit->Update->Final.
* @expect  1.return CRYPT_EAL_ERR_STATE 2.mac results are identical
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RETAIL_MAC_API_TC003(int algId, Hex *key, Hex *data)
{
    if (IsRetailMacDisabled()) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen1 = RETAIL_MAC_LEN;
    uint32_t macLen2 = RETAIL_MAC_LEN;
    uint8_t mac1[RETAIL_MAC_LEN] = {0};
    uint8_t mac2[RETAIL_MAC_LEN] = {0};
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac1, &macLen1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac2, &macLen2) == CRYPT_SUCCESS);
    ASSERT_TRUE(macLen1 == macLen2);
    ASSERT_COMPARE("mac1 vs mac2 result cmp", mac2, macLen2, mac1, macLen1);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_RETAIL_MAC_API_TC004
* @spec  -
* @title  Deinit state behavior
* @precon  nan
* @brief  1.Init->Update->Final->Deinit. 2.Update/Final should fail. 3.Init->Update->Final and compare MAC.
* @expect  1.return CRYPT_SUCCESS 2.return CRYPT_EAL_ERR_STATE 3.MACs are identical
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_RETAIL_MAC_API_TC004(int algId, Hex *key, Hex *data)
{
    if (IsRetailMacDisabled()) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen1 = RETAIL_MAC_LEN;
    uint32_t macLen2 = RETAIL_MAC_LEN;
    uint8_t mac1[RETAIL_MAC_LEN] = {0};
    uint8_t mac2[RETAIL_MAC_LEN] = {0};
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac1, &macLen1) == CRYPT_SUCCESS);
    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac2, &macLen2) == CRYPT_EAL_ERR_STATE);

    macLen2 = RETAIL_MAC_LEN;
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac2, &macLen2) == CRYPT_SUCCESS);
    ASSERT_TRUE(macLen1 == macLen2);
    ASSERT_COMPARE("mac1 vs mac2 result cmp", mac2, macLen2, mac1, macLen1);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_RETAIL_MAC_COPY_CTX_API_TC001(int algId, int isProvider)
{
    if (IsRetailMacDisabled()) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_MacCtx *ctxB = NULL;
    CRYPT_EAL_MacCtx ctxC = { 0 };
    CRYPT_EAL_MacCtx *ctxA = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxA != NULL);

    ctxB = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxB != NULL);

    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(NULL, ctxA), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(ctxB, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(ctxB, &ctxC), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(&ctxC, ctxA), CRYPT_SUCCESS);
    ctxC.macMeth.freeCtx(ctxC.ctx);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctxA);
    CRYPT_EAL_MacFreeCtx(ctxB);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_RETAIL_MAC_DUP_CTX_API_TC001(int algId, int isProvider)
{
    TestMemInit();
    CRYPT_EAL_MacCtx *ctxB = NULL;
    CRYPT_EAL_MacCtx ctxC = { 0 };
    CRYPT_EAL_MacCtx *ctxA = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxA != NULL);

    ctxB = CRYPT_EAL_MacDupCtx(NULL);
    ASSERT_TRUE(ctxB == NULL);
    ctxB = CRYPT_EAL_MacDupCtx(&ctxC);
    ASSERT_TRUE(ctxB == NULL);
    ctxB = CRYPT_EAL_MacDupCtx(ctxA);
    ASSERT_TRUE(ctxB != NULL);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctxA);
    CRYPT_EAL_MacFreeCtx(ctxB);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_RETAIL_MAC_COPY_CTX_TC001(int algId, Hex *key, Hex *data, Hex *vecMac, int isProvider)
{
    if (IsRetailMacDisabled()) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = vecMac->len;
    uint8_t mac[64];

    CRYPT_EAL_MacCtx *copyCtx1 = NULL;
    CRYPT_EAL_MacCtx *copyCtx2 = NULL;
    CRYPT_EAL_MacCtx *copyCtx3 = NULL;
    CRYPT_EAL_MacCtx *ctx = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);

    copyCtx1 = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(copyCtx1 != NULL);
    copyCtx2 = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(copyCtx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(copyCtx1, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(copyCtx1, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(copyCtx1, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac1 cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacFreeCtx(copyCtx1);
    copyCtx1 = NULL;

    copyCtx3 = CRYPT_EAL_MacDupCtx(ctx);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(copyCtx3, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(copyCtx3, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac2 cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacFreeCtx(copyCtx3);
    copyCtx3 = NULL;

    macLen = vecMac->len;
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(copyCtx2, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac3 cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacFreeCtx(ctx);
    ctx = NULL;

    macLen = vecMac->len;
    ASSERT_EQ(CRYPT_EAL_MacFinal(copyCtx2, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac4 cmp", mac, macLen, vecMac->x, vecMac->len);

EXIT:
    CRYPT_EAL_MacFreeCtx(copyCtx3);
    CRYPT_EAL_MacFreeCtx(copyCtx2);
    CRYPT_EAL_MacFreeCtx(copyCtx1);
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

static int32_t TestRetailMacCopyCtxMemCheck(int32_t algId, Hex *key, int isProvider)
{
    CRYPT_EAL_MacCtx *ctxA = NULL;
    CRYPT_EAL_MacCtx *ctxB = NULL;
    CRYPT_EAL_MacCtx *srcCtx = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    int32_t ret = CRYPT_EAL_MacInit(srcCtx, key->x, key->len);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ctxA = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ret = CRYPT_EAL_MacCopyCtx(ctxA, srcCtx);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ctxB = CRYPT_EAL_MacDupCtx(srcCtx);
    if (ctxB == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

EXIT:
    CRYPT_EAL_MacFreeCtx(ctxA);
    CRYPT_EAL_MacFreeCtx(ctxB);
    CRYPT_EAL_MacFreeCtx(srcCtx);
    return ret;
}

/* BEGIN_CASE */
void SDV_CRYPTO_RETAIL_MAC_COPY_CTX_STUB_TC001(int algId, Hex *key, int isProvider)
{
    TestMemInit();
    uint32_t totalMallocCount = 0;
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(TestRetailMacCopyCtxMemCheck((int32_t)algId, key, isProvider), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();

    STUB_EnableMallocFail(true);
    for (uint32_t j = 0; j < totalMallocCount; j++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(j);
        ASSERT_NE(TestRetailMacCopyCtxMemCheck((int32_t)algId, key, isProvider), CRYPT_SUCCESS);
    }

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
}
/* END_CASE */