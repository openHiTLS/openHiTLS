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
#include <stdlib.h>
#include <string.h>
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_params_key.h"
#include "crypt_eal_pkey.h"
#include "crypt_xmss.h"
#include "crypt_xmssmt.h"
#include "crypt_util_rand.h"
#include "test.h"
/* END_HEADER */

static void InitXmssPrvParams(BSL_Param *params, uint64_t *index, uint8_t *prvSeed,
    uint8_t *prvPrf,
    uint8_t *pubSeed, uint8_t *pubRoot, uint32_t keyLen, uint8_t *bdsState, uint32_t bdsStateLen)
{
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_XMSS_PRV_SEED, BSL_PARAM_TYPE_OCTETS, prvSeed, keyLen);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_XMSS_PRV_PRF, BSL_PARAM_TYPE_OCTETS, prvPrf, keyLen);
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_XMSS_PRV_INDEX, BSL_PARAM_TYPE_UINT64, index, sizeof(*index));
    BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_XMSS_PUB_SEED, BSL_PARAM_TYPE_OCTETS, pubSeed, keyLen);
    BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_XMSS_PUB_ROOT, BSL_PARAM_TYPE_OCTETS, pubRoot, keyLen);
    BSL_PARAM_InitValue(&params[5], CRYPT_PARAM_XMSS_BDS_STATE, BSL_PARAM_TYPE_OCTETS, bdsState, bdsStateLen);
    params[6] = (BSL_Param)BSL_PARAM_END;
}

static void StoreBe32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* @
 * @test SDV_CRYPTO_XMSS_INDEX_MATRIX_TC001
 * @spec -
 * @title Test XMSS index capacity and boundary values through EAL key import/export.
 * @precon nan
 * @brief Import one key vector at index 0, 33, 1025, last and capacity, then export the index.
 * @expect All indexes below capacity roundtrip; capacity and above are rejected.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_INDEX_MATRIX_TC001(int pkeyType, int algId, int keyLen, int capacity, Hex *key)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};
    uint8_t message[1] = {0};
    /* 50000 bytes is an upper-bound scratch buffer for XMSS/XMSSMT signatures. */
    uint8_t signature[50000] = {0};
    /* Test zero, interior values, the last valid index, capacity and UINT64_MAX. */
    uint64_t indexes[6] = {0, 33, 1025, 0, 0, 0};
    uint32_t signatureLen = sizeof(signature);
    uint32_t keyLenU = (uint32_t)keyLen;
    uint32_t i = 0;
    int32_t ret;

    TestMemInit();
    /* 1024 is a representative interior index; the supplied capacity is larger. */
    ASSERT_TRUE(capacity > 1024);
    ASSERT_TRUE(key->len >= keyLenU * 4);
    indexes[3] = (uint64_t)capacity - 1U;
    indexes[4] = (uint64_t)capacity;
    indexes[5] = UINT64_MAX;
    prv.id = (CRYPT_PKEY_AlgId)pkeyType;
    prv.key.xmssPrv.seed = key->x;
    prv.key.xmssPrv.prf = key->x + keyLenU;
    prv.key.xmssPrv.pub.seed = key->x + keyLenU * 2U;
    prv.key.xmssPrv.pub.root = key->x + keyLenU * 3U;
    prv.key.xmssPrv.pub.len = keyLenU;
    for (i = 0; i < sizeof(indexes) / sizeof(indexes[0]); i++) {
        ctx = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, algId), CRYPT_SUCCESS);
        prv.key.xmssPrv.index = indexes[i];
        ret = CRYPT_EAL_PkeySetPrv(ctx, &prv);
        if (indexes[i] >= (uint64_t)capacity) {
            ASSERT_EQ(ret, CRYPT_SUCCESS);
            signatureLen = sizeof(signature);
            ret = CRYPT_EAL_PkeySign(ctx, 0, message, sizeof(message), signature, &signatureLen);
            ASSERT_EQ(ret, CRYPT_XMSS_ERR_KEY_EXPIRED);
        } else {
            ASSERT_EQ(ret, CRYPT_SUCCESS);
            ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv), CRYPT_SUCCESS);
            ASSERT_EQ(prv.key.xmssPrv.index, indexes[i]);
        }
        CRYPT_EAL_PkeyFreeCtx(ctx);
        ctx = NULL;
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_XMSS_INDEX_ENCODING_TC001
 * @title Test XMSS/XMSSMT index capacity and fixed-width import/export matrix.
 * @brief
 * 1. Import index 0, 255, 256, the last valid value, the capacity and UINT64_MAX.
 * 2. Export every accepted index and compare it with the imported unsigned value.
 * 3. Check that out-of-capacity keys are rejected when signing.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_INDEX_ENCODING_TC001(int pkeyType, int algId, int keyLen, int height)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPrv outPrv = {0};
    uint8_t prvSeed[64] = {0};
    uint8_t prvPrf[64] = {0};
    uint8_t pubSeed[64] = {0};
    uint8_t pubRoot[64] = {0};
    uint64_t indexes[6] = {0};
    uint64_t capacity = 0;
    uint32_t indexCount = (uint32_t)(sizeof(indexes) / sizeof(indexes[0]));
    uint32_t i = 0;
    uint8_t msg[1] = {0};
    uint8_t sig[50000] = {0};
    uint32_t sigLen = sizeof(sig);

    TestMemInit();
    ASSERT_TRUE(keyLen > 0 && keyLen <= (int)sizeof(prvSeed));
    ASSERT_TRUE(height > 0 && height < 64);
    capacity = 1ULL << (uint32_t)height;
    indexes[0] = 0;
    indexes[1] = 255U;
    indexes[2] = 256U;
    indexes[3] = capacity - 1U;
    indexes[4] = capacity;
    indexes[5] = UINT64_MAX;

    memset(prvSeed, 0x11, sizeof(prvSeed));
    memset(prvPrf, 0x22, sizeof(prvPrf));
    memset(pubSeed, 0x33, sizeof(pubSeed));
    memset(pubRoot, 0x44, sizeof(pubRoot));
    ctx = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, algId), CRYPT_SUCCESS);

    prv.id = (CRYPT_PKEY_AlgId)pkeyType;
    prv.key.xmssPrv.seed = prvSeed;
    prv.key.xmssPrv.prf = prvPrf;
    prv.key.xmssPrv.pub.seed = pubSeed;
    prv.key.xmssPrv.pub.root = pubRoot;
    prv.key.xmssPrv.pub.len = (uint32_t)keyLen;
    outPrv.id = (CRYPT_PKEY_AlgId)pkeyType;
    outPrv.key.xmssPrv.seed = prvSeed;
    outPrv.key.xmssPrv.prf = prvPrf;
    outPrv.key.xmssPrv.pub.seed = pubSeed;
    outPrv.key.xmssPrv.pub.root = pubRoot;
    outPrv.key.xmssPrv.pub.len = (uint32_t)keyLen;

    for (i = 0; i < indexCount; i++) {
        prv.key.xmssPrv.index = indexes[i];
        ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &outPrv), CRYPT_SUCCESS);
        ASSERT_EQ(outPrv.key.xmssPrv.index, indexes[i]);
        if (indexes[i] >= capacity) {
            sigLen = sizeof(sig);
            ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, 0, msg, sizeof(msg), sig, &sigLen), CRYPT_XMSS_ERR_KEY_EXPIRED);
        }
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_XMSS_EXHAUSTION_TC001
 * @title Test the last valid XMSS index and the exhausted state transition.
 * @brief
 * 1. Import a SHA2-10-256 private key vector at index 1022.
 * 2. Sign twice and export the index after each signature.
 * 3. Attempt one more signature after the capacity is exhausted.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_EXHAUSTION_TC001(Hex *key)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPrv outPrv = {0};
    uint8_t msg[1] = {0};
    uint8_t sig[50000] = {0};
    uint32_t sigLen = sizeof(sig);
    uint64_t expectedIndex = 1022U;
    uint32_t keyLen = (uint32_t)key->len / 4U;

    TestMemInit();
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, CRYPT_XMSS_SHA2_10_256), CRYPT_SUCCESS);

    prv.id = CRYPT_PKEY_XMSS;
    prv.key.xmssPrv.index = expectedIndex;
    prv.key.xmssPrv.seed = key->x;
    prv.key.xmssPrv.prf = key->x + keyLen;
    prv.key.xmssPrv.pub.seed = key->x + keyLen * 2U;
    prv.key.xmssPrv.pub.root = key->x + keyLen * 3U;
    prv.key.xmssPrv.pub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, 0, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);
    expectedIndex++;
    outPrv = prv;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &outPrv), CRYPT_SUCCESS);
    ASSERT_EQ(outPrv.key.xmssPrv.index, expectedIndex);
    sigLen = sizeof(sig);

    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, 0, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);
    expectedIndex++;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &outPrv), CRYPT_SUCCESS);
    ASSERT_EQ(outPrv.key.xmssPrv.index, expectedIndex);
    sigLen = sizeof(sig);

    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, 0, msg, sizeof(msg), sig, &sigLen), CRYPT_XMSS_ERR_KEY_EXPIRED);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &outPrv), CRYPT_SUCCESS);
    ASSERT_EQ(outPrv.key.xmssPrv.index, expectedIndex);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_XMSS_MESSAGE_MATRIX_TC001
 * @title Test binary message patterns with XMSS and XMSSMT sign/verify.
 * @brief Sign and verify all-zero, all-FF, leading-zero, trailing-zero and middle-zero messages.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_MESSAGE_MATRIX_TC001(int pkeyType, int algId, int keyLen, Hex *key)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};
    uint8_t messages[5][32] = {{0}};
    uint8_t signature[50000] = {0};
    uint32_t signatureLen = 0;
    uint32_t keyLenU = (uint32_t)keyLen;
    uint32_t i = 0;

    TestMemInit();
    ASSERT_TRUE(keyLen > 0 && keyLen <= 64);
    ASSERT_TRUE(key->len >= keyLenU * 4U);
    pkey = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    prv.id = (CRYPT_PKEY_AlgId)pkeyType;
    prv.key.xmssPrv.seed = key->x;
    prv.key.xmssPrv.prf = key->x + keyLenU;
    prv.key.xmssPrv.pub.seed = key->x + keyLenU * 2U;
    prv.key.xmssPrv.pub.root = key->x + keyLenU * 3U;
    prv.key.xmssPrv.pub.len = keyLenU;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    memset(messages[1], 0xFF, sizeof(messages[1]));
    messages[2][0] = 0;
    memset(messages[2] + 1, 0xA5, sizeof(messages[2]) - 1U);
    memset(messages[3], 0xA5, sizeof(messages[3]) - 1U);
    messages[3][sizeof(messages[3]) - 1U] = 0;
    memset(messages[4], 0xA5, sizeof(messages[4]));
    messages[4][sizeof(messages[4]) / 2U] = 0;

    for (i = 0; i < (uint32_t)(sizeof(messages) / sizeof(messages[0])); i++) {
        signatureLen = sizeof(signature);
        ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, 0, messages[i], sizeof(messages[i]), signature, &signatureLen), 0);
        ASSERT_TRUE(signatureLen > 0);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, 0, messages[i], sizeof(messages[i]), signature, signatureLen), 0);
        messages[i][i] ^= 1U;
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, 0, messages[i], sizeof(messages[i]), signature, signatureLen),
            CRYPT_XMSS_ERR_MERKLETREE_ROOT_MISMATCH);
        messages[i][i] ^= 1U;
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_XMSSMT_BDS_IMPORT_INVALID_TC001
 * @title Test XMSSMT multi-layer BDS header validation and import atomicity.
 * @brief Corrupt the persisted state-count field and verify that the existing state is retained.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSSMT_BDS_IMPORT_INVALID_TC001(int algId, int keyLen)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t prvSeed[64] = {0};
    uint8_t prvPrf[64] = {0};
    uint8_t pubSeed[64] = {0};
    uint8_t pubRoot[64] = {0};
    uint8_t msg[1] = {0};
    uint8_t sig[50000] = {0};
    uint8_t bdsState[120000] = {0};
    uint8_t invalidBdsState[120000] = {0};
    uint64_t index = 0;
    uint32_t bdsStateLen = 0;
    uint32_t sigLen = sizeof(sig);
    /* The state-count field follows algId, idx, n, h and d in the fixed header. */
    uint32_t invalidStateCountPos = 28U;
    BSL_Param params[7];

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSSMT);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    /* BDS state only exists after keygen: importing a raw key leaves ctx->bds
     * disabled, Sign falls back to the stateless one-shot path, and GetPrvEx then
     * exports an empty state. This case must corrupt an existing BDS blob, so keygen
     * is required here and is intentionally kept. */
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, 0, msg, sizeof(msg), sig, &sigLen), CRYPT_SUCCESS);

    InitXmssPrvParams(params, &index, prvSeed, prvPrf, pubSeed, pubRoot, (uint32_t)keyLen, bdsState, sizeof(bdsState));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(pkey, params), CRYPT_SUCCESS);
    bdsStateLen = params[5].useLen;
    ASSERT_TRUE(bdsStateLen > invalidStateCountPos + sizeof(uint32_t));
    memcpy(invalidBdsState, bdsState, bdsStateLen);
    memset(invalidBdsState + invalidStateCountPos, 0xFF, sizeof(uint32_t));
    params[5].value = invalidBdsState;
    params[5].valueLen = bdsStateLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(pkey, params), CRYPT_INVALID_ARG);
    params[5].value = bdsState;
    params[5].valueLen = bdsStateLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(pkey, params), CRYPT_SUCCESS);
    ASSERT_EQ(params[5].useLen, bdsStateLen);
    ASSERT_EQ(memcmp(params[5].value, bdsState, bdsStateLen), 0);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_XMSS_EMPTY_MESSAGE_TC001
* @title Sign and verify empty messages through the XMSS/XMSSMT EAL interface
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_EMPTY_MESSAGE_TC001(int pkeyType, int algId, int keyLen, int sigLen, Hex *key)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};
    uint8_t zero = 0;
    uint8_t *sigAfterReject = NULL;
    uint32_t keyLenU = (uint32_t)keyLen;
    uint32_t sigAfterRejectLen = (uint32_t)sigLen;

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(keyLen > 0 && keyLen <= 64);
    ASSERT_TRUE(key->len >= keyLenU * 4U);

    pkey = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)pkeyType);
    sigAfterReject = (uint8_t *)malloc((uint32_t)sigLen);
    ASSERT_TRUE(pkey != NULL && sigAfterReject != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    prv.id = (CRYPT_PKEY_AlgId)pkeyType;
    prv.key.xmssPrv.seed = key->x;
    prv.key.xmssPrv.prf = key->x + keyLenU;
    prv.key.xmssPrv.pub.seed = key->x + keyLenU * 2U;
    prv.key.xmssPrv.pub.root = key->x + keyLenU * 3U;
    prv.key.xmssPrv.pub.len = keyLenU;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeySign(pkey, 0, NULL, 0, sigAfterReject, &sigAfterRejectLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, 0, &zero, 0, sigAfterReject, &sigAfterRejectLen), CRYPT_SUCCESS);
    ASSERT_EQ(sigAfterRejectLen, (uint32_t)sigLen);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(pkey, 0, NULL, 0, sigAfterReject, sigAfterRejectLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, 0, &zero, 0, sigAfterReject, sigAfterRejectLen), CRYPT_SUCCESS);

EXIT:
    free(sigAfterReject);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_XMSS_BDS_STACK_USAGE_SUM_TC001
 * @title Reject imported XMSS BDS state whose treehash stack usage exceeds the shared stack.
 * @brief
 * 1. Generate an XMSS-SHA2_10-256 key and export its BDS state.
 * 2. Forge stackOffset=2 with two unfinished treehash instances that each claim stackUsage=2.
 * 3. Require CRYPT_EAL_PkeySetPrvEx to reject the blob and keep the existing state intact.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSS_BDS_STACK_USAGE_SUM_TC001(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    uint8_t bdsState[8192] = {0};
    uint8_t forged[8192] = {0};
    uint64_t index = 0;
    uint32_t bdsLen = 0;
    BSL_Param params[7];
    /*
     * Fixed offsets for the XMSS-SHA2_10-256 state encoding (n=32, h=10, hp=10):
     * auth[10] keep[5] stack[11] precede stackLevels; each treehash entry is
     * 4+4+4+1+32 = 45 bytes and starts at 883. See xmss_bds.c EncodeState.
     */
    const uint32_t stackLevelsPos = 868U;
    const uint32_t stackOffsetPos = 879U;
    const uint32_t treehash1Pos = 883U + 45U;
    const uint32_t treehash2Pos = 883U + 90U;
    const uint32_t treehashMetaLen = 45U;
    const uint32_t expectedBlobLen = 1402U;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_XMSS_SHA2_10_256), CRYPT_SUCCESS);
    /* BDS state only exists after keygen; it is initialized with nextLeaf=1024
     * and a root matching the generated key. */
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    InitXmssPrvParams(params, &index, prvSeed, prvPrf, pubSeed, pubRoot, sizeof(prvSeed),
        bdsState, sizeof(bdsState));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(pkey, params), CRYPT_SUCCESS);
    bdsLen = params[5].useLen;
    ASSERT_EQ(bdsLen, expectedBlobLen);
    memcpy(forged, bdsState, bdsLen);

    /* Two treehash instances share a two-entry stack: treehash[1] owns
     * levels [1,0] and treehash[2] claims the same entries. */
    forged[stackLevelsPos] = 1U;
    forged[stackLevelsPos + 1U] = 0U;
    StoreBe32(forged + stackOffsetPos, 2U);
    StoreBe32(forged + treehash1Pos, 1U);
    StoreBe32(forged + treehash1Pos + 4U, 0U);
    StoreBe32(forged + treehash1Pos + 8U, 2U);
    forged[treehash1Pos + 12U] = 0U;
    StoreBe32(forged + treehash2Pos, 2U);
    StoreBe32(forged + treehash2Pos + 4U, 0U);
    StoreBe32(forged + treehash2Pos + 8U, 2U);
    forged[treehash2Pos + 12U] = 0U;
    ASSERT_TRUE(treehash2Pos + treehashMetaLen <= bdsLen);

    params[5].value = forged;
    params[5].valueLen = bdsLen;
    /* The two unfinished instances claim 4 stack entries in total, more than
     * stackOffset=2, which IsStateValid must reject. */
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(pkey, params), CRYPT_INVALID_ARG);

    /* A rejected import must leave the previously loaded BDS state unchanged. */
    params[5].value = bdsState;
    params[5].valueLen = bdsLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(pkey, params), CRYPT_SUCCESS);
    ASSERT_EQ(params[5].useLen, bdsLen);
    ASSERT_EQ(memcmp(params[5].value, bdsState, bdsLen), 0);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_XMSSMT_BDS_NEXT_TREE_STACK_TC001
 * @title Reject imported XMSSMT next-tree state that would overflow the shared stack.
 * @brief
 * 1. Build an XMSSMT-SHA2-40/2 BDS blob whose next-tree state has initialized=0,
 *    stackOffset=hp=20 and a non-zero level under it, then import it.
 * 2. Without the check, the second signature writes stack[21], corrupts
 *    stackOffset with hash output and indexes far out of bounds (F20).
 * 3. The import must reject the state because stackLevels is not strictly decreasing.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_XMSSMT_BDS_NEXT_TREE_STACK_TC001(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t prvSeed[32] = {0};
    uint8_t prvPrf[32] = {0};
    uint8_t pubSeed[32] = {0};
    uint8_t pubRoot[32] = {0};
    uint8_t blob[12000] = {0};
    uint64_t index = 0;
    BSL_Param params[7];
    /*
     * XMSSMT-SHA2-40/2-256: n=32, h=40, d=2, hp=20, wotsLen=67.
     * One encoded state is 73*32 + 21 + 8 + 20*13 + 1 = 2626 bytes:
     * auth[20] keep[10] stack[21] | stackLevels[21] stackOffset
     * | treehash[20] (45 bytes each) | retain[1] nextLeaf root initialized.
     */
    const uint32_t headerLen = 36U;
    const uint32_t stateLen = 2626U;
    const uint32_t stateCount = 3U;
    const uint32_t blobLen = 10058U; /* 36 + 3*2626 + (2-1)*67*32 */
    const uint32_t stackLevelsOff = 1632U;
    const uint32_t stackOffsetOff = 1653U;
    const uint32_t treehashOff = 1657U;
    const uint32_t nextLeafOff = 2589U;
    const uint32_t rootOff = 2593U;
    const uint32_t initializedOff = 2625U;
    const uint32_t treehashMetaLen = 45U;
    const uint32_t leafCount = 1U << 20;
    uint32_t base = 0;
    uint32_t i = 0;
    uint32_t j = 0;

    TestMemInit();
    /*
     * A matching active layer root is required by the import, but no tree is
     * actually computed, so the blob is assembled directly instead of running
     * the 2^20-leaf keygen for this parameter set.
     */
    memset(blob, 0, sizeof(blob));
    StoreBe32(blob, (uint32_t)CRYPT_XMSSMT_SHA2_40_2_256);
    StoreBe32(blob + 12U, 32U);
    StoreBe32(blob + 16U, 40U);
    StoreBe32(blob + 20U, 2U);
    StoreBe32(blob + 24U, 20U);
    StoreBe32(blob + 28U, stateCount);
    StoreBe32(blob + 32U, (2U - 1U) * 67U * 32U);

    for (i = 0; i < stateCount; i++) {
        base = headerLen + i * stateLen;
        for (j = 0; j < 20U; j++) {
            uint32_t entry = base + treehashOff + j * treehashMetaLen;
            StoreBe32(blob + entry, j);
            StoreBe32(blob + entry + 4U, 0U);
            StoreBe32(blob + entry + 8U, 0U);
            blob[entry + 12U] = 1U;
        }
        StoreBe32(blob + base + nextLeafOff, i < 2U ? leafCount : 2U);
        memset(blob + base + rootOff, 0x5A, 32U);
        blob[base + initializedOff] = (i < 2U) ? 1U : 0U;
    }

    /* The next-tree slot claims the full stack; a non-zero top level keeps the
     * first push from merging. */
    base = headerLen + 2U * stateLen;
    blob[base + stackLevelsOff + 19U] = 20U;
    StoreBe32(blob + base + stackOffsetOff, 20U);

    memset(prvSeed, 0x11, sizeof(prvSeed));
    memset(prvPrf, 0x22, sizeof(prvPrf));
    memset(pubSeed, 0x33, sizeof(pubSeed));
    memset(pubRoot, 0x5A, sizeof(pubRoot));
    InitXmssPrvParams(params, &index, prvSeed, prvPrf, pubSeed, pubRoot, sizeof(prvSeed), blob, blobLen);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSSMT);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_XMSSMT_SHA2_40_2_256), CRYPT_SUCCESS);
    /* The forged level layout is not strictly decreasing, so the next-tree
     * state must be rejected instead of driving stack[21] on the second sign. */
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(pkey, params), CRYPT_INVALID_ARG);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */


