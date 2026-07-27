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
#include <stdint.h>
#include <string.h>
#include "crypt_eal_md.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_blake2.h"
/* END_HEADER */

/*
 * Test vectors are selected from the official BLAKE2 KAT file:
 * https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json
 * File SHA256: 5031ac14800798ae15cee79c04d65e326a575f2c968c7e2846a79bd07a1c0e61
 * Selection criteria: hash == "blake2s" and key == "".
 */


/*
 * @test   SDV_CRYPTO_BLAKE2S_API_TC001
 * @title  BLAKE2s EAL API test.
 * @brief  Verify digest size query, EAL state checks, null parameter handling,
 *         output buffer length validation, final state rejection and deinit.
 * @expect All valid EAL operations return CRYPT_SUCCESS, invalid calls return
 *         the expected error codes, and no error remains on the stack.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BLAKE2S_API_TC001(void)
{
    TestMemInit();
    uint8_t input[100] = {0};
    uint8_t output[CRYPT_BLAKE2S256_DIGESTSIZE + 1] = {0};
    uint32_t outputLen = CRYPT_BLAKE2S256_DIGESTSIZE;
    CRYPT_EAL_MdCtx *ctx = NULL;

    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_BLAKE2S256), CRYPT_BLAKE2S256_DIGESTSIZE);
    ASSERT_EQ(CRYPT_EAL_MdDeinit(ctx), CRYPT_NULL_INPUT);
    TestErrClear();

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_BLAKE2S256);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, input, sizeof(input)), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outputLen), CRYPT_EAL_ERR_STATE);
    TestErrClear();

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(NULL, input, sizeof(input)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, NULL, sizeof(input)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, input, sizeof(input)), CRYPT_SUCCESS);
    TestErrClear();

    ASSERT_EQ(CRYPT_EAL_MdFinal(NULL, output, &outputLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, NULL, &outputLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, NULL), CRYPT_NULL_INPUT);
    TestErrClear();

    outputLen = CRYPT_BLAKE2S256_DIGESTSIZE - 1;
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outputLen), CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH);
    TestErrClear();
    outputLen = sizeof(output);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outputLen), CRYPT_SUCCESS);
    ASSERT_EQ(outputLen, CRYPT_BLAKE2S256_DIGESTSIZE);
    ASSERT_EQ(CRYPT_EAL_MdGetId(ctx), CRYPT_MD_BLAKE2S256);

    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outputLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, input, sizeof(input)), CRYPT_EAL_ERR_STATE);
    TestErrClear();
    ASSERT_EQ(CRYPT_EAL_MdDeinit(ctx), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BLAKE2S_API_TC002
 * @title  BLAKE2s low-level update input overflow test.
 * @brief  Initialize a low-level BLAKE2s-256 context, set the accumulated byte
 *         counter to UINT64_MAX manually, then update one more byte.
 * @expect CRYPT_BLAKE2S_Update returns CRYPT_MD_INPUT_OVERFLOW.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BLAKE2S_API_TC002(void)
{
    TestMemInit();
    uint8_t input[1] = {0};
    CRYPT_BLAKE2S_Ctx *ctx = CRYPT_BLAKE2S_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_BLAKE2S256_Init(ctx, 0), CRYPT_SUCCESS);
    ctx->t = UINT64_MAX;
    ASSERT_EQ(CRYPT_BLAKE2S_Update(ctx, input, sizeof(input)), CRYPT_MD_INPUT_OVERFLOW);
    TestErrClear();
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_BLAKE2S_FreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BLAKE2S_FUNC_TC001
 * @title  BLAKE2s final without update vector test.
 * @brief  Finalize a freshly initialized BLAKE2s-256 EAL context without any
 *         update input and compare the digest with the official empty-message KAT.
 * @expect Final succeeds and the digest matches the expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BLAKE2S_FUNC_TC001(Hex *hash)
{
    TestMemInit();
    uint8_t output[CRYPT_BLAKE2S256_DIGESTSIZE] = {0};
    uint32_t outputLen = sizeof(output);
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_BLAKE2S256);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outputLen), CRYPT_SUCCESS);
    ASSERT_EQ(outputLen, CRYPT_BLAKE2S256_DIGESTSIZE);
    ASSERT_COMPARE("blake2s", output, outputLen, hash->x, hash->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BLAKE2S_FUNC_TC002
 * @title  BLAKE2s vector test.
 * @brief  Hash one input message through Init/Update/Final and through the EAL
 *         one-shot interface, then compare both outputs with the official KAT.
 * @expect Both streaming and one-shot digests match the expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BLAKE2S_FUNC_TC002(Hex *msg, Hex *hash)
{
    TestMemInit();
    uint8_t output[CRYPT_BLAKE2S256_DIGESTSIZE] = {0};
    uint32_t outputLen = sizeof(output);
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_BLAKE2S256);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outputLen), CRYPT_SUCCESS);
    ASSERT_EQ(outputLen, CRYPT_BLAKE2S256_DIGESTSIZE);
    ASSERT_COMPARE("blake2s", output, outputLen, hash->x, hash->len);

    outputLen = sizeof(output);
    ASSERT_EQ(CRYPT_EAL_Md(CRYPT_MD_BLAKE2S256, msg->x, msg->len, output, &outputLen), CRYPT_SUCCESS);
    ASSERT_EQ(outputLen, CRYPT_BLAKE2S256_DIGESTSIZE);
    ASSERT_COMPARE("blake2s", output, outputLen, hash->x, hash->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BLAKE2S_FUNC_TC003
 * @title  BLAKE2s multiple update vector test.
 * @brief  Hash one message split across three Update calls and compare the final
 *         digest with the official KAT for the concatenated message.
 * @expect Multi-update digest matches the expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BLAKE2S_FUNC_TC003(Hex *data1, Hex *data2, Hex *data3, Hex *hash)
{
    TestMemInit();
    uint8_t output[CRYPT_BLAKE2S256_DIGESTSIZE] = {0};
    uint32_t outputLen = sizeof(output);
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_BLAKE2S256);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data1->x, data1->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data2->x, data2->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data3->x, data3->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outputLen), CRYPT_SUCCESS);
    ASSERT_EQ(outputLen, CRYPT_BLAKE2S256_DIGESTSIZE);
    ASSERT_COMPARE("blake2s", output, outputLen, hash->x, hash->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BLAKE2S_FUNC_TC004
 * @title  BLAKE2s split update consistency test.
 * @brief  Hash the same generated message once with 100 incremental Update calls
 *         and once with a single Update call.
 * @expect The two final digests are identical.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BLAKE2S_FUNC_TC004(void)
{
    TestMemInit();
    CRYPT_EAL_MdCtx *ctx1 = CRYPT_EAL_MdNewCtx(CRYPT_MD_BLAKE2S256);
    CRYPT_EAL_MdCtx *ctx2 = CRYPT_EAL_MdNewCtx(CRYPT_MD_BLAKE2S256);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    uint8_t input[5050] = {0};
    uint32_t inLenTotal = 0;
    uint8_t out1[CRYPT_BLAKE2S256_DIGESTSIZE] = {0};
    uint8_t out2[CRYPT_BLAKE2S256_DIGESTSIZE] = {0};
    uint32_t outLen = sizeof(out1);

    for (uint32_t i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)i;
    }

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx2), CRYPT_SUCCESS);

    for (uint32_t inLenBase = 1; inLenBase <= 100; inLenBase++) {
        ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx1, input + inLenTotal, inLenBase), CRYPT_SUCCESS);
        inLenTotal += inLenBase;
    }
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx1, out1, &outLen), CRYPT_SUCCESS);

    outLen = sizeof(out2);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx2, input, inLenTotal), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx2, out2, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(memcmp(out1, out2, CRYPT_BLAKE2S256_DIGESTSIZE), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx1);
    CRYPT_EAL_MdFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BLAKE2S_COPY_CTX_FUNC_TC001
 * @title  BLAKE2s copy and duplicate context test.
 * @brief  Validate null copy/dup error paths, then copy and duplicate a context
 *         after hashing a prefix and continue both contexts with the same suffix.
 * @expect Copied and duplicated contexts produce the expected digest and retain
 *         the original algorithm id.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BLAKE2S_COPY_CTX_FUNC_TC001(int id, Hex *prefix, Hex *suffix, Hex *hash)
{
    TestMemInit();
    uint8_t output[CRYPT_BLAKE2S256_DIGESTSIZE] = {0};
    uint32_t outputLen = sizeof(output);
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(id);
    CRYPT_EAL_MdCtx *copyCtx = CRYPT_EAL_MdNewCtx(id);
    CRYPT_EAL_MdCtx *dupCtx = NULL;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(copyCtx != NULL);

    dupCtx = CRYPT_EAL_MdDupCtx(NULL);
    ASSERT_TRUE(dupCtx == NULL);
    ASSERT_EQ(CRYPT_EAL_MdGetId(dupCtx), CRYPT_MD_MAX);
    ASSERT_EQ(CRYPT_EAL_MdCopyCtx(NULL, ctx), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdCopyCtx(copyCtx, NULL), CRYPT_NULL_INPUT);
    TestErrClear();

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, prefix->x, prefix->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdCopyCtx(copyCtx, ctx), CRYPT_SUCCESS);
    dupCtx = CRYPT_EAL_MdDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(copyCtx, suffix->x, suffix->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(copyCtx, output, &outputLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("blake2s-copy", output, outputLen, hash->x, hash->len);

    outputLen = sizeof(output);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(dupCtx, suffix->x, suffix->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(dupCtx, output, &outputLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("blake2s-dup", output, outputLen, hash->x, hash->len);
    ASSERT_EQ(CRYPT_EAL_MdGetId(dupCtx), id);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
    CRYPT_EAL_MdFreeCtx(copyCtx);
    CRYPT_EAL_MdFreeCtx(dupCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BLAKE2S_PROVIDER_FUNC_TC001
 * @title  BLAKE2s default provider vector test.
 * @brief  Create a default-provider BLAKE2s-256 context when provider support is
 *         enabled, otherwise use the regular EAL context, then hash a vector.
 * @expect The provider or fallback streaming digest matches the expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BLAKE2S_PROVIDER_FUNC_TC001(int id, Hex *msg, Hex *hash)
{
    TestMemInit();
    uint8_t output[CRYPT_BLAKE2S256_DIGESTSIZE] = {0};
    uint32_t outputLen = sizeof(output);
    CRYPT_EAL_MdCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderMdNewCtx(NULL, id, "provider=default");
#else
    ctx = CRYPT_EAL_MdNewCtx(id);
#endif
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outputLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("blake2s-provider", output, outputLen, hash->x, hash->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BLAKE2S_PROVIDER_FUNC_TC002
 * @title  BLAKE2s default provider one-shot vector test.
 * @brief  Hash one vector through the default-provider one-shot interface when
 *         provider support is enabled, otherwise through the regular EAL one-shot API.
 * @expect The one-shot digest matches the expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BLAKE2S_PROVIDER_FUNC_TC002(int id, Hex *msg, Hex *hash)
{
    TestMemInit();
    uint8_t output[CRYPT_BLAKE2S256_DIGESTSIZE] = {0};
    uint32_t outputLen = sizeof(output);
#ifdef HITLS_CRYPTO_PROVIDER
    ASSERT_EQ(CRYPT_EAL_ProviderMd(NULL, id, "provider=default", msg->x, msg->len, output, &outputLen),
        CRYPT_SUCCESS);
#else
    ASSERT_EQ(CRYPT_EAL_Md(id, msg->x, msg->len, output, &outputLen), CRYPT_SUCCESS);
#endif
    ASSERT_EQ(outputLen, CRYPT_BLAKE2S256_DIGESTSIZE);
    ASSERT_COMPARE("blake2s-provider-one-shot", output, outputLen, hash->x, hash->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    return;
}
/* END_CASE */
