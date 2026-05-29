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
#include "crypt_errno.h"
#include "crypt_asconhash.h"
#include "bsl_sal.h"
#include <string.h>

/* Helper struct for parameterized tests over ASCON-HASH128 / ASCON-HASH128A */
typedef struct {
    CRYPT_ASCONHASH_Ctx *(*NewCtx)(void);
    void (*FreeCtx)(CRYPT_ASCONHASH_Ctx *);
    int32_t (*Init)(CRYPT_ASCONHASH_Ctx *);
    int32_t (*Update)(CRYPT_ASCONHASH_Ctx *, const uint8_t *, uint32_t);
    int32_t (*Final)(CRYPT_ASCONHASH_Ctx *, uint8_t *, uint32_t *);
    int32_t (*Deinit)(CRYPT_ASCONHASH_Ctx *);
    int32_t (*CopyCtx)(CRYPT_ASCONHASH_Ctx *, const CRYPT_ASCONHASH_Ctx *);
    CRYPT_ASCONHASH_Ctx *(*DupCtx)(const CRYPT_ASCONHASH_Ctx *);
    int32_t digestSize;
    int32_t blockSize;
} HashApi;

static const HashApi g_hash128 = {
    CRYPT_ASCON_HASH128_NewCtx, CRYPT_ASCON_HASH128_FreeCtx,
    CRYPT_ASCON_HASH128_Init, CRYPT_ASCON_HASH128_Update, CRYPT_ASCON_HASH128_Final,
    CRYPT_ASCON_HASH128_Deinit, CRYPT_ASCON_HASH128_CopyCtx, CRYPT_ASCON_HASH128_DupCtx,
    CRYPT_ASCON_HASH128_DIGESTSIZE, CRYPT_ASCON_HASH128_BLOCKSIZE
};

static const HashApi g_hash128a = {
    CRYPT_ASCON_HASH128A_NewCtx, CRYPT_ASCON_HASH128A_FreeCtx,
    CRYPT_ASCON_HASH128A_Init, CRYPT_ASCON_HASH128A_Update, CRYPT_ASCON_HASH128A_Final,
    CRYPT_ASCON_HASH128A_Deinit, CRYPT_ASCON_HASH128A_CopyCtx, CRYPT_ASCON_HASH128A_DupCtx,
    CRYPT_ASCON_HASH128A_DIGESTSIZE, CRYPT_ASCON_HASH128A_BLOCKSIZE
};

/* Multi-thread test parameter */
typedef struct {
    const HashApi *api;
    uint8_t *data;
    uint8_t *hash;
    uint32_t dataLen;
    uint32_t hashLen;
} ThreadParam;

void AsconHashMultiThreadTest(void *arg)
{
    ThreadParam *tp = (ThreadParam *)arg;
    CRYPT_ASCONHASH_Ctx *ctx = tp->api->NewCtx();
    ASSERT_TRUE(ctx != NULL);
    for (uint32_t i = 0; i < 10; i++) {
        uint8_t out[32];
        uint32_t outLen = sizeof(out);
        ASSERT_EQ(tp->api->Init(ctx), CRYPT_SUCCESS);
        ASSERT_EQ(tp->api->Update(ctx, tp->data, tp->dataLen), CRYPT_SUCCESS);
        ASSERT_EQ(tp->api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
        ASSERT_EQ(outLen, tp->hashLen);
        ASSERT_EQ(memcmp(out, tp->hash, tp->hashLen), 0);
    }
EXIT:
    tp->api->FreeCtx(ctx);
}


/* ===================================================================
 * Generic helpers written as pass-through functions so that the SDV
 * framework can call them from the specific test bodies.
 * =================================================================== */

/* API_TC001: NewCtx / FreeCtx boundary */
static void ApiTest_NewCtx_FreeCtx(const HashApi *api)
{
    TestMemInit();

    /* 1. NewCtx normal */
    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    /* 2. FreeCtx(NULL) - should not crash */
    api->FreeCtx(NULL);

    /* 3. Double FreeCtx - call once normally, second call should not crash */
    api->FreeCtx(ctx);
    ctx = NULL;  /* prevent double-free in EXIT */

    /* 4. NewCtx returns non-NULL after previous FreeCtx */
    ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

EXIT:
    api->FreeCtx(ctx);
}

/* API_TC002: Init boundary */
static void ApiTest_Init(const HashApi *api)
{
    TestMemInit();

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    /* 1. Init(NULL) */
    ASSERT_EQ(api->Init(NULL), CRYPT_NULL_INPUT);

    /* 2. Init normal */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);

    /* 3. Re-Init (double init) - should be allowed or return success */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);

EXIT:
    api->FreeCtx(ctx);
}

/* API_TC003: Update boundary */
static void ApiTest_Update(const HashApi *api)
{
    TestMemInit();
    uint8_t buf[16] = {0};

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    /* 1. Update(NULL, buf, 16) */
    ASSERT_EQ(api->Update(NULL, buf, sizeof(buf)), CRYPT_NULL_INPUT);

    /* 2. Update(ctx, NULL, 16) */
    ASSERT_EQ(api->Update(ctx, NULL, sizeof(buf)), CRYPT_NULL_INPUT);

    /* 3. Update before Init */
    ASSERT_EQ(api->Update(ctx, buf, sizeof(buf)), CRYPT_EAL_ERR_STATE);

    /* 4. Init and Update with zero length */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, buf, 0), CRYPT_SUCCESS);

    /* 5. Update normal */
    ASSERT_EQ(api->Update(ctx, buf, sizeof(buf)), CRYPT_SUCCESS);

EXIT:
    api->FreeCtx(ctx);
}

/* API_TC004: Final boundary */
static void ApiTest_Final(const HashApi *api)
{
    TestMemInit();
    uint8_t buf[16] = {0};
    uint8_t out[32] = {0};
    uint32_t outLen = sizeof(out);

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    /* 1. Final(NULL, out, &outLen) - ctx=NULL */
    ASSERT_EQ(api->Final(NULL, out, &outLen), CRYPT_NULL_INPUT);

    /* 2. Final(ctx, NULL, &outLen) - out=NULL */
    ASSERT_EQ(api->Final(ctx, NULL, &outLen), CRYPT_NULL_INPUT);

    /* 3. Final(ctx, out, NULL) - outLen=NULL */
    ASSERT_EQ(api->Final(ctx, out, NULL), CRYPT_NULL_INPUT);

    /* 4. Final before Init - state error */
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_EAL_ERR_STATE);

    /* 5. Init+Update, then output buffer too small */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, buf, sizeof(buf)), CRYPT_SUCCESS);
    outLen = api->digestSize - 1;
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH);

    /* 6. Normal Final */
    outLen = sizeof(out);
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, buf, sizeof(buf)), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);

EXIT:
    api->FreeCtx(ctx);
}

/* API_TC005: State machine timing */
static void ApiTest_StateMachine(const HashApi *api)
{
    TestMemInit();
    uint8_t buf[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t out[32] = {0};
    uint32_t outLen = sizeof(out);

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    /* 1. Final after Final - should return STATE_ERROR */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, buf, sizeof(buf)), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_EAL_ERR_STATE);

    /* 2. Update after Final */
    ASSERT_EQ(api->Update(ctx, buf, sizeof(buf)), CRYPT_EAL_ERR_STATE);

    /* 3. Deinit then reinit - full lifecycle */
    ASSERT_EQ(api->Deinit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, buf, sizeof(buf)), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);

    /* 4. Init -> Final (empty message equivalent) */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);

    /* 5. Init -> Update -> Update -> Final (multi-update) */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, buf, 4), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, buf + 4, 4), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);

EXIT:
    api->FreeCtx(ctx);
}

/* API_TC006: CopyCtx boundary tests */
static void ApiTest_CopyCtx(const HashApi *api, Hex *msg, Hex *expectedHash)
{
    TestMemInit();
    uint8_t out[32] = {0};
    uint32_t outLen = sizeof(out);

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);
    CRYPT_ASCONHASH_Ctx *dst = api->NewCtx();
    ASSERT_TRUE(dst != NULL);

    /* 1. CopyCtx(NULL, ctx) */
    ASSERT_EQ(api->CopyCtx(NULL, ctx), CRYPT_NULL_INPUT);

    /* 2. CopyCtx(dst, NULL) */
    ASSERT_EQ(api->CopyCtx(dst, NULL), CRYPT_NULL_INPUT);

    /* 3. CopyCtx(NULL, NULL) */
    ASSERT_EQ(api->CopyCtx(NULL, NULL), CRYPT_NULL_INPUT);

    /* 4. DupCtx(NULL) */
    CRYPT_ASCONHASH_Ctx *dup = api->DupCtx(NULL);
    ASSERT_TRUE(dup == NULL);

    /* 5. Copy after partial update, then complete both independently */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, msg->x, msg->len), CRYPT_SUCCESS);

    /* Copy half-updated context */
    ASSERT_EQ(api->CopyCtx(dst, ctx), CRYPT_SUCCESS);

    /* Complete both independently */
    outLen = sizeof(out);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);

    outLen = sizeof(out);
    ASSERT_EQ(api->Final(dst, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);

    /* 6. DupCtx - create independent copy */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    dup = api->DupCtx(ctx);
    ASSERT_TRUE(dup != NULL);

    outLen = sizeof(out);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(api->Final(dup, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);

    api->FreeCtx(dup);
    dup = NULL;

    /* 7. CopyCtx before Init (uninit state) */
    CRYPT_ASCONHASH_Ctx *uninitDst = api->NewCtx();
    ASSERT_TRUE(uninitDst != NULL);
    CRYPT_ASCONHASH_Ctx *uninitSrc = api->NewCtx();
    ASSERT_TRUE(uninitSrc != NULL);
    ASSERT_EQ(api->CopyCtx(uninitDst, uninitSrc), CRYPT_SUCCESS);

    api->FreeCtx(uninitDst);
    api->FreeCtx(uninitSrc);

EXIT:
    api->FreeCtx(ctx);
    api->FreeCtx(dst);
    api->FreeCtx(dup);
}

/* API_TC007: Reset/Reinit lifecycle */
static void ApiTest_ResetReinit(const HashApi *api, Hex *msg, Hex *expectedHash)
{
    TestMemInit();
    uint8_t buf[8] = {0xFF};
    uint8_t out[32] = {0};
    uint32_t outLen = sizeof(out);

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    /* 1. Init -> Update -> Final -> Deinit -> Init -> Update -> Final (reuse) */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);

    /* Reinit and compute second different message */
    ASSERT_EQ(api->Deinit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, buf, sizeof(buf)), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);

    /* Third reuse cycle - just Init -> Final (empty) */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);

EXIT:
    api->FreeCtx(ctx);
}

/* FUNC_TC001: Empty message hash */
static void FuncTest_Empty(const HashApi *api, Hex *expectedHash)
{
    TestMemInit();
    uint8_t out[32];
    uint32_t outLen = sizeof(out);

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    api->FreeCtx(ctx);
}

/* FUNC_TC002: Single-segment KAT test */
static void FuncTest_SingleKat(const HashApi *api, Hex *data, Hex *expectedHash)
{
    TestMemInit();
    uint8_t out[32];
    uint32_t outLen = sizeof(out);

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    api->FreeCtx(ctx);
}

/* FUNC_TC003: Multi-segment streaming test (2 or 3 segments) */
static void FuncTest_MultiSegment3(const HashApi *api,
    Hex *data1, Hex *data2, Hex *data3, Hex *expectedHash)
{
    TestMemInit();
    uint8_t out[32];
    uint32_t outLen = sizeof(out);

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, data1->x, data1->len), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, data2->x, data2->len), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, data3->x, data3->len), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    api->FreeCtx(ctx);
}

/* FUNC_TC004: Two-segment streaming test */
static void FuncTest_MultiSegment2(const HashApi *api,
    Hex *data1, Hex *data2, Hex *expectedHash)
{
    TestMemInit();
    uint8_t out[32];
    uint32_t outLen = sizeof(out);

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, data1->x, data1->len), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, data2->x, data2->len), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    api->FreeCtx(ctx);
}

/* FUNC_TC005: Byte-by-byte streaming */
static void FuncTest_ByteByByte(const HashApi *api, Hex *data, Hex *expectedHash)
{
    TestMemInit();
    uint8_t out[32];
    uint32_t outLen = sizeof(out);

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    for (uint32_t i = 0; i < data->len; i++) {
        ASSERT_EQ(api->Update(ctx, &data->x[i], 1), CRYPT_SUCCESS);
    }
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    api->FreeCtx(ctx);
}

/* FUNC_TC006: Mixed streaming (empty + normal + tail) */
static void FuncTest_MixedStream(const HashApi *api, Hex *data, Hex *expectedHash)
{
    TestMemInit();
    uint8_t out[32];
    uint32_t outLen = sizeof(out);
    uint32_t half = data->len / 2;

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    /* Empty update */
    ASSERT_EQ(api->Update(ctx, data->x, 0), CRYPT_SUCCESS);
    /* First half */
    ASSERT_EQ(api->Update(ctx, data->x, half), CRYPT_SUCCESS);
    /* Another empty update */
    ASSERT_EQ(api->Update(ctx, NULL, 0), CRYPT_SUCCESS);
    /* Second half */
    ASSERT_EQ(api->Update(ctx, data->x + half, data->len - half), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    api->FreeCtx(ctx);
}

/* FUNC_TC007: KAT pattern diversity test (all-zeros + all-FFs as non-KAT)
 * Verifies: (1) seq 64-byte KAT vector, (2) 64 zero bytes length correct, (3) 64 0xFF diff from zeros */
static void FuncTest_AllZerosAllFFs(const HashApi *api, Hex *data, Hex *expectedHash)
{
    TestMemInit();
    uint8_t out[32];
    uint8_t outZeros[32];
    uint8_t outOnes[32];
    uint32_t outLen = sizeof(out);
    uint8_t zeros[64] = {0};
    uint8_t ones[64];
    memset(ones, 0xFF, sizeof(ones));

    CRYPT_ASCONHASH_Ctx *ctx = api->NewCtx();
    ASSERT_TRUE(ctx != NULL);

    /* 1. KAT verification for the given message */
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_EQ(memcmp(out, expectedHash->x, expectedHash->len), 0);

    /* 2. 64 zero bytes - verify output length */
    outLen = sizeof(outZeros);
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, zeros, sizeof(zeros)), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, outZeros, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);

    /* 3. 64 0xFF bytes - verify output length and different from zeros hash */
    outLen = sizeof(outOnes);
    ASSERT_EQ(api->Init(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(api->Update(ctx, ones, sizeof(ones)), CRYPT_SUCCESS);
    ASSERT_EQ(api->Final(ctx, outOnes, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, (uint32_t)api->digestSize);
    ASSERT_TRUE(memcmp(outZeros, outOnes, api->digestSize) != 0);

EXIT:
    api->FreeCtx(ctx);
}

/* FUNC_TC008: Multi-thread test */
static void FuncTest_MultiThread(const HashApi *api, Hex *data, Hex *expectedHash)
{
    int ret;
    TestMemInit();
    const uint32_t threadNum = 3;
    pthread_t thrd[3];
    ThreadParam arg[3];
    for (uint32_t i = 0; i < threadNum; i++) {
        arg[i].api = api;
        arg[i].data = data->x;
        arg[i].hash = expectedHash->x;
        arg[i].dataLen = data->len;
        arg[i].hashLen = expectedHash->len;
    }
    for (uint32_t i = 0; i < threadNum; i++) {
        ret = pthread_create(&thrd[i], NULL, (void *)AsconHashMultiThreadTest, &arg[i]);
        ASSERT_TRUE(ret == 0);
    }
    for (uint32_t i = 0; i < threadNum; i++) {
        pthread_join(thrd[i], NULL);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    return;
}

/* END_HEADER */

/* ===================================================================
 * Instantiate all test cases for ASCON-HASH128
 * =================================================================== */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_API_TC001
 * @title  CRYPT_ASCON_HASH128 NewCtx/FreeCtx boundary test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create ctx. Expected result 1.
 *    2. Call FreeCtx(NULL). Expected result 2.
 *    3. Call FreeCtx, then call again (double free). Expected result 3.
 *    4. Create new ctx again. Expected result 4.
 * @expect
 *    1. ctx is not NULL.
 *    2. No crash.
 *    3. No crash.
 *    4. ctx is not NULL.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_API_TC001(void)
{
    ApiTest_NewCtx_FreeCtx(&g_hash128);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_API_TC002
 * @title  CRYPT_ASCON_HASH128 Init boundary test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init(NULL). Expected result 1.
 *    2. Init(normal). Expected result 2.
 *    3. Init again (re-init). Expected result 3.
 * @expect
 *    1. Return CRYPT_NULL_INPUT.
 *    2. Return CRYPT_SUCCESS.
 *    3. Return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_API_TC002(void)
{
    ApiTest_Init(&g_hash128);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_API_TC003
 * @title  CRYPT_ASCON_HASH128 Update boundary test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Update(NULL, buf, 16). Expected result 1.
 *    2. Update(ctx, NULL, 16). Expected result 2.
 *    3. Update before Init. Expected result 3.
 *    4. Init then Update with 0 length. Expected result 4.
 *    5. Update normally. Expected result 5.
 * @expect
 *    1. Return CRYPT_NULL_INPUT.
 *    2. Return CRYPT_NULL_INPUT.
 *    3. Return CRYPT_EAL_ERR_STATE.
 *    4. Return CRYPT_SUCCESS.
 *    5. Return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_API_TC003(void)
{
    ApiTest_Update(&g_hash128);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_API_TC004
 * @title  CRYPT_ASCON_HASH128 Final boundary test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Final(NULL, out, &outLen). Expected result 1.
 *    2. Final(ctx, NULL, &outLen). Expected result 2.
 *    3. Final(ctx, out, NULL). Expected result 3.
 *    4. Final before Init. Expected result 4.
 *    5. Output buffer too small. Expected result 5.
 *    6. Normal Final. Expected result 6.
 * @expect
 *    1. Return CRYPT_NULL_INPUT.
 *    2. Return CRYPT_NULL_INPUT.
 *    3. Return CRYPT_NULL_INPUT.
 *    4. Return CRYPT_EAL_ERR_STATE.
 *    5. Return CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH.
 *    6. CRYPT_SUCCESS, outLen=32.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_API_TC004(void)
{
    ApiTest_Final(&g_hash128);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_API_TC005
 * @title  CRYPT_ASCON_HASH128 state machine timing test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update->Final then Final again (repeated Final allowed). Expected result 1.
 *    2. Update after Final. Expected result 2.
 *    3. Deinit->Init->Update->Final full lifecycle. Expected result 3.
 *    4. Init->Final (empty message). Expected result 4.
 *    5. Init->Update->Update->Final (multi-update). Expected result 5.
 * @expect
 *    1. Return CRYPT_EAL_ERR_STATE.
 *    2. Return CRYPT_EAL_ERR_STATE.
 *    3. All CRYPT_SUCCESS.
 *    4. CRYPT_SUCCESS, outLen=32.
 *    5. CRYPT_SUCCESS, outLen=32.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_API_TC005(void)
{
    ApiTest_StateMachine(&g_hash128);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_API_TC006
 * @title  CRYPT_ASCON_HASH128 CopyCtx/DupCtx boundary test
 * @precon Registering memory-related functions.
 * @brief
 *    1. CopyCtx(NULL, ctx). Expected result 1.
 *    2. CopyCtx(dst, NULL). Expected result 2.
 *    3. CopyCtx(NULL, NULL). Expected result 3.
 *    4. DupCtx(NULL). Expected result 4.
 *    5. CopyCtx after partial update, both final results identical. Expected result 5.
 *    6. DupCtx independent copy. Expected result 6.
 *    7. CopyCtx uninit context. Expected result 7.
 * @expect
 *    1. Return CRYPT_NULL_INPUT.
 *    2. Return CRYPT_NULL_INPUT.
 *    3. Return CRYPT_NULL_INPUT.
 *    4. Return NULL.
 *    5. CRYPT_SUCCESS, both hashes match expected.
 *    6. CRYPT_SUCCESS, dup result matches expected.
 *    7. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_API_TC006(Hex *msg, Hex *expectedHash)
{
    ApiTest_CopyCtx(&g_hash128, msg, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_API_TC007
 * @title  CRYPT_ASCON_HASH128 Reset/Reinit lifecycle test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update->Final->Deinit->Init->Update->Final. Expected result 1.
 *    2. Init->Final (empty after reinit). Expected result 2.
 * @expect
 *    1. Both computations succeed, first result matches expected.
 *    2. CRYPT_SUCCESS, outLen=32.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_API_TC007(Hex *msg, Hex *expectedHash)
{
    ApiTest_ResetReinit(&g_hash128, msg, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC001
 * @title  ASCON-HASH128 empty message hash
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init + Final without Update. Expected result 1.
 *    2. Compare with KAT value. Expected result 2.
 * @expect
 *    1. CRYPT_SUCCESS, outLen=32.
 *    2. Hash matches KAT.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC001(Hex *expectedHash)
{
    FuncTest_Empty(&g_hash128, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC002
 * @title  ASCON-HASH128 single-segment KAT test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update->Final. Expected result 1.
 *    2. Compare with KAT hash. Expected result 2.
 * @expect
 *    1. CRYPT_SUCCESS.
 *    2. Hash matches KAT.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC002(Hex *data, Hex *expectedHash)
{
    FuncTest_SingleKat(&g_hash128, data, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC003
 * @title  ASCON-HASH128 3-segment streaming test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update(seg1)->Update(seg2)->Update(seg3)->Final. Expected result 1.
 *    2. Compare with KAT hash of concatenated message. Expected result 2.
 * @expect
 *    1. CRYPT_SUCCESS.
 *    2. Hash matches KAT.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC003(Hex *data1, Hex *data2, Hex *data3, Hex *expectedHash)
{
    FuncTest_MultiSegment3(&g_hash128, data1, data2, data3, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC004
 * @title  ASCON-HASH128 cross-rate-boundary 2-segment streaming test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update(seg1)->Update(seg2)->Final. Expected result 1.
 *    2. Compare with KAT hash. Expected result 2.
 * @expect
 *    1. CRYPT_SUCCESS.
 *    2. Hash matches KAT.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC004(Hex *data1, Hex *data2, Hex *expectedHash)
{
    FuncTest_MultiSegment2(&g_hash128, data1, data2, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC005
 * @title  ASCON-HASH128 byte-by-byte streaming test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init then update each byte individually. Expected result 1.
 *    2. Compare with single-update hash. Expected result 2.
 * @expect
 *    1. All updates succeed.
 *    2. Hash matches expected KAT value.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC005(Hex *data, Hex *expectedHash)
{
    FuncTest_ByteByByte(&g_hash128, data, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC006
 * @title  ASCON-HASH128 mixed streaming (empty+normal+tail) test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update(empty)->Update(half)->Update(empty)->Update(tail)->Final.
 *    2. Compare with expected KAT hash.
 * @expect
 *    1. All updates succeed.
 *    2. Hash matches KAT.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC006(Hex *data, Hex *expectedHash)
{
    FuncTest_MixedStream(&g_hash128, data, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC007
 * @title  ASCON-HASH128 KAT diversity test (all-zeros + all-FFs patterns)
 * @precon Registering memory-related functions.
 * @brief
 *    1. Hash given KAT message. Compare with KAT hash. Expected result 1.
 *    2. Hash 64 zero bytes. Verify output length. Expected result 2.
 *    3. Hash 64 0xFF bytes. Verify output length and diff from zeros. Expected result 3.
 * @expect
 *    1. Hash matches KAT.
 *    2. Output length 32.
 *    3. Output length 32, different from zero hash.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC007(Hex *data, Hex *expectedHash)
{
    FuncTest_AllZerosAllFFs(&g_hash128, data, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC008
 * @title  ASCON-HASH128 multi-thread concurrent computation test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create 3 threads, each performing 10x Init->Update->Final cycles.
 *    2. Compare each result with expected KAT hash.
 * @expect
 *    1. All threads complete successfully.
 *    2. All results match expected KAT hash.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128_FUNC_TC008(Hex *data, Hex *expectedHash)
{
    FuncTest_MultiThread(&g_hash128, data, expectedHash);
}
/* END_CASE */

/* ===================================================================
 * Instantiate all test cases for ASCON-HASH128A
 * =================================================================== */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_API_TC001
 * @title  CRYPT_ASCON_HASH128A NewCtx/FreeCtx boundary test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create ctx. Expected result 1.
 *    2. Call FreeCtx(NULL). Expected result 2.
 *    3. FreeCtx then free again. Expected result 3.
 *    4. Create new ctx again. Expected result 4.
 * @expect
 *    1. ctx is not NULL.
 *    2. No crash.
 *    3. No crash.
 *    4. ctx is not NULL.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_API_TC001(void)
{
    ApiTest_NewCtx_FreeCtx(&g_hash128a);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_API_TC002
 * @title  CRYPT_ASCON_HASH128A Init boundary test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init(NULL). Expected result 1.
 *    2. Init(normal). Expected result 2.
 *    3. Init again. Expected result 3.
 * @expect
 *    1. Return CRYPT_NULL_INPUT.
 *    2. Return CRYPT_SUCCESS.
 *    3. Return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_API_TC002(void)
{
    ApiTest_Init(&g_hash128a);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_API_TC003
 * @title  CRYPT_ASCON_HASH128A Update boundary test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Update(NULL, buf, 16). Expected result 1.
 *    2. Update(ctx, NULL, 16). Expected result 2.
 *    3. Update before Init. Expected result 3.
 *    4. Init then Update with 0 length. Expected result 4.
 *    5. Update normally. Expected result 5.
 * @expect
 *    1. Return CRYPT_NULL_INPUT.
 *    2. Return CRYPT_NULL_INPUT.
 *    3. Return CRYPT_EAL_ERR_STATE.
 *    4. Return CRYPT_SUCCESS.
 *    5. Return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_API_TC003(void)
{
    ApiTest_Update(&g_hash128a);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_API_TC004
 * @title  CRYPT_ASCON_HASH128A Final boundary test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Final(NULL, out, &outLen). Expected result 1.
 *    2. Final(ctx, NULL, &outLen). Expected result 2.
 *    3. Final(ctx, out, NULL). Expected result 3.
 *    4. Final before Init. Expected result 4.
 *    5. Output buffer too small. Expected result 5.
 *    6. Normal Final. Expected result 6.
 * @expect
 *    1. Return CRYPT_NULL_INPUT.
 *    2. Return CRYPT_NULL_INPUT.
 *    3. Return CRYPT_NULL_INPUT.
 *    4. Return CRYPT_EAL_ERR_STATE.
 *    5. Return CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH.
 *    6. CRYPT_SUCCESS, outLen=32.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_API_TC004(void)
{
    ApiTest_Final(&g_hash128a);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_API_TC005
 * @title  CRYPT_ASCON_HASH128A state machine timing test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update->Final then Final again. Expected result 1.
 *    2. Update after Final. Expected result 2.
 *    3. Deinit->Init->Update->Final full lifecycle. Expected result 3.
 *    4. Init->Final (empty). Expected result 4.
 *    5. Init->Update->Update->Final. Expected result 5.
 * @expect
 *    1. Return CRYPT_EAL_ERR_STATE.
 *    2. Return CRYPT_EAL_ERR_STATE.
 *    3. All CRYPT_SUCCESS.
 *    4. CRYPT_SUCCESS.
 *    5. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_API_TC005(void)
{
    ApiTest_StateMachine(&g_hash128a);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_API_TC006
 * @title  CRYPT_ASCON_HASH128A CopyCtx/DupCtx boundary test
 * @precon Registering memory-related functions.
 * @brief
 *    1. CopyCtx(NULL, ctx). Expected result 1.
 *    2. CopyCtx(dst, NULL). Expected result 2.
 *    3. CopyCtx(NULL, NULL). Expected result 3.
 *    4. DupCtx(NULL). Expected result 4.
 *    5. CopyCtx after partial update, both final results identical. Expected result 5.
 *    6. DupCtx independent copy. Expected result 6.
 *    7. CopyCtx uninit context. Expected result 7.
 * @expect
 *    1. Return CRYPT_NULL_INPUT.
 *    2. Return CRYPT_NULL_INPUT.
 *    3. Return CRYPT_NULL_INPUT.
 *    4. Return NULL.
 *    5. CRYPT_SUCCESS, both hashes match expected.
 *    6. CRYPT_SUCCESS.
 *    7. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_API_TC006(Hex *msg, Hex *expectedHash)
{
    ApiTest_CopyCtx(&g_hash128a, msg, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_API_TC007
 * @title  CRYPT_ASCON_HASH128A Reset/Reinit lifecycle test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update->Final->Deinit->Init->Update->Final. Expected result 1.
 *    2. Init->Final (empty after reinit). Expected result 2.
 * @expect
 *    1. Both computations succeed.
 *    2. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_API_TC007(Hex *msg, Hex *expectedHash)
{
    ApiTest_ResetReinit(&g_hash128a, msg, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC001
 * @title  ASCON-HASH128A empty message hash
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init + Final. Expected result 1.
 *    2. Compare with KAT. Expected result 2.
 * @expect
 *    1. CRYPT_SUCCESS, outLen=32.
 *    2. Hash matches KAT.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC001(Hex *expectedHash)
{
    FuncTest_Empty(&g_hash128a, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC002
 * @title  ASCON-HASH128A single-segment KAT test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update->Final. Expected result 1.
 *    2. Compare with KAT hash. Expected result 2.
 * @expect
 *    1. CRYPT_SUCCESS.
 *    2. Hash matches KAT.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC002(Hex *data, Hex *expectedHash)
{
    FuncTest_SingleKat(&g_hash128a, data, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC003
 * @title  ASCON-HASH128A 3-segment streaming test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update(seg1)->Update(seg2)->Update(seg3)->Final. Expected result 1.
 *    2. Compare with KAT hash. Expected result 2.
 * @expect
 *    1. CRYPT_SUCCESS.
 *    2. Hash matches KAT.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC003(Hex *data1, Hex *data2, Hex *data3, Hex *expectedHash)
{
    FuncTest_MultiSegment3(&g_hash128a, data1, data2, data3, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC004
 * @title  ASCON-HASH128A cross-rate-boundary streaming test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update(seg1)->Update(seg2)->Final. Expected result 1.
 *    2. Compare with KAT hash. Expected result 2.
 * @expect
 *    1. CRYPT_SUCCESS.
 *    2. Hash matches KAT.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC004(Hex *data1, Hex *data2, Hex *expectedHash)
{
    FuncTest_MultiSegment2(&g_hash128a, data1, data2, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC005
 * @title  ASCON-HASH128A byte-by-byte streaming test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init then update each byte individually. Expected result 1.
 *    2. Compare with single-update hash. Expected result 2.
 * @expect
 *    1. All updates succeed.
 *    2. Hash matches expected KAT value.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC005(Hex *data, Hex *expectedHash)
{
    FuncTest_ByteByByte(&g_hash128a, data, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC006
 * @title  ASCON-HASH128A mixed streaming (empty+normal+tail) test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Init->Update(empty)->Update(half)->Update(empty)->Update(tail)->Final.
 *    2. Compare with KAT hash.
 * @expect
 *    1. All updates succeed.
 *    2. Hash matches KAT.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC006(Hex *data, Hex *expectedHash)
{
    FuncTest_MixedStream(&g_hash128a, data, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC007
 * @title  ASCON-HASH128A KAT diversity test (all-zeros + all-FFs patterns)
 * @precon Registering memory-related functions.
 * @brief
 *    1. Hash given KAT message. Compare with KAT hash. Expected result 1.
 *    2. Hash 64 zero bytes. Verify output length. Expected result 2.
 *    3. Hash 64 0xFF bytes. Verify output length and diff from zeros. Expected result 3.
 * @expect
 *    1. Hash matches KAT.
 *    2. Output length 32.
 *    3. Output length 32, different from zero hash.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC007(Hex *data, Hex *expectedHash)
{
    FuncTest_AllZerosAllFFs(&g_hash128a, data, expectedHash);
}
/* END_CASE */

/**
 * @test  SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC008
 * @title  ASCON-HASH128A multi-thread concurrent computation test
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create 3 threads, each performing 10x Init->Update->Final cycles.
 *    2. Compare each result with expected KAT hash.
 * @expect
 *    1. All threads complete successfully.
 *    2. All results match expected KAT hash.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_ASCONHASH128A_FUNC_TC008(Hex *data, Hex *expectedHash)
{
    FuncTest_MultiThread(&g_hash128a, data, expectedHash);
}
/* END_CASE */
