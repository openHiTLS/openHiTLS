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
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <pthread.h>
#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#endif
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "eal_drbg_local.h"
#include "crypt_entropy.h"
#include "crypt_eal_rand.h"
#include "eal_entropy.h"
#include "eal_md_local.h"
#include "crypt_eal_entropy.h"
#include "crypt_algid.h"
#include "bsl_list.h"
#include "es_cf.h"
#include "es_noise_source.h"
#include "es_ns_delta_common.h"
#include "es_entropy_local.h"
#include "es_entropy_pool.h"
#include "stub_utils.h"

#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && \
    defined(_SC_LEVEL1_DCACHE_SIZE) && !defined(HITLS_BSL_SAL_DARWIN) && (LONG_MAX > UINT32_MAX)
STUB_DEFINE_RET1(long, sysconf, int);
static long gEntropySysconfValue;

static long EntropySysconfStub(int name)
{
    (void)name;
    return gEntropySysconfValue;
}
#endif

#if defined(HITLS_CRYPTO_ENTROPY)
/* Interposing the wipe lets the suite observe it while the caller's frame is
   still alive, so no dead frame is ever read. While inactive the interposed
   entry forwards to the real implementation, so other cases are unaffected. */
STUB_DEFINE_VOID2(BSL_SAL_CleanseData, void *, uint32_t);

static uint8_t *g_ecfWipePtr;
static uint32_t g_ecfWipeLen;
static uint32_t g_ecfWipeSeen;
static uint32_t g_ecfWipeNonZero;

static void EntropyCleanseProbe(void *ptr, uint32_t size)
{
    if (ptr == g_ecfWipePtr && g_ecfWipePtr != NULL) {
        g_ecfWipeSeen++;
        g_ecfWipeLen = size;
        for (uint32_t i = 0; i < size; i++) {
            if (((uint8_t *)ptr)[i] != 0) {
                g_ecfWipeNonZero++;
                break;
            }
        }
    }
    real_BSL_SAL_CleanseData_func_t real = get_real_BSL_SAL_CleanseData();
    if (real != NULL) {
        real(ptr, size);
    }
}
#endif

/* Detect if running on WSL by checking /proc/version */
__attribute__((unused)) static bool IsRunningOnWSL(void)
{
    FILE *fp = fopen("/proc/version", "r");
    if (fp == NULL) {
        return false;
    }
    char buf[256] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    if (n == 0) {
        return false;
    }
    return (strstr(buf, "microsoft") != NULL || strstr(buf, "Microsoft") != NULL || strstr(buf, "WSL") != NULL);
}

#ifdef HITLS_CRYPTO_ENTROPY_SYS
/* NTG.1.4 seeds the pool at init; pool-mechanics tests that assume an empty
   pool drain that startup seed block first. */
static void DrainStartupSeed(CRYPT_EAL_Es *es)
{
    uint32_t size = 0;
    uint8_t tmp[64];
    while (CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, &size, sizeof(uint32_t)) == CRYPT_SUCCESS &&
        size > 0) {
        uint32_t want = (size < sizeof(tmp)) ? size : (uint32_t)sizeof(tmp);
        if (CRYPT_EAL_EsEntropyGet(es, tmp, want) != want) {
            break;
        }
    }
}

static bool IsCollectionEntropy(void *ctx)
{
    bool isWork = false;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_GET_STATE, &isWork, 1) == CRYPT_SUCCESS);
    uint32_t poolSize = 0;
    uint32_t currSize = 0;
    uint32_t cfSize = 0;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_GET_POOL_SIZE, &poolSize, 4) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_POOL_GET_CURRSIZE, &currSize, 4) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_GET_CF_SIZE, &cfSize, 4) == CRYPT_SUCCESS);
    return isWork && (cfSize <= poolSize - currSize);
EXIT:
    return false;
}

static void *EsGatherAuto(void *ctx)
{
    while(true) {
        if (!IsCollectionEntropy(ctx)) {
            break;
        }
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        uint32_t size;
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
        usleep(1000);
    }
EXIT:
    return NULL;
}

static void *EsGetAuto(void *ctx)
{
    uint8_t buf[48] = {0};
    for (int32_t iter = 0; iter < 3; iter++) {
        uint32_t len = CRYPT_EAL_EsEntropyGet(ctx, buf, 48);
        ASSERT_TRUE(len > 0);
    }
EXIT:
    return NULL;
}

static const char *EsGetCfMode(uint32_t algId)
{
    switch (algId) {
        case CRYPT_MD_SM3:
            return "sm3_df";
        case CRYPT_MD_SHA224:
            return "sha224_df";
        case CRYPT_MD_SHA256:
            return "sha256_df";
        case CRYPT_MD_SHA384:
            return "sha384_df";
        case CRYPT_MD_SHA512:
            return "sha512_df";
        case CRYPT_MD_SHA3_256:
            return "sha3_256_df";
        case CRYPT_MD_SHA3_384:
            return "sha3_384_df";
        case CRYPT_MD_SHA3_512:
            return "sha3_512_df";
        default:
            return NULL;
    }
}

static uint32_t EsGetCfLen(uint32_t algId)
{
    switch (algId) {
        case CRYPT_MD_SM3:
            return 32u;
        case CRYPT_MD_SHA224:
            return 28u;
        case CRYPT_MD_SHA256:
            return 32u;
        case CRYPT_MD_SHA384:
            return 48u;
        case CRYPT_MD_SHA512:
            return 64u;
        case CRYPT_MD_SHA3_256:
            return 32u;
        case CRYPT_MD_SHA3_384:
            return 48u;
        case CRYPT_MD_SHA3_512:
            return 64u;
        default:
            return 0u;
    }
}

static int32_t EntropyReadNormal(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    memset(buf, 0xff, bufLen);
    return CRYPT_SUCCESS;
}

static void *EntropyInitTest(void *para)
{
    (void)para;
    return EntropyInitTest;
}

static void *EntropyInitError(void *para)
{
    (void)para;
    return NULL;
}

static int32_t EntropyReadError(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    memset(buf, 0xff, bufLen);
    return -1;
}

static int32_t EntropyReadDiffData(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    for (uint32_t iter = 0; iter < bufLen; iter++) {
        buf[iter] = iter % 128;
    }
    return CRYPT_SUCCESS;
}

static void EntropyDeinitTest(void *ctx)
{
    (void)ctx;
    return;
}

static int g_entropyDeinitCalls = 0;

static void EntropyDeinitCount(void *ctx)
{
    (void)ctx;
    g_entropyDeinitCalls++;
}

static void *EsMutiAuto(void *ctx)
{
    CRYPT_EAL_NsPara para = {
        "aaa",
        false,
        7,
        {
            NULL,
            NULL,
            EntropyReadNormal,
            NULL,
        },
        {5, 39, 512},
    };
    CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df"));
    CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara));
    uint32_t size = 512;
    CRYPT_EAL_EsCtrl(ctx, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&size, sizeof(uint32_t));
    ASSERT_TRUE(CRYPT_EAL_EsInit(ctx) == CRYPT_SUCCESS);
    uint8_t buf[48] = {0};
    for (int32_t iter = 0; iter < 3; iter++) {
        uint32_t len = CRYPT_EAL_EsEntropyGet(ctx, buf, 48);
        ASSERT_TRUE(len > 0);
    }
EXIT:
    return NULL;
}

static void EntropyESMutilTest(void *alg)
{
    uint32_t poolSize = 4096;
    uint32_t expectGetLen = 32;
    uint8_t buf[1024] = {0};
    uint32_t currPoolSize = 0;

    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    const char *mode = EsGetCfMode((uint32_t)(*(int *)alg));
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&poolSize, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    for(int iter = 0; iter < 1; iter++) {
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, &currPoolSize, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(currPoolSize > expectGetLen);
    uint32_t resLen = CRYPT_EAL_EsEntropyGet(es, buf, expectGetLen);
    ASSERT_TRUE(resLen == expectGetLen);
EXIT:
    CRYPT_EAL_EsFree(es);
}
static int32_t GetEntropyTest(void *seedCtx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)strength;
    entropy->len = lenRange->min;
    entropy->data = malloc(entropy->len);
    ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(seedCtx, entropy->data, entropy->len) == entropy->len);
EXIT:
    return CRYPT_SUCCESS;
}

static void CleanEntropyTest(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    BSL_SAL_FREE(entropy->data);
}

static int32_t GetNonceTest(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    return GetEntropyTest(ctx, nonce, strength, lenRange);
}

static void CleanNonceTest(void *ctx, CRYPT_Data *nonce)
{
    CleanEntropyTest(ctx, nonce);
}
#endif
static uint32_t EntropyGetNormal(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)buf;
    (void)bufLen;
    memset(buf, 'a', bufLen);
    return 32 > bufLen ? bufLen : 32;
}

static uint32_t EntropyGet0Normal(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)buf;
    (void)bufLen;
    memset(buf, 'a', bufLen);
    return 0;
}

static uint32_t EntropyGetOversize(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    memset(buf, 'a', bufLen);
    return bufLen + 1;
}

static uint32_t EntropyGetReportedLen(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)buf;
    return bufLen;
}

static void *DrbgSeedTest(void *ctx)
{
    CRYPT_RandSeedMethod meth = {0};
    ASSERT_TRUE(EAL_SetDefaultEntropyMeth(&meth) == CRYPT_SUCCESS);
    CRYPT_EAL_RndCtx *randCtx = CRYPT_EAL_DrbgNew(CRYPT_RAND_AES128_CTR_DF, &meth, ctx);
    ASSERT_TRUE(randCtx != NULL);
    uint32_t in = 1;
    ASSERT_TRUE(CRYPT_EAL_DrbgCtrl(randCtx, CRYPT_CTRL_SET_RESEED_INTERVAL, &in, 4) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(randCtx, NULL, 0) == CRYPT_SUCCESS);
    for (int32_t index = 0; index < 10; index++) {
        uint8_t buf[32] = {0};
        ASSERT_TRUE(CRYPT_EAL_Drbgbytes(randCtx, buf, 32) == CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_DrbgDeinit(randCtx);
    return NULL;
}

#ifdef HITLS_CRYPTO_ENTROPY_SYS
static uint32_t ErrorGetEsEntropy(CRYPT_EAL_Es *esCtx, uint8_t *data, uint32_t len)
{
    (void)esCtx;
    (void)data;
    (void)len;

    return 0;
}
#endif

static CRYPT_EAL_SeedPoolCtx *GetPoolCtx(uint32_t ent1, uint32_t ent2, bool pes1, bool pes2)
{
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    CRYPT_EAL_EsPara para1 = {pes2, ent2, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    CRYPT_EAL_EsPara para2 = {pes1, ent1, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para2) == CRYPT_SUCCESS);
    return pool;
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    return NULL;
}
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
static void FreeNoiseSource(ES_NoiseSource *ns)
{
    if (ns == NULL) {
        return;
    }
    if (ns->deinit != NULL && ns->usrdata != NULL) {
        ns->deinit(ns->usrdata);
    }
    BSL_SAL_FREE(ns->name);
    BSL_SAL_FREE(ns);
}

static uint32_t g_entropyNsFailCount = 0;

static void EntropyRunLogCb(int32_t ret)
{
    if (ret != CRYPT_SUCCESS) {
        g_entropyNsFailCount++;
    }
}
#endif

#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
typedef struct {
    ES_DeltaNs *e;
    uint32_t pos;
} EntropyAptTripCtx;

/* [A x 8, B] cycle: base density 8/9 = 88.9% trips the osr-3 APT cutoff (449/512)
   while stuck runs stay at 7 and diff runs at 7, far below their cutoffs; the
   osr-4 APT cutoff (468) clears it, so an osr walk settles one rung up. */
static void EntropyMeasureAptTrip(void *srcCtx)
{
    EntropyAptTripCtx *c = (EntropyAptTripCtx *)srcCtx;
    uint64_t raw = ((c->pos % 9) < 8) ? 1000 : 9000;
    c->pos++;
    ES_DeltaNsProcessRawDelta(c->e, raw);
}
#endif

/* Global stream for the half-open APT window regression. Cycle 1 (bytes
   0..1023): window 2 opens at byte 512 on base 0xFF, the base repeats to
   count = aptCutoff - 1 = 7, then a 5-byte 0xFE run trips the RCT mid-window,
   leaving the APT window half open. Cycle 2 (bytes 1024..2047) starts with
   0xFF: a leaked window reaches the APT cutoff on that byte, a reset window
   opens fresh and passes. */
static uint32_t g_entropyHalfWinPos = 0;

static int32_t EntropyReadAptHalfWin(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    for (uint32_t i = 0; i < bufLen; i++, g_entropyHalfWinPos++) {
        uint32_t off = g_entropyHalfWinPos % 1024;
        int cycle1 = (g_entropyHalfWinPos < 1024);
        if (cycle1 && (off == 512 || off == 520 || off == 530 || off == 540 ||
                       off == 550 || off == 560 || off == 570)) {
            buf[i] = 0xFF;
        } else if (cycle1 && off >= 600 && off <= 604) {
            buf[i] = 0xFE;
        } else if (!cycle1 && off == 0) {
            buf[i] = 0xFF;
        } else {
            buf[i] = (uint8_t)(1 + (off % 251));
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t EntropyInitAtOsr12(void *para, uint32_t startOsr, void **usrdata)
{
    (void)para;
    (void)startOsr;
    static int dummy;
    *usrdata = &dummy;
    return CRYPT_SUCCESS;
}

static uint32_t EntropyOsrGet12(const void *usrdata)
{
    (void)usrdata;
    return 12;
}

static int32_t EntropyInitAtCondFail(void *para, uint32_t startOsr, void **usrdata)
{
    (void)para;
    (void)startOsr;
    (void)usrdata;
    return CRYPT_ENTROPY_CONDITION_FAILURE;
}

static int32_t EntropyInitAtNegCode(void *para, uint32_t startOsr, void **usrdata)
{
    (void)para;
    (void)startOsr;
    (void)usrdata;
    return -1;
}

static int g_entropyInitAtStatefulCount = 0;
static int32_t EntropyInitAtSucceedThenFail(void *para, uint32_t startOsr, void **usrdata)
{
    (void)para;
    (void)startOsr;
    if (g_entropyInitAtStatefulCount++ == 0) {
        static int dummy;
        *usrdata = &dummy;
        return CRYPT_SUCCESS;
    }
    return CRYPT_ENTROPY_ES_NS_NOT_AVA;
}

static int32_t EntropyInitAtAlwaysSucceed(void *para, uint32_t startOsr, void **usrdata)
{
    (void)para;
    (void)startOsr;
    static int dummy;
    *usrdata = &dummy;
    return CRYPT_SUCCESS;
}

/* Varied bytes through the 1024-byte startup window, then a constant value so
   the first runtime reads trip the RCT. */
static uint32_t g_entropyRunFailPos = 0;

static int32_t EntropyReadRunThenStuck(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    for (uint32_t i = 0; i < bufLen; i++, g_entropyRunFailPos++) {
        buf[i] = (g_entropyRunFailPos < 1024) ? (uint8_t)(1 + (g_entropyRunFailPos % 251)) : 0xAA;
    }
    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
static uint32_t g_entropyMeasureCount = 0;
static uint64_t g_entropyMeasureVal = 0;

static void EntropyMeasureCounted(void *srcCtx)
{
    ES_DeltaNs *e = (ES_DeltaNs *)srcCtx;
    g_entropyMeasureCount++;
    g_entropyMeasureVal += 1 + (g_entropyMeasureCount % 7);
    ES_DeltaNsProcessRawDelta(e, g_entropyMeasureVal);
}

typedef struct {
    ES_DeltaNs *e;
    uint32_t count;
    uint64_t value;
} EntropyRawMeasureCtx;

static void EntropyMeasureRaw(void *srcCtx)
{
    static const uint64_t first[] = {14, 22, 36, 58};
    EntropyRawMeasureCtx *c = (EntropyRawMeasureCtx *)srcCtx;
    uint64_t raw;
    if (c->count < sizeof(first) / sizeof(first[0])) {
        raw = first[c->count];
        c->value = raw;
    } else {
        c->value += 2 * (1 + (c->count % 7));
        raw = c->value;
    }
    c->count++;
    ES_DeltaNsProcessRawDelta(c->e, raw);
}

static void EntropyMeasureFixedWide(void *srcCtx)
{
    /* Every byte distinct and non-zero, so a truncated, zero-padded or
       byte-swapped emit cannot produce the expected record. */
    ES_DeltaNsProcessRawDelta((ES_DeltaNs *)srcCtx, 0x11100F0E0D0C0B0AULL);
}
#endif

static uint32_t g_entropyReadLogCalls = 0;

static void EntropyReadCountLog(int32_t ret)
{
    (void)ret;
    g_entropyReadLogCalls++;
}

static uint32_t g_entropyCondReadCalls = 0;

static int32_t EntropyReadCondFail(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    (void)buf;
    (void)bufLen;
    g_entropyCondReadCalls++;
    return CRYPT_ENTROPY_CONDITION_FAILURE;
}

/* Availability failure: fails init without retiring or demoting the source. */
static int32_t EntropyReadNotAvail(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    (void)buf;
    (void)bufLen;
    return CRYPT_ENTROPY_ES_NS_NOT_AVA;
}

/* Varied bytes until the test arms the fault, then a permanent conditioning
   fault: lets one callback serve the startup, seed and runtime phases. */
static uint32_t g_entropyFaultArmed = 0;

static int32_t EntropyReadArmedFault(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    if (g_entropyFaultArmed != 0) {
        g_entropyCondReadCalls++;
        return CRYPT_ENTROPY_CONDITION_FAILURE;
    }
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (uint8_t)(1 + (pos % 251));
    }
    return CRYPT_SUCCESS;
}

/* Varied bytes through the 1024-byte startup window, then a permanent
   conditioning fault: models a hash primitive that breaks after startup. */
static uint32_t g_entropySeedFaultPos = 0;

static int32_t EntropyReadSeedFault(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    if (g_entropySeedFaultPos >= 1024) {
        g_entropySeedFaultPos++;
        return CRYPT_ENTROPY_CONDITION_FAILURE;
    }
    for (uint32_t i = 0; i < bufLen; i++, g_entropySeedFaultPos++) {
        buf[i] = (uint8_t)(1 + (g_entropySeedFaultPos % 251));
    }
    return CRYPT_SUCCESS;
}

static uint32_t g_entropyDeinitNullCalls = 0;
static int g_entropyLifeDummy = 0;

static void *EntropyLifeInit(void *para)
{
    (void)para;
    return &g_entropyLifeDummy;
}

static void EntropyLifeDeinit(void *usrdata)
{
    if (usrdata == NULL) {
        g_entropyDeinitNullCalls++;
    }
}

static uint32_t g_entropyTailRunPos = 0;

static int32_t EntropyReadTailRun(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    /* Global stream shaped per 1024-byte startup window: byte 0 and bytes
       1020..1023 are 0xAA, the rest cycle through 1..4. Each window ends with
       a 4-byte 0xAA run (rctCutoff - 1 with rctCutoff = 5) that the next
       window's first byte would extend to the cutoff if RCT state leaked
       across init cycles. */
    for (uint32_t i = 0; i < bufLen; i++, g_entropyTailRunPos++) {
        uint32_t off = g_entropyTailRunPos % 1024;
        if (off == 0 || off >= 1020) {
            buf[i] = 0xAA;
        } else {
            buf[i] = (uint8_t)(1 + (off % 4));
        }
    }
    return CRYPT_SUCCESS;
}

static uint32_t g_entropySeedPollCalls = 0;
static uint32_t g_entropyFastPollCalls = 0;

/* Gather rounds read one byte at a time, so bufLen == 1 isolates
   seed/gather traffic from the 1024-byte window. */
static int32_t EntropyReadSeedPoll(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    if (bufLen == 1) {
        g_entropySeedPollCalls++;
    }
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (uint8_t)(1 + (pos % 251));
    }
    return CRYPT_SUCCESS;
}

static int32_t EntropyReadVaried(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (uint8_t)(1 + (pos % 251));
    }
    return CRYPT_SUCCESS;
}

static int32_t EntropyReadFastPoll(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    if (bufLen == 1) {
        g_entropyFastPollCalls++;
    }
    return EntropyReadVaried(ctx, timeout, buf, bufLen);
}

static int32_t EntropyRemoveBuiltInNs(CRYPT_EAL_Es *es)
{
    int32_t ret = CRYPT_SUCCESS;
    (void)es;
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
#endif
    return ret;
}

static uint32_t g_entropyMaxMallocSize = 0;

static void *EntropyMallocTrack(uint32_t size)
{
    if (size > g_entropyMaxMallocSize) {
        g_entropyMaxMallocSize = size;
    }
    return malloc(size);
}

static bool g_entropyFailOutputAlloc = false;

static void *EntropyMallocFailOutput(uint32_t size)
{
    if (g_entropyFailOutputAlloc && size == 32) {
        g_entropyFailOutputAlloc = false;
        return NULL;
    }
    return malloc(size);
}

static int g_entropyFailNthK = 0;
static int g_entropyMallocSeq = 0;

static void *EntropyMallocFailNth(uint32_t size)
{
    if (g_entropyFailNthK > 0 && ++g_entropyMallocSeq == g_entropyFailNthK) {
        return NULL;
    }
    return malloc(size);
}

/* Allocation-failure sweep with balance accounting: the same stub counts
   live blocks and fails the k-th request, so an error path that forgets a
   free shows up as a non-zero balance instead of passing silently. */
static int32_t g_entropyLiveBlocks = 0;

static void *EntropyMallocSweep(uint32_t size)
{
    /* Count first: the sequence must advance even on the pass that injects
       nothing, since that pass is what sizes the sweep. */
    g_entropyMallocSeq++;
    if (g_entropyFailNthK > 0 && g_entropyMallocSeq == g_entropyFailNthK) {
        return NULL;
    }
    void *p = malloc(size);
    if (p != NULL) {
        g_entropyLiveBlocks++;
    }
    return p;
}

static void EntropyFreeSweep(void *p)
{
    if (p != NULL) {
        g_entropyLiveBlocks--;
        free(p);
    }
}

/* Byte-accurate allocation accounting for the dual-source ES: every SAL
   allocation is tagged with its size so live bytes and the peak can be read
   back at each lifecycle stage. */
#define MEMPROBE_MAX 4096
static struct { void *p; uint32_t sz; } g_memProbe[MEMPROBE_MAX];
static uint32_t g_memProbeCount;
static uint64_t g_memLive;
static uint64_t g_memPeak;
static uint64_t g_memTotal;

static void *EntropyMemProbeMalloc(uint32_t size)
{
    void *p = malloc(size);
    if (p != NULL && g_memProbeCount < MEMPROBE_MAX) {
        g_memProbe[g_memProbeCount].p = p;
        g_memProbe[g_memProbeCount].sz = size;
        g_memProbeCount++;
        g_memLive += size;
        g_memTotal += size;
        if (g_memLive > g_memPeak) {
            g_memPeak = g_memLive;
        }
    }
    return p;
}

static void EntropyMemProbeFree(void *p)
{
    if (p == NULL) {
        return;
    }
    for (uint32_t i = 0; i < g_memProbeCount; i++) {
        if (g_memProbe[i].p == p) {
            g_memLive -= g_memProbe[i].sz;
            g_memProbe[i].p = NULL;
            break;
        }
    }
    free(p);
}

static void EntropyMemProbeReset(void)
{
    g_memProbeCount = 0;
    g_memLive = 0;
    g_memPeak = 0;
    g_memTotal = 0;
}

/* Full-entropy-input helpers: a conditioning function that can be made to
   fail, and a source that under-delivers so the pool cannot meet a request. */
static int g_entropyEcfFail = 0;

static uint32_t g_entropyEcfOverLen = 0;

static int32_t EntropyEcfStub(uint32_t algId, uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    (void)algId;
    (void)in;
    (void)inLen;
    if (g_entropyEcfFail != 0) {
        /* A failing conditioner may already have filled its output buffer. */
        if (out != NULL && outLen != NULL && *outLen > 0) {
            (void)memset(out, 0xC3, *outLen);
#if defined(HITLS_CRYPTO_ENTROPY)
            g_ecfWipePtr = out;
#endif
        }
        return CRYPT_ENTROPY_ECF_ALG_ERROR;
    }
    if (out != NULL && outLen != NULL && *outLen > 0) {
        (void)memset(out, 0x5A, *outLen);
    }
    if (g_entropyEcfOverLen != 0 && outLen != NULL) {
        /* A misbehaving conditioner reporting more than it wrote: the caller
           must not let this length index its fixed output buffer. */
        *outLen = *outLen + 1;
    }
    return CRYPT_SUCCESS;
}

static uint32_t EntropyGetShort(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    if (bufLen == 0) {
        return 0;
    }
    (void)memset(buf, 'b', 1);
    return 1;
}

static uint32_t g_entropyStreamPos = 0;

static int32_t EntropyReadStream(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    for (uint32_t i = 0; i < bufLen; i++) {
        buf[i] = (uint8_t)(1 + (g_entropyStreamPos++ % 251));
    }
    return CRYPT_SUCCESS;
}

/* Two alternating symbols: runs never reach an RCT cutoff, while the base
   symbol recurs often enough to trip APT inside one window. */
static int32_t EntropyReadAlternate(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (pos & 1U) ? 0xbbU : 0xaaU;
    }
    return CRYPT_SUCCESS;
}

static void EntropyRestoreMalloc(void)
{
#ifdef HITLS_BSL_SAL_MEM
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, NULL);
#else
    TestMemInit();
#endif
}

static int32_t EntropyWriteLockFail(BSL_SAL_ThreadLockHandle lock)
{
    (void)lock;
    return BSL_SAL_ERR_UNKNOWN;
}

static void EntropyRestoreLock(void)
{
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_WRITE_LOCK_CB_FUNC, NULL);
}

static int32_t g_entropyWindowFailRet = CRYPT_ENTROPY_RCT_FAILURE;

/* Startup window fails with the configured verdict before any byte is
   served. */
static int32_t EntropyReadWindowFail(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    (void)buf;
    (void)bufLen;
    return g_entropyWindowFailRet;
}

static uint32_t g_entropyNumberReads = 0;
static uint32_t g_entropyNumberDieAt = 0;

/* Varied bytes until the shared byte-read budget runs out, then a permanent
   availability failure: models sources going quiet without health alarms. */
static int32_t EntropyReadNumber(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    if (bufLen == 1 && g_entropyNumberDieAt != 0 && ++g_entropyNumberReads >= g_entropyNumberDieAt) {
        return CRYPT_ENTROPY_ES_NS_NOT_AVA;
    }
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (uint8_t)(1 + (pos % 251));
    }
    return CRYPT_SUCCESS;
}

static uint32_t g_entropyByteFailCalls = 0;

/* Bulk (window) reads succeed with varied bytes; every byte-wise gather read
   fails: a source dying right after its authoritative startup window, on
   platforms with and without the window alike. */
static int32_t EntropyReadByteFail(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    if (bufLen == 1) {
        g_entropyByteFailCalls++;
        return CRYPT_ENTROPY_RCT_FAILURE;
    }
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (uint8_t)(1 + (pos % 251));
    }
    return CRYPT_SUCCESS;
}

static uint32_t g_entropyCreditBReads = 0;
static uint32_t g_entropyCreditBFailAt = 11;
static int32_t g_entropyCreditBFailRet = CRYPT_ENTROPY_RCT_FAILURE;

static uint32_t g_entropyOperationalReads = 0;

static int32_t EntropyReadOperational(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    if (bufLen == 1) {
        g_entropyOperationalReads++;
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (uint8_t)(1 + (pos % 251));
    }
    return CRYPT_SUCCESS;
}

/* Varied bulk reads pass startup health checks; the configured byte-wise read
   returns an availability or health verdict after a fixed count. */
static int32_t EntropyReadCreditB(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    if (bufLen == 1 && ++g_entropyCreditBReads >= g_entropyCreditBFailAt) {
        return g_entropyCreditBFailRet;
    }
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (uint8_t)(1 + (pos % 251));
    }
    return CRYPT_SUCCESS;
}

static uint32_t g_entropyCreditArmed = 0;

static int32_t EntropyReadCreditArmed(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    if (g_entropyCreditArmed != 0) {
        return CRYPT_ENTROPY_RCT_FAILURE;
    }
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (uint8_t)(1 + (pos % 251));
    }
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_ENTROPY_SYS
static ENTROPY_CFPara EsMakeCfPara(void)
{
    const EAL_MdMethod *md = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    ENTROPY_CFPara para = {CRYPT_MD_SHA256, (void *)(uintptr_t)md};
    return para;
}

static void *MockMdNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    (void)algId;
    return (void *)0x1;
}

static int32_t MockMdInitOk(void *data, const BSL_Param *param)
{
    (void)data;
    (void)param;
    return CRYPT_SUCCESS;
}

static int32_t MockMdInitFail(void *data, const BSL_Param *param)
{
    (void)data;
    (void)param;
    return CRYPT_ENTROPY_ES_CF_ERROR;
}

static int32_t MockMdUpdateOk(void *data, const uint8_t *input, uint32_t len)
{
    (void)data;
    (void)input;
    (void)len;
    return CRYPT_SUCCESS;
}

static int32_t MockMdUpdateFail(void *data, const uint8_t *input, uint32_t len)
{
    (void)data;
    (void)input;
    (void)len;
    return CRYPT_ENTROPY_ES_CF_ERROR;
}

static int32_t MockMdFinalFail(void *data, uint8_t *out, uint32_t *len)
{
    (void)data;
    (void)out;
    (void)len;
    return CRYPT_ENTROPY_ES_CF_ERROR;
}

static int32_t MockMdDeinitNoop(void *data)
{
    (void)data;
    return CRYPT_SUCCESS;
}

static void MockMdFreeCtxNoop(void *data)
{
    (void)data;
}

static int g_mockInitCallCount = 0;

static int32_t MockMdInitFail2nd(void *data, const BSL_Param *param)
{
    (void)data;
    (void)param;
    if (++g_mockInitCallCount == 2) {
        return CRYPT_ENTROPY_ES_CF_ERROR;
    }
    return CRYPT_SUCCESS;
}

static EAL_MdMethod g_mockMdInitFail = {
    .id = CRYPT_MD_SHA256, .blockSize = 64, .mdSize = 32,
    .newCtx = MockMdNewCtx, .init = MockMdInitFail, .update = MockMdUpdateOk,
    .final = MockMdFinalFail, .deinit = MockMdDeinitNoop, .freeCtx = MockMdFreeCtxNoop
};

static EAL_MdMethod g_mockMdUpdateFail = {
    .id = CRYPT_MD_SHA256, .blockSize = 64, .mdSize = 32,
    .newCtx = MockMdNewCtx, .init = MockMdInitOk, .update = MockMdUpdateFail,
    .final = MockMdFinalFail, .deinit = MockMdDeinitNoop, .freeCtx = MockMdFreeCtxNoop
};

static EAL_MdMethod g_mockMdFinalFail = {
    .id = CRYPT_MD_SHA256, .blockSize = 64, .mdSize = 32,
    .newCtx = MockMdNewCtx, .init = MockMdInitOk, .update = MockMdUpdateOk,
    .final = MockMdFinalFail, .deinit = MockMdDeinitNoop, .freeCtx = MockMdFreeCtxNoop
};

/* The Hash_df prefix is a 5-byte update; anything wider is sample data. */
#define MOCK_MD_PREFIX_LEN 5
static int32_t MockMdUpdateDataFail(void *data, const uint8_t *input, uint32_t len)
{
    (void)data;
    (void)input;
    return (len == MOCK_MD_PREFIX_LEN) ? CRYPT_SUCCESS : CRYPT_ENTROPY_ES_CF_ERROR;
}

static int32_t MockMdFinalOk(void *data, uint8_t *out, uint32_t *len)
{
    (void)data;
    if (out != NULL && len != NULL && *len > 0) {
        (void)memset(out, 0xA5, *len);
    }
    return CRYPT_SUCCESS;
}

/* Data update fails while the prefix update succeeds. */
static EAL_MdMethod g_mockMdDataUpdateFail = {
    .id = CRYPT_MD_SHA256, .blockSize = 64, .mdSize = 32,
    .newCtx = MockMdNewCtx, .init = MockMdInitOk, .update = MockMdUpdateDataFail,
    .final = MockMdFinalOk, .deinit = MockMdDeinitNoop, .freeCtx = MockMdFreeCtxNoop
};

/* Init calls run persistent-context, transaction-context, then the re-init
   that follows final; failing from the third leaves only that last step. */
static int32_t MockMdInitFailFromThird(void *data, const BSL_Param *param)
{
    (void)data;
    (void)param;
    return (++g_mockInitCallCount >= 3) ? CRYPT_ENTROPY_ES_CF_ERROR : CRYPT_SUCCESS;
}

/* Final succeeds so the re-init that follows it is the failing step. */
static EAL_MdMethod g_mockMdReinitAfterFinal = {
    .id = CRYPT_MD_SHA256, .blockSize = 64, .mdSize = 32,
    .newCtx = MockMdNewCtx, .init = MockMdInitFailFromThird, .update = MockMdUpdateOk,
    .final = MockMdFinalOk, .deinit = MockMdDeinitNoop, .freeCtx = MockMdFreeCtxNoop
};

static EAL_MdMethod g_mockMdReinitFail = {
    .id = CRYPT_MD_SHA256, .blockSize = 64, .mdSize = 32,
    .newCtx = MockMdNewCtx, .init = MockMdInitFail2nd, .update = MockMdUpdateOk,
    .final = MockMdFinalFail, .deinit = MockMdDeinitNoop, .freeCtx = MockMdFreeCtxNoop
};
#endif

/* END_HEADER */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_JITTER_DELTA_TC002(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)
    /* Live counter: init succeeds and the conditioned output is neither
       all-zero nor repeating across consecutive reads. */
    ES_NoiseSource *ns = NULL;
    uint8_t out1[64] = {0};
    uint8_t out2[64] = {0};
    uint8_t zero[64] = {0};
    ns = ES_CpuJitterGetCtx();
    ASSERT_TRUE(ns != NULL);
    ASSERT_TRUE(ns->initAt(ns->para, ns->osr, &ns->usrdata) == CRYPT_SUCCESS);
    ASSERT_TRUE(ns->usrdata != NULL);
    ns->isInit = true;
    ns->isEnable = true;
    ASSERT_TRUE(ES_NsRead(ns, out1, sizeof(out1)) == CRYPT_SUCCESS);
    ASSERT_TRUE(ES_NsRead(ns, out2, sizeof(out2)) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(out1, zero, sizeof(zero)) != 0);
    ASSERT_TRUE(memcmp(out1, out2, sizeof(out1)) != 0);
EXIT:
    FreeNoiseSource(ns);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsNormalTest
* @spec  -
* @title  Basic function test of the entropy source.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsNormalTest(int alg, int size, int test)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    const char *mode = EsGetCfMode((uint32_t)alg);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : (bool)test;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    BSL_SAL_ThreadId thrd;
    ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrd, EsGatherAuto, es) == 0);
    BSL_SAL_ThreadId thrdget;
    ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrdget, EsGetAuto, es) == 0);
    BSL_SAL_ThreadClose(thrd);
    BSL_SAL_ThreadClose(thrdget);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)alg;
    (void)size;
    (void)test;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsCtrlTest1
* @spec  -
* @title  Testing the entropy source setting interface.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsCtrlTest1(int type, int state, int excRes)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    uint32_t len = 512;
    if (state == 1) {
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&len, sizeof(uint32_t)) == CRYPT_SUCCESS);
        ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    }
    if (excRes == 1) {
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, type, (void *)&len, sizeof(uint32_t)) == CRYPT_SUCCESS);
        ASSERT_TRUE(TestIsErrStackEmpty());
    } else {
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, type, (void *)&len, sizeof(uint32_t)) != CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)type;
    (void)state;
    (void)excRes;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsCtrlTest2
* @spec  -
* @title  Testing the entropy source setting interface.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsCtrlTest2(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool  healthTest = IsRunningOnWSL() ? false : true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {
        "aaa",
        false,
        7,
        {
            NULL,
            NULL,
            EntropyReadNormal,
            NULL,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(intptr_t)para.name, strlen(para.name)) == CRYPT_SUCCESS);
    bool flag = false;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GET_STATE, &flag, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(flag == false);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GET_STATE, &flag, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(flag == true);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(intptr_t)para.name, strlen(para.name)) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_REMOVE_NULL_NODE_FUNC_TC001
* @spec  -
* @title  Verify that removing a noise source skips list nodes whose data is NULL.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Create a noise source list and add two noise sources. Expected result 1.
*    2. Manually set the first node data to NULL to simulate an abnormal empty node. Expected result 2.
*    3. Call ES_NsRemove to remove the subsequent target noise source. Expected result 3.
*    4. Restore the first node data and verify the remaining list content. Expected result 4.
* @expect
*    1. The list is created and both noise sources are added successfully.
*    2. The list contains a node with NULL data and the test setup remains controllable.
*    3. ES_NsRemove skips the NULL-data node and removes "target-node" successfully.
*    4. Only the original first noise source remains in the list and the list structure is intact.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_REMOVE_NULL_NODE_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    BslListNode *firstNode = NULL;
    ES_NoiseSource *savedFirst = NULL;
    CRYPT_EAL_NsMethod method = {
        NULL,
        NULL,
        EntropyReadNormal,
        NULL,
    };
    CRYPT_EAL_NsTestPara para = {5, 39, 512};

    TestMemInit();
    nsList = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(nsList != NULL);
    ASSERT_TRUE(ES_NsAdd(nsList, "null-node", false, 7, &method, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(ES_NsAdd(nsList, "target-node", false, 7, &method, &para) == CRYPT_SUCCESS);

    firstNode = BSL_LIST_FirstNode(nsList);
    ASSERT_TRUE(firstNode != NULL);
    savedFirst = BSL_LIST_GetData(firstNode);
    ASSERT_TRUE(savedFirst != NULL);
    /* Deliberately inject a NULL payload node to cover ES_NsRemove traversal hardening. */
    firstNode->data = NULL;

    ASSERT_TRUE(ES_NsRemove(nsList, "target-node") == CRYPT_SUCCESS);
    /* Restore the saved pointer for list cleanup. */
    firstNode->data = savedFirst;
    ASSERT_TRUE(BSL_LIST_COUNT(nsList) == 1);
    ASSERT_TRUE(BSL_LIST_FirstNodeData(nsList) == savedFirst);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    /* Ensure cleanup sees a valid node payload even if the case exits early. */
    if (firstNode != NULL && firstNode->data == NULL) {
        firstNode->data = savedFirst;
    }
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_ENTROPY_SYS
static int32_t g_permInitAtRet = CRYPT_SUCCESS;
static uint32_t g_permInitAtCalls = 0;
static int32_t g_permReadRet = CRYPT_SUCCESS;
static uint8_t g_permDummyState = 0;

static int32_t EntropyPermInitAt(void *para, uint32_t startRung, void **usrdata)
{
    (void)para;
    (void)startRung;
    g_permInitAtCalls++;
    if (g_permInitAtRet != CRYPT_SUCCESS) {
        return g_permInitAtRet;
    }
    *usrdata = &g_permDummyState;
    return CRYPT_SUCCESS;
}

static int32_t EntropyPermRead(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    if (g_permReadRet != CRYPT_SUCCESS) {
        return g_permReadRet;
    }
    memset(buf, 0xa5, bufLen);
    return CRYPT_SUCCESS;
}

/* An external (no-initAt) source whose startup read fails recoverably. */
static int32_t EntropyReadRecoverFail(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    (void)buf;
    (void)bufLen;
    return CRYPT_ENTROPY_RCT_FAILURE;
}

/* Single adaptive mock source with an injected initAt walking osr [2, osrMax]. */
static BslList *PermNsListNew(uint32_t osrMax)
{
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyPermRead, NULL};
    CRYPT_EAL_NsTestPara para = {5, 39, 512};
    BslList *nsList = BSL_LIST_New(sizeof(ES_NoiseSource *));
    if (nsList == NULL) {
        return NULL;
    }
    if (ES_NsAdd(nsList, "perm-mock", true, 5, &method, &para) != CRYPT_SUCCESS) {
        ES_NsListFree(nsList);
        return NULL;
    }
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    ns->initAt = EntropyPermInitAt;
    ns->osr = 2;
    ns->osrMax = osrMax;
    g_permInitAtRet = CRYPT_SUCCESS;
    g_permReadRet = CRYPT_SUCCESS;
    g_permInitAtCalls = 0;
    return nsList;
}
#endif

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_STARTUP_OPERATIONAL_NO_DEMOTE_TC001(int failClass)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    TestMemInit();
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    g_permReadRet = failClass == 0 ? CRYPT_ENTROPY_ES_NS_NOT_AVA : CRYPT_DRBG_FAIL_GET_ENTROPY;
    ASSERT_EQ(ES_NsListInit(nsList, true), g_permReadRet);
    ASSERT_EQ(g_permInitAtCalls, 1);
    ASSERT_EQ(ns->osr, 2);
    ASSERT_EQ(ns->floorFailStreak, 0);
    ASSERT_TRUE(ns->permanentFailure == false);
EXIT:
    ES_NsListFree(nsList);
#else
    (void)failClass;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_STARTUP_HEALTH_DEMOTES_TC001(int failClass)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    TestMemInit();
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    g_permReadRet = failClass == 0 ? CRYPT_ENTROPY_RCT_FAILURE : CRYPT_ENTROPY_APT_FAILURE;
    ASSERT_EQ(ES_NsListInit(nsList, true), g_permReadRet);
    ASSERT_EQ(g_permInitAtCalls, 7);
    ASSERT_EQ(ns->osr, 8);
    ASSERT_EQ(ns->floorFailStreak, 1);
    ASSERT_TRUE(ns->permanentFailure == false);
EXIT:
    ES_NsListFree(nsList);
#else
    (void)failClass;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_PERMANENT_STREAK_FUNC_TC001
* @spec  -
* @title  Consecutive floor health failures latch the source permanently.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Fail initAt with RCT_FAILURE for three init cycles. Expected result 1.
*    2. Fail a fourth cycle. Expected result 2.
*    3. Run a fifth cycle. Expected result 3.
*    4. Free the list and build a fresh record. Expected result 4.
* @expect
*    1. Each cycle returns RCT_FAILURE, the streak counts up, the ceiling is
*       pressed to the floor, and no latch is set.
*    2. The fourth cycle latches the source and returns ES_PERMANENT_FAILURE.
*    3. The latched source is skipped: initAt is never invoked again and the
*       verdict stays ES_PERMANENT_FAILURE.
*    4. A fresh record starts with a clean latch and streak.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_PERMANENT_STREAK_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    TestMemInit();
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    g_permInitAtRet = CRYPT_ENTROPY_RCT_FAILURE;
    for (uint32_t i = 1; i < NS_PERMANENT_FAIL_STREAK; i++) {
        ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_RCT_FAILURE);
        ASSERT_TRUE(ns->permanentFailure == false);
        ASSERT_TRUE(ns->floorFailStreak == i);
        ASSERT_TRUE(ns->osr == ns->osrMax);
    }
    /* Stale runtime-suspension state on the retiring cycle must be canonicalized. */
    ns->needRecovery = true;
    ns->onProbation = true;
    ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    ASSERT_TRUE(ns->permanentFailure == true);
    ASSERT_TRUE(!ns->needRecovery && !ns->onProbation && !ns->isEnable);
    uint32_t calls = g_permInitAtCalls;
    ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    ASSERT_TRUE(g_permInitAtCalls == calls);
    ES_NsListFree(nsList);
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ns = BSL_LIST_FirstNodeData(nsList);
    ASSERT_TRUE(ns->permanentFailure == false && ns->floorFailStreak == 0);
EXIT:
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_PERMANENT_RESET_FUNC_TC001
* @spec  -
* @title  A successful init cycle resets the floor-failure streak.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Fail three init cycles, then let one cycle succeed. Expected result 1.
*    2. Fail three further cycles. Expected result 2.
* @expect
*    1. The success resets the streak to zero and enables the source.
*    2. Three failures after the reset leave the source unlatched: only
*       consecutive floor failures may latch.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_PERMANENT_RESET_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    TestMemInit();
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    g_permInitAtRet = CRYPT_ENTROPY_RCT_FAILURE;
    for (uint32_t i = 1; i < NS_PERMANENT_FAIL_STREAK; i++) {
        ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_RCT_FAILURE);
    }
    ASSERT_TRUE(ns->floorFailStreak == NS_PERMANENT_FAIL_STREAK - 1);
    ASSERT_EQ(ns->osr, ns->osrMax);
    g_permInitAtRet = CRYPT_SUCCESS;
    ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(ns->floorFailStreak == 0 && ns->isEnable == true);
    ES_NsListDeinit(nsList);
    g_permInitAtRet = CRYPT_ENTROPY_RCT_FAILURE;
    for (uint32_t i = 1; i < NS_PERMANENT_FAIL_STREAK; i++) {
        ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_RCT_FAILURE);
    }
    ASSERT_TRUE(ns->permanentFailure == false);
EXIT:
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_PERMANENT_STRUCTURAL_FUNC_TC001
* @spec  -
* @title  A timer-check verdict latches the source immediately.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Fail initAt with ES_DEAD_TIMER on the first init cycle. Expected result 1.
*    2. Run a second cycle. Expected result 2.
* @expect
*    1. The cycle returns the structural verdict ES_DEAD_TIMER and the latch
*       is set without any streak accumulation.
*    2. The source is skipped and the verdict becomes ES_PERMANENT_FAILURE.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_PERMANENT_STRUCTURAL_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    TestMemInit();
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    /* Simulate a source that was suspended at runtime and is now re-initialized
       with a dead timer: retirement must canonicalize the stale recovery state. */
    ns->needRecovery = true;
    ns->onProbation = true;
    g_permInitAtRet = CRYPT_ENTROPY_ES_DEAD_TIMER;
    ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_ES_DEAD_TIMER);
    ASSERT_TRUE(ns->permanentFailure == true && ns->floorFailStreak == 0);
    ASSERT_TRUE(!ns->needRecovery && !ns->onProbation && !ns->isEnable);
    uint32_t calls = g_permInitAtCalls;
    ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    ASSERT_TRUE(g_permInitAtCalls == calls);
EXIT:
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_PERMANENT_ALLOC_FUNC_TC001
* @spec  -
* @title  Allocation failures never feed the permanent latch.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Fail initAt with CRYPT_MEM_ALLOC_FAIL for five init cycles. Expected result 1.
* @expect
*    1. Every cycle returns CRYPT_MEM_ALLOC_FAIL; the streak stays zero and
*       the source is never latched.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_PERMANENT_ALLOC_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    TestMemInit();
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    g_permInitAtRet = CRYPT_MEM_ALLOC_FAIL;
    for (uint32_t i = 0; i < NS_PERMANENT_FAIL_STREAK + 1; i++) {
        ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_MEM_ALLOC_FAIL);
    }
    ASSERT_TRUE(ns->permanentFailure == false && ns->floorFailStreak == 0);
EXIT:
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_PERMANENT_ALLOC_GAP_FUNC_TC001
* @spec  -
* @title  An allocation gap neither advances nor resets the floor streak.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Accumulate three floor failures, interpose one allocation failure,
*       then fail once more at the floor. Expected result 1.
* @expect
*    1. The allocation cycle leaves the streak at three (zero-evidence: neither
*       increments nor resets); the following floor failure reaches the streak
*       limit and latches, so the interposed allocation does not shield the
*       source from a genuine run of floor failures.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_PERMANENT_ALLOC_GAP_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    TestMemInit();
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    g_permInitAtRet = CRYPT_ENTROPY_RCT_FAILURE;
    for (uint32_t i = 1; i < NS_PERMANENT_FAIL_STREAK; i++) {
        ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_RCT_FAILURE);
    }
    ASSERT_TRUE(ns->floorFailStreak == NS_PERMANENT_FAIL_STREAK - 1 && ns->permanentFailure == false);
    g_permInitAtRet = CRYPT_MEM_ALLOC_FAIL;
    ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_MEM_ALLOC_FAIL);
    ASSERT_TRUE(ns->floorFailStreak == NS_PERMANENT_FAIL_STREAK - 1 && ns->permanentFailure == false);
    g_permInitAtRet = CRYPT_ENTROPY_RCT_FAILURE;
    ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    ASSERT_TRUE(ns->permanentFailure == true);
EXIT:
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_PERMANENT_MIXED_SIBLING_FUNC_TC001
* @spec  -
* @title  A latched credited source keeps the source set unavailable.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Latch the adaptive mock source, add a sibling whose startup read fails
*       recoverably, and initialize the list. Expected result 1.
* @expect
*    1. Initialization returns ES_PERMANENT_FAILURE because every credited
*       source configured for the cycle is mandatory.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_PERMANENT_MIXED_SIBLING_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    CRYPT_EAL_NsMethod failMethod = {NULL, NULL, EntropyReadRecoverFail, NULL};
    CRYPT_EAL_NsTestPara para = {5, 39, 512};
    TestMemInit();
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    ns->permanentFailure = true;
    ASSERT_TRUE(ES_NsAdd(nsList, "recover-fail-node", false, 7, &failMethod, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    ASSERT_TRUE(g_permInitAtCalls == 0);
EXIT:
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_PERMANENT_WINDOW_FUNC_TC001
* @spec  -
* @title  Authoritative-window failures on a bottomed-out ladder latch the source.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Let initAt succeed with floor == ceiling while every startup-window
*       read fails with CRYPT_ENTROPY_RCT_FAILURE, for three cycles.
*       Expected result 1.
*    2. Fail a fourth cycle. Expected result 2.
* @expect
*    1. Each cycle returns the window verdict and counts one floor failure.
*    2. The fourth cycle latches the source and returns ES_PERMANENT_FAILURE.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_PERMANENT_WINDOW_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    TestMemInit();
    nsList = PermNsListNew(2);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    g_permReadRet = CRYPT_ENTROPY_RCT_FAILURE;
    for (uint32_t i = 1; i < NS_PERMANENT_FAIL_STREAK; i++) {
        ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_RCT_FAILURE);
        ASSERT_TRUE(ns->permanentFailure == false && ns->floorFailStreak == i);
    }
    ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    ASSERT_TRUE(ns->permanentFailure == true);
EXIT:
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_PERMANENT_RAWCODE_FUNC_TC001
* @spec  -
* @title  Private negative read verdicts preserve adaptive governance state.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Let every startup-window read fail with a private negative code (-1)
*       for five cycles. Expected result 1.
* @expect
*    1. Each cycle returns the public ES_NS_NOT_AVA verdict, keeps the current
*       osr, and leaves the health-failure streak and permanent latch clear.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_PERMANENT_RAWCODE_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    TestMemInit();
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    g_permReadRet = -1;
    for (uint32_t i = 0; i < NS_PERMANENT_FAIL_STREAK + 1; i++) {
        ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_ES_NS_NOT_AVA);
    }
    ASSERT_TRUE(ns->osr == 2 && ns->floorFailStreak == 0);
    ASSERT_TRUE(ns->permanentFailure == false);
EXIT:
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_PERMANENT_SURVIVOR_FUNC_TC001
* @spec  -
* @title  A newly latched credited source blocks a live credited sibling.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Put the adaptive mock source one failure below its permanent tier,
*       add a plain working source, and initialize the list. Expected result 1.
* @expect
*    1. The mock retires in this cycle and initialization returns
*       ES_PERMANENT_FAILURE even though the sibling initialized successfully.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_PERMANENT_SURVIVOR_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    CRYPT_EAL_NsMethod live = {NULL, NULL, EntropyReadNormal, NULL};
    CRYPT_EAL_NsTestPara para = {5, 39, 512};
    TestMemInit();
    nsList = PermNsListNew(8);
    ASSERT_TRUE(nsList != NULL);
    ES_NoiseSource *ns = BSL_LIST_FirstNodeData(nsList);
    ns->osr = ns->osrMax;
    ns->floorFailStreak = NS_PERMANENT_FAIL_STREAK - 1;
    g_permInitAtRet = CRYPT_ENTROPY_RCT_FAILURE;
    ASSERT_TRUE(ES_NsAdd(nsList, "live-node", true, 7, &live, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(ES_NsListInit(nsList, true) == CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    ASSERT_TRUE(ns->permanentFailure && !ns->isEnable && g_permInitAtCalls == 1);
EXIT:
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_NS_PERMANENT_SURVIVOR_FUNC_TC002
* @spec  -
* @title  A credited retirement is reported behind an earlier transient failure.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Register a transient RCT-failing credited source first, the adaptive
*       mock one failure below its permanent tier second, and a working source
*       third, then initialize the list. Expected result 1.
* @expect
*    1. Initialization returns ES_PERMANENT_FAILURE: the retirement verdict
*       is independent of registration order.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_PERMANENT_SURVIVOR_FUNC_TC002(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    BslList *nsList = NULL;
    CRYPT_EAL_NsMethod transient = {NULL, NULL, EntropyReadWindowFail, NULL};
    CRYPT_EAL_NsMethod adaptive = {NULL, NULL, EntropyPermRead, NULL};
    CRYPT_EAL_NsMethod live = {NULL, NULL, EntropyReadNormal, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    CRYPT_EAL_NsTestPara adaptivePara = {5, 39, 512};
    TestMemInit();
    nsList = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(nsList != NULL);
    g_entropyWindowFailRet = CRYPT_ENTROPY_RCT_FAILURE;
    ASSERT_EQ(ES_NsAdd(nsList, "transient-node", false, 5, &transient, &para), CRYPT_SUCCESS);
    ASSERT_EQ(ES_NsAdd(nsList, "perm-mock", true, 5, &adaptive, &adaptivePara), CRYPT_SUCCESS);
    ASSERT_EQ(ES_NsAdd(nsList, "live-node", true, 7, &live, &para), CRYPT_SUCCESS);
    BslListNode *node = BSL_LIST_GetNextNode(nsList, BSL_LIST_FirstNode(nsList));
    ASSERT_TRUE(node != NULL);
    ES_NoiseSource *ns = BSL_LIST_GetData(node);
    ASSERT_TRUE(ns != NULL);
    ns->initAt = EntropyPermInitAt;
    ns->osr = 8;
    ns->osrMax = 8;
    ns->floorFailStreak = NS_PERMANENT_FAIL_STREAK - 1;
    g_permInitAtRet = CRYPT_ENTROPY_RCT_FAILURE;
    g_permReadRet = CRYPT_SUCCESS;
    g_permInitAtCalls = 0;
    ASSERT_EQ(ES_NsListInit(nsList, true), CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    ASSERT_TRUE(ns->permanentFailure && !ns->isEnable && g_permInitAtCalls == 1);
EXIT:
    g_permInitAtRet = CRYPT_SUCCESS;
    g_entropyWindowFailRet = CRYPT_ENTROPY_RCT_FAILURE;
    ES_NsListFree(nsList);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsGatherTest
* @spec  -
* @title  Testing the entropy source gather interface.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsGatherTest(int gather, int length, int expRes)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    uint32_t size = 512;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    if (gather == 1) {
        BSL_SAL_ThreadId thrd;
        ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrd, EsGatherAuto, es) == 0);
        BSL_SAL_ThreadClose(thrd);
    }
    uint8_t buf[513] = {0};
    uint32_t len = CRYPT_EAL_EsEntropyGet(es, buf, length);
    ASSERT_TRUE(len == (uint32_t)expRes);

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)gather;
    (void)length;
    (void)expRes;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsWithoutNsTest
* @spec  -
* @title  No or no available noise source test.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsWithoutNsTest()
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10) == CRYPT_SUCCESS);
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9) == CRYPT_SUCCESS);
#endif
    bool healthTest = false;
    /* Disable health tests so the remaining source reaches the no-NS path. */
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) != CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {
        "aaa",
        false,
        7,
        {
            NULL,
            EntropyInitError,
            EntropyReadError,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsMultiNsTest
* @spec  -
* @title  Test with available and various unavailable noise sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsMultiNsTest()
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_LOG_CALLBACK, EntropyRunLogCb, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara errPara = {
        "read-err-ns",
        false,
        0,
        {
            NULL,
            NULL,
            EntropyReadError,
            NULL,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&errPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara initPara = {
        "init-err-ns",
        false,
        0,
        {
            NULL,
            EntropyInitError,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&initPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    /* Zero-credit source that survives the startup window (where one runs)
       and fails on byte-wise gather reads: its seed-phase death is tolerated
       and observable on every platform. */
    CRYPT_EAL_NsPara heaPara = {
        "health-err-ns",
        false,
        0,
        {
            NULL,
            EntropyInitTest,
            EntropyReadByteFail,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    g_entropyByteFailCalls = 0;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&heaPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    /* Varied across calls: the byte-wise gather must not collapse to a
       constant (EntropyReadDiffData restarts per call). */
    CRYPT_EAL_NsPara norPara = {
        "normal-ns",
        false,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadVaried,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&norPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    /* The NTG.1.4 startup gate gathers at init, so the failing source is
       observed (and disabled) during EsInit already; count from there. */
    g_entropyNsFailCount = 0;
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    uint8_t buf[32] = {0};
    ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(es, buf, 32) == 32);
    ASSERT_TRUE(g_entropyNsFailCount > 0);
    /* The zero-credit source did fail during the seed gather itself. */
    ASSERT_EQ(g_entropyByteFailCalls, 1);

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EsNsNumberTest
* @spec  -
* @title  Test with available and various unavailable noise sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_UNCREDITED_ONLY_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
    ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {
        "zero-credit",
        false,
        0,
        {NULL, NULL, EntropyReadNormal, NULL},
        {5, 39, 512},
    };
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para)), CRYPT_SUCCESS);
    bool healthTest = false;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    uint8_t buf[32] = {0};
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, buf, sizeof(buf)), 0);
    (void)TestErrClear();
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EsNsNumberTest(int number, int minEn, int expLen)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* Skip on WSL - platform-specific noise source behavior varies */
    if (IsRunningOnWSL()) {
        (void)number;
        (void)minEn;
        (void)expLen;
        SKIP_TEST();
    }
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10) == CRYPT_SUCCESS);
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9) == CRYPT_SUCCESS);
#endif
    CRYPT_EAL_NsPara errPara = {
        NULL,
        false,
        minEn,
        {
            NULL,
            NULL,
            EntropyReadNumber,
            NULL,
        },
        {5, 39, 512},
    };
    /* expLen == 0 rows stop each source before it reaches the credit target. */
    g_entropyNumberReads = 0;
    g_entropyNumberDieAt = (expLen == 0) ? 100 : 0;
    const char *name = "ns-normal-";
    errPara.name = BSL_SAL_Malloc(strlen(name) + 3);
    ASSERT_TRUE(errPara.name != NULL);
    size_t nameCap = strlen(name) + 3;
    for(int32_t iter = 0; iter < number; iter++) {
        char str[16] = {0}; /* enough for int32_t "%d" */
        strncpy((char *)(intptr_t)errPara.name, name, nameCap - 1);
        ((char *)(intptr_t)errPara.name)[nameCap - 1] = '\0';
        snprintf(str, sizeof(str), "%d", iter);
        strncat((char *)(intptr_t)errPara.name, str, nameCap - 1 - strlen((char *)(intptr_t)errPara.name));
        if (iter >= 16) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&errPara, sizeof(CRYPT_EAL_NsPara)) != CRYPT_SUCCESS);
            (void)TestErrClear();
        } else {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&errPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
        }
    }

    int32_t ret = CRYPT_EAL_EsInit(es);
    if (expLen == 0) {
        ASSERT_TRUE(ret != CRYPT_SUCCESS);
        (void)TestErrClear();
        goto EXIT;
    }
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    uint8_t buf[32] = {0};
    ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(es, buf, 32) == (uint32_t)expLen);
    if (expLen != 0) {
        ASSERT_TRUE(TestIsErrStackEmpty());
    }

EXIT:
    BSL_SAL_Free((void *)(intptr_t)errPara.name);
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)number;
    (void)minEn;
    (void)expLen;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_EorTest
* @spec  -
* @title  Test with available and various unavailable noise sources.
* @brief    1.conditioning function not set, expected result 1
            2.entropy source not initialized, expected result 2
            3.repeated setting of conditioning function, expected result 3
* @expect   1. result 1: failed
            2. result 2: failed
            3. result 3: failed
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EorTest(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    uint8_t buf[32] = {0};
    ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(es, buf, 32) == 0);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_MutiTest
* @spec  -
* @title  Test with available and various unavailable noise sources.
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MutiTest(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")) == CRYPT_SUCCESS);
    uint32_t size = 512;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    BSL_SAL_ThreadId thrd;
    ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrd, EsGatherAuto, es) == 0);
    BSL_SAL_ThreadClose(thrd);
    for (int32_t iter = 0; iter < 3; iter++) {
        BSL_SAL_ThreadId thrdget;
        ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrdget, EsGetAuto, es) == 0);
        BSL_SAL_ThreadClose(thrdget);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_MutiBeforeInitTest
* @spec  -
* @title  Test with available and various unavailable noise sources.
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MutiBeforeInitTest(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    for (int32_t iter = 0; iter < 3; iter++) {
        BSL_SAL_ThreadId thrdget;
        ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrdget, EsMutiAuto, es) == 0);
        BSL_SAL_ThreadClose(thrdget);
    }
    BSL_SAL_ThreadId thrd;
    ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrd, EsGatherAuto, es) == 0);
    BSL_SAL_ThreadClose(thrd);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0001
* @spec  -
* @title  Function test with the health test disabled, noise source not added, and entropy not added.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0001(int enableTest)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha512_df", strlen("sha512_df")) == CRYPT_SUCCESS);
    if(enableTest) {
        bool healthTest = IsRunningOnWSL() ? false : true;
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    DrainStartupSeed(es);
    uint32_t size;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 64);
    uint8_t buf[8192] = {0};
    uint32_t resLen = CRYPT_EAL_EsEntropyGet(es, buf, 8192);
    ASSERT_TRUE(resLen == 64);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)enableTest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0002
* @spec  -
* @title  Function test of adding noise sources and entropy by pressing Ctrl when the health check mode is disabled.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0002(int enableTest)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10) == CRYPT_SUCCESS);
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9) == CRYPT_SUCCESS);
#endif
    CRYPT_EAL_NsPara norPara = {
        "normal-ns",
        enableTest,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&norPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    if(enableTest) {
        bool healthTest = IsRunningOnWSL() ? false : true;
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    DrainStartupSeed(es);
    uint32_t size;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 32);
    uint8_t buf[8192] = {0};
    uint32_t resLen = CRYPT_EAL_EsEntropyGet(es, buf, 8192);
    ASSERT_TRUE(resLen == 32);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)enableTest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0003
* @spec  -
* @title  Entropy source traversal test with the health test disabled, no noise source added, and different compression functions enabled.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0003(int alg, int enableTest)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    const char *mode = EsGetCfMode((uint32_t)alg);
    uint32_t expectGetLen = EsGetCfLen((uint32_t)alg);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    if(enableTest) {
        bool healthTest = IsRunningOnWSL() ? false : true;
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    DrainStartupSeed(es);
    uint32_t size;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, expectGetLen);
    uint8_t buf[8192] = {0};
    uint32_t resLen = CRYPT_EAL_EsEntropyGet(es, buf, 8192);
    ASSERT_TRUE(resLen == expectGetLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)alg;
    (void)enableTest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0004
* @spec  -
* @title  Function test of adding noise source and removing noise source after obtaining entropy source in health test disabled mode.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0004(int enableTest)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    uint32_t expectGetLen = 32;
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10) == CRYPT_SUCCESS);
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9) == CRYPT_SUCCESS);
#endif
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_ENTROPY_ES_NO_NS);
    (void)TestErrClear();
    CRYPT_EAL_NsPara norPara1 = {
        "normal-ns",
        enableTest,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {0, 0, 512},
    };
    CRYPT_EAL_NsPara norPara2 = {
        "aux-src",
        enableTest,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&norPara1, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    if(enableTest) {
        bool healthTest = IsRunningOnWSL() ? false : true;
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    DrainStartupSeed(es);
    uint32_t size;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, expectGetLen);
    uint8_t buf[8192] = {0};
    uint32_t resLen = CRYPT_EAL_EsEntropyGet(es, buf, 8192);
    ASSERT_TRUE(resLen == expectGetLen);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_EQ(size, 0);

    (void)BSL_SAL_ThreadWriteLock(es->lock);
    ENTROPY_EsDeinit(es->es);
    (void)BSL_SAL_ThreadUnlock(es->lock);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"normal-ns", 10) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_ENTROPY_ES_NO_NS);
    (void)TestErrClear();
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&norPara2, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    DrainStartupSeed(es);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    resLen = CRYPT_EAL_EsEntropyGet(es, buf, 8192);
    ASSERT_TRUE(resLen == expectGetLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)enableTest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0005
* @spec  -
* @title  Functional testing of boundary values for different entropy pool sizes.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0005(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    uint32_t poolErrorSize[] = {511, 4097, 1024};
    uint32_t poolSize = 512;
    int32_t ret = 1;

    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    for (uint32_t i = 0; i < sizeof(poolErrorSize)/sizeof(uint32_t); i++) {
        ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&poolErrorSize[i], sizeof(uint32_t));
        if (ret == CRYPT_SUCCESS) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GET_POOL_SIZE, &poolSize, sizeof(uint32_t)) == CRYPT_ENTROPY_ES_STATE_ERROR);
            ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GET_POOL_SIZE, &poolSize, sizeof(uint32_t)) == CRYPT_SUCCESS);
            ASSERT_EQ(poolSize, poolErrorSize[i]);
        } else {
            ASSERT_TRUE(ret == CRYPT_ENTROPY_CTRL_INVALID_PARAM);
        }
    }
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0006
* @spec  -
* @title  Entropy source function test in the multi-thread concurrency scenario.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0006(int alg)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    const uint32_t threadNum = 5;
    pthread_t threadId[threadNum];

    for(uint32_t i = 0; i < threadNum; i++) {
        int ret = pthread_create(&threadId[i], NULL, (void *)EntropyESMutilTest, &alg);
        ASSERT_TRUE(ret == 0);
    }

    for(uint32_t i = 0; i < threadNum; i++) {
        pthread_join(threadId[i], NULL);
    }
EXIT:
    return;
#else
    (void)alg;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_FUNC_0007
* @spec  -
* @title  Adding an Existing Noise Source Control Test.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_FUNC_0007(int enableTest)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || \
    defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Duplicate detection matches on the name, so target a built-in source that
       this build actually registers. */
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)
    const char *dupName = "CPU-Jitter";
#else
    const char *dupName = "Hash-Loop";
#endif
    CRYPT_EAL_NsPara norPara = {
        dupName,
        enableTest,
        7,
        {
            NULL,
            EntropyInitTest,
            EntropyReadDiffData,
            EntropyDeinitTest,
        },
        {5, 39, 512},
    };

    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sm3_df", strlen("sm3_df")) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&norPara, sizeof(CRYPT_EAL_NsPara)) == CRYPT_ENTROPY_ES_DUP_NS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"notExistNs", 10) == CRYPT_ENTROPY_ES_NS_NOT_FOUND);
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)enableTest;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_SEEDPOOL_GetTest
* @spec  -
* @title  seedpool_GetTest
* @precon  nan
* @brief    1. Entropy data length: 32 - 512, entropy amount: 384, npes not available, return length: 48
            2. Entropy data length: 32 - 512, entropy amount: 384, npes available, return length: 64
            3. entropy data length: 64 - 512, entropy: 380, npes not available, return length: 64
            4. Entropy data length: 64 - 512, entropy amount: 380, npes available, return length: 64
            5. Entropy data length: 48 - 512, entropy amount: 384, npes available, return length: 54
            6. entropy data length: 32 - 32, entropy amount: 256, npes not available, return length: 32
            7. entropy data length: 48 - 48, entropy amount: 256, npes available, return length: 48
            8. entropy data length: 48 - 512, entropy amount: 680, npes available, return length: 48
* @expect
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_SEEDPOOL_GetTest(int min, int max, int entropy, int npes, int exp)
{
    uint8_t *buf = NULL;
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara para1 = {false, 6, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    CRYPT_EAL_EsPara para2 = {true, 8, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para2) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, (bool)npes, (uint32_t)min, (uint32_t)max, (uint32_t)entropy);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    uint32_t len;
    buf = EAL_EntropyDetachBuf(ctx, &len);
    ASSERT_TRUE(len == (uint32_t)exp);
    if (exp == 0) {
        ASSERT_TRUE(buf == NULL);
    } else {
        ASSERT_TRUE(buf != NULL);
    }
EXIT:
    BSL_SAL_Free(buf);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_SeedPoolFree(pool);
    return;
}
/* END_CASE */
#if defined(HITLS_CRYPTO_ENTROPY_GETENTROPY) || defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM)
#include "entropy_seed_pool.h"
typedef struct EntCtx {
    uint32_t entSum;
} EntCtx;

static uint32_t EntropyGetSum(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    EntCtx *enctx = (EntCtx *)ctx;
    uint32_t ret = ENTROPY_SysEntropyGet(ctx, buf, bufLen);
    enctx->entSum += ret;
    return ret;
}
#endif

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_SYS_CALLBACK_STACK_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_GETENTROPY) || defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM))
    uint8_t sentinel[1];
    (void)TestErrClear();
    ASSERT_EQ(ENTROPY_EsEntropyGet(NULL, sentinel, sizeof(sentinel)), 0);
    ASSERT_EQ(BSL_ERR_PeekLastError(), CRYPT_NULL_INPUT);
    ASSERT_EQ(BSL_ERR_SetMark(), BSL_SUCCESS);
    ASSERT_EQ(ENTROPY_SysEntropyGet(NULL, NULL, 1), 0);
    ASSERT_EQ(BSL_ERR_PeekLastError(), CRYPT_NULL_INPUT);
    ASSERT_EQ(BSL_ERR_PopToMark(), BSL_SUCCESS);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_NULL_INPUT);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_SEEDPOOL_EntropySumTest(int minEntropy1, int minEntropy2, int min, int entropy, int exp)
{
#if defined(HITLS_CRYPTO_ENTROPY_GETENTROPY) || defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM)
    uint8_t *buf = NULL;
    EAL_EntropyCtx *ctx = NULL;
    EntCtx enctx = {0};

    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara para1 = {false, minEntropy1, &enctx, (CRYPT_EAL_EntropyGet)EntropyGetSum};
    CRYPT_EAL_EsPara para2 = {false, minEntropy2, &enctx, (CRYPT_EAL_EntropyGet)EntropyGetSum};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para2) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)min, (uint32_t)min, (uint32_t)entropy);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    uint32_t len;
    buf = EAL_EntropyDetachBuf(ctx, &len);
    ASSERT_TRUE(len == (uint32_t)min);
    if (exp == 0) {
        ASSERT_TRUE(buf == NULL);
    } else {
        ASSERT_TRUE(buf != NULL);
    }
    ASSERT_TRUE(enctx.entSum == (uint32_t)exp);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(buf);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_SeedPoolFree(pool);
    return;
#else
    (void)minEntropy1;
    (void)minEntropy2;
    (void)min;
    (void)entropy;
    (void)exp;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_DrbgTest
* @spec  -
* @title  use seedpool to construct an entropy source and generate a random number.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_DrbgTest(int isNull, int algId)
{
#ifndef HITLS_CRYPTO_DRBG_GM
    if (algId == CRYPT_RAND_SM3 || algId == CRYPT_RAND_SM4_CTR_DF) {
        (void)isNull;
        SKIP_TEST();
    }
#endif
#ifndef HITLS_CRYPTO_DRBG_HASH
    if (algId == CRYPT_RAND_SHA256) {
        (void)isNull;
        SKIP_TEST();
    }
#endif
#ifndef HITLS_CRYPTO_DRBG_HMAC
    if (algId == CRYPT_RAND_HMAC_SHA256 || algId == CRYPT_RAND_HMAC_SHA384) {
        (void)isNull;
        SKIP_TEST();
    }
#endif
#ifndef HITLS_CRYPTO_DRBG_CTR
    if (algId == CRYPT_RAND_AES128_CTR_DF || algId == CRYPT_RAND_SM4_CTR_DF) {
        (void)isNull;
        SKIP_TEST();
    }
#endif
    uint8_t output[16];
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew((bool)isNull);
    CRYPT_EAL_EsPara para1 = {true, 6, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    CRYPT_EAL_EsPara para2 = {false, 7, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para2) == CRYPT_SUCCESS);
    CRYPT_RandSeedMethod meth = {0};
    ASSERT_TRUE(EAL_SetDefaultEntropyMeth(&meth) == CRYPT_SUCCESS);
    CRYPT_EAL_RandDeinit();
    ASSERT_TRUE(CRYPT_EAL_RandInit((CRYPT_RAND_AlgId)algId, &meth, (void *)pool, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_Randbytes(output, 16) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_SeedPoolFree(pool);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_DrbgTest
* @spec  -
* @title  use hitls es to construct an entropy source and generate a random number.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DrbgTest(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    uint8_t output[256];
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")) == CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {
        "aaa",
        true,
        7,
        {
            NULL,
            NULL,
            EntropyReadNormal,
            NULL,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    for (int32_t iter = 0; iter < 5; iter++) {
        ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    }
    CRYPT_RandSeedMethod meth = {GetEntropyTest, CleanEntropyTest, GetNonceTest, CleanNonceTest};
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, &meth, (void *)es, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_Randbytes(output, 256) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_MutiTest
* @spec  -
* @title  use seedpool to construct the entropy source and perform the multi-thread test.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_MutiTest(void)
{
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(false);
    CRYPT_EAL_EsPara para1 = {true, 6, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    CRYPT_EAL_EsPara para2 = {false, 7, NULL, (CRYPT_EAL_EntropyGet)EntropyGetNormal};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para2) == CRYPT_SUCCESS);
    CRYPT_RandSeedMethod meth = {0};
    ASSERT_TRUE(EAL_SetDefaultEntropyMeth(&meth) == CRYPT_SUCCESS);
    for (int32_t index = 0; index < 3; index++) {
        pthread_t thrd;
        ASSERT_TRUE(pthread_create(&thrd, NULL, DrbgSeedTest, pool) == 0);
        pthread_join(thrd, NULL);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_GetEntropyErrTest
* @spec  -
* @title  The entropy source quality is too poor to meet the requirements.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_GetEntropyErrTest(void)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(5, 5, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 32, 48, 256);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_EntLenLessMinTest
* @spec  -
* @title  The supplied entropy source data is smaller than the minimum length.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_EntLenLessMinTest(void)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(5, 5, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 32, 48, 128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_Get0EntropyTest
* @spec  -
* @title  failed to obtain entropy data from the entropy pool.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_Get0EntropyTest(void)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    CRYPT_EAL_EsPara para1 = {true, 6, NULL, (CRYPT_EAL_EntropyGet)EntropyGet0Normal};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, 32, 48, 256);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_OVERSIZE_RETURN_TC001(void)
{
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara para = {true, 8, NULL, (CRYPT_EAL_EntropyGet)EntropyGetOversize};
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(pool, &para), CRYPT_SUCCESS);
    uint8_t buf[8] = {0};
    uint32_t len = sizeof(buf);
    (void)TestErrClear();
    ASSERT_EQ(ENTROPY_SeedPoolCollect(pool->pool, true, 8, buf, &len), 0);
    ASSERT_EQ(len, 0);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_SEED_POOL_STATE_ERROR);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_UnsedSeedPoolTest
* @spec  -
* @title  Failed to obtain the entropy data of sufficient length.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_UnsedSeedPoolTest(void)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(8, 8, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 81, 100, 128);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_DiffEntropyTest
* @spec  -
* @title  The entropy pool used for handle creation is inconsistent with the obtained entropy pool. As a result,
           the entropy source fails to be obtained.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_DiffEntropyTest(void)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(8, 8, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 32, 64, 256);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_SeedPoolCtx *pool1 = GetPoolCtx(6, 6, true, false);
    ASSERT_TRUE(pool1 != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool1, ctx) != CRYPT_SUCCESS);
    CRYPT_EAL_SeedPoolFree(pool1);
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_Get0EntropyTest
* @spec  -
* @title  Obtains the total entropy output without using the conditioning function.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_FENoEcfTest(int ent)
{
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(8, 7, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 32, 32, ent);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    uint32_t len;
    uint8_t *data = EAL_EntropyDetachBuf(ctx, &len);
    ASSERT_TRUE(data != NULL);
    ASSERT_TRUE(len == 32);
    BSL_SAL_Free(data);

EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_FEWithEcfTest
* @spec  -
* @title  Obtains the total entropy output without using the conditioning function.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_FEWithEcfTest(void)
{
#ifndef HITLS_CRYPTO_HMAC
    SKIP_TEST();
#endif
    EAL_EntropyCtx *ctx = NULL;

    CRYPT_EAL_SeedPoolCtx *pool = GetPoolCtx(8, 7, true, false);
    ASSERT_TRUE(pool != NULL);
    ctx = EAL_EntropyNewCtx(pool, true, 48, 48, 384);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    uint32_t len;
    uint8_t *data = EAL_EntropyDetachBuf(ctx, &len);
    ASSERT_TRUE(data != NULL);
    ASSERT_TRUE(len == 48);
    BSL_SAL_Free(data);
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_SEEDPOOL_CompleteTest
* @spec  -
* @title  Complete usage testing from entropy source to drbg.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_CompleteTest(void)
{
    CRYPT_EAL_RndCtx *rndCtx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(false);
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) == CRYPT_SUCCESS);
    uint32_t size = 512;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, (void *)&size, sizeof(uint32_t)) == CRYPT_SUCCESS);
    /* Zero-credit mixing source: its constant stream dies on the startup
       window's per-sample tests; a credited source's health verdict fails
       the whole init, while a zero-credit one is carried by the built-ins. */
    CRYPT_EAL_NsPara para = {
        "aaa",
        false,
        0,
        {
            NULL,
            NULL,
            EntropyReadNormal,
            NULL,
        },
        {5, 39, 512},
    };
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsInit(es) == CRYPT_SUCCESS);
    BSL_SAL_ThreadId thrd;
    ASSERT_TRUE(BSL_SAL_ThreadCreate(&thrd, EsGatherAuto, es) == 0);
    BSL_SAL_ThreadClose(thrd);

    CRYPT_EAL_EsPara para1 = {false, 8, es, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &para1) == CRYPT_SUCCESS);
#endif
    CRYPT_RandSeedMethod meth = {0};
    ASSERT_TRUE(EAL_SetDefaultEntropyMeth(&meth) == CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_DRBG_GM
    rndCtx = CRYPT_EAL_DrbgNew(CRYPT_RAND_SM4_CTR_DF, &meth, pool);
#else
    rndCtx = CRYPT_EAL_DrbgNew(CRYPT_RAND_AES256_CTR_DF, &meth, pool);
#endif
    ASSERT_TRUE(rndCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(rndCtx, NULL, 0) == CRYPT_SUCCESS);
    uint8_t out[16] = {0};
    ASSERT_TRUE(CRYPT_EAL_Drbgbytes(rndCtx, out, 16) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_DrbgSeed(rndCtx) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_DrbgDeinit(rndCtx);
    CRYPT_EAL_SeedPoolFree(pool);
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_EsFree(es);
#endif
    return;
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC019
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC019(int isCreateNullPool, int isPhysical, int minEntropy, int minL, int maxL, int entropyL, int isValid)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    /* Retry startup health tests for timing-dependent cpu-jitter samples. */
    int32_t ret = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret = CRYPT_EAL_EsInit(es);
        if (ret == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC019] CRYPT_EAL_EsInit succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            printf("[TC019] CRYPT_EAL_EsInit attempt %d/%d failed: 0x%08x (%d), retrying...\n",
                   attempt, maxRetries, ret, ret);
            TestErrClear();
        } else {
            printf("[TC019] CRYPT_EAL_EsInit failed after %d attempts, last error: 0x%08x (%d)\n",
                   maxRetries, ret, ret);
            printf("[TC019] Test parameters: isCreateNullPool=%d, isPhysical=%d, minEntropy=%d, minL=%d, maxL=%d, entropyL=%d, isValid=%d\n",
                   isCreateNullPool, isPhysical, minEntropy, minL, maxL, entropyL, isValid);
            printf("[TC019] Health test enabled: %s\n", healthTest ? "true" : "false");
        }
    }
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    if (isCreateNullPool) {
        for (int i = 0; i < 16; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara = {isPhysical, (uint32_t)minEntropy, es, NULL};
    if (isValid) {
        esPara.entropyGet = (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet;
    } else {
        esPara.entropyGet = (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy;
    }
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara) == CRYPT_SUCCESS);
    uint8_t isNpesUsed = true;
    uint32_t minLen = (uint32_t)minL;
    uint32_t maxLen = (uint32_t)maxL;
    uint32_t entropy = (uint32_t)entropyL;
    ctx = EAL_EntropyNewCtx(pool, isNpesUsed, minLen, maxLen, entropy);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());
    if (isCreateNullPool && !isValid) {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT);
        TestErrClear();
    } else {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    (void)isValid;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC039
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC039(int isCreateNullPool, int isPhysical, int minEntropy, int minL, int maxL, int entropyL)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    CRYPT_EAL_Es *es1 = NULL;
    CRYPT_EAL_Es *es2 = NULL;
    CRYPT_EAL_Es *es3 = NULL;
    pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    es1 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es1 != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret1 = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret1 = CRYPT_EAL_EsInit(es1);
        if (ret1 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC039] es1 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret1 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara1 = {isPhysical, (uint32_t)minEntropy, es1, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    es2 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret2 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret2 = CRYPT_EAL_EsInit(es2);
        if (ret2 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC039] es2 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret2 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara2 = {!isPhysical, (uint32_t)minEntropy, es2, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    es3 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es3 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret3 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret3 = CRYPT_EAL_EsInit(es3);
        if (ret3 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC039] es3 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret3 == CRYPT_SUCCESS);
    if (isCreateNullPool) {
        for (int i = 0; i < 3; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara3 = {isPhysical, (uint32_t)minEntropy, es3, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara3) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)minL, (uint32_t)maxL, (uint32_t)entropyL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es1);
    CRYPT_EAL_EsFree(es2);
    CRYPT_EAL_EsFree(es3);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC067
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC067(int isCreateNullPool, int isPhysical, int minEntropy, int minL, int maxL, int entropyL)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    CRYPT_EAL_Es *es1 = NULL;
    CRYPT_EAL_Es *es2 = NULL;
    CRYPT_EAL_Es *es3 = NULL;
    pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    es1 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es1 != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret1 = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret1 = CRYPT_EAL_EsInit(es1);
        if (ret1 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC067] es1 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret1 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara1 = {isPhysical, (uint32_t)minEntropy, es1, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    es2 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret2 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret2 = CRYPT_EAL_EsInit(es2);
        if (ret2 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC067] es2 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret2 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara2 = {!isPhysical, (uint32_t)minEntropy, es2, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    es3 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es3 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret3 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret3 = CRYPT_EAL_EsInit(es3);
        if (ret3 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC067] es3 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret3 == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara3 = {isPhysical, (uint32_t)minEntropy, es3, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara3) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)minL, (uint32_t)maxL, (uint32_t)entropyL);
    ASSERT_TRUE(ctx != NULL);
    if (isCreateNullPool) {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) != CRYPT_SUCCESS);
    } else {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es1);
    CRYPT_EAL_EsFree(es2);
    CRYPT_EAL_EsFree(es3);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC071
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC071(int isCreateNullPool, int isPhysical, int minEntropy, int minL, int maxL, int entropyL)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    CRYPT_EAL_Es *es1 = NULL;
    CRYPT_EAL_Es *es2 = NULL;
    CRYPT_EAL_Es *es3 = NULL;
    pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    es1 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es1 != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret1 = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret1 = CRYPT_EAL_EsInit(es1);
        if (ret1 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC071] es1 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret1 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara1 = {!isPhysical, (uint32_t)minEntropy, es1, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    es2 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret2 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret2 = CRYPT_EAL_EsInit(es2);
        if (ret2 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC071] es2 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret2 == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_EsPara esPara2 = {isPhysical, (uint32_t)minEntropy, es2, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    es3 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es3 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret3 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret3 = CRYPT_EAL_EsInit(es3);
        if (ret3 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC071] es3 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret3 == CRYPT_SUCCESS);
    if (isCreateNullPool) {
        for (int i = 0; i < 13; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara3 = {isPhysical, (uint32_t)minEntropy, es3, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara3) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)minL, (uint32_t)maxL, (uint32_t)entropyL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es1);
    CRYPT_EAL_EsFree(es2);
    CRYPT_EAL_EsFree(es3);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC051
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC051(int isCreateNullPool, int isPhysical, int minEntropy1,
    int minEntropy2, int minEntropy3, int minL, int maxL, int entropyL)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    CRYPT_EAL_Es *es1 = NULL;
    CRYPT_EAL_Es *es2 = NULL;
    CRYPT_EAL_Es *es3 = NULL;
    pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    es1 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es1 != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret1 = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret1 = CRYPT_EAL_EsInit(es1);
        if (ret1 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC051] es1 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret1 == CRYPT_SUCCESS);

    if (isCreateNullPool) {
        for (int i = 0; i < 1; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara1 = {!isPhysical, (uint32_t)minEntropy1, es1, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    es2 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret2 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret2 = CRYPT_EAL_EsInit(es2);
        if (ret2 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC051] es2 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret2 == CRYPT_SUCCESS);

    if (isCreateNullPool) {
        for (int i = 0; i < 2; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara2 = {isPhysical, (uint32_t)minEntropy2, es2, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    es3 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es3 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret3 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret3 = CRYPT_EAL_EsInit(es3);
        if (ret3 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC051] es3 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret3 == CRYPT_SUCCESS);
    if (isCreateNullPool) {
        for (int i = 0; i < 13; i++) {
            ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) == CRYPT_SUCCESS);
        }
    }
    CRYPT_EAL_EsPara esPara3 = {isPhysical, (uint32_t)minEntropy3, es3, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara3) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)minL, (uint32_t)maxL, (uint32_t)entropyL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es1);
    CRYPT_EAL_EsFree(es2);
    CRYPT_EAL_EsFree(es3);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy1;
    (void)minEntropy2;
    (void)minEntropy3;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  HITLS_SDV_DRBG_GM_FUNC_TC056
* @spec  -
* @title  Complete usage testing from entropy sources.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void HITLS_SDV_DRBG_GM_FUNC_TC056(int isCreateNullPool, int isPhysical, int minEntropy1,
    int minEntropy2, int minEntropy3, int minL, int maxL, int entropyL)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    EAL_EntropyCtx *ctx = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    CRYPT_EAL_Es *es1 = NULL;
    CRYPT_EAL_Es *es2 = NULL;
    CRYPT_EAL_Es *es3 = NULL;
    pool = CRYPT_EAL_SeedPoolNew(isCreateNullPool);
    es1 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es1 != NULL);
    char *mode = "sm3_df";
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    /* On WSL, disable health testing due to timestamp precision issues */
    bool healthTest = IsRunningOnWSL() ? false : true;
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es1, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret1 = CRYPT_NULL_INPUT;
    const int maxRetries = 5;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret1 = CRYPT_EAL_EsInit(es1);
        if (ret1 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC056] es1 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret1 == CRYPT_SUCCESS);

    CRYPT_EAL_EsPara esPara1 = {!isPhysical, (uint32_t)minEntropy1, es1, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    es2 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es2 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es2, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret2 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret2 = CRYPT_EAL_EsInit(es2);
        if (ret2 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC056] es2 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret2 == CRYPT_SUCCESS);

    CRYPT_EAL_EsPara esPara2 = {isPhysical, (uint32_t)minEntropy2, es2, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    es3 = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es3 != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)mode, strlen(mode)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es3, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(bool)) == CRYPT_SUCCESS);

    int32_t ret3 = CRYPT_NULL_INPUT;
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        ret3 = CRYPT_EAL_EsInit(es3);
        if (ret3 == CRYPT_SUCCESS) {
            if (attempt > 1) {
                printf("[TC056] es3 init succeeded on attempt %d/%d\n", attempt, maxRetries);
            }
            break;
        }
        if (attempt < maxRetries) {
            TestErrClear();
        }
    }
    ASSERT_TRUE(ret3 == CRYPT_SUCCESS);

    CRYPT_EAL_EsPara esPara3 = {isPhysical, (uint32_t)minEntropy3, es3, (CRYPT_EAL_EntropyGet)ErrorGetEsEntropy};
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolAddEs(pool, &esPara3) == CRYPT_SUCCESS);
    ctx = EAL_EntropyNewCtx(pool, true, (uint32_t)minL, (uint32_t)maxL, (uint32_t)entropyL);
    ASSERT_TRUE(ctx != NULL);
    if (isCreateNullPool && minL != maxL) {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SEED_POOL_NO_ENTROPY_OBTAINED);
    } else if (isCreateNullPool) {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT);
    } else {
        ASSERT_TRUE(EAL_EntropyCollection(pool, ctx) == CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_EsFree(es1);
    CRYPT_EAL_EsFree(es2);
    CRYPT_EAL_EsFree(es3);
    return;
#else
    (void)isCreateNullPool;
    (void)isPhysical;
    (void)minEntropy1;
    (void)minEntropy2;
    (void)minEntropy3;
    (void)minL;
    (void)maxL;
    (void)entropyL;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_HIRES_TICK_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* The measurement counter must be live: every read advances on x86 rdtsc,
       while a 24 MHz aarch64 generic timer yields only ~15 advances per 1000
       pipelined reads. Require liveness and forward progress, and effectively
       no backwards steps. */
    uint64_t first = BSL_SAL_TIME_GetNSec();
    uint64_t prev = first;
    uint32_t advanced = 0;
    uint32_t regressed = 0;
    for (uint32_t i = 0; i < 1000; i++) {
        uint64_t now = BSL_SAL_TIME_GetNSec();
        if (now > prev) {
            advanced++;
        } else if (now < prev) {
            regressed++;
        }
        prev = now;
    }
    ASSERT_TRUE(advanced >= 5);
    ASSERT_TRUE(prev > first);
    ASSERT_TRUE(regressed <= 10);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_POOL_GATHER_DRAIN_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* Pool byte flow: the NTG.1.4 startup seed leaves exactly one CF output
       block banked at init, and reads drain it byte for byte. Every pooled
       byte is full entropy by the out*8+64 gather rule, so byte count is the
       entropy accounting. */
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    uint32_t cur = 0;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, &cur, sizeof(uint32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(cur, 32);
    uint8_t buf[8] = {0};
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, buf, sizeof(buf)), 8);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, &cur, sizeof(uint32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(cur, 32 - 8);
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_RAW_OUTPUT_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    ES_DeltaNs e = {0};
    ES_DeltaNsOsrApply(&e, 3);
    e.apt.cutoff = UINT32_MAX;
    EntropyRawMeasureCtx ctx = {&e, 0, 0};
    uint8_t out[4 * NS_DELTA_RECORD_BYTES] = {0};
    static const uint8_t expected[4 * NS_DELTA_RECORD_BYTES] = {
        14, 0, 0, 0, 0, 0, 0, 0,
        22, 0, 0, 0, 0, 0, 0, 0,
        36, 0, 0, 0, 0, 0, 0, 0,
        58, 0, 0, 0, 0, 0, 0, 0,
    };

    ASSERT_EQ(ES_DeltaNsRead(&e, EntropyMeasureRaw, &ctx, out, NS_DELTA_RECORD_BYTES / 2),
        CRYPT_ENTROPY_CTRL_INVALID_PARAM);
    ASSERT_EQ(ES_DeltaNsRead(&e, EntropyMeasureRaw, &ctx, out, sizeof(out)), CRYPT_SUCCESS);
    ASSERT_EQ(ctx.count, 4);
    ASSERT_TRUE(memcmp(out, expected, sizeof(out)) == 0);
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_RAW_HEALTH_DOMAIN_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    ES_DeltaNs e = {0};
    ES_DeltaNsOsrApply(&e, 3);
    e.stuckCutoff = UINT32_MAX;
    e.apt.cutoff = 5;
    /* Distinct 64-bit deltas that share one low byte are the degradation the
       byte-domain APT exists to catch: the assessed symbol has collapsed onto
       a single residue even though the full-width values still differ. */
    for (uint64_t i = 0; i < 4; i++) {
        uint64_t raw = 0x5A + 256 * (i + 1) * (i + 2) / 2;
        ES_DeltaNsProcessRawDelta(&e, raw);
        ASSERT_EQ(e.testFailure, CRYPT_SUCCESS);
    }
    ES_DeltaNsProcessRawDelta(&e, 0x5A + 256 * 15);
    ASSERT_EQ(e.testFailure, NS_ENTROPY_APT_FAILURE);

    /* RCT on its own, with APT and the stuck run silenced: deltas differing
       only above the low byte are a repetition run in the assessed domain.
       An implementation that projected for APT alone would stay quiet here. */
    ES_DeltaNs r = {0};
    ES_DeltaNsOsrApply(&r, 3);
    r.stuckCutoff = UINT32_MAX;
    r.apt.cutoff = UINT32_MAX;
    r.rct.cutoff = 5;
    for (uint64_t i = 0; i < 4; i++) {
        ES_DeltaNsProcessRawDelta(&r, 0x33 + 256 * (i + 1));
        ASSERT_EQ(r.testFailure, CRYPT_SUCCESS);
    }
    ES_DeltaNsProcessRawDelta(&r, 0x33 + 256 * 9);
    ASSERT_EQ(r.testFailure, NS_ENTROPY_RCT_FAILURE);

    /* Low bytes that keep changing leave the assessed-domain tests idle while
       the full-width stuck predicate still sees every delta: a constant stride
       is a second-difference zero, and the stuck run latches the intermittent
       RCT verdict that suspends the source pending recovery. */
    ES_DeltaNs s = {0};
    ES_DeltaNsOsrApply(&s, 3);
    s.apt.cutoff = UINT32_MAX;
    s.rct.cutoff = UINT32_MAX;
    for (uint32_t i = 0; i < s.stuckCutoff + 2U; i++) {
        ES_DeltaNsProcessRawDelta(&s, 0x100 + i);
    }
    ASSERT_EQ(s.testFailure, NS_ENTROPY_RCT_FAILURE);

    /* The conditioner still absorbs the whole 64-bit delta: the emitted record
       is its little-endian serialization, not the tested 8-bit symbol. */
    ES_DeltaNs w = {0};
    ES_DeltaNsOsrApply(&w, 3);
    w.stuckCutoff = UINT32_MAX;
    w.apt.cutoff = UINT32_MAX;
    w.rct.cutoff = UINT32_MAX;
    uint8_t rec[NS_DELTA_RECORD_BYTES] = {0};
    static const uint8_t wantRec[NS_DELTA_RECORD_BYTES] = {
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11};
    ASSERT_EQ(ES_DeltaNsRead(&w, EntropyMeasureFixedWide, &w, rec, sizeof(rec)), CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(rec, wantRec, sizeof(rec)) == 0);

    /* Identical raw deltas reach the APT cutoff; StartupReset clears run
       state only, the phase-1 configuration persists. */
    ES_DeltaNsStartupReset(&e);
    for (uint32_t i = 0; i < 4; i++) {
        ES_DeltaNsProcessRawDelta(&e, 0x5A);
        ASSERT_EQ(e.testFailure, CRYPT_SUCCESS);
    }
    ES_DeltaNsProcessRawDelta(&e, 0x5A);
    ASSERT_EQ(e.testFailure, NS_ENTROPY_APT_FAILURE);
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_BUILTIN_RAW_CREDIT_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    ES_NoiseSource *jitter = NULL;
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    ES_NoiseSource *hashLoop = NULL;
#endif
    CRYPT_EAL_Es *es = NULL;
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    jitter = ES_CpuJitterGetCtx();
    ASSERT_TRUE(jitter != NULL);
    ASSERT_EQ(jitter->claimBitsPerOsr, 1);
    ASSERT_EQ(jitter->sampleBytes, NS_DELTA_RECORD_BYTES);
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    hashLoop = ES_HashLoopGetCtx();
    ASSERT_TRUE(hashLoop != NULL);
    ASSERT_EQ(hashLoop->claimBitsPerOsr, 1);
    ASSERT_EQ(hashLoop->sampleBytes, NS_DELTA_RECORD_BYTES);
#endif
    es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9), CRYPT_SUCCESS);
#endif
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(uintptr_t)"sha256_df",
        strlen("sha256_df")), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_LOG_CALLBACK, (void *)EntropyReadCountLog, 0),
        CRYPT_SUCCESS);
    g_entropyReadLogCalls = 0;
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    ASSERT_TRUE(g_entropyReadLogCalls >= 320 * NS_DELTA_OSR_MIN);
    ASSERT_TRUE(g_entropyReadLogCalls <= 320 * NS_DELTA_OSR_MAX);
EXIT:
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    FreeNoiseSource(hashLoop);
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    FreeNoiseSource(jitter);
#endif
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
typedef struct {
    const uint64_t *v;
    uint32_t i;
} TimerSampleCursor;

static uint64_t TimerSampleNext(void *ctx)
{
    TimerSampleCursor *c = (TimerSampleCursor *)ctx;
    return c->v[c->i++];
}
#endif

#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
static uint64_t TimerVariedNext(void *ctx)
{
    uint32_t *i = (uint32_t *)ctx;
    return 168 + ((*i)++ % 7) * 21;
}
#endif

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_ENGINE_GUARDS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Entry guards of the shared delta engine: a record-misaligned read, an
       out-of-range osr latched by the ladder, and a timer check that fails
       before the cutoffs are armed. */
    ES_DeltaNs e = {0};
    EntropyRawMeasureCtx ctx = {&e, 0, 0};
    uint8_t out[NS_DELTA_RECORD_BYTES] = {0};

    ES_DeltaNsOsrApply(&e, NS_DELTA_OSR_MIN);
    e.apt.cutoff = UINT32_MAX;
    ASSERT_EQ(ES_DeltaNsRead(&e, EntropyMeasureRaw, &ctx, out, 0), CRYPT_ENTROPY_CTRL_INVALID_PARAM);
    ASSERT_EQ(ES_DeltaNsRead(&e, EntropyMeasureRaw, &ctx, out, NS_DELTA_RECORD_BYTES + 1),
        CRYPT_ENTROPY_CTRL_INVALID_PARAM);
    ASSERT_EQ(ctx.count, 0);

    /* An osr past the ladder latches inside OsrApply, so the soak never runs. */
    ES_DeltaNs bad = {0};
    ASSERT_TRUE(ES_DeltaNsTryOsr(&bad, NS_DELTA_OSR_MAX + 1, EntropyMeasureRaw, &ctx) != CRYPT_SUCCESS);
    ASSERT_TRUE(bad.testFailure != CRYPT_SUCCESS);
    ASSERT_EQ(ctx.count, 0);

    /* A zero delta is a coarse timer: qualification returns before arming. */
    ES_DeltaNs cold = {0};
    static const uint64_t zeroFirst[] = {0};
    TimerSampleCursor cur = {zeroFirst, 0};
    ASSERT_EQ(ES_DeltaNsTimerQualify(&cold, TimerSampleNext, &cur, NS_DELTA_OSR_MIN),
        CRYPT_ENTROPY_ES_COARSE_TIMER);
    ASSERT_EQ(cold.stuckCutoff, 0);
    (void)TestErrClear();
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_HEALTH_TimerQualifyRange(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* An out-of-range osr must surface as a failure return, never latch
       silently behind CRYPT_SUCCESS; an in-range osr arms the cutoffs. */
    ES_DeltaNs bad = {0};
    uint32_t n = 0;
    ASSERT_TRUE(ES_DeltaNsTimerQualify(&bad, TimerVariedNext, &n, NS_DELTA_OSR_MAX + 1) !=
        CRYPT_SUCCESS);
    ASSERT_TRUE(bad.testFailure != CRYPT_SUCCESS);
    ES_DeltaNs good = {0};
    n = 0;
    ASSERT_EQ(ES_DeltaNsTimerQualify(&good, TimerVariedNext, &n, NS_DELTA_OSR_MIN), CRYPT_SUCCESS);
    ASSERT_EQ(good.stuckCutoff, 1 + 20 * NS_DELTA_OSR_MIN);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_HEALTH_TimerCheckGates(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    uint64_t fine[4] = {168, 84, 42, 126};
    uint64_t constant[4] = {500, 500, 500, 500};
    uint64_t sameLsb[4] = {263, 1031, 1543, 2823};
    TimerSampleCursor cur = {fine, 0};

    ASSERT_EQ(ES_DeltaTimerCheck(TimerSampleNext, &cur, 4, NS_DELTA_OSR_MIN), CRYPT_SUCCESS);
    ASSERT_EQ(ES_DeltaTimerCheck(TimerSampleNext, &cur, 0, NS_DELTA_OSR_MIN),
        CRYPT_ENTROPY_ES_DEAD_TIMER);
    /* Constant deltas: adjacent variation never reaches the h = 1/osr floor. */
    cur.v = constant;
    cur.i = 0;
    ASSERT_EQ(ES_DeltaTimerCheck(TimerSampleNext, &cur, 4, NS_DELTA_OSR_MIN),
        CRYPT_ENTROPY_ES_COARSE_TIMER);
    /* Distinct deltas sharing one low byte pin the assessment symbol. */
    cur.v = sameLsb;
    cur.i = 0;
    ASSERT_EQ(ES_DeltaTimerCheck(TimerSampleNext, &cur, 4, NS_DELTA_OSR_MIN),
        CRYPT_ENTROPY_ES_COARSE_TIMER);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_HEALTH_TimerCheckDefects(int defect)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    uint64_t zeroDelta[4] = {84, 0, 126, 168};
    uint64_t lowVariation[4] = {42, 43, 43, 43};
    uint64_t boundaryVariation[4] = {42, 43, 43, 44};
    TimerSampleCursor cur = {defect == 0 ? zeroDelta : lowVariation, 0};
    int32_t ret;

    ret = ES_DeltaTimerCheck(TimerSampleNext, &cur, 4, NS_DELTA_OSR_MIN);
    ASSERT_EQ(ret, CRYPT_ENTROPY_ES_COARSE_TIMER);
    if (defect != 0) {
        cur.v = boundaryVariation;
        cur.i = 0;
        ret = ES_DeltaTimerCheck(TimerSampleNext, &cur, 4, NS_DELTA_OSR_MIN);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }
EXIT:
    return;
#else
    (void)defect;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_POOL_PushBound_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    ES_EntropyPool *pool = ES_EntropyPoolInit(512);
    uint8_t block[64];
    uint8_t out[512] = {0};
    ASSERT_TRUE(pool != NULL);
    for (uint32_t i = 0; i < sizeof(block); i++) {
        block[i] = (uint8_t)i;
    }
    for (uint32_t i = 0; i < 448 / 64; i++) {
        ASSERT_EQ(ES_EntropyPoolPushBytes(pool, block, sizeof(block)), CRYPT_SUCCESS);
    }
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 448);
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, out, 65), CRYPT_ENTROPY_ES_POOL_INSUFFICIENT);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 448);
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, block, sizeof(block)), CRYPT_SUCCESS);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 512);
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, block, 1), CRYPT_ENTROPY_ES_POOL_INSUFFICIENT);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 512);
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, sizeof(out)), 512);
    for (uint32_t i = 0; i < sizeof(out); i++) {
        ASSERT_EQ(out[i], i % sizeof(block));
    }
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 0);
EXIT:
    ES_EntropyPoolDeInit(pool);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_ENTROPY_SYS
/* Every ring slot outside [front, rear) must hold zero: the pool wipes each
   segment it hands out, so only undelivered bytes may be non-zero. */
static int EntropyPoolConsumedIsZero(const ES_EntropyPool *pool)
{
    for (uint32_t i = 0; i < pool->maxSize; i++) {
        bool live = (pool->front <= pool->rear) ? (i >= pool->front && i < pool->rear)
                                                : (i >= pool->front || i < pool->rear);
        if (!live && pool->buf[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void EntropyPoolFill(uint8_t *buf, uint32_t len, uint8_t seed)
{
    for (uint32_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + i);
    }
}
#endif

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_RETIRE_WIPES_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* A permanent verdict drops the retained raw deltas: a retired source holds
       no timestamp material until its instance is freed. */
    ES_DeltaNs e = {0};
    ES_DeltaNsOsrApply(&e, NS_DELTA_OSR_MIN);
    ASSERT_TRUE(e.rctPermCutoff > 0);

    /* Distinct 64-bit deltas sharing one low byte: the assessed symbol stays
       constant so RCT climbs to its permanent tier, while the raw values keep
       changing so no retained field is zero by construction. */
    for (uint32_t i = 0; i + 1 < e.rctPermCutoff; i++) {
        ES_DeltaNsProcessRawDelta(&e, 0x5AULL + 256ULL * ((uint64_t)(i + 1) * (i + 2) / 2));
    }
    ASSERT_TRUE(e.testFailure != NS_ENTROPY_PERMANENT_FAILURE);
    ASSERT_TRUE(e.lastDelta != 0);
    ASSERT_TRUE(e.lastDelta2 != 0);
    ASSERT_TRUE(e.rct.lastData != 0);
    ASSERT_TRUE(e.apt.base != 0);

    /* The next identical symbol reaches the permanent tier. */
    ES_DeltaNsProcessRawDelta(&e, 0x5AULL + 256ULL * 100000ULL);
    ASSERT_EQ(e.testFailure, NS_ENTROPY_PERMANENT_FAILURE);
    ASSERT_EQ(e.lastDelta, 0);
    ASSERT_EQ(e.lastDelta2, 0);
    ASSERT_EQ(e.rct.lastData, 0);
    ASSERT_EQ(e.apt.base, 0);
    (void)TestErrClear();
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_POOL_POP_WIPES_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    ES_EntropyPool *pool = NULL;
    uint8_t wide[60];
    uint8_t out[64] = {0};
    /* No wrap: one segment, front stays below rear the whole time. */
    pool = ES_EntropyPoolInit(64);
    ASSERT_TRUE(pool != NULL);
    EntropyPoolFill(wide, 16, 0x10);
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, wide, 16), CRYPT_SUCCESS);
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, 4), 4);
    ASSERT_EQ(out[0], 0x10);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 12);
    ASSERT_TRUE(EntropyPoolConsumedIsZero(pool));
    /* Undelivered bytes survive the wipe of the delivered prefix. */
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, 12), 12);
    ASSERT_EQ(out[0], 0x14);
    ASSERT_EQ(out[11], 0x1f);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 0);
    ASSERT_TRUE(EntropyPoolConsumedIsZero(pool));
EXIT:
    ES_EntropyPoolDeInit(pool);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_POOL_POP_WIPES_TC002(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    ES_EntropyPool *pool = NULL;
    uint8_t wide[60];
    uint8_t out[64] = {0};
    /* Delivery ends exactly on the physical ring end: one segment reaching the
       last slot, front wrapping to zero, no second segment. */
    pool = ES_EntropyPoolInit(64);
    ASSERT_TRUE(pool != NULL);
    EntropyPoolFill(wide, 60, 0x20);
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, wide, 60), CRYPT_SUCCESS);
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, 10), 10);
    EntropyPoolFill(wide, 10, 0x70);
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, wide, 10), CRYPT_SUCCESS);
    ASSERT_EQ(pool->front, 10);
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, 55), 55);
    ASSERT_EQ(pool->front, 0);
    ASSERT_TRUE(EntropyPoolConsumedIsZero(pool));
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, 5), 5);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 0);
    ASSERT_TRUE(EntropyPoolConsumedIsZero(pool));
EXIT:
    ES_EntropyPoolDeInit(pool);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_POOL_POP_WIPES_TC003(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    ES_EntropyPool *pool = NULL;
    uint8_t wide[60];
    uint8_t out[64] = {0};
    /* Wrapped delivery: front near the ring end, rear past the seam, so one
       pop spans two segments and both must be wiped. */
    pool = ES_EntropyPoolInit(64);
    ASSERT_TRUE(pool != NULL);
    EntropyPoolFill(wide, 60, 0x40);
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, wide, 60), CRYPT_SUCCESS);
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, 55), 55);
    ASSERT_TRUE(EntropyPoolConsumedIsZero(pool));
    EntropyPoolFill(wide, 40, 0x80);
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, wide, 40), CRYPT_SUCCESS);
    ASSERT_TRUE(pool->front > pool->rear);
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, 20), 20);
    /* Segment one is the tail of the first fill, segment two the head of the
       second: the seam must not reorder or drop a byte. */
    ASSERT_EQ(out[0], 0x77);
    ASSERT_EQ(out[4], 0x7b);
    ASSERT_EQ(out[5], 0x80);
    ASSERT_EQ(out[10], 0x85);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 25);
    ASSERT_TRUE(EntropyPoolConsumedIsZero(pool));
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, 25), 25);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 0);
    ASSERT_TRUE(EntropyPoolConsumedIsZero(pool));
EXIT:
    ES_EntropyPoolDeInit(pool);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_POOL_POP_WIPES_TC004(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    ES_EntropyPool *pool = NULL;
    uint8_t wide[60];
    uint8_t out[64] = {0};
    /* Short read: the request exceeds what the pool holds. */
    pool = ES_EntropyPoolInit(64);
    ASSERT_TRUE(pool != NULL);
    EntropyPoolFill(wide, 8, 0xc0);
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, wide, 8), CRYPT_SUCCESS);
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, sizeof(out)), 8);
    ASSERT_EQ(out[0], 0xc0);
    ASSERT_EQ(out[7], 0xc7);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 0);
    ASSERT_TRUE(EntropyPoolConsumedIsZero(pool));
EXIT:
    ES_EntropyPoolDeInit(pool);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_POOL_PopWrap_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    ES_EntropyPool *pool = ES_EntropyPoolInit(512);
    uint8_t sink[500] = {0};
    uint8_t src[100];
    uint8_t out[100] = {0};
    ASSERT_TRUE(pool != NULL);
    for (uint32_t i = 0; i < sizeof(src); i++) {
        src[i] = (uint8_t)i;
    }
    /* Drive front off zero so a later pop straddles the ring end: fill then drain
       500 bytes (front -> 500), then push 100 that wraps rear (13 at tail, 87 at head). */
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, sink, sizeof(sink)), CRYPT_SUCCESS);
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, sink, sizeof(sink)), 500);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 0);
    ASSERT_EQ(ES_EntropyPoolPushBytes(pool, src, sizeof(src)), CRYPT_SUCCESS);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 100);
    /* Cross-boundary read: partA = 13 from the tail, partB = 87 from the head. */
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, sizeof(out)), 100);
    for (uint32_t i = 0; i < sizeof(out); i++) {
        ASSERT_EQ(out[i], (uint8_t)i);
    }
    ASSERT_EQ(ES_EntropyPoolGetCurSize(pool), 0);
EXIT:
    ES_EntropyPoolDeInit(pool);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

#if defined(HITLS_CRYPTO_ENTROPY_HARDWARE) && \
    (defined(__x86_64__) || (defined(__aarch64__) && defined(__linux__)))
#include "entropy_seed_pool.h"
#endif
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_HW_ENTROPY_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_HARDWARE) && \
    (defined(__x86_64__) || (defined(__aarch64__) && defined(__linux__)))
    /* Probe the hardware DRNG leaf directly to learn whether this CPU provides
       it, then require the sole-source pool's public GetEntropy to agree with
       that ground truth. */
    uint8_t probe[32] = {0};
    uint32_t hwBytes = ENTROPY_HWEntropyGet(NULL, probe, sizeof(probe));
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    CRYPT_Data entropy = {0};
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara hwEs = {true, 8, NULL, (CRYPT_EAL_EntropyGet)ENTROPY_HWEntropyGet};
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(pool, &hwEs), CRYPT_SUCCESS);
    CRYPT_Range range = {16, 32};
    int32_t ret = CRYPT_EAL_SeedPoolGetEntropy(pool, &entropy, 128, &range);
    if (hwBytes > 0) {
        /* The DRNG delivers, so the sole-source pool must produce full entropy;
           a NO_ENTROPY here would mean a broken credit/collection path. */
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_TRUE(entropy.data != NULL);
        ASSERT_EQ(entropy.len, 16);
    } else {
        /* The DRNG yielded nothing (absent, or retry budget exhausted), so the
           sole-source pool reports none. */
        ASSERT_EQ(ret, CRYPT_SEED_POOL_NO_ENTROPY_OBTAINED);
        (void)TestErrClear();
    }
EXIT:
    BSL_SAL_Free(entropy.data);
    CRYPT_EAL_SeedPoolFree(pool);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_JITTER_RegionBytes_TC001(int l1dBytes, int expectBytes)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)
    /* HITLS_JITTER_MEM_BYTES is a lib-side CFLAGS knob that build_sdv.sh does
       not replay into this TU (macros.txt carries feature macros only), so
       detect pinning at runtime: the pinned policy curve is flat, the
       adaptive one is not. */
    if (ES_CpuJitterRegionBytes(0) == ES_CpuJitterRegionBytes(256U * 1024U)) {
        SKIP_TEST();
    }
    ASSERT_EQ(ES_CpuJitterRegionBytes((uint32_t)l1dBytes), (uint32_t)expectBytes);
EXIT:
    return;
#else
    (void)l1dBytes;
    (void)expectBytes;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_JITTER_L1dCacheClamp_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && \
    defined(_SC_LEVEL1_DCACHE_SIZE) && !defined(HITLS_BSL_SAL_DARWIN) && (LONG_MAX > UINT32_MAX)
    gEntropySysconfValue = (long)UINT32_MAX + 1L;
    STUB_REPLACE(sysconf, EntropySysconfStub);
    /* JitterStateNew passes this value to ES_CpuJitterRegionBytes, which caps the actual region size. */
    ASSERT_EQ(ES_CpuJitterL1dCacheSize(), UINT32_MAX);
EXIT:
    STUB_RESTORE(sysconf);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_HEALTH_OsrCutoffs(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* h = 1/osr: RCT = 1 + 20*osr; APT count model = 1 + Bin(511, 2^(-1/osr))
       (the base sample matches itself, SP800-90B comment #10b correction);
       every APT entry stays below the 512-sample window. */
    const uint32_t rct[15] = {21, 41, 61, 81, 101, 121, 141, 161,
                              181, 201, 221, 241, 261, 281, 301};
    const uint32_t apt[15] = {311, 411, 449, 468, 480, 488, 493, 497,
                              500, 502, 504, 505, 507, 508, 508};
    ES_DeltaCutoffs cutoffs = {0};
    for (uint32_t osr = 1; osr <= 15; osr++) {
        ASSERT_EQ(ES_DeltaOsrCutoffs(osr, &cutoffs), CRYPT_SUCCESS);
        ASSERT_EQ(cutoffs.rctCutoff, rct[osr - 1]);
        ASSERT_EQ(cutoffs.aptCutoff, apt[osr - 1]);
        ASSERT_TRUE(cutoffs.aptCutoff < 512);
    }
    ASSERT_TRUE(ES_DeltaOsrCutoffs(0, &cutoffs) != CRYPT_SUCCESS);
    ASSERT_TRUE(ES_DeltaOsrCutoffs(16, &cutoffs) != CRYPT_SUCCESS);
    ASSERT_TRUE(ES_DeltaOsrCutoffs(3, NULL) != CRYPT_SUCCESS);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_JITTER_OsrHealthy_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)
    /* A healthy stream passes at the start rate on the first rung of the
       walk, so the settled osr equals the start rate. */
    ES_NoiseSource *ns = ES_CpuJitterGetCtx();
    ASSERT_TRUE(ns != NULL);
    uint32_t start = ns->osr;
    ASSERT_TRUE(ns->initAt(ns->para, ns->osr, &ns->usrdata) == CRYPT_SUCCESS);
    ASSERT_TRUE(ns->usrdata != NULL);
    ASSERT_EQ(ns->osrGet(ns->usrdata), start);
EXIT:
    FreeNoiseSource(ns);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_ENTROPY_ES_STARTUP_GATE_FUNC_TC001
* @spec  -
* @title  AIS 20/31 NTG.1.4 startup gate: every credited source contributes at
*         least 240 bits of assessed min-entropy before the ES serves output.
* @precon  nan
* @prior  Level 1
* @auto  TRUE
* @brief
*    1. Build an ES with 8-bit and 1-bit credited sources, set the CF and init.
*       Expected result 1.
*    2. Count the 1-bit source reads. Expected result 2.
*    3. Read output immediately. Expected result 3.
* @expect
*    1. Init succeeds and runs the startup seeding gathers.
*    2. The 1-bit source is read exactly 320 times, satisfying the 240-bit
*       NTG.1.4 minimum.
*    3. The first read is served from the retained startup seed block
*       (NTG.1.4 seeding banks one CF block at init).
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_STARTUP_GATE_FUNC_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    uint8_t buf[64] = {0};
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(uintptr_t)"sha256_df",
        strlen("sha256_df")) == CRYPT_SUCCESS);
    ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
    CRYPT_EAL_NsPara fast = {
        "startup-fast", false, 8, {NULL, NULL, EntropyReadFastPoll, NULL}, {5, 200, 512}};
    CRYPT_EAL_NsPara slow = {
        "startup-slow", false, 1, {NULL, NULL, EntropyReadSeedPoll, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &fast, sizeof(fast)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &slow, sizeof(slow)), CRYPT_SUCCESS);
    g_entropyFastPollCalls = 0;
    g_entropySeedPollCalls = 0;
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    /* Startup quota per source is the conditioner need, 320 bit: 40 samples
       at 8 bit/sample, 320 at 1 bit/sample. */
    ASSERT_EQ(g_entropyFastPollCalls, 40);
    ASSERT_EQ(g_entropySeedPollCalls, 320);
    /* The startup seed block is retained in the pool, so the first read
       drains it without a fresh gather. */
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, buf, 32), 32);
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_PER_SOURCE_QUOTA_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(uintptr_t)"sha256_df",
        strlen("sha256_df")), CRYPT_SUCCESS);
    ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
    CRYPT_EAL_NsPara fast = {
        "quota-fast", false, 8, {NULL, NULL, EntropyReadFastPoll, NULL}, {5, 200, 512}};
    CRYPT_EAL_NsPara slow = {
        "quota-slow", false, 1, {NULL, NULL, EntropyReadSeedPoll, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &fast, sizeof(fast)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &slow, sizeof(slow)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    DrainStartupSeed(es);

    g_entropyFastPollCalls = 0;
    g_entropySeedPollCalls = 0;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    /* Each credited source funds the whole 320-bit need on its own: the fast
       source at 8 bit/sample needs 40, the slow one at 1 bit/sample needs 320.
       No share of the need is split between them. */
    ASSERT_EQ(g_entropyFastPollCalls, 40);
    ASSERT_EQ(g_entropySeedPollCalls, 320);
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_CF_DF_SEGMENTED_KAT_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    static const uint8_t expected[32] = {
        0x02, 0xe3, 0x95, 0x76, 0x1d, 0x8f, 0x52, 0xfc,
        0x3b, 0x30, 0x35, 0xe9, 0xac, 0x5b, 0xf7, 0x47,
        0x2c, 0xed, 0xd6, 0xd3, 0xc4, 0x98, 0x75, 0x0d,
        0x95, 0xa1, 0x36, 0x01, 0x48, 0x4d, 0x8e, 0x0f
    };
    const EAL_MdMethod *md = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    ES_CfMethod *cf = NULL;
    void *oneShot = NULL;
    void *segmented = NULL;
    uint8_t *oneShotOut = NULL;
    uint8_t *segmentedOut = NULL;
    uint32_t oneShotLen = 0;
    uint32_t segmentedLen = 0;
    uint8_t input[1025];

    ASSERT_TRUE(md != NULL);
    cf = ES_CFGetDfMethod((EAL_MdMethod *)(uintptr_t)md);
    ASSERT_TRUE(cf != NULL);
    oneShot = cf->init(&cf->meth.mdMeth);
    segmented = cf->init(&cf->meth.mdMeth);
    ASSERT_TRUE(oneShot != NULL);
    ASSERT_TRUE(segmented != NULL);
    for (uint32_t i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)i;
    }
    ASSERT_EQ(cf->update(oneShot, input, sizeof(input)), CRYPT_SUCCESS);
    ASSERT_EQ(cf->update(segmented, input, 1), CRYPT_SUCCESS);
    ASSERT_EQ(cf->update(segmented, input + 1, 1023), CRYPT_SUCCESS);
    ASSERT_EQ(cf->update(segmented, input + 1024, 1), CRYPT_SUCCESS);
    oneShotOut = cf->getEntropyData(oneShot, &oneShotLen);
    segmentedOut = cf->getEntropyData(segmented, &segmentedLen);
    ASSERT_TRUE(oneShotOut != NULL);
    ASSERT_TRUE(segmentedOut != NULL);
    ASSERT_EQ(oneShotLen, sizeof(expected));
    ASSERT_EQ(segmentedLen, sizeof(expected));
    ASSERT_TRUE(memcmp(oneShotOut, expected, sizeof(expected)) == 0);
    ASSERT_TRUE(memcmp(segmentedOut, expected, sizeof(expected)) == 0);
EXIT:
    BSL_SAL_ClearFree(oneShotOut, oneShotLen);
    BSL_SAL_ClearFree(segmentedOut, segmentedLen);
    if (cf != NULL) {
        cf->deinit(oneShot);
        cf->deinit(segmented);
    }
    BSL_SAL_Free(cf);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_STREAM_MEMORY_BOUND_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    char names[ES_NS_MAX_SIZE][16] = {{0}};
    bool mallocHooked = false;

    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(uintptr_t)"sha256_df",
        strlen("sha256_df")), CRYPT_SUCCESS);
    ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
    for (uint32_t i = 0; i < ES_NS_MAX_SIZE; i++) {
        ASSERT_TRUE(snprintf(names[i], sizeof(names[i]), "stream-%u", i) > 0);
        CRYPT_EAL_NsPara source = {
            names[i], false, i == 0 ? 1 : 0, {NULL, NULL, EntropyReadVaried, NULL}, {5, 200, 512}};
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &source, sizeof(source)), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    DrainStartupSeed(es);
    g_entropyMaxMallocSize = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocTrack), BSL_SUCCESS);
    mallocHooked = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_TRUE(g_entropyMaxMallocSize <= 4096);
EXIT:
    if (mallocHooked) {
        EntropyRestoreMalloc();
    }
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_GATHER_TRANSACTION_ISOLATION_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    char names[ES_NS_MAX_SIZE][16] = {{0}};
    uint8_t output[32] = {0};
    uint8_t reference[32] = {0};
    uint32_t poolSize = 0;
    uint32_t failedStreamPos = 0;
    bool mallocHooked = false;
    bool healthTest = false;

    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(uintptr_t)"sha256_df",
        strlen("sha256_df")), CRYPT_SUCCESS);
    ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(healthTest)), CRYPT_SUCCESS);
    for (uint32_t i = 0; i < ES_NS_MAX_SIZE; i++) {
        ASSERT_TRUE(snprintf(names[i], sizeof(names[i]), "txn-%u", i) > 0);
        CRYPT_EAL_NsPara source = {
            names[i], false, i == 0 ? 1 : 0, {NULL, NULL, EntropyReadStream, NULL}, {5, 200, 512}};
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &source, sizeof(source)), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    DrainStartupSeed(es);

    g_entropyStreamPos = 0;
    g_entropyFailOutputAlloc = true;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailOutput), BSL_SUCCESS);
    mallocHooked = true;
    int32_t ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0);
    EntropyRestoreMalloc();
    mallocHooked = false;
    ASSERT_EQ(ret, CRYPT_MEM_ALLOC_FAIL);
    ASSERT_TRUE(g_entropyStreamPos > 0);
    failedStreamPos = g_entropyStreamPos;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_POOL_GET_CURRSIZE, &poolSize, sizeof(poolSize)), CRYPT_SUCCESS);
    ASSERT_EQ(poolSize, 0);

    (void)TestErrClear();
    g_entropyStreamPos = 0;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    /* The discarded transaction consumed exactly as much of the deterministic
       stream as the successful one: no residue shifted the retry. */
    ASSERT_EQ(g_entropyStreamPos, failedStreamPos);
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, output, sizeof(output)), sizeof(output));

    /* Replaying the same stream from the same offset must reproduce the same
       conditioner output: the failed attempt left no state behind. Comparing
       two runs instead of a pinned digest keeps the invariant independent of
       the conditioner input ordering. */
    g_entropyStreamPos = 0;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(g_entropyStreamPos, failedStreamPos);
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, reference, sizeof(reference)), sizeof(reference));
    ASSERT_TRUE(memcmp(output, reference, sizeof(reference)) == 0);
EXIT:
    g_entropyFailOutputAlloc = false;
    if (mallocHooked) {
        EntropyRestoreMalloc();
    }
    CRYPT_EAL_EsFree(es);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_HEALTH_RctBoundary(int cutoff)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* Runs of cutoff - 1 identical samples stay clean; the cutoff-th must
       alarm; one differing sample restarts the run. */
    ES_RctState st = {0};
    st.cutoff = (uint32_t)cutoff;
    for (int i = 0; i < cutoff - 1; i++) {
        ASSERT_EQ(ES_HealthTestRct(&st, 0x55), CRYPT_SUCCESS);
    }
    ASSERT_EQ(ES_HealthTestRct(&st, 0x55), CRYPT_ENTROPY_RCT_FAILURE);
    ES_RctState br = {0};
    br.cutoff = (uint32_t)cutoff;
    for (int i = 0; i < cutoff - 1; i++) {
        ASSERT_EQ(ES_HealthTestRct(&br, 0x55), CRYPT_SUCCESS);
    }
    ASSERT_EQ(ES_HealthTestRct(&br, 0xAA), CRYPT_SUCCESS);
    for (int i = 0; i < cutoff - 1; i++) {
        ASSERT_EQ(ES_HealthTestRct(&br, 0x55), CRYPT_SUCCESS);
    }
EXIT:
    return;
#else
    (void)cutoff;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_HEALTH_AptBoundary(int cutoff, int window)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* The base value may repeat up to cutoff - 1 times inside one window; the
       cutoff-th occurrence must alarm; non-base samples never count. */
    ES_AptState st = {0};
    st.cutoff = (uint32_t)cutoff;
    st.windowSize = (uint32_t)window;
    ASSERT_EQ(ES_HealthTestApt(&st, 7), CRYPT_SUCCESS);
    for (int i = 0; i < cutoff - 2; i++) {
        ASSERT_EQ(ES_HealthTestApt(&st, 7), CRYPT_SUCCESS);
        ASSERT_EQ(ES_HealthTestApt(&st, (uint8_t)(100 + i)), CRYPT_SUCCESS);
    }
    ASSERT_EQ(ES_HealthTestApt(&st, 7), CRYPT_ENTROPY_APT_FAILURE);
    /* Window boundary: the window stays open through sample windowSize - 1,
       closes at windowSize, and base occurrences never cross windows. */
    ES_AptState w = {0};
    w.cutoff = (uint32_t)cutoff;
    w.windowSize = (uint32_t)window;
    ASSERT_EQ(ES_HealthTestApt(&w, 7), CRYPT_SUCCESS);
    /* Any symbol other than the base leaves the count untouched; the 8-bit
       alphabet cannot supply windowSize distinct fillers, and the assertion
       only needs the base to stay absent. */
    for (int i = 1; i < window - 1; i++) {
        ASSERT_EQ(ES_HealthTestApt(&w, 0xAA), CRYPT_SUCCESS);
    }
    ASSERT_EQ(w.baseSet, 1);
    ASSERT_EQ(ES_HealthTestApt(&w, 0xBB), CRYPT_SUCCESS);
    ASSERT_EQ(w.baseSet, 0);
    ASSERT_EQ(ES_HealthTestApt(&w, 9), CRYPT_SUCCESS);
    for (int i = 0; i < cutoff - 1; i++) {
        ASSERT_EQ(ES_HealthTestApt(&w, 7), CRYPT_SUCCESS);
    }
EXIT:
    return;
#else
    (void)cutoff;
    (void)window;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_STUCK_RUN_BOUNDARY_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Constant-difference deltas are stuck from the third sample on: the run
       must alarm exactly at the stuck cutoff, and one varied sample restarts
       the count. The APT cutoff is widened so the verdict can only come from
       the stuck run. */
    ES_DeltaNs e = {0};
    ES_DeltaNsOsrApply(&e, 3);
    e.apt.cutoff = 0x7FFFFFFF;
    uint32_t cutoff = e.stuckCutoff;
    ASSERT_TRUE(cutoff > 2);
    uint64_t v = 500;
    ES_DeltaNsProcessRawDelta(&e, v);
    v += 10;
    ES_DeltaNsProcessRawDelta(&e, v);
    v += 10;
    for (uint32_t i = 0; i < cutoff - 1; i++) {
        ES_DeltaNsProcessRawDelta(&e, v);
        v += 10;
        ASSERT_EQ(e.testFailure, 0);
    }
    ES_DeltaNsProcessRawDelta(&e, v);
    ASSERT_EQ(e.testFailure, NS_ENTROPY_RCT_FAILURE);
    ES_DeltaNs b = {0};
    ES_DeltaNsOsrApply(&b, 3);
    b.apt.cutoff = 0x7FFFFFFF;
    v = 500;
    ES_DeltaNsProcessRawDelta(&b, v);
    v += 10;
    ES_DeltaNsProcessRawDelta(&b, v);
    v += 10;
    for (uint32_t i = 0; i < cutoff - 1; i++) {
        ES_DeltaNsProcessRawDelta(&b, v);
        v += 10;
    }
    ASSERT_EQ(b.testFailure, 0);
    ES_DeltaNsProcessRawDelta(&b, v + 777);
    ASSERT_EQ(b.testFailure, 0);
    ASSERT_EQ(b.stuckCount, 0);
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    BSL_SAL_CleanseData(&b, sizeof(b));
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_STARTUP_RESET_REPRIME_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* StartupReset must clear every health run and prime flag so a fresh
       attempt needs its full run again. */
    ES_DeltaNs e = {0};
    ES_DeltaNsOsrApply(&e, 3);
    e.apt.cutoff = 0x7FFFFFFF;
    uint32_t cutoff = e.stuckCutoff;
    uint64_t v = 500;
    ES_DeltaNsProcessRawDelta(&e, v);
    v += 10;
    ES_DeltaNsProcessRawDelta(&e, v);
    v += 10;
    for (uint32_t i = 0; i < cutoff - 1; i++) {
        ES_DeltaNsProcessRawDelta(&e, v);
        v += 10;
    }
    ASSERT_EQ(e.testFailure, 0);
    ASSERT_TRUE(e.stuckCount == cutoff - 1);
    ASSERT_EQ(e.apt.baseSet, 1);
    ES_DeltaNsStartupReset(&e);
    ASSERT_EQ(e.stuckCount, 0);
    ASSERT_EQ(e.apt.baseSet, 0);
    ASSERT_EQ(e.apt.observed, 0);
    v = 500;
    ES_DeltaNsProcessRawDelta(&e, v);
    v += 10;
    ES_DeltaNsProcessRawDelta(&e, v);
    v += 10;
    for (uint32_t i = 0; i < cutoff - 1; i++) {
        ES_DeltaNsProcessRawDelta(&e, v);
        v += 10;
        ASSERT_EQ(e.testFailure, 0);
    }
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_HEALTH_RESET_ACROSS_CYCLES_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* A repetition run left dangling at the end of one init cycle must not
       leak into the next cycle's startup window. A bare single-source list
       makes the list-init verdict speak for this source alone (the built-in
       registry of ES_NsListCreat would mask its failure). */
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadTailRun, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    g_entropyTailRunPos = 0;
    ASSERT_EQ(ES_NsAdd(list, "tail-run", false, 5, &method, &para), CRYPT_SUCCESS);
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_SUCCESS);
    ES_NsListDeinit(list);
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_SUCCESS);
    ES_NsListDeinit(list);
EXIT:
    ES_NsListFree(list);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_VERDICT_PRIORITY_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* When one sample trips the stuck run and the APT at once, the first
       verdict (stuck RCT) must win and stay latched. */
    ES_DeltaNs e = {0};
    ES_DeltaNsOsrApply(&e, 3);
    e.lastDelta = 490;
    e.lastDelta2 = 10;
    e.stuckCount = e.stuckCutoff - 1;
    e.apt.baseSet = 1;
    e.apt.base = (uint8_t)500; /* the symbol the 500 delta below projects to */
    e.apt.count = e.apt.cutoff - 1;
    e.apt.observed = 5;
    ES_DeltaNsProcessRawDelta(&e, 500);
    ASSERT_EQ(e.testFailure, NS_ENTROPY_RCT_FAILURE);
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_OSR_WALK_ERRSTACK_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Candidate rungs rejected during the osr walk must not leave errors on
       the public stack after osr 3 fails APT and osr 4 succeeds. */
    (void)TestErrClear();
    ES_DeltaNs e = {0};
    EntropyAptTripCtx ctx = {&e, 0};
    ASSERT_EQ(ES_DeltaNsOsrWalk(&e, 3, 15, EntropyMeasureAptTrip, &ctx), CRYPT_SUCCESS);
    ASSERT_EQ(e.osr, 4);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_APT_RESET_HALF_WINDOW_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* An APT window left half open by a mid-window RCT abort must not leak
       into the next init cycle: cycle 2 reopens on the same base value and
       only passes when the window state was reset. */
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadAptHalfWin, NULL};
    CRYPT_EAL_NsTestPara para = {5, 8, 512};
    g_entropyHalfWinPos = 0;
    ASSERT_EQ(ES_NsAdd(list, "half-win", false, 5, &method, &para), CRYPT_SUCCESS);
    ASSERT_TRUE(ES_NsListInit(list, true) != CRYPT_SUCCESS);
    ES_NsListDeinit(list);
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_SUCCESS);
    ES_NsListDeinit(list);
    (void)TestErrClear();
EXIT:
    ES_NsListFree(list);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_STUCK_PREDICATES_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* The remaining stuck predicates alarm at the same run cutoff as the
       linear-ramp path: a frozen timer (delta == 0, stuck from the first
       sample), a constant non-zero delta (delta2 == 0, stuck from the second
       sample) and a zigzag (delta3 == 0 under absolute differences). The
       standard RCT and APT cutoffs are widened to isolate the supplementary
       stuck verdict. */
    ES_DeltaNs e = {0};
    ES_DeltaNsOsrApply(&e, 3);
    e.rct.cutoff = UINT32_MAX;
    e.apt.cutoff = 0x7FFFFFFF;
    uint32_t cutoff = e.stuckCutoff;
    for (uint32_t i = 0; i < cutoff - 1; i++) {
        ES_DeltaNsProcessRawDelta(&e, 0);
        ASSERT_EQ(e.testFailure, 0);
    }
    ES_DeltaNsProcessRawDelta(&e, 0);
    ASSERT_EQ(e.testFailure, NS_ENTROPY_RCT_FAILURE);

    ES_DeltaNs c = {0};
    ES_DeltaNsOsrApply(&c, 3);
    c.rct.cutoff = UINT32_MAX;
    c.apt.cutoff = 0x7FFFFFFF;
    ES_DeltaNsProcessRawDelta(&c, 500); /* priming sample: delta2 = 500, not stuck */
    ASSERT_EQ(c.testFailure, 0);
    for (uint32_t i = 0; i < cutoff - 1; i++) {
        ES_DeltaNsProcessRawDelta(&c, 500);
        ASSERT_EQ(c.testFailure, 0);
    }
    ES_DeltaNsProcessRawDelta(&c, 500);
    ASSERT_EQ(c.testFailure, NS_ENTROPY_RCT_FAILURE);

    /* Zigzag: the first differences alternate in sign with equal magnitude,
       so delta3 is zero only when the differences are compared by absolute
       value. Wrapping subtraction leaves delta3 near 2^64 and lets this
       period-2 alternation pass. */
    ES_DeltaNs z = {0};
    ES_DeltaNsOsrApply(&z, 3);
    z.rct.cutoff = UINT32_MAX;
    z.apt.cutoff = 0x7FFFFFFF;
    ES_DeltaNsProcessRawDelta(&z, 100);
    ES_DeltaNsProcessRawDelta(&z, 110); /* delta2 = 10, no delta3 history yet */
    for (uint32_t i = 0; i < cutoff - 1; i++) {
        ES_DeltaNsProcessRawDelta(&z, (i % 2 == 0) ? 100 : 110);
        ASSERT_EQ(z.testFailure, 0);
    }
    ES_DeltaNsProcessRawDelta(&z, (cutoff % 2 == 0) ? 110 : 100);
    ASSERT_EQ(z.testFailure, NS_ENTROPY_RCT_FAILURE);
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    BSL_SAL_CleanseData(&c, sizeof(c));
    BSL_SAL_CleanseData(&z, sizeof(z));
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_OSR_READBACK_RANGE_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* An adaptive instance that settles above osr 8 must still update the
       governance record. */
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadDiffData, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    ASSERT_EQ(ES_NsAdd(list, "osr-readback", false, 5, &method, &para), CRYPT_SUCCESS);
    ES_NoiseSource *ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ns->initAt = EntropyInitAtOsr12;
    ns->osrGet = EntropyOsrGet12;
    ns->osr = 3;
    ns->osrMax = 15;
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_SUCCESS);
    ASSERT_EQ(ns->osr, 12);
    ES_NsListDeinit(list);
    /* A readback above the instance ceiling is rejected. */
    ns->osr = 3;
    ns->osrMax = 8;
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_SUCCESS);
    ASSERT_EQ(ns->osr, 3);
    ES_NsListDeinit(list);
EXIT:
    ES_NsListFree(list);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_OSR_APPLY_INVALID_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* An out-of-range osr must latch a failure: zero cutoffs would otherwise
       silently disable the stuck run counter. */
    ES_DeltaNs e = {0};
    ES_DeltaNsOsrApply(&e, 0);
    ASSERT_EQ(e.testFailure, NS_ENTROPY_RCT_FAILURE);
    ES_DeltaNs f = {0};
    ES_DeltaNsOsrApply(&f, 16);
    ASSERT_EQ(f.testFailure, NS_ENTROPY_RCT_FAILURE);
    /* Validate-then-commit: a rejected osr must leave the previously
       committed configuration untouched. */
    ES_DeltaNs g = {0};
    ES_DeltaNsOsrApply(&g, 3);
    uint32_t committed = g.stuckCutoff;
    ASSERT_TRUE(committed > 0);
    ES_DeltaNsOsrApply(&g, 0);
    ASSERT_EQ(g.testFailure, NS_ENTROPY_RCT_FAILURE);
    ASSERT_EQ(g.stuckCutoff, committed);
    /* A latched verdict must refuse reads before taking another measurement. */
    uint8_t rb[1];
    g_entropyMeasureCount = 0;
    ASSERT_EQ(ES_DeltaNsRead(&e, EntropyMeasureCounted, &e, rb, sizeof(rb)), CRYPT_ENTROPY_RCT_FAILURE);
    ASSERT_EQ(g_entropyMeasureCount, 0);
    /* A startup reset clears the latch but must not resurrect the invalid
       configuration: the read gate still refuses an unconfigured engine. */
    ES_DeltaNsStartupReset(&e);
    ASSERT_EQ(e.testFailure, 0);
    ASSERT_EQ(ES_DeltaNsRead(&e, EntropyMeasureCounted, &e, rb, sizeof(rb)), CRYPT_ENTROPY_RCT_FAILURE);
    ASSERT_EQ(g_entropyMeasureCount, 0);
    ES_DeltaNs ok = {0};
    ES_DeltaNsOsrApply(&ok, 3);
    ASSERT_EQ(ok.testFailure, 0);
    (void)TestErrClear();
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_COND_FAULT_STRUCTURAL_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* A conditioning fault from an adaptive source is structural: the record
       is retired immediately instead of feeding the floor-failure streak. */
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadDiffData, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    ASSERT_EQ(ES_NsAdd(list, "cond-fault", false, 5, &method, &para), CRYPT_SUCCESS);
    ES_NoiseSource *ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ns->initAt = EntropyInitAtCondFail;
    ns->osr = 3;
    ns->osrMax = 15;
    ASSERT_TRUE(ES_NsListInit(list, true) != CRYPT_SUCCESS);
    ASSERT_EQ(ns->permanentFailure, true);
    ASSERT_EQ(ns->floorFailStreak, 0);
    (void)TestErrClear();
EXIT:
    ES_NsListFree(list);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_INIT_CALLER_MARK_SUCCESS_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {
        "mark-success", false, 8, {NULL, NULL, EntropyReadVaried, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(healthTest)), CRYPT_SUCCESS);

    uint8_t sentinel = 0;
    (void)TestErrClear();
    ASSERT_EQ(ENTROPY_EsEntropyGet(NULL, &sentinel, sizeof(sentinel)), 0);
    ASSERT_EQ(BSL_ERR_SetMark(), BSL_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_ERR_PopToMark(), BSL_SUCCESS);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_NULL_INPUT);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_INIT_CALLER_MARK_FAILURE_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {
        "mark-failure", false, 8, {NULL, NULL, EntropyReadWindowFail, NULL}, {5, 200, 512}};
    g_entropyWindowFailRet = CRYPT_ENTROPY_RCT_FAILURE;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(healthTest)), CRYPT_SUCCESS);

    uint8_t sentinel = 0;
    (void)TestErrClear();
    ASSERT_EQ(ENTROPY_EsEntropyGet(NULL, &sentinel, sizeof(sentinel)), 0);
    ASSERT_EQ(BSL_ERR_SetMark(), BSL_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_ENTROPY_RCT_FAILURE);
    ASSERT_EQ(BSL_ERR_PeekLastError(), CRYPT_ENTROPY_RCT_FAILURE);
    ASSERT_EQ(BSL_ERR_PopToMark(), BSL_SUCCESS);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_NULL_INPUT);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    g_entropyWindowFailRet = CRYPT_ENTROPY_RCT_FAILURE;
    CRYPT_EAL_EsFree(es);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_HEALTH_HELPER_STACK_TC001(int verdict)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    uint64_t coarse[3] = {1ULL << 31, 1ULL << 32, 3ULL << 31};
    ES_DeltaCutoffs cutoffs = {0};
    int32_t ret;
    int32_t expected;

    (void)TestErrClear();
    if (verdict == 0) {
        TimerSampleCursor cur = {NULL, 0};
        ret = ES_DeltaTimerCheck(TimerSampleNext, &cur, 0, NS_DELTA_OSR_MIN);
        expected = CRYPT_ENTROPY_ES_DEAD_TIMER;
    } else if (verdict == 1) {
        TimerSampleCursor cur = {coarse, 0};
        ret = ES_DeltaTimerCheck(TimerSampleNext, &cur, 3, NS_DELTA_OSR_MIN);
        expected = CRYPT_ENTROPY_ES_COARSE_TIMER;
    } else {
        ret = ES_DeltaOsrCutoffs(0, &cutoffs);
        expected = CRYPT_ENTROPY_CTRL_INVALID_PARAM;
    }
    ASSERT_EQ(ret, expected);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    (void)TestErrClear();
    return;
#else
    (void)verdict;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_COND_FAULT_NO_DEMOTE_LOOP_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* A conditioning fault reported by the startup window must not drive the
       adaptive demote loop: one startup read, then structural retirement. */
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadCondFail, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    g_entropyCondReadCalls = 0;
    ASSERT_EQ(ES_NsAdd(list, "cond-loop", false, 5, &method, &para), CRYPT_SUCCESS);
    ES_NoiseSource *ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ns->initAt = EntropyInitAtOsr12;
    ns->osr = 3;
    ns->osrMax = 15;
    ASSERT_TRUE(ES_NsListInit(list, true) != CRYPT_SUCCESS);
    ASSERT_EQ(g_entropyCondReadCalls, 1);
    ASSERT_EQ(ns->permanentFailure, true);
    (void)TestErrClear();
EXIT:
    ES_NsListFree(list);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_SEED_COND_FAULT_RETIRES_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* A conditioning fault reported during the startup-seed gather must
       retire the source permanently: after deinit + reinit the retired source
       is skipped, so its read callback sees no further traffic. */
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
    /* Zero-credit mixing source: the seed gather still polls it, but it does
       not join the per-source startup-bits ledger. */
    CRYPT_EAL_NsPara para = {"seed-fault", false, 0, {NULL, NULL, EntropyReadSeedFault, NULL}, {5, 200, 512}};
    g_entropySeedFaultPos = 0;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1), CRYPT_SUCCESS);
    (void)TestErrClear();
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    uint32_t posAfterInit = g_entropySeedFaultPos;
    ASSERT_TRUE(posAfterInit > 1024);
    /* Real deinit through the inner handle: the EAL surface has no deinit. */
    ENTROPY_EsDeinit(es->es);
    ASSERT_EQ(ENTROPY_EsInit(es->es), CRYPT_SUCCESS);
    ASSERT_EQ(g_entropySeedFaultPos, posAfterInit);
    /* Successful aggregate transactions leave no stale tolerated verdicts. */
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_STARTUP_COND_FAULT_RETIRES_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* Structural retirement is uniform across source kinds: an external
       source (no initAt) whose startup window reports a conditioning fault
       is retired permanently, exactly like an adaptive one. */
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadCondFail, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    g_entropyCondReadCalls = 0;
    ASSERT_EQ(ES_NsAdd(list, "ext-cond", false, 5, &method, &para), CRYPT_SUCCESS);
    ES_NoiseSource *ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ASSERT_TRUE(ES_NsListInit(list, true) != CRYPT_SUCCESS);
    ASSERT_EQ(ns->permanentFailure, true);
    (void)TestErrClear();
EXIT:
    ES_NsListFree(list);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_RECORD_GEOMETRY_TC001(int width, int expectOk)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* Record geometry is a construction-time contract: a nonzero width that
       divides the startup window; anything else is refused at source init. */
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadStream, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    ASSERT_EQ(ES_NsAdd(list, "geom", false, 5, &method, &para), CRYPT_SUCCESS);
    ES_NoiseSource *ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ns->sampleBytes = (uint32_t)width;
    g_entropyStreamPos = 0;
    if (expectOk != 0) {
        ASSERT_EQ(ES_NsListInit(list, true), CRYPT_SUCCESS);
    } else {
        ASSERT_TRUE(ES_NsListInit(list, true) != CRYPT_SUCCESS);
    }
    (void)TestErrClear();
EXIT:
    ES_NsListFree(list);
    return;
#else
    (void)width;
    (void)expectOk;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_RUNTIME_COND_FAULT_RETIRES_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* A conditioning fault first reported by the runtime gather must retire
       the source permanently: after deinit + reinit its read callback sees no
       further traffic. */
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {"runtime-fault", false, 0, {NULL, NULL, EntropyReadArmedFault, NULL}, {5, 200, 512}};
    g_entropyFaultArmed = 0;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    /* Arm the fault only after init, then drain the retained seed block so
       the next request forces a runtime gather that polls the source. */
    g_entropyCondReadCalls = 0;
    g_entropyFaultArmed = 1;
    uint8_t out[64];
    /* Caller-scope sentinel and mark: the quiet gather transactions must
       leave both untouched. */
    (void)TestErrClear();
    ASSERT_EQ(ENTROPY_EsEntropyGet(NULL, out, 1), 0);
    ASSERT_EQ(BSL_ERR_PeekLastError(), CRYPT_NULL_INPUT);
    ASSERT_EQ(BSL_ERR_SetMark(), BSL_SUCCESS);
    for (int i = 0; i < 64 && g_entropyCondReadCalls == 0; i++) {
        ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(es, out, sizeof(out)) > 0);
    }
    uint32_t armedCalls = g_entropyCondReadCalls;
    ASSERT_TRUE(armedCalls > 0);
    ASSERT_EQ(BSL_ERR_PeekLastError(), CRYPT_NULL_INPUT);
    ASSERT_EQ(BSL_ERR_PopToMark(), BSL_SUCCESS);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_NULL_INPUT);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ENTROPY_EsDeinit(es->es);
    ASSERT_EQ(ENTROPY_EsInit(es->es), CRYPT_SUCCESS);
    ASSERT_TRUE(ENTROPY_EsEntropyGet(es->es, out, sizeof(out)) > 0);
    /* The retired source saw no further traffic across the new cycle. */
    ASSERT_EQ(g_entropyCondReadCalls, armedCalls);
    /* Successful aggregate transactions leave no stale tolerated verdicts. */
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_DEINIT_NULL_GUARD_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* A permanently retired source keeps usrdata == NULL across later cycles;
       list deinit must never hand that NULL to the deinit callback. */
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod method = {NULL, EntropyLifeInit, EntropyReadCondFail, EntropyLifeDeinit};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    g_entropyDeinitNullCalls = 0;
    g_entropyCondReadCalls = 0;
    ASSERT_EQ(ES_NsAdd(list, "life-guard", false, 5, &method, &para), CRYPT_SUCCESS);
    ES_NoiseSource *ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ASSERT_TRUE(ES_NsListInit(list, true) != CRYPT_SUCCESS);
    ASSERT_EQ(ns->permanentFailure, true);
    ASSERT_TRUE(ES_NsListInit(list, true) != CRYPT_SUCCESS);
    ES_NsListDeinit(list);
    ASSERT_EQ(g_entropyDeinitNullCalls, 0);
    (void)TestErrClear();
EXIT:
    ES_NsListFree(list);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_SEED_AGGREGATE_GATE_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Every credited source funds the conditioner's full-entropy need on its
       own, so a single honest source suffices and no independence assumption
       between sources is needed. The companion below is credited at 1 bit per
       sample, giving it an exact 320-sample block alongside CPU-Jitter's. */
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9), CRYPT_SUCCESS);
#endif
    CRYPT_EAL_NsPara para = {"seed-poll", false, 1, {NULL, NULL, EntropyReadSeedPoll, NULL}, {5, 200, 512}};
    g_entropySeedPollCalls = 0;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1), CRYPT_SUCCESS);
    (void)TestErrClear();
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    /* 320-bit need at 1 bit per sample, drawn as one contiguous block. */
    ASSERT_EQ(g_entropySeedPollCalls, 320);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_DIRECT_GATHER_ERRSTACK_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* The direct gather entry shares the quiet-read transaction: a tolerated
       source failure leaves no verdict behind a successful gather, and a
       caller-scope mark survives it. */
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
    CRYPT_EAL_NsPara para = {"direct-fault", false, 0, {NULL, NULL, EntropyReadArmedFault, NULL}, {5, 200, 512}};
    g_entropyFaultArmed = 0;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    g_entropyCondReadCalls = 0;
    g_entropyFaultArmed = 1;
    uint8_t out[4];
    (void)TestErrClear();
    ASSERT_EQ(ENTROPY_EsEntropyGet(NULL, out, 1), 0);
    ASSERT_EQ(BSL_ERR_PeekLastError(), CRYPT_NULL_INPUT);
    ASSERT_EQ(BSL_ERR_SetMark(), BSL_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_TRUE(g_entropyCondReadCalls > 0);
    ASSERT_EQ(BSL_ERR_PeekLastError(), CRYPT_NULL_INPUT);
    ASSERT_EQ(BSL_ERR_PopToMark(), BSL_SUCCESS);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_NULL_INPUT);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    g_entropyFaultArmed = 0;
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_SEED_CREDITED_LOSS_FAILS_TC001(int failClass)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Every credited source is mandatory for the startup transaction. */
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9), CRYPT_SUCCESS);
#endif
    CRYPT_EAL_NsPara paraB = {"credit-b", false, 8, {NULL, NULL, EntropyReadCreditB, NULL}, {5, 200, 512}};
    CRYPT_EAL_NsPara paraPoll = {"seed-roundpoll", false, 0, {NULL, NULL, EntropyReadSeedPoll, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&paraB, sizeof(CRYPT_EAL_NsPara)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&paraPoll, sizeof(CRYPT_EAL_NsPara)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1), CRYPT_SUCCESS);
    bool observed = false;
    int32_t ret = CRYPT_SUCCESS;
    for (int32_t attempt = 0; attempt < 5 && !observed; attempt++) {
        g_entropyCreditBReads = 0;
        g_entropyCreditBFailAt = 11;
        g_entropyCreditBFailRet = failClass == 1 ? CRYPT_ENTROPY_RCT_FAILURE :
            (failClass == 2 ? CRYPT_DRBG_FAIL_GET_ENTROPY : CRYPT_ENTROPY_ES_NS_NOT_AVA);
        g_entropySeedPollCalls = 0;
        (void)TestErrClear();
        ret = ENTROPY_EsInit(es->es);
        observed = (g_entropyCreditBReads == 11 && g_entropySeedPollCalls == 0);
        if (!observed) {
            ENTROPY_EsDeinit(es->es);
        }
    }
    ASSERT_TRUE(observed);
    ASSERT_EQ(ret, CRYPT_ENTROPY_ES_NS_NOT_AVA);
    ASSERT_EQ(g_entropyCreditBReads, 11);
    /* Blocks are serial in registration order: the credited block aborts the
       transaction before the uncredited mix block is ever reached. */
    ASSERT_EQ(g_entropySeedPollCalls, 0);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_ES_NS_NOT_AVA);
    ASSERT_EQ(BSL_ERR_GetLastError(), g_entropyCreditBFailRet);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    g_entropyCreditBFailAt = 11;
    g_entropyCreditBFailRet = CRYPT_ENTROPY_RCT_FAILURE;
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)failClass;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_SEED_ERROR_PRECEDENCE_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9), CRYPT_SUCCESS);
#endif
    CRYPT_EAL_NsPara operational = {
        "operational", false, 0, {NULL, NULL, EntropyReadOperational, NULL}, {5, 200, 512}};
    CRYPT_EAL_NsPara health = {
        "health", false, 8, {NULL, NULL, EntropyReadCreditB, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &operational, sizeof(operational)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &health, sizeof(health)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(healthTest)), CRYPT_SUCCESS);
    bool observed = false;
    int32_t ret = CRYPT_SUCCESS;
    for (int32_t attempt = 0; attempt < 5 && !observed; attempt++) {
        g_entropyOperationalReads = 0;
        g_entropyCreditBReads = 0;
        g_entropyCreditBFailAt = 1;
        g_entropyCreditBFailRet = CRYPT_ENTROPY_RCT_FAILURE;
        (void)TestErrClear();
        ret = ENTROPY_EsInit(es->es);
        observed = (g_entropyOperationalReads == 1 && g_entropyCreditBReads == 1);
        if (!observed) {
            ENTROPY_EsDeinit(es->es);
        }
    }
    ASSERT_TRUE(observed);
    ASSERT_EQ(ret, CRYPT_ENTROPY_ES_NS_NOT_AVA);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_ES_NS_NOT_AVA);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_RCT_FAILURE);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    g_entropyCreditBFailAt = 11;
    g_entropyCreditBFailRet = CRYPT_ENTROPY_RCT_FAILURE;
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_GATHER_FAIL_STACK_ORDER_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    /* An all-failed gather reports top-down: the public gather verdict, the
       transaction boundary verdict, then the root per-source verdict. */
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10), CRYPT_SUCCESS);
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9), CRYPT_SUCCESS);
#endif
    CRYPT_EAL_NsPara para = {"credit-armed", false, 8, {NULL, NULL, EntropyReadCreditArmed, NULL}, {5, 200, 512}};
    g_entropyCreditArmed = 0;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1), CRYPT_SUCCESS);
    /* The explicit gather polls the armed credited source after startup. */
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    g_entropyCreditArmed = 1;
    (void)TestErrClear();
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_ES_NS_NOT_AVA);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_RCT_FAILURE);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    g_entropyCreditArmed = 0;
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_INIT_CREDITED_FAILURE_CLASS_TC001(int failClass)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Every credited source is mandatory for the initialization cycle. */
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9), CRYPT_SUCCESS);
#endif
    CRYPT_EAL_NsPara paraB = {"credit-b-init", false, 8, {NULL, NULL, EntropyReadWindowFail, NULL}, {5, 200, 512}};
    g_entropyWindowFailRet = failClass == 1 ? CRYPT_ENTROPY_RCT_FAILURE :
        (failClass == 2 ? CRYPT_DRBG_FAIL_GET_ENTROPY : CRYPT_ENTROPY_ES_NS_NOT_AVA);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&paraB, sizeof(CRYPT_EAL_NsPara)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1), CRYPT_SUCCESS);
    (void)TestErrClear();
    int32_t ret = ENTROPY_EsInit(es->es);
    ASSERT_EQ(ret, g_entropyWindowFailRet);
    ASSERT_EQ(BSL_ERR_GetLastError(), g_entropyWindowFailRet);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    g_entropyWindowFailRet = CRYPT_ENTROPY_RCT_FAILURE;
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)failClass;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_GATHER_CREDITED_FAILURE_CLASS_TC001(int failClass)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Every credited source is mandatory for the runtime transaction. */
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9), CRYPT_SUCCESS);
#endif
    CRYPT_EAL_NsPara paraB = {"credit-b", false, 8, {NULL, NULL, EntropyReadCreditB, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&paraB, sizeof(CRYPT_EAL_NsPara)), CRYPT_SUCCESS);
    bool healthTest = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1), CRYPT_SUCCESS);
    /* B survives startup and dies on its 11th runtime read. */
    int32_t ret = CRYPT_ENTROPY_ES_NS_NOT_AVA;
    for (int32_t attempt = 0; attempt < 5 && ret != CRYPT_SUCCESS; attempt++) {
        g_entropyCreditBReads = 0;
        g_entropyCreditBFailAt = UINT32_MAX;
        g_entropyCreditBFailRet = failClass == 1 ? CRYPT_ENTROPY_RCT_FAILURE :
            (failClass == 2 ? CRYPT_DRBG_FAIL_GET_ENTROPY : CRYPT_ENTROPY_ES_NS_NOT_AVA);
        (void)TestErrClear();
        ret = ENTROPY_EsInit(es->es);
        if (ret != CRYPT_SUCCESS) {
            ENTROPY_EsDeinit(es->es);
        }
    }
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint32_t failAt = g_entropyCreditBReads + 11;
    g_entropyCreditBFailAt = failAt;
    uint8_t out[64];
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, out, sizeof(out)), 32);
    (void)TestErrClear();
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, out, sizeof(out)), 0);
    ASSERT_EQ(g_entropyCreditBReads, failAt);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_ES_NS_NOT_AVA);
    ASSERT_EQ(BSL_ERR_GetLastError(), g_entropyCreditBFailRet);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, out, sizeof(out)), 0);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_ES_NS_NOT_AVA);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    g_entropyCreditBFailAt = 11;
    g_entropyCreditBFailRet = CRYPT_ENTROPY_RCT_FAILURE;
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)failClass;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_ZERO_CALLBACK_FALLBACK_TC001(void)
{
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    CRYPT_Data entropy = {0};
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara fallback = {true, 8, NULL, EntropyGetNormal};
    CRYPT_EAL_EsPara unavailable = {true, 8, NULL, EntropyGet0Normal};
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(pool, &fallback), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(pool, &unavailable), CRYPT_SUCCESS);
    CRYPT_Range range = {16, 32};
    (void)TestErrClear();
    ASSERT_EQ(CRYPT_EAL_SeedPoolGetEntropy(pool, &entropy, 128, &range), CRYPT_SUCCESS);
    ASSERT_TRUE(entropy.data != NULL);
    ASSERT_EQ(entropy.len, 16);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(entropy.data);
    CRYPT_EAL_SeedPoolFree(pool);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_ENTROPY_MAXLEN_OVERFLOW_TC001(void)
{
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    EAL_EntropyCtx *ctx = NULL;
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara para = {true, 8, NULL, EntropyGetNormal};
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(pool, &para), CRYPT_SUCCESS);
    uint32_t maxLen = UINT32_MAX / 8u + 1u;
    (void)TestErrClear();
    ctx = EAL_EntropyNewCtx(pool, true, 1, maxLen, 1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_SeedPoolFree(pool);
    (void)TestErrClear();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SEEDPOOL_CREDIT_SATURATION_TC001(void)
{
#if defined(__unix__) || defined(__APPLE__)
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    void *mapped = MAP_FAILED;
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara para = {true, 8, NULL, EntropyGetReportedLen};
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(pool, &para), CRYPT_SUCCESS);
    size_t mapLen = (size_t)(UINT32_MAX / 8u) + 1u;
    mapped = mmap(NULL, mapLen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    ASSERT_TRUE(mapped != MAP_FAILED);
    uint32_t len = (uint32_t)mapLen;
    ASSERT_EQ(ENTROPY_SeedPoolCollect(pool->pool, true, UINT32_MAX, mapped, &len), UINT32_MAX);
    ASSERT_EQ(len, (uint32_t)mapLen);
EXIT:
    if (mapped != MAP_FAILED) {
        (void)munmap(mapped, mapLen);
    }
    CRYPT_EAL_SeedPoolFree(pool);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_INIT_ERROR_PRIORITY_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod rct = {NULL, NULL, EntropyReadWindowFail, NULL};
    CRYPT_EAL_NsMethod structural = {NULL, NULL, EntropyReadNotAvail, NULL};
    CRYPT_EAL_NsMethod survivor = {NULL, NULL, EntropyReadVaried, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    g_entropyWindowFailRet = CRYPT_ENTROPY_RCT_FAILURE;
    ASSERT_EQ(ES_NsAdd(list, "priority-rct", false, 5, &rct, &para), CRYPT_SUCCESS);
    ASSERT_EQ(ES_NsAdd(list, "priority-structural", false, 5, &structural, &para), CRYPT_SUCCESS);
    ASSERT_EQ(ES_NsAdd(list, "priority-survivor", false, 5, &survivor, &para), CRYPT_SUCCESS);
    (void)TestErrClear();
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_ENTROPY_RCT_FAILURE);
EXIT:
    g_entropyWindowFailRet = CRYPT_ENTROPY_RCT_FAILURE;
    ES_NsListFree(list);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ------------------------------------------------------------------ */
/* dual-tier health verdicts and runtime recovery */
/* ------------------------------------------------------------------ */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_APT_WINDOW_TIERS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* The permanent tier is a single-window statistic: 479 base matches inside
       one 512-sample window reach it, but matches split across a window
       boundary must not accumulate past it (SP800-90B 4.4.2 fixes W). */
    const uint32_t aptCut = 449;
    const uint32_t aptPerm = 479;
    const uint32_t win = NS_APT_DELTA_WINDOW_SIZE;
    ES_AptState a = {0};
    a.cutoff = aptCut;
    a.windowSize = win;
    uint32_t maxA = 0;
    for (uint32_t i = 0; i < aptPerm; i++) {
        (void)ES_HealthTestApt(&a, 0x50);
        if (a.count > maxA) {
            maxA = a.count;
        }
    }
    ASSERT_TRUE(maxA >= aptPerm);
    ES_AptState b = {0};
    b.cutoff = aptCut;
    b.windowSize = win;
    uint32_t maxB = 0;
    for (uint32_t i = 0; i < 470; i++) {
        (void)ES_HealthTestApt(&b, 0x50);
        if (b.count > maxB) {
            maxB = b.count;
        }
    }
    for (uint32_t i = 0; i < 42; i++) {
        (void)ES_HealthTestApt(&b, 0x99);
    }
    for (uint32_t i = 0; i < 470; i++) {
        (void)ES_HealthTestApt(&b, 0x50);
        if (b.count > maxB) {
            maxB = b.count;
        }
    }
    ASSERT_TRUE(maxB < aptPerm);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_PERM_CUTOFF_TABLE_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    static const uint32_t aptPerm[15] = {355, 447, 479, 494, 502, 507, 510, 512, 512, 512, 512, 512, 512, 512, 512};
    ES_DeltaCutoffs cutoffs = {0};
    for (uint32_t osr = 1; osr <= 15; osr++) {
        ASSERT_EQ(ES_DeltaOsrCutoffs(osr, &cutoffs), CRYPT_SUCCESS);
        ASSERT_EQ(cutoffs.rctPermCutoff, 1 + 60 * osr);
        ASSERT_EQ(cutoffs.aptPermCutoff, aptPerm[osr - 1]);
        ASSERT_TRUE(cutoffs.rctPermCutoff > cutoffs.rctCutoff);
        /* permanent tier is armed at every osr (clamped to the window), always
           stricter than the intermittent cutoff and never above the window. */
        ASSERT_TRUE(cutoffs.aptPermCutoff > cutoffs.aptCutoff);
        ASSERT_TRUE(cutoffs.aptPermCutoff <= NS_APT_DELTA_WINDOW_SIZE);
    }
    ASSERT_EQ(ES_DeltaOsrCutoffs(0, &cutoffs), CRYPT_ENTROPY_CTRL_INVALID_PARAM);
    ASSERT_EQ(ES_DeltaOsrCutoffs(16, &cutoffs), CRYPT_ENTROPY_CTRL_INVALID_PARAM);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_APT_PERMANENT_TIER_TC001(int osr)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Drive the emitted-byte APT permanent tier in isolation (RCT and stuck
       disabled): osr 3 reaches the permanent bound mid-window (479); osr 9's
       bound is clamped to the 512 window, so a whole-window all-equal run still
       trips it at the last sample. Both retire. */
    ES_DeltaNs e = {0};
    e.osr = (uint32_t)osr;
    ES_DeltaNsOsrApply(&e, (uint32_t)osr);
    e.stuckCutoff = UINT32_MAX;
    e.rct.cutoff = UINT32_MAX;
    e.rctPermCutoff = UINT32_MAX;
    uint32_t fireAt = 0;
    for (uint32_t i = 0; i < NS_APT_DELTA_WINDOW_SIZE; i++) {
        ES_DeltaNsProcessRawDelta(&e, 0x50);
        fireAt = i + 1;
        if (e.testFailure == NS_ENTROPY_PERMANENT_FAILURE) {
            break;
        }
    }
    ASSERT_EQ(e.testFailure, NS_ENTROPY_PERMANENT_FAILURE);
    if (osr == 3) {
        ASSERT_EQ(fireAt, 479);
    } else {
        ASSERT_EQ(fireAt, NS_APT_DELTA_WINDOW_SIZE);
    }
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    return;
#else
    (void)osr;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_STUCK_TIER_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* The tailored stuck predicate (union over delta/delta2/delta3) raises only
       the intermittent alarm: a linear ramp is stuck on every sample yet its
       emitted bytes never repeat, so RCT/APT stay quiet. Even past the RCT
       permanent bound (181) the verdict must remain intermittent; persistent
       degradation is retired through repeated recovery, not an unproven
       2^-60 stuck cutoff. */
    ES_DeltaNs e = {0};
    e.osr = 3;
    ES_DeltaNsOsrApply(&e, 3);
    for (uint32_t i = 0; i < 2 * (1 + 60 * 3); i++) {
        ES_DeltaNsProcessRawDelta(&e, 0x1000 + i);
    }
    ASSERT_EQ(e.testFailure, NS_ENTROPY_RCT_FAILURE);
    ASSERT_TRUE(e.rct.count < e.rctPermCutoff);
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
typedef struct {
    ES_DeltaNs *e;
    uint32_t rawPos;
    uint32_t measPos;
    uint32_t mode; /* 0 varied; 1 run-below-permanent; 2 low-variation; 3 constant byte */
    uint64_t prng;
} EntropyRecScriptCtx;

static uint64_t EntropyRawRecScript(void *srcCtx)
{
    EntropyRecScriptCtx *c = (EntropyRecScriptCtx *)srcCtx;
    uint64_t d;
    if (c->mode == 2) {
        /* variation ~= 1024/60 < ceil(1024/osr) target -> COARSE_TIMER */
        d = 100 + c->rawPos / 60;
    } else if (c->mode == 4) {
        /* variation ~= 1024/10 = 102: passes ceil(1024/15)=69 but fails
           ceil(1024/3)=342, so recovery accepts it only if it (wrongly) used
           the settled osr 15 instead of the startup timerCheckOsr 3. */
        d = 100 + c->rawPos / 10;
    } else {
        /* consecutive values drive variation past the target */
        d = 100 + (c->rawPos % 200);
    }
    c->rawPos++;
    return d;
}

static void EntropyMeasureRecScript(void *srcCtx)
{
    EntropyRecScriptCtx *c = (EntropyRecScriptCtx *)srcCtx;
    uint64_t d;
    switch (c->mode) {
        case 0:
        case 5:
            /* non-linear varied stream: avoids the linear-ramp stuck predicate
               (constant first difference) while keeping bytes diverse. */
            c->prng ^= c->prng << 13;
            c->prng ^= c->prng >> 7;
            c->prng ^= c->prng << 17;
            d = (c->prng % 240) + 8;
            break;
        case 1:
            /* rotating value every 70 samples: trips the RCT/stuck intermittent
               cutoff (61) without reaching a permanent bound, and no byte
               dominates a 512-window enough to reach the APT permanent tier. */
            d = 0x50 + ((uint64_t)(c->measPos / 70)) * 0x10;
            break;
        default:
            d = 0x50;
            break;
    }
    c->measPos++;
    ES_DeltaNsProcessRawDelta(c->e, d);
}
#endif

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_RECOVERY_WINDOW_TC001(int scenario)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    ES_DeltaNs e = {0};
    /* Recovery reproduces the startup timer gate at timerCheckOsr, not the settled
       osr; scenario 4 settles a weaker osr to prove the gate stays strict. */
    e.osr = (scenario == 4) ? 15 : 3;
    e.timerCheckOsr = 3;
    EntropyRecScriptCtx ctx = {&e, 0, 0, (uint32_t)scenario, 0x9E3779B97F4A7C15ULL};
    int32_t ret = ES_DeltaNsRecoveryWindow(&e, EntropyRawRecScript, EntropyMeasureRecScript, &ctx);
    if (scenario == 0) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_EQ(e.testFailure, CRYPT_SUCCESS);
        ASSERT_EQ(ctx.measPos, ES_STARTUP_TEST_SAMPLES);
    } else if (scenario == 1) {
        ASSERT_EQ(ret, CRYPT_ENTROPY_RCT_FAILURE);
        ASSERT_EQ(e.testFailure, NS_ENTROPY_RCT_FAILURE);
        ASSERT_EQ(ctx.measPos, ES_STARTUP_TEST_SAMPLES);
    } else if (scenario == 2) {
        /* The recovery timer check rejects a timer that lost resolution before the
           soak even runs. */
        ASSERT_EQ(ret, CRYPT_ENTROPY_ES_COARSE_TIMER);
        ASSERT_EQ(ctx.measPos, 0);
    } else if (scenario == 4) {
        /* variation 102 would pass the settled osr 15 (target 69) but must be
           rejected at the startup timerCheckOsr 3 (target 342). */
        ASSERT_EQ(ret, CRYPT_ENTROPY_ES_COARSE_TIMER);
        ASSERT_EQ(ctx.measPos, 0);
    } else {
        ASSERT_EQ(ret, CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
        ASSERT_EQ(e.testFailure, NS_ENTROPY_PERMANENT_FAILURE);
        ASSERT_TRUE(ctx.measPos < 256);
    }
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    return;
#else
    (void)scenario;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_CONSTRUCTOR_RECOVER_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Both built-in delta sources must install their recovery callback
       so a runtime alarm can re-arm them in production. */
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    ES_NoiseSource *jitter = ES_CpuJitterGetCtx();
    ASSERT_TRUE(jitter != NULL);
    ASSERT_TRUE(jitter->recover != NULL);
    FreeNoiseSource(jitter);
    jitter = NULL;
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    ES_NoiseSource *hashLoop = ES_HashLoopGetCtx();
    ASSERT_TRUE(hashLoop != NULL);
    ASSERT_TRUE(hashLoop->recover != NULL);
    FreeNoiseSource(hashLoop);
    hashLoop = NULL;
#endif
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

static uint32_t g_recArmed = 0;
static uint32_t g_recPersistArmed = 0;
static uint32_t g_auxRecArmed = 0;

static int32_t EntropyReadRec(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    if (bufLen == 1 && g_recPersistArmed != 0) {
        return CRYPT_ENTROPY_RCT_FAILURE;
    }
    if (bufLen == 1 && g_recArmed != 0) {
        g_recArmed = 0;
        return CRYPT_ENTROPY_RCT_FAILURE;
    }
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (uint8_t)(1 + (pos % 251));
    }
    return CRYPT_SUCCESS;
}

static int32_t EntropyReadAuxRec(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    static uint32_t pos = 0;
    if (bufLen == 1 && g_auxRecArmed != 0) {
        g_auxRecArmed = 0;
        return CRYPT_ENTROPY_RCT_FAILURE;
    }
    for (uint32_t i = 0; i < bufLen; i++, pos++) {
        buf[i] = (uint8_t)(1 + (pos % 251));
    }
    return CRYPT_SUCCESS;
}

static uint32_t g_recCalls = 0;
static int32_t g_recRet = CRYPT_SUCCESS;

static int32_t EntropyRecoverCb(void *usrdata)
{
    (void)usrdata;
    g_recCalls++;
    return g_recRet;
}

#if defined(HITLS_CRYPTO_ENTROPY_SYS)
static ES_NoiseSource *EntropyFindNs(CRYPT_EAL_Es *es, const char *name)
{
    if (es == NULL || es->es == NULL) {
        return NULL;
    }
    for (BslListNode *node = BSL_LIST_FirstNode(es->es->nsList); node != NULL;
        node = BSL_LIST_GetNextNode(es->es->nsList, node)) {
        ES_NoiseSource *ns = BSL_LIST_GetData(node);
        if (ns != NULL && ns->name != NULL && strcmp(ns->name, name) == 0) {
            return ns;
        }
    }
    return NULL;
}

static CRYPT_EAL_Es *EntropyBuildRecoverEs(void)
{
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    if (es == NULL) {
        return NULL;
    }
    if (CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")) !=
        CRYPT_SUCCESS) {
        CRYPT_EAL_EsFree(es);
        return NULL;
    }
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    (void)CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"CPU-Jitter", 10);
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    (void)CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"Hash-Loop", 9);
#endif
    CRYPT_EAL_NsPara para = {"credit-r", false, 8, {NULL, NULL, EntropyReadRec, NULL}, {5, 200, 512}};
    if (CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara)) != CRYPT_SUCCESS) {
        CRYPT_EAL_EsFree(es);
        return NULL;
    }
    bool healthTest = true;
    if (CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, 1) != CRYPT_SUCCESS) {
        CRYPT_EAL_EsFree(es);
        return NULL;
    }
    return es;
}

/* Build, init, suspend the mock credited source via one armed RCT alarm, and
   inject the recovery callback white-box (recovery is internal-only). */
static CRYPT_EAL_Es *EntropySuspendRecoverEs(ES_NoiseSource **outNs, int32_t (*recover)(void *))
{
    CRYPT_EAL_Es *es = EntropyBuildRecoverEs();
    if (es == NULL) {
        return NULL;
    }
    g_recArmed = 0;
    g_recCalls = 0;
    if (CRYPT_EAL_EsInit(es) != CRYPT_SUCCESS) {
        CRYPT_EAL_EsFree(es);
        return NULL;
    }
    ES_NoiseSource *ns = EntropyFindNs(es, "credit-r");
    if (ns == NULL) {
        CRYPT_EAL_EsFree(es);
        return NULL;
    }
    ns->recover = recover;
    g_recArmed = 1;
    (void)TestErrClear();
    if (CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0) != CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH) {
        CRYPT_EAL_EsFree(es);
        return NULL;
    }
    (void)TestErrClear();
    *outNs = ns;
    return es;
}
#endif

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_UNCREDITED_RECOVERY_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_EAL_Es *es = EntropyBuildRecoverEs();
    ES_NoiseSource *ns = NULL;
    ASSERT_TRUE(es != NULL);
    CRYPT_EAL_NsPara para = {"aux-r", false, 0, {NULL, NULL, EntropyReadAuxRec, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para)), CRYPT_SUCCESS);
    g_auxRecArmed = 0;
    g_recCalls = 0;
    g_recRet = CRYPT_SUCCESS;
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    ns = EntropyFindNs(es, "aux-r");
    ASSERT_TRUE(ns != NULL);
    ns->recover = EntropyRecoverCb;
    g_auxRecArmed = 1;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_TRUE(ns->needRecovery && !ns->isEnable);
    ASSERT_EQ(g_recCalls, 0);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(g_recCalls, 1);
    ASSERT_TRUE(!ns->needRecovery && ns->isEnable);
EXIT:
    g_auxRecArmed = 0;
    g_recRet = CRYPT_SUCCESS;
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_UNCREDITED_RECOVERY_TC002(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* A request that empties the pool passes the readiness gate and then collects.
       A failing auxiliary recovery keeps needRecovery set across both steps, so one
       request charges the recovery streak once. */
    CRYPT_EAL_Es *es = EntropyBuildRecoverEs();
    ES_NoiseSource *ns = NULL;
    uint8_t buf[128];
    ASSERT_TRUE(es != NULL);
    CRYPT_EAL_NsPara para = {"aux-r", false, 0, {NULL, NULL, EntropyReadAuxRec, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para)), CRYPT_SUCCESS);
    g_recArmed = 0;
    g_recPersistArmed = 0;
    g_auxRecArmed = 0;
    g_recCalls = 0;
    g_recRet = CRYPT_ENTROPY_RCT_FAILURE;
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    ns = EntropyFindNs(es, "aux-r");
    ASSERT_TRUE(ns != NULL);
    ns->recover = EntropyRecoverCb;
    g_auxRecArmed = 1;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_TRUE(ns->needRecovery && !ns->isEnable);
    /* Drain exactly what the pool holds so the measured request has to collect. */
    uint32_t pooled = ES_EntropyPoolGetCurSize(es->es->pool);
    ASSERT_TRUE(pooled > 0 && pooled <= sizeof(buf));
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, buf, pooled), pooled);
    ASSERT_EQ(ES_EntropyPoolGetCurSize(es->es->pool), 0);
    g_recCalls = 0;
    ns->recoveryFailStreak = 0;
    ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(es, buf, sizeof(buf)) > 0);
    ASSERT_EQ(g_recCalls, 1);
    ASSERT_EQ(ns->recoveryFailStreak, 1);
    ASSERT_TRUE(ns->needRecovery && !ns->permanentFailure);
EXIT:
    g_auxRecArmed = 0;
    g_recRet = CRYPT_SUCCESS;
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_RUNTIME_RECOVERY_TC001(int scenario)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* A runtime RCT alarm suspends the credited source; the next transaction
       runs the timer check, and its outcome drives the three-state
       machine. */
    ES_NoiseSource *ns = NULL;
    CRYPT_EAL_Es *es = EntropySuspendRecoverEs(&ns, (scenario == 3) ? NULL : EntropyRecoverCb);
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(ns->needRecovery && !ns->isEnable && !ns->permanentFailure);
    ASSERT_EQ(g_recCalls, 0);
    if (scenario == 0) {
        g_recRet = CRYPT_SUCCESS;
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
        ASSERT_EQ(g_recCalls, 1);
        ASSERT_TRUE(!ns->needRecovery && ns->isEnable);
        ASSERT_EQ(ns->recoveryFailStreak, 0);
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
        ASSERT_EQ(g_recCalls, 1);
    } else if (scenario == 1) {
        g_recRet = CRYPT_ENTROPY_RCT_FAILURE;
        for (uint32_t i = 1; i < NS_PERMANENT_FAIL_STREAK; i++) {
            ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_RCT_FAILURE);
            (void)TestErrClear();
            ASSERT_EQ(ns->recoveryFailStreak, i);
            ASSERT_TRUE(!ns->permanentFailure);
        }
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
        (void)TestErrClear();
        ASSERT_TRUE(ns->permanentFailure && !ns->needRecovery && !ns->onProbation && !ns->isEnable);
        ASSERT_EQ(g_recCalls, NS_PERMANENT_FAIL_STREAK);
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
        (void)TestErrClear();
        ASSERT_EQ(g_recCalls, NS_PERMANENT_FAIL_STREAK);
    } else if (scenario == 2) {
        g_recRet = CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
        (void)TestErrClear();
        ASSERT_TRUE(ns->permanentFailure && !ns->needRecovery && !ns->onProbation && !ns->isEnable);
        ASSERT_EQ(g_recCalls, 1);
    } else if (scenario == 3) {
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_NS_NOT_AVA);
        (void)TestErrClear();
        ASSERT_TRUE(ns->needRecovery && !ns->permanentFailure);
        ASSERT_EQ(g_recCalls, 0);
    } else {
        g_recRet = CRYPT_NULL_INPUT;
        for (uint32_t i = 0; i < NS_PERMANENT_FAIL_STREAK + 2; i++) {
            ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_NULL_INPUT);
            (void)TestErrClear();
            ASSERT_EQ(ns->recoveryFailStreak, 0);
            ASSERT_TRUE(!ns->permanentFailure);
        }
        g_recRet = CRYPT_SUCCESS;
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
        ASSERT_TRUE(ns->isEnable);
    }
    (void)TestErrClear();
EXIT:
    g_recArmed = 0;
    g_recRet = CRYPT_SUCCESS;
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)scenario;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_GET_RECOVERY_TC001(int scenario)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* The consumption path (CRYPT_EAL_EsEntropyGet) must run the recovery gate:
       a pass re-arms and yields bytes; a failing verdict fails closed with zero
       output and the matching state. */
    ES_NoiseSource *ns = NULL;
    CRYPT_EAL_Es *es = EntropySuspendRecoverEs(&ns, (scenario == 3) ? NULL : EntropyRecoverCb);
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(ns->needRecovery && !ns->isEnable);
    ASSERT_EQ(g_recCalls, 0);
    uint8_t out[32];
    if (scenario == 0) {
        g_recRet = CRYPT_SUCCESS;
        ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, out, sizeof(out)), sizeof(out));
        ASSERT_EQ(g_recCalls, 1);
        ASSERT_TRUE(!ns->needRecovery && ns->isEnable);
    } else if (scenario == 1) {
        g_recRet = CRYPT_ENTROPY_RCT_FAILURE;
        ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, out, sizeof(out)), 0);
        ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_RCT_FAILURE);
        ASSERT_TRUE(TestIsErrStackEmpty());
        ASSERT_EQ(g_recCalls, 1);
        ASSERT_TRUE(ns->needRecovery && !ns->isEnable && !ns->permanentFailure);
    } else if (scenario == 2) {
        g_recRet = CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
        ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, out, sizeof(out)), 0);
        ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
        ASSERT_TRUE(TestIsErrStackEmpty());
        ASSERT_EQ(g_recCalls, 1);
        ASSERT_TRUE(ns->permanentFailure);
    } else {
        ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, out, sizeof(out)), 0);
        ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_ES_NS_NOT_AVA);
        ASSERT_TRUE(TestIsErrStackEmpty());
        ASSERT_EQ(g_recCalls, 0);
        ASSERT_TRUE(ns->needRecovery && !ns->permanentFailure);
    }
    (void)TestErrClear();
EXIT:
    g_recArmed = 0;
    g_recRet = CRYPT_SUCCESS;
    CRYPT_EAL_EsFree(es);
    return;
#else
    (void)scenario;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_RECOVERY_REINIT_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* A fresh startup timer check supersedes a pending suspension: after
       deinit + init the source starts clean and no recovery window runs. */
    ES_NoiseSource *ns = NULL;
    CRYPT_EAL_Es *es = EntropySuspendRecoverEs(&ns, EntropyRecoverCb);
    ASSERT_TRUE(es != NULL);
    ASSERT_TRUE(ns->needRecovery);
    ns->recoveryFailStreak = 2;
    ENTROPY_EsDeinit(es->es);
    g_recArmed = 0;
    ASSERT_EQ(ENTROPY_EsInit(es->es), CRYPT_SUCCESS);
    ns = EntropyFindNs(es, "credit-r");
    ASSERT_TRUE(ns != NULL);
    ASSERT_TRUE(!ns->needRecovery);
    ASSERT_EQ(ns->recoveryFailStreak, 0);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(g_recCalls, 0);
    (void)TestErrClear();
EXIT:
    g_recArmed = 0;
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_PERM_CUTOFF_BOUNDARY_TC001(int mode)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* cutoff-1 identical samples must stay non-permanent; the cutoff-th must
       enter permanent (distinguishes >= from >). mode 0: emitted-byte RCT
       (osr 3, bound 181); mode 1: emitted-byte APT (osr 3, bound 479); mode 2:
       APT at osr 8 where the bound equals the 512 window end. */
    uint32_t osr = (mode == 2) ? 8 : 3;
    ES_DeltaNs e = {0};
    e.osr = osr;
    ES_DeltaNsOsrApply(&e, osr);
    e.stuckCutoff = UINT32_MAX;
    uint32_t perm;
    if (mode == 0) {
        e.apt.cutoff = UINT32_MAX;
        e.aptPermCutoff = 0;
        perm = e.rctPermCutoff;
    } else {
        e.rct.cutoff = UINT32_MAX;
        e.rctPermCutoff = UINT32_MAX;
        perm = e.aptPermCutoff;
    }
    ASSERT_TRUE(perm > 1 && perm <= NS_APT_DELTA_WINDOW_SIZE);
    for (uint32_t i = 0; i < perm - 1; i++) {
        ES_DeltaNsProcessRawDelta(&e, 0x50);
    }
    ASSERT_TRUE(e.testFailure != NS_ENTROPY_PERMANENT_FAILURE);
    ES_DeltaNsProcessRawDelta(&e, 0x50);
    ASSERT_EQ(e.testFailure, NS_ENTROPY_PERMANENT_FAILURE);
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    return;
#else
    (void)mode;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_PROBATION_RETIRE_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* A source whose recovery window passes but whose production re-alarms on
       the very next transaction must not recover forever: each probation broken
       by a fresh alarm charges the failure streak, retiring the source after
       NS_PERMANENT_FAIL_STREAK broken attempts. */
    ES_NoiseSource *ns = NULL;
    CRYPT_EAL_Es *es = EntropyBuildRecoverEs();
    ASSERT_TRUE(es != NULL);
    g_recArmed = 0;
    g_recPersistArmed = 0;
    g_recCalls = 0;
    g_recRet = CRYPT_SUCCESS;
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    ns = EntropyFindNs(es, "credit-r");
    ASSERT_TRUE(ns != NULL);
    ns->recover = EntropyRecoverCb;
    g_recPersistArmed = 1;
    (void)TestErrClear();
    /* first gather: production alarm suspends, no probation yet, streak 0. */
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
    (void)TestErrClear();
    ASSERT_TRUE(ns->needRecovery && ns->recoveryFailStreak == 0 && !ns->permanentFailure);
    /* each subsequent gather: recovery re-arms (probation), production
       re-alarms, streak climbs to retirement. */
    for (uint32_t i = 1; i <= NS_PERMANENT_FAIL_STREAK; i++) {
        int32_t rc = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0);
        (void)TestErrClear();
        ASSERT_EQ(ns->recoveryFailStreak, i);
        ASSERT_EQ(g_recCalls, i);
        if (i < NS_PERMANENT_FAIL_STREAK) {
            ASSERT_EQ(rc, CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
            ASSERT_TRUE(!ns->permanentFailure);
        } else {
            /* the crossing alarm surfaces the permanent verdict on this same
               call, and leaves the canonical terminal state. */
            ASSERT_EQ(rc, CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
            ASSERT_TRUE(ns->permanentFailure && !ns->needRecovery && !ns->onProbation);
        }
    }
    /* retired: further gathers refuse without running another recovery window. */
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    (void)TestErrClear();
    ASSERT_EQ(g_recCalls, NS_PERMANENT_FAIL_STREAK);
EXIT:
    g_recPersistArmed = 0;
    g_recArmed = 0;
    g_recRet = CRYPT_SUCCESS;
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_PROBATION_CLEAR_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* A full successful runtime gather vindicates a probationary source: the
       streak resets and probation clears, so a later, separated alarm starts a
       fresh streak instead of inheriting the earlier probation charge. */
    ES_NoiseSource *ns = NULL;
    CRYPT_EAL_Es *es = EntropyBuildRecoverEs();
    ASSERT_TRUE(es != NULL);
    g_recArmed = 0;
    g_recPersistArmed = 0;
    g_recCalls = 0;
    g_recRet = CRYPT_SUCCESS;
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    ns = EntropyFindNs(es, "credit-r");
    ASSERT_TRUE(ns != NULL);
    ns->recover = EntropyRecoverCb;
    /* suspend via one alarm. */
    g_recArmed = 1;
    (void)TestErrClear();
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
    (void)TestErrClear();
    ASSERT_TRUE(ns->needRecovery && !ns->onProbation && ns->recoveryFailStreak == 0);
    /* one failed recovery window drives the streak to a non-zero value. */
    g_recRet = CRYPT_ENTROPY_RCT_FAILURE;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_RCT_FAILURE);
    (void)TestErrClear();
    ASSERT_EQ(ns->recoveryFailStreak, 1);
    ASSERT_TRUE(!ns->permanentFailure);
    /* now recovery passes and a full production gather succeeds: the retained
       streak of 1 must clear back to 0 and probation must lift. */
    g_recRet = CRYPT_SUCCESS;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(g_recCalls, 2);
    ASSERT_TRUE(!ns->onProbation && !ns->needRecovery && ns->isEnable);
    ASSERT_EQ(ns->recoveryFailStreak, 0);
    /* a later, separated alarm opens a fresh streak from 0, not inheriting the
       cleared charge: the first re-alarm suspends without touching the streak
       (onProbation was clear); only the next recover-pass / re-alarm cycle
       opens the streak at 1. */
    g_recPersistArmed = 1;
    (void)TestErrClear();
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
    (void)TestErrClear();
    ASSERT_TRUE(ns->needRecovery && !ns->permanentFailure);
    ASSERT_EQ(ns->recoveryFailStreak, 0);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
    (void)TestErrClear();
    ASSERT_EQ(ns->recoveryFailStreak, 1);
    ASSERT_TRUE(!ns->permanentFailure);
EXIT:
    g_recArmed = 0;
    g_recPersistArmed = 0;
    g_recRet = CRYPT_SUCCESS;
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

static int32_t g_lastLogVerdict = CRYPT_SUCCESS;

static void EntropyVerdictLog(int32_t ret)
{
    g_lastLogVerdict = ret;
}

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_RUNLOG_RAW_VERDICT_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* The log callback observes the raw per-source health verdict, even on the
       transaction that escalates to permanent retirement: the callback carries
       the RCT/APT event, while the gather return code carries the escalated
       permanent verdict. */
    ES_NoiseSource *ns = NULL;
    CRYPT_EAL_Es *es = EntropyBuildRecoverEs();
    ASSERT_TRUE(es != NULL);
    g_recArmed = 0;
    g_recPersistArmed = 0;
    g_recCalls = 0;
    g_recRet = CRYPT_SUCCESS;
    g_lastLogVerdict = CRYPT_SUCCESS;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_LOG_CALLBACK, (void *)EntropyVerdictLog, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    ns = EntropyFindNs(es, "credit-r");
    ASSERT_TRUE(ns != NULL);
    ns->recover = EntropyRecoverCb;
    g_recPersistArmed = 1;
    (void)TestErrClear();
    /* first alarm suspends (no probation yet). */
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
    (void)TestErrClear();
    ASSERT_EQ(g_lastLogVerdict, CRYPT_ENTROPY_RCT_FAILURE);
    /* drive to the retiring crossing; each cycle recovers then re-alarms. */
    int32_t rc = CRYPT_SUCCESS;
    for (uint32_t i = 1; i <= NS_PERMANENT_FAIL_STREAK; i++) {
        rc = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0);
        (void)TestErrClear();
    }
    /* the crossing gather returns the escalated permanent verdict... */
    ASSERT_EQ(rc, CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    ASSERT_TRUE(ns->permanentFailure);
    /* ...but the callback saw the raw RCT event, not the escalation. */
    ASSERT_EQ(g_lastLogVerdict, CRYPT_ENTROPY_RCT_FAILURE);
    (void)TestErrClear();
EXIT:
    g_recArmed = 0;
    g_recPersistArmed = 0;
    g_recRet = CRYPT_SUCCESS;
    g_lastLogVerdict = CRYPT_SUCCESS;
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NULL_PARAM_EAL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    ASSERT_EQ(CRYPT_EAL_EsInit(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(NULL, CRYPT_ENTROPY_SET_POOL_SIZE, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(NULL, NULL, 0), 0);
    uint8_t buf[32];
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(NULL, buf, sizeof(buf)), 0);
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)"sha256_df", 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)"bogus_df", 8), CRYPT_ENTROPY_ECF_ALG_ERROR);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_MAX, NULL, 0), CRYPT_ENTROPY_ES_CTRL_ERROR);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, (int32_t)(CRYPT_ENTROPY_SET_POOL_SIZE - 1), NULL, 0),
        CRYPT_ENTROPY_ES_CTRL_ERROR);
    CRYPT_EAL_EsFree(es);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NULL_PARAM_ES_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    ASSERT_EQ(ENTROPY_EsInit(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(NULL, CRYPT_ENTROPY_SET_POOL_SIZE, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsEntropyGet(NULL, NULL, 0), 0);
    ASSERT_EQ(ENTROPY_EsEntropyGather(NULL), CRYPT_NULL_INPUT);
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    ASSERT_EQ(ENTROPY_EsInit(raw), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ADD_NS, NULL, sizeof(CRYPT_EAL_NsPara)), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ADD_NS, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_REMOVE_NS, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ENABLE_TEST, NULL, sizeof(bool)), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ENABLE_TEST, NULL, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_GET_STATE, NULL, sizeof(bool)), CRYPT_INVALID_ARG);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_GET_STATE, NULL, 0), CRYPT_INVALID_ARG);
    ASSERT_EQ(ENTROPY_EsCtrl(NULL, CRYPT_ENTROPY_SET_LOG_CALLBACK, (void *)0x1, 0), CRYPT_NULL_INPUT);
    ENTROPY_EsFree(raw);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_INVALID_PARAM_ES_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    uint32_t poolSize = 1024;
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_POOL_SIZE, &poolSize, 0),
        CRYPT_ENTROPY_CTRL_INVALID_PARAM);
    poolSize = 256;
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_POOL_SIZE, &poolSize, sizeof(poolSize)),
        CRYPT_ENTROPY_CTRL_INVALID_PARAM);
    poolSize = 8192;
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_POOL_SIZE, &poolSize, sizeof(poolSize)),
        CRYPT_ENTROPY_CTRL_INVALID_PARAM);
    CRYPT_EAL_NsPara para = {"test", false, 1, {NULL, NULL, EntropyReadVaried, NULL}, {5, 200, 512}};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ADD_NS, &para, 0), CRYPT_NULL_INPUT);
    bool flag = true;
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ENABLE_TEST, &flag, 0), CRYPT_NULL_INPUT);
    ENTROPY_CFPara unsupportedCf = {CRYPT_MD_MD5, NULL};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &unsupportedCf, sizeof(unsupportedCf)),
        CRYPT_ENTROPY_ES_CF_NOT_SUPPORT);
    /* An undersized or NULL SET_CF buffer is rejected by the length guard
       before the struct is read. */
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &unsupportedCf, sizeof(unsupportedCf) - 1),
        CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, NULL, sizeof(ENTROPY_CFPara)), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_GET_POOL_SIZE, &poolSize, 0), CRYPT_NULL_INPUT);
    (void)TestErrClear();
    ENTROPY_EsFree(raw);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MALLOC_FAIL_ESNEW_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    g_entropyFailNthK = 1;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    ASSERT_TRUE(ENTROPY_EsNew() == NULL);
    EntropyRestoreMalloc();
    g_entropyFailNthK = 2;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    ASSERT_TRUE(ENTROPY_EsNew() == NULL);
    EntropyRestoreMalloc();
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MALLOC_FAIL_ESINIT_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    int sawFailure = 0;
    for (int k = 1; k <= 8; k++) {
        ENTROPY_EntropySource *raw = ENTROPY_EsNew();
        ASSERT_TRUE(raw != NULL);
        ENTROPY_CFPara cfPara = EsMakeCfPara();
        ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &cfPara, sizeof(cfPara)), CRYPT_SUCCESS);
        CRYPT_EAL_NsPara para = {"mn", false, 1, {NULL, NULL, EntropyReadVaried, NULL}, {5, 200, 512}};
        ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para)), CRYPT_SUCCESS);
        g_entropyFailNthK = k;
        g_entropyMallocSeq = 0;
        ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
        int32_t ret = ENTROPY_EsInit(raw);
        EntropyRestoreMalloc();
        (void)TestErrClear();
        if (ret != CRYPT_SUCCESS) {
            /* An injected allocation failure must surface as one of the defined
               fail-closed verdicts, never a crash or a corrupted code. */
            sawFailure = 1;
            ASSERT_TRUE(ret == CRYPT_MEM_ALLOC_FAIL || ret == CRYPT_ENTROPY_ES_CF_ERROR ||
                ret == CRYPT_ENTROPY_ES_POOL_ERROR || ret == CRYPT_ENTROPY_ES_NS_NOT_AVA);
        }
        ENTROPY_EsFree(raw);
        if (ret == CRYPT_SUCCESS) {
            break;
        }
    }
    /* k = 1 targets the conditioner context allocated by ENTROPY_EsInit. */
    ASSERT_EQ(sawFailure, 1);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MALLOC_FAIL_EALNEW_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    g_entropyFailNthK = 1;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsNew() == NULL);
    EntropyRestoreMalloc();
    g_entropyFailNthK = 2;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsNew() == NULL);
    EntropyRestoreMalloc();
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NULL_PARAM_SEEDPOOL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    ASSERT_EQ(ENTROPY_SeedPoolAddEs(NULL, NULL), CRYPT_NULL_INPUT);
    uint32_t len = 32;
    uint8_t data[32] = {0};
    ASSERT_EQ(ENTROPY_SeedPoolCollect(NULL, false, 0, data, &len), 0);
    ASSERT_EQ(ENTROPY_SeedPoolCheckState(NULL, false), false);
    ASSERT_EQ(ENTROPY_SeedPoolGetMinEntropy(NULL), 0);
    ENTROPY_SeedPool *pool = ENTROPY_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);
    ASSERT_EQ(ENTROPY_SeedPoolCollect(pool, false, 0, NULL, &len), 0);
    ASSERT_EQ(ENTROPY_SeedPoolCollect(pool, false, 0, data, NULL), 0);
    ASSERT_EQ(ENTROPY_SeedPoolCheckState(pool, false), false);
    ASSERT_EQ(ENTROPY_SeedPoolCheckState(pool, true), false);
    ENTROPY_SeedPoolFree(pool);
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(NULL, NULL), CRYPT_NULL_INPUT);
    CRYPT_EAL_SeedPoolCtx *spCtx = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(spCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(spCtx, NULL), CRYPT_NULL_INPUT);
    CRYPT_EAL_EsPara ePara = {false, 0, NULL, NULL};
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(spCtx, &ePara), CRYPT_NULL_INPUT);
    ePara.minEntropy = 16;
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(spCtx, &ePara), CRYPT_NULL_INPUT);
    CRYPT_EAL_SeedPoolFree(spCtx);
    ASSERT_EQ(CRYPT_EAL_SeedPoolGetEntropy(NULL, NULL, 0, NULL), CRYPT_NULL_INPUT);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_GENERIC_APT_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* The generic health loop runs for externally registered sources that ask
       for governance testing. An alternating stream stays under the RCT cutoff
       and reaches the APT cutoff, so the loop must report the APT verdict. */
    TestMemInit();
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadAlternate, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    ASSERT_EQ(ES_NsAdd(list, "alt", false, 5, &method, &para), CRYPT_SUCCESS);
    (void)TestErrClear();
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_ENTROPY_APT_FAILURE);
    ES_NoiseSource *ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ASSERT_TRUE(!ns->isEnable);
    (void)TestErrClear();
EXIT:
    ES_NsListFree(list);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ECF_FAIL_WIPE_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* A conditioning call that fails after filling its output buffer must have
       the whole buffer wiped, observed while the caller's frame is alive. */
    ENTROPY_SeedPool *pool = NULL;
    uint8_t out[64] = {0};
    ENTROPY_ECFCtx ecf = {CRYPT_MD_SHA256, 32, EntropyEcfStub};

    pool = ENTROPY_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara para = {true, 6, NULL, EntropyGetNormal};
    ASSERT_EQ(ENTROPY_SeedPoolAddEs(pool, &para), CRYPT_SUCCESS);

    g_entropyEcfFail = 1;
    g_ecfWipePtr = NULL;
    g_ecfWipeLen = 0;
    g_ecfWipeSeen = 0;
    g_ecfWipeNonZero = 0;
    STUB_REPLACE(BSL_SAL_CleanseData, EntropyCleanseProbe);
    int32_t ret = ENTROPY_GetFullEntropyInput(&ecf, pool, true, 128, out, sizeof(out));
    STUB_RESTORE(BSL_SAL_CleanseData);
    ASSERT_EQ(ret, CRYPT_ENTROPY_ECF_ALG_ERROR);
    /* The failing path wiped that buffer once, over its full width, and the
       sentinel was still present when the wipe ran. */
    ASSERT_EQ(g_ecfWipeSeen, 1);
    ASSERT_EQ(g_ecfWipeLen, 64);
    ASSERT_EQ(g_ecfWipeNonZero, 1);
    (void)TestErrClear();
EXIT:
    STUB_RESTORE(BSL_SAL_CleanseData);
    g_entropyEcfFail = 0;
    g_ecfWipePtr = NULL;
    ENTROPY_SeedPoolFree(pool);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_SEEDPOOL_NPES_ONLY_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* A pool holding only non-physical sources cannot serve a request that
       requires a physical source, and serves one that accepts NPES. */
    ENTROPY_SeedPool *pool = ENTROPY_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);
    CRYPT_EAL_EsPara npes = {false, 8, NULL, EntropyGetNormal};
    ASSERT_EQ(ENTROPY_SeedPoolAddEs(pool, &npes), CRYPT_SUCCESS);
    ASSERT_EQ(ENTROPY_SeedPoolCheckState(pool, false), false);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_SEED_POOL_NO_ENTROPY_SOURCE);
    (void)TestErrClear();
    ASSERT_EQ(ENTROPY_SeedPoolCheckState(pool, true), true);
    /* Adding a physical source lifts the restriction. */
    CRYPT_EAL_EsPara pes = {true, 8, NULL, EntropyGetNormal};
    ASSERT_EQ(ENTROPY_SeedPoolAddEs(pool, &pes), CRYPT_SUCCESS);
    ASSERT_EQ(ENTROPY_SeedPoolCheckState(pool, false), true);
EXIT:
    ENTROPY_SeedPoolFree(pool);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_SEEDPOOL_ADDFAIL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    ENTROPY_SeedPool *pool = ENTROPY_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);
    for (int i = 0; i < 32; i++) {
        CRYPT_EAL_EsPara p = {false, 1, NULL, EntropyGetNormal};
        int32_t ret = ENTROPY_SeedPoolAddEs(pool, &p);
        if (ret != CRYPT_SUCCESS) {
            ASSERT_EQ(ret, CRYPT_SEED_POOL_ES_LIST_FULL);
            break;
        }
    }
    ENTROPY_SeedPoolFree(pool);
    ENTROPY_SeedPool *pool2 = ENTROPY_SeedPoolNew(true);
    ASSERT_TRUE(pool2 != NULL);
    g_entropyFailNthK = 1;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    CRYPT_EAL_EsPara p2 = {false, 1, NULL, EntropyGetNormal};
    ASSERT_EQ(ENTROPY_SeedPoolAddEs(pool2, &p2), CRYPT_SEED_POOL_NEW_ERROR);
    EntropyRestoreMalloc();
    ENTROPY_SeedPoolFree(pool2);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_INIT_NO_NS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)"sha256_df",
        strlen("sha256_df")), CRYPT_SUCCESS);
    ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_ENTROPY_ES_NO_NS);
    (void)TestErrClear();
    CRYPT_EAL_EsFree(es);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_GATHER_NULL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    ASSERT_EQ(ENTROPY_EsEntropyGather(NULL), CRYPT_NULL_INPUT);
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    ASSERT_EQ(ENTROPY_EsEntropyGather(raw), CRYPT_NULL_INPUT);
    ENTROPY_EsFree(raw);
    ASSERT_EQ(ENTROPY_EsEntropyGet(NULL, NULL, 32), 0);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EAL_GET_NULL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, NULL, 32), 0);
    uint8_t buf[32];
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(NULL, buf, sizeof(buf)), 0);
    CRYPT_EAL_EsFree(es);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MALLOC_FAIL_SEEDPOOL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    g_entropyFailNthK = 1;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    ASSERT_TRUE(ENTROPY_SeedPoolNew(true) == NULL);
    EntropyRestoreMalloc();
    g_entropyFailNthK = 2;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    ASSERT_TRUE(ENTROPY_SeedPoolNew(true) == NULL);
    EntropyRestoreMalloc();
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MALLOC_FAIL_CFDF_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    g_entropyFailNthK = 1;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    const EAL_MdMethod *md = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    ASSERT_TRUE(md != NULL);
    ASSERT_TRUE(ES_CFGetDfMethod((EAL_MdMethod *)(uintptr_t)md) == NULL);
    EntropyRestoreMalloc();
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MALLOC_FAIL_EAL_SEEDPOOL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    g_entropyFailNthK = 1;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_SeedPoolNew(true) == NULL);
    EntropyRestoreMalloc();
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_SET_CF_DUP_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    ENTROPY_CFPara cfPara = EsMakeCfPara();
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &cfPara, sizeof(cfPara)), CRYPT_SUCCESS);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &cfPara, sizeof(cfPara)), CRYPT_ENTROPY_ES_CF_ERROR);
    (void)TestErrClear();
    ENTROPY_EsFree(raw);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_CTRL_GETSIZE_NOT_WORKING_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    ENTROPY_CFPara cfPara = EsMakeCfPara();
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &cfPara, sizeof(cfPara)), CRYPT_SUCCESS);
    uint32_t val = 0;
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_GET_POOL_SIZE, &val, sizeof(val)),
        CRYPT_ENTROPY_ES_STATE_ERROR);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_POOL_GET_CURRSIZE, &val, sizeof(val)),
        CRYPT_ENTROPY_ES_STATE_ERROR);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_GET_CF_SIZE, &val, sizeof(val)),
        CRYPT_ENTROPY_ES_STATE_ERROR);
    (void)TestErrClear();
    ENTROPY_EsFree(raw);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_STATE_ERROR_ON_WORKING_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_EAL_Es *es = EntropyBuildRecoverEs();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    uint32_t poolSize = 1024;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, &poolSize, sizeof(poolSize)),
        CRYPT_ENTROPY_ES_STATE_ERROR);
    CRYPT_EAL_NsPara para = {"x", false, 1, {NULL, NULL, EntropyReadVaried, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para)),
        CRYPT_ENTROPY_ES_STATE_ERROR);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)"x", 1),
        CRYPT_ENTROPY_ES_STATE_ERROR);
    bool flag = true;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &flag, sizeof(flag)),
        CRYPT_ENTROPY_ES_STATE_ERROR);
    (void)TestErrClear();
    CRYPT_EAL_EsFree(es);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_MALLOC_FAIL_NS_CREAT_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    for (int k = 1; k <= 15; k++) {
        g_entropyFailNthK = k;
        g_entropyMallocSeq = 0;
        ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
        ENTROPY_EntropySource *es = ENTROPY_EsNew();
        EntropyRestoreMalloc();
        /* k = 1 fails the very first allocation, so the constructor must return
           NULL rather than a half-built object. */
        if (k == 1) {
            ASSERT_TRUE(es == NULL);
        }
        if (es != NULL) {
            ENTROPY_EsFree(es);
            break;
        }
    }
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EAL_CF_NON_DF_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)"bogus", 5),
        CRYPT_ENTROPY_ECF_ALG_ERROR);
    (void)TestErrClear();
    CRYPT_EAL_EsFree(es);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_GETSIZE_UNKNOWN_CMD_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_EAL_Es *es = EntropyBuildRecoverEs();
    ASSERT_TRUE(es != NULL);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    uint32_t val = 0;
    ASSERT_EQ(ENTROPY_EsCtrl(es->es, CRYPT_ENTROPY_GATHER_ENTROPY, &val, sizeof(val)),
        CRYPT_ENTROPY_ES_CTRL_ERROR);
    (void)TestErrClear();
    CRYPT_EAL_EsFree(es);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EAL_SEEDPOOLNEW_FAIL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    for (int k = 1; k <= 20; k++) {
        g_entropyFailNthK = k;
        g_entropyMallocSeq = 0;
        ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
        CRYPT_EAL_SeedPoolCtx *sp = CRYPT_EAL_SeedPoolNew(false);
        EntropyRestoreMalloc();
        /* k = 1 fails the first allocation, so the constructor must return NULL. */
        if (k == 1) {
            ASSERT_TRUE(sp == NULL);
        }
        if (sp != NULL) {
            CRYPT_EAL_SeedPoolFree(sp);
            break;
        }
    }
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_CF_INIT_FAIL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    ENTROPY_CFPara para = {CRYPT_MD_SHA256, &g_mockMdInitFail};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &para, sizeof(para)), CRYPT_SUCCESS);
    ASSERT_EQ(ENTROPY_EsInit(raw), CRYPT_ENTROPY_ES_CF_ERROR);
    (void)TestErrClear();
    ENTROPY_EsFree(raw);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_CF_UPDATE_FAIL_TC001(int stage)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* stage 0 fails the Hash_df prefix update, stage 1 lets the prefix through
       and fails the first sample-data update. */
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    ENTROPY_CFPara para = {CRYPT_MD_SHA256,
        (stage == 0) ? &g_mockMdUpdateFail : &g_mockMdDataUpdateFail};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &para, sizeof(para)), CRYPT_SUCCESS);
    CRYPT_EAL_NsPara nsPara = {"mn", false, 8, {NULL, NULL, EntropyReadStream, NULL}, {5, 200, 512}};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ADD_NS, &nsPara, sizeof(nsPara)), CRYPT_SUCCESS);
    g_entropyStreamPos = 0;
    /* conditioner update returns CF_ERROR, propagated as result.conditionerErr. */
    ASSERT_EQ(ENTROPY_EsInit(raw), CRYPT_ENTROPY_ES_CF_ERROR);
    (void)TestErrClear();
    ENTROPY_EsFree(raw);
EXIT:
    return;
#else
    (void)stage;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_FULL_INPUT_GUARDS_TC001(int scenario, int expect)
{
#if defined(HITLS_CRYPTO_ENTROPY)
    /* Entry guards and the two shortfall paths of the seed-pool to
       full-entropy conversion: an empty pool, a missing or broken external
       conditioning function, a failing allocation, and a source that cannot
       deliver the requested amount. */
    ENTROPY_SeedPool *pool = NULL;
    uint8_t out[64] = {0};
    ENTROPY_ECFCtx ecf = {CRYPT_MD_SHA256, 32, EntropyEcfStub};
    ENTROPY_ECFCtx noFunc = {CRYPT_MD_SHA256, 32, NULL};
    void *ctx = &ecf;
    g_entropyEcfFail = 0;

    pool = ENTROPY_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);
    /* minEntropy 6 keeps the collected data short of full entropy, so the
       conditioning branch runs instead of the plain copy; scenario 0 registers
       a zero-rate source to drive the pool minimum to zero. */
    CRYPT_EAL_EsPara para = {true, (scenario == 0) ? 0 : 6, NULL,
        (CRYPT_EAL_EntropyGet)((scenario == 4) ? EntropyGetShort : EntropyGetNormal)};
    ASSERT_EQ(ENTROPY_SeedPoolAddEs(pool, &para), CRYPT_SUCCESS);
    if (scenario == 1) {
        ctx = NULL;
    } else if (scenario == 2) {
        ctx = &noFunc;
    } else if (scenario == 5) {
        g_entropyEcfFail = 1;
    } else if (scenario == 6) {
        g_entropyEcfOverLen = 1;
    }
    if (scenario == 3) {
        g_entropyFailNthK = 1;
        g_entropyMallocSeq = 0;
        ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    }
    int32_t ret = ENTROPY_GetFullEntropyInput(ctx, pool, true, 128, out, sizeof(out));
    if (scenario == 3) {
        g_entropyFailNthK = 0;
        EntropyRestoreMalloc();
    }
    ASSERT_EQ(ret, expect);
    (void)TestErrClear();
EXIT:
    g_entropyEcfFail = 0;
    g_entropyEcfOverLen = 0;
    g_entropyFailNthK = 0;
    EntropyRestoreMalloc();
    ENTROPY_SeedPoolFree(pool);
    (void)TestErrClear();
    return;
#else
    (void)scenario;
    (void)expect;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ALLOC_SWEEP_TC001(int cap)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    /* Walk the allocation sequence of a full lifecycle, failing one request
       per pass. Every pass must end with a defined verdict and a balanced
       heap: a leaked block on any error path fails the balance assert. */
    ENTROPY_EntropySource *raw = NULL;
    int reached = 0;
    int total = 0;
    int limit = 0;
    /* Pass 0 injects nothing; its allocation count sizes the sweep, so the
       walk is exhaustive by construction and cap only guards runtime. */
    for (int k = 0; k <= limit; k++) {
        g_entropyFailNthK = 0;
        g_entropyMallocSeq = 0;
        g_entropyLiveBlocks = 0;
        ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocSweep), BSL_SUCCESS);
        ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, EntropyFreeSweep), BSL_SUCCESS);
        g_entropyFailNthK = k;

        raw = ENTROPY_EsNew();
        if (raw != NULL) {
            ENTROPY_CFPara cfPara = EsMakeCfPara();
            (void)ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &cfPara, sizeof(cfPara));
            CRYPT_EAL_NsPara para = {"sweep", false, 1,
                {NULL, NULL, EntropyReadStream, NULL}, {5, 200, 512}};
            (void)ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para));
            g_entropyStreamPos = 0;
            int32_t ret = ENTROPY_EsInit(raw);
            if (ret == CRYPT_SUCCESS) {
                uint8_t out[16] = {0};
                (void)ENTROPY_EsEntropyGet(raw, out, sizeof(out));
                reached++;
            }
            ENTROPY_EsFree(raw);
            raw = NULL;
        }
        int32_t live = g_entropyLiveBlocks;
        int seq = g_entropyMallocSeq;
        g_entropyFailNthK = 0;
        EntropyRestoreMalloc();
        (void)TestErrClear();
        /* Balance is checked after the handle is released, so a surviving
           block is a genuine leak on the path the k-th failure took. */
        ASSERT_EQ(live, 0);
        if (k == 0) {
            total = seq;
            ASSERT_TRUE(total > 0 && total <= cap);
            limit = total;
        }
    }
    /* Some passes must still complete, otherwise the sweep only proved that
       every allocation is load-bearing. */
    ASSERT_TRUE(reached > 0);
EXIT:
    g_entropyFailNthK = 0;
    EntropyRestoreMalloc();
    ENTROPY_EsFree(raw);
    (void)TestErrClear();
    return;
#else
    (void)cap;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_ADD_CONTRACT_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* Registration contract: a source needs a read op and a matched
       init/deinit pair, its claim must stay inside the byte ceiling, and the
       list has a fixed capacity. */
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    CRYPT_EAL_NsMethod ok = {NULL, NULL, EntropyReadStream, NULL};
    CRYPT_EAL_NsMethod noRead = {NULL, NULL, NULL, NULL};
    CRYPT_EAL_NsMethod deinitOnly = {NULL, NULL, EntropyReadStream, EntropyLifeDeinit};
    CRYPT_EAL_NsMethod initOnly = {NULL, EntropyLifeInit, EntropyReadStream, NULL};

    ASSERT_EQ(ES_NsAdd(list, NULL, false, 5, &ok, &para), CRYPT_NULL_INPUT);
    ASSERT_EQ(ES_NsAdd(list, "over", false, 9, &ok, &para), CRYPT_NULL_INPUT);
    ASSERT_EQ(ES_NsAdd(list, "noread", false, 5, &noRead, &para), CRYPT_NULL_INPUT);
    ASSERT_EQ(ES_NsAdd(list, "half1", false, 5, &deinitOnly, &para), CRYPT_NULL_INPUT);
    ASSERT_EQ(ES_NsAdd(list, "half2", false, 5, &initOnly, &para), CRYPT_NULL_INPUT);
    (void)TestErrClear();

    /* Fill the list to its registration capacity, then one more is refused. */
    char name[16];
    for (uint32_t i = 0; i < ES_NS_MAX_SIZE; i++) {
        (void)snprintf(name, sizeof(name), "ns%u", i);
        ASSERT_EQ(ES_NsAdd(list, name, false, 5, &ok, &para), CRYPT_SUCCESS);
    }
    ASSERT_EQ(ES_NsAdd(list, "extra", false, 5, &ok, &para), CRYPT_ENTROPY_ES_NS_FULL);
    (void)TestErrClear();
EXIT:
    ES_NsListFree(list);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_CTRL_ARG_GUARDS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* Argument validation of the ctrl entry points: each rejects a null buffer
       and a length that does not match the command's operand. */
    ENTROPY_EntropySource *es = ENTROPY_EsNew();
    ASSERT_TRUE(es != NULL);
    uint32_t sz = 0;
    bool state = false;
    uint8_t out[4] = {0};

    ASSERT_EQ(ENTROPY_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, NULL, 4), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, (void *)(uintptr_t)"x", 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(es, CRYPT_ENTROPY_GET_POOL_SIZE, NULL, sizeof(sz)), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(es, CRYPT_ENTROPY_GET_POOL_SIZE, &sz, sizeof(sz) + 1), CRYPT_NULL_INPUT);
    ASSERT_EQ(ENTROPY_EsCtrl(es, CRYPT_ENTROPY_GET_STATE, NULL, sizeof(state)), CRYPT_INVALID_ARG);
    ASSERT_EQ(ENTROPY_EsCtrl(es, CRYPT_ENTROPY_GET_STATE, &state, sizeof(state) + 1), CRYPT_INVALID_ARG);
    ASSERT_EQ(ENTROPY_EsCtrl(es, CRYPT_ENTROPY_SET_LOG_CALLBACK, NULL, 0), CRYPT_NULL_INPUT);
    (void)TestErrClear();

    /* Not yet initialized: the read and gather entries refuse before any
       source is touched. */
    ASSERT_EQ(ENTROPY_EsEntropyGet(es, out, sizeof(out)), 0);
    ASSERT_EQ(ENTROPY_EsEntropyGather(es), CRYPT_NULL_INPUT);
    (void)TestErrClear();

    /* A working handle still refuses a null output buffer. */
    ASSERT_EQ(ENTROPY_EsCtrl(es, CRYPT_ENTROPY_GET_STATE, &state, sizeof(state)), CRYPT_SUCCESS);
    ASSERT_EQ(state, false);
EXIT:
    ENTROPY_EsFree(es);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_UNCONFIGURED_STATE_GUARDS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    /* Guards that only an unconfigured or degenerate argument reaches: a delta
       engine whose cutoffs were never armed, a zero-length pool read, and the
       verdict predicates over every code they classify. */
    ES_DeltaNs cold = {0};
    /* stuckCutoff 0 means the engine is unarmed, so the stuck run never counts
       and no verdict latches. */
    ES_DeltaNsProcessRawDelta(&cold, 0);
    ES_DeltaNsProcessRawDelta(&cold, 0);
    ASSERT_EQ(cold.stuckCount, 0);

    ES_EntropyPool *pool = ES_EntropyPoolInit(512);
    ASSERT_TRUE(pool != NULL);
    uint8_t out[8] = {0};
    ASSERT_EQ(ES_EntropyPoolPopBytes(pool, out, 0), 0);
    ES_EntropyPoolDeInit(pool);
    (void)TestErrClear();

    /* Every code the two verdict predicates classify, and one they do not. */
    ASSERT_TRUE(ES_NsVerdictRetires(CRYPT_ENTROPY_ES_DEAD_TIMER));
    ASSERT_TRUE(ES_NsVerdictRetires(CRYPT_ENTROPY_ES_COARSE_TIMER));
    ASSERT_TRUE(ES_NsVerdictRetires(CRYPT_ENTROPY_CONDITION_FAILURE));
    ASSERT_TRUE(ES_NsVerdictRetires(CRYPT_ENTROPY_ES_PERMANENT_FAILURE));
    ASSERT_TRUE(!ES_NsVerdictRetires(CRYPT_ENTROPY_RCT_FAILURE));
    ASSERT_TRUE(ES_NsVerdictDemotes(CRYPT_ENTROPY_RCT_FAILURE));
    ASSERT_TRUE(ES_NsVerdictDemotes(CRYPT_ENTROPY_APT_FAILURE));
    ASSERT_TRUE(!ES_NsVerdictDemotes(CRYPT_ENTROPY_ES_DEAD_TIMER));
EXIT:
    BSL_SAL_CleanseData(&cold, sizeof(cold));
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_BOUNDARY_GUARDS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* Boundary guards of the ES and noise-source layers: NULL handles, a list
       holding nothing usable, and a source that is not armed for reading. */
    ENTROPY_EsFree(NULL);
    ENTROPY_EsDeinit(NULL);

    BslList *empty = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(empty != NULL);
    ASSERT_EQ(ES_NsListInit(empty, false), CRYPT_ENTROPY_ES_NO_NS);
    ES_NsListDeinit(empty);
    (void)TestErrClear();

    /* A registered but uninitialized source refuses the quiet read path. */
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadStream, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};
    ASSERT_EQ(ES_NsAdd(empty, "bnd", false, 5, &method, &para), CRYPT_SUCCESS);
    ES_NoiseSource *ns = BSL_LIST_GetData(BSL_LIST_FirstNode(empty));
    ASSERT_TRUE(ns != NULL);
    uint8_t buf[8] = {0};
    ASSERT_EQ(ES_NsRead(ns, buf, sizeof(buf)), CRYPT_ENTROPY_ES_NS_NOT_AVA);

    /* Armed with governance health tests, a clean stream passes them all. */
    g_entropyStreamPos = 0;
    ASSERT_EQ(ES_NsListInit(empty, true), CRYPT_SUCCESS);
    ASSERT_EQ(ES_NsRead(ns, buf, sizeof(buf)), CRYPT_SUCCESS);
    (void)TestErrClear();
EXIT:
    ES_NsListFree(empty);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_CF_NTG1_MIN_ENTROPY_GUARD_TC001(int mdSize, int accept)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* A conditioner is refused when its digest cannot carry the NTG.1.4
       startup floor: the per-source quota is mdSize * 8 + 64, so 22 bytes is
       the narrowest that reaches 240 bit. */
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    EAL_MdMethod narrow = g_mockMdFinalFail;
    narrow.mdSize = (uint16_t)mdSize;
    ENTROPY_CFPara para = {CRYPT_MD_SHA256, &narrow};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &para, sizeof(para)),
        (accept != 0) ? CRYPT_SUCCESS : CRYPT_ENTROPY_ES_CF_NOT_SUPPORT);
EXIT:
    ENTROPY_EsFree(raw);
    (void)TestErrClear();
    return;
#else
    (void)mdSize;
    (void)accept;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_CF_NULL_METHOD_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* A missing method table is refused before it can be dereferenced. */
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    ENTROPY_CFPara missing = {CRYPT_MD_SHA256, NULL};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &missing, sizeof(missing)),
        CRYPT_ENTROPY_ES_CF_NOT_SUPPORT);
EXIT:
    ENTROPY_EsFree(raw);
    (void)TestErrClear();
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_CF_FINAL_FAIL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    ENTROPY_CFPara para = {CRYPT_MD_SHA256, &g_mockMdFinalFail};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &para, sizeof(para)), CRYPT_SUCCESS);
    CRYPT_EAL_NsPara nsPara = {"mn", false, 8, {NULL, NULL, EntropyReadStream, NULL}, {5, 200, 512}};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ADD_NS, &nsPara, sizeof(nsPara)), CRYPT_SUCCESS);
    g_entropyStreamPos = 0;
    /* final() fails inside getEntropyData, which returns NULL -> MEM_ALLOC_FAIL. */
    ASSERT_EQ(ENTROPY_EsInit(raw), CRYPT_MEM_ALLOC_FAIL);
    (void)TestErrClear();
    ENTROPY_EsFree(raw);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_CF_REINIT_FAIL_TC001(int stage)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* Init runs three times: the persistent context, the transaction context,
       then the re-init that follows a successful final. stage 0 fails the
       second, stage 1 the third. */
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    ENTROPY_CFPara para = {CRYPT_MD_SHA256,
        (stage == 0) ? &g_mockMdReinitFail : &g_mockMdReinitAfterFinal};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_CF, &para, sizeof(para)), CRYPT_SUCCESS);
    CRYPT_EAL_NsPara nsPara = {"mn", false, 8, {NULL, NULL, EntropyReadStream, NULL}, {5, 200, 512}};
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_ADD_NS, &nsPara, sizeof(nsPara)), CRYPT_SUCCESS);
    g_entropyStreamPos = 0;
    g_mockInitCallCount = 0;
    if (stage == 0) {
        /* ES_CfDfInit returns NULL, so the startup seed reports CF_ERROR. */
        ASSERT_EQ(ENTROPY_EsInit(raw), CRYPT_ENTROPY_ES_CF_ERROR);
        ASSERT_EQ(g_mockInitCallCount, 2);
    } else {
        /* final already produced a block; the failing re-init discards it,
           so getEntropyData returns NULL. */
        ASSERT_EQ(ENTROPY_EsInit(raw), CRYPT_MEM_ALLOC_FAIL);
        ASSERT_EQ(g_mockInitCallCount, 3);
    }
    (void)TestErrClear();
    ENTROPY_EsFree(raw);
EXIT:
    g_mockInitCallCount = 0;
    return;
#else
    (void)stage;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_SET_LOG_CB_NULL_DATA_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    ENTROPY_EntropySource *raw = ENTROPY_EsNew();
    ASSERT_TRUE(raw != NULL);
    ASSERT_EQ(ENTROPY_EsCtrl(raw, CRYPT_ENTROPY_SET_LOG_CALLBACK, NULL, 0), CRYPT_NULL_INPUT);
    (void)TestErrClear();
    ENTROPY_EsFree(raw);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EAL_NEWCTX_GUARDS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_EAL_SeedPoolCtx *empty = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    /* minLen > maxLen and maxLen == 0 are rejected before the pool is touched. */
    ASSERT_TRUE(EAL_EntropyNewCtx(NULL, true, 100, 10, 8) == NULL);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_INVALID_ARG);
    ASSERT_TRUE(EAL_EntropyNewCtx(NULL, true, 16, 0, 8) == NULL);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_INVALID_ARG);
    /* Valid lengths but an empty pool fails the seed-pool state check. */
    empty = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(empty != NULL);
    ASSERT_TRUE(EAL_EntropyNewCtx(empty, false, 16, 64, 8) == NULL);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_SEED_POOL_STATE_ERROR);
    CRYPT_EAL_SeedPoolFree(empty);
    empty = NULL;
    /* A populated pool passes the state check; entropy > maxLen*8 is out of range. */
    pool = GetPoolCtx(5, 5, true, false);
    ASSERT_TRUE(pool != NULL);
    ASSERT_TRUE(EAL_EntropyNewCtx(pool, false, 16, 64, 64 * 8 + 1) == NULL);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ENTROPY_RANGE_ERROR);
    /* Valid parameters build and free a context; ctx is freed on the spot and is
       NULL on every failure path, so it never reaches EXIT. */
    EAL_EntropyCtx *ctx = EAL_EntropyNewCtx(pool, false, 16, 64, 64);
    ASSERT_TRUE(ctx != NULL);
    EAL_EntropyFreeCtx(ctx);
    CRYPT_EAL_SeedPoolFree(pool);
    pool = NULL;
EXIT:
    CRYPT_EAL_SeedPoolFree(empty);
    CRYPT_EAL_SeedPoolFree(pool);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EAL_NEWCTX_MALLOC_FAIL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    pool = GetPoolCtx(5, 5, true, false);
    ASSERT_TRUE(pool != NULL);
    /* EAL_EntropyNewCtx allocates twice (the context, then its buffer); failing
       either aborts with CRYPT_MEM_ALLOC_FAIL, and the third injection point is
       past both so the build succeeds. */
    for (int k = 1; k <= 3; k++) {
        g_entropyFailNthK = k;
        g_entropyMallocSeq = 0;
        (void)TestErrClear();
        ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
        EAL_EntropyCtx *ctx = EAL_EntropyNewCtx(pool, false, 16, 64, 64);
        EntropyRestoreMalloc();
        if (k < 3) {
            ASSERT_TRUE(ctx == NULL);
            ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_MEM_ALLOC_FAIL);
        } else {
            ASSERT_TRUE(ctx != NULL);
            EAL_EntropyFreeCtx(ctx);
        }
        (void)TestErrClear();
    }
    CRYPT_EAL_SeedPoolFree(pool);
    pool = NULL;
EXIT:
    CRYPT_EAL_SeedPoolFree(pool);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_POOL_INIT_GUARDS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    /* A zero-size pool is rejected. */
    ASSERT_TRUE(ES_EntropyPoolInit(0) == NULL);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_NULL_INPUT);
#ifdef HITLS_BSL_SAL_MEM
    /* The pool-struct allocation (1st) fails. */
    g_entropyFailNthK = 1;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    ASSERT_TRUE(ES_EntropyPoolInit(512) == NULL);
    EntropyRestoreMalloc();
    /* The ring-buffer allocation (2nd) fails, so the pool struct is freed. */
    g_entropyFailNthK = 2;
    g_entropyMallocSeq = 0;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
    ASSERT_TRUE(ES_EntropyPoolInit(512) == NULL);
    EntropyRestoreMalloc();
#endif
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EAL_SEEDPOOL_GETENTROPY_ERR_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_Data data = {0};
    CRYPT_Range good = {16, 64};
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    CRYPT_EAL_SeedPoolCtx *starved = NULL;
    /* NULL argument guards. */
    ASSERT_EQ(CRYPT_EAL_SeedPoolGetEntropy(NULL, &data, 8, &good), CRYPT_NULL_INPUT);
    pool = GetPoolCtx(5, 5, true, false);
    ASSERT_TRUE(pool != NULL);
    ASSERT_EQ(CRYPT_EAL_SeedPoolGetEntropy(pool, NULL, 8, &good), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_SeedPoolGetEntropy(pool, &data, 8, NULL), CRYPT_NULL_INPUT);
    /* An inverted range makes EAL_EntropyNewCtx fail -> CTX_CREATE_FAILED. */
    CRYPT_Range bad = {100, 10};
    ASSERT_EQ(CRYPT_EAL_SeedPoolGetEntropy(pool, &data, 8, &bad), CRYPT_ENTROPY_CTX_CREATE_FAILED);
    (void)TestErrClear();
    /* A source that yields zero entropy passes context creation but the obtain
       loop reports no entropy. */
    starved = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(starved != NULL);
    CRYPT_EAL_EsPara zeroPara = {false, 8, NULL, (CRYPT_EAL_EntropyGet)EntropyGet0Normal};
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(starved, &zeroPara), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_SeedPoolGetEntropy(starved, &data, 8, &good), CRYPT_SEED_POOL_NO_ENTROPY_OBTAINED);
    (void)TestErrClear();
EXIT:
    BSL_SAL_FREE(data.data);
    CRYPT_EAL_SeedPoolFree(pool);
    CRYPT_EAL_SeedPoolFree(starved);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_EAL_SET_CF_BOGUS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    /* An unknown conditioner name maps to CRYPT_MD_MAX -> ECF_ALG_ERROR. */
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)"no_such_df", strlen("no_such_df")),
        CRYPT_ENTROPY_ECF_ALG_ERROR);
    (void)TestErrClear();
EXIT:
    CRYPT_EAL_EsFree(es);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_ADD_GUARDS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    BslList *list = NULL;
    BslList *list2 = NULL;
    list = ES_NsListCreat();
    ASSERT_TRUE(list != NULL);
    CRYPT_EAL_NsMethod good = {NULL, NULL, EntropyReadVaried, NULL};
    CRYPT_EAL_NsTestPara tp = {5, 200, 512};
    /* A NULL name or an over-range claim is rejected. */
    ASSERT_EQ(ES_NsAdd(list, NULL, false, 1, &good, &tp), CRYPT_NULL_INPUT);
    ASSERT_EQ(ES_NsAdd(list, "n1", false, 9, &good, &tp), CRYPT_NULL_INPUT);
    /* A method without read, or with init/deinit not paired, is rejected. */
    CRYPT_EAL_NsMethod noRead = {NULL, NULL, NULL, NULL};
    ASSERT_EQ(ES_NsAdd(list, "n2", false, 1, &noRead, &tp), CRYPT_NULL_INPUT);
    CRYPT_EAL_NsMethod initNoDeinit = {NULL, EntropyInitTest, EntropyReadVaried, NULL};
    ASSERT_EQ(ES_NsAdd(list, "n3", false, 1, &initNoDeinit, &tp), CRYPT_NULL_INPUT);
    ES_NsListFree(list);
    list = NULL;
#ifdef HITLS_BSL_SAL_MEM
    /* ES_NsCreate does two allocations (the record, then its name); either
       failing yields a create error. The third allocation is the list node
       inside BSL_LIST_AddElement, whose failure frees the record and returns
       the list error. */
    list2 = ES_NsListCreat();
    ASSERT_TRUE(list2 != NULL);
    for (int k = 1; k <= 3; k++) {
        g_entropyFailNthK = k;
        g_entropyMallocSeq = 0;
        ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
        int32_t ret = ES_NsAdd(list2, "mn", false, 1, &good, &tp);
        EntropyRestoreMalloc();
        (void)TestErrClear();
        ASSERT_EQ(ret, (k < 3) ? CRYPT_ENTROPY_ES_CREATE_ERROR : BSL_LIST_MALLOC_FAIL);
    }
    /* An initialized source carries usrdata, so freeing the list without an
       explicit deinit exercises the deinit-on-free path; the counting callback
       proves the deinit actually fired exactly once for that source. */
    CRYPT_EAL_NsMethod lifecycle = {NULL, EntropyInitTest, EntropyReadVaried, EntropyDeinitCount};
    g_entropyDeinitCalls = 0;
    ASSERT_EQ(ES_NsAdd(list2, "lc", false, 1, &lifecycle, &tp), CRYPT_SUCCESS);
    ASSERT_EQ(ES_NsListInit(list2, false), CRYPT_SUCCESS);
    ES_NsListFree(list2);
    list2 = NULL;
    ASSERT_EQ(g_entropyDeinitCalls, 1);
#endif
EXIT:
    ES_NsListFree(list);
    ES_NsListFree(list2);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_LOCK_FAIL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_EAL_Es *es = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    pool = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);

    /* Bring the source up first so a healthy EsEntropyGet returns data; the zero
       it returns once the lock fails is then unambiguously the write-lock bail,
       not an empty pool. */
    uint8_t buf[16] = {0};
    uint32_t poolSize = 512;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha256_df", strlen("sha256_df")),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, &poolSize, sizeof(poolSize)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_EsEntropyGet(es, buf, sizeof(buf)) > 0);

    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_WRITE_LOCK_CB_FUNC, EntropyWriteLockFail), BSL_SUCCESS);

    /* int32_t entry points return the lock error verbatim. The error stack cannot
       be inspected under the stub - it takes the same write lock - so the length
       contrast above is what proves EsEntropyGet's bail. */
    ASSERT_EQ(CRYPT_EAL_EsInit(es), BSL_SAL_ERR_UNKNOWN);
    ASSERT_EQ(CRYPT_EAL_EsEntropyGet(es, buf, sizeof(buf)), 0);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GATHER_ENTROPY, NULL, 0), BSL_SAL_ERR_UNKNOWN);

    CRYPT_EAL_EsPara para = {false, 8, es, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(pool, &para), BSL_SAL_ERR_UNKNOWN);
    CRYPT_Data ent = {NULL, 0};
    CRYPT_Range rng = {16, 64};
    ASSERT_EQ(CRYPT_EAL_SeedPoolGetEntropy(pool, &ent, 128, &rng), BSL_SAL_ERR_UNKNOWN);

    /* Free ignores the lock verdict but must still release under failure. */
    CRYPT_EAL_EsFree(es);
    es = NULL;
    EntropyRestoreLock();
EXIT:
    EntropyRestoreLock();
    CRYPT_EAL_EsFree(es);
    CRYPT_EAL_SeedPoolFree(pool);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
static void EntropyMeasureStuckZero(void *srcCtx)
{
    ES_DeltaNsProcessRawDelta((ES_DeltaNs *)srcCtx, 0);
}
#endif

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DELTA_LATCH_PATHS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    ES_DeltaNs e = {0};
    uint8_t buf[2 * NS_DELTA_RECORD_BYTES] = {0};

    /* A linear ramp (constant first difference) is stuck on delta3:
       stuck count increments to cutoff and latches the intermittent RCT. */
    ES_DeltaNsOsrApply(&e, 3);
    ES_DeltaNsProcessRawDelta(&e, 100);
    ES_DeltaNsProcessRawDelta(&e, 110);
    for (uint32_t i = 0; i < e.stuckCutoff; i++) {
        ES_DeltaNsProcessRawDelta(&e, 120 + i * 10);
    }
    ASSERT_EQ(e.testFailure, NS_ENTROPY_RCT_FAILURE);

    /* A permanent verdict overrides any latched intermittent one, and once
       permanent the latch becomes a no-op for subsequent samples. */
    e.rct.count = e.rctPermCutoff - 1;
    e.rct.lastData = 0;
    ES_DeltaNsProcessRawDelta(&e, 0);
    ASSERT_EQ(e.testFailure, NS_ENTROPY_PERMANENT_FAILURE);
    ES_DeltaNsProcessRawDelta(&e, 0);
    ASSERT_EQ(e.testFailure, NS_ENTROPY_PERMANENT_FAILURE);

    /* Read on an APT-latched engine returns the public APT failure code. */
    ES_DeltaNsStartupReset(&e);
    ES_DeltaNsOsrApply(&e, 3);
    e.testFailure = NS_ENTROPY_APT_FAILURE;
    ASSERT_EQ(ES_DeltaNsRead(&e, EntropyMeasureStuckZero, &e, buf, NS_DELTA_RECORD_BYTES),
        CRYPT_ENTROPY_APT_FAILURE);

    /* Read on a permanent-latched engine returns the permanent failure code. */
    e.testFailure = NS_ENTROPY_PERMANENT_FAILURE;
    ASSERT_EQ(ES_DeltaNsRead(&e, EntropyMeasureStuckZero, &e, buf, NS_DELTA_RECORD_BYTES),
        CRYPT_ENTROPY_ES_PERMANENT_FAILURE);

    /* A measure that triggers a latch mid-read returns immediately. */
    ES_DeltaNsStartupReset(&e);
    ES_DeltaNsOsrApply(&e, 3);
    e.stuckCount = e.stuckCutoff - 1;
    ASSERT_EQ(ES_DeltaNsRead(&e, EntropyMeasureStuckZero, &e, buf, sizeof(buf)), CRYPT_ENTROPY_RCT_FAILURE);

    /* Recovery window with unconfigured osr (stuckCutoff stays 0) fails. */
    ES_DeltaNs rec = {0};
    rec.timerCheckOsr = 3;
    EntropyRecScriptCtx rctx = {&rec, 0, 0, 0, 0x9E3779B97F4A7C15ULL};
    ASSERT_EQ(ES_DeltaNsRecoveryWindow(&rec, EntropyRawRecScript, EntropyMeasureRecScript, &rctx),
        CRYPT_ENTROPY_RCT_FAILURE);

    /* OsrWalk with a measure that fails every osr returns the last verdict. */
    ES_DeltaNs walk = {0};
    ASSERT_EQ(ES_DeltaNsOsrWalk(&walk, 3, 15, EntropyMeasureStuckZero, &walk),
        CRYPT_ENTROPY_RCT_FAILURE);
EXIT:
    BSL_SAL_CleanseData(&e, sizeof(e));
    BSL_SAL_CleanseData(&rec, sizeof(rec));
    BSL_SAL_CleanseData(&walk, sizeof(walk));
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_RUNTIME_EDGE_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS)
    CRYPT_EAL_Es *es = NULL;
    ES_CfMethod *cf = NULL;
    EAL_MdMethod origMd = {0};
    es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    /* Strip built-in sources so the conditioner error path is deterministic and
       does not depend on host-timer quality. */
    ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(uintptr_t)"sha256_df",
        strlen("sha256_df")), CRYPT_SUCCESS);
    /* A credited synthetic source drives collection into the conditioner; the
       uncredited one is mixed in with zero claim. */
    CRYPT_EAL_NsPara cred = {"cred", false, 8, {NULL, NULL, EntropyReadStream, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &cred, sizeof(cred)), CRYPT_SUCCESS);
    CRYPT_EAL_NsPara aux = {"aux", false, 0, {NULL, NULL, EntropyReadStream, NULL}, {5, 200, 512}};
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &aux, sizeof(aux)), CRYPT_SUCCESS);
    g_entropyStreamPos = 0;
    ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);

    /* Swap the embedded method (not the entire ES_CfMethod) so getCfOutLen keeps
       using the original ctx, but init/update see the mock. */
    cf = es->es->cfMeth;
    origMd = cf->meth.mdMeth;

    /* Runtime conditionerCtx NULL: init fails on the swapped method. */
    cf->meth.mdMeth = g_mockMdInitFail;
    ASSERT_EQ(ENTROPY_EsEntropyGather(es->es), CRYPT_ENTROPY_ES_CF_ERROR);
    (void)TestErrClear();

    /* Runtime conditionerErr: update fails on the swapped method. */
    cf->meth.mdMeth = g_mockMdUpdateFail;
    ASSERT_EQ(ENTROPY_EsEntropyGather(es->es), CRYPT_ENTROPY_ES_CF_ERROR);
    (void)TestErrClear();

    cf->meth.mdMeth = origMd;
    cf = NULL;
EXIT:
    /* Restore the real method on the failure path so EsFree runs the real
       conditioner cleanup instead of the mock's no-op freeCtx. */
    if (cf != NULL) {
        cf->meth.mdMeth = origMd;
    }
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_LIST_INIT_EDGE_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    TestMemInit();
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadDiffData, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};

    /* A permanently failed credited source sets creditedRet at list init. */
    BslList *list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    ASSERT_EQ(ES_NsAdd(list, "perm-cred", false, 5, &method, &para), CRYPT_SUCCESS);
    ES_NoiseSource *ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ns->permanentFailure = true;
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
    (void)TestErrClear();
    ES_NsListFree(list);
    list = NULL;

    /* A private negative init code is normalized to NS_NOT_AVA. */
    list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    ASSERT_EQ(ES_NsAdd(list, "neg-code", false, 5, &method, &para), CRYPT_SUCCESS);
    ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ns->initAt = EntropyInitAtNegCode;
    ns->osr = 3;
    ns->osrMax = 15;
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_ENTROPY_ES_NS_NOT_AVA);
    (void)TestErrClear();
    ES_NsListFree(list);
    list = NULL;

    /* Second structural failure does not overwrite the first structuralRet. */
    list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    ASSERT_EQ(ES_NsAdd(list, "struct1", false, 5, &method, &para), CRYPT_SUCCESS);
    ASSERT_EQ(ES_NsAdd(list, "struct2", false, 5, &method, &para), CRYPT_SUCCESS);
    BslListNode *node1 = BSL_LIST_FirstNode(list);
    BslListNode *node2 = BSL_LIST_GetNextNode(list, node1);
    ES_NoiseSource *ns1 = BSL_LIST_GetData(node1);
    ES_NoiseSource *ns2 = BSL_LIST_GetData(node2);
    ns1->initAt = EntropyInitAtCondFail; ns1->osr = 3; ns1->osrMax = 15;
    ns2->initAt = EntropyInitAtCondFail; ns2->osr = 3; ns2->osrMax = 15;
    /* Both sources fail structurally with CONDITION_FAILURE; the first sets
       structuralRet and the second must not overwrite it. */
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_ENTROPY_CONDITION_FAILURE);
    ASSERT_EQ(ns1->permanentFailure, true);
    ASSERT_EQ(ns2->permanentFailure, true);
    (void)TestErrClear();
    ES_NsListFree(list);
    list = NULL;

    /* All-fail with no structural: creditedRet path in the summary chain. */
    list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    ASSERT_EQ(ES_NsAdd(list, "cred-fail", false, 5, &method, &para), CRYPT_SUCCESS);
    ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ns->initAt = EntropyInitAtNegCode; ns->osr = 3; ns->osrMax = 15;
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_ENTROPY_ES_NS_NOT_AVA);
    (void)TestErrClear();
    ES_NsListFree(list);
    list = NULL;

    /* All-fail with no credited source: cycleRet path in the summary chain. */
    list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    ASSERT_EQ(ES_NsAdd(list, "cycle-fail", false, 0, &method, &para), CRYPT_SUCCESS);
    ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ns->initAt = EntropyInitAtNegCode; ns->osr = 3; ns->osrMax = 15;
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_ENTROPY_ES_NS_NOT_AVA);
    (void)TestErrClear();
    ES_NsListFree(list);
    list = NULL;

EXIT:
    ES_NsListFree(list);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ES_STARTUP_RUNTIME_FAULT_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_BSL_SAL_MEM)
    CRYPT_EAL_Es *es = NULL;
    /* Startup pool insufficient: CF output (32 bytes) exceeds pool space. This
       covers the early fast-path guard in EsStartupSeed; the same shortfall is
       also caught at pool-push time (identical threshold), so the assert pins the
       returned code rather than uniquely binding the early branch. Built-in
       sources are stripped config-awarely so only the custom credited source
       remains (no real-timer calibration, no config-specific NS_NOT_FOUND). */
    {
        es = CRYPT_EAL_EsNew();
        ASSERT_TRUE(es != NULL);
        ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
        es->es->poolSize = 16;
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(uintptr_t)"sha256_df",
            strlen("sha256_df")), CRYPT_SUCCESS);
        CRYPT_EAL_NsPara para = {"cred", false, 8, {NULL, NULL, EntropyReadStream, NULL}, {5, 200, 512}};
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para)), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_ENTROPY_ES_POOL_INSUFFICIENT);
        (void)TestErrClear();
        CRYPT_EAL_EsFree(es);
        es = NULL;
    }

    /* Startup allocation failure: some allocation during EsInit (conditioner ctx
       or collection buffer) fails and surfaces as MEM_ALLOC_FAIL. The sweep finds
       the failing point; it exercises the malloc-fail branches without binding to
       one specific allocation. */
    {
        bool sawAlloc = false;
        for (int k = 1; k <= 30; k++) {
            es = CRYPT_EAL_EsNew();
            ASSERT_TRUE(es != NULL);
            ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
            ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(uintptr_t)"sha256_df",
                strlen("sha256_df")), CRYPT_SUCCESS);
            CRYPT_EAL_NsPara para = {"cred", false, 8, {NULL, NULL, EntropyReadStream, NULL}, {5, 200, 512}};
            ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para)), CRYPT_SUCCESS);
            g_entropyFailNthK = k;
            g_entropyMallocSeq = 0;
            ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
            int32_t ret = CRYPT_EAL_EsInit(es);
            EntropyRestoreMalloc();
            (void)TestErrClear();
            if (ret == CRYPT_MEM_ALLOC_FAIL) {
                sawAlloc = true;
            }
            CRYPT_EAL_EsFree(es);
            es = NULL;
            if (ret == CRYPT_SUCCESS) {
                break;
            }
        }
        ASSERT_TRUE(sawAlloc);
    }

    /* Runtime buffer malloc fail: init first, then scan gather allocations. */
    {
        es = CRYPT_EAL_EsNew();
        ASSERT_TRUE(es != NULL);
        ASSERT_EQ(EntropyRemoveBuiltInNs(es), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(uintptr_t)"sha256_df",
            strlen("sha256_df")), CRYPT_SUCCESS);
        CRYPT_EAL_NsPara para = {"cred", false, 8, {NULL, NULL, EntropyReadStream, NULL}, {5, 200, 512}};
        ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ADD_NS, &para, sizeof(para)), CRYPT_SUCCESS);
        g_entropyStreamPos = 0;
        ASSERT_EQ(CRYPT_EAL_EsInit(es), CRYPT_SUCCESS);

        bool sawAlloc = false;
        for (int k = 1; k <= 10; k++) {
            g_entropyFailNthK = k;
            g_entropyMallocSeq = 0;
            ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMallocFailNth), BSL_SUCCESS);
            int32_t ret = ENTROPY_EsEntropyGather(es->es);
            EntropyRestoreMalloc();
            (void)TestErrClear();
            if (ret == CRYPT_MEM_ALLOC_FAIL) {
                sawAlloc = true;
                break;
            }
        }
        ASSERT_TRUE(sawAlloc);
        CRYPT_EAL_EsFree(es);
        es = NULL;
    }
EXIT:
    EntropyRestoreMalloc();
    CRYPT_EAL_EsFree(es);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_NS_DEMOTE_REINIT_FAIL_TC001(void)
{
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    TestMemInit();
    BslList *list = NULL;
    BslList *list2 = NULL;
    CRYPT_EAL_NsMethod method = {NULL, NULL, EntropyReadNormal, NULL};
    CRYPT_EAL_NsTestPara para = {5, 200, 512};

    /* Scenario 1 binds the demote re-init branch: initAt succeeds once, the 0xff
       startup window trips RCT, the demote loop re-inits, and that re-init fails,
       so the init count of 2 is the observable. */
    list = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list != NULL);
    ASSERT_EQ(ES_NsAdd(list, "demote-reinit", false, 5, &method, &para), CRYPT_SUCCESS);
    ES_NoiseSource *ns = BSL_LIST_GetData(BSL_LIST_FirstNode(list));
    ASSERT_TRUE(ns != NULL);
    ns->initAt = EntropyInitAtSucceedThenFail;
    ns->deinit = EntropyDeinitTest;
    ns->osr = 3;
    ns->osrMax = 15;
    g_entropyInitAtStatefulCount = 0;
    ASSERT_EQ(ES_NsListInit(list, true), CRYPT_ENTROPY_ES_NS_NOT_AVA);
    ASSERT_EQ(g_entropyInitAtStatefulCount, 2);
    (void)TestErrClear();

    /* Scenario 2 binds the demote-path deinit itself: initAt always succeeds but
       0xff trips RCT at every osr, so the demote loop walks the whole 3..15
       ladder and deinits on each rung. The counting deinit reaches >= 2; remove
       the demote deinit and it collapses to the single ES_NsListDeinit fallback
       (== 1), so this count uniquely binds the branch. */
    list2 = BSL_LIST_New(sizeof(ES_NoiseSource *));
    ASSERT_TRUE(list2 != NULL);
    ASSERT_EQ(ES_NsAdd(list2, "demote-walk", false, 5, &method, &para), CRYPT_SUCCESS);
    ES_NoiseSource *ns2 = BSL_LIST_GetData(BSL_LIST_FirstNode(list2));
    ASSERT_TRUE(ns2 != NULL);
    ns2->initAt = EntropyInitAtAlwaysSucceed;
    ns2->deinit = EntropyDeinitCount;
    ns2->osr = 3;
    ns2->osrMax = 15;
    g_entropyDeinitCalls = 0;
    ASSERT_EQ(ES_NsListInit(list2, true), CRYPT_ENTROPY_RCT_FAILURE);
    ASSERT_TRUE(g_entropyDeinitCalls >= 2);
    (void)TestErrClear();
EXIT:
    g_entropyInitAtStatefulCount = 0;
    g_entropyDeinitCalls = 0;
    ES_NsListFree(list);
    ES_NsListFree(list2);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_GUARD_NULL_TC001(void)
{
/* The delta engine helpers below only compile under a noise source that pulls
   it in. */
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)
    ES_NoiseSource *jitter = NULL;
#endif
    /* osr=0 is rejected before any sampling. */
    TimerSampleCursor cur = {0};
    ASSERT_EQ(ES_DeltaTimerCheck(TimerSampleNext, &cur, 1, 0),
        CRYPT_ENTROPY_CTRL_INVALID_PARAM);
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)
    /* CpuJitter NULL usrdata guards on osrGet, read, and recover. */
    ASSERT_EQ(ES_CpuJitterOsrGet(NULL), 0u);
    jitter = ES_CpuJitterGetCtx();
    ASSERT_TRUE(jitter != NULL);
    uint8_t buf[4] = {0};
    ASSERT_EQ(jitter->read(NULL, 0, buf, sizeof(buf)), CRYPT_NULL_INPUT);
    ASSERT_EQ(jitter->read(jitter, 0, NULL, sizeof(buf)), CRYPT_NULL_INPUT);
    ASSERT_EQ(jitter->read(jitter, 0, buf, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(jitter->recover(NULL), CRYPT_NULL_INPUT);
    FreeNoiseSource(jitter);
    jitter = NULL;
#endif
EXIT:
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)
    FreeNoiseSource(jitter);
#endif
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_RECOVER_WRAPPERS_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && \
    (defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
    ES_NoiseSource *ns = NULL;
    /* The built-in recover wrappers are thin glue over ES_DeltaNsRecoveryWindow
       (already unit-tested) and the production EsRecoverNs orchestration (already
       covered with a mock recover). Exercise each wrapper's NULL guard and its
       delegation on a real initialized source: initAt runs the same
       calibration recover re-runs, so a source that inits cleanly also recovers
       cleanly on this host. */
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)
    ns = ES_CpuJitterGetCtx();
    ASSERT_TRUE(ns != NULL);
    ASSERT_EQ(ns->recover(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(ns->initAt(ns->para, ns->osr, &ns->usrdata), CRYPT_SUCCESS);
    ASSERT_EQ(ns->recover(ns->usrdata), CRYPT_SUCCESS);
    FreeNoiseSource(ns);
    ns = NULL;
#endif
#if defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
    ns = ES_HashLoopGetCtx();
    ASSERT_TRUE(ns != NULL);
    ASSERT_EQ(ns->recover(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(ns->initAt(ns->para, ns->osr, &ns->usrdata), CRYPT_SUCCESS);
    ASSERT_EQ(ns->recover(ns->usrdata), CRYPT_SUCCESS);
    FreeNoiseSource(ns);
    ns = NULL;
#endif
EXIT:
    FreeNoiseSource(ns);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_HASHLOOP_GUARD_NULL_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
    ES_NoiseSource *ns = ES_HashLoopGetCtx();
    ASSERT_TRUE(ns != NULL);
    uint8_t buf[4] = {0};
    /* read rejects a NULL ctx/buf and a zero length before dereferencing. */
    ASSERT_EQ(ns->read(NULL, 0, buf, sizeof(buf)), CRYPT_NULL_INPUT);
    ASSERT_EQ(ns->read(ns, 0, NULL, sizeof(buf)), CRYPT_NULL_INPUT);
    ASSERT_EQ(ns->read(ns, 0, buf, 0), CRYPT_NULL_INPUT);
    /* osrGet and deinit tolerate NULL usrdata. */
    ASSERT_EQ(ES_HashLoopOsrGet(NULL), 0u);
    ns->deinit(NULL);
EXIT:
    FreeNoiseSource(ns);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_ECF_ALG_ERR_TC001(void)
{
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_MAC)
    ExternalConditioningFunction ecf = EAL_EntropyGetECF(CRYPT_MAC_CMAC_AES128);
    ASSERT_TRUE(ecf != NULL);
    uint8_t in[32] = {0};
    uint8_t out[64] = {0};
    uint32_t outLen = sizeof(out);
    /* An unsupported MAC id fails ctx creation inside the conditioning function. */
    ASSERT_EQ(ecf(CRYPT_MAC_MAX, in, sizeof(in), out, &outLen), CRYPT_ENTROPY_CONDITION_FAILURE);
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_ENTROPY_DUAL_NS_MEMORY_TC001(void)
{
#if defined(HITLS_CRYPTO_ENTROPY_SYS) && defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && \
    defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
    CRYPT_EAL_Es *es = NULL;
    uint8_t out[32] = {0};
    EntropyMemProbeReset();
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, EntropyMemProbeMalloc), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, EntropyMemProbeFree), BSL_SUCCESS);

    es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);
    uint64_t afterNew = g_memLive;
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)"sha3_256_df",
        strlen("sha3_256_df")), CRYPT_SUCCESS);
    if (CRYPT_EAL_EsInit(es) != CRYPT_SUCCESS) {
        printf("[mem] EsInit unavailable on this host, reporting EsNew only\n");
        goto EXIT;
    }
    uint64_t afterInit = g_memLive;
    uint64_t peakInit = g_memPeak;
    (void)CRYPT_EAL_EsEntropyGet(es, out, sizeof(out));
    uint64_t afterGet = g_memLive;
    uint64_t peakGet = g_memPeak;

    printf("[mem] EsNew  live=%llu B\n", (unsigned long long)afterNew);
    printf("[mem] EsInit live=%llu B  peak=%llu B\n",
        (unsigned long long)afterInit, (unsigned long long)peakInit);
    printf("[mem] Get    live=%llu B  peak=%llu B\n",
        (unsigned long long)afterGet, (unsigned long long)peakGet);
    printf("[mem] cumulative allocated=%llu B\n", (unsigned long long)g_memTotal);
    ASSERT_TRUE(afterInit > 0);
EXIT:
    if (es != NULL) {
        CRYPT_EAL_EsFree(es);
    }
    printf("[mem] after Free live=%llu B\n", (unsigned long long)g_memLive);
    EntropyRestoreMalloc();
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, NULL);
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */
