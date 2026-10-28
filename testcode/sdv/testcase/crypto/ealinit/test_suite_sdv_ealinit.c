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
#include "stub_utils.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_init.h"
#include "bsl_err.h"
#include "bsl_err_internal.h"
#include "crypt_types.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_cipher.h"
#include "asmcap_local.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "crypt_eal_init.h"
#include "crypt_provider.h"
#include "crypt_util_rand.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions - Define all functions to be stubbed
 * ============================================================================ */
STUB_DEFINE_RET0(bool, IsSupportAVX);
STUB_DEFINE_RET0(bool, IsSupportAES);
STUB_DEFINE_RET0(bool, IsSupportNEON);
STUB_DEFINE_RET0(bool, IsSupportBMI1);
STUB_DEFINE_RET0(bool, IsSupportMOVBE);
STUB_DEFINE_RET0(int32_t, CRYPT_AES_AsmCheck);
STUB_DEFINE_RET0(int32_t, CRYPT_GHASH_AsmCheck);
STUB_DEFINE_RET0(int32_t, CRYPT_POLY1305_AsmCheck);
STUB_DEFINE_RET1(int32_t, BSL_SAL_ThreadWriteLock, BSL_SAL_ThreadLockHandle);
STUB_DEFINE_RET1(int32_t, BSL_SAL_ThreadUnlock, BSL_SAL_ThreadLockHandle);
STUB_DEFINE_RET1(int32_t, BSL_SAL_ThreadLockNew, BSL_SAL_ThreadLockHandle *);
STUB_DEFINE_VOID1(BSL_SAL_ThreadLockFree, BSL_SAL_ThreadLockHandle);
STUB_DEFINE_RET2(int32_t, BSL_SAL_ThreadRunOnce, BSL_SAL_OnceControl *, BSL_SAL_ThreadInitRoutine);
#ifdef HITLS_CRYPTO_PROVIDER
STUB_DEFINE_RET1(CRYPT_EAL_LibCtx *, GetCurrentProviderLibCtx, CRYPT_EAL_LibCtx *);
#endif
#if defined(HITLS_BSL_INIT) && defined(HITLS_CRYPTO_ENTROPY) && \
    defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DRBG)
STUB_DEFINE_VOID0(GetCpuInstrSupportState);
STUB_DEFINE_RET0(int32_t, BSL_GLOBAL_Init);
STUB_DEFINE_RET0(int32_t, BSL_GLOBAL_DeInit);
STUB_DEFINE_RET0(int32_t, EAL_SeedDrbgLockInit);
STUB_DEFINE_VOID0(EAL_SeedDrbgLockDeInit);
STUB_DEFINE_RET0(int32_t, CRYPT_EAL_InitPreDefinedProviders);
STUB_DEFINE_VOID0(CRYPT_EAL_FreePreDefinedProviders);
STUB_DEFINE_RET6(int32_t, CRYPT_EAL_ProviderRandInitCtx, CRYPT_EAL_LibCtx *, int32_t, const char *,
    const uint8_t *, uint32_t, BSL_Param *);
STUB_DEFINE_VOID1(CRYPT_EAL_RandDeinitEx, CRYPT_EAL_LibCtx *);
STUB_DEFINE_RET5(int32_t, CRYPT_EAL_RandInit, CRYPT_RAND_AlgId, CRYPT_RandSeedMethod *, void *,
    const uint8_t *, uint32_t);
#endif

/* ============================================================================
 * Helper Functions
 * ============================================================================ */
#define DATA_LEN (64)
void ResetStatus(void)
{
    CRYPT_EAL_RandDeinit();
    BSL_GLOBAL_DeInit();
}

/* ============================================================================
 * Stub Function Implementations
 * ============================================================================ */
bool STUB_IsSupportAVX()
{
    return false;
}

bool STUB_CRYPT_AES_AsmCheck()
{
    return false;
}

bool STUB_IsSupportNEON()
{
    return false;
}

bool STUB_IsSupportBMI1()
{
    return false;
}

bool STUB_IsSupportMOVBE()
{
    return false;
}

bool STUB_IsSupportAES()
{
    return false;
}

int32_t STUB_CRYPT_GHASH_AsmCheck()
{
    return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
}

int32_t STUB_CRYPT_POLY1305_AsmCheck()
{
    return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
}

static int32_t STUB_BSL_SAL_ThreadWriteLock_Fail(BSL_SAL_ThreadLockHandle lock)
{
    (void)lock;
    return BSL_SAL_ERR_UNKNOWN;
}

#ifdef HITLS_CRYPTO_PROVIDER
static uint32_t g_initProviderCreates;

/* Simulate first provider access without depending on the process-wide once state. */
static CRYPT_EAL_LibCtx *STUB_GetCurrentProviderLibCtx_Fresh(CRYPT_EAL_LibCtx *libCtx)
{
    if (libCtx != NULL) {
        return libCtx;
    }
    if (CRYPT_EAL_GetGlobalLibCtx() == NULL) {
        if (CRYPT_EAL_InitPreDefinedProviders() != CRYPT_SUCCESS) {
            return NULL;
        }
        g_initProviderCreates++;
    }
    return CRYPT_EAL_GetGlobalLibCtx();
}
#endif

static int32_t STUB_BSL_SAL_ThreadRunOnce_Fail(BSL_SAL_OnceControl *once, BSL_SAL_ThreadInitRoutine init)
{
    (void)once;
    (void)init;
    return BSL_SAL_ERR_UNKNOWN;
}

static uint32_t g_initLockCreates;
static uint32_t g_initLockFrees;
static bool g_initLockFail;
static bool g_initLockNull;
static bool g_initLockTracking;
static BSL_SAL_ThreadLockHandle g_testInitLock;
static BSL_SAL_OnceControl *g_testInitOnce;

static int32_t STUB_BSL_SAL_ThreadRunOnce_Track(BSL_SAL_OnceControl *once, BSL_SAL_ThreadInitRoutine init)
{
    if (g_testInitOnce == NULL) {
        g_testInitOnce = once;
    }
    bool previous = g_initLockTracking;
    g_initLockTracking = once == g_testInitOnce;
    int32_t ret = get_real_BSL_SAL_ThreadRunOnce()(once, init);
    g_initLockTracking = previous;
    return ret;
}

static int32_t STUB_BSL_SAL_ThreadLockNew_Count(BSL_SAL_ThreadLockHandle *lock)
{
    if (!g_initLockTracking) {
        return get_real_BSL_SAL_ThreadLockNew()(lock);
    }
    g_initLockCreates++;
    if (g_initLockFail) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    int32_t ret = BSL_SUCCESS;
    if (g_initLockNull) {
        *lock = NULL;
    } else {
        ret = get_real_BSL_SAL_ThreadLockNew()(lock);
    }
    if (ret == BSL_SUCCESS) {
        g_testInitLock = *lock;
    }
    return ret;
}

static void STUB_BSL_SAL_ThreadLockFree_Count(BSL_SAL_ThreadLockHandle lock)
{
    if (lock != NULL && lock == g_testInitLock) {
        g_initLockFrees++;
        g_testInitLock = NULL;
    }
    get_real_BSL_SAL_ThreadLockFree()(lock);
}

static int32_t STUB_BSL_SAL_ThreadWriteLock_Null(BSL_SAL_ThreadLockHandle lock)
{
    return lock == NULL ? BSL_SUCCESS : get_real_BSL_SAL_ThreadWriteLock()(lock);
}

static int32_t STUB_BSL_SAL_ThreadUnlock_Null(BSL_SAL_ThreadLockHandle lock)
{
    return lock == NULL ? BSL_SUCCESS : get_real_BSL_SAL_ThreadUnlock()(lock);
}

#if defined(HITLS_BSL_INIT) && defined(HITLS_CRYPTO_ENTROPY) && \
    defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DRBG)
static uint64_t g_initFailOpt;
static struct {
    uint64_t attempted;
    uint32_t bslFrees;
    uint32_t lockFrees;
    uint32_t providerFrees;
    uint32_t providerRandFrees;
} g_initRollback;

static void STUB_GetCpuInstrSupportState_Count(void)
{
    g_initRollback.attempted |= CRYPT_EAL_INIT_CPU;
    get_real_GetCpuInstrSupportState()();
}

static int32_t STUB_BSL_GLOBAL_Init_Fail(void)
{
    g_initRollback.attempted |= CRYPT_EAL_INIT_BSL;
    return g_initFailOpt == CRYPT_EAL_INIT_BSL ? CRYPT_MEM_ALLOC_FAIL : get_real_BSL_GLOBAL_Init()();
}

static int32_t STUB_BSL_GLOBAL_DeInit_Count(void)
{
    g_initRollback.bslFrees++;
    return get_real_BSL_GLOBAL_DeInit()();
}

static int32_t STUB_EAL_SeedDrbgLockInit_Fail(void)
{
    g_initRollback.attempted |= CRYPT_EAL_INIT_LOCK;
    return g_initFailOpt == CRYPT_EAL_INIT_LOCK ? CRYPT_MEM_ALLOC_FAIL : get_real_EAL_SeedDrbgLockInit()();
}

static void STUB_EAL_SeedDrbgLockDeInit_Count(void)
{
    g_initRollback.lockFrees++;
    get_real_EAL_SeedDrbgLockDeInit()();
}

static int32_t STUB_CRYPT_EAL_InitPreDefinedProviders_Fail(void)
{
    g_initRollback.attempted |= CRYPT_EAL_INIT_PROVIDER;
    return g_initFailOpt == CRYPT_EAL_INIT_PROVIDER ?
        CRYPT_MEM_ALLOC_FAIL : get_real_CRYPT_EAL_InitPreDefinedProviders()();
}

static void STUB_CRYPT_EAL_FreePreDefinedProviders_Count(void)
{
    g_initRollback.providerFrees++;
    get_real_CRYPT_EAL_FreePreDefinedProviders()();
}

static int32_t STUB_CRYPT_EAL_ProviderRandInitCtx_Fail(CRYPT_EAL_LibCtx *libCtx, int32_t algId,
    const char *attrName, const uint8_t *pers, uint32_t persLen, BSL_Param *param)
{
    g_initRollback.attempted |= CRYPT_EAL_INIT_PROVIDER_RAND;
    return g_initFailOpt == CRYPT_EAL_INIT_PROVIDER_RAND ? CRYPT_MEM_ALLOC_FAIL :
        get_real_CRYPT_EAL_ProviderRandInitCtx()(libCtx, algId, attrName, pers, persLen, param);
}

static void STUB_CRYPT_EAL_RandDeinitEx_Count(CRYPT_EAL_LibCtx *libCtx)
{
    g_initRollback.providerRandFrees++;
    get_real_CRYPT_EAL_RandDeinitEx()(libCtx);
}

static int32_t STUB_CRYPT_EAL_RandInit_Fail(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth,
    void *seedCtx, const uint8_t *pers, uint32_t persLen)
{
    g_initRollback.attempted |= CRYPT_EAL_INIT_RAND;
    return g_initFailOpt == CRYPT_EAL_INIT_RAND ? CRYPT_MEM_ALLOC_FAIL :
        get_real_CRYPT_EAL_RandInit()(id, seedMeth, seedCtx, pers, persLen);
}
#endif

#define CRYPT_INIT_ABILITY_CPU_POS   0
#define CRYPT_INIT_ABILITY_BSL_POS   1
#define CRYPT_INIT_ABILITY_RAND_POS  2

#define CRYPT_INIT_ABILITY_BITMAP(value, pos) (((value) >> (pos)) & 0x1)
#define CRYPT_INIT_SUPPORT_ABILITY(cap, pos) (CRYPT_INIT_ABILITY_BITMAP(cap, pos) != 0)

#define DRBG_MAX_OUTPUT_SIZE (1 << 16)

#if defined(HITLS_CRYPTO_DRBG)
#define INIT_THREAD_NUM (8)
#define INIT_RACE_ROUND (32)

typedef struct {
    int32_t ret;
} InitThreadArg;

static pthread_mutex_t g_initStartMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_initStartCond = PTHREAD_COND_INITIALIZER;
static uint32_t g_initWaiting;
static bool g_initStart;

static void WaitForInitStart(void)
{
    pthread_mutex_lock(&g_initStartMutex);
    g_initWaiting++;
    pthread_cond_broadcast(&g_initStartCond);
    while (!g_initStart) {
        pthread_cond_wait(&g_initStartCond, &g_initStartMutex);
    }
    pthread_mutex_unlock(&g_initStartMutex);
}

static void ReleaseInitThreads(uint32_t started)
{
    pthread_mutex_lock(&g_initStartMutex);
    while (g_initWaiting < started) {
        pthread_cond_wait(&g_initStartCond, &g_initStartMutex);
    }
    g_initStart = true;
    pthread_cond_broadcast(&g_initStartCond);
    pthread_mutex_unlock(&g_initStartMutex);
}

static void *ConcurrentInitThread(void *ptr)
{
    InitThreadArg *arg = (InitThreadArg *)ptr;
    WaitForInitStart();
    arg->ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    return NULL;
}

#endif

#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DRBG)
/*
 * Occupying the global DRBG makes the RAND step of CRYPT_EAL_Init fail, so
 * the rollback runs after the ProviderRand step already succeeded.
 */
static int32_t ForceRandInitFailure(void)
{
    int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_ClearError();
    }
    return ret;
}
#endif

/**
 * @test SDV_CRYPT_INIT_LOCK_FAILURE_TC001
 * @brief Propagate run-once and write-lock failures on repeated init.
 * @expect Init returns the lock error even when CPU initialization is complete.
 */
/* BEGIN_CASE */
void SDV_CRYPT_INIT_LOCK_FAILURE_TC001(void)
{
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU), CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_ThreadRunOnce, STUB_BSL_SAL_ThreadRunOnce_Fail);
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU), BSL_SAL_ERR_UNKNOWN);
    STUB_RESTORE(BSL_SAL_ThreadRunOnce);
    STUB_REPLACE(BSL_SAL_ThreadWriteLock, STUB_BSL_SAL_ThreadWriteLock_Fail);
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU), BSL_SAL_ERR_UNKNOWN);
    STUB_RESTORE(BSL_SAL_ThreadWriteLock);
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU), CRYPT_SUCCESS);

EXIT:
    STUB_RESTORE(BSL_SAL_ThreadRunOnce);
    STUB_RESTORE(BSL_SAL_ThreadWriteLock);
    BSL_ERR_ClearError();
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_INIT_FUNC_TC001
* @spec  -
* @title  CRYPT_EAL_Init functional test as constructor
* @precon  nan
* @brief  1. CRYPT_EAL_Init called as constructor
          2. check if DRBG is initialized.
          3、check if BSL is initialized.
* @expect 1. DRBG is initialized
          2、BSL is initialized
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_INIT_FUNC_TC001()
{
#if defined(HITLS_EAL_INIT_OPTS)
    uint8_t output[DATA_LEN];
    uint32_t len = DATA_LEN;
    int32_t ret = CRYPT_SUCCESS;
    if(CRYPT_INIT_SUPPORT_ABILITY(HITLS_EAL_INIT_OPTS, CRYPT_INIT_ABILITY_RAND_POS)) {
        ret = CRYPT_EAL_ERR_DRBG_REPEAT_INIT;
    }
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0) == ret);
    ASSERT_TRUE(CRYPT_EAL_Randbytes(output, len) == CRYPT_SUCCESS);
EXIT:
    ResetStatus();
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_CRYPT_EAL_Init_TC002
 * @title  Check if cpu capability is called at entry point.
 * @precon nan
 * @brief
 *    1. STUB function
 *    1. call CRYPT_EAL_CipherNewCtx
 * @expect
 *    1. CRYPT_EAL_CipherNewCtx returns NULL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CRYPT_EAL_Init_TC002()
{
    CRYPT_EAL_CipherCtx *ctx = NULL;
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_CipherFreeCtx(ctx);
#if defined(HITLS_CRYPTO_ASM_CHECK)
#if defined(__x86_64__)
#if defined(HITLS_CRYPTO_AES_ASM)
    STUB_REPLACE(IsSupportAVX, STUB_IsSupportAVX);
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx == NULL);
#endif
#if defined(HITLS_CRYPTO_SM4_ASM)
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
    ASSERT_TRUE(ctx == NULL);
#endif
    STUB_RESTORE(IsSupportAVX);
#elif defined(__aarch64__)
#if defined(HITLS_CRYPTO_AES_ASM)
    STUB_REPLACE(IsSupportAES, STUB_IsSupportAES);
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx == NULL);
    STUB_RESTORE(IsSupportAES);
#endif
#endif
#endif
EXIT:
    STUB_RESTORE(IsSupportAVX);
    STUB_RESTORE(IsSupportAES);
    ResetStatus();
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_CRYPT_EAL_Init_TC003
 * @title  Check if cpu capability is called at entry point.
 * @precon nan
 * @brief
 *    1. STUB function
 *    1. call CRYPT_EAL_MdNewCtx
 * @expect
 *    1. CRYPT_EAL_CipherNewCtx returns NULL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CRYPT_EAL_Init_TC003()
{
    CRYPT_EAL_MdCtx *ctx = NULL;
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_MdFreeCtx(ctx);
#if defined(HITLS_CRYPTO_ASM_CHECK)
#if defined(__x86_64__)
#if defined(HITLS_CRYPTO_SM2_ASM)
    STUB_REPLACE(IsSupportMOVBE, STUB_IsSupportMOVBE);
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    ASSERT_TRUE(ctx == NULL);
    STUB_RESTORE(IsSupportMOVBE);
#endif
#endif
#endif
EXIT:
    ResetStatus();
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_CRYPT_EAL_Init_TC004
 * @title  Check if cpu capability is called at entry point.
 * @precon nan
 * @brief
 *    1. STUB function
 *    1. call CRYPT_EAL_MdNewCtx
 * @expect
 *    1. CRYPT_EAL_CipherNewCtx returns NULL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CRYPT_EAL_Init_TC004()
{
    ResetStatus();
    uint32_t keyLen = DATA_LEN;
    uint8_t key[keyLen];
    uint32_t saltLen = DATA_LEN;
    uint8_t salt[saltLen];
    uint32_t it = 1024;
    uint32_t outLen = DATA_LEN;
    uint8_t out[outLen];

    CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_MAC_AlgId macAlgId = CRYPT_MAC_HMAC_SHA256;
    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgId, sizeof(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        key, keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt, saltLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &it,
        sizeof(it)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);
#if defined(HITLS_CRYPTO_ASM_CHECK)
#if defined(__x86_64__)
#if defined(HITLS_CRYPTO_SHA2_ASM)
    STUB_REPLACE(IsSupportAVX, STUB_IsSupportAVX);
    ASSERT_TRUE(CRYPT_EAL_KdfSetParam(ctx, params) != CRYPT_SUCCESS);
    STUB_RESTORE(IsSupportAVX);
#endif
#if defined(HITLS_CRYPTO_MD5_ASM)
    STUB_REPLACE(IsSupportBMI1, STUB_IsSupportBMI1);
    macAlgId = CRYPT_MAC_HMAC_MD5;
    ASSERT_TRUE(CRYPT_EAL_KdfSetParam(ctx, params) != CRYPT_SUCCESS);
    STUB_RESTORE(IsSupportBMI1);
#endif
#if defined(HITLS_CRYPTO_SM3_ASM)
    STUB_REPLACE(IsSupportMOVBE, STUB_IsSupportMOVBE);
    macAlgId = CRYPT_MAC_HMAC_SM3;
    ASSERT_TRUE(CRYPT_EAL_KdfSetParam(ctx, params) != CRYPT_SUCCESS);
    STUB_RESTORE(IsSupportMOVBE);
#endif
#endif
#endif
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
    STUB_RESTORE(IsSupportAVX);
    STUB_RESTORE(IsSupportBMI1);
    STUB_RESTORE(IsSupportMOVBE);
    ResetStatus();
}
/* END_CASE */

/**
 * @test SDV_CRYPTO_CRYPT_EAL_Init_TC005
 * @title  Check if cpu capability is called at entry point.
 * @precon nan
 * @brief
 *    1. STUB function
 *    1. call CRYPT_EAL_MdNewCtx
 * @expect
 *    1. CRYPT_EAL_CipherNewCtx returns NULL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CRYPT_EAL_Init_TC005()
{
    ResetStatus();
    CRYPT_EAL_RndCtx *ctx = NULL;

    ctx = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, NULL, NULL);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_DrbgInstantiate(ctx, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_DrbgDeinit(ctx);
#if defined(HITLS_CRYPTO_ASM_CHECK)
#if defined(__x86_64__)
    STUB_REPLACE(IsSupportAVX, STUB_IsSupportAVX);
#if defined(HITLS_CRYPTO_SHA1_ASM)
    ctx = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA1, NULL, NULL);
    ASSERT_TRUE(ctx == NULL);
    ASSERT_NE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA1, NULL, NULL, NULL, 0), CRYPT_SUCCESS);
#endif
#if defined(HITLS_CRYPTO_SHA2_ASM)
    ctx = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, NULL, NULL);
    ASSERT_TRUE(ctx == NULL);
    ASSERT_NE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0), CRYPT_SUCCESS);
#endif
#if defined(HITLS_CRYPTO_AES_ASM)
    ctx = CRYPT_EAL_DrbgNew(CRYPT_RAND_AES128_CTR, NULL, NULL);
    ASSERT_TRUE(ctx == NULL);
    ASSERT_NE(CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0), CRYPT_SUCCESS);
#endif
    STUB_RESTORE(IsSupportAVX);
#elif defined(__aarch64__)
#if defined(HITLS_CRYPTO_AES_ASM)
    STUB_REPLACE(IsSupportAES, STUB_IsSupportAES);
    ctx = CRYPT_EAL_DrbgNew(CRYPT_RAND_AES128_CTR, NULL, NULL);
    ASSERT_TRUE(ctx == NULL);
    ASSERT_NE(CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0), CRYPT_SUCCESS);
    STUB_RESTORE(IsSupportAES);
#endif
#endif
#endif
EXIT:
    STUB_RESTORE(IsSupportAVX);
    STUB_RESTORE(IsSupportAES);
    ResetStatus();
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_INIT_THREAD_SAFETY_TC001
* @spec  -
* @title  Concurrent CRYPT_EAL_Init after exclusive cleanup
* @precon  DRBG is enabled.
* @brief  1. after cleanup, release waiting threads together to call CRYPT_EAL_Init
          2. join all threads before the next cleanup
          3. call CRYPT_EAL_Init and generate random bytes
* @expect 1. each CRYPT_EAL_Init call returns CRYPT_SUCCESS
          2. no crash or double free occurs
          3. step 3 returns CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_INIT_THREAD_SAFETY_TC001(void)
{
#if defined(HITLS_CRYPTO_DRBG)
    uint8_t output[DATA_LEN];
    InitThreadArg arg[INIT_THREAD_NUM];
    pthread_t thrd[INIT_THREAD_NUM];
    uint32_t started = 0;

    /* Cleanup runs only after all init threads have finished. */
    for (uint32_t round = 0; round < INIT_RACE_ROUND; round++) {
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
        g_initWaiting = 0;
        g_initStart = false;
        for (; started < INIT_THREAD_NUM; started++) {
            arg[started].ret = CRYPT_SUCCESS;
            ASSERT_TRUE(pthread_create(&thrd[started], NULL, ConcurrentInitThread, &arg[started]) == 0);
        }
        ReleaseInitThreads(started);
        for (uint32_t i = 0; i < started; i++) {
            pthread_join(thrd[i], NULL);
        }
        started = 0;
        for (uint32_t i = 0; i < INIT_THREAD_NUM; i++) {
            ASSERT_EQ(arg[i].ret, CRYPT_SUCCESS);
        }
    }

    /* Final state must be usable. */
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Randbytes(output, DATA_LEN), CRYPT_SUCCESS);

EXIT:
    /* Release any workers waiting after a partial thread-creation failure. */
    ReleaseInitThreads(started);
    for (uint32_t i = 0; i < started; i++) {
        pthread_join(thrd[i], NULL);
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ResetStatus();
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_INIT_CLEANUP_TC001
* @spec  -
* @title  Cleanup of PROVIDER_RAND frees the provider DRBG
* @precon  Provider and DRBG are enabled; automatic initialization is disabled.
* @brief  1. init CPU, BSL, the seed lock, provider, and provider rand
          2. clean PROVIDER_RAND only, the provider stays
          3. init provider rand again
* @expect 1. provider stays; its DRBG cannot generate bytes until reinitialized
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_INIT_CLEANUP_TC001(void)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DRBG) && !defined(HITLS_EAL_INIT_OPTS)
    uint8_t output[DATA_LEN];
    /* With HITLS_EAL_INIT_OPTS, Cleanup always cleans all bits. */
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_LOCK |
        CRYPT_EAL_INIT_PROVIDER | CRYPT_EAL_INIT_PROVIDER_RAND), CRYPT_SUCCESS);
    CRYPT_EAL_LibCtx *provider = CRYPT_EAL_GetGlobalLibCtx();
    ASSERT_TRUE(provider != NULL);
    ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, output, sizeof(output)), CRYPT_SUCCESS);

    /* Clean PROVIDER_RAND only, the provider must stay. */
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_PROVIDER_RAND);
    ASSERT_TRUE(CRYPT_EAL_GetGlobalLibCtx() == provider);
    ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, output, sizeof(output)), CRYPT_NULL_INPUT);
    BSL_ERR_ClearError();

    /* The cleanup must free the provider DRBG, the re-init must succeed. */
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_PROVIDER_RAND), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, output, sizeof(output)), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ResetStatus();
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_INIT_LAZY_PROVIDER_CLEANUP_TC001
 * @precon Provider is enabled.
 * @brief Simulate first ProviderLoad access, then clean the untracked global provider.
 * @expect Cleanup frees the provider even though EAL init did not record it.
 */
/* BEGIN_CASE */
void SDV_CRYPT_INIT_LAZY_PROVIDER_CLEANUP_TC001(void)
{
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_LOCK), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetGlobalLibCtx() == NULL);
    STUB_REPLACE(GetCurrentProviderLibCtx, STUB_GetCurrentProviderLibCtx_Fresh);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetGlobalLibCtx() != NULL);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_PROVIDER);
    ASSERT_TRUE(CRYPT_EAL_GetGlobalLibCtx() == NULL);
EXIT:
    STUB_RESTORE(GetCurrentProviderLibCtx);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_INIT_ROLLBACK_TC003
 * @precon Provider and DRBG are enabled.
 * @brief Provider RAND creates the global provider; the following RAND step fails.
 * @expect Rollback frees the new provider and preserves the caller's existing RAND.
 */
/* BEGIN_CASE */
void SDV_CRYPT_INIT_ROLLBACK_TC003(void)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DRBG)
    uint8_t output[DATA_LEN];
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_LOCK), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetGlobalLibCtx() == NULL);
    ASSERT_EQ(ForceRandInitFailure(), CRYPT_SUCCESS);
    g_initProviderCreates = 0;
    STUB_REPLACE(GetCurrentProviderLibCtx, STUB_GetCurrentProviderLibCtx_Fresh);
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_RAND | CRYPT_EAL_INIT_PROVIDER_RAND), CRYPT_EAL_ERR_DRBG_REPEAT_INIT);
    ASSERT_EQ(g_initProviderCreates, 1);
    ASSERT_TRUE(CRYPT_EAL_GetGlobalLibCtx() == NULL);
    ASSERT_EQ(CRYPT_EAL_Randbytes(output, sizeof(output)), CRYPT_SUCCESS);
EXIT:
    STUB_RESTORE(GetCurrentProviderLibCtx);
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_INIT_DIRECT_RAND_CLEANUP_TC001
 * @precon DRBG is enabled.
 * @brief Directly initialize RAND, clean it through EAL, then initialize it again.
 * @expect Cleanup frees RAND even though EAL init did not record it.
 */
/* BEGIN_CASE */
void SDV_CRYPT_INIT_DIRECT_RAND_CLEANUP_TC001(void)
{
#ifdef HITLS_CRYPTO_DRBG
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    for (uint32_t i = 0; i < 2; i++) {
        ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_BSL | CRYPT_EAL_INIT_LOCK), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0), CRYPT_SUCCESS);
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_RAND);
    }
EXIT:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_INIT_ROLLBACK_TC004
 * @brief Inject each init failure and check resource rollback and retry.
 * @expect Only new resources are freed; existing resources remain usable.
 */
/* BEGIN_CASE */
void SDV_CRYPT_INIT_ROLLBACK_TC004(int failOpt, int preOpts, int initOpts, int rollbackOpts)
{
#if defined(HITLS_BSL_INIT) && defined(HITLS_CRYPTO_ENTROPY) && \
    defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DRBG)
    uint8_t output[DATA_LEN];
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ResetStatus();
    ASSERT_EQ(CRYPT_EAL_Init(preOpts), CRYPT_SUCCESS);
    CRYPT_EAL_LibCtx *provider = CRYPT_EAL_GetGlobalLibCtx();
    g_initFailOpt = failOpt;
    memset(&g_initRollback, 0, sizeof(g_initRollback));
    STUB_REPLACE(GetCpuInstrSupportState, STUB_GetCpuInstrSupportState_Count);
    STUB_REPLACE(BSL_GLOBAL_Init, STUB_BSL_GLOBAL_Init_Fail);
    STUB_REPLACE(BSL_GLOBAL_DeInit, STUB_BSL_GLOBAL_DeInit_Count);
    STUB_REPLACE(EAL_SeedDrbgLockInit, STUB_EAL_SeedDrbgLockInit_Fail);
    STUB_REPLACE(EAL_SeedDrbgLockDeInit, STUB_EAL_SeedDrbgLockDeInit_Count);
    STUB_REPLACE(CRYPT_EAL_InitPreDefinedProviders, STUB_CRYPT_EAL_InitPreDefinedProviders_Fail);
    STUB_REPLACE(CRYPT_EAL_FreePreDefinedProviders, STUB_CRYPT_EAL_FreePreDefinedProviders_Count);
    STUB_REPLACE(CRYPT_EAL_ProviderRandInitCtx, STUB_CRYPT_EAL_ProviderRandInitCtx_Fail);
    STUB_REPLACE(CRYPT_EAL_RandDeinitEx, STUB_CRYPT_EAL_RandDeinitEx_Count);
    STUB_REPLACE(CRYPT_EAL_RandInit, STUB_CRYPT_EAL_RandInit_Fail);

    ASSERT_EQ(CRYPT_EAL_Init(initOpts), CRYPT_MEM_ALLOC_FAIL);
    ASSERT_EQ(g_initRollback.attempted, (uint64_t)(rollbackOpts | failOpt));
    ASSERT_EQ(g_initRollback.bslFrees, (rollbackOpts & CRYPT_EAL_INIT_BSL) != 0);
    ASSERT_EQ(g_initRollback.lockFrees, (rollbackOpts & CRYPT_EAL_INIT_LOCK) != 0);
    ASSERT_EQ(g_initRollback.providerFrees, (rollbackOpts & CRYPT_EAL_INIT_PROVIDER) != 0);
    ASSERT_EQ(g_initRollback.providerRandFrees, (rollbackOpts & CRYPT_EAL_INIT_PROVIDER_RAND) != 0 &&
        (rollbackOpts & CRYPT_EAL_INIT_PROVIDER) == 0);
    ASSERT_TRUE(CRYPT_EAL_GetGlobalLibCtx() == provider);
    ASSERT_EQ(CRYPT_EAL_Randbytes(output, sizeof(output)),
        (preOpts & CRYPT_EAL_INIT_RAND) ? CRYPT_SUCCESS : CRYPT_EAL_ERR_GLOBAL_DRBG_NULL);
    if (provider != NULL) {
        ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, output, sizeof(output)),
            (preOpts & CRYPT_EAL_INIT_PROVIDER_RAND) ? CRYPT_SUCCESS : CRYPT_NULL_INPUT);
    }
    BSL_ERR_ClearError();

    g_initFailOpt = 0;
    memset(&g_initRollback, 0, sizeof(g_initRollback));
    ASSERT_EQ(CRYPT_EAL_Init(initOpts), CRYPT_SUCCESS);
    ASSERT_EQ(g_initRollback.attempted, (uint64_t)(initOpts & ~preOpts));
    memset(&g_initRollback, 0, sizeof(g_initRollback));
    ASSERT_EQ(CRYPT_EAL_Init(initOpts), CRYPT_SUCCESS);
    ASSERT_EQ(g_initRollback.attempted, 0);
    ASSERT_EQ(g_initRollback.bslFrees, 0);
    ASSERT_EQ(g_initRollback.lockFrees, 0);
    ASSERT_EQ(g_initRollback.providerFrees, 0);
    ASSERT_EQ(g_initRollback.providerRandFrees, 0);
    ASSERT_EQ(CRYPT_EAL_Randbytes(output, sizeof(output)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_RandbytesEx(NULL, output, sizeof(output)), CRYPT_SUCCESS);

EXIT:
    STUB_RESTORE(GetCpuInstrSupportState);
    STUB_RESTORE(BSL_GLOBAL_Init);
    STUB_RESTORE(BSL_GLOBAL_DeInit);
    STUB_RESTORE(EAL_SeedDrbgLockInit);
    STUB_RESTORE(EAL_SeedDrbgLockDeInit);
    STUB_RESTORE(CRYPT_EAL_InitPreDefinedProviders);
    STUB_RESTORE(CRYPT_EAL_FreePreDefinedProviders);
    STUB_RESTORE(CRYPT_EAL_ProviderRandInitCtx);
    STUB_RESTORE(CRYPT_EAL_RandDeinitEx);
    STUB_RESTORE(CRYPT_EAL_RandInit);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ResetStatus();
#else
    (void)failOpt;
    (void)preOpts;
    (void)initOpts;
    (void)rollbackOpts;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_INIT_LOCK_CLEANUP_TC001
 * @brief Release the init lock during exclusive cleanup and recreate it on init.
 * @expect Repeated cleanup is harmless; failed creation and NULL locks can be reset.
 */
/* BEGIN_CASE */
void SDV_CRYPT_INIT_LOCK_CLEANUP_TC001(int mode, int cleanupOpts)
{
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ResetStatus();
    ASSERT_EQ(BSL_ERR_Init(), BSL_SUCCESS);
    g_initLockCreates = 0;
    g_initLockFrees = 0;
    g_initLockFail = mode == 1;
    g_initLockNull = mode == 2;
    g_initLockTracking = false;
    g_testInitLock = NULL;
    g_testInitOnce = NULL;
    STUB_REPLACE(BSL_SAL_ThreadRunOnce, STUB_BSL_SAL_ThreadRunOnce_Track);
    STUB_REPLACE(BSL_SAL_ThreadLockNew, STUB_BSL_SAL_ThreadLockNew_Count);
    STUB_REPLACE(BSL_SAL_ThreadLockFree, STUB_BSL_SAL_ThreadLockFree_Count);
    if (g_initLockNull) {
        STUB_REPLACE(BSL_SAL_ThreadWriteLock, STUB_BSL_SAL_ThreadWriteLock_Null);
        STUB_REPLACE(BSL_SAL_ThreadUnlock, STUB_BSL_SAL_ThreadUnlock_Null);
    }
    if (g_initLockFail) {
        ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU), CRYPT_MEM_ALLOC_FAIL);
        ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU), CRYPT_MEM_ALLOC_FAIL);
        ASSERT_EQ(g_initLockCreates, 1);
        g_initLockFail = false;
        CRYPT_EAL_Cleanup(cleanupOpts);
        ASSERT_EQ(g_initLockFrees, 0);
    }
    uint32_t failedCreates = mode == 1 ? 1 : 0;
    for (uint32_t i = 0; i < 3; i++) {
        ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU), CRYPT_SUCCESS);
        ASSERT_EQ(g_initLockCreates, failedCreates + i + 1);
        CRYPT_EAL_Cleanup(cleanupOpts);
        ASSERT_EQ(g_initLockFrees, g_initLockNull ? 0 : i + 1);
        CRYPT_EAL_Cleanup(cleanupOpts);
        ASSERT_EQ(g_initLockCreates, failedCreates + i + 1);
        ASSERT_EQ(g_initLockFrees, g_initLockNull ? 0 : i + 1);
    }
EXIT:
    STUB_RESTORE(BSL_SAL_ThreadRunOnce);
    STUB_RESTORE(BSL_SAL_ThreadLockNew);
    STUB_RESTORE(BSL_SAL_ThreadLockFree);
    STUB_RESTORE(BSL_SAL_ThreadWriteLock);
    STUB_RESTORE(BSL_SAL_ThreadUnlock);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    ResetStatus();
}
/* END_CASE */
