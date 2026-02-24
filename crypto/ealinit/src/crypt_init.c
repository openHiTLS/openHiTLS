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

#include "bsl_init.h"
#include "bsl_err_internal.h"
#include "crypt_local_types.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "crypt_utils.h"
#include "asmcap_local.h"
#include "crypt_ealinit.h"
#include "crypt_util_rand.h"
#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_eal_provider.h"
#include "crypt_provider.h"
#endif
#include "crypt_eal_init.h"

static uint64_t g_ealInitOpts = 0;

#if defined(HITLS_CRYPTO_PROVIDER)
static int32_t ProviderModuleInit(uint64_t initOpt, int32_t alg)
{
    (void) alg;
    int32_t ret = CRYPT_SUCCESS;
    if (initOpt & CRYPT_EAL_INIT_PROVIDER && (g_ealInitOpts & CRYPT_EAL_INIT_PROVIDER) == 0) {
        ret = CRYPT_EAL_InitPreDefinedProviders();
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        g_ealInitOpts |= CRYPT_EAL_INIT_PROVIDER;
    }
#if defined(HITLS_CRYPTO_DRBG)
    if (initOpt & CRYPT_EAL_INIT_PROVIDER_RAND && (g_ealInitOpts & CRYPT_EAL_INIT_PROVIDER_RAND) == 0) {
        ret = CRYPT_EAL_ProviderRandInitCtx(NULL, alg, "provider=default", NULL, 0, NULL);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        g_ealInitOpts |= CRYPT_EAL_INIT_PROVIDER_RAND;
    }
#endif

    return ret;
}

static void ProviderModuleFree(uint64_t initOpt)
{
    if (!(initOpt & CRYPT_EAL_INIT_PROVIDER)) {
        return;
    }
    CRYPT_EAL_FreePreDefinedProviders();
}
#else
static int32_t ProviderModuleInit(uint64_t initOpt, int32_t alg)
{
    (void) initOpt;
    (void) alg;
    return CRYPT_SUCCESS;
}

static void ProviderModuleFree(uint64_t initOpt)
{
    (void) initOpt;
    return;
}
#endif

#if defined(HITLS_BSL_INIT)
static int32_t BslModuleInit(uint64_t initOpt)
{
    if (!(initOpt & CRYPT_EAL_INIT_BSL) || (g_ealInitOpts & CRYPT_EAL_INIT_BSL) != 0) {
        return BSL_SUCCESS;
    }
    int32_t ret = BSL_GLOBAL_Init();
    if (ret == BSL_SUCCESS) {
        g_ealInitOpts |= CRYPT_EAL_INIT_BSL;
    }
    return ret;
}

static void BslModuleFree(uint64_t initOpt)
{
    if (!(initOpt & CRYPT_EAL_INIT_BSL)) {
        return;
    }
    BSL_GLOBAL_DeInit();
}
#else
static int32_t BslModuleInit(uint64_t initOpt)
{
    (void) initOpt;
    return CRYPT_SUCCESS;
}

static void BslModuleFree(uint64_t initOpt)
{
    (void) initOpt;
    return;
}
#endif

#if defined(HITLS_CRYPTO_DRBG)
static void RandModuleFree(uint64_t initOpt)
{
    if (!(initOpt & CRYPT_EAL_INIT_RAND)) {
        return;
    }
    CRYPT_EAL_RandDeinit();
}

static int32_t RandModuleInit(uint64_t initOpt, int32_t alg)
{
    if (!(initOpt & CRYPT_EAL_INIT_RAND) || (g_ealInitOpts & CRYPT_EAL_INIT_RAND) != 0) {
        return BSL_SUCCESS;
    }
    int32_t ret = CRYPT_EAL_RandInit(alg, NULL, NULL, NULL, 0);
    if (ret == CRYPT_SUCCESS) {
        g_ealInitOpts |= CRYPT_EAL_INIT_RAND;
    }
    return ret;
}
#else
static void RandModuleFree(uint64_t initOpt)
{
    (void) initOpt;
    return;
}

static int32_t RandModuleInit(uint64_t initOpt, int32_t alg)
{
    (void) alg;
    (void) initOpt;
    return CRYPT_SUCCESS;
}
#endif

static int32_t GlobalLockInit(uint64_t initOpt, int32_t alg)
{
	(void) alg;
    if ((initOpt & CRYPT_EAL_INIT_LOCK) == 0 || (g_ealInitOpts & CRYPT_EAL_INIT_LOCK) != 0) {
        return CRYPT_SUCCESS;
    }
#ifdef HITLS_CRYPTO_ENTROPY
    int32_t ret = EAL_SeedDrbgLockInit();
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
#endif
    g_ealInitOpts |= CRYPT_EAL_INIT_LOCK;
    return CRYPT_SUCCESS;
}

static void GlobalLockFree(uint64_t initOpt)
{
    if ((initOpt & CRYPT_EAL_INIT_LOCK) == 0) {
        return;
    }
#ifdef HITLS_CRYPTO_ENTROPY
    EAL_SeedDrbgLockDeInit();
#endif
    return;
}

#if defined(HITLS_EAL_INIT_OPTS)
static bool g_ealInitOptsFlags = false;
#endif

#if defined(HITLS_EAL_INIT_OPTS)
__attribute__((constructor(102))) int32_t CRYPT_EAL_Init(uint64_t opts)
#else
int32_t CRYPT_EAL_Init(uint64_t opts)
#endif
{
    int32_t ret = CRYPT_SUCCESS;
    uint64_t initOpt = opts;
#if defined(HITLS_EAL_INIT_OPTS)
    if (!g_ealInitOptsFlags) {
        initOpt = HITLS_EAL_INIT_OPTS;
        g_ealInitOptsFlags = true;
    }
#endif

#if defined(HITLS_CRYPTO_INIT_RAND_ALG)
    int32_t alg = HITLS_CRYPTO_INIT_RAND_ALG;
#else
    int32_t alg = CRYPT_RAND_SHA256;
#endif

    // Step 1: CPU capability detection (no dependencies)
    if ((initOpt & CRYPT_EAL_INIT_CPU) && (g_ealInitOpts & CRYPT_EAL_INIT_CPU) == 0) {
        GetCpuInstrSupportState();
        g_ealInitOpts |= CRYPT_EAL_INIT_CPU;
    }

    // Step 2: BSL initialization (foundational layer, no dependencies)
    ret = BslModuleInit(initOpt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Step 3: Global lock initialization (must be before Rand and Provider Rand)
    // The seed lock (g_seedLock) is used by EAL_GetDefaultSeed() which may be
    // called during DRBG initialization in both RandModuleInit and ProviderModuleInit.
    ret = GlobalLockInit(initOpt, alg);
    if (ret != CRYPT_SUCCESS) {
        BslModuleFree(initOpt);
        return ret;
    }

    // Step 4: Provider initialization (depends on BSL and Lock)
    ret = ProviderModuleInit(initOpt, alg);
    if (ret != CRYPT_SUCCESS) {
        GlobalLockFree(initOpt);
        BslModuleFree(initOpt);
        return ret;
    }

    // Step 5: Rand module initialization (depends on BSL and Lock, independent of Provider)
    // Note: Rand and Provider are independent parallel paths for random number generation
    ret = RandModuleInit(initOpt, alg);
    if (ret != CRYPT_SUCCESS) {
        ProviderModuleFree(initOpt);
        GlobalLockFree(initOpt);
        BslModuleFree(initOpt);
        return ret;
    }

    return ret;
}

#if defined(HITLS_EAL_INIT_OPTS)
__attribute__((destructor(101))) void CRYPT_EAL_Cleanup(uint64_t opts)
#else
void CRYPT_EAL_Cleanup(uint64_t opts)
#endif
{
    uint64_t initOpt = opts;
#if defined(HITLS_EAL_INIT_OPTS)
    initOpt = CRYPT_EAL_INIT_ALL;
#endif

    // Cleanup in reverse order of initialization (LIFO principle)
    // Init order: CPU → BSL → Lock → Provider → Rand
    // Cleanup order: Rand → Provider → Lock → BSL
    RandModuleFree(initOpt);
    ProviderModuleFree(initOpt);
    GlobalLockFree(initOpt);
    BslModuleFree(initOpt);
    g_ealInitOpts &= (~initOpt);
}

#ifdef HITLS_CRYPTO_ASM_CHECK
typedef int (*HITLS_ASM_CHECK_CALLBACK)(void);

typedef struct EAL_CheckAsm {
    uint32_t id;
    HITLS_ASM_CHECK_CALLBACK callback[2];
} EAL_CheckAsm;

static int32_t CryptCheckCapId(const BslCid id, const EAL_CheckAsm asmlist[], uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        if (asmlist[i].id != id) {
            continue;
        }
        for (uint32_t j = 0; j < 2; j++) { // 2 means Alg and Method
            if (asmlist[i].callback[j] != NULL && asmlist[i].callback[j]() != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
                return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
            }
        }
    }
    return CRYPT_SUCCESS;
}

static const EAL_CheckAsm HITLS_ASM_SYM_ALG_CHECK[] = {
    /* symmetric encryption/decryption combination algorithm ID */
#if defined(HITLS_CRYPTO_AES_ASM)
    {.id = CRYPT_CIPHER_AES128_CBC, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES192_CBC, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES256_CBC, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES128_CTR, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES192_CTR, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES256_CTR, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES128_ECB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES192_ECB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES256_ECB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES128_XTS, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES256_XTS, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES128_CCM, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES192_CCM, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES256_CCM, .callback = {CRYPT_AES_AsmCheck, NULL}},
#if defined(HITLS_CRYPTO_GCM_ASM)
    {.id = CRYPT_CIPHER_AES128_GCM, .callback = {CRYPT_AES_AsmCheck, CRYPT_GHASH_AsmCheck}},
    {.id = CRYPT_CIPHER_AES192_GCM, .callback = {CRYPT_AES_AsmCheck, CRYPT_GHASH_AsmCheck}},
    {.id = CRYPT_CIPHER_AES256_GCM, .callback = {CRYPT_AES_AsmCheck, CRYPT_GHASH_AsmCheck}},
#endif // HITLS_CRYPTO_GCM_ASM
    {.id = CRYPT_CIPHER_AES128_CFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES192_CFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES256_CFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES128_OFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES192_OFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES256_OFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
#endif // HITLS_CRYPTO_AES_ASM
#if defined(HITLS_CRYPTO_CHACHA20_ASM) || defined(HITLS_CRYPTO_CHACHA20POLY1305_ASM)
    {.id = CRYPT_CIPHER_CHACHA20_POLY1305, .callback = {CRYPT_CHACHA20_AsmCheck, CRYPT_POLY1305_AsmCheck}},
#endif  // HITLS_CRYPTO_CHACHA20POLY1305_ASM
#if defined(HITLS_CRYPTO_SM4_ASM)
    {.id = CRYPT_CIPHER_SM4_XTS, .callback = {CRYPT_SM4_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_SM4_CBC, .callback = {CRYPT_SM4_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_SM4_ECB, .callback = {CRYPT_SM4_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_SM4_CTR, .callback = {CRYPT_SM4_AsmCheck, NULL}},
#if defined(HITLS_CRYPTO_GCM_ASM)
    {.id = CRYPT_CIPHER_SM4_GCM, .callback = {CRYPT_SM4_AsmCheck, CRYPT_GHASH_AsmCheck}},
#endif // HITLS_CRYPTO_GCM_ASM
    {.id = CRYPT_CIPHER_SM4_CFB, .callback = {CRYPT_SM4_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_SM4_OFB, .callback = {CRYPT_SM4_AsmCheck, NULL}},
#endif // HITLS_CRYPTO_SM4
    {.id = CRYPT_CIPHER_MAX, .callback = {NULL, NULL}},
};

int32_t CRYPT_ASMCAP_Cipher(CRYPT_CIPHER_AlgId  id)
{
    return CryptCheckCapId((BslCid)id, HITLS_ASM_SYM_ALG_CHECK,
        sizeof(HITLS_ASM_SYM_ALG_CHECK) / sizeof(EAL_CheckAsm));
}

#if defined(HITLS_CRYPTO_MD)
static const EAL_CheckAsm HITLS_ASM_MD_ALG_CHECK[] = {
    /* hash algorithm ID */
#if defined(HITLS_CRYPTO_MD5_ASM)
    {.id = CRYPT_MD_MD5, .callback = {CRYPT_MD5_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_SHA1_ASM)
    {.id = CRYPT_MD_SHA1, .callback = {CRYPT_SHA1_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_SHA2_ASM)
    {.id = CRYPT_MD_SHA224, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_MD_SHA256, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_MD_SHA384, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_MD_SHA512, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_SM3_ASM)
    {.id = CRYPT_MD_SM3, .callback = {CRYPT_SM3_AsmCheck, NULL}},
#endif
    {.id = CRYPT_MD_MAX, .callback = {NULL, NULL}},
};
#endif

int32_t CRYPT_ASMCAP_Md(CRYPT_MD_AlgId id)
{
    return CryptCheckCapId((BslCid)id, HITLS_ASM_MD_ALG_CHECK,
        sizeof(HITLS_ASM_MD_ALG_CHECK) / sizeof(EAL_CheckAsm));
}

#if defined(HITLS_CRYPTO_PKEY)
static const EAL_CheckAsm HITLS_ASM_PKEY_ALG_CHECK[] = {
    /* Asymmetric algorithm ID */
#if defined(HITLS_CRYPTO_BN_ASM)
    {.id = CRYPT_PKEY_DSA, .callback = {CRYPT_BN_AsmCheck, NULL}},
    {.id = CRYPT_PKEY_RSA, .callback = {CRYPT_BN_AsmCheck, NULL}},
    {.id = CRYPT_PKEY_DH, .callback = {CRYPT_BN_AsmCheck, NULL}},
#if defined(HITLS_CRYPTO_CURVE_NISTP256_ASM)
    {.id = CRYPT_PKEY_ECDSA, .callback = {CRYPT_BN_AsmCheck, CRYPT_ECP256_AsmCheck}},
    {.id = CRYPT_PKEY_ECDH, .callback = {CRYPT_BN_AsmCheck, CRYPT_ECP256_AsmCheck}},
#endif
    {.id = CRYPT_PKEY_SM2, .callback = {CRYPT_BN_AsmCheck, NULL}},
#endif
    {.id = CRYPT_PKEY_MAX, .callback = {NULL, NULL}},
};

int32_t CRYPT_ASMCAP_Pkey(CRYPT_PKEY_AlgId id)
{
    return CryptCheckCapId((BslCid)id, HITLS_ASM_PKEY_ALG_CHECK,
        sizeof(HITLS_ASM_PKEY_ALG_CHECK) / sizeof(EAL_CheckAsm));
}
#endif // HITLS_CRYPTO_PKEY

#if defined(HITLS_CRYPTO_DRBG)
static const EAL_CheckAsm HITLS_ASM_DRBG_ALG_CHECK[] = {
    /* RAND algorithm ID */
#if defined(HITLS_CRYPTO_SHA1_ASM)
    {.id = CRYPT_RAND_SHA1, .callback = {CRYPT_SHA1_AsmCheck, NULL}},
    {.id = CRYPT_RAND_HMAC_SHA1, .callback = {CRYPT_SHA1_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_SHA2_ASM)
    {.id = CRYPT_RAND_SHA224, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_RAND_SHA256, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_RAND_SHA384, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_RAND_SHA512, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_RAND_HMAC_SHA224, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_RAND_HMAC_SHA256, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_RAND_HMAC_SHA384, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_RAND_HMAC_SHA512, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_SM3_ASM)
    {.id = CRYPT_RAND_SM3, .callback = {CRYPT_SM3_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_AES_ASM)
    {.id = CRYPT_RAND_AES128_CTR, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_RAND_AES192_CTR, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_RAND_AES256_CTR, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_RAND_AES128_CTR_DF, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_RAND_AES192_CTR_DF, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_RAND_AES256_CTR_DF, .callback = {CRYPT_AES_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_SM4_ASM)
    {.id = CRYPT_RAND_SM4_CTR_DF, .callback = {CRYPT_SM4_AsmCheck, NULL}},
#endif
    {.id = CRYPT_RAND_ALGID_MAX, .callback = {NULL, NULL}},
};

int32_t CRYPT_ASMCAP_Drbg(CRYPT_RAND_AlgId id)
{
    return CryptCheckCapId((BslCid)id, HITLS_ASM_DRBG_ALG_CHECK,
        sizeof(HITLS_ASM_DRBG_ALG_CHECK) / sizeof(EAL_CheckAsm));
}
#endif // HITLS_CRYPTO_DRBG

#if defined(HITLS_CRYPTO_MAC)
static const EAL_CheckAsm HITLS_ASM_MAC_ALG_CHECK[] = {
    /* MAC algorithm ID */
#if defined(HITLS_CRYPTO_MD5_ASM)
    {.id = CRYPT_MAC_HMAC_MD5, .callback = {CRYPT_MD5_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_SHA1_ASM)
    {.id = CRYPT_MAC_HMAC_SHA1, .callback = {CRYPT_SHA1_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_SHA2_ASM)
    {.id = CRYPT_MAC_HMAC_SHA224, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_MAC_HMAC_SHA256, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_MAC_HMAC_SHA384, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
    {.id = CRYPT_MAC_HMAC_SHA512, .callback = {CRYPT_SHA2_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_SM3_ASM)
    {.id = CRYPT_MAC_HMAC_SM3, .callback = {CRYPT_SM3_AsmCheck, NULL}},
#endif
#if defined(HITLS_CRYPTO_AES_ASM)
    {.id = CRYPT_MAC_CMAC_AES128, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_MAC_CMAC_AES192, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_MAC_CMAC_AES256, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_MAC_GMAC_AES128, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_MAC_GMAC_AES192, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_MAC_GMAC_AES256, .callback = {CRYPT_AES_AsmCheck, NULL}},
#endif
    {.id = CRYPT_MAC_MAX, .callback = {NULL, NULL}},
};

int32_t CRYPT_ASMCAP_Mac(CRYPT_MAC_AlgId id)
{
    return CryptCheckCapId((BslCid)id, HITLS_ASM_MAC_ALG_CHECK,
        sizeof(HITLS_ASM_MAC_ALG_CHECK) / sizeof(EAL_CheckAsm));
}

#endif // HITLS_CRYPTO_MAC
#endif /* HITLS_CRYPTO_ASM_CHECK */
