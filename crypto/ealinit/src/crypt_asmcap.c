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
#include "crypt_method.h"
#include "crypt_local_types.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "crypt_utils.h"
#include "asmcap_local.h"
#include "crypt_ealinit.h"

static bool g_trigger = false;

#define CRYPT_INIT_ABILITY_CPU_POS   0
#define CRYPT_INIT_ABILITY_BSL_POS   1
#define CRYPT_INIT_ABILITY_RAND_POS  2
 
#define CRYPT_INIT_ABILITY_BITMAP(value, pos) (((value) >> (pos)) & 0x1)
#define CRYPT_INIT_SUPPORT_ABILITY(cap, pos) (CRYPT_INIT_ABILITY_BITMAP(cap, pos) != 0)

#if defined(HITLS_EAL_INIT_OPTS)
__attribute__((constructor(102))) int32_t CRYPT_EAL_Init(uint64_t opts)
#else
int32_t CRYPT_EAL_Init(uint64_t opts)
#endif
{
    if (g_trigger) {
        return CRYPT_SUCCESS;
    }
    int32_t ret = CRYPT_SUCCESS;
    uint64_t initopt = opts;
#if defined(HITLS_EAL_INIT_OPTS)
    initopt = HITLS_EAL_INIT_OPTS;
#endif

#if defined(HITLS_CRYPTO_INIT_RAND_ALG)
    int32_t alg = HITLS_CRYPTO_INIT_RAND_ALG;
#else
    int32_t alg = CRYPT_RAND_SHA256;
#endif

    if (CRYPT_INIT_SUPPORT_ABILITY(initopt, CRYPT_INIT_ABILITY_CPU_POS)) {
        GetCpuInstrSupportState();
    }
 
    if (CRYPT_INIT_SUPPORT_ABILITY(initopt, CRYPT_INIT_ABILITY_BSL_POS)) {
#ifdef HITLS_BSL_INIT
        ret = BSL_GLOBAL_Init();
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
#else
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
 
#endif
    }
 
    if (CRYPT_INIT_SUPPORT_ABILITY(initopt, CRYPT_INIT_ABILITY_RAND_POS)) {
        ret = CRYPT_EAL_RandInit(alg, NULL, NULL, NULL, 0);
        if (ret != CRYPT_SUCCESS) {
            if (CRYPT_INIT_SUPPORT_ABILITY(initopt, CRYPT_INIT_ABILITY_BSL_POS)) {
                BSL_GLOBAL_DeInit();
            }
            return ret;
        }
    }
    g_trigger = true;
    return ret;
}

#if defined(HITLS_EAL_INIT_OPTS)
__attribute__((destructor(101))) void CRYPT_EAL_Cleanup(uint64_t opts)
#else
void CRYPT_EAL_Cleanup(uint64_t opts)
#endif
{
    uint64_t initopt = opts;
#if defined(HITLS_EAL_INIT_OPTS)
    initopt = HITLS_EAL_INIT_OPTS;
#endif
    if (CRYPT_INIT_SUPPORT_ABILITY(initopt, CRYPT_INIT_ABILITY_RAND_POS)) {
        CRYPT_EAL_RandDeinit();
    }
 
    if (CRYPT_INIT_SUPPORT_ABILITY(initopt, CRYPT_INIT_ABILITY_BSL_POS)) {
#ifdef HITLS_BSL_INIT
        BSL_GLOBAL_DeInit();
#endif
    }
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
    {.id = CRYPT_CIPHER_AES128_CCM, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES192_CCM, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES256_CCM, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES128_CFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES192_CFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES256_CFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES128_OFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES192_OFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_AES256_OFB, .callback = {CRYPT_AES_AsmCheck, NULL}},
#endif // HITLS_CRYPTO_AES_ASM
#if defined(HITLS_CRYPTO_SM4_ASM)
    {.id = CRYPT_CIPHER_SM4_XTS, .callback = {CRYPT_SM4_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_SM4_CBC, .callback = {CRYPT_SM4_AsmCheck, NULL}},
    {.id = CRYPT_CIPHER_SM4_CTR, .callback = {CRYPT_SM4_AsmCheck, NULL}},
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
#if defined(HITLS_CRYPTO_ECC_ASM)
    {.id = CRYPT_PKEY_ECDSA, .callback = {NULL, CRYPT_ECP256_AsmCheck}},
    {.id = CRYPT_PKEY_ECDH, .callback = {NULL, CRYPT_ECP256_AsmCheck}},
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
#if defined(HITLS_CRYPTO_AES_ASM)
    {.id = CRYPT_RAND_AES128_CTR, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_RAND_AES192_CTR, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_RAND_AES256_CTR, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_RAND_AES128_CTR_DF, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_RAND_AES192_CTR_DF, .callback = {CRYPT_AES_AsmCheck, NULL}},
    {.id = CRYPT_RAND_AES256_CTR_DF, .callback = {CRYPT_AES_AsmCheck, NULL}},
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
    {.id = CRYPT_MAC_MAX, .callback = {NULL, NULL}},
};

int32_t CRYPT_ASMCAP_Mac(CRYPT_MAC_AlgId id)
{
    return CryptCheckCapId((BslCid)id, HITLS_ASM_MAC_ALG_CHECK,
        sizeof(HITLS_ASM_MAC_ALG_CHECK) / sizeof(EAL_CheckAsm));
}

#endif // HITLS_CRYPTO_MAC
#endif /* HITLS_CRYPTO_ASM_CHECK */
