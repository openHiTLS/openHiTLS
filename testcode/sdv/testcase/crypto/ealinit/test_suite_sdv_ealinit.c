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

#include "stub_replace.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_init.h"
#include "bsl_err.h"
#include "bsl_err_internal.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_cipher.h"
#include "asmcap_local.h"
/* END_HEADER */

#define DATA_LEN (64)
void ResetStatus(void)
{
    CRYPT_EAL_RandDeinit();
    BSL_GLOBAL_DeInit();
}

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

#define CRYPT_INIT_ABILITY_CPU_POS   0
#define CRYPT_INIT_ABILITY_BSL_POS   1
#define CRYPT_INIT_ABILITY_RAND_POS  2
 
#define CRYPT_INIT_ABILITY_BITMAP(value, pos) (((value) >> (pos)) & 0x1)
#define CRYPT_INIT_SUPPORT_ABILITY(cap, pos) (CRYPT_INIT_ABILITY_BITMAP(cap, pos) != 0)

#define DRBG_MAX_OUTPUT_SIZE (1 << 16)


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
exit:
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
    FuncStubInfo tmpStubInfo = {0};
    CRYPT_EAL_CipherCtx *ctx = NULL;
    STUB_Init();
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_CipherFreeCtx(ctx);
#if defined(HITLS_CRYPTO_ASM_CHECK)
#if defined(__x86_64__)
#if defined(HITLS_CRYPTO_AES_ASM)
    STUB_Replace(&tmpStubInfo, IsSupportAVX, STUB_IsSupportAVX);
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx == NULL);
#endif
#if defined(HITLS_CRYPTO_SM4_ASM)
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
    ASSERT_TRUE(ctx == NULL);
#endif
    STUB_Reset(&tmpStubInfo);
#elif defined(__aarch64__)
#if defined(HITLS_CRYPTO_AES_ASM)
    STUB_Replace(&tmpStubInfo, IsSupportAES, STUB_IsSupportAES);
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx == NULL);
#endif
#endif
#endif
exit:
    STUB_Reset(&tmpStubInfo);
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
    CRYPT_EAL_MdCTX *ctx = NULL;
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_MdFreeCtx(ctx);
#if defined(HITLS_CRYPTO_ASM_CHECK)
#if defined(__x86_64__)
#if defined(HITLS_CRYPTO_SM2_ASM)
    FuncStubInfo tmpStubInfo = {0};
    STUB_Init();
    STUB_Replace(&tmpStubInfo, IsSupportMOVBE, STUB_IsSupportMOVBE);
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    ASSERT_TRUE(ctx == NULL);
    STUB_Reset(&tmpStubInfo);
#endif
#endif
#endif
exit:
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
    FuncStubInfo tmpStubInfo = {0};
    STUB_Init();
    uint32_t keyLen = DATA_LEN;
    uint8_t key[keyLen];
    uint32_t saltLen = DATA_LEN;
    uint8_t salt[saltLen];
    uint32_t it = 1024;
    uint32_t outLen = DATA_LEN;
    uint8_t out[outLen];
    ASSERT_TRUE(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA256, key, keyLen, salt, saltLen, it, out, outLen) == CRYPT_SUCCESS);
#if defined(HITLS_CRYPTO_ASM_CHECK)
#if defined(__x86_64__)
#if defined(HITLS_CRYPTO_SHA2_ASM)
    STUB_Replace(&tmpStubInfo, IsSupportAVX, STUB_IsSupportAVX);
    ASSERT_TRUE(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA256, key, keyLen, salt, saltLen, it, out, outLen) != CRYPT_SUCCESS);
    STUB_Reset(&tmpStubInfo);
#endif
#if defined(HITLS_CRYPTO_MD5_ASM)
    STUB_Replace(&tmpStubInfo, IsSupportBMI1, STUB_IsSupportBMI1);
    ASSERT_TRUE(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_MD5, key, keyLen, salt, saltLen, it, out, outLen) != CRYPT_SUCCESS);
    STUB_Reset(&tmpStubInfo);
#endif
#if defined(HITLS_CRYPTO_SM3_ASM)
    STUB_Replace(&tmpStubInfo, IsSupportMOVBE, STUB_IsSupportMOVBE);
    ASSERT_TRUE(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SM3, key, keyLen, salt, saltLen, it, out, outLen) != CRYPT_SUCCESS);
    STUB_Reset(&tmpStubInfo);
#endif
#endif
#endif
exit:
    STUB_Reset(&tmpStubInfo);
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
    FuncStubInfo tmpStubInfo = {0};
    CRYPT_EAL_RndCtx  *ctx = NULL;
    STUB_Init();
    ctx = CRYPT_EAL_DrbgInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_DrbgDeinit(ctx);
#if defined(HITLS_CRYPTO_ASM_CHECK)
#if defined(__x86_64__)
#if defined(HITLS_CRYPT_SHA1_ASM)
    STUB_Replace(&tmpStubInfo, IsSupportAVX, STUB_IsSupportAVX);
    ctx = CRYPT_EAL_DrbgInit(CRYPT_RAND_SHA1, NULL, NULL, NULL, 0);
    ASSERT_TRUE(ctx == NULL);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA1, NULL, NULL, NULL, 0) == CRYPT_EAL_ERR_DRBG_INIT_FAIL);
#endif
#if defined(HITLS_CRYPT_SHA2_ASM)
    ctx = CRYPT_EAL_DrbgInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    ASSERT_TRUE(ctx == NULL);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_EAL_ERR_DRBG_INIT_FAIL);
#endif
#if defined(HITLS_CRYPT_AES_ASM)
    ctx = CRYPT_EAL_DrbgInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0);
    ASSERT_TRUE(ctx == NULL);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0) == CRYPT_EAL_ERR_DRBG_INIT_FAIL);
    STUB_Reset(&tmpStubInfo);
#endif
#if defined(HITLS_CRYPT_SHA2_ASM)
    STUB_Replace(&tmpStubInfo, IsSupportMOVBE, STUB_IsSupportMOVBE);
    ctx = CRYPT_EAL_DrbgInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    ASSERT_TRUE(ctx == NULL);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_EAL_ERR_DRBG_INIT_FAIL);
#endif
#elif defined(__aarch64__)
#if defined(HITLS_CRYPT_AES_ASM)
    STUB_Replace(&tmpStubInfo, IsSupportAES, STUB_IsSupportAES);
    ctx = CRYPT_EAL_DrbgInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0);
    ASSERT_TRUE(ctx == NULL);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0) == CRYPT_EAL_ERR_DRBG_INIT_FAIL);
    STUB_Reset(&tmpStubInfo);
#endif
#endif
#endif
exit:
    STUB_Reset(&tmpStubInfo);
    ResetStatus();
}
/* END_CASE */
