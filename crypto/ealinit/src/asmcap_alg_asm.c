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
#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ASM_CHECK
 
#ifdef __cplusplus
extern "c" {
#endif
 
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "asmcap_local.h"

#if defined(HITLS_CRYPTO_CIPHER)
#if defined(HITLS_CRYPTO_AES_ASM)
int32_t CRYPT_AES_AsmCheck(void)
{
#if defined(HITLS_CRYPTO_AES_X8664)
    if (!IsSupportAVX() || !IsOSSupportAVX() ||
        !IsSupportAES() || !IsSupportSSE2()) {
        // SetEncryptKey256 uses AVX and SSE2.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#elif defined(HITLS_CRYPTO_AES_ARMV8)
    if (!IsSupportPMULL() || !IsSupportAES()) {
        // ARMV8 should support the PMULL instruction sets.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#elif defined(HITLS_CRYPTO_AES_RISCV64)
    if (!IsSupportV()) {
        // RISCV64 should support the Vector instruction sets.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_AES_ASM
#if defined(HITLS_CRYPTO_SM4_ASM)
int32_t CRYPT_SM4_AsmCheck(void)
{
#if defined(HITLS_CRYPTO_SM4_X8664)
    if ((!IsSupportAVX()) || !IsOSSupportAVX() || !IsSupportAVX2() ||
        (!IsSupportAES()) || (!IsSupportMOVBE())) {
        // The AES instruction is used for the SBOX assembly in the XTS.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#elif (HITLS_CRYPTO_SM4_ARMV8)
    if (!IsSupportAES()) {
        // sbox uses the AES instruction.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#elif (HITLS_CRYPTO_SM4_RISCV64)
    if (!IsSupportV()) {
        // RISCV64 should support the Vector instruction sets.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_SM4

#if defined(HITLS_CRYPTO_GCM_ASM)
int32_t CRYPT_GHASH_AsmCheck(void)
{
#if defined(HITLS_CRYPTO_GCM_X8664)
    if (!IsSupportAVX() || !IsOSSupportAVX()) {
        // GcmTableGen4bit uses the AVX.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#elif defined(HITLS_CRYPTO_GCM_ARMV8)
    if (!IsSupportPMULL()) {
        // In ARMV8, GHASH_BLOCK must support the PMULL instruction set.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_GCM

#endif // HITLS_CRYPTO_CIPHER

#if defined(HITLS_CRYPTO_MD)
#if defined(HITLS_CRYPTO_MD5_ASM)
int32_t CRYPT_MD5_AsmCheck(void)
{
#if defined(HITLS_CRYPTO_MD5_X8664)
    if (!IsSupportBMI1()) { // MD5_Compress uses the BMI1 instruction set.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_MD5

#if defined(HITLS_CRYPTO_SHA1_ASM)
int32_t CRYPT_SHA1_AsmCheck(void)
{
#if defined(HITLS_CRYPTO_SHA1_X8664)
    if (!IsSupportAVX() || !IsOSSupportAVX() || !IsSupportAVX2() || !IsSupportBMI1() || !IsSupportBMI2()) {
        // The SHA1_Step function uses the AVX, AVX2, BMI1, and BMI2 instruction sets.
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_SHA1

#if defined(HITLS_CRYPTO_SHA2_ASM)
int32_t CRYPT_SHA2_AsmCheck(void)
{
#if defined(HITLS_CRYPTO_SHA2_X8664)
    if (!IsSupportAVX() || !IsOSSupportAVX() || !IsSupportAVX2() || !IsSupportBMI1() || !IsSupportBMI2()) {
        // The SHA*CompressMultiBlocks_Asm function uses the AVX, AVX2, BMI1, and BMI2 instruction sets.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#elif defined(HITLS_CRYPTO_SHA2_RISCV64)
    if(!IsSupportZBB()) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_SHA2

#if defined(HITLS_CRYPTO_SM3_ASM)
int32_t CRYPT_SM3_AsmCheck(void)
{
#if defined(HITLS_CRYPTO_SM3_X8664)
    if (!IsSupportMOVBE()) {
        // MOVBE is used in the SM3_CompressAsm function.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_SM3
#endif // HITLS_CRYPTO_MD

#if defined(HITLS_CRYPTO_PKEY)
#if defined(HITLS_CRYPTO_CURVE_NISTP256_ASM)
int32_t CRYPT_ECP256_AsmCheck(void)
{
#if defined(HITLS_CRYPTO_ECC_X8664)
    if (!IsSupportAVX() || !IsOSSupportAVX()) { // ECP256_OrdSqr uses AVX.
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_ECC

#endif // HITLS_CRYPTO_PKEY
 
#ifdef __cplusplus
}
#endif
 
#endif // HITLS_CRYPTO_ASM_CHECK
