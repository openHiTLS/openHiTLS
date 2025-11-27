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

#include "crypt_utils.h"
#ifdef __x86_64__

#include <cpuid.h>
#include "securec.h"


CpuInstrSupportState g_cpuState = {0};

/* Obtain whether the CPU supports the SIMD instruction set through the cpuid instruction. */
void GetCpuId(uint32_t eax, uint32_t ecx, uint32_t cpuId[CPU_ID_OUT_U32_CNT])
{
    uint32_t eaxOut, ebxOut, ecxOut, edxOut;

    __asm("cpuid": "=a"(eaxOut), "=b"(ebxOut), "=c"(ecxOut), "=d"(edxOut): "a"(eax), "c"(ecx):);

    cpuId[EAX_OUT_IDX] = eaxOut;
    cpuId[EBX_OUT_IDX] = ebxOut;
    cpuId[ECX_OUT_IDX] = ecxOut;
    cpuId[EDX_OUT_IDX] = edxOut;
}

/* Obtain whether the OS supports the SIMD instruction set by using the xgetbv instruction. */
static uint32_t GetExCtl(uint32_t ecx)
{
    uint32_t ret = 0;

    __asm("xgetbv": "=a"(ret): "c"(ecx):);

    return ret;
}


bool IsSupportBMI1(void)
{
    return g_cpuState.code7Out[EBX_OUT_IDX] & bit_BMI;
}

bool IsSupportMOVBE(void)
{
    return g_cpuState.code1Out[ECX_OUT_IDX] & bit_MOVBE;
}

bool IsSupportBMI2(void)
{
    return g_cpuState.code7Out[EBX_OUT_IDX] & bit_BMI2;
}

bool IsSupportADX(void)
{
    return g_cpuState.code7Out[EBX_OUT_IDX] & bit_ADX;
}

bool IsSupportSSE(void)
{
    return g_cpuState.code1Out[EDX_OUT_IDX] & bit_SSE;
}

bool IsSupportSSE2(void)
{
    return g_cpuState.code1Out[EDX_OUT_IDX] & bit_SSE2;
}

bool IsSupportAVX(void)
{
    return g_cpuState.code1Out[ECX_OUT_IDX] & bit_AVX;
}

bool IsSupportAES(void)
{
    return g_cpuState.code1Out[ECX_OUT_IDX] & bit_AES;
}

bool IsSupportSSE3(void)
{
    return g_cpuState.code1Out[ECX_OUT_IDX] & bit_SSE3;
}

bool IsSupportAVX2(void)
{
    return g_cpuState.code7Out[EBX_OUT_IDX] & bit_AVX2;
}

bool IsSupportAVX512F(void)
{
    return g_cpuState.code7Out[EBX_OUT_IDX] & bit_AVX512F;
}

bool IsSupportAVX512DQ(void)
{
    return g_cpuState.code7Out[EBX_OUT_IDX] & bit_AVX512DQ;
}

bool IsSupportAVX512VL(void)
{
    return g_cpuState.code7Out[EBX_OUT_IDX] & bit_AVX512VL;
}

bool IsSupportAVX512BW(void)
{
    return g_cpuState.code7Out[EBX_OUT_IDX] & bit_AVX512BW;
}

bool IsSupportXSAVE(void)
{
    return g_cpuState.code1Out[ECX_OUT_IDX] & bit_XSAVE;
}

bool IsSupportOSXSAVE(void)
{
    return g_cpuState.code1Out[ECX_OUT_IDX] & bit_OSXSAVE;
}

bool IsOSSupportAVX(void)
{
    return g_cpuState.osSupportAVX;
}

bool IsOSSupportAVX512(void)
{
    return g_cpuState.osSupportAVX512;
}


/* ARM */
#elif defined(__arm__) || defined (__arm) || defined(__aarch64__)
#include "crypt_arm.h"
uint32_t g_cryptArmCpuInfo = 0;

#if defined(HITLS_CRYPTO_NO_AUXVAL)
#include <setjmp.h>
#include <signal.h>

static jmp_buf g_jump_buffer;

void signal_handler(int sig)
{
    (void)sig;
    longjmp(g_jump_buffer, 1);
}

void getarmcap(void)
{
    struct sigaction sa, old_sa;

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGILL, &sa, &old_sa);

    // NEON
    if (setjmp(g_jump_buffer) == 0) {
#if defined(__ARM_NEON) || defined(__aarch64__)
        // ORR v0.16b, v0.16b, v0.16b
        __asm__ volatile (".inst 0x4ea01c00" : : : "v0");
        g_cryptArmCpuInfo |= CRYPT_ARM_NEON;
#endif
#if defined(__aarch64__)
        // AES
        if (setjmp(g_jump_buffer) == 0) {
            // aese v0.16b, v0.16b
            __asm__ volatile (".inst 0x4e284800" : : : "v0");
            g_cryptArmCpuInfo |= CRYPT_ARM_AES;
        }
        // PMULL
        if (setjmp(g_jump_buffer) == 0) {
            // pmull v0.1q, v0.1d, v0.1d
            __asm__ volatile (".inst 0x0ee0e000" : : : "v0");
            g_cryptArmCpuInfo |= CRYPT_ARM_PMULL;
        }
        // SHA1
        if (setjmp(g_jump_buffer) == 0) {
            // sha1h s0, s0
            __asm__ volatile (".inst 0x5e280800" : : : "s0");
            g_cryptArmCpuInfo |= CRYPT_ARM_SHA1;
        }
        // SHA256
        if (setjmp(g_jump_buffer) == 0) {
            // sha256su0 v0.4s, v0.4s
            __asm__ volatile (".inst 0x5e282800" : : : "v0");
            g_cryptArmCpuInfo |= CRYPT_ARM_SHA256;
        }
        // SHA512
        if (setjmp(g_jump_buffer) == 0) {
            // sha512su0 v0.2d, v0.2d
            __asm__ volatile (".inst 0xcec08000" : : : "v0");
            g_cryptArmCpuInfo |= CRYPT_ARM_SHA512;
        }
#endif
    }

    sigaction(SIGILL, &old_sa, NULL);
}
#else

#include <sys/auxv.h>

static bool g_supportNEON = {0};

bool IsSupportAES(void)
{
    return g_cryptArmCpuInfo & CRYPT_ARM_AES;
}

bool IsSupportPMULL(void)
{
    return g_cryptArmCpuInfo & CRYPT_ARM_PMULL;
}

bool IsSupportSHA1(void)
{
    return g_cryptArmCpuInfo & CRYPT_ARM_SHA1;
}

bool IsSupportSHA256(void)
{
    return g_cryptArmCpuInfo & CRYPT_ARM_SHA256;
}

bool IsSupportNEON(void)
{
    return g_supportNEON;
}

#if defined(__aarch64__)
bool IsSupportSHA512(void)
{
    return g_cryptArmCpuInfo & CRYPT_ARM_SHA512;
}
#endif // __aarch64__

#endif // HITLS_CRYPTO_NO_AUXVAL
#endif // x86_64 || __arm__ || __arm || __aarch64__

void GetCpuInstrSupportState(void)
{
#ifdef __x86_64__
    uint32_t cpuId[CPU_ID_OUT_U32_CNT];
    uint64_t xcr0;

    /* SIMD CPU support */
    GetCpuId(0x1, 0, cpuId);
    (void)memcpy_s(g_cpuState.code1Out, CPU_ID_OUT_U32_CNT * sizeof(uint32_t), cpuId,
        CPU_ID_OUT_U32_CNT * sizeof(uint32_t));

    GetCpuId(0x7, 0, cpuId);
    (void)memcpy_s(g_cpuState.code7Out, CPU_ID_OUT_U32_CNT * sizeof(uint32_t), cpuId,
        CPU_ID_OUT_U32_CNT * sizeof(uint32_t));

    /* SIMD OS support */
    if (IsSupportXSAVE() && IsSupportOSXSAVE()) {
        xcr0 = GetExCtl(0);
        bool sse = xcr0 & XCR0_BIT_SSE;
        bool avx = xcr0 & XCR0_BIT_AVX;
        g_cpuState.osSupportAVX = sse && avx;
        bool opmask = xcr0 & XCR0_BIT_OPMASK;
        bool zmmLow = xcr0 & XCR0_BIT_ZMM_LOW;
        bool zmmHigh = xcr0 & XCR0_BIT_ZMM_HIGH;
        g_cpuState.osSupportAVX512 = opmask && zmmLow && zmmHigh;
    }
#elif defined(__arm__) || defined (__arm) || defined(__aarch64__)
#if defined(HITLS_CRYPTO_NO_AUXVAL)
    getarmcap();
#else // HITLS_CRYPTO_NO_AUXVAL
    g_supportNEON = getauxval(CRYPT_CAP) & CRYPT_ARM_NEON;
    if (g_supportNEON) {
        g_cryptArmCpuInfo = (uint32_t)getauxval(CRYPT_CE);
    }
#endif // HITLS_CRYPTO_NO_AUXVAL
#endif // defined(__arm__) || defined (__arm) || defined(__aarch64__)
}