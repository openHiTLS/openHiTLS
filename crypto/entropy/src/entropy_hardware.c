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
#ifdef HITLS_CRYPTO_ENTROPY

#include <stdint.h>
#include "securec.h"
#include "crypt_utils.h"
#include "entropy_seed_pool.h"

#ifdef HITLS_CRYPTO_ENTROPY_HARDWARE
#if defined(__x86_64__) || (defined(__aarch64__) && defined(__linux__))
/* For clarity */
#define DRNG_NO_SUPPORT	0x0
#define DRNG_HAS_RDRAND	0x1
#define DRNG_HAS_RDSEED	0x2

#define RDRAND_MAX_RETRIES 20

static uint32_t HWRandBytes(uint8_t *buf, uint32_t len, int32_t (*rand)(uint64_t *), uint32_t retries)
{
    uint32_t left = len;
    while (left != 0) {
        uint32_t cnt = 0;
        uint64_t randVal = 0;
        while (cnt < retries) {
            if (rand(&randVal) == 1) {
                break;
            }
            cnt++;
        }
        if (cnt == retries) {
            // high probability that it wouldn't be here
            return len - left;
        }
        uint32_t cpLen = left < sizeof(randVal) ? left : sizeof(randVal);
        (void)memcpy_s(buf + len - left, left, (uint8_t *)&randVal, cpLen);
        left -= cpLen;
    }

    return len;
}

#ifdef __x86_64__
#include <cpuid.h>

/**
 * Using Intel/AMD cpu's instructions to get hardware random value.
 *
 * references:
 * https://crypto.stackexchange.com/questions/42340/usage-difference-between-x86-rdrand-and-rdseed
 *
 * https://www.intel.com/content/www/us/en/developer/articles/guide/intel-
 * digital-random-number-generator-drng-software-implementation-guide.html
 */

/**
 * If the return value is 1, the variable passed by reference will be populated with a usable random value.
 * If the return value is 0, the caller understands that the value assigned to the variable is not usable.
 */
static int32_t Rdrand64(uint64_t *rand)
{
    uint8_t ok = 0;
    asm volatile("rdrand %0; setc %1" : "=r"(*rand), "=qm"(ok));
    return (int32_t)ok;
}

/**
 * return value of "Rdseed64" is same to "Rdrand64".
 */
static int32_t Rdseed64(uint64_t *seed)
{
    uint8_t ok = 0;
    asm volatile("rdseed %0; setc %1" : "=r"(*seed), "=qm"(ok));
    return (int32_t)ok;
}

#define RAND_BYTES(buf, len) HWRandBytes(buf, len, Rdrand64, RDRAND_MAX_RETRIES)
#define SEED_BYTES(buf, len) HWRandBytes(buf, len, Rdseed64, RDRAND_MAX_RETRIES)

static uint32_t GetDrbgSupport()
{
    static uint32_t drngCap = 0xffffffff;

    if (drngCap == 0xffffffff) {
        drngCap = DRNG_NO_SUPPORT;
        uint32_t cpuid[CPU_ID_OUT_U32_CNT];
        GetCpuId(0x1, 0, cpuid);
        if (cpuid[ECX_OUT_IDX] & bit_RDRND) {
            drngCap |= DRNG_HAS_RDRAND;
        }
        
        (void)memset_s(cpuid, sizeof(cpuid), 0, sizeof(cpuid));
        GetCpuId(0x7, 0, cpuid);
        if (cpuid[EBX_OUT_IDX] & bit_RDSEED) {
            drngCap |= DRNG_HAS_RDSEED;
        }
    }

    return drngCap;
}

uint32_t ENTROPY_HWEntropyGet(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;

    uint32_t drngCap = GetDrbgSupport();
    if (drngCap & DRNG_HAS_RDSEED) {
        return SEED_BYTES(buf, bufLen);
    } else if (drngCap & DRNG_HAS_RDRAND) {
        return RAND_BYTES(buf, bufLen);
    } else {
        return 0;
    }
}
#endif

#ifdef __aarch64__
#ifdef __linux__
#include <sys/auxv.h>
#include "crypt_arm.h"

static uint32_t GetDrbgSupport()
{
    static uint32_t drngCap = 0xffffffff;

    if (drngCap == 0xffffffff) {
        drngCap = DRNG_NO_SUPPORT;
        // On Linux, check CPU capability via auxv
        if (getauxval(CRYPT_CAP2) & CRYPT_ARM_CAP2_RNG) {
            drngCap |= (DRNG_HAS_RDRAND | DRNG_HAS_RDSEED);
        }
    }
    return drngCap;
}
// https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/RNDR--Random-Number
static int32_t Rndr64(uint64_t *rand)
{
    uint8_t ok = 0;
    asm volatile("mrs %0, s3_3_c2_c4_0; cset %w1, ne;" : "=r"(*rand), "=r"(ok));
    return (int32_t)ok;
}

// https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/RNDRRS--Random-Number-Full-Entropy
static int32_t Rndrrs64(uint64_t *seed)
{
    uint8_t ok = 0;
    asm volatile("mrs %0, s3_3_c2_c4_1; cset %w1, ne;" : "=r"(*seed), "=r"(ok));
    return (int32_t)ok;
}

#define RAND_BYTES(buf, len) HWRandBytes(buf, len, Rndr64, RDRAND_MAX_RETRIES)
#define SEED_BYTES(buf, len) HWRandBytes(buf, len, Rndrrs64, RDRAND_MAX_RETRIES)

uint32_t ENTROPY_HWEntropyGet(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    uint32_t drngCap = GetDrbgSupport();
    if (drngCap & DRNG_HAS_RDSEED) {
        uint32_t len = SEED_BYTES(buf, bufLen);
        if (bufLen - len > 0) {
            len += RAND_BYTES(buf + len, bufLen - len);
        }
        return len;
    } else {
        return 0;
    }
}

#endif // __linux__

#endif // __aarch64__

#else
uint32_t ENTROPY_HWEntropyGet(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)buf;
    (void)bufLen;
    return 0;
}

#endif
#else
uint32_t ENTROPY_HWEntropyGet(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)buf;
    (void)bufLen;
    return 0;
}

#endif
#endif