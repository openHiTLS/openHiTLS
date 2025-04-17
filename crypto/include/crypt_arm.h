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

#ifndef CRYPT_ARM_H
#define CRYPT_ARM_H

#ifndef CRYPT_VAL
#define CRYPT_VAL               16
#endif
#ifndef CRYPT_VAL2
#define CRYPT_VAL2              26
#endif
#if defined(__arm__) || defined (__arm)
#define CRYPT_CAP               CRYPT_VAL
#define CRYPT_CE                CRYPT_VAL2
#define CRYPT_ARM_NEON          (1 << 12)
#define CRYPT_ARM_AES           (1 << 0)
#define CRYPT_ARM_PMULL         (1 << 1)
#define CRYPT_ARM_SHA1          (1 << 2)
#define CRYPT_ARM_SHA256        (1 << 3)
#elif defined(__aarch64__)
#define CRYPT_CAP               CRYPT_VAL
#define CRYPT_CE                CRYPT_VAL
#define CRYPT_ARM_NEON          (1 << 1)
#define CRYPT_ARM_AES           (1 << 3)
#define CRYPT_ARM_PMULL         (1 << 4)
#define CRYPT_ARM_SHA1          (1 << 5)
#define CRYPT_ARM_SHA256        (1 << 6)
#define CRYPT_ARM_SM3           (1 << 18)
#define CRYPT_ARM_SM4           (1 << 19)
#define CRYPT_ARM_SHA512        (1 << 21)

#define CRYPT_CAP2              CRYPT_VAL2
#define CRYPT_ARM_CAP2_RNG      (1 << 16)
#endif

#ifndef __ASSEMBLER__
extern uint32_t g_cryptArmCpuInfo;
#else
#  ifdef HITLS_AARCH64_PACIASP
#   define AARCH64_PACIASP hint #25
#   define AARCH64_AUTIASP hint #29
#  else
#   define AARCH64_PACIASP
#   define AARCH64_AUTIASP
#  endif
#endif

#endif