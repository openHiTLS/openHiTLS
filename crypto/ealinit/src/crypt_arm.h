/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
#endif

#ifndef __ASSEMBLER__
extern uint32_t g_cryptArmCpuInfo;
#endif

#endif