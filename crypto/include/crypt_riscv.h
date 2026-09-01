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

#ifndef CRYPT_RISCV_H
#define CRYPT_RISCV_H

#include <stdint.h>

#ifndef __NR_riscv_hwprobe
#define __NR_riscv_hwprobe 258
#endif

#define CRYPT_RISCV_V            (1ULL << 2)
#define CRYPT_RISCV_ZBB          (1ULL << 4)
#define CRYPT_RISCV_ZKND         (1ULL << 11)
#define CRYPT_RISCV_ZKNE         (1ULL << 12)
#define CRYPT_RISCV_ZKNH         (1ULL << 13)
#define CRYPT_RISCV_ZKSED        (1ULL << 14)
#define CRYPT_RISCV_ZKSH         (1ULL << 15)

#ifndef __ASSEMBLER__
extern uint64_t g_cryptRiscvCpuInfo;
#endif

#endif
