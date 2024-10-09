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

#ifndef BN_BASIC_H
#define BN_BASIC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdbool.h>
#include "crypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BN_UINT_BITS ((uint32_t)sizeof(BN_UINT) << 3)
#define BITS_TO_BN_UNIT(bits) (((bits) + BN_UINT_BITS - 1) / BN_UINT_BITS)
#define BITS_TO_BYTES(bits) (((bits) + 7) / 8)
#define BN_CLRNEG(n)        ((n) &= 0x7FFFFFFF)
#define BN_SETNEG(n)        ((n) |= CRYPT_BN_FLAG_ISNEGTIVE)
#define BN_ISNEG(n)         (((n) & CRYPT_BN_FLAG_ISNEGTIVE) != 0)
#define BN_GETNEG(n)        ((n) & CRYPT_BN_FLAG_ISNEGTIVE)

struct BigNum {
    uint32_t size; /* *< BigNum size (count of BN_UINT) */
    uint32_t room; /* *< BigNum max size (count of BN_UINT) */
    uint32_t flag; /* *< BigNum flag */
    BN_UINT *data; /* *< BigNum data chunk(most significant limb at the largest) */
};

struct BnMont {
    uint32_t mSize;   /* *< size of mod in BN_UINT */
    BN_UINT k0;         /* *< low word of (1/(r - mod[0])) mod r */
    BN_UINT *mod;       /* *< mod */
    BN_UINT *montRR;    /* *< mont_enc(1) */
    BN_UINT *b;         /* *< tmpb(1) */
    BN_UINT *t;         /* *< tmpt(1) ^ 2 */
};

struct BnCbCtx {
    void *arg; // callback parameter
    BN_CallBack cb; // callback function, which is defined by the user
};

/* Find a pointer address aligned by 'alignment' bytes in the [ptr, ptr + alignment - 1] range.
   The input parameter alignment cannot be 0. */
static inline BN_UINT *AlignedPointer(const void *ptr, uintptr_t alignment)
{
    uint8_t *p = (uint8_t *)(uintptr_t)ptr + alignment - 1;
    return (BN_UINT *)((uintptr_t)p - (uintptr_t)p % alignment);
}

uint32_t BnExtend(BN_BigNum *a, uint32_t words);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_BN

#endif // BN_BASIC_H
