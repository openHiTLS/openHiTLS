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

#include "crypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

struct BnMont {
    uint32_t mSize;   /* *< size of mod in BN_UINT */
    BN_UINT k0;         /* *< low word of (1/(r - mod[0])) mod r */
    BN_UINT *mod;       /* *< mod */
    BN_UINT *one;       /* *< store one */
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

int32_t BnExtend(BN_BigNum *a, uint32_t words);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_BN */

#endif