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
#ifndef BN_ASM_H
#define BN_ASM_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include <stdlib.h>
#include "crypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  Function description: r = reduce(a * b) mod n
 *  Function prototype: void MontMul_Asm(uint64_t *r, const uint64_t *a, const uint64_t *b,
 *                            const uint64_t *n, const uint64_t k0, uint32_t size);
 *  Input register:
 *                 x0: result array pointer r
 *                 x1: source data array pointer a
 *                 x2: source data array pointer b
 *                 x3: source data array pointer n
 *                 x4: k0 in the mont structure
 *                 x5: The size of the first four arrays is 'size'.
 *  Modify registers: x0-x17, x19-x24
 *  Output register: None
 *  Function/Macro Call: bn_mont_sqr8x, bn_mont_mul4x
 *  Remarks: The four arrays must have the same length.
 *           If these are different, expand the length to the length of the longest array.
 *           In addition, the expanded part needs to be cleared to 0.
 */
void MontMul_Asm(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, const BN_UINT *n, const BN_UINT k0, size_t size);

#if defined(HITLS_CRYPTO_BN_X8664)
    void MontMulx_Asm(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, const BN_UINT *n, const BN_UINT k0, size_t size);
#endif

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_BN */

#endif