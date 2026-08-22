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
#ifdef HITLS_CRYPTO_BN

#include "crypt_arm.h"

CRYPT_AARCH64_ARCH_BASE
.text

/*
 * Constant-time gather for the Montgomery exponentiation precomputation
 * table. The table keeps the 2^winBits entries limb-interleaved: limb j of
 * entry i lies at tbl[(j << winBits) + i]. Every table word is read with
 * plain full-width loads at public addresses and the wanted entry is
 * selected with equality masks kept in stack scratch; the secret index only
 * reaches the mask compares, and the scratch is wiped before returning. The
 * per-winBits dispatch and all loop bounds depend only on the public
 * winBits/mSize. Requires winBits in [2, 6].
 */

/* One fully unrolled scan of a table row: \nvec 16-byte blocks ANDed with the
   stack masks and folded to one 64-bit limb stored to [x0]. ld1/st1 element
   accesses keep the lane order identical on little- and big-endian targets. */
.macro NEON_ROW_LOOP name nvec
.Lneon_row_\name:
    movi    v0.2d, #0
    mov     x7, sp
    .rept   \nvec / 2
    ld1     {v1.2d, v2.2d}, [x1], #32
    ld1     {v3.2d, v4.2d}, [x7], #32
    and     v1.16b, v1.16b, v3.16b
    and     v2.16b, v2.16b, v4.16b
    orr     v0.16b, v0.16b, v1.16b
    orr     v0.16b, v0.16b, v2.16b
    .endr
    ext     v1.16b, v0.16b, v0.16b, #8  // fold the high lane onto the low one
    orr     v0.16b, v0.16b, v1.16b
    st1     {v0.d}[0], [x0], #8
    subs    w2, w2, #1
    b.ne    .Lneon_row_\name
    b       .Lneon_done
.endm

/*
 * void MontGatherNeon_Asm(uint64_t *dst, const uint64_t *tbl, uint32_t mSize,
 *                         uint32_t winBits, uint64_t idx);
 * Input registers:
 *      x0: destination, mSize limbs
 *      x1: interleaved table, mSize << winBits limbs
 *      w2: mSize
 *      w3: winBits, in [2, 6]
 *      x4: secret entry index, < 2^winBits
 * Modified registers: x0-x7, v0-v7
 */
CRYPT_AARCH64_FUNC_START(MontGatherNeon_Asm)
AARCH64_PACIASP
    sub     sp, sp, #512                // 32 mask vectors * 16 bytes
    dup     v7.2d, x4                   // v7 = { idx, idx }
    movi    v6.2d, #0
    mov     x5, #1
    mov     v6.d[1], x5                 // v6 = { 0, 1 } entry counter
    mov     x5, #2
    dup     v5.2d, x5                   // v5 = { 2, 2 } counter step
    mov     w6, #1
    lsl     w6, w6, w3                  // w6 = tabSize = 1 << winBits
    lsr     w6, w6, #1                  // w6 = tabSize / 2 mask vectors
    mov     x7, sp
.Lneon_mask:
    cmeq    v0.2d, v6.2d, v7.2d
    st1     {v0.2d}, [x7], #16
    add     v6.2d, v6.2d, v5.2d
    subs    w6, w6, #1
    b.ne    .Lneon_mask
    cbz     w2, .Lneon_done
    cmp     w3, #5                      // dispatch on the public window size
    b.eq    .Lneon_row_w5
    b.hi    .Lneon_row_w6
    cmp     w3, #3
    b.eq    .Lneon_row_w3
    b.hi    .Lneon_row_w4
    NEON_ROW_LOOP w2 2
    NEON_ROW_LOOP w3 4
    NEON_ROW_LOOP w4 8
    NEON_ROW_LOOP w5 16
    NEON_ROW_LOOP w6 32
.Lneon_done:
    movi    v0.2d, #0                   // wipe the mask scratch: it encodes the secret index
    movi    v1.2d, #0
    mov     x7, sp
    .rept   16
    st1     {v0.2d, v1.2d}, [x7], #32
    .endr
    add     sp, sp, #512
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(MontGatherNeon_Asm)

#endif /* HITLS_CRYPTO_BN */

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
