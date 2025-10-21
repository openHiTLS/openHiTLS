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
#if defined(HITLS_CRYPTO_CURVE_NISTP256) && defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE)

#include "crypt_arm.h"
#include "ecp256_pre_comp_table.s"

.arch   armv8-a+crypto

.section .rodata
.align  4
.Lpoly:         // P
.quad   0xffffffffffffffff,0x00000000ffffffff,0x0000000000000000,0xffffffff00000001
.Lone_mont:     // R mod P, R = 2^256, = 2^256 - P
.quad   0x0000000000000001,0xffffffff00000000,0xffffffffffffffff,0x00000000fffffffe
.Lord:          // Order, n
.quad   0xf3b9cac2fc632551,0xbce6faada7179e84,0xffffffffffffffff,0xffffffff00000000
.LordK:         // (2^64 - ord[0]) * ordK = 1 // LordK * Lord, the lower 64 bits are all Fs.
                // LordK * Lord, The lower 64 bits are all Fs, coincidence?
.quad   0xccd1c8aaee00bc4f
.Lone:
.quad   1, 0, 0, 0
/*
Initial z is not set to 1
0000000300000000, 00000001FFFFFFFE, FFFFFFFD00000002, FFFFFFFE00000003
*/

.text
.globl  ECP256_GetPreCompTable
.type   ECP256_GetPreCompTable,%function
.align  4
ECP256_GetPreCompTable:
AARCH64_PACIASP
    adrp x0, g_preCompTable
    add	x0, x0, :lo12:g_preCompTable
AARCH64_AUTIASP
    ret
.size    ECP256_GetPreCompTable,.-ECP256_GetPreCompTable

.globl  ECP256_FromMont
.type   ECP256_FromMont,%function
.align  4
ECP256_FromMont:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-32]!
    add     x29, sp , #0
    stp     x19, x20, [sp, #16]

    ldp     x4 , x5 , [x1]
    ldp     x6 , x7 , [x1, #16]
    adrp    x14, .Lpoly+8
    add x14,x14,:lo12:.Lpoly+8
    ldr x12,[x14]
    ldr x13,[x14,#16]
    adrp    x2, .Lone // &bp[0]
    add	    x2, x2, :lo12:.Lone

    bl      ECP256_MulCore

    ldp     x19, x20, [sp , #16]
    ldp     x29, x30, [sp], #32
AARCH64_AUTIASP
    ret
.size    ECP256_FromMont,.-ECP256_FromMont

.type   ECP256_AddCore,%function
.align  4
ECP256_AddCore:
AARCH64_PACIASP
    adds    x14, x14, x8            // ret = a+b
    adcs    x15, x15, x9
    adcs    x16, x16, x10
    adcs    x17, x17, x11
    adc     x1 , xzr, xzr

    // r -= p, p = 0xffffffffffffffff,0x00000000ffffffff,0x0000000000000000,0xffffffff00000001
    adds    x8 , x14, #1            // x8  = x14 - 0xffffffffffffffff = x14 + 1
    sbcs    x9 , x15, x12           // x9  = x15 - 0x00000000ffffffff
    sbcs    x10, x16, xzr           // x10 = x16 - 0
    sbcs    x11, x17, x13           // x11 = x17 - 0xffffffff00000001
    sbcs    xzr, x1 , xzr           // Determine whether r-p has borrowing

    // r = r < p ? r : r-p
    // x8~x11 saves r-p, x14~x17 saves r
    csel    x14, x14, x8 , lo
    csel    x15, x15, x9 , lo
    csel    x16, x16, x10, lo
    csel    x17, x17, x11, lo

    stp     x14, x15, [x0]
    stp     x16, x17, [x0, #16]
AARCH64_AUTIASP
    ret
.size    ECP256_AddCore,.-ECP256_AddCore


///////////////////////////////////////
// x14~x17 = a[0~3], x8~x11 = b[0~3] //
///////////////////////////////////////
.type   ECP256_SubCore1,%function
.align  4
ECP256_SubCore1:
AARCH64_PACIASP
    subs    x14, x14, x8
    sbcs    x15, x15, x9
    sbcs    x16, x16, x10
    sbcs    x17, x17, x11
    sbc     x1 , xzr, xzr           // x1 = CF

    // r += p
    subs    x8 , x14, #1            // x8  = x14 + 0xffffffffffffffff = x14 - 1
    adcs    x9 , x15, x12           // x9  = x15 + 0x00000000ffffffff
    adcs    x10, x16, xzr           // x10 = x16 + 0
    adc     x11, x17, x13           // x11 = x17 + 0xffffffff00000001
    cmp     x1 , xzr

    // r = borrow==0 ? r : r+p
    csel    x14, x14, x8 , eq
    csel    x15, x15, x9 , eq
    csel    x16, x16, x10, eq
    csel    x17, x17, x11, eq
    stp     x14, x15, [x0]
    stp     x16, x17, [x0, #16]
AARCH64_AUTIASP
    ret
.size   ECP256_SubCore1,.-ECP256_SubCore1

.type   ECP256_SubCore2,%function
.align  4
ECP256_SubCore2:
AARCH64_PACIASP
    subs    x14, x8 , x14
    sbcs    x15, x9 , x15
    sbcs    x16, x10, x16
    sbcs    x17, x11, x17
    sbc     x1 , xzr, xzr           // x1 = CF

    // r += p
    subs    x8 , x14, #1            // x8  = x14 + 0xffffffffffffffff = x14 - 1
    adcs    x9 , x15, x12           // x9  = x15 + 0x00000000ffffffff
    adcs    x10, x16, xzr           // x10 = x16 + 0
    adc     x11, x17, x13           // x11 = x17 + 0xffffffff00000001
    cmp     x1 , xzr

    // r = borrow==0 ? r : r+p
    csel    x14, x14, x8 , eq
    csel    x15, x15, x9 , eq
    csel    x16, x16, x10, eq
    csel    x17, x17, x11, eq
    stp     x14, x15, [x0]
    stp     x16, x17, [x0, #16]
AARCH64_AUTIASP
    ret
.size   ECP256_SubCore2,.-ECP256_SubCore2


.type   ECP256_DivBy2Core,%function
.align  4
ECP256_DivBy2Core:
AARCH64_PACIASP
    // a+p
    subs    x8 , x14, #1            // x8  = x14 + 0xffffffffffffffff = x14 - 1
    adcs    x9 , x15, x12           // x9  = x15 + 0x00000000ffffffff
    adcs    x10, x16, xzr           // x10 = x16 + 0
    adcs    x11, x17, x13           // x11 = x17 + 0xffffffff00000001
    adc     x1 , xzr, xzr           // x1 = CF
    tst     x14, #1                 // Check whether a is an even number. eq indicates that a is an even number.

    // a = a Is an even number ? a : a+p
    csel    x14, x14, x8 , eq
    csel    x15, x15, x9 , eq
    csel    x16, x16, x10, eq
    csel    x17, x17, x11, eq
    csel    x1 , xzr, x1 , eq       // If a is still a, then x1, which holds the carry, is set to 0.

    lsr     x14, x14, #1            // r >>= 1, Divided by 2.
    orr     x14, x14, x15, lsl#63   // x15 is shifted leftward by 63 bits. The lower 63 bits become 0.
                                    // The most significant bit is the least significant bit before the shift.
    lsr     x15, x15, #1            // The most significant bit of x14 is changed to the least significant bit of x15
                                    // to achieve cyclic right shift.
    orr     x15, x15, x16, lsl#63
    lsr     x16, x16, #1
    orr     x16, x16, x17, lsl#63
    lsr     x17, x17, #1
    orr     x17, x17, x1 , lsl#63   // The most significant bit of the highest block is x1.
    stp     x14, x15, [x0]
    stp     x16, x17, [x0, #16]
AARCH64_AUTIASP
    ret
.size    ECP256_DivBy2Core,.-ECP256_DivBy2Core

.globl  ECP256_Neg
.type   ECP256_Neg,%function
.align  4
ECP256_Neg:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-16]!
    add     x29, sp , #0

    ldp     x14, x15, [x1]
    ldp     x16, x17, [x1, #16]

    mov     x8 , xzr
    mov     x9 , xzr
    mov     x10, xzr
    mov     x11, xzr

    adrp    x7, .Lpoly+8
    add x7,x7,:lo12:.Lpoly+8
    ldr x12,[x7]
    ldr x13,[x7,#16]
    // -a = 0 - a
    bl      ECP256_SubCore2

    ldp     x29, x30, [sp], #16
AARCH64_AUTIASP
    ret
.size    ECP256_Neg,.-ECP256_Neg


.type   ECP256_MulCore,%function
.align  4
ECP256_MulCore:
AARCH64_PACIASP
    ldr     x3 , [x2]               // b[0]

    mul     x14, x4 , x3
    umulh   x8 , x4 , x3
    mul     x15, x5 , x3
    umulh   x9 , x5 , x3
    mul     x16, x6 , x3
    umulh   x10, x6 , x3
    mul     x17, x7 , x3
    umulh   x11, x7 , x3

    adds    x15, x15, x8
    adcs    x16, x16, x9
    adcs    x17, x17, x10
    adc     x19, xzr, x11           // x19 = x11 + CF
    mov     x20, xzr

    lsl     x8 , x14, #32           // In this case, x14 stores the lower 32 bits of the lo(a[0]*b[i]), x8 = lo(a[0]*b[i]).
                                    // The lower 32 bits are shifted to the left by 32 bits, and 0s are padded to the lower bits.
    lsr     x9 , x14, #32           // x9 = The most significant 32 bits of lo(a[0]*b[i]) are shifted rightward by 32 bits
                                    // and 0s are padded to the most significant bits.
    subs    x10, x14, x8
    sbc     x11, x14, x9

    adds    x14, x15, x8
    adcs    x15, x16, x9
    adcs    x16, x17, x10
    adcs    x17, x19, x11
    adc     x19, x20, xzr

    ldr     x3 , [x2, #8]           // b[1]

    // lo(a[0~3] * b[i])
    mul     x8 , x4 , x3
    mul     x9 , x5 , x3
    mul     x10, x6 , x3
    mul     x11, x7 , x3

    adds    x14, x14, x8
    adcs    x15, x15, x9
    adcs    x16, x16, x10
    adcs    x17, x17, x11
    adc     x19, x19, xzr

    // hi(a[0~3] * b[i])
    umulh   x8 , x4 , x3
    umulh   x9 , x5 , x3
    umulh   x10, x6 , x3
    umulh   x11, x7 , x3

    adds    x15, x15, x8
    adcs    x16, x16, x9
    adcs    x17, x17, x10
    adcs    x19, x19, x11
    adc     x20, xzr, xzr

    lsl     x8 , x14, #32           // In this case, x14 stores the lower 32 bits of the lo(a[0]*b[i]),
                                    // x8 = lo(a[0]*b[i]). The lower 32 bits are shifted to the left by 32 bits,
                                    // and 0s are padded to the lower bits.
    lsr     x9 , x14, #32           // x9 = The most significant 32 bits of lo(a[0]*b[i]) are shifted rightward
                                    // by 32 bits and 0s are padded to the most significant bits.
    subs    x10, x14, x8
    sbc     x11, x14, x9

    adds    x14, x15, x8
    adcs    x15, x16, x9
    adcs    x16, x17, x10
    adcs    x17, x19, x11
    adc     x19, x20, xzr

    ldr     x3 , [x2, #8*2]           // b[2]

    // lo(a[0~3] * b[i])
    mul     x8 , x4 , x3
    mul     x9 , x5 , x3
    mul     x10, x6 , x3
    mul     x11, x7 , x3

    adds    x14, x14, x8
    adcs    x15, x15, x9
    adcs    x16, x16, x10
    adcs    x17, x17, x11
    adc     x19, x19, xzr

    // hi(a[0~3] * b[i])
    umulh   x8 , x4 , x3
    umulh   x9 , x5 , x3
    umulh   x10, x6 , x3
    umulh   x11, x7 , x3

    adds    x15, x15, x8
    adcs    x16, x16, x9
    adcs    x17, x17, x10
    adcs    x19, x19, x11
    adc     x20, xzr, xzr

    lsl     x8 , x14, #32           // x8  = lq<<32
    lsr     x9 , x14, #32           // x9  = hq
    subs    x10, x14, x8            // x10 = q - lq<<32
    sbc     x11, x14, x9            // x11 = q - hq

    adds    x14, x15, x8
    adcs    x15, x16, x9
    adcs    x16, x17, x10
    adcs    x17, x19, x11
    adc     x19, x20, xzr

    ldr     x3 , [x2, #8*3]           // b[3]

    // lo(a[0~3] * b[i])
    mul     x8 , x4 , x3
    mul     x9 , x5 , x3
    mul     x10, x6 , x3
    mul     x11, x7 , x3

    adds    x14, x14, x8
    adcs    x15, x15, x9
    adcs    x16, x16, x10
    adcs    x17, x17, x11
    adc     x19, x19, xzr

    // hi(a[0~3] * b[i])
    umulh   x8 , x4 , x3
    umulh   x9 , x5 , x3
    umulh   x10, x6 , x3
    umulh   x11, x7 , x3

    adds    x15, x15, x8
    adcs    x16, x16, x9
    adcs    x17, x17, x10
    adcs    x19, x19, x11
    adc     x20, xzr, xzr

    // last reduction
    lsl     x8 , x14, #32           // In this case, x14 stores the lower 32 bits of the lo(a[0]*b[i]),
                                    // x8 = The lower 32 bits of (lo(a[0]*b[i])) are shifted to the left by 32 bits,
                                    // and 0s are padded to the lower bits.
    lsr     x9 , x14, #32           // x9 = The most significant 32 bits of (lo(a[0]*b[i])) are shifted rightward
                                    // by 32 bits and 0s are padded to the most significant bits.
    subs    x10, x14, x8
    sbc     x11, x14, x9

    adds    x14, x15, x8
    adcs    x15, x16, x9
    adcs    x16, x17, x10
    adcs    x17, x19, x11
    adc     x19, x20, xzr

    // x8~x11 = r - p (r may be greater than p)
    adds    x8 , x14, #1            // x8  = x14 - 0xffffffffffffffff = x14 + 1
    sbcs    x9 , x15, x12           // x9  = x15 - 0x00000000ffffffff
    sbcs    x10, x16, xzr           // x10 = x16 - 0
    sbcs    x11, x17, x13           // x11 = x17 - 0xffffffff00000001
    sbcs    xzr, x19, xzr           // Determine whether to borrow

    csel    x14, x14, x8 , lo
    csel    x15, x15, x9 , lo
    csel    x16, x16, x10, lo
    csel    x17, x17, x11, lo

    stp     x14, x15, [x0]
    stp     x16, x17, [x0, #8*2]
AARCH64_AUTIASP
    ret
.size   ECP256_MulCore, .-ECP256_MulCore


.type   ECP256_SqrCore,%function
.align  4
ECP256_SqrCore:
AARCH64_PACIASP
/******************************************
    x7   x1   x20  x19  x17  x16  x15  x14
                             h0*1 l0*1
                        h0*2 l0*2
                   h0*3 l0*3
                   h1*2 l1*2
              h1*3 l1*3
         h2*3 l2*3
    h3*3 l3*3 h2*2 l2*2 h1*1 l1*1 h0*0 l0*0
*******************************************/

    // a[1~3] * a[0]
    mul     x15, x5 , x4            // lo(a[1] * a[0])
    umulh   x8 , x5 , x4            // hi(a[1] * a[0])
    mul     x16, x6 , x4            // lo(a[2] * a[0])
    umulh   x9 , x6 , x4            // hi(a[2] * a[0])
    mul     x17, x7 , x4            // lo(a[3] * a[0])
    umulh   x19, x7 , x4            // hi(a[3] * a[0])

    adds    x16, x16, x8
    adcs    x17, x17, x9
    adc     x19, x19, xzr           // There will be no more carry.

    // a[2~3] * a[1]
    mul     x8 , x6 , x5            // lo(a[2] * a[1])
    umulh   x9 , x6 , x5            // hi(a[2] * a[1])
    mul     x10, x7 , x5            // lo(a[3] * a[1])
    umulh   x11, x7 , x5            // hi(a[3] * a[1])

    // a[3] * a[2]
    mul     x20, x7 , x6
    umulh   x1 , x7 , x6

    // Add the results of the current round, and then add the acc (register in the note above).
    adds    x9 , x10, x9
    adc     x10, x11, xzr

    adds    x17, x17, x8
    adcs    x19, x19, x9
    adcs    x20, x20, x10
    adc     x1 , x1 , xzr           // a[0-3] has been saved in x4 to x7.

    // a[0~3] ^ 2
    mul     x14, x4 , x4
    umulh   x4 , x4 , x4
    mul     x8 , x5 , x5
    umulh   x5 , x5 , x5
    mul     x9 , x6 , x6
    umulh   x6 , x6 , x6
    mul     x10, x7 , x7
    umulh   x7 , x7 , x7

    // acc[1~6] << 1
    adds    x15, x15, x15
    adcs    x16, x16, x16
    adcs    x17, x17, x17
    adcs    x19, x19, x19
    adcs    x20, x20, x20
    adcs    x1 , x1 , x1
    adc     x2 , xzr, xzr

    // acc[] += a[] ^ 2
    adds    x15, x15, x4
    adcs    x16, x16, x8
    adcs    x17, x17, x5
    adcs    x19, x19, x9
    adcs    x20, x20, x6
    adcs    x1 , x1 , x10
    adc     x7 , x7 , x2

    // Four rounds of reduce.
    lsl     x8 , x14, #32
    lsr     x9 , x14, #32
    subs    x10, x14, x8
    sbc     x11, x14, x9
    adds    x14, x15, x8
    adcs    x15, x16, x9
    adcs    x16, x17, x10
    adc     x17, x11, xzr

    lsl     x8 , x14, #32
    lsr     x9 , x14, #32
    subs    x10, x14, x8
    sbc     x11, x14, x9
    adds    x14, x15, x8
    adcs    x15, x16, x9
    adcs    x16, x17, x10
    adc     x17, x11, xzr

    lsl     x8 , x14, #32
    lsr     x9 , x14, #32
    subs    x10, x14, x8
    sbc     x11, x14, x9
    adds    x14, x15, x8
    adcs    x15, x16, x9
    adcs    x16, x17, x10
    adc     x17, x11, xzr

    lsl     x8 , x14, #32
    lsr     x9 , x14, #32
    subs    x10, x14, x8
    sbc     x11, x14, x9
    adds    x14, x15, x8
    adcs    x15, x16, x9
    adcs    x16, x17, x10
    adc     x17, x11, xzr

    // Add acc[4-7]. x14~x19 is the current calculation result r.
    adds    x14, x14, x19
    adcs    x15, x15, x20
    adcs    x16, x16, x1
    adcs    x17, x17, x7
    adc     x19, xzr, xzr

    // r -= p
    adds    x8 , x14, #1            // subs x8,x14,#-1
    sbcs    x9 , x15, x12
    sbcs    x10, x16, xzr
    sbcs    x11, x17, x13
    sbcs    xzr, x19, xzr           // The set CF is used to determine the size relationship between r and p.

    // r = r-p < 0 ? r : r-p
    csel    x14, x14, x8 , lo
    csel    x15, x15, x9 , lo
    csel    x16, x16, x10, lo
    csel    x17, x17, x11, lo

    stp     x14, x15, [x0]
    stp     x16, x17, [x0, #16]
AARCH64_AUTIASP
    ret
.size   ECP256_SqrCore,.-ECP256_SqrCore

.globl  ECP256_Mul
.type   ECP256_Mul,%function
.align  4
ECP256_Mul:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-32]!
    add     x29, sp , #0
    stp     x19, x20, [sp, #16]

    ldp     x4 , x5 , [x1]
    ldp     x6 , x7 , [x1,#16]

    adrp    x3, .Lpoly+8
    add x3,x3,:lo12:.Lpoly+8
    ldr x12,[x3]
    ldr x13,[x3,#16]

    bl      ECP256_MulCore

    ldp     x19, x20, [sp , #16]
    ldp     x29, x30, [sp], #32
AARCH64_AUTIASP
    ret
.size   ECP256_Mul,.-ECP256_Mul

.globl  ECP256_Sqr
.type   ECP256_Sqr,%function
.align  4
ECP256_Sqr:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-32]!
    add     x29, sp , #0
    stp     x19, x20, [sp, #16]

    ldp     x4 , x5 , [x1]
    ldp     x6 , x7 , [x1, #16]
    adrp    x3, .Lpoly+8
    add x3,x3,:lo12:.Lpoly+8
    ldr x12,[x3]
    ldr x13,[x3,#16]

    bl      ECP256_SqrCore

    ldp     x19, x20, [sp , #16]
    ldp     x29, x30, [sp], #32
AARCH64_AUTIASP
    ret
.size   ECP256_Sqr,.-ECP256_Sqr

# ref. https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl
# Deal process:
#     Z1Z1 = Z12
#     U2 = X2*Z1Z1
#     S2 = Y2*Z1*Z1Z1
#     H = U2-X1
#     HH = H2
#     I = 4*HH
#     J = H*I
#     r = 2*(S2-Y1)
#     V = X1*I
#     X3 = r2-J-2*V
#     Y3 = r*(V-X3)-2*Y1*J
#     Z3 = (Z1+H)2-Z1Z1-HH
.globl  ECP256_AddAffine
.type   ECP256_AddAffine,%function
.align  5
ECP256_AddAffine:
AARCH64_PACIASP

    stp     x29, x30, [sp, #-80]!
    add     x29, sp , #0
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    sub     sp , sp , #32*10            // Each coordinate is 256 bits, that is, 32 bytes, and a space of 10 coordinates is applied for.
                                        // Based on C implementation, z1sqr and S2 lifecycles do not overlap.
                                        // You can share one piece of memory and save an extra piece of memory.

    // x0 to x2 will be used to invoke the interface to transfer parameters.
    // Therefore, the initial input parameters are saved to x21 to x23.
    // Obtains the structure members based on the address offset. Each member is 256 bits, that is, 32 bytes.
    mov     x21, x0                     // CRYPT_P256_Point *r
    mov     x22, x1                     // CRYPT_P256_Point *a
    mov     x23, x2                     // CRYPT_P256_AffinePoint *b


    adrp    x14, .Lpoly+8               // p[1]
    add x14,x14,:lo12:.Lpoly+8
    ldr x12,[x14]                       // p[3]
    ldr x13,[x14,#16]


    ldp     x4, x5, [x1, #64]           // x1+64     = &(a->z[0]), a->z[0] is marked as z1[0]
    ldp     x6, x7, [x1, #64+16]        // x1+64+16 = &(a->z[2])

    orr     x24, x4 , x5                // x24 = z1[0] | z1[1]
    orr     x24, x24, x6                // x24 |= z1[2]
    orr     x24, x24, x7                // x24 |= z1[3]
    cmp     x24, #0
    csetm   x24, ne                     // x24 = x24!=0 ? -1 : 0, it means ~iszero(z1),
                                        // determine whether point a is (x, y, 0)

    ldp     x8 , x9 , [x2]              // x2        = &(b->x[0]), b->x[0] is marked as x2[0]
    ldp     x10, x11, [x2, #16]         // x2+16     = &(b->x[2])
    ldp     x14, x15, [x2, 32]          // x2+32     = &(b->y[0])
    ldp     x16, x17, [x2, #32+16]      // x2+32+16  = &(b->y[2])

    // x25 = x2[0] | x2[1] | x2[2] | x2[3] | y2[0] | y2[1] | y2[2] | y2[3]
    orr     x25, x8 , x9
    orr     x25, x25, x10
    orr     x25, x25, x11
    orr     x25, x25, x14
    orr     x25, x25, x15
    orr     x25, x25, x16
    orr     x25, x25, x17
    cmp     x25, #0
    csetm   x25, ne                     // x25 = x25!=0 ? -1 : 0, it means ~iszero(x2|y2),
                                        // Check whether point b is (0, 0).

    add     x0 , sp , #32*3             // zsqr = sp[32*3]
    // x4~x7 = z1[0~3] (the value has been assigned.)
    bl      ECP256_SqrCore     // zsqr = z1^2
    // x14~x17 also temporarily stored results

    // The next calculation requires the zsqr calculation result as the input.
    // The calculation result is stored in x4 to x7 in advance to prevent x14 to x17 from being overwritten
    // by the next calculation. Therefore, the calculation result needs to be read from the memory.
    mov     x4 , x14
    mov     x5 , x15
    mov     x6 , x16
    mov     x7 , x17

    add     x0 , sp , #32*4             // u2 = sp[32*4]
    add     x2 , x23, #0                // x2 points to b->x.
    // x4~x7 * [x2]
    bl      ECP256_MulCore        // u2 = z1^2 * x2
    // x14~x17  also temporarily stored results.

    ldp     x8 , x9 , [x22]             // a->x
    ldp     x10, x11, [x22, #16]
    add     x0 , sp , #32*5             // h = sp[32*5]
    // x14~x17 - x8~x11
    bl      ECP256_SubCore1       // h = u2 - x1

    ldp     x4 , x5 , [sp, #32*3]       // zsqr = sp[32*3]
    ldp     x6 , x7 , [sp, #32*3+16]
    add     x2 , x22, #64               // x2 points to a->z
    add     x0 , sp , #32*3             // s2 = sp[32*3], zsqr will not be used later.
                                        // You can use this block memory to store and calculate s2.
    bl      ECP256_MulCore        // s2 = zsqr * z1 = z1^3

    ldp     x4 , x5 , [sp, #32*5]       // x4~x7 = h = sp[32*5]
    ldp     x6 , x7 , [sp, #32*5+16]
    add     x2 , x22, #64
    add     x0 , sp , #32*2             // x0 points to res_z.
    bl      ECP256_MulCore        // res_z = h * z1

    ldp     x4 , x5 , [sp, #32*3]       // x4~x7 = s2 = sp[32*3]
    ldp     x6 , x7 , [sp, #32*3+16]
    add     x2 , x23, #32               // x2 points to b->y.
    add     x0 , sp , #32*3             // s2 = sp[32*3]
    bl      ECP256_MulCore        // s2 = s2 * y2 = y2 * z1^3

    ldp     x8 , x9 , [x22, #32]
    ldp     x10, x11, [x22, #32+16]
    add     x0 , sp , #32*6             // R = sp[32*6]
    // x14~x17 - x8~x11
    bl      ECP256_SubCore1       // R = s2 - y1

    // Rsqr = R^2 and hsqr = h^2 are independent of each other. The sequence can be adjusted.
    // If Rsqr is calculated first, the memory can be read less once. (The pipeline bubble needs to be optimized.)
    // In addition, the calculated hsqr can read less memory in hcub = hsqr x h.
    mov     x4 , x14
    mov     x5 , x15
    mov     x6 , x16
    mov     x7 , x17
    add     x0 , sp , #32*7             // Rsqr = sp[32*7]
    bl      ECP256_SqrCore     // Rsqr = R^2

    ldp     x4 , x5 , [sp, #32*5]       // h = sp[32*5]
    ldp     x6 , x7 , [sp, #32*5+16]
    add     x0 , sp , #32*8             // hsqr = sp[32*8]
    bl      ECP256_SqrCore     // hsqr = h^2

    // x14 to x17 stores the hsqr results and does not need to be read from the memory.
    // (The pipeline bubble exists and needs to be optimized.)
    mov     x4 , x14
    mov     x5 , x15
    mov     x6 , x16
    mov     x7 , x17
    add     x2 , sp , #32*5             // h = sp[32*5]
    add     x0 , sp , #32*9             // hcub = sp[32*9]
    bl      ECP256_MulCore        // hcub = hsqr * h = h^3

    // Because the multiplication involves too many registers, the preceding hsqr cannot be backed up.
    // If the registers after x19 are used, the hsqr needs to be pushed and popped at the beginning
    // and end of the stack, which outweighs the gain. Therefore, the hsqr can only be read from the memory.
    ldp     x4 , x5 , [sp, #32*8]       // hsqr = sp[32*8]
    ldp     x6 , x7 , [sp, #32*8+16]
    add     x2 , x22, #0                // x2 points to a->x
    add     x0 , sp , #32*4             // u2 = sp[32*4]
    bl      ECP256_MulCore        // u2 = hsqr * x1

    mov     x8 , x14
    mov     x9 , x15
    mov     x10, x16
    mov     x11, x17
    add     x0 , sp , #32*8             // hsqr = sp[32*8]
    // x14~x17 + x8~x11
    bl      ECP256_AddCore        // hsqr = 2 * u2

    // x14~x17 saves hsqr, so ECP256_SubCore2 is called.
    ldp     x8 , x9 , [sp, #32*7]       // Rsqr = sp[32*7]
    ldp     x10, x11, [sp, #32*7+16]
    // x8~x11 - x14~x17
    add     x0 , sp , #0                // x0 points to res_x
    bl      ECP256_SubCore2       // res_x = Rsqr - hsqr

    // x14~x17 save res_x, so call ECP256_SubCore1
    ldp     x8 , x9 , [sp, #32*9]       // hcub = sp[32*9]
    ldp     x10, x11, [sp, #32*9+16]
    // x14~x17 - x8~x11
    bl      ECP256_SubCore1       // res_x = res_x - hcub

    // x14~x17 save res_x, so call ECP256_SubCore2
    ldp     x8 , x9 , [sp, #32*4]       // u2 = sp[32*4]
    ldp     x10, x11, [sp, #32*4+16]
    add     x0 , sp , #32*1
    bl      ECP256_SubCore2       // res_y = u2 - res_x

    ldp     x4 , x5 , [sp, #32*9]       // hcub = sp[32*9]
    ldp     x6 , x7 , [sp, #32*9+16]
    add     x2 , x22, #32               // y1 = a->y
    add     x0 , sp , #32*3             // s2 = sp[32*3]
    bl      ECP256_MulCore        // s2 = y1 * hcub

    add     x2 , sp , #32*6             // R = sp[32*6]
    add     x0 , sp , #32*1             // res_y = sp[32*1]
    ldp     x4 , x5 , [x0]
    ldp     x6 , x7 , [x0, #16]
    bl      ECP256_MulCore        // res_y = res_y * R

    // x14–x17 stores res_y, and x0 is still res_y. No value needs to be assigned again.
    ldp     x8 , x9 , [sp, #32*3]       // s2 = sp[32*3]
    ldp     x10, x11, [sp, #32*3+16]
    // x14~x17 - x8~x11
    bl      ECP256_SubCore1       // res_y = res_y - s2


    // Four memory blocks are not read. (The pipeline bubble exists and needs to be optimized.)
    // x14-x17 stores res_y. Therefore, res_y is judged and assigned a value.
    // copy y
    ldp     x4 , x5 , [x23, #32]        // in2_y, b->y
    ldp     x6 , x7 , [x23, #32+16]
    ldp     x8 , x9 , [x22, #32]        // in1_y, a->y
    ldp     x10, x11, [x22, #32+16]

    // res_y = in1infty == 0 ? res_y : in2_y
    cmp     x24, #0                     // x24 = ~in1infty
    csel    x14, x14, x4 , ne
    csel    x15, x15, x5 , ne
    csel    x16, x16, x6 , ne
    csel    x17, x17, x7 , ne
    // res_y = in2infty == 0 ? res_y : in1_y
    cmp     x25, #0                     // x25 = ~in2infty
    csel    x14, x14, x8 , ne
    csel    x15, x15, x9 , ne
    csel    x16, x16, x10, ne
    csel    x17, x17, x11, ne

    stp     x14, x15, [x21, #32]
    stp     x16, x17, [x21, #32+16]

    // copy x
    ldp     x4 , x5 , [x23]             // in2_x, b->x
    ldp     x6 , x7 , [x23, #16]
    ldp     x8 , x9 , [x22]             // in1_x, a->x
    ldp     x10, x11, [x22, #16]
    ldp     x14, x15, [sp]              // res_x
    ldp     x16, x17, [sp , #16]

    // res_x = in1infty == 0 ? res_x : in2_x
    cmp     x24, #0                     // x24 = ~in1infty
    csel    x14, x14, x4 , ne
    csel    x15, x15, x5 , ne
    csel    x16, x16, x6 , ne
    csel    x17, x17, x7 , ne
    // res_x = in2infty == 0 ? res_x : in1_x
    cmp     x25, #0                     // x25 = ~in2infty
    csel    x14, x14, x8 , ne
    csel    x15, x15, x9 , ne
    csel    x16, x16, x10, ne
    csel    x17, x17, x11, ne

    stp     x14, x15, [x21]
    stp     x16, x17, [x21, #16]

    // copy z
    adrp    x23, .Lone_mont
    add	    x23, x23, :lo12:.Lone_mont
    ldp     x4 , x5 , [x23]             // one_mont, 1 * RR * R' = R (mod p)
    ldp     x6 , x7 , [x23, #16]
    ldp     x8 , x9 , [x22, #64]        // in1_z, a->z
    ldp     x10, x11, [x22, #64+16]
    ldp     x14, x15, [sp , #64]        // res_z
    ldp     x16, x17, [sp , #64+16]

    // res_z = in1infty == 0 ? res_z : ONE
    cmp     x24, #0                     // x24 = ~in1infty
    csel    x14, x14, x4 , ne
    csel    x15, x15, x5 , ne
    csel    x16, x16, x6 , ne
    csel    x17, x17, x7 , ne
    // res_z = in2infty == 0 ? res_z : in1_z
    cmp     x25, #0                     // x25 = ~in2infty
    csel    x14, x14, x8 , ne
    csel    x15, x15, x9 , ne
    csel    x16, x16, x10, ne
    csel    x17, x17, x11, ne

    stp     x14, x15, [x21, #64]
    stp     x16, x17, [x21, #64+16]

    add     sp , x29, #0
    ldp     x19, x20, [x29, #16]
    ldp     x21, x22, [x29, #32]
    ldp     x23, x24, [x29, #48]
    ldp     x25, x26, [x29, #64]
    ldp     x29, x30, [sp], #80
AARCH64_AUTIASP
    ret
.size   ECP256_AddAffine,.-ECP256_AddAffine

# ref. https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo
# Deal process:
#     U1 = X1*Z22
#     U2 = X2*Z12
#     S1 = Y1*Z23
#     S2 = Y2*Z13
#     H = U2-U1
#     r = S2-S1
#     X3 = r2-H3-2*U1*H2
#     Y3 = r*(U1*H2-X3)-S1*H3
#     Z3 = Z1*Z2*H
.globl  ECP256_PointAdd
.type   ECP256_PointAdd,%function
.align  5
ECP256_PointAdd:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-96]!
    add     x29, sp , #0
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    stp     x27, x28, [sp, #80]
    sub     sp , sp , #32*12            // Each coordinate is 256 bits, that is, 32 bytes,
                                        // and a space of 10 coordinates is applied for.

    adrp    x14, .Lpoly+8               // p[1]
    add x14,x14,:lo12:.Lpoly+8
    ldr x12,[x14]                       // p[3]
    ldr x13,[x14,#16]

    // Pointer to the initial backup input parameter.
    // x0 to x2 are used to transfer parameters when the interface is invoked.
    mov     x21, x0
    mov     x22, x1
    mov     x23, x2

    ldp     x4 , x5 , [x22, #64]        // z1
    ldp     x6 , x7 , [x22, #64+16]
    // x24 = z1[0] | z1[1] | z1[2] | z1[3]
    orr     x24, x4 , x5
    orr     x24, x24, x6
    orr     x24, x24, x7                // x24 = ~in1infty
    cmp     x24, #0
    csetm   x24, ne                     // x24 = (x24 != 0) ? -1 : 0, that is ~iszero(z1),
                                        // Determine whether point a is(x, y, 0)

    // Because x4 to x7 exactly hold z1, z1^2 can be calculated first.
    add     x0 , sp , #0                 // z1sqr = sp[32*0]
    bl      ECP256_SqrCore     // z1sqr = z1^2

    // x14 to x17 exactly save the z1sqr result (the pipeline bubble exists and needs to be optimized).
    mov     x4 , x14
    mov     x5 , x15
    mov     x6 , x16
    mov     x7 , x17
    add     x2 , x22, #64               // x2 points to z1, that is a->z
    add     x0 , sp , #32*1             // s2 = sp[32*1]
    bl      ECP256_MulCore        // s2 = z1^3

    // x14 to x17 exactly save the result of s2. (The pipeline bubble exists and needs to be optimized.)
    mov     x4 , x14
    mov     x5 , x15
    mov     x6 , x16
    mov     x7 , x17
    add     x2 , x23, #32               // x2 points to y2, that is b->y
    // add     x0 , sp , #32*1             // s2 = sp[32*1], x0 It is exactly s2 and does not need to be set.
                                           // (There are pipeline bubbles to be optimized.)
    bl      ECP256_MulCore        // s2 = y2 * z1^3

    ldp     x4 , x5 , [x23, #64]        // z2
    ldp     x6 , x7 , [x23, #64+16]
    // x25 = z2[0] | z2[1] | z2[2] | z2[3]
    orr     x25, x4 , x5
    orr     x25, x25, x6
    orr     x25, x25, x7                // x25 = ~in2infty
    cmp     x25, #0
    csetm   x25, ne                     // x25 = (x25 != 0) ? -1 : 0, that is ~iszero(z2),
                                        // Check whether point b is(x, y, 0)

    // Because x4~x7 happens to hold z2, z2^2 can be calculated
    add     x0 , sp , #32*2             // z2sqr = sp[32*2]
    bl      ECP256_SqrCore     // z2sqr = z2^2

    // x14 to x17 exactly save the z2sqr result. (There are pipeline bubbles to be optimized.)
    mov     x4 , x14
    mov     x5 , x15
    mov     x6 , x16
    mov     x7 , x17
    add     x2 , x23, #64               // x2 points to z2, that is b->z
    add     x0 , sp , #32*3             // s1 = sp[32*3]
    bl      ECP256_MulCore        // s1 = z2^3

    // x14 to x17 exactly save the result of s2. (The pipeline bubble exists and needs to be optimized.)
    mov     x4 , x14
    mov     x5 , x15
    mov     x6 , x16
    mov     x7 , x17
    add     x2 , x22, #32               // x2 points to y1, that is a->y
    // add     x0 , sp , #32*3             // s1 = sp[32*3], x0 is exactly s1 and does not need to be set.
                                           //  (There are pipeline bubbles to be optimized.)
    bl      ECP256_MulCore        // s1 = y1 * z2^3


    // x14 to x17 save the result of s1. Therefore, the ECP256_SubCore2 interface is selected.
    ldp     x8 , x9 , [sp, #32*1]       // s2 = sp[32*1]
    ldp     x10, x11, [sp, #32*1+16]
    // x8~x11 - x14~x17
    add     x0 , sp , #32*4             // R = sp[32*4]
    bl      ECP256_SubCore2       // R = s2 - s1

    // x14 to x17 save the result of R, (R==0) <==> (s2 == s1)
    orr     x26, x14, x15
    orr     x26, x26, x16
    orr     x26, x26, x17               // x26 = ~(s1 == s2), The data of R is not read from the memory in advance.

    ldp     x4 , x5 , [x22]             // Take x1, that is a->x
    ldp     x6 , x7 , [x22, #16]
    add     x2 , sp , #32*2             // z2sqr = sp[32*2]
    add     x0 , sp , #32*5             // u1 = sp[32*5]
    bl      ECP256_MulCore        // u1 = x1 * z2sqr

    ldp     x4 , x5 , [x23]             // Take x2, that is b->x
    ldp     x6 , x7 , [x23, #16]
    add     x2 , sp , #0                // z1sqr = sp[32*0]
    add     x0 , sp , #32*6             // u2 = sp[32*6]
    bl      ECP256_MulCore        // u2 = x2 * z1sqr

    // x14 to x17 save the result of u2. Therefore, the ECP256_SubCore1 interface is selected.
    ldp     x8 , x9 , [sp, #32*5]       // u1 = sp[32*5]
    ldp     x10, x11, [sp, #32*5+16]
    // x14~x17 - x8~x11
    add     x0 , sp , #32*7             // h = sp[32*7]
    bl      ECP256_SubCore1       // h = u2 - u1

    // x14 to x17 save the result of h, (h==0) <==> (u2 == u1)
    orr     x14, x14, x15
    orr     x14, x14, x16
    orr     x14, x14, x17               // x14 = ~(u1 == u2), It is used for subsequent judgment.
                                        // The data of h does not need to be read from the memory in advance.

    // x24 = ~in2infty
    // x25 = ~in1infty
    // x26 = ~(s1 == s2) = ~is_equal(S1, S2)
    // x14 = ~(u1 == u2) = ~is_equal(U1, U2)
    // if(is_equal(U1, U2) & ~in1infty & ~in2infty & is_equal(S1, S2))
    // 将(is_equal(U1, U2) & ~in1infty & ~in2infty & is_equal(S1, S2))记为flag
    // <==>
    // if ((~is_equal(U1, U2) | in1infty | in2infty | ~is_equal(S1, S2)) == 0)
    // if (flag == 0)

    mvn     x27, x24                    // x27 = in1infty
    mvn     x28, x25                    // x28 = in2infty

    orr     x14, x14, x26
    orr     x14, x14, x27
    orr     x14, x14, x28
    cbnz    x14, .Lpoint_add            // flag != 0, Continue calculation by C implementation

.Ladd_double:
    mov     x0 , x21                    // x0 = r
    mov     x1 , x22                    // x1 = a
    ldp     x23, x24, [x29, #48]        // The double function uses only x19 to x22, and only x19 to x22
                                        // is popped at the end. Therefore, x23 to x28 is popped in advance.
    ldp     x25, x26, [x29, #64]
    ldp     x27, x28, [x29, #80]
    add     sp , sp , #32*(12-4)        // The size of the stack space used varies. The double function
                                        // only releases 32 x 4. Therefore, you need to release part of the stack space in advance.
    b       .Lpoint_double

.align  4
.Lpoint_add:
    ldp     x4 , x5 , [sp, #32*4]       // R = sp[32*4]
    ldp     x6 , x7 , [sp, #32*4+16]
    add     x0 , sp , #0                // Rsqr = sp[0], Because z1sqr will not be used later,
                                        // this memory can be used to save Rsqr.
    bl      ECP256_SqrCore     // Rsqr = R^2

    ldp     x4 , x5 , [sp, #32*7]       // h = sp[32*7]
    ldp     x6 , x7 , [sp, #32*7+16]
    add     x2 , x22, #64               // x2 points to z1
    add     x0 , sp , #32*11            // res_z = sp[32*11]
    bl      ECP256_MulCore        // res_z = h * z1

    // The res_z result is stored in x14 to x17. (The pipeline bubble needs to be optimized.)
    mov     x4 , x14
    mov     x5 , x15
    mov     x6 , x16
    mov     x7 , x17
    add     x2 , x23, #64               // x2 points to z2
    // x0 is still res_z and does not need to be reassigned.
    // add     x0 , sp , #32*11         // res_z = sp[32*11]
    bl      ECP256_MulCore        // res_z = res_z * z2

    ldp     x4 , x5 , [sp, #32*7]       // h = sp[32*7]
    ldp     x6 , x7 , [sp, #32*7+16]
    add     x0 , sp , #32*2             // hsqr = sp[32*2], Because z2sqr will not be used later,
                                        // you can use this memory to save hsqr.
    bl      ECP256_SqrCore

    // The hsqr result is stored in x14 to x17. (The pipeline bubble needs to be optimized.)
    mov     x4 , x14
    mov     x5 , x15
    mov     x6 , x16
    mov     x7 , x17
    add     x2 , sp , #32*7             // h = sp[32*7]
    add     x0 , sp , #32*8             // hcub = sp[32*8]
    bl      ECP256_MulCore        // hcub = hsqr * h

    ldp     x4 , x5 , [sp, #32*5]       // u1 = sp[32*5]
    ldp     x6 , x7 , [sp, #32*5+16]
    add     x2 , sp , #32*2             // hsqr = sp[32*2]
    add     x0 , sp , #32*6             // u2 = sp[32*6]
    bl      ECP256_MulCore        // u2 = u1 * hsqr

    // x14~x17 exactly save the result of u2.
    mov     x8 , x14
    mov     x9 , x15
    mov     x10, x16
    mov     x11, x17
    // add     x0 , sp , #32*2          // hsqr = sp[32*2]
    // The previous operation x2 also saves the address of hsqr.
    mov     x0 , x2
    // x14~x17 + x8~x11
    bl      ECP256_AddCore        // hsqr = 2 * u2

    // x14 to x17 save the hsqr result. Therefore, ECP256_SubCore2 is called.
    ldp     x8 , x9 , [sp]              // Rsqr = sp[0]
    ldp     x10, x11, [sp, #16]
    // x8~x11 - x14~x17
    add     x0 , sp , #32*9             // res_x = sp[32*9]
    bl      ECP256_SubCore2       // res_x = Rsqr - hsqr

    // x14 to x17 exactly save the result of res_x, so ECP256_SubCore1 is called.
    ldp     x8 , x9 , [sp, #32*8]       // hcub = sp[32*8]
    ldp     x10, x11, [sp, #32*8+16]
    // x14~x17 - x8~11
    // The previous operation x0 also stores the address of res_x.
    bl      ECP256_SubCore1       // res_x = res_x - hcub

    // x14 to x17 exactly save the result of res_x. Therefore, ECP256_SubCore2 is called.
    ldp     x8 , x9 , [sp, #32*6]       // u2 = sp[0]
    ldp     x10, x11, [sp, #32*6+16]
    // x8~x11 - x14~x17
    add     x0 , sp , #32*10
    bl      ECP256_SubCore2       // res_y = u2 - res_x

    ldp     x4 , x5 , [sp, #32*3]       // s1 = sp[32*3]
    ldp     x6 , x7 , [sp, #32*3+16]
    add     x2 , sp , #32*8             // hcub = sp[32*8]
    add     x0 , sp , #32*1             // s2 = sp[32*1]
    bl      ECP256_MulCore        // s2 = s1 * hcub

    add     x2 , sp , #32*4             // R = sp[32*4]
    add     x0 , sp , #32*10            // res_y = sp[32*10]
    ldp     x4 , x5 , [x0]              // res_y = sp[32*10], Borrowing x0 address without offset
    ldp     x6 , x7 , [x0, #16]
    bl      ECP256_MulCore        // res_y = res_y * R

    // x14 to x17 exactly save the result of res_y. Therefore, ECP256_SubCore1 is called.
    ldp     x8 , x9 , [sp, #32]         // s2 = sp[32*1]
    ldp     x10, x11, [sp, #32+16]
    // x14~x17 - x8~x11
    // The previous operation x0 also stores the address of res_y.
    bl      ECP256_SubCore1       // res_y = res_y - s2

    // Four memory blocks are not read. (The pipeline bubble exists and needs to be optimized.)
    // x14-x17 stores res_y. Therefore, res_y is judged and assigned a value.
    // copy y
    ldp     x4 , x5 , [x23, #32]        // in2_y, b->y
    ldp     x6 , x7 , [x23, #32+16]
    ldp     x8 , x9 , [x22, #32]        // in1_y, a->y
    ldp     x10, x11, [x22, #32+16]

    // res_y = in1infty == 0 ? res_y : in2_y
    cmp     x24, #0                     // x24 = ~in1infty
    csel    x14, x14, x4 , ne
    csel    x15, x15, x5 , ne
    csel    x16, x16, x6 , ne
    csel    x17, x17, x7 , ne
    // res_y = in2infty == 0 ? res_y : in1_y
    cmp     x25, #0                     // x25 = ~in2infty
    csel    x14, x14, x8 , ne
    csel    x15, x15, x9 , ne
    csel    x16, x16, x10, ne
    csel    x17, x17, x11, ne

    stp     x14, x15, [x21, #32]
    stp     x16, x17, [x21, #32+16]

    // copy x
    ldp     x4 , x5 , [x23]             // in2_x, b->x
    ldp     x6 , x7 , [x23, #16]
    ldp     x8 , x9 , [x22]             // in1_x, a->x
    ldp     x10, x11, [x22, #16]
    ldp     x14, x15, [sp , #32*9]      // res_x
    ldp     x16, x17, [sp , #32*9+16]

    // res_x = in1infty == 0 ? res_x : in2_x
    cmp     x24, #0                     // x24 = ~in1infty
    csel    x14, x14, x4 , ne
    csel    x15, x15, x5 , ne
    csel    x16, x16, x6 , ne
    csel    x17, x17, x7 , ne
    // res_x = in2infty == 0 ? res_x : in1_x
    cmp     x25, #0                     // x25 = ~in2infty
    csel    x14, x14, x8 , ne
    csel    x15, x15, x9 , ne
    csel    x16, x16, x10, ne
    csel    x17, x17, x11, ne

    stp     x14, x15, [x21]
    stp     x16, x17, [x21, #16]

    // copy z
    ldp     x4 , x5 , [x23, #64]        // in2_z, b->z
    ldp     x6 , x7 , [x23, #64+16]
    ldp     x8 , x9 , [x22, #64]        // in1_z, a->z
    ldp     x10, x11, [x22, #64+16]
    ldp     x14, x15, [sp , #32*11]     // res_z
    ldp     x16, x17, [sp , #32*11+16]

    // res_z = in1infty == 0 ? res_z : in2_z
    cmp     x24, #0                     // x24 = ~in1infty
    csel    x14, x14, x4 , ne
    csel    x15, x15, x5 , ne
    csel    x16, x16, x6 , ne
    csel    x17, x17, x7 , ne
    // res_z = in2infty == 0 ? res_z : in1_z
    cmp     x25, #0                     // x25 = ~in2infty
    csel    x14, x14, x8 , ne
    csel    x15, x15, x9 , ne
    csel    x16, x16, x10, ne
    csel    x17, x17, x11, ne

    stp     x14, x15, [x21, #64]
    stp     x16, x17, [x21, #64+16]

    add     sp , x29, #0                // Free temporary variable
    ldp     x19, x20, [x29, #16]
    ldp     x21, x22, [x29, #32]
    ldp     x23, x24, [x29, #48]
    ldp     x25, x26, [x29, #64]
    ldp     x27, x28, [x29, #80]
    ldp     x29, x30, [sp], #96
AARCH64_AUTIASP
    ret
.size    ECP256_PointAdd,.-ECP256_PointAdd

# ref. https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
# Deal process:
#     delta = Z12
#     gamma = Y12
#     beta = X1*gamma
#     alpha = 3*(X1-delta)*(X1+delta)
#     X3 = alpha2-8*beta
#     Z3 = (Y1+Z1)2-gamma-delta
#     Y3 = alpha*(4*beta-X3)-8*gamma2
.globl  ECP256_PointDouble
.type   ECP256_PointDouble,%function
.align  5
ECP256_PointDouble:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-96]!       // Why is 96 space given here? Only x19~x22 is stacked. Theoretically, only [sp, #-48] is required.
    add     x29, sp , #0                // Whether it is related to the Lpoint_double jump of the ecp_nistz256_point_add interface
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    sub     sp , sp , #32*4

.Lpoint_double:
    ldp     x14, x15, [x1 , #32]        // a->y
    ldp     x16, x17, [x1 , #32+16]
    // Back up the initial input parameter pointer r, a.
    mov     x21, x0
    mov     x22, x1
    adrp    x3, .Lpoly+8               // p[1]
    add x3,x3,:lo12:.Lpoly+8
    ldr x12,[x3]                       // p[3]
    ldr x13,[x3,#16]

    mov     x8 , x14
    mov     x9 , x15
    ldp     x4 , x5 , [x22, #64]        // a->z
    mov     x10, x16
    mov     x11, x17
    ldp     x6 , x7 , [x22, #64+16]
    add     x0 , sp , #0                // s = sp[0]
    bl      ECP256_AddCore        // s = 2 * a->y

    add     x0 , sp , #32               // zsqr = sp[32*1]
    bl      ECP256_SqrCore        // zsqr = (a->z)^2

    // x14 to x17 save the result of s. Calculate s^2 first.
    ldp     x4 , x5 , [sp]
    add     x0 , sp , #0                // s = sp[0]
    ldp     x6 , x7 , [sp, #16]
    bl      ECP256_SqrCore        // s = s^2

    ldp     x14, x15, [sp, #32]             // a->x
    ldp     x8 , x9 , [x22]             // a->x
    ldp     x16, x17, [sp, #32+16]
    add     x0 , sp , #64               // m = sp[32*2]
    ldp     x10, x11, [x22, #16]
    bl      ECP256_AddCore        // m = a->x + zsqr

    ldp     x14 , x15 , [sp, #32]             // a->x
    ldp     x8 , x9 , [x22]             // a->x
    ldp     x16, x17, [sp, #32+16]
    add     x0 , sp , #32
    ldp     x10, x11, [x22, #16]
    bl      ECP256_SubCore2       // zsqr = a->x - zsqr

    ldp     x4 , x5 , [x22, #64]        // a->z
    ldp     x6 , x7 , [x22, #64+16]
    add     x0 , x21, #64               // res_z
    add     x2 , x22, #32               // a->y
    bl      ECP256_MulCore        // res_z = a->z * a->y

    // x14 to x17 save the result of res_z.
    mov     x8 , x14
    mov     x9 , x15
    ldp     x4 , x5 , [sp]              // s = sp[0]
    mov     x10, x16
    mov     x11, x17
    ldp     x6 , x7 , [sp, #16]
    add     x0 , x21, #64               // res_z
    bl      ECP256_AddCore        // res_z = 2 * res_z

    add     x0 , x21, #32               // x0 points to res_y, that is r->y
    bl      ECP256_SqrCore        // res_y = s^2

    add     x0 , x21, #32
    bl      ECP256_DivBy2Core     // res_y = res_y / 2

    ldp     x4 , x5 , [sp, #64]         // m = sp[64]
    ldp     x6 , x7 , [sp, #64+16]
    add     x2 , sp , #32               // zsqr = sp[32]
    add     x0 , sp , #64
    bl      ECP256_MulCore        // m = m * zsqr

    // x14–x17 saves the result of m. Save an extra copy to x4–x7.
    mov     x8 , x14
    mov     x4 , x14
    mov     x9 , x15
    mov     x5 , x15
    mov     x10, x16
    mov     x6 , x16
    mov     x11, x17
    mov     x7 , x17
    add     x0 , sp , #64
    bl      ECP256_AddCore        // m = 2 * m
    mov     x8 , x4
    mov     x9 , x5
    mov     x10, x6
    mov     x11, x7
    bl      ECP256_AddCore        // m = 3 * m

    ldp     x4 , x5 , [sp]              // s = sp[0]
    add     x2 , x22, #0                // a->x
    ldp     x6 , x7 , [sp, #16]
    add     x0 , sp , #0                // s = sp[0]
    bl      ECP256_MulCore        // s = s * a->x

    // x14~x17 exactly saves the result of s
    mov     x8 , x14
    mov     x9 , x15
    ldp     x4 , x5 , [sp, #64]
    mov     x10, x16
    mov     x11, x17
    ldp     x6 , x7 , [sp, #64+16]
    add     x0 , sp , #96               // tmp = sp[96]
    bl      ECP256_AddCore        // tmp = 2 * s

    // x14~x17 exactly saves the result of m.
    add     x0 , x21, #0                // res_x = r->x
    bl      ECP256_SqrCore        // res_x = m^2

    // x14~x17 exactly saves the result of res_x.
    ldp     x8 , x9 , [sp, #96]         // tmp = sp[96]
    ldp     x10, x11, [sp, #96+16]
    bl      ECP256_SubCore1       // res_x = res_x - tmp

    // x14~x17 exactly saves the result of res_x, Therefore, ECP256_SubCore2 is invoked.
    ldp     x8 , x9 , [sp]              // s = sp[0]
    ldp     x10, x11, [sp, #16]
    add     x0 , sp , #0
    bl      ECP256_SubCore2       // s = s - res_x

    // x14~x17 exactly saves the result of s, x0 still points to s.
    mov     x4 , x14
    mov     x5 , x15
    mov     x6 , x16
    mov     x7 , x17
    add     x2 , sp , #64               // m = sp[64]
    bl      ECP256_MulCore        // s = s * m

    // x14 to x17 just save the result of s, so call ECP256_SubCore1.
    add     x0 , x21, #32               // x0 points to res_y
    ldp     x8 , x9 , [x0]              // res_y
    ldp     x10, x11, [x0, #16]
    bl      ECP256_SubCore1       // res_y = s - res_y

    add     sp , x29, #0                // Free temporary variable
    ldp     x19, x20, [x29, #16]
    ldp     x21, x22, [x29, #32]
    ldp     x29, x30, [sp], #96
AARCH64_AUTIASP
    ret
.size    ECP256_PointDouble,.-ECP256_PointDouble

.globl  ECP256_OrdMul
.type   ECP256_OrdMul,%function
.align  4
ECP256_OrdMul:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-64]!
    add     x29, sp , #0
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]

    adrp    x23, .Lord
    add	    x23, x23, :lo12:.Lord       // x23 = &n
    ldp     x12, x13, [x23]             // n[0~3]
    ldp     x21, x22, [x23, #16]
    ldr     x23, [x23, #32]             // x23 = LordK

    ldp     x4 , x5 , [x1]              // a[0~3]
    ldp     x6 , x7 , [x1, #16]

    ldr     x3 , [x2]                   // x3 = b[0]

    mul     x14, x4 , x3                // a[0~3] * b[0]
    umulh   x8 , x4 , x3
    mul     x15, x5 , x3
    umulh   x9 , x5 , x3
    mul     x16, x6 , x3
    umulh   x10, x6 , x3
    mul     x17, x7 , x3
    umulh   x11, x7 , x3

    // a[0-3] * b[0] is stored in x14~x17, x19, x20.
    adds    x15, x15, x8
    adcs    x16, x16, x9
    adcs    x17, x17, x10
    adc     x19, xzr, x11               // x19 = x11 + CF
    mov     x20, xzr

    // reduce
    // n[0] = 0xf3b9cac2fc632551
    // n[1] = 0xbce6faada7179e84
    // n[2] = 0xffffffffffffffff, lo(q*n[2]) = -q     , hi(q*n[2]) = q
    // n[3] = 0xffffffff00000000, lo(q*n[3]) = -lq<<32, hi(q*n[3]) = q-hq
    mul     x24, x14, x23               // x24 = lo(a[0]*b[0]*ordk), Equivalent to q in Montgomery
                                        // modular multiplication

    lsl     x8 , x24, #32               // lq << 32
    lsr     x9 , x24, #32               // hq
    subs    x16, x16, x24               // x16 = x16 + lo(q*n[2]) = x16 - q
    sbcs    x17, x17, x8                // x17 = x17 + lo(q*n[3]) = x17 - lq<<32
    sbcs    x19, x19, x9                // x19 = x19 - hq, Should have added q-hq, here first subtract hq, then add q.
    sbc     x20, x20, xzr               // x20 = x20 - CF

    umulh   x9 , x12, x24               // hi(q*n[0])
    mul     x10, x13, x24               // lo(q*n[1])
    umulh   x11, x13, x24               // hi(q*n[1])

    // First calculate the value to be added to the same accumulator.
    subs    xzr, x14, #1                // CF = (x14 < 1)?
    adcs    x10, x10, x9                // x10 = hi(q*n[0]) + lo(q*n[1])
    adc     x11, x11, xzr               // x11 = hi(q*n[1]) + CF

    // S /= r, accumulation of staggered blocks
    adds    x14, x15, x10               // x14 = x15 + hi(q*n[0]) + lo(q*n[1])
    adcs    x15, x16, x11               // x15 = x16 + hi(q*n[1])
    adcs    x16, x17, x24               // x16 = x17 + hi(q*n[2])
    adcs    x17, x19, x24               // x17 = x19 + q, hq has been subtracted from x19 in front,
                                        // so here x17 = hi(q*n[3])
    adc     x19, x20, xzr               // x19 = x20 + CF

    ldr     x3 , [x2, #8]               // b[1]

    mul     x8 , x4 , x3
    mul     x9 , x5 , x3
    mul     x10, x6 , x3
    mul     x11, x7 , x3

    // add lo(a[0~3] * b[i])
    adds    x14, x14, x8
    adcs    x15, x15, x9
    adcs    x16, x16, x10
    adcs    x17, x17, x11
    adc     x19, x19, xzr

    umulh   x8 , x4 , x3
    umulh   x9 , x5 , x3
    umulh   x10, x6 , x3
    umulh   x11, x7 , x3
    // add hi(a[0~3] * b[i])
    adds    x15, x15, x8
    adcs    x16, x16, x9
    adcs    x17, x17, x10
    adcs    x19, x19, x11
    adc     x20, xzr, xzr

    // reduce
    mul     x24, x14, x23               // x24 = lo(a[0]*b[0]*ordk), equivalent to q
                                        // in Montgomery modular multiplication

    lsl     x8 , x24, #32
    lsr     x9 , x24, #32
    subs    x16, x16, x24
    sbcs    x17, x17, x8
    sbcs    x19, x19, x9
    sbc     x20, x20, xzr

    umulh   x9 , x12, x24               // hi(q*n[0])
    mul     x10, x13, x24               // lo(q*n[1])
    umulh   x11, x13, x24               // hi(q*n[1])

    subs    xzr, x14, #1
    adcs    x10, x10, x9
    adc     x11, x11, xzr

    // S /= r, accumulation of staggered blocks
    adds    x14, x15, x10               // x14 = x15 + hi(q*n[0]) + lo(q*n[1])
    adcs    x15, x16, x11               // x15 = x16 + hi(q*n[1])
    adcs    x16, x17, x24               // x16 = x17 + hi(q*n[2])
    adcs    x17, x19, x24               // x17 = x19 + q, hq has been subtracted from x19 in front,
                                        // so here x17 = hi(q*n[3])
    adc     x19, x20, xzr               // x19 = x20 + CF

    ldr     x3 , [x2, #16]               // b[2]

    mul     x8 , x4 , x3
    mul     x9 , x5 , x3
    mul     x10, x6 , x3
    mul     x11, x7 , x3

    // adds lo(a[0~3] * b[i])
    adds    x14, x14, x8
    adcs    x15, x15, x9
    adcs    x16, x16, x10
    adcs    x17, x17, x11
    adc     x19, x19, xzr

    umulh   x8 , x4 , x3
    umulh   x9 , x5 , x3
    umulh   x10, x6 , x3
    umulh   x11, x7 , x3
    // adds hi(a[0~3] * b[i])
    adds    x15, x15, x8
    adcs    x16, x16, x9
    adcs    x17, x17, x10
    adcs    x19, x19, x11
    adc     x20, xzr, xzr

    // reduce
    mul     x24, x14, x23               // x24 = lo(a[0]*b[0]*ordk), equivalent to q in Montgomery
                                        // modular multiplication

    lsl     x8 , x24, #32
    lsr     x9 , x24, #32
    subs    x16, x16, x24
    sbcs    x17, x17, x8
    sbcs    x19, x19, x9
    sbc     x20, x20, xzr

    umulh   x9 , x12, x24               // hi(q*n[0])
    mul     x10, x13, x24               // lo(q*n[1])
    umulh   x11, x13, x24               // hi(q*n[1])

    subs    xzr, x14, #1
    adcs    x10, x10, x9
    adc     x11, x11, xzr

    // S /= r, accumulation of staggered blocks
    adds    x14, x15, x10               // x14 = x15 + hi(q*n[0]) + lo(q*n[1])
    adcs    x15, x16, x11               // x15 = x16 + hi(q*n[1])
    adcs    x16, x17, x24               // x16 = x17 + hi(q*n[2])
    adcs    x17, x19, x24               // x17 = x19 + q, hq has been subtracted from x19 in front,
                                        // so here x17 = hi(q*n[3])
    adc     x19, x20, xzr               // x19 = x20 + CF

    ldr     x3 , [x2, #24]               // b[3]

    mul     x8 , x4 , x3
    mul     x9 , x5 , x3
    mul     x10, x6 , x3
    mul     x11, x7 , x3

    // add lo(a[0~3] * b[i])
    adds    x14, x14, x8
    adcs    x15, x15, x9
    adcs    x16, x16, x10
    adcs    x17, x17, x11
    adc     x19, x19, xzr

    umulh   x8 , x4 , x3
    umulh   x9 , x5 , x3
    umulh   x10, x6 , x3
    umulh   x11, x7 , x3
    // add hi(a[0~3] * b[i])
    adds    x15, x15, x8
    adcs    x16, x16, x9
    adcs    x17, x17, x10
    adcs    x19, x19, x11
    adc     x20, xzr, xzr

    // reduce
    mul     x24, x14, x23               // x24 = lo(a[0]*b[0]*ordk), equivalent to q in Montgomery
                                        // modular multiplication.

    lsl     x8 , x24, #32
    lsr     x9 , x24, #32
    subs    x16, x16, x24
    sbcs    x17, x17, x8
    sbcs    x19, x19, x9
    sbc     x20, x20, xzr

    umulh   x9 , x12, x24               // hi(q*n[0])
    mul     x10, x13, x24               // lo(q*n[1])
    umulh   x11, x13, x24               // hi(q*n[1])

    subs    xzr, x14, #1
    adcs    x10, x10, x9
    adc     x11, x11, xzr

    // S /= r, Accumulation of staggered blocks
    adds    x14, x15, x10               // x14 = x15 + hi(q*n[0]) + lo(q*n[1])
    adcs    x15, x16, x11               // x15 = x16 + hi(q*n[1])
    adcs    x16, x17, x24               // x16 = x17 + hi(q*n[2])
    adcs    x17, x19, x24               // x17 = x19 + q, hq has been subtracted from x19 in front, so here x17 = hi(q*n[3])
    adc     x19, x20, xzr               // x19 = x20 + CF

    // So far, x14 to x17, and x19 retain the calculation results.
    // x8~x11 save r -= n
    subs    x8 , x14, x12
    sbcs    x9 , x15, x13
    sbcs    x10, x16, x21
    sbcs    x11, x17, x22
    sbcs    xzr, x19, xzr               // Finally, the CF bit is set to indicate whether r-n needs to be borrowed.

    // r = r-n < 0 ? r : r-n
    csel    x14, x14, x8 , lo
    csel    x15, x15, x9 , lo
    csel    x16, x16, x10, lo
    csel    x17, x17, x11, lo

    stp     x14, x15, [x0]              // Write the result to r
    stp     x16, x17, [x0, #16]

    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldr     x29, [sp], #64
AARCH64_AUTIASP
    ret
.size   ECP256_OrdMul,.-ECP256_OrdMul

.globl  ECP256_OrdSqr
.type   ECP256_OrdSqr,%function
.align  4
ECP256_OrdSqr:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-64]!
    add     x29, sp , #0
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]

    adrp    x23, .Lord
    add	    x23, x23, :lo12:.Lord       // x23 = &n
    ldp     x12, x13, [x23]             // n[0~3]
    ldp     x21, x22, [x23, #16]
    ldr     x23, [x23, #32]             // x23 = LordK

    ldp     x4 , x5 , [x1]              // x4~x7 = a[0~3]
    ldp     x6 , x7 , [x1, #16]

.align  4
.Lord_sqr:
    sub     x2 , x2 , #1
/******************************************
    x7   x1   x20  x19  x17  x16  x15  x14
                             h0*1 l0*1
                        h0*2 l0*2
                   h0*3 l0*3
                   h1*2 l1*2
              h1*3 l1*3
         h2*3 l2*3
    h3*3 l3*3 h2*2 l2*2 h1*1 l1*1 h0*0 l0*0
*******************************************/

    // a[1~3] * a[0]
    mul     x15, x5 , x4            // lo(a[1] * a[0])
    umulh   x8 , x5 , x4            // hi(a[1] * a[0])
    mul     x16, x6 , x4            // lo(a[2] * a[0])
    umulh   x9 , x6 , x4            // hi(a[2] * a[0])
    mul     x17, x7 , x4            // lo(a[3] * a[0])
    umulh   x19, x7 , x4            // hi(a[3] * a[0])

    adds    x16, x16, x8
    adcs    x17, x17, x9
    adc     x19, x19, xzr           // No more carry

    // a[2~3] * a[1]
    mul     x8 , x6 , x5            // lo(a[2] * a[1])
    umulh   x9 , x6 , x5            // hi(a[2] * a[1])
    mul     x10, x7 , x5            // lo(a[3] * a[1])
    umulh   x11, x7 , x5            // hi(a[3] * a[1])

    // a[3] * a[2]
    mul     x20, x7 , x6
    umulh   x1 , x7 , x6

    // Add the calculation result of the current round,
    // and then add the calculation result with the acc (register in the preceding note).
    adds    x9 , x10, x9
    adc     x10, x11, xzr

    adds    x17, x17, x8
    adcs    x19, x19, x9
    adcs    x20, x20, x10
    adc     x1 , x1 , xzr           // a[0-3] has been saved in x4 to x7.

    // a[0~3] ^ 2
    mul     x14, x4 , x4
    umulh   x4 , x4 , x4
    mul     x8 , x5 , x5
    umulh   x5 , x5 , x5
    mul     x9 , x6 , x6
    umulh   x6 , x6 , x6
    mul     x10, x7 , x7
    umulh   x7 , x7 , x7

    // acc[1~6] << 1
    adds    x15, x15, x15
    adcs    x16, x16, x16
    adcs    x17, x17, x17
    adcs    x19, x19, x19
    adcs    x20, x20, x20
    adcs    x1 , x1 , x1
    adc     x3 , xzr, xzr

    // acc[] += a[] ^ 2
    adds    x15, x15, x4
    adcs    x16, x16, x8
    adcs    x17, x17, x5
    adcs    x19, x19, x9
    adcs    x20, x20, x6
    adcs    x1 , x1 , x10
    adc     x7 , x7 , x3

    // Four rounds of reduce
    mul     x24, x14, x23               // x24 = lo(a[0]*b[0]*ordk), equivalent to q in Montgomery
                                        // modular multiplication

    umulh   x9 , x12, x24               // hi(q*n[0])
    mul     x10, x13, x24               // lo(q*n[1])
    umulh   x11, x13, x24               // hi(q*n[1])

    // First calculate the value to be added to the same accumulator.
    subs    xzr, x14, #1                // CF = (x14 < 1)
    adcs    x10, x10, x9                // x10 = hi(q*n[0]) + lo(q*n[1])
    adc     x11, x11, xzr               // x11 = hi(q*n[1]) + CF

    // S /= r, accumulation of staggered blocks
    adds    x14, x15, x10               // x14 = x15 + hi(q*n[0]) + lo(q*n[1])
    adcs    x15, x16, x11               // x15 = x16 + hi(q*n[1])
    adcs    x16, x17, x24               // x16 = x17 + hi(q*n[2])
    adc     x17, xzr, x24               // x17 += q, Supposed to be add hi(q*n[3]) = q-hq, hq will be subtracted later.

    lsl     x8 , x24, #32               // lq << 32
    lsr     x9 , x24, #32               // hq

    subs    x15, x15, x24               // x15 = x15 + lo(q*n[2]) = x15 - q
    sbcs    x16, x16, x8                // x16 = x16 + lo(q*n[3]) = x16 - lq<<32
    sbc     x17, x17, x9                // x17 = x17 - hq, (remaining part of hi(q*n[3]))

    // Round 2 reduce
    mul     x24, x14, x23               // x24 = lo(a[0]*b[0]*ordk), equivalent to q in Montgomery
                                        // modular multiplication

    umulh   x9 , x12, x24               // hi(q*n[0])
    mul     x10, x13, x24               // lo(q*n[1])
    umulh   x11, x13, x24               // hi(q*n[1])

    // First calculate the value to be added to the same accumulator.
    subs    xzr, x14, #1                // CF = (x14 < 1)
    adcs    x10, x10, x9                // x10 = hi(q*n[0]) + lo(q*n[1])
    adc     x11, x11, xzr               // x11 = hi(q*n[1]) + CF

    // S /= r, accumulation of staggered blocks
    adds    x14, x15, x10               // x14 = x15 + hi(q*n[0]) + lo(q*n[1])
    adcs    x15, x16, x11               // x15 = x16 + hi(q*n[1])
    adcs    x16, x17, x24               // x16 = x17 + hi(q*n[2])
    adc     x17, xzr, x24               // x17 += q, Supposed to be add hi(q*n[3]) = q-hq, hq will be subtracted later.

    lsl     x8 , x24, #32               // lq << 32
    lsr     x9 , x24, #32               // hq

    subs    x15, x15, x24               // x15 = x15 + lo(q*n[2]) = x15 - q
    sbcs    x16, x16, x8                // x16 = x16 + lo(q*n[3]) = x16 - lq<<32
    sbc     x17, x17, x9                // x17 = x17 - hq, (The remainder of the hi(q*n[3]))

    // Round 3 reduce
    mul     x24, x14, x23               // x24 = lo(a[0]*b[0]*ordk), equivalent to q in Montgomery
                                        // modular multiplication

    umulh   x9 , x12, x24               // hi(q*n[0])
    mul     x10, x13, x24               // lo(q*n[1])
    umulh   x11, x13, x24               // hi(q*n[1])

    // First calculate the value to be added to the same accumulator.
    subs    xzr, x14, #1                // CF = (x14 < 1)
    adcs    x10, x10, x9                // x10 = hi(q*n[0]) + lo(q*n[1])
    adc     x11, x11, xzr               // x11 = hi(q*n[1]) + CF

    // S /= r, accumulation of staggered blocks
    adds    x14, x15, x10               // x14 = x15 + hi(q*n[0]) + lo(q*n[1])
    adcs    x15, x16, x11               // x15 = x16 + hi(q*n[1])
    adcs    x16, x17, x24               // x16 = x17 + hi(q*n[2])
    adc     x17, xzr, x24               // x17 += q, Supposed to be add hi(q*n[3]) = q-hq, hq will be subtracted later.

    lsl     x8 , x24, #32               // lq << 32
    lsr     x9 , x24, #32               // hq

    subs    x15, x15, x24               // x15 = x15 + lo(q*n[2]) = x15 - q
    sbcs    x16, x16, x8                // x16 = x16 + lo(q*n[3]) = x16 - lq<<32
    sbc     x17, x17, x9                // x17 = x17 - hq, (Remaining part of hi(q*n[3]))

    // Round 4 reduce
    mul     x24, x14, x23               // x24 = lo(a[0]*b[0]*ordk), equivalent to q in Montgomery
                                        // modular multiplication

    umulh   x9 , x12, x24               // hi(q*n[0])
    mul     x10, x13, x24               // lo(q*n[1])
    umulh   x11, x13, x24               // hi(q*n[1])

    // First calculate the value to be added to the same accumulator.
    subs    xzr, x14, #1                // CF = (x14 < 1)
    adcs    x10, x10, x9                // x10 = hi(q*n[0]) + lo(q*n[1])
    adc     x11, x11, xzr               // x11 = hi(q*n[1]) + CF

    // S /= r, accumulation of staggered blocks
    adds    x14, x15, x10               // x14 = x15 + hi(q*n[0]) + lo(q*n[1])
    adcs    x15, x16, x11               // x15 = x16 + hi(q*n[1])
    adcs    x16, x17, x24               // x16 = x17 + hi(q*n[2])
    adc     x17, xzr, x24               // x17 += q, Supposed to be add hi(q*n[3]) = q-hq, hq will be subtracted later.

    lsl     x8 , x24, #32               // lq << 32
    lsr     x9 , x24, #32               // hq

    subs    x15, x15, x24               // x15 = x15 + lo(q*n[2]) = x15 - q
    sbcs    x16, x16, x8                // x16 = x16 + lo(q*n[3]) = x16 - lq<<32
    sbc     x17, x17, x9                // x17 = x17 - hq, (Remaining part of hi(q*n[3]))

    // add acc[4-7], x14~x19 is the current calculation result r
    adds    x14, x14, x19
    adcs    x15, x15, x20
    adcs    x16, x16, x1
    adcs    x17, x17, x7
    adc     x19, xzr, xzr

    // r -= p
    subs    x8 , x14, x12
    sbcs    x9 , x15, x13
    sbcs    x10, x16, x21
    sbcs    x11, x17, x22
    sbcs    xzr, x19, xzr           // The set CF is used to determine the relationship between r and p.

    // r = r-p < 0 ? r : r-p
    // Use x4 to x7 to save the result. You can perform the square operation cyclically.
    csel    x4 , x14, x8 , lo
    csel    x5 , x15, x9 , lo
    csel    x6 , x16, x10, lo
    csel    x7 , x17, x11, lo

    cbnz    x2 , .Lord_sqr      // Number of square operations, that is a^(2^rep)

    stp     x4 , x5 , [x0]
    stp     x6 , x7 , [x0, #16]

    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldr     x29, [sp], #64
AARCH64_AUTIASP
    ret
.size   ECP256_OrdSqr,.-ECP256_OrdSqr

.globl  ECP256_Scatterw5
.type   ECP256_Scatterw5,%function
.align  4
ECP256_Scatterw5:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-16]!
    add     x29, sp , #0

    add     x0 , x0 , x2 , lsl#3    // Needs x0 = x0 + (x2-1)*8 = x0 + x2*8 - 8
                                    // The action of -8 is placed in the str instruction.

    ldp     x4 , x5 , [x1]          // x
    ldp     x6 , x7 , [x1, #16]

    str     x4 , [x0, #128*0-8]     // 8*16*0
    str     x5 , [x0, #128*1-8]     // 8*16*1
    str     x6 , [x0, #128*2-8]     // 8*16*2
    str     x7 , [x0, #128*3-8]     // 8*16*3

    add     x0 , x0 , #64*8

    ldp     x4 , x5 , [x1, #32]     // y
    ldp     x6 , x7 , [x1, #32+16]

    str     x4 , [x0, #128*0-8]     // 8*16*0
    str     x5 , [x0, #128*1-8]     // 8*16*1
    str     x6 , [x0, #128*2-8]     // 8*16*2
    str     x7 , [x0, #128*3-8]     // 8*16*3

    add     x0 , x0 , #64*8

    ldp     x4 , x5 , [x1, #64]     // z
    ldp     x6 , x7 , [x1, #64+16]

    str     x4 , [x0, #128*0-8]     // 8*16*0
    str     x5 , [x0, #128*1-8]     // 8*16*1
    str     x6 , [x0, #128*2-8]     // 8*16*2
    str     x7 , [x0, #128*3-8]     // 8*16*3

    ldr     x29, [sp], #16
AARCH64_AUTIASP
    ret
.size   ECP256_Scatterw5,.-ECP256_Scatterw5

.globl  ECP256_Gatherw5
.type   ECP256_Gatherw5,%function
.align  4
ECP256_Gatherw5:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-16]!
    add     x29, sp , #0

    cmp     x2 , xzr
    csetm   x3 , ne                 // x3 = (x2 == 0) ? 0 : -1
    add     x2 , x2 , x3            // x2 += x3, if x2 != 0, then x2 = x2 - 1, if not x2 = 0

    add     x1 , x1 , x2 , lsl#3    // x1 += x2*8, offset

    ldr     x4 , [x1, #128*0]
    ldr     x5 , [x1, #128*1]
    ldr     x6 , [x1, #128*2]
    ldr     x7 , [x1, #128*3]

    csel    x4 , x4 , xzr, ne       // If x2 = 0, Then return to 0. Otherwise, returns the read point coordinates
    csel    x5 , x5 , xzr, ne
    csel    x6 , x6 , xzr, ne
    csel    x7 , x7 , xzr, ne

    stp     x4 , x5 , [x0]          // r->x
    stp     x6 , x7 , [x0, #16]

    add     x1 , x1 , #64*8

    ldr     x4 , [x1, #128*0]
    ldr     x5 , [x1, #128*1]
    ldr     x6 , [x1, #128*2]
    ldr     x7 , [x1, #128*3]

    csel    x4 , x4 , xzr, ne       // If x2 = 0, return 0. Otherwise, returns the read point coordinates
    csel    x5 , x5 , xzr, ne
    csel    x6 , x6 , xzr, ne
    csel    x7 , x7 , xzr, ne

    stp     x4 , x5 , [x0, #32]          // r->y
    stp     x6 , x7 , [x0, #48]

    add     x1 , x1 , #64*8

    ldr     x4 , [x1, #128*0]
    ldr     x5 , [x1, #128*1]
    ldr     x6 , [x1, #128*2]
    ldr     x7 , [x1, #128*3]

    csel    x4 , x4 , xzr, ne       // If x2 = 0, return 0. Otherwise, returns the read point coordinates
    csel    x5 , x5 , xzr, ne
    csel    x6 , x6 , xzr, ne
    csel    x7 , x7 , xzr, ne

    stp     x4 , x5 , [x0, #64]          // r->z
    stp     x6 , x7 , [x0, #80]

    ldr     x29, [sp], #16
AARCH64_AUTIASP
    ret
.size   ECP256_Gatherw5,.-ECP256_Gatherw5

.globl  ECP256_Scatterw7
.type   ECP256_Scatterw7,%function
.align  4
ECP256_Scatterw7:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-16]!
    add     x29, sp , #0

    // add     x0 , x0 , x2
    sub     x2 , x2 , #63           // x2 = x2 - 63
    sub     x0 , x0 , x2            // x0 = x0 - (x2(original) - 63) = x0 + (63 - x2(original))
    mov     x2 , #8                 // Loop count
.Lscatter_w7:
    ldr     x3 , [x1], #8
    subs    x2 , x2 , #1

    strb    w3 , [x0, #64*0]
    lsr     x3 , x3 , #8
    strb    w3 , [x0, #64*1]
    lsr     x3 , x3 , #8
    strb    w3 , [x0, #64*2]
    lsr     x3 , x3 , #8
    strb    w3 , [x0, #64*3]
    lsr     x3 , x3 , #8
    strb    w3 , [x0, #64*4]
    lsr     x3 , x3 , #8
    strb    w3 , [x0, #64*5]
    lsr     x3 , x3 , #8
    strb    w3 , [x0, #64*6]
    lsr     x3 , x3 , #8
    strb    w3 , [x0, #64*7]
    add     x0 , x0 , #64*8
    b.ne    .Lscatter_w7

    ldr    x29, [sp], #16
AARCH64_AUTIASP
    ret
.size   ECP256_Scatterw7,.-ECP256_Scatterw7

// The anti-cache attack solution can be used together with ECP256_Scatterw7.
.globl  ECP256_Gatherw7
.type   ECP256_Gatherw7,%function
.align  4
ECP256_Gatherw7:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-16]!
    add     x29, sp , #0

    cmp     x2 , xzr
    csetm   x3 , ne               // x3 = (x2 == 0) ? 0 : -1
    add     x2 , x2 , x3          // x2 = (x2 == 0) ? 0 : (x2 - 1) (offset)
    sub     x2 , x2 , #63         // x2 = x2 - 63
    sub     x1 , x1 , x2          // x0 = x0 - (x2(original) - 63) = x0 + (63 - x2(original))
    mov     x2 , #8               // Indicates the number of cycles. The x and y coordinates contain 64 bytes in total,
                                  // and 8 bytes are obtained at a time. Therefore, eight cycles are required.
    nop
.Lgather_w7:

    ldrb    w4 , [x1, #64*0]
    ldrb    w5 , [x1, #64*1]
    ldrb    w6 , [x1, #64*2]
    ldrb    w7 , [x1, #64*3]
    ldrb    w8 , [x1, #64*4]
    ldrb    w9 , [x1, #64*5]
    ldrb    w10, [x1, #64*6]
    ldrb    w11, [x1, #64*7]

    // x4 = x4 | x5 << 8
    // x6 = x6 | x7 << 8
    // x4 = x4 | x6 << 16
    // x4 = [x7][x6][x5][x4]
    orr     x4 , x4 , x5 , lsl#8
    orr     x6 , x6 , x7 , lsl#8
    orr     x4 , x4 , x6 , lsl#16

    // x8  = x8  | x9 << 8
    // x10 = x10 | x11 << 8
    // x8  = x8  | x10 << 16
    // x8  = [x11][x10][x9][x8]
    orr     x8 , x8 , x9 , lsl#8
    orr     x10, x10, x11, lsl#8
    orr     x8 , x8 , x10, lsl#16

    // x4  = x4 | x8 << 32
    // x4  = [x11][x10][x9][x8]
    orr     x4 , x4 , x8 , lsl#32

    and     x4 , x4 , x3
    str     x4 , [x0], #8

    add     x1 , x1 , #64*8
    subs    x2 , x2, #1
    b.ne    .Lgather_w7

    ldr    x29,[sp],#16
AARCH64_AUTIASP
    ret
.size   ECP256_Gatherw7,.-ECP256_Gatherw7

#endif
