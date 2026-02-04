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

/*
 * Description: Big number Montgomery modular multiplication in armv8 implementation, MontMul_Asm
 * Ref: Montgomery Multiplication
 * Process: To cal A * B mod n, we can convert to mont form, and cal A*B*R^(-1).
 * Detail: 
 * intput:A = (An-1,...,A1,A0)b, B = (Bn-1,...,B1,B0)b, n, n'
 * output:A*B*R^(-1)
 * tmp = (tn,tn-1,...,t1,t0)b, initialize to 0
 * for i: 0 -> (n-1)
 *     ui = (t0 + Ai*B0)m' mod b
 *     t = (t + Ai*B + ui * m) / b
 * if t >= m
 *     t -= m
 * return t;
 *
 * Deal process:
 *   i.    size % 8 == 0 & a == b --> Sqr8x --> complete multiplication
 *                                                --> size == 8, goto single reduce step
 *                                                --> size >= 8, goto loop reduce process
 *   ii.   size % 4 == 0 --> Mul4x
 *                           --> size == 4, goto single step
 *                           --> size >= 4, goto loop process
 *   iii.  Ordinary --> Mul1x
 *                       --> size == 2, goto single step
 *                       --> size >= 2, goto loop process
 *
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include "crypt_arm.h"

.arch   armv8-a+crypto
.file   "bn_mont_armv8.S"
.text

.global MontMul_Asm
.type   MontMul_Asm, %function
.align  5
MontMul_Asm:
AARCH64_PACIASP
    tst     x5, #7
    b.eq    MontSqr8
    tst     x5, #3
    b.eq    MontMul4

    stp     x29, x30, [sp, #-64]!
    mov     x29, sp
    stp     x23, x24, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x19, x20, [sp, #48]

    sub     x21, x5 , #2           // j = size-2
    cbnz    x21,.LMul1xBegin

    // if size == 2, goto single step
    ldp     x15, x16, [x1]         // a[0], a[1]
    ldp     x19, x20, [x2]         // b[0], b[1]
    ldp     x9, x10, [x3]          // n[0], n[1]

    mul     x23 , x15 , x19             // x23 = lo(a[0] * b[0])
    umulh   x24 , x15 , x19             // x24 = hi(a[0] * b[0])
    mul     x6, x16 , x19               // x6 = lo(a[1] * b[0])
    umulh   x7, x16 , x19               // x7 = hi(a[1] * b[0])

    mul     x11, x23 , x4               // x11 = lo(t[0] * k0)
    umulh   x19, x9, x11                // x19 = hi(n[0] * t[0]*k0)
    mul     x12, x10, x11               // x12 = lo(n[1] * t[0]*k0)
    umulh   x13, x10, x11               // x13 = hi(n[1] * t[0]*k0)

    // we knowns a*b + n'n = 0 (mod R)
    // so lo(a[0] * b[0]) + lo(n[0] * t[0]*k0) = 0 (mod R)
    // if lo(a[0] * b[0]) > 0, then 'lo(a[0] * b[0]) + lo(n[0] * t[0]*k0)' would overflow,
    // else if lo(a[0] * b[0]) == 0, then lo(n[0] * t[0]*k0) == 0
    cmp     x23, #1
    adc     x19, x19, xzr

    adds    x23 , x6, x24               // x23 = lo(a[1] * b[0]) + hi(a[0] * b[0])
    adc     x24 , x7, xzr               // x24 = hi(a[1] * b[0]) + CF

    adds    x8, x12, x19                // x8 = lo(n[1] * t[0]*k0) + hi(n[0] * t[0]*k0)
    adc     x19, x13, xzr               // x19 = hi(n[1] * t[0]*k0) + CF

    adds    x21, x8, x23                // x21 = lo(n[1] * t[0]*k0) + hi(n[0] * t[0]*k0)
    adcs    x22, x19, x24
    adc     x23, xzr, xzr               // x23 = CF

    mul     x14 , x15 , x20             // a[0] * b[1]
    umulh   x15 , x15 , x20
    mul     x6, x16 , x20               // a[1] * b[1]
    umulh   x7, x16 , x20
    adds    x14 , x14 , x21
    adc     x15 , x15 , xzr

    mul     x11, x14 , x4               // t[0] * k0

    umulh   x20, x9, x11
    mul     x12, x10, x11               // n[1] * t[0]*k0
    umulh   x13, x10, x11
    cmp     x14 , #1                    // Check whether the low location is carried.
    adc     x20, x20, xzr
    adds    x14 , x6, x15
    adc     x15 , x7, xzr

    adds    x21, x12, x20
    adcs    x20, x13, x23
    adc     x23, xzr, xzr

    adds    x14 , x14 , x22
    adc     x15 , x15 , xzr

    adds    x21, x21, x14
    adcs    x20, x20, x15
    adc     x23, x23, xzr               // x23 += CF

    subs    x12 , x21, x9
    sbcs    x13, x20, x10
    sbcs    x23, x23, xzr               // update CF

    csel    x10, x21, x12, lo
    csel    x11, x20, x13, lo
    stp     x10, x11, [x0]
    b       .LMul1xEnd

.LMul1xBegin:
    mov     x24, x5                 // the outermost pointers of our loop
    lsl     x5 , x5 , #3
    sub     x22, sp , x5            // The space size needs to be applied for.
    and     x22, x22, #-16          // For 4-byte alignment
    mov     sp , x22                // Apply for Space.
    mov     x6, x5
    mov     x23, xzr

.LMul1xInitstack:
    sub     x6, x6, #8
    str     xzr, [x22], #8
    cbnz    x6, .LMul1xInitstack
    mov     x22, sp

.LMul1xLoopProces:
    sub     x24, x24, #1
    sub     x21, x5 , #16           // j = size-2

    // Begin mulx
    ldr     x17, [x2], #8           // b[i]
    ldp     x15, x16, [x1], #16     // a[0], a[1]
    ldp     x9, x10, [x3], #16      // n[0], n[1]
    ldr     x19, [x22]              // The sp val is 0 during initialization.

    mul     x14 , x15 , x17         // a[0] * b[i]
    umulh   x15 , x15 , x17
    mul     x6, x16 , x17           // a[1] * b[i]
    umulh   x7, x16 , x17
    adds    x14 , x14 , x19
    adc     x15 , x15 , xzr

    mul     x11, x14 , x4
    umulh   x9, x9, x11
    mul     x12, x10, x11           // n[1] * t[0]*k0
    cmp     x14, #1
    umulh   x13, x10, x11

.LMul1xPrepare:
    sub     x21, x21, #8            // index -= 1
    ldr     x16, [x1], #8           // a[i]
    ldr     x10, [x3], #8           // n[i]
    ldr     x19, [x22, #8]          // t[j]

    adc     x9, x9, xzr
    adds    x14 , x6, x15
    adc     x15 , x7, xzr

    adds    x8, x12, x9
    adc     x9, x13, xzr

    mul     x6, x16, x17            // a[j] * b[i]
    adds    x14, x14 , x19
    umulh   x7, x16 , x17
    adc     x15, x15 , xzr

    mul     x12, x10, x11           // n[j] * t[0]*k0
    adds    x8, x8, x14
    umulh   x13, x10, x11
    str     x8, [x22], #8           // t[j-1]
    cbnz    x21, .LMul1xPrepare

.LMul1xReduce:
    ldr     x19, [x22, #8]
    adc     x9, x9, xzr
    adds    x14 , x6, x15
    adc     x15 , x7, xzr

    adds    x8, x12, x9
    adcs    x9, x13, x23
    adc     x23, xzr, xzr

    adds    x14 , x14 , x19
    adc     x15 , x15 , xzr

    adds    x8, x8, x14
    adcs    x9, x9, x15
    adc     x23, x23, xzr           // x23 += CF, carry of the most significant bit.
    stp     x8, x9, [x22], #8

    mov     x22, sp
    sub     x1 , x1 , x5
    subs    x3 , x3 , x5            // x3 = &n[0]
    cbnz    x24, .LMul1xLoopProces

    mov     x1, x0
    mov     x21, x5                 // get index

.LMul1xSubMod:
    ldr     x19, [x22], #8
    ldr     x10, [x3], #8
    sub     x21, x21, #8            // j--
    sbcs    x16, x19, x10           // t[j] - n[j]
    str     x16, [x1], #8           // r[j] = t[j] - n[j]
    cbnz    x21,.LMul1xSubMod

    sbcs    x23, x23, xzr           // x23 -= CF
    mov     x22, sp
.LMul1xCopy:
    ldr     x19, [x22], #8
    ldr     x16, [x0]
    sub     x5, x5, #8              // size--
    csel    x10, x19, x16, lo
    str     x10, [x0], #8
    cbnz    x5 , .LMul1xCopy

.LMul1xEnd:
    ldp     x23, x24, [x29, #16]
    mov     sp , x29
    ldp     x21, x22, [x29, #32]
    ldp     x19, x20, [x29, #48]
    ldr     x29, [sp], #64
AARCH64_AUTIASP
    ret
.size   MontMul_Asm, .-MontMul_Asm

.type   MontSqr8, %function
MontSqr8:
    cmp     x1, x2
    b.ne    MontMul4

    stp     x29, x30, [sp, #-128]!  //  sp = sp - 128(Modify the SP and then save the SP.), [sp] = x29, [sp + 8] = x30,
                                    //  !Indicates modification sp
    mov     x29, sp                 //  x29  = sp, The sp here has been reduced by 128.

    stp     x27, x28, [sp, #16]
    stp     x25, x26, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x21, x22, [sp, #64]
    stp     x19, x20, [sp, #80]
    stp     x0 , x3 , [sp, #96]     // offload r and n, Push the pointers of r and n into the stack.
    str     x4 , [sp, #112]         // store n0

    lsl     x5, x5, #3              // x5 = x5 * 8, Converts size to bytes.
    sub     x2, sp, x5, lsl#1       // x2 = sp - 2*x5*8, x5 = size, x2 points to the start address of a 2*size memory. *8 is to convert to bytes
    mov     sp, x2                  // Alloca, Apply for Space.
    mov     x19, x5                 // The lowest eight data blocks do not need to be cleared.
    eor     v0.16b,v0.16b,v0.16b
    eor     v1.16b,v1.16b,v1.16b

.LSqr8xStackInit:
    sub     x19, x19, #8*8          // Offset 64, cyclic increment.
    st1     {v0.2d, v1.2d}, [x2], #32
    st1     {v0.2d, v1.2d}, [x2], #32
    st1     {v0.2d, v1.2d}, [x2], #32
    st1     {v0.2d, v1.2d}, [x2], #32
    cbnz    x19, .LSqr8xStackInit   // When x19 = 0, the loop exits.

    mov     x2 , sp                 // After clear to zero, assign sp back to x2.

    ldp     x27, x28, [x2]
    ldp     x25, x26, [x2]
    ldp     x23, x24, [x2]
    ldp     x21, x22, [x2]

    add     x3 , x1 , x5            // x3 = x1 + bytes(size * 8)

    ldp     x14 , x15 , [x1], #16    // x14  = a[0], x15  = a[1]
    ldp     x16 , x17 , [x1], #16    // x16  = a[2], x17  = a[3]
    ldp     x6, x7, [x1], #16    // x6 = a[4], x7 = a[5]
    ldp     x8, x9, [x1], #16    // x8 = a[6], x9 = a[7]

.LSqr8xLoopMul:
    mul     x10, x14, x15             // a[0] * a[1~4]
    mul     x11, x14, x16             // keep cache hit ratio of x6
    mul     x12, x14, x17
    mul     x13, x14, x6
    adds    x28, x28, x10           // x27~x22 = t[0~7], x28 = t[1] = lo(a[0]*a[1]), adds is used to set CF to 0.
    adcs    x25, x25, x11           // x10~x17 Used to save subsequent calculation results

    mul     x10, x14 , x7           // lo(a[0] * a[5~7]), keep cache hit ratio of x14, the same below
    mul     x11, x14 , x8
    adcs    x26, x26, x12
    adcs    x23, x23, x13           // t[4] = lo(a[0] * a[4])
    adcs    x24, x24, x10           // x24~x22 = t[5~7]
    mul     x12, x14 , x9           // lo(a[0] * a[7])

    stp     x27, x28, [x2], #8*2        // t[0] = a[0]^2, Because the square term is not calculated temporarily,
                                    // so t[0] = 0, t[1] = a[0] * a[1] + carry

    adcs    x21, x21, x11
    adcs    x22, x22, x12           // t[7] += lo(a[0] * a[7]), Carrying has to be given t[8]
    adc     x27, xzr, xzr               // x27 = CF ( Set by t[7] += lo(a[0] * a[7]) ),
    umulh   x13, x14 , x15          // hi(a[0] * a[1~4]), Use x17 to keep the cache hit
    umulh   x10, x14 , x16
    umulh   x11, x14 , x17
    umulh   x12, x14 , x6

    // In the new round, the first calculation does not need to be carried, but the CF bit needs to be modified.
    adds    x25, x25, x13           // t[2] += hi(a[0] * a[1])
    adcs    x26, x26, x10
    adcs    x23, x23, x11
    adcs    x24, x24, x12           // t[5] += hi(a[0] * a[4])
    umulh   x13, x14 , x7           // hi(a[0] * a[5~7])
    umulh   x10, x14 , x8
    umulh   x11, x14 , x9

    //----- lo(a[1] * a[2~4]) ------
    adcs    x21, x21, x13           // t[6] += hi(a[0] * a[5])
    adcs    x22, x22, x10           // t[7] += hi(a[0] * a[6])
    adc     x27, x27, x11           // t[8] += hi(a[0] * a[7])
    mul     x12, x15, x16           // lo(a[1] * a[2])
    mul     x13, x15, x17
    mul     x10, x15, x6

    //----- lo(a[1] * a[5~7]) ------
    adds    x26, x26, x12           // t[3] += lo(a[1] * a[2]), The first calculation of this round
                                    // does not take into account the previous carry, and the CF is not modified in line 118.
    adcs    x23, x23, x13           // t[4] += lo(a[1] * a[3])
    adcs    x24, x24, x10           // t[5] += lo(a[1] * a[4])
    mul     x11, x15 , x7
    mul     x12, x15 , x8
    mul     x13, x15 , x9

    //----- hi(a[1] * a[2~5]) ------
    adcs    x21, x21, x11           // t[6] += lo(a[1] * a[5])
    adcs    x22, x22, x12           // t[7] += lo(a[1] * a[6])
    adcs    x27, x27, x13           // t[8] += lo(a[1] * a[7])
    umulh   x10, x15, x16           // hi(a[1] * a[2])
    umulh   x11, x15, x17
    umulh   x12, x15, x6
    umulh   x13, x15, x7

    stp     x25, x26, [x2], #8*2        // t[2] and t[3] are calculated and stored in the memory.
                                        // x25 and x22 are used to store t[10] and t[11].
    adc     x28, xzr, xzr               // t[9] = CF ( Set by t[8] += lo(a[1] * a[7]) )
    //In the new round, the first calculation does not need to be carried, but the CF bit needs to be modified.
    //----- hi(a[1] * a[6~7]) ------
    adds    x23, x23, x10           // t[4] += hi(a[1] * a[2])
    adcs    x24, x24, x11           // t[5] += hi(a[1] * a[3])
    adcs    x21, x21, x12           // t[6] += hi(a[1] * a[4])
    umulh   x10, x15 , x8           // hi(a[1] * a[6])
    umulh   x11, x15 , x9           // hi(a[1] * a[7])

    //----- lo(a[2] * a[3~7]) ------
    adcs    x22, x22, x13           // t[7] += hi(a[1] * a[5])
    adcs    x27, x27, x10           // t[8] += hi(a[1] * a[6])
    adc     x28, x28, x11           // t[9] += hi(a[1] * a[7]), Here, only the carry of the previous round
    mul     x12, x16, x17           // lo(a[2] * a[3])
    mul     x13, x16, x6
    mul     x10, x16, x7
                                    // of calculation is retained before x20 calculation. Add x15 to the carry.
    mul     x11, x16 , x8
    adds    x24, x24, x12           // t[5] += lo(a[2] * a[3]), For the first calculation of this round,
                                    // the previous carry is not considered.
    mul     x12, x16 , x9
    adcs    x21, x21, x13           // t[6] += lo(a[2] * a[4])

    //----- hi(a[2] * a[3~7]) ------
    adcs    x22, x22, x10           // t[7] += lo(a[2] * a[5])
    umulh   x13, x16, x17           // hi(a[2] * a[3])
    umulh   x10, x16, x6

    adcs    x27, x27, x11           // t[8] += lo(a[2] * a[6])
    adcs    x28, x28, x12           // t[9] += lo(a[2] * a[7])
    umulh   x11, x16, x7
    umulh   x12, x16, x8

    stp     x23, x24, [x2], #8*2    // After t[4] and t[5] are calculated, they are stored in the memory.
                                    // x23 and x24 are used to store t[12] and t[13].
    adc     x25, xzr, xzr           // t[10] = CF ( Set by t[9] += lo(a[2] * a[7]) )
    // In the new round, the first calculation does not need to be carried, but the CF bit needs to be modified.
    adds    x21, x21, x13           // t[6] += hi(a[2] * a[3])
    adcs    x22, x22, x10           // t[7] += hi(a[2] * a[4])
    umulh   x13, x16, x9

    //----- lo(a[3] * a[4~7]) ------
    adcs    x27, x27, x11           // t[8] += hi(a[2] * a[5])
    adcs    x28, x28, x12           // t[9] += hi(a[2] * a[6])
    adc     x25, x25, x13           // t[10] += hi(a[2] * a[7])
    mul     x10, x17, x6
    mul     x11, x17, x7
    mul     x12, x17, x8
    mul     x13, x17, x9

    //----- hi(a[3] * a[4~7]) ------
    adds    x22, x22, x10           // t[7] += lo(a[3] * a[4])
    adcs    x27, x27, x11           // t[8] += lo(a[3] * a[5])
    adcs    x28, x28, x12           // t[9] += lo(a[3] * a[6])
    adcs    x25, x25, x13           // t[10] += lo(a[3] * a[7])
    umulh   x10, x17, x6
    umulh   x11, x17, x7
    umulh   x12, x17, x8
    umulh   x13, x17, x9

    stp     x21, x22, [x2], #8*2    // t[6] and t[7] are calculated and stored in the memory.
                                    // x21 and x26 are used to store t[14] and t[15].
    adc     x26, xzr, xzr           // t[11] = CF ( Set by t[10] += lo(a[3] * a[7]) )
    // In the new round, the first calculation does not need to be carried, but the CF bit needs to be modified.
    adds    x27, x27, x10           // t[8] += hi(a[3] * a[4])

    //----- lo(a[4] * a[5~7]) ------
    adcs    x28, x28, x11           // t[9] += hi(a[3] * a[5])
    adcs    x25, x25, x12           // t[10] += hi(a[3] * a[6])
    adc     x26, x26, x13           // t[11] += hi(a[3] * a[7])
    mul     x10, x6, x7
    mul     x11, x6, x8
    mul     x12, x6, x9

    //----- hi(a[4] * a[5~7]) ------
    adds    x28, x28, x10           // t[9] += lo(a[4] * a[5])
    adcs    x25, x25, x11           // t[10] += lo(a[4] * a[6])
    adcs    x26, x26, x12           // t[11] += lo(a[4] * a[7])
    umulh   x13, x6, x7
    umulh   x10, x6, x8
    umulh   x11, x6, x9

    //----- lo(a[5] * a[6~7]) ------
    mul     x12, x7, x8
    // This is actually a new round, but only t[0-7] can be calculated in each cycle,
    // and t[8-15] retains the intermediate calculation result.
    adc     x23, xzr, xzr           // t[12] = CF( Set by t[11] += lo(a[4] * a[7]) )
    adds    x25, x25, x13           // t[10] += hi(a[4] * a[5])
    adcs    x26, x26, x10           // t[11] += hi(a[4] * a[6])
    mul     x13, x7, x9

    //----- hi(a[5] * a[6~7]) ------
    adc     x23, x23, x11           // t[12] += hi(a[4] * a[7])
    umulh   x10, x7, x8
    umulh   x11, x7, x9

    adds    x26, x26, x12           // t[11] += lo(a[5] * a[6])
    //----- lo(a[6] * a[7]) ------
    adcs    x23, x23, x13           // t[12] += lo(a[5] * a[7])
    mul     x12, x8, x9

    //----- hi(a[6] * a[7])  ------
    adc     x24, xzr, xzr           // t[13] = CF ( Set by t[12] += lo(a[5] * a[7]) ),
    umulh   x13, x8, x9
                                    // This operation is required when a new umulh is added.
    adds    x23, x23, x10           // t[12] += hi(a[5] * a[6])
    adc     x24, x24, x11           // t[13] += hi(a[5] * a[7])
    sub     x19, x3, x1             // x3 = &a[size], x1 = &a[8], x19 = (size - 8) * 8

    adds    x24, x24, x12           // t[13] += lo(a[6] * a[7])
    adc     x21, xzr, xzr           // t[14] = CF ( set by t[13] += lo(a[6] * a[7]) )
    add     x21, x21, x13           // t[14] += hi(a[6] * a[7]), There must be no carry in the last step.

    cbz     x19, .LSqr8xLoopMulEnd

    mov     x0, x1                  // x0 = &a[8]
    mov     x22, xzr

//########################################
//#          a[0~7] * a[8~15]            #
//########################################
.LSqr8xHighMulBegian:
    mov     x19, #-8*8                // Loop range. x0 can retrieve a[0–7] based on this offset.
    ldp     x14 , x15 , [x2, #8*0]    // x14  = t[8] , x15  = t[9]
    adds    x27, x27, x14             // t[8](t[8] reserved in the previous round of calculation) + = t[8]
                                      // (t[8] taken from memory, initially 0)
    adcs    x28, x28, x15             // t[9] += t[9], be the same as the above
    ldp     x16 , x17 , [x2, #8*2]    // x16 = t[10], x17 = t[11]
    ldp     x14 , x15 , [x1], #16   // x14 = a[8], x15 = a[9]
    adcs    x25, x25, x16
    adcs    x26, x26, x17

    ldp     x6, x7, [x2, #8*4]    // x6 = t[12], x7 = t[13]
    ldp     x16 , x17 , [x1], #16    // x16 = a[10], x17 = a[11]
    adcs    x23, x23, x6
    adcs    x24, x24, x7

    ldp     x8, x9, [x2, #8*6]    // x8 = t[14], x9 = t[15]
    ldp     x6, x7, [x1], #16    // x6 = a[12], x7 = a[13]
    adcs    x21, x21, x8
    adcs    x22, x22, x9           // t[15] = t[15] + CF, Because a[7]*a[7] is not calculated previously, t[15]=0
    ldp     x8, x9, [x1], #16    // x8 = a[14], x9 = a[15]

.LSqr8xHighMulProces:
    ldr     x4 , [x0, x19]          // x4 = [x0 + x19] = [x0 - 56] = [&a[8] - 56] = a[8 - 7] = a[1]
    //-----lo(a[0] * a[8~11])-----
    adc     x20, xzr, xzr           // x20 += CF, Save the carry of t[15]. The same operation is performed below.
    add     x19, x19, #8            // x19 += 8, Loop step size
    mul     x10, x4 , x14            // x4 = a[0], x14 = a[8], x10 = lo(a[0] * a[8])
    mul     x11, x4 , x15            // x11 = lo(a[0] * a[9])
    mul     x12, x4 , x16            // x12 = lo(a[0] * a[10])
    mul     x13, x4 , x17            // x13 = lo(a[0] * a[11])

    //-----lo(a[0] * a[12~15])-----
    adds    x27, x27, x10           // CF does not need to be added for the first calculation,
                                    // t[8] += lo(a[0] * a[8])
    adcs    x28, x28, x11           // t[9] += lo(a[0] * a[9])
    adcs    x25, x25, x12           // t[10] += lo(a[0] * a[10])
    adcs    x26, x26, x13           // t[11] += lo(a[0] * a[11])
    mul     x10, x4 , x6
    mul     x11, x4 , x7
    mul     x12, x4 , x8
    mul     x13, x4 , x9

    //-----hi(a[0] * a[8~11])-----
    adcs    x23, x23, x10           // t[12] += lo(a[0] * a[12])
    adcs    x24, x24, x11           // t[13] += lo(a[0] * a[13])
    adcs    x21, x21, x12           // t[14] += lo(a[0] * a[14])
    adcs    x22, x22, x13           // t[15] += lo(a[0] * a[15])
    umulh   x10, x4 , x14
    umulh   x11, x4 , x15
    umulh   x12, x4 , x16
    umulh   x13, x4 , x17

    adc     x20, x20, xzr           // x20 += CF, Save the carry of t[15]
    str     x27, [x2], #8           // [x2] = t[8], x2 += 8, x27~x22 = t[9~16],
                                    // Update the mapping relationship to facilitate cycling.
                                    // x27~x26 always correspond to t[m~m+7], and x19 is always the LSB of the window

    //-----hi(a[0] * a[12~15])-----
    adds    x27, x28, x10           // t[9] += hi(a[0] * a[8]), The last calculation was to calculate t[15],
                                    // so carry cannot be added to t[9], so adds is used
    adcs    x28, x25, x11           // t[10] += hi(a[0] * a[9])
    adcs    x25, x26, x12           // t[11] += hi(a[0] * a[10])
    adcs    x26, x23, x13           // t[12] += hi(a[0] * a[11])
    umulh   x10, x4 , x6
    umulh   x11, x4 , x7
    umulh   x12, x4 , x8
    umulh   x13, x4 , x9           // x13 = hi(a[0] * a[15])

    adcs    x23, x24, x10           // t[13] += hi(a[0] * a[12])
    adcs    x24, x21, x11           // t[14] += hi(a[0] * a[13])
    adcs    x21, x22, x12           // t[15] += hi(a[0] * a[14])
    adcs    x22, x20, x13           // t[16] = hi(a[0] * a[15]) + CF

    cbnz    x19, .LSqr8xHighMulProces        // When exiting the loop, x0 = &a[8], x2 = &t[16]

    sub     x16, x1, x3            // x3 = x1 + x5 * 8(Converted to bytes), When x1 = x3, the loop ends.
    cbnz    x16, .LSqr8xHighMulBegian      // x0 is the outer loop, x1 is the inner loop, and the inner loop ends.
                                   // In this case, x2 = &a[size], out-of-bounds position.

    mov     x1, x0                   // Outer Loop Increment, x1 = &a[16]
    ldp     x14 , x15 , [x1], #16    // x14  = a[8] , x15  = a[9]
    ldp     x16 , x17 , [x1], #16    // x16  = a[10], x17  = a[11]
    ldp     x6, x7, [x1], #16    // x6 = a[12], x7 = a[13]
    ldp     x8, x9, [x1], #16    // x8 = a[14], x9 = a[15]

    sub     x10, x3 , x1            // Check whether the outer loop ends, x3 = &a[size], x10 = (size - 16)*8
    cbz     x10, .LSqr8xLoopMul

    sub     x11, x2 , x10           // x2 = &t[24], x11 = &t[16]
    stp     x27, x28, [x2 , #8*0]   // t[24] = x27, t[25] = x28
    ldp     x27, x28, [x11, #8*0]   // x27 = t[16], x28 = t[17]

    stp     x25, x26, [x2 , #8*2]   // t[26] = x25, t[27] = x26
    ldp     x25, x26, [x11, #8*2]   // x25 = t[18], x26 = t[19]

    stp     x23, x24, [x2 , #8*4]   // t[28] = x23, t[29] = x24
    ldp     x23, x24, [x11, #8*4]   // x23 = t[20], x24 = t[21]

    stp     x21, x22, [x2 , #8*6]   // t[30] = x21, t[31] = x22
    ldp     x21, x22, [x11, #8*6]   // x21 = t[22], x22 = t[23]

    mov     x2 , x11                // x2 = &t[16]
    b       .LSqr8xLoopMul

.align  4
.LSqr8xLoopMulEnd:
    //===== Calculate the squared term =====
    //----- sp = &t[0] , x2 = &t[24]-----
    sub     x10, x3, x5             // x10 = a[0]
    stp     x27, x28, [x2, #8*0]    // t[24] = x27, t[25] = x28
    stp     x25, x26, [x2, #8*2]    // When this step is performed, the calculation results reserved for x27–x26
                                    // are not pushed to the stack.
    stp     x23, x24, [x2, #8*4]
    stp     x21, x22, [x2, #8*6]
    ldp     x11, x12, [sp, #8*1]    // x11 = t[1], x12 = t[2]
    ldp     x15, x17, [x10], #16    // x15 = a[0], x17 = a[1]
    ldp     x7, x9, [x10], #16      // x7 = a[2], x9 = a[3]
    mov     x1, x10
    ldp     x13, x10, [sp, #8*3]    // x13 = t[3], x10 = t[4]

    mul     x27, x15, x15           // x27 = lo(a[0] * a[0])
    umulh   x15, x15, x15           // x15 = hi(a[0] * a[0])
    mov     x2 , sp                 // x2 = sp = &t[0]
    mul     x16, x17, x17           // x16  = lo(a[1] * a[1])
    adds    x28, x15, x11, lsl#1    // x28 = x15 + (x11 * 2) = hi(a[0] * a[0]) + 2 * t[1]
    umulh   x17, x17, x17           // x17  = hi(a[1] * a[1])

    extr    x11, x12, x11, #63      // Lower 63 bits of x11 = x16 | most significant bit of x15
                                    // Cyclic right shift by 63 bits to obtain the lower bit,
                                    // which is equivalent to cyclic left shift by 1 bit to obtain the upper bit.
                                    // The purpose is to *2.
                                    // x11 = 2*t[2](Ignore the overflowed part) + carry of (2*t[1])
    mov     x19, x5                 // x19 = size*8

.LSqr8xDealSquare:
    adcs    x25, x16 , x11           // x25 = lo(a[1] * a[1]) + 2*t[2]
    extr    x12, x13, x12, #63       // x12 = 2*t[3](Ignore the overflowed part) + carry of (2*t[2])
    adcs    x26, x17 , x12           // x26 = hi(a[1] * a[1]) + 2*t[3]

    sub     x19, x19, #8*4          // x19 = (size - 8)*8
    stp     x27, x28, [x2], #16    // t[0~3]Re-push stack
    stp     x25, x26, [x2], #16

    mul     x6, x7, x7           // x6 = lo(a[2] * a[2])
    umulh   x7, x7, x7           // x7 = hi(a[2] * a[2])
    mul     x8, x9, x9           // x6 = lo(a[3] * a[3])
    umulh   x9, x9, x9           // x7 = hi(a[3] * a[3])
    ldp     x11, x12, [x2, #8]    // x11 = t[5], x12 = t[6]

    extr    x13, x10, x13, #63      // x13 = 2*t[4](Ignore the overflowed part) + carry of(2*t[3])
    extr    x10, x11, x10, #63      // x10 = 2*t[5](Ignore the overflowed part) + carry of(2*t[4])
    adcs    x23, x6, x13           // x23 = lo(a[2] * a[2]) + 2*t[4]
    adcs    x24, x7, x10           // x24 = hi(a[2] * a[2]) + 2*t[5]

    cbz     x19, .LSqr8xReduceStart

    ldp     x13, x10, [x2, #24]     // x13 = t[7], x10 = t[8]
    extr    x11, x12, x11, #63      // x11 = 2*t[6](Ignore the overflowed part) + carry of(2*t[5])
    extr    x12, x13, x12, #63      // x12 = 2*t[7](Ignore the overflowed part) + carry of(2*t[6])
    adcs    x21, x8, x11            // x21 = lo(a[3] * a[3]) + 2*t[6]
    adcs    x22, x9, x12            // x22 = hi(a[3] * a[3]) + 2*t[7]
    stp     x23, x24, [x2], #16     // t[4~7]re-push stack
    stp     x21, x22, [x2], #16
    ldp     x15, x17, [x1], #8*2    // x15  = a[4], x17  = a[5], x1 += 16 = &a[6]
    ldp     x11, x12, [x2, #8]      // x11 = t[9], x12 = t[10]

    mul     x14 , x15 , x15            // x14  = lo(a[4] * a[4])
    umulh   x15 , x15 , x15            // x15  = hi(a[4] * a[4])
    mul     x16 , x17 , x17            // x16  = lo(a[5] * a[5])
    umulh   x17 , x17 , x17            // x17  = hi(a[5] * a[5])

    extr    x13, x10, x13, #63      // x13 = 2*t[8](Ignore the overflowed part) + carry of(2*t[7])
    adcs    x27, x14 , x13           // x27 = lo(a[4] * a[4]) + 2*t[8]
    extr    x10, x11, x10, #63      // x10 = 2*t[9](Ignore the overflowed part) + carry of(2*t[8])
    adcs    x28, x15 , x10           // x28 = hi(a[4] * a[4]) + 2*t[9]

    extr    x11, x12, x11, #63      // x11 = 2*t[10](Ignore the overflowed part) + carry of(2*t[9])

    ldp     x13, x10, [x2, #8*3]    // Line 438 has obtained t[9] and t[10], x13 = &t[11], x10 = &t[12]
    ldp     x7, x9, [x1], #8*2    // x7 = a[6], x9 = a[7], x1 += 16 = &a[8]

    b       .LSqr8xDealSquare

.LSqr8xReduceStart:
    extr    x11, x12, x11, #63      // x11 = 2*t[2*size-2](Ignore the overflowed part) + carry of (2*t[2*size-3])
    adcs    x21, x8, x11            // x21 = lo(a[size-1] * a[size-1]) + 2*t[2*size-2]
    extr    x12, xzr, x12, #63      // x12 = 2*t[2*size-1](Ignore the overflowed part) + carry of (2*t[2*size-2])
    adc     x22, x9, x12            // x22 = hi(a[size-1] * a[size-1]) + 2*t[2*size-1]

    ldp     x1, x4, [x29, #104]     // Pop n and k0 out of the stack, x1 = &n[0], x4 = k0
    stp     x23, x24, [x2]          // t[2*size-4 ~ 2*size-1]re-push stack
    stp     x21, x22, [x2,#8*2]

    cmp     x5, #64      // if size == 8, we can goto Single step reduce
    b.ne    .LSqr8xReduceLoop

    ldp     x14 , x15 , [x1], #16    // x14~x9 = n[0~7]
    ldp     x16 , x17 , [x1], #16
    ldp     x6, x7, [x1], #16
    ldp     x8, x9, [x1], #16

    ldp     x27, x28, [sp]          // x14~x9 = t[0~7]
    ldp     x25, x26, [sp,#8*2]
    ldp     x23, x24, [sp,#8*4]
    ldp     x21, x22, [sp,#8*6]
    mov     x19, #8
    mov     x2 , sp

    // if size == 8, goto single reduce step
.LSqr8xSingleReduce:
    mul     x20, x4, x27
    sub     x19, x19, #1
    //----- lo(n[1~7] * lo(t[0]*k0)) -----
    mul     x11, x15 , x20
    mul     x12, x16 , x20
    mul     x13, x17 , x20
    mul     x10, x6, x20

    cmp     x27, #1
    adcs    x27, x28, x11
    adcs    x28, x25, x12
    adcs    x25, x26, x13
    adcs    x26, x23, x10
    mul     x11, x7, x20
    mul     x12, x8, x20
    mul     x13, x9, x20

    //----- hi(n[0~7] * lo(t[0]*k0)) -----
    adcs    x23, x24, x11
    adcs    x24, x21, x12
    adcs    x21, x22, x13
    adc     x22, xzr, xzr           // x22 += CF
    umulh   x10, x14 , x20
    umulh   x11, x15 , x20
    umulh   x12, x16 , x20
    umulh   x13, x17 , x20

    adds    x27, x27, x10
    adcs    x28, x28, x11
    adcs    x25, x25, x12
    adcs    x26, x26, x13
    umulh   x10, x6, x20
    umulh   x11, x7, x20
    umulh   x12, x8, x20
    umulh   x13, x9, x20

    adcs    x23, x23, x10
    adcs    x24, x24, x11
    adcs    x21, x21, x12
    adc     x22, x22, x13
    cbnz    x19, .LSqr8xSingleReduce   // Need cycle 8 times

    ldp     x10, x11, [x2, #64]    // x10 = t[8], x11 = t[9]
    ldp     x12, x13, [x2, #80]
    adds    x27, x27, x10
    adcs    x28, x28, x11
    ldp     x10, x11, [x2, #96]
    adcs    x25, x25, x12
    adcs    x26, x26, x13
    adcs    x23, x23, x10
    ldp     x12, x13, [x2, #112]

    adcs    x24, x24, x11
    adcs    x21, x21, x12
    adcs    x22, x22, x13
    adc     x20, xzr, xzr
    ldr     x0, [x29, #96]          // r Pop-Stack
 
    // t - mod
    subs    x14, x27, x14
    sbcs    x15, x28, x15
    sbcs    x16, x25, x16
    sbcs    x17, x26, x17
    sbcs    x6, x23, x6
    sbcs    x7, x24, x7
    sbcs    x8, x21, x8
    sbcs    x9, x22, x9
    sbcs    x20, x20, xzr           // determine whether there is a borrowing

    // according to CF choose our result
    csel    x14 , x27, x14 , lo
    csel    x15 , x28, x15 , lo
    csel    x16 , x25, x16 , lo
    csel    x17 , x26, x17 , lo
    stp     x14 , x15 , [x0, #8*0]
    csel    x6, x23, x6, lo
    csel    x7, x24, x7, lo
    stp     x16 , x17 , [x0, #8*2]
    csel    x8, x21, x8, lo
    csel    x9, x22, x9, lo
    stp     x6, x7, [x0, #8*4]
    stp     x8, x9, [x0, #8*6]
    b       .LMontSqr8xEnd

.LSqr8xReduceLoop:
    add     x3, x1, x5             // x3 = &n[size]
    mov     x30, xzr
    ldp     x14 , x15 , [x1], #16    // x14~x9 = n[0~7]
    ldp     x16 , x17 , [x1], #16
    ldp     x6, x7, [x1], #16
    ldp     x8, x9, [x1], #16

    ldp     x27, x28, [sp]          // x27 = t[0], x28 = t[1]
    ldp     x25, x26, [sp,#8*2]     // x25~x22 = t[2~7]
    ldp     x23, x24, [sp,#8*4]
    ldp     x21, x22, [sp,#8*6]
    mov     x19, #8
    mov     x2 , sp

.LSqr8xReduceProcess:
    mul     x20, x4, x27           // x20 = lo(k0 * t[0])
    sub     x19, x19, #1
    //----- lo(n[1~7] * lo(t[0]*k0)) -----
    mul     x11, x15, x20           // x11 = n[1] * lo(t[0]*k0)
    mul     x12, x16, x20           // x12 = n[2] * lo(t[0]*k0)
    mul     x13, x17, x20           // x13 = n[3] * lo(t[0]*k0)
    mul     x10, x6, x20            // x10 = n[4] * lo(t[0]*k0)

    str     x20, [x2], #8           // Push lo(t[0]*k0) on the stack., x2 += 8
    cmp     x27, #1                 // Check whether the low location is carried.

    adcs    x27, x28, x11           // x27 = t[1] + lo(n[1] * lo(t[0]*k0))
    adcs    x28, x25, x12           // x28 = t[2] + lo(n[2] * lo(t[0]*k0))
    adcs    x25, x26, x13           // x25 = t[3] + lo(n[3] * lo(t[0]*k0))
    adcs    x26, x23, x10           // x26 = t[4] + lo(n[4] * lo(t[0]*k0))
    mul     x11, x7, x20
    mul     x12, x8, x20
    mul     x13, x9, x20

    //----- hi(n[0~7] * lo(t[0]*k0)) -----
    adcs    x23, x24, x11           // x23 = t[5] + lo(n[5] * lo(t[0]*k0))
    adcs    x24, x21, x12           // x24 = t[6] + lo(n[6] * lo(t[0]*k0))
    adcs    x21, x22, x13           // x21 = t[7] + lo(n[7] * lo(t[0]*k0))
    adc     x22, xzr, xzr           // x22 += CF
    umulh   x10, x14 , x20
    umulh   x11, x15 , x20
    umulh   x12, x16 , x20
    umulh   x13, x17 , x20

    adds    x27, x27, x10           // x27 += hi(n[0] * lo(t[0]*k0))
    adcs    x28, x28, x11           // x28 += hi(n[1] * lo(t[0]*k0))
    adcs    x25, x25, x12           // x25 += hi(n[2] * lo(t[0]*k0))
    adcs    x26, x26, x13           // x26 += hi(n[3] * lo(t[0]*k0))
    umulh   x10, x6, x20
    umulh   x11, x7, x20
    umulh   x12, x8, x20
    umulh   x13, x9, x20

    adcs    x23, x23, x10           // x23 += hi(n[4] * lo(t[0]*k0))
    adcs    x24, x24, x11           // x24 += hi(n[5] * lo(t[0]*k0))
    adcs    x21, x21, x12           // x21 += hi(n[6] * lo(t[0]*k0))
    adc     x22, x22, x13           // x22 += hi(n[7] * lo(t[0]*k0))
    cbnz    x19, .LSqr8xReduceProcess   // Cycle 8 times, and at the end of the cycle, x2 += 8*8

    ldp     x10, x11, [x2, #8*0]    // x10 = t[8], x11 = t[9]
    ldp     x12, x13, [x2, #8*2]
    mov     x0, x2

    adds    x27, x27, x10
    adcs    x28, x28, x11
    ldp     x10, x11, [x2,#8*4]
    adcs    x25, x25, x12
    adcs    x26, x26, x13
    ldp     x12, x13, [x2,#8*6]
    adcs    x23, x23, x10
    adcs    x24, x24, x11
    adcs    x21, x21, x12
    adcs    x22, x22, x13

    ldr     x4 , [x2, #-8*8]        // x4 = t[0]
    ldp     x14 , x15 , [x1], #16    // x14~x9 = &n[8]~&n[15]
    ldp     x16 , x17 , [x1], #16
    ldp     x6, x7, [x1], #16
    ldp     x8, x9, [x1], #16
    mov     x19, #-8*8

.LSqr8xReduce:
    adc     x20, xzr, xzr           // x20 = CF
    add     x19, x19, #8

    mul     x10, x14 , x4
    mul     x11, x15 , x4
    mul     x12, x16 , x4
    mul     x13, x17 , x4

    adds    x27, x27, x10
    adcs    x28, x28, x11
    adcs    x25, x25, x12
    adcs    x26, x26, x13
    mul     x10, x6, x4
    mul     x11, x7, x4
    mul     x12, x8, x4
    mul     x13, x9, x4

    adcs    x23, x23, x10
    adcs    x24, x24, x11
    adcs    x21, x21, x12
    adcs    x22, x22, x13
    umulh   x10, x14 , x4
    umulh   x11, x15 , x4
    umulh   x12, x16 , x4
    umulh   x13, x17 , x4

    adc     x20, x20, xzr

    str     x27, [x2], #8           // x27 = t[8], x2 += 8

    adds    x27, x28, x10           // x27 = t[1] + lo(n[1] * lo(t[0]*k0))
    adcs    x28, x25, x11           // x28 = t[2] + lo(n[2] * lo(t[0]*k0))
    adcs    x25, x26, x12           // x25 = t[3] + lo(n[3] * lo(t[0]*k0))
    adcs    x26, x23, x13           // x26 = t[4] + lo(n[4] * lo(t[0]*k0))
    umulh   x10, x6, x4
    umulh   x11, x7, x4
    umulh   x12, x8, x4
    umulh   x13, x9, x4

    // x0 = &t[8]
    ldr     x4 , [x0, x19]

    adcs    x23, x24, x10
    adcs    x24, x21, x11
    adcs    x21, x22, x12
    adcs    x22, x20, x13

    cbnz    x19, .LSqr8xReduce

    ldp     x14 , x15 , [x2, #8*0]
    ldp     x16 , x17 , [x2, #8*2]
    sub     x19, x3, x1            // x19 = (size-16)*8

    ldp     x6, x7, [x2, #8*4]
    ldp     x8, x9, [x2, #8*6]
    cbz     x19, .LSqr8xReduceBreak

    ldr     x4 , [x0, #-8*8]

    adds    x27, x27, x14
    adcs    x28, x28, x15
    adcs    x25, x25, x16
    adcs    x26, x26, x17
    adcs    x23, x23, x6
    adcs    x24, x24, x7
    adcs    x21, x21, x8
    adcs    x22, x22, x9

    ldp     x14 , x15 , [x1], #16
    ldp     x16 , x17 , [x1], #16
    ldp     x6, x7, [x1], #16
    ldp     x8, x9, [x1], #16

    mov     x19, #-8*8
    b       .LSqr8xReduce

.align  4
.LSqr8xReduceBreak:
    sub     x12, x3, x5             // x12 = n, reassign to n
    ldr     x4 , [x29, #112]        // k0 pop-stack

    cmp     x30, #1                 // Check whether the low location is carried.

    adcs    x10, x27, x14
    adcs    x11, x28, x15
    stp     x10, x11, [x2] , #16

    ldp     x27 ,x28, [x0 , #8*0]
    ldp     x14 , x15, [x12], #16  // x12 = &n[0] (Line 638 assigns a value)

    adcs    x25, x25, x16
    adcs    x26, x26, x17
    adcs    x23, x23, x6
    adcs    x24, x24, x7
    adcs    x21, x21, x8
    adcs    x22, x22, x9
    adc     x30, xzr, xzr

    ldp     x16, x17, [x12], #16
    ldp     x6, x7, [x12], #16
    ldp     x8, x9, [x12], #16

    stp     x25, x26, [x2], #16
    ldp     x25, x26, [x0, #8*2]

    stp     x23, x24, [x2], #16
    ldp     x23, x24, [x0, #8*4]

    stp     x21, x22, [x2], #16
    ldp     x21, x22, [x0, #8*6]

    sub     x20, x2, x29                // Check whether the loop ends
    mov     x1, x12
    mov     x2, x0                      // sliding window
    mov     x19, #8
    cbnz    x20, .LSqr8xReduceProcess

    // Final step
    ldr     x0 , [x29, #96]         // r Pop-Stack
    add     x2 , x2 , #8*8
    subs    x10, x27, x14
    sbcs    x11, x28, x15
    sub     x19, x5 , #8*8
    mov     x3 , x0                 // backup x0

.LSqr8xSubMod:
    ldp     x14 , x15, [x1], #16
    sbcs    x12, x25, x16
    sbcs    x13, x26, x17
    ldp     x16 , x17 , [x1], #16
    stp     x10, x11, [x0], #16
    stp     x12, x13, [x0], #16

    sbcs    x10, x23, x6
    sbcs    x11, x24, x7
    ldp     x6, x7, [x1], #16

    sbcs    x12, x21, x8
    sbcs    x13, x22, x9
    ldp     x8, x9, [x1], #16
    stp     x10, x11, [x0], #16
    stp     x12, x13, [x0], #16

    ldp     x27, x28, [x2], #16
    ldp     x25, x26, [x2], #16
    ldp     x23, x24, [x2], #16
    ldp     x21, x22, [x2], #16

    sub     x19, x19, #8*8
    sbcs    x10, x27, x14
    sbcs    x11, x28, x15

    cbnz    x19, .LSqr8xSubMod

    mov     x2 , sp
    add     x1 , sp , x5

    sbcs    x12, x25, x16
    sbcs    x13, x26, x17
    stp     x12, x13, [x0, #8*2]
    stp     x10, x11, [x0, #8*0]
    sbcs    x10, x23, x6
    sbcs    x11, x24, x7
    stp     x10, x11, [x0, #8*4]
    sbcs    x12, x21, x8
    sbcs    x13, x22, x9
    stp     x12, x13, [x0, #8*6]
    sbcs    xzr, x30, xzr           // Determine whether there is a borrowing

.LSqr8xCopy:
    ldp     x14, x15, [x3, #8*0]
    ldp     x16, x17, [x3, #8*2]
    ldp     x6, x7, [x3, #8*4]
    ldp     x8, x9, [x3, #8*6]

    ldp     x27, x28, [x1], #16
    ldp     x25, x26, [x1], #16
    ldp     x23, x24, [x1], #16
    ldp     x21, x22, [x1], #16

    sub     x5, x5, #8*8

    csel    x10, x27, x14, lo        // Condition selection instruction, lo = less than,
                                      // equivalent to x14 = (conf==lo) ? x27 : x14
    csel    x11, x28, x15, lo
    csel    x12, x25, x16 , lo
    csel    x13, x26, x17, lo
    csel    x14, x23, x6, lo
    csel    x15, x24, x7, lo
    csel    x16, x21, x8, lo
    csel    x17, x22, x9, lo

    stp     x10, x11, [x3], #16
    stp     x12, x13, [x3], #16
    stp     x14, x15, [x3], #16
    stp     x16, x17, [x3], #16
    cbnz    x5, .LSqr8xCopy

.LMontSqr8xEnd:
    ldr     x30, [x29, #8]          // Pop-Stack
    ldp     x27, x28, [x29, #16]
    mov     sp ,  x29
    ldp     x25, x26, [x29, #32]
    mov     x0 ,  #1
    ldp     x23, x24, [x29, #48]
    ldp     x21, x22, [x29, #64]
    ldp     x19, x20, [x29, #80]    // x19 = [x29 + 80], x20 = [x29 + 80 + 8],
                                    // ldp reads two 8-byte memory blocks at a time.
    ldr     x29, [sp], #128         // x29 = [sp], sp = sp + 128,ldr reads only an 8-byte block of memory
AARCH64_AUTIASP
    ret
.size   MontSqr8, .-MontSqr8


.type   MontMul4, %function
MontMul4:
    stp     x29, x30, [sp, #-128]!
    mov     x29, sp
    stp     x27, x28, [sp, #16]
    stp     x25, x26, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x21, x22, [sp, #64]
    stp     x19, x20, [sp, #80]
    mov     x27, xzr
    mov     x28, xzr
    mov     x25, xzr
    mov     x26, xzr
    mov     x30, xzr

    lsl     x5 , x5 , #3
    sub     x22, sp , x5
    sub     sp , x22, #8*4          // The space of size + 4 is applied for
    mov     x22, sp

    sub     x6, x5, #32
    cbnz    x6, .LMul4xProcesStart

    ldp     x14 , x15 , [x1, #8*0]
    ldp     x16 , x17 , [x1, #8*2]    // x14~x17 = a[0~3]
    ldp     x10, x11, [x3]          // x10~x13 = n[0~3]
    ldp     x12, x13, [x3, #8*2]

    mov     x1 , xzr
    mov     x20, #4

    // if size == 4, goto single step
.LMul4xSingleStep:
    sub     x20, x20, #0x1
    ldr     x24, [x2], #8           // b[i]

    //----- lo(a[0~3] * b[0]) -----
    mul     x6, x14 , x24
    mul     x7, x15 , x24
    mul     x8, x16 , x24
    mul     x9, x17 , x24

    //----- hi(a[0~3] * b[0]) -----
    adds    x27, x27, x6
    umulh   x6, x14 , x24
    adcs    x28, x28, x7
    umulh   x7, x15 , x24
    adcs    x25, x25, x8
    umulh   x8, x16 , x24
    adcs    x26, x26, x9
    umulh   x9, x17 , x24

    mul     x21, x27, x4
    adc     x23, xzr, xzr
    //----- lo(n[0~3] * t[0]*k0) -----
    adds    x28, x28, x6
    adcs    x25, x25, x7
    mul     x7, x11, x21
    adcs    x26, x26, x8
    mul     x8, x12, x21
    adc     x23, x23, x9
    mul     x9, x13, x21
    cmp     x27, #1
    adcs    x27, x28, x7

    //----- hi(n[0~3] *t[0]*k0) -----
    umulh   x6, x10, x21
    umulh   x7, x11, x21
    adcs    x28, x25, x8
    umulh   x8, x12, x21
    adcs    x25, x26, x9
    umulh   x9, x13, x21
    adcs    x26, x23, x1
    adc     x1 , xzr, xzr

    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9
    adc     x1 , x1 , xzr

    cbnz    x20, .LMul4xSingleStep

    subs    x14 , x27, x10
    sbcs    x15 , x28, x11
    sbcs    x16 , x25, x12
    sbcs    x17 , x26, x13
    sbcs    xzr, x1 , xzr           // update CF, Determine whether to borrow

    csel    x14 , x27, x14 , lo
    csel    x15 , x28, x15 , lo
    csel    x16 , x25, x16 , lo
    csel    x17 , x26, x17 , lo
    stp     x14 , x15 , [x0, #8*0]
    stp     x16 , x17 , [x0, #8*2]
    b       .LMontMul4xEnd

.LMul4xProcesStart:
    add     x6, x5, #32
    eor     v0.16b,v0.16b,v0.16b
    eor     v1.16b,v1.16b,v1.16b
.LMul4xInitstack:
    sub     x6,  x6, #32
    st1     {v0.2d, v1.2d}, [x22], #32
    cbnz    x6, .LMul4xInitstack
    mov     x22, sp

    add     x6, x2 , x5            // x6 = &b[size]
    adds    x19, x1 , x5           // x19 = &a[size]
    stp     x0 , x6, [x29, #96]    // r and b[size] push stack
    mov     x0 , xzr
    mov     x20, #0

 .LMul4xLoopProces:
    ldr     x24, [x2]                // x24 = b[0]
    ldp     x14 , x15 , [x1], #16
    ldp     x16 , x17 , [x1], #16    // x14~x17 = a[0~3]

    ldp     x10 , x11 , [x3], #16
    ldp     x12 , x13 , [x3], #16    // x10~x13 = n[0~3]

.LMul4xPrepare:
    //----- lo(a[0~3] * b[0]) -----
    adc     x0 , x0 , xzr           // x0 += CF
    add     x20, x20, #8
    and     x20, x20, #31           // x20 &= 0xff. The lower eight bits are used.
                                    // When x28 = 32, the instruction becomes 0.
    mul     x6, x14 , x24
    mul     x7, x15 , x24
    mul     x8, x16 , x24
    mul     x9, x17 , x24

    //----- hi(a[0~3] * b[0]) -----
    adds    x27, x27, x6           // t[0] += lo(a[0] * b[0])
    adcs    x28, x28, x7           // t[1] += lo(a[1] * b[0])
    adcs    x25, x25, x8           // t[2] += lo(a[2] * b[0])
    adcs    x26, x26, x9           // t[3] += lo(a[3] * b[0])
    umulh   x6, x14 , x24           // x6 = hi(a[0] * b[0])
    umulh   x7, x15 , x24
    umulh   x8, x16 , x24
    umulh   x9, x17 , x24

    mul     x21, x27, x4            // x21 = t[0] * k0, t[0]*k0 needs to be recalculated in each round.
                                    // t[0] is different in each round.
    adc     x23, xzr, xzr           // t[4] += CF(set by t[3] += lo(a[3] * b[0]) )

    ldr     x24, [x2, x20]          // b[i]

    str     x21, [x22], #8          // t[0] * k0 push stack, x22 += 8

    //----- lo(n[0~3] * t[0]*k0) -----
    adds    x28, x28, x6           // t[1] += hi(a[0] * b[0])
    adcs    x25, x25, x7           // t[2] += hi(a[1] * b[0])
    adcs    x26, x26, x8           // t[3] += hi(a[2] * b[0])
    adc     x23, x23, x9           // t[4] += hi(a[3] * b[0])
    mul     x7, x11, x21           // x7 = lo(n[1] * t[0]*k0)
    mul     x8, x12, x21           // x8 = lo(n[2] * t[0]*k0)
    mul     x9, x13, x21           // x9 = lo(n[3] * t[0]*k0)
    cmp     x27, #1
    adcs    x27, x28, x7           // (t[0]) = x27 = t[1] + lo(n[1] * t[0]*k0),
                                   // Perform S/R operations, r=2^64, shift right 64 bits.

    //----- hi(n[0~3] *t[0]*k0) -----
    adcs    x28, x25, x8           // x28 = t[2] + lo(n[2] * t[0]*k0)
    adcs    x25, x26, x9           // x25 = t[3] + lo(n[3] * t[0]*k0)
    adcs    x26, x23, x0            // x26 = t[4] + 0 + CF
    adc     x0 , xzr, xzr           // x0 = CF
    umulh   x6, x10, x21           // x6 = hi(n[0] * t[0]*k0)
    umulh   x7, x11, x21           // x7 = hi(n[1] * t[0]*k0)
    umulh   x8, x12, x21           // x8 = hi(n[2] * t[0]*k0)
    umulh   x9, x13, x21           // x9 = hi(n[3] * t[0]*k0)

    adds    x27, x27, x6           // x27 = t[1] + hi(n[0] * t[0]*k0)
    adcs    x28, x28, x7           // x28 = t[2] + hi(n[1] * t[0]*k0)
    adcs    x25, x25, x8           // x25 = t[3] + hi(n[2] * t[0]*k0)
    adcs    x26, x26, x9           // x26 = t[4] + hi(n[3] * t[0]*k0)

    cbnz    x20, .LMul4xPrepare

    // Four t[0] * k0s are stacked in each loop.
    adc     x0 , x0 , xzr
    ldp     x6, x7, [x22, #8*4]   // load A (cal before)
    ldp     x8, x9, [x22, #8*6]

    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9
    ldr     x21, [sp]               // x21 = t[0] * k0

.LMul4xReduceBegin:
    ldp     x14 , x15 , [x1], #16
    ldp     x16 , x17 , [x1], #16    // x14~x17 = a[4~7]
    ldp     x10 , x11 , [x3], #16
    ldp     x12 , x13 , [x3], #16    // n[4~7]

.LMul4xReduceProces:
    adc     x0 , x0 , xzr
    add     x20, x20, #8
    and     x20, x20, #31
    //----- lo(a[4~7] * b[i]) -----
    mul     x6, x14 , x24
    mul     x7, x15 , x24
    mul     x8, x16 , x24
    mul     x9, x17 , x24

    //----- hi(a[4~7] * b[i]) -----
    adds    x27, x27, x6           // x27 += lo(a[4~7] * b[i])
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9
    adc     x23, xzr, xzr
    umulh   x6, x14 , x24
    umulh   x7, x15 , x24
    umulh   x8, x16 , x24
    umulh   x9, x17 , x24

    ldr     x24, [x2, x20]          // b[i]

    //----- lo(n[4~7] * t[0]*k0) -----
    adds    x28, x28, x6
    adcs    x25, x25, x7
    adcs    x26, x26, x8
    adc     x23, x23, x9
    mul     x6, x10, x21
    mul     x7, x11, x21
    mul     x8, x12, x21
    mul     x9, x13, x21

    //----- hi(n[4~7] * t[0]*k0) -----
    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9
    adcs    x23, x23, x0
    umulh   x6, x10, x21
    umulh   x7, x11, x21
    umulh   x8, x12, x21
    umulh   x9, x13, x21

    ldr     x21, [sp, x20]          // t[0]*k0

    adc     x0 , xzr, xzr           // x0 = CF, record carry
    str     x27, [x22], #8          // s[i] the calculation is complete, write the result, x22 += 8

    adds    x27, x28, x6
    adcs    x28, x25, x7
    adcs    x25, x26, x8
    adcs    x26, x23, x9

    cbnz    x20, .LMul4xReduceProces
    sub     x6, x19, x1            // x6 = &a[size] - &a[i]
                                   // (The value of x1 increases cyclically.) Check whether the loop ends
    adc     x0 , x0 , xzr
    cbz     x6, .LMul4xLoopExitCheck

    ldp     x6, x7, [x22, #8*4]   // t[4~7]
    ldp     x8, x9, [x22, #8*6]

    adds    x27, x27, x6
    adcs    x28, x28, x7
    adcs    x25, x25, x8
    adcs    x26, x26, x9

    b       .LMul4xReduceBegin

.LMul4xLoopExitCheck:
    ldr     x9, [x29, #104]         // b[size] Pop-Stack
    add     x2 , x2 , #8*4          // b subscript is offset once by 4 each time, &b[4], &b[8]......
    sub     x9 , x9, x2                // Indicates whether the outer loop ends.

    adds    x27, x27, x30
    adcs    x28, x28, xzr
    stp     x27, x28, [x22, #8*0]   // x27, x20 After the calculation is complete, Push-stack storage
    ldp     x27, x28, [sp , #8*4]   // t[0], t[1]

    adcs    x25, x25, xzr
    adcs    x26, x26, xzr
    stp     x25, x26, [x22, #8*2]   // x25, x22 After the calculation is complete, Push-stack storage
    ldp     x25, x26, [sp , #8*6]   // t[2], t[3]
    adc     x30, x0 , xzr
    sub     x3 , x3 , x5            // x1 = &n[0]
    cbz     x9, .LMul4xEnd

    sub     x1 , x1 , x5            // x1 = &a[0]

    mov     x22, sp
    mov     x0 , xzr
    b       .LMul4xLoopProces

.LMul4xEnd:
    ldp     x10, x11, [x3], #16
    ldp     x12, x13, [x3], #16
    ldr     x0, [x29, #96]         // r[0] Pop-Stack
    mov     x19, x0                // backup, x19 = &r[0]
    subs    x6, x27, x10           // t[0] - n[0], modify CF
    sbcs    x7, x28, x11           // t[1] - n[1] - CF
    add     x22, sp , #8*8         // x22 = &S[8]
    sub     x20, x5 , #8*4         // x20 = (size - 4)*8

    // t - n, x22 = &t[8], x3 = &n[0]
.LMul4xSubMod:
    sbcs    x8, x25, x12
    sbcs    x9, x26, x13

    ldp     x10, x11, [x3], #16
    ldp     x12, x13, [x3], #16
    ldp     x27, x28, [x22], #16
    ldp     x25, x26, [x22], #16

    sub     x20, x20, #8*4

    stp     x6, x7, [x0], 16
    stp     x8, x9, [x0], 16

    sbcs    x6, x27, x10
    sbcs    x7, x28, x11

    cbnz    x20, .LMul4xSubMod

    sbcs    x8, x25, x12
    sbcs    x9, x26, x13
    sbcs    xzr, x30, xzr           // CF = x30 - CF, x30 recorded the previous carry

    add     x1 , sp , #8*4          // The size of the SP space is size + 4., x1 = sp + 4
    stp     x6, x7, [x0]
    stp     x8, x9, [x0, #8*2]

.LMul4xCopy:
    ldp     x14 , x15 , [x19]         // x14~x17 = r[0~3]
    ldp     x16 , x17 , [x19, #8*2]
    ldp     x27, x28, [x1], #16       // x27~22 = S[4~7]
    ldp     x25, x26, [x1], #16
    sub     x5, x5, #8*4
    csel    x6, x27, x14, lo        // x6 = (CF == 1) ? x27 : x14
    csel    x7, x28, x15, lo
    csel    x8, x25, x16, lo
    csel    x9, x26, x17, lo
    stp     x6, x7, [x19], #16
    stp     x8, x9, [x19], #16

    cbnz    x5, .LMul4xCopy

.LMontMul4xEnd:
    ldr     x30, [x29, #8]          // Value Pop-Stack in x30 (address of next instruction)
    ldp     x27, x28, [x29, #16]
    ldp     x25, x26, [x29, #32]
    ldp     x23, x24, [x29, #48]
    ldp     x21, x22, [x29, #64]
    ldp     x19, x20, [x29, #80]
    mov     sp , x29
    ldr     x29, [sp], #128
AARCH64_AUTIASP
    ret
.size   MontMul4, .-MontMul4

#endif
