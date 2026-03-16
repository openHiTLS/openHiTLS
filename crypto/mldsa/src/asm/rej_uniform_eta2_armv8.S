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
#ifdef HITLS_CRYPTO_MLDSA

#include "crypt_arm.h"
#define MLDSA_N 256
#define MLD_STACK_SIZE (2*MLDSA_N + 64)

.macro push_stack
    sub sp, sp, #MLD_STACK_SIZE
.endm

.macro pop_stack
    add sp, sp, #MLD_STACK_SIZE
.endm

    /* Parameters */
    output                      .req x0
    buf                         .req x1
    buflen                      .req x2
    table_idx                   .req x3

    len                         .req x4

    /* Temporary output on the stack */
    xtmp                        .req x7
    wtmp                        .req w7
    output_tmp                  .req x7
    output_tmp_base             .req x8

    /* Number of coefficients sampled so far */
    count                       .req x9
    buf_consumed                .req x10

    /* Temporary registers */
    tmp                         .req w11
    initial_zero_count          .req x11
    final_copy_count            .req x11

    rec_idx_0                   .req x12
    rec_idx_1                   .req x13

    rec_idx_0_w                 .req w12
    rec_idx_1_w                 .req w13

    ctr0                        .req x12
    ctr1                        .req x13

    ctr0_w                      .req w12
    ctr1_w                      .req w13

    ctr01                       .req ctr0

    /* Vector registers */
    buf0                        .req v0

    tmp0                        .req v26
    tmp1                        .req v27
    tmp2                        .req v28
    tmp3                        .req v29

    sign0                       .req v4
    sign1                       .req v5
    const2                      .req v7

    // Barrett reduction constants
    barrett_const               .req v26
    modulus5                    .req v27
    barrett_tmp                 .req v28

    val0                        .req v16
    val1                        .req v17
    val2                        .req v18
    val3                        .req v19
    val0q                       .req q16
    val1q                       .req q17
    val2q                       .req q18
    val3q                       .req q19

    t0                          .req s20
    t1                          .req s21

    table0                      .req v24
    table1                      .req v25
    table0q                     .req q24
    table1q                     .req q25

    eta_bound                   .req v30
    bits                        .req v31


CRYPT_AARCH64_FUNC_START(MldRejUniformEta2Asm)
MldRejUniformEta2Asm:
    AARCH64_PACIASP
    push_stack

    // Load 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80
    movz xtmp, 0x1
    movk xtmp, 0x2, lsl 16
    movk xtmp, 0x4, lsl 32
    movk xtmp, 0x8, lsl 48
    mov bits.d[0], xtmp

    movz xtmp, 0x10
    movk xtmp, 0x20, lsl 16
    movk xtmp, 0x40, lsl 32
    movk xtmp, 0x80, lsl 48
    mov bits.d[1], xtmp

    // Load eta2 bound = 15
    movi eta_bound.8h, #15

    mov output_tmp_base, sp
    mov output_tmp, output_tmp_base

    mov initial_zero_count, #0
    eor val0.16b, val0.16b, val0.16b

.rej_uniform_eta2_initial_zero:
    str val0q, [output_tmp], #64
    str val0q, [output_tmp, #-48]
    str val0q, [output_tmp, #-32]
    str val0q, [output_tmp, #-16]
    add initial_zero_count, initial_zero_count, #32
    cmp initial_zero_count, #MLDSA_N
    b.lt .rej_uniform_eta2_initial_zero

    mov output_tmp, output_tmp_base

    mov count, #0
    mov len, #MLDSA_N

.rej_uniform_eta2_loop8:
        // Finish once we've generated sufficiently many coefficients
        cmp     count, len
        b.hs    .rej_uniform_eta2_memory_copy

        // Load 8 bytes and extract nibbles to get 16 4-bit values
        sub     buflen, buflen, #8
        ld1     {buf0.8b}, [buf], #8

        // Extract nibbles
        movi    tmp0.8b, #0x0F
        and     tmp1.8b, buf0.8b, tmp0.8b     // Low nibbles [L0, L1, L2, L3, L4, L5, L6, L7]
        ushr    tmp2.8b, buf0.8b, #4          // High nibbles [H0, H1, H2, H3, H4, H5, H6, H7]

        // Interleave low and high nibbles: L0,H0,L1,H1,L2,H2,L3,H3,...
        zip1    tmp0.8b, tmp1.8b, tmp2.8b     // First 8 nibbles interleaved [L0,H0,L1,H1,L2,H2,L3,H3]
        zip2    tmp3.8b, tmp1.8b, tmp2.8b     // Next 8 nibbles interleaved [L4,H4,L5,H5,L6,H6,L7,H7]

        // Convert to 16-bit values
        uxtl    val0.8h, tmp0.8b
        uxtl    val1.8h, tmp3.8b

        // Given 16 x int16, we do: 
        // 1. Check which coefficients are within range (< 9) 
        //      and create 8-bit bitmap of valid lane indices
        // 2. Use bitmap to index into lookup table for lane 
        //      reordering via tbl instruction
        // 3. Write valid coefficients to output buffer, 
        //      advancing pointer by count of valid coefficients

        // Check which coefficients are within range (< 15)
        cmhi sign0.8h, eta_bound.8h, val0.8h
        cmhi sign1.8h, eta_bound.8h, val1.8h

        // If lane i is valid and has value -1, retain only i-th bit
        and sign0.16b, sign0.16b, bits.16b
        and sign1.16b, sign1.16b, bits.16b

        // Get 8-bit bitmap of valid lane indices by adding lanes
        uaddlv t0, sign0.8h
        uaddlv t1, sign1.8h

        fmov rec_idx_0_w, t0
        fmov rec_idx_1_w, t1

        ldr table0q, [table_idx, rec_idx_0, lsl #4]
        ldr table1q, [table_idx, rec_idx_1, lsl #4]

        // Compute number of valid coefficients
        cnt sign0.16b, sign0.16b
        cnt sign1.16b, sign1.16b

        // Extract number of valid coefficients
        uaddlv  t0, sign0.8h
        uaddlv  t1, sign1.8h

        fmov ctr0_w, t0
        fmov ctr1_w, t1

        // Move valid coefficients to the front
        tbl val0.16b, {val0.16b}, table0.16b
        tbl val1.16b, {val1.16b}, table1.16b


        // Store 16-bit coefficients, expanded to 32-bit on copy out
        str val0q, [output_tmp]
        add output_tmp, output_tmp, ctr0, lsl #1

        str val1q, [output_tmp]
        add output_tmp, output_tmp, ctr1, lsl #1

        add ctr01, ctr0, ctr1
        add count, count, ctr01

        cmp buflen, #8
        b.hs .rej_uniform_eta2_loop8

.rej_uniform_eta2_memory_copy:
    // min = min(count,len)
    cmp  count, len
    csel count, count, len, lo

    // Initialize constant vectors for Barrett reduction
    movz    wtmp, #6554               // round((2**15)/5)
    dup     barrett_const.8h, wtmp
    movi    modulus5.8h, #5
    movi    const2.8h, #2

    // Always copy MLDSA_N coefficients from the stack to the destination
    mov final_copy_count, #0
    mov output_tmp, output_tmp_base

.rej_uniform_eta2_final_copy:
        ldr val0q, [output_tmp], #32
        ldr val2q, [output_tmp, #-16]

        // Reference:
        // Barrett reduction: t0 = t0 - (205 * t0 >> 10) * 5;
        // To make efficient use of sqdmulh, we use the equivalent
        // t0 = t0 - (13108 * t0 >> 16) * 5;

        sqdmulh barrett_tmp.8h, val0.8h, barrett_const.8h
        mls     val0.8h, barrett_tmp.8h, modulus5.8h

        sqdmulh barrett_tmp.8h, val2.8h, barrett_const.8h
        mls     val2.8h, barrett_tmp.8h, modulus5.8h

        sub     val0.8h, const2.8h, val0.8h
        sub     val2.8h, const2.8h, val2.8h

        // Expand from 16-bit to 32-bit
        sxtl2 val1.4s, val0.8h
        sxtl  val0.4s, val0.4h

        sxtl2 val3.4s, val2.8h
        sxtl  val2.4s, val2.4h

        str val0q, [output], #64
        str val1q, [output, #-48]
        str val2q, [output, #-32]
        str val3q, [output, #-16]
        add final_copy_count, final_copy_count, #16
        cmp final_copy_count, #MLDSA_N
        b.lt .rej_uniform_eta2_final_copy

    mov x0, count
    pop_stack
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MldRejUniformEta2Asm)

    .unreq output
    .unreq buf
    .unreq buflen
    .unreq table_idx
    .unreq len
    .unreq output_tmp
    .unreq output_tmp_base
    .unreq count
    .unreq buf_consumed
    .unreq tmp
    .unreq xtmp
    .unreq final_copy_count
    .unreq initial_zero_count
    .unreq rec_idx_0
    .unreq rec_idx_1
    .unreq rec_idx_0_w
    .unreq rec_idx_1_w
    .unreq ctr0
    .unreq ctr1
    .unreq ctr0_w
    .unreq ctr1_w
    .unreq ctr01
    .unreq buf0
    .unreq tmp0
    .unreq tmp1
    .unreq tmp2
    .unreq tmp3
    .unreq sign0
    .unreq sign1
    .unreq val0
    .unreq val0q
    .unreq val1
    .unreq val1q
    .unreq val2
    .unreq val2q
    .unreq val3
    .unreq val3q
    .unreq t0
    .unreq t1
    .unreq table0
    .unreq table0q
    .unreq table1
    .unreq table1q
    .unreq eta_bound
    .unreq bits
    .unreq const2
    .unreq barrett_const
    .unreq modulus5
    .unreq barrett_tmp
    .unreq wtmp

#undef MLD_STACK_SIZE
#endif // HITLS_CRYPTO_MLDSA
