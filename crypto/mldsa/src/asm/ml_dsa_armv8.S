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
#ifdef HITLS_CRYPTO_MLDSA_ARMV8

#include "crypt_arm.h"

CRYPT_AARCH64_EXTERN(POLYZ_UNPACK_17_INDICES)
CRYPT_AARCH64_EXTERN(POLYZ_UNPACK_19_INDICES)

/* decompose_armv8.S */

.macro load_data
    ldr q_r0_data0, [arr_r0]
    ldr q_r0_data1, [arr_r0, #1*16]
    ldr q_r0_data2, [arr_r0, #2*16]
    ldr q_r0_data3, [arr_r0, #3*16]
.endm

.macro save_data
    str q_r0_data1, [arr_r0, #1*16]
    str q_r0_data2, [arr_r0, #2*16]
    str q_r0_data3, [arr_r0, #3*16]
    str q_r0_data0, [arr_r0], #4*16

    str q_r1_data1, [arr_r1, #1*16]
    str q_r1_data2, [arr_r1, #2*16]
    str q_r1_data3, [arr_r1, #3*16]
    str q_r1_data0, [arr_r1], #4*16
.endm

.macro finit arr
    // w[i][j] = w[i][j] + (MLDSA_Q & (w[i][j] >> 31))
    eor tmp1.16b, tmp1.16b, tmp1.16b        // tmp1 == 0
    cmlt tmp.4s, \arr\().4s, #0
    bsl tmp.16b, const_q.16b, tmp1.16b
    add \arr\().4s, \arr\().4s, tmp.4s
.endm

.macro finit_all
    finit r0_data0
    finit r0_data1
    finit r0_data2
    finit r0_data3
.endm

.macro decompose a1, a, roundbit
    // a1 = round-(a / 2*gamma2)  round(a * barrett / 2^48 or 2^49),
    // for decompose 33: roundbit = 18, 2*gamma2 = 523776 -> barrett = 1074791425
    // for decompose 88: roundbit = 17, 2*gamma2 = 190464 -> barrett = 1477838209
    sqdmulh \a1\().4s, \a\().4s, const_barrett.4s
    srshr \a1\().4s, \a1\().4s, \roundbit

    // Check for wrap-around
    cmgt tmp.4s, \a\().4s, const_q_bound.4s

    // Compute remainder a0
    mls \a\().4s, \a1\().4s, const_2x_gamma2.4s

    // If wrap-around is required, set a1 = 0 and a0 -= 1
    bic \a1\().16b, \a1\().16b, tmp.16b
    add \a\().4s, \a\().4s, tmp.4s
.endm

    arr_r0      .req x0
    arr_r1      .req x1
    count       .req x4
    wtmp        .req w5

    r0_data0        .req v0
    r0_data1        .req v1
    r0_data2        .req v2
    r0_data3        .req v3
    r1_data0        .req v4
    r1_data1        .req v5
    r1_data2        .req v6
    r1_data3        .req v7
    q_r0_data0      .req q0
    q_r0_data1      .req q1
    q_r0_data2      .req q2
    q_r0_data3      .req q3
    q_r1_data0      .req q4
    q_r1_data1      .req q5
    q_r1_data2      .req q6
    q_r1_data3      .req q7

    const_q             .req v31
    const_2x_gamma2     .req v30
    const_q_bound       .req v29
    const_barrett       .req v28

    tmp             .req v27
    tmp1            .req v26

CRYPT_AARCH64_FUNC_START(BatchDecompose32)
BatchDecompose32:
    AARCH64_PACIASP
    sub sp, sp, #(16*4)
    stp d8, d9, [sp, #16*0]
    stp d10, d11, [sp, #16*1]
    stp d12, d13, [sp, #16*2]
    stp d14, d15, [sp, #16*3]
    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    // 2*GAMMA2 = 523776
    movz wtmp, #0xfe00
    movk wtmp, #7, lsl #16
    dup const_2x_gamma2.4s, wtmp

    // 31*GAMMA2 = 8118528
    movz wtmp, #0xe100
    movk wtmp, #0x7b, lsl #16
    dup const_q_bound.4s, wtmp

    // Barrett constant = 1074791425
    movz wtmp, #0x0401
    movk wtmp, #0x4010, lsl #16
    dup const_barrett.4s, wtmp

    mov count, #(256 / 4 / 4)

    VLDQ_4S 9, x0
    VLDQ_4S 22, x0, #16
    VLDQ_4S 25, x0, #32
    VLDQ_4S 16, x0, #48
    cmlt v7.4s, v9.4s, #0
    cmlt v15.4s, v22.4s, #0
    cmlt v6.4s, v25.4s, #0
    cmlt v2.4s, v16.4s, #0
    and v7.16b, v31.16b, v7.16b
    and v15.16b, v31.16b, v15.16b
    and v6.16b, v31.16b, v6.16b
    add v10.4s, v9.4s, v7.4s
    add v9.4s, v22.4s, v15.4s
    add v22.4s, v25.4s, v6.4s
    and v25.16b, v31.16b, v2.16b
    cmgt v14.4s, v10.4s, v29.4s
    sqdmulh v5.4s, v10.4s, v28.4s
    sub x4, x4, #1
    .Ldecompose_loop_32:
    VLDQ_4S 7, x0, #64
    cmgt v4.4s, v22.4s, v29.4s
    sqdmulh v11.4s, v22.4s, v28.4s
    VLDQ_4S 15, x0, #80
    VLDQ_4S 6, x0, #96
    add v25.4s, v16.4s, v25.4s
    VLDQ_4S 16, x0, #112
    sqdmulh v12.4s, v9.4s, v28.4s
    cmgt v20.4s, v9.4s, v29.4s
    srshr v8.4s, v5.4s, #18
    cmlt v2.4s, v7.4s, #0
    sqdmulh v19.4s, v25.4s, v28.4s
    srshr v24.4s, v11.4s, #18
    cmgt v5.4s, v25.4s, v29.4s
    mls v10.4s, v8.4s, v30.4s
    srshr v11.4s, v12.4s, #18
    mls v22.4s, v24.4s, v30.4s
    and v2.16b, v31.16b, v2.16b
    srshr v27.4s, v19.4s, #18
    cmlt v18.4s, v6.4s, #0
    mls v9.4s, v11.4s, v30.4s
    add v1.4s, v10.4s, v14.4s
    add v10.4s, v7.4s, v2.4s
    mls v25.4s, v27.4s, v30.4s
    add v19.4s, v22.4s, v4.4s
    bic v2.16b, v24.16b, v4.16b
    VSTQ_4S_POST 1, x0, #64
    cmlt v12.4s, v15.4s, #0
    add v1.4s, v9.4s, v20.4s
    cmlt v0.4s, v16.4s, #0
    VSTQ_4S 19, x0, #-32
    bic v7.16b, v11.16b, v20.16b
    and v18.16b, v31.16b, v18.16b
    add v19.4s, v25.4s, v5.4s
    VSTQ_4S 2, x1, #32
    bic v8.16b, v8.16b, v14.16b
    VSTQ_4S 1, x0, #-48
    bic v9.16b, v27.16b, v5.16b
    and v2.16b, v31.16b, v12.16b
    cmgt v14.4s, v10.4s, v29.4s
    add v22.4s, v6.4s, v18.4s
    VSTQ_4S 7, x1, #16
    VSTQ_4S 19, x0, #-16
    sqdmulh v5.4s, v10.4s, v28.4s
    and v25.16b, v31.16b, v0.16b
    VSTQ_4S_POST 8, x1, #64
    VSTQ_4S 9, x1, #-16
    add v9.4s, v15.4s, v2.4s
    subs x4, x4, 1
    cbnz x4, .Ldecompose_loop_32
    add v25.4s, v16.4s, v25.4s
    sqdmulh v7.4s, v22.4s, v28.4s
    srshr v15.4s, v5.4s, #18
    sqdmulh v6.4s, v9.4s, v28.4s
    cmgt v16.4s, v22.4s, v29.4s
    cmgt v2.4s, v9.4s, v29.4s
    cmgt v29.4s, v25.4s, v29.4s
    sqdmulh v28.4s, v25.4s, v28.4s
    srshr v7.4s, v7.4s, #18
    mls v10.4s, v15.4s, v30.4s
    bic v15.16b, v15.16b, v14.16b
    srshr v6.4s, v6.4s, #18
    mls v22.4s, v7.4s, v30.4s
    bic v7.16b, v7.16b, v16.16b
    srshr v28.4s, v28.4s, #18
    VSTQ_4S_POST 15, x1, #64
    mls v9.4s, v6.4s, v30.4s
    bic v15.16b, v6.16b, v2.16b
    add v6.4s, v10.4s, v14.4s
    VSTQ_4S 7, x1, #-32
    mls v25.4s, v28.4s, v30.4s
    bic v30.16b, v28.16b, v29.16b
    add v22.4s, v22.4s, v16.4s
    VSTQ_4S 15, x1, #-48
    VSTQ_4S_POST 6, x0, #64
    add v9.4s, v9.4s, v2.4s
    VSTQ_4S 30, x1, #-16
    VSTQ_4S 22, x0, #-32
    add v29.4s, v25.4s, v29.4s
    VSTQ_4S 9, x0, #-48
    VSTQ_4S 29, x0, #-16
    ldp d8, d9, [sp, #16*0]
    ldp d10, d11, [sp, #16*1]
    ldp d12, d13, [sp, #16*2]
    ldp d14, d15, [sp, #16*3]
    add sp, sp, #(16*4)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(BatchDecompose32)

CRYPT_AARCH64_FUNC_START(BatchDecompose88)
BatchDecompose88:
AARCH64_PACIASP
    sub sp, sp, #(16*4)
    stp d8, d9, [sp, #16*0]
    stp d10, d11, [sp, #16*1]
    stp d12, d13, [sp, #16*2]
    stp d14, d15, [sp, #16*3]
    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    // 2*GAMMA2 = 190464
    movz wtmp, #0xe800
    movk wtmp, #0x2, lsl #16
    dup const_2x_gamma2.4s, wtmp

    // 31*GAMMA2 = 8285184
    movz wtmp, #0x6c00
    movk wtmp, #0x7e, lsl #16
    dup const_q_bound.4s, wtmp

    // Barrett constant = 1477838209
    movz wtmp, #0x0581
    movk wtmp, #0x5816, lsl #16
    dup const_barrett.4s, wtmp

    mov count, #(256 / 4 / 4)

    VLDQ_4S 5, x0, #16
    VLDQ_4S 13, x0, #48
    VLDQ_4S 27, x0, #32
    VLDQ_4S 18, x0
    cmlt v14.4s, v5.4s, #0
    cmlt v1.4s, v13.4s, #0
    cmlt v19.4s, v27.4s, #0
    cmlt v15.4s, v18.4s, #0
    and v14.16b, v31.16b, v14.16b
    and v1.16b, v31.16b, v1.16b
    and v19.16b, v31.16b, v19.16b
    and v15.16b, v31.16b, v15.16b
    add v5.4s, v5.4s, v14.4s
    add v14.4s, v13.4s, v1.4s
    add v13.4s, v27.4s, v19.4s
    add v9.4s, v18.4s, v15.4s
    sqdmulh v27.4s, v5.4s, v28.4s
    cmgt v4.4s, v14.4s, v29.4s
    cmgt v22.4s, v9.4s, v29.4s
    sqdmulh v18.4s, v13.4s, v28.4s
    sqdmulh v17.4s, v9.4s, v28.4s
    srshr v24.4s, v27.4s, #17
    sqdmulh v15.4s, v14.4s, v28.4s
    srshr v25.4s, v18.4s, #17
    sub x4, x4, #1
    .Ldecompose_loop_88:
    VLDQ_4S 18, x0, #80
    cmgt v20.4s, v5.4s, v29.4s
    mls v5.4s, v24.4s, v30.4s
    srshr v0.4s, v17.4s, #17
    VLDQ_4S 19, x0, #112
    VLDQ_4S 1, x0, #96
    cmgt v12.4s, v13.4s, v29.4s
    mls v13.4s, v25.4s, v30.4s
    srshr v17.4s, v15.4s, #17
    VLDQ_4S 27, x0, #64
    mls v9.4s, v0.4s, v30.4s
    cmlt v15.4s, v18.4s, #0
    cmlt v23.4s, v19.4s, #0
    mls v14.4s, v17.4s, v30.4s
    cmlt v16.4s, v1.4s, #0
    and v21.16b, v31.16b, v15.16b
    and v23.16b, v31.16b, v23.16b
    cmlt v15.4s, v27.4s, #0
    and v16.16b, v31.16b, v16.16b
    add v11.4s, v9.4s, v22.4s
    add v3.4s, v5.4s, v20.4s
    add v5.4s, v18.4s, v21.4s
    add v14.4s, v14.4s, v4.4s
    and v9.16b, v31.16b, v15.16b
    VSTQ_4S_POST 11, x0, #64
    add v18.4s, v13.4s, v12.4s
    add v13.4s, v1.4s, v16.4s
    bic v1.16b, v25.16b, v12.16b
    sqdmulh v15.4s, v5.4s, v28.4s
    VSTQ_4S 3, x0, #-48
    add v9.4s, v27.4s, v9.4s
    VSTQ_4S 14, x0, #-16
    bic v21.16b, v24.16b, v20.16b
    VSTQ_4S 18, x0, #-32
    sqdmulh v18.4s, v13.4s, v28.4s
    add v14.4s, v19.4s, v23.4s
    bic v27.16b, v17.16b, v4.16b
    sqdmulh v17.4s, v9.4s, v28.4s
    bic v19.16b, v0.16b, v22.16b
    VSTQ_4S 21, x1, #16
    srshr v24.4s, v15.4s, #17
    sqdmulh v15.4s, v14.4s, v28.4s
    srshr v25.4s, v18.4s, #17
    VSTQ_4S 27, x1, #48
    VSTQ_4S 1, x1, #32
    cmgt v22.4s, v9.4s, v29.4s
    cmgt v4.4s, v14.4s, v29.4s
    VSTQ_4S_POST 19, x1, #64
    subs x4, x4, 1
    cbnz x4, .Ldecompose_loop_88
    cmgt v27.4s, v13.4s, v29.4s
    mls v13.4s, v25.4s, v30.4s
    srshr v17.4s, v17.4s, #17
    cmgt v26.4s, v5.4s, v29.4s
    mls v5.4s, v24.4s, v30.4s
    srshr v18.4s, v15.4s, #17
    bic v0.16b, v17.16b, v22.16b
    mls v9.4s, v17.4s, v30.4s
    bic v29.16b, v25.16b, v27.16b
    bic v28.16b, v24.16b, v26.16b
    mls v14.4s, v18.4s, v30.4s
    VSTQ_4S_POST 0, x1, #64
    add v30.4s, v13.4s, v27.4s
    VSTQ_4S 29, x1, #-32
    bic v29.16b, v18.16b, v4.16b
    VSTQ_4S 28, x1, #-48
    add v5.4s, v5.4s, v26.4s
    add v18.4s, v9.4s, v22.4s
    VSTQ_4S 30, x0, #32
    VSTQ_4S 29, x1, #-16
    add v28.4s, v14.4s, v4.4s
    VSTQ_4S 5, x0, #16
    VSTQ_4S_POST 18, x0, #64
    VSTQ_4S 28, x0, #-16
    ldp d8, d9, [sp, #16*0]
    ldp d10, d11, [sp, #16*1]
    ldp d12, d13, [sp, #16*2]
    ldp d14, d15, [sp, #16*3]
    add sp, sp, #(16*4)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(BatchDecompose88)

CRYPT_AARCH64_FUNC_START(MLDSA_Batch_Decompose)
MLDSA_Batch_Decompose:
    ldr x3, [x0]
    ldrb w3, [x3, #4]
    mov x0, x1
    mov x1, x2
    cmp w3, #4
    b.eq BatchDecompose88
    b BatchDecompose32
    CRYPT_AARCH64_FUNC_END(MLDSA_Batch_Decompose)

    .unreq arr_r0
    .unreq arr_r1
    .unreq count
    .unreq wtmp

    .unreq r0_data0
    .unreq r0_data1
    .unreq r0_data2
    .unreq r0_data3
    .unreq r1_data0
    .unreq r1_data1
    .unreq r1_data2
    .unreq r1_data3
    .unreq q_r0_data0
    .unreq q_r0_data1
    .unreq q_r0_data2
    .unreq q_r0_data3
    .unreq q_r1_data0
    .unreq q_r1_data1
    .unreq q_r1_data2
    .unreq q_r1_data3
    .unreq const_q
    .unreq const_2x_gamma2
    .unreq const_q_bound
    .unreq const_barrett
    .unreq tmp
    .unreq tmp1

.purgem load_data
.purgem save_data
.purgem finit
.purgem finit_all
.purgem decompose

/* polyz_unpack_armv8.S */

.macro trim_map_17 a
    // Keep only 18 out of 24 bits in each 32-bit lane
    //     Lane     0       1       2       3
    //     Bits     0..23   16..39  32..55  48..71
    ushl \a\().4s, \a\().4s, shifts.4s
    //     Bits     0..23   18..39  36..55  54..71
    and \a\().16b, \a\().16b, mask.16b
    //     Bits     0..17   18..35  36..53  54..71

    // Map [0, 1, ..., 2^18-1] to [2^17, 2^17-1, ..., -2^17+1]
    sub \a\().4s, gamma1.4s, \a\().4s
.endm

.macro trim_map_19 a
    // Keep only 20 out of 24 bits in each 32-bit lane
    //     Lane     0       1       2       3
    //     Bits     0..23   16..39  40..63  56..79
    ushl \a\().4s, \a\().4s, shifts.4s
    //     Bits     0..23   20..39  40..63  60..79
    and \a\().16b, \a\().16b, mask.16b
    //     Bits     0..19   20..39  40..59  60..79

    // Map [0, 1, ..., 2^20-1] to [2^19, 2^19-1, ..., -2^19+1]
    sub \a\().4s, gamma1.4s, \a\().4s
.endm

.macro load_idxs
    VLDQ_16B 24, arr_idxs
    VLDQ_16B 25, arr_idxs, #1*16
    VLDQ_16B 26, arr_idxs, #2*16
    VLDQ_16B 27, arr_idxs, #3*16
.endm

    /* Parameters */
    output          .req x0
    buf             .req x1
    arr_idxs         .req x2

    xtmp            .req x3
    count           .req x9

    buf0       .req v0
    buf1       .req v1
    buf2       .req v2
    buf3       .req v3
    tmp0        .req v4
    tmp1        .req v5
    tmp2        .req v6
    tmp3        .req v7

    q_buf0      .req q0
    q_buf1      .req q1
    s_buf2      .req s2
    q_tmp0      .req q4
    q_tmp1      .req q5
    q_tmp2      .req q6
    q_tmp3      .req q7
    d_buf2      .req d2

    /* Constant register assignments */
    idx0            .req v24
    idx1            .req v25
    idx2            .req v26
    idx3            .req v27
    q_idx0          .req q24
    q_idx1          .req q25
    q_idx2          .req q26
    q_idx3          .req q27
    shifts          .req v28
    mask            .req v29    // 2^18 - 1
    gamma1          .req v30    // 2^17

CRYPT_AARCH64_FUNC_START(PolyzUnpack17Asm)
PolyzUnpack17Asm:
AARCH64_PACIASP
    load_idxs

    // Load per-lane shifts 0, -2, -4, -6. (Negative means right shift.)
    // The shifts for the 4 32-bit lanes are sign-extended from the lowest
    // 8 bits, so it suffices to set up only byte 0, 4, 8, 12.
    movz xtmp, 0xfe, lsl 32
    mov shifts.d[0], xtmp
    movz xtmp, 0xfc
    movk xtmp, 0xfa, lsl 32
    mov shifts.d[1], xtmp

    movi mask.4s, 0x3, msl 16

    movi gamma1.4s, 0x2, lsl 16

    mov count, #(64/4)

.polyz_unpack_17_loop:
    VLDQ_16B 1, buf, #16
    add xtmp, buf, #32
    ld1 {buf2.b}[0], [xtmp], #1
    ld1 {buf2.b}[1], [xtmp], #1
    ld1 {buf2.b}[2], [xtmp], #1
    ld1 {buf2.b}[3], [xtmp]
    VLDQ_16B_POST 0, buf, #36

    tbl tmp0.16b, {buf0.16b}, idx0.16b
    tbl tmp1.16b, {buf0.16b - buf1.16b}, idx1.16b
    tbl tmp2.16b, {buf1.16b}, idx2.16b
    tbl tmp3.16b, {buf1.16b - buf2.16b}, idx3.16b

    trim_map_17 tmp0
    trim_map_17 tmp1
    trim_map_17 tmp2
    trim_map_17 tmp3

    VSTQ_4S 5, output, #1*16
    VSTQ_4S 6, output, #2*16
    VSTQ_4S 7, output, #3*16
    VSTQ_4S_POST 4, output, #4*16

    subs count, count, #1
    bne .polyz_unpack_17_loop

AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(PolyzUnpack17Asm)

CRYPT_AARCH64_FUNC_START(PolyzUnpack19Asm)
PolyzUnpack19Asm:
    AARCH64_PACIASP
    load_idxs

    // Load per-lane shifts 0, -4, 0, -4. (Negative means right shift.)
    // The shifts for the 4 32-bit lanes are sign-extended from the lowest
    // 8 bits, so it suffices to set up only byte 0, 4, 8, 12.
    movz xtmp, 0xfc, lsl 32
    dup shifts.2d, xtmp

    movi mask.4s, 0xf, msl 16

    movi gamma1.4s, 0x8, lsl 16

    mov count, #(64/4)

.polyz_unpack_19_loop:
    VLDQ_16B 1, buf, #16
    add xtmp, buf, #32
    ld1 {buf2.8b}, [xtmp]
    VLDQ_16B_POST 0, buf, #40

    tbl tmp0.16b, {buf0.16b}, idx0.16b
    tbl tmp1.16b, {buf0.16b - buf1.16b}, idx1.16b
    tbl tmp2.16b, {buf1.16b}, idx2.16b
    tbl tmp3.16b, {buf1.16b - buf2.16b}, idx3.16b

    trim_map_19 tmp0
    trim_map_19 tmp1
    trim_map_19 tmp2
    trim_map_19 tmp3

    VSTQ_4S 5, output, #1*16
    VSTQ_4S 6, output, #2*16
    VSTQ_4S 7, output, #3*16
    VSTQ_4S_POST 4, output, #4*16

    subs count, count, #1
    bne .polyz_unpack_19_loop

AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(PolyzUnpack19Asm)

    .unreq output
    .unreq buf
    .unreq arr_idxs
    .unreq xtmp
    .unreq count

    .unreq buf0
    .unreq buf1
    .unreq buf2
    .unreq buf3
    .unreq tmp0
    .unreq tmp1
    .unreq tmp2
    .unreq tmp3
    .unreq q_buf0
    .unreq q_buf1
    .unreq s_buf2
    .unreq q_tmp0
    .unreq q_tmp1
    .unreq q_tmp2
    .unreq q_tmp3
    .unreq d_buf2

    .unreq idx0
    .unreq idx1
    .unreq idx2
    .unreq idx3
    .unreq q_idx0
    .unreq q_idx1
    .unreq q_idx2
    .unreq q_idx3
    .unreq shifts
    .unreq mask
    .unreq gamma1

.purgem trim_map_17
.purgem trim_map_19
.purgem load_idxs

CRYPT_AARCH64_FUNC_START(MLDSA_SignBitUnPack)
MLDSA_SignBitUnPack:
    AARCH64_PACIASP
    str x30, [sp, #-16]!
    mov x3, x0
    mov x0, x1
    mov x1, x3

    cmp w2, #18
    b.eq .LMLDSA_SignBitUnPack_17
    cmp w2, #20
    b.eq .LMLDSA_SignBitUnPack_19
    b .LMLDSA_SignBitUnPack_done

.LMLDSA_SignBitUnPack_17:
    CRYPT_AARCH64_GET_GOTSYM(x2, POLYZ_UNPACK_17_INDICES)
    bl PolyzUnpack17Asm
    b .LMLDSA_SignBitUnPack_done

.LMLDSA_SignBitUnPack_19:
    CRYPT_AARCH64_GET_GOTSYM(x2, POLYZ_UNPACK_19_INDICES)
    bl PolyzUnpack19Asm

.LMLDSA_SignBitUnPack_done:
    ldr x30, [sp], #16
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_SignBitUnPack)

/* power2round_armv8.S */

#define MLDSA_D       13
#define MLDSA_D_SUB_1 12

.macro load_data
    ldr q_arr_b0, [arr_t1]
    ldr q_arr_b1, [arr_t1, #1*16]
    ldr q_arr_b2, [arr_t1, #2*16]
    ldr q_arr_b3, [arr_t1, #3*16]
    ldr q_arr_b4, [arr_t1, #4*16]
    ldr q_arr_b5, [arr_t1, #5*16]
    ldr q_arr_b6, [arr_t1, #6*16]
    ldr q_arr_b7, [arr_t1, #7*16]
.endm

.macro save_data
    str q_arr_a1, [arr_t0, #1*16]
    str q_arr_a2, [arr_t0, #2*16]
    str q_arr_a3, [arr_t0, #3*16]
    str q_arr_a4, [arr_t0, #4*16]
    str q_arr_a5, [arr_t0, #5*16]
    str q_arr_a6, [arr_t0, #6*16]
    str q_arr_a7, [arr_t0, #7*16]
    str q_arr_a0, [arr_t0], #8*16

    str q_arr_b1, [arr_t1, #1*16]
    str q_arr_b2, [arr_t1, #2*16]
    str q_arr_b3, [arr_t1, #3*16]
    str q_arr_b4, [arr_t1, #4*16]
    str q_arr_b5, [arr_t1, #5*16]
    str q_arr_b6, [arr_t1, #6*16]
    str q_arr_b7, [arr_t1, #7*16]
    str q_arr_b0, [arr_t1], #8*16
.endm

.macro power2round t1, t0
    add tmp.4s, \t1\().4s, const_12u_sub_1.4s
    sshr tmp.4s, tmp.4s, #13
    shl \t0\().4s, tmp.4s, #13
    sub \t0\().4s, \t1\().4s, \t0\().4s
    mov \t1\().16b, tmp.16b
.endm

    arr_t0      .req x0
    arr_t1      .req x1

    count   .req x4
    wtmp    .req w5

    arr_a0     .req v0
    arr_a1     .req v1
    arr_a2     .req v2
    arr_a3     .req v3
    arr_b0     .req v4
    arr_b1     .req v5
    arr_b2     .req v6
    arr_b3     .req v7
    q_arr_a0     .req q0
    q_arr_a1     .req q1
    q_arr_a2     .req q2
    q_arr_a3     .req q3
    q_arr_b0     .req q4
    q_arr_b1     .req q5
    q_arr_b2     .req q6
    q_arr_b3     .req q7

    const_12u_sub_1     .req v31
    tmp         .req v30
    tmp1        .req v29

    arr_a4      .req v16
    arr_a5      .req v17
    arr_a6      .req v18
    arr_a7      .req v19
    arr_b4      .req v20
    arr_b5      .req v21
    arr_b6      .req v22
    arr_b7      .req v23
    q_arr_a4      .req q16
    q_arr_a5      .req q17
    q_arr_a6      .req q18
    q_arr_a7      .req q19
    q_arr_b4      .req q20
    q_arr_b5      .req q21
    q_arr_b6      .req q22
    q_arr_b7      .req q23

CRYPT_AARCH64_FUNC_START(VecPower2round)
VecPower2round:
AARCH64_PACIASP
    stp d8, d9, [sp, #-64]!
    stp d10, d11, [sp, #16]
    stp d12, d13, [sp, #32]
    stp d14, d15, [sp, #48]

# 0x1000 - 1 = #0xFFF
    mov wtmp, #0x0FFF
    dup const_12u_sub_1.4s, wtmp

    mov count, #(256 / 8 / 4)

    VLDQ_4S 27, x1, #64
    VLDQ_4S 9, x1, #112
    VLDQ_4S 11, x1, #96
    VLDQ_4S 23, x1, #80
    add v6.4s, v27.4s, v31.4s
    add v24.4s, v9.4s, v31.4s
    add v18.4s, v23.4s, v31.4s
    sshr v24.4s, v24.4s, #13
    sshr v19.4s, v6.4s, #13
    add v6.4s, v11.4s, v31.4s
    sshr v13.4s, v18.4s, #13
    shl v18.4s, v24.4s, #13
    orr v24.16b, v24.16b, v24.16b
    sshr v6.4s, v6.4s, #13
    shl v7.4s, v13.4s, #13
    VSTQ_4S 24, x1, #112
    sub v2.4s, v9.4s, v18.4s
    shl v0.4s, v19.4s, #13
    orr v3.16b, v6.16b, v6.16b
    shl v10.4s, v6.4s, #13
    VLDQ_4S 24, x1, #32
    sub x4, x4, #1

.Lpower2round_loop:
    VLDQ_4S 28, x1
    sub v25.4s, v27.4s, v0.4s
    VLDQ_4S 18, x1, #48
    VLDQ_4S 27, x1, #192
    add v26.4s, v24.4s, v31.4s
    VLDQ_4S 6, x1, #16
    sub v20.4s, v23.4s, v7.4s
    VLDQ_4S 23, x1, #208
    VLDQ_4S 9, x1, #240
    VSTQ_4S 3, x1, #96
    orr v13.16b, v13.16b, v13.16b
    orr v3.16b, v19.16b, v19.16b
    add v15.4s, v28.4s, v31.4s
    add v30.4s, v18.4s, v31.4s
    VSTQ_4S 2, x0, #112
    VSTQ_4S 20, x0, #80
    add v7.4s, v6.4s, v31.4s
    sshr v0.4s, v26.4s, #13
    add v14.4s, v23.4s, v31.4s
    VSTQ_4S 13, x1, #80
    add v13.4s, v9.4s, v31.4s
    add v19.4s, v27.4s, v31.4s
    sshr v16.4s, v30.4s, #13
    sshr v26.4s, v7.4s, #13
    VSTQ_4S 3, x1, #64
    orr v22.16b, v0.16b, v0.16b
    sub v29.4s, v11.4s, v10.4s
    sshr v5.4s, v13.4s, #13
    VLDQ_4S 11, x1, #224
    sshr v20.4s, v15.4s, #13
    orr v15.16b, v16.16b, v16.16b
    shl v7.4s, v26.4s, #13
    VSTQ_4S 22, x1, #32
    orr v2.16b, v26.16b, v26.16b
    shl v3.4s, v5.4s, #13
    VSTQ_4S 25, x0, #64
    orr v12.16b, v5.16b, v5.16b
    VSTQ_4S 15, x1, #48
    add v13.4s, v11.4s, v31.4s
    shl v15.4s, v20.4s, #13
    shl v26.4s, v16.4s, #13
    sub v5.4s, v6.4s, v7.4s
    VSTQ_4S 2, x1, #16
    VSTQ_4S 12, x1, #240
    orr v20.16b, v20.16b, v20.16b
    shl v6.4s, v0.4s, #13
    sub v2.4s, v28.4s, v15.4s
    VSTQ_4S 29, x0, #96
    sshr v19.4s, v19.4s, #13
    sshr v15.4s, v13.4s, #13
    sub v29.4s, v18.4s, v26.4s
    VSTQ_4S 5, x0, #16
    sub v26.4s, v24.4s, v6.4s
    sshr v13.4s, v14.4s, #13
    VLDQ_4S 24, x1, #160
    VSTQ_4S_POST 2, x0, #128
    sub v2.4s, v9.4s, v3.4s
    shl v0.4s, v19.4s, #13
    shl v10.4s, v15.4s, #13
    VSTQ_4S_POST 20, x1, #128
    orr v3.16b, v15.16b, v15.16b
    VSTQ_4S 26, x0, #-96
    VSTQ_4S 29, x0, #-80
    shl v7.4s, v13.4s, #13
    subs x4, x4, 1
    cbnz x4, .Lpower2round_loop

    add v9.4s, v24.4s, v31.4s
    VLDQ_4S 18, x1, #48
    sub v6.4s, v11.4s, v10.4s
    VLDQ_4S 28, x1
    sub v0.4s, v27.4s, v0.4s
    VLDQ_4S 10, x1, #16
    orr v13.16b, v13.16b, v13.16b
    VSTQ_4S 2, x0, #112
    orr v27.16b, v19.16b, v19.16b
    VSTQ_4S 6, x0, #96
    VSTQ_4S 3, x1, #96
    sshr v6.4s, v9.4s, #13
    VSTQ_4S 0, x0, #64
    sub v20.4s, v23.4s, v7.4s
    add v23.4s, v18.4s, v31.4s
    VSTQ_4S 27, x1, #64
    add v9.4s, v10.4s, v31.4s
    add v11.4s, v28.4s, v31.4s
    orr v27.16b, v6.16b, v6.16b
    VSTQ_4S 13, x1, #80
    shl v6.4s, v6.4s, #13
    VSTQ_4S 20, x0, #80
    sshr v23.4s, v23.4s, #13
    sshr v11.4s, v11.4s, #13
    sub v6.4s, v24.4s, v6.4s
    VSTQ_4S 27, x1, #32
    sshr v9.4s, v9.4s, #13
    shl v27.4s, v23.4s, #13
    orr v2.16b, v23.16b, v23.16b
    shl v23.4s, v11.4s, #13
    orr v24.16b, v11.16b, v11.16b
    VSTQ_4S 6, x0, #32
    orr v11.16b, v9.16b, v9.16b
    shl v9.4s, v9.4s, #13
    sub v6.4s, v18.4s, v27.4s
    VSTQ_4S 2, x1, #48
    VSTQ_4S_POST 24, x1, #128
    sub v24.4s, v28.4s, v23.4s
    VSTQ_4S 11, x1, #-112
    sub v18.4s, v10.4s, v9.4s
    VSTQ_4S 6, x0, #48
    VSTQ_4S_POST 24, x0, #128
    VSTQ_4S 18, x0, #-112

    ldp d14, d15, [sp, #48]
    ldp d12, d13, [sp, #32]
    ldp d10, d11, [sp, #16]
    ldp d8, d9, [sp], #64
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(VecPower2round)

    .unreq arr_t0
    .unreq arr_t1
    .unreq count
    .unreq wtmp

    .unreq arr_a1
    .unreq arr_a2
    .unreq arr_a3
    .unreq arr_a0
    .unreq arr_b1
    .unreq arr_b2
    .unreq arr_b3
    .unreq arr_b0
    .unreq q_arr_a1
    .unreq q_arr_a2
    .unreq q_arr_a3
    .unreq q_arr_a0
    .unreq q_arr_b1
    .unreq q_arr_b2
    .unreq q_arr_b3
    .unreq q_arr_b0
    .unreq const_12u_sub_1
    .unreq tmp
    .unreq tmp1
    .unreq arr_a4
    .unreq arr_a5
    .unreq arr_a6
    .unreq arr_a7
    .unreq arr_b4
    .unreq arr_b5
    .unreq arr_b6
    .unreq arr_b7
    .unreq q_arr_a4
    .unreq q_arr_a5
    .unreq q_arr_a6
    .unreq q_arr_a7
    .unreq q_arr_b4
    .unreq q_arr_b5
    .unreq q_arr_b6
    .unreq q_arr_b7

.purgem load_data
.purgem save_data
.purgem power2round
#ifdef MLDSA_D
#undef MLDSA_D
#endif
#ifdef MLDSA_D_SUB_1
#undef MLDSA_D_SUB_1
#endif

CRYPT_AARCH64_FUNC_START(MLDSA_ComputesPower2Round)
MLDSA_ComputesPower2Round:
    AARCH64_PACIASP
    stp x19, x20, [sp, #-32]!
    stp x21, x30, [sp, #16]

    ldr x3, [x0]
    ldrb w21, [x3, #4]
    mov x19, x1
    mov x20, x2

.LMLDSA_ComputesPower2Round_loop:
    cbz w21, .LMLDSA_ComputesPower2Round_done
    ldr x0, [x19], #8
    ldr x1, [x20], #8
    bl VecPower2round
    subs w21, w21, #1
    b.ne .LMLDSA_ComputesPower2Round_loop

.LMLDSA_ComputesPower2Round_done:
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_ComputesPower2Round)

/* rej_uniform_armv8.S */

#define MLDSA_N        256
#define MLD_STACK_SIZE (4 * MLDSA_N + 64)

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

    /* Temporary registers */
    initial_zero_count          .req x11
    final_copy_count            .req x11

    rec_idx_0                   .req x12
    rec_idx_1                   .req x13
    rec_idx_2                   .req x14
    rec_idx_3                   .req x15

    ctr0                        .req x12
    ctr1                        .req x13
    ctr2                        .req x14
    ctr3                        .req x15

    ctr01                       .req ctr0
    ctr23                       .req ctr2

    /* Vector registers */

    buf0                        .req v0
    buf1                        .req v1
    buf2                        .req v2

    tmp0                        .req v4
    tmp1                        .req v5
    tmp2                        .req v6
    tmp3                        .req v7

    val0                        .req v16
    val1                        .req v17
    val2                        .req v18
    val3                        .req v19
    val0q                       .req q16
    val1q                       .req q17
    val2q                       .req q18
    val3q                       .req q19

    t0                          .req d20
    t1                          .req d21
    t2                          .req d22
    t3                          .req d23

    table0                      .req v24
    table1                      .req v25
    table2                      .req v26
    table3                      .req v27
    table0q                     .req q24
    table1q                     .req q25
    table2q                     .req q26
    table3q                     .req q27

    mldsa_q                     .req v30
    bits                        .req v31


CRYPT_AARCH64_FUNC_START(MldRejUniformAsm)
MldRejUniformAsm:
    AARCH64_PACIASP
    push_stack

    // Load 0x1, 0x2, 0x4, 0x8
    movz xtmp, 0x1
    movk xtmp, 0x2, lsl 32
    mov bits.d[0], xtmp

    movz xtmp, 0x4
    movk xtmp, 0x8, lsl 32
    mov bits.d[1], xtmp

    // load q = 8380417
    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup mldsa_q.4s, wtmp

    mov output_tmp_base, sp
    mov output_tmp, output_tmp_base

    mov initial_zero_count, #0
    eor val0.16b, val0.16b, val0.16b

.rej_uniform_initial_zero:
        str val0q, [output_tmp], #64
        str val0q, [output_tmp, #-48]
        str val0q, [output_tmp, #-32]
        str val0q, [output_tmp, #-16]
        add initial_zero_count, initial_zero_count, #16
        cmp initial_zero_count, #MLDSA_N
        b.lt .rej_uniform_initial_zero

    mov output_tmp, output_tmp_base

    mov count, #0
    mov len, #MLDSA_N

    cmp buflen, #48
    b.lo .rej_uniform_loop48_end

.rej_uniform_loop48:
        cmp     count, len
        b.hs    .rej_uniform_memory_copy

        // Read bytes from stream
        sub     buflen, buflen, #48
        ld3     {buf0.16b, buf1.16b, buf2.16b}, [buf], #48

        // Mask out top-most bit
        movi    tmp0.16b, #0x80
        bic     buf2.16b, buf2.16b, tmp0.16b

        // Unpack into 16 x int32 -> val 0-3
        zip1    tmp0.16b, buf0.16b, buf1.16b
        zip2    tmp1.16b, buf0.16b, buf1.16b
        uxtl    tmp2.8h, buf2.8b
        uxtl2   tmp3.8h, buf2.16b

        zip1    val0.8h, tmp0.8h, tmp2.8h
        zip2    val1.8h, tmp0.8h, tmp2.8h
        zip1    val2.8h, tmp1.8h, tmp3.8h
        zip2    val3.8h, tmp1.8h, tmp3.8h

        // Given 16 int32 in val 0-3, we do:
        // 1. Identify lanes within range (< q) and
        //      form a 4-bit bitmap of valid indices.
        // 2. Lookup tbl shuffles using that bitmap and
        //      pack valid lanes to the front.
        // 3. Store the packed lanes to the output and
        //      advance the output pointer by the valid count.

        // Set valid lanes to -1 (0b1...1)
        cmhi tmp0.4s, mldsa_q.4s, val0.4s
        cmhi tmp1.4s, mldsa_q.4s, val1.4s
        cmhi tmp2.4s, mldsa_q.4s, val2.4s
        cmhi tmp3.4s, mldsa_q.4s, val3.4s

        // If lane i is valid and has value -1, retain only i-th bit
        and tmp0.16b, tmp0.16b, bits.16b
        and tmp1.16b, tmp1.16b, bits.16b
        and tmp2.16b, tmp2.16b, bits.16b
        and tmp3.16b, tmp3.16b, bits.16b

        // Get 4-bit bitmap of valid lane indices by adding lanes
        uaddlv t0, tmp0.4s
        uaddlv t1, tmp1.4s
        uaddlv t2, tmp2.4s
        uaddlv t3, tmp3.4s

        fmov rec_idx_0, t0
        fmov rec_idx_1, t1
        fmov rec_idx_2, t2
        fmov rec_idx_3, t3

        VLDQ_16B_INDEX 24, table_idx, rec_idx_0
        VLDQ_16B_INDEX 25, table_idx, rec_idx_1
        VLDQ_16B_INDEX 26, table_idx, rec_idx_2
        VLDQ_16B_INDEX 27, table_idx, rec_idx_3

        // Compute number of valid coefficients
        cnt tmp0.16b, tmp0.16b
        cnt tmp1.16b, tmp1.16b
        cnt tmp2.16b, tmp2.16b
        cnt tmp3.16b, tmp3.16b

        // Extract number of valid coefficients
        uaddlv t0, tmp0.4s
        uaddlv t1, tmp1.4s
        uaddlv t2, tmp2.4s
        uaddlv t3, tmp3.4s

        fmov ctr0, t0
        fmov ctr1, t1
        fmov ctr2, t2
        fmov ctr3, t3

        // Move valid coefficients to the front
        tbl val0.16b, {val0.16b}, table0.16b
        tbl val1.16b, {val1.16b}, table1.16b
        tbl val2.16b, {val2.16b}, table2.16b
        tbl val3.16b, {val3.16b}, table3.16b

        VSTQ_4S 16, output_tmp
        add output_tmp, output_tmp, ctr0, lsl #2

        VSTQ_4S 17, output_tmp
        add output_tmp, output_tmp, ctr1, lsl #2

        VSTQ_4S 18, output_tmp
        add output_tmp, output_tmp, ctr2, lsl #2

        VSTQ_4S 19, output_tmp
        add output_tmp, output_tmp, ctr3, lsl #2

        add ctr01, ctr0, ctr1
        add ctr23, ctr2, ctr3
        add count, count, ctr01
        add count, count, ctr23

        cmp buflen, #48
        b.hs .rej_uniform_loop48

.rej_uniform_loop48_end:

    // Finish once we've generated sufficiently many coefficients
    cmp     count, len
    b.hs    .rej_uniform_memory_copy

    cmp buflen, #24
    b.lo .rej_uniform_memory_copy

        sub     buflen, buflen, #24
        ld3     {buf0.8b, buf1.8b, buf2.8b}, [buf], #24

        // mask out top-most bit
        movi    tmp0.16b, #0x80
        bic     buf2.16b, buf2.16b, tmp0.16b

        zip1    tmp0.16b, buf0.16b, buf1.16b
        uxtl    tmp2.8h, buf2.8b

        zip1    val0.8h, tmp0.8h, tmp2.8h
        zip2    val1.8h, tmp0.8h, tmp2.8h

        cmhi    tmp0.4s, mldsa_q.4s, val0.4s
        cmhi    tmp1.4s, mldsa_q.4s, val1.4s

        and     tmp0.16b, tmp0.16b, bits.16b
        and     tmp1.16b, tmp1.16b, bits.16b

        uaddlv  t0, tmp0.4s
        uaddlv  t1, tmp1.4s

        fmov    rec_idx_0, t0
        fmov    rec_idx_1, t1

        VLDQ_16B_INDEX 24, table_idx, rec_idx_0
        VLDQ_16B_INDEX 25, table_idx, rec_idx_1

        cnt     tmp0.16b, tmp0.16b
        cnt     tmp1.16b, tmp1.16b

        uaddlv  t0, tmp0.4s
        uaddlv  t1, tmp1.4s

        fmov    ctr0, t0
        fmov    ctr1, t1

        tbl     val0.16b, {val0.16b}, table0.16b
        tbl     val1.16b, {val1.16b}, table1.16b

        VSTQ_4S 16, output_tmp
        add     output_tmp, output_tmp, ctr0, lsl #2

        VSTQ_4S 17, output_tmp
        add     output_tmp, output_tmp, ctr1, lsl #2

        add     count, count, ctr0
        add     count, count, ctr1

.rej_uniform_memory_copy:
    // min = min(count,len)
    cmp  count, len
    csel count, count, len, lo

    mov final_copy_count, #0
    mov output_tmp, output_tmp_base

.rej_uniform_final_copy:
        VLDQ_4S_POST 16, output_tmp, #64
        VLDQ_4S 17, output_tmp, #-48
        VLDQ_4S 18, output_tmp, #-32
        VLDQ_4S 19, output_tmp, #-16
        VSTQ_4S_POST 16, output, #64
        VSTQ_4S 17, output, #-48
        VSTQ_4S 18, output, #-32
        VSTQ_4S 19, output, #-16
        add final_copy_count, final_copy_count, #16
        cmp final_copy_count, #MLDSA_N
        b.lt .rej_uniform_final_copy

    mov x0, count
    b .rej_uniform_return

.rej_uniform_return:
    pop_stack
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MldRejUniformAsm)

    .unreq output
    .unreq buf
    .unreq buflen
    .unreq table_idx
    .unreq len
    .unreq output_tmp
    .unreq output_tmp_base
    .unreq count
    .unreq xtmp
    .unreq wtmp
    .unreq final_copy_count
    .unreq initial_zero_count
    .unreq rec_idx_0
    .unreq rec_idx_1
    .unreq rec_idx_2
    .unreq rec_idx_3
    .unreq ctr0
    .unreq ctr1
    .unreq ctr2
    .unreq ctr3
    .unreq ctr01
    .unreq ctr23
    .unreq buf0
    .unreq buf1
    .unreq buf2
    .unreq tmp0
    .unreq tmp1
    .unreq tmp2
    .unreq tmp3
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
    .unreq t2
    .unreq t3
    .unreq table0
    .unreq table0q
    .unreq table1
    .unreq table1q
    .unreq table2
    .unreq table2q
    .unreq table3
    .unreq table3q
    .unreq mldsa_q
    .unreq bits

#undef MLD_STACK_SIZE

.purgem push_stack
.purgem pop_stack
#ifdef MLDSA_N
#undef MLDSA_N
#endif

/* rej_uniform_eta2_armv8.S */

#define MLDSA_N        256
#define MLD_STACK_SIZE (2 * MLDSA_N + 64)

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

        VLDQ_16B_INDEX 24, table_idx, rec_idx_0
        VLDQ_16B_INDEX 25, table_idx, rec_idx_1

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
        VSTQ_8H 16, output_tmp
        add output_tmp, output_tmp, ctr0, lsl #1

        VSTQ_8H 17, output_tmp
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
        VLDQ_8H_POST 16, output_tmp, #32
        VLDQ_8H 18, output_tmp, #-16

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

        VSTQ_4S_POST 16, output, #64
        VSTQ_4S 17, output, #-48
        VSTQ_4S 18, output, #-32
        VSTQ_4S 19, output, #-16
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

.purgem push_stack
.purgem pop_stack
#ifdef MLDSA_N
#undef MLDSA_N
#endif

/* rej_uniform_eta4_armv8.S */

#define MLDSA_N        256
#define MLD_STACK_SIZE (2 * MLDSA_N + 64)

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
    const4                      .req v7


    val0                        .req v16
    val0q                       .req q16
    val1                        .req v17
    val1q                       .req q17
    val2                        .req v18
    val2q                       .req q18
    val3                        .req v19
    val3q                       .req q19

    t0                          .req s20
    t1                          .req s21

    table0                      .req v24
    table0q                     .req q24
    table1                      .req v25
    table1q                     .req q25

    eta_bound                   .req v30
    bits                        .req v31

CRYPT_AARCH64_FUNC_START(MldRejUniformEta4Asm)
MldRejUniformEta4Asm:
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

    // Load eta4 bound = 9
    movi eta_bound.8h, #9
    movi const4.8h, #4

    mov output_tmp_base, sp
    mov output_tmp, output_tmp_base

    mov initial_zero_count, #0
    eor val0.16b, val0.16b, val0.16b

.rej_uniform_eta4_initial_zero:
        str val0q, [output_tmp], #64
        str val0q, [output_tmp, #-48]
        str val0q, [output_tmp, #-32]
        str val0q, [output_tmp, #-16]
        add initial_zero_count, initial_zero_count, #32
        cmp initial_zero_count, #MLDSA_N
        b.lt .rej_uniform_eta4_initial_zero

    mov output_tmp, output_tmp_base

    mov count, #0
    mov len, #MLDSA_N

.rej_uniform_eta4_loop8:
        // Finish once we've generated sufficiently many coefficients
        cmp     count, len
        b.hs    .rej_uniform_eta4_memory_copy

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

        // Check which coefficients are within range (< 9)
        cmhi    sign0.8h, eta_bound.8h, val0.8h
        cmhi    sign1.8h, eta_bound.8h, val1.8h

        // If lane i is valid and has value -1, retain only i-th bit
        and     sign0.16b, sign0.16b, bits.16b
        and     sign1.16b, sign1.16b, bits.16b

        // Get 8-bit bitmap of valid lane indices by adding lanes
        uaddlv  t0, sign0.8h
        uaddlv  t1, sign1.8h

        fmov    rec_idx_0_w, t0
        fmov    rec_idx_1_w, t1

        VLDQ_16B_INDEX 24, table_idx, rec_idx_0
        VLDQ_16B_INDEX 25, table_idx, rec_idx_1

        // Compute number of valid coefficients. Recall that at this
        // point, lane i has value 2^i (hence popcount 1) if its coefficient
        // is valid, and 0 otherwise.
        cnt     sign0.16b, sign0.16b
        cnt     sign1.16b, sign1.16b

        // Extract number of valid coefficients
        uaddlv  t0, sign0.8h
        uaddlv  t1, sign1.8h

        fmov    ctr0_w, t0
        fmov    ctr1_w, t1

        // Move valid coefficients to the front
        tbl     val0.16b, {val0.16b}, table0.16b
        tbl     val1.16b, {val1.16b}, table1.16b


        // We store 16-bit coefficients here. They will be expanded to 32-bit
        // on copy out
        st1     {val0.8h}, [output_tmp]
        add     output_tmp, output_tmp, ctr0, lsl #1

        st1     {val1.8h}, [output_tmp]
        add     output_tmp, output_tmp, ctr1, lsl #1

        add     ctr01, ctr0, ctr1
        add     count, count, ctr01

        cmp buflen, #8
        b.hs .rej_uniform_eta4_loop8

.rej_uniform_eta4_memory_copy:
    // min = min(count,len)
    cmp  count, len
    csel count, count, len, lo

    // Always copy MLDSA_N coefficients from the stack to the destination
    mov final_copy_count, #0
    mov output_tmp, output_tmp_base

.rej_uniform_eta4_final_copy:
        VLDQ_8H_POST 16, output_tmp, #32
        VLDQ_8H 18, output_tmp, #-16

        // Apply eta4 transformation: 4 - nibble
        sub val0.8h, const4.8h, val0.8h
        sub val2.8h, const4.8h, val2.8h

        // Expand from 16-bit to 32-bit
        sxtl2 val1.4s, val0.8h
        sxtl  val0.4s, val0.4h

        sxtl2 val3.4s, val2.8h
        sxtl  val2.4s, val2.4h

        VSTQ_4S_POST 16, output, #64
        VSTQ_4S 17, output, #-48
        VSTQ_4S 18, output, #-32
        VSTQ_4S 19, output, #-16
        add final_copy_count, final_copy_count, #16
        cmp final_copy_count, #MLDSA_N
        b.lt .rej_uniform_eta4_final_copy

    mov x0, count
    pop_stack
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MldRejUniformEta4Asm)

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
    .unreq wtmp
    .unreq const4

#undef MLD_STACK_SIZE

.purgem push_stack
.purgem pop_stack
#ifdef MLDSA_N
#undef MLDSA_N
#endif

/* usehint_armv8.S */

.macro load_data
    ldr q_data0, [in]
    ldr q_data1, [in, #1*16]
    ldr q_data2, [in, #2*16]
    ldr q_data3, [in, #3*16]

    ldr q_h_data1, [h_arr, #1*16]
    ldr q_h_data2, [h_arr, #2*16]
    ldr q_h_data3, [h_arr, #3*16]
    ldr q_h_data0, [h_arr], #4*16
.endm

.macro save_data
    str q_out1, [in, #1*16]
    str q_out2, [in, #2*16]
    str q_out3, [in, #3*16]
    str q_out0, [in], #4*16
.endm

.macro finit arr
    // w[i][j] = w[i][j] + (MLDSA_Q & (w[i][j] >> 31))
    eor tmp1.16b, tmp1.16b, tmp1.16b        // tmp1 == 0
    cmlt tmp.4s, \arr\().4s, #0
    bsl tmp.16b, const_q.16b, tmp1.16b
    add \arr\().4s, \arr\().4s, tmp.4s
.endm

.macro decompose a1, a, roundbit
    // a1 = round-(a / 2*gamma2)  round(a * barrett / 2^48 or 2^49),
    // for decompose 33: roundbit = 18, 2*gamma2 = 523776 -> barrett = 1074791425
    // for decompose 88: roundbit = 17, 2*gamma2 = 190464 -> barrett = 1477838209
    sqdmulh \a1\().4s, \a\().4s, const_barrett.4s
    srshr \a1\().4s, \a1\().4s, \roundbit

    // Check for wrap-around
    cmgt tmp.4s, \a\().4s, const_q_bound.4s

    // Compute remainder a0
    mls \a\().4s, \a1\().4s, const_2x_gamma2.4s

    // If wrap-around is required, set a1 = 0 and a0 -= 1
    bic \a1\().16b, \a1\().16b, tmp.16b
    add \a\().4s, \a\().4s, tmp.4s
.endm

.macro use_hint32 b, a, h
    decompose \b, \a, #18

    // delta = (a0 <= 0) ? -1 : 1
    cmle \a\().4s, \a\().4s, #0
    orr \a\().4s, #1

    // b = (b + delta * h) % 16
    mla \b\().4s, \a\().4s, \h\().4s
    and \b\().16b, \b\().16b, mask_15.16b
.endm

.macro use_hint88 b, a, h
    decompose \b, \a, #17

    // delta = (a0 <= 0) ? -1 : 1
    cmle \a\().4s, \a\().4s, #0
    orr \a\().4s, #1

    // b = (b + delta * h) % 44
    mla \b\().4s, \a\().4s, \h\().4s
    cmgt tmp.4s, \b\().4s, const_43.4s
    bic \b\().16b, \b\().16b, tmp.16b
    umin \b\().4s, \b\().4s, const_43.4s
.endm

.macro push_stack
    sub sp, sp, #(16*4)
    stp  d8,  d9, [sp, #16*0]
    stp d10, d11, [sp, #16*1]
    stp d12, d13, [sp, #16*2]
    stp d14, d15, [sp, #16*3]
.endm

.macro pop_stack
    ldp  d8,  d9, [sp, #16*0]
    ldp d10, d11, [sp, #16*1]
    ldp d12, d13, [sp, #16*2]
    ldp d14, d15, [sp, #16*3]
    add sp, sp, #(16*4)
.endm

    in          .req x0
    h_arr       .req x1
    count       .req x4
    wtmp        .req w5

    data0       .req v0
    data1       .req v1
    data2       .req v2
    data3       .req v3
    q_data0     .req q0
    q_data1     .req q1
    q_data2     .req q2
    q_data3     .req q3

    out0        .req v4
    out1        .req v5
    out2        .req v6
    out3        .req v7
    q_out0      .req q4
    q_out1      .req q5
    q_out2      .req q6
    q_out3      .req q7

    tmp                 .req v8
    tmp1                .req v9

    const_q             .req v10
    const_2x_gamma2     .req v11
    const_q_bound       .req v12
    const_barrett       .req v13
    mask_15             .req v14
    const_43            .req v15

    h_data0         .req v31
    h_data1         .req v30
    h_data2         .req v29
    h_data3         .req v28
    q_h_data0       .req q31
    q_h_data1       .req q30
    q_h_data2       .req q29
    q_h_data3       .req q28

CRYPT_AARCH64_FUNC_START(Usehint32)
Usehint32:
    AARCH64_PACIASP
    push_stack

    movz wtmp, #57345
    movk wtmp, #127, lsl #16
    dup const_q.4s, wtmp
    // 2*GAMMA2 = 523776
    movz wtmp, #0xfe00
    movk wtmp, #7, lsl #16
    dup const_2x_gamma2.4s, wtmp
    // 31*GAMMA2 = 8118528
    movz wtmp, #0xe100
    movk wtmp, #0x7b, lsl #16
    dup const_q_bound.4s, wtmp
    // Barrett constant = 1074791425
    movz wtmp, #0x0401
    movk wtmp, #0x4010, lsl #16
    dup const_barrett.4s, wtmp
    movi mask_15.4s, #15
    mov count, #(256 / 4 / 4)

    ldr q27, [x0, #32]
    ldr q1, [x0, #48]
    ldr q30, [x0, #16]
    ldr q2, [x1, #32]
    ldr q8, [x0]
    cmlt v7.4s, v27.4s, #0
    cmlt v20.4s, v1.4s, #0
    cmlt v17.4s, v30.4s, #0
    cmlt v25.4s, v8.4s, #0
    and v7.16b, v10.16b, v7.16b
    and v20.16b, v10.16b, v20.16b
    and v17.16b, v10.16b, v17.16b
    and v25.16b, v10.16b, v25.16b
    add v28.4s, v27.4s, v7.4s
    add v7.4s, v1.4s, v20.4s
    add v27.4s, v30.4s, v17.4s
    add v9.4s, v8.4s, v25.4s
    sqdmulh v1.4s, v28.4s, v13.4s
    cmgt v30.4s, v28.4s, v12.4s
    cmgt v18.4s, v7.4s, v12.4s
    cmgt v19.4s, v9.4s, v12.4s
    cmgt v21.4s, v27.4s, v12.4s
    sqdmulh v8.4s, v7.4s, v13.4s
    srshr v1.4s, v1.4s, #18
    sqdmulh v20.4s, v9.4s, v13.4s
    mls v28.4s, v1.4s, v11.4s
    srshr v4.4s, v8.4s, #18
    bic v25.16b, v1.16b, v30.16b
    srshr v24.4s, v20.4s, #18
    sqdmulh v1.4s, v27.4s, v13.4s
    mls v7.4s, v4.4s, v11.4s
    add v30.4s, v28.4s, v30.4s
    mls v9.4s, v24.4s, v11.4s
    srshr v15.4s, v1.4s, #18
    cmle v1.4s, v30.4s, #0

    .Lusehint_loop_32:
    add v8.4s, v9.4s, v19.4s
    orr v1.4s, #1
    ldr q28, [x0, #96]
    ldr q26, [x0, #112]
    mls v27.4s, v15.4s, v11.4s
    bic v17.16b, v4.16b, v18.16b
    ldr q22, [x1, #48]
    ldr q30, [x1, #16]
    add v20.4s, v7.4s, v18.4s
    mla v25.4s, v1.4s, v2.4s
    ldr q2, [x1, #96]
    cmle v1.4s, v8.4s, #0
    ldr q3, [x0, #80]
    ldr q18, [x0, #64]
    cmlt v5.4s, v28.4s, #0
    ldr q7, [x1], #64
    bic v9.16b, v24.16b, v19.16b
    cmlt v29.4s, v26.4s, #0
    add v0.4s, v27.4s, v21.4s
    orr v1.4s, #1
    bic v8.16b, v15.16b, v21.16b
    and v15.16b, v10.16b, v5.16b
    and v6.16b, v10.16b, v29.16b
    cmlt v23.4s, v18.4s, #0
    mla v9.4s, v1.4s, v7.4s
    cmle v27.4s, v20.4s, #0
    add v1.4s, v28.4s, v15.4s
    and v29.16b, v10.16b, v23.16b
    add v7.4s, v26.4s, v6.4s
    orr v27.4s, #1
    and v25.16b, v25.16b, v14.16b
    cmgt v16.4s, v1.4s, v12.4s
    sqdmulh v23.4s, v1.4s, v13.4s
    and v28.16b, v9.16b, v14.16b
    sqdmulh v4.4s, v7.4s, v13.4s
    cmlt v19.4s, v3.4s, #0
    str q25, [x0, #32]
    add v9.4s, v18.4s, v29.4s
    mla v17.4s, v27.4s, v22.4s
    str q28, [x0], #64
    cmle v20.4s, v0.4s, #0
    srshr v25.4s, v23.4s, #18
    and v19.16b, v10.16b, v19.16b
    sqdmulh v23.4s, v9.4s, v13.4s
    orr v20.4s, #1
    cmgt v18.4s, v7.4s, v12.4s
    mls v1.4s, v25.4s, v11.4s
    add v27.4s, v3.4s, v19.4s
    cmgt v19.4s, v9.4s, v12.4s
    mla v8.4s, v20.4s, v30.4s
    srshr v24.4s, v23.4s, #18
    sqdmulh v26.4s, v27.4s, v13.4s
    srshr v4.4s, v4.4s, #18
    add v21.4s, v1.4s, v16.4s
    mls v9.4s, v24.4s, v11.4s
    and v20.16b, v17.16b, v14.16b
    and v23.16b, v8.16b, v14.16b
    cmle v1.4s, v21.4s, #0
    mls v7.4s, v4.4s, v11.4s
    str q20, [x0, #-16]
    srshr v15.4s, v26.4s, #18
    cmgt v21.4s, v27.4s, v12.4s
    bic v25.16b, v25.16b, v16.16b
    str q23, [x0, #-48]
    subs x4, x4, 1
    cbnz x4, .Lusehint_loop_32

    add v9.4s, v9.4s, v19.4s
    mls v27.4s, v15.4s, v11.4s
    ldr q3, [x1, #16]
    bic v11.16b, v24.16b, v19.16b
    ldr q5, [x1], #64
    orr v1.4s, #1
    add v0.4s, v7.4s, v18.4s
    cmle v8.4s, v9.4s, #0
    ldr q9, [x1, #-16]
    mla v25.4s, v1.4s, v2.4s
    add v7.4s, v27.4s, v21.4s
    cmle v23.4s, v0.4s, #0
    bic v19.16b, v4.16b, v18.16b
    orr v8.4s, #1
    cmle v30.4s, v7.4s, #0
    orr v23.4s, #1
    bic v4.16b, v15.16b, v21.16b
    mla v11.4s, v8.4s, v5.4s
    orr v30.4s, #1
    mla v19.4s, v23.4s, v9.4s
    and v24.16b, v25.16b, v14.16b
    mla v4.4s, v30.4s, v3.4s
    and v0.16b, v11.16b, v14.16b
    str q24, [x0, #32]
    and v28.16b, v19.16b, v14.16b
    str q0, [x0], #64
    and v14.16b, v4.16b, v14.16b
    str q28, [x0, #-16]
    str q14, [x0, #-48]

    pop_stack
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(Usehint32)

CRYPT_AARCH64_FUNC_START(Usehint88)
Usehint88:
    AARCH64_PACIASP
    push_stack

    movz wtmp, #57345
    movk wtmp, #127, lsl #16
    dup const_q.4s, wtmp
    // 2*GAMMA2 = 190464
    movz wtmp, #0xe800
    movk wtmp, #0x2, lsl #16
    dup const_2x_gamma2.4s, wtmp
    // 31*GAMMA2 = 8285184
    movz wtmp, #0x6c00
    movk wtmp, #0x7e, lsl #16
    dup const_q_bound.4s, wtmp
    // Barrett constant = 1477838209
    movz wtmp, #0x0581
    movk wtmp, #0x5816, lsl #16
    dup const_barrett.4s, wtmp
    movi const_43.4s, #43
    mov count, #(256 / 4 / 4)

    ldr q31, [x0, #48]
    ldr q2, [x0, #32]
    ldr q30, [x0]
    ldr q28, [x0, #16]
    ldr q3, [x1, #48]
    ldr q14, [x1, #16]
    cmlt v29.4s, v31.4s, #0
    cmlt v21.4s, v2.4s, #0
    cmlt v23.4s, v30.4s, #0
    cmlt v18.4s, v28.4s, #0
    and v29.16b, v10.16b, v29.16b
    and v21.16b, v10.16b, v21.16b
    and v23.16b, v10.16b, v23.16b
    and v18.16b, v10.16b, v18.16b
    add v29.4s, v31.4s, v29.4s
    add v2.4s, v2.4s, v21.4s
    add v30.4s, v30.4s, v23.4s
    add v31.4s, v28.4s, v18.4s
    sqdmulh v28.4s, v29.4s, v13.4s
    cmgt v19.4s, v2.4s, v12.4s
    cmgt v21.4s, v29.4s, v12.4s
    cmgt v23.4s, v30.4s, v12.4s
    sqdmulh v18.4s, v30.4s, v13.4s
    srshr v28.4s, v28.4s, #17
    sqdmulh v9.4s, v2.4s, v13.4s
    mls v29.4s, v28.4s, v11.4s
    srshr v18.4s, v18.4s, #17
    bic v16.16b, v28.16b, v21.16b
    srshr v1.4s, v9.4s, #17
    sqdmulh v9.4s, v31.4s, v13.4s
    bic v28.16b, v18.16b, v23.16b
    mls v30.4s, v18.4s, v11.4s
    add v29.4s, v29.4s, v21.4s
    mls v2.4s, v1.4s, v11.4s
    srshr v7.4s, v9.4s, #17
    cmle v29.4s, v29.4s, #0
    add v30.4s, v30.4s, v23.4s
    orr v29.4s, #1
    mla v16.4s, v29.4s, v3.4s
    cmle v3.4s, v30.4s, #0

    .Lusehint_loop_88:
    cmgt v17.4s, v31.4s, v12.4s
    ldr q24, [x1], #64
    ldr q22, [x0, #112]
    mls v31.4s, v7.4s, v11.4s
    ldr q21, [x0, #96]
    bic v23.16b, v1.16b, v19.16b
    ldr q27, [x1, #-32]
    ldr q18, [x0, #64]
    add v30.4s, v2.4s, v19.4s
    orr v3.4s, #1
    ldr q9, [x0, #80]
    bic v29.16b, v7.16b, v17.16b
    ldr q5, [x1, #48]
    cmlt v0.4s, v22.4s, #0
    cmgt v7.4s, v16.4s, v15.4s
    cmle v2.4s, v30.4s, #0
    cmlt v20.4s, v21.4s, #0
    add v19.4s, v31.4s, v17.4s
    cmlt v6.4s, v18.4s, #0
    bic v26.16b, v16.16b, v7.16b
    and v0.16b, v10.16b, v0.16b
    orr v2.4s, #1
    and v16.16b, v10.16b, v20.16b
    mla v28.4s, v3.4s, v24.4s
    cmle v3.4s, v19.4s, #0
    add v30.4s, v22.4s, v0.4s
    mla v23.4s, v2.4s, v27.4s
    add v2.4s, v21.4s, v16.4s
    cmlt v31.4s, v9.4s, #0
    and v21.16b, v10.16b, v6.16b
    sqdmulh v1.4s, v30.4s, v13.4s
    orr v3.4s, #1
    cmgt v19.4s, v2.4s, v12.4s
    and v8.16b, v10.16b, v31.16b
    add v0.4s, v18.4s, v21.4s
    cmgt v16.4s, v23.4s, v15.4s
    mla v29.4s, v3.4s, v14.4s
    ldr q14, [x1, #16]
    umin v22.4s, v26.4s, v15.4s
    srshr v6.4s, v1.4s, #17
    cmgt v24.4s, v28.4s, v15.4s
    sqdmulh v25.4s, v0.4s, v13.4s
    cmgt v27.4s, v30.4s, v12.4s
    str q22, [x0, #48]
    mls v30.4s, v6.4s, v11.4s
    bic v4.16b, v23.16b, v16.16b
    bic v28.16b, v28.16b, v24.16b
    sqdmulh v20.4s, v2.4s, v13.4s
    add v31.4s, v9.4s, v8.4s
    srshr v25.4s, v25.4s, #17
    cmgt v17.4s, v0.4s, v12.4s
    cmgt v8.4s, v29.4s, v15.4s
    umin v16.4s, v4.4s, v15.4s
    add v7.4s, v30.4s, v27.4s
    mls v0.4s, v25.4s, v11.4s
    umin v4.4s, v28.4s, v15.4s
    bic v18.16b, v29.16b, v8.16b
    cmle v30.4s, v7.4s, #0
    str q16, [x0, #32]
    sqdmulh v7.4s, v31.4s, v13.4s
    srshr v1.4s, v20.4s, #17
    str q4, [x0], #64
    bic v16.16b, v6.16b, v27.16b
    umin v22.4s, v18.4s, v15.4s
    add v4.4s, v0.4s, v17.4s
    orr v30.4s, #1
    mls v2.4s, v1.4s, v11.4s
    bic v28.16b, v25.16b, v17.16b
    str q22, [x0, #-48]
    srshr v7.4s, v7.4s, #17
    mla v16.4s, v30.4s, v5.4s
    cmle v3.4s, v4.4s, #0
    subs x4, x4, 1
    cbnz x4, .Lusehint_loop_88

    cmgt v18.4s, v31.4s, v12.4s
    mls v31.4s, v7.4s, v11.4s
    bic v23.16b, v1.16b, v19.16b
    ldr q8, [x1, #32]
    add v19.4s, v2.4s, v19.4s
    bic v17.16b, v7.16b, v18.16b
    ldr q7, [x1], #64
    orr v3.4s, #1
    add v10.4s, v31.4s, v18.4s
    cmle v12.4s, v19.4s, #0
    cmgt v27.4s, v16.4s, v15.4s
    mla v28.4s, v3.4s, v7.4s
    cmle v30.4s, v10.4s, #0
    orr v12.4s, #1
    bic v20.16b, v16.16b, v27.16b
    orr v30.4s, #1
    cmgt v5.4s, v28.4s, v15.4s
    mla v23.4s, v12.4s, v8.4s
    mla v17.4s, v30.4s, v14.4s
    umin v30.4s, v20.4s, v15.4s
    bic v0.16b, v28.16b, v5.16b
    str q30, [x0, #48]
    cmgt v24.4s, v23.4s, v15.4s
    umin v11.4s, v0.4s, v15.4s
    cmgt v25.4s, v17.4s, v15.4s
    bic v2.16b, v23.16b, v24.16b
    str q11, [x0], #64
    bic v11.16b, v17.16b, v25.16b
    umin v17.4s, v2.4s, v15.4s
    umin v10.4s, v11.4s, v15.4s
    str q17, [x0, #-32]
    str q10, [x0, #-48]

    pop_stack
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(Usehint88)

    .unreq in
    .unreq h_arr
    .unreq count
    .unreq wtmp

    .unreq data0
    .unreq data1
    .unreq data2
    .unreq data3
    .unreq q_data0
    .unreq q_data1
    .unreq q_data2
    .unreq q_data3
    .unreq out0
    .unreq out1
    .unreq out2
    .unreq out3
    .unreq q_out0
    .unreq q_out1
    .unreq q_out2
    .unreq q_out3
    .unreq tmp
    .unreq tmp1

    .unreq h_data0
    .unreq h_data1
    .unreq h_data2
    .unreq h_data3
    .unreq q_h_data0
    .unreq q_h_data1
    .unreq q_h_data2
    .unreq q_h_data3

    .unreq const_q
    .unreq const_2x_gamma2
    .unreq const_q_bound
    .unreq const_barrett
    .unreq mask_15
    .unreq const_43

.purgem load_data
.purgem save_data
.purgem finit
.purgem decompose
.purgem use_hint32
.purgem use_hint88
.purgem push_stack
.purgem pop_stack

CRYPT_AARCH64_FUNC_START(MLDSA_UseHint)
MLDSA_UseHint:
    AARCH64_PACIASP
    stp x19, x20, [sp, #-32]!
    stp x21, x30, [sp, #16]

    ldr x3, [x0]
    ldrb w21, [x3, #4]
    mov x19, x1
    mov x20, x2
    cmp w21, #4
    b.eq .LMLDSA_UseHint_88

.LMLDSA_UseHint_32_loop:
    cbz w21, .LMLDSA_UseHint_done
    ldr x0, [x20], #8
    ldr x1, [x19], #8
    bl Usehint32
    subs w21, w21, #1
    b.ne .LMLDSA_UseHint_32_loop
    b .LMLDSA_UseHint_done

.LMLDSA_UseHint_88:
    cbz w21, .LMLDSA_UseHint_done
    ldr x0, [x20], #8
    ldr x1, [x19], #8
    bl Usehint88
    subs w21, w21, #1
    b.ne .LMLDSA_UseHint_88

.LMLDSA_UseHint_done:
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_UseHint)

/* validity_check_armv8.S */

.macro load_data
    ldr q_data1, [arr, #(1*(1024/8))]
    ldr q_data2, [arr, #(2*(1024/8))]
    ldr q_data3, [arr, #(3*(1024/8))]
    ldr q_data4, [arr, #(4*(1024/8))]
    ldr q_data5, [arr, #(5*(1024/8))]
    ldr q_data6, [arr, #(6*(1024/8))]
    ldr q_data7, [arr, #(7*(1024/8))]
    ldr q_data0, [arr], #16
.endm

.macro push_stack
    sub sp, sp, #(16*4)
    stp  d8,  d9, [sp, #16*0]
    stp d10, d11, [sp, #16*1]
    stp d12, d13, [sp, #16*2]
    stp d14, d15, [sp, #16*3]
.endm

.macro pop_stack
    ldp  d8,  d9, [sp, #16*0]
    ldp d10, d11, [sp, #16*1]
    ldp d12, d13, [sp, #16*2]
    ldp d14, d15, [sp, #16*3]
    add sp, sp, #(16*4)
.endm

.macro check_one_line ldata, lmask
    // n = z[j] >> 31;    // Shift rightwards by 31 bits.
    // n = z[j] - (n & ((uint32_t)z[j] << 1));
    // if (n >= t) return false;
    // => n = z < 0? z - z*2 : z = ABS(z);
    // n>=t -> hit -> return 1
    abs \ldata\().4s, \ldata\().4s
    cmge \lmask\().4s, \ldata\().4s, const_t.4s
.endm

    output     .req w0
    arr     .req x0
    para_t  .req w1

    count     .req x4

    data0     .req v0
    data1     .req v1
    data2     .req v2
    data3     .req v3
    data4     .req v4
    data5     .req v5
    data6     .req v6
    data7     .req v7
    q_data0     .req q0
    q_data1     .req q1
    q_data2     .req q2
    q_data3     .req q3
    q_data4     .req q4
    q_data5     .req q5
    q_data6     .req q6
    q_data7     .req q7
    tmp         .req v30
    tmp1        .req v29
    mask_tmp    .req v28
    mask_final  .req v27
    const_t     .req v26

CRYPT_AARCH64_FUNC_START(MLDSA_ValidityChecks)
MLDSA_ValidityChecks:
    AARCH64_PACIASP
    push_stack
    dup const_t.4s, para_t

    mov count, #(256 / 32)
    eor tmp.16b, tmp.16b, tmp.16b

    .p2align 2

    VLDQ_4S 0, x0, #128
    VLDQ_4S_POST 2, x0, #16
    VLDQ_4S 1, x0, #752
    VLDQ_4S 29, x0, #368
    VLDQ_4S 15, x0, #496
    VLDQ_4S 23, x0, #880
    sshr v11.4s, v0.4s, #31
    VLDQ_4S 3, x0, #240
    sshr v13.4s, v2.4s, #31
    sshr v20.4s, v15.4s, #31
    eor v0.16b, v0.16b, v11.16b
    sshr v16.4s, v23.4s, #31
    eor v2.16b, v2.16b, v13.16b
    sshr v4.4s, v3.4s, #31
    sshr v9.4s, v29.4s, #31
    eor v15.16b, v15.16b, v20.16b
    eor v23.16b, v23.16b, v16.16b
    sub v0.4s, v0.4s, v11.4s
    eor v11.16b, v3.16b, v4.16b
    sub v2.4s, v2.4s, v13.4s
    sub v3.4s, v15.4s, v20.4s
    eor v15.16b, v29.16b, v9.16b
    VLDQ_4S 27, x0, #624
    cmge v0.4s, v0.4s, v26.4s
    sshr v29.4s, v1.4s, #31
    cmge v20.4s, v2.4s, v26.4s
    sub v4.4s, v11.4s, v4.4s
    sub v15.4s, v15.4s, v9.4s
    eor v2.16b, v1.16b, v29.16b
    sshr v11.4s, v27.4s, #31
    cmge v4.4s, v4.4s, v26.4s
    orr v1.16b, v20.16b, v0.16b
    sub x4, x4, #1
.Lvalidity_check_loop:
    eor v20.16b, v27.16b, v11.16b
    sub v27.4s, v2.4s, v29.4s
    VLDQ_4S 0, x0, #384
    orr v28.16b, v1.16b, v4.16b
    VLDQ_4S_POST 2, x0, #16
    cmge v4.4s, v15.4s, v26.4s
    cmge v24.4s, v3.4s, v26.4s
    sub v23.4s, v23.4s, v16.4s
    VLDQ_4S 7, x0, #112
    cmge v13.4s, v27.4s, v26.4s
    VLDQ_4S 15, x0, #240
    sub v27.4s, v20.4s, v11.4s
    sshr v25.4s, v0.4s, #31
    VLDQ_4S 20, x0, #880
    orr v29.16b, v28.16b, v4.16b
    cmge v4.4s, v23.4s, v26.4s
    VLDQ_4S 16, x0, #752
    sshr v11.4s, v2.4s, #31
    sshr v1.4s, v7.4s, #31
    VLDQ_4S 23, x0, #496
    cmge v3.4s, v27.4s, v26.4s
    VLDQ_4S 27, x0, #624
    sshr v6.4s, v15.4s, #31
    orr v9.16b, v29.16b, v24.16b
    eor v24.16b, v0.16b, v25.16b
    eor v2.16b, v2.16b, v11.16b
    sshr v29.4s, v16.4s, #31
    eor v7.16b, v7.16b, v1.16b
    orr v0.16b, v9.16b, v3.16b
    eor v31.16b, v15.16b, v6.16b
    sub v11.4s, v2.4s, v11.4s
    sshr v3.4s, v23.4s, #31
    sub v1.4s, v7.4s, v1.4s
    eor v2.16b, v16.16b, v29.16b
    sshr v16.4s, v20.4s, #31
    orr v15.16b, v0.16b, v13.16b
    sub v6.4s, v31.4s, v6.4s
    cmge v7.4s, v11.4s, v26.4s
    eor v13.16b, v23.16b, v3.16b
    cmge v23.4s, v1.4s, v26.4s
    sshr v11.4s, v27.4s, #31
    orr v0.16b, v15.16b, v4.16b
    cmge v4.4s, v6.4s, v26.4s
    sub v15.4s, v24.4s, v25.4s
    orr v1.16b, v7.16b, v23.16b
    eor v23.16b, v20.16b, v16.16b
    sub v3.4s, v13.4s, v3.4s
    orr v30.16b, v30.16b, v0.16b

    subs x4, x4, #1
    cbnz x4, .Lvalidity_check_loop

    sub v0.4s, v23.4s, v16.4s
    eor v13.16b, v27.16b, v11.16b
    cmge v15.4s, v15.4s, v26.4s
    orr v20.16b, v1.16b, v4.16b
    sub v27.4s, v2.4s, v29.4s
    cmge v23.4s, v0.4s, v26.4s
    sub v0.4s, v13.4s, v11.4s
    cmge v16.4s, v3.4s, v26.4s
    orr v15.16b, v20.16b, v15.16b
    cmge v27.4s, v27.4s, v26.4s
    cmge v0.4s, v0.4s, v26.4s
    orr v15.16b, v15.16b, v16.16b
    orr v15.16b, v15.16b, v0.16b
    orr v15.16b, v15.16b, v27.16b
    orr v15.16b, v15.16b, v23.16b
    orr v30.16b, v30.16b, v15.16b

    umaxv s29, tmp.4s
    umov w3, v29.s[0]

.Lvalidity_check_done:
    mov w0, #0
    cmp w3, #0
    cset w0, eq

    pop_stack
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_ValidityChecks)

    .unreq output
    .unreq arr
    .unreq para_t
    .unreq count

    .unreq data0
    .unreq data1
    .unreq data2
    .unreq data3
    .unreq data4
    .unreq data5
    .unreq data6
    .unreq data7
    .unreq q_data0
    .unreq q_data1
    .unreq q_data2
    .unreq q_data3
    .unreq q_data4
    .unreq q_data5
    .unreq q_data6
    .unreq q_data7
    .unreq tmp
    .unreq tmp1
    .unreq mask_tmp
    .unreq mask_final
    .unreq const_t

.purgem load_data
.purgem push_stack
.purgem pop_stack
.purgem check_one_line

/* vec_opts_x8_armv8.S */

.macro load_data
    ldr q_arr_a1, [arr_a, #1*16]
    ldr q_arr_a2, [arr_a, #2*16]
    ldr q_arr_a3, [arr_a, #3*16]
    ldr q_arr_a0, [arr_a], #4*16

    ldr q_arr_a4, [arr_a, #1*16]
    ldr q_arr_a5, [arr_a, #2*16]
    ldr q_arr_a6, [arr_a, #3*16]
    ldr q_arr_a7, [arr_a], #4*16

    ldr q_arr_b1, [arr_b, #1*16]
    ldr q_arr_b2, [arr_b, #2*16]
    ldr q_arr_b3, [arr_b, #3*16]
    ldr q_arr_b0, [arr_b], #4*16

    ldr q_arr_b4, [arr_b, #1*16]
    ldr q_arr_b5, [arr_b, #2*16]
    ldr q_arr_b6, [arr_b, #3*16]
    ldr q_arr_b7, [arr_b], #4*16
.endm

.macro save_data
    str q_arr_a1, [arr_out, #1*16]
    str q_arr_a2, [arr_out, #2*16]
    str q_arr_a3, [arr_out, #3*16]
    str q_arr_a0, [arr_out], #4*16

    str q_arr_a4, [arr_out, #1*16]
    str q_arr_a5, [arr_out, #2*16]
    str q_arr_a6, [arr_out, #3*16]
    str q_arr_a7, [arr_out], #4*16
.endm

.macro vec_add_mod out, a, b
    // t[i] = a[i] + b[i];
    add \out\().4s, \a\().4s, \b\().4s
    // int32_t m = (t[i] + (1 << 22u)) >> 23u;
    // t[i] -= m * MLDSA_Q;
    srshr tmp.4s, \out\().4s, #23
    mls \out\().4s, tmp.4s, const_q.4s
.endm

.macro vec_add_q out, a, b
    // t[i] = a[i] + b[i];
    // t[i] = t[i] + (MLDSA_Q & (t[i] >> 31));
    add \out\().4s, \a\().4s, \b\().4s
    ushr tmp.4s, \out\().4s, #31
    mla \out\().4s, tmp.4s, const_q.4s
.endm

.macro vec_sub_mod out, a, b
    // t[i] = a[i] - b[i];
    sub \out\().4s, \a\().4s, \b\().4s
    // int32_t m = (t[i] + (1 << 22u)) >> 23u;
    // t[i] -= m * MLDSA_Q;
    srshr tmp.4s, \out\().4s, #23
    mls \out\().4s, tmp.4s, const_q.4s
.endm

    arr_out      .req x0
    arr_a      .req x1
    arr_b      .req x2
    count   .req x4
    wtmp    .req w5

    arr_a0     .req v0
    arr_a1     .req v1
    arr_a2     .req v2
    arr_a3     .req v3
    arr_b0     .req v4
    arr_b1     .req v5
    arr_b2     .req v6
    arr_b3     .req v7
    q_arr_a0     .req q0
    q_arr_a1     .req q1
    q_arr_a2     .req q2
    q_arr_a3     .req q3
    q_arr_b0     .req q4
    q_arr_b1     .req q5
    q_arr_b2     .req q6
    q_arr_b3     .req q7

    const_q     .req v31
    tmp         .req v30

    arr_a4      .req v16
    arr_a5      .req v17
    arr_a6      .req v18
    arr_a7      .req v19
    arr_b4      .req v20
    arr_b5      .req v21
    arr_b6      .req v22
    arr_b7      .req v23
    q_arr_a4      .req q16
    q_arr_a5      .req q17
    q_arr_a6      .req q18
    q_arr_a7      .req q19
    q_arr_b4      .req q20
    q_arr_b5      .req q21
    q_arr_b6      .req q22
    q_arr_b7      .req q23

CRYPT_AARCH64_FUNC_START(MLDSA_VectorsAdd)
MLDSA_VectorsAdd:
    AARCH64_PACIASP
    sub sp, sp, #(4*16)
    stp d8, d9, [sp, #0*16]
    stp d10, d11, [sp, #1*16]
    stp d12, d13, [sp, #2*16]
    stp d14, d15, [sp, #3*16]

    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    mov count, #(256 / 8 / 4)

    VLDQ_4S 14, x1, #48
    VLDQ_4S 17, x2, #48
    VLDQ_4S_POST 29, x1, #4*16
    VLDQ_4S_POST 18, x2, #4*16
    VLDQ_4S 9, x1, #32
    VLDQ_4S 6, x2, #32
    VLDQ_4S 24, x1, #48
    add v28.4s, v14.4s, v17.4s
    VLDQ_4S_POST 13, x1, #4*16
    VLDQ_4S_POST 11, x2, #4*16
    VLDQ_4S 27, x2, #-16
    add v25.4s, v29.4s, v18.4s
    srshr v5.4s, v28.4s, #23
    add v2.4s, v9.4s, v6.4s
    add v11.4s, v13.4s, v11.4s
    srshr v23.4s, v25.4s, #23
    VLDQ_4S 19, x1, #-96
    add v14.4s, v24.4s, v27.4s
    mls v28.4s, v5.4s, v31.4s
    VLDQ_4S 13, x2, #-48
    VLDQ_4S 12, x2, #-112
    srshr v6.4s, v2.4s, #23
    VLDQ_4S 17, x2, #-96
    VLDQ_4S 24, x1, #-48
    mls v25.4s, v23.4s, v31.4s
    srshr v29.4s, v11.4s, #23
    sub x4, x4, #1
    .Lvec_opts_x8_loop_add:
    VLDQ_4S 8, x1, #-112
    mls v2.4s, v6.4s, v31.4s
    add v6.4s, v19.4s, v17.4s
    VLDQ_4S 19, x1, #32
    VLDQ_4S_POST 27, x1, #4*16
    srshr v21.4s, v14.4s, #23
    mls v11.4s, v29.4s, v31.4s
    VLDQ_4S_POST 16, x2, #4*16
    add v13.4s, v24.4s, v13.4s
    VLDQ_4S 10, x2, #-16
    VLDQ_4S 24, x1, #-16
    srshr v9.4s, v6.4s, #23
    VLDQ_4S 17, x1, #32
    add v1.4s, v8.4s, v12.4s
    mls v14.4s, v21.4s, v31.4s
    VSTQ_4S 28, x0, #48
    VSTQ_4S_POST 25, x0, #4*16
    srshr v8.4s, v13.4s, #23
    mls v6.4s, v9.4s, v31.4s
    add v25.4s, v27.4s, v16.4s
    VLDQ_4S 16, x2, #32
    VSTQ_4S_POST 11, x0, #4*16
    VLDQ_4S_POST 11, x1, #4*16
    srshr v29.4s, v1.4s, #23
    add v28.4s, v24.4s, v10.4s
    VLDQ_4S_POST 26, x2, #4*16
    mls v13.4s, v8.4s, v31.4s
    VLDQ_4S 27, x2, #-16
    srshr v3.4s, v25.4s, #23
    VSTQ_4S 2, x0, #-32
    add v2.4s, v17.4s, v16.4s
    VLDQ_4S 9, x1, #-16
    mls v1.4s, v29.4s, v31.4s
    VSTQ_4S 6, x0, #-96
    VLDQ_4S 17, x2, #-96
    srshr v8.4s, v28.4s, #23
    mls v25.4s, v3.4s, v31.4s
    VLDQ_4S 24, x1, #-48
    add v11.4s, v11.4s, v26.4s
    VSTQ_4S 13, x0, #-48
    VSTQ_4S 14, x0, #-16
    srshr v6.4s, v2.4s, #23
    add v14.4s, v9.4s, v27.4s
    mls v28.4s, v8.4s, v31.4s
    VLDQ_4S 13, x2, #-48
    srshr v29.4s, v11.4s, #23
    VLDQ_4S 12, x2, #-112
    VSTQ_4S 1, x0, #-112
    subs x4, x4, 1
    cbnz x4, .Lvec_opts_x8_loop_add
    mls v2.4s, v6.4s, v31.4s
    add v13.4s, v24.4s, v13.4s
    VLDQ_4S 24, x1, #-112
    VSTQ_4S 28, x0, #48
    srshr v6.4s, v14.4s, #23
    add v8.4s, v19.4s, v17.4s
    mls v11.4s, v29.4s, v31.4s
    VSTQ_4S_POST 25, x0, #4*16
    srshr v1.4s, v13.4s, #23
    mls v14.4s, v6.4s, v31.4s
    add v6.4s, v24.4s, v12.4s
    VSTQ_4S 2, x0, #32
    srshr v28.4s, v8.4s, #23
    mls v13.4s, v1.4s, v31.4s
    VSTQ_4S_POST 11, x0, #4*16
    srshr v1.4s, v6.4s, #23
    mls v8.4s, v28.4s, v31.4s
    VSTQ_4S 14, x0, #-16
    mls v6.4s, v1.4s, v31.4s
    VSTQ_4S 13, x0, #-48
    VSTQ_4S 8, x0, #-96
    VSTQ_4S 6, x0, #-112
    ldp d8, d9, [sp, #0*16]
    ldp d10, d11, [sp, #1*16]
    ldp d12, d13, [sp, #2*16]
    ldp d14, d15, [sp, #3*16]
    add sp, sp, #(4*16)
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_VectorsAdd)

CRYPT_AARCH64_FUNC_START(MLDSA_VectorsSub)
MLDSA_VectorsSub:
    AARCH64_PACIASP
    sub sp, sp, #(4*16)
    stp d8, d9, [sp, #0*16]
    stp d10, d11, [sp, #1*16]
    stp d12, d13, [sp, #2*16]
    stp d14, d15, [sp, #3*16]

    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    mov count, #(256 / 8 / 4)

    VLDQ_4S 11, x2, #32
    VLDQ_4S 8, x1, #32
    VLDQ_4S 2, x2, #48
    VLDQ_4S 14, x1, #48
    VLDQ_4S 28, x1, #80
    VLDQ_4S 19, x2, #80
    VLDQ_4S 24, x2, #112
    sub v9.4s, v8.4s, v11.4s
    VLDQ_4S 26, x1, #112
    sub v20.4s, v14.4s, v2.4s
    srshr v23.4s, v9.4s, #23
    sub v8.4s, v28.4s, v19.4s
    sub v26.4s, v26.4s, v24.4s
    VLDQ_4S 29, x1, #96
    VLDQ_4S 7, x2, #96
    srshr v6.4s, v20.4s, #23
    VLDQ_4S 28, x2, #16
    srshr v24.4s, v8.4s, #23
    VLDQ_4S_POST 17, x2, #4*16
    mls v9.4s, v23.4s, v31.4s
    srshr v16.4s, v26.4s, #23
    VLDQ_4S_POST 2, x1, #4*16
    VLDQ_4S_POST 25, x1, #4*16
    mls v20.4s, v6.4s, v31.4s
    sub v15.4s, v29.4s, v7.4s
    VLDQ_4S_POST 11, x2, #4*16
    sub x4, x4, #1
    .Lvec_opts_x8_loop_sub:
    VLDQ_4S 19, x1, #-112
    sub v1.4s, v2.4s, v17.4s
    mls v26.4s, v16.4s, v31.4s
    VLDQ_4S 7, x1, #32
    srshr v13.4s, v15.4s, #23
    VLDQ_4S 29, x2, #48
    sub v14.4s, v25.4s, v11.4s
    mls v8.4s, v24.4s, v31.4s
    VLDQ_4S 2, x1, #48
    VLDQ_4S_POST 17, x2, #4*16
    srshr v10.4s, v1.4s, #23
    VSTQ_4S 20, x0, #48
    VLDQ_4S 6, x2, #-32
    sub v27.4s, v19.4s, v28.4s
    mls v15.4s, v13.4s, v31.4s
    VLDQ_4S 11, x1, #112
    VLDQ_4S 18, x2, #16
    srshr v30.4s, v14.4s, #23
    sub v20.4s, v2.4s, v29.4s
    VLDQ_4S 25, x2, #48
    mls v1.4s, v10.4s, v31.4s
    VLDQ_4S 19, x1, #80
    srshr v5.4s, v27.4s, #23
    VSTQ_4S 9, x0, #32
    sub v9.4s, v7.4s, v6.4s
    VLDQ_4S 29, x1, #96
    mls v14.4s, v30.4s, v31.4s
    VLDQ_4S 10, x2, #32
    srshr v7.4s, v20.4s, #23
    VSTQ_4S 26, x0, #112
    VLDQ_4S_POST 2, x1, #4*16
    sub v26.4s, v11.4s, v25.4s
    mls v27.4s, v5.4s, v31.4s
    VSTQ_4S_POST 1, x0, #4*16
    VSTQ_4S 8, x0, #16
    srshr v28.4s, v9.4s, #23
    mls v20.4s, v7.4s, v31.4s
    VLDQ_4S_POST 25, x1, #4*16
    sub v8.4s, v19.4s, v18.4s
    VSTQ_4S 15, x0, #32
    srshr v16.4s, v26.4s, #23
    VLDQ_4S_POST 11, x2, #4*16
    mls v9.4s, v28.4s, v31.4s
    VLDQ_4S 28, x2, #-112
    sub v15.4s, v29.4s, v10.4s
    VSTQ_4S_POST 14, x0, #4*16
    srshr v24.4s, v8.4s, #23
    VSTQ_4S 27, x0, #-112
    subs x4, x4, 1
    cbnz x4, .Lvec_opts_x8_loop_sub
    mls v26.4s, v16.4s, v31.4s
    sub v14.4s, v25.4s, v11.4s
    VLDQ_4S 7, x1, #-112
    VSTQ_4S 9, x0, #32
    srshr v9.4s, v15.4s, #23
    sub v19.4s, v2.4s, v17.4s
    mls v8.4s, v24.4s, v31.4s
    VSTQ_4S 20, x0, #48
    srshr v27.4s, v14.4s, #23
    mls v15.4s, v9.4s, v31.4s
    sub v9.4s, v7.4s, v28.4s
    VSTQ_4S 26, x0, #112
    srshr v20.4s, v19.4s, #23
    mls v14.4s, v27.4s, v31.4s
    VSTQ_4S 8, x0, #80
    srshr v27.4s, v9.4s, #23
    mls v19.4s, v20.4s, v31.4s
    VSTQ_4S 15, x0, #96
    mls v9.4s, v27.4s, v31.4s
    VSTQ_4S_POST 19, x0, #4*16
    VSTQ_4S_POST 14, x0, #4*16
    VSTQ_4S 9, x0, #-112
    ldp d8, d9, [sp, #0*16]
    ldp d10, d11, [sp, #1*16]
    ldp d12, d13, [sp, #2*16]
    ldp d14, d15, [sp, #3*16]
    add sp, sp, #(4*16)
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_VectorsSub)

CRYPT_AARCH64_FUNC_START(MLDSA_VectorsAddQ)
MLDSA_VectorsAddQ:
    AARCH64_PACIASP
    sub sp, sp, #(4*16)
    stp d8, d9, [sp, #0*16]
    stp d10, d11, [sp, #1*16]
    stp d12, d13, [sp, #2*16]
    stp d14, d15, [sp, #3*16]

    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    mov count, #(256 / 8 / 4)

    VLDQ_4S 16, x1, #32
    VLDQ_4S 11, x2, #32
    VLDQ_4S_POST 14, x2, #4*16
    VLDQ_4S_POST 26, x2, #4*16
    VLDQ_4S_POST 15, x1, #4*16
    VLDQ_4S_POST 8, x1, #4*16
    add v5.4s, v16.4s, v11.4s
    VLDQ_4S 6, x1, #-48
    VLDQ_4S 2, x2, #-48
    add v1.4s, v8.4s, v26.4s
    VLDQ_4S 16, x2, #-16
    ushr v26.4s, v5.4s, #31
    VLDQ_4S 10, x1, #-16
    add v8.4s, v15.4s, v14.4s
    VLDQ_4S 14, x1, #-32
    ushr v25.4s, v1.4s, #31
    add v12.4s, v6.4s, v2.4s
    mla v5.4s, v26.4s, v31.4s
    VLDQ_4S 6, x2, #-32
    ushr v26.4s, v8.4s, #31
    add v29.4s, v10.4s, v16.4s
    VLDQ_4S 4, x1, #-80
    VLDQ_4S 9, x2, #-80
    mla v1.4s, v25.4s, v31.4s
    ushr v3.4s, v12.4s, #31
    VLDQ_4S 15, x2, #-112
    sub x4, x4, #1
    .Lvec_opts_x8_loop_addq:
    VLDQ_4S 11, x1, #-112
    add v22.4s, v14.4s, v6.4s
    mla v8.4s, v26.4s, v31.4s
    VLDQ_4S 2, x1, #32
    VLDQ_4S_POST 0, x2, #4*16
    ushr v28.4s, v29.4s, #31
    mla v12.4s, v3.4s, v31.4s
    VLDQ_4S 17, x2, #-32
    add v10.4s, v4.4s, v9.4s
    VLDQ_4S_POST 9, x2, #4*16
    VLDQ_4S_POST 3, x1, #4*16
    ushr v20.4s, v22.4s, #31
    VLDQ_4S_POST 24, x1, #4*16
    add v11.4s, v11.4s, v15.4s
    mla v29.4s, v28.4s, v31.4s
    VSTQ_4S 5, x0, #32
    ushr v14.4s, v10.4s, #31
    VLDQ_4S 18, x1, #-48
    add v5.4s, v2.4s, v17.4s
    VLDQ_4S 26, x2, #-48
    mla v22.4s, v20.4s, v31.4s
    VSTQ_4S_POST 8, x0, #4*16
    VSTQ_4S_POST 1, x0, #4*16
    ushr v27.4s, v11.4s, #31
    add v1.4s, v24.4s, v9.4s
    mla v10.4s, v14.4s, v31.4s
    VLDQ_4S 2, x2, #-16
    VLDQ_4S 24, x1, #-16
    ushr v20.4s, v5.4s, #31
    VLDQ_4S 14, x1, #-32
    VLDQ_4S 6, x2, #-32
    mla v11.4s, v27.4s, v31.4s
    add v8.4s, v3.4s, v0.4s
    VSTQ_4S 29, x0, #-16
    VLDQ_4S 4, x1, #-80
    ushr v25.4s, v1.4s, #31
    VSTQ_4S 12, x0, #-48
    mla v5.4s, v20.4s, v31.4s
    add v12.4s, v18.4s, v26.4s
    ushr v26.4s, v8.4s, #31
    VSTQ_4S 22, x0, #-32
    VSTQ_4S 10, x0, #-80
    VLDQ_4S 9, x2, #-80
    mla v1.4s, v25.4s, v31.4s
    add v29.4s, v24.4s, v2.4s
    ushr v3.4s, v12.4s, #31
    VLDQ_4S 15, x2, #-112
    VSTQ_4S 11, x0, #-112
    subs x4, x4, 1
    cbnz x4, .Lvec_opts_x8_loop_addq
    add v16.4s, v14.4s, v6.4s
    mla v8.4s, v26.4s, v31.4s
    VLDQ_4S 30, x1, #-112
    VSTQ_4S 5, x0, #32
    ushr v13.4s, v29.4s, #31
    mla v12.4s, v3.4s, v31.4s
    add v7.4s, v4.4s, v9.4s
    ushr v22.4s, v16.4s, #31
    mla v29.4s, v13.4s, v31.4s
    add v13.4s, v30.4s, v15.4s
    VSTQ_4S_POST 8, x0, #4*16
    ushr v8.4s, v7.4s, #31
    VSTQ_4S_POST 1, x0, #4*16
    mla v16.4s, v22.4s, v31.4s
    VSTQ_4S 12, x0, #-48
    ushr v23.4s, v13.4s, #31
    mla v7.4s, v8.4s, v31.4s
    VSTQ_4S 29, x0, #-16
    mla v13.4s, v23.4s, v31.4s
    VSTQ_4S 16, x0, #-32
    VSTQ_4S 7, x0, #-80
    VSTQ_4S 13, x0, #-112
    ldp d8, d9, [sp, #0*16]
    ldp d10, d11, [sp, #1*16]
    ldp d12, d13, [sp, #2*16]
    ldp d14, d15, [sp, #3*16]
    add sp, sp, #(4*16)
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_VectorsAddQ)

    .unreq arr_out
    .unreq arr_a
    .unreq arr_b
    .unreq count
    .unreq wtmp

    .unreq arr_a1
    .unreq arr_a2
    .unreq arr_a3
    .unreq arr_a0
    .unreq arr_b1
    .unreq arr_b2
    .unreq arr_b3
    .unreq arr_b0
    .unreq q_arr_a1
    .unreq q_arr_a2
    .unreq q_arr_a3
    .unreq q_arr_a0
    .unreq q_arr_b1
    .unreq q_arr_b2
    .unreq q_arr_b3
    .unreq q_arr_b0
    .unreq const_q
    .unreq tmp
    .unreq arr_a4
    .unreq arr_a5
    .unreq arr_a6
    .unreq arr_a7
    .unreq arr_b4
    .unreq arr_b5
    .unreq arr_b6
    .unreq arr_b7
    .unreq q_arr_a4
    .unreq q_arr_a5
    .unreq q_arr_a6
    .unreq q_arr_a7
    .unreq q_arr_b4
    .unreq q_arr_b5
    .unreq q_arr_b6
    .unreq q_arr_b7

.purgem load_data
.purgem save_data
.purgem vec_add_mod
.purgem vec_add_q
.purgem vec_sub_mod

#endif /* HITLS_CRYPTO_MLDSA_ARMV8 */
