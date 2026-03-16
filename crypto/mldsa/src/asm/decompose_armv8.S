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

    ldr q9, [x0]
    ldr q22, [x0, #16]
    ldr q25, [x0, #32]
    ldr q16, [x0, #48]
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
    .Lloop_32:
    ldr q7, [x0, #64]
    cmgt v4.4s, v22.4s, v29.4s
    sqdmulh v11.4s, v22.4s, v28.4s
    ldr q15, [x0, #80]
    ldr q6, [x0, #96]
    add v25.4s, v16.4s, v25.4s
    ldr q16, [x0, #112]
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
    str q1, [x0], #64
    cmlt v12.4s, v15.4s, #0
    add v1.4s, v9.4s, v20.4s
    cmlt v0.4s, v16.4s, #0
    str q19, [x0, #-32]
    bic v7.16b, v11.16b, v20.16b
    and v18.16b, v31.16b, v18.16b
    add v19.4s, v25.4s, v5.4s
    str q2, [x1, #32]
    bic v8.16b, v8.16b, v14.16b
    str q1, [x0, #-48]
    bic v9.16b, v27.16b, v5.16b
    and v2.16b, v31.16b, v12.16b
    cmgt v14.4s, v10.4s, v29.4s
    add v22.4s, v6.4s, v18.4s
    str q7, [x1, #16]
    str q19, [x0, #-16]
    sqdmulh v5.4s, v10.4s, v28.4s
    and v25.16b, v31.16b, v0.16b
    str q8, [x1], #64
    str q9, [x1, #-16]
    add v9.4s, v15.4s, v2.4s
    subs x4, x4, 1
    cbnz x4, .Lloop_32
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
    str q15, [x1], #64
    mls v9.4s, v6.4s, v30.4s
    bic v15.16b, v6.16b, v2.16b
    add v6.4s, v10.4s, v14.4s
    str q7, [x1, #-32]
    mls v25.4s, v28.4s, v30.4s
    bic v30.16b, v28.16b, v29.16b
    add v22.4s, v22.4s, v16.4s
    str q15, [x1, #-48]
    str q6, [x0], #64
    add v9.4s, v9.4s, v2.4s
    str q30, [x1, #-16]
    str q22, [x0, #-32]
    add v29.4s, v25.4s, v29.4s
    str q9, [x0, #-48]
    str q29, [x0, #-16]
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

    ldr q5, [x0, #16]
    ldr q13, [x0, #48]
    ldr q27, [x0, #32]
    ldr q18, [x0]
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
    .Lloop_88:
    ldr q18, [x0, #80]
    cmgt v20.4s, v5.4s, v29.4s
    mls v5.4s, v24.4s, v30.4s
    srshr v0.4s, v17.4s, #17
    ldr q19, [x0, #112]
    ldr q1, [x0, #96]
    cmgt v12.4s, v13.4s, v29.4s
    mls v13.4s, v25.4s, v30.4s
    srshr v17.4s, v15.4s, #17
    ldr q27, [x0, #64]
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
    str q11, [x0], #64
    add v18.4s, v13.4s, v12.4s
    add v13.4s, v1.4s, v16.4s
    bic v1.16b, v25.16b, v12.16b
    sqdmulh v15.4s, v5.4s, v28.4s
    str q3, [x0, #-48]
    add v9.4s, v27.4s, v9.4s
    str q14, [x0, #-16]
    bic v21.16b, v24.16b, v20.16b
    str q18, [x0, #-32]
    sqdmulh v18.4s, v13.4s, v28.4s
    add v14.4s, v19.4s, v23.4s
    bic v27.16b, v17.16b, v4.16b
    sqdmulh v17.4s, v9.4s, v28.4s
    bic v19.16b, v0.16b, v22.16b
    str q21, [x1, #16]
    srshr v24.4s, v15.4s, #17
    sqdmulh v15.4s, v14.4s, v28.4s
    srshr v25.4s, v18.4s, #17
    str q27, [x1, #48]
    str q1, [x1, #32]
    cmgt v22.4s, v9.4s, v29.4s
    cmgt v4.4s, v14.4s, v29.4s
    str q19, [x1], #64
    subs x4, x4, 1
    cbnz x4, .Lloop_88
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
    str q0, [x1], #64
    add v30.4s, v13.4s, v27.4s
    str q29, [x1, #-32]
    bic v29.16b, v18.16b, v4.16b
    str q28, [x1, #-48]
    add v5.4s, v5.4s, v26.4s
    add v18.4s, v9.4s, v22.4s
    str q30, [x0, #32]
    str q29, [x1, #-16]
    add v28.4s, v14.4s, v4.4s
    str q5, [x0, #16]
    str q18, [x0], #64
    str q28, [x0, #-16]
    ldp d8, d9, [sp, #16*0]
    ldp d10, d11, [sp, #16*1]
    ldp d12, d13, [sp, #16*2]
    ldp d14, d15, [sp, #16*3]
    add sp, sp, #(16*4)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(BatchDecompose88)

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

#endif // HITLS_CRYPTO_MLDSA
