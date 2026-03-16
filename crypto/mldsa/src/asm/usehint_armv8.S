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

    .Lloop_32:
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
    cbnz x4, .Lloop_32

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

    .Lloop_88:
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
    cbnz x4, .Lloop_88

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
#endif // HITLS_CRYPTO_MLDSA


