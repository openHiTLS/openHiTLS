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

CRYPT_AARCH64_FUNC_START(VecAdd)
VecAdd:
    AARCH64_PACIASP

    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    mov count, #(256 / 8 / 4)

    ldr q14, [x1, #48]
    ldr q17, [x2, #48]
    ldr q29, [x1], #4*16
    ldr q18, [x2], #4*16
    ldr q9, [x1, #32]
    ldr q6, [x2, #32]
    ldr q24, [x1, #48]
    add v28.4s, v14.4s, v17.4s
    ldr q13, [x1], #4*16
    ldr q11, [x2], #4*16
    ldr q27, [x2, #-16]
    add v25.4s, v29.4s, v18.4s
    srshr v5.4s, v28.4s, #23
    add v2.4s, v9.4s, v6.4s
    add v11.4s, v13.4s, v11.4s
    srshr v23.4s, v25.4s, #23
    ldr q19, [x1, #-96]
    add v14.4s, v24.4s, v27.4s
    mls v28.4s, v5.4s, v31.4s
    ldr q13, [x2, #-48]
    ldr q12, [x2, #-112]
    srshr v6.4s, v2.4s, #23
    ldr q17, [x2, #-96]
    ldr q24, [x1, #-48]
    mls v25.4s, v23.4s, v31.4s
    srshr v29.4s, v11.4s, #23
    sub x4, x4, #1
    .Lloop_add:
    ldr q8, [x1, #-112]
    mls v2.4s, v6.4s, v31.4s
    add v6.4s, v19.4s, v17.4s
    ldr q19, [x1, #32]
    ldr q27, [x1], #4*16
    srshr v21.4s, v14.4s, #23
    mls v11.4s, v29.4s, v31.4s
    ldr q16, [x2], #4*16
    add v13.4s, v24.4s, v13.4s
    ldr q10, [x2, #-16]
    ldr q24, [x1, #-16]
    srshr v9.4s, v6.4s, #23
    ldr q17, [x1, #32]
    add v1.4s, v8.4s, v12.4s
    mls v14.4s, v21.4s, v31.4s
    str q28, [x0, #48]
    str q25, [x0], #4*16
    srshr v8.4s, v13.4s, #23
    mls v6.4s, v9.4s, v31.4s
    add v25.4s, v27.4s, v16.4s
    ldr q16, [x2, #32]
    str q11, [x0], #4*16
    ldr q11, [x1], #4*16
    srshr v29.4s, v1.4s, #23
    add v28.4s, v24.4s, v10.4s
    ldr q26, [x2], #4*16
    mls v13.4s, v8.4s, v31.4s
    ldr q27, [x2, #-16]
    srshr v3.4s, v25.4s, #23
    str q2, [x0, #-32]
    add v2.4s, v17.4s, v16.4s
    ldr q9, [x1, #-16]
    mls v1.4s, v29.4s, v31.4s
    str q6, [x0, #-96]
    ldr q17, [x2, #-96]
    srshr v8.4s, v28.4s, #23
    mls v25.4s, v3.4s, v31.4s
    ldr q24, [x1, #-48]
    add v11.4s, v11.4s, v26.4s
    str q13, [x0, #-48]
    str q14, [x0, #-16]
    srshr v6.4s, v2.4s, #23
    add v14.4s, v9.4s, v27.4s
    mls v28.4s, v8.4s, v31.4s
    ldr q13, [x2, #-48]
    srshr v29.4s, v11.4s, #23
    ldr q12, [x2, #-112]
    str q1, [x0, #-112]
    subs x4, x4, 1
    cbnz x4, .Lloop_add
    mls v2.4s, v6.4s, v31.4s
    add v13.4s, v24.4s, v13.4s
    ldr q24, [x1, #-112]
    str q28, [x0, #48]
    srshr v6.4s, v14.4s, #23
    add v8.4s, v19.4s, v17.4s
    mls v11.4s, v29.4s, v31.4s
    str q25, [x0], #4*16
    srshr v1.4s, v13.4s, #23
    mls v14.4s, v6.4s, v31.4s
    add v6.4s, v24.4s, v12.4s
    str q2, [x0, #32]
    srshr v28.4s, v8.4s, #23
    mls v13.4s, v1.4s, v31.4s
    str q11, [x0], #4*16
    srshr v1.4s, v6.4s, #23
    mls v8.4s, v28.4s, v31.4s
    str q14, [x0, #-16]
    mls v6.4s, v1.4s, v31.4s
    str q13, [x0, #-48]
    str q8, [x0, #-96]
    str q6, [x0, #-112]
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(VecAdd)

CRYPT_AARCH64_FUNC_START(VecSub)
VecSub:
    AARCH64_PACIASP
    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    mov count, #(256 / 8 / 4)

    ldr q11, [x2, #32]
    ldr q8, [x1, #32]
    ldr q2, [x2, #48]
    ldr q14, [x1, #48]
    ldr q28, [x1, #80]
    ldr q19, [x2, #80]
    ldr q24, [x2, #112]
    sub v9.4s, v8.4s, v11.4s
    ldr q26, [x1, #112]
    sub v20.4s, v14.4s, v2.4s
    srshr v23.4s, v9.4s, #23
    sub v8.4s, v28.4s, v19.4s
    sub v26.4s, v26.4s, v24.4s
    ldr q29, [x1, #96]
    ldr q7, [x2, #96]
    srshr v6.4s, v20.4s, #23
    ldr q28, [x2, #16]
    srshr v24.4s, v8.4s, #23
    ldr q17, [x2], #4*16
    mls v9.4s, v23.4s, v31.4s
    srshr v16.4s, v26.4s, #23
    ldr q2, [x1], #4*16
    ldr q25, [x1], #4*16
    mls v20.4s, v6.4s, v31.4s
    sub v15.4s, v29.4s, v7.4s
    ldr q11, [x2], #4*16
    sub x4, x4, #1
    .Lloop_sub:
    ldr q19, [x1, #-112]
    sub v1.4s, v2.4s, v17.4s
    mls v26.4s, v16.4s, v31.4s
    ldr q7, [x1, #32]
    srshr v13.4s, v15.4s, #23
    ldr q29, [x2, #48]
    sub v14.4s, v25.4s, v11.4s
    mls v8.4s, v24.4s, v31.4s
    ldr q2, [x1, #48]
    ldr q17, [x2], #4*16
    srshr v10.4s, v1.4s, #23
    str q20, [x0, #48]
    ldr q6, [x2, #-32]
    sub v27.4s, v19.4s, v28.4s
    mls v15.4s, v13.4s, v31.4s
    ldr q11, [x1, #112]
    ldr q18, [x2, #16]
    srshr v30.4s, v14.4s, #23
    sub v20.4s, v2.4s, v29.4s
    ldr q25, [x2, #48]
    mls v1.4s, v10.4s, v31.4s
    ldr q19, [x1, #80]
    srshr v5.4s, v27.4s, #23
    str q9, [x0, #32]
    sub v9.4s, v7.4s, v6.4s
    ldr q29, [x1, #96]
    mls v14.4s, v30.4s, v31.4s
    ldr q10, [x2, #32]
    srshr v7.4s, v20.4s, #23
    str q26, [x0, #112]
    ldr q2, [x1], #4*16
    sub v26.4s, v11.4s, v25.4s
    mls v27.4s, v5.4s, v31.4s
    str q1, [x0], #4*16
    str q8, [x0, #16]
    srshr v28.4s, v9.4s, #23
    mls v20.4s, v7.4s, v31.4s
    ldr q25, [x1], #4*16
    sub v8.4s, v19.4s, v18.4s
    str q15, [x0, #32]
    srshr v16.4s, v26.4s, #23
    ldr q11, [x2], #4*16
    mls v9.4s, v28.4s, v31.4s
    ldr q28, [x2, #-112]
    sub v15.4s, v29.4s, v10.4s
    str q14, [x0], #4*16
    srshr v24.4s, v8.4s, #23
    str q27, [x0, #-112]
    subs x4, x4, 1
    cbnz x4, .Lloop_sub
    mls v26.4s, v16.4s, v31.4s
    sub v14.4s, v25.4s, v11.4s
    ldr q7, [x1, #-112]
    str q9, [x0, #32]
    srshr v9.4s, v15.4s, #23
    sub v19.4s, v2.4s, v17.4s
    mls v8.4s, v24.4s, v31.4s
    str q20, [x0, #48]
    srshr v27.4s, v14.4s, #23
    mls v15.4s, v9.4s, v31.4s
    sub v9.4s, v7.4s, v28.4s
    str q26, [x0, #112]
    srshr v20.4s, v19.4s, #23
    mls v14.4s, v27.4s, v31.4s
    str q8, [x0, #80]
    srshr v27.4s, v9.4s, #23
    mls v19.4s, v20.4s, v31.4s
    str q15, [x0, #96]
    mls v9.4s, v27.4s, v31.4s
    str q19, [x0], #4*16
    str q14, [x0], #4*16
    str q9, [x0, #-112]
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(VecSub)

CRYPT_AARCH64_FUNC_START(VecAddq)
VecAddq:
    AARCH64_PACIASP

    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup const_q.4s, wtmp

    mov count, #(256 / 8 / 4)

    ldr q16, [x1, #32]
    ldr q11, [x2, #32]
    ldr q14, [x2], #4*16
    ldr q26, [x2], #4*16
    ldr q15, [x1], #4*16
    ldr q8, [x1], #4*16
    add v5.4s, v16.4s, v11.4s
    ldr q6, [x1, #-48]
    ldr q2, [x2, #-48]
    add v1.4s, v8.4s, v26.4s
    ldr q16, [x2, #-16]
    ushr v26.4s, v5.4s, #31
    ldr q10, [x1, #-16]
    add v8.4s, v15.4s, v14.4s
    ldr q14, [x1, #-32]
    ushr v25.4s, v1.4s, #31
    add v12.4s, v6.4s, v2.4s
    mla v5.4s, v26.4s, v31.4s
    ldr q6, [x2, #-32]
    ushr v26.4s, v8.4s, #31
    add v29.4s, v10.4s, v16.4s
    ldr q4, [x1, #-80]
    ldr q9, [x2, #-80]
    mla v1.4s, v25.4s, v31.4s
    ushr v3.4s, v12.4s, #31
    ldr q15, [x2, #-112]
    sub x4, x4, #1
    .Lloop_addq:
    ldr q11, [x1, #-112]
    add v22.4s, v14.4s, v6.4s
    mla v8.4s, v26.4s, v31.4s
    ldr q2, [x1, #32]
    ldr q0, [x2], #4*16
    ushr v28.4s, v29.4s, #31
    mla v12.4s, v3.4s, v31.4s
    ldr q17, [x2, #-32]
    add v10.4s, v4.4s, v9.4s
    ldr q9, [x2], #4*16
    ldr q3, [x1], #4*16
    ushr v20.4s, v22.4s, #31
    ldr q24, [x1], #4*16
    add v11.4s, v11.4s, v15.4s
    mla v29.4s, v28.4s, v31.4s
    str q5, [x0, #32]
    ushr v14.4s, v10.4s, #31
    ldr q18, [x1, #-48]
    add v5.4s, v2.4s, v17.4s
    ldr q26, [x2, #-48]
    mla v22.4s, v20.4s, v31.4s
    str q8, [x0], #4*16
    str q1, [x0], #4*16
    ushr v27.4s, v11.4s, #31
    add v1.4s, v24.4s, v9.4s
    mla v10.4s, v14.4s, v31.4s
    ldr q2, [x2, #-16]
    ldr q24, [x1, #-16]
    ushr v20.4s, v5.4s, #31
    ldr q14, [x1, #-32]
    ldr q6, [x2, #-32]
    mla v11.4s, v27.4s, v31.4s
    add v8.4s, v3.4s, v0.4s
    str q29, [x0, #-16]
    ldr q4, [x1, #-80]
    ushr v25.4s, v1.4s, #31
    str q12, [x0, #-48]
    mla v5.4s, v20.4s, v31.4s
    add v12.4s, v18.4s, v26.4s
    ushr v26.4s, v8.4s, #31
    str q22, [x0, #-32]
    str q10, [x0, #-80]
    ldr q9, [x2, #-80]
    mla v1.4s, v25.4s, v31.4s
    add v29.4s, v24.4s, v2.4s
    ushr v3.4s, v12.4s, #31
    ldr q15, [x2, #-112]
    str q11, [x0, #-112]
    subs x4, x4, 1
    cbnz x4, .Lloop_addq
    add v16.4s, v14.4s, v6.4s
    mla v8.4s, v26.4s, v31.4s
    ldr q30, [x1, #-112]
    str q5, [x0, #32]
    ushr v13.4s, v29.4s, #31
    mla v12.4s, v3.4s, v31.4s
    add v7.4s, v4.4s, v9.4s
    ushr v22.4s, v16.4s, #31
    mla v29.4s, v13.4s, v31.4s
    add v13.4s, v30.4s, v15.4s
    str q8, [x0], #4*16
    ushr v8.4s, v7.4s, #31
    str q1, [x0], #4*16
    mla v16.4s, v22.4s, v31.4s
    str q12, [x0, #-48]
    ushr v23.4s, v13.4s, #31
    mla v7.4s, v8.4s, v31.4s
    str q29, [x0, #-16]
    mla v13.4s, v23.4s, v31.4s
    str q16, [x0, #-32]
    str q7, [x0, #-80]
    str q13, [x0, #-112]
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(VecAddq)

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
#endif // HITLS_CRYPTO_MLDSA

