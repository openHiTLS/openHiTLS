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
#define MLDSA_D 13
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

    ldr q27, [x1, #64]
    ldr q9, [x1, #112]
    ldr q11, [x1, #96]
    ldr q23, [x1, #80]
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
    str q24, [x1, #112]
    sub v2.4s, v9.4s, v18.4s
    shl v0.4s, v19.4s, #13
    orr v3.16b, v6.16b, v6.16b
    shl v10.4s, v6.4s, #13
    ldr q24, [x1, #32]
    sub x4, x4, #1

.Lloop:
    ldr q28, [x1]
    sub v25.4s, v27.4s, v0.4s
    ldr q18, [x1, #48]
    ldr q27, [x1, #192]
    add v26.4s, v24.4s, v31.4s
    ldr q6, [x1, #16]
    sub v20.4s, v23.4s, v7.4s
    ldr q23, [x1, #208]
    ldr q9, [x1, #240]
    str q3, [x1, #96]
    orr v13.16b, v13.16b, v13.16b
    orr v3.16b, v19.16b, v19.16b
    add v15.4s, v28.4s, v31.4s
    add v30.4s, v18.4s, v31.4s
    str q2, [x0, #112]
    str q20, [x0, #80]
    add v7.4s, v6.4s, v31.4s
    sshr v0.4s, v26.4s, #13
    add v14.4s, v23.4s, v31.4s
    str q13, [x1, #80]
    add v13.4s, v9.4s, v31.4s
    add v19.4s, v27.4s, v31.4s
    sshr v16.4s, v30.4s, #13
    sshr v26.4s, v7.4s, #13
    str q3, [x1, #64]
    orr v22.16b, v0.16b, v0.16b
    sub v29.4s, v11.4s, v10.4s
    sshr v5.4s, v13.4s, #13
    ldr q11, [x1, #224]
    sshr v20.4s, v15.4s, #13
    orr v15.16b, v16.16b, v16.16b
    shl v7.4s, v26.4s, #13
    str q22, [x1, #32]
    orr v2.16b, v26.16b, v26.16b
    shl v3.4s, v5.4s, #13
    str q25, [x0, #64]
    orr v12.16b, v5.16b, v5.16b
    str q15, [x1, #48]
    add v13.4s, v11.4s, v31.4s
    shl v15.4s, v20.4s, #13
    shl v26.4s, v16.4s, #13
    sub v5.4s, v6.4s, v7.4s
    str q2, [x1, #16]
    str q12, [x1, #240]
    orr v20.16b, v20.16b, v20.16b
    shl v6.4s, v0.4s, #13
    sub v2.4s, v28.4s, v15.4s
    str q29, [x0, #96]
    sshr v19.4s, v19.4s, #13
    sshr v15.4s, v13.4s, #13
    sub v29.4s, v18.4s, v26.4s
    str q5, [x0, #16]
    sub v26.4s, v24.4s, v6.4s
    sshr v13.4s, v14.4s, #13
    ldr q24, [x1, #160]
    str q2, [x0], #128
    sub v2.4s, v9.4s, v3.4s
    shl v0.4s, v19.4s, #13
    shl v10.4s, v15.4s, #13
    str q20, [x1], #128
    orr v3.16b, v15.16b, v15.16b
    str q26, [x0, #-96]
    str q29, [x0, #-80]
    shl v7.4s, v13.4s, #13
    subs x4, x4, 1
    cbnz x4, .Lloop

    add v9.4s, v24.4s, v31.4s
    ldr q18, [x1, #48]
    sub v6.4s, v11.4s, v10.4s
    ldr q28, [x1]
    sub v0.4s, v27.4s, v0.4s
    ldr q10, [x1, #16]
    orr v13.16b, v13.16b, v13.16b
    str q2, [x0, #112]
    orr v27.16b, v19.16b, v19.16b
    str q6, [x0, #96]
    str q3, [x1, #96]
    sshr v6.4s, v9.4s, #13
    str q0, [x0, #64]
    sub v20.4s, v23.4s, v7.4s
    add v23.4s, v18.4s, v31.4s
    str q27, [x1, #64]
    add v9.4s, v10.4s, v31.4s
    add v11.4s, v28.4s, v31.4s
    orr v27.16b, v6.16b, v6.16b
    str q13, [x1, #80]
    shl v6.4s, v6.4s, #13
    str q20, [x0, #80]
    sshr v23.4s, v23.4s, #13
    sshr v11.4s, v11.4s, #13
    sub v6.4s, v24.4s, v6.4s
    str q27, [x1, #32]
    sshr v9.4s, v9.4s, #13
    shl v27.4s, v23.4s, #13
    orr v2.16b, v23.16b, v23.16b
    shl v23.4s, v11.4s, #13
    orr v24.16b, v11.16b, v11.16b
    str q6, [x0, #32]
    orr v11.16b, v9.16b, v9.16b
    shl v9.4s, v9.4s, #13
    sub v6.4s, v18.4s, v27.4s
    str q2, [x1, #48]
    str q24, [x1], #128
    sub v24.4s, v28.4s, v23.4s
    str q11, [x1, #-112]
    sub v18.4s, v10.4s, v9.4s
    str q6, [x0, #48]
    str q24, [x0], #128
    str q18, [x0, #-112]

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
#endif // HITLS_CRYPTO_MLDSA

