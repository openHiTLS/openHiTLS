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

CRYPT_AARCH64_FUNC_START(ValidityCheck)
ValidityCheck:
    AARCH64_PACIASP
    push_stack
    dup const_t.4s, para_t

    mov count, #(256 / 32)
    eor tmp.16b, tmp.16b, tmp.16b

    .p2align 2

    ldr q0, [x0, #128]
    ldr q2, [x0], #16
    ldr q1, [x0, #752]
    ldr q29, [x0, #368]
    ldr q15, [x0, #496]
    ldr q23, [x0, #880]
    sshr v11.4s, v0.4s, #31
    ldr q3, [x0, #240]
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
    ldr q27, [x0, #624]
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
.Lcheck_loop:
    eor v20.16b, v27.16b, v11.16b
    sub v27.4s, v2.4s, v29.4s
    ldr q0, [x0, #384]
    orr v28.16b, v1.16b, v4.16b
    ldr q2, [x0], #16
    cmge v4.4s, v15.4s, v26.4s
    cmge v24.4s, v3.4s, v26.4s
    sub v23.4s, v23.4s, v16.4s
    ldr q7, [x0, #112]
    cmge v13.4s, v27.4s, v26.4s
    ldr q15, [x0, #240]
    sub v27.4s, v20.4s, v11.4s
    sshr v25.4s, v0.4s, #31
    ldr q20, [x0, #880]
    orr v29.16b, v28.16b, v4.16b
    cmge v4.4s, v23.4s, v26.4s
    ldr q16, [x0, #752]
    sshr v11.4s, v2.4s, #31
    sshr v1.4s, v7.4s, #31
    ldr q23, [x0, #496]
    cmge v3.4s, v27.4s, v26.4s
    ldr q27, [x0, #624]
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
    cbnz x4, .Lcheck_loop

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

.Ldone:
    mov w0, #0
    cmp w3, #0
    cset w0, eq

    pop_stack
    AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(ValidityCheck)

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
#endif // HITLS_CRYPTO_MLDSA

