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
    ldr q_idx0, [arr_idxs]
    ldr q_idx1, [arr_idxs, #1*16]
    ldr q_idx2, [arr_idxs, #2*16]
    ldr q_idx3, [arr_idxs, #3*16]
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
    ldr q_buf1, [buf, #16]
    ldr s_buf2, [buf, #32]
    ldr q_buf0, [buf], #36

    tbl tmp0.16b, {buf0.16b}, idx0.16b
    tbl tmp1.16b, {buf0.16b - buf1.16b}, idx1.16b
    tbl tmp2.16b, {buf1.16b}, idx2.16b
    tbl tmp3.16b, {buf1.16b - buf2.16b}, idx3.16b

    trim_map_17 tmp0
    trim_map_17 tmp1
    trim_map_17 tmp2
    trim_map_17 tmp3

    str q_tmp1, [output, #1*16]
    str q_tmp2, [output, #2*16]
    str q_tmp3, [output, #3*16]
    str q_tmp0, [output], #4*16

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
    ldr q_buf1, [buf, #16]
    ldr d_buf2, [buf, #32]
    ldr q_buf0, [buf], #40

    tbl tmp0.16b, {buf0.16b}, idx0.16b
    tbl tmp1.16b, {buf0.16b - buf1.16b}, idx1.16b
    tbl tmp2.16b, {buf1.16b}, idx2.16b
    tbl tmp3.16b, {buf1.16b - buf2.16b}, idx3.16b

    trim_map_19 tmp0
    trim_map_19 tmp1
    trim_map_19 tmp2
    trim_map_19 tmp3

    str q_tmp1, [output, #1*16]
    str q_tmp2, [output, #2*16]
    str q_tmp3, [output, #3*16]
    str q_tmp0, [output], #4*16

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
#endif // HITLS_CRYPTO_MLDSA
