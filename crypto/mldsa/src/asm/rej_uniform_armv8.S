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
#define MLD_STACK_SIZE (4*MLDSA_N + 64)

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

        ldr table0q, [table_idx, rec_idx_0, lsl #4]
        ldr table1q, [table_idx, rec_idx_1, lsl #4]
        ldr table2q, [table_idx, rec_idx_2, lsl #4]
        ldr table3q, [table_idx, rec_idx_3, lsl #4]

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

        str val0q, [output_tmp]
        add output_tmp, output_tmp, ctr0, lsl #2

        str val1q, [output_tmp]
        add output_tmp, output_tmp, ctr1, lsl #2

        str val2q, [output_tmp]
        add output_tmp, output_tmp, ctr2, lsl #2

        str val3q, [output_tmp]
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

        ldr     table0q, [table_idx, rec_idx_0, lsl #4]
        ldr     table1q, [table_idx, rec_idx_1, lsl #4]

        cnt     tmp0.16b, tmp0.16b
        cnt     tmp1.16b, tmp1.16b

        uaddlv  t0, tmp0.4s
        uaddlv  t1, tmp1.4s

        fmov    ctr0, t0
        fmov    ctr1, t1

        tbl     val0.16b, {val0.16b}, table0.16b
        tbl     val1.16b, {val1.16b}, table1.16b

        str     val0q, [output_tmp]
        add     output_tmp, output_tmp, ctr0, lsl #2

        str     val1q, [output_tmp]
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
        ldr val0q, [output_tmp], #64
        ldr val1q, [output_tmp, #-48]
        ldr val2q, [output_tmp, #-32]
        ldr val3q, [output_tmp, #-16]
        str val0q, [output], #64
        str val1q, [output, #-48]
        str val2q, [output, #-32]
        str val3q, [output, #-16]
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
#endif // HITLS_CRYPTO_MLDSA
