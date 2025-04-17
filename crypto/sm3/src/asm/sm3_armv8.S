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
#ifdef HITLS_CRYPTO_SM3

#include "crypt_arm.h"
.arch    armv8-a+crypto

// The first 16 of the compression function, w13 is Tj.
.macro first16 A B C D E F G H W1 W2
    ror w13, w13, #31
    ror w10, \A, #20
    add w9, \E, w10
    eor w12, \E, \F
    ror \F, \F, #13
    eor w12, w12, \G
    add w12, w12, \H
    add w9, w9, w13
    ror w9, w9, #25
    add w12, w12, w9
    eor w10, w10, w9
    add w12, w12, \W1
    eor \H, w12, w12, ror #23
    ror w9, w12, #15
    eor \H, \H, w9
    eor w11, \A, \B
    ror \B, \B, #23
    eor w11, w11, \C
    add w11, w11, \D
    add w11, w11, w10
    eor w9, \W1, \W2
    add \D, w11, w9
    .endm

// Compress the last 48 of the function, w13 is Tj
.macro second48 A B C D E F G H W1 W2
    ror w13, w13, #31
    orr w11, \B, \C
    eor w12, \F, \G
    ror \F, \F, #13
    ror w10, \A, #20
    add w9, w10, \E
    and w14, \A, w11
    and w12, w12, \E
    eor w12, w12, \G
    add w12, w12, \H
    add w9, w9, w13
    ror w9, w9, #25
    add w12, w12, w9
    eor w10, w10, w9
    add w12, w12, \W1
    and w11, \B, \C
    ror \B, \B, #23
    orr w11, w11, w14
    eor w9, \W1, \W2
    add w11, w11, \D
    add w11, w11, w10
    add \D, w11, w9
    eor \H, w12, w12, ror #23
    ror w9, w12, #15
    eor \H, \H, w9
    .endm

// void SM3_CompressAsm(uint32_t state[8], const uint8_t *data, uint32_t blockCnt);
.globl SM3_CompressAsm
.type  SM3_CompressAsm, %function
.align 4
SM3_CompressAsm:
AARCH64_PACIASP
    sub sp, sp, 128
    stp x19, x20, [sp]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    // According to the calling convention, this function needs to be saved.
    stp d8, d9, [sp, #64]
    stp d10, d11, [sp, #80]
    stp d12, d13, [sp, #96]
    stp d14, d15, [sp, #112]

    sub sp, sp, 64
    mov x25, sp
    sub sp, sp, 64
    mov x26, sp

    mov x22, x0 // x22: state
    mov x23, x1 // x23: data
    mov w24, w2 // x24: blockCnt

    // w0-w7: ABCDEFGH word register in"SM3 cryptographic hash algorithm"
    ldp w0, w1, [x22]
    ldp w2, w3, [x22, #8]
    ldp w4, w5, [x22, #16]
    ldp w6, w7, [x22, #24]

    prfm pldl1keep, [x23, #64]
    blocksloop_1:
    subs w24, w24, #1
    bmi end
    // Due to the SM3 feature, only three messages can be extended in parallel.
    // You need to use ext to ensure that the data meets the requirements for calculation.
    // To reduce the delay, the message expansion is calculated together with the compression function,
    // and the compression function is calculated three times for every three Ws.

    // v0-v3 message group w0-w15
    ld1 {v0.4s-v3.4s}, [x23]
#ifndef HITLS_BIG_ENDIAN
    rev32 v0.16B, v0.16B
    rev32 v1.16B, v1.16B
    rev32 v2.16B, v2.16B
    rev32 v3.16B, v3.16B
#endif

    ldp w15, w20, [x23]
    ldp w19, w21, [x23, #16]
#ifndef HITLS_BIG_ENDIAN
    rev w15, w15
    rev w19, w19
    rev w20, w20
    rev w21, w21
#endif

    ext v24.16b, v3.16b, v3.16b, #4   // 13, 14, 15
    ext v25.16b, v0.16b, v1.16b, #12  // 3, 4, 5
    ext v23.16b, v1.16b, v2.16b, #12  // 7, 8, 9
    ext v26.16b, v2.16b, v3.16b, #8   // 10, 11, 12
    eor v27.16b, v0.16b, v23.16b
    // w13: constant Tj , 0 <= j <= 16
    mov w13, #0x228c
    movk w13, #0xbce6, lsl #16

    // Message grouping: Wj−3 ≪ 15, Wj−13 ≪ 7
    shl v21.4s, v24.4s, #15
    shl v22.4s, v25.4s, #7
    sri v21.4s, v24.4s, #17  // 13, 14, 15<<<15
    sri v22.4s, v25.4s, #25  // 3, 4, 5<<<7
    first16 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v26.16b
    first16 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    // permutation function P1: X ^ (X ≪ 15) ^ (X ≪ 23)
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    ldp w15, w20, [x23, #8]
    ldp w19, w21, [x23, #24]
#ifndef HITLS_BIG_ENDIAN
    rev w15, w15
    rev w19, w19
    rev w20, w20
    rev w21, w21
#endif
    eor v27.16b, v27.16b, v30.16b
    first16 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    eor v4.16b, v27.16b, v28.16b

    // 2:19, 20, 21
    ext v23.16b, v1.16b, v2.16b, #8  // 6, 7, 8
    eor v27.16b, v25.16b, v26.16b
    first16 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    shl v21.4s, v4.4s, #15
    shl v22.4s, v23.4s, #7
    sri v21.4s, v4.4s, #17   // 16, 17, 18<<<15
    sri v22.4s, v23.4s, #25  // 6, 7, 8<<<7
    ldp w15, w20, [x23, #16]
    ldp w19, w21, [x23, #32]
#ifndef HITLS_BIG_ENDIAN
    rev w15, w15
    rev w19, w19
    rev w20, w20
    rev w21, w21
#endif
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v24.16b
    first16 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    first16 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    eor v27.16b, v27.16b, v30.16b
    mov v4.s[3], v4.s[2]  // Due to ext requirements, to fill s[3]
    eor v5.16b, v27.16b, v28.16b

    // 3:22, 23, 24
    ext v25.16b, v2.16b, v3.16b, #4  // 9, 10, 11
    eor v27.16b, v23.16b, v24.16b
    ldp w15, w20, [x23, #24]
    ldp w19, w21, [x23, #40]
#ifndef HITLS_BIG_ENDIAN
    rev w15, w15
    rev w19, w19
    rev w20, w20
    rev w21, w21
#endif
    shl v21.4s, v5.4s, #15
    shl v22.4s, v25.4s, #7
    sri v21.4s, v5.4s, #17   // 19, 20, 21<<<15
    sri v22.4s, v25.4s, #25  // 9, 10, 11<<<7
    first16 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v4.16b
    first16 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    ldp w15, w20, [x23, #32]
    ldp w19, w21, [x23, #48]
#ifndef HITLS_BIG_ENDIAN
    rev w15, w15
    rev w19, w19
    rev w20, w20
    rev w21, w21
#endif
    first16 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    eor v27.16b, v27.16b, v30.16b
    mov v5.s[3], v5.s[2]  // Due to ext requirements, to fill s[3]
    eor v6.16b, v27.16b, v28.16b

    // 4:25, 26, 27
    eor v27.16b, v25.16b, v4.16b
    shl v21.4s, v6.4s, #15
    shl v22.4s, v3.4s, #7
    sri v21.4s, v6.4s, #17  // 22, 23, 24<<<15
    sri v22.4s, v3.4s, #25  // 12, 13, 14<<<7
    first16 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v5.16b
    ldp w15, w20, [x23, #40]
    ldp w19, w21, [x23, #56]
#ifndef HITLS_BIG_ENDIAN
    rev w15, w15
    rev w19, w19
    rev w20, w20
    rev w21, w21
#endif
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    first16 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    eor v27.16b, v27.16b, v29.16b
    first16 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    eor v27.16b, v27.16b, v30.16b
    mov v6.s[3], v6.s[2]  // Due to ext requirements, to fill s[3]
    eor v7.16b, v27.16b, v28.16b

    // 5:28, 29, 30
    ext v23.16b, v3.16b, v4.16b, #12  // 15, 16, 17
    eor v27.16b, v3.16b, v5.16b
    st1 {v4.4s-v7.4s}, [x25]  // There is a redundant data for every four 32-bit bits of the stored data.
                              // The data needs to be read in a skip manner.
    shl v21.4s, v7.4s, #15
    shl v22.4s, v23.4s, #7
    sri v21.4s, v7.4s, #17   // 25, 26, 27<<<15
    sri v22.4s, v23.4s, #25  // 15, 16, 17<<<7
    ldp w15, w20, [x23, #48]
    ldp w19, w21, [x25]
#ifndef HITLS_BIG_ENDIAN
    rev w15, w15
    rev w20, w20
#endif
    first16 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v6.16b
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    first16 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    ldp w15, w20, [x23, #56]
#ifndef HITLS_BIG_ENDIAN
    rev w15, w15
    rev w20, w20
#endif
    add x23, x23, #64
    prfm pldl1keep, [x23, #64]
    ldr w19, [x25, #8]
    ldr w21, [x25, #16]
    eor v27.16b, v27.16b, v30.16b
    first16 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    mov v7.s[3], v7.s[2]  // Due to ext requirements, to fill s[3]
    eor v8.16b, v27.16b, v28.16b

    // Message extension completed. Continue with the next 48 compression.
    ext v24.16b, v4.16b, v5.16b, #12  // 18, 19, 20
    eor v27.16b, v23.16b, v6.16b
    first16 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    shl v21.4s, v8.4s, #15
    shl v22.4s, v24.4s, #7
    sri v21.4s, v8.4s, #17   // 28, 29, 30<<<15
    sri v22.4s, v24.4s, #25  // 18, 19, 20<<<7
    ldp w15, w20, [x25]
    ldp w19, w21, [x25, #20]
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v7.16b
    // w13: constant Tj , 17 <= j <= 63
    mov w13, #0x3d43
    movk w13, #0xcec5, lsl #16
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    eor v27.16b, v27.16b, v30.16b
    mov v8.s[3], v8.s[2]  // Due to ext requirements, to fill s[3]
    eor v9.16b, v27.16b, v28.16b

    // 7:34, 35, 36
    ext v23.16b, v5.16b, v6.16b, #12  // 21, 22, 23
    eor v27.16b, v24.16b, v7.16b
    ldr w15, [x25, #8]
    ldr w20, [x25, #16]
    ldp w19, w21, [x25, #32]
    shl v21.4s, v9.4s, #15
    shl v22.4s, v23.4s, #7
    sri v21.4s, v9.4s, #17   // 31, 32, 33<<<15
    sri v22.4s, v23.4s, #25  // 21, 22, 23<<<7
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v8.16b
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    ldp w15, w20, [x25, #20]
    ldr w19, [x25, #40]
    ldr w21, [x25, #48]
    eor v27.16b, v27.16b, v30.16b
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    mov v9.s[3], v9.s[2]  // Due to ext requirements, to fill s[3]
    eor v10.16b, v27.16b, v28.16b

    // 8:37, 38, 39
    ext v24.16b, v6.16b, v7.16b, #12  // 24, 25, 26
    eor v27.16b, v23.16b, v8.16b
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    shl v21.4s, v10.4s, #15
    shl v22.4s, v24.4s, #7
    sri v21.4s, v10.4s, #17  // 34, 35, 36<<<15
    sri v22.4s, v24.4s, #25  // 24, 25, 26<<<7
    ldp w15, w20, [x25, #32]
    ldp w19, w21, [x25, #52]
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v9.16b
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    eor v27.16b, v27.16b, v30.16b
    mov v10.s[3], v10.s[2]  // Due to ext requirements, to fill s[3]
    eor v11.16b, v27.16b, v28.16b

    // 9:40, 41, 42
    ext v23.16b, v7.16b, v8.16b, #12  // 27, 28, 29
    eor v27.16b, v24.16b, v9.16b
    st1 {v8.4s-v11.4s}, [x26]
    shl v21.4s, v11.4s, #15
    shl v22.4s, v23.4s, #7
    sri v21.4s, v11.4s, #17  // 37, 38, 39<<<15
    sri v22.4s, v23.4s, #25  // 27, 28, 29<<<7
    ldr w15, [x25, #40]
    ldr w20, [x25, #48]
    ldp w19, w21, [x26]
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v10.16b
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    ldp w15, w20, [x25, #52]
    ldr w19, [x26, #8]
    ldr w21, [x26, #16]
    eor v27.16b, v27.16b, v30.16b
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    mov v11.s[3], v11.s[2]  // Due to ext requirements, to fill s[3]
    eor v12.16b, v27.16b, v28.16b

    // 10:43, 44, 45
    ext v24.16b, v8.16b, v9.16b, #12  // 30, 31, 32
    eor v27.16b, v23.16b, v10.16b
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    shl v21.4s, v12.4s, #15
    shl v22.4s, v24.4s, #7
    sri v21.4s, v12.4s, #17  // 40, 41, 42<<<15
    sri v22.4s, v24.4s, #25  // 30, 31, 32<<<7
    ldp w15, w20, [x26]
    ldp w19, w21, [x26, #20]
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v11.16b
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    eor v27.16b, v27.16b, v30.16b
    mov v12.s[3], v12.s[2]  // Due to ext requirements, to fill s[3]
    eor v13.16b, v27.16b, v28.16b

    // 11:46, 47, 48
    ext v23.16b, v9.16b, v10.16b, #12  // 33, 34, 35
    eor v27.16b, v24.16b, v11.16b
    ldr w15, [x26, #8]
    ldr w20, [x26, #16]
    ldp w19, w21, [x26, #32]
    shl v21.4s, v13.4s, #15
    shl v22.4s, v23.4s, #7
    sri v21.4s, v13.4s, #17  // 43, 44, 45<<<15
    sri v22.4s, v23.4s, #25  // 33, 34, 35<<<7
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v12.16b
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    ldp w15, w20, [x26, #20]
    ldr w19, [x26, #40]
    ldr w21, [x26, #48]
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    eor v27.16b, v27.16b, v30.16b
    mov v13.s[3], v13.s[2]  // Due to ext requirements, to fill s[3]
    eor v14.16b, v27.16b, v28.16b

    // 12:49, 50, 51
    ext v24.16b, v10.16b, v11.16b, #12  // 36, 37, 38
    eor v27.16b, v23.16b, v12.16b
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    shl v21.4s, v14.4s, #15
    shl v22.4s, v24.4s, #7
    sri v21.4s, v14.4s, #17  // 46, 47, 48<<<15
    sri v22.4s, v24.4s, #25  // 36, 37, 38<<<7
    ldp w15, w20, [x26, #32]
    ldp w19, w21, [x26, #52]
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v13.16b
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    eor v27.16b, v27.16b, v30.16b
    mov v14.s[3], v14.s[2]  // Due to ext requirements, to fill s[3]
    eor v15.16b, v27.16b, v28.16b

    // 13:52, 53, 54
    ext v23.16b, v11.16b, v12.16b, #12  // 39, 40, 41
    eor v27.16b, v24.16b, v13.16b
    st1 {v12.4s-v15.4s}, [x25]
    shl v21.4s, v15.4s, #15
    shl v22.4s, v23.4s, #7
    sri v21.4s, v15.4s, #17  // 49, 50, 51<<<15
    sri v22.4s, v23.4s, #25  // 39, 40, 41<<<7
    ldr w15, [x26, #40]
    ldr w20, [x26, #48]
    ldp w19, w21, [x25]
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v14.16b
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    ldp w15, w20, [x26, #52]
    ldr w19, [x25, #8]
    ldr w21, [x25, #16]
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    eor v27.16b, v27.16b, v30.16b
    mov v15.s[3], v15.s[2]  // Due to ext requirements, to fill s[3]
    eor v16.16b, v27.16b, v28.16b

    // 14:55, 56, 57
    ext v24.16b, v12.16b, v13.16b, #12  // 42, 43, 44
    eor v27.16b, v23.16b, v14.16b
    shl v21.4s, v16.4s, #15
    shl v22.4s, v24.4s, #7
    sri v21.4s, v16.4s, #17  // 52, 53, 54<<<15
    sri v22.4s, v24.4s, #25  // 42, 43, 44<<<7
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v15.16b
    ldp w15, w20, [x25]
    ldp w19, w21, [x25, #20]
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    eor v27.16b, v27.16b, v30.16b
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    mov v16.s[3], v16.s[2]  // Due to ext requirements, to fill s[3]
    eor v17.16b, v27.16b, v28.16b

    // 15:58, 59, 60
    ext v23.16b, v13.16b, v14.16b, #12  // 45, 46, 47
    eor v27.16b, v24.16b, v15.16b
    shl v21.4s, v17.4s, #15
    shl v22.4s, v23.4s, #7
    sri v21.4s, v17.4s, #17  // 55, 56, 57<<<15
    sri v22.4s, v23.4s, #25  // 45, 46, 47<<<7
    ldr w15, [x25, #8]
    ldr w20, [x25, #16]
    ldp w19, w21, [x25, #32]
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v16.16b
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    ldp w15, w20, [x25, #20]
    ldr w19, [x25, #40]
    ldr w21, [x25, #48]
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    eor v27.16b, v27.16b, v30.16b
    eor v18.16b, v27.16b, v28.16b

    // 16:61, 62, 63
    ext v24.16b, v14.16b, v15.16b, #12  // 48, 49, 50
    eor v27.16b, v23.16b, v16.16b
    shl v21.4s, v18.4s, #15
    shl v22.4s, v24.4s, #7
    sri v21.4s, v18.4s, #17  // 58, 59, 60<<<15
    sri v22.4s, v24.4s, #25  // 48, 49, 50<<<7
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v17.16b
    ldp w15, w20, [x25, #32]
    ldp w19, w21, [x25, #52]
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    eor v27.16b, v27.16b, v30.16b
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    eor v19.16b, v27.16b, v28.16b

    // 17:64, 65, 66
    ext v23.16b, v15.16b, v16.16b, #12  // 51, 52, 53
    eor v27.16b, v24.16b, v17.16b
    st1 {v16.4s-v19.4s}, [x26]
    shl v21.4s, v19.4s, #15
    shl v22.4s, v23.4s, #7
    sri v21.4s, v19.4s, #17  // 61, 62, 63<<<15
    sri v22.4s, v23.4s, #25  // 51, 52, 53<<<7
    ldr w15, [x25, #40]
    ldr w20, [x25, #48]
    ldp w19, w21, [x26]
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v18.16b
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    ldp w15, w20, [x25, #52]
    ldr w19, [x26, #8]
    ldr w21, [x26, #16]
    eor v27.16b, v27.16b, v30.16b
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    eor v20.16b, v27.16b, v28.16b

    // 18:67
    ext v24.16b, v16.16b, v17.16b, #12  // 54, 55, 56
    eor v27.16b, v23.16b, v18.16b
    shl v21.4s, v20.4s, #15
    shl v22.4s, v24.4s, #7
    sri v21.4s, v20.4s, #17  // 64, 65, 66<<<15
    sri v22.4s, v24.4s, #25  // 54, 55, 56<<<7
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    eor v27.16b, v21.16b, v27.16b
    eor v28.16b, v22.16b, v19.16b
    ldp w15, w20, [x26]
    ldp w19, w21, [x26, #20]
    shl v29.4s, v27.4s, #15
    shl v30.4s, v27.4s, #23
    sri v29.4s, v27.4s, #17
    sri v30.4s, v27.4s, #9
    eor v27.16b, v27.16b, v29.16b
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    eor v27.16b, v27.16b, v30.16b
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    eor v21.16b, v27.16b, v28.16b

    ldr w15, [x26, #8]
    ldr w20, [x26, #16]
    ldp w19, w21, [x26, #32]
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    st1 {v20.4s-v21.4s}, [x25]
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    ldp w15, w20, [x26, #20]
    ldr w19, [x26, #40]
    ldr w21, [x26, #48]
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19

    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    ldp w15, w20, [x26, #32]
    ldp w19, w21, [x26, #52]
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    ldr w15, [x26, #40]
    ldr w20, [x26, #48]
    ldp w19, w21, [x25]
    second48 w0 w1 w2 w3 w4 w5 w6 w7 w15 w19
    second48 w3 w0 w1 w2 w7 w4 w5 w6 w20 w21
    ldp w15, w20, [x26, #52]
    ldr w19, [x25, #8]
    ldr w21, [x25, #16]
    second48 w2 w3 w0 w1 w6 w7 w4 w5 w15 w19
    second48 w1 w2 w3 w0 w5 w6 w7 w4 w20 w21
    ldp w9, w10, [x22]  // XOR with the previous hash result
    ldp w11, w12, [x22, #8]
    ldp w13, w14, [x22, #16]
    ldp w15, w19, [x22, #24]
    eor w0, w0, w9
    eor w1, w1, w10
    eor w2, w2, w11
    eor w3, w3, w12
    eor w4, w4, w13
    eor w5, w5, w14
    eor w6, w6, w15
    eor w7, w7, w19
    stp w0, w1, [x22]  // Result saving
    stp w2, w3, [x22, #8]
    stp w4, w5, [x22, #16]
    stp w6, w7, [x22, #24]
    b blocksloop_1
    end:

    add sp, sp, 128

    ldp x19, x20, [sp]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp d8, d9, [sp, #64]
    ldp d10, d11, [sp, #80]
    ldp d12, d13, [sp, #96]
    ldp d14, d15, [sp, #112]
    add sp, sp, 128

AARCH64_AUTIASP
    ret
.size SM3_CompressAsm,.-SM3_CompressAsm

#endif
