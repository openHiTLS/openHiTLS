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
#ifdef HITLS_CRYPTO_GCM

#include "crypt_arm.h"

.arch    armv8-a+crypto
.text

INPUT_H  .req x0
OUT_TB   .req x1
MULL_C2  .req v31
MULL_H   .req v24
OUT_H0   .req v25
OUT_H1_2 .req v26
OUT_H2   .req v27
OUT_H3   .req v28
OUT_H3_4 .req v29
OUT_H4   .req v30
INPUT_X  .req v0
OUT_X    .req v23

.macro GEN_H
    ext v1.16b, MULL_H.16b, MULL_H.16b, #8      //
    ushr v2.2d, MULL_C2.2d, #63
    dup MULL_H.4s, MULL_H.s[1]
    ext v3.16b, v2.16b, MULL_C2.16b, #8         // t0 = 0xc2....01

    ushr v2.2d, v1.2d, #63
    sshr MULL_H.4s, MULL_H.4s, #31              // broadcast carry bit
    and v2.16b, v2.16b, v3.16b
    shl v1.2d, v1.2d, #1

    ext v2.16b, v2.16b, v2.16b, #8

    and v3.16b, v3.16b, MULL_H.16b
    orr v1.16b, v1.16b, v2.16b                  // H<<<=1
    eor OUT_H0.16b, v1.16b, v3.16b              // twisted H
    st1 {OUT_H0.2d}, [OUT_TB], #16              // store H0
.endm

.macro GEN_H2
    //(ah + al) * (ah + al) = ah * ah + 2 * ah * al + al * al
    ext v10.16b, OUT_H0.16b, OUT_H0.16b, #8     // A
    pmull v12.1q, OUT_H0.1d, OUT_H0.1d          // aL * aL
    eor v10.16b, v10.16b, OUT_H0.16b            // A + h
    pmull2 v11.1q, OUT_H0.2d, OUT_H0.2d         // ah * ah
    pmull v13.1q, v10.1d, v10.1d                // (A + h) * (A + h)

    ext v14.16b, v12.16b, v11.16b, #8           // B
    eor v15.16b, v12.16b, v11.16b               // aL * aL +  ah * ah
    eor v13.16b, v13.16b, v14.16b               // ah * al + B
    eor v13.16b, v13.16b, v15.16b               //
    pmull v15.1q, v12.1d, MULL_C2.1d            // 1st phase

    ins v11.d[0], v13.d[1]
    ins v13.d[1], v12.d[0]
    eor v12.16b, v13.16b, v15.16b

    ext v15.16b, v12.16b, v12.16b, #8
    pmull v12.1q, v12.1d, MULL_C2.1d
    eor v15.16b, v15.16b, v11.16b
    eor OUT_H2.16b, v12.16b, v15.16b                    // H^2

    ext v16.16b, OUT_H2.16b, OUT_H2.16b, #8
    eor v16.16b, v16.16b, OUT_H2.16b
    ext OUT_H1_2.16b, v10.16b, v16.16b, #8
    st1 {OUT_H1_2.2d, OUT_H2.2d}, [OUT_TB], #32         // store H^2h H^2
.endm

.macro GEN_H3_4
    //calculate H^3 and H^4
    pmull v0.1q, OUT_H0.1d, OUT_H2.1d
    pmull v1.1q, OUT_H2.1d, OUT_H2.1d
    pmull2 v2.1q, OUT_H0.2d, OUT_H2.2d
    pmull2 v3.1q, OUT_H2.2d, OUT_H2.2d
    pmull v4.1q, v10.1d, v16.1d
    pmull v5.1q, v16.1d, v16.1d

    ext v6.16b, v0.16b, v2.16b, #8                      // Karatsuba post-processing
    ext v7.16b, v1.16b, v3.16b, #8
    eor v8.16b, v0.16b, v2.16b

    eor v4.16b, v4.16b, v6.16b
    eor v9.16b, v1.16b, v3.16b
    eor v5.16b, v5.16b, v7.16b
    eor v4.16b, v4.16b, v8.16b

    pmull v8.1q, v0.1d, MULL_C2.1d                      // 1st phase
    eor v5.16b, v5.16b, v9.16b
    pmull v9.1q, v1.1d, MULL_C2.1d

    ins v2.d[0], v4.d[1]
    ins v3.d[0], v5.d[1]
    ins v4.d[1], v0.d[0]
    ins v5.d[1], v1.d[0]

    eor v0.16b, v4.16b, v8.16b
    eor v1.16b, v5.16b, v9.16b

    ext v8.16b, v0.16b, v0.16b,#8                       // 2nd phase
    ext v9.16b, v1.16b, v1.16b,#8

    pmull v0.1q, v0.1d, MULL_C2.1d
    pmull v1.1q, v1.1d, MULL_C2.1d

    eor v8.16b, v8.16b, v2.16b
    eor v9.16b, v9.16b, v3.16b
    eor OUT_H3.16b, v0.16b, v8.16b                      // H^3
    eor OUT_H4.16b, v1.16b, v9.16b                      // H^4

    ext v20.16b, OUT_H3.16b, OUT_H3.16b, #8             // Karatsuba pre-processing
    ext v21.16b, OUT_H4.16b, OUT_H4.16b, #8
    eor v20.16b, v20.16b, OUT_H3.16b
    eor v21.16b, v21.16b, OUT_H4.16b
    ext OUT_H3_4.16b, v20.16b, v21.16b, #8              // h
    st1 {OUT_H3.2d, OUT_H3_4.2d, OUT_H4.2d}, [OUT_TB]    // store h^3 h^3+h^4 h^4
.endm

.globl GcmTableGen4bit
.type GcmTableGen4bit, %function
.align 4
GcmTableGen4bit:
AARCH64_PACIASP
    stp x29, x30, [sp, #-0x50]!
    add x29, sp, #0
    stp d8, d9, [sp, #0x10]
    stp d10, d11, [sp, #0x20]
    stp d12, d13, [sp, #0x30]
    stp d14, d15, [sp, #0x40]

    movi MULL_C2.16b, #0xe1                     // set 0xc2
    ld1 {MULL_H.16b}, [INPUT_H]                 // load input H
    shl MULL_C2.2d, MULL_C2.2d, #57             // 0xc20000000000000
    rev64 MULL_H.16b, MULL_H.16b
    GEN_H
    GEN_H2
    GEN_H3_4
    ldp d8, d9, [sp, #0x10]
    ldp d10, d11, [sp, #0x20]
    ldp d12, d13, [sp, #0x30]
    ldp d14, d15, [sp, #0x40]
    ldp x29, x30, [sp], #0x50
AARCH64_AUTIASP
    ret
.size GcmTableGen4bit,.-GcmTableGen4bit

// Karatsuba post-processing for 128x128->256 carry-less multiply.
.macro GHASH_KARATSUBA_POST XL, XH, XM, TMP0, TMP1
    ext \TMP0\().16b, \XL\().16b, \XH\().16b, #8
    eor \TMP1\().16b, \XL\().16b, \XH\().16b
    eor \XM\().16b, \XM\().16b, \TMP0\().16b
    eor \XM\().16b, \XM\().16b, \TMP1\().16b
.endm

// Multiply one block by H.
.macro GHASH_MUL_H XL, XH, XM, IN, TMP0, TMP1
    ext \TMP0\().16b, \IN\().16b, \IN\().16b, #8
    pmull \XL\().1q, OUT_H0.1d, \TMP0\().1d
    eor \TMP1\().16b, \IN\().16b, \TMP0\().16b
    pmull2 \XH\().1q, OUT_H0.2d, \TMP0\().2d
    pmull \XM\().1q, OUT_H1_2.1d, \TMP1\().1d
    GHASH_KARATSUBA_POST \XL, \XH, \XM, \TMP0, \TMP1
.endm

// Multiply one block by H^2.
.macro GHASH_MUL_H2 XL, XH, XM, IN, TMP0, TMP1
    ext \TMP0\().16b, \IN\().16b, \IN\().16b, #8
    pmull \XL\().1q, OUT_H2.1d, \TMP0\().1d
    eor \TMP1\().16b, \IN\().16b, \TMP0\().16b
    pmull2 \XH\().1q, OUT_H2.2d, \TMP0\().2d
    pmull2 \XM\().1q, OUT_H1_2.2d, \TMP1\().2d
    GHASH_KARATSUBA_POST \XL, \XH, \XM, \TMP0, \TMP1
.endm

// Multiply one block by H^3.
.macro GHASH_MUL_H3 XL, XH, XM, IN, TMP0, TMP1
    ext \TMP0\().16b, \IN\().16b, \IN\().16b, #8
    pmull \XL\().1q, OUT_H3.1d, \TMP0\().1d
    eor \TMP1\().16b, \IN\().16b, \TMP0\().16b
    pmull2 \XH\().1q, OUT_H3.2d, \TMP0\().2d
    pmull \XM\().1q, OUT_H3_4.1d, \TMP1\().1d
    GHASH_KARATSUBA_POST \XL, \XH, \XM, \TMP0, \TMP1
.endm

// Multiply one block by H^4.
.macro GHASH_MUL_H4 XL, XH, XM, IN, TMP0, TMP1
    ext \TMP0\().16b, \IN\().16b, \IN\().16b, #8
    pmull \XL\().1q, OUT_H4.1d, \TMP0\().1d
    eor \TMP1\().16b, \IN\().16b, \TMP0\().16b
    pmull2 \XH\().1q, OUT_H4.2d, \TMP0\().2d
    pmull2 \XM\().1q, OUT_H3_4.2d, \TMP1\().2d
    GHASH_KARATSUBA_POST \XL, \XH, \XM, \TMP0, \TMP1
.endm

// Reduce 256-bit product (XL | XM | XH) to GF(2^128).
.macro GHASH_REDUCE XL, XH, XM, TMP0
    pmull \TMP0\().1q, \XL\().1d, MULL_C2.1d                  // reduction phase 1
    ins \XH\().d[0], \XM\().d[1]
    ins \XM\().d[1], \XL\().d[0]
    eor \XL\().16b, \XM\().16b, \TMP0\().16b

    ext \TMP0\().16b, \XL\().16b, \XL\().16b, #8                 // reduction phase 2
    pmull \XL\().1q, \XL\().1d, MULL_C2.1d
    eor \TMP0\().16b, \TMP0\().16b, \XH\().16b
    eor \XL\().16b, \XL\().16b, \TMP0\().16b
.endm

// void GcmHashMultiBlock(uint8_t t[GCM_BLOCKSIZE], const MODES_GCM_GF128 hTable[16], const uint8_t *in, uint32_t inLen)
.globl GcmHashMultiBlock
.type  GcmHashMultiBlock, %function
.align 4
GcmHashMultiBlock:
AARCH64_PACIASP
    and w3, w3, #0xfffffff0                    // process full blocks only
    ld1 {INPUT_X.16b}, [INPUT_H]                // load Xi
    movi MULL_C2.16b, #0xe1                     // set 0xc2
    // hTable layout:
    //  +0x00: H
    //  +0x10: [H^2.h+H^2.l | H.h+H.l]
    //  +0x20: H^2
    //  +0x30: H^3
    //  +0x40: [H^4.h+H^4.l | H^3.h+H^3.l]
    //  +0x50: H^4
    ld1 {OUT_H0.2d, OUT_H1_2.2d, OUT_H2.2d}, [OUT_TB], #48
    ld1 {OUT_H3.2d, OUT_H3_4.2d, OUT_H4.2d}, [OUT_TB]
    shl MULL_C2.2d, MULL_C2.2d, #57             // 0xc20000000000000
    cmp x3, #64
    b.lo .LGHashTry2x

.align 4
.LGHashLoop4x:
    // 4x aggregated GHASH:
    // X(i+4) = (Xi xor I0) * H^4 xor I1 * H^3 xor I2 * H^2 xor I3 * H
    ld1 {v1.16b, v2.16b, v3.16b, v4.16b}, [x2], #64
    eor v1.16b, v1.16b, INPUT_X.16b
    rev64 v1.16b, v1.16b
    rev64 v2.16b, v2.16b
    rev64 v3.16b, v3.16b
    rev64 v4.16b, v4.16b

    // Current round carry-over: H^4 * (Xi xor I0)
    GHASH_MUL_H4 v5, v6, v7, v1, v19, v20

    // Accumulate the remaining terms of this 4-block batch: I1*H^3, I2*H^2, I3*H.
    GHASH_MUL_H3 v16, v17, v18, v2, v19, v20
    eor v5.16b, v5.16b, v16.16b
    eor v6.16b, v6.16b, v17.16b
    eor v7.16b, v7.16b, v18.16b

    GHASH_MUL_H2 v16, v17, v18, v3, v19, v20
    eor v5.16b, v5.16b, v16.16b
    eor v6.16b, v6.16b, v17.16b
    eor v7.16b, v7.16b, v18.16b

    GHASH_MUL_H v16, v17, v18, v4, v19, v20
    eor v5.16b, v5.16b, v16.16b
    eor v6.16b, v6.16b, v17.16b
    eor v7.16b, v7.16b, v18.16b

    GHASH_REDUCE v5, v6, v7, v21
    rev64 v5.16b, v5.16b
    ext v5.16b, v5.16b, v5.16b, #8
    mov INPUT_X.16b, v5.16b

    sub x3, x3, #64
    cmp x3, #64
    b.hs .LGHashLoop4x

.LGHashTry2x:
    cmp x3, #32
    b.lo .LGHashTail1x

.align 4
.LGHashLoop2x:
    // 2x aggregated GHASH:
    // X(i+2) = (Xi xor I0) * H^2 xor I1 * H
    ld1 {v1.16b, v2.16b}, [x2], #32
    eor v1.16b, v1.16b, INPUT_X.16b
    rev64 v1.16b, v1.16b
    rev64 v2.16b, v2.16b

    GHASH_MUL_H2 v5, v6, v7, v1, v19, v20
    GHASH_MUL_H v16, v17, v18, v2, v19, v20
    eor v5.16b, v5.16b, v16.16b
    eor v6.16b, v6.16b, v17.16b
    eor v7.16b, v7.16b, v18.16b

    GHASH_REDUCE v5, v6, v7, v21
    rev64 v5.16b, v5.16b
    ext v5.16b, v5.16b, v5.16b, #8
    mov INPUT_X.16b, v5.16b

    sub x3, x3, #32
    cmp x3, #32
    b.hs .LGHashLoop2x

.LGHashTail1x:
    cbz x3, .LGHashStoreXi

.align 4
.LGHashLoop1x:
    // 1x tail path.
    ld1 {v1.16b}, [x2], #16
    eor v1.16b, v1.16b, INPUT_X.16b
    rev64 v1.16b, v1.16b

    GHASH_MUL_H v5, v6, v7, v1, v19, v20
    GHASH_REDUCE v5, v6, v7, v21
    rev64 v5.16b, v5.16b
    ext v5.16b, v5.16b, v5.16b, #8
    mov INPUT_X.16b, v5.16b

    subs x3, x3, #16
    b.ne .LGHashLoop1x

.LGHashStoreXi:
    st1 {INPUT_X.16b}, [INPUT_H]                       // write out Xi
.LhashEnd:
AARCH64_AUTIASP
    ret
.size GcmHashMultiBlock,.-GcmHashMultiBlock

#endif
