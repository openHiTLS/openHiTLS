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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_GCM)

.text
INPUT  .req x1
OUT00  .req x2
INLEN  .req x3
KEY00  .req x4
IVCTR  .req w4
HTABLE .req x5
IVEC0  .req x0
ROUNDS .req w8
COUNT  .req x15
COUNTW .req w15
IV_H   .req x10     // high 64 bits
IV_L   .req x11     // lower 64 bits
IV_C   .req x12
IV_W   .req w12
IV_CW  .req w9
IV_CX  .req x9
CTR0  .req v0
CTR1  .req v1
CTR2  .req v2
CTR3  .req v3
OUT0  .req v4
OUT1  .req v5
OUT2  .req v6
OUT3  .req v7
KEY0  .req v18
KEY1  .req v19
KEY2  .req v20
KEY3  .req v21
KEY4  .req v22
KEY5  .req v23
KEY6  .req v24
KEY7  .req v25
KEY8  .req v26
KEY9  .req v27
KEY10 .req v28
KEY11 .req v29
KEY12 .req v30
KEY13 .req v31
KEND0 .req x13
KEND1 .req x14
HASH0 .req v11
HASH1 .req v12
HASH2 .req v13
HASH3 .req v14
HASH4 .req v15
MULL_C2 .req v13
HASH1_2 .req v12

.macro IN_STP
    stp x19, x20, [sp, #-112]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp d8, d9, [sp, #48]
    stp d10, d11, [sp, #64]
    stp d12, d13, [sp, #80]
    stp d14, d15, [sp, #96]
.endm

.macro OUT_STP
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp d8, d9, [sp, #48]
    ldp d10, d11, [sp, #64]
    ldp d12, d13, [sp, #80]
    ldp d14, d15, [sp, #96]
    ldp x19, x20, [sp], #112
.endm

.macro REV_2S REG0, REG1
    rev \REG0, \REG0
    rev \REG1, \REG1
.endm

.macro LOAD_KEY
    ld1 {KEY0.4s, KEY1.4s}, [KEY00], #32                          // load key-0-1
    ld1 {KEY2.4s, KEY3.4s}, [KEY00], #32                          // load key-2-3
    ld1 {KEY4.4s, KEY5.4s}, [KEY00], #32                          // load key-4-5
    ld1 {KEY6.4s, KEY7.4s}, [KEY00], #32                          // load key-6-7
    ld1 {KEY8.4s, KEY9.4s}, [KEY00], #32                          // load key-8-9
.endm

.macro LOAD_GHASH_TABLE
    ld1 {HASH0.16b}, [HTABLE], #16                                // load ghash
    ld1 {HASH1.2d}, [HTABLE], #16                                 // load h^1
    add HTABLE, HTABLE, #16
    ld1 {HASH2.2d}, [HTABLE], #16                                 // load h^2
    ld1 {HASH3.2d}, [HTABLE], #16                                 // load h^3
    add HTABLE, HTABLE, #16
    ld1 {HASH4.2d}, [HTABLE]                                      // load h^4
.endm

.macro ROUND4 BLOCK0, BLOCK1, BLOCK2, BLOCK3, KEY
    aese \BLOCK0, \KEY
    aesmc \BLOCK0, \BLOCK0
    aese \BLOCK1, \KEY
    aesmc \BLOCK1, \BLOCK1
    aese \BLOCK2, \KEY
    aesmc \BLOCK2, \BLOCK2
    aese \BLOCK3, \KEY
    aesmc \BLOCK3, \BLOCK3
.endm

.macro ROUND4_END BLOCK0, BLOCK1, BLOCK2, BLOCK3, KEY
    aese \BLOCK0, \KEY
    aese \BLOCK1, \KEY
    aese \BLOCK2, \KEY
    aese \BLOCK3, \KEY
.endm

.macro ROUND BLOCK, KEY
    aese \BLOCK, \KEY
    aesmc \BLOCK, \BLOCK
.endm

.macro LOAD_CTR DI, VI
    rev IV_CW, IV_W
    fmov \DI, IV_H                          // set h64
    orr IV_CX, IV_L, IV_CX, lsl #32
    add IV_W, IV_W, #1                      // CTR++
    fmov \VI, IV_CX                         // set l64
.endm

.macro BEFORE_ROUND
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8                         // xi
    ext HASH1.16b, HASH1.16b, HASH1.16b, #8                         // h^1
    rev IV_W, IV_W                                               // rev_ctr32
    ext HASH2.16b, HASH2.16b, HASH2.16b, #8                         // h^2
    ext HASH3.16b, HASH3.16b, HASH3.16b, #8                         // h^3
    add IVCTR, IV_W, IVCTR
    ext HASH4.16b, HASH4.16b, HASH4.16b, #8                         // h^4
    add IV_W, IV_W, #1                                              // ctr++
    rev64 HASH0.16b, HASH0.16b                                      //
    orr w11, w11, w11                                               //
    trn2 v17.2d, HASH3.2d, HASH4.2d                                 // h4l | h3l
    LOAD_CTR d1, CTR1.d[1]                                          // CTR bolck 1
    trn1 v9.2d, HASH3.2d, HASH4.2d                                  // h4h | h3h
    LOAD_CTR d2, CTR2.d[1]                                          // CTR bolck 2
    trn2 v16.2d, HASH1.2d, HASH2.2d                                 // h2l | h1l
    LOAD_CTR d3, CTR3.d[1]                                          // CTR bolck 3
    trn1 v8.2d, HASH1.2d, HASH2.2d                                  // h2h | h1h
.endm

.macro FIRST_ROUND
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY0.16b         // round 0
    ldp x6, x7, [INPUT, #0]                                         // load INPUT 0
#ifdef HITLS_BIG_ENDIAN
    REV_2S x6, x7
#endif
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY1.16b         // round 1
    ldp x19, x20, [INPUT, #16]                                      // AES[1] - load plaintext
#ifdef HITLS_BIG_ENDIAN
    REV_2S x19, x20
#endif
    eor x6, x6, KEND0                                               // round 10 low
    eor x7, x7, KEND1                                               // round 10 high
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY2.16b         // round 2
    ldp x21, x22, [INPUT, #32]                                      // AES[2] - load plaintext
#ifdef HITLS_BIG_ENDIAN
    REV_2S x21, x22
#endif
    eor x19, x19, KEND0                                             // AES[1] - round 10 low
    eor x20, x20, KEND1                                             // AES[1] - round 10 high
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY3.16b         // round 3
    ldp x23, x24, [INPUT, #48]                                      // AES[3] - load plaintext
#ifdef HITLS_BIG_ENDIAN
    REV_2S x23, x24
#endif
    eor x21, x21, KEND0                                             // AES[2] - round 10 low
    eor x22, x22, KEND1                                             // AES[2] - round 10 high
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY4.16b         // round 4
    eor x23, x23, KEND0                                             // AES[3] - round 10 low
    eor x24, x24, KEND1                                             // AES[3] - round 10 high
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY5.16b         // round 5
    fmov d4, x6                                                     // INPUT 0 - mov low
    fmov d5, x19                                                    // AES[1] - mov low
    fmov d6, x21                                                    // AES[2] - mov low
    fmov d7, x23                                                    // AES[3] - mov low
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY6.16b         // round 6
    fmov OUT0.d[1], x7                                              // AES[0] - mov high
    fmov OUT1.d[1], x20                                             // AES[1] - mov high
    fmov OUT2.d[1], x22                                             // AES[2] - mov high
    fmov OUT3.d[1], x24                                             // AES[3] - mov high
.endm

.macro STORE_RESULT
    add INPUT, INPUT, #64                                           // AES input_ptr update
    eor OUT0.16b, OUT0.16b, CTR0.16b                                // AES[0] - result
    eor OUT1.16b, OUT1.16b, CTR1.16b                                // AES[1] - result
    eor OUT2.16b, OUT2.16b, CTR2.16b                                // AES[2] - result
    fmov d0, x10                                                    // CTR[0]
    eor OUT3.16b, OUT3.16b, CTR3.16b                                // AES[3] - result
    subs COUNT, COUNT, #1                                           // count--
    fmov CTR0.d[1], x9                                              // CTR[0]--OK
    rev w9, IV_W                                                    // CTR[1]--Start
    st1 {OUT0.16b}, [OUT00], #16                                    // AES[0] - store result
    orr x9, x11, x9, lsl #32                                        // CTR[1]
    st1 {OUT1.16b}, [OUT00], #16                                    // AES[1] - store result
    add IV_W, IV_W, #1                                              // CTR++
    fmov d1, x10                                                    // CTR[1]
    st1 {OUT2.16b}, [OUT00], #16                                    // AES[2] - store result
    fmov v1.d[1], x9                                                // CTR[1]--OK
    rev w9, IV_W                                                    // CTR[2]--Start
    st1 {OUT3.16b}, [OUT00], #16                                    // AES[3] - store result
    orr x9, x11, x9, lsl #32                                        // CTR[2]
    add IV_W, IV_W, #1                                              // CTR++
    fmov d2, x10                                                    // CTR2-0
    fmov v2.d[1], x9                                                // CTR[2]--OK
    rev w9, IV_W                                                    // CTR[3]--Start
    orr x9, x11, x9, lsl #32                                        // CTR[3]                                                 // <= 0
.endm

.macro STORE_DEC_RESULT
    ld1 {OUT0.16b}, [INPUT], #16
    ld1 {OUT1.16b}, [INPUT], #16
    ld1 {OUT2.16b}, [INPUT], #16
    eor CTR0.16b, CTR0.16b, OUT0.16b
    ld1 {OUT3.16b}, [INPUT], #16
    eor CTR1.16b, CTR1.16b, OUT1.16b
    eor CTR2.16b, CTR2.16b, OUT2.16b
    mov	x6, CTR0.d[0]
    mov	x7, CTR0.d[1]
    mov	x19, CTR1.d[0]
    mov	x20, CTR1.d[1]
#ifdef HITLS_BIG_ENDIAN
    REV_2S x6, x7
    REV_2S x19, x20
#endif
    rev w9, IV_W                         // CTR[0]
    eor x6, x6, KEND0
    orr x9, x11, x9, lsl #32            // CTR[0]
    eor x7, x7, KEND1
    add IV_W, IV_W, #1                    // CTR++
    fmov d0, x10                        // CTR[0]
    eor x19, x19, KEND0
    fmov CTR0.d[1], x9                    // CTR[0]--OK
    rev w9, IV_W                         // CTR[1]
    eor x20, x20, KEND1
    orr x9, x11, x9, lsl #32            // CTR[1]
    subs COUNT, COUNT, #1                                           // count--
    add IV_W, IV_W, #1                    // CTR++
    fmov d1, x10                        // CTR[1]
    stp x6, x7, [OUT00], #16
    fmov v1.d[1], x9                    // CTR[1]--OK
    stp x19, x20, [OUT00], #16
    rev w9, IV_W                         // CTR[2]
    rev64 OUT0.16b, OUT0.16b
    add IV_W, IV_W, #1                    // CTR++
    rev64 OUT1.16b, OUT1.16b
    orr x9, x11, x9, lsl #32            // CTR[2]
.endm

.macro GHASH_BLOCK
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8                         // PRE 0
    mov d30, OUT1.d[1]                                              // GHASH block 4k+1 - mid
    mov d31, OUT2.d[1]                                              // GHASH[2] - mid
    eor OUT0.16b, OUT0.16b, HASH0.16b                               // PRE 1 tag ^ out
    pmull2 v28.1q, OUT1.2d, HASH3.2d                                // GHASH block 4k+1 - high
    eor v30.8b, v30.8b, OUT1.8b                                     // GHASH block 4k+1 - mid
    eor v31.8b, v31.8b, OUT2.8b                                     // GHASH[2] - mid
    mov d8, OUT0.d[1]                                               // GHASH block 4k - mid
    mov d10, v17.d[1]                                               // GHASH block 4k - mid
    pmull2 v9.1q, OUT0.2d, HASH4.2d                                 // GHASH block 4k - high
    pmull HASH0.1q, OUT0.1d, HASH4.1d                               // GHASH block 4k - low
    eor v8.8b, v8.8b, OUT0.8b                                       // GHASH block 4k - mid
    eor v9.16b, v9.16b, v28.16b                                     // GHASH block 4k+1 - high
    pmull v29.1q, OUT1.1d, HASH3.1d                                 // GHASH block 4k+1 - low
    pmull v28.1q, OUT2.1d, HASH2.1d                                 // GHASH[2] - low
    pmull v10.1q, v8.1d, v10.1d                                     // GHASH block 4k - mid
    pmull v30.1q, v30.1d, v17.1d                                    // GHASH block 4k+1 - mid
    ins v31.d[1], v31.d[0]                                          // GHASH[2] - mid
    pmull2 v8.1q, OUT2.2d, HASH2.2d                                 // GHASH[2] - high
    eor v10.16b, v10.16b, v30.16b                                   // GHASH block 4k+1 - mid
    mov d30, OUT3.d[1]                                              // GHASH[0] - mid
    eor HASH0.16b, HASH0.16b, v29.16b                               // GHASH block 4k+1 - low
    eor v30.8b, v30.8b, OUT3.8b                                     // GHASH[0] - mid
    pmull2 OUT0.1q, OUT3.2d, HASH1.2d                               // GHASH[0] - high
    eor v9.16b, v9.16b, v8.16b                                      // GHASH[2] - high
    pmull2 v31.1q, v31.2d, v16.2d                                   // GHASH[2] - mid
    pmull v29.1q, OUT3.1d, HASH1.1d                                 // GHASH[0] - low
    movi v8.8b, #0xc2
    pmull v30.1q, v30.1d, v16.1d                                    // GHASH[0] - mid
    eor HASH0.16b, HASH0.16b, v28.16b                               // GHASH[2] - low
    shl d8, d8, #56                                                 // mod_constant
    eor v9.16b, v9.16b, OUT0.16b                                    // GHASH[0] - high
    eor v10.16b, v10.16b, v31.16b                                   // GHASH[2] - mid
    pmull v31.1q, v9.1d, v8.1d                                      // MODULO - top 64b align with mid
    eor HASH0.16b, HASH0.16b, v29.16b                               // GHASH[0] - low
    eor v10.16b, v10.16b, v30.16b                                   // GHASH[0] - mid
    eor v30.16b, HASH0.16b, v9.16b                                  // MODULO - karatsuba tidy up
    ext v9.16b, v9.16b, v9.16b, #8                                  // MODULO - other top alignment
    eor v10.16b, v10.16b, v30.16b                                   // MODULO - karatsuba tidy up
    eor v10.16b, v10.16b, v31.16b                                   // MODULO - fold into mid
    eor v10.16b, v10.16b, v9.16b                                    // MODULO - fold into mid
    pmull v9.1q, v10.1d, v8.1d                                      // MODULO - mid 64b align with low
    ext v10.16b, v10.16b, v10.16b, #8                               // MODULO - other mid alignment
    eor HASH0.16b, HASH0.16b, v9.16b                                // MODULO - fold into low
    eor HASH0.16b, HASH0.16b, v10.16b                               // MODULO - fold into low
.endm

.macro GHASH_DEC_BLOCK
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8 // PRE 0
    mov x21, v2.d[0]                        // AES[2] block - mov low
    mov x22, v2.d[1]                        // AES[2] block - mov high
    rev64 v6.16b, v6.16b                    // GHASH[2]
#ifdef HITLS_BIG_ENDIAN
    REV_2S x21, x22
#endif
    eor v4.16b, v4.16b, HASH0.16b           // PRE 1
    eor CTR3.16b, OUT3.16b, CTR3.16b        // AES[3] block - result
    eor x21, x21, KEND0                     // AES[2] - round 14 low
    eor x22, x22, KEND1                     // AES[2] - round 14 high
    pmull2 v9.1q, v4.2d, HASH4.2d           // GHASH block 4k - high
    mov d8, v4.d[1]                         // GHASH block 4k - mid
    mov d10, v17.d[1]                       // GHASH block 4k - mid
    mov x24, CTR3.d[1]                      // AES[3] block - mov high
    pmull HASH0.1q, v4.1d, HASH4.1d         // GHASH block 4k - low
    eor v8.8b, v8.8b, v4.8b                 // GHASH block 4k - mid
    pmull2 v4.1q, v5.2d, HASH3.2d           // GHASH block 4k+1 - high
    mov x23, CTR3.d[0]                      // AES[3] block - mov low
    rev64 v7.16b, v7.16b                    // GHASH[0]
#ifdef HITLS_BIG_ENDIAN
    REV_2S x24, x23
#endif
    pmull v10.1q, v8.1d, v10.1d             // GHASH block 4k - mid
    eor x23, x23, KEND0                     // AES[3] block - round 14 low
    pmull v8.1q, v5.1d, HASH3.1d            // GHASH block 4k+1 - low
    eor x24, x24, KEND1                     // AES[3] block - round 14 high
    eor v9.16b, v9.16b, v4.16b              // GHASH block 4k+1 - high
    mov d4, v5.d[1]                         // GHASH block 4k+1 - mid
    eor HASH0.16b, HASH0.16b, v8.16b        // GHASH block 4k+1 - low
    mov d8, v6.d[1]                         // GHASH[2] - mid
    eor v4.8b, v4.8b, v5.8b                 // GHASH block 4k+1 - mid
    pmull v5.1q, v6.1d, HASH2.1d            // GHASH[2] - low
    eor v8.8b, v8.8b, v6.8b                 // GHASH[2] - mid
    eor HASH0.16b, HASH0.16b, v5.16b        // GHASH[2] - low
    pmull v4.1q, v4.1d, v17.1d              // GHASH block 4k+1 - mid
    ins v8.d[1], v8.d[0]                    // GHASH[2] - mid
    eor v10.16b, v10.16b, v4.16b            // GHASH block 4k+1 - mid
    pmull2 v4.1q, v6.2d, HASH2.2d           // GHASH[2] - high
    mov d6, v7.d[1]                         // GHASH[0] - mid
    pmull2 v8.1q, v8.2d, v16.2d             // GHASH[2] - mid
    eor v9.16b, v9.16b, v4.16b              // GHASH[2] - high
    pmull v4.1q, v7.1d, HASH1.1d            // GHASH[0] - low
    eor v10.16b, v10.16b, v8.16b            // GHASH[2] - mid
    pmull2 v5.1q, v7.2d, HASH1.2d           // GHASH[0] - high
    eor v6.8b, v6.8b, v7.8b                 // GHASH[0] - mid
    eor v9.16b, v9.16b, v5.16b              // GHASH[0] - high
    pmull v6.1q, v6.1d, v16.1d              // GHASH[0] - mid
    movi v8.8b, #0xc2
    eor HASH0.16b, HASH0.16b, v4.16b        // GHASH[0] - low
    shl d8, d8, #56                         // mod_constant
    eor v10.16b, v10.16b, v6.16b            // GHASH[0] - mid
    pmull v7.1q, v9.1d, v8.1d               // MODULO - top 64b align with mid
    eor v6.16b, HASH0.16b, v9.16b           // MODULO - karatsuba tidy up
    ext v9.16b, v9.16b, v9.16b, #8          // MODULO - other top alignment
    eor v10.16b, v10.16b, v6.16b            // MODULO - karatsuba tidy up
    eor v10.16b, v10.16b, v7.16b            // MODULO - fold into mid
    eor v10.16b, v10.16b, v9.16b            // MODULO - fold into mid
    pmull v8.1q, v10.1d, v8.1d              // MODULO - mid 64b align with low
    eor HASH0.16b, HASH0.16b, v8.16b        // MODULO - fold into low
    stp x21, x22, [OUT00], #16              // AES[2] block - store result
    ext v10.16b, v10.16b, v10.16b, #8       // MODULO - other mid alignment
    stp x23, x24, [OUT00], #16              // AES[3] block - store result
    eor HASH0.16b, HASH0.16b, v10.16b       // MODULO - fold into low
.endm

.macro FIRST16_ROUND
    ROUND CTR0.16b, KEY0.16b
    ROUND CTR0.16b, KEY1.16b
    ROUND CTR0.16b, KEY2.16b
    ROUND CTR0.16b, KEY3.16b
    ROUND CTR0.16b, KEY4.16b
    ROUND CTR0.16b, KEY5.16b
    ROUND CTR0.16b, KEY6.16b
    ROUND CTR0.16b, KEY7.16b
    ROUND CTR0.16b, KEY8.16b
.endm

.macro DEC16_BLOCK
    ld1 {OUT0.16b}, [INPUT], #16
    eor CTR0.16b, CTR0.16b, OUT0.16b        // data->out[i] = data->in[i] ^ data->ctr[i];
    subs COUNT, COUNT, #1                   // COUNT--
    mov	x6, CTR0.d[0]
    mov	x7, CTR0.d[1]
#ifdef HITLS_BIG_ENDIAN
    REV_2S x6, x7
#endif
    rev w9, IV_W                            // CTR[0]
    eor x6, x6, KEND0
    orr x9, x11, x9, lsl #32                // CTR[0]
    eor x7, x7, KEND1
    stp x6, x7, [OUT00], #16                // OUT OK
    add IV_W, IV_W, #1                      // CTR++
    fmov d0, x10                            // CTR[0]
    fmov CTR0.d[1], x9                      // CTR[0]--OK
    ext	v8.16b, HASH0.16b, HASH0.16b, #8    // prepare final partial tag
    movi v11.8b, #0
    movi v9.8b, #0
    movi v10.8b, #0
    rev64 v4.16b, OUT0.16b                  // GHASH final block
    mov CTR1.16b, CTR0.16b
    eor	v4.16b, v4.16b, v8.16b              // feed in partial tag
    mov	d8, v4.d[1]                         // GHASH final block - mid
    pmull v6.1q, v4.1d, HASH1_2.1d          // GHASH final block - low
    eor	v8.8b, v8.8b, v4.8b                 // GHASH final block - mid
    pmull2 v5.1q, v4.2d, HASH1_2.2d         // GHASH final block - high
    pmull v8.1q, v8.1d, v16.1d              // GHASH final block - mid
    eor	HASH0.16b, HASH0.16b, v6.16b        // GHASH final block - low
    eor	v9.16b, v9.16b, v5.16b              // GHASH final block - high
    eor	v10.16b, v10.16b, v8.16b            // GHASH final block - mid
    movi v8.8b, #0xc2
    eor	v7.16b, HASH0.16b, v9.16b           // MODULO - karatsuba tidy up
    shl	d8, d8, #56                         // mod_constant
    eor	v10.16b, v10.16b, v7.16b            // MODULO - karatsuba tidy up
    pmull v5.1q, v9.1d, v8.1d               // MODULO - top 64b align with mid
    ext	v9.16b, v9.16b, v9.16b, #8          // MODULO - other top alignment
    eor	v10.16b, v10.16b, v5.16b            // MODULO - fold into mid
    eor	v10.16b, v10.16b, v9.16b            // MODULO - fold into mid
    pmull v9.1q, v10.1d, v8.1d              // MODULO - mid 64b align with low
    ext	v10.16b, v10.16b, v10.16b, #8       // MODULO - other mid alignment
    eor	HASH0.16b, HASH0.16b, v9.16b        // MODULO - fold into low
    eor	HASH0.16b, HASH0.16b, v10.16b       // MODULO - fold into low
.endm

.macro ENC16_BLOCK
    eor x6, x6, KEND0                       // round 10 low
    eor x7, x7, KEND1                       // round 10 high
    rev w9, IV_W                            // CTR[0]
    fmov d4, x6                             // INPUT 0 - mov low
    fmov OUT0.d[1], x7                      // AES[0] - mov high
    orr x9, x11, x9, lsl #32                // CTR[0]
    add IV_W, IV_W, #1                      // CTR++
    eor OUT0.16b, OUT0.16b, CTR0.16b        // AES[0] - result
    st1 {OUT0.16b}, [OUT00], #16            // AES[0] - store result
    fmov d0, x10                            // CTR[0]
    fmov CTR0.d[1], x9                      // CTR[0]--OK
    ext	v8.16b, HASH0.16b, HASH0.16b, #8    // prepare final partial tag
    movi v11.8b, #0
    movi v9.8b, #0
    movi v10.8b, #0
    rev64 v4.16b, OUT0.16b                  // GHASH final block
    mov CTR1.16b, CTR0.16b
    eor	v4.16b, v4.16b, v8.16b              // feed in partial tag
    mov	d8, v4.d[1]                         // GHASH final block - mid
    pmull v6.1q, v4.1d, HASH1_2.1d          // GHASH final block - low
    eor	v8.8b, v8.8b, v4.8b                 // GHASH final block - mid
    pmull2 v5.1q, v4.2d, HASH1_2.2d         // GHASH final block - high
    pmull v8.1q, v8.1d, v16.1d              // GHASH final block - mid
    eor	HASH0.16b, HASH0.16b, v6.16b        // GHASH final block - low
    eor	v9.16b, v9.16b, v5.16b              // GHASH final block - high
    eor	v10.16b, v10.16b, v8.16b            // GHASH final block - mid
    movi v8.8b, #0xc2
    eor	v7.16b, HASH0.16b, v9.16b           // MODULO - karatsuba tidy up
    shl	d8, d8, #56                         // mod_constant
    eor	v10.16b, v10.16b, v7.16b            // MODULO - karatsuba tidy up
    pmull v5.1q, v9.1d, v8.1d               // MODULO - top 64b align with mid
    ext	v9.16b, v9.16b, v9.16b, #8          // MODULO - other top alignment
    eor	v10.16b, v10.16b, v5.16b            // MODULO - fold into mid
    eor	v10.16b, v10.16b, v9.16b            // MODULO - fold into mid
    pmull v9.1q, v10.1d, v8.1d              // MODULO - mid 64b align with low
    ext	v10.16b, v10.16b, v10.16b, #8       // MODULO - other mid alignment
    eor	HASH0.16b, HASH0.16b, v9.16b        // MODULO - fold into low
    eor	HASH0.16b, HASH0.16b, v10.16b       // MODULO - fold into low
.endm

.macro BEFORE16_ROUND
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8                         // xi
    ext HASH1.16b, HASH1.16b, HASH1.16b, #8                         // h^1                                                 // rev_ctr32
    ext HASH2.16b, HASH2.16b, HASH2.16b, #8                         // h^2
    ldp KEND0, KEND1, [KEY00]                                       // load key-10
#ifdef HITLS_BIG_ENDIAN
    ror KEND0, KEND0, #32
    ror KEND1, KEND1, #32
#endif
    ldp IV_H, IV_L, [IVEC0]                                         // load IV
#ifdef HITLS_BIG_ENDIAN
    rev IV_H, IV_H
    rev IV_L, IV_L
#endif
    lsr IV_C, IV_L, #32
    ld1 {CTR0.16b}, [IVEC0]                                         // CTR[0]
    rev IV_W, IV_W                                                  // rev_ctr32
    trn1 v8.2d, HASH1.2d, HASH2.2d                                  // h2h | h1h
    trn2 v16.2d, HASH1.2d, HASH2.2d                                 // h2l | h1l
    orr w11, w11, w11                                               //
    rev64 HASH0.16b, HASH0.16b                                      //
    add IV_W, IV_W, #1                                              // ctr++
    eor	v16.16b, v16.16b, v8.16b                                    //h2k | h1k
.endm

#endif