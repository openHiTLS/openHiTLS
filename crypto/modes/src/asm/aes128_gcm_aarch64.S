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

.macro GCM_ENC128_LOOP
    ldp x6, x7, [INPUT], #16                // AES[0] - load plaintext
    rev64 OUT0.16b, OUT0.16b                // GHASH blocl[0]
    rev64 OUT2.16b, OUT2.16b                // GHASH block[2]
    ROUND CTR2.16b, KEY0.16b
#ifdef HITLS_BIG_ENDIAN
    rev x6, x6
    rev x7, x7
#endif

    fmov d3, x10                            // CTR[3]
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8 // PRE 0
    rev64 OUT1.16b, OUT1.16b                // GHASH block[1]
    ROUND CTR1.16b, KEY0.16b

    add IV_W, IV_W, #1                        // CTR3++
    fmov CTR3.d[1], x9                      // CTR[3]--OK
    ROUND CTR0.16b, KEY0.16b
    mov d31, OUT2.d[1]                      // GHASH block[2.1]

    ROUND CTR2.16b, KEY1.16b
    mov d30, OUT1.d[1]                      // GHASH block[1.1]
    ROUND CTR1.16b, KEY1.16b
    eor v4.16b, OUT0.16b, HASH0.16b         // PRE 1

    ROUND CTR3.16b, KEY0.16b
    eor x7, x7, KEND1                       // AES[0] - round 10 high
    pmull2 v28.1q, OUT1.2d, HASH3.2d        // GHASH block 4k+1 - high
    eor v31.8b, v31.8b, OUT2.8b             // GHASH[2] - mid

    ldp x19, x20, [INPUT], #16              // AES[1] - load plaintext
    ROUND CTR0.16b, KEY1.16b
    rev w9, IV_W                             // CTR0--Start
    eor v30.8b, v30.8b, OUT1.8b             // GHASH block 4k+1 - mid
#ifdef HITLS_BIG_ENDIAN
    rev x19, x19
    rev x20, x20
#endif

    mov d8, v4.d[1]                         // GHASH block 4k - mid
    orr x9, x11, x9, lsl #32                // CTR0 block 4k+8
    pmull2 v9.1q, v4.2d, HASH4.2d           // GHASH block 4k - high
    add IV_W, IV_W, #1                        // CTR0++

    mov d10, v17.d[1]                       // GHASH block 4k - mid
    ROUND CTR0.16b, KEY2.16b
    pmull HASH0.1q, v4.1d, HASH4.1d         // GHASH block 4k - low
    eor v8.8b, v8.8b, v4.8b                 // GHASH block 4k - mid

    ROUND CTR1.16b, KEY2.16b
    ROUND CTR0.16b, KEY3.16b
    eor v9.16b, v9.16b, v28.16b             // GHASH block 4k+1 - high
    pmull v28.1q, OUT2.1d, HASH2.1d         // GHASH[2] - low

    pmull v10.1q, v8.1d, v10.1d             // GHASH block 4k - mid
    rev64 OUT3.16b, OUT3.16b                // GHASH[0] (t0, t1, t2 and t3 free)
    pmull v30.1q, v30.1d, v17.1d            // GHASH block 4k+1 - mid
    pmull v29.1q, OUT1.1d, HASH3.1d         // GHASH block 4k+1 - low

    ins v31.d[1], v31.d[0]                  // GHASH[2] - mid
    pmull2 v8.1q, OUT2.2d, HASH2.2d         // GHASH[2] - high
    eor x20, x20, KEND1                     // AES[1] - round 10 high
    eor v10.16b, v10.16b, v30.16b           // GHASH block 4k+1 - mid

    mov d30, OUT3.d[1]                      // GHASH[0] - mid
    ROUND CTR3.16b, v19.16b
    eor HASH0.16b, HASH0.16b, v29.16b       // GHASH block 4k+1 - low
    ROUND CTR2.16b, KEY2.16b

    eor x6, x6, KEND0                       // AES[0] - round 10 low
    ROUND CTR1.16b, KEY3.16b
    eor v30.8b, v30.8b, OUT3.8b             // GHASH[0] - mid
    pmull2 v4.1q, OUT3.2d, HASH1.2d         // GHASH[0] - high

    ROUND CTR2.16b, KEY3.16b
    eor v9.16b, v9.16b, v8.16b              // GHASH[2] - high
    pmull2 v31.1q, v31.2d, v16.2d           // GHASH[2] - mid
    pmull v29.1q, OUT3.1d, HASH1.1d         // GHASH[0] - low

    movi v8.8b, #0xc2
    pmull v30.1q, v30.1d, v16.1d            // GHASH[0] - mid
    eor HASH0.16b, HASH0.16b, v28.16b       // GHASH[2] - low
    ROUND CTR1.16b, KEY4.16b

    ROUND CTR3.16b, v20.16b
    shl d8, d8, #56                         // mod_constant
    ROUND CTR0.16b, KEY4.16b
    eor v9.16b, v9.16b, v4.16b              // GHASH[0] - high

    ROUND CTR1.16b, KEY5.16b
    ldp x21, x22, [INPUT], #16              // AES[2] - load plaintext
    ROUND CTR3.16b, v21.16b
    eor v10.16b, v10.16b, v31.16b           // GHASH[2] - mid
#ifdef HITLS_BIG_ENDIAN
    rev x21, x21
    rev x22, x22
#endif

    ROUND CTR0.16b, KEY5.16b
    ldp x23, x24, [INPUT], #16              // AES[3] - load plaintext
    pmull v31.1q, v9.1d, v8.1d              // MODULO - top 64b align with mid
    eor HASH0.16b, HASH0.16b, v29.16b       // GHASH[0] - low
#ifdef HITLS_BIG_ENDIAN
    rev x23, x23
    rev x24, x24
#endif

    ROUND CTR2.16b, KEY4.16b
    eor x19, x19, KEND0                     // AES[1] - round 10 low
    ROUND CTR3.16b, v22.16b
    eor v10.16b, v10.16b, v30.16b           // GHASH[0] - mid

    ROUND CTR1.16b, KEY6.16b
    eor x23, x23, KEND0                     // AES[3] - round 10 low
    ROUND CTR2.16b, KEY5.16b
    eor v30.16b, HASH0.16b, v9.16b          // MODULO - karatsuba tidy up

    fmov d4, x6                             // AES[0] - mov low
    ROUND CTR0.16b, KEY6.16b
    fmov OUT0.d[1], x7                      // AES[0] - mov high
    fmov d7, x23                            // AES[3] - mov low

    ext v9.16b, v9.16b, v9.16b, #8          // MODULO - other top alignment
    ROUND CTR3.16b, v23.16b
    fmov d5, x19                            // AES[2] - mov low
    ROUND CTR0.16b, KEY7.16b

    eor v10.16b, v10.16b, v30.16b           // MODULO - karatsuba tidy up
    ROUND CTR2.16b, KEY6.16b
    eor x24, x24, KEND1                     // AES[3] - round 10 high
    ROUND CTR1.16b, KEY7.16b

    fmov OUT1.d[1], x20                     // AES[1] - mov high
    ROUND CTR0.16b, KEY8.16b
    fmov OUT3.d[1], x24                     // AES[3] - mov high
    ROUND CTR3.16b, v24.16b

    subs COUNT, COUNT, #1                          // count--
    ROUND CTR1.16b, KEY8.16b
    eor v10.16b, v10.16b, v31.16b           // MODULO - fold into mid
    aese CTR0.16b, KEY9.16b

    eor x21, x21, KEND0                     // AES[2] - round 10 low
    eor x22, x22, KEND1                     // AES[2] - round 10 high
    ROUND CTR3.16b, v25.16b
    fmov d6, x21                            // AES[2] - mov low

    aese CTR1.16b, KEY9.16b                 // AES[1] - round 9
    fmov OUT2.d[1], x22                     // AES[2] - mov high
    ROUND CTR2.16b, KEY7.16b
    eor OUT0.16b, OUT0.16b, CTR0.16b        // AES[0] - result

    fmov d0, x10                            // CTR0-0
    ROUND CTR3.16b, KEY8.16b
    fmov CTR0.d[1], x9                      // CTR0-1--OK
    rev w9, IV_W                            // CTR1--start

    eor v10.16b, v10.16b, v9.16b            // MODULO - fold into mid
    ROUND CTR2.16b, KEY8.16b
    eor OUT1.16b, OUT1.16b, CTR1.16b        // AES[1] - result
    add IV_W, IV_W, #1                      // CTR1++

    orr x9, x11, x9, lsl #32                // CTR1 block 4k+9
    fmov d1, x10                            // CTR1-0
    pmull v9.1q, v10.1d, v8.1d              // MODULO - mid 64b align with low
    fmov CTR1.d[1], x9                      // CTR1-1--OK

    rev w9, IV_W                            // CTR2--Start
    aese CTR2.16b, KEY9.16b
    st1 {OUT0.16b}, [OUT00], #16            // Write back - OUT0
    eor OUT2.16b, OUT2.16b, CTR2.16b        // AES[2]-result

    orr x9, x11, x9, lsl #32                // CTR2 block 4k+10
    aese CTR3.16b, KEY9.16b
    add IV_W, IV_W, #1                      // CTR2++
    ext v10.16b, v10.16b, v10.16b, #8       // MODULO - other mid alignment
    fmov d2, x10                            // CTR2-0

    eor HASH0.16b, HASH0.16b, v9.16b        // MODULO - fold into low
    st1 {OUT1.16b}, [OUT00], #16            // Write back - OUT1
    fmov CTR2.d[1], x9                      // CTR2-1--OK
    st1 {OUT2.16b}, [OUT00], #16            // Write back - OUT2

    rev w9, IV_W                            // CTR3--start
    eor OUT3.16b, OUT3.16b, CTR3.16b        // AES[3]-result
    orr x9, x11, x9, lsl #32                // CTR3 block 4k+11
    eor HASH0.16b, HASH0.16b, v10.16b       // MODULO - fold into low
    st1 {OUT3.16b}, [OUT00], #16            // Write back - OUT3
.endm

.macro GCM_DEC128_LOOP
    eor CTR3.16b, OUT3.16b, CTR3.16b            // AES[3] - result
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8     // PRE 0
    mov x21, CTR2.d[0]                          // AES[2] - mov low
    pmull2 v28.1q, v5.2d, HASH3.2d              // GHASH block 4k+1 - high
    mov x22, CTR2.d[1]                          // AES[2] - mov high
    ROUND CTR1.16b, KEY0.16b
    fmov d2, x10                                // CTR[3]
#ifdef HITLS_BIG_ENDIAN
    rev x21, x21
    rev x22, x22
#endif
    rev64 OUT2.16b, OUT2.16b                    // GHASH[2]
    fmov v2.d[1], x9                            // CTR[3]
    rev w9, IV_W                                // CTR[0]
    mov x23, CTR3.d[0]                          // AES[3] - mov low
    eor v4.16b, v4.16b, HASH0.16b               // PRE 1
    mov d30, v5.d[1]                            // GHASH block 4k+1 - mid
    ROUND CTR1.16b, KEY1.16b
    rev64 v7.16b, v7.16b                        // GHASH[0]
    pmull v29.1q, v5.1d, HASH3.1d               // GHASH block 4k+1 - low
    mov x24, CTR3.d[1]                          // AES[3] - mov high
    orr x9, x11, x9, lsl #32                    // CTR[0]
    pmull HASH0.1q, v4.1d, HASH4.1d             // GHASH block 4k - low
#ifdef HITLS_BIG_ENDIAN
    rev x23, x23
    rev x24, x24
#endif
    fmov d3, x10                                // CTR[0]
    eor v30.8b, v30.8b, v5.8b                   // GHASH block 4k+1 - mid
    ROUND CTR1.16b, KEY2.16b
    fmov v3.d[1], x9                            // CTR[0]
    ROUND CTR2.16b, KEY0.16b
    mov d10, v17.d[1]                           // GHASH block 4k - mid
    pmull2 v9.1q, v4.2d, HASH4.2d               // GHASH block 4k - high
    eor HASH0.16b, HASH0.16b, v29.16b           // GHASH block 4k+1 - low
    pmull v29.1q, v7.1d, HASH1.1d               // GHASH[0] - low
    ROUND CTR1.16b, KEY3.16b
    mov d8, v4.d[1]                             // GHASH block 4k - mid
    ROUND CTR3.16b, KEY0.16b
    eor v9.16b, v9.16b, v28.16b                 // GHASH block 4k+1 - high
    ROUND CTR0.16b, KEY0.16b
    pmull v28.1q, v6.1d, HASH2.1d               // GHASH[2] - low
    eor v8.8b, v8.8b, v4.8b                     // GHASH block 4k - mid
    ROUND CTR3.16b, KEY1.16b
    eor x23, x23, KEND0                         // AES[3] - round 10 low
    pmull v30.1q, v30.1d, v17.1d                // GHASH block 4k+1 - mid
    eor x22, x22, KEND1                         // AES[2] - round 10 high
    mov d31, v6.d[1]                            // GHASH[2] - mid
    ROUND CTR0.16b, KEY1.16b
    eor HASH0.16b, HASH0.16b, v28.16b           // GHASH[2] - low
    pmull v10.1q, v8.1d, v10.1d                 // GHASH block 4k - mid
    ROUND CTR3.16b, KEY2.16b
    eor v31.8b, v31.8b, v6.8b                   // GHASH[2] - mid
    ROUND CTR0.16b, KEY2.16b
    ROUND CTR1.16b, KEY4.16b
    eor v10.16b, v10.16b, v30.16b               // GHASH block 4k+1 - mid
    pmull2 v8.1q, v6.2d, HASH2.2d               // GHASH[2] - high
    ROUND CTR0.16b, KEY3.16b
    ins v31.d[1], v31.d[0]                      // GHASH[2] - mid
    pmull2 v4.1q, v7.2d, HASH1.2d               // GHASH[0] - high
    ROUND CTR2.16b, KEY1.16b
    mov d30, v7.d[1]                            // GHASH[0] - mid
    ROUND CTR0.16b, KEY4.16b
    eor v9.16b, v9.16b, v8.16b                  // GHASH[2] - high
    pmull2 v31.1q, v31.2d, v16.2d               // GHASH[2] - mid
    eor x24, x24, KEND1                         // AES[3] - round 10 high
    ROUND CTR2.16b, KEY2.16b
    eor v30.8b, v30.8b, v7.8b                   // GHASH[0] - mid
    ROUND CTR1.16b, KEY5.16b
    eor x21, x21, KEND0                         // AES[2] - round 10 low
    ROUND CTR0.16b, KEY5.16b
    movi v8.8b, #0xc2
    ROUND CTR2.16b, KEY3.16b
    eor HASH0.16b, HASH0.16b, v29.16b           // GHASH[0] - low
    ROUND CTR1.16b, KEY6.16b
    ROUND CTR0.16b, KEY6.16b
    eor v10.16b, v10.16b, v31.16b               // GHASH[2] - mid
    ROUND CTR2.16b, KEY4.16b
    stp x21, x22, [OUT00], #16                  // AES[2] - store result
    pmull v30.1q, v30.1d, v16.1d                // GHASH[0] - mid
    eor v9.16b, v9.16b, v4.16b                  // GHASH[0] - high

    ld1 {OUT0.16b}, [INPUT], #16                // AES[0] - load ciphertext

    ROUND CTR1.16b, KEY7.16b
    add IV_W, IV_W, #1                            // CTR++
    ROUND CTR0.16b, KEY7.16b
    shl d8, d8, #56                             // mod_constant
    ROUND CTR2.16b, KEY5.16b
    eor v10.16b, v10.16b, v30.16b               // GHASH[0] - mid
    ROUND CTR1.16b, KEY8.16b
    stp x23, x24, [OUT00], #16                  // AES[3] - store result
    ROUND CTR0.16b, KEY8.16b
    eor v30.16b, HASH0.16b, v9.16b              // MODULO - karatsuba tidy up
    ROUND CTR3.16b, KEY3.16b
    rev w9, IV_W                                 // CTR block 4k+8
    pmull v31.1q, v9.1d, v8.1d                  // MODULO - top 64b align with mid
    ld1 {OUT1.16b}, [INPUT], #16                // AES[1] - load
    ext v9.16b, v9.16b, v9.16b, #8              // MODULO - other top alignment
    aese CTR0.16b, KEY9.16b                     // AES[0] - round 9
    orr x9, x11, x9, lsl #32                    // CTR block 4k+8
    ROUND CTR3.16b, KEY4.16b
    eor v10.16b, v10.16b, v30.16b               // MODULO - karatsuba tidy up
    aese CTR1.16b, KEY9.16b                     // AES[1] - round 9
    ROUND CTR2.16b, KEY6.16b

    eor CTR0.16b, OUT0.16b, CTR0.16b            // AES[0] - result
    ROUND CTR3.16b, KEY5.16b
    ld1 {OUT2.16b}, [INPUT], #16                // AES[2] - load
    add IV_W, IV_W, #1                            // CTR++
    eor v10.16b, v10.16b, v31.16b               // MODULO - fold into mid
    eor CTR1.16b, OUT1.16b, CTR1.16b            // AES[1] - result
    ROUND CTR2.16b, KEY7.16b
    ld1 {OUT3.16b}, [INPUT], #16
    ROUND CTR3.16b, KEY6.16b

    rev64 OUT1.16b, OUT1.16b                    // GHASH block[1]
    eor v10.16b, v10.16b, v9.16b                // MODULO - fold into mid
    mov x7, CTR0.d[1]                           // AES[0] - mov high
    ROUND CTR2.16b, KEY8.16b
    mov x6, CTR0.d[0]                           // AES[0] - mov low

    ROUND CTR3.16b, KEY7.16b
    fmov d0, x10                                // CTR[0]
#ifdef HITLS_BIG_ENDIAN
    rev x7, x7
    rev x6, x6
#endif
    pmull v8.1q, v10.1d, v8.1d                  // MODULO - mid 64b align with low
    fmov CTR0.d[1], x9                            // CTR[0] - OK
    rev w9, IV_W                                 // CTR block 4k+9
    aese CTR2.16b, KEY9.16b
    orr x9, x11, x9, lsl #32                    // CTR block 4k+9

    ext v10.16b, v10.16b, v10.16b, #8           // MODULO - other mid alignment

    ROUND CTR3.16b, KEY8.16b

    eor x7, x7, KEND1                           // AES[0] - round 10 high
    eor HASH0.16b, HASH0.16b, v8.16b            // MODULO - fold into low
    mov x20, CTR1.d[1]                          // AES[1] - mov high
    eor x6, x6, KEND0                           // AES[0] - round 10 low
    eor CTR2.16b, OUT2.16b, CTR2.16b            // AES[2] - result
    mov x19, CTR1.d[0]                          // AES[1] - mov low
    add IV_W, IV_W, #1                            // CTR++
    aese CTR3.16b, KEY9.16b
    fmov d1, x10                                // CTR[1]
#ifdef HITLS_BIG_ENDIAN
    rev x20, x20
    rev x19, x19
#endif
    subs COUNT, COUNT, #1                       // COUNT--
    rev64 OUT0.16b, OUT0.16b                    // GHASH block[0]
    eor HASH0.16b, HASH0.16b, v10.16b           // MODULO - fold into low

    fmov v1.d[1], x9                            // CTR[1] - OK
    rev w9, IV_W                                 // CTR block 4k+10
    add IV_W, IV_W, #1                            // CTR block 4k+10

    eor x20, x20, KEND1                         // AES[1] - round 10 high
    stp x6, x7, [OUT00], #16                    // AES[0] - store result
    eor x19, x19, KEND0                         // AES[1] - round 10 low
    stp x19, x20, [OUT00], #16                  // AES[1] - store result
    orr x9, x11, x9, lsl #32                    // CTR block 4k+10
.endm

#endif
