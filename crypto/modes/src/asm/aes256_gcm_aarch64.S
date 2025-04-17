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

.macro GCM_ENC256_LOOP
    ROUND CTR0.16b, KEY0.16b
    rev64 v4.16b, v4.16b                            // GHASH block 4k (only t0 is free)
    ROUND CTR1.16b, KEY0.16b
    fmov d3, x10                                    // CTR[3]
    ROUND CTR2.16b, KEY0.16b

    ext HASH0.16b, HASH0.16b, HASH0.16b, #8         // PRE 0
    ROUND CTR0.16b, KEY1.16b
    fmov CTR3.d[1], x9                              // CTR[3] - OK

    ROUND CTR1.16b, KEY1.16b
    ldp x6, x7, [INPUT], #16                        // AES[0] - load plaintext
    ROUND CTR2.16b, KEY1.16b
    ldp x19, x20, [INPUT], #16                      // AES[1] - load plaintext
    ROUND CTR0.16b, KEY2.16b
#ifdef HITLS_BIG_ENDIAN
    rev x6, x6
    rev x7, x7
    rev x19, x19
    rev x20, x20
#endif
    eor v4.16b, v4.16b, HASH0.16b                   // PRE 1
    ROUND CTR1.16b, KEY2.16b
    ROUND CTR3.16b, KEY0.16b
    eor x6, x6, KEND0                               // AES[0] - round 14 low

    ROUND CTR0.16b, KEY3.16b
    mov d10, v17.d[1]                               // GHASH block 4k - mid
    pmull2 v9.1q, v4.2d, HASH4.2d                   // GHASH block 4k - high
    eor x7, x7, KEND1                               // AES[0] - round 14 high
    mov d8, v4.d[1]                                 // GHASH block 4k - mid
    ROUND CTR3.16b, KEY1.16b
    rev64 v5.16b, v5.16b                            // GHASH block 4k+1 (t0 and t1 free)
    ROUND CTR0.16b, KEY4.16b
    pmull HASH0.1q, v4.1d, HASH4.1d                 // GHASH block 4k - low
    eor v8.8b, v8.8b, v4.8b                         // GHASH block 4k - mid
    ROUND CTR2.16b, KEY2.16b
    ROUND CTR0.16b, KEY5.16b
    rev64 v7.16b, v7.16b                            // GHASH[0] (t0, t1, t2 and t3 free)

    pmull2 v4.1q, v5.2d, HASH3.2d                   // GHASH block 4k+1 - high
    pmull v10.1q, v8.1d, v10.1d                     // GHASH block 4k - mid
    rev64 v6.16b, v6.16b                            // GHASH[2] (t0, t1, and t2 free)
    pmull v8.1q, v5.1d, HASH3.1d                    // GHASH block 4k+1 - low
    eor v9.16b, v9.16b, v4.16b                      // GHASH block 4k+1 - high
    mov d4, v5.d[1]                                 // GHASH block 4k+1 - mid
    ROUND CTR1.16b, KEY3.16b
    ROUND CTR3.16b, KEY2.16b
    eor HASH0.16b, HASH0.16b, v8.16b                // GHASH block 4k+1 - low
    ROUND CTR2.16b, KEY3.16b
    ROUND CTR1.16b, KEY4.16b
    mov d8, v6.d[1]                                 // GHASH[2] - mid
    ROUND CTR3.16b, KEY3.16b
    eor v4.8b, v4.8b, v5.8b                         // GHASH block 4k+1 - mid
    ROUND CTR2.16b, KEY4.16b
    ROUND CTR0.16b, KEY6.16b
    eor v8.8b, v8.8b, v6.8b                         // GHASH[2] - mid
    ROUND CTR3.16b, KEY4.16b
    pmull v4.1q, v4.1d, v17.1d                      // GHASH block 4k+1 - mid
    ROUND CTR0.16b, KEY7.16b
    ROUND CTR3.16b, KEY5.16b
    ins v8.d[1], v8.d[0]                            // GHASH[2] - mid
    ROUND CTR1.16b, KEY5.16b
    ROUND CTR0.16b, KEY8.16b
    ROUND CTR2.16b, KEY5.16b
    ROUND CTR1.16b, KEY6.16b
    eor v10.16b, v10.16b, v4.16b                    // GHASH block 4k+1 - mid
    pmull2 v4.1q, v6.2d, HASH2.2d                   // GHASH[2] - high
    pmull v5.1q, v6.1d, HASH2.1d                    // GHASH[2] - low
    ROUND CTR1.16b, KEY7.16b
    pmull v6.1q, v7.1d, HASH1.1d                    // GHASH[0] - low
    eor v9.16b, v9.16b, v4.16b                      // GHASH[2] - high
    ROUND CTR3.16b, KEY6.16b

    ldp x21, x22, [INPUT], #16                      // AES[2] - load plaintext
    ROUND CTR1.16b, KEY8.16b
    mov d4, v7.d[1]                                 // GHASH[0] - mid
#ifdef HITLS_BIG_ENDIAN
    rev x21, x21
    rev x22, x22
#endif
    ROUND CTR2.16b, KEY6.16b
    eor HASH0.16b, HASH0.16b, v5.16b                // GHASH[2] - low
    pmull2 v8.1q, v8.2d, v16.2d                     // GHASH[2] - mid
    pmull2 v5.1q, v7.2d, HASH1.2d                   // GHASH[0] - high
    eor v4.8b, v4.8b, v7.8b                         // GHASH[0] - mid
    ROUND CTR2.16b, KEY7.16b
    eor x19, x19, KEND0                             // AES[1] - round 14 low
    ROUND CTR1.16b, KEY9.16b
    eor v10.16b, v10.16b, v8.16b                    // GHASH[2] - mid
    ROUND CTR3.16b, KEY7.16b
    eor x21, x21, KEND0                             // AES[2] - round 14 low
    ROUND CTR0.16b, KEY9.16b
    movi v8.8b, #0xc2
    pmull v4.1q, v4.1d, v16.1d                      // GHASH[0] - mid
    eor v9.16b, v9.16b, v5.16b                      // GHASH[0] - high
    fmov d5, x19                                    // AES[1] - mov low

    ROUND CTR2.16b, KEY8.16b
    ldp x23, x24, [INPUT], #16                      // AES[3] - load plaintext
    ROUND CTR0.16b, KEY10.16b
    shl d8, d8, #56                                 // mod_constant
#ifdef HITLS_BIG_ENDIAN
    rev x23, x23
    rev x24, x24
#endif
    ROUND CTR3.16b, KEY8.16b
    eor HASH0.16b, HASH0.16b, v6.16b                // GHASH[0] - low
    ROUND CTR2.16b, KEY9.16b
    ROUND CTR1.16b, KEY10.16b
    eor v10.16b, v10.16b, v4.16b                    // GHASH[0] - mid
    ROUND CTR3.16b, KEY9.16b
    add IV_W, IV_W, #1                                // CTR++
    ROUND CTR0.16b, KEY11.16b
    eor v4.16b, HASH0.16b, v9.16b                   // MODULO - karatsuba tidy up
    ROUND CTR1.16b, KEY11.16b

    pmull v7.1q, v9.1d, v8.1d                       // MODULO - top 64b align with mid
    rev w9, IV_W                                     // CTR block 4k+8
    ext v9.16b, v9.16b, v9.16b, #8                  // MODULO - other top alignment
    ROUND CTR2.16b, KEY10.16b
    eor x23, x23, KEND0                             // AES[3] - round 14 low
    ROUND CTR1.16b, KEY12.16b
    eor v10.16b, v10.16b, v4.16b                    // MODULO - karatsuba tidy up
    ROUND CTR3.16b, KEY10.16b
    eor x20, x20, KEND1                             // AES[1] - round 14 high

    fmov d4, x6                                     // AES[0] - mov low
    orr x9, x11, x9, lsl #32                        // CTR block 4k+8
    eor v7.16b, v9.16b, v7.16b                      // MODULO - fold into mid
    ROUND CTR0.16b, KEY12.16b
    eor x22, x22, KEND1                             // AES[2] - round 14 high
    ROUND CTR2.16b, KEY11.16b
    eor x24, x24, KEND1                             // AES[3] - round 14 high

    ROUND CTR3.16b, KEY11.16b
    add IV_W, IV_W, #1                                // CTR++
    aese CTR0.16b, KEY13.16b                        // AES[0] - round 13
    fmov OUT0.d[1], x7                              // AES[0] - mov high
    eor v10.16b, v10.16b, v7.16b                    // MODULO - fold into mid
    ROUND CTR2.16b, KEY12.16b
    fmov d7, x23                                    // AES[3] - mov low
    aese CTR1.16b, KEY13.16b                        // AES[2] - round 13
    fmov OUT1.d[1], x20                             // AES[1] - mov high
    fmov d6, x21                                    // AES[2] - mov low

    subs COUNT, COUNT, #1                           // COUNT--
    fmov OUT2.d[1], x22                             // AES[2] - mov high
    pmull v9.1q, v10.1d, v8.1d                      // MODULO - mid 64b align with low
    eor OUT0.16b, OUT0.16b, CTR0.16b                // AES[0] - result
    fmov d0, x10                                    // CTR[0]
    fmov CTR0.d[1], x9                                // CTR[0]--OK
    rev w9, IV_W                                     // CTR[1]
    add IV_W, IV_W, #1                                // CTR++

    eor OUT1.16b, OUT1.16b, CTR1.16b                // AES[1] - result
    fmov d1, x10                                    // CTR[1]
    orr x9, x11, x9, lsl #32                        // CTR[1]
    ROUND CTR3.16b, KEY12.16b
    fmov v1.d[1], x9                                // CTR[1]--OK
    aese CTR2.16b, KEY13.16b                        // AES[3] - round 13
    rev w9, IV_W                                     // CTR block 4k+10

    st1 {OUT0.16b}, [OUT00], #16                    // AES[0] - store result
    orr x9, x11, x9, lsl #32                        // CTR block 4k+10
    eor HASH0.16b, HASH0.16b, v9.16b                // MODULO - fold into low
    fmov OUT3.d[1], x24                             // AES[3] - mov high
    ext v10.16b, v10.16b, v10.16b, #8               // MODULO - other mid alignment
    st1 {OUT1.16b}, [OUT00], #16                    // AES[1] - store result
    add IV_W, IV_W, #1                                // CTR++
    aese CTR3.16b, KEY13.16b                        // AES[0] - round 13

    eor OUT2.16b, OUT2.16b, CTR2.16b                // AES[2] - result
    fmov d2, x10                                    // CTR[2]
    st1 {OUT2.16b}, [OUT00], #16                    // AES[2] - store result
    fmov v2.d[1], x9                                // CTR[2]--OK
    rev w9, IV_W                                     // CTR block 4k+11

    eor OUT3.16b, OUT3.16b, CTR3.16b                // AES[3] - result
    eor HASH0.16b, HASH0.16b, v10.16b               // MODULO - fold into low
    orr x9, x11, x9, lsl #32                        // CTR block 4k+11
    st1 {OUT3.16b}, [OUT00], #16                    // AES[3] - store result
.endm

.macro GCM_DEC256_LOOP
    mov x21, CTR2.d[0]                      // AES[2] block - mov low
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8 // PRE 0
    eor CTR3.16b, OUT3.16b, CTR3.16b        // AES[3] block - result
    ROUND CTR0.16b, KEY0.16b
    mov x22, CTR2.d[1]                      // AES[2] block - mov high

    ROUND CTR1.16b, KEY0.16b
    fmov d2, x10                            // CTR[2]
    fmov v2.d[1], x9                        // CTR[2]
    eor v4.16b, v4.16b, HASH0.16b           // PRE 1
#ifdef HITLS_BIG_ENDIAN
    rev x21, x21
    rev x22, x22
#endif
    rev w9, IV_W                             // CTR[0]
    ROUND CTR0.16b, KEY1.16b
    mov x24, CTR3.d[1]                      // AES[3] block - mov high
    ROUND CTR1.16b, KEY1.16b
    mov x23, CTR3.d[0]                      // AES[3] block - mov low

    pmull2 v9.1q, v4.2d, HASH4.2d           // GHASH block 4k - high
    mov d8, v4.d[1]                         // GHASH block 4k - mid
    fmov d3, x10                            // CTR[0]
#ifdef HITLS_BIG_ENDIAN
    rev x23, x23
    rev x24, x24
#endif
    ROUND CTR0.16b, KEY2.16b
    orr x9, x11, x9, lsl #32                // CTR[0]
    ROUND CTR2.16b, KEY0.16b
    fmov v3.d[1], x9                        // CTR[0]
    ROUND CTR1.16b, KEY2.16b
    eor v8.8b, v8.8b, v4.8b                 // GHASH block 4k - mid
    ROUND CTR0.16b, KEY3.16b
    eor x22, x22, KEND1                     // AES[2] - round 14 high
    ROUND CTR2.16b, KEY1.16b
    mov d10, v17.d[1]                       // GHASH block 4k - mid
    ROUND CTR1.16b, KEY3.16b
    rev64 v6.16b, v6.16b                    // GHASH[2]
    ROUND CTR3.16b, KEY0.16b
    eor x21, x21, KEND0                     // AES[2] - round 14 low
    ROUND CTR2.16b, KEY2.16b
    stp x21, x22, [OUT00], #16              // AES[2] - store result
    pmull HASH0.1q, v4.1d, HASH4.1d         // GHASH block 4k - low
    pmull2 v4.1q, v5.2d, HASH3.2d           // GHASH block 4k+1 - high
    ROUND CTR2.16b, KEY3.16b
    rev64 v7.16b, v7.16b                    // GHASH[0]

    pmull v10.1q, v8.1d, v10.1d             // GHASH block 4k - mid
    eor x23, x23, KEND0                     // AES[3] - round 14 low
    pmull v8.1q, v5.1d, HASH3.1d            // GHASH block 4k+1 - low
    eor x24, x24, KEND1                     // AES[3] - round 14 high
    eor v9.16b, v9.16b, v4.16b              // GHASH block 4k+1 - high
    ROUND CTR2.16b, KEY4.16b
    ROUND CTR3.16b, KEY1.16b
    mov d4, v5.d[1]                         // GHASH block 4k+1 - mid
    ROUND CTR0.16b, KEY4.16b
    eor HASH0.16b, HASH0.16b, v8.16b        // GHASH block 4k+1 - low
    ROUND CTR2.16b, KEY5.16b
    add IV_W, IV_W, #1                        // CTR[0]
    ROUND CTR3.16b, KEY2.16b
    mov d8, v6.d[1]                         // GHASH[2] - mid
    ROUND CTR1.16b, KEY4.16b
    eor v4.8b, v4.8b, v5.8b                 // GHASH block 4k+1 - mid

    pmull v5.1q, v6.1d, HASH2.1d            // GHASH[2] - low
    ROUND CTR3.16b, KEY3.16b
    eor v8.8b, v8.8b, v6.8b                 // GHASH[2] - mid
    ROUND CTR1.16b, KEY5.16b
    ROUND CTR0.16b, KEY5.16b
    eor HASH0.16b, HASH0.16b, v5.16b        // GHASH[2] - low

    pmull v4.1q, v4.1d, v17.1d              // GHASH block 4k+1 - mid
    rev w9, IV_W                             // CTR block 4k+8
    ROUND CTR1.16b, KEY6.16b
    ins v8.d[1], v8.d[0]                    // GHASH[2] - mid
    ROUND CTR0.16b, KEY6.16b
    add IV_W, IV_W, #1                        // CTR block 4k+8
    ROUND CTR3.16b, KEY4.16b
    ROUND CTR1.16b, KEY7.16b
    eor v10.16b, v10.16b, v4.16b            // GHASH block 4k+1 - mid
    ROUND CTR0.16b, KEY7.16b

    pmull2 v4.1q, v6.2d, HASH2.2d           // GHASH[2] - high
    mov d6, v7.d[1]                         // GHASH[0] - mid
    ROUND CTR3.16b, KEY5.16b

    pmull2 v8.1q, v8.2d, v16.2d             // GHASH[2] - mid
    ROUND CTR0.16b, KEY8.16b
    eor v9.16b, v9.16b, v4.16b              // GHASH[2] - high
    ROUND CTR3.16b, KEY6.16b

    pmull v4.1q, v7.1d, HASH1.1d            // GHASH[0] - low
    orr x9, x11, x9, lsl #32                // CTR block 4k+8
    eor v10.16b, v10.16b, v8.16b            // GHASH[2] - mid

    pmull2 v5.1q, v7.2d, HASH1.2d           // GHASH[0] - high
    ROUND CTR0.16b, KEY9.16b
    eor v6.8b, v6.8b, v7.8b                 // GHASH[0] - mid
    ROUND CTR1.16b, KEY8.16b
    ROUND CTR2.16b, KEY6.16b
    eor v9.16b, v9.16b, v5.16b              // GHASH[0] - high
    ROUND CTR0.16b, KEY10.16b
    pmull v6.1q, v6.1d, v16.1d              // GHASH[0] - mid
    movi v8.8b, #0xc2
    ROUND CTR2.16b, KEY7.16b
    eor HASH0.16b, HASH0.16b, v4.16b        // GHASH[0] - low
    ROUND CTR0.16b, KEY11.16b
    ROUND CTR3.16b, KEY7.16b
    shl d8, d8, #56                         // mod_constant
    ROUND CTR2.16b, KEY8.16b
    eor v10.16b, v10.16b, v6.16b            // GHASH[0] - mid
    ROUND CTR0.16b, KEY12.16b
    pmull v7.1q, v9.1d, v8.1d               // MODULO - top 64b align with mid
    eor v6.16b, HASH0.16b, v9.16b           // MODULO - karatsuba tidy up
    ROUND CTR1.16b, KEY9.16b

    ld1 {OUT0.16b}, [INPUT], #16            // AES load[0] ciphertext
    aese CTR0.16b, KEY13.16b
    ext v9.16b, v9.16b, v9.16b, #8          // MODULO - other top alignment
    ROUND CTR1.16b, KEY10.16b
    eor v10.16b, v10.16b, v6.16b            // MODULO - karatsuba tidy up
    ROUND CTR2.16b, KEY9.16b

    ld1 {OUT1.16b}, [INPUT], #16            // AES load[1] ciphertext
    ROUND CTR3.16b, KEY8.16b
    eor CTR0.16b, OUT0.16b, CTR0.16b        // AES[0] block - result
    ROUND CTR1.16b, KEY11.16b

    stp x23, x24, [OUT00], #16              // AES[3] block - store result
    ROUND CTR2.16b, KEY10.16b
    eor v10.16b, v10.16b, v7.16b            // MODULO - fold into mid
    ROUND CTR3.16b, KEY9.16b
    ld1 {OUT2.16b}, [INPUT], #16            // AES load[1] ciphertext

    ROUND CTR1.16b, KEY12.16b
    ld1 {OUT3.16b}, [INPUT], #16            // AES load[1] ciphertext
    ROUND CTR2.16b, KEY11.16b
    mov x7, CTR0.d[1]                       // AES[0] block - mov high
    ROUND CTR3.16b, KEY10.16b
    eor v10.16b, v10.16b, v9.16b            // MODULO - fold into mid
    aese CTR1.16b, KEY13.16b                // AES[2] - round 13
    mov x6, CTR0.d[0]                       // AES[0] block - mov low
    ROUND CTR2.16b, KEY12.16b
    fmov d0, x10                            // CTR[0]
    ROUND CTR3.16b, KEY11.16b
#ifdef HITLS_BIG_ENDIAN
    rev x6, x6
    rev x7, x7
#endif
    fmov CTR0.d[1], x9                      // CTR[0]--OK
    pmull v8.1q, v10.1d, v8.1d              // MODULO - mid 64b align with low
    eor CTR1.16b, OUT1.16b, CTR1.16b        // AES[1] block - result
    rev w9, IV_W                             // CTR block 4k+9
    aese CTR2.16b, KEY13.16b
    orr x9, x11, x9, lsl #32                // CTR block 4k+9

    subs COUNT, COUNT, #1                   // COUNT--
    add IV_W, IV_W, #1                        // CTR++
    eor x6, x6, KEND0                       // AES[0] block - round 14 low
    eor x7, x7, KEND1                       // AES[0] block - round 14 high

    mov x20, v1.d[1]                        // AES[1] block - mov high
    eor CTR2.16b, OUT2.16b, CTR2.16b        // AES[2] block - result
    eor HASH0.16b, HASH0.16b, v8.16b        // MODULO - fold into low
    ROUND CTR3.16b, KEY12.16b
    mov x19, CTR1.d[0]                      // AES[1] block - mov low
    fmov d1, x10                            // CTR[1]
    ext v10.16b, v10.16b, v10.16b, #8       // MODULO - other mid alignment
#ifdef HITLS_BIG_ENDIAN
    rev x20, x20
    rev x19, x19
#endif
    fmov CTR1.d[1], x9                      // CTR[1]--OK
    rev w9, IV_W                             // CTR block 4k+10
    add IV_W, IV_W, #1                        // CTR++

    aese CTR3.16b, KEY13.16b
    orr x9, x11, x9, lsl #32                // CTR block 4k+10
    rev64 v5.16b, v5.16b                    // GHASH[2]
    eor x20, x20, KEND1                     // AES[1] block - round 14 high
    stp x6, x7, [OUT00], #16                // AES[0] block - store result
    eor x19, x19, KEND0                     // AES[1] block - round 14 low
    stp x19, x20, [OUT00], #16              // AES[1] block - store result
    rev64 OUT0.16b, OUT0.16b                // GHASH block[0]
    eor HASH0.16b, HASH0.16b, v10.16b       // MODULO - fold into low
.endm

#endif
