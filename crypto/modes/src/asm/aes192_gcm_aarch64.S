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

.macro GCM_ENC192_LOOP
    ROUND CTR2.16b, KEY0.16b
    rev64 OUT1.16b, OUT1.16b                // GHASH block 4k+1 (t0 and t1 free)
    ROUND CTR1.16b, KEY0.16b
    ldp x6, x7, [INPUT], #16                // AES[0] - load plaintext
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8 // PRE 0

    fmov d3, x10                            // CTR[3]
    rev64 OUT0.16b, OUT0.16b                // GHASH block 4k (only t0 is free)
    ROUND CTR2.16b, KEY1.16b
    fmov CTR3.d[1], x9                      // CTR[3]--OK
#ifdef HITLS_BIG_ENDIAN
    rev x6, x6
    rev x7, x7
#endif
    pmull2 v30.1q, v5.2d, HASH3.2d          // GHASH block 4k+1 - high
    rev64 OUT3.16b, OUT3.16b                // GHASH[0] (t0, t1, t2 and t3 free)
    ldp x19, x20, [INPUT], #16              // AES[1] - load plaintext
    ROUND CTR0.16b, KEY0.16b
    ldp x21, x22, [INPUT], #16              // AES[2] - load plaintext
    pmull v31.1q, v5.1d, HASH3.1d           // GHASH block 4k+1 - low
    eor v4.16b, v4.16b, HASH0.16b           // PRE 1
#ifdef HITLS_BIG_ENDIAN
    rev x19, x19
    rev x20, x20
    rev x21, x21
    rev x22, x22
#endif
    ROUND CTR1.16b, KEY1.16b
    ROUND CTR0.16b, KEY1.16b
    rev64 OUT2.16b, OUT2.16b                // GHASH[2] (t0, t1, and t2 free)
    ROUND CTR3.16b, KEY0.16b
    eor x7, x7, KEND1                       // AES[0] - round 12 high
    pmull HASH0.1q, v4.1d, HASH4.1d         // GHASH block 4k - low
    mov d8, v4.d[1]                         // GHASH block 4k - mid
    ROUND CTR0.16b, KEY2.16b
    ROUND CTR3.16b, KEY1.16b

    eor x6, x6, KEND0                       // AES[0] - round 12 low
    eor v8.8b, v8.8b, v4.8b                 // GHASH block 4k - mid
    eor HASH0.16b, HASH0.16b, v31.16b       // GHASH block 4k+1 - low
    ROUND CTR0.16b, KEY3.16b
    eor x19, x19, KEND0                     // AES[1] - round 12 low
    ROUND CTR1.16b, KEY2.16b
    mov d31, v6.d[1]                        // GHASH[2] - mid
    pmull2 v9.1q, v4.2d, HASH4.2d           // GHASH block 4k - high
    mov d4, v5.d[1]                         // GHASH block 4k+1 - mid

    ROUND CTR2.16b, KEY2.16b
    ROUND CTR1.16b, KEY3.16b
    mov d10, v17.d[1]                       // GHASH block 4k - mid
    eor v9.16b, v9.16b, v30.16b             // GHASH block 4k+1 - high
    ROUND CTR3.16b, KEY2.16b
    eor v31.8b, v31.8b, v6.8b               // GHASH[2] - mid
    pmull2 v30.1q, v6.2d, HASH2.2d          // GHASH[2] - high
    ROUND CTR0.16b, KEY4.16b
    eor v4.8b, v4.8b, v5.8b                 // GHASH block 4k+1 - mid
    ROUND CTR3.16b, KEY3.16b
    pmull2 v5.1q, v7.2d, HASH1.2d           // GHASH[0] - high
    eor x20, x20, KEND1                     // AES[1] - round 12 high

    ins v31.d[1], v31.d[0]                  // GHASH[2] - mid
    ROUND CTR0.16b, KEY5.16b
    add IV_W, IV_W, #1                        // CTR++
    ROUND CTR3.16b, KEY4.16b
    eor v9.16b, v9.16b, v30.16b             // GHASH[2] - high
    pmull v4.1q, v4.1d, v17.1d              // GHASH block 4k+1 - mid
    eor x22, x22, KEND1                     // AES[2] - round 12 high

    pmull2 v31.1q, v31.2d, v16.2d           // GHASH[2] - mid
    eor x21, x21, KEND0                     // AES[2] - round 12 low
    mov d30, v7.d[1]                        // GHASH[0] - mid
    pmull v10.1q, v8.1d, v10.1d             // GHASH block 4k - mid
    rev w9, IV_W                             // CTR[0]
    pmull v8.1q, v6.1d, HASH2.1d            // GHASH[2] - low
    orr x9, x11, x9, lsl #32                // CTR[0]
    ROUND CTR2.16b, KEY3.16b
    eor v30.8b, v30.8b, v7.8b               // GHASH[0] - mid
    ROUND CTR1.16b, KEY4.16b

    ldp x23, x24, [INPUT], #16              // AES[3] - load plaintext
    ROUND CTR0.16b, KEY6.16b
    eor HASH0.16b, HASH0.16b, v8.16b        // GHASH[2] - low
    ROUND CTR2.16b, KEY4.16b
#ifdef HITLS_BIG_ENDIAN
    rev x23, x23
    rev x24, x24
#endif
    ROUND CTR1.16b, KEY5.16b
    movi v8.8b, #0xc2
    pmull v6.1q, v7.1d, HASH1.1d            // GHASH[0] - low
    eor x24, x24, KEND1                     // AES[3] - round 12 high
    eor v10.16b, v10.16b, v4.16b            // GHASH block 4k+1 - mid
    ROUND CTR2.16b, KEY5.16b
    eor x23, x23, KEND0                     // AES[3] - round 12 low

    ROUND CTR1.16b, KEY6.16b
    shl d8, d8, #56                         // mod_constant
    ROUND CTR3.16b, KEY5.16b
    eor v9.16b, v9.16b, v5.16b              // GHASH[0] - high
    ROUND CTR0.16b, KEY7.16b
    fmov d5, x19                            // AES[1] - mov low
    ROUND CTR1.16b, KEY7.16b
    eor v10.16b, v10.16b, v31.16b           // GHASH[2] - mid
    ROUND CTR3.16b, KEY6.16b
    fmov OUT1.d[1], x20                     // AES[1] - mov high

    ROUND CTR0.16b, KEY8.16b
    eor HASH0.16b, HASH0.16b, v6.16b        // GHASH[0] - low
    pmull v30.1q, v30.1d, v16.1d            // GHASH[0] - mid

    subs COUNT, COUNT, #1                          // count--
    fmov d4, x6                             // AES[0] - mov low
    ROUND CTR2.16b, KEY6.16b
    fmov OUT0.d[1], x7                      // AES[0] - mov high

    ROUND CTR1.16b, KEY8.16b
    fmov d7, x23                            // AES[0] - mov low
    eor v10.16b, v10.16b, v30.16b           // GHASH[0] - mid
    eor v30.16b, HASH0.16b, v9.16b          // MODULO - karatsuba tidy up
    add IV_W, IV_W, #1                        // CTR++
    ROUND CTR2.16b, KEY7.16b
    fmov OUT3.d[1], x24                     // AES[3] - mov high

    pmull v31.1q, v9.1d, v8.1d              // MODULO - top 64b align with mid
    ext v9.16b, v9.16b, v9.16b, #8          // MODULO - other top alignment
    fmov d6, x21                            // AES[3] - mov low
    ROUND CTR3.16b, KEY7.16b
    ROUND CTR0.16b, KEY9.16b
    eor v10.16b, v10.16b, v30.16b           // MODULO - karatsuba tidy up
    ROUND CTR2.16b, KEY8.16b
    ROUND CTR3.16b, KEY8.16b
    ROUND CTR1.16b, KEY9.16b
    ROUND CTR0.16b, KEY10.16b
    eor v10.16b, v10.16b, v31.16b           // MODULO - fold into mid
    ROUND CTR3.16b, KEY9.16b
    ROUND CTR2.16b, KEY9.16b
    aese CTR0.16b, KEY11.16b                // AES[1] - round 11

    ROUND CTR1.16b, KEY10.16b
    eor v10.16b, v10.16b, v9.16b            // MODULO - fold into mid
    ROUND CTR2.16b, KEY10.16b

    eor OUT0.16b, OUT0.16b, CTR0.16b        // AES[0] - result
    fmov d0, x10                            // CTR[0]
    aese CTR1.16b, KEY11.16b                // AES[2] - round 11
    fmov CTR0.d[1], x9                      // CTR[0]--OK

    rev w9, IV_W                             // CTR[1]
    pmull v9.1q, v10.1d, v8.1d              // MODULO - mid 64b align with low
    fmov OUT2.d[1], x22                     // AES[2] - mov high
    st1 {OUT0.16b}, [OUT00], #16            // AES[0] - store result

    ROUND CTR3.16b, KEY10.16b
    orr x9, x11, x9, lsl #32                // CTR[1]
    eor OUT1.16b, OUT1.16b, CTR1.16b        // AES[1] - result
    add IV_W, IV_W, #1                        // CTR++
    fmov d1, x10                            // CTR[1]
    aese CTR2.16b, KEY11.16b

    fmov v1.d[1], x9                        // CTR[1]--OK
    rev w9, IV_W                             // CTR[2]
    add IV_W, IV_W, #1                        // CTR++
    ext v10.16b, v10.16b, v10.16b, #8       // MODULO - other mid alignment
    orr x9, x11, x9, lsl #32                // CTR[2]
    st1 {OUT1.16b}, [OUT00], #16            // AES[1] - store result

    eor HASH0.16b, HASH0.16b, v9.16b        // MODULO - fold into low
    aese CTR3.16b, KEY11.16b                // AES[2] - round 11
    eor OUT2.16b, OUT2.16b, CTR2.16b        // AES[2] - result
    fmov d2, x10                            // CTR[2]
    st1 {OUT2.16b}, [OUT00], #16            // AES[2] - store result

    fmov CTR2.d[1], x9                      // CTR[2]--OK
    rev w9, IV_W                             // CTR[3]
    eor OUT3.16b, OUT3.16b, CTR3.16b        // AES[3] - result
    eor HASH0.16b, HASH0.16b, v10.16b       // MODULO - fold into low
    orr x9, x11, x9, lsl #32                // CTR[3]
    st1 {OUT3.16b}, [OUT00], #16            // AES[3] - store result
.endm

.macro GCM_DEC192_LOOP
    ROUND CTR1.16b, KEY0.16b
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8     // PRE 0
    pmull v31.1q, OUT1.1d, HASH3.1d             // GHASH block 4k+1 - low
    mov x21, CTR2.d[0]                          // AES[2] block - mov low
    mov x22, CTR2.d[1]                          // AES[2] block - mov high
    eor CTR3.16b, OUT3.16b, CTR3.16b            // AES[3] block - result

    rev64 v7.16b, v7.16b                        // GHASH[0]
    ROUND CTR1.16b, KEY1.16b
    fmov d2, x10                                // CTR[2] block
    ROUND CTR0.16b, KEY0.16b
#ifdef HITLS_BIG_ENDIAN
    rev x21, x21
    rev x22, x22
#endif
    eor v4.16b, v4.16b, HASH0.16b               // PRE 1
    pmull2 v30.1q, v5.2d, HASH3.2d              // GHASH block 4k+1 - high
    fmov CTR2.d[1], x9                          // CTR[2]--OK

    ROUND CTR1.16b, KEY2.16b
    mov x24, CTR3.d[1]                          // AES[3] block - mov high
    ROUND CTR0.16b, KEY1.16b
    mov x23, CTR3.d[0]                          // AES[3] block  - mov low

    pmull2 v9.1q, v4.2d, HASH4.2d               // GHASH block 4k - high
    fmov d3, x10                                // CTR[3]
    mov d8, v4.d[1]                             // GHASH block 4k - mid
    pmull HASH0.1q, v4.1d, HASH4.1d             // GHASH block 4k - low
#ifdef HITLS_BIG_ENDIAN
    rev x23, x23
    rev x24, x24
#endif
    mov d10, v17.d[1]                           // GHASH block 4k - mid
    rev w9, IV_W                                 // CTR[3]
    ROUND CTR2.16b, KEY0.16b
    orr x9, x11, x9, lsl #32                    // CTR[3]
    fmov CTR3.d[1], x9                          // CTR[3]--OK

    eor v8.8b, v8.8b, v4.8b                     // GHASH block 4k - mid
    mov d4, v5.d[1]                             // GHASH block 4k+1 - mid
    ROUND CTR1.16b, KEY3.16b
    ROUND CTR0.16b, KEY2.16b
    eor x22, x22, KEND1                         // AES[2] block - round 12 high

    ROUND CTR2.16b, KEY1.16b
    eor v4.8b, v4.8b, v5.8b                     // GHASH block 4k+1 - mid
    pmull v10.1q, v8.1d, v10.1d                 // GHASH block 4k - mid
    ROUND CTR3.16b, KEY0.16b
    rev64 v6.16b, v6.16b                        // GHASH[2]
    ROUND CTR2.16b, KEY2.16b
    pmull v4.1q, v4.1d, v17.1d                  // GHASH block 4k+1 - mid
    eor HASH0.16b, HASH0.16b, v31.16b           // GHASH block 4k+1 - low
    eor x21, x21, KEND0                         // AES[2] block  - round 12 low

    ROUND CTR1.16b, KEY4.16b
    ROUND CTR0.16b, KEY3.16b
    eor v10.16b, v10.16b, v4.16b                // GHASH block 4k+1 - mid
    mov d31, v6.d[1]                            // GHASH[2] - mid
    ROUND CTR3.16b, KEY1.16b
    eor v9.16b, v9.16b, v30.16b                 // GHASH block 4k+1 - high
    ROUND CTR0.16b, KEY4.16b
    pmull2 v30.1q, v6.2d, HASH2.2d              // GHASH[2] - high
    eor v31.8b, v31.8b, v6.8b                   // GHASH[2] - mid
    pmull v8.1q, v6.1d, HASH2.1d                // GHASH[2] - low
    ROUND CTR0.16b, KEY5.16b
    eor v9.16b, v9.16b, v30.16b                 // GHASH[2] - high
    mov d30, v7.d[1]                            // GHASH[0] - mid
    ROUND CTR1.16b, KEY5.16b
    pmull2 v5.1q, v7.2d, HASH1.2d               // GHASH[0] - high
    ROUND CTR3.16b, KEY2.16b
    eor v30.8b, v30.8b, v7.8b                   // GHASH[0] - mid
    ROUND CTR1.16b, KEY6.16b
    ROUND CTR0.16b, KEY6.16b
    ins v31.d[1], v31.d[0]                      // GHASH[2] - mid
    ROUND CTR3.16b, KEY3.16b
    pmull v30.1q, v30.1d, v16.1d                // GHASH[0] - mid
    eor HASH0.16b, HASH0.16b, v8.16b            // GHASH[2] - low
    ROUND CTR0.16b, KEY7.16b
    pmull2 v31.1q, v31.2d, v16.2d               // GHASH[2] - mid
    eor v9.16b, v9.16b, v5.16b                  // GHASH[0] - high
    ROUND CTR1.16b, KEY7.16b
    ROUND CTR0.16b, KEY8.16b
    movi v8.8b, #0xc2
    pmull v6.1q, v7.1d, HASH1.1d                // GHASH[0] - low
    ROUND CTR1.16b, KEY8.16b
    eor v10.16b, v10.16b, v31.16b               // GHASH[2] - mid
    ROUND CTR2.16b, KEY3.16b
    ROUND CTR0.16b, KEY9.16b
    eor HASH0.16b, HASH0.16b, v6.16b            // GHASH[0] - low
    ROUND CTR3.16b, KEY4.16b
    ROUND CTR2.16b, KEY4.16b
    eor v10.16b, v10.16b, v30.16b               // GHASH[0] - mid
    ROUND CTR0.16b, KEY10.16b
    ROUND CTR1.16b, KEY9.16b
    eor v30.16b, HASH0.16b, v9.16b              // MODULO - karatsuba tidy up
    ROUND CTR2.16b, KEY5.16b
    ROUND CTR3.16b, KEY5.16b
    shl d8, d8, #56                             // mod_constant
    ROUND CTR1.16b, KEY10.16b
    ROUND CTR2.16b, KEY6.16b
    ld1 {OUT0.16b}, [INPUT], #16                // AES load[0] ciphertext
    ROUND CTR3.16b, KEY6.16b
    eor v10.16b, v10.16b, v30.16b               // MODULO - karatsuba tidy up
    pmull v31.1q, v9.1d, v8.1d                  // MODULO - top 64b align with mid
    ld1 {OUT1.16b}, [INPUT], #16                // AES load[1] ciphertext
    eor x23, x23, KEND0                         // AES[3] block - round 12 low
    ROUND CTR2.16b, KEY7.16b
    ext v9.16b, v9.16b, v9.16b, #8              // MODULO - other top alignment
    aese CTR0.16b, KEY11.16b
    add IV_W, IV_W, #1                            // CTR++
    ROUND CTR3.16b, KEY7.16b
    eor v10.16b, v10.16b, v31.16b               // MODULO - fold into mid
    ld1 {OUT2.16b}, [INPUT], #16                // AES load[2] ciphertext
    ROUND CTR2.16b, KEY8.16b
    aese CTR1.16b, KEY11.16b
    ld1 {OUT3.16b}, [INPUT], #16                // AES load[3] ciphertext
    rev w9, IV_W                                 // CTR block 4k+8
    ROUND CTR3.16b, KEY8.16b

    stp x21, x22, [OUT00], #16                  // AES[2] block - store result
    ROUND CTR2.16b, KEY9.16b
    eor v10.16b, v10.16b, v9.16b                // MODULO - fold into mid

    subs COUNT, COUNT, #1                       // COUNT--
    eor CTR0.16b, OUT0.16b, CTR0.16b            // AES[0] block - result
    eor x24, x24, KEND1                         // AES[3] block - round 12 high
    eor CTR1.16b, OUT1.16b, CTR1.16b            // AES[1] block - result
    ROUND CTR2.16b, KEY10.16b
    orr x9, x11, x9, lsl #32                    // CTR block 4k+8
    ROUND CTR3.16b, KEY9.16b
    pmull v8.1q, v10.1d, v8.1d                  // MODULO - mid 64b align with low
    mov x19, CTR1.d[0]                          // AES[1] block - mov low
    mov x6, CTR0.d[0]                           // AES[0] block - mov low

    stp x23, x24, [OUT00], #16                  // AES[3] - store result
    rev64 v5.16b, v5.16b                        // GHASH[2]
    aese CTR2.16b, KEY11.16b
    mov x7, CTR0.d[1]                           // AES[0] block - mov high
    ROUND CTR3.16b, KEY10.16b
    mov x20, CTR1.d[1]                          // AES[1] block - mov high
#ifdef HITLS_BIG_ENDIAN
    rev x6, x6
    rev x7, x7
    rev x19, x19
    rev x20, x20
#endif
    fmov d0, x10                                // CTR[0]
    add IV_W, IV_W, #1                            // CTR++
    ext v10.16b, v10.16b, v10.16b, #8           // MODULO - other mid alignment
    eor CTR2.16b, OUT2.16b, CTR2.16b            // AES[2] block - result
    fmov CTR0.d[1], x9                            // CTR[0]--OK
    rev w9, IV_W                                 // CTR block 4k+9
    eor x6, x6, KEND0                           // AES[0] block - round 12 low
    orr x9, x11, x9, lsl #32                    // CTR block 4k+9
    eor HASH0.16b, HASH0.16b, v8.16b            // MODULO - fold into low
    fmov d1, x10                                // CTR[1]
    add IV_W, IV_W, #1                            // CTR++
    eor x19, x19, KEND0                         // AES[1] block - round 12 low
    fmov CTR1.d[1], x9                          // CTR[1]--OK
    rev w9, IV_W                                 // CTR block 4k+10
    eor x20, x20, KEND1                         // AES[2] - round 12 high
    eor x7, x7, KEND1                           // AES[0] - round 12 high

    stp x6, x7, [OUT00], #16                    // AES[0] block - store result
    eor HASH0.16b, HASH0.16b, v10.16b           // MODULO - fold into low
    add IV_W, IV_W, #1                            // CTR++
    rev64 v4.16b, v4.16b                        // GHASH[1]
    orr x9, x11, x9, lsl #32                    // CTR block 4k+10
    aese CTR3.16b, KEY11.16b                    // AES[3] round 11
    stp x19, x20, [OUT00], #16                  // AES[1] block - store result
.endm

#endif
