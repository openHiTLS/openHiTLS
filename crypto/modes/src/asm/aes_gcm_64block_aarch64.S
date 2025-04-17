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

#include "crypt_arm.h"
#include "aes_gcm_common_aarch64.S"
#include "aes128_gcm_aarch64.S"
#include "aes192_gcm_aarch64.S"
#include "aes256_gcm_aarch64.S"

.text
.arch armv8-a+crypto

.globl AES_GCM_ClearAsm
.type AES_GCM_ClearAsm,%function
.align 4
AES_GCM_ClearAsm:
AARCH64_PACIASP
    eor KEY0.16b, KEY0.16b, KEY0.16b
    eor KEY1.16b, KEY1.16b, KEY1.16b
    eor KEY2.16b, KEY2.16b, KEY2.16b
    eor KEY3.16b, KEY3.16b, KEY3.16b
    eor KEY4.16b, KEY4.16b, KEY4.16b
    eor KEY5.16b, KEY5.16b, KEY5.16b
    eor KEY6.16b, KEY6.16b, KEY6.16b
    eor KEY7.16b, KEY7.16b, KEY7.16b
    eor KEY8.16b, KEY8.16b, KEY8.16b
    eor KEY9.16b, KEY9.16b, KEY9.16b
    eor KEY10.16b, KEY10.16b, KEY10.16b
    eor HASH0.16b, HASH0.16b, HASH0.16b
    eor HASH1.16b, HASH1.16b, HASH1.16b
    eor HASH2.16b, HASH2.16b, HASH2.16b
    eor HASH3.16b, HASH3.16b, HASH3.16b
    eor HASH4.16b, HASH4.16b, HASH4.16b
AARCH64_AUTIASP
    ret
.size AES_GCM_ClearAsm,.-AES_GCM_ClearAsm

.globl AES_GCM_EncryptBlockAsm
.type AES_GCM_EncryptBlockAsm,%function
.align 4
AES_GCM_EncryptBlockAsm:
AARCH64_PACIASP
    IN_STP                                      // Register Protection
    ldr ROUNDS, [KEY00, #240]                   // Number of loading rounds
    add HTABLE, IVEC0, #16                      // Sets the gHash start address.
    lsr COUNT, INLEN, #6                        // Divided by 64, count the number of times
    cmp ROUNDS, #10                             // Number of comparison rounds 10
    LOAD_KEY                                    // load AES KEY
    b.eq .LEnc_128_process                      // go to AES128 processing part
    cmp ROUNDS, #12                             // Number of comparison rounds 12
    ld1 {KEY10.4s, KEY11.4s}, [KEY00], #32
    b.eq .LEnc_192_process                      // go to AES192 processing part
    ld1 {KEY12.4s, KEY13.4s}, [KEY00], #32
    b .LEnc_256_process                         // go to AES256 processing part

.LEnc_128_process:
    ldp KEND0, KEND1, [KEY00]                   // load key-10
    ldp IV_H, IV_L, [IVEC0]                     // load IV
#ifdef HITLS_BIG_ENDIAN
    ror KEND0, KEND0, #32
    ror KEND1, KEND1, #32
    REV_2S IV_H, IV_L
#endif
    lsr IV_C, IV_L, #32
    ld1 {CTR0.16b}, [IVEC0]                                         // CTR bolck 0
    lsl IVCTR, COUNTW, #2                                               // <<16
    LOAD_GHASH_TABLE                            // load gHashTable
    BEFORE_ROUND
    FIRST_ROUND                                 // data preprocessing
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY7.16b         // round 7
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY8.16b         // round 8
    rev w9, IV_W                                                    // CTR0--Start
    ROUND4_END CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY9.16b     // round 9
    orr x9, x11, x9, lsl #32                                        // CTR0 block 4k+8
    add IV_W, IV_W, #1                                              // CTR0++
    eor v17.16b, v17.16b, v9.16b                                    // h4k | h3k
    eor v16.16b, v16.16b, v8.16b                                    // h2k | h1k
    STORE_RESULT                                // data preprocessing
    b.le .LEnc_end                              // After the first 64-byte processing is complete,
                                                // check the remaining length.
    b .LEnc_128_loop                            // Enter the cyclic processing flow.

.LEnc_192_process:
    ldp KEND0, KEND1, [KEY00]                                       // load key-10
    ldp IV_H, IV_L, [IVEC0]                                         // load IV
#ifdef HITLS_BIG_ENDIAN
    ror KEND0, KEND0, #32
    ror KEND1, KEND1, #32
    REV_2S IV_H, IV_L
#endif
    lsr IV_C, IV_L, #32                                             // IV-l
    ld1 {CTR0.16b}, [IVEC0]                                         // CTR bolck 0
    lsl IVCTR, COUNTW, #2                                               // <<16
    LOAD_GHASH_TABLE                                                // load hash table
    BEFORE_ROUND
    FIRST_ROUND                                                     // aes round
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY7.16b         // round 7
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY8.16b         // round 8
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY9.16b         // round 9
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY10.16b        // round 10
    rev w9, IV_W                                                     // CTR0--Start
    ROUND4_END CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY11.16b    // round 11
    orr x9, x11, x9, lsl #32                                        // CTR0 block 4k+8
    add IV_W, IV_W, #1                                                // CTR0++
    eor v17.16b, v17.16b, v9.16b                                    // h4k | h3k
    eor v16.16b, v16.16b, v8.16b                                    // h2k | h1k
    STORE_RESULT
    b.le .LEnc_end
    b .LEnc_192_loop

.LEnc_256_process:
    ldp KEND0, KEND1, [KEY00]                                       // load key-10
    ldp IV_H, IV_L, [IVEC0]                                         // load IV
#ifdef HITLS_BIG_ENDIAN
    ror KEND0, KEND0, #32
    ror KEND1, KEND1, #32
    REV_2S IV_H, IV_L
#endif
    lsr IV_C, IV_L, #32
    ld1 {CTR0.16b}, [IVEC0]                                         // CTR bolck 0
    lsl IVCTR, COUNTW, #2                                           // <<16
    LOAD_GHASH_TABLE
    BEFORE_ROUND
    FIRST_ROUND
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY7.16b         // round 7
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY8.16b         // round 8
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY9.16b         // round 9
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY10.16b        // round 10
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY11.16b        // round 11
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY12.16b        // round 12
    rev w9, IV_W                                                     // CTR0--Start
    ROUND4_END CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY13.16b    // round 13
    orr x9, x11, x9, lsl #32                                        // CTR0 block 4k+8
    add IV_W, IV_W, #1                                                // CTR0++
    eor v17.16b, v17.16b, v9.16b                                    // h4k | h3k
    eor v16.16b, v16.16b, v8.16b                                    // h2k | h1k
    STORE_RESULT
    b.le .LEnc_end
    b .LEnc_256_loop

.LEnc_128_loop:
    GCM_ENC128_LOOP                         // Processes 64 bytes.
    b.le .LEnc_end                          // If the number of remaining blocks is 0, exit the loop.
    b .LEnc_128_loop                        // Continue the loop

.LEnc_192_loop:
    GCM_ENC192_LOOP
    b.le .LEnc_end                          // <= 0
    b .LEnc_192_loop

.LEnc_256_loop:
    GCM_ENC256_LOOP
    b.le .LEnc_end                          // <= 0
    b .LEnc_256_loop

.LEnc_end:
    rev64 OUT0.16b, OUT0.16b                // GHASH block 4k (only t0 is free)
    rev64 OUT1.16b, OUT1.16b                // GHASH block 4k+1 (t0 and t1 free)
    rev64 OUT2.16b, OUT2.16b                // GHASH[2] (t0, t1, and t2 free)
    rev64 OUT3.16b, OUT3.16b                // GHASH[0] (t0, t1, t2 and t3 free)
    GHASH_BLOCK                             // Ghash calculation and encryption/decryption processing
    rev w9, IVCTR                           // CTR[0]
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8
    add x6, IVEC0, #16
    orr x9, x11, x9, lsl #32                // CTR[0]
    fmov d0, x10                            // CTR[0]
    fmov CTR0.d[1], x9                      // CTR[0]--OK
    st1 {CTR0.16b }, [IVEC0]                // out hash
    rev64 HASH0.16b, HASH0.16b
    st1 {HASH0.16b }, [x6]                  // out hash
    OUT_STP
.LEnc_ret:
    and x0, INLEN, #-64                     // length of processed data
AARCH64_AUTIASP
    ret
.size AES_GCM_EncryptBlockAsm,.-AES_GCM_EncryptBlockAsm

.globl AES_GCM_DecryptBlockAsm
.type AES_GCM_DecryptBlockAsm,%function
.align 4
AES_GCM_DecryptBlockAsm:
AARCH64_PACIASP
    IN_STP                                                           // stp
    ldr ROUNDS, [KEY00, #240]                                       // pull rounds
    mov IVEC0, x0                                                   // ctr0
    add HTABLE, IVEC0, #16                                          // htable
    lsr COUNT, INLEN, #6                                            // divided by 64
    cmp ROUNDS, #10
    LOAD_KEY
    b.eq .LDec_128_process
    cmp ROUNDS, #12
    ld1 {KEY10.4s, KEY11.4s}, [KEY00], #32
    b.eq .LDec_192_process
    ld1 {KEY12.4s, KEY13.4s}, [KEY00], #32
    b .LDec_256_process

.LDec_128_process:
    ldp KEND0, KEND1, [KEY00]                                       // load key-10
    ldp IV_H, IV_L, [IVEC0]                                         // load IV
#ifdef HITLS_BIG_ENDIAN
    ror KEND0, KEND0, #32
    ror KEND1, KEND1, #32
    REV_2S IV_H, IV_L
#endif
    lsr IV_C, IV_L, #32
    ld1 {CTR0.16b}, [IVEC0]                                         // CTR[0]
#ifdef HITLS_BIG_ENDIAN
    REV_2S KEND0, KEND1
#endif
    lsl IVCTR, COUNTW, #2                                           // <<16
    LOAD_GHASH_TABLE
    BEFORE_ROUND
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY0.16b         // round 0
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY1.16b         // round 1
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY2.16b         // round 2
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY3.16b         // round 3
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY4.16b         // round 4
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY5.16b         // round 5
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY6.16b         // round 6
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY7.16b         // round 7
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY8.16b         // round 8
    ROUND4_END CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY9.16b     // round 9
    eor v17.16b, v17.16b, v9.16b                                    // h4k | h3k
    eor v16.16b, v16.16b, v8.16b                                    // h2k | h1k
    STORE_DEC_RESULT
    b.le .LDec_end
    b .LDec_128_loop

.LDec_192_process:
    ldp KEND0, KEND1, [KEY00]                                       // load key-10
    ldp IV_H, IV_L, [IVEC0]                                         // load IV
#ifdef HITLS_BIG_ENDIAN
    ror KEND0, KEND0, #32
    ror KEND1, KEND1, #32
    REV_2S IV_H, IV_L
#endif
    lsr IV_C, IV_L, #32
    ld1 {CTR0.16b}, [IVEC0]                                         // CTR[0]
#ifdef HITLS_BIG_ENDIAN
    REV_2S KEND0, KEND1
#endif
    lsl IVCTR, COUNTW, #2                                           // <<16
    LOAD_GHASH_TABLE
    BEFORE_ROUND
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY0.16b         // round 0
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY1.16b         // round 1
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY2.16b         // round 2
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY3.16b         // round 3
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY4.16b         // round 4
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY5.16b         // round 5
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY6.16b         // round 6
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY7.16b         // round 7
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY8.16b         // round 8
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY9.16b         // round 9
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY10.16b        // round 10
    ROUND4_END CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY11.16b    // round 11
    eor v17.16b, v17.16b, v9.16b                                    // h4k | h3k
    eor v16.16b, v16.16b, v8.16b                                    // h2k | h1k
    STORE_DEC_RESULT
    b.le .LDec_end
    b .LDec_192_loop

.LDec_256_process:
    ldp KEND0, KEND1, [KEY00]                                       // load key-10
    ldp IV_H, IV_L, [IVEC0]                                         // load IV
#ifdef HITLS_BIG_ENDIAN
    ror KEND0, KEND0, #32
    ror KEND1, KEND1, #32
    REV_2S IV_H, IV_L
#endif
    lsr IV_C, IV_L, #32
    ld1 {CTR0.16b}, [IVEC0]                                         // CTR[0]
#ifdef HITLS_BIG_ENDIAN
    REV_2S KEND0, KEND1
#endif
    lsl IVCTR, COUNTW, #2                                           // <<16
    LOAD_GHASH_TABLE
    BEFORE_ROUND

    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY0.16b         // round 0
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY1.16b         // round 1
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY2.16b         // round 2
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY3.16b         // round 3
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY4.16b         // round 4
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY5.16b         // round 5
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY6.16b         // round 6
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY7.16b         // round 7
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY8.16b         // round 8
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY9.16b         // round 9
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY10.16b        // round 10
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY11.16b        // round 11
    ROUND4 CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY12.16b        // round 12
    ROUND4_END CTR2.16b, CTR1.16b, CTR3.16b, CTR0.16b, KEY13.16b    // round 13
    eor v17.16b, v17.16b, v9.16b                                    // h4k | h3k
    eor v16.16b, v16.16b, v8.16b                                    // h2k | h1k
    STORE_DEC_RESULT
    b.le .LDec_end
    b .LDec_256_loop

.LDec_128_loop:
    GCM_DEC128_LOOP
    b.le .LDec_end                              // <=0
    b .LDec_128_loop

.LDec_192_loop:
    GCM_DEC192_LOOP
    b.le .LDec_end                              // <=0
    b .LDec_192_loop

.LDec_256_loop:
    GCM_DEC256_LOOP
    b.le .LDec_end                              // <=0
    b .LDec_256_loop

.LDec_end:
    GHASH_DEC_BLOCK
    rev w9, IVCTR                          // CTR[0]
    ext HASH0.16b, HASH0.16b, HASH0.16b, #8
    add x6, IVEC0, #16
    orr x9, x11, x9, lsl #32            // CTR[0]
    fmov d0, x10                        // CTR[0]
    rev64 HASH0.16b, HASH0.16b
    fmov CTR0.d[1], x9                  // CTR[0]--OK
    st1 {CTR0.16b }, [IVEC0]            // out hash
    st1 {HASH0.16b }, [x6]              // out hash
    OUT_STP
.LDec_ret:
    and x0, INLEN, #-64                     // length of processed data
AARCH64_AUTIASP
    ret
.size AES_GCM_DecryptBlockAsm,.-AES_GCM_DecryptBlockAsm
#endif