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

.text
.arch armv8-a+crypto

.globl AES_GCM_Encrypt16BlockAsm
.type AES_GCM_Encrypt16BlockAsm,%function
.align 4
AES_GCM_Encrypt16BlockAsm:
AARCH64_PACIASP
    IN_STP                                  // register Protection
    ldr ROUNDS, [KEY00, #240]               // load number of rounds
    add HTABLE, IVEC0, #16                  // obtains the start address of the ghash table
    lsr COUNT, INLEN, #4                    // length divided by 16
    LOAD_GHASH_TABLE                        // load the ghash table
    cmp ROUNDS, #10                         // number of comparison rounds 10
    LOAD_KEY                                // load AES KEY
    b.eq .LEnc16_128_process                // go to the AES128 part
    cmp ROUNDS, #12                         // number of comparison rounds 12
    ld1 {KEY10.4s, KEY11.4s}, [KEY00], #32
    b.eq .LEnc16_192_process                // go to the AES192 part
    ld1 {KEY12.4s, KEY13.4s}, [KEY00], #32
    b .LEnc16_256_process                   // go to the AES256 part

.LEnc16_128_process:
    BEFORE16_ROUND                          // data preprocessing
.LEnc16_128_loop:
    FIRST16_ROUND                           // data preprocessing
    ldp x6, x7, [INPUT], #16                // load INPUT 0
#ifdef HITLS_BIG_ENDIAN
    REV_2S x6, x7
#endif
    aese CTR0.16b, KEY9.16b
    subs COUNT, COUNT, #1                   // COUNT--
    ENC16_BLOCK                             // processes 16-byte data
    b.le .LEnc16_end
    b .LEnc16_128_loop

.LEnc16_192_process:
    BEFORE16_ROUND
.LEnc16_192_loop:
    FIRST16_ROUND
    ldp x6, x7, [INPUT], #16                // load INPUT 0
#ifdef HITLS_BIG_ENDIAN
    REV_2S x6, x7
#endif
    ROUND CTR0.16b, KEY9.16b
    ROUND CTR0.16b, KEY10.16b
    aese CTR0.16b, KEY11.16b
    subs COUNT, COUNT, #1                   // COUNT--
    ENC16_BLOCK
    b.le .LEnc16_end
    b .LEnc16_192_loop

.LEnc16_256_process:
    BEFORE16_ROUND
.LEnc16_256_loop:
    FIRST16_ROUND
    ldp x6, x7, [INPUT], #16                // load INPUT 0
#ifdef HITLS_BIG_ENDIAN
    REV_2S x6, x7
#endif
    ROUND CTR0.16b, KEY9.16b
    ROUND CTR0.16b, KEY10.16b
    ROUND CTR0.16b, KEY11.16b
    ROUND CTR0.16b, KEY12.16b
    aese CTR0.16b, KEY13.16b
    subs COUNT, COUNT, #1                   // COUNT--
    ENC16_BLOCK
    b.le .LEnc16_end
    b .LEnc16_256_loop
.LEnc16_end:
    ext	HASH0.16b, HASH0.16b, HASH0.16b, #8
    add x6, IVEC0, #16
    rev64 HASH0.16b, HASH0.16b
    st1 {CTR1.16b }, [IVEC0]                // out counter
    st1 {HASH0.16b }, [x6]                  // out hash
    OUT_STP                                 // restore protection register
.LEnc_ret:
    mov w0, #0x0
AARCH64_AUTIASP
    ret
.size AES_GCM_Encrypt16BlockAsm,.-AES_GCM_Encrypt16BlockAsm

.globl AES_GCM_Decrypt16BlockAsm
.type AES_GCM_Decrypt16BlockAsm,%function
.align 4
AES_GCM_Decrypt16BlockAsm:
AARCH64_PACIASP
    IN_STP                                              // stp
    ldr ROUNDS, [KEY00, #240]                           // pull rounds
    mov IVEC0, x0                                       // ctr0
    add HTABLE, IVEC0, #16                              // htable
    lsr COUNT, INLEN, #4                                // 2*2 2*2 = 16
    LOAD_GHASH_TABLE
    cmp ROUNDS, #10
    LOAD_KEY
    b.eq .LDec16_128_process
    cmp ROUNDS, #12
    ld1 {KEY10.4s, KEY11.4s}, [KEY00], #32
    b.eq .LDec16_192_process
    ld1 {KEY12.4s, KEY13.4s}, [KEY00], #32
    b .LDec16_256_process

.LDec16_128_process:
    BEFORE16_ROUND
#ifdef HITLS_BIG_ENDIAN
    REV_2S KEND0, KEND1
#endif

.LDec16_128_loop:
    FIRST16_ROUND
    aese CTR0.16b, KEY9.16b
    DEC16_BLOCK
    b.le .LDec16_end
    b .LDec16_128_loop

.LDec16_192_process:
    BEFORE16_ROUND
#ifdef HITLS_BIG_ENDIAN
    REV_2S KEND0, KEND1
#endif

.LDec16_192_loop:
    FIRST16_ROUND
    ROUND CTR0.16b, KEY9.16b
    ROUND CTR0.16b, KEY10.16b
    aese CTR0.16b, KEY11.16b
    DEC16_BLOCK
    b.le .LDec16_end
    b .LDec16_192_loop

.LDec16_256_process:
    BEFORE16_ROUND
#ifdef HITLS_BIG_ENDIAN
    REV_2S KEND0, KEND1
#endif

.LDec16_256_loop:
    FIRST16_ROUND
    ROUND CTR0.16b, KEY9.16b
    ROUND CTR0.16b, KEY10.16b
    ROUND CTR0.16b, KEY11.16b
    ROUND CTR0.16b, KEY12.16b
    aese CTR0.16b, KEY13.16b
    DEC16_BLOCK
    b.le .LDec16_end
    b .LDec16_256_loop
.LDec16_end:
    ext	HASH0.16b, HASH0.16b, HASH0.16b, #8
    add x6, IVEC0, #16
    rev64 HASH0.16b, HASH0.16b
    st1 {CTR1.16b }, [IVEC0]                                    // out counter
    st1 {HASH0.16b }, [x6]                                      // out hash
    OUT_STP
.LDec_ret:
    mov w0, #0x0
AARCH64_AUTIASP
    ret
.size AES_GCM_Decrypt16BlockAsm,.-AES_GCM_Decrypt16BlockAsm
#endif