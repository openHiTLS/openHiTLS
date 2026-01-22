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
#ifdef HITLS_CRYPTO_SHA256

#include "crypt_arm.h"

    .arch    armv8-a+crypto

/* sha256 used constant value. For the data source, see the RFC4634 document. */
.extern	g_cryptArmCpuInfo
.hidden	g_cryptArmCpuInfo
.section .rodata
.balign 64
.K256:
    .long    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .long    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .long    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .long    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .long    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .long    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .long    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .long    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

/*
 *  Macro description: updates the 32-bit plaintext information. W
 *  Input register：
 *      wi_16： W[i-16]
 *      wi_15： W[i-15]
 *      wi_7： W[i-7]
 *      wi_2： W[i-2]
 *  Modify the register： wi_16 w17 w28
 *  Output register：
 *      wi_16： Latest W[i] value, W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
 *  Function/Macro Call：None
 */
    .macro  UPDATE_W        wi_16, wi_15, wi_7, wi_2
    ror     w28, \wi_15, #7
    ror     w17, \wi_2, #17
    eor     w28, w28, \wi_15, ror#18
    eor     w17, w17, \wi_2, ror#19
    eor     w28, w28, \wi_15, lsr#3     // w28 = sigma0(w[i-15])
    eor     w17, w17, \wi_2, lsr#10     // w17 = sigma1(W[i-2])
    add     \wi_16, \wi_16, \wi_7       // + W[i-7]
    add     \wi_16, \wi_16, w28         // + sigma0(w[i-15])
    add     \wi_16, \wi_16, w17         // + sigma1(W[i-2])
    .endm

/*
 *  Macro description: Processes the update of a round of hash values in 64 rounds of compression.
 *  Input register：
 *        x19： Point to the address of the corresponding element in the g_k256 constant
 *         wi： Plaintext data after processing
 *      a - h： Intermediate variable of hash value
 *  Modify the register： h d w16 w17 w28 w29
 *  Output register：
 *          h： Indicates the value after a cyclic update.
 *          d： Indicates the value after a cyclic update.
 *  Function/Macro Call：None
 */
    .macro ONE_ROUND         wi, a, b, c, d, e, f, g, h
    ldr    w16, [x19], #4           // K[i]
    and    w17, \f, \e              // e&f
    bic    w28, \g, \e              // g&(~e)
    add    \h, \h, w16              // h += K[i]
    eor    w29, \e, \e, ror#14
    ror    w16, \e, #6
    orr    w17, w17, w28            // Ch(e, f, g) = e&f | g&(~e)
    add    \h, \h, \wi              // h += W[i]
    eor    w29, w16, w29, ror#11    // Sigma1(e) = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)
    eor    w28, \a, \c              // a^c
    eor    w16, \a, \b              // a^b
    add    \h, \h, w29              // h += Sigma1(e)
    and    w28, w28, w16            // (a^b)&(a^c)
    eor    w29, \a, \a, ror#9
    add    \h, \h, w17              // h += Ch(e, f, g)
    eor    w28, w28, \a             // Maj(a, b, c) = ((a^b)&(a^c))^a = (a&b)^(b&c)^(a&c)
    ror    w16, \a, #2
    add    \d, \d, \h               // d += h
    add    \h, \h, w28              // h += Maj(a, b, c)
    eor    w29, w16, w29, ror#13    // Sigma0(a) = ROR(a, 2)^ROR(a, 13)^ROR(a, 22)
    add    \h, \h, w29              // h += Sigma0(a)
    .endm

/*
 *  Function Description：Performs 64 rounds of compression calculation based on the input plaintext data
 *                        and updates the hash value.
 *  Function prototype：void SHA256CompressMultiBlocks(uint32_t hash[8], const uint8_t *in, uint32_t num);
 *  Input register：
 *         x0： Storage address of the hash value
 *         x1： Pointer to the input data address
 *         x2： Number of 64 rounds of cycles
 *  Modify the register： x0-x17
 *  Output register： None
 *  Function/Macro Call： None
 *
 */
    .text
    .balign 16
    .global SHA256CompressMultiBlocks
    .type SHA256CompressMultiBlocks, %function
SHA256CompressMultiBlocks:
    cbz     x2, .Lend_sha256
    /* If the SHA256 cryptography extension instruction is supported, go to. */
    adrp    x5, g_cryptArmCpuInfo
    ldr	    w6, [x5, #:lo12:g_cryptArmCpuInfo]
    tst     w6, #CRYPT_ARM_SHA256
    bne     SHA256CryptoExt
    /* Extension instructions are not supported. Base instructions are used. */
    stp     x29, x30, [sp, #-112]!
    add     x29, sp, #0
    stp     x19, x20, [sp, #8*2]
    stp     x21, x22, [sp, #8*4]
    stp     x23, x24, [sp, #8*6]
    stp     x25, x26, [sp, #8*8]
    stp     x27, x28, [sp, #8*10]

    /* load a - h */
    ldp     w20, w21, [x0]
    ldp     w22, w23, [x0, #4*2]
    ldp     w24, w25, [x0, #4*4]
    ldp     w26, w27, [x0, #4*6]

    str     x0, [sp, #96]
    mov     x16, x1     // Enter Value Address
    lsl     x30, x2, #6 // Number of times to process 2^6 = 64

    /* w0-w15 are used to record input values W[i] and temporary registers */
.Lloop_compress_64:

    /* Start a 64-round process */
    sub     x30, x30, #16
    adrp    x19, .K256
    add	    x19, x19, :lo12:.K256
    /* 8 bytes are loaded each time, and then two rounds are processed. */
    ldp     w0, w1, [x16] // load input value
    ldp     w2, w3, [x16, #4*2]
    ldp     w4, w5, [x16, #4*4]
    ldp     w6, w7, [x16, #4*6]
    ldp     w8, w9, [x16, #4*8]
    ldp     w10, w11, [x16, #4*10]
    ldp     w12, w13, [x16, #4*12]
    ldp     w14, w15, [x16, #4*14]

    add     x16, x16, #64
    str     x16, [sp, #104]
#ifndef	HITLS_BIG_ENDIAN
    rev     w0, w0
    rev     w1, w1
    rev     w2, w2
    rev     w3, w3
    rev     w4, w4
    rev     w5, w5
    rev     w6, w6
    rev     w7, w7
    rev     w8, w8
    rev     w9, w9
    rev     w10, w10
    rev     w11, w11
    rev     w12, w12
    rev     w13, w13
    rev     w14, w14
    rev     w15, w15
#endif
    /* w16 w17 w28 w29 used as a temporary register */
    ONE_ROUND   w0, w20, w21, w22, w23, w24, w25, w26, w27
    ONE_ROUND   w1, w27, w20, w21, w22, w23, w24, w25, w26
    ONE_ROUND   w2, w26, w27, w20, w21, w22, w23, w24, w25
    ONE_ROUND   w3, w25, w26, w27, w20, w21, w22, w23, w24

    ONE_ROUND   w4, w24, w25, w26, w27, w20, w21, w22, w23
    ONE_ROUND   w5, w23, w24, w25, w26, w27, w20, w21, w22
    ONE_ROUND   w6, w22, w23, w24, w25, w26, w27, w20, w21
    ONE_ROUND   w7, w21, w22, w23, w24, w25, w26, w27, w20

    ONE_ROUND   w8, w20, w21, w22, w23, w24, w25, w26, w27
    ONE_ROUND   w9, w27, w20, w21, w22, w23, w24, w25, w26
    ONE_ROUND   w10, w26, w27, w20, w21, w22, w23, w24, w25
    ONE_ROUND   w11, w25, w26, w27, w20, w21, w22, w23, w24

    ONE_ROUND   w12, w24, w25, w26, w27, w20, w21, w22, w23
    ONE_ROUND   w13, w23, w24, w25, w26, w27, w20, w21, w22
    ONE_ROUND   w14, w22, w23, w24, w25, w26, w27, w20, w21
    ONE_ROUND   w15, w21, w22, w23, w24, w25, w26, w27, w20

.Lloop_compress_16_63:
    /* Start 16-31, 32-47, 48-63 compression */
    sub     x30, x30, #16

    /* 0 */
    UPDATE_W    w0, w1, w9, w14
    ONE_ROUND   w0, w20, w21, w22, w23, w24, w25, w26, w27

    /* 1 */
    UPDATE_W    w1, w2, w10, w15
    ONE_ROUND   w1, w27, w20, w21, w22, w23, w24, w25, w26

    /* 2 */
    UPDATE_W    w2, w3, w11, w0
    ONE_ROUND   w2, w26, w27, w20, w21, w22, w23, w24, w25

    /* 3 */
    UPDATE_W    w3, w4, w12, w1
    ONE_ROUND   w3, w25, w26, w27, w20, w21, w22, w23, w24

    /* 4 */
    UPDATE_W    w4, w5, w13, w2
    ONE_ROUND   w4, w24, w25, w26, w27, w20, w21, w22, w23

    /* 5 */
    UPDATE_W    w5, w6, w14, w3
    ONE_ROUND   w5, w23, w24, w25, w26, w27, w20, w21, w22

    /* 6 */
    UPDATE_W    w6, w7, w15, w4
    ONE_ROUND   w6, w22, w23, w24, w25, w26, w27, w20, w21

    /* 7 */
    UPDATE_W    w7, w8, w0, w5
    ONE_ROUND   w7, w21, w22, w23, w24, w25, w26, w27, w20

    /* 8 */
    UPDATE_W    w8, w9, w1, w6
    ONE_ROUND   w8, w20, w21, w22, w23, w24, w25, w26, w27

    /* 9 */
    UPDATE_W    w9, w10, w2, w7
    ONE_ROUND   w9, w27, w20, w21, w22, w23, w24, w25, w26

    /* 10 */
    UPDATE_W    w10, w11, w3, w8
    ONE_ROUND   w10, w26, w27, w20, w21, w22, w23, w24, w25

    /* 11 */
    UPDATE_W    w11, w12, w4, w9
    ONE_ROUND   w11, w25, w26, w27, w20, w21, w22, w23, w24

    /* 12 */
    UPDATE_W    w12, w13, w5, w10
    ONE_ROUND   w12, w24, w25, w26, w27, w20, w21, w22, w23

    /* 13 */
    UPDATE_W    w13, w14, w6, w11
    ONE_ROUND   w13, w23, w24, w25, w26, w27, w20, w21, w22

    /* 14 */
    UPDATE_W    w14, w15, w7, w12
    ONE_ROUND   w14, w22, w23, w24, w25, w26, w27, w20, w21

    /* 15 */
    UPDATE_W    w15, w0, w8, w13
    ONE_ROUND   w15, w21, w22, w23, w24, w25, w26, w27, w20

    /* If the processing length is less than 64 bytes, the loop continues. */
    tst     x30, #63
    bne     .Lloop_compress_16_63

    /* Stores a - h information. */
    ldr     x0, [sp, #96]

    ldp     w10, w11, [x0]
    ldp     w12, w13, [x0, #4*2]
    ldp     w14, w15, [x0, #4*4]
    ldp     w16, w17, [x0, #4*6]

    add     w20, w20, w10
    add     w21, w21, w11
    add     w22, w22, w12
    add     w23, w23, w13
    stp     w20, w21, [x0]
    add     w24, w24, w14
    add     w25, w25, w15
    stp     w22, w23, [x0, #4*2]
    add     w26, w26, w16
    add     w27, w27, w17
    stp     w24, w25, [x0, #4*4]
    stp     w26, w27, [x0, #4*6]

    ldr     x16, [sp, #104]
    /* If the remaining length is not processed, the processing continues for 64 rounds. */
    cbnz    x30, .Lloop_compress_64

    /* The function returns */
    ldp     x19, x20, [sp, #8*2]
    ldp     x21, x22, [sp, #8*4]
    ldp     x23, x24, [sp, #8*6]
    ldp     x25, x26, [sp, #8*8]
    ldp     x27, x28, [sp, #8*10]
    ldp     x29, x30, [sp], #112
.Lend_sha256:
    ret
    .size SHA256CompressMultiBlocks, .-SHA256CompressMultiBlocks

/*
 *  Function Description：Performs 64 rounds of compression calculation based on the input plaintext data
 *                        and updates the hash value
 *  Function prototype：void SHA256CryptoExt(uint32_t hash[8], const uint8_t *in, uint32_t num);
 *  Input register：
 *         x0： Storage address of the hash value
 *         x1： Pointer to the input data address
 *         x2： Number of 64 rounds of cycles
 *  Modify the register： x1-x4, v0-v5, v16-v23
 *  Output register： None
 *  Function/Macro Call： None
 *
 */
    .text
    .balign 16
    .type SHA256CryptoExt, %function
SHA256CryptoExt:
    ld1     {v4.4s-v5.4s}, [x0]
.Lloop_compress_64_ext:
    adrp    x4, .K256
    add	    x4, x4, :lo12:.K256
    sub     x2, x2, #1
    /* 0-15 */
    ld1     {v16.16b-v19.16b}, [x1], #64

    mov     v0.16b, v4.16b
    mov     v1.16b, v5.16b

    rev32       v16.16b, v16.16b
    ld1         {v20.4s}, [x4], #16
    rev32       v17.16b, v17.16b
    ld1         {v21.4s}, [x4], #16
    rev32       v18.16b, v18.16b
    ld1         {v22.4s}, [x4], #16

    add         v20.4s, v20.4s, v16.4s

    rev32       v19.16b, v19.16b
    ld1         {v23.4s}, [x4], #16

    sha256su0   v16.4s, v17.4s
    mov         v2.16b, v0.16b
    sha256h     q0, q1, v20.4s
    sha256h2    q1, q2, v20.4s
    add         v21.4s, v21.4s, v17.4s
    sha256su1   v16.4s, v18.4s, v19.4s
    ld1         {v20.4s}, [x4], #16

    sha256su0   v17.4s, v18.4s
    mov         v3.16b, v0.16b
    sha256h     q0, q1, v21.4s
    sha256h2    q1, q3, v21.4s
    add         v22.4s, v22.4s, v18.4s
    sha256su1   v17.4s, v19.4s, v16.4s
    ld1         {v21.4s}, [x4], #16

    sha256su0   v18.4s, v19.4s
    mov         v2.16b, v0.16b
    sha256h     q0, q1, v22.4s
    sha256h2    q1, q2, v22.4s
    add         v23.4s, v23.4s, v19.4s
    sha256su1   v18.4s, v16.4s, v17.4s
    ld1         {v22.4s}, [x4], #16

    sha256su0   v19.4s, v16.4s
    mov         v3.16b, v0.16b
    sha256h     q0, q1, v23.4s
    sha256h2    q1, q3, v23.4s
    add         v20.4s, v20.4s, v16.4s
    sha256su1   v19.4s, v17.4s, v18.4s
    ld1         {v23.4s}, [x4], #16

    /* 16-31 */
    sha256su0   v16.4s, v17.4s
    mov         v2.16b, v0.16b
    sha256h     q0, q1, v20.4s
    sha256h2    q1, q2, v20.4s
    add         v21.4s, v21.4s, v17.4s
    sha256su1   v16.4s, v18.4s, v19.4s
    ld1         {v20.4s}, [x4], #16

    sha256su0   v17.4s, v18.4s
    mov         v3.16b, v0.16b
    sha256h     q0, q1, v21.4s
    sha256h2    q1, q3, v21.4s
    add         v22.4s, v22.4s, v18.4s
    sha256su1   v17.4s, v19.4s, v16.4s
    ld1         {v21.4s}, [x4], #16

    mov         v2.16b, v0.16b
    sha256su0   v18.4s, v19.4s
    sha256h     q0, q1, v22.4s
    sha256h2    q1, q2, v22.4s
    add         v23.4s, v23.4s, v19.4s
    sha256su1   v18.4s, v16.4s, v17.4s
    ld1         {v22.4s}, [x4], #16

    sha256su0   v19.4s, v16.4s
    mov         v3.16b, v0.16b
    sha256h     q0, q1, v23.4s
    sha256h2    q1, q3, v23.4s
    add         v20.4s, v20.4s, v16.4s
    sha256su1   v19.4s, v17.4s, v18.4s
    ld1         {v23.4s}, [x4], #16

    /* 32-47 */
    sha256su0   v16.4s, v17.4s
    mov         v2.16b, v0.16b
    sha256h     q0, q1, v20.4s
    sha256h2    q1, q2, v20.4s
    add         v21.4s, v21.4s, v17.4s
    sha256su1   v16.4s, v18.4s, v19.4s
    ld1         {v20.4s}, [x4], #16

    sha256su0   v17.4s, v18.4s
    mov         v3.16b, v0.16b
    sha256h     q0, q1, v21.4s
    sha256h2    q1, q3, v21.4s
    add         v22.4s, v22.4s, v18.4s

    sha256su1   v17.4s, v19.4s, v16.4s
    ld1         {v21.4s}, [x4], #16

    sha256su0   v18.4s, v19.4s
    mov         v2.16b, v0.16b
    sha256h     q0, q1, v22.4s
    sha256h2    q1, q2, v22.4s
    add         v23.4s, v23.4s, v19.4s
    sha256su1   v18.4s, v16.4s, v17.4s
    ld1         {v22.4s}, [x4], #16


    sha256su0   v19.4s, v16.4s
    mov         v3.16b, v0.16b
    sha256h     q0, q1, v23.4s
    sha256h2    q1, q3, v23.4s
    add         v20.4s, v20.4s, v16.4s
    sha256su1   v19.4s, v17.4s, v18.4s
    ld1         {v23.4s}, [x4], #16
    /* 48-63 */
    mov         v2.16b, v0.16b
    sha256h     q0, q1, v20.4s
    add         v21.4s, v21.4s, v17.4s
    sha256h2    q1, q2, v20.4s

    mov         v3.16b, v0.16b
    sha256h     q0, q1, v21.4s
    add         v22.4s, v22.4s, v18.4s
    sha256h2    q1, q3, v21.4s

    mov         v2.16b, v0.16b
    sha256h     q0, q1, v22.4s
    add         v23.4s, v23.4s, v19.4s
    sha256h2    q1, q2, v22.4s

    mov         v3.16b, v0.16b
    sha256h     q0, q1, v23.4s
    sha256h2    q1, q3, v23.4s
    /* Add the original hash value */
    add     v4.4s, v4.4s, v0.4s
    add     v5.4s, v5.4s, v1.4s
    cbnz    x2, .Lloop_compress_64_ext

    /* Output result */
    st1     {v4.4s-v5.4s}, [x0]
    ret
    .size SHA256CryptoExt, .-SHA256CryptoExt

/* 
 * Optimized macro for dual SHA-256 rounds - caller-saved registers only
 * Uses on-demand K256 loading to comply with AAPCS calling convention
 * v8-v15 are callee-saved and must be preserved
 */
.macro ROUNDS4X2_LOAD m0_a, m0_b, k
    mov         v30.16b, v4.16b
    mov         v31.16b, v6.16b
    add         v28.4s, v\k\().4s, v\m0_a\().4s
    add         v29.4s, v\k\().4s, v\m0_b\().4s
    sha256h     q4, q5, v28.4s
    sha256h     q6, q7, v29.4s
    sha256h2    q5, q30, v28.4s
    sha256h2    q7, q31, v29.4s
.endm

/* Macro for round with message schedule update */
.macro ROUND_SCHED m0, m1, m2, m3, m0b, m1b, m2b, m3b, k
    ROUNDS4X2_LOAD \m0, \m0b, \k
    sha256su0   v\m0\().4s, v\m1\().4s
    sha256su0   v\m0b\().4s, v\m1b\().4s
    sha256su1   v\m0\().4s, v\m2\().4s, v\m3\().4s
    sha256su1   v\m0b\().4s, v\m2b\().4s, v\m3b\().4s
.endm

.macro REVBE x0, x1
#ifndef HITLS_BIG_ENDIAN
    rev \x0, \x1
#else
    mov \x0, \x1
#endif
.endm

/*
 * Function: CRYPT_SHA256x2 - Dual SHA-256 hash computation
 * Prototype: void CRYPT_SHA256x2(uint32_t state1[8], uint32_t state2[8],
 *                                 const uint8_t *in1, const uint8_t *in2, uint32_t nbytes,
 *                                 uint8_t dgst1[32], uint8_t dgst2[32]);
 * 
 * Parameters:
 *   x0 - state1: Initial/final hash state for message 1
 *   x1 - state2: Initial/final hash state for message 2
 *   x2 - in1: Message 1 data pointer
 *   x3 - in2: Message 2 data pointer
 *   w4 - nbytes: Message length (same for both)
 *   x5 - dgst1: Output digest for message 1 (32 bytes, big-endian)
 *   x6 - dgst2: Output digest for message 2 (32 bytes, big-endian)
 * 
 * Computes two SHA-256 hashes simultaneously using ARMv8 crypto extensions.
 * Handles padding internally per FIPS 180-4.
 */

.balign 16
#ifdef __APPLE__
    .global _CRYPT_SHA256x2
    _CRYPT_SHA256x2:
#else
    .global CRYPT_SHA256x2
    .type CRYPT_SHA256x2, %function
CRYPT_SHA256x2:
#endif
AARCH64_PACIASP
    /* Stack: 256 bytes
     * 0-15: x29/x30, 96-159: buffer1, 160-223: buffer2 */
    stp     x29, x30, [sp, #-160]!
    add     x29, sp, #0
    stp     x19, x20, [sp, #16]
    
    /* Initialize */
    lsl     x19, x4, #3             // bit count for padding
    ld1     {v24.4s-v25.4s}, [x0]   // Load initial state1
    ld1     {v26.4s-v27.4s}, [x1]   // Load initial state2

    /* Process complete 64-byte blocks */
    lsr     w9, w4, #6              // num_blocks = nbytes / 64
    cbz     w9, .L_partial_2x

.L_fullblk_2x:
    /* Load 64 bytes from each message and convert to big-endian */
    ld1     {v16.16b-v19.16b}, [x2], #64
    ld1     {v20.16b-v23.16b}, [x3], #64
    rev32   v16.16b, v16.16b
    rev32   v20.16b, v20.16b
    rev32   v17.16b, v17.16b
    rev32   v21.16b, v21.16b
    rev32   v18.16b, v18.16b
    rev32   v22.16b, v22.16b
    rev32   v19.16b, v19.16b
    rev32   v23.16b, v23.16b

    /* Execute 64 rounds of compression */
    bl      sha256_block_x2

    subs    w9, w9, #1
    bne     .L_fullblk_2x

.L_partial_2x:
    /* Handle partial block and padding (FIPS 180-4):
     * Append 0x80, pad with zeros to 56 bytes, append 64-bit length */
    and     w10, w4, #63            // remaining bytes
    cbz     w10, .L_padding_aligned_2x
    
    /* Clear buffers and copy remaining bytes */
    add     x11, sp, #32
    movi    v28.16b, #0
    movi    v29.16b, #0
    movi    v30.16b, #0
    movi    v31.16b, #0
    st1     {v28.16b-v31.16b}, [x11], #64
    st1     {v28.16b-v31.16b}, [x11]
    
    add     x11, sp, #32
    add     x12, sp, #96
    mov     x13, x10
    
    /* Copy 16-byte chunks */
    cmp     x13, #16
    blt     .L_copy_bytes_2x
.L_copy_16_2x:
    ldr     q28, [x2], #16
    ldr     q29, [x3], #16
    str     q28, [x11], #16
    str     q29, [x12], #16
    sub     x13, x13, #16
    cmp     x13, #16
    bge     .L_copy_16_2x
    
    /* Copy remaining bytes */
.L_copy_bytes_2x:
    cbz     x13, .L_add_padding_2x
    ldrb    w14, [x2], #1
    ldrb    w15, [x3], #1
    strb    w14, [x11], #1
    strb    w15, [x12], #1
    subs    x13, x13, #1
    bne     .L_copy_bytes_2x

.L_add_padding_2x:
    /* Add 0x80 padding byte */
    mov     w13, #0x80
    add     x14, sp, #32
    add     x15, sp, #96
    strb    w13, [x14, x10]
    strb    w13, [x15, x10]
    
    /* Check if need one or two blocks */
    cmp     w10, #56
    bge     .L_need_extra_block_2x
    
    /* Case 1: Padding fits in one block */
    REVBE     x8, x19
    add     x14, sp, #32
    add     x15, sp, #96
    str     x8, [x14, #56]
    str     x8, [x15, #56]
    
    ld1     {v16.16b-v19.16b}, [x14]
    ld1     {v20.16b-v23.16b}, [x15]
    rev32   v16.16b, v16.16b
    rev32   v20.16b, v20.16b
    rev32   v17.16b, v17.16b
    rev32   v21.16b, v21.16b
    rev32   v18.16b, v18.16b
    rev32   v22.16b, v22.16b
    rev32   v19.16b, v19.16b
    rev32   v23.16b, v23.16b
    b       .L_process_final_2x

.L_need_extra_block_2x:
    /* Case 2: Need two blocks (remaining >= 56) */
    add     x14, sp, #32
    add     x15, sp, #96
    ld1     {v16.16b-v19.16b}, [x14]
    ld1     {v20.16b-v23.16b}, [x15]
    rev32   v16.16b, v16.16b
    rev32   v20.16b, v20.16b
    rev32   v17.16b, v17.16b
    rev32   v21.16b, v21.16b
    rev32   v18.16b, v18.16b
    rev32   v22.16b, v22.16b
    rev32   v19.16b, v19.16b
    rev32   v23.16b, v23.16b
    bl      sha256_block_x2
    
    /* Prepare second block: zeros + length */
    /* For direct vector register manipulation, always use rev (not REVBE)
     * because mov v.d[n], x is a pure bit copy, independent of system endianness */
    rev     x8, x19
    movi    v16.2d, #0
    movi    v17.2d, #0
    movi    v18.2d, #0
    mov     v19.d[0], xzr
    mov     v19.d[1], x8
    mov     v20.16b, v16.16b
    mov     v21.16b, v17.16b
    mov     v22.16b, v18.16b
    mov     v23.16b, v19.16b
    rev32   v16.16b, v16.16b
    rev32   v17.16b, v17.16b
    rev32   v18.16b, v18.16b
    rev32   v19.16b, v19.16b
    rev32   v20.16b, v20.16b
    rev32   v21.16b, v21.16b
    rev32   v22.16b, v22.16b
    rev32   v23.16b, v23.16b
    b       .L_process_final_2x

.L_padding_aligned_2x:
    /* Case 3: Block-aligned message */
    add     x14, sp, #32
    add     x15, sp, #96
    movi    v28.16b, #0
    movi    v29.16b, #0
    movi    v30.16b, #0
    movi    v31.16b, #0
    st1     {v28.16b-v31.16b}, [x14]
    st1     {v28.16b-v31.16b}, [x15]
    
    mov     w13, #0x80
    add     x14, sp, #32
    add     x15, sp, #96
    strb    w13, [x14]
    strb    w13, [x15]
    REVBE     x8, x19
    str     x8, [x14, #56]
    str     x8, [x15, #56]
    
    ld1     {v16.16b-v19.16b}, [x14]
    ld1     {v20.16b-v23.16b}, [x15]
    rev32   v16.16b, v16.16b
    rev32   v20.16b, v20.16b
    rev32   v17.16b, v17.16b
    rev32   v21.16b, v21.16b
    rev32   v18.16b, v18.16b
    rev32   v22.16b, v22.16b
    rev32   v19.16b, v19.16b
    rev32   v23.16b, v23.16b

.L_process_final_2x:
    bl      sha256_block_x2

.L_finalize_2x:
    /* Output results: state arrays (little-endian) and digests (big-endian) */
    st1     {v24.4s-v25.4s}, [x0]
    st1     {v26.4s-v27.4s}, [x1]
#ifndef HITLS_BIG_ENDIAN
    rev32   v24.16b, v24.16b
    rev32   v25.16b, v25.16b
    rev32   v26.16b, v26.16b
    rev32   v27.16b, v27.16b
#endif
    st1     {v24.4s-v25.4s}, [x5]
    st1     {v26.4s-v27.4s}, [x6]

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #160
AARCH64_AUTIASP
    ret
#ifndef __APPLE__
    .size CRYPT_SHA256x2, .-CRYPT_SHA256x2
#endif

/* Local subroutine: 64-round SHA-256 compression for dual messages
 * Input: v16-v19, v20-v23 (msg schedules), v24-v27 (states)
 * Modifies: v0-v7, v16-v23, v28-v31, x16 */
sha256_block_x2:
    mov v4.16b, v24.16b
    mov v5.16b, v25.16b
    mov v6.16b, v26.16b
    mov v7.16b, v27.16b

#ifdef __APPLE__
    adrp        x16, .K256@page
    add         x16, x16, .K256@pageoff
#else
    adrp        x16, .K256
    add         x16, x16, :lo12:.K256
#endif
    
    /* Rounds 0-47 */
    ld1 {v0.4s-v3.4s}, [x16], #64
    ROUND_SCHED 16, 17, 18, 19, 20, 21, 22, 23, 0
    ROUND_SCHED 17, 18, 19, 16, 21, 22, 23, 20, 1
    ROUND_SCHED 18, 19, 16, 17, 22, 23, 20, 21, 2
    ROUND_SCHED 19, 16, 17, 18, 23, 20, 21, 22, 3
    ld1 {v0.4s-v3.4s}, [x16], #64
    ROUND_SCHED 16, 17, 18, 19, 20, 21, 22, 23, 0
    ROUND_SCHED 17, 18, 19, 16, 21, 22, 23, 20, 1
    ROUND_SCHED 18, 19, 16, 17, 22, 23, 20, 21, 2
    ROUND_SCHED 19, 16, 17, 18, 23, 20, 21, 22, 3
    ld1 {v0.4s-v3.4s}, [x16], #64
    ROUND_SCHED 16, 17, 18, 19, 20, 21, 22, 23, 0
    ROUND_SCHED 17, 18, 19, 16, 21, 22, 23, 20, 1
    ROUND_SCHED 18, 19, 16, 17, 22, 23, 20, 21, 2
    ROUND_SCHED 19, 16, 17, 18, 23, 20, 21, 22, 3
    
    /* Rounds 48-63 */
    ld1 {v0.4s-v3.4s}, [x16], #64
    ROUNDS4X2_LOAD 16, 20, 0
    ROUNDS4X2_LOAD 17, 21, 1
    ROUNDS4X2_LOAD 18, 22, 2
    ROUNDS4X2_LOAD 19, 23, 3
    
    /* Add to state */
    add         v24.4s, v24.4s, v4.4s
    add         v25.4s, v25.4s, v5.4s
    add         v26.4s, v26.4s, v6.4s
    add         v27.4s, v27.4s, v7.4s
    ret


/*
 * void CRYPT_SHA256x2_Compress(uint32_t state1[CRYPT_SHA256_STATE_SIZE], uint32_t state2[CRYPT_SHA256_STATE_SIZE],
 *                            const uint8_t *block1, const uint8_t *block2, uint32_t nblocks);
 * 
 * Function: Compress multiple blocks for dual SHA-256 computation
 * Parameters:
 *   x0 - state1: Initial/final hash state for message 1
 *   x1 - state2: Initial/final hash state for message 2
 *   x2 - block1: Message 1 data pointer
 *   x3 - block2: Message 2 data pointer
 *   w4 - nblocks: Number of 64-byte blocks to process
 * 
 * Updates two SHA-256 states by compressing nblocks pairs of 64-byte blocks.
 */

.balign 16
#ifdef __APPLE__
    .global _CRYPT_SHA256x2_Compress
    _CRYPT_SHA256x2_Compress:
#else
    .global CRYPT_SHA256x2_Compress
    .type CRYPT_SHA256x2_Compress, %function
CRYPT_SHA256x2_Compress:
#endif
AARCH64_PACIASP
    stp     x29, x30, [sp, #-16]!
    add     x29, sp, #0
    /* Check if nblocks is zero */
    cbz     w4, .Lcompress_end_x2
    
    /* Load initial states */
    ld1     {v24.4s-v25.4s}, [x0]   // Load state1 (8 uint32_t = 2 vectors)
    ld1     {v26.4s-v27.4s}, [x1]   // Load state2 (8 uint32_t = 2 vectors)
    
    /* Loop through nblocks */
.Lcompress_loop_x2:
    /* Load 64 bytes from each block */
    ld1     {v16.16b-v19.16b}, [x2], #64  // Load block1 (64 bytes = 4 vectors)
    ld1     {v20.16b-v23.16b}, [x3], #64  // Load block2 (64 bytes = 4 vectors)
    
    /* Convert to big-endian (SHA-256 requires big-endian input) */
    rev32   v16.16b, v16.16b
    rev32   v17.16b, v17.16b
    rev32   v18.16b, v18.16b
    rev32   v19.16b, v19.16b
    rev32   v20.16b, v20.16b
    rev32   v21.16b, v21.16b
    rev32   v22.16b, v22.16b
    rev32   v23.16b, v23.16b
    
    /* Execute 64 rounds of compression */
    bl      sha256_block_x2
    
    /* Decrement block counter and loop if more blocks remain */
    subs    w4, w4, #1
    bne     .Lcompress_loop_x2
    
    /* Store final states */
    st1     {v24.4s-v25.4s}, [x0]   // Store state1
    st1     {v26.4s-v27.4s}, [x1]   // Store state2

.Lcompress_end_x2:
    ldp     x29, x30, [sp], #16
AARCH64_AUTIASP
    ret
#ifndef __APPLE__
    .size CRYPT_SHA256x2_Compress, .-CRYPT_SHA256x2_Compress
#endif

#endif
