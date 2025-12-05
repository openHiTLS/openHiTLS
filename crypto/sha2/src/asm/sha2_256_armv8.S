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
AARCH64_PACIASP
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
AARCH64_AUTIASP
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
AARCH64_PACIASP
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
AARCH64_AUTIASP
    ret
    .size SHA256CryptoExt, .-SHA256CryptoExt
#endif
