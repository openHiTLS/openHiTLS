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
#ifdef HITLS_CRYPTO_SHA512

#include "crypt_arm.h"

.arch    armv8-a+crypto
/* sha512 used constant value. For the data source, see the RFC4634 document. */
.section .rodata
.balign 64
.K512:
    .quad    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
    .quad    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118
    .quad    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
    .quad    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694
    .quad    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
    .quad    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
    .quad    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4
    .quad    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70
    .quad    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
    .quad    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b
    .quad    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30
    .quad    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8
    .quad    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
    .quad    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
    .quad    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
    .quad    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b
    .quad    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
    .quad    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b
    .quad    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
    .quad    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817

/**
 *  Macro description: Update the processed 64-bit plaintext information W.
 *  Input register:
 *      wi_16:  W[i-16]
 *      wi_15: W[i-15]
 *      wi_7: W[i-7]
 *      wi_2: W[i-2]
 *  Modify the register: wi_16 x17 x28.
 *  Output register:
 *      wi_16: latest W[i] value, W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
 *  Function/Macro Call: None
 */
    .macro  UPDATE_W        wi_16, wi_15, wi_7, wi_2
    ror     x28, \wi_15, #1
    ror     x17, \wi_2, #19
    eor     x28, x28, \wi_15, ror#8
    eor     x17, x17, \wi_2, ror#61
    eor     x28, x28, \wi_15, lsr#7
    eor     x17, x17, \wi_2, lsr#6
    add     \wi_16, \wi_16, \wi_7
    add     \wi_16, \wi_16, x28
    add     \wi_16, \wi_16, x17
    .endm

/**
 *  Macro description: Processes the update of a hash value in 80 rounds of compression.
 *  Input register:
 *      x19:  indicates the address of the corresponding element in the g_k512 constant.
 *      wi:   plaintext data after processing
 *      a - h: intermediate variable of the hash value
 *  Modify the register: h d x16 x17 x28 x29
 *  Output register:
 *      h: value after a round of cyclic update
 *      d: value after a round of cyclic update
 *  Function/Macro Call: None
 */
    .macro ONE_ROUND         wi, a, b, c, d, e, f, g, h
    ldr    x16, [x19], #8           // K[i]
    add    \h, \h, x16              // h += K[i]
    add    \h, \h, \wi              // h += W[i]

    and    x17, \f, \e              // e&f
    bic    x28, \g, \e              // g&(~e)
    orr    x17, x17, x28            // Ch(e, f, g) = e&f | g&(~e)
    add    \h, \h, x17              // h += Ch(e, f, g)

    eor    x29, \e, \e, ror#23
    ror    x16, \e, #14
    eor    x29, x16, x29, ror#18    // Sigma1(e) = ROR(e, 14) ^ ROR(e, 18) ^ ROR(e, 41)
    add    \h, \h, x29              // h += Sigma1(e)

    eor    x17, \a, \b              // a^b
    eor    x28, \a, \c              // a^c
    and    x28, x28, x17            // (a^b)&(a^c)
    eor    x28, x28, \a             // Maj(a, b, c) = ((a^b)&(a^c))^a = (a&b)^(b&c)^(a&c)

    add    \d, \d, \h               // d += h
    add    \h, \h, x28              // h += Maj(a, b, c)

    eor    x29, \a, \a, ror#5
    ror    x16, \a, #28
    eor    x29, x16, x29, ror#34    // Sigma0(a) = ROR(a, 28)^ROR(a, 34)^ROR(a, 39)
    add    \h, \h, x29              // h += Sigma0(a)
    .endm

/**
 *  Function description: Performs 80 rounds of compression calculation
 *based on the input plaintext data and updates the hash value.
 *  Function prototype: void SHA512CompressMultiBlocks(uint64_t hash[8], const uint8_t *in, uint32_t num);
 *  Input register:
 *         x0: indicates the storage address of the hash value.
 *         x1: pointer to the input data address
 *         x2: number of 80 rounds of cycles. The value is the input data length divided by 128.
 *  Change register: x0-x17.
 *  Output register: None
 *  Function/Macro Call: None
 *
 */
    .text
    .balign 16
    .global SHA512CompressMultiBlocks
    .type SHA512CompressMultiBlocks, %function
SHA512CompressMultiBlocks:
AARCH64_PACIASP
    cbz     x2, .Lend_sha512
    stp     x29, x30, [sp, #-112]!
    add     x29, sp, #0
    stp     x19, x20, [sp, #8*2]
    stp     x21, x22, [sp, #8*4]
    stp     x23, x24, [sp, #8*6]
    stp     x25, x26, [sp, #8*8]
    stp     x27, x28, [sp, #8*10]

    /* load a - h */
    ldp     x20, x21, [x0]
    ldp     x22, x23, [x0, #8*2]
    ldp     x24, x25, [x0, #8*4]
    ldp     x26, x27, [x0, #8*6]

    str     x0, [sp, #96]
    mov     x16, x1 // input Value Address
    lsl     x30, x2, #2

.Lloop_compress_80:
    /* Start 80 rounds of processing */
    adrp    x19, .K512
    add	    x19, x19, :lo12:.K512
    ldp     x0, x1, [x16] // Load input values.
    ldp     x2, x3, [x16, #8*2]
    ldp     x4, x5, [x16, #8*4]
    ldp     x6, x7, [x16, #8*6]
    ldp     x8, x9, [x16, #8*8]
    ldp     x10, x11, [x16, #8*10]
    ldp     x12, x13, [x16, #8*12]
    ldp     x14, x15, [x16, #8*14]

    add     x16, x16, #8*16
    str     x16, [sp, #104]
#ifndef	HITLS_BIG_ENDIAN
    rev     x0, x0
    rev     x1, x1
    rev     x2, x2
    rev     x3, x3
    rev     x4, x4
    rev     x5, x5
    rev     x6, x6
    rev     x7, x7
    rev     x8, x8
    rev     x9, x9
    rev     x10, x10
    rev     x11, x11
    rev     x12, x12
    rev     x13, x13
    rev     x14, x14
    rev     x15, x15
#endif
    /* x16 x17 x28 x29 used as a temporary register */
    ONE_ROUND   x0, x20, x21, x22, x23, x24, x25, x26, x27
    ONE_ROUND   x1, x27, x20, x21, x22, x23, x24, x25, x26
    ONE_ROUND   x2, x26, x27, x20, x21, x22, x23, x24, x25
    ONE_ROUND   x3, x25, x26, x27, x20, x21, x22, x23, x24

    ONE_ROUND   x4, x24, x25, x26, x27, x20, x21, x22, x23
    ONE_ROUND   x5, x23, x24, x25, x26, x27, x20, x21, x22
    ONE_ROUND   x6, x22, x23, x24, x25, x26, x27, x20, x21
    ONE_ROUND   x7, x21, x22, x23, x24, x25, x26, x27, x20

    ONE_ROUND   x8, x20, x21, x22, x23, x24, x25, x26, x27
    ONE_ROUND   x9, x27, x20, x21, x22, x23, x24, x25, x26
    ONE_ROUND   x10, x26, x27, x20, x21, x22, x23, x24, x25
    ONE_ROUND   x11, x25, x26, x27, x20, x21, x22, x23, x24

    ONE_ROUND   x12, x24, x25, x26, x27, x20, x21, x22, x23
    ONE_ROUND   x13, x23, x24, x25, x26, x27, x20, x21, x22
    ONE_ROUND   x14, x22, x23, x24, x25, x26, x27, x20, x21
    ONE_ROUND   x15, x21, x22, x23, x24, x25, x26, x27, x20

.Lloop_compress_16_79:
    /* Start 16 - 31, 32 - 47, 48 - 63, 64 - 79 compression */
    sub     x30, x30, #1

    /* 0 */
    UPDATE_W    x0, x1, x9, x14
    ONE_ROUND   x0, x20, x21, x22, x23, x24, x25, x26, x27

    /* 1 */
    UPDATE_W    x1, x2, x10, x15
    ONE_ROUND   x1, x27, x20, x21, x22, x23, x24, x25, x26

    /* 2 */
    UPDATE_W    x2, x3, x11, x0
    ONE_ROUND   x2, x26, x27, x20, x21, x22, x23, x24, x25

    /* 3 */
    UPDATE_W    x3, x4, x12, x1
    ONE_ROUND   x3, x25, x26, x27, x20, x21, x22, x23, x24

    /* 4 */
    UPDATE_W    x4, x5, x13, x2
    ONE_ROUND   x4, x24, x25, x26, x27, x20, x21, x22, x23

    /* 5 */
    UPDATE_W    x5, x6, x14, x3
    ONE_ROUND   x5, x23, x24, x25, x26, x27, x20, x21, x22

    /* 6 */
    UPDATE_W    x6, x7, x15, x4
    ONE_ROUND   x6, x22, x23, x24, x25, x26, x27, x20, x21

    /* 7 */
    UPDATE_W    x7, x8, x0, x5
    ONE_ROUND   x7, x21, x22, x23, x24, x25, x26, x27, x20

    /* 8 */
    UPDATE_W    x8, x9, x1, x6
    ONE_ROUND   x8, x20, x21, x22, x23, x24, x25, x26, x27

    /* 9 */
    UPDATE_W    x9, x10, x2, x7
    ONE_ROUND   x9, x27, x20, x21, x22, x23, x24, x25, x26

    /* 10 */
    UPDATE_W    x10, x11, x3, x8
    ONE_ROUND   x10, x26, x27, x20, x21, x22, x23, x24, x25

    /* 11 */
    UPDATE_W    x11, x12, x4, x9
    ONE_ROUND   x11, x25, x26, x27, x20, x21, x22, x23, x24

    /* 12 */
    UPDATE_W    x12, x13, x5, x10
    ONE_ROUND   x12, x24, x25, x26, x27, x20, x21, x22, x23

    /* 13 */
    UPDATE_W    x13, x14, x6, x11
    ONE_ROUND   x13, x23, x24, x25, x26, x27, x20, x21, x22

    /* 14 */
    UPDATE_W    x14, x15, x7, x12
    ONE_ROUND   x14, x22, x23, x24, x25, x26, x27, x20, x21

    /* 15 */
    UPDATE_W    x15, x0, x8, x13
    ONE_ROUND   x15, x21, x22, x23, x24, x25, x26, x27, x20

    /* If the processing length is not 80, continue the loop. */
    tst     x30, #3
    bne     .Lloop_compress_16_79

    /* Stores a - h information. */
    ldr     x0, [sp, #96]

    ldp     x10, x11, [x0]
    ldp     x12, x13, [x0, #8*2]
    ldp     x14, x15, [x0, #8*4]
    ldp     x16, x17, [x0, #8*6]

    add     x20, x20, x10
    add     x21, x21, x11
    add     x22, x22, x12
    add     x23, x23, x13
    add     x24, x24, x14
    add     x25, x25, x15
    add     x26, x26, x16
    add     x27, x27, x17

    stp     x20, x21, [x0]
    stp     x22, x23, [x0, #8*2]
    stp     x24, x25, [x0, #8*4]
    stp     x26, x27, [x0, #8*6]

    ldr     x16, [sp, #104]
    /* If the remaining length is not processed, continue to process 80 rounds. */
    cbnz    x30, .Lloop_compress_80

    /* The function returns */
    ldp     x19, x20, [sp, #8*2]
    ldp     x21, x22, [sp, #8*4]
    ldp     x23, x24, [sp, #8*6]
    ldp     x25, x26, [sp, #8*8]
    ldp     x27, x28, [sp, #8*10]
    ldp     x29, x30, [sp], #112
.Lend_sha512:
AARCH64_AUTIASP
    ret
    .size SHA512CompressMultiBlocks, .-SHA512CompressMultiBlocks

#endif
