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
#ifdef HITLS_CRYPTO_SHA1

#include "crypt_arm.h"

.arch   armv8-a+crypto
.extern	g_cryptArmCpuInfo
.hidden	g_cryptArmCpuInfo
/* SHA1 used constant value. For the data source, see the RFC3174 document.
 * K(t) = 5A827999 ( 0 <= t <= 19)
 * K(t) = 6ED9EBA1 (20 <= t <= 39)
 * K(t) = 8F1BBCDC (40 <= t <= 59)
 * K(t) = CA62C1D6 (60 <= t <= 79)
 */
.data
.balign 64         // Alignment based on the size of the read data block
.type   g_k, %object
g_k:
    .long   0x5a827999
    .long   0x6ed9eba1
    .long   0x8f1bbcdc
    .long   0xca62c1d6
.size   g_k, .-g_k

.balign 64         // Alignment based on the size of the read data block
.type   g_kExt, %object
g_kExt:
    .long   0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999   //K_00_19
    .long   0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1   //K_20_39
    .long   0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc   //K_40_59
    .long   0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6   //K_60_79
.size   g_kExt, .-g_kExt

/**
 *  Macro Description: 32位Message block扩展Wi
 *  input register:
 *      wi_3:  W[i-3]
 *      wi_8:  W[i-8]
 *     wi_14:  W[i-14]
 *     wi_16:  W[i-16]
 *     temp1: temporary register
 *     temp2: temporary register
 *  Modify the register:  wi_16 temp1 temp2
 *  Output register:
 *      wi_16:  Latest W[i] value, W(i) = S^1(W(i-3) XOR W(i-8) XOR W(i-14) XOR W(i-16))
 *  Function/Macro Call: NONE
 */
.macro  MESSAGE_EXPAND wi_16, wi_14, wi_8, wi_3, temp1, temp2
    eor     \temp1, \wi_14, \wi_16      // W(i-14) XOR W(i-16)
    eor     \temp2, \wi_3, \wi_8        // W(i-3) XOR W(i-8)
    eor     \wi_16, \temp1, \temp2      // W(i-3) XOR W(i-8) XOR W(i-14) XOR W(i-16)
    ror     \wi_16, \wi_16, #31         // Cyclic left shift 1 equals cyclic right shift 31
.endm

/**
 *  Macro Description: b、e Compute
 *  input register:
 *          k:  Constant data
 *         wi:  Message block
 *      a、b、e:  Intermediate variable of hash value
 *          f:  f(B, C, D)
 *    temp1-4:  temporary register
 *  Modify the register:  b e temp3-temp4
 *  Output register:
 *          b:  Indicates the value after a cyclic update.
 *          e:  Indicates the value after a cyclic update.
 *  Macro implementation:
 *          e = S^5(A) + f(B, C, D) + E + W(i) + K(i)
 *          b = S^30(B)
 *  Function/Macro Call: NONE
 */
.macro  CAL_B_E a, b, e, wi, k, f, temp3, temp4
    add     \temp3, \wi, \k             // W(i) + K(i)
    ror     \temp4, \a, #27             // S^5(A) Cyclic shift left 5 equal Cyclic shift right 27

    ror     \b, \b, #2                  // b = S^30(B) Cyclic shift left 30 equal Cyclic shift right 2
    add     \temp4, \temp4, \temp3      // S^5(A) + W(i) + K(i)
    add     \e, \e, \f                  // f(B, C, D) + E
    add     \e, \e, \temp4              // f(B, C, D) + E + S^5(A) + W(i) + K(i)
.endm

/**
 *  Macro Description: Message compression，0~19round data compression
 *  input register:
 *          k:  Constant data
 *         wi:  Message block
 *      a - h:  Intermediate variable of hash value
 *    temp1-4:  temporary register
 *  Modify the register:  b e temp1-temp4
 *  Output register:
 *          b:  Indicates the value after a cyclic update.
 *          e:  Indicates the value after a cyclic update.
 *  Macro implementation: f(B, C, D) = (B AND C) OR ((NOT B) AND D)
 *          e = S^5(A) + f(B, C, D) + E + W(i) + K(i)
 *          b = S^30(B)
 *  Function/Macro Call: CAL_B_E
 */
.macro  DATA_COMPRE_0_19 a, b, c, d, e, wi, k, temp1, temp2, temp3, temp4
    and     \temp1, \b, \c          // b&c
    bic     \temp2, \d, \b          // d&(~b)
    orr     \temp1, \temp1, \temp2  // f(B, C, D)

    CAL_B_E \a, \b, \e, \wi, \k, \temp1, \temp3, \temp4
.endm

/**
 *  Macro Description: Message compression，20~39、60~79round data compression
 *  input register:
 *          k:  Constant data
 *         wi:  Message block
 *      a - h:  Intermediate variable of hash value
 *    temp1-4:  temporary register
 *  Modify the register:  b e temp1-temp4
 *  Output register:
 *          b:  Indicates the value after a cyclic update.
 *          e:  Indicates the value after a cyclic update.
 *  Macro implementation: f(B, C, D) =  B XOR C XOR D
 *          e = S^5(A) + f(B, C, D) + E + W(i) + K(i)
 *          b = S^30(B)
 *  Function/Macro Call: CAL_B_E
 */
.macro  DATA_COMPRE_20_39_60_79 a, b, c, d, e, wi, k, temp1, temp2, temp3, temp4
    eor     \temp2, \b, \c          // b&c
    eor     \temp1, \temp2, \d          // f(B, C, D) = b&c&d

    CAL_B_E \a, \b, \e, \wi, \k, \temp1, \temp3, \temp4
.endm

/**
 *  Macro Description: Message compression，40~59round data compression
 *  input register:
 *          k:  Constant data
 *         wi:  Message block
 *      a - h:  Intermediate variable of hash value
 *    temp1-4:  temporary register
 *  Modify the register:  b e temp1-temp4
 *  Output register:
 *          b:  Indicates the value after a cyclic update.
 *          e:  Indicates the value after a cyclic update.
 *  Macro implementation: f(B, C, D) =  (B AND C) OR (B AND D) OR (C AND D)
 *          e = S^5(A) + f(B, C, D) + E + W(i) + K(i)
 *          b = S^30(B)
 *  Function/Macro Call: CAL_B_E
 */
.macro  DATA_COMPRE_40_59 a, b, c, d, e, wi, k, temp1, temp2, temp3, temp4
    and     \temp1, \b, \c          // b&c
    and     \temp2, \b, \d          // b&d
    and     \temp3, \c, \d          // c&d
    orr     \temp1, \temp1, \temp2    // (b&c) or (b&d)
    orr     \temp1, \temp1, \temp3  // f(B, C, D)

    CAL_B_E \a, \b, \e, \wi, \k, \temp1, \temp3, \temp4
.endm

/**
 *  Function Description: Perform SHA1 compression calculation based on the input message and update the hash value.
 *  Function prototype: static const uint8_t *SHA1_Step(const uint8_t *input, uint32_t len, uint32_t *h)
 *  Input register:
 *         x0:  Pointer to the input data address
 *         x1:  Message length
 *         x2:  Storage address of the hash value
 *  Register usage:  w0–w15 store message blocks, x/w16, w17, w28, and w29 are temporary registers,
 *                   and x30 stores the hash value address. a to e correspond to w20 to w24. w19 stores the k constant,
 *                   x25 stores the message pointer, and x26 stores the remaining message length.
 *  Output register:  x0 returns the address of the message for which sha1 calculation is not performed.
 *  Function/Macro Call:  DATA_COMPRE_0_19、DATA_COMPRE_20_39_60_79、DATA_COMPRE_40_59、MESSAGE_EXPAND、SHA1CryptoExt
 */
.text
.balign 16
.global SHA1_Step
.type   SHA1_Step, %function
SHA1_Step:
AARCH64_PACIASP
    cmp     x1, #64
    b.lo    .Lend_sha1

    /* If the SHA1 cryptography extension instruction is supported, go to. */
    adrp    x5, g_cryptArmCpuInfo
    add     x5, x5, :lo12:g_cryptArmCpuInfo
    ldr     x6, [x5]
    tst     x6, #CRYPT_ARM_SHA1
    bne     SHA1CryptoExt

    /* Extended instructions are not supported, Using Base Instructions, Open up stack space, push stack protection */
    stp     x29, x30, [sp, #-96]!
    stp     x19, x20, [sp, #8*2]
    stp     x21, x22, [sp, #8*4]
    stp     x23, x24, [sp, #8*6]
    stp     x25, x26, [sp, #8*8]
    stp     x27, x28, [sp, #8*10]

    /* load a - e */
    ldp     w20, w21, [x2]
    ldp     w22, w23, [x2, #4*2]
    ldr     w24, [x2, #4*4]

    mov     x30, x2             // x30 address for storing hash values
    mov     x25, x0             // pointer to the x25 store message
    mov     x26, x1             // x26: stores the remaining message length.

.Lloop_sha1_compress:
    adrp    x16, g_k
    add     x16, x16, :lo12:g_k
    ldr     w19, [x16]          // load k1

    ldp     w0, w1, [x25]       // load input value, load 64 bytes at a time
    ldp     w2, w3, [x25, #4*2]
    ldp     w4, w5, [x25, #4*4]
    ldp     w6, w7, [x25, #4*6]
    ldp     w8, w9, [x25, #4*8]
    ldp     w10, w11, [x25, #4*10]
    ldp     w12, w13, [x25, #4*12]
    ldp     w14, w15, [x25, #4*14]

    add     x25, x25, #64       // address offset: 64 bytes
    sub     x26, x26, #64       // update the remaining address length.

#ifndef   HITLS_BIG_ENDIAN
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
    /* 0~19round data compression */
    /* a, b, c, d, e, wi, k, temp1, temp2, temp3, temp4 */
    DATA_COMPRE_0_19 w20, w21, w22, w23, w24, w0, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w24, w20, w21, w22, w23, w1, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w23, w24, w20, w21, w22, w2, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w22, w23, w24, w20, w21, w3, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w21, w22, w23, w24, w20, w4, w19, w16, w17, w28, w29

    DATA_COMPRE_0_19 w20, w21, w22, w23, w24, w5, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w24, w20, w21, w22, w23, w6, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w23, w24, w20, w21, w22, w7, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w22, w23, w24, w20, w21, w8, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w21, w22, w23, w24, w20, w9, w19, w16, w17, w28, w29

    DATA_COMPRE_0_19 w20, w21, w22, w23, w24, w10, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w24, w20, w21, w22, w23, w11, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w23, w24, w20, w21, w22, w12, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w22, w23, w24, w20, w21, w13, w19, w16, w17, w28, w29
    DATA_COMPRE_0_19 w21, w22, w23, w24, w20, w14, w19, w16, w17, w28, w29

    DATA_COMPRE_0_19 w20, w21, w22, w23, w24, w15, w19, w16, w17, w28, w29
    /* Message block extension calculation wi_16, wi_14, wi_8, wi_3, temp1, temp2 */
    MESSAGE_EXPAND w0, w2, w8, w13, w16, w17
    DATA_COMPRE_0_19 w24, w20, w21, w22, w23, w0, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w1, w3, w9, w14, w16, w17
    DATA_COMPRE_0_19 w23, w24, w20, w21, w22, w1, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w2, w4, w10, w15, w16, w17
    DATA_COMPRE_0_19 w22, w23, w24, w20, w21, w2, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w3, w5, w11, w0, w16, w17
    DATA_COMPRE_0_19 w21, w22, w23, w24, w20, w3, w19, w16, w17, w28, w29

    /* 20~39 round data compression */
    adrp    x16, g_k
    add     x16, x16, :lo12:g_k
    ldr     w19, [x16, #4]      // load k2
    MESSAGE_EXPAND w4, w6, w12, w1, w16, w17
    DATA_COMPRE_20_39_60_79 w20, w21, w22, w23, w24, w4, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w5, w7, w13, w2, w16, w17
    DATA_COMPRE_20_39_60_79 w24, w20, w21, w22, w23, w5, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w6, w8, w14, w3, w16, w17
    DATA_COMPRE_20_39_60_79 w23, w24, w20, w21, w22, w6, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w7, w9, w15, w4, w16, w17
    DATA_COMPRE_20_39_60_79 w22, w23, w24, w20, w21, w7, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w8, w10, w0, w5, w16, w17
    DATA_COMPRE_20_39_60_79 w21, w22, w23, w24, w20, w8, w19, w16, w17, w28, w29

    MESSAGE_EXPAND w9, w11, w1, w6, w16, w17
    DATA_COMPRE_20_39_60_79 w20, w21, w22, w23, w24, w9, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w10, w12, w2, w7, w16, w17
    DATA_COMPRE_20_39_60_79 w24, w20, w21, w22, w23, w10, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w11, w13, w3, w8, w16, w17
    DATA_COMPRE_20_39_60_79 w23, w24, w20, w21, w22, w11, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w12, w14, w4, w9, w16, w17
    DATA_COMPRE_20_39_60_79 w22, w23, w24, w20, w21, w12, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w13, w15, w5, w10, w16, w17
    DATA_COMPRE_20_39_60_79 w21, w22, w23, w24, w20, w13, w19, w16, w17, w28, w29

    MESSAGE_EXPAND w14, w0,  w6, w11, w16, w17
    DATA_COMPRE_20_39_60_79 w20, w21, w22, w23, w24, w14, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w15, w1,  w7, w12, w16, w17
    DATA_COMPRE_20_39_60_79 w24, w20, w21, w22, w23, w15, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w0, w2, w8, w13, w16, w17
    DATA_COMPRE_20_39_60_79 w23, w24, w20, w21, w22, w0, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w1, w3, w9, w14, w16, w17
    DATA_COMPRE_20_39_60_79 w22, w23, w24, w20, w21, w1, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w2, w4, w10, w15, w16, w17
    DATA_COMPRE_20_39_60_79 w21, w22, w23, w24, w20, w2, w19, w16, w17, w28, w29

    MESSAGE_EXPAND w3, w5, w11, w0, w16, w17
    DATA_COMPRE_20_39_60_79 w20, w21, w22, w23, w24, w3, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w4, w6, w12, w1, w16, w17
    DATA_COMPRE_20_39_60_79 w24, w20, w21, w22, w23, w4, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w5, w7, w13, w2, w16, w17
    DATA_COMPRE_20_39_60_79 w23, w24, w20, w21, w22, w5, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w6, w8, w14, w3, w16, w17
    DATA_COMPRE_20_39_60_79 w22, w23, w24, w20, w21, w6, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w7, w9, w15, w4, w16, w17
    DATA_COMPRE_20_39_60_79 w21, w22, w23, w24, w20, w7, w19, w16, w17, w28, w29

    /* 40~59 round data compression */
    adrp    x16, g_k
    add     x16, x16, :lo12:g_k
    ldr     w19, [x16, #8]      // load k3
    MESSAGE_EXPAND w8, w10, w0, w5, w16, w17
    DATA_COMPRE_40_59 w20, w21, w22, w23, w24, w8, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w9, w11, w1, w6, w16, w17
    DATA_COMPRE_40_59 w24, w20, w21, w22, w23, w9, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w10, w12, w2, w7, w16, w17
    DATA_COMPRE_40_59 w23, w24, w20, w21, w22, w10, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w11, w13, w3, w8, w16, w17
    DATA_COMPRE_40_59 w22, w23, w24, w20, w21, w11, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w12, w14, w4, w9, w16, w17
    DATA_COMPRE_40_59 w21, w22, w23, w24, w20, w12, w19, w16, w17, w28, w29

    MESSAGE_EXPAND w13, w15, w5, w10, w16, w17
    DATA_COMPRE_40_59 w20, w21, w22, w23, w24, w13, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w14, w0,  w6, w11, w16, w17
    DATA_COMPRE_40_59 w24, w20, w21, w22, w23, w14, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w15, w1,  w7, w12, w16, w17
    DATA_COMPRE_40_59 w23, w24, w20, w21, w22, w15, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w0, w2, w8, w13, w16, w17
    DATA_COMPRE_40_59 w22, w23, w24, w20, w21, w0, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w1, w3, w9, w14, w16, w17
    DATA_COMPRE_40_59 w21, w22, w23, w24, w20, w1, w19, w16, w17, w28, w29

    MESSAGE_EXPAND w2, w4, w10, w15, w16, w17
    DATA_COMPRE_40_59 w20, w21, w22, w23, w24, w2, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w3, w5, w11, w0, w16, w17
    DATA_COMPRE_40_59 w24, w20, w21, w22, w23, w3, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w4, w6, w12, w1, w16, w17
    DATA_COMPRE_40_59 w23, w24, w20, w21, w22, w4, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w5, w7, w13, w2, w16, w17
    DATA_COMPRE_40_59 w22, w23, w24, w20, w21, w5, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w6, w8, w14, w3, w16, w17
    DATA_COMPRE_40_59 w21, w22, w23, w24, w20, w6, w19, w16, w17, w28, w29

    MESSAGE_EXPAND w7, w9, w15, w4, w16, w17
    DATA_COMPRE_40_59 w20, w21, w22, w23, w24, w7, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w8, w10, w0, w5, w16, w17
    DATA_COMPRE_40_59 w24, w20, w21, w22, w23, w8, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w9, w11, w1, w6, w16, w17
    DATA_COMPRE_40_59 w23, w24, w20, w21, w22, w9, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w10, w12, w2, w7, w16, w17
    DATA_COMPRE_40_59 w22, w23, w24, w20, w21, w10, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w11, w13, w3, w8, w16, w17
    DATA_COMPRE_40_59 w21, w22, w23, w24, w20, w11, w19, w16, w17, w28, w29

    /* 60~79 round data compression */
    adrp    x16, g_k
    add     x16, x16, :lo12:g_k
    ldr     w19, [x16, #12]         // load k4
    MESSAGE_EXPAND w12, w14, w4, w9, w16, w17
    DATA_COMPRE_20_39_60_79 w20, w21, w22, w23, w24, w12, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w13, w15, w5, w10, w16, w17
    DATA_COMPRE_20_39_60_79 w24, w20, w21, w22, w23, w13, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w14, w0,  w6, w11, w16, w17
    DATA_COMPRE_20_39_60_79 w23, w24, w20, w21, w22, w14, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w15, w1,  w7, w12, w16, w17
    DATA_COMPRE_20_39_60_79 w22, w23, w24, w20, w21, w15, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w0, w2, w8, w13, w16, w17
    DATA_COMPRE_20_39_60_79 w21, w22, w23, w24, w20, w0, w19, w16, w17, w28, w29

    MESSAGE_EXPAND w1, w3, w9, w14, w16, w17
    DATA_COMPRE_20_39_60_79 w20, w21, w22, w23, w24, w1, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w2, w4, w10, w15, w16, w17
    DATA_COMPRE_20_39_60_79 w24, w20, w21, w22, w23, w2, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w3, w5, w11, w0, w16, w17
    DATA_COMPRE_20_39_60_79 w23, w24, w20, w21, w22, w3, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w4, w6, w12, w1, w16, w17
    DATA_COMPRE_20_39_60_79 w22, w23, w24, w20, w21, w4, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w5, w7, w13, w2, w16, w17
    DATA_COMPRE_20_39_60_79 w21, w22, w23, w24, w20, w5, w19, w16, w17, w28, w29

    MESSAGE_EXPAND w6, w8, w14, w3, w16, w17
    DATA_COMPRE_20_39_60_79 w20, w21, w22, w23, w24, w6, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w7, w9, w15, w4, w16, w17
    DATA_COMPRE_20_39_60_79 w24, w20, w21, w22, w23, w7, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w8, w10, w0, w5, w16, w17
    DATA_COMPRE_20_39_60_79 w23, w24, w20, w21, w22, w8, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w9, w11, w1, w6, w16, w17
    DATA_COMPRE_20_39_60_79 w22, w23, w24, w20, w21, w9, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w10, w12, w2, w7, w16, w17
    DATA_COMPRE_20_39_60_79 w21, w22, w23, w24, w20, w10, w19, w16, w17, w28, w29

    MESSAGE_EXPAND w11, w13, w3, w8, w16, w17
    DATA_COMPRE_20_39_60_79 w20, w21, w22, w23, w24, w11, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w12, w14, w4, w9, w16, w17
    DATA_COMPRE_20_39_60_79 w24, w20, w21, w22, w23, w12, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w13, w15, w5, w10, w16, w17
    DATA_COMPRE_20_39_60_79 w23, w24, w20, w21, w22, w13, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w14, w0,  w6, w11, w16, w17
    DATA_COMPRE_20_39_60_79 w22, w23, w24, w20, w21, w14, w19, w16, w17, w28, w29
    MESSAGE_EXPAND w15, w1,  w7, w12, w16, w17
    DATA_COMPRE_20_39_60_79 w21, w22, w23, w24, w20, w15, w19, w16, w17, w28, w29

    /* load a - e */
    ldp     w0, w1, [x30]
    ldp     w2, w3, [x30, #4*2]
    ldr     w4, [x30, #4*4]

    /* H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4 + E */
    add     w20, w20, w0
    add     w21, w21, w1
    add     w22, w22, w2
    add     w23, w23, w3
    add     w24, w24, w4

    stp     w20, w21, [x30]
    stp     w22, w23, [x30, #4*2]
    str     w24, [x30, #4*4]

    cmp     x26, #64
    b.hs    .Lloop_sha1_compress

    /* returns the address of the message for which SHA1 calculation is not performed. */
    mov     x0, x25

    /* pop-stack */
    ldp     x19, x20, [sp, #8*2]
    ldp     x21, x22, [sp, #8*4]
    ldp     x23, x24, [sp, #8*6]
    ldp     x25, x26, [sp, #8*8]
    ldp     x27, x28, [sp, #8*10]
    ldp     x29, x30, [sp], #96

.Lend_sha1:
AARCH64_AUTIASP
    ret
.size   SHA1_Step, .-SHA1_Step

/**
 *  Function Description: Based on the input message, compress the SHA1 dedicated instruction and
 *                        update the hash value.
 *  Function prototype: static const uint8_t *SHA1CryptoExt(const uint8_t *input, uint32_t len, uint32_t *h)
 *  Input register:
 *         x0:  Pointer to the input data address
 *         x1:  Message length
 *         x2:  Storage address of the hash value
 *  Register usage:  v0–v3 stores k0–k3, s5 stores e temporarily, v6 stores abcd, and v7 stores e,
 *                   V23–V26 stores w0–w15 and recycles w16–w79. V19–v22 stores w+k calculation results.
 *                   V16 is used as the 0 register. v17 stores abcd and v18 stores e. v16 is used together with v6 and v7.
 *  Output register:  x0 returns the address of the message for which sha1 calculation is not performed.
 *  Function/Macro Call:  NONE
 */
.text
.balign 16
.type   SHA1CryptoExt, %function
SHA1CryptoExt:
    /* load k */
    adrp    x3, g_kExt
    add     x3, x3, :lo12:g_kExt
    ld1     {v0.4s-v3.4s}, [x3]

    /* load a - e */
    ld1     {v17.4s}, [x2]
    ld1     {v6.4s}, [x2], #16
    ld1     {v18.s}[0], [x2]
    ld1     {v7.s}[0], [x2]
    sub     x2, x2, #16

    eor     v16.16b, v16.16b, v16.16b

.Lloop_sha1_ext_compress:

    /* load w */
    ld1     {v23.4s-v26.4s}, [x0], #64
    sub     x1, x1, #64                 // update the remaining address length.

    /* little endian inversion */

#ifndef   HITLS_BIG_ENDIAN
    rev32     v23.16b, v23.16b
    rev32     v24.16b, v24.16b
    rev32     v25.16b, v25.16b
    rev32     v26.16b, v26.16b
#endif

    add     v19.4s, v0.4s, v23.4s       // k0+w[3:0]
    add     v20.4s, v0.4s, v24.4s       // k0+w[4:7]
    add     v21.4s, v0.4s, v25.4s       // k0+w[11:8]
    add     v22.4s, v0.4s, v26.4s       // k0+w[15:12]

    /* [0:16] data compression */
    sha1su0 v23.4s, v24.4s, v25.4s      // w[16:20]
    sha1h   s5, s6                      // a -> e
    sha1c   q6, s7, v19.4s              // a, b, c, d -> a, b, c, d
    sha1su1 v23.4s, v26.4s

    sha1su0 v24.4s, v25.4s, v26.4s
    sha1h   s7, s6
    sha1c   q6, s5, v20.4s
    sha1su1 v24.4s, v23.4s

    sha1su0 v25.4s, v26.4s, v23.4s
    sha1h   s5, s6
    sha1c   q6, s7, v21.4s
    sha1su1 v25.4s, v24.4s

    sha1su0 v26.4s, v23.4s, v24.4s
    sha1h   s7, s6
    sha1c   q6, s5, v22.4s
    sha1su1 v26.4s, v25.4s

    add     v19.4s, v0.4s, v23.4s    // k0+w[19:16]
    add     v20.4s, v1.4s, v24.4s    // k1+w[23:20]
    add     v21.4s, v1.4s, v25.4s   // k1+w[27:24]
    add     v22.4s, v1.4s, v26.4s   // k1+w[31:28]

    /* [16:20] data compression */
    sha1su0 v23.4s, v24.4s, v25.4s
    sha1h   s5, s6
    sha1c   q6, s7, v19.4s
    sha1su1 v23.4s, v26.4s

    /* [20:40] data compression */
    sha1su0 v24.4s, v25.4s, v26.4s
    sha1h   s7, s6
    sha1p   q6, s5, v20.4s
    sha1su1 v24.4s, v23.4s

    sha1su0 v25.4s, v26.4s, v23.4s
    sha1h   s5, s6
    sha1p   q6, s7, v21.4s
    sha1su1 v25.4s, v24.4s

    sha1su0 v26.4s, v23.4s, v24.4s
    sha1h   s7, s6
    sha1p   q6, s5, v22.4s
    sha1su1 v26.4s, v25.4s

    add     v19.4s, v1.4s, v23.4s    // k1+w[35:32]
    add     v20.4s, v1.4s, v24.4s    // k1+w[39:36]
    add     v21.4s, v2.4s, v25.4s   // k2+w[43:40]
    add     v22.4s, v2.4s, v26.4s   // k2+w[47:44]

    sha1su0 v23.4s, v24.4s, v25.4s
    sha1h   s5, s6
    sha1p   q6, s7, v19.4s
    sha1su1 v23.4s, v26.4s

    sha1su0 v24.4s, v25.4s, v26.4s
    sha1h   s7, s6
    sha1p   q6, s5, v20.4s
    sha1su1 v24.4s, v23.4s

    /* [40:60] data compression */
    sha1su0 v25.4s, v26.4s, v23.4s
    sha1h   s5, s6
    sha1m   q6, s7, v21.4s
    sha1su1 v25.4s, v24.4s

    sha1su0 v26.4s, v23.4s, v24.4s
    sha1h   s7, s6
    sha1m   q6, s5, v22.4s
    sha1su1 v26.4s, v25.4s

    add     v19.4s, v2.4s, v23.4s    // k2+w[51:48]
    add     v20.4s, v2.4s, v24.4s    // k2+w[55:52]
    add     v21.4s, v2.4s, v25.4s   // k2+w[59:56]
    add     v22.4s, v3.4s, v26.4s   // k3+w[63:60]

    sha1su0 v23.4s, v24.4s, v25.4s
    sha1h   s5, s6
    sha1m   q6, s7, v19.4s
    sha1su1 v23.4s, v26.4s

    sha1su0 v24.4s, v25.4s, v26.4s
    sha1h   s7, s6
    sha1m   q6, s5, v20.4s
    sha1su1 v24.4s, v23.4s

    sha1su0 v25.4s, v26.4s, v23.4s
    sha1h   s5, s6
    sha1m   q6, s7, v21.4s
    sha1su1 v25.4s, v24.4s

    /* [60:80] data compression */
    sha1su0 v26.4s, v23.4s, v24.4s
    sha1h   s7, s6
    sha1p   q6, s5, v22.4s
    sha1su1 v26.4s, v25.4s

    add     v19.4s, v3.4s, v23.4s    // k3+w[67:64]
    add     v20.4s, v3.4s, v24.4s    // k3+w[71:68]
    add     v21.4s, v3.4s, v25.4s   // k3+w[75:72]
    add     v22.4s, v3.4s, v26.4s   // k3+w[79:76]

    sha1h   s5, s6
    sha1p   q6, s7, v19.4s

    sha1h   s7, s6
    sha1p   q6, s5, v20.4s

    sha1h   s5, s6
    sha1p   q6, s7, v21.4s

    sha1h   s7, s6
    sha1p   q6, s5, v22.4s

    /* calculate H0 H1 H2 H3 H4 */
    add     v17.4s, v17.4s, v6.4s
    add     v18.4s, v18.4s, v7.4s

    add     v6.4s, v17.4s, v16.4s
    add     v7.4s, v18.4s, v16.4s

    cmp     x1, #64
    b.hs    .Lloop_sha1_ext_compress

    st1     {v17.4s}, [x2], #16
    st1     {v18.s}[0], [x2]
AARCH64_AUTIASP
    ret
.size   SHA1CryptoExt, .-SHA1CryptoExt

#endif
