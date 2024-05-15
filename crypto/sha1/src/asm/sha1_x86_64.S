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

.file   "sha1_x86_64.S"
.text

.set    INPUT, %rdi
.set    LEN, %rsi
.set    HASH, %rdx

.set    A, %r8d
.set    B, %r9d
.set    C, %r10d
.set    D, %r11d
.set    E, %r12d

.set    TEMP, %r13d
.set    TEMP1, %r15d
.set    TEMP2, %ebx
.set    TEMP3, %eax
.set    BLK0, %xmm0
.set    BLK1, %xmm1
.set    BLK2, %xmm2
.set    BLK3, %xmm3

.set    ZERO, %ymm4
.set    EXPAND0, %ymm5
.set    EXPAND1, %ymm6
.set    EXPAND2, %ymm7
.set    EXPAND3, %ymm8
.set    TEMP_W0, %ymm9
.set    TEMP_W1, %ymm10
.set    TEMP_W2, %ymm11
.set    KNUM, %ymm12

/* sha1 constant value used */
.section .rodata
.balign    64
.type    g_k, %object
g_k:
    .long   0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999  // K_00_19
    .long   0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1  // K_20_39
    .long   0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc  // K_40_59
    .long   0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6  // K_60_79
    .size   g_k, .-g_k

/* inverted mask */
.balign    64
.type    endian_mask, %object
endian_mask:
    .long 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f
    .long 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f
.size   endian_mask, .-endian_mask

/**
 *  Macro Description: Message compression, 0 to 18 rounds of data compression, pre-computation Next round F0, b
 *  Input register:
 *a - e, temp:  Intermediate variable of hash value
 *       addr:  Stack Address, Kt+W
 *   wkOffset:  Kt+W read Offset
 *    temp1-2:  temporary register
 *  Modify the register:  a e temp temp1 temp2
 *  Output register:
 *          a:   Next round F0
 *          e:  Indicates the value after a cyclic update.
 *       temp:   Next round B
 *  Macro implementation: F0(b,c,d) = (b AND c) OR ((NOT b) AND d)
 *                    =(((b) & (c)) | ((~(b)) & (d)))
 *          e = S^5(a) + F0(b,c,d) + e + W(i) + K(i)
 *          temp = S^30(b)
 */
.macro ROUND00_18 a, temp, b, c, d, e, addr, wkOffset, temp1, temp2
    addl  \wkOffset(\addr), \e                          // e = e + W + KT
    andn \c, \a, \temp1                                 // Next (~(b)) & (d)
    addl  \temp, \e                                     // e = F0(b, c, d) + e + W + KT
    rorxl   $27, \a, \temp2                             // Temp2 = ROTL32(a, 5)
    rorxl   $2, \a, \temp                               // Next ROTL32(b, 30)
    and   \b, \a                                        // Next ((b) & (c))
    addl  \temp2, \e                                    // e = F0(b, c, d) + e + W + KT + S^5(a)
    or   \temp1, \a                                     // Next (((b) & (c)) | ((~(b)) & (d)))
.endm

/**
 *  Macro Description: 0 to 18 rounds of message compression and 16 to 31 message extension,
 *                     pre-calculation Next round F0, b
 *  Input register:
 *a - e, temp: Intermediate variable of hash value
 *       addr: Stack Address, Kt+W
 *   wkOffset: Kt+W read offset
 *    temp1-2: temporary register
 *   wt_16_13: w(t-16) ~ w(t-13)
 *    wt_12_9: w(t-12) ~ w(t-9)
 *     wt_8_5: w(t-8)  ~ w(t-5)
 *     wt_4_1: w(t-4)  ~ w(t-1)
 *    expand0: w(t)  ~ w(t+3)
 *   tempw0-2: temporary register
 *      zero:  register with a value of zero
 *      knum:  k constant value
 *  Modify the register:  a b c d e temp temp1 temp2 expand0 tempw0 tempw1 tempw2
 *  Output register:
 *          a:  Third round B
 *          b:  Value after four rounds of cyclic update
 *          c:   Next round F0
 *          d:   Next round B
 *          e:  Fourth round B
 *       temp:  next b
 *    expand0: Value after a round of extension
 *  Macro implementation: f(b,c,d) = (b AND c) OR ((NOT b) AND d)
*                    =(((b) & (c)) | ((~(b)) & (d)))
 *          temp = S^5(a) + f(b,c,d) + e + W(i) + K(i)
 *          b = S^30(b)
 *      W(t  ) = ROL(W(t-3) ^ W(t-8) ^ W(t-14) ^ W(t-16), 1)
 *      W(t+1) = ROL(W(t-2) ^ W(t-7) ^ W(t-13) ^ W(t-15), 1)
 *      W(t+2) = ROL(W(t-1) ^ W(t-6) ^ W(t-12) ^ W(t-14), 1)
 *      W(t+3) = ROL(0      ^ W(t-5) ^ W(t-11) ^ W(t-13), 1)
 *      W(t+3) = W(t+3) ^ ROL(W(t), 1)
 */
.macro ROUND00_18_EXPAND a, temp, b, c, d, e, addr, wkOffset, wt_16_13, wt_12_9, wt_8_5, wt_4_1, expand0
    vpalignr $8, \wt_16_13, \wt_12_9, TEMP_W1            // Expand w(t-14) w(t-13) w(t-12) w(t-11)
    addl  \wkOffset(\addr), \e                          // e = e + W + KT
    andn \c, \a, TEMP1                                  // Next (~(b)) & (d)
    addl  \temp, \e                                     // e = F0 + e + W + KT
    vpalignr $4, \wt_4_1, ZERO, TEMP_W0                  // Expand w(t-3)  w(t-2)  w(t-1)  0
    vpxor   \wt_8_5, \wt_16_13, \expand0                // Expand w(t-8) ^ w(t-16)
    rorxl   $27, \a, TEMP2                              // Temp2 = ROTL32(a, 5)
    rorxl   $2, \a, \temp                               // Next ROTL32(b, 30)
    and   \b, \a                                        // Next ((b) & (c))
    vpxor   TEMP_W1, \expand0, \expand0                  // Expand w(t-14)  ^ w(t-8) ^ w(t-16)
    addl  TEMP2, \e                                     // e = F0 + e + W + KT + S^5(a)
    or   TEMP1, \a                                      // Next F0 done

    addl  \wkOffset + 4(\addr), \d                      // Next d = d + W + KT
    vpxor   TEMP_W0, \expand0, TEMP_W0                    // Expand tempw0 = w[t:t+4] before rol 1
    andn \b, \e, TEMP1                                  // Next F0
    addl  \a, \d                                        // d = F0 + d + W + KT
    rorxl   $27, \e, TEMP2                              // Temp2 = ROTL32(E, 5)
    rorxl   $2, \e, \a                                  // next ROTL32(E, 30)
    vpalignr $4, ZERO, TEMP_W0, TEMP_W1                   // Expand tempw1 = 0 0 0 w(t)
    and   \temp, \e                                     // Next F0
    addl  TEMP2, \d                                     // d = F0 + d + W + KT + S^5(E)
    or   TEMP1, \e                                      // Next F0 done

    vpsrld  $31, TEMP_W0, \expand0                       // Expand ROL(w(t), w(t+1), w(t+2), w(t+3),1)
    addl  \wkOffset + 8(\addr), \c                      // c = c + W + KT
    vpaddd TEMP_W0, TEMP_W0, TEMP_W0                       // Expand ROL(w(t), w(t+1), w(t+2), w(t+3),1)
    andn \temp, \d, TEMP1                               // Next F0
    addl  \e, \c                                        // c = F0 + c + W + KT
    rorxl   $27, \d, TEMP2                              // Temp2 = ROTL32(D, 5)
    rorxl   $2, \d, \e                                  // Next ROTL32(D, 30)
    vpsrld  $30, TEMP_W1, TEMP_W2                         // Expand ROL(w(t), 2)
    and   \a, \d                                        // Next F0
    addl  TEMP2, \c                                     // c = F0 + c + W + KT + S^5(D)
    or   TEMP1, \d                                      // Next F0 done

    vpslld  $2, TEMP_W1, TEMP_W1                          // Expand ROL(w(t), 2)
    vpxor \expand0, TEMP_W0, \expand0                    // Expand ROL(w(t), w(t+1), w(t+2), w(t+3),1)
    addl  \wkOffset + 12(\addr), \b                     // b = b + W + KT
    andn \a, \c, TEMP1                                  // Next F0
    vpxor TEMP_W2, TEMP_W1, TEMP_W0                        // Expand ROL(w(t), 2)
    addl  \d, \b                                        // b = F0 + b + W + KT
    rorxl   $27, \c, TEMP2                              // Temp2 = ROTL32(C, 5)
    rorxl   $2, \c, \d                                  // Next ROTL32(C, 30)
    vpxor \expand0, TEMP_W0, \expand0                    // Expand w[t:t+4]
    and   \e, \c                                        // Next F0
    addl  TEMP2, \b                                     // b = F0 + b + W + KT + S^5(C)
    vpaddd KNUM,\expand0, TEMP_W0                        // Expand w + k
    or   TEMP1, \c                                      // Next F0 done
    vmovdqa TEMP_W0, \wkOffset + 128(\addr)
.endm

/**
 *  Macro Description: Message compression, 20~39, 60~79 round data compression, precomputation Next round F1, b
 *  Input register:
 *a - e, temp:  Intermediate variable of hash value
 *       addr:  Stack Address, Kt+W
 *   wkOffset:  Kt+W read offset
 *    temp1-2:  temporary register
 *  Modify the register:  a e temp temp1 temp2
 *  Output register:
 *          a:   Next round F1
 *          e:  Indicates the value after a cyclic update.
 *       temp:   Next round B
 *  Macro implementation: F1(b,c,d) =  b XOR c XOR d
 *                    =(((b) ^ (c)) ^ (d))
 *          e = S^5(a) + F1(b,c,d) + e + W(i) + K(i)
 *          temp = S^30(b)
 */
.macro ROUND20_39 a, temp, b, c, d, e, addr, wkOffset, temp1, temp2
    addl  \wkOffset(\addr), \e                          // e = e + W + KT
    addl  \temp, \e                                     // e = F1(b, c, d) + e + W + KT
    rorx   $27, \a, TEMP2                               // Temp2 = ROTL32(a, 5)
    rorx   $2, \a, \temp                                // Next ROTL32(b, 30)
    xor   \b, \a                                        // Next (b) ^ (c)
    addl  TEMP2, \e                                     // e = F0(b, c, d) + e + W + KT + S^5(a)
    xor   \c, \a                                        // Next (b) ^ (c) ^ (d)
.endm

/**
 *  Macro Description: 20~39, 60~79 round data compression, and 16-31 message extension, precomputation Next round F1, b
 *  Input register:
 *a - e, temp: Intermediate variable of hash value
 *       addr: Stack Address, Kt+W
 *   wkOffset: Kt+W read offset
 *    temp1-2: temporary register
 *   wt_32_29: w(t-32) ~ w(t-29)
 *   wt_28_25: w(t-28) ~ w(t-25)
 *     wt_8_5: w(t-8)  ~ w(t-5)
 *     wt_4_1: w(t-4)  ~ w(t-1)
 *    expand0: w(t)  ~ w(t+3)
 *      zero: register with a value of zero
 *      knum: k constant value
 *  Modify the register:  a b c d e temp temp1 temp2 wt_32_29 tempw0
 *  Output register:
 *          a:  Third round B value
 *          b:  Value after four rounds of cyclic update
 *          c:   Next round F1
 *          d:   Next round B
 *          e:  Fourth round B value
 *       temp:  next b
 *    expand0: Value after a round of extension
 *  Macro implementation: F1(b,c,d) =  b XOR c XOR d
 *                    =(((b) ^ (c)) ^ (d))
 *          e = S^5(a) + F1(b,c,d) + e + W(i) + K(i)
 *          temp = S^30(b)
 *          w(t) = ROL(w(t-3)  ^ w(t-8)  ^ w(t-14) ^ w(t-16), 1)
 *               = ROL(w(t-6)  ^ w(t-11) ^ w(t-17) ^ w(t-19) ^
 *                     w(t-11) ^ w(t-16) ^ w(t-22) ^ w(t-24) ^
 *                     w(t-17) ^ w(t-22) ^ w(t-28) ^ w(t-30) ^
 *                     w(t-19) ^ w(t-24) ^ w(t-30) ^ w(t-32), 2)
 *               = ROL(w(t-6)  ^ w(t-16) ^ w(t-28) ^ w(t-32), 2)
 *          w(t+1), w(t+2), w(t+3) in the same way
 */
.macro ROUND20_39_EXPAND a, temp, b, c, d, e, addr, wkOffset, wt_32_29, wt_28_25, wt_16_13, wt_8_5, wt_4_1, wkOffset2
    vpalignr $8, \wt_8_5, \wt_4_1, TEMP_W0               // Expand w(t-6), w(t-5), w(t-4), w(t-3)
    vpxor   \wt_32_29, \wt_16_13, \wt_32_29             // Expand wt_32_29 =w[t-32:t-28] ^ w[t-16:t-12]
    addl  \wkOffset(\addr), \e                          // e = e + W + KT
    addl  \temp, \e                                     // e = F1(b, c, d) + e + W + KT
    rorx   $27, \a, TEMP2                               // temp2 = ROTL32(a, 5)
    rorx   $2, \a, \temp                                // Next ROTL32(b, 30)
    vpxor   \wt_32_29, \wt_28_25, \wt_32_29             // Expand wt_32_29 =w[t-32:t-28] ^ w[t-16:t-12]^ w[t-28:t-24]
    xor   \b, \a                                        // Next (b) ^ (c)
    addl  TEMP2, \e                                     // e = F0(b, c, d) + e + W + KT + S^5(a)
    xor   \c, \a                                        // Next F1 done

    addl  \wkOffset + 4(\addr), \d                      // d = d + W + KT
    vpxor   \wt_32_29, TEMP_W0, \wt_32_29                // Expand wt_32_29 =w[t-32] ^ w[t-16]^ w[t-28]^ w[t-6]
    addl  \a, \d                                        // d = F1 + d + W + KT
    rorx   $27, \e, TEMP2                               // Temp2 = ROTL32(e, 5)
    rorx   $2, \e, \a                                   // Next temp = ROTL32(e, 30)
    xor   \temp, \e                                     // Next F1
    addl  TEMP2, \d                                     // Expand d = F1 + d + W + KT + S^5(e)
    vpsrld  $30, \wt_32_29, TEMP_W0                      // Expand ROL(wt_32_29,2)
    xor   \b, \e                                        // Next F1 done

    addl  \wkOffset + 8(\addr), \c                      // c = c + W + KT
    addl  \e, \c                                        // c = F1 + c + W + KT
    rorx   $27, \d, TEMP2                               // Temp2 = ROTL32(e, 5)
    rorx   $2, \d, \e                                   // Next ROTL32(e, 30)
    vpslld  $2, \wt_32_29, \wt_32_29
    xor   \a, \d                                        // Next F1
    addl  TEMP2, \c                                     // c = F1 + c + W + KT + S^5(e)
    xor   \temp, \d                                     // Next F1 done

    addl  \wkOffset + 12(\addr), \b                     // b = b + W + KT
    vpxor \wt_32_29, TEMP_W0, \wt_32_29                  // Expand ROL(wt_32_29,2)
    rorx   $27, \c, TEMP2                               // Temp2 = ROTL32(c, 5)
    addl  \d, \b                                        // b = F1 + b + W + KT
    rorx   $2, \c, \d                                   // Next ROTL32(c, 30)
    vpaddd KNUM, \wt_32_29, TEMP_W0
    xor   \e, \c                                        // Next F1
    addl  TEMP2, \b                                     // b = F1 + b + W + KT + S^5(c)
    xor   \a, \c                                        // Next F1 done
    vmovdqa TEMP_W0, \wkOffset2(\addr)
.endm

/**
 *  Macro Description: Message compression, 40~59 round data compression, pre-computation Next round F2, b
 *  Input register:
 *a - e, temp:  Intermediate variable of hash value
 *       addr:  Stack Address, Kt+W
 *   wkOffset:  Kt+W read offset
 *    temp1-2:  temporary register
 *  Modify the register:  a e temp temp1 temp2
 *  Output register:
 *          a:   Next round F1
 *          e:  Indicates the value after a cyclic update.
 *       temp:   Next round B
 *  Macro implementation: F1(b,c,d) = (b AND c) OR (b AND d) OR (c AND d)
 *                    =((b^c) & (c^d) ^ c)
 *          e = S^5(a) + F1(b,c,d) + e + W(i) + K(i)
 *          temp = S^30(b)
 */
.macro ROUND40_59 a, temp, b, c, d, e, addr, wkOffset, temp1, temp2
    addl  \wkOffset(\addr), \e                          // e = e + W + KT
    mov   \c, \temp1
    addl  \temp, \e                                     // e = F2(b, c, d) + e + W + KT
    xor   \b, \temp1                                    // Next (c^d)
    rorx   $27, \a, \temp2                              // Temp2 = ROTL32(a, 5)
    rorx   $2, \a, \temp                                // Next ROTL32(b, 30)
    xor   \b, \a                                        // Next (b^c)
    addl  \temp2, \e                                    // e = F0(b, c, d) + e + W + KT + S^5(a)
    and   \temp1, \a                                    // Next (b^c) & (c^d)
    xor   \b, \a                                        // Next (((b^c)) & (c^d) ^ c)
.endm

/**
 *  Macro Description: 40~59 round data compression, and 32 to 79 rounds of message extension,
 * precomputation Next round F2, b
 *  Input register:
 *a - e, temp: Intermediate variable of hash value
 *       addr: Stack Address, Kt+W
 *   wkOffset: Kt+W read offset
 *    temp1-2: temporary register
 *   wt_32_29: w(t-32) ~ w(t-29)
 *   wt_28_25: w(t-28) ~ w(t-25)
 *     wt_8_5: w(t-8)  ~ w(t-5)
 *     wt_4_1: w(t-4)  ~ w(t-1)
 *    expand0: w(t)  ~ w(t+3)
 *      zero: register with a value of zero
 *      knum: k constant value
 *  Modify the register:  a b c d e temp temp1 temp2 wt_32_29 tempw0
 *  Output register:
 *          a:  Third round B value
 *          b:  Value after four rounds of cyclic update
 *          c:   Next round F1
 *          d:   Next round B
 *          e:  Fourth round B value
 *       temp:  next b
 *    expand0: Value after a round of extension
 *  Macro implementation: F1(b,c,d) = (b AND c) OR (b AND d) OR (c AND d)
 *                    =((b^c) & (c^d) ^ c)
 *          e = S^5(a) + F1(b,c,d) + e + W(i) + K(i)
 *          w(t) = ROL(w(t-3)  ^ w(t-8)  ^ w(t-14) ^ w(t-16), 1)
 *               = ROL(w(t-6)  ^ w(t-11) ^ w(t-17) ^ w(t-19) ^
 *                     w(t-11) ^ w(t-16) ^ w(t-22) ^ w(t-24) ^
 *                     w(t-17) ^ w(t-22) ^ w(t-28) ^ w(t-30) ^
 *                     w(t-19) ^ w(t-24) ^ w(t-30) ^ w(t-32), 2)
 *               = ROL(w(t-6)  ^ w(t-16) ^ w(t-28) ^ w(t-32), 2)
 *          w(t+1), w(t+2), w(t+3) in the same way
 */
.macro ROUND40_59_EXPAND a, temp, b, c, d, e, addr, wkOffset, wt_32_29, wt_28_25, wt_16_13, wt_8_5, wt_4_1, wkOffset2
    vpalignr $8, \wt_8_5, \wt_4_1, TEMP_W0               // Expand w(t-6), w(t-5), w(t-4), w(t-3)
    vpxor   \wt_32_29, \wt_16_13, \wt_32_29             // Expand wt_32_29 =w[t-32:t-28] ^ w[t-16:t-12]
    addl  \wkOffset(\addr), \e                          // e = e + W + KT
    mov   \c, TEMP1
    addl  \temp, \e                                     // e = F2(b, c, d) + e + W + KT
    xor   \b, TEMP1                                     // Next temp1 = (c^d)
    rorx   $27, \a, TEMP2                               // Temp2 = ROTL32(a, 5)
    rorx   $2, \a, \temp                                // Next ROTL32(b, 30)
    vpxor   \wt_32_29, \wt_28_25, \wt_32_29             // Expand wt_32_29 =w[t-32:t-28] ^ w[t-16:t-12]^ w[t-28:t-24]
    xor   \b, \a                                        // Next (b^c)
    addl  TEMP2, \e                                     // e = F0(b, c, d) + e + W + KT + S^5(a)
    and   TEMP1, \a                                     // Next (b^c) & (c^d)
    addl  \wkOffset + 4(\addr), \d                      // d = d + W + KT
    xor   \b, \a                                        // Next (((b^c)) & (c^d) ^ c)

    vpxor   \wt_32_29, TEMP_W0, \wt_32_29                // Expand wt_32_29 =w[t-32] ^ w[t-16]^ w[t-28]^ w[t-6]
    mov   \b, TEMP1
    addl  \a, \d                                        // d = F2 + d + W + KT
    xor   \temp, TEMP1                                  // Next F2
    rorx   $27, \e, TEMP2                               // Temp2 = ROTL32(e, 5)
    rorx   $2, \e, \a                                   // Next ROTL32(e, 30)
    addl  \wkOffset + 8(\addr), \c                      // c = c + W + KT
    xor   \temp, \e                                     // Next F2
    vpsrld  $30, \wt_32_29, TEMP_W0                      // Expand ROL(wt_32_29,2)
    and   TEMP1, \e                                     // Next F2
    addl  TEMP2, \d                                     // d = F2 + d + W + KT + S^5(e)
    xor   \temp, \e                                     // Next F2 done

    mov   \temp, TEMP1
    addl  \e, \c                                        // c = F2 + c + W + KT
    xor   \a, TEMP1                                     // Next F2
    vpslld  $2, \wt_32_29, \wt_32_29
    rorx   $27, \d, TEMP2                               // Temp2 = ROTL32(d, 5)
    rorx   $2, \d, \e                                   // Next ROTL32(d, 30)
    xor   \a, \d                                        // Next F2
    addl  TEMP2, \c                                     // c = F2 + c + W + KT + S^5(d)
    and   TEMP1, \d                                     // Next F2
    addl  \wkOffset + 12(\addr), \b                     // b = b + W + KT
    vpxor \wt_32_29, TEMP_W0, \wt_32_29                  // Expand ROL(wt_32_29,2)
    xor   \a, \d                                        // Next F2 done

    mov   \a, TEMP1
    addl  \d, \b                                        // b = F2 + b + W + KT
    xor   \e, TEMP1                                     // Next F2
    rorx   $27, \c, TEMP2                               // Temp2 = ROTL32(c, 5)
    rorx   $2, \c, \d                                   // Next ROTL32(c, 30)
    xor   \e, \c                                        // Next F2
    vpaddd KNUM, \wt_32_29, TEMP_W0
    addl  TEMP2, \b                                     // b = F2 + b + W + KT + S^5(c)
    and   TEMP1, \c                                     // Next F2
    xor   \e, \c                                        // Next F2 done
    vmovdqa TEMP_W0, \wkOffset2(\addr)
.endm

/**
 *  Function Description: Perform SHA1 compression calculation based on the input message and update the hash value.
 *  Function prototype: static const uint8_t *SHA1_Step(const uint8_t *input, uint32_t len, uint32_t *h)
 *  Input register:
 *         rdi:  Pointer to the input data address
 *         rsi:  Message length
 *         rdx:  Storage address of the hash value
 *  Register usage:  r8~r12: A~E, r13: TEMP, r15, ebx, eax: temporary register, ymm0~ymm3: w0~w15 Message block,
 * ymm4: 0, ymm5~ymm8: extended message block, ymm9~ymm13: temporary register, ymm13: k+w value
 *  Output register:  rax Returns the address of the message for which SHA1 calculation is not performed.
 *  Function/Macro Call: ROUND00_18, ROUND00_18_EXPAND, ROUND20_39, ROUND20_39_EXPAND, ROUND40_59, ROUND40_59_EXPAND
 */
.text
.globl  SHA1_Step
    .type   SHA1_Step, @function
SHA1_Step:
    .cfi_startproc
    cmp     $64, LEN
    jb      .Lend_sha1

    push    %rbx
    push    %rbp
    push    %r12
    push    %r13
    push    %r14
    push    %r15
    mov     %rsp, %r14
    lea     -1024(%rsp), %rsp                            // Apply for 1024-byte stack space.

    mov     0(HASH), A      // r8~r13: a~e
    mov     4(HASH), B
    andq    $-256, %rsp
    mov     8(HASH), C
    mov     12(HASH), D
    mov     16(HASH), E

.Lloop_sha1_compress:
.align  16
    vmovdqu (INPUT), BLK0                                // Loads the data of a block to the lower 128 bits
                                                         // of the YMM register.
    vmovdqu 16(INPUT), BLK1
    vmovdqu 32(INPUT), BLK2
    sub     $64, LEN
    vmovdqu 48(INPUT), BLK3
    add     $64, INPUT

    cmp     $64, LEN                                     // Check whether the remaining length is greater than 64.
    jb .Lsha1_compress
    vinserti128 $1, 0(INPUT), %ymm0, %ymm0               // Loads the data of a block to the upper 128 bits
                                                         // of the ymm register.
    vinserti128 $1, 16(INPUT), %ymm1, %ymm1
    vinserti128 $1, 32(INPUT), %ymm2, %ymm2
    vinserti128 $1, 48(INPUT), %ymm3, %ymm3
    add     $64, INPUT

.Lsha1_compress:
    vmovdqa endian_mask + 0(%rip), %ymm8                // Endian inversion mask
    leaq g_k + 0(%rip), %rbp                            // Get k

    vpshufb %ymm8, %ymm0, %ymm0                         // Little endian to big endian
    vmovdqa 0(%rbp), KNUM
    vpshufb %ymm8, %ymm1, %ymm1
    vpaddd  KNUM, %ymm0, %ymm13                         // w[0:15] + k0
    vpshufb %ymm8, %ymm2, %ymm2
    vmovdqa %ymm13, 0(%rsp)                             // wk push stack
    vpaddd  KNUM, %ymm1, %ymm9
    vpshufb %ymm8, %ymm3, %ymm3
    vmovdqa %ymm9, 32(%rsp)
    vpaddd  KNUM, %ymm2, %ymm10
    vpxor   %ymm4, %ymm4, %ymm4

    mov     C, TEMP                                      // The first round F0
    vmovdqa %ymm10, 64(%rsp)
    and     B, TEMP                                      // Round0 ((b) & (c))
    andn    D, B, TEMP2                                  // Round0 (~(b)) & (d)
    vpaddd  KNUM, %ymm3, %ymm11
    or      TEMP2, TEMP                                  // Round0 (((b) & (c)) | ((~(b)) & (d)))
    rol     $30, B                                       // Round0 B = ROTL32(B, 30)
    vmovdqa %ymm11, 96(%rsp)
    ROUND00_18_EXPAND A, TEMP, B, C, D, E, %rsp, 0, %ymm0, %ymm1, %ymm2, %ymm3, EXPAND0
    vmovdqa 32(%rbp), KNUM
    ROUND00_18_EXPAND B, C, D, E, A, TEMP, %rsp, 32, %ymm1, %ymm2, %ymm3, EXPAND0, EXPAND1
    ROUND00_18_EXPAND D, E, A, TEMP, B, C, %rsp, 64, %ymm2, %ymm3, EXPAND0, EXPAND1, EXPAND2
    ROUND00_18_EXPAND A, TEMP, B, C, D, E, %rsp, 96, %ymm3, EXPAND0, EXPAND1, EXPAND2, EXPAND3
    ROUND00_18 B, C, D, E, A, TEMP, %rsp, 128, TEMP1, TEMP2
    ROUND00_18 TEMP, B, C, D, E, A, %rsp, 132, TEMP1, TEMP2
    ROUND00_18 A, TEMP, B, C, D, E, %rsp, 136, TEMP1, TEMP2     // 18
    addl    140( %rsp), D                                 // D = DE + W + KT
    rorx    $27, E, TEMP2                                 // TEMP2 = ROTL32(E, 5)
    addl    A, D                                          // D = F0 + D + W + KT
    rorx    $2, E, A                                      // Round20 ROTL32(E, 30)
    xor     TEMP, E                                       // Round20 (TEMP) ^ (E)
    addl    TEMP2, D                                      // D = F0 + D + W + KT + S^5(E)
    xor     B, E                                          // Round20 F1

    ROUND20_39_EXPAND D, E, A, TEMP, B, C, %rsp, 160, %ymm0, %ymm1, EXPAND0, EXPAND2, EXPAND3, 256
    ROUND20_39_EXPAND A, TEMP, B, C, D, E, %rsp, 192, %ymm1, %ymm2, EXPAND1, EXPAND3, %ymm0, 288
    vmovdqa 64(%rbp), KNUM
    ROUND20_39_EXPAND B, C, D, E, A, TEMP, %rsp, 224, %ymm2, %ymm3, EXPAND2, %ymm0, %ymm1, 320
    ROUND20_39_EXPAND D, E, A, TEMP, B, C, %rsp, 256, %ymm3, EXPAND0, EXPAND3, %ymm1, %ymm2, 352
    ROUND20_39 A, TEMP, B, C, D, E, %rsp, 288, TEMP1, TEMP2
    ROUND20_39 E, A, TEMP, B, C, D, %rsp, 292, TEMP1, TEMP2
    ROUND20_39 D, E, A, TEMP, B, C, %rsp, 296, TEMP1, TEMP2     // 38
    addl    300(%rsp), B                                  // B = B + W + KT
    mov     A, TEMP1
    addl    D, B                                          // B = F1 + B + W + KT
    xor     E, TEMP1                                      // Round40 (E^A)
    rorx    $27, C, TEMP2                                 // TEMP2 = ROTL32(C, 5)
    rorx    $2, C, D                                      // Round40 ROTL32(C, 30)
    xor     E, C                                          // Round40 (E^C)
    addl    TEMP2, B                                      // B = F1 + B + W + KT + S^5(C)
    and     TEMP1, C                                      // Round40 (E^A) & (E^C)
    xor     E, C                                          // Round40 F2

    ROUND40_59_EXPAND B, C, D, E, A, TEMP, %rsp, 320, EXPAND0, EXPAND1, %ymm0, %ymm2, %ymm3, 384
    ROUND40_59_EXPAND D, E, A, TEMP, B, C, %rsp, 352, EXPAND1, EXPAND2, %ymm1, %ymm3, EXPAND0, 416
    ROUND40_59_EXPAND A, TEMP, B, C, D, E, %rsp, 384, EXPAND2, EXPAND3, %ymm2, EXPAND0, EXPAND1, 448
    vmovdqa 96(%rbp), KNUM
    ROUND40_59_EXPAND B, C, D, E, A, TEMP, %rsp, 416, EXPAND3, %ymm0, %ymm3, EXPAND1, EXPAND2, 480
    ROUND40_59 D, E, A, TEMP, B, C, %rsp, 448, TEMP1, TEMP2
    ROUND40_59 C, D, E, A, TEMP, B, %rsp, 452, TEMP1, TEMP2
    ROUND40_59 B, C, D, E, A, TEMP, %rsp, 456, TEMP1, TEMP2 // 58
    addl    460(%rsp), A                                  // A = A + W + KT
    rorx    $27, TEMP, TEMP2                              // TEMP2 = ROTL32(TEMP, 5)
    addl    B, A                                          // A = F2 + A + W + KT
    rorx    $2, TEMP, B                                   // Round60 ROTL32(TEMP, 30)
    xor     C, TEMP                                       // Round60 (C) ^ (TEMP)
    addl    TEMP2, A                                      // A = F2 + A + W + KT + S^5(TEMP)
    xor     D, TEMP                                       // Round60 F0

    ROUND20_39_EXPAND A, TEMP, B, C, D, E, %rsp, 480, %ymm0, %ymm1, EXPAND0, EXPAND2, EXPAND3, 512
    ROUND20_39_EXPAND B, C, D, E, A, TEMP, %rsp, 512, %ymm1, %ymm2, EXPAND1, EXPAND3, %ymm0, 544
    ROUND20_39_EXPAND D, E, A, TEMP, B, C, %rsp, 544, %ymm2, %ymm3, EXPAND2, %ymm0, %ymm1, 576
    ROUND20_39_EXPAND A, TEMP, B, C, D, E, %rsp, 576, %ymm3, EXPAND0, EXPAND3, %ymm1, %ymm2, 608
    ROUND20_39 B, C, D, E, A, TEMP, %rsp, 608, TEMP1, TEMP2
    ROUND20_39 TEMP, B, C, D, E, A, %rsp, 612, TEMP1, TEMP2
    ROUND20_39 A, TEMP, B, C, D, E, %rsp, 616, TEMP1, TEMP2 // 78
    addl    620(%rsp), D                                   // D = D + W + KT
    add     E, 4(HASH)                                     // Update HASH
    lea     (A, D), D                                      // D = F1 + D + W + KT
    add     TEMP, 8(HASH)
    rorx    $27, E, TEMP2                                  // TEMP2 = ROTL32(E, 5)

    add     B, 12(HASH)
    addl    TEMP2, D                                       // D = F1 + D + W + KT + S^5(E)
    add     C, 16(HASH)
    mov     4(HASH), B
    add     D, 0(HASH)
    mov     8(HASH), C
    mov     16(HASH), E
    mov     12(HASH), D
    mov     0(HASH), A

    cmp     $64, LEN                                       // Check whether the upper-bit register is calculated.
    jb      .Lend_sha1_pre
    sub     $64, LEN

    mov     C, TEMP
    andn    D, B, TEMP2                                    // TEMP2 = (~(b)) & (d)
    and     B, TEMP                                        // TEMP=((b) & (c))
    or      TEMP2, TEMP                                    // TEMP = (((b) & (c)) | ((~(b)) & (d)))
    rol     $30, B                                         // B = ROTL32(B, 30)
    ROUND00_18 A, TEMP, B, C, D, E, %rsp, 16, TEMP1, TEMP2
    ROUND00_18 E, A, TEMP, B, C, D, %rsp, 20, TEMP1, TEMP2
    ROUND00_18 D, E, A, TEMP, B, C, %rsp, 24, TEMP1, TEMP2
    ROUND00_18 C, D, E, A, TEMP, B, %rsp, 28, TEMP1, TEMP2          // Round 3

    ROUND00_18 B, C, D, E, A, TEMP, %rsp, 48, TEMP1, TEMP2
    ROUND00_18 TEMP, B, C, D, E, A, %rsp, 52, TEMP1, TEMP2
    ROUND00_18 A, TEMP, B, C, D, E, %rsp, 56, TEMP1, TEMP2
    ROUND00_18 E, A, TEMP, B, C, D, %rsp, 60, TEMP1, TEMP2          // Round 7

    ROUND00_18 D, E, A, TEMP, B, C, %rsp, 80, TEMP1, TEMP2
    ROUND00_18 C, D, E, A, TEMP, B, %rsp, 84, TEMP1, TEMP2
    ROUND00_18 B, C, D, E, A, TEMP, %rsp, 88, TEMP1, TEMP2
    ROUND00_18 TEMP, B, C, D, E, A, %rsp, 92, TEMP1, TEMP2          // Round 11

    ROUND00_18 A, TEMP, B, C, D, E, %rsp, 112, TEMP1, TEMP2
    ROUND00_18 E, A, TEMP, B, C, D, %rsp, 116, TEMP1, TEMP2
    ROUND00_18 D, E, A, TEMP, B, C, %rsp, 120, TEMP1, TEMP2
    ROUND00_18 C, D, E, A, TEMP, B, %rsp, 124, TEMP1, TEMP2         // Round 15

    ROUND00_18 B, C, D, E, A, TEMP, %rsp, 144, TEMP1, TEMP2
    ROUND00_18 TEMP, B, C, D, E, A, %rsp, 148, TEMP1, TEMP2
    ROUND00_18 A, TEMP, B, C, D, E, %rsp, 152, TEMP1, TEMP2         // Round 18
    addl    156( %rsp), D                                  // D = D + W + KT
    rorx    $27, E, TEMP2                                  // TEMP2 = ROTL32(E, 5)
    addl    A, D                                           // D = F0 + D + W + KT
    rorx    $2, E, A                                       // Round20 ROTL32(E, 30)
    xor     TEMP, E                                        // Round20 (TEMP) ^ (E)
    addl    TEMP2, D                                       // D = F0 + D + W + KT + S^5(E)
    xor     B, E                                           // Round20 F1

    ROUND20_39 D, E, A, TEMP, B, C, %rsp, 176, TEMP1, TEMP2
    ROUND20_39 C, D, E, A, TEMP, B, %rsp, 180, TEMP1, TEMP2
    ROUND20_39 B, C, D, E, A, TEMP, %rsp, 184, TEMP1, TEMP2
    ROUND20_39 TEMP, B, C, D, E, A, %rsp, 188, TEMP1, TEMP2         // Round 23

    ROUND20_39 A, TEMP, B, C, D, E, %rsp, 208, TEMP1, TEMP2
    ROUND20_39 E, A, TEMP, B, C, D, %rsp, 212, TEMP1, TEMP2
    ROUND20_39 D, E, A, TEMP, B, C, %rsp, 216, TEMP1, TEMP2
    ROUND20_39 C, D, E, A, TEMP, B, %rsp, 220, TEMP1, TEMP2         // Round 27

    ROUND20_39 B, C, D, E, A, TEMP, %rsp, 240, TEMP1, TEMP2
    ROUND20_39 TEMP, B, C, D, E, A, %rsp, 244, TEMP1, TEMP2
    ROUND20_39 A, TEMP, B, C, D, E, %rsp, 248, TEMP1, TEMP2
    ROUND20_39 E, A, TEMP, B, C, D, %rsp, 252, TEMP1, TEMP2         // Round 31

    ROUND20_39 D, E, A, TEMP, B, C, %rsp, 272, TEMP1, TEMP2
    ROUND20_39 C, D, E, A, TEMP, B, %rsp, 276, TEMP1, TEMP2
    ROUND20_39 B, C, D, E, A, TEMP, %rsp, 280, TEMP1, TEMP2
    ROUND20_39 TEMP, B, C, D, E, A, %rsp, 284, TEMP1, TEMP2         // Round 35

    ROUND20_39 A, TEMP, B, C, D, E, %rsp, 304, TEMP1, TEMP2
    ROUND20_39 E, A, TEMP, B, C, D, %rsp, 308, TEMP1, TEMP2
    ROUND20_39 D, E, A, TEMP, B, C, %rsp, 312, TEMP1, TEMP2         // Round 38
    addl    316(%rsp), B                                            // B = B + W + KT
    mov     A, TEMP1
    addl    D, B                                                    // B = F1 + B + W + KT
    xor     E, TEMP1                                                // Round40 (A^E)
    rorx    $2, C, D                                                // Round40 ROTL32(C, 30)
    rorx    $27, C, TEMP2                                           // TEMP2 = ROTL32(C, 5)
    xor     E, C                                                    // Round40 (E^C)
    addl    TEMP2, B                                                // B = F1 + B + W + KT + S^5(C)
    and     TEMP1, C                                                // Round40 (A^E) & (E^C)
    xor     E, C                                                    // Round40 F2

    ROUND40_59 B, C, D, E, A, TEMP, %rsp, 336, TEMP1, TEMP2
    ROUND40_59 TEMP, B, C, D, E, A, %rsp, 340, TEMP1, TEMP2
    ROUND40_59 A, TEMP, B, C, D, E, %rsp, 344, TEMP1, TEMP2
    ROUND40_59 E, A, TEMP, B, C, D, %rsp, 348, TEMP1, TEMP2         // Round 43

    ROUND40_59 D, E, A, TEMP, B, C, %rsp, 368, TEMP1, TEMP2
    ROUND40_59 C, D, E, A, TEMP, B, %rsp, 372, TEMP1, TEMP2
    ROUND40_59 B, C, D, E, A, TEMP, %rsp, 376, TEMP1, TEMP2
    ROUND40_59 TEMP, B, C, D, E, A, %rsp, 380, TEMP1, TEMP2         // Round 47

    ROUND40_59 A, TEMP, B, C, D, E, %rsp, 400, TEMP1, TEMP2
    ROUND40_59 E, A, TEMP, B, C, D, %rsp, 404, TEMP1, TEMP2
    ROUND40_59 D, E, A, TEMP, B, C, %rsp, 408, TEMP1, TEMP2
    ROUND40_59 C, D, E, A, TEMP, B, %rsp, 412, TEMP1, TEMP2         // Round 51

    ROUND40_59 B, C, D, E, A, TEMP, %rsp, 432, TEMP1, TEMP2
    ROUND40_59 TEMP, B, C, D, E, A, %rsp, 436, TEMP1, TEMP2
    ROUND40_59 A, TEMP, B, C, D, E, %rsp, 440, TEMP1, TEMP2
    ROUND40_59 E, A, TEMP, B, C, D, %rsp, 444, TEMP1, TEMP2         // Round 55

    ROUND40_59 D, E, A, TEMP, B, C, %rsp, 464, TEMP1, TEMP2
    ROUND40_59 C, D, E, A, TEMP, B, %rsp, 468, TEMP1, TEMP2
    ROUND40_59 B, C, D, E, A, TEMP, %rsp, 472, TEMP1, TEMP2         // Round 58
    addl    476(%rsp), A                                            // A = A + W + KT
    rorx    $27, TEMP, TEMP2                                        // TEMP2 = ROTL32(TEMP, 5)
    addl    B, A                                                    // A = F2 + A + W + KT
    rorx    $2, TEMP, B                                             // Round60 ROTL32(TEMP, 30)
    xor     C, TEMP                                                 // Round60 (TEMP) ^ (c)
    addl    TEMP2, A                                                // A = F2 + A + W + KT + S^5(TEMP)
    xor     D, TEMP                                                 // Round60 F1

    ROUND20_39 A, TEMP, B, C, D, E, %rsp, 496, TEMP1, TEMP2
    ROUND20_39 E, A, TEMP, B, C, D, %rsp, 500, TEMP1, TEMP2
    ROUND20_39 D, E, A, TEMP, B, C, %rsp, 504, TEMP1, TEMP2
    ROUND20_39 C, D, E, A, TEMP, B, %rsp, 508, TEMP1, TEMP2         // Round 63

    ROUND20_39 B, C, D, E, A, TEMP, %rsp, 528, TEMP1, TEMP2
    ROUND20_39 TEMP, B, C, D, E, A, %rsp, 532, TEMP1, TEMP2
    ROUND20_39 A, TEMP, B, C, D, E, %rsp, 536, TEMP1, TEMP2
    ROUND20_39 E, A, TEMP, B, C, D, %rsp, 540, TEMP1, TEMP2         // Round 67

    ROUND20_39 D, E, A, TEMP, B, C, %rsp, 560, TEMP1, TEMP2
    ROUND20_39 C, D, E, A, TEMP, B, %rsp, 564, TEMP1, TEMP2
    ROUND20_39 B, C, D, E, A, TEMP, %rsp, 568, TEMP1, TEMP2
    ROUND20_39 TEMP, B, C, D, E, A, %rsp, 572, TEMP1, TEMP2         // Round 71

    ROUND20_39 A, TEMP, B, C, D, E, %rsp, 592, TEMP1, TEMP2
    ROUND20_39 E, A, TEMP, B, C, D, %rsp, 596, TEMP1, TEMP2
    ROUND20_39 D, E, A, TEMP, B, C, %rsp, 600, TEMP1, TEMP2
    ROUND20_39 C, D, E, A, TEMP, B, %rsp, 604, TEMP1, TEMP2         // Round 75

    ROUND20_39 B, C, D, E, A, TEMP, %rsp, 624, TEMP1, TEMP2
    ROUND20_39 TEMP, B, C, D, E, A, %rsp, 628, TEMP1, TEMP2
    ROUND20_39 A, TEMP, B, C, D, E, %rsp, 632, TEMP1, TEMP2         // Round 78
    addl    636(%rsp), D                                            // D = D + W + KT
    add     E, 4(HASH)                                              // Update HASH
    add     TEMP, 8(HASH)                                           // Upadate H0~H5
    lea     (A, D), D                                               // D = F1 + D + W + KT
    rorx    $27, E, TEMP2                                           // TEMP2 = ROTL32(E, 5)
    add     B, 12(HASH)
    add     C, 16(HASH)
    addl    TEMP2, D                                                // D = F1 + D + W + KT + S^5(E)
    mov     4(HASH), B
    mov     8(HASH), C
    add     D, 0(HASH)
    mov     16(HASH), E
    mov     12(HASH), D
    mov     0(HASH), A
    cmp     $64, LEN
    jae    .Lloop_sha1_compress

.Lend_sha1_pre:
    mov %r14, %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
.Lend_sha1:
    mov INPUT, %rax
    ret
    .cfi_endproc
    .size SHA1_Step, .-SHA1_Step

#endif
