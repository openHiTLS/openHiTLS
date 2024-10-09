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
#ifdef HITLS_CRYPTO_MD5

.file   "md5_x86_64.S"

.set TEMP1, %r14d
.set TEMP2, %r15d

.set    T, %r13d
.set    W, %r12d

.set    T_ORIGIN_ADDR, %rcx
.set    HASH, %rdi
.set    INPUT, %rsi
.set    NUM, %rdx

.set    S11, 7
.set    S12, 12
.set    S13, 17
.set    S14, 22
.set    S21, 5
.set    S22, 9
.set    S23, 14
.set    S24, 20
.set    S31, 4
.set    S32, 11
.set    S33, 16
.set    S34, 23
.set    S41, 6
.set    S42, 10
.set    S43, 15
.set    S44, 21

.set    A, %r8d
.set    B, %r9d
.set    C, %r10d
.set    D, %r11d

/* MD5 Used constant value. For details about the data source, see the RFC1321 document. */
    .text
    .align 64
    .type	g_tMd5, %object
g_tMd5:
    .long   0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE
    .long   0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501
    .long   0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE
    .long   0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821

    .long   0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA
    .long   0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8
    .long   0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED
    .long   0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A

    .long   0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C
    .long   0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70
    .long   0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05
    .long   0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665

    .long   0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039
    .long   0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1
    .long   0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1
    .long   0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
.size    g_tMd5, .-g_tMd5

/*
 *  Macro description: The FF function processes the update of a hash value in a round of 0-15 compression.
 *  Input register:
 *       wAddr: sequence corresponding to W (wi)
 *       tAddr: order (ti) corresponding to t
 *       a - d: intermediate variable of the hash value
 *  Change register: r8d-r15d
 *  Output register:
 *           a: indicates the value after a round of cyclic update.
 *  Function/Macro Call: None
 *  Implementation description:
 *          Parameter: S11->28, S12->48, S13->17, S14->22
 *          T2 = BSIG0(a) + MAJ(a,b,c)
 *          a = b + ROTL32(F(a,b,c)+x+ac),s)
 *               F(X,Y,Z) = XY v not(X) Z
 *        G(X,Y,Z) = XZ v Y not(Z)
 *        H(X,Y,Z) = X xor Y xor Z
 *        I(X,Y,Z) = Y xor (X v not(Z))
 */
.macro FF_ONE_ROUND     a, b, c, d, wAddr, s, tAddr, w, t, temp1, temp2
    mov     \tAddr(T_ORIGIN_ADDR), \t
    mov     \wAddr(INPUT), \w

    /* F(b, c, d) ((b & c) | ((~b) & d)) */
    mov \b, \temp1
    andn    \d, \b, \temp2        // (~b) & d
    and \c, \temp1               // b & c
    or  \temp1, \temp2            // (b & c) | ((~b) & d)

    /* (a) += F((b), (c), (d)) + (\w) + (\t) */
    add \w, \a
    add \t, \a
    add \temp2, \a

    /* (a) = ROTL32((a), (s))  */
    rol $\s, \a

    /* (a) += (b) */
    add \b, \a
.endm

/*
 *  Macro description: The GG function updates a round of hash values in rounds 16-31 compression.
 *  Input register:
 *       wAddr:  sequence corresponding to W (wi)
 *       tAddr:  order (ti) corresponding to t
 *       a - d:  intermediate variable of the hash value
 *  Change register:  r8d-r15d
 *  Output register:
 *           a:  indicates the value after a round of cyclic update.
 *  Function/Macro Call: None
 *  Implementation description:
 *          For t = 0 to 63, T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
 *          T2 = BSIG0(a) + MAJ(a,b,c)
 *          h = g, g = f, f = e, e = d + T1, d = c, c = b, b = a, a = T1 + T2
 *             G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
 *       (a) += G((b), (c), (d)) + (x) + (ac);
 *      (a) = ROTL32((a), (s));
 *      (a) += (b);
 */
.macro GG_ONE_ROUND     a, b, c, d, wAddr, s, tAddr, w, t, temp1, temp2
    mov     \tAddr(T_ORIGIN_ADDR), \t
    mov     \wAddr(INPUT), \w

    /* G(x, y, z) ((b & d) | (c & (~d))) */
    mov \b, \temp1
    and \d, \temp1
    andn    \c, \d, \temp2
    or \temp1, \temp2

    /* (a) += G((b), (c), (d)) + (\w) + (t) */
    add \t, \a
    add \w, \a
    add \temp2, \a

    /* (a) = ROTL32((a), (s)) */
    rol $\s, \a

    /* (a) += (b) */
    add \b, \a
.endm

/*
 *  Macro description: The HH function processes the update of a hash value in a round of 32-47 compression.
 *  Input register:
 *      wAddr: sequence corresponding to W (wi)
 *      tAddr: order (ti) corresponding to t
 *      a - d: intermediate variable of the hash value
 *  Change register:  r8d-r15d
 *  Output register:
 *           a: indicates the value after a round of cyclic update.
 *  Function/Macro Call: None
 *  Implementation description:
 *
 *          H(x, y, z) ((x) ^ (y) ^ (z))
 *          (a) += H((b), (c), (d)) + (x) + (ac);
 *          (a) = ROTL32((a), (s));
 *          (a) += (b);
 *          b and c ->next c and d
 *          swap \temp2 temp4 for next round
 */
.macro HH_ONE_ROUND     a, b, c, d, wAddr, s, tAddr, w, t, temp1, temp2
    mov     \tAddr(T_ORIGIN_ADDR), \t
    mov     \wAddr(INPUT), \w

    /* H(x, y, z) (b ^ c ^ d) */
    mov \b, \temp1
    xor \d, \temp1
    xor \c, \temp1

    /* (a) += H((b), (c), (d)) + (\w) + (\t) */
    add \t, \a
    add \w, \a
    add \temp1, \a

    /* (a) = ROTL32((a), (s)) */
    rol $\s, \a

    /* (a) += (b) */
    add \b, \a
.endm

/*
 *  Macro description: Processes the update of a hash value in a round of 48-63 compression.
 *  Input register:
 *     wAddr: Sequence corresponding to W (wi)
 *     tAddr: Order (ti) corresponding to t
 *     a - d: Intermediate variable of the hash value
 *  Change register: r8d-r15d.
 *  Output register:
 *         a: indicates the value after a round of cyclic update.
 *  Function/Macro Call: None
 *  Implementation description:
 *          For t = 0 to 63, T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
 *          T2 = BSIG0(a) + MAJ(a,b,c)
 *          h = g, g = f, f = e, e = d + T1, d = c, c = b, b = a, a = T1 + T2
 *          I(x, y, z) ((y) ^ ((x) | (~(z))))
 *      (a) += I((b), (c), (d)) + (x) + (ac); \
 *      (a) = ROTL32((a), (s));               \
 *      (a) += (b);
 *          swap \temp2 temp4 for next round
 */
.macro II_ONE_ROUND     a, b, c, d, wAddr, s, tAddr, w, t, temp1, temp2
    mov     \tAddr(T_ORIGIN_ADDR), \t
    mov     \wAddr(INPUT), \w

    /* I(b, c, d) (c ^ (b | (~d))) */
    mov \d, \temp1
    not \temp1
    or  \b, \temp1
    xor \c, \temp1

    /* (a) += I((b), (c), (d)) + (\w) + (\t); */
    add \t, \a
    add \w, \a
    add \temp1, \a

    /* (a) = ROTL32((a), (s)) */
    rol $\s, \a

    /* (a) += (b) */
    add \b, \a
.endm

/*
 *  Function description: Performs 64 rounds of compression calculation
 *                        based on the input plaintext data and updates the hash value.
 *  Function prototype: void MD5_Compress(uint32_t hash[32], const uint8_t *in, uint32_t num);
 *  Input register:
 *      rdi: Indicates the storage address of the hash value.
 *      rsi: Pointer to the input data address (Wi)
 *      rdx: Indicates the number of 64 rounds of cycles.
 *           (You need to do several blocks, that is, you need to do several loops.)
 *  Change register: rsi, r8d-r15d, rcx.
 *  Output register: None
 *  Function/Macro Call: FF_ONE_ROUND, GG_ONE_ROUND, HH_ONE_ROUND, II_ONE_ROUND
 */
.text
.globl MD5_Compress
.type MD5_Compress,%function
.align 4
MD5_Compress:
.cfi_startproc
    /* Push stack and pop stack protection */
    pushq %r14
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r15

    /* r8d-r10d: a-d */
    mov 0(%rdi), A
    mov 4(%rdi), B
    mov 8(%rdi), C
    mov 12(%rdi), D

.Lmd5_loop:
    leaq    g_tMd5(%rip), T_ORIGIN_ADDR

    /* LEND_MD5_FF_ROUND_ROUND_0_15 */
    /* FF_ONE_ROUND      a, b, c, d, wAddr, s, tAddr, w, t, temp1, temp2 */
    FF_ONE_ROUND         A, B, C, D, 0, S11, 0, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         D, A, B, C, 4, S12, 4, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         C, D, A, B, 8, S13, 8, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         B, C, D, A, 12, S14, 12, W, T, TEMP1, TEMP2

    FF_ONE_ROUND         A, B, C, D, 16, S11, 16, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         D, A, B, C, 20, S12, 20, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         C, D, A, B, 24, S13, 24, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         B, C, D, A, 28, S14, 28, W, T, TEMP1, TEMP2

    FF_ONE_ROUND         A, B, C, D, 32, S11, 32, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         D, A, B, C, 36, S12, 36, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         C, D, A, B, 40, S13, 40, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         B, C, D, A, 44, S14, 44, W, T, TEMP1, TEMP2

    FF_ONE_ROUND         A, B, C, D, 48, S11, 48, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         D, A, B, C, 52, S12, 52, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         C, D, A, B, 56, S13, 56, W, T, TEMP1, TEMP2
    FF_ONE_ROUND         B, C, D, A, 60, S14, 60, W, T, TEMP1, TEMP2

    /* LEND_MD5_GG_ROUND_ROUND_16_31 */
    /* GG_ONE_ROUND      a, b, c, d, wAddr, s, tAddr, w, t, temp1, temp2 */
    GG_ONE_ROUND         A, B, C, D, 4, S21, 64, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         D, A, B, C, 24, S22, 68, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         C, D, A, B, 44, S23, 72, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         B, C, D, A, 0, S24, 76, W, T, TEMP1, TEMP2

    GG_ONE_ROUND         A, B, C, D, 20, S21, 80, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         D, A, B, C, 40, S22, 84, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         C, D, A, B, 60, S23, 88, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         B, C, D, A, 16, S24, 92, W, T, TEMP1, TEMP2

    GG_ONE_ROUND         A, B, C, D, 36, S21, 96, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         D, A, B, C, 56, S22, 100, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         C, D, A, B, 12, S23, 104, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         B, C, D, A, 32, S24, 108, W, T, TEMP1, TEMP2

    GG_ONE_ROUND         A, B, C, D, 52, S21, 112, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         D, A, B, C, 8, S22, 116, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         C, D, A, B, 28, S23, 120, W, T, TEMP1, TEMP2
    GG_ONE_ROUND         B, C, D, A, 48, S24, 124, W, T, TEMP1, TEMP2

    /* LEND_MD5_HH_ROUND_ROUND_32_47 */
    /* HH_ONE_ROUND      a,b,c,d,wAddr,s,tAddr, w, t, temp1, temp2 */
    HH_ONE_ROUND         A, B, C, D, 20, S31, 128, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         D, A, B, C, 32, S32, 132, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         C, D, A, B, 44, S33, 136, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         B, C, D, A, 56, S34, 140, W, T, TEMP1, TEMP2

    HH_ONE_ROUND         A, B, C, D, 4, S31, 144, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         D, A, B, C, 16, S32, 148, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         C, D, A, B, 28, S33, 152, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         B, C, D, A, 40, S34, 156, W, T, TEMP1, TEMP2

    HH_ONE_ROUND         A, B, C, D, 52, S31, 160, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         D, A, B, C, 0, S32, 164, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         C, D, A, B, 12, S33, 168, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         B, C, D, A, 24, S34, 172, W, T, TEMP1, TEMP2

    HH_ONE_ROUND         A, B, C, D, 36, S31, 176, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         D, A, B, C, 48, S32, 180, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         C, D, A, B, 60, S33, 184, W, T, TEMP1, TEMP2
    HH_ONE_ROUND         B, C, D, A, 8, S34, 188, W, T, TEMP1, TEMP2

    /* LEND_MD5_II_ROUND_ROUND_48_63 */
    /* II_ONE_ROUND      a, b,c,d,wAddr,s,tAddr, w, t, temp1, temp2 */
    II_ONE_ROUND         A, B, C, D, 0, S41, 192, W, T, TEMP1, TEMP2
    II_ONE_ROUND         D, A, B, C, 28, S42, 196, W, T, TEMP1, TEMP2
    II_ONE_ROUND         C, D, A, B, 56, S43, 200, W, T, TEMP1, TEMP2
    II_ONE_ROUND         B, C, D, A, 20, S44, 204, W, T, TEMP1, TEMP2

    II_ONE_ROUND         A, B, C, D, 48, S41, 208, W, T, TEMP1, TEMP2
    II_ONE_ROUND         D, A, B, C, 12, S42, 212, W, T, TEMP1, TEMP2
    II_ONE_ROUND         C, D, A, B, 40, S43, 216, W, T, TEMP1, TEMP2
    II_ONE_ROUND         B, C, D, A, 4, S44, 220, W, T, TEMP1, TEMP2

    II_ONE_ROUND         A, B, C, D, 32, S41, 224, W, T, TEMP1, TEMP2
    II_ONE_ROUND         D, A, B, C, 60, S42, 228, W, T, TEMP1, TEMP2
    II_ONE_ROUND         C, D, A, B, 24, S43, 232, W, T, TEMP1, TEMP2
    II_ONE_ROUND         B, C, D, A, 52, S44, 236, W, T, TEMP1, TEMP2

    II_ONE_ROUND         A, B, C, D, 16, S41, 240, W, T, TEMP1, TEMP2
    II_ONE_ROUND         D, A, B, C, 44, S42, 244, W, T, TEMP1, TEMP2
    II_ONE_ROUND         C, D, A, B, 8, S43, 248, W, T, TEMP1, TEMP2
    II_ONE_ROUND         B, C, D, A, 36, S44, 252, W, T, TEMP1, TEMP2

    /* Update the storage hash value. */
    add 0(%rdi), A
    add 4(%rdi), B
    add 8(%rdi), C
    add 12(%rdi), D
    mov A, 0(%rdi)
    mov B, 4(%rdi)
    mov C, 8(%rdi)
    mov D, 12(%rdi)
    lea 64(INPUT), INPUT
    sub $1, NUM
    ja .Lmd5_loop

.LEND_MD5_FINFISH_INITIAL:
    /* Registers and pointers are reset. */
    popq %r15
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    popq %r14
    ret
.cfi_endproc
    .size   MD5_Compress, .-MD5_Compress

#endif
