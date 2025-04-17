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
#ifdef HITLS_CRYPTO_CHACHA20

.text
.LAndBlock:
.long 1, 0, 0, 0
.LRor16:
.byte 0x2,0x3,0x0,0x1, 0x6,0x7,0x4,0x5, 0xa,0xb,0x8,0x9, 0xe,0xf,0xc,0xd
.LRor8:
.byte 0x3,0x0,0x1,0x2, 0x7,0x4,0x5,0x6, 0xb,0x8,0x9,0xa, 0xf,0xc,0xd,0xe

.set IN, %r9
.set OUT, %r10

/* Original State */
.set O00, %xmm12
.set O01, %xmm13
.set O02, %xmm14
.set O03, %xmm15

/* State 0 */
.set S00, %xmm0    // LINE 0 STATE 0
.set S01, %xmm1    // LINE 1 STATE 0
.set S02, %xmm2    // LINE 2 STATE 0
.set S03, %xmm3    // LINE 3 STATE 0

/* State 1 */
.set S10, %xmm5    // LINE 0 STATE 1
.set S11, %xmm6    // LINE 1 STATE 1
.set S12, %xmm7    // LINE 2 STATE 1
.set S13, %xmm8    // LINE 3 STATE 1


.macro CHACHA20_ROUND  S0 S1 S2 S3 CUR
    paddd  \S1, \S0
    pxor   \S0, \S3
    pshufb .LRor16(%rip), \S3

    paddd  \S3, \S2
    pxor   \S2, \S1
    movdqa \S1, \CUR
    psrld  $20, \S1
    pslld  $12, \CUR
    por	\CUR, \S1

    paddd  \S1, \S0
    pxor   \S0, \S3
    pshufb .LRor8(%rip), \S3

    paddd  \S3, \S2
    pxor   \S2, \S1
    movdqa \S1, \CUR
    psrld  $25, \S1
    pslld  $7, \CUR
    por	\CUR, \S1
.endm

/* QUARTERROUND for two states */
.macro CHACHA20_2_ROUND  S0 S1 S2 S3 CUR S4 S5 S6 S7 CUR1
    paddd  \S1, \S0
    pxor   \S0, \S3
    pshufb .LRor16(%rip), \S3

    paddd  \S3, \S2
    pxor   \S2, \S1
    movdqa \S1, \CUR
    psrld  $20, \S1
    pslld  $12, \CUR
    por	\CUR, \S1

    paddd  \S1, \S0
    pxor   \S0, \S3
    pshufb .LRor8(%rip), \S3

    paddd  \S3, \S2
    pxor   \S2, \S1
    movdqa \S1, \CUR
    psrld  $25, \S1
    pslld  $7, \CUR
    por	\CUR, \S1

    paddd  \S5, \S4
    pxor   \S4, \S7
    pshufb .LRor16(%rip), \S7

    paddd  \S7, \S6
    pxor   \S6, \S5
    movdqa \S5, \CUR1
    psrld  $20, \S5
    pslld  $12, \CUR1
    por	\CUR1, \S5

    paddd  \S5, \S4
    pxor   \S4, \S7
    pshufb .LRor8(%rip), \S7

    paddd  \S7, \S6
    pxor   \S6, \S5
    movdqa \S5, \CUR1
    psrld  $25, \S5
    pslld  $7, \CUR1
    por	\CUR1, \S5
.endm

/* final add & xor for 64 bytes */
 .macro WRITE_BACK_64 IN_POS OUT_POS
    paddd  O00, S00
    paddd  O01, S01
    paddd  O02, S02
    paddd  O03, S03

    movdqu  (\IN_POS),   %xmm4         // get input
    movdqu  16(\IN_POS), %xmm9
    movdqu  32(\IN_POS), %xmm10
    movdqu  48(\IN_POS), %xmm11

    pxor   %xmm4, S00
    pxor   %xmm9, S01
    pxor   %xmm10, S02
    pxor   %xmm11, S03

    movdqu  S00, (\OUT_POS)          // write back output
    movdqu  S01, 16(\OUT_POS)
    movdqu  S02, 32(\OUT_POS)
    movdqu  S03, 48(\OUT_POS)
.endm

/* final add & xor for 128 bytes */
.macro WRITE_BACK_128 IN_POS OUT_POS
    paddd  O00, S00               // state 0 + origin state 0
    paddd  O01, S01
    paddd  O02, S02
    paddd  O03, S03

    pinsrd  $0, %r11d, O03        // change Original state 0 to Original state 1

    paddd  O00, S10               // state 1 + origin state 1
    paddd  O01, S11
    paddd  O02, S12
    paddd  O03, S13

    movdqu  (\IN_POS),   %xmm4         // get input 0
    movdqu  16(\IN_POS), %xmm9
    movdqu  32(\IN_POS), %xmm10
    movdqu  48(\IN_POS), %xmm11

    pxor   %xmm4, S00              // input 0 ^ state 0
    pxor   %xmm9, S01
    pxor   %xmm10, S02
    pxor   %xmm11, S03

    movdqu  S00, (\OUT_POS)          // write back to output 0
    movdqu  S01, 16(\OUT_POS)
    movdqu  S02, 32(\OUT_POS)
    movdqu  S03, 48(\OUT_POS)

    movdqu  64(\IN_POS), %xmm4         // get input 1
    movdqu  80(\IN_POS), %xmm9
    movdqu  96(\IN_POS), %xmm10
    movdqu  112(\IN_POS), %xmm11

    pxor   %xmm4, S10              // input 1 ^ state 1
    pxor   %xmm9, S11
    pxor   %xmm10, S12
    pxor   %xmm11, S13

    movdqu  S10, 64(\OUT_POS)         // write back to output 1
    movdqu  S11, 80(\OUT_POS)
    movdqu  S12, 96(\OUT_POS)
    movdqu  S13, 112(\OUT_POS)
.endm

.macro GENERATE_1_STATE
    add   $1, %r11d
    pinsrd  $0, %r11d, O03

    movdqu  O00, S00         // set state 0
    movdqu  O01, S01
    movdqu  O02, S02
    movdqu  O03, S03
.endm

.macro GENERATE_2_STATE
    add   $1, %r11d
    pinsrd  $0, %r11d, O03

    movdqu  O00, S00         // set state 0
    movdqu  O01, S01
    movdqu  O02, S02
    movdqu  O03, S03
    movdqu  O00, S10         // set state 1
    movdqu  O01, S11
    movdqu  O02, S12
    movdqu  O03, S13

    add   $1, %r11d
    pinsrd  $0, %r11d, S13
.endm

/*
 * Processing 64 bytes: 4 xmm registers
 * xmm0 ~ xmm3:
 * xmm0 {0,  1,  2,  3}
 * xmm1 {4,  5,  6,  7}
 * xmm2 {8,  9,  10, 11}
 * xmm3 {12, 13, 14, 15}
 *
 * Processing 128 bytes: 8 xmm registers
 * xmm0 ~ xmm8:
 * xmm0 {0,  1,  2,  3}           xmm5 {0,  1,  2,  3}
 * xmm1 {4,  5,  6,  7}           xmm6 {4,  5,  6,  7}
 * xmm2 {8,  9,  10, 11}          xmm7 {8,  9,  10, 11}
 * xmm3 {12, 13, 14, 15}          xmm8 {12, 13, 14, 15}
 *
 * Processing 256 bytes: 16 xmm registers
 * xmm0 ~ xmm15:
 * xmm0 {0,  0,  0,  0}
 * xmm1 {1,  2,  2,  2}
 * xmm2 {3,  3,  3,  3}
 * xmm3 {4,  4,  4,  4}
 * ...
 * xmm15 {15, 15, 15, 15}
 *
 * Processing 512 bytes: 16 xmm registers
 * ymm0 ~ ymm15:
 * ymm0 {0,  0,  0,  0}
 * ymm1 {1,  2,  2,  2}
 * ymm2 {3,  3,  3,  3}
 * ymm3 {4,  4,  4,  4}
 * ...
 * ymm15 {15, 15, 15, 15}
 *
 */

 /**
 * @Interconnection with the C interface：void CHACHA20_Update(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
 * @brief chacha20 algorithm
 * @param ctx [IN] Algorithm context, which is set by the C interface and transferred.
 * @param in [IN] Data to be encrypted
 * @param out [OUT] Data after encryption
 * @param len [IN] Encrypted length
 * esp cannot use 15 available ctx in out len
 * 16 registers are needed in one cycle, then
 * {0,  1,  4,  5,  8,   9,  12, 13}
 * {2,  3,  6,  7,  10,  11, 14, 15}
**/

.globl CHACHA20_Update
.type CHACHA20_Update,%function
.align 64
CHACHA20_Update:
    .cfi_startproc
    push %r12
    mov %rcx, %r12
    mov	48(%rdi), %r11d
    mov %rsi, IN
    mov %rdx, OUT

    movdqu  (%rdi),   O00         // state[0-3]
    movdqu  16(%rdi), O01         // state[4-7]
    movdqu  32(%rdi), O02         // state[8-11]
    movdqu  48(%rdi), O03         // state[12-15]

    sub   $1, %r11d

.LChaCha20_start:
    cmp $128, %r12
    jae  .LChaCha20_128_start
    cmp $64, %r12
    jae  .LChaCha20_64_start
    jmp   .LChaCha20_end

.LChaCha20_64_start:
    GENERATE_1_STATE
    mov $10, %r8

.LChaCha20_64_loop:

    sub   $1, %r8

    /* 0 = 0 + 4, 12 = (12 ^ 0) >>> 16 | 8 =  8 + 12, 4 = (4 ^ 8) >>> 12 | 0 = 0 + 4, 12 = (12 ^ 0) >>> 8 |  8 = 8 + 12,  4 = (4 ^ 8) >>> 7 */
    /* 1 = 1 + 5, 13 = (13 ^ 1) >>> 16 | 9 =  9 + 13, 5 = (5 ^ 9) >>> 12 | 1 = 1 + 5, 13 = (13 ^ 1) >>> 8 |  9 = 9 + 13,  5 = (5 ^ 9) >>> 7 */
    /* 2 = 2 + 6, 14 = (14 ^ 2) >>> 16 | 10 = 10 + 14, 6 = (6 ^ 10)>>> 12 | 2 = 2 + 6, 14 = (14 ^ 2) >>> 8 |  10 =10+ 14,  6 = (6 ^ 10)>>> 7 */
    /* 3 = 3 + 7, 15 = (15 ^ 3) >>> 16 | 11 = 11 + 15, 7 = (7 ^ 11)>>> 12 | 3 = 3 + 7 ,15 = (15 ^ 3) >>> 8 |  11 =11+ 15,  7 = (7 ^ 11)>>> 7 */
    CHACHA20_ROUND S00 S01 S02 S03 %xmm4

    pshufd  $78, S02, S02       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    pshufd  $57, S01, S01       // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    pshufd  $147, S03, S03      // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    /* 0 = 0 + 5 , 15 = (15 ^ 0) >>> 16 | 10 = 10 + 15,   5 = (5 ^ 10) >>> 12 | 0 = 0 + 5, 15 = (15 ^ 0) >>> 8 |  10 = 10 + 15,  5 = (5 ^ 10) >>> 7 */
    /* 1 = 1 + 6 , 12 = (12 ^ 1) >>> 16 | 11 = 11 + 12,   6 = (6 ^ 11) >>> 12 | 1 = 1 + 6, 12 = (12 ^ 1) >>> 8 |  11 = 11 + 12,  6 = (6 ^ 11) >>> 7 */
    /* 2 = 2 + 7 , 13 = (13 ^ 2) >>> 16 | 8 = 8 + 13,     7 = (7 ^ 8)>>> 12   | 2 = 2 + 7, 13 = (13 ^ 2) >>> 8 |  8 =  8  + 13,  7 = (7 ^ 8)>>> 7 */
    /* 3 = 3 + 4 , 14 = (14 ^ 3) >>> 16 | 9 = 9 + 14,     4 = (4 ^ 9)>>> 12   | 3 = 3 + 4, 14 = (14 ^ 3) >>> 8 |  9 =  9  + 14,  4 = (4 ^ 9)>>> 7 */
    CHACHA20_ROUND S00 S01 S02 S03 %xmm4
    pshufd  $78, S02, S02       // {10 11 8  9} ==> {8  9  10 11}  01 00 11 10
    pshufd  $147, S01, S01      // {5  6  7  4} ==> {4  5  6   7}  00 11 10 01
    pshufd  $57, S03, S03       // {15 12 13 14} ==> {12 13 14 15} 10 01 00 11

    jnz	.LChaCha20_64_loop

    WRITE_BACK_64 IN OUT

    add $64, IN
    add $64, OUT

    sub  $64, %r12
    jmp .LChaCha20_start

.LChaCha20_128_start:
    GENERATE_2_STATE
    mov $10, %r8

.LChaCha20_128_loop:

    CHACHA20_2_ROUND  S00 S01 S02 S03 %xmm4 S10 S11 S12 S13 %xmm9

    pshufd  $78, S02, S02       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    pshufd  $57, S01, S01       // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    pshufd  $147, S03, S03      // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    pshufd  $78, S12, S12       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    pshufd  $57, S11, S11       // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    pshufd  $147, S13, S13      // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    CHACHA20_2_ROUND  S00 S01 S02 S03 %xmm4 S10 S11 S12 S13 %xmm9

    pshufd  $78, S02, S02       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    pshufd  $147, S01, S01      // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    pshufd  $57, S03, S03       // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    pshufd  $78, S12, S12       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    pshufd  $147, S11, S11      // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    pshufd  $57, S13, S13       // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    sub  $1, %r8
    jnz	.LChaCha20_128_loop

    WRITE_BACK_128 IN OUT
    add $128, IN
    add $128, OUT

    sub   $128, %r12
    jmp  .LChaCha20_start

.LChaCha20_end:
    add   $1, %r11d
    mov  %r11d, 48(%rdi)
    pop %r12
    ret
	.cfi_endproc

.size CHACHA20_Update,.-CHACHA20_Update

#endif
