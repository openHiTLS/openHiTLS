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

#include "chacha20_x8664_common.S"
.text
.align    64
g_ror16_128:
    .byte   0x2,0x3,0x0,0x1, 0x6,0x7,0x4,0x5, 0xa,0xb,0x8,0x9, 0xe,0xf,0xc,0xd, \
            0x2,0x3,0x0,0x1, 0x6,0x7,0x4,0x5, 0xa,0xb,0x8,0x9, 0xe,0xf,0xc,0xd
    .size   g_ror16_128, .-g_ror16_128
.align    64
g_ror8_128:
    .byte   0x3,0x0,0x1,0x2, 0x7,0x4,0x5,0x6, 0xb,0x8,0x9,0xa, 0xf,0xc,0xd,0xe, \
            0x3,0x0,0x1,0x2, 0x7,0x4,0x5,0x6, 0xb,0x8,0x9,0xa, 0xf,0xc,0xd,0xe
    .size   g_ror8_128, .-g_ror8_128
.align    64
g_ror16:
    .byte   0x2,0x3,0x0,0x1, 0x6,0x7,0x4,0x5, 0xa,0xb,0x8,0x9, 0xe,0xf,0xc,0xd
    .size   g_ror16, .-g_ror16
.align    64
g_ror8:
    .byte   0x3,0x0,0x1,0x2, 0x7,0x4,0x5,0x6, 0xb,0x8,0x9,0xa, 0xf,0xc,0xd,0xe
    .size   g_ror8, .-g_ror8
.align    64
g_ror16_512:
    .byte   0x2,0x3,0x0,0x1, 0x6,0x7,0x4,0x5, 0xa,0xb,0x8,0x9, 0xe,0xf,0xc,0xd, \
            0x2,0x3,0x0,0x1, 0x6,0x7,0x4,0x5, 0xa,0xb,0x8,0x9, 0xe,0xf,0xc,0xd
    .size   g_ror16_512, .-g_ror16_512
.align    64
g_ror8_512:
    .byte   0x3,0x0,0x1,0x2, 0x7,0x4,0x5,0x6, 0xb,0x8,0x9,0xa, 0xf,0xc,0xd,0xe, \
            0x3,0x0,0x1,0x2, 0x7,0x4,0x5,0x6, 0xb,0x8,0x9,0xa, 0xf,0xc,0xd,0xe
    .size   g_ror8_512, .-g_ror8_512
.align    64
g_add4block:
    .long   0, 1, 2, 3
    .size   g_add4block, .-g_add4block
.align    64
g_addsecond4block:
    .long   4, 4, 4, 4
    .size   g_addsecond4block, .-g_addsecond4block
.align    64
g_add8block:
    .long   0, 1, 2, 3, 4, 5, 6, 7
    .size   g_add8block, .-g_add8block
.align    64
g_addsecond8block:
    .long   8, 8, 8, 8, 8, 8, 8, 8
    .size   g_addsecond8block, .-g_addsecond8block
.align    64
g_addOne:
    .long   0, 0, 0, 0, 1, 0, 0, 0
    .size   g_addOne, .-g_addOne

.set  IN, %rsi
.set OUT, %rdx

/* QUARTERROUND for one state */
.macro CHACHA20_ROUND s0 s1 s2 s3 cur ror16 ror8
    vpaddd  \s1, \s0, \s0
    vpxor   \s0, \s3, \s3
    vpshufb (\ror16), \s3, \s3

    vpaddd  \s3, \s2, \s2
    vpxor   \s2, \s1, \s1
    vmovdqa \s1, \cur
    vpsrld  $20, \s1, \s1
    vpslld  $12, \cur, \cur
    vpor    \cur, \s1, \s1

    vpaddd  \s1, \s0, \s0
    vpxor   \s0, \s3, \s3
    vpshufb (\ror8), \s3, \s3

    vpaddd  \s3, \s2, \s2
    vpxor   \s2, \s1, \s1
    vmovdqa \s1, \cur
    vpsrld  $25, \s1, \s1
    vpslld  $7, \cur, \cur
    vpor    \cur, \s1, \s1
.endm

/* QUARTERROUND for two states */
.macro CHACHA20_2_ROUND s0 s1 s2 s3 cur s4 s5 s6 s7 cur1 ror16 ror8
    vpaddd  \s1, \s0, \s0
    vpxor   \s0, \s3, \s3
    vpshufb (\ror16), \s3, \s3

    vpaddd  \s3, \s2, \s2
    vpxor   \s2, \s1, \s1
    vmovdqa \s1, \cur
    vpsrld  $20, \s1, \s1
    vpslld  $12, \cur, \cur
    vpor    \cur, \s1, \s1

    vpaddd  \s1, \s0, \s0
    vpxor   \s0, \s3, \s3
    vpshufb (\ror8), \s3, \s3

    vpaddd  \s3, \s2, \s2
    vpxor   \s2, \s1, \s1
    vmovdqa \s1, \cur
    vpsrld  $25, \s1, \s1
    vpslld  $7, \cur, \cur
    vpor    \cur, \s1, \s1

    vpaddd  \s5, \s4, \s4
    vpxor   \s4, \s7, \s7
    vpshufb (\ror16), \s7, \s7

    vpaddd  \s7, \s6, \s6
    vpxor   \s6, \s5, \s5
    vmovdqa \s5, \cur1
    vpsrld  $20, \s5, \s5
    vpslld  $12, \cur1, \cur1
    vpor    \cur1, \s5, \s5

    vpaddd  \s5, \s4, \s4
    vpxor   \s4, \s7, \s7
    vpshufb (\ror8), \s7, \s7

    vpaddd  \s7, \s6, \s6
    vpxor   \s6, \s5, \s5
    vmovdqa \s5, \cur1
    vpsrld  $25, \s5, \s5
    vpslld  $7, \cur1, \cur1
    vpor    \cur1, \s5, \s5
.endm

/* current matrix add original matrix */
.macro LASTADD_MATRIX S0 S1 S2 S3 S4 S5 S6 S7 S8 S9 S10 S11 S12 S13 S14 S15 PER
    vpaddd (%rsp), \S0, \S0
    vpaddd 1*\PER(%rsp), \S1, \S1
    vpaddd 2*\PER(%rsp), \S2, \S2
    vpaddd 3*\PER(%rsp), \S3, \S3
    vpaddd 4*\PER(%rsp), \S4, \S4
    vpaddd 5*\PER(%rsp), \S5, \S5
    vpaddd 6*\PER(%rsp), \S6, \S6
    vpaddd 7*\PER(%rsp), \S7, \S7
    vpaddd 8*\PER(%rsp), \S8, \S8
    vpaddd 9*\PER(%rsp), \S9, \S9
    vpaddd 10*\PER(%rsp), \S10, \S10
    vpaddd 11*\PER(%rsp), \S11, \S11
    vpaddd 12*\PER(%rsp), \S12, \S12
    vpaddd 13*\PER(%rsp), \S13, \S13
    vpaddd 14*\PER(%rsp), \S14, \S14
    vpaddd 15*\PER(%rsp), \S15, \S15
.endm

/* write output for left part of 512 bytes (ymm) */
.macro WRITE_BACK_512_L inpos outpos s0 s1 s2 s3 s4 s5 s6 s7 out0 out1 out2 out3

    /* {A0 B0 C0 D0 E0 F0 G0 H0} {A1 B1 C1 D1 E1 F1 G1 H1} => {A0 B0 C0 D0 A1 B1 C1 D1} */
    vperm2i128        $0x20, \s1, \s0, \out0
    vpxor           (\inpos), \out0, \out0
    vmovdqu         \out0, (\outpos)                      // write back output

    vperm2i128        $0x20, \s3, \s2, \out1
    vpxor           32(\inpos), \out1, \out1
    vmovdqu         \out1, 32(\outpos)

    vperm2i128        $0x20, \s5, \s4, \out2
    vpxor           64(\inpos), \out2, \out2                // write back output
    vmovdqu         \out2, 64(\outpos)

    vperm2i128        $0x20, \s7, \s6, \out3
    vpxor           96(\inpos), \out3, \out3
    vmovdqu         \out3, 96(\outpos)
.endm

/* write output for right part of 512 bytes (ymm) */
.macro WRITE_BACK_512_R inpos outpos s0 s1 s2 s3 s4 s5 s6 s7

    /* {A0 B0 C0 D0 E0 F0 G0 H0} {A1 B1 C1 D1 E1 F1 G1 H1} => {E0 F0 G0 H0 E1 F1 G1 H1} */
    vperm2i128        $0x31, \s1, \s0, \s1
    vpxor           (\inpos), \s1, \s1
    vmovdqu         \s1, (\outpos)                 // write back output

    vperm2i128        $0x31, \s3, \s2, \s3
    vpxor           32(\inpos), \s3, \s3
    vmovdqu         \s3, 32(\outpos)

    vperm2i128        $0x31, \s5, \s4, \s5
    vpxor           64(\inpos), \s5, \s5
    vmovdqu         \s5, 64(\outpos)              // write back output

    vperm2i128        $0x31, \s7, \s6, \s7
    vpxor           96(\inpos), \s7, \s7
    vmovdqu         \s7, 96(\outpos)
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

/*
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
 */

.globl CHACHA20_Update
.type CHACHA20_Update,%function
.align 64
CHACHA20_Update:
    .cfi_startproc
    mov     48(%rdi), %r11d
    mov     %rsp, %rax
    subq    $1024,%rsp
    andq    $-512,%rsp

.Lchacha20_start:
    cmp  $512, %rcx
    jae  .Lchacha20_512_start
    cmp  $256, %rcx
    jae  .Lchacha20_256_start
    cmp  $128, %rcx
    jae  .Lchacha20_128_start
    cmp  $64, %rcx
    jae  .Lchacha20_64_start
    jmp  .Lchacha20_end

.Lchacha20_64_start:

    LOAD_STATE %xmm0, %xmm1, %xmm2, %xmm3, %rdi

    vmovdqa %xmm0, %xmm10
    vmovdqa %xmm1, %xmm11
    vmovdqa %xmm2, %xmm12
    vmovdqa %xmm3, %xmm13

    leaq    g_ror16(%rip), %r9
    leaq    g_ror8(%rip), %r10
    mov     $10, %r8

.Lchacha20_64_loop:

    /* 0 = 0 + 4, 12 = (12 ^ 0) >>> 16 | 8 = 8 + 12, 4 = (4 ^ 8) >>> 12 |
     * 0 = 0 + 4, 12 = (12 ^ 0) >>> 8 |  8 = 8 + 12, 4 = (4 ^ 8) >>> 7
     * 1 = 1 + 5, 13 = (13 ^ 1) >>> 16 | 9 = 9 + 13, 5 = (5 ^ 9) >>> 12 |
     * 1 = 1 + 5, 13 = (13 ^ 1) >>> 8 |  9 = 9 + 13, 5 = (5 ^ 9) >>> 7
     * 2 = 2 + 6, 14 = (14 ^ 2) >>> 16 | 10 = 10 + 14, 6 = (6 ^ 10)>>> 12 |
     * 2 = 2 + 6, 14 = (14 ^ 2) >>> 8 |  10 = 10 + 14, 6 = (6 ^ 10)>>> 7
     * 3 = 3 + 7, 15 = (15 ^ 3) >>> 16 | 11 = 11 + 15, 7 = (7 ^ 11)>>> 12 |
     * 3 = 3 + 7 ,15 = (15 ^ 3) >>> 8 |  11 = 11 + 15, 7 = (7 ^ 11)>>> 7
     */
    CHACHA20_ROUND %xmm0, %xmm1, %xmm2, %xmm3, %xmm4, %r9, %r10

    vpshufd  $78, %xmm2, %xmm2       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    vpshufd  $57, %xmm1, %xmm1       // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    vpshufd  $147, %xmm3, %xmm3      // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    /* 0 = 0 + 5 , 15 = (15 ^ 0) >>> 16 | 10 = 10 + 15, 5 = (5 ^ 10) >>> 12 |
     * 0 = 0 + 5, 15 = (15 ^ 0) >>> 8 |  10 = 10 + 15, 5 = (5 ^ 10) >>> 7
     * 1 = 1 + 6 , 12 = (12 ^ 1) >>> 16 | 11 = 11 + 12, 6 = (6 ^ 11) >>> 12 |
     * 1 = 1 + 6, 12 = (12 ^ 1) >>> 8 |  11 = 11 + 12,  6 = (6 ^ 11) >>> 7
     * 2 = 2 + 7 , 13 = (13 ^ 2) >>> 16 | 8 = 8 + 13, 7 = (7 ^ 8)>>> 12 |
     * 2 = 2 + 7, 13 = (13 ^ 2) >>> 8 |  8 =  8 + 13, 7 = (7 ^ 8)>>> 7
     * 3 = 3 + 4 , 14 = (14 ^ 3) >>> 16 | 9 = 9 + 14, 4 = (4 ^ 9)>>> 12 |
     * 3 = 3 + 4, 14 = (14 ^ 3) >>> 8 |  9 =  9 + 14, 4 = (4 ^ 9)>>> 7
     */
    CHACHA20_ROUND %xmm0, %xmm1, %xmm2, %xmm3, %xmm4, %r9, %r10

    vpshufd  $78, %xmm2, %xmm2       // {10 11 8  9} ==> {8  9  10 11}  01 00 11 10
    vpshufd  $147, %xmm1, %xmm1      // {5  6  7  4} ==> {4  5  6   7}  00 11 10 01
    vpshufd  $57, %xmm3, %xmm3       // {15 12 13 14} ==> {12 13 14 15} 10 01 00 11

    decq  %r8
    jnz   .Lchacha20_64_loop

    vpaddd  %xmm10, %xmm0, %xmm0
    vpaddd  %xmm11, %xmm1, %xmm1
    vpaddd  %xmm12, %xmm2, %xmm2
    vpaddd  %xmm13, %xmm3, %xmm3

    add     $1, %r11d
    vpxor   0(IN),  %xmm0, %xmm4
    vpxor   16(IN), %xmm1, %xmm5
    vpxor   32(IN), %xmm2, %xmm6
    vpxor   48(IN), %xmm3, %xmm7

    vmovdqu %xmm4, 0(OUT)
    vmovdqu %xmm5, 16(OUT)
    vmovdqu %xmm6, 32(OUT)
    vmovdqu %xmm7, 48(OUT)

    add $64, IN
    add $64, OUT

    mov %r11d, 48(%rdi)
    jmp .Lchacha20_end

.Lchacha20_128_start:

    vbroadcasti128 (%rdi),   %ymm0    // {0  1  2   3  0  1  2   3}
    vbroadcasti128 16(%rdi), %ymm1    // {4  5  6   7  4  5  6   7}
    vbroadcasti128 32(%rdi), %ymm2    // {8  9  10 11  8  9  10 11}
    vbroadcasti128 48(%rdi), %ymm3    // {12 13 14 15  12 13 14 15}

    vpaddd g_addOne(%rip), %ymm3, %ymm3

    vmovdqa %ymm0, %ymm12
    vmovdqa %ymm1, %ymm13
    vmovdqa %ymm2, %ymm14
    vmovdqa %ymm3, %ymm15

    leaq    g_ror16_128(%rip), %r9
    leaq    g_ror8_128(%rip), %r10
    mov     $10, %r8

.Lchacha20_128_loop:

    CHACHA20_ROUND %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %r9, %r10

    vpshufd  $78, %ymm2, %ymm2       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    vpshufd  $57, %ymm1, %ymm1       // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    vpshufd  $147, %ymm3, %ymm3      // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    CHACHA20_ROUND %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %r9, %r10

    vpshufd  $78, %ymm2, %ymm2       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    vpshufd  $147, %ymm1, %ymm1      // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    vpshufd  $57, %ymm3, %ymm3       // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    decq %r8
    jnz  .Lchacha20_128_loop

    vpaddd  %ymm12, %ymm0, %ymm0
    vpaddd  %ymm13, %ymm1, %ymm1
    vpaddd  %ymm14, %ymm2, %ymm2
    vpaddd  %ymm15, %ymm3, %ymm3

    vextracti128 $1, %ymm0, %xmm4     // ymm0 => {xmm0 xmm5}
    vextracti128 $1, %ymm1, %xmm5     // ymm1 => {xmm1 xmm6}
    vextracti128 $1, %ymm2, %xmm6     // ymm2 => {xmm2 xmm7}
    vextracti128 $1, %ymm3, %xmm7     // ymm3 => {xmm3 xmm8}

    WRITEBACK_64_AVX2   IN, OUT, %xmm0, %xmm1, %xmm2, %xmm3
    add   $2, %r11d
    WRITEBACK_64_AVX2   IN, OUT, %xmm4, %xmm5, %xmm6, %xmm7
    mov  %r11d, 48(%rdi)

    sub $128, %rcx
    jz  .Lchacha20_end
    jmp .Lchacha20_start

.Lchacha20_256_start:

    LOAD_STATE %xmm0, %xmm1, %xmm2, %xmm3, %rdi
    STATE_TO_MATRIX %xmm0, %xmm1, %xmm2, %xmm3, %xmm4, %xmm5, %xmm6, %xmm7, %xmm8, %xmm9, %xmm10, \
                    %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, 0, 16, g_add4block(%rip)

    /* move xmm8~11 into stack for CHACHA20_LOOP encryption */
    vmovdqa  %xmm8, 256(%rsp)
    vmovdqa  %xmm9, 256+16(%rsp)
    vmovdqa %xmm10, 256+32(%rsp)
    vmovdqa %xmm11, 256+48(%rsp)

    leaq    g_ror16(%rip), %r9
    leaq    g_ror8(%rip), %r10

    mov     $10, %r8

.Lchacha20_256_loop:

    CHACHA20_LOOP   %xmm0, %xmm1, %xmm2, %xmm3, %xmm4, %xmm5, %xmm6, %xmm7, %xmm8, %xmm9, %xmm10 \
                    %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, 256, 16, %rsp, %r9, %r10

    decq %r8
    jnz  .Lchacha20_256_loop

    /* xmm0~15: encrypt matrix 0 ~ 15*/
    vmovdqa 256+32(%rsp), %xmm10                                            // rsp32: encrypt matrix xmm10
    vmovdqa 256+48(%rsp), %xmm11

    LASTADD_MATRIX  %xmm0, %xmm1, %xmm2, %xmm3, %xmm4, %xmm5, %xmm6, %xmm7, %xmm8, %xmm9, %xmm10 \
                    %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, 16

    /* store xmm9, 10, 13, 14 in stack */
    vmovdqa %xmm9,  256(%rsp)                                               // rsp 0: encrypt matrix xmm9
    vmovdqa %xmm10, 256+32(%rsp)                                            // rsp32: encrypt matrix xmm9
    vmovdqa %xmm13, 256+16(%rsp)                                            // rsp16: encrypt matrix xmm13
    vmovdqa %xmm14, 256+48(%rsp)                                            // rsp48: encrypt matrix xmm14

    MATRIX_TO_STATE %xmm0, %xmm1, %xmm2, %xmm3, %xmm9, %xmm10               // set state 0, 3, 9, 10
    MATRIX_TO_STATE %xmm4, %xmm5, %xmm6, %xmm7, %xmm13, %xmm14              // set state 4, 7, 13, 14

    vmovdqa    256(%rsp), %xmm5
    vmovdqa 256+32(%rsp), %xmm6
    vmovdqa        %xmm9, 256(%rsp)
    vmovdqa       %xmm10, 256+32(%rsp)

    MATRIX_TO_STATE %xmm8, %xmm5, %xmm6, %xmm11, %xmm1, %xmm2               // set state 8, 11, 1, 2

    vmovdqa 256+16(%rsp), %xmm9
    vmovdqa 256+48(%rsp), %xmm10
    vmovdqa       %xmm13, 256+16(%rsp)
    vmovdqa       %xmm14, 256+48(%rsp)

    MATRIX_TO_STATE %xmm12, %xmm9, %xmm10, %xmm15, %xmm5, %xmm6             // set state 12, 15, 5, 6

    vmovdqa    256(%rsp), %xmm9                                             // rsp 0: state 9
    vmovdqa 256+32(%rsp), %xmm10                                            // rsp32: state 10
    vmovdqa 256+16(%rsp), %xmm13                                            // rsp16: state 13
    vmovdqa 256+48(%rsp), %xmm14                                            // rsp48: state 14

    /* finish state calculation, now write result to output */
    WRITEBACK_64_AVX2 IN, OUT, %xmm0, %xmm4, %xmm8, %xmm12
    WRITEBACK_64_AVX2 IN, OUT, %xmm3, %xmm7, %xmm11, %xmm15
    WRITEBACK_64_AVX2 IN, OUT, %xmm9, %xmm13, %xmm1, %xmm5
    WRITEBACK_64_AVX2 IN, OUT, %xmm10, %xmm14, %xmm2, %xmm6

    add $4, %r11d
    sub $256, %rcx
    mov %r11d, 48(%rdi)
    cmp $256, %rcx
    jz  .Lchacha20_end
    jmp .Lchacha20_start

.Lchacha20_512_start:

    LOAD_512_STATE %ymm0 %ymm1 %ymm2 %ymm3 %rdi
    STATE_TO_MATRIX %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7, %ymm8, %ymm9, \
                    %ymm10, %ymm11, %ymm12, %ymm13, %ymm14, %ymm15, 0, 32, g_add8block(%rip)
    jmp  .Lchacha20_512_run

.Lchacha20_512_start_cont:

    LOAD_MATRIX %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7, %ymm8, %ymm9, \
                %ymm10, %ymm11, %ymm12, %ymm13, %ymm14, %ymm15, 0, 32, g_addsecond8block(%rip)

.Lchacha20_512_run:

    /* move ymm8~11 into stack for CHACHA20_LOOP encryption */
    vmovdqa     %ymm8, 512(%rsp)
    vmovdqa     %ymm9, 512+32(%rsp)
    vmovdqa     %ymm10, 512+64(%rsp)
    vmovdqa     %ymm11, 512+96(%rsp)
    leaq        g_ror16_512(%rip), %r9
    leaq        g_ror8_512(%rip), %r10
    mov         $10, %r8
.align 32
.Lchacha20_512_loop:

    CHACHA20_LOOP   %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7, %ymm8, %ymm9, %ymm10 \
                    %ymm11, %ymm12, %ymm13, %ymm14, %ymm15, 512, 32, %rsp, %r9, %r10

    decq %r8
    jnz  .Lchacha20_512_loop

    /* ymm0~15: encrypt matrix 0 ~ 15*/
    vmovdqa 512+64(%rsp), %ymm10                                            // rsp64: encrypt matrix ymm10
    vmovdqu 512+96(%rsp), %ymm11

    LASTADD_MATRIX  %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7, %ymm8, %ymm9, %ymm10 \
                    %ymm11, %ymm12, %ymm13, %ymm14, %ymm15, 32

    /* store matrix ymm9, 10, 13, 14 in stack */
    vmovdqa %ymm9, 512(%rsp)                                                // rsp 0: encrypt matrix ymm9
    vmovdqu %ymm10, 512+32(%rsp)                                            // rsp32: encrypt matrix ymm10
    vmovdqa %ymm13, 512+64(%rsp)                                            // rsp64: encrypt matrix ymm13
    vmovdqu %ymm14, 512+96(%rsp)                                            // rsp96: encrypt matrix ymm14

    MATRIX_TO_STATE %ymm0, %ymm1, %ymm2, %ymm3, %ymm9, %ymm10               // set state 0, 3, 9, 10
    MATRIX_TO_STATE %ymm4, %ymm5, %ymm6, %ymm7, %ymm13, %ymm14              // set state 4, 7, 13, 14

    vmovdqu 512(%rsp), %ymm5
    vmovdqa 512+32(%rsp), %ymm6
    vmovdqu %ymm9, 512(%rsp)
    vmovdqa %ymm10, 512+32(%rsp)

    MATRIX_TO_STATE %ymm8, %ymm5, %ymm6, %ymm11, %ymm1, %ymm2               // set state 8, 11, 1, 2

    vmovdqa 512+64(%rsp), %ymm9
    vmovdqu 512+96(%rsp), %ymm10
    vmovdqa %ymm13, 512+64(%rsp)
    vmovdqu %ymm14, 512+96(%rsp)

    MATRIX_TO_STATE %ymm12, %ymm9, %ymm10, %ymm15, %ymm5, %ymm6             // set state 12, 15, 5, 6

    /*
     * {A0 A1 A2 A3 E0 E1 E2 E3}
     * {B0 B1 B2 B3 F0 F1 F2 F3}
     * {C0 C1 C2 C3 G0 G1 G2 G3}
     * {D0 D1 D2 D3 H0 H1 H2 H3}
     * ...
     * =>
     * {A0 A1 A2 A3 B0 B1 B2 B3}
     * {C0 C1 C2 C3 D0 D1 D2 D3}
     * ....
     */

    /* left half of ymm registers */
    WRITE_BACK_512_L IN, OUT, %ymm0, %ymm4, %ymm8, %ymm12, %ymm3, %ymm7, %ymm11, %ymm15, %ymm9, %ymm10, %ymm13, %ymm14
    add $256, IN
    add $256, OUT

    /* right half of ymm registers */
    WRITE_BACK_512_R IN, OUT, %ymm0, %ymm4, %ymm8, %ymm12, %ymm3, %ymm7, %ymm11, %ymm15
    sub $128, IN
    sub $128, OUT

    vmovdqa 512(%rsp), %ymm9
    vmovdqu 512+32(%rsp), %ymm10
    vmovdqa 512+64(%rsp), %ymm13
    vmovdqu 512+96(%rsp), %ymm14

    /* second left half of ymm registers */
    WRITE_BACK_512_L IN, OUT, %ymm9, %ymm13, %ymm1, %ymm5, %ymm10, %ymm14, %ymm2, %ymm6, %ymm0, %ymm4, %ymm8, %ymm12
    add $256, IN
    add $256, OUT

    /* second right half of ymm registers */
    WRITE_BACK_512_R IN, OUT, %ymm9, %ymm13, %ymm1, %ymm5, %ymm10, %ymm14, %ymm2, %ymm6
    add $128, IN
    add $128, OUT

    add $8, %r11d
    sub $512, %rcx
    mov %r11d, 48(%rdi)
    jz  .Lchacha20_end
    cmp $512, %rcx
    jae .Lchacha20_512_start_cont
    jmp .Lchacha20_start

.Lchacha20_end:
    /* clear sensitive info in stack */
    vpxor   %ymm0, %ymm0, %ymm0
    xor     %r11d, %r11d
    vmovdqa %ymm0, (%rsp)
    vmovdqa %ymm0, 32(%rsp)
    vmovdqa %ymm0, 64(%rsp)
    vmovdqa %ymm0, 96(%rsp)
    vmovdqa %ymm0, 128(%rsp)
    vmovdqa %ymm0, 160(%rsp)
    vmovdqa %ymm0, 192(%rsp)
    vmovdqa %ymm0, 224(%rsp)
    vmovdqa %ymm0, 256(%rsp)
    vmovdqa %ymm0, 288(%rsp)
    vmovdqa %ymm0, 320(%rsp)
    vmovdqa %ymm0, 352(%rsp)
    vmovdqa %ymm0, 384(%rsp)
    vmovdqa %ymm0, 416(%rsp)
    vmovdqa %ymm0, 448(%rsp)
    vmovdqa %ymm0, 480(%rsp)
    vmovdqa %ymm0, 512(%rsp)
    vmovdqa %ymm0, 512+32(%rsp)
    vmovdqa %ymm0, 512+64(%rsp)
    vmovdqa %ymm0, 512+96(%rsp)
    mov %rax, %rsp
    .cfi_endproc
    ret
.size CHACHA20_Update,.-CHACHA20_Update

#endif
