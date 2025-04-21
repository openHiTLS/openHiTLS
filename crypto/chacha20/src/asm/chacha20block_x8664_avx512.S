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
g_ror16:
    .byte   0x2,0x3,0x0,0x1, 0x6,0x7,0x4,0x5, 0xa,0xb,0x8,0x9, 0xe,0xf,0xc,0xd
    .size   g_ror16, .-g_ror16
.align    64
g_ror8:
    .byte   0x3,0x0,0x1,0x2, 0x7,0x4,0x5,0x6, 0xb,0x8,0x9,0xa, 0xf,0xc,0xd,0xe
    .size   g_ror8, .-g_ror8
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
g_addOne:
    .long   0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0
    .size   g_addOne, .-g_addOne
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
g_add16block:
    .long   0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15
    .size   g_add16block, .-g_add16block
.align    64
g_addsecond16block:
    .long   16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16
    .size   g_addsecond16block, .-g_addsecond16block

.set  IN, %rsi
.set OUT, %rdx

/*
 * Processing 64 bytes: 4 x registers, number of instructions in a single loop: 21*2 = 42
 * xmm0 ~ xmm3:
 * xmm0 {0,  1,  2,  3}
 * xmm1 {4,  5,  6,  7}
 * xmm2 {8,  9,  10, 11}
 * xmm3 {12, 13, 14, 15}
 *
 * Processing 128-256 bytes: 4 x registers, number of instructions in a single loop：30
 * ymm0 ~ ymm3:
 * ymm0 {0,  1,  2,  3,  0,  1,  2,  3 }
 * ymm1 {4,  5,  6,  7,  4,  5,  6,  7 }
 * ymm2 {8,  9,  10, 11, 8,  9,  10, 11}
 * ymm3 {12, 13, 14, 15, 12, 13, 14, 15}
 *
 * Processing 512 bytes: y registers 0-15, 128 stack space and y registers 16-31,number of instructions
 *in a single loop：12*8 = 96
 * Processing 1024 bytes: z registers 0-15, 256 stack space and z registers 16-31, number of instructions
 * in a single loop：12*8 = 96
 * ymm0 ~ ymm15:
 * ymm0  {0,  0,  0,  0,  0,  0,  0,  0}
 * ymm1  {1,  1,  1,  1,  1,  1,  1,  1}
 * ymm2  {2,  2,  2,  2,  2,  2,  2,  2}
 * ymm3  {3,  3,  3,  3,  3,  3,  3,  3}
 * ......
 * ymm15 {15, 15, 15, 15, 15, 15, 15, 15}
 *
 * zmm0 ~ zmm31:
 * zmm0  {0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}
 * zmm1  {1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1}
 * zmm2  {2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2}
 * zmm3  {3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3}
 * ...
 * zmm15 {15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}
 */

.macro CHACHA20_ROUND s0 s1 s2 s3
    vpaddd   \s1, \s0, \s0
    vpxord   \s0, \s3, \s3
    vprold   $16, \s3, \s3

    vpaddd   \s3, \s2, \s2
    vpxord   \s2, \s1, \s1
    vprold   $12, \s1, \s1

    vpaddd   \s1, \s0, \s0
    vpxord   \s0, \s3, \s3
    vprold   $8, \s3, \s3

    vpaddd   \s3, \s2, \s2
    vpxord   \s2, \s1, \s1
    vprold   $7, \s1, \s1
.endm

/* convert y registers and write back */
.macro CONVERT_Y s0 s1 pos inpos outpos
    /* ymm16 => {xmm16, xmm17} */
    vextracti32x4   \pos, \s0, %xmm16
    vextracti32x4   \pos, \s1, %xmm17
    vinserti32x4    $1, %xmm17, %ymm16, %ymm16

    vpxord      (IN), %ymm16, %ymm16
    vmovdqu64   %ymm16, (OUT)
    add $32, \inpos
    add $32, \outpos
.endm

/* convert z registers and write back */
.macro CONVERT_Z s0 s1 s2 s3 pos inpos outpos

    /* zmm16 => {xmm16, xmm17, xmm18, xmm19} */
    vextracti64x2  \pos, \s0, %xmm16
    vextracti64x2  \pos, \s1, %xmm17
    vextracti64x2  \pos, \s2, %xmm18
    vextracti64x2  \pos, \s3, %xmm19
    vinserti64x2  $1, %xmm17, %zmm16, %zmm16
    vinserti64x2  $2, %xmm18, %zmm16, %zmm16
    vinserti64x2  $3, %xmm19, %zmm16, %zmm16

    vpxord      (IN), %zmm16, %zmm16
    vmovdqu64   %zmm16, (OUT)
    add $64, \inpos
    add $64, \outpos
.endm

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
    mov  48(%rdi), %r11d
    mov  %rsp, %r9
    subq $2048,%rsp
    andq $-1024,%rsp

.Lchacha20_start:
    cmp  $1024, %rcx
    jae  .Lchacha20_1024_start
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
    LOAD_STATE  %xmm0, %xmm1, %xmm2, %xmm3, %rdi

    vmovdqa %xmm0, %xmm10
    vmovdqa %xmm1, %xmm11
    vmovdqa %xmm2, %xmm12
    vmovdqa %xmm3, %xmm13
    mov $10, %r8

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
    CHACHA20_ROUND %xmm0, %xmm1, %xmm2, %xmm3

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
    CHACHA20_ROUND %xmm0, %xmm1, %xmm2, %xmm3

    vpshufd  $78, %xmm2, %xmm2       // {10 11 8  9} ==> {8  9  10 11}  01 00 11 10
    vpshufd  $147, %xmm1, %xmm1      // {5  6  7  4} ==> {4  5  6   7}  00 11 10 01
    vpshufd  $57, %xmm3, %xmm3       // {15 12 13 14} ==> {12 13 14 15} 10 01 00 11

    decq   %r8
    jnz .Lchacha20_64_loop

    vpaddd  %xmm10, %xmm0, %xmm0
    vpaddd  %xmm11, %xmm1, %xmm1
    vpaddd  %xmm12, %xmm2, %xmm2
    vpaddd  %xmm13, %xmm3, %xmm3

    add     $1, %r11d
    WRITEBACK_64_AVX512    IN, OUT, %xmm0, %xmm1, %xmm2, %xmm3
    mov  %r11d, 48(%rdi)
    jmp  .Lchacha20_end

.Lchacha20_128_start:

    vbroadcasti128 (%rdi),   %ymm0    // {0  1  2   3  0  1  2   3}
    vbroadcasti128 16(%rdi), %ymm1    // {4  5  6   7  4  5  6   7}
    vbroadcasti128 32(%rdi), %ymm2    // {8  9  10 11  8  9  10 11}
    vbroadcasti128 48(%rdi), %ymm3    // {12 13 14 15  12 13 14 15}
    vpaddd g_addOne(%rip), %ymm3, %ymm3

    vmovdqa32 %ymm0, %ymm16
    vmovdqa32 %ymm1, %ymm17
    vmovdqa32 %ymm2, %ymm18
    vmovdqa32 %ymm3, %ymm19
    mov $10, %r8

.Lchacha20_128_loop:

    CHACHA20_ROUND %ymm0, %ymm1, %ymm2, %ymm3

    vpshufd  $78, %ymm2, %ymm2       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    vpshufd  $57, %ymm1, %ymm1       // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    vpshufd  $147, %ymm3, %ymm3      // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    CHACHA20_ROUND %ymm0, %ymm1, %ymm2, %ymm3

    vpshufd  $78, %ymm2, %ymm2       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    vpshufd  $147, %ymm1, %ymm1      // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    vpshufd  $57, %ymm3, %ymm3       // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    decq   %r8
    jnz    .Lchacha20_128_loop

    vpaddd    %ymm16, %ymm0, %ymm0
    vpaddd    %ymm17, %ymm1, %ymm1
    vpaddd    %ymm18, %ymm2, %ymm2
    vpaddd    %ymm19, %ymm3, %ymm3

    vextracti32x4  $1, %ymm0, %xmm5     // ymm0 => {xmm0 xmm5}
    vextracti32x4  $1, %ymm1, %xmm6     // ymm1 => {xmm1 xmm6}
    vextracti32x4  $1, %ymm2, %xmm7     // ymm2 => {xmm2 xmm7}
    vextracti32x4  $1, %ymm3, %xmm8     // ymm3 => {xmm3 xmm8}

    WRITEBACK_64_AVX512     IN, OUT, %xmm0, %xmm1, %xmm2, %xmm3
    WRITEBACK_64_AVX512     IN, OUT, %xmm5, %xmm6, %xmm7, %xmm8

    add $2, %r11d
    sub $128, %rcx
    mov %r11d, 48(%rdi)
    jz  .Lchacha20_end
    jmp .Lchacha20_start

.Lchacha20_256_start:

    LOAD_1024_STATE %zmm0 %zmm1 %zmm2 %zmm3 %rdi
    vpaddd g_addOne(%rip), %zmm3, %zmm3

    vmovdqa64 %zmm0, %zmm16
    vmovdqa64 %zmm1, %zmm17
    vmovdqa64 %zmm2, %zmm18
    vmovdqa64 %zmm3, %zmm19
    mov $10, %r8

.Lchacha20_256_loop:

    CHACHA20_ROUND %zmm0, %zmm1, %zmm2, %zmm3

    vpshufd  $78, %zmm2, %zmm2       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    vpshufd  $57, %zmm1, %zmm1       // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    vpshufd  $147, %zmm3, %zmm3      // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    CHACHA20_ROUND %zmm0, %zmm1, %zmm2, %zmm3

    vpshufd  $78, %zmm2, %zmm2       // {8  9  10 11} ==> {10 11 8  9}  01 00 11 10
    vpshufd  $147, %zmm1, %zmm1      // {4  5  6   7} ==> {5  6  7  4}  00 11 10 01
    vpshufd  $57, %zmm3, %zmm3       // {12 13 14 15} ==> {15 12 13 14} 10 01 00 11

    decq   %r8
    jnz    .Lchacha20_256_loop

    vpaddd    %zmm16, %zmm0, %zmm0
    vpaddd    %zmm17, %zmm1, %zmm1
    vpaddd    %zmm18, %zmm2, %zmm2
    vpaddd    %zmm19, %zmm3, %zmm3

    vextracti64x2  $1, %zmm0, %xmm4
    vextracti64x2  $1, %zmm1, %xmm5
    vextracti64x2  $1, %zmm2, %xmm6
    vextracti64x2  $1, %zmm3, %xmm7

    vextracti64x2  $2, %zmm0, %xmm8
    vextracti64x2  $2, %zmm1, %xmm9
    vextracti64x2  $2, %zmm2, %xmm10
    vextracti64x2  $2, %zmm3, %xmm11

    vextracti64x2  $3, %zmm0, %xmm12
    vextracti64x2  $3, %zmm1, %xmm13
    vextracti64x2  $3, %zmm2, %xmm14
    vextracti64x2  $3, %zmm3, %xmm15

    WRITEBACK_64_AVX512 IN, OUT, %xmm0, %xmm1, %xmm2, %xmm3
    WRITEBACK_64_AVX512 IN, OUT, %xmm4, %xmm5, %xmm6, %xmm7
    WRITEBACK_64_AVX512 IN, OUT, %xmm8, %xmm9, %xmm10, %xmm11
    WRITEBACK_64_AVX512 IN, OUT, %xmm12, %xmm13, %xmm14, %xmm15

    add   $4, %r11d
    sub   $256, %rcx
    mov  %r11d, 48(%rdi)
    jz   .Lchacha20_end
    jmp  .Lchacha20_start

.Lchacha20_512_start:
    LOAD_512_STATE %ymm0, %ymm1, %ymm2, %ymm3, %rdi

    vpshufd $0b00000000, %ymm3, %ymm12
    vpshufd $0b01010101, %ymm3, %ymm13

    vpaddd g_add8block(%rip), %ymm12, %ymm12             // 0, 1, 2, 3, 4, 5, 6 ,7
    vmovdqa32 %ymm12, %ymm28
    vpshufd $0b10101010, %ymm3, %ymm14
    vmovdqa32 %ymm13, %ymm29
    vpshufd $0b11111111, %ymm3, %ymm15
    vmovdqa32 %ymm14, %ymm30

    vpshufd $0b00000000, %ymm2, %ymm8
    vmovdqa32 %ymm15, %ymm31
    vpshufd $0b01010101, %ymm2, %ymm9
    vmovdqa32 %ymm8, %ymm24
    vpshufd $0b10101010, %ymm2, %ymm10
    vmovdqa32 %ymm9, %ymm25
    vpshufd $0b11111111, %ymm2, %ymm11
    vmovdqa32 %ymm10, %ymm26

    vpshufd $0b00000000, %ymm1, %ymm4
    vmovdqa32 %ymm11, %ymm27
    vpshufd $0b01010101, %ymm1, %ymm5
    vmovdqa32 %ymm4, %ymm20
    vpshufd $0b10101010, %ymm1, %ymm6
    vmovdqa32 %ymm5, %ymm21
    vpshufd $0b11111111, %ymm1, %ymm7
    vmovdqa32 %ymm6, %ymm22

    vpshufd $0b11111111, %ymm0, %ymm3
    vmovdqa32 %ymm7, %ymm23
    vpshufd $0b10101010, %ymm0, %ymm2
    vmovdqa32 %ymm3, %ymm19
    vpshufd $0b01010101, %ymm0, %ymm1
    vmovdqa32 %ymm2, %ymm18
    vpshufd $0b00000000, %ymm0, %ymm0
    vmovdqa32 %ymm1, %ymm17
    vmovdqa32 %ymm0, %ymm16
    mov $10, %r8

.Lchacha20_512_loop:

    CHACHA20_LOOP_AVX512 %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7, %ymm8, %ymm9, \
                        %ymm10, %ymm11, %ymm12, %ymm13, %ymm14, %ymm15

    decq  %r8
    jnz .Lchacha20_512_loop

    /* ymm16~31: original matrix */
    vpaddd %ymm16, %ymm0, %ymm0
    vpaddd %ymm17, %ymm1, %ymm1
    vpaddd %ymm18, %ymm2, %ymm2
    vpaddd %ymm19, %ymm3, %ymm3
    vpaddd %ymm20, %ymm4, %ymm4
    vpaddd %ymm21, %ymm5, %ymm5
    vpaddd %ymm22, %ymm6, %ymm6
    vpaddd %ymm23, %ymm7, %ymm7
    vpaddd %ymm24, %ymm8, %ymm8
    vpaddd %ymm25, %ymm9, %ymm9
    vpaddd %ymm26, %ymm10, %ymm10
    vpaddd %ymm27, %ymm11, %ymm11
    vpaddd %ymm28, %ymm12, %ymm12
    vpaddd %ymm29, %ymm13, %ymm13
    vpaddd %ymm30, %ymm14, %ymm14
    vpaddd %ymm31, %ymm15, %ymm15

    MATRIX_TO_STATE %ymm0, %ymm1, %ymm2, %ymm3, %ymm20, %ymm21              // set state 0, 3, 9, 10
    MATRIX_TO_STATE %ymm4, %ymm5, %ymm6, %ymm7, %ymm22, %ymm23              // set state 4, 7, 13, 14
    MATRIX_TO_STATE %ymm8, %ymm9, %ymm10, %ymm11, %ymm1, %ymm2              // set state 8, 11, 1, 2
    MATRIX_TO_STATE %ymm12, %ymm13, %ymm14, %ymm15, %ymm5, %ymm6            // set state 12, 15, 5, 6

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

    CONVERT_Y %ymm0, %ymm4, $0 IN OUT
    CONVERT_Y %ymm8, %ymm12, $0 IN OUT
    CONVERT_Y %ymm3, %ymm7, $0 IN OUT
    CONVERT_Y %ymm11, %ymm15, $0 IN OUT
    CONVERT_Y %ymm20, %ymm22, $0 IN OUT
    CONVERT_Y %ymm1, %ymm5, $0 IN OUT
    CONVERT_Y %ymm21, %ymm23, $0 IN OUT
    CONVERT_Y %ymm2, %ymm6, $0 IN OUT
    CONVERT_Y %ymm0, %ymm4, $1 IN OUT
    CONVERT_Y %ymm8, %ymm12, $1 IN OUT
    CONVERT_Y %ymm3, %ymm7, $1 IN OUT
    CONVERT_Y %ymm11, %ymm15, $1 IN OUT
    CONVERT_Y %ymm20, %ymm22, $1 IN OUT
    CONVERT_Y %ymm1, %ymm5, $1 IN OUT
    CONVERT_Y %ymm21, %ymm23, $1 IN OUT
    CONVERT_Y %ymm2, %ymm6, $1 IN OUT

    add   $8, %r11d
    sub   $512, %rcx
    mov   %r11d, 48(%rdi)
    jz   .Lchacha20_end
    jmp  .Lchacha20_start

.Lchacha20_1024_start:

    LOAD_1024_STATE %zmm0 %zmm1 %zmm2 %zmm3 %rdi

    STATE_TO_MATRIX_Z_AVX512 %zmm0, %zmm16, %zmm17, %zmm18, %zmm19
    STATE_TO_MATRIX_Z_AVX512 %zmm1, %zmm20, %zmm21, %zmm22, %zmm23
    STATE_TO_MATRIX_Z_AVX512 %zmm2, %zmm24, %zmm25, %zmm26, %zmm27
    STATE_TO_MATRIX_Z_AVX512 %zmm3, %zmm28, %zmm29, %zmm30, %zmm31
    vpaddd g_add16block(%rip), %zmm28, %zmm28

    vmovdqa64 %zmm16, %zmm0
    vmovdqa64 %zmm17, %zmm1
    vmovdqa64 %zmm18, %zmm2
    vmovdqa64 %zmm19, %zmm3
    vmovdqa64 %zmm20, %zmm4
    vmovdqa64 %zmm21, %zmm5
    vmovdqa64 %zmm22, %zmm6
    vmovdqa64 %zmm23, %zmm7
    vmovdqa64 %zmm24, %zmm8
    vmovdqa64 %zmm25, %zmm9
    vmovdqa64 %zmm26, %zmm10
    vmovdqa64 %zmm27, %zmm11
    vmovdqa64 %zmm28, %zmm12
    vmovdqa64 %zmm29, %zmm13
    vmovdqa64 %zmm30, %zmm14
    vmovdqa64 %zmm31, %zmm15
    mov $10, %r8
    jmp .Lchacha20_1024_loop

.Lchacha20_1024_start_cont:

    vmovdqa32 %zmm16, %zmm0
    vmovdqa32 %zmm17, %zmm1
    vmovdqa32 %zmm18, %zmm2
    vmovdqa32 %zmm19, %zmm3
    vmovdqa32 %zmm20, %zmm4
    vmovdqa32 %zmm21, %zmm5
    vmovdqa32 %zmm22, %zmm6
    vmovdqa32 %zmm23, %zmm7
    vmovdqa32 %zmm24, %zmm8
    vmovdqa32 %zmm25, %zmm9
    vmovdqa32 %zmm26, %zmm10
    vmovdqa32 %zmm27, %zmm11
    vmovdqa32 %zmm28, %zmm12
    vmovdqa32 %zmm29, %zmm13
    vpaddd g_addsecond16block(%rip), %zmm12, %zmm12                   // add 8, 8, 8, 8, 8, 8, 8, 8 or 4, 4, 4, 4
    vmovdqa32 %zmm30, %zmm14
    vmovdqa32 %zmm31, %zmm15
    vmovdqa32 %zmm12, %zmm28
    mov $10, %r8

.Lchacha20_1024_loop:

    CHACHA20_LOOP_AVX512    %zmm0, %zmm1, %zmm2, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, \
                            %zmm10, %zmm11, %zmm12, %zmm13, %zmm14, %zmm15
    decq  %r8
    jnz .Lchacha20_1024_loop

    vpaddd %zmm16, %zmm0, %zmm0
    vpaddd %zmm17, %zmm1, %zmm1
    vpaddd %zmm18, %zmm2, %zmm2
    vpaddd %zmm19, %zmm3, %zmm3
    vpaddd %zmm20, %zmm4, %zmm4
    vpaddd %zmm21, %zmm5, %zmm5
    vpaddd %zmm22, %zmm6, %zmm6
    vpaddd %zmm23, %zmm7, %zmm7
    vpaddd %zmm24, %zmm8, %zmm8
    vpaddd %zmm25, %zmm9, %zmm9
    vpaddd %zmm26, %zmm10, %zmm10
    vpaddd %zmm27, %zmm11, %zmm11
    vpaddd %zmm28, %zmm12, %zmm12
    vpaddd %zmm29, %zmm13, %zmm13
    vpaddd %zmm30, %zmm14, %zmm14
    vpaddd %zmm31, %zmm15, %zmm15

    /* store matrix 16, 17, 18, 19 in stack */
    vmovdqa64 %zmm16,    (%rsp)
    vmovdqa64 %zmm17,  64(%rsp)
    vmovdqa64 %zmm18, 128(%rsp)
    vmovdqa64 %zmm19, 192(%rsp)

    /* store matrix 9, 10, 13, 14 in zmm16, 17, 18, 19 */
    vmovdqa64 %zmm9,  %zmm16                                            // zmm16: encrypt matrix zmm9
    vmovdqa64 %zmm10, %zmm17                                            // zmm17: encrypt matrix zmm10
    vmovdqa64 %zmm13, %zmm18                                            // zmm18: encrypt matrix zmm13
    vmovdqa64 %zmm14, %zmm19                                            // zmm19: encrypt matrix zmm14

    /* zmm0~15: encrypt matrix 0 ~ 15*/
    MATRIX_TO_STATE %zmm0, %zmm1, %zmm2, %zmm3, %zmm9, %zmm10           // set state 0, 3, 9, 10
    MATRIX_TO_STATE %zmm4, %zmm5, %zmm6, %zmm7, %zmm13, %zmm14          // set state 4, 7, 13, 14
    MATRIX_TO_STATE %zmm8, %zmm16, %zmm17, %zmm11, %zmm1, %zmm2         // set state 8, 11, 1, 2
    MATRIX_TO_STATE %zmm12, %zmm18, %zmm19, %zmm15, %zmm5, %zmm6        // set state 12, 15, 5, 6

    /*
     * {A0 A1 A2 A3 E0 E1 E2 E3 I0 I1 I2 I3 M0 M1 M2 M3}
     * {B0 B1 B2 B3 F0 F1 F2 F3 J0 J1 J2 J3 N0 N1 N2 N3}
     * {C0 C1 C2 C3 G0 G1 G2 G3 K0 K1 K2 K3 O0 O1 O2 O3}
     * {D0 D1 D2 D3 H0 H1 H2 H3 L0 L1 L2 L3 P0 P1 P2 P3}
     * ...
     * =>
     * {A0 A1 A2 A3 B0 B1 B2 B3 C0 C1 C2 C3 D0 D1 D2 D3}
     * {E0 E1 E2 E3 F0 F1 F2 F3 G0 G1 G2 G3 H0 H1 H2 H3}
     * {I0 I1 I2 I3 J0 J1 J2 J3 K0 K1 K2 K3 L0 L1 L2 L3}
     * ....
     */

    CONVERT_Z %zmm0, %zmm4, %zmm8, %zmm12, $0 IN OUT
    CONVERT_Z %zmm3, %zmm7, %zmm11, %zmm15, $0 IN OUT
    CONVERT_Z %zmm9, %zmm13, %zmm1, %zmm5, $0 IN OUT
    CONVERT_Z %zmm10, %zmm14, %zmm2, %zmm6, $0 IN OUT
    CONVERT_Z %zmm0, %zmm4, %zmm8, %zmm12, $1 IN OUT
    CONVERT_Z %zmm3, %zmm7, %zmm11, %zmm15, $1 IN OUT
    CONVERT_Z %zmm9, %zmm13, %zmm1, %zmm5, $1 IN OUT
    CONVERT_Z %zmm10, %zmm14, %zmm2, %zmm6, $1 IN OUT
    CONVERT_Z %zmm0, %zmm4, %zmm8, %zmm12, $2 IN OUT
    CONVERT_Z %zmm3, %zmm7, %zmm11, %zmm15, $2 IN OUT
    CONVERT_Z %zmm9, %zmm13, %zmm1, %zmm5, $2 IN OUT
    CONVERT_Z %zmm10, %zmm14, %zmm2, %zmm6, $2 IN OUT
    CONVERT_Z %zmm0, %zmm4, %zmm8, %zmm12, $3 IN OUT
    CONVERT_Z %zmm3, %zmm7, %zmm11, %zmm15, $3 IN OUT
    CONVERT_Z %zmm9, %zmm13, %zmm1, %zmm5, $3 IN OUT
    CONVERT_Z %zmm10, %zmm14, %zmm2, %zmm6, $3 IN OUT

    /* store zmm16~19 in stack */
    vmovdqa64    (%rsp), %zmm16
    vmovdqa64  64(%rsp), %zmm17
    vmovdqa64 128(%rsp), %zmm18
    vmovdqa64 192(%rsp), %zmm19

    add  $16, %r11d
    sub  $1024, %rcx
    mov  %r11d, 48(%rdi)
    jz   .Lchacha20_clear
    cmp  $1024, %rcx
    jae  .Lchacha20_1024_start_cont
    jmp  .Lchacha20_start

.Lchacha20_clear:
    /* clear sensitive info in stack */
    vpxord %zmm0, %zmm0, %zmm0
    vmovdqa64 %zmm0,    (%rsp)
    vmovdqa64 %zmm0,  64(%rsp)
    vmovdqa64 %zmm0, 128(%rsp)
    vmovdqa64 %zmm0, 192(%rsp)

.Lchacha20_end:
    xor   %r11d, %r11d
    mov   %r9, %rsp
    .cfi_endproc
    ret
.size CHACHA20_Update,.-CHACHA20_Update

#endif
