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
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)

#include "poly1305_x86_64.S"

.file   "poly1305_x86_64_avx512.S"
.text

.set    ZH0, %zmm0
.set    ZH1, %zmm1
.set    ZH2, %zmm2
.set    ZH3, %zmm3
.set    ZH4, %zmm4
.set    ZT0, %zmm5
.set    ZT1, %zmm6
.set    ZT2, %zmm7
.set    ZT3, %zmm8
.set    ZT4, %zmm9
.set    ZMASK, %zmm10
.set    ZB0, %zmm11
.set    ZB1, %zmm12
.set    ZB2, %zmm13
.set    ZB3, %zmm14
.set    ZB4, %zmm15
.set    ZR0, %zmm16
.set    ZR1, %zmm17
.set    ZR2, %zmm18
.set    ZR3, %zmm19
.set    ZR4, %zmm20
.set    ZS1, %zmm21
.set    ZS2, %zmm22
.set    ZS3, %zmm23
.set    ZS4, %zmm24
.set    ZM0, %zmm25
.set    ZM1, %zmm26
.set    ZM2, %zmm27
.set    ZM3, %zmm28
.set    ZM4, %zmm29
.set    PADBIT_ZMM, %zmm30

.align  64
g_permd_avx512:
    .long  0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7
.size   g_permd_avx512, .-g_permd_avx512

/**
 *  Function description: This function is implemented by x86_64 poly1305. The result is stored in ctx->acc.
 *  Function prototype: uint32_t Poly1305Block(Poly1305_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t padbit);
 *  Input register:
 *        CTX: address of the Poly305_Ctx structure
 *        INP: pointer to the input data
 *        LEN: length of the input data
 *        PADBIT: padding bit, 0 or 1.
 *  Change register: r8-r15, rbx, rbp, rdx, rax
 *  Output register:
 *        %rax: length of the remaining data to be processed
 *  Function/Macro Call: Poly1305_MOD_MUL
 */
.globl  Poly1305Block
.type   Poly1305Block, @function
Poly1305Block:
.cfi_startproc
.align  32
    cmp $256, LEN
    jae .Lblock_avx_pre
    call Poly1305Block64Bit
    ret

.Lblock_avx_pre:
    andq $-16, LEN
    test $63, LEN
    jz  Poly1305BlockAVX512

.Lbase2_64_avx_body:

    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    movq LEN, %r15
    movq (CTX), ACC1                     // load acc
    LOAD_ACC_R  CTX, R0, R1, R2, ACC1, ACC2, ACC3, %r8d, %rax
    test   %r8d, %r8d
    jz  .Lbase2_64_avx_loop

    CONVERT_26TO64_PRE  ACC1, ACC2, D1, D2, D3
    CONVERT_26TO64 ACC1 D1, ACC2, D2, D3, ACC3
    movl $0, 220(CTX)

.align 32
.Lbase2_64_avx_loop:
    addq (INP), ACC1
    adcq 8(INP), ACC2
    adcq PADBIT, ACC3
    lea 16(INP), INP

    POLY1305_MOD_MUL ACC1, ACC2, ACC3, R0, R1, R2

    subq $16, %r15
    test $63, %r15
    movq R1, %rax
    jnz .Lbase2_64_avx_loop

    movq ACC1, (CTX)
    movq ACC2, 8(CTX)
    movq ACC3, 16(CTX)
    movq %r15, LEN
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx

    jmp Poly1305BlockAVX512
    ret
.cfi_endproc
.size  Poly1305Block, .-Poly1305Block

/**
 *  Function description: x86_64 poly1305 AVX512 assembly acceleration implementation
 *  Input register:
 *      CTX: address of the Poly305_Ctx structure
 *      INP: pointer to the input data
 *      LEN: length of the input data
 *      PADBIT: padding bit, 0 or 1.
 *  Change register: zmm0-31, rax, rsp, r11, rcx, rdi, k1-k3
 *  Output register:
 *      rax: length of the remaining data to be processed
 *  Function/Macro Call:
 *        CONVERT_64TO26
 */
.globl  Poly1305BlockAVX512
.type   Poly1305BlockAVX512, @function
.align  32
Poly1305BlockAVX512:
.cfi_startproc
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    vzeroupper
    movq (CTX), ACC1
    movq 8(CTX), ACC2
    movq 16(CTX), ACC3
    movl 220(CTX), %r8d
    test %r8d, %r8d
    jnz .Lblock_avx512_pre
    movq LEN, %r15
    CONVERT_64TO26  ACC1, ACC2, ACC3, %rax, %rdx
    movq %r15, LEN
    jmp .Lblock_avx512_body

.Lblock_avx512_pre:
    movd %r14, %xmm0
    movd %rbx, %xmm2
    shrq $32, %r14
    shrq $32, %rbx
    movd %r14, %xmm1
    movd %rbx, %xmm3
    movd %rbp, %xmm4

.Lblock_avx512_body:

    movl $15, %eax
    kmovw %eax, %k2
    leaq -8(%rsp), %r11
    subq $0x128, %rsp
    leaq 56(CTX), CTX
    vmovdqa g_permd_avx2(%rip), YT2                        // g_permd_avx2

    // Extend the precomputation table to the power of 8
    andq $-512, %rsp
    movq $0x20, %rax
    vmovdqu (CTX), %xmm11
    vmovdqu 16(CTX), %xmm12
    vmovdqu 32(CTX), %xmm5
    vmovdqu 48(CTX), %xmm13
    vmovdqu 64(CTX), %xmm6
    vmovdqu 80(CTX), %xmm14
    vpermd  ZB0, ZT2, ZR0                                 // 00 00 34 12 -> 14 24 34 44
    vmovdqu 96(CTX), %xmm8
    vpbroadcastq     g_mask26(%rip), ZMASK                // g_mask26
    vmovdqu 112(CTX), %xmm15
    vpermd  ZB1, ZT2, ZR1
    vmovdqu 128(CTX), %xmm9
    vpermd  ZT0, ZT2, ZS1
    vpermd  ZB2, ZT2, ZR2
    vmovdqa64   ZR0, (%rsp){%k2}
    vpsrlq  $32, ZR0, ZT0                                 // 14 24 34 44 -> 01 02 03 04
    vpermd  ZT1, ZT2, ZS2
    vmovdqu64   ZR1, (%rsp, %rax){%k2}
    vpsrlq  $32, ZR1, ZT1
    vpermd  ZB3, ZT2, ZR3
    vmovdqa64   ZS1, 0x40(%rsp){%k2}
    vpermd  ZT3, ZT2, ZS3
    vmovdqu64   ZR2, 0x40(%rsp, %rax){%k2}
    vpermd  ZB4, ZT2, ZR4
    vmovdqa64   ZS2, 0x80(%rsp){%k2}
    vpermd  ZT4, ZT2, ZS4
    vmovdqu64   ZR3, 0x80(%rsp, %rax){%k2}
    vmovdqa64   ZS3, 0xc0(%rsp){%k2}
    vmovdqu64   ZR4, 0xc0(%rsp, %rax){%k2}
    vmovdqa64   ZS4, 0x100(%rsp){%k2}

    vpmuludq    ZT0, ZR0, ZB0
    vpmuludq    ZT0, ZR1, ZB1
    vpmuludq    ZT0, ZR2, ZB2
    vpmuludq    ZT0, ZR3, ZB3
    vpmuludq    ZT0, ZR4, ZB4
    vpsrlq      $32, ZR2, ZT2

    vpmuludq    ZT1, ZS4, ZM0
    vpmuludq    ZT1, ZR0, ZM1
    vpmuludq    ZT1, ZR1, ZM2
    vpmuludq    ZT1, ZR2, ZM3
    vpmuludq    ZT1, ZR3, ZM4
    vpsrlq      $32, ZR3, ZT3
    vpaddq      ZM0, ZB0, ZB0
    vpaddq      ZM1, ZB1, ZB1
    vpaddq      ZM2, ZB2, ZB2
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4

    vpmuludq    ZT2, ZS3, ZM0
    vpmuludq    ZT2, ZS4, ZM1
    vpmuludq    ZT2, ZR0, ZM2
    vpmuludq    ZT2, ZR1, ZM3
    vpmuludq    ZT2, ZR2, ZM4
    vpsrlq      $32, ZR4, ZT4
    vpaddq      ZM0, ZB0, ZB0
    vpaddq      ZM1, ZB1, ZB1
    vpaddq      ZM2, ZB2, ZB2
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4

    vpmuludq    ZT3, ZS2, ZM0
    vpmuludq    ZT3, ZS3, ZM1
    vpmuludq    ZT3, ZS4, ZM2
    vpmuludq    ZT3, ZR0, ZM3
    vpmuludq    ZT3, ZR1, ZM4
    vpaddq      ZM0, ZB0, ZB0
    vpaddq      ZM1, ZB1, ZB1
    vpaddq      ZM2, ZB2, ZB2
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4

    vpmuludq    ZT4, ZS1, ZM0
    vpmuludq    ZT4, ZS2, ZM1
    vpmuludq    ZT4, ZS3, ZM2
    vpmuludq    ZT4, ZS4, ZM3
    vpmuludq    ZT4, ZR0, ZM4
    vpaddq      ZM0, ZB0, ZB0
    vpaddq      ZM1, ZB1, ZB1
    vpaddq      ZM2, ZB2, ZB2
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4

    // reduction
    vpsrlq      $26, ZB3, ZM3
    vpandq      ZMASK, ZB3, ZB3
    vpaddq      ZM3, ZB4, ZB4                               // d3 -> d4
    vpsrlq      $26, ZB0, ZM0
    vpandq      ZMASK, ZB0, ZB0
    vpaddq      ZM0, ZB1, ZB1                               // d0 -> d1
    vpsrlq      $26, ZB4, ZM4
    vpandq      ZMASK, ZB4, ZB4
    vmovdqu64   (INP), ZT3
    vmovdqu64   64(INP), ZT4
    leaq    128(INP), INP
    vpsrlq      $26, ZB1, ZM1
    vpandq      ZMASK, ZB1, ZB1
    vpaddq      ZM1, ZB2, ZB2                               // d1 -> d2
    vpaddq      ZM4, ZB0, ZB0
    vpsllq      $2, ZM4, ZM4
    vpaddq      ZM4, ZB0, ZB0                               // d4 -> d0
    vpsrlq      $26, ZB2, ZM2
    vpandq      ZMASK, ZB2, ZB2
    vpaddq      ZM2, ZB3, ZB3                               // d2 -> d3
    vpsrlq      $26, ZB0, ZM0
    vpandq      ZMASK, ZB0, ZB0
    vpaddq      ZM0, ZB1, ZB1                               // d0 -> d1
    vpsrlq      $26, ZB3, ZM3
    vpandq      ZMASK, ZB3, ZB3
    vpaddq      ZM3, ZB4, ZB4                               // d3 -> d4

    vpunpcklqdq ZT4, ZT3, ZT0
    vpunpckhqdq ZT4, ZT3, ZT4

    // Construct R and S to make them in operable form.
    vmovdqu32   g_permd_avx512(%rip), ZM0                   // g_permd_avx512
    movl    $0x7777, %eax
    kmovw   %eax, %k1
    vpermd      ZR0, ZM0, ZR0                               // 14 24 34 44 -> 1444 2444 3444 4444
    vpermd      ZR1, ZM0, ZR1
    vpermd      ZR2, ZM0, ZR2
    vpermd      ZR3, ZM0, ZR3
    vpermd      ZR4, ZM0, ZR4
    vpermd      ZB0, ZM0, ZR0{%k1}                          // 05 06 07 08 and 1444 2444 3444 4444 -> 1858 2868 3878 4888
    vpermd      ZB1, ZM0, ZR1{%k1}
    vpermd      ZB2, ZM0, ZR2{%k1}
    vpermd      ZB3, ZM0, ZR3{%k1}
    vpermd      ZB4, ZM0, ZR4{%k1}

    vpslld      $2, ZR1, ZS1
    vpslld      $2, ZR2, ZS2
    vpslld      $2, ZR3, ZS3
    vpslld      $2, ZR4, ZS4
    vpaddd      ZR1, ZS1, ZS1
    vpaddd      ZR2, ZS2, ZS2
    vpaddd      ZR3, ZS3, ZS3
    vpaddd      ZR4, ZS4, ZS4

    // Processes the input message block and constructs the operation form.
    vpbroadcastq    g_129(%rip), PADBIT_ZMM                 // g_129
    vpsrlq      $52, ZT0, ZT2
    vpsllq      $12, ZT4, ZT3
    vporq       ZT3, ZT2, ZT2
    vpsrlq      $26, ZT0, ZT1
    vpsrlq      $14, ZT4, ZT3
    vpsrlq      $40, ZT4, ZT4                               // 4
    vpandq      ZMASK, ZT0, ZT0                             // 0
    vpandq      ZMASK, ZT2, ZT2                             // 2

    vpaddq      ZH2, ZT2, ZH2
    subq    $192, LEN
    jbe     .Lblock_avx512_tail
    jmp     .Lblock_avx512_loop

.align  32
.Lblock_avx512_loop:

    // ((inp[0] * r^8 + inp[ 8]) * r^8 + inp[16]) * r^8
    // ((inp[1] * r^8 + inp[ 9]) * r^8 + inp[17]) * r^7
    // ((inp[2] * r^8 + inp[10]) * r^8 + inp[18]) * r^6
    // ((inp[3] * r^8 + inp[11]) * r^8 + inp[19]) * r^5
    // ((inp[4] * r^8 + inp[12]) * r^8 + inp[20]) * r^4
    // ((inp[5] * r^8 + inp[13]) * r^8 + inp[21]) * r^3
    // ((inp[6] * r^8 + inp[14]) * r^8 + inp[22]) * r^2
    // ((inp[7] * r^8 + inp[15]) * r^8 + inp[23]) * r^1

        // b3 = h2*r1   + h0*r3 + h1*r2   + h3*r0 + h4*5*r4
    // b4 = h2*r2   + h0*r4 + h1*r3   + h3*r1 + h4*r0
    // b0 = h2*5*r3 + h0*r0 + h1*5*r4         + h3*5*r2 + h4*5*r1
    // b1 = h2*5*r4 + h0*r1           + h1*r0 + h3*5*r3 + h4*5*r2
    // b2 = h2*r0           + h0*r2   + h1*r1 + h3*5*r4 + h4*5*r3

    vpmuludq    ZH2, ZR1, ZB3
    vpandq      ZMASK, ZT1, ZT1                             // 1
    vpmuludq    ZH2, ZR2, ZB4
    vpandq      ZMASK, ZT3, ZT3                             // 3
    vpmuludq    ZH2, ZS3, ZB0
    vporq       PADBIT_ZMM, ZT4, ZT4
    vpmuludq    ZH2, ZS4, ZB1
    vpaddq      ZH0, ZT0, ZH0
    vpmuludq    ZH2, ZR0, ZB2
    vpaddq      ZH1, ZT1, ZH1
    vpaddq      ZH3, ZT3, ZH3
    vpaddq      ZH4, ZT4, ZH4
    vmovdqu64   (INP), ZT3
    vmovdqu64   64(INP), ZT4
    lea   128(INP), INP

    vpmuludq    ZH0, ZR3, ZM3
    vpmuludq    ZH0, ZR4, ZM4
    vpmuludq    ZH0, ZR0, ZM0
    vpmuludq    ZH0, ZR1, ZM1
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4
    vpaddq      ZM0, ZB0, ZB0
    vpaddq      ZM1, ZB1, ZB1

    vpmuludq    ZH1, ZR2, ZM3
    vpmuludq    ZH1, ZR3, ZM4
    vpmuludq    ZH1, ZS4, ZM0
    vpmuludq    ZH0, ZR2, ZM2
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4
    vpaddq      ZM0, ZB0, ZB0
    vpaddq      ZM2, ZB2, ZB2
    vpunpcklqdq ZT4, ZT3, ZT0
    vpunpckhqdq ZT4, ZT3, ZT4

    vpmuludq    ZH3, ZR0, ZM3
    vpmuludq    ZH3, ZR1, ZM4
    vpmuludq    ZH1, ZR0, ZM1
    vpmuludq    ZH1, ZR1, ZM2
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4
    vpaddq      ZM1, ZB1, ZB1
    vpaddq      ZM2, ZB2, ZB2

    vpmuludq    ZH4, ZS4, ZM3
    vpmuludq    ZH4, ZR0, ZM4
    vpmuludq    ZH3, ZS2, ZM0
    vpmuludq    ZH3, ZS3, ZM1
    vpmuludq    ZH3, ZS4, ZM2
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4
    vpaddq      ZM0, ZB0, ZB0
    vpaddq      ZM1, ZB1, ZB1
    vpaddq      ZM2, ZB2, ZB2

    vpmuludq    ZH4, ZS1, ZM0
    vpmuludq    ZH4, ZS2, ZM1
    vpmuludq    ZH4, ZS3, ZM2
    vpaddq      ZM0, ZB0, ZH0
    vpaddq      ZM1, ZB1, ZH1
    vpaddq      ZM2, ZB2, ZH2
    vpsrlq    $52, ZT0, ZT2
    vpsllq    $12, ZT4, ZT3

    // reduction
    vpsrlq      $26, ZB3, ZH3
    vpandq      ZMASK, ZB3, ZB3
    vpaddq      ZH3, ZB4, ZH4
    vporq       ZT3, ZT2, ZT2

    vpsrlq      $26, ZH0, ZB0
    vpandq      ZMASK, ZH0, ZH0
    vpaddq      ZB0, ZH1, ZH1
    vpandq      ZMASK, ZT2, ZT2

    vpsrlq      $26, ZH4, ZB4
    vpandq      ZMASK, ZH4, ZH4
    vpsrlq      $26, ZH1, ZB1
    vpandq      ZMASK, ZH1, ZH1
    vpaddq      ZB1, ZH2, ZH2

    vpaddq      ZB4, ZH0, ZH0
    vpsllq      $2, ZB4, ZB4
    vpaddq      ZB4, ZH0, ZH0
    vpaddq      ZT2, ZH2, ZH2
    vpsrlq      $26, ZT0, ZT1

    vpsrlq      $26, ZH2, ZB2
    vpandq      ZMASK, ZH2, ZH2
    vpaddq      ZB2, ZB3, ZH3
    vpsrlq      $14, ZT4, ZT3
    vpsrlq      $40, ZT4, ZT4
    vpandq      ZMASK, ZT0, ZT0

    vpsrlq      $26, ZH0, ZB0
    vpandq      ZMASK, ZH0, ZH0
    vpaddq      ZB0, ZH1, ZH1

    vpsrlq      $26, ZH3, ZB3
    vpandq      ZMASK, ZH3, ZH3
    vpaddq      ZB3, ZH4, ZH4

    subq    $128, LEN
    ja  .Lblock_avx512_loop

.align  32
.Lblock_avx512_tail:

    vpsrlq      $32, ZR0, ZR0                               // 1858286838784888 -> 0105020603070408
    vpsrlq      $32, ZR1, ZR1
    vpsrlq      $32, ZS1, ZS1
    vpsrlq      $32, ZR2, ZR2
    vpsrlq      $32, ZS2, ZS2
    vpsrlq      $32, ZR3, ZR3
    vpsrlq      $32, ZS3, ZS3
    vpsrlq      $32, ZR4, ZR4
    vpsrlq      $32, ZS4, ZS4

    lea (INP, LEN), INP
    vpaddq      ZH0, ZT0, ZH0
    vpmuludq    ZH2, ZR1, ZB3
    vpandq      ZMASK, ZT1, ZT1
    vpmuludq    ZH2, ZR2, ZB4
    vpandq      ZMASK, ZT3, ZT3
    vpmuludq    ZH2, ZS3, ZB0
    vporq       PADBIT_ZMM, ZT4, ZT4
    vpmuludq    ZH2, ZS4, ZB1
    vpaddq      ZH1, ZT1, ZH1
    vpmuludq    ZH2, ZR0, ZB2
    vpaddq      ZH3, ZT3, ZH3
    vpaddq      ZH4, ZT4, ZH4

    vmovdqu     (INP), %xmm5
    vmovdqu     16(INP), %xmm6
    vpmuludq    ZH0, ZR3, ZM3
    vpmuludq    ZH0, ZR4, ZM4
    vpmuludq    ZH0, ZR0, ZM0
    vpmuludq    ZH0, ZR1, ZM1
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4
    vpaddq      ZM0, ZB0, ZB0
    vpaddq      ZM1, ZB1, ZB1

    vinserti128    $1, 32(INP), YT0, YT0
    vinserti128    $1, 48(INP), YT1, YT1
    vpmuludq    ZH1, ZR2, ZM3
    vpmuludq    ZH1, ZR3, ZM4
    vpmuludq    ZH1, ZS4, ZM0
    vpmuludq    ZH0, ZR2, ZM2
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4
    vpaddq      ZM0, ZB0, ZB0
    vpaddq      ZM2, ZB2, ZB2

    vpmuludq    ZH3, ZR0, ZM3
    vpmuludq    ZH3, ZR1, ZM4
    vpmuludq    ZH1, ZR0, ZM1
    vpmuludq    ZH1, ZR1, ZM2
    vpaddq      ZM3, ZB3, ZB3
    vpaddq      ZM4, ZB4, ZB4
    vpaddq      ZM1, ZB1, ZB1
    vpaddq      ZM2, ZB2, ZB2

    vpmuludq    ZH4, ZS4, ZM3
    vpmuludq    ZH4, ZR0, ZM4
    vpmuludq    ZH3, ZS2, ZM0
    vpmuludq    ZH3, ZS3, ZM1
    vpmuludq    ZH3, ZS4, ZM2
    vpaddq      ZM3, ZB3, ZH3
    vpaddq      ZM4, ZB4, ZB4
    vpaddq      ZM0, ZB0, ZB0
    vpaddq      ZM1, ZB1, ZB1
    vpaddq      ZM2, ZB2, ZB2

    vpmuludq    ZH4, ZS1, ZM0
    vpmuludq    ZH4, ZS2, ZM1
    vpmuludq    ZH4, ZS3, ZM2
    vpaddq      ZM0, ZB0, ZH0
    vpaddq      ZM1, ZB1, ZH1
    vpaddq      ZM2, ZB2, ZH2

    // Summary of calculation results of different blocks
    movl    $1, %eax
    kmovw   %eax, %k3
    vpermq      $0xb1, ZH0, ZB0
    vpermq      $0xb1, ZH1, ZB1
    vpermq      $0xb1, ZH2, ZB2
    vpermq      $0xb1, ZH3, ZB3
    vpermq      $0xb1, ZB4, ZH4
    vpaddq      ZB0, ZH0, ZH0
    vpaddq      ZB1, ZH1, ZH1
    vpaddq      ZB2, ZH2, ZH2
    vpaddq      ZB3, ZH3, ZH3
    vpaddq      ZB4, ZH4, ZH4
    vpermq      $0x2, ZH0, ZB0
    vpermq      $0x2, ZH1, ZB1
    vpermq      $0x2, ZH2, ZB2
    vpermq      $0x2, ZH3, ZB3
    vpermq      $0x2, ZH4, ZB4
    vpaddq      ZB0, ZH0, ZH0
    vpaddq      ZB1, ZH1, ZH1
    vpaddq      ZB2, ZH2, ZH2
    vpaddq      ZB3, ZH3, ZH3
    vpaddq      ZB4, ZH4, ZH4

    vextracti64x4   $0x1, ZH0, YB0
    vextracti64x4   $0x1, ZH1, YB1
    vextracti64x4   $0x1, ZH2, YB2
    vextracti64x4   $0x1, ZH3, YB3
    vextracti64x4   $0x1, ZH4, YB4
    vpaddq      ZB0, ZH0, ZH0{%k3}{z}
    vpaddq      ZB1, ZH1, ZH1{%k3}{z}
    vpaddq      ZB2, ZH2, ZH2{%k3}{z}
    vpaddq      ZB3, ZH3, ZH3{%k3}{z}
    vpaddq      ZB4, ZH4, ZH4{%k3}{z}

    // reduction
    vpsrlq      $26, YH3, YB3
    vpandq      YMASK, YH3, YH3
    vpaddq      YB3, YH4, YH4
    vpsrldq     $6, YT0, YT2
    vpsrldq     $6, YT1, YT3

    vpsrlq      $26, YH0, YB0
    vpandq      YMASK, YH0, YH0
    vpaddq      YB0, YH1, YH1
    vpunpckhqdq    YT1, YT0, YT4
    vpunpcklqdq    YT1, YT0, YT0
    vpunpcklqdq    YT3, YT2, YT2

    vpsrlq      $26, YH4, YB4
    vpandq      YMASK, YH4, YH4
    vpsrlq      $26, YH1, YB1
    vpandq      YMASK, YH1, YH1
    vpaddq      YB1, YH2, YH2
    vpsrlq      $30, YT2, YT3
    vpsrlq      $4, YT2, YT2

    vpaddq      YB4, YH0, YH0
    vpsllq      $2, YB4, YB4
    vpaddq      YB4, YH0, YH0
    vpsrlq      $26, YT0, YT1
    vpsrlq      $40, YT4, YT4

    vpsrlq      $26, YH2, YB2
    vpandq      YMASK, YH2, YH2
    vpaddq      YB2, YH3, YH3
    vpand       YMASK, YT2, YT2
    vpand       YMASK, YT3, YT3

    vpsrlq      $26, YH0, YB0
    vpandq      YMASK, YH0, YH0
    vpaddq      YB0, YH1, YH1
    vpaddq      YH2, YT2, YH2
    vpand       YMASK, YT1, YT1

    vpsrlq      $26, YH3, YB3
    vpand       YMASK, YH3, YH3
    vpaddq      YB3, YH4, YH4
    vpand       YMASK, YT0, YT0
    vpor        g_129(%rip), YT4, YT4

    addq    $64, LEN
    jnz     .Lblock_4_tail

    vpsubq      YT2, YH2, YH2
    jmp     .Lblock_avx512_end

.align  32
.Lblock_4_tail:
    BLOCK4_AVX2_TAIL YT0, YT1, YT2, YT3, YT4, YH0, YH1, YH2, YH3, YH4, YB0, YB1, YB2, YB3, YB4, YMASK, %rsp

.Lblock_avx512_end:
    vmovd       %xmm0, -56(CTX)
    vmovd       %xmm1, -52(CTX)
    vmovd       %xmm2, -48(CTX)
    vmovd       %xmm3, -44(CTX)
    vmovd       %xmm4, -40(CTX)
    vzeroall
    lea    8(%r11),%rsp

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    movq    LEN, %rax
    ret
.cfi_endproc
.size  Poly1305BlockAVX512, .-Poly1305BlockAVX512

 /**
 *  Function description: This function is used to clear residual sensitive information in a register.
 *  Function prototype: void Poly1305CleanRegister();
 *  Input register: None
 *  Modify the register:
 *  Output register: None
 *  Function/Macro Call: None
 */
.globl  Poly1305CleanRegister
.type   Poly1305CleanRegister,@function
Poly1305CleanRegister:
.cfi_startproc
    vzeroall
    vpxorq   ZR0, ZR0, ZR0
    vpxorq   ZR1, ZR1, ZR1
    vpxorq   ZR2, ZR2, ZR2
    vpxorq   ZR3, ZR3, ZR3
    vpxorq   ZR4, ZR4, ZR4
    vpxorq   ZS1, ZS1, ZS1
    vpxorq   ZS2, ZS2, ZS2
    vpxorq   ZS3, ZS3, ZS3
    vpxorq   ZS4, ZS4, ZS4
    vpxorq   ZM0, ZM0, ZM0
    vpxorq   ZM1, ZM1, ZM1
    vpxorq   ZM2, ZM2, ZM2
    vpxorq   ZM3, ZM3, ZM3
    vpxorq   ZM4, ZM4, ZM4
    ret
.cfi_endproc
.size  Poly1305CleanRegister, .-Poly1305CleanRegister

#endif
