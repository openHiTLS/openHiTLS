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

.file   "poly1305_x86_64_avx2.S"
.text

/**
 *  Function description: This function is implemented by x86_64 poly1305. The result is stored in ctx->acc.
 *  Function prototype: uint32_t Poly1305Block(Poly1305_Ctx *ctx, const uint8_t *data,
 *                                             uint32_t dataLen, uint32_t padbit);
 *  Input register:
 *        CTX: address of the Poly305_Ctx structure
 *        INP: pointer to the input data
 *        LEN: length of the input data
 *        PADBIT: padding bit, 0 or 1.
 *  Change registers: r8-r14, rbx, rbp
 *  Output register:
 *        %rax: length of the remaining data to be processed
 *  Function/Macro Call:Poly1305_MOD_MUL
 */
.globl  Poly1305Block
.type   Poly1305Block,@function
Poly1305Block:
.cfi_startproc
.align  32
    cmp $256, LEN
    jae .Lblock_avx_pre
    jmp Poly1305Block64Bit

.Lblock_avx_pre:
    andq $-16, LEN
    test $63, LEN
    jz  Poly1305BlockAVX2

.Lbase2_64_avx_body:

    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    movq LEN, %r15
    LOAD_ACC_R  CTX, R0, R1, R2, ACC1, ACC2, ACC3, %r8d, %rax
    test   %r8d, %r8d
    jz  .Lbase2_64_avx_loop

    CONVERT_26TO64_PRE  ACC1, ACC2, D1, D2, D3
    CONVERT_26TO64 ACC1, D1, ACC2, D2, D3, ACC3
    movl $0, 220(CTX)

.align 32
.Lbase2_64_avx_loop:
    addq (INP), ACC1
    adcq 8(INP), ACC2
    adcq PADBIT, ACC3
    lea 16(INP), INP

    POLY1305_MOD_MUL ACC1, ACC2, ACC3, R0, R1, R2

    subq $16, %r15
    movq R1, %rax
    test $63, %r15
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

    jmp Poly1305BlockAVX2
    ret
.cfi_endproc
.size  Poly1305Block, .-Poly1305Block

/**
 *  Function description: x86_64 poly1305 AVX2 implementation
 *  Input register:
 *        CTX: address of the Poly305_Ctx structure
 *        INP: pointer to the input data
 *        LEN: length of the input data
 *        PADBIT: padding bit, 0 or 1.
 *  Change register: ymm0-15, r8, r9, r14, r15, rax, rbx, rdx, rbp
 *  Output register:
 *        rax: length of the remaining data to be processed
 *  Function/Macro Call:
 *         CONVERT_64TO26
 */
.globl  Poly1305BlockAVX2
.type   Poly1305BlockAVX2, @function
.align  32
Poly1305BlockAVX2:
.cfi_startproc
    push %rbx
    push %rbp
    push %r14
    push %r15

    vzeroupper
    movq (CTX), ACC1                                    // load acc
    movq 8(CTX), ACC2
    movq 16(CTX), ACC3
    movl 220(CTX), %r8d
    test %r8d, %r8d
    jnz  .Lblock_avx2_pre
    movq LEN, %r15
    CONVERT_64TO26  ACC1, ACC2, ACC3, %rax, %rdx        // base2_64 --> base2_26
    movq %r15, LEN
    jmp  .Lblock_avx2_body

.Lblock_avx2_pre:
    movd %r14, %xmm0
    movd %rbx, %xmm2
    movd %rbp, %xmm4
    shrq $32, %r14
    shrq $32, %rbx
    movd %r14, %xmm1
    movd %rbx, %xmm3

.align  32
.Lblock_avx2_body:

    leaq 56(CTX), CTX                                   // 56(CTX)
    vmovdqu g_permd_avx2(%rip), YT0                     // g_permd_avx2
    leaq -8(%rsp), %r11

    /* Transform the content in the precomputation table into a computable form and put it into the stack. */
    vmovdqu (CTX), %xmm7
    vmovdqu 16(CTX), %xmm8
    subq $0x128, %rsp
    vmovdqu 32(CTX), %xmm9
    vmovdqu 48(CTX), %xmm11
    andq $-512, %rsp
    vmovdqu 64(CTX), %xmm12
    vmovdqu 80(CTX), %xmm13
    vpermd  YT2, YT0, YT2                               // 00 00 34 12 --> 14 24 34 44
    vmovdqu 96(CTX), %xmm14
    vpermd  YT3, YT0, YT3
    vmovdqu 112(CTX), %xmm15
    vpermd  YT4, YT0, YT4
    vmovdqu 128(CTX), %xmm10
    vpermd  YB0, YT0, YB0
    vmovdqa YT2, (%rsp)                                 // r0
    vpermd  YB1, YT0, YB1
    vmovdqa YT3, 0x20(%rsp)                             // r1
    vpermd  YB2, YT0, YB2
    vmovdqa YT4, 0x40(%rsp)                             // s1
    vpermd  YB3, YT0, YB3
    vmovdqa YB0, 0x60(%rsp)                             // r2
    vpermd  YB4, YT0, YB4
    vmovdqa YB1, 0x80(%rsp)                             // s2
    vpermd  YMASK, YT0, YMASK
    vmovdqa YB2, 0xa0(%rsp)                             // r3
    vmovdqa YB3, 0xc0(%rsp)                             // s3
    vmovdqa YB4, 0xe0(%rsp)                             // r4
    vmovdqa YMASK, 0x100(%rsp)                          // s4

    /* Load 4 blocks of data and convert them to base2_26 */
    vmovdqu g_mask26(%rip), YMASK                       // g_mask26
    vmovdqu (INP), %xmm5
    vmovdqu 16(INP), %xmm6
    vinserti128 $1, 32(INP), YT0, YT0
    vinserti128 $1, 48(INP), YT1, YT1
    leaq 64(INP), INP

    vpsrldq     $6, YT0, YT2
    vpsrldq     $6, YT1, YT3
    vpunpckhqdq YT1, YT0, YT4
    vpunpcklqdq YT1, YT0, YT0
    vpunpcklqdq YT3, YT2, YT2

    vpsrlq  $26, YT0, YT1
    vpsrlq  $30, YT2, YT3
    vpsrlq  $4, YT2, YT2
    vpsrlq  $40, YT4, YT4                               // 4
    vpand   YMASK, YT3, YT3                             // 3
    vpand   YMASK, YT2, YT2                             // 2
    vpor    g_129(%rip), YT4, YT4                       // padbit
    vpand   YMASK, YT1, YT1                             // 1
    vpand   YMASK, YT0, YT0                             // 0

    vpaddq  YH2, YT2, YH2
    sub     $64, LEN
    jz  .Lblock_avx2_tail
    jmp .Lblock_avx2_loop

.align  32
.Lblock_avx2_loop:

    // ((inp[0]*r^4 + inp[4])*r^4 + inp[ 8])*r^4
    // ((inp[1]*r^4 + inp[5])*r^4 + inp[ 9])*r^3
    // ((inp[2]*r^4 + inp[6])*r^4 + inp[10])*r^2
    // ((inp[3]*r^4 + inp[7])*r^4 + inp[11])*r^1
    vpaddq  YH0, YT0, YH0
    vpaddq  YH1, YT1, YH1
    vpaddq  YH3, YT3, YH3
    vpaddq  YH4, YT4, YH4
    vmovdqa (%rsp), YT0                              // r0^4
    vmovdqa 0x20(%rsp), YT1                          // r1^4
    vmovdqa 0x60(%rsp), YT2                          // r2^4
    vmovdqa 0xc0(%rsp), YT3                          // s3^4
    vmovdqa 0x100(%rsp), YMASK                       // s4^4

    // b4 = h4*r0^4 + h3*r1^4 + h2*r2^4 + h1*r3^4 + h0*r4^4
    // b3 = h3*r0^4 + h2*r1^4 + h1*r2^4 + h0*r3^4 + h4*s4^4
    // b2 = h2*r0^4 + h1*r1^4 + h0*r2^4 + h4*s3^4 + h3*s4^4
    // b1 = h1*r0^4 + h0*r1^4 + h4*s2^4 + h3*s3^4 + h2*s4^4
    // b0 = h0*r0^4 + h4*s1^4 + h3*s2^4 + h2*s3^4 + h1*s4^4
    //
    // First calculate h2, the above formula can be deformed as
    //
    // b4 = h2*r2^4 + h4*r0^4 + h3*r1^4 +         + h1*r3^4 + h0*r4^4
    // b3 = h2*r1^4 + h3*r0^4 +         + h1*r2^4 + h0*r3^4 + h4*s4^4
    // b2 = h2*r0^4 +         + h1*r1^4 + h0*r2^4 + h4*s3^4 + h3*s4^4
    // b1 = h2*s4^4 + h1*r0^4 + h0*r1^4 + h4*s2^4 + h3*s3^4 +
    // b0 = h2*s3^4 + h0*r0^4 + h4*s1^4 + h3*s2^4 +         + h1*s4^4

    vpmuludq    YH2, YT0, YB2                          // b2 = h2 * r0^4
    vpmuludq    YH2, YT1, YB3                          // b3 = h2 * r1^4
    vpmuludq    YH2, YT2, YB4                          // b4 = h2 * r2^4
    vpmuludq    YH2, YT3, YB0                          // b0 = h2 * s3^4
    vpmuludq    YH2, YMASK, YB1                        // b1 = h2 * s4^4

    vpmuludq    YH1, YT1, YT4                          // h1 * r1^4     (Available Scratch Registers：T4、H2)
    vpmuludq    YH0, YT1, YH2                          // h0 * r1^4
    vpaddq      YT4, YB2, YB2                          // b2 += h1 * r1^4
    vpaddq      YH2, YB1, YB1                          // b1 += h0 * r1^4
    vpmuludq    YH3, YT1, YT4                          // h3 * r1^4
    vpmuludq    0x40(%rsp), YH4, YH2                   // h4 * s1^4
    vpaddq      YT4 ,YB4, YB4                          // b4 += h3 * r1^4
    vpaddq      YH2, YB0, YB0                          // b0 += h4 * s1^4
    vmovdqa     0x80(%rsp), YT1                        // load s2^4

    vpmuludq    YH4, YT0, YT4                          // h4 * r0^4     (Available Scratch Registers：T4、H2)
    vpmuludq    YH3, YT0, YH2                          // h3 * r0^4
    vpaddq      YT4, YB4, YB4                          // b4 += h4 * r0^4
    vpaddq      YH2, YB3, YB3                          // b3 += h3 * r0^4
    vpmuludq    YH0, YT0, YT4                          // h0 * r0^4
    vpmuludq    YH1, YT0, YH2                          // h1 * r0^4
    vpaddq      YT4, YB0, YB0                          // b0 += h0 * r0^4
    vpaddq      YH2, YB1, YB1                          // b1 += h1 * r0^4
    vmovdqu     (INP), %xmm5                           // load input    (YT0)

    vpmuludq    YH4, YT1, YT4                          // h4 * s2^4
    vpmuludq    YH3, YT1, YH2                          // h3 * s2^4
    vinserti128    $1, 32(INP), YT0, YT0
    vpaddq      YT4, YB1, YB1                          // b1 += h4 * s2^4
    vpaddq      YH2, YB0, YB0                          // b0 += h3 * s2^4
    vpmuludq    YH1, YT2, YT4                          // h1 * r2^4     (Available Scratch Registers：T4、H2)
    vpmuludq    YH0, YT2, YH2                          // h0 * r2^4
    vmovdqu     16(INP), %xmm6                         // load input    (YT1)
    vpaddq      YT4, YB3, YB3                          // b3 += h1 * r2^4
    vpaddq      YH2, YB2, YB2                          // b2 += h0 * r2^4
    vinserti128    $1, 48(INP), YT1, YT1
    vmovdqa     0xa0(%rsp), YH2                        // load r3^4
    leaq    64(INP), INP

    vpmuludq    YH1, YH2, YT4                          // h1 * r3^4     (Available Scratch Registers：T4、H2)
    vpmuludq    YH0, YH2, YH2                          // h0 * r3^4
    vpsrldq     $6, YT0, YT2
    vpaddq      YT4, YB4, YB4                          // b4 += h1 * r3^4
    vpaddq      YH2, YB3, YB3                          // b3 += h0 * r3^4
    vpmuludq    YH4, YT3, YT4                          // h4 * s3^4
    vpmuludq    YH3, YT3, YH2                          // h3 * s3^4
    vpsrldq     $6, YT1, YT3
    vpaddq      YT4, YB2, YB2                          // b2 += h4 * s3^4
    vpaddq      YH2, YB1, YB1                          // b1 += h3 * s3^4   (finish)
    vpunpckhqdq YT1, YT0, YT4

    vpmuludq    YH3, YMASK, YH3                        // h3 * s4^4
    vpmuludq    YH4, YMASK, YH4                        // h4 * s4^4
    vpunpcklqdq YT1, YT0, YT0
    vpaddq  YB2, YH3, YH2                              // h2 += h3 * s4^4   (finish)
    vpaddq  YB3, YH4, YH3                              // h3 += h4 * s4^4   (finish)
    vpunpcklqdq YT3, YT2, YT3
    vpmuludq    0xe0(%rsp), YH0, YH4                   // h0 * r4^4
    vpmuludq    YH1, YMASK, YH0                        // h1 * s4^4
    vmovdqu     g_mask26(%rip), YMASK
    vpaddq  YH4, YB4, YH4                              // h4 += h0 * r4^4   (finish)
    vpaddq  YH0, YB0, YH0                              // h0 += h1 * s4^4   (finish)

    // reduction
    vpsrlq      $26, YH3, YB3
    vpand       YMASK, YH3, YH3
    vpaddq      YB3, YH4, YH4                          // h3 -> h4
    vpsrlq      $26, YH0, YB0
    vpand       YMASK, YH0, YH0
    vpaddq      YB0, YB1, YH1                          // h0 -> h1
    vpsrlq      $26, YH4, YB4
    vpand       YMASK, YH4, YH4
    vpsrlq      $4, YT3, YT2
    vpsrlq      $26, YH1, YB1
    vpand       YMASK, YH1, YH1
    vpaddq      YB1, YH2, YH2                          // h1 -> h2
    vpaddq      YB4, YH0, YH0
    vpsllq      $2, YB4, YB4
    vpaddq      YB4, YH0, YH0                          // h4 -> h0
    vpand       YMASK, YT2, YT2
    vpsrlq      $26, YT0, YT1
    vpsrlq      $26, YH2, YB2
    vpand       YMASK, YH2, YH2
    vpaddq      YB2, YH3, YH3                          // h2 -> h3
    vpaddq      YT2, YH2, YH2                          // prepare next 4 block
    vpsrlq      $30, YT3, YT3
    vpsrlq      $26, YH0, YB0
    vpand       YMASK, YH0, YH0
    vpaddq      YB0, YH1, YH1                          // h0 -> h1
    vpsrlq      $40, YT4, YT4
    vpsrlq      $26, YH3, YB3
    vpand       YMASK, YH3, YH3
    vpaddq      YB3, YH4, YH4                          // h3 -> h4

    vpand      YMASK, YT0, YT0                         // new input 0
    vpand      YMASK, YT1, YT1                         // new input 1
    vpand      YMASK, YT3, YT3                         // new input 3
    vpor       g_129(%rip), YT4, YT4                   // new input 4, padbit

    subq $64, LEN
    jnz .Lblock_avx2_loop

.Lblock_avx2_tail:
    BLOCK4_AVX2_TAIL   YT0, YT1, YT2, YT3, YT4, YH0, YH1, YH2, YH3, YH4, YB0, YB1, YB2, YB3, YB4, YMASK, %rsp

    vmovd       %xmm0, -56(CTX)
    vmovd       %xmm1, -52(CTX)
    vmovd       %xmm2, -48(CTX)
    vmovd       %xmm3, -44(CTX)
    vmovd       %xmm4, -40(CTX)
    vzeroupper
    leaq     8(%r11), %rsp
    pop %r15
    pop %r14
    pop %rbp
    pop %rbx
    movq LEN, %rax
    ret
.cfi_endproc
.size  Poly1305BlockAVX2, .-Poly1305BlockAVX2

 /**
 *  Function description: This function is used to clear residual sensitive information in a register.
 *  Function prototype: void Poly1305CleanRegister();
 */
.globl  Poly1305CleanRegister
.type   Poly1305CleanRegister, @function
Poly1305CleanRegister:
.cfi_startproc
    vzeroall
    ret
.cfi_endproc
.size  Poly1305CleanRegister, .-Poly1305CleanRegister

#endif
