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

.file   "poly1305_x86_64_macro.s"
.text

.align   32
g_129:
    .long    1<<24, 0, 1<<24, 0, 1<<24, 0, 1<<24, 0
.size    g_129, .-g_129
.align   32
g_mask26:
    .long    0x3ffffff, 0, 0x3ffffff, 0, 0x3ffffff, 0, 0x3ffffff, 0
.size    g_mask26, .-g_mask26
.align   32
g_permd_avx2:
    .long    2, 2, 2, 3, 2, 0, 2, 1
.size   g_permd_avx2, .-g_permd_avx2

.set    CTX, %rdi
.set    INP, %rsi
.set    LEN, %rdx
.set    PADBIT, %rcx

.set    ACC1, %r14
.set    ACC2, %rbx
.set    ACC3, %rbp
.set    D1, %r8
.set    D2, %r9
.set    D3, %r10
.set    R0, %r11
.set    R1, %r12
.set    R2, %r13

.set    YH0, %ymm0
.set    YH1, %ymm1
.set    YH2, %ymm2
.set    YH3, %ymm3
.set    YH4, %ymm4
.set    YT0, %ymm5
.set    YT1, %ymm6
.set    YT2, %ymm7
.set    YT3, %ymm8
.set    YT4, %ymm9
.set    YMASK, %ymm10
.set    YB0, %ymm11
.set    YB1, %ymm12
.set    YB2, %ymm13
.set    YB3, %ymm14
.set    YB4, %ymm15

/**
 *  Macro description: x86_64 poly1305 big number multiplication modulo basic instruction implementation (acc1|acc2|acc3) = (acc1|acc2|acc3) * (r0|r1) mod P
 *  Input register:
 *        acc1-3: accumulator
 *        r0-1: key r
 *        r2: r1 + (r1 >> 2)
 *  Change register: r8-r14, rbx, rbp, rax
 *  Output register:
 *        acc1-3: result of the one block operation
 */
.macro POLY1305_MOD_MUL acc1 acc2 acc3 r0 r1 r2
    mulq \acc1                           // acc1 * r1
    movq %rax, D2
    movq \r0, %rax
    movq %rdx, D3

    mulq \acc1                           // acc1 * r0
    movq %rax, \acc1
    movq \r0, %rax
    movq %rdx, D1

    mulq \acc2                           // acc2 * r0
    addq %rax, D2
    movq \r2, %rax
    adcq %rdx, D3

    mulq \acc2                           // acc2 * (r1 + (r1 >> 2))
    movq \acc3, \acc2
    addq %rax, \acc1
    adcq %rdx, D1

    imulq   \r2, \acc2                   // acc3 * (r1 + (r1 >> 2))
    addq \acc2, D2
    movq D1, \acc2
    adcq $0, D3

    imulq   \r0, \acc3                   // acc3 * r0
    mov $-4, %rax
    addq D2, \acc2
    adcq \acc3, D3

    andq D3, %rax                        // reduction
    movq D3, \acc3
    shrq $2, D3
    andq $3, \acc3
    addq D3, %rax
    addq %rax, \acc1
    adcq $0, \acc2
    adcq $0, \acc3
.endm

/**
 *  Macro description: converts 130-bit base2^26 data into base 2^64 data.
 *  Input register:
 *        a1: large data block 0 in the original format
 *        d1: large data block 1 in the original format
 *        a2: large data block 2 in the original format
 *        d2: large data block 3 in the original format
 *        r2: big number of data blocks 2 and 3 in the original format
 *        a3: large data block 4 in the original format
 *  Modify the register r8, r9, r13, r14, rbx, rbp.
 *  Output register:
 *       a1: bits 0 to 63 of the converted big number
 *       a2: 64-127 bits of the converted big number
 *       a3: 128-130 bits of the converted big number
 * Function/Macro Call: None
 */
.macro CONVERT_26TO64    a1 d1 a2 d2 r2 a3
    shrq $6, \d1
    shlq $52, \r2
    shrq $12, \a2
    addq \d1, \a1
    shrq $18, \d2
    addq \r2, \a1                              // 1st 64bit

    adcq \d2, \a2
    movq \a3, \d1
    shlq $40, \d1
    shrq $24, \a3
    addq \d1, \a2                              // 2nd 64bit
    adcq $0, \a3                               // 3rd 64bit
.endm

/**
 *  Macro description: converts 130-bit base2^64 data to base 2^26 data.
 *  Input register:
 *        a1: large data block 0 in the original format
 *        a2: large data block 1 in the original format
 *        a3: large data block 2 in the original format
 *  Modify the register: r8, r9, r14, rax, rdx, rbp, rbx.
 *  Output register:
 *       a4: 0 to 25 digits of the converted big number
 *       a5: 26 to 51 digits of the converted big number
 *       a1: 52 to 77 digits of the converted big number
 *       a2: 78 to 103 bits of the converted big number
 *       a3: 104-130 bits of the converted big number
 *  Function/Macro Call: None
 */
.macro CONVERT_64TO26    a1 a2 a3 a4 a5
    movq \a1, \a4
    movq \a1, \a5
    andq $0x3ffffff, \a4                        // 1st 26bit
    shrq $26, \a5
    movd \a4, %xmm0
    andq $0x3ffffff, \a5                        // 2nd 26bit
    shrq $52, \a1
    movd \a5, %xmm1
    movq \a2, D1
    movq \a2, D2
    shlq $12, D1
    orq  D1, \a1
    andq $0x3ffffff, \a1                        // 3rd 26bit
    shrq $14, \a2
    movd \a1, %xmm2
    shlq $24, \a3
    andq $0x3ffffff, \a2                        // 4th 26bit
    shrq $40, D2
    movd \a2, %xmm3
    orq  D2, \a3                                // 5th 26bit
    movl $1, 220(CTX)
    movd \a3, %xmm4

.endm

/**
 *  Macro description: preprocessing of converting base2^26 data to base 2^64
 *  Input register: 128 bits of acc1 and acc2 data
 *  Change register: r8-r10, r14, and rbx.
 *  Output register: acc1, acc2, d1, d2, d3
 */
.macro CONVERT_26TO64_PRE   acc1 acc2 d1 d2 d3
    movq $0xffffffff, \d3                       // base2_26 --> base2_64
    movq \acc1, \d1
    movq \acc2, \d2
    andq \d3, \acc1
    andq \d3, \acc2
    andq $-1*(1<<31), \d1
    movq \d2, \d3
    andq $-1*(1<<31), \d2
.endm

/**
 *  Macro description: load accumulator data and key r
 *  Input register: in_ctx context
 *  Modify the register: r8, r11-r14, rax, rbp, rbx.
 *  Output register:
 *      r0 - r2: key r
 *      acc1 - acc3: accumulator data
 *      flag: indicates the data organization flag of the current accumulator.
 *      mul: r1
 */
.macro LOAD_ACC_R   inctx r0 r1 r2 acc1 acc2 acc3 flag mul
    movq 24(\inctx), \r0                        // load r
    movq 32(\inctx), \r1
    movl 220(\inctx), \flag                     // judge the ACC organization form.
    movq \r1, \r2
    movq (\inctx), \acc1                        // load acc
    shrq $2, \r2
    movq 8(\inctx), \acc2
    addq \r1, \r2                               // R2 = R1 + (R1 >> 2)
    movq 16(\inctx), \acc3
    movq \r1, \mul
.endm

/**
 *  Macro description: The avx2 instruction set implements parallel operation of the last four blocks.
 *  Input register:
 *      yh0 - yh4: stores messages.
 *      yt0 - yt4: stores keys.
 *      yb0 - yb4: temporary storage of intermediate results
 *      addr: stack address
 *  Output register:
 *      yh0 - yh4: store operation results.
 */
.macro BLOCK4_AVX2_TAIL   yt0 yt1 yt2 yt3 yt4 yh0 yh1 yh2 yh3 yh4 yb0 yb1 yb2 yb3 yb4 ymask addr
    vpaddq      \yt0, \yh0, \yh0
    vpaddq      \yt1, \yh1, \yh1
    vpaddq      \yt3, \yh3, \yh3
    vpaddq      \yt4, \yh4, \yh4
    vmovdqu     0x4(\addr), \yt0                          // r0^i
    vmovdqu     0x24(\addr), \yt1                         // r1^i
    vmovdqu     0x64(\addr), \yt2                         // r2^i
    vmovdqu     0xc4(\addr), \yt3                         // s3^i
    vmovdqu     0x104(\addr), \ymask                      // s4^i

    vpmuludq    \yh2, \yt0, \yb2                          // b2 = h2 * r0^i
    vpmuludq    \yh2, \yt1, \yb3                          // b3 = h2 * r1^i
    vpmuludq    \yh2, \yt2, \yb4                          // b4 = h2 * r2^i
    vpmuludq    \yh2, \yt3, \yb0                          // b0 = h2 * s3^i
    vpmuludq    \yh2, \ymask, \yb1                        // b1 = h2 * s4^i

    vpmuludq    \yh1, \yt1, \yt4                          // h1 * r1^i
    vpmuludq    \yh0, \yt1, \yh2                          // h0 * r1^i
    vpaddq      \yt4, \yb2, \yb2                          // b2 += h1 * r1^i
    vpaddq      \yh2, \yb1, \yb1                          // b1 += h0 * r1^i
    vpmuludq    \yh3, \yt1, \yt4                          // h3 * r1^i
    vpmuludq    0x44(\addr), \yh4, \yh2                   // h4 * s1^i
    vpaddq      \yt4, \yb4, \yb4                          // b4 += h3 * r1^i
    vpaddq      \yh2, \yb0, \yb0                          // b0 += h4 * s1^i
    vmovdqu     0x84(\addr), \yt1                         // load s2^i

    vpmuludq    \yh4, \yt0, \yt4                          // h4 * r0^i
    vpmuludq    \yh3, \yt0, \yh2                          // h3 * r0^i
    vpaddq      \yt4, \yb4, \yb4                          // b4 += h4 * r0^i
    vpaddq      \yh2, \yb3, \yb3                          // b3 += h3 * r0^i
    vpmuludq    \yh0, \yt0, \yt4                          // h0 * r0^i
    vpmuludq    \yh1, \yt0, \yh2                          // h1 * r0^i
    vpaddq      \yt4, \yb0, \yb0                          // b0 += h0 * r0^i
    vpaddq      \yh2, \yb1, \yb1                          // b1 += h1 * r0^i

    vpmuludq    \yh1, \yt2, \yt4                          // h1 * r2^i
    vpmuludq    \yh0, \yt2, \yh2                          // h0 * r2^i
    vpaddq      \yt4, \yb3, \yb3                          // b3 += h1 * r2^i
    vpaddq      \yh2, \yb2, \yb2                          // b2 += h0 * r2^i
    vpmuludq    \yh4, \yt1, \yt4                          // h4 * s2^i
    vpmuludq    \yh3, \yt1, \yh2                          // h3 * s2^i
    vpaddq      \yt4, \yb1, \yb1                          // b1 += h4 * s2^i
    vpaddq      \yh2, \yb0, \yb0                          // b0 += h3 * s2^i
    vmovdqu     0xa4(\addr), \yh2                         // load r3^i

    vpmuludq    \yh1, \yh2, \yt4                          // h1 * r3^i
    vpmuludq    \yh0, \yh2, \yh2                          // h0 * r3^i
    vpaddq      \yt4, \yb4, \yb4                          // b4 += h1 * r3^i
    vpaddq      \yh2, \yb3, \yb3                          // b3 += h0 * r3^i
    vpmuludq    \yh4, \yt3, \yt4                          // h4 * s3^i
    vpmuludq    \yh3, \yt3, \yh2                          // h3 * s3^i
    vpaddq      \yt4, \yb2, \yb2                          // b2 += h4 * s3^i
    vpaddq      \yh2, \yb1, \yb1                          // b1 += h3 * s3^i   (finish)

    vpmuludq    \yh3, \ymask, \yh3                        // h3 * s4^i
    vpmuludq    \yh4, \ymask, \yh4                        // h4 * s4^i
    vpaddq  \yb2, \yh3, \yh2                              // h2 += h3 * s4^i   (finish)
    vpaddq  \yb3, \yh4, \yh3                              // h3 += h4 * s4^i   (finish)
    vpmuludq    0xe4(\addr), \yh0, \yh4                   // h0 * r4^i
    vpmuludq    \yh1, \ymask, \yh0                        // h1 * s4^i
    vmovdqu     g_mask26(%rip), \ymask
    vpaddq  \yh4, \yb4, \yh4                              // h4 += h0 * r4^i   (finish)
    vpaddq  \yh0, \yb0, \yh0                              // h0 += h1 * s4^i   (finish)

    // Summary of calculation results of different blocks
    vpsrldq     $8, \yh0, \yt0
    vpsrldq     $8, \yb1, \yt1
    vpaddq      \yt0, \yh0, \yh0
    vpsrldq     $8, \yh2, \yt2
    vpaddq      \yt1, \yb1, \yb1
    vpsrldq     $8, \yh3, \yt3
    vpaddq      \yt2, \yh2, \yh2
    vpsrldq     $8, \yh4, \yt4
    vpaddq      \yt3, \yh3, \yh3
    vpaddq      \yt4, \yh4, \yh4

    vpermq      $0x2, \yh0, \yt0
    vpermq      $0x2, \yb1, \yt1
    vpaddq      \yt0, \yh0, \yh0
    vpermq      $0x2, \yh2, \yt2
    vpaddq      \yt1, \yb1, \yb1
    vpermq      $0x2, \yh3, \yt3
    vpaddq      \yt2, \yh2, \yh2
    vpermq      $0x2, \yh4, \yt4
    vpaddq      \yt3, \yh3, \yh3
    vpaddq      \yt4, \yh4, \yh4

    // reduction
    vpsrlq      $26, \yh3, \yb3
    vpand       \ymask, \yh3, \yh3
    vpaddq      \yb3, \yh4, \yh4                          // h3 -> h4
    vpsrlq      $26, \yh0, \yb0
    vpand       \ymask, \yh0, \yh0
    vpaddq      \yb0, \yb1, \yh1                          // h0 -> h1
    vpsrlq      $26, \yh4, \yb4
    vpand       \ymask, \yh4, \yh4
    vpsrlq      $26, \yh1, \yb1
    vpand       \ymask, \yh1, \yh1
    vpaddq      \yb1, \yh2, \yh2                          // h1 -> h2
    vpaddq      \yb4, \yh0, \yh0
    vpsllq      $2, \yb4, \yb4
    vpaddq      \yb4, \yh0, \yh0                          // h4 -> h0
    vpsrlq      $26, \yh2, \yb2
    vpand       \ymask, \yh2, \yh2
    vpaddq      \yb2, \yh3, \yh3                          // h2 -> h3
    vpsrlq      $26, \yh0, \yb0
    vpand       \ymask, \yh0, \yh0
    vpaddq      \yb0, \yh1, \yh1                          // h0 -> h1
    vpsrlq      $26, \yh3, \yb3
    vpand       \ymask, \yh3, \yh3
    vpaddq      \yb3, \yh4, \yh4                          // h3 -> h4
.endm

#endif
