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

#include "poly1305_x86_64_macro.s"

.file   "poly1305_x86_64.S"
.text

/**
 *  Function description: Initializes the pre-computation table and clears the flag.
 *  Function prototype: void Poly1305InitForAsm(Poly1305_Ctx *ctx);
 *  Input register:
 *         CTX: address of the Poly305_Ctx structure
 *  Modify the register： rax, rdx, rbx, rbp, r8, r9, r11-r14.
 *  Output register: None
 *  Function/Macro Call: Poly1305_MOD_MUL
 */
.globl  Poly1305InitForAsm
.type   Poly1305InitForAsm, @function
.align  32
Poly1305InitForAsm:
.cfi_startproc
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14

    movl $0, 220(CTX)                                    // flag bit Clear
    movq 24(CTX), R0
    movq 32(CTX), R1
    movq R1, R2
    shrq $2, R2
    addq R1, R2
    lea 56(CTX), CTX
    movq R0, ACC1
    movq R1, ACC2
    xorq ACC3, ACC3

    movq R1, %rax
    POLY1305_MOD_MUL    ACC1, ACC2, ACC3, R0, R1, R2     // r^2
    movl $0x3ffffff, %eax
    movl $0x3ffffff, %edx
    movq ACC1, D1
    andl %r14d, %eax
    movq R0, D2
    andl %r11d, %edx
    movl %eax, (CTX)                                     // r0^2
    shrq $26, D1
    movl %edx, 4(CTX)                                    // r0
    shrq $26, D2
    movl $0x3ffffff, %eax
    movl $0x3ffffff, %edx
    andl %r8d, %eax
    andl %r9d, %edx
    movl %eax, 16(CTX)                                   // r1^2
    lea (%rax, %rax, 4), %eax
    movl %edx, 20(CTX)                                   // r1
    lea (%rdx, %rdx, 4), %edx
    movl %eax, 32(CTX)                                   // s1^2
    shrq $26, D1
    movl %edx, 36(CTX)                                   // s1
    shrq $26, D2

    movq ACC2, %rax
    movq R1, %rdx
    shlq $12, %rax
    shlq $12, %rdx
    orq  D1, %rax
    orq  D2, %rdx
    andl $0x3ffffff, %eax
    andl $0x3ffffff, %edx
    movl %eax, 48(CTX)                                  // r2^2
    lea (%rax, %rax, 4), %eax
    movl %edx, 52(CTX)                                  // r2
    lea (%rdx, %rdx, 4), %edx
    movl %eax, 64(CTX)                                  // s2^2
    movq ACC2, D1
    movl %edx, 68(CTX)                                  // s2
    movq R1, D2

    shrq $14, D1
    movl $0x3ffffff, %eax
    shrq $14, D2
    movl $0x3ffffff, %edx
    andl %r8d, %eax
    andl %r9d, %edx
    movl %eax, 80(CTX)                                  // r3^2
    lea (%rax, %rax, 4), %eax
    movl %edx, 84(CTX)                                  // r3
    lea (%rdx, %rdx, 4), %edx
    movl %eax, 96(CTX)                                  // s3^2
    shrq $26, D1
    movl %edx, 100(CTX)                                 // s3
    shrq $26, D2

    movq ACC3, %rax
    shlq $24, %rax
    orq  %rax, D1
    movl %r8d, 112(CTX)                                 // r4^2
    lea (D1, D1, 4), D1
    movl %r9d, 116(CTX)                                 // r4
    lea (D2, D2, 4), D2
    movl %r8d, 128(CTX)                                 // s4^2
    movl %r9d, 132(CTX)                                 // s4

    movq R1, %rax
    POLY1305_MOD_MUL    ACC1, ACC2, ACC3, R0, R1, R2    // r^3
    movq ACC1, D1
    movl $0x3ffffff, %edx
    andl %r8d, %edx
    movl %edx, 12(CTX)                                  // r0^3
    shrq $26, D1
    movl $0x3ffffff, %edx
    andl %r8d, %edx
    movl %edx, 28(CTX)                                  // r1^3
    lea (%rdx, %rdx, 4), %edx
    shrq $26, D1
    movl %edx, 44(CTX)                                  // s1^3
    movq ACC2, %rax
    shlq $12, %rax
    orq  D1, %rax
    andl $0x3ffffff, %eax
    movl %eax, 60(CTX)                                  // r2^3
    lea (%rax, %rax, 4), %eax
    movq ACC2, D1
    movl %eax, 76(CTX)                                  // s2^3
    shrq $14, D1
    movl $0x3ffffff, %eax
    andl %r8d, %eax
    movl %eax, 92(CTX)                                  // r3^3
    lea (%rax, %rax, 4), %eax
    shrq $26, D1
    movl %eax, 108(CTX)                                 // s3^3
    movq ACC3, %rdx
    shlq $24, %rdx
    orq  %rdx, D1
    movl %r8d, 124(CTX)                                 // r4^3
    lea (D1, D1, 4), D1
    movl %r8d, 140(CTX)                                 // s4^3

    movq R1, %rax
    POLY1305_MOD_MUL    ACC1, ACC2, ACC3, R0, R1, R2    // r^4
    movq ACC1, D1
    movl $0x3ffffff, %edx
    andl %r8d, %edx
    movl %edx, 8(CTX)                                   // r0^4
    shrq $26, D1
    movl $0x3ffffff, %edx
    andl %r8d, %edx
    movl %edx, 24(CTX)                                  // r1^4
    lea (%rdx, %rdx, 4), %edx
    shrq $26, D1
    movl %edx, 40(CTX)                                  // s1^4
    movq ACC2, %rax
    shlq $12, %rax
    orq  D1, %rax
    andl $0x3ffffff, %eax
    movl %eax, 56(CTX)                                  // r2^4
    lea (%rax, %rax, 4), %eax
    movq ACC2, D1
    movl %eax, 72(CTX)                                  // s2^4
    shrq $14, D1
    movl $0x3ffffff, %eax
    andl %r8d, %eax
    movl %eax, 88(CTX)                                  // r3^4
    lea (%rax, %rax, 4), %eax
    shrq $26, D1
    movl %eax, 104(CTX)                                 // s3^4
    movq ACC3, %rdx
    shlq $24, %rdx
    orq  %rdx, D1
    movl %r8d, 120(CTX)                                 // r4^4
    lea (D1, D1, 4), D1
    movl %r8d, 136(CTX)                                 // s4^4

    lea -56(CTX), CTX
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
.cfi_endproc
.size  Poly1305InitForAsm, .-Poly1305InitForAsm

/**
 *  Function description: x86_64 poly1305 64-bit basic instruction implementation
 *  Input register:
 *      CTX: address of the Poly305_Ctx structure
 *      INP: data pointer
 *      LEN: data length
 *      PADBIT: padding data
 *  Change register: r8-r15, rax, rbx, rdx, rbp
 *  Output register:
 *        rax: length of the remaining data to be processed
 *  Macro invoking:Poly1305_MOD_MUL
 */
.globl  Poly1305Block64Bit
.type   Poly1305Block64Bit, @function
Poly1305Block64Bit:
.cfi_startproc
.align  32
.Lblock_start:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    movq LEN, %r15
    LOAD_ACC_R  CTX, R0, R1, R2, ACC1, ACC2, ACC3, %r8d, %rax
    test %r8d, %r8d
    jz  .Lblock64_loop

    CONVERT_26TO64_PRE  ACC1, ACC2, D1, D2, D3
    CONVERT_26TO64 ACC1, D1, ACC2, D2, D3, ACC3
    movl $0, 220(CTX)

.align 32
.Lblock64_loop:

    addq (INP), ACC1
    adcq 8(INP), ACC2
    adcq PADBIT, ACC3
    lea 16(INP), INP

    POLY1305_MOD_MUL ACC1, ACC2, ACC3, R0, R1, R2

    subq $16, %r15
    movq R1, %rax
    jnz .Lblock64_loop

    movq ACC1, (CTX)
    movq ACC2, 8(CTX)
    movq ACC3, 16(CTX)
    movq %r15, %rax

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
.cfi_endproc
.size  Poly1305Block64Bit, .-Poly1305Block64Bit

/**
 *  Function description: Calculates (acc + s) mod 2^128 and outputs the final result to the specified memory.
 *  Function prototype: void Poly1305Last(Poly1305_Ctx *ctx, uint8_t mac[POLY1305_TAGSIZE]);
 *  Input register:
 *         rdi: address of the Poly305_Ctx structure
 *         rsi: pointer to the output buffer
 *  Modify the register: rax, rcx, r14, rbx, rbp, r8-r10.
 *  Output register: None
 *  Function/Macro Call:
 *         CONVERT_26TO64
 */
.globl  Poly1305Last
.type   Poly1305Last, @function
.align  32
Poly1305Last:
.cfi_startproc
    push %rbx
    push %rbp
    push %r14
    movl 220(CTX), %r8d
    movq (CTX), ACC1
    movq 8(CTX), ACC2
    movq 16(CTX), ACC3

    test %r8d, %r8d
    jz  .Lblock_last_body
    CONVERT_26TO64_PRE  ACC1, ACC2, D1, D2, D3
    CONVERT_26TO64 ACC1, D1, ACC2, D2, D3, ACC3
    movl $0, 220(CTX)

.Lblock_last_body:
    movq ACC1, %rax
    addq $5, ACC1
    movq ACC2, %rcx
    adcq $0, ACC2
    adcq $0, ACC3
    shrq $2, ACC3
    cmovnz  ACC1, %rax
    cmovnz  ACC2, %rcx

    addq 40(CTX), %rax
    adcq 48(CTX), %rcx
    movq %rax, (%rsi)
    movq %rcx, 8(%rsi)

    pop %r14
    pop %rbp
    pop %rbx
    ret
.cfi_endproc
.size  Poly1305Last, .-Poly1305Last

#endif
