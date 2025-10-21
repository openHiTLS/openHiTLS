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
#if defined(HITLS_CRYPTO_CURVE_NISTP256) && defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE)

#include "ecp256_pre_comp_table.s"

.data
.align	64
.Lpoly:         // P
.quad   0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001
.LrrModP:       // Indicates the calculated value of R * R mod p, which is used in montgomery modular multiplication.
.quad   0x0000000000000003, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x00000004fffffffd
.Lone_mont:     // R mod P, R = 2^256, = 2^256 - P
.quad   0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe
.Lord:          // order, n
.quad   0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000
.LordK:         // (2^64 - ord[0]) * ordK = 1 (mod 2^64)) LordK = -(ord[0])^(-1) (mod 2^64)  LordK * Lord,
                // The lower 64 bits are all Fs.
.quad   0xccd1c8aaee00bc4f
.LOne:
.quad   0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000

.text
/**
 * Function description: Returns the address of the field calculation table of the ECP256 field.
 * Function prototype: const ECP256_TableRow *ECP256_GetPreCompTable(void);
 * Input register: None
 * Change register: None
 * Output register: rax
 * Function/Macro Call: None
 */
.globl  ECP256_GetPreCompTable
.type   ECP256_GetPreCompTable,@function
.align 32
ECP256_GetPreCompTable:
.cfi_startproc

    leaq    g_preCompTable(%rip), %rax

    ret
.cfi_endproc
.size   ECP256_GetPreCompTable, .-ECP256_GetPreCompTable

/**
 * Function description: Addition core part of the ECP256 field, a + b mod P; Outputs r8-r11, r14,15 are P[1] and P[3]
 * Input register:
 *        r8-r11:256-bit input data a
 *        rdx: points to the input 256-bit data b.
 *        r14:P[1]
 *        r15:P[3]
 * Change register: rdx, rcx, rax, r8, r9, r10, r11, r12, r13
 * Output register: r8-r11
 */
.type   ECP256_AddCore,@function
.align 32
ECP256_AddCore:
.cfi_startproc
    xorq    %r13, %r13
    addq    (%rdx), %r8         // Addition result.
    adcq    8(%rdx), %r9
    movq    %r8, %rax
    adcq    16(%rdx), %r10
    adcq    24(%rdx), %r11
    movq    %r9, %rcx
    adcq    $0, %r13            // Save carry value to r13.

    subq    $-1, %r8            // Mod P.
    movq    %r10, %rdx
    sbbq    %r14, %r9
    sbbq    $0, %r10
    movq    %r11, %r12
    sbbq    %r15, %r11
    sbbq    $0, %r13

    cmovcq  %rax, %r8           // Obtain mod P result.
    cmovcq  %rcx, %r9
    movq    %r8, (%rdi)
    cmovcq  %rdx, %r10
    movq    %r9, 8(%rdi)
    cmovcq  %r12, %r11
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)
    ret
.cfi_endproc
.size   ECP256_AddCore, .-ECP256_AddCore

/**
 * Function description: subtraction core part of the ECP256 field, a-b mod P; no writeback
 * Input register:
 *        r8-r11:256-bit input data a
 *        rdx:Points to the input 256-bit data b.
 *        r14:P[1]
 *        r15:P[3]
 * Change register: rdx, rcx, rax, r8, r9, r10, r11, r12, r13
 * Output register: r8-r11
 */
.type   ECP256_SubCore,@function
.align 32
ECP256_SubCore:
.cfi_startproc
    xorq    %r13, %r13
    subq    (%rdx), %r8         // Subtraction results.
    sbbq    8(%rdx), %r9
    movq    %r8, %rax           // Save Results.
    sbbq    16(%rdx), %r10
    sbbq    24(%rdx), %r11
    movq    %r9, %rcx
    sbbq    $0, %r13            // Borrowing saved in r13.

    addq    $-1, %r8            // a - b + P
    movq    %r10, %rdx
    adcq    %r14, %r9
    adcq    $0, %r10
    movq    %r11, %r12
    adcq    %r15, %r11
    testq   %r13, %r13

    cmovzq  %rax, %r8           // If r13 is equal to 0, a-b is used. Otherwise, a-b+P is used.
    cmovzq  %rcx, %r9
    cmovzq  %rdx, %r10
    cmovzq  %r12, %r11

    ret
.cfi_endproc
.size   ECP256_SubCore, .-ECP256_SubCore

/**
 * Function description: negation of the ECP256 field. res = -a mod P
 * Function prototype: void ECP256_Neg(Coord *r, const Coord *a);
 * Input register:
 *       rdi: Pointer to the output Coord structure
 *       rsi: Address pointing to input data a
 * Change register: rsi, rdx, rcx, rax, r8, r9, r10, r11, r12, r13
 * Output register: None
 * Function/Macro Call:
 */
.globl  ECP256_Neg
.type   ECP256_Neg,@function
.align 32
ECP256_Neg:
.cfi_startproc
    pushq   %r12
    pushq   %r13

    xorq    %r8, %r8                    // -a = 0 - a
    xorq    %r9, %r9
    xorq    %r13, %r13
    leaq    .Lpoly(%rip), %rdx
    xorq    %r10, %r10
    xorq    %r11, %r11

    subq    (%rsi),%r8
    sbbq    8(%rsi),%r9
    movq    %r8, %rax
    sbbq    16(%rsi),%r10
    sbbq    24(%rsi),%r11
    movq    %r9, %rcx
    sbbq    $0, %r13

    addq    $-1, %r8
    movq    %r10, %rsi
    adcq    8(%rdx), %r9
    adcq    $0, %r10
    movq    %r11, %r12
    adcq    24(%rdx), %r11
    testq   %r13, %r13                  // Choost result

    cmovzq  %rax, %r8
    cmovzq  %rcx, %r9
    movq    %r8, (%rdi)
    cmovzq  %rsi, %r10
    movq    %r9, 8(%rdi)
    cmovzq  %r12, %r11
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    movq    (%rsp), %r13
    movq    8(%rsp), %r12
    leaq    16(%rsp), %rsp
    ret
.cfi_endproc
.size   ECP256_Neg, .-ECP256_Neg

/**
 *  Function description: multiplication of the ECP256 field: res = a * b * 2^-256 mod P
 *  Function prototype: void ECP256_Mul(Coord *r, const Coord *a, const Coord *b);
 *  Input register:
 *        rdi: Pointer to the output Coord structure
 *        rsi: Address pointing to input data a
 *        rdx: Address pointing to input data b
 *  Change register: rax, rbx, rcx, rdx, rbp, r8, r9, r10, r11, r12, r13, r14, r15
 *  Output register: None
 *  Function/macro call: Multiplication can be implemented by calling ECP256_MulCore.
 */
.globl  ECP256_Mul
.type   ECP256_Mul,@function
.align 32
ECP256_Mul:
.cfi_startproc
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    movq    %rdx, %rcx                      // rdx is for mul
    movq	.Lpoly+8(%rip), %r14
    movq	.Lpoly+24(%rip), %r15
    call    ECP256_MulCore_q

    movq    (%rsp), %r15
    movq    8(%rsp), %r14
    movq    16(%rsp), %r13
    movq    24(%rsp), %r12
    movq    32(%rsp), %rbp
    movq    40(%rsp), %rbx
    leaq    48(%rsp), %rsp
    ret
.cfi_endproc
.size   ECP256_Mul, .-ECP256_Mul

/**
 *  Function description: Montgomery multiplication of the ECP256 field
 *  Input register:
 *       rdi: Return address.
 *       rsi: Factor address.
 *       rcx: Factor address.
 *  Change register: rax,rbx,rcx,rdx,rbp,r8-r13
 *  Output register: None.
 */
.type   ECP256_MulCore_q,@function
.align 32
ECP256_MulCore_q:
.cfi_startproc
    movq    (%rcx), %rax                    // b[0]

    movq    %rax, %rbp                      // save b[0]
    mulq    (%rsi)                          // a[0] * b[0]
    movq    %rax, %r10
    movq    %rbp, %rax                      // b[0]
    movq    %rdx, %r11

    mulq    8(%rsi)                         // a[1] * b[0]
    addq    %rax, %r11
    movq    %rbp, %rax
    adcq    $0, %rdx                        // a[1:0] * b[0] < 2^192, no overflow
    movq    %rdx, %r12

    mulq    16(%rsi)                        // a[2] * b[0]
    addq    %rax, %r12
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %r13

    mulq    24(%rsi)                        // a[3] * b[0]
    addq    %rax, %r13
    adcq    $0, %rdx
    movq    %rdx, %r8                       // result: r8 r13 r12 r11 r10
    xorq    %r9, %r9
    movq    %r10, %rax                      // first reduction
    movq    %r10, %rbp
    shlq    $32, %r10                       // r10 * 2^96 low
    mulq    %r15                            // r10 * 0xffffffff00000001
    shrq    $32, %rbp                       // r10 * 2^96 high
    addq    %r10, %r11
    adcq    %rbp, %r12
    adcq    %rax, %r13
    adcq    %rdx, %r8
    movq    8(%rcx), %rax
    adcq    $0, %r9
    xorq    %r10, %r10
    movq    %rax, %rbp

    mulq    (%rsi)
    addq    %rax, %r11
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    8(%rsi)
    addq    %rbx, %r12
    adcq    $0, %rdx
    addq    %rax, %r12
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    16(%rsi)
    addq    %rbx, %r13
    adcq    $0, %rdx
    addq    %rax, %r13
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    24(%rsi)
    addq    %rbx, %r8
    adcq    $0, %rdx
    addq    %rax, %r8
    adcq    %rdx, %r9
    adcq    $0, %r10

    movq    %r11, %rbp
    movq    %r11, %rax
    shlq    $32, %r11                       // r11 * 2^96 low
    mulq    %r15                            // r11 * 0xffffffff00000001
    shrq    $32, %rbp                       // r11 * 2^96 high
    addq    %r11, %r12
    adcq    %rbp, %r13
    movq    16(%rcx), %rbp
    adcq    %rax, %r8
    adcq    %rdx, %r9
    movq    %rbp, %rax
    adcq    $0, %r10
    xorq    %r11, %r11

    mulq    (%rsi)                          // a[0] * b[2]
    addq    %rax, %r12
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    8(%rsi)
    addq    %rbx, %r13
    adcq    $0, %rdx
    addq    %rax, %r13
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rbx

    mulq    16(%rsi)
    addq    %rbx, %r8
    adcq    $0, %rdx
    addq    %rax, %r8
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rbx

    mulq    24(%rsi)
    addq    %rbx, %r9
    adcq    $0, %rdx
    addq    %rax, %r9
    adcq    %rdx, %r10
    movq    %r12, %rbp
    adcq    $0, %r11

    movq    %r12, %rax                      // third reduction
    shlq    $32, %r12                       // r12 * 2^96 low
    mulq    %r15                            // r12 * 0xffffffff00000001
    shrq    $32, %rbp                       // r12 * 2^96 high
    addq    %r12, %r13
    adcq    %rbp, %r8
    movq    24(%rcx), %rbp
    adcq    %rax, %r9
    adcq    %rdx, %r10
    movq    %rbp, %rax
    adcq    $0, %r11
    xorq    %r12, %r12

    mulq    (%rsi)                          // a[0] * b[3]
    addq    %rax, %r13
    adcq    $0, %rdx
    movq    %rdx, %rbx

    movq    %rbp, %rax
    mulq    8(%rsi)
    addq    %rbx, %r8
    adcq    $0, %rdx
    addq    %rax, %r8
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    16(%rsi)
    addq    %rbx, %r9
    adcq    $0, %rdx
    addq    %rax, %r9
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rbx

    mulq    24(%rsi)
    addq    %rbx, %r10
    adcq    $0, %rdx
    addq    %rax, %r10
    adcq    %rdx, %r11
    adcq    $0, %r12

    movq    %r13, %rbp
    movq    %r13, %rax                      // last reduction
    shlq    $32, %r13                       // r13 * 2^96 low
    mulq    %r15                            // r13 * 0xffffffff00000001
    shrq    $32, %rbp                       // r13 * 2^96 high

    addq    %r13, %r8
    adcq    %rbp, %r9
    adcq    %rax, %r10
    adcq    %rdx, %r11
    movq    %r8, %rbx
    movq    %r9, %rbp
    adcq    $0, %r12
    movq    %r10, %rax
    movq    %r11, %rdx
    subq    $-1, %r8
    sbbq    %r14, %r9
    sbbq    $0, %r10
    sbbq    %r15, %r11
    sbbq    $0, %r12

    cmovcq  %rbx, %r8
    cmovcq  %rbp, %r9
    cmovcq  %rax, %r10
    movq    %r8, (%rdi)
    movq    %r9, 8(%rdi)
    cmovcq  %rdx, %r11
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    ret
.cfi_endproc
.size   ECP256_MulCore_q, .-ECP256_MulCore_q

/**
 *  Function description: ECP256 Montgomery form
 *  Function prototype: void ECP256_ToMont(Coord *r, const Coord *a);
 *  Input register:
 *        rdi: pointer to the output Coord structure
 *        rsi: address pointing to input data a
 *  Change register: rax,rbx,rcx,rdx,rbp,r8-r13
 *  Output register: None
 *  Function/Macro invoking: This function can be implemented by calling ECP256_Mul.
 */
.globl  ECP256_ToMont
.type   ECP256_ToMont,@function
.align 32
ECP256_ToMont:
.cfi_startproc
    leaq	.LrrModP(%rip),%rcx
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    movq	.Lpoly+8(%rip), %r14
    movq	.Lpoly+24(%rip), %r15
    call    ECP256_MulCore_q

    movq    (%rsp), %r15
    movq    8(%rsp), %r14
    movq    16(%rsp), %r13
    movq    24(%rsp), %r12
    movq    32(%rsp), %rbp
    movq    40(%rsp), %rbx
    leaq    48(%rsp), %rsp

    ret
.cfi_endproc
.size   ECP256_ToMont, .-ECP256_ToMont

/**
 * Function description: ECP256 Montgomery form converted to normal form
 * Function prototype: void ECP256_FromMont(Coord *r, const Coord *a);
 * Input register:
 *        rdi: Pointer to the output Coord structure.
 *        rsi: Address pointing to input data a.
 * Change register: rax,rcx,rdx,r8-r13
 * Output register: None.
 * Function/Macro Call:
 */
.globl  ECP256_FromMont
.type   ECP256_FromMont,@function
.align 32
ECP256_FromMont:
.cfi_startproc
    pushq   %r12
    pushq   %r13

    movq	.Lpoly+8(%rip), %r12
    movq	.Lpoly+24(%rip), %r13

    movq    (%rsi), %r8
    movq    8(%rsi), %r9
    movq    16(%rsi), %r10
    movq    24(%rsi), %r11

    movq    %r8, %rax
    movq    %r8, %rcx
    shlq    $32, %r8
    mulq    %r13                    // 0xff * 0xff = 0xfe01
    shrq    $32, %rcx
    addq    %r8, %r9
    adcq    %rcx, %r10
    movq    %r9, %rcx
    adcq    %rax, %r11
    adcq    $0, %rdx                // rdx + 1 <= 0xff
    movq    %r9, %rax
    movq    %rdx, %r8

    shlq    $32, %r9
    mulq    %r13
    shrq    $32, %rcx
    addq    %r9, %r10
    adcq    %rcx, %r11
    movq    %r10, %rcx
    adcq    %rax, %r8
    adcq    $0, %rdx
    movq    %r10, %rax
    movq    %rdx, %r9

    shlq    $32, %r10
    mulq    %r13
    shrq    $32, %rcx
    addq    %r10, %r11
    adcq    %rcx, %r8
    movq    %r11, %rcx
    adcq    %rax, %r9
    adcq    $0, %rdx
    movq    %r11, %rax
    movq    %rdx, %r10

    shlq    $32, %r11
    mulq    %r13
    shrq    $32, %rcx
    addq    %r11, %r8
    adcq    %rcx, %r9
    movq    %r8, %rsi
    adcq    %rax, %r10
    adcq    $0, %rdx
    movq    %rdx, %r11              // r8 r9 r10 r11

    movq    %r9, %rdx
    subq    $-1, %r8
    movq    %r10, %rcx
    sbbq    %r12, %r9
    movq    %r11, %rax
    sbbq    $0, %r10
    sbbq    %r13, %r11

    cmovcq  %rsi, %r8               // < P
    cmovcq  %rdx, %r9
    movq    %r8, (%rdi)
    cmovcq  %rcx, %r10
    movq    %r9, 8(%rdi)
    cmovcq  %rax, %r11
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    movq    (%rsp), %r13
    movq    8(%rsp), %r12
    leaq    16(%rsp), %rsp
    ret
.cfi_endproc
.size   ECP256_FromMont, .-ECP256_FromMont

/**
 *  Function description: Multiplication of the ECP256 field：res = a*b*2^-256 mod P
 *  Function prototype: void ECP256_Sqr(Coord *r, const Coord *a);
 *  Input register:
 *        rdi: pointer to the output Coord structure
 *        rsi: address pointing to input data a
 *  Change register: rax, rbx, rcx, rdx, rsi, rdi, rbp, r8, r9, r10, r11, r12, r13, r14, r15
 *  Output register: None
 *  Function/Macro Call: Multiplication can be implemented by calling ECP256_SqrCore_q.
 */
.globl  ECP256_Sqr
.type   ECP256_Sqr,@function
.align 32
ECP256_Sqr:
.cfi_startproc
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    nop                                 // add this instruction to improve performance, movq %rsi, %rdx is ok
    movq    (%rsi), %rax                // a[0]
    movq    8(%rsi), %r14               // a[1]
    movq    16(%rsi), %rbp              // a[2]
    movq    24(%rsi), %r15              // a[3]
    call    ECP256_SqrCore_q

    movq    (%rsp), %r15
    movq    8(%rsp), %r14
    movq    16(%rsp), %r13
    movq    24(%rsp), %r12
    movq    32(%rsp), %rbp
    movq    40(%rsp), %rbx
    leaq    48(%rsp), %rsp
    ret
.cfi_endproc
.size   ECP256_Sqr, .-ECP256_Sqr

/**
 * Function description: Montgomery square of the ECP256 field
 * Input register:
 *        rdi: Return address
 *        rsi: Factor address
 * Change register: rax, rbx, rcx, rdx, rbp, rsi, r8-r15
 * Output register: None
 */
.type   ECP256_SqrCore_q,@function
.align 32
ECP256_SqrCore_q:
.cfi_startproc
    movq    %rax, %r8
    mulq    %r14                        // rdx:rax = a[0] * a[1]
    xorq    %rcx, %rcx
    movq    %rax, %r9                   // r9 = rax
    xorq    %r11, %r11
    xorq    %r12, %r12
    movq    %r8, %rax
    xorq    %r13, %r13
    xorq    %rbx, %rbx
    movq    %rdx, %r10                  // r10:r9 = a[0] * a[1]

    mulq    %rbp                        // rdx:rax = a[0] * a[2]
    addq    %rax, %r10                  // r10 += rax
    movq    %r8, %rax                   // a[0] --> rax
    adcq    %rdx, %r11                  // a[0] * (a[2] * 2^64 + a[1]) < 2^196, no overflow

    mulq    %r15                        // rdx:rax = a[0] * a[3]
    addq    %rax, %r11                  // r11 += rax
    movq    %r14, %rax                  // a[0] --> rax
    adcq    %rdx, %r12                  // a[0] * (a[3] * 2^128 + a[2] * 2^64 + a[1]) < 2^256, no overflow

    mulq    %rbp                        // rdx:rax = a[1] * a[2]
    addq    %rax, %r11
    movq    %r14, %rax
    adcq    %rdx, %r12
    adcq    $0, %r13

    mulq    %r15                        // rdx:rax = a[1] * a[3]
    addq    %rax, %r12
    movq    %rbp, %rax
    adcq    %rdx, %r13
    adcq    $0, %rbx

    mulq    %r15                        // rdx:rax = a[2] * a[3]
    addq    %rax, %r13
    adcq    %rdx, %rbx                  // rbx not overflow

    movq    %r8, %rax
    addq    %r9, %r9                    // twice
    adcq    %r10, %r10
    adcq    %r11, %r11
    adcq    %r12, %r12
    adcq    %r13, %r13
    adcq    %rbx, %rbx
    adcq    $0, %rcx

    mulq    %rax                        // rdx:rax = a[0] * a[0]
    movq    %rax, %r8
    movq    %r14, %rax
    movq    %rdx, %rsi

    mulq    %rax                        // rdx:rax = a[1] * a[1]
    addq    %rsi, %r9
    adcq    %rax, %r10
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %rsi

    mulq    %rax                        // rdx:rax = a[2] * a[2]
    addq    %rsi, %r11
    adcq    %rax, %r12
    movq    %r15, %rax
    adcq    $0, %rdx
    movq    %rdx, %rsi

    mulq    %rax                        // rdx:rax = a[3] * a[3]
    addq    %rsi, %r13
    adcq    %rax, %rbx
    movq    %r8, %rax
    adcq    %rdx, %rcx                  // rcx not overflow

    movq	.Lpoly+8(%rip), %r14
    movq	.Lpoly+24(%rip), %r15
    movq    %r8, %rbp                   // First reduction
    shlq    $32, %r8                    // l32[r8 << 96]
    mulq    %r15
    shrq    $32, %rbp                   // h32[r8 << 96]
    addq    %r8, %r9
    adcq    %rbp, %r10
    adcq    %rax, %r11
    adcq    $0, %rdx
    movq    %r9, %rax
    movq    %r9, %rbp
    movq    %rdx, %r8                   // r8 r11 r10 r9 0

    shlq    $32, %r9                    // Second reduction
    mulq    %r15
    shrq    $32, %rbp
    addq    %r9, %r10
    adcq    %rbp, %r11
    adcq    %rax, %r8
    adcq    $0, %rdx
    movq    %r10, %rax
    movq    %r10, %rbp
    movq    %rdx, %r9                   // r9 r8 r11 r10 0

    shlq    $32, %r10                   // Third reduction
    mulq    %r15
    shrq    $32, %rbp
    addq    %r10, %r11
    adcq    %rbp, %r8
    adcq    %rax, %r9
    adcq    $0, %rdx
    movq    %r11, %rax
    movq    %r11, %rbp
    movq    %rdx, %r10                  // r10 r9 r8 r11 0

    shlq    $32, %r11                   // Last reduction
    mulq    %r15
    shrq    $32, %rbp
    addq    %r11, %r8
    adcq    %rbp, %r9
    adcq    %rax, %r10
    adcq    $0, %rdx                    // rdx r10 r9 r8 0

    xorq    %rsi, %rsi                  // Add the reduction result
    addq    %r8, %r12
    adcq    %r9, %r13
    movq    %r12, %r8
    adcq    %r10, %rbx
    adcq    %rdx, %rcx
    movq    %r13, %r9
    adcq    $0, %rsi                    // Reserve carry value

    subq    $-1, %r8
    movq    %rbx, %r10
    sbbq    %r14, %r9
    sbbq    $0, %r10
    movq    %rcx, %r11
    sbbq    %r15, %r11
    sbbq    $0, %rsi

    cmovcq  %r12, %r8
    cmovcq  %r13, %r9
    movq    %r8, (%rdi)
    cmovcq  %rbx, %r10
    movq    %r9, 8(%rdi)
    cmovcq  %rcx, %r11
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    ret
.cfi_endproc
.size   ECP256_SqrCore_q, .-ECP256_SqrCore_q

/**
 *  Function description: Multiplication of the ECP256 field: res = a*b*2^-256 mod Order(P)
 *  Function prototype: void ECP256_OrdSqr(Coord *r, const Coord *a, int32_t repeat);
 *  Input register:
 *        rdi: Pointer to the output Coord structure
 *        rsi: Address pointing to input data a
 *        rdx:Repeat
 *  Change register: rax, rbx, rcx, rdx, rsi, rbp, r8, r9, r10, r11, r12, r13, r14, r15
 *  Output register: None
 *  Function/Macro Call:
 */
.globl  ECP256_OrdSqr
.type   ECP256_OrdSqr,@function
.align 32
ECP256_OrdSqr:
.cfi_startproc
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    movq    (%rsi), %r8
    movq    8(%rsi), %rax
    movq    16(%rsi), %r14
    movq    24(%rsi), %r15
    leaq    .Lord(%rip), %rbp           // ptr(N) --> rbp
    movq    %rdx, %rbx
.align 32
.Lord_sqr_loop:
    movq    %rax, %rsi
    mulq    %r8                         // rdx:rax = acc[0] * acc[1]
    movq    %rax, %r9                   // r9 = rax
    vmovq   %rsi, %xmm1                 // save acc[1] -> xmm1
    movq    %r14, %rax                  // acc[2] --> rax
    movq    %rdx, %r10                  // r10:r9 = acc[0] * acc[1]

    mulq    %r8                         // rdx:rax = acc[0] * acc[2]
    addq    %rax, %r10                  // r10 += rax
    vmovq   %r14, %xmm2                 // save acc[2] -> xmm2
    adcq    $0, %rdx                    // acc[0] * (acc[2] * 2^64 + acc[1]) < 2^196, no overflow
    movq    %r15, %rax                  // acc[3] --> rax
    movq    %rdx, %r11

    mulq    %r8                         // rdx:rax = a[0] * a[3]
    addq    %rax, %r11                  // r11 += rax
    vmovq   %r15, %xmm3                 // Save acc[3] -> xmm3
    adcq    $0, %rdx                    // acc[0] * (acc[3] * 2^128 + acc[2] * 2^64 + acc[1]) < 2^256, no overflow
    movq    %r15, %rax                  // acc[1] --> rax
    movq    %rdx, %r12

    mulq    %r14
    movq    %rax, %r13
    movq    %r14, %rax
    movq    %rdx, %r14

    mulq    %rsi
    addq    %rax, %r11
    movq    %r15, %rax
    adcq    $0, %rdx
    movq    %rdx, %r15

    mulq    %rsi
    addq    %rax, %r12
    adcq    $0, %rdx
    addq    %r15, %r12
    adcq    %rdx, %r13
    movq    %r8, %rax                   // acc[0] --> rax
    adcq    $0, %r14                    // r14 r13 r12 r11 r10 r9

    xorq    %r15, %r15                  // 0 --> r15
    addq    %r9, %r9                    // twice
    adcq    %r10, %r10
    adcq    %r11, %r11
    adcq    %r12, %r12
    adcq    %r13, %r13
    adcq    %r14, %r14
    adcq    $0, %r15                    // result: r15 r14 r13 r12 r11 r10 r9

    mulq    %rax                        // rdx:rax = acc[0] * acc[0]
    movq    %rax, %r8                   // rax --> r8
    vmovq   %xmm1, %rax                 // acc[1] --> rax
    movq    %rdx, %rcx                  // save rdx to rcx

    mulq    %rax                        // rdx:rax = acc[1] * acc[1]
    addq    %rcx, %r9                   // r9 += rcx
    adcq    %rax, %r10                  // r10 += rax
    adcq    $0, %rdx                    // no overflow
    vmovq   %xmm2, %rax                 // acc[2] --> rax
    movq    %rdx, %rcx                  // save rdx to rcx

    mulq    %rax                        // rdx:rax = a[2] * a[2]
    addq    %rcx, %r11                  // r11 += rcx
    adcq    %rax, %r12                  // r12 += rax
    movq    %r8, %rsi                   // acc[0] --> rsi
    adcq    $0, %rdx                    // no overflow
    vmovq   %xmm3, %rax                 // acc[3] --> rax
    movq    %rdx, %rcx                  // save rcx to rdx

    imulq   32(%rbp), %r8               // m = acc[0] * LordK (mod 2^64) --> r8

    mulq    %rax                        // rdx:rax = a[3] * a[3]
    addq    %rcx, %r13                  // r13 += rcx
    adcq    %rax, %r14                  // r14 += r
    movq    (%rbp), %rax                // N[0] --> rax
    adcq    %rdx, %r15                  // r15 not overflow

    /* Result acc[8:0] = r15 r14 r13 r12 r11 r10 r9 r8;   */
    /* The first reduction */
    mulq    %r8                         // rdx:rax = m * N[0]
    addq    %rax, %rsi                  // rsi = 0
    movq    %r8, %rcx                   // m --> rcx
    adcq    %rdx, %rsi                  // rsi = rdx + carry  --> acc[1]

    subq    %r8, %r10                   // acc[2] - m
    sbbq    $0, %rcx                    // m - borrwo, to acc[3]

    movq    8(%rbp), %rax               // N[1] --> rax
    mulq    %r8                         // rdx:rax = m * N[1]
    addq    %rsi, %r9                   // acc[1] += high[m * N[0]]
    adcq    $0, %rdx                    // save carry
    addq    %rax, %r9                   // acc[1] += low[m * N[1]]
    movq    %r8, %rax                   // m --> rax
    adcq    %rdx, %r10                  // acc[2] += high[m * N[1]]
    movq    %r9, %rsi                   // acc[1] --> rsi
    movq    %r8, %rdx                   // m --> rdx
    adcq    $0, %rcx                    // m - borrwoto acc[3]

    imulq   32(%rbp), %r9               // m = acc[1] * LordK --> r9

    shlq    $32, %rax                   // low(m) --> rax   low(m * 2^228)
    shrq    $32, %rdx                   // high(m) --> rdx   high(m * 2^228)
    subq    %rax, %r11                  // acc[3] - low(m * 2^228)
    movq    (%rbp), %rax                // N[0] --> rax
    sbbq    %rdx, %r8                   // m - high(m * 2^228)  to acc[4]

    addq    %rcx, %r11                  // acc[3] += m + carry - borrow
    adcq    $0, %r8                     // to acc[4]

    /* Second reduction */
    mulq    %r9                         // rdx:rax = m * N[0]
    addq    %rax, %rsi                  // acc[1] += rax  -->  0
    movq    %r9, %rcx                   // m --> rcx
    adcq    %rdx, %rsi                  // rsi = high[m * N[0]] + carry  --> acc[2]

    movq    8(%rbp), %rax               // N[1] --> rax
    subq    %r9, %r11                   // acc[3] -= m
    sbbq    $0, %rcx                    // m - borrow --> rcx

    mulq    %r9                         // rdx:rax = m * N[1]
    addq    %rsi, %r10                  // acc[2] += high[m * N[1]] + carry
    adcq    $0, %rdx                    // rdx += carry, no overflow
    addq    %rax, %r10                  // acc[2] += rax
    movq    %r9, %rax                   // m --> rax
    adcq    %rdx, %r11                  // acc[3] += rdx
    movq    %r10, %rsi                  // acc[2] --> rsi
    movq    %r9, %rdx                   // m --> rdx
    adcq    $0, %rcx                    // m - borrow + carry --> rcx

    imulq   32(%rbp), %r10              // m = acc[2] * LordK --> r10

    shlq    $32, %rax                   // low(m * 2^228)
    shrq    $32, %rdx                   // high(m * 2^228)
    subq    %rax, %r8                   // t0 acc[4] - low(m * 2^228)
    movq    (%rbp), %rax                // N[0] --> rax
    sbbq    %rdx, %r9                   // m - high(m * 2^228)  to acc[5]

    addq    %rcx, %r8                   // to acc[4]
    adcq    $0, %r9                     // to acc[5]

    /* Third reduction */
    mulq    %r10                        // rdx:rax = m * N[0]
    movq    %r10, %rcx                  // m --> rcx
    addq    %rax, %rsi                  // acc[2] += rax --> 0
    adcq    %rdx, %rsi                  // rsi = high[m * N[0]] + carry  --> acc[3]
    movq    8(%rbp), %rax               // N[1] --> rax
    subq    %r10, %r8                   // to acc[4] -= m
    sbbq    $0, %rcx                    // m - borrow --> rcx

    mulq    %r10                        // rdx:rax = m * N[1]
    addq    %rsi, %r11                  // acc[3] += high[m * N[1]] + carry
    adcq    $0, %rdx                    // rdx += carry, no overflow
    addq    %rax, %r11                  // acc[3] += rax
    movq    %r10, %rax                  // m --> rax
    adcq    %rdx, %r8                   // to acc[4] += rdx
    movq    %r11, %rsi                  // acc[3] --> rsi
    movq    %r10, %rdx                  // m --> rdx
    adcq    $0, %rcx                    // m - borrow + carry --> rcx

    imulq   32(%rbp), %r11              // m = acc[3] * LordK --> r11

    shlq    $32, %rax                   // low(m * 2^228)
    shrq    $32, %rdx                   // high(m * 2^228)
    subq    %rax, %r9                   // to acc[5]: - low(m * 2^228)
    sbbq    %rdx, %r10                  // to acc[6]: m - high(m * 2^228)
    movq    (%rbp), %rax                // N[0] --> rax
    addq    %rcx, %r9                   // to acc[5]
    adcq    $0, %r10                    // to acc[6]

    /* Last reduction */
    mulq    %r11                        // rdx:rax = m * N[0]
    addq    %rax, %rsi                  // acc[3] += rax --> 0
    movq    %r11, %rcx                  // m --> rcx
    adcq    %rdx, %rsi                  // rsi = high[m * N[0]] + carry  --> acc[4]
    movq    8(%rbp), %rax               // N[1] --> rax
    subq    %r11, %r9                   // to acc[5] : -= m
    sbbq    $0, %rcx                    // to acc[6] : m - borrow

    mulq    %r11                        // rdx:rax = m * N[1]
    addq    %rsi, %r8                   // to acc[4]: += high[m * N[1]] + carry
    adcq    $0, %rdx                    // rdx += carry, no overflow
    addq    %rax, %r8                   // to acc[4]: += rax
    movq    %r11, %rax                  // m --> rax
    adcq    %rdx, %r9                   // to acc[5]: += rdx
    movq    %r11, %rdx                  // m --> rdx
    adcq    $0, %rcx                    // m - borrow + carry --> rcx

    shlq    $32, %rax                   // low(m * 2^228)
    shrq    $32, %rdx                   // high(m * 2^228)

    subq    %rax, %r10                  // to acc[6]: - low(m * 2^228)
    sbbq    %rdx, %r11                  // to acc[7]: m - high(m * 2^228)

    addq    %rcx, %r10                  // to acc[6]
    adcq    $0, %r11                    // to acc[7]

    /* r15 r14 r13 r12 + r11 r10 r9 r8 */
    xorq    %rdx, %rdx
    addq    %r12, %r8
    adcq    %r13, %r9
    movq    %r8, %r12
    adcq    %r14, %r10
    adcq    %r15, %r11
    movq    %r9, %rax
    adcq    $0, %rdx

    subq    (%rbp), %r8
    movq    %r10, %r14
    sbbq    8(%rbp), %r9
    sbbq    16(%rbp), %r10
    movq    %r11, %r15
    sbbq    24(%rbp), %r11
    sbbq    $0, %rdx

    cmovcq  %r12, %r8
    cmovncq  %r9, %rax
    cmovncq  %r10, %r14
    cmovncq  %r11, %r15                     // r8 rax r14 r15

    decq    %rbx
    jnz     .Lord_sqr_loop

    movq    %r8, (%rdi)
    movq    %rax, 8(%rdi)
    vpxor   %xmm2, %xmm2, %xmm2
    movq    %r14, 16(%rdi)
    vpxor   %xmm3, %xmm3, %xmm3
    movq    %r15, 24(%rdi)
    vpxor   %xmm1, %xmm1, %xmm1

    movq    (%rsp), %r15
    movq    8(%rsp), %r14
    movq    16(%rsp), %r13
    movq    24(%rsp), %r12
    movq    32(%rsp), %rbp
    movq    40(%rsp), %rbx
    leaq    48(%rsp), %rsp

    ret
.cfi_endproc
.size   ECP256_OrdSqr, .-ECP256_OrdSqr

/**
 *  Function description: half calculation of the ECP256 field: res = a/2 mod P
 *  Input register:
 *        rdi: Pointer to the output Coord structure
 *        r8： a[0]
 *        r9： a[1]
 *        r10：a[2]
 *        r11：a[3]
 *        r14：P[1]
 *        r15：P[3]
 *  Change register: rax, rcx, rdx, rsi, r8, r9, r10, r11, r12, r13
 *  Output register: r8, r9, r10, r11
 */
.type   ECP256_DivBy2Core,@function
ECP256_DivBy2Core:
.cfi_startproc
    xorq    %r13, %r13
    movq    %r8, %rax
    movq    %r9, %rcx

    addq    $-1, %r8
    movq    %r10, %rdx
    adcq    %r14, %r9
    movq    %r11, %r12
    adcq    $0, %r10
    adcq    %r15, %r11
    adcq    $0, %r13
    xorq    %rsi, %rsi

    testq   $1, %rax
    cmovzq  %rax, %r8
    cmovzq  %rcx, %r9
    cmovzq  %rdx, %r10
    cmovzq  %r12, %r11
    movq    %r9, %rcx
    cmovzq  %rsi, %r13
    movq    %r10, %rdx
    movq    %r11, %r12

    shrq    $1, %r8
    shlq    $63, %rcx
    shrq    $1, %r9
    shlq    $63, %rdx
    shrq    $1, %r10
    orq     %rcx, %r8
    shlq    $63, %r12

    shrq    $1, %r11
    shlq    $63, %r13
    orq     %rdx, %r9
    orq     %r12, %r10
    orq     %r13, %r11

    movq    %r8, (%rdi)
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)
    ret
.cfi_endproc
.size   ECP256_DivBy2Core, .-ECP256_DivBy2Core

/* r14 = .Lpoly[1], r15 = .Lpoly[3] */
.type   ECP256_MulBy2Core,@function
.align 32
ECP256_MulBy2Core:
.cfi_startproc
    xorq    %r13, %r13

    addq    %r8, %r8
    adcq    %r9, %r9
    movq    %r8, %rax
    adcq    %r10, %r10
    adcq    %r11, %r11
    movq    %r9, %rcx
    adcq    $0, %r13

    subq    $-1, %r8
    movq    %r10, %rdx
    sbbq    %r14, %r9
    movq    %r11, %r12
    sbbq    $0, %r10
    sbbq    %r15, %r11
    sbbq    $0, %r13

    cmovcq  %rax, %r8           // Obtain mod P result
    cmovcq  %rcx, %r9
    movq    %r8, (%rdi)
    cmovcq  %rdx, %r10
    movq    %r9, 8(%rdi)
    cmovcq  %r12, %r11
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)
    ret
.cfi_endproc
.size   ECP256_MulBy2Core, .-ECP256_MulBy2Core

/* r14 = .Lpoly[1], r15 = .Lpoly[3] */
.type   ECP256_MulBy3Core,@function
.align 32
ECP256_MulBy3Core:
.cfi_startproc
    xorq    %r13, %r13
    addq    %r8, %r8
    adcq    %r9, %r9
    movq    %r8, %rax
    adcq    %r10, %r10
    adcq    %r11, %r11
    movq    %r9, %rcx
    adcq    $0, %r13
    subq    $-1, %r8
    movq    %r10, %rdx
    sbbq    %r14, %r9
    movq    %r11, %r12
    sbbq    $0, %r10
    sbbq    %r15, %r11
    sbbq    $0, %r13

    cmovcq  %rax, %r8           // Obtain mod P result
    cmovcq  %rcx, %r9
    cmovcq  %rdx, %r10
    cmovcq  %r12, %r11

    xorq    %r13, %r13
    addq    (%rsi), %r8
    adcq    8(%rsi), %r9
    movq    %r8, %rax
    adcq    16(%rsi), %r10
    adcq    24(%rsi), %r11
    movq    %r9, %rcx
    adcq    $0, %r13
    subq    $-1, %r8
    movq    %r10, %rdx
    sbbq    %r14, %r9
    sbbq    $0, %r10
    movq    %r11, %r12
    sbbq    %r15, %r11
    sbbq    $0, %r13

    cmovcq  %rax, %r8           // Obtain mod P result
    cmovcq  %rcx, %r9
    movq    %r8, (%rdi)
    cmovcq  %rdx, %r10
    movq    %r9, 8(%rdi)
    cmovcq  %r12, %r11
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)
    ret
.cfi_endproc
.size   ECP256_MulBy3Core, .-ECP256_MulBy3Core

/**
 *  Function description: This function is used to calculate the Montgomery multiplication of the ord(P256) field:
 *  res = a * b * 2^(-256) mod ord(P)
 *  Input register:
 *        rdi: Pointer to the output Coord structure
 *        rsi: Address pointing to input data a
 *        rdx: Address pointing to input data b
 *  Change register: rax, rbx, rcx, rdx, rbp, r8, r9, r10, r11, r12, r13, r14, r15
 *  Function/Macro invoking: The calculation can be implemented by calling ECP256_OrdMulCore.
 */
.globl  ECP256_OrdMul
.type   ECP256_OrdMul,@function
.align 32
ECP256_OrdMul:
.cfi_startproc
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    movq    %rdx, %rcx                      // rdx used to output the mul multiplication result.
                                            // The rcx saves the b address.
    leaq	.Lord(%rip), %r15
    movq	.LordK(%rip), %r14
    movq    (%rdx), %rax                    // b[0]

    //a[0-3] * b[0]
    movq    %rax, %rbp                      // save b[0]
    mulq    (%rsi)                          // a[0] * b[0]
    movq    %rax, %r8
    movq    %rbp, %rax                      // b[0]
    movq    %rdx, %r9

    mulq    8(%rsi)                         // a[1] * b[0]
    addq    %rax, %r9
    movq    %rbp, %rax
    adcq    $0, %rdx                        // a[1:0] * b[0] The result must be less than 2 ^ 192,
                                            // So no carry is required.
    movq    %rdx, %r10

    mulq    16(%rsi)                        // a[2] * b[0]
    addq    %rax, %r10
    movq    %rbp, %rax
    adcq    $0, %rdx
    movq    %rdx, %r11

    mulq    24(%rsi)                        // a[3] * b[0]
    addq    %rax, %r11
    adcq    $0, %rdx
    movq    %r8, %r13
    movq    %rdx, %r12                      // First round multiplication results r12 r11 r10 r9 r8

    // First round of reduction
    // n[0] = 0xf3b9cac2fc632551
    // n[1] = 0xbce6faada7179e84
    // n[2] = 0xffffffffffffffff, lo(q*n[2]) = -q     , hi(q*n[2]) = q
    // n[3] = 0xffffffff00000000, lo(q*n[3]) = -lq<<32, hi(q*n[3]) = q-hq
    imulq   %r14, %r8                        // r8 = r8 * ordK = q

    movq    %r8, %rax
    mulq    (%r15)                           // n[0] * q
    addq    %rax, %r13                       // %r13 must be 0.
    adcq    $0, %rdx                         // hi(n[0]*q) + 1 < 2^32 + 1 < 2^64 No further carry is required.
    movq    %r8, %rax
    movq    %rdx, %rbp                       // %rbp = hi(n[0]*q)

    mulq    8(%r15)                          // n[1] * q
    addq    %rbp, %rax                       // %rax = lo(n[1]*q)+hi(n[0]*q)
    adcq    $0, %rdx                         // %rdx = hi(n[1]*q),   be the same as the above hi(n[1]*q) + 1 < 2^64
                                             // No further carry is required.

    movq    %r8, %rbx
    subq    %r8, %r10                        // r10 = r[2] - q
    sbbq    $0, %rbx                         // When q>0, rbx - 1 = q - 1 >= 0, when q=0 (r[2]-q) does not borrow,
                                             // rbx = rbx - 0 >= 0, so the following formula does not borrow

    addq    %rax, %r9                        // r9 = r[1] + lo(n[1]*q) + hi(n[0]*q)
    adcq    %rdx, %r10                       // r10 = r[2] - q + hi(n[1]*q)
    movq    %r8, %rax
    adcq    $0, %rbx                         // Overflowing is not possible.

    movq    %r8, %rdx
    shrq    $32, %rax                        // rax = hq
    shlq    $32, %rdx                        // rdx = lq<<32

    subq    %rdx, %rbx                       // q - lq<<32
    sbbq    %rax, %r8                        // r8 = q - hq = hq * 2^32 + lq - hq >= lq,
                                             // When lq!=0, The following formula does not borrow.
                                             // When lq==0, the upper formula does not borrow.

    adcq    %rbx, %r11
    movq    8(%rcx), %rax
    adcq    %r8, %r12
    movq    %rax, %rbp
    adcq    $0, %r13

    // a[0-3] * b[1]
    mulq    (%rsi)
    addq    %rax, %r9
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    8(%rsi)
    addq    %rbx, %r10
    adcq    $0, %rdx
    addq    %rax, %r10
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    16(%rsi)
    addq    %rbx, %r11
    adcq    $0, %rdx
    addq    %rax, %r11
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    xorq    %r8, %r8                         // r8 = 0
    mulq    24(%rsi)
    addq    %rbx, %r12
    adcq    $0, %rdx
    addq    %rax, %r12
    adcq    %rdx, %r13
    movq    %r9, %rbx
    adcq    $0, %r8                          // Second round of multiplication results r9,r10,r11,r12,r13,r8

    // Second round of reduction
    imulq   %r14, %r9                        // r9 = r9 * ordK = q
    movq    %r9, %rax

    mulq    (%r15)                           // n[0] * q
    addq    %rax, %rbx                       // %rbx must be 0
    adcq    $0, %rdx                         // hi(n[0]*q) + 1 < 2^32 + 1 < 2^64 No further carry is required
    movq    %r9, %rax
    movq    %rdx, %rbp                       // %rbp = hi(n[0]*q)

    mulq    8(%r15)                          // n[1] * q
    addq    %rbp, %rax                       // %rax = lo(n[1]*q)+hi(n[0]*q)
    adcq    $0, %rdx                         // %rdx = hi(n[1]*q),  be the same as the above hi(n[1]*q) + 1 < 2^64
                                             // No further carry is required

    movq    %r9, %rbx
    subq    %r9, %r11                        // r11 = r[2] - q
    sbbq    $0, %rbx                         // when q>0 rbx - 1 = q - 1 >= 0,
                                             // When q=0 (r[2]-q) does not borrow, rbx = rbx - 0 >= 0,
                                             // So the following equation does not borrow

    addq    %rax, %r10                       // r10 = r[1] + lo(n[1]*q) + hi(n[0]*q)
    adcq    %rdx, %r11                       // r11 = r[2] - q + hi(n[1]*q)
    movq    %r9, %rax
    adcq    $0, %rbx                         // Overflowing is not possible.

    movq    %r9, %rdx
    shrq    $32, %rax                        // rax = hq
    shlq    $32, %rdx                        // rdx = lq<<32

    subq    %rdx, %rbx                       // q - lq<<32
    sbbq    %rax, %r9                        // r9 = q - hq = hq * 2^32 + lq - hq >= lq,
                                             // When lq!=0,  The following formula does not borrow.
                                             // When lq==0, the preceding formula does not borrow.

    movq    16(%rcx), %rax
    adcq    %rbx, %r12
    adcq    %r9, %r13
    adcq    $0, %r8

    //  a[0-3] * b[2]
    movq    %rax, %rbp
    mulq    (%rsi)                           // a[0] * b[2]
    addq    %rax, %r10
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    8(%rsi)
    addq    %rbx, %r11
    adcq    $0, %rdx
    addq    %rax, %r11
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    16(%rsi)
    addq    %rbx, %r12
    adcq    $0, %rdx
    addq    %rax, %r12
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    xorq    %r9, %r9
    mulq    24(%rsi)
    addq    %rbx, %r13
    adcq    $0, %rdx
    addq    %rax, %r13
    adcq    %rdx, %r8
    movq    %r10, %rbx
    adcq    $0, %r9

    // Third round reduction
    imulq   %r14, %r10                       // r10 = r10 * ordK = q

    movq    %r10, %rax
    mulq    (%r15)                           // n[0] * q
    addq    %rax, %rbx                       // %rbx must be 0
    adcq    $0, %rdx                         // hi(n[0]*q) + 1 < 2^32 + 1 < 2^64 no further carry is required.
    movq    %r10, %rax
    movq    %rdx, %rbp                       // %rbp = hi(n[0]*q)

    mulq    8(%r15)                          // n[1] * q
    addq    %rbp, %rax                       // %rax = lo(n[1]*q)+hi(n[0]*q)
    adcq    $0, %rdx                         // %rdx = hi(n[1]*q),  same as above hi(n[1]*q) + 1 < 2^64 no further carry is required.

    movq    %r10, %rbx
    subq    %r10, %r12                       // r12 = r[2] - q
    sbbq    $0, %rbx                         // if q>0, rbx - 1 = q - 1 >= 0.
                                             // if q=0, (r[2]-q) Won't borrow ,  rbx = rbx - 0 >= 0,
                                             // the following formula will not borrow.

    addq    %rax, %r11                       // r11 = r[1] + lo(n[1]*q) + hi(n[0]*q)
    adcq    %rdx, %r12                       // r12 = r[2] - q + hi(n[1]*q)
    movq    %r10, %rax
    adcq    $0, %rbx                         // Overflowing is not possible.

    movq    %r10, %rdx
    shrq    $32, %rax                        // rax = hq
    shlq    $32, %rdx                        // rdx = lq<<32

    subq    %rdx, %rbx                       // q - lq<<32
    sbbq    %rax, %r10                       // r10 = q - hq = hq * 2^32 + lq - hq >= lq,
                                             // if lq!=0,  the following formula does not borrow,
                                             // if lq==0,  The above formula does not borrow.

    movq    24(%rcx), %rax
    adcq    %rbx, %r13
    adcq    %r10, %r8
    adcq    $0, %r9

    // a[0-3] * b[3]
    movq    %rax, %rbp
    mulq    (%rsi)                           // a[0] * b[3]
    addq    %rax, %r11
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    8(%rsi)
    addq    %rbx, %r12
    adcq    $0, %rdx
    addq    %rax, %r12
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    mulq    16(%rsi)
    addq    %rbx, %r13
    adcq    $0, %rdx
    addq    %rax, %r13
    adcq    $0, %rdx
    movq    %rbp, %rax
    movq    %rdx, %rbx

    xorq    %r10, %r10
    mulq    24(%rsi)
    addq    %rbx, %r8
    adcq    $0, %rdx
    addq    %rax, %r8
    adcq    %rdx, %r9
    movq    %r11, %rbx
    adcq    $0, %r10

    // last round reduction.
    imulq   %r14, %r11                       // r11 = r11 * ordK = q

    movq    %r11, %rax
    mulq    (%r15)                           // n[0] * q
    addq    %rax, %rbx                       // %rbx must be 0
    adcq    $0, %rdx                         // hi(n[0]*q) + 1 < 2^32 + 1 < 2^64 no further carry is required.
    movq    %r11, %rax
    movq    %rdx, %rbp                       // %rbp = hi(n[0]*q)

    mulq    8(%r15)                          // n[1] * q
    addq    %rbp, %rax                       // %rax = lo(n[1]*q)+hi(n[0]*q)
    adcq    $0, %rdx                         // %rdx = hi(n[1]*q), same as above,
                                             // hi(n[1]*q) + 1 < 2^64 no further carry is required.

    movq    %r11, %rbx
    subq    %r11, %r13                       // r13 = r[2] - q
    sbbq    $0, %rbx                         // When q>0 rbx - 1 = q - 1 >= 0,
                                             // When q=0,(r[2]-q)No borrowing, rbx = rbx - 0 >= 0,
                                             // so the following formula does not borrow.

    addq    %rax, %r12                       // r12 = r[1] + lo(n[1]*q) + hi(n[0]*q)
    adcq    %rdx, %r13                       // r13 = r[2] - q + hi(n[1]*q)
    movq    %r11, %rax
    adcq    $0, %rbx                         // Overflowing is not possible.

    movq    %r11, %rdx
    shrq    $32, %rax                        // rax = hq
    shlq    $32, %rdx                        // rdx = lq<<32

    subq    %rdx, %rbx                       // q - lq<<32
    sbbq    %rax, %r11                       // r11 = q - hq = hq * 2^32 + lq - hq >= lq,
                                             // when lq!=0, the following formula does not borrow.
                                             // When lq==0, the preceding formula does not borrow.

    adcq    %rbx, %r8
    adcq    %r11, %r9
    adcq    $0, %r10

    // mod n
    movq    %r12, %rbx
    movq    %r13, %rbp
    movq    %r8, %rax
    movq    %r9, %rdx

    subq    (%r15), %r12
    sbbq    8(%r15), %r13
    sbbq    16(%r15), %r8
    sbbq    24(%r15), %r9
    sbbq    $0, %r10

    cmovcq  %rbx, %r12
    cmovcq  %rbp, %r13
    cmovcq  %rax, %r8
    cmovcq  %rdx, %r9

    movq    %r12, (%rdi)
    movq    %r13, 8(%rdi)
    movq    %r8, 16(%rdi)
    movq    %r9, 24(%rdi)

    movq    (%rsp), %r15
    movq    8(%rsp), %r14
    movq    16(%rsp), %r13
    movq    24(%rsp), %r12
    movq    32(%rsp), %rbp
    movq    40(%rsp), %rbx
    leaq    48(%rsp), %rsp
    ret
.cfi_endproc
.size   ECP256_OrdMul, .-ECP256_OrdMul

/**
 *  Function description: Calculate the point doubling of an elliptic curve: res = 2*a
 *  Function prototype: void ECP256_PointDouble(P256_Point *r, const P256_Point *a);
 *  Input register:
 *        rdi: pointer to the output P256_POINT structure
 *        rsi: address pointing to input data a
 *  Change register: rax, rbx, rcx, rdx, rbp, rsi, r8, r9, r10, r11, r12, r13, r14, r15
 *  Function/Macro Call: ECP256_MulBy2Core, ECP256_SqrCore_q, ECP256_AddCore, ECP256_MulCore_q, ECP256_SubCore
 * ref. https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
 * Deal process:
 *     delta = Z12
 *     gamma = Y12
 *     beta = X1*gamma
 *     alpha = 3*(X1-delta)*(X1+delta)
 *     X3 = alpha2-8*beta
 *     Z3 = (Y1+Z1)2-gamma-delta
 *     Y3 = alpha*(4*beta-X3)-8*gamma2
 */
.globl ECP256_PointDouble
.type  ECP256_PointDouble,@function
.align 32
ECP256_PointDouble:
.cfi_startproc
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    subq    $168, %rsp                  // Create 32 x 5 + 8 stack space.
.Lpoint_double_core:
    vmovdqu  (%rsi), %xmm0               // Save x to stack
    vmovdqu  16(%rsi), %xmm1
    vmovdqa  %xmm0, (%rsp)
    vmovdqa  %xmm1, 16(%rsp)

    vmovq    %rsi, %xmm3                 // Backup a
    vmovq    %rdi, %xmm0                 // Backup &r->x, &r->y, &r->z
    leaq    32(%rdi), %r12
    leaq    64(%rdi), %r13
    vmovq    %r12, %xmm1
    vmovq    %r13, %xmm2

    movq    32(%rsi), %r8               // Read a->y
    movq    40(%rsi), %r9
    movq    48(%rsi), %r10
    movq    56(%rsi), %r11

    movq    8+.Lpoly(%rip), %r14        // Read P[1], P[3]
    movq    24+.Lpoly(%rip), %r15

    leaq    32(%rsp), %rdi
    call    ECP256_MulBy2Core           // ECP256_MulBy2(S, &a->y), Not overwritten rsi

    movq    64(%rsi), %rax
    movq    72(%rsi), %r14
    movq    80(%rsi), %rbp
    movq    88(%rsi), %r15
    leaq    64(%rsi), %rsi              // Setting Input Parameters
    leaq    64(%rsp), %rdi              // Z2 = rsp + 64
    call    ECP256_SqrCore_q            // ECP256_Sqr(Z2, &a->z)

    leaq    (%rsp), %rdx
    leaq    96(%rsp), %rdi              // M = rsp + 96
    call    ECP256_AddCore              // ECP256_Add(M, a->x, Z2)

    movq    32(%rsp), %rax
    movq    40(%rsp), %r14
    movq    48(%rsp), %rbp
    movq    56(%rsp), %r15
    leaq    32(%rsp), %rdi              // S = rsp + 32
    call    ECP256_SqrCore_q            // ECP256_Sqr(S, S)

    vmovq    %xmm3, %rcx
    leaq    32(%rcx), %rsi
    leaq    64(%rcx), %rcx
    vmovq    %xmm2, %rdi
    call    ECP256_MulCore_q            // ECP256_Mul(r->z, a->y, a->z)
    call    ECP256_MulBy2Core           // ECP256_MulBy2(r->z, r->z)

    movq    (%rsp), %r8
    movq    8(%rsp), %r9
    movq    16(%rsp), %r10
    movq    24(%rsp), %r11
    leaq    64(%rsp), %rdx
    call    ECP256_SubCore              // ECP256_SubCore(Z2,a->x,Z2)
    movq    %r8, 64(%rsp)
    movq    %r9, 72(%rsp)
    movq    %r10, 80(%rsp)
    movq    %r11, 88(%rsp)

    movq    32(%rsp), %rax
    movq    40(%rsp), %r14
    movq    48(%rsp), %rbp
    movq    56(%rsp), %r15
    vmovq    %xmm1, %rdi
    call    ECP256_SqrCore_q            // ECP256_Sqr(r->y,S)

    call    ECP256_DivBy2Core           // ECP256_Div(r->y,r->y)

    leaq    96(%rsp), %rdi
    leaq    96(%rsp), %rsi
    leaq    64(%rsp), %rcx
    call    ECP256_MulCore_q            // ECP256_MulCore_q(M,M,Z2)
    call    ECP256_MulBy3Core           // ECP256_MulBy3Core(M,M)

    leaq    (%rsp), %rcx
    leaq    32(%rsp), %rsi
    leaq    32(%rsp), %rdi
    call    ECP256_MulCore_q            // ECP256_MulCore_q(S, S, a->x)

    leaq    128(%rsp), %rdi             // T = 128 + rsp
    call    ECP256_MulBy2Core           // ECP256_MulBy2Core(T,  S)

    movq    96(%rsp), %rax
    movq    104(%rsp), %r14
    movq    112(%rsp), %rbp
    movq    120(%rsp), %r15
    vmovq    %xmm0, %rdi
    call    ECP256_SqrCore_q            // ECP256_Sqr(r->x,  M)

    leaq    128(%rsp), %rdx
    call    ECP256_SubCore              // ECP256_SubCore(r->x,  r->x,  T)
    movq    %r8, (%rdi)
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    xorq    %rsi, %rsi                  // ECP256_SubCore(S,  S,  r->x), output %r12, %r13, %r8, %r9
    movq    32(%rsp), %rax
    movq    40(%rsp), %rbx
    movq    48(%rsp), %rcx
    subq    %r8, %rax
    sbbq    %r9, %rbx
    movq    56(%rsp), %rdx
    movq    %rax, %r12
    sbbq    %r10, %rcx
    sbbq    %r11, %rdx
    movq    %rbx, %r13
    movq    %rcx, %r8
    sbbq    $0, %rsi
    addq    $-1, %rax
    movq    %rdx, %r9
    adcq    %r14, %rbx
    adcq    $0, %rcx
    adcq    %r15, %rdx
    testq   %rsi, %rsi
    cmovnzq  %rax, %r12
    cmovnzq  %rbx, %r13
    cmovnzq  %rcx, %r8
    cmovnzq  %rdx, %r9
    movq    %r12, 32(%rsp)
    movq    %r13, 40(%rsp)
    movq    %r8, 48(%rsp)
    movq    %r9, 56(%rsp)

    leaq    32(%rsp), %rdi
    leaq    32(%rsp), %rsi
    leaq    96(%rsp), %rcx
    call    ECP256_MulCore_q            // ECP256_MulCore_q(S,  S,  M)

    vmovq    %xmm1, %rdx
    vmovq    %xmm1, %rdi
    call    ECP256_SubCore              // ECP256_SubCore(r->y,  S,  r->y)
    movq    %r8, (%rdi)
    movq    %r9, 8(%rdi)
    leaq    168+48(%rsp), %rsi
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    movq    -48(%rsi), %r15
    movq    -40(%rsi), %r14
    movq    -32(%rsi), %r13
    movq    -24(%rsi), %r12
    movq    -16(%rsi), %rbp
    movq    -8(%rsi), %rbx
    leaq    (%rsi), %rsp
    ret
.cfi_endproc
.size   ECP256_PointDouble, .-ECP256_PointDouble

/**
 *  Function description: Elliptic curve point addition calculation: res = a + b
 *  Function prototype: void ECP256_PointAdd(P256_Point *r, const P256_Point *a, const P256_Point *b);
 *  Input register:
 *        rdi: Pointer to the output P256_POINT structure
 *        rsi: Address pointing to input data a
 *        rdx: Address pointing to input data b
 *  Change register: rax, rbx, rcx, rdx, rbp, rsi, r8, r9, r10, r11, r12, r13, r14, r15
 *  Function/Macro Call: ECP256_PointDouble, ECP256_SqrCore_q, ECP256_MulCore_q, ECP256_SubCore, ECP256_MulBy2Core
 * ref. https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo
 * Deal process:
 *     U1 = X1*Z22
 *     U2 = X2*Z12
 *     S1 = Y1*Z23
 *     S2 = Y2*Z13
 *     H = U2-U1
 *     r = S2-S1
 *     X3 = r2-H3-2*U1*H2
 *     Y3 = r*(U1*H2-X3)-S1*H3
 *     Z3 = Z1*Z2*H
 */
.globl ECP256_PointAdd
.type  ECP256_PointAdd,@function
.align 32
ECP256_PointAdd:
.cfi_startproc
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    subq    $640+8, %rsp                // Create 32 x 20 + 8 stack space.

    vmovdqu  (%rsi), %xmm0
    vmovdqu  16(%rsi), %xmm1
    vmovdqu  32(%rsi), %xmm2
    vmovdqu  48(%rsi), %xmm3
    vmovdqu  64(%rsi), %xmm4
    vmovdqu  80(%rsi), %xmm5
    movq    %rsi, %rcx
    movq    %rdx, %rsi
    vmovdqu  %xmm0, (%rsp)              // Save a on the stack, a_cpy: 0~96(%rsp)
    vmovdqu  %xmm1, 16(%rsp)
    vmovdqu  %xmm2, 32(%rsp)
    vmovdqu  %xmm3, 48(%rsp)
    vmovdqu  %xmm4, 64(%rsp)
    vmovdqu  %xmm5, 80(%rsp)
    vpor     %xmm4, %xmm5, %xmm5        // xmm5 = (Za[3]|Za[1], Za[2]|Za[0])

    vmovdqu  (%rsi), %xmm0
    vpshufd  $0xb1, %xmm5, %xmm3        // xmm3 = ((lo(Za[3]|Za[1])<<32) | hi(Za[3]|Za[1]), (lo(Za[2]|Za[0])<<32) | hi(Za[2]|Za[0]))
    vmovdqu  16(%rsi), %xmm1
    vmovdqu  32(%rsi), %xmm2
    vpor     %xmm3, %xmm5, %xmm5        // xmm5 = ((lo(Za[3]|Za[1])|hi(Za[3]|Za[1]))##~, (lo(Za[2]|Za[0])|hi(Za[2]|Za[0]))##~)
    vmovdqu  48(%rsi), %xmm3

    movq    64(%rsi), %rax              // Read b.z, then calculate (b.z)^2
    movq    72(%rsi), %r14
    movq    80(%rsi), %rbp
    movq    88(%rsi), %r15

    vmovdqu  %xmm0, 96(%rsp)            // Save b on the stack. b_cpy: 96–192(%rsp)
    vpshufd  $0x1e, %xmm5, %xmm4        // xmm4 = ((lo(Za[2]|Za[0])|hi(Za[2]|Za[0]))##~, (lo(Za[3]|Za[1])|hi(Za[3]|Za[1]))##~)
    vmovdqu  %xmm1, 112(%rsp)
    vmovdqu  64(%rsi), %xmm0
    vmovdqu  80(%rsi), %xmm1
    vmovdqu  %xmm2, 128(%rsp)
    vmovdqu  %xmm3, 144(%rsp)
    vpor     %xmm4, %xmm5, %xmm5        // xmm5 = ((lo(Za[0]|Za[1]|Za[2]|Za[3])|hi(Za[0]|Za[1]|Za[2]|Za[3]))##~##~##~)
    vpxor    %xmm4, %xmm4, %xmm4
    vpor     %xmm0, %xmm1, %xmm1
    vmovq    %rdi, %xmm0                // Backup rdi
    movq    %rax, 160(%rsp)
    movq    %r14, 168(%rsp)
    leaq    192(%rsp), %rdi             // Zb^2: 192~224(%rsp)
    movq    %rbp, 176(%rsp)
    movq    %r15, 184(%rsp)

    vmovq    %rcx, %xmm2                // Backup a
    call    ECP256_SqrCore_q            // sqr(Zb^2, Zb)

    vpcmpeqd %xmm4, %xmm5, %xmm5        // a_infty, Whether a is an infinity point (Za == 0)
    vpshufd  $0xb1, %xmm1, %xmm4
    vpor     %xmm1, %xmm4, %xmm4
    vpshufd  $0x1e, %xmm4, %xmm3
    vpor     %xmm3, %xmm4, %xmm4
    vpxor    %xmm3, %xmm3, %xmm3
    vpcmpeqd %xmm3, %xmm4, %xmm4        // b_infty, Whether b is an infinity point (Zb == 0)

    movq    64(%rsp), %rax
    movq    72(%rsp), %r14
    leaq    224(%rsp), %rdi             // Za^2: 224~256(%rsp)
    movq    80(%rsp), %rbp
    movq    88(%rsp), %r15
    call    ECP256_SqrCore_q            // sqr(Za^2, Za)

    leaq    160(%rsp), %rsi             // Zb
    leaq    192(%rsp), %rcx             // Zb^2
    leaq    256(%rsp), %rdi             // S1: 256~288(%rsp)
    call    ECP256_MulCore_q            // mul(S1, Zb, Zb^2)

    leaq    64(%rsp), %rsi              // Za
    leaq    224(%rsp), %rcx             // Za^2
    leaq    288(%rsp), %rdi             // S2: 288~320(%rsp)
    call    ECP256_MulCore_q            // mul(S2, Za, Za^2)

    leaq    32(%rsp), %rsi              // Ya
    leaq    256(%rsp), %rcx             // S1
    leaq    256(%rsp), %rdi             // S1
    call    ECP256_MulCore_q            // mul(S1,S1,Ya)

    leaq    128(%rsp), %rsi             // Yb
    leaq    288(%rsp), %rcx             // S2
    leaq    288(%rsp), %rdi             // S2
    call    ECP256_MulCore_q            // mul(S2,S2,Yb)

    leaq    256(%rsp), %rdx             // S1
    call    ECP256_SubCore              // sub(R,S2,S1)
    movq    %r8, 320(%rsp)              // R: 320~352(%rsp)
    movq    %r9, 328(%rsp)
    movq    %r10, 336(%rsp)
    movq    %r11, 344(%rsp)

    orq     %r9, %r8
    vmovdqa  %xmm4, %xmm1
    orq     %r10, %r8
    orq     %r11, %r8
    vpor     %xmm5, %xmm1, %xmm1        // a_infty | b_infty
    vmovq    %r8, %xmm3

    leaq    (%rsp), %rsi                // Xa
    leaq    192(%rsp), %rcx             // Zb^2
    leaq    352(%rsp), %rdi             // U1: 352~384(%rsp)
    call    ECP256_MulCore_q            // Mul(U1, Xa, Zb^2)

    leaq    96(%rsp), %rsi              // Xb
    leaq    224(%rsp), %rcx             // Za^2
    leaq    384(%rsp), %rdi             // U2: 384~416(%rsp)
    call    ECP256_MulCore_q            // Mul(U2, Xb, Za^2)

    leaq    352(%rsp), %rdx             // U1
    leaq    416(%rsp), %rdi             // H: 416~448(%rsp)
    call    ECP256_SubCore              // sub(H,U2,U1)
    movq    %r8, 416(%rsp)
    movq    %r9, 424(%rsp)
    movq    %r10, 432(%rsp)
    movq    %r11, 440(%rsp)

    orq     %r9, %r8
    vmovq    %xmm1, %r12
    orq     %r10, %r8
    vmovq    %xmm3, %r13
    orq     %r11, %r8

    orq     %r12, %r8
    orq     %r13, %r8

    jnz     .Lpoint_add

.Lequal_point:
    vmovq    %xmm0, %rdi
    vmovq    %xmm2, %rsi
    addq    $640-32*5, %rsp
    jmp     .Lpoint_double_core

.align 32
.Lpoint_add:
    movq    320(%rsp), %rax             // R
    movq    328(%rsp), %r14
    leaq    448(%rsp), %rdi             // R^2: 448~480(%rsp)
    movq    336(%rsp), %rbp
    movq    344(%rsp), %r15
    call    ECP256_SqrCore_q            // sqr(R^2,R)

    leaq    64(%rsp), %rsi              // Za
    leaq    416(%rsp), %rcx             // H
    leaq    480(%rsp), %rdi             // Zr:480~512(%rsp)
    call    ECP256_MulCore_q            // Mul(Zr,H,Za)

    movq    416(%rsp), %rax             // H
    movq    424(%rsp), %r14
    leaq    512(%rsp), %rdi             // H^2:512~544(%rsp)
    movq    432(%rsp), %rbp
    movq    440(%rsp), %r15
    call    ECP256_SqrCore_q            // sqr(H^2, H)

    leaq    480(%rsp), %rdi             // Zr
    leaq    480(%rsp), %rsi             // Zr
    leaq    160(%rsp), %rcx             // Zb
    call    ECP256_MulCore_q            // Mul(Zr, Zr, Zb)

    leaq    544(%rsp), %rdi             // H3:544~576(%rsp)
    leaq    512(%rsp), %rsi             // H2
    leaq    416(%rsp), %rcx             // H
    call    ECP256_MulCore_q            // mul(H^3,H,H^2)

    leaq    384(%rsp), %rdi             // U2
    leaq    352(%rsp), %rsi             // U1
    leaq    512(%rsp), %rcx             // H2
    call    ECP256_MulCore_q            // mul(U2,U1,H^2)

    leaq    512(%rsp), %rdi             // H^2
    call    ECP256_MulBy2Core           // mulby2(H^2,U2)

    movq    448(%rsp), %rax             // sub(Xr,R^2,H^2)
    movq    456(%rsp), %rbx
    xorq    %rsi, %rsi
    movq    464(%rsp), %rcx
    movq    472(%rsp), %rdx
    subq    %r8, %rax
    sbbq    %r9, %rbx
    movq    %rax, %r8
    sbbq    %r10, %rcx
    sbbq    %r11, %rdx
    movq    %rbx, %r9
    sbbq    $0, %rsi

    addq    $-1, %r8
    movq    %rcx, %r10
    adcq    %r14, %r9
    adcq    $0, %r10
    movq    %rdx, %r11
    adcq    %r15, %r11
    testq   %rsi, %rsi
    cmovzq  %rax, %r8
    cmovzq  %rbx, %r9
    cmovzq  %rcx, %r10
    cmovzq  %rdx, %r11

    leaq    576(%rsp), %rdi             // Xr: 576~608(%rsp)
    leaq    544(%rsp), %rdx             // H^3
    call    ECP256_SubCore              // sub(Xr, Xr, H^3)
    movq    %r8, 576(%rsp)
    movq    %r9, 584(%rsp)
    movq    %r10, 592(%rsp)
    movq    %r11, 600(%rsp)

    movq    384(%rsp), %rax             // sub(Yr, U2, Xr)
    movq    392(%rsp), %rbx
    xorq    %rsi, %rsi
    movq    400(%rsp), %rcx
    movq    408(%rsp), %rdx
    subq    %r8, %rax
    sbbq    %r9, %rbx
    movq    %rax, %r8
    sbbq    %r10, %rcx
    sbbq    %r11, %rdx
    movq    %rbx, %r9
    sbbq    $0, %rsi

    addq    $-1, %r8
    movq    %rcx, %r10
    adcq    %r14, %r9
    adcq    $0, %r10
    movq    %rdx, %r11
    adcq    %r15, %r11
    testq   %rsi, %rsi
    cmovzq  %rax, %r8
    cmovzq  %rbx, %r9
    cmovzq  %rcx, %r10
    cmovzq  %rdx, %r11
    movq    %r8, 608(%rsp)              // Yr: 608~640(%rsp)
    movq    %r9, 616(%rsp)
    movq    %r10, 624(%rsp)
    movq    %r11, 632(%rsp)

    leaq    288(%rsp), %rdi             // S2
    leaq    256(%rsp), %rsi             // S1
    leaq    544(%rsp), %rcx             // H^3
    call    ECP256_MulCore_q            // Mul(S2, S1, H^3)

    leaq    608(%rsp), %rdi             // Yr
    leaq    608(%rsp), %rsi
    leaq    320(%rsp), %rcx             // r
    call    ECP256_MulCore_q            // Mul(Yr, Yr, R)

    leaq    608(%rsp), %rdi             // Yr
    leaq    288(%rsp), %rdx             // S2
    call    ECP256_SubCore              // sub(Yr,Yr,S2)
    movq    %r8, 608(%rsp)
    movq    %r9, 616(%rsp)
    movq    %r10, 624(%rsp)
    movq    %r11, 632(%rsp)

    vmovq    %xmm0, %rdi

    vmovdqa  %xmm5, %xmm0               // a_infty
    vmovdqa  %xmm5, %xmm1
    vpandn   576(%rsp), %xmm0, %xmm0    // !a_infty & Xr
    vpandn   592(%rsp), %xmm1, %xmm1
    vmovdqa  %xmm5, %xmm2
    vmovdqa  %xmm5, %xmm3
    vpand    96(%rsp), %xmm2, %xmm2     // a_infty & Xb
    vpand    112(%rsp), %xmm3, %xmm3
    vpor     %xmm0, %xmm2, %xmm2        // a_infty ? Xb : Xr
    vpor     %xmm1, %xmm3, %xmm3

    vmovdqa  %xmm4, %xmm0               // b_infty
    vmovdqa  %xmm4, %xmm1
    vpandn   %xmm2, %xmm0, %xmm0        // !b_infty & (a_infty ? Xb : Xr)
    vpandn   %xmm3, %xmm1, %xmm1
    vmovdqa  %xmm4, %xmm2
    vmovdqa  %xmm4, %xmm3
    vpand    (%rsp), %xmm2, %xmm2       // b_infty & Xa
    vpand    16(%rsp), %xmm3, %xmm3
    vpor     %xmm0, %xmm2, %xmm2        // b_infty ? Xa : (a_infty ? Xb : Xr)
    vpor     %xmm1, %xmm3, %xmm3
    vmovdqu  %xmm2, (%rdi)
    vmovdqu  %xmm3, 16(%rdi)

    vmovdqa  %xmm5, %xmm0               // a_infty
    vmovdqa  %xmm5, %xmm1
    vpandn   608(%rsp), %xmm0, %xmm0    // !a_infty & Yr
    vpandn   624(%rsp), %xmm1, %xmm1
    vmovdqa  %xmm5, %xmm2
    vmovdqa  %xmm5, %xmm3
    vpand    128(%rsp), %xmm2, %xmm2    // a_infty & Yb
    vpand    144(%rsp), %xmm3, %xmm3
    vpor     %xmm0, %xmm2, %xmm2        // a_infty ? Yb : Yr
    vpor     %xmm1, %xmm3, %xmm3

    vmovdqa  %xmm4, %xmm0               // b_infty
    vmovdqa  %xmm4, %xmm1
    vpandn   %xmm2, %xmm0, %xmm0        // !b_infty & (a_infty ? Yb : Yr)
    vpandn   %xmm3, %xmm1, %xmm1
    vmovdqa  %xmm4, %xmm2
    vmovdqa  %xmm4, %xmm3
    vpand    32(%rsp), %xmm2, %xmm2     // b_infty & Ya
    vpand    48(%rsp), %xmm3, %xmm3
    vpor     %xmm0, %xmm2, %xmm2        // b_infty ? Ya : (a_infty ? Yb : Yr)
    vpor     %xmm1, %xmm3, %xmm3
    vmovdqu  %xmm2, 32(%rdi)
    vmovdqu  %xmm3, 48(%rdi)

    vmovdqa  %xmm5, %xmm0               // a_infty
    vmovdqa  %xmm5, %xmm1
    vpandn   480(%rsp), %xmm0, %xmm0    // !a_infty & Zr
    vpandn   496(%rsp), %xmm1, %xmm1
    vmovdqa  %xmm5, %xmm2
    vmovdqa  %xmm5, %xmm3
    vpand    160(%rsp), %xmm2, %xmm2    // a_infty & Zb
    vpand    176(%rsp), %xmm3, %xmm3
    vpor     %xmm0, %xmm2, %xmm2        // a_infty ? Zb : Zr
    vpor     %xmm1, %xmm3, %xmm3

    vmovdqa  %xmm4, %xmm0               // b_infty
    vmovdqa  %xmm4, %xmm1
    vpandn   %xmm2, %xmm0, %xmm0        // !b_infty & (a_infty ? Zb : Zr)
    vpandn   %xmm3, %xmm1, %xmm1
    vmovdqa  %xmm4, %xmm2
    vmovdqa  %xmm4, %xmm3
    vpand    64(%rsp), %xmm2, %xmm2     // b_infty & Za
    vpand    80(%rsp), %xmm3, %xmm3
    vpor     %xmm0, %xmm2, %xmm2        // b_infty ? Za : (a_infty ? Zb : Zr)
    vpor     %xmm1, %xmm3, %xmm3
    vmovdqu  %xmm2, 64(%rdi)
    vmovdqu  %xmm3, 80(%rdi)

    leaq    640+56(%rsp), %rsi
    movq    -48(%rsi), %r15
    movq    -40(%rsi), %r14
    movq    -32(%rsi), %r13
    movq    -24(%rsi), %r12
    movq    -16(%rsi), %rbp
    movq    -8(%rsi), %rbx
    leaq    (%rsi), %rsp
    ret
.cfi_endproc
.size   ECP256_PointAdd, .-ECP256_PointAdd

/**
 *  Function description: Point addition of normal coordinates and affine coordinates assembly implementation
 *  Function prototype: void ECP256_AddAffine(P256_Point *r, const P256_Point *a, const P256_AffinePoint *b);
 *  Input register:
 *        rdi: Points to the returned P256_Point.
 *        rsi: Points to the input P256_Point.
 *        rdx: P256_AffinePoint that points to the input
 *  Change register: rax, rbx, rcx, rdx, rsi, rdi, rbp, r8, r9, r10, r11, r12, r13, r14, r15
 *  Output register: None
 *  Function/Macro Call: ECP256_MulBy2Core, ECP256_SqrCore_q, ECP256_AddCore, ECP256_MulCore_q, ECP256_SubCore
 *  ref. https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl
 *  Deal process:
 *     Z1Z1 = Z12
 *     U2 = X2*Z1Z1
 *     S2 = Y2*Z1*Z1Z1
 *     H = U2-X1
 *     HH = H2
 *     I = 4*HH
 *     J = H*I
 *     r = 2*(S2-Y1)
 *     V = X1*I
 *     X3 = r2-J-2*V
 *     Y3 = r*(V-X3)-2*Y1*J
 *     Z3 = (Z1+H)2-Z1Z1-HH
 */
.globl  ECP256_AddAffine
.type   ECP256_AddAffine,@function
.align 32
ECP256_AddAffine:
.cfi_startproc
    pushq       %rbp
    pushq	    %rbx
    pushq	    %r12
    pushq	    %r13
    pushq	    %r14
    pushq	    %r15

    subq	    $488, %rsp                      // open up stack space 32 * 15 + 8 = 488

    vmovdqu	    0(%rsi), %xmm0                  // X1[1]X1[0] --> xmm0
	vmovdqu	    16(%rsi), %xmm1                 // X1[3]X1[2]
    vmovdqu	    32(%rsi), %xmm2                 // Y1[1]Y1[0]
	vmovdqu	    48(%rsi), %xmm3                 // Y1[3]Y1[2]
    movq        72(%rsi), %r14                  // Z1[1] 64 + 8
    movq        64(%rsi), %rax                  // Z1[0] 64 + 0
	vmovdqu	    64(%rsi), %xmm4                 // Z1[1]Z1[0]
    movq        88(%rsi), %r15                  // Z1[3] 64 + 24
    movq        80(%rsi), %rbp                  // Z1[2] 64 + 16
    vmovdqu	    80(%rsi), %xmm5                 // Z1[3]Z1[2]

    vmovdqa     %xmm0, 320(%rsp)                // save X1[1]X1[0] to stack
    vmovdqa     %xmm1, 336(%rsp)                // save X1[3]X1[2] to stack
    vmovdqa     %xmm2, 352(%rsp)                // save Y1[1]Y1[0] to stack
    vmovdqa     %xmm3, 368(%rsp)                // save Y1[3]Y1[2] to stack
    vmovdqa     %xmm4, 384(%rsp)                // save Z1[1]Z1[0] to stack
    vmovdqa     %xmm5, 400(%rsp)                // save Z1[3]Z1[2] to stack
    vpor        %xmm4, %xmm5, %xmm5             // Z1[1]Z1[0] | Z1[3]Z1[2]

    vmovdqu     (%rdx), %xmm0                   // X2[1]X2[0] --> xmm0
    vpshufd     $0xb1, %xmm5, %xmm3             // Order(10 11 00 01) --> [2 3 0 1] with 32bit
    vmovdqu     16(%rdx), %xmm1                 // X2[3]X2[2] --> xmm1
    vmovdqu     32(%rdx), %xmm2                 // Y2[1]Y2[0] --> xmm2
    vpor        %xmm3, %xmm5, %xmm5             // [2 3 0 1] | [3 2 1 0]
    vmovdqu     48(%rdx), %xmm3                 // Y2[3]Y2[2] --> xmm3
    vmovdqa     %xmm0, 416(%rsp)                // save X2[1]X2[0] to stack
    vpshufd     $0x1e, %xmm5, %xmm4             // Order(00 01 11 10) --> [0 1 3 2]
    vmovdqa     %xmm1, 432(%rsp)                // save X2[3]X2[1] to stack
    vpor        %xmm0, %xmm1, %xmm1             // X2[1]X2[0] | X2[3]X2[2]

    vmovq       %rdi, %xmm0                     // save rdi to xmm0
    vmovdqa     %xmm2, 448(%rsp)                // save X2[1]X2[0] to stack
    vmovdqa     %xmm3, 464(%rsp)                // save X2[3]X2[2] to stack
    vpor        %xmm2, %xmm3, %xmm3             // Y2[1]Y2[0] | Y2[3]Y2[2]
    vpor        %xmm4, %xmm5, %xmm5
    vpxor       %xmm4, %xmm4, %xmm4             // 0
    vpor        %xmm1, %xmm3, %xmm3             // X2[1]X2[0] | X2[3]X2[2] | Y2[1]Y2[0] | Y2[3]Y2[2]

.balign 32
    /* Z1Z1 = Z1 ^ 2 */
    leaq        64(%rsi), %rsi                  // addr(z)
    leaq        32(%rsp), %rdi                  // save Z1Z1 to stack
    call        ECP256_SqrCore_q                // Output: r8 - r11  P[1] --> r14 P[3] --> r15

    vpcmpeqd    %xmm4, %xmm5, %xmm5
    vpshufd     $0xb1, %xmm3, %xmm4             // Order(10 11 00 01)
    vpor        %xmm3, %xmm4, %xmm4
    vpshufd     $0, %xmm5, %xmm5                // Order(00 00 00 00)
    vpshufd     $0x1e, %xmm4, %xmm3             // Order(00 01 11 10)
    vpor        %xmm3, %xmm4, %xmm4
    vpxor       %xmm3, %xmm3, %xmm3
    vpcmpeqd    %xmm3, %xmm4, %xmm4
    vpshufd     $0, %xmm4, %xmm4

    /* U2 = X2 * Z1Z1 */
    leaq        416(%rsp), %rcx                 // addr of X2 in stack
    leaq        32(%rsp), %rsi                  // read Z1Z1 from stack
    leaq        (%rsp), %rdi                    // save U2 to stack
    call        ECP256_MulCore_q                // ouput: r8 - r11 P[1] --> r14 P[3] --> r15

    /* H = U2 - X1 */
    leaq        320(%rsp), %rdx                 // read X1 from stack
    leaq        64(%rsp), %rdi                  // save H to stack
    call        ECP256_SubCore                  // input: rdx, r8 - r11 P[1] --> r14 P[3] --> r15
    movq        %r8, (%rdi)
    movq        %r9, 8(%rdi)
    movq        %r10, 16(%rdi)
    movq        %r11, 24(%rdi)

    /* Z1Z1Z1 = Z1Z1 * Z1 */
    leaq        384(%rsp), %rcx                 // read Z1 from stack
    leaq        32(%rsp), %rsi                  // read Z1Z1 from stack
    leaq        32(%rsp), %rdi                  // save Z1Z1Z1 to stack
    call        ECP256_MulCore_q                // output: r8-r11 P[1] --> r14 P[3] --> r15
    movq        %r8, (%rdi)
    movq        %r9, 8(%rdi)
    movq        %r10, 16(%rdi)
    movq        %r11, 24(%rdi)

    /* Z3/2 = H * Z1 */
    leaq        384(%rsp), %rcx                 // read Z1 from stack
    leaq        64(%rsp), %rsi                  // read H from stack
    leaq        288(%rsp), %rdi                 // save Z3/2 to stack
    call        ECP256_MulCore_q                // P[1] --> r14 P[3] --> r15

    /* S2 = Y2 * Z1Z1Z1 */
    leaq        448(%rsp), %rcx                 // read Y2 from stack
    leaq        32(%rsp), %rsi                  // read Z1Z1Z1 from stack
    leaq        32(%rsp), %rdi                  // save S2 to stack
    call        ECP256_MulCore_q                // output: r8-r11 P[1] --> r14 P[3] --> r15

    /* r/2 = (S2 - Y1) */
    leaq        352(%rsp), %rdx                 // read Y1 from stack
    leaq        96(%rsp), %rdi                  // save r/2 to stack
    call        ECP256_SubCore                  // output: r8-r11 P[1] --> r14 P[3] --> r15
    movq        %r8, (%rdi)                     // save r/2 to stack
    movq        %r9, 8(%rdi)
    movq        %r10, 16(%rdi)
    movq        %r11, 24(%rdi)

    /* I/4 = H ^ 2 */
    leaq        64(%rsp), %rsi                  // read H from stack
    movq        (%rsi), %rax                    // a[0]
    movq        8(%rsi), %r14                   // a[1]
    movq        16(%rsi), %rbp                  // a[2]
    movq        24(%rsi), %r15                  // a[3]
    leaq        128(%rsp), %rdi                 // save I/4 to stack
    call        ECP256_SqrCore_q                // output: r8-r11 P[1] --> r14 P[3] --> r15

    /* (r/2)^2 = (r^2)/4 */
    leaq        96(%rsp), %rsi                  // read r/2 from stack
    movq        (%rsi), %rax                    // a[0]
    movq        8(%rsi), %r14                   // a[1]
    movq        16(%rsi), %rbp                  // a[2]
    movq        24(%rsi), %r15                  // a[3]
    leaq        192(%rsp), %rdi                 // save (r^2)/4 to stack
    call        ECP256_SqrCore_q                // output: r8-r11 P[1] --> r14 P[3] --> r15

    /* J/4 = I/4 * H */
    leaq        128(%rsp), %rcx                 // read I/4 from stack
    leaq        64(%rsp), %rsi                  // read H from stack
    leaq        160(%rsp), %rdi                 // save J/4 to stack
    call        ECP256_MulCore_q                // output: r8-r11 P[1] --> r14 P[3] --> r15

    /* V/4 = X1 * I */
    leaq        320(%rsp), %rcx                 // read X1 from stack
    leaq        128(%rsp), %rsi                 // read I/4 from stack
    leaq        (%rsp), %rdi                    // save V/4 to stack
    call        ECP256_MulCore_q                // output: r8-r11 P[1] --> r14 P[3] --> r15

    xorq        %r12, %r12
    addq        %r8, %r8
    adcq	    %r9, %r9
	movq	    %r8, %rax
    adcq	    %r10, %r10
	adcq	    %r11, %r11
	movq	    %r9, %rbp
    adcq	    $0, %r12

	subq	    $-1, %r8
	movq	    %r10, %rcx
    sbbq	    %r14, %r9
	sbbq	    $0, %r10
	movq	    %r11, %r13
    sbbq	    %r15, %r11
	sbbq	    $0, %r12
	leaq        192(%rsp), %rsi                 // read (r^2)/4 from
    cmovcq	    %rax,%r8                        // b[0]  V/2 --> r8-r11
    cmovcq	    %rbp,%r9                        // b[1]
    cmovcq	    %rcx,%r10                       // b[2]
    cmovcq	    %r13,%r11                       // b[3]

    /* (r^2 - 2 * V)/4 = (r^2)/4 - V/2 */
    xorq        %r13, %r13
    movq        (%rsi), %rax                    // a[0]
    movq        8(%rsi), %rcx                   // a[1]
    movq        16(%rsi), %rdx                  // a[2]
    movq        24(%rsi), %r12                  // a[3]

    subq        %r8, %rax
    sbbq        %r9, %rcx
    movq        %rax, %r8
    sbbq        %r10, %rdx
    sbbq        %r11, %r12
    movq        %rcx, %r9
    sbbq        $0, %r13

    addq        $-1, %r8                        // a - b + P
    movq        %rdx, %r10
    adcq        %r14, %r9
    adcq        $0, %r10
    movq        %r12, %r11
    adcq        %r15, %r11
    testq       %r13, %r13

    cmovzq      %rax, %r8
    cmovzq      %rcx, %r9
    cmovzq      %rdx, %r10
    cmovzq      %r12, %r11                      // output: r8-r11 P[1] --> r14 P[3] --> r15

    /* X3/4 = (r^2 - 2 * V - J)/4 = (r^2 - 2 * V)/4 - J/4 */
    leaq        160(%rsp), %rdx                 // read J/4 from stack
    leaq        224(%rsp), %rdi                 // save (r^2 - 2 * V - J)/4 to stack
    call        ECP256_SubCore                  // output: r8-r11 P[1] --> r14 P[3] --> r15
    movq        %r8, (%rdi)                     // b[0]
    movq        %r9, 8(%rdi)                    // b[1]
    movq        %r10, 16(%rdi)                  // b[2]
    movq        %r11, 24(%rdi)                  // b[3]

    /* (V - X3)/4 = V/4 - X3/4 */
    leaq        (%rsp), %rsi                    // read (r^2 - 2 * V)/4 from stack
    xorq        %r13, %r13
    movq        (%rsi), %rax                    // a[0]
    movq        8(%rsi), %rcx                   // a[1]
    movq        16(%rsi), %rdx                  // a[2]
    movq        24(%rsi), %r12                  // a[3]

    subq        %r8, %rax
    sbbq        %r9, %rcx
    movq        %rax, %r8
    sbbq        %r10, %rdx
    sbbq        %r11, %r12
    movq        %rcx, %r9
    sbbq        $0, %r13
    movq        %rdx, %r10
    movq        %r12, %r11

    addq        $-1, %r8                        // a - b + P
    adcq        %r14, %r9
    adcq        $0, %r10
    adcq        %r15, %r11
    testq       %r13, %r13

    cmovzq      %rax, %r8
    cmovzq      %rcx, %r9
    cmovzq      %rdx, %r10
    cmovzq      %r12, %r11

    leaq        64(%rsp), %rdi                  // save (V - X3)/4 from stack
    movq        %r8, (%rdi)
    movq        %r9, 8(%rdi)
    movq        %r10, 16(%rdi)
    movq        %r11, 24(%rdi)                  // output: r8-r11 P[1] --> r14 P[3] --> r15

    /* (J * Y1)/4 = Y1 * J/4  */
    leaq        352(%rsp), %rcx                 // read Y1 from stack
    leaq        160(%rsp), %rsi                 // read J/4 from stack
    leaq        32(%rsp), %rdi                  // save (J * Y1)/4 to stack
    call        ECP256_MulCore_q                // output: r8-r11 P[1] --> r14 P[3] --> r15

    /* (r * (V - X3)/8) = (V - X3)/4 * r/2 */
    leaq        96(%rsp), %rcx                  // read r/2 from stack
    leaq        64(%rsp), %rsi                  // read (V - X3)/4 from stack
    leaq        64(%rsp), %rdi                  // save (r * (V - X3)/8) to stack
    call        ECP256_MulCore_q                // output: r8-r11 P[1] --> r14 P[3] --> r15

    /* Y3/8 =  (r * (V - X3)/8) - (J * Y1)/4 */
    leaq        32(%rsp), %rdx                  // read (J * Y1)/4 from stack
    leaq        256(%rsp), %rdi                 // save Y3/8
    call        ECP256_SubCore
    movq        %r8, (%rdi)
    movq        %r9, 8(%rdi)
    movq        %r10, 16(%rdi)
    movq        %r11, 24(%rdi)

    vmovq       %xmm0, %rdi

    vmovdqa     %xmm5, %xmm0
    vmovdqa     %xmm5, %xmm1
    vpandn      288(%rsp), %xmm0, %xmm0
    vmovdqa     %xmm5, %xmm2
    vpandn      304(%rsp), %xmm1, %xmm1
    vmovdqa     %xmm5, %xmm3
    vpand       .Lone_mont(%rip), %xmm2, %xmm2
    vpand       .Lone_mont+16(%rip), %xmm3, %xmm3
    vpor        %xmm0, %xmm2, %xmm2
    vpor        %xmm1, %xmm3, %xmm3

    vmovdqa     %xmm4, %xmm0
    vmovdqa     %xmm4, %xmm1
    vpandn      %xmm2, %xmm0, %xmm0
    vmovdqa     %xmm4, %xmm2
    vpandn      %xmm3, %xmm1, %xmm1
    vmovdqa     %xmm4, %xmm3
    vpand       384(%rsp), %xmm2, %xmm2
    vpand       400(%rsp), %xmm3, %xmm3
    vpor        %xmm0, %xmm2, %xmm2
    vpor        %xmm1, %xmm3, %xmm3
    vmovdqu     %xmm2, 64(%rdi)
    vmovdqu     %xmm3, 80(%rdi)

    vmovdqa	    %xmm5, %xmm0
	vmovdqa	    %xmm5, %xmm1
	vpandn	    224(%rsp), %xmm0, %xmm0
	vmovdqa	    %xmm5, %xmm2
	vpandn	    224+16(%rsp), %xmm1, %xmm1
	vmovdqa	    %xmm5, %xmm3
	vpand	    416(%rsp), %xmm2, %xmm2
	vpand	    416+16(%rsp), %xmm3, %xmm3
	vpor	    %xmm0, %xmm2, %xmm2
	vpor	    %xmm1, %xmm3, %xmm3

	vmovdqa	    %xmm4, %xmm0
	vmovdqa	    %xmm4, %xmm1
	vpandn	    %xmm2, %xmm0, %xmm0
	vmovdqa	    %xmm4, %xmm2
	vpandn	    %xmm3, %xmm1, %xmm1
	vmovdqa	    %xmm4, %xmm3
	vpand	    320(%rsp), %xmm2, %xmm2
	vpand	    336(%rsp), %xmm3, %xmm3
	vpor	    %xmm0, %xmm2, %xmm2
	vpor	    %xmm1, %xmm3, %xmm3
	vmovdqu	    %xmm2, 0(%rdi)
	vmovdqu	    %xmm3, 16(%rdi)

	vmovdqa	    %xmm5, %xmm0
	vmovdqa	    %xmm5, %xmm1
	vpandn	    256(%rsp), %xmm0, %xmm0
	vmovdqa	    %xmm5, %xmm2
	vpandn	    272(%rsp), %xmm1, %xmm1
	vmovdqa	    %xmm5, %xmm3
	vpand	    448(%rsp), %xmm2, %xmm2
	vpand	    464(%rsp), %xmm3, %xmm3
	vpor	    %xmm0, %xmm2, %xmm2
	vpor	    %xmm1, %xmm3, %xmm3

	vmovdqa	    %xmm4, %xmm0
	vmovdqa	    %xmm4, %xmm1
	vpandn	    %xmm2, %xmm0, %xmm0
	vmovdqa	    %xmm4, %xmm2
	vpandn	    %xmm3, %xmm1, %xmm1
	vmovdqa	    %xmm4, %xmm3
	vpand	    352(%rsp), %xmm2, %xmm2
	vpand	    368(%rsp), %xmm3, %xmm3
	vpor	    %xmm0, %xmm2, %xmm2
	vpor	    %xmm1, %xmm3, %xmm3
	vmovdqu	    %xmm2, 32(%rdi)
	vmovdqu	    %xmm3, 48(%rdi)

    addq        $488, %rsp
    popq        %r15
    popq        %r14
    popq        %r13
    popq        %r12
    popq        %rbx
    popq        %rbp
    ret
.cfi_endproc
.size   ECP256_AddAffine, .-ECP256_AddAffine

/**
 *  Function description: This interface is used to store the G-16G pre-computation table discretely.
 *  Function prototype: void ECP256_Scatterw5(P256_Point *table, const P256_Point *point, uint32_t index);
 *  Input register:
 *        rdi: Points to the base address of the pre-computation table.
 *        rsi: Points to P256_Point.
 *        rdx: Index value. The value ranges from 1 to 16.
 *  Change register: rdx, rsi, rdi, r8, r9, r10, r11
 *  Output register: None
 *  Function/Macro Call:
 */
.globl  ECP256_Scatterw5
.type   ECP256_Scatterw5,@function
.align 32
ECP256_Scatterw5:
.cfi_startproc
    subq    $1, %rdx                // index - 1
    movq    (%rsi), %r8             // x[0]
    movq    8(%rsi), %r9            // x[1]
    movq    16(%rsi), %r10          // x[2]
    movq    24(%rsi), %r11          // x[3]
    leaq    (%rdi, %rdx, 8), %rdi   // base = base + (index - 1) * 8 . offset for table

    movq    %r8, (%rdi)             // x[0] --> base + 0 * 128
    movq    %r9, 128(%rdi)          // x[1] --> base + 1 * 128
    movq    %r10, 256(%rdi)         // x[2] --> base + 2 * 128
    movq    %r11, 384(%rdi)         // x[3] --> base + 3 * 128
    leaq    512(%rdi), %rdi         // base + 128 * 4

    leaq    32(%rsi), %rsi          // addr(y) --> rsi

    movq    (%rsi), %r8             // y[0]
    movq    8(%rsi), %r9            // y[1]
    movq    16(%rsi), %r10          // y[2]
    movq    24(%rsi), %r11          // y[3]

    movq    %r8, (%rdi)             // y[0] --> base + 4 * 128
    movq    %r9, 128(%rdi)          // y[1] --> base + 5 * 128
    movq    %r10, 256(%rdi)         // y[2] --> base + 6 * 128
    movq    %r11, 384(%rdi)         // y[3] --> base + 7 * 128
    leaq    512(%rdi), %rdi         // base + 128 * 8

    leaq    32(%rsi), %rsi          // addr(z) --> rsi

    movq    (%rsi), %r8             // z[0]
    movq    8(%rsi), %r9            // z[1]
    movq    16(%rsi), %r10          // z[2]
    movq    24(%rsi), %r11          // z[3]

    movq    %r8, (%rdi)             // z[0] --> base + 8 * 128
    movq    %r9, 128(%rdi)          // z[1] --> base + 9 * 128
    movq    %r10, 256(%rdi)         // z[2] --> base + 10 * 128
    movq    %r11, 384(%rdi)         // z[3] --> base + 11 * 128

    ret
.cfi_endproc
.size   ECP256_Scatterw5, .-ECP256_Scatterw5

/**
 *  Function description: This interface is used to obtain the G-16G pre-computation table discretely.
 *  Function prototype: void ECP256_Gatherw5(P256_Point *point, const P256_Point *table, uint32_t index);
 *  Input register:
 *        rdi: points to P256_Point.
 *        rsi: points to the base address of the pre-computation table.
 *        edx: index value
 *  Change register: edx, rsi, rdi, r8, r9, r10, r11
 *  Output register: None
 *  Function/Macro Call:
 */
.globl  ECP256_Gatherw5
.type   ECP256_Gatherw5,@function
.align 32
ECP256_Gatherw5:
.cfi_startproc
    movq    $-1, %rax
    xorq    %rcx, %rcx
    cmp     $0, %rdx
    cmovzq  %rcx, %rax              // rax = (rdx == 0) ? 0 : -1
    add     %rax, %rdx              // rdx = (rdx == 0) ? rdx : (rdx - 1)

    leaq    (%rsi, %rdx, 8), %rsi   // Calculate offset. base = base + (index -1) * 8

    movq    (%rsi), %r8             // x[0]
    movq    128(%rsi), %r9          // x[1]
    movq    256(%rsi), %r10         // x[2]
    movq    384(%rsi), %r11         // x[3]
    leaq    512(%rsi), %rsi         // base += 512

    andq    %rax, %r8
    andq    %rax, %r9
    andq    %rax, %r10
    andq    %rax, %r11

    movq    %r8, (%rdi)             // Write back
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    leaq    32(%rdi), %rdi          // Write back point offset

    movq    (%rsi), %r8             // y[0]
    movq    128(%rsi), %r9          // y[1]
    movq    256(%rsi), %r10         // y[2]
    movq    384(%rsi), %r11         // y[3]
    leaq    512(%rsi), %rsi         // base += 512

    andq    %rax, %r8
    andq    %rax, %r9
    andq    %rax, %r10
    andq    %rax, %r11

    movq    %r8, (%rdi)             // Write back
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    leaq    32(%rdi), %rdi          // Write back point offset

    movq    (%rsi), %r8             // z[0]
    movq    128(%rsi), %r9          // z[1]
    movq    256(%rsi), %r10         // z[2]
    movq    384(%rsi), %r11         // z[3]

    andq    %rax, %r8
    andq    %rax, %r9
    andq    %rax, %r10
    andq    %rax, %r11

    movq    %r8, (%rdi)             // Write back
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    ret
.cfi_endproc
.size   ECP256_Gatherw5, .-ECP256_Gatherw5

/**
 *  Function description: Discretely obtains affine points in the precomputation table.
 *  Function prototype: void ECP256_Gatherw7(P256_AffinePoint *point, const P256_AffinePoint *table, uint32_t index);
 *  Input register:
 *        rdi: points to the returned P256_AffinePoint.
 *        rsi: points to the base address of the pre-computation table.
 *        rdx: index value
 *  Change register: rax, rcx, rdx, rsi, rdi, rbp, r8, r9, r10
 *  Output register: None
 *  Function/Macro Call:
 */
.globl  ECP256_Gatherw7
.type   ECP256_Gatherw7,@function
.align 32
ECP256_Gatherw7:
.cfi_startproc
    movq    $-1, %rax
    xorq    %rcx, %rcx
    cmp     $0, %rdx
    cmovzq  %rcx, %rax          // rax = (rdx == 0) ? 0 : -1
    addq    %rax, %rdx          // rdx = (rdx == 0) ? rdx : (rdx - 1)
    subq    $63, %rdx           // rdx = (rdx == 0) ? (rdx - 63) : (rdx - 1 - 63)
    subq    %rdx, %rsi          // rsi = (rdx == 0) ? (rsi + 63 - rdx) : (rsi + 64 - rdx)
    movq    $8, %r10            // Loop value

.Lgather_w7_loop:
    xorq    %r8, %r8            // Empty reg for data low 32
    xorq    %r9, %r9            // Empty reg for data high 32
    movb    192(%rsi), %r8b     // r8 = [0 0 0 byte(3)]
    movb    448(%rsi), %r9b     // r9 = [0 0 0 byte(7)]
    shlq    $8, %r8             // r8 = [0 0 byte(3) 0]
    shlq    $8, %r9             // r9 = [0 0 byte(7) 0]
    movb    128(%rsi), %r8b     // r8 = [0 0 byte(3) byte(2)]
    movb    384(%rsi), %r9b     // r9 = [0 0 byte(7) byte(6)]
    shlq    $8, %r8             // r8 = [0 byte(3) byte(2) 0]
    shlq    $8, %r9             // r9 = [0 byte(7) byte(6) 0]
    movb    64(%rsi), %r8b      // r8 = [0 byte(3) byte(2) byte(1)]
    movb    320(%rsi), %r9b     // r9 = [0 byte(7) byte(6) byte(5)]
    shlq    $8, %r8             // r8 = [byte(3) byte(2) byte(1) 0]
    shlq    $8, %r9             // r9 = [byte(7) byte(6) byte(5) 0]
    movb    (%rsi), %r8b        // r8 = [byte(3) byte(2) byte(1) byte(0)]
    movb    256(%rsi), %r9b     // r9 = [byte(7) byte(6) byte(5) byte(4)]
    leaq    512(%rsi), %rsi     // base += 64 * 8
    shlq    $32, %r9            // r9 = [byte(7) byte(6) byte(5) byte(4) 0 0 0 0]
    orq     %r9, %r8            // r8 = [byte(7) byte(6) byte(5) byte(4) byte(3) byte(2) byte(1) byte(0)]

    andq    %rax, %r8
    movq    %r8, (%rdi)
    leaq    8(%rdi), %rdi

    subq    $1, %r10
    jnz     .Lgather_w7_loop

    ret
.cfi_endproc
.size   ECP256_Gatherw7, .-ECP256_Gatherw7

#endif
