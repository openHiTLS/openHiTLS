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
#ifdef HITLS_CRYPTO_BN

.file   "bn_mont_x86_64.S"
.text

.macro  ADD_CARRY a b
    addq    \a,\b
    adcq    $0,%rdx
.endm

.macro  SAVE_REGISTERS
    pushq   %r15                        // Save non-volatile register.
    pushq   %r14
    pushq   %r13
    pushq   %r12
    pushq   %rbp
    pushq   %rbx
.endm

.macro  RESTORE_REGISTERS
    popq    %rbx              // Restore non-volatile register.
    popq    %rbp
    popq    %r12
    popq    %r13
    popq    %r14
    popq    %r15
.endm

/*
* void MontMul_Asm(uint64_t *r, const uint64_t *a, const uint64_t *b,
*                     const uint64_t *n, const uint64_t k0, uint32_t size);
*/
.globl  MontMul_Asm
.type   MontMul_Asm,@function
.align  16
MontMul_Asm:
.cfi_startproc
    testl   $3,%r9d
    jnz     .LMontMul                   // If size is not divisible by 4, LMontMul.
    cmpl    $8,%r9d
    jb      .LMontMul                   // LMontMul
    cmpq    %rsi,%rdx
    jne     MontMul4                    // if a != b, MontMul4
    testl   $7,%r9d
    jz      MontSqr8                    // If size is divisible by 8，enter MontSqr8.
    jmp     MontMul4

.align  16
.LMontMul:
    SAVE_REGISTERS                          // Save non-volatile register.
    movq    %rsp,%rax                       // rax stores the rsp

    movq    %r9, %r15
    negq    %r15                            // r15 = -size
    leaq    -16(%rsp, %r15, 8), %r15        // r15 = rsp - size * 8 - 16
    andq    $-1024, %r15                    // r15 The address is aligned down by 1 KB.
    movq    %rsp, %r14                      // r14 = rsp

    subq    %r15,%r14                       // __chkstk implemention, called when the stack size needs to exceed 4096.
                                            // (the size of a page) to allocate more pages.
    andq    $-4096,%r14                     // r14 4K down-align.
    leaq    (%r15,%r14),%rsp                // rsp = r15 + r14
    cmpq    %r15,%rsp                       // If you want to allocate more than one page, go to Lmul_page_walk.
    ja      .LoopPage
    jmp     .LMulBody

.align  16
.LoopPage:
    leaq    -4096(%rsp),%rsp            // rsp - 4096 each time until rsp < r15.
    cmpq    %r15,%rsp
    ja      .LoopPage

.LMulBody:
    movq    %rax,8(%rsp,%r9,8)          // Save the original rsp in the stack.
    movq    %rdx,%r13                   // r13 = b

    xorq    %r11,%r11                   // r11 = 0
    xorq    %r10,%r10                   // r10 = 0

    movq    (%r13),%rbx                 // rbx = b[0]
    movq    (%rsi),%rax                 // rax = a[0]
    mulq    %rbx                        // (rdx, rax) = a[0] * b[0]
    movq    %rax,%r15                   // r15 = t[0] = lo(a[0] * b[0])
    movq    %rdx,%r14                   // r14 = hi(a[0] * b[0])

    movq    %r8,%rbp                    // rbp = k0
    imulq   %r15,%rbp                   // rbp = t[0] * k0
    movq    (%rcx),%rax                 // rax = n[0]
    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[0]
    ADD_CARRY    %rax,%r15              // r15 = lo(t[0] * k0 * n[0]) + t[0]

    leaq    1(%r10),%r10                // j++

.Loop1st:
    movq    (%rsi,%r10,8),%rax          // rax = a[j]
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[0])

    mulq    %rbx                        // (rdx, rax) = a[j] * b[0]
    ADD_CARRY    %rax,%r14              // r14 = hi(a[j - 1] * b[0]) + lo(a[j] * b[0])
    movq    %rdx,%r15                   // r15 = hi(a[j] * b[0])

    movq    (%rcx,%r10,8),%rax          // rax = n[j]
    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j]
    leaq    1(%r10),%r10                // j++
    cmpq    %r9,%r10                    // if j != size, loop L1st
    je      .Loop1stSkip

    ADD_CARRY    %rax,%r12              // r12 = hi(t[0] * k0 * n[j]) + lo(t[0] * k0 * n[j])
    ADD_CARRY    %r14,%r12              // r12 += lo(a[j] * b[0]) + hi(a[j] * b[0])
    movq    %r12,-16(%rsp,%r10,8)       // t[j - 2] = r13
    movq    %r15,%r14                   // r14 = hi(a[j] * b[0])
    jmp     .Loop1st

.Loop1stSkip:
    ADD_CARRY    %rax,%r12              // r12 = hi(t[0] * k0 * n[j - 1]) + lo(t[0] * k0 * n[j])
    ADD_CARRY    %r14,%r12              // r12 += hi(a[j - 1] * b[0]) + lo(a[j] * b[0])
    movq    %r12,-16(%rsp,%r10,8)       // t[j - 2] = r13
    movq    %r15,%r14                   // r14 = hi(a[j] * b[0])

    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[j])
    xorq    %rdx,%rdx                   // rdx = 0, Clearing the CF.
    ADD_CARRY    %r14,%r12              // r12 = hi(t[0] * k0 * n[j]) + hi(a[j] * b[0])
    movq    %r12,-8(%rsp,%r9,8)         // t[size - 1] = hi(t[0] * k0 * n[j]) + hi(a[j] * b[0]), save overflow bit.
    movq    %rdx,(%rsp,%r9,8)

    leaq    1(%r11),%r11                // i++

.align  16
.LoopOuter:
    xorq    %r10,%r10                   // j = 0
    movq    (%rsi),%rax                 // rax = a[0]
    movq    (%r13,%r11,8),%rbx          // rbx = b[i]
    mulq    %rbx                        // (rdx, rax) = a[0] * b[i]
    movq    (%rsp),%r15                 // r15 = lo(a[0] * b[i]) + t[0]
    ADD_CARRY    %rax,%r15
    movq    %rdx,%r14                   // r14 = hi(a[0] * b[i])

    movq    %r8,%rbp                    // rbp = t[0] * k0
    imulq   %r15,%rbp
    movq    (%rcx),%rax                 // rax = n[0]
    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[0]
    ADD_CARRY    %rax,%r15              // r15 = lo(t[0] * k0 * n[0])

    leaq    1(%r10),%r10                // j++

.align  16
.LoopInner:
    movq    (%rsi,%r10,8),%rax          // rax = a[j]
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[j])
    movq    (%rsp,%r10,8),%r15          // r15 = t[j]

    mulq    %rbx                        // (rdx, rax) = a[1] * b[i]
    ADD_CARRY    %rax,%r14              // r14 = hi(a[0] * b[i]) + lo(a[1] * b[i])
    movq    (%rcx,%r10,8),%rax          // rax = n[j]
    ADD_CARRY    %r14,%r15              // r15 = a[j] * b[i] + t[j]
    movq    %rdx,%r14
    leaq    1(%r10),%r10                // j++

    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j]
    cmpq    %r9,%r10                    // if j != size, loop Linner
    je      .LoopInnerSkip

    ADD_CARRY    %rax,%r12              // r12 = t[0] * k0 * n[j]
    ADD_CARRY    %r15,%r12              // r12 = a[j] * b[i] + t[j] + n[j] * t[0] * k0
    movq    %r12,-16(%rsp,%r10,8)       // t[j - 2] = r13
    jmp     .LoopInner

.LoopInnerSkip:
    ADD_CARRY    %rax,%r12              // r12 = t[0] * k0 * n[j]
    ADD_CARRY    %r15,%r12              // r12 = t[0] * k0 * n[j] + a[j] * b[i] + t[j]
    movq    (%rsp,%r10,8),%r15          // r15 = t[j]
    movq    %r12,-16(%rsp,%r10,8)       // t[j - 2]
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[j])

    xorq    %rdx,%rdx                   // rdx 0
    ADD_CARRY    %r14,%r12              // r12 = hi(a[1] * b[i]) + hi(t[0] * k0 * n[j])
    ADD_CARRY    %r15,%r12              // r12 += t[j]
    movq    %r12,-8(%rsp,%r9,8)         // t[size - 1] = r13
    movq    %rdx,(%rsp,%r9,8)           // t[size] = CF

    leaq    1(%r11),%r11                // i++
    cmpq    %r9,%r11                    // if size < i (unsigned)
    jne     .LoopOuter

    xorq    %r11,%r11                   // r11 = 0, clear CF.
    movq    (%rsp),%rax                 // rax = t[0]
    movq    %r9,%r10                    // r10 = size

.align  16
.LoopSub:
    sbbq    (%rcx,%r11,8),%rax          // r[i] = t[i] - n[i]
    movq    %rax,(%rdi,%r11,8)
    movq    8(%rsp,%r11,8),%rax         // rax = t[i + 1]

    leaq    1(%r11),%r11                // i++
    decq    %r10                        // j--
    jnz     .LoopSub                    // if j != 0

    sbbq    $0,%rax                     // rax -= CF
    movq    $-1,%rbx
    xorq    %rax,%rbx                   // rbx = !t[i + 1]
    xorq    %r11,%r11                   // r11 = 0
    movq    %r9,%r10                    // r10 = size

.LoopCopy:
    movq    (%rdi,%r11,8),%rcx          // rcx = r[i] & t[i]
    andq    %rbx,%rcx
    movq    (%rsp,%r11,8),%rdx          // rdx = CF & t[i]
    andq    %rax,%rdx
    orq     %rcx,%rdx
    movq    %rdx,(%rdi,%r11,8)          // r[i] = t[i]
    movq    %r9,(%rsp,%r11,8)           // t[i] = size
    leaq    1(%r11),%r11                // i++
    subq    $1,%r10                     // j--
    jnz     .LoopCopy                   // if j != 0

    movq    8(%rsp,%r9,8),%rsi          // rsi = pressed-stacked rsp.
    movq    $1,%rax                     // rax = 1
    leaq    (%rsi),%rsp                 // restore rsp.
    RESTORE_REGISTERS                   // Restore non-volatile register.
    ret
.cfi_endproc
.size   MontMul_Asm,.-MontMul_Asm

.type   MontMul4,@function
.align  16
MontMul4:
.cfi_startproc
    SAVE_REGISTERS
    movq    %rsp,%rax                   // save rsp

    movq    %r9,%r15
    negq    %r15
    leaq    -32(%rsp,%r15,8),%r15       // Allocate space: size * 8 + 32 bytes.
    andq    $-1024,%r15
    movq    %rsp,%r14

    subq    %r15,%r14                   // __chkstk implemention, called when the stack size needs to exceed 4096.
    andq    $-4096,%r14
    leaq    (%r15,%r14),%rsp
    cmpq    %r15,%rsp                   // If you want to allocate more than one page, go to LoopPage4x.
    ja      .LoopPage4x
    jmp     .LoopMul4x

.LoopPage4x:
    leaq    -4096(%rsp),%rsp            // rsp - 4096each time until rsp >= r10.
    cmpq    %r15,%rsp
    ja      .LoopPage4x

.LoopMul4x:
    xorq    %r11,%r11                   // i = 0
    xorq    %r10,%r10                   // j = 0

    movq    %rax,8(%rsp,%r9,8)
    movq    %rdi,16(%rsp,%r9,8)         // t[size + 2] = r
    movq    %rdx,%r13                   // r13 = b
    movq    (%rsi),%rax                 // rax = a[0]
    movq    %r8,%rbp                    // rbp = k0
    movq    (%r13),%rbx                 // rbx = b[0]

    /* 计算a[i] * b[0] * k[0] * n[j] */
    mulq    %rbx                        // (rdx, rax) = a[0] * b[0]
    movq    %rax,%r15                   // r15 = t[0] = lo(b[0] * a[0])
    movq    (%rcx),%rax                 // rax = n[0]

    imulq   %r15,%rbp                   // rbp = t[0] * k0
    movq    %rdx,%r14                   // r14 = hi(a[0] * b[0])

    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[0]
    ADD_CARRY    %rax,%r15              // r15 = lo(t[0] * k0 * n[0])
    movq    8(%rsi),%rax                // rax = a[1]
    movq    %rdx,%rdi                   // rdi = hi(t[0] * k0 * n[0])

    mulq    %rbx                        // (rdx, rax) = a[1] * b[0]
    ADD_CARRY    %rax,%r14              // r14 = lo(a[1] * b[0]) + hi(a[0] * b[0])
    movq    8(%rcx),%rax                // rax = n[1]
    movq    %rdx,%r15                   // r15 = hi(a[1] * b[0])

    mulq    %rbp                        // (rdx, rax) =  t[0] * k0 * n[1]
    ADD_CARRY    %rax,%rdi              // rdi = lo(t[0] * k0 * n[1]) + hi(t[0] * k0 * n[0])
    movq    16(%rsi),%rax               // rax = a[2]
    ADD_CARRY    %r14,%rdi              // rdi += hi(a[0] * b[0]) + lo(a[1] * b[0])
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[1])
    movq    %rdi,(%rsp)                 // t[0] = rdi

    leaq    4(%r10),%r10                // j += 4

.align  16
.Loop1st4x:
    mulq    %rbx                        // (rdx, rax) = a[2] * b[0]
    ADD_CARRY    %rax,%r15              // r15 = hi(a[1] * b[0]) + lo(a[2] * b[0])
    movq    -16(%rcx,%r10,8),%rax       // rax = n[j - 2]
    movq    %rdx,%r14                   // r14 = hi[a[2] * b[0]]

    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j - 2]
    ADD_CARRY    %rax,%r12              // r12 = hi(t[0] * k0 * n[1]) + lo(t[0] * k0 * n[j - 2])
    movq    -8(%rsi,%r10,8),%rax        // rax = a[j - 1]
    ADD_CARRY    %r15,%r12              // r12 += hi(a[1] * b[0]) + lo(a[2] * b[0])
    movq    %r12,-24(%rsp,%r10,8)       // t[j - 3] = r13
    movq    %rdx,%rdi                   // rdi = hi(t[0] * k0 * n[j - 2])

    mulq    %rbx                        // (rdx, rax) = a[j - 1] * b[0]
    ADD_CARRY    %rax,%r14              // r14 = hi[a[2] * b[0]] + lo(a[j - 1] * b[0])
    movq    -8(%rcx,%r10,8),%rax        // rax = n[j - 1]
    movq    %rdx,%r15                   // r15 = hi(a[j - 1] * b[0])

    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j - 1]
    ADD_CARRY    %rax,%rdi              // rdi = hi(t[0] * k0 * n[j - 2]) + lo(t[0] * k0 * n[j - 1]
    movq    (%rsi,%r10,8),%rax          // rax = a[j]
    ADD_CARRY    %r14,%rdi              // rdi += hi[a[2] * b[0]] + lo(a[j - 1] * b[0])
    movq    %rdi,-16(%rsp,%r10,8)       // t[j - 2] = rdi
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[j - 1])

    mulq    %rbx                        // (rdx, rax) = a[j] * b[0]
    ADD_CARRY    %rax,%r15              // r15 = hi(a[j - 1] * b[0]) + lo(a[j] * b[0])
    movq    (%rcx,%r10,8),%rax          // rax = n[j]
    movq    %rdx,%r14                   // r14 = hi(a[j] * b[0])

    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j]
    ADD_CARRY    %rax,%r12              // r12 = hi(t[0] * k0 * n[j - 1]) + lo(t[0] * k0 * n[j])
    movq    8(%rsi,%r10,8),%rax         // rax = a[j + 1]
    ADD_CARRY    %r15,%r12              // r12 +=  hi(a[j - 1] * b[0]) + lo(a[j] * b[0])
    movq    %r12,-8(%rsp,%r10,8)        // t[j - 1] = r13
    movq    %rdx,%rdi                   // rdi = hi(t[0] * k0 * n[j])

    mulq    %rbx                        // (rdx, rax) = a[j + 1] * b[0]
    ADD_CARRY    %rax,%r14              // r14 = hi(a[j] * b[0]) + lo(a[j + 1] * b[0])
    movq    8(%rcx,%r10,8),%rax         // rax = n[j + 1]
    movq    %rdx,%r15                   // r15 = hi(a[j + 1] * b[0])

    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j + 1]
    ADD_CARRY    %rax,%rdi                  // rdi = hi(t[0] * k0 * n[j]) + lo(t[0] * k0 * n[j + 1])
    movq    16(%rsi,%r10,8),%rax        // rax = a[j + 2]
    ADD_CARRY    %r14,%rdi                  // rdi += hi(a[j] * b[0]) + lo(a[j + 1] * b[0])
    movq    %rdi,(%rsp,%r10,8)          // t[j - 4] = rdi
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[j + 1])

    leaq    4(%r10),%r10                // j += 4
    cmpq    %r9,%r10                    // if size != j
    jb      .Loop1st4x

    mulq    %rbx                        // (rdx, rax) = a[j - 2] * b[0]
    ADD_CARRY    %rax,%r15              // r15 = hi(a[j - 3] * b[0]) + lo(a[j - 2] * b[0])
    movq    -16(%rcx,%r10,8),%rax       // rax = n[j - 2]
    movq    %rdx,%r14                   // r14 = hi(a[j - 2] * b[0])

    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j - 2]
    ADD_CARRY    %rax,%r12              // r12 = hi(t[0] * k0 * n[j - 3]) + lo(t[0] * k0 * n[j - 2])
    movq    -8(%rsi,%r10,8),%rax        // rax = a[j - 1]
    ADD_CARRY    %r15,%r12              // r12 += hi(a[j - 3] * b[0]) + lo(a[j - 2] * b[0])
    movq    %r12,-24(%rsp,%r10,8)       // t[j - 3] = r13
    movq    %rdx,%rdi                   // rdi = hi(t[0] * k0 * n[j - 2])

    mulq    %rbx                        // (rdx, rax) =  a[j - 1] * b[0]
    ADD_CARRY    %rax,%r14              // r14 = hi(a[j - 2] * b[0]) + lo(a[j- 1] * b[0])
    movq    -8(%rcx,%r10,8),%rax        // rax = n[j - 1]
    movq    %rdx,%r15                   // r15 = hi(a[j - 1] * b[0])

    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j - 1]
    ADD_CARRY    %rax,%rdi              // rdi = hi(t[0] * k0 * n[j - 2]) + lo(t[0] * k0 * n[j - 1])
    ADD_CARRY    %r14,%rdi              // rdi +=  hi(a[j - 2] * b[0]) + lo(a[j- 1] * b[0])
    movq    %rdi,-16(%rsp,%r10,8)       // t[j - 2] = rdi
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[j - 1])

    xorq    %rdx,%rdx                   // rdx = 0
    ADD_CARRY    %r15,%r12              // r12 = hi(a[j - 1] * b[0]) + hi(t[0] * k0 * n[j - 1])
    movq    %r12,-8(%rsp,%r10,8)        // t[j - 1] = r13
    movq    %rdx,(%rsp,%r10,8)          // t[j] = CF

    leaq    1(%r11),%r11                // i++
.align  4
.LoopOuter4x:
    /* Calculate a[i] * b + q * N */
    movq    (%rsi),%rax                 // rax = a[0]
    movq    (%r13,%r11,8),%rbx          // rbx = b[i]
    xorq    %r10,%r10                   // j = 0
    movq    (%rsp),%r15                 // r15 = t[0]
    movq    %r8,%rbp                    // rbp = k0
    mulq    %rbx                        // (rdx, rax) = a[0] * b[i]
    ADD_CARRY    %rax,%r15              // r15 = lo(a[0] * b[i]) + t[0]
    movq    (%rcx),%rax                 // rax = n[0]

    imulq   %r15,%rbp                   // rbp = t[0] * k0
    movq    %rdx,%r14                   // r14 = hi[a[0] * b[i]]

    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[0]
    ADD_CARRY    %rax,%r15              // r15 = lo(t[0] * k0 * n[0])
    movq    8(%rsi),%rax                // rax = a[1]
    movq    %rdx,%rdi                   // rdi = hi(t[0] * k0 * n[0])

    mulq    %rbx                        // (rdx, rax) = a[1] * b[i]
    ADD_CARRY    %rax,%r14              // r14 = hi[a[0] * b[i]] + lo(a[1] * b[i])
    movq    8(%rcx),%rax                // rax = n[1]
    ADD_CARRY    8(%rsp),%r14           // r14 = t[1]
    movq    %rdx,%r15                   // r15 = hi(a[1] * b[i])

    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[1]
    ADD_CARRY    %rax,%rdi              // rdi = hi(t[0] * k0 * n[0]) + lo(t[0] * k0 * n[1])
    movq    16(%rsi),%rax               // rax = a[2]
    ADD_CARRY    %r14,%rdi              // rdi += t[1]
    leaq    4(%r10),%r10                // j += 4
    movq    %rdi,(%rsp)                 // t[0] = rdi
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[1])

.align  16
.Linner4x:
    mulq    %rbx                        // (rdx, rax) = a[2] * b[i]
    ADD_CARRY    %rax,%r15              // r15 = hi(a[1] * b[i]) + lo(a[2] * b[i])
    addq    -16(%rsp,%r10,8),%r15       // r15 = t[j - 2]
    adcq    $0,%rdx

    movq    -16(%rcx,%r10,8),%rax       // rax = n[j - 2]
    movq    %rdx,%r14                   // r14 = hi(a[2] * b[i])
    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j - 2]
    ADD_CARRY    %rax,%r12              // r12 = hi(t[0] * k0 * n[j - 3]) * lo(t[0] * k0 * n[j - 2])
    ADD_CARRY    %r15,%r12              // r12 += t[j - 2]
    movq    %r12,-24(%rsp,%r10,8)       // t[j - 3] = r13
    movq    %rdx,%rdi                   // rdi = hi(t[0] * k0 * n[j - 2])

    movq    -8(%rsi,%r10,8),%rax        // rax = a[j - 1]
    mulq    %rbx                        // (rdx, rax) = a[j - 1] * b[i]
    ADD_CARRY    %rax,%r14              // r14 = lo(a[j - 1] * b[i])
    addq    -8(%rsp,%r10,8),%r14        // r14 += t[j - 1]
    adcq    $0,%rdx
    movq    %rdx,%r15                   // r15 = hi(a[j - 1] * b[i])

    movq    -8(%rcx,%r10,8),%rax        // rax = n[j - 1]
    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j - 1]
    ADD_CARRY    %rax,%rdi              // rdi = hi(t[0] * k0 * n[j - 2]) + lo(t[0] * k0 * n[j - 1])
    ADD_CARRY    %r14,%rdi              // rdi += t[j - 1]
    movq    %rdi,-16(%rsp,%r10,8)       // t[j - 2] = rdi
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[j - 1])

    movq    (%rsi,%r10,8),%rax          // rax = a[j]
    mulq    %rbx                        // (rdx, rax) = a[j] * b[i]
    ADD_CARRY    %rax,%r15              // r15 = hi(a[j - 1] * b[i]) + lo(a[j] * b[i])
    addq    (%rsp,%r10,8),%r15          // r15 = t[j]
    adcq    $0,%rdx
    movq    %rdx,%r14                   // r14 = hi(a[j] * b[i])

    movq    (%rcx,%r10,8),%rax          // rax = n[j]
    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j]
    ADD_CARRY    %rax,%r12              // r12 = hi(t[0] * k0 * n[j - 1]) + lo(t[0] * k0 * n[j])
    ADD_CARRY    %r15,%r12              // r12 += t[j]
    movq    %r12,-8(%rsp,%r10,8)        // t[j - 1] = r13
    movq    %rdx,%rdi                   // rdi = hi(t[0] * k0 * n[j])

    movq    8(%rsi,%r10,8),%rax         // rax = a[j + 1]
    mulq    %rbx                        // (rdx, rax) = a[j + 1] * b[i]
    ADD_CARRY    %rax,%r14              // r14 = hi(a[j] * b[i]) + lo(a[j + 1] * b[i])
    addq    8(%rsp,%r10,8),%r14         // r14 = t[j + 1]
    adcq    $0,%rdx
    movq    %rdx,%r15                   // r15 = hi(a[j + 1] * b[i])

    movq    8(%rcx,%r10,8),%rax         // rax = n[j + 1]
    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j + 1]
    ADD_CARRY    %rax,%rdi              // rdi = hi(t[0] * k0 * n[j]) + lo(t[0] * k0 * n[j + 1])
    ADD_CARRY    %r14,%rdi              // rdi += t[j + 1]
    movq    %rdi,(%rsp,%r10,8)          // t[j] = rdi
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[j + 1])
    movq    16(%rsi,%r10,8),%rax        // rax = a[j + 2]

    leaq    4(%r10),%r10                // j += 4
    cmpq    %r9,%r10                    // if j != size
    jb      .Linner4x

    mulq    %rbx                        // (rdx, rax) = a[j - 2] * b[i]
    ADD_CARRY    %rax,%r15              // r15 = hi(a[j + 1] * b[i]) + lo(a[j - 2] * b[i])
    addq    -16(%rsp,%r10,8),%r15       // r15 = t[j - 2]
    adcq    $0,%rdx
    movq    %rdx,%r14                   // r14 = hi(a[j - 2] * b[i])

    movq    -16(%rcx,%r10,8),%rax       // rax = n[j - 2]
    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j - 2]
    ADD_CARRY    %rax,%r12              // r12 = hi(t[0] * k0 * n[j + 1]) + lo(t[0] * k0 * n[j - 2])
    ADD_CARRY    %r15,%r12              // r12 += t[j - 2]
    movq    %r12,-24(%rsp,%r10,8)       // t[j - 3] = r13
    movq    %rdx,%rdi                   // rdi = hi(t[0] * k0 * n[j - 2])

    movq    -8(%rsi,%r10,8),%rax        // rax = a[j - 1]
    mulq    %rbx                        // (rdx, rax) = a[j - 1] * b[i]
    ADD_CARRY    %rax,%r14              // r14 = hi(a[j - 2] * b[i]) + lo(a[j - 1] * b[i])
    addq    -8(%rsp,%r10,8),%r14        // r14 = t[j - 1]
    adcq    $0,%rdx
    leaq    1(%r11),%r11                // i++
    movq    %rdx,%r15                   // r15 = hi(a[j - 1] * b[i])

    movq    -8(%rcx,%r10,8),%rax        // rax = n[j - 1]
    mulq    %rbp                        // (rdx, rax) = t[0] * k0 * n[j - 1]
    ADD_CARRY    %rax,%rdi              // rdi = hi(t[0] * k0 * n[j - 2]) + lo(t[0] * k0 * n[j - 1])
    ADD_CARRY    %r14,%rdi              // rdi += t[j - 1]
    movq    %rdi,-16(%rsp,%r10,8)       // t[j - 2] = rdi
    movq    %rdx,%r12                   // r12 = hi(t[0] * k0 * n[j - 1])

    xorq    %rdx,%rdx                   // rdi = 0
    ADD_CARRY    %r15,%r12              // r12 = hi(t[0] * k0 * n[j - 1]) + r10
    addq    (%rsp,%r9,8),%r12           // r12 += t[size]
    adcq    $0,%rdx
    movq    %r12,-8(%rsp,%r10,8)        // t[j - 1] = r13
    movq    %rdx,(%rsp,%r10,8)          // t[j] = CF

    cmpq    %r9,%r11                    // if i != size
    jb      .LoopOuter4x

    movq    16(%rsp,%r9,8),%rdi         // rdi = t[size + 2]
    leaq    -4(%r9),%r10                // j = size - 4
    movq    (%rsp),%rax                 // rax = t[0]
    movq    8(%rsp),%rdx                // rdx = t[1]
    shrq    $2,%r10                     // r10 = (size - 4) / 4
    leaq    (%rsp),%rsi                 // rsi = t[0]
    xorq    %r11,%r11                   // i = 0

    subq    (%rcx),%rax                 // rax = t[0] - n[0]
    sbbq    8(%rcx),%rdx                // rdx = t[1] - (n[1] + CF)
    movq    16(%rsi),%rbx               // rbx = t[2]
    movq    24(%rsi),%rbp               // rbp = t[3]

    /* 计算 S-N */
.LoopSub4x:
    movq    %rax,(%rdi,%r11,8)          // r[i] = n[0]
    movq    %rdx,8(%rdi,%r11,8)         // r[i + 1] = n[1]

    movq    32(%rsi,%r11,8),%rax        // rax = t[i + 4]
    movq    40(%rsi,%r11,8),%rdx        // rdx = t[i + 5]

    sbbq    16(%rcx,%r11,8),%rbx        // rbx = t[2] - (n[i + 2] + CF)
    sbbq    24(%rcx,%r11,8),%rbp        // rbp = t[3] - (n[i + 3] + CF)
    sbbq    32(%rcx,%r11,8),%rax        // rax = t[i + 4] - (n[j + 4] + CF)
    sbbq    40(%rcx,%r11,8),%rdx        // rdx = t[i + 5] - (n[i + 5] + CF)

    movq    %rbx,16(%rdi,%r11,8)        // r[i + 2] = rbx
    movq    %rbp,24(%rdi,%r11,8)        // r[i + 3] = rbp

    movq    48(%rsi,%r11,8),%rbx        // rbx = t[i + 6]
    movq    56(%rsi,%r11,8),%rbp        // rbp = t[i + 7]
    leaq    4(%r11),%r11                // i += 4
    decq    %r10                        // j--
    jnz     .LoopSub4x                  // if j != 0

    sbbq    16(%rcx,%r11,8),%rbx        // rbx = rbx = t[i + 6] - (n[i + 2] + CF)
    sbbq    24(%rcx,%r11,8),%rbp        // rbp = t[i + 7] - (n[i + 3] + CF)

    movq    %rax,(%rdi,%r11,8)          // r[i] = rax
    movq    %rdx,8(%rdi,%r11,8)         // r[i + 1] = rdx
    movq    %rbx,16(%rdi,%r11,8)        // r[i + 2] = rbx
    movq    %rbp,24(%rdi,%r11,8)        // r[i + 3] = rbp

    movq    32(%rsi,%r11,8),%rax        // rax = t[i + 4]
    sbbq    $0,%rax                     // rax -= CF

    pxor    %xmm2,%xmm2                 // xmm0 = 0
    movq    %rax, %xmm0
    pcmpeqd %xmm1,%xmm1                 // xmm5 = -1
    pshufd  $0,%xmm0,%xmm0
    movq    %r9,%r10                    // j = size
    pxor    %xmm0,%xmm1
    shrq    $2,%r10                     // j = size / 4
    xorl    %eax,%eax                   // i = 0

.align  16
.LoopCopy4x:

    movdqa  (%rsp,%rax),%xmm5         // Copy the result to r.
    movdqu  (%rdi,%rax),%xmm3
    pand    %xmm0,%xmm5
    pand    %xmm1,%xmm3
    movdqa  16(%rsp,%rax),%xmm4
    movdqa  %xmm2,(%rsp,%rax)
    por     %xmm3,%xmm5
    movdqu  16(%rdi,%rax),%xmm3
    movdqu  %xmm5,(%rdi,%rax)
    pand    %xmm0,%xmm4
    pand    %xmm1,%xmm3
    movdqa  %xmm2,16(%rsp,%rax)
    por     %xmm3,%xmm4
    movdqu  %xmm4,16(%rdi,%rax)
    leaq    32(%rax),%rax
    decq    %r10                        // j--
    jnz     .LoopCopy4x
    movq    8(%rsp,%r9,8),%rsi          // rsi = pressed-stacked rsp.
    movq    $1,%rax
    leaq    (%rsi),%rsp                 // Restore srsp.
    RESTORE_REGISTERS
    ret
.cfi_endproc
.size   MontMul4,.-MontMul4

.type   MontSqr8,@function
.align  32
MontSqr8:
.cfi_startproc
    SAVE_REGISTERS
    movq    %rsp,%rax

    movl    %r9d,%r15d
    shll    $3,%r9d                 // Calculate size * 8 bytes.
    shlq    $5,%r15                 // size * 8 * 4
    negq    %r9

    leaq    -64(%rsp,%r9,2),%r14    // r14 = rsp[size * 2 - 8]
    subq    %rsi,%r14
    andq    $4095,%r14
    movq    %rsp,%rbp
    cmpq    %r14,%r15
    jae     .Loop8xCheckstk

    leaq    4032(,%r9,2),%r15    // r15 = 4096 - frame - 2 * size
    subq    %r15,%r14
    movq    $0,%r15
    cmovcq  %r15,%r14

.Loop8xCheckstk:
    subq    %r14,%rbp
    leaq    -64(%rbp,%r9,2),%rbp    // Allocate a frame + 2 x size.

    andq    $-64,%rbp               // __checkstk implementation,
                                    // which is invoked when the stack size needs to exceed one page.
    movq    %rsp,%r14
    subq    %rbp,%r14
    andq    $-4096,%r14
    leaq    (%r14,%rbp),%rsp
    cmpq    %rbp,%rsp
    jbe     .LoopMul8x

.align  16
.LoopPage8x:
    leaq    -4096(%rsp),%rsp        // Change sp - 4096 each time until sp <= the space to be allocated
    cmpq    %rbp,%rsp
    ja      .LoopPage8x

.LoopMul8x:
    movq    %r9,%r15                // r15 = -size * 8
    negq    %r9                     // Restoresize.
    movq    %r8,32(%rsp)            // Save the values of k0 and sp.
    movq    %rax,40(%rsp)

    movq    %rcx, %xmm1             // Pointer to saving n.
    pxor    %xmm2,%xmm2             // xmm0 = 0
    movq    %rdi, %xmm0             // Pointer to saving r.
    movq    %r15, %xmm5             // Save size.
    call    MontSqr8Inner

    leaq    (%rdi,%r9),%rbx       // rbx = t[size]
    movq    %r9,%rcx                // rcx = -size
    movq    %r9,%rdx                // rdx = -size
    movq    %xmm0, %rdi             // rdi = r
    sarq    $5,%rcx               // rcx >>= 5

.align  32
/* T -= N */
.LoopSub8x:
    movq    (%rbx),%r13             // r13 = t[i]
    movq    8(%rbx),%r12            // r12 = t[i + 1]
    movq    16(%rbx),%r11           // r11 = t[i + 2]
    movq    24(%rbx),%r10           // r10 = t[i + 3]

    sbbq    (%rbp),%r13             // r13 = t[i] - (n[i] + CF)
    sbbq    8(%rbp),%r12            // r12 = t[i + 1] - (n[i + 1] + CF)
    sbbq    16(%rbp),%r11           // r11 = t[i + 2] - (n[i + 2] + CF)
    sbbq    24(%rbp),%r10           // r10 = t[i + 3] - (n[i + 3] + CF)

    movq    %r13,0(%rdi)            // Assigning value to r.
    movq    %r12,8(%rdi)
    movq    %r11,16(%rdi)
    movq    %r10,24(%rdi)

    leaq    32(%rbp),%rbp           // n += 4
    leaq    32(%rdi),%rdi           // r += 4
    leaq    32(%rbx),%rbx           // t += 4
    incq    %rcx
    jnz     .LoopSub8x

    sbbq    $0,%rax                 // rax -= CF
    leaq    (%rbx,%r9),%rbx
    leaq    (%rdi,%r9),%rdi

    movq    %rax,%xmm0
    pxor    %xmm2,%xmm2
    pshufd  $0,%xmm0,%xmm0
    movq    40(%rsp),%rsi           // rsi = pressed-stacked rsp.

.align  32
.LoopCopy8x:
    movdqa  0(%rbx),%xmm1           // Copy the result to r.
    movdqa  16(%rbx),%xmm5
    leaq    32(%rbx),%rbx
    movdqu  0(%rdi),%xmm3
    movdqu  16(%rdi),%xmm4
    leaq    32(%rdi),%rdi
    movdqa  %xmm2,-32(%rbx)
    movdqa  %xmm2,-16(%rbx)
    movdqa  %xmm2,-32(%rbx,%rdx)
    movdqa  %xmm2,-16(%rbx,%rdx)
    pcmpeqd %xmm0,%xmm2
    pand    %xmm0,%xmm1
    pand    %xmm0,%xmm5
    pand    %xmm2,%xmm3
    pand    %xmm2,%xmm4
    pxor    %xmm2,%xmm2
    por     %xmm1,%xmm3
    por     %xmm5,%xmm4
    movdqu  %xmm3,-32(%rdi)
    movdqu  %xmm4,-16(%rdi)
    addq    $32,%r9
    jnz     .LoopCopy8x

    movq    $1,%rax
    leaq    (%rsi),%rsp             // Restore rsp.
    RESTORE_REGISTERS               // Restore non-volatile register.
    ret
.cfi_endproc
.size   MontSqr8,.-MontSqr8

.type   MontSqr8Inner,@function
.align  32
MontSqr8Inner:
.cfi_startproc
    leaq    32(%r15),%rbp           // i = -size + 32
    leaq    (%rsi,%r9),%rsi       // rsi = a[size]
    movq    %r9,%rcx                // j = size

    movq    -32(%rsi,%rbp),%r11   // r11 = a[0]
    movq    -24(%rsi,%rbp),%r10   // r10 = a[1]

    leaq    56(%rsp,%r9,2),%rdi   // rdi = t[2 * size]
    leaq    -16(%rsi,%rbp),%rbx   // rbx = a[2]
    leaq    -32(%rdi,%rbp),%rdi   // rdi = t[2 * size - i]

    movq    %r10,%rax               // rax = a[1]
    mulq    %r11                    // (rdx, rax) = a[1] * a[0]
    movq    %rax,%r15               // r15 = lo(a[1] * a[0])
    movq    %rdx,%r14               // r14 = hi(a[1] * a[0])
    movq    %r15,-24(%rdi,%rbp)   // t[1] = lo(a[1] * a[0])

    movq    (%rbx),%rax             // rax = a[2]
    mulq    %r11                    // (rdx, rax) = a[2] * a[0]
    ADD_CARRY    %rax,%r14          // r14 = hi(a[1] * a[0]) + lo(a[2] * a[0])
    movq    %r14,-16(%rdi,%rbp)   // t[2] = hi(a[1] * a[0]) + lo(a[2] * a[0])
    movq    %rdx,%r15               // r15 = hi(a[2] * a[0])

    movq    (%rbx),%rax             // rax = a[2]
    mulq    %r10                    // (rdx, rax) = a[2] * a[1]
    movq    %rax,%r13               // r13 = lo(a[2] * a[1])
    movq    %rdx,%r12               // r12 = hi(a[2] * a[1])

    leaq    8(%rbx),%rbx            // rbx = a[3]
    movq    (%rbx),%rax             // rax = a[3]
    mulq    %r11                    // (rdx, rax) = a[3] * a[0]
    ADD_CARRY    %rax,%r15          // r15 = hi(a[2] * a[0]) + lo(a[3] * a[0])
    ADD_CARRY    %r13,%r15          // r15 = hi(a[2] * a[0]) + lo(a[3] * a[0]) + lo(a[2] * a[1])
    movq    %rdx,%r14               // r14 = hi(a[3] * a[0])

    movq    (%rbx),%rax             // rax = a[3]
    leaq    (%rbp),%rcx             // j = i
    movq    %r15,-8(%rdi,%rcx)      // t[3] = hi(a[2] * a[0]) + lo(a[3] * a[0]) + lo(a[2] * a[1])

.align  32
.Loop1stSqr4x:
    leaq    (%rsi,%rcx),%rbx        // rbx = a[4]
    mulq    %r10                    // (rdx, rax) = a[3] * a[1]
    ADD_CARRY    %rax,%r12          // r12 = hi(a[2] * a[1]) + lo(a[3] * a[1])
    movq    %rdx,%r13               // r13 = hi(a[3] * a[1])

    movq    (%rbx),%rax             // rax = a[4]
    mulq    %r11                    // (rdx, rax) = a[4] * a[0]
    ADD_CARRY    %rax,%r14          // r14 = hi(a[3] * a[0]) + lo(a[4] * a[0])
    ADD_CARRY    %r12,%r14          // r14 = hi(a[3] * a[0]) + lo(a[4] * a[0]) + lo(a[3] * a[1])

    movq    (%rbx),%rax             // rax = a[4]
    movq    %rdx,%r15               // r15 = hi(a[4] * a[0])
    mulq    %r10                    // (rdx, rax) = a[4] * a[1]
    ADD_CARRY    %rax,%r13          // r13 = hi(a[3] * a[1]) + lo(a[4] * a[1])
    movq    %r14,(%rdi,%rcx)        // t[4] = hi(a[3] * a[0]) + lo(a[4] * a[0]) + lo(a[3] * a[1])
    movq    %rdx,%r12               // r12 = hi(a[4] * a[1])

    leaq    8(%rbx),%rbx            // rbx = a[5]
    movq    (%rbx),%rax             // rax = a[5]
    mulq    %r11                    // (rdx, rax) = a[5] * a[0]
    ADD_CARRY    %rax,%r15          // r15 = hi(a[4] * a[0]) + lo(a[5] * a[0])
    ADD_CARRY    %r13,%r15          // r15 = hi(a[4] * a[0]) + lo(a[5] * a[0]) + hi(a[3] * a[1]) + lo(a[4] * a[1])

    movq    (%rbx),%rax             // rax = a[5]
    movq    %rdx,%r14               // r14 = hi(a[5] * a[0])
    mulq    %r10                    // (rdx, rax) = a[5] * a[1]
    ADD_CARRY    %rax,%r12          // r12 = hi(a[4] * a[1]) + lo(a[5] * a[1])
    movq    %r15,8(%rdi,%rcx)       // t[5] = r10
    movq    %rdx,%r13               // r13 = hi(a[5] * a[1])

    leaq    8(%rbx),%rbx            // rbx = a[6]
    movq    (%rbx),%rax             // rax = a[6]
    mulq    %r11                    // (rdx, rax) = a[6] * a[0]
    ADD_CARRY    %rax,%r14          // r14 = hi(a[5] * a[0]) + lo(a[6] * a[0])
    ADD_CARRY    %r12,%r14          // r14 = hi(a[5] * a[0]) + lo(a[6] * a[0]) + hi(a[4] * a[1]) + lo(a[5] * a[1])

    movq    (%rbx),%rax             // rax = a[6]
    movq    %rdx,%r15               // r15 = hi(a[6] * a[0])
    mulq    %r10                    // (rdx, rax) = a[6] * a[1]
    ADD_CARRY    %rax,%r13          // r13 = lo(a[6] * a[1])
    movq    %r14,16(%rdi,%rcx)      // t[6] = r11
    movq    %rdx,%r12               // r12 = hi(a[6] * a[1])

    leaq    8(%rbx),%rbx            // rbx = a[7]
    movq    (%rbx),%rax             // rax = a[7]
    mulq    %r11                    // (rdx, rax) = a[7] * a[0]
    ADD_CARRY    %rax,%r15          // r15 = hi(a[6] * a[0]) + lo(a[7] * a[0])
    ADD_CARRY    %r13,%r15          // r15 = hi(a[6] * a[0]) + lo(a[7] * a[0]) + lo(a[6] * a[1])
    movq    %r15,24(%rdi,%rcx)    // t[7] = hi(a[6] * a[0]) + lo(a[7] * a[0]) + lo(a[6] * a[1])
    movq    %rdx,%r14               // r14 = hi(a[7] * a[0])

    movq    (%rbx),%rax             // rax = a[7]
    leaq    32(%rcx),%rcx           // j += 2
    cmpq    $0,%rcx                 // if j != 0
    jne     .Loop1stSqr4x

    mulq    %r10                    // (rdx, rax) = a[7] * a[1]
    ADD_CARRY    %rax,%r12          // r12 = hi(a[6] * a[1]) + lo(a[7] * a[1])
    leaq    16(%rbp),%rbp           // i++
    ADD_CARRY    %r14,%r12          // r12 = hi(a[6] * a[1]) + hi(a[7] * a[0]) + lo(a[7] * a[1])

    movq    %r12,(%rdi)             // t[8] = r13
    movq    %rdx,%r13               // r13 = hi(a[7] * a[1])
    movq    %rdx,8(%rdi)            // t[9] = hi(a[7] * a[1])

.align  32
.LoopOuterSqr4x:
    movq    -32(%rsi,%rbp),%r11   // r11 = a[0]
    movq    -24(%rsi,%rbp),%r10   // r10 = a[1]

    leaq    -16(%rsi,%rbp),%rbx   // rbx = a[2]
    leaq    56(%rsp,%r9,2),%rdi   // rdi = t[size * 2 - i]
    leaq    -32(%rdi,%rbp),%rdi

    movq    %r10,%rax               // rax = a[1]
    mulq    %r11                    // (rdx, rax) =  a[1] * a[0]
    movq    -24(%rdi,%rbp),%r15     // r15 = t[1]
    ADD_CARRY    %rax,%r15          // r15 = lo(a[1] * a[0]) + t[1]
    movq    %r15,-24(%rdi,%rbp)     // t[1] = r10
    movq    %rdx,%r14               // r14 = hi(a[1] * a[0])

    movq    (%rbx),%rax             // rax = a[2]
    mulq    %r11                    // (rdx, rax) = a[2] * a[0]
    ADD_CARRY    %rax,%r14          // r14 = hi(a[1] * a[0]) + lo(a[2] * a[0])
    addq    -16(%rdi,%rbp),%r14     // r14 = hi(a[1] * a[0]) + lo(a[2] * a[0]) + t[2]
    adcq    $0,%rdx                 // r10 += CF
    movq    %rdx,%r15               // r10 = hi(a[2] * a[0])
    movq    %r14,-16(%rdi,%rbp)     // t[2] = r11

    xorq    %r13,%r13               // Clear CF.

    movq    (%rbx),%rax             // rax = a[2]
    mulq    %r10                    // (rdx, rax) = a[2] * a[1]
    ADD_CARRY    %rax,%r13          // r13 = lo(a[2] * a[1])
    addq    -8(%rdi,%rbp),%r13      // r13 = lo(a[2] * a[1]) + t[3]
    adcq    $0,%rdx
    movq    %rdx,%r12               // r12 = hi(a[2] * a[1])

    leaq    8(%rbx),%rbx            // rbx = a[3]
    movq    (%rbx),%rax             // rax = a[3]
    mulq    %r11                    // (rdx, rax) = a[3] * a[0]
    ADD_CARRY    %rax,%r15          // r15 = hi(a[2] * a[0]) + lo(a[3] * a[0])
    ADD_CARRY    %r13,%r15          // r15 = hi(a[2] * a[0]) + lo(a[3] * a[0]) + lo(a[2] * a[1]) + t[3]

    movq    (%rbx),%rax             // rax = a[3]
    leaq    (%rbp),%rcx             // j = i
    movq    %r15,-8(%rdi,%rbp)      // t[3] = r10
    movq    %rdx,%r14               // r14 = hi(a[3] * a[0])

.align  32
.LoopInnerSqr4x:
    leaq    (%rsi,%rcx),%rbx        // rbx = a[4]
    mulq    %r10                    // (rdx, rax) = a[3] * a[1]
    ADD_CARRY    %rax,%r12          // r12 = hi(a[2] * a[1]) + lo(a[3] * a[1])
    movq    (%rbx),%rax             // rax = a[4]
    movq    %rdx,%r13               // r13 = hi(a[3] * a[1])
    addq    (%rdi,%rcx),%r12        // r12 = hi(a[2] * a[1]) + lo(a[3] * a[1]) + t[4]
    adcq    $0,%rdx                 // r13 += CF
    movq    %rdx,%r13               // r13 = hi(a[3] * a[1])

    mulq    %r11                    // (rdx, rax) = a[4] * a[0]
    ADD_CARRY    %rax,%r14          // r14 = hi(a[3] * a[0]) + lo(a[4] * a[0])
    ADD_CARRY    %r12,%r14          // r14 = hi(a[3] * a[0]) + lo(a[4] * a[0]) + hi(a[2] * a[1]) + lo(a[3] * a[1]) + t[4]
    movq    %r14,(%rdi,%rcx)        // t[4] = r11
    movq    %rdx,%r15               // r15 = hi(a[4] * a[0])

    movq    (%rbx),%rax             // rax = a[4]
    mulq    %r10                    // (rdx, rax) = a[4] * a[1]
    ADD_CARRY    %rax,%r13          // r13 = hi(a[3] * a[1]) + lo(a[4] * a[1])
    addq    8(%rdi,%rcx),%r13       // r13 = hi(a[3] * a[1]) + lo(a[4] * a[1]) + t[5]
    adcq    $0,%rdx                 // r12 += CF

    leaq    8(%rbx),%rbx            // rbx = a[5]
    movq    (%rbx),%rax             // rax = a[5]
    movq    %rdx,%r12               // r12 = hi(a[4] * a[1])
    mulq    %r11                    // (rdx, rax) = a[5] * a[0]
    ADD_CARRY    %rax,%r15          // r15 = hi(a[4] * a[0]) + lo(a[5] * a[0])
    ADD_CARRY    %r13,%r15          // r15 = hi(a[4] * a[0]) + lo(a[5] * a[0]) + hi(a[3] * a[1]) + lo(a[4] * a[1]) + t[5]
    movq    %r15,8(%rdi,%rcx)       // t[5] = r10
    movq    %rdx,%r14               // r14 = hi(a[5] * a[0])

    movq    (%rbx),%rax             // rax = a[5]
    leaq    16(%rcx),%rcx           // j++
    cmpq    $0,%rcx                 // if j != 0
    jne     .LoopInnerSqr4x

    mulq    %r10                    // (rdx, rax) = a[5] * a[1]
    ADD_CARRY    %rax,%r12          // r12 = hi(a[4] * a[1]) + lo(a[5] * a[1])
    ADD_CARRY    %r14,%r12          // r12 = hi(a[4] * a[1]) + lo(a[5] * a[1]) + hi(a[5] * a[0])

    movq    %r12,(%rdi)             // t[6] = r13
    movq    %rdx,%r13               // r13 = hi(a[5] * a[1])
    movq    %rdx,8(%rdi)            // t[7] = hi(a[5] * a[1])

    addq    $16,%rbp                // i++
    jnz     .LoopOuterSqr4x         // if i != 0

    movq    -32(%rsi),%r11          // r11 = a[0]
    leaq    56(%rsp,%r9,2),%rdi   // rdi = t[2 * size]
    movq    -24(%rsi),%rax          // rax = a[1]
    leaq    -32(%rdi,%rbp),%rdi   // rdi = t[2 * size - i]
    movq    -16(%rsi),%rbx          // rbx = a[2]
    movq    %rax,%r10               // r10 = a[1]

    mulq    %r11                    // (rdx, rax) = a[1] * a[0]
    ADD_CARRY    %rax,%r15          // r15 = lo(a[1] * a[0]) + t[1]

    movq    %rbx,%rax               // rax = a[2]
    movq    %rdx,%r14               // r14 = hi(a[1] * a[0])
    mulq    %r11                    // (rdx, rax) = a[2] * a[0]
    ADD_CARRY    %rax,%r14          // r14 = hi(a[1] * a[0]) + lo(a[2] * a[0])
    movq    %r15,-24(%rdi)          // t[1] = r10
    ADD_CARRY    %r12,%r14          // r14 = lo(a[2] * a[0]) + t[2]

    movq    %rbx,%rax               // rax = a[2]
    movq    %rdx,%r15               // r15 = hi(a[2] * a[0])
    mulq    %r10                    // (rdx, rax) = a[2] * a[1]
    ADD_CARRY    %rax,%r13          // r13 = lo(a[2] * a[1]) + t[3]
    movq    %r14,-16(%rdi)          // t[2] = r11
    movq    %rdx,%r12               // r12 = hi(a[2] * a[1])

    movq    -8(%rsi),%rbx           // rbx = a[3]
    movq    %rbx,%rax               // rax = a[3]
    mulq    %r11                    // (rdx, rax) = a[3] * a[0]
    ADD_CARRY    %rax,%r15          // r15 = hi(a[2] * a[0]) + lo(a[3] * a[0])
    ADD_CARRY    %r13,%r15          // r15 = hi(a[2] * a[0]) + lo(a[3] * a[0]) + lo(a[2] * a[1]) + t[3]

    movq    %rbx,%rax               // rax = a[3]
    movq    %r15,-8(%rdi)           // t[3] = r10
    movq    %rdx,%r14               // r14 = hi(a[3] * a[0])
    mulq    %r10                    // (rdx, rax) = a[3] * a[1]
    ADD_CARRY    %rax,%r12          // r12 = hi(a[2] * a[1]) + lo(a[3] * a[1])
    ADD_CARRY    %r14,%r12          // r12 = hi(a[3] * a[0]) + hi(a[2] * a[1]) + lo(a[3] * a[1])

    movq    %r12,(%rdi)             // t[4] = r13
    movq    %rdx,%r13               // r13 = hi(a[3] * a[1])
    movq    %rdx,8(%rdi)            // t[5] = hi(a[3] * a[1])

    movq    -16(%rsi),%rax          // rax = a[2]
    mulq    %rbx                    // (rdx, rax) = a[3] * a[2]
    addq    $16,%rbp
    xorq    %r11,%r11
    subq    %r9,%rbp                // i = 16 - size
    xorq    %r10,%r10

    ADD_CARRY    %r13,%rax          // rax = hi(a[3] * a[1]) + lo(a[3] * a[2])
    movq    %rax,8(%rdi)            // t[5] = hi(a[3] * a[1]) + lo(a[3] * a[2])
    movq    %rdx,16(%rdi)           // t[6] = hi(a[3] * a[2])
    movq    %r10,24(%rdi)           // t[7] = 0

    movq    -16(%rsi,%rbp),%rax   // rax = a[0]
    leaq    56(%rsp),%rdi         // rdi = t[0]
    xorq    %r15,%r15
    movq    8(%rdi),%r14            // r14 = t[1]

    leaq    (%r11,%r15,2),%r13
    shrq    $63,%r15                // Cyclically shifts 63 bits to the right to obtain the lower bits.
    leaq    (%rcx,%r14,2),%r12      // r12 = t[1] * 2
    shrq    $63,%r14                // r14 = t[1] >> 63
    orq     %r15,%r12               // r12 = t[1] * 2
    movq    16(%rdi),%r15           // r15 = t[2]
    movq    %r14,%r11               // r11 = t[1] >> 63
    mulq    %rax                    // (rdx, rax) = a[0] * a[0]
    negq    %r10                    // If the value is not 0, CF is set to 1.
    adcq    %rax,%r13               // r13 = lo(a[0] * a[0])
    movq    24(%rdi),%r14           // r14 = t[3]
    movq    %r13,(%rdi)             // t[0] = 0
    adcq    %rdx,%r12               // r12 = t[1] * 2 + hi(a[0] * a[0])

    leaq    (%r11,%r15,2),%rbx      // rbx = t[2] * 2 + t[1] >> 63
    movq    -8(%rsi,%rbp),%rax    // rax = a[1]
    movq    %r12,8(%rdi)            // t[1] = t[1] * 2 + hi(a[0] * a[0])
    sbbq    %r10,%r10               // r10 = -CF clear CF
    shrq    $63,%r15                // r15 = t[2] >> 63
    leaq    (%rcx,%r14,2),%r8       // r8 = t[3] * 2
    shrq    $63,%r14                // r14 = t[3] >> 63
    orq     %r15,%r8                // r8 = (t[3] * 2) + (t[2] >> 63)
    movq    32(%rdi),%r15           // r15 = t[4]
    movq    %r14,%r11               // r11 = t[3] >> 63
    mulq    %rax                    // (rdx, rax) = a[1] * a[1]
    negq    %r10                    // If the value is not 0, CF is set to 1.
    movq    40(%rdi),%r14           // r14 = t[5]
    adcq    %rax,%rbx               // rbx = t[2] * 2 + t[1] >> 63 + lo(a[1] * a[1])
    movq    (%rsi,%rbp),%rax     // rax = a[2]
    movq    %rbx,16(%rdi)           // t[2] = t[2] * 2 + t[1] >> 63 + lo(a[1] * a[1])
    adcq    %rdx,%r8                // r8 = t[3] * 2 + t[2] >> 63 + hi(a[1] * a[1])
    leaq    16(%rbp),%rbp           // i++
    movq    %r8,24(%rdi)            // t[3] = r8
    sbbq    %r10,%r10               // r10 = -CF clear CF.
    leaq    64(%rdi),%rdi           // t += 64

.align  32
.LoopShiftAddSqr4x:
    leaq    (%r11,%r15,2),%r13      // r13 = t[4] * 2 + t[3] >> 63
    shrq    $63,%r15                // r15 = t[4] >> 63
    leaq    (%rcx,%r14,2),%r12      // r12 = t[5] * 2
    shrq    $63,%r14                // r14 = t[5] >> 63
    orq     %r15,%r12               // r12 = (t[5] * 2) + t[4] >> 63
    movq    -16(%rdi),%r15          // r15 = t[6]
    movq    %r14,%r11               // r11 = t[5] >> 63
    mulq    %rax                    // (rdx, rax) = a[2] * a[2]
    negq    %r10                    // r10 = CF
    movq    -8(%rdi),%r14           // r14 = t[7]
    adcq    %rax,%r13               // r13 = t[4] * 2 + t[3] >> 63 + lo(a[2] * a[2])
    movq    %r13,-32(%rdi)          // t[4] = r12
    adcq    %rdx,%r12               // r12 = (t[5] * 2) + t[4] >> 63 + hi(a[2] * a[2])

    leaq    (%r11,%r15,2),%rbx      // rbx = t[6] * 2 + t[5] >> 63
    movq    -8(%rsi,%rbp),%rax    // rax = a[3]
    movq    %r12,-24(%rdi)          // t[5] = hi(a[2] * a[2])
    sbbq    %r10,%r10               // r10 = -CF
    shrq    $63,%r15                // r15 = t[6] >> 63
    leaq    (%rcx,%r14,2),%r8       // r8 = t[7] * 2
    shrq    $63,%r14                // r14 = t[7] >> 63
    orq     %r15,%r8                // r8 = t[7] * 2 + t[6] >> 63
    movq    0(%rdi),%r15            // r15 = t[8]
    movq    %r14,%r11               // r11 = t[7] >> 63
    mulq    %rax                    // (rdx, rax) = a[3] * a[3]
    negq    %r10                    // r10 = CF
    movq    8(%rdi),%r14            // r14 = t[9]
    adcq    %rax,%rbx               // rbx = t[6] * 2 + t[5] >> 63 + lo(a[3] * a[3])
    movq    %rbx,-16(%rdi)          // t[6] = rbx
    adcq    %rdx,%r8                // r8 = t[7] * 2 + t[6] >> 63 + hi(a[3] * a[3])

    leaq    (%r11,%r15,2),%r13      // r13 = t[8] * 2 + t[7] >> 63
    movq    %r8,-8(%rdi)            // t[7] = hi(a[3] * a[3])
    movq    (%rsi,%rbp),%rax     // rax = a[4]
    sbbq    %r10,%r10               // r10 = -CF
    shrq    $63,%r15                // r15 = t[8] >> 63
    leaq    (%rcx,%r14,2),%r12      // r12 = t[9] * 2
    shrq    $63,%r14                // r14 = t[9] >> 63
    orq     %r15,%r12               // r12 = t[9] * 2 + t[8] >> 63
    movq    16(%rdi),%r15           // r15 = t[10]
    movq    %r14,%r11               // r11 = t[9] >> 63
    mulq    %rax                    // (rdx, rax) = a[4] * a[4]
    negq    %r10                    // r10 = -CF
    movq    24(%rdi),%r14           // r14 = t[11]
    adcq    %rax,%r13               // r13 = t[8] * 2 + t[7] >> 63 + lo(a[4] * a[4])
    movq    %r13,(%rdi)            // t[8] = r12
    adcq    %rdx,%r12               // r12 = t[9] * 2 + t[8] >> 63 + hi(a[4] * a[4])

    leaq    (%r11,%r15,2),%rbx      // rbx = t[10] * 2 + t[9] >> 63
    movq    8(%rsi,%rbp),%rax     // rax = a[5]
    movq    %r12,8(%rdi)            // t[9] = r13
    sbbq    %r10,%r10               // r10 = -CF
    shrq    $63,%r15                // r15 = t[10] >> 63
    leaq    (%rcx,%r14,2),%r8       // r8 = t[11] * 2
    shrq    $63,%r14                // r14 = t[11] >> 63
    orq     %r15,%r8                // r8 = t[11] * 2 + t[10] >> 63
    movq    32(%rdi),%r15           // r15 = t[12]
    movq    %r14,%r11               // r11 = t[11] >> 63
    mulq    %rax                    // (rdx, rax) = a[5] * a[5]
    negq    %r10                    // r10 = CF
    movq    40(%rdi),%r14           // r14 = t[13]
    adcq    %rax,%rbx               // rbx = t[10] * 2 + t[9] >> 63 + lo(a[5] * a[5])
    movq    16(%rsi,%rbp),%rax    // rax = a[6]
    movq    %rbx,16(%rdi)           // t[10] = rbx
    adcq    %rdx,%r8                // r8 = t[11] * 2 + t[10] >> 63 + hi(a[5] * a[5])
    movq    %r8,24(%rdi)            // t[11] = r8
    sbbq    %r10,%r10               // r10 = -CF
    leaq    64(%rdi),%rdi           // t += 64
    addq    $32,%rbp                // i += 4
    jnz     .LoopShiftAddSqr4x          // if i != 0

    leaq    (%r11,%r15,2),%r13      // r13 = t[12] * 2 + t[11] >> 63
    shrq    $63,%r15                // r15 = t[12] >> 63
    leaq    (%rcx,%r14,2),%r12      // r12 = t[13] * 2
    shrq    $63,%r14                // r14 = t[13] >> 63
    orq     %r15,%r12               // r12 = t[13] * 2 + t[12] >> 63
    movq    -16(%rdi),%r15          // r15 = t[14]
    movq    %r14,%r11               // r11 = t[13] >> 63
    mulq    %rax                    // (rdx, rax) = a[6] * a[6]
    negq    %r10                    // r10 = CF
    movq    -8(%rdi),%r14           // r14 = t[15]
    adcq    %rax,%r13               // r13 = t[12] * 2 + t[11] >> 63 + lo(a[6] * a[6])
    movq    %r13,-32(%rdi)          // t[12] = r12
    adcq    %rdx,%r12               // r12 = t[13] * 2 + t[12] >> 63 + hi(a[6] * a[6])

    leaq    (%r11,%r15,2),%rbx      // rbx = t[14] * 2 + t[13] >> 63
    movq    -8(%rsi),%rax           // rax = a[7]
    movq    %r12,-24(%rdi)          // t[13] = r13
    sbbq    %r10,%r10               // r10 = -CF
    shrq    $63,%r15                // r15 = t[14] >> 63
    leaq    (%rcx,%r14,2),%r8       // r8 = t[15] * 2
    shrq    $63,%r14                // r14 = t[15] >> 63
    orq     %r15,%r8                // r8 = t[15] * 2 + t[14] >> 63
    mulq    %rax                    // (rdx, rax) = a[7] * a[7]
    negq    %r10                    // r10 = CF
    adcq    %rax,%rbx               // rbx = t[14] * 2 + t[13] >> 63 + lo(a[7] * a[7])
    adcq    %rdx,%r8                // r8 = t[15] * 2 + t[14] >> 63 + hi(a[7] * a[7])
    movq    %rbx,-16(%rdi)          // t[14] = rbx
    movq    %r8,-8(%rdi)            // t[15] = r8

    movq    %xmm1,%rbp              // rbp = n
    xorq    %rax,%rax               // rax = 0
    leaq    (%r9,%rbp),%rcx       // rcx = n[size]
    leaq    56(%rsp,%r9,2),%rdx   // rdx = t[size * 2]
    movq    %rcx,8(%rsp)
    leaq    56(%rsp,%r9),%rdi
    movq    %rdx,16(%rsp)
    negq    %r9

.align  32
.LoopReduceSqr8x:
    leaq    (%rdi,%r9),%rdi       // rdi = t[]

    movq    (%rdi),%rbx            // rbx = t[0]
    movq    8(%rdi),%r9             // r9 = t[1]
    movq    16(%rdi),%r15           // r15 = t[2]
    movq    24(%rdi),%r14           // r14 = t[3]
    movq    32(%rdi),%r13           // r13 = t[4]
    movq    40(%rdi),%r12           // r12 = t[5]
    movq    48(%rdi),%r11           // r11 = t[6]
    movq    56(%rdi),%r10           // r10 = t[7]
    movq    %rax,(%rdx)             // Store the highest carry bit.
    leaq    64(%rdi),%rdi           // rdi = t[8]

    movq    %rbx,%r8                // r8 = t[0]
    imulq   40(%rsp),%rbx         // rbx = k0 * t[0]
    movl    $8,%ecx

.align  32
.LoopReduce8x:
    movq    (%rbp),%rax             // rax = n[0]
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[0]
    negq    %r8                     // r8 = -t[0], If t[0] is not 0, set CF to 1.
    movq    %rdx,%r8                // r8 = hi(t[0] * k0 * n[0])
    adcq    $0,%r8                  // r8 += CF

    movq    8(%rbp),%rax            // rax = n[1]
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[1]
    movq    %rbx,48(%rsp,%rcx,8)
    ADD_CARRY    %rax,%r9           // r9 = t[1] + lo(t[0] * k0 * n[1])
    ADD_CARRY    %r9,%r8            // r8 = hi(t[0] * k0 * n[0]) + lo(t[0] * k0 * n[1]) + t[1]

    movq    16(%rbp),%rax           // rax = n[2]
    movq    %rdx,%r9                // r9 = hi(t[0] * k0 * n[1])
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[2]
    ADD_CARRY    %rax,%r15          // r15 = lo(t[0] * k0 * n[2]) + t[2]
    ADD_CARRY    %r15,%r9           // r9 = hi(t[0] * k0 * n[1]) + lo(t[0] * k0 * n[2]) + t[2]
    movq    40(%rsp),%rsi         // rsi = k0
    movq    %rdx,%r15               // r15 = hi(t[0] * k0 * n[2])

    movq    24(%rbp),%rax           // rax = n[3]
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[3]
    ADD_CARRY    %rax,%r14          // r14 = lo(t[0] * k0 * n[3])
    imulq   %r8,%rsi                // rsi = k0 * r8
    ADD_CARRY    %r14,%r15          // r15 = hi(t[0] * k0 * n[2]) + lo(t[0] * k0 * n[3])
    movq    %rdx,%r14               // r14 = hi(t[0] * k0 * n[3])

    movq    32(%rbp),%rax           // rax = n[4]
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[4]
    ADD_CARRY    %rax,%r13          // r13 = lo(t[0] * k0 * n[4]) + t[4]
    ADD_CARRY    %r13,%r14          // r14 = hi(t[0] * k0 * n[3]) + lo(t[0] * k0 * n[4]) + t[4]、

    movq    40(%rbp),%rax           // rax = n[5]
    movq    %rdx,%r13               // r13 = hi(t[0] * k0 * n[4])
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[5]
    ADD_CARRY    %rax,%r12          // r12 = lo(t[0] * k0 * n[5]) + t[5]
    ADD_CARRY    %r12,%r13          // r13 = hi(t[0] * k0 * n[4]) + lo(t[0] * k0 * n[5]) + t[5]

    movq    48(%rbp),%rax           // rax = n[6]
    movq    %rdx,%r12               // r12 = hi(t[0] * k0 * n[5])
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[6]
    ADD_CARRY    %rax,%r11          // r11 = lo(t[0] * k0 * n[6]) + t[6]
    ADD_CARRY    %r11,%r12          // r12 = hi(t[0] * k0 * n[5]) + lo(t[0] * k0 * n[6]) + t[6]

    movq    56(%rbp),%rax           // rax = n[7]
    movq    %rdx,%r11               // r11 = hi(t[0] * k0 * n[6])
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[7]
    movq    %rsi,%rbx               // rbx = k0 * r8
    ADD_CARRY    %rax,%r10          // r10 = lo(t[0] * k0 * n[7]) + t[7]
    ADD_CARRY    %r10,%r11          // r11 = hi(t[0] * k0 * n[6]) + lo(t[0] * k0 * n[7]) + t[7]
    movq    %rdx,%r10               // r10 = hi(t[0] * k0 * n[7])

    decl    %ecx                    // ecx--
    jnz     .LoopReduce8x           // if ecx != 0

    leaq    64(%rbp),%rbp           // rbp += 64, n Pointer Offset.
    xorq    %rax,%rax               // rax = 0
    movq    16(%rsp),%rdx           // rdx = t[size * 2]
    cmpq    8(%rsp),%rbp            // rbp = n[size]
    jae     .LoopEndCondMul8x

    addq    (%rdi),%r8             // r8 += t[0]
    adcq    8(%rdi),%r9             // r9 += t[1]
    adcq    16(%rdi),%r15           // r15 += t[2]
    adcq    24(%rdi),%r14           // r14 += t[3]
    adcq    32(%rdi),%r13           // r13 += t[4]
    adcq    40(%rdi),%r12           // r12 += t[5]
    adcq    48(%rdi),%r11           // r11 += t[6]
    adcq    56(%rdi),%r10           // r10 += t[7]
    sbbq    %rsi,%rsi               // rsi = -CF

    movq    112(%rsp),%rbx          // rbx = t[0] * k0, 48 + 56 + 8
    movl    $8,%ecx

.align  32
.LoopLastSqr8x:
    movq    (%rbp),%rax            // rax = n[0]
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[0]
    ADD_CARRY    %rax,%r8           // r8 += lo(t[0] * k0 * n[0])
    movq    %r8,(%rdi)              // t[0] = r8
    leaq    8(%rdi),%rdi            // t++
    movq    %rdx,%r8                // r8 = hi(t[0] * k0 * n[0])

    movq    8(%rbp),%rax            // rax = n[1]
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[1]
    ADD_CARRY    %rax,%r9           // r9 += lo(t[0] * k0 * n[1])
    ADD_CARRY    %r9,%r8            // r8 = hi(t[0] * k0 * n[0]) + r9

    movq    16(%rbp),%rax           // rax = n[2]
    movq    %rdx,%r9                // r9 = hi(t[0] * k0 * n[1])
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[2]
    ADD_CARRY    %rax,%r15          // r15 += lo(t[0] * k0 * n[2])
    ADD_CARRY    %r15,%r9           // r9 = hi(t[0] * k0 * n[1]) + r10

    movq    24(%rbp),%rax           // rax = n[3]
    movq    %rdx,%r15               // r15 = hi(t[0] * k0 * n[2])
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[3]
    ADD_CARRY    %rax,%r14          // r14 += lo(t[0] * k0 * n[3])
    ADD_CARRY    %r14,%r15          // r15 = hi(t[0] * k0 * n[2]) + r11

    movq    32(%rbp),%rax           // rax = n[4]
    movq    %rdx,%r14               // r14 = hi(t[0] * k0 * n[3])
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[4]
    ADD_CARRY    %rax,%r13          // r13 += lo(t[0] * k0 * n[4])
    ADD_CARRY    %r13,%r14          // r14 = hi(t[0] * k0 * n[3]) + r12

    movq    40(%rbp),%rax           // rax = n[5]
    movq    %rdx,%r13               // r13 = hi(t[0] * k0 * n[4])
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[5]
    ADD_CARRY    %rax,%r12          // r12 += lo(t[0] * k0 * n[5])
    ADD_CARRY    %r12,%r13          // r13 = hi(t[0] * k0 * n[4]) + r13

    movq    48(%rbp),%rax           // rax = n[6]
    movq    %rdx,%r12               // r12 = hi(t[0] * k0 * n[5])
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[6]
    ADD_CARRY    %rax,%r11          // r11 += lo(t[0] * k0 * n[6])
    ADD_CARRY    %r11,%r12          // r12 = hi(t[0] * k0 * n[5]) + r14

    movq    56(%rbp),%rax           // rax = n[7]
    movq    %rdx,%r11               // r11 = hi(t[0] * k0 * n[6])
    mulq    %rbx                    // (rdx, rax) = t[0] * k0 * n[7]
    movq    40(%rsp,%rcx,8),%rbx    // rbx = t[i] * k0
    ADD_CARRY    %rax,%r10          // r10 += lo(t[0] * k0 * n[7])
    ADD_CARRY    %r10,%r11          // r11 = hi(t[0] * k0 * n[6]) + r10
    movq    %rdx,%r10               // r10 = hi(t[0] * k0 * n[7])

    decl    %ecx                    // ecx--
    jnz     .LoopLastSqr8x              // if ecx != 0

    leaq    64(%rbp),%rbp           // n += 8
    movq    16(%rsp),%rdx           // rdx = t[size * 2]
    cmpq    8(%rsp),%rbp            // Check whether rbp is at the end of the n array. If yes, exit the loop.
    jae     .LoopSqrBreak8x

    movq    112(%rsp),%rbx          // rbx = t[0] * k0
    negq    %rsi                    // rsi = CF
    movq    (%rbp),%rax             // rax = = n[0]
    adcq    (%rdi),%r8              // r8 = t[0]
    adcq    8(%rdi),%r9             // r9 = t[1]
    adcq    16(%rdi),%r15           // r15 = t[2]
    adcq    24(%rdi),%r14           // r14 = t[3]
    adcq    32(%rdi),%r13           // r13 = t[4]
    adcq    40(%rdi),%r12           // r12 = t[5]
    adcq    48(%rdi),%r11           // r11 = t[6]
    adcq    56(%rdi),%r10           // r10 = t[7]
    sbbq    %rsi,%rsi               // rsi = -CF

    movl    $8,%ecx                 // ecx = 8
    jmp     .LoopLastSqr8x

.align  32
.LoopSqrBreak8x:
    xorq    %rax,%rax               // rax = 0
    addq    (%rdx),%r8              // r8 += Highest carry bit.
    adcq    $0,%r9                  // r9 += CF
    adcq    $0,%r15                 // r15 += CF
    adcq    $0,%r14                 // r14 += CF
    adcq    $0,%r13                 // r13 += CF
    adcq    $0,%r12                 // r12 += CF
    adcq    $0,%r11                 // r11 += CF
    adcq    $0,%r10                 // r10 += CF
    adcq    $0,%rax                 // rax += CF

    negq    %rsi                    // rsi = CF
.LoopEndCondMul8x:
    adcq    (%rdi),%r8              // r8 += t[0]
    adcq    8(%rdi),%r9             // r9 += t[1]
    adcq    16(%rdi),%r15           // r15 += t[2]
    adcq    24(%rdi),%r14           // r14 += t[3]
    adcq    32(%rdi),%r13           // r13 += t[4]
    adcq    40(%rdi),%r12           // r12 += t[5]
    adcq    48(%rdi),%r11           // r11 += t[6]
    adcq    56(%rdi),%r10           // r10 += t[7]
    adcq    $0,%rax                 // rax += CF
    movq    -8(%rbp),%rcx           // rcx = n[7]
    xorq    %rsi,%rsi               // rsi = 0

    movq    %xmm1,%rbp              // rbp = n
    movq    %r8,(%rdi)              // Save the calculated result back to t[].
    movq    %r9,8(%rdi)
    movq    %xmm5,%r9
    movq    %r15,16(%rdi)
    movq    %r14,24(%rdi)
    movq    %r13,32(%rdi)
    movq    %r12,40(%rdi)
    movq    %r11,48(%rdi)
    movq    %r10,56(%rdi)
    leaq    64(%rdi),%rdi           // t += 8

    cmpq    %rdx,%rdi               // Cycle the entire t[].
    jb      .LoopReduceSqr8x
    ret
.cfi_endproc
.size   MontSqr8Inner,.-MontSqr8Inner

#endif
