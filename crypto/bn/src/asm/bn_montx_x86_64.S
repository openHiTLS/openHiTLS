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
* void MontMulx_Asm(uint64_t *r, const uint64_t *a, const uint64_t *b,
*                     const uint64_t *n, const uint64_t k0, uint32_t size);
*/
.globl  MontMulx_Asm
.type   MontMulx_Asm,@function
.align  16
MontMulx_Asm:
.cfi_startproc
    testl   $3,%r9d
    jnz     .LMontMul                   // If size is not divisible by 4, LMontMul.
    cmpl    $8,%r9d
    jb      .LMontMul                   // LMontMul
    cmpq    %rsi,%rdx
    jne     MontMul4x                    // if a != b, MontMul4x
    testl   $7,%r9d
    jz      MontSqr8x                    // If size is divisible by 8，enter MontSqr8x.
    jmp     MontMul4x

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
.size   MontMulx_Asm,.-MontMulx_Asm

.type   MontMul4x,@function
.align  16
MontMul4x:
.cfi_startproc
    SAVE_REGISTERS
    movq    %rsp,%rax                   // save rsp

    movq    %r9,%r15
    negq    %r15
    leaq    -48(%rsp,%r15,8),%r15       // Allocate space: size * 8 + 48 bytes.
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
    movq    %rax, 0(%rsp)         // save stack pointer
    movq    %rdi, 8(%rsp)         // save r
    movq    %r8, 16(%rsp)         // save k0 
    movq    %r9, %r10
    shrq    $2, %r9
    decq    %r9
    movq    %r9, 24(%rsp)         // save (size/4) - 1
    shlq    $3, %r10
    movq    %rdx, %r12            // r12 = b
    movq    %r10, 32(%rsp)        // save (size * 8) -> bytes

    addq    %r10, %r12            // r12 = loc(b[size - 1])
    leaq    80(%rsp),%rbp         // rbp: start position of the tmp buffer

    movq    %rdx,%r13             // r13 = b
    movq    %r12, 40(%rsp)        // save loc(b + size * 8)
    movq    (%r13),%rdx           // rbx = b[0]

    // cal a[0 ~ 3] * b[0]
    mulx    (%rsi), %r12, %r14          // r14 = hi(a[0] * b[0]), r12 = lo(b[0] * a[0])
    mulx    8(%rsi), %rax, %r15         // (r15, rax) = a[1] * b[0]
    addq    %rax, %r14                  // r14 = hi(a[0] * b[0]) + lo(a[1] * b[0])
    mulx    16(%rsi), %rax, %r11        // (rax, r11) = a[2] * b[0]
    adcq    %rax, %r15                  // r15 = hi(a[1] * b[0]) + lo(a[2] * b[0])
    adcq    $0, %r11                    // r11 = hi(a[2] * b[0]) + CF

    imulq   %r12,%r8                    // r8 = t[0] * k0, will change CF
    xorq    %r10,%r10                   // get r10 = 0

    mulx    24(%rsi), %rax, %rbx        // (rax, rbx) = a[3] * b[0]
    movq    %r8, %rdx                   // rdx = t[0] * k0 = m'
    adcx    %rax, %r11                  // r11 = hi(a[2] * b[0]) + lo(a[3] * b[0])
    adcx    %r10, %rbx                  // rbx = hi(a[3] * b[0])

    // cal n[0 ~ 3] * t[0] * k0
    mulx    (%rcx), %rax, %rdi          // (rdi, rax) = n[0] * m'
    adcx    %rax, %r12                  // r12 = lo(b[0] * a[0]) + lo(n[0] * m')
    adox    %r14, %rdi                  // r8 = hi(n[0] * m') + hi(a[0] * b[0]) + hi(n[0] * m')

    mulx    8(%rcx), %rax, %r14         // (r14, rax) = n[1] * m'
    adcx    %rax, %rdi
    adox    %r15, %r14                  // r11 = hi(a[1] * b[0]) + lo(a[2] * b[0]) + hi(n[1] * m')
    movq    %rdi, -32(%rbp)

    mulx    16(%rcx), %rax, %r15        // (r15, rax) = n[2] * m'
    adcx    %rax, %r14
    adox    %r11, %r15                  // r11 = hi(a[2] * b[0]) + lo(a[3] * b[0]) + hi(n[2] * m')
    movq    %r14, -24(%rbp)

    mulx    24(%rcx), %rax, %r11        // (r11, rax) = n[3] * m'
    adcx    %rax, %r15
    adox    %r10, %r11                  // r11 = hi(n[3] * m')
    movq    %r15, -16(%rbp)

    leaq    4*8(%rsi),%rsi              // a offset 4 blocks
    leaq    4*8(%rcx),%rcx              // n offset 4 blocks
    movq    (%r13),%rdx                 // rdx = b[0]

.align  16
.Loop1st4x:
    mulx    (%rsi), %r12, %r14          // r14 = hi(a[4] * b[0]), r12 = lo(a[4] * b[0])
    adcx    %r10, %r11                  // r11 += carry
    mulx    8(%rsi), %rax, %r15         // r15 = hi(a[5] * b[0]), rax = lo(a[5] * b[0])
    adcx    %rbx, %r12                  // r12 = hi(a[3] * b[0]) + lo(a[4] * b[0])
    adcx    %rax, %r14                  // r14 = hi(a[4] * b[0]) + lo(a[5] * a[0])
    mulx    16(%rsi), %rax, %rdi        // rax = hi(a[6] * b[0]), rax = lo(a[6] * b[0])
    adcx    %rax, %r15                  // r15 = hi(a[5] * b[0]) + lo(a[6] * a[0])
    mulx    24(%rsi), %rax, %rbx        // rax = hi(a[7] * b[0]), rdi = lo(a[7] * b[0])
    adcx    %rax, %rdi                  // rbx = hi(a[6] * b[0]) + lo(a[7] * b[0])
    adcx    %r10, %rbx                  // rdi = hi(a[7] * b[0]) + CF

    movq    %r8, %rdx
    adox    %r11,%r12                   // r12 = hi(a[3] * b[0]) + lo(b[4] * a[0]) + hi(n[3] * m')
    mulx    (%rcx), %rax, %r11          // (rax, r8) = n[4] * m'
    leaq    4*8(%rsi), %rsi             // a offset 4 blocks
    adcx    %rax,%r12                   // r12 = hi(a[3] * b[0]) + lo(b[4] * a[0])
                                        //     + hi(n[3] * m') + lo(n[4] * m')
    adox    %r14, %r11                  // r8 = hi(a[4] * b[0]) + lo(a[5] * b[0]) + hi(n[4] * m')


    mulx    8(%rcx), %rax, %r14         // (rax, r14) = n[5] * m'
    leaq    4*8(%rbp), %rbp             // tmp offset 4 blocks
    adcx    %rax, %r11                  // r8  = hi(a[4] * b[0]) + lo(a[5] * b[0])
                                        //     + hi(n[4] * m') + lo(n[5] * m')
    adox    %r15, %r14                  // r14 = hi(a[5] * b[0]) + lo(a[6] * a[0])
                                        //     + ho(n[5] * m')

    mulx    16(%rcx), %rax, %r15         // (rax, r15) = n[6] * m'
    movq    %r12, -5*8(%rbp)
    adcx    %rax, %r14                   // r14 = hi(a[5] * b[0]) + lo(a[6] * a[0])
                                         //     + hi(n[5] * m') + lo(n[6] * m')
    adox    %rdi, %r15                   // r15 = hi(a[6] * b[0]) + lo(a[7] * b[0])
                                         //     + hi(n[6] * m')
    movq    %r11, -4*8(%rbp)

    mulx    24(%rcx), %rax, %r11         // (rax, r11) = n[7] * m'
    movq    %r14, -3*8(%rbp)
    adcx    %rax, %r15                   // r15 = hi(a[6] * b[0]) + lo(a[7] * b[0])
                                         //     + hi(n[6] * m') + lo(n[7] * m')

    adox    %r10, %r11
    movq    %r15, -2*8(%rbp)

    leaq    4*8(%rcx), %rcx             // n offset 4 blocks
    movq    (%r13),%rdx                 // recover rdx
    dec     %r9
    jnz      .Loop1st4x

    movq    32(%rsp), %r15              // r15 = size * 8
    leaq    8(%r13), %r13               // b offset 1 blocks

    adcx    %r10, %r11                  // hi(n[7] * m') + CF, here OX CF are carried.
    addq    %r11, %rbx                  // hi(a[7] * b[0]) + hi(n[7] * m')
    sbbq    %r11,%r11                   // check r11 > 0
    movq    %rbx, -1*8(%rbp)

.align  4
.LoopOuter4x:
    // cal a[0 ~ 3] * b[i]
    movq    (%r13),%rdx                 // rdx = b[i]
    mov     %r11, (%rbp)                // keep the highest carry
    subq    %r15, %rsi                  // get a[0]
    subq    %r15, %rcx                  // get n[0]
    leaq    80(%rsp),%rbp               // get tmp[0]

    // from here, a[0 ~ 3] * b[i] needs to add tmp
    mulx    (%rsi), %r12, %r14          // r14 = hi(a[0] * b[i]), r12 = lo(b[i] * a[0])
    xorq    %r10,%r10                   // get r10 = 0, and clear CF OF

    mulx    8(%rsi), %rax, %r15         // (r15, rax) = a[1] * b[i]
    adox    -4*8(%rbp), %r12            // lo(a[1] * b[i]) + tmp[0]
    adcx    %rax, %r14                  // r14 = hi(a[0] * b[i]) + lo(a[1] * b[i])

    mulx    16(%rsi), %rax, %r11        // (rax, r11) = a[2] * b[0]
    adox    -3*8(%rbp),%r14             // r14 = hi(a[1] * b[i]) + lo(a[1] * b[i]) + tmp[1]
    adcx    %rax, %r15                  // r15 = hi(a[1] * b[i]) + lo(a[2] * b[i])

    mulx    24(%rsi), %rax, %rbx        // (rax, rbx) = a[3] * b[0]
    adox    -2*8(%rbp),%r15             // r15 = hi(a[2] * b[i]) + lo(a[2] * b[i]) + tmp[2]
    adcx    %rax, %r11                  // r11 = hi(a[2] * b[0]) + lo(a[3] * b[0])
    adox    -1*8(%rbp),%r11             // r11 = hi(a[2] * b[i]) + lo(a[3] * b[i]) + tmp[3]
    adcx    %r10,%rbx
    movq    %r12, %rdx
    adox    %r10,%rbx

    imulq   16(%rsp),%rdx               // 16(%rsp) save k0, r8 = t[0] * k0 = m', imulq will change CF
    mulx    (%rcx), %rax, %r8           // (rax, r8) = n[0] * m'
    xorq    %r10, %r10                  // clear CF

    adcx    %rax, %r12                  // r12 = lo(b[0] * a[0]) + lo(n[0] * m')
    adox    %r14, %r8                   // r8 = hi(n[0] * m') + hi(a[0] * b[0]) + hi(n[0] * m')

    mulx    8(%rcx), %rax, %rdi         // (rdi, rax) = n[1] * m'
    leaq    4*8(%rsi),%rsi              // a offsets 4
    adcx    %rax, %r8
    adox    %r15, %rdi                  // r11 = hi(a[1] * b[0]) + lo(a[2] * b[0]) + hi(n[1] * m')

    mulx    16(%rcx), %rax, %r15        // (rdi, rax) = n[2] * m'
    movq    %r8, -32(%rbp)
    adcx    %rax, %rdi
    adox    %r11, %r15                  // r11 = hi(a[2] * b[0]) + lo(a[3] * b[0]) + hi(n[2] * m')

    mulx    24(%rcx), %rax, %r11        // (rdi, rax) = n[3] * m'
    movq    %rdi, -24(%rbp)
    adcx    %rax, %r15
    adox    %r10, %r11                  // r11 = hi(n[3] * m')
    movq    %r15, -16(%rbp)

    leaq    4*8(%rcx),%rcx              // n offsets 4

    movq    %rdx, %r8                   // r8 = t[0] * k0 = m'
    movq    (%r13), %rdx                // rdx = b[i]
    movq    24(%rsp), %r9

.align  16
.Linner4x:
    mulx    (%rsi), %r12, %r14          // r14 = hi(a[4] * b[i]), r12 = lo(a[4] * b[i])
    adcx    %r10, %r11                  // carry of previous round

    adox    %rbx, %r12                  // r12 = hi(a[3] * b[i]) + lo(a[4] * b[i])

    mulx    8(%rsi), %rax, %r15         // r15 = hi(a[5] * b[i]), rax = lo(a[5] * b[0])
    adcx    (%rbp), %r12                // r12 = hi(a[3] * b[i]) + lo(a[4] * b[i]) + tmp[4] --> 所以这里t不偏移
    adox    %rax,  %r14                 // r14 = hi(a[4] * b[i]) + lo(a[5] * b[0])

    mulx    16(%rsi), %rax, %rdi        // rax = hi(a[6] * b[i]), rax = lo(a[6] * b[i])
    adcx    8(%rbp), %r14               // r12 = hi(a[3] * b[i]) + lo(a[4] * b[i]) + tmp[5]
    adox    %rax, %r15                  // r15 = hi(a[5] * b[i]) + lo(a[6] * b[i])

    mulx    24(%rsi), %rax, %rbx        // rax = hi(a[7] * b[i]), rdi = lo(a[7] * b[i])
    adcx    16(%rbp), %r15              // r12 = hi(a[3] * b[i]) + lo(a[4] * b[i]) + tmp[6]
    adox    %rax, %rdi                  // rbx = hi(a[6] * b[i]) + lo(a[7] * b[i])

    adox    %r10, %rbx                  // rbx += OF
    adcx    24(%rbp), %rdi               // rdi = hi(a[6] * b[i]) + lo(a[7] * b[i]) + tmp[7]
    adcx    %r10, %rbx                  // rbx += CF

    // update rdx, begin cal n[i] * k0 * m
    adox    %r11,%r12                   // r12 = hi(a[3] * b[i]) + lo(a[4] * b[i]) + hi(n[3] * m')
    movq    %r8, %rdx
    mulx    (%rcx), %rax, %r11          // (rax, r8) = n[4] * m'
    leaq    4*8(%rbp), %rbp             // tmp offsets 4
    adcx    %rax,%r12                   // r12 = hi(a[3] * b[i]) + lo(b[4] * a[i])
                                        //     + hi(n[3] * m') + lo(n[4] * m')
    adox    %r14, %r11                  // r8 = hi(a[4] * b[i]) + lo(a[5] * b[i]) + hi(n[4] * m')

    mulx    8(%rcx), %rax, %r14         // (rax, r14) = n[5] * m'
    leaq    4*8(%rsi), %rsi             // a offsets 4
    adcx    %rax, %r11                  // r8  = hi(a[4] * b[i]) + lo(a[5] * b[i])
                                        //     + hi(n[4] * m') + lo(n[5] * m')
    adox    %r15, %r14                  // r14 = hi(a[5] * b[i]) + lo(a[6] * a[i])
                                        //     + ho(n[5] * m')

    mulx    16(%rcx), %rax, %r15        // (rax, r15) = n[6] * m'
    movq    %r12, -5*8(%rbp)
    adcx    %rax, %r14                  // r14 = hi(a[5] * b[i]) + lo(a[6] * b[i])
                                        //     + hi(n[5] * m') + lo(n[6] * m')
    movq    %r11, -4*8(%rbp)
    adox    %rdi, %r15                  // r15 = hi(a[6] * b[i]) + lo(a[7] * b[i])
                                        //     + hi(n[6] * m')

    mulx    24(%rcx), %rax, %r11        // (rax, r11) = n[7] * m'
    movq    %r14, -3*8(%rbp)
    adcx    %rax, %r15                  // r15 = hi(a[6] * b[0]) + lo(a[7] * b[0])
                                        //     + hi(n[6] * m') + lo(n[7] * m')

    adox    %r10, %r11
    movq    %r15, -2*8(%rbp)

    leaq    4*8(%rcx), %rcx             // n offsets 4
    movq    (%r13), %rdx
    dec     %r9
    jnz     .Linner4x

    movq    32(%rsp), %r15              // r15 = size * 8
    leaq    8(%r13), %r13               // b offsets 1.

    adcx    %r10, %r11                  // hi(n[7] * m') + OF + CF
    subq    0*8(%rbp), %r10
    adcx    %r11, %rbx                  // hi(a[7] * b[0]) + hi(n[7] * m')
    sbbq    %r11,%r11
    movq    %rbx, -1*8(%rbp)
    cmp     40(%rsp), %r13
    jne    .LoopOuter4x

    leaq   48(%rsp),%rbp                // rbp = tmp[0]
    subq    %r15, %rcx                  // rcx= n[0]
    negq    %r11

    movq   24(%rsp), %rdx            // rdx = size/4

    movq   8(%rsp), %rdi             // get r[0]

    // cal tmp - n
    movq    0(%rbp), %rax            // rax = tmp[0]
    movq    8(%rbp), %rbx            // rbx = tmp[1]
    movq    16(%rbp), %r10           // r10 = tmp[2]
    movq    24(%rbp), %r12           // r12 = tmp[3]

    leaq    32(%rbp), %rbp           // tmp += 4

    subq    0(%rcx), %rax            // tmp[0] - n[0]
    sbbq    8(%rcx), %rbx            // tmp[1] - n[1]
    sbbq    16(%rcx), %r10           // tmp[2] - n[2]
    sbbq    24(%rcx), %r12           // tmp[3] - n[3]

    leaq    32(%rcx), %rcx           // n += 4

    movq    %rax, 0(%rdi)            // r save the tmp - n
    movq    %rbx, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r12, 24(%rdi)

    leaq    32(%rdi), %rdi           // r += 4

.LoopSub4x:
    movq    0(%rbp), %rax            // rax = tmp[0]
    movq    8(%rbp), %rbx            // rbx = tmp[1]
    movq    16(%rbp), %r10           // r10 = tmp[2]
    movq    24(%rbp), %r12           // r12 = tmp[3]

    leaq    32(%rbp), %rbp

    sbbq    0(%rcx), %rax            // tmp[0] - n[0]
    sbbq    8(%rcx), %rbx            // tmp[1] - n[1]
    sbbq    16(%rcx), %r10           // tmp[2] - n[2]
    sbbq    24(%rcx), %r12           // tmp[3] - n[3]

    leaq    32(%rcx), %rcx

    movq    %rax, 0(%rdi)
    movq    %rbx, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r12, 24(%rdi)

    leaq    32(%rdi), %rdi

    decq    %rdx                    // j--
    jnz     .LoopSub4x              // if j != 0

    sbbq    $0,%r11                 // cancellation of highest carry
    subq    %r15, %rbp              // rbp = tmp[0]
    subq    %r15, %rdi              // r = n[0]

    movq    24(%rsp), %r10          // r10 = size/4 - 1

    pxor    %xmm2,%xmm2             // xmm0 = 0
    movq    %r11, %xmm0
    pcmpeqd %xmm1,%xmm1             // xmm5 = -1
    pshufd  $0,%xmm0,%xmm0
    pxor    %xmm0,%xmm1
    xorq    %rax,%rax

    movdqa  (%rbp,%rax),%xmm5      // Copy the result to r.
    movdqu  (%rdi,%rax),%xmm3
    pand    %xmm0,%xmm5
    pand    %xmm1,%xmm3
    movdqa  16(%rbp,%rax),%xmm4
    movdqu  %xmm2,(%rbp,%rax)
    por     %xmm3,%xmm5
    movdqu  16(%rdi,%rax),%xmm3
    movdqu  %xmm5,(%rdi,%rax)
    pand    %xmm0,%xmm4
    pand    %xmm1,%xmm3
    movdqa  %xmm2,16(%rbp,%rax)
    por     %xmm3,%xmm4
    movdqu  %xmm4,16(%rdi,%rax)
    leaq    32(%rax),%rax

.align  16
.LoopCopy4x:
    movdqa  (%rbp,%rax),%xmm5
    movdqu  (%rdi,%rax),%xmm3
    pand    %xmm0,%xmm5
    pand    %xmm1,%xmm3
    movdqa  16(%rbp,%rax),%xmm4
    movdqu  %xmm2,(%rbp,%rax)
    por     %xmm3,%xmm5
    movdqu  16(%rdi,%rax),%xmm3
    movdqu  %xmm5,(%rdi,%rax)
    pand    %xmm0,%xmm4
    pand    %xmm1,%xmm3
    movdqa  %xmm2,16(%rbp,%rax)
    por     %xmm3,%xmm4
    movdqu  %xmm4,16(%rdi,%rax)
    leaq    32(%rax),%rax
    decq    %r10                        // j--
    jnz     .LoopCopy4x
    movq    0(%rsp),%rsi                // rsi = pressed-stacked rsp.
    movq    $1,%rax
    leaq    (%rsi),%rsp                 // Restore srsp.
    RESTORE_REGISTERS
    ret
.cfi_endproc
.size   MontMul4x,.-MontMul4x

.type   MontSqr8x,@function
.align  32
MontSqr8x:
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
    leaq    -96(%rbp,%r9,2),%rbp    // Allocate a frame + 2 x size.

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
.size   MontSqr8x,.-MontSqr8x

.type   MontSqr8Inner,@function
.align  32
MontSqr8Inner:
.cfi_startproc

    movq    %rsi, %r8
    addq    %r9, %r8
    movq    %r8, 64(%rsp)           // save a[size]
    movq    %r9, 56(%rsp)           // save size * 8
    leaq    88(%rsp), %rbp          // tmp的首地址

    leaq    88(%rsp,%r9,2),%rbx
    movq    %rbx,16(%rsp)   // t[size * 2]
    leaq    (%rcx,%r9),%rax
    movq    %rax,8(%rsp)   // n[size]
    jmp     .MontSqr8xBegin

.MontSqr8xInitStack:
    movdqa    %xmm2,0*8(%rbp)
    movdqa    %xmm2,2*8(%rbp)
    movdqa    %xmm2,4*8(%rbp)
    movdqa    %xmm2,6*8(%rbp)
.MontSqr8xBegin:
    movdqa    %xmm2,8*8(%rbp)
    movdqa    %xmm2,10*8(%rbp)
    movdqa    %xmm2,12*8(%rbp)
    movdqa    %xmm2,14*8(%rbp)
    lea       128(%rbp), %rbp
    subq      $64, %r9
    jnz       .MontSqr8xInitStack

    xorq    %rbx, %rbx                 // clear CF OF
    movq    $0, %r13
    movq    $0, %r12
    movq    $0, %r11
    movq    $0, %rdi
    movq    $0, %r15
    movq    $0, %rcx

    leaq    88(%rsp), %rbp             // set tmp[0]
    movq    0(%rsi), %rdx              // rdx = a[0]
    movq    $0, %r10

.LoopOuterSqr8x:

    // begin a[0] * a[1~7]
    mulx    8(%rsi), %rax, %r14        // rax = lo(a[1] * a[0]), r14 = hi(a[1] * a[0])
    adcx    %rbx, %rax

    movq    %rax, 8(%rbp)
    adox    %r13, %r14

    mulx    16(%rsi), %rax, %r13       // (rax, r13) = a[2] * a[0]
    adcx    %rax, %r14                 // r14 = hi(a[1] * a[0]) + lo(a[2] * a[0])
    adox    %r12, %r13

    mulx    24(%rsi), %rax, %r12       // (rax, r12) = a[3] * a[0]
    movq    %r14, 16(%rbp)
    adcx    %rax, %r13                 // r13 = hi(a[2] * a[0]) + lo(a[3] * a[0])
    adox    %r11, %r12

    mulx    32(%rsi), %rax, %r11       // (rax, r11) = a[4] * a[0]
    adcx    %rax, %r12                 // r12 = hi(a[3] * a[0]) + lo(a[4] * a[0])

    adox    %rdi, %r11
    mulx    40(%rsi), %rax, %rdi       // (rax, rdi) = a[5] * a[0]
    adcx    %rax, %r11                 // r11 = hi(a[4] * a[0]) + lo(a[5] * a[0])

    adox    %r15, %rdi
    mulx    48(%rsi), %rax, %r8        // (rax, r8) = a[6] * a[0]
    adcx    %rax, %rdi                 // rdi = hi(a[5] * a[0]) + lo(a[6] * a[0])
    adox    %rcx, %r8

    mulx    56(%rsi), %rax, %rbx       // (rax, rbx) = a[7] * a[0]
    adcx    %rax, %r8                  // r8 = hi(a[6] * a[0]) + lo(a[7] * a[0])
    adox    %r10, %rbx                 // rbx += CF
    adcq    64(%rbp), %rbx             // rbx += CF

    sbbq    %r9, %r9                   // get high CF
    xorq    %r10, %r10                 // clear CF OF

    // begin a[1] * a[2~7]
    movq    8(%rsi), %rdx              // rdx = a[1]
    mulx    16(%rsi), %rax, %rcx       // rax = lo(a[2] * a[1]), rcx = hi(a[2] * a[1])
    adcx    %rax, %r13                 // r13 = hi(a[2] * a[0]) + lo(a[3] * a[0]) + lo(a[2] * a[1])

    mulx    24(%rsi), %rax, %r14       // rax = lo(a[3] * a[1]), r14 = hi(a[3] * a[1])
    movq    %r13, 24(%rbp)

    adox    %rax, %rcx                 // rcx = lo(a[3] * a[1]) + hi(a[2] * a[1])

    mulx    32(%rsi), %rax, %r13       // (rax, r13) = a[4] * a[1]
    adcx    %r12, %rcx                 // rcx = hi(a[3] * a[0]) + lo(a[4] * a[0]) + lo(a[3] * a[1]) + hi(a[2] * a[1])
    adox    %rax, %r14                 // r14 = lo(a[4] * a[1]) + hi(a[3] * a[1])

    mulx    40(%rsi), %rax, %r12       // (rax, r12) = a[5] * a[1]
    movq    %rcx, 32(%rbp)
    adcx    %r11, %r14                 // r14 = lo(a[4] * a[1]) + hi(a[3] * a[1]) + hi(a[4] * a[0]) + lo(a[5] * a[0])
    adox    %rax, %r13                 // r13 = lo(a[5] * a[1]) + hi(a[4] * a[1])

    mulx    48(%rsi), %rax, %r11       // (rax, r11) = a[6] * a[1]
    adcx    %rdi, %r13                 // r13 = lo(a[5] * a[1]) + hi(a[4] * a[1]) + hi(a[5] * a[0]) + lo(a[6] * a[0])
    adox    %rax, %r12                 // r12 = hi(a[5] * a[1]) + lo(a[6] * a[1])

    mulx    56(%rsi), %rax, %rdi       // (rax, rdi) = a[7] * a[1]
    adcx    %r8, %r12                  // r12 = hi(a[5] * a[1]) + lo(a[6] * a[1]) + hi(a[6] * a[0]) + lo(a[7] * a[0])
    adox    %rax, %r11                 // r11 = hi(a[6] * a[1]) + lo(a[7] * a[1])
    adcx    %rbx, %r11                 // r11 = hi(a[6] * a[1]) + lo(a[7] * a[1]) + hi(a[7] * a[0])

    adcx    %r10, %rdi                 // rdi += CF
    adox    %r10, %rdi                 // rdi += OF

    movq    16(%rsi), %rdx             // rdx = a[2]

    // begin a[2] * a[3~7]
    mulx    24(%rsi), %rax, %rbx       // rax = lo(a[2] * a[3]), rbx = hi(a[2] * a[3])
    adcx    %rax, %r14                 // r14 = lo(a[4] * a[1]) + hi(a[3] * a[1]) + hi(a[4] * a[0]) + lo(a[5] * a[0])
                                       //     + lo(a[2] * a[3])

    mulx    32(%rsi), %rax, %rcx       // rax = lo(a[2] * a[4]), rcx = hi(a[2] * a[4])

    movq    %r14, 40(%rbp)
    adox    %rax, %rbx                 // r13 = lo(a[2] * a[4]) + hi(a[2] * a[3])

    mulx    40(%rsi), %rax, %r8        // rax = lo(a[2] * a[5]), rcx = hi(a[2] * a[5])
    adcx    %r13, %rbx                 // rbx = lo(a[2] * a[4]) + hi(a[2] * a[3])
                                       //     + lo(a[5] * a[1]) + hi(a[4] * a[1]) + hi(a[5] * a[0]) + lo(a[6] * a[0])

    adox    %rax, %rcx                 // rcx = hi(a[2] * a[4]) + lo(a[2] * a[5])
    movq    %rbx, 48(%rbp)

    mulx    48(%rsi), %rax, %r13       // rax = lo(a[2] * a[6]), r13 = hi(a[2] * a[6])
    adcx    %r12, %rcx                 // rcx = hi(a[5] * a[1]) + lo(a[6] * a[1]) + hi(a[6] * a[0])
                                       //     + lo(a[7] * a[0]) + hi(a[2] * a[4]) + lo(a[2] * a[5])

    adox    %rax, %r8                  // r8 = hi(a[2] * a[5]) + lo(a[2] * a[6])

    mulx    56(%rsi), %rax, %r12       // rax = lo(a[2] * a[7]), r12 = hi(a[2] * a[7])

    adcx    %r11, %r8                  // r8 = hi(a[2] * a[5]) + lo(a[2] * a[6])
                                       //     + hi(a[6] * a[1]) + lo(a[7] * a[1]) + hi(a[7] * a[0])

    adox    %rax, %r13                 // r13 = hi(a[2] * a[6]) + lo(a[2] * a[7])
    adcx    %rdi, %r13                 // r13 = hi(a[2] * a[6]) + lo(a[2] * a[7]) + hi(a[7] * a[1])

    adcx    %r10, %r12                 // r12 += CF
    adox    %r10, %r12                 // r12 += OF

    movq    24(%rsi), %rdx             // rdx = a[3]

    // begin a[3] * a[4~7]
    mulx    32(%rsi), %rax, %r14       // rax = lo(a[3] * a[4]), r14 = hi(a[3] * a[4])
    adcx    %rax, %rcx                 // rcx = hi(a[5] * a[1]) + lo(a[6] * a[1]) + hi(a[6] * a[0])
                                       //     + lo(a[7] * a[0]) + hi(a[2] * a[4]) + lo(a[2] * a[5]) + lo(a[3] * a[4])

    mulx    40(%rsi), %rax, %rbx       // rax = lo(a[3] * a[5]), rbx = hi(a[3] * a[5])
    adox    %rax, %r14                 // r14 = hi(a[3] * a[4]) + lo(a[3] * a[5])

    mulx    48(%rsi), %rax, %r11       // rax = lo(a[3] * a[6]), r11 = hi(a[3] * a[6])
    adcx    %r8, %r14                  // r14 = hi(a[3] * a[4]) + lo(a[3] * a[5])+ hi(a[2] * a[5]) + lo(a[2] * a[6])
                                       //     + hi(a[6] * a[1]) + lo(a[7] * a[1]) + hi(a[7] * a[0])
    adox    %rax, %rbx                 // rbx = hi(a[3] * a[5]) + lo(a[3] * a[6])

    mulx    56(%rsi), %rax, %rdi       // rax = lo(a[3] * a[7]), rdi = hi(a[3] * a[7])
    adcx    %r13, %rbx                 // rbx = hi(a[3] * a[5]) + lo(a[3] * a[6])
                                       //     + hi(a[2] * a[6]) + lo(a[2] * a[7]) + hi(a[7] * a[1])
    adox    %rax, %r11                 // r11 = hi(a[3] * a[6]) + lo(a[3] * a[7])
    adcx    %r12, %r11                 // r11 = hi(a[2] * a[7]) + hi(a[3] * a[6]) + lo(a[3] * a[7])

    adcx    %r10, %rdi                 // rdi += CF
    adox    %r10, %rdi                 // rdi += OF

    movq    %rcx, 56(%rbp)
    movq    %r14, 64(%rbp)

    movq    32(%rsi), %rdx             // rdx = a[4]

    // begin a[4] * a[5~7]
    mulx    40(%rsi), %rax, %r13       // rax = lo(a[4] * a[5]), r13 = hi(a[4] * a[5])
    adcx    %rax, %rbx                 // rbx = hi(a[3] * a[5]) + lo(a[3] * a[6])
                                       //     + hi(a[2] * a[6]) + lo(a[2] * a[7]) + hi(a[7] * a[1]) + lo(a[4] * a[5])

    mulx    48(%rsi), %rax, %r12       // rax = lo(a[4] * a[6]), r12 = hi(a[4] * a[6])
    adox    %rax, %r13                 // r13 = lo(a[4] * a[6]) + hi(a[4] * a[5])

    mulx    56(%rsi), %rax, %r14       // rax = lo(a[4] * a[7]), r14 = hi(a[4] * a[7])
    adcx    %r11, %r13                 // r13 = hi(a[4] * a[5]) + hi(a[2] * a[7]) + hi(a[3] * a[6])
                                       //     + lo(a[3] * a[7])

    adox    %rax, %r12                 // r12 = hi(a[4] * a[6]) + lo(a[4] * a[7])
    adcx    %rdi, %r12                 // r12 = hi(a[4] * a[6]) + lo(a[4] * a[7]) + hi(a[3] * a[7])

    adcx    %r10, %r14                // r14 += CF
    adox    %r10, %r14                // r14 += OF

    movq    40(%rsi), %rdx            // rdx = a[5]

    // begin a[5] * a[6~7]
    mulx    48(%rsi), %rax, %r11      // rax = lo(a[5] * a[6]), r11 = hi(a[5] * a[6])

    adcx    %rax, %r12                // r14 = hi(a[4] * a[6]) + lo(a[4] * a[7]) + hi(a[3] * a[7]) + lo(a[5] * a[6])

    mulx    56(%rsi), %rax, %rdi      // rax = lo(a[5] * a[7]), rdi = hi(a[5] * a[7])

    adox    %rax, %r11                // r11 = hi(a[5] * a[6]) + lo(a[5] * a[7])
    adcx    %r14, %r11                // r11 = hi(a[5] * a[6]) + lo(a[5] * a[7]) + hi(a[4] * a[7])
    adcx    %r10, %rdi                // rdi += CF
    adox    %r10, %rdi                // rdi += OF

    movq    48(%rsi), %rdx            // rdx = a[6]

    mulx    56(%rsi), %rax, %r15      // rax = lo(a[7] * a[6]), r15 = hi(a[7] * a[6])
    adcx    %rax, %rdi                // rdi = hi(a[5] * a[6]) + lo(a[7] * a[6])
    adcx    %r10, %r15                // r15 += CF

    leaq    64(%rsi), %rsi

    cmp     64(%rsp), %rsi            // cmpared with a[size]
    je      .Lsqrx8xEnd

    neg     %r9
    movq    $0, %rcx
    movq    64(%rbp),%r14

    adcx    9*8(%rbp),%rbx
    adcx    10*8(%rbp),%r13
    adcx    11*8(%rbp),%r12
    adcx    12*8(%rbp),%r11
    adcx    13*8(%rbp),%rdi
    adcx    14*8(%rbp),%r15
    adcx    15*8(%rbp),%rcx

    leaq    (%rsi), %r10              // r10 = a[8]
    leaq    128(%rbp), %rbp
    sbbq    %rax,%rax
    movq    %rax, 72(%rsp)
    movq    %rbp, 80(%rsp)

    xor     %eax, %eax


    movq    -64(%rsi), %rdx

    movq    $-8, %r9

.align  32
.LoopSqr8x:
    movq    %r14,%r8

    // begin a[0] * a[8~11]
    mulx    0(%r10), %rax, %r14        // rax = lo(a[8] * a[0]), r14 = hi(a[8] * a[0])
    adcx    %rax, %r8
    adox    %rbx, %r14

    mulx    8(%r10), %rax, %rbx        // rax = lo(a[9] * a[0]), rbx = hi(a[8] * a[0])
    adcx    %rax, %r14
    adox    %r13, %rbx

    movq    %r8,(%rbp,%r9,8)

    mulx    16(%r10), %rax, %r13        // rax = lo(a[10] * a[0]), r13 = hi(a[10] * a[0])
    adcx    %rax, %rbx
    adox    %r12, %r13

    mulx    24(%r10), %rax, %r12        // rax = lo(a[11] * a[0]), r12 = hi(a[11] * a[0])
    adcx    %rax, %r13
    adox    %r11, %r12

    movq    $0, %r8

    mulx    32(%r10), %rax, %r11        // rax = lo(a[12] * a[0]), r11 = hi(a[12] * a[0])
    adcx    %rax, %r12
    adox    %rdi, %r11

    mulx    40(%r10), %rax, %rdi        // rax = lo(a[13] * a[0]), rdi = hi(a[13] * a[0])
    adcx    %rax, %r11
    adox    %r15, %rdi

    mulx    48(%r10), %rax, %r15        // rax = lo(a[14] * a[0]), r15 = hi(a[14] * a[0])
    adcx    %rax, %rdi
    adox    %rcx, %r15

    mulx    56(%r10), %rax, %rcx        // rax = lo(a[15] * a[0]), rcx = hi(a[15] * a[0])
    adcx    %rax, %r15
    adcx    %r8, %rcx                   // here r8 = 0
    adox    %r8, %rcx

    movq    8(%rsi,%r9,8),%rdx

    inc     %r9
    jnz     .LoopSqr8x

    leaq    64(%r10), %r10
    movq    $-8, %r9

    cmp     64(%rsp), %r10             // cmpared with a[size]
    je     .LoopSqr8xBreak

    subq     72(%rsp), %r8             // read the CF of the previous round.

    movq    -64(%rsi), %rdx

    adcx    0*8(%rbp),%r14
    adcx    1*8(%rbp),%rbx
    adcx    2*8(%rbp),%r13
    adcx    3*8(%rbp),%r12
    adcx    4*8(%rbp),%r11
    adcx    5*8(%rbp),%rdi
    adcx    6*8(%rbp),%r15
    adcx    7*8(%rbp),%rcx

    leaq    8*8(%rbp),%rbp

    sbbq     %rax, %rax
    xorq     %r8, %r8
    movq     %rax, 72(%rsp)

    jmp    .LoopSqr8x

.align  32
.LoopSqr8xBreak:

    xorq    %r10, %r10
    subq    72(%rsp),%r8
    adcx    %r10, %r14
    movq    0(%rsi),%rdx
    movq    %r14,0(%rbp)
    movq    80(%rsp), %r8

    adcx    %r10,%rbx
    adcx    %r10,%r13
    adcx    %r10,%r12
    adcx    %r10,%r11
    adcx    %r10,%rdi
    adcx    %r10,%r15
    adcx    %r10,%rcx

    cmp     %r8, %rbp
    je      .LoopOuterSqr8x

    // if tmp does not go to the end. The current value needs to be stored in tmp and updated.
    movq    %rbx,1*8(%rbp)
    movq    1*8(%r8),%rbx
    movq    %r13,2*8(%rbp)
    movq    2*8(%r8),%r13
    movq    %r12,3*8(%rbp)
    movq    3*8(%r8),%r12
    movq    %r11,4*8(%rbp)
    movq    4*8(%r8),%r11
    movq    %rdi,5*8(%rbp)
    movq    5*8(%r8),%rdi
    movq    %r15,6*8(%rbp)
    movq    6*8(%r8),%r15
    movq    %rcx,7*8(%rbp)
    movq    7*8(%r8),%rcx
    movq    %r8,%rbp
    jmp    .LoopOuterSqr8x

.align    32
.Lsqrx8xEnd:
    mov    %rbx,9*8(%rbp)
    mov    %r13,10*8(%rbp)
    mov    %r12,11*8(%rbp)
    mov    %r11,12*8(%rbp)
    mov    %rdi,13*8(%rbp)
    mov    %r15,14*8(%rbp)

    leaq    88(%rsp), %rbp          // tmp[0]

    movq    56(%rsp), %rcx          // rcx = size * 8
    sbbq    %rcx, %rsi              // get a[0]

    xorq    %r15, %r15              // clear CF OF, r15 = tmp[0] = 0
    movq    8(%rbp), %r14           // r14 = tmp[1]
    movq    16(%rbp), %r13          // r13 = tmp[2]
    movq    24(%rbp), %r12          // r12 = tmp[3]

    adox    %r14, %r14              // r14 = 2 * tmp[1]
    movq    0(%rsi), %rdx

.align  32
.LoopShiftAddSqr4x:

    mulx    %rdx, %rax, %rbx        // (rbx, rax) = a[0] * a[0]
    adox    %r13, %r13              // r13 = 2 * tmp[1]
    adox    %r12, %r12              // r12 = 2 * tmp[3]

    adcx    %rax, %r15              // r15 = 2 * tmp[0] + lo(a[0] * a[0])
    adcx    %rbx, %r14              // r14 = 2 * tmp[1] + hi(a[0] * a[0])

    movq    %r15, (%rbp)
    movq    %r14, 8(%rbp)

    movq    8(%rsi), %rdx

    mulx    %rdx, %rax, %rbx        // (rbx, rax) = a[1] * a[1]
    adcx    %rax, %r13              // r13 = 2 * tmp[2] + lo(a[1] * a[1])
    adcx    %rbx, %r12              // r12 = 2 * tmp[3] + hi(a[1] * a[1])

    movq    %r13, 16(%rbp)
    movq    %r12, 24(%rbp)

    movq    32(%rbp), %r15          // r15 = tmp[4]
    movq    40(%rbp), %r14          // r14 = tmp[5]
    movq    48(%rbp), %r13          // r13 = tmp[6]
    movq    56(%rbp), %r12          // r12 = tmp[7]

    movq    16(%rsi), %rdx
    mulx    %rdx, %rax, %rbx        // (rbx, rax) = a[2] * a[2]
    adox    %r15, %r15              // r15 = 2 * tmp[4]
    adcx    %rax, %r15              // r15 = 2 * tmp[4] + lo(a[2] * a[2])

    adox    %r14, %r14              // r14 = 2 * tmp[4]
    adcx    %rbx, %r14              // r14 = 2 * tmp[5] + hi(a[2] * a[2])

    movq    %r15, 32(%rbp)
    movq    %r14, 40(%rbp)

    movq    24(%rsi), %rdx
    mulx    %rdx, %rax, %rbx        // (rbx, rax) = a[3] * a[3]
    adox    %r13, %r13              // r13 = 2 * tmp[5]
    adcx    %rax, %r13              // r13 = 2 * tmp[5] + lo(a[3] * a[3])

    adox    %r12, %r12              // r12 = 2 * tmp[5]
    adcx    %rbx, %r12              // rbx = 2 * tmp[5] + hi(a[3] * a[3])

    movq    %r13, 48(%rbp)
    movq    %r12, 56(%rbp)

    leaq    32(%rsi), %rsi          // a[4]

    leaq    -32(%rcx),%rcx
    jrcxz   .LoopReduceSqr8xBegin   // if i != 0

    movq    64(%rbp), %r15          // r15 = tmp[8]
    movq    72(%rbp), %r14          // r14 = tmp[9]
    adox    %r15, %r15              // r15 = 2 * tmp[8]
    adox    %r14, %r14              // r14 = 2 * tmp[9]

    movq    80(%rbp), %r13          // r13 = tmp[8]
    movq    88(%rbp), %r12          // r12 = tmp[9]

    leaq    64(%rbp), %rbp

    movq    0(%rsi), %rdx

    jmp     .LoopShiftAddSqr4x      // if i != 0

.LoopReduceSqr8xBegin:
    xorq    %rax,%rax               // rax = 0
    leaq    88(%rsp), %rdi          // tmp[0]
    movq    $0, %r9                 // Save size.
    movq    %xmm1, %rbp             // get n[0]
    xorq    %rsi, %rsi              // rsi = 0

.align  32
.LoopReduceSqr8x:
    movq    %rax,80(%rsp)           // Store the highest carry bit.
    leaq    (%rdi,%r9),%rdi         // rdi = t[0]

    movq    (%rdi),%rdx             // rdx = t[0]
    movq    8(%rdi),%r9             // r9 = t[1]
    movq    16(%rdi),%r15           // r15 = t[2]
    movq    24(%rdi),%r14           // r14 = t[3]
    movq    32(%rdi),%r13           // r13 = t[4]
    movq    40(%rdi),%r12           // r12 = t[5]
    movq    48(%rdi),%r11           // r11 = t[6]
    movq    56(%rdi),%r10           // r10 = t[7]

    leaq    64(%rdi),%rdi           // rdi = t[8]

    movq    %rdx,%r8                // r8 = t[0]
    imulq   40(%rsp),%rdx           // rbx = k0 * t[0]
	xorq    %rbx,%rbx               // clear CF OF
    movl    $8,%ecx

.align  32
.LoopReduce8x:
	movq    %r8, %rbx
    movq    %rdx, 80(%rsp,%rcx,8)
    mulx    (%rbp), %rax, %r8      // (r8, rax) = m' * n[0]
    adcx    %rbx, %rax
    adox    %r9, %r8               // r9 = hi(m' * n[]) + t[1]

    mulx    8(%rbp), %rax, %r9     // (rdx, r9) = m' * n[0]
    adcx    %rax,%r8               // r9 = t[1] + lo(m' * n[1])
    adox    %r9, %r15              // r15 = hi(m' * n[1]) + t[2]

    mulx    16(%rbp), %r9, %rax    // (r9, rax) = m' * n[2]
    adcx    %r15, %r9              // r9 = hi(m' * n[1]) + lo(m' * n[2]) + t[2]
    adox    %rax, %r14             // rbx = hi(m' * n[2]) + t[3]

    mulx    24(%rbp), %r15, %rax   // (r15, rax) = m' * n[3]
    adcx    %r14,%r15              // r15 = hi(m' * n[2]) + lo(m' * n[3]) + t[3]
    adox    %rax,%r13              // r13 = hi(m' * n[3]) + t[4]

    mulx    32(%rbp), %r14, %rax   // (r14, rax) = m' * n[4]
    adcx    %r13,%r14              // r14 = hi(m' * n[3]) + lo(m' * n[4]) + t[4]
    adox    %rax,%r12              // r12 = hi(m' * n[4]) + t[5]

    mulx    40(%rbp), %r13, %rax   // (r13, rax) = m' * n[5]
    adcx    %r12,%r13              // r13 = hi(m' * n[4]) + lo(m' * n[5]) + t[5]
    adox    %rax,%r11              // r12 = hi(m' * n[5]) + t[6]

    mulx    48(%rbp), %r12, %rax   // (r12, rax) = m' * n[6]
    adcx    %r11,%r12              // r13 = hi(m' * n[5]) + lo(m' * n[6]) + t[6]
    adox    %r10,%rax              // r12 = hi(m' * n[5]) + t[7]

    mulx    56(%rbp), %r11, %r10   // (r11, r10) = m' * n[7]
    adcx    %rax,%r11              // r13 = hi(m' * n[6]) + lo(m' * n[7]) + t[7]

    adcx    %rsi,%r10              // r12 = hi(m' * n[7]) + t[8]
    adox    %rsi,%r10              // r12 = hi(m' * n[7]) + t[8]

    movq    %r8, %rdx
    mulx    40(%rsp), %rdx, %rax   // (rdx, rax) = m' * n[7]

    decl    %ecx                   // ecx--
    jnz     .LoopReduce8x          // if ecx != 0

    leaq    64(%rbp),%rbp          // rbp += 64, n Pointer Offset.
    xorq    %rax,%rax              // rax = 0
    cmpq    8(%rsp),%rbp           // rbp = n[size]
    jae     .LoopEndCondMul8x

    addq    (%rdi),%r8             // r8 += t[0]
    adcq    8(%rdi),%r9            // r9 += t[1]
    adcq    16(%rdi),%r15          // r15 += t[2]
    adcq    24(%rdi),%r14          // r14 += t[3]
    adcq    32(%rdi),%r13          // r13 += t[4]
    adcq    40(%rdi),%r12          // r12 += t[5]
    adcq    48(%rdi),%r11          // r11 += t[6]
    adcq    56(%rdi),%r10          // r10 += t[7]
    sbbq    %rsi,%rsi              // rsi = -CF

    movq    144(%rsp),%rdx         // rbx = m', 80 + 64
    movl    $8,%ecx
    xor     %eax,%eax
.align  32
.LoopLastSqr8x:
    mulx    (%rbp), %rax, %rbx     // (rbx, rax) = m' * n[0]
    adcx    %rax,%r8               // r8 = lo(m' * n[0]) + t[0]
    movq    %r8,(%rdi)             // t[0] = r8
    leaq    8(%rdi),%rdi           // t++

    adox    %rbx,%r9               // r9 = hi(m' * n[]) + t[2]

    mulx    8(%rbp), %r8, %rbx     // (r8, rbx) = m' * n[0]
    adcx    %r9,%r8                // r9 = t[1] + lo(m' * n[1])
    adox    %rbx, %r15             // r15 = hi(m' * n[1]) + t[2]

    mulx    16(%rbp), %r9, %rbx    // (r9, rbx) = m' * n[2]
    adcx    %r15, %r9              // r9 = hi(m' * n[1]) + lo(m' * n[2]) + t[2]
    adox    %rbx, %r14             // r14 = hi(m' * n[2]) + t[3]

    mulx    24(%rbp), %r15, %rbx   // (r15, rbx) = m' * n[3]
    adcx    %r14,%r15              // r15 = hi(m' * n[2]) + lo(m' * n[3]) + t[3]
    adox    %rbx,%r13              // r13 = hi(m' * n[3]) + t[4]

    mulx    32(%rbp), %r14, %rbx   // (r14, rbx) = m' * n[4]
    adcx    %r13,%r14              // r14 = hi(m' * n[3]) + lo(m' * n[4]) + t[4]
    adox    %rbx,%r12              // r12 = hi(m' * n[4]) + t[5]

    mulx    40(%rbp), %r13, %rbx   // (r13, rbx) = m' * n[5]
    adcx    %r12,%r13              // r13 = hi(m' * n[4]) + lo(m' * n[5]) + t[5]
    adox    %rbx,%r11              // r11 = hi(m' * n[5]) + t[6]

    mulx    48(%rbp), %r12, %rbx   // (r12, rbx) = m' * n[6]
    adcx    %r11,%r12              // r12 = hi(m' * n[5]) + lo(m' * n[6]) + t[6]
    adox    %r10,%rbx              // rbx = hi(m' * n[5]) + t[7]

    movq    $0, %rax

    mulx    56(%rbp), %r11, %r10   // (r11, r10) = m' * n[7]
    adcx    %rbx,%r11              // r11 = hi(m' * n[6]) + lo(m' * n[7]) + t[7]

    adcx    %rax,%r10              // r10 = hi(m' * n[7]) + t[8]
    adox    %rax,%r10              // r10 = hi(m' * n[7]) + t[8]

    movq    72(%rsp,%rcx,8),%rdx   // rbx = t[i] * k0

    decl    %ecx                   // ecx--
    jnz     .LoopLastSqr8x         // if ecx != 0

    leaq    64(%rbp),%rbp          // n += 8
    cmpq    8(%rsp),%rbp           // Check whether rbp is at the end of the n array. If yes, exit the loop.
    jae     .LoopSqrBreak8x

    movq    144(%rsp),%rdx          // rbx = m'
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
    xorq    %rax, %rax
    jmp     .LoopLastSqr8x

.align  32
.LoopSqrBreak8x:
    xorq    %rax,%rax               // rax = 0
    addq    80(%rsp),%r8            // r8 += Highest carry bit.
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

    cmpq    16(%rsp),%rdi           // Cycle the entire t[].
    jb      .LoopReduceSqr8x
    ret
.cfi_endproc
.size   MontSqr8Inner,.-MontSqr8Inner

#endif
