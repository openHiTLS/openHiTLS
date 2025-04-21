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
#ifdef HITLS_CRYPTO_X25519

.file "x25519_x86_64.S"
.text

.macro push_stack
    /* Save register. The following registers need to be saved by the caller and restored when the function exits. */
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    /* Allocate stack space and store the following necessary content: */
    leaq	-32(%rsp), %rsp
.endm

.macro pop_stack
    /* Recovery register */
    movq    32(%rsp),%r15
    movq    40(%rsp),%r14
    movq    48(%rsp),%r13
    movq    56(%rsp),%r12
    movq    64(%rsp),%rbp
    movq    72(%rsp),%rbx

    /* Restore stack pointer. The stack is opened with 32 bytes and 6 registers are restored.
       The total number is 80 bytes. */
    leaq    80(%rsp), %rsp
.endm

.macro u51mul cur, low, high, next
    mulq    \cur
    addq    %rax, \low
    movq    \next, %rax
    adcq    %rdx, \high
.endm

.macro reduce
    /* Retain the last 51 digits. */
    movq    $0x7ffffffffffff, %rbp

    /* Calculate h2' */
    movq    %r12, %rax
    shrq    $51, %r12
    shlq    $13, %r13

    /* Calculate h0' */
    movq    %r8, %rsi
    shrq    $51, %r8
    shlq    $13, %r9

    /* Calculate h2' */
    andq    %rbp, %rax              // h2' = rax = h2 & (2^51 - 1) = r12 & (2^51 - 1)
    orq     %r12, %r13              // r13 = (h2 >> 51)
    addq    %r13, %r14              // h3 += (h2 >> 51)
    adcq    $0, %r15

    /* Calculate h0' */
    andq    %rbp, %rsi              // h0' = rsi = h0 & (2^51 - 1) = r8 & (2^51 - 1)
    orq     %r8, %r9                // r9 = (h0 >> 51)
    addq    %r9, %r10               // h1 += (h0 >> 51)
    adcq    $0, %r11

    /* Calculate h3' */
    movq    %r14, %r8
    shrq    $51, %r14
    shlq    $13, %r15
    andq    %rbp, %r8               // h3' = r8 = h3 & (2^51 - 1) = r14 & (2^51 - 1)
    orq     %r14, %r15              // r15 = (h3 >> 51)
    addq    %r15, %rbx              // h4 += (h3 >> 51)
    adcq    $0, %rcx

    /* Calculate h1' */
    movq    %r10, %rdx
    shrq    $51, %r10
    shlq    $13, %r11
    andq    %rbp, %rdx              // h1' = rdx = h1 & (2^51 - 1) = r10 & (2^51 - 1)
    orq     %r10, %r11              // r11 = (h1 >> 51)
    addq    %r11, %rax              // h2 += (h1 >> 51)

    /* Calculate h4' */
    movq    %rbx, %r9
    shrq    $51, %rbx
    shlq    $13, %rcx
    andq    %rbp, %r9               // h4' = r9 = h4 & (2^51 - 1) = rbx & (2^51 - 1)
    orq     %rbx, %rcx              // rcx = (h4 >> 51)

    /* out[0] = out[0] + 19 * carry */
    leaq    (%rcx, %rcx, 8), %r10   // r10 = 8 * rcx
    leaq    (%rcx, %r10, 2), %rcx   // rcx = 2 * (8 * rcx) + rcx = 19 * rcx
    addq    %rcx, %rsi

    /* h2 remaining */
    movq    %rax, %r10
    andq    %rbp, %rax              // h2 &= (2^51 - 1)
    shrq    $51, %r10
    addq    %r10, %r8

    /* out[1] += out[0] >> 51 */
    movq    %rsi, %r10

    /* out[0] &= (2^51 - 1) */
    andq    %rbp, %rsi
    shrq    $51, %r10
    addq    %r10, %rdx

    /* Storing Results */
    movq    %rsi, (%rdi)            // h0'
    movq    %rdx, 8(%rdi)           // h1'
    movq    %rax, 16(%rdi)          // h2'
    movq    %r8, 24(%rdi)           // h3'
    movq    %r9, 32(%rdi)           // h4'
.endm

#############################################################
# void Fp51Mul (Fp51 *out, const Fp51 *f, const Fp51 *g);
#############################################################

.globl  Fp51Mul
.type   Fp51Mul, @function
.align  32
Fp51Mul:
.cfi_startproc
    /* Save Register */
    push_stack

    /* The input and output parameters are transferred by registers rdi, rsi, and rdx.
     * rdi: out; rsi: f; rdx: g; fp51 is an array of [u64; 5]
     * rdx will be overwritten in subsequent calculation.
     * Therefore, you need to load the data in the rdx variable in advance.
     */
    movq    (%rsi), %rax                // f0
    movq    (%rdx), %rbx                // g0
    movq    8(%rdx), %r14               // g1
    movq    16(%rdx), %r15              // g2
    movq    24(%rdx), %rbp              // g3, Store g0-g3, store g3 in unaffected registers
    movq    32(%rdx), %rcx              // g4

    /* Stores the out pointer and frees the rdi so that the rdi can be used in subsequent calculations. Stores 19 * g4. */
    movq	%rdi, 24(%rsp)
    movq    %rax, %rdi                  // f0
    /* r14, r15, rbx, and rcx will be overwritten in subsequent calculations. g0 to g2 will be stored.
     * Storage actions will be scattered in the calculation code for performance purposes.
     */

    /* h0 = f0g0 + 19f1g4 + 19f2g3 + 19f3g2 + 19f4g1; Stored in r8, r9 */
    mulq    %rbx                        // (rax, rdx) = f0 * g0, in le
    movq    %rax, %r8
    movq    %rdi, %rax                  // f0
    movq    %rbx, 16(%rsp)              // g0
    movq    %rdx, %r9

    /* h1 = f0g1 + f1g0 + 19f2g4 + 19f3g3 + 19f4g2; Stored in r10, r11 */
    mulq    %r14                        // (rax, rdx) = f0 * g1
    movq    %rax, %r10
    movq    %rdi, %rax                  // f0
    leaq    (%rcx, %rcx, 8), %rbx       // g4 * 8 + g4 = g4 * 9
    movq    %r14, 8(%rsp)               // g1
    movq    %rdx, %r11

    /* h2 = f0g2 + f1g1 + f2g0 + 19f3g4 + 19f4g3; Stored in r12, r13 */
    mulq    %r15                        // (rax, rdx) = f0 * g2
    movq    %rax, %r12
    movq    %rdi, %rax                  // f0
    leaq    (%rcx, %rbx, 2), %rdi       // rdi = 2 * (9 * g4) + g4, Store 19 * g4 to rdi before rcx is overwritten
    movq    %r15, (%rsp)                // g2
    movq    %rdx, %r13

    /* h3 = f0g3 + f1g2 + f2g1 + f3g0 + 19f4g4; Stored in r14, r15 */
    mulq    %rbp                        // (rax, rdx) = f0 * g3
    movq    %rax, %r14
    movq    (%rsi), %rax                // f0
    movq    %rdx, %r15

    /* h4 = f0g4 + f1g3 + f2g2 + f3g1 + f4g0; Stored in rbx, rcx */
    mulq    %rcx                        // (rax, rdx) = f0 * g4
    movq    %rax, %rbx
    movq    8(%rsi), %rax               // f1
    movq    %rdx, %rcx

    /* Calculate 19 * g4 related */
    u51mul  %rdi, %r8, %r9, 16(%rsi)    // (rax, rdx) = 19 * f1 * g4; load f2
    u51mul  %rdi, %r10, %r11, 24(%rsi)  // (rax, rdx) = 19 * f2 * g4; load f3
    u51mul  %rdi, %r12, %r13, 32(%rsi)  // (rax, rdx) = 19 * f3 * g4; load f4

    mulq    %rdi                        // (rax, rdx) = 19 * f4 * g4
    imulq   $19, %rbp, %rdi             // 19 * g3
    addq    %rax, %r14
    movq    8(%rsi), %rax               // f1
    adcq    %rdx, %r15

    /* Calculate g3 related */
    mulq    %rbp                        // (rax, rdx) = f1 * g3
    movq    (%rsp), %rbp                // g2
    addq    %rax, %rbx
    movq    16(%rsi), %rax              // f2
    adcq    %rdx, %rcx

    u51mul  %rdi, %r8, %r9, 24(%rsi)    // (rax, rdx) = 19 * f2 * g3; load f3
    u51mul  %rdi, %r10, %r11, 32(%rsi)  // (rax, rdx) = 19 * f3 * g3; load f4

    mulq    %rdi                        // (rax, rdx) = 19 * f4 * g3
    imulq   $19, %rbp, %rdi             // 19 * g2
    addq    %rax, %r12
    movq    8(%rsi), %rax               // f1
    adcq    %rdx, %r13

    /* Calculate g2 related */
    u51mul  %rbp, %r14, %r15, 16(%rsi)  // (rax, rdx) = f1 * g2; load f2

    mulq    %rbp                    // (rax, rdx) = f2 * g2
    movq    8(%rsp), %rbp           // g1
    addq    %rax, %rbx
    movq    24(%rsi), %rax          // f3
    adcq    %rdx, %rcx

    u51mul %rdi, %r8, %r9, 32(%rsi) // (rax, rdx) = 19 * f3 * g2; load f4
    u51mul %rdi, %r10, %r11, 8(%rsi) // (rax, rdx) = 19 * f4 * g2; load f2

    /* Calculate g1 related */
    mulq    %rbp                    // (rax, rdx) = f1 * g1
    imulq   $19, %rbp, %rdi         // 19 * g1
    addq    %rax, %r12
    movq    16(%rsi), %rax          // f2
    adcq    %rdx, %r13

    u51mul %rbp, %r14, %r15, 24(%rsi) // (rax, rdx) = f2 * g1; load f3

    mulq    %rbp                    // (rax, rdx) = f3 * g1
    movq    16(%rsp), %rbp          // g0
    addq    %rax, %rbx
    movq    32(%rsi), %rax          // f4
    adcq    %rdx, %rcx

    u51mul  %rdi, %r8, %r9, 8(%rsi) // (rax, rdx) = 19 * f4 * g1; load f1

    /* Calculate g0 related */
    u51mul  %rbp, %r10, %r11, 16(%rsi) // (rax, rdx) = f1 * g0; load f2
    u51mul  %rbp, %r12, %r13, 24(%rsi) // (rax, rdx) = f2 * g0; load f3
    u51mul  %rbp, %r14, %r15, 32(%rsi) // (rax, rdx) = f3 * g0; load f4

    mulq    %rbp                    // (rax, rdx) = f4 * g0
    addq    %rax, %rbx
    adcq    %rdx, %rcx

    /* Restore the stack pointer. */
    movq    24(%rsp), %rdi

    reduce

    /* Recovery register */
    pop_stack
    ret
.cfi_endproc
.size   Fp51Mul,.-Fp51Mul

#############################################################
# void Fp51Square(Fp51 *out, const Fp51 *f);
#############################################################

.globl  Fp51Square
.type   Fp51Square, @function
.align  32
Fp51Square:
.cfi_startproc
    /* Save Register */
    push_stack

    /* The input and output parameters are transferred by registers rdi and rsi.
     * rdi: out; rsi: f; fp51 is an array of [u64; 5]
     * Loads only non-adjacent data, vacating registers for storage calculations
     */
    movq    (%rsi), %rax                // f0
    movq    16(%rsi), %r15              // f2
    movq    32(%rsi), %rcx              // f4

    /* Open the stack and store the following necessary content, which is consistent with the Fp51Mul.
     * Stores the out pointer, frees the rdi,
     * so that the rdi can be used in subsequent calculations, and stores 19 * f4.
     */
    leaq    (%rax, %rax, 1), %rbp       // 2 * f0
    movq    %rdi, 24(%rsp)

    /* h0 = f0^2 + 38f1f4 + 38f2f3; Stored in r8, r9 */
    mulq    %rax                        // (rax, rdx) = f0^2
    movq    %rax, %r8
    movq    8(%rsi), %rax               // f1
    movq    %rdx, %r9

    /* h1 = 19f3^2 + 2f0f1 + 38f2g4; Stored in r10, r11 */
    mulq    %rbp                        // (rax, rdx) = 2f0 * f1
    movq    %rax, %r10
    movq    %r15, %rax                  // f2
    movq    %r15, 16(%rsp)              // Store f2 for later use of rsi
    movq    %rdx, %r11

    /* h2 = f1^2 + 2f0f2 + 38f3g4; Stored in r12, r13 */
    mulq    %rbp                        // (rax, rdx) = 2f0 * f2
    movq    %rax, %r12
    movq    24(%rsi), %rax              // f3
    movq    %rdx, %r13

    imulq    $19, %rcx, %rdi            // Store 19 * f4 to rdi before rcx is overwritten

    /* h3 = 19f4^2 + 2f0f3 + 2f1f2; Stored in r14, r15 */
    mulq    %rbp                        // (rax, rdx) = 2f0 * f3
    movq    %rax, %r14
    movq    %rcx, %rax                  // f4
    movq    %rdx, %r15

    /* h4 = f2^2 + 2f0f4 + 2f1f3; Stored in rbx, rcx */
    mulq    %rbp                        // (rax, rdx) = 2f0 * f4
    movq    %rax, %rbx
    movq    %rcx, %rax                  // f4
    movq    %rdx, %rcx

    /* Calculate 19 * f4 related
     * h3
     */
    u51mul  %rdi, %r14, %r15, 8(%rsi)   // (rax, rdx) = 19 * f4^2; load f1

    movq    24(%rsi), %rsi              // f3

    /* Calculate f1 related
     * h2
     */
    leaq   (%rax, %rax, 1), %rbp        // 2 * f1
    u51mul  %rax, %r12, %r13, 16(%rsp)  // (rax, rdx) = f1^2; load f2

    /* h3 */
    u51mul  %rbp, %r14, %r15, %rsi      // (rax, rdx) = 2 * f1 * f2; load f3

    /* h4 */
    u51mul  %rbp, %rbx, %rcx, %rbp      // (rax, rdx) = 2 * f1 * f3; load 2 * f1

    imulq   $19, %rsi, %rbp             // 19 * f3

    /* h0 */
    mulq    %rdi                        // (rax, rdx) = 2 * f1 * 19 * f4
    addq    %rax, %r8
    leaq    (%rsi, %rsi, 1), %rax       // 2 * f3
    adcq    %rdx, %r9

    /* Calculate f3 related
     * h2
     */
    u51mul  %rdi, %r12, %r13, %rsi       // (rax, rdx) = f3 * 2 * 19 * f4; load f3

    /* h1 */
    u51mul  %rbp, %r10, %r11, 16(%rsp)   // (rax, rdx) = 19 * f3^2; load f2

    /* Calculate f2 related
     * h4
     */
    leaq    (%rax, %rax, 1), %rsi       // 2 * f2
    u51mul  %rax, %rbx, %rcx, %rbp      // (rax, rdx) = f2^2; load 19 * f3

    /* h0 */
    u51mul  %rsi, %r8, %r9, %rsi        // (rax, rdx) = 2 * f2 * 19 * f3; load 2 * f2

    /* h1 */
    mulq    %rdi                    // (rax, rdx) = 2 * f2 * 19 * f4
    addq    %rax, %r10
    adcq    %rdx, %r11

    /* Recovery register */
    movq    24(%rsp), %rdi

    reduce

    /* Recovery register */
    pop_stack
    ret
.cfi_endproc
.size   Fp51Square,.-Fp51Square

#############################################################
# void Fp51MulScalar(Fp51 *out, const Fp51 *in);
#############################################################

.globl  Fp51MulScalar
.type   Fp51MulScalar, @function
.align  32
Fp51MulScalar:
.cfi_startproc
    /* Save Register */
    push_stack

    /*The input and output parameters are transferred by registers rdi, rsi, and rdx.
     * rdi: out; rsi: in; rdx: scalar; fp51 Is an array of [u64; 5]
     * Open stack, consistent with Fp51Mul
     */

    /* h0 */
    movl   $121666, %eax
    mulq   (%rsi)                    // f0 * 121666
    movq   %rax, %r8
    movl   $121666, %eax             // Modify the rax immediately after the rax is vacated.
    movq   %rdx, %r9

    /* h1 */
    mulq   8(%rsi)                   // f1 * 121666
    movq   %rax, %r10
    movl   $121666, %eax
    movq   %rdx, %r11

    /* h2 */
    mulq   16(%rsi)                  // f2 * 121666
    movq   %rax, %r12
    movl   $121666, %eax
    movq   %rdx, %r13

    /* h3 */
    mulq   24(%rsi)                  // f3 * 121666
    movq   %rax, %r14
    movl   $121666, %eax
    movq   %rdx, %r15

    /* h4 */
    mulq   32(%rsi)                 // f4 * 121666
    movq   %rax, %rbx
    movq   %rdx, %rcx

    reduce

    /* Recovery register */
    pop_stack
    ret
.cfi_endproc
.size   Fp51MulScalar,.-Fp51MulScalar

/**
 * Fp64 reduce:
 *     +------+-----+-----+-----+------+
 *     |      | r15 | r14 | r13 | r12  |
 *     |      |     |     |     |  38  |
 *     +-------------------------------+
 *     |      |     |     | r12'| r12' |
 *     |      |     | r13'| r13'|      |
 *     |      | r14'| r14'|     |      |
 *     | r15' | r15'|     |     |      |
 *     +-------------------------------+
 *     |      | r11'| r10'| r9' | r8'  |
 *     |      |     |     |     |19r15'|
 *     +-------------------------------+
 *     |      | r11 | r10 | r9  | r8   |
 *     +------+-----+-----+-----+------+
 */
.macro Fp64Reduce
    xorq     %rsi, %rsi
    movq     $38, %rdx
    mulx    %r12, %rax, %rbx
    adcx    %rax, %r8
    adox    %rbx, %r9
    mulx    %r13, %rax, %rbx
    adcx    %rax, %r9
    adox    %rbx, %r10
    mulx    %r14, %rax, %rbx
    adcx    %rax, %r10
    adox    %rbx, %r11
    mulx    %r15, %rax, %r12
    adcx    %rax, %r11
    adcx    %rsi, %r12
    adox    %rsi, %r12

    shld     $1, %r11, %r12
    movq     $0x7FFFFFFFFFFFFFFF, %rbp
    andq     %rbp, %r11
    imulq    $19, %r12, %r12
    addq     %r12, %r8
    adcx     %rsi, %r9
    adcx     %rsi, %r10
    adcx     %rsi, %r11

    movq    0(%rsp), %rdi
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)
    movq    %r8, 0(%rdi)
.endm

.globl    Fp64Mul
.type    Fp64Mul,@function
.align    32
Fp64Mul:
.cfi_startproc
    pushq    %rbp
    pushq    %rbx
    pushq    %r12
    pushq    %r13
    pushq    %r14
    pushq    %r15
    pushq    %rdi

/**
 * (f3, f2, f1, f0) * (g3, g2, g1, g0) :
 *         +    +    +    +    +    +    +    +    +
 *         |    |    |    |    | A3 | A2 | A1 | A0 |
 *         |    |    |    |    | B3 | B2 | B1 | B0 |
 *       +------------------------------------------+
 *         |    |    |    |    |    |    |A0B0|A0B0|
 *         |    |    |    |    |    |A1B0|A1B0|    |
 *         |    |    |    |    |A2B0|A2B0|    |    |
 *         |    |    |    |A3B0|A3B0|    |    |    |
 *         |    |    |    |    |    |A0B1|A0B1|    |
 *         |    |    |    |    |A1B1|A1B1|    |    |
 *         |    |    |    |A2B1|A2B1|    |    |    |
 *         |    |    |A3B1|A3B1|    |    |    |    |
 *         |    |    |    |    |A2B0|A2B0|    |    |
 *         |    |    |    |A2B1|A2B1|    |    |    |
 *         |    |    |A2B2|A2B2|    |    |    |    |
 *         |    |A2B3|A2B3|    |    |    |    |    |
 *         |    |    |    |A3B0|A3B0|    |    |    |
 *         |    |    |A3B1|A3B1|    |    |    |    |
 *         |    |A3B2|A3B2|    |    |    |    |    |
 *         |A3B3|A3B3|    |    |    |    |    |    |
 *       +------------------------------------------+
 *         |r15 |r14 |r13 |r12 |r11 |r10 |r9  |r8  |
 *         +    +    +    +    +    +    +    +    +
 */
    movq    0(%rdx), %rcx
    movq    8(%rdx), %rbp
    movq    16(%rdx), %rdi
    movq    24(%rdx), %r15
    movq    0(%rsi), %rdx
    xorq    %r14, %r14

    // (f3, f2, f1, f0) * g0
    mulx     %rcx, %r8, %rax
    mulx     %rbp, %r9, %rbx
    adcx     %rax, %r9
    mulx     %rdi, %r10, %rax
    adcx     %rbx, %r10
    mulx     %r15, %r11, %r12
    movq     8(%rsi), %rdx
    adcx     %rax, %r11
    adcx     %r14, %r12

    // (f3, f2, f1, f0) * g1
    mulx     %rcx, %rax, %rbx
    adcx     %rax, %r9
    adox     %rbx, %r10
    mulx     %rbp, %rax, %rbx
    adcx     %rax, %r10
    adox     %rbx, %r11
    mulx     %rdi, %rax, %rbx
    adcx     %rax, %r11
    adox     %rbx, %r12
    mulx     %r15, %rax, %r13
    movq     16(%rsi), %rdx
    adcx     %rax, %r12
    adox     %r14, %r13
    adcx     %r14, %r13

    // (f3, f2, f1, f0) * g2
    mulx     %rcx, %rax, %rbx
    adcx     %rax, %r10
    adox     %rbx, %r11
    mulx     %rbp, %rax, %rbx
    adcx     %rax, %r11
    adox     %rbx, %r12
    mulx     %rdi, %rax, %rbx
    adcx     %rax, %r12
    adox     %rbx, %r13
    mulx     %r15, %rax, %r14
    movq     24(%rsi), %rdx
    adcx     %rax, %r13
    movq     $0, %rsi
    adox     %rsi, %r14
    adcx     %rsi, %r14

    // (f3, f2, f1, f0) * g3
    mulx    %rcx, %rax, %rbx
    adcx    %rax, %r11
    adox    %rbx, %r12
    mulx    %rbp, %rax, %rbx
    adcx    %rax, %r12
    adox    %rbx, %r13
    mulx    %rdi, %rax, %rbx
    adcx    %rax, %r13
    adox    %rbx, %r14
    mulx    %r15, %rax, %r15
    adcx    %rax, %r14
    adox    %rsi, %r15
    adcx    %rsi, %r15

    // reduce
    Fp64Reduce

    movq    8(%rsp), %r15
    movq    16(%rsp), %r14
    movq    24(%rsp), %r13
    movq    32(%rsp), %r12
    movq    40(%rsp), %rbx
    movq    48(%rsp), %rbp
    leaq    56(%rsp), %rsp

    ret
.cfi_endproc
.size    Fp64Mul,.-Fp64Mul

.globl    Fp64Sqr
.type    Fp64Sqr,@function
.align    32
Fp64Sqr:
.cfi_startproc    
    pushq    %rbp
    pushq    %rbx
    pushq    %r12
    pushq    %r13
    pushq    %r14
    pushq    %r15
    pushq    %rdi
/**
 * (f3, f2, f1, f0) ^ 2 :
 *      +----+----+----+----+----+----+----+----+----+
 *      |    |    |    |    |    | A3 | A2 | A1 | A0 |
 *      | *  |    |    |    |    | A3 | A2 | A1 | A0 |
 *      +--------------------------------------------+
 *      |    |    |    |    |    |    |A0A1|A0A1|    |
 *      |    |    |    |    |    |A0A2|A0A2|    |    |
 *      | +  |    |    |    |A0A3|A0A3|    |    |    |
 *      |    |    |    |    |A1A2|A1A2|    |    |    |
 *      |    |    |    |A1A3|A1A3|    |    |    |    |
 *      |    |    |A2A3|A2A3|    |    |    |    |    |
 *      +--------------------------------------------+
 *      | *2 |    |r14`|r13`|r12`|r11`|r10`|r9` |    |
 *      +--------------------------------------------+
 *      |    |r15'|r14'|r13'|r12'|r11'|r10'|r9' |    |
 *      +--------------------------------------------+
 *      |    |    |    |    |    |    |    |A0A0|A0A0|
 *      |    |    |    |    |    |A1A1|A1A1|    |    |
 *      | +  |    |    |A2A2|A2A2|    |    |    |    |
 *      |    |A3A3|A3A3|    |    |    |    |    |    |
 *      +--------------------------------------------+
 *      |    |r15 |r14 |r13 |r12 |r11 |r10 |r9  |r8  |
 *      +--------------------------------------------+
 */
    movq   0(%rsi), %rbx  // a0
    movq   8(%rsi), %rcx  // a1
    movq   16(%rsi), %rbp // a2
    movq   24(%rsi), %rdi // a3
    xorq   %r15, %r15

    // (a1, a2, a3) * a0
    movq   %rbx, %rdx
    mulx   %rcx, %r9, %rsi
    mulx   %rbp, %r10, %rax
    adcx   %rsi, %r10
    mulx   %rdi, %r11, %r12
    movq   %rcx, %rdx
    adcx   %rax, %r11
    adcx   %r15, %r12

    // (a2, a3) * a1
    mulx   %rbp, %rsi, %rax
    adcx   %rsi, %r11
    adox   %rax, %r12
    mulx   %rdi, %rsi, %r13
    movq   %rbp, %rdx
    adcx   %rsi, %r12
    adcx   %r15, %r13
    adox   %r15, %r13

    // a3 * a2
    mulx   %rdi, %rsi, %r14
    movq   %rbx, %rdx
    adcx   %rsi, %r13
    adcx   %r15, %r14

    // (r9 --- r14) *2
    shld   $1, %r14, %r15
    shld   $1, %r13, %r14
    shld   $1, %r12, %r13
    shld   $1, %r11, %r12
    shld   $1, %r10, %r11
    shld   $1, %r9, %r10
    shlq   $1, %r9
    xorq   %r8, %r8   // clear cf flag
    // a0 * a0
    mulx   %rdx, %r8, %rax
    movq   %rcx, %rdx
    adcx   %rax, %r9

    // a1 * a1
    mulx    %rdx, %rsi, %rax
    movq    %rbp, %rdx
    adcx    %rsi, %r10
    adcx    %rax, %r11

    // a2 * a2
    mulx   %rdx, %rsi, %rax
    movq   %rdi, %rdx
    adcx   %rsi, %r12
    adcx   %rax, %r13

    // a3 * a3
    mulx   %rdx, %rsi, %rax
    adcx   %rsi, %r14
    adcx   %rax, %r15

    // reduce
    Fp64Reduce

    movq    8(%rsp), %r15
    movq    16(%rsp), %r14
    movq    24(%rsp), %r13
    movq    32(%rsp), %r12
    movq    40(%rsp), %rbx
    movq    48(%rsp), %rbp
    leaq    56(%rsp), %rsp
    ret
.cfi_endproc
.size   Fp64Sqr, .-Fp64Sqr

.globl  Fp64MulScalar
.type   Fp64MulScalar, @function
.align  32
Fp64MulScalar:
.cfi_startproc
    movl    $121666, %edx
    mulx   0(%rsi), %r8, %rax
    mulx   8(%rsi), %r9, %rcx  
    addq    %rax, %r9
    mulx   16(%rsi), %r10, %rax
    adcx    %rcx, %r10
    mulx   24(%rsi), %r11, %rcx
    adcx    %rax, %r11
    movl    $0, %edx
    adcx    %rdx, %rcx
    movq    $0x7FFFFFFFFFFFFFFF, %rax
    shld    $1, %r11, %rcx
    andq    %rax, %r11
    imulq   $19, %rcx, %rcx
    
    addq    %rcx, %r8
    adcx    %rdx, %r9
    movq    %r8, 0(%rdi)
    adcx    %rdx, %r10
    movq    %r9, 8(%rdi)
    adcx    %rdx, %r11
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)
    ret
.cfi_endproc    
.size   Fp64MulScalar, .-Fp64MulScalar

.globl   Fp64Add
.type    Fp64Add, @function
.align   32
Fp64Add:
.cfi_startproc    
    movq    0(%rsi),%r8
    movq    8(%rsi),%r9
    addq    0(%rdx),%r8
    adcx    8(%rdx),%r9
    movq    16(%rsi),%r10
    movq    24(%rsi),%r11
    adcx    16(%rdx),%r10
    adcx    24(%rdx),%r11

    movq    $0,   %rax
    movq    $38,  %rcx
    cmovae  %rax, %rcx
    addq    %rcx, %r8
    adcx    %rax, %r9
    adcx    %rax, %r10
    movq    %r9,  8(%rdi)
    adcx    %rax, %r11
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    cmovc   %rcx, %rax
    addq    %rax, %r8
    movq    %r8,  0(%rdi)
    ret
.cfi_endproc
.size   Fp64Add, .-Fp64Add

.globl   Fp64Sub
.type    Fp64Sub,@function
.align   32
Fp64Sub:
.cfi_startproc
    movq    0(%rsi),%r8
    movq    8(%rsi),%r9
    subq    0(%rdx),%r8
    sbbq    8(%rdx),%r9
    movq    16(%rsi),%r10
    movq    24(%rsi),%r11
    sbbq    16(%rdx),%r10
    sbbq    24(%rdx),%r11

    movq    $0,   %rax
    movq    $38,  %rcx
    cmovae  %rax, %rcx

    subq    %rcx, %r8
    sbbq    %rax, %r9
    sbbq    %rax, %r10
    movq    %r9,8(%rdi)
    sbbq    %rax, %r11
    movq    %r10,16(%rdi)
    cmovc   %rcx, %rax
    movq    %r11,24(%rdi)
    subq    %rax, %r8
    movq    %r8,0(%rdi)

    ret
.cfi_endproc
.size    Fp64Sub,.-Fp64Sub

.globl    Fp64PolyToData
.type    Fp64PolyToData,@function
.align    32
Fp64PolyToData:
.cfi_startproc    
    movq    24(%rsi), %r11
    movq    16(%rsi), %r10
    xorq    %rax, %rax

    leaq    (%r11, %r11, 1), %rcx
    sarq    $63, %r11
    shrq    $1, %rcx
    andq    $19, %r11
    addq    $19, %r11

    movq    0(%rsi), %r8
    movq    8(%rsi), %r9

    addq    %r11, %r8
    adcx    %rax, %r9
    adcx    %rax, %r10
    adcx    %rax, %rcx

    leaq    (%rcx, %rcx, 1), %r11
    sarq    $63, %rcx
    shrq    $1, %r11
    notq    %rcx
    andq    $19, %rcx

    subq    %rcx, %r8
    sbbq    $0, %r9
    movq    %r8, 0(%rdi)
    movq    %r9, 8(%rdi)
    sbbq    $0, %r10
    sbbq    $0, %r11
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)

    ret
.cfi_endproc    
.size    Fp64PolyToData,.-Fp64PolyToData

#endif
