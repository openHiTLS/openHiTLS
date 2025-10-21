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
#if defined(HITLS_CRYPTO_CURVE_NISTP384) && defined(HITLS_CRYPTO_NIST_USE_ACCEL)

.text
.align 32
# The polynomial
.Lpoly:
.quad    0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff
# The order of polynomial
.Lord:
.quad    0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff

.globl  FlimbsRshift1
.type   FlimbsRshift1,%function
.align 32
FlimbsRshift1:
    pushq   %r12
    pushq   %r13
    # Load inputs
    movq    (%rdi), %r8
    movq    8(%rdi), %r9
    movq    16(%rdi), %r10
    movq    24(%rdi), %r11
    movq    32(%rdi), %r12
    movq    40(%rdi), %r13
    # Right shift
    shrd    $1, %r9, %r8
    shrd    $1, %r10, %r9
    shrd    $1, %r11, %r10
    shrd    $1, %r12, %r11
    shrd    $1, %r13, %r12
    shrq    $1, %r13
    # Store results
    movq    %r8, (%rdi)
    movq    %r9, 8(%rdi)
    movq    %r10, 16(%rdi)
    movq    %r11, 24(%rdi)
    movq    %r12, 32(%rdi)
    movq    %r13, 40(%rdi)
    popq    %r13
    popq    %r12
    ret
.size FlimbsRshift1, .-FlimbsRshift1

#define FFFE_ADD(mod)               \
    /* Store scalar registers */    \
    pushq   %r12;                   \
    pushq   %r13;                   \
    pushq   %r14;                   \
    pushq   %r15;                   \
    subq    $32, %rsp;              \
    xorq    %rax, %rax;             \
    /* Load inputs */               \
    movq    (%rsi), %r8;            \
    movq    8(%rsi), %r9;           \
    movq    16(%rsi), %r10;         \
    movq    24(%rsi), %r11;         \
    movq    32(%rsi), %r12;         \
    movq    40(%rsi), %r13;         \
    /* Addition */                  \
    addq    (%rdx), %r8;            \
    adcq    8(%rdx), %r9;           \
    adcq    16(%rdx), %r10;         \
    adcq    24(%rdx), %r11;         \
    adcq    32(%rdx), %r12;         \
    adcq    40(%rdx), %r13;         \
    /* Store carry */               \
    adcq    $0, %rax;               \
    movq    %r8, %r14;              \
    movq    %r9, %r15;              \
    movq    %r10, 0(%rsp);          \
    movq    %r11, 8(%rsp);          \
    movq    %r12, 16(%rsp);         \
    movq    %r13, 24(%rsp);         \
    /* Sub polynomial */            \
    leaq    mod, %rsi;              \
    subq    0(%rsi), %r8;           \
    sbbq    8(%rsi), %r9;           \
    sbbq    16(%rsi), %r10;         \
    sbbq    24(%rsi), %r11;         \
    sbbq    32(%rsi), %r12;         \
    sbbq    40(%rsi), %r13;         \
    sbbq    $0, %rax;               \
    cmovcq    %r14, %r8;            \
    cmovcq    %r15, %r9;            \
    cmovcq    0(%rsp), %r10;        \
    cmovcq    8(%rsp), %r11;        \
    cmovcq    16(%rsp), %r12;       \
    cmovcq    24(%rsp), %r13;       \
    /* Store results */             \
    movq    %r8, (%rdi);            \
    movq    %r9, 8(%rdi);           \
    movq    %r10, 16(%rdi);         \
    movq    %r11, 24(%rdi);         \
    movq    %r12, 32(%rdi);         \
    movq    %r13, 40(%rdi);         \
    /* Restore scalar registers */  \
    addq    $32, %rsp;              \
    popq    %r15;                   \
    popq    %r14;                   \
    popq    %r13;                   \
    popq    %r12;                   \

.globl  FlimbsAdd
.type   FlimbsAdd,%function
.align 32
FlimbsAdd:
    FFFE_ADD(.Lpoly(%rip))
    ret
.size FlimbsAdd, .-FlimbsAdd

.globl  FlimbsAddModOrd
.type   FlimbsAddModOrd,%function
.align 32
FlimbsAddModOrd:
    FFFE_ADD(.Lpoly(%rip))
    ret
.size FlimbsAddModOrd, .-FlimbsAddModOrd

#define FFFE_SUB(mod)               \
    /* Store scalar registers */    \
    pushq   %r12;                   \
    pushq   %r13;                   \
    pushq   %r14;                   \
    pushq   %r15;                   \
    subq    $32, %rsp;              \
    xorq    %rax, %rax;             \
    /* Load inputs */               \
    movq    (%rsi), %r8;            \
    movq    8(%rsi), %r9;           \
    movq    16(%rsi), %r10;         \
    movq    24(%rsi), %r11;         \
    movq    32(%rsi), %r12;         \
    movq    40(%rsi), %r13;         \
    /* Subtraction */               \
    subq    (%rdx), %r8;            \
    sbbq    8(%rdx), %r9;           \
    sbbq    16(%rdx), %r10;         \
    sbbq    24(%rdx), %r11;         \
    sbbq    32(%rdx), %r12;         \
    sbbq    40(%rdx), %r13;         \
    sbbq    $0, %rax;               \
    movq    %r8, %r14;              \
    movq    %r9, %r15;              \
    movq    %r10, 0(%rsp);          \
    movq    %r11, 8(%rsp);          \
    movq    %r12, 16(%rsp);         \
    movq    %r13, 24(%rsp);         \
    /* Add polynomial */            \
    leaq    mod, %rsi;              \
    addq    0(%rsi), %r8;           \
    adcq    8(%rsi), %r9;           \
    adcq    16(%rsi), %r10;         \
    adcq    24(%rsi), %r11;         \
    adcq    32(%rsi), %r12;         \
    adcq    40(%rsi), %r13;         \
    testq    %rax, %rax;            \
    cmovzq    %r14, %r8;            \
    cmovzq    %r15, %r9;            \
    cmovzq    0(%rsp), %r10;        \
    cmovzq    8(%rsp), %r11;        \
    cmovzq    16(%rsp), %r12;       \
    cmovzq    24(%rsp), %r13;       \
    /* Store results */             \
    movq    %r8, (%rdi);            \
    movq    %r9, 8(%rdi);           \
    movq    %r10, 16(%rdi);         \
    movq    %r11, 24(%rdi);         \
    movq    %r12, 32(%rdi);         \
    movq    %r13, 40(%rdi);         \
    /* Restore scalar registers */  \
    addq    $32, %rsp;              \
    popq    %r15;                   \
    popq    %r14;                   \
    popq    %r13;                   \
    popq    %r12;                   \


.globl  FlimbsSubModOrd
.type   FlimbsSubModOrd,%function
.align 32
FlimbsSubModOrd:
    FFFE_SUB(.Lord(%rip))
    ret
.size FlimbsSubModOrd, .-FlimbsSubModOrd

.globl  FlimbsSub
.type   FlimbsSub,%function
.align 32
FlimbsSub:
    FFFE_SUB(.Lpoly(%rip))
    ret
.size FlimbsSub, .-FlimbsSub

#endif
