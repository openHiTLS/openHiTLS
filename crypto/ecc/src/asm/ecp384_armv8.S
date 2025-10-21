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

#include "crypt_arm.h"

.section .rodata
.align 4
# The polynomial
.Lpoly:
.quad    0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff
# The order of polynomial
.Lord:
.quad    0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff

.text
.globl  FlimbsRshift1
.type   FlimbsRshift1,%function
.align  4
FlimbsRshift1:
AARCH64_PACIASP
    ldp x9, x10, [x0]
    ldp x11, x12, [x0, #16]
    ldp x13, x14, [x0, #32]
    # Right shift
    extr x9, x10, x9, #1
    extr x10, x11, x10, #1
    extr x11, x12, x11, #1
    extr x12, x13, x12, #1
    extr x13, x14, x13, #1
    lsr  x14, x14, #1

    # Store results
    stp x9, x10, [x0]
    stp x11, x12, [x0, #16]
    stp x13, x14, [x0, #32]
AARCH64_AUTIASP
    ret
.size FlimbsRshift1, .-FlimbsRshift1

#define FFFE_ADD(mod)           \
    stp x19,x20,[sp,#-48]!;     \
    stp x21,x22,[sp,#16];       \
    stp x23,x24,[sp,#32];       \
    /* Load inputs */           \
    ldp x3,x4,[x1];             \
    ldp x5,x6,[x1,#16];         \
    ldp x19,x20,[x1,#32];       \
    /* Addition */              \
    ldp x7,x8,[x2];             \
    ldp x9,x10,[x2,#16];        \
    ldp x21,x22,[x2,#32];       \
    adds    x3,x3,x7;           \
    adcs    x4,x4,x8;           \
    adcs    x5,x5,x9;           \
    adcs    x6,x6,x10;          \
    adcs    x19,x19,x21;        \
    adcs    x20,x20,x22;        \
    adc     x15,xzr,xzr;        \
    mov x11,x3;                 \
    mov x12,x4;                 \
    mov x13,x5;                 \
    mov x14,x6;                 \
    mov x23,x19;                \
    mov x24,x20;                \
    /* Sub polynomial */        \
    adrp    x2, mod;            \
    add x2, x2, :lo12:mod;      \
    ldp x7,x8,[x2];             \
    ldp x9,x10,[x2,#16];        \
    ldp x21,x22,[x2,#32];       \
    subs    x11,x11,x7;         \
    sbcs    x12,x12,x8;         \
    sbcs    x13,x13,x9;         \
    sbcs    x14,x14,x10;        \
    sbcs    x23,x23,x21;        \
    sbcs    x24,x24,x22;        \
    sbcs    x15,x15,xzr;        \
    csel    x3,x3,x11,cc;       \
    csel    x4,x4,x12,cc;       \
    csel    x5,x5,x13,cc;       \
    csel    x6,x6,x14,cc;       \
    csel    x19,x19,x23,cc;     \
    csel    x20,x20,x24,cc;     \
    /* Store results */         \
    stp x3,x4,[x0];             \
    stp x5,x6,[x0,#16];         \
    stp x19,x20,[x0,#32];       \
                                \
    ldp x23,x24,[sp,#32];       \
    ldp x21,x22,[sp,#16];       \
    ldp x19,x20,[sp],#48;       \

#define FFFE_SUB(mod)           \
    stp x19,x20,[sp,#-48]!;     \
    stp x21,x22,[sp,#16];       \
    stp x23,x24,[sp,#32];       \
    /* Load inputs */           \
    ldp x3,x4,[x1];             \
    ldp x5,x6,[x1,#16];         \
    ldp x19,x20,[x1,#32];       \
    /* Addition */              \
    ldp x7,x8,[x2];             \
    ldp x9,x10,[x2,#16];        \
    ldp x21,x22,[x2,#32];       \
    subs    x3,x3,x7;           \
    sbcs    x4,x4,x8;           \
    sbcs    x5,x5,x9;           \
    sbcs    x6,x6,x10;          \
    sbcs    x19,x19,x21;        \
    sbcs    x20,x20,x22;        \
    sbc x15,xzr,xzr;            \
    mov x11,x3;                 \
    mov x12,x4;                 \
    mov x13,x5;                 \
    mov x14,x6;                 \
    mov x23,x19;                \
    mov x24,x20;                \
    /* Add polynomial */        \
    adrp    x2, mod;            \
    add x2, x2, :lo12:mod;      \
    ldp x7,x8,[x2];             \
    ldp x9,x10,[x2,#16];        \
    ldp x21,x22,[x2,#32];       \
    adds    x11,x11,x7;         \
    adcs    x12,x12,x8;         \
    adcs    x13,x13,x9;         \
    adcs    x14,x14,x10;        \
    adcs    x23,x23,x21;        \
    adcs    x24,x24,x22;        \
    tst x15,x15;                \
    csel    x3,x3,x11,eq;       \
    csel    x4,x4,x12,eq;       \
    csel    x5,x5,x13,eq;       \
    csel    x6,x6,x14,eq;       \
    csel    x19,x19,x23,eq;     \
    csel    x20,x20,x24,eq;     \
    /* Store results */         \
    stp x3,x4,[x0];             \
    stp x5,x6,[x0,#16];         \
    stp x19,x20,[x0,#32];       \
                                \
    ldp x23,x24,[sp,#32];       \
    ldp x21,x22,[sp,#16];       \
    ldp x19,x20,[sp],#48;       \


.globl  FlimbsAdd
.type   FlimbsAdd,%function
.align 4
FlimbsAdd:
AARCH64_PACIASP
    FFFE_ADD(.Lpoly)
AARCH64_AUTIASP
    ret
.size FlimbsAdd, .-FlimbsAdd

.globl  FlimbsAddModOrd
.type   FlimbsAddModOrd,%function
.align 4
FlimbsAddModOrd:
AARCH64_PACIASP
    FFFE_ADD(.Lord)
AARCH64_AUTIASP
    ret
.size FlimbsAddModOrd, .-FlimbsAddModOrd

.globl  FlimbsSub
.type   FlimbsSub,%function
.align 4
FlimbsSub:
AARCH64_PACIASP
    FFFE_SUB(.Lpoly)
AARCH64_AUTIASP
    ret
.size FlimbsSub, .-FlimbsSub

.globl  FlimbsSubModOrd
.type   FlimbsSubModOrd,%function
.align 4
FlimbsSubModOrd:
AARCH64_PACIASP
    FFFE_SUB(.Lord)
AARCH64_AUTIASP
    ret
.size FlimbsSubModOrd, .-FlimbsSubModOrd

#endif
