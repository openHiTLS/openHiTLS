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

.file "x25519_armv8.S"
.text

.macro push_stack
    /* 保存寄存器，以下寄存器需要由被调用者保存，并在函数退出时恢复 */
    stp    x19, x20, [sp, #-16]!
    stp    x21, x22, [sp, #-16]!
    sub    sp, sp, #32
.endm

.macro pop_stack
    add    sp, sp, #32
    /* 恢复寄存器 */
    ldp    x21, x22, [sp], #16
    ldp    x19, x20, [sp], #16
.endm

.macro u64mul oper1, oper2
    mul     x19, \oper1, \oper2
    umulh   x2, \oper1, \oper2
.endm

.macro u51mul cur, low, high
    u64mul  x3, \cur
    adds    \low, \low, x19
    adc     \high, \high, x2
.endm

.macro reduce
    /* 保留最后 51 位 */
    mov     x8, #0x7ffffffffffff

    /* 计算 h2' */
    mov     x3, x9
    lsr     x9, x9, #51               // carry(h2-low)
    lsl     x10, x10, #13             // (h2-high) << 13

    /* 计算 h0' */
    mov     x1, x4
    lsr     x4, x4, #51               // carry(h1-low)
    lsl     x5, x5, #13               // (h1-high) << 13

    /* 计算 h2' */
    and     x3, x3, x8                // h2' = rax = h2 & (2^51 - 1) = r12 & (2^51 - 1)      清空h2-low的高13位 - x3
    orr     x10, x10, x9              // r13 = (h2 >> 51)     h2的carry：h2-low的高13位 +->h2-high
    adds    x11, x11, x10             // h3 += (h2 >> 51)     h2-high +->h3-low
    adc     x12, x12, XZR             //     h3-high 进位

    /* 计算 h0' */
    and     x1, x1, x8                // h0' = rsi = h0 & (2^51 - 1) = r8 & (2^51 - 1)        清空h0-low的高13位 -x1
    orr     x5, x5, x4                // r9 = (h0 >> 51)      计算h0-high
    adds    x6, x6, x5                // h1 += (h0 >> 51)     h0-high +->h1-low
    adc     x7, x7, XZR               //        h1-high 进位

    /* 计算 h3' */
    mov     x4, x11                   // h3-low -> x4
    lsr     x11, x11, #51             // h3->low >> 51
    lsl     x12, x12, #13             // h3-high << 13
    and     x4, x4, x8                // h3' = r8 = h3 & (2^51 - 1) = r14 & (2^51 - 1)           清空h3-low的高13位 -x4
    orr     x12, x12, x11             // r15 = (h3 >> 51)      计算h3-high
    adds    x13, x13, x12             // h4 += (h3 >> 51)      h3-high +->h4-low
    adc     x14, x14, XZR             //          h4-high 进位

    /* 计算 h1' */
    mov     x2, x6                    // h1-low -> x2
    lsr     x6, x6, #51               // h1->low >> 51
    lsl     x7, x7, #13               // h1-high << 13
    and     x2, x2, x8                // h1' = rdx = h1 & (2^51 - 1) = r10 & (2^51 - 1)     清空h1-low的高13位 -x2
    orr     x7, x7, x6                // r11 = (h1 >> 51)       计算h1-high
    adds    x3, x3, x7                // h2 += (h1 >> 51)       h1-high +->h2-low

    /* 计算 h4' */
    mov     x5, x13                   // h4-low -> x5
    lsr     x13, x13, #51             // h4->low >> 51
    lsl     x14, x14, #13             // h4-high << 13
    and     x5, x5, x8                // h4' = r9 = h4 & (2^51 - 1) = rbx & (2^51 - 1) 清空h4-low的高13位 -x5
    orr     x14, x14, x13             // rcx = (h4 >> 51) 计算h4-high

    /* out[0] = out[0] + 19 * carry */
    lsl     x6, x14, #3
    adds    x6, x6, x14               // h4-high * 8 + h4-high -> x6 (9 * h4-high)
    adds    x14, x14, x6, lsl #1      // x6 *2 + x14 => x6 --- h4-high * 9 * 2 +  h4-high
    adds    x1, x1, x14               // h4-high * 19 +->h0-low

    /* h2 剩余 */
    mov     x6, x3                    // h2-low -> x6
    and     x3, x8, x3                // h2 &= (2^51 - 1)  清空h2-low的高13位 - x3
    lsr     x6, x6, #51               // h2-low << 51 (进位)
    adds    x4, x4, x6                // h2-low << 51 -> h3-low

    /* out[1] += out[0] >> 51 */
    mov     x6, x1                    // h0-low -> x6

    /* out[0] &= (2^51 - 1) */
    and     x1, x1, x8                // 清空h0-low的高13位
    lsr     x6, x6, #51               // h0-low << 51 (进位)
    adds    x2, x2, x6                // h0-low << 51 -> h1-low

    /* 存储结果 */
    str     x1, [x0]                  // h0'
    str     x2, [x0, #8]              // h1'
    str     x3, [x0, #16]             // h2'
    str     x4, [x0, #24]             // h3'
    str     x5, [x0, #32]             // h4'
.endm

#############################################################
# void Fp51Mul (Fp51 *out, const Fp51 *f, const Fp51 *g);
#############################################################

.globl  Fp51Mul
.type   Fp51Mul, @function
.align  6
Fp51Mul:
.cfi_startproc
    /* 保存寄存器 */
    push_stack

    /* 出入参由寄存器 x0, x1, x2 传递
     * x0: out; x1: f; x2: g; fp51 是 [u64; 5] 的数组
     * x2 在后续计算中会被覆盖，所以需要预先 load x2 中数据
     */
    ldr    x3, [x1]                  // f0
    ldr    x13, [x2]                 // g0
    ldp    x11, x12, [x2, #8]        // g1, g2, 存储 g0-g3，将 g3 存储在不受影响的寄存器
    ldp    x15, x14, [x2, #24]       // g3, g4

    /* 存储 out 指针，解放 x0, 使得 x0 在后续计算可以使用，存储 19 * g4 */
    str	   x0, [sp, #24]
    /* x13, x11, x12 在后续计算都会被覆盖，存储 g0 - g2，为了性能，存储
     * 动作将会散布在计算代码中
     */
    mov    x8, #19
    /* h0 = f0g0 + 19f1g4 + 19f2g3 + 19f3g2 + 19f4g1; 存储于 x4(low), x5(high)*/
    mul    x4, x3, x13               // (x4, x5) = f0 * g0
    umulh  x5, x3, x13
    str    x13, [sp, #16]            // g0

    /* h1 = f0g1 + f1g0 + 19f2g4 + 19f3g3 + 19f4g2; 存储于 x6, x7 */
    mul    x6, x3, x11               // (x6, x7) = f0 * g1
    umulh  x7, x3, x11
    lsl    x13, x14, #3
    add    x13, x13, x14             // g4 * 8 + g4 = g4 * 9
    str    x11, [sp, #8]             // g1

    /* h2 = f0g2 + f1g1 + f2g0 + 19f3g4 + 19f4g3; 存储于 x9, x10 */
    mul    x9, x3, x12               // (x9, x10) = f0 * g2
    umulh  x10, x3, x12
    lsl    x0, x13, #1
    add    x0, x0, x14               // rdi = 2 * (9 * g4) + g4, 在 rcx 被覆盖之前，将 19 * g4 存储至 rdi
    str    x12, [sp]                 // g2

    /* h3 = f0g3 + f1g2 + f2g1 + f3g0 + 19f4g4; 存储于 x11, x12 */
    mul    x11, x3, x15              // (x11, x12) = f0 * g3
    umulh  x12, x3, x15

    /* h4 = f0g4 + f1g3 + f2g2 + f3g1 + f4g0; 存储于 x13, x14 */
    mul    x13, x3, x14              // (x13, x14) = f0 * g4
    umulh  x14, x3, x14
    ldr    x3, [x1, #8]              // f1

    /* 计算 19 * g4 相关 */
    u51mul  x0, x4, x5               // (x4, x5) = 19 * f1 * g4; load f2
    ldr     x3, [x1, #16]
    u51mul  x0, x6, x7               // (x6, x7) = 19 * f2 * g4; load f3
    ldr     x3, [x1, #24]
    u51mul  x0, x9, x10              // (x9, x10) = 19 * f3 * g4; load f4
    ldr     x3, [x1, #32]
    u51mul  x0, x11, x12             // (x11, x12) = 19 * f3 * g4; load f4
    ldr     x3, [x1, #8]
    mul     x0, x15, x8              // 19 * g3

    /* 计算 g3 相关 */           
    u64mul  x3, x15                  // (x13, x14) = f1 * g3
    ldr     x15, [sp]                // g2
    adds    x13, x13, x19
    ldr     x3, [x1, #16]            // f2
    adc     x14, x14, x2

    u51mul  x0, x4, x5               // (x4, x5) = 19 * f2 * g3; load f3
    ldr     x3, [x1, #24]
    u51mul  x0, x6, x7               // (x6, x7) = 19 * f3 * g3; load f4
    ldr     x3, [x1, #32]
        
    u64mul  x3, x0                   // (rax, rdx) = 19 * f4 * g3
    mul     x0, x15, x8              // 19 * g2
    adds    x9, x9, x19
    ldr     x3, [x1, #8]             // f1
    adc     x10, x10, x2

    /* 计算 g2 相关 */
    u51mul  x15, x11, x12            // (x11, x12) = f1 * g2; load f2
    ldr     x3, [x1, #16]
         
    u64mul  x3, x15                  // (rax, rdx) = f2 * g2
    ldr     x15, [sp, #8]            // g1
    adds    x13, x13, x19
    ldr     x3, [x1, #24]            // f3
    adc     x14, x14, x2

    u51mul  x0, x4, x5               // (x4, x5) = 19 * f3 * g2; load f4
    ldr     x3, [x1, #32]
    u51mul  x0, x6, x7               // (x6, x7) = 19 * f4 * g2; load f2
    ldr     x3, [x1, #8]

    /* 计算 g1 相关 */
    u64mul  x3, x15                  // (x19, x2) = f1 * g1
    mul     x0, x15, x8              // 19 * g1
    adds    x9, x9, x19
    ldr     x3, [x1, #16]            // f2
    adc     x10, x10, x2

    u51mul  x15, x11, x12            // (x11, x12) += f2 * g1; load f3
    ldr     x3, [x1, #24]
                 
    u64mul  x3, x15                  // (x19, x2) = f3 * g1
    ldr     x15, [sp, #16]           // g0
    adds    x13, x13, x19
    ldr     x3, [x1, #32]            // f4
    adc     x14, x14, x2

    u51mul  x0, x4, x5               // (x4, x5) += 19 * f4 * g1; load f1
    ldr     x3, [x1, #8]

    /* 计算 g0 相关 */
    u51mul  x15, x6, x7              // (x6, x7) += f1 * g0; load f2
    ldr     x3, [x1, #16]
    u51mul  x15, x9, x10             // (x9, x10) += f2 * g0; load f3
    ldr     x3, [x1, #24]
    u51mul  x15, x11, x12            // (x11, x12) = f3 * g0; load f4
    ldr     x3, [x1, #32]
                  
    u64mul  x3, x15                  // (x13, x14) += f4 * g0
    adds    x13, x13, x19
    adc     x14, x14, x2

    /* 恢复栈指针 */
    ldr    x0, [sp, #24]

    reduce

    /* 恢复寄存器 */
    pop_stack
    ret
.cfi_endproc
.size   Fp51Mul,.-Fp51Mul

#############################################################
# void Fp51Square(Fp51 *out, const Fp51 *f);
#############################################################

.globl  Fp51Square
.type   Fp51Square, @function
.align  6
Fp51Square:
.cfi_startproc
    /* 保存寄存器 */
    push_stack

    /* 出入参由寄存器 x0, x1 传递
     * x0: out; x1: f; fp51 是 [u64; 5] 的数组
     * 只加载其中不相邻的数据，空出寄存器用于存储计算
     */

    ldr    x3, [x1]                 // f0
    ldr    x12, [x1, #16]           // f2
    ldr    x14, [x1, #32]           // f4
    mov    x8, #19
    /* 开栈，存储以下必要内容，和 Fp51Mul 保持一致
     * 存储 out 指针，解放 rdi，使得 rdi 在后续计算可以使用，存储 19 * f4
     */
    lsl    x2, x3, #1               // 2 * f0
    str    x0, [sp, #24]

    /* h0 = f0^2 + 38f1f4 + 38f2f3; 存储于 x4, x5 */
    mul     x4, x3, x3              // (x4, x5) = f0^2
    umulh   x5, x3, x3
    ldr     x3, [x1, #8]            // f1

    /* h1 = 19f3^2 + 2f0f1 + 38f2g4; 存储于 x6, x7 */
    mul     x6, x3, x2              // (x6, x7) = 2f0 * f1
    umulh   x7, x3, x2
    str     x12, [sp, #16]          // 存储 f2

    /* h2 = f1^2 + 2f0f2 + 38f3g4; 存储于 x9, x10 */
    mul     x9, x12, x2             // (x9, x10) = 2f0 * f2
    umulh   x10, x12, x2
    ldr     x3, [x1, #24]           // f3

    mul     x0, x14, x8             // 19 * f4

    /* h3 = 19f4^2 + 2f0f3 + 2f1f2; 存储于 r14, r15 */
    mul     x11, x3, x2             // (x11, x12) = 2f0 * f3
    umulh   x12, x3, x2
    mov     x3, x14                 // f4

    /* h4 = f2^2 + 2f0f4 + 2f1f3; 存储于 x13, x14 */
    mul     x13, x3, x2             // (x13, x14) = 2f0 * f4
    umulh   x14, x3, x2

    /* 计算 19 * f4 相关
     * h3
     */
    u51mul  x0, x11, x12            // (x11, x12) += 19 * f4^2; load f1
    ldr     x3, [x1, #8]

    /* 计算 f1 相关
     * h2
     */
    lsl     x15, x3, #1             // 2 * f1
    u51mul  x3, x9, x10             // (x9, x10) += f1^2; load f2
    ldr     x3, [sp, #16]

    /* h3 */
    u51mul  x15, x11, x12           // (x11, x12) += 2 * f1 * f2; load f3
    ldr     x3, [x1, #24]

    /* h4 */
    u51mul  x15, x13, x14           // (x13, x14) = 2 * f1 * f3; load 2 * f1
    mov     x3, x15

    ldr    x1, [x1, #24]            // f3
    mul    x15, x1, x8              // 19 * f3

    /* h0 */
    u64mul  x3, x0
    lsl     x3, x1, #1              // 2 * f3
    adds    x4, x4, x19             // (x4, x5) += 2 * f1 * 19 * f4
    adc     x5, x5, x2

    /* 计算 f3 相关
     * h2
     */
    u51mul  x0, x9, x10             // (x9, x10) += f3 * 2 * 19 * f4; load f3
    mov     x3, x1
    /* h1 */
    u51mul  x15, x6, x7             // (x6, x7) += 19 * f3 * f3; load f2
    ldr     x3, [sp, #16]

    /* 计算 f2 相关
     * h4
     */
    lsl    x1, x3, #1               // 2 * f2
    u51mul  x3, x13, x14            // (x13, x14) += f2 * f2; load 19 * f3
    mov      x3, x15
    /* h0 */
    u51mul  x1, x4, x5              // (x4, x5) = 2 * f2 * 19 * f3; load 2 * f2
    mov     x3, x1
    /* h1 */                  
    u64mul  x3, x0                  // (x6, x7) += 2 * f2 * 19 * f4
    adds    x6, x19, x6
    adc     x7, x2, x7

    /* 恢复寄存器 */
    ldr    x0, [sp, #24]

    reduce

    /* 恢复寄存器 */
    pop_stack
    ret
.cfi_endproc
.size   Fp51Square,.-Fp51Square

#############################################################
# void Fp51MulScalar(Fp51 *out, const Fp51 *in);
#############################################################

.globl  Fp51MulScalar
.type   Fp51MulScalar, @function
.align  6
Fp51MulScalar:
.cfi_startproc
    /* 出入参由寄存器 x0, x1 传递
     * x0: out; x1: in; fp51 是 [u64; 5] 的数组
     * 开栈，和 Fp51Mul 保持一致
     */

    /* mov 121666 */
    mov    x3, #0xDB42
    movk   x3, #0x1, lsl #16

    /* ldr f0, f1 */
    ldp x2, x8, [x1]

    /* h0 */
    mul    x4, x2, x3               // f0 * 121666
    umulh  x5, x2, x3

    /* h1 */
    mul    x6, x8, x3               // f1 * 121666
    umulh  x7, x8, x3

    /* ldr f2, f3 */
    ldp    x2, x8, [x1, #16]
    /* h2 */
    mul    x9, x2, x3               // f2 * 121666
    umulh  x10, x2, x3

    /* h3 */             
    mul   x11, x8, x3               // f3 * 121666
    umulh x12, x8, x3

    /* ldr f4 */
    ldr   x8, [x1, #32]
    /* h4 */
    mul   x13, x3, x8               // f4 * 121666
    umulh x14, x3, x8

    reduce
    ret
.cfi_endproc
.size   Fp51MulScalar,.-Fp51MulScalar

#endif
