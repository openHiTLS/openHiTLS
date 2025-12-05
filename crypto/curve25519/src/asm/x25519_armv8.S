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

#include "crypt_arm.h"

.text

.macro push_stack
    /* save register. */
    stp    x19, x20, [sp, #-16]!
    stp    x21, x22, [sp, #-16]!
    sub    sp, sp, #32
.endm

.macro pop_stack
    add    sp, sp, #32
    /* pop register */
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

    /* Compute h2 value' */
    extr   x10, x10, x9, #51          // h2
    and   x3, x9, #0x7ffffffffffff

    /* Compute h0 value' */
    extr   x5, x5, x4, #51            // h2
    and    x1, x4, #0x7ffffffffffff

    /* Compute h2 value' */
    adds    x11, x11, x10             // h3 += (h2 >> 51)     h2-high +->h3-low
    adc     x12, x12, XZR             // h3-high carry

    /* Compute h0 value' */
    adds    x6, x6, x5                // h1 += (h0 >> 51)     h0-high +->h1-low
    adc     x7, x7, XZR               // h1-high carry

    /* Compute h3 value' */
    extr   x12, x12, x11, #51         // h2
    and    x4, x11, #0x7ffffffffffff

    adds    x13, x13, x12             // h4 += (h3 >> 51)      h3-high +->h4-low
    adc     x14, x14, XZR             // h4-high carry

    /* Compute h1 value' */
    extr   x7, x7, x6, #51            // h2
    and    x2, x6, #0x7ffffffffffff
    adds    x3, x3, x7                // h2 += (h1 >> 51)       h1-high +->h2-low

    /* Compute h4 value' */
    extr   x14, x14, x13, #51         // h2
    and    x5, x13, #0x7ffffffffffff

    /* out[0] = out[0] + 19 * carry */
    lsl     x6, x14, #3
    adds    x6, x6, x14               // h4-high * 8 + h4-high -> x6 (9 * h4-high)
    adds    x14, x14, x6, lsl #1      // x6 *2 + x14 => x6 --- h4-high * 9 * 2 +  h4-high
    adds    x1, x1, x14               // h4-high * 19 +->h0-low

    /* Compute the remainder of h2 */
    and     x6, x3, #0x7ffffffffffff  // h2 &= (2^51 - 1)  Clear the high 13 bits of h2-low - x3
    lsr     x3, x3, #51               // h2-low << 51 (carry)
    adds    x4, x4, x3                // h2-low << 51 -> h3-low

    /* out[0] &= (2^51 - 1) */
    and     x3, x1, #0x7ffffffffffff  // Clear the high 13 bits of h0-low
    lsr     x1, x1, #51               // h0-low << 51 (carry)
    adds    x2, x2, x1                // h0-low << 51 -> h1-low

    /* Store the result */
    str     x3, [x0]                  // h0'
    str     x2, [x0, #8]              // h1'
    str     x6, [x0, #16]             // h2'
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
AARCH64_PACIASP
    /* save register */
    push_stack

    /*
     * x0: out; x1: f; x2: g; fp51: array[u64; 5]
     */
    ldr    x3, [x1]                  // f0
    ldr    x13, [x2]                 // g0
    ldp    x11, x12, [x2, #8]        // g1, g2
    ldp    x15, x14, [x2, #24]       // g3, g4

    str	   x0, [sp, #24]
    /*
     * x13, x11, and x12 will be overwritten in subsequent calculation, and g0 to g2 will be stored.
     */
    mov    x8, #19
    /* h0 = f0g0 + 19f1g4 + 19f2g3 + 19f3g2 + 19f4g1; save in x4(low), x5(high) */
    mul    x4, x3, x13               // (x4, x5) = f0 * g0
    umulh  x5, x3, x13
    str    x13, [sp, #16]            // g0

    /* h1 = f0g1 + f1g0 + 19f2g4 + 19f3g3 + 19f4g2; save in x6, x7 */
    mul    x6, x3, x11               // (x6, x7) = f0 * g1
    umulh  x7, x3, x11
    lsl    x13, x14, #3
    add    x13, x13, x14             // g4 * 8 + g4 = g4 * 9
    str    x11, [sp, #8]             // g1

    /* h2 = f0g2 + f1g1 + f2g0 + 19f3g4 + 19f4g3; save in x9, x10 */
    mul    x9, x3, x12               // (x9, x10) = f0 * g2
    umulh  x10, x3, x12
    lsl    x0, x13, #1
    add    x0, x0, x14               // rdi = 2 * (9 * g4) + g4
    str    x12, [sp]                 // g2

    /* h3 = f0g3 + f1g2 + f2g1 + f3g0 + 19f4g4; save in x11, x12 */
    mul    x11, x3, x15              // (x11, x12) = f0 * g3
    umulh  x12, x3, x15

    /* h4 = f0g4 + f1g3 + f2g2 + f3g1 + f4g0; save in x13, x14 */
    mul    x13, x3, x14              // (x13, x14) = f0 * g4
    umulh  x14, x3, x14
    ldr    x3, [x1, #8]              // f1

    /* compute 19 * g4 */
    u51mul  x0, x4, x5               // (x4, x5) = 19 * f1 * g4; load f2
    ldr     x3, [x1, #16]
    u51mul  x0, x6, x7               // (x6, x7) = 19 * f2 * g4; load f3
    ldr     x3, [x1, #24]
    u51mul  x0, x9, x10              // (x9, x10) = 19 * f3 * g4; load f4
    ldr     x3, [x1, #32]
    u51mul  x0, x11, x12             // (x11, x12) = 19 * f3 * g4; load f4
    ldr     x3, [x1, #8]
    mul     x0, x15, x8              // 19 * g3

    /* compute g3 */           
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

    /* compute g2 */
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

    /* compute g1 */
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

    /* compute g0 */
    u51mul  x15, x6, x7              // (x6, x7) += f1 * g0; load f2
    ldr     x3, [x1, #16]
    u51mul  x15, x9, x10             // (x9, x10) += f2 * g0; load f3
    ldr     x3, [x1, #24]
    u51mul  x15, x11, x12            // (x11, x12) = f3 * g0; load f4
    ldr     x3, [x1, #32]
                  
    u64mul  x3, x15                  // (x13, x14) += f4 * g0
    adds    x13, x13, x19
    adc     x14, x14, x2

    /* pop stack register */
    ldr    x0, [sp, #24]

    reduce

    pop_stack
AARCH64_AUTIASP
    ret
.size   Fp51Mul,.-Fp51Mul

#############################################################
# void Fp51Square(Fp51 *out, const Fp51 *f);
#############################################################

.globl  Fp51Square
.type   Fp51Square, @function
.align  6
Fp51Square:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    str     x19, [sp, #16]
    ldr     x7, [x1, #32]                  // load f4
    ldp     x2, x17, [x1]                  // load f0, f1
    ldp     x10, x6, [x1, #16]             // load f2, f3
    add     x5, x7, x7, lsl #2
    lsl     x5, x5, #2
    lsl     x15, x2, #1                    // f0 * 2
    sub     x5, x5, x7                     // f4 * 19
    lsl     x13, x17, #1                   // f1 * 2
    add     x14, x6, x6, lsl #2
    lsl     x3, x6, #1                     // f3 * 2
    lsl     x14, x14, #2
    mul     x16, x15, x6                   // 2 * f0 * f3  - low
    sub     x14, x14, x6                   // f3 * 19
    mul     x1, x7, x5                     // 19 * f4 * f4   - low
    umulh   x11, x15, x6                   // 2 * f0 * f3  - high
    mul     x18, x6, x13                   // 2 * f1 * f3  - low
    adds    x16, x16, x1                   // 2 * f0 * f3 + 19 * f4 * f4   h3 - low
    umulh   x4, x7, x5                     // 19 * f4 * f4   - high
    mul     x9, x15, x7                    // 2 * f0 * f4   - low
    umulh   x8, x6, x13                    // 2 * f1 * f3   - high
    adc     x4, x11, x4                    // 2 * f0 * f3 + 19 * f4 * f4   h3 - high
    umulh   x7, x15, x7                    // 2 * f0 * f4   - high
    adds    x9, x18, x9                    // 2 * f1 * f3 + 2 * f0 * f4    h4 - low
    mul     x1, x6, x14                    // 19 * f3 * f3   - low
    lsl     x18, x10, #1                   // f2 * 2
    mul     x12, x15, x17                  // 2 * f0 * f1   - low
    adc     x8, x8, x7                     // 2 * f1 * f3 + 2 * f0 * f4    h4 - high
    mul     x19, x15, x10                  // 2 * f0 * f2   - low
    umulh   x11, x15, x17                  // 2 * f0 * f1  - high
    adds    x12, x12, x1                   // h1 = 2 * f0 * f1 + 19 * f3 * f3  - low
    umulh   x6, x6, x14                    // 19 * f3 * f3   - high
    mul     x7, x3, x5                     // 38 * f3 * f4 - low
    umulh   x1, x15, x10                   // 2 * f0 * f2   - high
    adc     x11, x11, x6                   // h1 = 2 * f0 * f1 + 19 * f3 * f3   - high
    umulh   x3, x3, x5                     // 38 * f3 * f4   - high
    adds    x7, x7, x19                    // 38 * f3 * f4 + 2 * f0 * f2   h2 - low
    mul     x15, x17, x17                  // f1 * f1  - low
    adc     x1, x3, x1                     // 38 * f3 * f4 + 2 * f0 * f2   h2 - high
    mul     x6, x5, x13                    // 38 * f1 * f4 - low
    mul     x3, x14, x18                   // 38 * f3 * f2 - low
    adds    x7, x15, x7                    // 38 * f3 * f4 + 2 * f0 * f2 + f1 * f1  h2 - low
    umulh   x17, x17, x17                  // f1 * f1  - high
    mul     x30, x10, x13                  // 2 * f1 * f2  - low
    adc     x1, x1, x17                    // 38 * f3 * f4 + 2 * f0 * f2 + f1 * f1  h2 - high
    mul     x19, x2, x2                    // f0 * f0  - low
    adds    x6, x6, x3                     // 38 * f1 * f4 + 38 * f3 * f2  h0 - low
    umulh   x14, x14, x18                  // 38 * f3 * f2  - high
    umulh   x3, x10, x13                   // 2 * f1 * f2  - high
    extr    x1, x1, x7, #51                // performs a carry operation from the upper 13 bits of the lower 64 bits of h2 to the upper 64 bits of h2. h2 - high
    umulh   x13, x5, x13                   // 38 * f1 * f4   - high
    and     x7, x7, #0x7ffffffffffff       // Clears the upper 13 bits of the lower 64 bits of h2
    umulh   x2, x2, x2                     // f0 * f0  - high
    adc     x13, x13, x14                  // h0 = 38 * f3 * f2 + 38 * f1 * f4   - high
    adds    x6, x6, x19                    // h0 = 38 * f1 * f4 + 38 * f3 * f2 + f0 * f0  - low
    adc     x2, x2, x13                    // h0 = 38 * f3 * f2 + 38 * f1 * f4  + f0 * f0  - high
    adds    x1, x1, x30                    // carry h2 -> h3 (h2 - high + 2 * f1 * f2  - low)
    mul     x17, x5, x18                   // 38 * f2 * f4   - low
    cinc    x3, x3, cs
    adds    x1, x1, x16                    // 2 * f0 * f3 +  19 * f4 * f4 + 2 * f1 * f2 + h2-carry  h3 - low
    umulh   x5, x5, x18                    // 38 * f2 * f4   - high
    adc     x3, x4, x3                     // h3 =  2 * f0 *f3 +  19 * f4 * f4 + 2 * f1 * f2  - high
    extr    x2, x2, x6, #51                // h0 - high
    adds    x2, x2, x17                    // carry: h0 -> h1 (38 * f2 * f4   - low)
    mul     x15, x10, x10                  // f2 * f2  - low
    umulh   x4, x10, x10                   // f2 * f2  - high
    cinc    x5, x5, cs
    adds    x2, x2, x12                    // 2 * f0 * f1 + 19 * f3 * f3 + 38 * f2 * f4 + h0-carry  h1 - low
    extr    x3, x3, x1, #51                // h3 - high
    adc     x5, x11, x5                    // 2 * f0 * f1 + 19 * f3 * f3 + 38 * f2 * f4  h1 - high
    adds    x3, x3, x15                    // carry: h3 -> h4 (f2 * f2  - low)
    cinc    x4, x4, cs
    adds    x3, x3, x9                     // 2 * f1 * f3 + 2 * f0 * f4 + f2 * f2 + h3->carry  h4 - low
    adc     x4, x8, x4                     // 2 * f1 * f3 + 2 * f0 * f4 + f2 * f2  h4 - high
    extr    x5, x5, x2, #51                // h1 - high
    add     x7, x7, x5                     // carry: h1 -> h2
    and     x6, x6, #0x7ffffffffffff       // h0
    and     x1, x1, #0x7ffffffffffff       // h3
    extr    x4, x4, x3, #51                // h4 - high
    add     x5, x4, x4, lsl #2
    and     x2, x2, #0x7ffffffffffff       // h1
    add     x6, x6, x5, lsl #2             // carry : h4->h0, h4 - high * 20 + h0-low
    add     x1, x1, x7, lsr #51            // carry : h2->h3
    sub     x6, x6, x4                     // carry : h4->h0, h4 - high * 19 + h0-low
    and     x5, x7, #0x7ffffffffffff       // h1
    and     x4, x6, #0x7ffffffffffff       // h0
    add     x2, x2, x6, lsr #51            // carry: h0 -> h1
    and     x3, x3, #0x7ffffffffffff       // h4
    ldr     x19, [sp, #16]
    stp     x4, x2, [x0]
    ldp     x29, x30, [sp], #32
    stp     x5, x1, [x0, #16]
    str     x3, [x0, #32]
AARCH64_AUTIASP
    ret
.size   Fp51Square,.-Fp51Square

#############################################################
# void Fp51MulScalar(Fp51 *out, const Fp51 *in);
#############################################################

.globl  Fp51MulScalar
.type   Fp51MulScalar, @function
.align  6
Fp51MulScalar:
AARCH64_PACIASP
    /*
     * x0: out; x1: in; fp51 array [u64; 5]
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

AARCH64_AUTIASP
    ret
.size   Fp51MulScalar,.-Fp51MulScalar

#endif
