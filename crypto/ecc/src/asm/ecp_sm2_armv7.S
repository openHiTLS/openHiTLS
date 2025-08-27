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
 *
 * -----------------------------------------------------------------------------
 *
 * ARMv7 Cortex-M4 assembly optimization for SM2:
 *   Contributors: Zhao Runchen, Li Xukai, Wang Weijia
 *   Affiliation: Shandong University and Quan Cheng Laboratory
 *   Date: 2025.8.20
 *
 * -----------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CURVE_SM2

.syntax unified
.thumb

# sm2_p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
# sm2_q = 0x00000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
# sm2_s = 0x7FFFFFFF7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF800000008000000000000000
# sm2_n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
# sm2_m = 0x000000010000000000000000000000008DFC2094DE39FAD4AC440BF6C62ABEDD
# sm2_l = 0x7FFFFFFF7FFFFFFFFFFFFFFFFFFFFFFFB901EFB590E30295A9DDFA049CEAA092
# Note: sm2_q = - sm2_p mod 2^256, sm2_s = (sm2_p + 1) / 2.
# Note: sm2_m = - sm2_n mod 2^256, sm2_l = (sm2_n + 1) / 2.
.equ sm2_p1, 0xFFFFFFFF
.equ sm2_p2, 0xFFFFFFFF
.equ sm2_p3, 0x00000000
.equ sm2_p4, 0xFFFFFFFF
.equ sm2_p5, 0xFFFFFFFF
.equ sm2_p6, 0xFFFFFFFF
.equ sm2_p7, 0xFFFFFFFF
.equ sm2_p8, 0xFFFFFFFE
.equ sm2_q1, 0x00000001
.equ sm2_q2, 0x00000000
.equ sm2_q3, 0xFFFFFFFF
.equ sm2_q4, 0x00000000
.equ sm2_q5, 0x00000000
.equ sm2_q6, 0x00000000
.equ sm2_q7, 0x00000000
.equ sm2_q8, 0x00000001
.equ sm2_s1, 0x00000000
.equ sm2_s2, 0x80000000
.equ sm2_s3, 0x80000000
.equ sm2_s4, 0xFFFFFFFF
.equ sm2_s5, 0xFFFFFFFF
.equ sm2_s6, 0xFFFFFFFF
.equ sm2_s7, 0x7FFFFFFF
.equ sm2_s8, 0x7FFFFFFF
.equ sm2_n1, 0x39D54123
.equ sm2_n2, 0x53BBF409
.equ sm2_n3, 0x21C6052B
.equ sm2_n4, 0x7203DF6B
.equ sm2_n5, 0xFFFFFFFF
.equ sm2_n6, 0xFFFFFFFF
.equ sm2_n7, 0xFFFFFFFF
.equ sm2_n8, 0xFFFFFFFE
.equ sm2_m1, 0xC62ABEDD
.equ sm2_m2, 0xAC440BF6
.equ sm2_m3, 0xDE39FAD4
.equ sm2_m4, 0x8DFC2094
.equ sm2_m5, 0x00000000
.equ sm2_m6, 0x00000000
.equ sm2_m7, 0x00000000
.equ sm2_m8, 0x00000001
.equ sm2_l1, 0x9CEAA092
.equ sm2_l2, 0xA9DDFA04
.equ sm2_l3, 0x90E30295
.equ sm2_l4, 0xB901EFB5
.equ sm2_l5, 0xFFFFFFFF
.equ sm2_l6, 0xFFFFFFFF
.equ sm2_l7, 0x7FFFFFFF
.equ sm2_l8, 0x7FFFFFFF

# Note: In next, V refers specifically to the reglist {v1-v8} that stores 256-bit numbers.
# Return.
.macro RET
    MOV pc, lr
.endm

# v = n
.macro VLDR n1 n2 n3 n4 n5 n6 n7 n8
	LDR v1, =\n1
    LDR v2, =\n2
    LDR v3, =\n3
    LDR v4, =\n4
    LDR v5, =\n5
    LDR v6, =\n6
    LDR v7, =\n7
    LDR v8, =\n8
.endm

# v = v + n
.macro VADD n1 n2 n3 n4 n5 n6 n7 n8
	ADDS v1, \n1
	ADCS v2, \n2
	ADCS v3, \n3
	ADCS v4, \n4
	ADCS v5, \n5
	ADCS v6, \n6
	ADCS v7, \n7
	ADCS v8, \n8
.endm

# v = v - n
.macro VSUB n1 n2 n3 n4 n5 n6 n7 n8
	SUBS v1, \n1
	SBCS v2, \n2
	SBCS v3, \n3
	SBCS v4, \n4
	SBCS v5, \n5
	SBCS v6, \n6
	SBCS v7, \n7
	SBCS v8, \n8
.endm

# v = v - sm2_q
.macro VSUBQ
	VSUB sm2_q1, sm2_q2, sm2_q3, sm2_q4, sm2_q5, sm2_q6, sm2_q7, sm2_q8
.endm

# v = v + sm2_s
.macro VADDS
	VADD sm2_s1, sm2_s2, sm2_s3, sm2_s4, sm2_s5, sm2_s6, sm2_s7, sm2_s8
.endm

# v = v - sm2_m, Where sm2_m1~sm2_m4 is not an immediate value and must be loaded into a register.
.macro VSUBM reg1 reg2
	LDR \reg1, =sm2_m1
	LDR \reg2, =sm2_m2
	SUBS v1, \reg1
	SBCS v2, \reg2
	LDR \reg1, =sm2_m3
	LDR \reg2, =sm2_m4
	SBCS v3, \reg1
	SBCS v4, \reg2
	SBCS v5, #sm2_m5
	SBCS v6, #sm2_m6
	SBCS v7, #sm2_m7
	SBCS v8, #sm2_m8
.endm

# v = v - sm2_l, Where sm2_l1~sm2_l4 is not an immediate value and must be loaded into a register.
.macro VADDL reg1 reg2
	LDR \reg1, =sm2_l1
	LDR \reg2, =sm2_l2
	ADDS v1, \reg1
	ADCS v2, \reg2
	LDR \reg1, =sm2_l3
	LDR \reg2, =sm2_l4
	ADCS v3, \reg1
	ADCS v4, \reg2
	ADCS v5, #sm2_l5
	ADCS v6, #sm2_l6
	ADCS v7, #sm2_l7
	ADCS v8, #sm2_l8
.endm

# v = v >> 1
.macro VLSR
    LSRS v8, #1
    RRXS v7, v7
    RRXS v6, v6
    RRXS v5, v5
    RRXS v4, v4
    RRXS v3, v3
    RRXS v2, v2
    RRXS v1, v1
.endm

# v = v >> 1 mod modulus
.macro VHAF modulus
    VLSR
    BCC 0f
    .ifc "\modulus", "sm2_p"
        VADDS
    .endif
    .ifc "\modulus", "sm2_n"
        VADDL ip lr
    .endif
    0:
.endm

# v = v mod modulus
.macro VMOD modulus
	BCS 0f
    .ifc "\modulus", "sm2_p"
        VSUBQ
    .endif
    .ifc "\modulus", "sm2_n"
        VSUBM ip lr
    .endif
    0:
.endm

# v = - v
.macro VNEG
	MVN v1, v1
	MVN v2, v2
	MVN v3, v3
	MVN v4, v4
	MVN v5, v5
	MVN v6, v6
	MVN v7, v7
	MVN v8, v8
	ADDS v1, #1
	ADCS v2, #0
	ADCS v3, #0
	ADCS v4, #0
	ADCS v5, #0
	ADCS v6, #0
	ADCS v7, #0
	ADCS v8, #0
.endm

# The number pointed to by \reg1 minus the number pointed to by \reg2.
.macro PSUB reg1 reg2
	LDM \reg1!, {v1-v4}
	LDM \reg2!, {v5-v8}
	SUBS v1, v5
	SBCS v2, v6
	SBCS v3, v7
	SBCS v4, v8
	PUSH {v1-v4}
	LDM \reg1, {v5-v8}
	LDM \reg2, {v1-v4}
	SBCS v5, v1
	SBCS v6, v2
	SBCS v7, v3
	SBCS v8, v4
	SUB \reg1, #0x10
	SUB \reg2, #0x10
	POP {v1-v4}
.endm

# Multiplication iteration macro, one can refer to functions(ECP_Sm2FpMul/Sqr) that do not use macro expansion.
.macro MULIT at, ap, cp, i

    MOV lr, #0

    # Select the loading method based on the parameter type of at:
    # imm: load immediate values;
    # oft: load from stack using stack pointer(sp) + offset.
    .ifc \at, imm
    LDR ip, =\ap
    .else
    LDR ip, [sp, #\ap + 0x04 * \i]
    .endif

    # When i == 0, there is no need to load the multiplier from memory.
    .if \i == 0
        MOV r0, #0
        MOV r1, #0
        MOV r2, #0
        MOV r3, #0
    .else
        LDR r0, [sp, #\cp + 0x00 + 0x04 * \i]
        LDR r1, [sp, #\cp + 0x04 + 0x04 * \i]
        LDR r2, [sp, #\cp + 0x08 + 0x04 * \i]
        LDR r3, [sp, #\cp + 0x0C + 0x04 * \i]
    .endif

    UMAAL r0, lr, ip, v1
    UMAAL r1, lr, ip, v2
    UMAAL r2, lr, ip, v3
    UMAAL r3, lr, ip, v4

    STR r0, [sp, #\cp + 0x00 + 0x04 * \i]
    STR r1, [sp, #\cp + 0x04 + 0x04 * \i]
    STR r2, [sp, #\cp + 0x08 + 0x04 * \i]
    STR r3, [sp, #\cp + 0x0C + 0x04 * \i]

    # When i == 0, there is no need to load the multiplier from memory.
    .if \i == 0
        MOV r0, #0
        MOV r1, #0
        MOV r2, #0
        MOV r3, #0
    .else
        LDR r0, [sp, #\cp + 0x10 + 0x04 * \i]
        LDR r1, [sp, #\cp + 0x14 + 0x04 * \i]
        LDR r2, [sp, #\cp + 0x18 + 0x04 * \i]
        LDR r3, [sp, #\cp + 0x1C + 0x04 * \i]
    .endif

    UMAAL r0, lr, ip, v5
    UMAAL r1, lr, ip, v6
    UMAAL r2, lr, ip, v7
    UMAAL r3, lr, ip, v8

    STR r0, [sp, #\cp + 0x10 + 0x04 * \i]
    STR r1, [sp, #\cp + 0x14 + 0x04 * \i]
    STR r2, [sp, #\cp + 0x18 + 0x04 * \i]
    STR r3, [sp, #\cp + 0x1C + 0x04 * \i]
    STR lr, [sp, #\cp + 0x20 + 0x04 * \i]
.endm

.section .text, "ax"
.thumb_func
.align 4

### Compare a and b. If a >= b, return 1; otherwise, return 0.
# int32_t ECP_Sm2FpCmp(const Sm2Fp a, const Sm2Fp b);
.global ECP_Sm2FpCmp
.type   ECP_Sm2FpCmp, %function
ECP_Sm2FpCmp:
	LDR r2, [r0, #0x1C]
	LDR r3, [r1, #0x1C]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x18]
	LDR r3, [r1, #0x18]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x14]
	LDR r3, [r1, #0x14]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x10]
	LDR r3, [r1, #0x10]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x0C]
	LDR r3, [r1, #0x0C]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x08]
	LDR r3, [r1, #0x08]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x04]
	LDR r3, [r1, #0x04]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x00]
	LDR r3, [r1, #0x00]
	CMP r2, r3
	BCC 0f
 1: MOV r0, 1
    RET
 0: MOV r0, 0
    RET

### Compute r ≡ a + b mod sm2_p.
# void ECP_Sm2FpAdd(Sm2Fp r, const Sm2Fp a, const Sm2Fp b);
.global ECP_Sm2FpAdd
.type   ECP_Sm2FpAdd, %function
ECP_Sm2FpAdd:
	PUSH {v1-v8}
	LDM r2, {v1-v8}
	LDR r2, [r1, #0x00]
	LDR r3, [r1, #0x04]
	ADDS v1, r2
	ADCS v2, r3
	LDR r2, [r1, #0x08]
	LDR r3, [r1, #0x0C]
	ADCS v3, r2
	ADCS v4, r3
	LDR r2, [r1, #0x10]
	LDR r3, [r1, #0x14]
	ADCS v5, r2
	ADCS v6, r3
	LDR r2, [r1, #0x18]
	LDR r3, [r1, #0x1C]
	ADCS v7, r2
	ADCS v8, r3
	BCC 0f
	ADDS v1, #sm2_q1
	ADCS v2, #sm2_q2
	ADCS v3, #sm2_q3
	ADCS v4, #sm2_q4
	ADCS v5, #sm2_q5
	ADCS v6, #sm2_q6
	ADCS v7, #sm2_q7
	ADCS v8, #sm2_q8
 0: STM r0, {v1-v8}
	POP {v1-v8}
	RET

### Compute r ≡ a - b mod sm2_p.
# void ECP_Sm2FpSub(Sm2Fp r, const Sm2Fp a, const Sm2Fp b);
.global ECP_Sm2FpSub
.type   ECP_Sm2FpSub, %function
ECP_Sm2FpSub:
	PUSH {v1-v8}
	LDM r1, {v1-v8}
	LDR r1, [r2, #0x00]
	LDR r3, [r2, #0x04]
	SUBS v1, r1
	SBCS v2, r3
	LDR r1, [r2, #0x08]
	LDR r3, [r2, #0x0C]
	SBCS v3, r1
	SBCS v4, r3
	LDR r1, [r2, #0x10]
	LDR r3, [r2, #0x14]
	SBCS v5, r1
	SBCS v6, r3
	LDR r1, [r2, #0x18]
	LDR r3, [r2, #0x1C]
	SBCS v7, r1
	SBCS v8, r3
	BCS 0f
	SUBS v1, #sm2_q1
	SBCS v2, #sm2_q2
	SBCS v3, #sm2_q3
	SBCS v4, #sm2_q4
	SBCS v5, #sm2_q5
	SBCS v6, #sm2_q6
	SBCS v7, #sm2_q7
	SBCS v8, #sm2_q8
 0: STM r0, {v1-v8}
	POP {v1-v8}
	RET

### Compute r ≡ -a mod sm2_p.
# void ECP_Sm2FpNeg(Sm2Fp r, const Sm2Fp a);
.global ECP_Sm2FpNeg
.type   ECP_Sm2FpNeg, %function
ECP_Sm2FpNeg:
	PUSH {r4-r6}
	LDM  r1!, {r2-r4}
	RSB  r2, #sm2_p1
	RSB  r3, #sm2_p2
	RSBS r4, #sm2_p3
	STM  r0!, {r2-r4}
	LDM  r1, {r2-r6}
	RSB  r2, #sm2_p4
	RSB  r3, #sm2_p5
	RSB  r4, #sm2_p6
	RSB  r5, #sm2_p7
	RSB  r6, #sm2_p7
	SBCS r2, #0
	SBCS r4, #0
	SBCS r5, #0
	SBCS r6, #1
	STM  r0, {r2-r6}
	POP  {r4-r6}
	RET

### Compute r ≡ 2a mod sm2_p.
# void ECP_Sm2FpDou(Sm2Fp r, const Sm2Fp a);
.global ECP_Sm2FpDou
.type   ECP_Sm2FpDou, %function
ECP_Sm2FpDou:
	PUSH {r4-r8}
	LDM r1, {r1-r8}
	ADDS r1, r1
	ADCS r2, r2
	ADCS r3, r3
	ADCS r4, r4
	ADCS r5, r5
	ADCS r6, r6
	ADCS r7, r7
	ADCS r8, r8
	BCC 0f
	ADDS r1, #sm2_q1
	ADCS r2, #sm2_q2
	ADCS r3, #sm2_q3
	ADCS r4, #sm2_q4
	ADCS r5, #sm2_q5
	ADCS r6, #sm2_q6
	ADCS r7, #sm2_q7
	ADCS r8, #sm2_q8
 0: STM  r0, {r1-r8}
	POP  {r4-r8}
	RET

### Compute r ≡ a/2 mod sm2_p.
# void ECP_Sm2FpHaf(Sm2Fp r, const Sm2Fp a);
.global ECP_Sm2FpHaf
.type   ECP_Sm2FpHaf, %function
ECP_Sm2FpHaf:
	PUSH {r4-r8}
	LDM r1, {r1-r8}
    LSRS r8, #1
    RRXS r7, r7
    RRXS r6, r6
    RRXS r5, r5
    RRXS r4, r4
    RRXS r3, r3
    RRXS r2, r2
    RRXS r1, r1
	BCC 0f
	ADDS r1, #sm2_s1
	ADCS r2, #sm2_s2
	ADCS r3, #sm2_s3
	ADCS r4, #sm2_s4
	ADCS r5, #sm2_s5
	ADCS r6, #sm2_s6
	ADCS r7, #sm2_s7
	ADCS r8, #sm2_s8
 0: STM  r0, {r1-r8}
	POP  {r4-r8}
	RET

### Compute r ≡ a * b mod sm2_p.
# void ECP_Sm2FpMul(sm2_fp r, const sm2_fp a, const sm2_fp b);

## Step of computing r ≡ a * b mod sm2_p:
# 1. compute c = a * b.
# 2. compute t ≡ c mod sm2_p using the Fast modular reduction.
# 3. Compute r ≡ t mod sm2_p.

## Fast modular reduction:
    #      | c7 | c6 | c5 | c4 | c3 | c2 | c1 | c0 | (+)
    #      | c8 | cb | ca | c9 | c8 |  0 | c9 | c8 | (+)
    #      | c9 | ce | cd | cc | cb |  0 | ca | c9 | (+)
    #      | ca | cf | ce | cd | cc |  0 | cb | ca | (+)
    #      | cb |  0 | cf | ce | cd |  0 | cc | cb | (+)
    #      | cc |  0 | cf | ce | cd |  0 | cd | cc | (+)
    #      | cc |  0 |  0 | cf | ce |  0 | ce | cd | (+)
    #      | cd |  0 |  0 |  0 | cf |  0 | ce | cd | (+)
    #      | cd |  0 |  0 |  0 |  0 |  0 | cf | ce | (+)
    #      | ce |  0 |  0 |  0 |  0 |  0 | cf | ce | (+)
    #      | ce |  0 |  0 |  0 |  0 |  0 |  0 | cf | (+)
    #      | cf |  0 |  0 |  0 |  0 |  0 |  0 | cf | (+)
    #      | cf |  0 |  0 |  0 |  0 |  0 |  0 |  0 | (+)
    #      | cf |  0 |  0 |  0 |  0 |  0 |  0 |  0 | (+)
    #      |  0 |  0 |  0 |  0 |  0 | c8 |  0 |  0 | (-)
    #      |  0 |  0 |  0 |  0 |  0 | c9 |  0 |  0 | (-)
    #      |  0 |  0 |  0 |  0 |  0 | cd |  0 |  0 | (-)
    #      |  0 |  0 |  0 |  0 |  0 | ce |  0 |  0 | (-)
    # ———————————————————————————————————————————————————————
    # | t8 | t7 | t6 | t5 | t4 | t3 | t2 | t1 | t0 |

## Tips in step 2: one can calculate the repeating middle value first.
    # w0 = c8 + c9 + c10 + c11
    # w1 = c8 + c13
    # w2 = c9 + c14
    # w3 = c14 + c15
    # w4 = w3 + c13
    # w5 = w4 + c12
    # w0 = w0 + w5
    # T0 = c0 + w0 + w4
    # T1 = c1 + w0 + w4 - w1
    # T2 = c2 - w1 - w2
    # T3 = c3 + w5 + w1 + cb
    # T4 = c4 + w5 + w2
    # T5 = c5 + w4 + ca + cf
    # T6 = c6 + w3 + cb
    # T7 = c7 + w0 + w5 + cf
    # Obtain t0~t8 after processing the above carry in T0~T7.

## Tips in step 3: one can use the fast modular reduction algorithm again. At this point, c1,c2,c3,...cf = 0. Thus
    # r = t7 + t8 | t6 | t5 | t4 | t3 + t8 | t2 - t8 | t1 | t0 + t8
    #        ↑                        ↑         ↑              ↑
    # However, it is essential to ensure that the carry is handled.

## The 0x60 bytes of stack space allocated in the ECP_Sm2FpMul function are stored as follows:
    # 0x00 : c0 c1 c2 c3 c4 c5 c6 c7
    # 0x20 : c8 c9 ca cb cc cd ce cf
    # 0x40 : a0 a1 a2 a3 a4 a5 a6 a7

.global ECP_Sm2FpMul
.type   ECP_Sm2FpMul, %function
ECP_Sm2FpMul:
	PUSH {v1-v8, ip, lr}
	PUSH {r0}

	# Allocate stack space, load and store a, load b.
	SUB sp, #0x20
	LDM r1, {v1-v8}
	STM sp, {v1-v8}
	LDM r2, {v1-v8}

	# Allocate stack space, compute and store c.
	SUB sp, #0x40
	# 0
	MOV lr, #0
	LDR ip, [sp, #0x40 + 0x00]
	MOV r0, #0
	MOV r1, #0
	MOV r2, #0
	MOV r3, #0
	UMAAL r0, lr, ip, v1
	UMAAL r1, lr, ip, v2
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STR r0, [sp, #0x00 + 0x00]
	STR r1, [sp, #0x04 + 0x00]
	STR r2, [sp, #0x08 + 0x00]
	STR r3, [sp, #0x0C + 0x00]
	MOV r0, #0
	MOV r1, #0
	MOV r2, #0
	MOV r3, #0
	UMAAL r0, lr, ip, v5
	UMAAL r1, lr, ip, v6
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STR r0, [sp, #0x10 + 0x00]
	STR r1, [sp, #0x14 + 0x00]
	STR r2, [sp, #0x18 + 0x00]
	STR r3, [sp, #0x1C + 0x00]
	STR lr, [sp, #0x20 + 0x00]
	# 1
	MOV lr, #0
	LDR ip, [sp, #0x40 + 0x04]
	LDR r0, [sp, #0x00 + 0x04]
	LDR r1, [sp, #0x04 + 0x04]
	LDR r2, [sp, #0x08 + 0x04]
	LDR r3, [sp, #0x0C + 0x04]
	UMAAL r0, lr, ip, v1
	UMAAL r1, lr, ip, v2
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STR r0, [sp, #0x00 + 0x04]
	STR r1, [sp, #0x04 + 0x04]
	STR r2, [sp, #0x08 + 0x04]
	STR r3, [sp, #0x0C + 0x04]
	LDR r0, [sp, #0x10 + 0x04]
	LDR r1, [sp, #0x14 + 0x04]
	LDR r2, [sp, #0x18 + 0x04]
	LDR r3, [sp, #0x1C + 0x04]
	UMAAL r0, lr, ip, v5
	UMAAL r1, lr, ip, v6
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STR r0, [sp, #0x10 + 0x04]
	STR r1, [sp, #0x14 + 0x04]
	STR r2, [sp, #0x18 + 0x04]
	STR r3, [sp, #0x1C + 0x04]
	STR lr, [sp, #0x20 + 0x04]
	# 2
	MOV lr, #0
	LDR ip, [sp, #0x40 + 0x08]
	LDR r0, [sp, #0x00 + 0x08]
	LDR r1, [sp, #0x04 + 0x08]
	LDR r2, [sp, #0x08 + 0x08]
	LDR r3, [sp, #0x0C + 0x08]
	UMAAL r0, lr, ip, v1
	UMAAL r1, lr, ip, v2
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STR r0, [sp, #0x00 + 0x08]
	STR r1, [sp, #0x04 + 0x08]
	STR r2, [sp, #0x08 + 0x08]
	STR r3, [sp, #0x0C + 0x08]
	LDR r0, [sp, #0x10 + 0x08]
	LDR r1, [sp, #0x14 + 0x08]
	LDR r2, [sp, #0x18 + 0x08]
	LDR r3, [sp, #0x1C + 0x08]
	UMAAL r0, lr, ip, v5
	UMAAL r1, lr, ip, v6
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STR r0, [sp, #0x10 + 0x08]
	STR r1, [sp, #0x14 + 0x08]
	STR r2, [sp, #0x18 + 0x08]
	STR r3, [sp, #0x1C + 0x08]
	STR lr, [sp, #0x20 + 0x08]
	# 3
	MOV lr, #0
	LDR ip, [sp, #0x40 + 0x0C]
	LDR r0, [sp, #0x00 + 0x0C]
	LDR r1, [sp, #0x04 + 0x0C]
	LDR r2, [sp, #0x08 + 0x0C]
	LDR r3, [sp, #0x0C + 0x0C]
	UMAAL r0, lr, ip, v1
	UMAAL r1, lr, ip, v2
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STR r0, [sp, #0x00 + 0x0C]
	STR r1, [sp, #0x04 + 0x0C]
	STR r2, [sp, #0x08 + 0x0C]
	STR r3, [sp, #0x0C + 0x0C]
	LDR r0, [sp, #0x10 + 0x0C]
	LDR r1, [sp, #0x14 + 0x0C]
	LDR r2, [sp, #0x18 + 0x0C]
	LDR r3, [sp, #0x1C + 0x0C]
	UMAAL r0, lr, ip, v5
	UMAAL r1, lr, ip, v6
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STR r0, [sp, #0x10 + 0x0C]
	STR r1, [sp, #0x14 + 0x0C]
	STR r2, [sp, #0x18 + 0x0C]
	STR r3, [sp, #0x1C + 0x0C]
	STR lr, [sp, #0x20 + 0x0C]
	# 4
	MOV lr, #0
	LDR ip, [sp, #0x40 + 0x10]
	LDR r0, [sp, #0x00 + 0x10]
	LDR r1, [sp, #0x04 + 0x10]
	LDR r2, [sp, #0x08 + 0x10]
	LDR r3, [sp, #0x0C + 0x10]
	UMAAL r0, lr, ip, v1
	UMAAL r1, lr, ip, v2
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STR r0, [sp, #0x00 + 0x10]
	STR r1, [sp, #0x04 + 0x10]
	STR r2, [sp, #0x08 + 0x10]
	STR r3, [sp, #0x0C + 0x10]
	LDR r0, [sp, #0x10 + 0x10]
	LDR r1, [sp, #0x14 + 0x10]
	LDR r2, [sp, #0x18 + 0x10]
	LDR r3, [sp, #0x1C + 0x10]
	UMAAL r0, lr, ip, v5
	UMAAL r1, lr, ip, v6
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STR r0, [sp, #0x10 + 0x10]
	STR r1, [sp, #0x14 + 0x10]
	STR r2, [sp, #0x18 + 0x10]
	STR r3, [sp, #0x1C + 0x10]
	STR lr, [sp, #0x20 + 0x10]
	# 5
	MOV lr, #0
	LDR ip, [sp, #0x40 + 0x14]
	LDR r0, [sp, #0x00 + 0x14]
	LDR r1, [sp, #0x04 + 0x14]
	LDR r2, [sp, #0x08 + 0x14]
	LDR r3, [sp, #0x0C + 0x14]
	UMAAL r0, lr, ip, v1
	UMAAL r1, lr, ip, v2
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STR r0, [sp, #0x00 + 0x14]
	STR r1, [sp, #0x04 + 0x14]
	STR r2, [sp, #0x08 + 0x14]
	STR r3, [sp, #0x0C + 0x14]
	LDR r0, [sp, #0x10 + 0x14]
	LDR r1, [sp, #0x14 + 0x14]
	LDR r2, [sp, #0x18 + 0x14]
	LDR r3, [sp, #0x1C + 0x14]
	UMAAL r0, lr, ip, v5
	UMAAL r1, lr, ip, v6
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STR r0, [sp, #0x10 + 0x14]
	STR r1, [sp, #0x14 + 0x14]
	STR r2, [sp, #0x18 + 0x14]
	STR r3, [sp, #0x1C + 0x14]
	STR lr, [sp, #0x20 + 0x14]
	# 6
	MOV lr, #0
	LDR ip, [sp, #0x40 + 0x18]
	LDR r0, [sp, #0x00 + 0x18]
	LDR r1, [sp, #0x04 + 0x18]
	LDR r2, [sp, #0x08 + 0x18]
	LDR r3, [sp, #0x0C + 0x18]
	UMAAL r0, lr, ip, v1
	UMAAL r1, lr, ip, v2
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STR r0, [sp, #0x00 + 0x18]
	STR r1, [sp, #0x04 + 0x18]
	STR r2, [sp, #0x08 + 0x18]
	STR r3, [sp, #0x0C + 0x18]
	LDR r0, [sp, #0x10 + 0x18]
	LDR r1, [sp, #0x14 + 0x18]
	LDR r2, [sp, #0x18 + 0x18]
	LDR r3, [sp, #0x1C + 0x18]
	UMAAL r0, lr, ip, v5
	UMAAL r1, lr, ip, v6
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STR r0, [sp, #0x10 + 0x18]
	STR r1, [sp, #0x14 + 0x18]
	STR r2, [sp, #0x18 + 0x18]
	STR r3, [sp, #0x1C + 0x18]
	STR lr, [sp, #0x20 + 0x18]
	# 7
	MOV lr, #0
	LDR ip, [sp, #0x40 + 0x1C]
	LDR r0, [sp, #0x00 + 0x1C]
	LDR r1, [sp, #0x04 + 0x1C]
	LDR r2, [sp, #0x08 + 0x1C]
	LDR r3, [sp, #0x0C + 0x1C]
	UMAAL r0, lr, ip, v1
	UMAAL r1, lr, ip, v2
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STR r0, [sp, #0x00 + 0x1C]
	STR r1, [sp, #0x04 + 0x1C]
	STR r2, [sp, #0x08 + 0x1C]
	STR r3, [sp, #0x0C + 0x1C]
	LDR r0, [sp, #0x10 + 0x1C]
	LDR r1, [sp, #0x14 + 0x1C]
	LDR r2, [sp, #0x18 + 0x1C]
	LDR r3, [sp, #0x1C + 0x1C]
	UMAAL r0, lr, ip, v5
	UMAAL r1, lr, ip, v6
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STR r0, [sp, #0x10 + 0x1C]
	STR r1, [sp, #0x14 + 0x1C]
	STR r2, [sp, #0x18 + 0x1C]
	STR r3, [sp, #0x1C + 0x1C]
	STR lr, [sp, #0x20 + 0x1C]

    # Load c8~cf and compute w0~w5.
	# Tips: set ip = 1 such that UMLAL ra, rb, rc, ip ==> (rb|ra) += rc.
	LDR v1, [sp, 0x20]
	LDR v2, [sp, 0x24]
	LDR v3, [sp, 0x28]
	LDR v4, [sp, 0x2C]
	LDR v5, [sp, 0x30]
	LDR v6, [sp, 0x34]
	LDR v7, [sp, 0x38]
	LDR v8, [sp, 0x3C]
    MOV ip, #1
    MOV lr, #0

    # Note, The 4 bits overflow values of w0, w1...w5 are stored in bits 0-3, 4-8...20-24 of register lr, respectively.
    # w0 = c8 + c9 + c10 + c11
	UMULL r0, r1, v1, ip
	UMLAL r0, r1, v2, ip
	UMLAL r0, r1, v3, ip
	UMLAL r0, r1, v4, ip
    BFI lr, r1, #0, #4

    # w1 = c8 + c13
	UMULL r1, r2, v1, ip
	UMLAL r1, r2, v6, ip
	BFI lr, r2, #4, #4

    # w2 = c9 + c14
	UMULL r2, r3, v2, ip
	UMLAL r2, r3, v7, ip
	BFI lr, r3, #8, #4

    # w3 = c14 + c15, register r4,r5,r6,r7 is free now.
	UMULL r6, r7, v7, ip
	UMLAL r6, r7, v8, ip
	BFI lr, r7, #12, #4
	MOV r3, r6

    # w4 = w3 + c13
	UMLAL r6, r7, v6, ip
	BFI lr, r7, #16, #4
	MOV r4, r6

    # w5 = w4 + c12
	UMLAL r6, r7, v5, ip
	BFI lr, r7, #20, #4
	MOV r5, r6

    # w0 = w0 + w5
    UBFX v5, lr, #0, #4
    ADDS r6, r6, r0
    ADCS r7, r7, v5
    BFI lr, r7, #0, #4
    MOV r0, r6
    MOV r7, lr

    # Load c0,c1,c2,c3 and compute t0,t1,t2,t3 where lr is used as the carry register.
    # Tips: set ip = 0 such that UMAAL ra, lr, rx, ip ==> (lr|ra) = ra + lr.
    LDM sp, {v5-v8}
    MOV ip, #0
    MOV lr, #0

    # t0 = c0 + w0 + w4
    UBFX r6, r7, #0, #4
	ADDS v5, r0
	ADCS lr, r6
    UBFX r6, r7, #16, #4
    ADDS v5, r4
    ADCS lr, r6

    # t1 = c1 + w0 + w4 - w1
	UMAAL v6, lr, r0, ip
	ADDS v6, r4
	ADCS lr, r6
	UBFX r6, r7, #0, #4
	ADDS v6, r0
	ADCS lr, r6
	UBFX r6, r7, #4, #4
	SUBS v6, r1
	SBCS lr, r6

    # t2 = c2 - w1 - w2
	UMAAL v7, lr, r0, ip
	SUBS v7, r1
	SBCS lr, r6
	UBFX r6, r7, #8, #4
	SUBS v7, r2
	SBCS lr, r6

    # t3 = c3 + w5 + w1 + cb, register r1 is free now, load cb to r1
	ADDS v8, v8, lr
	MOV lr, #0
	UBFX r6, r7, #4, #4
	ADDS v8, r1
	ADCS lr, r6
	UBFX r6, r7, #20, #4
	ADDS v8, r5
	ADCS lr, r6
	LDR r1, [sp, #0x2C]
	ADDS v8, r1
	ADCS lr, #0

	# Stroe t0,t1,t2,t3, load c4,c5,c6,c7, compute t4,t5,t6,t7,t8
	STM sp, {v5-v8}
	LDR v5, [sp, #0x10]
	LDR v6, [sp, #0x14]
	LDR v7, [sp, #0x18]
	LDR v8, [sp, #0x1C]

    # t4 = c4 + w5 + w2
	UMAAL v5, lr, r0, ip
	ADDS v5, r5
    ADCS lr, r6
    UBFX r6, r7, #8, #4
	ADDS v5, r2
	ADCS lr, r6

    # t5 = c5 + w4 + ca + cf, register r2 and r4 is free now, load ca to r2 and cf to r4
	UMAAL v6, lr, r0, ip
	UBFX r6, r7, #16, #4
	ADDS v6, r4
	ADCS lr, r6
	LDR r2, [sp, #0x28]
    LDR r4, [sp, #0x3C]
    ADDS v6, r2
    ADCS lr, #0
    ADDS v6, r4
    ADCS lr, #0

    # t6 = c6 + w3 + cb
	UMAAL v7, lr, r0, ip
	UBFX r6, r7, #12, #4
	ADDS v7, r3
	ADCS lr, r6
	ADDS v7, r1
	ADCS lr, #0

    # t7 = c7 + w0 + w5 + cf, t8 = lr
	UMAAL v8, lr, r0, ip
	UBFX r6, r7, #0, #4
	ADDS v8, r0
	ADCS lr, r6
	UBFX r6, r7, #20, #4
	ADDS v8, r5
	ADCS lr, r6
    ADDS v8, r4
    ADCS lr, #0

	# compute r = t7 + t8 | t6 | t5 | t4 | t3 + t8 | t2 - t8 | t1 | t0 + t8
    LDM sp, {v1-v4}
	ADDS v1, lr
	ADCS v2, #0
	ADCS v3, #0
	ADCS v4, lr
	ADCS v5, #0
	ADCS v6, #0
	ADCS v7, #0
	ADCS v8, lr
	SUBS v3, lr
	SBCS v4, #0
	SBCS v5, #0
	SBCS v6, #0
	SBCS v7, #0
	SBCS v8, #0
	ADD sp, #0x60
	POP {r0}
	STM r0, {v1-v8}
	POP {v1-v8, ip, lr}
	RET

### Compute r ≡ a² mod sm2_p.
# void ECP_Sm2FpSqr(sm2_fp r, const sm2_fp a);
.global ECP_Sm2FpSqr
.type   ECP_Sm2FpSqr, %function
ECP_Sm2FpSqr:
	PUSH {v1-v8, ip, lr}
	PUSH {r0}

	# Allocate stack space, load a, compute c = a * a
    LDM r1, {v1-v8}
    SUB sp, #0x40

	# 0
	MOV lr, #0
	MOV r0, #0
	MOV r1, #0
	MOV r2, #0
	MOV r3, #0
	UMAAL r0, lr, v1, v1
	UMAAL r1, lr, v1, v2
	UMAAL r2, lr, v1, v3
	UMAAL r3, lr, v1, v4
	STR r0, [sp, #0x00 + 0x00]
	STR r1, [sp, #0x04 + 0x00]
	STR r2, [sp, #0x08 + 0x00]
	STR r3, [sp, #0x0C + 0x00]
	MOV r0, #0
	MOV r1, #0
	MOV r2, #0
	MOV r3, #0
	UMAAL r0, lr, v1, v5
	UMAAL r1, lr, v1, v6
	UMAAL r2, lr, v1, v7
	UMAAL r3, lr, v1, v8
	STR r0, [sp, #0x10 + 0x00]
	STR r1, [sp, #0x14 + 0x00]
	STR r2, [sp, #0x18 + 0x00]
	STR r3, [sp, #0x1C + 0x00]
	STR lr, [sp, #0x20 + 0x00]
	# 1
	MOV lr, #0
	LDR r0, [sp, #0x00 + 0x04]
	LDR r1, [sp, #0x04 + 0x04]
	LDR r2, [sp, #0x08 + 0x04]
	LDR r3, [sp, #0x0C + 0x04]
	UMAAL r0, lr, v2, v1
	UMAAL r1, lr, v2, v2
	UMAAL r2, lr, v2, v3
	UMAAL r3, lr, v2, v4
	STR r0, [sp, #0x00 + 0x04]
	STR r1, [sp, #0x04 + 0x04]
	STR r2, [sp, #0x08 + 0x04]
	STR r3, [sp, #0x0C + 0x04]
	LDR r0, [sp, #0x10 + 0x04]
	LDR r1, [sp, #0x14 + 0x04]
	LDR r2, [sp, #0x18 + 0x04]
	LDR r3, [sp, #0x1C + 0x04]
	UMAAL r0, lr, v2, v5
	UMAAL r1, lr, v2, v6
	UMAAL r2, lr, v2, v7
	UMAAL r3, lr, v2, v8
	STR r0, [sp, #0x10 + 0x04]
	STR r1, [sp, #0x14 + 0x04]
	STR r2, [sp, #0x18 + 0x04]
	STR r3, [sp, #0x1C + 0x04]
	STR lr, [sp, #0x20 + 0x04]
	# 2
	MOV lr, #0
	LDR r0, [sp, #0x00 + 0x08]
	LDR r1, [sp, #0x04 + 0x08]
	LDR r2, [sp, #0x08 + 0x08]
	LDR r3, [sp, #0x0C + 0x08]
	UMAAL r0, lr, v3, v1
	UMAAL r1, lr, v3, v2
	UMAAL r2, lr, v3, v3
	UMAAL r3, lr, v3, v4
	STR r0, [sp, #0x00 + 0x08]
	STR r1, [sp, #0x04 + 0x08]
	STR r2, [sp, #0x08 + 0x08]
	STR r3, [sp, #0x0C + 0x08]
	LDR r0, [sp, #0x10 + 0x08]
	LDR r1, [sp, #0x14 + 0x08]
	LDR r2, [sp, #0x18 + 0x08]
	LDR r3, [sp, #0x1C + 0x08]
	UMAAL r0, lr, v3, v5
	UMAAL r1, lr, v3, v6
	UMAAL r2, lr, v3, v7
	UMAAL r3, lr, v3, v8
	STR r0, [sp, #0x10 + 0x08]
	STR r1, [sp, #0x14 + 0x08]
	STR r2, [sp, #0x18 + 0x08]
	STR r3, [sp, #0x1C + 0x08]
	STR lr, [sp, #0x20 + 0x08]
	# 3
	MOV lr, #0
	LDR r0, [sp, #0x00 + 0x0C]
	LDR r1, [sp, #0x04 + 0x0C]
	LDR r2, [sp, #0x08 + 0x0C]
	LDR r3, [sp, #0x0C + 0x0C]
	UMAAL r0, lr, v4, v1
	UMAAL r1, lr, v4, v2
	UMAAL r2, lr, v4, v3
	UMAAL r3, lr, v4, v4
	STR r0, [sp, #0x00 + 0x0C]
	STR r1, [sp, #0x04 + 0x0C]
	STR r2, [sp, #0x08 + 0x0C]
	STR r3, [sp, #0x0C + 0x0C]
	LDR r0, [sp, #0x10 + 0x0C]
	LDR r1, [sp, #0x14 + 0x0C]
	LDR r2, [sp, #0x18 + 0x0C]
	LDR r3, [sp, #0x1C + 0x0C]
	UMAAL r0, lr, v4, v5
	UMAAL r1, lr, v4, v6
	UMAAL r2, lr, v4, v7
	UMAAL r3, lr, v4, v8
	STR r0, [sp, #0x10 + 0x0C]
	STR r1, [sp, #0x14 + 0x0C]
	STR r2, [sp, #0x18 + 0x0C]
	STR r3, [sp, #0x1C + 0x0C]
	STR lr, [sp, #0x20 + 0x0C]
	# 4
	MOV lr, #0
	LDR r0, [sp, #0x00 + 0x10]
	LDR r1, [sp, #0x04 + 0x10]
	LDR r2, [sp, #0x08 + 0x10]
	LDR r3, [sp, #0x0C + 0x10]
	UMAAL r0, lr, v5, v1
	UMAAL r1, lr, v5, v2
	UMAAL r2, lr, v5, v3
	UMAAL r3, lr, v5, v4
	STR r0, [sp, #0x00 + 0x10]
	STR r1, [sp, #0x04 + 0x10]
	STR r2, [sp, #0x08 + 0x10]
	STR r3, [sp, #0x0C + 0x10]
	LDR r0, [sp, #0x10 + 0x10]
	LDR r1, [sp, #0x14 + 0x10]
	LDR r2, [sp, #0x18 + 0x10]
	LDR r3, [sp, #0x1C + 0x10]
	UMAAL r0, lr, v5, v5
	UMAAL r1, lr, v5, v6
	UMAAL r2, lr, v5, v7
	UMAAL r3, lr, v5, v8
	STR r0, [sp, #0x10 + 0x10]
	STR r1, [sp, #0x14 + 0x10]
	STR r2, [sp, #0x18 + 0x10]
	STR r3, [sp, #0x1C + 0x10]
	STR lr, [sp, #0x20 + 0x10]
	# 5
	MOV lr, #0
	LDR r0, [sp, #0x00 + 0x14]
	LDR r1, [sp, #0x04 + 0x14]
	LDR r2, [sp, #0x08 + 0x14]
	LDR r3, [sp, #0x0C + 0x14]
	UMAAL r0, lr, v6, v1
	UMAAL r1, lr, v6, v2
	UMAAL r2, lr, v6, v3
	UMAAL r3, lr, v6, v4
	STR r0, [sp, #0x00 + 0x14]
	STR r1, [sp, #0x04 + 0x14]
	STR r2, [sp, #0x08 + 0x14]
	STR r3, [sp, #0x0C + 0x14]
	LDR r0, [sp, #0x10 + 0x14]
	LDR r1, [sp, #0x14 + 0x14]
	LDR r2, [sp, #0x18 + 0x14]
	LDR r3, [sp, #0x1C + 0x14]
	UMAAL r0, lr, v6, v5
	UMAAL r1, lr, v6, v6
	UMAAL r2, lr, v6, v7
	UMAAL r3, lr, v6, v8
	STR r0, [sp, #0x10 + 0x14]
	STR r1, [sp, #0x14 + 0x14]
	STR r2, [sp, #0x18 + 0x14]
	STR r3, [sp, #0x1C + 0x14]
	STR lr, [sp, #0x20 + 0x14]
	# 6
	MOV lr, #0
	LDR r0, [sp, #0x00 + 0x18]
	LDR r1, [sp, #0x04 + 0x18]
	LDR r2, [sp, #0x08 + 0x18]
	LDR r3, [sp, #0x0C + 0x18]
	UMAAL r0, lr, v7, v1
	UMAAL r1, lr, v7, v2
	UMAAL r2, lr, v7, v3
	UMAAL r3, lr, v7, v4
	STR r0, [sp, #0x00 + 0x18]
	STR r1, [sp, #0x04 + 0x18]
	STR r2, [sp, #0x08 + 0x18]
	STR r3, [sp, #0x0C + 0x18]
	LDR r0, [sp, #0x10 + 0x18]
	LDR r1, [sp, #0x14 + 0x18]
	LDR r2, [sp, #0x18 + 0x18]
	LDR r3, [sp, #0x1C + 0x18]
	UMAAL r0, lr, v7, v5
	UMAAL r1, lr, v7, v6
	UMAAL r2, lr, v7, v7
	UMAAL r3, lr, v7, v8
	STR r0, [sp, #0x10 + 0x18]
	STR r1, [sp, #0x14 + 0x18]
	STR r2, [sp, #0x18 + 0x18]
	STR r3, [sp, #0x1C + 0x18]
	STR lr, [sp, #0x20 + 0x18]
	# 7
	MOV lr, #0
	LDR r0, [sp, #0x00 + 0x1C]
	LDR r1, [sp, #0x04 + 0x1C]
	LDR r2, [sp, #0x08 + 0x1C]
	LDR r3, [sp, #0x0C + 0x1C]
	UMAAL r0, lr, v8, v1
	UMAAL r1, lr, v8, v2
	UMAAL r2, lr, v8, v3
	UMAAL r3, lr, v8, v4
	STR r0, [sp, #0x00 + 0x1C]
	STR r1, [sp, #0x04 + 0x1C]
	STR r2, [sp, #0x08 + 0x1C]
	STR r3, [sp, #0x0C + 0x1C]
	LDR r0, [sp, #0x10 + 0x1C]
	LDR r1, [sp, #0x14 + 0x1C]
	LDR r2, [sp, #0x18 + 0x1C]
	LDR r3, [sp, #0x1C + 0x1C]
	UMAAL r0, lr, v8, v5
	UMAAL r1, lr, v8, v6
	UMAAL r2, lr, v8, v7
	UMAAL r3, lr, v8, v8
	STR r0, [sp, #0x10 + 0x1C]
	STR r1, [sp, #0x14 + 0x1C]
	STR r2, [sp, #0x18 + 0x1C]
	STR r3, [sp, #0x1C + 0x1C]
	STR lr, [sp, #0x20 + 0x1C]

    # Load c8~cf and compute w0~w5.
	# Tips: set ip = 1 such that UMLAL ra, rb, rc, ip ==> (rb|ra) += rc.
	LDR v1, [sp, 0x20]
	LDR v2, [sp, 0x24]
	LDR v3, [sp, 0x28]
	LDR v4, [sp, 0x2C]
	LDR v5, [sp, 0x30]
	LDR v6, [sp, 0x34]
	LDR v7, [sp, 0x38]
	LDR v8, [sp, 0x3C]
    MOV ip, #1
    MOV lr, #0

    # Note, The 4 bits overflow values of w0, w1...w5 are stored in bits 0-3, 4-8...20-24 of register lr, respectively.
    # w0 = c8 + c9 + c10 + c11
	UMULL r0, r1, v1, ip
	UMLAL r0, r1, v2, ip
	UMLAL r0, r1, v3, ip
	UMLAL r0, r1, v4, ip
    BFI lr, r1, #0, #4

    # w1 = c8 + c13
	UMULL r1, r2, v1, ip
	UMLAL r1, r2, v6, ip
	BFI lr, r2, #4, #4

    # w2 = c9 + c14
	UMULL r2, r3, v2, ip
	UMLAL r2, r3, v7, ip
	BFI lr, r3, #8, #4

    # w3 = c14 + c15, register r4,r5,r6,r7 is free now.
	UMULL r6, r7, v7, ip
	UMLAL r6, r7, v8, ip
	BFI lr, r7, #12, #4
	MOV r3, r6

    # w4 = w3 + c13
	UMLAL r6, r7, v6, ip
	BFI lr, r7, #16, #4
	MOV r4, r6

    # w5 = w4 + c12
	UMLAL r6, r7, v5, ip
	BFI lr, r7, #20, #4
	MOV r5, r6

    # w0 = w0 + w5
    UBFX v5, lr, #0, #4
    ADDS r6, r6, r0
    ADCS r7, r7, v5
    BFI lr, r7, #0, #4
    MOV r0, r6
    MOV r7, lr

    # Load c0,c1,c2,c3 and compute t0,t1,t2,t3 where lr is used as the carry register.
    # Tips: set ip = 0 such that UMAAL ra, lr, rx, ip ==> (lr|ra) = ra + lr.
    LDM sp, {v5-v8}
    MOV ip, #0
    MOV lr, #0

    # t0 = c0 + w0 + w4
    UBFX r6, r7, #0, #4
	ADDS v5, r0
	ADCS lr, r6
    UBFX r6, r7, #16, #4
    ADDS v5, r4
    ADCS lr, r6

    # t1 = c1 + w0 + w4 - w1
	UMAAL v6, lr, r0, ip
	ADDS v6, r4
	ADCS lr, r6
	UBFX r6, r7, #0, #4
	ADDS v6, r0
	ADCS lr, r6
	UBFX r6, r7, #4, #4
	SUBS v6, r1
	SBCS lr, r6

    # t2 = c2 - w1 - w2
	UMAAL v7, lr, r0, ip
	SUBS v7, r1
	SBCS lr, r6
	UBFX r6, r7, #8, #4
	SUBS v7, r2
	SBCS lr, r6

    # t3 = c3 + w5 + w1 + cb, register r1 is free now, load cb to r1
	ADDS v8, v8, lr
	MOV lr, #0
	UBFX r6, r7, #4, #4
	ADDS v8, r1
	ADCS lr, r6
	UBFX r6, r7, #20, #4
	ADDS v8, r5
	ADCS lr, r6
	LDR r1, [sp, #0x2C]
	ADDS v8, r1
	ADCS lr, #0

	# Stroe t0,t1,t2,t3, load c4,c5,c6,c7, compute t4,t5,t6,t7,t8
	STM sp, {v5-v8}
	LDR v5, [sp, #0x10]
	LDR v6, [sp, #0x14]
	LDR v7, [sp, #0x18]
	LDR v8, [sp, #0x1C]

    # t4 = c4 + w5 + w2
	UMAAL v5, lr, r0, ip
	ADDS v5, r5
    ADCS lr, r6
    UBFX r6, r7, #8, #4
	ADDS v5, r2
	ADCS lr, r6

    # t5 = c5 + w4 + ca + cf, register r2 and r4 is free now, load ca to r2 and cf to r4
	UMAAL v6, lr, r0, ip
	UBFX r6, r7, #16, #4
	ADDS v6, r4
	ADCS lr, r6
	LDR r2, [sp, #0x28]
    LDR r4, [sp, #0x3C]
    ADDS v6, r2
    ADCS lr, #0
    ADDS v6, r4
    ADCS lr, #0

    # t6 = c6 + w3 + cb
	UMAAL v7, lr, r0, ip
	UBFX r6, r7, #12, #4
	ADDS v7, r3
	ADCS lr, r6
	ADDS v7, r1
	ADCS lr, #0

    # t7 = c7 + w0 + w5 + cf, t8 = lr
	UMAAL v8, lr, r0, ip
	UBFX r6, r7, #0, #4
	ADDS v8, r0
	ADCS lr, r6
	UBFX r6, r7, #20, #4
	ADDS v8, r5
	ADCS lr, r6
    ADDS v8, r4
    ADCS lr, #0

	# compute r = t7 + t8 | t6 | t5 | t4 | t3 + t8 | t2 - t8 | t1 | t0 + t8
    LDM sp, {v1-v4}
	ADDS v1, lr
	ADCS v2, #0
	ADCS v3, #0
	ADCS v4, lr
	ADCS v5, #0
	ADCS v6, #0
	ADCS v7, #0
	ADCS v8, lr
	SUBS v3, lr
	SBCS v4, #0
	SBCS v5, #0
	SBCS v6, #0
	SBCS v7, #0
	SBCS v8, #0
	ADD sp, #0x40
	POP {r0}
	STM r0, {v1-v8}
	POP {v1-v8, ip, lr}
	RET

### Compute r ≡ a⁻¹ mod sm2_p.
# void ECP_Sm2FpInv(Sm2Fp r, const Sm2Fp q);
# Note: Binary algorithm for inversion.
#   u = a, v = p, a = 1, c = 0
#   While(u > 0)
#       While(u is even)
#           u = u >> 1, a = a / 2 mod p
#       While(v is even)
#           v = v >> 1, c = c / 2 mod p
#       If (u >= v)
#           u = u - v, a = a - c mod p
#       Else
#           v = v - u, c = c - a mod p
#   return c
.global ECP_Sm2FpInv
.type   ECP_Sm2FpInv, %function
ECP_Sm2FpInv:
	PUSH {v1-v8, ip, lr}
	PUSH {r0}
	LDM r1, {v1-v8}
	SUB sp, sp, #0x80
	ADD r0, sp, #0x00
	ADD r1, sp, #0x20
	ADD r2, sp, #0x40
	ADD r3, sp, #0x60
	STM r0, {v1-v8}
    VLDR sm2_p1, sm2_p2, sm2_p3, sm2_p4, sm2_p5, sm2_p6, sm2_p7, sm2_p8
    STM r1, {v1-v8}
    VLDR 1, 0, 0, 0, 0, 0, 0, 0
    STM r2, {v1-v8}
    MOV v1, 0
    STM r3, {v1-v8}

	## while u >= 1 do inv_loop
 	.Lfp_inv_while:
	LDR v1, [r0]
	TEQ v1, #0
	BNE .Lfp_inv_loop
	LDM r0, {v1-v8}
	TEQ v2, #0
	BNE .Lfp_inv_loop
	TEQ v3, #0
	BNE .Lfp_inv_loop
	TEQ v4, #0
	BNE .Lfp_inv_loop
	TEQ v5, #0
	BNE .Lfp_inv_loop
	TEQ v6, #0
	BNE .Lfp_inv_loop
	TEQ v7, #0
	BNE .Lfp_inv_loop
	TEQ v8, #0
	BNE .Lfp_inv_loop
	B .Lfp_inv_end

	.Lfp_inv_loop:
	## while u is even, u = u >> 1, a = a / 2 mod p,
	.Lfp_inv_u_loop:
	LDR v1, [r0]
	TST v1, #1
	BNE .Lfp_inv_v_loop
	LDM r0, {v1-v8}
	VLSR
	STM r0, {v1-v8}
	LDM r2, {v1-v8}
    VHAF sm2_p
    STM r2, {v1-v8}
	B .Lfp_inv_u_loop

	## while v is even, v = v >> 1, c = c / 2 mod p
	.Lfp_inv_v_loop:
	LDR v1, [r1]
	TST v1, #1
	BNE .Lfp_inv_update_uv
	LDM r1, {v1-v8}
	VLSR
	STM r1, {v1-v8}
	LDM r3, {v1-v8}
    VHAF sm2_p
    STM r3, {v1-v8}
	B .Lfp_inv_v_loop

	## if u >= v, u = u - v, a = a - c mod p, else v = v - u, c = c - a mod p
	.Lfp_inv_update_uv:
	PSUB r0, r1
	BCC .Lfp_v_is_bigger

	.Lfp_u_is_bigger:
	STM r0, {v1-v8}
	PSUB r2, r3
    VMOD sm2_p
    STM r2, {v1-v8}
	B .Lfp_inv_while

	.Lfp_v_is_bigger:
    VNEG
	STM r1, {v1-v8}
	PSUB r3, r2
    VMOD sm2_p
    STM r3, {v1-v8}
	B .Lfp_inv_while

	.Lfp_inv_end:
	ADD sp, sp, #0x80
	POP {r0}
	LDM r3, {v1-v8}
	STM r0, {v1-v8}
	POP {v1-v8}
	RET

### Compute r ≡ a + b mod sm2_n.
# void ECP_Sm2FnAdd(Sm2Fp r, const Sm2Fp a, const Sm2Fp b);
.global ECP_Sm2FnAdd
.type   ECP_Sm2FnAdd, %function
ECP_Sm2FnAdd:
	PUSH {v1-v8}
	LDM r2, {v1-v8}
	LDR r2, [r1, #0x00]
	LDR r3, [r1, #0x04]
	ADDS v1, r2
	ADCS v2, r3
	LDR r2, [r1, #0x08]
	LDR r3, [r1, #0x0C]
	ADCS v3, r2
	ADCS v4, r3
	LDR r2, [r1, #0x10]
	LDR r3, [r1, #0x14]
	ADCS v5, r2
	ADCS v6, r3
	LDR r2, [r1, #0x18]
	LDR r3, [r1, #0x1C]
	ADCS v7, r2
	ADCS v8, r3
	BCC 0f
	LDR r2, =sm2_m1
	LDR r3, =sm2_m2
	ADDS v1, r2
	ADCS v2, r3
	LDR r2, =sm2_m3
	LDR r3, =sm2_m4
	ADCS v3, r2
	ADCS v4, r3
	ADCS v5, #sm2_m5
	ADCS v6, #sm2_m6
	ADCS v7, #sm2_m7
	ADCS v8, #sm2_m8
 0: STM r0, {v1-v8}
	POP {v1-v8}
	RET

### Compute r ≡ a - b mod sm2_n.
# void ECP_Sm2FnSub(Sm2Fp r, const Sm2Fp a, const Sm2Fp b);
.global ECP_Sm2FnSub
.type   ECP_Sm2FnSub, %function
ECP_Sm2FnSub:
	PUSH {v1-v8}
	LDM r1, {v1-v8}
	LDR r1, [r2, #0x00]
	LDR r3, [r2, #0x04]
	SUBS v1, r1
	SBCS v2, r3
	LDR r1, [r2, #0x08]
	LDR r3, [r2, #0x0C]
	SBCS v3, r1
	SBCS v4, r3
	LDR r1, [r2, #0x10]
	LDR r3, [r2, #0x14]
	SBCS v5, r1
	SBCS v6, r3
	LDR r1, [r2, #0x18]
	LDR r3, [r2, #0x1C]
	SBCS v7, r1
	SBCS v8, r3
	BCS 0f
	LDR r2, =sm2_m1
	LDR r3, =sm2_m2
	SUBS v1, r2
	SBCS v2, r3
	LDR r2, =sm2_m3
	LDR r3, =sm2_m4
	SBCS v3, r2
	SBCS v4, r3
	SBCS v5, #sm2_m5
	SBCS v6, #sm2_m6
	SBCS v7, #sm2_m7
	SBCS v8, #sm2_m8
 0: STM r0, {v1-v8}
	POP {v1-v8}
	RET

### Compute r ≡ a * b mod sm2_n.
# void ECP_Sm2FnMul(sm2_fp r, const sm2_fp a, const sm2_fp b);

## Step of computing r ≡ a * b mod sm2_n by using Barrett Reduction:
# 1. compute c = a * b.
# 2. compute d = (c >> 256) * u, where u = 2^512 / sm2_n = 0x1000000010000000100000001000000018DFC2096FA323C0112AC6361F15149A0.
# 3. compute e = (d >> 256) * sm2_n.
# 4. compute r = c - e, one only needs to calculate the lower 32*9 bits because all bits above 288 are 0.
# 5. compute r = r mod sm2_n.
## Note that since u is 257 bits, the storage of d and e uses 32 * 17 = 544 bits.

## The 0xE8 bytes of stack space allocated in the ECP_Sm2FnMul function are stored as follows:
    # 0x00 : a0 a1 a2 a3 a4 a5 a6 a7
    # 0x20 : c0 c1 c2 c3 c4 c5 c6 c7
    # 0x40 : c8 c9 ca cb cc cd ce cf
    # 0x60 : d0 d1 d2 d3 d4 d5 d6 d7
    # 0x80 : d8 d9 da db dc dd de df dg
    # 0xA4 : e0 e1 e2 e3 e4 e5 e6 e7
    # 0xC4 : e8 e9 ea eb ec ee ee ef eg
.global ECP_Sm2FnMul
.type   ECP_Sm2FnMul, %function
ECP_Sm2FnMul:
	PUSH {v1-v8, ip, lr}
	PUSH {r0}

	# Allocate stack space, load and store a, .
    SUB sp, #0xE8
	LDM r1, {v1-v8}
	STM sp, {v1-v8}

	# load b in V and compute c = a * b.
	LDM r2, {v1-v8}
    MULIT oft 0x0 0x20 0
    MULIT oft 0x0 0x20 1
    MULIT oft 0x0 0x20 2
    MULIT oft 0x0 0x20 3
    MULIT oft 0x0 0x20 4
    MULIT oft 0x0 0x20 5
    MULIT oft 0x0 0x20 6
    MULIT oft 0x0 0x20 7

    # load c >> 256 in V and compute d = (c >> 256) * u
    ADDS ip, sp, #0x40
    LDM ip, {v1-v8}
    MULIT imm 0xF15149A0 0x60 0
    MULIT imm 0x12AC6361 0x60 1
    MULIT imm 0xFA323C01 0x60 2
    MULIT imm 0x8DFC2096 0x60 3
    MULIT imm 0x00000001 0x60 4
    MULIT imm 0x00000001 0x60 5
    MULIT imm 0x00000001 0x60 6
    MULIT imm 0x00000001 0x60 7
    MULIT imm 0x00000001 0x60 8

    # load sm2_n in V and compute e = (d >> 256) * sm2_n.
    VLDR sm2_n1, sm2_n2, sm2_n3, sm2_n4, sm2_n5, sm2_n6, sm2_n7, sm2_n8
    MULIT oft 0x80 0xA4 0
    MULIT oft 0x80 0xA4 1
    MULIT oft 0x80 0xA4 2
    MULIT oft 0x80 0xA4 3
    MULIT oft 0x80 0xA4 4
    MULIT oft 0x80 0xA4 5
    MULIT oft 0x80 0xA4 6
    MULIT oft 0x80 0xA4 7
    MULIT oft 0x80 0xA4 8

	# compute r = c - e
	ADDS r0, sp, #0x20
	ADDS r1, sp, #0xA4
 	LDM r0!, {v1-v4}
 	LDM r1!, {v5-v8}
 	SUBS v1, v5
 	SBCS v2, v6
 	SBCS v3, v7
 	SBCS v4, v8
 	LDM r0, {v5-v8, ip}
 	LDM r1, {r0-r3, lr}
 	SBCS v5, r0
 	SBCS v6, r1
 	SBCS v7, r2
 	SBCS v8, r3
 	SBCS ip, lr

 	# compute r = r mod sm2_n: while(r >= sm2_n){ r = r - sm2_n}
 	LDR r0, =sm2_n1
    LDR r1, =sm2_n2
    LDR r2, =sm2_n3
    LDR r3, =sm2_n4
 0: TEQ ip, #0
    BEQ 1f
    SUBS v1, r0
    SBCS v2, r1
    SBCS v3, r2
    SBCS v4, r3
	SBCS v5, sm2_n5
	SBCS v6, sm2_n6
	SBCS v7, sm2_n7
	SBCS v8, sm2_n8
	SBCS ip, #0
    TEQ ip, #0
    BNE 0b
 1: CMP v8, #sm2_n8
	BCC 3f
 	BHI 2f
 	CMP v7, #sm2_n7
	BCC 3f
 	BHI 2f
	CMP v6, #sm2_n6
	BCC 3f
 	BHI 2f
	CMP v5, #sm2_n5
	BCC 3f
 	BHI 2f
	CMP v4, r3
	BCC 3f
 	BHI 2f
	CMP v3, r2
	BCC 3f
 	BHI 2f
	CMP v2, r1
	BCC 3f
 	BHI 2f
	CMP v1, r0
	BCC 3f
 2: SUBS v1, r0
    SBCS v2, r1
    SBCS v3, r2
    SBCS v4, r3
    SBCS v5, #sm2_n5
    SBCS v6, #sm2_n6
    SBCS v7, #sm2_n7
    SBCS v8, #sm2_n8
 3: ADDS sp, #0xE8
    POP {r0}
    STM r0, {v1-v8}
    POP {v1-v8, ip, lr}
    RET

### Compute r ≡ a^(-1) mod sm2_n.
# void ECP_Sm2FnInv(Sm2Fp r, const Sm2Fp q);
.global ECP_Sm2FnInv
.type   ECP_Sm2FnInv, %function
ECP_Sm2FnInv:
	PUSH {v1-v8, ip, lr}
	PUSH {r0}
	# u = input, v = n, a = 1, c = 0
	LDM r1, {v1-v8}
	SUBS sp, sp, #0x80
	ADDS r0, sp, #0x00
	ADDS r1, sp, #0x20
	ADDS r2, sp, #0x40
	ADDS r3, sp, #0x60
	STM r0, {v1-v8}
    VLDR sm2_n1, sm2_n2, sm2_n3, sm2_n4, sm2_n5, sm2_n6, sm2_n7, sm2_n8
    STM r1, {v1-v8}
    VLDR 1, 0, 0, 0, 0, 0, 0, 0
    STM r2, {v1-v8}
    MOV v1, 0
    STM r3, {v1-v8}

	## while u >= 1 do inv_loop
 	.Lfn_inv_while:
	LDR v1, [r0]
	TEQ v1, #0
	BNE .Lfn_inv_loop
	LDM r0, {v1-v8}
	TEQ v2, #0
	BNE .Lfn_inv_loop
	TEQ v3, #0
	BNE .Lfn_inv_loop
	TEQ v4, #0
	BNE .Lfn_inv_loop
	TEQ v5, #0
	BNE .Lfn_inv_loop
	TEQ v6, #0
	BNE .Lfn_inv_loop
	TEQ v7, #0
	BNE .Lfn_inv_loop
	TEQ v8, #0
	BNE .Lfn_inv_loop
	B .Lfn_inv_end

	.Lfn_inv_loop:

	## while u is even, u = u >> 1, a = a / 2 mod n

	.Lfn_inv_u_loop:
	LDR v1, [r0]
	TST v1, #1
	BNE .Lfn_inv_v_loop
	LDM r0, {v1-v8}
	VLSR
	STM r0, {v1-v8}
	LDM r2, {v1-v8}
	VHAF sm2_n
    STM r2, {v1-v8}
	B .Lfn_inv_u_loop

	## while v is even, v = v >> 1, c = c / 2 mod n
	.Lfn_inv_v_loop:
	LDR v1, [r1]
	TST v1, #1
	BNE .Lfn_inv_update_uv
	LDM r1, {v1-v8}
	VLSR
	STM r1, {v1-v8}
	LDM r3, {v1-v8}
    VHAF sm2_n
    STM r3, {v1-v8}
	B .Lfn_inv_v_loop

	## if u >= v, u = u - v, a = a - c mod n, else v = v - u, c = c - a mod n
	.Lfn_inv_update_uv:
	PSUB r0, r1
	BCC .Lfn_v_is_bigger

	.Lfn_u_is_bigger:
	STM r0, {v1-v8}
	PSUB r2, r3
    VMOD sm2_n
    STM r2, {v1-v8}
	B .Lfn_inv_while

	.Lfn_v_is_bigger:
    VNEG
	STM r1, {v1-v8}
	PSUB r3, r2
    VMOD sm2_n
    STM r3, {v1-v8}
	B .Lfn_inv_while

	.Lfn_inv_end:
	ADDS sp, sp, #0x80
	POP {r0}
	LDM r3, {v1-v8}
	STM r0, {v1-v8}
	POP {v1-v8, ip, lr}
	RET
.end
#endif