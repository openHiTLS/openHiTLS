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
 * ARMv7 assembly optimization for SM3:
 *   Contributors: Zhao Runchen, Li Xukai, Wang Weijia
 *   Affiliation: Shandong University and Quan Cheng Laboratory
 *   Date: 2025.7.10
 *
 * -----------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM3
.syntax unified
.arch armv7
.thumb

// State update function for 0~15 rounds, sp register points to the message w[i], r0 is the constant 0x79cc4519
.macro RF0 a b c d e f g h i
    LDR r1, [sp], #0x04                         // r1 = w[i]
    LDR r2, [sp, #0x0C]                         // r2 = w[i+4]
    EOR r2, r1                                  // r2 = w[i] ^ w[i+4]
    ADD \h, r1                                  // h += w[i]                (r1 is free now)
    ADD \d, r2                                  // d += w[i] ^ w[i + 4]     (r2 is free now)

	ADD r1, \e, r0, ROR #(32-\i%32)%32          // r1 = ss1 = ((a <<< 12) + e + T[i]) <<< 7
    ADD r1, r1, \a, ROR #20
    ROR r1, #25

    EOR r3, \e, \f                              // h += (e ^ f ^ g) + ss1
    EOR r3, \g
    ADD \h, r3
    ADD \h, r1

    EOR r3, \h, \h, ROR #23                     // h = h ^ (h <<< 9) ^ (h <<< 17)
    EOR \h, r3, \h, ROR #15

    EOR r2, r1, \a, ROR #20                     // r2 = ss2 = (a <<< 12) ^ ss1
    EOR r3, \a, \b                              // d += (a ^ b ^ c)+ ss2
    EOR r3, \c
    ADD \d, r3
	ADD \d, r2

    ROR \b, #23                                 // b = b <<< 9, f = f <<< 19
    ROR \f, #13
.endm

// State update function for rounds 16~63, sp register points to the message w[i], r0 is the constant 0x7a879d8a
.macro RF1 a b c d e f g h i
    LDR r1, [sp], #0x04                         // r1 = w[i]
    LDR r2, [sp, #0x0C]                         // r2 = w[i+4]
    EOR r2, r1                                  // r2 = w[i] ^ w[i+4]
    ADD \h, r1                                  // h += w[i]                (r1 is free now)
    ADD \d, r2                                  // d += w[i] ^ w[i + 4]     (r2 is free now)

	ADD r1, \e, r0, ROR #(32-\i%32)%32          // r1 = ss1 = ((a <<< 12) + e + T[i]) <<< 7
    ADD r1, r1, \a, ROR #20
    ROR r1, #25

	EOR r3, \f, \g                              // h += (e & f) | (~e & g) + ss1 = ((f ^ g) & e) ^ g + ss1
    AND r3, \e
    EOR r3, \g
    ADD \h, r3
	ADD \h, r1

    EOR r3, \h, \h, ROR #23                     // h = P0(h) = h ^ (h <<< 9) ^ (h <<< 17)
    EOR \h, r3, \h, ROR #15

    EOR r2, r1, \a, ROR #20                     // ss2 = (a <<< 12) ^ ss1   (r1 is free now)
    EOR r3, \b, \c                              // d += ((a & b) | (a & c) | (b & c)) + ss2  = (a & (b | c)) | ((b & c)) + ss2
    AND r3, \a
    AND r1, \b, \c
    EOR r3, r1
    ADD \d, r3
    ADD \d, r2

    ROR \b, #23                                 // b = b <<< 9, f = f <<< 19
    ROR \f, #13
.endm

// Message expansion: w[i+16] = P1(w[i] ^ w[i+7] ^ (w[i+13] <<< 15)) ^ (w[i+3] <<< 7) ^ w[i+10]
// P1(x) = x ^ x <<< 15 ^ x <<< 23 = x ^ x >>> 17 ^ x >>> 9
// Since the width of the sliding registers (w0-w13) is 14, there are no additional registers available for calculating P1(x).
// Therefore, w7 will be used as a temporary register here and restored from memory later.
// We hope you can have a better way to avoid reading the memory one more time.

.macro MSGEXP w0 w3 w7 w10 w13 i
    LDR \w13, [sp, #((13 + \i) << 2)]
    EOR \w0, \w0, \w7
    EOR \w0, \w0, \w13, ROR #17
    EOR \w7, \w0, \w0,  ROR #17
    EOR \w0, \w7, \w0,  ROR #9
    EOR \w0, \w0, \w3,  ROR #25
    EOR \w0, \w10
    LDR \w7, [sp, #((7 + \i) << 2)]
    STR \w0, [sp, #((16 + \i) << 2)]
.endm

// void SM3_CompressAsm(uint32_t state[8], const uint8_t *data, uint32_t blockCnt);
.globl SM3_CompressAsm
.type  SM3_CompressAsm, %function
.align 4
SM3_CompressAsm:
    PUSH {v1-ip, lr}
	.Lloop_start:
	SUBS r2, r2, 1
	BCC .Lloop_end
	PUSH {r0-r2}
    SUB sp, sp, #(52<<2)
    ADD r1, #0x40
    LDR v3, [r1, #-4]!
    LDR v2, [r1, #-4]!
    LDR v1, [r1, #-4]!
    REV v1, v1
    REV v2, v2
    REV v3, v3
    PUSH {v1-v3}
    LDR r12, [r1, #-4]!
    LDR r11, [r1, #-4]!
    LDR r10, [r1, #-4]!
    LDR r9, [r1, #-4]!
    LDR r8, [r1, #-4]!
    LDR r7, [r1, #-4]!
    LDR r6, [r1, #-4]!
    LDR r5, [r1, #-4]!
    LDR r4, [r1, #-4]!
    LDR r3, [r1, #-4]!
    LDR r2, [r1, #-4]!
    LDR r0, [r1, #-8]!
    LDR r1, [r1, #4]
    REV r0, r0
    REV r1, r1
    REV r2, r2
    REV r3, r3
    REV r4, r4
    REV r5, r5
    REV r6, r6
    REV r7, r7
    REV r8, r8
    REV r9, r9
    REV r10, r10
    REV r11, r11
    REV r12, r12
    PUSH {r0-r12}
    MSGEXP r0  r3  r7  r10 r14 0
    MSGEXP r1  r4  r8  r11 r0  1
    MSGEXP r2  r5  r9  r12 r1  2
    MSGEXP r3  r6  r10 r14 r2  3
    MSGEXP r4  r7  r11 r0  r3  4
    MSGEXP r5  r8  r12 r1  r4  5
    MSGEXP r6  r9  r14 r2  r5  6
    MSGEXP r7  r10 r0  r3  r6  7
    MSGEXP r8  r11 r1  r4  r7  8
    MSGEXP r9  r12 r2  r5  r8  9
    MSGEXP r10 r14 r3  r6  r9  10
    MSGEXP r11 r0  r4  r7  r10 11
    MSGEXP r12 r1  r5  r8  r11 12
    MSGEXP r14 r2  r6  r9  r12 13
    MSGEXP r0  r3  r7  r10 r14 14
    MSGEXP r1  r4  r8  r11 r0  15
    MSGEXP r2  r5  r9  r12 r1  16
    MSGEXP r3  r6  r10 r14 r2  17
    MSGEXP r4  r7  r11 r0  r3  18
    MSGEXP r5  r8  r12 r1  r4  19
    MSGEXP r6  r9  r14 r2  r5  20
    MSGEXP r7  r10 r0  r3  r6  21
    MSGEXP r8  r11 r1  r4  r7  22
    MSGEXP r9  r12 r2  r5  r8  23
    MSGEXP r10 r14 r3  r6  r9  24
    MSGEXP r11 r0  r4  r7  r10 25
    MSGEXP r12 r1  r5  r8  r11 26
    MSGEXP r14 r2  r6  r9  r12 27
    MSGEXP r0  r3  r7  r10 r14 28
    MSGEXP r1  r4  r8  r11 r0  29
    MSGEXP r2  r5  r9  r12 r1  30
    MSGEXP r3  r6  r10 r14 r2  31
    MSGEXP r4  r7  r11 r0  r3  32
    MSGEXP r5  r8  r12 r1  r4  33
    MSGEXP r6  r9  r14 r2  r5  34
    MSGEXP r7  r10 r0  r3  r6  35
    MSGEXP r8  r11 r1  r4  r7  36
    MSGEXP r9  r12 r2  r5  r8  37
    MSGEXP r10 r14 r3  r6  r9  38
    MSGEXP r11 r0  r4  r7  r10 39
    MSGEXP r12 r1  r5  r8  r11 40
    MSGEXP r14 r2  r6  r9  r12 41
    MSGEXP r0  r3  r7  r10 r14 42
    MSGEXP r1  r4  r8  r11 r0  43
    MSGEXP r2  r5  r9  r12 r1  44
    MSGEXP r3  r6  r10 r14 r2  45
    MSGEXP r4  r7  r11 r0  r3  46
    MSGEXP r5  r8  r12 r1  r4  47
    MSGEXP r6  r9  r14 r2  r5  48
    MSGEXP r7  r10 r0  r3  r6  49
    MSGEXP r8  r11 r1  r4  r7  50
    MSGEXP r9  r12 r2  r5  r8  51
    // Load the state.
    LDR r0, =0x79cc4519
    LDR r1, [sp, #(68 << 2)]
    LDM r1, {v1-v8}
    // Note: Since the LDR offset relative to the current PC value cannot exceed 4KB in ARMV7,
    // and there are approximately 2000 lines of instructions inside this function that are out of the offset range,
    // we declare the literal pool here and skip it.
    B 1f
    .ltorg
1:  // 0-15
    RF0 v1 v2 v3 v4 v5 v6 v7 v8 0
    RF0 v4 v1 v2 v3 v8 v5 v6 v7 1
    RF0 v3 v4 v1 v2 v7 v8 v5 v6 2
    RF0 v2 v3 v4 v1 v6 v7 v8 v5 3
    RF0 v1 v2 v3 v4 v5 v6 v7 v8 4
    RF0 v4 v1 v2 v3 v8 v5 v6 v7 5
    RF0 v3 v4 v1 v2 v7 v8 v5 v6 6
    RF0 v2 v3 v4 v1 v6 v7 v8 v5 7
    RF0 v1 v2 v3 v4 v5 v6 v7 v8 8
    RF0 v4 v1 v2 v3 v8 v5 v6 v7 9
    RF0 v3 v4 v1 v2 v7 v8 v5 v6 10
    RF0 v2 v3 v4 v1 v6 v7 v8 v5 11
    RF0 v1 v2 v3 v4 v5 v6 v7 v8 12
    RF0 v4 v1 v2 v3 v8 v5 v6 v7 13
    RF0 v3 v4 v1 v2 v7 v8 v5 v6 14
    RF0 v2 v3 v4 v1 v6 v7 v8 v5 15
    // 16-31
    LDR r0 , =0x7a879d8a
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 16
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 17
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 18
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 19
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 20
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 21
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 22
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 23
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 24
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 25
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 26
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 27
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 28
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 29
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 30
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 31
    // 32-47
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 32
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 33
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 34
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 35
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 36
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 37
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 38
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 39
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 40
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 41
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 42
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 43
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 44
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 45
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 46
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 47
    // 48-63
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 48
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 49
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 50
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 51
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 52
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 53
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 54
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 55
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 56
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 57
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 58
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 59
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 60
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 61
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 62
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 63
    // Load the state back and update it.
    ADD sp, sp, #16
    LDR ip, [sp]
    LDM ip!, {r0-r3}
    EOR v1, r0
    EOR v2, r1
    EOR v3, r2
    EOR v4, r3
    LDM ip!, {r0-r3}
    EOR v5, r0
    EOR v6, r1
    EOR v7, r2
    EOR v8, r3
    STMDB ip, {v1-v8}
    POP {r0-r2}
    ADD r1, r1, #0x40
	B .Lloop_start
	.Lloop_end:
    POP {v1-ip, lr}
    MOV pc, lr
.end
#endif