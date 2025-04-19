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
#ifdef HITLS_CRYPTO_SHA3

#include "crypt_arm.h"
.arch    armv8-a+crypto

/*
 * Status matrix using register aliases
 * A00~A04: x0~x4
 * A10~A14: x5~x9
 * A20~A24: x10~x14
 * A30~A34: x15~x19
 * A40~A44: x20~x24
 * T0~T4: x25~x29 temporary calculation register
 */
A00 .req x0
A01 .req x1
A02 .req x2
A03 .req x3
A04 .req x4
A10 .req x5
A11 .req x6
A12 .req x7
A13 .req x8
A14 .req x9
A20 .req x10
A21 .req x11
A22 .req x12
A23 .req x13
A24 .req x14
A30 .req x15
A31 .req x16
A32 .req x17
A33 .req x18
A34 .req x19
A40 .req x20
A41 .req x21
A42 .req x22
A43 .req x23
A44 .req x24

T0  .req x25
T1  .req x26
T2  .req x27
T3  .req x28
T4  .req x29

/**
 *  Macro Description: THETA mapping function
 *  Input register:
 *      A00~A44: x0~x24 State Matrix
 *        T0~T4: x25~x29 temporary calculation register
 *  Modify the register:
 *      A00~A44: x0~x24 State Matrix
 *        T0~T4: x25~x29 temporary calculation register
 *  Output register:
 *      A00~A44: x0~x24 The latest State Matrix, among them, The values of A10, A20, A30,
 *               and A40 are temporarily stored by T0, T1, T2, T3.
 *        T0~T3: x25 to x29 temporarily store the values of A10, A20, A30, and A40.
 *  Function/Macro Call: None
 */
.macro  THETA
    // for x in 0…4, C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4]
    eor T0, A00, A10
    eor T1, A01, A11
    eor T2, A02, A12
    eor T3, A03, A13
    eor T4, A04, A14

    stp A00, A10, [sp, #-16]!   // Borrow A00 and A10

    eor T0, T0, A20
    eor T1, T1, A21
    eor T2, T2, A22
    eor T3, T3, A23
    eor T4, T4, A24

    eor T0, T0, A30
    eor T1, T1, A31
    eor T2, T2, A32
    eor T3, T3, A33
    eor T4, T4, A34

    eor T0, T0, A40
    eor T1, T1, A41
    eor T2, T2, A42
    eor T3, T3, A43
    eor T4, T4, A44

    // D[1] = C[0] xor rol(C[2],1)
    eor A00, T0, T2, ror#63     // Borrow A00
    // D[2] = C[1] xor rol(C[3],1)
    eor A10, T1, T3, ror#63     // Borrow A10

    // for y in 0…4, A[y][1] ^= D[1]
    eor A01, A01, A00
    eor A11, A11, A00
    eor A21, A21, A00
    eor A31, A31, A00
    eor A41, A41, A00

    // D[3] = C[2] xor rol(C[4],1)
    eor T2, T2, T4, ror#63

    // for y in 0…4, A[y][2] ^= D[2]
    eor A02, A02, A10
    eor A12, A12, A10
    eor A22, A22, A10
    eor A32, A32, A10
    eor A42, A42, A10

    // D[4] = C[3] xor rol(C[0],1)
    eor T3, T3, T0, ror#63

    // for y in 0…4, A[y][3] ^= D[3]
    eor A03, A03, T2
    eor A13, A13, T2
    eor A23, A23, T2
    eor A33, A33, T2
    eor A43, A43, T2

    ldp A00, A10, [sp], #16   // Restore A00 and A10

    // D[0] = C[4] xor rol(C[1],1)
    eor T4, T4, T1, ror#63

    // for y in 0…4, A[y][4] ^= D[4]
    eor A04, A04, T3
    eor A14, A14, T3
    eor A24, A24, T3
    eor A34, A34, T3
    eor A44, A44, T3

    // for y in 0…4, A[y][0] ^= D[0]
    eor A00, A00, T4
    eor T0, A10, T4     // Store A10, A20, A30, and A40 in the rho phase in advance.
    eor T1, A20, T4
    eor T2, A30, T4
    eor T3, A40, T4
.endm

/**
 *  Macro Description: RHO mapping function and PI mapping function
 *  Input register:
 *      A00~A44: x0~x24 State Matrix among them, The values of A10, A20, A30, and A40 are temporarily stored by T0,
 *               T1, T2, T3 in the THETA function.
 *        T0~T3: x25 to x28: temporarily store the values of A10, A20, A30, and A40.
 *  Modify the register:
 *      A00~A44: x0~x24 State Matrix
 *  Output register:
 *      A00~A44: x0~x24 The latest State Matrix
 *  Function/Macro Call: None
 *  Implementation part:
 *             for x in 0…4: for y in 0…4: A[x, y] = rol(A[y,3x+y], rhotates[y,3x+y])
 */
.macro  RHOPi
    ror A10, A03, #64-28
    ror A20, A01, #64-1
    ror A30, A04, #64-27
    ror A40, A02, #64-62

    ror A01, A11, #64-44
    ror A02, A22, #64-43
    ror A03, A33, #64-21
    ror A04, A44, #64-14

    ror A11, A14, #64-20
    ror A22, A23, #64-25
    ror A33, A32, #64-15
    ror A44, A41, #64-2

    ror A14, A42, #64-61
    ror A23, A34, #64-8
    ror A32, A21, #64-10
    ror A41, A13, #64-55

    ror A42, A24, #64-39
    ror A34, A43, #64-56
    ror A21, A12, #64-6
    ror A13, A31, #64-45

    ror A24, T3, #64-18
    ror A43, T2, #64-41
    ror A12, T1, #64-3
    ror A31, T0, #64-36
.endm

/**
 *  Macro Description: CHI mapping function与IOTA mapping function
 *  Input register:
 *      A00~A44: x0~x24 State Matrix
 *        T0~T3: x25~x28 temporary calculation register
 *  Modify the register:
 *      A00~A44: x0~x24 State Matrix
 *        T0~T3: x25~x28 temporary calculation register
 *  Output register:
 *      A00~A44: x0~x24 The latest State Matrix
 *  Function/Macro Call: None
 *  Implementation part:
 *      for x in 0…4: for y in 0…4: A[x, y] ^= not A[x, y+1] and A[x, y+2]
 *      if x,y = 0,0: A[x, y] = A[x, y] xor iotas[i]
 */
.macro  CHIOTA offset
    // for y in 0…4: A[0, y] ^= not A[0, y+1] and A[0, y+2]
    bic T0, A02, A01
    bic T1, A01, A00
    bic T2, A00, A04
    bic T3, A03, A02
    eor A00, A00, T0
    eor A01, A01, T3
    bic T0, A04, A03
    eor A02, A02, T0
    eor A03, A03, T2
    eor A04, A04, T1

#ifdef __ILP32__
    ldr w25, =g_roundConstant
#else
    ldr x25, =g_roundConstant       // x25 === T0
#endif
    ldr T3, [x25, \offset*8]
    eor A00, A00, T3                // iota: A[0, 0] = A[0, 0] xor iotas[i]

    // for y in 0…4: A[1, y] ^= not A[1, y+1] and A[1, y+2]
    bic T0, A12, A11
    bic T1, A11, A10
    bic T2, A10, A14
    bic T3, A13, A12
    eor A10, A10, T0
    eor A11, A11, T3
    bic T0, A14, A13
    eor A12, A12, T0
    eor A13, A13, T2
    eor A14, A14, T1

    // for y in 0…4: A[2, y] ^= not A[2, y+1] and A[2, y+2]
    bic T0, A22, A21
    bic T1, A21, A20
    bic T2, A20, A24
    bic T3, A23, A22
    eor A20, A20, T0
    eor A21, A21, T3
    bic T0, A24, A23
    eor A22, A22, T0
    eor A23, A23, T2
    eor A24, A24, T1

    // for y in 0…4: A[3, y] ^= not A[3, y+1] and A[3, y+2]
    bic T0, A32, A31
    bic T1, A31, A30
    bic T2, A30, A34
    bic T3, A33, A32
    eor A30, A30, T0
    eor A31, A31, T3
    bic T0, A34, A33
    eor A32, A32, T0
    eor A33, A33, T2
    eor A34, A34, T1

    // for y in 0…4: A[4, y] ^= not A[4, y+1] and A[4, y+2]
    bic T0, A42, A41
    bic T1, A41, A40
    bic T2, A40, A44
    bic T3, A43, A42
    eor A40, A40, T0
    eor A41, A41, T3
    bic T0, A44, A43
    eor A42, A42, T0
    eor A43, A43, T2
    eor A44, A44, T1
.endm

/**
 *  Macro Description: Round of phase mapping
 *  Input register:
 *      A00~A44: x0~x24 State Matrix
 *        T0~T4: x25~x29 temporary calculation register
 *  Modify the register:
 *      A00~A44: x0~x24 State Matrix
 *        T0~T4: x25~x29 temporary calculation register
 *  Output register:
 *      A00~A44: The latest State Matrix
 *  Function/Macro Call: THETA RHOPi CHIOTA
 */
.macro  ROUND offset
    THETA
    RHOPi
    CHIOTA \offset
.endm

.macro Keccak
    /* The length of the digest after extrusion is greater than r. Then, the digest is mapped and then extruded. */
    stp x25, x26, [sp, #-32]!
    stp x27, x28, [sp, #8*2]
    /* Load states: x0~x24 */
    ldp A00, A01, [x25]
    ldp A02, A03, [x25, #16]
    ldp A04, A10, [x25, #16*2]
    ldp A11, A12, [x25, #16*3]
    ldp A13, A14, [x25, #16*4]
    ldp A20, A21, [x25, #16*5]
    ldp A22, A23, [x25, #16*6]
    ldp A24, A30, [x25, #16*7]
    ldp A31, A32, [x25, #16*8]
    ldp A33, A34, [x25, #16*9]
    ldp A40, A41, [x25, #16*10]
    ldp A42, A43, [x25, #16*11]
    ldr A44, [x25, #16*12]
    /* Mapping */
    ROUND #0
    ROUND #1
    ROUND #2
    ROUND #3
    ROUND #4
    ROUND #5
    ROUND #6
    ROUND #7
    ROUND #8
    ROUND #9
    ROUND #10
    ROUND #11
    ROUND #12
    ROUND #13
    ROUND #14
    ROUND #15
    ROUND #16
    ROUND #17
    ROUND #18
    ROUND #19
    ROUND #20
    ROUND #21
    ROUND #22
    ROUND #23

    ldp x25, x26, [sp], #8*2
    ldp x27, x28, [sp], #8*2
    /* Store states: x0~x24 */
    stp A00, A01, [x25]
    stp A02, A03, [x25, #8*2]
    stp A04, A10, [x25, #8*4]
    stp A11, A12, [x25, #8*6]
    stp A13, A14, [x25, #8*8]
    stp A20, A21, [x25, #8*10]
    stp A22, A23, [x25, #8*12]
    stp A24, A30, [x25, #8*14]
    stp A31, A32, [x25, #8*16]
    stp A33, A34, [x25, #8*18]
    stp A40, A41, [x25, #8*20]
    stp A42, A43, [x25, #8*22]
    str A44, [x25, #8*24]

    mov     x0, x25
    mov     x3, x28
.endm

.section .rodata
.balign    64
.type    g_roundConstant, %object
g_roundConstant:
    .quad   0x0000000000000001
    .quad   0x0000000000008082
    .quad   0x800000000000808a
    .quad   0x8000000080008000
    .quad   0x000000000000808b
    .quad   0x0000000080000001
    .quad   0x8000000080008081
    .quad   0x8000000000008009
    .quad   0x000000000000008a
    .quad   0x0000000000000088
    .quad   0x0000000080008009
    .quad   0x000000008000000a
    .quad   0x000000008000808b
    .quad   0x800000000000008b
    .quad   0x8000000000008089
    .quad   0x8000000000008003
    .quad   0x8000000000008002
    .quad   0x8000000000000080
    .quad   0x000000000000800a
    .quad   0x800000008000000a
    .quad   0x8000000080008081
    .quad   0x8000000000008080
    .quad   0x0000000080000001
    .quad   0x8000000080008008
    .size   g_roundConstant, .-g_roundConstant

/**
 *  Function description: Perform shA3 absorption according to the input message.
 *  Function prototype: const uint8_t *SHA3_Absorb(uint8_t *state, const uint8_t *in, uinT32_t inLen, uinT32_t r);
 *  Input register:
 *         x0: Pointer to the address of the State Matrix
 *         x1: Pointer to the input data address
 *         x2: Message length
 *         x3: Different shA3 algorithms are executed based on the shA3 parameter r.
 *  Register usage: A00~A44: x0~x24 State Matrix
 *                  T0~T4: x25~x29 temporary calculation register
 *  Output register: x0 Returns the address of the message for which shA3 calculation is not performed.
 *  Function/Macro Call: ROUND
 */

.text
.balign 16
.global SHA3_Absorb
.type   SHA3_Absorb, %function
SHA3_Absorb:
AARCH64_PACIASP
    /* push stack protection */
    stp x29, x30, [sp, #-96]!
    stp x19, x20, [sp, #8*2]
    stp x21, x22, [sp, #8*4]
    stp x23, x24, [sp, #8*6]
    stp x25, x26, [sp, #8*8]
    stp x27, x28, [sp, #8*10]

    stp x0, x1, [sp, #-32]!
    stp x2, x3, [sp, #8*2]
    mov x25, x0
    mov x26, x1
    mov x27, x2
    mov x28, x3

    cmp x2, x3
    blo .Labsorb_end

    /* Load states: x0~x24 */
    ldp A00, A01, [x25]
    ldp A02, A03, [x25, #16]
    ldp A04, A10, [x25, #16*2]
    ldp A11, A12, [x25, #16*3]
    ldp A13, A14, [x25, #16*4]
    ldp A20, A21, [x25, #16*5]
    ldp A22, A23, [x25, #16*6]
    ldp A24, A30, [x25, #16*7]
    ldp A31, A32, [x25, #16*8]
    ldp A33, A34, [x25, #16*9]
    ldp A40, A41, [x25, #16*10]
    ldp A42, A43, [x25, #16*11]
    ldr A44, [x25, #16*12]

.Labsorb:
    /* Absorb from inputs according to r */
    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A00, A00, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A01, A01, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A02, A02, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A03, A03, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A04, A04, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A10, A10, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A11, A11, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A12, A12, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A13, A13, x25

    cmp x28, #72            // SHA3_512: 72=8*9: (x0~x8)
    beq .Labsorb_mapping

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A14, A14, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A20, A20, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A21, A21, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A22, A22, x25

    cmp x28, #104           // SHA3_384: 104=8*13: (x0~x12)
    beq .Labsorb_mapping

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A23, A23, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A24, A24, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A30, A30, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A31, A31, x25

    cmp x28, #136           // SHA3_256: 136=8*17: (x0~x16)
    beq .Labsorb_mapping

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A32, A32, x25

    cmp x28, #144           // SHA3_224: 144=8*18: (x0~x17)
    beq .Labsorb_mapping

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A33, A33, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A34, A34, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A40, A40, x25

    cmp x28, #168           // SHAKE128: 168=8*21: (0~20)
    beq .Labsorb_mapping

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A41, A41, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A42, A42, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A43, A43, x25

    ldr x25, [x26], #8
#ifdef  HITLS_BIG_ENDIAN
    rev x25, x25
#endif
    eor A44, A44, x25

.Labsorb_mapping:
    /* Updating the Input Data Pointer and Length */
    sub x27, x27, x28
    stp x26, x27, [sp, #8]
    /* Mapping */
    ROUND #0
    ROUND #1
    ROUND #2
    ROUND #3
    ROUND #4
    ROUND #5
    ROUND #6
    ROUND #7
    ROUND #8
    ROUND #9
    ROUND #10
    ROUND #11
    ROUND #12
    ROUND #13
    ROUND #14
    ROUND #15
    ROUND #16
    ROUND #17
    ROUND #18
    ROUND #19
    ROUND #20
    ROUND #21
    ROUND #22
    ROUND #23
    ldp x26, x27, [sp, #8]
    ldr x28, [sp, #24]
    cmp x27, x28
    bhs .Labsorb

    /* Store states: x0~x24 */
    ldr x25, [sp]
    stp A00, A01, [x25]
    stp A02, A03, [x25, #8*2]
    stp A04, A10, [x25, #8*4]
    stp A11, A12, [x25, #8*6]
    stp A13, A14, [x25, #8*8]
    stp A20, A21, [x25, #8*10]
    stp A22, A23, [x25, #8*12]
    stp A24, A30, [x25, #8*14]
    stp A31, A32, [x25, #8*16]
    stp A33, A34, [x25, #8*18]
    stp A40, A41, [x25, #8*20]
    stp A42, A43, [x25, #8*22]
    str A44, [x25, #8*24]

.Labsorb_end:
    /* Return the remaining message address. */
    mov x0, x26

    /* End popping */
    add sp, sp, #32             // skip x0~x3
    ldp x29, x30, [sp], #8*2
    ldp x19, x20, [sp], #8*2
    ldp x21, x22, [sp], #8*2
    ldp x23, x24, [sp], #8*2
    ldp x25, x26, [sp], #8*2
    ldp x27, x28, [sp], #8*2
AARCH64_AUTIASP
    ret
.size SHA3_Absorb, .-SHA3_Absorb

.balign 16
/**
 *  Function description: Perform SHA3 squeezing to obtain the digest message.
 *  Function prototyp: void SHA3_Squeeze(uint8_t *state, uint8_t *out, uinT32_t outLen, uinT32_t r, bool isNeedKeccak)
 *  Input register:
 *         x0: Pointer to the address of the State Matrix
 *         x1: Pointer to the output summary address
 *         x2: digist Length
 *         x3: Different SHA3 algorithms are executed based on the SHA3 parameter r.
 *  Register usage: A00~A44: x0~x24 State Matrix
 *                  T0~T4: x25~x29 temporary calculation register
 *  Output register: x1: Pointer to the output summary address
 *  Function/Macro Call: ROUND
 */
.global SHA3_Squeeze
.type   SHA3_Squeeze, %function
SHA3_Squeeze:
AARCH64_PACIASP
    /* push stack protection */
    stp x29, x30, [sp, #-96]!
    stp x19, x20, [sp, #8*2]
    stp x21, x22, [sp, #8*4]
    stp x23, x24, [sp, #8*6]
    stp x25, x26, [sp, #8*8]
    stp x27, x28, [sp, #8*10]

    mov x25, x0
    mov x26, x1
    mov x27, x2
    mov x28, x3
    mov x30, x4

    /* Cyclically squeezing message summaries from the State Matrix */
.Loop_squeeze:
    ldr     x4, [x0], #8
    cmp     x27, #8
    blo     .Lsqueeze_tail      // If the remaining length is less than 8 bytes, perform single-byte extrusion.

#ifdef      HITLS_BIG_ENDIAN
    rev     x4, x4
#endif

    str     x4, [x26], #8       // Perform 8-byte squeeze
    subs    x27, x27, #8
    beq     .Lsqueeze_done

    subs    x3, x3, #8
    bhi     .Loop_squeeze
    Keccak
    b       .Loop_squeeze

    /* Single Byte Squeezing */
.Lsqueeze_tail:
    strb    w4, [x26], #1
    lsr     x4, x4, #8
    subs    x27, x27, #1
    beq     .Lsqueeze_done
    strb    w4, [x26], #1
    lsr     x4, x4, #8
    subs    x27, x27, #1
    beq     .Lsqueeze_done
    strb    w4, [x26], #1
    lsr     x4, x4, #8
    subs    x27, x27, #1
    beq     .Lsqueeze_done
    strb    w4, [x26], #1
    lsr     x4, x4, #8
    subs    x27, x27, #1
    beq     .Lsqueeze_done
    strb    w4, [x26], #1
    lsr     x4, x4, #8
    subs    x27, x27, #1
    beq     .Lsqueeze_done
    strb    w4, [x26], #1
    lsr     x4, x4, #8
    subs    x27, x27, #1
    beq     .Lsqueeze_done
    strb    w4, [x26], #1

.Lsqueeze_done:
    /* End popping */
    cmp x30, 0
    beq .Lsqueeze_end
    Keccak
.Lsqueeze_end:
    ldp x29, x30, [sp], #8*2
    ldp x19, x20, [sp], #8*2
    ldp x21, x22, [sp], #8*2
    ldp x23, x24, [sp], #8*2
    ldp x25, x26, [sp], #8*2
    ldp x27, x28, [sp], #8*2
    eor x0, x0, x0
AARCH64_AUTIASP
    ret
.size SHA3_Squeeze, .-SHA3_Squeeze

#endif
