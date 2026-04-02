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

    adrp x25, g_roundConstant
    add x25, x25, :lo12:g_roundConstant       // x25 === T0

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

/**
 *  Function description: Perform Keccak permutation on the state.
 *  Function prototyp: void SHA3_Keccak(uint8_t *state)
 *  Input register:
 *         x0: Pointer to the address of the State Matrix
 *  Register usage: A00~A44: x0~x24 State Matrix
 *                  T0~T4: x25~x29 temporary calculation register
 *  Output register: None
 *  Function/Macro Call: Keccak
 */
.global SHA3_Keccak
.type   SHA3_Keccak, %function
SHA3_Keccak:
AARCH64_PACIASP
    /* push stack protection */
    stp x29, x30, [sp, #-96]!
    stp x19, x20, [sp, #8*2]
    stp x21, x22, [sp, #8*4]
    stp x23, x24, [sp, #8*6]
    stp x25, x26, [sp, #8*8]
    stp x27, x28, [sp, #8*10]

    mov x25, x0
    Keccak

    ldp x29, x30, [sp], #8*2
    ldp x19, x20, [sp], #8*2
    ldp x21, x22, [sp], #8*2
    ldp x23, x24, [sp], #8*2
    ldp x25, x26, [sp], #8*2
    ldp x27, x28, [sp], #8*2
AARCH64_AUTIASP
    ret
.size SHA3_Keccak, .-SHA3_Keccak


/* ROL: rotate left by n bits for 2D vector */
.macro ROL dst, src, n
    shl     \dst\().2d, \src\().2d, #\n
    sri     \dst\().2d, \src\().2d, #(64 - \n)
.endm

/*
 * KeccakF1600StatePermutex2 - Keccak-f[1600] permutation for two parallel states
 *
 * void KeccakF1600StatePermutex2(Keccakx2State state)
 *   x0: pointer to state array of 25 x uint64x2_t (400 bytes)
 *
 * Register allocation:
 *   v0-v24:  state s[0]-s[24]
 *   v25-v29: temporaries (t0-t4 / C / D)
 *   v30-v31: additional temporaries
 *   x0:      state pointer (preserved in x19)
 *   x1:      round counter
 *   x2:      pointer to round constants
 */
.text
.balign 16
.global KeccakF1600StatePermutex2
.type   KeccakF1600StatePermutex2, %function
KeccakF1600StatePermutex2:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x29, sp

    mov     x19, x0

    ldp     q0,  q1,  [x0]
    ldp     q2,  q3,  [x0, #32]
    ldp     q4,  q5,  [x0, #64]
    ldp     q6,  q7,  [x0, #96]
    ldp     q8,  q9,  [x0, #128]
    ldp     q10, q11, [x0, #160]
    ldp     q12, q13, [x0, #192]
    ldp     q14, q15, [x0, #224]
    ldp     q16, q17, [x0, #256]
    ldp     q18, q19, [x0, #288]
    ldp     q20, q21, [x0, #320]
    ldp     q22, q23, [x0, #352]
    ldr     q24, [x0, #384]

    adrp    x2, g_roundConstant
    add     x2, x2, :lo12:g_roundConstant
    mov     x1, #24

.Lx2_round_loop:
    /* ===== Theta ===== */
    eor     v25.16b, v0.16b,  v5.16b
    eor     v30.16b, v10.16b, v15.16b
    eor     v25.16b, v25.16b, v30.16b
    eor     v25.16b, v25.16b, v20.16b

    eor     v26.16b, v1.16b,  v6.16b
    eor     v30.16b, v11.16b, v16.16b
    eor     v26.16b, v26.16b, v30.16b
    eor     v26.16b, v26.16b, v21.16b

    eor     v27.16b, v2.16b,  v7.16b
    eor     v30.16b, v12.16b, v17.16b
    eor     v27.16b, v27.16b, v30.16b
    eor     v27.16b, v27.16b, v22.16b

    eor     v28.16b, v3.16b,  v8.16b
    eor     v30.16b, v13.16b, v18.16b
    eor     v28.16b, v28.16b, v30.16b
    eor     v28.16b, v28.16b, v23.16b

    eor     v29.16b, v4.16b,  v9.16b
    eor     v30.16b, v14.16b, v19.16b
    eor     v29.16b, v29.16b, v30.16b
    eor     v29.16b, v29.16b, v24.16b

    ROL     v30, v26, 1
    eor     v30.16b, v29.16b, v30.16b
    ROL     v31, v27, 1
    eor     v31.16b, v25.16b, v31.16b

    eor     v0.16b,  v0.16b,  v30.16b
    eor     v5.16b,  v5.16b,  v30.16b
    eor     v10.16b, v10.16b, v30.16b
    eor     v15.16b, v15.16b, v30.16b
    eor     v20.16b, v20.16b, v30.16b

    eor     v1.16b,  v1.16b,  v31.16b
    eor     v6.16b,  v6.16b,  v31.16b
    eor     v11.16b, v11.16b, v31.16b
    eor     v16.16b, v16.16b, v31.16b
    eor     v21.16b, v21.16b, v31.16b

    ROL     v30, v28, 1
    eor     v30.16b, v26.16b, v30.16b

    eor     v2.16b,  v2.16b,  v30.16b
    eor     v7.16b,  v7.16b,  v30.16b
    eor     v12.16b, v12.16b, v30.16b
    eor     v17.16b, v17.16b, v30.16b
    eor     v22.16b, v22.16b, v30.16b

    ROL     v30, v29, 1
    eor     v30.16b, v27.16b, v30.16b

    eor     v3.16b,  v3.16b,  v30.16b
    eor     v8.16b,  v8.16b,  v30.16b
    eor     v13.16b, v13.16b, v30.16b
    eor     v18.16b, v18.16b, v30.16b
    eor     v23.16b, v23.16b, v30.16b

    ROL     v30, v25, 1
    eor     v30.16b, v28.16b, v30.16b

    eor     v4.16b,  v4.16b,  v30.16b
    eor     v9.16b,  v9.16b,  v30.16b
    eor     v14.16b, v14.16b, v30.16b
    eor     v19.16b, v19.16b, v30.16b
    eor     v24.16b, v24.16b, v30.16b

    /* ===== Rho + Pi + Chi ===== */
    sub     sp, sp, #400

    /* Rho + Pi: compute rotated values and store to stack in row order */
    str     q0, [sp, #0]
    ROL     v25, v6, 44
    str     q25, [sp, #16]
    ROL     v25, v12, 43
    str     q25, [sp, #32]
    ROL     v25, v18, 21
    str     q25, [sp, #48]
    ROL     v25, v24, 14
    str     q25, [sp, #64]

    ROL     v25, v3, 28
    str     q25, [sp, #80]
    ROL     v25, v9, 20
    str     q25, [sp, #96]
    ROL     v25, v10, 3
    str     q25, [sp, #112]
    ROL     v25, v16, 45
    str     q25, [sp, #128]
    ROL     v25, v22, 61
    str     q25, [sp, #144]

    ROL     v25, v1, 1
    str     q25, [sp, #160]
    ROL     v25, v7, 6
    str     q25, [sp, #176]
    ROL     v25, v13, 25
    str     q25, [sp, #192]
    ROL     v25, v19, 8
    str     q25, [sp, #208]
    ROL     v25, v20, 18
    str     q25, [sp, #224]

    ROL     v25, v4, 27
    str     q25, [sp, #240]
    ROL     v25, v5, 36
    str     q25, [sp, #256]
    ROL     v25, v11, 10
    str     q25, [sp, #272]
    ROL     v25, v17, 15
    str     q25, [sp, #288]
    ROL     v25, v23, 56
    str     q25, [sp, #304]

    ROL     v25, v2, 62
    str     q25, [sp, #320]
    ROL     v25, v8, 55
    str     q25, [sp, #336]
    ROL     v25, v14, 39
    str     q25, [sp, #352]
    ROL     v25, v15, 41
    str     q25, [sp, #368]
    ROL     v25, v21, 2
    str     q25, [sp, #384]

    /* Chi + Iota */
    ldp     q25, q26, [sp, #0]
    ldp     q27, q28, [sp, #32]
    ldr     q29, [sp, #64]

    bic     v30.16b, v27.16b, v26.16b
    eor     v0.16b, v25.16b, v30.16b
    ldr     x3, [x2]
    dup     v30.2d, x3
    eor     v0.16b, v0.16b, v30.16b

    bic     v30.16b, v28.16b, v27.16b
    eor     v1.16b, v26.16b, v30.16b

    bic     v30.16b, v29.16b, v28.16b
    eor     v2.16b, v27.16b, v30.16b

    bic     v30.16b, v25.16b, v29.16b
    eor     v3.16b, v28.16b, v30.16b

    bic     v30.16b, v26.16b, v25.16b
    eor     v4.16b, v29.16b, v30.16b

    ldp     q25, q26, [sp, #80]
    ldp     q27, q28, [sp, #112]
    ldr     q29, [sp, #144]

    bic     v30.16b, v27.16b, v26.16b
    eor     v5.16b, v25.16b, v30.16b

    bic     v30.16b, v28.16b, v27.16b
    eor     v6.16b, v26.16b, v30.16b

    bic     v30.16b, v29.16b, v28.16b
    eor     v7.16b, v27.16b, v30.16b

    bic     v30.16b, v25.16b, v29.16b
    eor     v8.16b, v28.16b, v30.16b

    bic     v30.16b, v26.16b, v25.16b
    eor     v9.16b, v29.16b, v30.16b

    ldp     q25, q26, [sp, #160]
    ldp     q27, q28, [sp, #192]
    ldr     q29, [sp, #224]

    bic     v30.16b, v27.16b, v26.16b
    eor     v10.16b, v25.16b, v30.16b

    bic     v30.16b, v28.16b, v27.16b
    eor     v11.16b, v26.16b, v30.16b

    bic     v30.16b, v29.16b, v28.16b
    eor     v12.16b, v27.16b, v30.16b

    bic     v30.16b, v25.16b, v29.16b
    eor     v13.16b, v28.16b, v30.16b

    bic     v30.16b, v26.16b, v25.16b
    eor     v14.16b, v29.16b, v30.16b

    ldp     q25, q26, [sp, #240]
    ldp     q27, q28, [sp, #272]
    ldr     q29, [sp, #304]

    bic     v30.16b, v27.16b, v26.16b
    eor     v15.16b, v25.16b, v30.16b

    bic     v30.16b, v28.16b, v27.16b
    eor     v16.16b, v26.16b, v30.16b

    bic     v30.16b, v29.16b, v28.16b
    eor     v17.16b, v27.16b, v30.16b

    bic     v30.16b, v25.16b, v29.16b
    eor     v18.16b, v28.16b, v30.16b

    bic     v30.16b, v26.16b, v25.16b
    eor     v19.16b, v29.16b, v30.16b

    ldp     q25, q26, [sp, #320]
    ldp     q27, q28, [sp, #352]
    ldr     q29, [sp, #384]

    bic     v30.16b, v27.16b, v26.16b
    eor     v20.16b, v25.16b, v30.16b

    bic     v30.16b, v28.16b, v27.16b
    eor     v21.16b, v26.16b, v30.16b

    bic     v30.16b, v29.16b, v28.16b
    eor     v22.16b, v27.16b, v30.16b

    bic     v30.16b, v25.16b, v29.16b
    eor     v23.16b, v28.16b, v30.16b

    bic     v30.16b, v26.16b, v25.16b
    eor     v24.16b, v29.16b, v30.16b

    add     sp, sp, #400

    add     x2, x2, #8
    subs    x1, x1, #1
    b.ne    .Lx2_round_loop

    /* Store state back */
    stp     q0,  q1,  [x19]
    stp     q2,  q3,  [x19, #32]
    stp     q4,  q5,  [x19, #64]
    stp     q6,  q7,  [x19, #96]
    stp     q8,  q9,  [x19, #128]
    stp     q10, q11, [x19, #160]
    stp     q12, q13, [x19, #192]
    stp     q14, q15, [x19, #224]
    stp     q16, q17, [x19, #256]
    stp     q18, q19, [x19, #288]
    stp     q20, q21, [x19, #320]
    stp     q22, q23, [x19, #352]
    str     q24, [x19, #384]

    ldp     x19, x20, [x29, #16]
    ldp     x21, x22, [x29, #32]
    ldp     x29, x30, [sp], #48
AARCH64_AUTIASP
    ret
.size KeccakF1600StatePermutex2, .-KeccakF1600StatePermutex2

/**
 * Keccakx2Absorb - AArch64 NEON implementation
 *
 * void Keccakx2Absorb(Keccakx2State state, size_t rate,
 *                     const uint8_t *in0, const uint8_t *in1,
 *                     size_t inlen, uint8_t domain)
 *
 * Register allocation (caller convention, AAPCS64):
 *   x0  = state (Keccakx2State: 25 x uint64x2_t = 400 bytes)
 *   x1  = rate  (bytes per block, e.g. 168 for SHAKE128)
 *   x2  = in0
 *   x3  = in1
 *   x4  = inlen
 *   x5  = domain (passed as uint8_t in w5)
 *
 * The Keccakx2State layout: s[i] = { lane_i_stream0, lane_i_stream1 }
 * (two parallel 1600-bit states tucked into 25 uint64x2_t registers)
 */
.text
.balign 16
.global Keccakx2Absorb
.type   Keccakx2Absorb, %function
Keccakx2Absorb:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-64]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]

    /* Save parameters */
    mov     x19, x0     /* state  */
    mov     x20, x1     /* rate   */
    mov     x21, x2     /* in0    */
    mov     x22, x3     /* in1    */
    mov     x23, x4     /* inlen  */
    and     x24, x5, #0xFF  /* domain */

    /* Step 1: initialize state to zero (25 x uint64x2_t = 400 bytes) */
    movi    v0.2d,  #0
    movi    v1.2d,  #0
    movi    v2.2d,  #0
    movi    v3.2d,  #0
    movi    v4.2d,  #0
    movi    v5.2d,  #0
    movi    v6.2d,  #0
    movi    v7.2d,  #0
    movi    v8.2d,  #0
    movi    v9.2d,  #0
    movi    v10.2d, #0
    movi    v11.2d, #0
    movi    v12.2d, #0
    movi    v13.2d, #0
    movi    v14.2d, #0
    movi    v15.2d, #0
    movi    v16.2d, #0
    movi    v17.2d, #0
    movi    v18.2d, #0
    movi    v19.2d, #0
    movi    v20.2d, #0
    movi    v21.2d, #0
    movi    v22.2d, #0
    movi    v23.2d, #0
    movi    v24.2d, #0

    stp     q0,  q1,  [x19]
    stp     q2,  q3,  [x19, #32]
    stp     q4,  q5,  [x19, #64]
    stp     q6,  q7,  [x19, #96]
    stp     q8,  q9,  [x19, #128]
    stp     q10, q11, [x19, #160]
    stp     q12, q13, [x19, #192]
    stp     q14, q15, [x19, #224]
    stp     q16, q17, [x19, #256]
    stp     q18, q19, [x19, #288]
    stp     q20, q21, [x19, #320]
    stp     q22, q23, [x19, #352]
    str     q24, [x19, #384]

    /* Step 2: absorb full blocks */
    /* while (inlen >= rate): XOR rate/8 words from in0+in1 into state, then permute */
.Labsorb2_full_block_check:
    cmp     x23, x20
    blo     .Labsorb2_tail

    /* XOR rate/8 words into state.  Each state word s[i] gets:
       lower 64 bits <- in0[i*8 .. i*8+7]
       upper 64 bits <- in1[i*8 .. i*8+7]
       We walk via pointer arithmetic: x0 = state offset, x6 = word index */
    mov     x0,  x19    /* state ptr current word */
    mov     x6,  x21    /* in0 current */
    mov     x7,  x22    /* in1 current */
    mov     x8,  x20    /* remaining bytes in this block = rate */

.Labsorb2_word_loop:
    cmp     x8, #8
    blo     .Labsorb2_word_done
    /* Load one 64-bit word from each input */
    ldr     x9,  [x6], #8
    ldr     x10, [x7], #8
    /* Combine into a uint64x2_t and XOR into state */
    fmov    d30, x9
    fmov    v30.d[1], x10
    ldr     q31, [x0]
    eor     v31.16b, v31.16b, v30.16b
    str     q31, [x0], #16   /* advance state pointer by sizeof(uint64x2_t) = 16 */
    sub     x8,  x8,  #8
    b       .Labsorb2_word_loop

.Labsorb2_word_done:
    /* Advance input pointers and reduce inlen */
    add     x21, x21, x20
    add     x22, x22, x20
    sub     x23, x23, x20

    /* Call KeccakF1600StatePermutex2(state) */
    mov     x0, x19
    bl      KeccakF1600StatePermutex2

    b       .Labsorb2_full_block_check

    /* Step 3: handle remaining bytes (< rate), byte by byte */
.Labsorb2_tail:
    /* x23 = number of remaining bytes; x6 = byte index 0..inlen-1 */
    cbz     x23, .Labsorb2_pad

    mov     x6,  #0   /* byte index i */
.Labsorb2_byte_loop:
    cmp     x6,  x23
    bge     .Labsorb2_pad

    /* lane = (uint64_t)in0[i] << (8*(i%8))
       packed into state[i/8] = { lane0, lane1 } */
    ldrb    w9,  [x21, x6]
    ldrb    w10, [x22, x6]
    and     x11, x6,  #7          /* i % 8            */
    lsl     x11, x11, #3          /* shift = 8*(i%8)  */
    lsl     x9,  x9,  x11         /* lane0            */
    lsl     x10, x10, x11         /* lane1            */
    /* state word index = i/8, byte offset in state = (i/8)*16 */
    lsr     x12, x6,  #3          /* i / 8            */
    add     x13, x19, x12, lsl #4 /* &state[i/8]      */
    ldr     q30, [x13]
    fmov    x14, d30
    fmov    x15, v30.d[1]
    eor     x14, x14, x9
    eor     x15, x15, x10
    fmov    d30, x14
    fmov    v30.d[1], x15
    str     q30, [x13]

    add     x6,  x6,  #1
    b       .Labsorb2_byte_loop

    /* Step 4: add domain byte */
.Labsorb2_pad:
    /* domain goes at position inlen; shift = 8*(inlen%8) */
    and     x11, x23, #7
    lsl     x11, x11, #3
    lsl     x9,  x24, x11         /* domain << shift, lane0 */
    mov     x10, x9               /* same for lane1 */
    lsr     x12, x23, #3          /* inlen/8 -- word index  */
    add     x13, x19, x12, lsl #4
    ldr     q30, [x13]
    fmov    x14, d30
    fmov    x15, v30.d[1]
    eor     x14, x14, x9
    eor     x15, x15, x10
    fmov    d30, x14
    fmov    v30.d[1], x15
    str     q30, [x13]

    /* Step 5: set bit 63 of word at (rate-1)/8 */
    sub     x11, x20, #1          /* rate - 1         */
    lsr     x12, x11, #3          /* (rate-1)/8       */
    add     x13, x19, x12, lsl #4 /* &state[(rate-1)/8] */
    ldr     q30, [x13]
    fmov    x14, d30
    fmov    x15, v30.d[1]
    mov     x9,  #1
    lsl     x9,  x9,  #63         /* 1ULL << 63       */
    eor     x14, x14, x9
    eor     x15, x15, x9
    fmov    d30, x14
    fmov    v30.d[1], x15
    str     q30, [x13]

    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x29, x30, [sp], #64
AARCH64_AUTIASP
    ret
.size Keccakx2Absorb, .-Keccakx2Absorb


/**
 * Keccakx2Squeeze - AArch64 NEON implementation
 *
 * void Keccakx2Squeeze(uint8_t *out0, uint8_t *out1,
 *                      size_t nblocks, unsigned int r,
 *                      Keccakx2State s)
 *
 * Register allocation:
 *   x0  = out0
 *   x1  = out1
 *   x2  = nblocks
 *   x3  = r  (rate in bytes)
 *   x4  = s  (pointer to Keccakx2State)
 */
.text
.balign 16
.global Keccakx2Squeeze
.type   Keccakx2Squeeze, %function
Keccakx2Squeeze:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]

    mov     x19, x0    /* out0    */
    mov     x20, x1    /* out1    */
    mov     x21, x2    /* nblocks */
    mov     x22, x3    /* r       */
    /* x4 = state pointer (s) */

.Lsqueeze2_loop:
    cbz     x21, .Lsqueeze2_done

    /* Permute */
    mov     x0, x4
    bl      KeccakF1600StatePermutex2

    /* Extract r/8 words from each state lane to out0 / out1 */
    mov     x0,  x4    /* state pointer */
    mov     x5,  x22   /* remaining bytes = r */

.Lsqueeze2_word_loop:
    cmp     x5,  #8
    blo     .Lsqueeze2_word_done
    ldr     q30, [x0], #16   /* load state[i] = {lane0, lane1} */
    fmov    x6,  d30         /* lane for out0 */
    fmov    x7,  v30.d[1]    /* lane for out1 */
    str     x6,  [x19], #8
    str     x7,  [x20], #8
    sub     x5,  x5,  #8
    b       .Lsqueeze2_word_loop

.Lsqueeze2_word_done:
    sub     x21, x21, #1
    b       .Lsqueeze2_loop

.Lsqueeze2_done:
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x29, x30, [sp], #48
AARCH64_AUTIASP
    ret
.size Keccakx2Squeeze, .-Keccakx2Squeeze

#endif
