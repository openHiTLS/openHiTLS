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
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)

#include "crypt_arm.h"

.arch   armv8-a

/**
 * c structure：Poly1305Ctx
 */

.set CTX_acc, 0
.set CTX_r, 24
.set CTX_s, 40
.set CTX_table, 56
.set CTX_data, 200
.set CTX_lastLen, 216
.set CTX_flag, 220
.set CTX_size, 224

.equ FLAG_BASE2_26,     1

/* 104           78            52            26            0
 * out4          out3          out2          out1          out0
 *                             in0[63:52]    in0[51:26]    in0[25:0]
 * in1[63:40]    in1[39:14]    in1[13:0]<<12
 * in2[39:0]<<24
 */
/**
 *  Macro description: converts the large number format. Three pieces of base 2^64 data are transferred,
 *                     and five pieces of base 2^26 data are transferred.
 *  Input register:
 *      in0: digits 0 to 63 of the large number in the original format
 *      in1:64 to 127 characters in the original format
 *      in2:128 or more digits of the large number in the original format
 *  Modified register: None
 *  Output register:
 *      out0: 0 to 25 bits of the converted large number
 *      out1:26 to 51 digits of the converted large number
 *      out2:52 to 77 bits of the converted large number
 *      out3:78 to 103 bits of the converted large number
 *      out4:104 or more digits of the converted large number
 *  Function/Macro Call: None
 *  Restriction: Note that the valid bits of in2 cannot exceed 40 bits.
 *               Otherwise, data will be lost.
 */
    .macro CONVERT_64TO26    out0 out1 out2 out3 out4 in0 in1 in2
    and     \out0, \in0, #0x03ffffff
    ubfx    \out1, \in0, #26, #26
    extr    \out2, \in1, \in0, #52
    and     \out2, \out2, #0x03ffffff
    ubfx    \out3, \in1, #14, #26
    extr    \out4, \in2, \in1, #40
    .endm

/* 128            64            0
 * out2           out1        out0
 *                            in0
 *               (in1>>38)    in1<<26
 *                in2>>12     in2<<52
 * (in3>>50)      in3<<14
 * in4>>24        in4<<40
 */
/**
 *  Macro description: converts the large number format. Five pieces of base2^26 data are transferred,
 *                     and three pieces of base2^64 data are transferred.
 *  Input register:
 *      in0: large data block 0 in the original format
 *      in1: large data block 1 in the original format
 *      in2: large data block 2 in the original format
 *      in3: large data block 3 in the original format
 *      in4: large data block 4 in the original format
 *  Modified register: None
 *  Output register:
 *       out0: bits 0 to 63 of the converted large number
 *       out1: 64-127 bits of the converted large number
 *       out2: 128 or more digits of the converted large number
 *  Function/Macro Call: None
 *  Restriction: Ensure that the valid bits in0-in4 of the input data do not exceed 38 bits. Otherwise,
 *               data will be lost.
 */
    .macro CONVERT_26TO64    out0 out1 out2 in0 in1 in2 in3 in4
    add     \out0, \in0, \in1, lsl#26
    adds    \out0, \out0, \in2, lsl#52
    lsr     \out1, \in2, #12
    add     \out1, \out1, \in3, lsl#14
    adc     \out1, \out1, xzr
    adds    \out1, \out1, \in4, lsl#40
    lsr     \out2, \in4, #24
    adc     \out2, \out2, xzr
    .endm


/*   register     |  t_0             t_1          |  t_2             |
 *   bits         |           128 bits            |     64 bits      |
 *   1            |  r0*a0(lo)       r0*a1(lo)    |  r0*a2(lo)       |
 *   2            |                  r0*a0(hi)    |  r0*a1(hi)       |
 *   3            |  s1*a1(lo)       r1*a0(lo)    |                  |
 *   4            |                  s1*a1(hi)    |  r1*a0(hi)       |
 *   5            |                  s1*a2(lo)    |                  |
 */
/**
 *  Macro description: Multiply large numbers and perform modulo
 *                     (a0|a1|a2) = (a0|a1|a2) * (r0|r1) mod P
 *  Input register:
 *        a_0: digits 0 to 63 of the large number a
 *        a_1: 64 to 127 digits of the major number a
 *        a_2: 128 or more digits of the major number a
 *        r_0: bits 0 to 63 of the large number r
 *        r_1: 64-127 bits of the large number r
 *        s_1: 5/4 times the large number r_1
 *  Change register: x11-x15
 *  Output register:
 *        a_0: bits 0 to 63 of the multiplication result
 *        a_1: 64-127 bits of the multiplication result
 *        a_2: 128 or more bits of the multiplication result
 *  Function/Macro Call: None
 *  Restriction: The relationship between s1 and r1 is s1 = r1 + r1 >> 2.
 */
    .macro  POLY1305_MOD_MUL  a_0, a_1, a_2, r_0, r_1, s_1
    /* 1 */
    mul     x11, \r_0, \a_0
    mul     x12, \r_0, \a_1
    mul     x13, \r_0, \a_2
    /* 2 */
    umulh   x14, \r_0, \a_0
    umulh   x15, \r_0, \a_1
    adds    x12, x12, x14
    adc     x13, x13, x15
    /* 3 */
    mul     x14, \s_1, \a_1
    mul     x15, \r_1, \a_0
    adds    x11, x11, x14
    adcs    x12, x12, x15
    adc     x13, x13, xzr
    /* 4 */
    umulh   x14, \s_1, \a_1
    umulh   x15, \r_1, \a_0
    adds    x12, x12, x14
    adc     x13, x13, x15
    /* 5 */
    mul     x15, \s_1, \a_2
    adds    x12, x12, x15
    adc     x13, x13, xzr
    /* Split x13 and add 5/4 of the high-order part to x11. */
    bic     x15, x13, #3
    and     x13, x13, #3
    add     x15, x15, x15, lsr#2
    adds    \a_0, x11, x15
    adcs    \a_1, x12, xzr
    adc     \a_2, x13, xzr
    .endm

/**
 *  Macro description: Convert the content of a large number (r_0|r_1|r_2) into the format of 2 ^ 26,
 *                     and then fill the memory pointed to by ptr at intervals.
 *  Input register:
 *       r_0: digits 0 to 63 of a large number
 *       r_1: indicates the 64th to 127th digits of the large number.
 *       r_2: 128th to 191th digits of a large number
 *       ptr: start address of the memory to be filled
 *   Change register: x11-x15
 *   Output register: None
 *   Function/Macro call: TRANSFER_64TO26
 *
 */
    .macro  Fill_TABLE r_0, r_1, r_2, ptr
    /* base 2^64 -> base 2^26 */
    /* r_0 r_1 r_2 --> x11 x12 x13 x14 x15 */
    CONVERT_64TO26 x11, x12, x13, x14, x15, \r_0, \r_1, \r_2
    /* Stores the converted value. */
    str     w11, [\ptr, #16*0]
    str     w12, [\ptr, #16*1]
    str     w13, [\ptr, #16*2]
    str     w14, [\ptr, #16*3]
    str     w15, [\ptr, #16*4]
    /* Multiply 5 times and continue to store */
    add     w12, w12, w12, lsl#2
    add     w13, w13, w13, lsl#2
    add     w14, w14, w14, lsl#2
    add     w15, w15, w15, lsl#2

    str     w12, [\ptr, #16*5]
    str     w13, [\ptr, #16*6]
    str     w14, [\ptr, #16*7]
    str     w15, [\ptr, #16*8]
    .endm

/**
 *  Function description: This function is used to initialize the pre-computation table.
 *  Function prototype: void Poly1305InitForAsm(Poly1305Ctx *ctx);
 *  Input register:
 *         x0: address of the context structure
 *  Change register x0 and x5-x15.
 *  Output register: None
 *  Function/Macro Call: Poly1305_MOD_MUL Fill_TABLE
 */
.text
.balign 64
.global Poly1305InitForAsm
.type Poly1305InitForAsm, %function
Poly1305InitForAsm:
AARCH64_PACIASP
    stp     x29, x30, [sp, #-16]!
    add     x29, sp, #0

    /* Clearing the member flag */
    str     wzr, [x0, #CTX_flag]

    /* Initialize the r table. */
    ldp     x8, x9, [x0, #CTX_r]

#ifdef	HITLS_BIG_ENDIAN
    /* The r value needs to be reversed in the big-endian case. */
    ror     x8, x8, #32
    ror     x9, x9, #32
#endif

    add     x10, x9, x9, lsr#2
    /* padding r^1 */
    add     x0, x0, #CTX_table + 12
    mov     x5, x8
    mov     x6, x9
    mov     x7, xzr
    Fill_TABLE x5, x6, x7, x0

    /* Calculate and populate r^2 */
    sub     x0, x0, #4
    POLY1305_MOD_MUL x5, x6, x7, x8, x9, x10
    Fill_TABLE x5, x6, x7, x0

    /* Calculate and populate r^3 */
    sub     x0, x0, #4
    POLY1305_MOD_MUL x5, x6, x7, x8, x9, x10
    Fill_TABLE x5, x6, x7, x0

    /* Calculate and populate r^4 */
    sub     x0, x0, #4
    POLY1305_MOD_MUL x5, x6, x7, x8, x9, x10
    Fill_TABLE x5, x6, x7, x0

    eor     x5, x5, x5
    eor     x6, x6, x6
    eor     x7, x7, x7
    eor     x8, x8, x8
    eor     x9, x9, x9
    eor     x10, x10, x10

    ldp     x29, x30, [sp], #16
AARCH64_AUTIASP
    ret
.size Poly1305InitForAsm, .-Poly1305InitForAsm

/**
 *  Function description: Outputs the final result value to the specified memory.
 *  Function prototype: void Poly1305Last(Poly1305Ctx *ctx, uint8_t mac[POLY1305_TAGSIZE]);
 *  Input register:
 *         x0: address of the context structure
 *         x1: pointer to the output buffer
 *  Change register: x3-x15
 *  Output register: None
 *  Function/Macro Call: Poly1305LastNeon
 */
.text
.balign 64
.global Poly1305Last
.type Poly1305Last, %function
Poly1305Last:
AARCH64_PACIASP
    ldr     w15, [x0, #CTX_flag]
    and     w15, w15, #FLAG_BASE2_26
    cbnz    w15, Poly1305LastNeon

    ldp     x3, x4, [x0, #CTX_acc]
    ldr     x5, [x0, #CTX_acc + 16]
    ldp     x12, x13, [x0, #CTX_s]

    adds    x9, x3, #5        // Compute acc + 5
    adcs    x10, x4, xzr
    adc     x11, x5, xzr
    /* Test for more than 2 ^ 130 */
    cmp     x11, #3
    /* If yes, use the value after adding 5 (equal to the value after modulo operation).
       If no, use the original value. */
    csel    x3, x3, x9, le
    csel    x4, x4, x10, le
    /* Plus the s value */
#ifdef	HITLS_BIG_ENDIAN
    /* In the big-endian scenario, the s value needs to be reversed. */
    ror     x12, x12, #32
    ror     x13, x13, #32
#endif
    adds    x3, x3, x12
    adc     x4, x4, x13
    mov     x12, xzr // zero out.
    mov     x13, xzr
#ifdef	HITLS_BIG_ENDIAN
    /* In big-endian mode, the data is converted to little-endian and then output to the memory. */
    rev     x3, x3
    rev     x4, x4
#endif
    stp     x3, x4, [x1]
AARCH64_AUTIASP
    ret
.size Poly1305Last, .-Poly1305Last

/**
 *  Function description: Outputs the final result value to the specified memory.
 *  Function prototype: void Poly1305LastNeon(Poly1305Ctx *ctx, uint8_t mac[POLY1305_TAGSIZE]);
 *  Input register:
 *         x0: address of the context structure
 *         x1: pointer to the output buffer
 *  Change register: x2-x15
 *  Output register: None
 *  Function/Macro Call: None
 */
.text
.balign 64
.type   Poly1305LastNeon, %function
Poly1305LastNeon:
AARCH64_PACIASP
    /* Load the value of base 2^26. */
    ldp     w11, w12, [x0, #CTX_acc]
    ldp     w13, w14, [x0, #CTX_acc + 8]
    ldr     w15, [x0, #CTX_acc + 16]
    /* Converted to base 2^64, x11 to x15 are within 30 bits. */
    CONVERT_26TO64 x5, x6, x7, x11, x12, x13, x14, x15
    /* Load the s value. */
    ldp     x2, x3, [x0, #CTX_s]

    /* Add more than 130 bits by 5 to the lower bits. */
    bic     x15, x7, #3
    and     x7, x7, #3
    add     x15, x15, x15, lsr#2
    adds    x5, x5, x15
    adcs    x6, x6, xzr
    adc     x7, x7, xzr

    /* Modulo P, subtract directly */
    /* subtraction：acc - (2^130 - 5) = acc + 5 - 2^130 */
    adds    x11, x5, #5
    adcs    x12, x6, xzr
    adc     x13, x7, xzr
    /* Test for more than 2 ^ 130 */
    cmp     x13, #4
    /* If P is greater than or equal to P, the new value is used. */
    csel    x5, x11, x5, ge
    csel    x6, x12, x6, ge

    /* Value of s plus acc */
#ifdef	HITLS_BIG_ENDIAN
    /* In the big-endian scenario, the s value needs to be reversed. */
    ror     x2, x2, #32
    ror     x3, x3, #32
#endif

    adds    x2, x2, x5
    adc     x3, x3, x6

#ifdef	HITLS_BIG_ENDIAN
    /* In big-endian mode, the data is converted to little-endian and then output to the memory. */
    rev     x2, x2
    rev     x3, x3
#endif

    stp     x2, x3, [x1]
AARCH64_AUTIASP
    ret
.size Poly1305LastNeon, .-Poly1305LastNeon


/**
 *  Function description: Compresses the input data and stores it in the context structure.
 *  Function prototype: uint32_t Poly1305Block(Poly1305Ctx *ctx, const uint8_t *data,
 *                                             uint32_t dataLen, uint32_t padbit);
 *  Input register:
 *         x0: address of the context structure
 *         x1: pointer to the input data
 *         x2: length of the input data
 *         x3: padded bits, 0 or 1.
 *  Change register: x4-x15
 *  Output register:
 *  x0: length of the remaining data to be processed
 *  Function/Macro Call: CONVERT_26TO64 POLY1305_MOD_MUL Poly1305BlockNeon
 */
.text
.balign 64
.global  Poly1305Block
.type   Poly1305Block, %function
Poly1305Block:
AARCH64_PACIASP
    /* x4 indicates the length of the basic instruction set to be processed,
       and x2 indicates the remaining length of the instruction set to be processed. */
    /* If the value is less than 16, no processing is required. If NEON is supported,
       the part that is greater than or equal to 256 is reserved for NEON. */
    and     x4, x2, #0xF0     // x4 is the processing length of the basic instruction set.
    bic     x2, x2, #0xF0     // x2 is the remaining length after the basic instruction set is processed.
    cbz     x4, .Lskip_process
    /* Load the ACC value. */
    ldr     w15, [x0, #CTX_flag]
    and     w14, w15, #FLAG_BASE2_26
    cbz     w14, .Lload_acc_64
    bic     w15, w15, #FLAG_BASE2_26
    str     w15, [x0, #CTX_flag]
    ldp     w10, w11, [x0, #CTX_acc]
    ldp     w12, w13, [x0, #CTX_acc + 8]
    ldr     w14, [x0, #CTX_acc + 16]
    CONVERT_26TO64 x5, x6, x7, x10, x11, x12, x13, x14
    b       .Lend_load_acc_64
.Lload_acc_64:
    ldp     x5, x6, [x0, #CTX_acc]
    ldr     x7, [x0, #CTX_acc + 16]
.Lend_load_acc_64:

    /* Load the r value. */
    ldp     x8, x9, [x0, #CTX_r]

#ifdef	HITLS_BIG_ENDIAN
    /* The r value needs to be reversed in the big-endian case. */
    ror     x8, x8, #32
    ror     x9, x9, #32
#endif

    add     x10, x9, x9, lsr#2

.Lloop_64:
    /* Accumulator acc plus plaintext block with padding x3 */
    ldp     x11, x12, [x1], #16

#ifdef	HITLS_BIG_ENDIAN
    rev     x11, x11
    rev     x12, x12
#endif

    adds    x5, x5, x11
    adcs    x6, x6, x12
    adc     x7, x7, x3
    /* Multiply large numbers and take modulo (x5|x6|x7) = (x5|x6|x7) * (x8|x9) mod P */
    /* x10 = x9 + x9 >> 2 */
    POLY1305_MOD_MUL x5, x6, x7, x8, x9, x10
    /* End of loop, update iteration information */
    sub     x4, x4, #16
    cbnz    x4, .Lloop_64

    stp     x5, x6, [x0, #CTX_acc]
    str     x7, [x0, #CTX_acc + 16]
.Lskip_process:
    /* If the remaining length is 256 bytes or more, the NEON processes the remaining length. */
    bic     x4, x2, #0xFF
    cbnz    x4, Poly1305BlockNeon

    /* function returns */
    and     x0, x2, #15 // The return value is the unprocessed length.
    eor     x8, x8, x8
    eor     x9, x9, x9
AARCH64_AUTIASP
    ret
.size Poly1305Block, .-Poly1305Block

/**
 *  Function description: Compresses the input data, stores the data in the context structure, and uses the NEON register.
 *  Function prototype: uint32_t Poly1305BlockNeon(Poly1305Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t padbit);
 *  Input register:
 *         x0: context structure address
 *         x1: pointer to the input data
 *         x2: length of the input data
 *         x3: padding bit, 0 or 1.
 *  Modify the register x0-x15,v0-v7,v16-v31.
 *  Output register:
 *         x0: length of the remaining data to be processed
 *  Function/Macro call: CONVERT_64TO26
 */
.text
.balign 64
.type   Poly1305BlockNeon, %function
Poly1305BlockNeon:
    stp     x29, x30, [sp, #-16]!
    stp     d8, d9, [sp, #-16]!
    stp     d10, d11, [sp, #-16]!
    stp     d12, d13, [sp, #-16]!
    stp     d14, d15, [sp, #-16]!

    /* Load the acc value, which is stored in v24-v28. */
    ldr     w15, [x0, #CTX_flag]
    and     w14, w15, #FLAG_BASE2_26
    cbnz    w14, .Lload_acc_26
    orr     w15, w15, #FLAG_BASE2_26
    str     w15, [x0, #CTX_flag]
    ldp     x5, x6, [x0, #CTX_acc]
    ldr     x7, [x0, #CTX_acc + 16]
    CONVERT_64TO26 x11, x12, x13, x14, x15, x5, x6, x7
    fmov    s24, w11
    fmov    s25, w12
    fmov    s26, w13
    fmov    s27, w14
    fmov    s28, w15
    b       .Lend_load_acc_26
.Lload_acc_26:
    ldp     s24, s25, [x0, #CTX_acc]
    ldp     s26, s27, [x0, #CTX_acc + 8]
    ldr     s28, [x0, #CTX_acc + 16]
.Lend_load_acc_26:

    /* Load r-value table */
    add     x15, x0, #CTX_table
    ld1     {v0.4s}, [x15], #16                         // r^n[0] mod P, n = 1, 2, 3, 4
    ld1     {v1.4s, v2.4s, v3.4s, v4.4s}, [x15], #64    // r^n[1:4] mod P
    ld1     {v5.4s, v6.4s, v7.4s, v8.4s}, [x15], #64    // 5 * r^n[1:4] mod P

    /* Pre-treatment before start of cycle */
    add     x1, x1, #64
    sub     x4, x4, #64
    /* v31.2d is {0x3ffffff, 0x3ffffff} */
    movi    v31.16b, #0xFF
    ushr    v31.2d, v31.2d, #38

    /* Load (m[2], m[3]), convert the format, and save it to v14-v18. */
    ldp     x9, x10, [x1, #-32]
    ldp     x14, x15, [x1, #-16]

#ifdef	HITLS_BIG_ENDIAN
    rev     x9, x9
    rev     x10, x10
    rev     x14, x14
    rev     x15, x15
#endif

    and     x6, x9, #0x03ffffff
    ubfx    x7, x9, #26, #26
    extr    x8, x10, x9, #52
    and     x8, x8, #0x03ffffff
    ubfx    x9, x10, #14, #26
    extr    x10, x3, x10, #40

    and     x11, x14, #0x03ffffff
    ubfx    x12, x14, #26, #26
    extr    x13, x15, x14, #52
    and     x13, x13, #0x03ffffff
    ubfx    x14, x15, #14, #26
    extr    x15, x3, x15, #40

    add     x6, x6, x11, lsl#32
    add     x7, x7, x12, lsl#32
    add     x8, x8, x13, lsl#32
    fmov    d14, x6
    fmov    d15, x7
    add     x9, x9, x14, lsl#32
    add     x10, x10, x15, lsl#32
    fmov    d16, x8
    fmov    d17, x9
    fmov    d18, x10

    /* Load (m[0], m[1]) and save the converted format in v9-v13. */
    ldp     x9, x10, [x1, #-64]
    ldp     x14, x15, [x1, #-48]

#ifdef	HITLS_BIG_ENDIAN
    rev     x9, x9
    rev     x10, x10
    rev     x14, x14
    rev     x15, x15
#endif

    and     x6, x9, #0x03ffffff
    ubfx    x7, x9, #26, #26
    extr    x8, x10, x9, #52
    and     x8, x8, #0x03ffffff
    ubfx    x9, x10, #14, #26
    extr    x10, x3, x10, #40

    and     x11, x14, #0x03ffffff
    ubfx    x12, x14, #26, #26
    extr    x13, x15, x14, #52
    and     x13, x13, #0x03ffffff
    ubfx    x14, x15, #14, #26
    extr    x15, x3, x15, #40

    add     x6, x6, x11, lsl#32
    add     x7, x7, x12, lsl#32
    add     x8, x8, x13, lsl#32
    fmov    d9, x6
    fmov    d10, x7
    add     x9, x9, x14, lsl#32
    add     x10, x10, x15, lsl#32
    fmov    d11, x8
    fmov    d12, x9
    fmov    d13, x10

    /*
        See NEON Crypto by Daniel J. Bernstein and Peter Schwabe
        Use base 2^26 to represent a large number: f = f[0] + f[1]<<26 + f[2]<<52 + f[3]<<78 + f[4]<<104
        Calculate h = (f * g) mod (2^130 - 5), using the NEON register
        h[0] = f[0]g[0] + 5f[1]g[4] + 5f[2]g[3] + 5f[3]g[2] + 5f[4]g[1]
        h[1] = f[0]g[1] +  f[1]g[0] + 5f[2]g[4] + 5f[3]g[3] + 5f[4]g[2]
        h[2] = f[0]g[2] +  f[1]g[1] +  f[2]g[0] + 5f[3]g[4] + 5f[4]g[3]
        h[3] = f[0]g[3] +  f[1]g[2] +  f[2]g[1] +  f[3]g[0] + 5f[4]g[4]
        h[4] = f[0]g[4] +  f[1]g[3] +  f[2]g[2] +  f[3]g[1] +  f[4]g[0]

        NEON Polynomial Calculation Process：
          ((m[0]r^4 + m[2]r^2 + m[4])*r^4 + m[6]r^2 + m[8])*r^4 + m[10]r^2
        + ((m[1]r^4 + m[3]r^2 + m[5])*r^4 + m[7]r^2 + m[9])*r^3 + m[11]r^1

        Calculated inside the loop:
            (x[0],y[0]) = (acc, 0)
            (x[1],y[1]) = (m[2],m[3])*(r^2,r^2) + ((m[0],m[1]) + (x[0],y[0]))*(r^4,r^4)
            (x[2],y[2]) = (m[6],m[7])*(r^2,r^2) + ((m[4],m[5]) + (x[1],y[1]))*(r^4,r^4)
    */
    /* Start loop, vector register has used v0-v8 to hold r value precalculated table, v24-v28 to hold ACC value */
.Lloop_neon:
    add     x1, x1, #64
    umull   v19.2d, v14.2s, v0.s[2]
    sub     x4, x4, #64
    umull   v20.2d, v14.2s, v1.s[2]

    /* Compute (m[2 + 4i], m[3 + 4i])*(r^2, r^2), stored in v19-v23 */
    /* Load the (m[6 + 4i], m[7 + 4i]) file and save it in v14-v18. */
    ldp     x9, x10, [x1, #-32]
    umull   v21.2d, v14.2s, v2.s[2]
    umull   v22.2d, v14.2s, v3.s[2]
    umull   v23.2d, v14.2s, v4.s[2]
    ldp     x14, x15, [x1, #-16]

#ifdef	HITLS_BIG_ENDIAN
    rev     x9, x9
    rev     x10, x10
    rev     x14, x14
    rev     x15, x15
#endif

    umlal   v19.2d, v15.2s, v8.s[2]
    and     x6, x9, #0x03ffffff
    umlal   v20.2d, v15.2s, v0.s[2]
    and     x11, x14, #0x03ffffff
    umlal   v21.2d, v15.2s, v1.s[2]
    ubfx    x7, x9, #26, #26
    umlal   v22.2d, v15.2s, v2.s[2]
    ubfx    x12, x14, #26, #26
    umlal   v23.2d, v15.2s, v3.s[2]
    extr    x8, x10, x9, #52

    umlal   v19.2d, v16.2s, v7.s[2]
    extr    x13, x15, x14, #52
    umlal   v20.2d, v16.2s, v8.s[2]
    and     x8, x8, #0x03ffffff
    umlal   v21.2d, v16.2s, v0.s[2]
    and     x13, x13, #0x03ffffff
    umlal   v22.2d, v16.2s, v1.s[2]
    ubfx    x9, x10, #14, #26
    umlal   v23.2d, v16.2s, v2.s[2]
    ubfx    x14, x15, #14, #26

    umlal   v19.2d, v17.2s, v6.s[2]
    extr    x10, x3, x10, #40
    umlal   v20.2d, v17.2s, v7.s[2]
    extr    x15, x3, x15, #40

    umlal   v21.2d, v17.2s, v8.s[2]
    add     x6, x6, x11, lsl#32
    umlal   v22.2d, v17.2s, v0.s[2]
    add     x7, x7, x12, lsl#32
    umlal   v23.2d, v17.2s, v1.s[2]
    add     x8, x8, x13, lsl#32

    umlal   v19.2d, v18.2s, v5.s[2]
    add     x9, x9, x14, lsl#32
    umlal   v20.2d, v18.2s, v6.s[2]
    add     x10, x10, x15, lsl#32

    umlal   v21.2d, v18.2s, v7.s[2]
    umlal   v22.2d, v18.2s, v8.s[2]
    umlal   v23.2d, v18.2s, v0.s[2]

    fmov    d14, x6
    fmov    d15, x7
    fmov    d16, x8
    fmov    d17, x9
    fmov    d18, x10

    /* It is not placed at the beginning of the loop because it depends on v24 to v28. */
    /* Compute ((m[0 + 4i], m[1 + 4i]) + (x[i], y[i]))*(r^4, r^4), stored in v19-v23 */
    /* Load the (m[4 + 4i], m[5 + 4i]) file and save it in v9-v13. */
    add     v9.2s, v9.2s, v24.2s
    add     v10.2s, v10.2s, v25.2s
    ldp     x9, x10, [x1, #-64]
    add     v11.2s, v11.2s, v26.2s
    add     v12.2s, v12.2s, v27.2s
    add     v13.2s, v13.2s, v28.2s


    umlal   v19.2d, v9.2s, v0.s[0]
    umlal   v20.2d, v9.2s, v1.s[0]
    ldp     x14, x15, [x1, #-48]
    umlal   v21.2d, v9.2s, v2.s[0]
    umlal   v22.2d, v9.2s, v3.s[0]
    umlal   v23.2d, v9.2s, v4.s[0]

#ifdef	HITLS_BIG_ENDIAN
    rev     x9, x9
    rev     x10, x10
    rev     x14, x14
    rev     x15, x15
#endif


    umlal   v19.2d, v10.2s, v8.s[0]
    and     x6, x9, #0x03ffffff
    umlal   v20.2d, v10.2s, v0.s[0]
    and     x11, x14, #0x03ffffff
    umlal   v21.2d, v10.2s, v1.s[0]
    ubfx    x7, x9, #26, #26
    umlal   v22.2d, v10.2s, v2.s[0]
    ubfx    x12, x14, #26, #26
    umlal   v23.2d, v10.2s, v3.s[0]
    extr    x8, x10, x9, #52


    umlal   v19.2d, v11.2s, v7.s[0]
    extr    x13, x15, x14, #52
    umlal   v20.2d, v11.2s, v8.s[0]
    and     x8, x8, #0x03ffffff
    umlal   v21.2d, v11.2s, v0.s[0]
    and     x13, x13, #0x03ffffff
    umlal   v22.2d, v11.2s, v1.s[0]
    ubfx    x9, x10, #14, #26
    umlal   v23.2d, v11.2s, v2.s[0]
    ubfx    x14, x15, #14, #26

    umlal   v19.2d, v12.2s, v6.s[0]
    extr    x10, x3, x10, #40
    umlal   v20.2d, v12.2s, v7.s[0]
    extr    x15, x3, x15, #40

    umlal   v21.2d, v12.2s, v8.s[0]
    add     x6, x6, x11, lsl#32
    umlal   v22.2d, v12.2s, v0.s[0]
    add     x7, x7, x12, lsl#32
    umlal   v23.2d, v12.2s, v1.s[0]
    add     x8, x8, x13, lsl#32

    umlal   v19.2d, v13.2s, v5.s[0]
    add     x9, x9, x14, lsl#32
    umlal   v20.2d, v13.2s, v6.s[0]
    add     x10, x10, x15, lsl#32

    umlal   v21.2d, v13.2s, v7.s[0]
    umlal   v22.2d, v13.2s, v8.s[0]
    umlal   v23.2d, v13.2s, v0.s[0]

    fmov    d9, x6
    fmov    d10, x7
    fmov    d11, x8
    fmov    d12, x9
    fmov    d13, x10

    /* Because v19-v23 significant bits may exceed 56 bits, to ensure that subsequent multiplication
       does not overflow, two carry is processed. */
    ushr    v24.2d, v19.2d, #26
    ushr    v25.2d, v20.2d, #26
    ushr    v26.2d, v21.2d, #26
    ushr    v27.2d, v22.2d, #26
    ushr    v28.2d, v23.2d, #26
    /* More than 130 digits multiplied by 5 to the lower bits */
    shl     v29.2d, v28.2d, #2
    add     v28.2d, v28.2d, v29.2d
    /* Use the AND operation to truncate the lower 26 bits. */
    and     v19.16b, v19.16b, v31.16b
    and     v20.16b, v20.16b, v31.16b
    and     v21.16b, v21.16b, v31.16b
    and     v22.16b, v22.16b, v31.16b
    and     v23.16b, v23.16b, v31.16b
    /* Add the part of the low carry */
    add     v19.2d, v19.2d, v28.2d
    add     v20.2d, v20.2d, v24.2d
    add     v21.2d, v21.2d, v25.2d
    add     v22.2d, v22.2d, v26.2d
    add     v23.2d, v23.2d, v27.2d
    /* Continue carry processing */
    ushr    v24.2d, v19.2d, #26
    ushr    v25.2d, v20.2d, #26
    ushr    v26.2d, v21.2d, #26
    ushr    v27.2d, v22.2d, #26
    ushr    v28.2d, v23.2d, #26
    shl     v29.2d, v28.2d, #2
    add     v28.2d, v28.2d, v29.2d

    and     v19.16b, v19.16b, v31.16b
    and     v20.16b, v20.16b, v31.16b
    and     v21.16b, v21.16b, v31.16b
    and     v22.16b, v22.16b, v31.16b
    and     v23.16b, v23.16b, v31.16b

    add     v19.2d, v19.2d, v28.2d
    add     v20.2d, v20.2d, v24.2d
    add     v21.2d, v21.2d, v25.2d
    add     v22.2d, v22.2d, v26.2d
    add     v23.2d, v23.2d, v27.2d

    /* The calculated (x[i + 1], y[i + 1]) is stored in v24-v28 and is reserved for the next cycle. */
    xtn     v24.2s, v19.2d
    xtn     v25.2s, v20.2d
    xtn     v26.2s, v21.2d
    xtn     v27.2s, v22.2d
    xtn     v28.2s, v23.2d

    /* End of loop, skip */
    cbnz    x4, .Lloop_neon

    /* Dealing with the tail */
    /* Compute (m[6 + 4i], m[7 + 4i])*(r^2, r^1), stored in v19-v23 */
    dup     v14.2d, v14.d[0]
    dup     v15.2d, v15.d[0]
    dup     v16.2d, v16.d[0]
    dup     v17.2d, v17.d[0]
    dup     v18.2d, v18.d[0]

    umull2  v19.2d, v14.4s, v0.4s
    umull2  v20.2d, v14.4s, v1.4s
    umull2  v21.2d, v14.4s, v2.4s
    umull2  v22.2d, v14.4s, v3.4s
    umull2  v23.2d, v14.4s, v4.4s

    umlal2  v19.2d, v15.4s, v8.4s
    umlal2  v20.2d, v15.4s, v0.4s
    umlal2  v21.2d, v15.4s, v1.4s
    umlal2  v22.2d, v15.4s, v2.4s
    umlal2  v23.2d, v15.4s, v3.4s

    umlal2  v19.2d, v16.4s, v7.4s
    umlal2  v20.2d, v16.4s, v8.4s
    umlal2  v21.2d, v16.4s, v0.4s
    umlal2  v22.2d, v16.4s, v1.4s
    umlal2  v23.2d, v16.4s, v2.4s

    umlal2  v19.2d, v17.4s, v6.4s
    umlal2  v20.2d, v17.4s, v7.4s
    umlal2  v21.2d, v17.4s, v8.4s
    umlal2  v22.2d, v17.4s, v0.4s
    umlal2  v23.2d, v17.4s, v1.4s

    umlal2  v19.2d, v18.4s, v5.4s
    umlal2  v20.2d, v18.4s, v6.4s
    umlal2  v21.2d, v18.4s, v7.4s
    umlal2  v22.2d, v18.4s, v8.4s
    umlal2  v23.2d, v18.4s, v0.4s

    /* Compute (m[4 + 4i], m[5 + 4i])*(r^4, r^3), stored in v19-v23 */
    add     v9.2s, v9.2s, v24.2s
    add     v10.2s, v10.2s, v25.2s
    add     v11.2s, v11.2s, v26.2s
    add     v12.2s, v12.2s, v27.2s
    add     v13.2s, v13.2s, v28.2s

    umlal   v19.2d, v9.2s, v0.2s
    umlal   v20.2d, v9.2s, v1.2s
    umlal   v21.2d, v9.2s, v2.2s
    umlal   v22.2d, v9.2s, v3.2s
    umlal   v23.2d, v9.2s, v4.2s

    umlal   v19.2d, v10.2s, v8.2s
    umlal   v20.2d, v10.2s, v0.2s
    umlal   v21.2d, v10.2s, v1.2s
    umlal   v22.2d, v10.2s, v2.2s
    umlal   v23.2d, v10.2s, v3.2s

    umlal   v19.2d, v11.2s, v7.2s
    umlal   v20.2d, v11.2s, v8.2s
    umlal   v21.2d, v11.2s, v0.2s
    umlal   v22.2d, v11.2s, v1.2s
    umlal   v23.2d, v11.2s, v2.2s

    umlal   v19.2d, v12.2s, v6.2s
    umlal   v20.2d, v12.2s, v7.2s
    umlal   v21.2d, v12.2s, v8.2s
    umlal   v22.2d, v12.2s, v0.2s
    umlal   v23.2d, v12.2s, v1.2s

    umlal   v19.2d, v13.2s, v5.2s
    umlal   v20.2d, v13.2s, v6.2s
    umlal   v21.2d, v13.2s, v7.2s
    umlal   v22.2d, v13.2s, v8.2s
    umlal   v23.2d, v13.2s, v0.2s

    /* The results are added, stored in v24-v28, and base 2^26 carry. */
    ushr    v24.2d, v19.2d, #26
    ushr    v25.2d, v20.2d, #26
    ushr    v26.2d, v21.2d, #26
    ushr    v27.2d, v22.2d, #26
    ushr    v28.2d, v23.2d, #26
    shl     v29.2d, v28.2d, #2
    add     v28.2d, v28.2d, v29.2d

    and     v19.16b, v19.16b, v31.16b
    and     v20.16b, v20.16b, v31.16b
    and     v21.16b, v21.16b, v31.16b
    and     v22.16b, v22.16b, v31.16b
    and     v23.16b, v23.16b, v31.16b

    add     v19.2d, v19.2d, v28.2d
    add     v20.2d, v20.2d, v24.2d
    add     v21.2d, v21.2d, v25.2d
    add     v22.2d, v22.2d, v26.2d
    add     v23.2d, v23.2d, v27.2d
    /* Continue carry processing */
    ushr    v24.2d, v19.2d, #26
    ushr    v25.2d, v20.2d, #26
    ushr    v26.2d, v21.2d, #26
    ushr    v27.2d, v22.2d, #26
    ushr    v28.2d, v23.2d, #26
    shl     v29.2d, v28.2d, #2
    add     v28.2d, v28.2d, v29.2d

    and     v19.16b, v19.16b, v31.16b
    and     v20.16b, v20.16b, v31.16b
    and     v21.16b, v21.16b, v31.16b
    and     v22.16b, v22.16b, v31.16b
    and     v23.16b, v23.16b, v31.16b

    add     v19.2d, v19.2d, v28.2d
    add     v20.2d, v20.2d, v24.2d
    add     v21.2d, v21.2d, v25.2d
    add     v22.2d, v22.2d, v26.2d
    add     v23.2d, v23.2d, v27.2d

    addp    v24.2d, v19.2d, v19.2d
    addp    v25.2d, v20.2d, v20.2d
    addp    v26.2d, v21.2d, v21.2d
    addp    v27.2d, v22.2d, v22.2d
    addp    v28.2d, v23.2d, v23.2d
    /* After the processing is complete, save the data. Note that the carry may not be completely processed. */
    stp     s24, s25, [x0, #CTX_acc]
    stp     s26, s27, [x0, #CTX_acc + 8]
    str     s28, [x0, #CTX_acc + 16]

    /* return */
    mov     x5, xzr
    ldp     d14, d15, [sp], #16
    ldp     d12, d13, [sp], #16
    ldp     d10, d11, [sp], #16
    ldp     d8, d9, [sp], #16
    ldp     x29, x30, [sp], #16
    and     x0, x2, #15 // The return value is the unprocessed length.
AARCH64_AUTIASP
    ret
.size Poly1305BlockNeon, .-Poly1305BlockNeon

/**
 *  Function description: This function is used to clear residual sensitive information in registers.
 *  Function prototype: void Poly1305CleanRegister();
 *  Input register: None
 *  Modify the registers v0-v7, v16-v31.
 *  Output register: None
 *  Function/Macro Call: None
 */
.text
.balign 64
.global Poly1305CleanRegister
.type Poly1305CleanRegister, %function
Poly1305CleanRegister:
AARCH64_PACIASP
    movi    v0.16b, #0
    and     v1.16b, v1.16b, v0.16b
    and     v2.16b, v2.16b, v0.16b
    and     v3.16b, v3.16b, v0.16b
    and     v4.16b, v4.16b, v0.16b
    and     v5.16b, v5.16b, v0.16b
    and     v6.16b, v6.16b, v0.16b
    and     v7.16b, v7.16b, v0.16b
    /* V8 to V15 are overwritten during register recovery and do not need to be cleared. */
    and     v16.16b, v16.16b, v0.16b
    and     v17.16b, v17.16b, v0.16b
    and     v18.16b, v18.16b, v0.16b
    and     v19.16b, v19.16b, v0.16b
    and     v20.16b, v20.16b, v0.16b
    and     v21.16b, v21.16b, v0.16b
    and     v22.16b, v22.16b, v0.16b
    and     v23.16b, v23.16b, v0.16b
    and     v24.16b, v24.16b, v0.16b
    and     v25.16b, v25.16b, v0.16b
    and     v26.16b, v26.16b, v0.16b
    and     v27.16b, v27.16b, v0.16b
    and     v28.16b, v28.16b, v0.16b
    and     v29.16b, v29.16b, v0.16b
    and     v30.16b, v30.16b, v0.16b
    and     v31.16b, v31.16b, v0.16b
AARCH64_AUTIASP
    ret
.size Poly1305CleanRegister, .-Poly1305CleanRegister

#endif
