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

/*
 * Portions of this file are derived from the X25519-AArch64 project:
 *     https://github.com/Emill/X25519-AArch64
 *
 * The original X25519-AArch64 project is distributed under CC0 1.0 Universal.
 * See the COPYING.txt file in that project for the full license text.
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_X25519) && defined(HITLS_CRYPTO_X25519_ARMV8_NEON_INTERLEAVE) && !defined(HITLS_BIG_ENDIAN)

#include "crypt_arm.h"

#define M62     0x3FFFFFFFFFFFFFFF

/* Stack layout for inversion subroutine */
#define INV_STACK       400
#define INV_OFF_RESULT  96
#define INV_OFF_F       104
#define INV_OFF_G       144
#define INV_OFF_D       184
#define INV_OFF_E       224
#define INV_OFF_ZETA    264
#define INV_OFF_OUTER   272
#define INV_OFF_SCRATCH 280

.cpu generic+fp+simd
    .text
    .balign 4

/* ============================================================================
 * Constants for Binary GCD
 * ============================================================================ */
.balign 16
.L_p25519:
    .quad   0x3FFFFFFFFFFFFFED
    .quad   0x3FFFFFFFFFFFFFFF
    .quad   0x3FFFFFFFFFFFFFFF
    .quad   0x3FFFFFFFFFFFFFFF
    .quad   0x7F
    .quad   0x39435E50D79435E5

/* ============================================================================
 * SECTION 2: Entry Point & Initialization
 *
 * STACK FRAME ARCHITECTURE
 * ========================
 *
 * This function uses TWO independent stack frames:
 *
 * FRAME 1: Main Function (X25519ScalarMultiPointNeonInterleave)
 * -------------------------------------------------------
 * Created by: stp x29,x30,[sp,#-160]! then sub sp,sp,224
 * Total size: 160 (saved regs) + 224 (working) = 384 bytes
 *
 *   All offsets below are relative to final SP (after sub sp,224).
 *
 *   [Higher addresses]
 *   +------------------+ <-- Original SP (= sp+384)
 *   | d8-d15           | sp+320..383 (callee-saved NEON)
 *   | x19-x28          | sp+240..319 (callee-saved GPR)
 *   | x29, x30         | sp+224..239 (frame pointer, link register)
 *   +------------------+ <-- SP after stp (= sp+224)
 *   | X2[10]           | sp+184..223 (40 bytes, for final mul)
 *   | outptr           | sp+176..183 (output address)
 *   | X1[10]           | sp+136..175 (40 bytes, base point)
 *   | scalar[32]       | sp+104..135 (clamped input)
 *   | counter,lastbit  | sp+96..103  (loop state)
 *   | B/BB[10]         | sp+56..95   (40 bytes, intermediate)
 *   | AA[10]           | sp+16..55   (40 bytes, intermediate)
 *   | mask1, mask2     | sp+0..15    (bias constants)
 *   +------------------+ <-- Final SP (= sp+0)
 *   [Lower addresses]
 *
 * FRAME 2: Inversion Function (.L_fe_invert)
 * ---------------------------------------------------
 * Created by: stp x29,x30,[sp,#-INV_STACK]!  (INV_STACK=400)
 * Total size: 400 bytes (nested inside Frame 1)
 *
 *   +------------------+ <-- SP before call (Frame 1's working SP)
 *   | x29, x30         | inv_sp+0..15
 *   | x19-x28          | inv_sp+16..95
 *   | result_ptr       | inv_sp+96..103   (INV_OFF_RESULT)
 *   | f[5]             | inv_sp+104..143  (INV_OFF_F, 40 bytes)
 *   | g[5]             | inv_sp+144..183  (INV_OFF_G, 40 bytes)
 *   | d[5]             | inv_sp+184..223  (INV_OFF_D, 40 bytes)
 *   | e[5]             | inv_sp+224..263  (INV_OFF_E, 40 bytes)
 *   | zeta             | inv_sp+264..271  (INV_OFF_ZETA)
 *   | outer_count      | inv_sp+272..279  (INV_OFF_OUTER)
 *   | scratch[15]      | inv_sp+280..399  (INV_OFF_SCRATCH, 120 bytes)
 *   +------------------+ <-- SP during inversion
 *
 * NOTE: Frame 2 is completely independent. When .L_fe_invert
 * returns, Frame 2 is deallocated and SP returns to Frame 1's state.
 * Scalar and point inputs are loaded inline via LDR; no auxiliary
 * loader subroutine frame is used.
 * ============================================================================ */

CRYPT_AARCH64_FUNC_START(X25519ScalarMultiPointNeonInterleave)
AARCH64_PACIASP
    /* Prologue: save callee-saved registers */
    stp    x29, x30, [sp, #-160]!
    mov    x29, sp
    stp    x19, x20, [sp, #16]
    stp    x21, x22, [sp, #32]
    stp    x23, x24, [sp, #48]
    stp    x25, x26, [sp, #64]
    stp    x27, x28, [sp, #80]
    stp    d8, d9, [sp, #96]
    stp    d10, d11, [sp, #112]
    stp    d12, d13, [sp, #128]
    stp    d14, d15, [sp, #144]
    sub    sp, sp, 224                            /* Extra space for BGCD */

    str    x0, [sp, #176]                         /* save output pointer */
    mov    x19, x2                                /* save point pointer */

    /* Load scalar as 4x64-bit little-endian words (per RFC 7748 Section 5).
     * Direct LDR supports unaligned addresses on little-endian AArch64
     * user-space targets (Linux, macOS).  BE AArch64 is not supported.
     * x1 (base pointer) is loaded last to avoid clobbering. */
    ldr    x0, [x1]
    ldr    x2, [x1, #16]
    ldr    x3, [x1, #24]
    ldr    x1, [x1, #8]

    /* RFC 7748 Section 5 clamping:
     *   scalar[0]  &= 248  (0xF8)   -- clear bits 0,1,2 => scalar mod 8 = 0
     *   scalar[31] &= 127  (0x7F)   -- clear bit 255    => scalar < 2^255
     *   scalar[31] |= 64   (0x40)   -- set bit 254      => scalar in [2^254, 2^255)
     *
     * In 4x64-bit little-endian layout {x0, x1, x2, x3}:
     *   x0 holds bits [0..63],  x3 holds bits [192..255]
     *   0x7FFFFFFFFFFFFFFF = 2^63 - 1  (63-bit mask on x3 clears bit 255)
     *   0xFFFFFFFFFFFFFFF8 = ~7         (clears lowest 3 bits of x0)
     *   0x4000000000000000 = 2^62       (sets bit 254 = bit 62 of x3) */
    and    x3, x3, #0x7fffffffffffffff            /* scalar &= ~(1<<255) */
    and    x0, x0, #0xfffffffffffffff8            /* scalar &= ~0x7      */
    orr    x3, x3, #0x4000000000000000            /* scalar |=  (1<<254) */

    stp    x0, x1, [sp, #104]
    stp    x2, x3, [sp, #104+16]

    /* Load base point as 4x64-bit little-endian words */
    ldr    x0, [x19]
    ldr    x1, [x19, #8]
    ldr    x2, [x19, #16]
    ldr    x3, [x19, #24]

    /* ---- Convert 256-bit point to radix-2^25.5 (fe[10]) representation ----
     *
     * Split 255-bit u-coordinate into 10 limbs with alternating 26/25-bit
     * Bit 255 (x3[63]) is implicitly discarded per RFC 7748 Section 5.
     *
     * Input: {x0, x1, x2, x3} = 4 x 64-bit LE words (bits 0..255)
     * Output: w10..w9 -> sp+136..175 as X1[10] (10 x 32-bit limbs)
     *
     * Bit layout across 64-bit words:
     *
     *   x0 (bits 0-63):
     *   +--------+-------+-------------+
     *   | L0 26b | L1 25b| L2-lo  13b  |
     *   +--------+-------+-------------+
     *   0       25 26   50 51         63
     *
     *   x1 (bits 64-127):
     *   +-------------+-------+--------+
     *   | L2-hi  13b  | L3 25b| L4 26b |
     *   +-------------+-------+--------+
     *   0            12 13   37 38    63
     *
     *   x2 (bits 128-191):
     *   +-------+--------+-------------+
     *   | L5 25b| L6 26b | L7-lo  13b  |
     *   +-------+--------+-------------+
     *   0      24 25    50 51         63
     *
     *   x3 (bits 192-255):
     *   +------------+--------+-------+-+
     *   | L7-hi 12b  | L8 26b | L9 25b|X|
     *   +------------+--------+-------+-+
     *   0           11 12    37 38   62 63
     *                                    ^ discarded (RFC 7748 u-coord MSB)
     */

    /* Step 1: Extract cross-word limbs L2 and L7 (span two 64-bit words) */
    lsr    x12, x0, #51                           /* x12 = x0[51:63], L2 low 13 bits  */
    lsr    x17, x2, #51                           /* x17 = x2[51:63], L7 low 13 bits  */
    orr    w12, w12, w1, lsl #13                  /* L2 = x0[51:63] | x1[0:12]<<13 */
    orr    w17, w17, w3, lsl #13                  /* L7 = x2[51:63] | x3[0:11]<<13 */

    /* Step 2: Extract inner limbs via unsigned bit field extract */
    ubfx    x8, x3, #12, #26                      /* L8 = x3[12:37], 26 bits */
    ubfx    x9, x3, #38, #25                      /* L9 = x3[38:62], 25 bits */
    ubfx    x11, x0, #26, #25                     /* L1 = x0[26:50], 25 bits */
    ubfx    x13, x1, #13, #25                     /* L3 = x1[13:37], 25 bits */
    lsr    x14, x1, #38                           /* L4 = x1[38:63], 26 bits (high zeros) */
    ubfx    x16, x2, #25, #26                     /* L6 = x2[25:50], 26 bits */

    /* Step 3: Extract base limbs and truncate cross-word limbs */
    and    w10, w0, #0x3ffffff                    /* L0 = x0[0:25],  26-bit mask */
    and    w12, w12, #0x3ffffff                   /* L2 truncate to  26 bits     */
    and    w15, w2, #0x1ffffff                    /* L5 = x2[0:24],  25-bit mask */
    and    w17, w17, #0x1ffffff                   /* L7 truncate to  25 bits     */

    /* Step 4: Store fe[10] to X1 on stack (sp+136..175, 40 bytes) */
    stp    w10, w11, [sp, #136]                   /* X1[0]=L0, X1[1]=L1 */
    stp    w12, w13, [sp, #136+8]                 /* X1[2]=L2, X1[3]=L3 */
    stp    w14, w15, [sp, #136+16]                /* X1[4]=L4, X1[5]=L5 */
    stp    w16, w17, [sp, #136+24]                /* X1[6]=L6, X1[7]=L7 */
    stp    w8, w9, [sp, #136+32]                  /* X1[8]=L8, X1[9]=L9 */

    /* ---- Initialize Montgomery ladder state ----
     *
     * Montgomery ladder (RFC 7748 S5) maintains two projective points:
     *   R0 = (X2, Z2)   and   R1 = (X3, Z3)
     *
     * Algorithm:
     *   R0 = (1, 0)           -- projective infinity (identity)
     *   R1 = (u, 1)           -- base point
     *   for i = 253 downto 0:
     *       cswap(R0, R1, k_i XOR k_{i+1})
     *       R1 = diff_add(R0, R1, u)
     *       R0 = double(R0)
     *   return X2 * Z2^(-1) mod p
     *
     * Per-iteration formulas (mod p = 2^255-19):
     *   A = X2+Z2   B = X2-Z2   C = X3+Z3   D = X3-Z3
     *   X2' = A^2 * B^2             X3' = (DA+CB)^2
     *   Z2' = E*(B^2 + a24*E)       Z3' = u * (DA-CB)^2
     *   where E = A^2 - B^2, a24 = 121666 (Emil paper Alg.1 line 25)
     *
     * NEON register layout (fe[10]: 10 x 32-bit limbs):
     *   Each d-reg holds 2 adjacent limbs packed as .2s
     *   Even regs = X, odd regs = Z:
     *     R0: v0/v2/v4/v6/v8  = X2    v1/v3/v5/v7/v9  = Z2
     *     R1: v10/v12/v14/v16/v18 = X3  v11/v13/v15/v17/v19 = Z3
     */

    /* R0 = (X2, Z2) = (1, 0): projective point at infinity.
     * fe[10] of 1 = {1,0,0,0,0,0,0,0,0,0} -- only limb 0 is nonzero.
     * fe[10] of 0 = all zeros. */
    mov    x1, #1
    mov    v0.d[0], x1                            /* X2[0:1] = {L0=1, L1=0} */
    mov    v2.d[0], xzr                           /* X2[2:3] = 0 */
    mov    v4.d[0], xzr                           /* X2[4:5] = 0 */
    mov    v6.d[0], xzr                           /* X2[6:7] = 0 */
    mov    v8.d[0], xzr                           /* X2[8:9] = 0 */

    mov    v1.d[0], xzr                           /* Z2[0:1] = 0 */
    mov    v3.d[0], xzr                           /* Z2[2:3] = 0 */
    mov    v5.d[0], xzr                           /* Z2[4:5] = 0 */
    mov    v7.d[0], xzr                           /* Z2[6:7] = 0 */
    mov    v9.d[0], xzr                           /* Z2[8:9] = 0 */

    /* R1 = (X3, Z3) = (u, 1): base point in projective form.
     * X3 = fe[10] of u, loaded from w10..w9 (computed in Step 3/4 above).
     * Z3 = fe[10] of 1 = {1,0,...,0}. */
    mov    v10.s[0], w10                          /* X3[0] = L0 */
    mov    v10.s[1], w11                          /* X3[1] = L1 */
    mov    v12.s[0], w12                          /* X3[2] = L2 */
    mov    v12.s[1], w13                          /* X3[3] = L3 */
    mov    v14.s[0], w14                          /* X3[4] = L4 */
    mov    v14.s[1], w15                          /* X3[5] = L5 */
    mov    v16.s[0], w16                          /* X3[6] = L6 */
    mov    v16.s[1], w17                          /* X3[7] = L7 */
    mov    v18.s[0], w8                           /* X3[8] = L8 */
    mov    v18.s[1], w9                           /* X3[9] = L9 */

    mov    v11.d[0], x1                           /* Z3[0:1] = {1, 0}  (x1 still = 1) */
    mov    v13.d[0], xzr                          /* Z3[2:3] = 0 */
    mov    v15.d[0], xzr                          /* Z3[4:5] = 0 */
    mov    v17.d[0], xzr                          /* Z3[6:7] = 0 */
    mov    v19.d[0], xzr                          /* Z3[8:9] = 0 */

    /* ---- Loop counter and arithmetic constants ---- */
    mov    x0, #255-1                             /* 254 iterations: bit 254 is implicit (clamped to 1) */
    str    w0, [sp, #96]                          /* sp+96 = loop counter (decremented each iteration) */

    mov    w30, #19
    dup    v31.2s, w30                            /* v31 = {19, 19}: reduction constant (2^255 = 19 mod p) */

    mov    x0, #(1<<26)-1
    dup    v30.2d, x0                             /* v30 = {0x3FFFFFF, 0x3FFFFFF}: 26-bit limb mask */

    /* ---- Bias constants for unsigned subtraction (Emil paper S6.1) ----
     *
     * NEON .2s is unsigned; X-Z could underflow. Compute (4p - Z) + X
     * instead of X - Z. Since 4p = 0 (mod p), result = X - Z (mod p).
     *
     * bias = 4p = 0x07FFFFFE_07FFFFFC packed as two oversized limbs:
     *   low  32 = 0x07FFFFFC = 2^27 - 4   (even limb bias, ~27 bits)
     *   high 32 = 0x07FFFFFE = 2^27 - 2   (odd  limb bias, ~27 bits)
     *
     * L0 needs adjustment: p[0] = 2^26-19 (not 2^26-1), so 4p[0]
     * is 4*18 = 72 = 0x48 less than the standard even limb bias.
     *
     * d29 = standard bias pair   (for limbs 2..9)
     * d28 = L0-adjusted pair     (for limbs 0,1; L0 reduced by 0x48) */
    mov    x0, #0x07fffffc
    movk   x0, #0xfffe, lsl #32
    movk   x0, #0x07ff, lsl #48
    stp    x0, x0, [sp]                           /* sp[0..15]  = {x0, x0} = standard bias */
    sub    x1, x0, #0xfc-0xb4                     /* x1 = x0 - 72; L0 bias for p[0]=2^26-19 (not 2^26-1) */
    stp    x1, x0, [sp, #8]                       /* sp[8..15] = x1 (L0-adj bias), sp[16..23] = x0 (std bias) */

    ldr    d28, [sp, #8]                          /* d28 = L0-adjusted bias (used for limbs 0,1) */
    ldr    d29, [sp]                              /* d29 = standard bias    (used for limbs 2..9) */

    /* ---- Extract first swap bit from scalar ----
     * Scalar byte 31 is at sp+135 (sp+104 + 31).
     * Bit 254 = byte[31] bit 6. Right-shift 6 to isolate it.
     * This is k_{254}, used as prev_bit for the first iteration's
     * swap = k_253 XOR k_254. */
    ldrb    w1, [sp, #135]                        /* scalar byte 31 (bits 248..255) */
    lsr    w1, w1, #6                             /* w1 = bit 254 (always 1 after clamping) */
    str    w1, [sp, #100]                         /* sp+100 = prev_bit for loop entry */

/* ============================================================================
 * SECTION 3: Montgomery Ladder Main Loop (254 iterations, bits 253..0)
 *
 * ALGORITHM (one doubling + one differential addition per iteration)
 * ------------------------------------------------------------------
 *   swap = k_i XOR k_{i+1}           (constant-time conditional swap)
 *   A = X2+Z2,  B = X2-Z2+4p        (biased sub prevents underflow)
 *   C = X3+Z3,  D = X3-Z3+4p
 *   AA = A*A,   BB = B*B
 *   DA = D*A,   CB = C*B
 *   X2' = AA * BB
 *   E = AA - BB + 4p                 (biased sub)
 *   Z2' = E * (BB + a24*E)           (a24 = 121666)
 *   X3' = (DA + CB)^2
 *   Z3' = u * (DA - CB)^2            (u = base point)
 *
 * PIPELINE SCHEDULING (6 sub-sections per iteration)
 * ------------------------------------------------------------------
 *   Section       NEON pipeline              GPR pipeline
 *   ----------    -----------------------    -----------------------
 *   3.1 cswap     A,B,C,D + trn interleave   A limbs extracted (mov)
 *                 spill: B[10] -> [sp+56]
 *
 *   3.2 mul #1    DA=D*A, CB=C*B             AA=A*A (squaring)
 *                 (parallel via trn)          store: AA -> [sp+16]
 *
 *   3.3 reassm    DA+CB, DA-CB+4p -> zip     BB=B*B (continuing)
 *
 *   3.4 sq #2     (DA+CB)^2, (DA-CB)^2       BB carry + mod-p wrap
 *                                             load: B <- [sp+56]
 *
 *   3.5 E+Z2'     Z3'=u*(DA-CB)^2            E=AA-BB+4p
 *                 X3' carry finish            Z2'=E*(BB+a24*E)
 *                 load: u <- [sp+136]         load: AA <- [sp+16]
 *
 *   3.6 loop      X3'/Z3' repack (trn)       Z2' carry -> v1/v3/v5/v7/v9
 *                 reload: d28/d29 bias        bit extract, swap = cur^prev
 *
 * REGISTER ALLOCATION AT LOOP ENTRY
 * ------------------------------------------------------------------
 *   v0,v2,v4,v6,v8:      X2 limb pairs (5 x .2s)
 *   v1,v3,v5,v7,v9:      Z2 limb pairs
 *   v10,v12,v14,v16,v18: X3 limb pairs
 *   v11,v13,v15,v17,v19: Z3 limb pairs
 *   v28: L0-adjusted bias, v29: standard bias (reloaded: reused as accumulators)
 *   v30: 26-bit mask {0x3FFFFFF, 0x3FFFFFF}
 *   v31: constant {19, 19}
 *   w1: swap bit (k_i XOR k_{i+1})
 * ============================================================================ */

    .balign 64
.Lmainloop:
    prfm    pldl1keep, [sp, #16]                  /* prefetch AA[10] region into L1 */
    prfm    pldl1keep, [sp, #56]                  /* prefetch B/BB[10] region into L1 */

    /* ---- 3.1 Conditional Swap + Coordinate Add/Sub --------------------------
     *
     * B = X2 - Z2 + 4p   (biased sub via v28/v29, prevents NEON underflow)
     * D = X3 - Z3 + 4p
     * A = X2 + Z2         (plain add, no bias needed)
     * C = X3 + Z3
     *
     * fcsel: constant-time swap of (A,B) <-> (C,D) based on swap bit.
     * trn1/trn2: interleave A[i],B[i] so one umull computes both products.
     */
    tst    w1, #1

    /* B = 4p - Z2 (first half; X2 added below) */
    sub    v20.2s, v28.2s, v1.2s                  /* L0-adj bias - Z2[0,1] */
    sub    v21.2s, v29.2s, v3.2s                  /* std bias    - Z2[2,3] */
    sub    v22.2s, v29.2s, v5.2s                  /* std bias    - Z2[4,5] */
    sub    v23.2s, v29.2s, v7.2s                  /* std bias    - Z2[6,7] */
    sub    v24.2s, v29.2s, v9.2s                  /* std bias    - Z2[8,9] */

    /* D = 4p - Z3 (first half; X3 added below) */
    sub    v25.2s, v28.2s, v11.2s                 /* L0-adj bias - Z3[0,1] */
    sub    v26.2s, v29.2s, v13.2s                 /* std bias    - Z3[2,3] */
    sub    v27.2s, v29.2s, v15.2s                 /* std bias    - Z3[4,5] */

    sub    v28.2s, v29.2s, v17.2s                 /* std bias    - Z3[6,7]; v28 destroyed */
    sub    v29.2s, v29.2s, v19.2s                 /* std bias    - Z3[8,9]; v29 destroyed */

    /* B = X2 + (4p - Z2) = X2 - Z2 (mod p) */
    add    v20.2s, v0.2s, v20.2s
    add    v21.2s, v2.2s, v21.2s
    add    v22.2s, v4.2s, v22.2s
    add    v23.2s, v6.2s, v23.2s
    add    v24.2s, v8.2s, v24.2s

    /* D = X3 + (4p - Z3) = X3 - Z3 (mod p) */
    add    v25.2s, v10.2s, v25.2s
    add    v26.2s, v12.2s, v26.2s
    add    v27.2s, v14.2s, v27.2s
    add    v28.2s, v16.2s, v28.2s
    add    v29.2s, v18.2s, v29.2s

    /* A = X2 + Z2,  C = X3 + Z3 (interleaved) */
    add    v0.2s, v0.2s, v1.2s                    /* A[0,1] */
    add    v10.2s, v10.2s, v11.2s                 /* C[0,1] */
    add    v2.2s, v2.2s, v3.2s                    /* A[2,3] */
    add    v12.2s, v12.2s, v13.2s                 /* C[2,3] */
    /* cswap: if swap==0 pick R0(A), else R1(C) */
    fcsel    d1, d0, d10, eq
    add    v4.2s, v4.2s, v5.2s                    /* A[4,5] */
    fcsel    d3, d2, d12, eq
    add    v14.2s, v14.2s, v15.2s                 /* C[4,5] */
    add    v6.2s, v6.2s, v7.2s                    /* A[6,7] */
    add    v16.2s, v16.2s, v17.2s                 /* C[6,7] */
    mov    x0, v1.d[0]                            /* extract A (or C) limbs to GPR for squaring */
    add    v8.2s, v8.2s, v9.2s                    /* A[8,9] */
    mov    x2, v3.d[0]
    add    v18.2s, v18.2s, v19.2s                 /* C[8,9] */
    fcsel    d5, d4, d14, eq

    /* trn interleave: {A[i],B[i]} so umull computes both products at once */
    trn2    v1.2s, v0.2s, v20.2s                  /* {A_L1, B_L1} odd limbs */
    fcsel    d7, d6, d16, eq
    trn1    v0.2s, v0.2s, v20.2s                  /* {A_L0, B_L0} even limbs */
    fcsel    d9, d8, d18, eq
    trn2    v3.2s, v2.2s, v21.2s
    mov    x4, v5.d[0]
    trn1    v2.2s, v2.2s, v21.2s
    mov    x6, v7.d[0]
    trn2    v5.2s, v4.2s, v22.2s
    mov    x8, v9.d[0]
    trn1    v4.2s, v4.2s, v22.2s
    fcsel    d20, d20, d25, eq                    /* cswap for B <-> D */
    trn2    v7.2s, v6.2s, v23.2s
    fcsel    d21, d21, d26, eq
    trn1    v6.2s, v6.2s, v23.2s
    fcsel    d22, d22, d27, eq
    trn2    v9.2s, v8.2s, v24.2s
    fcsel    d23, d23, d28, eq
    trn1    v8.2s, v8.2s, v24.2s
    fcsel    d24, d24, d29, eq

    /* trn interleave for {D, C} (same purpose: dual product per umull) */
    trn2    v11.2s, v25.2s, v10.2s
    trn1    v10.2s, v25.2s, v10.2s
    trn2    v13.2s, v26.2s, v12.2s
    trn1    v12.2s, v26.2s, v12.2s
    trn2    v15.2s, v27.2s, v14.2s
    trn1    v14.2s, v27.2s, v14.2s
    trn2    v17.2s, v28.2s, v16.2s
    trn1    v16.2s, v28.2s, v16.2s
    /* spill B (after cswap) to stack; all 32 NEON regs in use */
    stp    d20, d21, [sp, #56]
    trn2    v19.2s, v29.2s, v18.2s
    stp    d22, d23, [sp, #56+16]
    trn1    v18.2s, v29.2s, v18.2s
    str    d24, [sp, #56+32]

    /* ---- 3.2 Multiplication Kernel #1 ---------------------------------
     *
     * NEON: h[0..9] = D*A and C*B  (two fe_mul in parallel via trn)
     *       v0-v9 = {A[i],B[i]} interleaved, v10-v19 = {D[i],C[i]}
     *       Result accumulates in v20-v29 (.2d), then carry-propagated
     *
     * GPR:  h[0..9] = A*A  (squaring, exploiting a[i]*a[j]=a[j]*a[i] symmetry)
     *       w0-w9 = A limbs (extracted from NEON via mov), x20-x28 accum
     *       Result packed into x20-x28 via bfi, stored to sp+16..48
     *
     * Both pipelines run concurrently. */
    /* -- NEON h9: f0*g9 + f2*g7 + f4*g5 + f6*g3 + f8*g1  (+ odd terms) -- */
    /* accum v29, f=v0-v9{A,B}, g=v10-v19{D,C} */
    /* -- GPR: split packed limb pairs into individual w-regs for squaring -- */
    /* NEON pipe | GPR pipe  -- interleaved for dual-issue --------- */
    umull    v29.2d, v0.2s, v19.2s                /* N h9=f0*g9  */
    lsr    x1, x0, #32                            /* G w1 = A[1] */
    umlal    v29.2d, v2.2s, v17.2s                /* N h9+=f2*g7 */
    lsr    x3, x2, #32                            /* G w3 = A[3] */
    umlal    v29.2d, v4.2s, v15.2s                /* N h9+=f4*g5 */
    lsr    x5, x4, #32                            /* G w5 = A[5] */
    umlal    v29.2d, v6.2s, v13.2s                /* N h9+=f6*g3 */
    lsr    x7, x6, #32                            /* G w7 = A[7] */
    umlal    v29.2d, v8.2s, v11.2s                /* N h9+=f8*g1 */
    lsr    x9, x8, #32                            /* G w9 = A[9] */
    mul    v19.2s, v19.2s, v31.2s                 /* N g9 *= 19  */
    add    x21, x9, x9                            /* G 2*A[9]    */
    /* -- NEON h8: f1*g7 + f3*g5 + f5*g3 + f7*g1 + f9*19g9 (odd, *2 later) */
    /* accum v28, shl #1 after odd cols, then even cols added */
    /* -- GPR: 2*A[i] precomputation for squaring cross-terms 2*fi*fj ------- */
    umull    v28.2d, v1.2s, v17.2s                /* N h8=f1*g7    */
    add    x17, x8, x8                            /* G 2*A[8]      */
    umlal    v28.2d, v3.2s, v15.2s                /* N h8+=f3*g5   */
    add    x16, x7, x7                            /* G 2*A[7]      */
    umlal    v28.2d, v5.2s, v13.2s                /* N h8+=f5*g3   */
    add    x15, x6, x6                            /* G 2*A[6]      */
    umlal    v28.2d, v7.2s, v11.2s                /* N h8+=f7*g1   */
    add    x14, x5, x5                            /* G 2*A[5]      */
    umlal    v28.2d, v9.2s, v19.2s                /* N h8+=f9*19g9 */
    add    x13, x4, x4                            /* G 2*A[4]      */
    /* h9 continued: odd-index terms */
    umlal    v29.2d, v1.2s, v18.2s                /* N h9+=f1*g8   */
    add    x12, x3, x3                            /* x12 = 2*A[3]  */
    umlal    v29.2d, v3.2s, v16.2s                /* N h9+=f3*g6   */
    add    x11, x2, x2                            /* x11 = 2*A[2]  */
    umlal    v29.2d, v5.2s, v14.2s                /* N h9+=f5*g4   */
    add    x10, x1, x1                            /* x10 = 2*A[1]  */
    umlal    v29.2d, v7.2s, v12.2s                /* N h9+=f7*g2   */
    /* -- GPR: begin AA product accumulation -------------------------------- */
    umull    x28, w4, w4                          /* AA[8] = A[4]^2 */
    umlal    v29.2d, v9.2s, v10.2s                /* N h9+=f9*g0   */
    umull    x19, w4, w14                         /* AA[9] = A[4]*2A[5] */
    shl    v28.2d, v28.2d, #1                     /* h8 <<= 1: odd-index product needs *2 */
    /* GPR: 19*A[i] for wrap-around squaring terms (2^255 = 19 mod p) */
    mul    w9, w9, w30                            /* w9  = 19*A[9] (w30 holds constant 19) */
    /* -- NEON h7: f0*g7 + f2*g5 + f4*g3 + f6*g1 + f8*19g9 --------------- */
    /* accum v27, g9 already *19 in v19 */
    umull    v27.2d, v0.2s, v17.2s                /* N h7=f0*g7    */
    mul    w7, w7, w30                            /* w7  = 19*A[7] */
    umlal    v27.2d, v2.2s, v15.2s                /* N h7+=f2*g5   */
    mul    w5, w5, w30                            /* w5  = 19*A[5] */
    umlal    v27.2d, v4.2s, v13.2s                /* N h7+=f4*g3   */
    umaddl    x28, w9, w21, x28                   /* AA[8] += 19*A[9]*2A[7] */
    umlal    v27.2d, v6.2s, v11.2s                /* N h7+=f6*g1   */
    umaddl    x19, w0, w21, x19                   /* AA[9] += A[0]*2A[9]    */
    umlal    v27.2d, v8.2s, v19.2s                /* N h7+=f8*19g9 */

    /* GPR: AA[0..7] = A[0]*A[0], A[0]*2A[1], A[0]*2A[2], ... */
    umull    x20, w0, w0                          /* AA[0] = A[0]^2 */
    mul    v17.2s, v17.2s, v31.2s                 /* g7 *= 19 */
    umull    x21, w0, w10                         /* AA[1] = A[0]*2A[1] */
    /* h8 continued: even-index terms */
    umlal    v28.2d, v0.2s, v18.2s
    umull    x22, w0, w11                         /* AA[2] = A[0]*2A[2] */
    umlal    v28.2d, v2.2s, v16.2s
    umull    x23, w0, w12
    umlal    v28.2d, v4.2s, v14.2s
    umull    x24, w0, w13
    umlal    v28.2d, v6.2s, v12.2s
    umull    x25, w0, w14
    umlal    v28.2d, v8.2s, v10.2s
    umull    x26, w0, w15
    mul    v18.2s, v18.2s, v31.2s                 /* g8 *= 19 */
    umull    x27, w0, w16
    /* -- NEON h6: f1*g5 + f3*g3 + ... (odd, *2 later) -------------------- */
    /* accum v26 */
    umull    v26.2d, v1.2s, v15.2s
    umaddl    x28, w0, w17, x28
    umlal    v26.2d, v3.2s, v13.2s
    mul    w0, w6, w30
    umlal    v26.2d, v5.2s, v11.2s
    umaddl    x22, w1, w10, x22
    umlal    v26.2d, v7.2s, v19.2s
    umaddl    x23, w1, w11, x23
    umlal    v26.2d, v9.2s, v17.2s
    umaddl    x24, w10, w12, x24
    umlal    v27.2d, v1.2s, v16.2s
    umaddl    x25, w1, w13, x25
    umlal    v27.2d, v3.2s, v14.2s
    umaddl    x26, w10, w14, x26
    umlal    v27.2d, v5.2s, v12.2s
    umaddl    x27, w1, w15, x27
    umlal    v27.2d, v7.2s, v10.2s
    umaddl    x28, w10, w16, x28
    umlal    v27.2d, v9.2s, v18.2s
    umaddl    x19, w1, w17, x19
    shl    v26.2d, v26.2d, #1                     /* h6 <<= 1: odd-index product *2 */
    mul    w1, w8, w30                            /* w1 = 19*A[8] (reuse w1, A[1] no longer needed in w1) */
    /* -- NEON h5: f0*g5 + f2*g3 + f4*g1 + f6*19g9 + f8*19g7 ------------- */
    /* accum v25, g7 already *19 in v17 */
    umull    v25.2d, v0.2s, v15.2s
    umaddl    x24, w2, w2, x24
    umlal    v25.2d, v2.2s, v13.2s
    umaddl    x25, w2, w12, x25
    umlal    v25.2d, v4.2s, v11.2s
    umaddl    x26, w2, w13, x26
    umlal    v25.2d, v6.2s, v19.2s
    umaddl    x27, w2, w14, x27
    umlal    v25.2d, v8.2s, v17.2s
    umaddl    x28, w2, w15, x28
    mul    v15.2s, v15.2s, v31.2s                 /* g5 *= 19 */
    umaddl    x19, w2, w16, x19
    /* h6 continued: even-index terms */
    umlal    v26.2d, v0.2s, v16.2s
    umaddl    x26, w3, w12, x26
    umlal    v26.2d, v2.2s, v14.2s
    umaddl    x27, w3, w13, x27
    umlal    v26.2d, v4.2s, v12.2s
    umaddl    x28, w12, w14, x28
    umlal    v26.2d, v6.2s, v10.2s
    umaddl    x19, w3, w15, x19
    umlal    v26.2d, v8.2s, v18.2s
    umaddl    x26, w1, w8, x26
    mul    v16.2s, v16.2s, v31.2s                 /* g6 *= 19 */
    umaddl    x22, w0, w6, x22
    /* -- NEON h4: f1*g3 + f3*g1 + ... (odd, *2 later) -------------------- */
    /* accum v24 */
    umull    v24.2d, v1.2s, v13.2s
    /* -- GPR: AA carry chain starts (h9->h0 mod-p wrap, then h0->h1->...) - */
    add    x19, x19, x28, lsr #26                 /* h9 += h8 >> 26 */
    umlal    v24.2d, v3.2s, v11.2s
    umaddl    x20, w5, w14, x20
    umlal    v24.2d, v5.2s, v19.2s
    add    x20, x20, x19, lsr #25                 /* h0 += h9 >> 25 */
    umlal    v24.2d, v7.2s, v17.2s
    /* GPR: mod-p wrap: h0 += excess(h9) * 19 via shifted adds */
    bic    x2, x19, #0x1ffffff                    /* x2 = excess bits of h9 */
    umlal    v24.2d, v9.2s, v15.2s
    add    x20, x20, x2, lsr #24                  /* +excess*2 */
    umlal    v25.2d, v1.2s, v14.2s
    and    x19, x19, #0x1ffffff                   /* h9 &= 25-bit mask */
    umlal    v25.2d, v3.2s, v12.2s
    add    x20, x20, x2, lsr #21                  /* +excess*16; total = 1+2+16 = 19 */
    umlal    v25.2d, v5.2s, v10.2s
    umaddl    x24, w7, w16, x24
    umlal    v25.2d, v7.2s, v18.2s
    add    x2, x10, x10
    umlal    v25.2d, v9.2s, v16.2s
    add    x3, x12, x12
    shl    v24.2d, v24.2d, #1                     /* h4 <<= 1: odd-index product *2 */
    add    x4, x14, x14
    /* -- NEON h3: f0*g3 + f2*g1 + f4*19g9 + f6*19g7 + f8*19g5 ----------- */
    /* accum v23, g5 already *19 in v15 */
    umull    v23.2d, v0.2s, v13.2s
    add    x5, x16, x16
    umlal    v23.2d, v2.2s, v11.2s
    umaddl    x20, w0, w13, x20
    umlal    v23.2d, v4.2s, v19.2s
    umaddl    x21, w0, w14, x21
    umlal    v23.2d, v6.2s, v17.2s
    and    x28, x28, #0x3ffffff
    umlal    v23.2d, v8.2s, v15.2s
    umaddl    x20, w7, w3, x20
    mul    v13.2s, v13.2s, v31.2s                 /* g3 *= 19 */
    umaddl    x21, w7, w13, x21
    /* h4 continued: even-index terms */
    umlal    v24.2d, v0.2s, v14.2s
    umaddl    x22, w7, w4, x22
    umlal    v24.2d, v2.2s, v12.2s
    umaddl    x23, w7, w15, x23
    umlal    v24.2d, v4.2s, v10.2s
    umaddl    x20, w1, w11, x20
    umlal    v24.2d, v6.2s, v18.2s
    umaddl    x21, w1, w12, x21
    umlal    v24.2d, v8.2s, v16.2s
    umaddl    x22, w1, w13, x22
    mul    v14.2s, v14.2s, v31.2s                 /* g4 *= 19 */
    umaddl    x23, w1, w14, x23
    /* -- NEON h2: f1*g1 + f3*19g9 + ... (odd, *2 later) ------------------ */
    /* accum v22 */
    umull    v22.2d, v1.2s, v11.2s
    umaddl    x24, w1, w15, x24
    umlal    v22.2d, v3.2s, v19.2s
    umaddl    x25, w1, w16, x25
    umlal    v22.2d, v5.2s, v17.2s
    umaddl    x20, w9, w2, x20
    umlal    v22.2d, v7.2s, v15.2s
    umaddl    x21, w9, w11, x21
    umlal    v22.2d, v9.2s, v13.2s
    umaddl    x22, w9, w3, x22
    umlal    v23.2d, v1.2s, v12.2s
    umaddl    x23, w9, w13, x23
    umlal    v23.2d, v3.2s, v10.2s
    umaddl    x24, w9, w4, x24
    umlal    v23.2d, v5.2s, v18.2s
    umaddl    x25, w9, w15, x25
    umlal    v23.2d, v7.2s, v16.2s
    umaddl    x26, w9, w5, x26
    umlal    v23.2d, v9.2s, v14.2s
    umaddl    x27, w9, w17, x27
    shl    v22.2d, v22.2d, #1                     /* h2 <<= 1: odd-index product *2 */
    /* -- GPR: forward carry chain h0->h1->...->h8, pack pairs via bfi ----- */
    add    x21, x21, x20, lsr #26                 /* h1 += h0 >> 26 */
    /* -- NEON h1: f0*g1 + f2*19g9 + f4*19g7 + f6*19g5 + f8*19g3 --------- */
    /* accum v21, g3 already *19 in v13 */
    umull    v21.2d, v0.2s, v11.2s
    and    x20, x20, #0x3ffffff                   /* h0 &= 26-bit mask */
    umlal    v21.2d, v2.2s, v19.2s
    add    x22, x22, x21, lsr #25                 /* h2 += h1 >> 25 */
    umlal    v21.2d, v4.2s, v17.2s
    bfi    x20, x21, #32, #25                     /* pack {h0[25:0], h1[24:0]} into x20 */
    umlal    v21.2d, v6.2s, v15.2s
    add    x23, x23, x22, lsr #26
    umlal    v21.2d, v8.2s, v13.2s
    and    x22, x22, #0x3ffffff
    mul    v11.2s, v11.2s, v31.2s                 /* g1 *= 19 */
    add    x24, x24, x23, lsr #25                 /* h4 += h3 >> 25 */
    /* h2 continued: even-index terms */
    umlal    v22.2d, v0.2s, v12.2s
    bfi    x22, x23, #32, #25                     /* pack {h2, h3} into x22 */
    umlal    v22.2d, v2.2s, v10.2s
    add    x25, x25, x24, lsr #26
    umlal    v22.2d, v4.2s, v18.2s
    and    x24, x24, #0x3ffffff
    umlal    v22.2d, v6.2s, v16.2s
    add    x26, x26, x25, lsr #25
    umlal    v22.2d, v8.2s, v14.2s
    bfi    x24, x25, #32, #25
    mul    v12.2s, v12.2s, v31.2s                 /* g2 *= 19 (last wrap-around precompute) */
    add    x27, x27, x26, lsr #26                 /* h7 += h6 >> 26 */
    /* -- NEON h0: f1*19g9 + f3*19g7 + ... (odd, *2 later) -- last product  */
    /* accum v20, all g[odd] already *19 */
    umull    v20.2d, v1.2s, v19.2s
    and    x26, x26, #0x3ffffff
    umlal    v20.2d, v3.2s, v17.2s
    add    x28, x28, x27, lsr #25                 /* h8 += h7 >> 25 */
    umlal    v20.2d, v5.2s, v15.2s
    bfi    x26, x27, #32, #25                     /* pack {h6, h7} into x26 */
    /* NEON: 25-bit mask for odd limbs = v30 >> 1 = 0x1FFFFFF */
    ushr    v15.2d, v30.2d, #1
    add    x19, x19, x28, lsr #26                 /* h9 += h8 >> 26 */
    /* -- NEON: carry propagation chain h2->h3->...->h9 via usra ----------- */
    usra    v23.2d, v22.2d, #26                   /* h3 += h2 >> 26 */
    and    x28, x28, #0x3ffffff
    and    v22.16b, v22.16b, v30.16b              /* h2 &= 26-bit mask */
    bfi    x28, x19, #32, #26                     /* pack {h8, h9} into x28 */
    umlal    v21.2d, v1.2s, v10.2s
    /* -- GPR: store AA result to sp+16..48 (5 packed 64-bit values) ------- */
    stp    x20, x22, [sp, #16]                    /* AA[0,1], AA[2,3] */
    usra    v24.2d, v23.2d, #25
    stp    x24, x26, [sp, #32]                    /* AA[4,5], AA[6,7] */
    and    v23.16b, v23.16b, v15.16b              /* h3 &= 25-bit mask */
    str    x28, [sp, #48]                         /* AA[8,9] */
    umlal    v20.2d, v7.2s, v13.2s
    /* -- GPR: load B from sp+56..88 (spilled from section 3.1 cswap) ------ */
    ldr    x8, [sp, #88]                          /* B[8,9] */
    usra    v25.2d, v24.2d, #26                   /* h5 += h4 >> 26 */
    ldr    x6, [sp, #80]                          /* B[6,7] */
    and    v24.16b, v24.16b, v30.16b              /* h4 &= 26-bit mask */
    ldr    x4, [sp, #72]                          /* B[4,5] */
    umlal    v21.2d, v3.2s, v18.2s
    ldr    x2, [sp, #64]                          /* B[2,3] */
    usra    v26.2d, v25.2d, #25                   /* h6 += h5 >> 25 */
    lsr    x9, x8, #32                            /* w9 = B[9] */
    and    v25.16b, v25.16b, v15.16b              /* h5 &= 25-bit mask */
    ldr    x0, [sp, #56]                          /* B[0,1] */
    umlal    v20.2d, v9.2s, v11.2s
    lsr    x7, x6, #32
    usra    v27.2d, v26.2d, #26                   /* h7 += h6 >> 26 */
    lsr    x5, x4, #32                            /* w5 = B[5] */
    and    v26.16b, v26.16b, v30.16b              /* h6 &= 26-bit mask */
    lsr    x3, x2, #32                            /* w3 = B[3] */
    umlal    v21.2d, v5.2s, v16.2s
    lsr    x1, x0, #32                            /* w1 = B[1] */
    umlal    v21.2d, v7.2s, v14.2s
    /* GPR: 2*B[i] precompute for BB squaring (same pattern as AA above) */
    add    x21, x9, x9
    umlal    v21.2d, v9.2s, v12.2s
    add    x17, x8, x8
    usra    v28.2d, v27.2d, #25                   /* h8 += h7 >> 25 */
    add    x16, x7, x7
    and    v27.16b, v27.16b, v15.16b
    add    x15, x6, x6
    shl    v20.2d, v20.2d, #1                     /* h0 <<= 1: odd-index product *2 */
    add    x14, x5, x5
    usra    v29.2d, v28.2d, #26                   /* h9 += h8 >> 26 */
    add    x13, x4, x4
    and    v28.16b, v28.16b, v30.16b              /* h8 &= 26-bit mask */
    add    x12, x3, x3
    /* h0 continued: even-index terms */
    umlal    v20.2d, v0.2s, v10.2s
    add    x11, x2, x2
    umlal    v20.2d, v2.2s, v18.2s
    add    x10, x1, x1
    umlal    v20.2d, v4.2s, v16.2s
    /* -- GPR: begin BB = B*B product accumulation --------------------------- */
    umull    x28, w4, w4                          /* BB[8] = B[4]^2 */
    umlal    v20.2d, v6.2s, v14.2s
    umull    x19, w4, w14                         /* BB[9] = B[4]*2B[5] */
    umlal    v20.2d, v8.2s, v12.2s
    mul    w9, w9, w30                            /* w9  = 19*B[9] */
    /* -- 3.2/3.3 transition: 4 concurrent streams --------------------------
     *   NEON-1: h9->h0 mod-p wrap (usra: excess*19 = excess*(1+2+16))
     *   NEON-2: carry chain h0->h3 (usra + and, 26/25 alternating)
     *   NEON-3: uzp pack DA/CB from .2d to .4s (separate two products)
     *   GPR:    BB=B*B squaring begins (19*B[i] precompute + umull/umaddl)
     * -------------------------------------------------------------------- */
    bic    v19.16b, v29.16b, v15.16b              /* v19 = excess bits of h9 */
    mul    w7, w7, w30                            /* w7  = 19*B[7] */
    and    v29.16b, v29.16b, v15.16b              /* h9 &= 25-bit mask */
    mul    w5, w5, w30                            /* w5  = 19*B[5] */
    usra    v20.2d, v19.2d, #25                   /* h0 += excess * 1 */
    umaddl    x28, w9, w21, x28
    /* NEON: uzp1 narrows h[4..9] from .2d to .4s (discard upper 32 bits) */
    uzp1    v24.4s, v24.4s, v25.4s                /* pack {h4,h5} */
    umaddl    x19, w0, w21, x19
    usra    v20.2d, v19.2d, #24                   /* h0 += excess * 2 */
    umull    x20, w0, w0                          /* BB[0] = B[0]^2 */
    uzp1    v25.4s, v26.4s, v27.4s                /* pack {h6,h7} */
    umull    x21, w0, w10
    usra    v20.2d, v19.2d, #21                   /* h0 += excess * 16; (1+2+16=19) done */
    umull    x22, w0, w11
    /* NEON: reload standard bias for DA+CB / DA-CB reassembly */
    ld1r    {v19.2d}, [sp]                        /* v19 = {bias, bias} from stack */
    umull    x23, w0, w12
    uzp1    v26.4s, v24.4s, v25.4s                /* DA even limbs packed */
    umull    x24, w0, w13
    /* NEON: final carry chain h0->h1->h2->h3 for DA/CB results */
    usra    v21.2d, v20.2d, #26                   /* h1 += h0 >> 26 */
    umull    x25, w0, w14
    and    v20.16b, v20.16b, v30.16b              /* h0 &= 26-bit mask */
    umull    x26, w0, w15
    uzp2    v27.4s, v24.4s, v25.4s                /* CB even limbs packed */
    umull    x27, w0, w16
    usra    v22.2d, v21.2d, #25                   /* h2 += h1 >> 25 */
    umaddl    x28, w0, w17, x28
    and    v21.16b, v21.16b, v15.16b
    mul    w0, w6, w30                            /* w0 = 19*B[6] */
    trn1    v28.4s, v28.4s, v29.4s                /* pack {h8,h9} for reassembly */
    umaddl    x22, w1, w10, x22
    usra    v23.2d, v22.2d, #26
    umaddl    x23, w1, w11, x23
    and    v22.16b, v22.16b, v30.16b
    umaddl    x24, w10, w12, x24
    ldr    b0, [sp, #8]                           /* load L0 bias adjustment byte */
    umaddl    x25, w1, w13, x25
    uzp1    v20.4s, v20.4s, v21.4s
    umaddl    x26, w10, w14, x26
    uzp1    v21.4s, v22.4s, v23.4s
    umaddl    x27, w1, w15, x27
    mov    v29.d[0], v28.d[1]
    umaddl    x28, w10, w16, x28
    uzp1    v24.4s, v20.4s, v21.4s
    umaddl    x19, w1, w17, x19
    uzp2    v25.4s, v20.4s, v21.4s
    /* ---- 3.3 Result Reassembly: DA+CB, DA-CB ----------------------------
     *
     * NEON carry propagation is done. After uzp packing:
     *   v26/v28 = DA even/high limbs, v27/v29 = CB even/high limbs
     * Now compute:
     *   X3_input = DA + CB       (for squaring -> X3')
     *   Z3_input = DA - CB + bias (for squaring -> (DA-CB)^2, then * u -> Z3')
     *
     * Both are interleaved via zip for the next squaring kernel.
     * GPR continues BB squaring concurrently. */
    mul    w1, w8, w30
    add    v11.4s, v26.4s, v19.4s                 /* DA + bias (limbs 4..7) */
    umaddl    x24, w2, w2, x24
    add    v12.2s, v28.2s, v19.2s                 /* DA + bias (limbs 8,9) */
    umaddl    x25, w2, w12, x25
    mov    v19.b[0], v0.b[0]                      /* patch L0 bias byte */
    umaddl    x26, w2, w13, x26
    add    v20.4s, v24.4s, v25.4s                 /* DA + CB (limbs 0..3) */
    umaddl    x27, w2, w14, x27
    add    v21.4s, v26.4s, v27.4s                 /* DA + CB (limbs 4..7) */
    umaddl    x28, w2, w15, x28
    add    v22.2s, v28.2s, v29.2s                 /* DA + CB (limbs 8,9) */
    umaddl    x19, w2, w16, x19
    add    v10.4s, v24.4s, v19.4s                 /* DA + L0-adj bias (limbs 0..3) */
    umaddl    x26, w3, w12, x26
    sub    v11.4s, v11.4s, v27.4s                 /* (DA+bias) - CB = DA-CB+4p (limbs 4..7) */
    umaddl    x27, w3, w13, x27
    sub    v10.4s, v10.4s, v25.4s                 /* DA-CB+4p (limbs 0..3) */
    umaddl    x28, w12, w14, x28
    sub    v12.2s, v12.2s, v29.2s                 /* DA-CB+4p (limbs 8,9) */
    umaddl    x19, w3, w15, x19
    /* zip interleave: {DA-CB[i], DA+CB[i]} for dual squaring */
    zip1    v0.4s, v10.4s, v20.4s                 /* even lanes: (DA-CB, DA+CB) limbs 0..1 */
    umaddl    x26, w1, w8, x26
    zip2    v2.4s, v10.4s, v20.4s                 /* limbs 2..3 */
    umaddl    x22, w0, w6, x22
    zip1    v4.4s, v11.4s, v21.4s                 /* limbs 4..5 */
    add    x19, x19, x28, lsr #26
    zip2    v6.4s, v11.4s, v21.4s
    umaddl    x20, w5, w14, x20
    zip1    v8.2s, v12.2s, v22.2s
    add    x20, x20, x19, lsr #25
    zip2    v9.2s, v12.2s, v22.2s
    /* ---- 3.4 Squaring Kernel #2 -----------------------------------------
     *
     * NEON: (DA+CB)^2 -> X3'  and  (DA-CB)^2 (later * u -> Z3')
     *       v0-v9 hold interleaved input, shl doubles for 2*f_i*f_j terms
     *
     * GPR:  BB = B*B (second squaring, loads B from sp+56..88)
     *       Then E = AA - BB + 4p (biased sub) and Z2' setup via a24*E
     *
     * GPR carry for BB squaring finishes here (mod-p wrap h9->h0).
     * AA was stored to sp+16..48 earlier; BB result remains in GPR. */
    bic    x2, x19, #0x1ffffff                    /* x2 = BB h9 excess (bit 25+, low 25 cleared) */
    mov    v1.d[0], v0.d[1]                       /* unpack zip: odd lanes for squaring */
    add    x20, x20, x2, lsr #24                  /* h0 += excess*19 (mod p reduction) */
    mov    v3.d[0], v2.d[1]
    and    x19, x19, #0x1ffffff
    mov    v5.d[0], v4.d[1]
    add    x20, x20, x2, lsr #21                  /* 19 = 16+2+1 via shifted adds */
    mov    v7.d[0], v6.d[1]
    umaddl    x24, w7, w16, x24
    /* NEON: 2*f[i] precompute for squaring cross-terms 2*fi*fj */
    shl    v19.2s, v9.2s, #1                      /* 2*f9 */
    add    x2, x10, x10
    shl    v18.2s, v8.2s, #1                      /* 2*f8 */
    add    x3, x12, x12
    shl    v17.2s, v7.2s, #1                      /* 2*f7 */
    add    x4, x14, x14
    shl    v16.2s, v6.2s, #1                      /* 2*f6 */
    add    x5, x16, x16
    shl    v10.2s, v5.2s, #1                      /* 2*f5 */
    umaddl    x20, w0, w13, x20
    shl    v14.2s, v4.2s, #1                      /* 2*f4 */
    umaddl    x21, w0, w14, x21
    shl    v13.2s, v3.2s, #1                      /* 2*f3 */
    and    x28, x28, #0x3ffffff
    shl    v12.2s, v2.2s, #1                      /* 2*f2 */
    umaddl    x20, w7, w3, x20
    shl    v11.2s, v1.2s, #1                      /* 2*f1 */
    umaddl    x21, w7, w13, x21
    /* -- NEON sq_h9: f0*2f9 + f1*2f8 + f2*2f7 + f3*2f6 + f4*2f5 --------- */
    umull    v29.2d, v0.2s, v19.2s
    umaddl    x22, w7, w4, x22
    umlal    v29.2d, v1.2s, v18.2s
    umaddl    x23, w7, w15, x23
    umlal    v29.2d, v2.2s, v17.2s
    umaddl    x20, w1, w11, x20
    umlal    v29.2d, v3.2s, v16.2s
    umaddl    x21, w1, w12, x21
    umlal    v29.2d, v4.2s, v10.2s
    umaddl    x22, w1, w13, x22
    /* -- NEON sq_h8: f0*2f8 + 2f1*2f7 + f2*2f6 + 2f3*2f5 + f4^2 --------- */
    umull    v28.2d, v0.2s, v18.2s
    umaddl    x23, w1, w14, x23
    umlal    v28.2d, v11.2s, v17.2s
    umaddl    x24, w1, w15, x24
    umlal    v28.2d, v2.2s, v16.2s
    umaddl    x25, w1, w16, x25
    umlal    v28.2d, v13.2s, v10.2s
    umaddl    x20, w9, w2, x20
    umlal    v28.2d, v4.2s, v4.2s                 /* f4^2: squaring's unique diagonal term */
    umaddl    x21, w9, w11, x21
    mul    v4.2s, v9.2s, v31.2s                   /* 19*f9: for wrap-around terms */
    umaddl    x22, w9, w3, x22
    /* -- NEON sq_h7: f0*2f7 + f1*2f6 + f2*2f5 + f3*2f4 (+ fold later) --- */
    umull    v27.2d, v0.2s, v17.2s
    umaddl    x23, w9, w13, x23
    umlal    v27.2d, v1.2s, v16.2s
    umaddl    x24, w9, w4, x24
    umlal    v27.2d, v2.2s, v10.2s
    umaddl    x25, w9, w15, x25
    umlal    v27.2d, v3.2s, v14.2s
    umaddl    x26, w9, w5, x26
    umlal    v28.2d, v4.2s, v19.2s                /* sq_h8 continued: uses 19*f9 */
    umaddl    x27, w9, w17, x27
    /* -- NEON sq_h6: f0*2f6 + 2f1*2f5 + f2*2f4 + f3*2f3 (+ fold in 3.5) - */
    umull    v26.2d, v0.2s, v16.2s
    /* -- GPR: BB carry chain h0->h1->...->h9, pack via bfi --------------- */
    add    x1, x21, x20, lsr #26                  /* h1 += h0 >> 26 */
    umlal    v26.2d, v11.2s, v10.2s
    and    x0, x20, #0x3ffffff
    umlal    v26.2d, v2.2s, v14.2s
    add    x2, x22, x1, lsr #25
    umlal    v26.2d, v13.2s, v3.2s
    bfi    x0, x1, #32, #25                       /* pack {BB[0], BB[1]} */
    /* -- NEON sq_h5: f0*2f5 + f1*2f4 + f2*2f3 (+ fold in 3.5) ------------ */
    umull    v25.2d, v0.2s, v10.2s
    add    x3, x23, x2, lsr #26
    umlal    v25.2d, v1.2s, v14.2s
    and    x2, x2, #0x3ffffff
    umlal    v25.2d, v2.2s, v13.2s
    add    x4, x24, x3, lsr #25
    /* -- NEON sq_h4: f0*2f4 + 2f1*2f3 + f2^2 (+ fold in 3.5) ------------ */
    umull    v24.2d, v0.2s, v14.2s
    bfi    x2, x3, #32, #25                       /* pack {BB[2], BB[3]} */
    umlal    v24.2d, v11.2s, v13.2s
    add    x5, x25, x4, lsr #26
    umlal    v24.2d, v2.2s, v2.2s                 /* f2^2: diagonal term */
    and    x4, x4, #0x3ffffff
    /* -- NEON sq_h3: f0*2f3 + f1*2f2 (+ fold in 3.5) -------------------- */
    umull    v23.2d, v0.2s, v13.2s
    add    x6, x26, x5, lsr #25
    umlal    v23.2d, v1.2s, v12.2s
    bfi    x4, x5, #32, #25                       /* pack {BB[4], BB[5]} */
    /* -- NEON sq_h2: f0*2f2 + f1*2f1 (+ fold in 3.5) -------------------- */
    umull    v22.2d, v0.2s, v12.2s
    add    x7, x27, x6, lsr #26
    umlal    v22.2d, v11.2s, v1.2s
    and    x6, x6, #0x3ffffff
    /* -- NEON sq_h1: f0*2f1 (+ fold in 3.5) ------------------------------ */
    umull    v21.2d, v0.2s, v11.2s
    add    x8, x28, x7, lsr #25
    /* -- NEON sq_h0: starts with f0^2; remaining 19*fi terms added in 3.5  */
    umull    v20.2d, v0.2s, v0.2s
    bfi    x6, x7, #32, #25                       /* pack {BB[6], BB[7]} */
    /* -- NEON: carry propagation h8->h9 then mod-p wrap h9->h0 ----------- */
    usra    v29.2d, v28.2d, #26                   /* h9 += h8 >> 26 */
    add    x9, x19, x8, lsr #26
    and    v28.16b, v28.16b, v30.16b
    and    x8, x8, #0x3ffffff
    mul    v3.2s, v8.2s, v31.2s                   /* 19*f8: for h0 wrap-around terms */
    bfi    x8, x9, #32, #26                       /* pack {BB[8], BB[9]} */
    /* NEON: mod-p wrap — excess(h9) * 19 via shifted adds */
    bic    v19.16b, v29.16b, v15.16b              /* v19 = excess bits of h9 */
    and    x1, x1, #0x1ffffff                     /* clean up odd BB limbs for store */
    and    v9.16b, v29.16b, v15.16b               /* h9 &= 25-bit mask */
    and    x3, x3, #0x1ffffff
    usra    v20.2d, v19.2d, #25                   /* h0 += excess * 1 */
    and    x5, x5, #0x1ffffff
    mul    v2.2s, v7.2s, v31.2s                   /* 19*f7 */
    and    x7, x7, #0x1ffffff
    usra    v20.2d, v19.2d, #24                   /* h0 += excess * 2 */
    /* GPR: store BB result to sp+56..88 (X2' = AA*BB will read from here) */
    stp    x0, x2, [sp, #56]                      /* BB[0,1], BB[2,3] */
    mul    v1.2s, v6.2s, v31.2s                   /* 19*f6 */
    stp    x4, x6, [sp, #56+16]                   /* BB[4,5], BB[6,7] */
    usra    v20.2d, v19.2d, #21                   /* h0 += excess * 16; (1+2+16=19) done */
    str    x8, [sp, #56+32]                       /* BB[8,9] */
    mul    v0.2s, v5.2s, v31.2s                   /* 19*f5: last wrap-around precompute */

    /* -- 3.4/3.5 transition: sq_h0 split + pipeline switch ----------------
     *   NEON: sq_h0 started with f0^2 (line 1047), wrap added above;
     *         remaining 5 fold-back umlal deferred to 3.5 (19*fN ready now)
     *   GPR:  BB stored to [sp+56]; switches to E=AA-BB+4p (loads AA)
     * -------------------------------------------------------------------- */

    /* ---- 3.5 E = AA - BB + 4p (biased sub), then Z2' = E*(BB+a24*E) -----
     *
     * GPR: load AA from sp+16, build bias 0x07FFFFFE_07FFFFFC in x21,
     *       compute E[i] = AA[i] + bias - BB[i] for each limb pair.
     *       Then multiply E by (BB + a24*E) where a24 = 121666 = 0x1DB42.
     *
     * NEON: continues (DA-CB)^2 / (DA+CB)^2 squaring concurrently. */
    mov    x21, #0xfffc                           /* build standard bias in x21 */
    shl    v5.2s, v11.2s, #1
    movk    x21, #0x07ff, lsl #16                 /* x21 = 0x07FFFFFE_07FFFFFC */
    movk    x21, #0xfffe, lsl #32
    movk    x21, #0x07ff, lsl #48
    ldr    x10, [sp, #16]                         /* load AA[0,1] */
    shl    v7.2s, v13.2s, #1
    ldr    x12, [sp, #16+8]                       /* load AA[2,3] */
    shl    v19.2s, v10.2s, #1
    ldr    x14, [sp, #16+16]                      /* load AA[4,5] */
    shl    v11.2s, v17.2s, #1
    ldr    x16, [sp, #16+24]                      /* load AA[6,7] */
    /* sq_h0 continued: fold-back terms (v0-v4 now hold 19*fN, see 3.4 mul chain) */
    umlal    v20.2d, v0.2s, v10.2s                /* h0 += 19*f5 * 2*f5 = 38*f5^2  */
    ldr    x19, [sp, #16+32]                      /* load AA[8,9] */
    umlal    v20.2d, v4.2s, v5.2s                 /* h0 += 19*f9 * 4*f1 = 76*f1*f9 */
    add    x12, x12, x21                          /* AA[2,3] += standard bias */
    umlal    v20.2d, v3.2s, v12.2s                /* h0 += 19*f8 * 2*f2 = 38*f2*f8 */
    add    x14, x14, x21                          /* AA[4,5] += standard bias */
    umlal    v20.2d, v2.2s, v7.2s                 /* h0 += 19*f7 * 4*f3 = 76*f3*f7 */
    add    x16, x16, x21                          /* AA[6,7] += standard bias */
    umlal    v20.2d, v1.2s, v14.2s                /* h0 += 19*f6 * 2*f4 = 38*f4*f6 */
    add    x19, x19, x21                          /* AA[8,9] += standard bias */
    umlal    v21.2d, v4.2s, v12.2s
    movk    x21, #0xffb4                          /* patch L0: x21 low 16 bits -> 0xFFB4 */
    umlal    v21.2d, v3.2s, v13.2s
    add    x10, x10, x21                          /* AA[0,1] += L0-adjusted bias */
    umlal    v21.2d, v2.2s, v14.2s
    /* E = (AA + bias) - BB = AA - BB + 4p (mod p) */
    sub    x10, x10, x0                           /* E[0,1] = AA[0,1]+bias - BB[0,1] */
    umlal    v21.2d, v1.2s, v10.2s
    sub    x12, x12, x2                           /* E[2,3] */
    umlal    v22.2d, v1.2s, v6.2s
    sub    x14, x14, x4                           /* E[4,5] */
    umlal    v22.2d, v4.2s, v7.2s
    sub    x16, x16, x6                           /* E[6,7] */
    umlal    v22.2d, v3.2s, v14.2s
    sub    x19, x19, x8                           /* E[8,9] */
    umlal    v22.2d, v2.2s, v19.2s
    /* GPR: zero-extend BB even limbs — mov wN,wN clears upper 32 bits of xN,
     * so subsequent umaddl sees clean 32-bit values in BB[even] */
    mov    w0, w0                                 /* BB[0] zero-extend */
    usra    v21.2d, v20.2d, #26                   /* NEON: sq carry h1 += h0>>26 */
    mov    w2, w2                                 /* BB[2] */
    umlal    v23.2d, v4.2s, v14.2s
    mov    w4, w4                                 /* BB[4] */
    umlal    v23.2d, v3.2s, v10.2s
    mov    w6, w6                                 /* BB[6] */
    umlal    v23.2d, v2.2s, v16.2s
    mov    w8, w8                                 /* BB[8] */
    usra    v22.2d, v21.2d, #25
    /* GPR: split packed E[i] pairs into individual limbs for a24 multiply */
    lsr    x11, x10, #32                          /* E[1] */
    umlal    v24.2d, v2.2s, v17.2s
    lsr    x13, x12, #32                          /* E[3] */
    umlal    v24.2d, v4.2s, v19.2s
    lsr    x15, x14, #32                          /* E[5] */
    umlal    v24.2d, v3.2s, v16.2s
    lsr    x17, x16, #32                          /* E[7] */
    usra    v23.2d, v22.2d, #26
    lsr    x20, x19, #32                          /* E[9] */
    umlal    v25.2d, v4.2s, v16.2s
    /* a24 = (486662+2)/4 = 121666 = 0x1DB42: curve25519 parameter */
    mov    x21, #0xDB42
    umlal    v25.2d, v3.2s, v17.2s
    movk    x21, #0x1, lsl #16                    /* x21 = 0x1DB42 = 121666 */
    /* Z2' = E * (BB + a24*E): multiply each E limb by a24, add to BB */
    umaddl    x9, w20, w21, x9                    /* BB[9] += E[9] * a24 */
    usra    v24.2d, v23.2d, #25
    umaddl    x0, w10, w21, x0                    /* BB[0] += E[0] * a24 */
    umlal    v26.2d, v3.2s, v8.2s
    umaddl    x1, w11, w21, x1
    umlal    v26.2d, v4.2s, v11.2s
    umaddl    x2, w12, w21, x2
    usra    v25.2d, v24.2d, #26
    /* GPR: mod-p wrap for (BB+a24*E): h9->h0 via 19 = 1 + 2 + 16 */
    lsr    x22, x9, #25                           /* x22 = excess bits of h9 */
    umlal    v27.2d, v4.2s, v18.2s
    umaddl    x3, w13, w21, x3
    and    v4.16b, v24.16b, v30.16b
    and    x9, x9, #0x1ffffff                     /* h9 &= 25-bit mask */
    usra    v26.2d, v25.2d, #25
    umaddl    x4, w14, w21, x4                    /* BB[4] += E[4]*a24 */
    and    v5.16b, v25.16b, v15.16b
    add    x0, x0, x22                            /* h0 += excess * 1 */
    and    v0.16b, v20.16b, v30.16b               /* NEON: sq h0 &= 26-bit mask */
    umaddl    x5, w15, w21, x5                    /* BB[5] += E[5]*a24 */
    usra    v27.2d, v26.2d, #26
    add    x0, x0, x22, lsl #1                    /* h0 += excess * 2 */
    and    v6.16b, v26.16b, v30.16b
    umaddl    x6, w16, w21, x6                    /* BB[6] += E[6]*a24 */
    and    v1.16b, v21.16b, v15.16b
    add    x0, x0, x22, lsl #4                    /* h0 += excess * 16; total = 19 */
    usra    v28.2d, v27.2d, #25
    umaddl    x7, w17, w21, x7
    and    v7.16b, v27.16b, v15.16b
    umaddl    x8, w19, w21, x8                    /* BB[8] += E[8]*a24 (last limb) */
    and    v2.16b, v22.16b, v30.16b
    /* GPR: set up base pointers for ld2 reload (dual fe_mul inputs)
     *   x26 -> sp+136: base point u (constant, for Z3' = u*(DA-CB)^2)
     *   x27 -> sp+16:  AA (from 3.2, multiplicand for X2' = AA*BB)
     *   x28 -> sp+56:  BB (from 3.4, multiplicand for X2' = AA*BB) */
    add    x26, sp, #136
    usra    v9.2d, v28.2d, #26                    /* NEON: sq carry h9 += h8>>26 */
    add    x27, sp, #16
    and    v8.16b, v28.16b, v30.16b
    add    x28, sp, #56
    and    v3.16b, v23.16b, v15.16b
    /* GPR: carry chain for (BB+a24*E) h0->h1->...->h9
     * NEON: ld2 reload for dual fe_mul: AA*BB -> X2' and u*(DA-CB)^2 -> Z3'
     *   [1] lane = AA (x27) and BB (x28) as multiplicands for X2'
     *   [0] lane = base point u (x26) for Z3' multiply */
    add    x1, x1, x0, lsr #26                    /* h1 += h0 >> 26 */
    ld2    { v0.s, v1.s }[1], [x27], #8           /* AA[0,1] lane 1 */
    and    x0, x0, #0x3ffffff
    ld2    { v10.s, v11.s }[1], [x28], #8         /* BB[0,1] lane 1 */
    add    x2, x2, x1, lsr #25
    ld2    { v10.s, v11.s }[0], [x26], #8         /* u[0,1] (base point) */
    and    x1, x1, #0x1ffffff
    ld2    { v2.s, v3.s }[1], [x27], #8
    add    x3, x3, x2, lsr #26
    ld2    { v12.s, v13.s }[1], [x28], #8
    and    x2, x2, #0x3ffffff
    ld2    { v12.s, v13.s }[0], [x26], #8
    add    x4, x4, x3, lsr #25
    ld2    { v4.s, v5.s }[1], [x27], #8
    and    x3, x3, #0x1ffffff
    ld2    { v14.s, v15.s }[1], [x28], #8
    add    x5, x5, x4, lsr #26
    ld2    { v14.s, v15.s }[0], [x26], #8
    and    x4, x4, #0x3ffffff
    ld2    { v6.s, v7.s }[1], [x27], #8
    add    x6, x6, x5, lsr #25
    ld2    { v16.s, v17.s }[1], [x28], #8
    and    x5, x5, #0x1ffffff
    ld2    { v16.s, v17.s }[0], [x26], #8
    add    x7, x7, x6, lsr #26
    ld2    { v8.s, v9.s }[1], [x27], #8
    and    x6, x6, #0x3ffffff
    ld2    { v18.s, v19.s }[1], [x28], #8
    add    x8, x8, x7, lsr #25
    ld2    { v18.s, v19.s }[0], [x26], #8
    and    x7, x7, #0x1ffffff
    /* -- NEON+GPR: fe_mul #2 — Z3' = u*(DA-CB)^2, Z2' = E*(BB+a24*E) ----
     *
     * NEON: h[0..9] of u * (DA-CB)^2 — same 10-product structure as 3.2
     * GPR:  h[0..9] of E * (BB+a24*E) — full fe_mul, ~140 instructions
     *
     * Note: NEON h9 terms are issued in a different order for scheduling;
     * the limb/register mapping is standard (v0-v9 / v10-v19). */
    /* -- NEON h9: f0*g9 + f2*g7 + f4*g5 + f6*g3 + f8*g1 (+ odd terms) -- */
    umull    v29.2d, v6.2s, v13.2s
    add    x9, x9, x8, lsr #26
    umlal    v29.2d, v4.2s, v15.2s
    and    x8, x8, #0x3ffffff
    umlal    v29.2d, v0.2s, v19.2s
    /* -- GPR: Z2' = E * (BB+a24*E) product accumulation ------------------- */
    umull    x21, w1, w19
    umlal    v29.2d, v2.2s, v17.2s
    umull    x22, w1, w17
    umlal    v29.2d, v8.2s, v11.2s
    umull    x23, w1, w16
    mul    v19.2s, v19.2s, v31.2s                 /* g9 *= 19 */
    umull    x24, w1, w15
    /* -- NEON h8: f1*g7 + f3*g5 + f5*g3 + f7*g1 + f9*19g9 (odd, *2 later) */
    umull    v28.2d, v1.2s, v17.2s
    umaddl    x21, w3, w16, x21
    umlal    v28.2d, v3.2s, v15.2s
    umaddl    x22, w3, w15, x22
    umlal    v28.2d, v5.2s, v13.2s
    umaddl    x23, w3, w14, x23
    umlal    v28.2d, v7.2s, v11.2s
    umaddl    x24, w3, w13, x24
    umlal    v28.2d, v9.2s, v19.2s
    umaddl    x21, w5, w14, x21
    umlal    v29.2d, v1.2s, v18.2s
    umaddl    x22, w5, w13, x22
    umlal    v29.2d, v3.2s, v16.2s
    umaddl    x23, w5, w12, x23
    umlal    v29.2d, v5.2s, v14.2s
    umaddl    x24, w5, w11, x24
    umlal    v29.2d, v7.2s, v12.2s
    umaddl    x21, w7, w12, x21
    umlal    v29.2d, v9.2s, v10.2s
    umaddl    x22, w7, w11, x22
    shl    v28.2d, v28.2d, #1                     /* h8 <<= 1: odd-index product *2 */
    umaddl    x23, w7, w10, x23
    /* -- NEON h7: f0*g7 + f2*g5 + f4*g3 + f6*g1 + f8*19g9 --------------- */
    umull    v27.2d, v0.2s, v17.2s
    /* GPR: 19*limb precompute for Z2' wrap-around terms */
    mul    w27, w7, w30                           /* 19*E[7] */
    umlal    v27.2d, v2.2s, v15.2s
    mul    w25, w9, w30                           /* 19*E[9] */
    umlal    v27.2d, v4.2s, v13.2s
    mul    w26, w8, w30                           /* 19*E[8] */
    umlal    v27.2d, v6.2s, v11.2s
    mul    w28, w6, w30                           /* 19*E[6] */
    umlal    v27.2d, v8.2s, v19.2s
    umaddl    x24, w27, w20, x24
    mul    v17.2s, v17.2s, v31.2s                 /* g7 *= 19 */
    umaddl    x21, w9, w10, x21
    /* h8 continued: even-index terms */
    umlal    v28.2d, v0.2s, v18.2s
    umaddl    x22, w25, w20, x22
    umlal    v28.2d, v2.2s, v16.2s
    umaddl    x23, w25, w19, x23
    umlal    v28.2d, v4.2s, v14.2s
    umaddl    x24, w25, w17, x24
    umlal    v28.2d, v6.2s, v12.2s
    /* GPR: odd-index accumulators doubled (x = x + x is shl #1) */
    add    x22, x22, x22                          /* Z2'[h8] *= 2 */
    umlal    v28.2d, v8.2s, v10.2s
    umaddl    x21, w0, w20, x21
    mul    v18.2s, v18.2s, v31.2s                 /* g8 *= 19 */
    add    x24, x24, x24                          /* Z2'[h6] *= 2 */
    /* -- NEON h6: f1*g5 + f3*g3 + f5*g1 + f7*19g9 + f9*19g7 (odd, *2) -- */
    umull    v26.2d, v1.2s, v15.2s
    umaddl    x22, w0, w19, x22
    umlal    v26.2d, v3.2s, v13.2s
    umaddl    x23, w0, w17, x23
    umlal    v26.2d, v5.2s, v11.2s
    umaddl    x24, w0, w16, x24
    umlal    v26.2d, v7.2s, v19.2s
    umaddl    x21, w2, w17, x21
    umlal    v26.2d, v9.2s, v17.2s
    umaddl    x22, w2, w16, x22
    umlal    v27.2d, v1.2s, v16.2s
    umaddl    x23, w2, w15, x23
    umlal    v27.2d, v3.2s, v14.2s
    umaddl    x24, w2, w14, x24
    umlal    v27.2d, v5.2s, v12.2s
    umaddl    x21, w4, w15, x21
    umlal    v27.2d, v7.2s, v10.2s
    umaddl    x22, w4, w14, x22
    umlal    v27.2d, v9.2s, v18.2s
    umaddl    x23, w4, w13, x23
    shl    v26.2d, v26.2d, #1                     /* h6 <<= 1 */
    umaddl    x24, w4, w12, x24
    /* -- NEON h5: f0*g5 + f2*g3 + f4*g1 + f6*19g9 + f8*19g7 ------------- */
    umull    v25.2d, v0.2s, v15.2s
    umaddl    x21, w6, w13, x21
    umlal    v25.2d, v2.2s, v13.2s
    umaddl    x22, w6, w12, x22
    umlal    v25.2d, v4.2s, v11.2s
    umaddl    x23, w6, w11, x23
    umlal    v25.2d, v6.2s, v19.2s
    umaddl    x24, w6, w10, x24
    umlal    v25.2d, v8.2s, v17.2s
    umaddl    x21, w8, w11, x21
    mul    v15.2s, v15.2s, v31.2s                 /* g5 *= 19 */
    umaddl    x22, w8, w10, x22
    /* h6 continued: even-index terms */
    umlal    v26.2d, v0.2s, v16.2s
    umaddl    x23, w26, w20, x23
    umlal    v26.2d, v2.2s, v14.2s
    umaddl    x24, w26, w19, x24
    umlal    v26.2d, v4.2s, v12.2s
    umull    x6, w25, w16
    umlal    v26.2d, v6.2s, v10.2s
    umull    x7, w25, w15
    umlal    v26.2d, v8.2s, v18.2s
    umull    x8, w25, w14
    mul    v16.2s, v16.2s, v31.2s                 /* g6 *= 19 */
    umaddl    x6, w5, w10, x6
    /* -- NEON h4: f1*g3 + f3*g1 + f5*19g9 + f7*19g7 + f9*19g5 (odd, *2) */
    umull    v24.2d, v1.2s, v13.2s
    mul    w5, w5, w30
    umlal    v24.2d, v3.2s, v11.2s
    umaddl    x7, w27, w17, x7
    umlal    v24.2d, v5.2s, v19.2s
    umaddl    x8, w27, w16, x8
    umlal    v24.2d, v7.2s, v17.2s
    umaddl    x6, w27, w19, x6
    umlal    v24.2d, v9.2s, v15.2s
    umaddl    x7, w5, w20, x7
    umlal    v25.2d, v1.2s, v14.2s
    umaddl    x8, w5, w19, x8
    umlal    v25.2d, v3.2s, v12.2s
    umaddl    x6, w3, w12, x6
    umlal    v25.2d, v5.2s, v10.2s
    umaddl    x7, w3, w11, x7
    umlal    v25.2d, v7.2s, v18.2s
    umaddl    x8, w3, w10, x8
    umlal    v25.2d, v9.2s, v16.2s
    umaddl    x6, w1, w14, x6
    shl    v24.2d, v24.2d, #1                     /* h4 <<= 1 */
    umaddl    x7, w1, w13, x7
    /* -- NEON h3: f0*g3 + f2*g1 + f4*19g9 + f6*19g7 + f8*19g5 ----------- */
    umull    v23.2d, v0.2s, v13.2s
    umaddl    x8, w1, w12, x8
    umlal    v23.2d, v2.2s, v11.2s
    mul    w9, w4, w30
    umlal    v23.2d, v4.2s, v19.2s
    add    x7, x7, x7
    umlal    v23.2d, v6.2s, v17.2s
    umaddl    x6, w26, w17, x6
    umlal    v23.2d, v8.2s, v15.2s
    umaddl    x7, w26, w16, x7
    mul    v13.2s, v13.2s, v31.2s                 /* g3 *= 19 */
    umaddl    x8, w26, w15, x8
    /* h4 continued: even-index terms */
    umlal    v24.2d, v0.2s, v14.2s
    umaddl    x6, w28, w20, x6
    umlal    v24.2d, v2.2s, v12.2s
    umaddl    x7, w28, w19, x7
    umlal    v24.2d, v4.2s, v10.2s
    umaddl    x8, w28, w17, x8
    umlal    v24.2d, v6.2s, v18.2s
    umaddl    x6, w4, w11, x6
    umlal    v24.2d, v8.2s, v16.2s
    umaddl    x7, w4, w10, x7
    mul    v14.2s, v14.2s, v31.2s                 /* g4 *= 19 */
    umaddl    x8, w9, w20, x8
    /* -- NEON h2: f1*g1 + f3*19g9 + f5*19g7 + f7*19g5 + f9*19g3 (odd, *2) */
    umull    v22.2d, v1.2s, v11.2s
    umaddl    x6, w2, w13, x6
    umlal    v22.2d, v3.2s, v19.2s
    umaddl    x7, w2, w12, x7
    umlal    v22.2d, v5.2s, v17.2s
    umaddl    x8, w2, w11, x8
    umlal    v22.2d, v7.2s, v15.2s
    umaddl    x6, w0, w15, x6
    umlal    v22.2d, v9.2s, v13.2s
    umaddl    x7, w0, w14, x7
    umlal    v23.2d, v1.2s, v12.2s
    umaddl    x8, w0, w13, x8
    umlal    v23.2d, v3.2s, v10.2s
    mul    w4, w3, w30                            /* 19*E[3] (reuse w4) */
    umlal    v23.2d, v5.2s, v18.2s
    /* -- GPR: Z2' carry chain h4->h5->h6->h7->h8->h9 (forward) ---------- */
    add    x6, x6, x7, lsr #26
    umlal    v23.2d, v7.2s, v16.2s
    and    x7, x7, #0x3ffffff
    umlal    v23.2d, v9.2s, v14.2s
    add    x24, x24, x6, lsr #25
    shl    v22.2d, v22.2d, #1                     /* h2 <<= 1 */
    and    x6, x6, #0x1ffffff
    /* -- NEON h1: f0*g1 + f2*19g9 + f4*19g7 + f6*19g5 + f8*19g3 --------- */
    umull    v21.2d, v0.2s, v11.2s
    add    x23, x23, x24, lsr #26
    umlal    v21.2d, v2.2s, v19.2s
    and    x24, x24, #0x3ffffff
    umlal    v21.2d, v4.2s, v17.2s
    add    x22, x22, x23, lsr #25
    umlal    v21.2d, v6.2s, v15.2s
    bfi    x24, x23, #32, #25
    umlal    v21.2d, v8.2s, v13.2s
    add    x21, x21, x22, lsr #26
    mul    v11.2s, v11.2s, v31.2s                 /* g1 *= 19 */
    and    x22, x22, #0x3ffffff
    /* h2 continued: even-index terms */
    umlal    v22.2d, v0.2s, v12.2s
    /* GPR: Z2' mod-p wrap: excess(h9) * 19 folded back to h0 */
    bic    x3, x21, #0x3ffffff                    /* x3 = excess bits of h9 */
    umlal    v22.2d, v2.2s, v10.2s
    lsr    x23, x3, #26
    umlal    v22.2d, v4.2s, v18.2s
    bfi    x22, x21, #32, #26
    umlal    v22.2d, v6.2s, v16.2s
    add    x23, x23, x3, lsr #25
    umlal    v22.2d, v8.2s, v14.2s
    umull    x21, w25, w13
    mul    v12.2s, v12.2s, v31.2s                 /* g2 *= 19 (last wrap precompute) */
    add    x23, x23, x3, lsr #22                  /* += excess*16; (1+2+16=19) done */
    /* -- NEON h0: f1*19g9 + f3*19g7 + f5*19g5 + f7*19g3 + f9*19g1 (odd, *2) */
    umull    v20.2d, v1.2s, v19.2s
    umull    x3, w25, w12
    umlal    v20.2d, v3.2s, v17.2s
    umaddl    x23, w25, w11, x23
    umlal    v20.2d, v5.2s, v15.2s
    umaddl    x21, w27, w15, x21
    ushr    v15.2d, v30.2d, #1                    /* 25-bit mask = v30 >> 1 */
    umaddl    x3, w27, w14, x3
    /* -- NEON: carry propagation chain h2->h3->...->h9->h0 --------------- */
    usra    v23.2d, v22.2d, #26
    umaddl    x23, w27, w13, x23
    and    v22.16b, v22.16b, v30.16b
    mul    w27, w1, w30
    umlal    v21.2d, v1.2s, v10.2s
    umaddl    x3, w5, w16, x3
    usra    v24.2d, v23.2d, #25
    umaddl    x23, w5, w15, x23
    and    v23.16b, v23.16b, v15.16b
    umaddl    x21, w5, w17, x21
    umlal    v20.2d, v7.2s, v13.2s
    umaddl    x3, w4, w19, x3
    usra    v25.2d, v24.2d, #26
    umaddl    x23, w4, w17, x23
    and    v24.16b, v24.16b, v30.16b
    umaddl    x21, w4, w20, x21
    umlal    v21.2d, v3.2s, v18.2s
    umaddl    x3, w1, w10, x3
    usra    v26.2d, v25.2d, #25
    umaddl    x23, w27, w20, x23
    and    v25.16b, v25.16b, v15.16b
    umaddl    x21, w1, w11, x21
    umlal    v20.2d, v9.2s, v11.2s
    mul    w25, w2, w30
    usra    v27.2d, v26.2d, #26
    add    x23, x23, x23
    and    v26.16b, v26.16b, v30.16b
    add    x21, x21, x21
    umlal    v21.2d, v5.2s, v16.2s
    umaddl    x23, w26, w12, x23
    umlal    v21.2d, v7.2s, v14.2s
    umaddl    x3, w26, w13, x3
    umlal    v21.2d, v9.2s, v12.2s
    umaddl    x21, w26, w14, x21
    usra    v28.2d, v27.2d, #25
    umaddl    x23, w28, w14, x23
    and    v27.16b, v27.16b, v15.16b
    umaddl    x3, w28, w15, x3
    shl    v20.2d, v20.2d, #1                     /* h0 <<= 1: odd-index product *2 */
    umaddl    x21, w28, w16, x21
    usra    v29.2d, v28.2d, #26                   /* h9 += h8 >> 26 */
    umaddl    x23, w9, w16, x23
    and    v28.16b, v28.16b, v30.16b
    umaddl    x3, w9, w17, x3
    /* h0 continued: even-index terms */
    umlal    v20.2d, v0.2s, v10.2s
    umaddl    x21, w9, w19, x21
    umlal    v20.2d, v2.2s, v18.2s
    umaddl    x23, w25, w19, x23
    umlal    v20.2d, v4.2s, v16.2s
    umaddl    x3, w25, w20, x3
    umlal    v20.2d, v6.2s, v14.2s
    umaddl    x21, w2, w10, x21
    umlal    v20.2d, v8.2s, v12.2s
    umaddl    x23, w0, w10, x23
    /* NEON: mod-p wrap — excess(h9) * 19 via shifted adds */
    bic    v19.16b, v29.16b, v15.16b              /* v19 = excess bits of h9 */
    umaddl    x3, w0, w11, x3
    and    v29.16b, v29.16b, v15.16b              /* h9 &= 25-bit mask */
    umaddl    x21, w0, w12, x21
    usra    v20.2d, v19.2d, #25                   /* h0 += excess * 1 */
    /* GPR: Z2' carry chain final pass */
    add    x3, x3, x23, lsr #26
    /* NEON: trn1 repacks squaring output; d[0]=(DA-CB)^2 input, d[1]=X3' preserved */
    trn1    v0.4s, v0.4s, v1.4s
    and    x23, x23, #0x3ffffff
    usra    v20.2d, v19.2d, #24                   /* h0 += excess * 2 */
    add    x21, x21, x3, lsr #25
    trn1    v1.4s, v2.4s, v3.4s
    bfi    x23, x3, #32, #25
    usra    v20.2d, v19.2d, #21                   /* h0 += excess * 16; (1+2+16=19) done */
    add    x8, x8, x21, lsr #26
    trn1    v2.4s, v4.4s, v5.4s
    and    x21, x21, #0x3ffffff
    trn1    v3.4s, v6.4s, v7.4s

    /* ---- 3.6 Loop Control + Register Writeback ----------------------------
     *
     * Bit extraction: scalar is at sp+104 (32 bytes). The counter counts
     * down from 253 to 0. Each iteration extracts bit[counter] from the
     * scalar word array and XORs with the previous bit to get swap.
     *
     * NEON: final carry for Z3'=u*(DA-CB)^2 (lane 0) and X2'=AA*BB (lane 1).
     *       trn1 repacks limb pairs into X3/Z3 and X2 register layout.
     * GPR:  final carry for Z2' completes. Results move to v1/v3/v5/v7/v9.
     * Bias: d28/d29 reloaded from stack (destroyed in section 3.1). */
    ldr    x2, [sp, #96]                          /* x2 = {prev_bit[63:32], counter[31:0]} */
    add    x7, x7, x8, lsr #25
    usra    v21.2d, v20.2d, #26
    bfi    x21, x8, #32, #25
    and    v20.16b, v20.16b, v30.16b
    trn1    v4.4s, v8.4s, v9.4s
    lsr    x3, x2, #32                            /* w3 = prev_bit */
    usra    v22.2d, v21.2d, #25
    add    x4, sp, #104                           /* x4 -> scalar[0] */
    and    v21.16b, v21.16b, v15.16b
    subs    w0, w2, #1                            /* counter-- ; sets N flag for bpl */
    trn1    v19.4s, v28.4s, v29.4s
    asr    w1, w0, #5                             /* word_index = counter >> 5 */
    usra    v23.2d, v22.2d, #26
    add    x6, x6, x7, lsr #26
    and    v22.16b, v22.16b, v30.16b
    ldr    w1, [x4, w1, sxtw #2]                  /* load scalar word[word_index] */
    trn1    v11.4s, v20.4s, v21.4s                /* repack Z3'/X2': d[0]=Z3', d[1]=X2' */
    and    w4, w0, #0x1f                          /* bit_index = counter & 31 */
    trn1    v13.4s, v22.4s, v23.4s
    and    x7, x7, #0x3ffffff
    trn1    v15.4s, v24.4s, v25.4s
    lsr    w1, w1, w4                             /* w1 = scalar_word >> bit_index */
    trn1    v17.4s, v26.4s, v27.4s
    bfi    x7, x6, #32, #26
    mov    v10.d[0], v0.d[1]                      /* extract X3'[0,1] from d[1] */
    stp    w0, w1, [sp, #96]                      /* store {counter, current_bit} */

    /* swap = current_bit XOR prev_bit (Montgomery ladder cswap condition) */
    eor    w1, w1, w3

    /* unpack X3' limb pairs from trn1 high lanes */
    mov    v12.d[0], v1.d[1]
    mov    v14.d[0], v2.d[1]
    mov    v16.d[0], v3.d[1]
    mov    v18.d[0], v4.d[1]

    /* write Z2' result from GPR to NEON (v1,v3,v5,v7,v9 = Z2 limb pairs) */
    mov    v1.d[0], x23
    mov    v3.d[0], x21
    mov    v5.d[0], x7
    mov    v7.d[0], x24
    mov    v9.d[0], x22

    /* reload bias constants (destroyed during section 3.1) */
    ldr    d28, [sp, #8]                          /* d28 = L0-adjusted bias */
    mov    v0.d[0], v11.d[1]                      /* unpack X2' from NEON lane 1 */
    ldr    d29, [sp]                              /* d29 = standard bias */
    mov    v2.d[0], v13.d[1]
    mov    v4.d[0], v15.d[1]
    mov    v6.d[0], v17.d[1]
    mov    v8.d[0], v19.d[1]

    bpl    .Lmainloop                             /* loop while counter >= 0 */

/* ============================================================================
 * SECTION 4: Binary GCD Inversion (replaces Fermat inversion)
 *
 * Compute Z2^(-1) using Binary GCD (Bernstein-Yang 2019)
 * Then compute result = X2 * Z2^(-1) mod p
 *
 * This is ~3x faster than Fermat inversion for the modular inverse.
 * ============================================================================ */

    /* Extract Z2 from NEON registers */
    mov    w0, v1.s[0]
    mov    w1, v1.s[1]
    mov    w2, v3.s[0]
    mov    w3, v3.s[1]
    mov    w4, v5.s[0]
    mov    w5, v5.s[1]
    mov    w6, v7.s[0]
    mov    w7, v7.s[1]
    mov    w8, v9.s[0]
    mov    w9, v9.s[1]

    /* Carry reduction: Emil's ladder may leave limbs wider than nominal.
     * The BGCD inversion packs fe[10] -> 5x62-bit limbs, which requires
     * each limb to be within its nominal width (26/25 bits alternating).
     * Widths: fe[0]=26, fe[1]=25, fe[2]=26, ..., fe[9]=25 */
    lsr    w10, w0, #26
    and    w0, w0, #0x3FFFFFF
    add    w1, w1, w10
    lsr    w10, w1, #25
    and    w1, w1, #0x1FFFFFF
    add    w2, w2, w10
    lsr    w10, w2, #26
    and    w2, w2, #0x3FFFFFF
    add    w3, w3, w10
    lsr    w10, w3, #25
    and    w3, w3, #0x1FFFFFF
    add    w4, w4, w10
    lsr    w10, w4, #26
    and    w4, w4, #0x3FFFFFF
    add    w5, w5, w10
    lsr    w10, w5, #25
    and    w5, w5, #0x1FFFFFF
    add    w6, w6, w10
    lsr    w10, w6, #26
    and    w6, w6, #0x3FFFFFF
    add    w7, w7, w10
    lsr    w10, w7, #25
    and    w7, w7, #0x1FFFFFF
    add    w8, w8, w10
    lsr    w10, w8, #26
    and    w8, w8, #0x3FFFFFF
    add    w9, w9, w10
    lsr    w10, w9, #25
    and    w9, w9, #0x1FFFFFF
    mov    w11, #19
    mul    w10, w10, w11
    add    w0, w0, w10
    lsr    w10, w0, #26
    and    w0, w0, #0x3FFFFFF
    add    w1, w1, w10
    lsr    w10, w1, #25
    and    w1, w1, #0x1FFFFFF
    add    w2, w2, w10
    lsr    w10, w2, #26
    and    w2, w2, #0x3FFFFFF
    add    w3, w3, w10
    lsr    w10, w3, #25
    and    w3, w3, #0x1FFFFFF
    add    w4, w4, w10
    lsr    w10, w4, #26
    and    w4, w4, #0x3FFFFFF
    add    w5, w5, w10
    lsr    w10, w5, #25
    and    w5, w5, #0x1FFFFFF
    add    w6, w6, w10
    lsr    w10, w6, #26
    and    w6, w6, #0x3FFFFFF
    add    w7, w7, w10
    lsr    w10, w7, #25
    and    w7, w7, #0x1FFFFFF
    add    w8, w8, w10
    lsr    w10, w8, #26
    and    w8, w8, #0x3FFFFFF
    add    w9, w9, w10
    lsr    w10, w9, #25
    and    w9, w9, #0x1FFFFFF
    mov    w11, #19
    mul    w10, w10, w11
    add    w0, w0, w10
    lsr    w10, w0, #26
    and    w0, w0, #0x3FFFFFF
    add    w1, w1, w10

    /* Store reduced Z2 to stack [sp+80] */
    stp    w0, w1, [sp, #80]
    stp    w2, w3, [sp, #88]
    stp    w4, w5, [sp, #96]
    stp    w6, w7, [sp, #104]
    stp    w8, w9, [sp, #112]

    /* Extract X2 from NEON registers to stack [sp+184] (save for later mul) */
    mov    w10, v0.s[0]
    mov    w11, v0.s[1]
    mov    w12, v2.s[0]
    mov    w13, v2.s[1]
    mov    w14, v4.s[0]
    mov    w15, v4.s[1]
    mov    w16, v6.s[0]
    mov    w17, v6.s[1]
    mov    w19, v8.s[0]
    mov    w20, v8.s[1]

    stp    w10, w11, [sp, #184]
    stp    w12, w13, [sp, #192]
    stp    w14, w15, [sp, #200]
    stp    w16, w17, [sp, #208]
    stp    w19, w20, [sp, #216]

    /* Call Binary GCD: .L_fe_invert(result, Z2)
     * result = sp+0 (Z2_inv output)
     * input  = sp+80 (Z2 input)
     * Using CSEL-optimized ASM version (14% faster inversion) */
    mov    x0, sp                                 /* result pointer */
    add    x1, sp, #80                            /* input pointer (Z2) */
    bl    .L_fe_invert

    /* Now compute X2 * Z2_inv using inline field multiplication */
    /* Load Z2_inv from [sp+0] */
    ldp    w10, w11, [sp]
    ldp    w12, w13, [sp, #8]
    ldp    w14, w15, [sp, #16]
    ldp    w16, w17, [sp, #24]
    ldp    w19, w20, [sp, #32]

    /* Load X2 from [sp+184] */
    ldp    w0, w1, [sp, #184]
    ldp    w2, w3, [sp, #192]
    ldp    w4, w5, [sp, #200]
    ldp    w6, w7, [sp, #208]
    ldp    w8, w9, [sp, #216]

    /* Field multiplication: X2 * Z2_inv (GPR-only 10-limb schoolbook)
     *
     * Register allocation:
     *   f[0..9] = w0..w9  (X2)
     *   g[0..9] = w10,w11,w12,w13,w14,w15,w16,w17,w19,w20  (Z2_inv)
     *   Accumulators: Phase A/B: x21-x24 (h[9..6]), x6-x8 (h[5..3])
     *                 Phase C reuses: x23,x3,x21 for h[0..2]
     *   19x: w25=19*f[9], w26=19*f[8], w27=19*f[7], w28=19*f[6]
     *
     * Odd-index doubling: for EVEN output h[k], terms with BOTH f and g
     * indices odd get coefficient 2 (from alternating 26/25-bit radix).
     * Applied via `add xN, xN, xN` before adding even-index terms. */
    mov    w30, #19

    /* --- Phase A: h[9], h[8], h[7], h[6] (odd-f x g terms first) --- */
    umull    x21, w1, w19
    umull    x22, w1, w17
    umull    x23, w1, w16
    umull    x24, w1, w15
    umaddl    x21, w3, w16, x21
    umaddl    x22, w3, w15, x22
    umaddl    x23, w3, w14, x23
    umaddl    x24, w3, w13, x24
    umaddl    x21, w5, w14, x21
    umaddl    x22, w5, w13, x22
    umaddl    x23, w5, w12, x23
    umaddl    x24, w5, w11, x24
    umaddl    x21, w7, w12, x21
    umaddl    x22, w7, w11, x22
    umaddl    x23, w7, w10, x23
    /* Precompute 19*f[i] for wrap-around terms (2^255 = 19 mod p) */
    mul    w27, w7, w30                           /* 19*f[7] */
    mul    w25, w9, w30                           /* 19*f[9] */
    mul    w26, w8, w30                           /* 19*f[8] */
    mul    w28, w6, w30                           /* 19*f[6] */
    umaddl    x24, w27, w20, x24                  /* h[6] += 19*f[7]*g[9] */
    umaddl    x21, w9, w10, x21                   /* h[9] += f[9]*g[0] */
    umaddl    x22, w25, w20, x22                  /* h[8] += 19*f[9]*g[9] */
    umaddl    x23, w25, w19, x23                  /* h[7] += 19*f[9]*g[8] */
    umaddl    x24, w25, w17, x24                  /* h[6] += 19*f[9]*g[7] */
    add    x22, x22, x22                          /* 2x odd-f terms for h[8] (even output) */
    /* Even-f terms for h[9..6] */
    umaddl    x21, w0, w20, x21                   /* h[9] += f[0]*g[9] */
    add    x24, x24, x24                          /* 2x odd-f terms for h[6] (even output) */
    umaddl    x22, w0, w19, x22                   /* h[8] += f[0]*g[8] */
    umaddl    x23, w0, w17, x23
    umaddl    x24, w0, w16, x24
    umaddl    x21, w2, w17, x21
    umaddl    x22, w2, w16, x22
    umaddl    x23, w2, w15, x23
    umaddl    x24, w2, w14, x24
    umaddl    x21, w4, w15, x21
    umaddl    x22, w4, w14, x22
    umaddl    x23, w4, w13, x23
    umaddl    x24, w4, w12, x24
    umaddl    x21, w6, w13, x21
    umaddl    x22, w6, w12, x22
    umaddl    x23, w6, w11, x23
    umaddl    x24, w6, w10, x24
    umaddl    x21, w8, w11, x21
    umaddl    x22, w8, w10, x22
    umaddl    x23, w26, w20, x23
    umaddl    x24, w26, w19, x24
    /* --- Phase B: h[5], h[4], h[3] --- */
    umull    x6, w25, w16                         /* h[5] = 19*f[9]*g[6] */
    umull    x7, w25, w15                         /* h[4] = 19*f[9]*g[5] */
    umull    x8, w25, w14                         /* h[3] = 19*f[9]*g[4] */
    umaddl    x6, w5, w10, x6                     /* h[5] += f[5]*g[0] */
    mul    w5, w5, w30                            /* 19*f[5] (replaces f[5]) */
    umaddl    x7, w27, w17, x7                    /* h[4] += 19*f[7]*g[7] */
    umaddl    x8, w27, w16, x8
    umaddl    x6, w27, w19, x6
    umaddl    x7, w5, w20, x7
    umaddl    x8, w5, w19, x8
    umaddl    x6, w3, w12, x6
    umaddl    x7, w3, w11, x7
    umaddl    x8, w3, w10, x8
    umaddl    x6, w1, w14, x6
    umaddl    x7, w1, w13, x7
    umaddl    x8, w1, w12, x8
    mul    w9, w4, w30                            /* 19*f[4] */
    add    x7, x7, x7                             /* 2x odd-f terms for h[4] (even output) */
    /* Even-f terms for h[5..3] */
    umaddl    x6, w26, w17, x6                    /* h[5] += 19*f[8]*g[7] */
    umaddl    x7, w26, w16, x7
    umaddl    x8, w26, w15, x8
    umaddl    x6, w28, w20, x6
    umaddl    x7, w28, w19, x7
    umaddl    x8, w28, w17, x8
    umaddl    x6, w4, w11, x6
    umaddl    x7, w4, w10, x7
    umaddl    x8, w9, w20, x8
    umaddl    x6, w2, w13, x6
    umaddl    x7, w2, w12, x7
    umaddl    x8, w2, w11, x8
    umaddl    x6, w0, w15, x6
    umaddl    x7, w0, w14, x7
    umaddl    x8, w0, w13, x8
    mul    w4, w3, w30                            /* 19*f[3] (replaces f[4]) */
    /* --- Carry propagation pass 1: h[4] -> h[5] -> h[6] -> h[7] -> h[8] -> h[9] --- */
    add    x6, x6, x7, lsr #26                    /* h[5] += carry from h[4] */
    and    x7, x7, #0x3ffffff                     /* h[4] &= 26 bits */
    add    x24, x24, x6, lsr #25                  /* h[6] += carry from h[5] */
    and    x6, x6, #0x1ffffff                     /* h[5] &= 25 bits */
    add    x23, x23, x24, lsr #26                 /* h[7] += carry from h[6] */
    and    x24, x24, #0x3ffffff                   /* h[6] &= 26 bits */
    add    x22, x22, x23, lsr #25                 /* h[8] += carry from h[7] */
    bfi    x24, x23, #32, #25                     /* pack h[7]:h[6] into x24 */
    add    x21, x21, x22, lsr #26                 /* h[9] += carry from h[8] */
    and    x22, x22, #0x3ffffff                   /* h[8] &= 26 bits */
    /* h[9] overflow * 19 -> h[0] (19 = 16 + 2 + 1 decomposition) */
    bic    x3, x21, #0x3ffffff                    /* x3 = h[9] overflow (bits 26+) */
    lsr    x23, x3, #26                           /* x23 = overflow * 1 */
    bfi    x22, x21, #32, #26                     /* pack h[9]:h[8] into x22 */
    add    x23, x23, x3, lsr #25                  /* x23 += overflow * 2 */
    /* --- Phase C: h[2], h[1], h[0] (interleaved with wrap carry) --- */
    umull    x21, w25, w13                        /* h[2] = 19*f[9]*g[3] */
    add    x23, x23, x3, lsr #22                  /* x23 += overflow * 16 (total: 19 * overflow) */
    umull    x3, w25, w12
    umaddl    x23, w25, w11, x23
    umaddl    x21, w27, w15, x21
    umaddl    x3, w27, w14, x3
    umaddl    x23, w27, w13, x23
    mul    w27, w1, w30
    umaddl    x3, w5, w16, x3
    umaddl    x23, w5, w15, x23
    umaddl    x21, w5, w17, x21
    umaddl    x3, w4, w19, x3
    umaddl    x23, w4, w17, x23
    umaddl    x21, w4, w20, x21
    umaddl    x3, w1, w10, x3
    umaddl    x23, w27, w20, x23
    umaddl    x21, w1, w11, x21
    mul    w25, w2, w30                           /* 19*f[2] */
    add    x23, x23, x23                          /* 2x odd-f terms for h[0] (even output) */
    add    x21, x21, x21                          /* 2x odd-f terms for h[2] (even output) */
    /* Even-f terms for h[0..2] */
    umaddl    x23, w26, w12, x23
    umaddl    x3, w26, w13, x3
    umaddl    x21, w26, w14, x21
    umaddl    x23, w28, w14, x23
    umaddl    x3, w28, w15, x3
    umaddl    x21, w28, w16, x21
    umaddl    x23, w9, w16, x23
    umaddl    x3, w9, w17, x3
    umaddl    x21, w9, w19, x21
    umaddl    x23, w25, w19, x23
    umaddl    x3, w25, w20, x3
    umaddl    x21, w2, w10, x21
    umaddl    x23, w0, w10, x23
    umaddl    x3, w0, w11, x3
    umaddl    x21, w0, w12, x21                   /* h[2] += f[0]*g[2] */
    /* --- Carry propagation pass 2: h[0] -> h[1] -> h[2] -> h[3] -> h[4] -> h[5] --- */
    add    x1, x3, x23, lsr #26                   /* h[1] += carry from h[0] */
    and    x0, x23, #0x3ffffff                    /* h[0] &= 26 bits */
    add    x2, x21, x1, lsr #25                   /* h[2] += carry from h[1] */
    and    x1, x1, #0x1ffffff                     /* h[1] &= 25 bits */
    add    x3, x8, x2, lsr #26                    /* h[3] += carry from h[2] */
    and    x2, x2, #0x3ffffff                     /* h[2] &= 26 bits */
    add    x4, x7, x3, lsr #25                    /* h[4] += carry from h[3] */
    and    x3, x3, #0x1ffffff                     /* h[3] &= 25 bits */
    add    x5, x6, x4, lsr #26                    /* h[5] += carry from h[4] */
    and    x4, x4, #0x3ffffff                     /* h[4] &= 26 bits */
    and    x5, x5, #0x3ffffff                     /* h[5] (truncate, carry handled in pass 1) */

    /* Unpack bfi'd limb pairs from pass 1 */
    mov    w6, w24                                /* h[6] (low 32 of x24) */
    lsr    x7, x24, #32                           /* h[7] (high 32 of x24) */
    mov    w8, w22                                /* h[8] (low 32 of x22) */
    lsr    x9, x22, #32                           /* h[9] (high 32 of x22) */

/* ============================================================================
 * SECTION 5: Final Reduction & Result Packing
 * ============================================================================ */

    orr    x10, x0, x1, lsl #26
    orr    x10, x10, x2, lsl #51

    lsr    x11, x2, #13
    orr    x11, x11, x3, lsl #13
    orr    x11, x11, x4, lsl #38

    add    x12, x5, x6, lsl #25
    adds    x12, x12, x7, lsl #51

    lsr    x13, x7, #13
    orr    x13, x13, x8, lsl #12
    orr    x13, x13, x9, lsl #38

    adcs    x13, x13, xzr
    adc    x14, xzr, xzr

    extr    x17, x14, x13, #63
    mov    w19, #19
    mul    w15, w17, w19
    add    w15, w15, #19

    adds    x15, x10, x15
    adcs    x15, x11, xzr
    adcs    x15, x12, xzr
    adcs    x15, x13, xzr
    adc    x16, x14, xzr

    extr    x16, x16, x15, #63
    mul    w16, w16, w19

    adds    x10, x10, x16
    adcs    x11, x11, xzr
    adcs    x12, x12, xzr
    adc    x13, x13, xzr
    and    x13, x13, 0x7fffffffffffffff

    /* If Z2 ≡ 0 mod p, force output to zero (constant-time).
     * BGCD inversion produces undefined results for zero input.
     * After carry reduction Z2 is in [0, 2p), so Z2 ≡ 0 iff Z2=0 or Z2=p.
     *
     * p in fe[10] stored as 64-bit word pairs:
     *   word0 = 0x01FFFFFF03FFFFED  (fe[0]=0x3FFFFED, fe[1]=0x1FFFFFF)
     *   word1..4 = 0x01FFFFFF03FFFFFF  (remaining limbs at max) */

    /* Build p_hi = 0x01FFFFFF03FFFFFF (pattern for words 1-4) */
    mov    x14, #0xFFFF
    movk   x14, #0x03FF, lsl #16
    movk   x14, #0xFFFF, lsl #32
    movk   x14, #0x01FF, lsl #48

    /* Check Z2 = 0: OR all 5 × 64-bit words */
    ldp    x15, x16, [sp, #80]
    orr    x17, x15, x16
    ldp    x15, x16, [sp, #96]
    orr    x17, x17, x15
    orr    x17, x17, x16
    ldr    x15, [sp, #112]
    orr    x17, x17, x15

    /* Check Z2 = p: XOR each word with p, OR all differences */
    sub    x15, x14, #18
    ldr    x16, [sp, #80]
    eor    x15, x16, x15
    ldr    x16, [sp, #88]
    eor    x16, x16, x14
    orr    x15, x15, x16
    ldr    x16, [sp, #96]
    eor    x16, x16, x14
    orr    x15, x15, x16
    ldr    x16, [sp, #104]
    eor    x16, x16, x14
    orr    x15, x15, x16
    ldr    x16, [sp, #112]
    eor    x16, x16, x14
    orr    x15, x15, x16

    /* Combine: mask = 0 if Z2=0 OR Z2=p, all-1s otherwise */
    cmp    x17, #0
    ccmp   x15, #0, #4, ne
    csetm  x14, ne
    and    x10, x10, x14
    and    x11, x11, x14
    and    x12, x12, x14
    and    x13, x13, x14

    /* Store 256-bit result to output buffer (uint8_t *q).
     * Use STR (not STP) to match the input LDR pattern and ensure
     * compatibility with all AArch64 alignment configurations. */
    ldr    x17, [sp, #176]
    str    x10, [x17]
    str    x11, [x17, #8]
    str    x12, [x17, #16]
    str    x13, [x17, #24]

/* ============================================================================
 * SECTION 6: Epilogue
 *
 * Security: Clear sensitive intermediate values from stack before return.
 * This prevents leakage of Z2, X2, and ladder intermediates to subsequent
 * functions that may reuse this stack region.
 * ============================================================================ */

    /* Clear 224 bytes of working space (14 × 16 bytes) */
    mov     x0, sp
    stp     xzr, xzr, [x0]
    stp     xzr, xzr, [x0, #16]
    stp     xzr, xzr, [x0, #32]
    stp     xzr, xzr, [x0, #48]
    stp     xzr, xzr, [x0, #64]
    stp     xzr, xzr, [x0, #80]
    stp     xzr, xzr, [x0, #96]
    stp     xzr, xzr, [x0, #112]
    stp     xzr, xzr, [x0, #128]
    stp     xzr, xzr, [x0, #144]
    stp     xzr, xzr, [x0, #160]
    stp     xzr, xzr, [x0, #176]
    stp     xzr, xzr, [x0, #192]
    stp     xzr, xzr, [x0, #208]

    add    sp, sp, 224

    ldp    x19, x20, [sp, #16]
    ldp    x21, x22, [sp, #32]
    ldp    x23, x24, [sp, #48]
    ldp    x25, x26, [sp, #64]
    ldp    x27, x28, [sp, #80]
    ldp    d8, d9, [sp, #96]
    ldp    d10, d11, [sp, #112]
    ldp    d12, d13, [sp, #128]
    ldp    d14, d15, [sp, #144]
    ldp    x29, x30, [sp], #160

    AARCH64_AUTIASP
    ret

/* ============================================================================
 * Local Binary GCD Inversion Subroutine (CSEL-optimized)
 * ============================================================================ */
.balign 16

.L_fe_invert:
    AARCH64_PACIASP
    stp     x29, x30, [sp, #-INV_STACK]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    stp     x27, x28, [sp, #80]

    str     x0, [sp, #INV_OFF_RESULT]

    /* Convert input fe to g[5]
     * Note: ldp wN automatically zero-extends to xN in AArch64,
     * so no explicit uxtw is needed. */
    ldp     w2, w3, [x1]
    ldp     w4, w5, [x1, #8]
    ldp     w6, w7, [x1, #16]
    ldp     w8, w9, [x1, #24]
    ldp     w10, w11, [x1, #32]

    /* Pack fe[10] (26/25-bit limbs) into t[0..3] (4 x 64-bit, 256-bit packed)
     * t[0] = fe[0] | fe[1]<<26 | fe[2]<<51
     * t[1] = fe[2]>>13 | fe[3]<<13 | fe[4]<<38
     * t[2] = fe[4]>>26 | fe[5] | fe[6]<<25 | fe[7]<<51
     * t[3] = fe[7]>>13 | fe[8]<<12 | fe[9]<<38 */
    orr     x12, x2, x3, lsl #26
    orr     x12, x12, x4, lsl #51
    lsr     x13, x4, #13
    orr     x13, x13, x5, lsl #13
    orr     x13, x13, x6, lsl #38
    lsr     x14, x6, #26
    orr     x14, x14, x7
    orr     x14, x14, x8, lsl #25
    orr     x14, x14, x9, lsl #51
    lsr     x15, x9, #13
    orr     x15, x15, x10, lsl #12
    orr     x15, x15, x11, lsl #38

    /* Convert 256-bit packed -> g[0..4] radix-2^62 limbs
     * g[i] = (t >> (62*i)) & M62, except g[4] = t >> 248 (7 bits) */
    mov     x16, #M62
    and     x2, x12, x16
    lsr     x3, x12, #62
    orr     x3, x3, x13, lsl #2
    and     x3, x3, x16
    lsr     x4, x13, #60
    orr     x4, x4, x14, lsl #4
    and     x4, x4, x16
    lsr     x5, x14, #58
    orr     x5, x5, x15, lsl #6
    and     x5, x5, x16
    lsr     x6, x15, #56

    stp     x2, x3, [sp, #INV_OFF_G]
    stp     x4, x5, [sp, #INV_OFF_G+16]
    str     x6, [sp, #INV_OFF_G+32]

    /* Initialize f = p */
    CRYPT_AARCH64_GET_RELA(x0, .L_p25519)
    ldp     x2, x3, [x0]
    ldp     x4, x5, [x0, #16]
    ldr     x6, [x0, #32]

    stp     x2, x3, [sp, #INV_OFF_F]
    stp     x4, x5, [sp, #INV_OFF_F+16]
    str     x6, [sp, #INV_OFF_F+32]

    /* d = 0, e = 1, zeta = -1 */
    stp     xzr, xzr, [sp, #INV_OFF_D]
    stp     xzr, xzr, [sp, #INV_OFF_D+16]
    str     xzr, [sp, #INV_OFF_D+32]

    mov     x0, #1
    stp     x0, xzr, [sp, #INV_OFF_E]
    stp     xzr, xzr, [sp, #INV_OFF_E+16]
    str     xzr, [sp, #INV_OFF_E+32]

    mov     x0, #-1
    str     x0, [sp, #INV_OFF_ZETA]

    mov     x0, #12
    str     x0, [sp, #INV_OFF_OUTER]

.L_inv_main_loop:
    /* --- divsteps_62 with csel optimization --- */
    ldr     x19, [sp, #INV_OFF_ZETA]
    ldr     x20, [sp, #INV_OFF_F]
    ldr     x21, [sp, #INV_OFF_G]

    mov     x22, #1                               /* u */
    mov     x23, #0                               /* v */
    mov     x24, #0                               /* q */
    mov     x25, #1                               /* r */
    mov     w26, #62

.L_inv_divsteps:
    /* Check conditions for swap:
     * swap if (g & 1) && (zeta < 0) */
    tst     x21, #1                               /* g & 1 */
    ccmp    x19, xzr, #0, ne                      /* if (g & 1), compare zeta with 0 */
    /* ccmp sets NZCV=#0 when g is even, so lt is false regardless of zeta.
     * Effective swap condition: lt = (g & 1) && (zeta < 0) */

    /* Conditional swap using csel:
     * if swap: f<->g, u<->q, v<->r, negate g,q,r, negate zeta */
    csel    x0, x21, x20, lt                      /* x0 = swap ? g : f */
    csel    x1, x20, x21, lt                      /* x1 = swap ? f : g */
    mov     x20, x0
    mov     x21, x1

    csel    x0, x24, x22, lt                      /* x0 = swap ? q : u */
    csel    x1, x22, x24, lt                      /* x1 = swap ? u : q */
    mov     x22, x0
    mov     x24, x1

    csel    x0, x25, x23, lt                      /* x0 = swap ? r : v */
    csel    x1, x23, x25, lt                      /* x1 = swap ? v : r */
    mov     x23, x0
    mov     x25, x1

    /* Conditional negate g, q, r, zeta (if swap) */
    cneg    x21, x21, lt
    cneg    x24, x24, lt
    cneg    x25, x25, lt
    cneg    x19, x19, lt

    /* g += f & (g & 1 mask), q += u & mask, r += v & mask */
    sbfx    x0, x21, #0, #1                       /* mask = (g & 1) ? -1 : 0 */
    and     x2, x20, x0
    add     x21, x21, x2
    and     x2, x22, x0
    add     x24, x24, x2
    and     x2, x23, x0
    add     x25, x25, x2

    asr     x21, x21, #1
    lsl     x22, x22, #1
    lsl     x23, x23, #1
    sub     x19, x19, #1

    subs    w26, w26, #1
    b.ne    .L_inv_divsteps

    str     x19, [sp, #INV_OFF_ZETA]
    stp     x22, x23, [sp, #INV_OFF_SCRATCH]
    stp     x24, x25, [sp, #INV_OFF_SCRATCH+16]

    bl      .L_inv_update_fg
    bl      .L_inv_update_de

    ldr     x0, [sp, #INV_OFF_OUTER]
    subs    x0, x0, #1
    str     x0, [sp, #INV_OFF_OUTER]
    b.ne    .L_inv_main_loop

    bl      .L_inv_normalize

    /* Convert d[5] to fe output */
    ldp     x0, x1, [sp, #INV_OFF_D]
    ldp     x2, x3, [sp, #INV_OFF_D+16]
    ldr     x4, [sp, #INV_OFF_D+32]

    orr     x5, x0, x1, lsl #62
    lsr     x6, x1, #2
    orr     x6, x6, x2, lsl #60
    lsr     x7, x2, #4
    orr     x7, x7, x3, lsl #58
    lsr     x8, x3, #6
    orr     x8, x8, x4, lsl #56

    mov     w10, #0x3FFFFFF
    mov     w11, #0x1FFFFFF

    and     w0, w5, w10
    lsr     x12, x5, #26
    and     w1, w12, w11
    lsr     x12, x5, #51
    and     x13, x6, #0x1FFF
    orr     w2, w12, w13, lsl #13
    and     w2, w2, w10
    lsr     x12, x6, #13
    and     w3, w12, w11
    lsr     x12, x6, #38
    and     w4, w12, w10
    and     w12, w7, w11
    lsr     x13, x7, #25
    and     w13, w13, w10
    lsr     x14, x7, #51
    and     x15, x8, #0x1FFF
    orr     w14, w14, w15, lsl #13
    and     w14, w14, w11
    lsr     x15, x8, #12
    and     w15, w15, w10
    lsr     x5, x8, #38
    and     w5, w5, w11

    ldr     x6, [sp, #INV_OFF_RESULT]
    stp     w0, w1, [x6]
    stp     w2, w3, [x6, #8]
    stp     w4, w12, [x6, #16]
    stp     w13, w14, [x6, #24]
    stp     w15, w5, [x6, #32]

    /* Zero sensitive intermediate data before frame deallocation */
    stp     xzr, xzr, [sp, #96]
    stp     xzr, xzr, [sp, #112]
    stp     xzr, xzr, [sp, #128]
    stp     xzr, xzr, [sp, #144]
    stp     xzr, xzr, [sp, #160]
    stp     xzr, xzr, [sp, #176]
    stp     xzr, xzr, [sp, #192]
    stp     xzr, xzr, [sp, #208]
    stp     xzr, xzr, [sp, #224]
    stp     xzr, xzr, [sp, #240]
    stp     xzr, xzr, [sp, #256]
    stp     xzr, xzr, [sp, #272]
    stp     xzr, xzr, [sp, #288]
    stp     xzr, xzr, [sp, #304]
    stp     xzr, xzr, [sp, #320]
    stp     xzr, xzr, [sp, #336]
    stp     xzr, xzr, [sp, #352]
    stp     xzr, xzr, [sp, #368]
    stp     xzr, xzr, [sp, #384]

    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x25, x26, [sp, #64]
    ldp     x27, x28, [sp, #80]
    /* Zero callee-saved area after restore (defense-in-depth) */
    stp     xzr, xzr, [sp, #16]
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]
    stp     xzr, xzr, [sp, #64]
    stp     xzr, xzr, [sp, #80]
    ldp     x29, x30, [sp], #INV_STACK
    AARCH64_AUTIASP
    ret

/* ============================================================================
 * INTERNAL HELPER: .L_inv_update_fg
 *
 * Updates f and g vectors using the 2x2 matrix [u,v; q,r] from divsteps.
 * Computes: f_new = (u*f + v*g) >> 62, g_new = (q*f + r*g) >> 62
 *
 * CALLING CONTEXT (MUST be satisfied):
 *   - Called ONLY from .L_fe_invert via bl
 *   - Parent MUST have saved x19-x28 (this function clobbers them)
 *   - Stack pointer MUST point to parent's INV_STACK frame
 *
 * INPUT:  [sp, #INV_OFF_F], [sp, #INV_OFF_G], [sp, #INV_OFF_SCRATCH]
 * OUTPUT: [sp, #INV_OFF_F], [sp, #INV_OFF_G] updated
 * CLOBBERS: x0-x28 (relies on parent to preserve callee-saved)
 * ============================================================================ */
.L_inv_update_fg:
    /* Load f[0..4], g[0..4], and transition matrix [u,v; q,r] */
    ldp     x0, x1, [sp, #INV_OFF_F]
    ldp     x2, x3, [sp, #INV_OFF_F+16]
    ldr     x4, [sp, #INV_OFF_F+32]
    ldp     x5, x6, [sp, #INV_OFF_G]
    ldp     x7, x8, [sp, #INV_OFF_G+16]
    ldr     x9, [sp, #INV_OFF_G+32]
    ldp     x22, x23, [sp, #INV_OFF_SCRATCH]      /* u, v */
    ldp     x24, x25, [sp, #INV_OFF_SCRATCH+16]   /* q, r */

    mov     x16, #M62
    /* Each limb: f_new[i] = (u*f[i] + v*g[i] + carry) >> 62
     *            g_new[i] = (q*f[i] + r*g[i] + carry) >> 62
     * 128-bit multiply: mul(low64) + smulh(high64) */

    /* --- Limb [0]: f_new, g_new (no incoming carry) --- */
    mul     x10, x22, x0                          /* low(u * f[0]) */
    smulh   x11, x22, x0                          /* high(u * f[0]) */
    mul     x17, x23, x5
    smulh   x19, x23, x5
    adds    x10, x10, x17
    adc     x11, x11, x19
    lsr     x10, x10, #62
    orr     x10, x10, x11, lsl #2
    sbfx    x11, x11, #62, #2

    mul     x12, x24, x0                          /* low(q * f[0]) */
    smulh   x13, x24, x0                          /* high(q * f[0]) */
    mul     x17, x25, x5                          /* low(r * g[0]) */
    smulh   x19, x25, x5                          /* high(r * g[0]) */
    adds    x12, x12, x17                         /* accum = q*f[0] + r*g[0] */
    adc     x13, x13, x19
    lsr     x12, x12, #62                         /* >> 62: carry for g_new[0] */
    orr     x12, x12, x13, lsl #2
    sbfx    x13, x13, #62, #2                     /* sign-extend carry */

    /* --- Limb [1]: f_new, g_new --- */
    mul     x17, x22, x1                          /* low(u * f[1]) */
    smulh   x19, x22, x1                          /* high(u * f[1]) */
    adds    x10, x10, x17
    adc     x11, x11, x19
    mul     x17, x23, x6
    smulh   x19, x23, x6
    adds    x10, x10, x17
    adc     x11, x11, x19
    and     x26, x10, x16                         /* f_new[0] = low 62 bits */
    lsr     x10, x10, #62                         /* carry for f_new[1] */
    orr     x10, x10, x11, lsl #2
    asr     x11, x11, #62

    mul     x17, x24, x1                          /* low(q * f[1]) */
    smulh   x19, x24, x1
    adds    x12, x12, x17
    adc     x13, x13, x19
    mul     x17, x25, x6
    smulh   x19, x25, x6
    adds    x12, x12, x17
    adc     x13, x13, x19
    and     x27, x12, x16                         /* g_new[0] = low 62 bits */
    lsr     x12, x12, #62                         /* carry for g_new[1] */
    orr     x12, x12, x13, lsl #2
    asr     x13, x13, #62

    /* --- Limb [2]: f_new, g_new --- */
    mul     x17, x22, x2
    smulh   x19, x22, x2
    adds    x10, x10, x17
    adc     x11, x11, x19
    mul     x17, x23, x7
    smulh   x19, x23, x7
    adds    x10, x10, x17
    adc     x11, x11, x19
    and     x28, x10, x16                         /* f_new[1] = low 62 bits */
    lsr     x10, x10, #62
    orr     x10, x10, x11, lsl #2
    asr     x11, x11, #62

    mul     x17, x24, x2
    smulh   x19, x24, x2
    adds    x12, x12, x17
    adc     x13, x13, x19
    mul     x17, x25, x7
    smulh   x19, x25, x7
    adds    x12, x12, x17
    adc     x13, x13, x19
    and     x20, x12, x16                         /* g_new[1] = low 62 bits */
    lsr     x12, x12, #62
    orr     x12, x12, x13, lsl #2
    asr     x13, x13, #62

    /* Spill f_new[0:1], g_new[0:1] to scratch (registers exhausted) */
    stp     x26, x28, [sp, #INV_OFF_SCRATCH+80]   /* f_new[0], f_new[1] */
    stp     x27, x20, [sp, #INV_OFF_SCRATCH+96]   /* g_new[0], g_new[1] */

    /* --- Limb [3]: f_new, g_new --- */
    mul     x17, x22, x3
    smulh   x19, x22, x3
    adds    x10, x10, x17
    adc     x11, x11, x19
    mul     x17, x23, x8
    smulh   x19, x23, x8
    adds    x10, x10, x17
    adc     x11, x11, x19
    and     x26, x10, x16
    lsr     x10, x10, #62
    orr     x10, x10, x11, lsl #2
    asr     x11, x11, #62

    mul     x17, x24, x3
    smulh   x19, x24, x3
    adds    x12, x12, x17
    adc     x13, x13, x19
    mul     x17, x25, x8
    smulh   x19, x25, x8
    adds    x12, x12, x17
    adc     x13, x13, x19
    and     x27, x12, x16                         /* g_new[2] = low 62 bits */
    lsr     x12, x12, #62
    orr     x12, x12, x13, lsl #2
    asr     x13, x13, #62

    /* --- Limb [4]: f_new, g_new (final, carry becomes top limb) --- */
    mul     x17, x22, x4
    smulh   x19, x22, x4
    adds    x10, x10, x17
    adc     x11, x11, x19
    mul     x17, x23, x9
    smulh   x19, x23, x9
    adds    x10, x10, x17
    adc     x11, x11, x19
    and     x28, x10, x16
    lsr     x10, x10, #62
    orr     x10, x10, x11, lsl #2

    mul     x17, x24, x4
    smulh   x19, x24, x4
    adds    x12, x12, x17
    adc     x13, x13, x19
    mul     x17, x25, x9
    smulh   x19, x25, x9
    adds    x12, x12, x17
    adc     x13, x13, x19
    and     x20, x12, x16
    lsr     x12, x12, #62
    orr     x12, x12, x13, lsl #2

    /* Reload spilled f_new[0:1], g_new[0:1] and write all 5 limbs */
    ldp     x0, x1, [sp, #INV_OFF_SCRATCH+80]     /* f_new[0], f_new[1] */
    ldp     x2, x3, [sp, #INV_OFF_SCRATCH+96]     /* g_new[0], g_new[1] */

    stp     x0, x1, [sp, #INV_OFF_F]              /* f[0:1] */
    stp     x26, x28, [sp, #INV_OFF_F+16]         /* f[2:3] */
    str     x10, [sp, #INV_OFF_F+32]              /* f[4] */

    stp     x2, x3, [sp, #INV_OFF_G]              /* g[0:1] */
    stp     x27, x20, [sp, #INV_OFF_G+16]         /* g[2:3] */
    str     x12, [sp, #INV_OFF_G+32]              /* g[4] */

    ret

/* ============================================================================
 * INTERNAL HELPER: .L_inv_update_de
 *
 * Updates d and e coefficient vectors using matrix [u,v; q,r].
 * Includes modular reduction by p to keep coefficients bounded.
 *
 * CALLING CONTEXT (MUST be satisfied):
 *   - Called ONLY from .L_fe_invert via bl
 *   - Parent MUST have saved x19-x28 (this function clobbers them)
 *   - Stack pointer MUST point to parent's INV_STACK frame
 *
 * INPUT:  [sp, #INV_OFF_D], [sp, #INV_OFF_E], [sp, #INV_OFF_SCRATCH]
 * OUTPUT: [sp, #INV_OFF_D], [sp, #INV_OFF_E] updated
 * CLOBBERS: x0-x28 (relies on parent to preserve callee-saved)
 * ============================================================================ */
.L_inv_update_de:
    /* Load d[0..4], e[0..4], and transition matrix [u,v; q,r] */
    ldp     x0, x1, [sp, #INV_OFF_D]
    ldp     x2, x3, [sp, #INV_OFF_D+16]
    ldr     x4, [sp, #INV_OFF_D+32]
    ldp     x5, x6, [sp, #INV_OFF_E]
    ldp     x7, x8, [sp, #INV_OFF_E+16]
    ldr     x9, [sp, #INV_OFF_E+32]
    ldp     x22, x23, [sp, #INV_OFF_SCRATCH]      /* u, v */
    ldp     x24, x25, [sp, #INV_OFF_SCRATCH+16]   /* q, r */
    CRYPT_AARCH64_GET_RELA(x10, .L_p25519)

    /* Modular correction (Bernstein-Yang Lemma 10.2):
     *   mask_d = (d[4] < 0) ? all-1s : 0    (via asr #63)
     *   mask_e = (e[4] < 0) ? all-1s : 0
     *   md = (u & mask_d) + (v & mask_e)
     *   me = (q & mask_d) + (r & mask_e)
     * Then adjust md, me using p_inv so (u*d + v*e + md*p) = 0 (mod 2^62) */
    asr     x17, x4, #63                          /* sign(d[4]): all-1 if d<0, 0 otherwise */
    asr     x19, x9, #63                          /* sign(e[4]) */

    and     x20, x22, x17                         /* u & mask_d */
    and     x21, x23, x19                         /* v & mask_e */
    add     x20, x20, x21                         /* md = (u & mask_d) + (v & mask_e) */

    and     x21, x24, x17                         /* q & mask_d */
    and     x26, x25, x19                         /* r & mask_e */
    add     x21, x21, x26                         /* me = (q & mask_d) + (r & mask_e) */

    /* Compute low residue: (u*d[0] + v*e[0]) mod 2^62 */
    mul     x17, x22, x0
    mul     x19, x23, x5
    add     x17, x17, x19
    mov     x26, #M62
    and     x17, x17, x26                         /* residue_d mod 2^62 */

    mul     x19, x24, x0
    mul     x27, x25, x5
    add     x19, x19, x27
    and     x19, x19, x26                         /* residue_e mod 2^62 */

    ldr     x27, [x10, #40]                       /* p_inv = p^(-1) mod 2^62 */

    /* Adjust md: md = md - (p_inv * residue_d + md) mod 2^62 */
    mul     x28, x27, x17
    add     x28, x28, x20
    and     x28, x28, x26
    sub     x20, x20, x28                         /* final md */

    /* Adjust me: me = me - (p_inv * residue_e + me) mod 2^62 */
    mul     x28, x27, x19
    add     x28, x28, x21
    and     x28, x28, x26
    sub     x21, x21, x28                         /* final me */

    /* Load p[0..4] for triple-term accumulation */
    ldp     x11, x12, [x10]
    ldp     x13, x14, [x10, #16]
    ldr     x15, [x10, #32]

    /* --- Limb [0]: d_new = (u*d[0] + v*e[0] + md*p[0]) >> 62 --- */
    mul     x17, x22, x0
    smulh   x19, x22, x0
    mul     x27, x23, x5
    smulh   x28, x23, x5
    adds    x17, x17, x27
    adc     x19, x19, x28
    mul     x27, x20, x11
    smulh   x28, x20, x11
    adds    x17, x17, x27
    adc     x19, x19, x28
    lsr     x17, x17, #62
    orr     x17, x17, x19, lsl #2
    sbfx    x19, x19, #62, #2

    /* e_new[0]: (q*d[0] + r*e[0] + me*p[0]) >> 62 */
    mul     x26, x24, x0
    smulh   x27, x24, x0
    mul     x28, x25, x5
    smulh   x16, x25, x5
    adds    x26, x26, x28
    adc     x27, x27, x16
    mul     x28, x21, x11
    smulh   x16, x21, x11
    adds    x26, x26, x28
    adc     x27, x27, x16
    lsr     x26, x26, #62
    orr     x26, x26, x27, lsl #2
    sbfx    x27, x27, #62, #2

    /* --- Limb [1]: d_new, e_new --- */
    mul     x28, x22, x1
    smulh   x16, x22, x1
    adds    x17, x17, x28
    adc     x19, x19, x16
    mul     x28, x23, x6
    smulh   x16, x23, x6
    adds    x17, x17, x28
    adc     x19, x19, x16
    mul     x28, x20, x12
    smulh   x16, x20, x12
    adds    x17, x17, x28
    adc     x19, x19, x16
    mov     x16, #M62
    and     x0, x17, x16
    lsr     x17, x17, #62
    orr     x17, x17, x19, lsl #2
    asr     x19, x19, #62

    mul     x28, x24, x1
    smulh   x16, x24, x1
    adds    x26, x26, x28
    adc     x27, x27, x16
    mul     x28, x25, x6
    smulh   x16, x25, x6
    adds    x26, x26, x28
    adc     x27, x27, x16
    mul     x28, x21, x12
    smulh   x16, x21, x12
    adds    x26, x26, x28
    adc     x27, x27, x16
    mov     x16, #M62
    and     x5, x26, x16
    lsr     x26, x26, #62
    orr     x26, x26, x27, lsl #2
    asr     x27, x27, #62

    /* Spill d_new[0], e_new[0] */
    stp     x0, x5, [sp, #INV_OFF_SCRATCH+32]

    /* --- Limb [2]: d_new, e_new --- */
    ldr     x1, [sp, #INV_OFF_D+16]
    ldr     x6, [sp, #INV_OFF_E+16]

    mul     x28, x22, x1
    smulh   x16, x22, x1
    adds    x17, x17, x28
    adc     x19, x19, x16
    mul     x28, x23, x6
    smulh   x16, x23, x6
    adds    x17, x17, x28
    adc     x19, x19, x16
    mul     x28, x20, x13
    smulh   x16, x20, x13
    adds    x17, x17, x28
    adc     x19, x19, x16
    mov     x16, #M62
    and     x0, x17, x16
    lsr     x17, x17, #62
    orr     x17, x17, x19, lsl #2
    asr     x19, x19, #62

    mul     x28, x24, x1
    smulh   x16, x24, x1
    adds    x26, x26, x28
    adc     x27, x27, x16
    mul     x28, x25, x6
    smulh   x16, x25, x6
    adds    x26, x26, x28
    adc     x27, x27, x16
    mul     x28, x21, x13
    smulh   x16, x21, x13
    adds    x26, x26, x28
    adc     x27, x27, x16
    mov     x16, #M62
    and     x5, x26, x16
    lsr     x26, x26, #62
    orr     x26, x26, x27, lsl #2
    asr     x27, x27, #62

    /* Spill d_new[1], e_new[1] */
    stp     x0, x5, [sp, #INV_OFF_SCRATCH+48]

    /* --- Limb [3]: d_new, e_new --- */
    ldr     x1, [sp, #INV_OFF_D+24]
    ldr     x6, [sp, #INV_OFF_E+24]

    mul     x28, x22, x1
    smulh   x16, x22, x1
    adds    x17, x17, x28
    adc     x19, x19, x16
    mul     x28, x23, x6
    smulh   x16, x23, x6
    adds    x17, x17, x28
    adc     x19, x19, x16
    mul     x28, x20, x14
    smulh   x16, x20, x14
    adds    x17, x17, x28
    adc     x19, x19, x16
    mov     x16, #M62
    and     x0, x17, x16
    lsr     x17, x17, #62
    orr     x17, x17, x19, lsl #2
    asr     x19, x19, #62

    mul     x28, x24, x1
    smulh   x16, x24, x1
    adds    x26, x26, x28
    adc     x27, x27, x16
    mul     x28, x25, x6
    smulh   x16, x25, x6
    adds    x26, x26, x28
    adc     x27, x27, x16
    mul     x28, x21, x14
    smulh   x16, x21, x14
    adds    x26, x26, x28
    adc     x27, x27, x16
    mov     x16, #M62
    and     x5, x26, x16
    lsr     x26, x26, #62
    orr     x26, x26, x27, lsl #2
    asr     x27, x27, #62

    /* Spill d_new[2], e_new[2] */
    stp     x0, x5, [sp, #INV_OFF_SCRATCH+64]

    /* --- Limb [4]: d_new, e_new (final, carry becomes top limb) --- */
    ldr     x1, [sp, #INV_OFF_D+32]
    ldr     x6, [sp, #INV_OFF_E+32]

    mul     x28, x22, x1
    smulh   x16, x22, x1
    adds    x17, x17, x28
    adc     x19, x19, x16
    mul     x28, x23, x6
    smulh   x16, x23, x6
    adds    x17, x17, x28
    adc     x19, x19, x16
    mul     x28, x20, x15
    smulh   x16, x20, x15
    adds    x17, x17, x28
    adc     x19, x19, x16
    mov     x16, #M62
    and     x0, x17, x16
    lsr     x17, x17, #62
    orr     x17, x17, x19, lsl #2

    mul     x28, x24, x1
    smulh   x16, x24, x1
    adds    x26, x26, x28
    adc     x27, x27, x16
    mul     x28, x25, x6
    smulh   x16, x25, x6
    adds    x26, x26, x28
    adc     x27, x27, x16
    mul     x28, x21, x15
    smulh   x16, x21, x15
    adds    x26, x26, x28
    adc     x27, x27, x16
    mov     x16, #M62
    and     x5, x26, x16
    lsr     x26, x26, #62
    orr     x26, x26, x27, lsl #2

    /* Reload spilled d_new[0..2], e_new[0..2] and write all 5 limbs */
    ldp     x1, x6, [sp, #INV_OFF_SCRATCH+32]     /* d[0], e[0] */
    ldp     x2, x7, [sp, #INV_OFF_SCRATCH+48]     /* d[1], e[1] */
    ldp     x3, x8, [sp, #INV_OFF_SCRATCH+64]     /* d[2], e[2] */

    stp     x1, x2, [sp, #INV_OFF_D]              /* d[0:1] */
    stp     x3, x0, [sp, #INV_OFF_D+16]           /* d[2:3] */
    str     x17, [sp, #INV_OFF_D+32]              /* d[4] */

    stp     x6, x7, [sp, #INV_OFF_E]              /* e[0:1] */
    stp     x8, x5, [sp, #INV_OFF_E+16]           /* e[2:3] */
    str     x26, [sp, #INV_OFF_E+32]              /* e[4] */

    ret

/* ============================================================================
 * INTERNAL HELPER: .L_inv_normalize
 *
 * Constant-time normalization of d coefficient to range [0, p).
 * After Binary GCD, d is in range approximately [-2p, 2p].
 *
 * Algorithm (all constant-time via CSEL):
 *   Phase 1-2: Conditionally add p twice (if d < 0)
 *   Phase 3:   Conditionally negate (if f was negative)
 *   Phase 4-5: Conditionally subtract p twice (if d >= p)
 *
 * CALLING CONTEXT (MUST be satisfied):
 *   - Called ONLY from .L_fe_invert via bl
 *   - Parent MUST have saved x19-x28 (this function clobbers them)
 *   - Stack pointer MUST point to parent's INV_STACK frame
 *
 * INPUT:  [sp, #INV_OFF_D], [sp, #INV_OFF_F+32] (f[4] sign)
 * OUTPUT: [sp, #INV_OFF_D] normalized to [0, p)
 * CLOBBERS: x0-x28 (relies on parent to preserve callee-saved)
 * SECURITY: No data-dependent branches - constant-time execution
 * ============================================================================ */
.L_inv_normalize:
    ldp     x0, x1, [sp, #INV_OFF_D]
    ldp     x2, x3, [sp, #INV_OFF_D+16]
    ldr     x4, [sp, #INV_OFF_D+32]
    ldr     x5, [sp, #INV_OFF_F+32]

    /* x6 = 1 if f < 0, else 0 (need to negate d at end) */
    cmp     x5, #0
    cset    x6, lt
    CRYPT_AARCH64_GET_RELA(x10, .L_p25519)
    ldp     x11, x12, [x10]
    ldp     x13, x14, [x10, #16]
    ldr     x15, [x10, #32]
    mov     x16, #M62

    /* --- Phase 1: Conditional add p (first time) --- */
    /* Compute d + p (per-limb; software carry follows) */
    add     x20, x0, x11
    add     x21, x1, x12
    add     x22, x2, x13
    add     x23, x3, x14
    add     x24, x4, x15

    /* Carry propagation for d + p (62-bit limbs) */
    lsr     x17, x20, #62
    and     x20, x20, x16
    add     x21, x21, x17
    lsr     x17, x21, #62
    and     x21, x21, x16
    add     x22, x22, x17
    lsr     x17, x22, #62
    and     x22, x22, x16
    add     x23, x23, x17
    lsr     x17, x23, #62
    and     x23, x23, x16
    add     x24, x24, x17

    /* Select: if d[4] < 0, use d+p; else keep d */
    cmp     x4, #0
    csel    x0, x20, x0, lt
    csel    x1, x21, x1, lt
    csel    x2, x22, x2, lt
    csel    x3, x23, x3, lt
    csel    x4, x24, x4, lt

    /* --- Phase 2: Conditional add p (second time, for edge cases) --- */
    add     x20, x0, x11
    add     x21, x1, x12
    add     x22, x2, x13
    add     x23, x3, x14
    add     x24, x4, x15

    lsr     x17, x20, #62
    and     x20, x20, x16
    add     x21, x21, x17
    lsr     x17, x21, #62
    and     x21, x21, x16
    add     x22, x22, x17
    lsr     x17, x22, #62
    and     x22, x22, x16
    add     x23, x23, x17
    lsr     x17, x23, #62
    and     x23, x23, x16
    add     x24, x24, x17

    cmp     x4, #0
    csel    x0, x20, x0, lt
    csel    x1, x21, x1, lt
    csel    x2, x22, x2, lt
    csel    x3, x23, x3, lt
    csel    x4, x24, x4, lt

    /* --- Phase 3: Conditional negate (if f was negative) --- */
    /* Compute p - d (independent per-limb, carry via asr/and/add below) */
    sub     x20, x11, x0
    sub     x21, x12, x1
    sub     x22, x13, x2
    sub     x23, x14, x3
    sub     x24, x15, x4

    /* Carry propagation for p - d (signed, 62-bit limbs) */
    asr     x17, x20, #62
    and     x20, x20, x16
    add     x21, x21, x17
    asr     x17, x21, #62
    and     x21, x21, x16
    add     x22, x22, x17
    asr     x17, x22, #62
    and     x22, x22, x16
    add     x23, x23, x17
    asr     x17, x23, #62
    and     x23, x23, x16
    add     x24, x24, x17

    /* Conditional add p to (p - d) if result is negative */
    add     x25, x20, x11
    add     x26, x21, x12
    add     x27, x22, x13
    add     x28, x23, x14
    add     x19, x24, x15

    lsr     x17, x25, #62
    and     x25, x25, x16
    add     x26, x26, x17
    lsr     x17, x26, #62
    and     x26, x26, x16
    add     x27, x27, x17
    lsr     x17, x27, #62
    and     x27, x27, x16
    add     x28, x28, x17
    lsr     x17, x28, #62
    and     x28, x28, x16
    add     x19, x19, x17

    cmp     x24, #0
    csel    x20, x25, x20, lt
    csel    x21, x26, x21, lt
    csel    x22, x27, x22, lt
    csel    x23, x28, x23, lt
    csel    x24, x19, x24, lt

    /* Select: if x6 != 0 (f was negative), use negated; else keep d */
    cmp     x6, #0
    csel    x0, x20, x0, ne
    csel    x1, x21, x1, ne
    csel    x2, x22, x2, ne
    csel    x3, x23, x3, ne
    csel    x4, x24, x4, ne

    /* --- Phase 4: Conditional subtract p (reduce to [0, p)) --- */
    /* Compute d - p (independent per-limb, carry via asr/and/add below) */
    sub     x20, x0, x11
    sub     x21, x1, x12
    sub     x22, x2, x13
    sub     x23, x3, x14
    sub     x24, x4, x15

    /* Carry propagation for d - p (signed, 62-bit limbs) */
    asr     x19, x20, #62
    and     x20, x20, x16
    add     x21, x21, x19
    asr     x19, x21, #62
    and     x21, x21, x16
    add     x22, x22, x19
    asr     x19, x22, #62
    and     x22, x22, x16
    add     x23, x23, x19
    asr     x19, x23, #62
    and     x23, x23, x16
    add     x24, x24, x19

    /* Select: if d-p >= 0 (top limb non-negative), use d-p; else keep d */
    cmp     x24, #0
    csel    x0, x20, x0, ge
    csel    x1, x21, x1, ge
    csel    x2, x22, x2, ge
    csel    x3, x23, x3, ge
    csel    x4, x24, x4, ge

    /* --- Phase 5: Second conditional subtract p (for d in [p, 2p)) --- */
    sub     x20, x0, x11
    sub     x21, x1, x12
    sub     x22, x2, x13
    sub     x23, x3, x14
    sub     x24, x4, x15

    asr     x19, x20, #62
    and     x20, x20, x16
    add     x21, x21, x19
    asr     x19, x21, #62
    and     x21, x21, x16
    add     x22, x22, x19
    asr     x19, x22, #62
    and     x22, x22, x16
    add     x23, x23, x19
    asr     x19, x23, #62
    and     x23, x23, x16
    add     x24, x24, x19

    /* Select: if d-p >= 0 (top limb non-negative), use d-p; else keep d */
    cmp     x24, #0
    csel    x0, x20, x0, ge
    csel    x1, x21, x1, ge
    csel    x2, x22, x2, ge
    csel    x3, x23, x3, ge
    csel    x4, x24, x4, ge

.L_inv_done:
    stp     x0, x1, [sp, #INV_OFF_D]
    stp     x2, x3, [sp, #INV_OFF_D+16]
    str     x4, [sp, #INV_OFF_D+32]
    ret
CRYPT_AARCH64_FUNC_END(X25519ScalarMultiPointNeonInterleave)

#ifndef __APPLE__
/* Mark stack as non-executable (ELF targets) */
    .section .note.GNU-stack,"",@progbits
#endif

#endif /* HITLS_CRYPTO_X25519 && HITLS_CRYPTO_X25519_ARMV8_NEON_INTERLEAVE && !HITLS_BIG_ENDIAN */
