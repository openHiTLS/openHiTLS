/*
 * based on the techniques of https://eprint.iacr.org/2021/986, CC0 1.0 Universal.
 *
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
 * ============================================================================
 * ML-DSA Number Theoretic Transform (NTT) — ARMv8 NEON Implementation
 * ============================================================================
 *
 * References:
 *   [NeonNTT]  Becker, Hwang, Kannwischer, Yang, Yang.
 *              "Neon NTT: Faster Dilithium, Kyber, and Saber on Cortex-A72
 *              and Apple M1." https://eprint.iacr.org/2021/986
 *   [FIPS204]  NIST FIPS 204 — ML-DSA Standard, Algorithms 41 & 42.
 *
 * Algorithm overview:
 *   The NTT operates on polynomials in R_q = Z_q[X]/(X^256 + 1) with
 *   q = 8380417 and 32-bit signed coefficients. 256 coefficients form
 *   64 NEON vectors of 4 lanes; eight butterfly layers (len = 128 .. 1)
 *   are merged into two passes so each coefficient is loaded/stored twice:
 *
 *   - NTT top  (layers len = 128/64/32/16): four iterations, each owning the
 *     16 vectors {a + 16c + 64t : t = 0..15} which are closed under the
 *     +32/+16/+8/+4 vector-index butterfly strides of these layers.
 *   - NTT bottom (layers len = 8/4/2/1): eight iterations over pairs of
 *     16-coefficient blocks. Layers with stride below the 4-lane width use a
 *     4x4 transpose (trn1/trn2 on .4S/.2D) so paired elements end up in
 *     different vectors, then per-lane twiddle vectors finish len = 2/1.
 *
 *   The inverse NTT mirrors this (bottom first, Gentleman-Sande butterflies)
 *   and fuses the final len = 128 layer with the multiplication by
 *   F = 256^-1 * 2^32 == 2^24 mod q, cancelling both the inverse-transform
 *   1/256 scaling and the single 2^-32 Montgomery factor introduced by
 *   MLDSA_PointwiseAccMontAsm (see asm_ml_dsa_ntt.c for the domain contract).
 *
 * Barrett multiplication pattern (32-bit lanes, exact mod q):
 *   For twiddles stored as pairs (zl, zh) with zl = z mod+- q and
 *   zh = round(zl * 2^31 / q):
 *     sqrdmulh hi, a, zh    // hi  = round(a * zh / 2^31) ~= round(a * z / q)
 *     mul      lo, a, zl    // lo  = a * z mod 2^32
 *     mls      lo, hi, q    // lo  = a * z - hi * q == a * z mod+- q
 *   |result| <= q * (1/2 + |a| / 2^32), so eight forward Cooley-Tukey layers
 *   on input in (-q, q) stay below 6q and eight inverse Gentleman-Sande
 *   layers on input in [-q/2 - 2, q/2 + 2] stay below 2^30: no intermediate
 *   reductions are required anywhere.
 *
 * Montgomery + Barrett reduction (MLDSA_PointwiseAccMontAsm):
 *   64-bit lane accumulators T = sum a_i * b_i (|T| < 2^56 for l <= 7), then
 *     m = lo32(T) * q^-1 mod 2^32      (uzp1 + mul)
 *     r = (T - m * q) >> 32            (smlsl/smlsl2 + uzp2, exact division)
 *   giving r == T * 2^-32 mod q, |r| < 1.5q, followed by a Barrett reduction
 *     t = (2 * r * M) >> 32 >> 22, r -= t * q     (M = round(2^53 / q))
 *   to |r| <= q/2 + 2.
 *
 * Functions:
 *   MLDSA_NTTTopAsm(int32_t *a, const int32_t *table)
 *   MLDSA_NTTBotAsm(int32_t *a, const int32_t *table)
 *   MLDSA_INTTBotAsm(int32_t *a, const int32_t *table)
 *   MLDSA_INTTTopAsm(int32_t *a, const int32_t *table)
 *   MLDSA_PointwiseAccMontAsm(int32_t *t, const int32_t *const *a,
 *                             const int32_t *const *b, uint64_t l)
 *
 * Call order:  NTT  = NTTTop  then NTTBot
 *              INTT = INTTBot then INTTTop
 * Twiddle table layout: see asm_ml_dsa_ntt.c.
 * ============================================================================
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MLDSA_ARMV8

#include "crypt_arm.h"
CRYPT_AARCH64_ARCH_BASE

// ----------------------------------------------------------------------------
// Batched butterfly macros. All macros operate on .4S lanes, take the modulus
// q as an indexed element (qv.s[qi]) and use fixed scratch registers as noted.
// ----------------------------------------------------------------------------

// Four Cooley-Tukey butterflies (a, b) -> (a + z*b, a - z*b), per-butterfly
// indexed twiddle elements. Scratch: v24-v31.
.macro MLDSA_CT4 a0, b0, z0, l0, h0, a1, b1, z1, l1, h1, a2, b2, z2, l2, h2, a3, b3, z3, l3, h3, qv, qi
    sqrdmulh v24.4s, \b0\().4s, \z0\().s[\h0]
    sqrdmulh v25.4s, \b1\().4s, \z1\().s[\h1]
    sqrdmulh v26.4s, \b2\().4s, \z2\().s[\h2]
    sqrdmulh v27.4s, \b3\().4s, \z3\().s[\h3]
    mul      v28.4s, \b0\().4s, \z0\().s[\l0]
    mul      v29.4s, \b1\().4s, \z1\().s[\l1]
    mul      v30.4s, \b2\().4s, \z2\().s[\l2]
    mul      v31.4s, \b3\().4s, \z3\().s[\l3]
    mls      v28.4s, v24.4s, \qv\().s[\qi]
    mls      v29.4s, v25.4s, \qv\().s[\qi]
    mls      v30.4s, v26.4s, \qv\().s[\qi]
    mls      v31.4s, v27.4s, \qv\().s[\qi]
    sub      \b0\().4s, \a0\().4s, v28.4s
    sub      \b1\().4s, \a1\().4s, v29.4s
    sub      \b2\().4s, \a2\().4s, v30.4s
    sub      \b3\().4s, \a3\().4s, v31.4s
    add      \a0\().4s, \a0\().4s, v28.4s
    add      \a1\().4s, \a1\().4s, v29.4s
    add      \a2\().4s, \a2\().4s, v30.4s
    add      \a3\().4s, \a3\().4s, v31.4s
.endm

// Four Cooley-Tukey butterflies with full-vector twiddles (zl, zh).
// Scratch: v24-v31.
.macro MLDSA_CT4V a0, b0, zl0, zh0, a1, b1, zl1, zh1, a2, b2, zl2, zh2, a3, b3, zl3, zh3, qv, qi
    sqrdmulh v24.4s, \b0\().4s, \zh0\().4s
    sqrdmulh v25.4s, \b1\().4s, \zh1\().4s
    sqrdmulh v26.4s, \b2\().4s, \zh2\().4s
    sqrdmulh v27.4s, \b3\().4s, \zh3\().4s
    mul      v28.4s, \b0\().4s, \zl0\().4s
    mul      v29.4s, \b1\().4s, \zl1\().4s
    mul      v30.4s, \b2\().4s, \zl2\().4s
    mul      v31.4s, \b3\().4s, \zl3\().4s
    mls      v28.4s, v24.4s, \qv\().s[\qi]
    mls      v29.4s, v25.4s, \qv\().s[\qi]
    mls      v30.4s, v26.4s, \qv\().s[\qi]
    mls      v31.4s, v27.4s, \qv\().s[\qi]
    sub      \b0\().4s, \a0\().4s, v28.4s
    sub      \b1\().4s, \a1\().4s, v29.4s
    sub      \b2\().4s, \a2\().4s, v30.4s
    sub      \b3\().4s, \a3\().4s, v31.4s
    add      \a0\().4s, \a0\().4s, v28.4s
    add      \a1\().4s, \a1\().4s, v29.4s
    add      \a2\().4s, \a2\().4s, v30.4s
    add      \a3\().4s, \a3\().4s, v31.4s
.endm

// Four Gentleman-Sande butterflies (a, b) -> (a + b, (a - b)*z), indexed
// twiddles. Scratch: v24-v31.
.macro MLDSA_GS4 a0, b0, z0, l0, h0, a1, b1, z1, l1, h1, a2, b2, z2, l2, h2, a3, b3, z3, l3, h3, qv, qi
    sub      v24.4s, \a0\().4s, \b0\().4s
    sub      v25.4s, \a1\().4s, \b1\().4s
    sub      v26.4s, \a2\().4s, \b2\().4s
    sub      v27.4s, \a3\().4s, \b3\().4s
    add      \a0\().4s, \a0\().4s, \b0\().4s
    add      \a1\().4s, \a1\().4s, \b1\().4s
    add      \a2\().4s, \a2\().4s, \b2\().4s
    add      \a3\().4s, \a3\().4s, \b3\().4s
    sqrdmulh v28.4s, v24.4s, \z0\().s[\h0]
    sqrdmulh v29.4s, v25.4s, \z1\().s[\h1]
    sqrdmulh v30.4s, v26.4s, \z2\().s[\h2]
    sqrdmulh v31.4s, v27.4s, \z3\().s[\h3]
    mul      \b0\().4s, v24.4s, \z0\().s[\l0]
    mul      \b1\().4s, v25.4s, \z1\().s[\l1]
    mul      \b2\().4s, v26.4s, \z2\().s[\l2]
    mul      \b3\().4s, v27.4s, \z3\().s[\l3]
    mls      \b0\().4s, v28.4s, \qv\().s[\qi]
    mls      \b1\().4s, v29.4s, \qv\().s[\qi]
    mls      \b2\().4s, v30.4s, \qv\().s[\qi]
    mls      \b3\().4s, v31.4s, \qv\().s[\qi]
.endm

// Four Gentleman-Sande butterflies with full-vector twiddles. Scratch: v24-v31.
.macro MLDSA_GS4V a0, b0, zl0, zh0, a1, b1, zl1, zh1, a2, b2, zl2, zh2, a3, b3, zl3, zh3, qv, qi
    sub      v24.4s, \a0\().4s, \b0\().4s
    sub      v25.4s, \a1\().4s, \b1\().4s
    sub      v26.4s, \a2\().4s, \b2\().4s
    sub      v27.4s, \a3\().4s, \b3\().4s
    add      \a0\().4s, \a0\().4s, \b0\().4s
    add      \a1\().4s, \a1\().4s, \b1\().4s
    add      \a2\().4s, \a2\().4s, \b2\().4s
    add      \a3\().4s, \a3\().4s, \b3\().4s
    sqrdmulh v28.4s, v24.4s, \zh0\().4s
    sqrdmulh v29.4s, v25.4s, \zh1\().4s
    sqrdmulh v30.4s, v26.4s, \zh2\().4s
    sqrdmulh v31.4s, v27.4s, \zh3\().4s
    mul      \b0\().4s, v24.4s, \zl0\().4s
    mul      \b1\().4s, v25.4s, \zl1\().4s
    mul      \b2\().4s, v26.4s, \zl2\().4s
    mul      \b3\().4s, v27.4s, \zl3\().4s
    mls      \b0\().4s, v28.4s, \qv\().s[\qi]
    mls      \b1\().4s, v29.4s, \qv\().s[\qi]
    mls      \b2\().4s, v30.4s, \qv\().s[\qi]
    mls      \b3\().4s, v31.4s, \qv\().s[\qi]
.endm

// Three Gentleman-Sande butterflies, indexed twiddles. Scratch: v24-v29.
// (MLDSA_INTTTopAsm keeps q in v31, so only seven scratch registers exist.)
.macro MLDSA_GS3 a0, b0, z0, l0, h0, a1, b1, z1, l1, h1, a2, b2, z2, l2, h2, qv, qi
    sub      v24.4s, \a0\().4s, \b0\().4s
    sub      v25.4s, \a1\().4s, \b1\().4s
    sub      v26.4s, \a2\().4s, \b2\().4s
    add      \a0\().4s, \a0\().4s, \b0\().4s
    add      \a1\().4s, \a1\().4s, \b1\().4s
    add      \a2\().4s, \a2\().4s, \b2\().4s
    sqrdmulh v27.4s, v24.4s, \z0\().s[\h0]
    sqrdmulh v28.4s, v25.4s, \z1\().s[\h1]
    sqrdmulh v29.4s, v26.4s, \z2\().s[\h2]
    mul      \b0\().4s, v24.4s, \z0\().s[\l0]
    mul      \b1\().4s, v25.4s, \z1\().s[\l1]
    mul      \b2\().4s, v26.4s, \z2\().s[\l2]
    mls      \b0\().4s, v27.4s, \qv\().s[\qi]
    mls      \b1\().4s, v28.4s, \qv\().s[\qi]
    mls      \b2\().4s, v29.4s, \qv\().s[\qi]
.endm

// Two Gentleman-Sande butterflies, indexed twiddles. Scratch: v24-v27.
.macro MLDSA_GS2 a0, b0, z0, l0, h0, a1, b1, z1, l1, h1, qv, qi
    sub      v24.4s, \a0\().4s, \b0\().4s
    sub      v25.4s, \a1\().4s, \b1\().4s
    add      \a0\().4s, \a0\().4s, \b0\().4s
    add      \a1\().4s, \a1\().4s, \b1\().4s
    sqrdmulh v26.4s, v24.4s, \z0\().s[\h0]
    sqrdmulh v27.4s, v25.4s, \z1\().s[\h1]
    mul      \b0\().4s, v24.4s, \z0\().s[\l0]
    mul      \b1\().4s, v25.4s, \z1\().s[\l1]
    mls      \b0\().4s, v26.4s, \qv\().s[\qi]
    mls      \b1\().4s, v27.4s, \qv\().s[\qi]
.endm

// Two fused last-layer inverse butterflies with output scaling:
//   (a, b) -> (bmul(a + b, F), bmul(a - b, G))
// where F = v7.s[0]/[1] and G = v7.s[2]/[3]; q is v31 (all lanes).
// Scratch: v24-v29.
.macro MLDSA_FS2 a0, b0, a1, b1
    sub      v24.4s, \a0\().4s, \b0\().4s
    sub      v25.4s, \a1\().4s, \b1\().4s
    add      \a0\().4s, \a0\().4s, \b0\().4s
    add      \a1\().4s, \a1\().4s, \b1\().4s
    sqrdmulh v26.4s, \a0\().4s, v7.s[1]
    sqrdmulh v27.4s, \a1\().4s, v7.s[1]
    sqrdmulh v28.4s, v24.4s, v7.s[3]
    sqrdmulh v29.4s, v25.4s, v7.s[3]
    mul      \a0\().4s, \a0\().4s, v7.s[0]
    mul      \a1\().4s, \a1\().4s, v7.s[0]
    mul      \b0\().4s, v24.4s, v7.s[2]
    mul      \b1\().4s, v25.4s, v7.s[2]
    mls      \a0\().4s, v26.4s, v31.4s
    mls      \a1\().4s, v27.4s, v31.4s
    mls      \b0\().4s, v28.4s, v31.4s
    mls      \b1\().4s, v29.4s, v31.4s
.endm

// 4x4 int32 matrix transpose of x0..x3 in place. Scratch: t0-t3.
// Lane l of output xl holds the former lane l-th element of vector x_v, i.e.
// out_l[v] = in_v[l], moving sub-vector butterfly strides across vectors.
.macro MLDSA_TRN4 x0, x1, x2, x3, t0, t1, t2, t3
    trn1     \t0\().4s, \x0\().4s, \x1\().4s
    trn2     \t1\().4s, \x0\().4s, \x1\().4s
    trn1     \t2\().4s, \x2\().4s, \x3\().4s
    trn2     \t3\().4s, \x2\().4s, \x3\().4s
    trn1     \x0\().2d, \t0\().2d, \t2\().2d
    trn2     \x2\().2d, \t0\().2d, \t2\().2d
    trn1     \x1\().2d, \t1\().2d, \t3\().2d
    trn2     \x3\().2d, \t1\().2d, \t3\().2d
.endm

// Load q = 8380417 = 0x7FE001 into all lanes of the given vector via wtmp.
.macro MLDSA_DUPQ vec, wtmp
    movz     \wtmp, #0xE001
    movk     \wtmp, #0x7F, lsl #16
    dup      \vec\().4s, \wtmp
.endm

// =============================================================================
// MLDSA_NTTTopAsm — forward NTT, layers len = 128/64/32/16 (Cooley-Tukey)
// =============================================================================
//
// Signature: void MLDSA_NTTTopAsm(int32_t *a, const int32_t *table)
//   x0: 256-coefficient polynomial (in/out)
//   x1: twiddle table (top region: zeta_1..zeta_15 pairs, q in v7.s[2])
//
// Four iterations c = 0..3 process the 16 vectors {a + 16c + 64t : t=0..15}
// (v8..v23), applying all four layers in registers before storing back.
//
// Register allocation:
//   v0-v7   twiddles (v7.s[2] = q)        v8-v23  polynomial data
//   v24-v31 macro scratch                 x9 counter, x10 block pointer
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLDSA_NTTTopAsm)
AARCH64_PACIASP
    sub      sp, sp, #(4*16)
    stp      d8,  d9,  [sp, #0*16]
    stp      d10, d11, [sp, #1*16]
    stp      d12, d13, [sp, #2*16]
    stp      d14, d15, [sp, #3*16]

    ld1      {v0.4s, v1.4s, v2.4s, v3.4s}, [x1], #64
    ld1      {v4.4s, v5.4s, v6.4s, v7.4s}, [x1]
    mov      x9, #4
    mov      x10, x0
1:
    VLDQ_4S 8,  x10, #0*64
    VLDQ_4S 9,  x10, #1*64
    VLDQ_4S 10, x10, #2*64
    VLDQ_4S 11, x10, #3*64
    VLDQ_4S 12, x10, #4*64
    VLDQ_4S 13, x10, #5*64
    VLDQ_4S 14, x10, #6*64
    VLDQ_4S 15, x10, #7*64
    VLDQ_4S 16, x10, #8*64
    VLDQ_4S 17, x10, #9*64
    VLDQ_4S 18, x10, #10*64
    VLDQ_4S 19, x10, #11*64
    VLDQ_4S 20, x10, #12*64
    VLDQ_4S 21, x10, #13*64
    VLDQ_4S 22, x10, #14*64
    VLDQ_4S 23, x10, #15*64

    // layer len=128: twiddle zeta_1 (v0.s[0,1])
    MLDSA_CT4 v8,  v16, v0, 0, 1, v9,  v17, v0, 0, 1, v10, v18, v0, 0, 1, v11, v19, v0, 0, 1, v7, 2
    MLDSA_CT4 v12, v20, v0, 0, 1, v13, v21, v0, 0, 1, v14, v22, v0, 0, 1, v15, v23, v0, 0, 1, v7, 2

    // layer len=64: zeta_2 (v0.s[2,3]) lower half, zeta_3 (v1.s[0,1]) upper half
    MLDSA_CT4 v8,  v12, v0, 2, 3, v9,  v13, v0, 2, 3, v10, v14, v0, 2, 3, v11, v15, v0, 2, 3, v7, 2
    MLDSA_CT4 v16, v20, v1, 0, 1, v17, v21, v1, 0, 1, v18, v22, v1, 0, 1, v19, v23, v1, 0, 1, v7, 2

    // layer len=32: zeta_4..zeta_7 (v1.s[2,3], v2.s[0,1], v2.s[2,3], v3.s[0,1])
    MLDSA_CT4 v8,  v10, v1, 2, 3, v9,  v11, v1, 2, 3, v12, v14, v2, 0, 1, v13, v15, v2, 0, 1, v7, 2
    MLDSA_CT4 v16, v18, v2, 2, 3, v17, v19, v2, 2, 3, v20, v22, v3, 0, 1, v21, v23, v3, 0, 1, v7, 2

    // layer len=16: zeta_8..zeta_15
    MLDSA_CT4 v8,  v9,  v3, 2, 3, v10, v11, v4, 0, 1, v12, v13, v4, 2, 3, v14, v15, v5, 0, 1, v7, 2
    MLDSA_CT4 v16, v17, v5, 2, 3, v18, v19, v6, 0, 1, v20, v21, v6, 2, 3, v22, v23, v7, 0, 1, v7, 2

    VSTQ_4S 8,  x10, #0*64
    VSTQ_4S 9,  x10, #1*64
    VSTQ_4S 10, x10, #2*64
    VSTQ_4S 11, x10, #3*64
    VSTQ_4S 12, x10, #4*64
    VSTQ_4S 13, x10, #5*64
    VSTQ_4S 14, x10, #6*64
    VSTQ_4S 15, x10, #7*64
    VSTQ_4S 16, x10, #8*64
    VSTQ_4S 17, x10, #9*64
    VSTQ_4S 18, x10, #10*64
    VSTQ_4S 19, x10, #11*64
    VSTQ_4S 20, x10, #12*64
    VSTQ_4S 21, x10, #13*64
    VSTQ_4S 22, x10, #14*64
    VSTQ_4S 23, x10, #15*64

    add      x10, x10, #16
    subs     x9, x9, #1
    b.ne     1b

    ldp      d8,  d9,  [sp, #0*16]
    ldp      d10, d11, [sp, #1*16]
    ldp      d12, d13, [sp, #2*16]
    ldp      d14, d15, [sp, #3*16]
    add      sp, sp, #(4*16)
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(MLDSA_NTTTopAsm)

// =============================================================================
// MLDSA_NTTBotAsm — forward NTT, layers len = 8/4/2/1 (Cooley-Tukey)
// =============================================================================
//
// Signature: void MLDSA_NTTBotAsm(int32_t *a, const int32_t *table)
//   x0: 256-coefficient polynomial (in/out)
//   x1: twiddle table (bottom region, 64 entries per iteration)
//
// Eight iterations, each handling two 16-coefficient blocks B0/B1 (vectors
// v16-v19 / v20-v23). len = 8/4 use indexed scalar twiddles; a 4x4 transpose
// then moves the len = 2/1 strides across vectors so per-lane twiddle vectors
// can be used, and a second transpose restores the layout.
//
// Register allocation:
//   v0      q (all lanes)                 v1-v3   len=8/4 twiddles
//   v4-v9   block B0 vector twiddles      v10-v15 block B1 vector twiddles
//   v16-v23 polynomial data               v24-v31 macro scratch
//   x9 counter, x10 load pointer, x11 store pointer
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLDSA_NTTBotAsm)
AARCH64_PACIASP
    sub      sp, sp, #(4*16)
    stp      d8,  d9,  [sp, #0*16]
    stp      d10, d11, [sp, #1*16]
    stp      d12, d13, [sp, #2*16]
    stp      d14, d15, [sp, #3*16]

    MLDSA_DUPQ v0, w9
    mov      x9, #8
    mov      x10, x0
    mov      x11, x0
1:
    ld1      {v1.4s, v2.4s, v3.4s}, [x1], #48
    add      x1, x1, #16
    ld1      {v4.4s, v5.4s, v6.4s, v7.4s}, [x1], #64
    ld1      {v8.4s, v9.4s}, [x1], #32
    ld1      {v10.4s, v11.4s, v12.4s, v13.4s}, [x1], #64
    ld1      {v14.4s, v15.4s}, [x1], #32
    ld1      {v16.4s, v17.4s, v18.4s, v19.4s}, [x10], #64
    ld1      {v20.4s, v21.4s, v22.4s, v23.4s}, [x10], #64

    // layer len=8: zeta_{16+B0} (v1.s[0,1]), zeta_{16+B1} (v1.s[2,3])
    MLDSA_CT4 v16, v18, v1, 0, 1, v17, v19, v1, 0, 1, v20, v22, v1, 2, 3, v21, v23, v1, 2, 3, v0, 0

    // layer len=4: zeta_{32+2B}/zeta_{33+2B} (v2 for B0, v3 for B1)
    MLDSA_CT4 v16, v17, v2, 0, 1, v18, v19, v2, 2, 3, v20, v21, v3, 0, 1, v22, v23, v3, 2, 3, v0, 0

    MLDSA_TRN4 v16, v17, v18, v19, v24, v25, v26, v27
    MLDSA_TRN4 v20, v21, v22, v23, v28, v29, v30, v31

    // layer len=2 (transposed): per-lane twiddles zeta_{64+4B+v}
    MLDSA_CT4V v16, v18, v4, v5, v17, v19, v4, v5, v20, v22, v10, v11, v21, v23, v10, v11, v0, 0

    // layer len=1 (transposed): even pairs zeta_{128+8B+2v}, odd pairs +1
    MLDSA_CT4V v16, v17, v6, v7, v18, v19, v8, v9, v20, v21, v12, v13, v22, v23, v14, v15, v0, 0

    MLDSA_TRN4 v16, v17, v18, v19, v24, v25, v26, v27
    MLDSA_TRN4 v20, v21, v22, v23, v28, v29, v30, v31

    st1      {v16.4s, v17.4s, v18.4s, v19.4s}, [x11], #64
    st1      {v20.4s, v21.4s, v22.4s, v23.4s}, [x11], #64

    subs     x9, x9, #1
    b.ne     1b

    ldp      d8,  d9,  [sp, #0*16]
    ldp      d10, d11, [sp, #1*16]
    ldp      d12, d13, [sp, #2*16]
    ldp      d14, d15, [sp, #3*16]
    add      sp, sp, #(4*16)
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(MLDSA_NTTBotAsm)

// =============================================================================
// MLDSA_INTTBotAsm — inverse NTT, layers len = 1/2/4/8 (Gentleman-Sande)
// =============================================================================
//
// Signature: void MLDSA_INTTBotAsm(int32_t *a, const int32_t *table)
//   x0: 256-coefficient polynomial (in/out)
//   x1: inverse twiddle table (bottom region, 64 entries per iteration)
//
// Mirror of MLDSA_NTTBotAsm: transpose, len = 1/2 with per-lane inverse
// twiddles, transpose back, then len = 4/8 with indexed scalars.
// Register allocation identical to MLDSA_NTTBotAsm.
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLDSA_INTTBotAsm)
AARCH64_PACIASP
    sub      sp, sp, #(4*16)
    stp      d8,  d9,  [sp, #0*16]
    stp      d10, d11, [sp, #1*16]
    stp      d12, d13, [sp, #2*16]
    stp      d14, d15, [sp, #3*16]

    MLDSA_DUPQ v0, w9
    mov      x9, #8
    mov      x10, x0
    mov      x11, x0
1:
    ld1      {v1.4s, v2.4s, v3.4s}, [x1], #48
    add      x1, x1, #16
    ld1      {v4.4s, v5.4s, v6.4s, v7.4s}, [x1], #64
    ld1      {v8.4s, v9.4s}, [x1], #32
    ld1      {v10.4s, v11.4s, v12.4s, v13.4s}, [x1], #64
    ld1      {v14.4s, v15.4s}, [x1], #32
    ld1      {v16.4s, v17.4s, v18.4s, v19.4s}, [x10], #64
    ld1      {v20.4s, v21.4s, v22.4s, v23.4s}, [x10], #64

    MLDSA_TRN4 v16, v17, v18, v19, v24, v25, v26, v27
    MLDSA_TRN4 v20, v21, v22, v23, v28, v29, v30, v31

    // layer len=1 (transposed): even pairs -zeta_{255-8B-2v}, odd pairs -zeta_{254-8B-2v}
    MLDSA_GS4V v16, v17, v4, v5, v18, v19, v6, v7, v20, v21, v10, v11, v22, v23, v12, v13, v0, 0

    // layer len=2 (transposed): -zeta_{127-4B-v}
    MLDSA_GS4V v16, v18, v8, v9, v17, v19, v8, v9, v20, v22, v14, v15, v21, v23, v14, v15, v0, 0

    MLDSA_TRN4 v16, v17, v18, v19, v24, v25, v26, v27
    MLDSA_TRN4 v20, v21, v22, v23, v28, v29, v30, v31

    // layer len=4: -zeta_{63-2B} / -zeta_{62-2B} (v2 for B0, v3 for B1)
    MLDSA_GS4 v16, v17, v2, 0, 1, v18, v19, v2, 2, 3, v20, v21, v3, 0, 1, v22, v23, v3, 2, 3, v0, 0

    // layer len=8: -zeta_{31-B0} (v1.s[0,1]), -zeta_{31-B1} (v1.s[2,3])
    MLDSA_GS4 v16, v18, v1, 0, 1, v17, v19, v1, 0, 1, v20, v22, v1, 2, 3, v21, v23, v1, 2, 3, v0, 0

    st1      {v16.4s, v17.4s, v18.4s, v19.4s}, [x11], #64
    st1      {v20.4s, v21.4s, v22.4s, v23.4s}, [x11], #64

    subs     x9, x9, #1
    b.ne     1b

    ldp      d8,  d9,  [sp, #0*16]
    ldp      d10, d11, [sp, #1*16]
    ldp      d12, d13, [sp, #2*16]
    ldp      d14, d15, [sp, #3*16]
    add      sp, sp, #(4*16)
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(MLDSA_INTTBotAsm)

// =============================================================================
// MLDSA_INTTTopAsm — inverse NTT, layers len = 16/32/64/128 + final scaling
// =============================================================================
//
// Signature: void MLDSA_INTTTopAsm(int32_t *a, const int32_t *table)
//   x0: 256-coefficient polynomial (in/out)
//   x1: inverse twiddle table (top region: -zeta_15..-zeta_2 pairs, then
//       F = 2^24 mod q and G = F * (-zeta_1) pairs in v7)
//
// Mirror of MLDSA_NTTTopAsm. The last layer is fused with the multiplication
// by F (sum branch) and G (difference branch), which performs the 1/256
// inverse scaling and cancels the pointwise 2^-32 Montgomery factor.
//
// Register allocation:
//   v0-v7   twiddles                      v8-v23  polynomial data
//   v24-v30 macro scratch                 v31     q (all lanes)
//   x9 counter, x10 block pointer
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLDSA_INTTTopAsm)
AARCH64_PACIASP
    sub      sp, sp, #(4*16)
    stp      d8,  d9,  [sp, #0*16]
    stp      d10, d11, [sp, #1*16]
    stp      d12, d13, [sp, #2*16]
    stp      d14, d15, [sp, #3*16]

    ld1      {v0.4s, v1.4s, v2.4s, v3.4s}, [x1], #64
    ld1      {v4.4s, v5.4s, v6.4s, v7.4s}, [x1]
    MLDSA_DUPQ v31, w9
    mov      x9, #4
    mov      x10, x0
1:
    VLDQ_4S 8,  x10, #0*64
    VLDQ_4S 9,  x10, #1*64
    VLDQ_4S 10, x10, #2*64
    VLDQ_4S 11, x10, #3*64
    VLDQ_4S 12, x10, #4*64
    VLDQ_4S 13, x10, #5*64
    VLDQ_4S 14, x10, #6*64
    VLDQ_4S 15, x10, #7*64
    VLDQ_4S 16, x10, #8*64
    VLDQ_4S 17, x10, #9*64
    VLDQ_4S 18, x10, #10*64
    VLDQ_4S 19, x10, #11*64
    VLDQ_4S 20, x10, #12*64
    VLDQ_4S 21, x10, #13*64
    VLDQ_4S 22, x10, #14*64
    VLDQ_4S 23, x10, #15*64

    // layer len=16: -zeta_15..-zeta_8 (v0..v3, two pairs each)
    MLDSA_GS3 v8,  v9,  v0, 0, 1, v10, v11, v0, 2, 3, v12, v13, v1, 0, 1, v31, 0
    MLDSA_GS3 v14, v15, v1, 2, 3, v16, v17, v2, 0, 1, v18, v19, v2, 2, 3, v31, 0
    MLDSA_GS2 v20, v21, v3, 0, 1, v22, v23, v3, 2, 3, v31, 0

    // layer len=32: -zeta_7..-zeta_4 (v4, v5)
    MLDSA_GS3 v8,  v10, v4, 0, 1, v9,  v11, v4, 0, 1, v12, v14, v4, 2, 3, v31, 0
    MLDSA_GS3 v13, v15, v4, 2, 3, v16, v18, v5, 0, 1, v17, v19, v5, 0, 1, v31, 0
    MLDSA_GS2 v20, v22, v5, 2, 3, v21, v23, v5, 2, 3, v31, 0

    // layer len=64: -zeta_3 (v6.s[0,1]) lower half, -zeta_2 (v6.s[2,3]) upper half
    MLDSA_GS3 v8,  v12, v6, 0, 1, v9,  v13, v6, 0, 1, v10, v14, v6, 0, 1, v31, 0
    MLDSA_GS3 v11, v15, v6, 0, 1, v16, v20, v6, 2, 3, v17, v21, v6, 2, 3, v31, 0
    MLDSA_GS2 v18, v22, v6, 2, 3, v19, v23, v6, 2, 3, v31, 0

    // layer len=128 fused with scaling: a' = (a+b)*F, b' = (a-b)*G
    MLDSA_FS2 v8,  v16, v9,  v17
    MLDSA_FS2 v10, v18, v11, v19
    MLDSA_FS2 v12, v20, v13, v21
    MLDSA_FS2 v14, v22, v15, v23

    VSTQ_4S 8,  x10, #0*64
    VSTQ_4S 9,  x10, #1*64
    VSTQ_4S 10, x10, #2*64
    VSTQ_4S 11, x10, #3*64
    VSTQ_4S 12, x10, #4*64
    VSTQ_4S 13, x10, #5*64
    VSTQ_4S 14, x10, #6*64
    VSTQ_4S 15, x10, #7*64
    VSTQ_4S 16, x10, #8*64
    VSTQ_4S 17, x10, #9*64
    VSTQ_4S 18, x10, #10*64
    VSTQ_4S 19, x10, #11*64
    VSTQ_4S 20, x10, #12*64
    VSTQ_4S 21, x10, #13*64
    VSTQ_4S 22, x10, #14*64
    VSTQ_4S 23, x10, #15*64

    add      x10, x10, #16
    subs     x9, x9, #1
    b.ne     1b

    ldp      d8,  d9,  [sp, #0*16]
    ldp      d10, d11, [sp, #1*16]
    ldp      d12, d13, [sp, #2*16]
    ldp      d14, d15, [sp, #3*16]
    add      sp, sp, #(4*16)
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(MLDSA_INTTTopAsm)

// =============================================================================
// MLDSA_PointwiseAccMontAsm — accumulated pointwise multiply with reduction
// =============================================================================
//
// Signature: void MLDSA_PointwiseAccMontAsm(int32_t *t, const int32_t *const *a,
//                                           const int32_t *const *b, uint64_t l)
//   x0: output polynomial t
//   x1/x2: arrays of l pointers to NTT-domain polynomials
//   x3: number of polynomial pairs to accumulate (1 <= l <= 7)
//
// Computes t[j] = (sum_{i<l} a[i][j] * b[i][j]) * 2^-32 mod q for all j,
// |t[j]| <= q/2 + 2. Products are accumulated in 64-bit lanes, reduced once
// with a signed Montgomery reduction, then Barrett-reduced.
//
// Register allocation:
//   v0-v7   operand data / output scratch v16-v23 64-bit accumulators
//   v24-v27 Montgomery scratch            v28 q^-1 mod 2^32, v29 M, v30 q
//   x9 byte offset, x10 outer counter, x11/x12 pointer cursors,
//   x13 inner counter, x14/x15 row pointers
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLDSA_PointwiseAccMontAsm)
AARCH64_PACIASP
    movz     w9, #0x2001               // q^-1 mod 2^32 = 58728449
    movk     w9, #0x380, lsl #16
    dup      v28.4s, w9
    movz     w9, #0x0381               // M = round(2^53 / q) = 1074791297
    movk     w9, #0x4010, lsl #16
    dup      v29.4s, w9
    MLDSA_DUPQ v30, w9

    mov      x9, #0
    mov      x10, #16
1:
    movi     v16.2d, #0
    movi     v17.2d, #0
    movi     v18.2d, #0
    movi     v19.2d, #0
    movi     v20.2d, #0
    movi     v21.2d, #0
    movi     v22.2d, #0
    movi     v23.2d, #0
    mov      x11, x1
    mov      x12, x2
    mov      x13, x3
2:
    ldr      x14, [x11], #8
    ldr      x15, [x12], #8
    add      x14, x14, x9
    add      x15, x15, x9
    ld1      {v0.4s, v1.4s, v2.4s, v3.4s}, [x14]
    ld1      {v4.4s, v5.4s, v6.4s, v7.4s}, [x15]
    smlal    v16.2d, v0.2s, v4.2s
    smlal2   v17.2d, v0.4s, v4.4s
    smlal    v18.2d, v1.2s, v5.2s
    smlal2   v19.2d, v1.4s, v5.4s
    smlal    v20.2d, v2.2s, v6.2s
    smlal2   v21.2d, v2.4s, v6.4s
    smlal    v22.2d, v3.2s, v7.2s
    smlal2   v23.2d, v3.4s, v7.4s
    subs     x13, x13, #1
    b.ne     2b

    // signed Montgomery reduction: r = (T - (lo32(T) * q^-1 mod 2^32) * q) >> 32
    uzp1     v24.4s, v16.4s, v17.4s
    uzp1     v25.4s, v18.4s, v19.4s
    uzp1     v26.4s, v20.4s, v21.4s
    uzp1     v27.4s, v22.4s, v23.4s
    mul      v24.4s, v24.4s, v28.4s
    mul      v25.4s, v25.4s, v28.4s
    mul      v26.4s, v26.4s, v28.4s
    mul      v27.4s, v27.4s, v28.4s
    smlsl    v16.2d, v24.2s, v30.2s
    smlsl2   v17.2d, v24.4s, v30.4s
    smlsl    v18.2d, v25.2s, v30.2s
    smlsl2   v19.2d, v25.4s, v30.4s
    smlsl    v20.2d, v26.2s, v30.2s
    smlsl2   v21.2d, v26.4s, v30.4s
    smlsl    v22.2d, v27.2s, v30.2s
    smlsl2   v23.2d, v27.4s, v30.4s
    uzp2     v0.4s, v16.4s, v17.4s
    uzp2     v1.4s, v18.4s, v19.4s
    uzp2     v2.4s, v20.4s, v21.4s
    uzp2     v3.4s, v22.4s, v23.4s

    // Barrett reduction to |r| <= q/2 + 2
    sqdmulh  v4.4s, v0.4s, v29.4s
    sqdmulh  v5.4s, v1.4s, v29.4s
    sqdmulh  v6.4s, v2.4s, v29.4s
    sqdmulh  v7.4s, v3.4s, v29.4s
    srshr    v4.4s, v4.4s, #22
    srshr    v5.4s, v5.4s, #22
    srshr    v6.4s, v6.4s, #22
    srshr    v7.4s, v7.4s, #22
    mls      v0.4s, v4.4s, v30.4s
    mls      v1.4s, v5.4s, v30.4s
    mls      v2.4s, v6.4s, v30.4s
    mls      v3.4s, v7.4s, v30.4s

    st1      {v0.4s, v1.4s, v2.4s, v3.4s}, [x0], #64
    add      x9, x9, #64
    subs     x10, x10, #1
    b.ne     1b

AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(MLDSA_PointwiseAccMontAsm)

#endif /* HITLS_CRYPTO_MLDSA_ARMV8 */
