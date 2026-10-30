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
 *   - NTT top  (layers len = 128/64/32/16): four logical iterations c=0..3,
 *     each owning 16 vectors at byte offsets 16c + 64t (t=0..15), closed under
 *     the butterfly strides.
 *   - NTT bottom (layers len = 8/4/2/1): eight logical iterations over pairs of
 *     16-coefficient blocks. Layers with stride below the 4-lane width use a
 *     4x4 transpose (trn1/trn2 on .4S/.2D) so paired elements end up in
 *     different vectors, then per-lane twiddle vectors finish len = 2/1.
 *
 *   The inverse NTT mirrors this (bottom first, Gentleman-Sande butterflies)
 *   and fuses the final len = 128 layer with the multiplication by
 *   F = 256^-1 * 2^32 == 2^24 mod q, cancelling both the inverse-transform
 *   1/256 scaling and the single 2^-32 factor introduced by the Montgomery
 *   pointwise kernels (see asm_ml_dsa_ntt.c for the domain contract).
 *
 * Barrett multiplication pattern (32-bit lanes, exact mod q):
 *   For twiddles stored as pairs (zl, zh) with zl = z mod+- q and
 *   zh = round(zl * 2^31 / q):
 *     sqrdmulh hi, a, zh    // hi  = round(a * zh / 2^31) ~= round(a * z / q)
 *     mul      lo, a, zl    // lo  = a * z mod 2^32
 *     mls      lo, hi, q    // lo  = a * z - hi * q == a * z mod+- q
 *   |result| <= q * (1/2 + |a| / 2^32). Eight forward Cooley-Tukey layers on
 *   input in (-q, q) stay below 6q. Eight inverse Gentleman-Sande layers on
 *   input in (-q, q) have unreduced sums/differences below 256q < 2^31.
 *
 * Signed Montgomery reduction (pointwise and L4/L5/L7 accumulators):
 *   64-bit lane accumulators T = sum a_i * b_i, then
 *     m = signed32(lo32(T * q^-1))      (uzp1 + mul)
 *     r = (T - m * q) / 2^32           (smlsl/smlsl2 + uzp2, exact division)
 *   giving r == T * 2^-32 mod q. For l <= 7 and |a_i|, |b_i| < 6q,
 *   |r| < q/2 + 7*(6q)^2/2^32 < q, without a subsequent Barrett reduction.
 *
 * Functions:
 *   MLDSA_NTTAsm(int32_t *a, const int32_t *table)
 *   MLDSA_INTTAsm(int32_t *a, const int32_t *table)
 *   MLDSA_PointwiseMontAsm(int32_t *t, const int32_t *a, const int32_t *b)
 *   MLDSA_PointwiseAccMontL4Asm(int32_t *t, const int32_t *a, const int32_t *b)
 *   MLDSA_PointwiseAccMontL5Asm(int32_t *t, const int32_t *a, const int32_t *b)
 *   MLDSA_PointwiseAccMontL7Asm(int32_t *t, const int32_t *a, const int32_t *b)
 *
 * Optimizations relative to the original split-entry backend:
 *   - Reorder independent operations in forward Top; forward Bottom overlaps
 *     next-block loads with current-block arithmetic/stores.
 *   - Combine both stages per transform to share PAC and register-save work.
 *   - Pipeline inverse Bottom across blocks; interleave completed Top stores
 *     with independent products rather than waiting for a final store batch.
 *   - Use a dedicated pointwise kernel and fixed-length L4/L5/L7 accumulators
 *     with contiguous-vector addressing, avoiding temporary pointer arrays
 *     and a runtime inner-product-length loop.
 * The 4+4 split, two data passes, original twiddle values and fused inverse
 * scaling predate these scheduling changes; they are not new optimizations.
 * INTT Bottom covers eight blocks with fill, seven kernel rounds and drain;
 * this does not read a ninth block. Register assignments vary by stage and
 * by schedule; the shared inverse Top macros retain fixed scratch registers.
 * Twiddle table layout: see asm_ml_dsa_ntt.c.
 * ============================================================================
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MLDSA_ARMV8
#if defined(__AARCH64EB__) && !defined(HITLS_BIG_ENDIAN)
#error "Configure HITLS_PLATFORM_ENDIAN=big for a big-endian target."
#endif

#include "crypt_arm.h"

// Endian-safe stores must preserve vectors that remain live in the pipeline.
// VSTQ_4S[_POST] reverses lanes on big-endian targets; VFIX_4S restores them.
// On little-endian targets the restore is empty, retaining the original STR.
.macro MLDSA_VSTQ_4S vd, base, offset=#0
    VSTQ_4S \vd, \base, \offset
    VFIX_4S \vd
.endm

.macro MLDSA_VSTQ_4S_POST vd, base, inc=#16
    VSTQ_4S_POST \vd, \base, \inc
    VFIX_4S \vd
.endm

// Batched inverse butterflies use .4S lanes and an indexed modulus qv.s[qi].
// Three Gentleman-Sande butterflies, indexed twiddles. Scratch: v24-v29.
// The inverse Top stage keeps q in v31.
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

// Store the preceding independent output group while current products become ready.
.macro MLDSA_FS2_STORE a0, b0, a1, b1, p0, o0, p1, o1, p2, o2, p3, o3
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
    MLDSA_VSTQ_4S \p0, x10, \o0
    MLDSA_VSTQ_4S \p1, x10, \o1
    MLDSA_VSTQ_4S \p2, x10, \o2
    MLDSA_VSTQ_4S \p3, x10, \o3
    mls      \a0\().4s, v26.4s, v31.4s
    mls      \a1\().4s, v27.4s, v31.4s
    mls      \b0\().4s, v28.4s, v31.4s
    mls      \b1\().4s, v29.4s, v31.4s
.endm

// Load q = 8380417 = 0x7FE001 into all lanes of the given vector via wtmp.
.macro MLDSA_DUPQ vec, wtmp
    movz     \wtmp, #0xE001
    movk     \wtmp, #0x7F, lsl #16
    dup      \vec\().4s, \wtmp
.endm

// Forward 4+4 layers; x0 is the polynomial, x1 is the complete twiddle table.
CRYPT_AARCH64_FUNC_START(MLDSA_NTTAsm)

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
    VLDQ_4S 26, x10, #896
    VLDQ_4S 9, x10, #0
    VLDQ_4S 28, x10, #512
    VLDQ_4S 14, x10, #64
    VLDQ_4S 10, x10, #576
    VLDQ_4S 30, x10, #320
    VLDQ_4S 23, x10, #704
    VLDQ_4S 18, x10, #128
    VLDQ_4S 20, x10, #768
    VLDQ_4S 17, x10, #832
    sqrdmulh v19.4s, v26.4s, v0.s[1]
    VLDQ_4S 25, x10, #192
    VLDQ_4S 16, x10, #448
    mul v8.4s, v26.4s, v0.s[0]
    VLDQ_4S 21, x10, #256
    VLDQ_4S 26, x10, #960
    VLDQ_4S 31, x10, #384
    sqrdmulh v15.4s, v28.4s, v0.s[1]
    mul v27.4s, v28.4s, v0.s[0]
    mul v24.4s, v10.4s, v0.s[0]
    sqrdmulh v12.4s, v10.4s, v0.s[1]
    sqrdmulh v28.4s, v20.4s, v0.s[1]
    mul v10.4s, v20.4s, v0.s[0]
    sqrdmulh v20.4s, v17.4s, v0.s[1]
    mls v8.4s, v19.4s, v7.s[2]
    mls v10.4s, v28.4s, v7.s[2]
    mul v17.4s, v17.4s, v0.s[0]
    sub v22.4s, v31.4s, v8.4s
    mls v17.4s, v20.4s, v7.s[2]
    add v28.4s, v21.4s, v10.4s
    mls v27.4s, v15.4s, v7.s[2]
    sub v20.4s, v21.4s, v10.4s
    sqrdmulh v19.4s, v23.4s, v0.s[1]
    add v15.4s, v30.4s, v17.4s
    sub v13.4s, v30.4s, v17.4s
    mul v23.4s, v23.4s, v0.s[0]
    add v17.4s, v9.4s, v27.4s
    add v31.4s, v31.4s, v8.4s
    sqrdmulh v29.4s, v26.4s, v0.s[1]
    sub v27.4s, v9.4s, v27.4s
    VLDQ_4S 9, x10, #640
    mul v26.4s, v26.4s, v0.s[0]
    mls v23.4s, v19.4s, v7.s[2]
    mls v26.4s, v29.4s, v7.s[2]
    mul v10.4s, v15.4s, v0.s[2]
    sub v19.4s, v25.4s, v23.4s
    add v11.4s, v25.4s, v23.4s
    sqrdmulh v21.4s, v9.4s, v0.s[1]
    sqrdmulh v30.4s, v15.4s, v0.s[3]
    sub v23.4s, v16.4s, v26.4s
    add v16.4s, v16.4s, v26.4s
    sqrdmulh v29.4s, v28.4s, v0.s[3]
    mul v15.4s, v13.4s, v1.s[0]
    sqrdmulh v25.4s, v13.4s, v1.s[1]
    mul v28.4s, v28.4s, v0.s[2]
    sqrdmulh v26.4s, v31.4s, v0.s[3]
    mls v28.4s, v29.4s, v7.s[2]
    mul v13.4s, v31.4s, v0.s[2]
    mls v24.4s, v12.4s, v7.s[2]
    sub v12.4s, v17.4s, v28.4s
    add v8.4s, v17.4s, v28.4s
    mul v31.4s, v9.4s, v0.s[0]
    mls v31.4s, v21.4s, v7.s[2]
    add v28.4s, v14.4s, v24.4s
    mls v15.4s, v25.4s, v7.s[2]
    mls v13.4s, v26.4s, v7.s[2]
    sub v26.4s, v14.4s, v24.4s
    add v29.4s, v18.4s, v31.4s
    mls v10.4s, v30.4s, v7.s[2]
    sub v21.4s, v26.4s, v15.4s
    mul v24.4s, v16.4s, v0.s[2]
    add v17.4s, v26.4s, v15.4s
    sqrdmulh v26.4s, v16.4s, v0.s[3]
    sub v14.4s, v18.4s, v31.4s
    add v18.4s, v29.4s, v13.4s
    sub v30.4s, v29.4s, v13.4s
    sqrdmulh v25.4s, v22.4s, v1.s[1]
    sub v29.4s, v28.4s, v10.4s
    mul v22.4s, v22.4s, v1.s[0]
    add v28.4s, v28.4s, v10.4s
    mls v24.4s, v26.4s, v7.s[2]
    sqrdmulh v26.4s, v20.4s, v1.s[1]
    mul v10.4s, v20.4s, v1.s[0]
    sub v13.4s, v11.4s, v24.4s
    add v24.4s, v11.4s, v24.4s
    sqrdmulh v20.4s, v23.4s, v1.s[1]
    mul v23.4s, v23.4s, v1.s[0]
    mls v10.4s, v26.4s, v7.s[2]
    mls v23.4s, v20.4s, v7.s[2]
    sqrdmulh v26.4s, v18.4s, v1.s[3]
    sub v20.4s, v27.4s, v10.4s
    add v16.4s, v27.4s, v10.4s
    mul v27.4s, v18.4s, v1.s[2]
    add v18.4s, v19.4s, v23.4s
    sub v23.4s, v19.4s, v23.4s
    sqrdmulh v31.4s, v30.4s, v2.s[1]
    sub x9, x9, #1
.Lntt_slothy_full_top:
    mls v22.4s, v25.4s, v7.s[2]
    mls v27.4s, v26.4s, v7.s[2]
    mul v10.4s, v30.4s, v2.s[0]
    sub v30.4s, v14.4s, v22.4s
    add v25.4s, v14.4s, v22.4s
    mls v10.4s, v31.4s, v7.s[2]
    add v19.4s, v8.4s, v27.4s
    sub v8.4s, v8.4s, v27.4s
    sqrdmulh v26.4s, v24.4s, v1.s[3]
    mul v24.4s, v24.4s, v1.s[2]
    add v14.4s, v12.4s, v10.4s
    sqrdmulh v31.4s, v18.4s, v2.s[3]
    mul v18.4s, v18.4s, v2.s[2]
    sqrdmulh v22.4s, v13.4s, v2.s[1]
    mul v13.4s, v13.4s, v2.s[0]
    sqrdmulh v11.4s, v23.4s, v3.s[1]
    mul v27.4s, v23.4s, v3.s[0]
    mls v13.4s, v22.4s, v7.s[2]
    mls v18.4s, v31.4s, v7.s[2]
    mls v24.4s, v26.4s, v7.s[2]
    sub v15.4s, v29.4s, v13.4s
    add v23.4s, v29.4s, v13.4s
    sqrdmulh v29.4s, v30.4s, v3.s[1]
    sub v26.4s, v17.4s, v18.4s
    sqrdmulh v31.4s, v26.4s, v6.s[1]
    sub v9.4s, v28.4s, v24.4s
    add v13.4s, v28.4s, v24.4s
    mul v24.4s, v30.4s, v3.s[0]
    mls v27.4s, v11.4s, v7.s[2]
    mls v24.4s, v29.4s, v7.s[2]
    sqrdmulh v28.4s, v23.4s, v4.s[3]
    mul v29.4s, v23.4s, v4.s[2]
    sub v22.4s, v20.4s, v24.4s
    add v20.4s, v20.4s, v24.4s
    mul v24.4s, v26.4s, v6.s[0]
    add v26.4s, v17.4s, v18.4s
    mls v29.4s, v28.4s, v7.s[2]
    mul v23.4s, v26.4s, v5.s[2]
    sqrdmulh v30.4s, v26.4s, v5.s[3]
    sub v26.4s, v14.4s, v29.4s
    add v28.4s, v14.4s, v29.4s
    sqrdmulh v17.4s, v13.4s, v3.s[3]
    mul v11.4s, v13.4s, v3.s[2]
    MLDSA_VSTQ_4S 26, x10, #320
    MLDSA_VSTQ_4S 28, x10, #256
    sqrdmulh v26.4s, v25.4s, v2.s[3]
    mls v11.4s, v17.4s, v7.s[2]
    mul v28.4s, v25.4s, v2.s[2]
    mls v24.4s, v31.4s, v7.s[2]
    add v17.4s, v21.4s, v27.4s
    sub v13.4s, v21.4s, v27.4s
    sub v14.4s, v19.4s, v11.4s
    sqrdmulh v21.4s, v9.4s, v4.s[1]
    mul v9.4s, v9.4s, v4.s[0]
    MLDSA_VSTQ_4S 14, x10, #64
    sqrdmulh v31.4s, v15.4s, v5.s[1]
    mul v14.4s, v15.4s, v5.s[0]
    mls v9.4s, v21.4s, v7.s[2]
    sqrdmulh v15.4s, v17.4s, v6.s[3]
    mul v18.4s, v17.4s, v6.s[2]
    sub v27.4s, v8.4s, v9.4s
    mls v28.4s, v26.4s, v7.s[2]
    add v26.4s, v19.4s, v11.4s
    mls v18.4s, v15.4s, v7.s[2]
    MLDSA_VSTQ_4S 26, x10, #0
    sqrdmulh v26.4s, v13.4s, v7.s[1]
    sub v29.4s, v16.4s, v28.4s
    mls v14.4s, v31.4s, v7.s[2]
    add v28.4s, v16.4s, v28.4s
    sub v17.4s, v20.4s, v18.4s
    add v15.4s, v20.4s, v18.4s
    mul v21.4s, v13.4s, v7.s[0]
    mls v21.4s, v26.4s, v7.s[2]
    MLDSA_VSTQ_4S 17, x10, #832
    add v26.4s, v29.4s, v24.4s
    add v20.4s, v8.4s, v9.4s
    MLDSA_VSTQ_4S 27, x10, #192
    MLDSA_VSTQ_4S 15, x10, #768
    sub v10.4s, v12.4s, v10.4s
    mls v23.4s, v30.4s, v7.s[2]
    MLDSA_VSTQ_4S 26, x10, #640
    sub v26.4s, v29.4s, v24.4s
    MLDSA_VSTQ_4S 20, x10, #128
    sub v9.4s, v22.4s, v21.4s
    add v22.4s, v22.4s, v21.4s
    add v16.4s, v10.4s, v14.4s
    sub v10.4s, v10.4s, v14.4s
    MLDSA_VSTQ_4S 26, x10, #704
    sub v26.4s, v28.4s, v23.4s
    add v15.4s, v28.4s, v23.4s
    MLDSA_VSTQ_4S 9, x10, #960
    MLDSA_VSTQ_4S 22, x10, #896
    MLDSA_VSTQ_4S 16, x10, #384
    MLDSA_VSTQ_4S 10, x10, #448
    MLDSA_VSTQ_4S 26, x10, #576
    MLDSA_VSTQ_4S 15, x10, #512
    add x10, x10, #16
    VLDQ_4S 26, x10, #576
    VLDQ_4S 28, x10, #896
    VLDQ_4S 10, x10, #768
    VLDQ_4S 27, x10, #512
    VLDQ_4S 30, x10, #640
    VLDQ_4S 12, x10, #320
    VLDQ_4S 23, x10, #0
    VLDQ_4S 14, x10, #64
    VLDQ_4S 25, x10, #704
    mul v24.4s, v26.4s, v0.s[0]
    VLDQ_4S 18, x10, #128
    VLDQ_4S 19, x10, #192
    VLDQ_4S 8, x10, #256
    sqrdmulh v21.4s, v26.4s, v0.s[1]
    VLDQ_4S 26, x10, #384
    VLDQ_4S 11, x10, #960
    VLDQ_4S 17, x10, #832
    VLDQ_4S 16, x10, #448
    mul v31.4s, v28.4s, v0.s[0]
    sqrdmulh v28.4s, v28.4s, v0.s[1]
    sqrdmulh v13.4s, v10.4s, v0.s[1]
    mul v20.4s, v10.4s, v0.s[0]
    sqrdmulh v10.4s, v27.4s, v0.s[1]
    mul v27.4s, v27.4s, v0.s[0]
    sqrdmulh v15.4s, v11.4s, v0.s[1]
    mul v29.4s, v25.4s, v0.s[0]
    mul v22.4s, v11.4s, v0.s[0]
    mls v20.4s, v13.4s, v7.s[2]
    sqrdmulh v13.4s, v30.4s, v0.s[1]
    mls v27.4s, v10.4s, v7.s[2]
    sub v10.4s, v8.4s, v20.4s
    add v8.4s, v8.4s, v20.4s
    mul v20.4s, v17.4s, v0.s[0]
    sqrdmulh v11.4s, v17.4s, v0.s[1]
    add v17.4s, v23.4s, v27.4s
    sub v27.4s, v23.4s, v27.4s
    mls v31.4s, v28.4s, v7.s[2]
    mls v22.4s, v15.4s, v7.s[2]
    mls v24.4s, v21.4s, v7.s[2]
    add v21.4s, v26.4s, v31.4s
    mul v9.4s, v30.4s, v0.s[0]
    sub v30.4s, v26.4s, v31.4s
    add v26.4s, v16.4s, v22.4s
    sub v28.4s, v16.4s, v22.4s
    sqrdmulh v25.4s, v25.4s, v0.s[1]
    add v16.4s, v14.4s, v24.4s
    sqrdmulh v15.4s, v8.4s, v0.s[3]
    mul v23.4s, v8.4s, v0.s[2]
    sub v24.4s, v14.4s, v24.4s
    sqrdmulh v31.4s, v21.4s, v0.s[3]
    mul v8.4s, v21.4s, v0.s[2]
    mls v20.4s, v11.4s, v7.s[2]
    mls v8.4s, v31.4s, v7.s[2]
    mls v9.4s, v13.4s, v7.s[2]
    sub v21.4s, v12.4s, v20.4s
    add v11.4s, v12.4s, v20.4s
    mls v23.4s, v15.4s, v7.s[2]
    mls v29.4s, v25.4s, v7.s[2]
    add v14.4s, v18.4s, v9.4s
    mul v22.4s, v30.4s, v1.s[0]
    sub v12.4s, v17.4s, v23.4s
    sqrdmulh v25.4s, v30.4s, v1.s[1]
    add v15.4s, v14.4s, v8.4s
    sub v30.4s, v14.4s, v8.4s
    add v8.4s, v17.4s, v23.4s
    sqrdmulh v14.4s, v10.4s, v1.s[1]
    add v13.4s, v19.4s, v29.4s
    sub v31.4s, v19.4s, v29.4s
    sqrdmulh v17.4s, v21.4s, v1.s[1]
    mul v21.4s, v21.4s, v1.s[0]
    sqrdmulh v23.4s, v28.4s, v1.s[1]
    mls v21.4s, v17.4s, v7.s[2]
    mul v19.4s, v28.4s, v1.s[0]
    mls v19.4s, v23.4s, v7.s[2]
    add v17.4s, v24.4s, v21.4s
    sub v21.4s, v24.4s, v21.4s
    mul v24.4s, v10.4s, v1.s[0]
    mls v24.4s, v14.4s, v7.s[2]
    sub v14.4s, v18.4s, v9.4s
    sub v23.4s, v31.4s, v19.4s
    add v18.4s, v31.4s, v19.4s
    sqrdmulh v19.4s, v11.4s, v0.s[3]
    mul v31.4s, v11.4s, v0.s[2]
    sub v20.4s, v27.4s, v24.4s
    sqrdmulh v11.4s, v26.4s, v0.s[3]
    mls v31.4s, v19.4s, v7.s[2]
    mul v9.4s, v26.4s, v0.s[2]
    mls v9.4s, v11.4s, v7.s[2]
    sub v29.4s, v16.4s, v31.4s
    add v28.4s, v16.4s, v31.4s
    sqrdmulh v31.4s, v30.4s, v2.s[1]
    add v16.4s, v27.4s, v24.4s
    mul v27.4s, v15.4s, v1.s[2]
    add v24.4s, v13.4s, v9.4s
    sqrdmulh v26.4s, v15.4s, v1.s[3]
    sub v13.4s, v13.4s, v9.4s
    subs x9, x9, #1
    b.ne .Lntt_slothy_full_top
    sqrdmulh v19.4s, v18.4s, v2.s[3]
    sqrdmulh v15.4s, v13.4s, v2.s[1]
    mls v22.4s, v25.4s, v7.s[2]
    mul v9.4s, v13.4s, v2.s[0]
    mls v9.4s, v15.4s, v7.s[2]
    add v10.4s, v14.4s, v22.4s
    mls v27.4s, v26.4s, v7.s[2]
    sub v22.4s, v14.4s, v22.4s
    sqrdmulh v25.4s, v24.4s, v1.s[3]
    add v11.4s, v29.4s, v9.4s
    sqrdmulh v14.4s, v22.4s, v3.s[1]
    sub v29.4s, v29.4s, v9.4s
    sqrdmulh v9.4s, v11.4s, v4.s[3]
    mul v13.4s, v11.4s, v4.s[2]
    mul v11.4s, v22.4s, v3.s[0]
    mls v13.4s, v9.4s, v7.s[2]
    mul v9.4s, v10.4s, v2.s[2]
    mul v24.4s, v24.4s, v1.s[2]
    mls v24.4s, v25.4s, v7.s[2]
    mls v11.4s, v14.4s, v7.s[2]
    sqrdmulh v15.4s, v10.4s, v2.s[3]
    sub v26.4s, v28.4s, v24.4s
    add v28.4s, v28.4s, v24.4s
    mul v24.4s, v18.4s, v2.s[2]
    sub v22.4s, v20.4s, v11.4s
    mls v24.4s, v19.4s, v7.s[2]
    add v19.4s, v8.4s, v27.4s
    sub v8.4s, v8.4s, v27.4s
    mls v9.4s, v15.4s, v7.s[2]
    mul v25.4s, v29.4s, v5.s[0]
    add v15.4s, v17.4s, v24.4s
    mul v14.4s, v28.4s, v3.s[2]
    sub v24.4s, v17.4s, v24.4s
    sub v18.4s, v16.4s, v9.4s
    sqrdmulh v27.4s, v15.4s, v5.s[3]
    add v16.4s, v16.4s, v9.4s
    mul v17.4s, v15.4s, v5.s[2]
    sqrdmulh v15.4s, v29.4s, v5.s[1]
    sqrdmulh v10.4s, v28.4s, v3.s[3]
    sqrdmulh v28.4s, v23.4s, v3.s[1]
    mls v17.4s, v27.4s, v7.s[2]
    mul v27.4s, v23.4s, v3.s[0]
    add v20.4s, v20.4s, v11.4s
    sqrdmulh v11.4s, v26.4s, v4.s[1]
    sub v9.4s, v16.4s, v17.4s
    mul v29.4s, v30.4s, v2.s[0]
    add v16.4s, v16.4s, v17.4s
    MLDSA_VSTQ_4S 9, x10, #576
    mls v29.4s, v31.4s, v7.s[2]
    mul v30.4s, v26.4s, v4.s[0]
    MLDSA_VSTQ_4S 16, x10, #512
    sub v17.4s, v12.4s, v29.4s
    add v12.4s, v12.4s, v29.4s
    mls v27.4s, v28.4s, v7.s[2]
    sub v31.4s, v12.4s, v13.4s
    mls v14.4s, v10.4s, v7.s[2]
    add v16.4s, v12.4s, v13.4s
    sqrdmulh v23.4s, v24.4s, v6.s[1]
    MLDSA_VSTQ_4S 31, x10, #320
    add v12.4s, v21.4s, v27.4s
    mul v29.4s, v24.4s, v6.s[0]
    sub v21.4s, v21.4s, v27.4s
    MLDSA_VSTQ_4S 16, x10, #256
    sub v10.4s, v19.4s, v14.4s
    add v28.4s, v19.4s, v14.4s
    sqrdmulh v24.4s, v12.4s, v6.s[3]
    mls v29.4s, v23.4s, v7.s[2]
    MLDSA_VSTQ_4S 10, x10, #64
    MLDSA_VSTQ_4S 28, x10, #0
    mls v25.4s, v15.4s, v7.s[2]
    mls v30.4s, v11.4s, v7.s[2]
    add v27.4s, v18.4s, v29.4s
    mul v9.4s, v12.4s, v6.s[2]
    sub v13.4s, v18.4s, v29.4s
    sub v19.4s, v17.4s, v25.4s
    MLDSA_VSTQ_4S 27, x10, #640
    sqrdmulh v28.4s, v21.4s, v7.s[1]
    MLDSA_VSTQ_4S 13, x10, #704
    sub v13.4s, v8.4s, v30.4s
    mls v9.4s, v24.4s, v7.s[2]
    MLDSA_VSTQ_4S 19, x10, #448
    MLDSA_VSTQ_4S 13, x10, #192
    mul v14.4s, v21.4s, v7.s[0]
    mls v14.4s, v28.4s, v7.s[2]
    add v24.4s, v20.4s, v9.4s
    sub v23.4s, v20.4s, v9.4s
    add v30.4s, v8.4s, v30.4s
    add v31.4s, v17.4s, v25.4s
    MLDSA_VSTQ_4S 24, x10, #768
    sub v16.4s, v22.4s, v14.4s
    add v22.4s, v22.4s, v14.4s
    MLDSA_VSTQ_4S 23, x10, #832
    MLDSA_VSTQ_4S 30, x10, #128
    MLDSA_VSTQ_4S 31, x10, #384
    MLDSA_VSTQ_4S 16, x10, #960
    MLDSA_VSTQ_4S 22, x10, #896
    add x10, x10, #16
    // Second pass: advance past the Top table, retaining q for the Bottom stage.
    add      x1, x1, #64
    dup      v0.4s, v7.s[2]

    mov      x9, #8
    mov      x10, x0
    mov      x11, x0
    VLDQ_4S 22, x1, #0
    VLDQ_4S 26, x10, #48
    VLDQ_4S 2, x1, #16
    VLDQ_4S 3, x1, #32
    add x1, x1, #48
    VLDQ_4S 23, x10, #16
    VLDQ_4S 21, x10, #32
    VLDQ_4S 27, x10, #0
    add x10, x10, #64
    add x1, x1, #16
    sqrdmulh v30.4s, v26.4s, v22.s[1]
    VLDQ_4S 5, x1, #16
    VLDQ_4S 4, x1, #0
    VLDQ_4S 6, x1, #32
    VLDQ_4S 7, x1, #48
    mul v16.4s, v21.4s, v22.s[0]
    add x1, x1, #64
    VLDQ_4S 25, x10, #48
    mul v20.4s, v26.4s, v22.s[0]
    VLDQ_4S 14, x10, #32
    VLDQ_4S 9, x1, #16
    mls v20.4s, v30.4s, v0.s[0]
    VLDQ_4S 26, x10, #16
    VLDQ_4S 8, x1, #0
    add x1, x1, #32
    VLDQ_4S 28, x10, #0
    add x10, x10, #64
    sqrdmulh v21.4s, v21.4s, v22.s[1]
    VLDQ_4S 10, x1, #0
    VLDQ_4S 12, x1, #32
    sqrdmulh v30.4s, v14.4s, v22.s[3]
    VLDQ_4S 11, x1, #16
    VLDQ_4S 13, x1, #48
    add v17.4s, v23.4s, v20.4s
    add x1, x1, #64
    sub v23.4s, v23.4s, v20.4s
    mul v1.4s, v14.4s, v22.s[2]
    VLDQ_4S 14, x1, #0
    VLDQ_4S 15, x1, #16
    add x1, x1, #32
    sqrdmulh v29.4s, v17.4s, v2.s[1]
    mls v16.4s, v21.4s, v0.s[0]
    mul v19.4s, v17.4s, v2.s[0]
    mls v19.4s, v29.4s, v0.s[0]
    sub v18.4s, v27.4s, v16.4s
    add v31.4s, v27.4s, v16.4s
    sqrdmulh v29.4s, v25.4s, v22.s[3]
    mul v22.4s, v25.4s, v22.s[2]
    sub v21.4s, v31.4s, v19.4s
    add v17.4s, v31.4s, v19.4s
    sqrdmulh v20.4s, v23.4s, v2.s[3]
    mls v22.4s, v29.4s, v0.s[0]
    trn1 v24.4s, v17.4s, v21.4s
    mul v29.4s, v23.4s, v2.s[2]
    trn2 v19.4s, v17.4s, v21.4s
    mls v29.4s, v20.4s, v0.s[0]
    add v17.4s, v26.4s, v22.4s
    add v31.4s, v18.4s, v29.4s
    sqrdmulh v27.4s, v17.4s, v3.s[1]
    sub v21.4s, v26.4s, v22.4s
    sub v18.4s, v18.4s, v29.4s
    mls v1.4s, v30.4s, v0.s[0]
    sqrdmulh v22.4s, v21.4s, v3.s[3]
    trn2 v29.4s, v31.4s, v18.4s
    mul v17.4s, v17.4s, v3.s[0]
    trn1 v26.4s, v31.4s, v18.4s
    sub v23.4s, v28.4s, v1.4s
    add v16.4s, v28.4s, v1.4s
    mul v25.4s, v21.4s, v3.s[2]
    trn1 v2.2d, v19.2d, v29.2d
    trn2 v31.2d, v19.2d, v29.2d
    mls v25.4s, v22.4s, v0.s[0]
    trn2 v20.2d, v24.2d, v26.2d
    mls v17.4s, v27.4s, v0.s[0]
    sqrdmulh v3.4s, v31.4s, v5.4s
    add v30.4s, v23.4s, v25.4s
    sub x9, x9, #1
.Lntt_slothy_full_bot:
    trn1 v29.2d, v24.2d, v26.2d
    sub v21.4s, v23.4s, v25.4s
    VLDQ_4S 23, x10, #16
    VLDQ_4S 27, x10, #0
    mul v24.4s, v31.4s, v4.4s
    sub v18.4s, v16.4s, v17.4s
    add v22.4s, v16.4s, v17.4s
    VLDQ_4S 26, x10, #48
    trn1 v31.4s, v30.4s, v21.4s
    sqrdmulh v17.4s, v20.4s, v5.4s
    trn2 v28.4s, v30.4s, v21.4s
    mls v24.4s, v3.4s, v0.s[0]
    VLDQ_4S 3, x1, #32
    trn2 v21.4s, v22.4s, v18.4s
    trn1 v16.4s, v22.4s, v18.4s
    mul v5.4s, v20.4s, v4.4s
    trn2 v1.2d, v21.2d, v28.2d
    mls v5.4s, v17.4s, v0.s[0]
    trn2 v19.2d, v16.2d, v31.2d
    trn1 v21.2d, v21.2d, v28.2d
    sqrdmulh v22.4s, v1.4s, v11.4s
    trn1 v16.2d, v16.2d, v31.2d
    mul v17.4s, v1.4s, v10.4s
    add v18.4s, v29.4s, v5.4s
    sub v31.4s, v29.4s, v5.4s
    sqrdmulh v28.4s, v19.4s, v11.4s
    sub v4.4s, v2.4s, v24.4s
    add v2.4s, v2.4s, v24.4s
    mls v17.4s, v22.4s, v0.s[0]
    mul v22.4s, v2.4s, v6.4s
    sqrdmulh v6.4s, v2.4s, v7.4s
    VLDQ_4S 2, x1, #16
    add v11.4s, v21.4s, v17.4s
    sub v21.4s, v21.4s, v17.4s
    sqrdmulh v17.4s, v4.4s, v9.4s
    mul v8.4s, v4.4s, v8.4s
    mls v22.4s, v6.4s, v0.s[0]
    mls v8.4s, v17.4s, v0.s[0]
    sub v7.4s, v18.4s, v22.4s
    mul v4.4s, v19.4s, v10.4s
    add v6.4s, v18.4s, v22.4s
    VLDQ_4S 22, x1, #0
    add x1, x1, #48
    mls v4.4s, v28.4s, v0.s[0]
    sub v17.4s, v31.4s, v8.4s
    add v30.4s, v31.4s, v8.4s
    sqrdmulh v31.4s, v11.4s, v13.4s
    trn1 v10.4s, v6.4s, v7.4s
    trn2 v28.4s, v30.4s, v17.4s
    mul v12.4s, v11.4s, v12.4s
    sub v11.4s, v16.4s, v4.4s
    sqrdmulh v15.4s, v21.4s, v15.4s
    trn1 v17.4s, v30.4s, v17.4s
    trn2 v18.4s, v6.4s, v7.4s
    add v20.4s, v16.4s, v4.4s
    mls v12.4s, v31.4s, v0.s[0]
    trn2 v6.2d, v10.2d, v17.2d
    mul v16.4s, v21.4s, v14.4s
    trn1 v14.2d, v10.2d, v17.2d
    MLDSA_VSTQ_4S 6, x11, #32
    add x1, x1, #16
    VLDQ_4S 21, x10, #32
    add x10, x10, #64
    mls v16.4s, v15.4s, v0.s[0]
    trn2 v17.2d, v18.2d, v28.2d
    trn1 v31.2d, v18.2d, v28.2d
    MLDSA_VSTQ_4S 14, x11, #0
    VLDQ_4S 5, x1, #16
    add v14.4s, v20.4s, v12.4s
    sub v12.4s, v20.4s, v12.4s
    VLDQ_4S 4, x1, #0
    MLDSA_VSTQ_4S 17, x11, #48
    sqrdmulh v18.4s, v26.4s, v22.s[1]
    VLDQ_4S 6, x1, #32
    MLDSA_VSTQ_4S 31, x11, #16
    add x11, x11, #64
    VLDQ_4S 7, x1, #48
    add x1, x1, #64
    sub v1.4s, v11.4s, v16.4s
    VLDQ_4S 19, x10, #32
    add v13.4s, v11.4s, v16.4s
    mul v16.4s, v26.4s, v22.s[0]
    VLDQ_4S 8, x1, #0
    VLDQ_4S 9, x1, #16
    add x1, x1, #32
    mls v16.4s, v18.4s, v0.s[0]
    VLDQ_4S 30, x10, #48
    trn1 v24.4s, v14.4s, v12.4s
    VLDQ_4S 26, x10, #16
    trn1 v25.4s, v13.4s, v1.4s
    trn2 v11.4s, v14.4s, v12.4s
    trn2 v20.4s, v13.4s, v1.4s
    VLDQ_4S 1, x10, #0
    VLDQ_4S 12, x1, #32
    sqrdmulh v31.4s, v19.4s, v22.s[3]
    VLDQ_4S 13, x1, #48
    trn1 v15.2d, v11.2d, v20.2d
    sqrdmulh v17.4s, v30.4s, v22.s[3]
    VLDQ_4S 10, x1, #0
    trn2 v29.2d, v11.2d, v20.2d
    VLDQ_4S 11, x1, #16
    add x1, x1, #64
    mul v28.4s, v30.4s, v22.s[2]
    trn1 v30.2d, v24.2d, v25.2d
    add x10, x10, #64
    trn2 v20.2d, v24.2d, v25.2d
    MLDSA_VSTQ_4S 15, x11, #16
    VLDQ_4S 14, x1, #0
    MLDSA_VSTQ_4S 29, x11, #48
    add v24.4s, v23.4s, v16.4s
    mul v29.4s, v21.4s, v22.s[0]
    sub v23.4s, v23.4s, v16.4s
    MLDSA_VSTQ_4S 30, x11, #0
    sqrdmulh v18.4s, v21.4s, v22.s[1]
    MLDSA_VSTQ_4S 20, x11, #32
    add x11, x11, #64
    mls v28.4s, v17.4s, v0.s[0]
    VLDQ_4S 15, x1, #16
    add x1, x1, #32
    mls v29.4s, v18.4s, v0.s[0]
    mul v21.4s, v19.4s, v22.s[2]
    sub v16.4s, v26.4s, v28.4s
    add v22.4s, v26.4s, v28.4s
    mul v17.4s, v23.4s, v2.s[2]
    sub v18.4s, v27.4s, v29.4s
    add v28.4s, v27.4s, v29.4s
    sqrdmulh v23.4s, v23.4s, v2.s[3]
    sqrdmulh v30.4s, v24.4s, v2.s[1]
    mul v2.4s, v24.4s, v2.s[0]
    mls v17.4s, v23.4s, v0.s[0]
    mls v2.4s, v30.4s, v0.s[0]
    mls v21.4s, v31.4s, v0.s[0]
    add v31.4s, v18.4s, v17.4s
    sub v18.4s, v18.4s, v17.4s
    sqrdmulh v17.4s, v16.4s, v3.s[3]
    add v30.4s, v28.4s, v2.4s
    mul v25.4s, v16.4s, v3.s[2]
    sub v28.4s, v28.4s, v2.4s
    sub v23.4s, v1.4s, v21.4s
    add v16.4s, v1.4s, v21.4s
    sqrdmulh v21.4s, v22.4s, v3.s[1]
    trn2 v2.4s, v30.4s, v28.4s
    mls v25.4s, v17.4s, v0.s[0]
    trn2 v27.4s, v31.4s, v18.4s
    trn1 v24.4s, v30.4s, v28.4s
    mul v17.4s, v22.4s, v3.s[0]
    trn1 v26.4s, v31.4s, v18.4s
    trn2 v31.2d, v2.2d, v27.2d
    mls v17.4s, v21.4s, v0.s[0]
    trn1 v2.2d, v2.2d, v27.2d
    add v30.4s, v23.4s, v25.4s
    trn2 v20.2d, v24.2d, v26.2d
    sqrdmulh v3.4s, v31.4s, v5.4s
    subs x9, x9, #1
    b.ne .Lntt_slothy_full_bot
    sub v23.4s, v23.4s, v25.4s
    mul v22.4s, v31.4s, v4.4s
    sub v18.4s, v16.4s, v17.4s
    mls v22.4s, v3.4s, v0.s[0]
    trn1 v19.2d, v24.2d, v26.2d
    trn2 v21.4s, v30.4s, v23.4s
    trn1 v31.4s, v30.4s, v23.4s
    sqrdmulh v1.4s, v20.4s, v5.4s
    add v30.4s, v16.4s, v17.4s
    mul v4.4s, v20.4s, v4.4s
    add v16.4s, v2.4s, v22.4s
    trn2 v23.4s, v30.4s, v18.4s
    trn1 v25.4s, v30.4s, v18.4s
    mls v4.4s, v1.4s, v0.s[0]
    mul v6.4s, v16.4s, v6.4s
    trn2 v30.2d, v23.2d, v21.2d
    trn1 v17.2d, v23.2d, v21.2d
    sqrdmulh v21.4s, v16.4s, v7.4s
    sub v29.4s, v19.4s, v4.4s
    add v27.4s, v19.4s, v4.4s
    mls v6.4s, v21.4s, v0.s[0]
    sub v21.4s, v2.4s, v22.4s
    trn2 v16.2d, v25.2d, v31.2d
    trn1 v22.2d, v25.2d, v31.2d
    sqrdmulh v31.4s, v30.4s, v11.4s
    mul v4.4s, v30.4s, v10.4s
    add v18.4s, v27.4s, v6.4s
    sub v6.4s, v27.4s, v6.4s
    sqrdmulh v23.4s, v16.4s, v11.4s
    mul v16.4s, v16.4s, v10.4s
    trn2 v28.4s, v18.4s, v6.4s
    sqrdmulh v2.4s, v21.4s, v9.4s
    trn1 v7.4s, v18.4s, v6.4s
    mls v4.4s, v31.4s, v0.s[0]
    mul v21.4s, v21.4s, v8.4s
    mls v21.4s, v2.4s, v0.s[0]
    add v31.4s, v17.4s, v4.4s
    sub v17.4s, v17.4s, v4.4s
    mls v16.4s, v23.4s, v0.s[0]
    mul v4.4s, v31.4s, v12.4s
    sub v12.4s, v29.4s, v21.4s
    add v21.4s, v29.4s, v21.4s
    sqrdmulh v31.4s, v31.4s, v13.4s
    sub v18.4s, v22.4s, v16.4s
    add v16.4s, v22.4s, v16.4s
    sqrdmulh v22.4s, v17.4s, v15.4s
    trn2 v6.4s, v21.4s, v12.4s
    trn1 v21.4s, v21.4s, v12.4s
    mul v14.4s, v17.4s, v14.4s
    trn2 v17.2d, v28.2d, v6.2d
    trn1 v12.2d, v28.2d, v6.2d
    mls v4.4s, v31.4s, v0.s[0]
    trn2 v31.2d, v7.2d, v21.2d
    trn1 v21.2d, v7.2d, v21.2d
    mls v14.4s, v22.4s, v0.s[0]
    MLDSA_VSTQ_4S 17, x11, #48
    MLDSA_VSTQ_4S 12, x11, #16
    MLDSA_VSTQ_4S 31, x11, #32
    MLDSA_VSTQ_4S 21, x11, #0
    add x11, x11, #64
    sub v21.4s, v16.4s, v4.4s
    add v16.4s, v16.4s, v4.4s
    sub v17.4s, v18.4s, v14.4s
    add v14.4s, v18.4s, v14.4s
    trn2 v31.4s, v16.4s, v21.4s
    trn1 v21.4s, v16.4s, v21.4s
    trn2 v22.4s, v14.4s, v17.4s
    trn1 v16.4s, v14.4s, v17.4s
    trn1 v14.2d, v31.2d, v22.2d
    trn2 v22.2d, v31.2d, v22.2d
    trn1 v17.2d, v21.2d, v16.2d
    trn2 v21.2d, v21.2d, v16.2d
    MLDSA_VSTQ_4S 14, x11, #16
    MLDSA_VSTQ_4S 22, x11, #48
    MLDSA_VSTQ_4S 17, x11, #0
    MLDSA_VSTQ_4S 21, x11, #32
    add x11, x11, #64

    ldp      d8,  d9,  [sp, #0*16]
    ldp      d10, d11, [sp, #1*16]
    ldp      d12, d13, [sp, #2*16]
    ldp      d14, d15, [sp, #3*16]
    add      sp, sp, #(4*16)
AARCH64_AUTIASP
    ret

CRYPT_AARCH64_FUNC_END(MLDSA_NTTAsm)

// Inverse 4+4 layers with fused scaling; x0 is the polynomial, x1 is the table.
// The Bottom pipeline covers eight blocks: fill, seven kernel rounds, drain.
CRYPT_AARCH64_FUNC_START(MLDSA_INTTAsm)

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
    VLDQ_4S 1, x1, #0
    VLDQ_4S 2, x1, #16
    VLDQ_4S 3, x1, #32
    add x1, x1, #48
    VLDQ_4S 16, x10, #16
    VLDQ_4S 20, x10, #0
    VLDQ_4S 25, x10, #48
    VLDQ_4S 12, x10, #32
    add x10, x10, #64
    add x1, x1, #16
    VLDQ_4S 19, x10, #16
    VLDQ_4S 18, x10, #0
    trn1 v22.4s, v20.4s, v16.4s
    trn2 v16.4s, v20.4s, v16.4s
    VLDQ_4S 20, x10, #32
    trn1 v6.4s, v12.4s, v25.4s
    trn2 v12.4s, v12.4s, v25.4s
    VLDQ_4S 23, x10, #48
    add x10, x10, #64
    trn2 v25.2d, v16.2d, v12.2d
    trn1 v16.2d, v16.2d, v12.2d
    VLDQ_4S 12, x1, #0
    trn1 v7.4s, v18.4s, v19.4s
    trn2 v18.4s, v18.4s, v19.4s
    VLDQ_4S 19, x1, #48
    trn2 v8.2d, v22.2d, v6.2d
    VLDQ_4S 30, x1, #16
    VLDQ_4S 4, x1, #32
    add x1, x1, #64
    trn1 v22.2d, v22.2d, v6.2d
    trn1 v6.4s, v20.4s, v23.4s
    trn2 v26.4s, v20.4s, v23.4s
    add v14.4s, v8.4s, v25.4s
    sub v31.4s, v8.4s, v25.4s
    VLDQ_4S 8, x1, #0
    sub v15.4s, v22.4s, v16.4s
    add v16.4s, v22.4s, v16.4s
    VLDQ_4S 9, x1, #16
    add x1, x1, #32
    sqrdmulh v20.4s, v31.4s, v19.4s
    sub v25.4s, v16.4s, v14.4s
    add v16.4s, v16.4s, v14.4s
    mul v19.4s, v31.4s, v4.4s
    trn1 v22.2d, v7.2d, v6.2d
    VLDQ_4S 23, x1, #0
    trn2 v6.2d, v7.2d, v6.2d
    VLDQ_4S 7, x1, #32
    VLDQ_4S 21, x1, #16
    mul v12.4s, v15.4s, v12.4s
    trn1 v4.2d, v18.2d, v26.2d
    VLDQ_4S 29, x1, #48
    trn2 v18.2d, v18.2d, v26.2d
    add x1, x1, #64
    sqrdmulh v30.4s, v15.4s, v30.4s
    sub v5.4s, v22.4s, v4.4s
    VLDQ_4S 14, x1, #0
    VLDQ_4S 15, x1, #16
    mls v19.4s, v20.4s, v0.s[0]
    add v20.4s, v22.4s, v4.4s
    add x1, x1, #32
    sub v22.4s, v6.4s, v18.4s
    add v18.4s, v6.4s, v18.4s
    mul v6.4s, v5.4s, v23.4s
    mls v12.4s, v30.4s, v0.s[0]
    sub v23.4s, v20.4s, v18.4s
    sqrdmulh v30.4s, v5.4s, v21.4s
    mul v7.4s, v22.4s, v7.4s
    add v4.4s, v12.4s, v19.4s
    sqrdmulh v22.4s, v22.4s, v29.4s
    sub v19.4s, v12.4s, v19.4s
    add v12.4s, v20.4s, v18.4s
    sqrdmulh v20.4s, v25.4s, v9.4s
    trn1 v18.4s, v16.4s, v4.4s
    trn2 v4.4s, v16.4s, v4.4s
    sqrdmulh v16.4s, v19.4s, v9.4s
    mul v25.4s, v25.4s, v8.4s
    sub x9, x9, #1
.Lmldsa_intt_bottom_pipe:
    mul v19.4s, v19.4s, v8.4s
    mls v6.4s, v30.4s, v0.s[0]
    mls v25.4s, v20.4s, v0.s[0]
    mls v7.4s, v22.4s, v0.s[0]
    mls v19.4s, v16.4s, v0.s[0]
    sqrdmulh v16.4s, v23.4s, v15.4s
    sub v20.4s, v6.4s, v7.4s
    mul v22.4s, v23.4s, v14.4s
    add v6.4s, v6.4s, v7.4s
    trn1 v7.4s, v25.4s, v19.4s
    sqrdmulh v23.4s, v20.4s, v15.4s
    trn2 v25.4s, v25.4s, v19.4s
    trn1 v19.4s, v12.4s, v6.4s
    mul v20.4s, v20.4s, v14.4s
    trn2 v6.4s, v12.4s, v6.4s
    trn2 v12.2d, v18.2d, v7.2d
    mls v22.4s, v16.4s, v0.s[0]
    trn2 v16.2d, v4.2d, v25.2d
    trn1 v18.2d, v18.2d, v7.2d
    sub v7.4s, v12.4s, v16.4s
    trn1 v25.2d, v4.2d, v25.2d
    mls v20.4s, v23.4s, v0.s[0]
    add v16.4s, v12.4s, v16.4s
    VLDQ_4S 12, x10, #32
    sqrdmulh v23.4s, v7.4s, v2.s[3]
    add v8.4s, v18.4s, v25.4s
    sub v25.4s, v18.4s, v25.4s
    mul v18.4s, v7.4s, v2.s[2]
    trn1 v7.4s, v22.4s, v20.4s
    trn2 v22.4s, v22.4s, v20.4s
    sqrdmulh v30.4s, v25.4s, v2.s[1]
    VLDQ_4S 20, x10, #0
    sub v9.4s, v8.4s, v16.4s
    mul v25.4s, v25.4s, v2.s[0]
    trn2 v4.2d, v19.2d, v7.2d
    VLDQ_4S 2, x1, #16
    trn1 v19.2d, v19.2d, v7.2d
    mls v18.4s, v23.4s, v0.s[0]
    add v16.4s, v8.4s, v16.4s
    sqrdmulh v7.4s, v9.4s, v1.s[1]
    VLDQ_4S 8, x10, #16
    trn2 v23.2d, v6.2d, v22.2d
    trn1 v22.2d, v6.2d, v22.2d
    mls v25.4s, v30.4s, v0.s[0]
    MLDSA_VSTQ_4S 16, x11, #0
    mul v16.4s, v9.4s, v1.s[0]
    add v6.4s, v4.4s, v23.4s
    sub v23.4s, v4.4s, v23.4s
    mls v16.4s, v7.4s, v0.s[0]
    sub v7.4s, v19.4s, v22.4s
    add v19.4s, v19.4s, v22.4s
    sqrdmulh v30.4s, v23.4s, v3.s[3]
    sub v29.4s, v25.4s, v18.4s
    add v18.4s, v25.4s, v18.4s
    VLDQ_4S 25, x10, #48
    add x10, x10, #64
    sqrdmulh v9.4s, v7.4s, v3.s[1]
    MLDSA_VSTQ_4S 16, x11, #32
    sub v16.4s, v19.4s, v6.4s
    add v19.4s, v19.4s, v6.4s
    mul v22.4s, v7.4s, v3.s[0]
    MLDSA_VSTQ_4S 18, x11, #16
    trn1 v18.4s, v20.4s, v8.4s
    trn2 v20.4s, v20.4s, v8.4s
    VLDQ_4S 6, x10, #16
    VLDQ_4S 8, x10, #0
    mul v4.4s, v23.4s, v3.s[2]
    VLDQ_4S 23, x10, #48
    VLDQ_4S 14, x10, #32
    add x10, x10, #64
    trn1 v21.4s, v12.4s, v25.4s
    VLDQ_4S 3, x1, #32
    trn2 v25.4s, v12.4s, v25.4s
    mls v22.4s, v9.4s, v0.s[0]
    trn1 v7.4s, v8.4s, v6.4s
    mls v4.4s, v30.4s, v0.s[0]
    sub v12.4s, v22.4s, v4.4s
    sqrdmulh v30.4s, v29.4s, v1.s[1]
    add v9.4s, v22.4s, v4.4s
    mul v4.4s, v29.4s, v1.s[0]
    trn2 v5.2d, v18.2d, v21.2d
    trn1 v26.2d, v18.2d, v21.2d
    trn1 v21.4s, v14.4s, v23.4s
    sqrdmulh v29.4s, v16.4s, v1.s[3]
    trn2 v17.4s, v14.4s, v23.4s
    mul v23.4s, v16.4s, v1.s[2]
    trn2 v18.4s, v8.4s, v6.4s
    trn1 v22.2d, v7.2d, v21.2d
    trn2 v6.2d, v7.2d, v21.2d
    sqrdmulh v16.4s, v12.4s, v1.s[3]
    trn1 v7.2d, v20.2d, v25.2d
    trn2 v8.2d, v20.2d, v25.2d
    mul v20.4s, v12.4s, v1.s[2]
    VLDQ_4S 1, x1, #0
    add x1, x1, #48
    mls v4.4s, v30.4s, v0.s[0]
    add x1, x1, #16
    mls v23.4s, v29.4s, v0.s[0]
    MLDSA_VSTQ_4S 4, x11, #48
    add x11, x11, #64
    sub v12.4s, v26.4s, v7.4s
    add v7.4s, v26.4s, v7.4s
    trn1 v30.2d, v18.2d, v17.2d
    VLDQ_4S 4, x1, #16
    mls v20.4s, v16.4s, v0.s[0]
    trn2 v25.2d, v18.2d, v17.2d
    MLDSA_VSTQ_4S 19, x11, #0
    MLDSA_VSTQ_4S 9, x11, #16
    VLDQ_4S 16, x1, #0
    sub v18.4s, v5.4s, v8.4s
    MLDSA_VSTQ_4S 23, x11, #32
    sub v23.4s, v22.4s, v30.4s
    add v22.4s, v22.4s, v30.4s
    add v19.4s, v5.4s, v8.4s
    sqrdmulh v30.4s, v12.4s, v4.4s
    MLDSA_VSTQ_4S 20, x11, #48
    mul v16.4s, v12.4s, v16.4s
    VLDQ_4S 20, x1, #48
    add x11, x11, #64
    VLDQ_4S 12, x1, #32
    sub v9.4s, v7.4s, v19.4s
    add v7.4s, v7.4s, v19.4s
    add x1, x1, #64
    mls v16.4s, v30.4s, v0.s[0]
    sub v26.4s, v6.4s, v25.4s
    add v25.4s, v6.4s, v25.4s
    sqrdmulh v19.4s, v18.4s, v20.4s
    VLDQ_4S 21, x1, #16
    VLDQ_4S 8, x1, #0
    add x1, x1, #32
    mul v18.4s, v18.4s, v12.4s
    VLDQ_4S 6, x1, #0
    VLDQ_4S 30, x1, #16
    add v12.4s, v22.4s, v25.4s
    VLDQ_4S 4, x1, #48
    VLDQ_4S 29, x1, #32
    sqrdmulh v20.4s, v9.4s, v21.4s
    add x1, x1, #64
    mls v18.4s, v19.4s, v0.s[0]
    VLDQ_4S 14, x1, #0
    VLDQ_4S 15, x1, #16
    add x1, x1, #32
    mul v6.4s, v23.4s, v6.4s
    sqrdmulh v30.4s, v23.4s, v30.4s
    sub v23.4s, v22.4s, v25.4s
    add v5.4s, v16.4s, v18.4s
    mul v25.4s, v9.4s, v8.4s
    sub v19.4s, v16.4s, v18.4s
    sqrdmulh v22.4s, v26.4s, v4.4s
    trn1 v18.4s, v7.4s, v5.4s
    trn2 v4.4s, v7.4s, v5.4s
    mul v7.4s, v26.4s, v29.4s
    sqrdmulh v16.4s, v19.4s, v21.4s
    subs x9, x9, #1
    b.ne .Lmldsa_intt_bottom_pipe
    mul v19.4s, v19.4s, v8.4s
    mls v6.4s, v30.4s, v0.s[0]
    mls v19.4s, v16.4s, v0.s[0]
    mls v25.4s, v20.4s, v0.s[0]
    mls v7.4s, v22.4s, v0.s[0]
    sqrdmulh v16.4s, v23.4s, v15.4s
    trn1 v20.4s, v25.4s, v19.4s
    mul v23.4s, v23.4s, v14.4s
    trn2 v25.4s, v25.4s, v19.4s
    sub v19.4s, v6.4s, v7.4s
    trn2 v22.2d, v18.2d, v20.2d
    trn1 v20.2d, v18.2d, v20.2d
    mls v23.4s, v16.4s, v0.s[0]
    trn1 v18.2d, v4.2d, v25.2d
    trn2 v25.2d, v4.2d, v25.2d
    sqrdmulh v8.4s, v19.4s, v15.4s
    add v16.4s, v6.4s, v7.4s
    sub v6.4s, v20.4s, v18.4s
    mul v7.4s, v19.4s, v14.4s
    sub v30.4s, v22.4s, v25.4s
    add v25.4s, v22.4s, v25.4s
    mls v7.4s, v8.4s, v0.s[0]
    add v20.4s, v20.4s, v18.4s
    sqrdmulh v19.4s, v6.4s, v2.s[1]
    trn1 v18.4s, v12.4s, v16.4s
    trn2 v16.4s, v12.4s, v16.4s
    mul v12.4s, v6.4s, v2.s[0]
    sub v22.4s, v20.4s, v25.4s
    add v20.4s, v20.4s, v25.4s
    trn1 v25.4s, v23.4s, v7.4s
    sqrdmulh v6.4s, v30.4s, v2.s[3]
    trn2 v7.4s, v23.4s, v7.4s
    mul v23.4s, v30.4s, v2.s[2]
    MLDSA_VSTQ_4S 20, x11, #0
    trn1 v20.2d, v18.2d, v25.2d
    mls v12.4s, v19.4s, v0.s[0]
    trn1 v19.2d, v16.2d, v7.2d
    trn2 v2.2d, v18.2d, v25.2d
    trn2 v16.2d, v16.2d, v7.2d
    mls v23.4s, v6.4s, v0.s[0]
    sub v25.4s, v20.4s, v19.4s
    add v20.4s, v20.4s, v19.4s
    sub v18.4s, v2.4s, v16.4s
    sqrdmulh v19.4s, v22.4s, v1.s[1]
    add v16.4s, v2.4s, v16.4s
    mul v22.4s, v22.4s, v1.s[0]
    sub v6.4s, v12.4s, v23.4s
    add v12.4s, v12.4s, v23.4s
    sqrdmulh v7.4s, v25.4s, v3.s[1]
    sub v23.4s, v20.4s, v16.4s
    mul v25.4s, v25.4s, v3.s[0]
    add v16.4s, v20.4s, v16.4s
    MLDSA_VSTQ_4S 12, x11, #16
    sqrdmulh v20.4s, v18.4s, v3.s[3]
    mul v12.4s, v18.4s, v3.s[2]
    mls v25.4s, v7.4s, v0.s[0]
    mls v12.4s, v20.4s, v0.s[0]
    sqrdmulh v20.4s, v6.4s, v1.s[1]
    mul v18.4s, v6.4s, v1.s[0]
    sub v6.4s, v25.4s, v12.4s
    add v25.4s, v25.4s, v12.4s
    sqrdmulh v12.4s, v23.4s, v1.s[3]
    mul v7.4s, v23.4s, v1.s[2]
    sqrdmulh v23.4s, v6.4s, v1.s[3]
    mul v6.4s, v6.4s, v1.s[2]
    mls v22.4s, v19.4s, v0.s[0]
    mls v18.4s, v20.4s, v0.s[0]
    mls v7.4s, v12.4s, v0.s[0]
    MLDSA_VSTQ_4S 22, x11, #32
    mls v6.4s, v23.4s, v0.s[0]
    MLDSA_VSTQ_4S 18, x11, #48
    add x11, x11, #64
    MLDSA_VSTQ_4S 16, x11, #0
    MLDSA_VSTQ_4S 25, x11, #16
    MLDSA_VSTQ_4S 7, x11, #32
    MLDSA_VSTQ_4S 6, x11, #48
    add x11, x11, #64
    // Bottom consumed 512 table entries. Reuse q for Top layers len=16/32/64/128.
    mov      v31.16b, v0.16b

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
    MLDSA_GS3 v8,  v9,  v0, 0, 1, v10, v11, v0, 2, 3, v12, v13, v1, 0, 1, v31, 0
    MLDSA_GS3 v14, v15, v1, 2, 3, v16, v17, v2, 0, 1, v18, v19, v2, 2, 3, v31, 0
    MLDSA_GS2 v20, v21, v3, 0, 1, v22, v23, v3, 2, 3, v31, 0
    MLDSA_GS3 v8,  v10, v4, 0, 1, v9,  v11, v4, 0, 1, v12, v14, v4, 2, 3, v31, 0
    MLDSA_GS3 v13, v15, v4, 2, 3, v16, v18, v5, 0, 1, v17, v19, v5, 0, 1, v31, 0
    MLDSA_GS2 v20, v22, v5, 2, 3, v21, v23, v5, 2, 3, v31, 0
    MLDSA_GS3 v8,  v12, v6, 0, 1, v9,  v13, v6, 0, 1, v10, v14, v6, 0, 1, v31, 0
    MLDSA_GS3 v11, v15, v6, 0, 1, v16, v20, v6, 2, 3, v17, v21, v6, 2, 3, v31, 0
    MLDSA_GS2 v18, v22, v6, 2, 3, v19, v23, v6, 2, 3, v31, 0

    MLDSA_FS2 v8, v16, v9, v17
    MLDSA_FS2_STORE v10, v18, v11, v19, 8, #0*64, 9, #1*64, 16, #8*64, 17, #9*64
    MLDSA_FS2_STORE v12, v20, v13, v21, 10, #2*64, 11, #3*64, 18, #10*64, 19, #11*64
    MLDSA_FS2_STORE v14, v22, v15, v23, 12, #4*64, 13, #5*64, 20, #12*64, 21, #13*64
    add      x10, x10, #16
    subs     x9, x9, #1
    MLDSA_VSTQ_4S 14, x10, #368
    MLDSA_VSTQ_4S 15, x10, #432
    MLDSA_VSTQ_4S 22, x10, #880
    MLDSA_VSTQ_4S 23, x10, #944
    b.ne     1b

    ldp      d8,  d9,  [sp, #0*16]
    ldp      d10, d11, [sp, #1*16]
    ldp      d12, d13, [sp, #2*16]
    ldp      d14, d15, [sp, #3*16]
    add      sp, sp, #(4*16)
AARCH64_AUTIASP
    ret

CRYPT_AARCH64_FUNC_END(MLDSA_INTTAsm)

.macro pointwise_montgomery_reduce_long res, inl, inh
    uzp1   \res\().4s, \inl\().4s, \inh\().4s
    mul    \res\().4s, \res\().4s, const_q_twisted.4s
    smlsl  \inl\().2d, \res\().2s, const_q.2s
    smlsl2 \inh\().2d, \res\().4s, const_q.4s
    uzp2   \res\().4s, \inl\().4s, \inh\().4s
.endm

.macro pointwise_pmull dl, dh, a, b
    smull  \dl\().2d, \a\().2s, \b\().2s
    smull2 \dh\().2d, \a\().4s, \b\().4s
.endm

    out_ptr .req x0
    a_ptr   .req x1
    b_ptr   .req x2

    count   .req x3
    wtmp    .req w3

    const_q         .req v31
    const_q_twisted .req v30

    arr_a0      .req v0
    arr_a1      .req v1
    arr_a2      .req v2
    arr_a3      .req v3
    arr_b0      .req v4
    arr_b1      .req v5
    arr_b2      .req v6
    arr_b3      .req v7
    q_arr_a0    .req q0
    q_arr_a1    .req q1
    q_arr_a2    .req q2
    q_arr_a3    .req q3
    q_arr_b0    .req q4
    q_arr_b1    .req q5
    q_arr_b2    .req q6
    q_arr_b3    .req q7

    c_0_lo      .req v16
    c_0_hi      .req v17
    c_1_lo      .req v18
    c_1_hi      .req v19
    c_2_lo      .req v20
    c_2_hi      .req v21
    c_3_lo      .req v22
    c_3_hi      .req v23

CRYPT_AARCH64_FUNC_START(MLDSA_PointwiseMontAsm)
    AARCH64_PACIASP
    // The scheduled kernel uses d8-d15; preserve the AAPCS64 caller state.
    stp d8, d9, [sp, #-64]!
    stp d10, d11, [sp, #16]
    stp d12, d13, [sp, #32]
    stp d14, d15, [sp, #48]
    // MLDSA_Q = 8380417
    movz wtmp, #0xe001
    movk wtmp, #0x7f, lsl #16
    dup const_q.4s, wtmp

    // MLDSA_Q^-1 = unsigned_mod(pow(MLDSA_Q, -1, 2**32), 2**32)
    // = 58728449
    movz wtmp, #0x2001
    movk wtmp, #0x380, lsl #16
    dup const_q_twisted.4s, wtmp

    mov count, #(256 / 4 / 4)

    VLDQ_4S 12, x1, #32
    VLDQ_4S 24, x2, #32
    VLDQ_4S_POST 6, x1, #4*16
    VLDQ_4S_POST 13, x2, #4*16
    VLDQ_4S 3, x1, #-16
    VLDQ_4S 28, x2, #-16
    smull2 v1.2d, v12.4s, v24.4s
    smull v25.2d, v12.2s, v24.2s
    smull2 v12.2d, v6.4s, v13.4s
    uzp1 v24.4s, v25.4s, v1.4s
    smull v16.2d, v3.2s, v28.2s
    sub x3, x3, #1
.Lpoly_pointwise_montgomery_loop_start:
    smull2 v22.2d, v3.4s, v28.4s
    VLDQ_4S 20, x1, #-48
    VLDQ_4S 27, x2, #-48
    smull v8.2d, v6.2s, v13.2s
    VLDQ_4S_POST 13, x2, #4*16
    mul v0.4s, v24.4s, v30.4s
    uzp1 v4.4s, v8.4s, v12.4s
    VLDQ_4S 14, x2, #-32
    uzp1 v15.4s, v16.4s, v22.4s
    VLDQ_4S_POST 6, x1, #4*16
    VLDQ_4S 3, x1, #-16
    smull v24.2d, v20.2s, v27.2s
    VLDQ_4S 28, x2, #-16
    smull2 v27.2d, v20.4s, v27.4s
    mul v17.4s, v15.4s, v30.4s
    VLDQ_4S 20, x1, #-32
    smlsl v25.2d, v0.2s, v31.2s
    uzp1 v15.4s, v24.4s, v27.4s
    mul v4.4s, v4.4s, v30.4s
    smlsl2 v22.2d, v17.4s, v31.4s
    mul v15.4s, v15.4s, v30.4s
    smlsl2 v12.2d, v4.4s, v31.4s
    smlsl v8.2d, v4.2s, v31.2s
    uzp2 v7.4s, v8.4s, v12.4s
    smlsl2 v1.2d, v0.4s, v31.4s
    smlsl2 v27.2d, v15.4s, v31.4s
    uzp2 v4.4s, v25.4s, v1.4s
    smlsl v24.2d, v15.2s, v31.2s
    MLDSA_VSTQ_4S_POST 7, x0, #4*16
    uzp2 v27.4s, v24.4s, v27.4s
    smlsl v16.2d, v17.2s, v31.2s
    smull2 v1.2d, v20.4s, v14.4s
    uzp2 v10.4s, v16.4s, v22.4s
    smull v25.2d, v20.2s, v14.2s
    MLDSA_VSTQ_4S 27, x0, #-48
    uzp1 v24.4s, v25.4s, v1.4s
    smull2 v12.2d, v6.4s, v13.4s
    MLDSA_VSTQ_4S 10, x0, #-16
    smull v16.2d, v3.2s, v28.2s
    MLDSA_VSTQ_4S 4, x0, #-32
    subs x3, x3, 1
    cbnz x3, .Lpoly_pointwise_montgomery_loop_start
    smull2 v27.2d, v3.4s, v28.4s
    VLDQ_4S 22, x1, #-48
    VLDQ_4S 20, x2, #-48
    smull v3.2d, v6.2s, v13.2s
    uzp1 v6.4s, v16.4s, v27.4s
    mul v24.4s, v24.4s, v30.4s
    uzp1 v14.4s, v3.4s, v12.4s
    smull v4.2d, v22.2s, v20.2s
    mul v14.4s, v14.4s, v30.4s
    smlsl v25.2d, v24.2s, v31.2s
    smlsl2 v1.2d, v24.4s, v31.4s
    smull2 v24.2d, v22.4s, v20.4s
    uzp2 v25.4s, v25.4s, v1.4s
    smlsl2 v12.2d, v14.4s, v31.4s
    uzp1 v1.4s, v4.4s, v24.4s
    mul v22.4s, v6.4s, v30.4s
    MLDSA_VSTQ_4S 25, x0, #32
    mul v25.4s, v1.4s, v30.4s
    smlsl v3.2d, v14.2s, v31.2s
    smlsl v16.2d, v22.2s, v31.2s
    uzp2 v12.4s, v3.4s, v12.4s
    smlsl2 v27.2d, v22.4s, v31.4s
    smlsl v4.2d, v25.2s, v31.2s
    uzp2 v27.4s, v16.4s, v27.4s
    smlsl2 v24.2d, v25.4s, v31.4s
    MLDSA_VSTQ_4S_POST 12, x0, #4*16
    uzp2 v12.4s, v4.4s, v24.4s
    MLDSA_VSTQ_4S 27, x0, #-16
    MLDSA_VSTQ_4S 12, x0, #-48
    ldp d10, d11, [sp, #16]
    ldp d12, d13, [sp, #32]
    ldp d14, d15, [sp, #48]
    ldp d8, d9, [sp], #64
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_PointwiseMontAsm)

    .unreq out_ptr
    .unreq a_ptr
    .unreq b_ptr
    .unreq count
    .unreq wtmp

    .unreq const_q
    .unreq const_q_twisted
    .unreq arr_a0
    .unreq arr_a1
    .unreq arr_a2
    .unreq arr_a3
    .unreq arr_b0
    .unreq arr_b1
    .unreq arr_b2
    .unreq arr_b3
    .unreq q_arr_a0
    .unreq q_arr_a1
    .unreq q_arr_a2
    .unreq q_arr_a3
    .unreq q_arr_b0
    .unreq q_arr_b1
    .unreq q_arr_b2
    .unreq q_arr_b3
    .unreq c_0_lo
    .unreq c_0_hi
    .unreq c_1_lo
    .unreq c_1_hi
    .unreq c_2_lo
    .unreq c_2_hi
    .unreq c_3_lo
    .unreq c_3_hi

.macro pointwise_acc_push_stack
    // Preserve the callee-saved registers used by the scheduled kernels.
    stp d8, d9, [sp, #-64]!
    stp d10, d11, [sp, #16]
    stp d12, d13, [sp, #32]
    stp d14, d15, [sp, #48]
.endm

.macro pointwise_acc_pop_stack
    ldp d10, d11, [sp, #16]
    ldp d12, d13, [sp, #32]
    ldp d14, d15, [sp, #48]
    ldp d8, d9, [sp], #64
.endm

.macro pointwise_acc_load_const
    // MLDSA_Q = 8380417
    movz wtmp, #0xe001
    movk wtmp, #0x7f, lsl #16
    dup const_q.4s, wtmp

    // MLDSA_Q^-1 = unsigned_mod(pow(MLDSA_Q, -1, 2**32), 2**32)
    // = 58728449
    movz wtmp, #0x2001
    movk wtmp, #0x380, lsl #16
    dup const_q_twisted.4s, wtmp
.endm

.macro pointwise_acc_montgomery_reduce_long res, inl, inh
    uzp1   \res\().4s, \inl\().4s, \inh\().4s
    mul    \res\().4s, \res\().4s, const_q_twisted.4s
    smlsl  \inl\().2d, \res\().2s, const_q.2s
    smlsl2 \inh\().2d, \res\().4s, const_q.4s
    uzp2   \res\().4s, \inl\().4s, \inh\().4s
.endm

.macro pointwise_acc_load_polys p0, p1, p2, p3, ptr, idx
.if \idx == 0
    ldr \p1, [\ptr, #1*16]
    ldr \p2, [\ptr, #2*16]
    ldr \p3, [\ptr, #3*16]
    ldr \p0, [\ptr], #4*16
.else
    ldr \p0, [\ptr, #(1024*\idx-4*16)]
    ldr \p1, [\ptr, #(1024*\idx-3*16)]
    ldr \p2, [\ptr, #(1024*\idx-2*16)]
    ldr \p3, [\ptr, #(1024*\idx-1*16)]
.endif
.endm

.macro pointwise_acc_pmull dl, dh, a, b
    smull  \dl\().2d, \a\().2s, \b\().2s
    smull2 \dh\().2d, \a\().4s, \b\().4s
.endm

.macro pointwise_acc_pmlal dl, dh, a, b
    smlal  \dl\().2d, \a\().2s, \b\().2s
    smlal2 \dh\().2d, \a\().4s, \b\().4s
.endm

.macro pointwise_acc_l0_3
    pointwise_acc_load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 0
    pointwise_acc_load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 0

    pointwise_acc_pmull c_0_lo, c_0_hi, arr_a0, arr_b0
    pointwise_acc_pmull c_1_lo, c_1_hi, arr_a1, arr_b1
    pointwise_acc_pmull c_2_lo, c_2_hi, arr_a2, arr_b2
    pointwise_acc_pmull c_3_lo, c_3_hi, arr_a3, arr_b3

    pointwise_acc_load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 1
    pointwise_acc_load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 1

    pointwise_acc_pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pointwise_acc_pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pointwise_acc_pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pointwise_acc_pmlal c_3_lo, c_3_hi, arr_a3, arr_b3

    pointwise_acc_load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 2
    pointwise_acc_load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 2

    pointwise_acc_pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pointwise_acc_pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pointwise_acc_pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pointwise_acc_pmlal c_3_lo, c_3_hi, arr_a3, arr_b3

    pointwise_acc_load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 3
    pointwise_acc_load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 3

    pointwise_acc_pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pointwise_acc_pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pointwise_acc_pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pointwise_acc_pmlal c_3_lo, c_3_hi, arr_a3, arr_b3
.endm

.macro pointwise_acc_l4
    pointwise_acc_load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 4
    pointwise_acc_load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 4

    pointwise_acc_pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pointwise_acc_pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pointwise_acc_pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pointwise_acc_pmlal c_3_lo, c_3_hi, arr_a3, arr_b3
.endm

.macro pointwise_acc_l5_6
    pointwise_acc_load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 5
    pointwise_acc_load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 5

    pointwise_acc_pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pointwise_acc_pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pointwise_acc_pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pointwise_acc_pmlal c_3_lo, c_3_hi, arr_a3, arr_b3

    pointwise_acc_load_polys q_arr_a0, q_arr_a1, q_arr_a2, q_arr_a3, a_ptr, 6
    pointwise_acc_load_polys q_arr_b0, q_arr_b1, q_arr_b2, q_arr_b3, b_ptr, 6

    pointwise_acc_pmlal c_0_lo, c_0_hi, arr_a0, arr_b0
    pointwise_acc_pmlal c_1_lo, c_1_hi, arr_a1, arr_b1
    pointwise_acc_pmlal c_2_lo, c_2_hi, arr_a2, arr_b2
    pointwise_acc_pmlal c_3_lo, c_3_hi, arr_a3, arr_b3
.endm


.macro pointwise_acc_reduce
    pointwise_acc_montgomery_reduce_long arr_a0, c_0_lo, c_0_hi
    pointwise_acc_montgomery_reduce_long arr_a1, c_1_lo, c_1_hi
    pointwise_acc_montgomery_reduce_long arr_a2, c_2_lo, c_2_hi
    pointwise_acc_montgomery_reduce_long arr_a3, c_3_lo, c_3_hi
    // Bounds: |c_{i}| < q
.endm

    out_ptr .req x0
    a_ptr   .req x1
    b_ptr   .req x2
    count   .req x3
    wtmp    .req w3

    const_q         .req v31
    const_q_twisted .req v30

    arr_a0      .req v0
    arr_a1      .req v1
    arr_a2      .req v2
    arr_a3      .req v3
    arr_b0      .req v4
    arr_b1      .req v5
    arr_b2      .req v6
    arr_b3      .req v7
    q_arr_a0    .req q0
    q_arr_a1    .req q1
    q_arr_a2    .req q2
    q_arr_a3    .req q3
    q_arr_b0    .req q4
    q_arr_b1    .req q5
    q_arr_b2    .req q6
    q_arr_b3    .req q7

    c_0_lo   .req v16
    c_0_hi   .req v17
    c_1_lo   .req v18
    c_1_hi   .req v19
    c_2_lo   .req v20
    c_2_hi   .req v21
    c_3_lo   .req v22
    c_3_hi   .req v23

CRYPT_AARCH64_FUNC_START(MLDSA_PointwiseAccMontL4Asm)
    AARCH64_PACIASP
    pointwise_acc_push_stack
    pointwise_acc_load_const
    mov count, #(256 / 4 / 4)
    VLDQ_4S_POST 28, x2, #4*16
    VLDQ_4S_POST 26, x1, #4*16
    VLDQ_4S 13, x2, #-32
    VLDQ_4S 4, x2, #-48
    VLDQ_4S 6, x1, #-32
    VLDQ_4S 16, x1, #-48
    smull v25.2d, v26.2s, v28.2s
    smull2 v20.2d, v26.4s, v28.4s
    smull v10.2d, v16.2s, v4.2s
    VLDQ_4S 9, x2, #-16
    VLDQ_4S 22, x1, #-16
    smull v28.2d, v6.2s, v13.2s
    sub x3, x3, #1
    .Lpolyvecl_pointwise_acc_montgomery_l4_loop_start:
    VLDQ_4S 7, x2, #960
    VLDQ_4S 3, x1, #960
    smull2 v1.2d, v6.4s, v13.4s
    VLDQ_4S 21, x1, #976
    smull2 v13.2d, v16.4s, v4.4s
    VLDQ_4S 17, x1, #992
    smull v24.2d, v22.2s, v9.2s
    VLDQ_4S 5, x2, #976
    smull2 v22.2d, v22.4s, v9.4s
    smlal v25.2d, v3.2s, v7.2s
    VLDQ_4S 18, x2, #992
    smlal2 v20.2d, v3.4s, v7.4s
    VLDQ_4S 3, x1, #1008
    VLDQ_4S 29, x2, #1008
    smlal v10.2d, v21.2s, v5.2s
    smlal2 v13.2d, v21.4s, v5.4s
    VLDQ_4S 19, x1, #1984
    smlal v28.2d, v17.2s, v18.2s
    VLDQ_4S 8, x2, #1984
    smlal2 v1.2d, v17.4s, v18.4s
    smlal v24.2d, v3.2s, v29.2s
    VLDQ_4S 23, x1, #2000
    VLDQ_4S 2, x2, #2000
    smlal2 v22.2d, v3.4s, v29.4s
    VLDQ_4S 27, x1, #2016
    smlal v25.2d, v19.2s, v8.2s
    VLDQ_4S 12, x2, #2016
    smlal2 v20.2d, v19.4s, v8.4s
    VLDQ_4S 14, x1, #3008
    VLDQ_4S 26, x2, #3008
    smlal v10.2d, v23.2s, v2.2s
    smlal2 v13.2d, v23.4s, v2.4s
    VLDQ_4S 8, x1, #2032
    VLDQ_4S 7, x2, #2032
    smlal2 v1.2d, v27.4s, v12.4s
    smlal v25.2d, v14.2s, v26.2s
    smlal v28.2d, v27.2s, v12.2s
    VLDQ_4S 12, x1, #3024
    VLDQ_4S 0, x2, #3024
    smlal2 v20.2d, v14.4s, v26.4s
    smlal2 v22.2d, v8.4s, v7.4s
    uzp1 v26.4s, v25.4s, v20.4s
    VLDQ_4S 18, x2, #3040
    smlal v24.2d, v8.2s, v7.2s
    VLDQ_4S 7, x1, #3040
    smlal v10.2d, v12.2s, v0.2s
    smlal2 v13.2d, v12.4s, v0.4s
    VLDQ_4S 23, x1, #3056
    mul v14.4s, v26.4s, v30.4s
    VLDQ_4S 0, x2, #3056
    smlal v28.2d, v7.2s, v18.2s
    smlal2 v1.2d, v7.4s, v18.4s
    smlal v24.2d, v23.2s, v0.2s
    smlsl2 v20.2d, v14.4s, v31.4s
    uzp1 v26.4s, v10.4s, v13.4s
    smlsl v25.2d, v14.2s, v31.2s
    uzp1 v2.4s, v28.4s, v1.4s
    smlal2 v22.2d, v23.4s, v0.4s
    mul v27.4s, v26.4s, v30.4s
    uzp1 v0.4s, v24.4s, v22.4s
    mul v2.4s, v2.4s, v30.4s
    mul v26.4s, v0.4s, v30.4s
    VLDQ_4S_POST 15, x1, #4*16
    smlsl v10.2d, v27.2s, v31.2s
    VLDQ_4S 16, x1, #-48
    smlsl2 v13.2d, v27.4s, v31.4s
    VLDQ_4S 4, x2, #16
    VLDQ_4S_POST 11, x2, #4*16
    uzp2 v12.4s, v25.4s, v20.4s
    smlsl v28.2d, v2.2s, v31.2s
    VLDQ_4S 9, x2, #-16
    smlsl v24.2d, v26.2s, v31.2s
    smlsl2 v22.2d, v26.4s, v31.4s
    VLDQ_4S 6, x1, #-32
    uzp2 v0.4s, v10.4s, v13.4s
    smlsl2 v1.2d, v2.4s, v31.4s
    uzp2 v26.4s, v24.4s, v22.4s
    VLDQ_4S 13, x2, #-32
    uzp2 v5.4s, v28.4s, v1.4s
    smull v25.2d, v15.2s, v11.2s
    smull2 v20.2d, v15.4s, v11.4s
    VLDQ_4S 22, x1, #-16
    smull v10.2d, v16.2s, v4.2s
    MLDSA_VSTQ_4S_POST 12, x0, #4*16
    MLDSA_VSTQ_4S 26, x0, #-16
    MLDSA_VSTQ_4S 0, x0, #-48
    MLDSA_VSTQ_4S 5, x0, #-32
    smull v28.2d, v6.2s, v13.2s
    subs x3, x3, 1
    cbnz x3, .Lpolyvecl_pointwise_acc_montgomery_l4_loop_start
    VLDQ_4S 21, x1, #992
    smull2 v26.2d, v6.4s, v13.4s
    VLDQ_4S 15, x2, #992
    smull2 v6.2d, v16.4s, v4.4s
    smull v4.2d, v22.2s, v9.2s
    VLDQ_4S 24, x1, #2016
    VLDQ_4S 1, x2, #2016
    VLDQ_4S 16, x2, #3040
    smull2 v9.2d, v22.4s, v9.4s
    smlal v28.2d, v21.2s, v15.2s
    VLDQ_4S 13, x1, #3040
    smlal2 v26.2d, v21.4s, v15.4s
    VLDQ_4S 15, x1, #1008
    VLDQ_4S 3, x2, #1008
    smlal2 v26.2d, v24.4s, v1.4s
    VLDQ_4S 11, x1, #2032
    VLDQ_4S 22, x2, #2032
    smlal v28.2d, v24.2s, v1.2s
    VLDQ_4S 24, x1, #3056
    VLDQ_4S 1, x2, #3056
    smlal v28.2d, v13.2s, v16.2s
    smlal2 v26.2d, v13.4s, v16.4s
    smlal2 v9.2d, v15.4s, v3.4s
    uzp1 v13.4s, v28.4s, v26.4s
    smlal2 v9.2d, v11.4s, v22.4s
    smlal2 v9.2d, v24.4s, v1.4s
    mul v13.4s, v13.4s, v30.4s
    smlal v4.2d, v15.2s, v3.2s
    smlal v4.2d, v11.2s, v22.2s
    VLDQ_4S 3, x1, #976
    VLDQ_4S 17, x2, #976
    smlal v4.2d, v24.2s, v1.2s
    uzp1 v1.4s, v4.4s, v9.4s
    smlsl2 v26.2d, v13.4s, v31.4s
    VLDQ_4S 15, x1, #2000
    smlsl v28.2d, v13.2s, v31.2s
    VLDQ_4S 16, x2, #2000
    VLDQ_4S 22, x1, #3024
    VLDQ_4S 24, x2, #3024
    uzp2 v13.4s, v28.4s, v26.4s
    smlal2 v6.2d, v3.4s, v17.4s
    mul v28.4s, v1.4s, v30.4s
    VLDQ_4S 8, x1, #3008
    MLDSA_VSTQ_4S 13, x0, #32
    smlal2 v6.2d, v15.4s, v16.4s
    smlal2 v6.2d, v22.4s, v24.4s
    VLDQ_4S 26, x1, #960
    VLDQ_4S 11, x2, #960
    smlal v10.2d, v3.2s, v17.2s
    smlal v10.2d, v15.2s, v16.2s
    VLDQ_4S 13, x2, #1984
    VLDQ_4S 15, x1, #1984
    smlal v10.2d, v22.2s, v24.2s
    uzp1 v16.4s, v10.4s, v6.4s
    VLDQ_4S 1, x2, #3008
    smlal v25.2d, v26.2s, v11.2s
    smlal2 v20.2d, v26.4s, v11.4s
    smlal v25.2d, v15.2s, v13.2s
    smlal2 v20.2d, v15.4s, v13.4s
    smlal2 v20.2d, v8.4s, v1.4s
    smlal v25.2d, v8.2s, v1.2s
    uzp1 v1.4s, v25.4s, v20.4s
    mul v13.4s, v16.4s, v30.4s
    smlsl v4.2d, v28.2s, v31.2s
    mul v1.4s, v1.4s, v30.4s
    smlsl2 v6.2d, v13.4s, v31.4s
    smlsl v10.2d, v13.2s, v31.2s
    smlsl2 v9.2d, v28.4s, v31.4s
    uzp2 v30.4s, v10.4s, v6.4s
    uzp2 v10.4s, v4.4s, v9.4s
    smlsl2 v20.2d, v1.4s, v31.4s
    smlsl v25.2d, v1.2s, v31.2s
    MLDSA_VSTQ_4S 30, x0, #16
    uzp2 v20.4s, v25.4s, v20.4s
    MLDSA_VSTQ_4S 10, x0, #48
    MLDSA_VSTQ_4S_POST 20, x0, #4*16
    pointwise_acc_pop_stack
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_PointwiseAccMontL4Asm)

CRYPT_AARCH64_FUNC_START(MLDSA_PointwiseAccMontL5Asm)
AARCH64_PACIASP
    pointwise_acc_push_stack
    pointwise_acc_load_const
    mov count, #(256 / 4 / 4)
    VLDQ_4S_POST 12, x1, #4*16
    VLDQ_4S_POST 23, x2, #4*16
    VLDQ_4S 22, x2, #-48
    VLDQ_4S 13, x1, #-48
    smull v19.2d, v12.2s, v23.2s
    VLDQ_4S 6, x2, #-32
    smull2 v25.2d, v12.4s, v23.4s
    VLDQ_4S 21, x1, #-32
    smull v23.2d, v13.2s, v22.2s
    VLDQ_4S 7, x2, #-16
    VLDQ_4S 4, x1, #-16
    smull2 v13.2d, v13.4s, v22.4s
    sub x3, x3, #1
    .Lpolyvecl_pointwise_acc_montgomery_l5_loop_start:
    smull v29.2d, v21.2s, v6.2s
    VLDQ_4S 3, x1, #960
    VLDQ_4S 11, x2, #960
    smull2 v6.2d, v21.4s, v6.4s
    smull v5.2d, v4.2s, v7.2s
    VLDQ_4S 0, x1, #976
    VLDQ_4S 22, x2, #976
    smull2 v4.2d, v4.4s, v7.4s
    VLDQ_4S 20, x1, #992
    VLDQ_4S 21, x2, #992
    smlal v19.2d, v3.2s, v11.2s
    smlal2 v25.2d, v3.4s, v11.4s
    VLDQ_4S 3, x1, #1008
    VLDQ_4S 11, x2, #1008
    smlal v23.2d, v0.2s, v22.2s
    smlal2 v13.2d, v0.4s, v22.4s
    smlal v29.2d, v20.2s, v21.2s
    VLDQ_4S 0, x1, #1984
    VLDQ_4S 22, x2, #1984
    smlal2 v6.2d, v20.4s, v21.4s
    smlal v5.2d, v3.2s, v11.2s
    VLDQ_4S 20, x1, #2000
    VLDQ_4S 21, x2, #2000
    smlal2 v4.2d, v3.4s, v11.4s
    VLDQ_4S 3, x1, #2016
    VLDQ_4S 11, x2, #2016
    smlal v19.2d, v0.2s, v22.2s
    smlal2 v25.2d, v0.4s, v22.4s
    VLDQ_4S 0, x1, #2032
    VLDQ_4S 22, x2, #2032
    smlal v23.2d, v20.2s, v21.2s
    smlal2 v13.2d, v20.4s, v21.4s
    smlal v29.2d, v3.2s, v11.2s
    VLDQ_4S 20, x1, #3008
    VLDQ_4S 21, x2, #3008
    smlal2 v6.2d, v3.4s, v11.4s
    smlal v5.2d, v0.2s, v22.2s
    VLDQ_4S 3, x1, #3024
    VLDQ_4S 11, x2, #3024
    smlal2 v4.2d, v0.4s, v22.4s
    VLDQ_4S 0, x1, #3040
    VLDQ_4S 22, x2, #3040
    smlal v19.2d, v20.2s, v21.2s
    smlal2 v25.2d, v20.4s, v21.4s
    VLDQ_4S 7, x1, #3056
    VLDQ_4S 21, x2, #3056
    smlal v23.2d, v3.2s, v11.2s
    smlal2 v13.2d, v3.4s, v11.4s
    smlal v29.2d, v0.2s, v22.2s
    VLDQ_4S 3, x1, #4032
    VLDQ_4S 11, x2, #4032
    smlal2 v6.2d, v0.4s, v22.4s
    smlal v5.2d, v7.2s, v21.2s
    VLDQ_4S 20, x1, #4048
    VLDQ_4S 22, x2, #4048
    smlal2 v4.2d, v7.4s, v21.4s
    VLDQ_4S 0, x1, #4064
    VLDQ_4S 21, x2, #4064
    smlal v19.2d, v3.2s, v11.2s
    smlal2 v25.2d, v3.4s, v11.4s
    VLDQ_4S 3, x1, #4080
    VLDQ_4S 11, x2, #4080
    smlal v23.2d, v20.2s, v22.2s
    smlal2 v13.2d, v20.4s, v22.4s
    smlal v29.2d, v0.2s, v21.2s
    uzp1 v22.4s, v19.4s, v25.4s
    smlal2 v6.2d, v0.4s, v21.4s
    uzp1 v21.4s, v23.4s, v13.4s
    smlal v5.2d, v3.2s, v11.2s
    mul v22.4s, v22.4s, v30.4s
    mul v0.4s, v21.4s, v30.4s
    smlal2 v4.2d, v3.4s, v11.4s
    smlsl v19.2d, v22.2s, v31.2s
    uzp1 v21.4s, v29.4s, v6.4s
    smlsl2 v25.2d, v22.4s, v31.4s
    uzp1 v22.4s, v5.4s, v4.4s
    smlsl v23.2d, v0.2s, v31.2s
    mul v21.4s, v21.4s, v30.4s
    mul v11.4s, v22.4s, v30.4s
    smlsl2 v13.2d, v0.4s, v31.4s
    VLDQ_4S_POST 0, x1, #4*16
    VLDQ_4S_POST 1, x2, #4*16
    smlsl v29.2d, v21.2s, v31.2s
    VLDQ_4S 22, x1, #-48
    uzp2 v20.4s, v19.4s, v25.4s
    smlsl2 v6.2d, v21.4s, v31.4s
    VLDQ_4S 3, x2, #-48
    uzp2 v13.4s, v23.4s, v13.4s
    smlsl v5.2d, v11.2s, v31.2s
    VLDQ_4S 21, x1, #-32
    smlsl2 v4.2d, v11.4s, v31.4s
    uzp2 v23.4s, v29.4s, v6.4s
    VLDQ_4S 6, x2, #-32
    uzp2 v29.4s, v5.4s, v4.4s
    smull v19.2d, v0.2s, v1.2s
    VLDQ_4S 4, x1, #-16
    VLDQ_4S 7, x2, #-16
    smull2 v25.2d, v0.4s, v1.4s
    MLDSA_VSTQ_4S 23, x0, #32
    smull v23.2d, v22.2s, v3.2s
    MLDSA_VSTQ_4S 13, x0, #16
    smull2 v13.2d, v22.4s, v3.4s
    MLDSA_VSTQ_4S 29, x0, #48
    MLDSA_VSTQ_4S_POST 20, x0, #4*16
    subs x3, x3, 1
    cbnz x3, .Lpolyvecl_pointwise_acc_montgomery_l5_loop_start
    VLDQ_4S 29, x1, #960
    smull v5.2d, v4.2s, v7.2s
    VLDQ_4S 0, x2, #960
    smull v12.2d, v21.2s, v6.2s
    VLDQ_4S 1, x1, #1984
    VLDQ_4S 27, x2, #1984
    smull2 v21.2d, v21.4s, v6.4s
    VLDQ_4S 24, x1, #3008
    VLDQ_4S 20, x2, #3008
    smull2 v7.2d, v4.4s, v7.4s
    VLDQ_4S 3, x1, #4032
    VLDQ_4S 6, x2, #4032
    VLDQ_4S 8, x1, #3056
    smlal2 v25.2d, v29.4s, v0.4s
    smlal2 v25.2d, v1.4s, v27.4s
    VLDQ_4S 22, x2, #4048
    VLDQ_4S 11, x1, #4048
    smlal2 v25.2d, v24.4s, v20.4s
    VLDQ_4S 10, x2, #3056
    smlal2 v25.2d, v3.4s, v6.4s
    VLDQ_4S 2, x1, #1008
    smlal v19.2d, v29.2s, v0.2s
    VLDQ_4S 0, x2, #1008
    smlal v19.2d, v1.2s, v27.2s
    VLDQ_4S 1, x1, #2032
    VLDQ_4S 14, x2, #2032
    VLDQ_4S 4, x1, #4064
    smlal v19.2d, v24.2s, v20.2s
    smlal v19.2d, v3.2s, v6.2s
    uzp1 v29.4s, v19.4s, v25.4s
    smlal2 v7.2d, v2.4s, v0.4s
    smlal2 v7.2d, v1.4s, v14.4s
    VLDQ_4S 3, x1, #976
    VLDQ_4S 20, x2, #976
    smlal v5.2d, v2.2s, v0.2s
    mul v29.4s, v29.4s, v30.4s
    VLDQ_4S 27, x1, #2000
    VLDQ_4S 16, x2, #2000
    smlal v5.2d, v1.2s, v14.2s
    VLDQ_4S 1, x1, #992
    smlal2 v13.2d, v3.4s, v20.4s
    smlal2 v13.2d, v27.4s, v16.4s
    VLDQ_4S 0, x2, #992
    VLDQ_4S 28, x1, #2016
    smlsl2 v25.2d, v29.4s, v31.4s
    smlsl v19.2d, v29.2s, v31.2s
    VLDQ_4S 6, x1, #4080
    VLDQ_4S 29, x2, #4080
    smlal v23.2d, v3.2s, v20.2s
    VLDQ_4S 24, x2, #2016
    uzp2 v25.4s, v19.4s, v25.4s
    smlal2 v21.2d, v1.4s, v0.4s
    smlal2 v7.2d, v8.4s, v10.4s
    VLDQ_4S 3, x1, #3040
    VLDQ_4S 20, x2, #3040
    MLDSA_VSTQ_4S_POST 25, x0, #4*16
    smlal2 v7.2d, v6.4s, v29.4s
    VLDQ_4S 25, x2, #4064
    smlal2 v21.2d, v28.4s, v24.4s
    VLDQ_4S 14, x1, #3024
    VLDQ_4S 2, x2, #3024
    smlal v23.2d, v27.2s, v16.2s
    smlal2 v21.2d, v3.4s, v20.4s
    smlal2 v21.2d, v4.4s, v25.4s
    smlal v12.2d, v1.2s, v0.2s
    smlal v12.2d, v28.2s, v24.2s
    smlal v12.2d, v3.2s, v20.2s
    smlal v12.2d, v4.2s, v25.2s
    smlal2 v13.2d, v14.4s, v2.4s
    smlal2 v13.2d, v11.4s, v22.4s
    smlal v23.2d, v14.2s, v2.2s
    smlal v23.2d, v11.2s, v22.2s
    uzp1 v25.4s, v12.4s, v21.4s
    smlal v5.2d, v8.2s, v10.2s
    smlal v5.2d, v6.2s, v29.2s
    uzp1 v6.4s, v23.4s, v13.4s
    mul v29.4s, v25.4s, v30.4s
    uzp1 v25.4s, v5.4s, v7.4s
    mul v6.4s, v6.4s, v30.4s
    mul v25.4s, v25.4s, v30.4s
    smlsl2 v21.2d, v29.4s, v31.4s
    smlsl v12.2d, v29.2s, v31.2s
    smlsl2 v13.2d, v6.4s, v31.4s
    uzp2 v30.4s, v12.4s, v21.4s
    smlsl v23.2d, v6.2s, v31.2s
    smlsl2 v7.2d, v25.4s, v31.4s
    uzp2 v23.4s, v23.4s, v13.4s
    MLDSA_VSTQ_4S 30, x0, #-32
    smlsl v5.2d, v25.2s, v31.2s
    uzp2 v25.4s, v5.4s, v7.4s
    MLDSA_VSTQ_4S 23, x0, #-48
    MLDSA_VSTQ_4S 25, x0, #-16
    pointwise_acc_pop_stack
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_PointwiseAccMontL5Asm)

CRYPT_AARCH64_FUNC_START(MLDSA_PointwiseAccMontL7Asm)
AARCH64_PACIASP
    pointwise_acc_push_stack
    pointwise_acc_load_const
    mov count, #(256 / 4 / 4)
    VLDQ_4S 0, x1, #32
    VLDQ_4S_POST 10, x1, #4*16
    VLDQ_4S 1, x1, #-48
    VLDQ_4S 24, x2, #32
    VLDQ_4S 18, x2, #16
    smull v21.2d, v1.2s, v18.2s
    VLDQ_4S 28, x1, #992
    VLDQ_4S_POST 29, x2, #4*16
    VLDQ_4S 12, x2, #992
    smull2 v22.2d, v0.4s, v24.4s
    smlal2 v22.2d, v28.4s, v12.4s
    smull2 v17.2d, v10.4s, v29.4s
    sub x3, x3, #1
    .Lpolyvecl_pointwise_acc_montgomery_l7_loop_start:
    VLDQ_4S 11, x2, #-16
    VLDQ_4S 23, x1, #-16
    smull v13.2d, v10.2s, v29.2s
    VLDQ_4S 14, x1, #2016
    VLDQ_4S 2, x2, #960
    smull2 v25.2d, v1.4s, v18.4s
    VLDQ_4S 10, x1, #960
    smull v19.2d, v0.2s, v24.2s
    VLDQ_4S 29, x2, #976
    smlal v19.2d, v28.2s, v12.2s
    smull v16.2d, v23.2s, v11.2s
    VLDQ_4S 24, x1, #976
    smull2 v23.2d, v23.4s, v11.4s
    smlal v13.2d, v10.2s, v2.2s
    VLDQ_4S 5, x2, #2016
    VLDQ_4S 27, x1, #1008
    smlal2 v17.2d, v10.4s, v2.4s
    VLDQ_4S 26, x2, #1008
    smlal v21.2d, v24.2s, v29.2s
    VLDQ_4S 4, x2, #1984
    smlal2 v25.2d, v24.4s, v29.4s
    VLDQ_4S 24, x1, #1984
    smlal2 v22.2d, v14.4s, v5.4s
    VLDQ_4S 11, x2, #2000
    VLDQ_4S 12, x1, #2000
    smlal v16.2d, v27.2s, v26.2s
    smlal2 v23.2d, v27.4s, v26.4s
    smlal v13.2d, v24.2s, v4.2s
    VLDQ_4S 0, x1, #2032
    VLDQ_4S 15, x2, #2032
    smlal2 v17.2d, v24.4s, v4.4s
    smlal v21.2d, v12.2s, v11.2s
    VLDQ_4S 10, x1, #3008
    smlal2 v25.2d, v12.4s, v11.4s
    VLDQ_4S 3, x2, #3008
    smlal v19.2d, v14.2s, v5.2s
    VLDQ_4S 28, x1, #3024
    smlal v16.2d, v0.2s, v15.2s
    VLDQ_4S 4, x2, #3024
    VLDQ_4S 2, x2, #3040
    smlal2 v23.2d, v0.4s, v15.4s
    VLDQ_4S 12, x1, #3040
    smlal v13.2d, v10.2s, v3.2s
    VLDQ_4S 1, x2, #3056
    smlal2 v17.2d, v10.4s, v3.4s
    smlal v21.2d, v28.2s, v4.2s
    VLDQ_4S 6, x1, #3056
    VLDQ_4S 0, x2, #4032
    smlal2 v25.2d, v28.4s, v4.4s
    smlal v19.2d, v12.2s, v2.2s
    VLDQ_4S 11, x1, #4032
    smlal2 v22.2d, v12.4s, v2.4s
    VLDQ_4S 18, x2, #4048
    VLDQ_4S 12, x1, #4048
    smlal v16.2d, v6.2s, v1.2s
    smlal2 v23.2d, v6.4s, v1.4s
    smlal2 v17.2d, v11.4s, v0.4s
    VLDQ_4S 28, x2, #4064
    VLDQ_4S 9, x1, #4064
    smlal v21.2d, v12.2s, v18.2s
    VLDQ_4S 6, x2, #4080
    smlal2 v25.2d, v12.4s, v18.4s
    VLDQ_4S 20, x1, #4080
    smlal v13.2d, v11.2s, v0.2s
    VLDQ_4S 29, x1, #5056
    VLDQ_4S 18, x2, #5056
    VLDQ_4S 0, x2, #5072
    VLDQ_4S 24, x1, #5072
    smlal v19.2d, v9.2s, v28.2s
    smlal2 v22.2d, v9.4s, v28.4s
    smlal2 v23.2d, v20.4s, v6.4s
    VLDQ_4S 12, x1, #5088
    smlal v13.2d, v29.2s, v18.2s
    VLDQ_4S 11, x2, #5088
    smlal v21.2d, v24.2s, v0.2s
    smlal2 v17.2d, v29.4s, v18.4s
    VLDQ_4S 15, x1, #6080
    VLDQ_4S 1, x2, #6080
    smlal v16.2d, v20.2s, v6.2s
    VLDQ_4S 28, x2, #5104
    smlal2 v25.2d, v24.4s, v0.4s
    VLDQ_4S 0, x2, #6096
    smlal v19.2d, v12.2s, v11.2s
    VLDQ_4S 20, x1, #6096
    smlal2 v22.2d, v12.4s, v11.4s
    smlal v13.2d, v15.2s, v1.2s
    VLDQ_4S 11, x1, #6112
    VLDQ_4S 3, x2, #6112
    VLDQ_4S 8, x1, #5104
    smlal2 v17.2d, v15.4s, v1.4s
    smlal v21.2d, v20.2s, v0.2s
    smlal2 v25.2d, v20.4s, v0.4s
    smlal v19.2d, v11.2s, v3.2s
    uzp1 v10.4s, v13.4s, v17.4s
    smlal v16.2d, v8.2s, v28.2s
    uzp1 v4.4s, v21.4s, v25.4s
    VLDQ_4S 12, x2, #6128
    smlal2 v23.2d, v8.4s, v28.4s
    smlal2 v22.2d, v11.4s, v3.4s
    VLDQ_4S 28, x1, #6128
    mul v27.4s, v10.4s, v30.4s
    mul v4.4s, v4.4s, v30.4s
    smlal v16.2d, v28.2s, v12.2s
    smlal2 v23.2d, v28.4s, v12.4s
    uzp1 v10.4s, v19.4s, v22.4s
    smlsl v13.2d, v27.2s, v31.2s
    uzp1 v12.4s, v16.4s, v23.4s
    smlsl v21.2d, v4.2s, v31.2s
    mul v5.4s, v10.4s, v30.4s
    mul v20.4s, v12.4s, v30.4s
    VLDQ_4S 1, x1, #16
    smlsl2 v25.2d, v4.4s, v31.4s
    VLDQ_4S 0, x1, #32
    VLDQ_4S_POST 10, x1, #4*16
    VLDQ_4S 24, x2, #32
    smlsl2 v22.2d, v5.4s, v31.4s
    VLDQ_4S 28, x1, #992
    VLDQ_4S 18, x2, #16
    smlsl v19.2d, v5.2s, v31.2s
    VLDQ_4S_POST 29, x2, #4*16
    smlsl v16.2d, v20.2s, v31.2s
    uzp2 v26.4s, v19.4s, v22.4s
    VLDQ_4S 12, x2, #992
    uzp2 v3.4s, v21.4s, v25.4s
    smlsl2 v23.2d, v20.4s, v31.4s
    uzp2 v9.4s, v16.4s, v23.4s
    smlsl2 v17.2d, v27.4s, v31.4s
    MLDSA_VSTQ_4S 26, x0, #32
    smull v21.2d, v1.2s, v18.2s
    uzp2 v4.4s, v13.4s, v17.4s
    smull2 v17.2d, v10.4s, v29.4s
    MLDSA_VSTQ_4S 9, x0, #48
    smull2 v22.2d, v0.4s, v24.4s
    MLDSA_VSTQ_4S_POST 4, x0, #4*16
    MLDSA_VSTQ_4S 3, x0, #-48
    smlal2 v22.2d, v28.4s, v12.4s
    subs x3, x3, 1
    cbnz x3, .Lpolyvecl_pointwise_acc_montgomery_l7_loop_start
    VLDQ_4S 16, x2, #960
    smull v13.2d, v10.2s, v29.2s
    VLDQ_4S 2, x1, #960
    VLDQ_4S 27, x1, #-16
    smull v19.2d, v0.2s, v24.2s
    VLDQ_4S 11, x2, #-16
    VLDQ_4S 10, x2, #1008
    smlal v19.2d, v28.2s, v12.2s
    VLDQ_4S 12, x1, #1008
    VLDQ_4S 29, x2, #1984
    smull2 v25.2d, v1.4s, v18.4s
    VLDQ_4S 0, x1, #1984
    smlal v13.2d, v2.2s, v16.2s
    VLDQ_4S 14, x2, #976
    VLDQ_4S 3, x1, #976
    smull2 v23.2d, v27.4s, v11.4s
    VLDQ_4S 4, x2, #2000
    smlal2 v17.2d, v2.4s, v16.4s
    VLDQ_4S 15, x1, #2000
    smlal v21.2d, v3.2s, v14.2s
    VLDQ_4S 20, x1, #3024
    VLDQ_4S 24, x2, #3024
    VLDQ_4S 1, x1, #3008
    smlal2 v25.2d, v3.4s, v14.4s
    VLDQ_4S 9, x2, #3008
    smlal2 v17.2d, v0.4s, v29.4s
    VLDQ_4S 18, x2, #3056
    smlal v21.2d, v15.2s, v4.2s
    smlal v21.2d, v20.2s, v24.2s
    smlal2 v17.2d, v1.4s, v9.4s
    VLDQ_4S 5, x2, #2016
    VLDQ_4S 7, x2, #4032
    smull v16.2d, v27.2s, v11.2s
    VLDQ_4S 28, x1, #4032
    smlal v16.2d, v12.2s, v10.2s
    VLDQ_4S 11, x2, #5056
    VLDQ_4S 2, x1, #2016
    smlal v13.2d, v0.2s, v29.2s
    VLDQ_4S 0, x1, #5056
    smlal v13.2d, v1.2s, v9.2s
    smlal v13.2d, v28.2s, v7.2s
    smlal2 v17.2d, v28.4s, v7.4s
    VLDQ_4S 26, x1, #4048
    VLDQ_4S 8, x1, #2032
    smlal2 v25.2d, v15.4s, v4.4s
    VLDQ_4S 27, x2, #4048
    smlal2 v22.2d, v2.4s, v5.4s
    VLDQ_4S 1, x1, #3040
    VLDQ_4S 14, x2, #3040
    smlal v19.2d, v2.2s, v5.2s
    VLDQ_4S 4, x2, #4064
    VLDQ_4S 28, x1, #4064
    smlal2 v25.2d, v20.4s, v24.4s
    VLDQ_4S 24, x1, #3056
    VLDQ_4S 5, x2, #2032
    smlal2 v23.2d, v12.4s, v10.4s
    smlal2 v22.2d, v1.4s, v14.4s
    smlal v19.2d, v1.2s, v14.2s
    smlal v19.2d, v28.2s, v4.2s
    VLDQ_4S 1, x2, #6080
    smlal2 v22.2d, v28.4s, v4.4s
    VLDQ_4S 15, x1, #6080
    VLDQ_4S 28, x2, #4080
    VLDQ_4S 10, x1, #4080
    smlal2 v17.2d, v0.4s, v11.4s
    smlal2 v17.2d, v15.4s, v1.4s
    VLDQ_4S 6, x2, #5088
    VLDQ_4S 3, x1, #6096
    smlal v16.2d, v8.2s, v5.2s
    VLDQ_4S 29, x2, #6096
    VLDQ_4S 4, x1, #5072
    smlal v16.2d, v24.2s, v18.2s
    VLDQ_4S 14, x1, #5088
    smlal v16.2d, v10.2s, v28.2s
    smlal v13.2d, v0.2s, v11.2s
    smlal v13.2d, v15.2s, v1.2s
    smlal2 v23.2d, v8.4s, v5.4s
    VLDQ_4S 5, x2, #5072
    smlal2 v23.2d, v24.4s, v18.4s
    VLDQ_4S 0, x2, #5104
    VLDQ_4S 1, x2, #6112
    smlal2 v23.2d, v10.4s, v28.4s
    VLDQ_4S 24, x1, #5104
    VLDQ_4S 10, x2, #6128
    smlal2 v25.2d, v26.4s, v27.4s
    VLDQ_4S 18, x1, #6112
    uzp1 v11.4s, v13.4s, v17.4s
    smlal v21.2d, v26.2s, v27.2s
    VLDQ_4S 27, x1, #6128
    smlal2 v25.2d, v4.4s, v5.4s
    smlal v21.2d, v4.2s, v5.2s
    smlal2 v25.2d, v3.4s, v29.4s
    smlal v21.2d, v3.2s, v29.2s
    smlal2 v22.2d, v14.4s, v6.4s
    uzp1 v29.4s, v21.4s, v25.4s
    smlal v19.2d, v14.2s, v6.2s
    smlal v16.2d, v24.2s, v0.2s
    smlal2 v23.2d, v24.4s, v0.4s
    smlal2 v22.2d, v18.4s, v1.4s
    smlal v19.2d, v18.2s, v1.2s
    smlal v16.2d, v27.2s, v10.2s
    uzp1 v1.4s, v19.4s, v22.4s
    smlal2 v23.2d, v27.4s, v10.4s
    mul v0.4s, v11.4s, v30.4s
    uzp1 v24.4s, v16.4s, v23.4s
    mul v10.4s, v29.4s, v30.4s
    mul v1.4s, v1.4s, v30.4s
    mul v24.4s, v24.4s, v30.4s
    smlsl v21.2d, v10.2s, v31.2s
    smlsl2 v25.2d, v10.4s, v31.4s
    smlsl2 v17.2d, v0.4s, v31.4s
    uzp2 v21.4s, v21.4s, v25.4s
    smlsl v13.2d, v0.2s, v31.2s
    smlsl2 v22.2d, v1.4s, v31.4s
    uzp2 v17.4s, v13.4s, v17.4s
    smlsl v19.2d, v1.2s, v31.2s
    MLDSA_VSTQ_4S 21, x0, #16
    smlsl v16.2d, v24.2s, v31.2s
    uzp2 v21.4s, v19.4s, v22.4s
    smlsl2 v23.2d, v24.4s, v31.4s
    MLDSA_VSTQ_4S_POST 17, x0, #4*16
    uzp2 v17.4s, v16.4s, v23.4s
    MLDSA_VSTQ_4S 21, x0, #-32
    MLDSA_VSTQ_4S 17, x0, #-16
    pointwise_acc_pop_stack
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLDSA_PointwiseAccMontL7Asm)

    .unreq out_ptr
    .unreq a_ptr
    .unreq b_ptr
    .unreq count
    .unreq wtmp

    .unreq const_q
    .unreq const_q_twisted

    .unreq arr_a0
    .unreq arr_a1
    .unreq arr_a2
    .unreq arr_a3
    .unreq arr_b0
    .unreq arr_b1
    .unreq arr_b2
    .unreq arr_b3
    .unreq q_arr_a0
    .unreq q_arr_a1
    .unreq q_arr_a2
    .unreq q_arr_a3
    .unreq q_arr_b0
    .unreq q_arr_b1
    .unreq q_arr_b2
    .unreq q_arr_b3
    .unreq c_0_lo
    .unreq c_0_hi
    .unreq c_1_lo
    .unreq c_1_hi
    .unreq c_2_lo
    .unreq c_2_hi
    .unreq c_3_lo
    .unreq c_3_hi
#endif // HITLS_CRYPTO_MLDSA_ARMV8
