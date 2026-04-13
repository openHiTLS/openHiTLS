/*
 * based on https://eprint.iacr.org/2021/986, CC0 1.0 Universal.
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
 * ML-KEM Base Multiplication — ARMv8 NEON Implementation
 * ============================================================================
 *
 * References:
 *   [NeonNTT]  Becker, Hwang, Kannwischer, Yang, Yang.
 *              "Neon NTT." https://eprint.iacr.org/2021/986
 *   [FIPS203]  NIST FIPS 203, Algorithm 12 (BaseCaseMultiply).
 *
 * Algorithm Overview:
 *   In NTT domain, polynomial multiplication reduces to 128 independent
 *   degree-1 multiplications in F_q[X]/(X² − ζ_i), where ζ_i are the
 *   128 primitive 256th roots of unity modulo Q = 3329.
 *
 *   For two polynomials a = a₀ + a₁X and b = b₀ + b₁X in F_q[X]/(X² − ζ):
 *     c₀ = a₀·b₀ + a₁·b₁·ζ
 *     c₁ = a₀·b₁ + a₁·b₀
 *
 *   This file implements three main operations:
 *
 *   1. MLKEMPointMulExtended — Element-wise Montgomery multiplication of a
 *      polynomial by a precomputed extended table. Used for computing the
 *      "mulcache" (b₁·ζ values) needed for basemul.
 *      Input polynomials are stored interleaved: [a₀,a₁, a₂,a₃, ...]
 *      uzp2 extracts the odd elements (a₁ values) for multiplication.
 *
 *   2. MLKEMAsymMul — Asymmetric basemul accumulation over k polynomials:
 *        r = Σᵢ aᵢ ⊗ bᵢ  (sum of k basemul products)
 *      Dispatches to k2/k3/k4 variants. Uses 32-bit schoolbook accumulation:
 *        - smull/smlal for 16×16→32 multiply-accumulate
 *        - Accumulates k products in 32-bit before final Montgomery reduction
 *      The "asymmetric" name refers to the asymmetric representation where
 *      the mulcache (b₁·ζ) is precomputed and stored separately.
 *
 *   3. MLKEMAsymMulMont — Same as MLKEMAsymMul but with Montgomery form input.
 *      Used when input polynomial is already in Montgomery domain.
 *
 * Schoolbook Accumulation Pattern (per 16-coefficient block):
 *   Input layout: a = [a₀, a₁] interleaved, b = [b₀, b₁] interleaved
 *   uzp1/uzp2 deinterleave into even (a₀,b₀) and odd (a₁,b₁) halves
 *
 *   smull  v16.4S, a₀.4H, b₀.4H      // c₀_lo = a₀ × b₀  (low 4 lanes)
 *   smull2 v18.4S, a₀.8H, b₀.8H      // c₀_hi = a₀ × b₀  (high 4 lanes)
 *   smull  v17.4S, a₀.4H, b₁.4H      // c₁_lo = a₀ × b₁
 *   smull2 v19.4S, a₀.8H, b₁.8H      // c₁_hi = a₀ × b₁
 *   smlal  v16.4S, a₁.4H, γ.4H       // c₀_lo += a₁ × (b₁·ζ)
 *   smlal2 v18.4S, a₁.8H, γ.8H       // c₀_hi += a₁ × (b₁·ζ)
 *   smlal  v17.4S, a₁.4H, b₀.4H      // c₁_lo += a₁ × b₀
 *   smlal2 v19.4S, a₁.8H, b₀.8H      // c₁_hi += a₁ × b₀
 *
 *   After accumulating k products, Montgomery reduction:
 *   uzp1   lo.8H, c₀.4S, c₀.4S       // Extract low 16 bits
 *   mul    lo.8H, lo.8H, Qinv.H[1]    // lo × Q^{-1} mod 2^16
 *   smlal  c₀.4S, lo.4H, Q.H[0]      // c₀ += lo × Q
 *   uzp2   hi.8H, c₀.4S, c₀.4S       // Extract high 16 bits = result
 *   st2   {hi₀, hi₁}, [des], #32      // Store interleaved [c₀, c₁]
 *
 * Functions:
 *   MLKEMPointMulExtended(int16_t *des, int16_t *src, int16_t *table_ext)
 *   MLKEMAsymMul(uint32_t k, int16_t *r, int16_t **a, int16_t *b, int16_t *c)
 *   MLKEMAsymMulMont(uint32_t k, int16_t *r, int16_t *a, int16_t *b, int16_t *c)
 * ============================================================================
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MLKEM

#include "crypt_arm.h"
CRYPT_AARCH64_ARCH_BASE

// =============================================================================
// MLKEMPointMulExtended — Element-wise Montgomery multiplication
// =============================================================================
//
// Computes des[i] = src[2i+1] × table_ext[i] × R^{-1} mod Q
// for i = 0..127 (processing odd-indexed coefficients = a₁ values)
//
// This precomputes the "mulcache" used in asymmetric basemul:
//   mulcache[i] = a₁[i] × ζ[i] mod Q (in Montgomery form)
//
// Parameters:
//   x0 (des):    output buffer, 128 int16_t
//   x1 (src1):   input polynomial, 256 int16_t (interleaved a₀,a₁ pairs)
//   x2 (src2ex): extended table with (tw_lo, tw_hi) pairs for Montgomery mul
//
// Montgomery multiplication pattern:
//   uzp2  extracts odd elements (a₁ values) from interleaved pairs
//   sqrdmulh + mul + mls performs Montgomery reduction:
//     sqrdmulh hi, a₁, tw_hi   → hi ≈ (a₁ × tw_hi) >> 15
//     mul      lo, a₁, tw_lo   → lo = a₁ × tw_lo (low 16 bits)
//     mls      lo, hi, Q       → lo = lo − hi × Q  (Montgomery reduced result)
//
// Processes 256 input coefficients (128 odd-indexed) in 4 batches of 32 coefficients.
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEMPointMulExtended)
AARCH64_PACIASP
    // --- Prologue: save callee-saved registers (x19-x28, d8-d15) ---
    sub sp, sp, #(9*16)
    stp x19, x20, [sp, #0*16]
    stp x21, x22, [sp, #1*16]
    stp x23, x24, [sp, #2*16]
    stp x25, x26, [sp, #3*16]
    stp x27, x28, [sp, #4*16]
    stp  d8,  d9, [sp, #5*16]
    stp d10, d11, [sp, #6*16]
    stp d12, d13, [sp, #7*16]
    stp d14, d15, [sp, #8*16]
    // --- Register aliases ---
    Q         .req w20
    des       .req x0
    src1      .req x1
    src2ex    .req x2
    counter   .req x19

    // --- Load modulus Q = 3329 into all 16-bit lanes of v28 ---
    mov Q, #3329

    dup v28.8H, Q

    // --- Load first 8×16B of interleaved source polynomial [a₀,a₁] pairs ---
    ldr  q0, [src1, #0*16]
    ldr  q1, [src1, #1*16]
    ldr  q2, [src1, #2*16]
    ldr  q3, [src1, #3*16]
    ldr  q4, [src1, #4*16]
    ldr  q5, [src1, #5*16]
    ldr  q6, [src1, #6*16]
    ldr  q7, [src1, #7*16]

    add src1, src1, #8*16

    // --- Extract odd coefficients (a₁) from interleaved [a₀,a₁] pairs ---
    uzp2  v1.8H,  v0.8H,  v1.8H
    uzp2  v3.8H,  v2.8H,  v3.8H
    uzp2  v5.8H,  v4.8H,  v5.8H
    uzp2  v7.8H,  v6.8H,  v7.8H

    // --- Load first 8 Montgomery table pairs (tw_lo, tw_hi) ---
    ldr  q8, [src2ex, #0*16]
    ldr q10, [src2ex, #2*16]
    ldr q12, [src2ex, #4*16]
    ldr q14, [src2ex, #6*16]
    ldr  q9, [src2ex, #1*16]
    ldr q11, [src2ex, #3*16]
    ldr q13, [src2ex, #5*16]
    ldr q15, [src2ex, #7*16]

    add src2ex, src2ex, #8*16

    // --- Interleaved: sqrdmulh high parts + load next src1 batch ---
    ldr q16, [src1, #0*16]
    sqrdmulh  v0.8H,  v1.8H,  v9.8H
    ldr q17, [src1, #1*16]
    sqrdmulh  v2.8H,  v3.8H, v11.8H
    ldr q18, [src1, #2*16]
    sqrdmulh  v4.8H,  v5.8H, v13.8H
    ldr q19, [src1, #3*16]
    sqrdmulh  v6.8H,  v7.8H, v15.8H

    // --- Interleaved: mul low parts + uzp2 extract odd coefficients ---
    ldr q20, [src1, #4*16]
    mul       v1.8H,  v1.8H,  v8.8H
    uzp2 v17.8H, v16.8H, v17.8H
    ldr q21, [src1, #5*16]
    mul       v3.8H,  v3.8H, v10.8H
    uzp2 v19.8H, v18.8H, v19.8H
    ldr q22, [src1, #6*16]
    mul       v5.8H,  v5.8H, v12.8H
    uzp2 v21.8H, v20.8H, v21.8H
    ldr q23, [src1, #7*16]
    mul       v7.8H,  v7.8H, v14.8H
    uzp2 v23.8H, v22.8H, v23.8H

    add src1, src1, #8*16

    // --- Interleaved: mls subtract correction + load next table_ext batch ---
    ldr  q8, [src2ex, #0*16]
    mls       v1.8H,  v0.8H, v28.8H
    ldr q10, [src2ex, #2*16]
    mls       v3.8H,  v2.8H, v28.8H
    ldr q12, [src2ex, #4*16]
    mls       v5.8H,  v4.8H, v28.8H
    ldr q14, [src2ex, #6*16]
    mls       v7.8H,  v6.8H, v28.8H

    // --- Store first batch results while loading remaining table_ext ---
    ldr  q9, [src2ex, #1*16]
    str  q1, [des, #0*16]
    ldr q11, [src2ex, #3*16]
    str  q3, [des, #1*16]
    ldr q13, [src2ex, #5*16]
    str  q5, [des, #2*16]
    ldr q15, [src2ex, #7*16]
    str  q7, [des, #3*16]

    add des, des, #4*16

    add src2ex, src2ex, #8*16

    // --- Batch 2: sqrdmulh high parts + load src1 ---
    ldr  q0, [src1, #0*16]
    sqrdmulh v16.8H, v17.8H,  v9.8H
    ldr  q1, [src1, #1*16]
    sqrdmulh v18.8H, v19.8H, v11.8H
    ldr  q2, [src1, #2*16]
    sqrdmulh v20.8H, v21.8H, v13.8H
    ldr  q3, [src1, #3*16]
    sqrdmulh v22.8H, v23.8H, v15.8H

    // --- Batch 2: mul low parts + uzp2 extract odd coefficients ---
    ldr  q4, [src1, #4*16]
    mul      v17.8H, v17.8H,  v8.8H
    uzp2  v1.8H,  v0.8H,  v1.8H
    ldr  q5, [src1, #5*16]
    mul      v19.8H, v19.8H, v10.8H
    uzp2  v3.8H,  v2.8H,  v3.8H
    ldr  q6, [src1, #6*16]
    mul      v21.8H, v21.8H, v12.8H
    uzp2  v5.8H,  v4.8H,  v5.8H
    ldr  q7, [src1, #7*16]
    mul      v23.8H, v23.8H, v14.8H
    uzp2  v7.8H,  v6.8H,  v7.8H

    add src1, src1, #8*16

    // --- Batch 2: mls subtract correction + load next table_ext ---
    ldr  q8, [src2ex, #0*16]
    mls      v17.8H, v16.8H, v28.8H
    ldr q10, [src2ex, #2*16]
    mls      v19.8H, v18.8H, v28.8H
    ldr q12, [src2ex, #4*16]
    mls      v21.8H, v20.8H, v28.8H
    ldr q14, [src2ex, #6*16]
    mls      v23.8H, v22.8H, v28.8H

    // --- Batch 2: store results + load tw_hi for batch 3 ---
    ldr  q9, [src2ex, #1*16]
    str q17, [des, #0*16]
    ldr q11, [src2ex, #3*16]
    str q19, [des, #1*16]
    ldr q13, [src2ex, #5*16]
    str q21, [des, #2*16]
    ldr q15, [src2ex, #7*16]
    str q23, [des, #3*16]

    add des, des, #4*16

    add src2ex, src2ex, #8*16

    // --- Batch 3: sqrdmulh high parts + load remaining src1 ---
    ldr q16, [src1, #0*16]
    sqrdmulh  v0.8H,  v1.8H,  v9.8H
    ldr q17, [src1, #1*16]
    sqrdmulh  v2.8H,  v3.8H, v11.8H
    ldr q18, [src1, #2*16]
    sqrdmulh  v4.8H,  v5.8H, v13.8H
    ldr q19, [src1, #3*16]
    sqrdmulh  v6.8H,  v7.8H, v15.8H

    // --- Batch 3: mul low parts + uzp2 extract odd coefficients ---
    ldr q20, [src1, #4*16]
    mul       v1.8H,  v1.8H,  v8.8H
    uzp2 v17.8H, v16.8H, v17.8H
    ldr q21, [src1, #5*16]
    mul       v3.8H,  v3.8H, v10.8H
    uzp2 v19.8H, v18.8H, v19.8H
    ldr q22, [src1, #6*16]
    mul       v5.8H,  v5.8H, v12.8H
    uzp2 v21.8H, v20.8H, v21.8H
    ldr q23, [src1, #7*16]
    mul       v7.8H,  v7.8H, v14.8H
    uzp2 v23.8H, v22.8H, v23.8H

    add src1, src1, #8*16

    // --- Batch 3: mls subtract correction ---
    ldr  q8, [src2ex, #0*16]
    mls       v1.8H,  v0.8H, v28.8H
    ldr q10, [src2ex, #2*16]
    mls       v3.8H,  v2.8H, v28.8H
    ldr q12, [src2ex, #4*16]
    mls       v5.8H,  v4.8H, v28.8H
    ldr q14, [src2ex, #6*16]
    mls       v7.8H,  v6.8H, v28.8H

    // --- Batch 3: store results + load tw_hi for batch 4 ---
    ldr  q9, [src2ex, #1*16]
    str  q1, [des, #0*16]
    ldr q11, [src2ex, #3*16]
    str  q3, [des, #1*16]
    ldr q13, [src2ex, #5*16]
    str  q5, [des, #2*16]
    ldr q15, [src2ex, #7*16]
    str  q7, [des, #3*16]

    add des, des, #4*16

    add src2ex, src2ex, #8*16

    // --- Batch 4 (final): complete Montgomery mul without interleaved loads ---
    sqrdmulh v16.8H, v17.8H,  v9.8H
    sqrdmulh v18.8H, v19.8H, v11.8H
    sqrdmulh v20.8H, v21.8H, v13.8H
    sqrdmulh v22.8H, v23.8H, v15.8H

    mul      v17.8H, v17.8H,  v8.8H
    mul      v19.8H, v19.8H, v10.8H
    mul      v21.8H, v21.8H, v12.8H
    mul      v23.8H, v23.8H, v14.8H

    mls      v17.8H, v16.8H, v28.8H
    mls      v19.8H, v18.8H, v28.8H
    mls      v21.8H, v20.8H, v28.8H
    mls      v23.8H, v22.8H, v28.8H

    // --- Store batch 4 results ---
    str q17, [des, #0*16]
    str q19, [des, #1*16]
    str q21, [des, #2*16]
    str q23, [des, #3*16]

    add des, des, #4*16

    // --- Epilogue: restore registers and return ---
    .unreq    Q
    .unreq    des
    .unreq    src1
    .unreq    src2ex
    .unreq    counter
    ldp x19, x20, [sp, #0*16]
    ldp x21, x22, [sp, #1*16]
    ldp x23, x24, [sp, #2*16]
    ldp x25, x26, [sp, #3*16]
    ldp x27, x28, [sp, #4*16]
    ldp  d8,  d9, [sp, #5*16]
    ldp d10, d11, [sp, #6*16]
    ldp d12, d13, [sp, #7*16]
    ldp d14, d15, [sp, #8*16]
    add sp, sp, #(9*16)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMPointMulExtended)


// =============================================================================
// MLKEMAsymMul — Asymmetric basemul dispatcher
// =============================================================================
//
// Computes r = Σᵢ₌₀ᵏ⁻¹ aᵢ ⊗ bᵢ  where ⊗ is basemul in NTT domain.
// Input polynomials a[i] are in NTT form (interleaved [a₀,a₁] pairs).
// b and c (asymmetric cache) are contiguous arrays of k polynomials.
//
// Dispatches to MLKEMAsymMulk{2,3,4} based on k parameter.
// After dispatch, argument registers are reshuffled:
//   x0=r, x1=a (pointer array), x2=b, x3=c (mulcache), x4=asymConst
//
// Parameters:
//   x0: k (ML-KEM parameter: 2=ML-KEM-512, 3=ML-KEM-768, 4=ML-KEM-1024)
//   x1: r (output polynomial, 256 interleaved int16_t)
//   x2: a (int16_t**, array of k pointers to source polynomials)
//   x3: b (int16_t*, k×256 contiguous coefficients)
//   x4: c (int16_t*, k×128 precomputed mulcache = b₁·ζ values)
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEMAsymMul)
    cmp     w0, #2
    b.eq    .Lasm_mul_k2
    cmp     w0, #3
    b.eq    .Lasm_mul_k3
    cmp     w0, #4
    b.eq    .Lasm_mul_k4
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMAsymMul)
.Lasm_mul_k2:
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    b       CRYPT_AARCH64_SYM(MLKEMAsymMulk2)
.Lasm_mul_k3:
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    b       CRYPT_AARCH64_SYM(MLKEMAsymMulk3)
.Lasm_mul_k4:
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    b       CRYPT_AARCH64_SYM(MLKEMAsymMulk4)

// =============================================================================
// MLKEMAsymMulk2 — Asymmetric basemul accumulation, k=2 (ML-KEM-512)
// =============================================================================
//
// Computes r = a[0]⊗b[0..255] + a[1]⊗b[256..511]
// Each ⊗ is schoolbook multiplication in F_q[X]/(X²−ζ):
//   c₀ = a₀·b₀ + a₁·γ,  c₁ = a₀·b₁ + a₁·b₀
// where γ = b₁·ζ (precomputed mulcache).
//
// Uses 32-bit accumulation (smull/smlal) to sum 2 products before
// Montgomery reduction, avoiding intermediate reductions.
//
// Register mapping:
//   v0-v3:   current polynomial a[i] coefficients (a₀, a₁, b₀, b₁)
//   v4:      S[0]=Q, S[1]=Q^{-1} mod 2^16 (for Montgomery reduction)
//   v8-v15:  second polynomial pair coefficients
//   v16-v19: 32-bit accumulators [c₀_lo, c₁_lo, c₀_hi, c₁_hi]
//   v28-v30: mulcache γ values for each polynomial pair
//
// Loop: 16 iterations (first unrolled, 15 in loop body)
// Each iteration processes 16 output coefficients (8 interleaved pairs)
// =============================================================================
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMAsymMulk2)
AARCH64_PACIASP
    // --- Prologue: save callee-saved registers (x19-x28, d8-d15) ---
    sub sp, sp, #(9*16)
    stp x19, x20, [sp, #0*16]
    stp x21, x22, [sp, #1*16]
    stp x23, x24, [sp, #2*16]
    stp x25, x26, [sp, #3*16]
    stp x27, x28, [sp, #4*16]
    stp  d8,  d9, [sp, #5*16]
    stp d10, d11, [sp, #6*16]
    stp d12, d13, [sp, #7*16]
    stp d14, d15, [sp, #8*16]
    // --- Register aliases ---
    des       .req x11
    src1_0    .req x0
    src2_0    .req x1
    src2asy_0 .req x2
    src1_1    .req x7
    src2_1    .req x5
    src2asy_1 .req x6
    src1_2    .req x8
    src2_2    .req x9
    src2asy_2 .req x10
    src1_3    .req x12
    src2_3    .req x13
    src2asy_3 .req x14
    counter   .req x19

    // --- Setup: load pointers and pack Q|Qprime into v4.H[0:1] ---
    add des, x0, #0
    ldp src1_0, src1_1, [x1]
    mov src2_0, x2
    mov src2asy_0, x3

    mov w4, #3329             // Q
    movk w4, #3327, lsl #16   // Qprime = -Q^{-1} mod 2^16
    fmov s4, w4

    // --- Compute offsets for polynomial pair 1 (b offset by 512, mulcache by 256) ---
    add     src2_1,    src2_0, #512*1
    add  src2asy_1, src2asy_0, #256*1

    // --- Load and deinterleave first block of a[0] and b[0] ---
    ldr q20, [src1_0, #0*16]
    ldr q21, [src1_0, #1*16]
    ldr q22, [src2_0, #0*16]
    ldr q23, [src2_0, #1*16]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    // --- uzp1/uzp2 deinterleave: [a₀,a₁] → a₀ in v0, a₁ in v1; b₀ in v2, b₁ in v3 ---
    uzp1  v0.8H, v20.8H, v21.8H
    uzp2  v1.8H, v20.8H, v21.8H
    uzp1  v2.8H, v22.8H, v23.8H
    uzp2  v3.8H, v22.8H, v23.8H

    // --- Load mulcache γ₀ = b₁·ζ for polynomial pair 0 ---
    ld1 {v28.8H}, [src2asy_0], #16

    // ---- Schoolbook product 0: c₀ = a₀·b₀, c₁ = a₀·b₁ (initial smull) ----
    // Interleaved with loading a[1] and b[1] for product 1
    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    // --- Complete product 0: c₀ += a₁·γ₀, c₁ += a₁·b₀; deinterleave a[1], b[1] ---
    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    // --- Load mulcache γ₁ for polynomial pair 1 ---
    ld1 {v29.8H}, [src2asy_1], #16

    // ---- Schoolbook product 1: c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    smlal  v16.4S,  v8.4H, v10.4H
    smlal2 v18.4S,  v8.8H, v10.8H
    smlal  v17.4S,  v8.4H, v11.4H
    smlal2 v19.4S,  v8.8H, v11.8H

    // --- Complete product 1: c₀ += a₁·γ₁, c₁ += a₁·b₀ ---
    smlal  v16.4S,  v9.4H, v29.4H
    smlal2 v18.4S,  v9.8H, v29.8H
    smlal  v17.4S,  v9.4H, v10.4H
    smlal2 v19.4S,  v9.8H, v10.8H

    // --- Software pipeline: 15 iterations with interleaved compute/load/store ---
    // Each loop iteration performs three overlapping phases:
    //   Phase A: Montgomery-reduce previous iteration's 32-bit accumulators → 16-bit
    //   Phase B: Store reduced [c₀,c₁] via st2 while loading next iteration's a[0],b[0]
    //   Phase C: Schoolbook-accumulate k=2 polynomial products for next iteration
    // Memory loads for the next iteration's schoolbook are issued during Phase A's
    // NEON arithmetic, hiding L1D cache latency behind the reduction pipeline.
    mov counter, #15
    1:

    // ---- Montgomery reduction: 32-bit accumulators → 16-bit results ----
    // uzp1 extracts low 16 bits from 32-bit accumulators for Q^{-1} mul
    // smlal adds correction back; uzp2 extracts final high 16 bits
    ldr q20, [src1_0, #0*16]
    uzp1    v6.8H, v16.8H, v18.8H
    ldr q21, [src1_0, #1*16]
    uzp1    v7.8H, v17.8H, v19.8H

    ldr q22, [src2_0, #0*16]
    mul     v6.8H,  v6.8H, v4.H[1]
    ldr q23, [src2_0, #1*16]
    mul     v7.8H,  v7.8H, v4.H[1]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    smlal  v16.4S,  v6.4H, v4.H[0]
    uzp1  v0.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v6.8H, v4.H[0]
    uzp2  v1.8H, v20.8H, v21.8H
    smlal  v17.4S,  v7.4H, v4.H[0]
    uzp1  v2.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v7.8H, v4.H[0]
    uzp2  v3.8H, v22.8H, v23.8H

    ld1 {v28.8H}, [src2asy_0], #16
    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    st2 { v6.8H,  v7.8H}, [des], #32

    // ---- Schoolbook accumulation: product 1 (a[0]⊗b[0]) ----
    // c₀ = a₀·b₀,  c₁ = a₀·b₁ (initial smull)
    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    ld1 {v29.8H}, [src2asy_1], #16

    // ---- Schoolbook accumulation: product 2 (a[1]⊗b[1]) ----
    // c₀ += a₀·b₀,  c₁ += a₀·b₁ (smlal into existing accumulators)
    smlal  v16.4S,  v8.4H, v10.4H
    smlal2 v18.4S,  v8.8H, v10.8H
    smlal  v17.4S,  v8.4H, v11.4H
    smlal2 v19.4S,  v8.8H, v11.8H

    // c₀ += a₁·(b₁·ζ),  c₁ += a₁·b₀  (complete schoolbook for polynomial 2)
    smlal  v16.4S,  v9.4H, v29.4H
    smlal2 v18.4S,  v9.8H, v29.8H
    smlal  v17.4S,  v9.4H, v10.4H
    smlal2 v19.4S,  v9.8H, v10.8H

    sub counter, counter, #1
    cbnz counter, 1b

    uzp1    v6.8H, v16.8H, v18.8H
    uzp1    v7.8H, v17.8H, v19.8H

    mul     v6.8H,  v6.8H, v4.H[1]
    mul     v7.8H,  v7.8H, v4.H[1]

    smlal  v16.4S,  v6.4H, v4.H[0]
    smlal2 v18.4S,  v6.8H, v4.H[0]
    smlal  v17.4S,  v7.4H, v4.H[0]
    smlal2 v19.4S,  v7.8H, v4.H[0]

    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    st2 { v6.8H,  v7.8H}, [des], #32

    .unreq    des
    .unreq    src1_0
    .unreq    src2_0
    .unreq    src2asy_0
    .unreq    src1_1
    .unreq    src2_1
    .unreq    src2asy_1
    .unreq    src1_2
    .unreq    src2_2
    .unreq    src2asy_2
    .unreq    src1_3
    .unreq    src2_3
    .unreq    src2asy_3
    .unreq    counter
    ldp x19, x20, [sp, #0*16]
    ldp x21, x22, [sp, #1*16]
    ldp x23, x24, [sp, #2*16]
    ldp x25, x26, [sp, #3*16]
    ldp x27, x28, [sp, #4*16]
    ldp  d8,  d9, [sp, #5*16]
    ldp d10, d11, [sp, #6*16]
    ldp d12, d13, [sp, #7*16]
    ldp d14, d15, [sp, #8*16]
    add sp, sp, #(9*16)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMAsymMulk2)

// =============================================================================
// MLKEMAsymMulk3 — Asymmetric basemul accumulation, k=3 (ML-KEM-768)
// =============================================================================
//
// Computes r = a[0]⊗b[0..255] + a[1]⊗b[256..511] + a[2]⊗b[512..767]
// Each ⊗ is schoolbook multiplication in F_q[X]/(X²−ζ):
//   c₀ = a₀·b₀ + a₁·γ,  c₁ = a₀·b₁ + a₁·b₀  where γ = b₁·ζ
//
// Signature: void MLKEMAsymMulk3(int16_t *r, int16_t **a, int16_t *b, int16_t *c)
//   x0 (r):  output polynomial, 256 interleaved int16_t
//   x1 (a):  int16_t**, array of 3 pointers to source polynomials
//   x2 (b):  int16_t*, 3×256 contiguous coefficients
//   x3 (c):  int16_t*, 3×128 precomputed mulcache = b₁·ζ values
//
// Algorithm:
//   1. Load and deinterleave a[i], b[i] into even/odd coefficient halves
//   2. Schoolbook accumulate 3 products using smull/smlal (32-bit)
//   3. Montgomery-reduce accumulated 32-bit → 16-bit
//   4. Store interleaved [c₀, c₁] via st2
//   5. Repeat for 16 blocks (first unrolled, 15 in loop)
//
// Register allocation:
//   v0-v3:    polynomial 0 coefficients (a₀, a₁, b₀, b₁)
//   v4:       S[0]=Q, S[1]=Q^{-1} mod 2^16
//   v8-v11:   polynomial 1 coefficients
//   v12-v15:  polynomial 2 coefficients
//   v16-v19:  32-bit accumulators [c₀_lo, c₁_lo, c₀_hi, c₁_hi]
//   v28-v30:  mulcache γ values for each of the 3 polynomial pairs
//
// Uses 3 pairs of source pointers (src1_0/src2_0, src1_1/src2_1, src1_2/src2_2)
// and 3 mulcache pointers (src2asy_0, src2asy_1, src2asy_2).
// =============================================================================
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMAsymMulk3)
AARCH64_PACIASP
    // --- Prologue: save callee-saved registers (x19-x28, d8-d15) ---
    sub sp, sp, #(9*16)
    stp x19, x20, [sp, #0*16]
    stp x21, x22, [sp, #1*16]
    stp x23, x24, [sp, #2*16]
    stp x25, x26, [sp, #3*16]
    stp x27, x28, [sp, #4*16]
    stp  d8,  d9, [sp, #5*16]
    stp d10, d11, [sp, #6*16]
    stp d12, d13, [sp, #7*16]
    stp d14, d15, [sp, #8*16]
    // --- Register aliases ---
    des       .req x11
    src1_0    .req x0
    src2_0    .req x1
    src2asy_0 .req x2
    src1_1    .req x7
    src2_1    .req x5
    src2asy_1 .req x6
    src1_2    .req x8
    src2_2    .req x9
    src2asy_2 .req x10
    src1_3    .req x12
    src2_3    .req x13
    src2asy_3 .req x14
    counter   .req x19

    // --- Setup: load pointers and pack Q|Qprime into v4.H[0:1] ---
    add des, x0, #0
    ldp src1_0,src1_1, [x1]
    ldr src1_2, [x1, #16]
    mov src2_0, x2
    mov src2asy_0, x3

    mov w4, #3329             // Q
    movk w4, #3327, lsl #16   // Qprime
    fmov s4, w4

    // --- Compute offsets for polynomial pairs 1 and 2 ---
    add     src2_1,    src2_0, #512*1
    add  src2asy_1, src2asy_0, #256*1

    add     src2_2,    src2_0, #512*2
    add  src2asy_2, src2asy_0, #256*2

    // --- Load and deinterleave first block of a[0] and b[0] ---
    ldr q20, [src1_0, #0*16]
    ldr q21, [src1_0, #1*16]
    ldr q22, [src2_0, #0*16]
    ldr q23, [src2_0, #1*16]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    // --- uzp1/uzp2 deinterleave: a₀ in v0, a₁ in v1; b₀ in v2, b₁ in v3 ---
    uzp1  v0.8H, v20.8H, v21.8H
    uzp2  v1.8H, v20.8H, v21.8H
    uzp1  v2.8H, v22.8H, v23.8H
    uzp2  v3.8H, v22.8H, v23.8H

    // --- Load mulcache γ₀ = b₁·ζ for polynomial pair 0 ---
    ld1 {v28.8H}, [src2asy_0], #16

    // ---- Schoolbook product 0: c₀ = a₀·b₀, c₁ = a₀·b₁ (smull) ----
    // Interleaved with loading a[1] and b[1]
    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    // --- Complete product 0: c₀ += a₁·γ₀, c₁ += a₁·b₀; deinterleave a[1], b[1] ---
    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    // --- Load mulcache γ₁ for polynomial pair 1 ---
    ld1 {v29.8H}, [src2asy_1], #16

    // ---- Schoolbook product 1: c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    // Interleaved with loading a[2] and b[2]
    smlal  v16.4S,  v8.4H, v10.4H
    ldr q20, [src1_2, #0*16]
    smlal2 v18.4S,  v8.8H, v10.8H
    ldr q21, [src1_2, #1*16]
    smlal  v17.4S,  v8.4H, v11.4H
    ldr q22, [src2_2, #0*16]
    smlal2 v19.4S,  v8.8H, v11.8H
    ldr q23, [src2_2, #1*16]

    add src1_2, src1_2, #32
    add src2_2, src2_2, #32

    // --- Complete product 1: c₀ += a₁·γ₁, c₁ += a₁·b₀; deinterleave a[2], b[2] ---
    smlal  v16.4S,  v9.4H, v29.4H
    uzp1 v12.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v9.8H, v29.8H
    uzp2 v13.8H, v20.8H, v21.8H
    smlal  v17.4S,  v9.4H, v10.4H
    uzp1 v14.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v9.8H, v10.8H
    uzp2 v15.8H, v22.8H, v23.8H

    // --- Load mulcache γ₂ for polynomial pair 2 ---
    ld1 {v30.8H}, [src2asy_2], #16

    // ---- Schoolbook product 2: c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    smlal  v16.4S, v12.4H, v14.4H
    smlal2 v18.4S, v12.8H, v14.8H
    smlal  v17.4S, v12.4H, v15.4H
    smlal2 v19.4S, v12.8H, v15.8H

    // --- Complete product 2: c₀ += a₁·γ₂, c₁ += a₁·b₀ ---
    smlal  v16.4S, v13.4H, v30.4H
    smlal2 v18.4S, v13.8H, v30.8H
    smlal  v17.4S, v13.4H, v14.4H
    smlal2 v19.4S, v13.8H, v14.8H

    // --- Software pipeline: 15 iterations with interleaved compute/load/store ---
    // Same interleaving pattern as MLKEMAsymMulk2 but with k=3 polynomial products.
    // Phase A (Montgomery reduction) overlaps with loads for Phase C's 3-product
    // schoolbook accumulation, maximizing NEON arithmetic and load-store throughput.
    mov counter, #15
    1:

    // ---- Phase A: Montgomery reduction of accumulated 32-bit products → 16-bit ----
    // uzp1 extracts low 16 bits, mul by Q^{-1}, smlal adds Q correction, uzp2 extracts result
    ldr q20, [src1_0, #0*16]
    uzp1    v6.8H, v16.8H, v18.8H
    ldr q21, [src1_0, #1*16]
    uzp1    v7.8H, v17.8H, v19.8H

    ldr q22, [src2_0, #0*16]
    mul     v6.8H,  v6.8H, v4.H[1]
    ldr q23, [src2_0, #1*16]
    mul     v7.8H,  v7.8H, v4.H[1]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    // --- smlal correction + deinterleave next a[0], b[0] (load-use overlap) ---
    smlal  v16.4S,  v6.4H, v4.H[0]
    uzp1  v0.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v6.8H, v4.H[0]
    uzp2  v1.8H, v20.8H, v21.8H
    smlal  v17.4S,  v7.4H, v4.H[0]
    uzp1  v2.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v7.8H, v4.H[0]
    uzp2  v3.8H, v22.8H, v23.8H

    // --- Phase B: store reduced [c₀,c₁] and load mulcache for next product 0 ---
    ld1 {v28.8H}, [src2asy_0], #16
    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    st2 { v6.8H,  v7.8H}, [des], #32

    // ---- Phase C product 0: a[0]⊗b[0] ---- schoolbook c₀ = a₀·b₀, c₁ = a₀·b₁ ----
    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    // --- Complete product 0: c₀ += a₁·γ₀, c₁ += a₁·b₀; deinterleave a[1], b[1] ---
    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    ld1 {v29.8H}, [src2asy_1], #16

    // ---- Phase C product 1: a[1]⊗b[1] ---- c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    smlal  v16.4S,  v8.4H, v10.4H
    ldr q20, [src1_2, #0*16]
    smlal2 v18.4S,  v8.8H, v10.8H
    ldr q21, [src1_2, #1*16]
    smlal  v17.4S,  v8.4H, v11.4H
    ldr q22, [src2_2, #0*16]
    smlal2 v19.4S,  v8.8H, v11.8H
    ldr q23, [src2_2, #1*16]

    add src1_2, src1_2, #32
    add src2_2, src2_2, #32

    // --- Complete product 1: c₀ += a₁·γ₁, c₁ += a₁·b₀; deinterleave a[2], b[2] ---
    smlal  v16.4S,  v9.4H, v29.4H
    uzp1 v12.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v9.8H, v29.8H
    uzp2 v13.8H, v20.8H, v21.8H
    smlal  v17.4S,  v9.4H, v10.4H
    uzp1 v14.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v9.8H, v10.8H
    uzp2 v15.8H, v22.8H, v23.8H

    ld1 {v30.8H}, [src2asy_2], #16

    // ---- Phase C product 2: a[2]⊗b[2] ---- c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    smlal  v16.4S, v12.4H, v14.4H
    smlal2 v18.4S, v12.8H, v14.8H
    smlal  v17.4S, v12.4H, v15.4H
    smlal2 v19.4S, v12.8H, v15.8H

    // --- Complete product 2: c₀ += a₁·γ₂, c₁ += a₁·b₀ ---
    smlal  v16.4S, v13.4H, v30.4H
    smlal2 v18.4S, v13.8H, v30.8H
    smlal  v17.4S, v13.4H, v14.4H
    smlal2 v19.4S, v13.8H, v14.8H

    sub counter, counter, #1
    cbnz counter, 1b

    // --- Final Montgomery reduction: reduce last iteration's accumulators ---
    uzp1    v6.8H, v16.8H, v18.8H
    uzp1    v7.8H, v17.8H, v19.8H

    mul     v6.8H,  v6.8H, v4.H[1]
    mul     v7.8H,  v7.8H, v4.H[1]

    smlal  v16.4S,  v6.4H, v4.H[0]
    smlal2 v18.4S,  v6.8H, v4.H[0]
    smlal  v17.4S,  v7.4H, v4.H[0]
    smlal2 v19.4S,  v7.8H, v4.H[0]

    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    // --- Store final interleaved [c₀, c₁] pair ---
    st2 { v6.8H,  v7.8H}, [des], #32

    // --- Epilogue: release register aliases and restore callee-saved registers ---
    .unreq    des
    .unreq    src1_0
    .unreq    src2_0
    .unreq    src2asy_0
    .unreq    src1_1
    .unreq    src2_1
    .unreq    src2asy_1
    .unreq    src1_2
    .unreq    src2_2
    .unreq    src2asy_2
    .unreq    src1_3
    .unreq    src2_3
    .unreq    src2asy_3
    .unreq    counter
    ldp x19, x20, [sp, #0*16]
    ldp x21, x22, [sp, #1*16]
    ldp x23, x24, [sp, #2*16]
    ldp x25, x26, [sp, #3*16]
    ldp x27, x28, [sp, #4*16]
    ldp  d8,  d9, [sp, #5*16]
    ldp d10, d11, [sp, #6*16]
    ldp d12, d13, [sp, #7*16]
    ldp d14, d15, [sp, #8*16]
    add sp, sp, #(9*16)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMAsymMulk3)

// =============================================================================
// MLKEMAsymMulk4 — Asymmetric basemul accumulation, k=4 (ML-KEM-1024)
// =============================================================================
//
// Computes r = Σᵢ₌₀³ a[i]⊗b[i×256..(i+1)×256-1]
// Each ⊗ is schoolbook multiplication in F_q[X]/(X²−ζ):
//   c₀ = a₀·b₀ + a₁·γ,  c₁ = a₀·b₁ + a₁·b₀  where γ = b₁·ζ
//
// Signature: void MLKEMAsymMulk4(int16_t *r, int16_t **a, int16_t *b, int16_t *c)
//   x0 (r):  output polynomial, 256 interleaved int16_t
//   x1 (a):  int16_t**, array of 4 pointers to source polynomials
//   x2 (b):  int16_t*, 4×256 contiguous coefficients
//   x3 (c):  int16_t*, 4×128 precomputed mulcache = b₁·ζ values
//
// Algorithm:
//   1. Load and deinterleave a[i], b[i] into even/odd coefficient halves
//   2. Schoolbook accumulate 4 products using smull/smlal (32-bit)
//   3. Montgomery-reduce accumulated 32-bit → 16-bit
//   4. Store interleaved [c₀, c₁] via st2
//   5. Repeat for 16 blocks (first unrolled, 15 in loop)
//
// Register allocation:
//   v0-v3:    polynomial 0 coefficients (a₀, a₁, b₀, b₁)
//   v4:       S[0]=Q, S[1]=Q^{-1} mod 2^16
//   v8-v11:   polynomial 1 coefficients
//   v12-v15:  polynomial 2 coefficients
//   v24-v27:  polynomial 3 coefficients
//   v16-v19:  32-bit accumulators [c₀_lo, c₁_lo, c₀_hi, c₁_hi]
//   v28-v31:  mulcache γ values for each of the 4 polynomial pairs
//
// Uses 4 pairs of source pointers and 4 mulcache pointers.
// Maximum register pressure variant — all 14 callee-saved registers used.
// =============================================================================
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMAsymMulk4)
AARCH64_PACIASP
    // --- Prologue: save callee-saved registers (x19-x28, d8-d15) ---
    sub sp, sp, #(9*16)
    stp x19, x20, [sp, #0*16]
    stp x21, x22, [sp, #1*16]
    stp x23, x24, [sp, #2*16]
    stp x25, x26, [sp, #3*16]
    stp x27, x28, [sp, #4*16]
    stp  d8,  d9, [sp, #5*16]
    stp d10, d11, [sp, #6*16]
    stp d12, d13, [sp, #7*16]
    stp d14, d15, [sp, #8*16]
    // --- Register aliases ---
    des       .req x11
    src1_0    .req x0
    src2_0    .req x1
    src2asy_0 .req x2
    src1_1    .req x7
    src2_1    .req x5
    src2asy_1 .req x6
    src1_2    .req x8
    src2_2    .req x9
    src2asy_2 .req x10
    src1_3    .req x12
    src2_3    .req x13
    src2asy_3 .req x14
    counter   .req x19

    // --- Setup: load 4 pointers from a[] and pack Q|Qprime into v4.H[0:1] ---
    add des, x0, #0
    ldp src1_0,src1_1, [x1]
    ldp src1_2,src1_3, [x1, #16]
    mov src2_0, x2
    mov src2asy_0, x3

    mov w4, #3329             // Q
    movk w4, #3327, lsl #16   // Qprime
    fmov s4, w4

    // --- Compute offsets for polynomial pairs 1, 2, 3 ---
    add     src2_1,    src2_0, #512*1
    add  src2asy_1, src2asy_0, #256*1

    add     src2_2,    src2_0, #512*2
    add  src2asy_2, src2asy_0, #256*2

    add     src2_3,    src2_0, #512*3
    add  src2asy_3, src2asy_0, #256*3

    // --- Load and deinterleave first block of a[0] and b[0] ---
    ldr q20, [src1_0, #0*16]
    ldr q21, [src1_0, #1*16]
    ldr q22, [src2_0, #0*16]
    ldr q23, [src2_0, #1*16]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    // --- uzp1/uzp2 deinterleave: a₀ in v0, a₁ in v1; b₀ in v2, b₁ in v3 ---
    uzp1  v0.8H, v20.8H, v21.8H
    uzp2  v1.8H, v20.8H, v21.8H
    uzp1  v2.8H, v22.8H, v23.8H
    uzp2  v3.8H, v22.8H, v23.8H

    // --- Load mulcache γ₀ = b₁·ζ for polynomial pair 0 ---
    ld1 {v28.8H}, [src2asy_0], #16

    // ---- Schoolbook product 0: c₀ = a₀·b₀, c₁ = a₀·b₁ (smull) ----
    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    // --- Complete product 0: c₀ += a₁·γ₀, c₁ += a₁·b₀; deinterleave a[1], b[1] ---
    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    // --- Load mulcache γ₁ for polynomial pair 1 ---
    ld1 {v29.8H}, [src2asy_1], #16

    // ---- Schoolbook product 1: c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    // Interleaved with loading a[2], b[2]
    smlal  v16.4S,  v8.4H, v10.4H
    ldr q20, [src1_2, #0*16]
    smlal2 v18.4S,  v8.8H, v10.8H
    ldr q21, [src1_2, #1*16]
    smlal  v17.4S,  v8.4H, v11.4H
    ldr q22, [src2_2, #0*16]
    smlal2 v19.4S,  v8.8H, v11.8H
    ldr q23, [src2_2, #1*16]

    add src1_2, src1_2, #32
    add src2_2, src2_2, #32

    // --- Complete product 1: c₀ += a₁·γ₁, c₁ += a₁·b₀; deinterleave a[2], b[2] ---
    smlal  v16.4S,  v9.4H, v29.4H
    uzp1 v12.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v9.8H, v29.8H
    uzp2 v13.8H, v20.8H, v21.8H
    smlal  v17.4S,  v9.4H, v10.4H
    uzp1 v14.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v9.8H, v10.8H
    uzp2 v15.8H, v22.8H, v23.8H

    // --- Load mulcache γ₂ for polynomial pair 2 ---
    ld1 {v30.8H}, [src2asy_2], #16

    // ---- Schoolbook product 2: c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    // Interleaved with loading a[3], b[3]
    smlal  v16.4S, v12.4H, v14.4H
    ldr q20, [src1_3, #0*16]
    smlal2 v18.4S, v12.8H, v14.8H
    ldr q21, [src1_3, #1*16]
    smlal  v17.4S, v12.4H, v15.4H
    ldr q22, [src2_3, #0*16]
    smlal2 v19.4S, v12.8H, v15.8H
    ldr q23, [src2_3, #1*16]

    add src1_3, src1_3, #32
    add src2_3, src2_3, #32

    // --- Complete product 2: c₀ += a₁·γ₂, c₁ += a₁·b₀; deinterleave a[3], b[3] ---
    smlal  v16.4S, v13.4H, v30.4H
    uzp1 v24.8H, v20.8H, v21.8H
    smlal2 v18.4S, v13.8H, v30.8H
    uzp2 v25.8H, v20.8H, v21.8H
    smlal  v17.4S, v13.4H, v14.4H
    uzp1 v26.8H, v22.8H, v23.8H
    smlal2 v19.4S, v13.8H, v14.8H
    uzp2 v27.8H, v22.8H, v23.8H

    // --- Load mulcache γ₃ for polynomial pair 3 ---
    ld1 {v31.8H}, [src2asy_3], #16

    // ---- Schoolbook product 3: c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    smlal  v16.4S, v24.4H, v26.4H
    smlal2 v18.4S, v24.8H, v26.8H
    smlal  v17.4S, v24.4H, v27.4H
    smlal2 v19.4S, v24.8H, v27.8H

    // --- Complete product 3: c₀ += a₁·γ₃, c₁ += a₁·b₀ ---
    smlal  v16.4S, v25.4H, v31.4H
    smlal2 v18.4S, v25.8H, v31.8H
    smlal  v17.4S, v25.4H, v26.4H
    smlal2 v19.4S, v25.8H, v26.8H

    // --- Software pipeline: 15 iterations with interleaved compute/load/store ---
    // Same interleaving pattern as k2/k3 but with k=4 polynomial products.
    // The 4-product schoolbook accumulation is the longest Phase C, so the
    // pipeline hides the most latency here. ld1 for mulcache values are issued
    // between smlal/smlal2 pairs to keep the load pipeline busy during compute.
    mov counter, #15
    1:

    // ---- Phase A: Montgomery reduction of accumulated 32-bit products → 16-bit ----
    ldr q20, [src1_0, #0*16]
    uzp1    v6.8H, v16.8H, v18.8H
    ldr q21, [src1_0, #1*16]
    uzp1    v7.8H, v17.8H, v19.8H

    ldr q22, [src2_0, #0*16]
    mul     v6.8H,  v6.8H, v4.H[1]
    ldr q23, [src2_0, #1*16]
    mul     v7.8H,  v7.8H, v4.H[1]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    // --- smlal correction + deinterleave next a[0], b[0] (load-use overlap) ---
    smlal  v16.4S,  v6.4H, v4.H[0]
    uzp1  v0.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v6.8H, v4.H[0]
    uzp2  v1.8H, v20.8H, v21.8H
    smlal  v17.4S,  v7.4H, v4.H[0]
    uzp1  v2.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v7.8H, v4.H[0]
    uzp2  v3.8H, v22.8H, v23.8H

    // --- Phase B: store reduced [c₀,c₁] and load mulcache for next product 0 ---
    ld1 {v28.8H}, [src2asy_0], #16
    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    st2 { v6.8H,  v7.8H}, [des], #32

    // ---- Phase C product 0: a[0]⊗b[0] ---- schoolbook c₀ = a₀·b₀, c₁ = a₀·b₁ ----
    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    // --- Complete product 0: c₀ += a₁·γ₀, c₁ += a₁·b₀; deinterleave a[1], b[1] ---
    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    ld1 {v29.8H}, [src2asy_1], #16

    // ---- Phase C product 1: a[1]⊗b[1] ---- c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    smlal  v16.4S,  v8.4H, v10.4H
    ldr q20, [src1_2, #0*16]
    smlal2 v18.4S,  v8.8H, v10.8H
    ldr q21, [src1_2, #1*16]
    smlal  v17.4S,  v8.4H, v11.4H
    ldr q22, [src2_2, #0*16]
    smlal2 v19.4S,  v8.8H, v11.8H
    ldr q23, [src2_2, #1*16]

    add src1_2, src1_2, #32
    add src2_2, src2_2, #32

    // --- Complete product 1: c₀ += a₁·γ₁, c₁ += a₁·b₀; deinterleave a[2], b[2] ---
    smlal  v16.4S,  v9.4H, v29.4H
    uzp1 v12.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v9.8H, v29.8H
    uzp2 v13.8H, v20.8H, v21.8H
    smlal  v17.4S,  v9.4H, v10.4H
    uzp1 v14.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v9.8H, v10.8H
    uzp2 v15.8H, v22.8H, v23.8H

    ld1 {v30.8H}, [src2asy_2], #16

    // ---- Phase C product 2: a[2]⊗b[2] ---- c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    smlal  v16.4S, v12.4H, v14.4H
    ldr q20, [src1_3, #0*16]
    smlal2 v18.4S, v12.8H, v14.8H
    ldr q21, [src1_3, #1*16]
    smlal  v17.4S, v12.4H, v15.4H
    ldr q22, [src2_3, #0*16]
    smlal2 v19.4S, v12.8H, v15.8H
    ldr q23, [src2_3, #1*16]

    add src1_3, src1_3, #32
    add src2_3, src2_3, #32

    // --- Complete product 2: c₀ += a₁·γ₂, c₁ += a₁·b₀; deinterleave a[3], b[3] ---
    smlal  v16.4S, v13.4H, v30.4H
    uzp1 v24.8H, v20.8H, v21.8H
    smlal2 v18.4S, v13.8H, v30.8H
    uzp2 v25.8H, v20.8H, v21.8H
    smlal  v17.4S, v13.4H, v14.4H
    uzp1 v26.8H, v22.8H, v23.8H
    smlal2 v19.4S, v13.8H, v14.8H
    uzp2 v27.8H, v22.8H, v23.8H

    ld1 {v31.8H}, [src2asy_3], #16

    // ---- Phase C product 3: a[3]⊗b[3] ---- c₀ += a₀·b₀, c₁ += a₀·b₁ ----
    smlal  v16.4S, v24.4H, v26.4H
    smlal2 v18.4S, v24.8H, v26.8H
    smlal  v17.4S, v24.4H, v27.4H
    smlal2 v19.4S, v24.8H, v27.8H

    // --- Complete product 3: c₀ += a₁·γ₃, c₁ += a₁·b₀ ---
    smlal  v16.4S, v25.4H, v31.4H
    smlal2 v18.4S, v25.8H, v31.8H
    smlal  v17.4S, v25.4H, v26.4H
    smlal2 v19.4S, v25.8H, v26.8H


    sub counter, counter, #1
    cbnz counter, 1b

    // --- Final Montgomery reduction: reduce last iteration's accumulators ---
    uzp1    v6.8H, v16.8H, v18.8H
    uzp1    v7.8H, v17.8H, v19.8H

    mul     v6.8H,  v6.8H, v4.H[1]
    mul     v7.8H,  v7.8H, v4.H[1]

    smlal  v16.4S,  v6.4H, v4.H[0]
    smlal2 v18.4S,  v6.8H, v4.H[0]
    smlal  v17.4S,  v7.4H, v4.H[0]
    smlal2 v19.4S,  v7.8H, v4.H[0]

    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    // --- Store final interleaved [c₀, c₁] pair ---
    st2 { v6.8H,  v7.8H}, [des], #32

    // --- Epilogue: release register aliases and restore callee-saved registers ---
    .unreq    des
    .unreq    src1_0
    .unreq    src2_0
    .unreq    src2asy_0
    .unreq    src1_1
    .unreq    src2_1
    .unreq    src2asy_1
    .unreq    src1_2
    .unreq    src2_2
    .unreq    src2asy_2
    .unreq    src1_3
    .unreq    src2_3
    .unreq    src2asy_3
    .unreq    counter
    ldp x19, x20, [sp, #0*16]
    ldp x21, x22, [sp, #1*16]
    ldp x23, x24, [sp, #2*16]
    ldp x25, x26, [sp, #3*16]
    ldp x27, x28, [sp, #4*16]
    ldp  d8,  d9, [sp, #5*16]
    ldp d10, d11, [sp, #6*16]
    ldp d12, d13, [sp, #7*16]
    ldp d14, d15, [sp, #8*16]
    add sp, sp, #(9*16)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMAsymMulk4)


// =============================================================================
// MLKEMAsymMulMont — Asymmetric Montgomery-form basemul dispatcher
// =============================================================================
//
// Same as MLKEMAsymMul but for inputs already in Montgomery domain.
// The Montgomery variants perform an additional Montgomery-to-normal conversion
// step after standard Montgomery reduction, converting the result from
// Montgomery form (×R mod Q) to normal form.
//
// Dispatches to MLKEMAsymMulMontk{2,3,4} based on k parameter.
// After dispatch, argument registers are reshuffled:
//   x0=r, x1=a, x2=b, x3=c (mulcache)
//
// Parameters:
//   x0: k (ML-KEM parameter: 2=ML-KEM-512, 3=ML-KEM-768, 4=ML-KEM-1024)
//   x1: r (output polynomial, 256 interleaved int16_t, normal form)
//   x2: a (int16_t*, k×256 contiguous coefficients in Montgomery form)
//   x3: b (int16_t*, k×256 contiguous coefficients)
//   x4: c (int16_t*, k×128 precomputed mulcache = b₁·ζ values)
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEMAsymMulMont)
    cmp     w0, #2
    b.eq    .Lasm_mont_k2
    cmp     w0, #3
    b.eq    .Lasm_mont_k3
    cmp     w0, #4
    b.eq    .Lasm_mont_k4
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMAsymMulMont)
.Lasm_mont_k2:
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    b       CRYPT_AARCH64_SYM(MLKEMAsymMulMontk2)
.Lasm_mont_k3:
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    b       CRYPT_AARCH64_SYM(MLKEMAsymMulMontk3)
.Lasm_mont_k4:
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    b       CRYPT_AARCH64_SYM(MLKEMAsymMulMontk4)

// =============================================================================
// MLKEMAsymMulMontk2 — Montgomery-form basemul accumulation, k=2 (ML-KEM-512)
// =============================================================================
//
// Same as MLKEMAsymMulk2 but input a is in Montgomery form (×R mod Q).
// After standard Montgomery reduction, an EXTRA sqrdmulh/mul/mls step converts
// the result from Montgomery form to normal form — this is the KEY difference.
//
// Signature: void MLKEMAsymMulMontk2(int16_t *r, int16_t *a, int16_t *b, int16_t *c)
//   x0 (r):  output polynomial, 256 interleaved int16_t (normal form)
//   x1 (a):  int16_t*, 2×256 contiguous coefficients (Montgomery form)
//   x2 (b):  int16_t*, 2×256 contiguous coefficients
//   x3 (c):  int16_t*, 2×128 precomputed mulcache = b₁·ζ values
//
// Algorithm:
//   1. Schoolbook accumulate 2 products using smull/smlal (32-bit)
//   2. Standard Montgomery reduction: uzp1 → mul Qinv → smlal Q → uzp2
//   3. MONTGOMERY-TO-NORMAL CONVERSION (extra step vs non-Mont):
//        sqrdmulh hi, result, RmodQ_hi   → hi ≈ (result × R^{-1}_hi) >> 15
//        mul      lo, result, RmodQ_lo   → lo = result × R^{-1}_lo
//        mls      lo, hi, Q              → lo = lo − hi × Q = normal form
//   4. Store interleaved [c₀, c₁] via st2
//
// Register allocation:
//   v0-v3:    polynomial 0 coefficients (a₀, a₁, b₀, b₁)
//   v4:       64-bit constant: [Q, Qprime, RmodQ_lo, RmodQ_hi]
//   v8-v11:   polynomial 1 coefficients
//   v16-v19:  32-bit accumulators [c₀_lo, c₁_lo, c₀_hi, c₁_hi]
//   v28-v29:  mulcache γ values for each of the 2 polynomial pairs
//
// Loop: 16 iterations (first unrolled, 15 in loop body)
// =============================================================================
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMAsymMulMontk2)
AARCH64_PACIASP
    sub sp, sp, #(9*16)
    stp x19, x20, [sp, #0*16]
    stp x21, x22, [sp, #1*16]
    stp x23, x24, [sp, #2*16]
    stp x25, x26, [sp, #3*16]
    stp x27, x28, [sp, #4*16]
    stp  d8,  d9, [sp, #5*16]
    stp d10, d11, [sp, #6*16]
    stp d12, d13, [sp, #7*16]
    stp d14, d15, [sp, #8*16]
    des       .req x11
    src1_0    .req x0
    src2_0    .req x1
    src2asy_0 .req x2
    src1_1    .req x4
    src2_1    .req x5
    src2asy_1 .req x6
    src1_2    .req x8
    src2_2    .req x9
    src2asy_2 .req x10
    src1_3    .req x12
    src2_3    .req x13
    src2asy_3 .req x14
    counter   .req x19

    add des, x0, #0
    mov src1_0, x1
    mov src2_0, x2
    mov src2asy_0, x3

    mov x4, #3329             // Q
    movk x4, #3327, lsl #16   // Qprime = -Q^{-1} mod 2^16
    movk x4, #64492, lsl #32  // RmodQ_lo = 64492 (-1044 in signed 16-bit)
    movk x4, #55260, lsl #48  // RmodQ_hi = 55260 (-10276 in signed 16-bit)
    fmov d4, x4

    // --- Compute offsets for polynomial pair 1 (b offset by 512, mulcache by 256) ---
    add     src1_1,    src1_0, #512*1
    add     src2_1,    src2_0, #512*1
    add  src2asy_1, src2asy_0, #256*1

    // --- Load first 8×16B of interleaved source polynomial [a0,a1] pairs ---
    ldr q20, [src1_0, #0*16]
    ldr q21, [src1_0, #1*16]
    ldr q22, [src2_0, #0*16]
    ldr q23, [src2_0, #1*16]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    // --- Extract even/odd coefficients from interleaved [a0,a1] pairs ---
    uzp1  v0.8H, v20.8H, v21.8H
    uzp2  v1.8H, v20.8H, v21.8H
    uzp1  v2.8H, v22.8H, v23.8H
    uzp2  v3.8H, v22.8H, v23.8H

    // --- Load mulcache gamma values for polynomial pair 0 ---
    ld1 {v28.8H}, [src2asy_0], #16

    // --- Schoolbook multiply: accumulate 2 products (32-bit) ---
    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    // --- Accumulate mulcache contribution + load polynomial pair 1 ---
    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    // --- Load mulcache gamma values for polynomial pair 1 ---
    ld1 {v29.8H}, [src2asy_1], #16

    // --- Accumulate polynomial pair 1 contributions ---
    smlal  v16.4S,  v8.4H, v10.4H
    smlal2 v18.4S,  v8.8H, v10.8H
    smlal  v17.4S,  v8.4H, v11.4H
    smlal2 v19.4S,  v8.8H, v11.8H

    smlal  v16.4S,  v9.4H, v29.4H
    smlal2 v18.4S,  v9.8H, v29.8H
    smlal  v17.4S,  v9.4H, v10.4H
    smlal2 v19.4S,  v9.8H, v10.8H

    // --- Loop: 15 remaining iterations (first iteration unrolled above) ---
    mov counter, #15
    1:

    // --- Montgomery reduction step 1: uzp1 low halves, multiply by Qprime ---
    uzp1    v6.8H, v16.8H, v18.8H
    uzp1    v7.8H, v17.8H, v19.8H

    mul     v6.8H,  v6.8H, v4.H[1]
    mul     v7.8H,  v7.8H, v4.H[1]

    // --- Montgomery reduction step 2: accumulate correction + load next src ---
    ldr q20, [src1_0, #0*16]
    smlal  v16.4S,  v6.4H, v4.H[0]
    ldr q21, [src1_0, #1*16]
    smlal2 v18.4S,  v6.8H, v4.H[0]
    ldr q22, [src2_0, #0*16]
    smlal  v17.4S,  v7.4H, v4.H[0]
    ldr q23, [src2_0, #1*16]
    smlal2 v19.4S,  v7.8H, v4.H[0]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    // --- Montgomery reduction step 3: uzp2 extract reduced halves ---
    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    // --- Montgomery-to-normal conversion: sqrdmulh/mul/mls ---
    uzp1  v0.8H, v20.8H, v21.8H
    sqrdmulh v16.8H,  v6.8H,  v4.H[3]
    uzp2  v1.8H, v20.8H, v21.8H
    sqrdmulh v17.8H,  v7.8H,  v4.H[3]

    uzp1  v2.8H, v22.8H, v23.8H
    mul       v6.8H,  v6.8H,  v4.H[2]
    uzp2  v3.8H, v22.8H, v23.8H
    mul       v7.8H,  v7.8H,  v4.H[2]

    mls       v6.8H, v16.8H,  v4.H[0]
    mls       v7.8H, v17.8H,  v4.H[0]

    // --- Store interleaved [c0, c1] result ---
    st2 { v6.8H,  v7.8H}, [des], #32

    // --- Load mulcache for next iteration ---
    ld1 {v28.8H}, [src2asy_0], #16

    // --- Schoolbook multiply for next iteration ---
    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    // --- Accumulate mulcache + load polynomial pair 1 ---
    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    ld1 {v29.8H}, [src2asy_1], #16

    // --- Accumulate polynomial pair 1 ---
    smlal  v16.4S,  v8.4H, v10.4H
    smlal2 v18.4S,  v8.8H, v10.8H
    smlal  v17.4S,  v8.4H, v11.4H
    smlal2 v19.4S,  v8.8H, v11.8H

    smlal  v16.4S,  v9.4H, v29.4H
    smlal2 v18.4S,  v9.8H, v29.8H
    smlal  v17.4S,  v9.4H, v10.4H
    smlal2 v19.4S,  v9.8H, v10.8H

    sub counter, counter, #1
    cbnz counter, 1b

    // --- Final iteration: Montgomery reduction without interleaved loads ---
    uzp1    v6.8H, v16.8H, v18.8H
    uzp1    v7.8H, v17.8H, v19.8H

    mul     v6.8H,  v6.8H, v4.H[1]
    mul     v7.8H,  v7.8H, v4.H[1]

    smlal  v16.4S,  v6.4H, v4.H[0]
    smlal2 v18.4S,  v6.8H, v4.H[0]
    smlal  v17.4S,  v7.4H, v4.H[0]
    smlal2 v19.4S,  v7.8H, v4.H[0]

    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    // --- Montgomery-to-normal conversion for final result ---
    sqrdmulh v16.8H,  v6.8H,  v4.H[3]
    sqrdmulh v17.8H,  v7.8H,  v4.H[3]

    mul       v6.8H,  v6.8H,  v4.H[2]
    mul       v7.8H,  v7.8H,  v4.H[2]

    mls       v6.8H, v16.8H,  v4.H[0]
    mls       v7.8H, v17.8H,  v4.H[0]

    st2 { v6.8H,  v7.8H}, [des], #32

    // --- Epilogue: restore registers and return ---
    .unreq    des
    .unreq    src1_0
    .unreq    src2_0
    .unreq    src2asy_0
    .unreq    src1_1
    .unreq    src2_1
    .unreq    src2asy_1
    .unreq    src1_2
    .unreq    src2_2
    .unreq    src2asy_2
    .unreq    src1_3
    .unreq    src2_3
    .unreq    src2asy_3
    .unreq    counter
    ldp x19, x20, [sp, #0*16]
    ldp x21, x22, [sp, #1*16]
    ldp x23, x24, [sp, #2*16]
    ldp x25, x26, [sp, #3*16]
    ldp x27, x28, [sp, #4*16]
    ldp  d8,  d9, [sp, #5*16]
    ldp d10, d11, [sp, #6*16]
    ldp d12, d13, [sp, #7*16]
    ldp d14, d15, [sp, #8*16]
    add sp, sp, #(9*16)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMAsymMulMontk2)

// =============================================================================
// MLKEMAsymMulMontk3 — Montgomery-form basemul accumulation, k=3 (ML-KEM-768)
// =============================================================================
//
// Same as MLKEMAsymMulk3 but input a is in Montgomery form (×R mod Q).
// After standard Montgomery reduction, an EXTRA sqrdmulh/mul/mls step converts
// the result from Montgomery form to normal form.
//
// Signature: void MLKEMAsymMulMontk3(int16_t *r, int16_t *a, int16_t *b, int16_t *c)
//   x0 (r):  output polynomial, 256 interleaved int16_t (normal form)
//   x1 (a):  int16_t*, 3×256 contiguous coefficients (Montgomery form)
//   x2 (b):  int16_t*, 3×256 contiguous coefficients
//   x3 (c):  int16_t*, 3×128 precomputed mulcache = b₁·ζ values
//
// Algorithm:
//   1. Schoolbook accumulate 3 products using smull/smlal (32-bit)
//   2. Standard Montgomery reduction: uzp1 → mul Qinv → smlal Q → uzp2
//   3. MONTGOMERY-TO-NORMAL CONVERSION: sqrdmulh/mul/mls with RmodQ constants
//   4. Store interleaved [c₀, c₁] via st2
//
// Register allocation:
//   v0-v3:    polynomial 0 coefficients
//   v4:       64-bit constant: [Q, Qprime, RmodQ_lo, RmodQ_hi]
//   v8-v11:   polynomial 1 coefficients
//   v12-v15:  polynomial 2 coefficients
//   v16-v19:  32-bit accumulators
//   v28-v30:  mulcache γ values for each of the 3 polynomial pairs
// =============================================================================
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMAsymMulMontk3)
AARCH64_PACIASP
    sub sp, sp, #(9*16)
    stp x19, x20, [sp, #0*16]
    stp x21, x22, [sp, #1*16]
    stp x23, x24, [sp, #2*16]
    stp x25, x26, [sp, #3*16]
    stp x27, x28, [sp, #4*16]
    stp  d8,  d9, [sp, #5*16]
    stp d10, d11, [sp, #6*16]
    stp d12, d13, [sp, #7*16]
    stp d14, d15, [sp, #8*16]
    des       .req x11
    src1_0    .req x0
    src2_0    .req x1
    src2asy_0 .req x2
    src1_1    .req x4
    src2_1    .req x5
    src2asy_1 .req x6
    src1_2    .req x8
    src2_2    .req x9
    src2asy_2 .req x10
    src1_3    .req x12
    src2_3    .req x13
    src2asy_3 .req x14
    counter   .req x19

    add des, x0, #0
    mov src1_0, x1
    mov src2_0, x2
    mov src2asy_0, x3

    mov x4, #3329             // Q
    movk x4, #3327, lsl #16   // Qprime
    movk x4, #64492, lsl #32  // RmodQ = -1044
    movk x4, #55260, lsl #48  // RmodQ_hi = -10276
    fmov d4, x4


    add     src1_1,    src1_0, #512*1
    add     src2_1,    src2_0, #512*1
    add  src2asy_1, src2asy_0, #256*1

    add     src1_2,    src1_0, #512*2
    add     src2_2,    src2_0, #512*2
    add  src2asy_2, src2asy_0, #256*2

    ldr q20, [src1_0, #0*16]
    ldr q21, [src1_0, #1*16]
    ldr q22, [src2_0, #0*16]
    ldr q23, [src2_0, #1*16]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    uzp1  v0.8H, v20.8H, v21.8H
    uzp2  v1.8H, v20.8H, v21.8H
    uzp1  v2.8H, v22.8H, v23.8H
    uzp2  v3.8H, v22.8H, v23.8H

    ld1 {v28.8H}, [src2asy_0], #16

    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    ld1 {v29.8H}, [src2asy_1], #16

    smlal  v16.4S,  v8.4H, v10.4H
    ldr q20, [src1_2, #0*16]
    smlal2 v18.4S,  v8.8H, v10.8H
    ldr q21, [src1_2, #1*16]
    smlal  v17.4S,  v8.4H, v11.4H
    ldr q22, [src2_2, #0*16]
    smlal2 v19.4S,  v8.8H, v11.8H
    ldr q23, [src2_2, #1*16]

    add src1_2, src1_2, #32
    add src2_2, src2_2, #32

    smlal  v16.4S,  v9.4H, v29.4H
    uzp1 v12.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v9.8H, v29.8H
    uzp2 v13.8H, v20.8H, v21.8H
    smlal  v17.4S,  v9.4H, v10.4H
    uzp1 v14.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v9.8H, v10.8H
    uzp2 v15.8H, v22.8H, v23.8H

    ld1 {v30.8H}, [src2asy_2], #16

    smlal  v16.4S, v12.4H, v14.4H
    smlal2 v18.4S, v12.8H, v14.8H
    smlal  v17.4S, v12.4H, v15.4H
    smlal2 v19.4S, v12.8H, v15.8H

    smlal  v16.4S, v13.4H, v30.4H
    smlal2 v18.4S, v13.8H, v30.8H
    smlal  v17.4S, v13.4H, v14.4H
    smlal2 v19.4S, v13.8H, v14.8H


    mov counter, #15
    1:

    uzp1    v6.8H, v16.8H, v18.8H
    uzp1    v7.8H, v17.8H, v19.8H

    mul     v6.8H,  v6.8H, v4.H[1]
    mul     v7.8H,  v7.8H, v4.H[1]

    ldr q20, [src1_0, #0*16]
    smlal  v16.4S,  v6.4H, v4.H[0]
    ldr q21, [src1_0, #1*16]
    smlal2 v18.4S,  v6.8H, v4.H[0]
    ldr q22, [src2_0, #0*16]
    smlal  v17.4S,  v7.4H, v4.H[0]
    ldr q23, [src2_0, #1*16]
    smlal2 v19.4S,  v7.8H, v4.H[0]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    uzp1  v0.8H, v20.8H, v21.8H
    sqrdmulh v16.8H,  v6.8H,  v4.H[3]
    uzp2  v1.8H, v20.8H, v21.8H
    sqrdmulh v17.8H,  v7.8H,  v4.H[3]

    uzp1  v2.8H, v22.8H, v23.8H
    mul       v6.8H,  v6.8H,  v4.H[2]
    uzp2  v3.8H, v22.8H, v23.8H
    mul       v7.8H,  v7.8H,  v4.H[2]

    mls       v6.8H, v16.8H,  v4.H[0]
    mls       v7.8H, v17.8H,  v4.H[0]

    st2 { v6.8H,  v7.8H}, [des], #32

    ld1 {v28.8H}, [src2asy_0], #16

    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    ld1 {v29.8H}, [src2asy_1], #16

    smlal  v16.4S,  v8.4H, v10.4H
    ldr q20, [src1_2, #0*16]
    smlal2 v18.4S,  v8.8H, v10.8H
    ldr q21, [src1_2, #1*16]
    smlal  v17.4S,  v8.4H, v11.4H
    ldr q22, [src2_2, #0*16]
    smlal2 v19.4S,  v8.8H, v11.8H
    ldr q23, [src2_2, #1*16]

    add src1_2, src1_2, #32
    add src2_2, src2_2, #32

    smlal  v16.4S,  v9.4H, v29.4H
    uzp1 v12.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v9.8H, v29.8H
    uzp2 v13.8H, v20.8H, v21.8H
    smlal  v17.4S,  v9.4H, v10.4H
    uzp1 v14.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v9.8H, v10.8H
    uzp2 v15.8H, v22.8H, v23.8H

    ld1 {v30.8H}, [src2asy_2], #16

    smlal  v16.4S, v12.4H, v14.4H
    smlal2 v18.4S, v12.8H, v14.8H
    smlal  v17.4S, v12.4H, v15.4H
    smlal2 v19.4S, v12.8H, v15.8H

    smlal  v16.4S, v13.4H, v30.4H
    smlal2 v18.4S, v13.8H, v30.8H
    smlal  v17.4S, v13.4H, v14.4H
    smlal2 v19.4S, v13.8H, v14.8H

    sub counter, counter, #1
    cbnz counter, 1b

    uzp1    v6.8H, v16.8H, v18.8H
    uzp1    v7.8H, v17.8H, v19.8H

    mul     v6.8H,  v6.8H, v4.H[1]
    mul     v7.8H,  v7.8H, v4.H[1]

    smlal  v16.4S,  v6.4H, v4.H[0]
    smlal2 v18.4S,  v6.8H, v4.H[0]
    smlal  v17.4S,  v7.4H, v4.H[0]
    smlal2 v19.4S,  v7.8H, v4.H[0]

    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    sqrdmulh v16.8H,  v6.8H,  v4.H[3]
    sqrdmulh v17.8H,  v7.8H,  v4.H[3]

    mul       v6.8H,  v6.8H,  v4.H[2]
    mul       v7.8H,  v7.8H,  v4.H[2]

    mls       v6.8H, v16.8H,  v4.H[0]
    mls       v7.8H, v17.8H,  v4.H[0]

    st2 { v6.8H,  v7.8H}, [des], #32

    .unreq    des
    .unreq    src1_0
    .unreq    src2_0
    .unreq    src2asy_0
    .unreq    src1_1
    .unreq    src2_1
    .unreq    src2asy_1
    .unreq    src1_2
    .unreq    src2_2
    .unreq    src2asy_2
    .unreq    src1_3
    .unreq    src2_3
    .unreq    src2asy_3
    .unreq    counter
    ldp x19, x20, [sp, #0*16]
    ldp x21, x22, [sp, #1*16]
    ldp x23, x24, [sp, #2*16]
    ldp x25, x26, [sp, #3*16]
    ldp x27, x28, [sp, #4*16]
    ldp  d8,  d9, [sp, #5*16]
    ldp d10, d11, [sp, #6*16]
    ldp d12, d13, [sp, #7*16]
    ldp d14, d15, [sp, #8*16]
    add sp, sp, #(9*16)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMAsymMulMontk3)

// =============================================================================
// MLKEMAsymMulMontk4 — Montgomery-form basemul accumulation, k=4 (ML-KEM-1024)
// =============================================================================
//
// Same as MLKEMAsymMulk4 but input a is in Montgomery form (×R mod Q).
// After standard Montgomery reduction, an EXTRA sqrdmulh/mul/mls step converts
// the result from Montgomery form to normal form.
//
// Signature: void MLKEMAsymMulMontk4(int16_t *r, int16_t *a, int16_t *b, int16_t *c)
//   x0 (r):  output polynomial, 256 interleaved int16_t (normal form)
//   x1 (a):  int16_t*, 4×256 contiguous coefficients (Montgomery form)
//   x2 (b):  int16_t*, 4×256 contiguous coefficients
//   x3 (c):  int16_t*, 4×128 precomputed mulcache = b₁·ζ values
//
// Algorithm:
//   1. Schoolbook accumulate 4 products using smull/smlal (32-bit)
//   2. Standard Montgomery reduction: uzp1 → mul Qinv → smlal Q → uzp2
//   3. MONTGOMERY-TO-NORMAL CONVERSION: sqrdmulh/mul/mls with RmodQ constants
//   4. Store interleaved [c₀, c₁] via st2
//
// Register allocation:
//   v0-v3:    polynomial 0 coefficients
//   v4:       64-bit constant: [Q, Qprime, RmodQ_lo, RmodQ_hi]
//   v8-v11:   polynomial 1 coefficients
//   v12-v15:  polynomial 2 coefficients
//   v24-v27:  polynomial 3 coefficients
//   v16-v19:  32-bit accumulators
//   v28-v31:  mulcache γ values for each of the 4 polynomial pairs
// =============================================================================
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMAsymMulMontk4)
AARCH64_PACIASP
    sub sp, sp, #(9*16)
    stp x19, x20, [sp, #0*16]
    stp x21, x22, [sp, #1*16]
    stp x23, x24, [sp, #2*16]
    stp x25, x26, [sp, #3*16]
    stp x27, x28, [sp, #4*16]
    stp  d8,  d9, [sp, #5*16]
    stp d10, d11, [sp, #6*16]
    stp d12, d13, [sp, #7*16]
    stp d14, d15, [sp, #8*16]
    des       .req x11
    src1_0    .req x0
    src2_0    .req x1
    src2asy_0 .req x2
    src1_1    .req x4
    src2_1    .req x5
    src2asy_1 .req x6
    src1_2    .req x8
    src2_2    .req x9
    src2asy_2 .req x10
    src1_3    .req x12
    src2_3    .req x13
    src2asy_3 .req x14
    counter   .req x19

    add des, x0, #0
    mov src1_0, x1
    mov src2_0, x2
    mov src2asy_0, x3

    mov x4, #3329             // Q
    movk x4, #3327, lsl #16   // Qprime
    movk x4, #64492, lsl #32  // RmodQ = -1044
    movk x4, #55260, lsl #48  // RmodQ_hi = -10276
    fmov d4, x4


    add     src1_1,    src1_0, #512*1
    add     src2_1,    src2_0, #512*1
    add  src2asy_1, src2asy_0, #256*1

    add     src1_2,    src1_0, #512*2
    add     src2_2,    src2_0, #512*2
    add  src2asy_2, src2asy_0, #256*2

    add     src1_3,    src1_0, #512*3
    add     src2_3,    src2_0, #512*3
    add  src2asy_3, src2asy_0, #256*3

    ldr q20, [src1_0, #0*16]
    ldr q21, [src1_0, #1*16]
    ldr q22, [src2_0, #0*16]
    ldr q23, [src2_0, #1*16]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    uzp1  v0.8H, v20.8H, v21.8H
    uzp2  v1.8H, v20.8H, v21.8H
    uzp1  v2.8H, v22.8H, v23.8H
    uzp2  v3.8H, v22.8H, v23.8H

    ld1 {v28.8H}, [src2asy_0], #16

    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    ld1 {v29.8H}, [src2asy_1], #16

    smlal  v16.4S,  v8.4H, v10.4H
    ldr q20, [src1_2, #0*16]
    smlal2 v18.4S,  v8.8H, v10.8H
    ldr q21, [src1_2, #1*16]
    smlal  v17.4S,  v8.4H, v11.4H
    ldr q22, [src2_2, #0*16]
    smlal2 v19.4S,  v8.8H, v11.8H
    ldr q23, [src2_2, #1*16]

    add src1_2, src1_2, #32
    add src2_2, src2_2, #32

    smlal  v16.4S,  v9.4H, v29.4H
    uzp1 v12.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v9.8H, v29.8H
    uzp2 v13.8H, v20.8H, v21.8H
    smlal  v17.4S,  v9.4H, v10.4H
    uzp1 v14.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v9.8H, v10.8H
    uzp2 v15.8H, v22.8H, v23.8H

    ld1 {v30.8H}, [src2asy_2], #16

    smlal  v16.4S, v12.4H, v14.4H
    ldr q20, [src1_3, #0*16]
    smlal2 v18.4S, v12.8H, v14.8H
    ldr q21, [src1_3, #1*16]
    smlal  v17.4S, v12.4H, v15.4H
    ldr q22, [src2_3, #0*16]
    smlal2 v19.4S, v12.8H, v15.8H
    ldr q23, [src2_3, #1*16]

    add src1_3, src1_3, #32
    add src2_3, src2_3, #32

    smlal  v16.4S, v13.4H, v30.4H
    uzp1 v24.8H, v20.8H, v21.8H
    smlal2 v18.4S, v13.8H, v30.8H
    uzp2 v25.8H, v20.8H, v21.8H
    smlal  v17.4S, v13.4H, v14.4H
    uzp1 v26.8H, v22.8H, v23.8H
    smlal2 v19.4S, v13.8H, v14.8H
    uzp2 v27.8H, v22.8H, v23.8H

    ld1 {v31.8H}, [src2asy_3], #16

    smlal  v16.4S, v24.4H, v26.4H
    smlal2 v18.4S, v24.8H, v26.8H
    smlal  v17.4S, v24.4H, v27.4H
    smlal2 v19.4S, v24.8H, v27.8H

    smlal  v16.4S, v25.4H, v31.4H
    smlal2 v18.4S, v25.8H, v31.8H
    smlal  v17.4S, v25.4H, v26.4H
    smlal2 v19.4S, v25.8H, v26.8H


    mov counter, #15
    1:

    uzp1    v6.8H, v16.8H, v18.8H
    uzp1    v7.8H, v17.8H, v19.8H

    mul     v6.8H,  v6.8H, v4.H[1]
    mul     v7.8H,  v7.8H, v4.H[1]

    ldr q20, [src1_0, #0*16]
    smlal  v16.4S,  v6.4H, v4.H[0]
    ldr q21, [src1_0, #1*16]
    smlal2 v18.4S,  v6.8H, v4.H[0]
    ldr q22, [src2_0, #0*16]
    smlal  v17.4S,  v7.4H, v4.H[0]
    ldr q23, [src2_0, #1*16]
    smlal2 v19.4S,  v7.8H, v4.H[0]

    add src1_0, src1_0, #32
    add src2_0, src2_0, #32

    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    uzp1  v0.8H, v20.8H, v21.8H
    sqrdmulh v16.8H,  v6.8H,  v4.H[3]
    uzp2  v1.8H, v20.8H, v21.8H
    sqrdmulh v17.8H,  v7.8H,  v4.H[3]

    uzp1  v2.8H, v22.8H, v23.8H
    mul       v6.8H,  v6.8H,  v4.H[2]
    uzp2  v3.8H, v22.8H, v23.8H
    mul       v7.8H,  v7.8H,  v4.H[2]

    mls       v6.8H, v16.8H,  v4.H[0]
    mls       v7.8H, v17.8H,  v4.H[0]

    st2 { v6.8H,  v7.8H}, [des], #32

    ld1 {v28.8H}, [src2asy_0], #16

    smull  v16.4S,  v0.4H,  v2.4H
    ldr q20, [src1_1, #0*16]
    smull2 v18.4S,  v0.8H,  v2.8H
    ldr q21, [src1_1, #1*16]
    smull  v17.4S,  v0.4H,  v3.4H
    ldr q22, [src2_1, #0*16]
    smull2 v19.4S,  v0.8H,  v3.8H
    ldr q23, [src2_1, #1*16]

    add src1_1, src1_1, #32
    add src2_1, src2_1, #32

    smlal  v16.4S,  v1.4H, v28.4H
    uzp1  v8.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v1.8H, v28.8H
    uzp2  v9.8H, v20.8H, v21.8H
    smlal  v17.4S,  v1.4H,  v2.4H
    uzp1 v10.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v1.8H,  v2.8H
    uzp2 v11.8H, v22.8H, v23.8H

    ld1 {v29.8H}, [src2asy_1], #16

    smlal  v16.4S,  v8.4H, v10.4H
    ldr q20, [src1_2, #0*16]
    smlal2 v18.4S,  v8.8H, v10.8H
    ldr q21, [src1_2, #1*16]
    smlal  v17.4S,  v8.4H, v11.4H
    ldr q22, [src2_2, #0*16]
    smlal2 v19.4S,  v8.8H, v11.8H
    ldr q23, [src2_2, #1*16]

    add src1_2, src1_2, #32
    add src2_2, src2_2, #32

    smlal  v16.4S,  v9.4H, v29.4H
    uzp1 v12.8H, v20.8H, v21.8H
    smlal2 v18.4S,  v9.8H, v29.8H
    uzp2 v13.8H, v20.8H, v21.8H
    smlal  v17.4S,  v9.4H, v10.4H
    uzp1 v14.8H, v22.8H, v23.8H
    smlal2 v19.4S,  v9.8H, v10.8H
    uzp2 v15.8H, v22.8H, v23.8H

    ld1 {v30.8H}, [src2asy_2], #16

    smlal  v16.4S, v12.4H, v14.4H
    ldr q20, [src1_3, #0*16]
    smlal2 v18.4S, v12.8H, v14.8H
    ldr q21, [src1_3, #1*16]
    smlal  v17.4S, v12.4H, v15.4H
    ldr q22, [src2_3, #0*16]
    smlal2 v19.4S, v12.8H, v15.8H
    ldr q23, [src2_3, #1*16]

    add src1_3, src1_3, #32
    add src2_3, src2_3, #32

    smlal  v16.4S, v13.4H, v30.4H
    uzp1 v24.8H, v20.8H, v21.8H
    smlal2 v18.4S, v13.8H, v30.8H
    uzp2 v25.8H, v20.8H, v21.8H
    smlal  v17.4S, v13.4H, v14.4H
    uzp1 v26.8H, v22.8H, v23.8H
    smlal2 v19.4S, v13.8H, v14.8H
    uzp2 v27.8H, v22.8H, v23.8H

    ld1 {v31.8H}, [src2asy_3], #16

    smlal  v16.4S, v24.4H, v26.4H
    smlal2 v18.4S, v24.8H, v26.8H
    smlal  v17.4S, v24.4H, v27.4H
    smlal2 v19.4S, v24.8H, v27.8H

    smlal  v16.4S, v25.4H, v31.4H
    smlal2 v18.4S, v25.8H, v31.8H
    smlal  v17.4S, v25.4H, v26.4H
    smlal2 v19.4S, v25.8H, v26.8H

    sub counter, counter, #1
    cbnz counter, 1b

    uzp1    v6.8H, v16.8H, v18.8H
    uzp1    v7.8H, v17.8H, v19.8H

    mul     v6.8H,  v6.8H, v4.H[1]
    mul     v7.8H,  v7.8H, v4.H[1]

    smlal  v16.4S,  v6.4H, v4.H[0]
    smlal2 v18.4S,  v6.8H, v4.H[0]
    smlal  v17.4S,  v7.4H, v4.H[0]
    smlal2 v19.4S,  v7.8H, v4.H[0]

    uzp2    v6.8H, v16.8H, v18.8H
    uzp2    v7.8H, v17.8H, v19.8H

    sqrdmulh v16.8H,  v6.8H,  v4.H[3]
    sqrdmulh v17.8H,  v7.8H,  v4.H[3]

    mul       v6.8H,  v6.8H,  v4.H[2]
    mul       v7.8H,  v7.8H,  v4.H[2]

    mls       v6.8H, v16.8H,  v4.H[0]
    mls       v7.8H, v17.8H,  v4.H[0]

    st2 { v6.8H,  v7.8H}, [des], #32

    .unreq    des
    .unreq    src1_0
    .unreq    src2_0
    .unreq    src2asy_0
    .unreq    src1_1
    .unreq    src2_1
    .unreq    src2asy_1
    .unreq    src1_2
    .unreq    src2_2
    .unreq    src2asy_2
    .unreq    src1_3
    .unreq    src2_3
    .unreq    src2asy_3
    .unreq    counter
    ldp x19, x20, [sp, #0*16]
    ldp x21, x22, [sp, #1*16]
    ldp x23, x24, [sp, #2*16]
    ldp x25, x26, [sp, #3*16]
    ldp x27, x28, [sp, #4*16]
    ldp  d8,  d9, [sp, #5*16]
    ldp d10, d11, [sp, #6*16]
    ldp d12, d13, [sp, #7*16]
    ldp d14, d15, [sp, #8*16]
    add sp, sp, #(9*16)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMAsymMulMontk4)
#endif
