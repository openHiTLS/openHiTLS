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
 * ML-KEM Polynomial Arithmetic — ARMv8 NEON Implementation
 * ============================================================================
 *
 * References:
 *   [NeonNTT]  Becker, Hwang, Kannwischer, Yang, Yang.
 *              "Neon NTT: Faster Dilithium, Kyber, and Saber on Cortex-A72
 *              and Apple M1." https://eprint.iacr.org/2021/986
 *   [FIPS203]  NIST FIPS 203 — ML-KEM Standard.
 *
 * This file implements polynomial-level operations used by ML-KEM, operating
 * on polynomials in R_q = Z_q[X]/(X^256 + 1), q = 3329.
 *
 * Barrett Reduction Pattern (used in AddReduce, SubReduce, Add2Reduce):
 *   For reducing a ∈ [-2q, 2q] modulo Q = 3329:
 *     sqdmulh  t.8H, a.8H, M.H[0]    // t = (a × M × 2) >> 16, M = 25519
 *     srshr    t.8H, t.8H, #11        // t = round(t >> 11) ≈ round(a / Q)
 *     mls      a.8H, t.8H, Q.H[0]    // a = a − t × Q
 *   Result is in [−⌊Q/2⌋, ⌊Q/2⌋], not necessarily canonical.
 *
 * Unsigned Canonical Reduction (MLKEMPolyReduce):
 *   Barrett reduction followed by conditional correction:
 *     sshr    t.8H, a.8H, #15        // t = sign extension (0x0000 or 0xFFFF)
 *     and     t.16B, Q.16B, t.16B    // t = (a < 0) ? Q : 0
 *     add     a.8H, a.8H, t.8H      // a = a + t → result in [0, Q)
 *
 * Functions:
 *   MLKEMPolyAddReduce(k, r, e)        — r[i] += e[i] mod Q, for i in 0..k-1
 *   MLKEMSubReduce(r, b)               — r -= b mod Q
 *   MLKEMAdd2Reduce(r, b, d)           — r += b + d mod Q
 *   MLKEMPolyVecReduce(k, r)           — reduce r[i] to [0, Q), for i in 0..k-1
 *   PolyVectoBytes(k, r, a)            — encode k polys to byte arrays (12-bit packing)
 *   MLKEMPolyINTTtoMont(k, r)          — compute INTT for k polynomials
 *   MLKEMPolyCBDEta(eta, r, buf)       — CBD sampling (dispatches to CBD2 or CBD3)
 *   PackCipherText(k, c1len, ct, t, c2)— pack ciphertext (compress + encode)
 *   PolyCompress(k, r, a)              — compress to 4 or 5 bits per coefficient
 *   PolyVecCompress(k, r, a)           — compress to 10 or 11 bits per coefficient
 *   MLKEMPolyCompress1(r, a)           — 1-bit compression
 *   MLKEMRejUniform(r, buf)            — rejection sampling for matrix generation
 * ============================================================================
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MLKEM

#include "crypt_arm.h"
CRYPT_AARCH64_ARCH_BASE

CRYPT_AARCH64_FUNC_START(MLKEMPolyAddReduce)
// =============================================================================
// MLKEMPolyAddReduce — Vector polynomial addition with reduction
// =============================================================================
// Computes: for i in 0..k-1: r[i] = (r[i] + e[i]) mod Q
//
// Arguments:
//   x0 = k  (number of polynomials, ML-KEM dimension: 2, 3, or 4)
//   x1 = r  (int16_t** — array of pointers to destination polynomials)
//   x2 = e  (int16_t** — array of pointers to source polynomials)
//
// Implementation: simple k-loop dispatching to MLKEMAddReduce for each pair.
// =============================================================================
AARCH64_PACIASP
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x29, sp
    mov     w19, w0
    mov     x20, x1
    mov     x21, x2
    cbz     w19, .Lpolyaddreduce_done
    mov     w22, #0
.Lpolyaddreduce_loop:
    ldr     x0, [x20, x22, lsl #3]
    ldr     x1, [x21, x22, lsl #3]
    bl      CRYPT_AARCH64_SYM(MLKEMAddReduce)
    add     w22, w22, #1
    cmp     w22, w19
    b.lo    .Lpolyaddreduce_loop
.Lpolyaddreduce_done:
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMPolyAddReduce)

// ========== Polynomial Addition with Modular Reduction ==========
// Computes c = (a + b) mod Q where Q = 3329
// Uses Barrett reduction for efficient modular arithmetic
// Processes 256 coefficients (polynomial degree n-1) in parallel using NEON
// (from NEON-NTT paper, Section 4.1 - Barrett reduction)
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMAddReduce)
AARCH64_PACIASP
    // --- Setup: load Q=3329 and Barrett constant M=25519 ---
    mov w4, #3329    // Q = 3329 (ML-KEM modulus)
    mov w5, #25519   // Barrett constant: approx threshold

    add x2, x0, #0   // x2 = r (alias for dest pointer)

    // --- Broadcast constants to NEON vector lanes ---
    dup v0.8H, w4    // v0 = Q broadcast to 8 lanes
    dup v1.8H, w5    // v1 = M broadcast to 8 lanes

    // --- Prologue: load 32 coefficients from e[] and r[], compute r+e ---
    ld1 {v24.8H, v25.8H, v26.8H, v27.8H}, [x1], #64
    ld1 {v28.8H, v29.8H, v30.8H, v31.8H}, [x1], #64
    ld1 {v16.8H, v17.8H, v18.8H, v19.8H}, [x2], #64
    ld1 {v20.8H, v21.8H, v22.8H, v23.8H}, [x2], #64

    // --- Compute polynomial addition: sum = r + e ---
    add  v4.8H, v16.8H, v24.8H
    add  v5.8H, v17.8H, v25.8H
    add  v6.8H, v18.8H, v26.8H
    add  v7.8H, v19.8H, v27.8H

    add v16.8H, v20.8H, v28.8H
    add v17.8H, v21.8H, v29.8H
    add v18.8H, v22.8H, v30.8H
    add v19.8H, v23.8H, v31.8H

    // --- Barrett reduction (first pair, v4-v7): sqdmulh + srshr + mls ---
    // Full detail: t = (a * M * 2) >> 16 via sqdmulh, then t = round(t >> 11) via srshr,
    // then a = a - t*Q via mls. M=25519, Q=3329. Result in [-Q, Q].
    sqdmulh v20.8H, v4.8H, v1.h[0]
    sqdmulh v21.8H, v5.8H, v1.h[0]
    sqdmulh v22.8H, v6.8H, v1.h[0]
    sqdmulh v23.8H, v7.8H, v1.h[0]
    srshr   v20.8H, v20.8H, #11
    srshr   v21.8H, v21.8H, #11
    srshr   v22.8H, v22.8H, #11
    srshr   v23.8H, v23.8H, #11
    mls     v4.8H, v20.8H, v0.h[0]
    mls     v5.8H, v21.8H, v0.h[0]
    mls     v6.8H, v22.8H, v0.h[0]
    mls     v7.8H, v23.8H, v0.h[0]

    // --- Barrett reduction (second pair, v16-v19) ---
    sqdmulh v24.8H, v16.8H, v1.h[0]
    sqdmulh v25.8H, v17.8H, v1.h[0]
    sqdmulh v26.8H, v18.8H, v1.h[0]
    sqdmulh v27.8H, v19.8H, v1.h[0]
    srshr   v24.8H, v24.8H, #11
    srshr   v25.8H, v25.8H, #11
    srshr   v26.8H, v26.8H, #11
    srshr   v27.8H, v27.8H, #11
    mls     v16.8H, v24.8H, v0.h[0]
    mls     v17.8H, v25.8H, v0.h[0]
    mls     v18.8H, v26.8H, v0.h[0]
    mls     v19.8H, v27.8H, v0.h[0]

    // --- Main loop: 3 iterations × 32 coefficients = 96, plus prologue 32 = 128 pairs = 256 total ---
    mov x15, #3
    1:

    // --- Store previous results, load next batch ---
    st1 { v4.8H,  v5.8H,  v6.8H,  v7.8H}, [x0], #64
    ld1 {v24.8H, v25.8H, v26.8H, v27.8H}, [x1], #64
    st1 {v16.8H, v17.8H, v18.8H, v19.8H}, [x0], #64
    ld1 {v28.8H, v29.8H, v30.8H, v31.8H}, [x1], #64
    ld1 {v16.8H, v17.8H, v18.8H, v19.8H}, [x2], #64
    ld1 {v20.8H, v21.8H, v22.8H, v23.8H}, [x2], #64

    // --- Add: sum = r + e ---
    add  v4.8H, v16.8H, v24.8H
    add  v5.8H, v17.8H, v25.8H
    add  v6.8H, v18.8H, v26.8H
    add  v7.8H, v19.8H, v27.8H

    add v16.8H, v20.8H, v28.8H
    add v17.8H, v21.8H, v29.8H
    add v18.8H, v22.8H, v30.8H
    add v19.8H, v23.8H, v31.8H

    // --- Barrett reduction (v4-v7) ---
    sqdmulh v20.8H, v4.8H, v1.h[0]
    sqdmulh v21.8H, v5.8H, v1.h[0]
    sqdmulh v22.8H, v6.8H, v1.h[0]
    sqdmulh v23.8H, v7.8H, v1.h[0]
    srshr   v20.8H, v20.8H, #11
    srshr   v21.8H, v21.8H, #11
    srshr   v22.8H, v22.8H, #11
    srshr   v23.8H, v23.8H, #11
    mls     v4.8H, v20.8H, v0.h[0]
    mls     v5.8H, v21.8H, v0.h[0]
    mls     v6.8H, v22.8H, v0.h[0]
    mls     v7.8H, v23.8H, v0.h[0]

    // --- Barrett reduction (v16-v19) ---
    sqdmulh v24.8H, v16.8H, v1.h[0]
    sqdmulh v25.8H, v17.8H, v1.h[0]
    sqdmulh v26.8H, v18.8H, v1.h[0]
    sqdmulh v27.8H, v19.8H, v1.h[0]
    srshr   v24.8H, v24.8H, #11
    srshr   v25.8H, v25.8H, #11
    srshr   v26.8H, v26.8H, #11
    srshr   v27.8H, v27.8H, #11
    mls     v16.8H, v24.8H, v0.h[0]
    mls     v17.8H, v25.8H, v0.h[0]
    mls     v18.8H, v26.8H, v0.h[0]
    mls     v19.8H, v27.8H, v0.h[0]

    sub x15, x15, #1
    cbnz x15, 1b

    // --- Epilogue: store final 32 coefficients ---
    st1 { v4.8H,  v5.8H,  v6.8H,  v7.8H}, [x0], #64
    st1 {v16.8H, v17.8H, v18.8H, v19.8H}, [x0], #64
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMAddReduce)

// =============================================================================
// MLKEMSubReduce — Polynomial subtraction with modular reduction
// =============================================================================
// Computes: r[i] = (r[i] - b[i]) mod Q for i = 0..255
//
// Arguments:
//   x0 = r  (int16_t* — destination polynomial, 256 coefficients)
//   x1 = b  (int16_t* — source polynomial, 256 coefficients)
//
// Uses Barrett reduction (M=25519) for signed values in [-2q, 2q].
// Structure mirrors MLKEMAddReduce with sub instead of add.
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEMSubReduce)
AARCH64_PACIASP
    // --- Setup: load Q=3329 and Barrett constant M=25519 ---
    mov w4, #3329    // Q = 3329 (ML-KEM modulus)
    mov w5, #25519   // Barrett constant

    add x2, x0, #0   // x2 = r (alias for dest pointer)

    // --- Broadcast constants to NEON vector lanes ---
    dup v0.8H, w4
    dup v1.8H, w5

    // --- Prologue: load 32 coefficients from b[] and r[], compute r-b ---
    ld1 {v24.8H, v25.8H, v26.8H, v27.8H}, [x1], #64
    ld1 {v28.8H, v29.8H, v30.8H, v31.8H}, [x1], #64
    ld1 {v16.8H, v17.8H, v18.8H, v19.8H}, [x2], #64
    ld1 {v20.8H, v21.8H, v22.8H, v23.8H}, [x2], #64

    // --- Compute polynomial subtraction: diff = r - b ---
    sub  v4.8H, v16.8H, v24.8H
    sub  v5.8H, v17.8H, v25.8H
    sub  v6.8H, v18.8H, v26.8H
    sub  v7.8H, v19.8H, v27.8H

    sub v16.8H, v20.8H, v28.8H
    sub v17.8H, v21.8H, v29.8H
    sub v18.8H, v22.8H, v30.8H
    sub v19.8H, v23.8H, v31.8H

    // --- Barrett reduction (first pair, v4-v7): see MLKEMAddReduce for full detail ---
    sqdmulh v20.8H, v4.8H, v1.h[0]
    sqdmulh v21.8H, v5.8H, v1.h[0]
    sqdmulh v22.8H, v6.8H, v1.h[0]
    sqdmulh v23.8H, v7.8H, v1.h[0]
    srshr   v20.8H, v20.8H, #11
    srshr   v21.8H, v21.8H, #11
    srshr   v22.8H, v22.8H, #11
    srshr   v23.8H, v23.8H, #11
    mls     v4.8H, v20.8H, v0.h[0]
    mls     v5.8H, v21.8H, v0.h[0]
    mls     v6.8H, v22.8H, v0.h[0]
    mls     v7.8H, v23.8H, v0.h[0]

    // --- Barrett reduction (second pair, v16-v19) ---
    sqdmulh v24.8H, v16.8H, v1.h[0]
    sqdmulh v25.8H, v17.8H, v1.h[0]
    sqdmulh v26.8H, v18.8H, v1.h[0]
    sqdmulh v27.8H, v19.8H, v1.h[0]
    srshr   v24.8H, v24.8H, #11
    srshr   v25.8H, v25.8H, #11
    srshr   v26.8H, v26.8H, #11
    srshr   v27.8H, v27.8H, #11
    mls     v16.8H, v24.8H, v0.h[0]
    mls     v17.8H, v25.8H, v0.h[0]
    mls     v18.8H, v26.8H, v0.h[0]
    mls     v19.8H, v27.8H, v0.h[0]

    // --- Main loop: 3 iterations × 32 coefficients ---
    mov x15, #3
    1:

    // --- Store previous results, load next batch ---
    st1 { v4.8H,  v5.8H,  v6.8H,  v7.8H}, [x0], #64
    ld1 {v24.8H, v25.8H, v26.8H, v27.8H}, [x1], #64
    st1 {v16.8H, v17.8H, v18.8H, v19.8H}, [x0], #64
    ld1 {v28.8H, v29.8H, v30.8H, v31.8H}, [x1], #64
    ld1 {v16.8H, v17.8H, v18.8H, v19.8H}, [x2], #64
    ld1 {v20.8H, v21.8H, v22.8H, v23.8H}, [x2], #64

    // --- Subtract: diff = r - b ---
    sub  v4.8H, v16.8H, v24.8H
    sub  v5.8H, v17.8H, v25.8H
    sub  v6.8H, v18.8H, v26.8H
    sub  v7.8H, v19.8H, v27.8H

    sub v16.8H, v20.8H, v28.8H
    sub v17.8H, v21.8H, v29.8H
    sub v18.8H, v22.8H, v30.8H
    sub v19.8H, v23.8H, v31.8H

    // --- Barrett reduction (v4-v7) ---
    sqdmulh v20.8H, v4.8H, v1.h[0]
    sqdmulh v21.8H, v5.8H, v1.h[0]
    sqdmulh v22.8H, v6.8H, v1.h[0]
    sqdmulh v23.8H, v7.8H, v1.h[0]
    srshr   v20.8H, v20.8H, #11
    srshr   v21.8H, v21.8H, #11
    srshr   v22.8H, v22.8H, #11
    srshr   v23.8H, v23.8H, #11
    mls     v4.8H, v20.8H, v0.h[0]
    mls     v5.8H, v21.8H, v0.h[0]
    mls     v6.8H, v22.8H, v0.h[0]
    mls     v7.8H, v23.8H, v0.h[0]

    // --- Barrett reduction (v16-v19) ---
    sqdmulh v24.8H, v16.8H, v1.h[0]
    sqdmulh v25.8H, v17.8H, v1.h[0]
    sqdmulh v26.8H, v18.8H, v1.h[0]
    sqdmulh v27.8H, v19.8H, v1.h[0]
    srshr   v24.8H, v24.8H, #11
    srshr   v25.8H, v25.8H, #11
    srshr   v26.8H, v26.8H, #11
    srshr   v27.8H, v27.8H, #11
    mls     v16.8H, v24.8H, v0.h[0]
    mls     v17.8H, v25.8H, v0.h[0]
    mls     v18.8H, v26.8H, v0.h[0]
    mls     v19.8H, v27.8H, v0.h[0]

    sub x15, x15, #1
    cbnz x15, 1b

    // --- Epilogue: store final 32 coefficients ---
    st1 { v4.8H,  v5.8H,  v6.8H,  v7.8H}, [x0], #64
    st1 {v16.8H, v17.8H, v18.8H, v19.8H}, [x0], #64
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMSubReduce)

// =============================================================================
// MLKEMAdd2Reduce — Three-polynomial addition with modular reduction
// =============================================================================
// Computes: r[i] = (r[i] + b[i] + d[i]) mod Q for i = 0..255
//
// Arguments:
//   x0 = r  (int16_t* — destination polynomial, 256 coefficients)
//   x1 = b  (int16_t* — second source polynomial)
//   x2 = d  (int16_t* — third source polynomial)
//
// Uses Barrett reduction (M=25519). Sum of three polynomials can produce
// values in [-3q, 3q], but Barrett reduction still works correctly
// because M=25519 provides enough precision for values up to ±3q.
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEMAdd2Reduce)
AARCH64_PACIASP
    // --- Setup: load Q and Barrett constant ---
    mov w4, #3329    // Q = 3329 (ML-KEM modulus)
    mov w5, #25519   // Barrett constant

    add x3, x0, #0   // x3 = r (alias for dest pointer)

    // --- Broadcast constants to NEON ---
    dup v0.8H, w4
    dup v1.8H, w5

    // --- Prologue: load 32 coefficients from r[], b[], d[] ---
    ld1 { v4.8H,  v5.8H,  v6.8H,  v7.8H}, [x3], #64
    ld1 {v20.8H, v21.8H, v22.8H, v23.8H}, [x3], #64
    ld1 {v16.8H, v17.8H, v18.8H, v19.8H}, [x1], #64
    ld1 {v24.8H, v25.8H, v26.8H, v27.8H}, [x1], #64

    // --- First addition: r += b (interleaved with d[] loads for latency hiding) ---
    add   v4.8H,  v4.8H, v16.8H
    add   v5.8H,  v5.8H, v17.8H
    ld1 {v16.8H, v17.8H}, [x2], #32
    add   v6.8H,  v6.8H, v18.8H
    add   v7.8H,  v7.8H, v19.8H
    ld1 {v18.8H, v19.8H}, [x2], #32
    add  v20.8H, v20.8H, v24.8H
    add  v21.8H, v21.8H, v25.8H
    ld1 {v24.8H, v25.8H}, [x2], #32
    add  v22.8H, v22.8H, v26.8H
    add  v23.8H, v23.8H, v27.8H
    ld1 {v26.8H, v27.8H}, [x2], #32

    add   v4.8H,  v4.8H, v16.8H
    add   v5.8H,  v5.8H, v17.8H
    add   v6.8H,  v6.8H, v18.8H
    add   v7.8H,  v7.8H, v19.8H
    add  v20.8H, v20.8H, v24.8H
    add  v21.8H, v21.8H, v25.8H
    add  v22.8H, v22.8H, v26.8H
    add  v23.8H, v23.8H, v27.8H

    // --- Barrett reduction (v4-v7) ---
    sqdmulh v16.8H, v4.8H, v1.h[0]
    sqdmulh v17.8H, v5.8H, v1.h[0]
    sqdmulh v18.8H, v6.8H, v1.h[0]
    sqdmulh v19.8H, v7.8H, v1.h[0]
    srshr   v16.8H, v16.8H, #11
    srshr   v17.8H, v17.8H, #11
    srshr   v18.8H, v18.8H, #11
    srshr   v19.8H, v19.8H, #11
    mls     v4.8H, v16.8H, v0.h[0]
    mls     v5.8H, v17.8H, v0.h[0]
    mls     v6.8H, v18.8H, v0.h[0]
    mls     v7.8H, v19.8H, v0.h[0]

    // --- Barrett reduction (v20-v23) ---
    sqdmulh v16.8H, v20.8H, v1.h[0]
    sqdmulh v17.8H, v21.8H, v1.h[0]
    sqdmulh v18.8H, v22.8H, v1.h[0]
    sqdmulh v19.8H, v23.8H, v1.h[0]
    srshr   v16.8H, v16.8H, #11
    srshr   v17.8H, v17.8H, #11
    srshr   v18.8H, v18.8H, #11
    srshr   v19.8H, v19.8H, #11
    mls     v20.8H, v16.8H, v0.h[0]
    mls     v21.8H, v17.8H, v0.h[0]
    mls     v22.8H, v18.8H, v0.h[0]
    mls     v23.8H, v19.8H, v0.h[0]

    // --- Main loop: 3 iterations × 32 coefficients ---
    mov x15, #3
    1:

    // --- Store previous, load next batch from r[], b[], d[] ---
    st1 { v4.8H,  v5.8H,  v6.8H,  v7.8H}, [x0], #64
    ld1 { v4.8H,  v5.8H,  v6.8H,  v7.8H}, [x3], #64
    st1 {v20.8H, v21.8H, v22.8H, v23.8H}, [x0], #64
    ld1 {v20.8H, v21.8H, v22.8H, v23.8H}, [x3], #64
    ld1 {v16.8H, v17.8H, v18.8H, v19.8H}, [x1], #64
    ld1 {v24.8H, v25.8H, v26.8H, v27.8H}, [x1], #64

    add   v4.8H,  v4.8H, v16.8H
    add   v5.8H,  v5.8H, v17.8H
    ld1 {v16.8H, v17.8H}, [x2], #32
    add   v6.8H,  v6.8H, v18.8H
    add   v7.8H,  v7.8H, v19.8H
    ld1 {v18.8H, v19.8H}, [x2], #32
    add  v20.8H, v20.8H, v24.8H
    add  v21.8H, v21.8H, v25.8H
    ld1 {v24.8H, v25.8H}, [x2], #32
    add  v22.8H, v22.8H, v26.8H
    add  v23.8H, v23.8H, v27.8H
    ld1 {v26.8H, v27.8H}, [x2], #32

    add   v4.8H,  v4.8H, v16.8H
    add   v5.8H,  v5.8H, v17.8H
    add   v6.8H,  v6.8H, v18.8H
    add   v7.8H,  v7.8H, v19.8H
    add  v20.8H, v20.8H, v24.8H
    add  v21.8H, v21.8H, v25.8H
    add  v22.8H, v22.8H, v26.8H
    add  v23.8H, v23.8H, v27.8H

    // Barrett reduction for v4-v7
    sqdmulh v16.8H, v4.8H, v1.h[0]
    sqdmulh v17.8H, v5.8H, v1.h[0]
    sqdmulh v18.8H, v6.8H, v1.h[0]
    sqdmulh v19.8H, v7.8H, v1.h[0]
    srshr   v16.8H, v16.8H, #11
    srshr   v17.8H, v17.8H, #11
    srshr   v18.8H, v18.8H, #11
    srshr   v19.8H, v19.8H, #11
    mls     v4.8H, v16.8H, v0.h[0]
    mls     v5.8H, v17.8H, v0.h[0]
    mls     v6.8H, v18.8H, v0.h[0]
    mls     v7.8H, v19.8H, v0.h[0]

    // Barrett reduction for v20-v23
    sqdmulh v16.8H, v20.8H, v1.h[0]
    sqdmulh v17.8H, v21.8H, v1.h[0]
    sqdmulh v18.8H, v22.8H, v1.h[0]
    sqdmulh v19.8H, v23.8H, v1.h[0]
    srshr   v16.8H, v16.8H, #11
    srshr   v17.8H, v17.8H, #11
    srshr   v18.8H, v18.8H, #11
    srshr   v19.8H, v19.8H, #11
    mls     v20.8H, v16.8H, v0.h[0]
    mls     v21.8H, v17.8H, v0.h[0]
    mls     v22.8H, v18.8H, v0.h[0]
    mls     v23.8H, v19.8H, v0.h[0]

    sub x15, x15, #1
    cbnz x15, 1b

    st1 { v4.8H,  v5.8H,  v6.8H,  v7.8H}, [x0], #64
    st1 {v20.8H, v21.8H, v22.8H, v23.8H}, [x0], #64
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMAdd2Reduce)

// =============================================================================
// MLKEMPolyVecReduce — Vector polynomial unsigned canonical reduction
// =============================================================================
// Computes: for i in 0..k-1: r[i] = MLKEMPolyReduce(r[i])
//   Each polynomial is reduced in-place to unsigned canonical form [0, Q).
//
// Arguments:
//   x0 = k  (number of polynomials, ML-KEM dimension)
//   x1 = r  (int16_t** — array of pointers to polynomials)
//
// Implementation: simple k-loop dispatching to MLKEMPolyReduce for each poly.
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEMPolyVecReduce)
AARCH64_PACIASP
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x29, sp
    mov     w19, w0
    mov     x20, x1
    cbz     w19, .Lpolyvecreduce_done
    mov     w21, #0
.Lpolyvecreduce_loop:
    // --- Load pointer to i-th polynomial and reduce it ---
    ldr     x0, [x20, x21, lsl #3]
    bl      CRYPT_AARCH64_SYM(MLKEMPolyReduce)
    add     w21, w21, #1
    cmp     w21, w19
    b.lo    .Lpolyvecreduce_loop
.Lpolyvecreduce_done:
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMPolyVecReduce)

// ========== Unsigned Canonical Polynomial Reduction ==========
// Reduces 256 polynomial coefficients to [0, Q) where Q = 3329.
// Uses Barrett reduction followed by conditional correction.
//
// Processing: 4 coefficients per iteration (2 vectors of 8 each),
//   8 loop iterations + prologue/epilogue = 256 coefficients total.
//
// Per-vector algorithm:
//   1. Barrett reduction: sqdmulh → srshr → mls (same as AddReduce)
//      This produces a ∈ (−Q, Q)
//   2. Conditional correction to unsigned canonical form:
//      sshr   t, a, #15        // t = 0x0000 if a ≥ 0, 0xFFFF if a < 0
//      and    t, Q, t          // t = 0 if a ≥ 0, Q if a < 0
//      add    a, a, t          // a = a (if a ≥ 0) or a + Q (if a < 0)
//      Result: a ∈ [0, Q)
//
// Note: The output loop interleaves pipeline stages for throughput:
//   Barrett reduction of current pair → conditional correction of previous pair
//   → store previous pair → load next pair
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMPolyReduce)
AARCH64_PACIASP
        // --- Setup: Q=3329 (0xD01), Barrett M=20159 (0x4EBF) ---
        // Note: M=20159 differs from AddReduce's M=25519. This value is optimized
        // for unsigned canonical reduction where inputs may be in a different range.
        // The sign-extension trick (sshr #15 → and → add) converts signed results to [0, Q).
        mov	w2, #0xd01              // Q = 3329
        dup	v3.8h, w2
        mov	w2, #0x4ebf             // Barrett constant M = 20159 (signed: 0x4ebf)
        dup	v4.8h, w2
        mov	x1, #0x8                // Loop counter: 8 iterations
        // --- Prologue: load first pair, Barrett reduce, conditional correct ---
        ldr	q21, [x0, #0x20]
        ldr	q23, [x0, #0x30]
        sqdmulh	v7.8h, v21.8h, v4.h[0]
        sqdmulh	v30.8h, v23.8h, v4.h[0]
        srshr	v7.8h, v7.8h, #0xb
        srshr	v30.8h, v30.8h, #0xb
        mls	v21.8h, v7.8h, v3.h[0]
        mls	v23.8h, v30.8h, v3.h[0]
        ldr	q5, [x0, #0x10]
        sshr	v7.8h, v21.8h, #0xf
        sshr	v30.8h, v23.8h, #0xf
        and	v7.16b, v3.16b, v7.16b
        add	v21.8h, v21.8h, v7.8h
        and	v7.16b, v3.16b, v30.16b
        add	v16.8h, v23.8h, v7.8h
        sub	x1, x1, #0x1

1:
        // --- Interleaved pipeline: load next pair + Barrett reduce + sign-correct + store prev ---
        ldr	q6, [x0], #0x40
        ldr	q30, [x0, #0x20]
        sqdmulh	v31.8h, v6.8h, v4.h[0]
        sqdmulh	v29.8h, v5.8h, v4.h[0]
        sqdmulh	v22.8h, v30.8h, v4.h[0]
        stur	q16, [x0, #-0x10]
        srshr	v20.8h, v31.8h, #0xb
        srshr	v28.8h, v29.8h, #0xb
        stur	q21, [x0, #-0x20]
        mls	v6.8h, v20.8h, v3.h[0]
        mls	v5.8h, v28.8h, v3.h[0]
        ldr	q2, [x0, #0x30]
        sshr	v31.8h, v6.8h, #0xf
        srshr	v19.8h, v22.8h, #0xb
        and	v22.16b, v3.16b, v31.16b
        add	v0.8h, v6.8h, v22.8h
        mls	v30.8h, v19.8h, v3.h[0]
        sshr	v26.8h, v5.8h, #0xf
        sqdmulh	v25.8h, v2.8h, v4.h[0]
        and	v17.16b, v3.16b, v26.16b
        add	v1.8h, v5.8h, v17.8h
        sshr	v31.8h, v30.8h, #0xf
        srshr	v25.8h, v25.8h, #0xb
        stur	q1, [x0, #-0x30]
        and	v18.16b, v3.16b, v31.16b
        mls	v2.8h, v25.8h, v3.h[0]
        add	v21.8h, v30.8h, v18.8h
        ldr	q5, [x0, #0x10]
        sshr	v18.8h, v2.8h, #0xf
        stur	q0, [x0, #-0x40]
        and	v27.16b, v3.16b, v18.16b
        add	v16.8h, v2.8h, v27.8h
        sub	x1, x1, #0x1
        cbnz	x1, 1b
        // --- Epilogue: reduce and store final pair ---
        sqdmulh	v20.8h, v5.8h, v4.h[0]
        ldr	q24, [x0], #0x40
        stur	q21, [x0, #-0x20]
        srshr	v20.8h, v20.8h, #0xb
        sqdmulh	v25.8h, v24.8h, v4.h[0]
        stur	q16, [x0, #-0x10]
        mls	v5.8h, v20.8h, v3.h[0]
        srshr	v20.8h, v25.8h, #0xb
        sshr	v2.8h, v5.8h, #0xf
        mls	v24.8h, v20.8h, v3.h[0]
        and	v20.16b, v3.16b, v2.16b
        add	v31.8h, v5.8h, v20.8h
        sshr	v20.8h, v24.8h, #0xf
        stur	q31, [x0, #-0x30]
        and	v31.16b, v3.16b, v20.16b
        add	v24.8h, v24.8h, v31.8h
        stur	q24, [x0, #-0x40]
AARCH64_AUTIASP
        ret
        CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMPolyReduce)


// =============================================================================
// PolyVectoBytes — Encode vector of polynomials to byte arrays
// =============================================================================
// Computes: for i in 0..k-1: MLKEMPolytoBytesAsm(r + i*384, a[i])
//   Encodes each polynomial using ByteEncode₁₂ (12-bit packing → 384 bytes).
//
// Arguments:
//   x0 = k  (number of polynomials, ML-KEM dimension: 2, 3, or 4)
//   x1 = r  (uint8_t* — contiguous output buffer, k*384 bytes)
//   x2 = a  (int16_t** — array of pointers to input polynomials)
//
// Implementation: k-loop dispatching to MLKEMPolytoBytesAsm for each poly.
// Stride is 384 bytes (= 256 × 12 / 8), the ByteEncode₁₂ output size.
// =============================================================================
CRYPT_AARCH64_FUNC_START(PolyVectoBytes)
AARCH64_PACIASP
    stp     x29, x30, [sp, #-64]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    mov     x29, sp
    mov     w19, w0
    mov     x20, x1
    mov     x21, x2
    cbz     w19, .Lpolyvectobytes_done
    mov     w22, #0
    mov     x23, #384
.Lpolyvectobytes_loop:
    madd    x0, x22, x23, x20
    ldr     x1, [x21, x22, lsl #3]
    bl      CRYPT_AARCH64_SYM(MLKEMPolytoBytesAsm)
    add     w22, w22, #1
    cmp     w22, w19
    b.lo    .Lpolyvectobytes_loop
.Lpolyvectobytes_done:
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #64
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(PolyVectoBytes)

// ========== Polynomial to Byte Encoding (FIPS 203 ByteEncode₁₂) ==========
// Packs 256 × 12-bit coefficients into 384 bytes (3 bytes per 2 coefficients).
//
// 12-bit packing pattern (for each pair of coefficients c_even, c_odd):
//   byte0 = c_even[7:0]                     (low 8 bits of even coeff)
//   byte1 = c_even[11:8] | c_odd[3:0] << 4  (top 4 bits of even + low 4 of odd)
//   byte2 = c_odd[11:4]                      (top 8 bits of odd coeff)
//
// NEON implementation processes 16 coefficients (8 pairs) per group:
//   1. uzp1/uzp2:  separate even-indexed and odd-indexed coefficients
//   2. xtn:        extract low 8 bits → byte0
//   3. shrn #8:    shift even coeffs right by 8 → top 4 bits of even
//   4. xtn:        extract low 8 bits of odd coeffs (contains bits 3:0)
//   5. sli #4:     shift-left-insert: merge odd[3:0]<<4 into byte1
//   6. shrn #4:    shift odd coeffs right by 4 → byte2
//   7. st3:        store 3 interleaved byte vectors → packed 24 bytes
//
// Loop: 4 iterations of 4 groups each (16 coefficients/group × 4 × 4 = 256)
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMPolytoBytesAsm)
AARCH64_PACIASP
        mov	x2, #0x10               // Total: 16 groups of 16 coefficients
        ldr	q6, [x1], #0x20
        ldur	q24, [x1, #-0x10]
        ldr	q30, [x1], #0x20
        ldur	q22, [x1, #-0x10]
        ldr	q5, [x1], #0x20
        ldur	q17, [x1, #-0x10]
        ldr	q19, [x1], #0x20
        ldur	q4, [x1, #-0x10]
        lsr	x2, x2, #2              // 16 / 4 = 4 loop iterations
        sub	x2, x2, #0x1            // First iteration is unrolled (start with 3)

1:
        uzp1	v25.8h, v6.8h, v24.8h
        uzp2	v6.8h, v6.8h, v24.8h
        xtn	v24.8b, v25.8h
        shrn	v25.8b, v25.8h, #0x8
        xtn	v18.8b, v6.8h
        shrn	v26.8b, v6.8h, #0x4
        sli	v25.8b, v18.8b, #0x4
        st3	{ v24.8b, v25.8b, v26.8b }, [x0], #24
        uzp1	v25.8h, v30.8h, v22.8h
        uzp2	v6.8h, v30.8h, v22.8h
        xtn	v24.8b, v25.8h
        xtn	v18.8b, v6.8h
        uzp1	v30.8h, v5.8h, v17.8h
        uzp2	v22.8h, v5.8h, v17.8h
        xtn	v5.8b, v30.8h
        xtn	v17.8b, v22.8h
        uzp1	v28.8h, v19.8h, v4.8h
        uzp2	v19.8h, v19.8h, v4.8h
        xtn	v4.8b, v28.8h
        xtn	v20.8b, v19.8h
        shrn	v25.8b, v25.8h, #0x8
        sli	v25.8b, v18.8b, #0x4
        shrn	v26.8b, v6.8h, #0x4
        st3	{ v24.8b, v25.8b, v26.8b }, [x0], #24
        shrn	v6.8b, v30.8h, #0x8
        sli	v6.8b, v17.8b, #0x4
        shrn	v7.8b, v22.8h, #0x4
        st3	{ v5.8b, v6.8b, v7.8b }, [x0], #24
        shrn	v5.8b, v28.8h, #0x8
        shrn	v6.8b, v19.8h, #0x4
        sli	v5.8b, v20.8b, #0x4
        st3	{ v4.8b, v5.8b, v6.8b }, [x0], #24
        ldr	q6, [x1], #0x20
        ldur	q24, [x1, #-0x10]
        ldr	q30, [x1], #0x20
        ldur	q22, [x1, #-0x10]
        ldr	q5, [x1], #0x20
        ldur	q17, [x1, #-0x10]
        ldr	q19, [x1], #0x20
        ldur	q4, [x1, #-0x10]
        sub	x2, x2, #0x1
        cbnz	x2, 1b
        uzp1	v25.8h, v30.8h, v22.8h
        uzp2	v18.8h, v30.8h, v22.8h
        uzp1	v30.8h, v6.8h, v24.8h
        uzp2	v6.8h, v6.8h, v24.8h
        uzp1	v24.8h, v5.8h, v17.8h
        uzp2	v22.8h, v5.8h, v17.8h
        uzp1	v5.8h, v19.8h, v4.8h
        uzp2	v17.8h, v19.8h, v4.8h
        xtn	v19.8b, v25.8h
        shrn	v20.8b, v25.8h, #0x8
        xtn	v25.8b, v18.8h
        shrn	v21.8b, v18.8h, #0x4
        xtn	v28.8b, v30.8h
        shrn	v29.8b, v30.8h, #0x8
        xtn	v18.8b, v6.8h
        shrn	v30.8b, v6.8h, #0x4
        xtn	v1.8b, v24.8h
        shrn	v2.8b, v24.8h, #0x8
        xtn	v6.8b, v22.8h
        shrn	v3.8b, v22.8h, #0x4
        xtn	v22.8b, v5.8h
        shrn	v23.8b, v5.8h, #0x8
        xtn	v5.8b, v17.8h
        shrn	v24.8b, v17.8h, #0x4
        sli	v20.8b, v25.8b, #0x4
        sli	v29.8b, v18.8b, #0x4
        st3	{ v28.8b, v29.8b, v30.8b }, [x0], #24
        st3	{ v19.8b, v20.8b, v21.8b }, [x0], #24
        sli	v2.8b, v6.8b, #0x4
        st3	{ v1.8b, v2.8b, v3.8b }, [x0], #24
        sli	v23.8b, v5.8b, #0x4
        st3	{ v22.8b, v23.8b, v24.8b }, [x0], #24
AARCH64_AUTIASP
        ret
        CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMPolytoBytesAsm)

// =============================================================================
// MLKEMPolyINTTtoMont — Inverse NTT followed by Montgomery conversion
// =============================================================================
// Computes: for i in 0..k-1: MLKEM_ComputeINTTAsm(r[i])
//
// Arguments:
//   x0 = k  (number of polynomials)
//   x1 = r  (int16_t** — array of pointers to polynomials)
//
// Implementation: k-loop calling MLKEM_ComputeINTTAsm (defined externally in
// ml_kem_ntt_armv8.S). That function performs INTT and scales coefficients
// by Montgomery factor n⁻¹ mod Q, bringing results to standard form.
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEMPolyINTTtoMont)
AARCH64_PACIASP
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    mov     x29, sp
    mov     w19, w0
    mov     x20, x1
    cbz     w19, .Lpolyintt_done
    mov     w21, #0
.Lpolyintt_loop:
    ldr     x0, [x20, x21, lsl #3]
    bl      CRYPT_AARCH64_SYM(MLKEM_ComputeINTTAsm)
    add     w21, w21, #1
    cmp     w21, w19
    b.lo    .Lpolyintt_loop
.Lpolyintt_done:
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMPolyINTTtoMont)

// =============================================================================
// MLKEMPolyCBDEta — Centered Binomial Distribution dispatcher
// =============================================================================
// Dispatches to MLKEMCBD2 or MLKEMCBD3 based on the eta parameter.
//
// Arguments:
//   x0 = eta  (uint32_t — CBD parameter, must be 2 or 3)
//   x1 = r    (int16_t* — output polynomial, 256 coefficients)
//   x2 = buf  (const uint8_t* — input random bytes, 128 or 192 bytes)
//
// For eta=2: consumes 128 bytes, outputs coefficients in {-2, -1, 0, 1, 2}
// For eta=3: consumes 192 bytes, outputs coefficients in {-3, -2, ..., 2, 3}
//
// FIPS 203, Algorithm 8: CBD_η(PRF_η(seed, nonce))
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEMPolyCBDEta)
    cmp     w0, #2
    b.eq    .Lpolycbd_eta2
    cmp     w0, #3
    b.eq    .Lpolycbd_eta3
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMPolyCBDEta)
.Lpolycbd_eta2:
    mov     x0, x1
    mov     x1, x2
    b       CRYPT_AARCH64_SYM(MLKEMCBD2)
.Lpolycbd_eta3:
    mov     x0, x1
    mov     x1, x2
    b       CRYPT_AARCH64_SYM(MLKEMCBD3)

// MLKEMCBD2 - Centered Binomial Distribution with eta=2 (internal, called by MLKEMPolyCBDEta)
//
// Input:  x0 = int16_t *r (output, 256 coefficients)
//         x1 = const uint8_t *buf (input, 128 bytes)
//
// Output: None (writes to r)
//
// Algorithm:
//   For each pair of input bytes, extract four 2-bit values and compute:
//   r[i] = a - b, where a and b are the extracted 2-bit values
//
//   Each input byte contains 4 pairs of 2-bit values:
//   - Bits 0-1: a0, bits 2-3: b0, bits 4-5: a1, bits 6-7: b1
//
//   The result ranges from -2 to +2
//
// Loop: 4 iterations, each processes 32 input bytes, generates 128 int16_t
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMCBD2)
    movi    v17.16b, #0x55         // Bit mask 0x55 for extracting even/odd bits
    add     x3, x0, #0x200         // End of output buffer (512 bytes)
    movi    v16.16b, #0x3          // Mask for lower 2 bits
1:
    // Load 32 bytes (2 interleaved vectors of 16 bytes each)
    ld2     { v20.16b, v21.16b }, [x1], #32
    mov     x2, x0                 // Save current output position
    add     x0, x0, #0x80          // Advance output pointer by 128 bytes

    // Extract and sum 2-bit pairs: (byte & 0x55) + ((byte >> 1) & 0x55)
    ushr    v18.16b, v20.16b, #1
    and     v22.16b, v17.16b, v20.16b
    ushr    v19.16b, v21.16b, #1
    and     v20.16b, v17.16b, v21.16b
    and     v18.16b, v18.16b, v17.16b
    and     v19.16b, v19.16b, v17.16b
    add     v18.16b, v18.16b, v22.16b
    add     v19.16b, v19.16b, v20.16b

    // Extract 4 pairs of 2-bit values from summed bytes
    // Each byte now contains 4 pairs: (a0+b0, a1+b1, a2+b2, a3+b3)
    // where each sum is in range [0, 4]
    // Extract pairs at positions 0, 2, 4, 6 (shifted by 0, 2, 4, 6)
    ushr    v22.16b, v18.16b, #2
    and     v24.16b, v18.16b, v16.16b  // Bits 0-1
    ushr    v23.16b, v18.16b, #4
    ushr    v20.16b, v19.16b, #2
    and     v22.16b, v22.16b, v16.16b  // Bits 2-3
    ushr    v18.16b, v18.16b, #6
    and     v23.16b, v23.16b, v16.16b  // Bits 4-5
    and     v21.16b, v19.16b, v16.16b  // Bits 0-1 (second vector)

    // Compute first 4 results: a - b
    usubl   v4.8h, v24.8b, v22.8b    // Low 8 bytes: bits 0-1 minus bits 2-3
    usubl2  v0.8h, v24.16b, v22.16b  // High 8 bytes: bits 0-1 minus bits 2-3

    // Extract remaining pairs and compute results
    ushr    v22.16b, v19.16b, #4
    and     v20.16b, v20.16b, v16.16b
    ushr    v19.16b, v19.16b, #6
    usubl   v5.8h, v23.8b, v18.8b    // Low 8 bytes: bits 4-5 minus bits 6-7
    usubl2  v1.8h, v23.16b, v18.16b  // High 8 bytes: bits 4-5 minus bits 6-7
    and     v18.16b, v22.16b, v16.16b  // Bits 4-5 (second vector)
    usubl   v6.8h, v21.8b, v20.8b    // Low 8 bytes: bits 0-1 minus bits 2-3
    usubl2  v2.8h, v21.16b, v20.16b  // High 8 bytes: bits 0-1 minus bits 2-3
    usubl   v7.8h, v18.8b, v19.8b    // Low 8 bytes: bits 4-5 minus bits 6-7
    usubl2  v3.8h, v18.16b, v19.16b  // High 8 bytes: bits 4-5 minus bits 6-7

    // Store 64 int16_t (128 bytes) per iteration
    st4     { v4.8h, v5.8h, v6.8h, v7.8h }, [x2], #64
    st4     { v0.8h, v1.8h, v2.8h, v3.8h }, [x2]

    cmp     x3, x0                 // Check if output buffer is filled
    b.ne    1b
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMCBD2)

CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMCBD3)
AARCH64_PACIASP
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    mov     w7, #0x9249
    movk    w7, #0x0024, lsl #16
    dup     v30.4s, w7              // v30 = 0x00249249 (every-3rd-bit mask for popcount)

    CRYPT_AARCH64_GET_RELA(x9, .LCBD3_shuffle)
    ldr     q29, [x9]  // TBL shuffle: 12 bytes → 4 × 24-bit lanes

    add     x2, x0, #512           // End pointer (256 × 2 bytes = 512)

.LCBD3_loop:
    // ---- Load 12 bytes and rearrange via TBL ----
    ldr     x3, [x1]
    ldr     w4, [x1, #8]
    add     x1, x1, #12
    fmov    d0, x3
    mov     v0.s[2], w4

    tbl     v16.16b, {v0.16b}, v29.16b

    and     v17.16b, v16.16b, v30.16b
    ushr    v18.4s, v16.4s, #1
    and     v18.16b, v18.16b, v30.16b
    ushr    v19.4s, v16.4s, #2
    and     v19.16b, v19.16b, v30.16b
    add     v16.4s, v17.4s, v18.4s
    add     v16.4s, v16.4s, v19.4s

    umov    w4, v16.s[0]
    umov    w9, v16.s[1]
    umov    w15, v16.s[2]
    umov    w12, v16.s[3]

    // Block 0 → x3
    ubfx    w3, w4, #0, #3
    ubfx    w5, w4, #3, #3
    sub     w3, w3, w5
    ubfx    w5, w4, #6, #3
    ubfx    w6, w4, #9, #3
    sub     w5, w5, w6
    bfi     w3, w5, #16, #16
    ubfx    w5, w4, #12, #3
    ubfx    w6, w4, #15, #3
    sub     w5, w5, w6
    ubfx    w6, w4, #18, #3
    ubfx    w13, w4, #21, #3
    sub     w6, w6, w13
    bfi     w5, w6, #16, #16
    orr     x3, x3, x5, lsl #32

    // Block 1 → x8
    ubfx    w8, w9, #0, #3
    ubfx    w10, w9, #3, #3
    sub     w8, w8, w10
    ubfx    w10, w9, #6, #3
    ubfx    w11, w9, #9, #3
    sub     w10, w10, w11
    bfi     w8, w10, #16, #16
    ubfx    w10, w9, #12, #3
    ubfx    w11, w9, #15, #3
    sub     w10, w10, w11
    ubfx    w11, w9, #18, #3
    ubfx    w13, w9, #21, #3
    sub     w11, w11, w13
    bfi     w10, w11, #16, #16
    orr     x8, x8, x10, lsl #32

    stp     x3, x8, [x0]

    // Block 2 → x14 (d2 in w15, caller-saved temps: w3-w6)
    ubfx    w3, w15, #0, #3
    ubfx    w4, w15, #3, #3
    sub     w3, w3, w4
    ubfx    w4, w15, #6, #3
    ubfx    w5, w15, #9, #3
    sub     w4, w4, w5
    bfi     w3, w4, #16, #16
    ubfx    w4, w15, #12, #3
    ubfx    w5, w15, #15, #3
    sub     w4, w4, w5
    ubfx    w5, w15, #18, #3
    ubfx    w13, w15, #21, #3
    sub     w5, w5, w13
    bfi     w4, w5, #16, #16
    orr     x14, x3, x4, lsl #32

    // Block 3 → x3 (d3 in w12, reuse caller-saved w4-w6)
    ubfx    w3, w12, #0, #3
    ubfx    w4, w12, #3, #3
    sub     w3, w3, w4
    ubfx    w4, w12, #6, #3
    ubfx    w5, w12, #9, #3
    sub     w4, w4, w5
    bfi     w3, w4, #16, #16
    ubfx    w4, w12, #12, #3
    ubfx    w5, w12, #15, #3
    sub     w4, w4, w5
    ubfx    w5, w12, #18, #3
    ubfx    w13, w12, #21, #3
    sub     w5, w5, w13
    bfi     w4, w5, #16, #16
    orr     x3, x3, x4, lsl #32

    stp     x14, x3, [x0, #16]
    add     x0, x0, #32

    cmp     x0, x2
    b.ne    .LCBD3_loop

    ldp     x29, x30, [sp], #16
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMCBD3)

// =============================================================================
// PackCipherText — Pack ML-KEM ciphertext (FIPS 203, line 26 of Encaps)
// =============================================================================
// Computes:
//   PolyVecCompress(k, ct, t)        — compress and encode vector part c₁
//   PolyCompress(k, ct + c1len, c2)  — compress and encode scalar part c₂
//
// Arguments:
//   x0 = k      (ML-KEM dimension: 2, 3, or 4)
//   x1 = c1len  (length of compressed vector part in bytes)
//   x2 = ct     (uint8_t* — output ciphertext buffer)
//   x3 = t      (int16_t** — vector of polynomials for c₁)
//   x4 = c2     (int16_t* — polynomial for c₂)
//
// Implementation: saves all argument registers, calls PolyVecCompress,
// then PolyCompress with adjusted pointers, and restores callee-saved regs.
// =============================================================================
CRYPT_AARCH64_FUNC_START(PackCipherText)
AARCH64_PACIASP
    stp     x29, x30, [sp, #-48]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    str     x23, [sp, #40]
    mov     x29, sp
    mov     w19, w0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    mov     w0, w19
    mov     x1, x21
    mov     x2, x22
    bl      CRYPT_AARCH64_SYM(PolyVecCompress)
    add     x1, x21, x20
    mov     w0, w19
    mov     x2, x23
    bl      CRYPT_AARCH64_SYM(PolyCompress)
    ldr     x23, [sp, #40]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(PackCipherText)

// =============================================================================
// PolyCompress — Compress single polynomial (dispatch by ML-KEM parameter set)
// =============================================================================
// Dispatches based on ML-KEM parameter k:
//   k=2 (ML-KEM-512) or k=3 (ML-KEM-768): calls MLKEMPolyCompress4 (d=4)
//   k=4 (ML-KEM-1024): calls MLKEMPolyCompress5 (d=5)
//
// Arguments:
//   x0 = k  (ML-KEM parameter set indicator: 2, 3, or 4)
//   x1 = r  (uint8_t* — output compressed buffer)
//   x2 = a  (int16_t* — input polynomial, 256 coefficients)
//
// FIPS 203: Compress_d(x) = round(2^d / q × x) mod 2^d
// =============================================================================
CRYPT_AARCH64_FUNC_START(PolyCompress)
    cmp     w0, #2
    b.eq    .Lpolycompress_4
    cmp     w0, #3
    b.eq    .Lpolycompress_4
    mov     x0, x1
    mov     x1, x2
    b       CRYPT_AARCH64_SYM(MLKEMPolyCompress5)
.Lpolycompress_4:
    mov     x0, x1
    mov     x1, x2
    b       CRYPT_AARCH64_SYM(MLKEMPolyCompress4)
    CRYPT_AARCH64_FUNC_END(PolyCompress)

// =============================================================================
// MLKEMPolyCompress4 — 4-bit polynomial compression (ML-KEM-512, ML-KEM-768)
// =============================================================================
// Internal, called by PolyCompress when k=2 or k=3.
//
// Input:  x0 = uint8_t r[128] (output, 128 bytes)
//         x1 = int16_t *a (input, 256 coefficients in [0, Q))
//
// FIPS 203 Compress_4(x) = round(16 / q × x) mod 16
//   Approximation: Compress_4(x) = ((x × 315 × 2) >> 16 + 1) >> 1 & 0xf
//   where 315 ≈ round(2^16 × 16 / 3329).
//   sqdmulh computes (x × 315 × 2) >> 16 (signed saturating doubling mul high),
//   shadd computes (result + 1) >> 1 (halving add for rounding).
//
// Bit packing: pairs of 4-bit nibbles merged into bytes via
//   xtn/xtn2 (narrow 16-bit → 8-bit), sshr #4 + orr (merge adjacent nibbles).
//
// Loop: 8 iterations × 32 coefficients = 256 total
// =============================================================================
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMPolyCompress4)
    mov     w3, #0x13b              // w3 = 315 ≈ round(2^15 × 16 / 3329)
    add     x2, x0, #0x80          // End of output buffer (128 bytes for d=4)
    movi    v6.8h, #0x1             // Constant 1 for rounding in shadd
    movi    v5.8h, #0xf             // Mask for lower 4 bits (2^d - 1)
    dup     v4.4h, w3              // v4 = {315, 315, 315, 315}
1:
    ldp     q3, q2, [x1]           // Load 16 int16_t
    sqdmulh v3.8h, v3.8h, v4.h[0]  // v3 = (v3 * 315) >> 32 (rounding)
    sqdmulh v2.8h, v2.8h, v4.h[0]  // v2 = (v2 * 315) >> 32
    shadd   v3.8h, v3.8h, v6.8h    // v3 = (v3 + 1) >> 1
    shadd   v2.8h, v2.8h, v6.8h    // v2 = (v2 + 1) >> 1
    ldp     q1, q0, [x1, #32]      // Load next 16 int16_t
    sqdmulh v1.8h, v1.8h, v4.h[0]  // v1 = (v1 * 315) >> 32
    sqdmulh v0.8h, v0.8h, v4.h[0]  // v0 = (v0 * 315) >> 32
    shadd   v1.8h, v1.8h, v6.8h    // v1 = (v1 + 1) >> 1
    add     x1, x1, #0x40          // Advance input pointer by 64 bytes
    shadd   v0.8h, v0.8h, v6.8h    // v0 = (v0 + 1) >> 1
    and     v2.16b, v2.16b, v5.16b  // v2 &= 0xf
    and     v3.16b, v3.16b, v5.16b  // v3 &= 0xf
    and     v1.16b, v1.16b, v5.16b  // v1 &= 0xf
    and     v0.16b, v0.16b, v5.16b  // v0 &= 0xf
    xtn     v7.8b, v3.8h            // v7 = low 8 bits of v3
    xtn2    v7.16b, v2.8h           // v7 += low 8 bits of v2
    xtn     v2.8b, v1.8h            // v2 = low 8 bits of v1
    xtn2    v2.16b, v0.8h           // v2 += low 8 bits of v0
    sshr    v1.8h, v7.8h, #4        // v1 = v7 >> 4 (arithmetic)
    sshr    v0.8h, v2.8h, #4        // v0 = v2 >> 4 (arithmetic)
    orr     v1.16b, v1.16b, v7.16b  // v1 |= v7
    orr     v0.16b, v0.16b, v2.16b  // v0 |= v2
    xtn     v2.8b, v1.8h            // v2 = low 8 bits of v1
    xtn2    v2.16b, v0.8h           // v2 += low 8 bits of v0
    str     q2, [x0], #16          // Store 16 bytes
    cmp     x0, x2                 // Check if done
    b.ne    1b
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMPolyCompress4)


// =============================================================================
// MLKEMPolyCompress5 — 5-bit polynomial compression (ML-KEM-1024)
// =============================================================================
// Internal, called by PolyCompress when k=4.
//
// Input:  x0 = uint8_t r[160] (output, 160 bytes)
//         x1 = int16_t *a (input, 256 coefficients)
//
// Output: None (writes to r)
//
// FIPS 203 Compress_5(x) = round(2^5 / q × x) mod 2^5
//   Approximation: sqrdmulh × 315 then mask to 5 bits.
//   315 ≈ round(2^15 × 32 / 3329).
//
// Bit packing via SHIFT_WITH_HOLES: cascade of mask+shift+or to collapse
// 8 × 5-bit values from 128-bit vector into 40 bits (5 bytes per 8 coefficients).
//
// Loop: 16 iterations × 16 coefficients = 256 total.
//
// Register usage:
//   x14 = end-of-buffer pointer
//   x13 = temp buffer on stack for byte extraction
//   v3  = compression constant {315}
//   v4  = 5-bit mask (0x1f)
//   v5/v6/v7/v16/v17/v18 = intermediate packing masks (loaded from .rodata)
// =============================================================================
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMPolyCompress5)
    stp     x29, x30, [sp, #-64]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]    // Save callee-saved regs we use
    add     x14, x0, #0xa0         // End of output buffer (160 bytes)
    mov     w19, #0                // round index
    add     x13, sp, #0x18         // Temp buffer on stack
    movi    v4.8h, #0x1f           // Mask for lower 5 bits
    movi    v18.8h, #0x1f, lsl #8  // Mask for bits 8-12 (0x1f00)
    movi    v17.8h, #0x1f          // Mask for lower 5 bits
    ldr     q16, 0f                // mask_h_lo
    ldr     q6, 1f                 // mask_w_hi
    movi    v7.4s, #0x3, msl #8    // mask_w_lo = {0x3ff, 0x3ff, 0x3ff, 0x3ff}
    ldr     q5, 2f                 // mask for final 12-bit shift
    mov     w2, #0x13b             // w2 = 315
    dup     v3.4h, w2              // v3 = {315, 315, 315, 315}
    b       100f
0:  .word   0x03ff0000  // mask_h_lo: {0x0000, 0x03ff, 0x0000, 0x03ff, ...}
    .word   0x03ff0000
    .word   0x03ff0000
    .word   0x03ff0000
1:  .word   0x00000000  // mask_w_hi: {0x00000000, 0x000fffff, 0x00000000, 0x000fffff, ...}
    .word   0x000fffff
    .word   0x00000000
    .word   0x000fffff
2:  .word   0x000fffff  // final_12bit_mask: {0x00000000, 0x000fffff, 0x00000000, 0x000fffff, ...}
    .word   0x00000000
    .word   0x000fffff
    .word   0x00000000
100:
    add     x0, x0, #0xa           // Pre-add for sturb addressing
    ldp     q1, q0, [x1]           // Load 16 int16_t
    sqrdmulh v1.8h, v1.8h, v3.h[0] // v1 = (v1 * 315) >> 16 (rounding)
    sqrdmulh v0.8h, v0.8h, v3.h[0] // v0 = (v0 * 315) >> 16
    and     v1.16b, v1.16b, v4.16b // v1 &= 0x1f
    add     x1, x1, #0x20          // Advance input pointer by 32 bytes
    and     v0.16b, v0.16b, v4.16b // v0 &= 0x1f
    xtn     v2.8b, v1.8h           // v2 = low 8 bits of v1
    xtn2    v2.16b, v0.8h          // v2 += low 8 bits of v0
    and     v0.16b, v2.16b, v18.16b // v0 = v2 & 0x1f00 (bits 8-12)
    and     v2.16b, v2.16b, v17.16b // v2 = v2 & 0x1f (bits 0-4)
    sshr    v0.8h, v0.8h, #3       // v0 >>= 3
    orr     v0.16b, v0.16b, v2.16b // v0 |= v2
    and     v1.16b, v0.16b, v16.16b // v1 = v0 & mask_h_lo
    and     v0.16b, v0.16b, v7.16b // v0 = v0 & mask_w_lo
    sshr    v1.4s, v1.4s, #6       // v1 >>= 6
    orr     v1.16b, v1.16b, v0.16b // v1 |= v0
    and     v0.16b, v1.16b, v6.16b // v0 = v1 & mask_w_hi
    and     v1.16b, v1.16b, v5.16b // v1 = v1 & final_12bit_mask
    sshr    v0.2d, v0.2d, #12      // v0 >>= 12
    orr     v0.16b, v0.16b, v1.16b // v0 |= v1
    fmov    x2, d0                 // Move vector to gp registers
    mov     x3, v0.d[1]            // Extract high 64 bits
    fmov    d0, x2                 // Restore low 64 bits
    and     w7, w2, #0xffff        // Extract lower 16 bits
    lsr     w6, w2, #16            // Extract bits 16-31
    and     w5, w3, #0xffff        // Extract lower 16 bits of high
    mov     v0.d[1], x3            // Restore high 64 bits
    lsr     w12, w7, #8            // Prepare for byte packing
    lsr     w11, w6, #8
    lsr     w10, w5, #8
    ubfx    x2, x2, #32, #16       // Extract bits 32-47 (t[2])
    str     q0, [x13]              // Store packed result to stack
    ldrh    w4, [sp, #34]          // t[5] from stack
    ldrh    w8, [sp, #36]          // t[6] from stack
    sturb   w7, [x0, #-10]         // r[0]
    lsr     w9, w4, #8
    sturb   w12, [x0, #-9]         // r[1]
    sturb   w6, [x0, #-8]          // r[2]
    sturb   w11, [x0, #-7]         // r[3]
    sturb   w2, [x0, #-6]          // r[4]
    sturb   w5, [x0, #-5]          // r[5]
    sturb   w10, [x0, #-4]         // r[6]
    sturb   w4, [x0, #-3]          // r[7]
    sturb   w9, [x0, #-2]          // r[8]
    sturb   w8, [x0, #-1]          // r[9]
    add     w19, w19, #1           // round++
    cmp     x0, x14                // Check if done
    b.ne    100b
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #64
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMPolyCompress5)

// =============================================================================
// PolyVecCompress — Compress vector of polynomials (dispatch by parameter set)
// =============================================================================
// Dispatches based on ML-KEM parameter k:
//   k=4 (ML-KEM-1024): calls MLKEMPolyCompress11 for each polynomial (d=11)
//   k=2 (ML-KEM-512) or k=3 (ML-KEM-768): calls MLKEMPolyCompress10 for each polynomial (d=10)
//
// Arguments:
//   x0 = k  (ML-KEM dimension: 2, 3, or 4)
//   x1 = r  (uint8_t* — output compressed buffer)
//   x2 = a  (int16_t** — array of pointers to input polynomials)
//
// Output strides: 352 bytes/poly (d=11), 320 bytes/poly (d=10).
// =============================================================================
CRYPT_AARCH64_FUNC_START(PolyVecCompress)
AARCH64_PACIASP
    stp     x29, x30, [sp, #-64]!
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    mov     x29, sp
    mov     w19, w0
    mov     x20, x1
    mov     x21, x2
    cmp     w19, #4
    b.eq    .Lpolyveccompress_k4
    cmp     w19, #2
    b.eq    .Lpolyveccompress_k2k3
    cmp     w19, #3
    b.eq    .Lpolyveccompress_k2k3
    b       .Lpolyveccompress_done
.Lpolyveccompress_k4:
    mov     w22, #0
    mov     x23, #352
.Lpolyveccompress_k4_loop:
    madd    x0, x22, x23, x20
    ldr     x1, [x21, x22, lsl #3]
    bl      CRYPT_AARCH64_SYM(MLKEMPolyCompress11)
    add     w22, w22, #1
    cmp     w22, w19
    b.lo    .Lpolyveccompress_k4_loop
    b       .Lpolyveccompress_done
.Lpolyveccompress_k2k3:
    mov     w22, #0
    mov     x23, #320
.Lpolyveccompress_k2k3_loop:
    madd    x0, x22, x23, x20
    ldr     x1, [x21, x22, lsl #3]
    bl      CRYPT_AARCH64_SYM(MLKEMPolyCompress10)
    add     w22, w22, #1
    cmp     w22, w19
    b.lo    .Lpolyveccompress_k2k3_loop
.Lpolyveccompress_done:
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #64
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(PolyVecCompress)

// FIPS 203 Compress_11(x) = round(2^11 / q × x) mod 2^11
//
// Input:  x0 = uint8_t r[352] (output)
//         x1 = int16_t *a (input, 256 coefficients)
//
// Output: None (writes to r)
//
// Approximation using integer-only arithmetic:
//   compress = ((a × -20553) >> 16 + a/2 + a × 20) >> 5 & 0x7ff
//   where -20553 ≈ -2^16 × (20 - 32 × 2^11 / 3329).
//   sqdmulh computes (a × -20553 × 2) >> 16;
//   shadd computes (result + 0) >> 1 = result/2;
//   mla adds a × 20; srshr >> 5 completes the division with rounding.
//
// Bit packing via SHIFT_WITH_HOLES: 8 × 11-bit → 88 bits = 11 bytes.
//
// Loop: 32 iterations × 8 coefficients = 256 total
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMPolyCompress11)
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp
    add     x16, x0, #0x160        // End of output buffer (352 bytes)
    movi    v16.4s, #0x0           // Zero vector
    add     x15, sp, #0x10         // Temp buffer on stack
    movi    v2.4h, #0x14           // v2 = {20, 20, 20, 20}
    CRYPT_AARCH64_GET_RELA(x9, .LMLKEMPolyCompress11_mask11)
    ldr     q7, [x9]               // mask11 / mask for 0x7ff
    mov     w2, #0xffffafb7        // w2 = -20553
    movi    v6.4s, #0x7, msl #8    // mask_w_lo = {0x7ff, 0x7ff, 0x7ff, 0x7ff}
    dup     v4.4h, w2              // v4 = {-20553, -20553, -20553, -20553}
    CRYPT_AARCH64_GET_RELA(x9, .LMLKEMPolyCompress11_mask_h_lo)
    ldr     q5, [x9]               // mask_h_lo
    CRYPT_AARCH64_GET_RELA(x9, .LMLKEMPolyCompress11_mask_w_hi)
    ldr     q3, [x9]               // mask_w_hi
    b       100f
100:
    add     x0, x0, #0xb           // Pre-add for sturb addressing
    ldr     q1, [x1], #16          // Load 8 int16_t
    sqdmulh v0.8h, v1.8h, v4.h[0]  // v0 = (v1 * -20553) >> 16 (rounding)
    shadd   v0.8h, v0.8h, v16.8h   // v0 = (v0 + 0) >> 1
    mla     v0.8h, v1.8h, v2.h[0]  // v0 += v1 * 20
    srshr   v0.8h, v0.8h, #5       // v0 = (v0 + 16) >> 5 (rounding)
    and     v1.16b, v0.16b, v7.16b // v1 = v0 & mask11
    and     v0.16b, v0.16b, v6.16b // v0 = v0 & mask_w_lo
    sshr    v1.4s, v1.4s, #5       // v1 >>= 5
    orr     v1.16b, v1.16b, v0.16b // v1 |= v0
    and     v0.16b, v1.16b, v5.16b // v0 = v1 & mask_h_lo
    and     v1.16b, v1.16b, v3.16b // v1 = v1 & mask_w_hi
    sshr    v0.2d, v0.2d, #10      // v0 >>= 10
    orr     v0.16b, v0.16b, v1.16b // v0 |= v1
    fmov    x2, d0                 // Move vector to gp registers
    mov     x3, v0.d[1]            // Extract high 64 bits
    fmov    d0, x2                 // Restore low 64 bits
    lsr     x4, x2, #40            // Extract bits 40-63
    orr     x4, x4, x3, lsl #4     // Combine with low bits shifted
    and     w6, w2, #0xffff        // Extract lower 16 bits
    mov     v0.d[1], x3            // Restore high 64 bits
    lsr     w5, w2, #16            // Extract bits 16-31
    lsr     w14, w6, #8            // Prepare for byte packing
    ubfx    x12, x2, #32, #16      // Extract bits 32-47
    lsr     x11, x4, #8
    lsr     x10, x4, #16
    lsr     x9, x4, #24
    lsr     x8, x4, #32
    str     q0, [x15]              // Store packed result to stack
    lsr     x7, x4, #40
    lsr     w13, w5, #8
    sturb   w6, [x0, #-11]         // r[0]
    sturb   w14, [x0, #-10]        // r[1]
    sturb   w5, [x0, #-9]          // r[2]
    sturb   w13, [x0, #-8]         // r[3]
    sturb   w12, [x0, #-7]         // r[4]
    sturb   w4, [x0, #-6]          // r[5]
    sturb   w11, [x0, #-5]         // r[6]
    sturb   w10, [x0, #-4]         // r[7]
    sturb   w9, [x0, #-3]          // r[8]
    sturb   w8, [x0, #-2]          // r[9]
    sturb   w7, [x0, #-1]          // r[10]
    cmp     x0, x16                // Check if done
    b.ne    100b
    ldp     x29, x30, [sp], #48
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMPolyCompress11)


// ============================================================================
// MLKEMPolyCompress10 — 10-bit compression (k=2,3)
// FIPS 203 Compress_10(x) = round(2^10 / q × x) mod 2^10
// Input:  x0 = output buffer (320 bytes), x1 = input coefficients (256 int16_t)
// Output: 320 bytes (8 coefficients packed into 10 bytes)
//
// Same approximation scheme as Compress11 but with:
//   srshr >> 6 (instead of >> 5) and 0x3ff mask (instead of 0x7ff).
// Bit packing: 8 × 10-bit → 80 bits = 10 bytes per iteration.
// ============================================================================
// MLKEMPolyCompress10 - internal, called by PolyVecCompress
CRYPT_AARCH64_LOCAL_FUNC_START(MLKEMPolyCompress10)
AARCH64_PACIASP
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp

    // Setup loop
    mov     x7, x0                  // output pointer base
    add     x16, x0, #320           // end of output buffer

100:
    // Load 8 coefficients
    ldr     q1, [x1], #16

 // --- Setup: compression constant,15553, computation masks, bit packing constants ---
    mov     w3, #0xafb7             // w3 = -20553
    dup     v4.4h, w3
    movi    v5.8h, #0x0             // zero
    movi    v6.4h, #0x14            // 20

    sqdmulh v0.8h, v1.8h, v4.h[0]   // vqdmulhq_n_s16(avec, -20553)
    shadd   v0.8h, v0.8h, v5.8h     // vhaddq_s16(tvec, zero)
    mla     v0.8h, v1.8h, v6.h[0]   // vmlaq_n_s16(tvec, avec, 20)
    srshr   v0.8h, v0.8h, #6        // vrshrq_n_s16(tvec, 6)

    // --- SHIFT_WITH_HOLES_H: compress 16-bit lanes by removing gaps ---
    //   Step 1: mask even/odd half-words separately, shift odd down by 6
    movi    v6.4s, #0x3, msl #8     // mask_h_lo = {0x3ff, 0x3ff, 0x3ff, 0x3ff} (keeps all)
    CRYPT_AARCH64_GET_RELA(x9, .LMLKEMPolyCompress10_mask_h_hi)
    ldr     q7, [x9]                // mask_h_hi = {0, 0x3ff, 0, 0x3ff, 0, 0x3ff, 0, 0x3ff}
    and     v1.16b, v0.16b, v7.16b // tvec & mask_h_hi (odd indices)
    and     v0.16b, v0.16b, v6.16b // tvec & mask_h_lo (all indices, keeps low 10 bits)
    sshr    v1.4s, v1.4s, #6       // (tvec & mask_h_hi) >> 6 (32-bit shift)
    orr     v1.16b, v1.16b, v0.16b // combine: even indices stay, odd indices shifted
    // --- SHIFT_WITH_HOLES_S: compress 32-bit lanes by removing gaps ---
    //   Step 2: mask alternating 32-bit words, shift upper by 12
    CRYPT_AARCH64_GET_RELA(x9, .LMLKEMPolyCompress10_mask_w_lo)
    ldr     q5, [x9]                // mask_w_lo = {0xfffff, 0, 0xfffff, 0}
    CRYPT_AARCH64_GET_RELA(x9, .LMLKEMPolyCompress10_mask_w_hi)
    ldr     q7, [x9]                // mask_w_hi = {0, 0xfffff, 0, 0xfffff}
    and     v0.16b, v1.16b, v5.16b // tvec & mask_w_lo
    and     v1.16b, v1.16b, v7.16b // tvec & mask_w_hi
    sshr    v1.2d, v1.2d, #12      // (tvec & mask_w_hi) >> 12 (64-bit shift)
    orr     v0.16b, v0.16b, v1.16b // final result

    // Store to stack for byte extraction
    str     q0, [sp, #16]

    add     x0, x7, #10
    ldr     w2, [sp, #16]          // t[0], t[1]
    ldr     w3, [sp, #20]          // t[2], t[3]
    ldr     w4, [sp, #24]          // t[4], t[5]
    ldr     w5, [sp, #28]          // t[6], t[7]

    sturb   w2, [x0, #-10]
    lsr     w8, w2, #8
    sturb   w8, [x0, #-9]

    lsr     w8, w2, #16
    sturb   w8, [x0, #-8]
    lsr     w8, w2, #24
    sturb   w8, [x0, #-7]

    sturb   w3, [x0, #-6]

    sturb   w4, [x0, #-5]
    lsr     w8, w4, #8
    sturb   w8, [x0, #-4]

    lsr     w8, w4, #16
    sturb   w8, [x0, #-3]
    lsr     w8, w4, #24
    sturb   w8, [x0, #-2]

    sturb   w5, [x0, #-1]

    mov     x7, x0
    cmp     x0, x16
    b.ne    100b

    ldp     x29, x30, [sp], #48
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_LOCAL_FUNC_END(MLKEMPolyCompress10)

// ============================================================================
// MLKEMPolyCompress1 — 1-bit compression
// FIPS 203 Compress_1(x) = round(2 / q × x) mod 2
// Input:  x0 = output buffer (32 bytes), x1 = input coefficients (256 int16_t)
// Output: 32 bytes (each coefficient compressed to 1 bit)
//
// Approximation: sqdmulh × 315 → srshr >> 4 → and 0x1
// Then uses recursive halving to pack 256 × 1-bit into 32 bytes:
//   Stage 1: 16 vectors → 8  (xtn/xtn2 narrow pairs, sshr #7 + orr)
//   Stage 2: 8 vectors  → 4  (stride 32, sshr #6 + orr)
//   Stage 3: 4 vectors  → 2  (stride 64, sshr #4 + orr)
//   Final:   2 vectors  → 1  (xtn/xtn2 + store 16 bytes)
// Two outer iterations produce 2 × 16 = 32 output bytes.
// ============================================================================
CRYPT_AARCH64_FUNC_START(MLKEMPolyCompress1)
    stp     x29, x30, [sp, #-288]!
    mov     x29, sp

    movi    v2.8h, #0x1                // mask: keep only bit 0 after compression
    mov     w3, #0x13b                 // 315 ≈ round(2^15 × 2 / 3329)
    dup     v3.4h, w3                  // v3 = {315, 315, 315, 315}

    mov     x6, #0                     // outer loop counter (0 or 16)
    add     x7, sp, #16                // x7 = base of 256-byte temp storage on stack

100:
    // === Initialization: Load and compute 16 vectors ===
    add     x8, x0, x6                 // x8 = output pointer + counter (MUST be here!)
    // x5 = base of temp storage (from x7)
    // x2 = current temp pointer (from x7)
    // x3 = current input pointer
    mov     x5, x7                     // x5 = x7 = sp + 16 (constant)
    mov     x2, x7                     // x2 = x7 = sp + 16 (constant)
    add     x3, x1, x6, lsl #4         // input + counter * 16

    mov     x4, sp
    add     x4, x4, #272               // end of temp storage (sp + 16 + 16*16)

110:
    ldr     q0, [x3], #16
    sqdmulh v0.8h, v0.8h, v3.h[0]
    srshr   v0.8h, v0.8h, #4
    and     v0.16b, v0.16b, v2.16b
    str     q0, [x2], #16
    cmp     x2, x4
    b.ne    110b

    // === Stage 1: 16 -> 8 vectors (shift = 7) ===
    // Process pairs (j, j+1) -> j, skip the next one
    mov     x2, x7                     // x2 = x7 = sp + 16 (reset to constant!)

120:
    ldp     q4, q0, [x2]              // load tvec[j], tvec[j+1]
    xtn     v1.8b, v4.8h
    xtn2    v1.16b, v0.8h
    sshr    v0.8h, v1.8h, #7
    orr     v0.16b, v0.16b, v1.16b
    str     q0, [x2], #32             // skip next vector (stride 32)
    cmp     x2, x4
    b.ne    120b

    // === Stage 2: 8 -> 4 vectors (shift = 6) ===
    // Process pairs with stride 64 (tvec[0]&[2], tvec[4]&[6], etc.)
    mov     x5, x7                     // x5 = x7 = sp + 16 (reset to constant!)

130:
    ldr     q4, [x5]                  // tvec[j]
    ldr     q0, [x5, #32]             // tvec[j+2]
    xtn     v1.8b, v4.8h
    xtn2    v1.16b, v0.8h
    sshr    v0.8h, v1.8h, #6
    orr     v0.16b, v0.16b, v1.16b
    str     q0, [x5], #64             // stride 64
    cmp     x5, x4
    b.ne    130b

    // === Stage 3: 4 -> 2 vectors (shift = 4) ===
    // Load 4 vectors from fixed positions:
    // tvec[0] = sp + 16, tvec[4] = sp + 80
    // tvec[8] = sp + 144, tvec[12] = sp + 208
    ldr     q6, [sp, #16]             // tvec[0]
    add     x6, x6, #16               // advance loop counter (MUST be here!)
    ldr     q4, [sp, #80]             // tvec[4]
    ldr     q1, [sp, #144]            // tvec[8]
    ldr     q0, [sp, #208]            // tvec[12]

    // First half: narrow tvec[0] and tvec[4]
    xtn     v5.8b, v6.8h
    xtn2    v5.16b, v4.8h

    // Second half: narrow tvec[8] and tvec[12]
    xtn     v4.8b, v1.8h
    xtn2    v4.16b, v0.8h

    // Shift and OR both halves
    sshr    v1.8h, v5.8h, #4        // first half
    sshr    v0.8h, v4.8h, #4        // second half
    orr     v1.16b, v1.16b, v5.16b
    orr     v0.16b, v0.16b, v4.16b

    // === Final: 2 vectors -> 1 vector (16 bytes) ===
    xtn     v4.8b, v1.8h
    xtn2    v4.16b, v0.8h

    // Store intermediate results (matches NEON objdump)
    str     q0, [sp, #144]
    str     q4, [sp, #16]
    // Store 16 bytes to output
    str     q4, [x8]

    cmp     x6, #32                  // 2 iterations * 16
    b.ne    100b

    ldp     x29, x30, [sp], #288
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMPolyCompress1)

// ============================================================================
// MLKEMRejUniform — Rejection uniform sampling (FIPS 203, Algorithm 7)
// ============================================================================
//
// Input:  x0 = int16_t *r (output polynomial, up to 256 coefficients)
//         x1 = const uint8_t *buf (input random bytes, 504 bytes from XOF)
// Output: w0 = number of accepted coefficients (≤ 256)
//
// Algorithm: Extract 12-bit values from 3-byte groups, reject values ≥ Q.
//   Each 3-byte group [b0, b1, b2] yields two 12-bit candidates:
//     d1 = b0 | (b1 & 0xF) << 8
//     d2 = b1 >> 4 | b2 << 4
//
// Vectorized pipeline (main loop processes 48 bytes → up to 32 coefficients):
//   1. ld3 {v3,v4,v5}.16b:  load 16 × 3-byte groups (48 bytes)
//   2. zip1/zip2 + and:     extract d1 = (b0 | b1<<8) & 0xFFF
//   3. zip1/zip2 + ushr:    extract d2 = (b1 | b2<<8) >> 4
//   4. zip1/zip2 interleave: rearrange d1,d2 into 4 vectors of 8 candidates
//   5. cmhs v0 (=3328):     compare each candidate ≤ 3328 (i.e. < Q)
//   6. and + addv:          build per-vector acceptance bitmask
//   7. cnt:                 count accepted values per vector
//   8. tbl:                 compact accepted values using precomputed shuffle table
//   9. st1:                 store compacted values to output
//
// Tail loop: processes 24 bytes → up to 16 coefficients using 64-bit NEON.
// Final scalar copy: move tail results from temp buffer to output.
// ============================================================================
CRYPT_AARCH64_FUNC_START(MLKEMRejUniform)
    stp     x29, x30, [sp, #-176]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]

    mov     x19, x0                    // x19 = output base pointer
    mov     w20, #0                    // w20 = main output count
    mov     w21, #0                    // w21 = bytes consumed from input
    add     x24, sp, #80              // x24 = tail temp buffer (on stack)

    CRYPT_AARCH64_GET_RELA(x22, .Lrej_table_idx)
    CRYPT_AARCH64_GET_RELA(x23, .Lrej_table_idx_small)

    mov     w2, #3328                  // Q - 1 = 3328 (for cmhs comparison: ≤ 3328 means < Q)
    dup     v0.8h, w2
    mov     w2, #0xfff                 // 12-bit mask for extracting candidates
    dup     v1.8h, w2
    CRYPT_AARCH64_GET_RELA(x9, .Lrej_bit_table)
    ldr     q2, [x9]                   // bit_table = {1,2,4,8,16,32,64,128} for bitmask encoding

.Lrej_main_loop:
    cmp     w21, #480
    b.hs    .Lrej_main_end
    cmp     w20, #224
    b.hs    .Lrej_main_end

    ld3     {v3.16b, v4.16b, v5.16b}, [x1], #48
    add     w21, w21, #48

    zip1    v16.16b, v3.16b, v4.16b
    zip2    v17.16b, v3.16b, v4.16b
    and     v16.16b, v16.16b, v1.16b
    and     v17.16b, v17.16b, v1.16b

    zip1    v18.16b, v4.16b, v5.16b
    zip2    v19.16b, v4.16b, v5.16b
    ushr    v18.8h, v18.8h, #4
    ushr    v19.8h, v19.8h, #4

    zip1    v20.8h, v16.8h, v18.8h
    zip2    v21.8h, v16.8h, v18.8h
    zip1    v22.8h, v17.8h, v19.8h
    zip2    v23.8h, v17.8h, v19.8h

    cmhs    v24.8h, v0.8h, v20.8h
    cmhs    v25.8h, v0.8h, v21.8h
    cmhs    v26.8h, v0.8h, v22.8h
    cmhs    v27.8h, v0.8h, v23.8h

    and     v24.16b, v24.16b, v2.16b
    and     v25.16b, v25.16b, v2.16b
    and     v26.16b, v26.16b, v2.16b
    and     v27.16b, v27.16b, v2.16b

    addv    h28, v24.8h
    addv    h29, v25.8h
    addv    h30, v26.8h
    addv    h31, v27.8h

    umov    w6, v28.h[0]
    umov    w7, v29.h[0]
    umov    w8, v30.h[0]
    umov    w9, v31.h[0]

    orr     w10, w6, w7, lsl #8
    orr     w10, w10, w8, lsl #16
    orr     w10, w10, w9, lsl #24
    fmov    s28, w10
    cnt     v28.8b, v28.8b
    umov    w10, v28.b[0]
    umov    w11, v28.b[1]
    umov    w12, v28.b[2]
    umov    w13, v28.b[3]

    add     x14, x22, w6, uxtw #4
    ldr     q24, [x14]
    add     x14, x22, w7, uxtw #4
    ldr     q25, [x14]
    add     x14, x22, w8, uxtw #4
    ldr     q26, [x14]
    add     x14, x22, w9, uxtw #4
    ldr     q27, [x14]

    tbl     v20.16b, {v20.16b}, v24.16b
    tbl     v21.16b, {v21.16b}, v25.16b
    tbl     v22.16b, {v22.16b}, v26.16b
    tbl     v23.16b, {v23.16b}, v27.16b

    add     x14, x19, w20, uxtw #1
    st1     {v20.8h}, [x14]
    add     w20, w20, w10

    add     x14, x19, w20, uxtw #1
    st1     {v21.8h}, [x14]
    add     w20, w20, w11

    add     x14, x19, w20, uxtw #1
    st1     {v22.8h}, [x14]
    add     w20, w20, w12

    add     x14, x19, w20, uxtw #1
    st1     {v23.8h}, [x14]
    add     w20, w20, w13

    b       .Lrej_main_loop

.Lrej_main_end:
    mov     w25, #0

.Lrej_tail_loop:
    ld3     {v3.8b, v4.8b, v5.8b}, [x1], #24
    add     w21, w21, #24

    zip1    v16.8b, v3.8b, v4.8b
    zip2    v17.8b, v3.8b, v4.8b
    and     v16.8b, v16.8b, v1.8b
    and     v17.8b, v17.8b, v1.8b

    zip1    v18.8b, v4.8b, v5.8b
    zip2    v19.8b, v4.8b, v5.8b
    ushr    v18.4h, v18.4h, #4
    ushr    v19.4h, v19.4h, #4

    zip1    v20.4h, v16.4h, v18.4h
    zip2    v21.4h, v16.4h, v18.4h
    zip1    v22.4h, v17.4h, v19.4h
    zip2    v23.4h, v17.4h, v19.4h

    cmhs    v24.4h, v0.4h, v20.4h
    cmhs    v25.4h, v0.4h, v21.4h
    cmhs    v26.4h, v0.4h, v22.4h
    cmhs    v27.4h, v0.4h, v23.4h

    and     v24.8b, v24.8b, v2.8b
    and     v25.8b, v25.8b, v2.8b
    and     v26.8b, v26.8b, v2.8b
    and     v27.8b, v27.8b, v2.8b

    addv    h28, v24.4h
    addv    h29, v25.4h
    addv    h30, v26.4h
    addv    h31, v27.4h

    umov    w6, v28.h[0]
    umov    w7, v29.h[0]
    umov    w8, v30.h[0]
    umov    w9, v31.h[0]

    orr     w10, w6, w7, lsl #8
    orr     w10, w10, w8, lsl #16
    orr     w10, w10, w9, lsl #24
    fmov    s28, w10
    cnt     v28.8b, v28.8b
    umov    w10, v28.b[0]
    umov    w11, v28.b[1]
    umov    w12, v28.b[2]
    umov    w13, v28.b[3]

    add     x14, x23, w6, uxtw #3
    ld1     {v24.8b}, [x14]
    add     x14, x23, w7, uxtw #3
    ld1     {v25.8b}, [x14]
    add     x14, x23, w8, uxtw #3
    ld1     {v26.8b}, [x14]
    add     x14, x23, w9, uxtw #3
    ld1     {v27.8b}, [x14]

    tbl     v20.8b, {v20.16b}, v24.8b
    tbl     v21.8b, {v21.16b}, v25.8b
    tbl     v22.8b, {v22.16b}, v26.8b
    tbl     v23.8b, {v23.16b}, v27.8b

    add     x14, x24, w25, uxtw #1
    st1     {v20.4h}, [x14]
    add     w25, w25, w10

    add     x14, x24, w25, uxtw #1
    st1     {v21.4h}, [x14]
    add     w25, w25, w11

    add     x14, x24, w25, uxtw #1
    st1     {v22.4h}, [x14]
    add     w25, w25, w12

    add     x14, x24, w25, uxtw #1
    st1     {v23.4h}, [x14]
    add     w25, w25, w13

    mov     w14, #256
    sub     w14, w14, w20
    cmp     w25, w14
    b.hs    .Lrej_tail_end
    cmp     w21, #504
    b.lo    .Lrej_tail_loop

.Lrej_tail_end:
    mov     w6, #0

.Lrej_copy:
    cmp     w6, w25
    b.hs    .Lrej_done
    cmp     w20, #256
    b.hs    .Lrej_done

    add     x14, x24, w6, uxtw #1
    ldrh    w7, [x14]
    strh    wzr, [x14]
    add     x14, x19, w20, uxtw #1
    strh    w7, [x14]

    add     w6, w6, #1
    add     w20, w20, #1
    b       .Lrej_copy

.Lrej_done:
    mov     w0, w20

    ldp     x25, x26, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #176
    ret
    CRYPT_AARCH64_FUNC_END(MLKEMRejUniform)

CRYPT_AARCH64_RODATA_SECTION
.balign 16
.LMLKEMPolyCompress11_mask11:
    // mask11: {0x0000, 0x07ff, 0x0000, 0x07ff, ...}
    .word   0x07ff0000
    .word   0x07ff0000
    .word   0x07ff0000
    .word   0x07ff0000

.balign 16
.LMLKEMPolyCompress11_mask_h_lo:
    // mask_h_lo: {0, 0x3ff, 0, 0x3ff, ...} (as 16-bit packed)
    .word   0x00000000
    .word   0x003fffff
    .word   0x00000000
    .word   0x003fffff

.balign 16
.LMLKEMPolyCompress11_mask_w_hi:
    // mask_w_hi: {0xffff, 0x3f00, 0xffff, 0x3f00, ...} (as 16-bit packed)
    .word   0x003fffff
    .word   0x00000000
    .word   0x003fffff
    .word   0x00000000

.balign 16
.LMLKEMPolyCompress10_mask_h_hi:
    // mask_h_hi = {0, 0x3ff, 0, 0x3ff, 0, 0x3ff, 0, 0x3ff}
    .short  0
    .short  0x3ff
    .short  0
    .short  0x3ff
    .short  0
    .short  0x3ff
    .short  0
    .short  0x3ff

.balign 16
.LMLKEMPolyCompress10_mask_w_lo:
    // mask_w_lo = {0xfffff, 0, 0xfffff, 0}
    .word   0xfffff
    .word   0
    .word   0xfffff
    .word   0

.balign 16
.LMLKEMPolyCompress10_mask_w_hi:
    // mask_w_hi = {0, 0xfffff, 0, 0xfffff}
    .word   0
    .word   0xfffff
    .word   0
    .word   0xfffff

.balign 16
.LCBD3_shuffle:
    .byte   0, 1, 2, 0xFF, 3, 4, 5, 0xFF, 6, 7, 8, 0xFF, 9, 10, 11, 0xFF

.balign 16
.Lrej_bit_table:
    .short  1, 2, 4, 8, 16, 32, 64, 128

.balign 16
.Lrej_table_idx:
    .byte   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 0
    .byte   0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 1
    .byte   0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 2
    .byte   0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 3
    .byte   0x04, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 4
    .byte   0x00, 0x01, 0x04, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 5
    .byte   0x02, 0x03, 0x04, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 6
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 7
    .byte   0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 8
    .byte   0x00, 0x01, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 9
    .byte   0x02, 0x03, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 10
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 11
    .byte   0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 12
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 13
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 14
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 15
    .byte   0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 16
    .byte   0x00, 0x01, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 17
    .byte   0x02, 0x03, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 18
    .byte   0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 19
    .byte   0x04, 0x05, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 20
    .byte   0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 21
    .byte   0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 22
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 23
    .byte   0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 24
    .byte   0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 25
    .byte   0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 26
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 27
    .byte   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 28
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 29
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 30
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 31
    .byte   0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 32
    .byte   0x00, 0x01, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 33
    .byte   0x02, 0x03, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 34
    .byte   0x00, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 35
    .byte   0x04, 0x05, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 36
    .byte   0x00, 0x01, 0x04, 0x05, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 37
    .byte   0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 38
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 39
    .byte   0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 40
    .byte   0x00, 0x01, 0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 41
    .byte   0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 42
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 43
    .byte   0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 44
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 45
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 46
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 47
    .byte   0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 48
    .byte   0x00, 0x01, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 49
    .byte   0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 50
    .byte   0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 51
    .byte   0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 52
    .byte   0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 53
    .byte   0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 54
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 55
    .byte   0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 56
    .byte   0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 57
    .byte   0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 58
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 59
    .byte   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 60
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 61
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 62
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff  // 63
    .byte   0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 64
    .byte   0x00, 0x01, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 65
    .byte   0x02, 0x03, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 66
    .byte   0x00, 0x01, 0x02, 0x03, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 67
    .byte   0x04, 0x05, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 68
    .byte   0x00, 0x01, 0x04, 0x05, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 69
    .byte   0x02, 0x03, 0x04, 0x05, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 70
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 71
    .byte   0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 72
    .byte   0x00, 0x01, 0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 73
    .byte   0x02, 0x03, 0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 74
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 75
    .byte   0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 76
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 77
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 78
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 79
    .byte   0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 80
    .byte   0x00, 0x01, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 81
    .byte   0x02, 0x03, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 82
    .byte   0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 83
    .byte   0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 84
    .byte   0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 85
    .byte   0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 86
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 87
    .byte   0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 88
    .byte   0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 89
    .byte   0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 90
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 91
    .byte   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 92
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 93
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 94
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff  // 95
    .byte   0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 96
    .byte   0x00, 0x01, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 97
    .byte   0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 98
    .byte   0x00, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 99
    .byte   0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 100
    .byte   0x00, 0x01, 0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 101
    .byte   0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 102
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 103
    .byte   0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 104
    .byte   0x00, 0x01, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 105
    .byte   0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 106
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 107
    .byte   0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 108
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 109
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 110
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff  // 111
    .byte   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 112
    .byte   0x00, 0x01, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 113
    .byte   0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 114
    .byte   0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 115
    .byte   0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 116
    .byte   0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 117
    .byte   0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 118
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff  // 119
    .byte   0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 120
    .byte   0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 121
    .byte   0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 122
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff  // 123
    .byte   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 124
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff  // 125
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff  // 126
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff  // 127
    .byte   0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 128
    .byte   0x00, 0x01, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 129
    .byte   0x02, 0x03, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 130
    .byte   0x00, 0x01, 0x02, 0x03, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 131
    .byte   0x04, 0x05, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 132
    .byte   0x00, 0x01, 0x04, 0x05, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 133
    .byte   0x02, 0x03, 0x04, 0x05, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 134
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 135
    .byte   0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 136
    .byte   0x00, 0x01, 0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 137
    .byte   0x02, 0x03, 0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 138
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 139
    .byte   0x04, 0x05, 0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 140
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 141
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 142
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 143
    .byte   0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 144
    .byte   0x00, 0x01, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 145
    .byte   0x02, 0x03, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 146
    .byte   0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 147
    .byte   0x04, 0x05, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 148
    .byte   0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 149
    .byte   0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 150
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 151
    .byte   0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 152
    .byte   0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 153
    .byte   0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 154
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 155
    .byte   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 156
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 157
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 158
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 159
    .byte   0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 160
    .byte   0x00, 0x01, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 161
    .byte   0x02, 0x03, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 162
    .byte   0x00, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 163
    .byte   0x04, 0x05, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 164
    .byte   0x00, 0x01, 0x04, 0x05, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 165
    .byte   0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 166
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 167
    .byte   0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 168
    .byte   0x00, 0x01, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 169
    .byte   0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 170
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 171
    .byte   0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 172
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 173
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 174
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 175
    .byte   0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 176
    .byte   0x00, 0x01, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 177
    .byte   0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 178
    .byte   0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 179
    .byte   0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 180
    .byte   0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 181
    .byte   0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 182
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 183
    .byte   0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 184
    .byte   0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 185
    .byte   0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 186
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 187
    .byte   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 188
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 189
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 190
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff  // 191
    .byte   0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 192
    .byte   0x00, 0x01, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 193
    .byte   0x02, 0x03, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 194
    .byte   0x00, 0x01, 0x02, 0x03, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 195
    .byte   0x04, 0x05, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 196
    .byte   0x00, 0x01, 0x04, 0x05, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 197
    .byte   0x02, 0x03, 0x04, 0x05, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 198
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 199
    .byte   0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 200
    .byte   0x00, 0x01, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 201
    .byte   0x02, 0x03, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 202
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 203
    .byte   0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 204
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 205
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 206
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 207
    .byte   0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 208
    .byte   0x00, 0x01, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 209
    .byte   0x02, 0x03, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 210
    .byte   0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 211
    .byte   0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 212
    .byte   0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 213
    .byte   0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 214
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 215
    .byte   0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 216
    .byte   0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 217
    .byte   0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 218
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 219
    .byte   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 220
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 221
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 222
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff  // 223
    .byte   0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 224
    .byte   0x00, 0x01, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 225
    .byte   0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 226
    .byte   0x00, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 227
    .byte   0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 228
    .byte   0x00, 0x01, 0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 229
    .byte   0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 230
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 231
    .byte   0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 232
    .byte   0x00, 0x01, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 233
    .byte   0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 234
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 235
    .byte   0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 236
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 237
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 238
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff  // 239
    .byte   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 240
    .byte   0x00, 0x01, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 241
    .byte   0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 242
    .byte   0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 243
    .byte   0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 244
    .byte   0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 245
    .byte   0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 246
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff  // 247
    .byte   0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 248
    .byte   0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 249
    .byte   0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 250
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff  // 251
    .byte   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff  // 252
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff  // 253
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff  // 254
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f  // 255

.balign 8
.Lrej_table_idx_small:
    .byte   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 0
    .byte   0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 1
    .byte   0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 2
    .byte   0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff  // 3
    .byte   0x04, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 4
    .byte   0x00, 0x01, 0x04, 0x05, 0xff, 0xff, 0xff, 0xff  // 5
    .byte   0x02, 0x03, 0x04, 0x05, 0xff, 0xff, 0xff, 0xff  // 6
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff, 0xff  // 7
    .byte   0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // 8
    .byte   0x00, 0x01, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff  // 9
    .byte   0x02, 0x03, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff  // 10
    .byte   0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0xff, 0xff  // 11
    .byte   0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff  // 12
    .byte   0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff, 0xff  // 13
    .byte   0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff, 0xff  // 14
    .byte   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07  // 15

.text
#endif
