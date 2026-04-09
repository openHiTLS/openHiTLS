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
 * ML-KEM Number Theoretic Transform (NTT) — ARMv8 NEON Implementation
 * ============================================================================
 *
 * References:
 *   [NeonNTT]  Becker, Hwang, Kannwischer, Yang, Yang.
 *              "Neon NTT: Faster Dilithium, Kyber, and Saber on Cortex-A72
 *              and Apple M1." https://eprint.iacr.org/2021/986
 *   [FIPS203]  NIST FIPS 203 — ML-KEM Standard, Algorithms 9 & 10.
 *
 * Algorithm Overview:
 *   NTT operates on polynomials in R_q = Z_q[X]/(X^256 + 1), q = 3329.
 *   The 256-coefficient polynomial is transformed in-place using 7 layers
 *   of Cooley-Tukey (CT) butterflies (forward NTT) or Gentleman-Santer (GS)
 *   butterflies (inverse NTT).
 *
 *   Each butterfly: (a, b) → (a + b·ω, a − b·ω)  [CT forward]
 *                   (a, b) → (a + b, (a − b)·ω)   [GS inverse]
 *   where ω is a precomputed twiddle factor in Montgomery domain.
 *
 * Split into Top and Bot Functions:
 *   Due to ARMv8 having only 32 NEON registers (v0-v31), processing all 256
 *   coefficients (= 32 NEON registers of 8×int16) at once is infeasible.
 *   The NTT is split into two halves:
 *
 *   - NTT_top: Layers 1-3 (stride 128 → 64 → 32 coefficients)
 *     Processes all 256 coefficients, loading 16 vectors (v4-v19) at 32-byte
 *     stride from src[0], src[32], ..., src[15×32]. After layer 3, the 16
 *     groups of 8 coefficients are independent and can be processed by bot.
 *     Then shifts to src+16 and processes the second half interleaved.
 *
 *   - NTT_bot: Layers 4-7 (stride 16 → 8 → 4 → 2 coefficients)
 *     Processes 64-coefficient blocks. Uses 4×4 transpose (trn1/trn2) to
 *     rearrange data layout for the final layers where butterfly stride
 *     drops below 8 (the NEON lane width), then applies Barrett reduction
 *     at the end to keep coefficients bounded.
 *
 * Montgomery Multiplication Pattern (used throughout):
 *   For computing (a × twiddle) mod Q in Montgomery domain:
 *     mul      lo.8H, a.8H, tw_lo.H[i]    // lo = a × tw_lo (low 16 bits)
 *     sqrdmulh hi.8H, a.8H, tw_hi.H[i]    // hi ≈ a × tw_hi >> 15
 *     mls      lo.8H, hi.8H, Q.H[0]       // lo = lo − hi × Q
 *   Where (tw_lo, tw_hi) are stored as adjacent pairs in the twiddle table.
 *   This is equivalent to Montgomery reduction of a 32-bit product:
 *     result = (a × twiddle × R^{-1}) mod Q, where R = 2^16.
 *
 * Barrett Reduction Pattern (used in NTT_bot final stage):
 *   For reducing a coefficient modulo Q = 3329:
 *     sqdmulh  t.8H, a.8H, M.H[0]    // t = (a × M × 2) >> 16, M = 20159
 *     srshr    t.8H, t.8H, #11        // t = round(t >> 11) ≈ round(a / Q)
 *     mls      a.8H, t.8H, Q.H[0]    // a = a − t × Q
 *
 * Twiddle Table Layout (MLKEM_NTT_TWIDDLE_TABLE):
 *   Twiddle factors are stored as (tw_lo, tw_hi) pairs for Montgomery mul.
 *   Layers 1-3 use v0-v3 (loaded once, shared twiddles for large strides).
 *   Layers 4-7 use per-iteration twiddles loaded from advancing table ptr.
 *
 * Data Memory Layout:
 *   Input polynomial: int16_t a[256], stored contiguously (512 bytes).
 *   NTT_top accesses coefficients at stride 32 bytes = 16 coefficients.
 *   NTT_bot splits into src0 (first 128 coeffs) and src1 (last 128 coeffs),
 *   processing 64-byte blocks with 4×4 transpose shuffle between stages.
 *
 * Functions:
 *   MLKEM_NTT_top(int16_t *a, const int16_t *twiddle_table)
 *   MLKEM_NTT_bot(int16_t *a, const int16_t *twiddle_table)
 *   MLKEM_INTT_bot(int16_t *a, const int16_t *twiddle_table)
 *   MLKEM_INTT_top(int16_t *a, const int16_t *twiddle_table)
 *
 * Call order:  NTT  = NTT_top  then NTT_bot
 *              INTT = INTT_bot then INTT_top
 * ============================================================================
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MLKEM

#include "crypt_arm.h"
CRYPT_AARCH64_ARCH_BASE

// =============================================================================
// MLKEM_NTT_top — Forward NTT, Layers 1-3 (Cooley-Tukey butterfly)
// =============================================================================
//
// Signature: void MLKEM_NTT_top(int16_t *a, const int16_t *table)
//   x0 (src):   pointer to 256-coefficient polynomial (in/out)
//   x1 (table): pointer to twiddle factor table (tw_lo, tw_hi pairs in v0-v3)
//
// Algorithm:
//   1. Load twiddle factors for layers 1-3 into v0-v3; set v0.H[0] = Q = 3329
//   2. Pass 1 (even vectors): load 16 vectors from src[i*32], i=0..15
//   3. Layer 1 (stride 128): CT butterfly with 1 twiddle pair per 128-coeff half
//   4. Layer 2 (stride 64):  CT butterfly with 2 twiddle pairs (v1.H[0-7])
//   5. Layer 3 (stride 32):  CT butterfly with 4 twiddle pairs (v2/v3.H[0-7])
//   6. Store pass 1 results; begin loading pass 2 odd-indexed vectors
//   7. Pass 2 (odd vectors): repeat layers 1-3 on src[i*32+16], i=0..15
//   8. Store pass 2 results and return
//
// Register allocation:
//   v0-v3:   twiddle factors (v0.H[0] = Q for Montgomery reduction mls)
//   v4-v19:  polynomial coefficients (16 vectors × 8 int16 lanes = 128 coeffs/pass)
//   v20-v23: Montgomery mul intermediate (twiddle × coeff high part)
//   v28-v31: Montgomery mul low products (twiddle × coeff low part)
//   x0 (src):    polynomial pointer (in/out)
//   x1 (table):  twiddle table pointer
//   w8 (Q):      modulus 3329
//   x11 (counter): loop counter (unused, reserved)
//
// Notes:
//   Two-pass design handles 256 coefficients with only 32 NEON registers.
//   Pipeline interleaving: loads are issued during sqrdmulh latency (3-4 cycles)
//   to hide memory latency. After layer 3, data is in 16 independent blocks of
//   16 coefficients each, ready for NTT_bot processing.
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEM_NTT_top)
AARCH64_PACIASP
    sub sp, sp, #(4*16)
    stp  d8,  d9, [sp, #0*16]
    stp d10, d11, [sp, #1*16]
    stp d12, d13, [sp, #2*16]
    stp d14, d15, [sp, #3*16]
    Q         .req w8
    src       .req x0
    table     .req x1
    counter   .req x11

    mov Q, #3329              // Q (ML-KEM modulus)

    ldr  q0, [table, # 0*16]
    ldr  q1, [table, # 1*16]
    ldr  q2, [table, # 2*16]
    ldr  q3, [table, # 3*16]

    mov v0.H[0], Q

    // ============================= Pass 1 (even vectors) =============================
    // Load upper half coefficients (indices 8-15 at stride 32)
    ldr q13, [src, # 9*32]
    ldr q15, [src, #11*32]
    ldr q17, [src, #13*32]
    ldr q19, [src, #15*32]

    // ========== Layer 1 (stride 128): 1 twiddle v0.H[2,3], 8 butterflies ==========
    // Montgomery mul: result = (coeff × twiddle × R^{-1}) mod Q
    //   mul   lo = coeff × tw_lo          (low 16 bits of product)
    //   sqrdmulh hi ≈ (coeff × tw_hi × 2) >> 16  (approximate high part)
    //   mls   lo = lo − hi × Q            (Montgomery reduction)
    mul      v28.8H, v13.8H, v0.H[2]
    mul      v29.8H, v15.8H, v0.H[2]
    mul      v30.8H, v17.8H, v0.H[2]
    mul      v31.8H, v19.8H, v0.H[2]

    ldr         q5, [src, #1*32]
    sqrdmulh v13.8H, v13.8H, v0.H[3]
    ldr         q7, [src, #3*32]
    sqrdmulh v15.8H, v15.8H, v0.H[3]
    ldr         q9, [src, #5*32]
    sqrdmulh v17.8H, v17.8H, v0.H[3]
    ldr         q11, [src, #7*32]
    sqrdmulh v19.8H, v19.8H, v0.H[3]

    mls      v28.8H, v13.8H, v0.H[0]
    mls      v29.8H, v15.8H, v0.H[0]
    mls      v30.8H, v17.8H, v0.H[0]
    mls      v31.8H, v19.8H, v0.H[0]

    ldr         q12, [src, #8*32]
    sub      v13.8H, v5.8H, v28.8H
    mul      v20.8H, v12.8H, v0.H[2]
    ldr         q14, [src, #10*32]
    sub      v15.8H, v7.8H, v29.8H
    mul      v21.8H, v14.8H, v0.H[2]
    ldr         q16, [src, #12*32]
    sub      v17.8H, v9.8H, v30.8H
    mul      v22.8H, v16.8H, v0.H[2]
    ldr         q18, [src, #14*32]
    sub      v19.8H, v11.8H, v31.8H
    mul      v23.8H, v18.8H, v0.H[2]

    ldr         q4, [src, #0*32]
    add      v5.8H, v5.8H, v28.8H
    sqrdmulh v12.8H, v12.8H, v0.H[3]
    ldr         q6, [src, #2*32]
    add      v7.8H, v7.8H, v29.8H
    sqrdmulh v14.8H, v14.8H, v0.H[3]
    ldr         q8, [src, #4*32]
    add      v9.8H, v9.8H, v30.8H
    sqrdmulh v16.8H, v16.8H, v0.H[3]
    ldr         q10, [src, #6*32]
    add      v11.8H, v11.8H, v31.8H
    sqrdmulh v18.8H, v18.8H, v0.H[3]

    mls      v20.8H, v12.8H, v0.H[0]
    mls      v21.8H, v14.8H, v0.H[0]
    mls      v22.8H, v16.8H, v0.H[0]
    mls      v23.8H, v18.8H, v0.H[0]

    // ========== Layer 1 continued: CT butterfly (a,b) → (a+twiddle·b, a−twiddle·b) ==========
    // The twiddle product twiddle·b was computed above; now complete the butterfly.
    sub      v12.8H, v4.8H, v20.8H
    mul      v28.8H, v9.8H, v0.H[4]
    sub      v14.8H, v6.8H, v21.8H
    mul      v29.8H, v11.8H, v0.H[4]
    sub      v16.8H, v8.8H, v22.8H
    mul      v30.8H, v17.8H, v0.H[6]
    sub      v18.8H, v10.8H, v23.8H
    mul      v31.8H, v19.8H, v0.H[6]

    add      v4.8H, v4.8H, v20.8H
    sqrdmulh v9.8H, v9.8H, v0.H[5]
    add      v6.8H, v6.8H, v21.8H
    sqrdmulh v11.8H, v11.8H, v0.H[5]
    add      v8.8H, v8.8H, v22.8H
    sqrdmulh v17.8H, v17.8H, v0.H[7]
    add      v10.8H, v10.8H, v23.8H
    sqrdmulh v19.8H, v19.8H, v0.H[7]

    mls      v28.8H, v9.8H, v0.H[0]
    mls      v29.8H, v11.8H, v0.H[0]
    mls      v30.8H, v17.8H, v0.H[0]
    mls      v31.8H, v19.8H, v0.H[0]

    // ========== Layer 1 second half: remaining 4 butterflies with v0.H[4-7] ==========
    sub      v9.8H, v5.8H, v28.8H
    mul      v20.8H, v8.8H, v0.H[4]
    sub      v11.8H, v7.8H, v29.8H
    mul      v21.8H, v10.8H, v0.H[4]
    sub      v17.8H, v13.8H, v30.8H
    mul      v22.8H, v16.8H, v0.H[6]
    sub      v19.8H, v15.8H, v31.8H
    mul      v23.8H, v18.8H, v0.H[6]

    add      v5.8H, v5.8H, v28.8H
    sqrdmulh v8.8H, v8.8H, v0.H[5]
    add      v7.8H, v7.8H, v29.8H
    sqrdmulh v10.8H, v10.8H, v0.H[5]
    add      v13.8H, v13.8H, v30.8H
    sqrdmulh v16.8H, v16.8H, v0.H[7]
    add      v15.8H, v15.8H, v31.8H
    sqrdmulh v18.8H, v18.8H, v0.H[7]

    mls      v20.8H, v8.8H, v0.H[0]
    mls      v21.8H, v10.8H, v0.H[0]
    mls      v22.8H, v16.8H, v0.H[0]
    mls      v23.8H, v18.8H, v0.H[0]

    // ========== Layer 2 (stride 64): 2 twiddles, butterflies with v1.H[0-7] ==========
    sub      v8.8H, v4.8H, v20.8H
    mul      v28.8H, v7.8H, v1.H[0]
    sub      v10.8H, v6.8H, v21.8H
    mul      v29.8H, v11.8H, v1.H[2]
    sub      v16.8H, v12.8H, v22.8H
    mul      v30.8H, v15.8H, v1.H[4]
    sub      v18.8H, v14.8H, v23.8H
    mul      v31.8H, v19.8H, v1.H[6]

    add      v4.8H, v4.8H, v20.8H
    sqrdmulh v7.8H, v7.8H, v1.H[1]
    add      v6.8H, v6.8H, v21.8H
    sqrdmulh v11.8H, v11.8H, v1.H[3]
    add      v12.8H, v12.8H, v22.8H
    sqrdmulh v15.8H, v15.8H, v1.H[5]
    add      v14.8H, v14.8H, v23.8H
    sqrdmulh v19.8H, v19.8H, v1.H[7]

    mls      v28.8H, v7.8H, v0.H[0]
    mls      v29.8H, v11.8H, v0.H[0]
    mls      v30.8H, v15.8H, v0.H[0]
    mls      v31.8H, v19.8H, v0.H[0]

    // ========== Layer 2 second half: remaining butterflies with v1.H[0-7] ==========
    sub      v7.8H, v5.8H, v28.8H
    mul      v20.8H, v6.8H, v1.H[0]
    sub      v11.8H, v9.8H, v29.8H
    mul      v21.8H, v10.8H, v1.H[2]
    sub      v15.8H, v13.8H, v30.8H
    mul      v22.8H, v14.8H, v1.H[4]
    sub      v19.8H, v17.8H, v31.8H
    mul      v23.8H, v18.8H, v1.H[6]

    add      v5.8H, v5.8H, v28.8H
    sqrdmulh v6.8H, v6.8H, v1.H[1]
    add      v9.8H, v9.8H, v29.8H
    sqrdmulh v10.8H, v10.8H, v1.H[3]
    add      v13.8H, v13.8H, v30.8H
    sqrdmulh v14.8H, v14.8H, v1.H[5]
    add      v17.8H, v17.8H, v31.8H
    sqrdmulh v18.8H, v18.8H, v1.H[7]

    mls      v20.8H, v6.8H, v0.H[0]
    mls      v21.8H, v10.8H, v0.H[0]
    mls      v22.8H, v14.8H, v0.H[0]
    mls      v23.8H, v18.8H, v0.H[0]

    // ========== Layer 3 (stride 32): 4 twiddles, butterflies with v2.H[0-7] ==========
    sub      v6.8H, v4.8H, v20.8H
    mul      v28.8H, v5.8H, v2.H[0]
    sub      v10.8H, v8.8H, v21.8H
    mul      v29.8H, v7.8H, v2.H[2]
    sub      v14.8H, v12.8H, v22.8H
    mul      v30.8H, v9.8H, v2.H[4]
    sub      v18.8H, v16.8H, v23.8H
    mul      v31.8H, v11.8H, v2.H[6]

    add      v4.8H, v4.8H, v20.8H
    sqrdmulh v5.8H, v5.8H, v2.H[1]
    add      v8.8H, v8.8H, v21.8H
    sqrdmulh v7.8H, v7.8H, v2.H[3]
    add      v12.8H, v12.8H, v22.8H
    sqrdmulh v9.8H, v9.8H, v2.H[5]
    add      v16.8H, v16.8H, v23.8H
    sqrdmulh v11.8H, v11.8H, v2.H[7]

    mls      v28.8H, v5.8H, v0.H[0]
    mls      v29.8H, v7.8H, v0.H[0]
    mls      v30.8H, v9.8H, v0.H[0]
    mls      v31.8H, v11.8H, v0.H[0]

    // ========== Layer 3 second half: 4 twiddles v3.H[0-7] + store pass 1 results ==========
    // Complete Layer 3 butterflies for the remaining coefficient pairs,
    // store pass 1 (even vector) results, and begin loading pass 2 (odd vector) data.
    sub      v5.8H, v4.8H, v28.8H
    str         q5, [src, #1*32]
    mul      v20.8H, v13.8H, v3.H[0]
    sub      v7.8H, v6.8H, v29.8H
    str         q7, [src, #3*32]
    mul      v21.8H, v15.8H, v3.H[2]
    sub      v9.8H, v8.8H, v30.8H
    str         q9, [src, #5*32]
    mul      v22.8H, v17.8H, v3.H[4]
    sub      v11.8H, v10.8H, v31.8H
    str         q11, [src, #7*32]
    mul      v23.8H, v19.8H, v3.H[6]

    ldr         q5, [src, #(16+1*32)]
    add      v4.8H, v4.8H, v28.8H
    sqrdmulh v13.8H, v13.8H, v3.H[1]
    ldr         q7, [src, #(16+3*32)]
    add      v6.8H, v6.8H, v29.8H
    sqrdmulh v15.8H, v15.8H, v3.H[3]
    ldr         q9, [src, #(16+5*32)]
    add      v8.8H, v8.8H, v30.8H
    sqrdmulh v17.8H, v17.8H, v3.H[5]
    ldr         q11, [src, #(16+7*32)]
    add      v10.8H, v10.8H, v31.8H
    sqrdmulh v19.8H, v19.8H, v3.H[7]

    str         q4, [src, #0*32]
    mls      v20.8H, v13.8H, v0.H[0]
    str         q6, [src, #2*32]
    mls      v21.8H, v15.8H, v0.H[0]
    str         q8, [src, #4*32]
    mls      v22.8H, v17.8H, v0.H[0]
    str         q10, [src, #6*32]
    mls      v23.8H, v19.8H, v0.H[0]

    sub     v13.8H, v12.8H, v20.8H
    str        q13, [src, #9*32]
    ldr        q13, [src, #(16+9*32)]
    sub     v15.8H, v14.8H, v21.8H
    str        q15, [src, #11*32]
    ldr        q15, [src, #(16+11*32)]
    sub     v17.8H, v16.8H, v22.8H
    str        q17, [src, #13*32]
    ldr        q17, [src, #(16+13*32)]
    sub     v19.8H, v18.8H, v23.8H
    str        q19, [src, #15*32]
    ldr        q19, [src, #(16+15*32)]

    add     v12.8H, v12.8H, v20.8H
    str        q12, [src, #8*32]
    add     v14.8H, v14.8H, v21.8H
    str        q14, [src, #10*32]
    add     v16.8H, v16.8H, v22.8H
    str        q16, [src, #12*32]
    add     v18.8H, v18.8H, v23.8H
    str        q18, [src, #14*32]

    // ============================= Pass 2 (odd vectors, offset +16) =============================
    // Same Layer 1-3 structure as pass 1, but on the odd-indexed 128-bit vectors
    // (i.e., coefficients at src+16, src+48, ..., src+16+15*32).
    // ========== Layer 1 (stride 128): Montgomery mul + butterfly ==========
    mul      v28.8H, v13.8H, v0.H[2]
    mul      v29.8H, v15.8H, v0.H[2]
    mul      v30.8H, v17.8H, v0.H[2]
    mul      v31.8H, v19.8H, v0.H[2]

    ldr         q12, [src, #(16+8*32)]
    sqrdmulh v13.8H, v13.8H, v0.H[3]
    ldr         q14, [src, #(16+10*32)]
    sqrdmulh v15.8H, v15.8H, v0.H[3]
    ldr         q16, [src, #(16+12*32)]
    sqrdmulh v17.8H, v17.8H, v0.H[3]
    ldr         q18, [src, #(16+14*32)]
    sqrdmulh v19.8H, v19.8H, v0.H[3]

    mls      v28.8H, v13.8H, v0.H[0]
    mls      v29.8H, v15.8H, v0.H[0]
    mls      v30.8H, v17.8H, v0.H[0]
    mls      v31.8H, v19.8H, v0.H[0]

    ldr         q4, [src, #(16+0*32)]
    sub      v13.8H, v5.8H, v28.8H
    mul      v20.8H, v12.8H, v0.H[2]
    ldr         q6, [src, #(16+2*32)]
    sub      v15.8H, v7.8H, v29.8H
    mul      v21.8H, v14.8H, v0.H[2]
    ldr         q8, [src, #(16+4*32)]
    sub      v17.8H, v9.8H, v30.8H
    mul      v22.8H, v16.8H, v0.H[2]
    ldr         q10, [src, #(16+6*32)]
    sub      v19.8H, v11.8H, v31.8H
    mul      v23.8H, v18.8H, v0.H[2]

    add      v5.8H, v5.8H, v28.8H
    sqrdmulh v12.8H, v12.8H, v0.H[3]
    add      v7.8H, v7.8H, v29.8H
    sqrdmulh v14.8H, v14.8H, v0.H[3]
    add      v9.8H, v9.8H, v30.8H
    sqrdmulh v16.8H, v16.8H, v0.H[3]
    add      v11.8H, v11.8H, v31.8H
    sqrdmulh v18.8H, v18.8H, v0.H[3]

    mls      v20.8H, v12.8H, v0.H[0]
    mls      v21.8H, v14.8H, v0.H[0]
    mls      v22.8H, v16.8H, v0.H[0]
    mls      v23.8H, v18.8H, v0.H[0]

    sub      v12.8H, v4.8H, v20.8H
    mul      v28.8H, v9.8H, v0.H[4]
    sub      v14.8H, v6.8H, v21.8H
    mul      v29.8H, v11.8H, v0.H[4]
    sub      v16.8H, v8.8H, v22.8H
    mul      v30.8H, v17.8H, v0.H[6]
    sub      v18.8H, v10.8H, v23.8H
    mul      v31.8H, v19.8H, v0.H[6]

    add      v4.8H, v4.8H, v20.8H
    sqrdmulh v9.8H, v9.8H, v0.H[5]
    add      v6.8H, v6.8H, v21.8H
    sqrdmulh v11.8H, v11.8H, v0.H[5]
    add      v8.8H, v8.8H, v22.8H
    sqrdmulh v17.8H, v17.8H, v0.H[7]
    add      v10.8H, v10.8H, v23.8H
    sqrdmulh v19.8H, v19.8H, v0.H[7]

    mls      v28.8H, v9.8H, v0.H[0]
    mls      v29.8H, v11.8H, v0.H[0]
    mls      v30.8H, v17.8H, v0.H[0]
    mls      v31.8H, v19.8H, v0.H[0]

    sub      v9.8H, v5.8H, v28.8H
    mul      v20.8H, v8.8H, v0.H[4]
    sub      v11.8H, v7.8H, v29.8H
    mul      v21.8H, v10.8H, v0.H[4]
    sub      v17.8H, v13.8H, v30.8H
    mul      v22.8H, v16.8H, v0.H[6]
    sub      v19.8H, v15.8H, v31.8H
    mul      v23.8H, v18.8H, v0.H[6]

    add      v5.8H, v5.8H, v28.8H
    sqrdmulh v8.8H, v8.8H, v0.H[5]
    add      v7.8H, v7.8H, v29.8H
    sqrdmulh v10.8H, v10.8H, v0.H[5]
    add      v13.8H, v13.8H, v30.8H
    sqrdmulh v16.8H, v16.8H, v0.H[7]
    add      v15.8H, v15.8H, v31.8H
    sqrdmulh v18.8H, v18.8H, v0.H[7]

    mls      v20.8H, v8.8H, v0.H[0]
    mls      v21.8H, v10.8H, v0.H[0]
    mls      v22.8H, v16.8H, v0.H[0]
    mls      v23.8H, v18.8H, v0.H[0]

    sub      v8.8H, v4.8H, v20.8H
    mul      v28.8H, v7.8H, v1.H[0]
    sub      v10.8H, v6.8H, v21.8H
    mul      v29.8H, v11.8H, v1.H[2]
    sub      v16.8H, v12.8H, v22.8H
    mul      v30.8H, v15.8H, v1.H[4]
    sub      v18.8H, v14.8H, v23.8H
    mul      v31.8H, v19.8H, v1.H[6]

    add      v4.8H, v4.8H, v20.8H
    sqrdmulh v7.8H, v7.8H, v1.H[1]
    add      v6.8H, v6.8H, v21.8H
    sqrdmulh v11.8H, v11.8H, v1.H[3]
    add      v12.8H, v12.8H, v22.8H
    sqrdmulh v15.8H, v15.8H, v1.H[5]
    add      v14.8H, v14.8H, v23.8H
    sqrdmulh v19.8H, v19.8H, v1.H[7]

    mls      v28.8H, v7.8H, v0.H[0]
    mls      v29.8H, v11.8H, v0.H[0]
    mls      v30.8H, v15.8H, v0.H[0]
    mls      v31.8H, v19.8H, v0.H[0]

    sub      v7.8H, v5.8H, v28.8H
    mul      v20.8H, v6.8H, v1.H[0]
    sub      v11.8H, v9.8H, v29.8H
    mul      v21.8H, v10.8H, v1.H[2]
    sub      v15.8H, v13.8H, v30.8H
    mul      v22.8H, v14.8H, v1.H[4]
    sub      v19.8H, v17.8H, v31.8H
    mul      v23.8H, v18.8H, v1.H[6]

    add      v5.8H, v5.8H, v28.8H
    sqrdmulh v6.8H, v6.8H, v1.H[1]
    add      v9.8H, v9.8H, v29.8H
    sqrdmulh v10.8H, v10.8H, v1.H[3]
    add      v13.8H, v13.8H, v30.8H
    sqrdmulh v14.8H, v14.8H, v1.H[5]
    add      v17.8H, v17.8H, v31.8H
    sqrdmulh v18.8H, v18.8H, v1.H[7]

    mls      v20.8H, v6.8H, v0.H[0]
    mls      v21.8H, v10.8H, v0.H[0]
    mls      v22.8H, v14.8H, v0.H[0]
    mls      v23.8H, v18.8H, v0.H[0]

    sub      v6.8H, v4.8H, v20.8H
    mul      v28.8H, v5.8H, v2.H[0]
    sub      v10.8H, v8.8H, v21.8H
    mul      v29.8H, v7.8H, v2.H[2]
    sub      v14.8H, v12.8H, v22.8H
    mul      v30.8H, v9.8H, v2.H[4]
    sub      v18.8H, v16.8H, v23.8H
    mul      v31.8H, v11.8H, v2.H[6]

    add      v4.8H, v4.8H, v20.8H
    sqrdmulh v5.8H, v5.8H, v2.H[1]
    add      v8.8H, v8.8H, v21.8H
    sqrdmulh v7.8H, v7.8H, v2.H[3]
    add      v12.8H, v12.8H, v22.8H
    sqrdmulh v9.8H, v9.8H, v2.H[5]
    add      v16.8H, v16.8H, v23.8H
    sqrdmulh v11.8H, v11.8H, v2.H[7]

    mls      v28.8H, v5.8H, v0.H[0]
    mls      v29.8H, v7.8H, v0.H[0]
    mls      v30.8H, v9.8H, v0.H[0]
    mls      v31.8H, v11.8H, v0.H[0]

    mul      v20.8H, v13.8H, v3.H[0]
    sub      v5.8H, v4.8H, v28.8H
    str         q5, [src, #(16+1*32)]
    mul      v21.8H, v15.8H, v3.H[2]
    sub      v7.8H, v6.8H, v29.8H
    str         q7, [src, #(16+3*32)]
    mul      v22.8H, v17.8H, v3.H[4]
    sub      v9.8H, v8.8H, v30.8H
    str         q9, [src, #(16+5*32)]
    mul      v23.8H, v19.8H, v3.H[6]
    sub      v11.8H, v10.8H, v31.8H
    str         q11, [src, #(16+7*32)]

    sqrdmulh v13.8H, v13.8H, v3.H[1]
    add      v4.8H, v4.8H, v28.8H
    str         q4, [src, #(16+0*32)]
    sqrdmulh v15.8H, v15.8H, v3.H[3]
    add      v6.8H, v6.8H, v29.8H
    str         q6, [src, #(16+2*32)]
    sqrdmulh v17.8H, v17.8H, v3.H[5]
    add      v8.8H, v8.8H, v30.8H
    str         q8, [src, #(16+4*32)]
    sqrdmulh v19.8H, v19.8H, v3.H[7]
    add      v10.8H, v10.8H, v31.8H
    str         q10, [src, #(16+6*32)]

    mls      v20.8H, v13.8H, v0.H[0]
    mls      v21.8H, v15.8H, v0.H[0]
    mls      v22.8H, v17.8H, v0.H[0]
    mls      v23.8H, v19.8H, v0.H[0]

    sub     v13.8H, v12.8H, v20.8H
    str        q13, [src, #(16+9*32)]
    sub     v15.8H, v14.8H, v21.8H
    str        q15, [src, #(16+11*32)]
    sub     v17.8H, v16.8H, v22.8H
    str        q17, [src, #(16+13*32)]
    sub     v19.8H, v18.8H, v23.8H
    str        q19, [src, #(16+15*32)]

    add     v12.8H, v12.8H, v20.8H
    str        q12, [src, #(16+8*32)]
    add     v14.8H, v14.8H, v21.8H
    str        q14, [src, #(16+10*32)]
    add     v16.8H, v16.8H, v22.8H
    str        q16, [src, #(16+12*32)]
    add     v18.8H, v18.8H, v23.8H
    str        q18, [src, #(16+14*32)]

    .unreq    Q
    .unreq    src
    .unreq    table
    .unreq    counter
    ldp  d8,  d9, [sp, #0*16]
    ldp d10, d11, [sp, #1*16]
    ldp d12, d13, [sp, #2*16]
    ldp d14, d15, [sp, #3*16]
    add sp, sp, #(4*16)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLKEM_NTT_top)

// =============================================================================
// MLKEM_NTT_bot — Forward NTT, Layers 4-7 (Cooley-Tukey butterfly + Barrett reduction)
// =============================================================================
//
// Signature: void MLKEM_NTT_bot(int16_t *a, const int16_t *table)
//   x0 (a):     polynomial pointer (in/out), split into src0 (a[0..127]) and
//               src1 (a[128..255])
//   x1 (table): twiddle table (starting at offset 64 to skip layers 1-3 twiddles)
//
// Algorithm:
//   1. Set Q = 3329, BarrettM = 20159; init src0/src1 pointers, advance table
//   2. For each of 4 iterations (64-coeff block per iteration):
//      a. Load 4 vectors from src0/src1 at offsets 0,1,2,3 ×16
//      b. Apply 4×4 matrix transpose (trn1/trn2 in .4S then .2D) to rearrange
//         coefficients so butterfly-dependent elements fall into different lanes
//      c. Layer 4 (stride 16): element-wise Montgomery mul + CT butterfly
//      d. Layer 5 (stride 8):  half-vector twiddle (4 twiddle pairs)
//      e. Layer 6 (stride 4):  quarter-vector twiddle (4 twiddle pairs)
//      f. Layer 7 (stride 2):  per-pair twiddle + Barrett reduction (M = 20159)
//      g. Inverse 4×4 transpose to restore original memory layout
//      h. Store results back to src0/src1; advance pointers by 64 bytes
//   3. First iteration is unrolled; remaining 3 use a counted loop
//
// Register allocation:
//   v0.H[0]:  Q = 3329 (for Montgomery reduction mls)
//   v0.H[1]:  BarrettM = 20159 (0x4EBF, for Barrett reduction sqdmulh)
//   v1-v15:   twiddle factors loaded per layer (tw_lo/tw_hi pairs)
//   v16-v31:  polynomial data and intermediate results
//   x0 (src0):  pointer to first 128 coefficients
//   x1 (src1):  pointer to last 128 coefficients (src0 + 256)
//   x10 (table): twiddle table pointer (advanced by 256 per iteration)
//   x11 (counter): loop counter (init 3)
//   w8 (Q):       modulus 3329
//   w9 (BarrettM): Barrett reduction constant 20159
//
// Notes:
//   The 4×4 transpose is required because layers 5-7 have butterfly stride
//   below the NEON lane count (8), meaning dependent elements share a lane.
//   Barrett reduction uses M = round(2^26 / Q) = 20159 with srshr #11 to
//   approximate division by Q, keeping coefficients bounded after layer 7.
//   Pipeline interleaving: twiddle loads overlap with sqrdmulh computation.
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEM_NTT_bot)
AARCH64_PACIASP
    sub sp, sp, #(4*16)
    stp  d8,  d9, [sp, #0*16]
    stp d10, d11, [sp, #1*16]
    stp d12, d13, [sp, #2*16]
    stp d14, d15, [sp, #3*16]
    Q         .req w8
    BarrettM  .req w9
    src0      .req x0
    src1      .req x1
    table     .req x10
    counter   .req x11

    mov Q, #3329              // Q
    mov BarrettM, #20159      // round(2^26 / Q)

    add table, x1, #64

    add src0, x0, #256*0
    add src1, x0, #256*1

    mov v0.H[0], Q
    mov v0.H[1], BarrettM

    ldr q28, [src0, # 1*16]
    ldr q29, [src1, # 1*16]
    ldr q30, [src0, # 3*16]
    ldr q31, [src1, # 3*16]

    // ========== 4×4 Matrix Transpose (pre-butterfly) ==========
    // Rearranges coefficient layout so that butterfly-dependent elements
    // fall into different NEON lanes. Required because layers 5-7 have
    // stride < 8 (the NEON lane count). Uses trn1/trn2 in .4S then .2D.
    // (See [NeonNTT] §4.3 — Matrix transpose for sub-lane butterflies)
    trn1 v20.4S, v28.4S, v29.4S
    trn2 v21.4S, v28.4S, v29.4S
    ldr        q1, [table, #1*16]
    trn1 v22.4S, v30.4S, v31.4S
    trn2 v23.4S, v30.4S, v31.4S

    ldr        q2, [table, #2*16]
    trn1 v28.2D, v20.2D, v22.2D
    trn2 v30.2D, v20.2D, v22.2D
    ldr        q3, [table, #3*16]
    trn1 v29.2D, v21.2D, v23.2D
    trn2 v31.2D, v21.2D, v23.2D

    // ========== Layer 4 (stride 16): full-vector twiddle, v2-v3 pairs ==========
    ldr        q24, [src0, #0*16]
    mul      v18.8H, v29.8H, v2.8H
    ldr        q25, [src1, #0*16]
    mul      v19.8H, v31.8H, v2.8H

    ldr        q26, [src0, #2*16]
    trn1   v20.4S, v24.4S, v25.4S
    trn2   v21.4S, v24.4S, v25.4S
    ldr        q27, [src1, #2*16]
    trn1   v22.4S, v26.4S, v27.4S
    trn2   v23.4S, v26.4S, v27.4S

    sqrdmulh v29.8H, v29.8H, v3.8H
    trn1   v24.2D, v20.2D, v22.2D
    sqrdmulh v31.8H, v31.8H, v3.8H
    trn2   v26.2D, v20.2D, v22.2D

    mls      v18.8H, v29.8H, v0.H[0]
    trn1   v25.2D, v21.2D, v23.2D
    mls      v19.8H, v31.8H, v0.H[0]
    trn2   v27.2D, v21.2D, v23.2D

    ldr         q4, [table, #4*16]
    sub      v29.8H, v25.8H, v18.8H
    mul      v16.8H, v28.8H, v2.8H
    ldr         q5, [table, #5*16]
    sub      v31.8H, v27.8H, v19.8H
    mul      v17.8H, v30.8H, v2.8H

    ldr         q6, [table, #6*16]
    add      v25.8H, v25.8H, v18.8H
    sqrdmulh v28.8H, v28.8H, v3.8H
    ldr         q7, [table, #7*16]
    add      v27.8H, v27.8H, v19.8H
    sqrdmulh v30.8H, v30.8H, v3.8H

    mls      v16.8H, v28.8H, v0.H[0]
    mls      v17.8H, v30.8H, v0.H[0]

    // ========== Layer 5 (stride 8): half-vector twiddle, v4-v7 pairs ==========
    ldr         q8, [table, #8*16]
    sub      v28.8H, v24.8H, v16.8H
    mul      v18.8H, v27.8H, v4.8H
    ldr         q9, [table, #9*16]
    sub      v30.8H, v26.8H, v17.8H
    mul      v19.8H, v31.8H, v6.8H

    ldr         q10, [table, #10*16]
    add      v24.8H, v24.8H, v16.8H
    sqrdmulh v27.8H, v27.8H, v5.8H
    ldr         q11, [table, #11*16]
    add      v26.8H, v26.8H, v17.8H
    sqrdmulh v31.8H, v31.8H, v7.8H

    mls      v18.8H, v27.8H, v0.H[0]
    mls      v19.8H, v31.8H, v0.H[0]

    ldr         q12, [table, #12*16]
    sub      v27.8H, v25.8H, v18.8H
    mul      v16.8H, v26.8H, v4.8H
    ldr         q13, [table, #13*16]
    sub      v31.8H, v29.8H, v19.8H
    mul      v17.8H, v30.8H, v6.8H

    ldr         q14, [table, #14*16]
    add      v25.8H, v25.8H, v18.8H
    sqrdmulh v26.8H, v26.8H, v5.8H
    ldr         q15, [table, #15*16]
    add      v29.8H, v29.8H, v19.8H
    sqrdmulh v30.8H, v30.8H, v7.8H

    mls      v16.8H, v26.8H, v0.H[0]
    mls      v17.8H, v30.8H, v0.H[0]

    add table, table, #256

    // ========== Layer 6 (stride 4): quarter-vector twiddle, v8-v11 pairs ==========
    sub      v26.8H, v24.8H, v16.8H
    mul      v18.8H, v25.8H, v8.8H
    sub      v30.8H, v28.8H, v17.8H
    mul      v19.8H, v27.8H, v10.8H

    add      v24.8H, v24.8H, v16.8H
    sqrdmulh v25.8H, v25.8H, v9.8H
    add      v28.8H, v28.8H, v17.8H
    sqrdmulh v27.8H, v27.8H, v11.8H

    mls      v18.8H, v25.8H, v0.H[0]
    mls      v19.8H, v27.8H, v0.H[0]

    sub      v25.8H, v24.8H, v18.8H
    mul      v16.8H, v29.8H, v12.8H
    sub      v27.8H, v26.8H, v19.8H
    mul      v17.8H, v31.8H, v14.8H

    add      v24.8H, v24.8H, v18.8H
    sqrdmulh v29.8H, v29.8H, v13.8H
    add      v26.8H, v26.8H, v19.8H
    sqrdmulh v31.8H, v31.8H, v15.8H

    mls      v16.8H, v29.8H, v0.H[0]
    mls      v17.8H, v31.8H, v0.H[0]

    // ========== Layer 7 (stride 2): per-pair twiddle, v12-v15 pairs ==========
    // After layer 7, apply Barrett reduction to bound coefficient growth.
    sqdmulh  v20.8H, v24.8H, v0.H[1]
    sub      v29.8H, v28.8H, v16.8H
    sqdmulh  v21.8H, v25.8H, v0.H[1]
    sub      v31.8H, v30.8H, v17.8H
    sqdmulh  v22.8H, v26.8H, v0.H[1]
    add      v28.8H, v28.8H, v16.8H
    sqdmulh  v23.8H, v27.8H, v0.H[1]
    add      v30.8H, v30.8H, v17.8H

    sqdmulh  v16.8H, v28.8H, v0.H[1]
    srshr    v20.8H, v20.8H, #11
    sqdmulh  v17.8H, v29.8H, v0.H[1]
    srshr    v21.8H, v21.8H, #11
    sqdmulh  v18.8H, v30.8H, v0.H[1]
    srshr    v22.8H, v22.8H, #11
    sqdmulh  v19.8H, v31.8H, v0.H[1]
    srshr    v23.8H, v23.8H, #11

    mls      v24.8H, v20.8H, v0.H[0]
    srshr    v16.8H, v16.8H, #11
    mls      v25.8H, v21.8H, v0.H[0]
    srshr    v17.8H, v17.8H, #11
    mls      v26.8H, v22.8H, v0.H[0]
    srshr    v18.8H, v18.8H, #11
    mls      v27.8H, v23.8H, v0.H[0]
    srshr    v19.8H, v19.8H, #11

    // ========== Inverse 4×4 Transpose + Store ==========
    // Restore original memory layout after sub-lane butterfly processing.
    mls      v28.8H, v16.8H, v0.H[0]
    trn1     v20.4S, v24.4S, v25.4S
    mls      v29.8H, v17.8H, v0.H[0]
    trn2     v21.4S, v24.4S, v25.4S
    mls      v30.8H, v18.8H, v0.H[0]
    trn1     v22.4S, v26.4S, v27.4S
    mls      v31.8H, v19.8H, v0.H[0]

    trn2     v23.4S, v26.4S, v27.4S

    trn1     v24.2D, v20.2D, v22.2D
    trn2     v26.2D, v20.2D, v22.2D
    trn1     v25.2D, v21.2D, v23.2D
    trn2     v27.2D, v21.2D, v23.2D

    str        q24, [src0, #0*16]
    trn1 v16.4S, v28.4S, v29.4S
    trn2 v17.4S, v28.4S, v29.4S
    str        q25, [src1, #0*16]
    trn1 v18.4S, v30.4S, v31.4S
    trn2 v19.4S, v30.4S, v31.4S

    str        q26, [src0, #2*16]
    trn1 v28.2D, v16.2D, v18.2D
    trn2 v30.2D, v16.2D, v18.2D
    str        q27, [src1, #2*16]
    trn1 v29.2D, v17.2D, v19.2D
    trn2 v31.2D, v17.2D, v19.2D

    mov counter, #3
1:

    // ---- Store previous iteration results, load next 64-coeff block ----
    str q28, [src0, # 1*16]
    ldr q28, [src0, #(64+1*16)]
    str q29, [src1, # 1*16]
    ldr q29, [src1, #(64+1*16)]
    str q30, [src0, # 3*16]
    ldr q30, [src0, #(64+3*16)]
    str q31, [src1, # 3*16]
    ldr q31, [src1, #(64+3*16)]

    add src0, src0, #64
    add src1, src1, #64

    // ========== 4×4 Matrix Transpose (pre-butterfly) ==========
    trn1 v20.4S, v28.4S, v29.4S
    trn2 v21.4S, v28.4S, v29.4S
    ldr        q1, [table, #1*16]
    trn1 v22.4S, v30.4S, v31.4S
    trn2 v23.4S, v30.4S, v31.4S

    ldr        q2, [table, #2*16]
    trn1 v28.2D, v20.2D, v22.2D
    trn2 v30.2D, v20.2D, v22.2D
    ldr        q3, [table, #3*16]
    trn1 v29.2D, v21.2D, v23.2D
    trn2 v31.2D, v21.2D, v23.2D

    // ========== Layer 4 (stride 16): full-vector twiddle, v2-v3 pairs ==========
    ldr        q24, [src0, #0*16]
    mul      v18.8H, v29.8H, v2.8H
    ldr        q25, [src1, #0*16]
    mul      v19.8H, v31.8H, v2.8H

    ldr        q26, [src0, #2*16]
    trn1   v20.4S, v24.4S, v25.4S
    trn2   v21.4S, v24.4S, v25.4S
    ldr        q27, [src1, #2*16]
    trn1   v22.4S, v26.4S, v27.4S
    trn2   v23.4S, v26.4S, v27.4S

    sqrdmulh v29.8H, v29.8H, v3.8H
    trn1   v24.2D, v20.2D, v22.2D
    sqrdmulh v31.8H, v31.8H, v3.8H
    trn2   v26.2D, v20.2D, v22.2D

    mls      v18.8H, v29.8H, v0.H[0]
    trn1   v25.2D, v21.2D, v23.2D
    mls      v19.8H, v31.8H, v0.H[0]
    trn2   v27.2D, v21.2D, v23.2D

    ldr         q4, [table, #4*16]
    sub      v29.8H, v25.8H, v18.8H
    mul      v16.8H, v28.8H, v2.8H
    ldr         q5, [table, #5*16]
    sub      v31.8H, v27.8H, v19.8H
    mul      v17.8H, v30.8H, v2.8H

    ldr         q6, [table, #6*16]
    add      v25.8H, v25.8H, v18.8H
    sqrdmulh v28.8H, v28.8H, v3.8H
    ldr         q7, [table, #7*16]
    add      v27.8H, v27.8H, v19.8H
    sqrdmulh v30.8H, v30.8H, v3.8H

    mls      v16.8H, v28.8H, v0.H[0]
    mls      v17.8H, v30.8H, v0.H[0]

    // ========== Layer 5 (stride 8): half-vector twiddle, v4-v7 pairs ==========
    ldr         q8, [table, #8*16]
    sub      v28.8H, v24.8H, v16.8H
    mul      v18.8H, v27.8H, v4.8H
    ldr         q9, [table, #9*16]
    sub      v30.8H, v26.8H, v17.8H
    mul      v19.8H, v31.8H, v6.8H

    ldr         q10, [table, #10*16]
    add      v24.8H, v24.8H, v16.8H
    sqrdmulh v27.8H, v27.8H, v5.8H
    ldr         q11, [table, #11*16]
    add      v26.8H, v26.8H, v17.8H
    sqrdmulh v31.8H, v31.8H, v7.8H

    mls      v18.8H, v27.8H, v0.H[0]
    mls      v19.8H, v31.8H, v0.H[0]

    ldr         q12, [table, #12*16]
    sub      v27.8H, v25.8H, v18.8H
    mul      v16.8H, v26.8H, v4.8H
    ldr         q13, [table, #13*16]
    sub      v31.8H, v29.8H, v19.8H
    mul      v17.8H, v30.8H, v6.8H

    ldr         q14, [table, #14*16]
    add      v25.8H, v25.8H, v18.8H
    sqrdmulh v26.8H, v26.8H, v5.8H
    ldr         q15, [table, #15*16]
    add      v29.8H, v29.8H, v19.8H
    sqrdmulh v30.8H, v30.8H, v7.8H

    mls      v16.8H, v26.8H, v0.H[0]
    mls      v17.8H, v30.8H, v0.H[0]

    add table, table, #256

    // ========== Layer 6 (stride 4): quarter-vector twiddle, v8-v11 pairs ==========
    sub      v26.8H, v24.8H, v16.8H
    mul      v18.8H, v25.8H, v8.8H
    sub      v30.8H, v28.8H, v17.8H
    mul      v19.8H, v27.8H, v10.8H

    add      v24.8H, v24.8H, v16.8H
    sqrdmulh v25.8H, v25.8H, v9.8H
    add      v28.8H, v28.8H, v17.8H
    sqrdmulh v27.8H, v27.8H, v11.8H

    mls      v18.8H, v25.8H, v0.H[0]
    mls      v19.8H, v27.8H, v0.H[0]

    sub      v25.8H, v24.8H, v18.8H
    mul      v16.8H, v29.8H, v12.8H
    sub      v27.8H, v26.8H, v19.8H
    mul      v17.8H, v31.8H, v14.8H

    add      v24.8H, v24.8H, v18.8H
    sqrdmulh v29.8H, v29.8H, v13.8H
    add      v26.8H, v26.8H, v19.8H
    sqrdmulh v31.8H, v31.8H, v15.8H

    mls      v16.8H, v29.8H, v0.H[0]
    mls      v17.8H, v31.8H, v0.H[0]

    // ========== Layer 7 (stride 2) + Barrett reduction ==========
    sqdmulh  v20.8H, v24.8H, v0.H[1]
    sub      v29.8H, v28.8H, v16.8H
    sqdmulh  v21.8H, v25.8H, v0.H[1]
    sub      v31.8H, v30.8H, v17.8H
    sqdmulh  v22.8H, v26.8H, v0.H[1]
    add      v28.8H, v28.8H, v16.8H
    sqdmulh  v23.8H, v27.8H, v0.H[1]
    add      v30.8H, v30.8H, v17.8H

    sqdmulh  v16.8H, v28.8H, v0.H[1]
    srshr    v20.8H, v20.8H, #11
    sqdmulh  v17.8H, v29.8H, v0.H[1]
    srshr    v21.8H, v21.8H, #11
    sqdmulh  v18.8H, v30.8H, v0.H[1]
    srshr    v22.8H, v22.8H, #11
    sqdmulh  v19.8H, v31.8H, v0.H[1]
    srshr    v23.8H, v23.8H, #11

    mls      v24.8H, v20.8H, v0.H[0]
    srshr    v16.8H, v16.8H, #11
    mls      v25.8H, v21.8H, v0.H[0]
    srshr    v17.8H, v17.8H, #11
    mls      v26.8H, v22.8H, v0.H[0]
    srshr    v18.8H, v18.8H, #11
    mls      v27.8H, v23.8H, v0.H[0]
    srshr    v19.8H, v19.8H, #11

    // ========== Inverse 4×4 Transpose + Store ==========
    mls      v28.8H, v16.8H, v0.H[0]
    trn1     v20.4S, v24.4S, v25.4S
    mls      v29.8H, v17.8H, v0.H[0]
    trn2     v21.4S, v24.4S, v25.4S
    mls      v30.8H, v18.8H, v0.H[0]
    trn1     v22.4S, v26.4S, v27.4S
    mls      v31.8H, v19.8H, v0.H[0]

    trn2     v23.4S, v26.4S, v27.4S

    trn1     v24.2D, v20.2D, v22.2D
    trn2     v26.2D, v20.2D, v22.2D
    trn1     v25.2D, v21.2D, v23.2D
    trn2     v27.2D, v21.2D, v23.2D

    str        q24, [src0, #0*16]
    trn1 v16.4S, v28.4S, v29.4S
    trn2 v17.4S, v28.4S, v29.4S
    str        q25, [src1, #0*16]
    trn1 v18.4S, v30.4S, v31.4S
    trn2 v19.4S, v30.4S, v31.4S

    str        q26, [src0, #2*16]
    trn1 v28.2D, v16.2D, v18.2D
    trn2 v30.2D, v16.2D, v18.2D
    str        q27, [src1, #2*16]
    trn1 v29.2D, v17.2D, v19.2D
    trn2 v31.2D, v17.2D, v19.2D

    sub counter, counter, #1
    cbnz counter, 1b

    str q28, [src0, # 1*16]
    str q29, [src1, # 1*16]
    str q30, [src0, # 3*16]
    str q31, [src1, # 3*16]

    add src0, src0, #64
    add src1, src1, #64

    .unreq    Q
    .unreq    BarrettM
    .unreq    src0
    .unreq    src1
    .unreq    table
    .unreq    counter
    ldp  d8,  d9, [sp, #0*16]
    ldp d10, d11, [sp, #1*16]
    ldp d12, d13, [sp, #2*16]
    ldp d14, d15, [sp, #3*16]
    add sp, sp, #(4*16)
AARCH64_AUTIASP
    ret
    CRYPT_AARCH64_FUNC_END(MLKEM_NTT_bot)

// =============================================================================
// MLKEM_INTT_bot — Inverse NTT, Layers 7-4 (Gentleman-Sander butterfly + Barrett reduction)
// =============================================================================
//
// Signature: void MLKEM_INTT_bot(int16_t *a, const int16_t *table)
//   x0 (a):     polynomial pointer (in/out)
//   x1 (table): inverse twiddle table (MLKEM_INTT_TWIDDLE_TABLE)
//
// Algorithm:
//   1. Set Q = 3329, BarrettM = 20159; init src0/src1 pointers, advance table
//   2. For each of 4 iterations (64-coeff block per iteration):
//      a. Load 4 vectors from src0/src1; apply 4×4 matrix transpose
//      b. GS Layer 7 (stride 2):  GS butterfly (a,b) → (a+b, (a-b)×ω^{-1})
//      c. GS Layer 6 (stride 4):  quarter-vector inverse twiddle
//      d. GS Layer 5 (stride 8):  half-vector inverse twiddle
//      e. GS Layer 4 (stride 16): full-vector inverse twiddle (two Montgomery mul rounds)
//      f. Barrett reduction on all 8 output vectors (M = 20159, srshr #11)
//      g. Inverse 4×4 transpose to restore original memory layout
//      h. Store results; advance pointers by 64 bytes
//   3. First iteration unrolled; remaining 3 use a counted loop
//
// Register allocation:
//   v0.H[0]:  Q = 3329 (for Montgomery reduction mls)
//   v0.H[1]:  BarrettM = 20159 (0x4EBF, for Barrett reduction sqdmulh)
//   v1-v15:   inverse twiddle factors loaded per layer
//   v16-v31:  polynomial data and intermediate results
//   x0 (src0):   pointer to first 128 coefficients
//   x1 (src1):   pointer to last 128 coefficients
//   x28 (table): twiddle table pointer (callee-saved, advanced per iteration)
//   x19 (counter): loop counter
//   w20 (Q):      modulus 3329
//   w21 (BarrettM): Barrett reduction constant 20159
//
// Notes:
//   GS butterfly computes (a+b, (a-b)×ω^{-1}) — the subtraction is multiplied
//   by the inverse twiddle, unlike CT where the multiplication precedes add/sub.
//   Layer 4 uses two rounds of Montgomery mul because the GS butterfly for
//   stride 16 requires multiplying differences from two preceding sub-groups.
//   Extra callee-saved registers (x19-x28) accommodate the reversed layer order
//   and additional pointer tracking compared to NTT_bot.
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEM_INTT_bot)
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
    Q         .req w20
    BarrettM  .req w21
    src0      .req x0
    src1      .req x1
    table     .req x28
    counter   .req x19

    mov Q, #3329              // Q
    mov BarrettM, #20159      // round(2^26 / Q)

    add table, x1, #64

    add src0, x0, #256*0
    add src1, x0, #256*1

    mov v0.H[0], Q
    mov v0.H[1], BarrettM

    ldr q28, [src0, #1*16]
    ldr q29, [src1, #1*16]
    ldr q30, [src0, #3*16]
    ldr q31, [src1, #3*16]

    // ========== 4×4 Matrix Transpose (pre-butterfly) ==========
    ldr        q24, [src0, #0*16]
    trn1 v20.4S, v28.4S, v29.4S
    trn2 v21.4S, v28.4S, v29.4S
    ldr        q25, [src1, #0*16]
    trn1 v22.4S, v30.4S, v31.4S
    trn2 v23.4S, v30.4S, v31.4S

    ldr        q26, [src0, #2*16]
    trn1 v28.2D, v20.2D, v22.2D
    trn2 v30.2D, v20.2D, v22.2D
    ldr        q27, [src1, #2*16]
    trn1 v29.2D, v21.2D, v23.2D
    trn2 v31.2D, v21.2D, v23.2D

    ldr        q12, [table, #12*16]
    trn1 v20.4S, v24.4S, v25.4S
    trn2 v21.4S, v24.4S, v25.4S
    ldr        q13, [table, #13*16]
    trn1 v22.4S, v26.4S, v27.4S
    trn2 v23.4S, v26.4S, v27.4S

    ldr        q14, [table, #14*16]
    trn1 v24.2D, v20.2D, v22.2D
    trn2 v26.2D, v20.2D, v22.2D
    ldr        q15, [table, #15*16]
    trn1 v25.2D, v21.2D, v23.2D
    trn2 v27.2D, v21.2D, v23.2D

    // ========== GS Layer 7 (stride 2): per-pair twiddle, v12-v15 pairs ==========
    // GS butterfly: (a,b) → (a+b, (a−b)×ω^{-1})
    sub     v18.8H, v28.8H, v29.8H
    sub     v19.8H, v30.8H, v31.8H
    add     v28.8H, v28.8H, v29.8H
    add     v30.8H, v30.8H, v31.8H

    ldr         q8, [table, #8*16]
    mul      v29.8H, v18.8H, v12.8H
    sub      v16.8H, v24.8H, v25.8H
    ldr         q9, [table, #9*16]
    mul      v31.8H, v19.8H, v14.8H
    sub      v17.8H, v26.8H, v27.8H

    ldr         q10, [table, #10*16]
    sqrdmulh v18.8H, v18.8H, v13.8H
    add      v24.8H, v24.8H, v25.8H
    ldr         q11, [table, #11*16]
    sqrdmulh v19.8H, v19.8H, v15.8H
    add      v26.8H, v26.8H, v27.8H

    mls      v29.8H, v18.8H, v0.H[0]
    mls      v31.8H, v19.8H, v0.H[0]

    // ========== GS Layer 6 (stride 4): quarter-vector twiddle, v8-v11 pairs ==========
    ldr         q4, [table, #4*16]
    mul      v25.8H, v16.8H, v8.8H
    sub      v18.8H, v28.8H, v30.8H
    ldr         q5, [table, #5*16]
    mul      v27.8H, v17.8H, v10.8H
    sub      v19.8H, v29.8H, v31.8H

    ldr         q6, [table, #6*16]
    sqrdmulh v16.8H, v16.8H, v9.8H
    add      v28.8H, v28.8H, v30.8H
    ldr         q7, [table, #7*16]
    sqrdmulh v17.8H, v17.8H, v11.8H
    add      v29.8H, v29.8H, v31.8H

    mls      v25.8H, v16.8H, v0.H[0]
    mls      v27.8H, v17.8H, v0.H[0]

    // ========== GS Layer 5 (stride 8): half-vector twiddle, v6-v7 pairs ==========
    mul      v30.8H, v18.8H, v6.8H
    sub      v16.8H, v24.8H, v26.8H
    ldr         q1, [table, #1*16]
    mul      v31.8H, v19.8H, v6.8H
    sub      v17.8H, v25.8H, v27.8H

    ldr         q2, [table, #2*16]
    sqrdmulh v18.8H, v18.8H, v7.8H
    add      v24.8H, v24.8H, v26.8H
    ldr         q3, [table, #3*16]
    sqrdmulh v19.8H, v19.8H, v7.8H
    add      v25.8H, v25.8H, v27.8H

    mls      v30.8H, v18.8H, v0.H[0]
    mls      v31.8H, v19.8H, v0.H[0]

    // ========== GS Layer 4 (stride 16): full-vector twiddle, v4-v5 pairs ==========
    mul      v26.8H, v16.8H, v4.8H
    sub      v18.8H, v24.8H, v28.8H
    mul      v27.8H, v17.8H, v4.8H
    sub      v19.8H, v25.8H, v29.8H

    sqrdmulh v16.8H, v16.8H, v5.8H
    add      v24.8H, v24.8H, v28.8H
    sqrdmulh v17.8H, v17.8H, v5.8H
    add      v25.8H, v25.8H, v29.8H

    mls      v26.8H, v16.8H, v0.H[0]
    mls      v27.8H, v17.8H, v0.H[0]

    mul      v28.8H, v18.8H, v2.8H
    sub      v16.8H, v26.8H, v30.8H
    mul      v29.8H, v19.8H, v2.8H
    sub      v17.8H, v27.8H, v31.8H

    sqrdmulh v18.8H, v18.8H, v3.8H
    add      v26.8H, v26.8H, v30.8H
    sqrdmulh v19.8H, v19.8H, v3.8H
    add      v27.8H, v27.8H, v31.8H

    mls      v28.8H, v18.8H, v0.H[0]
    mls      v29.8H, v19.8H, v0.H[0]
    mul      v30.8H, v16.8H, v2.8H
    mul      v31.8H, v17.8H, v2.8H
    sqrdmulh v16.8H, v16.8H, v3.8H
    sqrdmulh v17.8H, v17.8H, v3.8H
    mls      v30.8H, v16.8H, v0.H[0]
    mls      v31.8H, v17.8H, v0.H[0]

    // ========== Barrett reduction (all 8 output vectors) ==========
    sqdmulh v16.8H, v24.8H, v0.H[1]
    sqdmulh v17.8H, v25.8H, v0.H[1]
    sqdmulh v18.8H, v26.8H, v0.H[1]
    sqdmulh v19.8H, v27.8H, v0.H[1]

    srshr   v16.8H, v16.8H, #11
    sqdmulh v20.8H, v28.8H, v0.H[1]
    srshr   v17.8H, v17.8H, #11
    sqdmulh v21.8H, v29.8H, v0.H[1]
    srshr   v18.8H, v18.8H, #11
    sqdmulh v22.8H, v30.8H, v0.H[1]
    srshr   v19.8H, v19.8H, #11
    sqdmulh v23.8H, v31.8H, v0.H[1]

    mls     v24.8H, v16.8H, v0.H[0]
    srshr   v20.8H, v20.8H, #11
    mls     v25.8H, v17.8H, v0.H[0]
    srshr   v21.8H, v21.8H, #11
    mls     v26.8H, v18.8H, v0.H[0]
    srshr   v22.8H, v22.8H, #11
    mls     v27.8H, v19.8H, v0.H[0]
    srshr   v23.8H, v23.8H, #11

    mls     v28.8H, v20.8H, v0.H[0]
    mls     v29.8H, v21.8H, v0.H[0]
    mls     v30.8H, v22.8H, v0.H[0]
    mls     v31.8H, v23.8H, v0.H[0]

    add table, table, #256

    // ========== Inverse 4×4 Transpose + Store ==========
    trn1 v16.4S, v28.4S, v29.4S
    trn2 v17.4S, v28.4S, v29.4S
    trn1 v18.4S, v30.4S, v31.4S
    trn2 v19.4S, v30.4S, v31.4S

    trn1 v28.2D, v16.2D, v18.2D
    trn2 v30.2D, v16.2D, v18.2D
    trn1 v29.2D, v17.2D, v19.2D
    trn2 v31.2D, v17.2D, v19.2D

    str        q28, [src0, #1*16]
    trn1 v16.4S, v24.4S, v25.4S
    trn2 v17.4S, v24.4S, v25.4S
    str        q29, [src1, #1*16]
    trn1 v18.4S, v26.4S, v27.4S
    trn2 v19.4S, v26.4S, v27.4S

    str        q30, [src0, #3*16]
    trn1 v24.2D, v16.2D, v18.2D
    trn2 v26.2D, v16.2D, v18.2D
    str        q31, [src1, #3*16]
    trn1 v25.2D, v17.2D, v19.2D
    trn2 v27.2D, v17.2D, v19.2D

    mov counter, #3
1:

    // ---- Store previous iteration results, load next 64-coeff block ----
    str q24, [src0, #0*16]
    ldr q28, [src0, #(64+1*16)]
    str q25, [src1, #0*16]
    ldr q29, [src1, #(64+1*16)]
    str q26, [src0, #2*16]
    ldr q30, [src0, #(64+3*16)]
    str q27, [src1, #2*16]
    ldr q31, [src1, #(64+3*16)]

    add src0, src0, #64
    add src1, src1, #64

    // ========== 4×4 Matrix Transpose (pre-butterfly) ==========
    ldr        q24, [src0, #0*16]
    trn1 v20.4S, v28.4S, v29.4S
    trn2 v21.4S, v28.4S, v29.4S
    ldr        q25, [src1, #0*16]
    trn1 v22.4S, v30.4S, v31.4S
    trn2 v23.4S, v30.4S, v31.4S

    ldr        q26, [src0, #2*16]
    trn1 v28.2D, v20.2D, v22.2D
    trn2 v30.2D, v20.2D, v22.2D
    ldr        q27, [src1, #2*16]
    trn1 v29.2D, v21.2D, v23.2D
    trn2 v31.2D, v21.2D, v23.2D

    ldr        q12, [table, #12*16]
    trn1 v20.4S, v24.4S, v25.4S
    trn2 v21.4S, v24.4S, v25.4S
    ldr        q13, [table, #13*16]
    trn1 v22.4S, v26.4S, v27.4S
    trn2 v23.4S, v26.4S, v27.4S

    ldr        q14, [table, #14*16]
    trn1 v24.2D, v20.2D, v22.2D
    trn2 v26.2D, v20.2D, v22.2D
    ldr        q15, [table, #15*16]
    trn1 v25.2D, v21.2D, v23.2D
    trn2 v27.2D, v21.2D, v23.2D

    // ========== GS Layer 7 (stride 2): per-pair twiddle, v12-v15 pairs ==========
    sub     v18.8H, v28.8H, v29.8H
    sub     v19.8H, v30.8H, v31.8H
    add     v28.8H, v28.8H, v29.8H
    add     v30.8H, v30.8H, v31.8H

    ldr         q8, [table, #8*16]
    mul      v29.8H, v18.8H, v12.8H
    sub      v16.8H, v24.8H, v25.8H
    ldr         q9, [table, #9*16]
    mul      v31.8H, v19.8H, v14.8H
    sub      v17.8H, v26.8H, v27.8H

    ldr         q10, [table, #10*16]
    sqrdmulh v18.8H, v18.8H, v13.8H
    add      v24.8H, v24.8H, v25.8H
    ldr         q11, [table, #11*16]
    sqrdmulh v19.8H, v19.8H, v15.8H
    add      v26.8H, v26.8H, v27.8H

    mls      v29.8H, v18.8H, v0.H[0]
    mls      v31.8H, v19.8H, v0.H[0]

    // ========== GS Layer 6 (stride 4): quarter-vector twiddle, v8-v11 pairs ==========
    ldr         q4, [table, #4*16]
    mul      v25.8H, v16.8H, v8.8H
    sub      v18.8H, v28.8H, v30.8H
    ldr         q5, [table, #5*16]
    mul      v27.8H, v17.8H, v10.8H
    sub      v19.8H, v29.8H, v31.8H

    ldr         q6, [table, #6*16]
    sqrdmulh v16.8H, v16.8H, v9.8H
    add      v28.8H, v28.8H, v30.8H
    ldr         q7, [table, #7*16]
    sqrdmulh v17.8H, v17.8H, v11.8H
    add      v29.8H, v29.8H, v31.8H

    mls      v25.8H, v16.8H, v0.H[0]
    mls      v27.8H, v17.8H, v0.H[0]

    // ========== GS Layer 5 (stride 8): half-vector twiddle, v6-v7 pairs ==========
    mul      v30.8H, v18.8H, v6.8H
    sub      v16.8H, v24.8H, v26.8H
    ldr         q1, [table, #1*16]
    mul      v31.8H, v19.8H, v6.8H
    sub      v17.8H, v25.8H, v27.8H

    ldr         q2, [table, #2*16]
    sqrdmulh v18.8H, v18.8H, v7.8H
    add      v24.8H, v24.8H, v26.8H
    ldr         q3, [table, #3*16]
    sqrdmulh v19.8H, v19.8H, v7.8H
    add      v25.8H, v25.8H, v27.8H

    mls      v30.8H, v18.8H, v0.H[0]
    mls      v31.8H, v19.8H, v0.H[0]

    // ========== GS Layer 4 (stride 16): full-vector twiddle, v4-v5 pairs ==========
    mul      v26.8H, v16.8H, v4.8H
    sub      v18.8H, v24.8H, v28.8H
    mul      v27.8H, v17.8H, v4.8H
    sub      v19.8H, v25.8H, v29.8H

    sqrdmulh v16.8H, v16.8H, v5.8H
    add      v24.8H, v24.8H, v28.8H
    sqrdmulh v17.8H, v17.8H, v5.8H
    add      v25.8H, v25.8H, v29.8H

    mls      v26.8H, v16.8H, v0.H[0]
    mls      v27.8H, v17.8H, v0.H[0]

    mul      v28.8H, v18.8H, v2.8H
    sub      v16.8H, v26.8H, v30.8H
    mul      v29.8H, v19.8H, v2.8H
    sub      v17.8H, v27.8H, v31.8H

    sqrdmulh v18.8H, v18.8H, v3.8H
    add      v26.8H, v26.8H, v30.8H
    sqrdmulh v19.8H, v19.8H, v3.8H
    add      v27.8H, v27.8H, v31.8H

    mls      v28.8H, v18.8H, v0.H[0]
    mls      v29.8H, v19.8H, v0.H[0]
    mul      v30.8H, v16.8H, v2.8H
    mul      v31.8H, v17.8H, v2.8H
    sqrdmulh v16.8H, v16.8H, v3.8H
    sqrdmulh v17.8H, v17.8H, v3.8H
    mls      v30.8H, v16.8H, v0.H[0]
    mls      v31.8H, v17.8H, v0.H[0]

    // ========== Barrett reduction (all 8 output vectors) ==========
    sqdmulh v16.8H, v24.8H, v0.H[1]
    sqdmulh v17.8H, v25.8H, v0.H[1]
    sqdmulh v18.8H, v26.8H, v0.H[1]
    sqdmulh v19.8H, v27.8H, v0.H[1]

    srshr   v16.8H, v16.8H, #11
    sqdmulh v20.8H, v28.8H, v0.H[1]
    srshr   v17.8H, v17.8H, #11
    sqdmulh v21.8H, v29.8H, v0.H[1]
    srshr   v18.8H, v18.8H, #11
    sqdmulh v22.8H, v30.8H, v0.H[1]
    srshr   v19.8H, v19.8H, #11
    sqdmulh v23.8H, v31.8H, v0.H[1]

    mls     v24.8H, v16.8H, v0.H[0]
    srshr   v20.8H, v20.8H, #11
    mls     v25.8H, v17.8H, v0.H[0]
    srshr   v21.8H, v21.8H, #11
    mls     v26.8H, v18.8H, v0.H[0]
    srshr   v22.8H, v22.8H, #11
    mls     v27.8H, v19.8H, v0.H[0]
    srshr   v23.8H, v23.8H, #11

    mls     v28.8H, v20.8H, v0.H[0]
    mls     v29.8H, v21.8H, v0.H[0]
    mls     v30.8H, v22.8H, v0.H[0]
    mls     v31.8H, v23.8H, v0.H[0]

    add table, table, #256

    // ========== Inverse 4×4 Transpose + Store ==========
    trn1 v16.4S, v28.4S, v29.4S
    trn2 v17.4S, v28.4S, v29.4S
    trn1 v18.4S, v30.4S, v31.4S
    trn2 v19.4S, v30.4S, v31.4S

    trn1 v28.2D, v16.2D, v18.2D
    trn2 v30.2D, v16.2D, v18.2D
    trn1 v29.2D, v17.2D, v19.2D
    trn2 v31.2D, v17.2D, v19.2D

    str        q28, [src0, #1*16]
    trn1 v16.4S, v24.4S, v25.4S
    trn2 v17.4S, v24.4S, v25.4S
    str        q29, [src1, #1*16]
    trn1 v18.4S, v26.4S, v27.4S
    trn2 v19.4S, v26.4S, v27.4S

    str        q30, [src0, #3*16]
    trn1 v24.2D, v16.2D, v18.2D
    trn2 v26.2D, v16.2D, v18.2D
    str        q31, [src1, #3*16]
    trn1 v25.2D, v17.2D, v19.2D
    trn2 v27.2D, v17.2D, v19.2D

    sub counter, counter, #1
    cbnz counter, 1b

    str q24, [src0, #0*16]
    str q25, [src1, #0*16]
    str q26, [src0, #2*16]
    str q27, [src1, #2*16]


    .unreq    Q
    .unreq    BarrettM
    .unreq    src0
    .unreq    src1
    .unreq    table
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
    CRYPT_AARCH64_FUNC_END(MLKEM_INTT_bot)

// =============================================================================
// MLKEM_INTT_top — Inverse NTT, Layers 3-1 + n^{-1} Scaling (Gentleman-Sander butterfly)
// =============================================================================
//
// Signature: void MLKEM_INTT_top(int16_t *a, const int16_t *table)
//   x0 (src):   polynomial pointer (in/out)
//   x1 (table): inverse twiddle table
//
// Algorithm:
//   1. Set Q = 3329, BarrettM = 20159, FINAL_SCALE = 512|5040<<16,
//      FINAL_SCALE_F = 266|2618<<16 for n^{-1} Montgomery scaling
//   2. Load inverse twiddles v0-v3 (v0.H[0] = Q); load all 256 coefficients
//      into v8-v23 (second half v16-v23, first half loaded during computation)
//   3. Pass 1 (even vectors):
//      a. GS Layer 3 (stride 32): 4 twiddle pairs (v3.H[0-7])
//      b. GS Layer 2 (stride 64): 2 twiddle pairs (v1.H[0-7], interleaved)
//      c. GS Layer 1 (stride 128): 1 twiddle pair (v0.H[4-7])
//      d. n^{-1} Montgomery scaling: a[i] = a[i] × invN × R^{-1} mod Q
//      e. Store pass 1 results; load pass 2 odd-indexed vectors
//   4. Pass 2 (odd vectors): repeat steps 3a-3d on src[i*32+16], i=0..15
//   5. Store pass 2 results and return
//
// Register allocation:
//   v0-v3:   inverse twiddle factors (v0.H[0] = Q for Montgomery reduction mls)
//   v4:      FINAL_SCALE parameters: S[0]=invN, S[1]=invN_f for n^{-1} mul
//   v8-v23:  polynomial coefficients (v16-v23 = second half, v8-v15 loaded on-the-fly)
//   v24-v27: Montgomery mul intermediate results
//   v28-v31: Montgomery mul low products
//   x0 (src):  polynomial pointer (in/out)
//   x1 (table): inverse twiddle table pointer
//   w20 (Q):        modulus 3329
//   w21 (BarrettM): Barrett constant 20159
//   w22 (invN):     FINAL_SCALE = n^{-1} × R mod Q (packed: lo=512, hi=5040)
//   w23 (invN_f):   FINAL_SCALE_F (packed: lo=266, hi=2618)
//   x19 (counter):  loop counter (reserved)
//
// Notes:
//   The n^{-1} scaling absorbs the factor of n = 2^7 = 128 that accumulates
//   during the 7-layer inverse transform. It uses Montgomery multiplication
//   with FINAL_SCALE (packed as two 16-bit halves in w22/w23) applied to
//   all 16 coefficient vectors. Pipeline interleaving hides load latency
//   during the GS butterfly computation by issuing stores/loads during
//   the sqrdmulh latency window.
// =============================================================================
CRYPT_AARCH64_FUNC_START(MLKEM_INTT_top)
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
    Q         .req w20
    BarrettM  .req w21
    invN      .req w22      // n^(-1) mod Q for final scaling
    invN_f    .req w23      // Montgomery form of n^(-1)
    src       .req x0
    table     .req x1
    counter   .req x19

    mov Q, #3329              // Q
    mov BarrettM, #20159      // round(2^26 / Q)
    mov invN, #512            // FINAL_SCALE = NTT^{-1} * R mod Q
    movk invN, #5040, lsl #16 // FINAL_SCALE_hi
    mov invN_f, #266          // FINAL_SCALE_F = omega^{-64} * FINAL_SCALE mod Q
    movk invN_f, #2618, lsl #16 // FINAL_SCALE_F_hi

    mov v4.S[0], invN
    mov v4.S[1], invN_f

    ldr q0, [table, #0*16]
    mov v0.H[0], Q

    ldr q1, [table, #1*16]
    ldr q2, [table, #2*16]
    ldr q3, [table, #3*16]

    // Load second half of coefficients (indices 8-15)
    ldr q16, [src, # 8*32]
    ldr q17, [src, # 9*32]
    ldr q18, [src, #10*32]
    ldr q19, [src, #11*32]
    ldr q20, [src, #12*32]
    ldr q21, [src, #13*32]
    ldr q22, [src, #14*32]
    ldr q23, [src, #15*32]

    // ========== GS Layer 3 (stride 32): 8 twiddles v3.H[0-7] ==========
    // GS butterfly: (a,b) → (a+b, (a−b)×ω^{-1})
    sub     v28.8H, v16.8H, v17.8H
    ldr        q8, [src, #0*32]
    sub     v29.8H, v18.8H, v19.8H
    ldr        q9, [src, #1*32]
    sub     v30.8H, v20.8H, v21.8H
    ldr        q10, [src, #2*32]
    sub     v31.8H, v22.8H, v23.8H
    ldr        q11, [src, #3*32]

    add     v16.8H, v16.8H, v17.8H
    ldr        q12, [src, #4*32]
    add     v18.8H, v18.8H, v19.8H
    ldr        q13, [src, #5*32]
    add     v20.8H, v20.8H, v21.8H
    ldr        q14, [src, #6*32]
    add     v22.8H, v22.8H, v23.8H
    ldr        q15, [src, #7*32]


    // Butterfly with multiplication (first half of qo_butterfly_botll)
    mul      v17.8H, v28.8H, v3.H[0]
    sub      v24.8H, v8.8H, v9.8H
    mul      v19.8H, v29.8H, v3.H[2]
    sub      v25.8H, v10.8H, v11.8H
    mul      v21.8H, v30.8H, v3.H[4]
    sub      v26.8H, v12.8H, v13.8H
    mul      v23.8H, v31.8H, v3.H[6]
    sub      v27.8H, v14.8H, v15.8H

    sqrdmulh v28.8H, v28.8H, v3.H[1]
    add      v8.8H, v8.8H, v9.8H
    sqrdmulh v29.8H, v29.8H, v3.H[3]
    add      v10.8H, v10.8H, v11.8H
    sqrdmulh v30.8H, v30.8H, v3.H[5]
    add      v12.8H, v12.8H, v13.8H
    sqrdmulh v31.8H, v31.8H, v3.H[7]
    add      v14.8H, v14.8H, v15.8H

    mls      v17.8H, v28.8H, v0.H[0]
    mls      v19.8H, v29.8H, v0.H[0]
    mls      v21.8H, v30.8H, v0.H[0]
    mls      v23.8H, v31.8H, v0.H[0]
    sub      v28.8H, v16.8H, v18.8H
    mul      v9.8H, v24.8H, v2.H[0]
    sub      v29.8H, v17.8H, v19.8H
    mul      v11.8H, v25.8H, v2.H[2]
    sub      v30.8H, v20.8H, v22.8H
    mul      v13.8H, v26.8H, v2.H[4]
    sub      v31.8H, v21.8H, v23.8H
    mul      v15.8H, v27.8H, v2.H[6]

    sqrdmulh v24.8H, v24.8H, v2.H[1]
    add      v16.8H, v16.8H, v18.8H
    sqrdmulh v25.8H, v25.8H, v2.H[3]
    add      v17.8H, v17.8H, v19.8H
    sqrdmulh v26.8H, v26.8H, v2.H[5]
    add      v20.8H, v20.8H, v22.8H
    sqrdmulh v27.8H, v27.8H, v2.H[7]
    add      v21.8H, v21.8H, v23.8H

    mls      v9.8H, v24.8H, v0.H[0]
    mls      v11.8H, v25.8H, v0.H[0]
    mls      v13.8H, v26.8H, v0.H[0]
    mls      v15.8H, v27.8H, v0.H[0]
    // ========== GS Layer 2 (stride 64): 4 twiddles v1.H[4-7], v1.H[0-3] ==========
    sub      v24.8H, v8.8H, v10.8H
    mul      v18.8H, v28.8H, v1.H[4]
    sub      v25.8H, v9.8H, v11.8H
    mul      v19.8H, v29.8H, v1.H[4]
    sub      v26.8H, v12.8H, v14.8H
    mul      v22.8H, v30.8H, v1.H[6]
    sub      v27.8H, v13.8H, v15.8H
    mul      v23.8H, v31.8H, v1.H[6]

    sqrdmulh v28.8H, v28.8H, v1.H[5]
    add      v8.8H, v8.8H, v10.8H
    sqrdmulh v29.8H, v29.8H, v1.H[5]
    add      v9.8H, v9.8H, v11.8H
    sqrdmulh v30.8H, v30.8H, v1.H[7]
    add      v12.8H, v12.8H, v14.8H
    sqrdmulh v31.8H, v31.8H, v1.H[7]
    add      v13.8H, v13.8H, v15.8H

    mls      v18.8H, v28.8H, v0.H[0]
    mls      v19.8H, v29.8H, v0.H[0]
    mls      v22.8H, v30.8H, v0.H[0]
    mls      v23.8H, v31.8H, v0.H[0]
    sub      v28.8H, v16.8H, v20.8H
    mul      v10.8H, v24.8H, v1.H[0]
    sub      v29.8H, v17.8H, v21.8H
    mul      v11.8H, v25.8H, v1.H[0]
    sub      v30.8H, v18.8H, v22.8H
    mul      v14.8H, v26.8H, v1.H[2]
    sub      v31.8H, v19.8H, v23.8H
    mul      v15.8H, v27.8H, v1.H[2]

    sqrdmulh v24.8H, v24.8H, v1.H[1]
    add      v16.8H, v16.8H, v20.8H
    sqrdmulh v25.8H, v25.8H, v1.H[1]
    add      v17.8H, v17.8H, v21.8H
    sqrdmulh v26.8H, v26.8H, v1.H[3]
    add      v18.8H, v18.8H, v22.8H
    sqrdmulh v27.8H, v27.8H, v1.H[3]
    add      v19.8H, v19.8H, v23.8H

    mls      v10.8H, v24.8H, v0.H[0]
    mls      v11.8H, v25.8H, v0.H[0]
    mls      v14.8H, v26.8H, v0.H[0]
    mls      v15.8H, v27.8H, v0.H[0]
    // ========== GS Layer 1 (stride 128): 1 twiddle v0.H[4-7] ==========
    sub      v24.8H, v8.8H, v12.8H
    mul      v20.8H, v28.8H, v0.H[6]
    sub      v25.8H, v9.8H, v13.8H
    mul      v21.8H, v29.8H, v0.H[6]
    sub      v26.8H, v10.8H, v14.8H
    mul      v22.8H, v30.8H, v0.H[6]
    sub      v27.8H, v11.8H, v15.8H
    mul      v23.8H, v31.8H, v0.H[6]

    sqrdmulh v28.8H, v28.8H, v0.H[7]
    add      v8.8H, v8.8H, v12.8H
    sqrdmulh v29.8H, v29.8H, v0.H[7]
    add      v9.8H, v9.8H, v13.8H
    sqrdmulh v30.8H, v30.8H, v0.H[7]
    add      v10.8H, v10.8H, v14.8H
    sqrdmulh v31.8H, v31.8H, v0.H[7]
    add      v11.8H, v11.8H, v15.8H

    mls      v20.8H, v28.8H, v0.H[0]
    mls      v21.8H, v29.8H, v0.H[0]
    mls      v22.8H, v30.8H, v0.H[0]
    mls      v23.8H, v31.8H, v0.H[0]
    sub      v28.8H, v8.8H, v16.8H
    mul      v12.8H, v24.8H, v0.H[4]
    sub      v29.8H, v9.8H, v17.8H
    mul      v13.8H, v25.8H, v0.H[4]
    sub      v30.8H, v10.8H, v18.8H
    mul      v14.8H, v26.8H, v0.H[4]
    sub      v31.8H, v11.8H, v19.8H
    mul      v15.8H, v27.8H, v0.H[4]

    sqrdmulh v24.8H, v24.8H, v0.H[5]
    add      v8.8H, v8.8H, v16.8H
    sqrdmulh v25.8H, v25.8H, v0.H[5]
    add      v9.8H, v9.8H, v17.8H
    sqrdmulh v26.8H, v26.8H, v0.H[5]
    add      v10.8H, v10.8H, v18.8H
    sqrdmulh v27.8H, v27.8H, v0.H[5]
    add      v11.8H, v11.8H, v19.8H

    mls      v12.8H, v24.8H, v0.H[0]
    mls      v13.8H, v25.8H, v0.H[0]
    mls      v14.8H, v26.8H, v0.H[0]
    mls      v15.8H, v27.8H, v0.H[0]
    // ========== n^{-1} Montgomery scaling: a[i] = a[i] × invN × R^{-1} mod Q ==========
    // v4.H[0] = invN (low), v4.H[1] = invN_f (high) for Montgomery mul.
    // Applied to all 16 coefficient vectors (8 from each half).
    // The sub/add here separates the two branches that get different twiddle treatment
    // during the final layer, then both are scaled by invN.
    sub      v24.8H, v12.8H, v20.8H
    mul      v16.8H, v28.8H, v4.H[2]
    sub      v25.8H, v13.8H, v21.8H
    mul      v17.8H, v29.8H, v4.H[2]
    sub      v26.8H, v14.8H, v22.8H
    mul      v18.8H, v30.8H, v4.H[2]
    sub      v27.8H, v15.8H, v23.8H
    mul      v19.8H, v31.8H, v4.H[2]

    sqrdmulh v28.8H, v28.8H, v4.H[3]
    add      v12.8H, v12.8H, v20.8H
    sqrdmulh v29.8H, v29.8H, v4.H[3]
    add      v13.8H, v13.8H, v21.8H
    sqrdmulh v30.8H, v30.8H, v4.H[3]
    add      v14.8H, v14.8H, v22.8H
    sqrdmulh v31.8H, v31.8H, v4.H[3]
    add      v15.8H, v15.8H, v23.8H

    mls      v16.8H, v28.8H, v0.H[0]
    mls      v17.8H, v29.8H, v0.H[0]
    mls      v18.8H, v30.8H, v0.H[0]
    mls      v19.8H, v31.8H, v0.H[0]

    mul      v20.8H, v24.8H, v4.H[2]
    mul      v21.8H, v25.8H, v4.H[2]
    mul      v22.8H, v26.8H, v4.H[2]
    mul      v23.8H, v27.8H, v4.H[2]

    str         q16, [src, #8*32]
    ldr         q16, [src, #(16+8*32)]
    sqrdmulh v24.8H, v24.8H, v4.H[3]
    str         q17, [src, #9*32]
    ldr         q17, [src, #(16+9*32)]
    sqrdmulh v25.8H, v25.8H, v4.H[3]
    str         q18, [src, #10*32]
    ldr         q18, [src, #(16+10*32)]
    sqrdmulh v26.8H, v26.8H, v4.H[3]
    str         q19, [src, #11*32]
    ldr         q19, [src, #(16+11*32)]
    sqrdmulh v27.8H, v27.8H, v4.H[3]

    mls      v20.8H, v24.8H, v0.H[0]
    mls      v21.8H, v25.8H, v0.H[0]
    mls      v22.8H, v26.8H, v0.H[0]
    mls      v23.8H, v27.8H, v0.H[0]

    str         q20, [src, #12*32]
    ldr         q20, [src, #(16+12*32)]
    sqrdmulh v28.8H, v8.8H, v4.H[1]
    str         q21, [src, #13*32]
    ldr         q21, [src, #(16+13*32)]
    sqrdmulh v29.8H, v9.8H, v4.H[1]
    str         q22, [src, #14*32]
    ldr         q22, [src, #(16+14*32)]
    sqrdmulh v30.8H, v10.8H, v4.H[1]
    str         q23, [src, #15*32]
    ldr         q23, [src, #(16+15*32)]
    sqrdmulh v31.8H, v11.8H, v4.H[1]

    mul      v8.8H, v8.8H, v4.H[0]
    mul      v9.8H, v9.8H, v4.H[0]
    mul      v10.8H, v10.8H, v4.H[0]
    mul      v11.8H, v11.8H, v4.H[0]

    mls      v8.8H, v28.8H, v0.H[0]
    mls      v9.8H, v29.8H, v0.H[0]
    mls      v10.8H, v30.8H, v0.H[0]
    mls      v11.8H, v31.8H, v0.H[0]

    sqrdmulh v24.8H, v12.8H, v4.H[1]
    sub      v28.8H, v16.8H, v17.8H
    str         q8, [src, #0*32]
    sqrdmulh v25.8H, v13.8H, v4.H[1]
    sub      v29.8H, v18.8H, v19.8H
    str         q9, [src, #1*32]
    sqrdmulh v26.8H, v14.8H, v4.H[1]
    sub      v30.8H, v20.8H, v21.8H
    str         q10, [src, #2*32]
    sqrdmulh v27.8H, v15.8H, v4.H[1]
    sub      v31.8H, v22.8H, v23.8H
    str         q11, [src, #3*32]

    mul      v12.8H, v12.8H, v4.H[0]
    add      v16.8H, v16.8H, v17.8H
    ldr         q8, [src, #(16+0*32)]
    mul      v13.8H, v13.8H, v4.H[0]
    add      v18.8H, v18.8H, v19.8H
    ldr         q9, [src, #(16+1*32)]
    mul      v14.8H, v14.8H, v4.H[0]
    add      v20.8H, v20.8H, v21.8H
    ldr         q10, [src, #(16+2*32)]
    mul      v15.8H, v15.8H, v4.H[0]
    add      v22.8H, v22.8H, v23.8H
    ldr         q11, [src, #(16+3*32)]

    mls      v12.8H, v24.8H, v0.H[0]
    mls      v13.8H, v25.8H, v0.H[0]
    mls      v14.8H, v26.8H, v0.H[0]
    mls      v15.8H, v27.8H, v0.H[0]

    str q12, [src, # 4*32]
    ldr q12, [src, #(16+ 4*32)]
    str q13, [src, # 5*32]
    ldr q13, [src, #(16+ 5*32)]
    str q14, [src, # 6*32]
    ldr q14, [src, #(16+ 6*32)]
    str q15, [src, # 7*32]
    ldr q15, [src, #(16+ 7*32)]

    // ============================= Pass 2 (odd vectors, offset +16) =============================
    // Same GS Layer 3→1 + n^{-1} scaling as pass 1, on odd-indexed 128-bit vectors.
    // ========== GS Layer 3 (stride 32): 8 twiddles v3.H[0-7] ==========
    mul      v17.8H, v28.8H, v3.H[0]
    sub      v24.8H, v8.8H, v9.8H
    mul      v19.8H, v29.8H, v3.H[2]
    sub      v25.8H, v10.8H, v11.8H
    mul      v21.8H, v30.8H, v3.H[4]
    sub      v26.8H, v12.8H, v13.8H
    mul      v23.8H, v31.8H, v3.H[6]
    sub      v27.8H, v14.8H, v15.8H

    sqrdmulh v28.8H, v28.8H, v3.H[1]
    add      v8.8H, v8.8H, v9.8H
    sqrdmulh v29.8H, v29.8H, v3.H[3]
    add      v10.8H, v10.8H, v11.8H
    sqrdmulh v30.8H, v30.8H, v3.H[5]
    add      v12.8H, v12.8H, v13.8H
    sqrdmulh v31.8H, v31.8H, v3.H[7]
    add      v14.8H, v14.8H, v15.8H

    mls      v17.8H, v28.8H, v0.H[0]
    mls      v19.8H, v29.8H, v0.H[0]
    mls      v21.8H, v30.8H, v0.H[0]
    mls      v23.8H, v31.8H, v0.H[0]
    // ========== GS Layer 2 (stride 64): 4 twiddles v2.H[0-7] ==========
    sub      v28.8H, v16.8H, v18.8H
    mul      v9.8H, v24.8H, v2.H[0]
    sub      v29.8H, v17.8H, v19.8H
    mul      v11.8H, v25.8H, v2.H[2]
    sub      v30.8H, v20.8H, v22.8H
    mul      v13.8H, v26.8H, v2.H[4]
    sub      v31.8H, v21.8H, v23.8H
    mul      v15.8H, v27.8H, v2.H[6]

    sqrdmulh v24.8H, v24.8H, v2.H[1]
    add      v16.8H, v16.8H, v18.8H
    sqrdmulh v25.8H, v25.8H, v2.H[3]
    add      v17.8H, v17.8H, v19.8H
    sqrdmulh v26.8H, v26.8H, v2.H[5]
    add      v20.8H, v20.8H, v22.8H
    sqrdmulh v27.8H, v27.8H, v2.H[7]
    add      v21.8H, v21.8H, v23.8H

    mls      v9.8H, v24.8H, v0.H[0]
    mls      v11.8H, v25.8H, v0.H[0]
    mls      v13.8H, v26.8H, v0.H[0]
    mls      v15.8H, v27.8H, v0.H[0]
    sub      v24.8H, v8.8H, v10.8H
    mul      v18.8H, v28.8H, v1.H[4]
    sub      v25.8H, v9.8H, v11.8H
    mul      v19.8H, v29.8H, v1.H[4]
    sub      v26.8H, v12.8H, v14.8H
    mul      v22.8H, v30.8H, v1.H[6]
    sub      v27.8H, v13.8H, v15.8H
    mul      v23.8H, v31.8H, v1.H[6]

    sqrdmulh v28.8H, v28.8H, v1.H[5]
    add      v8.8H, v8.8H, v10.8H
    sqrdmulh v29.8H, v29.8H, v1.H[5]
    add      v9.8H, v9.8H, v11.8H
    sqrdmulh v30.8H, v30.8H, v1.H[7]
    add      v12.8H, v12.8H, v14.8H
    sqrdmulh v31.8H, v31.8H, v1.H[7]
    add      v13.8H, v13.8H, v15.8H

    mls      v18.8H, v28.8H, v0.H[0]
    mls      v19.8H, v29.8H, v0.H[0]
    mls      v22.8H, v30.8H, v0.H[0]
    mls      v23.8H, v31.8H, v0.H[0]
    sub      v28.8H, v16.8H, v20.8H
    mul      v10.8H, v24.8H, v1.H[0]
    sub      v29.8H, v17.8H, v21.8H
    mul      v11.8H, v25.8H, v1.H[0]
    sub      v30.8H, v18.8H, v22.8H
    mul      v14.8H, v26.8H, v1.H[2]
    sub      v31.8H, v19.8H, v23.8H
    mul      v15.8H, v27.8H, v1.H[2]

    sqrdmulh v24.8H, v24.8H, v1.H[1]
    add      v16.8H, v16.8H, v20.8H
    sqrdmulh v25.8H, v25.8H, v1.H[1]
    add      v17.8H, v17.8H, v21.8H
    sqrdmulh v26.8H, v26.8H, v1.H[3]
    add      v18.8H, v18.8H, v22.8H
    sqrdmulh v27.8H, v27.8H, v1.H[3]
    add      v19.8H, v19.8H, v23.8H

    mls      v10.8H, v24.8H, v0.H[0]
    mls      v11.8H, v25.8H, v0.H[0]
    mls      v14.8H, v26.8H, v0.H[0]
    mls      v15.8H, v27.8H, v0.H[0]
    // ========== GS Layer 1 (stride 128): 1 twiddle v0.H[4-7] ==========
    sub      v24.8H, v8.8H, v12.8H
    mul      v20.8H, v28.8H, v0.H[6]
    sub      v25.8H, v9.8H, v13.8H
    mul      v21.8H, v29.8H, v0.H[6]
    sub      v26.8H, v10.8H, v14.8H
    mul      v22.8H, v30.8H, v0.H[6]
    sub      v27.8H, v11.8H, v15.8H
    mul      v23.8H, v31.8H, v0.H[6]

    sqrdmulh v28.8H, v28.8H, v0.H[7]
    add      v8.8H, v8.8H, v12.8H
    sqrdmulh v29.8H, v29.8H, v0.H[7]
    add      v9.8H, v9.8H, v13.8H
    sqrdmulh v30.8H, v30.8H, v0.H[7]
    add      v10.8H, v10.8H, v14.8H
    sqrdmulh v31.8H, v31.8H, v0.H[7]
    add      v11.8H, v11.8H, v15.8H

    mls      v20.8H, v28.8H, v0.H[0]
    mls      v21.8H, v29.8H, v0.H[0]
    mls      v22.8H, v30.8H, v0.H[0]
    mls      v23.8H, v31.8H, v0.H[0]
    sub      v28.8H, v8.8H, v16.8H
    mul      v12.8H, v24.8H, v0.H[4]
    sub      v29.8H, v9.8H, v17.8H
    mul      v13.8H, v25.8H, v0.H[4]
    sub      v30.8H, v10.8H, v18.8H
    mul      v14.8H, v26.8H, v0.H[4]
    sub      v31.8H, v11.8H, v19.8H
    mul      v15.8H, v27.8H, v0.H[4]

    sqrdmulh v24.8H, v24.8H, v0.H[5]
    add      v8.8H, v8.8H, v16.8H
    sqrdmulh v25.8H, v25.8H, v0.H[5]
    add      v9.8H, v9.8H, v17.8H
    sqrdmulh v26.8H, v26.8H, v0.H[5]
    add      v10.8H, v10.8H, v18.8H
    sqrdmulh v27.8H, v27.8H, v0.H[5]
    add      v11.8H, v11.8H, v19.8H

    mls      v12.8H, v24.8H, v0.H[0]
    mls      v13.8H, v25.8H, v0.H[0]
    mls      v14.8H, v26.8H, v0.H[0]
    mls      v15.8H, v27.8H, v0.H[0]
    // ========== n^{-1} Montgomery scaling (pass 2): a[i] = a[i] × invN × R^{-1} mod Q ==========
    sub      v24.8H, v12.8H, v20.8H
    mul      v16.8H, v28.8H, v4.H[2]
    sub      v25.8H, v13.8H, v21.8H
    mul      v17.8H, v29.8H, v4.H[2]
    sub      v26.8H, v14.8H, v22.8H
    mul      v18.8H, v30.8H, v4.H[2]
    sub      v27.8H, v15.8H, v23.8H
    mul      v19.8H, v31.8H, v4.H[2]

    sqrdmulh v28.8H, v28.8H, v4.H[3]
    add      v12.8H, v12.8H, v20.8H
    sqrdmulh v29.8H, v29.8H, v4.H[3]
    add      v13.8H, v13.8H, v21.8H
    sqrdmulh v30.8H, v30.8H, v4.H[3]
    add      v14.8H, v14.8H, v22.8H
    sqrdmulh v31.8H, v31.8H, v4.H[3]
    add      v15.8H, v15.8H, v23.8H

    mls      v16.8H, v28.8H, v0.H[0]
    mls      v17.8H, v29.8H, v0.H[0]
    mls      v18.8H, v30.8H, v0.H[0]
    mls      v19.8H, v31.8H, v0.H[0]

    mul      v20.8H, v24.8H, v4.H[2]
    mul      v21.8H, v25.8H, v4.H[2]
    mul      v22.8H, v26.8H, v4.H[2]
    mul      v23.8H, v27.8H, v4.H[2]

    str         q16, [src, #(16+8*32)]
    sqrdmulh v24.8H, v24.8H, v4.H[3]
    str         q17, [src, #(16+9*32)]
    sqrdmulh v25.8H, v25.8H, v4.H[3]
    str         q18, [src, #(16+10*32)]
    sqrdmulh v26.8H, v26.8H, v4.H[3]
    str         q19, [src, #(16+11*32)]
    sqrdmulh v27.8H, v27.8H, v4.H[3]

    mls      v20.8H, v24.8H, v0.H[0]
    mls      v21.8H, v25.8H, v0.H[0]
    mls      v22.8H, v26.8H, v0.H[0]
    mls      v23.8H, v27.8H, v0.H[0]


    str         q20, [src, #(16+12*32)]
    sqrdmulh v28.8H, v8.8H, v4.H[1]
    str         q21, [src, #(16+13*32)]
    sqrdmulh v29.8H, v9.8H, v4.H[1]
    str         q22, [src, #(16+14*32)]
    sqrdmulh v30.8H, v10.8H, v4.H[1]
    str         q23, [src, #(16+15*32)]
    sqrdmulh v31.8H, v11.8H, v4.H[1]

    mul      v8.8H, v8.8H, v4.H[0]
    mul      v9.8H, v9.8H, v4.H[0]
    mul      v10.8H, v10.8H, v4.H[0]
    mul      v11.8H, v11.8H, v4.H[0]

    mls      v8.8H, v28.8H, v0.H[0]
    mls      v9.8H, v29.8H, v0.H[0]
    mls      v10.8H, v30.8H, v0.H[0]
    mls      v11.8H, v31.8H, v0.H[0]

    str         q8, [src, #(16+0*32)]
    sqrdmulh v24.8H, v12.8H, v4.H[1]
    str         q9, [src, #(16+1*32)]
    sqrdmulh v25.8H, v13.8H, v4.H[1]
    str         q10, [src, #(16+2*32)]
    sqrdmulh v26.8H, v14.8H, v4.H[1]
    str         q11, [src, #(16+3*32)]
    sqrdmulh v27.8H, v15.8H, v4.H[1]

    mul      v12.8H, v12.8H, v4.H[0]
    mul      v13.8H, v13.8H, v4.H[0]
    mul      v14.8H, v14.8H, v4.H[0]
    mul      v15.8H, v15.8H, v4.H[0]

    mls      v12.8H, v24.8H, v0.H[0]
    mls      v13.8H, v25.8H, v0.H[0]
    mls      v14.8H, v26.8H, v0.H[0]
    mls      v15.8H, v27.8H, v0.H[0]

    str q12, [src, #(16+ 4*32)]
    str q13, [src, #(16+ 5*32)]
    str q14, [src, #(16+ 6*32)]
    str q15, [src, #(16+ 7*32)]

    .unreq    Q
    .unreq    BarrettM
    .unreq    invN
    .unreq    invN_f
    .unreq    src
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
    CRYPT_AARCH64_FUNC_END(MLKEM_INTT_top)

#endif
