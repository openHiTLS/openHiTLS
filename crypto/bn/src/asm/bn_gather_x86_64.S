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
#ifdef HITLS_CRYPTO_BN

/*
 * Constant-time gathers for the Montgomery exponentiation precomputation
 * table. The table keeps the 2^winBits entries limb-interleaved: limb j of
 * entry i lies at tbl[(j << winBits) + i]. Both routines read every table
 * word with plain full-width loads at public addresses and select the wanted
 * entry with equality masks kept in 16/32-byte-aligned stack scratch; the
 * secret index only reaches the mask compares, and the scratch is wiped
 * before returning. The per-winBits dispatch and all loop bounds depend only
 * on the public winBits/mSize. Requires winBits in [2, 6].
 */

/* One fully unrolled scan of a table row: \nvec 16-byte blocks ANDed with the
   stack masks and folded to one 64-bit limb stored to (%rdi). */
.macro SSE_ROW_LOOP name nvec
.Lsse_row_\name:
    pxor    %xmm0,%xmm0
    .set    GATHER_OFF, 0
    .rept   \nvec
    movdqu  GATHER_OFF(%rsi),%xmm1
    pand    GATHER_OFF(%rsp),%xmm1
    por     %xmm1,%xmm0
    .set    GATHER_OFF, GATHER_OFF+16
    .endr
    pshufd  $0xEE,%xmm0,%xmm1           // fold the high lane onto the low one
    por     %xmm1,%xmm0
    movq    %xmm0,(%rdi)
    addq    $8,%rdi
    addq    $(\nvec*16),%rsi
    decl    %edx
    jnz     .Lsse_row_\name
    jmp     .Lsse_done
.endm

/* Same as SSE_ROW_LOOP with 32-byte blocks. */
.macro AVX_ROW_LOOP name nvec
.Lavx_row_\name:
    vpxor   %xmm0,%xmm0,%xmm0
    .set    GATHER_OFF, 0
    .rept   \nvec
    vmovdqu GATHER_OFF(%rsi),%ymm1
    vpand   GATHER_OFF(%rsp),%ymm1,%ymm1
    vpor    %ymm1,%ymm0,%ymm0
    .set    GATHER_OFF, GATHER_OFF+32
    .endr
    vextracti128 $1,%ymm0,%xmm1
    vpor    %xmm1,%xmm0,%xmm0
    vpshufd $0xEE,%xmm0,%xmm1           // fold the high lane onto the low one
    vpor    %xmm1,%xmm0,%xmm0
    vmovq   %xmm0,(%rdi)
    addq    $8,%rdi
    addq    $(\nvec*32),%rsi
    decl    %edx
    jnz     .Lavx_row_\name
    jmp     .Lavx_done
.endm

.section .rodata
.align  16
.Lgather_sse_init:
    .quad   0, 1
.Lgather_sse_step:
    .quad   2, 2
.align  32
.Lgather_avx_init:
    .quad   0, 1, 2, 3
.Lgather_avx_step:
    .quad   4, 4, 4, 4

.text

/*
 * void MontGatherSse2_Asm(uint64_t *dst, const uint64_t *tbl, uint32_t mSize,
 *                         uint32_t winBits, uint64_t idx);
 * Input registers:
 *      rdi: destination, mSize limbs
 *      rsi: interleaved table, mSize << winBits limbs
 *      edx: mSize
 *      ecx: winBits, in [2, 6]
 *      r8:  secret entry index, < 2^winBits
 */
.globl  MontGatherSse2_Asm
.type   MontGatherSse2_Asm,@function
.align  16
MontGatherSse2_Asm:
.cfi_startproc
    movq    %rsp,%r11
    subq    $528,%rsp                   // 32 mask vectors * 16 bytes + alignment slack
    andq    $-16,%rsp
    movl    $1,%eax
    shll    %cl,%eax                    // eax = tabSize = 1 << winBits
    shrl    $1,%eax                     // eax = tabSize / 2 mask vectors
    movq    %r8,%xmm7
    punpcklqdq %xmm7,%xmm7              // xmm7 = { idx, idx }
    movdqa  .Lgather_sse_init(%rip),%xmm6
    movdqa  .Lgather_sse_step(%rip),%xmm5
    movq    %rsp,%r9
.Lsse_mask:
    // 64-bit lane equality from two 32-bit compares (SSE2 has no pcmpeqq):
    // the high lane halves are zero because idx and the counters are < 2^6.
    movdqa  %xmm6,%xmm0
    pcmpeqd %xmm7,%xmm0
    pshufd  $0xB1,%xmm0,%xmm1           // 0xB1 swaps the 32-bit halves of each lane
    pand    %xmm1,%xmm0
    movdqa  %xmm0,(%r9)
    paddq   %xmm5,%xmm6
    addq    $16,%r9
    decl    %eax
    jnz     .Lsse_mask
    testl   %edx,%edx
    jz      .Lsse_done
    cmpl    $5,%ecx                     // dispatch on the public window size
    je      .Lsse_row_w5
    ja      .Lsse_row_w6
    cmpl    $3,%ecx
    je      .Lsse_row_w3
    ja      .Lsse_row_w4
    SSE_ROW_LOOP w2 2
    SSE_ROW_LOOP w3 4
    SSE_ROW_LOOP w4 8
    SSE_ROW_LOOP w5 16
    SSE_ROW_LOOP w6 32
.Lsse_done:
    pxor    %xmm0,%xmm0                 // wipe the mask scratch: it encodes the secret index
    .set    GATHER_OFF, 0
    .rept   32
    movdqa  %xmm0,GATHER_OFF(%rsp)
    .set    GATHER_OFF, GATHER_OFF+16
    .endr
    movq    %r11,%rsp
    ret
.cfi_endproc
.size   MontGatherSse2_Asm,.-MontGatherSse2_Asm

/*
 * void MontGatherAvx2_Asm(uint64_t *dst, const uint64_t *tbl, uint32_t mSize,
 *                         uint32_t winBits, uint64_t idx);
 * Same contract as MontGatherSse2_Asm; the caller must have checked AVX2
 * support at run time.
 */
.globl  MontGatherAvx2_Asm
.type   MontGatherAvx2_Asm,@function
.align  16
MontGatherAvx2_Asm:
.cfi_startproc
    movq    %rsp,%r11
    subq    $560,%rsp                   // 16 mask vectors * 32 bytes + alignment slack
    andq    $-32,%rsp
    movl    $1,%eax
    shll    %cl,%eax                    // eax = tabSize = 1 << winBits
    shrl    $2,%eax                     // eax = tabSize / 4 mask vectors
    vmovq   %r8,%xmm0
    vpbroadcastq %xmm0,%ymm7            // ymm7 = { idx, idx, idx, idx }
    vmovdqa .Lgather_avx_init(%rip),%ymm6
    vmovdqa .Lgather_avx_step(%rip),%ymm5
    movq    %rsp,%r9
.Lavx_mask:
    vpcmpeqq %ymm7,%ymm6,%ymm0
    vmovdqa %ymm0,(%r9)
    vpaddq  %ymm5,%ymm6,%ymm6
    addq    $32,%r9
    decl    %eax
    jnz     .Lavx_mask
    testl   %edx,%edx
    jz      .Lavx_done
    cmpl    $5,%ecx                     // dispatch on the public window size
    je      .Lavx_row_w5
    ja      .Lavx_row_w6
    cmpl    $3,%ecx
    je      .Lavx_row_w3
    ja      .Lavx_row_w4
    AVX_ROW_LOOP w2 1
    AVX_ROW_LOOP w3 2
    AVX_ROW_LOOP w4 4
    AVX_ROW_LOOP w5 8
    AVX_ROW_LOOP w6 16
.Lavx_done:
    vpxor   %xmm0,%xmm0,%xmm0           // wipe the mask scratch: it encodes the secret index
    .set    GATHER_OFF, 0
    .rept   16
    vmovdqa %ymm0,GATHER_OFF(%rsp)
    .set    GATHER_OFF, GATHER_OFF+32
    .endr
    vzeroupper
    movq    %r11,%rsp
    ret
.cfi_endproc
.size   MontGatherAvx2_Asm,.-MontGatherAvx2_Asm

#endif /* HITLS_CRYPTO_BN */

.section .note.GNU-stack,"",@progbits
