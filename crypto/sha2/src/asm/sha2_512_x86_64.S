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
#ifdef HITLS_CRYPTO_SHA512

.file   "sha2_512_x86_64.S"

.set TEMP1, %rbp
.set TEMP2, %rax
.set TEMP3, %rbx
.set TEMP4, %rcx
.set TEMP5, %rdi

.set YTEMP1, %ymm8
.set YTEMP2, %ymm9
.set YTEMP3, %ymm10
.set YTEMP4, %ymm11
.set YTEMP5, %ymm12
.set YTEMP6, %ymm13
.set YTEMP7, %ymm14

    .struct 0
SHA512_wk:
    .struct SHA512_wk + 1280
SHA512_in:
    .struct SHA512_in + 8
SHA512_hash:
    .struct SHA512_hash + 8
SHA512_num:
    .struct SHA512_num + 8
SHA512_rsp:
    .struct SHA512_rsp + 8
SHA512_size:

.section .rodata
.balign    64
.type    g_k512,%object
g_k512:
    .quad    0x428a2f98d728ae22, 0x7137449123ef65cd,    0x428a2f98d728ae22, 0x7137449123ef65cd
    .quad    0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,    0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
    .quad    0x3956c25bf348b538, 0x59f111f1b605d019,    0x3956c25bf348b538, 0x59f111f1b605d019
    .quad    0x923f82a4af194f9b, 0xab1c5ed5da6d8118,    0x923f82a4af194f9b, 0xab1c5ed5da6d8118
    .quad    0xd807aa98a3030242, 0x12835b0145706fbe,    0xd807aa98a3030242, 0x12835b0145706fbe
    .quad    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
    .quad    0x72be5d74f27b896f, 0x80deb1fe3b1696b1,    0x72be5d74f27b896f, 0x80deb1fe3b1696b1
    .quad    0x9bdc06a725c71235, 0xc19bf174cf692694,    0x9bdc06a725c71235, 0xc19bf174cf692694
    .quad    0xe49b69c19ef14ad2, 0xefbe4786384f25e3,    0xe49b69c19ef14ad2, 0xefbe4786384f25e3
    .quad    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
    .quad    0x2de92c6f592b0275, 0x4a7484aa6ea6e483,    0x2de92c6f592b0275, 0x4a7484aa6ea6e483
    .quad    0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,    0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
    .quad    0x983e5152ee66dfab, 0xa831c66d2db43210,    0x983e5152ee66dfab, 0xa831c66d2db43210
    .quad    0xb00327c898fb213f, 0xbf597fc7beef0ee4,    0xb00327c898fb213f, 0xbf597fc7beef0ee4
    .quad    0xc6e00bf33da88fc2, 0xd5a79147930aa725,    0xc6e00bf33da88fc2, 0xd5a79147930aa725
    .quad    0x06ca6351e003826f, 0x142929670a0e6e70,    0x06ca6351e003826f, 0x142929670a0e6e70
    .quad    0x27b70a8546d22ffc, 0x2e1b21385c26c926,    0x27b70a8546d22ffc, 0x2e1b21385c26c926
    .quad    0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,    0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
    .quad    0x650a73548baf63de, 0x766a0abb3c77b2a8,    0x650a73548baf63de, 0x766a0abb3c77b2a8
    .quad    0x81c2c92e47edaee6, 0x92722c851482353b,    0x81c2c92e47edaee6, 0x92722c851482353b
    .quad    0xa2bfe8a14cf10364, 0xa81a664bbc423001,    0xa2bfe8a14cf10364, 0xa81a664bbc423001
    .quad    0xc24b8b70d0f89791, 0xc76c51a30654be30,    0xc24b8b70d0f89791, 0xc76c51a30654be30
    .quad    0xd192e819d6ef5218, 0xd69906245565a910,    0xd192e819d6ef5218, 0xd69906245565a910
    .quad    0xf40e35855771202a, 0x106aa07032bbd1b8,    0xf40e35855771202a, 0x106aa07032bbd1b8
    .quad    0x19a4c116b8d2d0c8, 0x1e376c085141ab53,    0x19a4c116b8d2d0c8, 0x1e376c085141ab53
    .quad    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
    .quad    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
    .quad    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
    .quad    0x748f82ee5defb2fc, 0x78a5636f43172f60,    0x748f82ee5defb2fc, 0x78a5636f43172f60
    .quad    0x84c87814a1f0ab72, 0x8cc702081a6439ec,    0x84c87814a1f0ab72, 0x8cc702081a6439ec
    .quad    0x90befffa23631e28, 0xa4506cebde82bde9,    0x90befffa23631e28, 0xa4506cebde82bde9
    .quad    0xbef9a3f7b2c67915, 0xc67178f2e372532b,    0xbef9a3f7b2c67915, 0xc67178f2e372532b
    .quad    0xca273eceea26619c, 0xd186b8c721c0c207,    0xca273eceea26619c, 0xd186b8c721c0c207
    .quad    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
    .quad    0x06f067aa72176fba, 0x0a637dc5a2c898a6,    0x06f067aa72176fba, 0x0a637dc5a2c898a6
    .quad    0x113f9804bef90dae, 0x1b710b35131c471b,    0x113f9804bef90dae, 0x1b710b35131c471b
    .quad    0x28db77f523047d84, 0x32caab7b40c72493,    0x28db77f523047d84, 0x32caab7b40c72493
    .quad    0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,    0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
    .quad    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
    .quad    0x5fcb6fab3ad6faec, 0x6c44198c4a475817,    0x5fcb6fab3ad6faec, 0x6c44198c4a475817
.size    g_k512, .-g_k512

    .balign    64
    .type    g_endianMask,%object
g_endianMask:
    .quad 0x0001020304050607, 0x08090a0b0c0d0e0f
    .quad 0x0001020304050607, 0x08090a0b0c0d0e0f
.size   g_endianMask, .-g_endianMask

/**
 *  Macro Description： Processes the update of the hash value in one round of 80 compressions.
 *  input register：
 *       addr: Stack space initial address
 *   wkOffset: wi+k512 Data address offset
 *      a - h: Intermediate variable of hash value
 *  Modify the register：temp1, temp2, temp3, temp4, temp5
 *  Output register：
 *          h： Indicates the value after a cyclic update.
 *          d： Indicates the value after a cyclic update.
 *          temp1: BSIG0(a) from last round
 *          temp4: b^a for next round b^c
 *  Function/Macro Call: None
 *  Implementation Description:
 *          T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
 *          T2 = BSIG0(a) + MAJ(a,b,c)
 *          CH(e, f, g) = (e AND f) XOR ((NOT e) AND g)
 *          MAJ(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c)
 *                       = CH(a^b, c, b)
 *                       = ((a XOR b) AND c) XOR ((NOT(a XOR b)) AND b)
 *                       = (b XOR c) AND (a XOR b) XOR b
 *          BSIG0(x) = ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x)
 *          BSIG1(x) = ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x)
 *          d += T1;        h = T1 + T2
 *  Optimization Principle：asert b^c in temp4, temp1 equal 0, f in temp5 when round begin
 *              mov  b, temp4
 *              xor  temp1, temp1
 *              xor  c, temp4
 *              mov  f, temp5
 *           swap temp2 temp4 for next round
 *           add BSIG0(a) back to a when all round finished
 */
    .macro ONE_ROUND    a, b, c, d, e, f, g, h, temp1, temp2, temp3, temp4, temp5, addr, wkOffset
        // asert b^c in temp4, temp1 equal 0, f in temp5 when round begin
        addq \wkOffset(\addr), \h       // h += Kt + Wt
        and  \e, \temp5                 // e&f
        rorx $14, \e, \temp2            // ROTR^14(e)
        addq \temp1, \a                 // a += BSIG0(a) from last round
        rorx $18, \e, \temp3            // ROTR^18(e)
        andn \g, \e, \temp1             // (~e)&g
        xor  \temp2, \temp3             // ROTR^14(e) ^ ROTR^18(e)
        xor  \temp1, \temp5             // CH(e,f,g)
        rorx $41, \e, \temp2            // ROTR^41(e)
        addq \temp5, \h                 // h += CH(e,f,g)
        xor  \temp2, \temp3             // BSIG1(e)
        rorx $28, \a, \temp1            // ROTR^28(a)
        mov  \a, \temp2                 // a
        addq \temp3, \h                 // h += BSIG1(e)
        rorx $34, \a, \temp5            // ROTR^34(a)
        xor  \b, \temp2                 // b^a for next round b^c
        addq \h, \d                     // d += T1
        xor  \temp5, \temp1             // ROTR^14(a) ^ ROTR^34(a)
        and  \temp2, \temp4             // (b^a) & (b^c)
        rorx $39, \a, \temp3            // ROTR^39(a)
        xor  \b, \temp4                 // Maj(a,b,c)
        mov  \e, \temp5                 // for next round f
        xor  \temp3, \temp1             // BSIG0(a)
        addq \temp4, \h                 // h += Maj(a,b,c)
        // swap temp2 temp4 for next round
        // add BSIG0(a) back to a when all round finished
    .endm

/**
 *  Macro Description： Processes the update of two rounds of hash values in 80 rounds of compression,
 *                      and expands messages.
 *  Input register：
 *       addr: Stack space initial address
 *       wkOffset: wi+k512 Data address offset
 *       a - h: Intermediate variable of hash value
 *       wi_17_16： W[i-16-15]
 *       wi_15_14： W[i-15-14]
 *       wi_7_6： W[i-7-6]
 *       wi_9_8： W[i-7-8]
 *       wi_3_2： W[i-3-2]
 *  Modify the register：TEMP1, TEMP2, TEMP3, TEMP4, TEMP5, wi_17_16, YTEMP1, YTEMP2, YTEMP3, YTEMP4, YTEMP5, YTEMP6
 *  Output register：
 *       h： Value after two rounds of cyclic update
 *       d： Value after two rounds of cyclic update
 *       TEMP1: BSIG0(a) from last round
 *       TEMP4: b^a for next round b^c
 *       wi_17_16: expanded message
 *  Function/Macro Call: None
 *  Implementation Description:
 *          T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
 *          T2 = BSIG0(a) + MAJ(a,b,c)
 *          CH(e, f, g) = (e AND f) XOR ((NOT e) AND g)
 *          MAJ(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c)
 *                       = CH(a^b, c, b)
 *                       = ((a XOR b) AND c) XOR ((NOT(a XOR b)) AND b)
 *                       = (b XOR c) AND (a XOR b) XOR b
 *          BSIG0(x) = ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x)
 *          BSIG1(x) = ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x)
 *          d += T1;        h = T1 + T2
 *
 *          wi_16： Latest W[i] value, W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
 *          SSIG0(x) = ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x)
 *          SSIG1(x) = ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x)
 *  Optimization Principle：asert b^c in TEMP4, TEMP1 equal 0, f in TEMP5 when round begin
 *              mov  b, TEMP4
 *              xor  TEMP1, TEMP1
 *              xor  c, TEMP4
 *              mov  f, TEMP5
 *           swap TEMP2 TEMP4 for next round
 *           add BSIG0(a) back to a when all round finished
 */
    .macro TWO_ROUND_UPDATE_2W    a, b, c, d, e, f, g, h, wkOffset, wi_17_16, wi_15_14, wi_9_8, wi_7_6, wi_3_2
        // 1st round
        vpalignr $8, \wi_17_16, \wi_15_14, YTEMP1       // wi_16_15
        vpalignr $8, \wi_9_8, \wi_7_6, YTEMP7           // wi_8_7
        addq \wkOffset(%rsi), \h        // h += Kt + Wt
        and  \e, TEMP5                  // e&f
        vpsrlq   $1, YTEMP1, YTEMP2
        rorx $14, \e, TEMP2             // ROTR^14(e)
        addq TEMP1, \a                  // a += BSIG0(a) from last round
        vpsrlq   $8, YTEMP1, YTEMP3
        rorx $18, \e, TEMP3             // ROTR^18(e)
        andn \g, \e, TEMP1              // (~e)&g
        vpsrlq   $7, YTEMP1, YTEMP4
        xor  TEMP2, TEMP3               // ROTR^14(e) ^ ROTR^18(e)
        xor  TEMP1, TEMP5               // CH(e,f,g)
        vpsllq   $63, YTEMP1, YTEMP5
        rorx $41, \e, TEMP2             // ROTR^41(e)
        addq TEMP5, \h                  // h += CH(e,f,g)
        vpsllq   $56, YTEMP1, YTEMP6
        xor  TEMP2, TEMP3               // BSIG1(e)
        rorx $28, \a, TEMP1             // ROTR^28(a)
        vpaddq   YTEMP7, \wi_17_16, \wi_17_16           // W[i-17..16] + W[8..7]
        mov  \a, TEMP2                  // a
        addq TEMP3, \h                  // h += BSIG1(e)
        vpxor    YTEMP5, YTEMP2, YTEMP2                 // ROTR^1(wi_16_15)
        rorx $34, \a, TEMP5             // ROTR^34(a)
        xor  \b, TEMP2                  // b^a for next round b^c
        vpxor    YTEMP6, YTEMP3, YTEMP3                 // ROTR^8(wi_16_15)
        addq \h, \d                     // d += T1
        xor  TEMP5, TEMP1               // ROTR^14(a) ^ ROTR^34(a)
        vpxor    YTEMP4, YTEMP2, YTEMP1
        and  TEMP2, TEMP4               // (b^a) & (b^c)
        rorx $39, \a, TEMP3             // ROTR^39(a)
        vpxor    YTEMP3, YTEMP1, YTEMP1                 // SSIG0(wi_16_15)
        xor  \b, TEMP4                  // Maj(a,b,c)
        mov  \e, TEMP5                  // for next round f
        vpaddq   YTEMP1, \wi_17_16, \wi_17_16           // SSIG0(wi_16_15) + W[i-17..16] + W[8..7]
        xor  TEMP3, TEMP1               // BSIG0(a)
        addq TEMP4, \h                  // h += Maj(a,b,c)
        // swap TEMP2 TEMP4 for next round

        // 2nd round
        // ror abcdefgh to habcdefg
        vpsrlq   $19, \wi_3_2, YTEMP2
        addq 8+\wkOffset(%rsi), \g      // h += Kt + Wt
        and  \d, TEMP5                  // e&f
        vpsrlq   $61, \wi_3_2, YTEMP3
        rorx $14, \d, TEMP4             // ROTR^14(e)
        addq TEMP1, \h                  // a += BSIG0(a) from last round
        vpsrlq   $6, \wi_3_2, YTEMP4
        rorx $18, \d, TEMP3             // ROTR^18(e)
        andn \f, \d, TEMP1              // (~e)&g
        vpsllq   $45, \wi_3_2, YTEMP5
        xor  TEMP4, TEMP3               // ROTR^14(e) ^ ROTR^18(e)
        xor  TEMP1, TEMP5               // CH(e,f,g)
        vpsllq   $3, \wi_3_2, YTEMP6
        rorx $41, \d, TEMP4             // ROTR^41(e)
        addq TEMP5, \g                  // h += CH(e,f,g)
        vpxor    YTEMP5, YTEMP2, YTEMP2                 // ROTR^19(wi_3_2)
        xor  TEMP4, TEMP3               // BSIG1(e)
        rorx $28, \h, TEMP1             // ROTR^28(a)
        vpxor    YTEMP6, YTEMP3, YTEMP3                 // ROTR^61(wi_3_2)
        mov  \h, TEMP4                  // a
        addq TEMP3, \g                  // h += BSIG1(e)
        vpxor    YTEMP4, YTEMP2, YTEMP1
        rorx $34, \h, TEMP5             // ROTR^34(a)
        xor  \a, TEMP4                  // b^a for next round b^c
        vpxor    YTEMP3, YTEMP1, YTEMP1                 // SSIG1(wi_3_2)
        addq \g, \c                     // d += T1
        xor  TEMP5, TEMP1               // ROTR^14(a) ^ ROTR^34(a)
        vpaddq   YTEMP1, \wi_17_16, \wi_17_16           // SSIG0(wi_16_15) + W[i-17..16] + W[i-8..7] + SSIG1(wi_3_2)
        and  TEMP4, TEMP2               // (b^a) & (b^c)
        rorx $39, \h, TEMP3             // ROTR^39(a)
        vpaddq   \wkOffset(%rdx), \wi_17_16, YTEMP1     // wi + k
        xor  \a, TEMP2                  // Maj(a,b,c)
        mov  \d, TEMP5                  // for next round f
        vmovdqa  YTEMP1, \wkOffset + 256(%rsi)
        xor  TEMP3, TEMP1               // BSIG0(a)
        addq TEMP2, \g                  // h += Maj(a,b,c)
        // swap TEMP2 TEMP4 for next round
        // add BSIG0(a) back to a when all round finished
    .endm

/**
 *  Function description: Performs 80 rounds of compression calculation based on the input plaintext data and updates the hash value.
 *  function prototype：void SHA512CompressMultiBlocks(uint64_t hash[8], const uint8_t *in, uint32_t num);
 *  input register：
 *         rdi：function prototype
 *         rsi：Pointer to the input data address
 *         rdx：Number of 80 rounds of cycles. The value is the length of the input data divided by 128.
 *  Register usage：ymm0-ymm7 to participate in the calculation of message blocks (of two data blocks).
 *                  ymm8-ymm14 is temporary wide register
 *                  r8-r15 Storage a-h
 *                  The stack space temporarily stores wi+k512 (1280 bytes) and hash addresses、in、num
 *  Output register：None
 *  Function/Macro Call：UPDATE_W、ONE_ROUND
 *
 */
    .text
    .balign 16
    .global SHA512CompressMultiBlocks
    .type SHA512CompressMultiBlocks, %function
SHA512CompressMultiBlocks:
.cfi_startproc
    cmp $0, %rdx
    je .Lsha512end

    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    mov %rsp, %r14
    sub $1320, %rsp
    and $-256, %rsp     // 32-byte address alignment
    mov %r14, SHA512_rsp(%rsp) // rsp The original value is added to the stack.

    /* load A-H */
    mov 0(%rdi), %r8
    mov 8(%rdi), %r9
    mov 16(%rdi), %r10
    mov 24(%rdi), %r11
    mov 32(%rdi), %r12
    mov 40(%rdi), %r13
    mov 48(%rdi), %r14
    mov 56(%rdi), %r15

    mov %rdi, SHA512_hash(%rsp)
    mov %rsi, SHA512_in(%rsp) // The input data address is stored in the stack.

.Lsha512_loop:
    mov SHA512_in(%rsp), %rsi

    /* Loads the data of a block to the lower 128 bits of the ymm register. */
    vmovdqu 0(%rsi), %xmm0
    vmovdqu 16(%rsi), %xmm1
    vmovdqu 32(%rsi), %xmm2
    vmovdqu 48(%rsi), %xmm3
    vmovdqu 64(%rsi), %xmm4
    vmovdqu 80(%rsi), %xmm5
    vmovdqu 96(%rsi), %xmm6
    vmovdqu 112(%rsi), %xmm7

    mov %rsi, %rcx
    add $128, %rsi
    cmp $1, %rdx
    cmovne %rsi, %rcx // If num is greater than 1, rcx points to the next block.

    mov %rdx, SHA512_num(%rsp) // Remaining nums are added to the stack.

    /* Loads the data of a block to the upper 128 bits of the ymm register. */
    vinserti128 $1, 0(%rcx),  %ymm0, %ymm0
    vinserti128 $1, 16(%rcx), %ymm1, %ymm1
    vinserti128 $1, 32(%rcx), %ymm2, %ymm2
    vinserti128 $1, 48(%rcx), %ymm3, %ymm3
    vinserti128 $1, 64(%rcx), %ymm4, %ymm4
    vinserti128 $1, 80(%rcx), %ymm5, %ymm5
    vinserti128 $1, 96(%rcx), %ymm6, %ymm6
    vinserti128 $1, 112(%rcx),%ymm7,  %ymm7
    add $128, %rcx
    mov %rcx, SHA512_in(%rsp)  // The input data address is stored in the stack.

    vmovdqa g_endianMask + 0(%rip), %ymm8
    leaq g_k512 + 0(%rip), %rdx
    /* Little-endian order to big-endian order */
    vpshufb %ymm8, %ymm0, %ymm0
    vpshufb %ymm8, %ymm1, %ymm1
    vpshufb %ymm8, %ymm2, %ymm2
    vpshufb %ymm8, %ymm3, %ymm3
    vpshufb %ymm8, %ymm4, %ymm4
    vpshufb %ymm8, %ymm5, %ymm5
    vpshufb %ymm8, %ymm6, %ymm6
    vpshufb %ymm8, %ymm7, %ymm7
    /* w[0..15] + k*/
    vpaddq 0(%rdx), %ymm0, %ymm8
    vpaddq 32(%rdx), %ymm1, %ymm9
    vpaddq 64(%rdx), %ymm2, %ymm10
    vpaddq 96(%rdx), %ymm3, %ymm11
    vpaddq 128(%rdx), %ymm4, %ymm12
    vpaddq 160(%rdx), %ymm5, %ymm13
    vpaddq 192(%rdx), %ymm6, %ymm14
    vpaddq 224(%rdx), %ymm7, %ymm15
    /* wk push stack */
    vmovdqa %ymm8, 0(%rsp)
    vmovdqa %ymm9, 32(%rsp)
    vmovdqa %ymm10, 64(%rsp)
    vmovdqa %ymm11, 96(%rsp)
    vmovdqa %ymm12, 128(%rsp)
    vmovdqa %ymm13, 160(%rsp)
    vmovdqa %ymm14, 192(%rsp)
    vmovdqa %ymm15, 224(%rsp)

    movq $4, 1312(%rsp)
    leaq 0(%rsp), %rsi

    mov  %r9, %rcx          // mov  b, TEMP4
    xor  %rbp, %rbp         // xor  TEMP1, TEMP1
    xor  %r10, %rcx         // xor  c, TEMP4
    mov  %r13, %rdi         // mov  f, TEMP5
.Lround00_63:
    leaq 256(%rdx), %rdx

    TWO_ROUND_UPDATE_2W %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, 0, %ymm0, %ymm1, %ymm4, %ymm5, %ymm7
    TWO_ROUND_UPDATE_2W %r14, %r15, %r8, %r9, %r10, %r11, %r12, %r13, 32, %ymm1, %ymm2, %ymm5, %ymm6, %ymm0
    TWO_ROUND_UPDATE_2W %r12, %r13, %r14, %r15, %r8, %r9, %r10, %r11, 64, %ymm2, %ymm3, %ymm6, %ymm7, %ymm1
    TWO_ROUND_UPDATE_2W %r10, %r11, %r12, %r13, %r14, %r15, %r8, %r9, 96, %ymm3, %ymm4, %ymm7, %ymm0, %ymm2
    TWO_ROUND_UPDATE_2W %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, 128, %ymm4, %ymm5, %ymm0, %ymm1, %ymm3
    TWO_ROUND_UPDATE_2W %r14, %r15, %r8, %r9, %r10, %r11, %r12, %r13, 160, %ymm5, %ymm6, %ymm1, %ymm2, %ymm4
    TWO_ROUND_UPDATE_2W %r12, %r13, %r14, %r15, %r8, %r9, %r10, %r11, 192, %ymm6, %ymm7, %ymm2, %ymm3, %ymm5
    TWO_ROUND_UPDATE_2W %r10, %r11, %r12, %r13, %r14, %r15, %r8, %r9, 224, %ymm7, %ymm0, %ymm3, %ymm4, %ymm6

    leaq 256(%rsi), %rsi
    decq 1312(%rsp)
    jne .Lround00_63

    /* round 64-79 */
    ONE_ROUND %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 0
    ONE_ROUND %r15, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 8
    ONE_ROUND %r14, %r15, %r8, %r9, %r10, %r11, %r12, %r13, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 32
    ONE_ROUND %r13, %r14, %r15, %r8, %r9, %r10, %r11, %r12, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 40
    ONE_ROUND %r12, %r13, %r14, %r15, %r8, %r9, %r10, %r11, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 64
    ONE_ROUND %r11, %r12, %r13, %r14, %r15, %r8, %r9, %r10, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 72
    ONE_ROUND %r10, %r11, %r12, %r13, %r14, %r15, %r8, %r9, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 96
    ONE_ROUND %r9, %r10, %r11, %r12, %r13, %r14, %r15, %r8, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 104

    ONE_ROUND %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 128
    ONE_ROUND %r15, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 136
    ONE_ROUND %r14, %r15, %r8, %r9, %r10, %r11, %r12, %r13, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 160
    ONE_ROUND %r13, %r14, %r15, %r8, %r9, %r10, %r11, %r12, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 168
    ONE_ROUND %r12, %r13, %r14, %r15, %r8, %r9, %r10, %r11, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 192
    ONE_ROUND %r11, %r12, %r13, %r14, %r15, %r8, %r9, %r10, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 200
    ONE_ROUND %r10, %r11, %r12, %r13, %r14, %r15, %r8, %r9, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 224
    ONE_ROUND %r9, %r10, %r11, %r12, %r13, %r14, %r15, %r8, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 232
    addq %rbp, %r8          // a += BSIG0(a) from last round

    leaq -1024(%rsi), %rsi  // rsi Point to the original address
    /* Update the hash value. */
    mov SHA512_hash(%rsp), %rdi
    mov SHA512_num(%rsp), %rdx
    addq 0(%rdi), %r8
    addq 8(%rdi), %r9
    addq 16(%rdi), %r10
    addq 24(%rdi), %r11
    addq 32(%rdi), %r12
    addq 40(%rdi), %r13
    addq 48(%rdi), %r14
    addq 56(%rdi), %r15
    mov %r8, 0(%rdi)
    mov %r9, 8(%rdi)
    mov %r10, 16(%rdi)
    mov %r11, 24(%rdi)
    mov %r12, 32(%rdi)
    mov %r13, 40(%rdi)
    mov %r14, 48(%rdi)
    mov %r15, 56(%rdi)

    cmp $1, %rdx
    je .Lsha512_finish

    movq $10, 1312(%rsp)

    mov  %r9, %rcx          // mov  b, TEMP4
    xor  %rbp, %rbp         // xor  TEMP1, TEMP1
    xor  %r10, %rcx         // xor  c, TEMP4
    mov  %r13, %rdi         // mov  f, TEMP5
.Lnext_block:
    ONE_ROUND %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 16
    ONE_ROUND %r15, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 24
    ONE_ROUND %r14, %r15, %r8, %r9, %r10, %r11, %r12, %r13, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 48
    ONE_ROUND %r13, %r14, %r15, %r8, %r9, %r10, %r11, %r12, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 56
    ONE_ROUND %r12, %r13, %r14, %r15, %r8, %r9, %r10, %r11, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 80
    ONE_ROUND %r11, %r12, %r13, %r14, %r15, %r8, %r9, %r10, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 88
    ONE_ROUND %r10, %r11, %r12, %r13, %r14, %r15, %r8, %r9, %rbp, %rax, %rbx, %rcx, %rdi, %rsi, 112
    ONE_ROUND %r9, %r10, %r11, %r12, %r13, %r14, %r15, %r8, %rbp, %rcx, %rbx, %rax, %rdi, %rsi, 120
    leaq 128(%rsi), %rsi
    decq 1312(%rsp)
    jne .Lnext_block

    addq %rbp, %r8          // a += BSIG0(a) from last round
    leaq -1280(%rsi), %rsi // rsi Point to the original address
    /* Update the hash value. */
    mov SHA512_hash(%rsp), %rdi
    addq 0(%rdi), %r8
    addq 8(%rdi), %r9
    addq 16(%rdi), %r10
    addq 24(%rdi), %r11
    addq 32(%rdi), %r12
    addq 40(%rdi), %r13
    addq 48(%rdi), %r14
    addq 56(%rdi), %r15
    mov %r8, 0(%rdi)
    mov %r9, 8(%rdi)
    mov %r10, 16(%rdi)
    mov %r11, 24(%rdi)
    mov %r12, 32(%rdi)
    mov %r13, 40(%rdi)
    mov %r14, 48(%rdi)
    mov %r15, 56(%rdi)

    sub $2, %rdx
    jne .Lsha512_loop

.Lsha512_finish:
    mov SHA512_rsp(%rsp), %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx

.Lsha512end:
    ret
.cfi_endproc
    .size SHA512CompressMultiBlocks, .-SHA512CompressMultiBlocks

#endif
