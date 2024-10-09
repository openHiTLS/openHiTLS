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
#ifdef HITLS_CRYPTO_SHA256

.file   "sha2_256_x86_64.S"

.set HashAddr, %rdi
.set InAddr, %rsi
.set NUM, %rdx

.set tempFirst, %ebp
.set tempThird, %ebx
.set tempFifth, %edi
.set avx2Temp1, %ymm4
.set avx2Temp2, %ymm5
.set avx2Temp3, %ymm6
.set avx2Temp4, %ymm7
.set avx2Temp5, %ymm10
.set avx2Temp6, %ymm11
.set avx2Temp7, %ymm15

.set BlockFrontMessageW3_0, %xmm0
.set BlockFrontMessageW7_4, %xmm1
.set BlockFrontMessageW11_8, %xmm2
.set BlockFrontMessageW15_12, %xmm3

.set g_maskMerge, %ymm12
.set g_maskShift, %ymm13
.set g_maskTransformEndian, %ymm14

/* Constant value used by sha256. For details about the data source, see the RFC4634 document. */
.section .rodata
.align 64
.type   g_K256, %object
g_K256:
    .long   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
    .long   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
    .long   0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
    .long   0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
    .long   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
    .long   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
    .long   0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
    .long   0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
    .long   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
    .long   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
    .long   0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
    .long   0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
    .long   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
    .long   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
    .long   0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
    .long   0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
    .long   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
    .long   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
    .long   0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
    .long   0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
    .long   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
    .long   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
    .long   0xd192e819,0xd6990624,0xf40e3585,0x106aa070
    .long   0xd192e819,0xd6990624,0xf40e3585,0x106aa070
    .long   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
    .long   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
    .long   0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
    .long   0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
    .long   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
    .long   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
    .long   0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    .long   0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
.size    g_K256, .-g_K256

/* Mask block */
.balign    64
.type    g_mask, %object
g_mask:
    .long   0x00010203,0x04050607, 0x08090a0b,0x0c0d0e0f
    .long   0x00010203,0x04050607, 0x08090a0b,0x0c0d0e0f
    .long   0x03020100,0x0b0a0908, 0xffffffff,0xffffffff
    .long   0x03020100,0x0b0a0908, 0xffffffff,0xffffffff
    .long   0xffffffff,0xffffffff, 0x03020100,0x0b0a0908
    .long   0xffffffff,0xffffffff, 0x03020100,0x0b0a0908
.size   g_mask, .-g_mask

/*
 *   Macro description: Processes the fast extension of four messages of two blocks at the same time
 *                         and completes the four-round compression function of the first block.
 *   Input register:
 *       WkAddr: Address of the stack space where wi+kt is located.
 *       a - h： Intermediate variable of hash value
 *   Modify the register： r8d-r15d, ebp, eax, ebx, ecx, edi, ymm0-ymm10
 *   Output register：
 *          a-h： Value after four rounds of cyclic update
 *          B3_0: Value after data extension
 *   Naming convention：
 *          B3_0:   w3-w0
 *          B7_4:   w7-w4
 *          B11_8:  w11-w8
 *          B15_12: w15-w12
 *   Function/Macro Call：None
 *   Implementation Description：
 *          ONE_ROUND algorithm implementation：
 *          For t = 0 to 63, T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
 *          T2 = BSIG0(a) + MAJ(a,b,c)
 *          h = g, g = f, f = e, e = d + T1, d = c, c = b, b = a, a = T1 + T2
 *          CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)           CH(e,f,g)
 *          MAJ(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c)
 *                       = CH(a^b, c, b)
 *                       = ((a XOR b) AND c) XOR ((NOT(a XOR b)) AND b)
 *                       = (b XOR c) AND (a XOR b) XOR b
 *          BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)      BSIG0(a)
 *          BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)      BSIG1(e)
 *          Optimization idea: b xor c in the next round of MAJ is a xor b in the previous round of MAJ
 *                             to avoid redundant calculation.
 *
 *          UPDATE_4W algorithm implementation：
 *          For t = 0 to 15     Wt = W0_W15(input w0-w15)
 *          For t = 16 to 63    Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(w(t-15)) + W(t-16)
 *          SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
 *          SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
 *          Optimization idea: Optimization point 1: Each WI message block is 32-bit, and the xmm register is
 *                             a 128-bit register. Therefore, the common operation of four WI messages can be
 *                             performed at the same time (SSIG0, W(t-16), W(t-7)).
 *                             Due to the dependency of wi, four wis are calculated each time as the
 *                             optimal solution found so far.
 *                             Optimization point 2: The ymm register is a 256-bit register. Therefore, two rounds
 *                             of 128-bit calculation can be performed at the same time, and two blocks can be used
 *                             for the same calculation.
 */
.macro FOUR_ROUND_UPDATE_4W a, b, c, d, e, f, g, h, tempSwitch2, tempSwitch4, WkAddr, B3_0, B7_4, B11_8, B15_12
    vpalignr   $4,\B3_0,\B7_4,avx2Temp1                  // avx2Temp1->w4_1
    add  \WkAddr(%rsp),\h                                // h += Kt + Wt
    and  \e, tempFifth                                   // e&f
    rorx $6, \e, \tempSwitch2                            // ROTR^6(e)
    add  tempFirst, \a                                   // a += BSIG0(a) from last round
    rorx $11, \e, tempThird                              // ROTR^11(e)
    andn \g, \e, tempFirst                               // (~e)&g
    xor  \tempSwitch2, tempThird                         // ROTR^6(e) ^ ROTR^11(e)
    xor  tempFirst, tempFifth                            // CH(e,f,g)
    vpshufd     $250, \B15_12, avx2Temp5
    rorx $25, \e, \tempSwitch2                           // ROTR^25(e)
    add  tempFifth, \h                                   // h += CH(e,f,g)
    xor  \tempSwitch2, tempThird                         // BSIG1(e)
    vpalignr   $4, \B11_8, \B15_12, avx2Temp2            // avx2Temp2->w12_9
    vpslld      $14, avx2Temp1, avx2Temp4                // w4_1<<datum line 14
    rorx $2, \a, tempFirst                               // ROTR^2(a)
    mov  \a, \tempSwitch2                                // a
    add  tempThird, \h                                   // h += BSIG1(e)[h->T1]
    vpsrld      $3, avx2Temp1, avx2Temp3                 // w4_1>>datum line 3
    rorx $13, \a, tempFifth                              // ROTR^13(a)
    xor  \b, \tempSwitch2                                // b^a for next round b^c
    add  \h, \d                                          // d += T1
    vpsrld      $10, avx2Temp5, avx2Temp6                // >>10
    xor  tempFifth, tempFirst                            // ROTR^2(a) ^ ROTR^13(a)
    and  \tempSwitch2, \tempSwitch4                      // (b^a) & (b^c)
    vpsrld      $7, avx2Temp1, avx2Temp1                 // >>7
    vpaddd      avx2Temp2, \B3_0, \B3_0
    rorx $22, \a, tempThird                              // ROTR^22(a)
    add  4+\WkAddr(%rsp),\g                              // h += Kt + Wt
    xor  \b, \tempSwitch4                                // Maj(a,b,c)
    vpxor       avx2Temp3, avx2Temp4, avx2Temp3          // 3 xor 14
    mov  \e, tempFifth                                   // for next round f
    xor  tempThird, tempFirst                            // BSIG0(a)
    vpsrlq      $17, avx2Temp5, avx2Temp7                // >>17
    add  \tempSwitch4, \h                                // h += Maj(a,b,c)
    and  \d, tempFifth                                   // e&f
    rorx $6, \d, \tempSwitch4
    add  tempFirst, \h                                   // a += BSIG0(a) from last round
    vpxor       avx2Temp3, avx2Temp1, avx2Temp3          // 7xor14xor3
    vpsrlq      $19, avx2Temp5, avx2Temp5                // >>19
    rorx $11, \d, tempThird
    andn \f, \d, tempFirst
    xor  \tempSwitch4, tempThird
    vpsrld      $11, avx2Temp1, avx2Temp1                // >>18
    xor  tempFirst, tempFifth
    rorx $25, \d, \tempSwitch4
    add  tempFifth, \g
    xor  \tempSwitch4, tempThird
    vpslld      $11, avx2Temp4, avx2Temp4                // <<25
    rorx $2, \h, tempFirst
    mov  \h, \tempSwitch4
    add  tempThird, \g
    rorx $13, \h,tempFifth
    xor  \a, \tempSwitch4
    vpxor       avx2Temp7, avx2Temp6, avx2Temp7          // 17xor10
    add  \g, \c
    xor  tempFifth, tempFirst
    vpxor       avx2Temp3, avx2Temp1, avx2Temp3          // 7xor14xor3xor18
    and  \tempSwitch4, \tempSwitch2
    rorx $22, \h, tempThird
    add  8+\WkAddr(%rsp),\f
    xor  \a, \tempSwitch2
    vpxor       avx2Temp7, avx2Temp5, avx2Temp7          // 17xor10xor19
    mov  \d, tempFifth
    xor  tempThird, tempFirst
    add  \tempSwitch2, \g
    vpshufb       g_maskMerge, avx2Temp7, avx2Temp7       // BSIG1 w15_14
    vpxor       avx2Temp3, avx2Temp4, avx2Temp3           // 7xor14xor3xor18xor25
    and  \c, tempFifth
    rorx $6, \c, \tempSwitch2
    add  tempFirst, \g
    rorx $11, \c, tempThird
    vpaddd      avx2Temp3, \B3_0, \B3_0                   // BSIG0+w(t-16)+w(t-7)
    andn \e, \c, tempFirst
    xor  \tempSwitch2, tempThird
    xor  tempFirst, tempFifth
    rorx $25, \c, \tempSwitch2
    add  tempFifth, \f
    xor  \tempSwitch2, tempThird
    rorx $2, \g, tempFirst
    mov  \g, \tempSwitch2
    add  tempThird, \f
    rorx $13, \g, tempFifth
    vpaddd      \B3_0, avx2Temp7, \B3_0                   // w17_16
    xor  \h, \tempSwitch2
    add  \f, \b
    xor  tempFifth, tempFirst
    and  \tempSwitch2, \tempSwitch4
    vpshufd       $80, \B3_0, avx2Temp1
    rorx $22, \g, tempThird
    add  12+\WkAddr(%rsp),\e
    xor  \h, \tempSwitch4
    mov  \c, tempFifth
    xor  tempThird, tempFirst
    add  \tempSwitch4, \f
    vpsrld       $10, avx2Temp1, avx2Temp2                 // >>10
    and  \b, tempFifth
    rorx $6, \b, \tempSwitch4
    vpsrlq       $17, avx2Temp1, avx2Temp3                 // >>17
    add  tempFirst, \f
    rorx $11, \b, tempThird
    andn \d, \b, tempFirst
    xor  \tempSwitch4, tempThird
    vpsrlq     $19,avx2Temp1, avx2Temp1                    // >>19
    xor  tempFirst, tempFifth
    rorx $25, \b, \tempSwitch4
    add  tempFifth, \e
    xor  \tempSwitch4, tempThird
    vpxor       avx2Temp2, avx2Temp3, avx2Temp3            // 10xor17
    rorx $2, \f, tempFirst
    mov  \f, \tempSwitch4
    add  tempThird, \e
    rorx $13, \f, tempFifth
    xor  \g, \tempSwitch4
    vpxor       avx2Temp3, avx2Temp1, avx2Temp3            // 10xor17xor19
    add  \e, \a
    xor  tempFifth, tempFirst
    and  \tempSwitch4, \tempSwitch2
    rorx $22, \f, tempThird
    vpshufb       g_maskShift, avx2Temp3, avx2Temp3        // BSIG1(W17_16)Move to the desired location
    xor  \g, \tempSwitch2
    mov  \b, tempFifth
    xor  tempThird, tempFirst
    add  \tempSwitch2, \e
    vpaddd       avx2Temp3, \B3_0, \B3_0                    // W19_16
.endm

/*
 *   Macro description: Processes the update of a round of hash values in 64 rounds of compression.
 *   Input register：
 *      wkAddr： wi+kt Stack space address.
 *       a - h： Intermediate variable of hash value
 *   Modify the register： r8d-r15d, ebp, eax, ebx, ecx, edi
 *   Output register：
 *         a-h： Indicates the value after a cyclic update.
 *   Function/Macro Call：None
 *          ONE_ROUND Algorithm Implementation：
 *          For t = 0 to 63, T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
 *          T2 = BSIG0(a) + MAJ(a,b,c)
 *          h = g, g = f, f = e, e = d + T1, d = c, c = b, b = a, a = T1 + T2
 *          CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)           CH(e,f,g)
 *          MAJ(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c)
 *                       = CH(a^b, c, b)
 *                       = ((a XOR b) AND c) XOR ((NOT(a XOR b)) AND b)
 *                       = (b XOR c) AND (a XOR b) XOR b
 *          BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)      BSIG0(a)
 *          BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)      BSIG1(e)
 *          Optimization idea: b xor c in the next round of MAJ is a xor b in the
 *                             previous round of MAJ to avoid redundant calculation.
 *          Note: At the end of each round, the tempSwitch2 and tempSwitch4 of the next round need to be exchanged.
 */
    .macro ONE_ROUND         a, b, c, d, e, f, g, h, tempSwitch2, tempSwitch4, WkAddr
    rorx $11, \e, tempThird                          // ROTR^11(e)
    rorx $6, \e, \tempSwitch2                        // ROTR^6(e)
    add  tempFirst, \a                               // a += BSIG0(a) from last round
    and  \e, tempFifth                               // e&f
    andn \g, \e, tempFirst                           // (~e)&g
    xor  \tempSwitch2, tempThird                     // ROTR^6(e) ^ ROTR^11(e)
    add  \WkAddr(%rsp),\h                            // h += Kt + Wt
    xor  tempFirst, tempFifth                        // CH(e,f,g)
    rorx $25, \e, \tempSwitch2                       // ROTR^25(e)
    add  tempFifth, \h                               // h += CH(e,f,g)
    xor  \tempSwitch2, tempThird                     // BSIG1(e)
    rorx $2, \a, tempFirst                           // ROTR^2(a)
    mov  \a, \tempSwitch2                            // a
    leal  (tempThird, \h), \h                        // h += BSIG1(e)[h->T1]
    rorx $13, \a, tempFifth                          // ROTR^13(a)
    xor  \b, \tempSwitch2                            // b^a for next round b^c
    add  \h, \d                                      // d += T1
    xor  tempFifth, tempFirst                        // ROTR^2(a) ^ ROTR^13(a)
    and  \tempSwitch2, \tempSwitch4                  // (b^a) & (b^c)
    rorx $22, \a, tempThird                          // ROTR^22(a)
    xor  \b, \tempSwitch4                            // Maj(a,b,c)
    mov  \e, tempFifth                               // for next round f
    xor  tempThird, tempFirst                        // BSIG0(a)
    add  \tempSwitch4, \h                            // h += Maj(a,b,c)
    .endm

/*
 *  Function description: Performs 64 rounds of compression calculation based on the input plaintext data and updates the hash value.
 *  function prototype：void SHA256CompressMultiBlocks(uint32_t hash[8], const uint8_t *in, uint32_t num);
 *  Input register:
 *         rdi： Storage address of the hash value
 *         rsi： Pointer to the input data address (Wi)
 *         rdx： Number of 64 rounds of cycles. (You need to do several blocks, that is, you need to do several loops.)
 *  Modify the register： r0-r14
 *  Output register： None
 *  Function/Macro Call： None
 */
.text
.globl SHA256CompressMultiBlocks
.type SHA256CompressMultiBlocks,%function
.align 4
SHA256CompressMultiBlocks:
.cfi_startproc
    /* Determine whether to end the process directly. */
    cmp $0, NUM
    je .LEND_SHA256

    /* Pop-stack/push stack protection */
    pushq %r14
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r15

    /* The pre-stored stack space and 32-byte address are aligned.
       The original RSP value is added to the stack and the mask is assigned. */
    mov %rsp, %r14
    mov 0(HashAddr), %r8d
    sub $600, %rsp
    vmovdqa g_mask + 0(%rip), g_maskTransformEndian
    mov 4(HashAddr), %r9d
    mov 8(HashAddr), %r10d
    and $-256, %rsp
    vmovdqa g_mask + 64(%rip), g_maskShift
    mov 12(HashAddr), %r11d
    mov %r14, 0(%rsp)

    /* r8d-r15d: a-h */
    mov 16(HashAddr), %r12d
    mov 20(HashAddr), %r13d
    vmovdqa g_mask + 32(%rip), g_maskMerge
    mov 24(HashAddr), %r14d
    mov 28(HashAddr), %r15d

.LEND_SHA256_LOOP:
    mov InAddr, %rcx

    /* Loads the data of a block to the lower 128 bits of the ymm register. */
    vmovdqu 0(InAddr), BlockFrontMessageW3_0
    vmovdqu 16(InAddr), BlockFrontMessageW7_4
    vmovdqu 32(InAddr), BlockFrontMessageW11_8
    vmovdqu 48(InAddr), BlockFrontMessageW15_12

    /* block Judgment condition processing */
    leaq 64(InAddr), InAddr
    cmp $1, NUM
    cmovne InAddr, %rcx                   // If num is greater than 1, rcx points to the next block.

    /* Load the data of another block to the upper 128 bits of the ymm register. */
    vinserti128 $1, 0(%rcx),  %ymm0, %ymm0
    vinserti128 $1, 16(%rcx), %ymm1, %ymm1
    vpshufb g_maskTransformEndian, %ymm0, %ymm0
    mov NUM, 16(%rsp)
    vinserti128 $1, 32(%rcx), %ymm2, %ymm2
    mov HashAddr, 24(%rsp)
    vpshufb g_maskTransformEndian, %ymm1, %ymm1
    vinserti128 $1, 48(%rcx), %ymm3, %ymm3
    vpshufb g_maskTransformEndian, %ymm2, %ymm2

    add $64, %rcx
    leaq    g_K256(%rip), NUM

    /* Little-endian order to big-endian order, wi + kt:ymm9-11*/
    mov %rcx, 8(%rsp)
    leaq    32(%rsp), %rsp
    vpaddd 0(NUM), %ymm0, %ymm8
    mov %r9d, %ecx
    vpaddd 32(NUM), %ymm1, %ymm9
    vmovdqa %ymm8, 0(%rsp)
    vpshufb g_maskTransformEndian, %ymm3, %ymm3
    xor %ebp, %ebp
    vpaddd 64(NUM), %ymm2, %ymm10
    vmovdqu %ymm9, 32(%rsp)
    xor %r10d, %ecx
    vpaddd 96(NUM), %ymm3, %ymm11
    mov %r13d, %edi
    vmovdqa %ymm10, 64(%rsp)
    vmovdqu %ymm11, 96(%rsp)

.LEND_SHA256_ROUND_00_47:

    /* Next round wi + kt: ymm9-11, 16 rounds of compression + 4 rounds of message block expansion */
    /* FOUR_ROUND_UPDATE_4W a, b, c, d, e, f, g, h, tempSwitch2,tempSwitch4, WkAddr,B3_0, B7_4, B11_8, B15_12 */
    FOUR_ROUND_UPDATE_4W %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 0, %ymm0, %ymm1, %ymm2, %ymm3
    leaq 128(NUM), NUM
    FOUR_ROUND_UPDATE_4W %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 32, %ymm1, %ymm2, %ymm3, %ymm0
    vpaddd 0(NUM), %ymm0, %ymm8
    FOUR_ROUND_UPDATE_4W   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 64, %ymm2, %ymm3, %ymm0, %ymm1
    vpaddd 32(NUM), %ymm1, %ymm9
    vmovdqa %ymm8, 128(%rsp)
    FOUR_ROUND_UPDATE_4W %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 96, %ymm3, %ymm0, %ymm1, %ymm2
    vpaddd 64(NUM), %ymm2, %ymm10
    vmovdqa %ymm9, 160(%rsp)
    vpaddd 96(NUM), %ymm3, %ymm11
    vmovdqu %ymm10, 192(%rsp)
    vmovdqa %ymm11, 224(%rsp)

    /* Next round wi + kt: ymm9-11, 16 rounds of compression + 4 rounds of message block expansion */
    /* FOUR_ROUND_UPDATE_4W a, b, c, d, e, f, g, h, tempSwitch2,tempSwitch4, WkAddr,B19_16, B23_20, B27_24, B31_27 */
    FOUR_ROUND_UPDATE_4W %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 128, %ymm0, %ymm1, %ymm2, %ymm3
    leaq 128(NUM), NUM
    FOUR_ROUND_UPDATE_4W %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 160, %ymm1, %ymm2, %ymm3, %ymm0
    vpaddd 0(NUM), %ymm0, %ymm8
    FOUR_ROUND_UPDATE_4W   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 192, %ymm2, %ymm3, %ymm0, %ymm1
    vpaddd 32(NUM), %ymm1, %ymm9
    vmovdqa %ymm8, 256(%rsp)
    FOUR_ROUND_UPDATE_4W %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 224, %ymm3, %ymm0, %ymm1, %ymm2
    vpaddd 64(NUM), %ymm2, %ymm10
    vmovdqa %ymm9, 288(%rsp)
    vpaddd 96(NUM), %ymm3, %ymm11
    vmovdqu %ymm10, 320(%rsp)
    vmovdqa %ymm11, 352(%rsp)

    /* Next round wi + kt: ymm9-11, 16 rounds of compression + 4 rounds of message block expansion */
    /* FOUR_ROUND_UPDATE_4W a, b, c, d, e, f, g, h, tempSwitch2,tempSwitch4, WkAddr,B35_32, B39_36, B43_40, B47_44 */
    FOUR_ROUND_UPDATE_4W %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 256, %ymm0, %ymm1, %ymm2, %ymm3
    leaq 128(NUM), NUM
    FOUR_ROUND_UPDATE_4W %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 288, %ymm1, %ymm2, %ymm3, %ymm0
    vpaddd 0(NUM), %ymm0, %ymm8
    FOUR_ROUND_UPDATE_4W   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 320, %ymm2, %ymm3, %ymm0, %ymm1
    vpaddd 32(NUM), %ymm1, %ymm9
    vmovdqa %ymm8, 384(%rsp)
    FOUR_ROUND_UPDATE_4W %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 352, %ymm3, %ymm0, %ymm1, %ymm2
    vpaddd 64(NUM), %ymm2, %ymm10
    vmovdqa %ymm9, 416(%rsp)
    vpaddd 96(NUM), %ymm3, %ymm11
    vmovdqu %ymm10, 448(%rsp)
    vmovdqa %ymm11, 480(%rsp)

.LEND_SHA256_ROUND_48_63:
    /* ONE_ROUND a, b, c, d, e, f, g, h, tempSwitch2, Fourth, WkAddr */
    ONE_ROUND   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 384
    ONE_ROUND   %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %ecx, %eax, 388
    ONE_ROUND   %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %eax, %ecx, 392
    ONE_ROUND   %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %ecx, %eax, 396

    ONE_ROUND   %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 416
    ONE_ROUND   %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %ecx, %eax, 420
    ONE_ROUND   %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %eax, %ecx, 424
    ONE_ROUND   %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %ecx, %eax, 428

    ONE_ROUND   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 448
    ONE_ROUND   %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %ecx, %eax, 452
    ONE_ROUND   %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %eax, %ecx, 456
    ONE_ROUND   %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %ecx, %eax, 460

    ONE_ROUND   %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 480
    ONE_ROUND   %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %ecx, %eax, 484
    ONE_ROUND   %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %eax, %ecx, 488
    ONE_ROUND   %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %ecx, %eax, 492

    sub    $32, %rsp
    add %ebp, %r8d                      // a+=BSIG0
    mov 24(%rsp), HashAddr

    /* Update the storage hash value. */
    add 0(HashAddr), %r8d
    add 4(HashAddr), %r9d
    mov %r8d, 0(HashAddr)
    add 8(HashAddr), %r10d
    mov %r9d, 4(HashAddr)
    add 12(HashAddr), %r11d
    mov %r10d, 8(HashAddr)
    add 16(HashAddr), %r12d
    mov 16(%rsp), NUM
    mov %r11d, 12(HashAddr)
    add 20(HashAddr), %r13d
    mov %r12d, 16(HashAddr)
    add 24(HashAddr), %r14d
    mov %r13d, 20(HashAddr)
    add 28(HashAddr), %r15d
    mov %r14d, 24(HashAddr)
    mov %r15d, 28(HashAddr)

    cmp $1, NUM
    je .LEND_SHA256_FINFISH_INITIAL

    /* Data compression of the second block */
    xor %ebp, %ebp
    mov %r9d, %ecx
    xor %r10d, %ecx
    mov %r13d, %edi

.LEND_SHA256_NEXT_BLOCK:
    /* 0-15 */
    /* ONE_ROUND a,   b,    c,     d,     e,     f,    g,       h,    tempSwitch2,tempSwitch4, WkAddr */
    ONE_ROUND   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 16+32
    ONE_ROUND   %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %ecx, %eax, 20+32
    ONE_ROUND   %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %eax, %ecx, 24+32
    ONE_ROUND   %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %ecx, %eax, 28+32

    ONE_ROUND   %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 48+32
    ONE_ROUND   %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %ecx, %eax, 52+32
    ONE_ROUND   %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %eax, %ecx, 56+32
    ONE_ROUND   %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %ecx, %eax, 60+32

    ONE_ROUND   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 80+32
    ONE_ROUND   %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %ecx, %eax, 84+32
    ONE_ROUND   %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %eax, %ecx, 88+32
    ONE_ROUND   %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %ecx, %eax, 92+32

    ONE_ROUND   %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 112+32
    ONE_ROUND   %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %ecx, %eax, 116+32
    ONE_ROUND   %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %eax, %ecx, 120+32
    ONE_ROUND   %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %ecx, %eax, 124+32

    /* 16-31 */
    ONE_ROUND   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 16+128+32
    ONE_ROUND   %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %ecx, %eax, 20+128+32
    ONE_ROUND   %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %eax, %ecx, 24+128+32
    ONE_ROUND   %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %ecx, %eax, 28+128+32

    ONE_ROUND   %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 48+128+32
    ONE_ROUND   %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %ecx, %eax, 52+128+32
    ONE_ROUND   %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %eax, %ecx, 56+128+32
    ONE_ROUND   %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %ecx, %eax, 60+128+32

    ONE_ROUND   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 80+128+32
    ONE_ROUND   %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %ecx, %eax, 84+128+32
    ONE_ROUND   %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %eax, %ecx, 88+128+32
    ONE_ROUND   %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %ecx, %eax, 92+128+32

    ONE_ROUND   %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 112+128+32
    ONE_ROUND   %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %ecx, %eax, 116+128+32
    ONE_ROUND   %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %eax, %ecx, 120+128+32
    ONE_ROUND   %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %ecx, %eax, 124+128+32

    /* 32-47 */
    ONE_ROUND   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 16+256+32
    ONE_ROUND   %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %ecx, %eax, 20+256+32
    ONE_ROUND   %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %eax, %ecx, 24+256+32
    ONE_ROUND   %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %ecx, %eax, 28+256+32

    ONE_ROUND   %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 48+256+32
    ONE_ROUND   %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %ecx, %eax, 52+256+32
    ONE_ROUND   %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %eax, %ecx, 56+256+32
    ONE_ROUND   %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %ecx, %eax, 60+256+32

    ONE_ROUND   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 80+256+32
    ONE_ROUND   %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %ecx, %eax, 84+256+32
    ONE_ROUND   %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %eax, %ecx, 88+256+32
    ONE_ROUND   %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %ecx, %eax, 92+256+32

    ONE_ROUND   %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 112+256+32
    ONE_ROUND   %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %ecx, %eax, 116+256+32
    ONE_ROUND   %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %eax, %ecx, 120+256+32
    ONE_ROUND   %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %ecx, %eax, 124+256+32

    /* 48-63 */
    ONE_ROUND   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 16+384+32
    ONE_ROUND   %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %ecx, %eax, 20+384+32
    ONE_ROUND   %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %eax, %ecx, 24+384+32
    ONE_ROUND   %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %ecx, %eax, 28+384+32

    ONE_ROUND   %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 48+384+32
    ONE_ROUND   %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %ecx, %eax, 52+384+32
    ONE_ROUND   %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %eax, %ecx, 56+384+32
    ONE_ROUND   %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %ecx, %eax, 60+384+32

    ONE_ROUND   %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %eax, %ecx, 80+384+32
    ONE_ROUND   %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %ecx, %eax, 84+384+32
    ONE_ROUND   %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %r13d, %eax, %ecx, 88+384+32
    ONE_ROUND   %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %r12d, %ecx, %eax, 92+384+32

    ONE_ROUND   %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %r11d, %eax, %ecx, 112+384+32
    ONE_ROUND   %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %r10d, %ecx, %eax, 116+384+32
    ONE_ROUND   %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %r9d, %eax, %ecx, 120+384+32
    ONE_ROUND   %r9d, %r10d, %r11d, %r12d, %r13d, %r14d, %r15d, %r8d, %ecx, %eax, 124+384+32

    mov 24(%rsp), HashAddr
    lea (%ebp, %r8d), %r8d              // a+=BSIG0

    /* Update the storage hash value. */
    add 0(HashAddr), %r8d
    add 4(HashAddr), %r9d
    mov %r8d, 0(HashAddr)
    add 8(HashAddr), %r10d
    mov %r9d, 4(HashAddr)
    add 12(HashAddr), %r11d
    mov %r10d, 8(HashAddr)
    add 16(HashAddr), %r12d
    mov %r11d, 12(HashAddr)
    add 20(HashAddr), %r13d
    mov %r12d, 16(HashAddr)
    mov 8(%rsp), InAddr
    add 24(HashAddr), %r14d
    mov %r13d, 20(HashAddr)
    mov 16(%rsp), NUM
    add 28(HashAddr), %r15d
    mov %r14d, 24(HashAddr)
    mov %r15d, 28(HashAddr)

    sub $2, NUM
    ja .LEND_SHA256_LOOP

.LEND_SHA256_FINFISH_INITIAL:
    /* Registers and pointers are reset. */
    mov 0(%rsp), %rsp
    popq %r15
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    popq %r14

.LEND_SHA256:
    ret
.cfi_endproc
    .size   SHA256CompressMultiBlocks, .-SHA256CompressMultiBlocks

#endif
