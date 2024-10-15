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
#ifdef HITLS_CRYPTO_GCM

.file   "ghash_x86_64.S"
.text

.set INL,       %xmm11
.set INH,       %xmm12
.set INM,       %xmm13
.set HKEY3,     %xmm14
.set HKEY4,     %xmm15

.set INPUT_XI,  %rdi
.set HTABLE,    %rsi
.set INPUT_IN,  %rdx
.set LEN,       %rcx
.set XI_L,      %xmm0
.set XI_H,      %xmm1
.set HKEY,      %xmm2

.set IN_L,      %xmm3
.set IN_H,      %xmm4
.set IN_M,      %xmm5
.set HKEY2,     %xmm6
.set HKEY1_2,   %xmm7
.set TEMP1,     %xmm8
.set TEMP2,     %xmm9
.set MASK,      %xmm10

.balign 16
g_bswapMask:
    .byte	15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
.size g_bswapMask, .-g_bswapMask
.balign 16
g_polynomial:
	.byte	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc2
.size g_polynomial, .-g_polynomial
.balign 16
g_64swapMask:
    .byte   7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
.size g_64swapMask, .-g_64swapMask
.balign 16
g_poly:
    .byte   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .byte   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2
.size   g_poly, .-g_poly

/**
 *  Macro description: one block * H (128bit * 128bit)
 *  Input registers: xl, hKey, hKey12
 *  Change registers: temp1 and temp2
 *  Result register: xh, xl
 */
.macro  GHASH_MUL128X128 xh, xl, hKey, hKey12, temp1, temp2
    vpshufd  $0x4e, \xl, \temp1
    vpclmulqdq   $0x11, \hKey, \xl, \xh
    vpxor    \xl, \temp1, \temp1

    vpclmulqdq   $0x00, \hKey, \xl, \xl
    vpxor    \xl, \xh, \temp2
    vpclmulqdq   $0x00, \hKey12, \temp1, \temp1
    vpxor    \temp2, \temp1, \temp1

    vpslldq  $8, \temp1, \temp2
    vpsrldq  $8, \temp1, \temp1
    vpxor    \temp1, \xh, \xh
    vpxor    \temp2, \xl, \xl
.endm

/**
 *  Macro description: 256-bit large number reduction modulo g(x)
 *  Input register: xh, xl
 *  Change registers: temp1 and temp2
 *  Result register: xl
 */
.macro REDUCTION_256BIT xh, xl, temp1, temp2, reducMask
    vmovdqa \reducMask(%rip), \temp1     // g_poly
    vpalignr $8, \xl, \xl, \temp2        // 1st phase of reduction
    vpclmulqdq $0x10, \temp1, \xl, \xl
    vpxor \temp2, \xl, \xl

    vpalignr $8, \xl, \xl, \temp2        // 2nd phase of reduction
    vpclmulqdq $0x10, \temp1, \xl, \xl
    vpxor \xh, \temp2, \temp2
    vpxor \temp2, \xl, \xl
.endm

/**
 *  Function description: x86_64 hTable pre-computation table implementation (H has been transformed)
 *  Function prototype: void GcmTableGen4bit(uint8_t key[GCM_BLOCKSIZE], MODES_GCM_GF128 hTable[16]);
 *  Input register:
 *      rdi: uint8_t key[GCM_BLOCKSIZE]
 *      rsi: MODES_GCM_GF128 hTable[16]
 *  Change register: xmm0-xmm15
 *  Function/Macro Call:
 *          GHASH_MUL128X128
 *          REDUCTION_256BIT
 */
.align 32
.globl  GcmTableGen4bit
.type GcmTableGen4bit, %function
GcmTableGen4bit:
.cfi_startproc
    vmovdqu  (INPUT_XI), HKEY
    vpshufb  g_64swapMask(%rip), HKEY, HKEY
    vpshufd  $0x4e, HKEY, IN_L
    vpshufd  $0x55, HKEY, HKEY              // broadcast carry bit
    vmovdqa  g_polynomial(%rip), IN_H

    vpsrlq   $63, IN_L, IN_M
    vpxor    MASK, MASK, MASK
    vpcmpgtd HKEY, MASK, HKEY
    vpand    IN_H, IN_M, IN_M
    vpsllq   $1, IN_L, IN_L

    vpshufd  $0x4e, IN_M, IN_M

    vpand    HKEY, IN_H, IN_H
    vpor     IN_M, IN_L, IN_L               // H<<<=1
    vpxor   IN_L, IN_H, HKEY                // twisted H

    vmovdqu  HKEY, (HTABLE)                 // store in H[0]
    vpshufd  $0x4e, HKEY, HKEY1_2
    vpxor    HKEY, HKEY1_2, HKEY1_2
    vmovdqa  HKEY, XI_L
    /* xh, xl, hKey, hKey12, temp1, temp2 */
    GHASH_MUL128X128 XI_H, XI_L, HKEY, HKEY1_2, TEMP1, TEMP2                        // calculate H^2
    /* xh, xl, temp1, temp2, reducMask */
    REDUCTION_256BIT XI_H, XI_L, TEMP1, TEMP2, g_poly
    vmovdqa  XI_L, HKEY2
    GHASH_MUL128X128 XI_H, XI_L, HKEY, HKEY1_2, TEMP1, TEMP2                         // calculate H^3
    REDUCTION_256BIT XI_H, XI_L, TEMP1, TEMP2, g_poly
    vmovdqa  XI_L, HKEY3
    GHASH_MUL128X128 XI_H, XI_L, HKEY, HKEY1_2, TEMP1, TEMP2                         // calculate H^4
    REDUCTION_256BIT XI_H, XI_L, TEMP1, TEMP2, g_poly
    vmovdqa  XI_L, HKEY4
    vmovdqu  HKEY2, 0x10(HTABLE)            // store H^2 in H[1]
    vmovdqu  HKEY3, 0x30(HTABLE)            // store H^3 in H[3]
    vmovdqu  HKEY4, 0x40(HTABLE)            // store H^4 in H[4]

    vpshufd  $0x4e, HKEY2, TEMP1
    vpxor    HKEY2, TEMP1, TEMP1
    vshufps $0x44, TEMP1, HKEY1_2, HKEY1_2
    vmovdqu  HKEY1_2, 0x20(HTABLE)          // store [H^2.h + H^2.l, H.h + H.l] in H[2]

    vpshufd  $0x4e, HKEY3, TEMP1
    vpshufd  $0x4e, HKEY4, TEMP2
    vpxor    HKEY3, TEMP1, TEMP1
    vpxor    HKEY4, TEMP2, TEMP2
    vshufps $0x44, TEMP2, TEMP1, HKEY1_2
    vmovdqu  HKEY1_2, 0x50(HTABLE)          // store [H^4.h + H^4.l, H^3.h + H^3.l] in H[5]

    vmovdqu  0x20(HTABLE), HKEY1_2          // reload [H^2.h + H^2.l, H.h + H.l]
    GHASH_MUL128X128 XI_H, XI_L, HKEY, HKEY1_2, TEMP1, TEMP2                         // calculate H^5,  for aes-gcm
    REDUCTION_256BIT XI_H, XI_L, TEMP1, TEMP2, g_poly
    vmovdqa  XI_L, HKEY3
    GHASH_MUL128X128 XI_H, XI_L, HKEY, HKEY1_2, TEMP1, TEMP2                         // calculate H^6,  for aes-gcm
    REDUCTION_256BIT XI_H, XI_L, TEMP1, TEMP2, g_poly
    vmovdqa  XI_L, HKEY4
    vmovdqu  HKEY3, 0x60(HTABLE)            // store H^5 in H[6]
    vmovdqu  HKEY4, 0x70(HTABLE)            // store H^6 in H[7]
    vpshufd  $0x4e, HKEY3, TEMP1
    vpshufd  $0x4e, HKEY4, TEMP2
    vpxor    HKEY3, TEMP1, TEMP1
    vpxor    HKEY4, TEMP2, TEMP2
    vshufps $0x44, TEMP2, TEMP1, HKEY1_2
    vmovdqu  HKEY1_2, 0x80(HTABLE)          // store [H^6.h + H^6.l, H^5.h + H^5.l] in H[8]

    vpxor    HKEY, HKEY, HKEY               // clear hTable
    vpxor    HKEY1_2, HKEY1_2, HKEY1_2
    vpxor    HKEY2, HKEY2, HKEY2
    vpxor    HKEY3, HKEY3, HKEY3
    vpxor    HKEY4, HKEY4, HKEY4
    ret
.cfi_endproc
.size   GcmTableGen4bit, .-GcmTableGen4bit

/**
 *  Function description: x86_64 ghash assembly acceleration implementation
 *  Function prototype: void GcmHashMultiBlock(uint8_t t[GCM_BLOCKSIZE], const MODES_GCM_GF128 hTable[16],
 *                                             const uint8_t *in, uint32_t inLen);
 *  Input register:
 *        rdi: uint8_t t[GCM_BLOCKSIZE]
 *        rsi: const MODES_GCM_GF128 hTable[16]
 *        rdx: const uint8_t *in
 *        rcx: uint32_t inLen
 *  Change register: xmm0-xmm15
 *  Function/Macro Call:
 *          GHASH_MUL128X128
 *          REDUCTION_256BIT      // reduction modulo g(x)
 */
.align	32
.globl GcmHashMultiBlock
.type GcmHashMultiBlock, %function
GcmHashMultiBlock:
.cfi_startproc
    vmovdqa	 g_bswapMask(%rip), MASK
    vmovdqu  (INPUT_XI), XI_L
    vmovdqu  (HTABLE), HKEY
    vmovdqu  0x20(HTABLE), HKEY1_2
    vpshufb  MASK, XI_L, XI_L

    cmp $0x10, LEN
    je  .Lremain_1block

    vmovdqu  0x10(HTABLE), HKEY2
    cmp $0x40, LEN
    jae .Lmul_4blocks
    jmp .Lremain_Least_2blocks

.align	32
.Lmul_4blocks:
    subq $0x40, LEN

    vmovdqu  0x30(INPUT_IN), IN_L           // load In_3, In_2
    vmovdqu  0x20(INPUT_IN), INL
    vpshufb  MASK, IN_L, IN_L
    vpshufb  MASK, INL, INL

    vmovdqa  IN_L, IN_H                     // H * In_3
    vpshufd  $0x4e, IN_L, IN_M
    vpxor    IN_L, IN_M, IN_M
    vpclmulqdq   $0x00, HKEY, IN_L, IN_L
    vpclmulqdq   $0x11, HKEY, IN_H, IN_H
    vpclmulqdq   $0x00, HKEY1_2, IN_M, IN_M

    vmovdqa  INL, INH                       // H^2 * In_2
    vpshufd  $0x4e, INL, INM
    vpxor    INL, INM, INM
    vpclmulqdq   $0x00, HKEY2, INL, INL
    vpclmulqdq   $0x11, HKEY2, INH, INH
    vpclmulqdq   $0x10, HKEY1_2, INM, INM
    vxorps   INL, IN_L, IN_L                // H * In_3 + H^2 * In_2
    vxorps   INH, IN_H, IN_H
    vxorps   INM, IN_M, IN_M

    vmovdqu  0x30(HTABLE), HKEY3
    vmovdqu  0x40(HTABLE), HKEY4
    vmovdqu  0x50(HTABLE), HKEY1_2

    vmovdqu  0x10(INPUT_IN), INL            // load In_1, In_0
    vmovdqu  (INPUT_IN), TEMP1
    vpshufb  MASK, INL, INL
    vpshufb  MASK, TEMP1, TEMP1

    vmovdqa  INL, INH                       // H^3 * In_1
    vpshufd  $0x4e, INL, INM
    vpxor    INL, INM, INM
    vpclmulqdq   $0x00, HKEY3, INL, INL
    vpclmulqdq   $0x11, HKEY3, INH, INH
    vpclmulqdq   $0x00, HKEY1_2, INM, INM
    vxorps   INL, IN_L, IN_L                // H * In_3 + H^2 * In_2 + H^3 * In_1
    vxorps   INH, IN_H, IN_H
    vxorps   INM, IN_M, IN_M

    vpxor    TEMP1, XI_L, XI_L              // (In_1 + Xi)
    vmovdqa  XI_L, XI_H
    vpshufd  $0x4e, XI_L, TEMP1
    vpxor    XI_L, TEMP1, TEMP1
    vpclmulqdq   $0x00, HKEY4, XI_L, XI_L   // H^4 * (In_1 + Xi)
    vpclmulqdq   $0x11, HKEY4, XI_H, XI_H
    vpclmulqdq   $0x10, HKEY1_2, TEMP1, TEMP1
    vxorps   IN_L, XI_L, XI_L               // H * In_3 + H^2 * In_2 + H^3 * In_1 + H^4 * (In_1 + Xi)
    vxorps   IN_H, XI_H, XI_H
    vxorps   IN_M, TEMP1, TEMP1

    vpxor    XI_L, TEMP1, TEMP1
    vpxor    XI_H, TEMP1, TEMP1
    vmovdqa  TEMP1, TEMP2
    vpslldq  $8, TEMP1, TEMP1
    vpsrldq  $8, TEMP2, TEMP2
    vpxor    TEMP1, XI_L, XI_L
    vpxor    TEMP2, XI_H, XI_H

    REDUCTION_256BIT XI_H, XI_L, TEMP1, TEMP2, g_poly
    cmp     $0x00, LEN
    jz     .Lend                            // finshed all blocks
    leaq     0x40(INPUT_IN), INPUT_IN
    vmovdqu  0x20(HTABLE), HKEY1_2
    cmp     $0x40, LEN
    jae .Lmul_4blocks
    cmp     $0x20, LEN
    jae .Lremain_Least_2blocks
    jmp .Lremain_1block

.align	32
.Lremain_Least_2blocks:
    subq $0x20, LEN
    vmovdqu  0x10(INPUT_IN), IN_L           // loda (4 * i) + 1 or 2 block
    vmovdqu  (INPUT_IN), TEMP1
    vpshufb  MASK, IN_L, IN_L
    vpshufb  MASK, TEMP1, TEMP1
    vpxor    TEMP1, XI_L, XI_L

    vmovdqa  IN_L, IN_H
    vpshufd  $0x4e, IN_L, IN_M
    vpxor    IN_L, IN_M, IN_M
    vpclmulqdq   $0x00, HKEY, IN_L, IN_L
    vpclmulqdq   $0x11, HKEY, IN_H, IN_H
    vpclmulqdq   $0x00, HKEY1_2, IN_M, IN_M

    vmovdqa  XI_L, XI_H
    vpshufd  $0x4e, XI_L, TEMP1
    vpxor    XI_L, TEMP1, TEMP1
    vpclmulqdq   $0x00, HKEY2, XI_L, XI_L
    vpclmulqdq   $0x11, HKEY2, XI_H, XI_H
    vpclmulqdq   $0x10, HKEY1_2, TEMP1, TEMP1
    vxorps   IN_L, XI_L, XI_L
    vxorps   IN_H, XI_H, XI_H
    vxorps   IN_M, TEMP1, TEMP1

    vpxor    XI_L, TEMP1, TEMP1
    vpxor    XI_H, TEMP1, TEMP1
    vmovdqa  TEMP1, TEMP2
    vpslldq  $8, TEMP1, TEMP1
    vpsrldq  $8, TEMP2, TEMP2
    vpxor    TEMP1, XI_L, XI_L
    vpxor    TEMP2, XI_H, XI_H

    REDUCTION_256BIT XI_H, XI_L, TEMP1, TEMP2, g_poly
    cmp $0x00, LEN
    jz  .Lend
    leaq 0x20(INPUT_IN), INPUT_IN

.align	32
.Lremain_1block:
    subq $0x10, LEN
    vmovdqu (INPUT_IN), TEMP1
    vpshufb  MASK, TEMP1, TEMP1
    vpxor TEMP1, XI_L, XI_L

    GHASH_MUL128X128 XI_H, XI_L, HKEY, HKEY1_2, TEMP1, TEMP2
    REDUCTION_256BIT XI_H, XI_L, TEMP1, TEMP2, g_poly

.Lend:
    vpshufb  MASK, XI_L, XI_L
    vmovdqu  XI_L, (INPUT_XI)
    vpxor    HKEY, HKEY, HKEY               // clear hTable
    vpxor    HKEY1_2, HKEY1_2, HKEY1_2
    vpxor    HKEY2, HKEY2, HKEY2
    vpxor    HKEY3, HKEY3, HKEY3
    vpxor    HKEY4, HKEY4, HKEY4
    ret
.cfi_endproc
.size	GcmHashMultiBlock, .-GcmHashMultiBlock

#endif
