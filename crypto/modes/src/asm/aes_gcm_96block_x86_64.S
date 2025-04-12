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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_GCM)

.text

/*
 * MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, void *key
 * ctx  %rdi
 * in   %rsi
 * out  %rdx
 * len  %rcx
 * key  %r8
 * The %r12 register is shared with AES_GCM_EncryptBlockAsm. Pay attention to its use.
 */
.type   AES_GCM_Encrypt96BlockAsm, @function
.balign 16
AES_GCM_Encrypt96BlockAsm:
.cfi_startproc
    push %rbp
    mov %rsp, %rbp
    vmovdqu (%rdi), %xmm0                       // iv
    lea -2(%r9d), %r13d
    addl $0x6000000, %r12d                      // ctr inc
    vmovdqu -0x80(%r8), %xmm6                   // key0
    leaq -0x70(%r8), %r10
    jc .Lm96_enc_ctr_carry
    vmovdqa 0x20(%r11), %xmm7
    movl %r12d, 12(%rdi)                        // out iv
    vpaddb %xmm7, %xmm0, %xmm1                  // g_oneLow
    vpxor %xmm6, %xmm0, %xmm0
    vpaddb %xmm7, %xmm1, %xmm2
    vpxor %xmm6, %xmm1, %xmm1
    vpaddb %xmm7, %xmm2, %xmm3
    vpxor %xmm6, %xmm2, %xmm2
    vpaddb %xmm7, %xmm3, %xmm4
    vpxor %xmm6, %xmm3, %xmm3
    vpaddb %xmm7, %xmm4, %xmm5
    vpxor %xmm6, %xmm4, %xmm4
    vpxor %xmm6, %xmm5, %xmm5
    vmovdqu (%r10), %xmm6                       // key1
.balign 16
.Lm96_enc_aes:
    vaesenc %xmm6, %xmm0, %xmm0
    vaesenc %xmm6, %xmm1, %xmm1
    vaesenc %xmm6, %xmm2, %xmm2
    vaesenc %xmm6, %xmm3, %xmm3
    vaesenc %xmm6, %xmm4, %xmm4
    leaq 0x10(%r10), %r10
    vaesenc %xmm6, %xmm5, %xmm5
    vmovdqu (%r10), %xmm6                       // key2-9/11/13
    decl %r13d
    jnz .Lm96_enc_aes
    vaesenc %xmm6, %xmm0, %xmm0
    vmovdqu 0x10(%r10), %xmm10                   // key10/12/14
    sub $112, %rsp
    vaesenc %xmm6, %xmm1, %xmm1
    vpxor (%rsi), %xmm10, %xmm8                  // last key xor plaintext
    and $-16, %rsp
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor 0x10(%rsi), %xmm10, %xmm7
    vaesenc %xmm6, %xmm3, %xmm3
    vpxor 0x20(%rsi), %xmm10, %xmm9
    vaesenc %xmm6, %xmm4, %xmm4
    vpxor 0x30(%rsi), %xmm10, %xmm11
    vaesenc %xmm6, %xmm5, %xmm5
    vpxor 0x40(%rsi), %xmm10, %xmm12
    vaesenclast %xmm8, %xmm0, %xmm0
    vpxor 0x50(%rsi), %xmm10, %xmm13
    vmovdqa (%r11), %xmm15                      // g_byteSwapMask
    vaesenclast %xmm7, %xmm1, %xmm1
    vmovdqu %xmm0, (%rdx)                       // out ciphertext
    vpxor 16(%rdi), %xmm0, %xmm0               // Do it in advance. input for ghash operation
    vmovdqa 0x20(%r11), %xmm6
    vpshufb %xmm15, %xmm0, %xmm8
    vmovdqu (%rdi), %xmm0                       // iv
    vaesenclast %xmm9, %xmm2, %xmm2
    vmovdqa %xmm8, (%rsp)
    vmovdqu -0x80(%r8), %xmm7
    vmovdqu %xmm1, 0x10(%rdx)
    vpshufb %xmm15, %xmm1, %xmm9
    vpaddb %xmm6, %xmm0, %xmm1                  // g_oneLow
    vpxor %xmm7, %xmm0, %xmm0                   // key 0
    vaesenclast %xmm11, %xmm3, %xmm3
    vmovdqa %xmm9, 0x10(%rsp)
    vmovdqu %xmm2, 0x20(%rdx)
    vpshufb %xmm15, %xmm2, %xmm11
    vpaddb %xmm6, %xmm1, %xmm2
    vpxor %xmm7, %xmm1, %xmm1
    vaesenclast %xmm12, %xmm4, %xmm4
    vmovdqa %xmm11, 0x20(%rsp)
    vmovdqu %xmm3, 0x30(%rdx)
    vpshufb %xmm15, %xmm3, %xmm12
    vpaddb %xmm6, %xmm2, %xmm3
    vpxor %xmm7, %xmm2, %xmm2
    vaesenclast %xmm13, %xmm5, %xmm5
    vmovdqa %xmm12, 0x30(%rsp)
    vmovdqu %xmm4, 0x40(%rdx)
    vpshufb %xmm15, %xmm4, %xmm13
    vpaddb %xmm6, %xmm3, %xmm4
    vpxor %xmm7, %xmm3, %xmm3
    leaq 0x60(%rsi), %rsi
    vmovdqu %xmm5, 0x50(%rdx)
    vpshufb %xmm15, %xmm5, %xmm14
    vpaddb %xmm6, %xmm4, %xmm5
    vmovdqa %xmm13, 0x40(%rsp)
    vmovdqa %xmm14, 0x50(%rsp)
    cmpl $12, %ecx                              // If the remaining length is less than 12,
                                                // the loop is not performed.

    jb .Lm96_inner_out
    addl $0x6000000, %r12d
    jc .Lm96_inner_ctr_carry
.balign 16
.Lm96_inner_loop:
    vmovdqu -0x70(%r8), %xmm6                   // rk0
    // function stitch second 6x-blocks encryption and ghash of first 6x-blocks.
    vaesenc %xmm6, %xmm0, %xmm0                 // encryption of the 'inout0' of second 6x-blocks.
    vmovdqu 0x20+0x70(%rdi), %xmm11             // H^6
    vmovdqa (%rsp), %xmm10                      // xmm10 = inout0, the first encrypted 6x-blocks
    vaesenc %xmm6, %xmm1, %xmm1
    movl %r12d, 12(%rdi)                        // out iv
    vmovdqu 0x20+0x80(%rdi), %xmm12             // xmm12 = (H^5.h + H^5.l, H^6.h + H^6.l)
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm15    // Karatsuba Multiply. xmm15 = H^6.h·inout0.h,  where '·' represent multiply in GF(2^128) of GHASH.
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor %xmm7, %xmm4, %xmm4
    vpxor %xmm7, %xmm5, %xmm5
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm14    // xmm14 = H^6.l·inout0.l
    vaesenc %xmm6, %xmm3, %xmm3
    vpunpckhqdq %xmm10, %xmm10, %xmm13          // xmm13= (inout0.h, inout0.h)
    leaq 0x10(%r8), %r10
    vpxor %xmm10, %xmm13, %xmm13                // xmm13 = (inout0.h + inout0.l, inout0.h + inout0.h)
    vmovdqu 0x20+0x60(%rdi), %xmm11             // H^5
    vpclmulqdq $0x10, %xmm12, %xmm13, %xmm13    // xmm13 = (H^6.h + H^6.l)·(inout0.h + inout0.l)
    vaesenc %xmm6, %xmm4, %xmm4
    vmovdqa 0x10(%rsp), %xmm10                  // xmm10 = inout1
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm8     // xmm8 = H^5.h·inout1.h
    vaesenc %xmm6, %xmm5, %xmm5
    vmovdqu -0x60(%r8), %xmm7                   // rk1
    vpxor %xmm8, %xmm15, %xmm15                 // xmm15 += xmm8
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm11    // xmm11 = H^5.l·inout1.l
    vaesenc %xmm7, %xmm0, %xmm0
    vpunpckhqdq %xmm10, %xmm10, %xmm8           // xmm8 = (inout1.h, inout1.h)
    vpxor %xmm11, %xmm14, %xmm14                // xmm14 += xmm11
    vpxor %xmm10, %xmm8, %xmm8                  // xmm8 = (inout1.h + inout1.l, inout1.h + inout1.h)
    vmovdqu 0x20+0x40(%rdi), %xmm11             // xmm11 = H^4
    vpclmulqdq $0x00, %xmm12, %xmm8, %xmm9      // xmm9 = (H^5.h + H^5.l)·(inout1.h + inout1.l)
    vaesenc %xmm7, %xmm1, %xmm1
    vmovdqa 0x20(%rsp), %xmm10                  // xmm10 = inout2
    vpxor %xmm9, %xmm13, %xmm13                 // xmm13 += xmm9

    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm8     // xmm8 = H^4.h·inout2.h
    vaesenc %xmm7, %xmm2, %xmm2
    vmovdqu 0x20+0x50(%rdi), %xmm12             // xmm12 = (H^3.h + H^3.l, H^4.h + H^4.l)
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm9     // xmm9 = H^4.l·inout2.l
    vaesenc %xmm7, %xmm3, %xmm3
    vpxor %xmm8, %xmm15, %xmm15                 // xmm15 += xmm8
    vpxor %xmm9, %xmm14, %xmm14                 // xmm14 += xmm9
    vpunpckhqdq %xmm10, %xmm10, %xmm6           // xmm6 = (inout2.h, inout2.h)
    vaesenc %xmm7, %xmm4, %xmm4
    vpxor %xmm10, %xmm6, %xmm6                  // xmm6 = (inout2.h + inout2.l, inout2.h + inout2.h)
    vmovdqu 0x20+0x30(%rdi), %xmm11             // xmm11 = H^3
    vpclmulqdq $0x10, %xmm12, %xmm6, %xmm8      // xmm8 = (H^4.h + H^4.l)·(inout2.h + inout2.h)
    vaesenc %xmm7, %xmm5, %xmm5
    vmovdqa 0x30(%rsp), %xmm10                  // xmm10 = inout3
    vmovdqu -0x50(%r8), %xmm6                   // rk2

    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm9     // xmm9 = H^3.h·inout3.h
    vaesenc %xmm6, %xmm0, %xmm0
    vpxor %xmm8, %xmm13, %xmm13                 // xmm13 += xmm8
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm7     // xmm7 = H^3.l·inout3.l
    vaesenc %xmm6, %xmm1, %xmm1
    vpxor %xmm9, %xmm15, %xmm15                 // xmm15 += xmm9
    vpunpckhqdq %xmm10, %xmm10, %xmm8           // xmm8 = (inout3.h, inout3,h)
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor %xmm10, %xmm8, %xmm8                  // xmm8 = (inout3.h + inout3.l, inout3.h + inout3.h)
    vpxor %xmm7, %xmm14, %xmm14                 // xmm14 += xmm7
    vpclmulqdq $0x00, %xmm12, %xmm8, %xmm9      // xmm9 = (H^3.h + H^3.l)·(inout3.h + inout3.l)
    vaesenc %xmm6, %xmm3, %xmm3
    vmovdqa 0x40(%rsp), %xmm10                  // xmm10 = inout4
    vmovdqu 0x20+0x10(%rdi), %xmm11             // xmm11 = H^2
    vaesenc %xmm6, %xmm4, %xmm4
    vpxor %xmm9, %xmm13, %xmm13                 // xmm13 += xmm9
    vaesenc %xmm6, %xmm5, %xmm5
    vmovdqu -0x40(%r8), %xmm7                   // rk3

    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm8     // xmm8 = H^2.h·inout4.h
    vaesenc %xmm7, %xmm0, %xmm0
    vmovdqu 0x20+0x20(%rdi), %xmm12             // xmm12 = (H^1.h + H^1.l, H^2.h + H^2.l)
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm9     // xmm9 = H^2.h·inout4.h
    vaesenc %xmm7, %xmm1, %xmm1
    vpunpckhqdq %xmm10, %xmm10, %xmm6           // xmm6 = (inout4.h, inout4.h)
    vpxor %xmm8, %xmm15, %xmm15                 // xmm15 += xmm8
    vaesenc %xmm7, %xmm2, %xmm2
    vpxor %xmm10, %xmm6, %xmm6                  // xmm6 = (inout4.h + inout4.l, inout4.h + inout4.h)
    vpxor %xmm9, %xmm14, %xmm14                 // xmm14 += xmm9
    vpclmulqdq $0x10, %xmm12, %xmm6, %xmm8      // xmm8 = (H^2.h + H^2.l)·(inout4.h + inout4.l)
    vaesenc %xmm7, %xmm3, %xmm3
    vmovdqa 0x50(%rsp), %xmm10                  // xmm10 = inout5
    vmovdqu 0x20(%rdi), %xmm11                  // xmm11 = H^1
    vaesenc %xmm7, %xmm4, %xmm4
    vpxor %xmm8, %xmm13, %xmm13                 // xmm13 += xmm8
    vmovdqu -0x30(%r8), %xmm6                   // rk4
    vaesenc %xmm7, %xmm5, %xmm5

    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm9     // xmm9 = H^1.h·inout5.h
    vaesenc %xmm6, %xmm0, %xmm0
    vpunpckhqdq %xmm10, %xmm10, %xmm7           // xmm7 = (inout5.h, inout5.h)
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm8     // xmm8 = H^1.l·inout5.l
    vaesenc %xmm6, %xmm1, %xmm1
    vpxor %xmm10, %xmm7, %xmm7                  // xmm7 = (inout5.h + inout5.l, inout5.h + inout5.h)
    vpxor %xmm9, %xmm15, %xmm15                 // xmm15 += xmm9
    vpclmulqdq $0x00, %xmm12, %xmm7, %xmm12     // xmm12 = (H^1.h + H^1.l)·(inout5.h + inout5.l), that's all the (l+h)·(l+h)
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor %xmm12, %xmm13, %xmm13                // xmm13 += xmm12
    vpxor %xmm8, %xmm14, %xmm14                 // xmm14 += xmm8
    vaesenc %xmm6, %xmm3, %xmm3
    vpxor %xmm15, %xmm13, %xmm13                // Karatsuba, middle coefficient + higher coefficient
    vpxor %xmm14, %xmm13, %xmm13                // Karatsuba, middle coefficient + lower coefficient
    vpslldq $8, %xmm13, %xmm9                   // xmm9 = (0, xmm13.l)
    vaesenc %xmm6, %xmm4, %xmm4
    vpxor %xmm9, %xmm14, %xmm14                 // xmm14 is the lower 128-bits of ghash of first 6x-blocks
    vaesenc %xmm6, %xmm5, %xmm5

    // montgomery reduction method from https://link.springer.com/chapter/10.1007/978-3-031-34671-2_30
    // T = [D:C:B:A]. here, xmm14 = [B:A], xmm15 = [D:C]
    // WA = W·A, U = C + A + WA.h, V = B + WA.l
    vmovdqu -0x20(%r8), %xmm7                   // rk5
    vpalignr $8, %xmm14, %xmm14, %xmm9          // xmm9 = [A:B]
    vaesenc %xmm7, %xmm0, %xmm0
    vmovdqu 0x30(%r11), %xmm12                  // poly
    vaesenc %xmm7, %xmm1, %xmm1
    vpsrldq $8, %xmm13, %xmm8                   // xmm8 = (xmm13.h, 0)
    vpxor %xmm8, %xmm15, %xmm15                 // xmm15 is the higher 128-bits of ghash of first 6x-blocks
    vaesenc %xmm7, %xmm2, %xmm2
    vpclmulqdq $0x10, %xmm12, %xmm14, %xmm14    // xmm14 = W·A, where W = 0xC200000000000000.
    vaesenc %xmm7, %xmm3, %xmm3
    vmovdqu -0x10(%r8), %xmm6                   // rk6
    vpxor %xmm9, %xmm14, %xmm14                 // xmm14 = W·A + [A:B] = [A+WA.h:B+WA.l] = [U':V], where U' = A + WA.h
    vaesenc %xmm7, %xmm4, %xmm4
    vpalignr $8, %xmm14, %xmm14, %xmm8          // xmm8 = [V:U']
    vpclmulqdq $0x10, %xmm12, %xmm14, %xmm14    // xmm14 = W·V
    vaesenc %xmm7, %xmm5, %xmm5
    vpxor %xmm8, %xmm15, %xmm15                 // xmm15 = [D+V:C+U']
    vpxor %xmm14, %xmm15, %xmm15                // xmm15 = [D+V:C+U'] +  W·V = [D+V+WV.h:C+U'+WV.l] = [D+V+WV.h:U+WV.l] = [D+V:U+WV]
                                                // reduction finished. 
    vaesenc %xmm6, %xmm0, %xmm0
    vaesenc %xmm6, %xmm1, %xmm1
    vaesenc %xmm6, %xmm2, %xmm2
    vaesenc %xmm6, %xmm3, %xmm3
    vaesenc %xmm6, %xmm4, %xmm4
    vaesenc %xmm6, %xmm5, %xmm5

    vmovdqu 0x00(%r8), %xmm7                   // rk7
    vaesenc %xmm7, %xmm0, %xmm0
    vaesenc %xmm7, %xmm1, %xmm1
    vmovdqa %xmm15, %xmm10
    vaesenc %xmm7, %xmm2, %xmm2
    vaesenc %xmm7, %xmm3, %xmm3
    vaesenc %xmm7, %xmm4, %xmm4
    cmpl $12, %r9d
    vaesenc %xmm7, %xmm5, %xmm5

    vmovdqu (%r10), %xmm6
    vmovdqu 0x10(%r10), %xmm11
    jb .Lm96_inner_ending

    vaesenc %xmm6, %xmm0, %xmm0                 // key 10
    vaesenc %xmm6, %xmm1, %xmm1
    vaesenc %xmm6, %xmm2, %xmm2
    vaesenc %xmm6, %xmm3, %xmm3
    vaesenc %xmm6, %xmm4, %xmm4
    vaesenc %xmm6, %xmm5, %xmm5

    vaesenc %xmm11, %xmm0, %xmm0                 // key 11
    vaesenc %xmm11, %xmm1, %xmm1
    vaesenc %xmm11, %xmm2, %xmm2
    vaesenc %xmm11, %xmm3, %xmm3
    leaq 0x20(%r10), %r10
    vaesenc %xmm11, %xmm4, %xmm4
    vmovdqu (%r10), %xmm6
    vaesenc %xmm11, %xmm5, %xmm5
    vmovdqu 0x10(%r10), %xmm11

    je .Lm96_inner_ending

    vaesenc %xmm6, %xmm0, %xmm0                 // key 12
    vaesenc %xmm6, %xmm1, %xmm1
    vaesenc %xmm6, %xmm2, %xmm2
    vaesenc %xmm6, %xmm3, %xmm3
    vaesenc %xmm6, %xmm4, %xmm4
    vaesenc %xmm6, %xmm5, %xmm5

    vaesenc %xmm11, %xmm0, %xmm0                 // key 13
    vaesenc %xmm11, %xmm1, %xmm1
    vaesenc %xmm11, %xmm2, %xmm2
    vaesenc %xmm11, %xmm3, %xmm3
    leaq 0x20(%r10), %r10
    vaesenc %xmm11, %xmm4, %xmm4
    vmovdqu (%r10), %xmm6
    vaesenc %xmm11, %xmm5, %xmm5
    vmovdqu 0x10(%r10), %xmm11

    jmp .Lm96_inner_ending
.balign 16
.Lm96_inner_ctr_carry:
    vmovdqu (%rdi), %xmm0                       // iv
    bswap %r12d
    vmovdqa (%r11), %xmm15
    addl $0x100, %r12d                          // add carry bit
    vmovdqa 0x10(%r11), %xmm14                   // lone_high
    vpshufb %xmm15, %xmm0, %xmm0
    vmovdqu -0x80(%r8), %xmm7
    vpaddd %xmm14, %xmm0, %xmm1
    vpshufb %xmm15, %xmm0, %xmm0
    vpaddd %xmm14, %xmm1, %xmm2
    vpxor %xmm7, %xmm0, %xmm0                   // key 0
    vpshufb %xmm15, %xmm1, %xmm1
    vpaddd %xmm14, %xmm2, %xmm3
    vpxor %xmm7, %xmm1, %xmm1
    vpshufb %xmm15, %xmm2, %xmm2
    vpaddd %xmm14, %xmm3, %xmm4
    vpxor %xmm7, %xmm2, %xmm2
    vpshufb %xmm15, %xmm3, %xmm3
    vpaddd %xmm14, %xmm4, %xmm5
    vpxor %xmm7, %xmm3, %xmm3
    vpshufb %xmm15, %xmm4, %xmm4
    bswap %r12d
    vpshufb %xmm15, %xmm5, %xmm5
    jmp .Lm96_inner_loop
.balign 16
.Lm96_inner_ending:
    vaesenc %xmm6, %xmm0, %xmm0                 // key 9
    vpxor (%rsi), %xmm11, %xmm13                  // last key xor plaintext
    vpxor %xmm14, %xmm12, %xmm12
    vaesenc %xmm6, %xmm1, %xmm1
    vpxor 0x10(%rsi), %xmm11, %xmm8
    vaesenclast %xmm13, %xmm0, %xmm0             // key 10/12/14
    vmovdqa (%r11), %xmm15
    leaq 0x60(%rdx), %rdx
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor 0x20(%rsi), %xmm11, %xmm9
    sub $6, %ecx
    vaesenclast %xmm8, %xmm1, %xmm1
    vmovdqu %xmm0, (%rdx)                       // out result text
    vaesenc %xmm6, %xmm3, %xmm3
    vpshufb %xmm15, %xmm0, %xmm0
    vmovdqa 0x20(%r11), %xmm12
    vpxor %xmm10, %xmm0, %xmm0                  // Do it in advance. input for ghash operation
    vpxor 0x30(%rsi), %xmm11, %xmm8
    vmovdqa %xmm0, (%rsp)
    vaesenclast %xmm9, %xmm2, %xmm2
    vmovdqu -0x80(%r8), %xmm7
    vmovdqu %xmm1, 0x10(%rdx)
    vmovdqu (%rdi), %xmm0                       // iv
    vpshufb %xmm15, %xmm1, %xmm1
    vaesenc %xmm6, %xmm4, %xmm4
    vmovdqa %xmm1, 0x10(%rsp)
    vpaddb %xmm12, %xmm0, %xmm1                  // g_oneLow
    vaesenc %xmm6, %xmm5, %xmm5
    vpxor %xmm7, %xmm0, %xmm0                   // key 0
    vmovdqu %xmm2, 0x20(%rdx)
    vpxor 0x40(%rsi), %xmm11, %xmm9
    vpshufb %xmm15, %xmm2, %xmm2
    vaesenclast %xmm8, %xmm3, %xmm3
    vmovdqa %xmm2, 0x20(%rsp)
    vpaddb %xmm12, %xmm1, %xmm2
    vpxor %xmm7, %xmm1, %xmm1
    vpxor 0x50(%rsi), %xmm11, %xmm8
    vmovdqu %xmm3, 0x30(%rdx)
    vpshufb %xmm15, %xmm3, %xmm3
    vaesenclast %xmm9, %xmm4, %xmm4
    vmovdqa %xmm3, 0x30(%rsp)
    vpaddb %xmm12, %xmm2, %xmm3
    vpxor %xmm7, %xmm2, %xmm2
    leaq 0x60(%rsi), %rsi
    vmovdqu %xmm4, 0x40(%rdx)
    vpshufb %xmm15, %xmm4, %xmm4
    vaesenclast %xmm8, %xmm5, %xmm5
    vmovdqa %xmm4, 0x40(%rsp)
    vpaddb %xmm12, %xmm3, %xmm4
    vpxor %xmm7, %xmm3, %xmm3
    vmovdqu %xmm5, 0x50(%rdx)
    vpshufb %xmm15, %xmm5, %xmm5
    cmpl $12, %ecx                              // If the remaining length is greater than or equal to 12,
                                                // the loop continues.
    vmovdqa %xmm5, 0x50(%rsp)
    vpaddb %xmm12, %xmm4, %xmm5
    jb .Lm96_inner_out
    addl $0x6000000, %r12d
    jc .Lm96_inner_ctr_carry
    jmp .Lm96_inner_loop
.balign 16
.Lm96_enc_ctr_carry:
    vmovdqa (%r11), %xmm15
    bswap %r12d
    vmovdqa 0x10(%r11), %xmm14
    vpshufb %xmm15, %xmm0, %xmm0
    addl $0x100, %r12d                          // add carry bit
    vpaddd %xmm14, %xmm0, %xmm1                 // g_oneHigh
    vpshufb %xmm15, %xmm0, %xmm0
    vpaddd %xmm14, %xmm1, %xmm2
    vpxor %xmm6, %xmm0, %xmm0
    vpshufb %xmm15, %xmm1, %xmm1
    vpaddd %xmm14, %xmm2, %xmm3
    vpxor %xmm6, %xmm1, %xmm1
    vpshufb %xmm15, %xmm2, %xmm2
    vpaddd %xmm14, %xmm3, %xmm4
    vpxor %xmm6, %xmm2, %xmm2
    vpshufb %xmm15, %xmm3, %xmm3
    vpaddd %xmm14, %xmm4, %xmm5
    vpxor %xmm6, %xmm3, %xmm3
    vpshufb %xmm15, %xmm4, %xmm4
    bswap %r12d
    vpshufb %xmm15, %xmm5, %xmm5
    vpxor %xmm6, %xmm4, %xmm4
    movl %r12d, 12(%rdi)                        // out iv
    vpxor %xmm6, %xmm5, %xmm5
    vmovdqu (%r10), %xmm6                       // key1
    jmp .Lm96_enc_aes
.balign 16
.Lm96_inner_out:
// +++++++++++++++++ ghash process +++++++++++++++++++++++++++++++++
    vmovdqu 0x20+0x70(%rdi), %xmm11            // hash key h^6
    vmovdqa (%rsp), %xmm10
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm9    // Karatsuba Multiply
    vmovdqu 0x20+0x80(%rdi), %xmm12            // hash key h^5_6
    vpxor 0x08(%rsp), %xmm10, %xmm13
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm7
    vmovdqu 0x20+0x60(%rdi), %xmm11            // hash key h^5
    vmovdqa 0x10(%rsp), %xmm10
    vpclmulqdq $0x10, %xmm12, %xmm13, %xmm8

    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14   // Karatsuba Multiply
    vmovdqu 0x20+0x50(%rdi), %xmm6             // hash key h^3_4
    vpxor 0x18(%rsp), %xmm10, %xmm13
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    vmovdqu 0x20+0x40(%rdi), %xmm11             // hash key h^4
    vpxor %xmm14, %xmm9, %xmm9
    vpclmulqdq $0x00, %xmm12, %xmm13, %xmm13
    vpxor %xmm10, %xmm7, %xmm7
    vmovdqa 0x20(%rsp), %xmm10
    vpxor %xmm13, %xmm8, %xmm8

    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply
    vpxor 0x28(%rsp), %xmm10, %xmm13
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    vmovdqu 0x20+0x30(%rdi), %xmm11             // hash key h^3
    vpxor %xmm14, %xmm9, %xmm9
    vpclmulqdq $0x10, %xmm6, %xmm13, %xmm13
    vpxor %xmm10, %xmm7, %xmm7
    vmovdqa 0x30(%rsp), %xmm10
    vpxor %xmm13, %xmm8, %xmm8

    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply
    vmovdqu 0x20+0x20(%rdi), %xmm12             // hash key h^1_2
    vpxor 0x38(%rsp), %xmm10, %xmm13
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    vmovdqu 0x20+0x10(%rdi), %xmm11             // hash key h^2
    vpxor %xmm14, %xmm9, %xmm9
    vpclmulqdq $0x00, %xmm6, %xmm13, %xmm13
    vpxor %xmm10, %xmm7, %xmm7
    vmovdqa 0x40(%rsp), %xmm10
    vpxor %xmm13, %xmm8, %xmm8

    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply
    vpxor 0x48(%rsp), %xmm10, %xmm13
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    vmovdqu 0x20(%rdi), %xmm11                  // hash key h^1
    vpxor %xmm14, %xmm9, %xmm9
    vpclmulqdq $0x10, %xmm12, %xmm13, %xmm13
    vpxor %xmm10, %xmm7, %xmm7
    vmovdqa 0x50(%rsp), %xmm10
    vpxor %xmm13, %xmm8, %xmm8

    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply
    vpxor 0x58(%rsp), %xmm10, %xmm13
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    vpxor %xmm14, %xmm9, %xmm14
    vpclmulqdq $0x00, %xmm12, %xmm13, %xmm13
    vpxor %xmm10, %xmm7, %xmm10
    vpxor %xmm13, %xmm8, %xmm13

    vpxor %xmm10, %xmm14, %xmm11
    vpxor %xmm11, %xmm13, %xmm13

    vpslldq $8, %xmm13, %xmm11
    vmovdqa 0x30(%r11), %xmm15                  // g_poly
    vpsrldq $8, %xmm13, %xmm13
    vpxor %xmm11, %xmm10, %xmm10
    vpxor %xmm13, %xmm14, %xmm14

    vpalignr $8, %xmm10, %xmm10, %xmm12         // 1st phase of reduction
    vpclmulqdq $0x10, %xmm15, %xmm10, %xmm10
    sub $6, %ecx
    vpxor %xmm12, %xmm10, %xmm10

    vpalignr $8, %xmm10, %xmm10, %xmm12         // 2nd phase of reduction
    vpclmulqdq $0x10, %xmm15, %xmm10, %xmm10
    vpxor %xmm14, %xmm12, %xmm12
    leaq 0x60(%rdx), %rdx
    vpxor %xmm12, %xmm10, %xmm10

    vpxor %xmm0, %xmm0, %xmm0
    vpshufb (%r11), %xmm10, %xmm10
// ------------------- ghash complete ---------------------------------
    vmovdqa %xmm0, (%rsp)
    vmovdqu %xmm10, 16(%rdi)                     // out ghash
    vmovdqa %xmm0, 0x10(%rsp)
    vmovdqa %xmm0, 0x20(%rsp)
    vmovdqa %xmm0, 0x30(%rsp)
    vmovdqa %xmm0, 0x40(%rsp)
    vmovdqa %xmm0, 0x50(%rsp)
    mov %rbp, %rsp
    pop %rbp
    ret
.cfi_endproc
.size   AES_GCM_Encrypt96BlockAsm, .-AES_GCM_Encrypt96BlockAsm

/*
 * MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, void *key
 * ctx  %rdi
 * in   %rsi
 * out  %rdx
 * len  %rcx
 * key  %r8
 */
.type   AES_GCM_Decrypt96BlockAsm, @function
.balign  32
AES_GCM_Decrypt96BlockAsm:
.cfi_startproc
    push %rbp
    push %r12
    push %r13
    push %r14
    mov %rsp, %rbp
    sub $112, %rsp
    vmovdqu (%rsi), %xmm0                       // in0
    vmovdqa (%r11), %xmm6
    and $-16, %rsp
    vpshufb %xmm6, %xmm0, %xmm0
    vmovdqu 0x10(%rsi), %xmm1                   // in1
    vmovdqa %xmm0, (%rsp)
    vpshufb %xmm6, %xmm1, %xmm1
    vmovdqu 0x20(%rsi), %xmm2                   // in2
    vmovdqa %xmm1, 0x10(%rsp)
    vpshufb %xmm6, %xmm2, %xmm2
    vmovdqu 0x30(%rsi), %xmm3                   // in3
    vmovdqa %xmm2, 0x20(%rsp)
    vpshufb %xmm6, %xmm3, %xmm3
    vmovdqu 0x40(%rsi), %xmm4                   // in4
    vmovdqa %xmm3, 0x30(%rsp)
    vpshufb %xmm6, %xmm4, %xmm4
    vmovdqu 0x50(%rsi), %xmm5                   // in5
    vmovdqa %xmm4, 0x40(%rsp)
    vpshufb %xmm6, %xmm5, %xmm5
    vmovdqu 16(%rdi), %xmm10                    // ghash
    vmovdqa %xmm5, 0x50(%rsp)
    vpshufb %xmm6, %xmm10, %xmm10
.balign 16
.Lm96_dec_loop:
    mov 12(%rdi), %r10d                         // counter  r10d(32bit)
    vmovdqu (%rdi), %xmm0                       // iv
    addl $0x6000000, %r10d                      // ctr inc
    jc .Lm96_dec_ctr_carry
    vmovdqa 0x20(%r11), %xmm6
    vmovdqu (%r8), %xmm7
    vpaddb %xmm6, %xmm0, %xmm1                  // g_oneLow
    vpxor %xmm7, %xmm0, %xmm0                   // key 0
    vpaddb %xmm6, %xmm1, %xmm2
    vpxor %xmm7, %xmm1, %xmm1
    vpaddb %xmm6, %xmm2, %xmm3
    vpxor %xmm7, %xmm2, %xmm2
    vpaddb %xmm6, %xmm3, %xmm4
    vpxor %xmm7, %xmm3, %xmm3
    vpaddb %xmm6, %xmm4, %xmm5
    vmovdqu 0x10(%r8), %xmm6

.Lm96_dec_aes_cipher:
    vaesenc %xmm6, %xmm0, %xmm0                 // key 1
    xor %r14, %r14
    cmp $12, %ecx
    mov %r10d, 12(%rdi)                         // out iv
    setae %r14b
    vaesenc %xmm6, %xmm1, %xmm1
    vpxor %xmm7, %xmm4, %xmm4
    neg %r14
    lea 0x90(%r8), %r10
// +++++++++++++++++ ghash process +++++++++++++++++++++++++++++++++
    vmovdqu 0x20+0x70(%rdi), %xmm11             // hash key h^6
    and $0x60, %r14
    vpxor %xmm7, %xmm5, %xmm5
    vmovdqu 0x20+0x80(%rdi), %xmm12             // hash key h^5_6
    lea (%rsi, %r14), %r14
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor (%rsp), %xmm10, %xmm10                // xor ghash

    vaesenc %xmm6, %xmm3, %xmm3
    vpalignr $8, %xmm10, %xmm10, %xmm13
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm15    // Karatsuba Multiply
    vpxor %xmm10, %xmm13, %xmm13
    vaesenc %xmm6, %xmm4, %xmm4
    movbe (%r14), %r12
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm7
    movbe 0x08(%r14), %r13
    vaesenc %xmm6, %xmm5, %xmm5
    vmovdqu 0x20(%r8), %xmm6
    mov %r13, (%rsp)
    vpclmulqdq $0x10, %xmm12, %xmm13, %xmm8
    vmovdqu 0x20+0x60(%rdi), %xmm11             // hash key h^5
    mov %r12, 0x08(%rsp)
    vaesenc %xmm6, %xmm0, %xmm0                 // key 2
    vmovdqa 0x10(%rsp), %xmm10
    vaesenc %xmm6, %xmm1, %xmm1
    vpxor 0x18(%rsp), %xmm10, %xmm13
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply

    movbe 0x10(%r14), %r12
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor %xmm14, %xmm15, %xmm15
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    movbe 0x18(%r14), %r13
    vaesenc %xmm6, %xmm3, %xmm3
    mov %r13, 0x10(%rsp)
    vmovdqu 0x20+0x40(%rdi), %xmm11             // hash key h^4
    vpclmulqdq $0x00, %xmm12, %xmm13, %xmm13
    mov %r12, 0x18(%rsp)
    vpxor %xmm10, %xmm7, %xmm7
    vaesenc %xmm6, %xmm4, %xmm4
    vpxor %xmm13, %xmm8, %xmm8
    vmovdqu 0x20+0x50(%rdi), %xmm12             // hash key h^3_4
    vaesenc %xmm6, %xmm5, %xmm5
    vmovdqu 0x30(%r8), %xmm6
    vmovdqa 0x20(%rsp), %xmm10

    vaesenc %xmm6, %xmm0, %xmm0                 // key 3
    vpxor 0x28(%rsp), %xmm10, %xmm13
    movbe 0x20(%r14), %r12
    vaesenc %xmm6, %xmm1, %xmm1
    movbe 0x28(%r14), %r13
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply
    mov %r13, 0x20(%rsp)
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor %xmm14, %xmm15, %xmm15
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    mov %r12, 0x28(%rsp)
    vmovdqu 0x20+0x30(%rdi), %xmm11             // hash key h^3
    vaesenc %xmm6, %xmm3, %xmm3
    vpxor %xmm10, %xmm7, %xmm7

    vpclmulqdq $0x10, %xmm12, %xmm13, %xmm13
    vmovdqa 0x30(%rsp), %xmm10
    vaesenc %xmm6, %xmm4, %xmm4
    vpxor %xmm13, %xmm8, %xmm8
    vaesenc %xmm6, %xmm5, %xmm5
    vmovdqu 0x40(%r8), %xmm6
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply

    vpxor 0x38(%rsp), %xmm10, %xmm13
    vaesenc %xmm6, %xmm0, %xmm0                 // key 4
    movbe 0x30(%r14), %r12
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    vpxor %xmm14, %xmm15, %xmm15
    vaesenc %xmm6, %xmm1, %xmm1
    movbe 0x38(%r14), %r13
    vpxor %xmm10, %xmm7, %xmm7
    vpclmulqdq $0x00, %xmm12, %xmm13, %xmm13
    mov %r13, 0x30(%rsp)
    vpxor %xmm13, %xmm8, %xmm8
    vaesenc %xmm6, %xmm2, %xmm2
    mov %r12, 0x38(%rsp)
    vaesenc %xmm6, %xmm3, %xmm3
    vmovdqu 0x20+0x10(%rdi), %xmm11             // hash key h^2
    vaesenc %xmm6, %xmm4, %xmm4
    vmovdqu 0x20+0x20(%rdi), %xmm12             // hash key h^1_2
    vaesenc %xmm6, %xmm5, %xmm5
    vmovdqu 0x50(%r8), %xmm6

    vmovdqa 0x40(%rsp), %xmm10
    vaesenc %xmm6, %xmm0, %xmm0                 // key 5
    vpxor 0x48(%rsp), %xmm10, %xmm13
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply
    movbe 0x40(%r14), %r12
    vaesenc %xmm6, %xmm1, %xmm1
    movbe 0x48(%r14), %r13
    vpxor %xmm14, %xmm15, %xmm15
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    mov %r13, 0x40(%rsp)
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor %xmm10, %xmm7, %xmm7
    vpclmulqdq $0x10, %xmm12, %xmm13, %xmm13
    mov %r12, 0x48(%rsp)
    vpxor %xmm13, %xmm8, %xmm8
    vaesenc %xmm6, %xmm3, %xmm3
    vmovdqu 0x20(%rdi), %xmm11                  // hash key h^1
    vaesenc %xmm6, %xmm4, %xmm4
    vmovdqa 0x50(%rsp), %xmm10
    vaesenc %xmm6, %xmm5, %xmm5
    vmovdqu 0x60(%r8), %xmm6

    vaesenc %xmm6, %xmm0, %xmm0                 // key 6
    vpxor 0x58(%rsp), %xmm10, %xmm13
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply
    movbe 0x50(%r14), %r12
    vaesenc %xmm6, %xmm1, %xmm1
    vpxor %xmm14, %xmm15, %xmm14
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    movbe 0x58(%r14), %r13
    vaesenc %xmm6, %xmm2, %xmm2
    mov %r13, 0x50(%rsp)
    vpclmulqdq $0x00, %xmm12, %xmm13, %xmm13
    mov %r12, 0x58(%rsp)
    vpxor %xmm10, %xmm7, %xmm10
    vaesenc %xmm6, %xmm3, %xmm3
    vpxor %xmm13, %xmm8, %xmm13
    vaesenc %xmm6, %xmm4, %xmm4
    vpxor %xmm10, %xmm14, %xmm11
    vaesenc %xmm6, %xmm5, %xmm5

    vmovdqu 0x70(%r8), %xmm6
    vpxor %xmm11, %xmm13, %xmm13
    vaesenc %xmm6, %xmm0, %xmm0                 // key 7
    vpslldq $8, %xmm13, %xmm11
    vaesenc %xmm6, %xmm1, %xmm1
    vpsrldq $8, %xmm13, %xmm13
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor %xmm13, %xmm14, %xmm14
    vaesenc %xmm6, %xmm3, %xmm3
    vpxor %xmm11, %xmm10, %xmm10
    vaesenc %xmm6, %xmm4, %xmm4
    vmovdqa 0x30(%r11), %xmm13                  // g_poly
    vaesenc %xmm6, %xmm5, %xmm5

    vmovdqu 0x80(%r8), %xmm6
    vpalignr $8, %xmm10, %xmm10, %xmm12         // 1st phase of reduction
    vaesenc %xmm6, %xmm0, %xmm0                 // key 8
    vpclmulqdq $0x10, %xmm13, %xmm10, %xmm10
    vaesenc %xmm6, %xmm1, %xmm1
    vpxor %xmm12, %xmm10, %xmm10
    vaesenc %xmm6, %xmm2, %xmm2
    vpalignr $8, %xmm10, %xmm10, %xmm12         // 2nd phase of reduction
    vaesenc %xmm6, %xmm3, %xmm3
    vpclmulqdq $0x10, %xmm13, %xmm10, %xmm10
    vpxor %xmm14, %xmm12, %xmm12
    vaesenc %xmm6, %xmm4, %xmm4
    vpxor %xmm12, %xmm10, %xmm10
    vmovdqu 0x10(%r10), %xmm7
    vaesenc %xmm6, %xmm5, %xmm5
    vmovdqu (%r10), %xmm6
// ------------------- ghash complete ---------------------------------
    cmp $12, %r9d

    jb .Lm96_dec_ending

    vaesenc %xmm6, %xmm0, %xmm0                 // key 9
    vaesenc %xmm6, %xmm1, %xmm1
    vaesenc %xmm6, %xmm2, %xmm2
    vaesenc %xmm6, %xmm3, %xmm3
    vaesenc %xmm6, %xmm4, %xmm4
    vaesenc %xmm6, %xmm5, %xmm5

    vaesenc %xmm7, %xmm0, %xmm0                 // key 10
    vaesenc %xmm7, %xmm1, %xmm1
    vaesenc %xmm7, %xmm2, %xmm2
    vaesenc %xmm7, %xmm3, %xmm3
    lea 0x20(%r10), %r10
    vaesenc %xmm7, %xmm4, %xmm4
    vmovdqu (%r10), %xmm6
    vaesenc %xmm7, %xmm5, %xmm5
    vmovdqu 0x10(%r10), %xmm7

    je .Lm96_dec_ending

    vaesenc %xmm6, %xmm0, %xmm0                 // key 11
    vaesenc %xmm6, %xmm1, %xmm1
    vaesenc %xmm6, %xmm2, %xmm2
    vaesenc %xmm6, %xmm3, %xmm3
    vaesenc %xmm6, %xmm4, %xmm4
    vaesenc %xmm6, %xmm5, %xmm5

    vaesenc %xmm7, %xmm0, %xmm0                 // key 12
    vaesenc %xmm7, %xmm1, %xmm1
    vaesenc %xmm7, %xmm2, %xmm2
    vaesenc %xmm7, %xmm3, %xmm3
    lea 0x20(%r10), %r10
    vaesenc %xmm7, %xmm4, %xmm4
    vmovdqu (%r10), %xmm6
    vaesenc %xmm7, %xmm5, %xmm5
    vmovdqu 0x10(%r10), %xmm7

    jmp .Lm96_dec_ending
.balign 16
.Lm96_dec_ctr_carry:
    vmovdqa (%r11), %xmm8
    vmovdqu (%r8), %xmm7
    bswap %r10d
    vpshufb %xmm8, %xmm0, %xmm0
    vmovdqa 0x10(%r11), %xmm6
    addl $0x100, %r10d                          // add carry bit
    vpaddd %xmm6, %xmm0, %xmm1
    vpshufb %xmm8, %xmm0, %xmm0
    vpaddd %xmm6, %xmm1, %xmm2
    vpxor %xmm7, %xmm0, %xmm0                   // key 0
    vpshufb %xmm8, %xmm1, %xmm1
    vpaddd %xmm6, %xmm2, %xmm3
    vpxor %xmm7, %xmm1, %xmm1
    vpshufb %xmm8, %xmm2, %xmm2
    vpaddd %xmm6, %xmm3, %xmm4
    vpxor %xmm7, %xmm2, %xmm2
    vpshufb %xmm8, %xmm3, %xmm3
    vpaddd %xmm6, %xmm4, %xmm5
    vpxor %xmm7, %xmm3, %xmm3
    vpshufb %xmm8, %xmm4, %xmm4
    bswap %r10d
    vpshufb %xmm8, %xmm5, %xmm5
    vmovdqu 0x10(%r8), %xmm6
    jmp .Lm96_dec_aes_cipher
.balign 16
.Lm96_dec_ending:
    vaesenc %xmm6, %xmm0, %xmm0
    sub $6, %ecx
    vpxor (%rsi), %xmm7, %xmm8                 // last key xor plaintext
    vaesenc %xmm6, %xmm1, %xmm1
    vpxor 0x10(%rsi), %xmm7, %xmm9                 // last key xor plaintext
    vaesenc %xmm6, %xmm2, %xmm2
    vpxor 0x20(%rsi), %xmm7, %xmm11                 // last key xor plaintext
    vaesenc %xmm6, %xmm3, %xmm3
    vpxor 0x30(%rsi), %xmm7, %xmm12                 // last key xor plaintext
    vaesenc %xmm6, %xmm4, %xmm4
    vpxor 0x40(%rsi), %xmm7, %xmm13                 // last key xor plaintext
    vaesenc %xmm6, %xmm5, %xmm5
    vpxor 0x50(%rsi), %xmm7, %xmm14                 // last key xor plaintext
    vaesenclast %xmm8, %xmm0, %xmm0             // last key
    lea 0x60(%rsi), %rsi
    vaesenclast %xmm9, %xmm1, %xmm1
    vmovdqu %xmm0, (%rdx)                       // out result text
    vaesenclast %xmm11, %xmm2, %xmm2
    vmovdqu %xmm1, 0x10(%rdx)
    vaesenclast %xmm12, %xmm3, %xmm3
    vmovdqu %xmm2, 0x20(%rdx)
    vaesenclast %xmm13, %xmm4, %xmm4
    vmovdqu %xmm3, 0x30(%rdx)
    vaesenclast %xmm14, %xmm5, %xmm5
    vmovdqu %xmm4, 0x40(%rdx)
    cmp $6, %ecx
    vmovdqu %xmm5, 0x50(%rdx)
    lea 0x60(%rdx), %rdx
    jae .Lm96_dec_loop

    vpxor %xmm0, %xmm0, %xmm0
    vpshufb (%r11), %xmm10, %xmm10
    vmovdqa %xmm0, (%rsp)
    vmovdqa %xmm0, 0x10(%rsp)
    vmovdqa %xmm0, 0x20(%rsp)
    vmovdqa %xmm0, 0x30(%rsp)
    vmovdqa %xmm0, 0x40(%rsp)
    vmovdqa %xmm0, 0x50(%rsp)
    mov %rbp, %rsp
    vmovdqu %xmm10, 16(%rdi)                    // out ghash
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    ret
.cfi_endproc
.size   AES_GCM_Decrypt96BlockAsm, .-AES_GCM_Decrypt96BlockAsm
#endif
