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

.balign 16
g_byteSwapMask:
.byte   0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
.byte   0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
.size   g_byteSwapMask, .-g_byteSwapMask
.balign 16
g_poly:
.byte   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2
.size   g_poly, .-g_poly

/*
 * void AES_GCM_Encrypt16BlockAsm(MODES_GCM_Ctx *ctx, const uint8_t *in,
 *                                       uint8_t *out, uint32_t len, void *key);
 * ctx  %rdi
 * in   %rsi
 * out  %rdx
 * len  %rcx
 * key  %r8
 */
.globl  AES_GCM_Encrypt16BlockAsm
.type   AES_GCM_Encrypt16BlockAsm, @function
.align 32
AES_GCM_Encrypt16BlockAsm:
.cfi_startproc
    leaq g_byteSwapMask(%rip), %r11
    shrl $4, %ecx                           // blocks number = loop times
    mov 240(%r8), %r9d                      // rounds
.Lenc_loop:
    mov 12(%rdi), %eax                      // counter eax(32bit)
    addl $0x1000000, %eax                   // ctr inc
    vmovdqu (%rdi), %xmm0                   // iv
    jc .Lenc_ctr_carry
    jmp .Lenc_aes_cipher
.Lenc_ctr_carry:
    bswap %eax
    addl $0x100, %eax                       // add carry bit
    bswap %eax
    jmp .Lenc_aes_cipher
.Lenc_aes_cipher:
    mov %eax, 12(%rdi)                      // out iv
    vmovdqu (%r8), %xmm1                    // key0
    vpxor %xmm1, %xmm0, %xmm0

    vmovdqu 0x10(%r8), %xmm2                // key1
    lea 0xa0(%r8), %r10                     // point to the last key in 128-bit encryption
    vmovdqu 0x20(%r8), %xmm3                // key2
    vaesenc %xmm2, %xmm0, %xmm0

    vmovdqu 0x30(%r8), %xmm4                // key3
    vaesenc %xmm3, %xmm0, %xmm0

    vmovdqu 0x40(%r8), %xmm5                // key4
    vaesenc %xmm4, %xmm0, %xmm0

    vmovdqu 0x50(%r8), %xmm6                // key5
    vaesenc %xmm5, %xmm0, %xmm0

    vmovdqu 0x60(%r8), %xmm7                // key6
    vaesenc %xmm6, %xmm0, %xmm0

    vmovdqu 0x70(%r8), %xmm8                // key7
    vaesenc %xmm7, %xmm0, %xmm0

    vmovdqu 0x80(%r8), %xmm9                // key8
    vaesenc %xmm8, %xmm0, %xmm0

    vmovdqu 0x90(%r8), %xmm10               // key9
    vaesenc %xmm9, %xmm0, %xmm0

    vaesenc %xmm10, %xmm0, %xmm0
    cmp $12, %r9d                           // compare the number of rounds to determine
                                            // when to jump to the next processing part

    jb .Lenc_aes_end

    vmovdqu (%r10), %xmm1                   // key10
    vaesenc %xmm1, %xmm0, %xmm0

    vmovdqu 0x10(%r10), %xmm2               // key11
    vaesenc %xmm2, %xmm0, %xmm0
    lea 0x20(%r10), %r10

    je .Lenc_aes_end

    vmovdqu (%r10), %xmm1                   // key12
    vaesenc %xmm1, %xmm0, %xmm0

    vmovdqu 0x10(%r10), %xmm2               // key13
    vaesenc %xmm2, %xmm0, %xmm0
    lea 0x20(%r10), %r10
    jmp .Lenc_aes_end
.Lenc_aes_end:
    vmovdqu (%r10), %xmm1                   // key last
    vpxor (%rsi), %xmm1, %xmm1              // Advance ciphertext XOR in
    vaesenclast %xmm1, %xmm0, %xmm0
    vmovdqu %xmm0, (%rdx)                   // out

    vmovdqu 16(%rdi), %xmm1                 // ghash
    vmovdqa (%r11), %xmm15                  // .LByte_Swap_Mask
    vpxor %xmm1, %xmm0, %xmm0               // input for ghash operation
    vmovdqu 32(%rdi), %xmm1                 // Hash key H^1
    vpshufb %xmm15, %xmm0, %xmm0            // data transform
    vmovdqu 32+32(%rdi), %xmm2              // Hash key H^1_2

    vpalignr $8, %xmm0, %xmm0, %xmm3        // data transform

    vpclmulqdq $0x11, %xmm1, %xmm0, %xmm5   // Karatsuba Multiply
    vpxor %xmm0, %xmm3, %xmm3
    vpclmulqdq $0x00, %xmm1, %xmm0, %xmm0
    vpxor %xmm0, %xmm5, %xmm1
    vpclmulqdq $0x00, %xmm2, %xmm3, %xmm3
    vpxor %xmm1, %xmm3, %xmm3

    vpslldq $8, %xmm3, %xmm4
    vpsrldq $8, %xmm3, %xmm3
    vpxor %xmm4, %xmm0, %xmm0
    vpxor %xmm3, %xmm5, %xmm5

    vmovdqa 0x10(%r11), %xmm14              // g_poly
    vpalignr $8, %xmm0, %xmm0, %xmm2        // 1st phase of reduction
    vpclmulqdq $0x10, %xmm14, %xmm0, %xmm0
    vpxor %xmm2, %xmm0, %xmm0

    vpalignr $8, %xmm0, %xmm0, %xmm2        // 2nd phase of reduction
    vpclmulqdq $0x10, %xmm14, %xmm0, %xmm0
    vpxor %xmm5, %xmm2, %xmm2
    vpxor %xmm2, %xmm0, %xmm0

    vpshufb %xmm15, %xmm0, %xmm0
    lea 0x10(%rsi), %rsi
    vmovdqu %xmm0, 16(%rdi)                 // out
    lea 0x10(%rdx), %rdx
    dec %ecx
    jnz .Lenc_loop
    ret
.cfi_endproc
.size   AES_GCM_Encrypt16BlockAsm, .-AES_GCM_Encrypt16BlockAsm

/*
 * void AES_GCM_Decrypt16BlockAsm(MODES_GCM_Ctx *ctx, const uint8_t *in,
 *                                       uint8_t *out, uint32_t len, void *key);
 * ctx  %rdi
 * in   %rsi
 * out  %rdx
 * len  %rcx
 * key  %r8
 */
.globl  AES_GCM_Decrypt16BlockAsm
.type   AES_GCM_Decrypt16BlockAsm, @function
.balign 32
AES_GCM_Decrypt16BlockAsm:
.cfi_startproc
    leaq g_byteSwapMask(%rip), %r11
    vmovdqu 16(%rdi), %xmm10                // ghash
    shrl $4, %ecx                           // blocks number = loop times
    vmovdqa (%r11), %xmm15                  // g_byteSwapMask
.Ldec_loop:
    mov 12(%rdi), %eax                      // counter  eax(32bit)
    addl $0x1000000, %eax                   // ctr inc
    mov 240(%r8), %r9d                      // rounds
    vmovdqu (%rdi), %xmm0                   // iv
    jc .Ldec_ctr_carry
    jmp .Ldec_aes_cipher
.Ldec_ctr_carry:
    bswap %eax
    addl $0x100, %eax                       // add carry bit
    bswap %eax
    jmp .Ldec_aes_cipher
.balign 32
.Ldec_aes_cipher:
    mov %eax, 12(%rdi)                      // out iv
    cmp $12, %r9d                           // Compare the number of rounds to determine
                                            // when to jump to the next processing part
    vmovdqu (%r8), %xmm1                    // key 0
    vpxor (%rsi), %xmm10, %xmm10            // input for ghash operation
    lea 0xa0(%r8), %r10                     // Point to the last key in 128-bit encryption
    vpxor %xmm1, %xmm0, %xmm0
    vmovdqu 0x10(%r8), %xmm1                // key 1
    vmovdqu 32(%rdi), %xmm11                // Hash key H^1
    vmovdqu 32+32(%rdi), %xmm12             // Hash key H^1_2

    vaesenc %xmm1, %xmm0, %xmm0
    vmovdqu 0x20(%r8), %xmm1                // key 2
    vpshufb %xmm15, %xmm10, %xmm10          // data transform
    vpshufd $0x4e, %xmm10, %xmm13

    vaesenc %xmm1, %xmm0, %xmm0
    vmovdqu 0x30(%r8), %xmm1                // key 3
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14// Karatsuba Multiply
    vpxor %xmm10, %xmm13, %xmm13

    vaesenc %xmm1, %xmm0, %xmm0
    vmovdqu 0x40(%r8), %xmm1                // key 4
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    vpxor %xmm10, %xmm14, %xmm11

    vaesenc %xmm1, %xmm0, %xmm0
    vmovdqu 0x50(%r8), %xmm1                // key 5
    vpclmulqdq $0x00, %xmm12, %xmm13, %xmm13
    vpxor %xmm11, %xmm13, %xmm13

    vaesenc %xmm1, %xmm0, %xmm0
    vmovdqu 0x60(%r8), %xmm1                // key 6
    vpslldq $8, %xmm13, %xmm11
    vpsrldq $8, %xmm13, %xmm13
    vpxor %xmm11, %xmm10, %xmm10
    vpxor %xmm13, %xmm14, %xmm14

    vaesenc %xmm1, %xmm0, %xmm0
    vmovdqu 0x70(%r8), %xmm1                // key 7
    vmovdqa 0x10(%r11), %xmm13              // g_poly
    vpalignr $8, %xmm10, %xmm10, %xmm12     // 1st phase of reduction

    vaesenc %xmm1, %xmm0, %xmm0
    vmovdqu 0x80(%r8), %xmm1                // key 8
    vpclmulqdq $0x10, %xmm13, %xmm10, %xmm10
    vpxor %xmm12, %xmm10, %xmm10

    vaesenc %xmm1, %xmm0, %xmm0
    vmovdqu 0x90(%r8), %xmm1                // key 9
    vpalignr $8, %xmm10, %xmm10, %xmm12     // 2nd phase of reduction
    vpclmulqdq $0x10, %xmm13, %xmm10, %xmm10

    vaesenc %xmm1, %xmm0, %xmm0
    vpxor %xmm14, %xmm12, %xmm12

    jb .Ldec_ending

    vmovdqu (%r10), %xmm1                   // key 10
    vmovdqu 0x10(%r10), %xmm2               // key 11
    lea 0x20(%r10), %r10
    vaesenc %xmm1, %xmm0, %xmm0
    vaesenc %xmm2, %xmm0, %xmm0

    je .Ldec_ending

    vmovdqu (%r10), %xmm1                   // key 12
    vmovdqu 0x10(%r10), %xmm2               // key 13
    lea 0x20(%r10), %r10
    vaesenc %xmm1, %xmm0, %xmm0
    vaesenc %xmm2, %xmm0, %xmm0

    jmp .Ldec_ending

.Ldec_ending:
    vmovdqu (%r10), %xmm1                   // key last
    vpxor %xmm12, %xmm10, %xmm10
    vpxor (%rsi), %xmm1, %xmm1
    vaesenclast %xmm1, %xmm0, %xmm0
    vpshufb %xmm15, %xmm10, %xmm10
    vmovdqu %xmm0, (%rdx)                   // out
    lea 0x10(%rsi), %rsi
    lea 0x10(%rdx), %rdx
    dec %ecx
    jnz .Ldec_loop
    vmovdqu %xmm10, 16(%rdi)                // out
    ret
.cfi_endproc
.size   AES_GCM_Decrypt16BlockAsm, .-AES_GCM_Decrypt16BlockAsm

.globl  AES_GCM_ClearAsm
.type   AES_GCM_ClearAsm, @function
.balign 32
AES_GCM_ClearAsm:
.cfi_startproc
    vpxor %xmm1, %xmm1, %xmm1
    vpxor %xmm2, %xmm2, %xmm2
    vpxor %xmm3, %xmm3, %xmm3
    vpxor %xmm4, %xmm4, %xmm4
    vpxor %xmm5, %xmm5, %xmm5
    vpxor %xmm6, %xmm6, %xmm6
    vpxor %xmm7, %xmm7, %xmm7
    vpxor %xmm8, %xmm8, %xmm8
    vpxor %xmm9, %xmm9, %xmm9
    vpxor %xmm10, %xmm10, %xmm10
    vpxor %xmm11, %xmm11, %xmm11
    vpxor %xmm12, %xmm12, %xmm12
    ret
.cfi_endproc
.size   AES_GCM_ClearAsm, .-AES_GCM_ClearAsm
#endif