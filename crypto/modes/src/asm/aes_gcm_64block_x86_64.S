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

#include "aes_gcm_96block_x86_64.S"
.text

.balign 16
g_byteSwapMask:
.byte	0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
.byte	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
.size   g_byteSwapMask, .-g_byteSwapMask
.balign 16
g_oneHigh:
.byte   0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.size   g_oneHigh, .-g_oneHigh
.balign 16
g_oneLow:
.byte   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
.size   g_oneLow, .-g_oneLow
.balign 16
g_poly:
.byte   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2
.size   g_poly, .-g_poly

/*
 * uint32_t AES_GCM_EncryptBlockAsm(MODES_GCM_Ctx *ctx, const uint8_t *in,
 *                                       uint8_t *out, uint32_t len, void *key);
 * ctx  %rdi
 * in   %rsi
 * out  %rdx
 * len  %rcx
 * key  %r8
 */
.globl  AES_GCM_EncryptBlockAsm
.type   AES_GCM_EncryptBlockAsm, @function
.balign 32
AES_GCM_EncryptBlockAsm:
.cfi_startproc
    push %r12
    push %r13
    leaq g_byteSwapMask(%rip), %r11
    mov 240(%r8), %r9d                          // rounds
    shrl $4, %ecx
    movl 12(%rdi), %r12d                        // counter  r12d(32bit)
    mov %ecx, %eax
    lea 0x80(%r8), %r8
    shl $4, %eax
    cmp $6, %ecx
    jb .Lm64_enc_pass                           // If the number of data blocks is less than six, the data is skipped.
    call AES_GCM_Encrypt96BlockAsm              // Invoke six parallel processing parts.
.Lm64_enc_pass:
    cmp $4, %ecx                                // If the remaining data is less than four blocks,
                                                // the function is returned.
    jb .Lm64_enc_return
    vmovdqu (%rdi), %xmm0                       // iv
    and $0b11, %ecx
    lea -2(%r9d), %r13d
    addl $0x4000000, %r12d                      // ctr inc
    jc .Lm64_enc_ctr_carry
    mov %r12d, 12(%rdi)                         // out iv
    vmovdqa 0x20(%r11), %xmm14                  // Lone_low
    lea -0x70(%r8), %r10
    vpaddb %xmm14, %xmm0, %xmm1
    vmovdqu -0x80(%r8), %xmm4                   // key0
    vpaddb %xmm14, %xmm1, %xmm2
    vpxor %xmm4, %xmm0, %xmm0
    vpxor %xmm4, %xmm1, %xmm1
    vpaddb %xmm14, %xmm2, %xmm3
    vpxor %xmm4, %xmm2, %xmm2
    vpxor %xmm4, %xmm3, %xmm3
    jmp .Lm64_enc_aes
.Lm64_enc_ctr_carry:
    vmovdqa 0x10(%r11), %xmm14                  // Lone_high
    bswap %r12d
    vmovdqa (%r11), %xmm15
    addl $0x100, %r12d                          // add carry bit
    vpshufb %xmm15, %xmm0, %xmm0
    bswap %r12d
    vpaddd %xmm14, %xmm0, %xmm1
    vpshufb %xmm15, %xmm0, %xmm0
    mov %r12d, 12(%rdi)                         // out iv
    vpaddd %xmm14, %xmm1, %xmm2
    lea -0x70(%r8), %r10
    vpshufb %xmm15, %xmm1, %xmm1
    vmovdqu -0x80(%r8), %xmm4                   // key0
    vpaddd %xmm14, %xmm2, %xmm3
    vpxor %xmm4, %xmm0, %xmm0
    vpshufb %xmm15, %xmm2, %xmm2
    vpxor %xmm4, %xmm1, %xmm1
    vpshufb %xmm15, %xmm3, %xmm3
    vpxor %xmm4, %xmm2, %xmm2
    vpxor %xmm4, %xmm3, %xmm3
    jmp .Lm64_enc_aes
.balign 16
.Lm64_enc_aes:
    vmovdqu (%r10), %xmm4                       // key1-8/10/12
    vaesenc %xmm4, %xmm0, %xmm0
    vaesenc %xmm4, %xmm1, %xmm1
    vaesenc %xmm4, %xmm2, %xmm2
    vaesenc %xmm4, %xmm3, %xmm3
    lea 0x10(%r10), %r10
    dec %r13d
    jnz .Lm64_enc_aes
    vmovdqu (%r10), %xmm4                       // key9/11/13
    vmovdqu 0x10(%r10), %xmm5                   // key10/12/14
    vaesenc %xmm4, %xmm0, %xmm0
    vpxor (%rsi), %xmm5, %xmm6                  // last key xor plaintext
    vaesenc %xmm4, %xmm1, %xmm1
    vpxor 0x10(%rsi), %xmm5, %xmm7
    vaesenc %xmm4, %xmm2, %xmm2
    vpxor 0x20(%rsi), %xmm5, %xmm8
    vaesenc %xmm4, %xmm3, %xmm3
    vpxor 0x30(%rsi), %xmm5, %xmm9
    vaesenclast %xmm6, %xmm0, %xmm10
    vmovdqu 16(%rdi), %xmm5                     // ghash
    vaesenclast %xmm7, %xmm1, %xmm11
    vmovdqu %xmm10, (%rdx)                      // out ciphertext
    vaesenclast %xmm8, %xmm2, %xmm12
    vmovdqu %xmm11, 0x10(%rdx)
    vaesenclast %xmm9, %xmm3, %xmm13
    vmovdqu %xmm12, 0x20(%rdx)
// +++++++++++++++++ ghash process +++++++++++++++++++++++++++++++++
    vmovdqu %xmm13, 0x30(%rdx)
    vpxor %xmm5, %xmm10, %xmm0                  // input for ghash operation
    vmovdqu 0x20+0x40(%rdi), %xmm1              // hash key h^4
    vpshufb (%r11), %xmm0, %xmm0                // data transform
    vmovdqu 0x20+0x50(%rdi), %xmm2              // hash key h^3_4
    vpalignr $8, %xmm0, %xmm0, %xmm3

    vpclmulqdq $0x11, %xmm1, %xmm0, %xmm9       // Karatsuba Multiply
    vpxor %xmm0, %xmm3, %xmm3
    vpclmulqdq $0x00, %xmm1, %xmm0, %xmm7
    vmovdqu 0x20+0x30(%rdi), %xmm1              // hash key h^3
    vpclmulqdq $0x11, %xmm2, %xmm3, %xmm8
    vpshufb (%r11), %xmm11, %xmm0               // data transform
    vpalignr $8, %xmm0, %xmm0, %xmm3

    vpclmulqdq $0x11, %xmm1, %xmm0, %xmm5       // Karatsuba Multiply
    vpxor %xmm0, %xmm3, %xmm3
    vpclmulqdq $0x00, %xmm1, %xmm0, %xmm0
    vpxor %xmm5, %xmm9, %xmm9
    vmovdqu 0x20+0x10(%rdi), %xmm1              // hash key h^2
    vpclmulqdq $0x00, %xmm2, %xmm3, %xmm3
    vpxor %xmm0, %xmm7, %xmm7
    vpshufb (%r11), %xmm12, %xmm0               // data transform
    vpxor %xmm3, %xmm8, %xmm8
    vmovdqu 0x20+0x20(%rdi), %xmm2              // hash key h^1_2
    vpalignr $8, %xmm0, %xmm0, %xmm3

    vpclmulqdq $0x11, %xmm1, %xmm0, %xmm5       // Karatsuba Multiply
    vpxor %xmm0, %xmm3, %xmm3
    vpclmulqdq $0x00, %xmm1, %xmm0, %xmm0
    vmovdqu 0x20(%rdi), %xmm1                   // hash key h^1
    vpxor %xmm5, %xmm9, %xmm9
    vpclmulqdq $0x11, %xmm2, %xmm3, %xmm3
    vpxor %xmm0, %xmm7, %xmm7
    vpshufb (%r11), %xmm13, %xmm0               // data transform
    vpxor %xmm3, %xmm8, %xmm8
    vpalignr $8, %xmm0, %xmm0, %xmm3

    vpclmulqdq $0x11, %xmm1, %xmm0, %xmm5       // Karatsuba Multiply
    vpxor %xmm0, %xmm3, %xmm3
    vpclmulqdq $0x00, %xmm1, %xmm0, %xmm0
    vpxor %xmm5, %xmm9, %xmm5
    vpclmulqdq $0x00, %xmm2, %xmm3, %xmm3
    vpxor %xmm0, %xmm7, %xmm0
    vpxor %xmm3, %xmm8, %xmm3
    vpxor %xmm0, %xmm5, %xmm1
    vpxor %xmm1, %xmm3, %xmm3

    vpslldq $8, %xmm3, %xmm4
    vmovdqa 0x30(%r11), %xmm14                  // Lpoly
    vpxor %xmm4, %xmm0, %xmm0

    vpalignr $8, %xmm0, %xmm0, %xmm2            // 1st phase of reduction
    vpclmulqdq $0x10, %xmm14, %xmm0, %xmm0
    vpsrldq $8, %xmm3, %xmm3
    vpxor %xmm2, %xmm0, %xmm0

    vpalignr $8, %xmm0, %xmm0, %xmm2            // 2nd phase of reduction
    vpxor %xmm3, %xmm5, %xmm5
    vpclmulqdq $0x10, %xmm14, %xmm0, %xmm0
    vpxor %xmm5, %xmm2, %xmm2
    vpxor %xmm2, %xmm0, %xmm0

    vpshufb (%r11), %xmm0, %xmm0                // results for ghash
// ------------------- ghash complete ---------------------------------
    vmovdqu %xmm0, 16(%rdi)                     // out ghash
.Lm64_enc_return:
    shl $4, %ecx
    sub %ecx, %eax
    pop %r13
    pop %r12
    ret
.cfi_endproc
.size   AES_GCM_EncryptBlockAsm, .-AES_GCM_EncryptBlockAsm

/*
 * uint32_t AES_GCM_DecryptBlockAsm(MODES_GCM_Ctx *ctx, const uint8_t *in,
 *                                       uint8_t *out, uint32_t len, void *key);
 * ctx  %rdi
 * in   %rsi
 * out  %rdx
 * len  %rcx
 * key  %r8
 */
.globl  AES_GCM_DecryptBlockAsm
.type   AES_GCM_DecryptBlockAsm, @function
.balign 32
AES_GCM_DecryptBlockAsm:
.cfi_startproc
    leaq g_byteSwapMask(%rip), %r11
    shrl $4, %ecx
    mov %ecx, %eax
    shll $4, %eax
    vmovdqa (%r11), %xmm15                      // g_byteSwapMask
    mov 240(%r8), %r9d                          // rounds
    cmp $6, %ecx                                // invoke six parallel processing parts.
    jb .Lm64_dec_pass                           // if the number of data blocks is less than six, the data is skipped.
    call AES_GCM_Decrypt96BlockAsm
.Lm64_dec_pass:
    cmp $4, %ecx                                // If the remaining data is less than four blocks,
                                                // the function is returned.
    jb .Lm64_dec_return
.balign 16
.Lm64_dec_loop:
    vmovdqu (%rdi), %xmm0                       // iv
    mov 12(%rdi), %r10d                         // counter  r10d(32bit)
    addl $0x4000000, %r10d                      // ctr inc
    jc .Lm64_dec_ctr_carry
    vmovdqa 0x20(%r11), %xmm14                  // Lone_low
    vpaddb %xmm14, %xmm0, %xmm1
    vpaddb %xmm14, %xmm1, %xmm2
    vpaddb %xmm14, %xmm2, %xmm3
    jmp .Lm64_dec_aes_cipher
.Lm64_dec_ctr_carry:
    vmovdqa (%r11), %xmm15
    bswap %r10d
    vpshufb %xmm15, %xmm0, %xmm0
    vmovdqa 0x10(%r11), %xmm14                  // Lone_high
    addl $0x100, %r10d                          // add carry bit
    vpaddd %xmm14, %xmm0, %xmm1
    vpshufb %xmm15, %xmm0, %xmm0
    vpaddd %xmm14, %xmm1, %xmm2
    vpshufb %xmm15, %xmm1, %xmm1
    vpaddd %xmm14, %xmm2, %xmm3
    vpshufb %xmm15, %xmm2, %xmm2
    bswap %r10d
    vpshufb %xmm15, %xmm3, %xmm3
    jmp .Lm64_dec_aes_cipher
.balign 32
.Lm64_dec_aes_cipher:
    vmovdqu (%r8), %xmm7
    mov %r10d, 12(%rdi)                         // out iv
    lea 0x10(%r8), %r10
    vmovdqu 0x10(%rsi), %xmm5
    vpxor %xmm7, %xmm0, %xmm0                   // key 0
    vmovdqu 0x20(%rsi), %xmm6
    vpxor %xmm7, %xmm1, %xmm1
    vmovdqu 0x30(%rsi), %xmm9
    vpxor %xmm7, %xmm2, %xmm2

    vmovdqu (%r10), %xmm4
    vpxor %xmm7, %xmm3, %xmm3
// +++++++++++++++++ ghash process +++++++++++++++++++++++++++++++++
    vmovdqu 16(%rdi), %xmm11                    // ghash
    lea 0x10(%r10), %r10
    vaesenc %xmm4, %xmm0, %xmm0                 // key 1
    vpxor (%rsi), %xmm11, %xmm10                // input for ghash operation
    vmovdqu 0x20+0x40(%rdi), %xmm11             // hash key h^4
    vaesenc %xmm4, %xmm1, %xmm1
    vmovdqu 0x20+0x50(%rdi), %xmm12             // hash key h^3_4
    vpshufb (%r11), %xmm10, %xmm10              // data transform
    vaesenc %xmm4, %xmm2, %xmm2
    vpalignr $8, %xmm10, %xmm10, %xmm13
    vaesenc %xmm4, %xmm3, %xmm3
    vmovdqu (%r10), %xmm4

    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm15    // Karatsuba Multiply
    lea 0x10(%r10), %r10
    vaesenc %xmm4, %xmm0, %xmm0                 // key 2
    vpxor %xmm10, %xmm13, %xmm13
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm7
    vaesenc %xmm4, %xmm1, %xmm1
    vmovdqu 0x20+0x30(%rdi), %xmm11             // hash key h^3
    vpclmulqdq $0x11, %xmm12, %xmm13, %xmm8
    vaesenc %xmm4, %xmm2, %xmm2
    vpshufb (%r11), %xmm5, %xmm10               // data transform
    vaesenc %xmm4, %xmm3, %xmm3
    vmovdqu (%r10), %xmm4

    vpalignr $8, %xmm10, %xmm10, %xmm13
    lea 0x10(%r10), %r10
    vaesenc %xmm4, %xmm0, %xmm0                 // key 3
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply
    vaesenc %xmm4, %xmm1, %xmm1
    vpxor %xmm10, %xmm13, %xmm13
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    vaesenc %xmm4, %xmm2, %xmm2
    vpxor %xmm14, %xmm15, %xmm15
    vpclmulqdq $0x00, %xmm12, %xmm13, %xmm13
    vaesenc %xmm4, %xmm3, %xmm3
    vmovdqu (%r10), %xmm4

    vpxor %xmm10, %xmm7, %xmm7
    lea 0x10(%r10), %r10
    vaesenc %xmm4, %xmm0, %xmm0                 // key 4
    vpxor %xmm13, %xmm8, %xmm8
    vaesenc %xmm4, %xmm1, %xmm1
    vmovdqu 0x20+0x10(%rdi), %xmm11             // hash key h^2
    vmovdqu 0x20+0x20(%rdi), %xmm12             // hash key h^1_2
    vaesenc %xmm4, %xmm2, %xmm2
    vpshufb (%r11), %xmm6, %xmm10               // data transform
    vaesenc %xmm4, %xmm3, %xmm3
    vmovdqu (%r10), %xmm4
    vpalignr $8, %xmm10, %xmm10, %xmm13
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply

    lea 0x10(%r10), %r10
    vaesenc %xmm4, %xmm0, %xmm0                 // key 5
    vpxor %xmm10, %xmm13, %xmm13
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    vaesenc %xmm4, %xmm1, %xmm1
    vpxor %xmm14, %xmm15, %xmm15
    vpclmulqdq $0x11, %xmm12, %xmm13, %xmm13
    vaesenc %xmm4, %xmm2, %xmm2
    vpxor %xmm10, %xmm7, %xmm7
    vaesenc %xmm4, %xmm3, %xmm3
    vmovdqu (%r10), %xmm4

    vpxor %xmm13, %xmm8, %xmm8
    lea 0x10(%r10), %r10
    vaesenc %xmm4, %xmm0, %xmm0                 // key 6
    vmovdqu 0x20(%rdi), %xmm11                  // hash key h^1
    vpshufb (%r11), %xmm9, %xmm10               // data transform
    vpalignr $8, %xmm10, %xmm10, %xmm13
    vaesenc %xmm4, %xmm1, %xmm1
    vpclmulqdq $0x11, %xmm11, %xmm10, %xmm14    // Karatsuba Multiply
    vpxor %xmm10, %xmm13, %xmm13
    vaesenc %xmm4, %xmm2, %xmm2
    vpclmulqdq $0x00, %xmm11, %xmm10, %xmm10
    vpxor %xmm14, %xmm15, %xmm14
    vaesenc %xmm4, %xmm3, %xmm3
    vmovdqu (%r10), %xmm4
    vpclmulqdq $0x00, %xmm12, %xmm13, %xmm13
    vpxor %xmm10, %xmm7, %xmm10
    vpxor %xmm13, %xmm8, %xmm13

    lea 0x10(%r10), %r10
    vaesenc %xmm4, %xmm0, %xmm0                 // key 7
    vpxor %xmm10, %xmm14, %xmm11
    vaesenc %xmm4, %xmm1, %xmm1
    vpxor %xmm11, %xmm13, %xmm13
    vpslldq $8, %xmm13, %xmm11
    vaesenc %xmm4, %xmm2, %xmm2
    vpsrldq $8, %xmm13, %xmm13
    vpxor %xmm13, %xmm14, %xmm14
    vaesenc %xmm4, %xmm3, %xmm3
    vmovdqu (%r10), %xmm4

    vpxor %xmm11, %xmm10, %xmm10
    lea 0x10(%r10), %r10
    vaesenc %xmm4, %xmm0, %xmm0                 // key 8
    vmovdqa 0x30(%r11), %xmm13                  // Lpoly
    vaesenc %xmm4, %xmm1, %xmm1
    vpalignr $8, %xmm10, %xmm10, %xmm12         // 1st phase of reduction
    vpclmulqdq $0x10, %xmm13, %xmm10, %xmm10
    vpxor %xmm12, %xmm10, %xmm10
    vaesenc %xmm4, %xmm2, %xmm2
    vpalignr $8, %xmm10, %xmm10, %xmm12         // 2nd phase of reduction
    vaesenc %xmm4, %xmm3, %xmm3
    vmovdqu (%r10), %xmm4

    vpclmulqdq $0x10, %xmm13, %xmm10, %xmm10
    vpxor %xmm14, %xmm12, %xmm12
    vaesenc %xmm4, %xmm0, %xmm0                 // key 9
    vpxor %xmm12, %xmm10, %xmm10
    vaesenc %xmm4, %xmm1, %xmm1
    lea 0x10(%r10), %r10
    vaesenc %xmm4, %xmm2, %xmm2
    vpshufb (%r11), %xmm10, %xmm10
// ------------------- ghash complete ---------------------------------
    vaesenc %xmm4, %xmm3, %xmm3
    vmovdqu %xmm10, 16(%rdi)                    // out ghash

    cmp $12, %r9d
    jb .Lm64_dec_ending

    vmovdqu (%r10), %xmm4
    vmovdqu 0x10(%r10), %xmm5
    vaesenc %xmm4, %xmm0, %xmm0                 // key 10
    vaesenc %xmm4, %xmm1, %xmm1
    vaesenc %xmm4, %xmm2, %xmm2
    vaesenc %xmm4, %xmm3, %xmm3

    lea 0x20(%r10), %r10
    vaesenc %xmm5, %xmm0, %xmm0                 // key 11
    vaesenc %xmm5, %xmm1, %xmm1
    vaesenc %xmm5, %xmm2, %xmm2
    vaesenc %xmm5, %xmm3, %xmm3

    je .Lm64_dec_ending

    vmovdqu (%r10), %xmm4
    vmovdqu 0x10(%r10), %xmm5
    vaesenc %xmm4, %xmm0, %xmm0                 // key 12
    vaesenc %xmm4, %xmm1, %xmm1
    vaesenc %xmm4, %xmm2, %xmm2
    vaesenc %xmm4, %xmm3, %xmm3

    lea 0x20(%r10), %r10
    vaesenc %xmm5, %xmm0, %xmm0                 // key 13
    vaesenc %xmm5, %xmm1, %xmm1
    vaesenc %xmm5, %xmm2, %xmm2
    vaesenc %xmm5, %xmm3, %xmm3

    jmp .Lm64_dec_ending
.Lm64_dec_ending:
    vmovdqu (%r10), %xmm4                       // key10/12/14
    vpxor (%rsi), %xmm4, %xmm5                  // last key xor plaintext
    vpxor 0x10(%rsi), %xmm4, %xmm6
    vaesenclast %xmm5, %xmm0, %xmm0
    vpxor 0x20(%rsi), %xmm4, %xmm7
    vaesenclast %xmm6, %xmm1, %xmm1
    vpxor 0x30(%rsi), %xmm4, %xmm8
    vmovdqu %xmm0, (%rdx)                       // out ciphertext
    vaesenclast %xmm7, %xmm2, %xmm2
    vmovdqu %xmm1, 0x10(%rdx)
    vaesenclast %xmm8, %xmm3, %xmm3
    vmovdqu %xmm2, 0x20(%rdx)
    and $0b11, %ecx
    vmovdqu %xmm3, 0x30(%rdx)
.Lm64_dec_return:
    shl $4, %ecx
    sub %ecx, %eax
    ret
.cfi_endproc
.size   AES_GCM_DecryptBlockAsm, .-AES_GCM_DecryptBlockAsm
#endif