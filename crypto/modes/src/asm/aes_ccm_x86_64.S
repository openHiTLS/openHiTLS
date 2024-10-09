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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CCM)

.text

.balign 16
g_byteSwapMask:
.byte   0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
.byte   0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
.size   g_byteSwapMask, .-g_byteSwapMask
.balign 16
g_one:
.byte   0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.byte   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.size   g_one, .-g_one

/*
 * void AesCcmEncryptAsm(void *key, uint8_t *nonce, const uint8_t *in, uint8_t *out, uint32_t len)
 * rdi *key
 * rsi *nonce
 * rdx *in
 * rcx *out
 * r8 len
 */
.globl  AesCcmEncryptAsm
.type   AesCcmEncryptAsm, @function
.balign 16
AesCcmEncryptAsm:
.cfi_startproc
    shr $4, %r8d                    // loop times
    jz .Lenc_ret
    lea g_byteSwapMask(%rip), %r11
    mov 0xf0(%rdi), %r9d            // key->rounds
    vmovdqa (%r11), %xmm15          // g_byteSwapMask
    sub $1, %r9d
    vmovdqa 0x10(%r11), %xmm14      // g_one
    vmovdqu (%rsi), %xmm0           // nonce(counter)
    vmovdqu 0x10(%rsi), %xmm8       // tag
    vmovdqu 0x20(%rsi), %xmm9       // last
.balign 16
.Lenc_outer_loop:
    mov %r9d, %r10d
    vpxor (%rdx), %xmm8, %xmm8      // in ^ tag = tag
    vmovdqu (%rdi), %xmm1           // key0
    lea 0x10(%rdi), %r11            // &key + 1
    vpxor %xmm0, %xmm1, %xmm2       // first round xor(aes-ctr)
    vpshufb %xmm15, %xmm0, %xmm0    // reverse byte order of nonce => nonce'
    vpxor %xmm8, %xmm1, %xmm3       // first round xor(aes-cmac)
.balign 16
.Lenc_aes_loop:
    vmovdqu (%r11), %xmm1
    vaesenc %xmm1, %xmm2, %xmm2
    vaesenc %xmm1, %xmm3, %xmm3
    lea 0x10(%r11), %r11            // to next key ptr
    dec %r10d
    jnz .Lenc_aes_loop
    vmovdqu (%r11), %xmm1           // get the last key
    vpaddq %xmm14, %xmm0, %xmm0     // nonce' + 1
    vaesenclast %xmm1, %xmm2, %xmm9
    vaesenclast %xmm1, %xmm3, %xmm8
    vpxor (%rdx), %xmm9, %xmm2      // in ^ last = out
    vpshufb %xmm15, %xmm0, %xmm0    // reverse byte order of nonce' => nonce
    lea 0x10(%rdx), %rdx            // go to next ptr
    vmovdqu %xmm2, (%rcx)           // out out

    lea 0x10(%rcx), %rcx            // go to next ptr
    dec %r8d
    jnz .Lenc_outer_loop
    vpxor %xmm1, %xmm1, %xmm1
    vpxor %xmm2, %xmm2, %xmm2
    vpxor %xmm3, %xmm3, %xmm3
    vmovdqu %xmm0, (%rsi)           // out nonce
    vpxor %xmm0, %xmm0, %xmm0
    vmovdqu %xmm8, 0x10(%rsi)       // out tag
    vpxor %xmm8, %xmm8, %xmm8
    vmovdqu %xmm9, 0x20(%rsi)       // out last
    vpxor %xmm9, %xmm9, %xmm9
.Lenc_ret:
    ret
.cfi_endproc
.size   AesCcmEncryptAsm, .-AesCcmEncryptAsm

/*
 * void AesCcmDecryptAsm(void *key, uint8_t *nonce, const uint8_t *in, uint8_t *out, uint32_t len)
 * rdi *key
 * rsi *nonce
 * rdx *in
 * rcx *out
 * r8 len
 */
.globl  AesCcmDecryptAsm
.type   AesCcmDecryptAsm, @function
.balign 16
AesCcmDecryptAsm:
.cfi_startproc
    shr $4, %r8d                    // loop times
    jz .Ldec_ret
    lea g_byteSwapMask(%rip), %r11
    mov 0xf0(%rdi), %r9d            // key->rounds
    vmovdqa (%r11), %xmm15          // g_byteSwapMask
    sub $1, %r9d
    vmovdqa 0x10(%r11), %xmm14      // g_one
    vmovdqu (%rsi), %xmm0           // nonce(counter)
    vmovdqu 0x10(%rsi), %xmm8       // tag

.balign 16
.Ldec_outer_loop:
    mov %r9d, %r10d
    lea 0x10(%rdi), %r11            // &key
    vmovdqu (%rdi), %xmm1           // key0
    vpxor %xmm0, %xmm1, %xmm2       // first round xor(aes-ctr)
.Ldec_aes_loop:
    vmovdqu (%r11), %xmm1
    vaesenc %xmm1, %xmm2, %xmm2
    lea 0x10(%r11), %r11
    dec %r10d
    jnz .Ldec_aes_loop
    vmovdqu (%r11), %xmm1
    vaesenclast %xmm1, %xmm2, %xmm4
    vmovdqu %xmm4, 0x20(%rsi)       // out last
    vpxor (%rdx), %xmm4, %xmm2      // in ^ last = out
    vpxor %xmm2, %xmm8, %xmm8       // out ^ tag = tag
    vmovdqu %xmm2, (%rcx)           // out out
    lea 0x10(%rdx), %rdx
    lea 0x10(%rcx), %rcx
    vpshufb %xmm15, %xmm0, %xmm0    // reverse byte order of nonce => nonce'
    vpaddq %xmm14, %xmm0, %xmm0     // nonce' + 1
    vpshufb %xmm15, %xmm0, %xmm0    // reverse byte order of nonce' => nonce
    cmp $2, %r8d
    jb .Ldec_parallel_out

.Ldec_parallel_loop:
    mov %r9d, %r10d
    lea 0x10(%rdi), %r11            // &key
    vmovdqu (%rdi), %xmm1           // key0
    vpxor %xmm0, %xmm1, %xmm2       // first round xor(aes-ctr)
    vpxor %xmm8, %xmm1, %xmm3       // first round xor(aes-cmac)
.Ldec_parallel_inner_loop:
    vmovdqu (%r11), %xmm1
    vaesenc %xmm1, %xmm2, %xmm2
    lea 0x10(%r11), %r11
    vaesenc %xmm1, %xmm3, %xmm3
    dec %r10d
    jnz .Ldec_parallel_inner_loop
    vmovdqu (%r11), %xmm1
    vaesenclast %xmm1, %xmm2, %xmm4
    vaesenclast %xmm1, %xmm3, %xmm8
    vmovdqu %xmm4, 0x20(%rsi)       // out last
    vpxor (%rdx), %xmm4, %xmm2      // in ^ last = out
    vpxor %xmm2, %xmm8, %xmm8       // out ^ tag = tag
    vmovdqu %xmm2, (%rcx)           // out out
    lea 0x10(%rdx), %rdx
    lea 0x10(%rcx), %rcx
    vpshufb %xmm15, %xmm0, %xmm0    // reverse byte order of nonce => nonce'
    vpaddq %xmm14, %xmm0, %xmm0     // nonce' + 1
    vpshufb %xmm15, %xmm0, %xmm0    // reverse byte order of nonce' => nonce
    dec %r8d
    cmp $2, %r8d
    jae .Ldec_parallel_loop

.Ldec_parallel_out:
    mov %r9d, %r10d
    lea 0x10(%rdi), %r11            // &key
    vmovdqu (%rdi), %xmm1           // key0
    vpxor %xmm8, %xmm1, %xmm3       // first round xor(aes-cmac)
.Ldec_aes_loop_1:
    vmovdqu (%r11), %xmm1
    vaesenc %xmm1, %xmm3, %xmm3
    lea 0x10(%r11), %r11
    dec %r10d
    jnz .Ldec_aes_loop_1
    vmovdqu (%r11), %xmm1
    vaesenclast %xmm1, %xmm3, %xmm8
    dec %r8d
    jnz .Ldec_outer_loop

    vmovdqu %xmm0, (%rsi)           // out nonce
    vpxor %xmm0, %xmm0, %xmm0
    vpxor %xmm1, %xmm1, %xmm1
    vpxor %xmm2, %xmm2, %xmm2
    vmovdqu %xmm8, 0x10(%rsi)       // out tag
    vpxor %xmm8, %xmm8, %xmm8
    vpxor %xmm3, %xmm3, %xmm3
    vpxor %xmm4, %xmm4, %xmm4
.Ldec_ret:
    ret
.cfi_endproc
.size   AesCcmDecryptAsm, .-AesCcmDecryptAsm
#endif
