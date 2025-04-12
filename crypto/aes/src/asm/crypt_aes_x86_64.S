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
#ifdef HITLS_CRYPTO_AES

 #include "crypt_aes_macro_x86_64.s"

 .file "crypt_aes_x86_64.S"
 .text

.set    ARG1, %rdi
.set    ARG2, %rsi
.set    ARG3, %rdx
.set    ARG4, %rcx
.set    ARG5, %r8
.set    ARG6, %r9
.set    RET, %eax

.set    XM0, %xmm0
.set    XM1, %xmm1
.set    XM2, %xmm2
.set    XM3, %xmm3
.set    XM4, %xmm4
.set    XM5, %xmm5

/**
 * aes128 macros for key extension processing.
 */
.macro KEY_EXPANSION_HELPER_128 xm0 xm1 xm2
    vpermilps $0xff, \xm1, \xm1
    vpslldq $4, \xm0, \xm2
    vpxor \xm2, \xm0, \xm0
    vpslldq $4, \xm2, \xm2
    vpxor \xm2, \xm0, \xm0
    vpslldq $4, \xm2, \xm2
    vpxor \xm2, \xm0, \xm0
    vpxor \xm1, \xm0, \xm0
.endm

/**
 * aes192 macros for key extension processing.
 */
.macro KEY_EXPANSION_HELPER_192 xm1 xm3
    vpslldq $4, \xm1, \xm3
    vpxor \xm3, \xm1, \xm1
    vpslldq $4, \xm3, \xm3
    vpxor \xm3, \xm1, \xm1
    vpslldq $4, \xm3, \xm3
    vpxor \xm3, \xm1, \xm1
.endm

/**
 *  Function description: Sets the AES encryption key. Key length: 128 bits.
 *  Function prototype: void SetEncryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key);
 *  Input register:
 *        x0：Pointer to the output key structure.
 *        x1：Pointer to the input key.
 *  Change register：xmm0-xmm2.
 *  Output register：None.
 *  Function/Macro Call: None.
 */
    .globl SetEncryptKey128
    .type SetEncryptKey128, @function
SetEncryptKey128:
    .cfi_startproc

    movl $10, 240(%rdi)
    movdqu (ARG2), XM0
    movdqu XM0, (ARG1)

    aeskeygenassist $0x01, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0, 16(ARG1)

    aeskeygenassist $0x02, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0, 32(ARG1)

    aeskeygenassist $0x04, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0, 48(ARG1)

    aeskeygenassist $0x08, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0, 64(ARG1)

    aeskeygenassist $0x10, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0, 80(ARG1)

    aeskeygenassist $0x20, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0, 96(ARG1)

    aeskeygenassist $0x40, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0, 112(ARG1)

    aeskeygenassist $0x80, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0, 128(ARG1)

    aeskeygenassist $0x1b, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0, 144(ARG1)

    aeskeygenassist $0x36, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0, 160(ARG1)

    vpxor XM0, XM0, XM0
    vpxor XM1, XM1, XM1
    vpxor XM2, XM2, XM2

    ret
    .cfi_endproc
    .size SetEncryptKey128, .-SetEncryptKey128

/**
 *  Function description: Sets the AES decryption key. Key length: 128 bits.
 *  Function prototype: void SetDecryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key);
 *  Input register:
 *        x0：Pointer to the output key structure.
 *        x1：Pointer to the input key.
 *  Change register：xmm0-xmm3.
 *  Output register: None.
 *  Function/Macro Call: None.
 */
    .globl SetDecryptKey128
    .type SetDecryptKey128, @function
SetDecryptKey128:
    .cfi_startproc

    movl $10, 240(%rdi)
    movdqu (ARG2), XM0
    movdqu XM0, 160(ARG1)

    aeskeygenassist $0x01, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    aesimc  XM0, XM3
    movdqu XM3, 144(ARG1)

    aeskeygenassist $0x02, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    aesimc  XM0, XM3
    movdqu XM3, 128(ARG1)

    aeskeygenassist $0x04, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    aesimc  XM0, XM3
    movdqu XM3, 112(ARG1)

    aeskeygenassist $0x08, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    aesimc  XM0, XM3
    movdqu XM3, 96(ARG1)

    aeskeygenassist $0x10, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    aesimc  XM0, XM3
    movdqu XM3, 80(ARG1)

    aeskeygenassist $0x20, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    aesimc  XM0, XM3
    movdqu XM3, 64(ARG1)

    aeskeygenassist $0x40, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    aesimc  XM0, XM3
    movdqu XM3, 48(ARG1)

    aeskeygenassist $0x80, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    aesimc  XM0, XM3
    movdqu XM3, 32(ARG1)

    aeskeygenassist $0x1b, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    aesimc  XM0, XM3
    movdqu XM3, 16(ARG1)

    aeskeygenassist $0x36, XM0, XM1
    KEY_EXPANSION_HELPER_128 XM0, XM1, XM2
    movdqu XM0,(ARG1)

    vpxor XM0, XM0, XM0
    vpxor XM1, XM1, XM1
    vpxor XM2, XM2, XM2
    vpxor XM3, XM3, XM3

    ret
    .cfi_endproc
    .size SetDecryptKey128, .-SetDecryptKey128

/**
 *  Function description: Sets the AES encryption key. Key length: 192 bits.
 *  Function prototype: void SetEncryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key);
 *  Input register:
 *        x0：Pointer to the output key structure.
 *        x1：Pointer to the input key.
 *  Change register: xmm0-xmm4.
 *  Output register: None.
 *  Function/Macro Call: None.
 */
    .globl SetEncryptKey192
    .type SetEncryptKey192, @function
SetEncryptKey192:
    .cfi_startproc

    movl $12, 240(ARG1)
    movdqu (ARG2), XM0
    movdqu 8(ARG2), XM1
    movdqu XM0,(ARG1)

    vpxor XM4, XM4, XM4
    vshufps $0x40, XM0, XM4, XM2
    aeskeygenassist $0x01, XM1, XM0
    vshufps $0xf0, XM0, XM4, XM0
    vpslldq $0x04, XM2, XM3
    vpxor XM3, XM2, XM2
    vpxor XM2, XM0, XM0
    vshufps $0xee, XM0, XM1, XM0
    movdqu XM0, 16(ARG1)

    movdqu XM1, XM2
    vpslldq $4, XM2, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpermilps $0xff, XM0, XM3
    vpxor XM3, XM2, XM2
    movdqu XM2, 32(ARG1)

    vshufps $0x4e, XM2, XM0, XM1
    aeskeygenassist $0x02, XM2, XM0
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM0, XM0
    vpxor XM1, XM0, XM0
    movdqu XM0, 48(ARG1)

    vshufps $0x4e, XM0, XM2, XM1
    vpslldq $8, XM1, XM2
    vpslldq $4, XM2, XM3
    vpxor  XM3, XM2, XM2
    vpermilps $0xff, XM0, XM3
    vpxor  XM3, XM2, XM2
    aeskeygenassist $0x04, XM2, XM3
    vpermilps $0xff, XM3, XM3
    vpsrldq $8, XM1, XM4
    vpslldq $12, XM4, XM4
    vpxor  XM4, XM1, XM1
    vpxor  XM3, XM1, XM1
    vshufps $0xee, XM1, XM2, XM2
    movdqu XM2, 64(ARG1)

    vshufps $0x4e, XM2, XM0, XM1
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM2, XM0
    vpxor XM1, XM0, XM0
    movdqu XM0, 80(ARG1)

    vshufps $0x4e, XM0, XM2, XM1
    aeskeygenassist $0x08, XM0, XM2
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM2, XM2
    vpxor XM1, XM2, XM2
    movdqu XM2, 96(ARG1)

    vshufps $0x4e, XM2, XM0, XM1
    vpslldq $8, XM1, XM0
    vpslldq $4, XM0, XM3
    vpxor  XM3, XM0, XM0
    vpermilps $0xff, XM2, XM3
    vpxor  XM3, XM0, XM0
    aeskeygenassist $0x10, XM0, XM3
    vpermilps $0xff, XM3, XM3
    vpsrldq $8, XM1, XM4
    vpslldq $12, XM4, XM4
    vpxor  XM4, XM1, XM1
    vpxor  XM3, XM1, XM1
    vshufps $0xee, XM1, XM0, XM0
    movdqu XM0, 112(ARG1)

    vshufps $0x4e, XM0, XM2, XM1
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM0, XM2
    vpxor XM1, XM2, XM2
    movdqu XM2, 128(ARG1)

    vshufps $0x4e, XM2, XM0, XM1
    aeskeygenassist $0x20, XM2, XM0
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM0, XM0
    vpxor XM1, XM0, XM0
    movdqu XM0, 144(ARG1)

    vshufps $0x4e, XM0, XM2, XM1
    vpslldq $8, XM1, XM2
    vpslldq $4, XM2, XM3
    vpxor  XM3, XM2, XM2
    vpermilps $0xff, XM0, XM3
    vpxor  XM3, XM2, XM2
    aeskeygenassist $0x40, XM2, XM3
    vpermilps $0xff, XM3, XM3
    vpsrldq $8, XM1, XM4
    vpslldq $12, XM4, XM4
    vpxor  XM4, XM1, XM1
    vpxor  XM3, XM1, XM1
    vshufps $0xee, XM1, XM2, XM2
    movdqu XM2, 160(ARG1)

    vshufps $0x4e, XM2, XM0, XM1
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM2, XM0
    vpxor XM1, XM0, XM0
    movdqu XM0, 176(ARG1)

    vshufps $0x4e, XM0, XM2, XM1
    aeskeygenassist $0x80, XM0, XM2
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM2, XM2
    vpxor XM1, XM2, XM2
    movdqu XM2, 192(ARG1)

    vpxor XM0, XM0, XM0
    vpxor XM1, XM1, XM1
    vpxor XM2, XM2, XM2
    vpxor XM3, XM3, XM3
    vpxor XM4, XM4, XM4

    ret
    .cfi_endproc
    .size SetEncryptKey192, .-SetEncryptKey192

/**
 *  Function description: Sets the AES decryption key. Key length: 192 bits.
 *  Function prototype: void SetDecryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key);
 *  Input register:
 *        x0：Pointer to the output key structure.
 *        x1：Pointer to the input key.
 *  Change register: xmm0-xmm5
 *  Output register: None.
 *  Function/Macro Call: None.
 */
     .globl SetDecryptKey192
    .type SetDecryptKey192, @function
SetDecryptKey192:
    .cfi_startproc

    movl $12, 240(ARG1)
    movdqu (ARG2), XM0
    movdqu 8(ARG2), XM1
    movdqu XM0, 192(ARG1)

    vpxor XM4, XM4, XM4
    vshufps $0x40, XM0, XM4, XM2
    aeskeygenassist $0x01, XM1, XM0
    vshufps $0xf0, XM0, XM4, XM0
    vpslldq $0x04, XM2, XM3
    vpxor XM3, XM2, XM2
    vpxor XM2, XM0, XM0
    vshufps $0xee, XM0, XM1, XM0
    aesimc  XM0, XM5
    movdqu XM5, 176(ARG1)

    movdqu XM1, XM2
    vpslldq $4, XM2, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpermilps $0xff, XM0, XM3
    vpxor XM3, XM2, XM2
    aesimc  XM2, XM5
    movdqu XM5, 160(ARG1)

    vshufps $0x4e, XM2, XM0, XM1
    aeskeygenassist $0x02, XM2, XM0
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM0, XM0
    vpxor XM1, XM0, XM0
    aesimc  XM0, XM5
    movdqu XM5, 144(ARG1)

    vshufps $0x4e, XM0, XM2, XM1
    vpslldq $8, XM1, XM2
    vpslldq $4, XM2, XM3
    vpxor  XM3, XM2, XM2
    vpermilps $0xff, XM0, XM3
    vpxor  XM3, XM2, XM2
    aeskeygenassist $0x04, XM2, XM3
    vpermilps $0xff, XM3, XM3
    vpsrldq $8, XM1, XM4
    vpslldq $12, XM4, XM4
    vpxor  XM4, XM1, XM1
    vpxor  XM3, XM1, XM1
    vshufps $0xee, XM1, XM2, XM2
    aesimc  XM2, XM5
    movdqu XM5, 128(ARG1)

    vshufps $0x4e, XM2, XM0, XM1
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM2, XM0
    vpxor XM1, XM0, XM0
    aesimc  XM0, XM5
    movdqu XM5,112(ARG1)

    vshufps $0x4e, XM0, XM2, XM1
    aeskeygenassist $0x08, XM0, XM2
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM2, XM2
    vpxor XM1, XM2, XM2
    aesimc  XM2, XM5
    movdqu XM5, 96(ARG1)

    vshufps $0x4e, XM2, XM0, XM1
    vpslldq $8, XM1, XM0
    vpslldq $4, XM0, XM3
    vpxor  XM3, XM0, XM0
    vpermilps $0xff, XM2, XM3
    vpxor  XM3, XM0, XM0
    aeskeygenassist $0x10, XM0, XM3
    vpermilps $0xff, XM3, XM3
    vpsrldq $8, XM1, XM4
    vpslldq $12, XM4, XM4
    vpxor  XM4, XM1, XM1
    vpxor  XM3, XM1, XM1
    vshufps $0xee, XM1, XM0, XM0
    aesimc  XM0, XM5
    movdqu XM5, 80(ARG1)

    vshufps $0x4e, XM0, XM2, XM1
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM0, XM2
    vpxor XM1, XM2, XM2
    aesimc  XM2, XM5
    movdqu XM5, 64(ARG1)

    vshufps $0x4e, XM2, XM0, XM1
    aeskeygenassist $0x20, XM2, XM0
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM0, XM0
    vpxor XM1, XM0, XM0
    aesimc  XM0, XM5
    movdqu XM5, 48(ARG1)

    vshufps $0x4e, XM0, XM2, XM1
    vpslldq $8, XM1, XM2
    vpslldq $4, XM2, XM3
    vpxor  XM3, XM2, XM2
    vpermilps $0xff, XM0, XM3
    vpxor  XM3, XM2, XM2
    aeskeygenassist $0x40, XM2, XM3
    vpermilps $0xff, XM3, XM3
    vpsrldq $8, XM1, XM4
    vpslldq $12, XM4, XM4
    vpxor  XM4, XM1, XM1
    vpxor  XM3, XM1, XM1
    vshufps $0xee, XM1, XM2, XM2
    aesimc  XM2, XM5
    movdqu XM5, 32(ARG1)

    vshufps $0x4e, XM2, XM0, XM1
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM2, XM0
    vpxor XM1, XM0, XM0
    aesimc  XM0, XM5
    movdqu XM5, 16(ARG1)

    vshufps $0x4e, XM0, XM2, XM1
    aeskeygenassist $0x80, XM0, XM2
    KEY_EXPANSION_HELPER_192 XM1, XM3
    vpermilps $0xff, XM2, XM2
    vpxor XM1, XM2, XM2
    movdqu XM2,(ARG1)

    vpxor XM0, XM0, XM0
    vpxor XM1, XM1, XM1
    vpxor XM2, XM2, XM2
    vpxor XM3, XM3, XM3
    vpxor XM4, XM4, XM4
    vpxor XM5, XM5, XM5

    ret
    .cfi_endproc
    .size SetDecryptKey192, .-SetDecryptKey192

/**
 *  Function description: Sets the AES encryption key. Key length: 192 bits.
 *  Function prototype: void SetEncryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key);
 *  Input register:
 *        x0：Pointer to the output key structure.
 *        x1：Pointer to the input key.
 *  Change register: xmm0-xmm3.
 *  Output register: None.
 *  Function/Macro Call: None.
 */
    .globl SetEncryptKey256
    .type SetEncryptKey256, @function
SetEncryptKey256:
    .cfi_startproc

    movl $14, 240(ARG1)
    movdqu (ARG2), XM0
    movdqu 16(ARG2), XM1
    movdqu XM0, (ARG1)
    movdqu XM1, 16(ARG1)

    aeskeygenassist $0x01, XM1, XM2
    vpermilps $0xff, XM2, XM2
    vpslldq $4, XM0, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpxor XM0, XM2, XM2
    movdqu XM2, 32(ARG1)

    aeskeygenassist $0x01, XM2, XM0
    vpermilps $0xAA, XM0, XM0
    vpslldq $4, XM1, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpxor XM1, XM0, XM0
    movdqu XM0, 48(ARG1)
    /*2*/
    aeskeygenassist $0x02, XM0, XM1
    vpermilps $0xff, XM1, XM1
    vpslldq $4, XM2, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpxor XM2, XM1, XM1
    movdqu XM1, 64(ARG1)

    aeskeygenassist $0x02, XM1, XM2
    vpermilps $0xAA, XM2, XM2
    vpslldq $4, XM0, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpxor XM0, XM2, XM2
    movdqu XM2, 80(ARG1)
    /*3*/
    aeskeygenassist $0x04, XM2, XM0
    vpermilps $0xff, XM0, XM0
    vpslldq $4, XM1, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpxor XM1, XM0, XM0
    movdqu XM0, 96(ARG1)

    aeskeygenassist $0x04, XM0, XM1
    vpermilps $0xAA, XM1, XM1
    vpslldq $4, XM2, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpxor XM2, XM1, XM1
    movdqu XM1, 112(ARG1)
    /*4*/
    aeskeygenassist $0x08, XM1, XM2
    vpermilps $0xff, XM2, XM2
    vpslldq $4, XM0, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpxor XM0, XM2, XM2
    movdqu XM2, 128(ARG1)

    aeskeygenassist $0x08, XM2, XM0
    vpermilps $0xAA, XM0, XM0
    vpslldq $4, XM1, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpxor XM1, XM0, XM0
    movdqu XM0, 144(ARG1)
    /*5*/
    aeskeygenassist $0x10, XM0, XM1
    vpermilps $0xff, XM1, XM1
    vpslldq $4, XM2, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpxor XM2, XM1, XM1
    movdqu XM1, 160(ARG1)

    aeskeygenassist $0x10, XM1, XM2
    vpermilps $0xAA, XM2, XM2
    vpslldq $4, XM0, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpxor XM0, XM2, XM2
    movdqu XM2, 176(ARG1)
    /*6*/
    aeskeygenassist $0x20, XM2, XM0
    vpermilps $0xff, XM0, XM0
    vpslldq $4, XM1, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpxor XM1, XM0, XM0
    movdqu XM0, 192(ARG1)

    aeskeygenassist $0x20, XM0, XM1
    vpermilps $0xAA, XM1, XM1
    vpslldq $4, XM2, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpxor XM2, XM1, XM1
    movdqu XM1, 208(ARG1)
    /*7*/
    aeskeygenassist $0x40, XM1, XM2
    vpermilps $0xff, XM2, XM2
    vpslldq $4, XM0, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpxor XM0, XM2, XM2
    movdqu XM2, 224(ARG1)

    vpxor XM0, XM0, XM0
    vpxor XM1, XM1, XM1
    vpxor XM2, XM2, XM2
    vpxor XM3, XM3, XM3

    ret
    .cfi_endproc
    .size SetEncryptKey256, .-SetEncryptKey256


 /**
 *  Function description: Sets the AES encryption key. Key length: 192 bits.
 *  Function prototype: void SetDecryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key);
 *  Input register:
 *        x0：Pointer to the output key structure.
 *        x1：Pointer to the input key.
 *  Change register: xmm0-xmm4.
 *  Output register: None.
 *  Function/Macro Call: None.
 */
     .globl SetDecryptKey256
    .type SetDecryptKey256, @function
SetDecryptKey256:
    .cfi_startproc

    movl $14, 240(ARG1)
    movdqu (ARG2), XM0
    movdqu 16(ARG2), XM1
    movdqu XM0, 224(ARG1)

    aesimc  XM1, XM4
    movdqu XM4, 208(ARG1)

    aeskeygenassist $0x01, XM1, XM2
    vpermilps $0xff, XM2, XM2
    vpslldq $4, XM0, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpxor XM0, XM2, XM2
    aesimc  XM2, XM4
    movdqu XM4, 192(ARG1)

    aeskeygenassist $0x01, XM2, XM0
    vpermilps $0xAA, XM0, XM0
    vpslldq $4, XM1, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpxor XM1, XM0, XM0
    aesimc  XM0, XM4
    movdqu XM4, 176(ARG1)
    /*2*/
    aeskeygenassist $0x02, XM0, XM1
    vpermilps $0xff, XM1, XM1
    vpslldq $4, XM2, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpxor XM2, XM1, XM1
    aesimc  XM1, XM4
    movdqu XM4, 160(ARG1)

    aeskeygenassist $0x02, XM1, XM2
    vpermilps $0xAA, XM2, XM2
    vpslldq $4, XM0, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpxor XM0, XM2, XM2
    aesimc  XM2, XM4
    movdqu XM4, 144(ARG1)
    /*3*/
    aeskeygenassist $0x04, XM2, XM0
    vpermilps $0xff, XM0, XM0
    vpslldq $4, XM1, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpxor XM1, XM0, XM0
    aesimc  XM0, XM4
    movdqu XM4, 128(ARG1)

    aeskeygenassist $0x04, XM0, XM1
    vpermilps $0xAA, XM1, XM1
    vpslldq $4, XM2, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpxor XM2, XM1, XM1
    aesimc  XM1, XM4
    movdqu XM4, 112(ARG1)
    /*4*/
    aeskeygenassist $0x08, XM1, XM2
    vpermilps $0xff, XM2, XM2
    vpslldq $4, XM0, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpxor XM0, XM2, XM2
    aesimc  XM2, XM4
    movdqu XM4, 96(ARG1)

    aeskeygenassist $0x08, XM2, XM0
    vpermilps $0xAA, XM0, XM0
    vpslldq $4, XM1, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpxor XM1, XM0, XM0
    aesimc  XM0, XM4
    movdqu XM4, 80(ARG1)
    /*5*/
    aeskeygenassist $0x10, XM0, XM1
    vpermilps $0xff, XM1, XM1
    vpslldq $4, XM2, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpxor XM2, XM1, XM1
    aesimc  XM1, XM4
    movdqu XM4, 64(ARG1)

    aeskeygenassist $0x10, XM1, XM2
    vpermilps $0xAA, XM2, XM2
    vpslldq $4, XM0, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpxor XM0, XM2, XM2
    aesimc  XM2, XM4
    movdqu XM4, 48(ARG1)
    /*6*/
    aeskeygenassist $0x20, XM2, XM0
    vpermilps $0xff, XM0, XM0
    vpslldq $4, XM1, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpslldq $4, XM3, XM3
    vpxor XM3, XM1, XM1
    vpxor XM1, XM0, XM0
    aesimc  XM0, XM4
    movdqu XM4, 32(ARG1)

    aeskeygenassist $0x20, XM0, XM1
    vpermilps $0xAA, XM1, XM1
    vpslldq $4, XM2, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpslldq $4, XM3, XM3
    vpxor XM3, XM2, XM2
    vpxor XM2, XM1, XM1
    aesimc  XM1, XM4
    movdqu XM4, 16(ARG1)
    /*7*/
    aeskeygenassist $0x40, XM1, XM2
    vpermilps $0xff, XM2, XM2
    vpslldq $4, XM0, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpslldq $4, XM3, XM3
    vpxor XM3, XM0, XM0
    vpxor XM0, XM2, XM2
    movdqu XM2, (ARG1)

    vpxor XM0, XM0, XM0
    vpxor XM1, XM1, XM1
    vpxor XM2, XM2, XM2
    vpxor XM3, XM3, XM3
    vpxor XM4, XM4, XM4

    ret
    .cfi_endproc
    .size SetDecryptKey256, .-SetDecryptKey256

/**
 *  Function description: This API is used to set the AES encryption assembly acceleration.
 *  Function prototype: int32_t CRYPT_AES_Encrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
 *  Input register:
 *        x0：Pointer to the input key structure.
 *        x1：Points to the 128-bit input data.
 *        x2：Points to the 128-bit output data.
 *        x3：Indicates the length of a data block, that is, 16 bytes.
 *  Change register: xmm0-xmm1.
 *  Output register: eax.
 *  Function/Macro Call: None.
 */
     .globl CRYPT_AES_Encrypt
    .type CRYPT_AES_Encrypt, @function
CRYPT_AES_Encrypt:
    .cfi_startproc
    .set    ROUNDS,%eax

    movdqu (ARG2), XM0
    movl 240(ARG1),ROUNDS

    vpxor (ARG1), XM0, XM0

    movdqu 16(ARG1), XM1
    aesenc  XM1, XM0

    movdqu 32(ARG1), XM1
    aesenc  XM1, XM0

    movdqu 48(ARG1), XM1
    aesenc  XM1, XM0

    movdqu 64(ARG1), XM1
    aesenc  XM1, XM0

    movdqu 80(ARG1), XM1
    aesenc  XM1, XM0

    movdqu 96(ARG1), XM1
    aesenc  XM1, XM0

    movdqu 112(ARG1), XM1
    aesenc  XM1, XM0

    movdqu 128(ARG1), XM1
    aesenc  XM1, XM0

    movdqu 144(ARG1), XM1
    aesenc  XM1, XM0

    cmpl $10,ROUNDS
    je  .Laesenc_128

    movdqu 160(ARG1), XM1
    aesenc  XM1, XM0

    movdqu 176(ARG1), XM1
    aesenc  XM1, XM0

    cmpl $12,ROUNDS
    je  .Laesenc_192

    movdqu 192(ARG1), XM1
    aesenc  XM1, XM0

    movdqu 208(ARG1), XM1
    aesenc  XM1, XM0

    cmpl $14,ROUNDS
    je  .Laesenc_256

.Laesenc_128:
    movdqu 160(ARG1), XM1
    aesenclast XM1, XM0
    jmp  .Laesenc_end

.Laesenc_192:
    movdqu 192(ARG1), XM1
    aesenclast XM1, XM0
    jmp  .Laesenc_end

.Laesenc_256:
    movdqu 224(ARG1), XM1
    aesenclast XM1, XM0

.Laesenc_end:
    vpxor XM1, XM1, XM1
    movdqu XM0,(ARG3)
    vpxor XM0, XM0, XM0
    movl $0,RET
    ret
    .cfi_endproc
    .size CRYPT_AES_Encrypt, .-CRYPT_AES_Encrypt

/**
 *  Function description: AES decryption and assembly acceleration API.
 *  Function prototype: int32_t CRYPT_AES_Decrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
 *  Input register:
 *        x0：Pointer to the input key structure.
 *        x1：Points to the 128-bit input data.
 *        x2：Points to the 128-bit output data.
 *        x3：Indicates the length of a data block, that is, 16 bytes.
 *  Change register: xmm0-xmm1.
 *  Output register: eax.
 *  Function/Macro Call: None.
 */
     .globl CRYPT_AES_Decrypt
    .type CRYPT_AES_Decrypt, @function
CRYPT_AES_Decrypt:
    .cfi_startproc
    .set    ROUNDS,%eax

    movdqu (ARG2), XM0
    movl 240(ARG1),ROUNDS
    vpxor (ARG1), XM0, XM0

    movdqu 16(ARG1), XM1
    aesdec  XM1, XM0

    movdqu 32(ARG1), XM1
    aesdec  XM1, XM0

    movdqu 48(ARG1), XM1
    aesdec  XM1, XM0

    movdqu 64(ARG1), XM1
    aesdec  XM1, XM0

    movdqu 80(ARG1), XM1
    aesdec  XM1, XM0

    movdqu 96(ARG1), XM1
    aesdec  XM1, XM0

    movdqu 112(ARG1), XM1
    aesdec  XM1, XM0

    movdqu 128(ARG1), XM1
    aesdec  XM1, XM0

    movdqu 144(ARG1), XM1
    aesdec  XM1, XM0

    cmpl $10,ROUNDS
    je  .aesdec_128

    movdqu 160(ARG1), XM1
    aesdec  XM1, XM0

    movdqu 176(ARG1), XM1
    aesdec  XM1, XM0

    cmpl $12,ROUNDS
    je  .aesdec_192

    movdqu 192(ARG1), XM1
    aesdec  XM1, XM0

    movdqu 208(ARG1), XM1
    aesdec  XM1, XM0

    cmpl $14,ROUNDS
    je  .aesdec_256

.aesdec_128:
    movdqu 160(ARG1), XM1
    aesdeclast XM1, XM0
    jmp  .aesdec_end

.aesdec_192:
    movdqu 192(ARG1), XM1
    aesdeclast XM1, XM0
    jmp  .aesdec_end

.aesdec_256:
    movdqu 224(ARG1), XM1
    aesdeclast XM1, XM0

.aesdec_end:

    vpxor XM1, XM1, XM1
    movdqu XM0,(ARG3)
    vpxor XM0, XM0, XM0
    movl $0,RET

    ret
    .cfi_endproc
    .size CRYPT_AES_Decrypt, .-CRYPT_AES_Decrypt

#endif
