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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CBC)

#include "crypt_aes_macro_x86_64.s"

.file   "crypt_aes_cbc_x86_64.S"
.text

.set    ARG1, %rdi
.set    ARG2, %rsi
.set    ARG3, %rdx
.set    ARG4, %ecx
.set    ARG5, %r8
.set    ARG6, %r9

.set    RDK, %xmm3
.set    KEY, %rdi
.set    KTMP, %r9
.set    ROUNDS, %eax
.set    RET, %eax

.set    BLK0, %xmm1
.set    BLK1, %xmm4
.set    BLK2, %xmm5
.set    BLK3, %xmm6
.set    BLK4, %xmm10
.set    BLK5, %xmm11
.set    BLK6, %xmm12
.set    BLK7, %xmm13
.set    IV0, %xmm0
.set    IV1, %xmm7
.set    IV2, %xmm8
.set    IV3, %xmm9

.set    KEY1, %xmm4
.set    KEY2, %xmm5
.set    KEY3, %xmm6
.set    KEY4, %xmm10
.set    KEY5, %xmm11
.set    KEY6, %xmm12
.set    KEY7, %xmm13
.set    KEY8, %xmm14
.set    KEY9, %xmm15
.set    KEY10, %xmm2
.set    KEY11, %xmm7
.set    KEY12, %xmm8
.set    KEY13, %xmm9
.set    KEYTEMP, %xmm3

/**
 *  Function description：AES encrypted assembly acceleration API in CBC mode.
 *  Function prototype：int32_t CRYPT_AES_CBC_Encrypt(const CRYPT_AES_Key *ctx,
 *                      const uint8_t *in,
 *                      uint8_t *out,
 *                      uint32_t len,
 *                      uint8_t *iv);
 *  Input register：
 *        rdi：pointer to the input key structure
 *        rsi：points to the input data address
 *        rdx：points to the output data address
 *        rcx：Length of the input data, which must be a multiple of 16
 *        r8： Points to the CBC mode mask address
 *  Change register：xmm0-xmm15
 *  Output register：eax
 *  Function/Macro Call: None
 */
    .globl CRYPT_AES_CBC_Encrypt
    .type CRYPT_AES_CBC_Encrypt, @function
CRYPT_AES_CBC_Encrypt:
    .cfi_startproc
    .align 16
    cmpl  $16, ARG4
    jb .Laescbcend_end
    movl 240(KEY), ROUNDS
    vmovdqu (ARG5), IV0
    vmovdqu  (KEY), KEY1
    vmovdqu  16(KEY), KEY2
    vmovdqu  32(KEY), KEY3
    vmovdqu  48(KEY), KEY4
    vmovdqu  64(KEY), KEY5
    vmovdqu  80(KEY), KEY6
    vmovdqu  96(KEY), KEY7
    vmovdqu  112(KEY), KEY8
    vmovdqu  128(KEY), KEY9
    vmovdqu  144(KEY), KEY10
    vmovdqu 160(KEY), KEY11
    cmpl $12, ROUNDS
    jb  .Laes_128_cbc_start
    je  .Laes_192_cbc_start
.align 16
.Laes_256_cbc_start:
    vmovdqu 176(KEY), KEY12
    vmovdqu 192(KEY), KEY13
.Laes_256_cbc_loop:
    vpxor (ARG2), IV0, BLK0
    vmovdqu 208(KEY), KEYTEMP
    vpxor BLK0, KEY1, BLK0
    aesenc  KEY2, BLK0
    aesenc  KEY3, BLK0
    aesenc  KEY4, BLK0
    aesenc  KEY5, BLK0
    aesenc  KEY6, BLK0
    aesenc  KEY7, BLK0
    aesenc  KEY8, BLK0
    aesenc  KEY9, BLK0
    aesenc  KEY10, BLK0
    aesenc  KEY11, BLK0
    aesenc  KEY12, BLK0
    aesenc  KEY13, BLK0
    aesenc  KEYTEMP, BLK0
    vmovdqu 224(KEY), KEYTEMP
    aesenclast KEYTEMP, BLK0
    leaq 16(ARG2), ARG2
    vmovdqu BLK0, (ARG3)
    movdqa BLK0,  IV0
    leaq 16(ARG3), ARG3
    subl $16, ARG4
    cmpl $16, ARG4
    jnb .Laes_256_cbc_loop   // Special value processing
    vpxor KEY12, KEY12, KEY12
    vpxor  KEY13, KEY13, KEY13
    vpxor KEYTEMP, KEYTEMP, KEYTEMP
    jmp .Laescbcenc_finish

.align 16
.Laes_192_cbc_start:
    vmovdqu 176(KEY), KEY12
    vmovdqu 192(KEY), KEY13
.Laes_192_cbc_loop:
    vpxor (ARG2), IV0, BLK0
    vpxor BLK0, KEY1, BLK0
    aesenc  KEY2, BLK0
    aesenc  KEY3, BLK0
    aesenc  KEY4, BLK0
    aesenc  KEY5, BLK0
    aesenc  KEY6, BLK0
    aesenc  KEY7, BLK0
    aesenc  KEY8, BLK0
    aesenc  KEY9, BLK0
    aesenc  KEY10, BLK0
    aesenc  KEY11, BLK0
    aesenc  KEY12, BLK0
    aesenclast KEY13, BLK0
    leaq 16(ARG2),  ARG2
    vmovdqu BLK0,  (ARG3)
    movdqa BLK0,  IV0
    leaq 16(ARG3), ARG3
    subl $16 , ARG4
    jnz .Laes_192_cbc_loop
    vpxor KEY12, KEY12, KEY12
    vpxor KEY13, KEY13, KEY13
    jmp .Laescbcenc_finish

.align 16
.Laes_128_cbc_start:
    vpxor (ARG2), IV0, BLK0
    vpxor BLK0, KEY1, BLK0
    aesenc  KEY2, BLK0
    aesenc  KEY3, BLK0
    aesenc  KEY4, BLK0
    aesenc  KEY5, BLK0
    aesenc  KEY6, BLK0
    aesenc  KEY7, BLK0
    aesenc  KEY8, BLK0
    aesenc  KEY9, BLK0
    aesenc  KEY10, BLK0
    aesenclast KEY11, BLK0
    leaq 16(ARG2), ARG2
    vmovdqu BLK0, (ARG3)
    movdqa BLK0, IV0
    leaq 16(ARG3), ARG3
    subl $16, ARG4
    jnz .Laes_128_cbc_start
    jmp .Laescbcenc_finish

.Laescbcenc_finish:
    vmovdqu BLK0,(ARG5)
    vpxor KEY1, KEY1, KEY1
    vpxor KEY2, KEY2, KEY2
    vpxor KEY3, KEY3, KEY3
    vpxor KEY4, KEY4, KEY4
    vpxor KEY5, KEY5, KEY5
    vpxor KEY6, KEY6, KEY6
    vpxor KEY7, KEY7, KEY7
    vpxor KEY8, KEY8, KEY8
    vpxor KEY9, KEY9, KEY9
    vpxor KEY10, KEY10, KEY10
    vpxor KEY11, KEY11, KEY11
.Laescbcend_end:
    movl $0, RET
    ret
    .cfi_endproc
    .size CRYPT_AES_CBC_Encrypt, .-CRYPT_AES_CBC_Encrypt

/**
 *  Function description: Sets the AES decryption and assembly accelerated implementation interface in CBC mode
 *  Function prototype：int32_t CRYPT_AES_CBC_Decrypt(const CRYPT_AES_Key *ctx,
 *                      const uint8_t *in,
 *                      uint8_t *out,
 *                      uint32_t len,
 *                      uint8_t *iv);
 *  Input register:
 *        rdi：pointer to the input key structure
 *        rsi：points to the input data address.
 *        rdx：points to the output data address.
 *        rcx：Length of the input data, which must be a multiple of 16
 *        r8： Points to the CBC mode mask address
 *  Change register：xmm0-xmm13
 *  Output register：eax
 *  Function/Macro Call: None
 */
    .globl CRYPT_AES_CBC_Decrypt
    .type CRYPT_AES_CBC_Decrypt, @function
CRYPT_AES_CBC_Decrypt:
    .cfi_startproc
.align 16
    vmovdqu (ARG5), IV0
.Laes_cbc_dec_start:
    cmpl    $64, ARG4
    jae     .Labove_equal_4_blks
    cmpl    $32, ARG4
    jae     .Labove_equal_2_blks
    cmpl    $0, ARG4
    je      .Laes_cbc_dec_finish
    jmp     .Lproc_1_blk

.Labove_equal_2_blks:
    cmpl    $48, ARG4
    jb      .Lproc_2_blks
    jmp     .Lproc_3_blks

.Labove_equal_4_blks:
    cmpl    $96, ARG4
    jae     .Labove_equal_6_blks
    cmpl    $80, ARG4
    jb      .Lproc_4_blks
    jmp     .Lproc_5_blks

.Labove_equal_6_blks:
    cmpl    $112, ARG4
    jb      .Lproc_6_blks
    cmpl    $128, ARG4
    jb      .Lproc_7_blks

.align 16
.Lproc_8_blks:
.Laescbcdec_8_blks_loop:
    vmovdqu (ARG2), BLK0
    vmovdqu 16(ARG2), BLK1
    vmovdqu 32(ARG2), BLK2
    movdqa BLK0, IV1
    movdqa BLK1, IV2
    movdqa BLK2, IV3
    movq    KEY, KTMP
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor BLK0, RDK, BLK0
    vpxor BLK1, RDK, BLK1
    vpxor BLK2, RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    vpxor 96(ARG2), RDK, BLK6
    vpxor 112(ARG2), RDK, BLK7
    decl ROUNDS
    AES_DEC_8_BLKS    KTMP ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5 BLK6 BLK7
    vpxor BLK0, IV0, BLK0
    vpxor BLK1, IV1, BLK1
    vpxor BLK2, IV2, BLK2
    vpxor BLK3, IV3, BLK3
    vpxor 48(ARG2), BLK4, BLK4
    vpxor 64(ARG2), BLK5, BLK5
    vpxor 80(ARG2), BLK6, BLK6
    vpxor 96(ARG2), BLK7, BLK7
    vmovdqu 112(ARG2), IV0
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    vmovdqu BLK6, 96(ARG3)
    vmovdqu BLK7, 112(ARG3)
    subl $128, ARG4
    leaq 128(ARG2), ARG2
    leaq 128(ARG3), ARG3
    cmpl    $128, ARG4
    jb  .Laes_cbc_dec_start
    jmp .Laescbcdec_8_blks_loop

.align 16
.Lproc_1_blk:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    decl ROUNDS
    AES_DEC_1_BLK    KEY ROUNDS RDK BLK0
    vpxor BLK0, IV0, BLK0
    vmovdqu (ARG2), IV0
    vmovdqu BLK0, (ARG3)
    jmp  .Laes_cbc_dec_finish

.align 16
.Lproc_2_blks:
    vmovdqu (ARG2), BLK0
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    movdqa BLK0, IV1
    vpxor BLK0, RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    decl ROUNDS
    AES_DEC_2_BLKS    KEY ROUNDS RDK BLK0 BLK1
    vpxor BLK0, IV0, BLK0
    vpxor BLK1, IV1, BLK1
    vmovdqu 16(ARG2), IV0
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    jmp  .Laes_cbc_dec_finish

.align 16
.Lproc_3_blks:
    vmovdqu (ARG2), BLK0
    vmovdqu 16(ARG2), BLK1
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    movdqa BLK0, IV1
    movdqa BLK1, IV2
    vpxor BLK0, RDK, BLK0
    vpxor BLK1, RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    decl ROUNDS
    AES_DEC_3_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2
    vpxor BLK0, IV0, BLK0
    vpxor BLK1, IV1, BLK1
    vpxor BLK2, IV2, BLK2
    vmovdqu 32(ARG2), IV0
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    jmp  .Laes_cbc_dec_finish

.align 16
.Lproc_4_blks:
    vmovdqu (ARG2), BLK0
    vmovdqu 16(ARG2), BLK1
    vmovdqu 32(ARG2), BLK2
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    movdqa BLK0, IV1
    movdqa BLK1, IV2
    movdqa BLK2, IV3
    vpxor BLK0, RDK, BLK0
    vpxor BLK1, RDK, BLK1
    vpxor BLK2, RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    decl ROUNDS
    AES_DEC_4_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3
    vpxor BLK0, IV0, BLK0
    vpxor BLK1, IV1, BLK1
    vpxor BLK2, IV2, BLK2
    vpxor BLK3, IV3, BLK3
    vmovdqu 48(ARG2), IV0
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    jmp  .Laes_cbc_dec_finish

.align 16
.Lproc_5_blks:
    vmovdqu (ARG2), BLK0
    vmovdqu 16(ARG2), BLK1
    vmovdqu 32(ARG2), BLK2
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    movdqa BLK0, IV1
    movdqa BLK1, IV2
    movdqa BLK2, IV3
    vpxor BLK0, RDK, BLK0
    vpxor BLK1, RDK, BLK1
    vpxor BLK2, RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    decl ROUNDS
    AES_DEC_5_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4
    vpxor BLK0, IV0, BLK0
    vpxor BLK1, IV1, BLK1
    vpxor BLK2, IV2, BLK2
    vpxor BLK3, IV3, BLK3
    vpxor 48(ARG2), BLK4, BLK4
    vmovdqu 64(ARG2), IV0
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    jmp  .Laes_cbc_dec_finish

.align 16
.Lproc_6_blks:
    vmovdqu (ARG2), BLK0
    vmovdqu 16(ARG2), BLK1
    vmovdqu 32(ARG2), BLK2
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    movdqa BLK0, IV1
    movdqa BLK1, IV2
    movdqa BLK2, IV3
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    decl ROUNDS
    AES_DEC_6_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5
    vpxor BLK0, IV0, BLK0
    vpxor BLK1, IV1, BLK1
    vpxor BLK2, IV2, BLK2
    vpxor BLK3, IV3, BLK3
    vpxor 48(ARG2), BLK4, BLK4
    vpxor 64(ARG2), BLK5, BLK5
    vmovdqu 80(ARG2), IV0
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    jmp  .Laes_cbc_dec_finish

.align 16
.Lproc_7_blks:
    vmovdqu (ARG2), BLK0
    vmovdqu 16(ARG2), BLK1
    vmovdqu 32(ARG2), BLK2
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    movdqa BLK0, IV1
    movdqa BLK1, IV2
    movdqa BLK2, IV3
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    vpxor 96(ARG2), RDK, BLK6
    decl ROUNDS
    AES_DEC_7_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5 BLK6
    vpxor BLK0, IV0, BLK0
    vpxor BLK1, IV1, BLK1
    vpxor BLK2, IV2, BLK2
    vpxor BLK3, IV3, BLK3
    vpxor 48(ARG2), BLK4, BLK4
    vpxor 64(ARG2), BLK5, BLK5
    vpxor 80(ARG2), BLK6, BLK6
    vmovdqu 96(ARG2), IV0
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    vmovdqu BLK6, 96(ARG3)

.align 16
.Laes_cbc_dec_finish:
    vmovdqu IV0, (ARG5)
    vpxor BLK0, BLK0, BLK0
    vpxor BLK1, BLK1, BLK1
    vpxor BLK2, BLK2, BLK2
    vpxor BLK3, BLK3, BLK3
    vpxor BLK4, BLK4, BLK4
    vpxor BLK5, BLK5, BLK5
    vpxor BLK6, BLK6, BLK6
    vpxor BLK7, BLK7, BLK7
    vpxor RDK, RDK, RDK
    movl $0, RET
    ret
    .cfi_endproc
    .size CRYPT_AES_CBC_Decrypt,  .-CRYPT_AES_CBC_Decrypt

#endif
