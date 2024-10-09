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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_ECB)

#include "crypt_aes_macro_x86_64.s"

.file   "crypt_aes_ecb_x86_64.S"
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
.set    BLK8, %xmm0
.set    BLK9, %xmm2
.set    BLK10, %xmm7
.set    BLK11, %xmm8
.set    BLK12, %xmm9
.set    BLK13, %xmm14


/**
 *  Function description: Sets the AES encryption assembly acceleration API in ECB mode.
 *  Function prototype: int32_t CRYPT_AES_ECB_Encrypt(const CRYPT_AES_Key *ctx,
 *                                       const uint8_t *in, uint8_t *out, uint32_t len);
 *  Input register:
 *        x0: Pointer to the input key structure.
 *        x1: Points to the 128-bit input data.
 *        x2: Points to the 128-bit output data.
 *        x3: Indicates the length of a data block, that is, 16 bytes.
 *  Change register: xmm1,xmm3,xmm4,xmm5,xmm6,xmm10,xmm11,xmm12,xmm13.
 *  Output register: eax.
 *  Function/Macro Call: None.
 */

.globl CRYPT_AES_ECB_Encrypt
    .type CRYPT_AES_ECB_Encrypt, @function
CRYPT_AES_ECB_Encrypt:
    .cfi_startproc
.align 16
.Lecb_aesenc_start:
    cmpl    $64, ARG4
    jae     .Lecb_enc_above_equal_4_blks
    cmpl    $32, ARG4
    jae     .Lecb_enc_above_equal_2_blks
    cmpl    $0, ARG4
    je      .Lecb_aesdec_finish
    jmp     .Lecb_enc_proc_1_blk

.Lecb_enc_above_equal_2_blks:
    cmpl    $48, ARG4
    jb      .Lecb_enc_proc_2_blks
    jmp     .Lecb_enc_proc_3_blks

.Lecb_enc_above_equal_4_blks:
    cmpl    $96, ARG4
    jae     .Lecb_enc_above_equal_6_blks
    cmpl    $80, ARG4
    jb      .Lecb_enc_proc_4_blks
    jmp     .Lecb_enc_proc_5_blks

.Lecb_enc_above_equal_6_blks:
    cmpl    $112, ARG4
    jb      .Lecb_enc_proc_6_blks
    cmpl    $128, ARG4
    jb      .Lecb_enc_proc_7_blks
    cmpl  $256, ARG4
    jbe     .Lecb_enc_proc_8_blks

.align 16
.ecb_enc_proc_14_blks:
.Lecb_aesenc_14_blks_loop:
    movq    KEY, KTMP
    vmovdqu (KEY), RDK
    movl 240(KEY), ROUNDS
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    vpxor 96(ARG2), RDK, BLK6
    vpxor 112(ARG2), RDK, BLK7
    vpxor 128(ARG2), RDK, BLK8
    vpxor 144(ARG2), RDK, BLK9
    vpxor 160(ARG2), RDK, BLK10
    vpxor 176(ARG2), RDK, BLK11
    vpxor 192(ARG2), RDK, BLK12
    vpxor 208(ARG2), RDK, BLK13
    decl ROUNDS
    AES_ENC_14_BLKS    ARG2 KTMP ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5 BLK6 BLK7 BLK8 BLK9 BLK10 BLK11 BLK12 BLK13
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    vmovdqu BLK6, 96(ARG3)
    vmovdqu BLK7, 112(ARG3)
    vmovdqu BLK8, 128(ARG3)
    vmovdqu BLK9, 144(ARG3)
    vmovdqu BLK10, 160(ARG3)
    vmovdqu BLK11, 176(ARG3)
    vmovdqu BLK12, 192(ARG3)
    vmovdqu BLK13, 208(ARG3)
    leaq 224(ARG2), ARG2
    leaq 224(ARG3), ARG3
    subl $224, ARG4
    cmpl    $224, ARG4
    jb  .Lecb_aesenc_start
    jmp  .Lecb_aesenc_14_blks_loop

.align 16
.Lecb_enc_proc_8_blks:
.Lecb_aesenc_8_blks_loop:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    movq    KEY, KTMP
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    vpxor 96(ARG2), RDK, BLK6
    vpxor 112(ARG2), RDK, BLK7
    decl ROUNDS
    AES_ENC_8_BLKS    KTMP ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5 BLK6 BLK7
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    vmovdqu BLK6, 96(ARG3)
    vmovdqu BLK7, 112(ARG3)
    leaq 128(ARG2), ARG2
    leaq 128(ARG3), ARG3
    subl $128, ARG4
    cmpl    $128, ARG4
    jb  .Lecb_aesenc_start
    jmp  .Lecb_aesenc_8_blks_loop

.align 16
.Lecb_enc_proc_1_blk:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    decl ROUNDS
    AES_ENC_1_BLK KEY ROUNDS RDK BLK0
    vmovdqu BLK0, (ARG3)
    jmp  .Lecb_aesenc_finish

.align 16
.Lecb_enc_proc_2_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    decl ROUNDS
    AES_ENC_2_BLKS    KEY ROUNDS RDK BLK0 BLK1
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    jmp  .Lecb_aesenc_finish

.align 16
.Lecb_enc_proc_3_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    decl ROUNDS
    AES_ENC_3_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    jmp  .Lecb_aesenc_finish

.align 16
.Lecb_enc_proc_4_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    decl ROUNDS
    AES_ENC_4_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    jmp  .Lecb_aesenc_finish

.align 16
.Lecb_enc_proc_5_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    decl ROUNDS
    AES_ENC_5_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    jmp  .Lecb_aesenc_finish

.align 16
.Lecb_enc_proc_6_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    decl ROUNDS
    AES_ENC_6_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    jmp  .Lecb_aesenc_finish

.align 16
.Lecb_enc_proc_7_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    vpxor 96(ARG2), RDK, BLK6
    decl ROUNDS
    AES_ENC_7_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5 BLK6
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    vmovdqu BLK6, 96(ARG3)

.align 16
.Lecb_aesenc_finish:
    vpxor RDK, RDK, RDK
    movl $0, RET
    ret
    .cfi_endproc
    .size CRYPT_AES_ECB_Encrypt, .-CRYPT_AES_ECB_Encrypt


/**
 *  Function description: Sets the AES decryption and assembly acceleration API in ECB mode.
 *  Function prototype: int32_t CRYPT_AES_ECB_Decrypt(const CRYPT_AES_Key *ctx,
 *                                              const uint8_t *in, uint8_t *out, uint32_t len);
 *  Input register:
 *        x0: Pointer to the input key structure.
 *        x1: Points to the 128-bit input data.
 *        x2: Indicates the 128-bit output data.
 *        x3: Indicates the length of a data block, that is, 16 bytes.
 *  Change register: xmm1,xmm3,xmm4,xmm5,xmm6,xmm10,xmm11,xmm12,xmm13.
 *  Output register: eax.
 *  Function/Macro Call: None.
 */
    .globl CRYPT_AES_ECB_Decrypt
    .type CRYPT_AES_ECB_Decrypt, @function
CRYPT_AES_ECB_Decrypt:
    .cfi_startproc
.align 16
.ecb_aesdec_start:
    cmpl    $64, ARG4
    jae     .ecb_dec_above_equal_4_blks
    cmpl    $32, ARG4
    jae     .ecb_dec_above_equal_2_blks
    cmpl    $0, ARG4
    je      .Lecb_aesdec_finish
    jmp     .ecb_dec_proc_1_blk
.ecb_dec_above_equal_2_blks:
    cmpl    $48, ARG4
    jb      .ecb_dec_proc_2_blks
    jmp     .ecb_dec_proc_3_blks

.ecb_dec_above_equal_4_blks:
    cmpl    $96, ARG4
    jae     .ecb_dec_above_equal_6_blks
    cmpl    $80, ARG4
    jb      .ecb_dec_proc_4_blks
    jmp     .ecb_dec_proc_5_blks

.ecb_dec_above_equal_6_blks:
    cmpl    $112, ARG4
    jb      .ecb_dec_proc_6_blks
    cmpl    $128, ARG4
    jb      .ecb_dec_proc_7_blks
    cmpl  $256, ARG4
    jbe      .ecb_dec_proc_8_blks

.align 16
.ecb_dec_proc_14_blks:
.ecb_aesdec_14_blks_loop:
    movq    KEY, KTMP
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    vpxor 96(ARG2), RDK, BLK6
    vpxor 112(ARG2), RDK, BLK7
    vpxor 128(ARG2), RDK, BLK8
    vpxor 144(ARG2), RDK, BLK9
    vpxor 160(ARG2), RDK, BLK10
    vpxor 176(ARG2), RDK, BLK11
    vpxor 192(ARG2), RDK, BLK12
    vpxor 208(ARG2), RDK, BLK13
    decl ROUNDS
    AES_DEC_14_BLKS    KTMP ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5 BLK6 BLK7 BLK8 BLK9 BLK10 BLK11 BLK12 BLK13
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    vmovdqu BLK6, 96(ARG3)
    vmovdqu BLK7, 112(ARG3)
    vmovdqu BLK8, 128(ARG3)
    vmovdqu BLK9, 144(ARG3)
    vmovdqu BLK10, 160(ARG3)
    vmovdqu BLK11, 176(ARG3)
    vmovdqu BLK12, 192(ARG3)
    vmovdqu BLK13, 208(ARG3)
    leaq 224(ARG2), ARG2
    leaq 224(ARG3), ARG3
    subl $224, ARG4
    cmpl    $224, ARG4
    jb  .ecb_aesdec_start
    jmp  .ecb_aesdec_14_blks_loop

.align 16
.ecb_dec_proc_8_blks:
.aesecbdec_8_blks_loop:
    movq    KEY, KTMP
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    vpxor 96(ARG2), RDK, BLK6
    vpxor 112(ARG2), RDK, BLK7
    decl ROUNDS
    AES_DEC_8_BLKS    KTMP ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5 BLK6 BLK7
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    vmovdqu BLK6, 96(ARG3)
    vmovdqu BLK7, 112(ARG3)
    leaq 128(ARG2), ARG2
    leaq 128(ARG3), ARG3
    subl $128, ARG4
    cmpl    $128, ARG4
    jb  .ecb_aesdec_start
    jmp .aesecbdec_8_blks_loop

.align 16
.ecb_dec_proc_1_blk:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    decl ROUNDS
    AES_DEC_1_BLK    KEY ROUNDS RDK BLK0
    vmovdqu BLK0, (ARG3)
    jmp  .Lecb_aesdec_finish

.align 16
.ecb_dec_proc_2_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    decl ROUNDS
    AES_DEC_2_BLKS    KEY ROUNDS RDK BLK0 BLK1
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    jmp  .Lecb_aesdec_finish

.align 16
.ecb_dec_proc_3_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    decl ROUNDS
    AES_DEC_3_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    jmp  .Lecb_aesdec_finish

.align 16
.ecb_dec_proc_4_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    decl ROUNDS
    AES_DEC_4_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    jmp  .Lecb_aesdec_finish

.align 16
.ecb_dec_proc_5_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    decl ROUNDS
    AES_DEC_5_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    jmp  .Lecb_aesdec_finish

.align 16
.ecb_dec_proc_6_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    decl ROUNDS
    AES_DEC_6_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    jmp  .Lecb_aesdec_finish

.align 16
.ecb_dec_proc_7_blks:
    movl 240(KEY), ROUNDS
    vmovdqu (KEY), RDK
    vpxor (ARG2), RDK, BLK0
    vpxor 16(ARG2), RDK, BLK1
    vpxor 32(ARG2), RDK, BLK2
    vpxor 48(ARG2), RDK, BLK3
    vpxor 64(ARG2), RDK, BLK4
    vpxor 80(ARG2), RDK, BLK5
    vpxor 96(ARG2), RDK, BLK6
    decl ROUNDS
    AES_DEC_7_BLKS    KEY ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4 BLK5 BLK6
    vmovdqu BLK0, (ARG3)
    vmovdqu BLK1, 16(ARG3)
    vmovdqu BLK2, 32(ARG3)
    vmovdqu BLK3, 48(ARG3)
    vmovdqu BLK4, 64(ARG3)
    vmovdqu BLK5, 80(ARG3)
    vmovdqu BLK6, 96(ARG3)

.align 16
.Lecb_aesdec_finish:
    vpxor BLK0, BLK0, BLK0
    vpxor BLK1, BLK1, BLK1
    vpxor BLK2, BLK2, BLK2
    vpxor BLK3, BLK3, BLK3
    vpxor BLK4, BLK4, BLK4
    vpxor BLK5, BLK5, BLK5
    vpxor BLK6, BLK6, BLK6
    vpxor BLK7, BLK7, BLK7
    vpxor BLK8, BLK8, BLK8
    vpxor BLK9, BLK9, BLK9
    vpxor BLK10, BLK10, BLK10
    vpxor BLK11, BLK11, BLK11
    vpxor BLK12, BLK12, BLK12
    vpxor BLK13, BLK13, BLK13
    vpxor RDK, RDK, RDK
    movl $0, RET
    ret
    .cfi_endproc
    .size CRYPT_AES_ECB_Decrypt, .-CRYPT_AES_ECB_Decrypt

#endif
