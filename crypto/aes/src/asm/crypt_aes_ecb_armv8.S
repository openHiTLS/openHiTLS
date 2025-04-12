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

#include "crypt_arm.h"
#include "crypt_aes_macro_armv8.s"

.file    "crypt_aes_ecb_armv8.S"
.text
.arch    armv8-a+crypto

KEY     .req    x0
IN      .req    x1
OUT     .req    x2
LEN     .req    x3

KTMP    .req    x4
LTMP    .req    x9

ROUNDS  .req    w6

BLK0    .req    v0
BLK1    .req    v1
BLK2    .req    v2
BLK3    .req    v3
BLK4    .req    v4
BLK5    .req    v5
BLK6    .req    v6
BLK7    .req    v7

RDK0    .req    v17
RDK1    .req    v18

/*
 * Vn      -  V0 ~ V31
 * 8bytes  -  Vn.8B  Vn.4H  Vn.2S  Vn.1D
 * 16bytes -  Vn.16B Vn.8H  Vn.4S  Vn.2D
 *
 * In Return-oriented programming (ROP) and Jump-oriented programming (JOP), we explored features
 * that Arm introduced to the Arm architecture to mitigate against JOP-style and ROP-style attacks.
 * ...
 * Whether the combined or NOP-compatible instructions are generated depends on the architecture
 * version that the code is built for. When building for Armv8.3-A, or later, the compiler will use
 * the combined operations. When building for Armv8.2-A, or earlier, it will use the NOP compatible
 * instructions.
 * (https://developer.arm.com/documentation/102433/0100/Applying-these-techniques-to-real-code?lang=en)
 *
 * The paciasp and autiasp instructions are used for function pointer authentication. The pointer
 * authentication feature is added in armv8.3 and is supported only by AArch64.
 * The addition of pointer authentication features is described in Section A2.6.1 of
 * DDI0487H_a_a-profile_architecture_reference_manual.pdf.
 */

/**
 * Function description: Sets the AES encryption assembly acceleration interface in ECB mode.
 * int32_t CRYPT_AES_ECB_Encrypt(const CRYPT_AES_Key *ctx,
 *                              const uint8_t *in,
 *                              uint8_t *out,
 *                              uint32_t len);
 * Input register:
 *        x0: Pointer to the input key structure.
 *        x1: Points to the 128-bit input data.
 *        x2: Points to the 128-bit output data.
 *        x3: Indicates the length of a data block, that is, 16 bytes.
 *  Change register: x4, x6, x9, v0-v7, v17, v18.
 *  Output register: x0.
 *  Function/Macro Call: AES_ENC_8_BLKS, AES_ENC_1_BLK, AES_ENC_2_BLKS, AES_ENC_4_BLKS,
 *              AES_ENC_5_BLKS, AES_ENC_6_BLKS, AES_ENC_7_BLKS.
 */
.globl CRYPT_AES_ECB_Encrypt
.type CRYPT_AES_ECB_Encrypt, %function
CRYPT_AES_ECB_Encrypt:
AARCH64_PACIASP
    mov LTMP, LEN
.Lecb_aesenc_start:
    cmp LTMP, #64
    b.ge .Lecb_enc_above_equal_4_blks
    cmp LTMP, #32
    b.ge .Lecb_enc_above_equal_2_blks
    cmp LTMP, #0
    b.eq .Lecb_aesenc_finish
    b .Lecb_enc_proc_1_blk

.Lecb_enc_above_equal_2_blks:
    cmp LTMP, #48
    b.lt .Lecb_enc_proc_2_blks
    b .Lecb_enc_proc_3_blks

.Lecb_enc_above_equal_4_blks:
    cmp LTMP, #96
    b.ge .Lecb_enc_above_equal_6_blks
    cmp LTMP, #80
    b.lt .Lecb_enc_proc_4_blks
    b .Lecb_enc_proc_5_blks

.Lecb_enc_above_equal_6_blks:
    cmp LTMP, #112
    b.lt .Lecb_enc_proc_6_blks
    cmp LTMP, #128
    b.lt .Lecb_enc_proc_7_blks

.Lecb_enc_proc_8_blks:
.Lecb_aesenc_8_blks_loop:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [IN], #64
    mov KTMP, KEY
    AES_ENC_8_BLKS KTMP BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b \
                   BLK5.16b BLK6.16b BLK7.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [OUT], #64
    sub LTMP, LTMP, #128
    cmp LTMP, #128
    b.lt .Lecb_aesenc_start
    b .Lecb_aesenc_8_blks_loop

.Lecb_enc_proc_1_blk:
    ld1 {BLK0.16b}, [IN]
    AES_ENC_1_BLK KEY BLK0.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b}, [OUT]
    b .Lecb_aesenc_finish

.Lecb_enc_proc_2_blks:
    ld1 {BLK0.16b, BLK1.16b}, [IN]
    AES_ENC_2_BLKS KEY BLK0.16b BLK1.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b}, [OUT]
    b .Lecb_aesenc_finish

.Lecb_enc_proc_3_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b}, [IN]
    AES_ENC_3_BLKS KEY BLK0.16b BLK1.16b BLK2.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b}, [OUT]
    b .Lecb_aesenc_finish

.Lecb_enc_proc_4_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN]
    AES_ENC_4_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT]
    b .Lecb_aesenc_finish

.Lecb_enc_proc_5_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b}, [IN]
    AES_ENC_5_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b}, [OUT]
    b .Lecb_aesenc_finish

.Lecb_enc_proc_6_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b}, [IN]
    AES_ENC_6_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b BLK5.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b}, [OUT]
    b .Lecb_aesenc_finish

.Lecb_enc_proc_7_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b, BLK6.16b}, [IN]
    AES_ENC_7_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b BLK5.16b BLK6.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b, BLK6.16b}, [OUT]

.Lecb_aesenc_finish:
    mov x0, #0
    eor RDK0.16b, RDK0.16b, RDK0.16b
    eor RDK1.16b, RDK1.16b, RDK1.16b
AARCH64_AUTIASP
    ret
.size CRYPT_AES_ECB_Encrypt, .-CRYPT_AES_ECB_Encrypt


/**
 * Function description: Sets the AES decryption and assembly acceleration API in ECB mode.
 * int32_t CRYPT_AES_ECB_Decrypt(const CRYPT_AES_Key *ctx,
 *                              const uint8_t *in,
 *                              uint8_t *out,
 *                              uint32_t len);
 * Input register:
 *        x0: Pointer to the input key structure.
 *        x1: Points to the 128-bit input data.
 *        x2: Points to the 128-bit output data.
 *        x3: Indicates the length of a data block, that is, 16 bytes.
 *  Change register: x4, x6, x9, v0-v7, v17, v18
 *  Output register: x0
 *  Function/Macro Call: AES_DEC_8_BLKS, AES_DEC_1_BLK, AES_DEC_2_BLKS, AES_DEC_4_BLKS,
 *              AES_DEC_5_BLKS, AES_DEC_6_BLKS, AES_DEC_7_BLKS.
 */
.globl CRYPT_AES_ECB_Decrypt
.type CRYPT_AES_ECB_Decrypt, %function
CRYPT_AES_ECB_Decrypt:
AARCH64_PACIASP
    mov LTMP, LEN
.Lecb_aesdec_start:
    cmp LTMP, #64
    b.ge .Lecb_dec_above_equal_4_blks
    cmp LTMP, #32
    b.ge .Lecb_dec_above_equal_2_blks
    cmp LTMP, #0
    b.eq .Lecb_aesdec_finish
    b .Lecb_dec_proc_1_blk

.Lecb_dec_above_equal_2_blks:
    cmp LTMP, #48
    b.lt .Lecb_dec_proc_2_blks
    b .Lecb_dec_proc_3_blks

.Lecb_dec_above_equal_4_blks:
    cmp LTMP, #96
    b.ge .Lecb_dec_above_equal_6_blks
    cmp LTMP, #80
    b.lt .Lecb_dec_proc_4_blks
    b .Lecb_dec_proc_5_blks


.Lecb_dec_above_equal_6_blks:
    cmp LTMP, #112
    b.lt .Lecb_dec_proc_6_blks
    cmp LTMP, #128
    b.lt .Lecb_dec_proc_7_blks

.Lecb_dec_proc_8_blks:
.Lecb_aesdec_8_blks_loop:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [IN], #64
    mov KTMP, KEY
    AES_DEC_8_BLKS KTMP BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b \
                   BLK5.16b BLK6.16b BLK7.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [OUT], #64
    sub LTMP, LTMP, #128
    cmp LTMP, #128
    b.lt .Lecb_aesdec_start
    b .Lecb_aesdec_8_blks_loop

.Lecb_dec_proc_1_blk:
    ld1 {BLK0.16b}, [IN]
    AES_DEC_1_BLK KEY BLK0.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b}, [OUT]
    b .Lecb_aesdec_finish

.Lecb_dec_proc_2_blks:
    ld1 {BLK0.16b, BLK1.16b}, [IN]
    AES_DEC_2_BLKS KEY BLK0.16b BLK1.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b}, [OUT]
    b .Lecb_aesdec_finish

.Lecb_dec_proc_3_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b}, [IN]
    AES_DEC_3_BLKS KEY BLK0.16b BLK1.16b BLK2.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b}, [OUT]
    b .Lecb_aesdec_finish

.Lecb_dec_proc_4_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN]
    AES_DEC_4_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT]
    b .Lecb_aesdec_finish

.Lecb_dec_proc_5_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b}, [IN]
    AES_DEC_5_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b}, [OUT]
    b .Lecb_aesdec_finish

.Lecb_dec_proc_6_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b}, [IN]
    AES_DEC_6_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b BLK5.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b}, [OUT]
    b .Lecb_aesdec_finish

.Lecb_dec_proc_7_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b, BLK6.16b}, [IN]
    AES_DEC_7_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b BLK5.16b BLK6.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b, BLK6.16b}, [OUT]

.Lecb_aesdec_finish:
    mov x0, #0
    eor RDK0.16b, RDK0.16b, RDK0.16b
    eor RDK1.16b, RDK1.16b, RDK1.16b
AARCH64_AUTIASP
    ret
.size CRYPT_AES_ECB_Decrypt, .-CRYPT_AES_ECB_Decrypt

#endif
