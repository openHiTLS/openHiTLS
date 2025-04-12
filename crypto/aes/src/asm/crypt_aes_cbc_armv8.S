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

#include "crypt_arm.h"
#include "crypt_aes_macro_armv8.s"

.file    "crypt_aes_cbc_armv8.S"
.text
.arch	armv8-a+crypto

KEY     .req    x0
IN      .req    x1
OUT     .req    x2
LEN     .req    x3
P_IV    .req    x4

KTMP    .req    x5
ROUNDS  .req    w6

BLK0	.req	v0
BLK1	.req	v1
BLK2	.req	v2
BLK3	.req	v3
BLK4	.req	v4
BLK5	.req	v5
BLK6	.req	v6
BLK7	.req	v7

KEY0_END .req   v16
KEY0    .req    v17
KEY1    .req    v18
KEY2    .req    v19
KEY3    .req    v20
KEY4    .req    v21
KEY5    .req    v22
KEY6    .req    v23
KEY7    .req    v24
KEY8    .req    v25
KEY9    .req    v26
KEY10   .req    v27
KEY11   .req    v28
KEY12   .req    v29
KEY13   .req    v30
KEY14   .req    v31

IVENC	.req	v1
IV0		.req    v17
IV1		.req    v18
IV2		.req    v19
IV3		.req    v20
IV4		.req    v21
IV5		.req    v22
IV6		.req    v23
IV7		.req    v24
IVT		.req	v25

RDK0    .req    v26
RDK1    .req    v27
RDK2    .req    v28

/*
 * One round of encryption process.
 * block：input the plaintext.
 * key: One round key.
 */
.macro ROUND block, key
    aese \block, \key
    aesmc \block, \block
.endm

/*
 * Eight blocks of decryption.
 * block0_7：Input the ciphertext.
 * rdk0: Round key.
 * ktmp: Temporarily stores pointers to keys.
 */
.macro DEC8 rdk0s rdk0 blk0 blk1 blk2 blk3 blk4 blk5 blk6 blk7 ktmp
    aesd \blk0, \rdk0
    aesimc \blk0, \blk0
    aesd \blk5, \rdk0
    aesimc \blk5, \blk5
    aesd \blk1, \rdk0
    aesimc \blk1, \blk1
    aesd \blk6, \rdk0
    aesimc \blk6, \blk6
    aesd \blk2, \rdk0
    aesimc \blk2, \blk2
    aesd \blk3, \rdk0
    aesimc \blk3, \blk3
    aesd \blk4, \rdk0
    aesimc \blk4, \blk4
    aesd \blk7, \rdk0
    aesimc \blk7, \blk7
    ld1 {\rdk0s}, [\ktmp], #16
.endm

/**
 * Function description: AES encrypted assembly acceleration API in CBC mode.
 * int32_t CRYPT_AES_CBC_Encrypt(const CRYPT_AES_Key *ctx,
 *                          const uint8_t *in,
 *                          uint8_t *out,
 *                          uint32_t len,
 *                          uint8_t *iv);
 * Input register:
 *        x0：Pointer to the input key structure
 *        x1：points to the input data address
 *        x2：points to the output data address
 *        x3：Length of the input data, which must be a multiple of 16
 *        x4：Points to the CBC mode mask address
 * Change register：x5, x6, v0-v31
 * Output register：x0
 * Function/Macro Call: None
 */
.globl    CRYPT_AES_CBC_Encrypt
.type    CRYPT_AES_CBC_Encrypt, %function
CRYPT_AES_CBC_Encrypt:
AARCH64_PACIASP
    ld1 {IVENC.16b}, [P_IV]                    // load IV
    ldr w6, [KEY, #240]                      // load rounds
    ld1 {BLK0.16b}, [IN], #16                // load in
    ld1 {KEY0.4s, KEY1.4s}, [KEY], #32       // load keys
    cmp w6, #12
    ld1 {KEY2.4s, KEY3.4s}, [KEY], #32
    ld1 {KEY4.4s, KEY5.4s}, [KEY], #32
    ld1 {KEY6.4s, KEY7.4s}, [KEY], #32
    ld1 {KEY8.4s, KEY9.4s}, [KEY], #32
    eor IVENC.16b, IVENC.16b, BLK0.16b           // iv + in
    b.lt .Laes_cbc_128_start

    ld1 {KEY10.4s, KEY11.4s}, [KEY], #32
    b.eq .Laes_cbc_192_start
    ld1 {KEY12.4s, KEY13.4s}, [KEY], #32

.Laes_cbc_256_start:
    ld1 {KEY14.4s}, [KEY]
    ROUND IVENC.16b, KEY0.16b
    eor KEY0_END.16b, KEY0.16b, KEY14.16b   // key0 + keyEnd
    b .Laes_cbc_256_round_loop

.Laes_cbc_256_loop:
    ROUND IVENC.16b, KEY0.16b
    st1 {BLK0.16b}, [OUT], #16

.Laes_cbc_256_round_loop:
    ROUND IVENC.16b, KEY1.16b
    ROUND IVENC.16b, KEY2.16b
    subs LEN, LEN, #16
    ROUND IVENC.16b, KEY3.16b
    ROUND IVENC.16b, KEY4.16b
    ROUND IVENC.16b, KEY5.16b
    ld1 {KEY0.16b}, [IN], #16             // load IN
    ROUND IVENC.16b, KEY6.16b
    ROUND IVENC.16b, KEY7.16b
    ROUND IVENC.16b, KEY8.16b
    ROUND IVENC.16b, KEY9.16b
    ROUND IVENC.16b, KEY10.16b
    ROUND IVENC.16b, KEY11.16b
    ROUND IVENC.16b, KEY12.16b
    aese IVENC.16b, KEY13.16b
    eor KEY0.16b, KEY0.16b, KEY0_END.16b  // IN + KEY0 + KEYEND
    eor BLK0.16b, IVENC.16b, KEY14.16b
    b.gt .Laes_cbc_256_loop
    b .Lescbcenc_finish

.Laes_cbc_128_start:
    ld1 {KEY10.4s}, [KEY]
    ROUND IVENC.16b, KEY0.16b
    eor KEY0_END.16b, KEY0.16b, KEY10.16b      // key0 + keyEnd
    b .Laes_cbc_128_round_loop

.Laes_cbc_128_loop:
    ROUND IVENC.16b, KEY0.16b
    st1 {BLK0.16b}, [OUT], #16

.Laes_cbc_128_round_loop:
    ROUND IVENC.16b, KEY1.16b
    ROUND IVENC.16b, KEY2.16b
    subs LEN, LEN, #16
    ROUND IVENC.16b, KEY3.16b
    ROUND IVENC.16b, KEY4.16b
    ROUND IVENC.16b, KEY5.16b
    ld1 {KEY0.16b}, [IN], #16             // load IN
    ROUND IVENC.16b, KEY6.16b
    ROUND IVENC.16b, KEY7.16b
    ROUND IVENC.16b, KEY8.16b
    aese IVENC.16b, KEY9.16b
    eor KEY0.16b, KEY0.16b, KEY0_END.16b  // IN + KEY0 + KEYEND
    eor BLK0.16b, IVENC.16b, KEY10.16b      // enc OK
    b.gt .Laes_cbc_128_loop
    b .Lescbcenc_finish

.Laes_cbc_192_start:
    ld1 {KEY12.4s}, [KEY]
    ROUND IVENC.16b, KEY0.16b
    eor KEY0_END.16b, KEY0.16b, KEY12.16b   // key0 + keyEnd
    b .Laes_cbc_192_round_loop

.Laes_cbc_192_loop:
    ROUND IVENC.16b, KEY0.16b
    st1 {BLK0.16b}, [OUT], #16

.Laes_cbc_192_round_loop:
    ROUND IVENC.16b, KEY1.16b
    ROUND IVENC.16b, KEY2.16b
    subs LEN, LEN, #16
    ROUND IVENC.16b, KEY3.16b
    ROUND IVENC.16b, KEY4.16b
    ROUND IVENC.16b, KEY5.16b
    ld1 {KEY0.16b}, [IN], #16             // load IN
    ROUND IVENC.16b, KEY6.16b
    ROUND IVENC.16b, KEY7.16b
    ROUND IVENC.16b, KEY8.16b
    ROUND IVENC.16b, KEY9.16b
    ROUND IVENC.16b, KEY10.16b
    aese IVENC.16b, KEY11.16b
    eor KEY0.16b, KEY0.16b, KEY0_END.16b  // IN + KEY0 + KEYEND
    eor BLK0.16b, IVENC.16b, KEY12.16b
    b.gt .Laes_cbc_192_loop

.Lescbcenc_finish:
    st1 {BLK0.16b}, [OUT], #16
    st1 {BLK0.16b}, [P_IV]
    mov x0, #0
AARCH64_AUTIASP
    ret
.size CRYPT_AES_CBC_Encrypt, .-CRYPT_AES_CBC_Encrypt

/**
 * Function description: AES decryption and assembly acceleration API in CBC mode.
 * int32_t CRYPT_AES_CBC_Decrypt(const CRYPT_AES_Key *ctx,
 *                          const uint8_t *in,
 *                          uint8_t *out,
 *                          uint32_t len,
 *                          uint8_t *iv);
 * Input register：
 *        x0：pointer to the input key structure
 *        x1：points to the input data address
 *        x2：points to the output data address
 *        x3：Length of the input data, which must be a multiple of 16
 *        x4：Points to the CBC mode mask address
 * Change register：x5, x6, v0-v31
 * Output register：x0
 * Function/Macro Call: AES_DEC_8_BLKS, AES_DEC_1_BLK, AES_DEC_2_BLKS, AES_DEC_3_BLKS,
 *             AES_DEC_4_BLKS, AES_DEC_5_BLKS, AES_DEC_6_BLKS, AES_DEC_7_BLKS
 */
.globl	CRYPT_AES_CBC_Decrypt
.type	CRYPT_AES_CBC_Decrypt, %function
CRYPT_AES_CBC_Decrypt:
AARCH64_PACIASP
    ld1	{IV0.16b}, [P_IV]
.Lcbc_aesdec_start:
    cmp    LEN, #64
    b.ge      .Lcbc_dec_above_equal_4_blks
    cmp    LEN, #32
    b.ge      .Lcbc_dec_above_equal_2_blks
    cmp    LEN, #0
    b.eq      .Lcbc_aesdec_finish
    b     .Lcbc_dec_proc_1_blk

.Lcbc_dec_above_equal_2_blks:
    cmp    LEN, #48
    b.lt      .Lcbc_dec_proc_2_blks
    b     .Lcbc_dec_proc_3_blks

.Lcbc_dec_above_equal_4_blks:
    cmp    LEN, #96
    b.ge      .Lcbc_dec_above_equal_6_blks
    cmp    LEN, #80
    b.lt      .Lcbc_dec_proc_4_blks
    b     .Lcbc_dec_proc_5_blks

.Lcbc_dec_above_equal_6_blks:
    cmp    LEN, #112
    b.lt      .Lcbc_dec_proc_6_blks
    cmp    LEN, #128
    b.lt      .Lcbc_dec_proc_7_blks

.align	4
.Lcbc_aesdec_8_blks_loop:
    ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    mov KTMP, KEY
    ldr ROUNDS, [KEY, #240]
    ld1	{BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [IN], #64

    mov	IV1.16b, BLK0.16b
    mov	IV2.16b, BLK1.16b
    mov	IV3.16b, BLK2.16b
    ld1 {RDK0.4s, RDK1.4s}, [KTMP], #32
    mov	IV4.16b, BLK3.16b
    mov	IV5.16b, BLK4.16b
    mov	IV6.16b, BLK5.16b
    mov	IV7.16b, BLK6.16b
    mov	IVT.16b, BLK7.16b


    DEC8 RDK0.4s, RDK0.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP
    DEC8 RDK1.4s, RDK1.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP
    DEC8 RDK0.4s, RDK0.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP
    DEC8 RDK1.4s, RDK1.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP
    DEC8 RDK0.4s, RDK0.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP
    DEC8 RDK1.4s, RDK1.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP
    DEC8 RDK0.4s, RDK0.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP
    DEC8 RDK1.4s, RDK1.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP

    cmp ROUNDS, #12
    b.lt .Ldec_8_blks_last
    DEC8 RDK0.4s, RDK0.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP
    DEC8 RDK1.4s, RDK1.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP
    b.eq .Ldec_8_blks_last
    DEC8 RDK0.4s, RDK0.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP
    DEC8 RDK1.4s, RDK1.16b, BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b, BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b, KTMP

.Ldec_8_blks_last:
    ld1 {RDK2.4s}, [KTMP]
    aesd BLK0.16b, RDK0.16b
    aesimc BLK0.16b, BLK0.16b
    aesd BLK1.16b, RDK0.16b
    aesimc BLK1.16b, BLK1.16b
    aesd BLK2.16b, RDK0.16b
    aesimc BLK2.16b, BLK2.16b
    eor IV0.16b, IV0.16b, RDK2.16b
    aesd BLK3.16b, RDK0.16b
    aesimc BLK3.16b, BLK3.16b
    eor IV1.16b, IV1.16b, RDK2.16b
    aesd BLK4.16b, RDK0.16b
    aesimc BLK4.16b, BLK4.16b
    eor IV2.16b, IV2.16b, RDK2.16b
    aesd BLK5.16b, RDK0.16b
    aesimc BLK5.16b, BLK5.16b
    eor IV3.16b, IV3.16b, RDK2.16b
    aesd BLK6.16b, RDK0.16b
    aesimc BLK6.16b, BLK6.16b
    eor IV4.16b, IV4.16b, RDK2.16b
    aesd BLK7.16b, RDK0.16b
    aesimc BLK7.16b, BLK7.16b
    eor IV5.16b, IV5.16b, RDK2.16b

    aesd BLK0.16b, RDK1.16b
    aesd BLK1.16b, RDK1.16b
    eor IV6.16b, IV6.16b, RDK2.16b
    aesd BLK2.16b, RDK1.16b
    aesd BLK3.16b, RDK1.16b
    eor IV7.16b, IV7.16b, RDK2.16b
    aesd BLK4.16b, RDK1.16b
    aesd BLK5.16b, RDK1.16b
    aesd BLK6.16b, RDK1.16b
    aesd BLK7.16b, RDK1.16b

    sub	LEN, LEN, #128
    eor	BLK0.16b, BLK0.16b, IV0.16b
    eor	BLK1.16b, BLK1.16b, IV1.16b
    eor	BLK2.16b, BLK2.16b, IV2.16b
    eor	BLK3.16b, BLK3.16b, IV3.16b
    st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    eor	BLK4.16b, BLK4.16b, IV4.16b
    eor	BLK5.16b, BLK5.16b, IV5.16b
    cmp LEN, #0
    eor	BLK6.16b, BLK6.16b, IV6.16b
    eor	BLK7.16b, BLK7.16b, IV7.16b
    mov	IV0.16b, IVT.16b
    st1	{BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [OUT], #64
    b.eq  .Lcbc_aesdec_finish
    cmp LEN, #128
    b.lt    .Lcbc_aesdec_start
    b   .Lcbc_aesdec_8_blks_loop

.Lcbc_dec_proc_1_blk:
    ld1	{BLK0.16b}, [IN]
    AES_DEC_1_BLK KEY BLK0.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    eor	BLK0.16b, BLK0.16b, IV0.16b
    ld1	{IV0.16b}, [IN]
    st1	{BLK0.16b}, [OUT]
    b		.Lcbc_aesdec_finish

.Lcbc_dec_proc_2_blks:
    ld1	{BLK0.16b, BLK1.16b}, [IN]
    ld1	{IV1.16b}, [IN], #16
    AES_DEC_2_BLKS KEY BLK0.16b BLK1.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    eor	BLK0.16b, BLK0.16b, IV0.16b
    eor	BLK1.16b, BLK1.16b, IV1.16b
    ld1	{IV0.16b}, [IN]
    st1	{BLK0.16b, BLK1.16b}, [OUT]
    b		.Lcbc_aesdec_finish

.Lcbc_dec_proc_3_blks:
    ld1	{BLK0.16b, BLK1.16b, BLK2.16b}, [IN]
    ld1	{IV1.16b, IV2.16b}, [IN], #32
    AES_DEC_3_BLKS KEY BLK0.16b BLK1.16b BLK2.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    eor	BLK0.16b, BLK0.16b, IV0.16b
    eor	BLK1.16b, BLK1.16b, IV1.16b
    eor	BLK2.16b, BLK2.16b, IV2.16b
    ld1	{IV0.16b}, [IN]
    st1	{BLK0.16b, BLK1.16b, BLK2.16b}, [OUT]
    b		.Lcbc_aesdec_finish

.Lcbc_dec_proc_4_blks:
    ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN]
    ld1	{IV1.16b, IV2.16b, IV3.16b}, [IN], #48
    AES_DEC_4_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    eor	BLK0.16b, BLK0.16b, IV0.16b
    eor	BLK1.16b, BLK1.16b, IV1.16b
    eor	BLK2.16b, BLK2.16b, IV2.16b
    eor	BLK3.16b, BLK3.16b, IV3.16b
    ld1	{IV0.16b}, [IN]
    st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT]
    b		.Lcbc_aesdec_finish

.Lcbc_dec_proc_5_blks:
    ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN]
    ld1	{IV1.16b, IV2.16b, IV3.16b, IV4.16b}, [IN], #64
    ld1	{BLK4.16b}, [IN]
    AES_DEC_5_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    eor	BLK0.16b, BLK0.16b, IV0.16b
    eor	BLK1.16b, BLK1.16b, IV1.16b
    eor	BLK2.16b, BLK2.16b, IV2.16b
    eor	BLK3.16b, BLK3.16b, IV3.16b
    eor	BLK4.16b, BLK4.16b, IV4.16b
    ld1	{IV0.16b}, [IN]
    st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1	{BLK4.16b}, [OUT]
    b		.Lcbc_aesdec_finish

.Lcbc_dec_proc_6_blks:
    ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN]
    ld1	{IV1.16b, IV2.16b, IV3.16b, IV4.16b}, [IN], #64
    ld1	{BLK4.16b, BLK5.16b}, [IN]
    ld1	{IV5.16b}, [IN], #16
    AES_DEC_6_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b BLK5.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    eor	BLK0.16b, BLK0.16b, IV0.16b
    eor	BLK1.16b, BLK1.16b, IV1.16b
    eor	BLK2.16b, BLK2.16b, IV2.16b
    eor	BLK3.16b, BLK3.16b, IV3.16b
    eor	BLK4.16b, BLK4.16b, IV4.16b
    eor	BLK5.16b, BLK5.16b, IV5.16b
    ld1	{IV0.16b}, [IN]
    st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1	{BLK4.16b, BLK5.16b}, [OUT]
    b		.Lcbc_aesdec_finish

.Lcbc_dec_proc_7_blks:
    ld1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN]
    ld1	{IV1.16b, IV2.16b, IV3.16b, IV4.16b}, [IN], #64
    ld1	{BLK4.16b, BLK5.16b, BLK6.16b}, [IN]
    ld1	{IV5.16b, IV6.16b}, [IN], #32
    AES_DEC_7_BLKS KEY BLK0.16b BLK1.16b BLK2.16b BLK3.16b BLK4.16b BLK5.16b BLK6.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    eor	BLK0.16b, BLK0.16b, IV0.16b
    eor	BLK1.16b, BLK1.16b, IV1.16b
    eor	BLK2.16b, BLK2.16b, IV2.16b
    eor	BLK3.16b, BLK3.16b, IV3.16b
    eor	BLK4.16b, BLK4.16b, IV4.16b
    eor	BLK5.16b, BLK5.16b, IV5.16b
    eor	BLK6.16b, BLK6.16b, IV6.16b

    ld1	{IV0.16b}, [IN]
    st1	{BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1	{BLK4.16b, BLK5.16b, BLK6.16b}, [OUT]

.Lcbc_aesdec_finish:
    st1	{IV0.16b}, [P_IV]
    mov x0, #0
    eor RDK0.16b, RDK0.16b, RDK0.16b
    eor RDK1.16b, RDK1.16b, RDK1.16b
    eor RDK2.16b, RDK2.16b, RDK2.16b
AARCH64_AUTIASP
    ret
.size	CRYPT_AES_CBC_Decrypt, .-CRYPT_AES_CBC_Decrypt

#endif
