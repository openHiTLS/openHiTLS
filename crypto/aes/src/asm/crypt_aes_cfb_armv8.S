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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CFB)

#include "crypt_arm.h"
#include "crypt_aes_macro_armv8.s"

.file    "crypt_aes_cfb_armv8.S"
.text
.arch    armv8-a+crypto

.align   5

KEY     .req    x0
IN      .req    x1
OUT     .req    x2
LEN     .req    x3
IV      .req    x4

LTMP    .req    x12

IVC	    .req    v19
CT1	    .req    v20
CT2	    .req    v21
CT3	    .req    v22
CT4	    .req    v23
CT5	    .req    v24
CT6	    .req    v25
CT7	    .req    v26
CT8     .req    v27

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
ROUNDS  .req    w6

/*
 * int32_t CRYPT_AES_CFB_Decrypt(const CRYPT_AES_Key *ctx,
 *                              const uint8_t *in,
 *                              uint8_t *out,
 *                              uint32_t len,
 *                              uint8_t *iv);
 */

.globl CRYPT_AES_CFB_Decrypt
.type CRYPT_AES_CFB_Decrypt, %function
CRYPT_AES_CFB_Decrypt:
AARCH64_PACIASP
    ld1	{IVC.16b}, [IV]              // Load the IV
    mov LTMP, LEN

.Lcfb_aesdec_start:
    cmp LTMP, #64
    b.ge .Lcfb_dec_above_equal_4_blks
    cmp LTMP, #32
    b.ge .Lcfb_dec_above_equal_2_blks
    cmp LTMP, #0
    b.eq .Lcfb_len_zero
    b .Lcfb_dec_proc_1_blk

.Lcfb_dec_above_equal_2_blks:
    cmp LTMP, #48
    b.lt .Lcfb_dec_proc_2_blks
    b .Lcfb_dec_proc_3_blks

.Lcfb_dec_above_equal_4_blks:
    cmp LTMP, #96
    b.ge .Lcfb_dec_above_equal_6_blks
    cmp LTMP, #80
    b.lt .Lcfb_dec_proc_4_blks
    b .Lcfb_dec_proc_5_blks

.Lcfb_dec_above_equal_6_blks:
    cmp LTMP, #112
    b.lt .Lcfb_dec_proc_6_blks
    cmp LTMP, #128
    b.lt .Lcfb_dec_proc_7_blks

.Lcfb_dec_proc_8_blks:

/* When the length is greater than or equal to 128, eight blocks loop is used */
.Lcfb_aesdec_8_blks_loop:

    /* Compute 8 CBF Decryption */
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [IN], #64

    mov	CT1.16b, IVC.16b // Prevent the IV or BLK from being changed
    mov	CT2.16b, BLK0.16b
    mov	CT3.16b, BLK1.16b
    mov	CT4.16b, BLK2.16b
    mov	CT5.16b, BLK3.16b
    mov	CT6.16b, BLK4.16b
    mov	CT7.16b, BLK5.16b
    mov	CT8.16b, BLK6.16b

    mov x14, KEY // Prevent the key from being changed
    AES_ENC_8_BLKS  x14 CT1.16b CT2.16b CT3.16b CT4.16b CT5.16b \
        CT6.16b CT7.16b CT8.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS


    mov	IVC.16b, BLK7.16b // Prepares for the next loop or update

    eor BLK0.16b, BLK0.16b, CT1.16b
    eor BLK1.16b, BLK1.16b, CT2.16b
    eor BLK2.16b, BLK2.16b, CT3.16b
    eor BLK3.16b, BLK3.16b, CT4.16b
    eor BLK4.16b, BLK4.16b, CT5.16b
    eor BLK5.16b, BLK5.16b, CT6.16b
    eor BLK6.16b, BLK6.16b, CT7.16b
    eor BLK7.16b, BLK7.16b, CT8.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [OUT], #64

    sub LTMP, LTMP, #128
    cmp LTMP, #0
    b.eq .Lcfb_aesdec_finish

    cmp LTMP, #128
    b.lt .Lcfb_aesdec_start
    b .Lcfb_aesdec_8_blks_loop

.Lcfb_dec_proc_1_blk:
    ld1 {BLK0.16b}, [IN]
    mov	CT1.16b, IVC.16b

    AES_ENC_1_BLK KEY CT1.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    mov	IVC.16b, BLK0.16b
    eor BLK0.16b, CT1.16b, BLK0.16b
    st1 {BLK0.16b}, [OUT]
    b .Lcfb_aesdec_finish

.Lcfb_dec_proc_2_blks:
    ld1 {BLK0.16b, BLK1.16b}, [IN]
    mov	CT1.16b, IVC.16b
    mov	CT2.16b, BLK0.16b

    AES_ENC_2_BLKS KEY CT1.16b CT2.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    mov	IVC.16b, BLK1.16b
    eor BLK0.16b, CT1.16b, BLK0.16b
    eor BLK1.16b, CT2.16b, BLK1.16b

    st1 {BLK0.16b, BLK1.16b}, [OUT]
    b .Lcfb_aesdec_finish

.Lcfb_dec_proc_3_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b}, [IN]
    mov	CT1.16b, IVC.16b
    mov	CT2.16b, BLK0.16b
    mov	CT3.16b, BLK1.16b
    AES_ENC_3_BLKS KEY CT1.16b CT2.16b CT3.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    mov	IVC.16b, BLK2.16b
    eor BLK0.16b, BLK0.16b, CT1.16b
    eor BLK1.16b, BLK1.16b, CT2.16b
    eor BLK2.16b, BLK2.16b, CT3.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b}, [OUT]
    b .Lcfb_aesdec_finish

.Lcfb_dec_proc_4_blks:

    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN]
    mov	CT1.16b, IVC.16b
    mov	CT2.16b, BLK0.16b
    mov	CT3.16b, BLK1.16b
    mov	CT4.16b, BLK2.16b
    AES_ENC_4_BLKS KEY CT1.16b CT2.16b CT3.16b CT4.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    mov	IVC.16b, BLK3.16b

    eor BLK0.16b, BLK0.16b, CT1.16b
    eor BLK1.16b, BLK1.16b, CT2.16b
    eor BLK2.16b, BLK2.16b, CT3.16b
    eor BLK3.16b, BLK3.16b, CT4.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT]
    b .Lcfb_aesdec_finish

.Lcfb_dec_proc_5_blks:

    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b}, [IN]
    mov	CT1.16b, IVC.16b
    mov	CT2.16b, BLK0.16b
    mov	CT3.16b, BLK1.16b
    mov	CT4.16b, BLK2.16b
    mov	CT5.16b, BLK3.16b

    AES_ENC_5_BLKS KEY CT1.16b CT2.16b CT3.16b CT4.16b CT5.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    mov	IVC.16b, BLK4.16b

    eor BLK0.16b, BLK0.16b, CT1.16b
    eor BLK1.16b, BLK1.16b, CT2.16b
    eor BLK2.16b, BLK2.16b, CT3.16b
    eor BLK3.16b, BLK3.16b, CT4.16b
    eor BLK4.16b, BLK4.16b, CT5.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b}, [OUT]
    b .Lcfb_aesdec_finish
.Lcfb_dec_proc_6_blks:

    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b}, [IN]
    mov	CT1.16b, IVC.16b
    mov	CT2.16b, BLK0.16b
    mov	CT3.16b, BLK1.16b
    mov	CT4.16b, BLK2.16b
    mov	CT5.16b, BLK3.16b
    mov	CT6.16b, BLK4.16b

    AES_ENC_6_BLKS  KEY CT1.16b CT2.16b CT3.16b CT4.16b CT5.16b CT6.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    mov	IVC.16b, BLK5.16b

    eor BLK0.16b, BLK0.16b, CT1.16b
    eor BLK1.16b, BLK1.16b, CT2.16b
    eor BLK2.16b, BLK2.16b, CT3.16b
    eor BLK3.16b, BLK3.16b, CT4.16b
    eor BLK4.16b, BLK4.16b, CT5.16b
    eor BLK5.16b, BLK5.16b, CT6.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b}, [OUT]
    b .Lcfb_aesdec_finish

.Lcfb_dec_proc_7_blks:
    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b, BLK6.16b}, [IN]
    mov	CT1.16b, IVC.16b
    mov	CT2.16b, BLK0.16b
    mov	CT3.16b, BLK1.16b
    mov	CT4.16b, BLK2.16b
    mov	CT5.16b, BLK3.16b
    mov	CT6.16b, BLK4.16b
    mov	CT7.16b, BLK5.16b

    AES_ENC_7_BLKS  KEY CT1.16b CT2.16b CT3.16b CT4.16b CT5.16b CT6.16b CT7.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    mov	IVC.16b, BLK6.16b

    eor BLK0.16b, BLK0.16b, CT1.16b
    eor BLK1.16b, BLK1.16b, CT2.16b
    eor BLK2.16b, BLK2.16b, CT3.16b
    eor BLK3.16b, BLK3.16b, CT4.16b
    eor BLK4.16b, BLK4.16b, CT5.16b
    eor BLK5.16b, BLK5.16b, CT6.16b
    eor BLK6.16b, BLK6.16b, CT7.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b, BLK6.16b}, [OUT]

.Lcfb_aesdec_finish:
    st1 {IVC.16b}, [IV]

.Lcfb_len_zero:
    mov x0, #0
    eor CT1.16b, CT1.16b, CT1.16b
    eor CT2.16b, CT2.16b, CT2.16b
    eor CT3.16b, CT3.16b, CT3.16b
    eor CT4.16b, CT4.16b, CT4.16b
    eor CT5.16b, CT5.16b, CT5.16b
    eor CT6.16b, CT6.16b, CT6.16b
    eor RDK0.16b, RDK0.16b, RDK0.16b
    eor RDK1.16b, RDK1.16b, RDK1.16b

AARCH64_AUTIASP
    ret
.size CRYPT_AES_CFB_Decrypt, .-CRYPT_AES_CFB_Decrypt

#endif
