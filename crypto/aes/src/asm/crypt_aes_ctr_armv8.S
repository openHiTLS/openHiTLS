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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CTR)

#include "crypt_arm.h"
#include "crypt_aes_macro_armv8.s"

.file    "crypt_aes_ctr_armv8.S"
.text
.arch    armv8-a+crypto

.align   5

KEY     .req    x0
IN      .req    x1
OUT     .req    x2
LEN     .req    x3
IV      .req    x4

LTMP    .req    x12
CTMP    .req    v27

BLK0    .req    v0
BLK1    .req    v1
BLK2    .req    v2
BLK3    .req    v3
BLK4    .req    v4
BLK5    .req    v5
BLK6    .req    v6
BLK7    .req    v7

CTR0	.req    v19
CTR1	.req    v20
CTR2	.req    v21
CTR3	.req    v22
CTR4	.req    v23
CTR5	.req    v24
CTR6	.req    v25
CTR7	.req    v26

RDK0    .req    v17
RDK1    .req    v18
ROUNDS  .req    w6

/* ctr + 1 */
.macro ADDCTR ctr
#ifndef HITLS_BIG_ENDIAN
    add w11, w11, #1
    rev w9, w11
    mov \ctr, w9
#else
    rev w11, w11
    add w11, w11, #1
    rev w11, w11
    mov \ctr, w11
#endif
.endm

/*
 * Vn      -  V0 ~ V31
 * 8bytes  -  Vn.8B  Vn.4H  Vn.2S  Vn.1D
 * 16bytes -  Vn.16B Vn.8H  Vn.4S  Vn.2D
 */

/*
 * int32_t CRYPT_AES_CTR_Encrypt(const CRYPT_AES_Key *ctx,
 *                              const uint8_t *in,
 *                              uint8_t *out,
 *                              uint32_t len,
 *                              uint8_t *iv);
 */

.globl CRYPT_AES_CTR_Encrypt
.type CRYPT_AES_CTR_Encrypt, %function
CRYPT_AES_CTR_Encrypt:
AARCH64_PACIASP
    ld1	{CTR0.16b}, [IV]              // Reads the IV.
    mov	CTMP.16b, CTR0.16b
    mov	w11, CTR0.s[3]
#ifndef HITLS_BIG_ENDIAN
    rev w11, w11
#endif
    mov LTMP, LEN

.Lctr_aesenc_start:
    cmp LTMP, #64
    b.ge .Lctr_enc_above_equal_4_blks
    cmp LTMP, #32
    b.ge .Lctr_enc_above_equal_2_blks
    cmp LTMP, #0
    b.eq .Lctr_len_zero
    b .Lctr_enc_proc_1_blk

.Lctr_enc_above_equal_2_blks:
    cmp LTMP, #48
    b.lt .Lctr_enc_proc_2_blks
    b .Lctr_enc_proc_3_blks

.Lctr_enc_above_equal_4_blks:
    cmp LTMP, #96
    b.ge .Lctr_enc_above_equal_6_blks
    cmp LTMP, #80
    b.lt .Lctr_enc_proc_4_blks
    b .Lctr_enc_proc_5_blks

.Lctr_enc_above_equal_6_blks:
    cmp LTMP, #112
    b.lt .Lctr_enc_proc_6_blks
    cmp LTMP, #128
    b.lt .Lctr_enc_proc_7_blks

.Lctr_enc_proc_8_blks:

/* When the length is greater than or equal to 128, eight blocks loop is used. */
.Lctr_aesenc_8_blks_loop:

    /* Calculate eight CTRs. */
    mov	CTR1.16b, CTMP.16b
    mov	CTR2.16b, CTMP.16b
    mov	CTR3.16b, CTMP.16b
    mov	CTR4.16b, CTMP.16b
    mov	CTR5.16b, CTMP.16b
    mov	CTR6.16b, CTMP.16b
    mov	CTR7.16b, CTMP.16b

    ADDCTR CTR1.s[3]
    ADDCTR CTR2.s[3]
    ADDCTR CTR3.s[3]
    ADDCTR CTR4.s[3]
    ADDCTR CTR5.s[3]
    ADDCTR CTR6.s[3]
    ADDCTR CTR7.s[3]

    mov x14, KEY                      // Prevent the key from being changed.
    AES_ENC_8_BLKS  x14 CTR0.16b CTR1.16b CTR2.16b CTR3.16b CTR4.16b \
                    CTR5.16b CTR6.16b CTR7.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [IN], #64

    eor BLK0.16b, BLK0.16b, CTR0.16b
    eor BLK1.16b, BLK1.16b, CTR1.16b
    eor BLK2.16b, BLK2.16b, CTR2.16b
    eor BLK3.16b, BLK3.16b, CTR3.16b
    eor BLK4.16b, BLK4.16b, CTR4.16b
    eor BLK5.16b, BLK5.16b, CTR5.16b
    eor BLK6.16b, BLK6.16b, CTR6.16b
    eor BLK7.16b, BLK7.16b, CTR7.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b, BLK6.16b, BLK7.16b}, [OUT], #64

    sub LTMP, LTMP, #128
    cmp LTMP, #0
    b.eq .Lctr_aesenc_finish

    ADDCTR CTMP.s[3]
    mov CTR0.16b, CTMP.16b

    cmp LTMP, #128
    b.lt .Lctr_aesenc_start
    b .Lctr_aesenc_8_blks_loop

.Lctr_enc_proc_1_blk:

    AES_ENC_1_BLK KEY CTR0.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    ld1 {BLK0.16b}, [IN]
    eor BLK0.16b, CTR0.16b, BLK0.16b
    st1 {BLK0.16b}, [OUT]
    b .Lctr_aesenc_finish

.Lctr_enc_proc_2_blks:

    mov	CTR1.16b, CTMP.16b
    ADDCTR CTR1.s[3]

    AES_ENC_2_BLKS KEY CTR0.16b CTR1.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    ld1 {BLK0.16b, BLK1.16b}, [IN]

    eor BLK0.16b, CTR0.16b, BLK0.16b
    eor BLK1.16b, CTR1.16b, BLK1.16b

    st1 {BLK0.16b, BLK1.16b}, [OUT]
    b .Lctr_aesenc_finish

.Lctr_enc_proc_3_blks:

    mov	CTR1.16b, CTMP.16b
    mov	CTR2.16b, CTMP.16b

    ADDCTR CTR1.s[3]
    ADDCTR CTR2.s[3]

    AES_ENC_3_BLKS KEY CTR0.16b CTR1.16b CTR2.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    ld1 {BLK0.16b, BLK1.16b, BLK2.16b}, [IN]

    eor BLK0.16b, BLK0.16b, CTR0.16b
    eor BLK1.16b, BLK1.16b, CTR1.16b
    eor BLK2.16b, BLK2.16b, CTR2.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b}, [OUT]
    b .Lctr_aesenc_finish

.Lctr_enc_proc_4_blks:

    mov	CTR1.16b, CTMP.16b
    mov	CTR2.16b, CTMP.16b
    mov	CTR3.16b, CTMP.16b

    ADDCTR CTR1.s[3]
    ADDCTR CTR2.s[3]
    ADDCTR CTR3.s[3]

    AES_ENC_4_BLKS KEY CTR0.16b CTR1.16b CTR2.16b CTR3.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN]

    eor BLK0.16b, BLK0.16b, CTR0.16b
    eor BLK1.16b, BLK1.16b, CTR1.16b
    eor BLK2.16b, BLK2.16b, CTR2.16b
    eor BLK3.16b, BLK3.16b, CTR3.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT]
    b .Lctr_aesenc_finish

.Lctr_enc_proc_5_blks:

    mov	CTR1.16b, CTMP.16b
    mov	CTR2.16b, CTMP.16b
    mov	CTR3.16b, CTMP.16b
    mov	CTR4.16b, CTMP.16b

    ADDCTR CTR1.s[3]
    ADDCTR CTR2.s[3]
    ADDCTR CTR3.s[3]
    ADDCTR CTR4.s[3]

    AES_ENC_5_BLKS KEY CTR0.16b CTR1.16b CTR2.16b CTR3.16b CTR4.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b}, [IN]

    eor BLK0.16b, BLK0.16b, CTR0.16b
    eor BLK1.16b, BLK1.16b, CTR1.16b
    eor BLK2.16b, BLK2.16b, CTR2.16b
    eor BLK3.16b, BLK3.16b, CTR3.16b
    eor BLK4.16b, BLK4.16b, CTR4.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b}, [OUT]
    b .Lctr_aesenc_finish

.Lctr_enc_proc_6_blks:

    mov	CTR1.16b, CTMP.16b
    mov	CTR2.16b, CTMP.16b
    mov	CTR3.16b, CTMP.16b
    mov	CTR4.16b, CTMP.16b
    mov	CTR5.16b, CTMP.16b

    ADDCTR CTR1.s[3]
    ADDCTR CTR2.s[3]
    ADDCTR CTR3.s[3]
    ADDCTR CTR4.s[3]
    ADDCTR CTR5.s[3]

    AES_ENC_6_BLKS  KEY CTR0.16b CTR1.16b CTR2.16b CTR3.16b CTR4.16b \
                    CTR5.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b}, [IN]

    eor BLK0.16b, BLK0.16b, CTR0.16b
    eor BLK1.16b, BLK1.16b, CTR1.16b
    eor BLK2.16b, BLK2.16b, CTR2.16b
    eor BLK3.16b, BLK3.16b, CTR3.16b
    eor BLK4.16b, BLK4.16b, CTR4.16b
    eor BLK5.16b, BLK5.16b, CTR5.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b}, [OUT]
    b .Lctr_aesenc_finish

.Lctr_enc_proc_7_blks:

    mov	CTR1.16b, CTMP.16b
    mov	CTR2.16b, CTMP.16b
    mov	CTR3.16b, CTMP.16b
    mov	CTR4.16b, CTMP.16b
    mov	CTR5.16b, CTMP.16b
    mov	CTR6.16b, CTMP.16b

    ADDCTR CTR1.s[3]
    ADDCTR CTR2.s[3]
    ADDCTR CTR3.s[3]
    ADDCTR CTR4.s[3]
    ADDCTR CTR5.s[3]
    ADDCTR CTR6.s[3]

    AES_ENC_7_BLKS  KEY CTR0.16b CTR1.16b CTR2.16b CTR3.16b CTR4.16b \
                    CTR5.16b CTR6.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS

    ld1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [IN], #64
    ld1 {BLK4.16b, BLK5.16b, BLK6.16b}, [IN]

    eor BLK0.16b, BLK0.16b, CTR0.16b
    eor BLK1.16b, BLK1.16b, CTR1.16b
    eor BLK2.16b, BLK2.16b, CTR2.16b
    eor BLK3.16b, BLK3.16b, CTR3.16b
    eor BLK4.16b, BLK4.16b, CTR4.16b
    eor BLK5.16b, BLK5.16b, CTR5.16b
    eor BLK6.16b, BLK6.16b, CTR6.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b, BLK3.16b}, [OUT], #64
    st1 {BLK4.16b, BLK5.16b, BLK6.16b}, [OUT]

.Lctr_aesenc_finish:
    ADDCTR CTMP.s[3]                     // Fill CTR0 for the next round.
    st1 {CTMP.16b}, [IV]

.Lctr_len_zero:
    mov x0, #0
    eor CTR0.16b, CTR0.16b, CTR0.16b
    eor CTR1.16b, CTR1.16b, CTR1.16b
    eor CTR2.16b, CTR2.16b, CTR2.16b
    eor CTR3.16b, CTR3.16b, CTR3.16b
    eor CTR4.16b, CTR4.16b, CTR4.16b
    eor CTR5.16b, CTR5.16b, CTR5.16b
    eor CTR6.16b, CTR6.16b, CTR6.16b
    eor CTR7.16b, CTR7.16b, CTR7.16b
    eor RDK0.16b, RDK0.16b, RDK0.16b
    eor RDK1.16b, RDK1.16b, RDK1.16b

AARCH64_AUTIASP
    ret
.size CRYPT_AES_CTR_Encrypt, .-CRYPT_AES_CTR_Encrypt

#endif
