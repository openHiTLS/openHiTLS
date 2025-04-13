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
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_XTS)

#include "crypt_aes_macro_armv8.s"
#include "crypt_arm.h"

.file    "crypt_aes_xts_armv8.S"
.text
.arch    armv8-a+crypto

KEY     .req    x0
IN      .req    x1
OUT     .req    x2
LEN     .req    x3
TWEAK   .req    x4
TMPOUT  .req    x17
WP      .req    w11
WC      .req    w12

KTMP    .req    x5
LTMP    .req    x6
TAILNUM .req    x8
POS     .req    x16

ROUNDS  .req    w7
XROUNDS  .req   x7
TROUNDS .req    w15

WTMP0   .req    w9
WTMP1   .req    w10
WTMP2   .req    w11
WTMP3   .req    w12

XTMP1   .req    x10
XTMP2   .req    x11

TWX0    .req    x13
TWX1    .req    x14
TWW1    .req    w14

BLK0    .req    v0
BLK1    .req    v1
BLK2    .req    v2
BLK3    .req    v3
BLK4    .req    v4

IN0   .req    v5
IN1   .req    v6
IN2   .req    v7
IN3   .req    v30
IN4   .req    v31

TWK0  .req    v8
TWK1  .req    v9
TWK2  .req    v10
TWK3  .req    v11
TWK4  .req    v12

TWKD00   .req    d8
TWKD10   .req    d9

TWKD20   .req    d10
TWKD30   .req    d11
TWKD40   .req    d12

#define TWKD01   v8.d[1]
#define TWKD11   v9.d[1]
#define TWKD21   v10.d[1]
#define TWKD31   v11.d[1]
#define TWKD41   v12.d[1]

RDK0    .req    v16
RDK1    .req    v17
RDK2    .req    v18
RDK3    .req    v19
RDK4    .req    v20
RDK5    .req    v21
RDK6    .req    v22
RDK7    .req    v23
RDK8    .req    v24

TMP0    .req    v25
TMP1    .req    v26
TMP2    .req    v27
TMP3    .req    v28
TMP4    .req    v29


#define MOV_REG_TO_VEC(SRC0, SRC1, DES0, DES1)        \
    fmov DES0,SRC0                        ; \
    fmov DES1,SRC1                        ; \

.macro NextTweak twkl, twkh, twkd0, twkd1
asr XTMP2,\twkh,#63
extr \twkh,\twkh,\twkl,#63
and WTMP1,WTMP0,WTMP2
eor \twkl,XTMP1,\twkl,lsl#1
fmov \twkd0,\twkl  // must set lower bits of 'q' register first.1
fmov \twkd1,\twkh  // Set lower bits using 'd' register will clear higer bits.
.endm

.macro AesCrypt1x en, mc, d0, rk
aes\en \d0\().16b, \rk\().16b
aes\mc \d0\().16b, \d0\().16b
.endm

.macro AesEncrypt1x d0, rk
AesCrypt1x e, mc, \d0, \rk
.endm

.macro AesDecrypt1x d0, rk
AesCrypt1x d, imc, \d0, \rk
.endm

/**
 * int32_t CRYPT_AES_XTS_Encrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len, const uint8_t *tweak);
 */
.globl CRYPT_AES_XTS_Encrypt
.type CRYPT_AES_XTS_Encrypt, %function
.align 4
CRYPT_AES_XTS_Encrypt:
AARCH64_PACIASP
    stp x29, x30, [sp,#-80]!
    add x29, sp, #0
    stp d8, d9, [sp,#16]
    stp d10, d11, [sp,#32]
    stp d12, d13, [sp,#48]
    stp d14, d15, [sp,#64]

    ld1 {TWK0.16b}, [TWEAK]
    and TAILNUM, LEN, #0xF   // get tail num, LEN % 16
    and LTMP, LEN, #-16
    mov WTMP0,0x87
    ldr ROUNDS,[KEY,#240]
    fmov TWX0,TWKD00
    fmov TWX1,TWKD01

    sub ROUNDS,ROUNDS,#6   // perload last 7 rounds key
    add KTMP,KEY,XROUNDS,lsl#4
    ld1 {RDK2.4s,RDK3.4s},[KTMP],#32
    ld1 {RDK4.4s,RDK5.4s},[KTMP],#32
    ld1 {RDK6.4s,RDK7.4s},[KTMP],#32
    ld1 {RDK8.4s},[KTMP]

.Lxts_aesenc_start:
    cmp LTMP, #80
    b.ge .Lxts_enc_proc_5_blks
    cmp LTMP, #48
    b.ge .Lxts_enc_proc_3_blks
    cmp LTMP, #32
    b.eq .Lxts_enc_proc_2_blks
    cmp LTMP, #16
    b.eq .Lxts_enc_proc_1blk

.Lxtx_tail_blk:
    fmov TWX0,TWKD00  // reset already computed tweak
    fmov TWX1,TWKD01
    cbz TAILNUM,.Lxts_aesenc_finish
    // prepare encrypt tail block
    sub TMPOUT,OUT,#16
.Lxtx_tail_blk_loop:
    subs TAILNUM,TAILNUM,1
    ldrb WC,[TMPOUT,TAILNUM]
    ldrb WP,[IN,TAILNUM]
    strb WC,[OUT,TAILNUM]
    strb WP,[TMPOUT,TAILNUM]
    b.gt .Lxtx_tail_blk_loop
    ld1 {BLK0.16b}, [TMPOUT]
    mov LTMP,#16
    mov OUT,TMPOUT
    b .Lxts_enc_proc_1blk_loaded

    cbz LTMP,.Lxts_aesenc_finish

.Lxts_enc_proc_1blk:
    ld1 {BLK0.16b},[IN],#16
.Lxts_enc_proc_1blk_loaded:
    eor BLK0.16b,BLK0.16b,TWK0.16b
    mov KTMP, KEY
    ld1 {RDK0.4s,RDK1.4s},[KTMP],#32
    sub TROUNDS,ROUNDS,#2
.Lxts_rounds_1blks:
    AesEncrypt1x BLK0,RDK0
    ld1 {RDK0.4s},[KTMP],#16
    subs TROUNDS,TROUNDS,#2

    AesEncrypt1x BLK0,RDK1
    ld1 {RDK1.4s},[KTMP],#16
    b.gt .Lxts_rounds_1blks

    AesEncrypt1x BLK0,RDK0
    AesEncrypt1x BLK0,RDK1

    // last 7 rounds 
    AesEncrypt1x BLK0,RDK2
    AesEncrypt1x BLK0,RDK3
    AesEncrypt1x BLK0,RDK4
    AesEncrypt1x BLK0,RDK5
    AesEncrypt1x BLK0,RDK6

    aese BLK0.16b,RDK7.16b  // final round
    eor BLK0.16b,BLK0.16b,RDK8.16b
    eor BLK0.16b,BLK0.16b,TWK0.16b

    st1 {BLK0.16b}, [OUT], #16

    NextTweak TWX0,TWX1,TWKD00,TWKD01

    subs LTMP,LTMP,#16
    b.hs .Lxts_aesenc_start

.Lxts_enc_proc_2_blks:
    ld1 {BLK0.16b, BLK1.16b}, [IN], #32
    mov KTMP, KEY
    NextTweak TWX0,TWX1,TWKD10,TWKD11
    ld1 {RDK0.4s,RDK1.4s},[KTMP],#32
    sub TROUNDS,ROUNDS,#2
    eor BLK0.16b, BLK0.16b, TWK0.16b
    eor BLK1.16b, BLK1.16b, TWK1.16b
.Lxts_rounds_2blks:
    AesEncrypt1x BLK0,RDK0
    AesEncrypt1x BLK1,RDK0
    ld1 {RDK0.4s},[KTMP],#16
    subs TROUNDS,TROUNDS,#2

    AesEncrypt1x BLK0,RDK1
    AesEncrypt1x BLK1,RDK1
    ld1 {RDK1.4s},[KTMP],#16
    b.gt .Lxts_rounds_2blks

    AesEncrypt1x BLK0,RDK0
    AesEncrypt1x BLK1,RDK0

    AesEncrypt1x BLK0,RDK1
    AesEncrypt1x BLK1,RDK1

    // last 7 rounds 
    AesEncrypt1x BLK0,RDK2
    AesEncrypt1x BLK1,RDK2

    AesEncrypt1x BLK0,RDK3
    AesEncrypt1x BLK1,RDK3

    AesEncrypt1x BLK0,RDK4
    AesEncrypt1x BLK1,RDK4

    AesEncrypt1x BLK0,RDK5
    AesEncrypt1x BLK1,RDK5

    AesEncrypt1x BLK0,RDK6
    AesEncrypt1x BLK1,RDK6

    eor TWK0.16b,TWK0.16b,RDK8.16b
    eor TWK1.16b,TWK1.16b,RDK8.16b

    aese BLK0.16b,RDK7.16b  // final round
    aese BLK1.16b,RDK7.16b

    eor BLK0.16b,BLK0.16b,TWK0.16b
    eor BLK1.16b,BLK1.16b,TWK1.16b

    st1 {BLK0.16b, BLK1.16b}, [OUT], #32
    NextTweak TWX0,TWX1,TWKD00,TWKD01
    subs LTMP,LTMP,#32
    b.hs .Lxts_aesenc_start

.Lxts_enc_proc_3_blks:
    ld1 {BLK0.16b}, [IN], #16   // first block
    NextTweak TWX0,TWX1,TWKD10,TWKD11
    eor BLK0.16b,BLK0.16b,TWK0.16b

    ld1 {BLK1.16b}, [IN], #16   // second block
    NextTweak TWX0,TWX1,TWKD20,TWKD21
    eor BLK1.16b,BLK1.16b,TWK1.16b

    ld1 {BLK2.16b}, [IN], #16   // third block
    eor BLK2.16b,BLK2.16b,TWK2.16b

    mov KTMP, KEY
    ld1 {RDK0.4s,RDK1.4s},[KTMP],#32
    sub TROUNDS,ROUNDS,#2

.Lxts_rounds_3blks:
    AesEncrypt1x BLK0,RDK0
    AesEncrypt1x BLK1,RDK0
    AesEncrypt1x BLK2,RDK0
    ld1 {RDK0.4s},[KTMP],#16
    subs TROUNDS,TROUNDS,#2

    AesEncrypt1x BLK0,RDK1
    AesEncrypt1x BLK1,RDK1
    AesEncrypt1x BLK2,RDK1
    ld1 {RDK1.4s},[KTMP],#16
    b.gt .Lxts_rounds_3blks

    AesEncrypt1x BLK0,RDK0
    AesEncrypt1x BLK1,RDK0
    AesEncrypt1x BLK2,RDK0

    AesEncrypt1x BLK0,RDK1
    AesEncrypt1x BLK1,RDK1
    AesEncrypt1x BLK2,RDK1

    // last 7 rounds 
    AesEncrypt1x BLK0,RDK2
    AesEncrypt1x BLK1,RDK2
    AesEncrypt1x BLK2,RDK2

    AesEncrypt1x BLK0,RDK3
    AesEncrypt1x BLK1,RDK3
    AesEncrypt1x BLK2,RDK3

    AesEncrypt1x BLK0,RDK4
    AesEncrypt1x BLK1,RDK4
    AesEncrypt1x BLK2,RDK4

    AesEncrypt1x BLK0,RDK5
    AesEncrypt1x BLK1,RDK5
    AesEncrypt1x BLK2,RDK5

    AesEncrypt1x BLK0,RDK6
    AesEncrypt1x BLK1,RDK6
    AesEncrypt1x BLK2,RDK6

    eor TWK0.16b,TWK0.16b,RDK8.16b
    eor TWK1.16b,TWK1.16b,RDK8.16b
    eor TWK2.16b,TWK2.16b,RDK8.16b

    aese BLK0.16b,RDK7.16b
    aese BLK1.16b,RDK7.16b
    aese BLK2.16b,RDK7.16b

    eor BLK0.16b,BLK0.16b,TWK0.16b
    eor BLK1.16b,BLK1.16b,TWK1.16b
    eor BLK2.16b,BLK2.16b,TWK2.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b}, [OUT], #48

    NextTweak TWX0,TWX1,TWKD00,TWKD01

    subs LTMP,LTMP,#48
    b.hs .Lxts_aesenc_start

.align 4
.Lxts_enc_proc_5_blks:
    ld1 {BLK0.16b}, [IN], #16   // first block
    NextTweak TWX0,TWX1,TWKD10,TWKD11
    eor BLK0.16b,BLK0.16b,TWK0.16b

    ld1 {BLK1.16b}, [IN], #16   // second block
    NextTweak TWX0,TWX1,TWKD20,TWKD21
    eor BLK1.16b,BLK1.16b,TWK1.16b
    sub LTMP,LTMP,#32

    ld1 {BLK2.16b}, [IN], #16   // third block
    NextTweak TWX0,TWX1,TWKD30,TWKD31
    eor BLK2.16b,BLK2.16b,TWK2.16b

    ld1 {BLK3.16b}, [IN], #16   // fourth block
    NextTweak TWX0,TWX1,TWKD40,TWKD41
    eor BLK3.16b,BLK3.16b,TWK3.16b
    sub LTMP,LTMP,#32

    ld1 {BLK4.16b}, [IN], #16   // fifth block
    eor BLK4.16b, BLK4.16b, TWK4.16b
    sub LTMP,LTMP,#16

    mov KTMP, KEY
    ld1 {RDK0.4s,RDK1.4s},[KTMP],#32
    sub TROUNDS,ROUNDS,#2
.align 4
.Lxts_rounds_5blks:
    AesEncrypt1x BLK0,RDK0
    AesEncrypt1x BLK1,RDK0
    AesEncrypt1x BLK2,RDK0
    AesEncrypt1x BLK3,RDK0
    AesEncrypt1x BLK4,RDK0
    ld1 {RDK0.4s},[KTMP],#16
    subs TROUNDS,TROUNDS,#2

    AesEncrypt1x BLK0,RDK1
    AesEncrypt1x BLK1,RDK1
    AesEncrypt1x BLK2,RDK1
    AesEncrypt1x BLK3,RDK1
    AesEncrypt1x BLK4,RDK1
    ld1 {RDK1.4s},[KTMP],#16
    b.gt .Lxts_rounds_5blks

    AesEncrypt1x BLK0,RDK0
    AesEncrypt1x BLK1,RDK0
    AesEncrypt1x BLK2,RDK0
    AesEncrypt1x BLK3,RDK0
    AesEncrypt1x BLK4,RDK0
    subs LTMP,LTMP,#80

    AesEncrypt1x BLK0,RDK1
    AesEncrypt1x BLK1,RDK1
    AesEncrypt1x BLK2,RDK1
    AesEncrypt1x BLK3,RDK1
    AesEncrypt1x BLK4,RDK1

    // last 7 rounds 
    AesEncrypt1x BLK0,RDK2
    AesEncrypt1x BLK1,RDK2
    AesEncrypt1x BLK2,RDK2
    AesEncrypt1x BLK3,RDK2
    AesEncrypt1x BLK4,RDK2
    csel POS,xzr,LTMP,gt  // 

    AesEncrypt1x BLK0,RDK3
    AesEncrypt1x BLK1,RDK3
    AesEncrypt1x BLK2,RDK3
    AesEncrypt1x BLK3,RDK3
    AesEncrypt1x BLK4,RDK3
    add IN,IN,POS

    AesEncrypt1x BLK0,RDK4
    AesEncrypt1x BLK1,RDK4
    AesEncrypt1x BLK2,RDK4
    AesEncrypt1x BLK3,RDK4
    AesEncrypt1x BLK4,RDK4

    AesEncrypt1x BLK0,RDK5
    AesEncrypt1x BLK1,RDK5
    AesEncrypt1x BLK2,RDK5
    AesEncrypt1x BLK3,RDK5
    AesEncrypt1x BLK4,RDK5

    AesEncrypt1x BLK0,RDK6
    AesEncrypt1x BLK1,RDK6
    AesEncrypt1x BLK2,RDK6
    AesEncrypt1x BLK3,RDK6
    AesEncrypt1x BLK4,RDK6

    eor TMP0.16b,TWK0.16b,RDK8.16b
    aese BLK0.16b,RDK7.16b  // final round
    NextTweak TWX0,TWX1,TWKD00,TWKD01  // perform operations of next 5blks in advance

    eor TMP1.16b,TWK1.16b,RDK8.16b
    ld1 {IN0.16b}, [IN], #16
    aese BLK1.16b,RDK7.16b
    NextTweak TWX0,TWX1,TWKD10,TWKD11

    eor TMP2.16b,TWK2.16b,RDK8.16b
    ld1 {IN1.16b}, [IN], #16
    aese BLK2.16b,RDK7.16b
    NextTweak TWX0,TWX1,TWKD20,TWKD21

    eor TMP3.16b,TWK3.16b,RDK8.16b
    ld1 {IN2.16b}, [IN], #16
    aese BLK3.16b,RDK7.16b
    NextTweak TWX0,TWX1,TWKD30,TWKD31

    eor TMP4.16b,TWK4.16b,RDK8.16b
    ld1 {IN3.16b}, [IN], #16
    aese BLK4.16b,RDK7.16b
    NextTweak TWX0,TWX1,TWKD40,TWKD41

    ld1 {IN4.16b}, [IN], #16
    mov KTMP, KEY
    ld1 {RDK0.4s,RDK1.4s},[KTMP],#32
    eor TMP0.16b,TMP0.16b,BLK0.16b
    eor BLK0.16b,IN0.16b,TWK0.16b  // blk0 = in0 ^ twk0
    eor TMP1.16b,TMP1.16b,BLK1.16b
    eor BLK1.16b,IN1.16b,TWK1.16b
    st1 {TMP0.16b}, [OUT], #16
    eor TMP2.16b,TMP2.16b,BLK2.16b
    eor BLK2.16b,IN2.16b,TWK2.16b
    eor TMP3.16b,TMP3.16b,BLK3.16b
    eor BLK3.16b,IN3.16b,TWK3.16b
    st1 {TMP1.16b}, [OUT], #16
    eor TMP4.16b,TMP4.16b,BLK4.16b
    eor BLK4.16b,IN4.16b,TWK4.16b
    st1 {TMP2.16b}, [OUT], #16
    sub TROUNDS,ROUNDS,#2
    st1 {TMP3.16b,TMP4.16b}, [OUT], #32

    b.hs .Lxts_rounds_5blks
    add LTMP,LTMP,#80      // add 5 blocks length back if LTMP < 0
    cbz LTMP,.Lxtx_tail_blk
    cmp LTMP, #16
    b.eq .Lxts_pre_last_1blks
    cmp LTMP,#32
    b.eq .Lxts_pre_last_2blks
    cmp LTMP,#48
    b.eq .Lxts_pre_last_3blks
    cmp LTMP,#64
    b.eq .Lxts_pre_last_4blks
.Lxts_pre_last_1blks:
    eor IN0.16b,IN0.16b,IN4.16b   //in0 = in0 ^ in41
    eor BLK0.16b,BLK0.16b,IN0.16b   // blk0 =  in0 ^ twk0 ^ in0 ^ in4
    fmov TWX0,TWKD00  // reset already computed tweak
    fmov TWX1,TWKD01
    b .Lxts_rounds_1blks
.Lxts_pre_last_2blks:
    eor BLK0.16b,BLK0.16b,IN0.16b
    eor BLK1.16b,BLK1.16b,IN1.16b
    eor BLK0.16b,BLK0.16b,IN3.16b  // in3 -> blk0
    eor BLK1.16b,BLK1.16b,IN4.16b  // in4 -> blk1
    fmov TWX0,TWKD10  // reset already computed tweak
    fmov TWX1,TWKD11
    b .Lxts_rounds_2blks
.Lxts_pre_last_3blks:
    eor BLK0.16b,BLK0.16b,IN0.16b
    eor BLK1.16b,BLK1.16b,IN1.16b
    eor BLK2.16b,BLK2.16b,IN2.16b
    eor BLK0.16b,BLK0.16b,IN2.16b  // in2 -> blk0
    eor BLK1.16b,BLK1.16b,IN3.16b  // in3 -> blk1
    eor BLK2.16b,BLK2.16b,IN4.16b  // in4 -> blk2
    fmov TWX0,TWKD20  // reset already computed tweak
    fmov TWX1,TWKD21
    b .Lxts_rounds_3blks
.Lxts_pre_last_4blks:
    eor BLK0.16b,BLK0.16b,IN0.16b
    eor BLK1.16b,BLK1.16b,IN1.16b
    eor BLK2.16b,BLK2.16b,IN2.16b
    eor BLK3.16b,BLK3.16b,IN3.16b
    sub IN,IN,#16 // have loaded 4blks, using 3blks to process, so step back 1blk here
    eor BLK0.16b,BLK0.16b,IN1.16b  // in1 -> blk0
    eor BLK1.16b,BLK1.16b,IN2.16b  // in2 -> blk1
    eor BLK2.16b,BLK2.16b,IN3.16b  // in3 -> blk2
    eor BLK3.16b,BLK3.16b,IN4.16b  // in4 -> blk3
    fmov TWX0,TWKD20  // reset already computed tweak
    fmov TWX1,TWKD21
    b .Lxts_rounds_3blks

.Lxts_aesenc_finish:
    MOV_REG_TO_VEC(TWX0,TWX1,TWKD00,TWKD01)
    st1 {TWK0.16b}, [TWEAK]

    mov x0, #0  // return value ? no need

    ldp d14, d15, [sp,#64]
    ldp d12, d13, [sp, #48]
    ldp d10, d11, [sp, #32]
    ldp d8, d9, [sp, #16]
    ldp x29, x30, [sp], #80

AARCH64_AUTIASP
    ret
.size CRYPT_AES_XTS_Encrypt, .-CRYPT_AES_XTS_Encrypt


/**
 * int32_t CRYPT_AES_XTS_Decrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len, const uint8_t *t);
 */
.globl CRYPT_AES_XTS_Decrypt
.type CRYPT_AES_XTS_Decrypt, %function
.align    4
CRYPT_AES_XTS_Decrypt:
AARCH64_PACIASP
    stp x29, x30, [sp,#-80]!
    add x29, sp, #0
    stp d8, d9, [sp,#16]
    stp d10, d11, [sp,#32]
    stp d12, d13, [sp,#48]
    stp d14, d15, [sp,#64]

    ld1 {TWK0.16b}, [TWEAK]
    and LTMP, LEN, #-16
    ands TAILNUM, LEN, #0xF   // get tail num, LEN % 16
    sub XTMP1,LTMP,#16      // preserve last and tail block
    csel LTMP,XTMP1,LTMP,ne  // if tailnum != 0, len -= 16
    
    mov WTMP0,0x87
    ldr ROUNDS,[KEY,#240]
    fmov TWX0,TWKD00
    fmov TWX1,TWKD01

    sub ROUNDS,ROUNDS,#6   // perload last 7 rounds key
    add KTMP,KEY,XROUNDS,lsl#4
    ld1 {RDK2.4s,RDK3.4s},[KTMP],#32
    ld1 {RDK4.4s,RDK5.4s},[KTMP],#32
    ld1 {RDK6.4s,RDK7.4s},[KTMP],#32
    ld1 {RDK8.4s},[KTMP]

.Lxts_aesdec_start:
    cmp LTMP, #80
    b.gt .Lxts_dec_proc_5_blks
    cmp LTMP, #48
    b.ge .Lxts_dec_proc_3_blks
    cmp LTMP, #32
    b.eq .Lxts_dec_proc_2_blks
    cmp LTMP, #16
    b.eq .Lxts_dec_proc_1blk
    cmp LTMP, #0
    b.eq .Lxts_dec_last_secondblk
.Lxtx_dec_tail_blk:
    fmov TWX0,TWKD00  // reset already computed tweak
    fmov TWX1,TWKD01
    cbz TAILNUM,.Lxts_aesdec_finish
    // prepare encrypt tail block
    sub TMPOUT,OUT,#16
.Lxtx_dec_tail_blk_loop:
    subs TAILNUM,TAILNUM,1
    ldrb WC,[TMPOUT,TAILNUM]
    ldrb WP,[IN,TAILNUM]
    strb WC,[OUT,TAILNUM]
    strb WP,[TMPOUT,TAILNUM]
    b.gt .Lxtx_dec_tail_blk_loop
    ld1 {BLK0.16b}, [TMPOUT]
    mov OUT,TMPOUT
    mov TWK0.16b,TWK1.16b  // load pre-tweak back
    b .Lxts_dec_proc_1blk_loaded

    cbz LTMP,.Lxts_aesdec_finish

.Lxts_dec_last_secondblk:
    cbz TAILNUM,.Lxts_aesdec_finish
    mov TWK1.16b,TWK0.16b   // save last second tweak
    NextTweak TWX0,TWX1,TWKD00,TWKD01
.Lxts_dec_proc_1blk:
    ld1 {BLK0.16b}, [IN],#16
.Lxts_dec_proc_1blk_loaded:
    mov KTMP, KEY
    eor BLK0.16b,BLK0.16b,TWK0.16b
    ld1 {RDK0.4s},[KTMP],#16
    sub TROUNDS,ROUNDS,#2
    ld1 {RDK1.4s},[KTMP],#16
.Lxts_dec_rounds_1blks:
    AesDecrypt1x BLK0,RDK0
    ld1 {RDK0.4s},[KTMP],#16
    subs TROUNDS,TROUNDS,#2

    AesDecrypt1x BLK0,RDK1
    ld1 {RDK1.4s},[KTMP],#16
    b.gt .Lxts_dec_rounds_1blks

    AesDecrypt1x BLK0,RDK0
    AesDecrypt1x BLK0,RDK1

    // last 7 rounds 
    AesDecrypt1x BLK0,RDK2
    AesDecrypt1x BLK0,RDK3
    AesDecrypt1x BLK0,RDK4
    AesDecrypt1x BLK0,RDK5
    AesDecrypt1x BLK0,RDK6

    aesd BLK0.16b,RDK7.16b  // final round
    eor BLK0.16b,BLK0.16b,RDK8.16b
    eor BLK0.16b,BLK0.16b,TWK0.16b

    st1 {BLK0.16b}, [OUT], #16

    NextTweak TWX0,TWX1,TWKD00,TWKD01

    subs LTMP,LTMP,#16
    b.lt .Lxtx_dec_tail_blk
    b.hs .Lxts_aesdec_start

.Lxts_dec_proc_2_blks:
    ld1 {BLK0.16b, BLK1.16b}, [IN], #32
    mov KTMP, KEY
    NextTweak TWX0,TWX1,TWKD10,TWKD11
    ld1 {RDK0.4s,RDK1.4s},[KTMP],#32
    sub TROUNDS,ROUNDS,#2
    eor BLK0.16b, BLK0.16b, TWK0.16b
    eor BLK1.16b, BLK1.16b, TWK1.16b
.Lxts_dec_rounds_2blks:
    AesDecrypt1x BLK0,RDK0
    AesDecrypt1x BLK1,RDK0
    ld1 {RDK0.4s},[KTMP],#16
    subs TROUNDS,TROUNDS,#2

    AesDecrypt1x BLK0,RDK1
    AesDecrypt1x BLK1,RDK1
    ld1 {RDK1.4s},[KTMP],#16
    b.gt .Lxts_dec_rounds_2blks

    AesDecrypt1x BLK0,RDK0
    AesDecrypt1x BLK1,RDK0

    AesDecrypt1x BLK0,RDK1
    AesDecrypt1x BLK1,RDK1

    // last 7 rounds 
    AesDecrypt1x BLK0,RDK2
    AesDecrypt1x BLK1,RDK2

    AesDecrypt1x BLK0,RDK3
    AesDecrypt1x BLK1,RDK3

    AesDecrypt1x BLK0,RDK4
    AesDecrypt1x BLK1,RDK4

    AesDecrypt1x BLK0,RDK5
    AesDecrypt1x BLK1,RDK5

    AesDecrypt1x BLK0,RDK6
    AesDecrypt1x BLK1,RDK6

    eor TWK0.16b,TWK0.16b,RDK8.16b
    eor TWK1.16b,TWK1.16b,RDK8.16b

    aesd BLK0.16b,RDK7.16b  // final round
    aesd BLK1.16b,RDK7.16b

    eor BLK0.16b,BLK0.16b,TWK0.16b
    eor BLK1.16b,BLK1.16b,TWK1.16b

    st1 {BLK0.16b, BLK1.16b}, [OUT], #32
    NextTweak TWX0,TWX1,TWKD00,TWKD01
    subs LTMP,LTMP,#32
    b.hs .Lxts_aesdec_start

.Lxts_dec_proc_3_blks:
    ld1 {BLK0.16b}, [IN], #16   // first block
    NextTweak TWX0,TWX1,TWKD10,TWKD11
    eor BLK0.16b,BLK0.16b,TWK0.16b

    ld1 {BLK1.16b}, [IN], #16   // second block
    NextTweak TWX0,TWX1,TWKD20,TWKD21
    eor BLK1.16b,BLK1.16b,TWK1.16b

    ld1 {BLK2.16b}, [IN], #16   // third block
    eor BLK2.16b,BLK2.16b,TWK2.16b

    mov KTMP, KEY
    ld1 {RDK0.4s,RDK1.4s},[KTMP],#32
    sub TROUNDS,ROUNDS,#2

.Lxts_dec_rounds_3blks:
    AesDecrypt1x BLK0,RDK0
    AesDecrypt1x BLK1,RDK0
    AesDecrypt1x BLK2,RDK0
    ld1 {RDK0.4s},[KTMP],#16
    subs TROUNDS,TROUNDS,#2

    AesDecrypt1x BLK0,RDK1
    AesDecrypt1x BLK1,RDK1
    AesDecrypt1x BLK2,RDK1
    ld1 {RDK1.4s},[KTMP],#16
    b.gt .Lxts_dec_rounds_3blks

    AesDecrypt1x BLK0,RDK0
    AesDecrypt1x BLK1,RDK0
    AesDecrypt1x BLK2,RDK0

    AesDecrypt1x BLK0,RDK1
    AesDecrypt1x BLK1,RDK1
    AesDecrypt1x BLK2,RDK1

    // last 7 rounds 
    AesDecrypt1x BLK0,RDK2
    AesDecrypt1x BLK1,RDK2
    AesDecrypt1x BLK2,RDK2

    AesDecrypt1x BLK0,RDK3
    AesDecrypt1x BLK1,RDK3
    AesDecrypt1x BLK2,RDK3

    AesDecrypt1x BLK0,RDK4
    AesDecrypt1x BLK1,RDK4
    AesDecrypt1x BLK2,RDK4

    AesDecrypt1x BLK0,RDK5
    AesDecrypt1x BLK1,RDK5
    AesDecrypt1x BLK2,RDK5

    AesDecrypt1x BLK0,RDK6
    AesDecrypt1x BLK1,RDK6
    AesDecrypt1x BLK2,RDK6

    eor TWK0.16b,TWK0.16b,RDK8.16b
    eor TWK1.16b,TWK1.16b,RDK8.16b
    eor TWK2.16b,TWK2.16b,RDK8.16b

    aesd BLK0.16b,RDK7.16b
    aesd BLK1.16b,RDK7.16b
    aesd BLK2.16b,RDK7.16b

    eor BLK0.16b,BLK0.16b,TWK0.16b
    eor BLK1.16b,BLK1.16b,TWK1.16b
    eor BLK2.16b,BLK2.16b,TWK2.16b

    st1 {BLK0.16b, BLK1.16b, BLK2.16b}, [OUT], #48

    NextTweak TWX0,TWX1,TWKD00,TWKD01

    subs LTMP,LTMP,#48
    b.hs .Lxts_aesdec_start

.align 4
.Lxts_dec_proc_5_blks:
    ld1 {BLK0.16b}, [IN], #16   // first block
    NextTweak TWX0,TWX1,TWKD10,TWKD11
    eor BLK0.16b,BLK0.16b,TWK0.16b

    ld1 {BLK1.16b}, [IN], #16   // second block
    NextTweak TWX0,TWX1,TWKD20,TWKD21
    eor BLK1.16b,BLK1.16b,TWK1.16b
    sub LTMP,LTMP,#32

    ld1 {BLK2.16b}, [IN], #16   // third block
    NextTweak TWX0,TWX1,TWKD30,TWKD31
    eor BLK2.16b,BLK2.16b,TWK2.16b

    ld1 {BLK3.16b}, [IN], #16   // fourth block
    NextTweak TWX0,TWX1,TWKD40,TWKD41
    eor BLK3.16b,BLK3.16b,TWK3.16b
    sub LTMP,LTMP,#32

    ld1 {BLK4.16b}, [IN], #16   // fifth block
    eor BLK4.16b, BLK4.16b, TWK4.16b
    sub LTMP,LTMP,#16

    mov KTMP, KEY
    ld1 {RDK0.4s,RDK1.4s},[KTMP],#32
    sub TROUNDS,ROUNDS,#2
.align 4
.Lxts_dec_rounds_5blks:
    AesDecrypt1x BLK0,RDK0
    AesDecrypt1x BLK1,RDK0
    AesDecrypt1x BLK2,RDK0
    AesDecrypt1x BLK3,RDK0
    AesDecrypt1x BLK4,RDK0
    ld1 {RDK0.4s},[KTMP],#16
    subs TROUNDS,TROUNDS,#2

    AesDecrypt1x BLK0,RDK1
    AesDecrypt1x BLK1,RDK1
    AesDecrypt1x BLK2,RDK1
    AesDecrypt1x BLK3,RDK1
    AesDecrypt1x BLK4,RDK1
    ld1 {RDK1.4s},[KTMP],#16
    b.gt .Lxts_dec_rounds_5blks

    AesDecrypt1x BLK0,RDK0
    AesDecrypt1x BLK1,RDK0
    AesDecrypt1x BLK2,RDK0
    AesDecrypt1x BLK3,RDK0
    AesDecrypt1x BLK4,RDK0
    subs LTMP,LTMP,#80

    AesDecrypt1x BLK0,RDK1
    AesDecrypt1x BLK1,RDK1
    AesDecrypt1x BLK2,RDK1
    AesDecrypt1x BLK3,RDK1
    AesDecrypt1x BLK4,RDK1

    // last 7 rounds 
    AesDecrypt1x BLK0,RDK2
    AesDecrypt1x BLK1,RDK2
    AesDecrypt1x BLK2,RDK2
    AesDecrypt1x BLK3,RDK2
    AesDecrypt1x BLK4,RDK2
    csel POS,xzr,LTMP,gt  // 

    AesDecrypt1x BLK0,RDK3
    AesDecrypt1x BLK1,RDK3
    AesDecrypt1x BLK2,RDK3
    AesDecrypt1x BLK3,RDK3
    AesDecrypt1x BLK4,RDK3
    add IN,IN,POS

    AesDecrypt1x BLK0,RDK4
    AesDecrypt1x BLK1,RDK4
    AesDecrypt1x BLK2,RDK4
    AesDecrypt1x BLK3,RDK4
    AesDecrypt1x BLK4,RDK4

    AesDecrypt1x BLK0,RDK5
    AesDecrypt1x BLK1,RDK5
    AesDecrypt1x BLK2,RDK5
    AesDecrypt1x BLK3,RDK5
    AesDecrypt1x BLK4,RDK5

    AesDecrypt1x BLK0,RDK6
    AesDecrypt1x BLK1,RDK6
    AesDecrypt1x BLK2,RDK6
    AesDecrypt1x BLK3,RDK6
    AesDecrypt1x BLK4,RDK6

    eor TMP0.16b,TWK0.16b,RDK8.16b
    aesd BLK0.16b,RDK7.16b  // final round
    NextTweak TWX0,TWX1,TWKD00,TWKD01  // perform operations of next 5blks in advance

    eor TMP1.16b,TWK1.16b,RDK8.16b
    ld1 {IN0.16b}, [IN], #16
    aesd BLK1.16b,RDK7.16b
    NextTweak TWX0,TWX1,TWKD10,TWKD11

    eor TMP2.16b,TWK2.16b,RDK8.16b
    ld1 {IN1.16b}, [IN], #16
    aesd BLK2.16b,RDK7.16b
    NextTweak TWX0,TWX1,TWKD20,TWKD21

    eor TMP3.16b,TWK3.16b,RDK8.16b
    ld1 {IN2.16b}, [IN], #16
    aesd BLK3.16b,RDK7.16b
    NextTweak TWX0,TWX1,TWKD30,TWKD31

    eor TMP4.16b,TWK4.16b,RDK8.16b
    ld1 {IN3.16b}, [IN], #16
    aesd BLK4.16b,RDK7.16b
    NextTweak TWX0,TWX1,TWKD40,TWKD41

    ld1 {IN4.16b}, [IN], #16
    mov KTMP, KEY
    ld1 {RDK0.4s,RDK1.4s},[KTMP],#32
    eor TMP0.16b,TMP0.16b,BLK0.16b
    eor BLK0.16b,IN0.16b,TWK0.16b  // blk0 = in0 ^ twk0
    eor TMP1.16b,TMP1.16b,BLK1.16b
    eor BLK1.16b,IN1.16b,TWK1.16b
    st1 {TMP0.16b}, [OUT], #16
    eor TMP2.16b,TMP2.16b,BLK2.16b
    eor BLK2.16b,IN2.16b,TWK2.16b
    eor TMP3.16b,TMP3.16b,BLK3.16b
    eor BLK3.16b,IN3.16b,TWK3.16b
    st1 {TMP1.16b}, [OUT], #16
    eor TMP4.16b,TMP4.16b,BLK4.16b
    eor BLK4.16b,IN4.16b,TWK4.16b
    st1 {TMP2.16b}, [OUT], #16
    sub TROUNDS,ROUNDS,#2
    st1 {TMP3.16b,TMP4.16b}, [OUT], #32

    b.hs .Lxts_dec_rounds_5blks
    add LTMP,LTMP,#80      // add 5 blocks length back if LTMP < 0
    cbz LTMP,.Lxtx_dec_tail_blk
    cmp LTMP, #16
    b.eq .Lxts_dec_pre_last_1blks
    cmp LTMP,#32
    b.eq .Lxts_dec_pre_last_2blks
    cmp LTMP,#48
    b.eq .Lxts_dec_pre_last_3blks
    cmp LTMP,#64
    b.eq .Lxts_dec_pre_last_4blks
.Lxts_dec_pre_last_1blks:
    eor IN0.16b,IN0.16b,IN4.16b   //in0 = in0 ^ in41
    eor BLK0.16b,BLK0.16b,IN0.16b   // blk0 =  in0 ^ twk0 ^ in0 ^ in4
    fmov TWX0,TWKD00  // reset already computed tweak
    fmov TWX1,TWKD01
    b .Lxts_dec_rounds_1blks
.Lxts_dec_pre_last_2blks:
    eor BLK0.16b,BLK0.16b,IN0.16b
    eor BLK1.16b,BLK1.16b,IN1.16b
    eor BLK0.16b,BLK0.16b,IN3.16b  // in3 -> blk0
    eor BLK1.16b,BLK1.16b,IN4.16b  // in4 -> blk1
    fmov TWX0,TWKD10  // reset already computed tweak
    fmov TWX1,TWKD11
    b .Lxts_dec_rounds_2blks
.Lxts_dec_pre_last_3blks:
    eor BLK0.16b,BLK0.16b,IN0.16b
    eor BLK1.16b,BLK1.16b,IN1.16b
    eor BLK2.16b,BLK2.16b,IN2.16b
    eor BLK0.16b,BLK0.16b,IN2.16b  // in2 -> blk0
    eor BLK1.16b,BLK1.16b,IN3.16b  // in3 -> blk1
    eor BLK2.16b,BLK2.16b,IN4.16b  // in4 -> blk2
    fmov TWX0,TWKD20  // reset already computed tweak
    fmov TWX1,TWKD21
    b .Lxts_dec_rounds_3blks
.Lxts_dec_pre_last_4blks:
    eor BLK0.16b,BLK0.16b,IN0.16b
    eor BLK1.16b,BLK1.16b,IN1.16b
    eor BLK2.16b,BLK2.16b,IN2.16b
    eor BLK3.16b,BLK3.16b,IN3.16b
    sub IN,IN,#16 // have loaded 4blks, using 3blks to process, so step back 1blk here
    eor BLK0.16b,BLK0.16b,IN1.16b  // in1 -> blk0
    eor BLK1.16b,BLK1.16b,IN2.16b  // in2 -> blk1
    eor BLK2.16b,BLK2.16b,IN3.16b  // in3 -> blk2
    eor BLK3.16b,BLK3.16b,IN4.16b  // in4 -> blk3
    fmov TWX0,TWKD20  // reset already computed tweak
    fmov TWX1,TWKD21
    b .Lxts_dec_rounds_3blks

.Lxts_aesdec_finish:
    MOV_REG_TO_VEC(TWX0,TWX1,TWKD00,TWKD01)
    st1 {TWK0.16b}, [TWEAK]

    mov x0, #0

    ldp d14, d15, [sp,#64]
    ldp d12, d13, [sp, #48]
    ldp d10, d11, [sp, #32]
    ldp d8, d9, [sp, #16]
    ldp x29, x30, [sp], #80
AARCH64_AUTIASP
    ret
.size CRYPT_AES_XTS_Decrypt, .-CRYPT_AES_XTS_Decrypt

#endif
