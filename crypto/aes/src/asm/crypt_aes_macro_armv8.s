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

.file    "crypt_aes_macro_armv8.s"
.text
.arch    armv8-a+crypto

BLK0     .req    v0

/*
 * AES_ENC_1_BLKS
 */
.macro AES_ENC_1_BLK key blk rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_enc:
    aese \blk,\rdk0
    aesmc \blk,\blk
    subs \rounds,\rounds,#2
    ld1 {\rdk0s},[\key],#16
    aese \blk,\rdk1
    aesmc \blk,\blk
    ld1 {\rdk1s},[\key],#16
    b.gt .Loop_enc

    aese \blk,\rdk0
    aesmc \blk,\blk
    ld1 {\rdk0s},[\key]
    aese \blk,\rdk1
    eor \blk,\blk,\rdk0
.endm

/*
 * AES_DEC_1_BLKS
 */
.macro  AES_DEC_1_BLK key blk rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_dec:
    aesd \blk,\rdk0
    aesimc \blk,\blk
    subs \rounds,\rounds,#2
    ld1 {\rdk0s},[\key],#16
    aesd \blk,\rdk1
    aesimc \blk,\blk
    ld1 {\rdk1s},[\key],#16
    b.gt .Loop_dec

    aesd \blk,\rdk0
    aesimc \blk,\blk
    ld1 {\rdk0s},[\key]
    aesd \blk,\rdk1
    eor \blk,\blk,\rdk0
.endm

.macro  SETDECKEY_LDR_9_BLOCK PTR
    ld1 {v1.4s}, [\PTR], #16
    ld1 {v2.4s}, [\PTR], #16
    ld1 {v3.4s}, [\PTR], #16
    ld1 {v4.4s}, [\PTR], #16
    ld1 {v5.4s}, [\PTR], #16
    ld1 {v6.4s}, [\PTR], #16
    ld1 {v7.4s}, [\PTR], #16
    ld1 {v8.4s}, [\PTR], #16
    ld1 {v9.4s}, [\PTR], #16
.endm

.macro  SETDECKEY_INVMIX_9_BLOCK
    aesimc v1.16b, v1.16b
    aesimc v2.16b, v2.16b
    aesimc v3.16b, v3.16b
    aesimc v4.16b, v4.16b
    aesimc v5.16b, v5.16b
    aesimc v6.16b, v6.16b
    aesimc v7.16b, v7.16b
    aesimc v8.16b, v8.16b
    aesimc v9.16b, v9.16b
.endm

.macro  SETDECKEY_STR_9_BLOCK PTR OFFSETREG
    st1 {v1.4s}, [\PTR], \OFFSETREG
    st1 {v2.4s}, [\PTR], \OFFSETREG
    st1 {v3.4s}, [\PTR], \OFFSETREG
    st1 {v4.4s}, [\PTR], \OFFSETREG
    st1 {v5.4s}, [\PTR], \OFFSETREG
    st1 {v6.4s}, [\PTR], \OFFSETREG
    st1 {v7.4s}, [\PTR], \OFFSETREG
    st1 {v8.4s}, [\PTR], \OFFSETREG
    st1 {v9.4s}, [\PTR], \OFFSETREG
.endm

/*
 * AES_ENC_2_BLKS
 */
.macro AES_ENC_2_BLKS key blk0 blk1 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_enc_2_blks:
    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk0,\rdk1
    aesmc \blk0,\blk0

    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk1,\rdk1
    aesmc \blk1,\blk1

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_enc_2_blks

    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    ld1 {\rdk0s},[\key]
    aese \blk0,\rdk1
    aese \blk1,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
.endm

/*
 * AES_ENC_3_BLKS
 */
.macro AES_ENC_3_BLKS key blk0 blk1 blk2 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.align 3
.Loop_enc_3_blks:
    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk0,\rdk1
    aesmc \blk0,\blk0

    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk1,\rdk1
    aesmc \blk1,\blk1

    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk2,\rdk1
    aesmc \blk2,\blk2

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_enc_3_blks

    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    ld1 {\rdk0s},[\key]
    aese \blk0,\rdk1
    aese \blk1,\rdk1
    aese \blk2,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
.endm

/*
 * AES_ENC_4_BLKS
 */
.macro AES_ENC_4_BLKS key blk0 blk1 blk2 blk3 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_enc_4_blks:
    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk0,\rdk1
    aesmc \blk0,\blk0

    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk1,\rdk1
    aesmc \blk1,\blk1

    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk2,\rdk1
    aesmc \blk2,\blk2

    aese \blk3,\rdk0
    aesmc \blk3,\blk3
    aese \blk3,\rdk1
    aesmc \blk3,\blk3

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_enc_4_blks

    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk3,\rdk0
    aesmc \blk3,\blk3
    ld1 {\rdk0s},[\key]
    aese \blk0,\rdk1
    aese \blk1,\rdk1
    aese \blk2,\rdk1
    aese \blk3,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
    eor \blk3,\blk3,\rdk0
.endm


/*
 * AES_ENC_5_BLKS
 */
.macro AES_ENC_5_BLKS key blk0 blk1 blk2 blk3 blk4 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_enc_5_blks:
    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk3,\rdk0
    aesmc \blk3,\blk3
    aese \blk4,\rdk0
    aesmc \blk4,\blk4
    ld1 {\rdk0s},[\key],#16
    subs \rounds,\rounds,#2
    aese \blk0,\rdk1
    aesmc \blk0,\blk0

    aese \blk1,\rdk1
    aesmc \blk1,\blk1

    aese \blk2,\rdk1
    aesmc \blk2,\blk2

    aese \blk3,\rdk1
    aesmc \blk3,\blk3

    aese \blk4,\rdk1
    aesmc \blk4,\blk4

    ld1 {\rdk1s},[\key],#16
    b.gt .Loop_enc_5_blks

    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk3,\rdk0
    aesmc \blk3,\blk3
    aese \blk4,\rdk0
    aesmc \blk4,\blk4
    ld1 {\rdk0s},[\key]
    aese \blk0,\rdk1
    aese \blk1,\rdk1
    aese \blk2,\rdk1
    aese \blk3,\rdk1
    aese \blk4,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
    eor \blk3,\blk3,\rdk0
    eor \blk4,\blk4,\rdk0
.endm

/*
 * AES_ENC_6_BLKS
 */
.macro AES_ENC_6_BLKS key blk0 blk1 blk2 blk3 blk4 blk5 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_enc_6_blks:
    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk0,\rdk1
    aesmc \blk0,\blk0

    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk1,\rdk1
    aesmc \blk1,\blk1

    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk2,\rdk1
    aesmc \blk2,\blk2

    aese \blk3,\rdk0
    aesmc \blk3,\blk3
    aese \blk3,\rdk1
    aesmc \blk3,\blk3

    aese \blk4,\rdk0
    aesmc \blk4,\blk4
    aese \blk4,\rdk1
    aesmc \blk4,\blk4

    aese \blk5,\rdk0
    aesmc \blk5,\blk5
    aese \blk5,\rdk1
    aesmc \blk5,\blk5

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_enc_6_blks

    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk3,\rdk0
    aesmc \blk3,\blk3
    aese \blk4,\rdk0
    aesmc \blk4,\blk4
    aese \blk5,\rdk0
    aesmc \blk5,\blk5
    ld1 {\rdk0s},[\key]
    aese \blk0,\rdk1
    aese \blk1,\rdk1
    aese \blk2,\rdk1
    aese \blk3,\rdk1
    aese \blk4,\rdk1
    aese \blk5,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
    eor \blk3,\blk3,\rdk0
    eor \blk4,\blk4,\rdk0
    eor \blk5,\blk5,\rdk0
.endm


/*
 * AES_ENC_7_BLKS
 */
.macro AES_ENC_7_BLKS key blk0 blk1 blk2 blk3 blk4 blk5 blk6 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_enc_7_blks:
    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk0,\rdk1
    aesmc \blk0,\blk0

    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk1,\rdk1
    aesmc \blk1,\blk1

    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk2,\rdk1
    aesmc \blk2,\blk2

    aese \blk3,\rdk0
    aesmc \blk3,\blk3
    aese \blk3,\rdk1
    aesmc \blk3,\blk3

    aese \blk4,\rdk0
    aesmc \blk4,\blk4
    aese \blk4,\rdk1
    aesmc \blk4,\blk4

    aese \blk5,\rdk0
    aesmc \blk5,\blk5
    aese \blk5,\rdk1
    aesmc \blk5,\blk5

    aese \blk6,\rdk0
    aesmc \blk6,\blk6
    aese \blk6,\rdk1
    aesmc \blk6,\blk6

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_enc_7_blks

    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk3,\rdk0
    aesmc \blk3,\blk3
    aese \blk4,\rdk0
    aesmc \blk4,\blk4
    aese \blk5,\rdk0
    aesmc \blk5,\blk5
    aese \blk6,\rdk0
    aesmc \blk6,\blk6
    ld1 {\rdk0s},[\key]
    aese \blk0,\rdk1
    aese \blk1,\rdk1
    aese \blk2,\rdk1
    aese \blk3,\rdk1
    aese \blk4,\rdk1
    aese \blk5,\rdk1
    aese \blk6,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
    eor \blk3,\blk3,\rdk0
    eor \blk4,\blk4,\rdk0
    eor \blk5,\blk5,\rdk0
    eor \blk6,\blk6,\rdk0
.endm

/*
 * AES_ENC_8_BLKS
 */
.macro AES_ENC_8_BLKS key blk0 blk1 blk2 blk3 blk4 blk5 blk6 blk7 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_enc_8_blks:
    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk0,\rdk1
    aesmc \blk0,\blk0

    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk1,\rdk1
    aesmc \blk1,\blk1

    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk2,\rdk1
    aesmc \blk2,\blk2

    aese \blk3,\rdk0
    aesmc \blk3,\blk3
    aese \blk3,\rdk1
    aesmc \blk3,\blk3

    aese \blk4,\rdk0
    aesmc \blk4,\blk4
    aese \blk4,\rdk1
    aesmc \blk4,\blk4

    aese \blk5,\rdk0
    aesmc \blk5,\blk5
    aese \blk5,\rdk1
    aesmc \blk5,\blk5

    aese \blk6,\rdk0
    aesmc \blk6,\blk6
    aese \blk6,\rdk1
    aesmc \blk6,\blk6

    aese \blk7,\rdk0
    aesmc \blk7,\blk7
    aese \blk7,\rdk1
    aesmc \blk7,\blk7

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_enc_8_blks


    aese \blk0,\rdk0
    aesmc \blk0,\blk0
    aese \blk1,\rdk0
    aesmc \blk1,\blk1
    aese \blk2,\rdk0
    aesmc \blk2,\blk2
    aese \blk3,\rdk0
    aesmc \blk3,\blk3
    aese \blk4,\rdk0
    aesmc \blk4,\blk4
    aese \blk5,\rdk0
    aesmc \blk5,\blk5
    aese \blk6,\rdk0
    aesmc \blk6,\blk6
    aese \blk7,\rdk0
    aesmc \blk7,\blk7
    ld1 {\rdk0s},[\key]
    aese \blk0,\rdk1
    aese \blk1,\rdk1
    aese \blk2,\rdk1
    aese \blk3,\rdk1
    aese \blk4,\rdk1
    aese \blk5,\rdk1
    aese \blk6,\rdk1
    aese \blk7,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
    eor \blk3,\blk3,\rdk0
    eor \blk4,\blk4,\rdk0
    eor \blk5,\blk5,\rdk0
    eor \blk6,\blk6,\rdk0
    eor \blk7,\blk7,\rdk0
.endm

/*
 * AES_DEC_2_BLKS
 */
.macro AES_DEC_2_BLKS key blk0 blk1 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_dec_2_blks:
    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk0,\rdk1
    aesimc \blk0,\blk0

    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk1,\rdk1
    aesimc \blk1,\blk1

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_dec_2_blks


    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    ld1 {\rdk0s},[\key]
    aesd \blk0,\rdk1
    aesd \blk1,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
.endm

/*
 * AES_DEC_3_BLKS
 */
.macro AES_DEC_3_BLKS key blk0 blk1 blk2 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.align    3
.Loop_dec_3_blks:
    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk0,\rdk1
    aesimc \blk0,\blk0

    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk1,\rdk1
    aesimc \blk1,\blk1

    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk2,\rdk1
    aesimc \blk2,\blk2

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_dec_3_blks

    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    ld1 {\rdk0s},[\key]
    aesd \blk0,\rdk1
    aesd \blk1,\rdk1
    aesd \blk2,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
.endm

/*
 * AES_DEC_4_BLKS
 */
.macro AES_DEC_4_BLKS key blk0 blk1 blk2 blk3 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_dec_4_blks:
    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk0,\rdk1
    aesimc \blk0,\blk0

    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk1,\rdk1
    aesimc \blk1,\blk1

    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk2,\rdk1
    aesimc \blk2,\blk2

    aesd \blk3,\rdk0
    aesimc \blk3,\blk3
    aesd \blk3,\rdk1
    aesimc \blk3,\blk3

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_dec_4_blks

    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk3,\rdk0
    aesimc \blk3,\blk3
    ld1 {\rdk0s},[\key]
    aesd \blk0,\rdk1
    aesd \blk1,\rdk1
    aesd \blk2,\rdk1
    aesd \blk3,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
    eor \blk3,\blk3,\rdk0
.endm

/*
 * AES_DEC_5_BLKS
 */
.macro AES_DEC_5_BLKS key blk0 blk1 blk2 blk3 blk4 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_dec_5_blks:
    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk0,\rdk1
    aesimc \blk0,\blk0

    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk1,\rdk1
    aesimc \blk1,\blk1

    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk2,\rdk1
    aesimc \blk2,\blk2

    aesd \blk3,\rdk0
    aesimc \blk3,\blk3
    aesd \blk3,\rdk1
    aesimc \blk3,\blk3

    aesd \blk4,\rdk0
    aesimc \blk4,\blk4
    aesd \blk4,\rdk1
    aesimc \blk4,\blk4

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_dec_5_blks

    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk3,\rdk0
    aesimc \blk3,\blk3
    aesd \blk4,\rdk0
    aesimc \blk4,\blk4
    ld1 {\rdk0s},[\key]
    aesd \blk0,\rdk1
    aesd \blk1,\rdk1
    aesd \blk2,\rdk1
    aesd \blk3,\rdk1
    aesd \blk4,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
    eor \blk3,\blk3,\rdk0
    eor \blk4,\blk4,\rdk0
.endm

/*
 * AES_DEC_6_BLKS
 */
.macro AES_DEC_6_BLKS key blk0 blk1 blk2 blk3 blk4 blk5 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_dec_6_blks:
    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk0,\rdk1
    aesimc \blk0,\blk0

    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk1,\rdk1
    aesimc \blk1,\blk1

    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk2,\rdk1
    aesimc \blk2,\blk2

    aesd \blk3,\rdk0
    aesimc \blk3,\blk3
    aesd \blk3,\rdk1
    aesimc \blk3,\blk3

    aesd \blk4,\rdk0
    aesimc \blk4,\blk4
    aesd \blk4,\rdk1
    aesimc \blk4,\blk4

    aesd \blk5,\rdk0
    aesimc \blk5,\blk5
    aesd \blk5,\rdk1
    aesimc \blk5,\blk5

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_dec_6_blks

    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk3,\rdk0
    aesimc \blk3,\blk3
    aesd \blk4,\rdk0
    aesimc \blk4,\blk4
    aesd \blk5,\rdk0
    aesimc \blk5,\blk5
    ld1 {\rdk0s},[\key]
    aesd \blk0,\rdk1
    aesd \blk1,\rdk1
    aesd \blk2,\rdk1
    aesd \blk3,\rdk1
    aesd \blk4,\rdk1
    aesd \blk5,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
    eor \blk3,\blk3,\rdk0
    eor \blk4,\blk4,\rdk0
    eor \blk5,\blk5,\rdk0
.endm

/*
 * AES_DEC_7_BLKS
 */
.macro AES_DEC_7_BLKS key blk0 blk1 blk2 blk3 blk4 blk5 blk6 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.Loop_dec_7_blks:
    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk0,\rdk1
    aesimc \blk0,\blk0

    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk1,\rdk1
    aesimc \blk1,\blk1

    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk2,\rdk1
    aesimc \blk2,\blk2

    aesd \blk3,\rdk0
    aesimc \blk3,\blk3
    aesd \blk3,\rdk1
    aesimc \blk3,\blk3

    aesd \blk4,\rdk0
    aesimc \blk4,\blk4
    aesd \blk4,\rdk1
    aesimc \blk4,\blk4

    aesd \blk5,\rdk0
    aesimc \blk5,\blk5
    aesd \blk5,\rdk1
    aesimc \blk5,\blk5

    aesd \blk6,\rdk0
    aesimc \blk6,\blk6
    aesd \blk6,\rdk1
    aesimc \blk6,\blk6

    ld1 {\rdk0s,\rdk1s},[\key],#32
    subs \rounds,\rounds,#2
    b.gt .Loop_dec_7_blks

    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk3,\rdk0
    aesimc \blk3,\blk3
    aesd \blk4,\rdk0
    aesimc \blk4,\blk4
    aesd \blk5,\rdk0
    aesimc \blk5,\blk5
    aesd \blk6,\rdk0
    aesimc \blk6,\blk6
    ld1 {\rdk0s},[\key]
    aesd \blk0,\rdk1
    aesd \blk1,\rdk1
    aesd \blk2,\rdk1
    aesd \blk3,\rdk1
    aesd \blk4,\rdk1
    aesd \blk5,\rdk1
    aesd \blk6,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
    eor \blk3,\blk3,\rdk0
    eor \blk4,\blk4,\rdk0
    eor \blk5,\blk5,\rdk0
    eor \blk6,\blk6,\rdk0
.endm

/*
 * AES_DEC_8_BLKS
 */
.macro AES_DEC_8_BLKS key blk0 blk1 blk2 blk3 blk4 blk5 blk6 blk7 rdk0s rdk1s rdk0 rdk1 rounds
    ldr \rounds,[\key,#240]
    ld1 {\rdk0s,\rdk1s},[\key],#32
    sub \rounds,\rounds,#2
.align 5
.Loop_dec_8_blks:
    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk5,\rdk0
    aesimc \blk5,\blk5
    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk6,\rdk0
    aesimc \blk6,\blk6
    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk3,\rdk0
    aesimc \blk3,\blk3
    aesd \blk4,\rdk0
    aesimc \blk4,\blk4
    aesd \blk7,\rdk0
    aesimc \blk7,\blk7

    aesd \blk0,\rdk1
    aesimc \blk0,\blk0
    aesd \blk5,\rdk1
    aesimc \blk5,\blk5
    aesd \blk1,\rdk1
    aesimc \blk1,\blk1
    aesd \blk6,\rdk1
    aesimc \blk6,\blk6
    aesd \blk2,\rdk1
    aesimc \blk2,\blk2
    aesd \blk3,\rdk1
    aesimc \blk3,\blk3
    aesd \blk4,\rdk1
    aesimc \blk4,\blk4
    aesd \blk7,\rdk1
    ld1 {\rdk0s, \rdk1s},[\key],#32
    aesimc \blk7,\blk7

    subs \rounds,\rounds,#2
    b.gt .Loop_dec_8_blks

    aesd \blk0,\rdk0
    aesimc \blk0,\blk0
    aesd \blk1,\rdk0
    aesimc \blk1,\blk1
    aesd \blk2,\rdk0
    aesimc \blk2,\blk2
    aesd \blk3,\rdk0
    aesimc \blk3,\blk3
    aesd \blk4,\rdk0
    aesimc \blk4,\blk4
    aesd \blk5,\rdk0
    aesimc \blk5,\blk5
    aesd \blk6,\rdk0
    aesimc \blk6,\blk6
    aesd \blk7,\rdk0
    ld1 {\rdk0s},[\key]
    aesimc \blk7,\blk7

    aesd \blk0,\rdk1
    aesd \blk1,\rdk1
    aesd \blk2,\rdk1
    aesd \blk3,\rdk1
    aesd \blk4,\rdk1
    aesd \blk5,\rdk1
    aesd \blk6,\rdk1
    aesd \blk7,\rdk1
    eor \blk0,\blk0,\rdk0
    eor \blk1,\blk1,\rdk0
    eor \blk2,\blk2,\rdk0
    eor \blk3,\blk3,\rdk0
    eor \blk4,\blk4,\rdk0
    eor \blk5,\blk5,\rdk0
    eor \blk6,\blk6,\rdk0
    eor \blk7,\blk7,\rdk0
.endm

#endif
