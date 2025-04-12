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

.file    "crypt_aes_macro_x86_64.s"

/* AES_ENC_1_BLK */
.macro    AES_ENC_1_BLK    key round rdk blk
.align 16
.Laesenc_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenc  \rdk, \blk
    decl \round
    jnz .Laesenc_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenclast \rdk, \blk
.endm

/* AES_ENC_2_BLKS */
.macro    AES_ENC_2_BLKS    key round rdk blk0 blk1
.align 16
.Laesenc_2_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenc  \rdk, \blk0
    aesenc  \rdk, \blk1
    decl \round
    jnz .Laesenc_2_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenclast \rdk, \blk0
    aesenclast \rdk, \blk1
.endm

/* AES_ENC_3_BLKS */
.macro    AES_ENC_3_BLKS    key round rdk blk0 blk1 blk2
.align 16
.Laesenc_3_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenc  \rdk, \blk0
    aesenc  \rdk, \blk1
    aesenc  \rdk, \blk2
    decl \round
    jnz .Laesenc_3_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenclast \rdk, \blk0
    aesenclast \rdk, \blk1
    aesenclast \rdk, \blk2
.endm

/* AES_ENC_4_BLKS */
.macro    AES_ENC_4_BLKS    key round rdk blk0 blk1 blk2 blk3
.align 16
.Laesenc_4_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenc  \rdk, \blk0
    aesenc  \rdk, \blk1
    aesenc  \rdk, \blk2
    aesenc  \rdk, \blk3
    decl \round
    jnz .Laesenc_4_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenclast \rdk, \blk0
    aesenclast \rdk, \blk1
    aesenclast \rdk, \blk2
    aesenclast \rdk, \blk3
.endm

/* AES_ENC_5_BLKS */
.macro    AES_ENC_5_BLKS    key round rdk blk0 blk1 blk2 blk3 blk4
.align 16
.Laesenc_5_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenc  \rdk, \blk0
    aesenc  \rdk, \blk1
    aesenc  \rdk, \blk2
    aesenc  \rdk, \blk3
    aesenc  \rdk, \blk4
    decl \round
    jnz .Laesenc_5_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenclast \rdk, \blk0
    aesenclast \rdk, \blk1
    aesenclast \rdk, \blk2
    aesenclast \rdk, \blk3
    aesenclast \rdk, \blk4
.endm

/* AES_ENC_6_BLKS */
.macro    AES_ENC_6_BLKS    key round rdk blk0 blk1 blk2 blk3 blk4 blk5
.align 16
.Laesenc_6_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenc  \rdk, \blk0
    aesenc  \rdk, \blk1
    aesenc  \rdk, \blk2
    aesenc  \rdk, \blk3
    aesenc  \rdk, \blk4
    aesenc  \rdk, \blk5
    decl \round
    jnz .Laesenc_6_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenclast \rdk, \blk0
    aesenclast \rdk, \blk1
    aesenclast \rdk, \blk2
    aesenclast \rdk, \blk3
    aesenclast \rdk, \blk4
    aesenclast \rdk, \blk5
.endm

/* AES_ENC_7_BLKS */
.macro    AES_ENC_7_BLKS    key round rdk blk0 blk1 blk2 blk3 blk4 blk5 blk6
.align 16
.Laesenc_7_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenc  \rdk, \blk0
    aesenc  \rdk, \blk1
    aesenc  \rdk, \blk2
    aesenc  \rdk, \blk3
    aesenc  \rdk, \blk4
    aesenc  \rdk, \blk5
    aesenc  \rdk, \blk6
    decl \round
    jnz .Laesenc_7_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenclast \rdk, \blk0
    aesenclast \rdk, \blk1
    aesenclast \rdk, \blk2
    aesenclast \rdk, \blk3
    aesenclast \rdk, \blk4
    aesenclast \rdk, \blk5
    aesenclast \rdk, \blk6
.endm

/* AES_ENC_8_BLKS */
.macro    AES_ENC_8_BLKS    key round rdk blk0 blk1 blk2 blk3 blk4 blk5 blk6 blk7
.align 16
.Laesenc_8_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenc  \rdk, \blk0
    aesenc  \rdk, \blk1
    aesenc  \rdk, \blk2
    aesenc  \rdk, \blk3
    aesenc  \rdk, \blk4
    aesenc  \rdk, \blk5
    aesenc  \rdk, \blk6
    aesenc  \rdk, \blk7
    decl \round
    jnz .Laesenc_8_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenclast \rdk, \blk0
    aesenclast \rdk, \blk1
    aesenclast \rdk, \blk2
    aesenclast \rdk, \blk3
    aesenclast \rdk, \blk4
    aesenclast \rdk, \blk5
    aesenclast \rdk, \blk6
    aesenclast \rdk, \blk7
.endm

/* AES_ENC_14_BLKS */
.macro AES_ENC_14_BLKS    ARG2 key round rdk blk0 blk1 blk2 blk3 blk4 blk5 blk6 blk7 blk8 blk9 blk10 blk11 blk12 blk13
.align 16
.Laesenc_14_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenc  \rdk, \blk0
    aesenc  \rdk, \blk1
    aesenc  \rdk, \blk2
    aesenc  \rdk, \blk3
    aesenc  \rdk, \blk4
    aesenc  \rdk, \blk5
    aesenc  \rdk, \blk6
    aesenc  \rdk, \blk7
    aesenc  \rdk, \blk8
    aesenc  \rdk, \blk9
    aesenc  \rdk, \blk10
    aesenc  \rdk, \blk11
    aesenc  \rdk, \blk12
    aesenc  \rdk, \blk13
    decl \round
    jnz .Laesenc_14_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesenclast \rdk, \blk0
    aesenclast \rdk, \blk1
    aesenclast \rdk, \blk2
    aesenclast \rdk, \blk3
    aesenclast \rdk, \blk4
    aesenclast \rdk, \blk5
    aesenclast \rdk, \blk6
    aesenclast \rdk, \blk7
    aesenclast \rdk, \blk8
    aesenclast \rdk, \blk9
    aesenclast \rdk, \blk10
    aesenclast \rdk, \blk11
    aesenclast \rdk, \blk12
    aesenclast \rdk, \blk13
.endm

/* AES_DEC_1_BLK */
.macro    AES_DEC_1_BLK    key round rdk blk
.align 16
.Laesdec_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdec  \rdk, \blk
    decl \round
    jnz .Laesdec_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdeclast \rdk, \blk
.endm

/* AES_DEC_2_BLKS */
.macro    AES_DEC_2_BLKS    key round rdk blk0 blk1
.align 32
.Laesdec_2_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdec  \rdk, \blk0
    aesdec  \rdk, \blk1
    decl \round
    jnz .Laesdec_2_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdeclast \rdk, \blk0
    aesdeclast \rdk, \blk1
.endm

/* AES_DEC_3_BLKS */
.macro    AES_DEC_3_BLKS    key round rdk blk0 blk1 blk2
.align 16
.Laesdec_3_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdec  \rdk, \blk0
    aesdec  \rdk, \blk1
    aesdec  \rdk, \blk2
    decl \round
    jnz .Laesdec_3_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdeclast \rdk, \blk0
    aesdeclast \rdk, \blk1
    aesdeclast \rdk, \blk2
.endm

/* AES_DEC_4_BLKS */
.macro    AES_DEC_4_BLKS    key round rdk blk0 blk1 blk2 blk3
.align 16
.Laesdec_4_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdec  \rdk, \blk0
    aesdec  \rdk, \blk1
    aesdec  \rdk, \blk2
    aesdec  \rdk, \blk3
    decl \round
    jnz .Laesdec_4_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdeclast \rdk, \blk0
    aesdeclast \rdk, \blk1
    aesdeclast \rdk, \blk2
    aesdeclast \rdk, \blk3
.endm

/* AES_DEC_5_BLKS */
.macro    AES_DEC_5_BLKS    key round rdk blk0 blk1 blk2 blk3 blk4
.align 16
.Laesdec_5_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdec  \rdk, \blk0
    aesdec  \rdk, \blk1
    aesdec  \rdk, \blk2
    aesdec  \rdk, \blk3
    aesdec  \rdk, \blk4
    decl \round
    jnz .Laesdec_5_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdeclast \rdk, \blk0
    aesdeclast \rdk, \blk1
    aesdeclast \rdk, \blk2
    aesdeclast \rdk, \blk3
    aesdeclast \rdk, \blk4
.endm

/* AES_DEC_6_BLKS */
.macro    AES_DEC_6_BLKS    key round rdk blk0 blk1 blk2 blk3 blk4 blk5
.align 16
.Laesdec_6_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdec  \rdk, \blk0
    aesdec  \rdk, \blk1
    aesdec  \rdk, \blk2
    aesdec  \rdk, \blk3
    aesdec  \rdk, \blk4
    aesdec  \rdk, \blk5
    decl \round
    jnz .Laesdec_6_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdeclast \rdk, \blk0
    aesdeclast \rdk, \blk1
    aesdeclast \rdk, \blk2
    aesdeclast \rdk, \blk3
    aesdeclast \rdk, \blk4
    aesdeclast \rdk, \blk5
.endm

/* AES_DEC_7_BLKS */
.macro    AES_DEC_7_BLKS    key round rdk blk0 blk1 blk2 blk3 blk4 blk5 blk6
.align 16
.Laesdec_7_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdec  \rdk, \blk0
    aesdec  \rdk, \blk1
    aesdec  \rdk, \blk2
    aesdec  \rdk, \blk3
    aesdec  \rdk, \blk4
    aesdec  \rdk, \blk5
    aesdec  \rdk, \blk6
    decl \round
    jnz .Laesdec_7_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdeclast \rdk, \blk0
    aesdeclast \rdk, \blk1
    aesdeclast \rdk, \blk2
    aesdeclast \rdk, \blk3
    aesdeclast \rdk, \blk4
    aesdeclast \rdk, \blk5
    aesdeclast \rdk, \blk6
.endm

/* AES_DEC_8_BLKS */
.macro    AES_DEC_8_BLKS    key round rdk blk0 blk1 blk2 blk3 blk4 blk5 blk6 blk7

.align 16
.Laesdec_8_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdec  \rdk, \blk0
    aesdec  \rdk, \blk1
    aesdec  \rdk, \blk2
    aesdec  \rdk, \blk3
    aesdec  \rdk, \blk4
    aesdec  \rdk, \blk5
    aesdec  \rdk, \blk6
    aesdec  \rdk, \blk7
    decl \round
    jnz .Laesdec_8_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdeclast \rdk, \blk0
    aesdeclast \rdk, \blk1
    aesdeclast \rdk, \blk2
    aesdeclast \rdk, \blk3
    aesdeclast \rdk, \blk4
    aesdeclast \rdk, \blk5
    aesdeclast \rdk, \blk6
    aesdeclast \rdk, \blk7
.endm

/* AES_DEC_14_BLKS */
.macro    AES_DEC_14_BLKS    key round rdk blk0 blk1 blk2 blk3 blk4 blk5 blk6 blk7 blk8 blk9 blk10 blk11 blk12 blk13
.align 16
.Laesdec_14_blks_loop:
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdec  \rdk, \blk0
    aesdec  \rdk, \blk1
    aesdec  \rdk, \blk2
    aesdec  \rdk, \blk3
    aesdec  \rdk, \blk4
    aesdec  \rdk, \blk5
    aesdec  \rdk, \blk6
    aesdec  \rdk, \blk7
    aesdec  \rdk, \blk8
    aesdec  \rdk, \blk9
    aesdec  \rdk, \blk10
    aesdec  \rdk, \blk11
    aesdec  \rdk, \blk12
    aesdec  \rdk, \blk13
    decl \round
    jnz .Laesdec_14_blks_loop
    leaq 16(\key), \key
    movdqu (\key), \rdk
    aesdeclast \rdk, \blk0
    aesdeclast \rdk, \blk1
    aesdeclast \rdk, \blk2
    aesdeclast \rdk, \blk3
    aesdeclast \rdk, \blk4
    aesdeclast \rdk, \blk5
    aesdeclast \rdk, \blk6
    aesdeclast \rdk, \blk7
    aesdeclast \rdk, \blk8
    aesdeclast \rdk, \blk9
    aesdeclast \rdk, \blk10
    aesdeclast \rdk, \blk11
    aesdeclast \rdk, \blk12
    aesdeclast \rdk, \blk13
.endm

#endif
