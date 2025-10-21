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
#ifdef HITLS_CRYPTO_SM4

#include "crypt_arm.h"

#define VTMP0 V8
#define VTMP1 V9
#define VTMP2 V10

#define DATA0 V16

#define MaskV      v26
#define TAHMatV    v27
#define TALMatV    v28
#define ATAHMatV   v29
#define ATALMatV   v30
#define ANDMaskV   v31

#define MaskQ      q26
#define TAHMatQ    q27
#define TALMatQ    q28
#define ATAHMatQ   q29
#define ATALMatQ   q30
#define ANDMaskQ   q31

.section .rodata
.align 4
#ifdef HITLS_BIG_ENDIAN
 .qtmp0:
    .quad 0x0101010101010101,0x0101010101010187
.Lsbox_magic:
    .quad 0x0306090c0f020508,0x0b0e0104070a0d00
    .quad 0x22581a6002783a40,0x62185a2042387a00
    .quad 0xc10bb67c4a803df7,0x15df62a89e54e923
    .quad 0x1407c6d56c7fbead,0xb9aa6b78c1d21300
    .quad 0xe383c1a1fe9edcbc,0x6404462679195b3b
    .quad 0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f
#else
 .qtmp0:
    .quad 0x0101010101010187,0x0101010101010101
.Lsbox_magic:
    .quad 0x0b0e0104070a0d00,0x0306090c0f020508
    .quad 0x62185a2042387a00,0x22581a6002783a40
    .quad 0x15df62a89e54e923,0xc10bb67c4a803df7
    .quad 0xb9aa6b78c1d21300,0x1407c6d56c7fbead
    .quad 0x6404462679195b3b,0xe383c1a1fe9edcbc
    .quad 0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f
#endif

.Lck:
    .long 0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269
    .long 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9
    .long 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249
    .long 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9
    .long 0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229
    .long 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299
    .long 0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209
    .long 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
.Lfk:
    .long 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
.Lshuffles:
    .long 0x07060504, 0x0B0A0908, 0x0F0E0D0C, 0x03020100

#ifndef HITLS_BIG_ENDIAN
    #define REV32_EQ(DST, SRC)                             \
        rev32    DST.16b,DST.16b                           ;

#else
    #define REV32_EQ(DST, SRC)                             \
    /*rev32 eq is null in armeb  */                        ;

#endif

.macro LOAD_SBOX_MATRIX
    adrp    x15,.Lsbox_magic
    add x15,x15,:lo12:.Lsbox_magic
    ldr MaskQ,      [x15]
    ldr TAHMatQ,    [x15, #16]
    ldr TALMatQ,    [x15, #32]
    ldr ATAHMatQ,   [x15, #48]
    ldr ATALMatQ,   [x15, #64]
    ldr ANDMaskQ,   [x15, #80]
.endm

/* matrix multiplication Mat*x = (lowerMat*x) ^ (higherMat*x) */
#define MUL_MATRIX(X, HIGHERMAT, LOWERMAT, TMP)            \
    ushr    TMP.16b, X.16b, 4                             ; \
    and     X.16b, X.16b, ANDMaskV.16b                    ; \
    tbl     X.16b, {LOWERMAT.16b}, X.16b                  ; \
    tbl     TMP.16b, {HIGHERMAT.16b}, TMP.16b             ; \
    eor     X.16b, X.16b, TMP.16b                         ;


.arch    armv8-a+crypto
.text
#define USER_KEY x0
#define ROUND_KEY1 x1
#define ENC1 w2

#define POINTER1 x5
#define SCHEDULES x6
#define WTMP w7
#define ROUND_KEY2 w8

#define V_KEY v5
#define V_FK v6
#define V_MAP v7

/*
 * void vpsm4_ex_set_key(const unsigned char *userKey, SM4_KEY *key, int enc);
 * generate sm4 rounk key context
 *   USER_KEY => userKey; 
 *   ROUND_KEY1 => key ; 
 *   if encryption: ENC=>enc
 */
.type    vpsm4_ex_set_key,%function
.align 4
vpsm4_ex_set_key:
AARCH64_PACIASP
    stp x29, x30, [sp, #-0x30]!
    stp d8, d9, [sp, #0x10]
    stp d10, d11, [sp, #0x20]

    ld1 {V_KEY.4s},[USER_KEY]
    LOAD_SBOX_MATRIX
    REV32_EQ(V_KEY,V_KEY)

    adrp POINTER1,.Lshuffles
    add POINTER1,POINTER1,:lo12:.Lshuffles
    ld1 {V_MAP.4s},[POINTER1]
    adrp POINTER1,.Lfk
    add POINTER1,POINTER1,:lo12:.Lfk
    ld1 {V_FK.4s},[POINTER1]
    eor V_KEY.16b,V_KEY.16b,V_FK.16b
    mov SCHEDULES,#32
    adrp POINTER1,.Lck
    add POINTER1,POINTER1,:lo12:.Lck
    movi VTMP0.16b,#64
    cbnz ENC1,1f
    add ROUND_KEY1,ROUND_KEY1,124
1:  // loop
    mov WTMP,V_KEY.s[1]
    ldr ROUND_KEY2,[POINTER1],#4
    eor ROUND_KEY2,ROUND_KEY2,WTMP
    mov WTMP,V_KEY.s[2]
    eor ROUND_KEY2,ROUND_KEY2,WTMP
    mov WTMP,V_KEY.s[3]
    eor ROUND_KEY2,ROUND_KEY2,WTMP
    
    /* optimize sbox using AESE instruction */
    mov DATA0.s[0],ROUND_KEY2
    tbl VTMP0.16b, {DATA0.16b}, MaskV.16b
    MUL_MATRIX(VTMP0, TAHMatV, TALMatV, VTMP2)
    eor VTMP1.16b, VTMP1.16b, VTMP1.16b
    aese VTMP0.16b,VTMP1.16b
    MUL_MATRIX(VTMP0, ATAHMatV, ATALMatV, VTMP2)
    mov WTMP,VTMP0.s[0]
    
    /* linear transformation */
    eor ROUND_KEY2,WTMP,WTMP,ror #19
    eor ROUND_KEY2,ROUND_KEY2,WTMP,ror #9
    mov WTMP,V_KEY.s[0]
    eor ROUND_KEY2,ROUND_KEY2,WTMP
    mov V_KEY.s[0],ROUND_KEY2
    cbz ENC1,2f
    str ROUND_KEY2,[ROUND_KEY1],#4
    b 3f
2:  // set encrypt key
    str ROUND_KEY2,[ROUND_KEY1],#-4
3:  // final
    tbl V_KEY.16b,{V_KEY.16b},V_MAP.16b
    subs SCHEDULES,SCHEDULES,#1
    b.ne 1b
    /*clear register for temp key */
    eor V_KEY.16b, V_KEY.16b, V_KEY.16b
    eor ROUND_KEY2, ROUND_KEY2, ROUND_KEY2
    ldp d10, d11, [sp, #0x20]
    ldp d8, d9, [sp, #0x10]
    ldp x29, x30, [sp], #0x30
AARCH64_AUTIASP
    ret
.size vpsm4_ex_set_key,.-vpsm4_ex_set_key

/*
 * void Vpsm4SetEncryptKey(const unsigned char *userKey, SM4_KEY *key);
 * generate SM4 encrypt round KEY context 
 * x0 => userKey; x1 => key
 */
.globl Vpsm4SetEncryptKey
.type Vpsm4SetEncryptKey,%function
.align 5
Vpsm4SetEncryptKey:
AARCH64_PACIASP
    stp x29,x30,[sp,#-16]!
    mov w2,1
    bl vpsm4_ex_set_key
    ldp x29,x30,[sp],#16
AARCH64_AUTIASP
    ret
.size Vpsm4SetEncryptKey,.-Vpsm4SetEncryptKey

/*
 * void Vpsm4SetDecryptKey(const unsigned char *userKey, SM4_KEY *key);
 * generate SM4 decryption round KEY context 
 * x0 => userKey; x1 => key
 */
.globl Vpsm4SetDecryptKey
.type Vpsm4SetDecryptKey,%function
.align 5
Vpsm4SetDecryptKey:
AARCH64_PACIASP
    stp x29,x30,[sp,#-16]!
    mov w2,0
    bl vpsm4_ex_set_key
    ldp x29,x30,[sp],#16
AARCH64_AUTIASP
    ret
.size Vpsm4SetDecryptKey,.-Vpsm4SetDecryptKey

#endif
