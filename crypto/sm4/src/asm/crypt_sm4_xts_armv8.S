#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#define INP  X0
#define OUTP X1
#define RKS1 X3
#define IVP  X5
#define ENC  X6

#define BLOCKS X2
#define LEN    X2
#define REMAIN X7

#define TWX0 X8
#define TWX1 X9
#define TWX2 X10
#define TWX3 X11
#define TWX4 X12
#define TWX5 X13
#define TWX6 X14
#define TWX7 X15
#define TWX8 X16
#define TWX9 X17
#define TWX10 X18
#define TWX11 X19
#define TWX12 X20
#define TWX13 X21
#define TWX14 X22
#define TWX15 X23

#define PTR X24
#define COUNTER W25

#define WTMP0  W27
#define WTMP1  W28
#define WTMP2  W29
#define WTMP3  W30

#define XTMP1  X28
#define XTMP2  X29

#define WORD0  W20
#define WORD1  W21
#define WORD2  W22
#define WORD3  W23

#define LAST_BLK X26

#define TWEAK0 V0
#define TWEAK1 V1
#define TWEAK2 V2
#define TWEAK3 V3
#define TWEAK4 V4
#define TWEAK5 V5
#define TWEAK6 V6
#define TWEAK7 V7

#define QTMP0 Q8

#define VTMP0 V8
#define VTMP1 V9
#define VTMP2 V10
#define VTMP3 V11

#define RK0 V12
#define RK1 V13
#define RK_A V14
#define RK_B V15

#define DATA0 V16
#define DATA1 V17
#define DATA2 V18
#define DATA3 V19

#define DATAX0 V20
#define DATAX1 V21
#define DATAX2 V22
#define DATAX3 V23

#define VTMP4 V24
#define VTMP5 V25
#define LAST_TWEAK V25

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

#define SAVE_STACK()                        \
    stp x15, x16, [sp, #-0x10]!   ; \
    stp x17, x18, [sp, #-0x10]!   ; \
    stp x19, x20, [sp, #-0x10]!   ; \
    stp x21, x22, [sp, #-0x10]!   ; \
    stp x23, x24, [sp, #-0x10]!   ; \
    stp x25, x26, [sp, #-0x10]!   ; \
    stp x27, x28, [sp, #-0x10]!   ; \
    stp x29, x30, [sp, #-0x10]!   ; \
    stp d8, d9, [sp, #-0x10]!     ; \
    stp d10, d11, [sp, #-0x10]!   ; \
    stp d12, d13, [sp, #-0x10]!   ; \
    stp d14, d15, [sp, #-0x10]!   ;

#define LOAD_STACK()                \
    ldp d14, d15, [sp], #0x10     ; \
    ldp d12, d13, [sp], #0x10     ; \
    ldp d10, d11, [sp], #0x10     ; \
    ldp d8, d9, [sp], #0x10       ; \
    ldp x29, x30, [sp], #0x10     ; \
    ldp x27, x28, [sp], #0x10     ; \
    ldp x25, x26, [sp], #0x10     ; \
    ldp x23, x24, [sp], #0x10     ; \
    ldp x21, x22, [sp], #0x10     ; \
    ldp x19, x20, [sp], #0x10     ; \
    ldp x17, x18, [sp], #0x10     ; \
    ldp x15, x16, [sp], #0x10     ;

#ifdef HITLS_BIG_ENDIAN
    #define MOV_REG_TO_VEC(SRC0, SRC1, DESV)        \
        mov DESV.d[0],SRC0                        ; \
        mov DESV.d[1],SRC1                        ; \
        rev32  DESV.16b,DESV.16b                  ;
#else
    #define MOV_REG_TO_VEC(SRC0, SRC1, DESV)        \
        mov DESV.d[0],SRC0                        ; \
        mov DESV.d[1],SRC1                        ;
#endif

#define MOV_VEC_TO_REG(SRCV, DES0, DES1)        \
    mov DES0,SRCV.d[0]                        ; \
    mov DES1,SRCV.d[1]                        ;

#define COMPUTE_ALPHA(SRC0, SRC1, DES0, DES1)    \
    mov WTMP0,0x87                               ; \
    extr    XTMP2,SRC1,SRC1,#32                  ; \
    extr    DES1,SRC1,SRC0,#63                   ; \
    and    WTMP1,WTMP0,WTMP2,asr#31              ; \
    eor    DES0,XTMP1,SRC0,lsl#1                 ;

#ifdef HITLS_BIG_ENDIAN
 .qtmp0:
    .dword 0x0101010101010101,0x0101010101010187
#else
 .qtmp0:
    .dword 0x0101010101010187,0x0101010101010101
#endif

#define COMPUTE_ALPHA_VEC(SRC, DES)                    \
    ldr  QTMP0, .qtmp0                                ; \
    rbit VTMP2.16b,SRC.16b                            ; \
    shl  DES.16b, VTMP2.16b, #1                       ; \
    ext  VTMP1.16b, VTMP2.16b, VTMP2.16b,#15          ; \
    ushr VTMP1.16b, VTMP1.16b, #7                     ; \
    mul  VTMP1.16b, VTMP1.16b, VTMP0.16b              ; \
    eor  DES.16b, DES.16b, VTMP1.16b                  ; \
    rbit DES.16b,DES.16b                              ;

#ifndef HITLS_BIG_ENDIAN
    #define REV32(DST, SRC)                                \
        rev32    DST.16b,SRC.16b                           ;

    #define REV32_EQ(DST, SRC)                             \
        rev32    DST.16b,DST.16b                           ;

    #define REV32_ARMEB_EQ(DST, SRC)                       \
    /*rev32_armeb eq is null if not in  armeb  */          ;

#else
    #define REV32(DST, SRC)                                \
        mov    DST.16b,SRC.16b                             ;

    #define REV32_EQ(DST, SRC)                             \
    /*rev32 eq is null in armeb  */                        ;

    #define REV32_ARMEB_EQ(DST, SRC)                       \
        rev32    DST.16b,DST.16b                           ;

#endif

#define TRANSPOSE(DAT0,DAT1,DAT2,DAT3,VT0,VT1,VT2,VT3)    \
    zip1    VT0.4s,DAT0.4s,DAT1.4s                      ; \
    zip2    VT1.4s,DAT0.4s,DAT1.4s                      ; \
    zip1    VT2.4s,DAT2.4s,DAT3.4s                      ; \
    zip2    VT3.4s,DAT2.4s,DAT3.4s                      ; \
    zip1    DAT0.2d,VT0.2d,VT2.2d                       ; \
    zip2    DAT1.2d,VT0.2d,VT2.2d                       ; \
    zip1    DAT2.2d,VT1.2d,VT3.2d                       ; \
    zip2    DAT3.2d,VT1.2d,VT3.2d                       ;

/* sbox operations for 4-lane of words */
#define SBOX(DAT)                                          \
    /* optimize sbox using AESE instruction */           ; \
    tbl    VTMP0.16b, {DAT.16b}, MaskV.16b               ; \
                                                         ; \
    MUL_MATRIX(VTMP0, TAHMatV, TALMatV, VTMP4)           ; \
                                                         ; \
    eor VTMP1.16b, VTMP1.16b, VTMP1.16b                  ; \
    aese VTMP0.16b,VTMP1.16b                             ; \
                                                         ; \
    MUL_MATRIX(VTMP0, ATAHMatV, ATALMatV, VTMP4)         ; \
                                                         ; \
    mov  DAT.16b,VTMP0.16b                               ; \
                                                         ; \
    /* linear transformation */                          ; \
    ushr    VTMP0.4s,DAT.4s,32-2                         ; \
    ushr    VTMP1.4s,DAT.4s,32-10                        ; \
    ushr    VTMP2.4s,DAT.4s,32-18                        ; \
    ushr    VTMP3.4s,DAT.4s,32-24                        ; \
    sli    VTMP0.4s,DAT.4s,2                             ; \
    sli    VTMP1.4s,DAT.4s,10                            ; \
    sli    VTMP2.4s,DAT.4s,18                            ; \
    sli    VTMP3.4s,DAT.4s,24                            ; \
    eor    VTMP4.16b,VTMP0.16b,DAT.16b                   ; \
    eor    VTMP4.16b,VTMP4.16b,VTMP1.16b                 ; \
    eor    DAT.16b,VTMP2.16b,VTMP3.16b                   ; \
    eor    DAT.16b,DAT.16b,VTMP4.16b                     ;

/* sbox operation for 8-lane of words */
#define SBOX_DOUBLE(DAT, DATX)                             \
    /* optimize sbox using AESE instruction */           ; \
    tbl    VTMP0.16b, {DAT.16b}, MaskV.16b               ; \
    tbl    VTMP1.16b, {DATX.16b}, MaskV.16b              ; \
                                                         ; \
    MUL_MATRIX(VTMP0, TAHMatV, TALMatV, VTMP4)           ; \
    MUL_MATRIX(VTMP1, TAHMatV, TALMatV, VTMP4)           ; \
                                                         ; \
    eor VTMP5.16b, VTMP5.16b, VTMP5.16b                  ; \
    aese VTMP0.16b,VTMP5.16b                             ; \
    aese VTMP1.16b,VTMP5.16b                             ; \
                                                         ; \
    MUL_MATRIX(VTMP0, ATAHMatV, ATALMatV,VTMP4)          ; \
    MUL_MATRIX(VTMP1, ATAHMatV, ATALMatV,VTMP4)          ; \
                                                         ; \
    mov    DAT.16b,VTMP0.16b                             ; \
    mov    DATX.16b,VTMP1.16b                            ; \
                                                         ; \
    /* linear transformation */                          ; \
    ushr    VTMP0.4s,DAT.4s,32-2                         ; \
    ushr    VTMP5.4s,DATX.4s,32-2                        ; \
    ushr    VTMP1.4s,DAT.4s,32-10                        ; \
    ushr    VTMP2.4s,DAT.4s,32-18                        ; \
    ushr    VTMP3.4s,DAT.4s,32-24                        ; \
    sli    VTMP0.4s,DAT.4s,2                             ; \
    sli    VTMP5.4s,DATX.4s,2                            ; \
    sli    VTMP1.4s,DAT.4s,10                            ; \
    sli    VTMP2.4s,DAT.4s,18                            ; \
    sli    VTMP3.4s,DAT.4s,24                            ; \
    eor    VTMP4.16b,VTMP0.16b,DAT.16b                   ; \
    eor    VTMP4.16b,VTMP4.16b,VTMP1.16b                 ; \
    eor    DAT.16b,VTMP2.16b,VTMP3.16b                   ; \
    eor    DAT.16b,DAT.16b,VTMP4.16b                     ; \
                                                         ; \
    ushr    VTMP1.4s,DATX.4s,32-10                       ; \
    ushr    VTMP2.4s,DATX.4s,32-18                       ; \
    ushr    VTMP3.4s,DATX.4s,32-24                       ; \
    sli    VTMP1.4s,DATX.4s,10                           ; \
    sli    VTMP2.4s,DATX.4s,18                           ; \
    sli    VTMP3.4s,DATX.4s,24                           ; \
    eor    VTMP4.16b,VTMP5.16b,DATX.16b                  ; \
    eor    VTMP4.16b,VTMP4.16b,VTMP1.16b                 ; \
    eor    DATX.16b,VTMP2.16b,VTMP3.16b                  ; \
    eor    DATX.16b,DATX.16b,VTMP4.16b                   ;

/* sbox operation for one single word */
#define SBOX_1WORD(WORD)                                   \
    mov    VTMP3.s[0],WORD                               ; \
    /*optimize sbox using AESE instruction */            ; \
    tbl    VTMP0.16b, {VTMP3.16b}, MaskV.16b             ; \
                                                         ; \
    MUL_MATRIX(VTMP0, TAHMatV, TALMatV, VTMP2)           ; \
    eor VTMP1.16b, VTMP1.16b, VTMP1.16b                  ; \
    aese VTMP0.16b,VTMP1.16b                             ; \
                                                         ; \
    MUL_MATRIX(VTMP0, ATAHMatV, ATALMatV, VTMP2)         ; \
                                                         ; \
    mov    WTMP0,VTMP0.s[0]                              ; \
    eor    WORD,WTMP0,WTMP0,ror #32-2                    ; \
    eor    WORD,WORD,WTMP0,ror #32-10                    ; \
    eor    WORD,WORD,WTMP0,ror #32-18                    ; \
    eor    WORD,WORD,WTMP0,ror #32-24                    ;

/* sm4 for one block of data, in scalar registers word0/word1/word2/word3 */
#define SM4_1BLK(K_PTR)                                    \
    ldp    WTMP0,WTMP1,[K_PTR],8                         ; \
                                                         ; \
    /* B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0) */                 ; \
    eor    WTMP3,WORD2,WORD3                             ; \
    eor    WTMP2,WTMP0,WORD1                             ; \
    eor    WTMP3,WTMP3,WTMP2                             ; \
    SBOX_1WORD(WTMP3)                                    ; \
    eor    WORD0,WORD0,WTMP3                             ; \
                                                         ; \
    /* B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1) */                 ; \
    eor    WTMP3,WORD2,WORD3                             ; \
    eor    WTMP2,WORD0,WTMP1                             ; \
    eor    WTMP3,WTMP3,WTMP2                             ; \
    SBOX_1WORD(WTMP3)                                    ; \
    ldp    WTMP0,WTMP1,[K_PTR],8                         ; \
    eor    WORD1,WORD1,WTMP3                             ; \
                                                         ; \
    /* B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2) */                 ; \
    eor    WTMP3,WORD0,WORD1                             ; \
    eor    WTMP2,WTMP0,WORD3                             ; \
    eor    WTMP3,WTMP3,WTMP2                             ; \
    SBOX_1WORD(WTMP3)                                    ; \
    eor    WORD2,WORD2,WTMP3                             ; \
                                                         ; \
    /* B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3) */                 ; \
    eor    WTMP3,WORD0,WORD1                             ; \
    eor    WTMP2,WORD2,WTMP1                             ; \
    eor    WTMP3,WTMP3,WTMP2                             ; \
    SBOX_1WORD(WTMP3)                                    ; \
    eor    WORD3,WORD3,WTMP3                             ;

/* sm4 for 4-lanes of data, in neon registers data0/data1/data2/data3 */
#define SM4_4BLKS(K_PTR)                                 \
    ldp    WTMP0,WTMP1,[K_PTR],8                         ; \
    dup    RK0.4s,WTMP0                                  ; \
    dup    RK1.4s,WTMP1                                  ; \
                                                         ; \
    /* B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0) */                 ; \
    eor    RK_A.16b,DATA2.16b,DATA3.16b                  ; \
    eor    RK0.16b,DATA1.16b,RK0.16b                     ; \
    eor    RK0.16b,RK_A.16b,RK0.16b                      ; \
    SBOX(RK0)                                            ; \
    eor    DATA0.16b,DATA0.16b,RK0.16b                   ; \
                                                         ; \
    /* B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1) */                 ; \
    eor    RK_A.16b,RK_A.16b,DATA0.16b                   ; \
    eor    RK1.16b,RK_A.16b,RK1.16b                      ; \
    SBOX(RK1)                                            ; \
    ldp    WTMP0,WTMP1,[K_PTR],8                         ; \
    eor    DATA1.16b,DATA1.16b,RK1.16b                   ; \
                                                         ; \
    dup    RK0.4s,WTMP0                                  ; \
    dup    RK1.4s,WTMP1                                  ; \
                                                         ; \
    /* B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2) */                 ; \
    eor    RK_A.16b,DATA0.16b,DATA1.16b                  ; \
    eor    RK0.16b,DATA3.16b,RK0.16b                     ; \
    eor    RK0.16b,RK_A.16b,RK0.16b                      ; \
    SBOX(RK0)                                            ; \
    eor    DATA2.16b,DATA2.16b,RK0.16b                   ; \
                                                         ; \
    /* B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3) */                 ; \
    eor    RK_A.16b,RK_A.16b,DATA2.16b                   ; \
    eor    RK1.16b,RK_A.16b,RK1.16b                      ; \
    SBOX(RK1)                                            ; \
    eor    DATA3.16b,DATA3.16b,RK1.16b                   ;

/* sm4 for 8 lanes of data, in neon registers */
/* data0/data1/data2/data3 datax0/datax1/datax2/datax3 */
#define SM4_8BLKS(K_PTR)                                   \
    ldp    WTMP0,WTMP1,[K_PTR],8                         ; \
                                                         ; \
    /* B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0) */                 ; \
    dup    RK0.4s,WTMP0                                  ; \
    eor    RK_A.16b,DATA2.16b,DATA3.16b                  ; \
    eor    RK_B.16b,DATAX2.16b,DATAX3.16b                ; \
    eor    VTMP0.16b,DATA1.16b,RK0.16b                   ; \
    eor    VTMP1.16b,DATAX1.16b,RK0.16b                  ; \
    eor    RK0.16b,RK_A.16b,VTMP0.16b                    ; \
    eor    RK1.16b,RK_B.16b,VTMP1.16b                    ; \
    SBOX_DOUBLE(RK0,RK1)                                 ; \
                                                         ; \
    eor    DATA0.16b,DATA0.16b,RK0.16b                   ; \
    eor    DATAX0.16b,DATAX0.16b,RK1.16b                 ; \
                                                         ; \
    /* B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1) */                 ; \
    dup    RK1.4s,WTMP1                                  ; \
    eor    RK_A.16b,RK_A.16b,DATA0.16b                   ; \
    eor    RK_B.16b,RK_B.16b,DATAX0.16b                  ; \
    eor    RK0.16b,RK_A.16b,RK1.16b                      ; \
    eor    RK1.16b,RK_B.16b,RK1.16b                      ; \
    SBOX_DOUBLE(RK0,RK1)                                 ; \
                                                         ; \
    ldp    WTMP0,WTMP1,[K_PTR],8                         ; \
    eor    DATA1.16b,DATA1.16b,RK0.16b                   ; \
    eor    DATAX1.16b,DATAX1.16b,RK1.16b                 ; \
                                                         ; \
    /* B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2) */                 ; \
    dup    RK0.4s,WTMP0                                  ; \
    eor    RK_A.16b,DATA0.16b,DATA1.16b                  ; \
    eor    RK_B.16b,DATAX0.16b,DATAX1.16b                ; \
    eor    VTMP0.16b,DATA3.16b,RK0.16b                   ; \
    eor    VTMP1.16b,DATAX3.16b,RK0.16b                  ; \
    eor    RK0.16b,RK_A.16b,VTMP0.16b                    ; \
    eor    RK1.16b,RK_B.16b,VTMP1.16b                    ; \
    SBOX_DOUBLE(RK0,RK1)                                 ; \
    eor    DATA2.16b,DATA2.16b,RK0.16b                   ; \
    eor    DATAX2.16b,DATAX2.16b,RK1.16b                 ; \
                                                         ; \
    /* B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3) */                 ; \
    dup    RK1.4s,WTMP1                                  ; \
    eor    RK_A.16b,RK_A.16b,DATA2.16b                   ; \
    eor    RK_B.16b,RK_B.16b,DATAX2.16b                  ; \
    eor    RK0.16b,RK_A.16b,RK1.16b                      ; \
    eor    RK1.16b,RK_B.16b,RK1.16b                      ; \
    SBOX_DOUBLE(RK0,RK1)                                 ; \
    eor    DATA3.16b,DATA3.16b,RK0.16b                   ; \
    eor    DATAX3.16b,DATAX3.16b,RK1.16b                 ;

#define ENCRYPT_1BLK_NOREV(DAT, RKS)                       \
    mov    PTR,RKS                                       ; \
    mov    COUNTER,#8                                    ; \
    mov    WORD0,DAT.s[0]                                ; \
    mov    WORD1,DAT.s[1]                                ; \
    mov    WORD2,DAT.s[2]                                ; \
    mov    WORD3,DAT.s[3]                                ; \
10:                                                        \
    /* loop begin */                                     ; \
    SM4_1BLK(PTR)                                        ; \
    subs    COUNTER,COUNTER,#1                           ; \
    b.ne    10b                                          ; \
    mov    DAT.s[0],WORD3                                ; \
    mov    DAT.s[1],WORD2                                ; \
    mov    DAT.s[2],WORD1                                ; \
    mov    DAT.s[3],WORD0                                ;

#define ENCRYPT_1BLK(DAT, RKS)       \
    ENCRYPT_1BLK_NOREV(DAT,RKS)    ; \
    REV32_EQ(DAT,DAT)              ;

#define ENCRYPT_4BLKS()             \
    mov    PTR,RKS1               ; \
    mov    COUNTER,#8             ; \
10:                                 \
    /* loop begin */              ; \
    SM4_4BLKS(PTR)                ; \
    subs    COUNTER,COUNTER,#1    ; \
    b.ne    10b                   ; \
    REV32(VTMP3,DATA0)            ; \
    REV32(VTMP2,DATA1)            ; \
    REV32(VTMP1,DATA2)            ; \
    REV32(VTMP0,DATA3)            ;

#define ENCRYPT_8BLKS(RKS)                  \
    mov    PTR,RKS                         ; \
    mov    COUNTER,#8                      ; \
10:                                          \
    /* loop begin */                       ; \
    SM4_8BLKS(PTR)                         ; \
    subs    COUNTER,COUNTER,#1             ; \
    b.ne    10b                            ; \
    REV32(VTMP3,DATA0)                     ; \
    REV32(VTMP2,DATA1)                     ; \
    REV32(VTMP1,DATA2)                     ; \
    REV32(VTMP0,DATA3)                     ; \
    REV32(DATA3,DATAX0)                    ; \
    REV32(DATA2,DATAX1)                    ; \
    REV32(DATA1,DATAX2)                    ; \
    REV32(DATA0,DATAX3)                    ;

.macro LOAD_SBOX_MATRIX
    ldr MaskQ,      .Lsbox_magic
    ldr TAHMatQ,    .Lsbox_magic+16
    ldr TALMatQ,    .Lsbox_magic+32
    ldr ATAHMatQ,   .Lsbox_magic+48
    ldr ATALMatQ,   .Lsbox_magic+64
    ldr ANDMaskQ,   .Lsbox_magic+80
.endm

#ifdef HITLS_BIG_ENDIAN
.Lsbox_magic:
    .dword 0x0306090c0f020508,0x0b0e0104070a0d00
    .dword 0x22581a6002783a40,0x62185a2042387a00
    .dword 0xc10bb67c4a803df7,0x15df62a89e54e923
    .dword 0x1407c6d56c7fbead,0xb9aa6b78c1d21300
    .dword 0xe383c1a1fe9edcbc,0x6404462679195b3b
    .dword 0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f
#else
.Lsbox_magic:
    .dword 0x0b0e0104070a0d00,0x0306090c0f020508
    .dword 0x62185a2042387a00,0x22581a6002783a40
    .dword 0x15df62a89e54e923,0xc10bb67c4a803df7
    .dword 0xb9aa6b78c1d21300,0x1407c6d56c7fbead
    .dword 0x6404462679195b3b,0xe383c1a1fe9edcbc
    .dword 0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f
#endif

/* matrix multiplication Mat*x = (lowerMat*x) ^ (higherMat*x) */
#define MUL_MATRIX(X, HIGHERMAT, LOWERMAT, TMP)            \
    ushr    TMP.16b, X.16b, 4                             ; \
    and     X.16b, X.16b, ANDMaskV.16b                    ; \
    tbl     X.16b, {LOWERMAT.16b}, X.16b                  ; \
    tbl     TMP.16b, {HIGHERMAT.16b}, TMP.16b             ; \
    eor     X.16b, X.16b, TMP.16b                         ;


.arch    armv8-a+crypto
.text

.type	vpsm4_ex_consts,%object
.align	7
vpsm4_ex_consts:
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
 
.size	vpsm4_ex_consts,.-vpsm4_ex_consts

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
 *   if encryption：ENC=>enc
 */
.type    vpsm4_ex_set_key,%function
.align 4
vpsm4_ex_set_key:
    ld1 {V_KEY.4s},[USER_KEY]
    LOAD_SBOX_MATRIX
    REV32_EQ(V_KEY,V_KEY)
    adr POINTER1,.Lshuffles
    ld1 {V_MAP.4s},[POINTER1]
    adr POINTER1,.Lfk
    ld1 {V_FK.4s},[POINTER1]
    eor V_KEY.16b,V_KEY.16b,V_FK.16b
    mov SCHEDULES,#32
    adr POINTER1,.Lck
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
    ret
.size vpsm4_ex_set_key,.-vpsm4_ex_set_key

/*
 * void vpsm4_ex_enc_4blks();
 * encrypt four blocks
 * use RSK1 register as user key
 */
.type    vpsm4_ex_enc_4blks,%function
.align    4
vpsm4_ex_enc_4blks:
    ENCRYPT_4BLKS()
    ret
.size    vpsm4_ex_enc_4blks,.-vpsm4_ex_enc_4blks

/*
 * void vpsm4_ex_enc_8blks();
 * encrypt eight blocks
 * use RSK1 register as user key
 */
.type    vpsm4_ex_enc_8blks,%function
.align    4
vpsm4_ex_enc_8blks:
    ENCRYPT_8BLKS(RKS1)
    ret
.size    vpsm4_ex_enc_8blks,.-vpsm4_ex_enc_8blks

/*
 * void Vpsm4SetEncryptKey(const unsigned char *userKey, SM4_KEY *key);
 * generate SM4 encrypt round KEY context 
 * x0 => userKey; x1 => key
 */
.globl Vpsm4SetEncryptKey
.type Vpsm4SetEncryptKey,%function
.align 5
Vpsm4SetEncryptKey:
    stp x29,x30,[sp,#-16]!
    mov w2,1
    bl vpsm4_ex_set_key
    ldp x29,x30,[sp],#16
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
    stp x29,x30,[sp,#-16]!
    mov w2,0
    bl vpsm4_ex_set_key
    ldp x29,x30,[sp],#16
    ret
.size Vpsm4SetDecryptKey,.-Vpsm4SetDecryptKey


/*
 * void Vpsm4XtsCipher(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
                          const SM4_KEY *key2, const uint8_t *iv, int env);
 *  encryption and decryption for sm4-xts, use ENC regsiter as ecrypt direction flag
 * INP => in; OUTP => out; LEN => length; RKS1 => key1; IVP => iv; ENC=>enc
 */
.globl    Vpsm4XtsCipher
.type    Vpsm4XtsCipher,%function
.align    5
Vpsm4XtsCipher:
    SAVE_STACK()
    ld1    {TWEAK0.4s}, [IVP]
    LOAD_SBOX_MATRIX

    and    REMAIN,LEN,#0x0F
    // convert length into blocks
    lsr    BLOCKS,LEN,4
    cmp    BLOCKS,#1
    b.lt .return

    cmp REMAIN,0
    // If the encryption/decryption Length is N times of 16,
    // the all blocks are encrypted/decrypted in .xts_encrypt_blocks
    b.eq .xts_encrypt_blocks

    // If the encryption/decryption length is not N times of 16,
    // the last two blocks are encrypted/decrypted in .last_2blks_tweak or .only_2blks_tweak
    // the other blocks are encrypted/decrypted in .xts_encrypt_blocks
    subs BLOCKS,BLOCKS,#1
    b.eq .only_2blks_tweak

.xts_encrypt_blocks:
    rbit TWEAK0.16b,TWEAK0.16b

    REV32_ARMEB_EQ(TWEAK0,TWEAK0)
    MOV_VEC_TO_REG(TWEAK0,TWX0,TWX1)
    COMPUTE_ALPHA(TWX0,TWX1,TWX2,TWX3)
    COMPUTE_ALPHA(TWX2,TWX3,TWX4,TWX5)
    COMPUTE_ALPHA(TWX4,TWX5,TWX6,TWX7)
    COMPUTE_ALPHA(TWX6,TWX7,TWX8,TWX9)
    COMPUTE_ALPHA(TWX8,TWX9,TWX10,TWX11)
    COMPUTE_ALPHA(TWX10,TWX11,TWX12,TWX13)
    COMPUTE_ALPHA(TWX12,TWX13,TWX14,TWX15)

.Lxts_8_blocks_process:
    cmp    BLOCKS,#8
    MOV_REG_TO_VEC(TWX0,TWX1,TWEAK0)
    COMPUTE_ALPHA(TWX14,TWX15,TWX0,TWX1)
    MOV_REG_TO_VEC(TWX2,TWX3,TWEAK1)
    COMPUTE_ALPHA(TWX0,TWX1,TWX2,TWX3)
    MOV_REG_TO_VEC(TWX4,TWX5,TWEAK2)
    COMPUTE_ALPHA(TWX2,TWX3,TWX4,TWX5)
    MOV_REG_TO_VEC(TWX6,TWX7,TWEAK3)
    COMPUTE_ALPHA(TWX4,TWX5,TWX6,TWX7)
    MOV_REG_TO_VEC(TWX8,TWX9,TWEAK4)
    COMPUTE_ALPHA(TWX6,TWX7,TWX8,TWX9)
    MOV_REG_TO_VEC(TWX10,TWX11,TWEAK5)
    COMPUTE_ALPHA(TWX8,TWX9,TWX10,TWX11)
    MOV_REG_TO_VEC(TWX12,TWX13,TWEAK6)
    COMPUTE_ALPHA(TWX10,TWX11,TWX12,TWX13)
    MOV_REG_TO_VEC(TWX14,TWX15,TWEAK7)
    COMPUTE_ALPHA(TWX12,TWX13,TWX14,TWX15)

    b.lt    .Lxts_4_blocks_process
    ld1 {DATA0.4s,DATA1.4s,DATA2.4s,DATA3.4s},[INP],#64
    rbit TWEAK0.16b,TWEAK0.16b
    rbit TWEAK1.16b,TWEAK1.16b
    rbit TWEAK2.16b,TWEAK2.16b
    rbit TWEAK3.16b,TWEAK3.16b
    eor DATA0.16b, DATA0.16b, TWEAK0.16b
    eor DATA1.16b, DATA1.16b, TWEAK1.16b
    eor DATA2.16b, DATA2.16b, TWEAK2.16b
    eor DATA3.16b, DATA3.16b, TWEAK3.16b
    ld1    {DATAX0.4s,DATAX1.4s,DATAX2.4s,DATAX3.4s},[INP],#64
    rbit TWEAK4.16b,TWEAK4.16b
    rbit TWEAK5.16b,TWEAK5.16b
    rbit TWEAK6.16b,TWEAK6.16b
    rbit TWEAK7.16b,TWEAK7.16b
    eor DATAX0.16b, DATAX0.16b, TWEAK4.16b
    eor DATAX1.16b, DATAX1.16b, TWEAK5.16b
    eor DATAX2.16b, DATAX2.16b, TWEAK6.16b
    eor DATAX3.16b, DATAX3.16b, TWEAK7.16b

    REV32_EQ(DATA0,DATA0)
    REV32_EQ(DATA1,DATA1)
    REV32_EQ(DATA2,DATA2)
    REV32_EQ(DATA3,DATA3)
    REV32_EQ(DATAX0,DATAX0)
    REV32_EQ(DATAX1,DATAX1)
    REV32_EQ(DATAX2,DATAX2)
    REV32_EQ(DATAX3,DATAX3)

    TRANSPOSE(DATA0,DATA1,DATA2,DATA3,VTMP0,VTMP1,VTMP2,VTMP3)
    TRANSPOSE(DATAX0,DATAX1,DATAX2,DATAX3,VTMP0,VTMP1,VTMP2,VTMP3)

    bl    vpsm4_ex_enc_8blks

    TRANSPOSE(VTMP0,VTMP1,VTMP2,VTMP3,DATAX0,DATAX1,DATAX2,DATAX3)
    TRANSPOSE(DATA0,DATA1,DATA2,DATA3,DATAX0,DATAX1,DATAX2,DATAX3)

    eor VTMP0.16b, VTMP0.16b, TWEAK0.16b
    eor VTMP1.16b, VTMP1.16b, TWEAK1.16b
    eor VTMP2.16b, VTMP2.16b, TWEAK2.16b
    eor VTMP3.16b, VTMP3.16b, TWEAK3.16b
    eor DATA0.16b, DATA0.16b, TWEAK4.16b
    eor DATA1.16b, DATA1.16b, TWEAK5.16b
    eor DATA2.16b, DATA2.16b, TWEAK6.16b
    eor DATA3.16b, DATA3.16b, TWEAK7.16b

    // save the last tweak
    mov LAST_TWEAK.16b,TWEAK7.16b
    st1    {VTMP0.4s,VTMP1.4s,VTMP2.4s,VTMP3.4s},[OUTP],#64
    st1    {DATA0.4s,DATA1.4s,DATA2.4s,DATA3.4s},[OUTP],#64
    subs    BLOCKS,BLOCKS,#8
    b.gt    .Lxts_8_blocks_process
    b    100f

.Lxts_4_blocks_process:
    cmp    BLOCKS,#4
    b.lt    1f
    ld1    {DATA0.4s,DATA1.4s,DATA2.4s,DATA3.4s},[INP],#64
    rbit TWEAK0.16b,TWEAK0.16b
    rbit TWEAK1.16b,TWEAK1.16b
    rbit TWEAK2.16b,TWEAK2.16b
    rbit TWEAK3.16b,TWEAK3.16b
    eor DATA0.16b, DATA0.16b, TWEAK0.16b
    eor DATA1.16b, DATA1.16b, TWEAK1.16b
    eor DATA2.16b, DATA2.16b, TWEAK2.16b
    eor DATA3.16b, DATA3.16b, TWEAK3.16b

    REV32_EQ(DATA0,DATA0)
    REV32_EQ(DATA1,DATA1)
    REV32_EQ(DATA2,DATA2)
    REV32_EQ(DATA3,DATA3)
    TRANSPOSE(DATA0,DATA1,DATA2,DATA3,VTMP0,VTMP1,VTMP2,VTMP3)

    bl    vpsm4_ex_enc_4blks
    TRANSPOSE(VTMP0,VTMP1,VTMP2,VTMP3,DATA0,DATA1,DATA2,DATA3)

    eor VTMP0.16b, VTMP0.16b, TWEAK0.16b
    eor VTMP1.16b, VTMP1.16b, TWEAK1.16b
    eor VTMP2.16b, VTMP2.16b, TWEAK2.16b
    eor VTMP3.16b, VTMP3.16b, TWEAK3.16b
    st1    {VTMP0.4s,VTMP1.4s,VTMP2.4s,VTMP3.4s},[OUTP],#64
    sub    BLOCKS,BLOCKS,#4
    mov TWEAK0.16b,TWEAK4.16b
    mov TWEAK1.16b,TWEAK5.16b
    mov TWEAK2.16b,TWEAK6.16b
    // save the last tweak
    mov LAST_TWEAK.16b,TWEAK3.16b
1:  // process last block
    cmp    BLOCKS,#1
    b.lt    100f
    b.gt    1f
    ld1    {DATA0.4s},[INP],#16
    rbit TWEAK0.16b,TWEAK0.16b
    eor DATA0.16b, DATA0.16b, TWEAK0.16b
    REV32_EQ(DATA0,DATA0)
    ENCRYPT_1BLK(DATA0,RKS1)
    eor DATA0.16b, DATA0.16b, TWEAK0.16b
    st1    {DATA0.4s},[OUTP],#16
    // save the last tweak
    mov LAST_TWEAK.16b,TWEAK0.16b
    b    100f
1:  // process last 2 blocks
    cmp    BLOCKS,#2
    b.gt    1f
    ld1    {DATA0.4s,DATA1.4s},[INP],#32
    rbit TWEAK0.16b,TWEAK0.16b
    rbit TWEAK1.16b,TWEAK1.16b
    eor DATA0.16b, DATA0.16b, TWEAK0.16b
    eor DATA1.16b, DATA1.16b, TWEAK1.16b

    REV32_EQ(DATA0,DATA0)
    REV32_EQ(DATA1,DATA1)
    TRANSPOSE(DATA0,DATA1,DATA2,DATA3,VTMP0,VTMP1,VTMP2,VTMP3)

    bl    vpsm4_ex_enc_4blks
    TRANSPOSE(VTMP0,VTMP1,VTMP2,VTMP3,DATA0,DATA1,DATA2,DATA3)

    eor VTMP0.16b, VTMP0.16b, TWEAK0.16b
    eor VTMP1.16b, VTMP1.16b, TWEAK1.16b
    st1    {VTMP0.4s,VTMP1.4s},[OUTP],#32
    // save the last tweak
    mov LAST_TWEAK.16b,TWEAK1.16b
    b    100f
1:  // process last 3 blocks
    ld1    {DATA0.4s,DATA1.4s,DATA2.4s},[INP],#48
    rbit TWEAK0.16b,TWEAK0.16b
    rbit TWEAK1.16b,TWEAK1.16b
    rbit TWEAK2.16b,TWEAK2.16b
    eor DATA0.16b, DATA0.16b, TWEAK0.16b
    eor DATA1.16b, DATA1.16b, TWEAK1.16b
    eor DATA2.16b, DATA2.16b, TWEAK2.16b

    REV32_EQ(DATA0,DATA0)
    REV32_EQ(DATA1,DATA1)
    REV32_EQ(DATA2,DATA2)

    TRANSPOSE(DATA0,DATA1,DATA2,DATA3,VTMP0,VTMP1,VTMP2,VTMP3)

    bl    vpsm4_ex_enc_4blks
    TRANSPOSE(VTMP0,VTMP1,VTMP2,VTMP3,DATA0,DATA1,DATA2,DATA3)

    eor VTMP0.16b, VTMP0.16b, TWEAK0.16b
    eor VTMP1.16b, VTMP1.16b, TWEAK1.16b
    eor VTMP2.16b, VTMP2.16b, TWEAK2.16b
    st1    {VTMP0.4s,VTMP1.4s,VTMP2.4s},[OUTP],#48
    // save the last tweak
    mov LAST_TWEAK.16b,TWEAK2.16b
100: //process end
    cmp REMAIN,0
    b.eq .return

// This brance calculates the last two tweaks, 
// while the encryption/decryption length is larger than 32
.last_2blks_tweak:
    REV32_ARMEB_EQ(LAST_TWEAK,LAST_TWEAK)
    COMPUTE_ALPHA_VEC(LAST_TWEAK,TWEAK1)
    COMPUTE_ALPHA_VEC(TWEAK1,TWEAK2)
    b .check_dec


// This brance calculates the last two tweaks, 
// while the encryption/decryption length is equal to 32, who only need two tweaks
.only_2blks_tweak:
    mov TWEAK1.16b,TWEAK0.16b
    REV32_ARMEB_EQ(TWEAK1,TWEAK1)
    COMPUTE_ALPHA_VEC(TWEAK1,TWEAK2)

    b .check_dec


// Determine whether encryption or decryption is required.
// The last two tweaks need to be swapped for decryption.
.check_dec:
    // encryption:1 decryption:0
    cmp ENC,1
    b.eq .process_last_2blks
    mov VTMP0.16B,TWEAK1.16b
    mov TWEAK1.16B,TWEAK2.16b
    mov TWEAK2.16B,VTMP0.16b

.process_last_2blks:
    REV32_ARMEB_EQ(TWEAK1,TWEAK1)
    REV32_ARMEB_EQ(TWEAK2,TWEAK2)
    ld1    {DATA0.4s},[INP],#16
    eor DATA0.16b, DATA0.16b, TWEAK1.16b
    REV32_EQ(DATA0,DATA0)
    ENCRYPT_1BLK(DATA0,RKS1)
    eor DATA0.16b, DATA0.16b, TWEAK1.16b
    st1    {DATA0.4s},[OUTP],#16

    sub LAST_BLK,OUTP,16
    .loop:
        subs REMAIN,REMAIN,1
        ldrb    WTMP0,[LAST_BLK,REMAIN]
        ldrb    WTMP1,[INP,REMAIN]
        strb    WTMP1,[LAST_BLK,REMAIN]
        strb    WTMP0,[OUTP,REMAIN]
    b.gt .loop
    ld1        {DATA0.4s}, [LAST_BLK]    
    eor DATA0.16b, DATA0.16b, TWEAK2.16b
    REV32_EQ(DATA0,DATA0)
    ENCRYPT_1BLK(DATA0,RKS1)
    eor DATA0.16b, DATA0.16b, TWEAK2.16b
    st1        {DATA0.4s}, [LAST_BLK]
.return:
    /*clear INPUT Data */
    eor DATA0.16b, DATA0.16b, DATA0.16b
    eor DATA1.16b, DATA1.16b, DATA1.16b
    eor DATA2.16b, DATA2.16b, DATA2.16b
    eor DATA3.16b, DATA3.16b, DATA3.16b
    eor DATAX0.16b, DATAX0.16b, DATAX0.16b
    eor DATAX1.16b, DATAX1.16b, DATAX1.16b
    eor DATAX2.16b, DATAX2.16b, DATAX2.16b
    eor DATAX3.16b, DATAX3.16b, DATAX3.16b
    /*clear user temp key data*/
    eor    WTMP0,WTMP0,WTMP0
    eor    WTMP1,WTMP1,WTMP1

    LOAD_STACK()
    ret
.size    Vpsm4XtsCipher,.-Vpsm4XtsCipher

/*
 * void Vpsm4XtsEncrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
                          const SM4_KEY *key2, const uint8_t *iv);
 * encryption for sm4-xts
 * x0 => in; x1 => out; x2 => length; x3 => key1; x4 => key2; x5 => iv
 */
.globl   Vpsm4XtsEncrypt
.type    Vpsm4XtsEncrypt,%function
.align    5
Vpsm4XtsEncrypt:
    SAVE_STACK()
    mov   ENC,1
    bl    Vpsm4XtsCipher
    LOAD_STACK()
    ret
.size    Vpsm4XtsEncrypt,.-Vpsm4XtsEncrypt

/*
 * void Vpsm4XtsDecrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
                          const SM4_KEY *key2, const uint8_t *iv);
 * decryption for sm4-xts
 * x0 => in; x1 => out; x2 => length; x3 => key1; x4 => key2; x5 => iv
 */
.globl   Vpsm4XtsDecrypt
.type    Vpsm4XtsDecrypt,%function
.align    5
Vpsm4XtsDecrypt:
    SAVE_STACK()
    mov   ENC,0
    bl    Vpsm4XtsCipher
    LOAD_STACK()
    ret
.size    Vpsm4XtsDecrypt,.-Vpsm4XtsDecrypt

#endif
