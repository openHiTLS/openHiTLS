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

#include "crypt_aes_macro_x86_64.s"

.file   "crypt_aes_xts_x86_64.S"

.set    KEY, %rdi
.set    IN, %rsi
.set    OUT, %rdx
.set    LEN, %ecx
.set    TWEAK, %r8

.set    KTMP, %r9
.set    LTMP, %r15d
.set    TAILNUM,%r14d
.set    TMPOUT,%r13
.set    TMPIN,%r9

.set    ROUNDS, %eax
.set    RET, %eax
.set    TROUNDS, %r10
.set    ROUNDSQ,%rax
.set    KEYEND,%r9

.set    WTMP0,   %ecx
.set    WTMP1,   %r10d
.set    WTMP2,   %r11d

.set    XTMP0,   %rcx
.set    XTMP1,   %r10
.set    XTMP2,   %r11

.set    TWX0,    %r13
.set    TWX1,    %r14

.set    BLK0, %xmm8
.set    BLK1, %xmm9
.set    BLK2, %xmm10
.set    BLK3, %xmm11
.set    BLK4, %xmm12
.set    BLK5, %xmm13
.set    BLK6, %xmm14

.set    TWEAK0, %xmm0
.set    TWEAK1, %xmm1
.set    TWEAK2, %xmm2
.set    TWEAK3, %xmm3
.set    TWEAK4, %xmm4
.set    TWEAK5, %xmm5
.set    TWEAK6, %xmm6

.set    RDK, %xmm15
.set    RDK1, %xmm7
.set    TMPX, %xmm7
.set    GFP, %xmm6
.set    TWKTMP, %xmm14


.macro NextTweakCore gfp, twkin, twktmp, tmp
    vmovdqa \twktmp,\tmp
    vpaddd \twktmp,\twktmp,\twktmp  // doubleword << 1
    vpsrad $31,\tmp,\tmp            // ASR doubleword
    vpaddq \twkin,\twkin,\twkin     // quadword << 1
    vpand \gfp,\tmp,\tmp            // and 0x10000000000000087
    vpxor \tmp,\twkin,\twkin
.endm

.macro NextTweak gfp, twkin, twkout, twktmp, tmp
    NextTweakCore \gfp,\twkin,\twktmp,\tmp
    vmovdqa \twkin,\twkout
.endm

.macro SAVE_STACK
    push %rbx
    push %rbp
    push %rsp
    push %r12
    push %r13
    push %r14
    push %r15
.endm

.macro LOAD_STACK
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rsp
    pop %rbp
    pop %rbx
.endm

.data
.align 64
// modulus of Galois Field x^128+x^7+x^2+x+1 => 0x87(0b10000111)
.Lgfp128:
.long 0x87,0,1,0

.text

/**
 *  Function description: Sets the AES encryption assembly acceleration API in XTS mode.
 *  Function prototype: int32_t CRYPT_AES_XTS_Encrypt(const CRYPT_AES_Key *ctx,
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
.align 32
.globl CRYPT_AES_XTS_Encrypt
.type CRYPT_AES_XTS_Encrypt, @function
CRYPT_AES_XTS_Encrypt:
.cfi_startproc
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    sub $96,%rsp
    mov %rsp,%rbp
    and $-16,%rsp  // 16 bytes align

    movl LEN, LTMP
    movl LEN, TAILNUM
    andl $-16,LTMP
    andl $0xf,TAILNUM // LEN % 16
    movl 240(KEY), ROUNDS
    vmovdqa .Lgfp128(%rip),GFP
    vmovdqu (TWEAK), TWEAK0
    shl $4,ROUNDS  // roundkey size: rounds*16, except for the last one
    lea 16(KEY, ROUNDSQ),KEYEND   // step to the end of roundkeys

.Lxts_aesenc_start:
    cmpl    $64, LTMP
    jae     .Lxts_enc_above_equal_4_blks
    cmpl    $32, LTMP
    jae     .Lxts_enc_above_equal_2_blks
    cmpl    $0, LTMP
    je      .Lxts_aesenc_finish
    jmp     .Lxts_enc_proc_1_blk

.Lxts_enc_above_equal_2_blks:
    cmpl    $48, LTMP
    jb      .Lxts_enc_proc_2_blks
    jmp     .Lxts_enc_proc_3_blks

.Lxts_enc_above_equal_4_blks:
    cmpl    $96, LTMP
    jae     .Lxts_enc_proc_6_blks_pre
    cmpl    $80, LTMP
    jb      .Lxts_enc_proc_4_blks
    jmp     .Lxts_enc_proc_5_blks

.align 16
.Lxts_enc_proc_1_blk:
    vmovdqu (IN),BLK0
.Lxts_enc_proc_1blk_loaded:
    mov KEY,KTMP
    vpshufd $0x5f,TWEAK0,TWKTMP 
    vmovdqa TWEAK0,TWEAK5
    movl 240(KTMP), ROUNDS
    vmovdqu (KTMP), RDK
    vpxor RDK,BLK0,BLK0
    decl ROUNDS
    vpxor TWEAK0, BLK0, BLK0
    AES_ENC_1_BLK KTMP ROUNDS RDK BLK0
    vpxor TWEAK0, BLK0, BLK0
    vmovdqu BLK0, (OUT)
    NextTweak GFP, TWEAK5, TWEAK0, TWKTMP, TMPX
    lea 16(IN),IN
    subl $16,LTMP
    lea 16(OUT),OUT

    je .Lxts_aesenc_finish

.align 16
.Lxts_enc_proc_2_blks:
    mov KEY,KTMP
    vpshufd $0x5f,TWEAK0,TWKTMP 
    vmovdqa TWEAK0,TWEAK5
    movl 240(KTMP), ROUNDS
    vmovdqu (KTMP), RDK
    NextTweak GFP, TWEAK5, TWEAK1, TWKTMP, TMPX
    vpxor (IN), RDK, BLK0
    vpxor 16(IN), RDK, BLK1
    decl ROUNDS
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    AES_ENC_2_BLKS    KTMP ROUNDS RDK BLK0 BLK1
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vmovdqu BLK0, (OUT)
    vmovdqu BLK1, 16(OUT)
    NextTweak GFP, TWEAK5, TWEAK0, TWKTMP, TMPX
    lea 32(IN),IN
    subl $32,LTMP
    lea 32(OUT),OUT

    je .Lxts_aesenc_finish

.align 16
.Lxts_enc_proc_3_blks:
    mov KEY,KTMP
    vpshufd $0x5f,TWEAK0,TWKTMP 
    vmovdqa TWEAK0,TWEAK5
    movl 240(KTMP), ROUNDS
    vmovdqu (KTMP), RDK
    NextTweak GFP, TWEAK5, TWEAK1, TWKTMP, TMPX
    vpxor (IN), RDK, BLK0
    vpxor 16(IN), RDK, BLK1
    NextTweak GFP, TWEAK5, TWEAK2, TWKTMP, TMPX
    vpxor 32(IN), RDK, BLK2
    decl ROUNDS
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    AES_ENC_3_BLKS    KTMP ROUNDS RDK BLK0 BLK1 BLK2
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    vmovdqu BLK0, (OUT)
    vmovdqu BLK1, 16(OUT)
    vmovdqu BLK2, 32(OUT)
    NextTweak GFP, TWEAK5, TWEAK0, TWKTMP, TMPX
    lea 48(IN),IN
    subl $48,LTMP
    lea 48(OUT),OUT
    je  .Lxts_aesenc_finish

.align 16
.Lxts_enc_proc_4_blks:
    mov KEY,KTMP
    vpshufd $0x5f,TWEAK0,TWKTMP 
    vmovdqa TWEAK0,TWEAK5
    movl 240(KTMP), ROUNDS
    vmovdqu (KTMP), RDK
    NextTweak GFP, TWEAK5, TWEAK1, TWKTMP, TMPX
    vpxor (IN), RDK, BLK0
    vpxor 16(IN), RDK, BLK1
    NextTweak GFP, TWEAK5, TWEAK2, TWKTMP, TMPX
    vpxor 32(IN), RDK, BLK2
    NextTweak GFP, TWEAK5, TWEAK3, TWKTMP, TMPX
    vpxor 48(IN), RDK, BLK3
    decl ROUNDS
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    vpxor TWEAK3, BLK3, BLK3
    AES_ENC_4_BLKS    KTMP ROUNDS RDK BLK0 BLK1 BLK2 BLK3
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    vpxor TWEAK3, BLK3, BLK3
    vmovdqu BLK0, (OUT)
    vmovdqu BLK1, 16(OUT)
    vmovdqu BLK2, 32(OUT)
    vmovdqu BLK3, 48(OUT)
    NextTweak GFP, TWEAK5, TWEAK0, TWKTMP, TMPX
    lea 64(IN),IN
    subl $64,LTMP
    lea 64(OUT),OUT
    je  .Lxts_aesenc_finish

.align 16
.Lxts_enc_proc_5_blks:
    mov KEY,KTMP
    vpshufd $0x5f,TWEAK0,TWKTMP 
    vmovdqa TWEAK0,TWEAK5
    movl 240(KTMP), ROUNDS
    vmovdqu (KTMP), RDK
    NextTweak GFP, TWEAK5, TWEAK1, TWKTMP, TMPX
    vpxor (IN), RDK, BLK0
    vpxor 16(IN), RDK, BLK1
    NextTweak GFP, TWEAK5, TWEAK2, TWKTMP, TMPX
    vpxor 32(IN), RDK, BLK2
    NextTweak GFP, TWEAK5, TWEAK3, TWKTMP, TMPX
    vpxor 48(IN), RDK, BLK3
    NextTweak GFP, TWEAK5, TWEAK4, TWKTMP, TMPX
    vpxor 64(IN), RDK, BLK4
    decl ROUNDS
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    vpxor TWEAK3, BLK3, BLK3
    vpxor TWEAK4, BLK4, BLK4
    AES_ENC_5_BLKS    KTMP ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    vpxor TWEAK3, BLK3, BLK3
    vpxor TWEAK4, BLK4, BLK4
    vmovdqu BLK0, (OUT)
    vmovdqu BLK1, 16(OUT)
    vmovdqu BLK2, 32(OUT)
    vmovdqu BLK3, 48(OUT)
    vmovdqu BLK4, 64(OUT)
    NextTweak GFP, TWEAK5, TWEAK0, TWKTMP, TMPX
    lea 80(IN),IN
    subl $80,LTMP
    lea 80(OUT),OUT
    je  .Lxts_aesenc_finish

.align 16
.Lxts_enc_proc_6_blks_pre:
    vpshufd $0x5f,TWEAK0,TWKTMP   // save higher doubleword of tweak
    vmovdqa TWEAK0,TWEAK5    // copy first tweak
    NextTweak GFP, TWEAK5, TWEAK1, TWKTMP, TMPX
    NextTweak GFP, TWEAK5, TWEAK2, TWKTMP, TMPX
    NextTweak GFP, TWEAK5, TWEAK3, TWKTMP, TMPX
    NextTweak GFP, TWEAK5, TWEAK4, TWKTMP, TMPX
    NextTweakCore GFP, TWEAK5, TWKTMP, TMPX
    
.Lxts_enc_proc_6_blks:
    vmovdqu (KEY), RDK
    vmovdqu (IN),BLK0
    vpxor TWEAK0,BLK0,BLK0    // blk0 ^= tweak0
    vpxor RDK,BLK0,BLK0   // blk0 = blk0 ^ tweak0 ^ rk0, prepared for the loop round
    vmovdqu -16(KEYEND),RDK1   // load last round key

    vmovdqu 16(IN),BLK1
    vpxor RDK1,TWEAK0,TWEAK0
    aesenc 16(KEY),BLK0  // first round: rk1
    vmovdqa TWEAK0,(%rsp)
    vpxor TWEAK1,BLK1,BLK1
    vpxor RDK,BLK1,BLK1

    vmovdqu 32(IN),BLK2
    vpxor RDK1,TWEAK1,TWEAK1
    aesenc 16(KEY),BLK1
    vmovdqa TWEAK1,16(%rsp)
    vpxor TWEAK2,BLK2,BLK2
    vpxor RDK,BLK2,BLK2

    vmovdqu 48(IN),BLK3
    vpxor RDK1,TWEAK2,TWEAK2
    aesenc 16(KEY),BLK2
    vmovdqa TWEAK2,32(%rsp)
    vpxor TWEAK3,BLK3,BLK3
    vpxor RDK,BLK3,BLK3

    vmovdqu 64(IN),BLK4
    vpxor RDK1,TWEAK3,TWEAK3
    aesenc 16(KEY),BLK3
    vmovdqa TWEAK3,48(%rsp)
    vpxor TWEAK4,BLK4,BLK4
    vpxor RDK,BLK4,BLK4

    vmovdqu 80(IN),BLK5
    vpxor RDK1,TWEAK4,TWEAK4
    aesenc 16(KEY),BLK4 
    vmovdqa TWEAK4,64(%rsp)
    vpxor TWEAK5,BLK5,BLK5
    vpxor RDK,BLK5,BLK5
    vpxor RDK1,TWEAK5,TWEAK5
    aesenc 16(KEY),BLK5
    vmovdqa TWEAK5,80(%rsp)

    mov $(7*16),TROUNDS  // loop 7 rounds
    sub ROUNDSQ,TROUNDS
.align 16
.Lxts_6_blks_loop:
    vmovdqu -96(KEYEND,TROUNDS),RDK  // left 5+1 block to interval
    aesenc  RDK, BLK0
    aesenc  RDK, BLK1
    aesenc  RDK, BLK2
    add $16,TROUNDS
    aesenc  RDK, BLK3
    aesenc  RDK, BLK4
    aesenc  RDK, BLK5
    jnz .Lxts_6_blks_loop

    vpxor 80(%rsp),RDK1,TWEAK5  // tweak5 = tweak5^lastroundkey^lastroundkey
    vmovdqu -96(KEYEND,TROUNDS),RDK
    vpshufd $0x5f,TWEAK5,TWKTMP  // use new tweak-tmp
    vmovdqa TWKTMP,TMPX      // pre-calculate next round tweak0~tweak5
    aesenc  RDK, BLK0
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesenc  RDK, BLK1
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesenc  RDK, BLK2
    vpxor TMPX,TWEAK5,TWEAK5
    add $16,TROUNDS
    aesenc  RDK, BLK3
    vmovdqa TWEAK5,TWEAK0
    aesenc  RDK, BLK4
    aesenc  RDK, BLK5

    vmovdqu -96(KEYEND,TROUNDS),RDK
    vmovdqa TWKTMP,TMPX
    aesenc  RDK, BLK0
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesenc  RDK, BLK1
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesenc  RDK, BLK2
    vpxor TMPX,TWEAK5,TWEAK5
    add $16,TROUNDS
    aesenc  RDK, BLK3
    vmovdqa TWEAK5,TWEAK1
    aesenc  RDK, BLK4
    aesenc  RDK, BLK5

    vmovdqu -96(KEYEND,TROUNDS),RDK
    vmovdqa TWKTMP,TMPX
    aesenc  RDK, BLK0
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesenc  RDK, BLK1
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesenc  RDK, BLK2
    vpxor TMPX,TWEAK5,TWEAK5
    add $16,TROUNDS
    aesenc  RDK, BLK3
    vmovdqa TWEAK5,TWEAK2
    aesenc  RDK, BLK4
    aesenc  RDK, BLK5

    vmovdqu -96(KEYEND,TROUNDS),RDK
    vmovdqa TWKTMP,TMPX
    aesenc  RDK, BLK0
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesenc  RDK, BLK1
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesenc  RDK, BLK2
    vpxor TMPX,TWEAK5,TWEAK5
    add $16,TROUNDS
    aesenc  RDK, BLK3
    vmovdqa TWEAK5,TWEAK3
    aesenc  RDK, BLK4
    aesenc  RDK, BLK5

    vmovdqu -96(KEYEND,TROUNDS),RDK
    vmovdqa TWKTMP,TMPX
    aesenc  RDK, BLK0
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesenc  RDK, BLK1
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesenc  RDK, BLK2
    vpxor TMPX,TWEAK5,TWEAK5
    aesenc  RDK, BLK3
    vmovdqa TWEAK5,TWEAK4
    aesenc  RDK, BLK4
    aesenc  RDK, BLK5

    vmovdqa TWKTMP,TMPX
    aesenclast (%rsp), BLK0
    aesenclast 16(%rsp), BLK1   // already do the tweak^lastround, so here just aesenclast 
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesenclast 32(%rsp), BLK2
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesenclast 48(%rsp), BLK3
    vpxor TMPX,TWEAK5,TWEAK5
    aesenclast 64(%rsp), BLK4
    aesenclast 80(%rsp), BLK5

    vmovdqu BLK0, (OUT)
    vmovdqu BLK1, 16(OUT)
    vmovdqu BLK2, 32(OUT)
    vmovdqu BLK3, 48(OUT)
    vmovdqu BLK4, 64(OUT)
    vmovdqu BLK5, 80(OUT)

    leaq 96(IN), IN
    leaq 96(OUT), OUT
    sub $96, LTMP
    cmp $96, LTMP
    jb  .Lxts_aesenc_start
    jmp  .Lxts_enc_proc_6_blks

.align 16
.Lxts_aesenc_finish:
    cmp $0,TAILNUM
    je .Lxts_ret
.Lxts_tail_proc:
    mov OUT,TMPOUT
    mov IN,TMPIN
.Lxts_tail_loop:
    sub $1,TAILNUM
    movzb -16(TMPOUT),%r10d
    movzb (TMPIN),%r11d
    mov %r10b,(TMPOUT)
    lea 1(TMPIN),TMPIN
    mov %r11b,-16(TMPOUT)
    lea 1(TMPOUT),TMPOUT
    ja .Lxts_tail_loop
    sub $16,OUT  // step 1 block back to save the last stealing block encryption
    add $16,LTMP
    vmovdqu (OUT),BLK0
    jmp .Lxts_enc_proc_1blk_loaded

.Lxts_ret:
    vmovdqu TWEAK0, (TWEAK)
    vpxor BLK0, BLK0, BLK0
    vpxor BLK1, BLK1, BLK1
    vpxor BLK2, BLK2, BLK2
    vpxor BLK3, BLK3, BLK3
    vpxor BLK4, BLK4, BLK4
    vpxor BLK5, BLK5, BLK5
    vpxor BLK6, BLK6, BLK6
    vpxor RDK, RDK, RDK
    movl $0, RET

    mov %rbp,%rsp
    add $96,%rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
.cfi_endproc
.size CRYPT_AES_XTS_Encrypt, .-CRYPT_AES_XTS_Encrypt


/**
 *  Function description: Sets the AES decryption and assembly acceleration API in XTS mode.
 *  Function prototype: int32_t CRYPT_AES_XTS_Decrypt(const CRYPT_AES_Key *ctx,
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
.align 32
.globl CRYPT_AES_XTS_Decrypt
.type CRYPT_AES_XTS_Decrypt, @function
CRYPT_AES_XTS_Decrypt:
.cfi_startproc
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    sub $96,%rsp
    mov %rsp,%rbp
    and $-16,%rsp  // 16 bytes align

    movl LEN, LTMP
    movl LEN, TAILNUM

    andl $-16,LTMP
    movl LTMP,WTMP2
    sub $16,WTMP2    // preserve last and tail block
    andl $0xf,TAILNUM // LEN % 16
    cmovg WTMP2,LTMP 
    movl 240(KEY), ROUNDS
    vmovdqa .Lgfp128(%rip),GFP
    vmovdqu (TWEAK), TWEAK0
    shl $4,ROUNDS  // roundkey size: rounds*16, except for the last one
    lea 16(KEY, ROUNDSQ),KEYEND   // step to the end of roundkeys

.Lxts_aesdec_start:
    cmpl    $64, LTMP
    jae     .Lxts_dec_above_equal_4_blks
    cmpl    $32, LTMP
    jae     .Lxts_dec_above_equal_2_blks
    cmpl    $0, LTMP
    je      .Lxts_dec_last_2blks
    jmp     .Lxts_dec_proc_1_blk

.Lxts_dec_above_equal_2_blks:
    cmpl    $48, LTMP
    jb      .Lxts_dec_proc_2_blks
    jmp     .Lxts_dec_proc_3_blks

.Lxts_dec_above_equal_4_blks:
    cmpl    $96, LTMP
    jae     .Lxts_dec_proc_6_blks_pre
    cmpl    $80, LTMP
    jb      .Lxts_dec_proc_4_blks
    jmp     .Lxts_dec_proc_5_blks

.align 16
.Lxts_dec_tail_proc:
    cmp $0,TAILNUM
    je .Lxts_aesdec_finish
    vmovdqa TWEAK1,TWEAK0  // restore back tweak0
    mov OUT,TMPOUT
    mov IN,TMPIN
.Lxts_dec_tail_loop:
    sub $1,TAILNUM
    movzb -16(TMPOUT),%r10d
    movzb (TMPIN),%r11d
    mov %r10b,(TMPOUT)
    lea 1(TMPIN),TMPIN
    mov %r11b,-16(TMPOUT)
    lea 1(TMPOUT),TMPOUT
    ja .Lxts_dec_tail_loop

    sub $16,OUT  // step 1 block back to save the last stealing block encryption
    add $16,LTMP

    vmovdqu (OUT),BLK0
    jmp .Lxts_dec_proc_1blk_loaded

.align 16
.Lxts_dec_last_2blks:
    cmp $0,TAILNUM
    je .Lxts_aesdec_finish
    vpshufd $0x5f,TWEAK0,TWKTMP
    vmovdqa TWEAK0,TWEAK1    // tail block use tweak0, last block use tweak1
    NextTweakCore GFP, TWEAK0, TWKTMP, TMPX  
.Lxts_dec_proc_1_blk:
    vmovdqu (IN),BLK0
.Lxts_dec_proc_1blk_loaded:
    mov KEY,KTMP
    vpshufd $0x5f,TWEAK0,TWKTMP 
    vmovdqa TWEAK0,TWEAK5
    movl 240(KTMP), ROUNDS
    vmovdqu (KTMP), RDK
    vpxor RDK,BLK0,BLK0
    decl ROUNDS
    vpxor TWEAK0, BLK0, BLK0
    AES_DEC_1_BLK KTMP ROUNDS RDK BLK0
    vpxor TWEAK0, BLK0, BLK0
    vmovdqu BLK0, (OUT)
    NextTweak GFP, TWEAK5, TWEAK0, TWKTMP, TMPX
    lea 16(IN),IN
    subl $16,LTMP
    lea 16(OUT),OUT
    jl .Lxts_dec_tail_proc
    jmp .Lxts_aesdec_start

.align 16
.Lxts_dec_proc_2_blks:
    mov KEY,KTMP
    vpshufd $0x5f,TWEAK0,TWKTMP 
    vmovdqa TWEAK0,TWEAK5
    movl 240(KTMP), ROUNDS
    vmovdqu (KTMP), RDK
    NextTweak GFP, TWEAK5, TWEAK1, TWKTMP, TMPX
    vpxor (IN), RDK, BLK0
    vpxor 16(IN), RDK, BLK1
    decl ROUNDS
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    AES_DEC_2_BLKS    KTMP ROUNDS RDK BLK0 BLK1
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vmovdqu BLK0, (OUT)
    vmovdqu BLK1, 16(OUT)
    NextTweak GFP, TWEAK5, TWEAK0, TWKTMP, TMPX
    lea 32(IN),IN
    subl $32,LTMP
    lea 32(OUT),OUT

    jge .Lxts_aesdec_start

.align 16
.Lxts_dec_proc_3_blks:
    mov KEY,KTMP
    vpshufd $0x5f,TWEAK0,TWKTMP 
    vmovdqa TWEAK0,TWEAK5
    movl 240(KTMP), ROUNDS
    vmovdqu (KTMP), RDK
    NextTweak GFP, TWEAK5, TWEAK1, TWKTMP, TMPX
    vpxor (IN), RDK, BLK0
    vpxor 16(IN), RDK, BLK1
    NextTweak GFP, TWEAK5, TWEAK2, TWKTMP, TMPX
    vpxor 32(IN), RDK, BLK2
    decl ROUNDS
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    AES_DEC_3_BLKS    KTMP ROUNDS RDK BLK0 BLK1 BLK2
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    vmovdqu BLK0, (OUT)
    vmovdqu BLK1, 16(OUT)
    vmovdqu BLK2, 32(OUT)
    NextTweak GFP, TWEAK5, TWEAK0, TWKTMP, TMPX
    lea 48(IN),IN
    subl $48,LTMP
    lea 48(OUT),OUT
    jge .Lxts_aesdec_start

.align 16
.Lxts_dec_proc_4_blks:
    mov KEY,KTMP
    vpshufd $0x5f,TWEAK0,TWKTMP 
    vmovdqa TWEAK0,TWEAK5
    movl 240(KTMP), ROUNDS
    vmovdqu (KTMP), RDK
    NextTweak GFP, TWEAK5, TWEAK1, TWKTMP, TMPX
    vpxor (IN), RDK, BLK0
    vpxor 16(IN), RDK, BLK1
    NextTweak GFP, TWEAK5, TWEAK2, TWKTMP, TMPX
    vpxor 32(IN), RDK, BLK2
    NextTweak GFP, TWEAK5, TWEAK3, TWKTMP, TMPX
    vpxor 48(IN), RDK, BLK3
    decl ROUNDS
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    vpxor TWEAK3, BLK3, BLK3
    AES_DEC_4_BLKS    KTMP ROUNDS RDK BLK0 BLK1 BLK2 BLK3
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    vpxor TWEAK3, BLK3, BLK3
    vmovdqu BLK0, (OUT)
    vmovdqu BLK1, 16(OUT)
    vmovdqu BLK2, 32(OUT)
    vmovdqu BLK3, 48(OUT)
    NextTweak GFP, TWEAK5, TWEAK0, TWKTMP, TMPX
    lea 64(IN),IN
    subl $64,LTMP
    lea 64(OUT),OUT
    jge .Lxts_aesdec_start

.align 16
.Lxts_dec_proc_5_blks:
    mov KEY,KTMP
    vpshufd $0x5f,TWEAK0,TWKTMP 
    vmovdqa TWEAK0,TWEAK5
    movl 240(KTMP), ROUNDS
    vmovdqu (KTMP), RDK
    NextTweak GFP, TWEAK5, TWEAK1, TWKTMP, TMPX
    vpxor (IN), RDK, BLK0
    vpxor 16(IN), RDK, BLK1
    NextTweak GFP, TWEAK5, TWEAK2, TWKTMP, TMPX
    vpxor 32(IN), RDK, BLK2
    NextTweak GFP, TWEAK5, TWEAK3, TWKTMP, TMPX
    vpxor 48(IN), RDK, BLK3
    NextTweak GFP, TWEAK5, TWEAK4, TWKTMP, TMPX
    vpxor 64(IN), RDK, BLK4
    decl ROUNDS
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    vpxor TWEAK3, BLK3, BLK3
    vpxor TWEAK4, BLK4, BLK4
    AES_DEC_5_BLKS    KTMP ROUNDS RDK BLK0 BLK1 BLK2 BLK3 BLK4
    vpxor TWEAK0, BLK0, BLK0
    vpxor TWEAK1, BLK1, BLK1
    vpxor TWEAK2, BLK2, BLK2
    vpxor TWEAK3, BLK3, BLK3
    vpxor TWEAK4, BLK4, BLK4
    vmovdqu BLK0, (OUT)
    vmovdqu BLK1, 16(OUT)
    vmovdqu BLK2, 32(OUT)
    vmovdqu BLK3, 48(OUT)
    vmovdqu BLK4, 64(OUT)
    NextTweak GFP, TWEAK5, TWEAK0, TWKTMP, TMPX
    lea 80(IN),IN
    subl $80,LTMP
    lea 80(OUT),OUT
    jge .Lxts_aesdec_start

.align 32
.Lxts_dec_proc_6_blks_pre:
    vpshufd $0x5f,TWEAK0,TWKTMP   // save higher doubleword of tweak
    vmovdqa TWEAK0,TWEAK5    // copy first tweak
    NextTweak GFP, TWEAK5, TWEAK1, TWKTMP, TMPX
    NextTweak GFP, TWEAK5, TWEAK2, TWKTMP, TMPX
    NextTweak GFP, TWEAK5, TWEAK3, TWKTMP, TMPX
    NextTweak GFP, TWEAK5, TWEAK4, TWKTMP, TMPX
    NextTweakCore GFP, TWEAK5, TWKTMP, TMPX
.align 32
.Lxts_dec_proc_6_blks:
    vmovdqu (KEY), RDK
    vmovdqu (IN),BLK0
    vpxor TWEAK0,BLK0,BLK0    // blk0 ^= tweak0
    vpxor RDK,BLK0,BLK0   // blk0 = blk0 ^ tweak0 ^ rk0, prepared for the loop round
    vmovdqu -16(KEYEND),RDK1   // load last round key

    vmovdqu 16(IN),BLK1
    vpxor RDK1,TWEAK0,TWEAK0
    aesdec 16(KEY),BLK0  // first round: rk1
    vmovdqa TWEAK0,(%rsp)
    vpxor TWEAK1,BLK1,BLK1
    vpxor RDK,BLK1,BLK1

    vmovdqu 32(IN),BLK2
    vpxor RDK1,TWEAK1,TWEAK1
    aesdec 16(KEY),BLK1
    vmovdqa TWEAK1,16(%rsp)
    vpxor TWEAK2,BLK2,BLK2
    vpxor RDK,BLK2,BLK2

    vmovdqu 48(IN),BLK3
    vpxor RDK1,TWEAK2,TWEAK2
    aesdec 16(KEY),BLK2
    vmovdqa TWEAK2,32(%rsp)
    vpxor TWEAK3,BLK3,BLK3
    vpxor RDK,BLK3,BLK3

    vmovdqu 64(IN),BLK4
    vpxor RDK1,TWEAK3,TWEAK3
    aesdec 16(KEY),BLK3
    vmovdqa TWEAK3,48(%rsp)
    vpxor TWEAK4,BLK4,BLK4
    vpxor RDK,BLK4,BLK4

    vmovdqu 80(IN),BLK5
    vpxor RDK1,TWEAK4,TWEAK4
    aesdec 16(KEY),BLK4 
    vmovdqa TWEAK4,64(%rsp)
    vpxor TWEAK5,BLK5,BLK5
    vpxor RDK,BLK5,BLK5
    vpxor RDK1,TWEAK5,TWEAK5
    aesdec 16(KEY),BLK5
    vmovdqa TWEAK5,80(%rsp)

    mov $(7*16),TROUNDS  // loop 7 rounds
    sub ROUNDSQ,TROUNDS
.align 32
.Lxts_dec_6blks_loop:
    vmovdqu -96(KEYEND,TROUNDS),RDK  // left 5+1 block to interval
    aesdec  RDK, BLK0
    aesdec  RDK, BLK1
    aesdec  RDK, BLK2
    add $16,TROUNDS
    aesdec  RDK, BLK3
    aesdec  RDK, BLK4
    aesdec  RDK, BLK5
    jnz .Lxts_dec_6blks_loop

    vpxor 80(%rsp),RDK1,TWEAK5  // tweak5 = tweak5^lastroundkey^lastroundkey
    vmovdqu -96(KEYEND,TROUNDS),RDK
    vpshufd $0x5f,TWEAK5,TWKTMP  // use new tweak-tmp
    vmovdqa TWKTMP,TMPX      // pre-calculate next round tweak0~tweak5
    aesdec  RDK, BLK0
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesdec  RDK, BLK1
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesdec  RDK, BLK2
    vpxor TMPX,TWEAK5,TWEAK5
    add $16,TROUNDS
    aesdec  RDK, BLK3
    vmovdqa TWEAK5,TWEAK0
    aesdec  RDK, BLK4
    aesdec  RDK, BLK5

    vmovdqu -96(KEYEND,TROUNDS),RDK
    vmovdqa TWKTMP,TMPX
    aesdec  RDK, BLK0
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesdec  RDK, BLK1
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesdec  RDK, BLK2
    vpxor TMPX,TWEAK5,TWEAK5
    add $16,TROUNDS
    aesdec  RDK, BLK3
    vmovdqa TWEAK5,TWEAK1
    aesdec  RDK, BLK4
    aesdec  RDK, BLK5

    vmovdqu -96(KEYEND,TROUNDS),RDK
    vmovdqa TWKTMP,TMPX
    aesdec  RDK, BLK0
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesdec  RDK, BLK1
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesdec  RDK, BLK2
    vpxor TMPX,TWEAK5,TWEAK5
    add $16,TROUNDS
    aesdec  RDK, BLK3
    vmovdqa TWEAK5,TWEAK2
    aesdec  RDK, BLK4
    aesdec  RDK, BLK5

    vmovdqu -96(KEYEND,TROUNDS),RDK
    vmovdqa TWKTMP,TMPX
    aesdec  RDK, BLK0
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesdec  RDK, BLK1
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesdec  RDK, BLK2
    vpxor TMPX,TWEAK5,TWEAK5
    add $16,TROUNDS
    aesdec  RDK, BLK3
    vmovdqa TWEAK5,TWEAK3
    aesdec  RDK, BLK4
    aesdec  RDK, BLK5

    vmovdqu -96(KEYEND,TROUNDS),RDK
    vmovdqa TWKTMP,TMPX
    aesdec  RDK, BLK0
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesdec  RDK, BLK1
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesdec  RDK, BLK2
    vpxor TMPX,TWEAK5,TWEAK5
    aesdec  RDK, BLK3
    vmovdqa TWEAK5,TWEAK4
    aesdec  RDK, BLK4
    aesdec  RDK, BLK5

    vmovdqa TWKTMP,TMPX
    aesdeclast (%rsp), BLK0
    aesdeclast 16(%rsp), BLK1   // already do the tweak^lastround, so here just aesdeclast 
    vpaddd TWKTMP,TWKTMP,TWKTMP
    vpsrad $31,TMPX,TMPX
    aesdeclast 32(%rsp), BLK2
    vpaddq TWEAK5,TWEAK5,TWEAK5
    vpand GFP,TMPX,TMPX
    aesdeclast 48(%rsp), BLK3
    vpxor TMPX,TWEAK5,TWEAK5
    aesdeclast 64(%rsp), BLK4
    aesdeclast 80(%rsp), BLK5

    vmovdqu BLK0, (OUT)
    vmovdqu BLK1, 16(OUT)
    vmovdqu BLK2, 32(OUT)
    vmovdqu BLK3, 48(OUT)
    vmovdqu BLK4, 64(OUT)
    vmovdqu BLK5, 80(OUT)

    leaq 96(IN), IN
    leaq 96(OUT), OUT
    sub $96, LTMP
    cmp $96, LTMP
    jb  .Lxts_aesdec_start
    jmp  .Lxts_dec_proc_6_blks

.align 16
.Lxts_aesdec_finish:
    vmovdqu TWEAK0, (TWEAK)
    vpxor BLK0, BLK0, BLK0
    vpxor BLK1, BLK1, BLK1
    vpxor BLK2, BLK2, BLK2
    vpxor BLK3, BLK3, BLK3
    vpxor BLK4, BLK4, BLK4
    vpxor BLK5, BLK5, BLK5
    vpxor BLK6, BLK6, BLK6
    vpxor RDK, RDK, RDK
    movl $0, RET

    mov %rbp,%rsp
    add $96,%rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
.cfi_endproc
.size CRYPT_AES_XTS_Decrypt, .-CRYPT_AES_XTS_Decrypt

#endif
