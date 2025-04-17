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

.file   "crypt_aes_ctr_x86_64.S"
.text

.set    KEY, %rdi
.set    INPUT, %rsi
.set    OUTPUT, %rdx
.set    LEN, %ecx
.set    CTR_IV, %r8

.set    RDK, %xmm0
.set    RDK2, %xmm1
.set    KTMP, %r13
.set    ROUNDS, %eax
.set    RET, %eax

.set    IV0, %xmm2
.set    IV1, %xmm3
.set    IV2, %xmm4
.set    IV3, %xmm5
.set    IV4, %xmm6
.set    IV5, %xmm7
.set    IV6, %xmm8
.set    IV7, %xmm9
.set    BLK0, %xmm10
.set    BLK1, %xmm11
.set    BLK2, %xmm12
.set    BLK3, %xmm13
.set    BLK4, %xmm14
.set    BLK5, %xmm15

/**
 *    Macro description: Eight IVs are encrypted.
 *       Input register:
 *                  Key: Round key.
 *             block0-7: Encrypted IV.
 *  Modify the register:  block0-7.
 *      Output register:
 *             block0-7:  IV after a round of encryption.
 */
.macro ONE_ENC key block0 block1 block2 block3 block4 block5 block6 block7
    aesenc  \key, \block0
    aesenc  \key, \block1
    aesenc  \key, \block2
    aesenc  \key, \block3
    aesenc  \key, \block4
    aesenc  \key, \block5
    aesenc  \key, \block6
    aesenc  \key, \block7
.endm

/**
 *  Macro description: Obtains a new ctr and XORs it with the round key.
 *  input register：
 *      ctr32：Initialization vector.
 *     offset：Offset.
 *       temp：32-bit CTR temporary register.
 *      key32：32-bit round key.
 * addrOffset：push stack address offset.
 *       addr：push stack address.
 *  Modify the register： Temp.
 */
.macro XOR_KEY ctr32 offset temp key32 addrOffset addr
    leal \offset(\ctr32), \temp                 // XOR 32-bit ctr and key, push into the stack
    bswapl \temp
    xorl \key32, \temp
    movl \temp, \addrOffset+12(\addr)
.endm

/**
 *  Macro description: Obtain the round key, encrypt the IV, obtain the next round of ctr, and XOR the round key.
 *  Input register:
 *              Key: pointer to the key.
 *           Offset: round key offset.
 *             Temp: Temporary register for the round key.
 *            Ctr32: initialization vector.
 *          Offset2: Ctr offset.
 *            Temp2: 32-bit CTR temporary register.
 *            Key32: 32-bit round key.
 *       AddrOffset: Offest of entering the stack.
 *             Addr: Address for entering the stack.
 *  Modify register: Temp temp2 IV0-7.
 *  Output register:
 *            IV0-7:  IV after a round of encryption.
 */
.macro ONE_ENC_XOR_KEY key offset temp ctr32 offset2 temp2 key32 addrOffset addr
    vmovdqu \offset(\key), \temp
    aesenc  \temp, IV0
    leal    \offset2(\ctr32), \temp2                 // XOR 32-bit ctr and key, push stack.
    aesenc  \temp, IV1
    bswapl  \temp2
    aesenc  \temp, IV2
    aesenc  \temp, IV3
    xorl    \key32, \temp2
    aesenc  \temp, IV4
    aesenc  \temp, IV5
    movl    \temp2, \addrOffset+12(\addr)
    aesenc  \temp, IV6
    aesenc  \temp, IV7

.endm

/**
 *  Macro description: Update the in and out pointer offsets and the remaining length of len.
 *       Input register：
 *                Input：pointer to the input memory.
 *               Output：pointer to the output memory.
 *                  Len：remaining data length.
 *               Offset：indicates the offset.
 *  Modify the register： Input output len.
 *      Output register：
 *      Input output len
 */
.macro UPDATE_DATA input output len offset
    leaq    \offset(\input), \input
    leaq    \offset(\output), \output
    subl    $\offset, \len
.endm

/**
 *  Function description：Sets the AES encrypted assembly acceleration API, ctr mode.
 *  Function prototype：int32_t CRYPT_AES_CTR_Encrypt(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out,
 *                                          uint32_t len, uint8_t *iv);
 *  Input register：
 *        rdi：Pointer to the input key structure.
 *        rsi：Points to the 128-bit input data.
 *        rdx：Points to the 128-bit output data.
 *        rcx：Length of the data block, that is, 16 bytes.
 *         r8: 16-byte initialization vector.
 *  Change register：xmm1, xmm3, xmm4, xmm5, xmm6, xmm10, xmm11, xmm12, xmm13.
 *  Output register：rdx, r8.
 */
.globl  CRYPT_AES_CTR_Encrypt
    .type   CRYPT_AES_CTR_Encrypt, @function
CRYPT_AES_CTR_Encrypt:
    .cfi_startproc
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    mov     %rsp, %r12
    subq    $128, %rsp                      // Declare for 128-byte stack space.
    andq    $-16, %rsp

    vmovdqu (KEY), RDK
    vpxor   (CTR_IV), RDK, IV0
    vmovdqa IV0, 0(%rsp)
    vmovdqa IV0, 16(%rsp)
    vmovdqa IV0, 32(%rsp)
    vmovdqa IV0, 48(%rsp)
    vmovdqa IV0, 64(%rsp)
    vmovdqa IV0, 80(%rsp)
    vmovdqa IV0, 96(%rsp)
    vmovdqa IV0, 112(%rsp)

    movl    12(CTR_IV), %r11d              // Read 32-bit ctr.
    movl    12(KEY), %r9d                  // Read 32-bit key.
    bswap   %r11d

    mov     LEN, %r14d
    shr    $4, %r14d
    and    $7, %r14d
    cmp     $1, %r14d
    je .Lctr_enc_proc_1_blk
    cmp     $2, %r14d
    je .Lctr_enc_proc_2_blk
    cmp     $3, %r14d
    je .Lctr_enc_proc_3_blk
    cmp     $4, %r14d
    je .Lctr_enc_proc_4_blk
    cmp     $5, %r14d
    je .Lctr_enc_proc_5_blk
    cmp     $6, %r14d
    je .Lctr_enc_proc_6_blk
    cmp     $7, %r14d
    je .Lctr_enc_proc_7_blk

.Lctr_enc_proc_8_blk:
    cmp $0, LEN
    je .Lctr_aesenc_finish

    leal 0(%r11d), %r15d
    leal 1(%r11d), %r10d
    bswapl %r15d
    bswapl %r10d
    xorl %r9d, %r15d
    xorl %r9d, %r10d
    leal 2(%r11d), %r14d
    movl %r15d, 12(%rsp)
    bswapl %r14d
    movl %r10d, 16+12(%rsp)
    xorl %r9d, %r14d
    leal 3(%r11d), %r15d
    leal 4(%r11d), %r10d
    bswapl %r15d
    bswapl %r10d
    movl %r14d, 32+12(%rsp)
    xorl %r9d, %r15d
    xorl %r9d, %r10d
    movl %r15d, 48+12(%rsp)
    leal 5(%r11d), %r14d
    bswapl %r14d
    movl %r10d, 64+12(%rsp)
    xorl %r9d, %r14d
    leal 6(%r11d), %r15d
    leal 7(%r11d), %r10d
    movl %r14d, 80+12(%rsp)
    bswapl %r15d
    bswapl %r10d
    xorl %r9d, %r15d
    xorl %r9d, %r10d
    movl %r15d, 96+12(%rsp)
    movl %r10d, 112+12(%rsp)

    vmovdqa (%rsp), IV0
    vmovdqa 16(%rsp), IV1
    vmovdqa 32(%rsp), IV2
    vmovdqa 48(%rsp), IV3
    vmovdqa 64(%rsp), IV4
    vmovdqa 80(%rsp), IV5
    vmovdqa 96(%rsp), IV6
    vmovdqa 112(%rsp), IV7
.align 16
.Lctr_aesenc_8_blks_enc_loop:
    addl    $8, %r11d                                                   // ctr+8
    movl    240(KEY), ROUNDS
    ONE_ENC_XOR_KEY KEY, 16, RDK2, %r11d, 0, %r10d, %r9d, 0, %rsp       // Round 1 encryption
    ONE_ENC_XOR_KEY KEY, 32, RDK2, %r11d, 1, %r10d, %r9d, 16, %rsp      // Round 2 encryption
    ONE_ENC_XOR_KEY KEY, 48, RDK2, %r11d, 2, %r10d, %r9d, 32, %rsp      // Round 3 encryption
    ONE_ENC_XOR_KEY KEY, 64, RDK2, %r11d, 3, %r10d, %r9d, 48, %rsp      // Round 4 encryption
    ONE_ENC_XOR_KEY KEY, 80, RDK2, %r11d, 4, %r10d, %r9d, 64, %rsp      // Round 5 encryption
    ONE_ENC_XOR_KEY KEY, 96, RDK2, %r11d, 5, %r10d, %r9d, 80, %rsp      // Round 6 encryption
    ONE_ENC_XOR_KEY KEY, 112, RDK2, %r11d, 6, %r10d, %r9d, 96, %rsp     // Round 7 encryption
    ONE_ENC_XOR_KEY KEY, 128, RDK2, %r11d, 7, %r10d, %r9d, 112, %rsp    // Round 8 encryption

    vmovdqu 144(KEY), RDK                                               // Round 9 key Load
    vmovdqu 160(KEY), RDK2                                              // Round 10 key Load
    cmp     $12, ROUNDS
    jb .Lctr_aesenc_8_blks_enc_last

    ONE_ENC RDK, IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7                 // Round 9 encryption
    vmovdqu 176(KEY), RDK                                               // Round 11 key Load
    ONE_ENC RDK2, IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7                // Round 10 encryption
    vmovdqu 192(KEY), RDK2                                              // Round 12 key Load

    je .Lctr_aesenc_8_blks_enc_last

    ONE_ENC RDK, IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7                 // Round 11 encryption
    vmovdqu 208(KEY), RDK                                               // Round 13 key Load
    ONE_ENC RDK2, IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7                // Round 12 encryption
    vmovdqu 224(KEY), RDK2                                              // Round 14 key Load

.align 16
.Lctr_aesenc_8_blks_enc_last:
    vpxor   (INPUT), RDK2, BLK0         // Last round Key ^ Plaintext.
    vpxor   16(INPUT), RDK2, BLK1
    vpxor   32(INPUT), RDK2, BLK2
    vpxor   48(INPUT), RDK2, BLK3

    ONE_ENC RDK, IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7

    aesenclast BLK0, IV0                // Last round of encryption.
    aesenclast BLK1, IV1
    aesenclast BLK2, IV2
    aesenclast BLK3, IV3
    aesenclast RDK2, IV4
    aesenclast RDK2, IV5
    aesenclast RDK2, IV6
    aesenclast RDK2, IV7

    vmovdqu IV0, (OUTPUT)               // The first four ciphertexts are stored in out.
    vmovdqu IV1, 16(OUTPUT)
    vmovdqu IV2, 32(OUTPUT)
    vmovdqu IV3, 48(OUTPUT)
    vpxor   64(INPUT), IV4, BLK0        // Last Round Key ^ Plaintext.
    vpxor   80(INPUT), IV5, BLK1
    vpxor   96(INPUT), IV6, BLK2
    vpxor   112(INPUT), IV7, BLK3

    vmovdqu BLK0, 64(OUTPUT)
    vmovdqu BLK1, 80(OUTPUT)
    vmovdqu BLK2, 96(OUTPUT)            // The last four ciphertexts are stored in out.
    vmovdqu BLK3, 112(OUTPUT)
    vmovdqa (%rsp), IV0                 // Reads the next round of ctr from the stack.
    vmovdqa 16(%rsp), IV1
    vmovdqa 32(%rsp), IV2
    vmovdqa 48(%rsp), IV3
    vmovdqa 64(%rsp), IV4
    vmovdqa 80(%rsp), IV5
    vmovdqa 96(%rsp), IV6
    vmovdqa 112(%rsp), IV7
    UPDATE_DATA INPUT, OUTPUT, LEN, 128
    cmpl    $0, LEN
    jbe .Lctr_aesenc_finish
    jmp .Lctr_aesenc_8_blks_enc_loop

.Lctr_enc_proc_1_blk:
    movl    240(KEY), ROUNDS
    movq    KEY, KTMP
    decl    ROUNDS
.align  16
.Laesenc_loop:
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenc  RDK, IV0
    decl    ROUNDS
    jnz .Laesenc_loop                   // Loop the loop until the ROUNDS is 0.
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenclast RDK, IV0
    addl    $1, %r11d                   // Update ctr32.
    vpxor   (INPUT), IV0, BLK0
    vmovdqu BLK0, (OUTPUT)              // Ciphertext stored in out.
    UPDATE_DATA INPUT, OUTPUT, LEN, 16
    jmp .Lctr_enc_proc_8_blk
.Lctr_enc_proc_2_blk:
    movl    240(KEY), ROUNDS
    movq    KEY, KTMP
    decl    ROUNDS
    XOR_KEY %r11d, 1, %r10d, %r9d, 16, %rsp
    vmovdqa 16(%rsp), IV1
.align 16
.Laesenc_2_blks_loop:
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenc  RDK, IV0
    aesenc  RDK, IV1
    decl    ROUNDS
    jnz .Laesenc_2_blks_loop
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenclast RDK, IV0
    aesenclast RDK, IV1

    vpxor   (INPUT), IV0, BLK0
    vpxor   16(INPUT), IV1, BLK1
    vmovdqu BLK0, (OUTPUT)
    vmovdqu BLK1, 16(OUTPUT)
    addl    $2, %r11d
    UPDATE_DATA INPUT, OUTPUT, LEN, 32
    jmp  .Lctr_enc_proc_8_blk
.Lctr_enc_proc_3_blk:
    movl    240(KEY), ROUNDS
    movq    KEY, KTMP
    decl    ROUNDS
    XOR_KEY %r11d, 1, %r10d, %r9d, 16, %rsp
    XOR_KEY %r11d, 2, %r10d, %r9d, 32, %rsp
    vmovdqa 16(%rsp), IV1
    vmovdqa 32(%rsp), IV2
.align 16
.Laesenc_3_blks_loop:
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenc  RDK, IV0
    aesenc  RDK, IV1
    aesenc  RDK, IV2
    decl    ROUNDS
    jnz .Laesenc_3_blks_loop
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenclast RDK, IV0
    aesenclast RDK, IV1
    aesenclast RDK, IV2

    vpxor   (INPUT), IV0, BLK0
    vpxor   16(INPUT), IV1, BLK1
    vpxor   32(INPUT), IV2, BLK2

    vmovdqu BLK0, (OUTPUT)
    vmovdqu BLK1, 16(OUTPUT)
    vmovdqu BLK2, 32(OUTPUT)
    addl    $3, %r11d
    UPDATE_DATA INPUT, OUTPUT, LEN, 48
    jmp  .Lctr_enc_proc_8_blk
.Lctr_enc_proc_4_blk:
    movl    240(KEY), ROUNDS
    movq    KEY, KTMP
    decl    ROUNDS
    XOR_KEY %r11d, 1, %r10d, %r9d, 16, %rsp
    XOR_KEY %r11d, 2, %r10d, %r9d, 32, %rsp
    XOR_KEY %r11d, 3, %r10d, %r9d, 48, %rsp
    vmovdqa 16(%rsp), IV1
    vmovdqa 32(%rsp), IV2
    vmovdqa 48(%rsp), IV3
.align 16
.Laesenc_4_blks_loop:
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenc  RDK, IV0
    aesenc  RDK, IV1
    aesenc  RDK, IV2
    aesenc  RDK, IV3
    decl    ROUNDS
    jnz .Laesenc_4_blks_loop
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenclast RDK, IV0
    aesenclast RDK, IV1
    aesenclast RDK, IV2
    aesenclast RDK, IV3

    vpxor   (INPUT), IV0, BLK0
    vpxor   16(INPUT), IV1, BLK1
    vpxor   32(INPUT), IV2, BLK2
    vpxor   48(INPUT), IV3, BLK3

    vmovdqu BLK0, (OUTPUT)
    vmovdqu BLK1, 16(OUTPUT)
    vmovdqu BLK2, 32(OUTPUT)
    vmovdqu BLK3, 48(OUTPUT)
    addl    $4, %r11d
    UPDATE_DATA INPUT, OUTPUT, LEN, 64
    jmp  .Lctr_enc_proc_8_blk

.Lctr_enc_proc_5_blk:
    movl    240(KEY), ROUNDS
    movq    KEY, KTMP
    decl ROUNDS
    XOR_KEY %r11d, 1, %r10d, %r9d, 16, %rsp
    XOR_KEY %r11d, 2, %r10d, %r9d, 32, %rsp
    XOR_KEY %r11d, 3, %r10d, %r9d, 48, %rsp
    XOR_KEY %r11d, 4, %r10d, %r9d, 64, %rsp
    vmovdqa 16(%rsp), IV1
    vmovdqa 32(%rsp), IV2
    vmovdqa 48(%rsp), IV3
    vmovdqa 64(%rsp), IV4
.align 16
.Laesenc_5_blks_loop:
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenc  RDK, IV0
    aesenc  RDK, IV1
    aesenc  RDK, IV2
    aesenc  RDK, IV3
    aesenc  RDK, IV4
    decl    ROUNDS
    jnz .Laesenc_5_blks_loop
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenclast RDK, IV0
    aesenclast RDK, IV1
    aesenclast RDK, IV2
    aesenclast RDK, IV3
    aesenclast RDK, IV4

    vpxor   (INPUT), IV0, BLK0
    vpxor   16(INPUT), IV1, BLK1
    vpxor   32(INPUT), IV2, BLK2
    vpxor   48(INPUT), IV3, BLK3
    vpxor   64(INPUT), IV4, BLK4
    vmovdqu BLK0, (OUTPUT)
    vmovdqu BLK1, 16(OUTPUT)
    vmovdqu BLK2, 32(OUTPUT)
    vmovdqu BLK3, 48(OUTPUT)
    vmovdqu BLK4, 64(OUTPUT)
    addl    $5, %r11d
    UPDATE_DATA INPUT, OUTPUT, LEN, 80
    jmp  .Lctr_enc_proc_8_blk
.Lctr_enc_proc_6_blk:
    movl    240(KEY), ROUNDS
    movq    KEY, KTMP
    decl    ROUNDS
    XOR_KEY %r11d, 1, %r10d, %r9d, 16, %rsp
    XOR_KEY %r11d, 2, %r10d, %r9d, 32, %rsp
    XOR_KEY %r11d, 3, %r10d, %r9d, 48, %rsp
    XOR_KEY %r11d, 4, %r10d, %r9d, 64, %rsp
    XOR_KEY %r11d, 5, %r10d, %r9d, 80, %rsp
    vmovdqa 16(%rsp), IV1
    vmovdqa 32(%rsp), IV2
    vmovdqa 48(%rsp), IV3
    vmovdqa 64(%rsp), IV4
    vmovdqa 80(%rsp), IV5
.align 16
.Laesenc_6_blks_loop:
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenc  RDK, IV0
    aesenc  RDK, IV1
    aesenc  RDK, IV2
    aesenc  RDK, IV3
    aesenc  RDK, IV4
    aesenc  RDK, IV5
    decl    ROUNDS
    jnz .Laesenc_6_blks_loop
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenclast RDK, IV0
    aesenclast RDK, IV1
    aesenclast RDK, IV2
    aesenclast RDK, IV3
    aesenclast RDK, IV4
    aesenclast RDK, IV5

    vpxor   (INPUT), IV0, BLK0
    vpxor   16(INPUT), IV1, BLK1
    vpxor   32(INPUT), IV2, BLK2
    vpxor   48(INPUT), IV3, BLK3
    vpxor   64(INPUT), IV4, BLK4
    vpxor   80(INPUT), IV5, BLK5
    vmovdqu BLK0, (OUTPUT)
    vmovdqu BLK1, 16(OUTPUT)
    vmovdqu BLK2, 32(OUTPUT)
    vmovdqu BLK3, 48(OUTPUT)
    vmovdqu BLK4, 64(OUTPUT)
    vmovdqu BLK5, 80(OUTPUT)
    addl    $6, %r11d
    UPDATE_DATA INPUT, OUTPUT, LEN, 96

    jmp  .Lctr_enc_proc_8_blk
.Lctr_enc_proc_7_blk:
    movl    240(KEY), ROUNDS
    movq    KEY, KTMP
    decl    ROUNDS
    XOR_KEY %r11d, 1, %r10d, %r9d, 16, %rsp
    XOR_KEY %r11d, 2, %r10d, %r9d, 32, %rsp
    XOR_KEY %r11d, 3, %r10d, %r9d, 48, %rsp
    XOR_KEY %r11d, 4, %r10d, %r9d, 64, %rsp
    XOR_KEY %r11d, 5, %r10d, %r9d, 80, %rsp
    XOR_KEY %r11d, 6, %r10d, %r9d, 96, %rsp
    vmovdqa 16(%rsp), IV1
    vmovdqa 32(%rsp), IV2
    vmovdqa 48(%rsp), IV3
    vmovdqa 64(%rsp), IV4
    vmovdqa 80(%rsp), IV5
    vmovdqa 96(%rsp), IV6

.align 16
.Laesenc_7_blks_loop:
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenc  RDK, IV0
    aesenc  RDK, IV1
    aesenc  RDK, IV2
    aesenc  RDK, IV3
    aesenc  RDK, IV4
    aesenc  RDK, IV5
    aesenc  RDK, IV6
    decl    ROUNDS
    jnz .Laesenc_7_blks_loop
    leaq    16(KTMP), KTMP
    vmovdqu (KTMP), RDK
    aesenclast RDK, IV0
    aesenclast RDK, IV1
    aesenclast RDK, IV2
    aesenclast RDK, IV3
    aesenclast RDK, IV4
    aesenclast RDK, IV5
    aesenclast RDK, IV6
    vpxor   (INPUT), IV0, BLK0
    vpxor   16(INPUT), IV1, BLK1
    vpxor   32(INPUT), IV2, BLK2
    vpxor   48(INPUT), IV3, BLK3
    vmovdqu BLK0, (OUTPUT)
    vmovdqu BLK1, 16(OUTPUT)
    vmovdqu BLK2, 32(OUTPUT)
    vmovdqu BLK3, 48(OUTPUT)
    vpxor   64(INPUT), IV4, BLK0
    vpxor   80(INPUT), IV5, BLK1
    vpxor   96(INPUT), IV6, BLK2
    vmovdqu BLK0, 64(OUTPUT)
    vmovdqu BLK1, 80(OUTPUT)
    vmovdqu BLK2, 96(OUTPUT)
    addl    $7, %r11d
    UPDATE_DATA INPUT, OUTPUT, LEN, 112
    jmp  .Lctr_enc_proc_8_blk

.Lctr_aesenc_finish:
    bswap   %r11d
    movl    %r11d, 12(CTR_IV)
    vpxor   IV0, IV0, IV0
    vpxor   IV1, IV1, IV1
    vpxor   IV2, IV2, IV2
    vpxor   IV3, IV3, IV3
    vpxor   IV4, IV4, IV4
    vpxor   IV5, IV5, IV5
    vpxor   IV6, IV6, IV6
    vpxor   IV7, IV7, IV7
    vpxor   RDK, RDK, RDK
    vmovdqa IV0, 0(%rsp)
    vmovdqa IV0, 16(%rsp)
    vmovdqa IV0, 32(%rsp)
    vmovdqa IV0, 48(%rsp)
    vmovdqa IV0, 64(%rsp)
    vmovdqa IV0, 80(%rsp)
    vmovdqa IV0, 96(%rsp)
    vmovdqa IV0, 112(%rsp)

    movq    %r12, %rsp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12

    movl    $0, RET
    ret
    .cfi_endproc
    .size CRYPT_AES_CTR_Encrypt, .-CRYPT_AES_CTR_Encrypt

#endif
