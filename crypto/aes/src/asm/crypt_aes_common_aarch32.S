/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_AES

.file "crypt_aes_common_aarch32.S"
.code   32
.text

/*
 * Data initialization
 * ptr base address
 */
.macro  INIT ptr
    adr lr, \ptr
    ldr r12, [r0, #240]         // Load rounds.
    mov r3, #0xff
.endm

/*
 * Data preprocessing, XOR of plaintext and key (for encryption)
 * offset Address offset
 */
.macro  PRE_PROCESS_ENC offset
    sub lr, lr, #\offset        // Mix_EncTable's address.
    sub r12, r12, #1
    ldr r8, [r0], #16           // Load key.
    eor r4, r4, r8
    ldr r9, [r0, #-12]
    eor r5, r5, r9
    ldr r10, [r0, #-8]
    eor r6, r6, r10
    ldr r11, [r0, #-4]
    eor r7, r7, r11             // Plaintext XOR key.
.endm

/*
 * Loop Encryption Process
 * Excute n - 1 rounds of loop
 */
.macro  LOOP_PROCESS_ENC
.Laes_enc_loop:
    lsr r9, r4, #24             // D
    and r10, r3, r4, lsr#16     // C
    ldr r9, [lr, r9, lsl#2]     // d
    and r11, r3, r4, lsr#8      // B
    ldr r10, [lr, r10, lsl#2]   // c
    and r4, r4, r3              // A
    ldr r11, [lr, r11, lsl#2]   // b
    lsr r1, r5, #24             // H
    ldr r4, [lr, r4, lsl#2]     // A sbox and mix columns.

    and r2, r3, r5, lsr#16      // G
    ldr r1, [lr, r1, lsl#2]
    and r8, r3, r5, lsr#8       // F
    ldr r2, [lr, r2, lsl#2]
    and r5, r5, r3              // E
    ldr r8, [lr, r8, lsl#2]
    eor r10, r10, r1, ror#24    // c ^ h
    ldr r5, [lr, r5, lsl#2]     // Sbox and mix columns.
    eor r4, r4, r8, ror#24      // a ^ f
    eor r11, r11, r2, ror#24    // b ^ g
    lsr r1, r6, #24             // L
    eor r5, r5, r9, ror#8       // e ^ d

    and r8, r3, r6, lsr#16      // K
    subs r12, r12, #1           // Rounds counter.
    and r9, r3, r6, lsr#8       // J
    ldr r1, [lr, r1, lsl#2]
    ldr r8, [lr, r8, lsl#2]
    and r6, r6, r3              // I
    eor r4, r4, r8, ror#16      // a ^ f ^ k
    ldr r9, [lr, r9, lsl#2]
    ldr r6, [lr, r6, lsl#2]     // Sbox and mix columns.
    eor r5, r5, r9, ror#24      // e ^ j ^ d
    lsr r8, r7, #24             // P
    eor r11, r11, r1, ror#16    // b ^ g ^ l
    and r9, r3, r7, lsr#16      // O
    ldr r8, [lr, r8, lsl#2]
    eor r6, r6, r10, ror#16     // i ^ c ^ h

    and r10, r3, r7, lsr#8      // N
    ldr r9, [lr, r9, lsl#2]
    and r7, r7, r3              // M
    ldr r10, [lr, r10, lsl#2]
    eor r4, r4, r8, ror#8       // a ^ f ^ k ^ p
    ldr r7, [lr, r7, lsl#2]     // Sbox and mix columns.
    eor r5, r5, r9, ror#16      // e ^ j ^ o ^ d
    ldr r8, [r0], #16           // Load key.
    eor r6, r6, r10, ror#24     // i ^ n ^ c ^ h
    ldr r9, [r0, #-12]
    eor r7, r7, r11, ror#24     // m ^ b ^ g ^ l

    eor r4, r4, r8
    ldr r10, [r0, #-8]
    eor r5, r5, r9
    ldr r11, [r0, #-4]
    eor r6, r6, r10
    eor r7, r7, r11             // Plaintext XOR key.
    bgt .Laes_enc_loop
.endm

/*
 * Last round of encryption
 * (n - 1) + 1 = n required rounds of encryption completed
 */
.macro  LAST_PROCESS_ENC
    lsr r9, r4, #24             // D
    add lr, lr, #0x400          // Add 1024 to Sbox.
    and r10, r3, r4, lsr#16     // C
    ldrb r9, [lr, r9]
    and r11, r3, r4, lsr#8      // B
    ldrb r10, [lr, r10]
    and r4, r4, r3              // A
    ldrb r11, [lr, r11]
    lsr r1, r5, #24             // H
    ldrb r4, [lr, r4]           // Sbox

    and r2, r3, r5, lsr#16      // G
    ldrb r1, [lr, r1]
    and r8, r3, r5, lsr#8       // F
    ldrb r2, [lr, r2]
    and r5, r5, r3              // E
    ldrb r8, [lr, r8]
    eor r10, r10, r1, lsl#8     // HC
    ldrb r5, [lr, r5]           // Sbox
    eor r4, r4, r8, lsl#8       // 00FA
    eor r11, r11, r2, lsl#8     // GB
    lsr r1, r6, #24             // L
    eor r5, r5, r9, lsl#24      // D00E

    and r8, r3, r6, lsr#16      // K
    ldrb r1, [lr, r1]
    and r9, r3, r6, lsr#8       // J
    ldrb r8, [lr, r8]
    and r6, r6, r3              // I
    ldrb r9, [lr, r9]
    eor r4, r4, r8, lsl#16      // 0KFA
    ldrb r6, [lr, r6]           // sbox
    eor r5, r5, r9, lsl#8       // D0JE
    eor r6, r6, r10, lsl#16     // HC0I
    lsr r8, r7, #24             // P
    eor r11, r11, r1, lsl#16    // LGB

    and r9, r3, r7, lsr#16      // O
    ldrb r8, [lr, r8]
    and r10, r3, r7, lsr#8      // N
    ldrb r9, [lr, r9]
    and r7, r7, r3              // M
    ldrb r10, [lr, r10]
    eor r4, r4, r8, lsl#24      // PKFA
    ldrb r7, [lr, r7]           // sbox
    eor r5, r5, r9, lsl#16      // DOJE
    eor r6, r6, r10, lsl#8      // HCNI
    ldr r8, [r0], #16           // load key
    eor r7, r7, r11, lsl#8      // LGBM
    ldr r9, [r0, #-12]

    eor r4, r4, r8
    ldr r10, [r0, #-8]
    eor r5, r5, r9
    ldr r11, [r0, #-4]
    eor r6, r6, r10
    eor r7, r7, r11             // Plaintext XOR key.
.endm

/*
 * Data preprocessing, XOR between plaintext and key (for decryption)
 * offset Address offset
 */
.macro  PRE_PROCESS_DEC offset
    sub lr, lr, #\offset        // Mix_EncTable's address.
    ldr r8, [r0], #16           // Load key.
    sub r12, r12, #1
    ldr r9, [r0, #-12]
    eor r4, r4, r8
    ldr r10, [r0, #-8]
    eor r5, r5, r9
    ldr r11, [r0, #-4]
    eor r6, r6, r10
    eor r7, r7, r11             // Plaintext XOR key.
.endm

/*
 * Decryption loop processing flow
 * n - 1 round of decryption
 */
.macro  LOOP_PROCESS_DEC
.Laes_dec_loop:
    and r10, r3, r4, lsr#16     // C
    lsr r11, r4, #24            // D
    ldr r10, [lr, r10, lsl#2]
    and r9, r3, r4, lsr#8       // B
    ldr r11, [lr, r11, lsl#2]
    lsl r4, r4, #24             // A
    ldr r9, [lr, r9, lsl#2]
    lsr r8, r5, #24             // H
    ldr r4, [lr, r4, lsr#22]    // (inv)sbox and mix columns

    and r2, r3, r5, lsr#16      // G
    ldr r8, [lr, r8, lsl#2]
    and r1, r3, r5, lsr#8       // F
    ldr r2, [lr, r2, lsl#2]
    and r5, r3, r5              // E
    ldr r1, [lr, r1, lsl#2]
    eor r4, r4, r8, ror#8       // a ^ h
    ldr r5, [lr, r5, lsl#2]     // (inv)sbox and mix columns
    eor r11, r11, r2, ror#8     // g ^ d
    and r8, r3, r6, lsr#16      // K
    eor r10, r10, r1, ror#8     // f ^ c
    eor r5, r5, r9, ror#24      // e ^ b
    lsr r9, r6, #24             // L

    and r1, r3, r6, lsr#8       // J
    ldr r9, [lr, r9, lsl#2]
    and r6, r3, r6              // I
    ldr r8, [lr, r8, lsl#2]
    eor r5, r5, r9, ror#8       // e ^ b ^ l
    ldr r1, [lr, r1, lsl#2]
    eor r4, r4, r8, ror#16      // a ^ k ^ h
    ldr r6, [lr, r6, lsl#2]     // (inv)sbox and mix columns
    eor r11, r11, r1, ror#16    // j ^ g ^ d
    and r9, r3, r7, lsr#16      // O
    eor r6, r6, r10, ror#16     // i ^ f ^ c

    and r8, r3, r7, lsr#8       // N
    ldr r9, [lr, r9, lsl#2]
    lsr r10, r7, #24            // P
    ldr r8, [lr, r8, lsl#2]
    and r7, r3, r7              // M
    ldr r10, [lr, r10, lsl#2]
    eor r5, r5, r9, ror#16      // e ^ b ^ o ^ l
    ldr r7, [lr, r7, lsl#2]     // (inv)sbox and mix columns
    eor r6, r6, r10, ror#8      // i ^ f ^ c ^ p
    subs r12, r12, #1           // Rounds counter.
    eor r4, r4, r8, ror#24      // a ^ n ^ k ^ h
    ldr r8, [r0], #16           // load key
    eor r7, r7, r11, ror#8      // m ^ j ^ g ^ d

    ldr r9, [r0, #-12]
    eor r4, r4, r8
    ldr r10, [r0, #-8]
    eor r5, r5, r9
    ldr r11, [r0, #-4]
    eor r6, r6, r10
    eor r7, r7, r11             // Plaintext XOR key.
    bgt .Laes_dec_loop
.endm

/*
 * Last round of decryption
 * (n - 1) + 1 = n required n rounds of decryption complete
 */
.macro  LAST_PROCESS_DEC
    add lr, lr, #0x400          // Add 1024 to Sbox.
    lsr r11, r4, #24            // D
    and r10, r3, r4, lsr#16     // C
    ldrb r11, [lr, r11]
    and r9, r3, r4, lsr#8       // B
    ldrb r10, [lr, r10]
    and r4, r4, r3              // A
    ldrb r9, [lr, r9]
    lsr r8, r5, #24             // H
    ldrb r4, [lr, r4]           // (inv)sbox

    and r2, r3, r5, lsr#16      // G
    ldrb r8, [lr, r8]
    and r1, r3, r5, lsr#8       // F
    ldrb r2, [lr, r2]
    and r5, r5, r3              // E
    ldrb r1, [lr, r1]
    eor r4, r4, r8, lsl#24      // H00A
    ldrb r5, [lr, r5]           // (inv)sbox
    eor r10, r1, r10, lsl#8     // CF
    eor r5, r5, r9, lsl#8       // 00BE
    and r8, r3, r6, lsr#16      // K
    eor r11, r2, r11, lsl#8     // DG

    lsr r9, r6, #24             // L
    and r1, r3, r6, lsr#8       // J
    ldrb r9, [lr, r9]
    and r6, r6, r3              // I
    ldrb r8, [lr, r8]
    eor r4, r4, r8, lsl#16      // HK0A
    ldrb r1, [lr, r1]
    eor r5, r5, r9, lsl#24      // L0BE
    ldrb r6, [lr, r6]           // (inv)sbox
    eor r11, r1, r11, lsl#8     // DGJ
    and r9, r3, r7, lsr#16      // O
    eor r6, r6, r10, lsl#8      // CFI

    lsr r10, r7, #24            // P
    and r8, r3, r7, lsr#8       // N
    ldrb r10, [lr, r10]
    and r7, r7, r3              // M
    ldrb r9, [lr, r9]
    eor r5, r5, r9, lsl#16      // LOBE
    ldrb r8, [lr, r8]
    eor r4, r4, r8, lsl#8       // HKNA
    ldrb r7, [lr, r7]           // (inv)sbox
    eor r6, r6, r10, lsl#24     // PCFI
    ldr r8, [r0], #16           // load key
    eor r7, r7, r11, lsl#8      // DGJM

    ldr r9, [r0, #-12]
    eor r4, r4, r8
    ldr r10, [r0, #-8]
    eor r5, r5, r9
    ldr r11, [r0, #-4]
    eor r6, r6, r10
    eor r7, r7, r11             // Plaintext XOR key.
.endm

.macro  RESULT ptr
    str r4, [\ptr]
    str r5, [\ptr, #4]
    str r6, [\ptr, #8]
    str r7, [\ptr, #12]         // Return result.
    eor r0, r0, r0              // Return CRYPT_SUCCESS.
.endm

#endif
