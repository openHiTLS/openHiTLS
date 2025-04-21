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

#include "crypt_arm.h"
#include "crypt_aes_macro_armv8.s"
.file    "crypt_aes_armv8.S"
.text
.arch    armv8-a+crypto

KEY     .req    x0
IN      .req    x1
OUT     .req    x2

ROUNDS  .req    w6

RDK0    .req    v17
RDK1    .req    v18

.section .rodata
.align  5
.g_cron:
.long   0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
.align  5

/*
 * In Return-oriented programming (ROP) and Jump-oriented programming (JOP), we explored features
 * that Arm introduced to the Arm architecture to mitigate against JOP-style and ROP-style attacks.
 * ...
 * Whether the combined or NOP-compatible instructions are set depends on the architecture
 * version that the code is built for. When building for Armv8.3-A, or later, the compiler will use
 * the combined operations. When building for Armv8.2-A, or earlier, it will use the NOP compatible
 * instructions.
 *
 * The paciasp and autiasp instructions are used for function pointer authentication.
 * The pointer authentication feature is added in armv8.3 and is supported only by AArch64.
 * The addition of pointer authentication features is described in Section A2.6.1 of
 * DDI0487H_a_a-profile_architecture_reference_manual.pdf.
 */

/*
 * int32_t CRYPT_AES_Encrypt(const CRYPT_AES_Key *ctx,
 *                              const uint8_t *in,
 *                              uint8_t *out,
 *                              uint32_t len);
 */
.text
.globl  CRYPT_AES_Encrypt
.type   CRYPT_AES_Encrypt, %function
.align  5
CRYPT_AES_Encrypt:
.ecb_aesenc_start:
AARCH64_PACIASP
    stp x29, x30, [sp, #-16]!
    add x29, sp, #0

    ld1 {BLK0.16b}, [IN]
    AES_ENC_1_BLK KEY BLK0.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b}, [OUT]

    eor x0, x0, x0
    eor RDK0.16b, RDK0.16b, RDK0.16b
    eor RDK1.16b, RDK1.16b, RDK1.16b
    ldp x29, x30, [sp], #16
AARCH64_AUTIASP
    ret
.size   CRYPT_AES_Encrypt, .-CRYPT_AES_Encrypt

/*
 * int32_t CRYPT_AES_Decrypt(const CRYPT_AES_Key *ctx,
 *                              const uint8_t *in,
 *                              uint8_t *out,
 *                              uint32_t len);
 */
.globl  CRYPT_AES_Decrypt
.type   CRYPT_AES_Decrypt, %function
.align  5
CRYPT_AES_Decrypt:
.ecb_aesdec_start:
AARCH64_PACIASP
    stp x29, x30, [sp, #-16]!
    add x29, sp, #0

    ld1 {BLK0.16b}, [IN]
    AES_DEC_1_BLK KEY BLK0.16b RDK0.4s RDK1.4s RDK0.16b RDK1.16b ROUNDS
    st1 {BLK0.16b}, [OUT]

    eor x0, x0, x0
    eor RDK0.16b, RDK0.16b, RDK0.16b
    eor RDK1.16b, RDK1.16b, RDK1.16b
    ldp x29, x30, [sp], #16
AARCH64_AUTIASP
    ret
.size   CRYPT_AES_Decrypt, .-CRYPT_AES_Decrypt

/*
 * void SetEncryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key);
 * Generating extended keys.
 * x0 => CRYPT_AES_Key *ctx; x1 => const uint8_t *key
 */
.globl  SetEncryptKey128
.type   SetEncryptKey128, %function
.align  5
SetEncryptKey128:
.Lenc_key_128:
AARCH64_PACIASP
    stp x29, x30, [sp, #-64]!
    add x29, sp, #0
    stp x25, x26, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x21, x22, [sp, #48]             // Register push stack completed.

    adrp x23, .g_cron
    add x23, x23, :lo12:.g_cron         // Round key start address.
    mov x24, x0                         // Copy key string address. The address increases by 16 bytes.
    ld1 {v1.16b}, [x1]                  // Reads the 16-byte key of a user.
    mov w26, #10                        // Number of encryption rounds, which is filled
                                        // with rounds in the structure.
    st1 {v1.4s}, [x0], #16              // Save the first key.
    eor v0.16b, v0.16b, v0.16b          // Clear zeros in V0.
    mov w25, #10                        // loop for 10 times.
.Lenc_key_128_loop:
    ldr w21, [x23], #4                  // Obtains the round constant.
    dup v1.4s, v1.s[3]                  // Repeated four times,The last word of v1 is changed to v1 (128 bits).
    ld1 {v2.4s}, [x24], #16             // Obtains the 4 words used for XOR.
    ext v1.16b, v1.16b, v1.16b, #1      // Byte loop.
    dup v3.4s, w21                      // Repeat four times to change w21 to v3 (128 bits).
    aese v1.16b, v0.16b                 // Xor then shift then sbox (XOR operation with 0 is itself,
                                        // equivalent to omitting the XOR operation).
    subs w25, w25, #1                   // Count of 10-round key extension.
    eor v1.16b, v1.16b, v3.16b          // Round constant XOR.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (1).
    ext v2.16b, v0.16b, v2.16b, #12     // 4321->3210.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (2).
    ext v2.16b, v0.16b, v2.16b, #12     // 3210->2100.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (3).
    ext v2.16b, v0.16b, v2.16b, #12     // 2100->1000.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (4).
    st1 {v1.4s}, [x0], #16              // Stores the newly calculated 4-bytes key data into the key string.
    b.ne .Lenc_key_128_loop             // Loop jump.
    str w26, [x0, #64]                  // Fill in the number of rounds.
    eor x24, x24, x24                   // Clear sensitivity.
    eor x0, x0, x0
    ldp x21, x22, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #16]
    ldp x29, x30, [sp], #64             // Pop stack completed.
AARCH64_AUTIASP
    ret
.size   SetEncryptKey128, .-SetEncryptKey128


/*
 * void SetDecryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key);
 * Set a decryption key string.
 * x0 => CRYPT_AES_Key *ctx; x1 => const uint8_t *key
 */
.globl  SetDecryptKey128
.type   SetDecryptKey128, %function
.align 5
SetDecryptKey128:
AARCH64_PACIASP
    stp x29, x30, [sp, #-32]!
    add x29, sp, #0
    stp x25, x28, [sp, #16]             // Register push stack completed.

    mov x28, x0
    bl .Lenc_key_128
    ld1 {v0.4s}, [x28], #16
    SETDECKEY_LDR_9_BLOCK x28
    ld1 {v10.4s}, [x28]
    mov x25, #-16
    SETDECKEY_INVMIX_9_BLOCK
    st1 {v0.4s}, [x28], x25
    SETDECKEY_STR_9_BLOCK x28, x25
    st1 {v10.4s}, [x28]
    eor x28, x28, x28
    eor x0, x0, x0
    ldp x25, x28, [sp, #16]
    ldp x29, x30, [sp], #32             // Stacking completed.
AARCH64_AUTIASP
    ret
.size   SetDecryptKey128, .-SetDecryptKey128


/*
 * void SetEncryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key);
 * Generating extended keys.
 * x0 => CRYPT_AES_Key *ctx; x1 => const uint8_t *key
 */
.globl  SetEncryptKey192
.type   SetEncryptKey192, %function
.align 5
SetEncryptKey192:
.Lenc_key_192:
AARCH64_PACIASP
    stp x29, x30, [sp, #-64]!
    add x29, sp, #0
    stp x25, x26, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x21, x22, [sp, #48]             // Register push stack completed.

    mov x24, x0                         // Copy key string address. The address increases by 16 bytes.
    ld1 {v0.16b}, [x1], #16             // Obtain the first 128-bit key.
    mov w26, #12                        // Number of encryption rounds.
    st1 {v0.4s}, [x0], #16              // Store the first 128-bit key.
    ld1 {v1.8b}, [x1]                   // Obtains the last 64-bit key.
    adrp x23, .g_cron
    add x23, x23, :lo12:.g_cron         // Round key start address.
    st1 {v1.2s}, [x0], #8               // Store the last 64-bit key.
    eor v0.16b, v0.16b, v0.16b          // Clear zeros in V0.
    mov w25, #8                         // loop for 8 times.
.Lenc_key_192_loop:
    dup v1.4s, v1.s[1]                  // Repeated four times,The last word of v1 is changed to v1 (128 bits).
    subs w25, w25, #1                   // Count of 8-round key extensions.
    ext v1.16b, v1.16b, v1.16b, #1      // Byte cycle.
    ldr w22, [x23], #4                  // Obtains the round constant.
    aese v1.16b, v0.16b                 // Shift and sbox (XOR operation with 0 is itself,equivalent to omitting the XOR operation).
    dup v2.4s, w22                      // Repeat 4 times. W22 becomes v2(128bit).
    eor v1.16b, v1.16b, v2.16b          // Round constant XOR.
    ld1 {v2.4s}, [x24], #16             // Obtains the 4 words used for XOR
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (1).
    ext v2.16b, v0.16b, v2.16b, #12     // 4321->3210.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (2).
    ext v2.16b, v0.16b, v2.16b, #12     // 3210->2100.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (3).
    ext v2.16b, v0.16b, v2.16b, #12     // 2100->1000.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (4).
    st1 {v1.4s}, [x0], #16              // Stores the newly calculated 4-word key data into the key string.
    ld1 {v2.2s}, [x24], #8              // Loads 6 words for the last 2 words of XOR.
    dup v1.2s, v1.s[3]                  // Repeated two times,The last word of v1 is changed to v1 （64bit）.
    eor v1.8b, v1.8b, v2.8b             // 2 XOR operation (1).
    ext v2.8b, v0.8b, v2.8b, #4         // 21->10.
    eor v1.8b, v1.8b, v2.8b             // 2 XOR operation (2).
    st1 {v1.2s}, [x0], #8               // Stores the newly calculated 2-word key data into the key string.
    b.ne .Lenc_key_192_loop             // Loop jump.
    str w26, [x0, #24]                  // Fill in the number of rounds.
    eor x24, x24, x24                   // Clear sensitivity.
    eor x0, x0, x0
    ldp x21, x22, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #16]
    ldp x29, x30, [sp], #64             // Stacking completed.
AARCH64_AUTIASP
    ret
.size   SetEncryptKey192, .-SetEncryptKey192


/*
 * void SetDecryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key);
 * Set a decryption key string.
 * x0 => CRYPT_AES_Key *ctx; x1 => const uint8_t *key
 */
.globl  SetDecryptKey192
.type   SetDecryptKey192, %function
.align 5
SetDecryptKey192:
AARCH64_PACIASP
    stp x29, x30, [sp, #-32]!
    add x29, sp, #0
    stp x25, x28, [sp, #16]             // Register is stacked.

    mov x28, x0
    bl .Lenc_key_192
    mov x25, #-16
    ld1 {v0.4s}, [x28], #16
    SETDECKEY_LDR_9_BLOCK x28
    ld1 {v10.4s}, [x28], #16
    ld1 {v11.4s}, [x28], #16
    ld1 {v12.4s}, [x28]
    SETDECKEY_INVMIX_9_BLOCK
    aesimc v10.16b, v10.16b
    aesimc v11.16b, v11.16b
    st1 {v0.4s}, [x28], x25
    SETDECKEY_STR_9_BLOCK x28, x25
    st1 {v10.4s}, [x28], x25
    st1 {v11.4s}, [x28], x25
    st1 {v12.4s}, [x28]
    eor x28, x28, x28
    eor x0, x0, x0
    ldp x25, x28, [sp, #16]
    ldp x29, x30, [sp], #32             // Stacking completed.
AARCH64_AUTIASP
    ret
.size   SetDecryptKey192, .-SetDecryptKey192

/*
 * void SetEncryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key);
 * Generating extended keys.
 * x0 => CRYPT_AES_Key *ctx; x1 => const uint8_t *key
 */
.globl  SetEncryptKey256
.type   SetEncryptKey256, %function
.align 5
SetEncryptKey256:
.Lenc_key_256:
AARCH64_PACIASP
    stp x29, x30, [sp, #-64]!
    add x29, sp, #0
    stp x25, x26, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x21, x22, [sp, #48]             // Register is stacked.

    adrp x23, .g_cron
    add x23, x23, :lo12:.g_cron         // Round key start address.
    ld1 {v0.16b}, [x1], #16             // Obtain the first 128-bit key.
    mov x24, x0                         // Copy key string address. The address increases by 16 bytes.
    st1 {v0.4s}, [x0], #16              // Store the first 128-bit key.
    ld1 {v1.16b}, [x1]                  // Obtain the last 128-bit key.
    eor v0.16b, v0.16b, v0.16b          // Clear zeros in V0.
    st1 {v1.4s}, [x0], #16              // Store the last 128-bit key.
    mov w26, #14                        // Number of encryption rounds.
    mov w25, #6                         // Loop for 7-1 times.
.Lenc_key_256_loop:
    dup v1.4s, v1.s[3]                  // Repeated four times,The last word of v1 is changed to v1 (128 bits).
    ldr w22, [x23], #4                  // Obtains the round constant.
    ext v1.16b, v1.16b, v1.16b, #1      // Byte cycle.
    aese v1.16b, v0.16b                 // XOR then shift then sbox (XOR operation with 0 is itself,
                                        // equivalent to omitting the XOR operation).
    dup v2.4s, w22                      // Repeat 4 times. w22 becomes v2.
    eor v1.16b, v1.16b, v2.16b          // Round constant XOR.
    ld1 {v2.4s}, [x24], #16             // Obtains the 4 words used for XOR.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (1).
    ext v2.16b, v0.16b, v2.16b, #12     // 4321->3210.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (2).
    ext v2.16b, v0.16b, v2.16b, #12     // 3210->2100.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (3).
    ext v2.16b, v0.16b, v2.16b, #12     // 2100->1000.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (4).
    st1 {v1.4s}, [x0], #16              // Stores the newly calculated 4-word key data into the key string.
    subs w25, w25, #1                   // Count of 7-1-round key extensions.
    dup v1.4s, v1.s[3]                  // Repeated four times,The last word of v1 is changed to v1 (128 bits).
    ld1 {v2.4s}, [x24], #16             // Obtains the 4 words used for XOR.
    aese v1.16b, v0.16b                 // XOR then shift then sbox.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (1).
    ext v2.16b, v0.16b, v2.16b, #12     // 4321->3210.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (2).
    ext v2.16b, v0.16b, v2.16b, #12     // 3210->2100.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (3).
    ext v2.16b, v0.16b, v2.16b, #12     // 2100->1000.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (4).
    st1 {v1.4s}, [x0], #16              // Stores the newly calculated 4-word key data into the key string.
    b.ne .Lenc_key_256_loop             // Loop jump.

    dup v1.4s, v1.s[3]                  // Repeated four times,The last word of v1 is changed to v1 (128 bits).
    ldr w22, [x23], #4                  // Obtains the round constant.
    ext v1.16b, v1.16b, v1.16b, #1      // Byte cycle.
    aese v1.16b, v0.16b                 // XOR then shift then sbox.
    dup v2.4s, w22                      // Repeat 4 times. w22 becomes v2（128bit）.
    eor v1.16b, v1.16b, v2.16b          // Round constant XOR.
    ld1 {v2.4s}, [x24], #16             // Obtains the 4 words used for XOR.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (1).
    ext v2.16b, v0.16b, v2.16b, #12     // 4321->3210.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (2).
    ext v2.16b, v0.16b, v2.16b, #12     // 3210->2100.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (3).
    ext v2.16b, v0.16b, v2.16b, #12     // 2100->1000.
    eor v1.16b, v1.16b, v2.16b          // 4 XOR operation (4).
    st1 {v1.4s}, [x0], #16              // Stores the newly calculated 4-word key data into the key string.
    str w26, [x0]                       // Fill in the number of rounds.
    eor x24, x24, x24                   // Clear sensitivity.
    eor x0, x0, x0
    ldp x21, x22, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #16]
    ldp x29, x30, [sp], #64             // Stacking completed.
AARCH64_AUTIASP
    ret
.size   SetEncryptKey256, .-SetEncryptKey256

/*
 * void SetDecryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key);
 * Set a decryption key string.
 * x0 => CRYPT_AES_Key *ctx; x1 => const uint8_t *key
 */
.globl  SetDecryptKey256
.type   SetDecryptKey256, %function
.align 5
SetDecryptKey256:
AARCH64_PACIASP
    stp x29, x30, [sp, #-32]!
    add x29, sp, #0
    stp x25, x28, [sp, #16]

    mov x28, x0
    bl .Lenc_key_256
    mov x25, #-16
    ld1 {v0.4s}, [x28], #16
    SETDECKEY_LDR_9_BLOCK x28
    ld1 {v10.4s}, [x28], #16
    ld1 {v11.4s}, [x28], #16
    ld1 {v12.4s}, [x28], #16
    ld1 {v13.4s}, [x28], #16
    ld1 {v14.4s}, [x28]
    SETDECKEY_INVMIX_9_BLOCK
    aesimc v10.16b, v10.16b
    aesimc v11.16b, v11.16b
    aesimc v12.16b, v12.16b
    aesimc v13.16b, v13.16b
    st1 {v0.4s}, [x28], x25
    SETDECKEY_STR_9_BLOCK x28, x25
    st1 {v10.4s}, [x28], x25
    st1 {v11.4s}, [x28], x25
    st1 {v12.4s}, [x28], x25
    st1 {v13.4s}, [x28], x25
    st1 {v14.4s}, [x28]
    eor x28, x28, x28
    eor x0, x0, x0
    ldp x25, x28, [sp, #16]
    ldp x29, x30, [sp], #32             // Stack has been popped.
AARCH64_AUTIASP
    ret
.size   SetDecryptKey256, .-SetDecryptKey256

#endif
