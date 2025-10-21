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
#ifdef HITLS_CRYPTO_SHA512

 .option    arch, +zbb

.section .rodata
.align 3
.LK512:
    .dword 0x428a2f98d728ae22, 0x7137449123ef65cd
    .dword 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
    .dword 0x3956c25bf348b538, 0x59f111f1b605d019
    .dword 0x923f82a4af194f9b, 0xab1c5ed5da6d8118
    .dword 0xd807aa98a3030242, 0x12835b0145706fbe
    .dword 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
    .dword 0x72be5d74f27b896f, 0x80deb1fe3b1696b1
    .dword 0x9bdc06a725c71235, 0xc19bf174cf692694
    .dword 0xe49b69c19ef14ad2, 0xefbe4786384f25e3
    .dword 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
    .dword 0x2de92c6f592b0275, 0x4a7484aa6ea6e483
    .dword 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
    .dword 0x983e5152ee66dfab, 0xa831c66d2db43210
    .dword 0xb00327c898fb213f, 0xbf597fc7beef0ee4
    .dword 0xc6e00bf33da88fc2, 0xd5a79147930aa725
    .dword 0x06ca6351e003826f, 0x142929670a0e6e70
    .dword 0x27b70a8546d22ffc, 0x2e1b21385c26c926
    .dword 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
    .dword 0x650a73548baf63de, 0x766a0abb3c77b2a8
    .dword 0x81c2c92e47edaee6, 0x92722c851482353b
    .dword 0xa2bfe8a14cf10364, 0xa81a664bbc423001
    .dword 0xc24b8b70d0f89791, 0xc76c51a30654be30
    .dword 0xd192e819d6ef5218, 0xd69906245565a910
    .dword 0xf40e35855771202a, 0x106aa07032bbd1b8
    .dword 0x19a4c116b8d2d0c8, 0x1e376c085141ab53
    .dword 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
    .dword 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
    .dword 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
    .dword 0x748f82ee5defb2fc, 0x78a5636f43172f60
    .dword 0x84c87814a1f0ab72, 0x8cc702081a6439ec
    .dword 0x90befffa23631e28, 0xa4506cebde82bde9
    .dword 0xbef9a3f7b2c67915, 0xc67178f2e372532b
    .dword 0xca273eceea26619c, 0xd186b8c721c0c207
    .dword 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
    .dword 0x06f067aa72176fba, 0x0a637dc5a2c898a6
    .dword 0x113f9804bef90dae, 0x1b710b35131c471b
    .dword 0x28db77f523047d84, 0x32caab7b40c72493
    .dword 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
    .dword 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
    .dword 0x5fcb6fab3ad6faec, 0x6c44198c4a475817

/*
 *  Macro description: prepares the message schedule w for i = 0 to 15.
 *  Input register：
 *      INDEX： Int
        t1: W[INDEX] 
 *  Modify the register： t1
 *  Output register：
 *      t1： Latest W[i] value, W[i] = M(i)
 *  Function/Macro Call：None
 *
 */  
    .macro MSGSCHEDULE_W_16 INDEX
    ld t1, (8*\INDEX)(a1)  # Load the message block M(i) into t1
    rev8 t1, t1  # Reverse the byte order of t1
    sd t1, (8*\INDEX)(sp) # Store the latest W[i] value
    .endm


/*
 *  Macro description: Prepares the message schedule w for i = 16 to 79.
 *  Input register：
 *      INDEX: Int, current round index
 *  Modify the register: t1, t2, t3, t4, t5, t6
 *  Output register：
 *      W[INDEX & 0x0f]: Latest W[i] value, W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
 *  Function/Macro Call: None
 *
 */
    .macro MSGSCHEDULE_W_80 INDEX
    ld t1, (((\INDEX-2)&0x0f)*8)(sp)  # Load W[i-2]
    ld t2, (((\INDEX-15)&0x0f)*8)(sp) # Load W[i-15]
    ld t3, (((\INDEX-7)&0x0f)*8)(sp)  # Load W[i-7]
    ld t4, ((\INDEX&0x0f)*8)(sp)      # Load W[i-16]

    rori t5, t1, 19
    rori t6, t1, 61

    srli t1, t1, 6
    xor t1, t1, t5
    xor t1, t1, t6
    add t1, t1, t3  # t1 = sigma1(W[i-2]) + W[i-7]

    rori t5, t2, 1
    rori t6, t2, 8

    srli t2, t2, 7
    xor t2, t2, t5
    xor t2, t2, t6
    add t1, t1, t2  # t1 = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15])
    add t1, t1, t4  # t1 = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
    sd t1, (8*(\INDEX&0x0f))(sp)
    .endm

/*
 *  Macro description: Calculate SHA-512 T1 value and update t1 register.
 *  Input register：
 *      INDEX: Int, current round index
 *      e, f, g, h: SHA-512 registers for T1 calculation
 *      K: Base address register for the constant table (e.g., t0, storing .LK512 address)
 *  Modify the register: t1, t2, t3, t4, h
 *  Output register：
 *      h: Updated value after adding W[i], K[i], and sigma1(e)
 *      t1: T1 result (intermediate value for SHA-512 round function)
 *  Function/Macro Call: None
 *
 */
    .macro SHA512_T1 INDEX, e, f, g, h, K
    ld t4, 8*\INDEX(\K)
    add \h, \h, t1    # h += W[i]
    add \h, \h, t4    # h += K[i]

    rori t2, \e, 14  # t2 = e ror 14
    rori t3, \e, 18  # t3 = e ror 18
    rori t4, \e, 41  # t4 = e ror 41

    xor t2, t2, t3   # t2 = (e ror 14) ^ (e ror 18)
    xor t1, \f, \g   # t1 = f ^ g
    xor t2, t2, t4   # t2 = (e ror 14) ^ (e ror 18) ^ (e ror 41)
    and t1, t1, \e   # t1 = (f ^ g) & e
    add \h, \h, t2   # h += (e ror 14) ^ (e ror 18) ^ (e ror 41)
    xor t1, t1, \g   # t1 = (f ^ g) & e ^ g
    add t1, t1, \h   # t1 = (f ^ g) & e ^ g + h
    .endm

/*
 *  Macro description: Calculate SHA-512 T2 value and update t2 register.
 *  Input register：
 *      a, b, c: SHA-512 working registers
 *  Modify the register: t2, t3, t4, t5
 *  Output register：
 *      t2: T2 result (intermediate value for SHA-512 round function)
 *  Function/Macro Call: None
 *
 */
    .macro SHA512_T2 a, b, c
    rori t2, \a, 28  # t2 = a ror 28
    rori t3, \a, 34  # t3 = a ror 34
    rori t4, \a, 39  # t4 = a ror 39

    xor t2, t2, t3   # t2 = (a ror 28) ^ (a ror 34)
    xor t5, \b, \c   # t5 = b ^ c
    and t3, \b, \c   # t3 = b & c
    and t5, t5, \a   # t5 = (b ^ c) & a
    xor t2, t2, t4   # t2 = (a ror 28) ^ (a ror 34) ^ (a ror 39)
    xor t3, t3, t5   # t3 = (b & c) ^ ((b ^ c) & a)
    add t2, t2, t3   # t2 = (a ror 28) ^ (a ror 34) ^ (a ror 39) + ((b & c) ^ ((b ^ c) & a))
    .endm

/*
 *  Macro description: Perform one SHA-512 round calculation.
 *  Input register：
 *      INDEX: Int, current round index
 *      a, b, c, d, e, f, g, h: SHA-512 working registers
 *  Modify the register: t1, t2, t3, t4, d, h
 *  Output register：
 *      d: Updated value after adding T1
 *      h: Updated value after adding T1 and T2
 *  Function/Macro Call: SHA512_T1, SHA512_T2
 *
 */
    .macro ROUND INDEX, a, b, c, d, e, f, g, h
    SHA512_T1 \INDEX, \e, \f, \g, \h, t0
    SHA512_T2 \a, \b, \c
    add \d, \d, t1  # d += t1
    add \h, t2, t1  # h = t1 + t2
    .endm

/*
 *  Macro description: Perform one SHA-512 round for i = 0 to 15 (message schedule from input block).
 *  Input register：
 *      INDEX: Int, current round index
 *      a, b, c, d, e, f, g, h: SHA-512 working registers
 *      w_i: Temporary register for W[INDEX]
 *  Modify the register: t1, t2, t3, t4, w_i, d, h
 *  Output register：
 *      d: Updated value after adding T1
 *      h: Updated value after adding T1 and T2
 *  Function/Macro Call: MSGSCHEDULE_W_16, ROUND
 *
 */
    .macro ROUND_16 INDEX, a, b, c, d, e, f, g, h
    MSGSCHEDULE_W_16 \INDEX
    ROUND \INDEX, \a, \b, \c, \d, \e, \f, \g, \h
    .endm

/*
 *  Macro description: Perform one SHA-512 round for i = 16 to 79 (message schedule from previous W).
 *  Input register：
 *      INDEX: Int, current round index
 *      a, b, c, d, e, f, g, h: SHA-512 working registers
 *  Modify the register: t1, t2, t3, t4, t5, t6, d, h
 *  Output register：
 *      d: Updated value after adding T1
 *      h: Updated value after adding T1 and T2
 *  Function/Macro Call: MSGSCHEDULE_W_80, ROUND
 *
 */
    .macro ROUND_80 INDEX, a, b, c, d, e, f, g, h
    MSGSCHEDULE_W_80 \INDEX
    ROUND \INDEX, \a, \b, \c, \d, \e, \f, \g, \h
    .endm

/*
 *  Function Description: Performs 80 rounds of compression calculation based on the input plaintext data
 *                        and updates the hash value.
 *  Function prototype:   void SHA512CompressMultiBlocks(uint64_t hash[8], const uint8_t *in, uint64_t num);
 *  Input register：
 *      a0: Storage address of the hash value (hash[8])
 *      a1: Pointer to the input data address
 *      a2: Number of 80-round cycles (number of message blocks)
 *  Modify the register: 
 *      t0-t6, s0-s11, a0-a2, sp, ra
 *  Output register: None
 *  Function/Macro Call: ROUND_16, ROUND_80, MSGSCHEDULE_W_16, MSGSCHEDULE_W_80, SHA512_T1, SHA512_T2
 *
 */
    .text
    .align 3
    .global SHA512CompressMultiBlocks
    .type SHA512CompressMultiBlocks, @function
SHA512CompressMultiBlocks:

    beqz a2, .Lend_sha512

    addi sp, sp, -96
    sd s0, 0(sp)
    sd s1, 8(sp)
    sd s2, 16(sp)
    sd s3, 24(sp)
    sd s4, 32(sp)
    sd s5, 40(sp)
    sd s6, 48(sp)
    sd s7, 56(sp)
    sd s8, 64(sp)
    sd s9, 72(sp)
    sd s10, 80(sp)
    sd s11, 88(sp)

    addi sp, sp, -128

    la t0, .LK512          # Load the address of the K constants

    ld s2, 0(a0)    #A load hash[0]
    ld s3, 8(a0)    #B load hash[1]
    ld s4, 16(a0)   #C load hash[2]
    ld s5, 24(a0)   #D load hash[3]
    ld s6, 32(a0)   #E load hash[4]
    ld s7, 40(a0)   #F load hash[5]
    ld s8, 48(a0)   #G load hash[6]
    ld s9, 56(a0)   #H load hash[7] 

.Lloop_compress_80:

    addi a2, a2, -1

    ROUND_16 0, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_16 1, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_16 2, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_16 3, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_16 4, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_16 5, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_16 6, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_16 7, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_16 8, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_16 9, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_16 10, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_16 11, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_16 12, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_16 13, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_16 14, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_16 15, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_80 16, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_80 17, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_80 18, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_80 19, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_80 20, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_80 21, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_80 22, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_80 23, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_80 24, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_80 25, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_80 26, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_80 27, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_80 28, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_80 29, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_80 30, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_80 31, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_80 32, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_80 33, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_80 34, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_80 35, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_80 36, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_80 37, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_80 38, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_80 39, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_80 40, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_80 41, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_80 42, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_80 43, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_80 44, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_80 45, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_80 46, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_80 47, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_80 48, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_80 49, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_80 50, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_80 51, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_80 52, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_80 53, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_80 54, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_80 55, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_80 56, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_80 57, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_80 58, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_80 59, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_80 60, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_80 61, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_80 62, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_80 63, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_80 64, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_80 65, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_80 66, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_80 67, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_80 68, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_80 69, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_80 70, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_80 71, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_80 72, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_80 73, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_80 74, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_80 75, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_80 76, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_80 77, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_80 78, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_80 79, s3, s4, s5, s6, s7, s8, s9, s2

    ld t1, 0(a0)    # Load hash[0]
    ld t2, 8(a0)    # Load hash[1]
    ld t3, 16(a0)   # Load hash[2]
    ld t4, 24(a0)   # Load hash[3]

    add s2, s2, t1  # Update hash[0]
    add s3, s3, t2  # Update hash[1]
    add s4, s4, t3  # Update hash[2]
    add s5, s5, t4  # Update hash[3]

    sd s2, 0(a0)    # Store updated hash[0]
    sd s3, 8(a0)    # Store updated hash[1]
    sd s4, 16(a0)    # Store updated hash[2]
    sd s5, 24(a0)   # Store updated hash[3]

    ld t1, 32(a0)   # Load hash[4]
    ld t2, 40(a0)   # Load hash[5]
    ld t3, 48(a0)   # Load hash[6]
    ld t4, 56(a0)   # Load hash[7]

    add s6, s6, t1  # Update hash[4]
    add s7, s7, t2  # Update hash[5]
    add s8, s8, t3  # Update hash[6]
    add s9, s9, t4  # Update hash[7]

    sd s6, 32(a0)   # Store updated hash[4]
    sd s7, 40(a0)   # Store updated hash[5]
    sd s8, 48(a0)   # Store updated hash[6]
    sd s9, 56(a0)   # Store updated hash[7]

    addi a1, a1, 128  # Move to the next block of input data

    bnez a2, .Lloop_compress_80


    addi sp, sp, 128

    ld s0, 0(sp)
    ld s1, 8(sp)
    ld s2, 16(sp)
    ld s3, 24(sp)
    ld s4, 32(sp)
    ld s5, 40(sp)
    ld s6, 48(sp)
    ld s7, 56(sp)
    ld s8, 64(sp)
    ld s9, 72(sp)
    ld s10, 80(sp)
    ld s11, 88(sp)

    addi sp, sp, 96

.Lend_sha512:
    ret

    .size SHA512CompressMultiBlocks, .-SHA512CompressMultiBlocks

#endif // HITLS_CRYPTO_SHA512