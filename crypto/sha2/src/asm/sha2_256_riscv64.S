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
#ifdef HITLS_CRYPTO_SHA256

 .option    arch, +zbb

.section .rodata
.balign 64
.LK256:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

/*
 *  Macro description: Prepares the message schedule w for i = 0 to 15.
 *  Input register：
 *      INDEX： Int, current round index
 *      w_i: Temporary register for W[INDEX]
 *  Modify the register： w_i
 *  Output register：
 *      w_i： Latest W[i] value, W[i] = M(i)
 *  Function/Macro Call：None
 */  
    .macro MSGSCHEDULE_W_16 INDEX, w_i
    lw \w_i, (4*\INDEX)(a1)  # Load the message block M(i) into w_i
    rev8 \w_i, \w_i  # Reverse the byte order of w_i
    srli \w_i, \w_i, 32  # Shift right by 32 bits to align the bits
    sw \w_i, (4*\INDEX)(sp) # Store the latest W[i] value
    .endm

/*
 *  Macro description: Prepares the message schedule w for i = 16 to 63.
 *  Input register：
 *      INDEX： Int, current round index
 *  Modify the register： t1, t2, t3, t4, t5, t6
 *  Output register：
 *      W[INDEX & 0x0f]： Latest W[i] value, W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
 *  Function/Macro Call：None
 */
    .macro MSGSCHEDULE_W_64 INDEX
    lw t1, (((\INDEX-2)&0x0f)*4)(sp)  # Load W[i-2]
    lw t2, (((\INDEX-15)&0x0f)*4)(sp) # Load W[i-15]
    lw t3, (((\INDEX-7)&0x0f)*4)(sp)  # Load W[i-7]
    lw t4, ((\INDEX&0x0f)*4)(sp)      # Load W[i-16]

    roriw t5, t1, 17
    roriw t6, t1, 19

    srliw t1, t1, 10
    xor t1, t1, t5
    xor t1, t1, t6
    addw t1, t1, t3  # t1 = sigma1(W[i-2]) + W[i-7]

    roriw t5, t2, 7
    roriw t6, t2, 18

    srliw t2, t2, 3
    xor t2, t2, t5
    xor t2, t2, t6
    addw t1, t1, t2  # t1 = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15])
    addw t1, t1, t4  # t1 = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
    sw t1, (4*(\INDEX&0x0f))(sp)
    .endm

/*
 *  Macro description: Caculate SHA-256 T1 value and update t1 register.
 *  Input register：
 *      INDEX： Int, current round index
 *      e, f, g, h: SHA-256 registers for T1 calculation
 *      K: Base address register for the constant table (= t0 = storing .LK256 address)
 *  Modify the register： t1, t2, t3, t4, h
 *  Output register：
 *      h: Updated value after adding W[i], K[i], and sigma1(e)
 *      t1: T1 result (intermediate value for SHA-256 round function)
 *  Function/Macro Call：None
 */
    .macro SHA256_T1 INDEX, e, f, g, h, K
    lw t4, 4*\INDEX(\K)
    addw \h, \h, t1    # h += W[i]
    addw \h, \h, t4    # h += K[i]

    roriw t2, \e, 6  # t2 = e ror 6
    roriw t3, \e, 11 # t3 = e ror 11
    roriw t4, \e, 25 # t4 = e ror 25

    xor t2, t2, t3   # t2 = t2 ^ t3
    xor t1, \f, \g   # t1 = f ^ g
    xor t2, t2, t4   # t2 = t2 ^ t4
    and t1, t1, \e   # t1 = (f ^ g) & e
    addw \h, \h, t2  # h += (e ror 6) ^ (e ror 11) ^ (e ror 25)
    xor t1, t1, \g   # t1 = (f ^ g) & e ^ g
    addw t1, t1, \h  # t1 = (f ^ g) & e ^ g + h
    .endm

/*
 *  Macro description: Calculate SHA-256 T2 value and update t2 register.
 *  Input register：
 *      INDEX: Int, current round index
 *      a, b, c: SHA-256 working registers
 *  Modify the register: t2, t3, t4
 *  Output register：
 *      t2: T2 result (intermediate value for SHA-256 round function)
 *  Function/Macro Call: None
 */
    .macro SHA256_T2 INDEX, a, b, c
    roriw t2, \a, 2  # t2 = a ror 2
    roriw t3, \a, 13 # t3 = a ror 13
    roriw t4, \a, 22 # t4 = a ror 22

    xor t2, t2, t3   # t2 = t2 ^ t3
    xor t2, t2, t4   # t2 = t2 ^ t4
    xor t4, \b, \c   # t4 = b ^ c
    and t3, \b, \c   # t3 = b & c
    and t4, t4, \a   # t4 = (b ^ c) & a
    xor t4, t4, t3   # t4 = (b ^ c) & a ^ (b & c)
    addw t2, t2, t4  # t2 = (b ^ c) & a ^ (b & c) + (a ror 2) ^ (a ror 13) ^ (a ror 22)
    .endm

/*
 *  Macro description: Perform one SHA-256 round calculation.
 *  Input register：
 *      INDEX: Int, current round index
 *      a, b, c, d, e, f, g, h: SHA-256 working registers
 *  Modify the register: t1, t2, t3, t4, d, h
 *  Output register：
 *      d: Updated value after adding T1
 *      h: Updated value after adding T1 and T2
 *  Function/Macro Call: SHA256_T1, SHA256_T2
 */
    .macro ROUND INDEX, a, b, c, d, e, f, g, h
    SHA256_T1 \INDEX, \e, \f, \g, \h, t0
    SHA256_T2 \INDEX, \a, \b, \c
    addw \d, \d, t1  # d += t1
    addw \h, t2, t1  # h = t1 + t2
    .endm

/*
 *  Macro description: Perform one SHA-256 round for i = 0 to 15 (message schedule from input block).
 *  Input register：
 *      INDEX: Int, current round index
 *      a, b, c, d, e, f, g, h: SHA-256 working registers
 *      w_i: Temporary register for W[INDEX]
 *  Modify the register: t1, t2, t3, t4, t5, t6, w_i, d, h
 *  Output register：
 *      d: Updated value after adding T1
 *      h: Updated value after adding T1 and T2
 *  Function/Macro Call: MSGSCHEDULE_W_16, ROUND
 */
    .macro ROUND_16 INDEX, a, b, c, d, e, f, g, h, w_i
    MSGSCHEDULE_W_16 \INDEX, \w_i  
    ROUND \INDEX, \a, \b, \c, \d, \e, \f, \g, \h
    .endm

/*
 *  Macro description: Perform one SHA-256 round for i = 16 to 63 (message schedule from previous W).
 *  Input register：
 *      INDEX: Int, current round index
 *      a, b, c, d, e, f, g, h: SHA-256 working registers
 *  Modify the register: t1, t2, t3, t4, t5, t6, d, h
 *  Output register：
 *      d: Updated value after adding T1
 *      h: Updated value after adding T1 and T2
 *  Function/Macro Call: MSGSCHEDULE_W_64, ROUND
 */
    .macro ROUND_64 INDEX, a, b, c, d, e, f, g, h
    MSGSCHEDULE_W_64 \INDEX
    ROUND \INDEX, \a, \b, \c, \d, \e, \f, \g, \h
    .endm

/*
 *  Function Description：Performs 64 rounds of compression calculation based on the input plaintext data
 *                        and updates the hash value.
 *  Function prototype：void SHA256CompressMultiBlocks(uint32_t hash[8], const uint8_t *in, uint32_t num);
 *  Input register：
 *         a0： Storage address of the hash value
 *         a1： Pointer to the input data address
 *         a2： Number of 64 rounds of cycles
 *  Modify the register： t0-t6, s0-s11, a0-a2, sp, ra
 *  Output register： None
 *  Function/Macro Call： ROUND_16, ROUND_64, MSGSCHEDULE_W_16, MSGSCHEDULE_W_64, SHA256_T1, SHA256_T2
 *
 */
    .text
    .align 2
    .global SHA256CompressMultiBlocks
    .type SHA256CompressMultiBlocks, @function
SHA256CompressMultiBlocks:
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

    addi sp, sp, -64

    la t0, .LK256          # Load the address of the K constants

    lw s2, 0(a0)    #A load hash[0]
    lw s3, 4(a0)    #B load hash[1]
    lw s4, 8(a0)    #C load hash[2]
    lw s5, 12(a0)   #D load hash[3]
    lw s6, 16(a0)   #E load hash[4]
    lw s7, 20(a0)   #F load hash[5]
    lw s8, 24(a0)   #G load hash[6]
    lw s9, 28(a0)   #H load hash[7] 

.Lloop_compress_64:

    addi a2, a2, -1

    ROUND_16 0, s2, s3, s4, s5, s6, s7, s8, s9, t1
    ROUND_16 1, s9, s2, s3, s4, s5, s6, s7, s8, t1
    ROUND_16 2, s8, s9, s2, s3, s4, s5, s6, s7, t1
    ROUND_16 3, s7, s8, s9, s2, s3, s4, s5, s6, t1

    ROUND_16 4, s6, s7, s8, s9, s2, s3, s4, s5, t1
    ROUND_16 5, s5, s6, s7, s8, s9, s2, s3, s4, t1
    ROUND_16 6, s4, s5, s6, s7, s8, s9, s2, s3, t1
    ROUND_16 7, s3, s4, s5, s6, s7, s8, s9, s2, t1

    ROUND_16 8, s2, s3, s4, s5, s6, s7, s8, s9, t1
    ROUND_16 9, s9, s2, s3, s4, s5, s6, s7, s8, t1
    ROUND_16 10, s8, s9, s2, s3, s4, s5, s6, s7, t1
    ROUND_16 11, s7, s8, s9, s2, s3, s4, s5, s6, t1

    ROUND_16 12, s6, s7, s8, s9, s2, s3, s4, s5, t1
    ROUND_16 13, s5, s6, s7, s8, s9, s2, s3, s4, t1
    ROUND_16 14, s4, s5, s6, s7, s8, s9, s2, s3, t1
    ROUND_16 15, s3, s4, s5, s6, s7, s8, s9, s2, t1

    ROUND_64 16, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_64 17, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_64 18, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_64 19, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_64 20, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_64 21, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_64 22, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_64 23, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_64 24, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_64 25, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_64 26, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_64 27, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_64 28, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_64 29, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_64 30, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_64 31, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_64 32, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_64 33, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_64 34, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_64 35, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_64 36, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_64 37, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_64 38, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_64 39, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_64 40, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_64 41, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_64 42, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_64 43, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_64 44, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_64 45, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_64 46, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_64 47, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_64 48, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_64 49, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_64 50, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_64 51, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_64 52, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_64 53, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_64 54, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_64 55, s3, s4, s5, s6, s7, s8, s9, s2

    ROUND_64 56, s2, s3, s4, s5, s6, s7, s8, s9
    ROUND_64 57, s9, s2, s3, s4, s5, s6, s7, s8
    ROUND_64 58, s8, s9, s2, s3, s4, s5, s6, s7
    ROUND_64 59, s7, s8, s9, s2, s3, s4, s5, s6

    ROUND_64 60, s6, s7, s8, s9, s2, s3, s4, s5
    ROUND_64 61, s5, s6, s7, s8, s9, s2, s3, s4
    ROUND_64 62, s4, s5, s6, s7, s8, s9, s2, s3
    ROUND_64 63, s3, s4, s5, s6, s7, s8, s9, s2

    lw t1, 0(a0)    # Load hash[0]
    lw t2, 4(a0)    # Load hash[1]
    lw t3, 8(a0)    # Load hash[2]
    lw t4, 12(a0)   # Load hash[3]

    addw s2, s2, t1  # Update hash[0]
    addw s3, s3, t2  # Update hash[1]
    addw s4, s4, t3  # Update hash[2]
    addw s5, s5, t4  # Update hash[3]

    sw s2, 0(a0)    # Store updated hash[0]
    sw s3, 4(a0)    # Store updated hash[1]
    sw s4, 8(a0)    # Store updated hash[2]
    sw s5, 12(a0)   # Store updated hash[3]

    lw t1, 16(a0)   # Load hash[4]
    lw t2, 20(a0)   # Load hash[5]
    lw t3, 24(a0)   # Load hash[6]
    lw t4, 28(a0)   # Load hash[7]

    addw s6, s6, t1  # Update hash[4]
    addw s7, s7, t2  # Update hash[5]
    addw s8, s8, t3  # Update hash[6]
    addw s9, s9, t4  # Update hash[7]

    sw s6, 16(a0)   # Store updated hash[4]
    sw s7, 20(a0)   # Store updated hash[5]
    sw s8, 24(a0)   # Store updated hash[6]
    sw s9, 28(a0)   # Store updated hash[7]

    addi a1, a1, 64  # Move to the next block of input data

    bnez a2, .Lloop_compress_64


    addi sp, sp, 64

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

    ret

    .size SHA256CompressMultiBlocks, .-SHA256CompressMultiBlocks

#endif // HITLS_CRYPTO_SHA256