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
#ifdef HITLS_CRYPTO_CHACHA20

#include "crypt_arm.h"
#include "chacha20_common_aarch64.S"
#include "chacha20_64block_aarch64.S"
#include "chacha20_256block_aarch64.S"
#include "chacha20_512block_aarch64.S"

.section .rodata
.ADD_LONG:
.long 1,0,0,0
/**
 * @Interconnection with the C interface：void CHACHA20_Update(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
 * @brief Chacha20 algorithm
 * @param ctx [IN] Algorithm context, which is set by the C interface and transferred.
 * @param in [IN] Data to be encrypted
 * @param out [OUT] Data after encryption
 * @param len [IN] Encrypted length
 */

.text
.globl CHACHA20_Update
.type CHACHA20_Update,%function
.align 4
CHACHA20_Update:
AARCH64_PACIASP
    lsr REGLEN, REGLEN, #6                  // Divided by 64 to calculate how many blocks.
    stp x29, x30, [sp, #-96]!               // x29 x30 store sp -96 address sp -=96.
    add x29, sp, #0                         // x29 = sp
    stp x19, x20, [sp, #80]                 // x19 x20 store sp, sp +=16.
    stp x21, x22, [sp, #64]
    cmp REGLEN, #1                          // 1
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #32]
    stp x27, x28, [sp, #16]
    sub sp, sp, #128+64                     // sp -= 192
    b.lo .Lchacha_end                       // Less than 1 block.
    b.eq .Lchacha64                         // Equals 1 block.
    adrp x5, .ADD_LONG
    add x5, x5, :lo12:.ADD_LONG                       // load(1, 0, 0, 0)

    cmp REGLEN, #8                          // >= 512(64*8)
#ifdef HITLS_BIG_ENDIAN
    ldp XSIG01, XSIG02, [x0]
    ld1 {VSIGMA.4s}, [x0], #16              // {sima0, sima1, key0, key1, key3, key4, counter1, counter2}
    ldp XKEY01, XKEY02, [x0]
    ldp XKEY03, XKEY04, [x0, #16]
    ld1 {VKEY01.4s, VKEY02.4s}, [x0], #32
    ldp XCOUN1, XCOUN2, [x0]
    ld1 {VCOUN0.4s}, [x0]

    // Processing when the big-endian machine is loaded.
    ror XCOUN1, XCOUN1, #32
    ror XCOUN2, XCOUN2, #32
    ror XSIG01, XSIG01, #32
    ror XSIG02, XSIG02, #32
    add WINPUT2, WCOUN1, w3
    ror XKEY01, XKEY01, #32
    ror XKEY02, XKEY02, #32
    ror XKEY03, XKEY03, #32
    ror XKEY04, XKEY04, #32
    str WINPUT2, [x0]
#else
    ldp XSIG01, XSIG02, [x0]
    ld1 {VSIGMA.4s}, [x0], #16              // {sima0, sima1, key0, key1, key3, key4, counter1, counter2}
    ldp XKEY01, XKEY02, [x0]
    ldp XKEY03, XKEY04, [x0, #16]
    ld1 {VKEY01.4s, VKEY02.4s}, [x0], #32
    ldp XCOUN1, XCOUN2, [x0]
    ld1 {VCOUN0.4s}, [x0]
    add x6, XCOUN1, REGLEN
    str x6, [x0]                            // Write back the counter.
#endif
    b.lo .Lchacha256                        // < 512

    stp QCUR05, QCUR06, [sp, #0]            // Write sigma key1 to SP.
    ld1 {VADDER.4s}, [x5]                   // Load ADDR.
    add VCUR01.4s, VCOUN0.4s, VADDER.4s     // 0
    add VCUR01.4s, VCUR01.4s, VADDER.4s     // +2
    add VCUR02.4s, VCUR01.4s, VADDER.4s     // +3
    add VCUR03.4s, VCUR02.4s, VADDER.4s     // +4
    add VCUR04.4s, VCUR03.4s, VADDER.4s     // +5
    shl VADDER.4s, VADDER.4s, #2            // 4

    stp d8, d9,[sp,#128+0]                  // Meet ABI requirements.
    stp d10, d11,[sp,#128+16]
    stp d12, d13,[sp,#128+32]
    stp d14, d15,[sp,#128+48]

// 8 block
.Loop_512_start:
    cmp REGLEN, #8
    b.lo .L512ToChacha256                   // Less than 512.
    CHA64_SET_WDATA                         // General-purpose register 1 x 64 bytes.
    CHA512_SET_VDATA                        // Wide register 6 x 64 bytes.

    stp QCUR01, QCUR02, [sp, #32]           // Write counter 0, 1, 2 3 to sp.
    stp QCUR03, QCUR04, [sp, #64]
    mov x4, #5
    sub REGLEN, REGLEN, #8                  // Process 512 at a time.
.Loop_512_a_run:
    sub x4, x4, #1
    CHA512_ROUND
    CHA512_EXTA
    CHA512_ROUND
    CHA512_EXTB
    cbnz x4, .Loop_512_a_run

    CHA64_ROUND_END                         // Add to input after the loop is complete.
    CHA64_WRITE_BACK                        // 512 Write 64 bytes in the first half round.
    add XCOUN1, XCOUN1, #1                  // +1
    CHA64_SET_WDATA                         // Resetting.

    mov x4, #5
.Loop_512_b_run:
    sub x4, x4, #1
    CHA512_ROUND
    CHA512_EXTA
    CHA512_ROUND
    CHA512_EXTB
    cbnz x4, .Loop_512_b_run

    CHA64_ROUND_END                         // Add to input after the loop is complete.
    CHA64_WRITE_BACK                        // 512 Write 64 bytes in the first half round.
    add XCOUN1, XCOUN1, #7                  // +7

    ldp QCUR05, QCUR06, [sp, #0]            // Restore sigma and key1.
    ldp QCUR01, QCUR02, [sp, #32]           // Restore counter 0 1 2 4.
    ldp QCUR03, QCUR04, [sp, #64]

    CHA512_ROUND_END                        // Add to input after the loop is complete.
    CHA512_WRITE_BACK                       // Write back data.
    b .Loop_512_start                       // return start.

// 1 block
.Lchacha64:
#ifdef HITLS_BIG_ENDIAN
    ldp XCOUN1, XCOUN2, [x0, #48]
    ldp XSIG01, XSIG02, [x0]
    ldp XKEY01, XKEY02, [x0, #16]
    // Processing when the big-endian machine is loaded
    ror XCOUN1, XCOUN1, #32
    ror XCOUN2, XCOUN2, #32
    ror XSIG01, XSIG01, #32
    ror XSIG02, XSIG02, #32
    ldp XKEY03, XKEY04, [x0, #32]
    add WINPUT0, WCOUN1, w3
    ror XKEY01, XKEY01, #32
    ror XKEY02, XKEY02, #32
    ror XKEY03, XKEY03, #32
    ror XKEY04, XKEY04, #32
    str WINPUT0, [x0, #48]
#else
    ldp XCOUN1, XCOUN2, [x0, #48]
    ldp XSIG01, XSIG02, [x0]
    ldp XKEY01, XKEY02, [x0, #16]
    add XINPUT0, XCOUN1, REGLEN
    ldp XKEY03, XKEY04, [x0, #32]
    str XINPUT0, [x0, #48]                   // Write data.
#endif

.Loop_64_start:
    CHA64_SET_WDATA                          // General-purpose register, 1x64byte.
    mov x4, #10
.Loop_64_run:
    sub x4, x4, #1
    WCHA_ADD_A_B                                            // a += b
    WCHA_EOR_D_A                                            // d ^= a
    WCHA_ROR_D #16                                          // d <<<= 16 ror Cyclic shift right by 16 bits.
    WCHA_ADD_C_D                                            // c += d
    WCHA_EOR_B_C
    WCHA_ROR_B #20
    WCHA_ADD_A_B                                                                    // a += b
    WCHA_EOR_D_A
    WCHA_ROR_D #24
    WCHA_ADD_C_D                                            // c += d
    WCHA_EOR_B_C
    WCHA_ROR_B #25

    WCHA_ADD2_A_B
    WCHA_EOR2_D_A
    WCHA_ROR_D #16
    WCHA_ADD2_C_D
    WCHA_EOR2_B_C
    WCHA_ROR_B #20
    WCHA_ADD2_A_B
    WCHA_EOR2_D_A
    WCHA_ROR_D #24
    WCHA_ADD2_C_D
    WCHA_EOR2_B_C
    WCHA_ROR_B #25
    cbnz x4, .Loop_64_run
    CHA64_ROUND_END                         // Add to input after the loop is complete.
    subs REGLEN, REGLEN, #1
    CHA64_WRITE_BACK                        // Write 64 bytes.
    add XCOUN1, XCOUN1, #1
    b.le .Lchacha_end
    b .Loop_64_start

.L512ToChacha256:
    ldp d8,d9,[sp,#128+0]                   // Meet ABI requirements.
    ldp d10,d11,[sp,#128+16]
    ldp d12,d13,[sp,#128+32]
    ldp d14,d15,[sp,#128+48]
    cbz REGLEN, .Lchacha_end                 // The length is 0.
    ushr VADDER.4s, VADDER.4s, #2           // 4->1
    sub VREG52.4s, VCUR01.4s, VADDER.4s     // 10-1 = 9  8
    sub VREG53.4s, VCUR02.4s, VADDER.4s     // 11-1 = 10
    sub VREG54.4s, VCUR03.4s, VADDER.4s     // 12-1 = 11
    shl VCUR01.4s, VADDER.4s, #2            // 2 -> 4
    b .Loop_256_start

// 4 block
.Lchacha256:
    ld1 {VADDER.4s}, [x5]                   // Load ADDR.
    mov VREG51.16b, VCOUN0.16b              // 0
    add VREG52.4s, VCOUN0.4s, VADDER.4s     // 1
    add VREG53.4s, VREG52.4s, VADDER.4s     // 2
    add VREG54.4s, VREG53.4s, VADDER.4s     // 3
    shl VCUR01.4s, VADDER.4s, #2            // 4

.Loop_256_start:
    CHA64_SET_WDATA                         // General-purpose register 16 byte.
    CHA256_SET_VDATA                        // Neon register 3 * 48 byte.
    mov x4, #10
.Loop_256_run:
    sub x4, x4, #1
    CHA256_ROUND_A
    VEXT2 VREG04.16b, VREG14.16b, #12
    VEXT2 VREG24.16b, VREG34.16b, #12
    VEXT2 VREG02.16b, VREG12.16b, #4
    VEXT2 VREG22.16b, VREG32.16b, #4
    CHA256_ROUND_B
    VEXT2 VREG04.16b, VREG14.16b, #4
    VEXT2 VREG24.16b, VREG34.16b, #4
    VEXT2 VREG02.16b, VREG12.16b, #12
    VEXT2 VREG22.16b, VREG32.16b, #12
    cbnz x4, .Loop_256_run
    subs REGLEN, REGLEN, #4                 // One-time processing 256.
    CHA256_ROUND_END
    b.lo .Lchacha_less_than_256             // < 0
    CHA64_ROUND_END
    CHA256_WRITE_BACK                       // Write back data.
    b.le .Lchacha_end                       // = 0
    add	XCOUN1, XCOUN1, #4			        // Counter+4.
    add VREG52.4s, VREG52.4s, VCUR01.4s     // Counter+4.
    add VREG53.4s, VREG53.4s, VCUR01.4s
    add VREG54.4s, VREG54.4s, VCUR01.4s
    b .Loop_256_start

.Lchacha_less_than_256:
    add REGLEN, REGLEN, #4
    cmp REGLEN, #1
    b.lo .Lchacha_end                        // <= 64 byte.
    CHA64_ROUND_END
    CHA64_WRITE_BACK

    sub REGLEN, REGLEN, #1
    cmp REGLEN, #1
    b.lo .Lchacha_end
    CHA256_WRITE_BACKB VREG01.16b, VREG02.16b, VREG03.16b, VREG04.16b

    sub REGLEN, REGLEN, #1
    cmp REGLEN, #1
    b.lo .Lchacha_end
    CHA256_WRITE_BACKB VREG11.16b, VREG12.16b, VREG13.16b, VREG14.16b

.Lchacha_end:
    eor XKEY01, XKEY01, XKEY01
    eor XKEY02, XKEY02, XKEY02
    eor XKEY03, XKEY03, XKEY03
    eor XKEY04, XKEY04, XKEY04
    eor XKEY04, XKEY04, XKEY04
    eor XCOUN2, XCOUN2, XCOUN2
    eor VKEY01.16b, VKEY01.16b, VKEY01.16b
    eor VKEY02.16b, VKEY02.16b, VKEY02.16b
    eor VCUR01.16b, VCUR01.16b, VCUR01.16b
    ldp x19, x20, [x29, #80]
    add sp, sp, #128+64
    ldp x21, x22, [x29, #64]
    ldp x23, x24, [x29, #48]
    ldp x25, x26, [x29, #32]
    ldp x27, x28, [x29, #16]
    ldp x29, x30, [sp], #96

.Labort:
AARCH64_AUTIASP
    ret
.size CHACHA20_Update,.-CHACHA20_Update

#endif
