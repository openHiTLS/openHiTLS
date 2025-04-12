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

.text

.macro CHA512_EXTA
    VEXT2 VREG04.16b, VREG14.16b, #12
    VEXT2 VREG24.16b, VREG34.16b, #12
    VEXT2 VREG44.16b, VREG54.16b, #12
    VEXT2 VREG02.16b, VREG12.16b, #4
    VEXT2 VREG22.16b, VREG32.16b, #4
    VEXT2 VREG42.16b, VREG52.16b, #4
.endm

.macro CHA512_EXTB
    VEXT2 VREG04.16b, VREG14.16b, #4
    VEXT2 VREG24.16b, VREG34.16b, #4
    VEXT2 VREG44.16b, VREG54.16b, #4
    VEXT2 VREG02.16b, VREG12.16b, #12
    VEXT2 VREG22.16b, VREG32.16b, #12
    VEXT2 VREG42.16b, VREG52.16b, #12
.endm

.macro CHA512_SET_VDATA
    mov VREG01.16b, VSIGMA.16b
    mov VREG11.16b, VSIGMA.16b
    mov VREG21.16b, VSIGMA.16b
    mov VREG31.16b, VSIGMA.16b
    mov VREG41.16b, VSIGMA.16b
    mov VREG51.16b, VSIGMA.16b
    mov VREG02.16b, VKEY01.16b
    mov VREG12.16b, VKEY01.16b
    mov VREG22.16b, VKEY01.16b
    mov VREG32.16b, VKEY01.16b
    mov VREG42.16b, VKEY01.16b
    mov VREG52.16b, VKEY01.16b
    mov VREG03.16b, VKEY02.16b
    mov VREG13.16b, VKEY02.16b
    mov VREG23.16b, VKEY02.16b
    mov VREG33.16b, VKEY02.16b
    mov VREG43.16b, VKEY02.16b
    mov VREG53.16b, VKEY02.16b
    mov VREG04.16b, VCUR01.16b              // Counter + 2
    mov VREG14.16b, VCUR02.16b              // Counter + 3
    mov VREG24.16b, VCUR03.16b              // Counter + 4
    mov VREG34.16b, VCUR04.16b              // Counter + 5
    add VREG44.4s, VREG04.4s, VADDER.4s     // Counter + 6 = 4 + 2
    add VREG54.4s, VREG14.4s, VADDER.4s     // Counter + 7 = 4 + 3
.endm

.macro CHA512_ROUND_END
    add VREG01.4s, VREG01.4s, VSIGMA.4s     // After the loop is complete, add input.
    add VREG11.4s, VREG11.4s, VSIGMA.4s
    add VREG21.4s, VREG21.4s, VSIGMA.4s
    add VREG31.4s, VREG31.4s, VSIGMA.4s
    add VREG41.4s, VREG41.4s, VSIGMA.4s
    add VREG51.4s, VREG51.4s, VSIGMA.4s
    add VREG02.4s, VREG02.4s, VKEY01.4s     // After the loop is complete, add input.
    add VREG12.4s, VREG12.4s, VKEY01.4s
    add VREG22.4s, VREG22.4s, VKEY01.4s
    add VREG32.4s, VREG32.4s, VKEY01.4s
    add VREG42.4s, VREG42.4s, VKEY01.4s
    add VREG52.4s, VREG52.4s, VKEY01.4s
    add VREG03.4s, VREG03.4s, VKEY02.4s     // After the loop is complete, add input.
    add VREG13.4s, VREG13.4s, VKEY02.4s
    add VREG23.4s, VREG23.4s, VKEY02.4s
    add VREG33.4s, VREG33.4s, VKEY02.4s
    add VREG43.4s, VREG43.4s, VKEY02.4s
    add VREG53.4s, VREG53.4s, VKEY02.4s
    add VREG44.4s, VREG44.4s, VCUR01.4s     // 2
    add VREG54.4s, VREG54.4s, VCUR02.4s     // 3
    add VREG04.4s, VREG04.4s, VCUR01.4s     // 2
    add VREG14.4s, VREG14.4s, VCUR02.4s     // 3
    add VREG24.4s, VREG24.4s, VCUR03.4s     // 4
    add VREG34.4s, VREG34.4s, VCUR04.4s     // 5
    add VREG44.4s, VREG44.4s, VADDER.4s     // 4 + 2
    add VREG54.4s, VREG54.4s, VADDER.4s     // 4 + 3
.endm

.macro CHA512_WRITE_BACK
    ld1 {VCUR01.16b, VCUR02.16b, VCUR03.16b, VCUR04.16b}, [REGINC], #64  // Load 64 bytes.
    eor VREG01.16b, VREG01.16b, VCUR01.16b
    eor VREG02.16b, VREG02.16b, VCUR02.16b
    eor VREG03.16b, VREG03.16b, VCUR03.16b
    eor VREG04.16b, VREG04.16b, VCUR04.16b
    ld1 {VCUR01.16b, VCUR02.16b, VCUR03.16b, VCUR04.16b}, [REGINC], #64  // Load 64 bytes.
    st1 {VREG01.16b, VREG02.16b, VREG03.16b, VREG04.16b}, [REGOUT], #64  // Write 64 bytes.
    eor VREG11.16b, VREG11.16b, VCUR01.16b
    eor VREG12.16b, VREG12.16b, VCUR02.16b
    eor VREG13.16b, VREG13.16b, VCUR03.16b
    eor VREG14.16b, VREG14.16b, VCUR04.16b
    ld1 {VREG01.16b, VREG02.16b, VREG03.16b, VREG04.16b}, [REGINC], #64  // Load 64 bytes.
    st1 {VREG11.16b, VREG12.16b, VREG13.16b, VREG14.16b}, [REGOUT], #64  // Write 64 bytes.
    eor VREG21.16b, VREG21.16b, VREG01.16b
    eor VREG22.16b, VREG22.16b, VREG02.16b
    eor VREG23.16b, VREG23.16b, VREG03.16b
    eor VREG24.16b, VREG24.16b, VREG04.16b
    ld1 {VREG11.16b, VREG12.16b, VREG13.16b, VREG14.16b}, [REGINC], #64  // Load 64 bytes.
    st1 {VREG21.16b, VREG22.16b, VREG23.16b, VREG24.16b}, [REGOUT], #64  // Write 64 bytes.
    eor VREG31.16b, VREG31.16b, VREG11.16b
    eor VREG32.16b, VREG32.16b, VREG12.16b
    eor VREG33.16b, VREG33.16b, VREG13.16b
    eor VREG34.16b, VREG34.16b, VREG14.16b
    ld1 {VREG01.16b, VREG02.16b, VREG03.16b, VREG04.16b}, [REGINC], #64  // Load 64 bytes.
    st1 {VREG31.16b, VREG32.16b, VREG33.16b, VREG34.16b}, [REGOUT], #64  // Write 64 bytes.
    shl VREG21.4s, VADDER.4s, #1                                        // 4 -> 8
    eor VREG41.16b, VREG41.16b, VREG01.16b
    eor VREG42.16b, VREG42.16b, VREG02.16b
    eor VREG43.16b, VREG43.16b, VREG03.16b
    eor VREG44.16b, VREG44.16b, VREG04.16b
    ld1 {VREG11.16b, VREG12.16b, VREG13.16b, VREG14.16b}, [REGINC], #64  // Load 64 bytes.
    st1 {VREG41.16b, VREG42.16b, VREG43.16b, VREG44.16b}, [REGOUT], #64  // Write 64 bytes.
    ldp QCUR01, QCUR02, [sp, #32]           // restore counter 0 1 2 4
    ldp QCUR03, QCUR04, [sp, #64]
    eor VREG51.16b, VREG51.16b, VREG11.16b
    eor VREG52.16b, VREG52.16b, VREG12.16b
    eor VREG53.16b, VREG53.16b, VREG13.16b
    eor VREG54.16b, VREG54.16b, VREG14.16b
    st1 {VREG51.16b, VREG52.16b, VREG53.16b, VREG54.16b}, [REGOUT], #64  // Write 64 bytes.
    add VCUR01.4s, VCUR01.4s, VREG21.4s
    add VCUR02.4s, VCUR02.4s, VREG21.4s
    add VCUR03.4s, VCUR03.4s, VREG21.4s
    add VCUR04.4s, VCUR04.4s, VREG21.4s
.endm

.macro CHA512_ROUND
    WCHA_ADD_A_B                                            // a += b
    VADD2 VREG02.4s, VREG01.4s, VREG12.4s, VREG11.4s        // a[0,1,2,3] += b[4,5,6,7]
    VADD2 VREG22.4s, VREG21.4s, VREG32.4s, VREG31.4s
    WCHA_EOR_D_A                                            // d ^= a
    VADD2 VREG42.4s, VREG41.4s, VREG52.4s, VREG51.4s
    VEOR2 VREG01.16b, VREG04.16b, VREG11.16b, VREG14.16b    // d[12,13,14,15] ^= a[0,1,2,3]
    WCHA_ROR_D #16                                          // d <<<= 16 ror Cyclic shift right by 16 bits.
    VEOR2 VREG21.16b, VREG24.16b, VREG31.16b, VREG34.16b
    VEOR2 VREG41.16b, VREG44.16b, VREG51.16b, VREG54.16b
    WCHA_ADD_C_D                                            // c += d
    VREV322 VREG04.8h, VREG14.8h                            // d[12,13,14,15] (#16 inverse).
    VREV322 VREG24.8h, VREG34.8h
    WCHA_EOR_B_C
    VREV322 VREG44.8h, VREG54.8h
    VADD2 VREG04.4s, VREG03.4s, VREG14.4s, VREG13.4s        // c[8,9,10,11] += d[12,13,14,15]
    WCHA_ROR_B #20
    VADD2 VREG24.4s, VREG23.4s, VREG34.4s, VREG33.4s
    VADD2 VREG44.4s, VREG43.4s, VREG54.4s, VREG53.4s
    WCHA_ADD_A_B                                                                    // a += b
    VEORX VREG03.16b, VREG02.16b, VCUR01.16b, VREG13.16b, VREG12.16b, VCUR02.16b    // m = b[4,5,6,7] ^ c[8,9,10,11]
    VEORX VREG23.16b, VREG22.16b, VCUR03.16b, VREG33.16b, VREG32.16b, VCUR04.16b
    WCHA_EOR_D_A
    VEORX VREG43.16b, VREG42.16b, VCUR05.16b, VREG53.16b, VREG52.16b, VCUR06.16b
    VUSHR2 VCUR01.4s, VREG02.4s, VCUR02.4s, VREG12.4s, #20  // b[4,5,6,7] = m << 20
    WCHA_ROR_D #24
    VUSHR2 VCUR03.4s, VREG22.4s, VCUR04.4s, VREG32.4s, #20
    VUSHR2 VCUR05.4s, VREG42.4s, VCUR06.4s, VREG52.4s, #20
    WCHA_ADD_C_D                                            // c += d
    VSLI2 VCUR01.4s, VREG02.4s, VCUR02.4s, VREG12.4s, #12   // b[4,5,6,7] = m >> 12
    VSLI2 VCUR03.4s, VREG22.4s, VCUR04.4s, VREG32.4s, #12
    WCHA_EOR_B_C
    VSLI2 VCUR05.4s, VREG42.4s, VCUR06.4s, VREG52.4s, #12
    VADD2 VREG02.4s, VREG01.4s, VREG12.4s, VREG11.4s        // a[0,1,2,3] += b[4,5,6,7]
    WCHA_ROR_B #25
    VADD2 VREG22.4s, VREG21.4s, VREG32.4s, VREG31.4s
    VADD2 VREG42.4s, VREG41.4s, VREG52.4s, VREG51.4s
    WCHA_ADD2_A_B
    VEORX VREG04.16b, VREG01.16b, VCUR01.16b, VREG14.16b, VREG11.16b, VCUR02.16b // m = d[12,13,14,15] ^ a[0,1,2,3]
    VEORX VREG24.16b, VREG21.16b, VCUR03.16b, VREG34.16b, VREG31.16b, VCUR04.16b
    WCHA_EOR2_D_A
    VEORX VREG44.16b, VREG41.16b, VCUR05.16b, VREG54.16b, VREG51.16b, VCUR06.16b
    VUSHR2 VCUR01.4s, VREG04.4s, VCUR02.4s, VREG14.4s, #24  // d[12,13,14,15] = m << 24
    WCHA_ROR_D #16
    VUSHR2 VCUR03.4s, VREG24.4s, VCUR04.4s, VREG34.4s, #24
    VUSHR2 VCUR05.4s, VREG44.4s, VCUR06.4s, VREG54.4s, #24
    WCHA_ADD2_C_D
    VSLI2 VCUR01.4s, VREG04.4s, VCUR02.4s, VREG14.4s, #8    // d[12,13,14,15] = m >> 8
    VSLI2 VCUR03.4s, VREG24.4s, VCUR04.4s, VREG34.4s, #8
    WCHA_EOR2_B_C
    VSLI2 VCUR05.4s, VREG44.4s, VCUR06.4s, VREG54.4s, #8
    VADD2 VREG04.4s, VREG03.4s, VREG14.4s, VREG13.4s        // c[8,9,10,11] += d[12,13,14,15]
    WCHA_ROR_B #20
    VADD2 VREG24.4s, VREG23.4s, VREG34.4s, VREG33.4s
    VADD2 VREG44.4s, VREG43.4s, VREG54.4s, VREG53.4s
    WCHA_ADD2_A_B
    VEORX VREG03.16b, VREG02.16b, VCUR01.16b, VREG13.16b, VREG12.16b, VCUR02.16b // m = b[4,5,6,7] ^ c[8,9,10,11]
    VEORX VREG23.16b, VREG22.16b, VCUR03.16b, VREG33.16b, VREG32.16b, VCUR04.16b
    WCHA_EOR2_D_A
    VEORX VREG43.16b, VREG42.16b, VCUR05.16b, VREG53.16b, VREG52.16b, VCUR06.16b
    VUSHR2 VCUR01.4s, VREG02.4s, VCUR02.4s, VREG12.4s, #25  // b[4,5,6,7] = m << 25
    WCHA_ROR_D #24
    VUSHR2 VCUR03.4s, VREG22.4s, VCUR04.4s, VREG32.4s, #25
    VUSHR2 VCUR05.4s, VREG42.4s, VCUR06.4s, VREG52.4s, #25
    WCHA_ADD2_C_D
    VSLI2 VCUR01.4s, VREG02.4s, VCUR02.4s, VREG12.4s, #7    // b[4,5,6,7] = m >> 7
    VSLI2 VCUR03.4s, VREG22.4s, VCUR04.4s, VREG32.4s, #7
    WCHA_EOR2_B_C
    VSLI2 VCUR05.4s, VREG42.4s, VCUR06.4s, VREG52.4s, #7
    VEXT2 VREG03.16b, VREG13.16b, #8
    WCHA_ROR_B #25
    VEXT2 VREG23.16b, VREG33.16b, #8
    VEXT2 VREG43.16b, VREG53.16b, #8
.endm

#endif
