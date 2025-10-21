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

.macro CHA512_ROUND flag
    // 0, 1, 2, 3
    // 4, 5, 6, 7
    // 8, 9, 10, 11
    // 12, 13, 14, 15

    // first 4 round (a += b)
    add WINPUT0, WINPUT0, WINPUT4    // 0 + 4
    add VREG01.4s, VREG01.4s, VREG02.4s      // (0, 1, 2 , 3) += (4, 5, 6, 7)
    add WINPUT1, WINPUT1, WINPUT5    // 1 + 5
    add VREG11.4s, VREG11.4s, VREG12.4s
    add WINPUT2, WINPUT2, WINPUT6    // 2 + 6
    add VREG21.4s, VREG21.4s, VREG22.4s    // (0, 1, 2 , 3) += (4, 5, 6, 7)
    add WINPUT3, WINPUT3, WINPUT7    // 3 + 7
    add VREG31.4s, VREG31.4s, VREG32.4s
    
    // first 4 round (d ^= a)
    eor WINPUT12, WINPUT12, WINPUT0  // 12 ^= 0
    add VREG41.4s, VREG41.4s, VREG42.4s    // (0, 1, 2 , 3) += (4, 5, 6, 7)
    eor WINPUT13, WINPUT13, WINPUT1  // 13 ^= 1
    add VREG51.4s, VREG51.4s, VREG52.4s
    eor WINPUT14, WINPUT14, WINPUT2  // 14 ^= 2
    eor VREG04.16b, VREG04.16b, VREG01.16b    // (12, 13, 14, 15) ^= (0, 1, 2 , 3)
    eor WINPUT15, WINPUT15, WINPUT3  // 15 ^= 3
    eor VREG14.16b, VREG14.16b, VREG11.16b

    // first 4 round (d <<<= 16)
    ror WINPUT12, WINPUT12, #16
    eor VREG24.16b, VREG24.16b, VREG21.16b   // (12, 13, 14, 15) ^= (0, 1, 2 , 3)
    ror WINPUT13, WINPUT13, #16
    eor VREG34.16b, VREG34.16b, VREG31.16b
    ror WINPUT14, WINPUT14, #16
    eor VREG44.16b, VREG44.16b, VREG41.16b // (12, 13, 14, 15) ^= (0, 1, 2 , 3)
    ror WINPUT15, WINPUT15, #16
    eor VREG54.16b, VREG54.16b, VREG51.16b

    // first 4 round (c += d)
    add WINPUT8, WINPUT8, WINPUT12
    rev32 VREG04.8h, VREG04.8h    // reverse 16-bit of 32-bit words is same to <<<16
    add WINPUT9, WINPUT9, WINPUT13
    rev32 VREG14.8h, VREG14.8h
    add WINPUT10, WINPUT10, WINPUT14
    rev32 VREG24.8h, VREG24.8h
    add WINPUT11, WINPUT11, WINPUT15
    rev32 VREG34.8h, VREG34.8h

    // first 4 round (b ^= c)
    eor WINPUT4, WINPUT4, WINPUT8
    rev32 VREG44.8h, VREG44.8h
    eor WINPUT5, WINPUT5, WINPUT9
    rev32 VREG54.8h, VREG54.8h
    eor WINPUT6, WINPUT6, WINPUT10
    add VREG03.4s, VREG03.4s, VREG04.4s  // (8, 9, 10, 11) += (12, 13, 14, 15)
    eor WINPUT7, WINPUT7, WINPUT11
    add VREG13.4s, VREG13.4s, VREG14.4s

    // first 4 round (b <<<= 12)
    ror WINPUT4, WINPUT4, #20
    add VREG23.4s, VREG23.4s, VREG24.4s  // (8, 9, 10, 11) += (12, 13, 14, 15)
    ror WINPUT5, WINPUT5, #20
    add VREG33.4s, VREG33.4s, VREG34.4s
    ror WINPUT6, WINPUT6, #20
    add VREG43.4s, VREG43.4s, VREG44.4s // (8, 9, 10, 11) += (12, 13, 14, 15)
    ror WINPUT7, WINPUT7, #20
    add VREG53.4s, VREG53.4s, VREG54.4s

    // first 4 round (a += b)
    add WINPUT0, WINPUT0, WINPUT4
    eor VCUR01.16b, VREG02.16b, VREG03.16b  // (4, 5, 6, 7) ^= (8, 9, 10, 11)
    add WINPUT1, WINPUT1, WINPUT5
    eor VCUR02.16b, VREG12.16b, VREG13.16b
    add WINPUT2, WINPUT2, WINPUT6
    eor VCUR03.16b, VREG22.16b, VREG23.16b
    add WINPUT3, WINPUT3, WINPUT7
    eor VCUR04.16b, VREG32.16b, VREG33.16b

    // first 4 round (d ^= a)
    eor WINPUT12, WINPUT12, WINPUT0
    eor VCUR05.16b, VREG42.16b, VREG43.16b // (4, 5, 6, 7) ^= (8, 9, 10, 11)
    eor WINPUT13, WINPUT13, WINPUT1
    eor VCUR06.16b, VREG52.16b, VREG53.16b
    eor WINPUT14, WINPUT14, WINPUT2
    ushr VREG02.4s, VCUR01.4s, #20    // (4, 5, 6, 7) >> 20
    eor WINPUT15, WINPUT15, WINPUT3
    ushr VREG12.4s, VCUR02.4s, #20

    //  first 4 round (d <<<= 8)
    ror WINPUT12, WINPUT12, #24
    ushr VREG22.4s, VCUR03.4s, #20
    ror WINPUT13, WINPUT13, #24
    ushr VREG32.4s, VCUR04.4s, #20
    ror WINPUT14, WINPUT14, #24
    ushr VREG42.4s, VCUR05.4s, #20
    ror WINPUT15, WINPUT15, #24
    ushr VREG52.4s, VCUR06.4s, #20

    // first 4 round (c += d)
    add WINPUT8, WINPUT8, WINPUT12
    sli VREG02.4s, VCUR01.4s, #12   //  (ushr 20 + sli 12) is same to  <<<12
    add WINPUT9, WINPUT9, WINPUT13
    sli VREG12.4s, VCUR02.4s, #12
    add WINPUT10, WINPUT10, WINPUT14
    sli VREG22.4s, VCUR03.4s, #12
    add WINPUT11, WINPUT11, WINPUT15
    sli VREG32.4s, VCUR04.4s, #12

    // first 4 round (b ^= c)
    eor WINPUT4, WINPUT4, WINPUT8
    sli VREG42.4s, VCUR05.4s, #12
    eor WINPUT5, WINPUT5, WINPUT9
    sli VREG52.4s, VCUR06.4s, #12
    eor WINPUT6, WINPUT6, WINPUT10
    add VREG01.4s, VREG01.4s, VREG02.4s  // (0, 1, 2 , 3) += (4, 5, 6, 7)
    eor WINPUT7, WINPUT7, WINPUT11
    add VREG11.4s, VREG11.4s, VREG12.4s

    // first 4 round (c <<<= 7)
    ror WINPUT4, WINPUT4, #25           //  b <<<= 7
    add VREG21.4s, VREG21.4s, VREG22.4s
    ror WINPUT5, WINPUT5, #25
    add VREG31.4s, VREG31.4s, VREG32.4s
    ror WINPUT6, WINPUT6, #25
    add VREG41.4s, VREG41.4s, VREG42.4s
    ror WINPUT7, WINPUT7, #25
    add VREG51.4s, VREG51.4s, VREG52.4s

    // second 4 round (a + b)
    add WINPUT0, WINPUT0, WINPUT5
    eor VREG04.16b, VREG04.16b, VREG01.16b// (0, 1, 2, 3) ^ (12, 13, 14, 15)
    add WINPUT1, WINPUT1, WINPUT6
    eor VREG14.16b, VREG14.16b, VREG11.16b
    add WINPUT2, WINPUT2, WINPUT7
    eor VREG24.16b, VREG24.16b, VREG21.16b
    add WINPUT3, WINPUT3, WINPUT4
    eor VREG34.16b, VREG34.16b, VREG31.16b

    // second 4 round (d ^= a)
    eor WINPUT15, WINPUT15, WINPUT0
    eor VREG44.16b, VREG44.16b, VREG41.16b
    eor WINPUT12, WINPUT12, WINPUT1
    eor VREG54.16b, VREG54.16b, VREG51.16b
    eor WINPUT13, WINPUT13, WINPUT2
    tbl VREG04.16b, {VREG04.16b}, VADDER.16b
    eor WINPUT14, WINPUT14, WINPUT3
    tbl VREG14.16b, {VREG14.16b}, VADDER.16b

    // second 4 round (d <<<= 16)
    ror WINPUT12, WINPUT12, #16
    tbl VREG24.16b, {VREG24.16b}, VADDER.16b
    ror WINPUT13, WINPUT13, #16
    tbl VREG34.16b, {VREG34.16b}, VADDER.16b
    ror WINPUT14, WINPUT14, #16
    tbl VREG44.16b, {VREG44.16b}, VADDER.16b
    ror WINPUT15, WINPUT15, #16
    tbl VREG54.16b, {VREG54.16b}, VADDER.16b

    // second 4 round (c += d)
    add WINPUT10, WINPUT10, WINPUT15
    add VREG03.4s, VREG03.4s, VREG04.4s  // (8, 9, 10, 11) += (12, 13, 14, 15)
    add WINPUT11, WINPUT11, WINPUT12
    add VREG13.4s, VREG13.4s, VREG14.4s
    add WINPUT8, WINPUT8, WINPUT13
    add VREG23.4s, VREG23.4s, VREG24.4s
    add WINPUT9, WINPUT9, WINPUT14
    add VREG33.4s, VREG33.4s, VREG34.4s


    // second 4 round (b ^= c)
    eor WINPUT5, WINPUT5, WINPUT10
    add VREG43.4s, VREG43.4s, VREG44.4s
    eor WINPUT6, WINPUT6, WINPUT11
    add VREG53.4s, VREG53.4s, VREG54.4s
    eor WINPUT7, WINPUT7, WINPUT8
    eor VCUR01.16b, VREG02.16b, VREG03.16b  // (4, 5, 6, 7) ^ (8, 9, 10, 11)
    eor WINPUT4, WINPUT4, WINPUT9
    eor VCUR02.16b, VREG12.16b, VREG13.16b

    // second 4 round (b <<<= 12)
    ror WINPUT4, WINPUT4, #20
    eor VCUR03.16b, VREG22.16b, VREG23.16b
    ror WINPUT5, WINPUT5, #20
    eor VCUR04.16b, VREG32.16b, VREG33.16b
    ror WINPUT6, WINPUT6, #20
    eor VCUR05.16b, VREG42.16b, VREG43.16b
    ror WINPUT7, WINPUT7, #20
    eor VCUR06.16b, VREG52.16b, VREG53.16b

    // second 4 round (a += b)
    add WINPUT0, WINPUT0, WINPUT5
    ushr VREG02.4s, VCUR01.4s, #25   // <<<= 7
    add WINPUT1, WINPUT1, WINPUT6
    ushr VREG12.4s, VCUR02.4s, #25
    add WINPUT2, WINPUT2, WINPUT7
    ushr VREG22.4s, VCUR03.4s, #25
    add WINPUT3, WINPUT3, WINPUT4
    ushr VREG32.4s, VCUR04.4s, #25

    // second 4 round (d ^= a)
    eor WINPUT15, WINPUT15, WINPUT0
    ushr VREG42.4s, VCUR05.4s, #25
    eor WINPUT12, WINPUT12, WINPUT1
    ushr VREG52.4s, VCUR06.4s, #25
    eor WINPUT13, WINPUT13, WINPUT2
    sli VREG02.4s, VCUR01.4s, #7
    eor WINPUT14, WINPUT14, WINPUT3
    sli VREG12.4s, VCUR02.4s, #7

    // second 4 round (d <<<= 8)
    ror WINPUT12, WINPUT12, #24
    sli VREG22.4s, VCUR03.4s, #7
    ror WINPUT13, WINPUT13, #24
    sli VREG32.4s, VCUR04.4s, #7
    ror WINPUT14, WINPUT14, #24
    sli VREG42.4s, VCUR05.4s, #7
    ror WINPUT15, WINPUT15, #24
    sli VREG52.4s, VCUR06.4s, #7

    // second 4 round (c += d)
    add WINPUT10, WINPUT10, WINPUT15
    ext VREG03.16b, VREG03.16b, VREG03.16b, #8
    add WINPUT11, WINPUT11, WINPUT12
    ext VREG13.16b, VREG13.16b, VREG13.16b, #8
    add WINPUT8, WINPUT8, WINPUT13
    ext VREG23.16b, VREG23.16b, VREG23.16b, #8
    add WINPUT9, WINPUT9, WINPUT14
    ext VREG33.16b, VREG33.16b, VREG33.16b, #8

.if \flag == 1
    // second 4 round (b ^= c)
    eor WINPUT5, WINPUT5, WINPUT10
    ext VREG43.16b, VREG43.16b, VREG43.16b, #8
    eor WINPUT6, WINPUT6, WINPUT11
    ext VREG53.16b, VREG53.16b, VREG53.16b, #8
    eor WINPUT7, WINPUT7, WINPUT8
    ext VREG04.16b, VREG04.16b, VREG04.16b, #12
    eor WINPUT4, WINPUT4, WINPUT9
    ext VREG14.16b, VREG14.16b, VREG14.16b, #12

    // second 4 round (b <<<= 7)
    ror WINPUT4, WINPUT4, #25
    ext VREG24.16b, VREG24.16b, VREG24.16b, #12
    ror WINPUT5, WINPUT5, #25
    ext VREG34.16b, VREG34.16b, VREG34.16b, #12
    ror WINPUT6, WINPUT6, #25
    ext VREG44.16b, VREG44.16b, VREG44.16b, #12
    ror WINPUT7, WINPUT7, #25
    ext VREG54.16b, VREG54.16b, VREG54.16b, #12
    ext VREG02.16b, VREG02.16b, VREG02.16b, #4
    ext VREG12.16b, VREG12.16b, VREG12.16b, #4
    ext VREG22.16b, VREG22.16b, VREG22.16b, #4
    ext VREG32.16b, VREG32.16b, VREG32.16b, #4
    ext VREG42.16b, VREG42.16b, VREG42.16b, #4
    ext VREG52.16b, VREG52.16b, VREG52.16b, #4
.else
    // second 4 round (b ^= c)
    eor WINPUT5, WINPUT5, WINPUT10
    ext VREG43.16b, VREG43.16b, VREG43.16b, #8
    eor WINPUT6, WINPUT6, WINPUT11
    ext VREG53.16b, VREG53.16b, VREG53.16b, #8
    eor WINPUT7, WINPUT7, WINPUT8
    ext VREG04.16b, VREG04.16b, VREG04.16b, #4
    eor WINPUT4, WINPUT4, WINPUT9
    ext VREG14.16b, VREG14.16b, VREG14.16b, #4

    // second 4 round (b <<<= 7)
    ror WINPUT4, WINPUT4, #25
    ext VREG24.16b, VREG24.16b, VREG24.16b, #4
    ror WINPUT5, WINPUT5, #25
    ext VREG34.16b, VREG34.16b, VREG34.16b, #4
    ror WINPUT6, WINPUT6, #25
    ext VREG44.16b, VREG44.16b, VREG44.16b, #4
    ror WINPUT7, WINPUT7, #25
    ext VREG54.16b, VREG54.16b, VREG54.16b, #4
    ext VREG02.16b, VREG02.16b, VREG02.16b, #12
    ext VREG12.16b, VREG12.16b, VREG12.16b, #12
    ext VREG22.16b, VREG22.16b, VREG22.16b, #12
    ext VREG32.16b, VREG32.16b, VREG32.16b, #12
    ext VREG42.16b, VREG42.16b, VREG42.16b, #12
    ext VREG52.16b, VREG52.16b, VREG52.16b, #12
.endif
.endm

#endif
