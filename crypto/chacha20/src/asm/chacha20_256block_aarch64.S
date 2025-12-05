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

.macro CHA256_SET_VDATA
    mov VREG01.16b, VSIGMA.16b
    mov VREG11.16b, VSIGMA.16b
    mov VREG21.16b, VSIGMA.16b

    mov VREG02.16b, VKEY01.16b
    mov VREG12.16b, VKEY01.16b
    mov VREG22.16b, VKEY01.16b

    mov VREG03.16b, VKEY02.16b
    mov VREG13.16b, VKEY02.16b
    mov VREG23.16b, VKEY02.16b

    mov VREG04.16b, VREG52.16b              // 1
    mov VREG14.16b, VREG53.16b              // 2
    mov VREG24.16b, VREG54.16b              // 3
.endm

.macro CHA256_ROUND_A
    add WINPUT0, WINPUT0, WINPUT4               // A+B
    add VREG01.4s, VREG01.4s, VREG02.4s
    add WINPUT1, WINPUT1, WINPUT5               // A+B
    add VREG11.4s, VREG11.4s, VREG12.4s
    add WINPUT2, WINPUT2, WINPUT6               // A+B
    add VREG21.4s, VREG21.4s, VREG22.4s
    add WINPUT3, WINPUT3, WINPUT7               // A+B
    eor VREG04.16b, VREG04.16b, VREG01.16b

    eor WINPUT12, WINPUT12, WINPUT0             // D^A
    eor VREG14.16b, VREG14.16b, VREG11.16b
    eor WINPUT13, WINPUT13, WINPUT1             // D^A
    eor VREG24.16b, VREG24.16b, VREG21.16b
    eor WINPUT14, WINPUT14, WINPUT2             // D^A
    rev32 VREG04.8h, VREG04.8h
    eor WINPUT15, WINPUT15, WINPUT3             // D^A
    rev32 VREG14.8h, VREG14.8h

    ror WINPUT12, WINPUT12, #16                 // D>>>16
    rev32 VREG24.8h, VREG24.8h
    ror WINPUT13, WINPUT13, #16                 // D>>>16
    add VREG03.4s, VREG03.4s, VREG04.4s
    ror WINPUT14, WINPUT14, #16                 // D>>>16
    add VREG13.4s, VREG13.4s, VREG14.4s
    ror WINPUT15, WINPUT15, #16                 // D>>>16
    add VREG23.4s, VREG23.4s, VREG24.4s

    add WINPUT8, WINPUT8, WINPUT12              // C+D
    eor VREG41.16b, VREG03.16b, VREG02.16b
    add WINPUT9, WINPUT9, WINPUT13              // C+D
    eor VREG42.16b, VREG13.16b, VREG12.16b
    add WINPUT10, WINPUT10, WINPUT14            // C+D
    eor VREG43.16b, VREG23.16b, VREG22.16b
    add WINPUT11, WINPUT11, WINPUT15            // C+D
    ushr VREG02.4s, VREG41.4s, #20

    eor WINPUT4, WINPUT4, WINPUT8               // B^C
    ushr VREG12.4s, VREG42.4s, #20
    eor WINPUT5, WINPUT5, WINPUT9               // B^C
    ushr VREG22.4s, VREG43.4s, #20
    eor WINPUT6, WINPUT6, WINPUT10              // B^C
    sli VREG02.4s, VREG41.4s, #12
    eor WINPUT7, WINPUT7, WINPUT11              // B^C
    sli VREG12.4s, VREG42.4s, #12

    ror WINPUT4, WINPUT4, #20                   // B>>>20
    sli VREG22.4s, VREG43.4s, #12
    ror WINPUT5, WINPUT5, #20                   // B>>>20
    add VREG01.4s, VREG01.4s, VREG02.4s
    ror WINPUT6, WINPUT6, #20                   // B>>>20
    add VREG11.4s, VREG11.4s, VREG12.4s
    ror WINPUT7, WINPUT7, #20                   // B>>>20
    add VREG21.4s, VREG21.4s, VREG22.4s

    add WINPUT0, WINPUT0, WINPUT4               // A+B
    eor VREG41.16b, VREG04.16b, VREG01.16b
    add WINPUT1, WINPUT1, WINPUT5               // A+B
    eor VREG42.16b, VREG14.16b, VREG11.16b
    add WINPUT2, WINPUT2, WINPUT6               // A+B
    eor VREG43.16b, VREG24.16b, VREG21.16b
    add WINPUT3, WINPUT3, WINPUT7               // A+B
    tbl VREG04.16b, {VREG41.16b}, VCOUN0.16b

    eor WINPUT12, WINPUT12, WINPUT0             // D^A
    tbl VREG14.16b, {VREG42.16b}, VCOUN0.16b
    eor WINPUT13, WINPUT13, WINPUT1             // D^A
    tbl VREG24.16b, {VREG43.16b}, VCOUN0.16b
    eor WINPUT14, WINPUT14, WINPUT2             // D^A
    add VREG03.4s, VREG03.4s, VREG04.4s
    eor WINPUT15, WINPUT15, WINPUT3             // D^A
    add VREG13.4s, VREG13.4s, VREG14.4s

    ror WINPUT12, WINPUT12, #24                 // D>>>24
    add VREG23.4s, VREG23.4s, VREG24.4s
    ror WINPUT13, WINPUT13, #24                 // D>>>24
    eor VREG41.16b, VREG03.16b, VREG02.16b
    ror WINPUT14, WINPUT14, #24                 // D>>>24
    eor VREG42.16b, VREG13.16b, VREG12.16b
    ror WINPUT15, WINPUT15, #24                 // D>>>24
    eor VREG43.16b, VREG23.16b, VREG22.16b

    add WINPUT8, WINPUT8, WINPUT12              // C+D
    ushr VREG02.4s, VREG41.4s, #25
    add WINPUT9, WINPUT9, WINPUT13              // C+D
    ushr VREG12.4s, VREG42.4s, #25
    add WINPUT10, WINPUT10, WINPUT14            // C+D
    ushr VREG22.4s, VREG43.4s, #25
    add WINPUT11, WINPUT11, WINPUT15            // C+D
    sli VREG02.4s, VREG41.4s, #7

    eor WINPUT4, WINPUT4, WINPUT8               // B^C
    sli VREG12.4s, VREG42.4s, #7
    eor WINPUT5, WINPUT5, WINPUT9               // B^C
    sli VREG22.4s, VREG43.4s, #7
    eor WINPUT6, WINPUT6, WINPUT10              // B^C
    ext VREG03.16b, VREG03.16b, VREG03.16b, #8
    eor WINPUT7, WINPUT7, WINPUT11              // B^C
    ext VREG13.16b, VREG13.16b, VREG13.16b, #8

    ror WINPUT4, WINPUT4, #25                   // B>>>25
    ext VREG23.16b, VREG23.16b, VREG23.16b, #8
    ror WINPUT5, WINPUT5, #25                   // B>>>25
    ext VREG04.16b, VREG04.16b, VREG04.16b, #12
    ror WINPUT6, WINPUT6, #25                   // B>>>25
    ext VREG14.16b, VREG14.16b, VREG14.16b, #12
    ror WINPUT7, WINPUT7, #25                   // B>>>25
    ext VREG24.16b, VREG24.16b, VREG24.16b, #12

    ext VREG34.16b, VREG34.16b, VREG34.16b, #12
    ext VREG02.16b, VREG02.16b, VREG02.16b, #4
    ext VREG12.16b, VREG12.16b, VREG12.16b, #4
    ext VREG22.16b, VREG22.16b, VREG22.16b, #4
    ext VREG32.16b, VREG32.16b, VREG32.16b, #4
.endm

.macro CHA256_ROUND_B
    add WINPUT0, WINPUT0, WINPUT5               // A+B
    add VREG01.4s, VREG01.4s, VREG02.4s
    add WINPUT1, WINPUT1, WINPUT6               // A+B
    add VREG11.4s, VREG11.4s, VREG12.4s
    add WINPUT2, WINPUT2, WINPUT7               // A+B
    add VREG21.4s, VREG21.4s, VREG22.4s
    add WINPUT3, WINPUT3, WINPUT4               // A+B
    eor VREG04.16b, VREG04.16b, VREG01.16b

    eor WINPUT15, WINPUT15, WINPUT0             // D^A
    eor VREG14.16b, VREG14.16b, VREG11.16b
    eor WINPUT12, WINPUT12, WINPUT1             // D^A
    eor VREG24.16b, VREG24.16b, VREG21.16b
    eor WINPUT13, WINPUT13, WINPUT2             // D^A
    rev32 VREG04.8h, VREG04.8h
    eor WINPUT14, WINPUT14, WINPUT3             // D^A
    rev32 VREG14.8h, VREG14.8h

    ror WINPUT12, WINPUT12, #16                 // D>>>16
    rev32 VREG24.8h, VREG24.8h
    ror WINPUT13, WINPUT13, #16                 // D>>>16
    add VREG03.4s, VREG03.4s, VREG04.4s
    ror WINPUT14, WINPUT14, #16                 // D>>>16
    add VREG13.4s, VREG13.4s, VREG14.4s
    ror WINPUT15, WINPUT15, #16                 // D>>>16
    add VREG23.4s, VREG23.4s, VREG24.4s

    add WINPUT10, WINPUT10, WINPUT15            // C+D
    eor VREG41.16b, VREG03.16b, VREG02.16b
    add WINPUT11, WINPUT11, WINPUT12            // C+D
    eor VREG42.16b, VREG13.16b, VREG12.16b
    add WINPUT8, WINPUT8, WINPUT13              // C+D
    eor VREG43.16b, VREG23.16b, VREG22.16b
    add WINPUT9, WINPUT9, WINPUT14              // C+D
    ushr VREG02.4s, VREG41.4s, #20

    eor WINPUT5, WINPUT5, WINPUT10              // B^C
    ushr VREG12.4s, VREG42.4s, #20
    eor WINPUT6, WINPUT6, WINPUT11              // B^C
    ushr VREG22.4s, VREG43.4s, #20
    eor WINPUT7, WINPUT7, WINPUT8               // B^C
    sli VREG02.4s, VREG41.4s, #12
    eor WINPUT4, WINPUT4, WINPUT9               // B^C
    sli VREG12.4s, VREG42.4s, #12

    ror WINPUT4, WINPUT4, #20                   // B>>>20
    sli VREG22.4s, VREG43.4s, #12
    ror WINPUT5, WINPUT5, #20                   // B>>>20
    add VREG01.4s, VREG01.4s, VREG02.4s
    ror WINPUT6, WINPUT6, #20                   // B>>>20
    add VREG11.4s, VREG11.4s, VREG12.4s
    ror WINPUT7, WINPUT7, #20                   // B>>>20
    add VREG21.4s, VREG21.4s, VREG22.4s

    add WINPUT0, WINPUT0, WINPUT5               // A+B
    eor VREG41.16b, VREG04.16b, VREG01.16b
    add WINPUT1, WINPUT1, WINPUT6               // A+B
    eor VREG42.16b, VREG14.16b, VREG11.16b
    add WINPUT2, WINPUT2, WINPUT7               // A+B
    eor VREG43.16b, VREG24.16b, VREG21.16b
    add WINPUT3, WINPUT3, WINPUT4               // A+B
    tbl VREG04.16b, {VREG41.16b}, VCOUN0.16b

    eor WINPUT15, WINPUT15, WINPUT0             // D^A
    tbl VREG14.16b, {VREG42.16b}, VCOUN0.16b
    eor WINPUT12, WINPUT12, WINPUT1             // D^A
    tbl VREG24.16b, {VREG43.16b}, VCOUN0.16b
    eor WINPUT13, WINPUT13, WINPUT2             // D^A
    add VREG03.4s, VREG03.4s, VREG04.4s
    eor WINPUT14, WINPUT14, WINPUT3             // D^A
    add VREG13.4s, VREG13.4s, VREG14.4s

    ror WINPUT12, WINPUT12, #24                 // D>>>24
    add VREG23.4s, VREG23.4s, VREG24.4s
    ror WINPUT13, WINPUT13, #24
    eor VREG41.16b, VREG03.16b, VREG02.16b
    ror WINPUT14, WINPUT14, #24
    eor VREG42.16b, VREG13.16b, VREG12.16b
    ror WINPUT15, WINPUT15, #24
    eor VREG43.16b, VREG23.16b, VREG22.16b

    add WINPUT10, WINPUT10, WINPUT15            // C+D
    ushr VREG02.4s, VREG41.4s, #25
    add WINPUT11, WINPUT11, WINPUT12            // C+D
    ushr VREG12.4s, VREG42.4s, #25
    add WINPUT8, WINPUT8, WINPUT13              // C+D
    ushr VREG22.4s, VREG43.4s, #25
    add WINPUT9, WINPUT9, WINPUT14              // C+D
    sli VREG02.4s, VREG41.4s, #7

    eor WINPUT5, WINPUT5, WINPUT10              // B^C
    sli VREG12.4s, VREG42.4s, #7
    eor WINPUT6, WINPUT6, WINPUT11
    sli VREG22.4s, VREG43.4s, #7
    eor WINPUT7, WINPUT7, WINPUT8
    ext VREG03.16b, VREG03.16b, VREG03.16b, #8
    eor WINPUT4, WINPUT4, WINPUT9
    ext VREG13.16b, VREG13.16b, VREG13.16b, #8

    ror WINPUT4, WINPUT4, #25                   // B>>>25
    ext VREG23.16b, VREG23.16b, VREG23.16b, #8
    ror WINPUT5, WINPUT5, #25
    ext VREG04.16b, VREG04.16b, VREG04.16b, #4
    ror WINPUT6, WINPUT6, #25
    ext VREG14.16b, VREG14.16b, VREG14.16b, #4
    ror WINPUT7, WINPUT7, #25
    ext VREG24.16b, VREG24.16b, VREG24.16b, #4

    ext VREG34.16b, VREG34.16b, VREG34.16b, #4
    ext VREG02.16b, VREG02.16b, VREG02.16b, #12
    ext VREG12.16b, VREG12.16b, VREG12.16b, #12
    ext VREG22.16b, VREG22.16b, VREG22.16b, #12
    ext VREG32.16b, VREG32.16b, VREG32.16b, #12
.endm

.macro CHA256_ROUND_END
    add VREG01.4s, VREG01.4s, VSIGMA.4s     // After the cycle is complete, add input.
    add VREG11.4s, VREG11.4s, VSIGMA.4s
    add VREG21.4s, VREG21.4s, VSIGMA.4s

    add VREG02.4s, VREG02.4s, VKEY01.4s     // After the cycle is complete, add input.
    add VREG12.4s, VREG12.4s, VKEY01.4s
    add VREG22.4s, VREG22.4s, VKEY01.4s

    add VREG03.4s, VREG03.4s, VKEY02.4s     // After the cycle is complete, add input.
    add VREG13.4s, VREG13.4s, VKEY02.4s
    add VREG23.4s, VREG23.4s, VKEY02.4s

    add VREG04.4s, VREG04.4s, VREG52.4s     // 0
    add VREG14.4s, VREG14.4s, VREG53.4s     // 1
    add VREG24.4s, VREG24.4s, VREG54.4s     // 2
.endm

.macro CHA256_WRITE_BACK
    ld1 {VREG41.16b, VREG42.16b, VREG43.16b, VREG44.16b}, [REGINC], #64  // Load 64 bytes.
    eor XINPUT0, XINPUT0, XINPUT1
    eor XINPUT2, XINPUT2, XINPUT3
    eor XINPUT4, XINPUT4, XINPUT5
    eor XINPUT6, XINPUT6, XINPUT7
    eor XINPUT8, XINPUT8, XINPUT9
    stp XINPUT0, XINPUT2, [REGOUT], #16            // Write data.
    eor VREG01.16b, VREG01.16b, VREG41.16b
    stp XINPUT4, XINPUT6, [REGOUT], #16
    eor XINPUT10, XINPUT10, XINPUT11
    eor VREG02.16b, VREG02.16b, VREG42.16b
    eor XINPUT12, XINPUT12, XINPUT13
    eor VREG03.16b, VREG03.16b, VREG43.16b
    eor XINPUT14, XINPUT14, XINPUT15
    stp XINPUT8, XINPUT10, [REGOUT], #16
    eor VREG04.16b, VREG04.16b, VREG44.16b

    ld1 {VREG41.16b, VREG42.16b, VREG43.16b, VREG44.16b}, [REGINC], #64  // Load 64 bytes.
    stp XINPUT12, XINPUT14, [REGOUT], #16

    eor VREG11.16b, VREG11.16b, VREG41.16b
    eor VREG12.16b, VREG12.16b, VREG42.16b

    st1 {VREG01.16b, VREG02.16b, VREG03.16b, VREG04.16b}, [REGOUT], #64  // Write 64 bytes.

    eor VREG13.16b, VREG13.16b, VREG43.16b
    eor VREG14.16b, VREG14.16b, VREG44.16b

    ld1 {VREG01.16b, VREG02.16b, VREG03.16b, VREG04.16b}, [REGINC], #64  // Load 64 bytes.
    st1 {VREG11.16b, VREG12.16b, VREG13.16b, VREG14.16b}, [REGOUT], #64  // Write 64 bytes.

    eor VREG21.16b, VREG21.16b, VREG01.16b
    eor VREG22.16b, VREG22.16b, VREG02.16b
    eor VREG23.16b, VREG23.16b, VREG03.16b
    eor VREG24.16b, VREG24.16b, VREG04.16b
    st1 {VREG21.16b, VREG22.16b, VREG23.16b, VREG24.16b}, [REGOUT], #64  // Write 64 bytes.
.endm

.macro CHA256_WRITE_BACKB src1, src2, src3, src4
    ld1 {VREG41.16b, VREG42.16b, VREG43.16b, VREG44.16b}, [REGINC], #64  // Load 64 bytes.
    eor \src1, \src1, VREG41.16b
    eor \src2, \src2, VREG42.16b
    eor \src3, \src3, VREG43.16b
    eor \src4, \src4, VREG44.16b
    st1 {\src1, \src2, \src3, \src4}, [REGOUT], #64  // Write 64 bytes.
.endm

#endif
