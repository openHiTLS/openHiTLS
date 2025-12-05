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

// Input ctx、in、out、len.
REGCTX .req x0
REGINC .req x1
REGOUT .req x2
INLEN .req x3

// 64-byte input, temporarily loaded register(0 ~ 15).
WINPUT0 .req w5
XINPUT0 .req x5
WINPUT1 .req w6
XINPUT1 .req x6
WINPUT2 .req w7
XINPUT2 .req x7
WINPUT3 .req w8
XINPUT3 .req x8
WINPUT4 .req w9
XINPUT4 .req x9
WINPUT5 .req w10
XINPUT5 .req x10
WINPUT6 .req w11
XINPUT6 .req x11
WINPUT7 .req w12
XINPUT7 .req x12
WINPUT8 .req w13
XINPUT8 .req x13
WINPUT9 .req w14
XINPUT9 .req x14
WINPUT10 .req w15
XINPUT10 .req x15
WINPUT11 .req w16
XINPUT11 .req x16
WINPUT12 .req w17
XINPUT12 .req x17
WINPUT13 .req w19
XINPUT13 .req x19
WINPUT14 .req w20
XINPUT14 .req x20
WINPUT15 .req w21
XINPUT15 .req x21

// 8 blocks in parallel, 6 blocks of 64-byte data in 8 blocks of 512 bytes.
VREG01 .req v0
VREG02 .req v1
VREG03 .req v2
VREG04 .req v3
VREG11 .req v4
VREG12 .req v5
VREG13 .req v6
VREG14 .req v7
VREG21 .req v8
VREG22 .req v9
VREG23 .req v10
VREG24 .req v11
VREG31 .req v12
VREG32 .req v13
VREG33 .req v14
VREG34 .req v15
VREG41 .req v16
VREG42 .req v17
VREG43 .req v18
VREG44 .req v19
VREG51 .req v20
VREG52 .req v21
VREG53 .req v22
VREG54 .req v23

// Public register, used for temporary calculation.
VCUR01 .req v24
QCUR01 .req q24
VCUR02 .req v25
QCUR02 .req q25
VCUR03 .req v26
QCUR03 .req q26
VCUR04 .req v27
QCUR04 .req q27
VCUR05 .req v28
QCUR05 .req q28
VCUR06 .req v29
QCUR06 .req q29

// Counter、sigma、key、adder register.
VCOUN0 .req v27
VSIGMA .req v28
VKEY01 .req v29
VKEY02 .req v30
QKEY02 .req q30
VADDER .req v31
QADDER .req q31

// Counter、sigma、key、adder register.
WSIG01 .req w22
XSIG01 .req x22
WSIG02 .req w23
XSIG02 .req x23
WKEY01 .req w24
XKEY01 .req x24
WKEY02 .req w25
XKEY02 .req x25
WKEY03 .req w26
XKEY03 .req x26
WKEY04 .req w27
XKEY04 .req x27
WCOUN1 .req w28
XCOUN1 .req x28
WCOUN2 .req w30
XCOUN2 .req x30

.macro VADD2 src, dest, src2, dest2
    add \dest, \dest, \src
    add \dest2, \dest2, \src2
.endm

.macro VEOR2 src, dest, src2, dest2
    eor \dest, \dest, \src
    eor \dest2, \dest2, \src2
.endm

.macro VEORX srca, srcb, dest, srca2, srcb2, dest2
    eor \dest, \srcb, \srca
    eor \dest2, \srcb2, \srca2
.endm

.macro VREV322 dest, dest2
    rev32 \dest, \dest
    rev32 \dest2, \dest2
.endm

.macro VUSHR2 src, dest, src2, dest2, count
    ushr \dest, \src, \count
    ushr \dest2, \src2, \count
.endm

.macro VSLI2 src, dest, src2, dest2, count
    sli \dest, \src, \count
    sli \dest2, \src2, \count
.endm

.macro VEXT2 src, src2, count
    ext \src, \src, \src, \count
    ext \src2, \src2, \src2, \count
.endm

.macro WCHA_ADD_A_B
    add WINPUT0, WINPUT0, WINPUT4
    add WINPUT1, WINPUT1, WINPUT5
    add WINPUT2, WINPUT2, WINPUT6
    add WINPUT3, WINPUT3, WINPUT7
.endm

.macro WCHA_EOR_D_A
    eor WINPUT12, WINPUT12, WINPUT0
    eor WINPUT13, WINPUT13, WINPUT1
    eor WINPUT14, WINPUT14, WINPUT2
    eor WINPUT15, WINPUT15, WINPUT3
.endm

.macro WCHA_ROR_D  count
    ror WINPUT12, WINPUT12, \count
    ror WINPUT13, WINPUT13, \count
    ror WINPUT14, WINPUT14, \count
    ror WINPUT15, WINPUT15, \count
.endm

.macro WCHA_ADD_C_D
    add WINPUT8, WINPUT8, WINPUT12
    add WINPUT9, WINPUT9, WINPUT13
    add WINPUT10, WINPUT10, WINPUT14
    add WINPUT11, WINPUT11, WINPUT15
.endm

.macro WCHA_EOR_B_C
    eor WINPUT4, WINPUT4, WINPUT8
    eor WINPUT5, WINPUT5, WINPUT9
    eor WINPUT6, WINPUT6, WINPUT10
    eor WINPUT7, WINPUT7, WINPUT11
.endm

.macro WCHA_ROR_B  count
    ror WINPUT4, WINPUT4, \count
    ror WINPUT5, WINPUT5, \count
    ror WINPUT6, WINPUT6, \count
    ror WINPUT7, WINPUT7, \count
.endm

.macro WCHA_ADD2_A_B
    add WINPUT0, WINPUT0, WINPUT5
    add WINPUT1, WINPUT1, WINPUT6
    add WINPUT2, WINPUT2, WINPUT7
    add WINPUT3, WINPUT3, WINPUT4
.endm

.macro WCHA_EOR2_D_A
    eor WINPUT15, WINPUT15, WINPUT0
    eor WINPUT12, WINPUT12, WINPUT1
    eor WINPUT13, WINPUT13, WINPUT2
    eor WINPUT14, WINPUT14, WINPUT3
.endm

.macro WCHA_ADD2_C_D
    add WINPUT10, WINPUT10, WINPUT15
    add WINPUT11, WINPUT11, WINPUT12
    add WINPUT8, WINPUT8, WINPUT13
    add WINPUT9, WINPUT9, WINPUT14
.endm

.macro WCHA_EOR2_B_C
    eor WINPUT5, WINPUT5, WINPUT10
    eor WINPUT6, WINPUT6, WINPUT11
    eor WINPUT7, WINPUT7, WINPUT8
    eor WINPUT4, WINPUT4, WINPUT9
.endm

#endif
