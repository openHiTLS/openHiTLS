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

/* --------------AVX2 Overall design-----------------
 * 64->%xmm0-%xmm7 No need to use stack memory
 * 128->%xmm0-%xmm11 No need to use stack memory
 * 256->%xmm0-%xmm15 Use 256 + 64 bytes of stack memory
 * 512->%ymm0-%ymm15 Use 512 + 128 bytes of stack memory
 *
 --------------AVX512 Overall design-----------------
 * 64->%xmm0-%xmm7 No need to use stack memory
 * 128->%xmm0-%xmm11 No need to use stack memory
 * 256->%xmm0-%xmm31 Use 64-byte stack memory
 * 512->%ymm0-%ymm31 Use 128-byte stack memory
 * 1024->%zmm0-%zmm31 Use 256-byte stack memory
 */

/*************************************************************************************
 * AVX2/AVX512 Generic Instruction Set Using Macros
 *************************************************************************************/

/* %xmm0-15 load STATE Macro. */
.macro LOAD_STATE s0 s1 s2 s3 adr
    vmovdqu    (\adr),   \s0           // state[0-3]
    vmovdqu    16(\adr), \s1           // state[4-7]
    vmovdqu    32(\adr), \s2           // state[8-11]
    vmovdqu    48(\adr), \s3           // state[12-15]
.endm

/* %ymm0-15 load STATE Macro. */
.macro LOAD_512_STATE s0 s1 s2 s3 adr
    vbroadcasti128 (\adr),   \s0    // state[0-3]
    vbroadcasti128 16(\adr), \s1    // state[4-7]
    vbroadcasti128 32(\adr), \s2    // state[8-11]
    vbroadcasti128 48(\adr), \s3    // state[12-15]
.endm

/*
 * %xmm0-15, %ymm0-15 MATRIX TO STATE
 * IN: s0 s1 s2 s3 cur1 cur2
 * OUT: s0 s3 cur1 cur2
 * xmm:
 * {A0 B0 C0 D0} => {A0 A1 A2 A3}
 * {A1 B1 C1 D1}    {B0 B1 B2 B3}
 * {A2 B2 C2 D2}    {C0 C1 C2 C3}
 * {A3 B3 C3 D3}    {D0 D1 D2 D3}
 * ymm:
 * {A0 B0 C0 D0 E0 F0 G0 H0} => {A0 A1 A2 A3 E0 E1 E2 E3}
 * {A1 B1 C1 D1 E1 F1 G1 H1}    {B0 B1 B2 B3 F0 F1 F2 F3}
 * {A2 B2 C2 D2 E2 F2 G2 H2}    {C0 C1 C2 C3 G0 G1 G2 G3}
 * {A3 B3 C3 D3 E3 F3 G3 H3}    {D0 D1 D2 D3 H0 H1 H2 H3}
 * zmm:
 * {A0 B0 C0 D0 E0 F0 G0 H0 I0 J0 K0 L0 M0 N0 O0 P0} => {A0 A1 A2 A3 E0 E1 E2 E3 I0 I1 I2 I3 M0 M1 M2 M3}
 * {A1 B1 C1 D1 E1 F1 G1 H1 I1 J1 K1 L1 M1 N1 O1 P1}    {B0 B1 B2 B3 F0 F1 F2 F3 J0 J1 J2 J3 N0 N1 N2 N3}
 * {A2 B2 C2 D2 E2 F2 G2 H2 I2 J2 K2 L2 M2 N2 O2 P2}    {C0 C1 C2 C3 G0 G1 G2 G3 K0 K1 K2 K3 O0 O1 O2 O3}
 * {A3 B3 C3 D3 E3 F3 G3 H3 I3 J3 K3 L3 M3 N3 O3 P3}    {D0 D1 D2 D3 H0 H1 H2 H3 L0 L1 L2 L3 P0 P1 P2 P3}
*/
.macro MATRIX_TO_STATE s0 s1 s2 s3 cur1 cur2
    vpunpckldq \s1, \s0, \cur1
    vpunpckldq \s3, \s2, \cur2
    vpunpckhdq \s1, \s0, \s1
    vpunpckhdq \s3, \s2, \s2

    vpunpcklqdq \cur2, \cur1, \s0
    vpunpckhqdq \cur2, \cur1, \s3
    vpunpcklqdq \s2, \s1, \cur1
    vpunpckhqdq \s2, \s1, \cur2
.endm

/*************************************************************************************
 * AVX2 instruction set use macros
 *************************************************************************************/

.macro WRITEBACK_64_AVX2 inpos outpos s0 s1 s2 s3
    vpxor  (\inpos), \s0, \s0
    vpxor  16(\inpos), \s1, \s1
    vpxor  32(\inpos), \s2, \s2
    vpxor  48(\inpos), \s3, \s3

    vmovdqu  \s0, (\outpos)          // write back output
    vmovdqu  \s1, 16(\outpos)
    vmovdqu  \s2, 32(\outpos)
    vmovdqu  \s3, 48(\outpos)

    add $64, \inpos
    add $64, \outpos
.endm

/*
 * Converts a state into a matrix.
 * %xmm0-15 %ymm0-15 STATE TO MATRIX
 * s0-s15：Corresponding to 16 wide-bit registers,adr：counter Settings;  base：address of the data storage stack;
 * per：Register bit width，Byte representation（16、32）
 */
.macro STATE_TO_MATRIX s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 base per adr
    vpshufd $0b00000000, \s3, \s12
    vpshufd $0b01010101, \s3, \s13

    vpaddd  \adr, \s12, \s12             // 0, 1, 2, 3, 4, 5, 6 ,7
    vmovdqa \s12, \base+12*\per(%rsp)
    vpshufd $0b10101010, \s3, \s14
    vmovdqa \s13, \base+13*\per(%rsp)
    vpshufd $0b11111111, \s3, \s15
    vmovdqa \s14, \base+14*\per(%rsp)

    vpshufd $0b00000000, \s2, \s8
    vmovdqa \s15, \base+15*\per(%rsp)
    vpshufd $0b01010101, \s2, \s9
    vmovdqa \s8, \base+8*\per(%rsp)
    vpshufd $0b10101010, \s2, \s10
    vmovdqa \s9, \base+9*\per(%rsp)
    vpshufd $0b11111111, \s2, \s11
    vmovdqa \s10, \base+10*\per(%rsp)

    vpshufd $0b00000000, \s1, \s4
    vmovdqa \s11, \base+11*\per(%rsp)
    vpshufd $0b01010101, \s1, \s5
    vmovdqa \s4, \base+4*\per(%rsp)
    vpshufd $0b10101010, \s1, \s6
    vmovdqa \s5, \base+5*\per(%rsp)
    vpshufd $0b11111111, \s1, \s7
    vmovdqa \s6, \base+6*\per(%rsp)

    vpshufd $0b11111111, \s0, \s3
    vmovdqa \s7, \base+7*\per(%rsp)
    vpshufd $0b10101010, \s0, \s2
    vmovdqa \s3, \base+3*\per(%rsp)
    vpshufd $0b01010101, \s0, \s1
    vmovdqa \s2, \base+2*\per(%rsp)
    vpshufd $0b00000000, \s0, \s0
    vmovdqa \s1, \base+1*\per(%rsp)
    vmovdqa \s0, \base(%rsp)
.endm

/*
 * %xmm0-15 %ymm0-15 LOAD MATRIX
 */
.macro LOAD_MATRIX s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 base per adr
    vmovdqa \base(%rsp), \s0
    vmovdqa \base+1*\per(%rsp), \s1
    vmovdqa \base+2*\per(%rsp), \s2
    vmovdqa \base+3*\per(%rsp), \s3
    vmovdqa \base+4*\per(%rsp), \s4
    vmovdqa \base+5*\per(%rsp), \s5
    vmovdqa \base+6*\per(%rsp), \s6
    vmovdqa \base+7*\per(%rsp), \s7
    vmovdqa \base+8*\per(%rsp), \s8
    vmovdqa \base+9*\per(%rsp), \s9
    vmovdqa \base+10*\per(%rsp), \s10
    vmovdqa \base+11*\per(%rsp), \s11
    vmovdqa \base+12*\per(%rsp), \s12
    vmovdqa \base+13*\per(%rsp), \s13
    vpaddd  \adr, \s12, \s12                   // add 8, 8, 8, 8, 8, 8, 8, 8 or 4, 4, 4, 4
    vmovdqa \base+14*\per(%rsp), \s14
    vmovdqa \base+15*\per(%rsp), \s15
    vmovdqa \s12, \base+12*\per(%rsp)
.endm

/*
 * %xmm0-15(256) %ymm0-15(512) Loop
 */
.macro CHACHA20_LOOP s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 base per A8 ror16 ror8

    /* 0 = 0 + 4, 12 = (12 ^ 0) >>> 16 | 8 = 8 + 12, 4 = (4 ^ 8) >>> 12 |
     * 0 = 0 + 4, 12 = (12 ^ 0) >>> 8  | 8 = 8 + 12, 4 = (4 ^ 8) >>> 7
     * 1 = 1 + 5, 13 = (13 ^ 1) >>> 16 | 9 = 9 + 13, 5 = (5 ^ 9) >>> 12 |
     * 1 = 1 + 5, 13 = (13 ^ 1) >>> 8  | 9 = 9 + 13, 5 = (5 ^ 9) >>> 7
     */
    COLUM_QUARTER_AVX_0 \s0 \s4 \s12 \s1 \s5 \s13 (\ror16)
    COLUM_QUARTER_AVX_1 \s8 \s12 \s4 \s9 \s13 \s5 \s10 \s11 $20 $12
    COLUM_QUARTER_AVX_0 \s0 \s4 \s12 \s1 \s5 \s13 (\ror8)
    COLUM_QUARTER_AVX_1 \s8 \s12 \s4 \s9 \s13 \s5 \s10 \s11 $25 $7
    vmovdqa \s8, \base(\A8)
    vmovdqa \s9, \base+\per(\A8)
    vmovdqa \base+2*\per(\A8), \s10
    vmovdqa \base+3*\per(\A8), \s11

    /* 2 = 2 + 6, 14 = (14 ^ 2) >>> 16 | 10 = 10 + 14, 6 = (6 ^ 10)>>> 12 |
     * 2 = 2 + 6, 14 = (14 ^ 2) >>> 8  | 10 = 10 + 14, 6 = (6 ^ 10)>>> 7
     * 3 = 3 + 7, 15 = (15 ^ 3) >>> 16 | 11 = 11 + 15, 7 = (7 ^ 11)>>> 12 |
     * 3 = 3 + 7, 15 = (15 ^ 3) >>> 8  | 11 = 11 + 15, 7 = (7 ^ 11)>>> 7
     */
    COLUM_QUARTER_AVX_0 \s2 \s6 \s14 \s3 \s7 \s15 (\ror16)
    COLUM_QUARTER_AVX_1 \s10 \s14 \s6 \s11 \s15 \s7 \s8 \s9 $20 $12
    COLUM_QUARTER_AVX_0 \s2 \s6 \s14 \s3 \s7 \s15 (\ror8)
    COLUM_QUARTER_AVX_1 \s10 \s14 \s6 \s11 \s15 \s7 \s8 \s9 $25 $7

    /* 0 = 0 + 5, 15 = (15 ^ 0) >>> 16 | 10 = 10 + 15, 5 = (5 ^ 10) >>> 12 |
     * 0 = 0 + 5, 15 = (15 ^ 0) >>> 8  | 10 = 10 + 15, 5 = (5 ^ 10) >>> 7
     * 1 = 1 + 6, 12 = (12 ^ 1) >>> 16 | 11 = 11 + 12, 6 = (6 ^ 11) >>> 12 |
     * 1 = 1 + 6, 12 = (12 ^ 1) >>> 8  | 11 = 11 + 12, 6 = (6 ^ 11) >>> 7
     */
    COLUM_QUARTER_AVX_0 \s0 \s5 \s15 \s1 \s6 \s12 (\ror16)
    COLUM_QUARTER_AVX_1 \s10 \s15 \s5 \s11 \s12 \s6 \s8 \s9 $20 $12
    COLUM_QUARTER_AVX_0 \s0 \s5 \s15 \s1 \s6 \s12 (\ror8)
    COLUM_QUARTER_AVX_1 \s10 \s15 \s5 \s11 \s12 \s6 \s8 \s9 $25 $7
    vmovdqa \s10, \base+2*\per(\A8)
    vmovdqa \s11, \base+3*\per(\A8)
    vmovdqa \base(\A8), \s8
    vmovdqa \base+\per(\A8), \s9

    /* 2 = 2 + 7, 13 = (13 ^ 2) >>> 16 | 8 = 8 + 13, 7 = (7 ^ 8)>>> 12 |
     * 2 = 2 + 7, 13 = (13 ^ 2) >>> 8  | 8 = 8 + 13, 7 = (7 ^ 8)>>> 7
     * 3 = 3 + 4, 14 = (14 ^ 3) >>> 16 | 9 = 9 + 14, 4 = (4 ^ 9)>>> 12 |
     * 3 = 3 + 4, 14 = (14 ^ 3) >>> 8  | 9 = 9 + 14, 4 = (4 ^ 9)>>> 7
     */
    COLUM_QUARTER_AVX_0 \s2 \s7 \s13 \s3 \s4 \s14 (\ror16)
    COLUM_QUARTER_AVX_1 \s8 \s13 \s7 \s9 \s14 \s4 \s10 \s11 $20 $12
    COLUM_QUARTER_AVX_0 \s2 \s7 \s13 \s3 \s4 \s14 (\ror8)
    COLUM_QUARTER_AVX_1 \s8 \s13 \s7 \s9 \s14 \s4 \s10 \s11 $25 $7
.endm

/*
 * %xmm0-15 %ymm0-15 QUARTER macro（used when cyclically moving right by 16 or 8）
 */
.macro COLUM_QUARTER_AVX_0 a0 a1 a2 b0 b1 b2 ror
    vpaddd  \a1, \a0, \a0
    vpaddd  \b1, \b0, \b0
    vpxor   \a0, \a2, \a2
    vpxor   \b0, \b2, \b2
    vpshufb \ror, \a2, \a2
    vpshufb \ror, \b2, \b2
.endm

/*
 * %xmm0-15 %ymm0-15 QUARTER macro（used when cyclically moving right by 12 or 7）
 */
.macro COLUM_QUARTER_AVX_1 a0 a1 a2 b0 b1 b2 cur1 cur2 psr psl
    vpaddd  \a1, \a0, \a0
    vpaddd  \b1, \b0, \b0
    vpxor   \a0, \a2, \a2
    vpxor   \b0, \b2, \b2
    vpsrld  \psr, \a2, \cur1
    vpsrld  \psr, \b2, \cur2
    vpslld  \psl, \a2, \a2
    vpslld  \psl, \b2, \b2
    vpor    \cur1, \a2, \a2
    vpor    \cur2, \b2, \b2
.endm

/*************************************************************************************
 * AVX512 generic instruction set using macros.
 *************************************************************************************/

/* %zmm0-15 LOAD STATE MACRO. */
.macro LOAD_1024_STATE s0 s1 s2 s3 adr
    vbroadcasti32x4 (\adr),   \s0    // state[0-3]
    vbroadcasti32x4 16(\adr), \s1    // state[4-7]
    vbroadcasti32x4 32(\adr), \s2    // state[8-11]
    vbroadcasti32x4 48(\adr), \s3    // state[12-15]
.endm

.macro WRITEBACK_64_AVX512 inpos outpos s0 s1 s2 s3
    vpxord  (\inpos), \s0, \s0
    vpxord  16(\inpos), \s1, \s1
    vpxord  32(\inpos), \s2, \s2
    vpxord  48(\inpos), \s3, \s3

    vmovdqu32  \s0, (\outpos)          // Write back output.
    vmovdqu32  \s1, 16(\outpos)
    vmovdqu32  \s2, 32(\outpos)
    vmovdqu32  \s3, 48(\outpos)

    add $64, \inpos
    add $64, \outpos
.endm

/*
 * %zmm0-15 STATE TO MATRIX
 */
.macro STATE_TO_MATRIX_Z_AVX512 in out0 out1 out2 out3
    // {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} .... {15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15}
    vpshufd $0b00000000, \in, \out0
    vpshufd $0b01010101, \in, \out1
    vpshufd $0b10101010, \in, \out2
    vpshufd $0b11111111, \in, \out3
.endm

/* AVX512 instruction set
 * %zmm0-31(1024) QUARTER
 */
.macro COLUM_QUARTER_AVX512_4 s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 ror
    vpaddd \s4, \s0, \s0
    vpaddd \s5, \s1, \s1
    vpaddd \s6, \s2, \s2
    vpaddd \s7, \s3, \s3

    vpxord \s0, \s8, \s8
    vpxord \s1, \s9, \s9
    vpxord \s2, \s10, \s10
    vpxord \s3, \s11, \s11

    vprold \ror, \s8, \s8
    vprold \ror, \s9, \s9
    vprold \ror, \s10, \s10
    vprold \ror, \s11, \s11
.endm

/* AVX512 instruction set
 * %xmm0-15(256) %ymm0-15(512) %zmm0-31(1024) Loop
 */
.macro CHACHA20_LOOP_AVX512 s00 s01 s02 s03 s04 s05 s06 s07 s08 s09 s10 s11 s12 s13 s14 s15

    /* 0 = 0 + 4, 12 = (12 ^ 0) >>> 16 | 8 = 8 + 12, 4 = (4 ^ 8) >>> 12 |
     * 0 = 0 + 4, 12 = (12 ^ 0) >>> 8  | 8 = 8 + 12, 4 = (4 ^ 8) >>> 7
     * 1 = 1 + 5, 13 = (13 ^ 1) >>> 16 | 9 = 9 + 13, 5 = (5 ^ 9) >>> 12 |
     * 1 = 1 + 5, 13 = (13 ^ 1) >>> 8  | 9 = 9 + 13, 5 = (5 ^ 9) >>> 7
     * 2 = 2 + 6, 14 = (14 ^ 2) >>> 16 | 10 = 10 + 14, 6 = (6 ^ 10)>>> 12 |
     * 2 = 2 + 6, 14 = (14 ^ 2) >>> 8  | 10 = 10 + 14, 6 = (6 ^ 10)>>> 7
     * 3 = 3 + 7, 15 = (15 ^ 3) >>> 16 | 11 = 11 + 15, 7 = (7 ^ 11)>>> 12 |
     * 3 = 3 + 7, 15 = (15 ^ 3) >>> 8  | 11 = 11 + 15, 7 = (7 ^ 11)>>> 7
     */
    COLUM_QUARTER_AVX512_4 \s00 \s01 \s02 \s03 \s04 \s05 \s06 \s07 \s12 \s13 \s14 \s15 $16
    COLUM_QUARTER_AVX512_4 \s08 \s09 \s10 \s11 \s12 \s13 \s14 \s15 \s04 \s05 \s06 \s07 $12
    COLUM_QUARTER_AVX512_4 \s00 \s01 \s02 \s03 \s04 \s05 \s06 \s07 \s12 \s13 \s14 \s15 $8
    COLUM_QUARTER_AVX512_4 \s08 \s09 \s10 \s11 \s12 \s13 \s14 \s15 \s04 \s05 \s06 \s07 $7

    /* 0 = 0 + 5, 15 = (15 ^ 0) >>> 16 | 10 = 10 + 15, 5 = (5 ^ 10) >>> 12 |
     * 0 = 0 + 5, 15 = (15 ^ 0) >>> 8  | 10 = 10 + 15, 5 = (5 ^ 10) >>> 7
     * 1 = 1 + 6, 12 = (12 ^ 1) >>> 16 | 11 = 11 + 12, 6 = (6 ^ 11) >>> 12 |
     * 1 = 1 + 6, 12 = (12 ^ 1) >>> 8  | 11 = 11 + 12, 6 = (6 ^ 11) >>> 7
     * 2 = 2 + 7, 13 = (13 ^ 2) >>> 16 | 8 = 8 + 13, 7 = (7 ^ 8)>>> 12 |
     * 2 = 2 + 7, 13 = (13 ^ 2) >>> 8  | 8 = 8 + 13, 7 = (7 ^ 8)>>> 7
     * 3 = 3 + 4, 14 = (14 ^ 3) >>> 16 | 9 = 9 + 14, 4 = (4 ^ 9)>>> 12 |
     * 3 = 3 + 4, 14 = (14 ^ 3) >>> 8  | 9 = 9 + 14, 4 = (4 ^ 9)>>> 7
     */
    COLUM_QUARTER_AVX512_4 \s00 \s01 \s02 \s03 \s05 \s06 \s07 \s04 \s15 \s12 \s13 \s14 $16
    COLUM_QUARTER_AVX512_4 \s10 \s11 \s08 \s09 \s15 \s12 \s13 \s14 \s05 \s06 \s07 \s04 $12
    COLUM_QUARTER_AVX512_4 \s00 \s01 \s02 \s03 \s05 \s06 \s07 \s04 \s15 \s12 \s13 \s14 $8
    COLUM_QUARTER_AVX512_4 \s10 \s11 \s08 \s09 \s15 \s12 \s13 \s14 \s05 \s06 \s07 \s04 $7
.endm

#endif
