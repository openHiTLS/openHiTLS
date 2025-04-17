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
#ifdef HITLS_CRYPTO_GCM

#include "crypt_arm.h"

.arch    armv8-a+crypto
.text

INPUT_H  .req x0
OUT_TB   .req x1
MULL_C2  .req v31
MULL_H   .req v24
OUT_H0   .req v25
OUT_H1_2 .req v26
OUT_H2   .req v27
OUT_H3   .req v28
OUT_H3_4 .req v29
OUT_H4   .req v30
INPUT_X  .req v0
OUT_X    .req v23

.macro GEN_H
    ext v1.16b, MULL_H.16b, MULL_H.16b, #8      //
    ushr v2.2d, MULL_C2.2d, #63
    dup MULL_H.4s, MULL_H.s[1]
    ext v3.16b, v2.16b, MULL_C2.16b, #8         // t0 = 0xc2....01

    ushr v2.2d, v1.2d, #63
    sshr MULL_H.4s, MULL_H.4s, #31              // broadcast carry bit
    and v2.16b, v2.16b, v3.16b
    shl v1.2d, v1.2d, #1

    ext v2.16b, v2.16b, v2.16b, #8

    and v3.16b, v3.16b, MULL_H.16b
    orr v1.16b, v1.16b, v2.16b                  // H<<<=1
    eor OUT_H0.16b, v1.16b, v3.16b              // twisted H
    st1 {OUT_H0.2d}, [OUT_TB], #16              // store H0
.endm

.macro GEN_H2
    //(ah + al) * (ah + al) = ah * ah + 2 * ah * al + al * al
    ext v10.16b, OUT_H0.16b, OUT_H0.16b, #8     // A
    pmull v12.1q, OUT_H0.1d, OUT_H0.1d          // aL * aL
    eor v10.16b, v10.16b, OUT_H0.16b            // A + h
    pmull2 v11.1q, OUT_H0.2d, OUT_H0.2d         // ah * ah
    pmull v13.1q, v10.1d, v10.1d                // (A + h) * (A + h)

    ext v14.16b, v12.16b, v11.16b, #8           // B
    eor v15.16b, v12.16b, v11.16b               // aL * aL +  ah * ah
    eor v13.16b, v13.16b, v14.16b               // ah * al + B
    eor v13.16b, v13.16b, v15.16b               //
    pmull v15.1q, v12.1d, MULL_C2.1d            // 1st phase

    ins v11.d[0], v13.d[1]
    ins v13.d[1], v12.d[0]
    eor v12.16b, v13.16b, v15.16b

    ext v15.16b, v12.16b, v12.16b, #8
    pmull v12.1q, v12.1d, MULL_C2.1d
    eor v15.16b, v15.16b, v11.16b
    eor OUT_H2.16b, v12.16b, v15.16b                    // H^2

    ext v16.16b, OUT_H2.16b, OUT_H2.16b, #8
    eor v16.16b, v16.16b, OUT_H2.16b
    ext OUT_H1_2.16b, v10.16b, v16.16b, #8
    st1 {OUT_H1_2.2d, OUT_H2.2d}, [OUT_TB], #32         // store H^2h H^2
.endm

.macro GEN_H3_4
    //calculate H^3 and H^4
    pmull v0.1q, OUT_H0.1d, OUT_H2.1d
    pmull v1.1q, OUT_H2.1d, OUT_H2.1d
    pmull2 v2.1q, OUT_H0.2d, OUT_H2.2d
    pmull2 v3.1q, OUT_H2.2d, OUT_H2.2d
    pmull v4.1q, v10.1d, v16.1d
    pmull v5.1q, v16.1d, v16.1d

    ext v6.16b, v0.16b, v2.16b, #8                      // Karatsuba post-processing
    ext v7.16b, v1.16b, v3.16b, #8
    eor v8.16b, v0.16b, v2.16b

    eor v4.16b, v4.16b, v6.16b
    eor v9.16b, v1.16b, v3.16b
    eor v5.16b, v5.16b, v7.16b
    eor v4.16b, v4.16b, v8.16b

    pmull v8.1q, v0.1d, MULL_C2.1d                      // 1st phase
    eor v5.16b, v5.16b, v9.16b
    pmull v9.1q, v1.1d, MULL_C2.1d

    ins v2.d[0], v4.d[1]
    ins v3.d[0], v5.d[1]
    ins v4.d[1], v0.d[0]
    ins v5.d[1], v1.d[0]

    eor v0.16b, v4.16b, v8.16b
    eor v1.16b, v5.16b, v9.16b

    ext v8.16b, v0.16b, v0.16b,#8                       // 2nd phase
    ext v9.16b, v1.16b, v1.16b,#8

    pmull v0.1q, v0.1d, MULL_C2.1d
    pmull v1.1q, v1.1d, MULL_C2.1d

    eor v8.16b, v8.16b, v2.16b
    eor v9.16b, v9.16b, v3.16b
    eor OUT_H3.16b, v0.16b, v8.16b                      // H^3
    eor OUT_H4.16b, v1.16b, v9.16b                      // H^4

    ext v20.16b, OUT_H3.16b, OUT_H3.16b, #8             // Karatsuba pre-processing
    ext v21.16b, OUT_H4.16b, OUT_H4.16b, #8
    eor v20.16b, v20.16b, OUT_H4.16b
    eor v21.16b, v21.16b, OUT_H4.16b
    ext OUT_H3_4.16b, v20.16b, v21.16b, #8              // h
    st1 {OUT_H3.2d, OUT_H3_4.2d, OUT_H4.2d}, [OUT_TB]    // store h^3 h^3+h^4 h^4
.endm

.globl GcmTableGen4bit
.type GcmTableGen4bit, %function
.align 4
GcmTableGen4bit:
AARCH64_PACIASP
    movi MULL_C2.16b, #0xe1                     // set 0xc2
    ld1 {MULL_H.16b}, [INPUT_H]                 // load input H
    shl MULL_C2.2d, MULL_C2.2d, #57             // 0xc20000000000000
    rev64 MULL_H.16b, MULL_H.16b
    GEN_H
    GEN_H2
    GEN_H3_4
AARCH64_AUTIASP
    ret
.size GcmTableGen4bit,.-GcmTableGen4bit

// void GcmHashMultiBlock(uint8_t t[GCM_BLOCKSIZE], const MODES_GCM_GF128 hTable[16], const uint8_t *in, uint32_t inLen)
.globl GcmHashMultiBlock
.type  GcmHashMultiBlock, %function
.align 4
GcmHashMultiBlock:
AARCH64_PACIASP
    lsr x3, x3, #4                              // Divided by 64 16*2*2
    ld1 {INPUT_X.16b}, [INPUT_H]                // load Xi
    movi MULL_C2.16b, #0xe1                     // set 0xc2
    ld1 {OUT_H0.2d, OUT_H1_2.2d}, [OUT_TB]      // load twisted H, ...
    shl MULL_C2.2d, MULL_C2.2d, #57             // 0xc20000000000000
.LGcmLoop:
    subs x3, x3, #1
    ld1 {v20.16b}, [x2], #16                    // load in
    eor INPUT_X.16b, INPUT_X.16b, v20.16b       // t ^ in

    rev64 INPUT_X.16b, INPUT_X.16b              // Vectors are reversed in doublewords

    ext v3.16b, INPUT_X.16b, INPUT_X.16b, #8    // {Xi.hi, Xi.lo} =>  {Xi.lo, Xi.hi}
    pmull OUT_X.1q, OUT_H0.1d, v3.1d            // (H.lo * Xi.hi)
    eor INPUT_X.16b, INPUT_X.16b, v3.16b        // (Xi.lo + Xi.hi)
    pmull2 v2.1q, OUT_H0.2d, v3.2d              // (H.hi * Xi.lo)
    pmull v1.1q, OUT_H1_2.1d, INPUT_X.1d        // (H.lo + H.hi) * (Xi.lo + Xi.hi)

    ext v7.16b, OUT_X.16b, v2.16b, #8           // M
    eor v8.16b, OUT_X.16b, v2.16b               // (H.lo * Xi.hi) + (H.hi * Xi.lo)
    eor v1.16b, v1.16b, v7.16b                  // (H.lo + H.hi) * (Xi.lo + Xi.hi) + M
    eor v1.16b, v1.16b, v8.16b                  // (H.lo * Xi.hi) + (H.hi * Xi.lo) + (H.lo + H.hi) * (Xi.lo + Xi.hi) + M
    pmull v18.1q, OUT_X.1d, MULL_C2.1d          // 1st phase of reduction

    ins v2.d[0], v1.d[1]
    ins v1.d[1], OUT_X.d[0]
    eor OUT_X.16b, v1.16b, v18.16b

    ext v18.16b, OUT_X.16b, OUT_X.16b, #8        // 2nd phase of reduction
    pmull OUT_X.1q, OUT_X.1d, MULL_C2.1d
    eor v18.16b, v18.16b, v2.16b
    eor OUT_X.16b, OUT_X.16b, v18.16b

    rev64 OUT_X.16b, OUT_X.16b

    ext INPUT_X.16b, OUT_X.16b, OUT_X.16b, #8
    b.gt .LGcmLoop                                  // > 0
    st1 {INPUT_X.16b}, [INPUT_H]                       // write out Xi
.LhashEnd:
AARCH64_AUTIASP
    ret
.size GcmHashMultiBlock,.-GcmHashMultiBlock

#endif
