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

.macro CHA64_SET_WDATA
    mov WINPUT0, WSIG01
    lsr XINPUT1, XSIG01, #32
    mov WINPUT2, WSIG02
    lsr XINPUT3, XSIG02, #32

    mov WINPUT4, WKEY01
    lsr XINPUT5, XKEY01, #32
    mov WINPUT6, WKEY02
    lsr XINPUT7, XKEY02, #32

    mov WINPUT8, WKEY03
    lsr XINPUT9, XKEY03, #32
    mov WINPUT10, WKEY04
    lsr XINPUT11, XKEY04, #32

    mov WINPUT12, WCOUN1
    lsr XINPUT13, XCOUN1, #32             // 0
    mov WINPUT14, WCOUN2
    lsr XINPUT15, XCOUN2, #32
.endm

.macro CHA64_ROUND_END
    add WINPUT0, WINPUT0, WSIG01              // Sum of the upper 32 bits and lower 32 bits.
    add XINPUT1, XINPUT1, XSIG01, lsr#32
    add WINPUT2, WINPUT2, WSIG02
    add XINPUT3, XINPUT3, XSIG02, lsr#32
    add WINPUT4, WINPUT4, WKEY01
    add XINPUT5, XINPUT5, XKEY01, lsr#32
    add WINPUT6, WINPUT6, WKEY02
    add XINPUT7, XINPUT7, XKEY02, lsr#32
    add WINPUT8, WINPUT8, WKEY03
    add XINPUT9, XINPUT9, XKEY03, lsr#32
    add WINPUT10, WINPUT10, WKEY04
    add XINPUT11, XINPUT11, XKEY04, lsr#32
    add WINPUT12, WINPUT12, WCOUN1
    add XINPUT13, XINPUT13, XCOUN1, lsr#32
    add WINPUT14, WINPUT14, WCOUN2
    add XINPUT15, XINPUT15, XCOUN2, lsr#32

    add XINPUT0, XINPUT0, XINPUT1, lsl#32      // Combination of upper 32 bits and lower 32 bits.
    add XINPUT2, XINPUT2, XINPUT3, lsl#32      // Combination of upper 32 bits and lower 32 bits.
    ldp XINPUT1, XINPUT3, [REGINC], #16        // Load input.

    add XINPUT4, XINPUT4, XINPUT5, lsl#32      // Combination of upper 32 bits and lower 32 bits.
    add XINPUT6, XINPUT6, XINPUT7, lsl#32      // Combination of upper 32 bits and lower 32 bits.
    ldp XINPUT5, XINPUT7, [REGINC], #16        // Load input.

    add XINPUT8, XINPUT8, XINPUT9, lsl#32      // Combination of upper 32 bits and lower 32 bits.
    add XINPUT10, XINPUT10, XINPUT11, lsl#32   // Combination of upper 32 bits and lower 32 bits.
    ldp XINPUT9, XINPUT11, [REGINC], #16       // Load input.

    add XINPUT12, XINPUT12, XINPUT13, lsl#32      // Combination of upper 32 bits and lower 32 bits.
    add XINPUT14, XINPUT14, XINPUT15, lsl#32      // Combination of upper 32 bits and lower 32 bits.
    ldp XINPUT13, XINPUT15, [REGINC], #16         // Load input.

#ifdef  HITLS_BIG_ENDIAN                          // Special processing is required in big-endian mode.
    rev XINPUT0, XINPUT0
    rev XINPUT2, XINPUT2
    rev XINPUT4, XINPUT4
    rev XINPUT6, XINPUT6
    rev XINPUT8, XINPUT8
    rev XINPUT10, XINPUT10
    rev XINPUT12, XINPUT12
    rev XINPUT14, XINPUT14
#endif
.endm

.macro CHA64_WRITE_BACK
    eor XINPUT0, XINPUT0, XINPUT1
    eor XINPUT2, XINPUT2, XINPUT3
    eor XINPUT4, XINPUT4, XINPUT5
    eor XINPUT6, XINPUT6, XINPUT7
    eor XINPUT8, XINPUT8, XINPUT9
    stp XINPUT0, XINPUT2, [REGOUT], #16           // Write data.
    eor XINPUT10, XINPUT10, XINPUT11
    stp XINPUT4, XINPUT6, [REGOUT], #16
    eor XINPUT12, XINPUT12, XINPUT13
    eor XINPUT14, XINPUT14, XINPUT15
    stp XINPUT8, XINPUT10, [REGOUT], #16
    stp XINPUT12, XINPUT14, [REGOUT], #16
.endm

#endif