/*
 * based on https://eprint.iacr.org/2021/986, CC0 1.0 Universal.
 *
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
#ifdef HITLS_CRYPTO_MLKEM

#include "crypt_arm.h"
.arch    armv8-a

/*
 * Big-endian safe NEON load/store macros (HITLS_BIG_ENDIAN only).
 * "ldr q" on BE places byte[0] in the MSB, reversing element order.
 * Fix: rev64 + ext #8 after load, ext #8 + rev64 before store.
 * Store macros clobber the source register.
 *
 * VLDQ/VSTQ_8H : 8×int16_t  VLDQ/VSTQ_16B: 16×uint8_t  VLDQ/VSTQ_4S: 4×uint32_t
 * VLDQ/VSTQ_LDUR/STUR_8H: unscaled offset  VLDQ/VSTQ_8H/16B_POST: post-increment
 * VFIX_8H/16B/4S reg: fix element order after a plain "ldr q" (e.g. literal pool)
 */
#ifdef HITLS_BIG_ENDIAN
/* --- Fixed-offset forms ------------------------------------------------- */
.macro VLDQ_8H vd, base, offset=#0
    ldr     q\vd, [\base, \offset]
    rev64   v\vd\().8h, v\vd\().8h
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
.endm
.macro VSTQ_8H vd, base, offset=#0
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
    rev64   v\vd\().8h, v\vd\().8h
    str     q\vd, [\base, \offset]
.endm
.macro VLDQ_16B vd, base, offset=#0
    ldr     q\vd, [\base, \offset]
    rev64   v\vd\().16b, v\vd\().16b
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
.endm
.macro VSTQ_16B vd, base, offset=#0
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
    rev64   v\vd\().16b, v\vd\().16b
    str     q\vd, [\base, \offset]
.endm
.macro VLDQ_4S vd, base, offset=#0
    ldr     q\vd, [\base, \offset]
    rev64   v\vd\().4s, v\vd\().4s
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
.endm
.macro VSTQ_4S vd, base, offset=#0
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
    rev64   v\vd\().4s, v\vd\().4s
    str     q\vd, [\base, \offset]
.endm
/* --- Unscaled-offset forms (ldur/stur: offsets not required to be 16-byte-aligned) */
.macro VLDQ_LDUR_8H vd, base, offset=#0
    ldur    q\vd, [\base, \offset]
    rev64   v\vd\().8h, v\vd\().8h
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
.endm
.macro VSTQ_STUR_8H vd, base, offset=#0
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
    rev64   v\vd\().8h, v\vd\().8h
    stur    q\vd, [\base, \offset]
.endm
/* --- Post-increment forms ----------------------------------------------- */
.macro VLDQ_8H_POST vd, base, inc=#16
    ldr     q\vd, [\base], \inc
    rev64   v\vd\().8h, v\vd\().8h
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
.endm
.macro VSTQ_8H_POST vd, base, inc=#16
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
    rev64   v\vd\().8h, v\vd\().8h
    str     q\vd, [\base], \inc
.endm
.macro VSTQ_16B_POST vd, base, inc=#16
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
    rev64   v\vd\().16b, v\vd\().16b
    str     q\vd, [\base], \inc
.endm
/* VFIX: post-load fix for plain "ldr q" (e.g. PC-relative literal pool) */
.macro VFIX_8H  reg
    rev64   v\reg\().8h, v\reg\().8h
    ext     v\reg\().16b, v\reg\().16b, v\reg\().16b, #8
.endm
.macro VFIX_16B reg
    rev64   v\reg\().16b, v\reg\().16b
    ext     v\reg\().16b, v\reg\().16b, v\reg\().16b, #8
.endm
.macro VFIX_4S  reg
    rev64   v\reg\().4s, v\reg\().4s
    ext     v\reg\().16b, v\reg\().16b, v\reg\().16b, #8
.endm
#else   /* !HITLS_BIG_ENDIAN */
.macro VLDQ_8H  vd, base, offset=#0
    ldr     q\vd, [\base, \offset]
.endm
.macro VSTQ_8H  vd, base, offset=#0
    str     q\vd, [\base, \offset]
.endm
.macro VLDQ_16B vd, base, offset=#0
    ldr     q\vd, [\base, \offset]
.endm
.macro VSTQ_16B vd, base, offset=#0
    str     q\vd, [\base, \offset]
.endm
.macro VLDQ_4S  vd, base, offset=#0
    ldr     q\vd, [\base, \offset]
.endm
.macro VSTQ_4S  vd, base, offset=#0
    str     q\vd, [\base, \offset]
.endm
.macro VLDQ_LDUR_8H vd, base, offset=#0
    ldur    q\vd, [\base, \offset]
.endm
.macro VSTQ_STUR_8H vd, base, offset=#0
    stur    q\vd, [\base, \offset]
.endm
.macro VLDQ_8H_POST vd, base, inc=#16
    ldr     q\vd, [\base], \inc
.endm
.macro VSTQ_8H_POST vd, base, inc=#16
    str     q\vd, [\base], \inc
.endm
.macro VSTQ_16B_POST vd, base, inc=#16
    str     q\vd, [\base], \inc
.endm
.macro VFIX_8H  reg
.endm
.macro VFIX_16B reg
.endm
.macro VFIX_4S  reg
.endm
#endif  /* HITLS_BIG_ENDIAN */


#endif
