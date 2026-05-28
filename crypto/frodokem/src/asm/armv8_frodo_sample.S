/*
 * Optimized FrodoCommonSampleNFromR for ARM64 NEON
 *
 * void FrodoCommonSampleNFromR(
 *     uint16_t *samples,      // x0
 *     uint32_t n,             // x1
 *     const uint16_t *cdfTable, // x2
 *     uint32_t cdfLen,        // x3 (ignored, assumed 15)
 *     const uint8_t *rBytes   // x4
 * );
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_FRODOKEM
#include "crypt_arm.h"

CRYPT_AARCH64_ARCH_BASE

CRYPT_AARCH64_FUNC_START(FrodoCommonSampleNFromR)
AARCH64_PACIASP
    sub     sp, sp, #64
    stp     d8,  d9,  [sp, #0]
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]

    add     x5, x4, x1, lsl #1 
    sub     x3, x3, 1

    movi    v8.8h, #0x01

.Loop:
    ld1     {v0.8h, v1.8h, v2.8h, v3.8h}, [x4], #64
    // C reference reads each 16-bit sample as little-endian bytes; on BE-AArch64
    // ld1 .8h interprets each pair as a big-endian halfword, so swap to match.
#ifdef HITLS_BIG_ENDIAN
    rev16   v0.16b, v0.16b
    rev16   v1.16b, v1.16b
    rev16   v2.16b, v2.16b
    rev16   v3.16b, v3.16b
#endif
    //sign
    and     v4.16b, v0.16b, v8.16b
    and     v5.16b, v1.16b, v8.16b
    and     v6.16b, v2.16b, v8.16b
    and     v7.16b, v3.16b, v8.16b
    //prng
    ushr    v0.8h, v0.8h, #1
    ushr    v1.8h, v1.8h, #1
    ushr    v2.8h, v2.8h, #1
    ushr    v3.8h, v3.8h, #1

    //sub     x7, x3, #0x01
    add     x7, x2, x3, lsl #1
    mov     x8, x2 

    // t
    movi    v14.8h, #0
    movi    v15.8h, #0
    movi    v16.8h, #0
    movi    v17.8h, #0

.CdfLoop:

    ld1r    {v9.8h}, [x8], #2
//    add     x8, x8, #0x02
    cmgt     v10.8h, v0.8h, v9.8h
    cmgt     v11.8h, v1.8h, v9.8h
    cmgt     v12.8h, v2.8h, v9.8h
    cmgt     v13.8h, v3.8h, v9.8h
    // t>T_\chi(z) +1
    ushr    v10.8h, v10.8h, #15
    ushr    v11.8h, v11.8h, #15
    ushr    v12.8h, v12.8h, #15
    ushr    v13.8h, v13.8h, #15 

    add     v14.8h, v14.8h, v10.8h
    add     v15.8h, v15.8h, v11.8h  
    add     v16.8h, v16.8h, v12.8h
    add     v17.8h, v17.8h, v13.8h
    cmp     x8, x7
    b.mi    .CdfLoop

    shl     v4.8h, v4.8h, #15
    shl     v5.8h, v5.8h, #15
    shl     v6.8h, v6.8h, #15
    shl     v7.8h, v7.8h, #15

    sshr    v4.8h, v4.8h, #15
    sshr    v5.8h, v5.8h, #15
    sshr    v6.8h, v6.8h, #15
    sshr    v7.8h, v7.8h, #15

    neg     v0.8h, v14.8h
    neg     v1.8h, v15.8h
    neg     v2.8h, v16.8h
    neg     v3.8h, v17.8h

    bsl     v4.16b, v0.16b, v14.16b
    bsl     v5.16b, v1.16b, v15.16b
    bsl     v6.16b, v2.16b, v16.16b
    bsl     v7.16b, v3.16b, v17.16b

   st1    {v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #64

     
    cmp x4, x5
    b.mi .Loop

    ldp     d8,  d9,  [sp, #0]
    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    add     sp, sp, #64
AARCH64_AUTIASP
    ret

CRYPT_AARCH64_FUNC_END(FrodoCommonSampleNFromR)

#endif
