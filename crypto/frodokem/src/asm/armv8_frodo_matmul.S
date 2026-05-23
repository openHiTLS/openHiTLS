#include "hitls_build.h"
#ifdef HITLS_CRYPTO_FRODOKEM
#include "crypt_arm.h"

CRYPT_AARCH64_ARCH_BASE

.macro FRODO_SAVE_D8_D15
    sub     sp, sp, #64
    stp     d8,  d9,  [sp, #0]
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]
.endm

.macro FRODO_RESTORE_D8_D15
    ldp     d8,  d9,  [sp, #0]
    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    add     sp, sp, #64
.endm


CRYPT_AARCH64_FUNC_START(FrodoCommonMulAddSbPlusEPortable)
AARCH64_PACIASP

    FRODO_SAVE_D8_D15

    // mov E'' -> V:v12-v19
    ld1 {v12.8h-v15.8h}, [x3], #64
    ld1 {v16.8h-v19.8h}, [x3]


    ldrh  w5, [x4, #4]   //n
    lsl   x5, x5, #1    
//  add   x1 , x1 , #0    //S0
    add   x6 , x1 , x5    //S1
    add   x7 , x6 , x5    //S2
    add   x8 , x7 , x5    //S3
    add   x9 , x8 , x5    //S4
    add   x10, x9 , x5    //S5
    add   x11, x10, x5    //S6
    add   x12, x11, x5    //S7

    mov   x13, x6   // End S

.SLoop:
    ldr   d0, [x1 ], #8   //S0
    ldr   d1, [x6 ], #8   //S1
    ldr   d2, [x7 ], #8   //S2
    ldr   d3, [x8 ], #8   //S3
    ldr   d4, [x9 ], #8   //S4
    ldr   d5, [x10], #8   //S5
    ldr   d6, [x11], #8   //S6
    ldr   d7, [x12], #8   //S7

    ld1   {v8.8h, v9.8h, v10.8h, v11.8h}, [x2], #64   // B0, B1, B2, B3

    mla   v12.8h , v8.8h , v0.h[0]
    mla   v12.8h , v9.8h , v0.h[1]  
    mla   v12.8h , v10.8h, v0.h[2]
    mla   v12.8h , v11.8h, v0.h[3]  

    mla   v13.8h , v8.8h , v1.h[0]
    mla   v13.8h , v9.8h , v1.h[1]  
    mla   v13.8h , v10.8h, v1.h[2]
    mla   v13.8h , v11.8h, v1.h[3] 

    mla   v14.8h , v8.8h , v2.h[0]
    mla   v14.8h , v9.8h , v2.h[1]  
    mla   v14.8h , v10.8h, v2.h[2]
    mla   v14.8h , v11.8h, v2.h[3] 

    mla   v15.8h , v8.8h , v3.h[0]
    mla   v15.8h , v9.8h , v3.h[1]  
    mla   v15.8h , v10.8h, v3.h[2]
    mla   v15.8h , v11.8h, v3.h[3]

    mla   v16.8h , v8.8h , v4.h[0]
    mla   v16.8h , v9.8h , v4.h[1]  
    mla   v16.8h , v10.8h, v4.h[2]
    mla   v16.8h , v11.8h, v4.h[3]  

    mla   v17.8h , v8.8h , v5.h[0]
    mla   v17.8h , v9.8h , v5.h[1]  
    mla   v17.8h , v10.8h, v5.h[2]
    mla   v17.8h , v11.8h, v5.h[3] 

    mla   v18.8h , v8.8h , v6.h[0]
    mla   v18.8h , v9.8h , v6.h[1]  
    mla   v18.8h , v10.8h, v6.h[2]
    mla   v18.8h , v11.8h, v6.h[3] 

    mla   v19.8h , v8.8h , v7.h[0]
    mla   v19.8h , v9.8h , v7.h[1]  
    mla   v19.8h , v10.8h, v7.h[2]
    mla   v19.8h , v11.8h, v7.h[3]

    cmp   x1, x13
    b.mi  .SLoop

    st1   {v12.8h-v15.8h}, [x0], #64
    st1   {v16.8h-v19.8h}, [x0]

    FRODO_RESTORE_D8_D15
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(FrodoCommonMulAddSbPlusEPortable)

// MultAsPlusEAES: compute B[rowNumber..rowNumber+3][0..7] += A_rows · S + E
// Outer-product approach: for each k-block of 4, broadcast A scalar × S[k][0..7] vector.
// matrixS is pre-transposed S (N×8 layout) so S[k][0..7] is always contiguous.
// Diagonal MLA scheduling: each accumulator register is written at most once per 3
// instructions, eliminating 2-3 cycle RAW stalls (replaces mul+addv+ins sequence).
//
// x0 = out (N×8), x1 = matrixS (N×8, S[k] at &matrixS[k*8]),
// x2 = n, x3 = nBar(=8,unused), x4 = rows (4 A rows contiguous), x5 = rowNumber
CRYPT_AARCH64_FUNC_START(MultAsPlusEAES)
AARCH64_PACIASP
    FRODO_SAVE_D8_D15

    lsl     x9,  x2,  #1              // x9  = n * 2 bytes
    add     x0,  x0,  x5, lsl #4     // out = &out[rowNumber][0]
    add     x5,  x4,  x9             // row1 = rows + n*2
    add     x6,  x5,  x9             // row2
    add     x7,  x6,  x9             // row3
    add     x10, x4,  x9             // end  = rows + n*2

    ld1     {v0.8h, v1.8h, v2.8h, v3.8h}, [x0]   // load B[rowNumber..+3][0..7]

.LoopAsEAES:
    // Load 4 consecutive S rows: S[k], S[k+1], S[k+2], S[k+3] (64 bytes contiguous)
    ld1     {v4.8h, v5.8h, v6.8h, v7.8h}, [x1], #64

    // Load 4 scalars from each A row (4 half-words = 8 bytes per row)
    ldr     d8,  [x4], #8            // A[row0][k..k+3]
    ldr     d9,  [x5], #8            // A[row1][k..k+3]
    ldr     d10, [x6], #8            // A[row2][k..k+3]
    ldr     d11, [x7], #8            // A[row3][k..k+3]

    // Diagonal MLA: 4 output rows × 4 k-values = 16 mla, each accumulator
    // separated by 3 instructions to hide 2-3 cycle MLA write latency.
    // Row 1: (out0,k0),(out1,k1),(out2,k2),(out3,k3)
    mla     v0.8h, v4.8h, v8.h[0]
    mla     v1.8h, v5.8h, v9.h[1]
    mla     v2.8h, v6.8h, v10.h[2]
    mla     v3.8h, v7.8h, v11.h[3]
    // Row 2: (out0,k3),(out1,k0),(out2,k1),(out3,k2)
    mla     v0.8h, v7.8h, v8.h[3]
    mla     v1.8h, v4.8h, v9.h[0]
    mla     v2.8h, v5.8h, v10.h[1]
    mla     v3.8h, v6.8h, v11.h[2]
    // Row 3: (out0,k2),(out1,k3),(out2,k0),(out3,k1)
    mla     v0.8h, v6.8h, v8.h[2]
    mla     v1.8h, v7.8h, v9.h[3]
    mla     v2.8h, v4.8h, v10.h[0]
    mla     v3.8h, v5.8h, v11.h[1]
    // Row 4: (out0,k1),(out1,k2),(out2,k3),(out3,k0)
    mla     v0.8h, v5.8h, v8.h[1]
    mla     v1.8h, v6.8h, v9.h[2]
    mla     v2.8h, v7.8h, v10.h[3]
    mla     v3.8h, v4.8h, v11.h[0]

    cmp     x4, x10
    b.mi    .LoopAsEAES

    st1     {v0.8h, v1.8h, v2.8h, v3.8h}, [x0]

    FRODO_RESTORE_D8_D15
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(MultAsPlusEAES)

// MulAsPlusESHAKE: same outer-product strategy as MultAsPlusEAES.
// x0=out, x1=matrixS(N×8), x2=n, x3=nBar(unused),
// x4=row0, x5=row1, x6=row2, x7=row3, [sp+0]=rowNumber
CRYPT_AARCH64_FUNC_START(MulAsPlusESHAKE)
AARCH64_PACIASP

    // Read rowNumber from stack BEFORE FRODO_SAVE_D8_D15 adjusts sp
    ldr     w9, [sp]
    uxtw    x9, w9

    FRODO_SAVE_D8_D15

    add     x0,  x0,  x9, lsl #4     // out = &out[rowNumber][0]
    lsl     x9,  x2,  #1             // x9  = n * 2 bytes (reuse register)
    add     x10, x4,  x9             // end = row0 + n*2

    ld1     {v0.8h, v1.8h, v2.8h, v3.8h}, [x0]   // load B[rowNumber..+3][0..7]

.LoopAsESHAKE:
    ld1     {v4.8h, v5.8h, v6.8h, v7.8h}, [x1], #64

    ldr     d8,  [x4], #8
    ldr     d9,  [x5], #8
    ldr     d10, [x6], #8
    ldr     d11, [x7], #8

    mla     v0.8h, v4.8h, v8.h[0]
    mla     v1.8h, v5.8h, v9.h[1]
    mla     v2.8h, v6.8h, v10.h[2]
    mla     v3.8h, v7.8h, v11.h[3]

    mla     v0.8h, v7.8h, v8.h[3]
    mla     v1.8h, v4.8h, v9.h[0]
    mla     v2.8h, v5.8h, v10.h[1]
    mla     v3.8h, v6.8h, v11.h[2]

    mla     v0.8h, v6.8h, v8.h[2]
    mla     v1.8h, v7.8h, v9.h[3]
    mla     v2.8h, v4.8h, v10.h[0]
    mla     v3.8h, v5.8h, v11.h[1]

    mla     v0.8h, v5.8h, v8.h[1]
    mla     v1.8h, v6.8h, v9.h[2]
    mla     v2.8h, v7.8h, v10.h[3]
    mla     v3.8h, v4.8h, v11.h[0]

    cmp     x4, x10
    b.mi    .LoopAsESHAKE

    st1     {v0.8h, v1.8h, v2.8h, v3.8h}, [x0]

    FRODO_RESTORE_D8_D15
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(MulAsPlusESHAKE)

CRYPT_AARCH64_FUNC_START(MultSaPlusEAES)
AARCH64_PACIASP

    FRODO_SAVE_D8_D15

    lsl   x2 , x2 , #1    // n bytes
    add   x1 , x1 , x5, lsl #1   // matrixST + rowNumber
    add   x10, x1 , x2   // matrixST + rowNumber + n
    add   x11, x10, x2   // matrixST + rowNumber + 2 * n
    add   x12, x11, x2   // matrixST + rowNumber + 3 * n
    add   x13, x12, x2   // matrixST + rowNumber + 4 * n
    add   x14, x13, x2   // matrixST + rowNumber + 5 * n
    add   x15, x14, x2   // matrixST + rowNumber + 6 * n
    add   x16, x15, x2   // matrixST + rowNumber + 7 * n
    add   x5 , x4 , x2      //row1
    add   x6 , x5 , x2      //row2
    add   x7 , x6 , x2      //row3

    ldr   d0 , [x1 ]      // S0
    ldr   d1 , [x10]      // S1
    ldr   d2 , [x11]      // S2
    ldr   d3 , [x12]      // S3
    ldr   d4 , [x13]      // S4
    ldr   d5 , [x14]      // S5
    ldr   d6 , [x15]      // S6
    ldr   d7 , [x16]      // S7

  //add   x0 , x0 , #0    //out
    add   x10, x0 , x2    //out + n
    add   x11, x10, x2    //out + n * 2
    add   x12, x11, x2    //out + n * 3
    add   x13, x12, x2    //out + n * 4
    add   x14, x13, x2    //out + n * 5
    add   x15, x14, x2    //out + n * 6
    add   x16, x15, x2    //out + n * 7

    add   x9 , x4 , x2    //row0 end 

.Loop4: 

    ld1   {v8.8h} , [x4], #16  // row0
    ld1   {v9.8h} , [x5], #16  // row1
    ld1   {v10.8h}, [x6], #16  // row2
    ld1   {v11.8h}, [x7], #16  // row3

    ld1   {v12.8h}, [x0]  // out0
    ld1   {v13.8h}, [x10]  // out1
    ld1   {v14.8h}, [x11]  // out2
    ld1   {v15.8h}, [x12]  // out3

    ld1   {v16.8h}, [x13]  // out4
    ld1   {v17.8h}, [x14]  // out5
    ld1   {v18.8h}, [x15]  // out6
    ld1   {v19.8h}, [x16]  // out7



    mla    v12.8h, v8.8h , v0.h[0]
    mla    v13.8h, v9.8h , v1.h[1]
    mla    v14.8h, v10.8h, v2.h[2]
    mla    v15.8h, v11.8h, v3.h[3]

    mla    v12.8h, v11.8h, v0.h[3]
    mla    v13.8h, v8.8h , v1.h[0]
    mla    v14.8h, v9.8h , v2.h[1]
    mla    v15.8h, v10.8h, v3.h[2]

    mla    v12.8h, v10.8h, v0.h[2]
    mla    v13.8h, v11.8h, v1.h[3]
    mla    v14.8h, v8.8h , v2.h[0]
    mla    v15.8h, v9.8h , v3.h[1]

    mla    v12.8h, v9.8h , v0.h[1]
    mla    v13.8h, v10.8h, v1.h[2]
    mla    v14.8h, v11.8h, v2.h[3]
    mla    v15.8h, v8.8h , v3.h[0]
          
    mla    v16.8h, v8.8h , v4.h[0]
    mla    v17.8h, v9.8h , v5.h[1]
    mla    v18.8h, v10.8h, v6.h[2]
    mla    v19.8h, v11.8h, v7.h[3]

    mla    v16.8h, v11.8h, v4.h[3]
    mla    v17.8h, v8.8h , v5.h[0]
    mla    v18.8h, v9.8h , v6.h[1]
    mla    v19.8h, v10.8h, v7.h[2]

    
    mla    v16.8h, v10.8h, v4.h[2]
    mla    v17.8h, v11.8h, v5.h[3]
    mla    v18.8h, v8.8h , v6.h[0]
    mla    v19.8h, v9.8h , v7.h[1]
    
    mla    v16.8h, v9.8h , v4.h[1]   
    mla    v17.8h, v10.8h, v5.h[2]
    mla    v18.8h, v11.8h, v6.h[3]
    mla    v19.8h, v8.8h , v7.h[0]
  
    st1   {v12.8h}, [x0] , #16  // out0
    st1   {v13.8h}, [x10], #16  // out1
    st1   {v14.8h}, [x11], #16  // out2
    st1   {v15.8h}, [x12], #16  // out3

    st1   {v16.8h}, [x13], #16  // out4
    st1   {v17.8h}, [x14], #16  // out5
    st1   {v18.8h}, [x15], #16  // out6
    st1   {v19.8h}, [x16], #16  // out7

    cmp   x4, x9
    b.mi  .Loop4

    FRODO_RESTORE_D8_D15
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(MultSaPlusEAES)

CRYPT_AARCH64_FUNC_START(MulSaPlusESHAKE)
AARCH64_PACIASP
    // read stack arg (rowNumber) BEFORE adjusting sp
    ldr   w9, [sp]          //rowNumber
    uxtw  x9, w9

    FRODO_SAVE_D8_D15

    lsl   x2 , x2 , #1    // n bytes
    add   x1 , x1 , x9, lsl #1   // matrixST + rowNumber
    add   x10, x1 , x2   // matrixST + rowNumber + n
    add   x11, x10, x2   // matrixST + rowNumber + 2 * n
    add   x12, x11, x2   // matrixST + rowNumber + 3 * n
    add   x13, x12, x2   // matrixST + rowNumber + 4 * n
    add   x14, x13, x2   // matrixST + rowNumber + 5 * n
    add   x15, x14, x2   // matrixST + rowNumber + 6 * n
    add   x16, x15, x2   // matrixST + rowNumber + 7 * n

    ldr   d0 , [x1 ]      // S0
    ldr   d1 , [x10]      // S1
    ldr   d2 , [x11]      // S2
    ldr   d3 , [x12]      // S3
    ldr   d4 , [x13]      // S4
    ldr   d5 , [x14]      // S5
    ldr   d6 , [x15]      // S6
    ldr   d7 , [x16]      // S7

  //add   x0 , x0 , #0    //out
    add   x10, x0 , x2    //out + n
    add   x11, x10, x2    //out + n * 2
    add   x12, x11, x2    //out + n * 3
    add   x13, x12, x2    //out + n * 4
    add   x14, x13, x2    //out + n * 5
    add   x15, x14, x2    //out + n * 6
    add   x16, x15, x2    //out + n * 7

    add   x9 , x4 , x2    //row0 end 

.Loop5: 

    ld1   {v8.8h} , [x4], #16  // row0
    ld1   {v9.8h} , [x5], #16  // row1
    ld1   {v10.8h}, [x6], #16  // row2
    ld1   {v11.8h}, [x7], #16  // row3

    ld1   {v12.8h}, [x0]  // out0
    ld1   {v13.8h}, [x10]  // out1
    ld1   {v14.8h}, [x11]  // out2
    ld1   {v15.8h}, [x12]  // out3

    ld1   {v16.8h}, [x13]  // out4
    ld1   {v17.8h}, [x14]  // out5
    ld1   {v18.8h}, [x15]  // out6
    ld1   {v19.8h}, [x16]  // out7



    mla    v12.8h, v8.8h , v0.h[0]
    mla    v13.8h, v9.8h , v1.h[1]
    mla    v14.8h, v10.8h, v2.h[2]
    mla    v15.8h, v11.8h, v3.h[3]

    mla    v12.8h, v11.8h, v0.h[3]
    mla    v13.8h, v8.8h , v1.h[0]
    mla    v14.8h, v9.8h , v2.h[1]
    mla    v15.8h, v10.8h, v3.h[2]

    
    
    mla    v12.8h, v10.8h, v0.h[2]
    mla    v13.8h, v11.8h, v1.h[3]
    mla    v14.8h, v8.8h , v2.h[0]
    mla    v15.8h, v9.8h , v3.h[1]

    mla    v12.8h, v9.8h , v0.h[1]
    mla    v13.8h, v10.8h, v1.h[2]
    mla    v14.8h, v11.8h, v2.h[3]
    mla    v15.8h, v8.8h , v3.h[0]
          
    mla    v16.8h, v8.8h , v4.h[0]
    mla    v17.8h, v9.8h , v5.h[1]
    mla    v18.8h, v10.8h, v6.h[2]
    mla    v19.8h, v11.8h, v7.h[3]

    mla    v16.8h, v11.8h, v4.h[3]
    mla    v17.8h, v8.8h , v5.h[0]
    mla    v18.8h, v9.8h , v6.h[1]
    mla    v19.8h, v10.8h, v7.h[2]

    
    mla    v16.8h, v10.8h, v4.h[2]
    mla    v17.8h, v11.8h, v5.h[3]
    mla    v18.8h, v8.8h , v6.h[0]
    mla    v19.8h, v9.8h , v7.h[1]
    
    mla    v16.8h, v9.8h , v4.h[1]   
    mla    v17.8h, v10.8h, v5.h[2]
    mla    v18.8h, v11.8h, v6.h[3]
    mla    v19.8h, v8.8h , v7.h[0]
  
    st1   {v12.8h}, [x0] , #16  // out0
    st1   {v13.8h}, [x10], #16  // out1
    st1   {v14.8h}, [x11], #16  // out2
    st1   {v15.8h}, [x12], #16  // out3

    st1   {v16.8h}, [x13], #16  // out4
    st1   {v17.8h}, [x14], #16  // out5
    st1   {v18.8h}, [x15], #16  // out6
    st1   {v19.8h}, [x16], #16  // out7

    cmp   x4, x9
    b.mi  .Loop5

    FRODO_RESTORE_D8_D15
AARCH64_AUTIASP
    ret
CRYPT_AARCH64_FUNC_END(MulSaPlusESHAKE)

#endif

