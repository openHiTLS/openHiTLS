#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4
.file "crypt_sm4_riscv64_rvv.S"
.text
.global RVV_ENC_ROUND_FUNCTION_NumBlocks
RVV_ENC_ROUND_FUNCTION_NumBlocks:
    li t1, 0
    mv t2, a1
    li t3, 32
    vsetvli t0, a2, e32, m1, ta, ma
    vlseg4e32.v v8, (a0)
sm4_enc_round_func:
    lw t4, 0(t2)
    vxor.vv v7, v9, v10
    vxor.vv v7, v7, v11
    vxor.vx v7, v7, t4
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vluxei8.v v7, (a3), v7
    li t4, 4
    vsetvli t0, t4, e32, m1, ta, ma
    vsll.vi v12, v7, 2
    vsrl.vi v13, v7, 30
    vor.vv v6, v12, v13
    vsll.vi v12, v7, 10
    vsrl.vi v13, v7, 22
    vor.vv v5, v12, v13
    vsll.vi v12, v7, 18
    vsrl.vi v13, v7, 14
    vor.vv v4, v12, v13
    vsll.vi v12, v7, 24
    vsrl.vi v13, v7, 8
    vor.vv v3, v12, v13
    vxor.vv v7, v7, v6
    vxor.vv v7, v7, v5
    vxor.vv v7, v7, v4
    vxor.vv v7, v7, v3
    vxor.vv v8, v7, v8
    lw t4, 4(t2)
    vxor.vv v7, v8, v10
    vxor.vv v7, v7, v11
    vxor.vx v7, v7, t4
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vluxei8.v v7, (a3), v7
    li t4, 4
    vsetvli t0, t4, e32, m1, ta, ma
    vsll.vi v12, v7, 2
    vsrl.vi v13, v7, 30
    vor.vv v6, v12, v13
    vsll.vi v12, v7, 10
    vsrl.vi v13, v7, 22
    vor.vv v5, v12, v13
    vsll.vi v12, v7, 18
    vsrl.vi v13, v7, 14
    vor.vv v4, v12, v13
    vsll.vi v12, v7, 24
    vsrl.vi v13, v7, 8
    vor.vv v3, v12, v13
    vxor.vv v7, v7, v6
    vxor.vv v7, v7, v5
    vxor.vv v7, v7, v4
    vxor.vv v7, v7, v3
    vxor.vv v9, v7, v9
    lw t4, 8(t2)
    vxor.vv v7, v8, v9
    vxor.vv v7, v7, v11
    vxor.vx v7, v7, t4
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vluxei8.v v7, (a3), v7
    li t4, 4
    vsetvli t0, t4, e32, m1, ta, ma
    vsll.vi v12, v7, 2
    vsrl.vi v13, v7, 30
    vor.vv v6, v12, v13
    vsll.vi v12, v7, 10
    vsrl.vi v13, v7, 22
    vor.vv v5, v12, v13
    vsll.vi v12, v7, 18
    vsrl.vi v13, v7, 14
    vor.vv v4, v12, v13
    vsll.vi v12, v7, 24
    vsrl.vi v13, v7, 8
    vor.vv v3, v12, v13
    vxor.vv v7, v7, v6
    vxor.vv v7, v7, v5
    vxor.vv v7, v7, v4
    vxor.vv v7, v7, v3
    vxor.vv v10, v7, v10
    lw t4, 12(t2)
    vxor.vv v7, v9, v10
    vxor.vv v7, v7, v8
    vxor.vx v7, v7, t4
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vluxei8.v v7, (a3), v7
    li t4, 4
    vsetvli t0, t4, e32, m1, ta, ma
    vsll.vi v12, v7, 2
    vsrl.vi v13, v7, 30
    vor.vv v6, v12, v13
    vsll.vi v12, v7, 10
    vsrl.vi v13, v7, 22
    vor.vv v5, v12, v13
    vsll.vi v12, v7, 18
    vsrl.vi v13, v7, 14
    vor.vv v4, v12, v13
    vsll.vi v12, v7, 24
    vsrl.vi v13, v7, 8
    vor.vv v3, v12, v13
    vxor.vv v7, v7, v6
    vxor.vv v7, v7, v5
    vxor.vv v7, v7, v4
    vxor.vv v7, v7, v3
    vxor.vv v11, v7, v11
    add t2, t2, 16
    addi t1, t1, 4
    bne t1, t3, sm4_enc_round_func
    vsetvli t0, a2, e32, m1, ta, ma
    vsseg4e32.v v8, (a0)
    ret

.global RVV_DEC_ROUND_FUNCTION_NumBlocks
RVV_DEC_ROUND_FUNCTION_NumBlocks:
    li t1, 32
    mv t2, a1
    vsetvli t0, a2, e32, m1, ta, ma
    vlseg4e32.v v8, (a0)
    slli t1, t1, 2
    add t2, t1, t2
    li t1, 32
sm4_dec_round_func:
    addi t2, t2, -4
    lw t4, 0(t2)
    vxor.vv v7, v9, v10
    vxor.vv v7, v7, v11
    vxor.vx v7, v7, t4
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vluxei8.v v7, (a3), v7
    li t4, 4
    vsetvli t0, t4, e32, m1, ta, ma
    vsll.vi v12, v7, 2
    vsrl.vi v13, v7, 30
    vor.vv v6, v12, v13
    vsll.vi v12, v7, 10
    vsrl.vi v13, v7, 22
    vor.vv v5, v12, v13
    vsll.vi v12, v7, 18
    vsrl.vi v13, v7, 14
    vor.vv v4, v12, v13
    vsll.vi v12, v7, 24
    vsrl.vi v13, v7, 8
    vor.vv v3, v12, v13
    vxor.vv v7, v7, v6
    vxor.vv v7, v7, v5
    vxor.vv v7, v7, v4
    vxor.vv v7, v7, v3
    vxor.vv v8, v7, v8
    addi t2, t2, -4
    lw t4, 0(t2)
    vxor.vv v7, v8, v10
    vxor.vv v7, v7, v11
    vxor.vx v7, v7, t4
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vluxei8.v v7, (a3), v7
    li t4, 4
    vsetvli t0, t4, e32, m1, ta, ma
    vsll.vi v12, v7, 2
    vsrl.vi v13, v7, 30
    vor.vv v6, v12, v13
    vsll.vi v12, v7, 10
    vsrl.vi v13, v7, 22
    vor.vv v5, v12, v13
    vsll.vi v12, v7, 18
    vsrl.vi v13, v7, 14
    vor.vv v4, v12, v13
    vsll.vi v12, v7, 24
    vsrl.vi v13, v7, 8
    vor.vv v3, v12, v13
    vxor.vv v7, v7, v6
    vxor.vv v7, v7, v5
    vxor.vv v7, v7, v4
    vxor.vv v7, v7, v3
    vxor.vv v9, v7, v9
    addi t2, t2, -4
    lw t4, 0(t2)
    vxor.vv v7, v8, v9
    vxor.vv v7, v7, v11
    vxor.vx v7, v7, t4
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vluxei8.v v7, (a3), v7
    li t4, 4
    vsetvli t0, t4, e32, m1, ta, ma
    vsll.vi v12, v7, 2
    vsrl.vi v13, v7, 30
    vor.vv v6, v12, v13
    vsll.vi v12, v7, 10
    vsrl.vi v13, v7, 22
    vor.vv v5, v12, v13
    vsll.vi v12, v7, 18
    vsrl.vi v13, v7, 14
    vor.vv v4, v12, v13
    vsll.vi v12, v7, 24
    vsrl.vi v13, v7, 8
    vor.vv v3, v12, v13
    vxor.vv v7, v7, v6
    vxor.vv v7, v7, v5
    vxor.vv v7, v7, v4
    vxor.vv v7, v7, v3
    vxor.vv v10, v7, v10
    addi t2, t2, -4
    lw t4, 0(t2)
    vxor.vv v7, v9, v10
    vxor.vv v7, v7, v8
    vxor.vx v7, v7, t4
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vluxei8.v v7, (a3), v7
    li t4, 4
    vsetvli t0, t4, e32, m1, ta, ma
    vsll.vi v12, v7, 2
    vsrl.vi v13, v7, 30
    vor.vv v6, v12, v13
    vsll.vi v12, v7, 10
    vsrl.vi v13, v7, 22
    vor.vv v5, v12, v13
    vsll.vi v12, v7, 18
    vsrl.vi v13, v7, 14
    vor.vv v4, v12, v13
    vsll.vi v12, v7, 24
    vsrl.vi v13, v7, 8
    vor.vv v3, v12, v13
    vxor.vv v7, v7, v6
    vxor.vv v7, v7, v5
    vxor.vv v7, v7, v4
    vxor.vv v7, v7, v3
    vxor.vv v11, v7, v11
    addi t1, t1, -4
    bne t1, x0, sm4_dec_round_func
    vsetvli t0, a2, e32, m1, ta, ma
    vsseg4e32.v v8, (a0)
    ret
#endif
