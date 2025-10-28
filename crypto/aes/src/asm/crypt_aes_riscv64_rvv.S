#include "hitls_build.h"
#ifdef HITLS_CRYPTO_AES
.file "crypt_aes_riscv64_rvv.S"
.text
.globl RVVAddRoundKeyAndSubBytes
RVVAddRoundKeyAndSubBytes:
    slli t1, a2, 4
    add t1, t1, a1
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vle8.v v0, (a0)
    vle8.v v1, (t1)
    vxor.vv v0, v0, v1
    vluxei8.v v0, (a3), v0
    vse8.v v0, (a0)
    ret

.globl RVVAddRoundKeyAndInvSubBytes
RVVAddRoundKeyAndInvSubBytes:
    slli t1, a2, 4
    add t1, t1, a1
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vle8.v v0, (a0)
    vle8.v v1, (t1)
    vxor.vv v0, v0, v1
    vluxei8.v v0, (a3), v0
    vse8.v v0, (a0)
    ret

.globl RVVEncSingleRound
RVVEncSingleRound:
    slli t1, a2, 4
    add t1, t1, a1
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vle8.v v0, (a0)
    vle8.v v1, (t1)
    vxor.vv v0, v0, v1
    vluxei8.v v8, (a3), v0
    vmv.v.v v9, v8
    li t4, 32
    csrr t1, vlenb
    li t2, 0x00000020
    bne t1, t2, vlen_aes_enc_eq_16 # rvv 256
    
    vsetvli t0, t4, e8, m1, ta, ma
    vslideup.vi v8, v9, 16
    vslideup.vi v6, v8, 3
    vslideup.vi v4, v8, 6
    vslideup.vi v2, v8, 9
    li t4, 4
    vsetvli t0, t4, e32, m1, tu, mu
    li t1, 0xff000000
    vand.vx v2, v2, t1
    vand.vx v4, v4, t1
    vand.vx v6, v6, t1
    vand.vx v8, v8, t1
    j rvv_aes_enc_next
    
vlen_aes_enc_eq_16:
    vsetvli t0, t4, e8, m2, ta, ma
    vslideup.vi v6, v8, 13
    vslideup.vi v4, v8, 10
    vslideup.vi v2, v8, 7
    li t4, 4
    vsetvli t0, t4, e32, m1, tu, mu
    li t1, 0xff000000
    vand.vx v2, v3, t1
    vand.vx v4, v5, t1
    vand.vx v6, v7, t1
    vand.vx v8, v8, t1
    
rvv_aes_enc_next:
    li t1, 0x1b000000
    li t4, 0x7f000000
    vmsgtu.vx v0, v8, t4
    vsll.vi v1, v8, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v6, t4
    vsll.vi v3, v6, 1
    vxor.vx v3, v3, t1, v0.t
    vxor.vv v3, v3, v6
    vxor.vv v3, v3, v4
    vxor.vv v3, v3, v2
    vxor.vv v10, v3, v1
    vmsgtu.vx v0, v6, t4
    vsll.vi v1, v6, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v4, t4
    vsll.vi v3, v4, 1
    vxor.vx v3, v3, t1, v0.t
    vxor.vv v3, v3, v4
    vxor.vv v3, v3, v2
    vxor.vv v3, v3, v8
    vxor.vv v11, v3, v1
    vmsgtu.vx v0, v4, t4
    vsll.vi v1, v4, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v2, t4
    vsll.vi v3, v2, 1
    vxor.vx v3, v3, t1, v0.t
    vxor.vv v3, v3, v2
    vxor.vv v3, v3, v8
    vxor.vv v3, v3, v6
    vxor.vv v12, v3, v1
    vmsgtu.vx v0, v2, t4
    vsll.vi v1, v2, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v8, t4
    vsll.vi v3, v8, 1
    vxor.vx v3, v3, t1, v0.t
    vxor.vv v3, v3, v8
    vxor.vv v3, v3, v6
    vxor.vv v3, v3, v4
    vxor.vv v13, v3, v1
    vsrl.vi v11, v11, 8
    vsrl.vi v12, v12, 16
    vsrl.vi v13, v13, 24
    vxor.vv v10, v10, v11
    vxor.vv v10, v10, v12
    vxor.vv v10, v10, v13
    vse32.v v10, (a0)
    ret

.globl RVVDecSingleRound
RVVDecSingleRound:
    slli t1, a2, 4
    add t1, t1, a1
    li t4, 16
    vsetvli t0, t4, e8, m1, ta, ma
    vle8.v v0, (a0)
    vle8.v v1, (t1)
    vxor.vv v0, v0, v1
    vluxei8.v v8, (a3), v0
    vmv.v.v v9, v8
    li t4, 32
    csrr t1, vlenb
    li t2, 0x00000020
    bne t1, t2, vlen_aes_dec_eq_16 # rvv 256
    
    vsetvli t0, t4, e8, m1, ta, ma
    vslideup.vi v8, v9, 16
    vslideup.vi v6, v8, 11
    vslideup.vi v4, v8, 6
    vslideup.vi v2, v8, 1
    li t4, 4
    vsetvli t0, t4, e32, m1, tu, mu
    li t1, 0xff000000
    vand.vx v2, v2, t1
    vand.vx v4, v4, t1
    vand.vx v6, v6, t1
    vand.vx v8, v8, t1
    j rvv_aes_dec_next
    
vlen_aes_dec_eq_16:
    vsetvli t0, t4, e8, m2, tu, mu
    vslideup.vi v6, v8, 5
    vslideup.vi v4, v8, 10
    vslideup.vi v2, v8, 15
    li t4, 4
    vsetvli t0, t4, e32, m1, tu, mu
    li t1, 0xff000000
    vand.vx v2, v3, t1
    vand.vx v4, v5, t1
    vand.vx v6, v7, t1
    vand.vx v8, v8, t1
    
rvv_aes_dec_next:
    li t1, 0x1b000000
    li t4, 0x7f000000
    vmsgtu.vx v0, v8, t4
    vsll.vi v1, v8, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v1, t4
    vsll.vi v3, v1, 1
    vxor.vx v3, v3, t1, v0.t
    vmsgtu.vx v0, v3, t4
    vsll.vi v5, v3, 1
    vxor.vx v5, v5, t1, v0.t
    vxor.vv v5, v5, v1
    vxor.vv v9, v5, v3
    vmsgtu.vx v0, v6, t4
    vsll.vi v1, v6, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v1, t4
    vsll.vi v3, v1, 1
    vxor.vx v3, v3, t1, v0.t
    vmsgtu.vx v0, v3, t4
    vsll.vi v5, v3, 1
    vxor.vx v5, v5, t1, v0.t
    vxor.vv v5, v5, v6
    vxor.vv v10, v5, v1
    vmsgtu.vx v0, v4, t4
    vsll.vi v1, v4, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v1, t4
    vsll.vi v3, v1, 1
    vxor.vx v3, v3, t1, v0.t
    vmsgtu.vx v0, v3, t4
    vsll.vi v5, v3, 1
    vxor.vx v5, v5, t1, v0.t
    vxor.vv v5, v5, v4
    vxor.vv v11, v5, v3
    vmsgtu.vx v0, v2, t4
    vsll.vi v1, v2, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v1, t4
    vsll.vi v3, v1, 1
    vxor.vx v3, v3, t1, v0.t
    vmsgtu.vx v0, v3, t4
    vsll.vi v5, v3, 1
    vxor.vx v5, v5, t1, v0.t
    vxor.vv v12, v5, v2
    vxor.vv v13, v12, v11
    vxor.vv v13, v13, v10
    vxor.vv v13, v13, v9
    vmsgtu.vx v0, v6, t4
    vsll.vi v1, v6, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v1, t4
    vsll.vi v3, v1, 1
    vxor.vx v3, v3, t1, v0.t
    vmsgtu.vx v0, v3, t4
    vsll.vi v5, v3, 1
    vxor.vx v5, v5, t1, v0.t
    vxor.vv v5, v5, v1
    vxor.vv v9, v5, v3
    vmsgtu.vx v0, v4, t4
    vsll.vi v1, v4, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v1, t4
    vsll.vi v3, v1, 1
    vxor.vx v3, v3, t1, v0.t
    vmsgtu.vx v0, v3, t4
    vsll.vi v5, v3, 1
    vxor.vx v5, v5, t1, v0.t
    vxor.vv v5, v5, v4
    vxor.vv v10, v5, v1
    vmsgtu.vx v0, v2, t4
    vsll.vi v1, v2, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v1, t4
    vsll.vi v3, v1, 1
    vxor.vx v3, v3, t1, v0.t
    vmsgtu.vx v0, v3, t4
    vsll.vi v5, v3, 1
    vxor.vx v5, v5, t1, v0.t
    vxor.vv v5, v5, v2
    vxor.vv v11, v5, v3
    vmsgtu.vx v0, v8, t4
    vsll.vi v1, v8, 1
    vxor.vx v1, v1, t1, v0.t
    vmsgtu.vx v0, v1, t4
    vsll.vi v3, v1, 1
    vxor.vx v3, v3, t1, v0.t
    vmsgtu.vx v0, v3, t4
    vsll.vi v5, v3, 1
    vxor.vx v5, v5, t1, v0.t
    vxor.vv v12, v5, v8
    vxor.vv v14, v12, v11
    vxor.vv v14, v14, v10
    vxor.vv v14, v14, v9
    vmsgtu.vx v0, v4, t4
    vsll.vi v1, v4, 1
    vxor.vx v1, v1, t1, v0.t
    ret
#endif
