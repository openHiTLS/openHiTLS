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

.file	"ecc_msm_riscv64.S"

### Memory 256-bit transpose load in MSM ###
	# void MSM_MEM_LOAD256(uint64_t *nums[8], uint64_t (*limbs)[8])
	# a0	nums
    # a1    limb 0, 1, 2, 3
	.globl	MSM_MEM_LOAD256
	.type	MSM_MEM_LOAD256, @function
	.align	6

MSM_MEM_LOAD256:
	vsetivli    t0, 4, e64, m2
    ld          t0, (a0)
    ld          t1, 8(a0)
    ld          t2, 16(a0)
    vle64.v     v0, (t0)
    ld          t3, 24(a0)
    vle64.v     v2, (t1)
    ld          t4, 32(a0)
	vle64.v     v4, (t2)
    ld          t5, 40(a0)
	vle64.v     v6, (t3)
    ld          t6, 48(a0)
	vle64.v     v8, (t4)
    ld          a2, 56(a0)
	vle64.v     v10, (t5)
	vle64.v     v12, (t6)
	vle64.v     v14, (a2)

    vsetivli    t0, 16, e64, m8
	la			t1, MSM_8_LANE_TRANSPOSE_TABLE_1
	la			t2, MSM_8_LANE_TRANSPOSE_TABLE_2
	vle64.v		v16, (t1)
	addi		t1, a1, 64
	addi		t3, a1, 192
	vrgather.vv v24, v0, v16
	vrgather.vv v0, v8, v16
	vsetivli    t0, 8, e64, m4
	vmv.v.v     v12, v0
	vmv.v.v     v0, v28
	vmv.v.v     v8, v24
	vsetivli    t0, 16, e64, m8
	vle64.v     v16, (t2)
	addi		t2, a1, 128
	vrgather.vv v24, v0, v16
	vrgather.vv v0, v8, v16
	vsetivli    t0, 8, e64, m4
	vse64.v     v0, (a1)
	vse64.v     v4, (t1)
	vse64.v     v24, (t2)
	vse64.v     v28, (t3)
	ret

### Memory 256-bit transpose store in MSM ###
	# void MSM_MEM_STORE256(uint64_t *nums[8], uint64_t (*limbs)[8])
	# a0	nums
	# a1	limbs
	.globl	MSM_MEM_STORE256
	.type	MSM_MEM_STORE256, @function
	.align	6

MSM_MEM_STORE256:
    vsetivli    t0, 8, e64, m4
	addi		t1, a1, 64
	addi		t2, a1, 128
	addi		t3, a1, 192
	vle64.v     v0, (a1)
	vle64.v     v4, (t1)
    la			t1, MSM_8_LANE_TRANSPOSE_TABLE_1_INV
	vle64.v     v8, (t2)
	la			t2, MSM_8_LANE_TRANSPOSE_TABLE_2_INV
	vle64.v     v12, (t3)
	vsetivli    t0, 16, e64, m8
    vle64.v		v16, (t2)
    vrgather.vv v24, v0, v16
	vrgather.vv v0, v8, v16
	vle64.v		v16, (t1)
	vsetivli    t0, 8, e64, m4
	vmv.v.v     v12, v0
	vmv.v.v     v0, v28
	vmv.v.v     v8, v24
	vsetivli    t0, 16, e64, m8
	vrgather.vv v24, v0, v16
	vrgather.vv v0, v8, v16

    vsetivli    t0, 4, e64, m2
    ld          t0,  0(a0)
    ld          t1,  8(a0)
    ld          t2, 16(a0)
    vse64.v     v0, (t0)
    ld          t3, 24(a0)
    vse64.v     v2, (t1)
    ld          t4, 32(a0)
    vse64.v     v4, (t2)
    ld          t5, 40(a0)
    vse64.v     v6, (t3)
    ld          t6, 48(a0)
    vse64.v     v24, (t4)
    ld          a2, 56(a0)
    vse64.v     v26, (t5)
    vse64.v     v28, (t6)
    vse64.v     v30, (a2)
	ret

### Memory 128-bit transpose load in MSM ###
	# void MSM_MEM_LOAD128(uint64_t *nums[8], uint64_t (*limbs)[8])
	# a0	nums
	# a1	limbs
	.globl	MSM_MEM_LOAD128
	.type	MSM_MEM_LOAD128, @function
	.align	6

MSM_MEM_LOAD128:
	vsetivli    t0, 2, e64, m1
    ld          t0, (a0)
    ld          t1, 8(a0)
    ld          t2, 16(a0)
    vle64.v     v0, (t0)
    ld          t3, 24(a0)
    vle64.v     v1, (t1)
    ld          t4, 32(a0)
	vle64.v     v2, (t2)
    ld          t5, 40(a0)
	vle64.v     v3, (t3)
    ld          t6, 48(a0)
	vle64.v     v4, (t4)
    ld          a2, 56(a0)
	vle64.v     v5, (t5)
	vle64.v     v6, (t6)
	vle64.v     v7, (a2)

    la			t1, MSM_8_LANE_TRANSPOSE_TABLE_2
	addi		t2, a1, 64
	vsetivli    t0, 16, e64, m8
	vle64.v		v8, (t1)
	vrgather.vv v16, v0, v8
	vsetivli    t0, 8, e64, m4
	vse64.v     v16, (a1)
	vse64.v     v20, (t2)
	ret

### Memory 128-bit transpose store in MSM ###
	# void MSM_MEM_STORE128(uint64_t *nums[8], uint64_t (*limbs)[8])
	# a0	nums
	# a1	limbs
	.globl	MSM_MEM_STORE128
	.type	MSM_MEM_STORE128, @function
	.align	6

MSM_MEM_STORE128:
    addi		t1, a1, 64
	la			t2, MSM_8_LANE_TRANSPOSE_TABLE_2_INV
	vsetivli    t0, 8, e64, m4
	vle64.v     v8, (a1)
	vle64.v     v12, (t1)
	vsetivli    t0, 16, e64, m8
	vle64.v		v16, (t2)
	vrgather.vv v0, v8, v16

    vsetivli    t0, 4, e64, m2
    ld          t0,  0(a0)
    ld          t1,  8(a0)
    ld          t2, 16(a0)
    vse64.v     v0, (t0)
    ld          t3, 24(a0)
    vse64.v     v1, (t1)
    ld          t4, 32(a0)
    vse64.v     v2, (t2)
    ld          t5, 40(a0)
    vse64.v     v3, (t3)
    ld          t6, 48(a0)
    vse64.v     v4, (t4)
    ld          a2, 56(a0)
    vse64.v     v5, (t5)
    vse64.v     v6, (t6)
    vse64.v     v7, (a2)
	ret

### Set limb to zero in MSM ###
	# void MSM_MEM_SET_ZERO(uint64_t (*limbs)[8], uint32_t len)
	# a0	limb
	# a1	len
	.globl	MSM_MEM_SET_ZERO
	.type	MSM_MEM_SET_ZERO, @function
	.align	6
MSM_MEM_SET_ZERO:
	vsetivli    t0, 8, e64, m4
	slli        t0, a1, 6
	vmv.v.i     v0, 0
	add         t0, a0, t0

	ble         t0, a0, .MSM_MEM_SET_ZERO_END

.MSM_MEM_SET_ZERO_LOOP:
	vse64.v     v0, (a0)
	addi        a0, a0, 64
	blt         a0, t0, .MSM_MEM_SET_ZERO_LOOP

.MSM_MEM_SET_ZERO_END:
	ret

##### Vector Add with Modulus #####
	# void MSM_VV_MOD_ADD(uint64_t result[][8], uint64_t a[][8], uint64_t b[][8], uint64_t N[], int len);
    # a0 = result
    # a1 = a
    # a2 = b
    # a3 = N
    # a4 = len
    # ret: v0 = carry mask
	.globl	MSM_VV_MOD_ADD
	.type	MSM_VV_MOD_ADD, @function
	.align	6

MSM_VV_MOD_ADD:
    slli    a5, a4, 6 # a5: len*64
    vsetivli    t0, 8, e64, m4 # could be better if vl has been set up
    vmv.v.i     v0, 0

    mv      t0, a1 # t0 := &a[i]
    add     t6, a1, a5
    mv      t1, a2 # t1 := &b[i]
    mv      t2, a0 # t2 := &result[i]

    ble     t6, t0, .MSM_VV_MOD_ADD_I_LOOP_END
.MSM_VV_MOD_ADD_I_LOOP:
    vle64.v v8, (t1)
    vle64.v v4, (t0)

    vadc.vvm v12, v4, v8, v0
    addi    t0, t0, 64
    addi    t1, t1, 64

    vse64.v v12, (t2)
    addi    t2, t2, 64
    vmadc.vvm v0, v4, v8, v0

    blt     t0, t6, .MSM_VV_MOD_ADD_I_LOOP
.MSM_VV_MOD_ADD_I_LOOP_END:

    vmnot.m v16, v0
    vmv.v.i v0, 0

    mv      t0, a0 # t0 := &result[i]
    add     t6, a0, a5
    mv      t1, a3 # t1 := &N[i]
    sub     t2, sp, a5 # t2 := &buffer[i]

    ble     t6, t0, .MSM_VV_MOD_ADD_VXSUB_I_LOOP_END
.MSM_VV_MOD_ADD_VXSUB_I_LOOP:
    ld      t3, (t1)
    vle64.v v4, (t0)

    vsbc.vxm v8, v4, t3, v0
    vmsbc.vxm v0, v4, t3, v0
    addi    t0, t0, 64
    addi    t1, t1, 8

    vse64.v v8, (t2)
    addi    t2, t2, 64

    blt     t0, t6, .MSM_VV_MOD_ADD_VXSUB_I_LOOP
.MSM_VV_MOD_ADD_VXSUB_I_LOOP_END:

    vmand.mm   v0, v16, v0

    mv      t0, a0  # t0 := &result[i]
    add     t1, a0, a5
    sub     t2, sp, a5  # t2 := &buffer[i]
    ble     t1, t0, .MSM_VV_MOD_ADD_MERGE_LOOP_END
.MSM_VV_MOD_ADD_MERGE_LOOP:
    vle64.v v4, (t0)
    vle64.v v8, (t2)
    vmerge.vvm  v12, v8, v4, v0
    vse64.v     v12, (t0)

    addi    t0, t0, 64
    addi    t2, t2, 64
    blt     t0, t1, .MSM_VV_MOD_ADD_MERGE_LOOP
.MSM_VV_MOD_ADD_MERGE_LOOP_END:

    ret

##### Vector Sub with Modulus #####
	# void MSM_VV_MOD_SUB(uint64_t result[][8], uint64_t a[][8], uint64_t b[][8], uint64_t N[], int len);
    # a0 = result
    # a1 = a
    # a2 = b
    # a3 = N
    # a4 = len
    # ret: v0 = carry mask
	.globl	MSM_VV_MOD_SUB
	.type	MSM_VV_MOD_SUB, @function
	.align	6

MSM_VV_MOD_SUB:
    slli    a5, a4, 6 # a5: len*64
    vsetivli    t0, 8, e64, m4 # could be better if vl has been set up
    vmv.v.i     v0, 0

    mv      t0, a1 # t0 := &a[i]
    add     t6, a1, a5
    mv      t1, a2 # t1 := &b[i]
    mv      t2, a0 # t2 := &result[i]

    ble     t6, t0, .MSM_VV_MOD_SUB_I_LOOP_END
.MSM_VV_MOD_SUB_I_LOOP:
    vle64.v v8, (t1)
    vle64.v v4, (t0)

    vsbc.vvm v12, v4, v8, v0
    addi    t0, t0, 64

    vmsbc.vvm v0, v4, v8, v0
    addi    t1, t1, 64

    vse64.v v12, (t2)

    addi    t2, t2, 64
    blt     t0, t6, .MSM_VV_MOD_SUB_I_LOOP
.MSM_VV_MOD_SUB_I_LOOP_END:


    mv      t0, a0  # t0 := &result[i]
    add     t1, a0, a5
    mv      t2, a3
    vmnot.m v20, v0
    vmv.v.i v16, 0
    ble     t1, t0, .MSM_VV_MOD_SUB_MERGE_LOOP_END
.MSM_VV_MOD_SUB_MERGE_LOOP:
    vle64.v v4, (t0)
    ld      t3, (t2)

    vmmv.m  v0, v16
    vadc.vxm    v8, v4, t3, v0
    vmadc.vxm   v16, v4, t3, v0
    vmmv.m  v0, v20
    vmerge.vvm  v12, v8, v4, v0
    addi    t2, t2, 8
    vse64.v     v12, (t0)

    addi    t0, t0, 64
    blt     t0, t1, .MSM_VV_MOD_SUB_MERGE_LOOP
.MSM_VV_MOD_SUB_MERGE_LOOP_END:

    ret

##### Vector Montgomery Multiply (CIOS) #####
	# void MSM_VV_MOD_MUL(uint64_t result[][8], uint64_t a[][8], uint64_t b[][8], uint64_t N[], uint64_t N0, int len);
    # a0 = sum
    # a1 = a
    # a2 = b
    # a3 = N
    # a4 = N0
    # a5 = len
	.globl	MSM_VV_MOD_MUL
	.type	MSM_VV_MOD_MUL, @function
	.align	6

MSM_VV_MOD_MUL:
    beq     a5, zero, .MSM_VV_MOD_MUL_RET

    slli    a6,a5, 6 # a6: len*64
    slli    t0,a5, 7
    add     a7,t0,a6 # a7: (len*3)*64
    sub     sp,sp,a7 # T[2*len][8], buffer[len][8]

    #init
    vsetivli    t0, 8, e64, m4
    vmv.v.i     v28, 0

    mv      t0, sp
    add     t1, sp, a6 # only T[0..(len-1)] is enough

.MSM_VV_MOD_MUL_MEMSET_LOOP:
    vse64.v     v28, (t0)

    addi    t0, t0, 64
    blt     t0, t1, .MSM_VV_MOD_MUL_MEMSET_LOOP

    mv      t3, zero
    mv      t1, a1 # t1 := &a[i]
    add     t5, a1, a6
    slli    a1, a5, 3
.MSM_VV_MOD_MUL_I_LOOP:
    vle64.v v4, (t1)
    vmv.v.i v20, 0
    vmv.v.i v0, 0

    mv      t2, a2 # t2 := &b[j]
    add     t0, sp, t3 # t0 := &T[i+j]
    add     a5, a2, a6
.MSM_VV_MOD_MUL_J_LOOP:

    vle64.v v8, (t2)
    vle64.v v12, (t0)

    vadc.vvm v16, v20, v12, v0
    vmadc.vvm v0, v20, v12, v0
    vmulhu.vv v12, v4, v8

    vmul.vv v8, v4, v8
    vadc.vxm v24, v12, zero, v0

    vmv.v.i v0, 0
    vadc.vvm v12, v16, v8, v0
    vmadc.vvm v0, v16, v8, v0

    addi    t2, t2, 64

    vse64.v v12, (t0)
    vadc.vxm v20, v24, zero, v0

    addi    t0, t0, 64
    vmadc.vxm v0, v24, zero, v0

    blt     t2, a5, .MSM_VV_MOD_MUL_J_LOOP

    vadc.vxm v16, v20, zero, v0
    vmadc.vxm v0, v20, zero, v0
    vse64.v v16, (t0)

    add     t0, sp, t3 # t0 := &T[i+j]
    mv      t2, a3 # t2 := &N[j]

    vmv.v.i v20, 0
    vmv.v.i v0, 0
    vle64.v v12, (t0) # v12 := T[i+0]

    add     t6, a3, a1
    vmul.vx v4, v12, a4 # m := (T[i+0] * N0') mod 2^64
.MSM_VV_MOD_MUL_M_LOOP:

    ld      t4, (t2)
    vmv.v.x v8, t4

    vadc.vvm v16, v20, v12, v0
    vmadc.vvm v0, v20, v12, v0
    vmulhu.vv v12, v4, v8

    vmul.vv v8, v4, v8
    vadc.vxm v24, v12, zero, v0
    # ca is always zero

    vmv.v.i v0, 0
    addi    t2, t2, 8
    vadc.vvm v12, v16, v8, v0
    vmadc.vvm v0, v16, v8, v0

    vadc.vxm v20, v24, zero, v0
    vse64.v v12, (t0)
    addi    t0, t0, 64

    # vmadc.vxm v0, v24, zero, v0 # ca is always zero
    vmv.v.i v0, 0

    vle64.v v12, (t0)
    blt     t2, t6, .MSM_VV_MOD_MUL_M_LOOP

    addi    t1, t1, 64
    vadc.vvm v16, v20, v12, v0
    vmadc.vvm v24, v20, v12, v0
    vmmv.m  v0, v28

    addi    t3, t3, 64

    vadc.vxm v12, v16, zero, v0
    vmmv.m  v28, v24
    vse64.v v12, (t0)

    blt     t1, t5, .MSM_VV_MOD_MUL_I_LOOP

    # CALL VXSUB
    vmnot.m v28, v28
    slli    t0, a6, 1 # t0 := (2*len)*64
    mv      a5, a0
    mv      a4, ra
    mv      a2, a3     # a2 := N
    srli    a3, a6, 6  # a3 := len
    add     a1, sp, a6 # a1 := &T[4]
    add     a0, sp, t0 # a2 := buffer
    # v28 and all ax should be unchanged
    jal     ra, MSM_VX_SUB
    # ret carry mask in v0


    add     t0, sp, a6 # t0 := &T[len]

    mv      ra, a4
    vmand.mm   v0, v28, v0

    mv      t1, a5     # t1 := sum
    add     t2, t0, a6
    add     t3, t0, a6 # t3 := buffer

.MSM_VV_MOD_MUL_MEMCPY_LOOP:
    vle64.v     v4, (t0)
    vle64.v     v8, (t3)
    addi    t0, t0, 64
    addi    t3, t3, 64
    vmerge.vvm  v12, v8, v4, v0
    vse64.v     v12, (t1)
    addi    t1, t1, 64

    blt     t0, t2, .MSM_VV_MOD_MUL_MEMCPY_LOOP

    add     sp,sp,a7 # free T, buffer
.MSM_VV_MOD_MUL_RET:
    ret

##### Vector Montgomery Multiply (CIOS) #####
	# void MSM_VX_MOD_MUL(uint64_t result[][8], uint64_t a[][8], uint64_t b[8], uint64_t N[], uint64_t N0, int len);
    # a0 = sum
    # a1 = a
    # a2 = b
    # a3 = N
    # a4 = N0
    # a5 = len
	.globl	MSM_VX_MOD_MUL
	.type	MSM_VX_MOD_MUL, @function
	.align	6

MSM_VX_MOD_MUL:
    beq     a5, zero, .MSM_VX_MONT_RET

    slli    a6,a5, 6 # a6: len*64
    slli    t0,a5, 7
    add     a7,t0,a6 # a7: (len*3)*64
    sub     sp,sp,a7 # T[2*len][8], buffer[len][8]

    #init
    vsetivli    t0, 8, e64, m4
    vmv.v.i     v28, 0

    mv      t0, sp
    add     t1, sp, a6 # only T[0..(len-1)] is enough

.MSM_VX_MOD_MUL_MEMSET_LOOP:
    vse64.v     v28, (t0)

    addi    t0, t0, 64
    blt     t0, t1, .MSM_VX_MOD_MUL_MEMSET_LOOP

    mv      t3, zero
    mv      t1, a1 # t1 := &a[i]
    add     t5, a1, a6
    slli    a1, a5, 3
.MSM_VX_MOD_MUL_I_LOOP:
    vle64.v v4, (t1)
    vmv.v.i v20, 0
    vmv.v.i v0, 0

    mv      t2, a2 # t2 := &b[j]
    add     t0, sp, t3 # t0 := &T[i+j]
    add     a5, a2, a1
.MSM_VX_MOD_MUL_J_LOOP:

    ld      t4, (t2)
    vle64.v v12, (t0)

    vadc.vvm v16, v20, v12, v0
    vmadc.vvm v0, v20, v12, v0
    vmulhu.vx v12, v4, t4

    vmul.vx v8, v4, t4
    vadc.vxm v24, v12, zero, v0

    vmv.v.i v0, 0
    vadc.vvm v12, v16, v8, v0
    vmadc.vvm v0, v16, v8, v0

    addi    t2, t2, 8

    vse64.v v12, (t0)
    vadc.vxm v20, v24, zero, v0

    addi    t0, t0, 64
    vmadc.vxm v0, v24, zero, v0

    blt     t2, a5, .MSM_VX_MOD_MUL_J_LOOP

    vadc.vxm v16, v20, zero, v0
    vmadc.vxm v0, v20, zero, v0
    vse64.v v16, (t0)

    add     t0, sp, t3 # t0 := &T[i+j]
    mv      t2, a3 # t2 := &N[j]

    vmv.v.i v20, 0
    vmv.v.i v0, 0
    vle64.v v12, (t0) # v12 := T[i+0]

    add     t6, a3, a1
    vmul.vx v4, v12, a4 # m := (T[i+0] * N0') mod 2^64
.MSM_VX_MOD_MUL_M_LOOP:

    ld      t4, (t2)
    vmv.v.x v8, t4

    vadc.vvm v16, v20, v12, v0
    vmadc.vvm v0, v20, v12, v0
    vmulhu.vv v12, v4, v8

    vmul.vv v8, v4, v8
    vadc.vxm v24, v12, zero, v0
    # ca is always zero

    vmv.v.i v0, 0
    addi    t2, t2, 8
    vadc.vvm v12, v16, v8, v0
    vmadc.vvm v0, v16, v8, v0

    vadc.vxm v20, v24, zero, v0
    vse64.v v12, (t0)
    addi    t0, t0, 64

    # vmadc.vxm v0, v24, zero, v0 # ca is always zero
    vmv.v.i v0, 0

    vle64.v v12, (t0)
    blt     t2, t6, .MSM_VX_MOD_MUL_M_LOOP

    addi    t1, t1, 64
    vadc.vvm v16, v20, v12, v0
    vmadc.vvm v24, v20, v12, v0
    vmmv.m  v0, v28

    addi    t3, t3, 64

    vadc.vxm v12, v16, zero, v0
    vmmv.m  v28, v24
    vse64.v v12, (t0)

    blt     t1, t5, .MSM_VX_MOD_MUL_I_LOOP

    # CALL VXSUB
    vmnot.m v28, v28
    slli    t0, a6, 1 # t0 := (2*len)*64
    mv      a5, a0
    mv      a4, ra
    mv      a2, a3     # a2 := N
    srli    a3, a6, 6  # a3 := len
    add     a1, sp, a6 # a1 := &T[4]
    add     a0, sp, t0 # a2 := buffer
    # v28 and all ax should be unchanged
    jal     ra, MSM_VX_SUB
    # ret carry mask in v0


    add     t0, sp, a6 # t0 := &T[len]

    mv      ra, a4
    vmand.mm   v0, v28, v0

    mv      t1, a5     # t1 := sum
    add     t2, t0, a6
    add     t3, t0, a6 # t3 := buffer

.MSM_VX_MOD_MUL_MEMCPY_LOOP:
    vle64.v     v4, (t0)
    vle64.v     v8, (t3)
    addi    t0, t0, 64
    addi    t3, t3, 64
    vmerge.vvm  v12, v8, v4, v0
    vse64.v     v12, (t1)
    addi    t1, t1, 64

    blt     t0, t2, .MSM_VX_MOD_MUL_MEMCPY_LOOP

    add     sp,sp,a7 # free T, buffer
.MSM_VX_MONT_RET:
    ret

##### Vector-Scalar Subtraction #####
	# void MSM_VX_SUB(uint64_t result[][8], uint64_t a[][8], uint64_t b[], int len);
    # a0 = result
    # a1 = a
    # a2 = b
    # a3 = len
    # ret: v0 = carry mask
	.globl	MSM_VX_SUB
	.type	MSM_VX_SUB, @function
	.align	6

MSM_VX_SUB:
    slli    t5,a3, 6 # t5: len*64
    vsetivli    t0, 8, e64, m4 # could be better if vl has been set up
    vmv.v.i     v0, 0

    mv      t0, a1 # t0 := &a[i]
    add     t6, a1, t5
    mv      t1, a2 # t1 := &b[i]
    mv      t2, a0 # t2 := &sum[i]

    ble     t6, t0, .MSM_VX_SUB_I_LOOP_END
.MSM_VX_SUB_I_LOOP:
    ld      t3, (t1)
    vle64.v v4, (t0)
    addi    t1, t1, 8

    vsbc.vxm v8, v4, t3, v0
    addi    t0, t0, 64

    vse64.v v8, (t2)
    addi    t2, t2, 64
    vmsbc.vxm v0, v4, t3, v0


    blt     t0, t6, .MSM_VX_SUB_I_LOOP
.MSM_VX_SUB_I_LOOP_END:

    # return carry mask in v0
    ret

.section .rodata
MSM_8_LANE_TRANSPOSE_TABLE_1:
.quad   0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15
MSM_8_LANE_TRANSPOSE_TABLE_2:
.quad   0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15
MSM_8_LANE_TRANSPOSE_TABLE_1_INV:
.quad   0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15
MSM_8_LANE_TRANSPOSE_TABLE_2_INV:
.quad   0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15
