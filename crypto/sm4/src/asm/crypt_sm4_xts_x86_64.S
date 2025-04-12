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
#ifdef HITLS_CRYPTO_SM4

#include "crypt_sm4_modes_macro_x86_64.s"

.file   "crypt_sm4_xts_x86_64.S"
.text

.set	X0,%ymm0
.set    X1,%ymm1
.set 	X2,%ymm2
.set	X3,%ymm3

.set	T0,%ymm4
.set	T1,%ymm5
.set	T2,%ymm6

.set	Y0,%ymm7
.set    Y1,%ymm8
.set 	Y2,%ymm9
.set	Y3,%ymm10

.set	V0,%ymm11
.set	V1,%ymm12
.set	V2,%ymm13

.set	RK,%rdx

.set	XORMASK_2,%ymm14
.set	LOADMASK_2,T0
.set 	STOREMASK_2,T1
.set 	SHUFFLEMASK_2,T2

.set	AES_MASK, %ymm15
.set	AND_MASK, %ymm14
.set    ENDIAN_MASK, %xmm14
.set	G_TMP_2,%ymm15

.macro  GALOIS_FIELD_MUL    Idx
    #r8 = t[0], r10 = t[0]
    #r9 = t[1], r11 = t[1]

    movq    %r8,%r10
    movq    %r9,%r11

    shlq    $63,%r10
    shrq    $1,%r9
    addq    %r10,%r9

    shrq    $1,%r8
    andq    $1,%r11
    movq    $0xe1,%r10
    shlq    $56, %r10
    imulq   %r10,%r11
    xorq    %r11,%r8

    movbe   %r8,\Idx(%rcx)
    movbe   %r9,\Idx+8(%rcx)

.endm

.macro GALOIS_FIELD_MUL_16_INNER
	GALOIS_FIELD_MUL 16

	#T2:T1->T2
	GALOIS_FIELD_MUL 32

	#T3:T2->T3
	GALOIS_FIELD_MUL 48

	#T4:T3->T4
	GALOIS_FIELD_MUL 64

	#T5:T4->T5
	GALOIS_FIELD_MUL 80

	#T6:T5->T6
	GALOIS_FIELD_MUL 96

	#T7:T6->T7
	GALOIS_FIELD_MUL 112

	#T8:T7->T8
	GALOIS_FIELD_MUL 128

	#T9:T8->T9
	GALOIS_FIELD_MUL 144

	#T10:T9->T10
	GALOIS_FIELD_MUL 160

	#T11:T10->T11
	GALOIS_FIELD_MUL 176

	#T12:T11->T12
	GALOIS_FIELD_MUL 192

	#T13:T12->T13
	GALOIS_FIELD_MUL 208

	#T14:T13->T14
	GALOIS_FIELD_MUL 224

	#T15:T14->T15
	GALOIS_FIELD_MUL 240
.endm

.macro GALOIS_FIELD_MUL_16  Idx
    movbe   \Idx(%rcx),%r8
    movbe   \Idx+8(%rcx),%r9

    #T0:T15->T0
    GALOIS_FIELD_MUL 0
    GALOIS_FIELD_MUL_16_INNER
.endm

.macro GALOIS_FIELD_MUL_16_1st  Idx
    movbe   \Idx(%rcx),%r8
    movbe   \Idx+8(%rcx),%r9
    GALOIS_FIELD_MUL_16_INNER
.endm


.macro SM4_XTS_16_EN_INNER
    #Prepare Mask
	vmovdqa		4096(%rax), XORMASK_2
	vmovdqa		32+4096(%rax), SHUFFLEMASK_2
	vmovdqa		64+4096(%rax), LOADMASK_2

	subq		$256, %rsp

	vmovdqu		(%rsi),X0
	vmovdqu		32(%rsi),X1
	vmovdqu		64(%rsi),X2
	vmovdqu		96(%rsi),X3

	vmovdqu		128(%rsi),Y0
	vmovdqu		128+32(%rsi),Y1
	vmovdqu		128+64(%rsi),Y2
	vmovdqu		128+96(%rsi),Y3

	vpxor		(%rcx),X0,X0
	vpxor		32(%rcx),X1,X1
	vpxor		64(%rcx),X2,X2
	vpxor		96(%rcx),X3,X3

	vpxor		128(%rcx),Y0,Y0
	vpxor		128+32(%rcx),Y1,Y1
	vpxor		128+64(%rcx),Y2,Y2
	vpxor		128+96(%rcx),Y3,Y3

	vmovdqu		X0,(%rsp)
	vmovdqu		X1,32(%rsp)
	vmovdqu		X2,64(%rsp)
	vmovdqu		X3,96(%rsp)

	vmovdqu		Y0,128(%rsp)
	vmovdqu		Y1,128+32(%rsp)
	vmovdqu		Y2,128+64(%rsp)
	vmovdqu		Y3,128+96(%rsp)

	#Load Data
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,0(%rsp,LOADMASK_2,4),X0
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,4(%rsp,LOADMASK_2,4),X1
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,8(%rsp,LOADMASK_2,4),X2
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,12(%rsp,LOADMASK_2,4),X3

	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+0(%rsp,LOADMASK_2,4),Y0
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+4(%rsp,LOADMASK_2,4),Y1
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+8(%rsp,LOADMASK_2,4),Y2
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+12(%rsp,LOADMASK_2,4),Y3

	vpshufb		SHUFFLEMASK_2,X0,X0
	vpshufb		SHUFFLEMASK_2,X1,X1
	vpshufb		SHUFFLEMASK_2,X2,X2
	vpshufb		SHUFFLEMASK_2,X3,X3

	vpshufb		SHUFFLEMASK_2,Y0,Y0
	vpshufb		SHUFFLEMASK_2,Y1,Y1
	vpshufb		SHUFFLEMASK_2,Y2,Y2
	vpshufb		SHUFFLEMASK_2,Y3,Y3

	addq		$256, %rsp

	vmovdqa		128+4096(%rax), AES_MASK
	vmovdqa		288+4096(%rax), AND_MASK
	#ROUNDS
	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 0
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 4
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 8
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 12

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 16
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 20
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 24
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 28

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 32
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 36
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 40
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 44

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 48
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 52
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 56
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 60

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 64
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 68
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 72
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 76

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 80
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 84
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 88
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 92

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 96
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 100
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 104
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 108

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 112
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 116
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 120
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 124

	#Store Result
	subq		$256,%rsp

	#Get Address
	leaq	SBOX4X_MASK(%rip), %rax

	#Prepare Mask
	vmovdqa		32+4096(%rax), SHUFFLEMASK_2
	vmovdqa		96+4096(%rax), STOREMASK_2

	vpshufb		SHUFFLEMASK_2,X0,X0
	vpshufb		SHUFFLEMASK_2,X1,X1
	vpshufb		SHUFFLEMASK_2,X2,X2
	vpshufb		SHUFFLEMASK_2,X3,X3

	vpshufb		SHUFFLEMASK_2,Y0,Y0
	vpshufb		SHUFFLEMASK_2,Y1,Y1
	vpshufb		SHUFFLEMASK_2,Y2,Y2
	vpshufb		SHUFFLEMASK_2,Y3,Y3

	vmovdqu		X3,0(%rsp)
	vmovdqu		X2,32(%rsp)
	vmovdqu		X1,64(%rsp)
	vmovdqu		X0,96(%rsp)

	vmovdqu		Y3,128+0(%rsp)
	vmovdqu		Y2,128+32(%rsp)
	vmovdqu		Y1,128+64(%rsp)
	vmovdqu		Y0,128+96(%rsp)

	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,0(%rsp,STOREMASK_2,4),X0
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,8(%rsp,STOREMASK_2,4),X1
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,16(%rsp,STOREMASK_2,4),X2
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,24(%rsp,STOREMASK_2,4),X3

	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+0(%rsp,STOREMASK_2,4),Y0
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+8(%rsp,STOREMASK_2,4),Y1
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+16(%rsp,STOREMASK_2,4),Y2
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+24(%rsp,STOREMASK_2,4),Y3

	vpxor		(%rcx),X0,X0
	vpxor		32(%rcx),X1,X1
	vpxor		64(%rcx),X2,X2
	vpxor		96(%rcx),X3,X3

	vpxor		128(%rcx),Y0,Y0
	vpxor		128+32(%rcx),Y1,Y1
	vpxor		128+64(%rcx),Y2,Y2
	vpxor		128+96(%rcx),Y3,Y3


	vmovdqu		X0,0(%rdi)
	vmovdqu		X1,32(%rdi)
	vmovdqu		X2,64(%rdi)
	vmovdqu		X3,96(%rdi)

	vmovdqu		Y0,128+0(%rdi)
	vmovdqu		Y1,128+32(%rdi)
	vmovdqu		Y2,128+64(%rdi)
	vmovdqu		Y3,128+96(%rdi)

	addq		$256,%rsp

	vpxor		X0,X0,X0
	vpxor		X1,X1,X1
	vpxor		X2,X2,X2
	vpxor		X3,X3,X3

	vpxor		T0,T0,T0
	vpxor		T1,T1,T1

	vpxor		Y0,Y0,Y0
	vpxor		Y1,Y1,Y1
	vpxor		Y2,Y2,Y2
	vpxor		Y3,Y3,Y3

	vpxor		V0,V0,V0
	vpxor		V1,V1,V1
.endm

############################################################################################################################


	#void SM4_XTS_16_EncryptBlock1st(uint8_t* cipher, uint8_t* plain, unsigned int* ecb_rk, uint8_t* T);
	#cipher		%rdi
	#plain		%rsi
	#rk			%rdx
	#T			%rcx

	.globl	SM4_XTS_16_EncryptBlock1st
	.type	SM4_XTS_16_EncryptBlock1st, @function
	.align	64

SM4_XTS_16_EncryptBlock1st:
	#Get Address
	leaq	SBOX4X_MASK(%rip), %rax

	#compute tweak
	GALOIS_FIELD_MUL_16_1st 0
    SM4_XTS_16_EN_INNER

	ret
	.size	SM4_XTS_16_EncryptBlock1st, .-SM4_XTS_16_EncryptBlock1st


	#void SM4_XTS_16_EncryptBlock(uint8_t* cipher, uint8_t* plain, unsigned int* ecb_rk, uint8_t* T);
	#cipher		%rdi
	#plain		%rsi
	#rk			%rdx
	#T		%rcx

	.globl	SM4_XTS_16_EncryptBlock
	.type	SM4_XTS_16_EncryptBlock, @function
	.align	64

SM4_XTS_16_EncryptBlock:
	#Get Address
	leaq	SBOX4X_MASK(%rip), %rax

	#compute tweak
	GALOIS_FIELD_MUL_16 240
	SM4_XTS_16_EN_INNER

	ret
	.size	SM4_XTS_16_EncryptBlock, .-SM4_XTS_16_EncryptBlock


.macro SM4_XTS_16_DE_INNER
    #Prepare Mask
	vmovdqa		4096(%rax), XORMASK_2
	vmovdqa		32+4096(%rax), SHUFFLEMASK_2
	vmovdqa		64+4096(%rax), LOADMASK_2

	subq		$256, %rsp

	vmovdqu		(%rsi),X0
	vmovdqu		32(%rsi),X1
	vmovdqu		64(%rsi),X2
	vmovdqu		96(%rsi),X3

	vmovdqu		128(%rsi),Y0
	vmovdqu		128+32(%rsi),Y1
	vmovdqu		128+64(%rsi),Y2
	vmovdqu		128+96(%rsi),Y3

	vpxor		(%rcx),X0,X0
	vpxor		32(%rcx),X1,X1
	vpxor		64(%rcx),X2,X2
	vpxor		96(%rcx),X3,X3

	vpxor		128(%rcx),Y0,Y0
	vpxor		128+32(%rcx),Y1,Y1
	vpxor		128+64(%rcx),Y2,Y2
	vpxor		128+96(%rcx),Y3,Y3

	vmovdqu		X0,(%rsp)
	vmovdqu		X1,32(%rsp)
	vmovdqu		X2,64(%rsp)
	vmovdqu		X3,96(%rsp)

	vmovdqu		Y0,128(%rsp)
	vmovdqu		Y1,128+32(%rsp)
	vmovdqu		Y2,128+64(%rsp)
	vmovdqu		Y3,128+96(%rsp)

	#Load Data
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,0(%rsp,LOADMASK_2,4),X0
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,4(%rsp,LOADMASK_2,4),X1
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,8(%rsp,LOADMASK_2,4),X2
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,12(%rsp,LOADMASK_2,4),X3

	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+0(%rsp,LOADMASK_2,4),Y0
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+4(%rsp,LOADMASK_2,4),Y1
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+8(%rsp,LOADMASK_2,4),Y2
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+12(%rsp,LOADMASK_2,4),Y3

	vpshufb		SHUFFLEMASK_2,X0,X0
	vpshufb		SHUFFLEMASK_2,X1,X1
	vpshufb		SHUFFLEMASK_2,X2,X2
	vpshufb		SHUFFLEMASK_2,X3,X3

	vpshufb		SHUFFLEMASK_2,Y0,Y0
	vpshufb		SHUFFLEMASK_2,Y1,Y1
	vpshufb		SHUFFLEMASK_2,Y2,Y2
	vpshufb		SHUFFLEMASK_2,Y3,Y3

	addq		$256, %rsp


	vmovdqa		128+4096(%rax), AES_MASK
	vmovdqa		288+4096(%rax), AND_MASK
	#ROUNDS
	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 124
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 120
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 116
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 112

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 108
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 104
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 100
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 96

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 92
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 88
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 84
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 80

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 76
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 72
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 68
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 64

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 60
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 56
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 52
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 48

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 44
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 40
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 36
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 32

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 28
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 24
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 20
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 16

	SM4_AVX2_AES_2_ROUND	X0 X1 X2 X3 Y0 Y1 Y2 Y3 RK 12
	SM4_AVX2_AES_2_ROUND 	X1 X2 X3 X0 Y1 Y2 Y3 Y0 RK 8
	SM4_AVX2_AES_2_ROUND	X2 X3 X0 X1 Y2 Y3 Y0 Y1 RK 4
	SM4_AVX2_AES_2_ROUND  	X3 X0 X1 X2 Y3 Y0 Y1 Y2 RK 0


	#Store Result
	subq		$256,%rsp

	#Get Address
	leaq	SBOX4X_MASK(%rip), %rax

	#Prepare Mask
	vmovdqa		32+4096(%rax), SHUFFLEMASK_2
	vmovdqa		96+4096(%rax), STOREMASK_2

	vpshufb		SHUFFLEMASK_2,X0,X0
	vpshufb		SHUFFLEMASK_2,X1,X1
	vpshufb		SHUFFLEMASK_2,X2,X2
	vpshufb		SHUFFLEMASK_2,X3,X3

	vpshufb		SHUFFLEMASK_2,Y0,Y0
	vpshufb		SHUFFLEMASK_2,Y1,Y1
	vpshufb		SHUFFLEMASK_2,Y2,Y2
	vpshufb		SHUFFLEMASK_2,Y3,Y3

	vmovdqu		X3,0(%rsp)
	vmovdqu		X2,32(%rsp)
	vmovdqu		X1,64(%rsp)
	vmovdqu		X0,96(%rsp)

	vmovdqu		Y3,128+0(%rsp)
	vmovdqu		Y2,128+32(%rsp)
	vmovdqu		Y1,128+64(%rsp)
	vmovdqu		Y0,128+96(%rsp)

	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,0(%rsp,STOREMASK_2,4),X0
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,8(%rsp,STOREMASK_2,4),X1
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,16(%rsp,STOREMASK_2,4),X2
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,24(%rsp,STOREMASK_2,4),X3

	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+0(%rsp,STOREMASK_2,4),Y0
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+8(%rsp,STOREMASK_2,4),Y1
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+16(%rsp,STOREMASK_2,4),Y2
	vpcmpeqd	G_TMP_2,G_TMP_2,G_TMP_2
	vpgatherdd	G_TMP_2,128+24(%rsp,STOREMASK_2,4),Y3

	vpxor		(%rcx),X0,X0
	vpxor		32(%rcx),X1,X1
	vpxor		64(%rcx),X2,X2
	vpxor		96(%rcx),X3,X3

	vpxor		128(%rcx),Y0,Y0
	vpxor		128+32(%rcx),Y1,Y1
	vpxor		128+64(%rcx),Y2,Y2
	vpxor		128+96(%rcx),Y3,Y3


	vmovdqu		X0,0(%rdi)
	vmovdqu		X1,32(%rdi)
	vmovdqu		X2,64(%rdi)
	vmovdqu		X3,96(%rdi)

	vmovdqu		Y0,128+0(%rdi)
	vmovdqu		Y1,128+32(%rdi)
	vmovdqu		Y2,128+64(%rdi)
	vmovdqu		Y3,128+96(%rdi)

	addq		$256,%rsp

	vpxor		X0,X0,X0
	vpxor		X1,X1,X1
	vpxor		X2,X2,X2
	vpxor		X3,X3,X3

	vpxor		T0,T0,T0
	vpxor		T1,T1,T1

	vpxor		Y0,Y0,Y0
	vpxor		Y1,Y1,Y1
	vpxor		Y2,Y2,Y2
	vpxor		Y3,Y3,Y3

	vpxor		V0,V0,V0
	vpxor		V1,V1,V1
.endm

#######################################################################


	#void SM4_XTS_16_DecryptBlock1st(uint8_t* plain, uint8_t* cipher, unsigned int* ecb_rk, uint8_t* T);
	#plain		%rdi
	#cipher		%rsi
	#rk			%rdx
	#T			%rcx

	.globl	SM4_XTS_16_DecryptBlock1st
	.type	SM4_XTS_16_DecryptBlock1st, @function
	.align	64

SM4_XTS_16_DecryptBlock1st:
	#Get Address
	leaq	SBOX4X_MASK(%rip), %rax

	#compute tweak
	GALOIS_FIELD_MUL_16_1st 0
    SM4_XTS_16_DE_INNER

	ret
	.size	SM4_XTS_16_DecryptBlock1st, .-SM4_XTS_16_DecryptBlock1st



	#void SM4_XTS_16_DecryptBlock(uint8_t* plain, uint8_t* cipher, unsigned int* ecb_rk, uint8_t* T);
	#plain		%rdi
	#cipher		%rsi
	#rk			%rdx
	#T			%rcx

	.globl	SM4_XTS_16_DecryptBlock
	.type	SM4_XTS_16_DecryptBlock, @function
	.align	64

SM4_XTS_16_DecryptBlock:
	#Get Address
	leaq	SBOX4X_MASK(%rip), %rax

	#compute tweak
	GALOIS_FIELD_MUL_16 240
	SM4_XTS_16_DE_INNER

	ret
	.size	SM4_XTS_16_DecryptBlock, .-SM4_XTS_16_DecryptBlock

#endif
